"""WatchlightPydanticAIPlugin + RunHandle.

Pydantic AI's lifecycle model: customer constructs an
``Agent`` with model + tool callables, then calls
``agent.run(prompt)``. There's no global plugin protocol; the
integration point is `@agent.tool` decorator wrapping. We expose
:meth:`RunHandle.guarded_tool` as a thin decorator that runs
``authorize_action`` before the wrapped function executes.

For multi-agent flows (the "agent as composable callable"
idiom — a parent tool body calling ``other_agent.run(...)``),
this plugin auto-installs runtime instrumentation in its
constructor that stitches every nested ``Agent.run()`` into one
lineage tree under one workflow root. Zero customer code changes.
See :mod:`watchlight_pydantic_ai.instrumentation` for the design.
"""

from __future__ import annotations

import functools
import os
import uuid
import warnings
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Dict, List, Optional, Sequence, Union
from uuid import UUID

from watchlight_core import (
    AgentNotRegistered,
    ApdpClient,
    application_id_from_env,
    resolve_application_id,
    BaseRunHandle,
    DeclaredRootRefused,
    GovernanceBackend,
    GovernanceTelemetry,
    GovernanceUnavailable,
    WatchlightError,
    get_logger,
    require_manifest,
)
from watchlight_core.backend import EgressBinding, RunRef, egress_binding_for
from watchlight_core.errors import DECLARED_ROOT_UNSUPPORTED
from watchlight_core.scope import ResourceMatcher

logger = get_logger("watchlight_pydantic_ai")

# Source tag stamped on AgentSpawnObserved / ExecutionStarted events
# emitted by the runtime instrumentation when a nested ``Agent.run()``
# is detected. Mirrors LangGraph's ``langgraph.spawn`` provenance tag.
_SPAWN_PROVENANCE_TAG = "pydantic-ai.spawn"


# ─── Legacy `delegation_scope` → canonical kwargs ─────────────────────


# The canonical sub-agent scope kwarg names — used by
# :func:`_reconcile_legacy_delegation_scope` to detect the
# mixed-use ValueError case.
_CANONICAL_SCOPE_KWARGS = (
    "allowed_tools",
    "allowed_resources",
    "allowed_intents",
    "max_depth",
    "time_budget_seconds",
)


def _reconcile_legacy_delegation_scope(
    *,
    delegation_scope: Optional[Dict[str, Any]],
    allowed_tools: Optional[List[str]],
    allowed_resources: Optional[List[Union[ResourceMatcher, str]]],
    allowed_intents: Optional[List[str]],
    max_depth: Optional[int],
    time_budget_seconds: Optional[int],
) -> tuple[
    Optional[List[str]],
    Optional[List[Union[ResourceMatcher, str]]],
    Optional[List[str]],
]:
    """Map the deprecated ``delegation_scope`` dict onto the canonical
    sub-agent scope kwargs.

    Mirrors the LangGraph plugin's helper of the same name. See
    :func:`watchlight_langgraph.plugin._reconcile_legacy_delegation_scope`
    for the full contract — the two implementations are deliberately
    duplicated rather than shared via a `watchlight_core` helper
    because the deprecation warning's ``stacklevel`` is meaningful
    only at the framework plugin's call site, and the import-graph
    cost of shipping a `watchlight_core.deprecation` helper just for
    this is higher than the small duplication tax.
    """
    if delegation_scope is None:
        return (allowed_tools, allowed_resources, allowed_intents)

    mixed_kwargs = []
    if allowed_tools is not None:
        mixed_kwargs.append("allowed_tools")
    if allowed_resources is not None:
        mixed_kwargs.append("allowed_resources")
    if allowed_intents is not None:
        mixed_kwargs.append("allowed_intents")
    if max_depth is not None:
        mixed_kwargs.append("max_depth")
    if time_budget_seconds is not None:
        mixed_kwargs.append("time_budget_seconds")

    if mixed_kwargs:
        raise ValueError(
            "spawn_subagent: ``delegation_scope`` is deprecated; the "
            "canonical scope kwargs ("
            + ", ".join(_CANONICAL_SCOPE_KWARGS)
            + ") are the supported surface. Passing both is a sign of a "
            "half-migrated call site — pick one. Migrating? Replace "
            "delegation_scope={'allowed_actions': [...], "
            "'allowed_intents': [...]} with allowed_tools=[...] + "
            f"allowed_intents=[...]. (You mixed delegation_scope with "
            f"{mixed_kwargs}.)"
        )

    warnings.warn(
        "spawn_subagent: ``delegation_scope`` is deprecated and will be "
        "removed in a future release. Migrate to the canonical scope "
        "kwargs: allowed_tools, allowed_resources, allowed_intents, "
        "max_depth, time_budget_seconds. See the CHANGELOG for the "
        "field mapping.",
        DeprecationWarning,
        stacklevel=3,
    )

    legacy_actions = delegation_scope.get("allowed_actions")
    legacy_intents = delegation_scope.get("allowed_intents")
    legacy_resources = delegation_scope.get("allowed_resources")

    mapped_tools: Optional[List[str]] = (
        list(legacy_actions) if isinstance(legacy_actions, list) else []
    )
    mapped_intents: Optional[List[str]] = (
        list(legacy_intents) if isinstance(legacy_intents, list) else []
    )
    mapped_resources: Optional[List[Union[ResourceMatcher, str]]] = (
        list(legacy_resources)
        if isinstance(legacy_resources, list)
        else []
    )

    return (mapped_tools, mapped_resources, mapped_intents)


class RunHandle(BaseRunHandle):
    """Pydantic AI-flavoured run handle.

    Inherits the full lifecycle from
    :class:`watchlight_core.BaseRunHandle`. Adds two Pydantic AI-
    specific extensions:

    Provenance: ad-hoc observation events emitted via
    :meth:`watchlight_core.BaseRunHandle.publish_observation` carry
    ``metadata.source = "pydantic-ai.workload"`` via the per-class
    :attr:`_observation_source` override below.

    - :meth:`guarded_tool` — decorator that wraps a Pydantic AI
      tool callable so every invocation goes through
      ``authorize_action`` before the tool body runs.
    - :meth:`spawn_subagent` — opens a child handle linked to this
      handle's workflow root. The plugin's runtime instrumentation
      calls this automatically when it detects a nested
      ``Agent.run()`` inside a parent's tool body; customers can
      also call it explicitly (it's the LangGraph-compatible
      shape).

    The execution_id minted when this handle is opened is exposed
    as :attr:`execution_id` so the runtime instrumentation can
    stamp events with both the parent's and child's execution ids.
    """

    #: Provenance tag stamped on every ad-hoc observation event emitted
    #: via :meth:`watchlight_core.BaseRunHandle.publish_observation`.
    #: Identifies Pydantic AI workloads on the canonical event stream.
    _observation_source = "pydantic-ai.workload"

    # Delegation tree linkage stamped by ``spawn_subagent`` (or by
    # the runtime instrumentation in :mod:`.instrumentation`).
    parent_execution_id: Optional[str] = None
    parent_agent_id: Optional[str] = None
    delegation_depth: int = 0
    # The workflow root execution id. Set on the orchestrator's
    # top-level handle immediately after ``start_run``; inherited by
    # every spawned child so the whole agent tree's
    # ``lineage.executions`` rows reference the SAME root.
    root_execution_id: Optional[str] = None
    # The CHILD's execution_id captured at spawn time so
    # ``complete()`` can emit a paired ``execution_completed``
    # event. Without this, spawned sub-agents stay in
    # ``started`` status forever in the lineage graph.
    spawned_execution_id: Optional[str] = None
    spawn_started_at: Optional[float] = None

    def __init__(
        self,
        plugin: Any,
        agent_uuid: str,
        session_id: str,
        run: Optional[RunRef] = None,
        egress: Optional[EgressBinding] = None,
        execution_id: Optional[str] = None,
        run_handle_id: Optional[str] = None,
        server_run_handle: bool = False,
        intent_objective: Optional[str] = None,
        intent_provenance: Optional[str] = None,
    ):
        # Thread ``execution_id`` through to ``super().__init__`` so
        # :attr:`execution_id` and :attr:`root_execution_id` are
        # minted together and stay in sync. If this class instead
        # called ``super().__init__()`` (which auto-mints a fresh
        # execution_id AND sets root_execution_id to match) and then
        # OVERWROTE ``self.execution_id`` here, the two fields would
        # silently desync. That mismatch surfaces as a conformance
        # invariant-9 failure (sub-agent events' ``root_execution_id``
        # then points at the pre-overwrite value, not the post-).
        # The defensive ``execution_completed`` emit on close depends
        # on this — without it, lifecycle events would carry a
        # different id than the framework events on the same handle.
        super().__init__(
            plugin=plugin,
            agent_uuid=agent_uuid,
            session_id=session_id,
            # The run's reference; its credentials stay in the backend.
            run=run,
            egress=egress,
            execution_id=execution_id,
            run_handle_id=run_handle_id,
            server_run_handle=server_run_handle,
        )
        # intent_objective + intent_provenance extracted from
        # the framework's prompt arg by
        # :mod:`watchlight_pydantic_ai.instrumentation`. Stored on the
        # handle so the wrapping plugin path (or downstream
        # ``_emit_spawn_pair`` for nested calls) can plumb these into
        # the ``execution_started`` payload at emit time.
        #
        # ``intent_provenance`` is the wire-format string
        # ("plugin_derived" / "declared" / "absent" / …) rather than
        # the :class:`IntentProvenance` enum so callers don't need to
        # import the enum at every emit site. The schema validates
        # the wire format at deserialisation time.
        self.intent_objective: Optional[str] = intent_objective
        self.intent_provenance: Optional[str] = intent_provenance

    def guarded_tool(
        self,
        action: str = "execute",
    ) -> Callable[[Callable[..., Awaitable[Any]]], Callable[..., Awaitable[Any]]]:
        """Deprecated: use the module-level
        :func:`watchlight_pydantic_ai.guarded_tool` decorator.

        Decorator factory that wraps a Pydantic AI tool callable with
        authorization. The governing handle is resolved when the tool is
        CALLED, not when it is decorated: inside an instrumented
        ``Agent.run`` (root or nested sub-agent) the tool is authorized
        on that run's handle, so a sub-agent's tools are always
        authorized on the sub-agent's own credential and scope. Only
        when no instrumented run is active does it fall back to this
        handle. A finished governing run refuses the call.

        The ``resource`` argument to ``authorize_action`` is derived
        from the wrapped function's ``__name__``; ``functools.wraps``
        keeps Pydantic AI's tool-schema introspection working.
        """
        warnings.warn(
            "RunHandle.guarded_tool() is deprecated; decorate tools with "
            "watchlight_pydantic_ai.guarded_tool() instead. It authorizes "
            "each call on the run (or sub-agent) that is actually driving "
            "the agent.",
            DeprecationWarning,
            stacklevel=2,
        )
        return _make_guarded_tool(action, fallback=self)

    async def spawn_subagent(
        self,
        child_agent_slug: str,
        *,
        # REQUIRED — the child's own intent and goal, derived from this
        # run's (``ChildIntent`` or its dict form). wl-apdp refuses a spawn
        # without one.
        child_intent: Any,
        # Canonical sub-agent scope-attenuation kwargs. A sub-agent's
        # scope must be a strict subset of its parent's. Empty /
        # ``None`` values resolve to fail-closed defaults (the child
        # inherits nothing it isn't explicitly granted).
        allowed_tools: Optional[List[str]] = None,
        allowed_resources: Optional[
            List[Union[ResourceMatcher, str]]
        ] = None,
        allowed_intents: Optional[List[str]] = None,
        max_depth: Optional[int] = None,
        time_budget_seconds: Optional[int] = None,
        # Plugin-specific plumbing — workflow tree linkage + the
        # intent surface. Not part of the scope-attenuation contract.
        parent_execution_id: Optional[str] = None,
        child_execution_id: Optional[str] = None,
        intent: Optional[Dict[str, Any]] = None,
        reason: Optional[str] = None,
        intent_objective: Optional[str] = None,
        intent_provenance: Optional[str] = None,
        # DEPRECATED — legacy scope dict. See
        # :func:`_reconcile_legacy_delegation_scope` in this module.
        delegation_scope: Optional[Dict[str, Any]] = None,
    ) -> "RunHandle":
        """Open a governed sub-agent run under this handle.

        Uses the canonical scope-attenuation kwargs. Mirrors the
        LangGraph reference contract with one ergonomic difference:
        ``parent_execution_id`` is OPTIONAL (defaults to this
        handle's own ``execution_id``, the right answer for the
        common "parent's tool body calls child.run()" case).

        See :meth:`watchlight_langgraph.RunHandle.spawn_subagent`
        for the full flow. The behavior is mirrored here except for
        the Pydantic AI-specific ``intent_objective`` /
        ``intent_provenance`` per-execution surface, which flows
        through to the child's ``execution_started`` event.

        Raises:
            ValueError: when ``delegation_scope`` is passed
                alongside any canonical scope kwarg.
            AgentQuarantinedError: when this parent handle is in
                ``QUARANTINED`` state.
            ScopeAttenuationDenied: when APDP's strict-subset
                validator rejected the requested scope.
            RunHandleInvalidated: when APDP rejected because the
                parent's RunHandle is no longer valid.
            WatchlightError: on transport errors or any
                non-canonical APDP response.
        """
        # Step -1 — quarantine short-circuit. MUST come before the
        # resolve_agent call so a quarantined agent cannot probe the
        # registry for sibling agent ids.
        from watchlight_core.decision import (
            AgentQuarantinedError as _Quar,
            RunHandleState as _State,
        )

        if self._state == _State.QUARANTINED:
            assert self._quarantine_decision is not None
            self._fire_kill_signal()
            raise _Quar.from_decision(self._quarantine_decision)

        # Step 0 — reconcile the deprecated ``delegation_scope`` dict
        # with the canonical scope kwargs. Fail-closed mapping on
        # ambiguous legacy keys.
        (
            allowed_tools,
            allowed_resources,
            allowed_intents,
        ) = _reconcile_legacy_delegation_scope(
            delegation_scope=delegation_scope,
            allowed_tools=allowed_tools,
            allowed_resources=allowed_resources,
            allowed_intents=allowed_intents,
            max_depth=max_depth,
            time_budget_seconds=time_budget_seconds,
        )

        # Execution-lineage integrity. The child's tree position is
        # SERVER-derived — the parent-exec is THIS handle's own
        # execution_id (the parent token's verified `eid`), never the
        # client-supplied `parent_execution_id`. The child execution_id +
        # root come back on the spawn response (see below).
        parent_exec_id = self.execution_id
        effective_root_execution_id = (
            self.root_execution_id or self.execution_id
        )

        # Step 1 — resolve the child's slug to a canonical UUID for
        # the spawn handler.
        resolved = await self._plugin.apdp.resolve_agent(child_agent_slug)
        if resolved is None:
            raise AgentNotRegistered(
                f"Sub-agent {child_agent_slug!r} is not registered with "
                f"Watchlight. Register via wl-registry's "
                f"/api/v1/agents/register before spawning."
            )
        child_uuid_str = resolved["id"]
        try:
            child_uuid = UUID(child_uuid_str)
        except (ValueError, TypeError) as exc:
            raise WatchlightError(
                f"resolve_agent returned a non-UUID id for "
                f"{child_agent_slug!r}: {child_uuid_str!r}"
            ) from exc

        # Step 2 — canonical APDP round-trip. Presents the PARENT's
        # `sst_` credential; the server derives the child's lineage from
        # the parent's VERIFIED claims + mints the child execution_id.
        response = await self._perform_spawn_apdp_roundtrip(
            child_uuid,
            child_intent=child_intent,
            allowed_tools=allowed_tools,
            allowed_resources=allowed_resources,
            allowed_intents=allowed_intents,
            max_depth=max_depth,
            time_budget_seconds=time_budget_seconds,
        )
        # Adopt the SERVER-derived child lineage.
        child_exec_id = response.child_execution_id or f"exec_{uuid.uuid4()}"
        effective_root_execution_id = (
            response.root_execution_id or self.root_execution_id or self.execution_id
        )

        # Step 3 — mint the Pydantic-AI-flavoured child handle. The
        # child's ``session_id`` MUST equal the ``sid`` claim inside its
        # own ``sst_`` credential — the server mints both as
        # ``ses_<child-run-handle>`` and returns the value as
        # ``child_session_id`` so the ``/v1/events`` binding gate's
        # ``session_id == sid`` check holds. Using the bare
        # ``child_run_handle_id`` (no ``ses_`` prefix) makes every child
        # event fail that gate with 409 ``lineage_event_identity_mismatch``.
        # Mirror ``BaseRunHandle.spawn_subagent`` (fallback covers a
        # pre-field server).
        child_handle_id = response.child_run_handle_id
        child_session_id = response.child_session_id or f"ses_{child_handle_id}"
        # The child's provenance is never above the derived one (at most
        # ``plugin_derived``, never above the parent's). An ``absent``
        # derived provenance records no objective.
        intent_objective, intent_provenance = _cap_to_derived_provenance(
            intent_objective, intent_provenance, response.derived_intent
        )
        child = RunHandle(
            plugin=self._plugin,
            agent_uuid=str(child_uuid),
            session_id=child_session_id,
            execution_id=child_exec_id,
            intent_objective=intent_objective,
            intent_provenance=intent_provenance,
            # The child's own run (its server-minted per-run credential
            # stays in the backend).
            run=RunRef(response.child_run),
            # The child session's own egress binding (never the
            # parent's).
            egress=egress_binding_for(self._plugin.apdp, RunRef(response.child_run)),
        )
        # Sub-agent handles minted via the Pydantic AI override
        # are returned to the caller without an explicit ``async with``
        # block. Flip the fail-closed flag so the first
        # ``authorize_action_detailed`` on the child doesn't raise
        # :class:`watchlight_core.WatchlightContractError`. The
        # ``_emit_child_started`` call below publishes the canonical
        # ``execution_started`` for the child with the correct root
        # linkage.
        child._aentered = True
        # Wire the child into the parent-chain for quarantine
        # propagation. The :class:`BaseRunHandle` __init__ does this
        # when ``parent_handle`` is passed, but the Pydantic AI
        # RunHandle has its own ``__init__`` signature that doesn't
        # accept ``parent_handle`` (legacy), so we do it manually
        # here via the same helper the base class would.
        import weakref as _weakref
        child._parent_handle_ref = _weakref.ref(self)
        # Without the registration a quarantine of this parent would not
        # reach the child: refuse the spawn instead of running it.
        try:
            self._register_child_handle(child)
        except Exception as exc:
            try:
                await child.complete()
            except Exception:  # noqa: BLE001 — the refusal below wins
                logger.warning(
                    "spawn_subagent: closing the unregistered child failed",
                    exc_info=True,
                )
            raise GovernanceUnavailable(
                "spawn_subagent: the sub-agent could not be registered "
                "under its parent; refusing the spawn"
            ) from exc
        # Stamp the server-attested grant + run_handle_id (the
        # Pydantic AI RunHandle's __init__ also doesn't accept
        # these — set directly).
        child.run_handle_id = str(child_handle_id)
        child.granted_scope = response.granted_scope
        child._derived_intent = response.derived_intent
        # A sub-agent presents its APDP-minted run_handle_id on every
        # authorize, so wl-apdp's scope-membership check binds the call to
        # the child's granted scope. The base class decides that from a
        # ``parent_handle`` constructor argument this RunHandle does not
        # take, so mark it here: without it the child's calls go out
        # without the handle and are not checked against its grant.
        child._is_subagent = True
        child._server_run_handle = False

        # Step 4 — stamp workflow tree-linkage on the child.
        child.parent_execution_id = parent_exec_id
        child.parent_agent_id = self.agent_uuid
        child.delegation_depth = self.delegation_depth + 1
        child.root_execution_id = effective_root_execution_id
        child.spawned_execution_id = child_exec_id
        import time as _time
        child.spawn_started_at = _time.monotonic()

        # Step 5 — emit the child ``execution_started``. The
        # ``agent_spawn_observed`` attestation is NOT emitted here —
        # spawn lineage is SERVER-attested only: wl-apdp's
        # ``spawn_handler`` emits the single authoritative
        # ``agent_spawn_observed`` (carrying the server-validated
        # ``granted_scope`` and server-minted child execution id) while it
        # processes the ``POST /v1/spawn_subagent`` round-trip above. A
        # per-plugin spawn emission is redundant and is REJECTED at ingest
        # (``lineage_event_class_not_permitted``).
        await _emit_child_started(
            plugin=self._plugin,
            parent_execution_id=parent_exec_id,
            child_session_id=child.session_id,
            child_agent_id=child.agent_uuid,
            child_execution_id=child_exec_id,
            child_depth=child.delegation_depth,
            root_execution_id=child.root_execution_id,
            tenant_id=getattr(self._plugin, "tenant_id", None),
            intent_objective=intent_objective,
            intent_provenance=intent_provenance,
            intent_category=(response.derived_intent or {}).get("intent_category"),
            # The child's own run.
            child_run=child.run,
        )
        # ``_emit_child_started`` published the canonical
        # ``execution_started`` event for ``child_exec_id`` with the
        # correct workflow-root linkage. Mark it as already emitted
        # so the SDK's defensive late-binding mint in
        # :meth:`BaseRunHandle.authorize_action_detailed` doesn't
        # emit a duplicate event when the child's first authorize
        # call lands.
        child.mark_execution_started_emitted(child_exec_id)

        # Step 6 — bind child as the active sub-agent in this
        # asyncio task's contextvars copy so that each sub-agent's
        # tool calls authorize against its own governed handle.
        #
        # A failed bind is NOT swallowed: without it the child's tool
        # calls would resolve the parent's handle and be authorized on
        # the parent's credential. Close the child and refuse the spawn.
        # The token lets the child's complete()/terminate() reset the
        # binding it made.
        from watchlight_core.run_handle import _current_subagent_handle

        try:
            child._subagent_cv_token = _current_subagent_handle.set(child)
        except Exception as exc:
            try:
                await child.complete()
            except Exception:  # noqa: BLE001 — the refusal below wins
                logger.warning(
                    "spawn_subagent: closing the unbound child failed",
                    exc_info=True,
                )
            raise GovernanceUnavailable(
                "spawn_subagent: could not bind the sub-agent handle to "
                "this context; refusing the spawn"
            ) from exc

        return child

    async def complete(self) -> None:
        """Close the APDP session cleanly + (for spawned handles)
        emit ``execution_completed`` for the spawn's own execution.

        Mirrors :class:`watchlight_langgraph.RunHandle.complete`:
        for top-level (non-spawned) handles this is identical to
        :meth:`BaseRunHandle.complete`. For handles minted by
        :meth:`spawn_subagent`, we ALSO publish an
        ``execution_completed`` event so wl-execution-graph
        transitions the child's row in ``lineage.executions``
        from ``started`` to ``completed``. Without this, sub-
        agents render as perpetually-Started in the lineage graph
        — a UX-credibility hole.
        """
        if not self._completed and self.spawned_execution_id is not None:
            # Declare the lifecycle emission BEFORE the manual
            # publish so :meth:`BaseRunHandle.complete` (called via
            # ``super().complete()`` below) does NOT also emit a
            # defensive ``execution_completed`` for this handle's
            # ``execution_id`` (== ``spawned_execution_id`` for
            # spawn-minted handles). The plugin's manual emit carries
            # the richer per-spawn payload + provenance tag; the
            # SDK's defensive emit is the fallback for plugin lanes
            # that don't have one.
            self.mark_execution_completed_emitted()
            await _emit_spawn_execution_completed(
                plugin=self._plugin,
                execution_id=self.spawned_execution_id,
                agent_id=self.agent_uuid,
                session_id=self.session_id,
                parent_execution_id=self.parent_execution_id,
                parent_agent_id=self.parent_agent_id,
                root_execution_id=self.root_execution_id,
                tenant_id=getattr(self._plugin, "tenant_id", None),
                duration_ms=self._spawn_duration_ms(),
                actions_taken=self._plugin.last_actions_allowed,
                actions_denied=self._plugin.last_actions_denied,
                # The child's own run.
                run=self.run,
            )
        await super().complete()

    async def terminate(self, reason: str = "manual") -> None:
        """Abnormal close. Emit ``execution_failed`` for spawned
        handles so the lineage view reflects the bad path.
        """
        if not self._completed and self.spawned_execution_id is not None:
            # See ``complete()`` for rationale.
            self.mark_execution_failed_emitted()
            await _emit_spawn_execution_failed(
                plugin=self._plugin,
                execution_id=self.spawned_execution_id,
                agent_id=self.agent_uuid,
                session_id=self.session_id,
                parent_execution_id=self.parent_execution_id,
                root_execution_id=self.root_execution_id,
                tenant_id=getattr(self._plugin, "tenant_id", None),
                duration_ms=self._spawn_duration_ms(),
                error=reason,
                # The child's own run.
                run=self.run,
            )
        await super().terminate(reason=reason)

    def _spawn_duration_ms(self) -> int:
        """Wall-clock ms since ``spawn_subagent`` minted this handle."""
        if self.spawn_started_at is None:
            return 0
        import time as _time
        return int((_time.monotonic() - self.spawn_started_at) * 1000)


# ─── Event-emit helpers (mirroring langgraph plugin shape) ────────────


_PROVENANCE_RANK = {"absent": 0, "proxy_inferred": 1, "plugin_derived": 2, "declared": 3}


def _cap_to_derived_provenance(
    objective: Optional[str],
    provenance: Optional[str],
    derived: Optional[Dict[str, Any]],
) -> "tuple[Optional[str], Optional[str]]":
    """Cap a spawned child's intent provenance at the one wl-apdp derived
    for it. The derived provenance is at most ``plugin_derived`` and never
    above the parent's; a child never raises it. When the cap is
    ``absent``, no objective is recorded (an objective needs a source).
    Without a derivation (an older server) the child keeps the parent-side
    value, capped at ``plugin_derived``. A child with no objective of its
    own keeps reporting none (its provenance stays as given, capped)."""
    cap = "plugin_derived"
    if isinstance(derived, dict):
        raw = derived.get("provenance")
        cap = raw if raw in _PROVENANCE_RANK and raw != "declared" else "absent"
    if provenance is None:
        if objective is None:
            return None, None
        provenance = "plugin_derived"
    own = provenance if provenance in _PROVENANCE_RANK else "absent"
    effective = own if _PROVENANCE_RANK[own] <= _PROVENANCE_RANK[cap] else cap
    if objective is None or effective == "absent":
        return None, "absent"
    return objective, effective


async def _emit_child_started(
    *,
    plugin: "WatchlightPydanticAIPlugin",
    parent_execution_id: str,
    child_session_id: str,
    child_agent_id: str,
    child_execution_id: str,
    child_depth: int,
    root_execution_id: Optional[str],
    tenant_id: Optional[str],
    intent_objective: Optional[str] = None,
    intent_provenance: Optional[str] = None,
    child_run: Optional[RunRef] = None,
    intent_category: Optional[str] = None,
) -> None:
    """Publish the child ``execution_started`` for a governed spawn.

    The ``agent_spawn_observed`` attestation is NOT emitted from the
    plugin. Spawn lineage is SERVER-attested only: wl-apdp's
    ``spawn_handler`` emits the single authoritative ``agent_spawn_observed``
    (carrying the server-validated ``granted_scope`` and the server-minted
    child execution id) while it processes the ``POST /v1/spawn_subagent``
    round-trip. A per-plugin spawn emission is redundant, forgeable, and
    REJECTED at ``/v1/events`` ingest (``lineage_event_class_not_permitted``)
    — so this helper emits only the child's own ``execution_started``,
    authenticated by the CHILD's own per-run credential.

    ``intent_objective`` and ``intent_provenance`` are optional. When
    provided they're stamped onto the ``execution_started`` payload so
    Cedar policies and the dashboard's intent column see the
    per-execution intent for the
    spawned child. The schema invariant
    ``intent_objective is not None ⇒ intent_provenance ∈ {declared,
    plugin_derived, proxy_inferred}`` is enforced by
    :class:`watchlight_core.ExecutionStartedPayload` at deserialise
    time.
    """
    now_iso = (
        datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    )

    started_payload: Dict[str, Any] = {
        "principal": {"principal_type": "agent", "id": child_agent_id},
        "depth": child_depth,
    }
    if isinstance(intent_category, str) and intent_category:
        started_payload["intent_category"] = intent_category
    # Emit ``intent_objective`` + ``intent_provenance`` only
    # when the extractor produced a value. Omitting the fields when
    # they're ``None`` keeps the wire envelope identical to the
    # pre-intent shape for backward-compatible replay.
    if intent_objective is not None:
        started_payload["intent_objective"] = intent_objective
        # Schema invariant: a populated objective MUST carry a non-
        # Absent provenance. The instrumentation layer guarantees
        # this in the normal path; defensively default to
        # "plugin_derived" if the extractor produced an objective
        # without an explicit provenance (e.g. a downstream caller
        # forgot to thread both through).
        started_payload["intent_provenance"] = (
            intent_provenance or "plugin_derived"
        )
    elif intent_provenance is not None:
        # Provenance without an objective is valid — typically the
        # "absent" sentinel marking that the extractor saw the call
        # but couldn't infer a prompt.
        started_payload["intent_provenance"] = intent_provenance

    started_event = {
        "event_id": f"evt_{uuid.uuid4()}",
        "event_type": "execution_started",
        "timestamp": now_iso,
        "execution_id": child_execution_id,
        "agent_id": child_agent_id,
        "session_id": child_session_id,
        "tenant_id": tenant_id,
        "parent_execution_id": parent_execution_id,
        "root_execution_id": root_execution_id,
        "metadata": {"source": _SPAWN_PROVENANCE_TAG, "kind": "child_started"},
        "payload": started_payload,
    }

    try:
        # Child-attributed execution start → CHILD credential.
        await plugin.apdp.publish_events(child_run, [started_event])
    except Exception:  # noqa: BLE001 — observability is best-effort
        logger.debug(
            "spawn_subagent: event emission failed", exc_info=True
        )


async def _emit_spawn_execution_completed(
    *,
    plugin: "WatchlightPydanticAIPlugin",
    execution_id: str,
    agent_id: str,
    session_id: str,
    parent_execution_id: Optional[str],
    parent_agent_id: Optional[str],
    root_execution_id: Optional[str],
    tenant_id: Optional[str],
    duration_ms: int,
    actions_taken: int,
    actions_denied: int,
    run: Optional[RunRef] = None,
) -> None:
    """Publish ``execution_completed`` for a spawned sub-agent's exec.

    The payload carries exactly the fields
    ``wl_lineage::events::ExecutionCompletedPayload`` models. It used
    to also carry ``depth`` and ``spawned_by_agent_id``, which that
    struct does not model: Rust's payload structs do not set
    ``deny_unknown_fields``, so serde accepted the event and dropped
    both keys on the floor. The spawner now rides the
    ENVELOPE's ``parent_agent_id`` — the canonical field for it, which
    ``BaseRunHandle`` already stamps on every other event — and the
    depth is computed server-side by wl-execution-graph and served on
    ``lineage.executions.depth``.
    """
    event = {
        "event_id": f"evt_{uuid.uuid4()}",
        "event_type": "execution_completed",
        "timestamp": (
            datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        ),
        "execution_id": execution_id,
        "agent_id": agent_id,
        "session_id": session_id,
        "tenant_id": tenant_id,
        "parent_execution_id": parent_execution_id,
        # Canonical envelope field for "who spawned this agent".
        "parent_agent_id": parent_agent_id,
        "root_execution_id": root_execution_id,
        "metadata": {"source": _SPAWN_PROVENANCE_TAG, "kind": "child_completed"},
        "payload": {
            "duration_ms": duration_ms,
            "actions_taken": actions_taken,
            "actions_denied": actions_denied,
        },
    }
    try:
        # Child-attributed completion → CHILD credential.
        await plugin.apdp.publish_events(run, [event])
    except Exception:  # noqa: BLE001 — observability is best-effort
        logger.debug("spawn complete: event emission failed", exc_info=True)


async def _emit_spawn_execution_failed(
    *,
    plugin: "WatchlightPydanticAIPlugin",
    execution_id: str,
    agent_id: str,
    session_id: str,
    parent_execution_id: Optional[str],
    root_execution_id: Optional[str],
    tenant_id: Optional[str],
    duration_ms: int,
    error: str,
    run: Optional[RunRef] = None,
) -> None:
    """Publish ``execution_failed`` for a spawned sub-agent's exec."""
    event = {
        "event_id": f"evt_{uuid.uuid4()}",
        "event_type": "execution_failed",
        "timestamp": (
            datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        ),
        "execution_id": execution_id,
        "agent_id": agent_id,
        "session_id": session_id,
        "tenant_id": tenant_id,
        "parent_execution_id": parent_execution_id,
        "root_execution_id": root_execution_id,
        "metadata": {"source": _SPAWN_PROVENANCE_TAG, "kind": "child_failed"},
        "payload": {
            "duration_ms": duration_ms,
            "error": error[:240],
            "policy_denied": False,
        },
    }
    try:
        # Child-attributed failure → CHILD credential.
        await plugin.apdp.publish_events(run, [event])
    except Exception:  # noqa: BLE001 — observability is best-effort
        logger.debug("spawn fail: event emission failed", exc_info=True)


def _resolve_governing_handle(
    fallback: Optional["RunHandle"], resource: str
) -> "RunHandle":
    """Return the handle that governs a tool call made right now.

    The instrumentation's per-context handle (the current run, or the
    current sub-agent's own handle when called inside a nested
    ``Agent.run``) always wins over a handle captured at decoration
    time. With neither, or when the governing handle has finished, the
    call is refused: a tool never runs ungoverned or on a stale run.
    """
    from .instrumentation import current_handle

    handle = current_handle() or fallback
    if handle is None or getattr(handle, "_completed", False):
        raise GovernanceUnavailable(
            f"Watchlight AI Agent Runtime Governance refused tool "
            f"{resource!r}: no live governed run is active for this call, "
            f"so the tool was not run. Call it from an instrumented "
            f"Agent.run() (or an open run)."
        )
    return handle


def _make_guarded_tool(
    action: str, fallback: Optional["RunHandle"] = None
) -> Callable[[Callable[..., Awaitable[Any]]], Callable[..., Awaitable[Any]]]:
    def decorator(
        fn: Callable[..., Awaitable[Any]],
    ) -> Callable[..., Awaitable[Any]]:
        resource = fn.__name__

        @functools.wraps(fn)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            handle = _resolve_governing_handle(fallback, resource)
            allowed = await handle.authorize_action(
                action=action,
                resource=resource,
            )
            if not allowed:
                raise PermissionError(
                    f"watchlight-pydantic-ai: APDP denied {action!r} "
                    f"on {resource!r}"
                )
            return await fn(*args, **kwargs)

        return wrapper

    return decorator


def guarded_tool(
    action: str = "execute",
) -> Callable[[Callable[..., Awaitable[Any]]], Callable[..., Awaitable[Any]]]:
    """Decorator factory: authorize every call of a Pydantic AI tool.

    Usage::

        agent = Agent("openai:gpt-4o-mini", name="research-agent")

        @agent.tool
        @guarded_tool()
        async def web_search(ctx, query: str) -> list[dict]:
            ...

        await agent.run("...")   # the plugin opens the governed run

    Each call runs ``authorize_action(action, <function name>)`` on the
    run that is driving the agent at call time: the root run for a
    top-level ``Agent.run``, or a sub-agent's own handle when the agent
    runs nested inside another agent's tool. A denial raises
    ``PermissionError`` and the tool body never runs. A call with no
    live governed run raises :class:`watchlight_core.GovernanceUnavailable`.
    """
    return _make_guarded_tool(action)


class WatchlightPydanticAIPlugin(GovernanceTelemetry):
    """Watchlight governance plugin for Pydantic AI agents.

    Usage::

        from pydantic_ai import Agent
        from watchlight_pydantic_ai import WatchlightPydanticAIPlugin, guarded_tool

        wl = WatchlightPydanticAIPlugin(apdp_url="https://apdp.your-org")
        agent = Agent("openai:gpt-4", name="research-agent")

        @agent.tool
        @guarded_tool()
        async def web_search(ctx, query: str) -> list[dict]:
            return await fetch(query)

        async def main():
            # The instrumented ``agent.run`` opens the governed run; the
            # model and every tool call run under that same run.
            result = await agent.run("find Q3 revenue figures")
            return result.output

    **Multi-agent flows (zero customer code):** the plugin's
    constructor installs runtime instrumentation on
    ``pydantic_ai.Agent``'s entry points (``run``, ``run_sync``,
    ``run_stream``, ``iter``) that automatically stitches every
    nested ``Agent.run()`` into one lineage tree under one
    workflow root, with each sub-agent's tool calls authorized
    against the sub-agent's own principal.

    Construction is the one and only enable point. The patch is
    idempotent — constructing the plugin a second time in the same
    process does not double-wrap. Call
    :func:`watchlight_pydantic_ai.uninstall_instrumentation` to
    explicitly remove the patch.
    """

    def __init__(
        self,
        apdp_url: str = "http://localhost:8081",
        tenant_id: Optional[str] = None,
        apdp_api_key: Optional[str] = None,
        log_decisions: bool = True,
        connect_proxy_url: Optional[str] = None,
        auto_instrument: bool = True,
        governance: Optional[GovernanceBackend] = None,
        application_id: Optional[str] = None,
        nested_agent_time_budget_seconds: Optional[int] = None,
        child_intent_category: Optional[str] = None,
    ):
        super().__init__()
        # The intent category declared for the nested agents the
        # instrumentation spawns (``None``: the parent's own derived
        # category, else ``DEFAULT_PLUGIN_CHILD_INTENT_CATEGORY``). wl-apdp
        # refuses a category outside the parent run's intent bounds.
        self.child_intent_category = child_intent_category
        # A tighter default time budget for the nested agents the
        # instrumentation spawns on its own (an ``Agent.run`` inside a tool).
        # ``None`` (the default): a nested agent inherits its parent's
        # remaining time. A value is sent exactly as configured and is never
        # shortened: a spawn whose parent cannot give that much (its granted
        # budget, its remaining time, or the tenant threshold) is refused,
        # and the nested agent does not run.
        if nested_agent_time_budget_seconds is not None and (
            isinstance(nested_agent_time_budget_seconds, bool)
            or not isinstance(nested_agent_time_budget_seconds, int)
            or nested_agent_time_budget_seconds <= 0
        ):
            raise ValueError(
                "nested_agent_time_budget_seconds must be a positive integer or None"
            )
        self.nested_agent_time_budget_seconds = nested_agent_time_budget_seconds
        # Authentication precedence for the ApdpClient (mirrors the
        # other Watchlight framework plugins):
        #   1. An explicit ``apdp_api_key=`` kwarg (legacy / tests) wins.
        #   2. Otherwise, if a unified credential is configured (AWS
        #      Secrets Manager, the environment, or a credential file),
        #      load it via ``Credential.from_default()`` so the client
        #      emits ``Authorization: Bearer`` and ``X-Wl-Credential-Kind``
        #      (no tenant header) — the headers wl-apdp's pepper-gated
        #      ``routed_auth_middleware`` requires once a credential pepper
        #      is loaded.
        #   3. Otherwise fall back to the unauthenticated client (local /
        #      dev stacks where wl-apdp runs without a pepper).
        #
        # No credential configured at all → the unauthenticated path, so
        # pepper-less local stacks still run (the server is the authority;
        # if it requires a credential it will 401). A credential that IS
        # explicitly configured (an AWS secret id or a credential file) but
        # cannot be loaded raises: it must never degrade silently. Any other
        # load failure is logged (loader error class only, never a value).
        credential = None
        if apdp_api_key is None:
            try:
                from watchlight_core import Credential, CredentialNotFound

                explicitly_configured = bool(
                    os.environ.get("WATCHLIGHT_CREDENTIAL_AWS_SECRET_ID", "").strip()
                    or os.environ.get("WATCHLIGHT_CREDENTIAL_FILE", "").strip()
                )
                try:
                    credential = Credential.from_default()
                except Exception as exc:  # noqa: BLE001 — classified below
                    if explicitly_configured:
                        # The loader's message can quote file content or a
                        # token prefix; surface the error class only.
                        raise CredentialNotFound(
                            "watchlight_pydantic_ai: the configured credential "
                            f"could not be loaded ({type(exc).__name__})"
                        ) from None
                    if not isinstance(exc, CredentialNotFound):
                        logger.warning(
                            "watchlight_pydantic_ai: the configured credential "
                            "could not be loaded (%s); continuing "
                            "unauthenticated, the server decides whether that "
                            "is allowed.",
                            type(exc).__name__,
                        )
                    credential = None
            except ImportError:
                credential = None

        if governance is not None:
            # Developer-Edition / in-process seam: use the caller-supplied
            # GovernanceBackend (e.g. watchlight_core.InProcessClient over the
            # compiled watchlight-engine) verbatim, skipping the networked
            # ApdpClient. Same plugin, same agent code — only the backend
            # differs; going to production is swapping this back for an
            # ApdpClient (one config flip, not a rewrite). apdp_url /
            # apdp_api_key are ignored in this mode.
            # SECURITY: a supplied backend bypasses ApdpClient's channel-safety
            # guard. The shipped InProcessClient is network-free; a CUSTOM
            # networked backend passed here MUST enforce its own transport
            # security (TLS). Only pass a backend you trust to do so.
            self.apdp = governance
        elif credential is not None:
            self.apdp = ApdpClient(apdp_url, credential=credential)
        else:
            self.apdp = ApdpClient(apdp_url, api_key=apdp_api_key)
        self.tenant_id = tenant_id
        self.log_decisions = log_decisions
        # wl-proxy CONNECT mode. The plugin auto-installs a local
        # sidecar in start_run; the customer's HTTP calls (Pydantic AI
        # uses httpx under the hood) auto-route through wl-proxy with
        # the session-scoped Proxy-Authorization JWT. Zero agent-code
        # touches. Env fallback: WATCHLIGHT_PROXY_URL.
        import os as _os
        self.connect_proxy_url = connect_proxy_url or _os.getenv(
            "WATCHLIGHT_PROXY_URL"
        )
        # AI application attribution. The application every run
        # opened by this plugin belongs to; forwarded on session create
        # so wl-apdp binds it to the run credential. Explicit
        # configuration only — never inferred from prompts or names.
        # The zero-touch instrumentation opens runs with no per-call
        # argument, so this plugin-level value is how a deployment
        # attributes a Pydantic AI agent. ``start_run(application_id=...)``
        # overrides per run. Env fallback: ``WATCHLIGHT_APPLICATION_ID``.
        # ``None`` / empty / whitespace ⇒ unset, the field is not sent.
        # A non-UUID raises ``ValueError`` here (client-side format
        # check only — wl-apdp stays the authority on membership). The
        # in-process engine (Developer Edition) refuses the field:
        # attribution is an Enterprise feature.
        self.application_id = (
            resolve_application_id(application_id) or application_id_from_env()
        )
        # Kill-signal registry. Defaults ON: in-process cancellation
        # is free until an interceptor registers a request, whereas
        # leaving it unwired makes the BaseRunHandle quarantine
        # transition a SILENT no-op. Proxy-side hard-kill escalation
        # stays opt-in — assign a registry built with
        # ``httpx_hard_kill_escalator`` to enable it. Set to ``None``
        # to disable interruption entirely.
        from watchlight_core import default_kill_signal_registry

        self.kill_signal_registry = default_kill_signal_registry()

        # Auto-install runtime instrumentation for nested
        # ``Agent.run()`` calls. See :mod:`.instrumentation` for the
        # design. Idempotent — second-construct doesn't double-
        # wrap. Customers who want to opt out (e.g. when running
        # multiple isolated plugins in a single process and one
        # of them shouldn't govern nested calls) pass
        # ``auto_instrument=False``. The default reflects the
        # zero-touch product principle.
        if auto_instrument:
            from .instrumentation import install_instrumentation

            install_instrumentation(self)

    async def start_run(
        self,
        agent_slug: str,
        *,
        intent_objective: Optional[str] = None,
        intent_provenance: Optional[str] = None,
        application_id: Optional[str] = None,
        declared_root: Optional[Sequence[str]] = None,
    ) -> RunHandle:
        """Open a governed run for the named Pydantic AI agent.

        ``declared_root`` is set by
        :func:`watchlight_pydantic_ai.root_run`, never by customer code: the
        root execution ids of the governed runs live in this process. The
        run opens only when the server confirms it decided the declared root
        (``Action::"open_declared_root"``); a server that does not confirm
        it gets its session ended and the run refused with
        :class:`watchlight_core.DeclaredRootRefused`.

        ``application_id``: the AI application this run belongs to.
        wl-apdp checks the agent is a member of it and refuses
        the session otherwise; an agent in exactly one application needs
        nothing here. Defaults to the plugin-level ``application_id``
        (constructor kwarg, else ``WATCHLIGHT_APPLICATION_ID``) — the
        zero-touch instrumentation never passes it per call. The
        application is bound to the run credential and to every
        sub-agent the run spawns.

        ``intent_objective`` and ``intent_provenance`` are OPTIONAL
        kwargs that the runtime instrumentation populates from the
        ``Agent.run(prompt)`` arg via
        :func:`watchlight_pydantic_ai.intent.extract_intent_from_pydantic_args`.
        Customer code does NOT pass these explicitly — a declared
        intent instead flows in through the synthetic
        declare-intent tool. For the plugin's automatic zero-touch
        path, the instrumentation wrapper does the extraction + the
        forward.

        Both kwargs are optional + default to ``None`` so callers
        that don't supply an intent (e.g. the conformance harness's
        synthetic lifecycle, or the test fixtures that mint a
        handle directly) keep working unchanged.

        ``intent_provenance`` is a wire-format string ("declared",
        "plugin_derived", "proxy_inferred", "absent") matching
        :class:`watchlight_core.IntentProvenance`. The wire shape is
        chosen over the enum so callers don't have to import the
        enum at every emit site.
        """
        self._reset_telemetry()

        resolved = await self.apdp.resolve_agent(agent_slug)
        if resolved is None:
            raise AgentNotRegistered(
                f"Agent {agent_slug!r} is not registered with Watchlight. "
                f"Register via wl-registry's /api/v1/agents/register before "
                f"invoking it."
            )
        agent_uuid = resolved["id"]

        # Empty / whitespace ⇒ unset (the plugin default applies); a
        # non-UUID raises before any session is opened.
        app_id = resolve_application_id(application_id) or self.application_id
        session = await self.apdp.create_session(
            agent_id=agent_uuid,
            ttl_seconds=3600,
            metadata={"framework": "pydantic-ai", "tenant_id": self.tenant_id},
            # Only when set, so an older watchlight-agent-sdk still works.
            **({"application_id": app_id} if app_id is not None else {}),
            **({"declared_root": list(declared_root)} if declared_root is not None else {}),
        )
        if session is None:
            raise GovernanceUnavailable(
                "WL-APDP did not accept the session create. Check that "
                "APDP is reachable and the data plane is configured."
            )
        session_id = session.session_id
        run = session.run
        if declared_root is not None and not session.declared_root:
            # An older server ignores the field and opens a plain root that
            # no policy decided. That session is ended; the run is refused.
            refusal = DeclaredRootRefused(
                "WL-APDP opened the session without confirming the declared "
                "root (it may not support declared roots), so the session was "
                "ended and the agent was not started.",
                code=DECLARED_ROOT_UNSUPPORTED,
            )
            await self._terminate_unstarted_session(session_id, refusal, run)
            raise refusal
        # The run's wl-proxy egress binding, if APDP issued a proxy token
        # for this session (the token itself stays in the backend).
        egress = egress_binding_for(self.apdp, run)
        # Server-minted ROOT run-handle id (present when wl-apdp has a
        # run-handle store). Presented on every authorize so runtime
        # Attenuate applies to the root run; ``None`` on older wl-apdp
        # → prior behaviour (client-minted id, never presented).
        root_run_handle_id = session.root_run_handle_id

        # Everything after the session create fails closed: if the run
        # cannot be set up completely, the session is terminated and the
        # run is refused. It never proceeds ungoverned or with direct
        # egress.
        try:
            # The run credential bounds the manifest by the run's grant.
            manifest = await self.apdp.get_manifest(agent_uuid, run=run)
            # A missing manifest refuses the run (before any egress is set
            # up) unless the operator explicitly opted into
            # WATCHLIGHT_PLAN_GOVERNANCE_MODE=degrade.
            governance_level = require_manifest(manifest, agent_id=agent_uuid)

            # wl-proxy CONNECT mode. A configured proxy URL is a promise
            # that this run's egress goes through wl-proxy, so a session
            # without an issued proxy token, or a sidecar that cannot be
            # installed, refuses the run instead of egressing directly.
            if self.connect_proxy_url:
                if egress is None:
                    raise GovernanceUnavailable(
                        "Watchlight is configured to route this agent's "
                        "egress through wl-proxy (connect_proxy_url / "
                        "WATCHLIGHT_PROXY_URL), but WL-APDP issued no proxy "
                        "token for the session, so the run was not started. "
                        "Check that wl-apdp is configured to issue proxy "
                        "tokens, or unset the proxy URL."
                    )
                from watchlight_core import SidecarRunActive, install_connect_proxy

                try:
                    install_connect_proxy(
                        self.connect_proxy_url,
                        egress.proxy_authorization(),
                        egress=egress,
                    )
                except SidecarRunActive:
                    raise
                except Exception as exc:  # noqa: BLE001 — fail closed below
                    raise GovernanceUnavailable(
                        "Watchlight could not install the wl-proxy CONNECT "
                        f"sidecar ({type(exc).__name__}), so the run was "
                        "not started (it would otherwise egress directly)."
                    ) from None
        except BaseException as exc:
            await self._terminate_unstarted_session(session_id, exc, run)
            raise

        self.last_governance_mode = governance_level
        self.last_session_id = session_id
        self.last_manifest = manifest

        if self.log_decisions:
            logger.info(
                "[GOVERNANCE-MODE] %s — session=%s manifest=%s agent=%s",
                self.last_governance_mode,
                session_id,
                bool(manifest),
                agent_uuid,
            )

        return RunHandle(
            plugin=self,
            agent_uuid=agent_uuid,
            session_id=session_id,
            run_handle_id=root_run_handle_id,
            server_run_handle=root_run_handle_id is not None,
            run=run,
            egress=egress,
            intent_objective=intent_objective,
            intent_provenance=intent_provenance,
            # Execution-lineage integrity — the server-minted canonical
            # `execution_id` so emitted events match the run the
            # backend's per-run credential authenticates.
            execution_id=session.execution_id,
        )

    async def _terminate_unstarted_session(
        self,
        session_id: str,
        exc: BaseException,
        run: Optional[RunRef] = None,
    ) -> None:
        """Best-effort close of a session whose run was refused during
        setup, so it does not stay ACTIVE server-side. The run closes it
        with its own credential (``complete_session``); agent credentials
        cannot terminate a session."""
        try:
            await self.apdp.complete_session(run)
        except Exception:  # noqa: BLE001 — the refusal is what matters
            logger.warning(
                "watchlight_pydantic_ai: could not close session %s after "
                "a refused run setup (%s).",
                session_id,
                type(exc).__name__,
            )

    @staticmethod
    def uninstall_instrumentation() -> None:
        """Restore the original ``pydantic_ai.Agent`` entry points.

        Convenience accessor on the plugin class so customers don't
        have to import :mod:`.instrumentation` directly. See
        :func:`watchlight_pydantic_ai.uninstall_instrumentation`.
        """
        from .instrumentation import uninstall_instrumentation

        uninstall_instrumentation()

    @staticmethod
    def supports_nested_runtime_instrumentation() -> bool:
        """Capability signal for the conformance harness.

        Returns ``True`` to indicate this plugin auto-instruments
        Pydantic AI's entry points so nested ``Agent.run()`` calls
        stitch into one lineage tree without customer-side
        spawn-primitive calls.

        The watchlight-core conformance harness reads this
        capability flag to opt the plugin into the nested-aware
        synthetic lifecycle in a future extension. Plugins that
        don't auto-instrument (most of the LangGraph / Bedrock
        family) return ``False`` (the default — they don't
        implement this method, so the harness's ``getattr(..., None)``
        check sees nothing).
        """
        return True
