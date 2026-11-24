"""WatchlightLangGraphPlugin — governance for LangGraph plan-and-execute agents.

Unlike the Google ADK plugin which hooks via ``BasePlugin`` callbacks,
LangGraph doesn't have a global plugin protocol — its extensibility is
via graph composition. So this plugin exposes **explicit primitives**
the customer threads into their graph wherever makes sense for their
topology:

- ``start_run(agent_slug, goal_id=None)`` — open APDP session, fetch
  manifest, return a :class:`RunHandle` the customer keeps for the
  duration of the graph invocation.
- ``handle.submit_plan(plan)`` — call after the planner node runs;
  returns the validation outcome so the graph can branch on
  Allow / Modify / Deny.
- ``handle.preflight_step(action, resource)`` — call before each tool
  node; returns whether the step is permitted (read-only, no audit).
- ``handle.authorize_action(action, resource)`` — authoritative authz
  call (counts toward budget, writes to audit chain).
- ``handle.complete()`` — call at end of run; closes the APDP session.

The lifecycle implementation lives in :class:`watchlight_core.BaseRunHandle`;
:class:`RunHandle` here is a thin LangGraph-flavoured subclass kept for
historical import compatibility (the shared lifecycle logic was extracted
into ``watchlight_core``).

Errors / result wrappers / ``governance_mode`` / ``ApdpClient`` /
``normalize_plan`` all live in :mod:`watchlight_core`. This module owns
only the LangGraph-specific surface: the ``WatchlightLangGraphPlugin``
class and the ``RunHandle`` subclass.
"""

import asyncio
import uuid
import warnings
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union
from uuid import UUID

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from watchlight_core import (
    InProcessClient,
    RunGrant,
    AgentNotRegistered,
    ApdpClient,
    application_id_from_env,
    resolve_application_id,
    BaseRunHandle,
    GovernanceBackend,
    GovernanceTelemetry,
    GovernanceUnavailable,
    PlanResult,
    get_logger,
    PreflightResult,
    WatchlightError,
    governance_mode,
    require_manifest,
)
from watchlight_core import attribution
from watchlight_core import langchain_backstop
from watchlight_core.backend import RunRef, egress_binding_for
from watchlight_core.scope import ResourceMatcher

from .callbacks import (
    WatchlightAsyncCallbackHandler,
    WatchlightCallbackHandler,
    fresh_execution_id,
    reset_active_handler,
    set_active_handler,
)
from . import tool_gate
from .tool_gate import publish_tool_gate_refusals
from .synthetic_tools import (
    build_synthetic_langchain_tools,
    merge_customer_tools_with_synthetic,
    should_skip_authorize_for_tool_call,
)

logger = get_logger("watchlight_langgraph")

# Source tag stamped on AgentSpawnObserved / ExecutionStarted events
# emitted from this module. The dashboard timeline classifier maps
# anything containing ``langgraph`` to the ``plugin`` emitter chip.
_SPAWN_PROVENANCE_TAG = "langgraph.spawn"


# ─── Legacy `delegation_scope` → canonical scope kwargs ──────────


# Whitelisted canonical scope kwarg names — used by
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
    scope kwargs.

    Behavior matrix:

    - ``delegation_scope is None`` → pass the canonical kwargs through
      verbatim.
    - ``delegation_scope`` set AND any canonical scope kwarg set → raise
      :class:`ValueError`. The two surfaces are mutually exclusive.
    - ``delegation_scope`` set alone → emit
      :class:`DeprecationWarning` AND map fields:

        ``delegation_scope["allowed_actions"]`` → ``allowed_tools``
        ``delegation_scope["allowed_intents"]`` → ``allowed_intents``
        ``delegation_scope["allowed_resources"]`` → ``allowed_resources``

      Any other legacy keys are silently dropped (they were once
      free-form audit metadata).

    Returns the reconciled ``(allowed_tools, allowed_resources,
    allowed_intents)`` triple. ``max_depth`` and
    ``time_budget_seconds`` are NEVER inferred from the legacy dict
    (they were not part of the legacy surface) — callers must pass
    them explicitly or accept the fail-closed default. Prefer
    fail-closed over inferring scope, on security grounds.
    """
    if delegation_scope is None:
        return (allowed_tools, allowed_resources, allowed_intents)

    # Detect mixed use. ``None`` defaults are accepted (the caller
    # is using only the legacy path); any explicit list / int is a
    # signal the caller is half-migrated.
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
            "canonical kwargs ("
            + ", ".join(_CANONICAL_SCOPE_KWARGS)
            + ") are the supported surface. Passing both is a sign of a "
            "half-migrated call site — pick one. Migrating? "
            f"Replace delegation_scope={{'allowed_actions': [...], "
            f"'allowed_intents': [...]}} with allowed_tools=[...] + "
            f"allowed_intents=[...]. (You mixed delegation_scope with "
            f"{mixed_kwargs}.)"
        )

    # Emit the deprecation signal once per call site.
    warnings.warn(
        "spawn_subagent: ``delegation_scope`` is deprecated and will be "
        "removed in a future release. Migrate to the canonical "
        "kwargs: allowed_tools, allowed_resources, allowed_intents, "
        "max_depth, time_budget_seconds. See "
        "the CHANGELOG for the field mapping.",
        DeprecationWarning,
        stacklevel=3,
    )

    # Fail-closed mapping on security grounds: missing
    # keys → empty list (NOT widened to None which the canonical
    # path would interpret as fail-closed-empty anyway, but
    # explicitness here protects against future flow changes).
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
    """LangGraph-flavoured run handle.

    Inherits the lifecycle primitives (``submit_plan``,
    ``preflight_step``, ``authorize_action``, ``complete``,
    ``terminate``, async context manager) from
    :class:`watchlight_core.BaseRunHandle`. Adds the LangGraph-
    specific helper for attaching a Watchlight callback handler
    that captures and publishes canonical execution events, and the
    ``spawn_subagent`` primitive for governed multi-agent delegation
    trees.
    """

    #: Provenance tag stamped on every ad-hoc observation event emitted
    #: via :meth:`watchlight_core.BaseRunHandle.publish_observation`.
    #: Identifies LangGraph workloads on the canonical event stream.
    _observation_source = "langgraph.workload"

    # Delegation tree linkage stamped by ``spawn_subagent``. Read by
    # callers that need to populate ``parent_execution_id`` on
    # downstream events; ``None`` for top-level (non-spawned) handles.
    parent_execution_id: Optional[str] = None
    parent_agent_id: Optional[str] = None
    delegation_depth: int = 0
    # The workflow root execution id. Set on the orchestrator's
    # top-level handle immediately after ``start_run``; inherited by
    # every spawned child so the whole agent tree's ``lineage.
    # executions`` rows reference the SAME root. Without this, the
    # /lineage view treats each spawned sub-agent as its own root in
    # the recent-executions list and the graph for any selected
    # sub-agent only shows its own subtree (with the orchestrator
    # missing).
    root_execution_id: Optional[str] = None
    # The child's execution_id captured at spawn time so ``complete()``
    # can emit a paired ``execution_completed`` event. Without this,
    # spawned sub-agents stayed in ``started`` status forever in the
    # lineage graph because no completion event closed them out.
    spawned_execution_id: Optional[str] = None
    spawn_started_at: Optional[float] = None
    # ContextVar token for the callback handler this handle attached
    # via :meth:`callback_handler`. Reset on ``complete`` / ``terminate``
    # so the attachment lives exactly as long as the run does.
    _callback_attach_token: Optional[Any] = None
    # The root's attribution binding made by ``__aenter__``.
    _root_bind_token: Optional[Any] = None
    # The run's mark for the provider SDK gate and the LangChain model-call
    # check: set on the run's context and counted as a live
    # governed run from ``async with`` entry until the run ends (see
    # ``watchlight_core.langchain_backstop``).
    _hosted_gate_run: Optional[Any] = None

    async def __aenter__(self) -> "RunHandle":
        tool_gate.install()
        entered = await super().__aenter__()
        try:
            self._attach_hosted_gate()
        except BaseException:
            await super().__aexit__(None, None, None)
            raise
        if self._parent_handle_ref is None:
            # A root entered in another context than the one start_run
            # returned it to acts there too. A sub-agent is bound by
            # spawn_subagent.
            self._root_bind_token = attribution.bind_run(self)
        return entered

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> bool:
        token, self._root_bind_token = self._root_bind_token, None
        try:
            # While still entered: lineage is only published from an
            # entered run (the ungoverned-request gate).
            await publish_tool_gate_refusals(self)
            return await super().__aexit__(exc_type, exc_val, exc_tb)
        finally:
            # Even when cancelled mid-publish: the run stops counting as live.
            self._release_hosted_gate()
            if token is not None:
                try:
                    attribution.unbind_run(token)
                except ValueError:
                    pass  # exited in another context; the run is closed anyway

    def _attach_hosted_gate(self) -> None:
        """Mark this run's context: every provider request made in it is
        decided by the provider SDK gate, and every LangChain model call in
        it must use a known or allowed chat model class. Counts the run as
        live. Refuses the run when a wrap is not in place."""
        self._release_hosted_gate()
        self._hosted_gate_run = langchain_backstop.enter_run(
            self,
            run_loop=asyncio.get_running_loop(),
            registered_mcp_servers=getattr(self._plugin, "registered_mcp_servers", None),
            allowed_model_classes=getattr(self._plugin, "allowed_model_classes", None),
        )

    def _release_hosted_gate(self) -> None:
        """Undo :meth:`_attach_hosted_gate`. Idempotent."""
        run, self._hosted_gate_run = self._hosted_gate_run, None
        if run is not None:
            langchain_backstop.leave_run(run)

    async def spawn_subagent(
        self,
        child_agent_slug: str,
        *,
        # REQUIRED — the child's own intent and goal, derived from this
        # run's (``ChildIntent`` or its dict form). wl-apdp refuses a spawn
        # without one.
        child_intent: Any,
        # Canonical scope-attenuation kwargs. Empty / ``None`` =
        # fail-closed defaults — a parent that omits scope gets a
        # zero-privilege child.
        allowed_tools: Optional[List[str]] = None,
        allowed_resources: Optional[
            List[Union[ResourceMatcher, str]]
        ] = None,
        allowed_intents: Optional[List[str]] = None,
        max_depth: Optional[int] = None,
        time_budget_seconds: Optional[int] = None,
        # Execution-lineage integrity. These lineage hints are now
        # IGNORED and accepted only so existing call sites don't break:
        # the child's parent-exec + root + execution_id are
        # SERVER-derived from the parent's VERIFIED `sst_` credential (the
        # parent-exec is this handle's own `execution_id`), never
        # client-supplied. A caller can no longer stitch a child onto a
        # different tree by passing a foreign `parent_execution_id`.
        parent_execution_id: Optional[str] = None,
        child_execution_id: Optional[str] = None,
        intent: Optional[Dict[str, Any]] = None,
        reason: Optional[str] = None,
        # DEPRECATED — legacy scope dict. Mapped onto the canonical
        # kwargs above with a :class:`DeprecationWarning`. Mixing
        # ``delegation_scope`` with the canonical kwargs raises
        # :class:`ValueError` — see the migration note in the plugin
        # changelog.
        delegation_scope: Optional[Dict[str, Any]] = None,
    ) -> "RunHandle":
        """Open a governed sub-agent run under this handle.

        The full lifecycle for a single spawn:

        1. Call ``POST /v1/spawn_subagent`` (via the shared
           :meth:`BaseRunHandle._perform_spawn_apdp_roundtrip`
           helper) with the canonical scope-attenuation envelope.
           wl-apdp's strict-subset validator gates the spawn; on
           success the server mints a child ``run_handle_id`` carrying
           the server-attested ``granted_scope``. The older path of
           calling ``plugin.start_run(child_slug)`` is RETIRED — it
           opened a fresh session without scope validation, which
           bypassed scope enforcement at depth N.
        2. Mint a fresh :class:`RunHandle` whose ``session_id`` is
           the child ``run_handle_id`` and whose ``granted_scope``
           carries the server's attestation. The child is bound to
           THIS parent via the parent-chain so a quarantine on the
           child bubbles UP.
        3. Stamp ``parent_execution_id`` + ``parent_agent_id`` +
           ``delegation_depth`` + ``root_execution_id`` on the child
           handle so downstream ``authorize_action`` and event-emit
           calls propagate the workflow linkage on every event.
        4. Emit ``execution_started`` on the CHILD so the Watchlight
           lineage service's builder upserts the proper tree row.
           The ``agent_spawn_observed`` attestation is SERVER-emitted by
           wl-apdp's spawn handler — the plugin does not emit it (it is
           rejected at ``/v1/events`` ingest).
        5. Bind the child as the active sub-agent in the current
           asyncio task's ``contextvars`` copy so the plugin's
           tool-call interceptors authorize against the sub-agent's
           handle, not the root's — a sub-agent must never be
           authorized with its parent's authority.

        Args:
            child_agent_slug: The registry slug of the child agent
                (e.g. ``"agent-data-collector"``). Resolved to a
                canonical UUID via the plugin's ``apdp.resolve_agent``
                before the spawn round-trip.
            allowed_tools: Cedar action UIDs / tool slugs the child
                may invoke. Empty / ``None`` = fail-closed (no
                tools).
            allowed_resources: :class:`ResourceMatcher` instances
                (or bare strings, coerced to ``{"matcher": ...}``)
                the child may access. Empty = no resources.
            allowed_intents: Intent objectives the child may
                declare. Empty = no intents.
            max_depth: Maximum further spawn depth. ``None`` →
                fail-closed (0 = child cannot spawn descendants).
            time_budget_seconds: Per-spawn time budget in seconds.
                ``None`` → the child inherits the parent's remaining
                time, bounded by the tenant threshold, never more.
                ``0`` is refused as unsatisfiable.
            parent_execution_id: The parent's current execution_id
                — typically the workflow root for the orchestrator,
                or the parent agent's most-recent execution id for
                deeper spawns. Used to stamp the spawn-pair audit
                events with proper tree linkage.
            child_intent: REQUIRED. The child's intent and goal
                (:class:`watchlight_core.ChildIntent` or its dict form):
                the intent ``category`` within this run's intent bounds,
                the ``objective`` this run gives the child, and an optional
                ``max_actions`` no larger than this run's remaining budget.
            child_execution_id: Optional explicit id for the child.
                Defaults to a freshly-generated ``exec_<uuid>``.
            intent: Optional intent declaration. Accepted for backward
                compatibility; the ``agent_spawn_observed`` event is now
                SERVER-attested, so the plugin no longer stamps
                this onto an audit payload. For per-spawn enforcement,
                pass the objective via ``allowed_intents`` so wl-apdp's
                strict-subset validator gates the child's intent
                declarations.
            reason: Free-text justification. Accepted for backward
                compatibility; the ``agent_spawn_observed`` event is now
                SERVER-attested, so this value is no longer stamped
                by the plugin.
            delegation_scope: **DEPRECATED.** Legacy scope dict
                with legacy field names (``allowed_actions`` →
                ``allowed_tools``, ``allowed_intents`` carries
                through). Emits :class:`DeprecationWarning` when
                used alone; raises :class:`ValueError` if mixed
                with the canonical kwargs. Will be removed in a
                future major version.

        Returns:
            A live :class:`RunHandle` bound to the child agent,
            ready for ``authorize_action`` calls. Caller owns the
            handle's lifecycle — wrap in ``async with`` or call
            ``complete()`` / ``terminate()`` explicitly.

        Raises:
            ValueError: when ``delegation_scope`` is passed
                alongside any canonical scope kwarg
                (``allowed_tools`` / ``allowed_resources`` /
                ``allowed_intents`` / ``max_depth`` /
                ``time_budget_seconds``). The two surfaces are
                exclusive — mixing them obscures the operator's
                read of effective scope at the call site.
            AgentQuarantinedError: when this parent handle is in
                ``QUARANTINED`` state — a quarantined agent has no
                authority to delegate.
            ScopeAttenuationDenied: when wl-apdp's strict-subset
                validator rejected the requested scope.
            RunHandleInvalidated: when wl-apdp rejected because the
                parent's RunHandle is no longer valid.
            WatchlightError: on transport errors or any
                non-canonical wl-apdp response.
        """
        # Step -1 — quarantine short-circuit. MUST come before the
        # resolve_agent call so a quarantined agent cannot probe the
        # registry for sibling agent ids. The base class enforces this
        # for the canonical kwargs path; the override must enforce it
        # at the same point because the plugin's flow runs additional
        # APDP-side work (slug resolution, audit emission) before the
        # canonical roundtrip.
        from watchlight_core.decision import (
            AgentQuarantinedError as _Quar,
            RunHandleState as _State,
        )

        if self._state == _State.QUARANTINED:
            assert self._quarantine_decision is not None
            self._fire_kill_signal()
            raise _Quar.from_decision(self._quarantine_decision)

        # Step 0 — reconcile the deprecated ``delegation_scope`` dict
        # with the canonical scope kwargs. The two surfaces are mutually
        # exclusive — mixing them widens the operator's surface area
        # without a clear win. On security grounds, when the legacy
        # dict is ambiguous (missing keys), prefer fail-closed mapping
        # (empty list) over inferring scope from prompts.
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

        # Step 1 — resolve the child's slug to a canonical UUID.
        # APDP's spawn handler expects a UUID (not a slug); the
        # resolution is the same code path ``start_run`` uses.
        resolved = await self._plugin.apdp.resolve_agent(child_agent_slug)
        if resolved is None:
            raise AgentNotRegistered(
                f"Sub-agent {child_agent_slug!r} is not registered with "
                f"Watchlight. Register via wl-registry's /api/v1/agents/"
                f"register before spawning."
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
        # `sst_` credential and returns the typed
        # :class:`SpawnSubagentResponse`.
        #
        # Execution-lineage integrity. The child's tree position is NO
        # LONGER client-supplied. wl-apdp derives the child's
        # parent-exec + root from the parent's VERIFIED credential
        # and SERVER-mints the child ``execution_id`` — returning it (plus
        # the child ``sst_`` credential + the tree root) here. The plugin's
        # own ``execution_started`` emission reuses the SERVER id so the
        # dashboard renders one child row; the ``agent_spawn_observed``
        # attestation is emitted server-side by wl-apdp's spawn handler.
        # Never let a new child take over a context where another live
        # sub-agent acts: its calls would then be made with the new
        # child's authority.
        tool_gate.refuse_live_sibling(self)

        response = await self._perform_spawn_apdp_roundtrip(
            child_uuid,
            child_intent=child_intent,
            allowed_tools=allowed_tools,
            allowed_resources=allowed_resources,
            allowed_intents=allowed_intents,
            max_depth=max_depth,
            time_budget_seconds=time_budget_seconds,
        )
        # Adopt the SERVER-derived lineage. The parent-exec the server
        # bound the child under is THIS handle's execution_id (the parent
        # token's `eid`); the root comes back on the response.
        child_exec_id = response.child_execution_id or fresh_execution_id()
        effective_parent_execution_id = self.execution_id
        effective_root_execution_id = (
            response.root_execution_id or self.root_execution_id
        )

        # Step 4 — mint the LangGraph-flavoured child handle. The
        # child's ``session_id`` is the child_run_handle_id: the current
        # protocol does NOT carry a separate APDP session for
        # sub-agents — the run_handle_id IS the session-equivalent
        # identifier wl-apdp uses to bind authorize-time
        # scope-membership checks.
        child_handle_id = response.child_run_handle_id
        # Execution-lineage integrity. The child's
        # ``session_id`` MUST equal the ``sid`` claim inside its own
        # ``sst_`` credential — the server mints both as
        # ``ses_<child-run-handle>`` and returns the value as
        # ``child_session_id`` precisely so the ``/v1/events`` binding
        # gate's ``session_id == sid`` check holds. Using the bare
        # ``child_run_handle_id`` here (no ``ses_`` prefix) makes every
        # child event fail that gate with 409 ``lineage_event_identity_mismatch``.
        # Mirror the base ``BaseRunHandle.spawn_subagent`` derivation
        # (fallback covers a pre-field server).
        child_session_id = response.child_session_id or f"ses_{child_handle_id}"
        child = RunHandle(
            plugin=self._plugin,
            agent_uuid=str(child_uuid),
            session_id=child_session_id,
            parent_handle=self,
            run_handle_id=child_handle_id,
            granted_scope=response.granted_scope,
            # Execution-lineage integrity. The child's OWN run (the
            # backend presents its server-minted `sst_` credential on
            # `/v1/events`), and the server-minted child `execution_id` +
            # the shared root so its events bind to the child session and
            # stitch under the parent's VERIFIED tree.
            run=RunRef(response.child_run),
            # The child session's own egress binding (never the
            # parent's).
            egress=egress_binding_for(self._plugin.apdp, RunRef(response.child_run)),
            execution_id=child_exec_id,
            root_execution_id=effective_root_execution_id,
            parent_execution_id=effective_parent_execution_id,
            # Sub-agents inherit the parent run's goal (one goal per tree).
            goal_id=self._goal_id,
        )
        child._derived_intent = response.derived_intent
        # Sub-agent handles minted via the plugin override are
        # returned to the caller without an explicit ``async with``
        # block. Flip the fail-closed flag so the first
        # ``authorize_action_detailed`` on the child doesn't raise
        # :class:`watchlight_core.WatchlightContractError`. The
        # ``_emit_child_started`` call below emits the canonical
        # ``execution_started`` for the child via the LangGraph
        # spawn translator, which means the SDK's defensive
        # late-binding mint in ``authorize_action_detailed`` is a
        # no-op for the child's spawned ``execution_id`` (good — no
        # duplicate event on the wire). We also mark the child's
        # spawned execution_id as already emitted so the child's
        # subsequent ``authorize_action`` doesn't double-emit.
        child._aentered = True

        # Step 5 — stamp the workflow tree-linkage on the child
        # handle so downstream ``authorize_action`` and event-emit
        # calls propagate the parent→child relationship. The
        # parent-exec is THIS handle's execution_id (the value the
        # server bound the child under — the parent token's `eid`).
        child.parent_execution_id = effective_parent_execution_id
        child.parent_agent_id = self.agent_uuid
        child.delegation_depth = self.delegation_depth + 1
        child.root_execution_id = effective_root_execution_id
        import time as _time
        child.spawned_execution_id = child_exec_id
        child.spawn_started_at = _time.monotonic()

        # Step 6 — emit the child ``execution_started`` so the
        # Watchlight lineage service upserts the child tree row. Best-effort:
        # observability failures must never break governed work.
        #
        # The ``agent_spawn_observed`` attestation is NO LONGER emitted
        # here — spawn lineage is SERVER-attested only: wl-apdp's spawn
        # handler emits the single authoritative
        # ``agent_spawn_observed`` (carrying the server-validated
        # ``granted_scope`` and server-minted child execution id) while it
        # processes the ``POST /v1/spawn_subagent`` round-trip above. A
        # per-plugin spawn emission is redundant and is REJECTED at ingest
        # (``lineage_event_class_not_permitted``).
        await _emit_child_started(
            plugin=self._plugin,
            parent_execution_id=effective_parent_execution_id,
            child_session_id=child.session_id,
            child_agent_id=child.agent_uuid,
            child_execution_id=child_exec_id,
            # Single auto-calculated source of truth (base ``self.depth``,
            # which the child inherits as parent+1 via ``parent_handle=self``).
            child_depth=child.depth,
            root_execution_id=child.root_execution_id,
            tenant_id=getattr(self._plugin, "tenant_id", None),
            # The child's own run.
            child_run=child.run,
            derived_intent=response.derived_intent,
        )
        # ``_emit_child_started`` published the canonical
        # ``execution_started`` event for ``child_exec_id``. Mark it as
        # already emitted so the SDK's defensive late-binding mint in
        # :meth:`BaseRunHandle.authorize_action_detailed` doesn't emit a
        # duplicate when the child's first authorize call lands.
        child.mark_execution_started_emitted(child_exec_id)

        # Step 7 — bind the child as the active sub-agent handle in
        # this asyncio task's contextvars copy so plugin
        # interceptors attribute tool calls to the sub-agent's
        # principal, not the root's — a sub-agent must never be
        # authorized with its parent's authority.
        #
        # A failed bind is NOT swallowed: without it, interceptors would
        # resolve the parent's handle and authorize the child's calls on
        # the parent's credential. Close the child and refuse the spawn.
        from watchlight_core.run_handle import _current_subagent_handle

        try:
            # The token lets the child's complete()/terminate() reset the
            # binding it made (core's token-based unbind).
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

        tool_gate.register(child)
        return child

    async def complete(self) -> None:
        """Close the APDP session cleanly + (for spawned handles)
        emit ``execution_completed`` for the spawn's own execution.

        For top-level (non-spawned) handles this is identical to
        :meth:`BaseRunHandle.complete`. For handles minted by
        :meth:`spawn_subagent`, we ALSO publish an
        ``execution_completed`` event so the Watchlight lineage service
        transitions the child's row in ``lineage.executions`` from
        ``started`` to ``completed``. Without this, sub-agents
        rendered as perpetually-Started in the lineage graph view —
        a UX-credibility hole rather than a correctness bug, but
        operators read "Started" as "in flight" and that's wrong.
        """
        if not self._completed and self.spawned_execution_id is not None:
            # Declare the lifecycle emission BEFORE the manual
            # publish so :meth:`BaseRunHandle.complete` (via
            # ``super().complete()`` below) does NOT also emit a
            # defensive ``execution_completed`` for the same
            # execution_id.
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
        # Release the context attachment before the session closes, so
        # no callback manager built after this run can still pick up
        # this run's handler.
        self.detach_callbacks()
        # A run never entered cannot publish lineage: its refusals held
        # anyway, and are counted and logged as unpublished.
        try:
            await publish_tool_gate_refusals(self)
            await super().complete()
        finally:
            self._release_hosted_gate()
            tool_gate.unregister(self)

    async def terminate(self, reason: str = "manual") -> None:
        """Abnormal close. Emit ``execution_failed`` for spawned
        handles so the lineage view reflects the bad path.
        """
        if not self._completed and self.spawned_execution_id is not None:
            # See complete() for rationale.
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
        # See complete(): the attachment is scoped to the run.
        self.detach_callbacks()
        try:
            await publish_tool_gate_refusals(self)
            await super().terminate(reason=reason)
        finally:
            self._release_hosted_gate()
            tool_gate.unregister(self)

    def _spawn_duration_ms(self) -> int:
        """Wall-clock ms since ``spawn_subagent`` minted this handle.

        Returns 0 if never spawned (i.e. someone called
        ``_spawn_duration_ms`` on a top-level handle by mistake);
        the lineage UI tolerates a 0 duration without misbehaving.
        """
        if self.spawn_started_at is None:
            return 0
        import time as _time
        return int((_time.monotonic() - self.spawn_started_at) * 1000)

    def bind_tools(
        self,
        model: Any,
        customer_tools: Optional[list] = None,
        *,
        mode: Optional[str] = None,
        **bind_kwargs: Any,
    ) -> Any:
        """Bind the customer's tools + Watchlight-managed synthetic
        tools to a LangChain chat model.

        When the agent's effective intent-enforcement mode is
        ``"greenfield"``, this method appends the
        :data:`watchlight_core.WATCHLIGHT_DECLARE_INTENT_TOOL`
        synthetic tool to the customer's tool list before calling
        ``model.bind_tools([...])``. In ``"brownfield"`` mode the
        synthetic tool is NOT injected and the call is wire-equivalent
        to ``model.bind_tools(customer_tools)``.

        The plugin's mode is read from:

        1. ``mode`` kwarg here (highest authority — operator override
           at the call site).
        2. ``WatchlightLangGraphPlugin(intent_enforcement_mode=...)``
           constructor kwarg.
        3. ``WATCHLIGHT_INTENT_ENFORCEMENT_MODE`` env var.
        4. ``"brownfield"`` — the default when nothing else is set.

        This governs only the synthetic tool. The customer's tools are
        passed through and re-bound to the same model unchanged; they are
        decided when they run, by the ``ToolNode`` tool gate or
        ``governed_tool_call``, not by binding them here.

        # Authorize-bypass carve-out

        The synthetic tool's invocation NEVER round-trips to
        :meth:`authorize_action` — see
        :mod:`watchlight_langgraph.synthetic_tools` for the
        rationale. The tool's ``func`` is a closure over THIS handle,
        so any sub-agent must call ``bind_tools`` on its OWN handle
        — passing the parent handle here would be a privilege
        escalation.

        Parameters
        ----------
        model:
            A LangChain chat model that exposes ``bind_tools`` (every
            ``BaseChatModel`` subclass does).
        customer_tools:
            The customer's tools as they would have passed to
            ``model.bind_tools(...)`` directly. ``None`` or empty
            list is accepted — useful for greenfield-only demos
            where the synthetic tool is the only tool the agent
            sees (the model declares intent and then the workflow
            graph routes downstream).
        mode:
            Override the plugin's configured mode for THIS bind call.
            See resolution order above.
        bind_kwargs:
            Forwarded to ``model.bind_tools(**bind_kwargs)`` so
            customer-side knobs (``tool_choice``,
            ``parallel_tool_calls``, ``strict``, …) flow through
            untouched.

        Returns
        -------
        Any
            The model returned by ``model.bind_tools([...])`` — same
            object the customer would otherwise have used. When the
            model has no ``bind_tools`` (a custom non-LangChain
            model), the model is returned unchanged AND a debug log
            line surfaces — the customer's run continues but the
            synthetic tool isn't bound. We deliberately don't raise
            on missing ``bind_tools`` because the plugin's other
            primitives (``authorize_action``, ``submit_plan``) still
            work and the operator may want a partial wiring.
        """
        # Resolve mode at call site so the customer can override per
        # bind. The plugin-level kwarg is the deployment default; the
        # call-site kwarg is the per-invocation override.
        effective_mode: Optional[str] = mode
        if effective_mode is None:
            effective_mode = getattr(
                self._plugin, "intent_enforcement_mode", None
            )

        merged = merge_customer_tools_with_synthetic(
            customer_tools=customer_tools,
            handle=self,
            mode=effective_mode,
        )

        bind = getattr(model, "bind_tools", None)
        if bind is None:
            # Non-LangChain model — return unchanged. The synthetic
            # tool will not fire because the model never sees it; the
            # customer's other governance hooks still work. This is
            # the rare path; logged at debug so operators can spot it
            # without alarm.
            logger.debug(
                "model %s has no bind_tools(); synthetic tool not bound. "
                "Customer code continues unchanged.",
                type(model).__name__,
            )
            return model

        if not merged:
            # Nothing to bind — pass-through. Avoids calling
            # bind_tools([]) which some chat models reject.
            return model

        return bind(merged, **bind_kwargs)

    def synthetic_langchain_tools(
        self,
        *,
        mode: Optional[str] = None,
    ) -> list:
        """Return the LangChain :class:`StructuredTool` instances the
        plugin would inject for this handle, without calling
        ``bind_tools``.

        Customers who need the tools as a list (e.g., to compose a
        custom tool registry, or pass them to ``create_react_agent``
        via the ``tools=`` arg) call this directly. Equivalent to
        :func:`watchlight_langgraph.synthetic_tools.build_synthetic_langchain_tools(self, mode=mode)`.
        """
        effective_mode: Optional[str] = mode
        if effective_mode is None:
            effective_mode = getattr(
                self._plugin, "intent_enforcement_mode", None
            )
        return build_synthetic_langchain_tools(self, mode=effective_mode)

    def callback_handler(
        self,
        *,
        execution_id: Optional[str] = None,
        parent_execution_id: Optional[str] = None,
        async_handler: bool = False,
        otlp_exporter: Optional[Any] = None,
        declared_intent_objective: Optional[str] = None,
        attach: bool = True,
    ):
        """Return a Watchlight callback handler, attached to the
        current context so a host cannot displace it.

        By default the handler is installed through LangChain's
        ``register_configure_hook`` mechanism, which a caller-supplied
        ``callbacks`` list cannot override — see the "Undisplaceable
        attachment" note in :mod:`watchlight_langgraph.callbacks`. The
        customer does **not** have to pass the handler on the config
        any more::

            async with await wl.start_run("research-analyst") as handle:
                handler = handle.callback_handler(async_handler=True)
                result = await graph.ainvoke({"input": "..."})
                await handler.flush()

        Passing it explicitly still works and is still supported for a
        handler scoped to one graph or one invocation; the ambient one
        stands down for that call so events are captured exactly once.

        Args:
            execution_id: The Watchlight execution id to attribute
                captured events to. Defaults to **this handle's own
                ``execution_id``** — the canonical root of the run.
                The SDK's ``__aenter__`` already emits an
                ``execution_started`` for ``handle.execution_id`` and
                every ``authorize_action`` attaches its
                ``policy_decision_made`` to the same id; defaulting the
                callback stream to that id keeps the framework's
                ``execution_started`` + the SDK's + every
                ``tool_call_observed`` on ONE canonical root, so a
                single ``lineage.executions`` row materialises for the
                run. Minting a *fresh* id here (the pre-fix behaviour)
                split the run into TWO root rows — an orphan
                (``handle.execution_id``, root-only, no tools) plus the
                real tree under the fresh id. Pass an explicit value
                ONLY for a genuinely separate execution — e.g. a
                spawned sub-agent's own ``execution_id`` (the
                divergence is intentional there: a child IS a distinct
                execution).
            parent_execution_id: For nested runs (sub-agent
                spawned by a parent), the parent's execution id.
                Lands on every captured event under the same
                key so the delegation tree can be reconstructed
                downstream.
            async_handler: ``True`` returns the
                :class:`WatchlightAsyncCallbackHandler` (use this
                for ``ainvoke`` / ``astream``); ``False`` (default)
                returns the synchronous handler.
            declared_intent_objective: Customer-declared intent
                override. When set, the handler stamps the canonical
                ``execution_started`` payload with this objective +
                :attr:`IntentProvenance.DECLARED` — the highest-
                authority lane in the intent precedence chain (declared
                > plugin-derived > absent). When ``None`` (default),
                the plugin-derived extractor reads from
                ``on_chain_start.inputs`` and stamps
                :attr:`IntentProvenance.PLUGIN_DERIVED` if anything
                is recoverable, otherwise leaves the canonical
                payload's intent fields unset (Cedar treats this
                as :attr:`IntentProvenance.ABSENT`).
            attach: ``True`` (default) installs the handler on the
                current context via the configure hook, so every
                callback manager built until this handle closes picks
                it up regardless of what the caller passes as
                ``callbacks``. The attachment is released by this
                handle's :meth:`complete` / :meth:`terminate`, i.e. on
                ``async with`` exit — it is scoped to the run, not to
                the process. Pass ``False`` for a handler you intend to
                attach yourself (an explicit ``callbacks`` list, or
                :func:`watchlight_langgraph.callbacks.attached_handler`
                for a block-scoped attachment).

        Returns:
            A handler instance with session/agent/tenant already
            bound, attached to the current context unless
            ``attach=False``.

        The handler is **stateful** per execution. Use a fresh
        handler per run; don't share across concurrent runs.
        """
        tenant_id = getattr(self._plugin, "tenant_id", None)
        # Default to THIS handle's canonical execution_id — NOT a fresh
        # one. See the ``execution_id`` arg docstring: a fresh id here
        # orphans the run into two root ``lineage.executions`` rows.
        exec_id = execution_id or self.execution_id
        handler_cls = (
            WatchlightAsyncCallbackHandler if async_handler else WatchlightCallbackHandler
        )
        handler = handler_cls(
            apdp_client=self._plugin.apdp,
            execution_id=exec_id,
            agent_id=self.agent_uuid,
            session_id=self.session_id,
            tenant_id=tenant_id,
            parent_execution_id=parent_execution_id,
            otlp_exporter=otlp_exporter,
            declared_intent_objective=declared_intent_objective,
            # Wire the owning handle so the callback's
            # ``flush()`` can declare its lifecycle emissions on the
            # handle BEFORE publishing them. Suppresses the SDK's
            # defensive ``execution_completed`` / ``execution_failed``
            # emit from :meth:`BaseRunHandle.complete` /
            # :meth:`BaseRunHandle.terminate` so no row in
            # ``lineage.executions`` ends up with two lifecycle events
            # for the same logical close.
            run_handle=self,
        )
        if attach:
            self._attach_callback_handler(handler)
        return handler

    def _attach_callback_handler(self, handler: Any) -> None:
        """Install ``handler`` on the current context for the rest of
        this handle's life.

        Replaces any handler this handle attached earlier (a caller
        that asks for a second handler gets the second one, not both),
        and records the ContextVar token so :meth:`detach_callbacks`
        can put the context back the way it found it.
        """
        self.detach_callbacks()
        token = set_active_handler(handler)
        if token is None:
            # `set_active_handler` only returns None when
            # langchain_core has no `register_configure_hook`. The
            # handler still works if the customer passes it on the
            # config, but that attachment is displaceable — say so at
            # warning level rather than leaving a governed-looking run
            # that isn't.
            logger.warning(
                "Watchlight callback handler could not be attached via the "
                "langchain_core configure hook; it will only capture events "
                "if you pass it explicitly on the invocation config, and a "
                "host that supplies its own callbacks will drop it."
            )
            return
        self._callback_attach_token = token

    def detach_callbacks(self) -> None:
        """Release the context attachment made by
        :meth:`callback_handler`. Idempotent; safe to call on a handle
        that never attached one."""
        token = getattr(self, "_callback_attach_token", None)
        if token is None:
            return
        self._callback_attach_token = None
        reset_active_handler(token)


async def _emit_child_started(
    *,
    plugin: "WatchlightLangGraphPlugin",
    parent_execution_id: str,
    child_session_id: str,
    child_agent_id: str,
    child_execution_id: str,
    child_depth: int,
    root_execution_id: Optional[str],
    tenant_id: Optional[str],
    child_run: Optional[RunRef] = None,
    derived_intent: Optional[Dict[str, Any]] = None,
) -> None:
    """Publish the child ``execution_started`` for one governed spawn.

    ``derived_intent`` is the intent wl-apdp derived for the child at the
    spawn: its category is stamped, and its objective with its provenance
    (at most ``plugin_derived``) when that provenance is above ``absent``.

    The ``agent_spawn_observed`` attestation is NO LONGER emitted from the
    plugin. Spawn lineage is SERVER-attested only: wl-apdp's spawn handler
    emits the single authoritative ``agent_spawn_observed``
    (carrying the server-validated ``granted_scope`` and the server-minted
    child execution id) while it processes the ``POST /v1/spawn_subagent``
    round-trip. A per-plugin spawn emission is redundant, forgeable, and
    REJECTED at ``/v1/events`` ingest (``lineage_event_class_not_permitted``)
    — so this helper emits only the child's own ``execution_started``,
    authenticated by the CHILD's per-run ``sst_`` credential.

    Failures are logged at debug and swallowed; observability is
    best-effort and must never break the governed call site.
    """
    now_iso = datetime.now(timezone.utc).isoformat()

    started_event = {
        "event_id": f"evt_{uuid.uuid4()}",
        "event_type": "execution_started",
        "timestamp": now_iso,
        # The child's first heartbeat — its OWN execution_id, with
        # parent_execution_id set so the Watchlight lineage service
        # upserts a proper child row in ``lineage.executions`` (depth =
        # parent+1 courtesy of the builder's upsert mutation).
        #
        # ``root_execution_id`` is propagated from the orchestrator's
        # root all the way down so every row in the agent tree has
        # the SAME root. Without this, the recent-executions list
        # shows each sub-agent as a separate root and the
        # graph-for-selected-root only walks downward from the
        # selected node.
        "execution_id": child_execution_id,
        "agent_id": child_agent_id,
        "session_id": child_session_id,
        "tenant_id": tenant_id,
        "parent_execution_id": parent_execution_id,
        "root_execution_id": root_execution_id,
        "metadata": {"source": _SPAWN_PROVENANCE_TAG, "kind": "child_started"},
        "payload": {
            "principal": {"principal_type": "agent", "id": child_agent_id},
            "depth": child_depth,
        },
    }
    if isinstance(derived_intent, dict):
        payload = started_event["payload"]
        category = derived_intent.get("intent_category")
        if isinstance(category, str) and category:
            payload["intent_category"] = category
        provenance = derived_intent.get("provenance")
        objective = derived_intent.get("objective")
        if (
            provenance in ("plugin_derived", "proxy_inferred")
            and isinstance(objective, str)
            and objective
        ):
            payload["intent_objective"] = objective
            payload["intent_provenance"] = provenance

    try:
        # Child-attributed execution start → CHILD credential.
        await plugin.apdp.publish_events(child_run, [started_event])
    except Exception:  # noqa: BLE001 — observability is best-effort
        logger.debug("spawn_subagent: event emission failed", exc_info=True)


async def _emit_spawn_execution_completed(
    *,
    plugin: "WatchlightLangGraphPlugin",
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
    both keys on the floor. The dashboard timeline read them for
    months and never saw a value.

    Neither fact is lost by removing them, because both already land
    by a canonical route:

    - the spawner rides the ENVELOPE's ``parent_agent_id`` — the
      field ``EventEnvelope`` models for exactly this, which
      ``BaseRunHandle`` already stamps on every event it emits and
      which is covered by the lineage signature;
    - the depth is computed SERVER-side by wl-execution-graph from
      the child's ``execution_started`` and its tree position, and
      served on ``lineage.executions.depth``. A self-reported depth
      on a completion would be an emitter claim about the agent's own
      authority; the projection's value is platform-computed.

    Best-effort: emission failures are logged at debug and swallowed.
    """
    event = {
        "event_id": f"evt_{uuid.uuid4()}",
        "event_type": "execution_completed",
        "timestamp": datetime.now(timezone.utc).isoformat(),
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
    plugin: "WatchlightLangGraphPlugin",
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
        "timestamp": datetime.now(timezone.utc).isoformat(),
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


class WatchlightLangGraphPlugin(GovernanceTelemetry):
    """Governance plugin for LangGraph plan-and-execute agents.

    Usage::

        wl = WatchlightLangGraphPlugin(apdp_url="http://localhost:8081")

        async def run_agent(question: str) -> dict:
            async with await wl.start_run(agent_slug="research-analyst") as handle:
                state = await graph.ainvoke({"input": question})
                result = await handle.submit_plan(state["plan"])
                if result.is_deny():
                    raise PermissionError(f"Plan denied: {result.violations}")
                if result.is_modify():
                    state["plan"] = result.modified_plan
                return state
    """

    #: Invariant 19: every provider-hosted tool a model call in a governed
    #: run sends is authorized before the request is sent, by the provider
    #: SDK gate (``watchlight_core.provider_sdk_gate``). The conformance
    #: hook sends the probe through the ``openai`` SDK, which the gate reads
    #: as ``openai``.
    supports_hosted_tools = True
    hosted_tool_provider: Optional[str] = "openai"

    async def conformance_hosted_tool_call(self, probe: Any) -> None:
        """Invariant 19: one governed model call of ``probe.request``."""
        await _conformance_hosted_tool_call(probe)

    def __init__(
        self,
        apdp_url: str = "http://localhost:8081",
        tenant_id: Optional[str] = None,
        apdp_api_key: Optional[str] = None,
        log_decisions: bool = True,
        connect_proxy_url: Optional[str] = None,
        intent_enforcement_mode: Optional[str] = None,
        governance: Optional[GovernanceBackend] = None,
        application_id: Optional[str] = None,
        registered_mcp_servers: Optional[Dict[str, str]] = None,
        allowed_model_classes: Optional[List[str]] = None,
    ):
        # GovernanceTelemetry.__init__ initialises the seven last_* attrs.
        super().__init__()
        # Remote MCP servers a model call may enable: server URL -> the name
        # policy sees as ``Resource::"mcp://<name>/"``. A server not listed
        # refuses the model call before any decision.
        self.registered_mcp_servers: Optional[Dict[str, str]] = registered_mcp_servers
        # Chat model classes ("module:ClassName") a governed run may use
        # beyond the known ones, whose requests go through a provider SDK
        # the gate wraps. Each is logged when a run opens.
        self.allowed_model_classes = sorted(langchain_backstop.model_class_names(allowed_model_classes))
        # Authentication precedence for the ApdpClient:
        #   1. An explicit ``apdp_api_key=`` kwarg (legacy / tests) wins.
        #   2. Otherwise, if a unified credential is present in the
        #      environment (``WATCHLIGHT_PLUGIN_TOKEN`` + the kind-specific
        #      claims), load it via ``Credential.from_env()`` so the
        #      client emits ``Authorization: Bearer`` and
        #      ``X-Wl-Credential-Kind`` (no tenant header) — the
        #      headers wl-apdp's pepper-gated ``routed_auth_middleware``
        #      requires once a credential pepper is loaded.
        #   3. Otherwise fall back to the unauthenticated client (local
        #      / dev deployments where wl-apdp runs without a pepper and
        #      the data plane uses the legacy anonymous auth_middleware).
        #
        # Fail-soft on (2): a missing/malformed env credential must not
        # crash construction — we degrade to the unauthenticated path so
        # pepper-less local stacks still run. The server is the
        # authority; if it requires a credential it will 401, which the
        # plugin already surfaces as GovernanceUnavailable.
        credential = None
        if apdp_api_key is None:
            try:
                from watchlight_core import Credential, CredentialNotFound

                try:
                    credential = Credential.from_default()
                except CredentialNotFound:
                    credential = None
                except Exception:  # noqa: BLE001 — malformed env → unauth
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
        # WL-Proxy CONNECT mode. When set AND wl-apdp issues
        # a proxy token for the session, the plugin auto-installs an
        # httpx interceptor in start_run that routes all outbound
        # HTTPS through this URL with Proxy-Authorization. **Zero
        # customer agent-code changes** — the customer's workflow
        # makes normal httpx calls; this plugin transparently adds
        # the proxy + auth.
        #
        # Env-var fallback: WATCHLIGHT_PROXY_URL.
        # `None` (default): CONNECT mode OFF; outbound HTTPS goes
        # direct.
        import os as _os
        self.connect_proxy_url = connect_proxy_url or _os.getenv(
            "WATCHLIGHT_PROXY_URL"
        )
        # AI application attribution. The application every run
        # opened by this plugin belongs to; forwarded on session create
        # so wl-apdp binds it to the run credential. Explicit
        # configuration only — never inferred from prompts or names.
        # ``start_run(application_id=...)`` overrides per run. Env
        # fallback: ``WATCHLIGHT_APPLICATION_ID``. ``None`` / empty /
        # whitespace ⇒ unset, the field is not sent. A non-UUID raises
        # ``ValueError`` here (client-side format check only — wl-apdp
        # stays the authority on membership). The in-process engine
        # (Developer Edition) refuses the field: attribution is an
        # Enterprise feature.
        self.application_id = (
            resolve_application_id(application_id) or application_id_from_env()
        )
        # Intent enforcement mode. Resolves once at plugin
        # construction so every RunHandle minted from this plugin
        # inherits the same default. The
        # :meth:`RunHandle.bind_tools` call-site kwarg can override
        # per invocation; this field is the deployment-wide default.
        # Resolution chain (highest-authority first):
        #   1. constructor kwarg here
        #   2. ``WATCHLIGHT_INTENT_ENFORCEMENT_MODE`` env var
        #   3. ``"brownfield"`` (the default)
        # See :func:`watchlight_core.resolve_intent_enforcement_mode`.
        from watchlight_core import resolve_intent_enforcement_mode
        self.intent_enforcement_mode = resolve_intent_enforcement_mode(
            intent_enforcement_mode
        )

        # Kill-signal registry. Defaults ON: in-process cancellation
        # is free until an interceptor registers a request, whereas
        # leaving it unwired makes the BaseRunHandle quarantine
        # transition a SILENT no-op. Proxy-side hard-kill escalation
        # stays opt-in — assign a registry built with
        # ``httpx_hard_kill_escalator`` to enable it. Set to ``None``
        # to disable interruption entirely. The CONNECT sidecar picks
        # the registry up at ``install_connect_proxy`` time.
        from watchlight_core import default_kill_signal_registry

        self.kill_signal_registry = default_kill_signal_registry()

    async def start_run(
        self,
        agent_slug: str,
        goal_id: Optional[str] = None,
        max_actions: Optional[int] = None,
        ttl_seconds: int = 3600,
        subject_token: Optional[str] = None,
        application_id: Optional[str] = None,
    ) -> "RunHandle":
        """Open a governed run for the named agent.

        Resolves the slug to a UUID via ``/agents/resolve``, opens an
        APDP session, fetches the constraint manifest. Returns a
        :class:`RunHandle` the customer threads through their graph.

        ``subject_token``: an identity-provider token (an OIDC ID token) for
        the end user this run acts on behalf of. wl-apdp verifies it and
        binds the user to the run and every sub-agent it spawns. Obtaining
        the token is the application's job; the SDK only presents it.

        ``application_id``: the AI application this run belongs to.
        wl-apdp checks the agent is a member of it and refuses the
        session otherwise; an agent in exactly one application needs
        nothing here. Defaults to the plugin-level ``application_id``
        (constructor kwarg, else ``WATCHLIGHT_APPLICATION_ID``). The
        application is bound to the run credential and to every
        sub-agent the run spawns.

        Fail-closed:
          - Unknown slug → raises :class:`AgentNotRegistered`
          - APDP unreachable → raises :class:`GovernanceUnavailable`
        """
        # Every tool LangGraph's ToolNode runs in this run is decided
        # before it runs, and every other tool start is refused while the
        # run is live. If that cannot be put in place, the run is
        # refused: the plugin never falls back to only observing.
        tool_gate.install()

        # Reset per-run telemetry. Stale state from a prior run must
        # never bleed into the current run's governance card.
        self._reset_telemetry()

        resolved = await self.apdp.resolve_agent(agent_slug)
        if resolved is None:
            raise AgentNotRegistered(
                f"Agent '{agent_slug}' is not registered with Watchlight. "
                f"Register the agent before invoking it."
            )
        agent_uuid = resolved["id"]

        # Empty / whitespace ⇒ unset (the plugin default applies); a
        # non-UUID raises before any session is opened.
        app_id = resolve_application_id(application_id) or self.application_id
        session = await self.apdp.create_session(
            agent_id=agent_uuid,
            goal_id=goal_id,
            max_actions=max_actions,
            ttl_seconds=ttl_seconds,
            metadata={"framework": "langgraph", "tenant_id": self.tenant_id},
            # Only when set, so an older watchlight-agent-sdk still works.
            **({"subject_token": subject_token} if subject_token is not None else {}),
            **({"application_id": app_id} if app_id is not None else {}),
        )
        if session is None:
            raise GovernanceUnavailable(
                "WL-APDP did not accept the session create. Check that "
                "APDP is reachable and the data plane is configured."
            )
        session_id = session.session_id
        # The run's opaque reference. Its per-run ``sst_`` credential (the
        # one presented on ``POST /v1/events``, never the shared tenant
        # bearer) and its wl-proxy token stay inside the governance
        # backend; this plugin and its handle name the run only.
        run = session.run

        # The server-minted ROOT run-handle id, if wl-apdp minted one for
        # this root run (deployment has a run-handle store). When present,
        # the root handle presents this id on every authorize so runtime
        # Attenuate applies to the ROOT run — not only to spawned
        # sub-agents. Absent on older wl-apdp: ``None`` → the root
        # auto-mints a client-side id it never presents (Cedar governs).
        root_run_handle_id = session.root_run_handle_id

        try:
            return await self._open_run_handle(
                agent_uuid=agent_uuid,
                session_id=session_id,
                goal_id=goal_id,
                run=run,
                root_run_handle_id=root_run_handle_id,
                execution_id=session.execution_id,
            )
        except BaseException:
            # The run is refused (or opening it failed in any other way,
            # including cancellation): close the session it opened so it
            # does not linger as a live, ungoverned credential.
            try:
                await self.apdp.complete_session(run)
            except Exception:  # noqa: BLE001 — the refusal below wins
                logger.warning(
                    "start_run: closing the refused session failed",
                    exc_info=True,
                )
            raise

    async def adopt_run(self, grant: RunGrant) -> "RunHandle":
        """Adopt a run a trusted launcher already opened.

        For an agent started inside an isolated workload (an OpenShell
        sandbox) by a launcher that holds the ``workload:bind`` credential.
        The launcher opened the run OUTSIDE the workload, bound to it, and
        handed this process only the run's :class:`RunGrant` (on stdin, or
        ``WATCHLIGHT_RUN_CREDENTIAL``). No slug is resolved and no session is
        opened here — the grant's run credential cannot do either. It is the
        only credential this plugin presents: wl-apdp admits it on this
        run's own authorize, manifest, plan, preflight and complete calls.

        ``grant``: required and explicit — read it with
        :meth:`RunGrant.from_stdin` (preferred) or :meth:`RunGrant.from_env`.
        There is no implicit default: a run credential is never picked up
        from the environment behind the caller's back.

        Fail-closed:
          - no or malformed grant → :class:`InvalidCredential`
          - the in-process engine (Developer Edition) → ``ValueError``:
            workload binding needs a Beacon launcher
          - a governance backend authenticating with anything but this
            grant → ``ValueError`` (the plugin must not mix a tenant token
            into a bound run)
        """
        self._reset_telemetry()
        if not isinstance(grant, RunGrant):
            raise ValueError(
                "adopt_run needs an explicit RunGrant (RunGrant.from_stdin() or RunGrant.from_env())"
            )
        if isinstance(self.apdp, InProcessClient):
            raise ValueError(
                "adopt_run needs a networked Beacon; the in-process engine "
                "(Developer Edition) has no launcher-bound runs"
            )
        credential = getattr(self.apdp, "credential", None)
        if credential is None or getattr(credential, "kind", None) != "run" or (
            credential.bearer_token != grant.session_token
        ):
            raise ValueError(
                "adopt_run: the governance client must authenticate with this run's "
                "grant (ApdpClient(url, credential=grant.credential())), never a "
                "plugin or service token"
            )
        # The grant's credentials move into the client's run table; the
        # handle names the run only.
        info = self.apdp.adopt_run_grant(grant)
        return await self._open_run_handle(
            agent_uuid=info.agent_id,
            session_id=info.session_id,
            goal_id=None,
            run=info.run,
            root_run_handle_id=info.root_run_handle_id,
            execution_id=info.execution_id,
        )

    async def _open_run_handle(
        self,
        *,
        agent_uuid: str,
        session_id: str,
        goal_id: Optional[str],
        run: RunRef,
        root_run_handle_id: Optional[str],
        execution_id: Optional[str],
    ) -> "RunHandle":
        """Shared tail of :meth:`start_run` and :meth:`adopt_run`: the
        manifest, the CONNECT sidecar and the handle."""

        # Auto-install the wl-proxy CONNECT local sidecar.
        #
        # The customer touches NO agent code. They set
        # `WATCHLIGHT_PROXY_URL` (or pass `connect_proxy_url=` to the
        # plugin) and wl-apdp issues the per-session JWT. The plugin
        # starts a tiny local HTTP CONNECT proxy on
        # `127.0.0.1:<dynamic>` and sets `HTTPS_PROXY` so EVERY
        # Python HTTP library that honors the env var (httpx,
        # requests, urllib3, aiohttp, openai-python,
        # anthropic-python, boto3, …) auto-routes its outbound HTTPS
        # through wl-proxy with `Proxy-Authorization: Bearer <token>`.
        # The customer's workflow makes normal HTTP calls; the
        # plugin handles routing + auth transparently.
        #
        # Conditions for install:
        #   1. `self.connect_proxy_url` is set (operator opted in)
        #   2. the backend gives the run an egress binding (wl-apdp
        #      issued a proxy token: `WL_PROXY_TOKEN_AUDIENCE` configured)
        #
        # When ``connect_proxy_url`` is unset, CONNECT mode is OFF.
        # When it IS set (the operator asked for governed egress), the
        # run refuses to start unless wl-apdp issued a proxy token AND
        # the sidecar comes up: a configured proxy must never silently
        # degrade to direct egress.
        # Fetch the pre-flight manifest FIRST — it carries the
        # governed_proxy_hosts allowlist the sidecar needs at spawn time
        # (which wl-proxy reverse-proxy / MCP hosts the session token may
        # be attached to on the plain-HTTP path). The fetch goes direct to
        # wl-apdp (NO_PROXY-bypassed), so it is safe before the sidecar is
        # installed.
        # The run credential bounds the manifest by the run's grant.
        manifest = await self.apdp.get_manifest(agent_uuid, goal_id=goal_id, run=run)
        # A missing manifest refuses the run unless the operator explicitly
        # opted into WATCHLIGHT_PLAN_GOVERNANCE_MODE=degrade.
        governance_level = require_manifest(manifest, agent_id=agent_uuid)

        egress = egress_binding_for(self.apdp, run)
        if self.connect_proxy_url and egress is None:
            raise GovernanceUnavailable(
                "A wl-proxy URL is configured (connect_proxy_url / "
                "WATCHLIGHT_PROXY_URL) but wl-apdp issued no proxy token for "
                "this session. Refusing the run rather than letting its "
                "egress go direct. Configure WL_PROXY_TOKEN_AUDIENCE on "
                "wl-apdp, or unset the proxy URL."
            )

        if self.connect_proxy_url and egress is not None:
            import os as _os

            from watchlight_core import SidecarRunActive, install_sidecar

            # Spawn the common wl-sidecar governance binary. It routes the
            # agent's outbound traffic through wl-proxy with the session
            # token attached — over TLS when connect_proxy_url is https://
            # (token never plaintext on the wire), and attaches the token
            # to plain-HTTP (MCP / reverse-proxy) calls ONLY for hosts in
            # the manifest's governed_proxy_hosts allowlist. Zero customer
            # code; the token is handed to the sidecar on stdin, never in
            # this process's argv/env or heap.
            try:
                install_sidecar(
                    self.connect_proxy_url,
                    egress.proxy_authorization(),
                    governed_proxy_hosts=(manifest or {}).get("governed_proxy_hosts"),
                    ca_cert=_os.getenv("WATCHLIGHT_PROXY_CA_CERT"),
                    egress=egress,
                )
            except SidecarRunActive:
                raise
            except Exception as exc:
                # Never continue with direct egress when governed egress
                # was configured. The token is never part of the message.
                raise GovernanceUnavailable(
                    "wl-sidecar could not be installed for governed egress "
                    f"({type(exc).__name__}); refusing the run."
                ) from exc

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

        handle = RunHandle(
            plugin=self,
            agent_uuid=agent_uuid,
            session_id=session_id,
            run_handle_id=root_run_handle_id,
            server_run_handle=root_run_handle_id is not None,
            run=run,
            egress=egress,
            # Execution-lineage integrity. Adopt the canonical root
            # ``execution_id`` wl-apdp minted server-side (bound into
            # BOTH the session token's ``eid`` claim and the proxy token) so
            # the run's emitted events carry the SAME id the ``/v1/events``
            # binding gate enforces — in wl-proxy AND non-proxy deployments
            # alike. ``None`` on an older server ⇒ the handle adopts
            # from the proxy token or self-mints (legacy).
            execution_id=execution_id,
            goal_id=goal_id,
        )
        # The run is open from here, entered or not: the tool gate and
        # the backstop see it, and it acts for this context (core's
        # attribution binding), so a graph run after a bare start_run is
        # decided for it, or refused, never run undecided.
        tool_gate.register(handle)
        attribution.bind_run(handle)
        return handle


# Re-export error types and result wrappers from core for backwards-
# compat with code that imports them from this module. The canonical
# definitions live in watchlight_core; do NOT re-implement here.
__all__ = [
    "WatchlightLangGraphPlugin",
    "RunHandle",
    "PlanResult",
    "PreflightResult",
    "WatchlightError",
    "AgentNotRegistered",
    "GovernanceUnavailable",
    "governance_mode",
]


class _ConformanceHandle:
    """The run handle under the hosted-tool conformance probe: the probe
    answers the hosted-tool decisions; anything else is refused."""

    async def authorize_action_detailed(self, *_args: Any, **_kw: Any) -> Any:
        from watchlight_core.results import AuthorizeResult

        return AuthorizeResult("deny", reason="conformance_probe_only")


class _ConformanceProbeChatModel(BaseChatModel):
    """The chat model the conformance hook runs: it sends its bound request
    through the ``openai`` SDK, whose transport hands the body actually sent
    to the probe's recording client."""

    client: Any = None
    request: Any = None

    @property
    def _llm_type(self) -> str:
        return "watchlight-conformance-probe"

    def _generate(self, *_a: Any, **_kw: Any) -> ChatResult:
        raise RuntimeError("the conformance probe model is async only")

    async def _agenerate(self, *_a: Any, **_kw: Any) -> ChatResult:
        await self.client.post("/responses", body=self.request, cast_to=object)
        return ChatResult(generations=[ChatGeneration(message=AIMessage(content=""))])


async def _conformance_hosted_tool_call(probe: Any) -> None:
    """Invariant 19: one LangChain chat model call of ``probe.request`` in a
    marked run, sent through the real ``openai`` SDK, so the provider SDK
    gate decides it as it decides every request in a run."""
    import json

    import openai
    from openai import _base_client

    hx = getattr(_base_client, "httpx2", None) or _base_client.httpx

    async def send(request: Any) -> Any:
        await probe.model_client.call(json.loads(request.content or b"{}"))
        return hx.Response(200, json={})

    client = openai.AsyncOpenAI(
        api_key="conformance-probe", max_retries=0, http_client=hx.AsyncClient(transport=hx.MockTransport(send))
    )
    run = langchain_backstop.enter_run(
        probe.wrap(_ConformanceHandle()),
        registered_mcp_servers=probe.registered_mcp_servers,
        allowed_model_classes=[f"{__name__}:_ConformanceProbeChatModel"],
    )
    try:
        await _ConformanceProbeChatModel(client=client, request=probe.request).ainvoke("probe")
    finally:
        langchain_backstop.leave_run(run)
        await client.close()
