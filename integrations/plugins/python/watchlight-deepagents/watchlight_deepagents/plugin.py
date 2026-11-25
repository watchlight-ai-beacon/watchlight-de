"""WatchlightDeepAgentsPlugin — governance for LangChain ``deepagents``.

``deepagents`` is LangChain's opinionated agent harness. Unlike raw
LangGraph (no global plugin protocol — extensibility is via graph
composition), ``deepagents`` standardises on the LangChain v1
``AgentMiddleware`` protocol and exposes a first-class ``middleware=``
insertion slot. So this plugin is **auto-registering**: the customer
swaps one import (``create_deep_agent`` → ``create_governed_deep_agent``)
or adds one ``middleware=[...]`` entry, and every model turn, tool call,
virtual-filesystem operation, and sub-agent spawn is governed with zero
tool-code changes.

This module owns the ``deepagents``-specific run lifecycle: the
:class:`WatchlightDeepAgentsPlugin` (session open, pre-flight manifest,
proxy-token + sidecar install — reused verbatim from the LangGraph
reference) and the :class:`RunHandle` subclass whose ``spawn_subagent``
override drives the strict-subset attenuation for the ``task`` tool.

Everything else — the APDP wire protocol, ``authorize_action``,
telemetry, the canonical event envelope, and the base ``spawn_subagent``
round-trip — is inherited from :mod:`watchlight_core`.
"""

from __future__ import annotations

import os
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Union
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
    get_logger,
    require_manifest,
    resolve_intent_enforcement_mode,
)
from watchlight_core.backend import RunRef, egress_binding_for
from watchlight_core.errors import DECLARED_ROOT_UNSUPPORTED
from watchlight_core.scope import ResourceMatcher

logger = get_logger("watchlight_deepagents")

#: ``metadata.source`` tag stamped on spawn-pair events emitted from this
#: module. The dashboard timeline classifier maps ``deepagents`` to the
#: ``plugin`` emitter chip; the source-attribution conformance invariant
#: asserts the prefix.
_SPAWN_PROVENANCE_TAG = "deepagents.spawn"

#: Source tag for ad-hoc observation events emitted via the base
#: ``publish_observation`` path (the source-attribution conformance
#: invariant).
_OBSERVATION_SOURCE = "deepagents.workload"


class RunHandle(BaseRunHandle):
    """``deepagents``-flavoured run handle.

    Inherits the lifecycle primitives (``authorize_action``,
    ``complete``, ``terminate``, the async context manager) from
    :class:`watchlight_core.BaseRunHandle`. Overrides ``spawn_subagent``
    to (a) resolve the child's registry *slug* to a canonical UUID and
    (b) emit the child ``execution_started`` so the ``/lineage`` view
    renders the delegation tree. The authoritative ``agent_spawn_observed``
    attestation is SERVER-emitted by wl-apdp's ``spawn_handler`` —
    the plugin no longer emits it. The server-side strict-subset validator
    still gates the spawn — the plugin only advises the requested
    scope and never becomes the enforcement authority.
    """

    _observation_source = _OBSERVATION_SOURCE

    # Delegation-tree linkage stamped by ``spawn_subagent`` for the
    # spawn-pair audit events. ``None`` on the root (non-spawned) handle.
    spawned_execution_id: Optional[str] = None
    #: Monotonic clock reading when this child was spawned (``None`` for
    #: a root run); the spawn's ``execution_completed`` reports the real
    #: elapsed time from it.
    spawn_started_at: Optional[float] = None

    async def spawn_subagent(  # type: ignore[override]
        self,
        child_agent_slug: Union[str, UUID],
        *,
        child_intent: Any,
        allowed_tools: Optional[List[str]] = None,
        allowed_resources: Optional[List[Union[ResourceMatcher, str]]] = None,
        allowed_intents: Optional[List[str]] = None,
        max_depth: Optional[int] = None,
        time_budget_seconds: Optional[int] = None,
        reason: Optional[str] = None,
    ) -> "RunHandle":
        """Open a governed sub-agent run under this handle.

        Resolves ``child_agent_slug`` (a registry slug) to a canonical
        UUID, then delegates the canonical ``POST /v1/spawn_subagent``
        round-trip + child-handle mint + contextvar bind to the base
        :meth:`watchlight_core.BaseRunHandle.spawn_subagent`. APDP's
        strict-subset validator gates the spawn server-side; a
        requested scope that is not a strict subset of this handle's is
        denied at APDP with :class:`ScopeAttenuationDenied` — the plugin
        cannot widen scope even if buggy.

        Empty / ``None`` scope kwargs are the **fail-closed default**:
        a parent that omits scope gets a
        zero-privilege child. The scope is declared per-subagent in
        plugin config (``subagent_scopes``), never inferred from the
        ``task`` tool call's free-text description.

        Args:
            child_agent_slug: The child agent's registry slug, or an
                already-resolved UUID.
            allowed_tools: The tools the child may invoke, named as the
                call's resource names them (``deepagents://tool/<name>``).
                An action verb (``read``, ``write``, ``execute``) never
                grants a tool. Empty = the child may invoke no tools.
            allowed_resources: :class:`ResourceMatcher` (or bare-string)
                resources the child may access. Empty = none.
            allowed_intents: Intent objectives the child may declare.
            max_depth: Maximum further spawn depth (``0`` = the child
                cannot spawn descendants).
            time_budget_seconds: Per-spawn time budget. ``None``
                inherits the parent's remaining time. A named budget is
                granted exactly or the spawn is refused (never clamped)
                when it is more than the parent can give.
            reason: Free-text justification for the spawn. Accepted for
                backward compatibility; the ``agent_spawn_observed`` event
                is now SERVER-attested, so this value is no longer
                stamped by the plugin.

        Returns:
            A live child :class:`RunHandle` bound to this parent, its
            ``granted_scope`` carrying APDP's server attestation. The
            child is also bound as the active sub-agent in the current
            asyncio task's contextvars so the child governance
            middleware authorizes against the child's handle.

        Raises:
            AgentNotRegistered: the child slug is not registered.
            ScopeAttenuationDenied: APDP rejected the requested scope
                (not a strict subset).
            AgentQuarantinedError: this parent handle is quarantined.
            WatchlightError: transport / non-canonical APDP response.
        """
        # Resolve slug → UUID unless the caller already passed a UUID.
        if isinstance(child_agent_slug, UUID):
            child_uuid = child_agent_slug
        else:
            try:
                child_uuid = UUID(str(child_agent_slug))
            except (ValueError, TypeError):
                resolved = await self._plugin.apdp.resolve_agent(str(child_agent_slug))
                if resolved is None:
                    raise AgentNotRegistered(
                        f"Sub-agent {child_agent_slug!r} is not registered "
                        f"with Watchlight. Register via wl-registry before "
                        f"spawning."
                    )
                child_uuid = UUID(resolved["id"])

        # Base override does the scope-attenuation envelope build, the APDP
        # strict-subset round-trip, the child-handle mint (as
        # ``type(self)`` so this subclass propagates), the ``_aentered``
        # flip, and the ``_current_subagent_handle`` bind.
        child = await super().spawn_subagent(
            child_uuid,
            child_intent=child_intent,
            allowed_tools=allowed_tools,
            allowed_resources=allowed_resources,
            allowed_intents=allowed_intents,
            max_depth=max_depth,
            time_budget_seconds=time_budget_seconds,
        )
        assert isinstance(child, RunHandle)

        # Emit the child's ``execution_started`` so wl-execution-graph
        # upserts the child tree row. Best-effort: observability must never
        # break governed work. The child's ``execution_started`` is emitted
        # here, so mark it emitted to suppress the SDK's defensive late-bind
        # mint.
        #
        # The ``agent_spawn_observed`` attestation is NOT emitted here — the
        # spawn lineage is SERVER-attested only: wl-apdp's
        # ``spawn_handler`` emits the single authoritative
        # ``agent_spawn_observed`` (carrying the server-validated
        # ``granted_scope`` and server-minted child execution id) while it
        # processes the ``POST /v1/spawn_subagent`` round-trip above. A
        # per-plugin spawn emission is redundant and is REJECTED at ingest
        # (``lineage_event_class_not_permitted``).
        child.spawned_execution_id = child.execution_id
        child.spawn_started_at = time.monotonic()
        await _emit_child_started(
            plugin=self._plugin,
            parent_execution_id=self.execution_id,
            child_session_id=child.session_id,
            child_agent_id=child.agent_uuid,
            child_execution_id=child.execution_id,
            # AUTO-CALCULATED depth — the base ``spawn_subagent`` mints the
            # child with ``parent_handle=self`` and a server-attested
            # ``granted_scope``, so ``child.depth`` is the real spawn-tree
            # depth (server-authoritative, else parent+1). Never a literal:
            # the old ``… else 1`` hardcode meant a base-minted child (whose
            # langgraph ``delegation_depth`` is never incremented on this
            # path) rendered as DEPTH 0 on the dashboard.
            child_depth=child.depth,
            root_execution_id=child.root_execution_id,
            tenant_id=getattr(self._plugin, "tenant_id", None),
            # Execution-lineage integrity — the child's own run.
            child_run=child.run,
        )
        child.mark_execution_started_emitted(child.execution_id)
        return child

    def _spawn_duration_ms(self) -> int:
        """Milliseconds since this child was spawned (``0`` when the
        spawn time is unknown)."""
        if self.spawn_started_at is None:
            return 0
        return max(0, int((time.monotonic() - self.spawn_started_at) * 1000))

    async def complete(self) -> None:
        """Close the session; emit ``execution_completed`` for spawns."""
        if not self._completed and self.spawned_execution_id is not None:
            self.mark_execution_completed_emitted()
            await _emit_spawn_lifecycle(
                plugin=self._plugin,
                event_type="execution_completed",
                execution_id=self.spawned_execution_id,
                agent_id=self.agent_uuid,
                session_id=self.session_id,
                parent_execution_id=self.parent_execution_id,
                root_execution_id=self.root_execution_id,
                tenant_id=getattr(self._plugin, "tenant_id", None),
                extra={
                    # Required by the canonical ExecutionCompletedPayload;
                    # without it /v1/events rejects the event (and its batch).
                    "duration_ms": self._spawn_duration_ms(),
                    "actions_taken": self._plugin.last_actions_allowed,
                    "actions_denied": self._plugin.last_actions_denied,
                },
                # Execution-lineage integrity — the child's own run.
                run=self.run,
            )
        await super().complete()

    async def terminate(self, reason: str = "manual") -> None:
        """Abnormal close; emit ``execution_failed`` for spawns."""
        if not self._completed and self.spawned_execution_id is not None:
            self.mark_execution_failed_emitted()
            await _emit_spawn_lifecycle(
                plugin=self._plugin,
                event_type="execution_failed",
                execution_id=self.spawned_execution_id,
                agent_id=self.agent_uuid,
                session_id=self.session_id,
                parent_execution_id=self.parent_execution_id,
                root_execution_id=self.root_execution_id,
                tenant_id=getattr(self._plugin, "tenant_id", None),
                extra={"error": reason[:240], "policy_denied": False},
                # Execution-lineage integrity — the child's own run.
                run=self.run,
            )
        await super().terminate(reason=reason)


async def _emit_child_started(
    *,
    plugin: "WatchlightDeepAgentsPlugin",
    parent_execution_id: str,
    child_session_id: str,
    child_agent_id: str,
    child_execution_id: str,
    child_depth: int,
    root_execution_id: Optional[str],
    tenant_id: Optional[str],
    child_run: Optional[RunRef] = None,
) -> None:
    """Publish the child ``execution_started`` for a governed spawn.

    The ``agent_spawn_observed`` attestation is NO LONGER emitted from the
    plugin. Spawn lineage is SERVER-attested only: wl-apdp's
    ``spawn_handler`` emits the single authoritative ``agent_spawn_observed``
    (carrying the server-validated ``granted_scope`` and the server-minted
    child execution id) while it processes the ``POST /v1/spawn_subagent``
    round-trip. A per-plugin spawn emission is redundant, forgeable, and
    REJECTED at ``/v1/events`` ingest (``lineage_event_class_not_permitted``)
    — so this helper emits only the child's own ``execution_started``,
    attributed to the CHILD's per-run ``sst_`` credential.

    Failures are swallowed — observability is best-effort and must never
    break the governed call.
    """
    now_iso = datetime.now(timezone.utc).isoformat()
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
        "payload": {
            "principal": {"principal_type": "agent", "id": child_agent_id},
            "depth": child_depth,
        },
    }
    try:
        # Child-attributed start → CHILD credential.
        await plugin.apdp.publish_events(child_run, [started_event])
    except Exception:  # noqa: BLE001 — observability is best-effort
        logger.debug("spawn_subagent: event emission failed", exc_info=True)


async def _emit_spawn_lifecycle(
    *,
    plugin: "WatchlightDeepAgentsPlugin",
    event_type: str,
    execution_id: str,
    agent_id: str,
    session_id: str,
    parent_execution_id: Optional[str],
    root_execution_id: Optional[str],
    tenant_id: Optional[str],
    extra: Dict[str, Any],
    run: Optional[RunRef] = None,
) -> None:
    """Publish a terminal lifecycle event for a spawned sub-agent."""
    event = {
        "event_id": f"evt_{uuid.uuid4()}",
        "event_type": event_type,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "execution_id": execution_id,
        "agent_id": agent_id,
        "session_id": session_id,
        "tenant_id": tenant_id,
        "parent_execution_id": parent_execution_id,
        "root_execution_id": root_execution_id,
        "metadata": {
            "source": _SPAWN_PROVENANCE_TAG,
            "kind": f"child_{event_type.split('_', 1)[1]}",
        },
        "payload": dict(extra),
    }
    try:
        # Child-attributed lifecycle → CHILD credential.
        await plugin.apdp.publish_events(run, [event])
    except Exception:  # noqa: BLE001 — observability is best-effort
        logger.debug("spawn lifecycle emission failed", exc_info=True)


class WatchlightDeepAgentsPlugin(GovernanceTelemetry):
    """Governance plugin for LangChain ``deepagents``.

    Construct directly, or use :meth:`from_env` (the plug-and-play
    path). Bind governance to an agent via :meth:`middleware` (returns a
    ready-to-insert ``AgentMiddleware``) or via the
    :func:`watchlight_deepagents.create_governed_deep_agent` factory.
    """

    def __init__(
        self,
        apdp_url: str = "http://localhost:8081",
        tenant_id: Optional[str] = None,
        apdp_api_key: Optional[str] = None,
        log_decisions: bool = True,
        connect_proxy_url: Optional[str] = None,
        intent_enforcement_mode: Optional[str] = None,
        application_id: Optional[str] = None,
        child_intent_category: Optional[str] = None,
        governance: Optional[GovernanceBackend] = None,
    ) -> None:
        super().__init__()
        # The intent category declared for a ``task`` sub-agent whose
        # configured scope names no single intent (``None``: the parent's
        # own derived category, else ``DEFAULT_PLUGIN_CHILD_INTENT_CATEGORY``).
        # wl-apdp refuses a category outside the parent run's intent bounds.
        self.child_intent_category = child_intent_category
        # Credential precedence mirrors the LangGraph reference:
        #   1. explicit ``apdp_api_key`` kwarg (tests / legacy) wins;
        #   2. else a unified ``Credential.from_env()`` if present;
        #   3. else the unauthenticated client (pepper-less local).
        # Fail-soft on (2): a missing/malformed env credential degrades
        # to unauth so pepper-less local stacks still run — the server
        # is the authority and 401s if it requires a credential.
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
            # Developer-Edition / in-process seam, as in the LangGraph
            # plugin: use the caller-supplied GovernanceBackend (e.g.
            # watchlight_core.InProcessClient over the compiled
            # watchlight-engine) verbatim and skip the networked ApdpClient.
            # apdp_url / apdp_api_key are ignored in this mode.
            # SECURITY: a supplied backend bypasses ApdpClient's
            # channel-safety guard. The shipped InProcessClient is
            # network-free; a CUSTOM networked backend passed here MUST
            # enforce its own transport security (TLS).
            self.apdp = governance
        elif credential is not None:
            self.apdp = ApdpClient(apdp_url, credential=credential)
        else:
            self.apdp = ApdpClient(apdp_url, api_key=apdp_api_key)
        self.tenant_id = tenant_id
        self.log_decisions = log_decisions
        # Opt-in wl-proxy sidecar egress governance. ``None`` (default)
        # ⇒ direct egress. Env fallback: ``WATCHLIGHT_PROXY_URL``.
        self.connect_proxy_url = connect_proxy_url or os.getenv("WATCHLIGHT_PROXY_URL")
        # AI application attribution. The application every run
        # opened by this plugin belongs to; forwarded on session create
        # so wl-apdp binds it to the run credential. Explicit
        # configuration only — never inferred from prompts or names.
        # ``start_run(application_id=...)`` overrides per run. Env
        # fallback: ``WATCHLIGHT_APPLICATION_ID``. ``None`` / empty /
        # whitespace ⇒ unset, the field is not sent (an agent in exactly
        # one application needs nothing here). A non-UUID raises
        # ``ValueError`` here (client-side format check only — wl-apdp
        # stays the authority on membership).
        self.application_id = (
            resolve_application_id(application_id) or application_id_from_env()
        )
        self.intent_enforcement_mode = resolve_intent_enforcement_mode(
            intent_enforcement_mode
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

    @classmethod
    def from_env(cls) -> "WatchlightDeepAgentsPlugin":
        """Construct from the ≤3 required env knobs — fail loud on
        missing config.

        Required:
          - ``WATCHLIGHT_APDP_URL`` — the APDP endpoint.

        Optional:
          - ``WATCHLIGHT_TENANT_ID`` — tenant scope (required in
            multi-tenant deployments; APDP is the authority).
          - ``WATCHLIGHT_PROXY_URL`` — opt-in sidecar egress governance.
          - ``WATCHLIGHT_INTENT_ENFORCEMENT_MODE`` — ``brownfield``
            (default) / ``greenfield``.
          - ``WATCHLIGHT_APPLICATION_ID`` — the AI application the
            runs belong to (attribution; read in ``__init__``).
          - ``WATCHLIGHT_PLUGIN_TOKEN`` (+ tenant/kind claims) —
            resolved via ``Credential.from_env()`` in ``__init__``.

        Raises:
            GovernanceUnavailable: ``WATCHLIGHT_APDP_URL`` is unset —
                fail loud rather than silently defaulting to localhost
                and appearing to work while ungoverned.
        """
        apdp_url = os.getenv("WATCHLIGHT_APDP_URL")
        if not apdp_url:
            raise GovernanceUnavailable(
                "WATCHLIGHT_APDP_URL is not set. The deepagents governance "
                "plugin requires the APDP endpoint. Set WATCHLIGHT_APDP_URL "
                "(and WATCHLIGHT_TENANT_ID in multi-tenant deployments) "
                "before constructing the governed agent."
            )
        return cls(
            apdp_url=apdp_url,
            tenant_id=os.getenv("WATCHLIGHT_TENANT_ID"),
            connect_proxy_url=os.getenv("WATCHLIGHT_PROXY_URL"),
        )

    async def start_run(
        self,
        agent_slug: str,
        goal_id: Optional[str] = None,
        max_actions: Optional[int] = None,
        ttl_seconds: int = 3600,
        application_id: Optional[str] = None,
        declared_root: Optional[Sequence[str]] = None,
    ) -> RunHandle:
        """Open a governed run for the named agent.

        ``declared_root`` is set by the governance middleware inside
        :func:`watchlight_deepagents.root_run`, never by customer code: the
        root execution ids of the governed runs live in this process. The
        run opens only when the server confirms it decided the declared root
        (``Action::"open_declared_root"``); otherwise the session is closed
        and the run refused with :class:`watchlight_core.DeclaredRootRefused`.

        Resolves the slug → UUID, opens an APDP session, fetches the
        pre-flight ConstraintManifest, and (when opted in) installs the
        wl-proxy sidecar for out-of-process egress governance. Reused
        verbatim from the LangGraph reference ``start_run``.

        ``application_id``: the AI application this run belongs to.
        wl-apdp checks the agent is a member of it and refuses
        the session otherwise; an agent in exactly one application needs
        nothing here. Defaults to the plugin-level ``application_id``
        (constructor kwarg, else ``WATCHLIGHT_APPLICATION_ID``). The
        application is bound to the run credential and to every
        sub-agent the run spawns.

        Fail-closed:
          - Unknown slug → :class:`AgentNotRegistered`.
          - APDP unreachable / rejects the session → :class:`GovernanceUnavailable`.
        """
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
            metadata={"framework": "deepagents", "tenant_id": self.tenant_id},
            # Only when set, so an older watchlight-agent-sdk still works.
            **({"application_id": app_id} if app_id is not None else {}),
            **({"declared_root": list(declared_root)} if declared_root is not None else {}),
        )
        if session is None:
            raise GovernanceUnavailable(
                "WL-APDP did not accept the session create. Check that APDP "
                "is reachable and the data plane is configured."
            )
        session_id = session.session_id
        root_run_handle_id = session.root_run_handle_id

        # Everything after the session create fails closed: if the run
        # cannot be set up completely (missing manifest, egress that
        # cannot be governed, or any other error, including
        # cancellation), the session it opened is closed and the
        # failure propagates. It never proceeds ungoverned.
        try:
            if declared_root is not None and not session.declared_root:
                # An older server ignores the field and opens a plain root
                # no policy decided: the session is closed below.
                raise DeclaredRootRefused(
                    "WL-APDP opened the session without confirming the "
                    "declared root (it may not support declared roots), so "
                    "the session was closed and the agent was not started.",
                    code=DECLARED_ROOT_UNSUPPORTED,
                )
            # Fetch the pre-flight manifest FIRST — it carries the
            # ``governed_proxy_hosts`` allowlist the sidecar needs, and the
            # fetch goes direct to wl-apdp (NO_PROXY-bypassed) before the
            # sidecar exists.
            # The run credential bounds the manifest by the run's grant.
            manifest = await self.apdp.get_manifest(agent_uuid, goal_id=goal_id, run=session.run)
            # A missing manifest refuses the run unless the operator
            # explicitly opted into WATCHLIGHT_PLAN_GOVERNANCE_MODE=degrade.
            governance_level = require_manifest(manifest, agent_id=agent_uuid)

            # Fail closed: with a wl-proxy URL configured, egress MUST go
            # through it. No issued proxy token, or a sidecar that fails to
            # start, refuses the run (never direct egress).
            egress = egress_binding_for(self.apdp, session.run)
            if self.connect_proxy_url:
                if egress is None:
                    raise GovernanceUnavailable(
                        "A wl-proxy URL is configured but WL-APDP issued no proxy "
                        "token for this session; refusing to run with direct egress."
                    )
                from watchlight_core import SidecarRunActive, install_sidecar

                try:
                    install_sidecar(
                        self.connect_proxy_url,
                        egress.proxy_authorization(),
                        governed_proxy_hosts=(manifest or {}).get(
                            "governed_proxy_hosts"
                        ),
                        ca_cert=os.getenv("WATCHLIGHT_PROXY_CA_CERT"),
                        egress=egress,
                    )
                except SidecarRunActive:
                    raise
                except Exception as e:  # noqa: BLE001 — any failure refuses
                    raise GovernanceUnavailable(
                        "The wl-proxy CONNECT sidecar could not be installed "
                        f"({type(e).__name__}); refusing to run with direct "
                        "egress."
                    ) from None

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
                # Execution-lineage integrity — the run (its per-run `sst_`
                # credential stays in the backend), its egress binding, and
                # the server-minted canonical `execution_id` so emitted
                # events match the run the credential authenticates.
                run=session.run,
                egress=egress,
                execution_id=session.execution_id,
            )
        except BaseException as exc:
            try:
                await self.apdp.complete_session(session.run)
            except Exception as e:  # noqa: BLE001 — best-effort close
                logger.warning(
                    "closing refused session %s failed: %s (%s)",
                    session_id,
                    type(e).__name__,
                    type(exc).__name__,
                )
            raise

    def middleware(
        self,
        agent_slug: str,
        *,
        subagent_scopes: Optional[Dict[str, Dict[str, Any]]] = None,
        subagent_slugs: Optional[Dict[str, str]] = None,
    ) -> Any:
        """Return the **root-only** governance ``AgentMiddleware`` to
        insert into ``create_deep_agent(middleware=[...])`` — the "Option
        B" path for customers who build their own ``middleware=`` list.

        **Governs the root agent only. Refuses sub-agent spawns.**
        deepagents composes a sub-agent's middleware as
        ``base_stack + spec["middleware"]``; the root ``middleware=`` list
        is *not* propagated to sub-agents, and deepagents auto-adds an
        ``general-purpose`` sub-agent whose stack never inherits our
        ``watchlight_governance`` slot. This method receives no
        ``subagents=`` reference, so it **cannot** inject child governance
        and cannot prove a spawned child is attenuated. To stay
        fail-closed, the root
        middleware therefore **refuses every ``task`` sub-agent spawn** at
        runtime. If this agent delegates to sub-agents, construct it with
        :func:`watchlight_deepagents.create_governed_deep_agent` — the
        single governed-construction path that injects child governance
        into every spawnable sub-agent.

        Args:
            agent_slug: The registered Watchlight slug for this agent.
                Resolved server-side to a UUID — never inferred from the
                model's prompt or tool arguments.
            subagent_scopes: Accepted for signature parity with the
                factory but **inert on this path** — sub-agent spawns are
                refused (see above). Declare scopes via
                ``create_governed_deep_agent`` instead.
            subagent_slugs: Same parity note as ``subagent_scopes``.

        The ``deepagents`` framework surface (``AgentMiddleware``) is
        imported lazily here so ``import watchlight_deepagents`` works
        without ``deepagents`` installed (e.g. for the stub-based unit
        tests); the import is required only when actually binding.
        """
        from .middleware import build_governance_middleware

        return build_governance_middleware(
            plugin=self,
            agent_slug=agent_slug,
            subagent_scopes=subagent_scopes or {},
            subagent_slugs=subagent_slugs or {},
            is_child=False,
            # Option B cannot inject child governance into sub-agents, so
            # child governance is NOT guaranteed → the root middleware
            # refuses ``task`` spawns (fail-closed).
            child_governance_guaranteed=False,
        )


__all__ = ["WatchlightDeepAgentsPlugin", "RunHandle"]
