"""Base run-handle lifecycle — used by LangGraph and Bedrock plugins.

A "run handle" represents one governed agent invocation:

- An APDP session has been opened (``session_id`` minted)
- A constraint manifest has been fetched (or attempted)
- The agent's slug has been resolved to a canonical UUID
- The plugin's ``last_*`` telemetry has been reset

Once the handle exists, the customer's code uses it to submit plans,
preflight steps, authorise actions, and finally complete or terminate
the session.

The contract is identical for any framework whose execution model is
"customer composes the topology, framework runs it" — that's
LangGraph (graph composition) and Bedrock (orchestrator + Lambda
action groups). ADK is different — it uses lifecycle callbacks, not
explicit primitives — and continues to handle this in
``watchlight_adk.plugin`` directly.

This module exposes:

- :class:`GovernedPlugin` — the Protocol describing what fields a
  framework plugin must expose to satisfy ``BaseRunHandle``.
- :class:`BaseRunHandle` — the concrete lifecycle implementation.
  Subclass to add framework-specific helpers (e.g.
  ``bedrock_agent_runtime()``).
"""

import asyncio
import contextvars
import uuid
import weakref
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, ClassVar, Dict, List, Optional, Protocol, Set, Tuple, Union
from uuid import UUID

from ._cedar_entities import shape_for_backend
from ._lineage_retry import lineage_decision_path, lineage_direct_attempt
from .apdp_client import ApdpClient
from .backend import EgressBinding, RunRef, egress_binding_for
from .decision import (
    AgentQuarantinedError,
    AgentRevokedError,
    Attenuation,
    Escalation,
    ExecutionTerminatedError,
    Observation,
    QuarantineDecision,
    RevokeDecision,
    RunHandleState,
    SeverSubtreeDecision,
    SubtreeSeveredError,
    TerminateDecision,
    parse_authorization_decision,
)
from .errors import WatchlightError
from .kill_signal import (
    LLM_CALL_INTERRUPTED_REASON_POLICY_TERMINATE,
    LLM_CALL_INTERRUPTED_REASON_QUARANTINE,
    LLM_CALL_INTERRUPTED_REASON_REVOKE,
    LLM_CALL_INTERRUPTED_REASON_SEVER_SUBTREE,
    InterceptorKillRegistry,
)
from .log import get_logger
from .plan import normalize_plan
from .results import AuthorizeResult, PlanResult, PreflightResult, authorize_response_problem
from .scope import (
    ChildIntent,
    GrantedScope,
    RequestedScope,
    ResourceMatcher,
    coerce_child_intent,
    spawn_subagent_request_to_dict,
)

logger = get_logger("watchlight_core.run_handle")


# Tag used in the ``metadata.source`` field of the
# ``execution_quarantined`` event emitted by ``BaseRunHandle`` when it
# transitions to the Quarantined state. Plugin authors can override by
# emitting the event themselves with a more specific source tag — the
# core emission is the load-bearing fallback so a quarantine ALWAYS
# leaves an audit trail regardless of which framework the plugin
# integrates.
_QUARANTINE_PROVENANCE_TAG = "watchlight_core.run_handle.quarantine"

#: Cap on side-effect-axis escalations retained on a handle (the
#: ``Escalate`` enforcement effect). Bounds memory on a long-lived
#: handle; the most-recent N are kept.
MAX_RECORDED_ESCALATIONS = 256
MAX_RECORDED_OBSERVATIONS = 256
MAX_RECORDED_ATTENUATIONS = 256


# Module-private :class:`contextvars.ContextVar` that carries
# the currently-active sub-agent :class:`BaseRunHandle` so concurrent
# spawns (``asyncio.gather`` from a parent into N sub-agents) keep
# scope isolated. ``contextvars`` are copied on task creation, so each
# spawned task sees ONLY its own sub-handle. The root agent's task
# sees ``None`` until it spawns a child.
#
# Plugins MAY read this via :func:`current_subagent_handle` to obtain
# the active sub-agent handle inside a task. The ``set`` /
# ``reset`` token pattern is owned by :meth:`BaseRunHandle.spawn_subagent`,
# which scopes the binding to the async-context the caller is running
# in via :class:`contextvars.copy_context`. Mirrors the Pydantic AI
# plugin's nested-handle pattern — the per-spawn handle
# stays attributable across an ``await``-boundary even when another
# spawn runs in a sibling task.
_current_subagent_handle: contextvars.ContextVar[
    Optional["BaseRunHandle"]
] = contextvars.ContextVar(
    "watchlight_core.run_handle._current_subagent_handle",
    default=None,
)


# Root-cause fix — public read-only contextvar carrying the lineage
# tier of the currently-active :class:`BaseRunHandle`.
#
# wl-proxy's CONNECT/MITM emitters need the orchestrator's
# ``execution_id`` so per-tunnel events
# (``tls_terminate_observed``, ``intent_inferred_observed``) and per-request
# events (``api_request_observed``) carry the correct identity instead of a
# freshly-minted ``exec_<uuid>`` fallback. wl-proxy takes that identity
# only from the verified claims of the run's proxy token; this
# contextvar is never written to a request header.
#
# Lifecycle:
# - The plugin's ``start_run`` (or sub-agent ``spawn_subagent``) helper
#   binds the contextvar to a :class:`HandleLineage` snapshot of the
#   active handle inside the framework's task context via
#   :func:`contextvars.copy_context` semantics.
# - Sub-agent contexts
#   override the orchestrator's binding so the sidecar emits HEADERS
#   matching the sub-agent's identity, NOT the root's. The contextvar
#   is copied on task creation so concurrent ``asyncio.gather`` of
#   N sub-agents each see their own binding.
# - ``None`` means no handle is active in this task; the sidecar then
#   does NOT inject headers and wl-proxy stamps
#   ``metadata.warning = "no_execution_context"`` on emitted events.
_current_handle_lineage: contextvars.ContextVar[
    Optional["HandleLineage"]
] = contextvars.ContextVar(
    "watchlight_core.run_handle._current_handle_lineage",
    default=None,
)


@dataclass(frozen=True)
class HandleLineage:
    """Immutable lineage-tier snapshot of an active :class:`BaseRunHandle`.

    Carries the four headers wl-proxy's CONNECT/MITM emitters need to
    populate the canonical event envelope's lineage tier. The plugin's
    CONNECT sidecar stamps these (validated server-side) onto every
    CONNECT request to wl-proxy.

    Frozen so a child's snapshot cannot mutate the parent's binding.

    Format invariants (validated server-side; misformatted values are
    dropped by wl-proxy and result in ``metadata.warning``):

    * ``execution_id`` — ``exec_<uuid>`` shape, required.
    * ``parent_execution_id`` — ``exec_<uuid>`` shape, optional.
    * ``root_execution_id`` — ``exec_<uuid>`` shape, optional;
      synthesized to ``execution_id`` when absent.
    * ``parent_agent_id`` — opaque slug, length-bounded.
    """

    execution_id: str
    parent_execution_id: Optional[str] = None
    root_execution_id: Optional[str] = None
    parent_agent_id: Optional[str] = None


def current_handle_lineage() -> Optional[HandleLineage]:
    """Return the active :class:`HandleLineage` for the current asyncio
    task, or ``None`` when no handle is bound in this context.

    Public read-only accessor. The CONNECT sidecar reads this at
    outbound-request time to stamp ``X-Wl-*`` headers onto CONNECT
    requests to wl-proxy. Plugins generally use
    :meth:`BaseRunHandle.activate_lineage` (the context-manager API)
    to bind the contextvar; calling :func:`set` on the underlying
    contextvar directly is reserved for SDK-internal code paths.
    """
    return _current_handle_lineage.get()


def _validate_execution_id(value: Optional[str]) -> Optional[str]:
    """Drop values that don't look like ``exec_<uuid>``.

    Mirrors the server-side execution-id validation. The check
    is permissive enough to accept any ``exec_`` prefix + 36-char tail
    of safe characters; wl-proxy does the strict UUID validation on
    receipt. This client-side guard prevents the sidecar from stamping
    blatantly malformed values onto outbound requests.
    """
    if value is None:
        return None
    if not isinstance(value, str):
        return None
    if not value.startswith("exec_"):
        return None
    # Length cap matches the server-side validation (5 prefix + 36 uuid = 41).
    if len(value) > 64:
        return None
    if any(c.isspace() or ord(c) < 0x20 for c in value):
        return None
    return value


def _validate_agent_id(value: Optional[str]) -> Optional[str]:
    """Drop control chars and oversize agent ids."""
    if value is None or not isinstance(value, str):
        return None
    if len(value) == 0 or len(value) > 128:
        return None
    if any(ord(c) < 0x20 for c in value):
        return None
    return value


def _coerce_allowed_resources(
    raw: Optional[List[Union[ResourceMatcher, str]]],
) -> List[ResourceMatcher]:
    """Normalise the SDK-facing ``allowed_resources`` kwarg.

    Customers MAY pass bare strings as a convenience (the SDK then
    wraps each into a :class:`ResourceMatcher` with the string as the
    matcher pattern). The canonical wire shape always emits the
    object form ``{"matcher": "..."}`` — the SDK ergonomics layer is
    the only place where bare strings live, mirroring
    :func:`watchlight_core.scope._coerce_resource_matchers` which
    does the same on the decode side.

    ``None`` → empty list (fail-closed default).
    """
    if not raw:
        return []
    out: List[ResourceMatcher] = []
    for entry in raw:
        if isinstance(entry, ResourceMatcher):
            out.append(entry)
        elif isinstance(entry, str):
            out.append(ResourceMatcher(matcher=entry))
        else:
            raise TypeError(
                f"allowed_resources entry must be ResourceMatcher or str, "
                f"got {type(entry).__name__}"
            )
    return out


def current_subagent_handle() -> Optional["BaseRunHandle"]:
    """Return the sub-agent :class:`BaseRunHandle` active for the
    current asyncio task, or ``None`` when no sub-agent has been
    spawned in this context.

    Public read-only accessor for the sub-agent contextvar. Plugins
    typically read this from a tool-call interceptor to decide which
    handle to authorize against — the sub-agent's handle is
    load-bearing and using the parent's instead is a privilege
    escalation.
    """
    handle = _current_subagent_handle.get()
    if handle is None:
        return None
    # A child that closed cleanly is never handed out again (a stale
    # binding can survive in a copied context). A child ended by a
    # policy decision IS returned: its own authorize raises the typed
    # error, so a caller never falls back to a laxer handle.
    if (
        getattr(handle, "_completed", False)
        and getattr(handle, "_state", None) == RunHandleState.COMPLETED
        and getattr(handle, "_run_end_decision", None) is None
    ):
        return None
    return handle



def _failing_fields_suffix(exc: BaseException) -> str:
    """`` (fields: a, b.c)`` naming only the response fields a parse
    failure is about (never their values), or the error class."""
    fields: List[str] = []
    if isinstance(exc, KeyError) and exc.args:
        fields.append(str(exc.args[0]))
    errors = getattr(exc, "errors", None)
    if callable(errors):
        try:
            for err in errors():
                loc = err.get("loc") if isinstance(err, dict) else None
                if loc:
                    fields.append(".".join(str(p) for p in loc))
        except Exception:  # noqa: BLE001 — fall back to the class
            fields = []
    if fields:
        return f" (fields: {', '.join(sorted(set(fields))[:10])})"
    return f" ({type(exc).__name__})"

class GovernedPlugin(Protocol):
    """Structural contract for plugins consumed by :class:`BaseRunHandle`.

    Implemented by :class:`watchlight_langgraph.WatchlightLangGraphPlugin`,
    :class:`watchlight_bedrock.WatchlightBedrockPlugin`, and any future
    explicit-primitives framework plugin.

    Telemetry attributes come from
    :class:`watchlight_core.GovernanceTelemetry`; declared here too so
    the Protocol is self-contained for type checkers.

    Plugins MAY expose ``kill_signal_registry`` (an
    :class:`watchlight_core.InterceptorKillRegistry`) so the
    :class:`BaseRunHandle` quarantine transition fires the kill switch
    against every in-flight LLM call originating from this plugin's
    process. ``None`` (or absent) means the plugin runs without the
    HTTP interceptor and the quarantine transition skips the
    in-process abort. Plugins that wire the CONNECT sidecar
    typically also wire a registry so the kill switch is composable
    with the existing interceptor lane.
    """

    apdp: ApdpClient
    tenant_id: Optional[str]
    log_decisions: bool

    last_governance_mode: str
    last_session_id: Optional[str]
    last_manifest: Optional[Dict[str, Any]]
    last_plan_validation: Optional[Dict[str, Any]]
    last_proposed_plan: Optional[Any]
    last_actions_allowed: int
    last_actions_denied: int

    # Optional per-plugin kill-signal registry. Use
    # ``getattr(plugin, "kill_signal_registry", None)`` rather than a
    # required attribute so legacy plugin code continues to work even
    # before it has been migrated to expose the registry.
    kill_signal_registry: Optional[InterceptorKillRegistry]


class _LineageActivation:
    """Sync + async context-manager that binds a :class:`HandleLineage`
    to the ``_current_handle_lineage`` contextvar and resets it on
    exit.

    Two-flavour support so plugins can use either ``with`` (sync
    framework lifecycle) or ``async with`` (asyncio task contexts).
    Re-binding inside a nested ``async with`` (e.g. orchestrator →
    sub-agent) MUST scope correctly — the token-reset pattern
    delivers that automatically.
    """

    def __init__(self, lineage: HandleLineage) -> None:
        self._lineage = lineage
        self._token: Optional[contextvars.Token] = None

    def __enter__(self) -> HandleLineage:
        self._token = _current_handle_lineage.set(self._lineage)
        return self._lineage

    def __exit__(self, *_: Any) -> None:
        if self._token is not None:
            _current_handle_lineage.reset(self._token)
            self._token = None

    async def __aenter__(self) -> HandleLineage:
        return self.__enter__()

    async def __aexit__(self, *_: Any) -> None:
        self.__exit__()


class BaseRunHandle:
    """Concrete run-handle lifecycle.

    Construct with the plugin instance, the resolved agent UUID, and
    the APDP session id. Subclass to add framework-specific helpers;
    do not override the lifecycle methods unless you have a strong
    reason — they are the contract.

    Idempotent close: ``complete()`` and ``terminate()`` may both be
    called; only the first wins. The async context-manager exit calls
    ``terminate`` on exception and ``complete`` on clean exit, so the
    customer's typical pattern is::

        async with await plugin.start_run(slug) as handle:
            ...

    Both close paths emit a terminal lifecycle event
    (``execution_completed`` from :meth:`complete`,
    ``execution_failed`` from :meth:`terminate`) for the run's
    :attr:`execution_id`. This closes the lineage-projection gap
    where ``lineage.executions`` rows would stay at
    ``status='started'`` indefinitely. Framework translators that
    emit the same canonical event from their own callback
    (LangGraph ``on_chain_end``, OpenClaw ``session_end``, Claude
    Agent SDK ``Stop``, etc.) MUST call
    :meth:`mark_execution_completed_emitted` /
    :meth:`mark_execution_failed_emitted` BEFORE publishing the
    event so the SDK's defensive emit is suppressed.
    """

    #: Provenance tag stamped on every ad-hoc observation event emitted
    #: via :meth:`publish_observation`. Plugin RunHandle subclasses
    #: SHOULD override this with a framework-identifying value (e.g.
    #: ``"langgraph.workload"``) so downstream surfaces (the dashboard
    #: lineage view, SIEM exports, drift detection) can attribute events
    #: to the originating framework without parsing the payload.
    #:
    #: The default value identifies the unbranded SDK path — used when a
    #: customer constructs :class:`BaseRunHandle` directly without a
    #: plugin subclass, or when a plugin author has not yet wired the
    #: per-framework override.
    _observation_source: ClassVar[str] = "watchlight-core.publish_observation"

    #: A sub-agent's label (``spawn_subagent(child_label=...)``), as wl-apdp
    #: echoed it; ``None`` for a root run or a child spawned without one.
    #: Evidence only: policy sees it as ``context.subagent_label``, set by
    #: the server from the child's run credential.
    child_label: Optional[str] = None
    #: How the child was identified: ``"registered"``, ``"mapped"`` or
    #: ``"anonymous"`` (``None`` for a root run, or from an older server).
    child_identity: Optional[str] = None

    def __init__(
        self,
        plugin: GovernedPlugin,
        agent_uuid: str,
        session_id: str,
        run: Optional[RunRef] = None,
        egress: Optional[EgressBinding] = None,
        parent_handle: Optional["BaseRunHandle"] = None,
        run_handle_id: Optional[Union[str, UUID]] = None,
        server_run_handle: bool = False,
        granted_scope: Optional[GrantedScope] = None,
        execution_id: Optional[str] = None,
        root_execution_id: Optional[str] = None,
        parent_execution_id: Optional[str] = None,
        parent_agent_id: Optional[str] = None,
        goal_id: Optional[str] = None,
        on_escalation: Optional[Callable[[Escalation], Any]] = None,
        on_observation: Optional[Callable[[Observation], Any]] = None,
        on_attenuation: Optional[Callable[[Attenuation], Any]] = None,
    ):
        self._plugin = plugin
        self.agent_uuid = agent_uuid
        self.session_id = session_id
        # Optional NON-throwing listener for side-effect-axis escalations
        # (the ``Escalate`` enforcement effect). Fire-and-forget; never
        # alters the decision. A listener exception is swallowed so an
        # observability hook can never become an authorization failure.
        self._on_escalation: Optional[Callable[[Escalation], Any]] = on_escalation
        # Optional NON-throwing listener for allow-downgrade-axis
        # observations (the ``Observe`` enforcement effect). Same contract
        # as ``on_escalation``: fire-and-forget, never alters the decision,
        # listener exceptions swallowed.
        self._on_observation: Optional[Callable[[Observation], Any]] = on_observation
        # Optional NON-throwing listener for allow-downgrade-axis
        # attenuations (the ``Attenuate`` enforcement effect). Same contract
        # as ``on_observation``: fire-and-forget, never alters the decision,
        # listener exceptions swallowed.
        self._on_attenuation: Optional[Callable[[Attenuation], Any]] = on_attenuation

        # Stable per-run lineage identity, set on every handle (root +
        # sub-agent). It is never sent as a header: wl-proxy takes a
        # run's execution from the verified proxy-token claims.
        #
        # Roots without a caller-supplied id auto-mint a fresh one so
        # the field is always populated. Sub-agents receive the
        # spawn-time child execution_id from the plugin's
        # ``spawn_subagent`` flow.
        #
        # Execution-lineage integrity. The backend reports the canonical
        # ``execution_id`` wl-apdp minted SERVER-SIDE for this run
        # (``SessionInfo.execution_id`` / the spawn response's
        # ``child_execution_id``; for an older server, the id bound into
        # the run's proxy token), so the in-process emit stream and the
        # wl-proxy egress share one root id. Without one, a fresh
        # client-minted id.
        self.execution_id: str = execution_id or f"exec_{uuid.uuid4()}"
        # Root of the execution tree — equals ``execution_id`` for root
        # runs. Sub-agents inherit the orchestrator's root so the whole
        # spawn tree groups under one ``lineage.executions`` root.
        self.root_execution_id: str = root_execution_id or self.execution_id
        # ``None`` on the orchestrator; set on sub-agents to the
        # parent's ``execution_id`` for ``parent_execution_id`` envelope
        # population.
        self.parent_execution_id: Optional[str] = parent_execution_id
        # Spawner agent id; ``None`` on the orchestrator. Populated by
        # the plugin's ``spawn_subagent`` flow with the parent handle's
        # ``agent_uuid`` (or framework-specific slug).
        self.parent_agent_id: Optional[str] = parent_agent_id
        # Contextvar token captured by ``__aenter__`` and reset by
        # ``__aexit__`` so the lineage binding scopes correctly to the
        # ``async with`` body. ``None`` outside the ``async with`` lifetime.
        self._lineage_token: Optional[contextvars.Token] = None
        # Token from binding THIS handle into ``_current_subagent_handle``
        # at spawn; used to unbind it when the child closes.
        self._subagent_cv_token: Optional[contextvars.Token] = None
        # Stable RunHandle UUID used by APDP for the spawn-tree
        # walker, kill-signal cascade, and the
        # ``parent_run_handle_id`` field on the canonical
        # ``SpawnSubagentRequest`` shape. Roots typically auto-mint a
        # fresh UUID; sub-agents carry the ``child_run_handle_id`` APDP
        # returned from ``POST /v1/spawn_subagent``. The string form is
        # the wire shape — but we accept a UUID and stringify for
        # convenience.
        if run_handle_id is None:
            self.run_handle_id: str = str(uuid.uuid4())
        elif isinstance(run_handle_id, UUID):
            self.run_handle_id = str(run_handle_id)
        else:
            self.run_handle_id = str(run_handle_id)
        # Server-attested granted scope. ``None`` on the root
        # handle (the agent's full registered scope applies; no
        # attenuation has been declared). Set on sub-agent handles via
        # the server response to ``POST /v1/spawn_subagent``. Read by
        # plugins that want to surface the granted scope onto
        # ``agent_spawn_observed`` lineage events.
        self.granted_scope: Optional[GrantedScope] = granted_scope
        # Depth in the spawn tree — AUTO-CALCULATED, never hardcoded. This is
        # the value stamped on every ``execution_started`` payload and stored
        # verbatim by wl-execution-graph (it does not recompute), so the
        # dashboard's SUB-AGENT · DEPTH badge reflects exactly this. Precedence:
        #   1. the server-authoritative depth wl-apdp's spawn-tree walker
        #      stamped on the granted scope (``granted_scope.depth``);
        #   2. otherwise derive from the in-process parent chain
        #      (``parent_handle.depth + 1``);
        #   3. a root (no parent, no attenuated scope) is depth 0 by definition.
        # A sub-agent's depth is never a literal — it always comes from (1)/(2).
        if granted_scope is not None and getattr(granted_scope, "depth", 0):
            self.depth: int = int(granted_scope.depth)
        elif parent_handle is not None:
            self.depth = int(getattr(parent_handle, "depth", 0)) + 1
        else:
            self.depth = 0
        self._completed = False
        # The run's opaque reference, issued by the backend that opened
        # (or spawned) it. Every per-run backend call names the run by
        # it; the run's credentials (its ``sst_`` session token and its
        # wl-proxy token) stay inside the backend and are never held by
        # the handle. Emission is run-credential-only: with no run (a
        # wiring bug), the backend refuses to emit rather than send under
        # the shared tenant bearer (fail closed).
        self.run: Optional[RunRef] = run
        # Where this run's egress goes (``GovernanceBackend.egress_for``).
        # ``None`` when the backend gives the run no governed egress (the
        # Developer Edition, or no wl-proxy). The binding resolves the
        # run's egress token from the backend when it is used; it stores
        # no credential.
        self.egress: Optional[EgressBinding] = egress
        # A handle dropped without complete()/terminate() must not keep its
        # run (and the credentials behind it) live in the backend: when the
        # handle is garbage-collected, the backend ends the run client-side
        # (best effort, never raising). A no-op for a run already ended.
        self._run_finalizer: Optional[weakref.finalize] = None
        backend = getattr(plugin, "apdp", None)
        if run is not None and callable(
            getattr(type(backend), "_release_dropped_run", None)
        ):
            self._run_finalizer = weakref.finalize(
                self, backend._release_dropped_run, run
            )
            self._run_finalizer.atexit = False

        # Handle state machine. Starts ACTIVE; flips to
        # QUARANTINED on a wl-apdp Quarantine decision or via the
        # parent-chain propagation in ``_propagate_quarantine_to_parents``.
        # Subsequent authorize_action / spawn_subagent calls
        # short-circuit when in QUARANTINED state. COMPLETED is reached
        # via complete() / terminate(). The state is observable via
        # :attr:`state` for tests and dashboard surfaces.
        self._state: RunHandleState = RunHandleState.ACTIVE
        # Stored quarantine payload — populated on the ACTIVE →
        # QUARANTINED transition so the short-circuit path can raise
        # AgentQuarantinedError with the same context the wl-apdp
        # response originally carried.
        self._quarantine_decision: Optional[QuarantineDecision] = None
        # SeverSubtree — the decision that flipped this handle to
        # SEVERED (as the root that received it OR as a descendant
        # collapsed by the depth-first walk). ``None`` until severed.
        self._sever_decision: Optional[SeverSubtreeDecision] = None
        # Terminate / Revoke — the policy decision that ended this run.
        # Once set, every later authorize / publish / spawn on the handle
        # fails closed with the matching typed error, without a
        # round-trip (the handle is COMPLETED, but that alone must never
        # read as "still usable").
        self._run_end_decision: Optional[
            Union[TerminateDecision, RevokeDecision]
        ] = None
        # Flag so the ``execution_quarantined`` event is emitted at
        # most once per handle, regardless of how many short-circuit
        # raises happen afterwards.
        self._quarantine_event_emitted: bool = False
        # Side-effect-axis escalations recorded on this handle (the
        # ``Escalate`` enforcement effect). NON-throwing, additive
        # observability — recorded ALONGSIDE whatever decision fired (a
        # Deny, a Quarantine, …) WITHOUT altering the raise/return path.
        # Read via :meth:`get_escalations`. Bounded to the most recent
        # :data:`MAX_RECORDED_ESCALATIONS` for memory safety.
        self._escalations: List[Escalation] = []
        # Allow-downgrade-axis observations recorded on this handle (the
        # ``Observe`` enforcement effect). NON-throwing, additive
        # observability — recorded whenever an observe forbid matched,
        # WITHOUT altering the raise/return path (present even when a
        # co-occurring hard forbid kept the deny). Read via
        # :meth:`get_observations`. Bounded like escalations.
        self._observations: List[Observation] = []
        # Allow-downgrade-axis attenuations recorded on this handle (the
        # ``Attenuate`` enforcement effect). NON-throwing, additive
        # observability — recorded whenever an attenuate forbid matched,
        # WITHOUT altering the raise/return path (present even when a
        # co-occurring hard forbid kept the deny, or when the attenuation
        # failed fail-closed). Read via :meth:`get_attenuations`. Bounded
        # like escalations.
        self._attenuations: List[Attenuation] = []

        # execution_started lineage-contract state.
        #
        # ``_emitted_execution_started_for`` records every
        # ``execution_id`` for which this handle has already published
        # an ``execution_started`` event (whether via the SDK's
        # defensive late-binding mint or via an explicit
        # :meth:`mark_execution_started_emitted` call from a plugin
        # whose framework callback stream emits the event itself).
        # The set is bounded by the number of distinct execution_ids a
        # single run touches — typically 1-3 (the handle's own id, an
        # optional workload root, and rare per-call overrides). Memory
        # cost is negligible.
        #
        # ``_execution_started_lock`` serialises concurrent
        # :meth:`_ensure_execution_started_emitted` callers (e.g.
        # ``asyncio.gather`` of N ``publish_observation`` /
        # ``authorize_action_detailed`` calls on the same handle) so a
        # single ``execution_started`` event lands on the wire even
        # under microtask interleaving.
        self._emitted_execution_started_for: set[str] = set()
        self._execution_started_lock: asyncio.Lock = asyncio.Lock()
        # The ``execution_started`` event built for an execution, kept
        # until it is accepted so every attempt carries the same event_id.
        self._started_event_cache: Dict[str, Dict[str, Any]] = {}
        # The direct (authorize-path) mint attempt in flight, per
        # execution_id; concurrent authorize callers await its outcome.
        self._started_direct_attempts: Dict[str, "asyncio.Future[bool]"] = {}

        # Fail-closed guard for the lineage contract.
        # Flips ``True`` in :meth:`__aenter__` and ``False`` in
        # :meth:`__aexit__`. The guard in
        # :meth:`authorize_action_detailed` /
        # :meth:`publish_observation` raises
        # :class:`watchlight_core.WatchlightContractError` when an
        # SDK primitive lands while the handle is NOT inside its
        # ``async with`` block — the only place where lineage is
        # active, the contextvar is bound, and the SDK has emitted
        # the handle's own ``execution_started`` event.
        # Security-first: ambiguity → refuse.
        # Per the locked ungoverned-request-gate direction: NO
        # ``allow_no_run_handle=True`` escape hatch on
        # :meth:`publish_observation`. :meth:`authorize_action` /
        # :meth:`authorize_action_detailed` retain the opt-out kwarg
        # for legitimate bootstrap / setup paths.
        self._aentered: bool = False

        # Execution lifecycle emit tracker. The set contains
        # the terminal event_types whose emission the SDK has either
        # performed itself (via :meth:`complete` / :meth:`terminate`) or
        # been told a framework translator already emitted (via
        # :meth:`mark_execution_completed_emitted` /
        # :meth:`mark_execution_failed_emitted`). The members are the
        # canonical wire event_type strings: ``"execution_completed"``
        # and ``"execution_failed"``.
        #
        # Semantics:
        #   - At-most-once per kind per handle.
        #   - First write wins. Framework translators that emit the
        #     event from a callback (LangGraph ``on_chain_end``,
        #     OpenClaw ``session_end``, etc.) call
        #     ``mark_execution_*_emitted`` BEFORE their own
        #     ``publish_events`` so the subsequent
        #     :meth:`complete` / :meth:`terminate` close does NOT
        #     double-emit.
        #   - terminate-then-complete: the ``execution_failed``
        #     emission wins; the subsequent :meth:`complete` short-
        #     circuits at the ``self._completed`` guard and never reaches
        #     the lifecycle emit path. Symmetric for
        #     complete-then-terminate.
        #   - The quarantine path is independent — it writes its own
        #     terminal ``execution_completed`` via
        #     :meth:`_emit_quarantined_completion_event` and stamps the
        #     set so the defensive emit does not duplicate.
        self._execution_lifecycle_emitted: Set[str] = set()

        # Guard concurrent :meth:`complete` and :meth:`terminate`
        # races (impossible in normal flow but defensively required by
        # the lifecycle-emit contract). The lock is created lazily
        # because creating an
        # asyncio.Lock at __init__ time would bind it to whatever
        # loop happens to be running (or no loop at all); the lazy
        # creation defers the binding to the first acquire which is
        # always inside a coroutine.
        self._lifecycle_lock: Optional[asyncio.Lock] = None

        # Declared-intent state, mutated by the synthetic
        # ``watchlight.declare_intent`` tool path. When the agent calls
        # the synthetic tool, the plugin's tool-call interceptor
        # delegates to
        # :func:`watchlight_core.declare_intent.handle_declare_intent_call`
        # which writes these two attributes. The subsequent
        # ``authorize_action_detailed`` then auto-injects
        # ``intent={"objective": <stored>}`` into the APDP request body
        # — which hits wl-apdp's Cedar context projection's
        # "caller-declared inline intent" branch and stamps
        # ``provenance: "declared"`` on the evaluation context,
        # clearing the greenfield custodial-intent gate.
        #
        # Stored as a string + the enum value so the auto-inject path
        # can also surface the canonical wire shape directly when
        # required. The attributes are intentionally underscore-named:
        # they are SDK-internal state, not part of the run-handle's
        # public API (subclasses such as Pydantic AI's ``RunHandle``
        # carry their own ``intent_objective`` / ``intent_provenance``
        # fields for the canonical event emission path; the storage
        # here is the AUTHORIZE-time mirror, not the
        # EXECUTION_STARTED-time mirror).
        self._intent_objective: Optional[str] = None
        # The declared intent CATEGORY, in wl-apdp's wire form (a listed
        # name or ``{"custom": name}``). wl-apdp requires it on every
        # intent, so an objective without it is never sent.
        self._intent_category: Optional[Any] = None
        # The declared justification (optional), carried with the intent.
        self._intent_justification: Optional[str] = None
        # The goal this run was opened under (``start_run(goal_id=...)``).
        # Surfaced on ``execution_started`` so lineage can render the goal
        # per execution without a session lookup.
        self._goal_id: Optional[str] = goal_id
        # The child's intent and goal as wl-apdp validated them at the spawn
        # (``SpawnSubagentResponse.derived_intent``). ``None`` for a root run.
        # A call that names no intent acts under it server-side, and its
        # provenance is at most ``plugin_derived``.
        self._derived_intent: Optional[Dict[str, Any]] = None
        self._intent_provenance: Optional[Any] = None

        # Parent-chain tracking. When this handle is spawned
        # as a sub-agent (via a plugin's ``spawn_subagent`` flow), the
        # plugin passes the parent ``BaseRunHandle`` so quarantine on
        # the child propagates UP. The reference is weak so a finished
        # parent handle can still be GC'd; we only need it to walk the
        # chain at quarantine time. Children registered for downward
        # propagation track the parent too — see
        # ``_register_child_handle``.
        self._parent_handle_ref: Optional[weakref.ReferenceType] = (
            weakref.ref(parent_handle) if parent_handle is not None else None
        )
        # Is this a spawned SUB-AGENT handle? True iff it was
        # constructed with a parent (via ``spawn_subagent``), in which case
        # ``run_handle_id`` is the APDP-minted ``child_run_handle_id`` that
        # wl-apdp's scope-membership check binds against. A root handle
        # (``start_run``) has a client-minted ``run_handle_id`` the server
        # store does NOT know, so it MUST NOT present it. Stored as a stable
        # bool (not derived from the GC-able weakref) so the authorize path
        # never mis-classifies a handle whose parent was collected.
        self._is_subagent: bool = parent_handle is not None
        # Root-run handle — True iff wl-apdp minted a
        # server-side run handle for THIS root run at ``create_session``
        # and returned its id as ``root_run_handle_id``. Unlike a
        # sub-agent's ``run_handle_id`` (which is a client-unknown,
        # client-minted UUID for a root), a server-minted root
        # ``run_handle_id`` IS known to wl-apdp's run-handle store, so the
        # root MAY (and must) present it on every authorize — that is what
        # makes runtime Attenuate (and future run-handle governance) apply
        # to the root run, not only to spawned sub-agents. Mutually
        # exclusive with ``_is_subagent`` in practice (a handle is either a
        # root or a sub-agent). A root run whose deployment did not mint a
        # server handle (older wl-apdp, or no run-handle store) leaves this
        # False and behaves exactly as before — Cedar governs, no handle
        # presented. Fail-safe: never presents a client-minted id.
        self._server_run_handle: bool = bool(server_run_handle) and not self._is_subagent
        # Children registered by this handle (the parent end of the
        # ref). Weak references so completed sub-agent handles don't
        # leak into the parent. Children are only walked at quarantine
        # time so the data-structure overhead is bounded by the number
        # of currently-live sub-agents.
        self._child_handle_refs: List[weakref.ReferenceType] = []

        # If this handle was constructed with a parent, register
        # ourselves on the parent so the parent CAN walk downward to
        # propagate state if needed (currently used for symmetry —
        # quarantine propagates UP only per the locked decision, but
        # the downward link keeps the audit-trail walkable).
        if parent_handle is not None:
            try:
                parent_handle._register_child_handle(self)
            except Exception:  # noqa: BLE001 — parent registration is
                # best-effort; failing to register the child must
                # never break the child's lifecycle.
                logger.debug(
                    "parent registration failed (non-fatal)", exc_info=True
                )

    # ─── lineage propagation surface ──────────────────────────

    # ── Removed credential attributes ───────────────────────────────
    #
    # A handle used to carry the run's ``sst_`` session token and its
    # wl-proxy token. Both now stay inside the governance backend, under
    # :attr:`run`. These names fail loudly, on read and on write, so stale
    # code neither reads ``None`` by accident nor stores a credential on
    # the handle.

    _REMOVED_CREDENTIAL_ATTRS: ClassVar[Dict[str, str]] = {
        "session_token": "the backend holds the run credential; name the run with handle.run",
        "proxy_token": "the backend holds the egress token; use handle.egress",
        "proxy_token_expires_at": "use handle.egress.expires_at",
    }

    def __getattr__(self, name: str) -> Any:
        hint = BaseRunHandle._REMOVED_CREDENTIAL_ATTRS.get(name)
        if hint is not None:
            raise AttributeError(
                f"RunHandle.{name} was removed: {hint}"
            )
        raise AttributeError(
            f"{type(self).__name__!r} object has no attribute {name!r}"
        )

    def __setattr__(self, name: str, value: Any) -> None:
        if name in BaseRunHandle._REMOVED_CREDENTIAL_ATTRS:
            raise AttributeError(
                f"RunHandle.{name} was removed: "
                f"{BaseRunHandle._REMOVED_CREDENTIAL_ATTRS[name]}"
            )
        object.__setattr__(self, name, value)

    def lineage_snapshot(self) -> HandleLineage:
        """Return an immutable :class:`HandleLineage` snapshot of this
        handle's lineage tier.

        Introspection only: the snapshot is never written to a
        request header. wl-proxy takes a run's execution from the
        verified proxy-token claims.
        """
        return HandleLineage(
            execution_id=self.execution_id,
            parent_execution_id=self.parent_execution_id,
            root_execution_id=self.root_execution_id,
            parent_agent_id=self.parent_agent_id,
        )

    def activate_lineage(self) -> "_LineageActivation":
        """Bind this handle's lineage to the current asyncio task's
        context so the CONNECT sidecar can read it on outbound HTTP
        requests.

        Returns a context-manager that resets the contextvar token on
        exit, matching the ``set`` / ``reset`` token pattern used by
        :meth:`spawn_subagent`. Use as::

            async with handle.activate_lineage():
                # outbound HTTP calls in this task carry handle's lineage
                await framework.run(...)

        Concurrent sub-agent spawns (asyncio.gather of N children) each
        see their own binding because ``contextvars`` are copied on
        task creation — the sub-agent's
        lineage MUST be used, NEVER the root's, when the sub-agent's
        framework dispatches outbound HTTP.
        """
        return _LineageActivation(self.lineage_snapshot())

    # ─── state-machine surface ────────────────────────────────

    @property
    def state(self) -> RunHandleState:
        """Current lifecycle state of the handle. Observable for tests
        and dashboard surfaces. See :class:`RunHandleState`.
        """
        return self._state

    @property
    def quarantine_decision(self) -> Optional[QuarantineDecision]:
        """The decision that caused the handle to flip to QUARANTINED,
        or ``None`` if the handle has never been quarantined.
        """
        return self._quarantine_decision

    @property
    def is_quarantined(self) -> bool:
        """Convenience predicate. Equivalent to
        ``self.state == RunHandleState.QUARANTINED``.
        """
        return self._state == RunHandleState.QUARANTINED

    def get_escalations(self) -> Tuple[Escalation, ...]:
        """Snapshot of the side-effect-axis escalations recorded on this
        handle (the ``Escalate`` enforcement effect), most-recent last.
        Read by observability / dashboard code that wants to know "was
        this agent escalated to SOC/HITL" WITHOUT the escalation ever
        having changed the decision (it is NON-throwing, additive).
        Returns a tuple so callers can't mutate the handle's record.
        """
        return tuple(self._escalations)

    def has_escalations(self) -> bool:
        """``True`` iff at least one escalation has been recorded."""
        return len(self._escalations) > 0

    def _record_escalations(
        self, escalations: Tuple[Escalation, ...]
    ) -> None:
        """Record side-effect-axis escalations for an authorize call —
        NON-throwing, additive observability that NEVER alters the
        decision (the raise/return path is untouched). Appends to the
        bounded :attr:`_escalations` record and fires the optional
        ``on_escalation`` listener fire-and-forget (a listener exception
        is swallowed so an observability hook can never become an
        authorization failure). No-op when no escalation fired.
        """
        if not escalations:
            return
        for esc in escalations:
            self._escalations.append(esc)
            # Bound memory on a long-lived handle: keep the most recent N.
            if len(self._escalations) > MAX_RECORDED_ESCALATIONS:
                self._escalations.pop(0)
            if self._on_escalation is not None:
                try:
                    self._on_escalation(esc)
                except Exception:  # noqa: BLE001 — never let a hook fail authz
                    logger.debug(
                        "on_escalation listener raised; swallowing "
                        "(observability hooks must never fail authorization)",
                        exc_info=True,
                    )

    def get_observations(self) -> Tuple[Observation, ...]:
        """Snapshot of the allow-downgrade-axis observations recorded on
        this handle (the ``Observe`` enforcement effect), most-recent last.
        Read by observability / dashboard code that wants to know "which
        policies WOULD have denied, in monitor mode" WITHOUT the observation
        ever having changed the decision (it is NON-throwing, additive).
        Returns a tuple so callers can't mutate the handle's record.
        """
        return tuple(self._observations)

    def has_observations(self) -> bool:
        """``True`` iff at least one observation has been recorded."""
        return len(self._observations) > 0

    def _record_observations(
        self, observations: Tuple[Observation, ...]
    ) -> None:
        """Record allow-downgrade-axis observations for an authorize call —
        NON-throwing, additive observability that NEVER alters the decision
        (the raise/return path is untouched). Appends to the bounded
        :attr:`_observations` record and fires the optional
        ``on_observation`` listener fire-and-forget (a listener exception is
        swallowed so an observability hook can never become an authorization
        failure). No-op when no observation fired.
        """
        if not observations:
            return
        for obs in observations:
            self._observations.append(obs)
            # Bound memory on a long-lived handle: keep the most recent N.
            if len(self._observations) > MAX_RECORDED_OBSERVATIONS:
                self._observations.pop(0)
            if self._on_observation is not None:
                try:
                    self._on_observation(obs)
                except Exception:  # noqa: BLE001 — never let a hook fail authz
                    logger.debug(
                        "on_observation listener raised; swallowing "
                        "(observability hooks must never fail authorization)",
                        exc_info=True,
                    )

    def get_attenuations(self) -> Tuple[Attenuation, ...]:
        """Snapshot of the allow-downgrade-axis attenuations recorded on
        this handle (the ``Attenuate`` enforcement effect), most-recent last.
        Read by observability / dashboard code that wants to know "which
        policies narrowed this run's authority, and to what" WITHOUT the
        attenuation ever having changed the decision (it is NON-throwing,
        additive). Returns a tuple so callers can't mutate the handle's
        record.
        """
        return tuple(self._attenuations)

    def has_attenuations(self) -> bool:
        """``True`` iff at least one attenuation has been recorded."""
        return len(self._attenuations) > 0

    def was_scope_attenuated(self) -> bool:
        """``True`` iff at least one SUCCESSFUL attenuation (``narrowed``)
        has been recorded on this handle — i.e. the run's granted scope was
        actually tightened. A fail-closed attenuation (``narrowed=False``)
        does NOT count: the forbid stayed a real deny and no authority was
        narrowed.
        """
        return any(a.narrowed for a in self._attenuations)

    def _record_attenuations(
        self, attenuations: Tuple[Attenuation, ...]
    ) -> None:
        """Record allow-downgrade-axis attenuations for an authorize call —
        NON-throwing, additive observability that NEVER alters the decision
        (the raise/return path is untouched). Appends to the bounded
        :attr:`_attenuations` record and fires the optional
        ``on_attenuation`` listener fire-and-forget (a listener exception is
        swallowed so an observability hook can never become an authorization
        failure). No-op when no attenuation fired.
        """
        if not attenuations:
            return
        for att in attenuations:
            self._attenuations.append(att)
            # Bound memory on a long-lived handle: keep the most recent N.
            if len(self._attenuations) > MAX_RECORDED_ATTENUATIONS:
                self._attenuations.pop(0)
            if self._on_attenuation is not None:
                try:
                    self._on_attenuation(att)
                except Exception:  # noqa: BLE001 — never let a hook fail authz
                    logger.debug(
                        "on_attenuation listener raised; swallowing "
                        "(observability hooks must never fail authorization)",
                        exc_info=True,
                    )

    @property
    def sever_decision(self) -> Optional[SeverSubtreeDecision]:
        """The decision that caused the handle to flip to SEVERED, or
        ``None`` if the handle has never been severed. Set on the root
        that received the ``SeverSubtree`` decision AND on every
        descendant collapsed by the depth-first walk.
        """
        return self._sever_decision

    @property
    def is_severed(self) -> bool:
        """Convenience predicate. Equivalent to
        ``self.state == RunHandleState.SEVERED``. Severing is a TERMINAL
        state (multi-agent containment) — NOT a durable agent-bag like
        quarantine; a re-spawned tree is clean.
        """
        return self._state == RunHandleState.SEVERED

    # ─── declared-intent surface ────────────────────────────

    @property
    def derived_intent(self) -> Optional[Dict[str, Any]]:
        """The intent and goal wl-apdp derived for this sub-agent at its
        spawn (``intent_category``, ``objective``, ``max_actions``,
        ``sub_goal_id``, ``parent_goal_id``, ``provenance``), or ``None`` for
        a root run. Read-only: the server's copy is authoritative."""
        return dict(self._derived_intent) if self._derived_intent else None

    @property
    def declared_intent_objective(self) -> Optional[str]:
        """The objective most recently stamped via
        ``watchlight.declare_intent``, or ``None`` when the agent has
        not yet declared. Observable for tests and dashboard surfaces.
        """
        return self._intent_objective

    @property
    def declared_intent_category(self) -> Optional[Any]:
        """The intent category stamped via ``watchlight.declare_intent``
        (wire form), or ``None`` when the agent has not declared one."""
        return self._intent_category

    @property
    def declared_intent_provenance(self) -> Optional[Any]:
        """The :class:`IntentProvenance` stamped via the synthetic
        tool, or ``None`` when the agent has not declared. Returns
        the enum value (not the wire string) so the caller can
        compare via ``IntentProvenance.DECLARED`` symbolically.
        """
        return self._intent_provenance

    def synthetic_tools(
        self,
        mode: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Return the synthetic Watchlight-managed tools the agent
        should see for this run.

        When the agent's effective intent-enforcement mode is
        greenfield, the list contains the
        :data:`watchlight_core.WATCHLIGHT_DECLARE_INTENT_TOOL`
        definition. Brownfield agents see an empty list — the
        synthetic-tool gate is inert in brownfield because the matrix
        accepts inferred provenance at every tier.

        Plugins call this from their tool-list construction path and
        union the result with the customer's own tools. The plugin is
        also responsible for intercepting calls to the synthetic
        tool's name (via
        :func:`watchlight_core.is_declare_intent_tool_call`) and
        delegating to
        :func:`watchlight_core.handle_declare_intent_call` BEFORE
        forwarding to its normal authorize path.

        Parameters
        ----------
        mode:
            Override the SDK's mode-resolution helper. When ``None``
            (the default), reads
            :func:`watchlight_core.resolve_intent_enforcement_mode`
            which falls back to the
            ``WATCHLIGHT_INTENT_ENFORCEMENT_MODE`` env var, then to
            the locked brownfield default.

        Returns
        -------
        list of dict
            Empty in brownfield. In greenfield: a single-element list
            containing
            :data:`watchlight_core.WATCHLIGHT_DECLARE_INTENT_TOOL`.
            Future synthetic tools (e.g., a sub-agent intent
            attenuation surface) would land here without changing the
            plugin call sites.
        """
        from .declare_intent import (
            WATCHLIGHT_DECLARE_INTENT_TOOL,
            resolve_intent_enforcement_mode,
            should_inject_synthetic_tool,
        )

        effective_mode = (
            mode if isinstance(mode, str) else resolve_intent_enforcement_mode()
        )
        if not should_inject_synthetic_tool(effective_mode):
            return []
        return [dict(WATCHLIGHT_DECLARE_INTENT_TOOL)]

    def record_declared_intent(
        self, objective: str, category: Any = None, justification: Optional[str] = None
    ) -> Optional[str]:
        """Stamp a declared objective onto this handle.

        Convenience wrapper around
        :func:`watchlight_core.declare_intent.handle_declare_intent_call`
        for callers that already have a normalised objective string.
        Returns the truncated objective that was stored, or ``None``
        when the input normalised to empty (in which case the handle
        is unchanged — the intent gate will still forbid).

        Plugins generally call ``handle_declare_intent_call`` instead
        because it produces the full LLM-visible tool response dict;
        this method is for internal SDK code paths that just need to
        mutate the handle's intent state without producing a response.
        """
        # Local import to avoid a circular dependency with
        # ``declare_intent`` (which imports
        # ``IntentProvenance`` from this package and would otherwise
        # need to import ``BaseRunHandle`` at module load time).
        from .declare_intent import handle_declare_intent_call

        args: Dict[str, Any] = {"objective": objective, "category": category}
        if justification is not None:
            args["justification"] = justification
        response = handle_declare_intent_call(self, args)
        if response.get("status") == "intent_declared":
            return response.get("objective")
        # A programmatic declaration that cannot be recorded fails loudly.
        raise ValueError(f"declared intent refused: {response.get('reason')}")

    def _register_child_handle(self, child: "BaseRunHandle") -> None:
        """Register a sub-agent handle so the parent can walk the tree
        at quarantine time. Called by the child's ``__init__`` when a
        ``parent_handle`` is provided.

        Compaction: dead weakrefs are pruned on every registration so
        the list stays bounded by the number of live sub-agents.
        """
        self._child_handle_refs = [
            ref for ref in self._child_handle_refs if ref() is not None
        ]
        self._child_handle_refs.append(weakref.ref(child))

    # ─── execution_started lineage contract ──────────

    async def _emit_execution_started(
        self, execution_id: str, *, direct: bool = False
    ) -> None:
        """Emit a canonical ``execution_started`` event for ``execution_id``.

        Mirrors the canonical
        :class:`watchlight_core.events_schema.ExecutionStartedPayload`
        shape and posts via the plugin's
        :meth:`watchlight_core.ApdpClient.publish_events` transport.

        **Fail-loud on the defensive path used by
        :meth:`publish_observation`** — see
        :meth:`_ensure_execution_started_emitted` for the contract.
        :meth:`__aenter__` uses this method in a best-effort wrapper
        because observability should never break the customer's
        framework at session-open time; the
        ``publish_observation`` / ``authorize_action_detailed`` call
        sites surface the transport failure to the caller so an
        observability tool that depends on the observation succeeding
        can branch.

        Per the closed-set lineage contract, every
        non-lifecycle event MUST attach to an execution whose
        ``execution_started`` was emitted earlier (otherwise the
        dashboard's `/lineage` tree has no node to render under, and
        wl-execution-graph cannot mint a ``lineage.executions`` row
        for the event's ``execution_id``).

        The payload carries the canonical ``PrincipalRef`` (agent
        principal, this handle's ``agent_uuid``) plus the declared
        intent objective + provenance when set via the
        synthetic-tool path. Frameworks that already emit a richer
        ``execution_started`` (LangGraph's callback handler) call
        :meth:`mark_execution_started_emitted` BEFORE triggering the
        first authorize / publish round-trip so this method's
        defensive late-binding is a no-op — no duplicate event lands.
        """
        # Local imports avoid a module-load-time circular dependency.
        # ``events_schema`` does not import ``run_handle`` directly,
        # but going lazy here keeps the load-order risk minimal as
        # the schema module grows.
        from .events_schema import ExecutionEvent as ExecutionEventModel
        from .events_schema import IntentProvenance

        # One event per execution until it is accepted: a re-attempt (or a
        # background redelivery of a failed attempt) carries the same
        # ``event_id``, so the event plane deduplicates it.
        cached = self._started_event_cache.get(execution_id)
        if cached is not None:
            await self._publish_started(execution_id, cached, direct)
            return

        tenant_id = getattr(self._plugin, "tenant_id", None)
        timestamp = datetime.now(timezone.utc).isoformat().replace(
            "+00:00", "Z"
        )

        # PrincipalRef carries the canonical agent identity tied to
        # this handle. ``principal_type: "agent"`` matches every
        # plugin lane's emission. The handle's ``agent_uuid`` is the
        # canonical UUID — wl-apdp's resolution path always produces
        # this shape.
        principal_payload: Dict[str, Any] = {
            "principal_type": "agent",
            "id": str(self.agent_uuid),
        }

        payload: Dict[str, Any] = {
            "principal": principal_payload,
            # AUTO-CALCULATED spawn-tree depth (see ``__init__``). Root = 0,
            # each sub-agent = its server-attested / parent-derived depth.
            # wl-execution-graph stores this verbatim (the graph builder reads
            # ``payload.depth`` directly), so it MUST be the real depth, never
            # a literal.
            "depth": self.depth,
        }
        if self._goal_id:
            payload["goal_id"] = str(self._goal_id)

        # Surface declared intent on the canonical event if
        # the workload populated it via the synthetic-tool path
        # before entering the run. Plugins emitting
        # ``execution_started`` via their own callback stream
        # (LangGraph) own the precedence chain; this late-binding
        # path is for direct-authorize / direct-publish workloads
        # that have no other emitter.
        if self._intent_objective is not None:
            payload["intent_objective"] = self._intent_objective
            provenance = self._intent_provenance or IntentProvenance.DECLARED
            payload["intent_provenance"] = (
                provenance.value
                if isinstance(provenance, IntentProvenance)
                else str(provenance)
            )
        # A sub-agent acts under the intent wl-apdp derived for it at the
        # spawn. Its provenance is the derived one (at most
        # ``plugin_derived``), even when the child declared an objective of
        # its own: a child never raises its provenance above its parent's.
        # When the derived provenance is ``absent`` (the parent's own intent
        # had no recorded source), no objective is recorded on the child's
        # ``execution_started``: an objective needs a provenance above absent.
        derived = self._derived_intent
        if isinstance(derived, dict):
            category = derived.get("intent_category")
            if isinstance(category, str) and category:
                payload["intent_category"] = category
            derived_provenance = derived.get("provenance")
            if derived_provenance in ("plugin_derived", "proxy_inferred"):
                objective = self._intent_objective or derived.get("objective")
                if isinstance(objective, str) and objective:
                    payload["intent_objective"] = objective
                    payload["intent_provenance"] = derived_provenance
            else:
                payload.pop("intent_objective", None)
                payload.pop("intent_provenance", None)

        event: Dict[str, Any] = {
            "event_id": f"evt_{uuid.uuid4()}",
            "event_type": "execution_started",
            "timestamp": timestamp,
            "execution_id": execution_id,
            "agent_id": str(self.agent_uuid),
            "session_id": self.session_id,
            "payload": payload,
            "metadata": {
                # Stamp the plugin's framework-specific observation
                # source so the canonical conformance invariant 2
                # (``metadata.source`` starts with the framework tag)
                # passes against defensive emissions too.
                "source": self._observation_source,
                # Additional discriminator so audit replay can tell
                # SDK-defensive late-bind emissions apart from
                # primary framework emissions for the same event_type.
                "kind": "execution_started_lineage_contract",
            },
        }
        # Sub-agent envelope linkage: a child handle stamps the
        # canonical parent/root pointers so wl-execution-graph
        # stitches the row under the right tree.
        if self.parent_execution_id is not None:
            event["parent_execution_id"] = self.parent_execution_id
        if (
            self.root_execution_id is not None
            and self.root_execution_id != execution_id
        ):
            event["root_execution_id"] = self.root_execution_id
        if self.parent_agent_id is not None:
            event["parent_agent_id"] = self.parent_agent_id
        if tenant_id is not None:
            event["tenant_id"] = tenant_id

        # Validate BEFORE the network call so a future schema change
        # surfaces the diagnostic at the SDK boundary, not as a 422
        # from APDP.
        ExecutionEventModel.model_validate(event)
        self._started_event_cache[execution_id] = event
        await self._publish_started(execution_id, event, direct)

    async def _publish_started(
        self, execution_id: str, event: Dict[str, Any], direct: bool
    ) -> None:
        # Surface the transport result to the caller. The defensive
        # call-site wrappers decide whether a failure is fatal
        # (publish_observation / authorize_action_detailed → raise)
        # or best-effort (``__aenter__`` startup hook → swallow).
        if direct:
            with lineage_direct_attempt():
                ok = await self._plugin.apdp.publish_events(self.run, [event])
        else:
            ok = await self._plugin.apdp.publish_events(self.run, [event])
        if not ok:
            raise WatchlightError(
                f"APDP rejected execution_started defensive emission "
                f"for execution_id={execution_id!r}"
            )

    async def _ensure_execution_started_emitted(
        self, execution_id: Optional[str], *, direct: bool = False
    ) -> str:
        """Mint ``execution_started`` for ``execution_id`` if not yet
        seen on this handle, and return the effective execution_id.

        Called from :meth:`authorize_action_detailed` BEFORE the
        APDP authorize round-trip and from
        :meth:`publish_observation` BEFORE the observation event is
        posted, so any non-lifecycle event the SDK emits has a
        parent ``execution_started`` row to attach under. ``None``
        falls back to the handle's own ``execution_id`` (set at
        construction time); an explicit value (the workload-root id
        a scenario threads through) is honoured.

        Idempotent per ``execution_id`` — the set guard ensures at
        most one ``execution_started`` per (handle, execution_id)
        pair, regardless of how many authorize / publish calls
        share the same id.

        Concurrency: the per-handle :class:`asyncio.Lock` serialises
        concurrent callers so two ``asyncio.gather``'d
        ``publish_observation`` calls on the same handle race to a
        single emission, not two.

        **Fail-loud**: if the started emit fails (NATS down, APDP
        unreachable), the slot is NOT reserved and the error
        propagates to the caller. A subsequent retry has a clean
        slate to attempt the emit again.
        """
        effective = execution_id or self.execution_id
        if effective in self._emitted_execution_started_for:
            return effective
        if direct:
            return await self._mint_started_direct(effective)
        async with self._execution_started_lock:
            if effective in self._emitted_execution_started_for:
                return effective
            # Emit FIRST; only mark as emitted on success. If the
            # transport fails (NATS / APDP unreachable), the caller
            # MUST see the error so the observation isn't silently
            # published into a tree with no root.
            await self._emit_execution_started(effective)
            self._mark_started(effective)
        return effective

    def _mark_started(self, execution_id: str) -> None:
        self._emitted_execution_started_for.add(execution_id)
        self._started_event_cache.pop(execution_id, None)

    async def _mint_started_direct(self, effective: str) -> str:
        """The mint in front of ``authorize``: one direct attempt, never
        behind a retry, and fail closed. A concurrent authorize caller
        awaits the attempt already in flight and gets its outcome, so it
        cannot go ahead of a mint that is then refused. It does not wait
        for an awaited (retrying) mint started elsewhere: it makes its own
        single attempt with the same event (same ``event_id``)."""
        pending = self._started_direct_attempts.get(effective)
        if pending is not None:
            if not await asyncio.shield(pending):
                raise WatchlightError(
                    f"APDP rejected execution_started defensive emission "
                    f"for execution_id={effective!r}"
                )
            return effective
        future: "asyncio.Future[bool]" = asyncio.get_running_loop().create_future()
        self._started_direct_attempts[effective] = future
        ok = False
        try:
            await self._emit_execution_started(effective, direct=True)
            ok = True
            self._mark_started(effective)
        finally:
            self._started_direct_attempts.pop(effective, None)
            if not future.done():
                future.set_result(ok)
        return effective

    def mark_execution_started_emitted(self, execution_id: str) -> None:
        """Record that ``execution_id`` has already had its
        ``execution_started`` event emitted by some other path.

        Frameworks that drive their own callback stream — LangGraph's
        ``on_chain_start`` translator is the canonical example —
        publish ``execution_started`` themselves with framework-level
        attribution (e.g. ``metadata.source = "langgraph.callback"``).
        Calling this method BEFORE the first
        :meth:`authorize_action_detailed` /
        :meth:`publish_observation` of that execution suppresses the
        SDK's defensive late-binding mint so no duplicate event lands.

        Workloads that bypass the framework callback stream (direct
        ``authorize_action`` / ``publish_observation`` chains in the
        ``denied``, ``bad-actor``, ``quarantine``, ``hot-swap``,
        ``scope_violation`` scenarios) do NOT call this method — the
        SDK guard mints ``execution_started`` for them automatically.
        """
        self._mark_started(execution_id)

    async def submit_plan(self, plan: Any) -> PlanResult:
        """Submit a plan for validation.

        Accepts the framework-agnostic plan shapes documented in
        :func:`watchlight_core.normalize_plan` (``list[str]`` or
        ``list[dict]``).

        On successful submission, promotes
        ``plugin.last_governance_mode`` to ``"strong"`` — a validated
        plan is the strongest governance signal regardless of whether
        a manifest was previously fetched.
        """
        normalized = normalize_plan(plan)
        self._plugin.last_proposed_plan = normalized

        resp = await self._plugin.apdp.submit_plan(self.run, normalized)
        if resp is None:
            return PlanResult.deny_transport_failure()

        validation = resp.get("validation") or {}
        self._plugin.last_plan_validation = validation
        # A validated plan = strong-governance posture. Idempotent if
        # mode was already "strong" (manifest was fetched at start_run).
        self._plugin.last_governance_mode = "strong"
        return PlanResult(validation)

    async def preflight_step(
        self,
        action: str,
        resource: str,
        intent: Optional[Dict[str, Any]] = None,
    ) -> PreflightResult:
        """Read-only check that this action+resource would be permitted.

        Does not consume budget or write to the audit chain — useful
        for surfacing diagnostics in the customer's UI before invoking
        a tool.
        """
        resp = await self._plugin.apdp.preflight_step(
            self.run, action, resource, intent=intent
        )
        if resp is None:
            return PreflightResult.transport_failure()
        return PreflightResult(resp.get("preflight", {}))

    async def authorize_action(
        self,
        action: str,
        resource: str,
        execution_id: Optional[str] = None,
        intent: Optional[Dict[str, Any]] = None,
        context: Optional[Dict[str, Any]] = None,
        *,
        principal: Optional[str] = None,
        allow_no_run_handle: bool = False,
    ) -> bool:
        """Authoritative authorization check via APDP ``/authorize``.

        Counts toward action budget; writes to the audit chain.
        Updates the plugin's ``last_actions_allowed`` /
        ``last_actions_denied`` counters atomically with the decision.

        ``context`` lets the caller surface additional Cedar context
        fields (``intent_category``, ``goal_id``, ``delegation_scope``,
        etc.) so policies can gate on them. The plugin's ``tenant_id``
        is always authoritative and overrides any ``tenant_id`` the
        caller passes here. wl-apdp derives ``goal_action_count``,
        ``goal_max_actions``, ``allowed_intent_categories`` and
        ``intent_aligned`` itself and drops any caller value.

        Returns ``True`` on Allow, ``False`` on Deny (or transport
        failure — fail-closed).

        **Quarantine semantics**: when the handle is in
        ``QUARANTINED`` state (because wl-apdp previously returned a
        Quarantine decision, or because a parent handle propagated
        quarantine), this method raises
        :class:`AgentQuarantinedError` WITHOUT round-tripping to
        wl-apdp. This is the load-bearing security invariant — a
        quarantined agent CANNOT silently fall through to a fresh
        wl-apdp call. If wl-apdp returns Quarantine on this call,
        the handle flips to QUARANTINED, an
        ``execution_quarantined`` event is emitted, and
        :class:`AgentQuarantinedError` is raised.

        ``principal`` names the SUBJECT this call is made for — see
        :meth:`authorize_action_detailed`. Omitted, the acting agent
        is the subject, exactly as before.

        Note — the bool collapse intentionally hides the
        ``needs_approval`` decision and the ``approval_request_id``.
        Callers that need to handle the human-approval pause path
        should use :meth:`authorize_action_detailed` instead.
        """
        result = await self.authorize_action_detailed(
            action=action,
            resource=resource,
            execution_id=execution_id,
            intent=intent,
            context=context,
            principal=principal,
            allow_no_run_handle=allow_no_run_handle,
        )
        return result.is_allow()

    async def authorize_action_detailed(
        self,
        action: str,
        resource: str,
        execution_id: Optional[str] = None,
        intent: Optional[Dict[str, Any]] = None,
        context: Optional[Dict[str, Any]] = None,
        *,
        principal: Optional[str] = None,
        allow_no_run_handle: bool = False,
    ) -> AuthorizeResult:
        """Rich-result variant of :meth:`authorize_action`.

        Returns an :class:`AuthorizeResult` carrying one of three
        decisions:

        * ``allow``  — proceed with the action.
        * ``deny``   — halt; ``reason`` carries the policy id / message.
        * ``needs_approval`` — APDP signalled ``escalation_required``
          and minted an ``approval_request_id``. The caller's
          framework pauses (LangGraph plugins use
          :func:`langgraph.types.interrupt`); when the workflow is
          resumed with the approval token, retry with
          ``intent.approval_token`` set.

        The plugin's ``last_actions_allowed`` /
        ``last_actions_denied`` counters are kept in lock-step
        regardless of which method the caller uses;
        ``needs_approval`` is counted as denied (the action did
        not execute).

        **Quarantine semantics**: when the handle is in
        ``QUARANTINED`` state, this method raises
        :class:`AgentQuarantinedError` immediately, WITHOUT calling
        wl-apdp. When the wl-apdp response carries
        ``decision: "Quarantine"``, the handle transitions to
        ``QUARANTINED``, an ``execution_quarantined`` event is
        emitted (best-effort), the quarantine propagates UP through
        any registered parent handles, and
        :class:`AgentQuarantinedError` is raised on this call. There
        is NO ``AuthorizeResult.quarantine`` variant —
        :class:`AgentQuarantinedError` is the exclusive signal for
        the quarantine path. Customer agent code MUST catch the
        error or let it propagate; the SDK has no in-process recovery
        path.

        Security model — the ``approval_request_id`` is a bearer
        secret in the retry leg. Callers MUST NOT log it at
        info-level nor embed it in errors surfaced to untrusted
        callers.

        ``principal`` — the SUBJECT of the decision: WHO this call is
        made for. Omitted (the default), the acting agent is the
        subject and the decision is evaluated under
        ``Agent::"<agent_uuid>"``, exactly as before. Supplied, it
        becomes the Cedar principal verbatim, so an application can
        say a tool call runs on behalf of ``User::"alice"`` and have
        the policy decide on HER authority rather than the runtime's.

        Pass a TYPED entity reference (``User::"alice"``). A bare
        name is accepted, but on a verbatim backend it reaches the
        engine bare, where it is a WILDCARD that matches a policy
        naming any entity type with that id — convenient in a
        sandbox, wrong for an authorization decision you rely on —
        and on every other backend it is wrapped as ``Agent::"…"``,
        which is unlikely to be the type you meant for a human
        subject.

        The acting agent is unaffected: it remains the ``agent_id``
        and the ``execution_started`` principal on every lineage
        event for this run, so a supplied subject never erases which
        agent acted.

        Entity shaping is chosen by the BACKEND. Against the
        in-process backend (which declares
        ``cedar_entities_verbatim``) ``principal`` / ``action`` /
        ``resource`` reach the engine exactly as given: a bare name
        (``"read"``, ``"dataset"``) stays bare — the long-standing
        behaviour — and a typed reference (``Document::"d1"``) keeps
        its type and discriminates. Against a networked, mock or
        third-party backend a bare term is wrapped into
        ``Agent::"…"`` / ``Action::"…"`` / ``Resource::"…"``, which
        is the request body wl-apdp has always received; a typed one
        is left alone. See :mod:`watchlight_core._cedar_entities`.

        Raises:
            AgentQuarantinedError: when the handle is already
                quarantined or wl-apdp returns Quarantine. The
                error carries the full anomaly attribution
                (reason, anomaly_score, contributing_features,
                model_version, policy_id).
        """
        # ── fail-closed lineage contract guard ─────
        # A Cedar evaluation requested via this handle WITHOUT first
        # entering the ``async with`` block produces a
        # ``policy_decision_made`` event without an
        # ``execution_started`` parent. Per the closed-set lineage
        # contract, non-lifecycle events that arrive for an
        # execution with no row in ``lineage.executions`` are dropped
        # from the dashboard ``/lineage`` view — the operator sees
        # NO audit row for the deny / allow. That is exactly the
        # observability gap this guard closes.
        #
        # Fail-closed: raise the typed error so the caller's bug
        # surfaces at the line of the misuse instead of silently
        # producing an orphan event the operator would have to debug
        # after the fact. Callers with a legitimate bootstrap /
        # setup path can opt out with ``allow_no_run_handle=True``;
        # the docstring on :class:`WatchlightContractError` carries
        # the strong warning. Per the locked
        # ungoverned-request-gate direction, the opt-out is
        # NOT available on :meth:`publish_observation` — only on the
        # authorize methods, which retain it for source-compat.
        if not self._aentered and not allow_no_run_handle:
            from .errors import WatchlightContractError

            raise WatchlightContractError(
                "authorize_action() called without an open RunHandle. "
                "Cedar evaluations MUST attach to an execution per the "
                "lineage contract. Wrap the call in "
                "`async with await client.start_run(...) as handle:`."
            )

        # ── quarantine short-circuit ────────────────────────────────────
        # Load-bearing security invariant: a quarantined handle MUST
        # NOT round-trip to wl-apdp. If we silently fell through, an
        # attacker who knows the wl-apdp anomaly cache has been
        # cleared (e.g. via a transient connectivity blip that purged
        # in-memory state) could regain Allow decisions on a
        # quarantined agent. The plugin's view of quarantine is
        # authoritative until operator lift via the dashboard.
        if self._state == RunHandleState.QUARANTINED:
            assert self._quarantine_decision is not None, (
                "RunHandleState.QUARANTINED reached without a stored "
                "QuarantineDecision — this is a SDK bug; the state "
                "transition must always populate _quarantine_decision."
            )
            self._plugin.last_actions_denied += 1
            # Re-fire the kill signal on the short-circuit path.
            # The first transition already fired it (see below), but a
            # late-arriving in-flight LLM call that started AFTER the
            # transition (e.g. the agent's framework retried an HTTP
            # request) MUST also be aborted. ``cancel`` is idempotent —
            # firing twice with no live requests is a no-op.
            self._fire_kill_signal()
            raise AgentQuarantinedError.from_decision(
                self._quarantine_decision
            )

        # ── SeverSubtree short-circuit ─────────────────────────────
        # A severed handle is TERMINAL (multi-agent containment): it
        # MUST NOT round-trip to wl-apdp. This covers the root that
        # received the SeverSubtree decision AND every descendant the
        # depth-first walk collapsed — a descendant whose framework
        # keeps issuing tool calls after its parent was severed fails
        # closed here without ever reaching wl-apdp. Unlike quarantine
        # this is NOT a durable agent-bag; it is scoped to this
        # in-process tree, and a fresh ``start_run`` re-spawns clean.
        if self._state == RunHandleState.SEVERED:
            assert self._sever_decision is not None, (
                "RunHandleState.SEVERED reached without a stored "
                "SeverSubtreeDecision — this is a SDK bug; the state "
                "transition must always populate _sever_decision."
            )
            self._plugin.last_actions_denied += 1
            # Re-fire the kill signal on the short-circuit path — a
            # late-arriving in-flight LLM call that started AFTER the
            # sever MUST also be aborted. ``cancel`` is idempotent.
            self._fire_kill_signal(
                reason=LLM_CALL_INTERRUPTED_REASON_SEVER_SUBTREE
            )
            raise SubtreeSeveredError.from_decision(self._sever_decision)

        # ── Terminate / Revoke short-circuit ───────────────────────
        # A run ended by policy MUST NOT round-trip again: the next
        # decision could be an Allow (Terminate leaves no durable server
        # state, and a Revoke may not have propagated yet).
        if self._run_end_decision is not None:
            self._plugin.last_actions_denied += 1
            self._raise_if_run_ended()

        context_payload: Dict[str, Any] = dict(context) if context else {}
        context_payload["tenant_id"] = self._plugin.tenant_id

        # ── sub-agent RunHandle binding (auto-wired) ──────
        # A spawned sub-agent MUST present its APDP-minted
        # ``run_handle_id`` on every authorize so wl-apdp's
        # scope-membership check can validate the
        # child's server-attested, attenuated scope. This is the SDK's job
        # — the customer never wires it (SDK contract: "run_handle_id
        # without the customer's code wiring it").
        #
        # FAIL-CLOSED, by design: a spawned sub-agent that
        # presents NO valid handle is DENIED (`subagent_run_handle_required`)
        # rather than silently falling through to the ROOT's full Cedar
        # scope — the exact attenuation-bypass privilege escalation this
        # closed. So the plugin presenting the handle is what makes
        # sub-agent scope attenuation real end-to-end.
        #
        # Present it for sub-agent handles AND for a root handle whose
        # ``run_handle_id`` was SERVER-MINTED (the
        # ``_server_run_handle`` case). A root handle with only a client-minted
        # id (older wl-apdp / no run-handle store) still MUST NOT send it:
        # the server store does not know that id, so the membership check
        # would reject a legitimate root call. wl-apdp's
        # scope-membership check treats an un-narrowed root handle as
        # NotApplicable (Cedar governs) and only enforces membership once
        # the root has been narrowed by a runtime Attenuate — so presenting
        # a server-minted root id is inert until an Attenuate fires, then
        # load-bearing. A caller-supplied ``run_handle_id`` in ``context``
        # wins (explicit override), and is never clobbered.
        if (self._is_subagent or self._server_run_handle) and "run_handle_id" not in context_payload:
            context_payload["run_handle_id"] = self.run_handle_id

        # Auto-inject declared-intent into the APDP request
        # body when the agent has called ``watchlight.declare_intent``
        # AND the caller didn't already supply an explicit ``intent``
        # kwarg. This is the load-bearing step that ties the synthetic
        # tool's side effect (mutation of ``self._intent_objective``)
        # to the Cedar intent gate: APDP reads
        # ``request.intent.objective`` and stamps the evaluation
        # context with ``provenance: "declared"``.
        #
        # Caller-supplied ``intent`` wins over the stored value — an
        # explicit ``authorize_action(intent={"objective": ...})``
        # invocation indicates the caller has overriding declared
        # context (e.g., the customer-declared ``start_run`` kwarg
        # path), and the locked decision says declared
        # always wins.
        #
        # wl-apdp's intent is typed (objective AND category, both required;
        # a category-less intent is answered 422). The declared values fill
        # what the caller left out, and an intent that is still untyped is
        # not sent at all (see ``wire_intent``).
        from .declare_intent import wire_intent

        from .errors import IntentRefused

        try:
            effective_intent: Optional[Dict[str, Any]] = wire_intent(
                intent,
                self._intent_objective,
                self._intent_category,
                self._intent_justification,
            )
        except IntentRefused as exc:
            # Refused locally, before any request: a malformed intent is
            # never replaced by none (that would skip intent validation).
            logger.warning("authorize refused locally: %s", exc)
            self._plugin.last_actions_denied += 1
            return AuthorizeResult("deny", reason=f"intent_refused: {exc}")

        # Contract enforcement: every Cedar evaluation
        # MUST attach to a real execution. APDP emits
        # ``policy_decision_made`` with whatever ``execution_id`` we
        # pass; if no ``execution_started`` was ever emitted for that
        # id, the dashboard's `/lineage` tree has nothing to render
        # the deny / allow under (only
        # ``execution_started`` and ``agent_spawn_observed`` mint
        # ``lineage.executions`` rows; non-lifecycle events that
        # arrive without a parent execution stay in
        # ``lineage.execution_events`` but produce no graph node).
        # The defensive late-binding mint guarantees the parent
        # exists before APDP's emission lands.
        # Fail closed, never delayed: the mint is ONE direct attempt that
        # bypasses the run's lineage lane (never behind a retry). Any
        # failure raises, so authorize does not proceed without its
        # execution_started (wl-execution-graph would drop the decision
        # as an orphan). A transient failure is also queued for
        # background delivery; dedup on event_id makes that harmless.
        effective_execution_id = await self._ensure_execution_started_emitted(
            execution_id, direct=True
        )

        # Entity shaping. This layer used to force-wrap all three
        # terms unconditionally (``Agent::"…"`` / ``Action::"…"`` /
        # ``Resource::"…"``) and the in-process backend stripped the
        # wrapper straight back off, so every term reached the
        # compiled engine BARE — and a bare term is a wildcard
        # matching any entity type with that name.
        #
        # The shape is now chosen by the BACKEND. One that declares
        # ``cedar_entities_verbatim`` (the in-process client) gets the
        # caller's terms untouched, so a bare name stays bare and a
        # typed one discriminates. One that declares nothing —
        # ``ApdpClient``, ``MockApdpClient``, any third-party backend
        # — gets the historical wrapping, byte for byte. Shaping
        # stays HERE rather than inside ``ApdpClient.authorize``
        # because that is a published public method and must keep
        # putting a direct caller's terms on the wire untouched. See
        # ``watchlight_core._cedar_entities``.
        #
        # The ONE type this layer still supplies is the DEFAULT
        # subject: with no caller-supplied ``principal``, the acting
        # agent is the subject and it is named TYPED, so a policy
        # written for a ``User::`` can no longer match this agent on
        # a verbatim backend.
        wire_principal, wire_action, wire_resource = shape_for_backend(
            self._plugin.apdp,
            principal or f'Agent::"{self.agent_uuid}"',
            action,
            resource,
        )
        try:
            raw = await self._plugin.apdp.authorize(
                principal=wire_principal,
                action=wire_action,
                resource=wire_resource,
                context=context_payload,
                execution_id=effective_execution_id,
                session_id=self.session_id,
                intent=effective_intent,
                # Bind this decision's lineage to the run: the backend attaches
                # the run's SIGNED credential, and wl-apdp derives eid/rid from
                # its VERIFIED claims so the PolicyDecisionMade nests under this
                # execution's tree (never from spoofable body/context).
                run=self.run,
            )
        except Exception as exc:  # noqa: BLE001 — an unknown decision is a Deny
            # A backend that raises (a custom backend's bug, an exception
            # type nobody planned for) gave no decision: a Deny, never an
            # exception a plugin hook might swallow and fall through from.
            logger.error(
                "governance backend authorize raised %s; failing closed to Deny",
                type(exc).__name__,
            )
            self._plugin.last_actions_denied += 1
            return AuthorizeResult(
                "deny",
                reason=f"governance backend failed ({type(exc).__name__}); authorize defaulted to deny",
            )
        problem = authorize_response_problem(raw)
        if problem is not None:
            # Not a decision any backend sends: refused, never read as the
            # decision it appears to name (an Allow carrying an error, a
            # non-object answer, details that are not an object).
            logger.error(
                "governance backend returned an unrecognised authorize answer (%s); "
                "failing closed to Deny",
                problem,
            )
            self._plugin.last_actions_denied += 1
            return AuthorizeResult(
                "deny", reason="governance backend returned an unrecognised answer; denied"
            )

        # ── Quarantine detection ────────────────────────────
        # Parse the wire decision before reducing to AuthorizeResult
        # so we can distinguish Quarantine from Deny. AuthorizeResult
        # has no quarantine variant on purpose (the kill-switch
        # semantics is exclusive to AgentQuarantinedError); we walk
        # the typed decision first and raise before returning.
        try:
            typed = parse_authorization_decision(raw if isinstance(raw, dict) else {})
        except Exception:  # noqa: BLE001
            # Malformed Quarantine payload — fail-closed per the
            # decision module's docstring. Treat as a Deny rather
            # than crashing the customer's framework; the audit
            # trail still captures the wl-apdp response shape via
            # the plugin's normal observability path.
            logger.exception(
                "wl-apdp authorize response could not be parsed; "
                "failing closed to Deny"
            )
            self._plugin.last_actions_denied += 1
            return AuthorizeResult.deny_transport_failure()

        # ── Side-effect axis (Escalate) ───────────────────────────
        # Record any escalations BEFORE the decision-axis branches
        # below raise. Escalate is orthogonal to the decision — it can
        # fire alongside a Deny, a Quarantine, etc. — so recording it
        # here (ahead of the raises) guarantees the escalation is
        # captured even when a co-occurring halt effect raises.
        # NON-throwing: this never alters the decision.
        self._record_escalations(typed.escalations)

        # ── Allow-downgrade axis (Observe) ────────────────────────
        # Record any observations BEFORE the decision-axis branches
        # below raise. Observe is orthogonal to the decision — it is
        # recorded even when a co-occurring HARD forbid kept the deny
        # (the fail-closed invariant), so recording it here (ahead of
        # the raises) guarantees the monitor signal is captured
        # regardless of the decision. NON-throwing: never alters it.
        self._record_observations(typed.observations)

        # ── Allow-downgrade axis (Attenuate) ──────────────────────
        # Record any attenuations BEFORE the decision-axis branches
        # below raise. Attenuate is orthogonal to the decision — the
        # narrowing is recorded even when a co-occurring HARD forbid
        # kept the deny (the fail-closed invariant), and a fail-closed
        # attenuation (narrowed=False) is recorded for attribution too.
        # The durable narrowing + subsequent enforcement is server-side;
        # this is NON-throwing observability that never alters the
        # decision.
        self._record_attenuations(typed.attenuations)

        if typed.kind == "quarantine":
            # Transition: ACTIVE → QUARANTINED. Stash the decision,
            # fire the kill signal (interrupts every in-flight LLM call
            # from this plugin's HTTP interceptor lane), emit the
            # execution_quarantined event (best-effort, never waiting),
            # propagate up the parent chain, then raise.
            assert isinstance(typed, QuarantineDecision)
            self._quarantine_decision = typed
            self._state = RunHandleState.QUARANTINED
            self._plugin.last_actions_denied += 1
            # Fire the kill signal FIRST. This is the load-bearing
            # security primitive: the in-flight LLM call the agent is
            # waiting on MUST be aborted within the graceful window
            # (2s default) so the agent can't observe any further
            # upstream tokens after wl-apdp said Quarantine. Lineage
            # (best-effort, never waiting) comes after it.
            self._fire_kill_signal()
            await self._emit_quarantine_event(typed, decision_path=True)
            self._propagate_quarantine_to_parents(typed)
            raise AgentQuarantinedError.from_decision(typed)

        if typed.kind == "terminate":
            # Terminate enforcement effect — end the CURRENT run/
            # execution but do NOT bag the agent. Contrast with the
            # quarantine branch above:
            #
            # - Transition ACTIVE → COMPLETED (NOT QUARANTINED): the
            #   agent is not durably contained; a fresh ``start_run``
            #   afterward is clean. We deliberately do NOT set
            #   ``_quarantine_decision`` — that would make the handle
            #   report ``is_quarantined() == True`` and trip the
            #   cross-execution short-circuit, which Terminate must not.
            # - Fire the kill signal with the ``policy_terminate``
            #   reason token (distinct from ``manual_terminate``): the
            #   in-flight LLM call the agent is waiting on MUST be
            #   aborted within the graceful window so the agent can't
            #   observe further upstream tokens after wl-apdp said
            #   Terminate. We reuse the same kill primitive as
            #   quarantine, only the reason token differs.
            # - NO ``execution_quarantined`` event and NO parent-chain
            #   propagation — Terminate is scoped to the current run.
            # - Mark ``_completed`` so a subsequent ``terminate()`` /
            #   ``complete()`` is an idempotent no-op (the run is
            #   already terminal). We stamp the lifecycle tracker
            #   so the eventual ``complete()`` / ``terminate()`` call
            #   does not double-emit a lifecycle event; the terminal
            #   ``execution_failed`` shape is emitted here as the
            #   run's authoritative terminal record.
            assert isinstance(typed, TerminateDecision)
            self._plugin.last_actions_denied += 1
            self._run_end_decision = typed
            self._state = RunHandleState.COMPLETED
            self._completed = True
            self._fire_kill_signal(
                reason=LLM_CALL_INTERRUPTED_REASON_POLICY_TERMINATE
            )
            if (
                "execution_failed" not in self._execution_lifecycle_emitted
                and "execution_completed"
                not in self._execution_lifecycle_emitted
            ):
                self._execution_lifecycle_emitted.add("execution_failed")
                event = self._build_execution_failed_event(
                    f"policy_terminate: {typed.reason}"
                )
                await self._emit_lifecycle_event(event, decision_path=True)
            # The run is over: close the server session too (``_completed``
            # makes the later complete()/terminate() a no-op).
            await self._close_session_after_run_end()
            raise ExecutionTerminatedError.from_decision(typed)

        if typed.kind == "sever_subtree":
            # SeverSubtree enforcement effect — collapse the spawn
            # TREE rooted at this handle (multi-agent containment). This
            # is the THIRD rung of the halt/contain ladder (above
            # Quarantine). The load-bearing distinction from every other
            # effect: the containment is a TREE, so we walk DOWN to
            # descendants (contrast the quarantine walk, which goes UP to
            # parents).
            #
            # Ordering is deliberate and fail-closed:
            #   1. Sever every descendant FIRST (depth-first), so a
            #      compromised child is contained before we surface the
            #      raise. Fail-closed: sever everything reachable and
            #      COUNT any unreachable (dead weak-ref) child — never
            #      silently under-collapse.
            #   2. Then sever THIS handle (the root of the severed
            #      subtree).
            #   3. Raise SubtreeSeveredError carrying the descendant
            #      counts so the caller/audit can see the blast radius.
            #
            # Like Terminate — and UNLIKE Quarantine — the agent is NOT
            # bagged: SEVERED is terminal but ephemeral, there is NO
            # durable state, and a fresh ``start_run`` re-spawns clean.
            # We deliberately do NOT set ``_quarantine_decision``.
            assert isinstance(typed, SeverSubtreeDecision)
            self._plugin.last_actions_denied += 1
            # Snapshot whether the root already had a terminal lifecycle
            # record BEFORE severing, so we only emit the root's
            # ``execution_failed`` once (mirrors the Terminate branch).
            root_needs_lifecycle = (
                "execution_failed" not in self._execution_lifecycle_emitted
                and "execution_completed" not in self._execution_lifecycle_emitted
            )
            severed_count, unreachable_count = self._sever_subtree_descendants(
                typed
            )
            # Now sever THIS handle (the root of the collapse). The root's
            # terminal lifecycle event is awaited here (not scheduled) so
            # it lands deterministically before we raise, matching the
            # Terminate branch's contract.
            self._apply_sever_to_self(typed)
            if root_needs_lifecycle:
                event = self._build_execution_failed_event(
                    f"sever_subtree: {typed.reason}"
                )
                await self._emit_lifecycle_event(event, decision_path=True)
            await self._close_session_after_run_end()
            raise SubtreeSeveredError.from_decision(
                typed,
                descendants_severed=severed_count,
                unreachable_descendants=unreachable_count,
            )

        if typed.kind == "revoke":
            # Revoke enforcement effect — the agent's identity TRUST is
            # withdrawn (the terminal, most-severe verb, ordinal 4). We
            # end the CURRENT run like Terminate, but the DURABLE state
            # lives in wl-registry, NOT
            # in this SDK:
            #
            # - Transition ACTIVE → COMPLETED (NOT QUARANTINED). We do
            #   NOT set ``_quarantine_decision`` and keep NO durable local
            #   state — a revoked agent stays denied across process
            #   restarts because wl-apdp's pre-Cedar trust gate denies
            #   every subsequent authorize once wl-registry has set
            #   ``trust_state=Revoked`` (CQRS: wl-apdp emits the
            #   ``agent.trust.revoke`` event, wl-registry writes it).
            # - Fire the kill signal with the ``revoke`` reason token so
            #   the in-flight LLM call aborts within the graceful window
            #   rather than waiting for the trust write to propagate.
            # - Emit the run's terminal ``execution_failed`` record once
            #   (mirrors Terminate) so audit/replay sees the revoke.
            # - Recovery is operator-only (re-trust via wl-registry);
            #   there is NO in-process recovery path.
            assert isinstance(typed, RevokeDecision)
            self._plugin.last_actions_denied += 1
            self._run_end_decision = typed
            self._state = RunHandleState.COMPLETED
            self._completed = True
            self._fire_kill_signal(reason=LLM_CALL_INTERRUPTED_REASON_REVOKE)
            if (
                "execution_failed" not in self._execution_lifecycle_emitted
                and "execution_completed" not in self._execution_lifecycle_emitted
            ):
                self._execution_lifecycle_emitted.add("execution_failed")
                event = self._build_execution_failed_event(
                    f"revoke: {typed.reason}"
                )
                await self._emit_lifecycle_event(event, decision_path=True)
            await self._close_session_after_run_end()
            raise AgentRevokedError.from_decision(typed)

        result = AuthorizeResult.from_apdp(raw)
        if result.is_allow():
            self._plugin.last_actions_allowed += 1
        else:
            self._plugin.last_actions_denied += 1
        return result

    # ─── Canonical ad-hoc observation emission ──────────────────────

    async def publish_observation(
        self,
        event_type: str,
        payload: Dict[str, Any],
        *,
        parent_execution_id: Optional[str] = None,
        execution_id: Optional[str] = None,
        extra_metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Emit an ad-hoc canonical :class:`ExecutionEvent` for this run.

        Constructs the canonical flat envelope + ``payload`` shape from
        this handle's session/agent/tenant context (matching the
        canonical ``ExecutionEvent`` wire layout, kept in lockstep with
        the Rust and TypeScript lanes), validates the result
        against :class:`watchlight_core.events_schema.ExecutionEvent`,
        and posts it to APDP's ``POST /v1/events`` ingest.

        Plugin authors and workload code SHOULD call this instead of
        constructing events by hand — the envelope shape is owned by
        the SDK and may evolve (e.g. future canonical fields,
        audit signing). Customers using the helper inherit those
        changes automatically without touching workload code.

        Args:
            event_type: Canonical event-type discriminator (snake_case
                — one of the values in
                :class:`watchlight_core.events_schema.EventType`).
                See the Watchlight Agent SDK documentation for the
                closed set.
            payload: Event-type-specific payload. MUST match the
                corresponding payload variant in
                :mod:`watchlight_core.events_schema` (e.g.
                :class:`ToolCallObservedPayload` for
                ``"tool_call_observed"``). Validation is enforced
                BEFORE the network call — a shape mismatch raises
                ``ValidationError`` here, not at the receiving service.
            parent_execution_id: Optional parent execution_id stamped
                on the envelope so downstream consumers
                (wl-execution-graph builder, dashboard lineage tree)
                can stitch the event into the correct parent context.
                ``None`` when omitted.
            execution_id: Optional override that MUST equal the
                handle's own :attr:`execution_id`. The kwarg is kept
                for source-compatibility with the earlier
                signature; passing it is now optional. Workloads that
                threaded a workflow-root execution id distinct from
                the handle's own id MUST migrate to the dedicated
                :meth:`publish_observation_for_execution` method —
                the explicit escape hatch with intentional naming. A
                divergent value raises :class:`WatchlightContractError`
                per the locked lineage contract.
            extra_metadata: Additional fields merged into
                ``envelope.metadata`` (which always carries
                ``metadata.source = self._observation_source`` from the
                handle subclass). Useful for framework-specific
                annotations that don't belong in the closed-set
                payload variants.

        Raises:
            WatchlightContractError: If the handle is not inside its
                ``async with`` block (no open lineage; refuses on
                ambiguity), OR if the caller passes
                an ``execution_id`` kwarg that does not match the
                handle's own ``self.execution_id`` (the wire envelope
                MUST attribute to the open handle's execution; a
                divergent value would orphan the event in another
                execution's tree).
            pydantic.ValidationError: If the constructed event fails
                Pydantic validation (wrong payload shape for the
                event_type, malformed envelope, unknown event_type).
                The error is raised BEFORE the network call so
                callers see the diagnostic at the line of the bad
                payload, not asynchronously from APDP's 422 reject.
            WatchlightError: If APDP rejects the publish with a
                non-2xx response, OR if the defensive
                ``execution_started`` emit fails before the
                observation can be published (fail-loud —
                we never silently publish an observation into a tree
                with no root).

        Notes:
            **Lineage contract**: this method calls
            :meth:`_ensure_execution_started_emitted` BEFORE the
            observation event is posted so any non-lifecycle event
            the SDK emits has a parent ``execution_started`` row to
            attach under. The emission is idempotent per
            (handle, execution_id) so two consecutive
            ``publish_observation`` calls on the same handle produce
            a SINGLE ``execution_started`` event.

            **Sub-agent governance**:
            this helper attributes the event to the handle it's
            called on. When a plugin's interceptor needs to emit an
            event for a sub-agent's action, it MUST call
            ``subagent_handle.publish_observation(...)``, NEVER the
            parent's. Using the parent's handle would attribute the
            event to the wrong principal — a privilege-attribution
            bug that breaks the audit trail.

            Plugin RunHandle subclasses should override the
            :attr:`_observation_source` class attribute with a
            framework-identifying string (e.g.
            ``"langgraph.workload"``) so downstream consumers can
            attribute the event to the originating framework.
        """
        # Local import to avoid the module-load-time circular
        # dependency: events_schema imports nothing from run_handle
        # but the runtime validation path is lazy.
        from .errors import WatchlightContractError
        from .events_schema import ExecutionEvent as ExecutionEventModel

        # ── fail-closed lineage contract guards ────
        # Refuse a publish on a handle that is not inside its
        # ``async with`` block. The contract requires the
        # ``execution_started`` parent row before any non-lifecycle
        # event lands; the only place that row is emitted by default
        # is the handle's ``__aenter__``.
        # Locked ungoverned-request-gate direction:
        # NO ``allow_no_run_handle=True`` escape hatch.
        if not self._aentered:
            raise WatchlightContractError(
                "publish_observation() called without an open RunHandle. "
                "Non-lifecycle events MUST attach to an execution per "
                "the lineage contract. Wrap the call in "
                "`async with await client.start_run(...) as handle:`."
            )

        # A run ended by a policy decision publishes nothing further.
        self._raise_if_run_ended()

        # Refuse a publish whose explicit ``execution_id`` does not
        # match the handle's own ``execution_id``. Earlier,
        # workloads passed a workflow-root id distinct from the
        # handle's id; with the contract guard active that would
        # silently emit an observation into a different execution
        # tree (the handle's ``execution_started`` parent is for the
        # HANDLE's id, not the caller-supplied one). Workloads with
        # a genuine cross-execution observation need MUST use the
        # explicit escape hatch
        # :meth:`publish_observation_for_execution` (a separately-
        # named method for a clear call site; the
        # locked-contract direction rejects a kwarg
        # flag on ``publish_observation`` itself).
        if execution_id is not None and execution_id != self.execution_id:
            raise WatchlightContractError(
                f"publish_observation() received execution_id="
                f"{execution_id!r} which does not match the handle's "
                f"execution_id ({self.execution_id!r}). The event "
                f"would orphan into a different execution's tree. "
                f"Workloads with cross-execution observation needs "
                f"must use publish_observation_for_execution() "
                f"— the explicit escape hatch with intentional naming. "
                f"For events about this handle's run, omit the "
                f"execution_id kwarg or pass the handle's own "
                f"execution_id."
            )

        # Delegate the build / validate / parent-mint / emit pipeline
        # to the shared internal helper. The strict guards above are
        # this method's load-bearing contract; everything below is
        # mechanically identical between ``publish_observation`` and
        # its cross-execution escape hatch ``publish_observation_for_execution``,
        # so we keep one code path for both.
        await self._publish_observation_internal(
            event_type=event_type,
            payload=payload,
            execution_id=execution_id or self.execution_id,
            parent_execution_id=parent_execution_id,
            root_execution_id=None,
            extra_metadata=extra_metadata,
        )

    async def publish_observation_for_execution(
        self,
        event_type: str,
        *,
        execution_id: str,
        payload: Dict[str, Any],
        parent_execution_id: Optional[str] = None,
        root_execution_id: Optional[str] = None,
        extra_metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Publish an observation that attaches to a DIFFERENT execution
        than this handle's own ``self.execution_id``.

        This is the EXPLICIT escape hatch for legitimate cross-execution
        observations — the strict :meth:`publish_observation` method
        refuses any divergent ``execution_id`` kwarg by design (per
        the locked lineage contract), so workloads with
        a genuine need to attach an event to an execution other than
        this handle's call this method instead.

        Canonical use cases:

        - A workflow orchestrator (e.g. LangGraph node closure) wants
          its ``plan_observed`` / ``api_request_observed`` events to
          attach to the workflow ROOT ``execution_id`` rather than the
          per-node handle's own id, so the dashboard's ``/lineage``
          tree renders a single coherent run instead of N orphan roots.
        - A sub-agent emitting an observation about its parent's
          execution context (e.g. a child agent recording an upstream
          policy decision the parent triggered).
        - Cross-agent telemetry where the canonical execution context
          lives on a different handle than the one driving the emit.

        The method's name (``_for_execution``) is the deliberate
        intent signal: a caller reading the call site sees this is
        NOT the default observation path. The escape hatch
        is a separately-named method, not a kwarg flag on
        :meth:`publish_observation` — the call site documents the
        cross-execution intent at a glance.

        Args:
            event_type: Canonical event-type discriminator (snake_case
                — one of the values in
                :class:`watchlight_core.events_schema.EventType`).
            execution_id: REQUIRED — the target execution_id the event
                attaches to. The signature makes this a keyword-only
                positional argument so a caller cannot accidentally
                omit it and silently fall back to the handle's own id
                (which would be a regression to the
                :meth:`publish_observation` semantics).
            payload: Event-type-specific payload. MUST match the
                corresponding payload variant in
                :mod:`watchlight_core.events_schema`.
            parent_execution_id: Optional parent execution_id stamped
                on the envelope so wl-execution-graph can stitch the
                event into the right parent context. ``None`` when
                omitted (the event is rooted at ``execution_id``).
            root_execution_id: Optional root execution_id for the
                lineage tree. ``None`` defaults to ``execution_id``
                (the event is the root of its own tree from
                wl-execution-graph's point of view).
            extra_metadata: Additional fields merged into
                ``envelope.metadata`` (which always carries
                ``metadata.source = self._observation_source``).

        Raises:
            WatchlightContractError: If the handle is not inside its
                ``async with`` block. Even the escape hatch refuses to
                emit observations without an open governance context,
                per the closed-set lineage contract (the SDK is the
                first enforcement layer).
            pydantic.ValidationError: If the constructed event fails
                Pydantic validation (wrong payload shape for the
                event_type, malformed envelope, unknown event_type).
            WatchlightError: If APDP rejects the publish.

        Notes:
            **Caller responsibility**: the target ``execution_id`` MUST
            already have its ``execution_started`` row on the wire —
            this method does NOT auto-mint
            ``execution_started`` (the ingest gateway validates
            and rejects orphans with HTTP 422, and the SDK cannot
            know the target's started state from inside this handle's
            context). Workloads that thread a workflow-root
            ``execution_id`` typically have a separate emission path
            (a framework callback handler, an explicit
            ``mark_execution_started_emitted(...)`` call, or the
            ``start_run(...)`` lifecycle of the root handle) that
            lands the parent row.

            **No execution_id == self.execution_id check**: that's the
            whole point of this method. A caller who passes the
            handle's own ``execution_id`` to this method gets the same
            wire result as :meth:`publish_observation`; the divergent
            case is the legitimate one.

            **No defensive execution_started emit**: unlike
            :meth:`publish_observation`, this method does NOT call
            :meth:`_ensure_execution_started_emitted` for the target
            execution_id. The handle's own
            ``_emitted_execution_started_for`` set tracks emissions
            for executions THIS handle owns; minting a synthetic
            ``execution_started`` for an arbitrary external
            ``execution_id`` would emit it with this handle's identity
            (``agent_uuid`` / ``session_id``), which is the wrong
            attribution. The ingest gateway is the right enforcement
            layer for the target's lifecycle precedence.

            **Sub-agent governance**:
            cross-execution attribution does NOT change the identity
            stamped on the wire — the event still carries this
            handle's ``agent_id`` and ``session_id``. Use the
            sub-agent's own handle if the event should be attributed
            to the sub-agent's principal.

        Migration from the earlier :meth:`publish_observation` usage:

        Before (now raises ``WatchlightContractError``):

            await handle.publish_observation(
                "plan_observed",
                payload={...},
                parent_execution_id=root_exec_id,
                execution_id=root_exec_id,  # cross-execution
            )

        After:

            await handle.publish_observation_for_execution(
                "plan_observed",
                execution_id=root_exec_id,
                payload={...},
            )

        A ``parent_execution_id`` equal to ``execution_id``, or any parent
        on a root handle, is dropped: wl-apdp would refuse the batch.
        """
        # Local import to avoid the module-load-time circular
        # dependency (mirrors the publish_observation pattern).
        from .errors import WatchlightContractError

        # The handle MUST still be inside its ``async with`` block.
        # Even the explicit escape hatch refuses to emit observations
        # without an open governance context — the closed-set lineage
        # contract makes the SDK the first enforcement layer; a
        # cross-execution emit on a disposed handle would carry a
        # stale principal identity that the audit chain cannot
        # reconstruct.
        if not self._aentered:
            raise WatchlightContractError(
                "publish_observation_for_execution() called without an "
                "open RunHandle. Even the explicit cross-execution "
                "escape hatch requires an open governance context — "
                "the wire envelope carries this handle's agent_id / "
                "session_id, and a disposed handle would emit stale "
                "attribution. Wrap the call in "
                "`async with await client.start_run(...) as handle:`."
            )

        # A run ended by a policy decision publishes nothing further.
        self._raise_if_run_ended()

        # NOTE: NO ``execution_id == self.execution_id`` check — that
        # is precisely what distinguishes this method from
        # ``publish_observation``. A caller has explicitly opted into
        # cross-execution attribution by reaching this method, so the
        # SDK accepts the divergent id without raising. The target
        # execution's ``execution_started`` precedence is enforced at
        # the ingest gateway (the right layer — it has visibility
        # across all handles and services).
        await self._publish_observation_internal(
            event_type=event_type,
            payload=payload,
            execution_id=execution_id,
            parent_execution_id=parent_execution_id,
            root_execution_id=root_execution_id,
            extra_metadata=extra_metadata,
        )

    async def _publish_observation_internal(
        self,
        *,
        event_type: str,
        payload: Dict[str, Any],
        execution_id: str,
        parent_execution_id: Optional[str],
        root_execution_id: Optional[str],
        extra_metadata: Optional[Dict[str, Any]],
    ) -> None:
        """Build, validate, and emit an observation event.

        Shared between :meth:`publish_observation` (which adds the
        strict same-execution guard + defensive
        ``execution_started`` mint) and
        :meth:`publish_observation_for_execution` (which skips both
        because the caller is explicitly cross-execution).

        Both call sites share
        ONE code path so envelope-shape changes land in one place.
        """
        # Local import to avoid the module-load-time circular
        # dependency: events_schema imports nothing from run_handle
        # but the runtime validation path is lazy.
        from .events_schema import ExecutionEvent as ExecutionEventModel

        tenant_id = getattr(self._plugin, "tenant_id", None)
        timestamp = datetime.now(timezone.utc).isoformat().replace(
            "+00:00", "Z"
        )

        metadata: Dict[str, Any] = {"source": self._observation_source}
        if extra_metadata:
            # extra_metadata wins over the default source so a caller
            # that explicitly stamps a more specific source tag (e.g.
            # ``"langgraph.workload.scenario_denied"``) takes effect.
            # The base ``source`` is the fall-back when the caller
            # didn't override.
            for key, value in extra_metadata.items():
                metadata[key] = value

        event: Dict[str, Any] = {
            "event_id": f"evt_{uuid.uuid4()}",
            "event_type": event_type,
            "timestamp": timestamp,
            "execution_id": execution_id,
            "agent_id": self.agent_uuid,
            "session_id": self.session_id,
            "payload": payload,
            "metadata": metadata,
        }
        if tenant_id is not None:
            event["tenant_id"] = tenant_id
        # wl-apdp refuses the WHOLE /v1/events batch when an event's
        # parent is its own execution, or when a ROOT run (a handle with no
        # parent) names a parent. Drop such a parent here rather than lose
        # the batch; a genuine parent (a sub-agent handle's) is kept.
        if (
            parent_execution_id is not None
            and parent_execution_id != execution_id
            and self.parent_execution_id is not None
        ):
            event["parent_execution_id"] = parent_execution_id
        if root_execution_id is not None:
            event["root_execution_id"] = root_execution_id

        # Pydantic validation runs the per-event-type payload check
        # (see ``ExecutionEvent._validate_payload_matches_event_type``).
        # Surface the typed ValidationError directly to the caller —
        # workload code should see the diagnostic at the call site so
        # a shape mismatch is fixed locally, not asynchronously from
        # APDP's reject path.
        ExecutionEventModel.model_validate(event)

        # Contract enforcement: every non-lifecycle
        # event MUST attach to an execution whose
        # ``execution_started`` was emitted earlier. We only run the
        # defensive late-binding mint when the target ``execution_id``
        # is THIS handle's own — for cross-execution emits via
        # :meth:`publish_observation_for_execution`, the target's
        # ``execution_started`` is the responsibility of whichever
        # path started that execution (typically the root handle's
        # ``__aenter__`` or a framework callback handler), and the
        # ingest gateway is the authoritative check on
        # precedence across services. Minting an
        # ``execution_started`` here for an arbitrary external
        # ``execution_id`` would stamp it with THIS handle's
        # ``agent_uuid`` / ``session_id``, which is the wrong
        # attribution.
        if execution_id == self.execution_id:
            await self._ensure_execution_started_emitted(execution_id)

        ok = await self._plugin.apdp.publish_events(self.run, [event])
        if not ok:
            # Translate the transport-level failure into a typed
            # error so workload code can distinguish "shape was
            # wrong" (ValidationError above) from "APDP unreachable
            # or rejected the publish" (this branch).
            raise WatchlightError(
                f"APDP rejected publish_observation for event_type "
                f"{event_type!r} (event_id={event['event_id']})"
            )

    # ─── quarantine event emission + parent propagation ─────

    async def _emit_quarantine_event(
        self, decision: QuarantineDecision, *, decision_path: bool = False
    ) -> None:
        """Publish an ``execution_quarantined`` event for this handle.

        Best-effort: observability is never allowed to break the
        customer's framework. If APDP is unreachable the audit trail
        loses this event, but the in-process kill switch still fires
        (the customer-visible failure mode is the raised
        :class:`AgentQuarantinedError`, not a silent drop).

        Idempotent: at most one event is emitted per handle no matter
        how many quarantine round-trips happen — the handle is
        terminal once quarantined.
        """
        if self._quarantine_event_emitted:
            return
        self._quarantine_event_emitted = True

        tenant_id = getattr(self._plugin, "tenant_id", None)
        # Emit on the handle's stable execution_id so the
        # canonical ``lineage.executions`` row reflects the
        # ``execution_started`` → ``execution_quarantined`` transition
        # without spawning a phantom orphan row. Plugins that want a
        # different execution_id can emit themselves and set
        # ``_quarantine_event_emitted = True`` to suppress this.
        execution_id = self.execution_id
        timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

        event: Dict[str, Any] = {
            "event_id": f"evt_{uuid.uuid4()}",
            "event_type": "execution_quarantined",
            "timestamp": timestamp,
            "execution_id": execution_id,
            "agent_id": self.agent_uuid,
            "session_id": self.session_id,
            "tenant_id": tenant_id,
            "metadata": {"source": _QUARANTINE_PROVENANCE_TAG},
            "payload": {
                "policy_id": decision.policy_id,
                "anomaly_score": decision.anomaly_score,
                # Payload contract — we surface the threshold
                # as 0.0 when wl-apdp's response didn't carry it
                # (the SDK only sees the post-decision payload, not
                # the per-tier threshold the policy compared against).
                # wl-apdp's policy template encodes the threshold in
                # the policy itself, so 0.0 is a truthful "we don't
                # know" rather than a misleading bound.
                "threshold": 0.0,
                # Optional on the wire: a STRUCTURAL Cedar quarantine has no
                # IF model behind it. Send the UUID when there is one; an
                # empty string used to be rejected at ingest (422), which
                # silently dropped the audit of the quarantine transition.
                **(
                    {"model_version": decision.model_version}
                    if decision.model_version
                    else {}
                ),
                "contributing_features": [
                    fc.model_dump() for fc in decision.contributing_features
                ],
                "reason": decision.reason,
            },
        }
        try:
            if decision_path:
                await self._publish_on_decision_path(event)
            else:
                await self._plugin.apdp.publish_events(self.run, [event])
        except Exception:  # noqa: BLE001 — observability is best-effort
            logger.debug(
                "execution_quarantined event emission failed", exc_info=True
            )

    def _propagate_quarantine_to_parents(
        self, decision: QuarantineDecision
    ) -> None:
        """Propagate Quarantine state UP through every registered parent
        handle.

        Locked design decision: "quarantine state DOES cross
        goals for the same agent. One bad goal taints the whole
        agent — bag the agent, not just one bucket of work." Any
        parent handle in the chain that's still ACTIVE flips to
        QUARANTINED carrying the SAME decision. Already-QUARANTINED
        parents are left untouched (idempotent — the first child to
        quarantine wins for audit reasons; subsequent children
        observing the same decision don't overwrite the existing
        attribution).

        This is a load-bearing conformance path in
        :mod:`watchlight_core_testing.conformance`.
        """
        parent_ref = self._parent_handle_ref
        visited: set[int] = {id(self)}
        while parent_ref is not None:
            parent = parent_ref()
            if parent is None:
                # Parent has been GC'd — nothing more to walk.
                break
            if id(parent) in visited:
                # Defensive cycle guard. Cycles can't actually exist
                # because spawn_subagent only links downward, but
                # this keeps us safe if a customer plugin builds an
                # exotic topology by hand.
                break
            visited.add(id(parent))
            if parent._state == RunHandleState.ACTIVE:
                parent._state = RunHandleState.QUARANTINED
                parent._quarantine_decision = decision
                # Emit on the parent too — every quarantined handle
                # must produce its own execution_quarantined event so
                # the audit replay can render the full propagation
                # tree. We do NOT await here because the propagation
                # walk is synchronous; the parent's emission is
                # fire-and-forget via a background task. Plugins
                # that need a stronger guarantee can override this
                # method to await sequentially.
                try:
                    self._spawn_background_quarantine_emit(parent, decision)
                except Exception:  # noqa: BLE001 — observability is
                    # best-effort
                    logger.debug(
                        "parent emit task spawn failed", exc_info=True
                    )
                # Fire the parent's kill signal too. The locked
                # decision says quarantine bags the whole agent
                # tree, not just the offending branch; the kill switch
                # must follow. Each parent handle may sit on a
                # different plugin instance with its own
                # ``kill_signal_registry``; the cascade fires every
                # registry on the chain that has live in-flight calls.
                try:
                    parent._fire_kill_signal()
                except Exception:  # noqa: BLE001 — the kill cascade
                    # must NEVER break the in-process propagation walk.
                    # An in-flight LLM call that escapes the kill is
                    # logged but doesn't block the security envelope.
                    logger.warning(
                        "parent kill-signal cascade failed (continuing)",
                        exc_info=True,
                    )
            parent_ref = parent._parent_handle_ref

    # ─── SeverSubtree — depth-first descendant collapse ─────────────

    def _sever_subtree_descendants(
        self, decision: SeverSubtreeDecision
    ) -> tuple[int, int]:
        """Depth-first collapse of every descendant RunHandle this
        handle spawned (the sub-agent spawn subtree rooted here).

        This is the DOWNWARD dual of
        :meth:`_propagate_quarantine_to_parents` (which walks UP). It
        walks the ``_child_handle_refs`` registry — populated by
        :meth:`_register_child_handle` at ``spawn_subagent`` time —
        transitively over grandchildren, great-grandchildren, and so on.

        For every LIVE descendant still in a non-terminal state
        (``ACTIVE``), it: flips the descendant to ``SEVERED``, stamps the
        decision, fires the descendant's kill signal with
        ``reason=sever_subtree`` (each descendant may sit on a different
        plugin instance with its own ``kill_signal_registry``), and
        schedules its terminal lifecycle event.

        **Fail-closed containment (never under-collapse).** A child weak
        ref that resolves to ``None`` (the descendant was GC'd) is
        COUNTED as unreachable and surfaced on the returned tuple / the
        raised :class:`SubtreeSeveredError` — we sever everything we CAN
        reach and make the gap loud rather than silently leaving a
        possibly-compromised descendant alive. The kill cascade for one
        descendant is wrapped so a failure there can NEVER abort the walk
        (a stuck registry must not leave the rest of the tree un-severed).

        Returns ``(descendants_severed, unreachable_descendants)``.
        """
        severed = 0
        unreachable = 0
        # Iterative DFS with an explicit stack + cycle guard. Cycles
        # can't actually exist (spawn_subagent only links downward), but
        # the guard keeps us safe against an exotic hand-built topology.
        visited: set[int] = {id(self)}
        stack: List[BaseRunHandle] = []

        def _push_children(handle: "BaseRunHandle") -> None:
            nonlocal unreachable
            for child_ref in handle._child_handle_refs:
                child = child_ref()
                if child is None:
                    # Dead weak ref — the descendant was GC'd. Count it
                    # loudly; NEVER silently skip (fail-closed).
                    unreachable += 1
                    continue
                if id(child) in visited:
                    continue
                stack.append(child)

        _push_children(self)
        while stack:
            node = stack.pop()
            if id(node) in visited:
                continue
            visited.add(id(node))
            # Recurse into this node's children BEFORE severing it, so
            # even if severing raises we've still enqueued the deeper
            # descendants for collapse.
            _push_children(node)
            if node._state == RunHandleState.ACTIVE:
                node._apply_sever_to_self(decision, schedule_lifecycle=True)
                severed += 1
            # A descendant already SEVERED / QUARANTINED / COMPLETED is a
            # terminal node — leave its attribution intact (idempotent).

        return severed, unreachable

    def _apply_sever_to_self(
        self,
        decision: SeverSubtreeDecision,
        *,
        schedule_lifecycle: bool = False,
    ) -> None:
        """Flip THIS handle to the terminal ``SEVERED`` state, stamp the
        decision, fire its kill signal (``reason=sever_subtree``), and
        record the terminal lifecycle event.

        Used both for the root that received the ``SeverSubtree``
        decision and for every descendant the depth-first walk collapses.
        Idempotent — a handle already ``SEVERED`` is left untouched.

        ``schedule_lifecycle`` controls how the terminal
        ``execution_failed`` event is emitted:

        - ``False`` (the root): the caller (the ``authorize_action``
          dispatch) awaits the emit itself, so we only stamp the
          lifecycle-emitted tracker here.
        - ``True`` (a descendant, severed from inside the synchronous
          DFS): schedule the emit as a background task (mirrors the
          quarantine parent-walk's fire-and-forget emit) so the walk
          stays synchronous.
        """
        if self._state == RunHandleState.SEVERED:
            return
        self._sever_decision = decision
        self._state = RunHandleState.SEVERED
        self._completed = True
        # Fire the kill signal — the in-flight LLM call this handle is
        # waiting on MUST be aborted within the graceful window so the
        # (possibly compromised) agent can't observe further upstream
        # tokens after wl-apdp said SeverSubtree. Wrap so a failing
        # registry never aborts the surrounding DFS walk.
        try:
            self._fire_kill_signal(
                reason=LLM_CALL_INTERRUPTED_REASON_SEVER_SUBTREE
            )
        except Exception:  # noqa: BLE001 — the kill cascade must NEVER
            # break the in-process sever walk; a call that escapes is
            # logged but doesn't punch a hole in the containment envelope.
            logger.warning(
                "sever-subtree kill-signal fire failed (continuing)",
                exc_info=True,
            )
        # Terminal lifecycle record — stamp the lifecycle tracker so a later
        # complete()/terminate() does not double-emit.
        if (
            "execution_failed" not in self._execution_lifecycle_emitted
            and "execution_completed" not in self._execution_lifecycle_emitted
        ):
            self._execution_lifecycle_emitted.add("execution_failed")
            if schedule_lifecycle:
                self._spawn_background_sever_lifecycle_emit(self, decision)
        if schedule_lifecycle:
            # A severed descendant's server session is closed too (in the
            # background, so the synchronous walk stays synchronous).
            self._spawn_background_session_close(self)

    @staticmethod
    def _spawn_background_sever_lifecycle_emit(
        handle: "BaseRunHandle",
        decision: SeverSubtreeDecision,
    ) -> None:
        """Schedule a descendant's terminal ``execution_failed`` emit on
        the running loop without awaiting it, so the synchronous DFS
        walk stays synchronous.

        Extracted as a static method (mirrors
        :meth:`_spawn_background_quarantine_emit`) so tests can
        monkey-patch it deterministically. If no loop is running the
        emit is skipped — a synchronous test path then asserts on the
        state transition + kill counts rather than the emitted event.
        """
        import asyncio

        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return
        event = handle._build_execution_failed_event(
            f"sever_subtree: {decision.reason}"
        )
        loop.create_task(handle._emit_lifecycle_event(event))

    @staticmethod
    def _spawn_background_session_close(handle: "BaseRunHandle") -> None:
        """Schedule :meth:`_close_session_after_run_end` on the running
        loop without awaiting it (no loop: skipped)."""
        import asyncio

        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return
        loop.create_task(handle._close_session_after_run_end())

    async def _close_session_after_run_end(self) -> None:
        """Close the server session of a run ended by a policy decision
        (Terminate, Revoke, SeverSubtree).

        The handle is already terminal locally (``_completed``), so the
        normal :meth:`complete` would be a no-op; without this the server
        session stays open until its TTL. Never raises: the decision's
        typed error is what the caller must see. A failed close is logged
        at WARNING (no credential values).
        """
        try:
            ok = await self._plugin.apdp.complete_session(self.run)
        except Exception as exc:  # noqa: BLE001 — the decision raise wins
            logger.warning(
                "session close after a run-ending decision failed (session=%s): %s",
                self.session_id,
                type(exc).__name__,
            )
            return
        if ok is False:
            logger.warning(
                "session close after a run-ending decision was not accepted "
                "(session=%s); it ends at its TTL",
                self.session_id,
            )

    def _raise_if_run_ended(self) -> None:
        """Raise the typed error of the decision that ended this run, if
        any: Quarantine, SeverSubtree, Terminate or Revoke. Re-fires the
        kill signal (idempotent) so a late in-flight call is aborted too.
        Used by every authorize / publish / spawn entry point."""
        if self._state == RunHandleState.QUARANTINED and self._quarantine_decision is not None:
            self._fire_kill_signal()
            raise AgentQuarantinedError.from_decision(self._quarantine_decision)
        if self._state == RunHandleState.SEVERED and self._sever_decision is not None:
            self._fire_kill_signal(reason=LLM_CALL_INTERRUPTED_REASON_SEVER_SUBTREE)
            raise SubtreeSeveredError.from_decision(self._sever_decision)
        decision = self._run_end_decision
        if isinstance(decision, TerminateDecision):
            self._fire_kill_signal(reason=LLM_CALL_INTERRUPTED_REASON_POLICY_TERMINATE)
            raise ExecutionTerminatedError.from_decision(decision)
        if isinstance(decision, RevokeDecision):
            self._fire_kill_signal(reason=LLM_CALL_INTERRUPTED_REASON_REVOKE)
            raise AgentRevokedError.from_decision(decision)

    # ─── kill-signal invocation ────────────────────────────

    def _fire_kill_signal(
        self,
        reason: str = LLM_CALL_INTERRUPTED_REASON_QUARANTINE,
    ) -> None:
        """Fire the plugin's :class:`InterceptorKillRegistry` if wired.

        The load-bearing handover between the SDK Quarantine
        state machine and the kill-signal protocol. When
        the plugin has a registry (typically because CONNECT mode is
        active), this triggers the in-flight LLM-call abort path:

        1. Every tracked request's ``cancel_requested`` event fires —
           the interceptor races its upstream task against the event
           and breaks out, returning a 503-ish error to the agent code.
        2. Requests that don't ack within the graceful window
           (2 seconds by default) are escalated to wl-proxy's
           ``/internal/v1/connect/kill`` endpoint, which forcibly
           closes the upstream TCP socket.
        3. Each cancelled request emits an ``llm_call_interrupted``
           canonical event recording what actually happened —
           ``graceful``, ``proxy_hard_kill`` (only on a CONFIRMED
           kill), or ``unconfirmed``.

        Non-blocking: ``cancel`` is awaitable and returns immediately
        for the empty-in-flight case; the registry's per-request
        waiters run on the existing event loop as background tasks.
        The customer's agent code observes the
        :class:`AgentQuarantinedError` we raise *after* this call;
        whether the kill landed gracefully or via hard-kill is
        observable separately via the emitted lineage event.

        Safe to call when the plugin has no registry (``None`` /
        absent attribute) — the method is a no-op in that case so
        unit tests, demo plugins, and any code path without the
        CONNECT sidecar continue to work without surfacing a
        misconfigured-plugin error. Every plugin shipped from this
        repository now wires
        :func:`~watchlight_core.kill_signal.default_kill_signal_registry`,
        so reaching the no-op branch means a third-party or
        deliberately unwired plugin — and it is WARNED, once, rather
        than passing silently. A silent no-op here is what let
        operators believe in-flight interruption was active when it
        was not.
        """
        registry = getattr(self._plugin, "kill_signal_registry", None)
        if registry is None:
            if not getattr(self, "_warned_kill_signal_unwired", False):
                # Instance-scoped latch; `object.__setattr__` keeps
                # this working for frozen/slotted plugin handles.
                try:
                    object.__setattr__(self, "_warned_kill_signal_unwired", True)
                except Exception:  # noqa: BLE001 — never break the kill path
                    pass
                logger.warning(
                    "kill signal requested but this plugin has no "
                    "kill_signal_registry — in-flight LLM-call interruption is "
                    "NOT available for this run. Nothing was interrupted and no "
                    "llm_call_interrupted evidence will be produced."
                )
            return
        # ``cancel`` is async — schedule it on the running loop and
        # return immediately. The customer's framework's running
        # tasks (including the one that called ``authorize_action``)
        # continue without waiting for the abort to settle; the
        # ``AgentQuarantinedError`` we raise immediately after this
        # call is the customer-visible signal that the agent has been
        # quarantined.
        import asyncio

        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            # No running loop — sync test path. Best-effort: we can't
            # schedule the async ``cancel`` so we skip. The customer's
            # observability test would see no ``llm_call_interrupted``
            # event in this case; that's correct — there's no live
            # event loop to drive a cancellation against.
            logger.debug(
                "kill-signal fired without a running loop "
                "(sync path); registry cancel skipped"
            )
            return
        loop.create_task(registry.cancel(reason))

    @staticmethod
    def _spawn_background_quarantine_emit(
        parent: "BaseRunHandle",
        decision: QuarantineDecision,
    ) -> None:
        """Schedule the parent's ``_emit_quarantine_event`` on the
        running loop without awaiting it.

        Extracted as a static method so tests can monkey-patch the
        background-task behaviour deterministically. The default
        implementation uses ``asyncio.ensure_future`` on the current
        loop; if no loop is running (synchronous test path) the
        emission is skipped — the test's own assertions on
        ``published_events`` then cover only the originating handle.
        """
        import asyncio

        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return
        loop.create_task(parent._emit_quarantine_event(decision))

    # ─── lifecycle emit contract ────────────────────────────

    def mark_execution_completed_emitted(self) -> None:
        """Tell the SDK an ``execution_completed`` event has already
        been emitted for this handle's :attr:`execution_id`.

        Framework translators that emit the canonical
        ``execution_completed`` event from a callback (LangGraph
        ``on_chain_end``, OpenClaw ``session_end``, Claude Agent SDK
        ``Stop``, etc.) MUST call this method BEFORE their own
        ``publish_events`` so the subsequent :meth:`complete`
        invocation does NOT double-emit.

        Idempotent — subsequent calls are no-ops. The dual
        :meth:`mark_execution_failed_emitted` covers the failure path.

        This is part of the lifecycle contract that closes the lifecycle
        hole observed in ``lineage.executions`` (rows stuck at
        ``status='started'``): every handle's :meth:`complete` now
        emits ``execution_completed`` defensively, but a framework
        translator that already emitted the same event must suppress
        the defensive emit via this method to avoid two rows landing
        for the same logical close.
        """
        self._execution_lifecycle_emitted.add("execution_completed")

    def mark_execution_failed_emitted(self) -> None:
        """Tell the SDK an ``execution_failed`` event has already been
        emitted for this handle's :attr:`execution_id`.

        Mirror of :meth:`mark_execution_completed_emitted` for the
        failure path. Framework translators that emit
        ``execution_failed`` from a callback (LangGraph
        ``on_chain_error``, Claude Agent SDK ``PostToolUseFailure``,
        etc.) MUST call this before their own ``publish_events``.

        Once marked, the subsequent :meth:`terminate` invocation
        skips the defensive ``execution_failed`` emit but still runs
        the rest of the close path (state transition + client-side
        session release).
        """
        self._execution_lifecycle_emitted.add("execution_failed")

    @property
    def execution_lifecycle_emitted(self) -> Set[str]:
        """Snapshot of the lifecycle-emit tracker.

        Exposed read-only for tests and dashboard introspection. The
        set contains the canonical wire event_type strings the SDK has
        either emitted itself or been told a framework translator
        emitted — at most ``{"execution_completed", "execution_failed"}``
        for any given handle.
        """
        return set(self._execution_lifecycle_emitted)

    def _get_lifecycle_lock(self) -> asyncio.Lock:
        """Lazily create (and cache) the :class:`asyncio.Lock` that
        serialises :meth:`complete` and :meth:`terminate`.

        Lazy because constructing the lock at ``__init__`` time would
        bind it to whichever loop is running (or none) — the lazy
        creation defers the binding to the first acquire which is
        always inside a coroutine on the correct loop.
        """
        if self._lifecycle_lock is None:
            self._lifecycle_lock = asyncio.Lock()
        return self._lifecycle_lock

    def _lifecycle_source_tag(self, suffix: str) -> str:
        """Compose the ``metadata.source`` value for a defensively-
        emitted lifecycle event.

        Plugin subclasses override :attr:`_observation_source` with a
        framework-identifying prefix (e.g. ``"langgraph.workload"``,
        ``"openclaw.workload"``). The defensive emit reuses that
        prefix so the canonical event-attribution rule (every event's
        ``metadata.source`` starts with the framework tag) keeps
        holding — the SDK lifecycle emit is functionally a framework
        signal and the source MUST identify the framework, not the
        SDK plumbing. The trailing ``.suffix`` (e.g. ``run_handle_close``)
        narrows the provenance so dashboard filters can distinguish
        framework-callback emits from SDK-fallback emits when both are
        present in the audit trail.
        """
        prefix = (self._observation_source or "watchlight-core").split(
            ".", 1
        )[0]
        return f"{prefix}.{suffix}"

    def _build_execution_completed_event(
        self,
        outcome: str = "completed",
    ) -> Dict[str, Any]:
        """Construct the canonical ``execution_completed`` envelope for
        this handle.

        The shape mirrors the canonical ``ExecutionEvent``'s flat
        envelope + nested ``payload`` (kept in lockstep with the Rust
        and TypeScript lanes). The
        ``payload.actions_taken`` / ``payload.actions_denied`` fields
        reflect the plugin's running counters at close time.
        """
        tenant_id = getattr(self._plugin, "tenant_id", None)
        timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        actions_allowed = int(getattr(self._plugin, "last_actions_allowed", 0) or 0)
        actions_denied = int(getattr(self._plugin, "last_actions_denied", 0) or 0)
        event: Dict[str, Any] = {
            "event_id": f"evt_{uuid.uuid4()}",
            "event_type": "execution_completed",
            "timestamp": timestamp,
            "execution_id": self.execution_id,
            "agent_id": self.agent_uuid,
            "session_id": self.session_id,
            "metadata": {
                "source": self._lifecycle_source_tag(
                    "run_handle_close"
                ),
                "kind": "sdk_lifecycle_emit",
            },
            "payload": {
                "duration_ms": 0,
                "actions_taken": actions_allowed + actions_denied,
                "actions_denied": actions_denied,
                "outcome": outcome,
            },
        }
        if tenant_id is not None:
            event["tenant_id"] = tenant_id
        if self.parent_execution_id is not None:
            event["parent_execution_id"] = self.parent_execution_id
        if self.root_execution_id is not None:
            event["root_execution_id"] = self.root_execution_id
        return event

    def _build_execution_failed_event(
        self,
        reason: str,
    ) -> Dict[str, Any]:
        """Construct the canonical ``execution_failed`` envelope for
        this handle.

        The shape mirrors the canonical ``ExecutionFailedPayload`` (kept
        in lockstep with the Rust and TypeScript lanes).
        ``payload.error`` (the REQUIRED field) carries the operator-visible
        reason the customer's framework provided (typed as
        ``run_failed: <ExceptionType>`` for the ``__aexit__`` lane,
        free-form for explicit :meth:`terminate` calls).
        """
        tenant_id = getattr(self._plugin, "tenant_id", None)
        timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        # Truncate the reason at a defensive bound so a stack trace
        # leaking into the reason can't blow up the audit envelope.
        bounded_reason = (reason or "manual")[:512]
        event: Dict[str, Any] = {
            "event_id": f"evt_{uuid.uuid4()}",
            "event_type": "execution_failed",
            "timestamp": timestamp,
            "execution_id": self.execution_id,
            "agent_id": self.agent_uuid,
            "session_id": self.session_id,
            "metadata": {
                "source": self._lifecycle_source_tag(
                    "run_handle_terminate"
                ),
                "kind": "sdk_lifecycle_emit",
            },
            # Match the canonical ``ExecutionFailedPayload`` across all
            # lanes: the required field
            # is `error` (NOT `error_message`), and `actions_taken`/
            # `actions_denied` are NOT part of the failed payload (they live
            # on `ExecutionCompletedPayload`). Emitting the wrong shape made
            # every execution_failed event fail `/v1/events` deserialize
            # (422 — missing required `error`), silently dropping the run's
            # terminal lineage record on any failing/terminating run.
            "payload": {
                "error": bounded_reason,
                "duration_ms": 0,
            },
        }
        if tenant_id is not None:
            event["tenant_id"] = tenant_id
        if self.parent_execution_id is not None:
            event["parent_execution_id"] = self.parent_execution_id
        if self.root_execution_id is not None:
            event["root_execution_id"] = self.root_execution_id
        return event

    async def _publish_on_decision_path(self, event: Dict[str, Any]) -> bool:
        """Publish ``event`` from the governance decision path.

        Never waits: the client gives it one attempt when the run's lane
        is free, and otherwise (lane busy with a retry, or a transient
        answer) queues it for background delivery with the full retry
        budget, so neither the raise nor the kill signal is delayed. A
        queued event can land after a batch that was being retried when
        it was emitted. Backends without lanes make their single call.
        """
        with lineage_decision_path():
            ok = await self._plugin.apdp.publish_events(self.run, [event])
        return bool(ok)

    async def _drain_client_lineage(self) -> None:
        """At the end of the run, wait (bounded by one retry budget) for
        the run's queued lineage, so a short-lived process does not exit
        with it still queued. Backends without lanes have nothing to
        drain."""
        drain = getattr(self._plugin.apdp, "drain", None)
        if drain is None or self.run is None:
            return
        try:
            await drain(self.run)
        except Exception:  # noqa: BLE001 — observability is best-effort
            logger.debug("lineage drain at run end failed", exc_info=True)

    async def _emit_lifecycle_event(
        self,
        event: Dict[str, Any],
        *,
        decision_path: bool = False,
    ) -> None:
        """Publish a lifecycle envelope via APDP, treating any
        transport failure as a warning that MUST NOT block close.

        Per the lifecycle-emit edge-case enumeration: NATS / APDP unavailability
        during a lifecycle emit logs a warning and continues — the
        customer's framework finishes its cleanup, the operator sees
        the gap in the audit trail, and the existing
        wl-execution-graph "stuck-state row" alerting surfaces it.
        """
        event_type = event.get("event_type", "<unknown>")
        detail = ""
        try:
            # ``publish_events`` reports failure by RETURNING False, not
            # by raising — a bare try/except here would be dead code and
            # the warning below would never fire. Check the return.
            if decision_path:
                ok = await self._publish_on_decision_path(event)
            else:
                ok = await self._plugin.apdp.publish_events(self.run, [event])
        except Exception as e:  # noqa: BLE001 — observability is best-effort
            ok = False
            # Error class only: the client error text can carry the URL.
            detail = f": {type(e).__name__}"
        if not ok:
            logger.warning(
                "lifecycle emit failed (event_type=%s, "
                "execution_id=%s)%s; audit trail will show the row "
                "stuck at 'started'.",
                event_type,
                event.get("execution_id"),
                detail,
            )

    async def complete(self) -> None:
        """Close the APDP session cleanly. Idempotent.

        **Quarantine**: when the handle is in QUARANTINED state, completion
        is still semantically meaningful — the customer's framework
        wants to release session resources — but the outcome is
        recorded as ``quarantined`` rather than ``ok``. An
        ``execution_completed`` event is emitted (best-effort)
        carrying the quarantine payload in metadata so the audit
        replay shows the terminal state. The APDP
        ``/sessions/:id/complete`` call still goes through so the
        session is closed server-side.

        **Lifecycle**: emits ``execution_completed`` for the run's
        :attr:`execution_id` after the APDP round-trip succeeds,
        unless a framework translator has already emitted the event
        (signalled via :meth:`mark_execution_completed_emitted`). This
        closes the lifecycle hole that left ``lineage.executions``
        rows stuck at ``status='started'`` when a framework's emission
        path didn't fire (Bedrock, MSAF, Pydantic-AI today). Emission
        failures log a warning and don't block close — the customer's
        framework MUST be able to release its resources even when
        observability is degraded.
        """
        self._unbind_subagent_contextvar()
        await self._complete_impl()
        await self._drain_client_lineage()

    async def _complete_impl(self) -> None:
        async with self._get_lifecycle_lock():
            if self._completed:
                return

            was_quarantined = self._state == RunHandleState.QUARANTINED
            # Retries a transient answer (503 / 429 / transport) within
            # the client's bounded budget and returns only once the
            # server accepted the close or the budget ran out, so the
            # handle is not marked completed before that.
            ok = await self._plugin.apdp.complete_session(self.run)
            self._completed = True
            # Don't overwrite QUARANTINED — it's the terminal-state
            # signal in the audit trail. Only flip to COMPLETED when the
            # handle is finishing cleanly.
            if not was_quarantined:
                self._state = RunHandleState.COMPLETED

            if was_quarantined:
                # The quarantine path owns the terminal
                # ``execution_completed`` shape (carries the policy_id
                # / contributing_features attribution). Stamp the
                # lifecycle tracker so the defensive emit below does not
                # duplicate.
                await self._emit_quarantined_completion_event()
                self._execution_lifecycle_emitted.add("execution_completed")
            else:
                # Defensive lifecycle emit. Suppressed when a
                # framework translator already emitted (via
                # ``mark_execution_completed_emitted``) OR when
                # ``terminate`` already emitted ``execution_failed``
                # for this handle (terminate-then-complete edge case).
                if (
                    "execution_completed"
                    not in self._execution_lifecycle_emitted
                    and "execution_failed"
                    not in self._execution_lifecycle_emitted
                ):
                    self._execution_lifecycle_emitted.add(
                        "execution_completed"
                    )
                    event = self._build_execution_completed_event()
                    await self._emit_lifecycle_event(event)

            if self._plugin.log_decisions:
                outcome = (
                    "quarantined-complete"
                    if was_quarantined
                    else ("completed" if ok else "complete-failed")
                )
                logger.info("[SESSION] %s -> %s", self.session_id, outcome)

    async def terminate(self, reason: str = "manual") -> None:
        """End the run abnormally. Idempotent.

        ``reason`` is a free-form descriptive string (e.g.
        ``"run_failed: TimeoutError"``) that rides on the
        ``execution_failed`` lineage event. It is **not** a server-side
        ``TerminationReason``; the SDK does not transition session state
        server-side, because terminating a session is an operator-plane
        verb (``POST /v1/admin/sessions/{id}/terminate``, Operator role)
        and is deliberately unreachable with agent credentials. The
        session's own ``expires_at`` bounds it regardless.

        **Quarantine**: when the handle is already QUARANTINED, terminate
        becomes a no-op (the handle is already terminal; the
        quarantine state is the audit-trail signal). The
        ``self._completed`` flag is set so subsequent calls don't
        round-trip to APDP.

        **Lifecycle**: emits ``execution_failed`` for the run's
        :attr:`execution_id` — the authoritative record of the abnormal
        end — unless a framework translator has already emitted the
        event (signalled via :meth:`mark_execution_failed_emitted`). When
        both :meth:`complete` and :meth:`terminate` are called (in
        either order), the first call wins for the lifecycle event
        the second call short-circuits at the ``self._completed``
        guard.
        """
        self._unbind_subagent_contextvar()
        await self._terminate_impl(reason)
        await self._drain_client_lineage()

    def _unbind_subagent_contextvar(self) -> None:
        """Remove THIS handle from ``_current_subagent_handle`` when it is
        the current binding (token reset; plain clear when the token
        belongs to another context). A newer binding is left alone."""
        token = self._subagent_cv_token
        self._subagent_cv_token = None
        try:
            if _current_subagent_handle.get() is not self:
                return
            if token is not None:
                try:
                    _current_subagent_handle.reset(token)
                except (ValueError, RuntimeError):
                    pass
            if _current_subagent_handle.get() is self:
                _current_subagent_handle.set(None)
        except Exception:  # noqa: BLE001 — the accessor still hides a closed child
            logger.warning(
                "sub-agent context binding could not be cleared for session %s",
                self.session_id,
            )

    async def _terminate_impl(self, reason: str) -> None:
        async with self._get_lifecycle_lock():
            if self._completed:
                return

            if self._state == RunHandleState.QUARANTINED:
                # No-op for terminate-after-quarantine. The
                # ``execution_quarantined`` event already captured the
                # terminal state; there is no additional audit value to
                # emit a separate terminate event. Mark completed so
                # subsequent calls remain idempotent.
                self._completed = True
                if self._plugin.log_decisions:
                    logger.info(
                        "[SESSION] %s -> terminate-noop (already quarantined)",
                        self.session_id,
                    )
                return

            # Client-side release only. On the HTTP lane this is a
            # deprecated no-op (see ``ApdpClient.terminate_session``):
            # ending a session is an operator-plane verb, not something
            # the governed agent may do to itself. On the in-process
            # lane it drops the local session entry. Either way the
            # authoritative record of the abnormal end is the
            # ``execution_failed`` lineage event emitted below — which,
            # unlike the old server round-trip, actually works.
            await self._plugin.apdp.terminate_session(self.run, reason)
            self._completed = True
            self._state = RunHandleState.COMPLETED

            # Defensive lifecycle emit. Suppressed when a
            # framework translator already emitted (via
            # ``mark_execution_failed_emitted``) OR when ``complete``
            # already emitted ``execution_completed`` for this handle
            # (complete-then-terminate edge case, where ``terminate``
            # would already have been guarded by ``self._completed``
            # above — the explicit check below is defence-in-depth).
            if (
                "execution_failed" not in self._execution_lifecycle_emitted
                and "execution_completed"
                not in self._execution_lifecycle_emitted
            ):
                self._execution_lifecycle_emitted.add("execution_failed")
                event = self._build_execution_failed_event(reason)
                await self._emit_lifecycle_event(event)

            if self._plugin.log_decisions:
                logger.info(
                    "[SESSION] %s -> terminated (%s)",
                    self.session_id,
                    reason,
                )

    async def _emit_quarantined_completion_event(self) -> None:
        """Publish an ``execution_completed`` event carrying the
        terminal quarantine outcome.

        Mirrors the canonical ``ExecutionCompletedPayload`` shape;
        the quarantine attribution is surfaced via
        ``payload.outcome = "quarantined"`` plus the same
        ``contributing_features`` / ``policy_id`` block the
        ``execution_quarantined`` event carried. The dashboard
        renders the completion as a quarantined session without a
        follow-up query.
        """
        decision = self._quarantine_decision
        tenant_id = getattr(self._plugin, "tenant_id", None)
        timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        event: Dict[str, Any] = {
            "event_id": f"evt_{uuid.uuid4()}",
            "event_type": "execution_completed",
            # Required on the wire — without it the event was rejected at
            # ingest (422) and the quarantined run never closed in lineage.
            "timestamp": timestamp,
            # Reuse the handle's stable execution_id so the
            # quarantined-complete event lands on the SAME
            # ``lineage.executions`` row the ``execution_started`` /
            # ``execution_quarantined`` events wrote. Earlier this
            # minted a fresh ``exec_<uuid>`` and ``wl-execution-graph``
            # rendered a phantom orphan row.
            "execution_id": self.execution_id,
            "agent_id": self.agent_uuid,
            "session_id": self.session_id,
            "tenant_id": tenant_id,
            "metadata": {
                "source": _QUARANTINE_PROVENANCE_TAG,
                "kind": "quarantined_complete",
                "quarantine": (
                    {
                        "policy_id": decision.policy_id,
                        "anomaly_score": decision.anomaly_score,
                        "model_version": decision.model_version,
                        "contributing_features": [
                            fc.model_dump()
                            for fc in decision.contributing_features
                        ],
                        "reason": decision.reason,
                    }
                    if decision is not None
                    else None
                ),
            },
            "payload": {
                "duration_ms": 0,
                "actions_taken": self._plugin.last_actions_allowed,
                "actions_denied": self._plugin.last_actions_denied,
                "outcome": "quarantined",
            },
        }
        # Populate lineage stitching fields when present so
        # the dashboard can render the quarantined-completion in the
        # spawn tree alongside its parents.
        if self.parent_execution_id is not None:
            event["parent_execution_id"] = self.parent_execution_id
        if self.root_execution_id is not None:
            event["root_execution_id"] = self.root_execution_id
        try:
            await self._plugin.apdp.publish_events(self.run, [event])
        except Exception:  # noqa: BLE001 — observability is best-effort
            logger.debug(
                "quarantined-completion event emission failed", exc_info=True
            )

    async def _perform_spawn_apdp_roundtrip(
        self,
        child_agent_id: Optional[Union[str, UUID]] = None,
        *,
        child_label: Optional[str] = None,
        child_intent: Union[ChildIntent, Dict[str, Any]],
        allowed_tools: Optional[List[str]] = None,
        allowed_resources: Optional[
            List[Union[ResourceMatcher, str]]
        ] = None,
        allowed_intents: Optional[List[str]] = None,
        max_depth: Optional[int] = None,
        time_budget_seconds: Optional[int] = None,
    ) -> Any:
        """Run the canonical ``POST /v1/spawn_subagent`` round-trip.

        Shared helper called by :meth:`spawn_subagent` AND by every
        framework plugin's ``spawn_subagent`` override that needs to
        layer plugin-specific tree-stamping on top of the canonical
        attenuation roundtrip. Keeping the APDP wire shape + the
        QUARANTINE short-circuit + the fail-closed defaults in ONE
        place means a plugin override cannot accidentally widen scope
        — the canonical envelope is built here from explicit
        kwargs, never from a plugin-side dict.

        Extracted from the in-line body of
        :meth:`spawn_subagent` so the LangGraph + Pydantic AI plugin
        overrides reuse the exact same authorization round-trip the
        base method uses, instead of falling back to the older
        ``plugin.start_run(child_slug)`` path that opened a fresh
        session without server-side strict-subset validation.

        Returns the typed :class:`SpawnSubagentResponse`. Raises the
        same typed errors documented on :meth:`spawn_subagent`.

        Fail closed: the sub-agent context variable is cleared before the
        attempt, so a refused spawn never leaves an earlier child visible
        to the next one; a response without a child run
        reference (``child_run``) raises :class:`GovernanceUnavailable`.

        ``child_label`` names a child that is not a registered agent; see
        :meth:`spawn_subagent`. The response's ``child_agent_id`` is the
        agent the child runs as, checked against what was asked for.
        """
        # Shape checks first: a malformed identity sends nothing.
        child_uuid = _spawn_child_uuid(child_agent_id, child_label)
        # The binding before the spawn is the spawner itself when it is a
        # sub-agent (``None`` for a root), never an earlier sibling: the
        # grandchild's token then restores the spawner when it closes.
        spawner_binding = self if self._parent_handle_ref is not None else None
        try:
            _current_subagent_handle.set(spawner_binding)
        except Exception as exc:  # noqa: BLE001 — fail closed
            from .errors import GovernanceUnavailable

            raise GovernanceUnavailable(
                "spawn_subagent: the sub-agent handle binding could not be "
                f"cleared ({type(exc).__name__}); refusing the spawn."
            ) from exc
        # Short-circuit when the parent is quarantined.
        # MUST come before the APDP round-trip so a bagged agent
        # cannot probe the spawn endpoint for telemetry.
        if self._state == RunHandleState.QUARANTINED:
            assert self._quarantine_decision is not None
            self._fire_kill_signal()
            raise AgentQuarantinedError.from_decision(
                self._quarantine_decision
            )

        # SeverSubtree — short-circuit when this handle is severed. A
        # severed node MUST NOT spawn new descendants (that would grow a
        # subtree we just collapsed). MUST come before the APDP round-
        # trip. Fail-closed and terminal (multi-agent containment).
        if self._state == RunHandleState.SEVERED:
            assert self._sever_decision is not None
            self._fire_kill_signal(
                reason=LLM_CALL_INTERRUPTED_REASON_SEVER_SUBTREE
            )
            raise SubtreeSeveredError.from_decision(self._sever_decision)

        # A run ended by Terminate / Revoke has no authority to delegate.
        self._raise_if_run_ended()

        # Every spawn declares the child's own intent and
        # goal, derived from this run's. Refused locally (before any network
        # call) when absent or malformed; wl-apdp validates the derivation.
        declared_child_intent = coerce_child_intent(child_intent)

        # Fail-closed defaults. ``None`` kwargs
        # marshal as empty lists on the wire so a parent that forgets
        # to declare scope gets a zero-privilege child, not an
        # inherit-all child.
        requested = RequestedScope(
            allowed_tools=list(allowed_tools or []),
            allowed_resources=_coerce_allowed_resources(allowed_resources),
            allowed_intents=list(allowed_intents or []),
            max_depth=int(max_depth or 0),
            # As given: ``None`` stays off the wire and the backend resolves
            # it to the parent's remaining time; a value is never coerced
            # (the backend refuses one that is not an integer in range).
            time_budget_seconds=time_budget_seconds,
        )

        from .scope import SpawnSubagentRequest

        try:
            parent_uuid = UUID(str(self.agent_uuid))
        except (ValueError, TypeError) as exc:
            raise ValueError(
                f"spawn_subagent: this handle's agent_uuid is not a "
                f"valid UUID ({self.agent_uuid!r}); the canonical "
                f"identity model requires UUIDs for the spawn envelope"
            ) from exc

        try:
            parent_handle_uuid = UUID(self.run_handle_id)
        except (ValueError, TypeError):
            parent_handle_uuid = uuid.uuid4()

        # Execution-lineage integrity. The request no
        # longer carries any child/parent/root execution id — wl-apdp
        # SERVER-derives the child's tree position from the PARENT's
        # VERIFIED `sst_` credential + a server-minted child id. The child
        # execution id + child credential + tree root come back on the
        # response and the child handle adopts them.
        request = SpawnSubagentRequest(
            parent_agent_id=parent_uuid,
            child_agent_id=child_uuid,
            parent_run_handle_id=parent_handle_uuid,
            requested_scope=requested,
            child_label=child_label,
            child_intent=declared_child_intent,
        )
        body = spawn_subagent_request_to_dict(request)

        # The backend presents the PARENT run's own credential to
        # authenticate the spawn — the shared tenant bearer is refused on
        # this path. The server binds the child's lineage to this verified
        # parent run.
        try:
            response_dict = await self._plugin.apdp.spawn_subagent(self.run, body)
        except WatchlightError:
            raise
        except Exception as exc:  # noqa: BLE001 — the child never runs
            from .errors import GovernanceUnavailable

            logger.error(
                "governance backend spawn_subagent raised %s; refusing the spawn",
                type(exc).__name__,
            )
            raise GovernanceUnavailable(
                f"spawn_subagent: the governance backend failed ({type(exc).__name__}); "
                "refusing to run the sub-agent."
            ) from exc

        from .scope import spawn_subagent_response_from_dict

        child_run_issued = (
            response_dict.get("child_run") if isinstance(response_dict, dict) else None
        )
        try:
            response = spawn_subagent_response_from_dict(response_dict)
        except Exception as exc:  # noqa: BLE001 — surface wire-shape
            await self._discard_refused_child_run(child_run_issued)
            # mismatches as a typed error so plugin authors see a clean
            # diagnostic. Fail-closed by contract.
            # Fixed message plus the failing field names only: the parser's
            # own text can echo response values (tokens, ids).
            raise WatchlightError(
                "spawn_subagent: APDP response did not match the canonical "
                "SpawnSubagentResponse shape"
                + _failing_fields_suffix(exc)
            ) from exc

        # The backend issues the child its own run reference (holding the
        # child's own credential, when it mints one); without it the child's
        # calls and lineage could not be attributed to the child run.
        # Refuse rather than run the child unattributed.
        if not response.child_run:
            from .errors import GovernanceUnavailable

            raise GovernanceUnavailable(
                "spawn_subagent: the governance backend approved the spawn but "
                "issued no child run; refusing to run the sub-agent without "
                "attributable lineage."
            )
        # The child must be its own run: a backend handing back the
        # parent's run would let the child act (and emit lineage) as its
        # parent.
        if self.run is not None and response.child_run == self.run:
            from .errors import GovernanceUnavailable

            raise GovernanceUnavailable(
                "spawn_subagent: the governance backend issued the parent's own "
                "run for the child; refusing to run the sub-agent."
            )

        # Who the child runs as must be what was asked for. A labelled child
        # is identified by the server (its mapped agent, else its parent's);
        # a registered child is the agent requested. The label comes back
        # unchanged. Anything else refuses the spawn, and the child run the
        # backend registered is released.
        problem = _child_identity_problem(
            response,
            requested_agent=str(child_uuid) if child_uuid is not None else None,
            requested_label=child_label,
            parent_agent=str(parent_uuid),
        )
        if problem is not None:
            await self._discard_refused_child_run(response.child_run)
            from .errors import GovernanceUnavailable

            raise GovernanceUnavailable(
                f"spawn_subagent: {problem}; refusing to run the sub-agent."
            )
        if response.child_agent_id is None and child_uuid is not None:
            # An older server names no child agent: the requested one ran.
            response.child_agent_id = str(child_uuid)
        return response

    async def _discard_refused_child_run(self, child_run: Any) -> None:
        """Release a child run the backend registered for a spawn the SDK
        then refused (best effort, never raises; never the parent's run)."""
        if not isinstance(child_run, str) or not child_run or child_run == self.run:
            return
        try:
            await self._plugin.apdp.terminate_session(RunRef(child_run), "spawn_refused")
        except Exception:  # noqa: BLE001 — the refusal is what the caller sees
            logger.debug("releasing a refused child run failed", exc_info=True)

    async def spawn_subagent(
        self,
        child_agent_id: Optional[Union[str, UUID]] = None,
        *,
        child_label: Optional[str] = None,
        child_intent: Union[ChildIntent, Dict[str, Any]],
        allowed_tools: Optional[List[str]] = None,
        allowed_resources: Optional[
            List[Union[ResourceMatcher, str]]
        ] = None,
        allowed_intents: Optional[List[str]] = None,
        max_depth: Optional[int] = None,
        time_budget_seconds: Optional[int] = None,
    ) -> "BaseRunHandle":
        """Spawn a governed sub-agent under this handle with an
        explicit, per-spawn attenuated scope.

        Calls ``POST /v1/spawn_subagent`` with the canonical
        envelope. On 200 OK, mints a new sub-agent
        :class:`BaseRunHandle` whose ``granted_scope`` carries the
        server-attested scope and whose ``run_handle_id`` carries the
        ``child_run_handle_id`` APDP returned.

        The default way to name the child is its label: the plugin passes
        the framework's own name for it, and the child needs no registered
        agent::

            child = await handle.spawn_subagent(
                child_label="research-agent", allowed_tools=["search"]
            )

        Parameters
        ----------
        child_agent_id:
            Optional. The canonical UUID of a registered agent the child
            runs as (either the :class:`uuid.UUID` or its string form).
            Leave it out to spawn a child that is not a registered agent.

        child_label:
            The child's type or label: a deepagents or Claude
            ``subagent_type``, an ADK ``agent.name``, a Strands node id.
            1 to 128 bytes, starting with a letter or digit, using only
            letters, digits, space and ``. _ : / @ -``; checked before
            anything is sent (:class:`ValueError`). Without
            ``child_agent_id`` the child is identified by this run and the
            label: it runs as the agent an operator mapped the label to for
            the tenant, else as this run's own agent. Either way it is
            attenuated to a strict subset of this run's scope. The label is
            recorded in lineage and reaches policy as
            ``context.subagent_label``; it never grants anything. At least
            one of ``child_agent_id`` and ``child_label`` is required.

        child_intent:
            REQUIRED. The child's own intent and goal
            (:class:`~watchlight_core.scope.ChildIntent`, or its dict form):
            the intent ``category`` the child acts under, the ``objective``
            the parent gives it, and optionally an action budget
            (``max_actions``). wl-apdp refuses the spawn unless the category
            lies within this run's intent bounds and a named budget fits in
            this run's remaining budget; the child is then granted exactly
            that category. A missing or malformed value raises
            :class:`ValueError` before any network call.

        allowed_tools:
            Cedar action UIDs / tool slugs the child may invoke. Empty
            list (or ``None``) = the child may invoke **no tools** —
            the fail-closed default.

        allowed_resources:
            List of :class:`ResourceMatcher` (or bare strings, which
            the SDK coerces to ``ResourceMatcher(matcher=...)`` for
            backwards-compat with the early preview) the child
            may access. Empty list = no resources.

        allowed_intents:
            Intent objectives the child may declare. v1 uses exact
            string match. Empty list = no intents.

        max_depth:
            Maximum further spawn depth. ``None`` is sent to APDP as
            ``null`` and the server resolves it from the tenant
            default. ``0`` means the child cannot
            spawn descendants.

        time_budget_seconds:
            Per-spawn time budget in seconds. ``None`` (the default)
            inherits the parent's remaining time, bounded by the
            parent's deadline and the tenant threshold; it never
            widens. A named budget is granted exactly or refused, never
            clamped: ``0`` is refused as unsatisfiable, and a budget above
            what the parent can give (its granted budget, its remaining
            time, or the tenant threshold) is refused as a ``TimeBudget``
            scope violation, so the child never runs.

        Returns
        -------
        BaseRunHandle
            A new sub-agent handle with ``granted_scope`` set and
            ``run_handle_id`` populated from the server. The handle is
            tied to this parent via the existing parent-chain
            propagation so a quarantine on the child bubbles UP. The
            handle is also bound as the active sub-agent in the
            current asyncio task's :class:`contextvars.ContextVar`
            (``_current_subagent_handle``) so plugin interceptors can
            attribute tool calls to the sub-agent's
            ``run_handle_id`` without the customer's code wiring it
            manually.

        Raises
        ------
        AgentQuarantinedError
            When this parent handle is in ``QUARANTINED`` state — a
            quarantined agent has no authority to delegate.
        ScopeAttenuationDenied
            When APDP's strict-subset validator rejected the
            requested scope. Carries the typed dimension list.
        RunHandleInvalidated
            When APDP rejected because the parent's RunHandle is no
            longer valid (a validity race or kill-signal cascade).
        WatchlightError
            On transport errors or any non-canonical APDP response.

        Notes
        -----
        Backward-compat with the earlier stub signature
        (``spawn_subagent(agent_uuid, session_id)``) is deliberately
        broken — the new contract is the canonical primitive. Plugins
        that overrode the earlier signature (LangGraph, Pydantic AI)
        are unaffected because they override the method outright.
        Tests and conformance harnesses that called the stub directly
        must migrate to the kwargs form.

        See the Watchlight documentation on sub-agent scope
        attenuation: per-spawn explicit scope and fail-closed default.
        """
        # Shape checks ONCE up here (the roundtrip helper repeats them).
        child_uuid = _spawn_child_uuid(child_agent_id, child_label)

        # Delegate the canonical envelope build + APDP round-trip to
        # the shared helper so plugin overrides (LangGraph /
        # Pydantic AI) reuse the exact same code path.
        response = await self._perform_spawn_apdp_roundtrip(
            child_uuid,
            child_label=child_label,
            child_intent=child_intent,
            allowed_tools=allowed_tools,
            allowed_resources=allowed_resources,
            allowed_intents=allowed_intents,
            max_depth=max_depth,
            time_budget_seconds=time_budget_seconds,
        )

        # Mint the child handle. ``session_id`` is the SERVER-derived child
        # session id returned in the spawn response (``ses_<child-run-handle>``)
        # — the child adopts it verbatim so it matches the ``sid`` claim in the
        # per-child run credential and its ``/v1/events`` emissions bind (see
        # ``child_session_id`` below). Authorize-time scope-membership checks
        # still key off ``run_handle_id``.
        #
        # ``type(self)`` is used (instead of a literal ``BaseRunHandle``)
        # so plugins whose ``RunHandle`` subclass overrides class-level
        # attributes (e.g. ``_observation_source``) propagate those
        # overrides onto sub-agent handles automatically. Without this,
        # a sub-agent spawned via the base ``spawn_subagent`` would
        # carry the framework-default observation source instead of the
        # plugin's override, which would mis-attribute the child's
        # canonical events on the dashboard lineage view.
        child_handle_id = response.child_run_handle_id
        # Execution-lineage integrity. Adopt the
        # SERVER-derived child ``session_id`` (canonical
        # ``ses_<child-run-handle>``) so it EXACTLY matches the ``sid`` claim
        # inside the child run credential. The ingest binding gate compares
        # ``envelope.session_id`` to that ``sid``; if the child reconstructs a
        # differently-shaped id the gate 409s every child event (the v0.9.11
        # bug — the child used to stamp the bare ``child_handle_id``). Fall
        # back to ``ses_<handle>`` when talking to a pre-Phase-2 server that
        # omits the field, matching how the server now derives it.
        child_session_id = response.child_session_id or f"ses_{child_handle_id}"
        # The agent the child runs as, as the server named it (checked in
        # the roundtrip helper against what was asked for).
        child_agent = response.child_agent_id or (
            str(child_uuid) if child_uuid is not None else None
        )
        if not child_agent:
            from .errors import GovernanceUnavailable

            await self._discard_refused_child_run(response.child_run)
            raise GovernanceUnavailable(
                "spawn_subagent: the governance backend did not name the agent the "
                "child runs as; refusing to run the sub-agent."
            )
        child = type(self)(
            plugin=self._plugin,
            agent_uuid=child_agent,
            session_id=child_session_id,
            parent_handle=self,
            run_handle_id=child_handle_id,
            granted_scope=response.granted_scope,
            # Root-cause fix — thread the child's lineage tier so
            # the CONNECT sidecar emits with the sub-agent's
            # ``execution_id`` rather than the orchestrator's (the
            # sub-agent's own governed identity). The child gets a
            # fresh ``execution_id``; root + parent are inherited so the
            # spawn tree groups under one ``lineage.executions`` root.
            # Plugin subclasses that mint the child execution_id at
            # spawn-event time (LangGraph's ``spawn_subagent`` accepts
            # ``child_execution_id`` as a kwarg) re-bind the field
            # post-construction so the spawn-pair audit + the
            # CONNECT-sidecar lineage agree.
            # Execution-lineage integrity. Adopt the
            # SERVER-resolved child ``execution_id`` so the child's emitted
            # events carry the SAME id the child credential's ``eid`` claim
            # binds to — otherwise the ``/v1/events`` gate would reject the
            # child's own events as a mismatch. ``None`` (pre-Phase-2
            # server) falls back to an auto-minted client id. Plugin
            # subclasses that supply ``child_execution_id`` in the spawn
            # request get it echoed back here (server validated it), so the
            # post-construction re-bind is a no-op.
            execution_id=response.child_execution_id,
            root_execution_id=self.root_execution_id,
            parent_execution_id=self.execution_id,
            parent_agent_id=self.agent_uuid,
            # A sub-agent runs under the SAME goal as its parent; the whole
            # tree renders under one goal in lineage.
            goal_id=self._goal_id,
            # Execution-lineage integrity. The child's OWN run reference:
            # the backend presents the per-child credential wl-apdp minted
            # at spawn on the child's calls, so its events bind to the
            # child session and can never be attributed to the parent or
            # any other run. Emission is run-credential-only.
            run=RunRef(response.child_run),
            # The child session's OWN egress binding (``None`` when
            # the deployment issues no proxy tokens). Never the parent's.
            egress=egress_binding_for(self._plugin.apdp, RunRef(response.child_run)),
            # Propagate the escalation listener so sub-agent authorize
            # calls surface escalations through the same hook.
            on_escalation=self._on_escalation,
        )
        child._derived_intent = response.derived_intent
        # Sub-agent handles minted via
        # :meth:`spawn_subagent` are returned to the caller WITHOUT
        # an explicit ``async with`` block (the canonical sub-agent
        # flow returns the handle to the parent's code, which uses
        # it inline). The spawn round-trip IS the entry-point
        # semantically — the sub-agent's session is active from this
        # line onward — so flip the fail-closed flag here so the
        # first :meth:`authorize_action_detailed` /
        # :meth:`publish_observation` on the child doesn't raise
        # :class:`WatchlightContractError`.
        #
        # The child's own ``execution_started`` will be emitted by
        # the SDK on the first authorize / publish call (via
        # :meth:`_ensure_execution_started_emitted`) OR by the
        # plugin's ``agent_spawn_observed`` translator (the LangGraph
        # spawn path emits both). Plugins that emit both should call
        # :meth:`mark_execution_started_emitted` on the child to
        # suppress the SDK's defensive mint.
        child._aentered = True
        child.child_label = response.child_label
        child.child_identity = response.child_identity

        # Sub-agent governance — bind the
        # child as the active sub-agent handle in this asyncio task's
        # contextvars copy. Concurrent ``asyncio.gather`` tasks see
        # their own bindings because ``contextvars`` are copied on
        # task creation. The caller is responsible for clearing the
        # binding: ``child.complete()`` / ``terminate()`` reset it with
        # the token stored here (the handle outlives this method).
        try:
            child._subagent_cv_token = _current_subagent_handle.set(child)
        except Exception as exc:  # noqa: BLE001 — fail closed below
            # Without the binding the child's tool calls cannot be
            # attributed to its attenuated handle. Close the child's
            # session and refuse the spawn rather than run it unbound.
            child._aentered = False
            child._completed = True
            child._state = RunHandleState.COMPLETED
            await child._close_session_after_run_end()
            from .errors import GovernanceUnavailable

            raise GovernanceUnavailable(
                "spawn_subagent: the sub-agent handle could not be bound to "
                f"the current context ({type(exc).__name__}); refusing to run "
                "the sub-agent."
            ) from exc

        return child

    async def __aenter__(self) -> "BaseRunHandle":
        # Flip the fail-closed flag so
        # :meth:`authorize_action_detailed` and
        # :meth:`publish_observation` accept subsequent calls without
        # raising :class:`WatchlightContractError`. The flag is
        # per-handle (NOT a contextvar) so concurrent tasks in the
        # same context can all share one entered handle without
        # interference. It is set only once the lineage is bound.

        # Root-cause fix — bind the handle's lineage in two places:
        #
        # 1. The ``_current_handle_lineage`` contextvar — copied on
        #    asyncio task creation so sub-agent spawns naturally see
        #    their own snapshot in their task context. Used by future
        #    in-process emitters that read the contextvar directly.
        #
        # 2. The sidecar's process-global state (via
        #    :func:`connect_proxy.set_active_handle_lineage`) so the
        #    CONNECT sidecar's dedicated event-loop thread can read
        #    the lineage at outbound-CONNECT time. The sidecar runs in
        #    its own thread for ``HTTPS_PROXY`` interception of sync
        #    customer code, so the contextvar from this task does NOT
        #    propagate; the process-global is the wire.
        #
        # This is the load-bearing transparent integration point — the
        # customer never touches either mechanism. They use the
        # standard ``async with await plugin.start_run(...) as handle:``
        # pattern and outbound HTTPS in that scope automatically
        # carries the workflow's lineage.
        snapshot = self.lineage_snapshot()
        try:
            self._lineage_token = _current_handle_lineage.set(snapshot)
        except Exception as exc:  # noqa: BLE001 — fail closed
            # A run whose lineage cannot be bound must not start: its
            # events would be unattributable.
            self._lineage_token = None
            from .errors import GovernanceUnavailable

            raise GovernanceUnavailable(
                "RunHandle could not bind its lineage context "
                f"({type(exc).__name__}); refusing to start the run."
            ) from exc
        self._aentered = True
        # Also publish to the sidecar process-global so the CONNECT
        # sidecar's handler thread sees it. Imported lazily to avoid a
        # circular import between this module and ``connect_proxy``
        # (which conditionally imports ``HandleLineage``).
        try:
            from .connect_proxy import set_active_handle_lineage

            set_active_handle_lineage(snapshot)
        except Exception:  # noqa: BLE001 — introspection only, never on the wire
            logger.warning(
                "BaseRunHandle.__aenter__: sidecar lineage snapshot publish failed",
                exc_info=True,
            )

        # Defensive ``execution_started`` emission for
        # the handle's own ``execution_id`` so any subsequent
        # :meth:`authorize_action_detailed` /
        # :meth:`publish_observation` / :meth:`spawn_subagent` call
        # has a parent execution row to attach under. Frameworks
        # that emit their own ``execution_started`` via callback
        # streams (LangGraph's ``on_chain_start``) MAY call
        # :meth:`mark_execution_started_emitted` immediately after
        # ``__aenter__`` to suppress this defensive mint and avoid a
        # duplicate event on the wire.
        #
        # We swallow exceptions because observability MUST NEVER
        # break the customer's framework at session-open time; the
        # missing event is logged at debug and the run continues. If
        # the defensive emit failed here, the first authorize /
        # publish call will retry it via
        # :meth:`_ensure_execution_started_emitted` (and that path
        # IS fail-loud — the caller will see the transport failure).
        try:
            await self._ensure_execution_started_emitted(self.execution_id)
        except Exception:  # noqa: BLE001 — defensive emission is best-effort
            logger.debug(
                "BaseRunHandle.__aenter__: execution_started defensive "
                "emission raised; swallowing — will retry on first "
                "authorize/publish",
                exc_info=True,
            )

        return self

    @staticmethod
    def parse_root_run_handle_id(
        session_response: Dict[str, Any],
    ) -> Optional[str]:
        """Extract the server-minted ``root_run_handle_id`` from an APDP
        ``POST /sessions`` response.

        wl-apdp populates this top-level field when the deployment has a
        run-handle store configured — it mints a first-class run handle
        for the ROOT run so runtime Attenuate (and future run-handle
        governance) applies to the root, not only to spawned sub-agents.
        On older wl-apdp, or a deployment with no run-handle store, the
        field is absent and this returns ``None`` — the root then behaves
        exactly as before (client-minted id, never presented; Cedar
        governs).

        Used by plugin ``start_run`` implementations::

            session = await self.apdp.create_session(...)
            root_rh = BaseRunHandle.parse_root_run_handle_id(session)
            return MyRunHandle(
                plugin=self,
                agent_uuid=...,
                session_id=...,
                run_handle_id=root_rh,            # None → auto-mint client id
                server_run_handle=root_rh is not None,
            )

        Returns ``None`` on malformed or absent field rather than raising:
        a missing root handle must NOT break sessions on deployments
        without a run-handle store.
        """
        if not isinstance(session_response, dict):
            return None
        rh = session_response.get("root_run_handle_id")
        return rh if isinstance(rh, str) and rh else None

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> bool:
        # Flip the fail-closed flag back so any
        # post-exit :meth:`authorize_action_detailed` /
        # :meth:`publish_observation` call raises
        # :class:`WatchlightContractError`. Callers should NOT be
        # invoking authorize / publish after ``async with`` exits —
        # the session is closing — but a misbehaving framework that
        # does will get the typed error instead of an orphan event.
        self._aentered = False

        # Root-cause fix — reset both lineage bindings:
        #
        # 1. The contextvar binding the ``__aenter__`` set, so the
        #    caller's outer context is restored (typically ``None`` on
        #    the orchestrator, or the parent's lineage on a nested
        #    sub-agent ``async with``).
        # 2. The sidecar's process-global, cleared to ``None`` so a
        #    later out-of-band HTTP call doesn't accidentally carry
        #    this completed run's lineage on a future request. (Nested
        #    sub-agents re-publish in their own ``__aenter__``, so the
        #    process-global toggles parent ↔ child along the spawn
        #    spine; the architectural gap on truly-concurrent sub-agent
        #    fan-out is documented in the connect_proxy module
        #    docstring.)
        token = getattr(self, "_lineage_token", None)
        if token is not None:
            try:
                _current_handle_lineage.reset(token)
            except Exception:  # noqa: BLE001 — best-effort cleanup
                logger.debug(
                    "BaseRunHandle.__aexit__: lineage contextvar reset failed",
                    exc_info=True,
                )
            self._lineage_token = None
        try:
            from .connect_proxy import set_active_handle_lineage

            # Restore whatever the contextvar now points to (parent's
            # snapshot for nested, ``None`` for top-level).
            set_active_handle_lineage(_current_handle_lineage.get())
        except Exception:  # noqa: BLE001 — best-effort sidecar restore
            logger.debug(
                "BaseRunHandle.__aexit__: sidecar lineage restore failed",
                exc_info=True,
            )
        if exc_type is not None:
            await self.terminate(reason=f"run_failed: {exc_type.__name__}")
        else:
            await self.complete()
        # Returning False re-raises any exception that escaped the body.
        return False


def _spawn_child_uuid(
    child_agent_id: Optional[Union[str, UUID]], child_label: Optional[str]
) -> Optional[UUID]:
    """The requested child agent as a UUID (``None`` for a labelled child
    that names no agent), after checking that the child is named and that
    the label is well-formed. Raises :class:`ValueError`; nothing is sent."""
    if child_agent_id is None and child_label is None:
        raise ValueError(
            "spawn_subagent: name the child by child_label (its type or label) "
            "or by child_agent_id (a registered agent)"
        )
    if child_label is not None:
        from .root_identity import validate_child_label

        validate_child_label(child_label)
    if child_agent_id is None:
        return None
    try:
        return (
            child_agent_id
            if isinstance(child_agent_id, UUID)
            else UUID(str(child_agent_id))
        )
    except (ValueError, TypeError) as exc:
        raise ValueError(
            f"spawn_subagent: child_agent_id must be a UUID or its "
            f"string form; got {child_agent_id!r}"
        ) from exc


def _child_identity_problem(
    response: Any,
    *,
    requested_agent: Optional[str],
    requested_label: Optional[str],
    parent_agent: str,
) -> Optional[str]:
    """Why the server's account of who the child runs as disagrees with the
    request, or ``None`` when it agrees. Fail closed: a labelled child with
    no named agent, a label that came back changed, an unknown identity
    kind, a registered child running as another agent, or an anonymous
    child running as anyone but its parent."""
    from .root_identity import (
        CHILD_IDENTITIES,
        CHILD_IDENTITY_ANONYMOUS,
        CHILD_IDENTITY_MAPPED,
        CHILD_IDENTITY_REGISTERED,
    )

    served = response.child_agent_id
    identity = response.child_identity
    if served is not None:
        try:
            served = str(UUID(str(served)))
        except (ValueError, TypeError):
            return "the governance backend named a child agent that is not a UUID"
    if identity is not None and identity not in CHILD_IDENTITIES:
        return "the governance backend named an unknown child identity"
    if response.child_label is not None and response.child_label != requested_label:
        return "the governance backend returned another child label than the one sent"
    if requested_agent is not None:
        if served is not None and served != requested_agent:
            return "the governance backend ran the child as another agent than the one named"
        if identity not in (None, CHILD_IDENTITY_REGISTERED):
            return "the governance backend did not run the named agent as the child"
        return None
    # A labelled child that names no agent: the server says who it is.
    if served is None:
        return "the governance backend did not name the agent the labelled child runs as"
    if identity == CHILD_IDENTITY_ANONYMOUS and served != parent_agent:
        return "an anonymous child must run as its parent's agent"
    if identity not in (CHILD_IDENTITY_ANONYMOUS, CHILD_IDENTITY_MAPPED):
        return "the governance backend did not say how the labelled child is identified"
    return None
