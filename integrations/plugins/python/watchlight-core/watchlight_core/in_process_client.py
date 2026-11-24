"""In-process governance backend for the Watchlight Developer Edition.

``InProcessClient`` is a drop-in alternative to :class:`ApdpClient` that answers
the same method surface — but instead of round-tripping to a networked WL-APDP,
it drives the **compiled** ``watchlight-engine`` policy engine *in-process* and
writes execution lineage to a local JSONL file. No database, no network, no
services.

Both implement :class:`~watchlight_core.backend.GovernanceBackend` (re-exported
here under its old import path), so a plugin constructed with an ``InProcessClient``
behaves exactly like one talking to a networked APDP — the same
``authorize_action`` / ``preflight_step`` / lifecycle calls, the same decision
shapes — only the transport differs. This is the "same code, one env var away"
promise made real at the SDK layer.

Developer-Edition semantics (a deliberate subset of the governed platform):

* **Lineage** is appended to ``.watchlight/audit.jsonl`` locally — NOT signed,
  tamper-evident NATS lineage (that is the Enterprise control plane).
* **Agent resolution** is a local, deterministic identity map — there is no
  registry service. ``resolve_agent`` registers the agent's slug with the
  engine as its trusted ``name`` and ``slug``, so ``principal.name`` and
  ``principal.slug`` are what wl-apdp reads from a registry record (the DE's
  name for an agent is its slug).
* **Root identity.** There is no credential in-process, so "the agent the
  credential is bound to" is the process's configured identity: the
  ``agent=`` argument, else the ``WATCHLIGHT_AGENT`` environment variable (a
  slug, mapped to an id exactly like :meth:`InProcessClient.resolve_agent`).
  ``create_session()`` with no agent opens the root run as that agent and
  raises :class:`~watchlight_core.CredentialBindsNoAgent` when none is
  configured. A named agent that differs from a configured identity is
  refused, as wl-apdp refuses a name an agent-bound credential does not match.
  The configured identity and every ``subagent_agents`` slug are registered
  with the engine at construction, as ``resolve_agent`` registers a slug, so
  they decide with their trusted ``name`` and ``slug`` without a lookup.
* **Labelled sub-agents.** A spawn may name the child by ``child_label``
  alone. It runs as the agent ``subagent_agents`` maps the label to, else as
  its parent's agent, and is attenuated like every spawn. The label is
  written to the local ``attenuation`` record and set as
  ``context.subagent_label`` on the child's own decisions (a caller value
  for that key is removed).
* **Entity types are the caller's.** ``principal`` / ``action`` / ``resource``
  reach the engine EXACTLY as given. A typed reference (``User::"alice"``,
  ``Document::"d1"``) keeps its type and DISCRIMINATES — a policy naming a
  different type with the same id does not match. A bare name (``"read"``,
  ``"dataset"``) reaches the engine bare, where it gets one fixed type for its
  position (``User`` / ``Action`` / ``Resource``; engine 0.2.2 and older
  matched it against any type with that id). Name the type. (This client used
  to strip the type off every term, so nothing discriminated; see
  :mod:`watchlight_core._cedar_entities`.)
* **Engine version.** Construction refuses a ``watchlight-engine`` older than
  :data:`REQUIRED_ENGINE_VERSION` with :class:`EngineVersionUnsupported`.
* **Sub-agent scope attenuation** runs the real strict-subset validator
  in-process (:meth:`InProcessClient.spawn_subagent`) and writes an
  ``attenuation`` lineage record for the ``watchlight dev`` tree.
* **Plan validation** needs a compiled-engine method not yet exposed to the
  in-process binding, so :meth:`InProcessClient.submit_plan` raises
  ``NotImplementedError`` with a clear message rather than silently allowing;
  authorize each step with ``authorize_action`` in the meantime.

The engine itself is the *real* production authorization pipeline, so every
``Allow`` / ``Deny`` is a genuine, fail-closed decision.
"""

from __future__ import annotations

import json
import os
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
import secrets
from collections import OrderedDict
from typing import Any, Dict, List, Mapping, NoReturn, Optional, Set

from .backend import (
    EgressBinding,
    GovernanceBackend,
    KillCallback,
    KillNotice,
    KillSubscriptions,
    RunRef,
    SessionInfo,
    Unsubscribe,
    fire_kill_callback,
    public_session_record,
)
from .errors import (
    CredentialBindsNoAgent,
    EngineVersionUnsupported,
    GovernanceRefused,
    WatchlightContractError,
)
from .root_identity import (
    CHILD_IDENTITY_ANONYMOUS,
    CHILD_IDENTITY_MAPPED,
    CHILD_IDENTITY_REGISTERED,
    SUBAGENT_LABEL_CONTEXT_KEY,
    validate_child_label,
)

#: The environment variable naming the Developer Edition process's identity
#: (an agent slug) when ``InProcessClient(agent=...)`` is not given.
ENV_AGENT = "WATCHLIGHT_AGENT"

__all__ = ["InProcessClient", "GovernanceBackend", "REQUIRED_ENGINE_VERSION"]

#: Ended runs kept for their late lineage (oldest first out).
MAX_ENDED_RUNS = 1024

# Bound the capability names written to the local audit so a caller-supplied
# (denied) request can't bloat audit.jsonl. The engine caps the granted set; the
# denied path echoes the raw request, so cap it here.
_AUDIT_MAX_TOOLS = 64
_AUDIT_MAX_TOOL_NAME = 120


def _strip_nulls(value: Any) -> Any:
    """Recursively drop ``None`` values — Cedar forbids ``null`` in the context."""
    if isinstance(value, dict):
        return {k: _strip_nulls(v) for k, v in value.items() if v is not None}
    if isinstance(value, list):
        return [_strip_nulls(v) for v in value if v is not None]
    return value


def _session_agent_principal(agent_id: Optional[str]) -> Optional[str]:
    """The principal a session's agent is decided as: ``Agent::"<id>"``.

    ``create_session`` is given the agent's id (``resolve_agent``'s ``id``).
    A reference that already names its type is kept as given, as
    ``authorize`` keeps the caller's terms. ``None`` (decide nothing, deny)
    for a missing id or one that cannot be written inside a Cedar string.
    """
    if not isinstance(agent_id, str) or not agent_id:
        return None
    if "::" in agent_id:
        return agent_id
    if any(c in agent_id for c in '"\\') or any(ord(c) < 0x20 or ord(c) == 0x7F for c in agent_id):
        return None
    return f'Agent::"{agent_id}"'


# Namespace for deterministic agent UUIDs derived from a slug (uuid5).
_AGENT_NS = uuid.UUID("6f9619ff-8b86-d011-b42d-00c04fc964ff")


#: wl-apdp's default ``subagent_time_budget_threshold_seconds``: a root
#: agent's time budget for its sub-agents when nothing configures one. The
#: in-process root uses the same default, so a first-level sub-agent that
#: names no budget inherits at most this, as it would against wl-apdp.
DEFAULT_SUBAGENT_TIME_BUDGET_THRESHOLD_SECONDS = 3600

#: The largest budget the engine's ``u32`` field holds.
_MAX_BUDGET_SECONDS = 2**32 - 1


#: The lowest ``watchlight-engine`` this SDK runs against. 0.2.5 is the first
#: engine with ``set_principal_attributes``: it takes the agent's name from
#: the host, so a policy scoped by ``principal.name`` decides as it does on
#: wl-apdp; an older engine would leave a name-scoped ``forbid`` silently
#: inapplicable. 0.2.4 checks a sub-agent's every call against the scope its
#: spawn granted (``check_scope_membership``); 0.2.3 resolved a spawn
#: that names no time budget and carries the reserved-context-key and
#: unknown-enforcement-effect hardening.
REQUIRED_ENGINE_VERSION = "0.2.5"
#: The first engine release this SDK does not accept: a new minor may change
#: the engine contract, so it is refused until an SDK is released for it.
ENGINE_VERSION_BELOW = "0.3.0"

#: ASCII digits only, each part at most 6 digits, and a short tail: any
#: other string is not a version and is refused.
_ENGINE_VERSION_RE = re.compile(r"(\d{1,6})\.(\d{1,6})\.(\d{1,6})(?:([-+])\S{0,64})?", re.ASCII)


def _parse_engine_version(text: str) -> Optional[tuple]:
    """``"0.2.3"`` -> ``(0, 2, 3, 0)``; a pre-release (``"0.2.3-rc.1"``) sorts
    below its release (``(0, 2, 3, -1)``); a build tag (``+…``) does not.
    Anything else -> ``None``."""
    m = _ENGINE_VERSION_RE.fullmatch(text.strip())
    if m is None:
        return None
    pre = -1 if m.group(4) == "-" else 0
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)), pre)


def _require_engine_version(engine: Any) -> None:
    """Refuse an engine older than :data:`REQUIRED_ENGINE_VERSION`, or at or
    above :data:`ENGINE_VERSION_BELOW`.

    Fail closed: an engine that reports no version, or one that cannot be
    read, is refused too. Raises :class:`EngineVersionUnsupported`.
    """
    try:
        found = engine.version()
    except Exception:  # noqa: BLE001 — no readable version: refuse
        found = None
    if not isinstance(found, str):
        raise EngineVersionUnsupported(required=REQUIRED_ENGINE_VERSION, found="unknown")
    have = _parse_engine_version(found)
    need = _parse_engine_version(REQUIRED_ENGINE_VERSION)
    below = _parse_engine_version(ENGINE_VERSION_BELOW)
    assert need is not None and below is not None
    if have is None or have < need or have[:3] >= below[:3]:
        shown = found if have is not None else "unknown"
        raise EngineVersionUnsupported(required=REQUIRED_ENGINE_VERSION, found=shown)


class InProcessClient:
    """A :class:`GovernanceBackend` backed by the in-process ``watchlight-engine``.

    Parameters
    ----------
    policies:
        Optional Cedar policies to load. Either a list of ``{"name", "code"}``
        dicts, or a path to a JSON file containing such a list.
    audit_path:
        Where to append execution-lineage events (default ``.watchlight/audit.jsonl``).
        Set to ``None`` to disable local lineage.
    subagent_time_budget_threshold_seconds:
        The root's own time budget for its sub-agents, as wl-apdp caps a root
        agent with ``subagent_time_budget_threshold_seconds`` (default 3600,
        wl-apdp's default). A first-level sub-agent that names no budget
        inherits this, so every sub-agent's time is bounded. Must be a
        positive integer.
    agent:
        The process's identity, an agent slug: the Developer Edition
        equivalent of "the agent the credential is bound to".
        ``create_session()`` with no agent opens the root run as it. Defaults
        to the ``WATCHLIGHT_AGENT`` environment variable; with neither,
        a slug-less ``create_session`` raises
        :class:`~watchlight_core.CredentialBindsNoAgent`.
    subagent_agents:
        Optional ``{child_label: agent_slug}``: a sub-agent spawned with
        that label (and no ``child_agent_id``) runs as that agent instead of
        its parent's, still attenuated under its parent. The Developer
        Edition equivalent of a tenant's label mapping in wl-admin.

    Raises
    ------
    ImportError
        ``watchlight-engine`` is not installed.
    EngineVersionUnsupported
        The installed engine is older than :data:`REQUIRED_ENGINE_VERSION`
        (or reports no readable version). No client is built; nothing falls
        back to another backend.
    """

    #: This backend wants the caller's entity references untouched — see the
    #: "Entity types are the caller's" note in the module docstring. Declaring
    #: it is what stops the SDK wrapping a bare term into ``Resource::"…"`` on
    #: our behalf, which would deny every policy that names its own resource
    #: type.
    cedar_entities_verbatim = True

    def __init__(
        self,
        policies: Optional[Any] = None,
        *,
        audit_path: Optional[str] = ".watchlight/audit.jsonl",
        subagent_time_budget_threshold_seconds: int = DEFAULT_SUBAGENT_TIME_BUDGET_THRESHOLD_SECONDS,
        agent: Optional[str] = None,
        subagent_agents: Optional[Mapping[str, str]] = None,
    ) -> None:
        if agent is None:
            agent = os.environ.get(ENV_AGENT) or None
        if agent is not None and (not isinstance(agent, str) or not agent.strip()):
            raise ValueError("agent must be a non-empty agent slug")
        self._identity_agent_id: Optional[str] = (
            str(uuid.uuid5(_AGENT_NS, agent)) if agent is not None else None
        )
        # The slugs this process configures as agents (its identity and the
        # agents labels map to): registered with the engine below, as
        # resolve_agent registers a slug, so they decide with their trusted
        # name and slug even when nothing resolves them first.
        configured_slugs: List[str] = [agent] if agent is not None else []
        self._subagent_agents: Dict[str, str] = {}
        for label, slug in dict(subagent_agents or {}).items():
            validate_child_label(label)
            if not isinstance(slug, str) or not slug.strip():
                raise ValueError("subagent_agents maps a label to an empty agent slug")
            self._subagent_agents[label] = str(uuid.uuid5(_AGENT_NS, slug))
            configured_slugs.append(slug)
        threshold = subagent_time_budget_threshold_seconds
        if (
            isinstance(threshold, bool)
            or not isinstance(threshold, int)
            or not 0 < threshold <= _MAX_BUDGET_SECONDS
        ):
            raise ValueError(
                "subagent_time_budget_threshold_seconds must be a positive integer "
                f"no larger than {_MAX_BUDGET_SECONDS}"
            )
        self._root_time_budget_seconds = threshold
        try:
            import watchlight_engine  # noqa: PLC0415 — optional compiled dep
        except ImportError as exc:  # pragma: no cover — env-dependent
            raise ImportError(
                "InProcessClient requires the compiled engine. "
                "Install it with `pip install \"watchlight-engine>=0.2.5,<0.3\"`."
            ) from exc
        # An older engine is refused here, before it answers anything.
        _require_engine_version(watchlight_engine)

        self._engine = watchlight_engine.PolicyEngine()
        for policy in _load_policies(policies):
            self._engine.add_policy(json.dumps(policy))
        for slug in configured_slugs:
            self._trust_agent(slug)

        self._audit_path = Path(audit_path) if audit_path else None
        # session_id -> agent_id, so preflight (which carries no principal) can
        # authorize under the session's agent.
        self._sessions: Dict[str, str] = {}
        # RunRef -> session_id. The DE holds no credential: a run reference
        # names a local session only.
        self._runs: Dict[RunRef, str] = {}
        # Ended runs, kept (bounded, oldest first out) so their late lineage
        # is still written while every control call on them is refused.
        self._ended: "OrderedDict[RunRef, None]" = OrderedDict()
        self._kill_subs = KillSubscriptions()
        # run_handle_id -> the effective GrantedScope dict handed to that handle,
        # so a sub-agent's OWN spawns are strict-subset-validated against it,
        # and its calls are denied once its deadline has passed.
        # A sub-agent's scope is found ONLY through its run (``_run_handles``),
        # never by a handle id the caller names.
        self._scopes: Dict[str, Dict[str, Any]] = {}
        # Live RunRef -> its run_handle_id. ``create_session`` mints a root
        # run's handle (in ``_root_handles``: undeclared full authority); a
        # spawn mints a sub-agent's (its scope in ``_scopes``). A spawn is
        # validated against the parent run's own handle, never a handle id
        # the request names.
        self._run_handles: Dict[RunRef, str] = {}
        self._root_handles: Set[str] = set()
        # Live RunRef -> the agent it runs as (roots and sub-agents), so an
        # anonymous labelled child runs as its parent's agent.
        self._run_agents: Dict[RunRef, str] = {}
        # Live RunRef -> the sub-agent label it was spawned with. Set on the
        # child's decisions as ``context.subagent_label``.
        self._run_labels: Dict[RunRef, str] = {}
        # Sub-agent run handle -> the reason it was invalidated. As wl-apdp
        # does, a scope violation on authorize invalidates the handle: every
        # later call on it, and on every handle spawned under it, is denied
        # (``run_handle_invalidated (<reason>)``), and it cannot spawn.
        self._invalidated: Dict[str, str] = {}

    # ── identity / session lifecycle (local, no registry) ────────────

    async def probe(self) -> bool:
        return True

    async def health_check(self) -> bool:
        return bool(self._engine.ready())

    def _trust_agent(self, slug: str) -> str:
        """Register ``slug``'s agent with the engine (trusted ``name`` and
        ``slug``) and return its id. Idempotent; the engine refuses
        different attributes for the same id, or a name another agent
        holds, by raising."""
        agent_id = str(uuid.uuid5(_AGENT_NS, slug))
        self._engine.set_principal_attributes(
            f'Agent::"{agent_id}"', json.dumps({"name": slug, "slug": slug})
        )
        return agent_id

    async def resolve_agent(self, slug: str) -> Optional[Dict[str, Any]]:
        # The engine has no registry: tell it what wl-apdp reads from the
        # registry record, so a policy on `principal.name` or
        # `principal.slug` decides here as it does on the server. The DE has
        # no other name for an agent, so its name is its slug (the `name`
        # returned below). The slug is this process's own configuration (the
        # DE trusts its host); nothing in a request can set or change it.
        # The engine refuses different attributes for the same id and a name
        # or slug another agent holds, so a refusal raises here rather than
        # resolving to an agent it cannot name.
        agent_id = self._trust_agent(slug)
        return {"id": agent_id, "slug": slug, "name": slug}

    async def create_session(
        self,
        agent_id: Optional[str] = None,
        goal_id: Optional[str] = None,
        max_actions: Optional[int] = None,
        ttl_seconds: int = 3600,
        metadata: Optional[Dict[str, Any]] = None,
        subject_token: Optional[str] = None,
        application_id: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        if application_id is not None:
            # Application attribution is decided by wl-apdp from the
            # control plane's declared memberships; the in-process engine has
            # no application registry. Refuse rather than record an
            # attribution nothing verified.
            raise WatchlightContractError(
                "application_id is not supported by the in-process engine: "
                "run attribution to an AI application needs Watchlight "
                "Enterprise (wl-apdp)"
            )
        if subject_token is not None:
            # Subject ingress (a run acting for a verified end user) is an
            # Enterprise capability: the in-process engine has no identity
            # provider to verify the token against. Refuse rather than open
            # a run that silently drops who it acts for.
            raise WatchlightContractError(
                "subject_token is not supported by the in-process engine: "
                "a run on behalf of a verified end user needs Watchlight "
                "Enterprise (wl-apdp subject ingress)"
            )
        identity = self._identity_agent_id
        if agent_id is None:
            if identity is None:
                # No credential in-process: the configured identity is the
                # equivalent of the credential's agent. Without one nothing
                # is guessed.
                raise CredentialBindsNoAgent(
                    "The run names no agent and this process has no identity: pass "
                    f"InProcessClient(agent=...) or set {ENV_AGENT}, or name the agent."
                )
            agent_id = identity
        elif identity is not None and agent_id != identity:
            # As wl-apdp refuses a name an agent-bound credential does not
            # match.
            raise GovernanceRefused(
                "The run names another agent than this process's identity; refusing it.",
                status_code=403,
            )
        session_id = f"ses_{uuid.uuid4()}"
        self._sessions[session_id] = agent_id
        run = self._new_run(session_id)
        self._run_agents[run] = agent_id
        # The root run's handle, as wl-apdp mints one at session creation:
        # a spawn under this run must name it.
        root_handle = str(uuid.uuid4())
        self._run_handles[run] = root_handle
        self._root_handles.add(root_handle)
        # No run credential: the DE has no server to mint one, and lineage is
        # written locally.
        return SessionInfo(
            run=run,
            session_id=session_id,
            agent_id=agent_id,
            execution_id=f"exec_{uuid.uuid4()}",
            root_run_handle_id=root_handle,
            # The caller's free-form ``metadata`` is not echoed back: only
            # documented, non-secret session fields reach the caller.
            session=public_session_record(
                {
                    "id": session_id,
                    "agent_id": agent_id,
                    "goal_id": goal_id,
                    "max_actions": max_actions,
                    "ttl_seconds": ttl_seconds,
                }
            ),
        )

    def _new_run(self, session_id: str) -> RunRef:
        run = RunRef("run_" + secrets.token_urlsafe(18))
        self._runs[run] = session_id
        return run

    def _end_run(self, run: RunRef, reason: str) -> bool:
        session_id = self._runs.pop(run, None) if isinstance(run, str) else None
        if session_id is None:
            return False
        self._sessions.pop(session_id, None)
        handle = self._run_handles.pop(run, None)
        if handle is not None:
            self._root_handles.discard(handle)
        self._run_agents.pop(run, None)
        self._run_labels.pop(run, None)
        self._ended[run] = None
        while len(self._ended) > MAX_ENDED_RUNS:
            self._ended.popitem(last=False)
        self._kill_subs.notify(KillNotice(run=run, reason=reason, source="backend"))
        return True

    def _live(self, run: Optional[RunRef]) -> bool:
        return isinstance(run, str) and run in self._runs

    def _release_dropped_run(self, run: RunRef) -> None:
        """A run handle was garbage-collected without closing its run: end
        it (local bookkeeping). Never raises."""
        try:
            self._end_run(run, "handle_dropped")
        except Exception:  # noqa: BLE001 - a finalizer never raises
            pass

    async def get_manifest(
        self,
        agent_id: str,
        goal_id: Optional[str] = None,
        ttl_seconds: int = 3600,
        run: Optional[RunRef] = None,
        application_id: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        if run is not None and not self._live(run):
            return None  # unknown or ended run: no manifest (fail closed)
        # A non-None manifest keeps the plugin in strong governance mode.
        return {"agent_id": agent_id, "goal_id": goal_id, "policies": []}

    async def complete_session(self, run: RunRef) -> bool:
        # ``False`` for an unknown or already-ended run.
        return self._end_run(run, "run_completed")

    async def terminate_session(self, run: RunRef, reason: str = "manual") -> bool:
        # Local bookkeeping only — there is no server to transition. The
        # in-process lane genuinely needs this: without it, every
        # abnormally-ended run leaks its ``_sessions`` entry.
        del reason
        return self._end_run(run, "run_terminated")

    async def drain(self, run: RunRef, timeout_s: Optional[float] = None) -> None:
        # Lineage is written synchronously to the local file: nothing queued.
        return None

    def subscribe_kill(self, run: RunRef, callback: KillCallback) -> Unsubscribe:
        """Fires when the run ends in this backend. An unknown or ended run
        fires at once (fail closed)."""
        if not (isinstance(run, str) and run in self._runs):
            fire_kill_callback(
                callback, KillNotice(run=run, reason="unknown_run", source="backend")
            )
            return lambda: None
        return self._kill_subs.subscribe(run, callback)

    def egress_for(self, run: RunRef) -> Optional[EgressBinding]:
        # No governed egress in the Developer Edition.
        return None

    async def close(self) -> None:
        return None

    async def check_agent_trust(self, agent_id: str) -> Dict[str, Any]:
        # No trust-state service in the DE; a locally-run agent is trusted.
        return {
            "trusted": True,
            "trust_state": "trusted",
            "reason": "developer-edition",
        }

    # ── authorization (real engine decisions) ────────────────────────

    async def authorize(
        self,
        principal: str,
        action: str,
        resource: str,
        context: Optional[Dict[str, Any]] = None,
        execution_id: Optional[str] = None,
        session_id: Optional[str] = None,
        intent: Optional[Dict[str, Any]] = None,
        # DE runs the engine IN-PROCESS: no network, no wl-proxy, no
        # wl-execution-graph, no lineage projection. The run reference only
        # binds a decision's lineage to a run OVER THE WIRE (Enterprise);
        # there is no wire and no lineage graph here. Accepted for
        # GovernanceBackend signature-compatibility; only checked: an
        # unknown or ended run is a Deny (fail closed). ``None`` (a direct
        # call naming no run) is decided as before.
        run: Optional[RunRef] = None,
    ) -> Dict[str, Any]:
        if run is not None and not self._live(run):
            return {"decision": "Deny", "reason": "unknown or ended run", "details": {}}
        # A sub-agent's time budget is enforced here, as wl-apdp enforces it:
        # once its granted deadline has passed, every call it makes is denied.
        mismatch = self._handle_ownership_refusal(run, context)
        if mismatch is not None:
            return {"decision": "Deny", "reason": mismatch, "details": {}}
        handle_id = self._subagent_handle_id(run, context)
        invalidated = self._invalidation_refusal(handle_id)
        if invalidated is not None:
            return {"decision": "Deny", "reason": invalidated, "details": {}}
        scope = self._scopes.get(handle_id or "")
        if _deadline_passed(scope, datetime.now(timezone.utc)):
            return {"decision": "Deny", "reason": "time_budget_exceeded", "details": {}}
        # A sub-agent may act only inside the scope its spawn granted (the
        # tools, resources and intents), as wl-apdp's pre-Cedar
        # scope-membership check enforces it; checked by the engine. A
        # violation invalidates the handle, as on the server, but only a
        # handle bound to the calling run: a handle a call merely NAMES in
        # its context is never invalidated by that call.
        refusal = self._scope_refusal(
            handle_id, action, resource, intent,
            preview=not self._is_run_bound(run, handle_id),
        )
        if refusal is not None:
            return {"decision": "Deny", "reason": refusal, "details": {}}
        # Terms reach the engine EXACTLY as the caller expressed them. This
        # client used to strip a `Type::"name"` wrapper off all three, which —
        # combined with the SDK force-wrapping them on the way in — meant every
        # term arrived BARE, and a bare term was a WILDCARD that matched a
        # policy naming any entity type with that id. A policy written
        # `permit(principal == User::"u1", …)` therefore allowed a principal of
        # `Agent::"u1"`. A typed term now keeps its type and discriminates; a
        # bare term reaches the engine bare, where it gets one fixed type for
        # its position (`User` / `Action` / `Resource`).
        return self._decide(principal, action, resource, self._run_context(run, context))

    def _run_context(
        self, run: Optional[RunRef], context: Optional[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """The decision context: the caller's, with ``subagent_label`` set
        from the run's own spawn (never the caller's value)."""
        ctx = dict(context or {})
        ctx.pop(SUBAGENT_LABEL_CONTEXT_KEY, None)
        label = self._run_labels.get(run) if isinstance(run, str) else None
        if label is not None:
            ctx[SUBAGENT_LABEL_CONTEXT_KEY] = label
        return ctx

    async def preflight_step(
        self,
        run: RunRef,
        action: str,
        resource: str,
        resource_type: Optional[str] = None,
        intent: Optional[Dict[str, Any]] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        # As authorize: an unknown or ended run is denied first, so a
        # sub-agent whose run has ended cannot skip its deadline check.
        if run is not None and not self._live(run):
            return {"preflight": {"decision": "Deny", "reason": "unknown or ended run"}}
        mismatch = self._handle_ownership_refusal(run, context)
        if mismatch is not None:
            return {"preflight": {"decision": "Deny", "reason": mismatch}}
        handle_id = self._subagent_handle_id(run, context)
        invalidated = self._invalidation_refusal(handle_id)
        if invalidated is not None:
            return {"preflight": {"decision": "Deny", "reason": invalidated}}
        scope = self._scopes.get(handle_id or "")
        if _deadline_passed(scope, datetime.now(timezone.utc)):
            # As authorize: a sub-agent past its deadline is denied.
            return {"preflight": {"decision": "Deny", "reason": "time_budget_exceeded"}}
        # As authorize, but a preview (as wl-apdp's preflight): a call outside
        # the grant is denied and the handle is NOT invalidated.
        refusal = self._scope_refusal(handle_id, action, resource, intent, preview=True)
        if refusal is not None:
            return {"preflight": {"decision": "Deny", "reason": refusal}}
        # preflight carries no principal — authorize under the session's
        # agent, as the SAME principal `authorize` decides for it:
        # `Agent::"<agent id>"`, so the agent's trusted name and slug (and
        # every rule scoped by them, forbids included) apply here too. A bare
        # id used to reach the engine bare, where it is a `User`.
        session_id = self._runs.get(run) if isinstance(run, str) else None
        principal = _session_agent_principal(self._sessions.get(session_id or ""))
        if principal is None:
            # No session agent to decide for: fail closed.
            return {"preflight": {"decision": "Deny", "reason": "unknown or ended run"}}
        result = self._decide(principal, action, resource, self._run_context(run, context))
        return {"preflight": {"decision": result["decision"]}}

    def _subagent_handle_id(
        self, run: Optional[RunRef], context: Optional[Dict[str, Any]]
    ) -> Optional[str]:
        """The sub-agent run handle a call is made under: the one the run's
        own session names (a child's session is ``ses_<run_handle_id>``),
        else a ``run_handle_id`` in the context. ``None`` for a root run or
        a call naming no sub-agent."""
        if run is not None and isinstance(run, str):
            bound = self._run_handles.get(run)
            if bound is not None and bound in self._scopes:
                return bound
        handle = (context or {}).get("run_handle_id")
        if isinstance(handle, str) and handle in self._scopes:
            return handle
        return None

    def _is_run_bound(self, run: Optional[RunRef], handle_id: Optional[str]) -> bool:
        """Whether ``handle_id`` is the handle the calling run is bound to."""
        return (
            isinstance(run, str)
            and handle_id is not None
            and self._run_handles.get(run) == handle_id
        )

    def _handle_ownership_refusal(
        self, run: Optional[RunRef], context: Optional[Dict[str, Any]]
    ) -> Optional[str]:
        """As wl-apdp, before any scope check: a ``run_handle_id`` in the
        context that names no known handle is refused
        (``run_handle_not_found``), and a call on a run that names a handle
        that is not the run's own is refused
        (``run_handle_principal_mismatch``), so it can neither borrow nor
        invalidate another run's handle."""
        named = (context or {}).get("run_handle_id")
        if named is None:
            return None
        if not isinstance(named, str) or (
            named not in self._scopes and named not in self._root_handles
        ):
            # As wl-apdp: a supplied handle with no record is a stale,
            # replayed or forged value, refused (run_handle_not_found).
            return "run_handle_not_found"
        if not isinstance(run, str) or self._run_handles.get(run) == named:
            return None
        return "run_handle_principal_mismatch"

    def _invalidation_refusal(self, handle_id: Optional[str]) -> Optional[str]:
        """The refusal for a call on an invalidated sub-agent handle, or on
        one spawned (at any depth) under an invalidated handle; ``None``
        otherwise. The reasons are wl-apdp's."""
        current = handle_id
        own = True
        seen: Set[str] = set()
        while isinstance(current, str) and current not in seen:
            seen.add(current)
            reason = self._invalidated.get(current)
            if reason is not None:
                return f"run_handle_invalidated ({reason if own else 'parent_handle_invalidated'})"
            scope = self._scopes.get(current)
            current = scope.get("parent_run_handle_id") if isinstance(scope, dict) else None
            own = False
        return None

    def _scope_refusal(
        self,
        handle_id: Optional[str],
        action: str,
        resource: str,
        intent: Optional[Dict[str, Any]],
        *,
        preview: bool,
    ) -> Optional[str]:
        """Why a sub-agent's call falls outside its granted scope, or
        ``None`` when it is inside (or the call is not a sub-agent's).

        The engine decides (``check_scope_membership``: wl-apdp's own
        per-call check of the tool, resource, intent and deadline, with the
        intent parsed by wl-apdp's own type, so the category comes only from
        the typed ``intent``, never from the context). Unless ``preview``,
        a violation invalidates the handle and is recorded in the local
        audit as ``scope_violation_observed``, as wl-apdp does. Fail closed:
        an engine without the check, or one that cannot read the grant,
        refuses the call."""
        scope = self._scopes.get(handle_id or "")
        if scope is None:
            return None
        check = getattr(self._engine, "check_scope_membership", None)
        if check is None:
            return (
                "subagent_scope_unenforceable: the installed watchlight-engine "
                "cannot check a sub-agent's granted scope; upgrade it to "
                f"{REQUIRED_ENGINE_VERSION} or later"
            )
        # An empty intent is no intent (the HTTP client drops it too).
        if not intent:
            intent = None
        try:
            raw = json.loads(
                check(
                    json.dumps(scope),
                    action,
                    resource,
                    None if intent is None else json.dumps(intent),
                )
            )
        except Exception as exc:  # noqa: BLE001 — an unreadable grant refuses
            return f"subagent_scope_unreadable ({type(exc).__name__})"
        if isinstance(raw, dict) and raw.get("decision") == "Allow":
            return None
        if not isinstance(raw, dict):
            return "scope_attenuation_violation"
        reason = raw.get("reason")
        reason = reason if isinstance(reason, str) and reason else "scope_attenuation_violation"
        invalidation = raw.get("invalidation_reason")
        if not preview and isinstance(invalidation, str) and invalidation and handle_id:
            self._invalidated[handle_id] = invalidation
            violations = raw.get("violations")
            self._emit_scope_violation(
                handle_id=handle_id,
                scope=scope,
                action=action,
                resource=resource,
                violations=violations if isinstance(violations, list) else [],
                invalidation=invalidation,
            )
        return reason

    def _emit_scope_violation(
        self,
        *,
        handle_id: str,
        scope: Dict[str, Any],
        action: str,
        resource: str,
        violations: List[Any],
        invalidation: str,
    ) -> None:
        """Append a value-free ``scope_violation_observed`` record (the
        server's event name) to the local audit: which sub-agent handle,
        which tool it tried (names only), the failed dimensions and why the
        handle was invalidated. Best-effort: never raises."""
        if self._audit_path is None:
            return
        record: Dict[str, Any] = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "event": "scope_violation_observed",
            "intent": "attenuate",
            "node_id": handle_id,
            "decision": "Deny",
            "action": str(action)[:_AUDIT_MAX_TOOL_NAME],
            "resource": str(resource)[:_AUDIT_MAX_TOOL_NAME],
            "violations": [str(v)[:_AUDIT_MAX_TOOL_NAME] for v in violations[:_AUDIT_MAX_TOOLS]],
            "reason": invalidation,
            "depth": int(scope.get("depth", 0) or 0),
        }
        parent = scope.get("parent_run_handle_id")
        if isinstance(parent, str) and parent:
            record["parent_id"] = parent
        try:
            self._audit_path.parent.mkdir(parents=True, exist_ok=True)
            with self._audit_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(record) + "\n")
        except OSError:  # pragma: no cover — best-effort local audit
            pass

    def _decide(
        self, principal: str, action: str, resource: str, context: Dict[str, Any]
    ) -> Dict[str, Any]:
        request = {
            "principal": principal,
            "action": action,
            "resource": resource,
            # Cedar rejects JSON `null` in the context. The SDK auto-wires
            # optional fields (run_handle_id, tenant_id, …) that may be None;
            # the networked apdp tolerates them, so drop nulls to match.
            "context": _strip_nulls(context),
        }
        raw = json.loads(self._engine.authorize(json.dumps(request)))
        decision = raw.get("decision", "Deny")
        return {
            "decision": decision,
            "reason": raw.get("reason", ""),
            "details": raw.get("details", {}),
        }

    # ── plan / spawn ─────────────────────────────────────────────────

    async def submit_plan(
        self, run: RunRef, plan: List[Dict[str, Any]]
    ) -> Optional[Dict[str, Any]]:
        raise NotImplementedError(
            "In-process plan validation needs a compiled-engine method not yet "
            "exposed to the in-process binding. Authorize each step with "
            "authorize_action in the meantime."
        )

    async def spawn_subagent(
        self,
        parent: RunRef,
        request: Dict[str, Any],
    ) -> Dict[str, Any]:
        """In-process strict-subset sub-agent scope attenuation.

        Mirrors :meth:`ApdpClient.spawn_subagent`: ``RunHandle.spawn_subagent``
        hands us the serialised
        :class:`~watchlight_core.scope.SpawnSubagentRequest`; we run the REAL
        engine strict-subset validator in-process, record the child's granted
        scope, write a value-free ``attenuation`` lineage record (so the
        ``watchlight dev`` attenuation tree populates), and return the response
        envelope. On overreach we raise
        :class:`~watchlight_core.errors.ScopeAttenuationDenied` — the same typed
        error the networked 403 path raises — so plugin code behaves identically
        dev ↔ prod.

        Root delegation (Developer Edition). A DE root agent carries the
        developer's full, undeclared authority (its ``RunHandle.granted_scope`` is
        ``None``), so its FIRST delegation is validated against a root scope that
        holds the requested tools, resources, intents and depth, with the
        client's ``subagent_time_budget_threshold_seconds`` as its time budget;
        every DESCENDANT is strict-subset-validated by the engine against its
        parent's granted scope. Every child gets a deadline (spawn time plus
        its resolved budget, never later than its parent's). A spawn that names
        no budget inherits the parent's remaining time; one whose resolved
        budget is zero is refused as unsatisfiable (``reason_code
        UNSATISFIABLE_SCOPE``); a budget that is not an integer in range is
        refused as ``invalid_spawn_request``. Once the deadline passes,
        :meth:`authorize` and :meth:`preflight_step` deny every call the child
        makes, as wl-apdp does.

        Every run is bound to a handle: ``create_session`` mints the root
        run's handle and returns it as ``root_run_handle_id``, and a spawn
        mints the child's. A spawn is validated against the handle bound to
        the ``parent`` run, never against a handle the request names. It is
        refused with :class:`~watchlight_core.errors.ScopeAttenuationDenied`
        (``reason == "parent_run_handle_not_found"``), a ``Deny``
        attenuation record is written, and no child run is opened, when:

        - ``parent_run_handle_id`` is missing or not a UUID;
        - it is not the parent run's own handle (an unknown handle is
          refused for a root run too, as wl-apdp refuses it);
        - the parent's scope cannot be established.

        Advisory boundary. This runs the engine's real strict-subset math, but
        in-process it is **not** an enforcement boundary against a *hostile*
        child: everything runs in one cooperative process that already holds
        the developer's full authority, so this is a governance / observability
        aid, not a sandbox. Confinement of an *untrusted* sub-agent is enforced
        server-side by the control plane (Enterprise), where the spawn is
        authenticated with the parent's session credential.

        ``parent`` must be a live run of this backend: an unknown or ended
        parent is refused with :class:`GovernanceUnavailable`, as the
        networked backend refuses it (the parent proves nothing more here:
        see "Advisory boundary"). The child gets its own run reference
        (``child_run``), naming its local session
        ``ses_<child_run_handle_id>``.
        """
        if not self._live(parent):
            from .errors import GovernanceUnavailable

            raise GovernanceUnavailable(
                "spawn_subagent: the parent run is unknown or has ended; "
                "refusing the spawn"
            )
        request_body = request
        from .errors import ScopeAttenuationDenied, ScopeViolationDimension
        from .scope import (
            SpawnSubagentResponse,
            granted_scope_from_dict,
            requested_scope_to_dict,
            spawn_subagent_request_from_dict,
            spawn_subagent_response_to_dict,
        )

        child_handle_id = uuid.uuid4()

        def _refuse(reason: str, message: str, *, agent: str, tools: List[str],
                    parent_id: Optional[str], depth: int) -> NoReturn:
            self._emit_attenuation(
                node_id=str(child_handle_id),
                parent_id=parent_id,
                agent=agent,
                tools=tools,
                depth=depth,
                decision="Deny",
                reason=reason,
            )
            raise ScopeAttenuationDenied(reason, message=message)

        body = request_body if isinstance(request_body, dict) else {}
        raw_parent = body.get("parent_run_handle_id")
        raw_label = body.get("child_label")
        child_agent = str(body.get("child_agent_id") or raw_label or "")
        try:
            parent_handle_id = str(uuid.UUID(raw_parent)) if isinstance(raw_parent, str) else None
        except ValueError:
            parent_handle_id = None
        if parent_handle_id is None:
            _refuse(
                "parent_run_handle_not_found",
                "spawn_subagent: the request names no valid parent run handle; "
                "the sub-agent was not started",
                agent=child_agent, tools=[], parent_id=None, depth=0,
            )
        try:
            request = spawn_subagent_request_from_dict(request_body)
        except (TypeError, ValueError, KeyError, AttributeError):
            _refuse(
                "invalid_spawn_request",
                "spawn_subagent: the spawn request is malformed; the sub-agent "
                "was not started",
                agent=child_agent, tools=[], parent_id=parent_handle_id, depth=0,
            )
        # Every spawn declares the child's intent, as
        # wl-apdp requires. The child is granted exactly that category: a
        # requested intent list must be empty or exactly it.
        if request.child_intent is None:
            _refuse(
                "child_intent_required",
                "spawn_subagent: the spawn declares no child intent; the "
                "sub-agent was not started",
                agent=child_agent, tools=[], parent_id=parent_handle_id, depth=0,
            )
        requested = request.requested_scope
        category = request.child_intent.category
        if requested.allowed_intents and list(requested.allowed_intents) != [category]:
            _refuse(
                "intent_not_derived",
                "spawn_subagent: the requested intents contradict the child "
                "intent; the sub-agent was not started",
                agent=child_agent, tools=[], parent_id=parent_handle_id, depth=0,
            )
        requested.allowed_intents = [category]
        requested_tools = list(requested.allowed_tools)
        # Who the child runs as: the named agent; else the agent its label is
        # mapped to; else (anonymous) its parent's agent. Never anything the
        # label itself could widen: the scope below is attenuated either way.
        child_label = request.child_label
        if request.child_agent_id is not None:
            child_agent = str(request.child_agent_id)
            child_identity = CHILD_IDENTITY_REGISTERED
        elif child_label is not None and child_label in self._subagent_agents:
            child_agent = self._subagent_agents[child_label]
            child_identity = CHILD_IDENTITY_MAPPED
        else:
            child_agent = self._run_agents.get(parent, "")
            child_identity = CHILD_IDENTITY_ANONYMOUS
        if not child_agent:
            _refuse(
                "invalid_spawn_request",
                "spawn_subagent: the parent run's agent is unknown, so an anonymous "
                "child has no identity; the sub-agent was not started",
                agent="", tools=requested_tools, parent_id=parent_handle_id, depth=0,
            )

        # The parent's scope comes from the parent RUN's own handle, never
        # from the handle id the request names. Fail closed: an unknown
        # handle (root included) or an unknown scope refuses the spawn.
        bound_handle = self._run_handles.get(parent)
        is_root = bound_handle is not None and bound_handle in self._root_handles
        if getattr(self._engine, "check_scope_membership", None) is None:
            # The child's calls could not be checked against its grant: the
            # child never runs.
            _refuse(
                "subagent_scope_unenforceable",
                "spawn_subagent: the installed watchlight-engine cannot check a "
                "sub-agent's granted scope; upgrade it to "
                f"{REQUIRED_ENGINE_VERSION} or later. The sub-agent was not started",
                agent=child_agent, tools=requested_tools,
                parent_id=parent_handle_id, depth=0,
            )
        invalidated = self._invalidation_refusal(bound_handle)
        if invalidated is not None:
            _refuse(
                # wl-apdp's spawn handler code for this refusal.
                "parent_handle_invalidated",
                f"spawn_subagent: the parent's run handle is invalidated ({invalidated}); "
                "the sub-agent was not started",
                agent=child_agent, tools=requested_tools,
                parent_id=parent_handle_id, depth=0,
            )
        parent_scope: Optional[Dict[str, Any]] = (
            None if bound_handle is None or is_root else self._scopes.get(bound_handle)
        )
        if parent_handle_id != bound_handle or (not is_root and parent_scope is None):
            _refuse(
                "parent_run_handle_not_found",
                "spawn_subagent: the parent's scope could not be established; "
                "the sub-agent was not started",
                agent=child_agent,
                tools=requested_tools,
                parent_id=parent_handle_id,
                depth=int((parent_scope or {}).get("depth", 0)) + 1,
            )
        if is_root:
            # Root delegation: validated by the engine against the root's
            # effective scope, as wl-apdp validates a root spawn (see
            # docstring). The root holds the developer's full authority, so
            # the requested tools, resources, intents and depth are within it;
            # the time budget is checked like any other spawn's, so a child
            # whose resolved budget is zero is refused as unsatisfiable.
            parent_scope = _root_effective_scope(
                requested_scope_to_dict(requested),
                parent_handle_id,
                self._root_time_budget_seconds,
            )
        assert parent_scope is not None  # checked above
        try:
            raw = json.loads(
                self._engine.attenuate_scope(
                    json.dumps(parent_scope),
                    json.dumps(requested_scope_to_dict(requested)),
                )
            )
        except ValueError:
            # The engine could not read the request (a budget it cannot hold):
            # a typed refusal with its Deny record, never an untyped error.
            # An engine too old to resolve an absent budget never gets here;
            # construction refuses it (REQUIRED_ENGINE_VERSION).
            _refuse(
                "invalid_spawn_request",
                "spawn_subagent: the engine could not read the spawn request "
                "(an out-of-range time budget); the sub-agent was not started",
                agent=child_agent,
                tools=requested_tools,
                parent_id=parent_handle_id,
                depth=int(parent_scope.get("depth", 0)) + 1,
            )
        if raw.get("decision") != "Allow":
            reason = raw.get("reason") or "scope_attenuation_violation"
            # The engine's refusal class, as wl-apdp reports it. An engine
            # that predates the field is read from its message.
            engine_code = raw.get("reason_code") or (
                "UNSATISFIABLE_SCOPE"
                if str(reason).startswith("unsatisfiable scope")
                else None
            )
            dims: List[ScopeViolationDimension] = []
            for label in raw.get("violations") or []:
                dim = _engine_violation_to_dim(label, ScopeViolationDimension)
                if dim is not None:
                    dims.append(dim)
            # The parent's depth budget is spent: the child would be deeper
            # than the tree's limit — the delegation-depth deny, not a
            # widening request.
            parent_depth = int(parent_scope.get("depth", 0))
            depth_exceeded = "MaxDepth" in (raw.get("violations") or []) and int(
                parent_scope.get("max_depth", 0)
            ) == 0
            depth_limit = parent_depth + int(parent_scope.get("max_depth", 0))
            # Record the denied node too, so the tree shows where authority
            # narrowing was refused.
            self._emit_attenuation(
                node_id=str(child_handle_id),
                parent_id=parent_handle_id,
                agent=child_agent,
                tools=requested_tools,
                depth=parent_depth + 1,
                decision="Deny",
                reason=reason,
                reason_code=(
                    "DELEGATION_DEPTH_EXCEEDED" if depth_exceeded else (engine_code or "")
                ),
                max_delegation_depth=depth_limit if depth_exceeded else None,
                label=child_label,
            )
            if depth_exceeded:
                raise ScopeAttenuationDenied(
                    reason,
                    dims,
                    reason_code="DELEGATION_DEPTH_EXCEEDED",
                    observed_depth=parent_depth + 1,
                    max_delegation_depth=depth_limit,
                )
            raise ScopeAttenuationDenied(reason, dims, reason_code=engine_code)
        granted_dict = raw["granted_scope"]
        # Record the ACTUAL parent handle (the engine threads the
        # grandparent's id through its validator context; overwrite so the
        # child's stored scope and any next-level context are correctly
        # parented).
        granted_dict["parent_run_handle_id"] = parent_handle_id

        # Track the child's effective scope so ITS descendants validate against
        # it, then write the allow lineage node.
        child_key = str(child_handle_id)
        self._scopes[child_key] = granted_dict
        self._emit_attenuation(
            node_id=child_key,
            parent_id=parent_handle_id,
            agent=child_agent,
            tools=list(granted_dict.get("allowed_tools") or []),
            depth=int(granted_dict.get("depth", 1)),
            decision="Allow",
            reason="",
            label=child_label,
        )
        response = spawn_subagent_response_to_dict(
            SpawnSubagentResponse(
                child_run_handle_id=child_handle_id,
                granted_scope=granted_scope_from_dict(granted_dict),
                child_agent_id=child_agent,
                child_label=child_label,
                child_identity=child_identity,
            )
        )
        child_session = f"ses_{child_handle_id}"
        # The child's own agent, so its preflight decides for it (as an
        # Agent), never for an unknown principal.
        # The agent the child runs as (named, mapped from its label, or its
        # parent's for an anonymous child), the same one its spawn resolved.
        self._sessions[child_session] = child_agent
        child_run = self._new_run(child_session)
        self._run_handles[child_run] = child_key
        self._run_agents[child_run] = child_agent
        if child_label is not None:
            self._run_labels[child_run] = child_label
        response["child_run"] = child_run
        return response

    def _emit_attenuation(
        self,
        *,
        node_id: str,
        parent_id: Optional[str],
        agent: str,
        tools: List[str],
        depth: int,
        decision: str,
        reason: str,
        reason_code: str = "",
        max_delegation_depth: Optional[int] = None,
        label: Optional[str] = None,
    ) -> None:
        """Append a value-free ``attenuation`` lineage record — the shape the
        ``watchlight dev`` attenuation-tree view reads (``node_id`` / ``parent_id``
        / ``depth`` / ``tools`` / ``decision``). Argument VALUES never enter it;
        only capability NAMES and the decision. Best-effort: never raises."""
        if self._audit_path is None:
            return
        record: Dict[str, Any] = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "agent": agent,
            "intent": "attenuate",
            "event": "attenuation",
            "node_id": node_id,
            "resource": f"sub-agent depth {depth}",
            "decision": decision,
            "depth": depth,
            "tools": [
                str(t)[:_AUDIT_MAX_TOOL_NAME] for t in list(tools)[:_AUDIT_MAX_TOOLS]
            ],
        }
        if parent_id:
            record["parent_id"] = parent_id
        if reason:
            record["reason"] = reason
        if reason_code:
            record["reason_code"] = reason_code
        if max_delegation_depth is not None:
            record["max_delegation_depth"] = max_delegation_depth
        if label is not None:
            # The child's label (already validated): evidence, never authority.
            record["child_label"] = label
        try:
            self._audit_path.parent.mkdir(parents=True, exist_ok=True)
            with self._audit_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(record) + "\n")
        except OSError:  # pragma: no cover — best-effort local audit
            pass

    # ── lineage (local JSONL, not signed NATS lineage) ───────────────

    async def publish_events(
        self, run: Optional[RunRef], events: List[Dict[str, Any]]
    ) -> bool:
        if not events:
            return True
        # An unknown run is refused; an ended run's late lineage (its
        # terminal event) is still written. ``None`` names no run: the DE
        # has no run credential, so such events (the @watchlight
        # decorator's) are written as before.
        if run is not None and not (self._live(run) or run in self._ended):
            return False
        if self._audit_path is None:
            return True
        self._audit_path.parent.mkdir(parents=True, exist_ok=True)
        with self._audit_path.open("a", encoding="utf-8") as fh:
            for event in events:
                fh.write(json.dumps(event, ensure_ascii=True) + "\n")
        return True


def _root_effective_scope(
    requested: Dict[str, Any], root_handle_id: str, time_budget_seconds: int
) -> Dict[str, Any]:
    """The effective scope of a Developer Edition root run, for validating
    its first delegation with the engine, as wl-apdp validates a root spawn
    against the root agent's effective scope.

    The root holds the developer's full, undeclared authority, so the
    requested tools, resources and intents are within it (the scope names
    exactly them) and so is the requested depth. Its time budget is the
    client's ``subagent_time_budget_threshold_seconds``, as wl-apdp caps a
    root with the agent's or tenant's threshold. The engine sets the root's
    deadline to spawn time plus that budget, so a child that names no
    budget inherits it, a larger request is refused as a widening, and zero
    is refused as unsatisfiable, as wl-apdp does.

    One difference from wl-apdp: wl-apdp anchors the root's deadline at
    session creation (its TTL), so a child spawned late in a session gets
    only what is left of it. The in-process root is not time-bound, so its
    ceiling starts again at each first-level spawn. A child never gets more
    than the threshold either way, and a named budget above it is refused
    in both, never clamped."""
    return {
        "allowed_tools": list(requested.get("allowed_tools") or []),
        "allowed_resources": list(requested.get("allowed_resources") or []),
        "allowed_intents": list(requested.get("allowed_intents") or []),
        "max_depth": int(requested.get("max_depth") or 0) + 1,
        "time_budget_seconds": time_budget_seconds,
        "depth": 0,
        "parent_run_handle_id": root_handle_id,
    }


def _deadline_passed(scope: Optional[Dict[str, Any]], now: datetime) -> bool:
    """True when a sub-agent's granted scope says its time is up. ``None``
    (not a sub-agent) has no deadline to pass. A granted scope with no
    deadline, or one that cannot be read, counts as passed (fail closed),
    as wl-apdp's membership check treats it."""
    if scope is None:
        return False
    raw = scope.get("deadline")
    if raw is None:
        return True
    try:
        # The engine writes RFC 3339 with up to nine fractional digits;
        # ``fromisoformat`` (Python 3.10) takes at most six and no ``Z``.
        text = re.sub(r"(\.\d{6})\d+", r"\1", str(raw)).replace("Z", "+00:00")
        deadline = datetime.fromisoformat(text)
        if deadline.tzinfo is None:
            deadline = deadline.replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return True
    return now >= deadline


def _engine_violation_to_dim(label: Any, dim_enum: Any) -> Any:
    """Map a strict-subset engine violation label to a
    :class:`~watchlight_core.errors.ScopeViolationDimension`.

    The compiled engine emits the Rust enum's Debug spelling (PascalCase, e.g.
    ``MaxDepth``); the SDK enum uses the snake_case wire form (``max_depth``).
    Convert, then defer to ``from_wire``. An unmappable label yields ``None`` and
    is dropped — the ``reason`` string still carries the human detail, so an
    engine that grows a new dimension never crashes an older SDK."""
    if not isinstance(label, str):
        return None
    wire = re.sub(r"(?<!^)(?=[A-Z])", "_", label).lower()
    for candidate in (wire, label):
        try:
            return dim_enum.from_wire(candidate)
        except ValueError:
            continue
    return None


def _load_policies(policies: Optional[Any]) -> List[Dict[str, Any]]:
    if policies is None:
        return []
    if isinstance(policies, (str, Path)):
        data = json.loads(Path(policies).read_text(encoding="utf-8"))
    else:
        data = policies
    if not isinstance(data, list):
        raise ValueError(
            "policies must be a list of {name, code} dicts or a path to such a JSON file"
        )
    return data
