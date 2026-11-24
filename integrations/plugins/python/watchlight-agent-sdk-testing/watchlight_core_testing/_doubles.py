"""Pytest fixtures + helpers for plugin authors.

Import from ``watchlight_core_testing`` when writing tests for a
framework plugin. Provides:

  - :class:`MockApdpClient` — drop-in replacement for
    :class:`watchlight_core.ApdpClient` that returns canned
    Allow / Deny / needs_approval responses. Lets plugin tests
    run without a live APDP server.
  - :func:`capture_events` — async context manager that intercepts
    every event published via the mock client's
    ``publish_events`` and records them for later assertion.
  - :func:`stub_handle` — synthetic
    :class:`watchlight_core.BaseRunHandle` for unit tests that
    need a handle but don't want to mock out the whole session
    lifecycle.
  - :func:`assert_canonical_event` — runs the seven conformance
    invariants on a single event dict. The same assertions the
    cross-plugin conformance suite uses, exposed for plugin
    authors to call in their own tests.

All helpers are framework-agnostic. They work for any plugin that
satisfies the :class:`watchlight_core.GovernedPlugin` Protocol.
"""

from __future__ import annotations

import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, AsyncIterator, Dict, List, Optional, Sequence

from watchlight_core.backend import (
    EgressBinding,
    KillCallback,
    KillNotice,
    KillSubscriptions,
    RunRef,
    SessionInfo,
    Unsubscribe,
    fire_kill_callback,
    public_session_record,
)
from watchlight_core.errors import AgentNotRegistered, GovernanceUnavailable
from watchlight_core.events_schema import (
    EVENT_ID_RE,
    INPUT_SUMMARY_MAX_CHARS,
    ERROR_MESSAGE_MAX_CHARS,
    EventType,
    PayloadSchemaError,
    PLAN_INTENDED_TOOLS_MAX,
    PLAN_RATIONALE_MAX_BYTES,
    PLAN_TOOL_NAME_RE,
    unknown_payload_keys,
    validate_event_payload,
)
from watchlight_core.results import AuthorizeResult
from watchlight_core.run_handle import BaseRunHandle

__all__ = [
    "MockApdpClient",
    "register_test_run",
    "bind_test_run",
    "stub_session_info",
    "capture_events",
    "stub_handle",
    "stub_session",
    "assert_canonical_event",
    "assert_payload_matches_schema",
    "ConformanceFailure",
]


# ─── Canned-response APDP client ──────────────────────────────────────


class MockApdpClient:
    """Stub :class:`ApdpClient` for unit-testing plugins.

    Returns canned responses; every method that the real
    ``ApdpClient`` exposes is mocked here. Behaviours are tunable
    by setting attributes on the instance:

      - ``default_decision``: ``"Deny"`` (the default) | ``"Allow"`` |
        ``"needs_approval"`` — what ``authorize()`` returns for a call
        no rule in ``decisions`` names. It denies unless a test says
        otherwise, so no test passes because the double allowed by
        omission: pass ``default_decision="Allow"`` or set per-call
        rules in ``decisions``.
      - ``decisions``: ``Dict[str, str]`` keyed by ``(action, resource)``
        — explicit overrides for specific calls.
      - ``known_agents``: ``Dict[str, str]`` slug → UUID. ``resolve_agent``
        returns ``None`` for unknown slugs (the production behaviour
        that triggers ``AgentNotRegistered``).
      - ``probe_succeeds``: when ``False``, ``probe()`` returns
        False so plugin start_run paths can exercise the
        degraded-governance branch.
      - ``credential_agent``: the agent UUID the mock's credential is
        bound to (``None``: bound to no agent, like a tenant plugin
        credential). ``create_session()`` with no agent opens the run as
        it, or raises :class:`~watchlight_core.CredentialBindsNoAgent`;
        a named agent that differs is refused (``None``), as wl-apdp
        refuses it.
      - ``subagent_label_map``: ``Dict[str, str]`` label → agent UUID, the
        tenant's label mapping. A spawn by ``child_label`` alone runs as
        the mapped agent, else as its parent's agent (anonymous).

    The instance also captures every event published via
    ``publish_events()`` into ``published_events``, so tests can
    assert on the canonical event shape after the plugin runs.

    Example:

    .. code-block:: python

        client = MockApdpClient(default_decision="Allow")
        client.known_agents["my-agent"] = "uuid-1234"
        client.decisions[("execute", "fs.read")] = "Deny"

        plugin = WatchlightMyFrameworkPlugin(apdp_url="https://stub")
        plugin.apdp = client  # inject the mock
        handle = await plugin.start_run("my-agent")
        result = await handle.authorize_action_detailed("execute", "fs.read")
        assert result.is_deny()
    """

    #: The decisions ``authorize()`` knows how to return. ``default_decision``
    #: refuses anything else, so a typo such as ``"allow"`` fails the test
    #: that wrote it rather than deciding nothing.
    KNOWN_DECISIONS = frozenset(
        {"Allow", "Deny", "needs_approval", "Quarantine", "Terminate", "SeverSubtree", "Revoke"}
    )

    def __init__(self, *, default_decision: str = "Deny") -> None:
        self.default_decision = default_decision
        self.decisions: Dict[tuple, str] = {}
        self.known_agents: Dict[str, str] = {}
        self.credential_agent: Optional[str] = None
        self.subagent_label_map: Dict[str, str] = {}
        self.probe_succeeds: bool = True
        # Declared roots. Every ``create_session`` that declared one
        # appends its ``live_execution_ids`` here. ``declared_root_echo``
        # False plays an older server that ignores the field (no
        # ``declared_root: true`` in the answer); ``declared_root_error``
        # is raised instead of opening the session (a policy refusal).
        self.declared_root_calls: List[List[str]] = []
        self.declared_root_echo: bool = True
        self.declared_root_error: Optional[Exception] = None
        self.published_events: List[Dict[str, Any]] = []
        # Execution-lineage integrity. Records every
        # ``publish_events`` batch as ``(session_token, [events])``: the
        # stand-in run credential the mock holds for the run the SDK named
        # (``None`` for no run or an unknown one), so tests can assert
        # each batch went out under its own run. ``published_events``
        # still holds the flat event stream.
        self.published_event_batches: List[tuple] = []
        # Like ``ApdpClient``, the mock keeps each run's stand-in
        # credentials in its own run table (RunRef -> record); handles
        # hold only the RunRef. ``token_for(run)`` reads one back for
        # assertions. The ``sst_``-shaped value is a stand-in, unique per
        # run.
        self.session_token_prefix: str = "sst_mock"
        self._runs: Dict[str, Dict[str, Any]] = {}
        self._kill_subs = KillSubscriptions()
        # Proxy (egress) tokens, off by default like a deployment without
        # wl-proxy. Set a prefix to have ``create_session`` return a
        # ``proxy_token`` and every approved spawn its own
        # ``child_proxy_token``, each unique to its session.
        self.proxy_token_prefix: Optional[str] = None
        self._closed_sessions: List[str] = []
        self._terminated_sessions: List[tuple] = []  # [(session_id, reason)]
        # Recording for the sub-agent governance invariant — tests can
        # assert which principal each authorize() call was made under
        # to catch the "sub-agent's tool call authorized against the
        # root's principal" privilege-escalation bug.
        # Each entry: {"principal": str, "action": str, "resource": str}.
        self.authorize_calls: List[Dict[str, Any]] = []
        # Record every ``POST /v1/spawn_subagent`` body so tests
        # can assert the wire shape of the requested scope and the
        # parent identity. Each entry is the dict the SDK sent on the
        # wire (canonical snake_case form). ``spawn_response`` is the
        # canned response — tests override to inject 403 / 404 /
        # custom granted_scope by raising the matching typed
        # exception or returning a tailored dict.
        self.spawn_subagent_calls: List[Dict[str, Any]] = []
        # Execution-lineage integrity — the PARENT `sst_` token the
        # SDK attached to each spawn call (parallel to spawn_subagent_calls).
        self.spawn_subagent_tokens: List[Optional[str]] = []
        self.spawn_response_override: Optional[Dict[str, Any]] = None
        self.spawn_error_override: Optional[Exception] = None
        # Tests that want to control the Quarantine payload
        # shape (different anomaly score, contributing features, etc.)
        # set this dict before calling authorize. Defaults to a
        # synthetic payload when ``default_decision == "Quarantine"``
        # or when a specific (action, resource) is mapped to
        # ``"Quarantine"`` in ``decisions``.
        self.quarantine_payload: Optional[Dict[str, Any]] = None
        # Terminate enforcement effect — tests that want to control the
        # ``details.enforcement`` block (specific ``policy_id`` /
        # ``reason``) set this dict before calling authorize. Defaults
        # to a synthetic enforcement block when
        # ``default_decision == "Terminate"`` or when a specific
        # (action, resource) is mapped to ``"Terminate"`` in
        # ``decisions``.
        self.terminate_enforcement: Optional[Dict[str, Any]] = None
        # SeverSubtree enforcement effect — tests that want to control
        # the ``details.enforcement`` block (specific ``policy_id`` /
        # ``reason``) set this dict before calling authorize. Defaults
        # to a synthetic enforcement block when
        # ``default_decision == "SeverSubtree"`` or when a specific
        # (action, resource) is mapped to ``"SeverSubtree"`` in
        # ``decisions``.
        self.sever_enforcement: Optional[Dict[str, Any]] = None
        # Revoke enforcement effect — tests that want to control the
        # ``details.enforcement`` block (specific ``policy_id`` /
        # ``reason``) for the terminal trust-revoke verb set this to a
        # synthetic enforcement block when
        # ``default_decision == "Revoke"`` or when a specific
        # (action, resource) is mapped to ``"Revoke"`` in ``decisions``.
        self.revoke_enforcement: Optional[Dict[str, Any]] = None
        # Escalate enforcement effect (side-effect axis) — tests set this
        # to a list of ``{"policy_id", "reason"}`` dicts to inject
        # side-effect-axis escalations onto ANY decision's
        # ``details.enforcement.escalations`` (additive; never changes the
        # decision). Empty by default.
        self.escalations: List[Dict[str, Any]] = []
        # Observe enforcement effect (allow-downgrade axis) — tests set this
        # to a list of ``{"policy_id", "reason"}`` dicts to inject
        # allow-downgrade-axis observations onto ANY decision's
        # ``details.enforcement.observations`` (additive; never changes the
        # decision). Empty by default.
        self.observations: List[Dict[str, Any]] = []
        # Attenuate enforcement effect (allow-downgrade axis) — tests set
        # this to a list of ``{"policy_id", "reason", "narrowed",
        # "descendants_affected"}`` dicts to inject allow-downgrade-axis
        # attenuations onto ANY decision's
        # ``details.enforcement.attenuations`` (additive; never changes the
        # decision). Empty by default.
        self.attenuations: List[Dict[str, Any]] = []

    # --- Run table (stand-in credentials) ---------------------------------


    @property
    def default_decision(self) -> str:
        """What ``authorize()`` returns for a call no rule in ``decisions``
        names."""
        return self._default_decision

    @default_decision.setter
    def default_decision(self, value: str) -> None:
        if value not in self.KNOWN_DECISIONS:
            raise ValueError(
                f"default_decision must be one of {sorted(self.KNOWN_DECISIONS)}, got {value!r}"
            )
        self._default_decision = value

    def open_run(
        self,
        session_id: Optional[str] = None,
        agent_id: str = "",
        *,
        session_token: Optional[str] = None,
        proxy_token: Optional[str] = None,
    ) -> RunRef:
        """Register a run directly (for tests that build a handle without
        ``create_session``) and return its reference. Without an explicit
        ``session_token`` the stand-in ``<session_token_prefix>_<session_id>``
        is used."""
        session_id = session_id or f"ses_{uuid.uuid4()}"
        run = RunRef(f"run_mock_{uuid.uuid4().hex}")
        self._runs[run] = {
            "session_id": session_id,
            "agent_id": agent_id,
            "session_token": (
                session_token
                if session_token is not None
                else f"{self.session_token_prefix}_{session_id}"
            ),
            "proxy_token": proxy_token,
            "ended": False,
        }
        return run

    def token_for(self, run: Optional[str]) -> Optional[str]:
        """The stand-in run credential the mock holds for ``run``."""
        entry = self._runs.get(run) if isinstance(run, str) else None
        return entry["session_token"] if entry is not None else None

    def proxy_token_for(self, run: Optional[str]) -> Optional[str]:
        """The stand-in egress token the mock holds for ``run``."""
        entry = self._runs.get(run) if isinstance(run, str) else None
        return entry["proxy_token"] if entry is not None else None

    def session_id_for(self, run: Optional[str]) -> Optional[str]:
        entry = self._runs.get(run) if isinstance(run, str) else None
        return entry["session_id"] if entry is not None else None

    def _end(self, run: Optional[str], reason: str) -> None:
        entry = self._runs.get(run) if isinstance(run, str) else None
        if entry is None or entry["ended"]:
            return
        entry["ended"] = True
        self._kill_subs.notify(KillNotice(run=RunRef(run), reason=reason, source="backend"))

    async def drain(self, run: RunRef, timeout_s: Optional[float] = None) -> None:
        return None

    def subscribe_kill(self, run: RunRef, callback: KillCallback) -> Unsubscribe:
        entry = self._runs.get(run) if isinstance(run, str) else None
        if entry is None or entry["ended"]:
            fire_kill_callback(
                callback,
                KillNotice(
                    run=run,
                    reason="unknown_run" if entry is None else "run_ended",
                    source="backend",
                ),
            )
            return lambda: None
        return self._kill_subs.subscribe(run, callback)

    def egress_for(self, run: RunRef) -> Optional[EgressBinding]:
        entry = self._runs.get(run) if isinstance(run, str) else None
        if entry is None or entry["ended"] or not entry["proxy_token"]:
            return None

        def _token() -> Optional[str]:
            current = self._runs.get(run)
            if current is None or current["ended"]:
                return None
            return current["proxy_token"]

        return EgressBinding(proxy_url=None, expires_at=None, token_source=_token)

    # --- Lifecycle ----------------------------------------------------

    async def probe(self) -> bool:
        return self.probe_succeeds

    async def health_check(self) -> bool:
        return self.probe_succeeds

    async def close(self) -> None:
        return None

    async def resolve_agent(self, agent_slug: str) -> Optional[Dict[str, Any]]:
        uuid_str = self.known_agents.get(agent_slug)
        if uuid_str is None:
            return None
        return {"id": uuid_str, "slug": agent_slug, "name": agent_slug}

    async def create_session(
        self,
        agent_id: Optional[str] = None,
        goal_id: Optional[str] = None,
        max_actions: Optional[int] = None,
        ttl_seconds: int = 3600,
        metadata: Optional[Dict[str, Any]] = None,
        subject_token: Optional[str] = None,
        application_id: Optional[str] = None,
        declared_root: Optional[Sequence[str]] = None,
    ) -> Optional[SessionInfo]:
        # The credential-bound root, as wl-apdp decides it: no agent named
        # runs as the credential's agent; a credential bound to none is a
        # typed refusal; a named agent the credential does not match is
        # refused (opaquely: ``None``, as ``ApdpClient`` reports it).
        if agent_id is None:
            if self.credential_agent is None:
                from watchlight_core.errors import CredentialBindsNoAgent

                raise CredentialBindsNoAgent(
                    "the mock credential is not bound to one agent and the run "
                    "named none"
                )
            agent_id = self.credential_agent
        elif self.credential_agent is not None and agent_id != self.credential_agent:
            return None
        if declared_root is not None:
            self.declared_root_calls.append(list(declared_root))
            if self.declared_root_error is not None:
                raise self.declared_root_error
        session_id = f"ses_{uuid.uuid4()}"
        # Execution-lineage integrity. Surface a per-run
        # ``session_token`` and the server-minted canonical
        # ``execution_id`` so handles built through the mock carry the
        # run credential the SDK attaches on ``POST /v1/events``.
        #
        # ``application_id`` is accepted with the same signature
        # as ``ApdpClient.create_session`` — a plugin that forwards it
        # must not break against the mock — and echoed on the session
        # so a test can assert what was sent (``None`` when unset).
        run = self.open_run(
            session_id,
            agent_id,
            proxy_token=(
                f"{self.proxy_token_prefix}_{session_id}"
                if self.proxy_token_prefix
                else None
            ),
        )
        return SessionInfo(
            run=run,
            session_id=session_id,
            agent_id=agent_id,
            execution_id=f"exec_{uuid.uuid4()}",
            session=public_session_record(
                {
                    "id": session_id,
                    "agent_id": agent_id,
                    "goal_id": goal_id,
                    "max_actions": max_actions,
                    "ttl_seconds": ttl_seconds,
                    "application_id": application_id,
                }
            ),
            declared_root=declared_root is not None and self.declared_root_echo,
        )

    async def get_manifest(
        self,
        agent_id: str,
        goal_id: Optional[str] = None,
        ttl_seconds: int = 3600,
        run: Optional[RunRef] = None,
        application_id: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        # A non-None manifest puts the plugin in "strong"
        # governance mode. Tests that need the "degraded" branch
        # can swap this method.
        return {"agent_id": agent_id, "goal_id": goal_id, "policies": []}

    async def complete_session(self, run: RunRef) -> bool:
        session_id = self.session_id_for(run)
        if session_id is None:
            return False
        self._closed_sessions.append(session_id)
        self._end(run, "run_completed")
        return True

    async def terminate_session(self, run: RunRef, reason: str = "manual") -> bool:
        self._terminated_sessions.append((self.session_id_for(run), reason))
        self._end(run, "run_terminated")
        return True

    # --- Plan / preflight / authorize --------------------------------

    async def submit_plan(
        self,
        run: RunRef,
        plan: List[Dict[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        return {"validation": {"decision": "Allow", "violations": []}}

    async def preflight_step(
        self,
        run: RunRef,
        action: str,
        resource: str,
        resource_type: Optional[str] = None,
        intent: Optional[Dict[str, Any]] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        decision = self.decisions.get((action, resource), self.default_decision)
        return {"preflight": {"decision": decision}}

    async def authorize(
        self,
        principal: str,
        action: str,
        resource: str,
        context: Dict[str, Any],
        execution_id: str,
        session_id: str,
        intent: Optional[Dict[str, Any]] = None,
        run: Optional[RunRef] = None,
    ) -> Dict[str, Any]:
        # Extract the bare action / resource name from the Cedar
        # ``Action::"…"`` / ``Resource::"…"`` wrapping so the
        # decisions dict can be keyed on simple strings.
        bare_action = action.split('"')[1] if '"' in action else action
        bare_resource = resource.split('"')[1] if '"' in resource else resource
        # Record for the sub-agent governance invariant — tests can
        # assert which principal each call was made under.
        self.authorize_calls.append(
            {
                "principal": principal,
                "action": action,
                "resource": resource,
                "execution_id": execution_id,
                "session_id": session_id,
                # Record the full Cedar context so tests can assert on
                # auto-wired fields (e.g. the sub-agent
                # ``run_handle_id`` binding, tenant_id).
                "context": context,
                "intent": intent,
                "run": run,
            }
        )
        decision = self.decisions.get(
            (bare_action, bare_resource), self.default_decision
        )
        response: Dict[str, Any] = {"decision": decision, "details": {}}
        if decision == "needs_approval":
            response["details"]["escalation_required"] = True
            response["details"]["approval_request_id"] = f"appr_{uuid.uuid4()}"
        elif decision == "Quarantine":
            # Synthesise the quarantine wire shape so the SDK's
            # decision parser deserialises into a QuarantineDecision.
            # Tests that need a specific payload (different anomaly
            # score, contributing features, model version) should set
            # ``quarantine_payload`` on the mock client before calling
            # authorize.
            q = self.quarantine_payload or {
                "reason": "synthetic quarantine response",
                "anomaly_score": 0.91,
                "contributing_features": [],
                "model_version": None,
                "policy_id": "synthetic.quarantine",
            }
            response["reason"] = q.get("reason") or "synthetic quarantine"
            response["details"]["quarantine"] = q
        elif decision == "Terminate":
            # Synthesise the enforcement-effect wire shape so the SDK's
            # decision parser deserialises into a TerminateDecision.
            # Tests needing a specific policy_id / reason set
            # ``terminate_enforcement`` before calling authorize.
            enforcement = self.terminate_enforcement or {
                "effect": "terminate",
                "severity": 1,
                "reason": "policy_terminate",
                "lift_required": False,
                "policy_id": "synthetic.terminate",
            }
            response["reason"] = "synthetic terminate response"
            response["details"]["enforcement"] = enforcement
        elif decision == "SeverSubtree":
            # Synthesise the enforcement-effect wire shape so the SDK's
            # decision parser deserialises into a SeverSubtreeDecision.
            # Tests needing a specific policy_id / reason set
            # ``sever_enforcement`` before calling authorize.
            enforcement = self.sever_enforcement or {
                "effect": "sever_subtree",
                "severity": 3,
                "reason": "sever_subtree",
                "lift_required": False,
                "policy_id": "synthetic.sever_subtree",
            }
            response["reason"] = "synthetic sever_subtree response"
            response["details"]["enforcement"] = enforcement
        elif decision == "Revoke":
            # Synthesise the enforcement-effect wire shape so the SDK's
            # decision parser deserialises into a RevokeDecision. Tests
            # needing a specific policy_id / reason set
            # ``revoke_enforcement`` before calling authorize.
            enforcement = self.revoke_enforcement or {
                "effect": "revoke",
                "severity": 4,
                "reason": "revoke",
                "lift_required": True,
                "policy_id": "synthetic.revoke",
            }
            response["reason"] = "synthetic revoke response"
            response["details"]["enforcement"] = enforcement
        # Side-effect axis (Escalate): inject escalations onto
        # ``details.enforcement.escalations`` ADDITIVELY — independent of
        # the decision above (an escalation rides alongside a Deny, a
        # Quarantine, …). Never changes the decision.
        if self.escalations:
            enforcement_block = response["details"].get("enforcement")
            if not isinstance(enforcement_block, dict):
                enforcement_block = {}
            enforcement_block["escalations"] = list(self.escalations)
            response["details"]["enforcement"] = enforcement_block
        # Allow-downgrade axis (Observe): inject observations onto
        # ``details.enforcement.observations`` ADDITIVELY — independent of
        # the decision above (an observation is recorded even when a
        # co-occurring hard forbid kept the deny). Never changes the
        # decision here.
        if self.observations:
            enforcement_block = response["details"].get("enforcement")
            if not isinstance(enforcement_block, dict):
                enforcement_block = {}
            enforcement_block["observations"] = list(self.observations)
            response["details"]["enforcement"] = enforcement_block
        # Allow-downgrade axis (Attenuate): inject attenuations onto
        # ``details.enforcement.attenuations`` ADDITIVELY — independent of
        # the decision above (an attenuation is recorded even when a
        # co-occurring hard forbid kept the deny, or when it failed
        # fail-closed). Never changes the decision here.
        if self.attenuations:
            enforcement_block = response["details"].get("enforcement")
            if not isinstance(enforcement_block, dict):
                enforcement_block = {}
            enforcement_block["attenuations"] = list(self.attenuations)
            response["details"]["enforcement"] = enforcement_block
        return response

    # --- spawn_subagent ---------------------------------------------

    async def spawn_subagent(
        self,
        parent: RunRef,
        request: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Stub for the ``POST /v1/spawn_subagent`` round-trip.

        Execution-lineage integrity. ``parent`` names the PARENT run; the
        stand-in credential the mock holds for it is recorded on
        ``spawn_subagent_tokens`` so tests can assert the spawn was
        authenticated as the parent run. Like ``ApdpClient``, the child's
        stand-in credentials go into the mock's run table and the response
        carries ``child_run`` instead (an override without a
        ``child_session_token`` gets no ``child_run``, as the real client
        refuses such an approval).

        Records ``request_body`` into ``spawn_subagent_calls`` so tests
        can assert the wire shape. Returns ``spawn_response_override``
        if set; otherwise mints a default 200-OK response that mirrors
        the stub's pass-through semantics (granted_scope ==
        requested_scope; fresh ``child_run_handle_id``).

        To exercise the denial paths, set
        ``spawn_error_override`` to a
        :class:`watchlight_core.errors.ScopeAttenuationDenied` /
        :class:`RunHandleInvalidated` instance — the mock raises it
        verbatim. This mirrors how the production client surfaces the
        wire-level 403 / 404 as a typed exception.
        """
        # Record the call BEFORE side effects so tests asserting on
        # the body can run their assertions even when the mock raises.
        request_body = request
        self.spawn_subagent_calls.append(request_body)
        self.spawn_subagent_tokens.append(self.token_for(parent))

        if self.spawn_error_override is not None:
            raise self.spawn_error_override

        # Mirror wl-apdp: a spawn without the child's intent is refused.
        # The SDK refuses it locally first; this catches
        # a caller that bypassed the SDK's request builder.
        child_intent = request_body.get("child_intent")
        if not isinstance(child_intent, dict):
            from watchlight_core.errors import ScopeAttenuationDenied

            raise ScopeAttenuationDenied(
                "scope_attenuation_violation",
                [],
                reason_code="CHILD_INTENT_REQUIRED",
            )

        # Mirror wl-apdp: the requested intents are empty or exactly the
        # declared category.
        requested_intents = list(
            (request_body.get("requested_scope") or {}).get("allowed_intents") or []
        )
        if requested_intents and requested_intents != [child_intent.get("category")]:
            from watchlight_core.errors import ScopeAttenuationDenied

            raise ScopeAttenuationDenied(
                "scope_attenuation_violation",
                [],
                reason_code="INTENT_NOT_DERIVED",
            )

        if self.spawn_response_override is not None:
            return self._register_child(dict(self.spawn_response_override), request_body)

        # Default 200-OK pass-through — granted_scope equals
        # requested_scope; deadline omitted (the SDK tolerates None);
        # depth is 0.
        requested = request_body.get("requested_scope") or {}
        granted: Dict[str, Any] = {
            "allowed_tools": list(requested.get("allowed_tools") or []),
            "allowed_resources": [
                dict(r) if isinstance(r, dict) else {"matcher": str(r)}
                for r in (requested.get("allowed_resources") or [])
            ],
            # wl-apdp grants exactly the derived category.
            "allowed_intents": [child_intent.get("category")],
            "max_depth": int(requested.get("max_depth") or 0),
            "time_budget_seconds": int(
                requested.get("time_budget_seconds") or 0
            ),
            "depth": 0,
        }
        # Echo the parent_run_handle_id so the SDK has the audit-trail
        # back-pointer.
        parent_handle = request_body.get("parent_run_handle_id")
        if parent_handle is not None:
            granted["parent_run_handle_id"] = parent_handle
        # Execution-lineage integrity. Echo the child's
        # execution ids and mint a per-child ``sst_``-shaped token so the
        # child handle presents its own run credential on emission.
        child_handle_id = str(uuid.uuid4())
        child_exec = request_body.get("child_execution_id") or f"exec_{uuid.uuid4()}"
        root_exec = request_body.get("root_execution_id")
        # Execution-lineage integrity. Mirror the real
        # server: the child session id is the SERVER-derived
        # ``ses_<child-run-handle>`` and is the SINGLE value the credential
        # ``sid`` and the child's ``envelope.session_id`` share.
        child_session_id = f"ses_{child_handle_id}"
        # Who the child runs as, as wl-apdp decides it: the named agent;
        # else the agent its label is mapped to; else its parent's agent.
        label = request_body.get("child_label")
        if request_body.get("child_agent_id"):
            child_agent = str(request_body["child_agent_id"])
            identity = "registered"
        elif label is not None and label in self.subagent_label_map:
            child_agent = self.subagent_label_map[label]
            identity = "mapped"
        else:
            child_agent = str(request_body.get("parent_agent_id") or "")
            identity = "anonymous"
        response: Dict[str, Any] = {
            "child_run_handle_id": child_handle_id,
            "child_agent_id": child_agent,
            "child_identity": identity,
            "granted_scope": granted,
            "child_execution_id": child_exec,
            "root_execution_id": root_exec,
            "child_session_id": child_session_id,
            "child_session_token": f"{self.session_token_prefix}_child_{child_handle_id}",
            # What wl-apdp returns for a validated derivation. The stand-in
            # does not check the category against a parent bound.
            "derived_intent": {
                "intent_category": child_intent.get("category"),
                "objective": child_intent.get("objective"),
                **(
                    {"max_actions": child_intent["max_actions"]}
                    if child_intent.get("max_actions") is not None
                    else {}
                ),
                "parent_intent_categories": [],
                "sub_goal_id": str(uuid.uuid4()),
                "provenance": "plugin_derived",
            },
        }
        if label is not None:
            response["child_label"] = label
        # When proxy tokens are on, the child session gets its OWN
        # egress token, as the real server mints at spawn.
        if self.proxy_token_prefix:
            response["child_proxy_token"] = (
                f"{self.proxy_token_prefix}_child_{child_handle_id}"
            )
        return self._register_child(response, request_body)

    def _register_child(
        self, response: Dict[str, Any], request_body: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Move a wire-shaped response's child credentials into the run
        table and add ``child_run`` (the shape every backend returns)."""
        token = response.pop("child_session_token", None)
        proxy = response.pop("child_proxy_token", None)
        response.pop("child_proxy_token_expires_at", None)
        handle = response.get("child_run_handle_id")
        if token and handle is not None and "child_run" not in response:
            response["child_run"] = self.open_run(
                response.get("child_session_id") or f"ses_{handle}",
                str(
                    response.get("child_agent_id")
                    or request_body.get("child_agent_id")
                    or ""
                ),
                session_token=token,
                proxy_token=proxy if isinstance(proxy, str) and proxy else None,
            )
        return response

    # --- Events -------------------------------------------------------

    async def publish_events(
        self,
        run: Optional[RunRef],
        events: List[Dict[str, Any]],
    ) -> bool:
        """Capture events for assertions and return ``True``.

        Mirrors :meth:`ApdpClient.publish_events` which returns
        ``True`` on accepted publish and ``False`` on transport
        failure. Tests that want to simulate a publish failure can
        monkey-patch this method on the mock instance.

        Execution-lineage integrity. Records the stand-in run credential
        of the run the SDK named alongside the batch in
        ``published_event_batches`` so tests can assert each batch went
        out under its own run.
        """
        self.published_events.extend(events)
        self.published_event_batches.append((self.token_for(run), list(events)))
        return True


# ─── Test runs (stand-in credentials behind a RunRef) ──────────────────


def register_test_run(
    backend: Any,
    session_token: Optional[str],
    session_id: Optional[str] = None,
    *,
    agent_id: str = "agent",
    proxy_token: Optional[str] = None,
) -> RunRef:
    """The :data:`~watchlight_core.backend.RunRef` under which ``backend``
    holds the stand-in run credential ``session_token`` (registered on first
    use; the same token on the same backend gives the same run). For tests
    only: production runs are opened by the backend itself.

    Works for :class:`~watchlight_core.ApdpClient` and
    :class:`MockApdpClient`; any other backend (a ``MagicMock``) gets a
    plain reference it can record."""
    cache = backend.__dict__.setdefault("_wl_test_runs", {})
    key = (session_token, proxy_token)
    if key in cache:
        return cache[key]
    sid = session_id or f"ses_{uuid.uuid4()}"
    if isinstance(backend, MockApdpClient):
        run = backend.open_run(
            sid, agent_id, session_token=session_token, proxy_token=proxy_token
        )
    elif callable(getattr(type(backend), "_register_run", None)):
        run = backend._register_run(
            session_id=sid,
            agent_id=agent_id,
            session_token=session_token,
            proxy_token=proxy_token,
        )
    else:
        run = RunRef(f"run_test_{uuid.uuid4().hex}")
    cache[key] = run
    return run


def stub_session_info(
    backend: Any,
    session_id: str,
    *,
    session_token: Optional[str] = None,
    proxy_token: Optional[str] = None,
    execution_id: Optional[str] = None,
    root_run_handle_id: Optional[str] = None,
    agent_id: str = "agent",
    session: Optional[Dict[str, Any]] = None,
) -> SessionInfo:
    """A :class:`~watchlight_core.backend.SessionInfo` for a test that stubs
    ``create_session``: a fresh run whose stand-in credentials ``backend``
    holds (an :class:`~watchlight_core.ApdpClient` or :class:`MockApdpClient`
    run table; any other backend just gets the reference). For tests only.

    It cannot build an uncredentialed run for an
    :class:`~watchlight_core.ApdpClient`, which never registers one: with
    no ``session_token`` it registers a stand-in credential instead."""
    if isinstance(backend, MockApdpClient):
        run = backend.open_run(
            session_id, agent_id, session_token=session_token, proxy_token=proxy_token
        )
    elif callable(getattr(type(backend), "_register_run", None)):
        # A real backend never registers a run without a run credential, so
        # a test that names none gets a stand-in one.
        run = backend._register_run(
            session_id=session_id,
            agent_id=agent_id,
            session_token=session_token or f"sst_stand_in_{uuid.uuid4().hex}",
            proxy_token=proxy_token,
        )
    else:
        run = RunRef(f"run_test_{uuid.uuid4().hex}")
    return SessionInfo(
        run=run,
        session_id=session_id,
        agent_id=agent_id,
        execution_id=execution_id,
        root_run_handle_id=root_run_handle_id,
        session=public_session_record(session if session is not None else {"id": session_id}),
    )


def bind_test_run(
    handle: BaseRunHandle,
    session_token: Optional[str],
    *,
    proxy_token: Optional[str] = None,
) -> BaseRunHandle:
    """Give a directly-constructed test handle a run whose stand-in
    credentials its plugin's backend holds (see :func:`register_test_run`),
    plus that run's egress binding. Returns the handle."""
    from watchlight_core.backend import egress_binding_for

    backend = handle._plugin.apdp
    handle.run = register_test_run(
        backend,
        session_token,
        handle.session_id,
        agent_id=str(handle.agent_uuid),
        proxy_token=proxy_token,
    )
    handle.egress = egress_binding_for(backend, handle.run)
    return handle


# ─── Event capture context manager ────────────────────────────────────


@asynccontextmanager
async def capture_events(
    client: MockApdpClient,
) -> AsyncIterator[List[Dict[str, Any]]]:
    """Async context manager that resets the mock client's published
    events buffer on entry and yields the buffer for inspection on
    exit.

    Example:

    .. code-block:: python

        client = MockApdpClient()
        async with capture_events(client) as events:
            # ... run plugin code that emits events ...
            pass
        assert any(e["event_type"] == "tool_call_observed" for e in events)
    """
    client.published_events.clear()
    yield client.published_events


# ─── Synthetic RunHandle ──────────────────────────────────────────────


def stub_session() -> Dict[str, Any]:
    """One-shot synthetic session dict. Useful for tests that
    construct a :class:`BaseRunHandle` directly without going
    through ``plugin.start_run()``. In-process stand-in for unit
    tests only.
    """
    return {
        "id": f"ses_{uuid.uuid4()}",
        "agent_id": f"agent-{uuid.uuid4().hex[:8]}",
        "max_actions": 100,
        "ttl_seconds": 3600,
    }


def stub_handle(
    plugin: Any,
    agent_uuid: Optional[str] = None,
    session_id: Optional[str] = None,
) -> BaseRunHandle:
    """Construct a synthetic :class:`BaseRunHandle` bound to the
    given plugin. Bypasses ``start_run()`` for tests that don't
    need to exercise session resolution. In-process stand-in for
    unit tests only — never wire it into production code.

    The plugin SHOULD already have its ``apdp`` attribute set to
    a :class:`MockApdpClient` instance.

    Example:

    .. code-block:: python

        plugin = WatchlightMyFrameworkPlugin(apdp_url="http://stub")
        plugin.apdp = MockApdpClient()
        handle = stub_handle(plugin)
        assert await handle.authorize_action("execute", "noop")
    """
    agent_uuid = agent_uuid or f"uuid-{uuid.uuid4().hex[:8]}"
    session_id = session_id or f"ses_{uuid.uuid4()}"
    backend = getattr(plugin, "apdp", None)
    run = (
        backend.open_run(session_id, agent_uuid)
        if isinstance(backend, MockApdpClient)
        else None
    )
    handle = BaseRunHandle(
        plugin=plugin,
        agent_uuid=agent_uuid,
        session_id=session_id,
        run=run,
    )
    # Synthetic test handle bypasses the production
    # ``async with`` entry path. Flip the fail-closed flag so the
    # lineage contract guard in ``authorize_action_detailed`` /
    # ``publish_observation`` accepts the test's direct calls. Real
    # customer code MUST go through the ``async with`` block; tests
    # that explicitly want to assert the refusal path can flip the
    # flag back to ``False`` after construction.
    handle._aentered = True
    return handle


# ─── Conformance assertion (single event) ─────────────────────────────


class ConformanceFailure(AssertionError):
    """Raised by :func:`assert_canonical_event` when an event
    violates one of the seven conformance invariants. The
    exception's ``args`` is a tuple of (invariant_number, reason).
    """


_REQUIRED_ENVELOPE_FIELDS = frozenset(
    {"event_id", "event_type", "timestamp", "execution_id", "agent_id", "payload"}
)

_OPTIONAL_ENVELOPE_FIELDS = frozenset(
    {
        "parent_execution_id",
        "root_execution_id",
        "parent_agent_id",
        "session_id",
        "request_id",
        "tenant_id",
        "metadata",
    }
)

_CANONICAL_EVENT_TYPES = frozenset(e.value for e in EventType)


def assert_canonical_event(
    event: Dict[str, Any],
    *,
    expected_source: Optional[str] = None,
    expected_uri_prefix: Optional[str] = None,
) -> None:
    """Assert that ``event`` satisfies the seven conformance
    invariants.

    Plugin authors call this in their test suites:

    .. code-block:: python

        async with capture_events(client) as events:
            await plugin_emit_one_tool_call(...)
        for ev in events:
            assert_canonical_event(
                ev,
                expected_source="myframework.callback",
                expected_uri_prefix="myframework://",
            )

    Raises :class:`ConformanceFailure` on the first invariant
    violation; passes silently when all seven hold.
    """
    # Invariant 1 — envelope shape
    missing = _REQUIRED_ENVELOPE_FIELDS - event.keys()
    if missing:
        raise ConformanceFailure(1, f"missing required envelope fields: {missing}")

    # Invariant 7 — closed-set top-level keys (checked here because
    # it's part of the envelope-shape contract)
    allowed = _REQUIRED_ENVELOPE_FIELDS | _OPTIONAL_ENVELOPE_FIELDS
    unknown = event.keys() - allowed
    if unknown:
        raise ConformanceFailure(
            7, f"unknown top-level keys (closed-set violation): {unknown}"
        )

    # Invariant 5 — event_id format
    if not EVENT_ID_RE.match(event["event_id"]):
        raise ConformanceFailure(
            5, f"event_id {event['event_id']!r} does not match evt_<uuid>"
        )

    # Invariant 3 — canonical event types
    if event["event_type"] not in _CANONICAL_EVENT_TYPES:
        raise ConformanceFailure(
            3,
            f"event_type {event['event_type']!r} is not in the canonical set "
            f"({sorted(_CANONICAL_EVENT_TYPES)})",
        )

    # Invariant 2 — source attribution
    metadata = event.get("metadata") or {}
    source = metadata.get("source") if isinstance(metadata, dict) else None
    if expected_source is not None and source != expected_source:
        raise ConformanceFailure(
            2,
            f"metadata.source {source!r} does not match expected "
            f"{expected_source!r}",
        )
    if source is None:
        raise ConformanceFailure(2, "metadata.source is missing")

    # Invariant 4 — resource URI namespacing (only on
    # tool_call_observed; other event types don't carry a tool ref)
    if event["event_type"] == "tool_call_observed":
        payload = event.get("payload") or {}
        tool = payload.get("tool") or {}
        uri = tool.get("endpoint") or tool.get("resource")
        if expected_uri_prefix is not None:
            if not isinstance(uri, str) or not uri.startswith(expected_uri_prefix):
                raise ConformanceFailure(
                    4,
                    f"tool URI {uri!r} does not start with expected prefix "
                    f"{expected_uri_prefix!r}",
                )

    # Invariant 6 — bounded sizes
    payload = event.get("payload") or {}
    if event["event_type"] == "tool_call_observed":
        summary = payload.get("input_summary")
        if isinstance(summary, str) and len(summary) > INPUT_SUMMARY_MAX_CHARS:
            raise ConformanceFailure(
                6,
                f"input_summary length {len(summary)} exceeds cap "
                f"{INPUT_SUMMARY_MAX_CHARS}",
            )
    if event["event_type"] == "execution_failed":
        err = payload.get("error")
        if isinstance(err, str) and len(err) > ERROR_MESSAGE_MAX_CHARS:
            raise ConformanceFailure(
                6,
                f"error length {len(err)} exceeds cap {ERROR_MESSAGE_MAX_CHARS}",
            )
    if event["event_type"] == "plan_observed":
        tools = payload.get("intended_tools") or []
        if len(tools) > PLAN_INTENDED_TOOLS_MAX:
            raise ConformanceFailure(
                6,
                f"intended_tools length {len(tools)} exceeds cap "
                f"{PLAN_INTENDED_TOOLS_MAX}",
            )
        for name in tools:
            if not isinstance(name, str) or not PLAN_TOOL_NAME_RE.match(name):
                raise ConformanceFailure(
                    6, f"intended_tools entry {name!r} fails the tool-name pattern"
                )
        rationale = payload.get("rationale")
        if isinstance(rationale, str):
            byte_len = len(rationale.encode("utf-8"))
            if byte_len > PLAN_RATIONALE_MAX_BYTES:
                raise ConformanceFailure(
                    6,
                    f"rationale byte-length {byte_len} exceeds cap "
                    f"{PLAN_RATIONALE_MAX_BYTES}",
                )

    # Invariant 16 — the payload matches the canonical struct its
    # event_type selects. Last, so the earlier, more specific
    # invariants report first.
    assert_payload_matches_schema(event)


def assert_payload_matches_schema(event: Dict[str, Any]) -> None:
    """Assert conformance invariant 16 — ``payload`` deserializes into
    the canonical payload struct ``event_type`` selects, and carries no
    key that struct does not model.

    This is the check that pins the SERVER contract. It covers two
    distinct failure modes, and BOTH are failures.

    **The payload does not deserialize.** wl-apdp's
    ``POST /v1/events`` dispatches on the envelope's ``event_type`` and
    decodes the payload as that type's struct, failing closed on a
    mismatch (``422 Failed to deserialize the JSON body into the target
    type: data did not match any variant of untagged enum
    IngestExecutionEventsRequest``). One malformed event rejects the
    WHOLE batch, and because lineage publish failures are fail-open by
    design, the run just disappears from the execution-lineage view with
    nothing surfaced to the operator. Typical violations:

    * ``{"principal": {"agent_id": ...}}`` or
      ``{"principal": {"principal": "Agent::\\"...\\""}}`` instead of the
      canonical ``PrincipalRef`` (``principal_type`` + ``id``);
    * a flattened ``{"tool": {"resource": "<uri>"}}`` instead of a
      ``ResourceRef`` (``resource_type`` + ``identifier``
      [+ ``endpoint``]).

    **The payload carries a key the struct does not model.** Rust's
    payload structs do NOT set ``deny_unknown_fields``, so this one is
    not rejected at all: serde accepts the event and drops the key on
    the floor. That is worse than a rejection, not better — nothing
    surfaces anywhere, and a consumer written against the key reads
    nothing forever. That happened once: two plugins put ``depth``
    and ``spawned_by_agent_id`` on an ``execution_completed`` payload,
    the dashboard timeline composed "depth N, spawned by Y" from them,
    and neither value ever existed. Silent data loss on an audit record
    is not the lesser bug, so this raises rather than warns.

    Either way the emitter is the only place this can be caught, and it
    has to be caught loudly.

    Raises:
        ConformanceFailure: invariant 16, naming the event type and the
            offending field.
    """
    event_type = event.get("event_type")
    payload = event.get("payload")
    try:
        validate_event_payload(event_type, payload)
    except PayloadSchemaError as exc:
        raise ConformanceFailure(
            16,
            f"event_type {event_type!r} payload does not match the canonical "
            f"struct wl-apdp /v1/events decodes it as — wl-apdp would reject "
            f"the WHOLE batch with 422 and the run would never appear in "
            f"lineage: {exc}",
        ) from exc
    dropped = unknown_payload_keys(event_type, payload)
    if dropped:
        raise ConformanceFailure(
            16,
            f"event_type {event_type!r} payload carries key(s) the server "
            f"does not model: {', '.join(dropped)}. serde DROPS them "
            f"silently — the values never reach lineage and any consumer "
            f"reading them sees nothing. Add the field to the canonical "
            f"struct in the wl-lineage event schema (and its mirror in "
            f"watchlight_core.events_schema), emit the fact on the canonical "
            f"field that already models it, or move it under the envelope's "
            f"`metadata`, which does round-trip.",
        )


# Re-exported for plugin-author convenience — they don't have to
# also import these from `errors`.
__all__ += ["AgentNotRegistered", "GovernanceUnavailable"]


# ─── Re-export helpers ────────────────────────────────────────────────
# (Imports kept at top; this block is just a marker so static analysis
# tools don't flag the re-exports above as unused.)
_ = (AgentNotRegistered, GovernanceUnavailable, datetime, timezone)
