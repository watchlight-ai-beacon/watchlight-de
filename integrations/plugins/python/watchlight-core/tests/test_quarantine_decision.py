"""Tests for the Quarantine decision wiring through ``BaseRunHandle``.

These tests pin down the load-bearing security invariant of the
quarantine effect from the Python SDK side:

- The wl-apdp Quarantine wire shape deserialises into a
  typed :class:`QuarantineDecision`.
- A Quarantine response transitions the handle to
  :class:`RunHandleState.QUARANTINED` and raises
  :class:`AgentQuarantinedError`.
- Every subsequent ``authorize_action`` / ``spawn_subagent`` call
  short-circuits — it raises :class:`AgentQuarantinedError` WITHOUT
  round-tripping to wl-apdp. Test #3 is the load-bearing assertion
  on the call counter; test #8 is the load-bearing assertion on
  parent-chain propagation across goals (locked decision #2:
  "quarantine state DOES cross goals").
- Lifecycle methods (``complete`` / ``terminate``) handle the
  QUARANTINED terminal state without silently treating it as a
  clean completion.
- The error message includes the top-3 contributors so operators
  reading the customer's stack trace see why.
- Legacy Allow/Deny responses are unaffected (regression coverage
  on the discriminated-union refactor).
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock

import pytest
import pytest_asyncio

from watchlight_core import (
    AgentQuarantinedError,
    AllowDecision,
    ApdpClient,
    BaseRunHandle,
    DenyDecision,
    FeatureContribution,
    NeedsApprovalDecision,
    QuarantineDecision,
    RunHandleState,
    parse_authorization_decision,
)
from watchlight_core.telemetry import GovernanceTelemetry
from watchlight_core_testing import MockApdpClient
from watchlight_core_testing import bind_test_run


# ─── Plugin fixture ──────────────────────────────────────────────────


@pytest.fixture
def plugin() -> Any:
    """A minimal plugin satisfying the GovernedPlugin Protocol.

    Uses :class:`MockApdpClient` so we can drive Quarantine
    responses + assert on call counts.
    """

    class Plugin(GovernanceTelemetry):
        def __init__(self) -> None:
            super().__init__()
            self.apdp = MockApdpClient()
            self.apdp.known_agents["agent-x"] = "uuid-x"
            self.tenant_id = "tenant-acme"
            self.log_decisions = False

    return Plugin()


@pytest_asyncio.fixture
async def handle(plugin: Any) -> BaseRunHandle:
    h = bind_test_run(
        BaseRunHandle(plugin=plugin, agent_uuid="uuid-x", session_id="ses_x"),
        "sst_x.sig",
    )
    # flip the contract-guard flag; the synthetic test handle bypasses
    # the production ``async with`` entry path.
    h._aentered = True
    return h


def _quarantine_wire_payload() -> dict:
    """The exact wire shape emitted on Quarantine."""
    return {
        "decision": "Quarantine",
        "reason": "Agent quarantined by policy forbid-q (anomaly_score=0.910)",
        "details": {
            "quarantine": {
                "reason": "tool_diversity exceeded baseline_p95 by 4x",
                "anomaly_score": 0.91,
                "contributing_features": [
                    {
                        "name": "tool_diversity",
                        "value": 12.0,
                        "baseline_median": 3.0,
                        "baseline_p95": 6.0,
                        "contribution": 0.42,
                    },
                    {
                        "name": "actions_denied",
                        "value": 8.0,
                        "baseline_median": 0.0,
                        "baseline_p95": 2.0,
                        "contribution": 0.31,
                    },
                    {
                        "name": "auth_failures",
                        "value": 4.0,
                        "baseline_median": 0.0,
                        "baseline_p95": 1.0,
                        "contribution": 0.18,
                    },
                ],
                "model_version": "11111111-2222-3333-4444-555555555555",
                "policy_id": "forbid-quarantined-agent-all-actions",
            },
        },
    }


# ─── Test 1 — parse Quarantine wire shape ─────────────────────────────


def test_parse_quarantine_decision_from_apdp_response() -> None:
    """The wl-apdp Quarantine wire shape deserialises into a
    typed :class:`QuarantineDecision` with every field populated.
    """
    decision = parse_authorization_decision(_quarantine_wire_payload())

    assert isinstance(decision, QuarantineDecision)
    assert decision.kind == "quarantine"
    assert decision.policy_id == "forbid-quarantined-agent-all-actions"
    assert decision.anomaly_score == pytest.approx(0.91)
    assert decision.model_version == "11111111-2222-3333-4444-555555555555"
    assert decision.reason.startswith("tool_diversity exceeded")
    assert len(decision.contributing_features) == 3
    top = decision.contributing_features[0]
    assert isinstance(top, FeatureContribution)
    assert top.name == "tool_diversity"
    assert top.value == pytest.approx(12.0)
    assert top.baseline_p95 == pytest.approx(6.0)
    assert top.contribution == pytest.approx(0.42)


# ─── Test 2 — authorize_action raises on Quarantine response ─────────


@pytest.mark.asyncio
async def test_authorize_action_raises_quarantined_error_on_quarantine_response(
    plugin: Any, handle: BaseRunHandle
) -> None:
    """When wl-apdp returns Quarantine, the handle transitions to
    QUARANTINED, the plugin counters reflect the denial, and
    :class:`AgentQuarantinedError` is raised on the originating call.
    """
    plugin.apdp.default_decision = "Quarantine"
    plugin.apdp.quarantine_payload = _quarantine_wire_payload()["details"]["quarantine"]

    assert handle.state == RunHandleState.ACTIVE

    with pytest.raises(AgentQuarantinedError) as excinfo:
        await handle.authorize_action("execute", "Tool::scanner")

    err = excinfo.value
    assert err.policy_id == "forbid-quarantined-agent-all-actions"
    assert err.anomaly_score == pytest.approx(0.91)
    assert err.model_version == "11111111-2222-3333-4444-555555555555"
    assert len(err.contributing_features) == 3

    assert handle.state == RunHandleState.QUARANTINED
    assert handle.is_quarantined is True
    assert handle.quarantine_decision is not None
    assert handle.quarantine_decision.policy_id == "forbid-quarantined-agent-all-actions"
    assert plugin.last_actions_denied == 1
    assert plugin.last_actions_allowed == 0


# ─── Test 3 — subsequent calls short-circuit (load-bearing) ──────────


@pytest.mark.asyncio
async def test_subsequent_authorize_calls_short_circuit_without_apdp(
    plugin: Any, handle: BaseRunHandle
) -> None:
    """**Load-bearing test for the quarantine kill-switch semantics.**

    After the handle is quarantined, five more ``authorize_action``
    calls all raise :class:`AgentQuarantinedError` AND the
    ``MockApdpClient.authorize_calls`` counter MUST NOT advance.

    A regression here would let a quarantined agent silently regain
    Allow decisions whenever the wl-apdp anomaly cache is cleared
    (transient connectivity blip, APDP restart, operator-misclick).
    The SDK is the last line of defence — it cannot fall through.
    """
    plugin.apdp.default_decision = "Quarantine"
    plugin.apdp.quarantine_payload = _quarantine_wire_payload()["details"]["quarantine"]

    # First call — Quarantine response, handle transitions.
    with pytest.raises(AgentQuarantinedError):
        await handle.authorize_action("execute", "Tool::a")
    assert handle.state == RunHandleState.QUARANTINED

    baseline_calls = len(plugin.apdp.authorize_calls)
    assert baseline_calls == 1

    # 5 more calls — all raise, none round-trip.
    for i in range(5):
        with pytest.raises(AgentQuarantinedError):
            await handle.authorize_action(f"execute_{i}", f"Tool::r_{i}")
        assert len(plugin.apdp.authorize_calls) == baseline_calls, (
            f"authorize call #{i + 2} on a QUARANTINED handle round-tripped "
            f"to wl-apdp (authorize_calls advanced)"
        )

    # Counters reflect every denied attempt.
    assert plugin.last_actions_denied == 6
    assert plugin.last_actions_allowed == 0


# ─── Test 4 — spawn_subagent on a quarantined handle raises ───────────


@pytest.mark.asyncio
async def test_quarantine_state_persists_across_method_calls(
    plugin: Any, handle: BaseRunHandle
) -> None:
    """``spawn_subagent`` on a quarantined handle raises
    :class:`AgentQuarantinedError` without round-tripping to wl-apdp.
    A quarantined agent has no authority to delegate.
    """
    plugin.apdp.default_decision = "Quarantine"
    plugin.apdp.quarantine_payload = _quarantine_wire_payload()["details"]["quarantine"]

    with pytest.raises(AgentQuarantinedError):
        await handle.authorize_action("execute", "Tool::a")
    assert handle.state == RunHandleState.QUARANTINED

    baseline = len(plugin.apdp.authorize_calls)
    # spawn_subagent uses the kwargs-only canonical signature; the
    # quarantine short-circuit fires before any APDP round-trip so a
    # valid UUID for the child is the only positional requirement.
    with pytest.raises(AgentQuarantinedError):
        await handle.spawn_subagent(
            "11111111-1111-1111-1111-111111111111",
        child_intent={"category": "research", "objective": "Delegated sub-task"},
        )
    # spawn must not trigger any wl-apdp authorize round-trip.
    assert len(plugin.apdp.authorize_calls) == baseline


# ─── Test 5 — complete after quarantine emits quarantined status ─────


@pytest.mark.asyncio
async def test_complete_after_quarantine_emits_quarantined_status(
    plugin: Any, handle: BaseRunHandle
) -> None:
    """``complete()`` on a quarantined handle emits an
    ``execution_completed`` event whose ``payload.outcome`` is
    ``"quarantined"`` and whose ``metadata.quarantine`` carries the
    same anomaly payload the ``execution_quarantined`` event did.
    The APDP session is still closed (complete_session is called).
    """
    plugin.apdp.default_decision = "Quarantine"
    plugin.apdp.quarantine_payload = _quarantine_wire_payload()["details"]["quarantine"]

    with pytest.raises(AgentQuarantinedError):
        await handle.authorize_action("execute", "Tool::a")

    plugin.apdp.published_events.clear()
    await handle.complete()

    completion_events = [
        e
        for e in plugin.apdp.published_events
        if e["event_type"] == "execution_completed"
    ]
    assert len(completion_events) == 1, (
        f"expected exactly one execution_completed event, got "
        f"{[e['event_type'] for e in plugin.apdp.published_events]}"
    )
    completion = completion_events[0]
    assert completion["payload"]["outcome"] == "quarantined"
    assert completion["metadata"]["quarantine"]["policy_id"] == (
        "forbid-quarantined-agent-all-actions"
    )
    assert completion["metadata"]["quarantine"]["anomaly_score"] == pytest.approx(0.91)
    assert plugin.apdp._closed_sessions == ["ses_x"]  # noqa: SLF001
    # Re-completing is idempotent.
    plugin.apdp.published_events.clear()
    await handle.complete()
    assert plugin.apdp.published_events == []


# ─── Test 6 — terminate after quarantine is a no-op ───────────────────


@pytest.mark.asyncio
async def test_terminate_after_quarantine_is_noop(
    plugin: Any, handle: BaseRunHandle
) -> None:
    """``terminate()`` on a quarantined handle is a no-op — no
    APDP ``/terminate`` round-trip and no events emitted (the
    ``execution_quarantined`` event already captured the terminal
    state).
    """
    plugin.apdp.default_decision = "Quarantine"
    plugin.apdp.quarantine_payload = _quarantine_wire_payload()["details"]["quarantine"]

    with pytest.raises(AgentQuarantinedError):
        await handle.authorize_action("execute", "Tool::a")

    plugin.apdp.published_events.clear()
    await handle.terminate(reason="customer_canceled")

    # No terminate call, no further events.
    assert plugin.apdp._terminated_sessions == []  # noqa: SLF001
    terminate_events = [
        e
        for e in plugin.apdp.published_events
        if e["event_type"] == "execution_completed"
        or e["event_type"] == "execution_failed"
    ]
    assert terminate_events == []
    # Idempotent: a follow-up terminate is also a no-op.
    await handle.terminate(reason="again")
    assert plugin.apdp._terminated_sessions == []  # noqa: SLF001


# ─── Test 7 — error message format ────────────────────────────────────


def test_agent_quarantined_error_message_is_opaque() -> None:
    """The message carries no reason, contributor, policy id or score (it
    can reach the model through a framework's tool-error path); the
    detail stays on the attributes for operator code."""
    contribs = [
        FeatureContribution(
            name="tool_diversity",
            value=12.0,
            baseline_median=3.0,
            baseline_p95=6.0,
            contribution=0.42,
        ),
        FeatureContribution(
            name="actions_denied",
            value=8.0,
            baseline_median=0.0,
            baseline_p95=2.0,
            contribution=0.31,
        ),
        FeatureContribution(
            name="auth_failures",
            value=4.0,
            baseline_median=0.0,
            baseline_p95=1.0,
            contribution=0.18,
        ),
    ]
    err = AgentQuarantinedError(
        reason="behaviour deviates from baseline",
        anomaly_score=0.92,
        contributing_features=contribs,
        model_version="11111111-2222-3333-4444-555555555555",
        policy_id="forbid-quarantined-agent-all-actions",
    )
    msg = str(err)
    assert "Agent quarantined" in msg
    for detail in (
        "behaviour deviates from baseline",
        "tool_diversity",
        "forbid-quarantined-agent-all-actions",
        "0.92",
    ):
        assert detail not in msg
    assert err.reason == "behaviour deviates from baseline"
    assert err.policy_id == "forbid-quarantined-agent-all-actions"
    assert err.anomaly_score == 0.92


# ─── Test 8 — parent-chain propagation (load-bearing) ─────────────────


@pytest.mark.asyncio
async def test_quarantine_propagates_up_parent_chain(plugin: Any) -> None:
    """**Load-bearing test for locked decision #2 — quarantine
    crosses goals.**

    A sub-agent's handle quarantining MUST flip the parent's handle
    to QUARANTINED too. Calling ``authorize_action`` on the parent
    after the child's quarantine raises :class:`AgentQuarantinedError`
    without round-tripping to wl-apdp.

    This is the "bag the agent, not the goal" invariant — one
    misbehaving goal taints the whole agent.
    """
    # spawn_subagent requires valid UUIDs on the wire (the
    # SpawnSubagentRequest envelope). The construction of the test
    # root handle therefore uses canonical UUID strings; the
    # behavioural assertion (parent-chain quarantine propagation) is
    # independent of the identity format.
    root_uuid = "00000000-0000-0000-0000-0000000000a1"
    child_uuid = "00000000-0000-0000-0000-0000000000a2"
    root = BaseRunHandle(
        plugin=plugin, agent_uuid=root_uuid, session_id="ses_root",
    )
    root._aentered = True  # synthetic test handle
    child = await root.spawn_subagent(child_uuid, child_intent={"category": "research", "objective": "Delegated sub-task"})
    # ``spawn_subagent`` already sets ``_aentered = True`` on the
    # child; explicit assertion below documents the invariant.
    assert child._aentered, "spawn_subagent must enter the child handle"

    assert root.state == RunHandleState.ACTIVE
    assert child.state == RunHandleState.ACTIVE

    plugin.apdp.default_decision = "Quarantine"
    plugin.apdp.quarantine_payload = _quarantine_wire_payload()["details"]["quarantine"]

    # Child quarantines on its first authorize_action.
    with pytest.raises(AgentQuarantinedError):
        await child.authorize_action("execute", "Tool::child_action")

    assert child.state == RunHandleState.QUARANTINED
    # The kill switch crosses goals — the root inherits QUARANTINED.
    assert root.state == RunHandleState.QUARANTINED, (
        "parent handle did not propagate to QUARANTINED — the bagged-agent "
        "invariant from locked decision #2 is broken"
    )
    assert root.quarantine_decision is not None
    assert (
        root.quarantine_decision.policy_id
        == "forbid-quarantined-agent-all-actions"
    )

    # And the parent's subsequent authorize_action short-circuits.
    baseline_calls = len(plugin.apdp.authorize_calls)
    with pytest.raises(AgentQuarantinedError):
        await root.authorize_action("execute", "Tool::root_action")
    assert len(plugin.apdp.authorize_calls) == baseline_calls, (
        "parent's authorize_action after child quarantine round-tripped to "
        "wl-apdp — short-circuit invariant violated on the parent handle"
    )

    # Allow any scheduled background emit on the parent to flush
    # before we move on (best-effort observability).
    await asyncio.sleep(0)


# ─── Test 9 — backward-compat regression on Allow/Deny ────────────────


@pytest.mark.asyncio
async def test_legacy_allow_deny_responses_still_work(
    plugin: Any, handle: BaseRunHandle
) -> None:
    """Legacy Allow/Deny/needs_approval responses parse into the
    expected variants of the discriminated union and exercise the
    existing :class:`AuthorizeResult` collapsed-bool path identically
    to v0.4.0.
    """
    # Allow
    allow = parse_authorization_decision({"decision": "Allow"})
    assert isinstance(allow, AllowDecision)
    assert allow.kind == "allow"

    # Deny
    deny = parse_authorization_decision({"decision": "Deny", "reason": "no"})
    assert isinstance(deny, DenyDecision)
    assert deny.kind == "deny"
    assert deny.reason == "no"

    # needs_approval (Deny + escalation_required + approval_request_id)
    na = parse_authorization_decision(
        {
            "decision": "Deny",
            "reason": "human approval required",
            "details": {
                "escalation_required": True,
                "approval_request_id": "appr_12345",
            },
        }
    )
    assert isinstance(na, NeedsApprovalDecision)
    assert na.approval_request_id == "appr_12345"

    # Unknown decision → fail-closed Deny.
    unknown = parse_authorization_decision({"decision": "WhatNow"})
    assert isinstance(unknown, DenyDecision)

    # And the integration path through BaseRunHandle is unchanged.
    plugin.apdp.default_decision = "Allow"
    ok = await handle.authorize_action("execute", "Tool::x")
    assert ok is True
    assert plugin.last_actions_allowed == 1
    assert handle.state == RunHandleState.ACTIVE

    plugin.apdp.default_decision = "Deny"
    ok = await handle.authorize_action("execute", "Tool::y")
    assert ok is False
    assert plugin.last_actions_denied == 1
    assert handle.state == RunHandleState.ACTIVE  # Deny does NOT quarantine


# ─── Test 10 — execution_quarantined event emission ───────────────────


@pytest.mark.asyncio
async def test_execution_quarantined_event_is_emitted(
    plugin: Any, handle: BaseRunHandle
) -> None:
    """When the handle transitions to QUARANTINED, an
    ``execution_quarantined`` event is published carrying the
    payload shape. The audit trail captures the transition even
    though customer code only sees the raised error.
    """
    plugin.apdp.default_decision = "Quarantine"
    plugin.apdp.quarantine_payload = _quarantine_wire_payload()["details"]["quarantine"]

    with pytest.raises(AgentQuarantinedError):
        await handle.authorize_action("execute", "Tool::a")

    quarantine_events = [
        e
        for e in plugin.apdp.published_events
        if e["event_type"] == "execution_quarantined"
    ]
    assert len(quarantine_events) == 1, (
        f"expected exactly one execution_quarantined event, got "
        f"{[e['event_type'] for e in plugin.apdp.published_events]}"
    )
    ev = quarantine_events[0]
    assert ev["agent_id"] == "uuid-x"
    assert ev["session_id"] == "ses_x"
    assert ev["tenant_id"] == "tenant-acme"
    payload = ev["payload"]
    assert payload["policy_id"] == "forbid-quarantined-agent-all-actions"
    assert payload["anomaly_score"] == pytest.approx(0.91)
    assert payload["reason"].startswith("tool_diversity exceeded")
    assert len(payload["contributing_features"]) == 3
    assert payload["contributing_features"][0]["name"] == "tool_diversity"
    # Wire contract (wl-lineage `ExecutionEvent`): every event carries a
    # timestamp, and `model_version` is either a real value or ABSENT —
    # never an empty string, which the ingest rejected (422) and dropped.
    assert ev["timestamp"].endswith("Z")
    assert payload.get("model_version", "absent") != ""


@pytest.mark.asyncio
async def test_quarantined_completion_event_carries_a_timestamp(
    plugin: Any, handle: BaseRunHandle
) -> None:
    """The quarantined-complete ``execution_completed`` event must carry
    the wire-required ``timestamp`` — it was the one lifecycle event
    without it, so the run never closed in lineage after a quarantine."""
    plugin.apdp.default_decision = "Quarantine"
    plugin.apdp.quarantine_payload = _quarantine_wire_payload()["details"]["quarantine"]
    with pytest.raises(AgentQuarantinedError):
        await handle.authorize_action("execute", "Tool::a")
    await handle.complete()
    completions = [
        e
        for e in plugin.apdp.published_events
        if e["event_type"] == "execution_completed"
    ]
    assert completions, "quarantined run must still emit execution_completed"
    for ev in completions:
        assert ev.get("timestamp", "").endswith("Z"), ev
        assert ev["payload"]["outcome"] == "quarantined"


@pytest.mark.asyncio
async def test_structural_quarantine_omits_model_version(
    plugin: Any, handle: BaseRunHandle
) -> None:
    """A structural (policy) quarantine has no IF model: the field is
    omitted rather than sent as ``""``."""
    plugin.apdp.default_decision = "Quarantine"
    wire = _quarantine_wire_payload()["details"]["quarantine"]
    wire = {**wire, "model_version": None}
    plugin.apdp.quarantine_payload = wire
    with pytest.raises(AgentQuarantinedError):
        await handle.authorize_action("execute", "Tool::a")
    ev = next(
        e for e in plugin.apdp.published_events if e["event_type"] == "execution_quarantined"
    )
    assert "model_version" not in ev["payload"]


# ─── Test 11 — invariant function smoke test ─────────────────────────


@pytest.mark.asyncio
async def test_conformance_invariant_function_smoke() -> None:
    """The new invariant function
    :func:`watchlight_core_testing.conformance.check_handle_short_circuits_after_quarantine`
    PASSES against a vanilla plugin whose handle honours the
    short-circuit semantics. The exhaustive cross-plugin wire-up is
    tracked separately; here we verify the function itself works
    against a minimal plugin so the contract is locked when that
    work consumes it.
    """
    from watchlight_core_testing.conformance import (
        check_handle_short_circuits_after_quarantine,
    )

    class _Plugin(GovernanceTelemetry):
        def __init__(self) -> None:
            super().__init__()
            self.apdp = MockApdpClient()
            self.tenant_id = "t"
            self.log_decisions = False

        async def start_run(self, slug: str) -> BaseRunHandle:
            agent_uuid = self.apdp.known_agents[slug]
            return BaseRunHandle(
                plugin=self,
                agent_uuid=agent_uuid,
                session_id=f"ses_{slug}",
            )

    plugin = _Plugin()
    # The function installs its own quarantine response wiring; it
    # only needs the MockApdpClient + a working start_run.
    await check_handle_short_circuits_after_quarantine(plugin)


def test_quarantined_payload_schema_model_version_optional_never_empty() -> None:
    """Mirror of the wl-lineage wire contract: ``model_version`` is optional
    (a structural Cedar quarantine has no IF model) but an empty string is
    not a model version."""
    from watchlight_core.events_schema import ExecutionQuarantinedPayload

    base = {"policy_id": "p", "anomaly_score": 0.9, "threshold": 0.5, "reason": "r"}
    assert ExecutionQuarantinedPayload.model_validate(base).model_version is None
    assert ExecutionQuarantinedPayload.model_validate({**base, "model_version": None}).model_version is None
    ok = ExecutionQuarantinedPayload.model_validate(
        {**base, "model_version": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"}
    )
    assert ok.model_version == "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    with pytest.raises(ValueError):
        ExecutionQuarantinedPayload.model_validate({**base, "model_version": ""})
