"""Escalate enforcement effect — Python SDK side-effect axis.

Escalate is the first SIDE-EFFECT-class effect (see the
enforcement-effects "two-axis model"). It DENIES the action AND
raises a high-priority SOC/HITL alert, but it fires ALONGSIDE the
decision WITHOUT changing it: a Deny stays a Deny, a
Quarantine stays a Quarantine. The SDK surfaces the escalation as
NON-throwing additive metadata (an ``escalations`` field on the parsed
decision + a recorded/observable surface on the run handle) WITHOUT
altering the existing raise/return contract. There is NO EscalatedError.

Mirrors the TypeScript lane ``tests/escalate.test.ts`` 1:1.
"""

from __future__ import annotations

from typing import Any

import pytest
import pytest_asyncio

from watchlight_core import (
    AgentQuarantinedError,
    BaseRunHandle,
    Escalation,
    parse_authorization_decision,
)
from watchlight_core.telemetry import GovernanceTelemetry
from watchlight_core_testing import MockApdpClient


# ─── Fixtures ────────────────────────────────────────────────────────


@pytest.fixture
def plugin() -> Any:
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
    h = BaseRunHandle(plugin=plugin, agent_uuid="uuid-x", session_id="ses_x")
    h._aentered = True
    return h


def _deny_with_escalation() -> dict:
    return {
        "decision": "Deny",
        "reason": "action denied",
        "details": {
            "enforcement": {
                "side_effects": [
                    {
                        "effect": "escalate",
                        "class": "side_effect",
                        "policy_id": "forbid-escalate-suspicious-tool",
                        "reason": "escalated to SOC/HITL by policy forbid-escalate-suspicious-tool",
                    }
                ],
                "escalations": [
                    {
                        "policy_id": "forbid-escalate-suspicious-tool",
                        "reason": "escalated to SOC/HITL by policy forbid-escalate-suspicious-tool",
                    }
                ],
            }
        },
    }


def _quarantine_with_escalation() -> dict:
    return {
        "decision": "Quarantine",
        "reason": "Agent quarantined by policy forbid-quarantine-y",
        "details": {
            "quarantine": {
                "reason": "anomaly score above tier threshold",
                "anomaly_score": 0.9,
                "contributing_features": [],
                "model_version": None,
                "policy_id": "forbid-quarantine-y",
            },
            "enforcement": {
                "effect": "quarantine",
                "severity": 2,
                "reason": "quarantine",
                "lift_required": True,
                "policy_id": "forbid-quarantine-y",
                "escalations": [
                    {"policy_id": "forbid-escalate-x", "reason": "escalated"}
                ],
            },
        },
    }


# ─── Parser tests ────────────────────────────────────────────────────


def test_parses_escalation_onto_plain_deny() -> None:
    decision = parse_authorization_decision(_deny_with_escalation())
    # Escalate NEVER changes the decision.
    assert decision.kind == "deny"
    assert len(decision.escalations) == 1
    assert decision.escalations[0].policy_id == "forbid-escalate-suspicious-tool"


def test_parses_escalation_onto_quarantine_decision() -> None:
    decision = parse_authorization_decision(_quarantine_with_escalation())
    # Quarantine still wins the decision; escalation rides alongside.
    assert decision.kind == "quarantine"
    assert len(decision.escalations) == 1
    assert decision.escalations[0].policy_id == "forbid-escalate-x"


def test_no_escalation_leaves_field_empty() -> None:
    decision = parse_authorization_decision({"decision": "Deny", "reason": "plain"})
    assert decision.kind == "deny"
    assert decision.escalations == ()


# ─── Run-handle non-throwing surface tests ───────────────────────────


@pytest.mark.asyncio
async def test_handle_records_escalation_on_deny_without_raising(
    plugin: Any, handle: BaseRunHandle
) -> None:
    plugin.apdp.default_decision = "Deny"
    plugin.apdp.escalations = [
        {"policy_id": "forbid-escalate-suspicious-tool", "reason": "escalated"}
    ]

    # A Deny is a returned result, not a raise — the escalation did not
    # change the decision.
    result = await handle.authorize_action_detailed("execute", "Tool::scanner")
    assert result.is_allow() is False
    assert handle.has_escalations() is True
    assert len(handle.get_escalations()) == 1
    assert handle.get_escalations()[0].policy_id == "forbid-escalate-suspicious-tool"


@pytest.mark.asyncio
async def test_handle_records_escalation_even_when_quarantine_raises(
    plugin: Any, handle: BaseRunHandle
) -> None:
    # The load-bearing two-axis property: a Quarantine STILL raises
    # (decision axis unchanged) AND the escalation is recorded (additive
    # axis), because recording happens before the raise.
    plugin.apdp.default_decision = "Quarantine"
    plugin.apdp.quarantine_payload = {
        "reason": "anomaly above threshold",
        "anomaly_score": 0.9,
        "contributing_features": [],
        "model_version": None,
        "policy_id": "forbid-quarantine-y",
    }
    plugin.apdp.escalations = [
        {"policy_id": "forbid-escalate-x", "reason": "escalated"}
    ]

    with pytest.raises(AgentQuarantinedError):
        await handle.authorize_action("execute", "Tool::scanner")

    assert handle.has_escalations() is True
    assert handle.get_escalations()[0].policy_id == "forbid-escalate-x"


@pytest.mark.asyncio
async def test_on_escalation_listener_fires_and_throwing_listener_never_breaks_authz(
    plugin: Any,
) -> None:
    seen: list[Escalation] = []

    def _listener(esc: Escalation) -> None:
        seen.append(esc)
        raise RuntimeError("listener boom — must be swallowed")

    h = BaseRunHandle(
        plugin=plugin,
        agent_uuid="uuid-x",
        session_id="ses_x",
        on_escalation=_listener,
    )
    h._aentered = True
    plugin.apdp.default_decision = "Deny"
    plugin.apdp.escalations = [
        {"policy_id": "forbid-escalate-suspicious-tool", "reason": "escalated"}
    ]

    # The throwing listener must NOT propagate — authz completes normally.
    result = await h.authorize_action_detailed("execute", "Tool::scanner")
    assert result.is_allow() is False
    assert len(seen) == 1
    assert seen[0].policy_id == "forbid-escalate-suspicious-tool"
