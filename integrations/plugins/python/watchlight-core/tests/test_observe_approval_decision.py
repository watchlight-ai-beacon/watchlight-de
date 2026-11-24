"""Observe + RequireApproval enforcement effects — Python SDK.

Observe is the shipped ALLOW-DOWNGRADE-class effect and RequireApproval
the shipped GATE-class effect (see the enforcement-effects
decision-resolution order REAL-DENY > GATE > ALLOW-DOWNGRADE).

- **Observe** downgrades a Cedar Deny to ``Allow`` (monitor mode) when it
  is the sole deny reason. The SDK surfaces the observation as NON-throwing
  additive metadata (an ``observations`` field on the parsed decision + a
  recorded/observable surface on the run handle). There is NO terminal
  error — the action proceeds. The observation is recorded EVEN when a
  co-occurring hard forbid kept the deny (the fail-closed invariant).
- **RequireApproval** REUSES the existing NeedsApproval surface (wl-apdp
  emits ``decision:"Deny"`` + ``escalation_required`` +
  ``approval_request_id``) — the SDK already collapses that to
  :class:`NeedsApprovalDecision`, so there is NO new error type.

Mirrors the TypeScript lane ``tests/observe-approval.test.ts`` 1:1.
"""

from __future__ import annotations

from typing import Any

import pytest
import pytest_asyncio

from watchlight_core import (
    BaseRunHandle,
    Observation,
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


def _allow_with_observation() -> dict:
    """wl-apdp's Observe wire shape: the Cedar Deny is downgraded to a
    top-level ``Allow`` with the observation recorded additively."""
    return {
        "decision": "Allow",
        "reason": "Cedar Deny downgraded to Allow (monitor mode) by policy forbid-observe-x",
        "details": {
            "enforcement": {
                "effect": "observe",
                "class": "allow_downgrade",
                "severity": 0,
                "policy_id": "forbid-observe-x",
                "reason": "observed (monitor mode) by policy forbid-observe-x",
                "observations": [
                    {
                        "effect": "observe",
                        "class": "allow_downgrade",
                        "policy_id": "forbid-observe-x",
                        "reason": "observed (monitor mode) by policy forbid-observe-x",
                    }
                ],
            }
        },
    }


def _quarantine_with_observation() -> dict:
    """Fail-closed: an Observe co-occurring with a hard Quarantine stays a
    Quarantine, and the observation still rides alongside."""
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
                "observations": [
                    {"policy_id": "forbid-observe-x", "reason": "observed"}
                ],
            },
        },
    }


def _needs_approval_wire() -> dict:
    """wl-apdp's RequireApproval wire shape — the EXISTING NeedsApproval
    surface (Deny + escalation_required + approval_request_id)."""
    return {
        "decision": "Deny",
        "reason": "Action gated for human approval by policy forbid-require-approval-x",
        "details": {
            "escalation_required": True,
            "approval_request_id": "appr_1234",
            "enforcement": {
                "effect": "require_approval",
                "class": "gate",
                "severity": 0,
                "policy_id": "forbid-require-approval-x",
                "reason": "Action gated for human approval by policy forbid-require-approval-x",
            },
        },
    }


# ─── Observe parser tests ────────────────────────────────────────────


def test_observe_downgrades_to_allow_and_records_observation() -> None:
    decision = parse_authorization_decision(_allow_with_observation())
    # The decision is a top-level Allow — the action proceeds.
    assert decision.kind == "allow"
    assert len(decision.observations) == 1
    assert decision.observations[0].policy_id == "forbid-observe-x"


def test_observe_never_rescues_a_quarantine_but_still_records() -> None:
    decision = parse_authorization_decision(_quarantine_with_observation())
    # Fail-closed: Quarantine still wins; the observation rides alongside.
    assert decision.kind == "quarantine"
    assert len(decision.observations) == 1
    assert decision.observations[0].policy_id == "forbid-observe-x"


def test_no_observation_leaves_field_empty() -> None:
    decision = parse_authorization_decision({"decision": "Allow", "reason": "plain"})
    assert decision.kind == "allow"
    assert decision.observations == ()


# ─── RequireApproval parser tests (reuses NeedsApproval) ─────────────


def test_require_approval_maps_to_needs_approval() -> None:
    decision = parse_authorization_decision(_needs_approval_wire())
    # RequireApproval reuses the existing NeedsApproval surface — no new
    # decision variant, no new error type.
    assert decision.kind == "needs_approval"
    assert decision.approval_request_id == "appr_1234"


# ─── Run-handle non-throwing observation surface tests ───────────────


@pytest.mark.asyncio
async def test_handle_records_observation_on_allow_without_raising(
    plugin: Any, handle: BaseRunHandle
) -> None:
    plugin.apdp.default_decision = "Allow"
    plugin.apdp.observations = [
        {"policy_id": "forbid-observe-x", "reason": "observed (monitor mode)"}
    ]

    # An Allow is a returned result, not a raise — and the observation is
    # recorded additively.
    result = await handle.authorize_action_detailed("execute", "Tool::scanner")
    assert result.is_allow() is True
    assert handle.has_observations() is True
    assert len(handle.get_observations()) == 1
    assert handle.get_observations()[0].policy_id == "forbid-observe-x"


@pytest.mark.asyncio
async def test_handle_records_observation_even_when_quarantine_raises(
    plugin: Any, handle: BaseRunHandle
) -> None:
    # THE fail-closed property: a co-occurring Quarantine STILL raises
    # (decision axis unchanged) AND the observation is recorded (additive
    # axis), because recording happens before the raise.
    from watchlight_core import AgentQuarantinedError

    plugin.apdp.default_decision = "Quarantine"
    plugin.apdp.quarantine_payload = {
        "reason": "anomaly above threshold",
        "anomaly_score": 0.9,
        "contributing_features": [],
        "model_version": None,
        "policy_id": "forbid-quarantine-y",
    }
    plugin.apdp.observations = [
        {"policy_id": "forbid-observe-x", "reason": "observed"}
    ]

    with pytest.raises(AgentQuarantinedError):
        await handle.authorize_action("execute", "Tool::scanner")

    assert handle.has_observations() is True
    assert handle.get_observations()[0].policy_id == "forbid-observe-x"


@pytest.mark.asyncio
async def test_on_observation_listener_fires_and_throwing_listener_never_breaks_authz(
    plugin: Any,
) -> None:
    seen: list[Observation] = []

    def _listener(obs: Observation) -> None:
        seen.append(obs)
        raise RuntimeError("listener boom — must be swallowed")

    h = BaseRunHandle(
        plugin=plugin,
        agent_uuid="uuid-x",
        session_id="ses_x",
        on_observation=_listener,
    )
    h._aentered = True
    plugin.apdp.default_decision = "Allow"
    plugin.apdp.observations = [
        {"policy_id": "forbid-observe-x", "reason": "observed"}
    ]

    # The throwing listener must NOT propagate — authz completes normally.
    result = await h.authorize_action_detailed("execute", "Tool::scanner")
    assert result.is_allow() is True
    assert len(seen) == 1
    assert seen[0].policy_id == "forbid-observe-x"
