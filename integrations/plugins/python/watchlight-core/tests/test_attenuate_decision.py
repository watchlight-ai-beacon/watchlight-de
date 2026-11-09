"""Attenuate enforcement effect — Python SDK.

Attenuate is the SECOND shipped ALLOW-DOWNGRADE-class effect (see the
enforcement-effects decision-resolution order
REAL-DENY > GATE > ALLOW-DOWNGRADE).

Attenuate downgrades a Cedar Deny to ``Allow`` when it is the sole deny
reason AND durably NARROWS the run's sub-agent RunHandle scope to a strict
subset. The SDK surfaces the attenuation as NON-throwing additive metadata
(an ``attenuations`` field on the parsed decision + a recorded/observable
surface on the run handle). There is NO terminal error — the action
proceeds under the narrowed grant; every SUBSEQUENT authorize is enforced
against the tighter grant server-side. The attenuation is recorded EVEN
when a co-occurring hard forbid kept the deny (the fail-closed invariant),
and a fail-closed attenuation (``narrowed=False``) is surfaced for
attribution.

Mirrors the TypeScript lane ``tests/attenuate.test.ts`` 1:1.
"""

from __future__ import annotations

from typing import Any

import pytest
import pytest_asyncio

from watchlight_core import (
    Attenuation,
    BaseRunHandle,
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


def _allow_with_attenuation() -> dict:
    """wl-apdp's Attenuate wire shape: the Cedar Deny is downgraded to a
    top-level ``Allow`` with the attenuation recorded additively (the
    narrowing was applied server-side)."""
    return {
        "decision": "Allow",
        "reason": "Cedar Deny downgraded to Allow (run scope narrowed) by policy forbid-attenuate-x",
        "details": {
            "enforcement": {
                "effect": "attenuate",
                "class": "allow_downgrade",
                "severity": 0,
                "policy_id": "forbid-attenuate-x",
                "reason": "run scope narrowed by policy forbid-attenuate-x",
                "attenuations": [
                    {
                        "effect": "attenuate",
                        "class": "allow_downgrade",
                        "policy_id": "forbid-attenuate-x",
                        "reason": "run scope narrowed by policy forbid-attenuate-x",
                        "narrowed": True,
                        "descendants_affected": 1,
                    }
                ],
            }
        },
    }


def _quarantine_with_attenuation() -> dict:
    """Fail-closed: an Attenuate co-occurring with a hard Quarantine stays a
    Quarantine, and the attenuation still rides alongside (the narrowing
    happened; the run is killed by the Quarantine anyway)."""
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
                "attenuations": [
                    {
                        "policy_id": "forbid-attenuate-x",
                        "reason": "narrowed",
                        "narrowed": True,
                    }
                ],
            },
        },
    }


def _deny_with_failed_attenuation() -> dict:
    """Fail-closed: an Attenuate that could not narrow (narrowed=False)
    stays a real Deny; the record is surfaced for attribution."""
    return {
        "decision": "Deny",
        "reason": "attenuate without a run handle to narrow",
        "details": {
            "enforcement": {
                "effect": "attenuate",
                "class": "allow_downgrade",
                "policy_id": "forbid-attenuate-x",
                "reason": "attenuate with no run handle to narrow",
                "attenuations": [
                    {
                        "policy_id": "forbid-attenuate-x",
                        "reason": "attenuate with no run handle to narrow",
                        "narrowed": False,
                    }
                ],
            }
        },
    }


# ─── Attenuate parser tests ──────────────────────────────────────────


def test_attenuate_downgrades_to_allow_and_records_attenuation() -> None:
    decision = parse_authorization_decision(_allow_with_attenuation())
    # The decision is a top-level Allow — the action proceeds under the
    # narrowed grant.
    assert decision.kind == "allow"
    assert len(decision.attenuations) == 1
    assert decision.attenuations[0].policy_id == "forbid-attenuate-x"
    assert decision.attenuations[0].narrowed is True
    assert decision.attenuations[0].descendants_affected == 1


def test_attenuate_never_rescues_a_quarantine_but_still_records() -> None:
    decision = parse_authorization_decision(_quarantine_with_attenuation())
    # Fail-closed: Quarantine still wins; the attenuation rides alongside.
    assert decision.kind == "quarantine"
    assert len(decision.attenuations) == 1
    assert decision.attenuations[0].narrowed is True


def test_failed_attenuation_stays_deny_but_records() -> None:
    decision = parse_authorization_decision(_deny_with_failed_attenuation())
    # Fail-closed: a failed attenuation is a real Deny; the record shows
    # narrowed=False for attribution.
    assert decision.kind == "deny"
    assert len(decision.attenuations) == 1
    assert decision.attenuations[0].narrowed is False


def test_no_attenuation_leaves_field_empty() -> None:
    decision = parse_authorization_decision({"decision": "Allow", "reason": "plain"})
    assert decision.kind == "allow"
    assert decision.attenuations == ()


# ─── Run-handle non-throwing attenuation surface tests ───────────────


@pytest.mark.asyncio
async def test_handle_records_attenuation_on_allow_without_raising(
    plugin: Any, handle: BaseRunHandle
) -> None:
    plugin.apdp.default_decision = "Allow"
    plugin.apdp.attenuations = [
        {
            "policy_id": "forbid-attenuate-x",
            "reason": "run scope narrowed",
            "narrowed": True,
        }
    ]

    # An Allow is a returned result, not a raise — and the attenuation is
    # recorded additively.
    result = await handle.authorize_action_detailed("execute", "Tool::scanner")
    assert result.is_allow() is True
    assert handle.has_attenuations() is True
    assert handle.was_scope_attenuated() is True
    assert len(handle.get_attenuations()) == 1
    assert handle.get_attenuations()[0].policy_id == "forbid-attenuate-x"


@pytest.mark.asyncio
async def test_handle_records_attenuation_even_when_quarantine_raises(
    plugin: Any, handle: BaseRunHandle
) -> None:
    # THE fail-closed property: a co-occurring Quarantine STILL raises
    # (decision axis unchanged) AND the attenuation is recorded (additive
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
    plugin.apdp.attenuations = [
        {"policy_id": "forbid-attenuate-x", "reason": "narrowed", "narrowed": True}
    ]

    with pytest.raises(AgentQuarantinedError):
        await handle.authorize_action("execute", "Tool::scanner")

    assert handle.has_attenuations() is True
    assert handle.was_scope_attenuated() is True


@pytest.mark.asyncio
async def test_failed_attenuation_does_not_count_as_scope_attenuated(
    plugin: Any, handle: BaseRunHandle
) -> None:
    # A fail-closed attenuation (narrowed=False) is recorded but
    # was_scope_attenuated() is False — no authority was narrowed.
    plugin.apdp.default_decision = "Deny"
    plugin.apdp.attenuations = [
        {"policy_id": "forbid-attenuate-x", "reason": "no handle", "narrowed": False}
    ]
    result = await handle.authorize_action_detailed("execute", "Tool::scanner")
    assert result.is_allow() is False
    assert handle.has_attenuations() is True
    assert handle.was_scope_attenuated() is False


@pytest.mark.asyncio
async def test_on_attenuation_listener_fires_and_throwing_listener_never_breaks_authz(
    plugin: Any,
) -> None:
    seen: list[Attenuation] = []

    def _listener(att: Attenuation) -> None:
        seen.append(att)
        raise RuntimeError("listener boom — must be swallowed")

    h = BaseRunHandle(
        plugin=plugin,
        agent_uuid="uuid-x",
        session_id="ses_x",
        on_attenuation=_listener,
    )
    h._aentered = True
    plugin.apdp.default_decision = "Allow"
    plugin.apdp.attenuations = [
        {"policy_id": "forbid-attenuate-x", "reason": "narrowed", "narrowed": True}
    ]

    # The throwing listener must NOT propagate — authz completes normally.
    result = await h.authorize_action_detailed("execute", "Tool::scanner")
    assert result.is_allow() is True
    assert len(seen) == 1
    assert seen[0].policy_id == "forbid-attenuate-x"
