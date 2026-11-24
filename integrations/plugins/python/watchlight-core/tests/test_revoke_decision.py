"""Enforcement-effect Revoke — tests for the Python lane.

These tests pin down the Revoke enforcement effect
(A · Halt/contain) — the terminal, most-severe verb on the
halt/contain severity ladder
(ordinal 4) — as it wires through the decision parser and
``BaseRunHandle``:

- The wl-apdp Revoke wire shape (``decision: "Revoke"`` +
  ``details.enforcement`` with ``effect == "revoke"``) deserialises into
  a typed :class:`RevokeDecision` carrying the ``policy_id``.
- A Revoke response ends the CURRENT run: ``authorize_action`` raises
  :class:`AgentRevokedError`, fires the kill signal with ``reason=revoke``,
  and transitions the handle to :class:`RunHandleState.COMPLETED` — NOT
  ``QUARANTINED`` (the SDK keeps NO durable local state; the durable
  deny lives in wl-registry's ``trust_state``).
- :class:`AgentRevokedError` is catchable by the same generic
  ``except Exception`` handler pattern the deny/quarantine paths use,
  while an effect-aware handler can match the specific type.

Revoke contrasts with Quarantine at every load-bearing point (no
durable LOCAL state, no parent propagation, COMPLETED not QUARANTINED,
a distinct kill-signal reason token). Because a revoke's durable state
lives server-side in wl-registry, a revoked agent stays denied across
process restarts — the SDK does not need to persist anything locally.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import List, Optional

import pytest
import pytest_asyncio

from watchlight_core import (
    AgentQuarantinedError,
    AgentRevokedError,
    BaseRunHandle,
    LLM_CALL_INTERRUPTED_REASON_REVOKE,
    RevokeDecision,
    RunHandleState,
    parse_authorization_decision,
)
from watchlight_core.telemetry import GovernanceTelemetry
from watchlight_core_testing import MockApdpClient


# ─── Stub kill-signal registry (mirrors test_terminate_decision) ─────


@dataclass
class _CountingKillRegistry:
    """Counts ``cancel`` calls so tests assert on invocation shape."""

    cancel_calls: List[str] = field(default_factory=list)

    async def cancel(self, reason: str) -> list:
        self.cancel_calls.append(reason)
        return []


# ─── Plugin + handle fixtures ────────────────────────────────────────


class _Plugin(GovernanceTelemetry):
    def __init__(
        self,
        kill_signal_registry: Optional[_CountingKillRegistry] = None,
    ) -> None:
        super().__init__()
        self.apdp = MockApdpClient()
        self.apdp.known_agents["agent-x"] = "uuid-x"
        self.tenant_id = "tenant-acme"
        self.log_decisions = False
        self.kill_signal_registry = kill_signal_registry


@pytest.fixture
def registry() -> _CountingKillRegistry:
    return _CountingKillRegistry()


@pytest.fixture
def plugin(registry: _CountingKillRegistry) -> _Plugin:
    return _Plugin(kill_signal_registry=registry)


@pytest_asyncio.fixture
async def handle(plugin: _Plugin) -> BaseRunHandle:
    h = BaseRunHandle(plugin=plugin, agent_uuid="uuid-x", session_id="ses_x")
    h._aentered = True
    return h


def _revoke_wire_payload() -> dict:
    """The exact wire shape wl-apdp emits on a policy-driven Revoke."""
    return {
        "decision": "Revoke",
        "reason": "Agent trust revoked by policy forbid-revoke-compromised-agent",
        "details": {
            "enforcement": {
                "effect": "revoke",
                "severity": 4,
                "reason": "revoke",
                "lift_required": True,
                "policy_id": "forbid-revoke-compromised-agent",
            }
        },
    }


# ─── Test (a) — parser returns a RevokeDecision ──────────────────────


def test_parse_revoke_wire_returns_revoke_decision() -> None:
    typed = parse_authorization_decision(_revoke_wire_payload())

    assert isinstance(typed, RevokeDecision)
    assert typed.kind == "revoke"
    assert typed.policy_id == "forbid-revoke-compromised-agent"
    assert typed.reason.startswith("Agent trust revoked")


def test_parse_revoke_falls_back_to_determining_policy_id() -> None:
    payload = {
        "decision": "Revoke",
        "reason": "revoked",
        "determining_policy_id": "top-level-pid",
        "details": {"enforcement": {"effect": "revoke", "severity": 4}},
    }
    typed = parse_authorization_decision(payload)
    assert isinstance(typed, RevokeDecision)
    assert typed.policy_id == "top-level-pid"


def test_parse_revoke_ignores_non_revoke_effect_block() -> None:
    """Defensive: a ``Revoke`` decision whose enforcement block claims a
    *different* effect must not mis-attribute that effect's policy_id.
    """
    payload = {
        "decision": "Revoke",
        "reason": "revoked",
        "details": {
            "enforcement": {"effect": "quarantine", "policy_id": "wrong-pid"}
        },
    }
    typed = parse_authorization_decision(payload)
    assert isinstance(typed, RevokeDecision)
    assert typed.policy_id is None


def test_parse_revoke_default_reason_when_absent() -> None:
    typed = parse_authorization_decision(
        {"decision": "Revoke", "details": {"enforcement": {"effect": "revoke"}}}
    )
    assert isinstance(typed, RevokeDecision)
    assert typed.reason == "Agent trust revoked"


# ─── Test (b) — authorize raises AgentRevokedError, ends run ─────────


@pytest.mark.asyncio
async def test_revoke_raises_error_and_ends_run_without_local_bag(
    plugin: _Plugin,
    handle: BaseRunHandle,
    registry: _CountingKillRegistry,
) -> None:
    """A Revoke response ends the current run:

    - ``authorize_action`` raises :class:`AgentRevokedError`.
    - the kill signal fires with ``reason=revoke``.
    - the handle transitions to ``COMPLETED`` (NOT ``QUARANTINED``).
    - the SDK keeps NO durable local bag (``quarantine_decision`` is
      ``None``) — the durable deny lives in wl-registry's ``trust_state``.
    """
    plugin.apdp.default_decision = "Revoke"

    with pytest.raises(AgentRevokedError) as exc_info:
        await handle.authorize_action("execute", "Tool::scanner")

    await asyncio.sleep(0)

    assert handle.state == RunHandleState.COMPLETED
    assert handle.is_quarantined is False
    assert handle.quarantine_decision is None

    assert registry.cancel_calls == [LLM_CALL_INTERRUPTED_REASON_REVOKE]

    assert exc_info.value.policy_id == "synthetic.revoke"
    assert "revoked" in str(exc_info.value).lower()


@pytest.mark.asyncio
async def test_revoke_marks_run_completed_idempotently(
    plugin: _Plugin,
    handle: BaseRunHandle,
) -> None:
    plugin.apdp.default_decision = "Revoke"

    with pytest.raises(AgentRevokedError):
        await handle.authorize_action("execute", "Tool::scanner")
    await asyncio.sleep(0)

    closed_before = list(plugin.apdp._closed_sessions)
    terminated_before = list(plugin.apdp._terminated_sessions)

    await handle.terminate("late")
    await handle.complete()

    assert plugin.apdp._closed_sessions == closed_before
    assert plugin.apdp._terminated_sessions == terminated_before
    assert handle.state == RunHandleState.COMPLETED


# ─── Test (c) — a revoked agent stays denied on the SERVER side ──────


@pytest.mark.asyncio
async def test_second_run_denied_by_server_side_trust_gate(
    plugin: _Plugin,
) -> None:
    """A revoke's durable state lives in wl-registry, NOT the SDK. The
    SDK keeps no local bag; a fresh run stays denied because wl-apdp's
    pre-Cedar trust gate denies every authorize once wl-registry has set
    ``trust_state=Revoked``. We model that here: after a Revoke, the
    *server* continues to refuse (a plain Deny from the trust gate).
    """
    plugin.apdp.default_decision = "Revoke"

    h1 = BaseRunHandle(plugin=plugin, agent_uuid="uuid-x", session_id="ses_1")
    h1._aentered = True
    with pytest.raises(AgentRevokedError):
        await h1.authorize_action("execute", "Tool::scanner")
    await asyncio.sleep(0)
    assert h1.state == RunHandleState.COMPLETED

    # Server-side: wl-registry set trust_state=Revoked, so wl-apdp's
    # pre-Cedar trust gate now returns a plain Deny for every subsequent
    # authorize — across a brand-new handle, across process restarts.
    plugin.apdp.default_decision = "Deny"
    h2 = BaseRunHandle(plugin=plugin, agent_uuid="uuid-x", session_id="ses_2")
    h2._aentered = True
    allowed = await h2.authorize_action("execute", "Tool::scanner")
    assert allowed is False


# ─── Test (d) — generic + effect-aware handler both catch it ─────────


@pytest.mark.asyncio
async def test_revoke_error_caught_by_generic_handler(
    plugin: _Plugin,
    handle: BaseRunHandle,
) -> None:
    plugin.apdp.default_decision = "Revoke"

    caught_generic = False
    try:
        await handle.authorize_action("execute", "Tool::scanner")
    except Exception as exc:  # noqa: BLE001 — intentional generic catch
        caught_generic = True
        assert isinstance(exc, AgentRevokedError)
    assert caught_generic

    # Effect-aware: AgentRevokedError is a distinct type from Quarantine.
    assert not issubclass(AgentRevokedError, AgentQuarantinedError)
    assert not issubclass(AgentQuarantinedError, AgentRevokedError)


@pytest.mark.asyncio
async def test_revoke_does_not_propagate_to_parent(
    registry: _CountingKillRegistry,
) -> None:
    """Revoke ends the CURRENT run and revokes THIS agent's trust — it
    does NOT sever/propagate up the parent chain (contrast SeverSubtree,
    which walks DOWN to descendants). A parent handle stays ACTIVE.
    """
    parent_registry = _CountingKillRegistry()
    child_registry = _CountingKillRegistry()

    parent_plugin = _Plugin(kill_signal_registry=parent_registry)
    child_plugin = _Plugin(kill_signal_registry=child_registry)

    parent = BaseRunHandle(
        plugin=parent_plugin, agent_uuid="uuid-root", session_id="ses_root"
    )
    parent._aentered = True
    child = BaseRunHandle(
        plugin=child_plugin,
        agent_uuid="uuid-child",
        session_id="ses_child",
        parent_handle=parent,
    )
    child._aentered = True

    child_plugin.apdp.default_decision = "Revoke"

    with pytest.raises(AgentRevokedError):
        await child.authorize_action("execute", "Tool::scanner")
    await asyncio.sleep(0)

    assert child.state == RunHandleState.COMPLETED
    assert parent.state == RunHandleState.ACTIVE
    assert child_registry.cancel_calls == [LLM_CALL_INTERRUPTED_REASON_REVOKE]
    assert parent_registry.cancel_calls == []
