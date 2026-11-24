"""Claude Agent SDK (Python) plugin Quarantine + kill-signal tests.

This plugin uses :class:`watchlight_core.BaseRunHandle` for the
lifecycle, so the SDK's automatic ``_fire_kill_signal`` hook fires
on the Quarantine transition. The Python Claude Agent SDK doesn't
expose a per-tool decorator (unlike pydantic-ai), so the
integration point is the customer's own pre-call to
``handle.authorize_action(...)`` — that's the path we exercise.
"""

from __future__ import annotations

import asyncio
from typing import List

import pytest

from watchlight_core import (
    AgentQuarantinedError,
    LLM_CALL_INTERRUPTED_REASON_QUARANTINE,
)
from watchlight_core_testing import MockApdpClient
from watchlight_claude_agent import WatchlightClaudeAgentSDKPlugin


def _quarantine_payload() -> dict:
    return {
        "reason": "Claude Agent SDK Python — quarantined for anomalous behavior",
        "anomaly_score": 0.92,
        "contributing_features": [],
        "model_version": None,
        "policy_id": "quarantine.claude_agent_sdk.kill",
    }


class _CountingRegistry:
    def __init__(self) -> None:
        self.cancel_calls: List[str] = []

    async def cancel(self, reason: str) -> list:
        self.cancel_calls.append(reason)
        return []


@pytest.mark.asyncio
async def test_authorize_action_fires_kill_signal_on_quarantine() -> None:
    """The customer's pre-call to ``handle.authorize_action`` — which
    is THE integration point for the Python Claude Agent SDK —
    transitions to QUARANTINED, fires the kill signal, and raises
    :class:`AgentQuarantinedError`.
    """
    plugin = WatchlightClaudeAgentSDKPlugin(apdp_url="http://localhost:8081")
    plugin.apdp = MockApdpClient()
    plugin.apdp.known_agents["agent-x"] = "uuid-x"
    plugin.apdp.default_decision = "Quarantine"
    plugin.apdp.quarantine_payload = _quarantine_payload()
    registry = _CountingRegistry()
    plugin.kill_signal_registry = registry

    handle = await plugin.start_run("agent-x")
    handle._aentered = True  # synthetic test handle
    with pytest.raises(AgentQuarantinedError):
        await handle.authorize_action("execute", "Tool::scanner")
    await asyncio.sleep(0)

    assert registry.cancel_calls == [LLM_CALL_INTERRUPTED_REASON_QUARANTINE]


@pytest.mark.asyncio
async def test_short_circuit_re_fires_kill_signal_and_no_apdp_round_trip() -> None:
    """After the first quarantine raise, subsequent calls short-circuit
    AND re-fire the kill signal AND do not round-trip to wl-apdp.
    Load-bearing for the "no round-trip after quarantine" conformance
    invariant.
    """
    plugin = WatchlightClaudeAgentSDKPlugin(apdp_url="http://localhost:8081")
    plugin.apdp = MockApdpClient()
    plugin.apdp.known_agents["agent-x"] = "uuid-x"
    plugin.apdp.default_decision = "Quarantine"
    plugin.apdp.quarantine_payload = _quarantine_payload()
    registry = _CountingRegistry()
    plugin.kill_signal_registry = registry

    handle = await plugin.start_run("agent-x")
    handle._aentered = True  # synthetic test handle
    with pytest.raises(AgentQuarantinedError):
        await handle.authorize_action("execute", "Tool::a")
    await asyncio.sleep(0)

    for _ in range(3):
        with pytest.raises(AgentQuarantinedError):
            await handle.authorize_action("execute", "Tool::b")
        await asyncio.sleep(0)

    assert len(registry.cancel_calls) == 4
    # Invariant: no wl-apdp round-trip after first quarantine.
    assert len(plugin.apdp.authorize_calls) == 1
