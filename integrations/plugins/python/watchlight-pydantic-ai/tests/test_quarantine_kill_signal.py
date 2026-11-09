"""Pydantic AI plugin Quarantine handling + kill-signal cascade.

The Pydantic AI plugin uses :class:`watchlight_core.BaseRunHandle`
under the hood (the kill-signal wiring fires automatically via the
SDK's ``_fire_kill_signal`` hook on the quarantine transition). This test
suite verifies the inheritance path works for Pydantic AI's
``guarded_tool`` decorator as well — every tool call wrapped with
``guarded_tool`` goes through ``handle.authorize_action``, so the
kill signal fires there too.
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
from watchlight_pydantic_ai import WatchlightPydanticAIPlugin


def _quarantine_payload() -> dict:
    return {
        "reason": "Pydantic AI regression — agent quarantined for anomalous behavior",
        "anomaly_score": 0.93,
        "contributing_features": [],
        "model_version": None,
        "policy_id": "anomaly.pydantic_ai.kill",
    }


class _CountingRegistry:
    def __init__(self) -> None:
        self.cancel_calls: List[str] = []

    async def cancel(self, reason: str) -> list:
        self.cancel_calls.append(reason)
        return []


@pytest.fixture
def plugin_with_quarantine():
    plugin = WatchlightPydanticAIPlugin(
        apdp_url="http://localhost:8081", auto_instrument=False
    )
    plugin.apdp = MockApdpClient()
    plugin.apdp.known_agents["agent-x"] = "uuid-x"
    plugin.apdp.default_decision = "Quarantine"
    plugin.apdp.quarantine_payload = _quarantine_payload()
    registry = _CountingRegistry()
    plugin.kill_signal_registry = registry
    yield plugin, registry


@pytest.mark.asyncio
async def test_authorize_action_fires_kill_signal(plugin_with_quarantine) -> None:
    """Direct ``handle.authorize_action`` path (the canonical
    Pydantic-AI integration point) fires the kill signal on
    Quarantine.
    """
    plugin, registry = plugin_with_quarantine

    handle = await plugin.start_run("agent-x")
    handle._aentered = True  # synthetic test handle
    with pytest.raises(AgentQuarantinedError):
        await handle.authorize_action("execute", "Tool::scanner")
    await asyncio.sleep(0)

    assert registry.cancel_calls == [LLM_CALL_INTERRUPTED_REASON_QUARANTINE]


@pytest.mark.asyncio
async def test_guarded_tool_path_propagates_quarantined_error(
    plugin_with_quarantine,
) -> None:
    """``handle.guarded_tool`` wraps a callable; when authorize raises
    AgentQuarantinedError, the wrapper must let it propagate (the
    Pydantic-AI agent's ``Agent.run`` loop catches and surfaces it).
    """
    plugin, registry = plugin_with_quarantine

    handle = await plugin.start_run("agent-x")
    handle._aentered = True  # synthetic test handle

    @handle.guarded_tool(action="execute")
    async def fetch_data(ctx, query: str) -> str:
        return f"data:{query}"

    with pytest.raises(AgentQuarantinedError):
        await fetch_data(None, "foo")
    await asyncio.sleep(0)

    assert registry.cancel_calls == [LLM_CALL_INTERRUPTED_REASON_QUARANTINE]


@pytest.mark.asyncio
async def test_short_circuit_re_fires_kill_signal(plugin_with_quarantine) -> None:
    """Subsequent authorize calls on a quarantined Pydantic-AI handle
    re-fire the kill signal AND do not round-trip to wl-apdp.
    """
    plugin, registry = plugin_with_quarantine

    handle = await plugin.start_run("agent-x")
    handle._aentered = True  # synthetic test handle
    with pytest.raises(AgentQuarantinedError):
        await handle.authorize_action("execute", "Tool::a")
    await asyncio.sleep(0)

    for _ in range(2):
        with pytest.raises(AgentQuarantinedError):
            await handle.authorize_action("execute", "Tool::b")
        await asyncio.sleep(0)

    assert len(registry.cancel_calls) == 3
    assert len(plugin.apdp.authorize_calls) == 1
