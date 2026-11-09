"""ADK plugin Quarantine handling + kill-signal cascade.

ADK uses the BasePlugin callback model rather than
:class:`watchlight_core.BaseRunHandle`, so the SDK's automatic
quarantine wiring doesn't fire here. The plugin wires the kill signal
explicitly inside ``before_tool_callback`` when wl-apdp returns
Quarantine.

These tests drive the ``before_tool_callback`` hook directly with
a mocked APDP client that returns Quarantine; the assertion is that
the kill-signal registry's ``cancel("quarantine")`` was invoked and
the callback returned a strongly-worded block message (so the agent
halts).
"""

from __future__ import annotations

import asyncio
from typing import Any, List
from unittest.mock import AsyncMock, MagicMock

import pytest

from watchlight_core import LLM_CALL_INTERRUPTED_REASON_QUARANTINE
from watchlight_adk import WatchlightPlugin


class _CountingRegistry:
    def __init__(self) -> None:
        self.cancel_calls: List[str] = []

    async def cancel(self, reason: str) -> list:
        self.cancel_calls.append(reason)
        return []


# In-process stand-in for unit tests only.
def _stub_tool(name: str = "fetch_data") -> Any:
    tool = MagicMock()
    tool.name = name
    return tool


def _plugin_armed_for_quarantine() -> tuple:
    """Construct an ADK plugin with a counting kill-signal registry and
    a mocked APDP client that returns Quarantine on ``authorize``.
    """
    plugin = WatchlightPlugin(
        apdp_url="http://localhost:8081",
        agent_slug="agent-research-analyst",
        root_agent_name="research_analyst",
    )
    registry = _CountingRegistry()
    plugin.kill_signal_registry = registry

    plugin.apdp.authorize = AsyncMock(
        return_value={
            "decision": "Quarantine",
            "reason": "ADK regression — quarantined",
            "details": {
                "quarantine": {
                    "reason": "ADK regression — quarantined",
                    "anomaly_score": 0.94,
                    "contributing_features": [],
                    "model_version": None,
                    "policy_id": "adk.kill",
                },
            },
        }
    )
    plugin.apdp.preflight_step = AsyncMock(
        return_value={"preflight": {"allowed": True}}
    )
    # Mark plugin ready so the callback doesn't try to bootstrap.
    plugin._initialized = True
    plugin._current_agent_id = "agent-uuid"
    plugin._current_agent_slug = "agent-x"
    plugin._current_execution_id = "exec_test"
    return plugin, registry


@pytest.mark.asyncio
async def test_before_tool_callback_quarantine_fires_kill_signal() -> None:
    """When wl-apdp returns Quarantine, ``before_tool_callback`` MUST
    invoke the kill-signal registry's ``cancel("quarantine")`` so any
    in-flight LLM call from the agent's framework is aborted.
    """
    plugin, registry = _plugin_armed_for_quarantine()

    result = await plugin.before_tool_callback(
        tool=_stub_tool("scanner"),
        tool_args={"query": "test"},
        tool_context=None,
    )
    # Yield so the asyncio.create_task scheduled by
    # ``_fire_kill_signal_quarantine`` runs.
    await asyncio.sleep(0)

    # The callback returns a strongly-worded block dict (ADK contract).
    assert isinstance(result, dict)
    assert "AGENT QUARANTINED" in result.get("result", "")
    # The kill signal fired with the canonical reason.
    assert registry.cancel_calls == [LLM_CALL_INTERRUPTED_REASON_QUARANTINE], (
        f"expected one 'quarantine' cancel; got {registry.cancel_calls!r}"
    )
    # Denied counter incremented.
    assert plugin._denied_count == 1


@pytest.mark.asyncio
async def test_before_tool_callback_quarantine_blocks_tool() -> None:
    """The returned dict must convey the quarantine state to ADK's
    framework — the agent gets a strongly-worded "AGENT QUARANTINED"
    instruction in the tool result, telling it to stop.
    """
    plugin, _registry = _plugin_armed_for_quarantine()

    result = await plugin.before_tool_callback(
        tool=_stub_tool("scanner"),
        tool_args={},
        tool_context=None,
    )

    assert result is not None
    body = result.get("result", "")
    assert "AGENT QUARANTINED" in body
    assert "Watchlight" in body
    # Opaque deny: the server's reason stays in its audit trail.
    assert "ADK regression" not in body


def test_kill_signal_registry_is_wired_by_default() -> None:
    """The shipped default is ON.

    Leaving the registry unwired made the quarantine callback's
    kill-switch invocation a SILENT no-op. A live registry costs
    nothing until an interceptor registers a request, and proxy-side
    escalation stays opt-in so a zero-infrastructure run is
    unaffected.
    """
    from watchlight_core import InterceptorKillRegistry

    # Construct directly — `_plugin_armed_for_quarantine` overwrites
    # the registry with a counting stub.
    plugin = WatchlightPlugin(
        apdp_url="http://localhost:8081",
        agent_slug="agent-research-analyst",
        root_agent_name="research_analyst",
    )
    assert isinstance(plugin.kill_signal_registry, InterceptorKillRegistry)
    # Degrades safely — no escalator means no network, no credentials.
    assert plugin.kill_signal_registry.hard_kill_available is False


@pytest.mark.asyncio
async def test_plugin_without_registry_does_not_raise() -> None:
    """ADK plugin without ``kill_signal_registry`` wired continues to
    work; the kill-signal call is a no-op.
    """
    plugin, _ = _plugin_armed_for_quarantine()
    plugin.kill_signal_registry = None  # explicit unwire

    result = await plugin.before_tool_callback(
        tool=_stub_tool("scanner"),
        tool_args={},
        tool_context=None,
    )
    # Still blocks the call.
    assert "AGENT QUARANTINED" in result.get("result", "")
