"""LangGraph plugin Quarantine handling + kill-signal cascade.

The LangGraph plugin inherits Quarantine semantics from
:class:`watchlight_core.BaseRunHandle`. The plugin wires
``plugin.kill_signal_registry`` into the transition so the
in-flight LLM call (whatever the LangGraph node was awaiting) is
aborted within the graceful shutdown window.

These tests drive the canonical path through ``guarded_tool_call``
+ ``RunHandle.authorize_action_detailed`` so we exercise the same
code path the customer's LangGraph workflow runs on every node.
"""

from __future__ import annotations

import asyncio
from typing import List

import pytest
import pytest_asyncio

from watchlight_core import (
    AgentQuarantinedError,
    LLM_CALL_INTERRUPTED_REASON_QUARANTINE,
)
from watchlight_core_testing import MockApdpClient
from watchlight_langgraph import WatchlightLangGraphPlugin


def _quarantine_payload() -> dict:
    return {
        "reason": "LangGraph regression — agent quarantined for anomalous behavior",
        "anomaly_score": 0.94,
        "contributing_features": [],
        "model_version": None,
        "policy_id": "anomaly.langgraph.kill",
    }


class _CountingRegistry:
    """Stand-in for :class:`InterceptorKillRegistry` so we can assert
    on the cancel-call shape without instantiating the real registry
    (which would try to talk to wl-proxy on the hard-kill path).
    """

    def __init__(self) -> None:
        self.cancel_calls: List[str] = []

    async def cancel(self, reason: str) -> list:
        self.cancel_calls.append(reason)
        return []


@pytest_asyncio.fixture
async def plugin_with_quarantine() -> tuple:
    """Plugin armed to return Quarantine on every authorize call, with
    a counting kill-signal registry wired in.
    """
    plugin = WatchlightLangGraphPlugin(apdp_url="http://localhost:8081")
    plugin.apdp = MockApdpClient()
    plugin.apdp.known_agents["agent-x"] = "uuid-x"
    plugin.apdp.default_decision = "Quarantine"
    plugin.apdp.quarantine_payload = _quarantine_payload()
    registry = _CountingRegistry()
    plugin.kill_signal_registry = registry
    return plugin, registry


@pytest.mark.asyncio
async def test_quarantine_fires_kill_signal_via_guarded_tool_call_path(
    plugin_with_quarantine: tuple,
) -> None:
    """When the LangGraph plugin's authorize path returns Quarantine,
    the plugin MUST fire the kill signal so any in-flight LLM call
    from the node body (the LLM call the workflow was awaiting at the
    tool boundary) is aborted within ~2 seconds.
    """
    plugin, registry = plugin_with_quarantine

    handle = await plugin.start_run("agent-x")
    handle._aentered = True  # synthetic test handle
    with pytest.raises(AgentQuarantinedError):
        await handle.authorize_action("execute", "Tool::scanner")
    # Yield so the asyncio.create_task scheduled by ``_fire_kill_signal``
    # runs.
    await asyncio.sleep(0)

    assert registry.cancel_calls == [LLM_CALL_INTERRUPTED_REASON_QUARANTINE], (
        f"expected exactly one 'quarantine' cancel; got "
        f"{registry.cancel_calls!r}"
    )


@pytest.mark.asyncio
async def test_subsequent_authorize_calls_short_circuit_and_re_fire_kill_signal(
    plugin_with_quarantine: tuple,
) -> None:
    """After the first quarantine, subsequent authorize calls must
    short-circuit AND re-fire the kill signal — late-arriving LLM
    calls (agent retried HTTP after the first abort) must be killed too.
    """
    plugin, registry = plugin_with_quarantine

    handle = await plugin.start_run("agent-x")
    handle._aentered = True  # synthetic test handle
    with pytest.raises(AgentQuarantinedError):
        await handle.authorize_action("execute", "Tool::a")
    await asyncio.sleep(0)
    assert len(registry.cancel_calls) == 1

    # 3 more calls — every one short-circuits AND fires the kill signal.
    for _ in range(3):
        with pytest.raises(AgentQuarantinedError):
            await handle.authorize_action("execute", "Tool::b")
        await asyncio.sleep(0)

    assert len(registry.cancel_calls) == 4
    # Load-bearing invariant — no wl-apdp round-trip after the
    # first quarantine transition.
    assert len(plugin.apdp.authorize_calls) == 1


@pytest.mark.asyncio
async def test_kill_signal_registry_is_wired_by_default() -> None:
    """The shipped default is ON.

    Leaving the registry unwired made the quarantine transition a
    SILENT no-op. A live registry costs nothing until an interceptor
    registers a request, and proxy-side escalation stays opt-in so a
    zero-infrastructure run is unaffected.
    """
    from watchlight_core import InterceptorKillRegistry

    plugin = WatchlightLangGraphPlugin(apdp_url="http://localhost:8081")
    assert isinstance(plugin.kill_signal_registry, InterceptorKillRegistry)
    # Degrades safely — no escalator means no network, no credentials.
    assert plugin.kill_signal_registry.hard_kill_available is False


@pytest.mark.asyncio
async def test_plugin_without_registry_continues_to_work() -> None:
    """Plugins that explicitly unwire ``kill_signal_registry`` MUST
    still raise :class:`AgentQuarantinedError` normally; the
    kill-signal step is a (warned) no-op.
    """
    plugin = WatchlightLangGraphPlugin(apdp_url="http://localhost:8081")
    plugin.apdp = MockApdpClient()
    plugin.apdp.known_agents["agent-x"] = "uuid-x"
    plugin.apdp.default_decision = "Quarantine"
    plugin.apdp.quarantine_payload = _quarantine_payload()
    plugin.kill_signal_registry = None  # explicit unwire

    handle = await plugin.start_run("agent-x")
    handle._aentered = True  # synthetic test handle
    with pytest.raises(AgentQuarantinedError):
        await handle.authorize_action("execute", "Tool::scanner")
