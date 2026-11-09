"""Bedrock plugin Quarantine handling + kill-signal cascade.

The Bedrock plugin has TWO authorize paths:

1. **Orchestrator side** — :class:`RunHandle` is a thin
   :class:`watchlight_core.BaseRunHandle` subclass, so the
   kill-signal fires automatically via the SDK's
   ``_fire_kill_signal`` hook on quarantine transition. We test
   it the same way we test LangGraph (mock APDP, mock registry,
   assert cancel call).

2. **Lambda action-group side** — bypasses BaseRunHandle and calls
   ``plugin.apdp.authorize`` directly. The decorator wires
   ``_fire_kill_signal_best_effort`` explicitly so the kill signal
   still fires when the Lambda's wl-apdp call returns Quarantine.
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
from watchlight_bedrock import WatchlightBedrockPlugin


def _quarantine_payload() -> dict:
    return {
        "reason": "Bedrock regression — agent quarantined for anomalous behavior",
        "anomaly_score": 0.95,
        "contributing_features": [],
        "model_version": None,
        "policy_id": "anomaly.bedrock.kill",
    }


class _CountingRegistry:
    def __init__(self) -> None:
        self.cancel_calls: List[str] = []

    async def cancel(self, reason: str) -> list:
        self.cancel_calls.append(reason)
        return []


# ─── Orchestrator path (BaseRunHandle inheritance) ──────────────────


@pytest.mark.asyncio
async def test_orchestrator_quarantine_fires_kill_signal() -> None:
    """The orchestrator's RunHandle, on Quarantine, fires the kill
    signal so the in-flight ``invoke_agent`` call (and any downstream
    LLM stream) is aborted.
    """
    plugin = WatchlightBedrockPlugin(apdp_url="http://localhost:8081")
    plugin.apdp = MockApdpClient()
    plugin.apdp.known_agents["agent-x"] = "uuid-x"
    plugin.apdp.default_decision = "Quarantine"
    plugin.apdp.quarantine_payload = _quarantine_payload()
    registry = _CountingRegistry()
    plugin.kill_signal_registry = registry

    handle = await plugin.start_run("agent-x")
    handle._aentered = True  # synthetic test handle bypasses async-enter
    with pytest.raises(AgentQuarantinedError):
        await handle.authorize_action("execute", "Tool::scanner")
    await asyncio.sleep(0)

    assert registry.cancel_calls == [LLM_CALL_INTERRUPTED_REASON_QUARANTINE]


@pytest.mark.asyncio
async def test_orchestrator_short_circuit_re_fires_kill_signal() -> None:
    """Subsequent authorize calls on a quarantined Bedrock orchestrator
    handle must re-fire the kill signal AND not round-trip to wl-apdp.
    """
    plugin = WatchlightBedrockPlugin(apdp_url="http://localhost:8081")
    plugin.apdp = MockApdpClient()
    plugin.apdp.known_agents["agent-x"] = "uuid-x"
    plugin.apdp.default_decision = "Quarantine"
    plugin.apdp.quarantine_payload = _quarantine_payload()
    registry = _CountingRegistry()
    plugin.kill_signal_registry = registry

    handle = await plugin.start_run("agent-x")
    handle._aentered = True  # synthetic test handle bypasses async-enter
    with pytest.raises(AgentQuarantinedError):
        await handle.authorize_action("execute", "Tool::a")
    await asyncio.sleep(0)

    for _ in range(3):
        with pytest.raises(AgentQuarantinedError):
            await handle.authorize_action("execute", "Tool::b")
        await asyncio.sleep(0)

    assert len(registry.cancel_calls) == 4
    assert len(plugin.apdp.authorize_calls) == 1


# ─── Lambda decorator path (bypasses BaseRunHandle) ──────────────────


def test_lambda_decorator_path_fires_kill_signal_best_effort() -> None:
    """The Lambda action-group decorator calls ``apdp.authorize``
    directly (no BaseRunHandle in the loop). The wiring in
    ``_fire_kill_signal_best_effort`` must fire the registry when
    wl-apdp returns Quarantine.

    The helper is sync (Lambda handlers run in a sync entry point and
    use ``asyncio.run`` to bridge into the async APDP client) so this
    test is also sync — mirrors the real Lambda code path.
    """
    from watchlight_bedrock.plugin import _fire_kill_signal_best_effort

    plugin = WatchlightBedrockPlugin(apdp_url="http://localhost:8081")
    registry = _CountingRegistry()
    plugin.kill_signal_registry = registry

    # Direct invocation — what the decorator does when wl-apdp says
    # Quarantine. The Lambda runs in its own ``asyncio.run`` scope, so
    # the helper's ``_run(registry.cancel(...))`` is safe here.
    _fire_kill_signal_best_effort(plugin)

    assert registry.cancel_calls == [LLM_CALL_INTERRUPTED_REASON_QUARANTINE], (
        f"expected one 'quarantine' cancel; got {registry.cancel_calls!r}"
    )


def test_kill_signal_registry_is_wired_by_default() -> None:
    """The shipped default is ON.

    Leaving the registry unwired made the quarantine path a SILENT
    no-op. A live registry costs nothing until an interceptor
    registers a request, and proxy-side escalation stays opt-in so a
    zero-infrastructure Lambda run is unaffected.
    """
    from watchlight_core import InterceptorKillRegistry

    plugin = WatchlightBedrockPlugin(apdp_url="http://localhost:8081")
    assert isinstance(plugin.kill_signal_registry, InterceptorKillRegistry)
    # Degrades safely — no escalator means no network, no credentials.
    assert plugin.kill_signal_registry.hard_kill_available is False


def test_lambda_path_no_registry_is_noop() -> None:
    """With the registry explicitly unwired the helper is a no-op —
    defensive for Bedrock deployments that opt out.
    """
    from watchlight_bedrock.plugin import _fire_kill_signal_best_effort

    plugin = WatchlightBedrockPlugin(apdp_url="http://localhost:8081")
    plugin.kill_signal_registry = None  # explicit unwire

    # Must not raise.
    _fire_kill_signal_best_effort(plugin)
