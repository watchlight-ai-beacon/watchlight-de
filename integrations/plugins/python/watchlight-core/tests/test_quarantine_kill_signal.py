"""Kill-signal invocation on Quarantine transition.

These tests verify the load-bearing handover between the quarantine
state machine and the kill-signal protocol:

- When wl-apdp returns Quarantine, the handle calls
  ``plugin.kill_signal_registry.cancel("quarantine")`` BEFORE raising
  :class:`AgentQuarantinedError`.
- The kill-signal invocation is idempotent on the short-circuit path —
  every subsequent ``authorize_action`` / ``spawn_subagent`` on the
  QUARANTINED handle fires the registry again so late-arriving LLM
  calls (e.g. the agent's framework retried an HTTP request after
  the first quarantine raise) also get aborted.
- Parent-chain propagation cascades the kill signal — every ancestor
  with an in-flight LLM call gets its registry fired.
- Plugins without a registry (``kill_signal_registry = None`` or
  attribute absent) continue to work unchanged.

The registry is replaced with a counting stub so the test asserts on
the call shape directly rather than driving a real interceptor.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any, List, Optional

import pytest
import pytest_asyncio

from watchlight_core import (
    AgentQuarantinedError,
    BaseRunHandle,
    LLM_CALL_INTERRUPTED_REASON_QUARANTINE,
    RunHandleState,
)
from watchlight_core.telemetry import GovernanceTelemetry
from watchlight_core_testing import MockApdpClient


# ─── Stub kill-signal registry ──────────────────────────────────────


@dataclass
class _CountingKillRegistry:
    """Replacement for :class:`InterceptorKillRegistry` that counts
    ``cancel`` calls so tests can assert on invocation shape directly.

    Mirrors the registry's ``async def cancel(reason: str)`` signature
    so the production code path doesn't branch on the registry type.
    """

    cancel_calls: List[str] = field(default_factory=list)

    async def cancel(self, reason: str) -> list:
        self.cancel_calls.append(reason)
        return []


# ─── Plugin fixtures ────────────────────────────────────────────────


class _Plugin(GovernanceTelemetry):
    """Minimal plugin satisfying the GovernedPlugin Protocol + the
    ``kill_signal_registry`` attribute.
    """

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
    # synthetic test handle bypasses the production ``async with`` entry
    # path; flip the fail-closed flag so the contract guard accepts the
    # test's direct authorize calls.
    h._aentered = True
    return h


def _quarantine_payload() -> dict:
    return {
        "reason": "regression payload",
        "anomaly_score": 0.93,
        "contributing_features": [],
        "model_version": None,
        "policy_id": "kill.signal.test",
    }


# ─── Test 1 — Quarantine response fires kill signal ────────────────


@pytest.mark.asyncio
async def test_quarantine_response_fires_kill_signal_with_quarantine_reason(
    plugin: _Plugin, handle: BaseRunHandle, registry: _CountingKillRegistry,
) -> None:
    """**Load-bearing test for the quarantine kill signal.**

    When wl-apdp returns Quarantine, the SDK MUST call
    ``plugin.kill_signal_registry.cancel("quarantine")`` so any
    in-flight LLM call from the plugin's HTTP interceptor lane is
    aborted within the graceful window (2s default).

    The cancel reason MUST be the canonical
    ``LLM_CALL_INTERRUPTED_REASON_QUARANTINE`` string ("quarantine")
    so SIEM rules that grep on the disposition correlate the
    interrupt with its trigger.
    """
    plugin.apdp.default_decision = "Quarantine"
    plugin.apdp.quarantine_payload = _quarantine_payload()

    assert registry.cancel_calls == []

    with pytest.raises(AgentQuarantinedError):
        await handle.authorize_action("execute", "Tool::scanner")

    # Yield so the asyncio.create_task scheduled by ``_fire_kill_signal``
    # can run — the kill cancel is non-blocking on the SDK side.
    await asyncio.sleep(0)

    assert registry.cancel_calls == [LLM_CALL_INTERRUPTED_REASON_QUARANTINE], (
        f"kill_signal_registry.cancel was called "
        f"{len(registry.cancel_calls)} time(s) with reasons "
        f"{registry.cancel_calls!r}; expected exactly one "
        f"'quarantine' invocation"
    )
    assert handle.state == RunHandleState.QUARANTINED


# ─── Test 2 — short-circuit path re-fires kill signal ──────────────


@pytest.mark.asyncio
async def test_short_circuit_authorize_call_re_fires_kill_signal(
    plugin: _Plugin, handle: BaseRunHandle, registry: _CountingKillRegistry,
) -> None:
    """The short-circuit path (handle already in QUARANTINED) MUST also
    fire the kill signal. A late-arriving LLM call that started AFTER
    the original transition (e.g. agent framework retried HTTP) needs
    to be aborted too — the kill switch is idempotent on the registry
    side, but the SDK must call it on every quarantine-raising path.
    """
    plugin.apdp.default_decision = "Quarantine"
    plugin.apdp.quarantine_payload = _quarantine_payload()

    with pytest.raises(AgentQuarantinedError):
        await handle.authorize_action("execute", "Tool::scanner")
    await asyncio.sleep(0)
    assert len(registry.cancel_calls) == 1

    # Now the short-circuit path on the second + third calls — both
    # should re-fire the kill signal.
    for _ in range(2):
        with pytest.raises(AgentQuarantinedError):
            await handle.authorize_action("execute", "Tool::scanner")
        await asyncio.sleep(0)

    # 1 transition + 2 short-circuit = 3 total
    assert len(registry.cancel_calls) == 3, registry.cancel_calls
    # The wl-apdp call counter MUST NOT have advanced past the first
    # transition — the conformance #11 invariant (no fall-through to
    # wl-apdp on a quarantined handle).
    assert len(plugin.apdp.authorize_calls) == 1


# ─── Test 3 — spawn_subagent while quarantined fires kill signal ────


@pytest.mark.asyncio
async def test_spawn_subagent_while_quarantined_fires_kill_signal(
    plugin: _Plugin, handle: BaseRunHandle, registry: _CountingKillRegistry,
) -> None:
    """The spawn-attempted-while-quarantined path also fires the kill
    signal. The orchestrator framework may have an in-flight planner
    LLM call when it tries to spawn a sub-agent; that call must be
    aborted by the kill signal too.
    """
    plugin.apdp.default_decision = "Quarantine"
    plugin.apdp.quarantine_payload = _quarantine_payload()

    with pytest.raises(AgentQuarantinedError):
        await handle.authorize_action("execute", "Tool::scanner")
    await asyncio.sleep(0)
    assert len(registry.cancel_calls) == 1

    # spawn_subagent uses the kwargs-only canonical signature; the
    # quarantine short-circuit still fires before any APDP round-trip
    # so the child UUID is the only positional arg required.
    with pytest.raises(AgentQuarantinedError):
        await handle.spawn_subagent(
            "11111111-1111-1111-1111-111111111111",
        child_intent={"category": "research", "objective": "Delegated sub-task"},
        )
    await asyncio.sleep(0)
    # 1 transition + 1 short-circuit on spawn = 2 total
    assert len(registry.cancel_calls) == 2, registry.cancel_calls


# ─── Test 4 — parent-chain cascade fires every registry ─────────────


@pytest.mark.asyncio
async def test_parent_chain_cascade_fires_every_registry() -> None:
    """**Locked decision #2 — bag-the-agent-not-the-branch.**

    When a sub-agent quarantines, every ancestor handle's
    ``kill_signal_registry`` MUST also fire so an in-flight LLM call
    on the parent (e.g. an orchestrator waiting on a planner response)
    is aborted too. Different ancestors may sit on different plugin
    instances with different registries; the cascade fires each one.
    """
    parent_registry = _CountingKillRegistry()
    child_registry = _CountingKillRegistry()

    parent_plugin = _Plugin(kill_signal_registry=parent_registry)
    child_plugin = _Plugin(kill_signal_registry=child_registry)

    parent = BaseRunHandle(
        plugin=parent_plugin, agent_uuid="uuid-root", session_id="ses_root"
    )
    parent._aentered = True  # synthetic test handle
    child = BaseRunHandle(
        plugin=child_plugin,
        agent_uuid="uuid-child",
        session_id="ses_child",
        parent_handle=parent,
    )
    child._aentered = True  # synthetic test handle

    child_plugin.apdp.default_decision = "Quarantine"
    child_plugin.apdp.quarantine_payload = _quarantine_payload()

    with pytest.raises(AgentQuarantinedError):
        await child.authorize_action("execute", "Tool::scanner")
    await asyncio.sleep(0)

    # Child's registry fired on its own transition.
    assert child_registry.cancel_calls == [LLM_CALL_INTERRUPTED_REASON_QUARANTINE], (
        f"child registry expected one cancel; got "
        f"{child_registry.cancel_calls!r}"
    )
    # Parent's registry fired via the cascade.
    assert parent_registry.cancel_calls == [LLM_CALL_INTERRUPTED_REASON_QUARANTINE], (
        f"parent registry expected one cancel via cascade; got "
        f"{parent_registry.cancel_calls!r}"
    )
    assert parent.state == RunHandleState.QUARANTINED
    assert child.state == RunHandleState.QUARANTINED


# ─── Test 5 — plugin without registry is a no-op ─────────────────────


@pytest.mark.asyncio
async def test_quarantine_without_registry_does_not_raise() -> None:
    """Plugins that do NOT wire a kill_signal_registry (legacy plugin,
    test fixture without CONNECT mode, demo plugin without interceptor)
    must continue to work — the kill-signal invocation is a no-op when
    no registry is wired.

    Regression: if ``_fire_kill_signal`` raised on missing registry, it
    would break every plugin until they migrate, which violates the
    "no breaking change without migration window" rule.
    """
    plugin_no_registry = _Plugin(kill_signal_registry=None)
    h = BaseRunHandle(
        plugin=plugin_no_registry,
        agent_uuid="uuid-x",
        session_id="ses_x",
    )
    h._aentered = True  # synthetic test handle
    plugin_no_registry.apdp.default_decision = "Quarantine"
    plugin_no_registry.apdp.quarantine_payload = _quarantine_payload()

    # Must raise the typed error normally.
    with pytest.raises(AgentQuarantinedError):
        await h.authorize_action("execute", "Tool::scanner")
    assert h.state == RunHandleState.QUARANTINED

    # Short-circuit path also OK without a registry.
    with pytest.raises(AgentQuarantinedError):
        await h.authorize_action("execute", "Tool::scanner")


# ─── Test 6 — full flow — no further APDP calls ─────────────────────


@pytest.mark.asyncio
async def test_full_flow_quarantine_kill_signal_then_no_further_apdp_calls(
    plugin: _Plugin, handle: BaseRunHandle, registry: _CountingKillRegistry,
) -> None:
    """End-to-end load-bearing check for the quarantine kill signal —
    exactly what the prompt's pre-merge checklist asks for:

    1. wl-apdp returns Quarantine → state flips to QUARANTINED.
    2. kill_signal_registry.cancel("quarantine") fires.
    3. AgentQuarantinedError raised.
    4. 10 more authorize_action calls → all raise, none round-trip,
       kill_signal fires on every one.
    """
    plugin.apdp.default_decision = "Quarantine"
    plugin.apdp.quarantine_payload = _quarantine_payload()

    # Step 1 — the originating call.
    with pytest.raises(AgentQuarantinedError):
        await handle.authorize_action("execute", "Tool::a")
    await asyncio.sleep(0)

    assert handle.state == RunHandleState.QUARANTINED
    assert len(registry.cancel_calls) == 1
    assert registry.cancel_calls[-1] == LLM_CALL_INTERRUPTED_REASON_QUARANTINE
    assert len(plugin.apdp.authorize_calls) == 1

    # Steps 2–11 — short-circuit.
    for i in range(10):
        with pytest.raises(AgentQuarantinedError):
            await handle.authorize_action(f"execute_{i}", f"Tool::b{i}")
        await asyncio.sleep(0)

    # No further APDP round trips.
    assert len(plugin.apdp.authorize_calls) == 1
    # Kill signal fired on every short-circuit too — 1 + 10 = 11.
    assert len(registry.cancel_calls) == 11
    assert all(
        r == LLM_CALL_INTERRUPTED_REASON_QUARANTINE for r in registry.cancel_calls
    )
