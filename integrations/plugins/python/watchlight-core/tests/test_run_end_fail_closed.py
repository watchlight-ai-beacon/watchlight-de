"""A run-ending decision stops the handle for good.

After wl-apdp answers Terminate, Revoke, Quarantine or SeverSubtree,
every later ``authorize_action`` / ``publish_observation`` /
``spawn_subagent`` on that handle fails closed WITHOUT a round-trip,
and the server session is still closed.
"""

from __future__ import annotations

import uuid

import pytest

from watchlight_core import (
    AgentQuarantinedError,
    AgentRevokedError,
    BaseRunHandle,
    ExecutionTerminatedError,
    SubtreeSeveredError,
)
from watchlight_core.telemetry import GovernanceTelemetry
from watchlight_core_testing import MockApdpClient
from watchlight_core_testing import bind_test_run


class _Plugin(GovernanceTelemetry):
    def __init__(self) -> None:
        super().__init__()
        self.apdp = MockApdpClient()
        self.tenant_id = "tenant-acme"
        self.log_decisions = False
        self.kill_signal_registry = None


def _handle(plugin: _Plugin) -> BaseRunHandle:
    h = bind_test_run(BaseRunHandle(plugin=plugin, agent_uuid=str(uuid.uuid4()), session_id=f"ses_{uuid.uuid4()}", run_handle_id=str(uuid.uuid4())), "sst_root")
    h._aentered = True
    return h


_OBSERVATION = {
    "tool": {"resource_type": "tool", "identifier": "web_search"},
    "action": {"action": "execute"},
}

_CASES = [
    ("Terminate", ExecutionTerminatedError),
    ("Revoke", AgentRevokedError),
    ("Quarantine", AgentQuarantinedError),
    ("SeverSubtree", SubtreeSeveredError),
]


@pytest.mark.asyncio
@pytest.mark.parametrize("decision,error", _CASES, ids=[c[0] for c in _CASES])
async def test_authorize_after_run_ending_decision_fails_closed_without_round_trip(
    decision, error
) -> None:
    plugin = _Plugin()
    handle = _handle(plugin)
    plugin.apdp.default_decision = decision
    with pytest.raises(error):
        await handle.authorize_action("execute", "Tool::scanner")

    # The backend would now say Allow; the handle must not ask it.
    plugin.apdp.default_decision = "Allow"
    calls = len(plugin.apdp.authorize_calls)
    with pytest.raises(error):
        await handle.authorize_action("execute", "Tool::scanner")
    assert len(plugin.apdp.authorize_calls) == calls


@pytest.mark.asyncio
@pytest.mark.parametrize("decision,error", _CASES, ids=[c[0] for c in _CASES])
async def test_publish_after_run_ending_decision_fails_closed(decision, error) -> None:
    plugin = _Plugin()
    handle = _handle(plugin)
    plugin.apdp.default_decision = decision
    with pytest.raises(error):
        await handle.authorize_action("execute", "Tool::scanner")

    published = len(plugin.apdp.published_events)
    with pytest.raises(error):
        await handle.publish_observation("tool_call_observed", payload=_OBSERVATION)
    with pytest.raises(error):
        await handle.publish_observation_for_execution(
            "tool_call_observed",
            execution_id=handle.execution_id,
            payload=_OBSERVATION,
        )
    assert [
        e for e in plugin.apdp.published_events[published:]
        if e.get("event_type") == "tool_call_observed"
    ] == []


@pytest.mark.asyncio
@pytest.mark.parametrize("decision,error", _CASES, ids=[c[0] for c in _CASES])
async def test_spawn_after_run_ending_decision_fails_closed(decision, error) -> None:
    plugin = _Plugin()
    handle = _handle(plugin)
    plugin.apdp.default_decision = decision
    with pytest.raises(error):
        await handle.authorize_action("execute", "Tool::scanner")

    with pytest.raises(error):
        await handle.spawn_subagent(str(uuid.uuid4()), child_intent={"category": "research", "objective": "Delegated sub-task"}, allowed_tools=["t"])
    assert plugin.apdp.spawn_subagent_calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "decision,error",
    [c for c in _CASES if c[0] != "Quarantine"],
    ids=[c[0] for c in _CASES if c[0] != "Quarantine"],
)
async def test_run_ending_decision_closes_the_server_session(decision, error) -> None:
    plugin = _Plugin()
    handle = _handle(plugin)
    plugin.apdp.default_decision = decision
    with pytest.raises(error):
        await handle.authorize_action("execute", "Tool::scanner")
    assert handle.session_id in plugin.apdp._closed_sessions


@pytest.mark.asyncio
async def test_quarantined_handle_session_is_closed_on_complete() -> None:
    plugin = _Plugin()
    handle = _handle(plugin)
    plugin.apdp.default_decision = "Quarantine"
    with pytest.raises(AgentQuarantinedError):
        await handle.authorize_action("execute", "Tool::scanner")
    await handle.complete()
    assert handle.session_id in plugin.apdp._closed_sessions


@pytest.mark.asyncio
async def test_severed_descendant_session_is_closed_and_handle_refuses() -> None:
    plugin = _Plugin()
    root = _handle(plugin)
    child = await root.spawn_subagent(str(uuid.uuid4()), child_intent={"category": "research", "objective": "Delegated sub-task"}, allowed_tools=["t"])
    plugin.apdp.default_decision = "SeverSubtree"
    with pytest.raises(SubtreeSeveredError):
        await root.authorize_action("execute", "Tool::scanner")
    # Let the scheduled background close run.
    import asyncio

    for _ in range(5):
        await asyncio.sleep(0)
    assert child.session_id in plugin.apdp._closed_sessions
    plugin.apdp.default_decision = "Allow"
    with pytest.raises(SubtreeSeveredError):
        await child.authorize_action("execute", "Tool::scanner")
