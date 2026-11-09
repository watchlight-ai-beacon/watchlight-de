"""The tool gate: every tool call is authorized on the invocation's own
run before it runs, and anything but allow stops it."""

from __future__ import annotations

import asyncio
from typing import Any, AsyncGenerator, List

import pytest
from conftest import SECRET, ScriptedModel, events_of, resources, text, tool_call
from strands import Agent, tool
from strands.hooks import BeforeToolCallEvent, HookOrder
from strands.tools.executors import SequentialToolExecutor
from strands.types.exceptions import EventLoopException
from watchlight_core import AgentQuarantinedError
from watchlight_core_testing import MockApdpClient

ran: List[str] = []


@pytest.fixture(autouse=True)
def _reset_ran() -> None:
    ran.clear()


@tool
def lookup(q: str) -> str:
    """Look something up."""
    ran.append(f"lookup:{q}")
    return "found"


@tool
def delete_records(table: str) -> str:
    """Delete records."""
    ran.append(f"delete:{table}")
    return "deleted"


@tool
async def fetch_async(url: str) -> str:
    """An async tool."""
    ran.append("fetch_async")
    return "fetched"


@tool
async def stream_rows(n: int) -> AsyncGenerator[Any, None]:
    """A streaming tool."""
    ran.append("stream_rows")
    for i in range(n):
        yield f"row {i}"
    yield "rows done"


def _agent(make_plugin, model, tools, **kwargs) -> Agent:
    return Agent(
        model=model,
        tools=tools,
        plugins=[make_plugin("agent-root")],
        callback_handler=None,
        **kwargs,
    )


def test_allowed_tool_runs_and_only_shape_leaves_the_process(make_plugin, mock_apdp: MockApdpClient):
    model = ScriptedModel([[tool_call("lookup", {"q": SECRET})], [text("ok")]])
    agent = _agent(make_plugin, model, [lookup])

    agent("find it")

    assert ran == [f"lookup:{SECRET}"]
    assert resources(mock_apdp) == ["lookup"]
    ctx = mock_apdp.authorize_calls[0]["context"]
    assert ctx["tool_args"] == {"arg_count": 1, "arg_names": ["q"], "arg_types": {"q": "str"}}
    assert SECRET not in repr(mock_apdp.authorize_calls)
    observed = events_of(mock_apdp, "tool_call_observed")
    assert len(observed) == 1 and observed[0]["payload"]["decision"] == "Allow"
    assert observed[0]["payload"]["tool"]["endpoint"] == "strands://tool/lookup"
    assert SECRET not in repr(mock_apdp.published_events)


def test_denied_tool_never_runs(make_plugin, mock_apdp: MockApdpClient):
    mock_apdp.decisions[("execute", "delete_records")] = "Deny"
    model = ScriptedModel([[tool_call("delete_records", {"table": "users"})], [text("ok")]])
    agent = _agent(make_plugin, model, [delete_records])

    result = agent("clean up")

    assert ran == []
    assert result.stop_reason == "end_turn"
    assert any("Denied by Watchlight policy" in t for t in model.tool_result_texts())
    observed = events_of(mock_apdp, "tool_call_observed")
    assert [e["payload"]["decision"] for e in observed] == ["Deny"]


def test_transport_error_cancels_the_call(make_plugin, mock_apdp: MockApdpClient, monkeypatch):
    async def broken(*args: Any, **kwargs: Any) -> Any:
        raise ConnectionError("wl-apdp unreachable")

    monkeypatch.setattr(mock_apdp, "authorize", broken)
    model = ScriptedModel([[tool_call("lookup", {"q": "a"})], [text("ok")]])
    agent = _agent(make_plugin, model, [lookup])

    agent("go")

    assert ran == []
    assert any("could not be completed" in t or "Denied" in t for t in model.tool_result_texts())


def test_authorize_timeout_cancels_the_call(make_plugin, mock_apdp: MockApdpClient, monkeypatch):
    async def slow(*args: Any, **kwargs: Any) -> Any:
        await asyncio.sleep(5)
        return {"decision": "Allow", "details": {}}

    monkeypatch.setattr(mock_apdp, "authorize", slow)
    model = ScriptedModel([[tool_call("lookup", {"q": "a"})], [text("ok")]])
    agent = Agent(
        model=model,
        tools=[lookup],
        plugins=[make_plugin("agent-root", authorize_timeout_seconds=0.05)],
        callback_handler=None,
    )

    agent("go")

    assert ran == []
    assert any("could not be completed" in t for t in model.tool_result_texts())


def test_quarantine_ends_the_invocation(make_plugin, mock_apdp: MockApdpClient):
    mock_apdp.decisions[("execute", "lookup")] = "Quarantine"
    model = ScriptedModel([[tool_call("lookup", {"q": "a"})], [text("ok")]])
    agent = _agent(make_plugin, model, [lookup])

    with pytest.raises(Exception) as excinfo:
        agent("go")

    chain = []
    exc: Any = excinfo.value
    while exc is not None:
        chain.append(type(exc))
        exc = exc.__cause__ or exc.__context__
    assert AgentQuarantinedError in chain
    assert ran == []
    assert model.calls == 1, "no further model turn after the quarantine"
    # The run was closed on the way out.
    assert mock_apdp._closed_sessions


@pytest.mark.parametrize("executor", [None, SequentialToolExecutor()])
def test_concurrent_calls_are_each_authorized(make_plugin, mock_apdp: MockApdpClient, executor):
    mock_apdp.decisions[("execute", "delete_records")] = "Deny"
    model = ScriptedModel(
        [[tool_call("lookup", {"q": "one"}), tool_call("delete_records", {"table": "t"}), tool_call("lookup", {"q": "two"})], [text("ok")]]
    )
    kwargs = {"tool_executor": executor} if executor is not None else {}
    agent = _agent(make_plugin, model, [lookup, delete_records], **kwargs)

    agent("go")

    assert sorted(ran) == ["lookup:one", "lookup:two"]
    assert sorted(resources(mock_apdp)) == ["delete_records", "lookup", "lookup"]


def test_async_and_streaming_tools_are_gated(make_plugin, mock_apdp: MockApdpClient):
    mock_apdp.decisions[("execute", "stream_rows")] = "Deny"
    model = ScriptedModel(
        [[tool_call("fetch_async", {"url": "u"}), tool_call("stream_rows", {"n": 3})], [text("ok")]]
    )
    agent = _agent(make_plugin, model, [fetch_async, stream_rows])

    asyncio.run(agent.invoke_async("go"))

    assert ran == ["fetch_async"]
    assert sorted(resources(mock_apdp)) == ["fetch_async", "stream_rows"]


def test_stream_async_entry_point_is_governed(make_plugin, mock_apdp: MockApdpClient):
    mock_apdp.default_decision = "Deny"
    model = ScriptedModel([[tool_call("lookup", {"q": "a"})], [text("ok")]])
    agent = _agent(make_plugin, model, [lookup])

    async def consume() -> None:
        async for _ in agent.stream_async("go"):
            pass

    asyncio.run(consume())
    assert ran == []
    assert resources(mock_apdp) == ["lookup"]


def test_direct_tool_call_outside_an_invocation_is_refused(make_plugin, mock_apdp: MockApdpClient):
    agent = _agent(make_plugin, ScriptedModel(), [lookup])

    result = agent.tool.lookup(q="x")

    assert ran == []
    assert result["status"] == "error"
    assert mock_apdp.authorize_calls == []


def test_unknown_tool_is_refused_without_authorizing(make_plugin, mock_apdp: MockApdpClient):
    model = ScriptedModel([[tool_call("no_such_tool", {"x": 1})], [text("ok")]])
    agent = _agent(make_plugin, model, [lookup])

    agent("go")

    assert mock_apdp.authorize_calls == []
    assert any("not registered" in t for t in model.tool_result_texts())


def test_a_hook_that_swaps_the_tool_cannot_slip_past_the_gate(make_plugin, mock_apdp: MockApdpClient):
    """A user hook that runs at Strands' last SDK order still runs before
    the gate, so the gate authorizes what will actually run."""
    mock_apdp.decisions[("execute", "delete_records")] = "Deny"
    delete_tool = None

    def swap(event: BeforeToolCallEvent) -> None:
        event.selected_tool = delete_tool
        event.tool_use = {**event.tool_use, "name": "delete_records"}

    model = ScriptedModel([[tool_call("lookup", {"q": "a"})], [text("ok")]])
    agent = _agent(make_plugin, model, [lookup, delete_records])
    delete_tool = agent.tool_registry.registry["delete_records"]
    agent.hooks.add_callback(BeforeToolCallEvent, swap, order=HookOrder.SDK_LAST)

    agent("go")

    assert ran == []
    assert resources(mock_apdp) == ["delete_records"]


def test_an_inconsistent_tool_rewrite_is_refused(make_plugin, mock_apdp: MockApdpClient):
    def swap_only_the_object(event: BeforeToolCallEvent) -> None:
        event.selected_tool = event.agent.tool_registry.registry["delete_records"]

    model = ScriptedModel([[tool_call("lookup", {"q": "a"})], [text("ok")]])
    agent = _agent(make_plugin, model, [lookup, delete_records])
    agent.hooks.add_callback(BeforeToolCallEvent, swap_only_the_object)

    agent("go")

    assert ran == []
    assert mock_apdp.authorize_calls == []


def test_a_raising_user_hook_stops_the_call_and_closes_the_run(make_plugin, mock_apdp: MockApdpClient):
    def explode(event: BeforeToolCallEvent) -> None:
        raise RuntimeError("user hook failed")

    model = ScriptedModel([[tool_call("lookup", {"q": "a"})], [text("ok")]])
    agent = _agent(make_plugin, model, [lookup])
    agent.hooks.add_callback(BeforeToolCallEvent, explode)

    with pytest.raises((RuntimeError, EventLoopException), match="user hook failed"):
        agent("go")

    assert ran == []
    assert len(mock_apdp._terminated_sessions) == 1
    assert [e["event_type"] for e in mock_apdp.published_events][-1] == "execution_failed"


def test_a_call_another_hook_cancelled_is_not_authorized(make_plugin, mock_apdp: MockApdpClient):
    def cancel(event: BeforeToolCallEvent) -> None:
        event.cancel_tool = "cancelled by the application"

    model = ScriptedModel([[tool_call("lookup", {"q": "a"})], [text("ok")]])
    agent = _agent(make_plugin, model, [lookup])
    agent.hooks.add_callback(BeforeToolCallEvent, cancel)

    agent("go")

    assert ran == []
    assert mock_apdp.authorize_calls == []


def test_mcp_tools_are_gated(make_plugin, mock_apdp: MockApdpClient):
    from mcp.types import Tool as MCPTool
    from strands.tools.mcp import MCPAgentTool

    calls: List[str] = []

    # In-process stand-in for unit tests only: records calls, no server.
    class RecordingMCPClient:
        async def call_tool_async(self, tool_use_id: str, name: str, arguments: Any = None, **kwargs: Any) -> Any:
            calls.append(name)
            return {"toolUseId": tool_use_id, "status": "success", "content": [{"text": "mcp ok"}]}

    def mcp_tool(name: str) -> MCPAgentTool:
        spec = MCPTool(name=name, description=name, inputSchema={"type": "object", "properties": {"path": {"type": "string"}}})
        return MCPAgentTool(spec, RecordingMCPClient())  # type: ignore[arg-type]

    mock_apdp.decisions[("execute", "write_file")] = "Deny"
    model = ScriptedModel(
        [[tool_call("read_file", {"path": "/etc/hosts"}), tool_call("write_file", {"path": "/etc/hosts"})], [text("ok")]]
    )
    agent = _agent(make_plugin, model, [mcp_tool("read_file"), mcp_tool("write_file")])

    agent("go")

    assert calls == ["read_file"]
    assert sorted(resources(mock_apdp)) == ["read_file", "write_file"]
    endpoints = [e["payload"]["tool"]["endpoint"] for e in events_of(mock_apdp, "tool_call_observed")]
    assert "strands://mcp/read_file" in endpoints


def test_a_swap_after_the_gate_is_detected_and_its_result_withheld(make_plugin, mock_apdp: MockApdpClient):
    """Only a hook registered after the plugin at an infinite order runs
    after the gate. Such a swap is outside what the gate can stop; the
    plugin detects it after the fact and withholds the result."""
    import math

    def late_swap(event: BeforeToolCallEvent) -> None:
        event.selected_tool = event.agent.tool_registry.registry["delete_records"]
        event.tool_use = {**event.tool_use, "name": "delete_records"}

    model = ScriptedModel([[tool_call("lookup", {"q": "a"})], [text("ok")]])
    agent = _agent(make_plugin, model, [lookup, delete_records])
    agent.hooks.add_callback(BeforeToolCallEvent, late_swap, order=math.inf)

    agent("go")

    assert resources(mock_apdp) == ["lookup"]
    assert "deleted" not in repr(model.seen_tool_results)
    assert any("changed which tool" in t for t in model.tool_result_texts())
