"""Every ROOT run records its terminal lineage event.

A governed run closes under its OWN handle: ``execution_completed`` (or
``execution_failed``) for the run's execution, under the run's own
agent, published with the run's own ``sst_`` credential, before the hook
returns. Before the fix the live deepagents lane had 9 root runs and 0
terminal events:

* on a real ``deepagents`` graph the run token ``abefore_agent`` returned
  was dropped (no middleware declared the state key), so ``aafter_agent``
  found no token and never closed the run (and every tool call was
  refused for want of a handle);
* a run that raised never reached ``aafter_agent`` at all.

The stub-driven tests pin the hook contract; the real-graph tests (skipped
without ``deepagents``) drive ``create_governed_deep_agent`` end to end.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

import pytest

from conftest import (
    CHILD_UUID,
    ROOT_UUID,
    RecordingHandler,
    StubModelRequest,
    make_child_middleware,
    make_root_middleware,
    make_tool_call_request,
    start_root,
)
from watchlight_deepagents.middleware import _HANDLE_REGISTRY, STATE_TOKEN_KEY

TERMINAL = ("execution_completed", "execution_failed")


def _handle(state: Dict[str, Any]) -> Any:
    return _HANDLE_REGISTRY[state[STATE_TOKEN_KEY]].handle


def _terminals(mock_apdp: Any, execution_id: str) -> List[Tuple[Dict[str, Any], Optional[str]]]:
    """Terminal events for ``execution_id`` with the credential each rode."""
    return [
        (event, token)
        for token, batch in mock_apdp.published_event_batches
        for event in batch
        if event.get("execution_id") == execution_id and event.get("event_type") in TERMINAL
    ]


def _assert_one_terminal(
    mock_apdp: Any, handle: Any, agent_uuid: str, event_type: str
) -> Dict[str, Any]:
    terminals = _terminals(mock_apdp, handle.execution_id)
    assert len(terminals) == 1, f"run needs exactly one terminal event, got {terminals}"
    event, token = terminals[0]
    assert event["event_type"] == event_type
    assert event["agent_id"] == agent_uuid
    assert token == mock_apdp.token_for(handle.run)
    _assert_every_run_closes_under_its_own_agent(mock_apdp)
    return event


def _assert_every_run_closes_under_its_own_agent(mock_apdp: Any) -> None:
    """The lineage structure rule, applied to everything published: every execution that
    published an ``execution_started`` has exactly one terminal event of
    its OWN, under the agent that started it and on the credential that
    started it, and no terminal event names an execution that never
    started."""
    published = [
        (event, token)
        for token, batch in mock_apdp.published_event_batches
        for event in batch
    ]
    starts = {
        event["execution_id"]: (event["agent_id"], token)
        for event, token in published
        if event.get("event_type") == "execution_started"
    }
    assert starts, "no run started"
    for execution_id, (agent_id, token) in starts.items():
        terminals = _terminals(mock_apdp, execution_id)
        assert [(e["agent_id"], t) for e, t in terminals] == [(agent_id, token)], (
            f"{execution_id} must close exactly once under its own agent "
            f"{agent_id} and credential {token}, got {terminals}"
        )
    for event, _ in published:
        if event.get("event_type") in TERMINAL:
            assert event["execution_id"] in starts, event


class _Boom(RuntimeError):
    pass


async def _raising_handler(request: Any) -> Any:
    raise _Boom("backend unavailable")


# ─── Stub-driven hook contract ────────────────────────────────────────


async def test_root_run_close_records_completion_under_the_root(plugin, mock_apdp):
    mw = make_root_middleware(plugin)
    state = await start_root(mw)
    root = _handle(state)
    await mw.awrap_tool_call(make_tool_call_request("search", state=state), RecordingHandler())

    await mw.aafter_agent(state, runtime=None)

    _assert_one_terminal(mock_apdp, root, ROOT_UUID, "execution_completed")
    assert state[STATE_TOKEN_KEY] not in _HANDLE_REGISTRY


async def test_root_run_with_a_denied_tool_records_completion(plugin, mock_apdp):
    mock_apdp.decisions[("execute", "transfer_funds")] = "Deny"
    mock_apdp.default_decision = "Deny"
    mw = make_root_middleware(plugin)
    state = await start_root(mw)
    root = _handle(state)
    handler = RecordingHandler()
    await mw.awrap_tool_call(make_tool_call_request("transfer_funds", state=state), handler)
    assert handler.ran is False

    await mw.aafter_agent(state, runtime=None)

    _assert_one_terminal(mock_apdp, root, ROOT_UUID, "execution_completed")


async def test_root_and_child_each_close_under_their_own_agent(plugin, mock_apdp):
    mock_apdp.default_decision = "Allow"
    root_mw = make_root_middleware(plugin)
    root_state = await start_root(root_mw)
    root = _handle(root_state)
    child_mw = make_child_middleware(plugin)
    seen: Dict[str, Any] = {}

    async def _run_child(request: Any) -> Any:
        child_state = await child_mw.abefore_agent({}, runtime=None)
        seen["child"] = _handle(child_state)
        await child_mw.awrap_tool_call(
            make_tool_call_request("summarize", state=child_state), RecordingHandler()
        )
        await child_mw.aafter_agent(child_state, runtime=None)
        return "ok"

    await root_mw.awrap_tool_call(
        make_tool_call_request("task", {"subagent_type": "researcher"}, state=root_state),
        _run_child,
    )
    child = seen["child"]
    await root_mw.aafter_agent(root_state, runtime=None)

    _assert_one_terminal(mock_apdp, child, CHILD_UUID, "execution_completed")
    _assert_one_terminal(mock_apdp, root, ROOT_UUID, "execution_completed")


async def test_a_tool_that_raises_closes_the_root_run_as_failed(plugin, mock_apdp):
    """LangGraph never runs ``after_agent`` for a run that raised."""
    mock_apdp.default_decision = "Allow"
    mw = make_root_middleware(plugin)
    state = await start_root(mw)
    root = _handle(state)

    with pytest.raises(_Boom):
        await mw.awrap_tool_call(make_tool_call_request("search", state=state), _raising_handler)

    event = _assert_one_terminal(mock_apdp, root, ROOT_UUID, "execution_failed")
    assert "_Boom" in event["payload"]["error"]
    assert state[STATE_TOKEN_KEY] not in _HANDLE_REGISTRY
    # A late after_agent (if a host ever runs one) does not add a second.
    await mw.aafter_agent(state, runtime=None)
    assert len(_terminals(mock_apdp, root.execution_id)) == 1


async def test_a_model_call_that_raises_closes_the_root_run_as_failed(plugin, mock_apdp):
    mw = make_root_middleware(plugin)
    state = await start_root(mw)
    root = _handle(state)

    with pytest.raises(_Boom):
        await mw.awrap_model_call(StubModelRequest(state=state), _raising_handler)

    _assert_one_terminal(mock_apdp, root, ROOT_UUID, "execution_failed")


async def test_a_failing_child_closes_the_child_and_then_the_root(plugin, mock_apdp):
    """The child's error unwinds through the parent's ``task`` call: the
    child closes as failed under the child, then the root under the root."""
    mock_apdp.default_decision = "Allow"
    root_mw = make_root_middleware(plugin, subagent_scopes={"researcher": {"allowed_tools": ["summarize"]}})
    root_state = await start_root(root_mw)
    root = _handle(root_state)
    child_mw = make_child_middleware(plugin)
    seen: Dict[str, Any] = {}

    async def _run_child(request: Any) -> Any:
        child_state = await child_mw.abefore_agent({}, runtime=None)
        seen["child"] = _handle(child_state)
        await child_mw.awrap_tool_call(
            make_tool_call_request("summarize", state=child_state), _raising_handler
        )

    with pytest.raises(_Boom):
        await root_mw.awrap_tool_call(
            make_tool_call_request("task", {"subagent_type": "researcher"}, state=root_state),
            _run_child,
        )

    _assert_one_terminal(mock_apdp, seen["child"], CHILD_UUID, "execution_failed")
    _assert_one_terminal(mock_apdp, root, ROOT_UUID, "execution_failed")


async def test_an_interrupt_does_not_close_the_run(plugin, mock_apdp):
    """``interrupt()`` pauses a run for a human; it does not end it."""
    errors = pytest.importorskip("langgraph.errors")
    mock_apdp.default_decision = "Allow"
    mw = make_root_middleware(plugin)
    state = await start_root(mw)
    root = _handle(state)

    async def _interrupting(request: Any) -> Any:
        raise errors.GraphInterrupt(())

    with pytest.raises(errors.GraphInterrupt):
        await mw.awrap_tool_call(make_tool_call_request("search", state=state), _interrupting)

    assert _terminals(mock_apdp, root.execution_id) == []
    assert state[STATE_TOKEN_KEY] in _HANDLE_REGISTRY
    await mw.aafter_agent(state, runtime=None)
    _assert_one_terminal(mock_apdp, root, ROOT_UUID, "execution_completed")


# ─── The real deepagents graph ────────────────────────────────────────


def _real_agent(plugin: Any, tool_name: str) -> Any:
    pytest.importorskip("deepagents", reason="deepagents not installed in this sandbox")
    from langchain_core.language_models.fake_chat_models import GenericFakeChatModel
    from langchain_core.messages import AIMessage
    from langchain_core.tools import tool

    from watchlight_deepagents import create_governed_deep_agent

    class _ScriptedModel(GenericFakeChatModel):
        """In-process stand-in for a chat model (tests only)."""

        def bind_tools(self, tools: Any, **kwargs: Any) -> Any:
            return self

    @tool
    def web_search(query: str) -> str:
        """Search the web."""
        return "results"

    @tool
    def flaky_search(query: str) -> str:
        """A search whose backend is down."""
        raise _Boom("backend unavailable")

    turns = iter(
        [
            AIMessage(
                content="",
                tool_calls=[{"name": tool_name, "args": {"query": "q"}, "id": "c1", "type": "tool_call"}],
            ),
            AIMessage(content="done"),
        ]
    )
    return create_governed_deep_agent(
        model=_ScriptedModel(messages=turns),
        tools=[web_search, flaky_search],
        agent_slug="research-orchestrator",
        plugin=plugin,
    )


def _root_terminal_events(mock_apdp: Any) -> List[Tuple[Dict[str, Any], Optional[str]]]:
    started = [
        e for e in mock_apdp.published_events
        if e.get("event_type") == "execution_started" and e.get("agent_id") == ROOT_UUID
    ]
    assert len(started) == 1
    _assert_every_run_closes_under_its_own_agent(mock_apdp)
    return _terminals(mock_apdp, started[0]["execution_id"])


async def test_a_real_graph_run_records_the_root_completion(plugin, mock_apdp):
    mock_apdp.default_decision = "Allow"
    agent = _real_agent(plugin, "web_search")

    result = await agent.ainvoke({"messages": [{"role": "user", "content": "go"}]})

    # The tool was governed and ran (the handle was found), not refused.
    tool_messages = [m for m in result["messages"] if type(m).__name__ == "ToolMessage"]
    assert [m.content for m in tool_messages] == ["results"]
    # The run token is private: it never leaves in the result.
    assert STATE_TOKEN_KEY not in result
    terminals = _root_terminal_events(mock_apdp)
    assert [(e["event_type"], e["agent_id"]) for e, _ in terminals] == [
        ("execution_completed", ROOT_UUID)
    ]
    assert terminals[0][1] is not None  # rode the run's own sst_


async def test_a_real_graph_run_that_raises_records_the_root_failure(plugin, mock_apdp):
    mock_apdp.default_decision = "Allow"
    agent = _real_agent(plugin, "flaky_search")

    with pytest.raises(_Boom):
        await agent.ainvoke({"messages": [{"role": "user", "content": "go"}]})

    terminals = _root_terminal_events(mock_apdp)
    assert [(e["event_type"], e["agent_id"]) for e, _ in terminals] == [
        ("execution_failed", ROOT_UUID)
    ]
