"""The Watchlight handler must survive a caller-supplied callbacks list.

A host that builds its own ``RunnableConfig`` and passes
``callbacks=[]`` on the tool invocation used to drop our handler:
LangChain treats an explicit non-``None`` ``callbacks`` as a
replacement for the inherited manager, so the tools ran, the graph
returned, and nothing was captured — no error, no warning, an
ungoverned run that looked governed. NVIDIA's NeMo Agent Toolkit does
exactly this (its LangChain agent base pins
``self.callbacks = callbacks or []`` and nothing populates that list).

These tests drive REAL ``langchain_core`` tools and a REAL LangGraph
``StateGraph`` — the point is that langchain's own callback plumbing
behaves as claimed, which a fixture could not prove.
"""

from __future__ import annotations

from typing import Any, Dict, List, TypedDict
from unittest.mock import AsyncMock, MagicMock

import pytest

from watchlight_langgraph import (
    RunHandle,
    WatchlightAsyncCallbackHandler,
    WatchlightCallbackHandler,
    WatchlightLangGraphPlugin,
    active_handler,
    attached_handler,
)
from watchlight_core_testing import stub_session_info

try:
    from langchain_core.tools import StructuredTool
    from langgraph.graph import END, StateGraph
except ImportError:  # pragma: no cover — deps are required by pyproject
    pytest.skip(
        "langgraph / langchain_core not available", allow_module_level=True
    )


# ─── Fixtures ──────────────────────────────────────────────────────────


class _StubApdp:
    """In-process stand-in for unit tests only — records batches."""

    def __init__(self) -> None:
        self.published_batches: List[List[Dict[str, Any]]] = []

        async def _capture(events, session_token=None):
            self.published_batches.append(list(events))
            return True

        self.publish_events = AsyncMock(side_effect=_capture)


def _build_run_handle() -> RunHandle:
    """Bypass the production constructor — populate only the fields
    ``callback_handler()`` reads. Mirrors ``test_callbacks.py``."""
    plugin = MagicMock()
    plugin.apdp = _StubApdp()
    plugin.tenant_id = "acme"
    handle = RunHandle.__new__(RunHandle)
    handle._plugin = plugin
    handle.agent_uuid = "agent-1"
    handle.session_id = "sess_42"
    handle._completed = False
    handle.execution_id = "exec_root-fixture"
    handle._callback_attach_token = None
    return handle


def _echo_tool() -> StructuredTool:
    """A real LangChain tool. ``BaseTool.invoke`` routes through
    ``CallbackManager.configure`` exactly as a host's tool call does."""

    def _echo(text: str) -> str:
        return text

    return StructuredTool.from_function(
        func=_echo, name="echo", description="Echo the input back."
    )


def _tool_starts(handler) -> List[Dict[str, Any]]:
    return [e for e in handler.snapshot() if e["hook"] == "on_tool_start"]


# ─── The regression: an explicit callbacks list must not displace us ───


def test_tool_call_with_explicit_empty_callbacks_is_still_captured():
    """THE issue. A host supplies ``callbacks=[]`` on the tool config.

    Before the configure-hook attach this captured nothing at all.
    """
    handle = _build_run_handle()
    handler = handle.callback_handler()

    result = _echo_tool().invoke({"text": "hello"}, config={"callbacks": []})

    assert result == "hello"
    starts = _tool_starts(handler)
    assert len(starts) == 1, (
        "handler was displaced by the host's callbacks list — "
        f"captured {handler.snapshot()}"
    )
    assert starts[0]["name"] == "echo"


def test_tool_call_with_a_hosts_own_handler_is_still_captured():
    """The host supplies a non-empty list of its OWN handlers."""
    from langchain_core.callbacks import BaseCallbackHandler

    class _HostHandler(BaseCallbackHandler):
        def __init__(self) -> None:
            self.seen: List[str] = []

        def on_tool_start(self, serialized, input_str, **kwargs) -> None:
            self.seen.append(serialized.get("name", "?"))

    host = _HostHandler()
    handle = _build_run_handle()
    handler = handle.callback_handler()

    _echo_tool().invoke({"text": "hi"}, config={"callbacks": [host]})

    assert host.seen == ["echo"], "the host's own handler must still run"
    assert len(_tool_starts(handler)) == 1


@pytest.mark.asyncio
async def test_graph_ainvoke_with_explicit_empty_callbacks_is_still_captured():
    """The same displacement through a real compiled ``StateGraph``."""

    class _S(TypedDict, total=False):
        q: str
        a: str

    def _node(state: _S) -> _S:
        return {"a": f"answered: {state.get('q', '')}"}

    graph = StateGraph(_S)
    graph.add_node("answer", _node)
    graph.set_entry_point("answer")
    graph.add_edge("answer", END)
    app = graph.compile()

    handle = _build_run_handle()
    handler = handle.callback_handler(async_handler=True)

    out = await app.ainvoke({"q": "why"}, config={"callbacks": []})

    assert out["a"] == "answered: why"
    assert any(e["hook"] == "on_chain_start" for e in handler.snapshot())


# ─── No double invocation ──────────────────────────────────────────────


def test_attached_and_explicitly_passed_same_handler_captures_once():
    """Belt AND braces must not mean two events per tool call.

    A doubled capture would inflate lineage counts and, on the
    authorize lanes that share this attachment, double the round-trips.
    """
    handle = _build_run_handle()
    handler = handle.callback_handler()

    _echo_tool().invoke({"text": "x"}, config={"callbacks": [handler]})

    assert len(_tool_starts(handler)) == 1


def test_explicit_handler_wins_over_a_different_attached_instance():
    """A second, scoped handler passed on the config takes the call;
    the ambient one stands down. One capture in total, not two."""
    ambient_handle = _build_run_handle()
    ambient = ambient_handle.callback_handler()

    scoped_handle = _build_run_handle()
    scoped = scoped_handle.callback_handler(attach=False)

    _echo_tool().invoke({"text": "x"}, config={"callbacks": [scoped]})

    assert len(_tool_starts(scoped)) == 1
    assert _tool_starts(ambient) == []


def test_sync_explicit_handler_suppresses_an_ambient_async_one():
    """The marker base makes the de-duplication span both flavours —
    an isinstance check against only one class would miss this."""
    ambient_handle = _build_run_handle()
    ambient = ambient_handle.callback_handler(async_handler=True)
    assert isinstance(ambient, WatchlightAsyncCallbackHandler)

    scoped_handle = _build_run_handle()
    scoped = scoped_handle.callback_handler(attach=False)
    assert isinstance(scoped, WatchlightCallbackHandler)

    _echo_tool().invoke({"text": "x"}, config={"callbacks": [scoped]})

    assert len(_tool_starts(scoped)) == 1
    assert _tool_starts(ambient) == []


def test_nested_runs_capture_each_tool_call_once():
    """A tool called under a chain inherits the handler through the
    child manager, not through a second hook injection."""
    handle = _build_run_handle()
    handler = handle.callback_handler()

    tool = _echo_tool()
    tool.invoke({"text": "a"}, config={"callbacks": []})
    tool.invoke({"text": "b"}, config={"callbacks": []})

    starts = _tool_starts(handler)
    assert len(starts) == 2, "one capture per call, no more and no fewer"


# ─── Lifecycle: the attachment is scoped to the run ────────────────────


def test_attach_false_does_not_touch_the_context():
    handle = _build_run_handle()
    handler = handle.callback_handler(attach=False)

    assert active_handler() is None
    _echo_tool().invoke({"text": "x"}, config={"callbacks": []})
    assert _tool_starts(handler) == []


def test_detach_callbacks_restores_the_previous_context():
    handle = _build_run_handle()
    handler = handle.callback_handler()
    assert active_handler() is handler

    handle.detach_callbacks()

    assert active_handler() is None
    _echo_tool().invoke({"text": "x"}, config={"callbacks": []})
    assert _tool_starts(handler) == []


def test_second_callback_handler_replaces_the_first_attachment():
    handle = _build_run_handle()
    first = handle.callback_handler()
    second = handle.callback_handler()

    assert active_handler() is second
    _echo_tool().invoke({"text": "x"}, config={"callbacks": []})

    assert len(_tool_starts(second)) == 1
    assert _tool_starts(first) == []

    handle.detach_callbacks()
    assert active_handler() is None


@pytest.mark.asyncio
async def test_complete_releases_the_attachment():
    """A process-wide hook that never lets go would be its own hazard.
    Closing the run must put the context back."""
    plugin = WatchlightLangGraphPlugin(apdp_url="https://apdp.test")
    plugin.apdp.resolve_agent = AsyncMock(return_value={"id": "u", "slug": "x"})
    plugin.apdp.create_session = AsyncMock(
        return_value=stub_session_info(plugin.apdp, "ses_z", session_token="sst_z")
    )
    plugin.apdp.get_manifest = AsyncMock(return_value={"tool_allowlist": ["read"]})
    plugin.apdp.complete_session = AsyncMock(return_value=True)
    plugin.apdp.publish_events = AsyncMock(return_value=True)

    handle = await plugin.start_run(agent_slug="x")
    handler = handle.callback_handler()
    assert active_handler() is handler

    await handle.complete()

    assert active_handler() is None
    _echo_tool().invoke({"text": "x"}, config={"callbacks": []})
    assert _tool_starts(handler) == []


def test_attached_handler_context_manager_scopes_the_attachment():
    handle = _build_run_handle()
    handler = handle.callback_handler(attach=False)

    with attached_handler(handler):
        _echo_tool().invoke({"text": "x"}, config={"callbacks": []})
    _echo_tool().invoke({"text": "y"}, config={"callbacks": []})

    assert len(_tool_starts(handler)) == 1
    assert active_handler() is None


# ─── The hook itself ───────────────────────────────────────────────────


def test_hook_is_registered_once_however_many_handles_attach():
    from langchain_core.tracers.context import _configure_hooks

    from watchlight_langgraph.callbacks import _ACTIVE_HANDLER

    for _ in range(3):
        _build_run_handle().callback_handler()

    ours = [h for h in _configure_hooks if h[0] is _ACTIVE_HANDLER]
    assert len(ours) == 1
    var, inheritable, handler_class, env_var = ours[0]
    # `inheritable` so tool calls nested under a node see it; `env_var`
    # None so langchain never tries to construct a handler itself (it
    # could not — ours need an APDP client).
    assert inheritable is True
    assert env_var is None
    assert handler_class is not None
