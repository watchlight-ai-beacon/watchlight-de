"""An agent a tool body builds and runs is refused while a governed run is
live.

A deep agent built inside a governed agent's tool gets no Watchlight
middleware. The process-wide backstop (``watchlight_deepagents.backstop``)
refuses its model turns inside the tool body and any tool start the
governance middleware did not grant, on any thread and whatever config or
callbacks the inner agent is given. Driven through real
``create_governed_deep_agent`` graphs with scripted models. Skips when
``deepagents`` is not installed.
"""

from __future__ import annotations

import contextvars
import threading
from typing import Any, Dict, List

import pytest

pytest.importorskip("deepagents", reason="deepagents not installed in this sandbox")

from langchain_core.callbacks import AsyncCallbackHandler  # noqa: E402
from langchain_core.language_models.fake_chat_models import (  # noqa: E402
    GenericFakeChatModel,
)
from langchain_core.messages import AIMessage, HumanMessage  # noqa: E402
from langchain_core.runnables import RunnableConfig  # noqa: E402
from langchain_core.tools import tool  # noqa: E402
from langchain_core.tracers.context import register_configure_hook  # noqa: E402

from watchlight_core import GovernanceUnavailable  # noqa: E402
from watchlight_core import langchain_tool_backstop as backstop  # noqa: E402
from watchlight_deepagents import create_governed_deep_agent  # noqa: E402
from watchlight_core.langchain_tool_backstop import (  # noqa: E402
    UngovernedModelCall,
    UngovernedToolCall,
    direct_model_use,
)
from watchlight_deepagents.middleware import _HANDLE_REGISTRY  # noqa: E402

from conftest import (  # noqa: E402
    ROOT_SLUG,
    ROOT_UUID,
    make_root_middleware,
    make_tool_call_request,
    start_root,
)

HOSTED = [{"type": "web_search_20250305", "name": "web_search"}]


class _ScriptedModel(GenericFakeChatModel):
    """In-process stand-in for a chat model (tests only). Binds no tools
    unless ``hosted`` is set, when it binds a provider-hosted tool spec."""

    hosted: bool = False

    def bind_tools(self, tools: Any, **kwargs: Any) -> Any:
        return self.bind(tools=HOSTED) if self.hosted else self


def _turns(*calls: Dict[str, Any]) -> Any:
    out = [AIMessage(content="", tool_calls=[{**c, "type": "tool_call"}]) for c in calls]
    return iter(out + [AIMessage(content="done")])


RAN: List[str] = []
SEEN: List[BaseException] = []


@pytest.fixture(autouse=True)
def _reset() -> Any:
    # Live-run state is process-wide: runs other test modules drive by hand
    # and leave open must not count as live here.
    left_open = dict(_HANDLE_REGISTRY)
    _HANDLE_REGISTRY.clear()
    RAN.clear()
    SEEN.clear()
    yield
    assert not _HANDLE_REGISTRY, "a governed run stayed live"
    _HANDLE_REGISTRY.update(left_open)


@tool
def inner_danger(query: str) -> str:
    """A tool no governed agent authorized."""
    RAN.append("inner_danger")
    return "danger"


def _inner_agent(*, hosted: bool = False) -> Any:
    from deepagents import create_deep_agent

    model = _ScriptedModel(
        messages=_turns({"name": "inner_danger", "args": {"query": "secret-value"}, "id": "i1"}),
        hosted=hosted,
    )
    return create_deep_agent(model=model, tools=[inner_danger])


def _run_inner(**kwargs: Any) -> None:
    try:
        _inner_agent(hosted=kwargs.pop("hosted", False)).invoke(
            {"messages": [{"role": "user", "content": "go"}]}, **kwargs
        )
    except GovernanceUnavailable as exc:
        SEEN.append(exc)


async def _governed(outer: Any, plugin: Any, mock_apdp: Any, **kwargs: Any) -> Any:
    mock_apdp.default_decision = "Allow"
    agent = create_governed_deep_agent(
        model=_ScriptedModel(messages=_turns({"name": outer.name, "args": {"query": "q"}, "id": "c1"})),
        tools=[outer],
        agent_slug=ROOT_SLUG,
        plugin=plugin,
        **kwargs,
    )
    return await agent.ainvoke({"messages": [{"role": "user", "content": "go"}]})


def _backstop_events(mock_apdp: Any) -> List[Dict[str, Any]]:
    return [
        e for e in mock_apdp.published_events
        if (e.get("metadata") or {}).get("backstop") is True
    ]


# ─── An agent built in a tool body ───────────────────────────────────


async def test_a_raw_deep_agent_in_a_tool_body_is_refused(plugin, mock_apdp):
    @tool
    def outer(query: str) -> str:
        """Runs a raw deep agent."""
        _run_inner()
        return "outer"

    await _governed(outer, plugin, mock_apdp)
    assert RAN == []
    assert [type(e) for e in SEEN] == [UngovernedModelCall]


async def test_the_tool_config_passed_to_the_inner_agent_does_not_make_it_governed(plugin, mock_apdp):
    @tool
    def outer(query: str, config: RunnableConfig) -> str:
        """Runs a raw deep agent under the tool's own config."""
        _run_inner(config=config)
        return "outer"

    await _governed(outer, plugin, mock_apdp)
    assert RAN == []
    assert [type(e) for e in SEEN] == [UngovernedModelCall]


async def test_empty_callbacks_do_not_remove_the_backstop(plugin, mock_apdp):
    @tool
    def outer(query: str) -> str:
        """Runs a raw deep agent with no callbacks."""
        _run_inner(config={"callbacks": []})
        try:
            inner_danger.invoke({"query": "q"}, config={"callbacks": []})
        except UngovernedToolCall as exc:
            SEEN.append(exc)
        return "outer"

    await _governed(outer, plugin, mock_apdp)
    assert RAN == []
    assert [type(e) for e in SEEN] == [UngovernedModelCall, UngovernedToolCall]


async def test_a_raw_agent_on_a_new_thread_cannot_run_a_tool(plugin, mock_apdp):
    @tool
    def outer(query: str) -> str:
        """Runs a raw deep agent on a raw thread."""
        worker = threading.Thread(target=_run_inner)
        worker.start()
        worker.join()
        return "outer"

    await _governed(outer, plugin, mock_apdp)
    assert RAN == []
    assert [type(e) for e in SEEN] == [UngovernedToolCall]


@pytest.mark.parametrize("where", ["thread", "fresh_context"])
async def test_a_raw_agent_binding_hosted_tools_is_refused_at_its_model_start(plugin, mock_apdp, where):
    @tool
    def outer(query: str) -> str:
        """Runs a raw agent whose model binds a provider-hosted tool."""
        if where == "thread":
            worker = threading.Thread(target=_run_inner, kwargs={"hosted": True})
            worker.start()
            worker.join()
        else:
            contextvars.Context().run(_run_inner, hosted=True)
        return "outer"

    await _governed(outer, plugin, mock_apdp)
    assert RAN == []
    assert [type(e) for e in SEEN] == [UngovernedModelCall]


async def test_the_outer_call_id_reused_by_an_inner_tool_is_refused(plugin, mock_apdp):
    @tool
    def outer(query: str) -> str:
        """Calls tools under the outer call's own id."""
        for name, target in (("inner_danger", inner_danger), ("outer", outer)):
            try:
                target.invoke({"type": "tool_call", "id": "c1", "name": name, "args": {"query": "q"}})
            except UngovernedToolCall as exc:
                SEEN.append(exc)
        RAN.append("outer")
        return "outer"

    await _governed(outer, plugin, mock_apdp)
    # The outer call ran once; neither a different tool nor the same tool
    # again could use its id.
    assert RAN == ["outer"]
    assert [type(e) for e in SEEN] == [UngovernedToolCall, UngovernedToolCall]


async def test_a_refusal_is_recorded_without_values(plugin, mock_apdp):
    @tool
    def outer(query: str) -> str:
        """Runs a raw deep agent on a raw thread."""
        worker = threading.Thread(target=_run_inner)
        worker.start()
        worker.join()
        return "outer"

    await _governed(outer, plugin, mock_apdp)
    (event,) = _backstop_events(mock_apdp)
    assert event["event_type"] == "tool_call_observed"
    assert event["agent_id"] == ROOT_UUID
    assert event["payload"]["decision"] == "Deny"
    assert event["payload"]["tool"]["identifier"] == "inner_danger"
    assert "secret-value" not in repr(event)


async def test_a_refused_model_turn_is_recorded(plugin, mock_apdp):
    @tool
    def outer(query: str) -> str:
        """Runs a raw deep agent."""
        _run_inner()
        return "outer"

    await _governed(outer, plugin, mock_apdp)
    (event,) = _backstop_events(mock_apdp)
    assert event["event_type"] == "api_request_observed"
    assert event["metadata"]["decision"] == "Deny"
    assert "secret-value" not in repr(event)


async def test_the_grant_binds_the_tool_name(plugin, mock_apdp):
    """A different tool started under the authorized call's id is refused,
    even before the authorized tool itself starts."""
    mock_apdp.default_decision = "Allow"
    mw = make_root_middleware(plugin)
    state = await start_root(mw)

    async def _handler(request: Any) -> str:
        try:
            inner_danger.invoke({"type": "tool_call", "id": "c1", "name": "inner_danger", "args": {"query": "q"}})
        except UngovernedToolCall as exc:
            SEEN.append(exc)
        return "ok"

    await mw.awrap_tool_call(make_tool_call_request("search", state=state, tool_call_id="c1"), _handler)
    await mw.aafter_agent(state, runtime=None)
    assert RAN == []
    assert [type(e) for e in SEEN] == [UngovernedToolCall]


# ─── What still runs ─────────────────────────────────────────────────


async def test_a_governed_task_sub_agent_still_runs(plugin, mock_apdp):
    @tool
    def search_web(query: str) -> str:
        """Search the web."""
        RAN.append("search_web")
        return "results"

    mock_apdp.default_decision = "Allow"
    child = _ScriptedModel(messages=_turns({"name": "search_web", "args": {"query": "q"}, "id": "s1"}))
    agent = create_governed_deep_agent(
        model=_ScriptedModel(
            messages=_turns(
                {"name": "task", "args": {"description": "find", "subagent_type": "researcher"}, "id": "t1"}
            )
        ),
        tools=[search_web],
        subagents=[
            {
                "name": "researcher",
                "description": "research",
                "system_prompt": "research",
                "tools": [search_web],
                "model": child,
            }
        ],
        subagent_scopes={"researcher": {"allowed_tools": ["deepagents://tool/search_web"], "max_depth": 0}},
        agent_slug=ROOT_SLUG,
        plugin=plugin,
    )
    await agent.ainvoke({"messages": [{"role": "user", "content": "go"}]})
    assert RAN == ["search_web"]
    assert _backstop_events(mock_apdp) == []


async def test_a_task_spawn_body_is_not_a_tool_body(plugin, mock_apdp):
    """The ``task`` tool's body runs a governed sub-agent, whose own
    summarization calls the model outside its governance wrap: a tool-less
    model call there is not refused."""
    mock_apdp.default_decision = "Allow"
    mw = make_root_middleware(plugin, subagent_scopes={"researcher": {"allowed_tools": []}})
    state = await start_root(mw)

    async def _child_summarizes(request: Any) -> str:
        model = _ScriptedModel(messages=iter([AIMessage(content="summary")]))
        RAN.append(model.invoke([HumanMessage(content="x")]).content)
        return "ok"

    await mw.awrap_tool_call(
        make_tool_call_request("task", {"subagent_type": "researcher"}, state=state), _child_summarizes
    )
    await mw.aafter_agent(state, runtime=None)
    assert RAN == ["summary"]


async def test_a_governed_turn_binding_hosted_tools_runs(plugin, mock_apdp):
    @tool
    def lookup(query: str) -> str:
        """Look something up."""
        RAN.append("lookup")
        return "ok"

    mock_apdp.default_decision = "Allow"
    agent = create_governed_deep_agent(
        model=_ScriptedModel(messages=_turns({"name": "lookup", "args": {"query": "q"}, "id": "c1"}), hosted=True),
        tools=[lookup],
        agent_slug=ROOT_SLUG,
        plugin=plugin,
    )
    await agent.ainvoke({"messages": [{"role": "user", "content": "go"}]})
    assert RAN == ["lookup"]
    assert _backstop_events(mock_apdp) == []


async def test_a_tool_less_model_call_outside_a_tool_body_runs(plugin, mock_apdp):
    """Deep agents' summarization calls the model outside the governance
    middleware's model wrap, binding no tools: it is not refused."""
    seen: List[str] = []

    @tool
    def outer(query: str) -> str:
        """Makes a tool-less model call on a fresh context, as summarization would."""
        model = _ScriptedModel(messages=iter([AIMessage(content="summary")]))
        seen.append(contextvars.Context().run(model.invoke, [HumanMessage(content="x")]).content)
        return "outer"

    await _governed(outer, plugin, mock_apdp)
    assert seen == ["summary"]


async def test_direct_model_use_allows_a_tool_less_model_call(plugin, mock_apdp):
    @tool
    def outer(query: str) -> str:
        """Calls a model directly, with and without the escape."""
        model = _ScriptedModel(messages=iter([AIMessage(content="a"), AIMessage(content="b")]))
        try:
            model.invoke([HumanMessage(content="x")])
        except UngovernedModelCall as exc:
            SEEN.append(exc)
        with direct_model_use():
            RAN.append(model.invoke([HumanMessage(content="x")]).content)
            try:
                model.bind(tools=HOSTED).invoke([HumanMessage(content="x")])
            except UngovernedModelCall as exc:
                SEEN.append(exc)
        return "outer"

    await _governed(outer, plugin, mock_apdp)
    assert RAN == ["a"]
    assert [type(e) for e in SEEN] == [UngovernedModelCall, UngovernedModelCall]


def test_nothing_is_refused_with_no_governed_run_live(plugin):
    # Installed (building the middleware installs it), but no run is live.
    create_governed_deep_agent(
        model=_ScriptedModel(messages=iter([AIMessage(content="x")])),
        tools=[],
        agent_slug=ROOT_SLUG,
        plugin=plugin,
    )
    assert not _HANDLE_REGISTRY
    _run_inner(hosted=True)
    assert RAN == ["inner_danger"]
    assert SEEN == []


# ─── Why the handler is synchronous ──────────────────────────────────


def test_the_backstop_handler_raises_inline_and_synchronously(plugin):
    create_governed_deep_agent(
        model=_ScriptedModel(messages=iter([AIMessage(content="x")])),
        tools=[],
        agent_slug=ROOT_SLUG,
        plugin=plugin,
    )
    assert backstop._HANDLER_VAR is not None
    handler = backstop._HANDLER_VAR.get()
    assert not isinstance(handler, AsyncCallbackHandler)
    assert handler.raise_error is True
    assert handler.run_inline is True


def test_an_async_handler_raise_would_not_stop_a_tool():
    """Why the backstop is sync: LangChain swallows what an async handler
    raises on the sync tool path, so the tool body would still run."""

    class _AsyncRefuser(AsyncCallbackHandler):
        raise_error = True

        async def on_tool_start(self, *args: Any, **kwargs: Any) -> None:
            raise UngovernedToolCall("refused")

    var: contextvars.ContextVar = contextvars.ContextVar("test_async_refuser", default=None)
    register_configure_hook(var, True)
    token = var.set(_AsyncRefuser())
    try:
        inner_danger.invoke({"query": "q"})
    finally:
        var.reset(token)
    assert RAN == ["inner_danger"]


# ─── Review follow-ups ───────────────────────────────────────────────


async def test_a_refusal_that_cannot_be_recorded_still_stands_and_is_counted(
    plugin, mock_apdp, monkeypatch, caplog
):
    from watchlight_deepagents.plugin import RunHandle

    original = RunHandle.publish_observation

    async def _failing(self: Any, *args: Any, **kwargs: Any) -> Any:
        if (kwargs.get("extra_metadata") or {}).get("backstop"):
            raise RuntimeError("lineage down")
        return await original(self, *args, **kwargs)

    monkeypatch.setattr(RunHandle, "publish_observation", _failing)

    @tool
    def outer(query: str) -> str:
        """Runs a raw deep agent on a raw thread."""
        worker = threading.Thread(target=_run_inner)
        worker.start()
        worker.join()
        return "outer"

    before = backstop.emit_failures()
    with caplog.at_level("WARNING"):
        await _governed(outer, plugin, mock_apdp)
    assert RAN == []
    assert backstop.emit_failures() == before + 1
    assert any(
        r.levelname == "WARNING" and "could not be published" in r.getMessage()
        for r in caplog.records
    )


@pytest.mark.parametrize(
    "serialized, params",
    [
        ({}, {"model_kwargs": {"tools": HOSTED}}),
        ({"kwargs": {"model_kwargs": {"tools": HOSTED}}}, {}),
        ({"kwargs": {"model_kwargs": {"tool_choice": "auto"}}}, {}),
    ],
)
def test_tools_nested_in_model_kwargs_count_as_binding(serialized, params):
    assert backstop._binds_tools(serialized, {"invocation_params": params})
    assert not backstop._binds_tools({}, {"invocation_params": {}})
