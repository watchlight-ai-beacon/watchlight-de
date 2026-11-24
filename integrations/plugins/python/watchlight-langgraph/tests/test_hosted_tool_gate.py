"""Provider-hosted tools on a model call in a governed LangGraph run.

A provider runs a hosted tool (web search, code execution, a remote MCP
server) on its own servers, inside the model call. No LangGraph tool node
sees it. The run marks its context; the provider SDK gate decides every
hosted tool on the request the SDK actually sends, and the LangChain layer
refuses a chat model class whose requests might not go through a wrapped
SDK. These tests drive real LangChain provider models (``ChatAnthropic``,
``ChatOpenAI``) at a local listener, through a real governed run: a refused
call opens no connection.
"""

from __future__ import annotations

import asyncio
import contextvars
import functools
import logging
import socket
import threading
from typing import Any, Iterator, List

import pytest
from langchain_core.callbacks.manager import CallbackManager
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from watchlight_core import GovernanceUnavailable, langchain_backstop, provider_sdk_gate
from watchlight_core_testing.conformance import (
    HOSTED_TOOL_PLUGINS_PENDING,
    check_hosted_tool_gate_wired,
)
from watchlight_core.hosted_tools import HostedToolRefused
from watchlight_core.langchain_backstop import UnknownModelClassRefused
from watchlight_core.langchain_tool_backstop import UngovernedModelCall
from watchlight_core.provider_sdk_gate import UnmarkedToolBindingRefused
from watchlight_core_testing import MockApdpClient

from watchlight_langgraph import WatchlightLangGraphPlugin

langchain_anthropic = pytest.importorskip("langchain_anthropic")

SENT: List[dict] = []
AGENT_UUID = "1d2bdf18-1a89-4bd1-81ad-33269b484266"
MCP_URL = "https://mcp.docs.example/mcp"
WEB_SEARCH = {"type": "web_search_20250305", "name": "web_search", "max_uses": 1}
FUNCTION = {
    "name": "lookup",
    "description": "Look it up.",
    "input_schema": {"type": "object", "properties": {}},
}
RECORDING = f"{__name__}:_RecordingChatModel"


class _RecordingChatModel(BaseChatModel):
    """A chat model of a class the gate does not know: it records the call
    and never contacts a provider."""

    def _generate(
        self, messages: Any, stop: Any = None, run_manager: Any = None, **kwargs: Any
    ) -> ChatResult:
        SENT.append(dict(kwargs))
        return ChatResult(generations=[ChatGeneration(message=AIMessage(content="ok"))])

    @property
    def _llm_type(self) -> str:
        return "recording"


class _AnthropicSubclass(langchain_anthropic.ChatAnthropic):
    """A subclass of a known class: it could send its requests another way."""


class _Listener:
    """A local TCP listener that counts connections and closes them: the
    model's provider endpoint, so a test sees whether the call was sent."""

    def __init__(self) -> None:
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.connections = 0
        threading.Thread(target=self._serve, daemon=True).start()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.sock.getsockname()[1]}"

    def _serve(self) -> None:
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            self.connections += 1
            conn.close()

    def close(self) -> None:
        self.sock.close()


@pytest.fixture(autouse=True)
def _reset() -> Iterator[None]:
    SENT.clear()
    yield
    assert not provider_sdk_gate.live(), "a governed run leaked its live count"


@pytest.fixture
def listener() -> Iterator[_Listener]:
    lst = _Listener()
    yield lst
    lst.close()


def _apdp(decision: str) -> MockApdpClient:
    apdp = MockApdpClient()
    apdp.known_agents["research-analyst"] = AGENT_UUID
    apdp.default_decision = decision
    return apdp


def _plugin(apdp: MockApdpClient, **kw: Any) -> WatchlightLangGraphPlugin:
    plugin = WatchlightLangGraphPlugin(apdp_url="https://apdp.test", **kw)
    plugin.apdp = apdp  # type: ignore[assignment]
    return plugin


def _decisions(apdp: MockApdpClient, needle: str) -> List[Any]:
    return [c for c in apdp.authorize_calls if needle in str(c)]


def _claude(listener: _Listener, cls: Any = None, **kw: Any) -> Any:
    cls = cls or langchain_anthropic.ChatAnthropic
    return cls(
        model="claude-sonnet-5-5",
        api_key="not-a-key",
        base_url=listener.url,
        max_retries=0,
        **kw,
    )


async def _sent_anyway(call: Any) -> None:
    """Make an allowed call: it reaches the listener, which closes the
    connection, so the provider SDK raises a connection error."""
    with pytest.raises(Exception) as sent:
        await call()
    assert not isinstance(sent.value, (HostedToolRefused, UnknownModelClassRefused)), (
        sent.value
    )


# ── decided on the request the provider SDK sends ───────────────────


@pytest.mark.asyncio
async def test_an_unregistered_mcp_server_set_on_chat_anthropic_is_refused_before_it_is_sent(
    listener: _Listener,
) -> None:
    """``ChatAnthropic(mcp_servers=...)`` adds the server to the request
    itself; the framework's invocation parameters do not show it."""
    model = _claude(
        listener,
        mcp_servers=[{"type": "url", "url": MCP_URL, "name": "docs"}],
        betas=["mcp-client-2025-04-04"],
    )
    apdp = _apdp("Allow")
    async with await _plugin(apdp).start_run(agent_slug="research-analyst"):
        with pytest.raises(HostedToolRefused):
            await model.ainvoke("ask the docs")
    assert listener.connections == 0, (
        "the request left with an MCP server nobody registered"
    )
    assert _decisions(apdp, "mcp://") == []

    registered = _apdp("Allow")
    plugin = _plugin(registered, registered_mcp_servers={MCP_URL: "docs"})
    async with await plugin.start_run(agent_slug="research-analyst"):
        await _sent_anyway(functools.partial(model.ainvoke, "ask the docs"))
    assert _decisions(registered, 'Resource::"mcp://docs/"'), (
        "the server must be decided by its registered name"
    )
    assert listener.connections >= 1


@pytest.mark.asyncio
async def test_a_chat_anthropic_server_tool_is_refused_on_every_entry(
    listener: _Listener,
) -> None:
    model = _claude(listener).bind_tools([WEB_SEARCH])
    apdp = _apdp("Deny")
    async with await _plugin(apdp).start_run(agent_slug="research-analyst"):
        with pytest.raises(HostedToolRefused):
            await model.ainvoke("search")
        with pytest.raises(HostedToolRefused):
            [_ async for _ in model.astream("search")]
        with pytest.raises(HostedToolRefused):
            await asyncio.to_thread(model.invoke, "search")
        with pytest.raises(HostedToolRefused):
            await asyncio.to_thread(lambda: list(model.stream("search")))
    assert listener.connections == 0
    assert _decisions(apdp, 'Tool::"web_search"')

    async with await _plugin(_apdp("Allow")).start_run(agent_slug="research-analyst"):
        await _sent_anyway(functools.partial(model.ainvoke, "search"))
    assert listener.connections >= 1


@pytest.mark.asyncio
async def test_chat_openai_request_level_fields_are_decided(
    listener: _Listener,
) -> None:
    langchain_openai = pytest.importorskip("langchain_openai")
    model = langchain_openai.ChatOpenAI(
        model="gpt-x", api_key="not-a-key", base_url=listener.url, max_retries=0
    ).bind(web_search_options={})
    apdp = _apdp("Deny")
    async with await _plugin(apdp).start_run(agent_slug="research-analyst"):
        with pytest.raises(HostedToolRefused):
            await model.ainvoke("search")
    assert listener.connections == 0
    assert _decisions(apdp, 'Tool::"web_search"')


class _LoopRecordingApdp(MockApdpClient):
    """Records the event loop each decision runs on."""

    def __init__(self) -> None:
        super().__init__()
        self.decision_loops: List[Any] = []

    async def authorize(self, *args: Any, **kwargs: Any) -> Any:
        self.decision_loops.append(asyncio.get_running_loop())
        return await super().authorize(*args, **kwargs)


@pytest.mark.asyncio
@pytest.mark.parametrize("decision", ["Deny", "Allow"])
async def test_a_sync_node_model_call_is_decided_on_the_runs_loop(
    listener: _Listener, decision: str
) -> None:
    """A governed graph with a synchronous node: LangGraph runs the node on
    a worker thread, and its synchronous ``invoke`` is decided on the run's
    loop, where the run's backend client lives."""
    from typing import TypedDict

    from langgraph.graph import END, StateGraph

    class _S(TypedDict, total=False):
        q: str

    model = _claude(listener).bind_tools([WEB_SEARCH])
    threads: List[str] = []

    def ask(state: _S) -> _S:
        threads.append(threading.current_thread().name)
        model.invoke(state.get("q", ""))
        return state

    graph = StateGraph(_S)
    graph.add_node("ask", ask)
    graph.set_entry_point("ask")
    graph.add_edge("ask", END)
    app = graph.compile()

    apdp = _LoopRecordingApdp()
    apdp.known_agents["research-analyst"] = AGENT_UUID
    apdp.default_decision = decision
    run_loop = asyncio.get_running_loop()
    async with await _plugin(apdp).start_run(agent_slug="research-analyst"):
        with pytest.raises(Exception) as raised:
            await app.ainvoke({"q": "search"})
    if decision == "Deny":
        assert isinstance(raised.value, HostedToolRefused), raised.value
        assert listener.connections == 0
    else:
        assert not isinstance(
            raised.value, (HostedToolRefused, UnknownModelClassRefused)
        ), raised.value
        assert listener.connections >= 1
    assert threads and threads[0] != threading.current_thread().name, (
        "the node ran on a worker thread"
    )
    assert _decisions(apdp, 'Tool::"web_search"')
    assert apdp.decision_loops and set(apdp.decision_loops) == {run_loop}


@pytest.mark.asyncio
async def test_a_sync_call_on_the_runs_loop_thread_is_refused_without_hanging(
    listener: _Listener,
) -> None:
    model = _claude(listener).bind_tools([WEB_SEARCH])
    async with await _plugin(_apdp("Allow")).start_run(agent_slug="research-analyst"):
        with pytest.raises(HostedToolRefused):
            model.invoke("search")
    assert listener.connections == 0


# ── the chat model class ─────────────────────────────────────────────


@pytest.mark.asyncio
async def test_an_unknown_model_class_is_refused_in_a_run(
    caplog: pytest.LogCaptureFixture,
) -> None:
    async with await _plugin(_apdp("Allow")).start_run(agent_slug="research-analyst"):
        with pytest.raises(UnknownModelClassRefused):
            await _RecordingChatModel().ainvoke("x")
        with pytest.raises(UnknownModelClassRefused):
            await asyncio.to_thread(_RecordingChatModel().invoke, "x")
    assert SENT == []

    with caplog.at_level(logging.WARNING, logger="watchlight_core.langchain_backstop"):
        plugin = _plugin(_apdp("Allow"), allowed_model_classes=[RECORDING])
        async with await plugin.start_run(agent_slug="research-analyst"):
            await _RecordingChatModel().ainvoke("x")
    assert len(SENT) == 1
    assert any(RECORDING in r.getMessage() for r in caplog.records), (
        "an allowed class must be logged"
    )


@pytest.mark.asyncio
async def test_a_subclass_of_a_known_class_needs_the_allow_list(
    listener: _Listener,
) -> None:
    model = _claude(listener, cls=_AnthropicSubclass)
    async with await _plugin(_apdp("Allow")).start_run(agent_slug="research-analyst"):
        with pytest.raises(UnknownModelClassRefused):
            await model.ainvoke("x")
    assert listener.connections == 0

    allowed = [f"{__name__}:_AnthropicSubclass"]
    async with await _plugin(_apdp("Allow"), allowed_model_classes=allowed).start_run(
        agent_slug="research-analyst"
    ):
        await _sent_anyway(functools.partial(model.ainvoke, "x"))
    assert listener.connections >= 1


@pytest.mark.asyncio
async def test_an_allowed_class_is_plain_chat_only(listener: _Listener) -> None:
    """Allowing a class says it has no hosted capability; the SDK gate may
    not see its requests, so it may not bind any tool."""
    allowed = [RECORDING, f"{__name__}:_AnthropicSubclass"]
    plugin = _plugin(_apdp("Allow"), allowed_model_classes=allowed)
    async with await plugin.start_run(agent_slug="research-analyst"):
        for call in (
            functools.partial(
                _RecordingChatModel().bind(tools=[FUNCTION]).ainvoke, "x"
            ),
            functools.partial(
                _RecordingChatModel().bind(tool_choice="auto").ainvoke, "x"
            ),
            functools.partial(
                asyncio.to_thread,
                _RecordingChatModel().bind(tools=[FUNCTION]).invoke,
                "x",
            ),
            functools.partial(
                _claude(listener, cls=_AnthropicSubclass)
                .bind_tools([FUNCTION])
                .ainvoke,
                "x",
            ),
        ):
            with pytest.raises(UnknownModelClassRefused) as refused:
                await call()
            assert refused.value.binds_tools
        await _RecordingChatModel().ainvoke("plain chat")
    assert listener.connections == 0 and len(SENT) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("close", ["exit", "complete", "terminate"])
async def test_a_run_cancelled_while_publishing_stops_counting_as_live(
    monkeypatch: pytest.MonkeyPatch, close: str
) -> None:
    from watchlight_langgraph import plugin as plugin_module

    async def cancelled(_handle: Any) -> None:
        raise asyncio.CancelledError

    handle = await _plugin(_apdp("Allow")).start_run(agent_slug="research-analyst")
    await handle.__aenter__()
    assert provider_sdk_gate.live()
    monkeypatch.setattr(plugin_module, "publish_tool_gate_refusals", cancelled)
    with pytest.raises(asyncio.CancelledError):
        if close == "exit":
            await handle.__aexit__(None, None, None)
        elif close == "complete":
            await handle.complete()
        else:
            await handle.terminate(reason="test")
    assert not provider_sdk_gate.live()


def test_a_malformed_allow_list_is_refused() -> None:
    for wrong in ("pkg:Model", ["Model"], ["pkg.Model"], [3]):
        with pytest.raises(ValueError):
            _plugin(_apdp("Allow"), allowed_model_classes=wrong)


# ── outside the run's context ────────────────────────────────────────


def _in_bare_thread(fn: Any) -> Any:
    """Run ``fn`` on a raw thread, which does NOT copy the caller's context."""
    box: dict = {}

    def run() -> None:
        try:
            box["value"] = fn()
        except BaseException as exc:  # noqa: BLE001 - re-raised below
            box["error"] = exc

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    thread.join(10)
    assert not thread.is_alive(), "the call hung"
    if "error" in box:
        raise box["error"]
    return box.get("value")


#: Where no run acts, a tool-binding model call is refused by whichever check
#: sees it first: the LangChain backstop's model start, or else the
#: provider SDK gate at the request. Either way nothing is sent.
OFF_CONTEXT_REFUSALS = (UnmarkedToolBindingRefused, UngovernedModelCall)


def _bound_recording() -> Any:
    return _RecordingChatModel().bind(tools=[FUNCTION]).invoke("x")


@pytest.mark.asyncio
async def test_a_thread_without_the_runs_context_cannot_bind_tools(
    listener: _Listener,
) -> None:
    claude = _claude(listener).bind_tools([FUNCTION])
    async with await _plugin(_apdp("Allow")).start_run(
        agent_slug="research-analyst"
    ) as handle:
        with pytest.raises(OFF_CONTEXT_REFUSALS):
            await asyncio.to_thread(
                _in_bare_thread, functools.partial(claude.invoke, "x")
            )
        with pytest.raises(OFF_CONTEXT_REFUSALS):
            await asyncio.to_thread(_in_bare_thread, _bound_recording)
        await asyncio.to_thread(
            _in_bare_thread, functools.partial(_RecordingChatModel().invoke, "plain")
        )
        assert provider_sdk_gate.live() and not handle._completed, (
            "the refusal must not end the run"
        )
    assert listener.connections == 0 and len(SENT) == 1


@pytest.mark.asyncio
async def test_the_provider_sdk_gate_alone_refuses_an_off_context_sdk_call(
    listener: _Listener,
) -> None:
    """A provider SDK called directly, with no LangChain model start, meets
    only the provider SDK gate: the refusal is its own, not the backstop's."""
    import anthropic

    client = anthropic.Anthropic(
        api_key="not-a-key", base_url=listener.url, max_retries=0
    )

    direct = functools.partial(
        client.messages.create,
        model="claude-sonnet-5-5",
        max_tokens=16,
        messages=[{"role": "user", "content": "x"}],
        tools=[FUNCTION],
    )
    async with await _plugin(_apdp("Allow")).start_run(agent_slug="research-analyst"):
        before = provider_sdk_gate.unmarked_refusals()
        with pytest.raises(UnmarkedToolBindingRefused):
            await asyncio.to_thread(_in_bare_thread, direct)
        assert provider_sdk_gate.unmarked_refusals() == before + 1
    assert listener.connections == 0


@pytest.mark.asyncio
async def test_a_call_outside_async_with_run_is_refused_while_a_run_is_live(
    listener: _Listener,
) -> None:
    entered, leave = asyncio.Event(), asyncio.Event()

    async def governed() -> None:
        async with await _plugin(_apdp("Allow")).start_run(
            agent_slug="research-analyst"
        ):
            entered.set()
            await leave.wait()

    task = asyncio.create_task(governed(), context=contextvars.Context())
    await entered.wait()
    try:
        with pytest.raises(OFF_CONTEXT_REFUSALS):
            await _claude(listener).bind_tools([WEB_SEARCH]).ainvoke("outside the run")
    finally:
        leave.set()
        await task
    assert listener.connections == 0


async def _after(go: asyncio.Event, call: Any) -> Any:
    await go.wait()
    return await call()


@pytest.mark.asyncio
async def test_a_task_that_outlives_its_run_is_refused(listener: _Listener) -> None:
    go = asyncio.Event()
    claude = _claude(listener).bind_tools([FUNCTION])
    async with await _plugin(_apdp("Allow")).start_run(agent_slug="research-analyst"):
        stale_sdk = asyncio.create_task(
            _after(go, functools.partial(claude.ainvoke, "x"))
        )
        stale_class = asyncio.create_task(
            _after(go, functools.partial(_RecordingChatModel().ainvoke, "x"))
        )
    go.set()
    with pytest.raises(UnmarkedToolBindingRefused):
        await stale_sdk
    with pytest.raises(UnknownModelClassRefused):
        await stale_class
    assert listener.connections == 0 and SENT == []


@pytest.mark.asyncio
async def test_no_effect_with_no_governed_run_live() -> None:
    await _RecordingChatModel().bind(tools=[FUNCTION]).ainvoke("x")
    await asyncio.to_thread(_in_bare_thread, _bound_recording)
    assert len(SENT) == 2


# ── nesting ──────────────────────────────────────────────────────────


async def _inner_run_step(apdp: MockApdpClient, model: Any, _: Any, config: Any) -> Any:
    """A graph step that opens its own governed run and calls a model."""
    async with await _plugin(apdp).start_run(agent_slug="research-analyst"):
        return await model.ainvoke("x", config)


@pytest.mark.asyncio
@pytest.mark.parametrize("outer,inner", [("Allow", "Deny"), ("Deny", "Allow")])
async def test_a_run_opened_inside_another_runs_step_decides_its_own_calls(
    listener: _Listener, outer: str, inner: str
) -> None:
    from langchain_core.runnables import RunnableLambda

    inner_apdp = _apdp(inner)
    step = functools.partial(
        _inner_run_step, inner_apdp, _claude(listener).bind_tools([WEB_SEARCH])
    )
    async with await _plugin(_apdp(outer)).start_run(agent_slug="research-analyst"):
        if inner == "Deny":
            with pytest.raises(HostedToolRefused):
                await RunnableLambda(step).ainvoke("go")
            assert listener.connections == 0
        else:
            await _sent_anyway(functools.partial(RunnableLambda(step).ainvoke, "go"))
    assert _decisions(inner_apdp, 'Tool::"web_search"')


@pytest.mark.asyncio
async def test_a_graph_invoked_inside_a_runs_step_is_governed_as_part_of_the_run(
    listener: _Listener,
) -> None:
    """A nested ``invoke`` of another compiled graph from a node of the
    governed graph runs in the run's context: the run's handler sees it as
    a child chain, and its model call is decided as the run's."""
    from typing import TypedDict

    from langgraph.graph import END, StateGraph

    class _S(TypedDict, total=False):
        q: str

    model = _claude(listener).bind_tools([WEB_SEARCH])

    async def ask(state: _S) -> _S:
        await model.ainvoke(state.get("q", ""))
        return state

    inner = StateGraph(_S)
    inner.add_node("ask", ask)
    inner.set_entry_point("ask")
    inner.add_edge("ask", END)
    inner_app = inner.compile()

    async def delegate(state: _S) -> _S:
        return await inner_app.ainvoke(state)

    outer = StateGraph(_S)
    outer.add_node("delegate", delegate)
    outer.set_entry_point("delegate")
    outer.add_edge("delegate", END)
    app = outer.compile()

    apdp = _apdp("Deny")
    async with await _plugin(apdp).start_run(agent_slug="research-analyst") as handle:
        handler = handle.callback_handler(async_handler=True)
        with pytest.raises(HostedToolRefused):
            await app.ainvoke({"q": "search"})
    assert listener.connections == 0
    assert _decisions(apdp, 'Tool::"web_search"'), (
        "the nested graph's call must be decided as the run's"
    )
    starts = [e for e in handler.snapshot() if e["hook"] == "on_chain_start"]
    assert sum(1 for e in starts if e.get("parent_run_id")) >= 2, (
        "the nested graph must be a child chain"
    )


# ── the wraps must be in place ───────────────────────────────────────


@pytest.mark.asyncio
async def test_a_replaced_wrap_refuses_the_run(monkeypatch: pytest.MonkeyPatch) -> None:
    langchain_backstop.install()
    wrapped = CallbackManager.__dict__["on_chat_model_start"]
    monkeypatch.setattr(CallbackManager, "on_chat_model_start", wrapped.__wrapped__)
    with pytest.raises(GovernanceUnavailable):
        async with await _plugin(_apdp("Allow")).start_run(
            agent_slug="research-analyst"
        ):
            pytest.fail("the run must not open")
    monkeypatch.undo()

    import anthropic._base_client as base

    monkeypatch.setattr(
        base.AsyncAPIClient,
        "request",
        base.AsyncAPIClient.__dict__["request"].__wrapped__,
    )
    with pytest.raises(GovernanceUnavailable):
        async with await _plugin(_apdp("Allow")).start_run(
            agent_slug="research-analyst"
        ):
            pytest.fail("the run must not open")


# ── conformance ──────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_hosted_tool_invariant_19_passes_and_is_not_pending() -> None:
    pytest.importorskip("openai")
    assert "watchlight-langgraph" not in HOSTED_TOOL_PLUGINS_PENDING
    plugin = WatchlightLangGraphPlugin(apdp_url="https://apdp.test")
    assert await check_hosted_tool_gate_wired(plugin, "watchlight_langgraph") == "ok"
