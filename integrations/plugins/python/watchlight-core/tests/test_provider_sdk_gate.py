"""``watchlight_core.provider_sdk_gate``: provider-hosted tools decided on the
request each real provider SDK sends.

Every test drives a real SDK client (anthropic, openai, google-genai) whose
transport counts what reaches the wire, so "refused" means nothing was sent.
"""

from __future__ import annotations

import asyncio
import contextvars
import socket
import threading
import time
from typing import Any, Dict, Iterator, List, Optional

import httpx
import pytest

from watchlight_core import provider_sdk_gate as gate
from watchlight_core.errors import GovernanceUnavailable
from watchlight_core.hosted_tools import HostedToolRefused
from watchlight_core.provider_sdk_gate import (
    ProviderApiRefused,
    UnmarkedToolBindingRefused,
)
from watchlight_core.results import AuthorizeResult

anthropic = pytest.importorskip("anthropic")
openai = pytest.importorskip("openai")
genai = pytest.importorskip("google.genai")

WEB_SEARCH = {"type": "web_search_20250305", "name": "web_search", "max_uses": 1}
MCP_URL = "https://mcp.example.test/mcp"
MESSAGE = {
    "id": "msg_1",
    "type": "message",
    "role": "assistant",
    "model": "m",
    "content": [{"type": "text", "text": "ok"}],
    "stop_reason": "end_turn",
    "stop_sequence": None,
    "usage": {"input_tokens": 1, "output_tokens": 1},
}
COMPLETION = {
    "id": "c1",
    "object": "chat.completion",
    "created": 0,
    "model": "m",
    "choices": [
        {
            "index": 0,
            "finish_reason": "stop",
            "message": {"role": "assistant", "content": "ok"},
        }
    ],
}


class _Handle:
    """A run handle stand-in: answers every decision with ``decision`` and
    records ``(action, resource)`` and each context."""

    def __init__(self, decision: str = "allow") -> None:
        self.decision = decision
        self.decisions: List[tuple] = []
        self.contexts: List[Optional[dict]] = []

    async def authorize_action_detailed(
        self, action: str, resource: str, *, context: Optional[dict] = None
    ) -> Any:
        self.decisions.append((action, resource))
        self.contexts.append(context)
        return AuthorizeResult(self.decision)


def _response_for(request: Any) -> Any:
    """Response from the same httpx package as request."""
    import sys

    return sys.modules[type(request).__module__.split(".")[0]].Response


class _Wire:
    """An httpx transport that counts requests and answers ``body``."""

    def __init__(self, body: Dict[str, Any]) -> None:
        self.sent: List[str] = []
        self.body = body

    def __call__(self, request: Any) -> Any:
        self.sent.append(request.url.path)
        return _response_for(request)(200, json=self.body)


def _httpx_of(sdk: Any) -> Any:
    """The httpx package the SDK's client is built on (httpx2 in newer
    releases)."""
    return getattr(sdk._base_client, "httpx2", None) or getattr(
        sdk._base_client, "httpx", httpx
    )


def _anthropic(wire: _Wire, *, asynchronous: bool = False) -> Any:
    hx = _httpx_of(anthropic)
    transport = hx.MockTransport(wire)
    if asynchronous:
        return anthropic.AsyncAnthropic(
            api_key="k", http_client=hx.AsyncClient(transport=transport), max_retries=0
        )
    return anthropic.Anthropic(
        api_key="k", http_client=hx.Client(transport=transport), max_retries=0
    )


def _openai(
    wire: _Wire, *, asynchronous: bool = False, base_url: Optional[str] = None
) -> Any:
    hx = _httpx_of(openai)
    transport = hx.MockTransport(wire)
    kw: Dict[str, Any] = {"api_key": "k", "max_retries": 0}
    if base_url:
        kw["base_url"] = base_url
    if asynchronous:
        return openai.AsyncOpenAI(http_client=hx.AsyncClient(transport=transport), **kw)
    return openai.OpenAI(http_client=hx.Client(transport=transport), **kw)


class _LoopThread:
    def __init__(self) -> None:
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=self.loop.run_forever, daemon=True)
        self.thread.start()

    def stop(self) -> None:
        self.loop.call_soon_threadsafe(self.loop.stop)
        self.thread.join(5)
        self.loop.close()


@pytest.fixture(autouse=True)
def _no_leaks() -> Iterator[None]:
    assert not gate.live() and gate.current_run() is None
    yield
    assert not gate.live(), "a run leaked its live count"


@pytest.fixture
def run_loop() -> Iterator[asyncio.AbstractEventLoop]:
    lt = _LoopThread()
    yield lt.loop
    lt.stop()


def _governed(handle: Any, loop: Any, **kw: Any) -> Any:
    """Mark the current context as a run, the way a plugin does."""
    return gate.attach_run(handle, run_loop=loop, **kw)


def _ms(**kw: Any) -> Dict[str, Any]:
    return {
        "model": "m",
        "max_tokens": 16,
        "messages": [{"role": "user", "content": "hi"}],
        **kw,
    }


# ── decided on the real request ─────────────────────────────────────


def test_anthropic_sync_hosted_tool_is_decided_before_it_is_sent(run_loop: Any) -> None:
    wire = _Wire(MESSAGE)
    client = _anthropic(wire)
    deny = _Handle("deny")
    run = _governed(deny, run_loop)
    try:
        with pytest.raises(HostedToolRefused):
            client.messages.create(**_ms(tools=[WEB_SEARCH]))
    finally:
        gate.detach_run(run)
    assert wire.sent == []
    assert deny.decisions == [('Action::"execute"', 'Tool::"web_search"')]

    allow = _Handle("allow")
    run = _governed(allow, run_loop)
    try:
        client.messages.create(**_ms(tools=[WEB_SEARCH]))
    finally:
        gate.detach_run(run)
    assert wire.sent == ["/v1/messages"]


@pytest.mark.asyncio
async def test_anthropic_async_hosted_tool_is_decided_before_it_is_sent() -> None:
    wire = _Wire(MESSAGE)
    client = _anthropic(wire, asynchronous=True)
    run = _governed(_Handle("deny"), None)
    try:
        with pytest.raises(HostedToolRefused):
            await client.messages.create(**_ms(tools=[WEB_SEARCH]))
        with pytest.raises(HostedToolRefused):
            async with client.messages.stream(**_ms(tools=[WEB_SEARCH])):
                pytest.fail("the stream must not open")
        with pytest.raises(HostedToolRefused):
            await client.beta.messages.create(**_ms(tools=[WEB_SEARCH]))
    finally:
        gate.detach_run(run)
    assert wire.sent == []


@pytest.mark.asyncio
async def test_a_hosted_tool_in_extra_body_is_decided() -> None:
    wire = _Wire(MESSAGE)
    client = _anthropic(wire, asynchronous=True)
    run = _governed(_Handle("deny"), None)
    try:
        with pytest.raises(HostedToolRefused):
            await client.messages.create(**_ms(), extra_body={"tools": [WEB_SEARCH]})
    finally:
        gate.detach_run(run)
    assert wire.sent == []


@pytest.mark.asyncio
async def test_an_unregistered_mcp_server_is_refused_and_a_registered_one_is_decided() -> (
    None
):
    wire = _Wire(MESSAGE)
    client = _anthropic(wire, asynchronous=True)
    server = {"type": "url", "url": MCP_URL, "name": "docs"}
    handle = _Handle("allow")
    run = _governed(handle, None)
    try:
        with pytest.raises(HostedToolRefused):
            await client.beta.messages.create(
                **_ms(), extra_body={"mcp_servers": [server]}
            )
    finally:
        gate.detach_run(run)
    assert wire.sent == [] and handle.decisions == []

    run = _governed(handle, None, registered_mcp_servers={MCP_URL: "docs"})
    try:
        await client.beta.messages.create(**_ms(), extra_body={"mcp_servers": [server]})
    finally:
        gate.detach_run(run)
    assert handle.decisions == [('Action::"execute"', 'Resource::"mcp://docs/"')]
    assert len(wire.sent) == 1


@pytest.mark.asyncio
async def test_a_message_batch_is_decided_request_by_request_and_refused_whole() -> (
    None
):
    wire = _Wire(
        {"id": "b", "type": "message_batch", "processing_status": "in_progress"}
    )
    client = _anthropic(wire, asynchronous=True)
    requests = [
        {"custom_id": "plain", "params": _ms()},
        {"custom_id": "search", "params": _ms(tools=[WEB_SEARCH])},
    ]
    handle = _Handle("deny")
    run = _governed(handle, None)
    try:
        with pytest.raises(HostedToolRefused):
            await client.messages.batches.create(requests=requests)
    finally:
        gate.detach_run(run)
    assert wire.sent == []
    assert handle.decisions == [('Action::"execute"', 'Tool::"web_search"')]


@pytest.mark.asyncio
async def test_openai_chat_and_responses_request_fields_are_decided() -> None:
    wire = _Wire(COMPLETION)
    client = _openai(wire, asynchronous=True)
    run = _governed(_Handle("deny"), None)
    try:
        with pytest.raises(HostedToolRefused):
            await client.chat.completions.create(
                model="m",
                messages=[{"role": "user", "content": "x"}],
                web_search_options={},
            )
        with pytest.raises(HostedToolRefused):
            await client.responses.create(
                model="m", input="x", tools=[{"type": "web_search"}]
            )
        with pytest.raises(HostedToolRefused):
            await client.responses.create(
                model="m", input="x", extra_body={"prompt": {"id": "pmpt_1"}}
            )
    finally:
        gate.detach_run(run)
    assert wire.sent == []


@pytest.mark.asyncio
async def test_an_xai_request_is_decided_as_xai() -> None:
    wire = _Wire(COMPLETION)
    client = _openai(wire, asynchronous=True, base_url="https://api.x.ai/v1")
    handle = _Handle("deny")
    run = _governed(handle, None)
    try:
        with pytest.raises(HostedToolRefused):
            await client.chat.completions.create(
                model="grok",
                messages=[{"role": "user", "content": "x"}],
                extra_body={"search_parameters": {"mode": "on"}},
            )
    finally:
        gate.detach_run(run)
    assert wire.sent == [] and handle.decisions


def test_a_function_tool_alone_needs_no_decision(run_loop: Any) -> None:
    wire = _Wire(COMPLETION)
    handle = _Handle("deny")
    run = _governed(handle, run_loop)
    try:
        _openai(wire).chat.completions.create(
            model="m",
            messages=[{"role": "user", "content": "x"}],
            tools=[
                {
                    "type": "function",
                    "function": {"name": "f", "parameters": {"type": "object"}},
                }
            ],
        )
    finally:
        gate.detach_run(run)
    assert handle.decisions == [] and len(wire.sent) == 1


# ── refused APIs ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_apis_with_server_side_tools_are_refused_in_a_governed_run() -> None:
    wire = _Wire({})
    oa = _openai(wire, asynchronous=True)
    an = _anthropic(wire, asynchronous=True)
    run = _governed(_Handle("allow"), None)
    try:
        with pytest.raises(ProviderApiRefused):
            await oa.batches.create(
                completion_window="24h",
                endpoint="/v1/responses",
                input_file_id="file_1",
            )
        with pytest.raises(ProviderApiRefused):
            await oa.responses.create(
                model="m", input="x", previous_response_id="resp_1"
            )
        with pytest.raises(ProviderApiRefused):
            await oa.post(
                "/threads/thread_1/runs",
                body={"assistant_id": "asst_1"},
                cast_to=_httpx_of(openai).Response,
            )
        with pytest.raises(ProviderApiRefused):
            await oa.post(
                "/agents/sessions", body={}, cast_to=_httpx_of(openai).Response
            )
        with pytest.raises(ProviderApiRefused):
            await an.post(
                "/v1/sessions", body={}, cast_to=_httpx_of(anthropic).Response
            )
        with pytest.raises(ProviderApiRefused):
            async with oa.realtime.connect(model="gpt-realtime"):
                pytest.fail("the socket must not open")
    finally:
        gate.detach_run(run)
    assert wire.sent == []

    # Outside any governed run, nothing changes.
    await oa.post("/agents/sessions", body={}, cast_to=_httpx_of(openai).Response)
    assert wire.sent == ["/v1/agents/sessions"] or wire.sent == ["/agents/sessions"]


@pytest.mark.asyncio
async def test_endpoints_that_send_no_tools_pass() -> None:
    wire = _Wire(
        {
            "object": "list",
            "data": [
                {"object": "embedding", "index": 0, "embedding": [0.1], "id": "m"}
            ],
            "model": "m",
            "usage": {"prompt_tokens": 0, "total_tokens": 0},
        }
    )
    client = _openai(wire, asynchronous=True)
    handle = _Handle("deny")
    run = _governed(handle, None)
    try:
        await client.embeddings.create(model="m", input="x")
        await client.models.list()
    finally:
        gate.detach_run(run)
    assert handle.decisions == [] and len(wire.sent) == 2


@pytest.mark.asyncio
async def test_a_made_up_write_path_is_refused_on_each_sdk(
    listener: "_Listener",
) -> None:
    wire = _Wire({})
    oa = _openai(wire, asynchronous=True)
    an = _anthropic(wire, asynchronous=True)
    gm = _gemini(listener)
    run = _governed(_Handle("allow"), asyncio.get_running_loop())
    try:
        with pytest.raises(ProviderApiRefused):
            await an.post(
                "/v1/made_up/run", body={}, cast_to=_httpx_of(anthropic).Response
            )
        with pytest.raises(ProviderApiRefused):
            await oa.post("/made_up/run", body={}, cast_to=_httpx_of(openai).Response)
        with pytest.raises(ProviderApiRefused):
            await gm.aio._api_client.async_request(
                "post", "models/gemini-x:madeUpRun", {}
            )
    finally:
        gate.detach_run(run)
    assert wire.sent == [] and listener.connections == 0


#: Paths the HTTP client may rewrite before sending: each is refused, never
#: normalised (``files/../responses`` is sent to ``responses``).
_REWRITTEN_PATHS = [
    "/files/../responses",
    "/./responses",
    "/files/%2e%2e/responses",
    "/files/%2E%2E/responses",
    "/files%2f..%2fresponses",
    "/files%2F..%2Fresponses",
    "/files%5c..%5cresponses",
    "/files%5C..%5Cresponses",
    "/files\\..\\responses",
    "//responses",
    "/files//responses",
    "/responses/",
]


@pytest.mark.asyncio
@pytest.mark.parametrize("path", _REWRITTEN_PATHS)
async def test_a_path_the_http_client_could_rewrite_is_refused(path: str) -> None:
    wire = _Wire(COMPLETION)
    client = _openai(wire, asynchronous=True)
    handle = _Handle("allow")
    run = _governed(handle, None)
    try:
        with pytest.raises(ProviderApiRefused):
            await client.post(
                path,
                body={"model": "m", "input": "x", "tools": [{"type": "web_search"}]},
                cast_to=_httpx_of(openai).Response,
            )
    finally:
        gate.detach_run(run)
    assert wire.sent == [] and handle.decisions == []


@pytest.mark.asyncio
async def test_a_rewritable_path_is_refused_on_each_sdk(listener: "_Listener") -> None:
    wire = _Wire(MESSAGE)
    an = _anthropic(wire, asynchronous=True)
    gm = _gemini(listener)
    run = _governed(_Handle("allow"), asyncio.get_running_loop())
    try:
        with pytest.raises(ProviderApiRefused):
            await an.post(
                "/v1/files/../messages",
                body=_ms(tools=[WEB_SEARCH]),
                cast_to=_httpx_of(anthropic).Response,
            )
        with pytest.raises(ProviderApiRefused):
            await gm.aio._api_client.async_request(
                "post",
                "models/gemini-x/../gemini-x:generateContent",
                {"tools": [{"google_search": {}}]},
            )
    finally:
        gate.detach_run(run)
    assert wire.sent == [] and listener.connections == 0


@pytest.mark.asyncio
async def test_an_unreadable_body_is_refused_in_the_run_and_by_the_backstop() -> None:
    wire = _Wire(MESSAGE)
    client = _anthropic(wire, asynchronous=True)
    handle = _Handle("allow")
    unreadable = ["not", "an", "object"]
    response = _httpx_of(anthropic).Response
    run = _governed(handle, None)
    try:
        with pytest.raises(HostedToolRefused):
            await client.post("/v1/messages", body=unreadable, cast_to=response)
    finally:
        gate.detach_run(run)
    entered, leave = asyncio.Event(), asyncio.Event()

    async def governed_elsewhere() -> None:
        other = _governed(_Handle("allow"), None)
        entered.set()
        await leave.wait()
        gate.detach_run(other)

    task = asyncio.create_task(governed_elsewhere(), context=contextvars.Context())
    await entered.wait()
    try:
        with pytest.raises(UnmarkedToolBindingRefused):
            await client.post("/v1/messages", body=unreadable, cast_to=response)
    finally:
        leave.set()
        await task
    assert wire.sent == [] and handle.decisions == []


def test_a_client_created_before_install_is_gated(
    monkeypatch: pytest.MonkeyPatch, run_loop: Any
) -> None:
    """The wraps are on the SDK classes, so a client made before them is
    gated too."""
    gate.install()
    base = anthropic._base_client.SyncAPIClient
    monkeypatch.setattr(base, "request", base.__dict__["request"].__wrapped__)
    monkeypatch.setattr(gate, "_installed", {})
    wire = _Wire(MESSAGE)
    client = _anthropic(wire)
    assert not getattr(base.__dict__["request"], gate._MARK, False)
    handle = _Handle("deny")
    run = _governed(handle, run_loop)  # attach_run installs the wraps
    try:
        with pytest.raises(HostedToolRefused):
            client.messages.create(**_ms(tools=[WEB_SEARCH]))
    finally:
        gate.detach_run(run)
    assert wire.sent == [] and handle.decisions == [
        ('Action::"execute"', 'Tool::"web_search"')
    ]


@pytest.mark.asyncio
async def test_each_skill_is_decided_on_the_request_sent() -> None:
    wire = _Wire(MESSAGE)
    client = _anthropic(wire, asynchronous=True)
    handle = _Handle("allow")
    skills = [
        {"type": "anthropic", "skill_id": "pptx"},
        {"type": "custom", "skill_id": "skill_01abc"},
    ]
    run = _governed(handle, None)
    try:
        await client.beta.messages.create(
            **_ms(), extra_body={"container": {"skills": skills}}
        )
        with pytest.raises(HostedToolRefused):
            await client.beta.messages.create(
                **_ms(), extra_body={"container": {"skills": "pptx"}}
            )
    finally:
        gate.detach_run(run)
    assert handle.decisions == [('Action::"execute"', 'Tool::"skill"')] * 2
    assert [c["hosted_tool"]["skill_id"] for c in handle.contexts] == [
        "pptx",
        "skill_01abc",
    ]
    assert len(wire.sent) == 1


@pytest.mark.asyncio
async def test_file_search_is_decided_with_its_stores() -> None:
    wire = _Wire(COMPLETION)
    client = _openai(wire, asynchronous=True)
    handle = _Handle("deny")
    run = _governed(handle, None)
    try:
        with pytest.raises(HostedToolRefused):
            await client.responses.create(
                model="m",
                input="x",
                tools=[{"type": "file_search", "vector_store_ids": ["vs_b", "vs_a"]}],
            )
    finally:
        gate.detach_run(run)
    assert wire.sent == []
    hosted = {
        "provider": "openai",
        "kind": "file_search",
        "vector_store_ids": ["vs_a", "vs_b"],
    }
    assert handle.contexts == [{"builtin_tool": True, "hosted_tool": hosted}]


# ── the backstop and the marker ─────────────────────────────────────


@pytest.mark.asyncio
async def test_without_the_marker_a_tool_binding_request_is_refused_while_a_run_is_live() -> (
    None
):
    wire = _Wire(MESSAGE)
    client = _anthropic(wire, asynchronous=True)
    before = gate.unmarked_refusals()
    entered, leave = asyncio.Event(), asyncio.Event()

    async def governed() -> None:
        run = _governed(_Handle("allow"), None)
        entered.set()
        await leave.wait()
        gate.detach_run(run)

    task = asyncio.create_task(governed(), context=contextvars.Context())
    await entered.wait()
    try:
        with pytest.raises(UnmarkedToolBindingRefused):
            await client.messages.create(**_ms(tools=[WEB_SEARCH]))
        fn = {"name": "f", "input_schema": {"type": "object"}}
        with pytest.raises(UnmarkedToolBindingRefused):
            await client.messages.create(**_ms(tools=[fn]))
        with pytest.raises(UnmarkedToolBindingRefused):
            await asyncio.to_thread(
                _bare_thread,
                lambda: _anthropic(wire).messages.create(**_ms(tools=[fn])),
            )
        await client.messages.create(**_ms())  # no tools: passes
        assert gate.live(), "the refusal must not end the live run"
    finally:
        leave.set()
        await task
    assert gate.unmarked_refusals() == before + 3
    assert wire.sent == ["/v1/messages"]


@pytest.mark.asyncio
async def test_a_task_that_outlives_its_run_is_refused() -> None:
    wire = _Wire(MESSAGE)
    client = _anthropic(wire, asynchronous=True)
    go = asyncio.Event()

    async def late_call() -> Any:
        await go.wait()
        return await client.messages.create(
            **_ms(tools=[{"name": "f", "input_schema": {"type": "object"}}])
        )

    run = _governed(_Handle("allow"), None)
    task = asyncio.create_task(late_call())  # copies the context: carries the marker
    gate.detach_run(run)
    go.set()
    with pytest.raises(UnmarkedToolBindingRefused):
        await task
    assert wire.sent == []


@pytest.mark.asyncio
async def test_no_effect_with_no_governed_run() -> None:
    wire = _Wire(MESSAGE)
    await _anthropic(wire, asynchronous=True).messages.create(**_ms(tools=[WEB_SEARCH]))
    _anthropic(wire).messages.create(**_ms(tools=[WEB_SEARCH]))
    assert len(wire.sent) == 2


@pytest.mark.asyncio
async def test_a_sync_request_on_the_runs_loop_thread_is_refused_without_hanging() -> (
    None
):
    wire = _Wire(MESSAGE)
    run = _governed(_Handle("allow"), asyncio.get_running_loop())
    try:
        with pytest.raises(HostedToolRefused):
            _anthropic(wire).messages.create(**_ms(tools=[WEB_SEARCH]))
    finally:
        gate.detach_run(run)
    assert wire.sent == []


class _LoopRecordingHandle(_Handle):
    """Records the loop each decision is made on."""

    def __init__(self, decision: str) -> None:
        super().__init__(decision)
        self.loops: List[Any] = []

    async def authorize_action_detailed(self, *args: Any, **kwargs: Any) -> Any:
        self.loops.append(asyncio.get_running_loop())
        return await super().authorize_action_detailed(*args, **kwargs)


@pytest.mark.parametrize("decision,sent", [("deny", []), ("allow", ["/v1/messages"])])
def test_an_async_request_on_another_loop_is_decided_on_the_runs_loop(
    run_loop: Any, decision: str, sent: List[str]
) -> None:
    """A framework that drives its own loop on a worker thread (Pydantic
    AI's ``run_sync``): the run's backend client belongs to the run's loop,
    so the decision is made there."""
    wire = _Wire(MESSAGE)
    handle = _LoopRecordingHandle(decision)
    run = _governed(handle, run_loop)
    try:
        call = _anthropic(wire, asynchronous=True).messages.create(
            **_ms(tools=[WEB_SEARCH])
        )
        if decision == "deny":
            with pytest.raises(HostedToolRefused):
                asyncio.run(call)
        else:
            asyncio.run(call)
    finally:
        gate.detach_run(run)
    assert handle.loops == [run_loop]
    assert wire.sent == sent


def _finished_loop(closed: bool) -> asyncio.AbstractEventLoop:
    """A loop that ran and stopped, closed or not."""
    loop = asyncio.new_event_loop()
    loop.run_until_complete(asyncio.sleep(0))
    if closed:
        loop.close()
    return loop


@pytest.mark.parametrize("closed", [False, True])
@pytest.mark.parametrize("asynchronous", [False, True])
def test_a_request_whose_run_loop_has_finished_is_refused_at_once(
    closed: bool, asynchronous: bool
) -> None:
    """No loop is left to decide on: the request is refused immediately,
    without waiting for the decision timeout."""
    loop = _finished_loop(closed)
    wire = _Wire(MESSAGE)
    handle = _Handle("allow")
    run = _governed(handle, loop)
    started = time.monotonic()
    try:
        with pytest.raises(HostedToolRefused) as refused:
            if asynchronous:
                asyncio.run(
                    _anthropic(wire, asynchronous=True).messages.create(
                        **_ms(tools=[WEB_SEARCH])
                    )
                )
            else:
                _anthropic(wire).messages.create(**_ms(tools=[WEB_SEARCH]))
    finally:
        gate.detach_run(run)
        if not closed:
            loop.close()
    assert time.monotonic() - started < 2.0 < gate.DECISION_TIMEOUT_SECONDS
    assert refused.value.gate.result.reason == "hosted_tool_authorization_unavailable"
    assert handle.decisions == [] and wire.sent == []


@pytest.mark.parametrize("asynchronous", [False, True])
def test_a_request_whose_run_loop_stays_busy_is_refused_at_the_timeout(
    run_loop: Any, monkeypatch: pytest.MonkeyPatch, asynchronous: bool
) -> None:
    monkeypatch.setattr(gate, "DECISION_TIMEOUT_SECONDS", 0.3)
    release = threading.Event()
    run_loop.call_soon_threadsafe(release.wait, 10)  # the run's loop is blocked
    wire = _Wire(MESSAGE)
    handle = _Handle("allow")
    run = _governed(handle, run_loop)
    started = time.monotonic()
    try:
        with pytest.raises(HostedToolRefused) as refused:
            if asynchronous:
                asyncio.run(
                    _anthropic(wire, asynchronous=True).messages.create(
                        **_ms(tools=[WEB_SEARCH])
                    )
                )
            else:
                _anthropic(wire).messages.create(**_ms(tools=[WEB_SEARCH]))
        waited = time.monotonic() - started
    finally:
        release.set()
        gate.detach_run(run)
    asyncio.run_coroutine_threadsafe(asyncio.sleep(0), run_loop).result(5)
    assert 1.0 <= waited < 5.0
    assert refused.value.gate.result.reason == "hosted_tool_authorization_timeout"
    assert handle.decisions == [], (
        "a decision that lands after the wait gave up is never made"
    )
    assert wire.sent == []


def test_a_replaced_wrap_refuses_the_run(monkeypatch: pytest.MonkeyPatch) -> None:
    gate.install()
    base = anthropic._base_client.AsyncAPIClient
    monkeypatch.setattr(base, "request", base.__dict__["request"].__wrapped__)
    with pytest.raises(GovernanceUnavailable):
        gate.attach_run(_Handle("allow"))
    assert not gate.live()


def _bare_thread(fn: Any) -> Any:
    box: Dict[str, Any] = {}

    def run() -> None:
        try:
            box["value"] = fn()
        except BaseException as exc:  # noqa: BLE001 - re-raised below
            box["error"] = exc

    thread = threading.Thread(target=run, daemon=True)  # does not copy the context
    thread.start()
    thread.join(10)
    assert not thread.is_alive(), "the call hung"
    if "error" in box:
        raise box["error"]
    return box.get("value")


# ── google-genai ────────────────────────────────────────────────────


class _Listener:
    """A local TCP endpoint that counts connections and closes them."""

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


@pytest.fixture
def listener() -> Iterator[_Listener]:
    lst = _Listener()
    yield lst
    lst.close()


def _gemini(listener: _Listener) -> Any:
    from google.genai import types

    return genai.Client(
        api_key="k", http_options=types.HttpOptions(base_url=listener.url, timeout=2000)
    )


def _search_config() -> Any:
    from google.genai import types

    return types.GenerateContentConfig(
        tools=[types.Tool(google_search=types.GoogleSearch())]
    )


@pytest.mark.asyncio
async def test_gemini_hosted_tool_is_decided_before_it_is_sent(
    listener: _Listener,
) -> None:
    client = _gemini(listener)
    handle = _Handle("deny")
    run = _governed(handle, asyncio.get_running_loop())
    try:
        with pytest.raises(HostedToolRefused):
            await client.aio.models.generate_content(
                model="gemini-x", contents="q", config=_search_config()
            )
        with pytest.raises(HostedToolRefused):
            stream = await client.aio.models.generate_content_stream(
                model="gemini-x", contents="q", config=_search_config()
            )
            [_ async for _ in stream]
        with pytest.raises(HostedToolRefused):
            await asyncio.to_thread(
                client.models.generate_content,
                model="gemini-x",
                contents="q",
                config=_search_config(),
            )
        with pytest.raises(ProviderApiRefused):
            async with client.aio.live.connect(model="gemini-live"):
                pytest.fail("the socket must not open")
    finally:
        gate.detach_run(run)
    assert listener.connections == 0
    assert ('Action::"execute"', 'Tool::"google_search"') in handle.decisions

    # Control: allowed, the same request is sent.
    run = _governed(_Handle("allow"), asyncio.get_running_loop())
    try:
        with pytest.raises(Exception) as sent:
            await client.aio.models.generate_content(
                model="gemini-x", contents="q", config=_search_config()
            )
    finally:
        gate.detach_run(run)
    assert not isinstance(sent.value, HostedToolRefused)
    assert listener.connections >= 1
