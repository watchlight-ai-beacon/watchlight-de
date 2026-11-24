"""Every provider-hosted tool on a Strands model call is authorized before
the call (conformance invariant 19).

The gate is the innermost invoke-model middleware, so it reads the FINAL
request: the egress-parity tests drive a real Strands ``Agent`` with each
model class Strands ships over its real provider SDK, its HTTP (or boto3)
transport replaced by a recorder. Every hosted tool in a sent request has
an Allow recorded before the send; a Deny means nothing is sent. Further
tests show that a middleware which swaps the model or rewrites the tool
specs after ``BeforeModelCallEvent`` is gated on what it sends, and that a
middleware registry Watchlight cannot govern through refuses the call.
"""

from __future__ import annotations

import dataclasses
import importlib
import importlib.metadata
import inspect
import json
from types import ModuleType
from typing import Any, Callable, Dict, List, Optional, Tuple

import httpx
import pytest
from conftest import ScriptedModel, resources
from strands import Agent, tool
from watchlight_core import HostedToolRefused, normalize_hosted_request
from watchlight_core_testing import MockApdpClient

import watchlight_strands.plugin as plugin_module
from watchlight_strands import model_backstop
from watchlight_strands.model_backstop import UngovernedModelCall
from watchlight_strands import WatchlightStrandsPlugin
from watchlight_strands.hosted_tools import GATE_MARKER, MiddlewareDrift, invoke_model_stage

InvokeModelStage = invoke_model_stage()

MCP_URL = "https://mcp.example.test/mcp"


@tool
def lookup(q: str) -> str:
    """Look something up."""
    return "found"


class _Sent:
    """The provider requests a test transport saw, each with the hosted-tool
    allows recorded before it was sent."""

    def __init__(self, mock: MockApdpClient) -> None:
        self.mock = mock
        self.requests: List[Tuple[Dict[str, Any], List[str]]] = []

    def record(self, body: Dict[str, Any]) -> None:
        allowed = [
            call["context"]["hosted_tool"]["kind"]
            for call in self.mock.authorize_calls
            if isinstance(call.get("context"), dict) and "hosted_tool" in call["context"]
        ]
        self.requests.append((body, allowed))

    def transport(self, http: ModuleType = httpx) -> Any:
        """A recording transport from ``http`` (``httpx``, or ``httpx2`` for an
        SDK built on it; both have the same transport API)."""

        def handler(request: Any) -> Any:
            self.record(json.loads(request.content))
            # Refuse the call: the body is what matters, and a 400 is not retried.
            return http.Response(400, json={"error": {"message": "test transport", "type": "invalid_request_error"}})

        return http.MockTransport(handler)


def _http_library_of(distribution: str) -> ModuleType:
    """The HTTP client library the installed ``distribution`` is built on:
    anthropic 2.x requires ``httpx2`` and refuses an ``httpx`` client; 0.x
    uses ``httpx``."""
    from packaging.requirements import Requirement

    names = {Requirement(r).name for r in importlib.metadata.requires(distribution) or []}
    return importlib.import_module("httpx2") if "httpx2" in names else httpx


def _anthropic_http_client(sent: _Sent) -> Any:
    http = _http_library_of("anthropic")
    return http.AsyncClient(transport=sent.transport(http))


def _hosted_kinds(body: Dict[str, Any], provider: str) -> List[str]:
    return [t.kind for t in normalize_hosted_request(body, provider)]


def _in_chain(error: Optional[BaseException], kind: type) -> bool:
    """Is ``kind`` the error raised, or in its cause chain?"""
    chain = []
    while error is not None and error not in chain:
        chain.append(error)
        error = error.__cause__ or error.__context__
    return any(isinstance(e, kind) for e in chain)


async def _invoke(agent: Agent) -> Optional[BaseException]:
    try:
        await agent.invoke_async("Look it up.")
    except Exception as exc:  # noqa: BLE001 - the test asserts on what was sent
        return exc
    return None


# ── the model classes Strands ships, over their real SDKs ────────────


def _openai(sent: _Sent) -> Any:
    from strands.models.openai import OpenAIModel

    return OpenAIModel(
        model_id="gpt-test",
        client_args={"api_key": "test-key", "max_retries": 0, "http_client": httpx.AsyncClient(transport=sent.transport())},
        params={"web_search_options": {}},
    )


def _openai_responses(sent: _Sent) -> Any:
    from strands.models.openai_responses import OpenAIResponsesModel

    return OpenAIResponsesModel(
        model_id="gpt-test",
        client_args={"api_key": "test-key", "max_retries": 0, "http_client": httpx.AsyncClient(transport=sent.transport())},
        params={"tools": [{"type": "web_search"}]},
    )


def _anthropic(sent: _Sent) -> Any:
    from strands.models.anthropic import AnthropicModel

    return AnthropicModel(
        model_id="claude-test",
        max_tokens=16,
        client_args={"api_key": "test-key", "max_retries": 0, "http_client": _anthropic_http_client(sent)},
        params={"extra_body": {"tools": [{"type": "web_search_20250305", "name": "web_search"}]}},
    )


def _anthropic_mcp(sent: _Sent) -> Any:
    from strands.models.anthropic import AnthropicModel

    return AnthropicModel(
        model_id="claude-test",
        max_tokens=16,
        client_args={"api_key": "test-key", "max_retries": 0, "http_client": _anthropic_http_client(sent)},
        params={"extra_body": {"mcp_servers": [{"type": "url", "url": MCP_URL, "name": "docs"}]}},
    )


def _gemini(sent: _Sent) -> Any:
    from google.genai import types
    from strands.models.gemini import GeminiModel

    return GeminiModel(
        model_id="gemini-test",
        client_args={
            "api_key": "test-key",
            "http_options": types.HttpOptions(httpx_async_client=httpx.AsyncClient(transport=sent.transport())),
        },
        params={"http_options": {"extra_body": {"tools": [{"googleSearch": {}}]}}},
    )


def _bedrock(sent: _Sent) -> Any:
    from botocore.stub import Stubber
    from strands.models.bedrock import BedrockModel

    model = BedrockModel(
        model_id="anthropic.claude-test",
        region_name="us-east-1",
        streaming=False,
        additional_request_fields={"tools": [{"type": "web_search_20250305", "name": "web_search"}]},
    )
    model.client.meta.events.register(
        "provide-client-params.bedrock-runtime.Converse", lambda params, **_: sent.record(params)
    )
    stubber = Stubber(model.client)
    stubber.add_client_error("converse", service_error_code="ValidationException", http_status_code=400)
    stubber.activate()
    return model


#: (name, model factory, provider, the hosted kind its request enables)
MODELS: List[Tuple[str, Callable[[_Sent], Any], str, str]] = [
    ("openai_chat_web_search_options", _openai, "openai", "web_search"),
    ("openai_responses_params_tools", _openai_responses, "openai", "web_search"),
    ("anthropic_extra_body", _anthropic, "anthropic", "web_search"),
    ("gemini_http_options_extra_body", _gemini, "gemini", "google_search"),
    ("bedrock_additional_request_fields", _bedrock, "bedrock", "web_search"),
]


@pytest.fixture(autouse=True)
def _aws_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "test")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "test")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")


@pytest.mark.asyncio
@pytest.mark.parametrize("name,factory,provider,kind", MODELS, ids=[m[0] for m in MODELS])
async def test_every_hosted_tool_that_leaves_was_allowed_first(
    name: str, factory: Callable[[_Sent], Any], provider: str, kind: str, make_plugin: Any, mock_apdp: MockApdpClient
) -> None:
    sent = _Sent(mock_apdp)
    agent = Agent(model=factory(sent), tools=[lookup], plugins=[make_plugin("agent-root")])

    await _invoke(agent)

    assert len(sent.requests) == 1
    body, allowed_before = sent.requests[0]
    hosted = _hosted_kinds(body, provider)
    assert kind in hosted
    assert set(hosted) <= set(allowed_before)


@pytest.mark.asyncio
@pytest.mark.parametrize("name,factory,provider,kind", MODELS, ids=[m[0] for m in MODELS])
async def test_a_denied_hosted_tool_sends_nothing(
    name: str, factory: Callable[[_Sent], Any], provider: str, kind: str, make_plugin: Any, mock_apdp: MockApdpClient
) -> None:
    mock_apdp.decisions[("execute", kind)] = "Deny"
    sent = _Sent(mock_apdp)
    agent = Agent(model=factory(sent), tools=[lookup], plugins=[make_plugin("agent-root")])

    error = await _invoke(agent)

    assert sent.requests == []
    assert error is not None
    assert kind in resources(mock_apdp)


@pytest.mark.asyncio
async def test_an_unregistered_mcp_server_sends_nothing(make_plugin: Any, mock_apdp: MockApdpClient) -> None:
    sent = _Sent(mock_apdp)
    agent = Agent(model=_anthropic_mcp(sent), plugins=[make_plugin("agent-root")])

    error = await _invoke(agent)

    # The gate refused it, not the SDK (an SDK that rejected the client
    # would also send nothing).
    assert isinstance(error, HostedToolRefused), repr(error)
    assert sent.requests == []
    assert not [r for r in resources(mock_apdp) if r.startswith("mcp://")]


def test_the_anthropic_sdk_accepts_the_test_client(mock_apdp: MockApdpClient) -> None:
    """The recording client is one the installed anthropic SDK accepts, so a
    test that sends nothing is not passing on a rejected client."""
    import anthropic

    anthropic.AsyncAnthropic(api_key="test-key", http_client=_anthropic_http_client(_Sent(mock_apdp)))


@pytest.mark.asyncio
async def test_a_registered_mcp_server_is_allowed_before_it_leaves(make_plugin: Any, mock_apdp: MockApdpClient) -> None:
    sent = _Sent(mock_apdp)
    agent = Agent(
        model=_anthropic_mcp(sent),
        plugins=[make_plugin("agent-root", registered_mcp_servers={MCP_URL: "docs"})],
    )

    await _invoke(agent)

    assert len(sent.requests) == 1
    assert "mcp://docs/" in resources(mock_apdp)
    assert "mcp" in sent.requests[0][1]


# ── a middleware that changes the call after BeforeModelCallEvent ────


def _swap_to(model: Any) -> Callable[[Any], Any]:
    """An input middleware, as Strands' router model registers one, that
    swaps the model the call goes to."""

    def swap(ctx: Any) -> Any:
        return dataclasses.replace(ctx, model=model)

    return swap


@pytest.mark.asyncio
async def test_a_model_swapped_by_middleware_is_gated_on_what_it_sends(make_plugin: Any, mock_apdp: MockApdpClient) -> None:
    mock_apdp.decisions[("execute", "web_search")] = "Deny"
    sent = _Sent(mock_apdp)
    scripted = ScriptedModel()
    agent = Agent(model=scripted, plugins=[make_plugin("agent-root")])
    agent._middleware_registry.add_middleware(InvokeModelStage.Input, _swap_to(_openai(sent)))

    error = await _invoke(agent)

    # The model the hook saw has no hosted tool; the one the call reaches
    # has web search, which policy denies.
    assert error is not None
    assert sent.requests == [] and scripted.calls == 0
    assert "web_search" in resources(mock_apdp)


def _stream_on_the_instance(model: Any) -> Any:
    """``model`` with the class's unwrapped ``stream`` set on the instance: its
    calls skip the per-model backstop."""
    import types

    model.stream = types.MethodType(inspect.unwrap(type(model).stream), model)
    assert not model_backstop.has_backstop(model)
    return model


def _swap_to_a_model_made_per_call(sent: _Sent) -> Callable[[Any], Any]:
    """An input middleware that makes the model it swaps in at call time, so
    no check at run open can reach it, with ``stream`` set on the instance."""

    def swap(ctx: Any) -> Any:
        return dataclasses.replace(ctx, model=_stream_on_the_instance(_openai(sent)))

    return swap


@pytest.mark.asyncio
async def test_a_swapped_model_that_skips_the_backstop_is_decided_on_the_call(
    make_plugin: Any, mock_apdp: MockApdpClient
) -> None:
    mock_apdp.decisions[("execute", "web_search")] = "Deny"
    sent = _Sent(mock_apdp)
    scripted = ScriptedModel()
    agent = Agent(model=scripted, plugins=[make_plugin("agent-root")])
    agent._middleware_registry.add_middleware(InvokeModelStage.Input, _swap_to_a_model_made_per_call(sent))

    error = await _invoke(agent)

    assert _in_chain(error, HostedToolRefused)
    assert sent.requests == [] and scripted.calls == 0
    assert "web_search" in resources(mock_apdp)


@pytest.mark.asyncio
async def test_a_swapped_model_that_skips_the_backstop_is_refused_even_when_allowed(
    make_plugin: Any, mock_apdp: MockApdpClient
) -> None:
    """The per-call gate allows the call, but a model whose calls skip the
    backstop is refused, as it would be at run open."""
    sent = _Sent(mock_apdp)
    scripted = ScriptedModel()
    agent = Agent(model=scripted, plugins=[make_plugin("agent-root")])
    agent._middleware_registry.add_middleware(InvokeModelStage.Input, _swap_to_a_model_made_per_call(sent))

    error = await _invoke(agent)

    assert _in_chain(error, UngovernedModelCall)
    assert sent.requests == [] and scripted.calls == 0


@pytest.mark.asyncio
async def test_a_wrap_middleware_added_after_the_plugin_stays_outside_the_gate(
    make_plugin: Any, mock_apdp: MockApdpClient
) -> None:
    sent = _Sent(mock_apdp)
    openai_model = _openai(sent)
    agent = Agent(model=ScriptedModel(), plugins=[make_plugin("agent-root")])

    async def swap_then_call(ctx: Any, next_fn: Any) -> Any:
        async for event in next_fn(dataclasses.replace(ctx, model=openai_model)):
            yield event

    agent._middleware_registry.add_middleware(InvokeModelStage, swap_then_call)

    await _invoke(agent)

    assert len(sent.requests) == 1
    body, allowed_before = sent.requests[0]
    assert "web_search_options" in body
    assert "web_search" in allowed_before


@pytest.mark.asyncio
async def test_tool_specs_rewritten_by_middleware_are_what_the_gate_reads(
    make_plugin: Any, mock_apdp: MockApdpClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    sent = _Sent(mock_apdp)
    agent = Agent(model=_openai(sent), tools=[lookup], plugins=[make_plugin("agent-root")])
    late = {"name": "late_tool", "description": "added late", "inputSchema": {"json": {"type": "object", "properties": {}}}}

    def add_spec(ctx: Any) -> Any:
        return dataclasses.replace(ctx, tool_specs=list(ctx.tool_specs) + [late])

    agent._middleware_registry.add_middleware(InvokeModelStage.Input, add_spec)
    gated: List[Any] = []
    real = plugin_module.final_request

    def spy(ctx: Any) -> Any:
        request, provider = real(ctx)
        gated.append(request)
        return request, provider

    monkeypatch.setattr(plugin_module, "final_request", spy)

    await _invoke(agent)

    names = lambda req: sorted(t["function"]["name"] for t in req["tools"])  # noqa: E731
    assert len(sent.requests) == 1 and len(gated) == 1
    assert names(gated[0]) == names(sent.requests[0][0]) == ["late_tool", "lookup"]


# ── the private middleware API drifts: refuse, never fall back ───────


async def _refused(agent: Agent, model: ScriptedModel) -> None:
    """The model call is refused by the Watchlight drift check itself, not
    by Strands failing on the broken state."""
    error = await _invoke(agent)
    chain = []
    while error is not None:
        chain.append(error)
        error = error.__cause__ or error.__context__
    assert any(isinstance(e, MiddlewareDrift) for e in chain), chain
    assert model.calls == 0


class _RenamedHandlers:
    """A working registry whose private handler list has another name, as a
    Strands release might rename it: Strands still runs, Watchlight cannot
    pin its gate."""

    def __init__(self, inner: Any) -> None:
        self._inner = inner

    def add_middleware(self, *args: Any) -> None:
        self._inner.add_middleware(*args)

    def compose(self, *args: Any) -> Any:
        return self._inner.compose(*args)

    def invoke(self, *args: Any) -> Any:
        return self._inner.invoke(*args)


@pytest.mark.asyncio
async def test_a_registry_without_the_handler_list_refuses_the_model_call(make_plugin: Any) -> None:
    model = ScriptedModel()
    agent = Agent(model=model, plugins=[make_plugin("agent-root")])
    agent._middleware_registry = _RenamedHandlers(agent._middleware_registry)  # type: ignore[assignment]
    await _refused(agent, model)


@pytest.mark.asyncio
async def test_a_missing_invoke_model_stage_refuses_the_model_call(
    make_plugin: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    model = ScriptedModel()
    agent = Agent(model=model, plugins=[make_plugin("agent-root")])
    from watchlight_strands.hosted_tools import _stage_modules

    for module in _stage_modules():
        monkeypatch.delattr(module, "InvokeModelStage", raising=False)
    await _refused(agent, model)


@pytest.mark.asyncio
async def test_a_handler_list_of_another_shape_refuses_the_model_call(make_plugin: Any) -> None:
    model = ScriptedModel()
    agent = Agent(model=model, plugins=[make_plugin("agent-root")])
    agent._middleware_registry._handlers[InvokeModelStage] = ["not a handler"]
    await _refused(agent, model)


@pytest.mark.asyncio
async def test_a_handler_inside_the_gate_refuses_the_model_call(
    make_plugin: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    model = ScriptedModel()
    agent = Agent(model=model, plugins=[make_plugin("agent-root")])
    real = plugin_module.pin_innermost

    async def inner(ctx: Any, next_fn: Any) -> Any:
        async for event in next_fn(ctx):
            yield event

    def pin_then_add_inner(target: Any, gate: Any) -> None:
        real(target, gate)
        target._middleware_registry.add_middleware(InvokeModelStage, inner)

    monkeypatch.setattr(plugin_module, "pin_innermost", pin_then_add_inner)
    await _refused(agent, model)


def test_the_gate_is_marked_for_the_registry_check() -> None:
    plugin = WatchlightStrandsPlugin(apdp_url="http://localhost", agent_slug="agent-root", log_decisions=False)
    assert getattr(plugin._hosted_tool_gate, GATE_MARKER) is True
    assert issubclass(MiddlewareDrift, Exception)
    assert issubclass(HostedToolRefused, Exception)


# ── every model call is decided, not only the first ─────────────────


def _chunk(delta: Dict[str, Any], finish: Optional[str] = None) -> str:
    choice = {"index": 0, "delta": delta, "finish_reason": finish}
    return "data: " + json.dumps({"id": "c", "object": "chat.completion.chunk", "created": 0, "model": "gpt-test", "choices": [choice]}) + "\n\n"


class _KeptOpenClient(httpx.AsyncClient):
    """Strands' OpenAI model opens and closes an SDK client per call, which
    closes the ``http_client`` it was given: keep it open for the next call."""

    async def aclose(self) -> None:
        return None


def _streams_a_lookup_then_text(sent: _Sent) -> Any:
    """An OpenAI chat transport whose first answer calls ``lookup`` and whose
    later answers are text, so one invocation makes two model calls."""
    from strands.models.openai import OpenAIModel

    def handler(request: Any) -> Any:
        sent.record(json.loads(request.content))
        if len(sent.requests) == 1:
            call = {"index": 0, "id": "call_1", "type": "function", "function": {"name": "lookup", "arguments": '{"q": "x"}'}}
            body = _chunk({"role": "assistant", "tool_calls": [call]}) + _chunk({}, "tool_calls")
        else:
            body = _chunk({"role": "assistant", "content": "done"}) + _chunk({}, "stop")
        return httpx.Response(200, headers={"content-type": "text/event-stream"}, content=body + "data: [DONE]\n\n")

    return OpenAIModel(
        model_id="gpt-test",
        client_args={"api_key": "test-key", "max_retries": 0, "http_client": _KeptOpenClient(transport=httpx.MockTransport(handler))},
        params={"web_search_options": {}},
    )


@pytest.mark.asyncio
async def test_a_hosted_tool_denied_mid_run_is_refused_on_the_next_model_call(
    make_plugin: Any, mock_apdp: MockApdpClient
) -> None:
    """A hosted tool allowed on the first model call is decided again on the
    next one: when policy denies it in between, the next call is refused and
    nothing more is sent. An allow is never carried over to a later call."""
    sent = _Sent(mock_apdp)

    @tool(name="lookup")
    def revoke_then_answer(q: str) -> str:
        """Look something up; policy revokes web search meanwhile."""
        mock_apdp.decisions[("execute", "web_search")] = "Deny"
        return "found"

    agent = Agent(model=_streams_a_lookup_then_text(sent), tools=[revoke_then_answer], plugins=[make_plugin("agent-root")])

    error = await _invoke(agent)

    assert len(sent.requests) == 1, "the call after the denial was sent"
    assert _in_chain(error, HostedToolRefused)
    web_search = [c for c in mock_apdp.authorize_calls if "web_search" in str(c)]
    assert len(web_search) >= 3, "decided at run open, on call 1, and again on call 2"
