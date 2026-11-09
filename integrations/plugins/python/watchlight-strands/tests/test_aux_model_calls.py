"""Model calls Strands makes outside the agent loop.

The deprecated ``Agent.structured_output``, the default summary of
``SummarizingConversationManager`` and memory extraction call the model
with no ``BeforeModelCallEvent`` and no invoke-model middleware. These
tests drive real Strands agents and the providers' real SDKs; only the
transports are stand-ins (``httpx.MockTransport`` for OpenAI and Gemini,
botocore's ``Stubber`` for Bedrock), so a request that reaches a provider
is recorded exactly as it would be sent. Every refusal test first checks
the request it refuses really would have reached the provider.
"""

from __future__ import annotations

import json
import warnings
from typing import Any, Dict, List

import httpx
import pytest
from botocore.stub import Stubber
from conftest import ScriptedModel, events_of, text
from pydantic import BaseModel
from strands import Agent
from strands.agent.conversation_manager import SummarizingConversationManager
from strands.hooks import BeforeModelCallEvent
from strands.memory import ExtractionConfig, InvocationTrigger, MemoryManager, ModelExtractor
from strands.models import Model
from strands.types.exceptions import ContextWindowOverflowException
from strands.vended_memory_stores.test_memory_store import TestMemoryStore
from watchlight_core.hosted_tools import HostedToolRefused
from watchlight_core_testing import MockApdpClient
from watchlight_strands import governing_plugin
from watchlight_strands.aux_models import UngovernedModelCall

HAS_AUX_MODEL = isinstance(getattr(Agent, "aux_model", None), property)


def assert_refusal_recorded(mock: MockApdpClient, error: str) -> None:
    """The refusal is on the run's lineage: the run opened, then closed as
    failed with the refusal's type, and no tool or hosted tool was decided."""
    assert len(events_of(mock, "execution_started")) == 1
    (failed,) = events_of(mock, "execution_failed")
    assert error in json.dumps(failed)
    assert mock.authorize_calls == []


@pytest.fixture(autouse=True)
def _aws(monkeypatch: pytest.MonkeyPatch) -> None:
    # Credentials only so botocore builds a client; the Stubber answers.
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "stand-in")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "stand-in")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")


class Out(BaseModel):
    answer: str


def hosted_calls(mock: MockApdpClient) -> List[Dict[str, Any]]:
    return [c for c in mock.authorize_calls if "hosted_tool" in json.dumps(c, default=str)]


# ── provider stand-ins ───────────────────────────────────────────────


class OpenAIWire:
    """The OpenAI SDK's transport: records every request body."""

    def __init__(self) -> None:
        self.requests: List[Dict[str, Any]] = []
        self.mock: Any = None
        self.decided_before: List[int] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content or b"{}")
        self.requests.append(body)
        if self.mock is not None:
            self.decided_before.append(len(hosted_calls(self.mock)))
        if body.get("stream"):
            chunks = [
                {"id": "c", "object": "chat.completion.chunk", "created": 0, "model": "m",
                 "choices": [{"index": 0, "delta": {"role": "assistant", "content": "ok"}, "finish_reason": None}]},
                {"id": "c", "object": "chat.completion.chunk", "created": 0, "model": "m",
                 "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]},
            ]
            sse = "".join(f"data: {json.dumps(c)}\n\n" for c in chunks) + "data: [DONE]\n\n"
            return httpx.Response(200, headers={"content-type": "text/event-stream"}, content=sse.encode())
        return httpx.Response(200, json={
            "id": "c", "object": "chat.completion", "created": 0, "model": "m",
            "choices": [{"index": 0, "finish_reason": "stop",
                         "message": {"role": "assistant", "content": json.dumps({"answer": "x"})}}],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
        })

    def with_hosted_tool(self) -> List[Dict[str, Any]]:
        return [r for r in self.requests if "web_search_options" in r]


def openai_model(wire: OpenAIWire) -> Any:
    import openai
    from strands.models.openai import OpenAIModel

    client = openai.AsyncOpenAI(
        api_key="stand-in", http_client=httpx.AsyncClient(transport=httpx.MockTransport(wire.handler))
    )
    return OpenAIModel(client=client, model_id="gpt-4o", params={"web_search_options": {}})


class GeminiWire:
    def __init__(self) -> None:
        self.requests: List[Dict[str, Any]] = []
        self.mock: Any = None
        self.decided_before: List[int] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(json.loads(request.content or b"{}"))
        if self.mock is not None:
            self.decided_before.append(len(hosted_calls(self.mock)))
        reply = {"candidates": [{"content": {"role": "model", "parts": [{"text": json.dumps({"answer": "x"})}]},
                                 "finishReason": "STOP"}],
                 "usageMetadata": {"promptTokenCount": 1, "candidatesTokenCount": 1, "totalTokenCount": 2}}
        if "streamGenerateContent" in str(request.url):
            return httpx.Response(200, headers={"content-type": "text/event-stream"},
                                  content=f"data: {json.dumps(reply)}\n\n".encode())
        return httpx.Response(200, json=reply)

    def with_hosted_tool(self) -> List[Dict[str, Any]]:
        return [r for r in self.requests if any("googleSearch" in t for t in r.get("tools", []))]


def gemini_model(wire: GeminiWire) -> Any:
    from google import genai
    from google.genai import types
    from strands.models.gemini import GeminiModel

    client = genai.Client(
        api_key="stand-in",
        http_options=types.HttpOptions(
            httpx_async_client=httpx.AsyncClient(transport=httpx.MockTransport(wire.handler))
        ),
    )
    return GeminiModel(client=client, model_id="gemini-2.5-flash",
                       gemini_tools=[types.Tool(google_search=types.GoogleSearch())])


BEDROCK_HOSTED = {"tools": [{"type": "web_search_20250305", "name": "web_search"}]}


def bedrock_reply(content: List[Dict[str, Any]], stop: str = "end_turn") -> Dict[str, Any]:
    return {"output": {"message": {"role": "assistant", "content": content}}, "stopReason": stop,
            "usage": {"inputTokens": 1, "outputTokens": 1, "totalTokens": 2}, "metrics": {"latencyMs": 1}}


class BedrockWire:
    """botocore's Stubber on the model's own client, plus a record of the
    parameters of every call it answered."""

    def __init__(self, model: Any) -> None:
        self.stubber = Stubber(model.client)
        self.requests: List[Dict[str, Any]] = []
        self.mock: Any = None
        self.decided_before: List[int] = []
        model.client.meta.events.register("provide-client-params.bedrock-runtime.*", self._record)

    def _record(self, params: Dict[str, Any], **_: Any) -> None:
        self.requests.append(params)
        if self.mock is not None:
            self.decided_before.append(len(hosted_calls(self.mock)))

    def with_hosted_tool(self) -> List[Dict[str, Any]]:
        return [r for r in self.requests if r.get("additionalModelRequestFields") == BEDROCK_HOSTED]


def bedrock_model(**config: Any) -> Any:
    from strands.models.bedrock import BedrockModel

    config.setdefault("additional_request_fields", BEDROCK_HOSTED)
    return BedrockModel(model_id="anthropic.claude-stand-in", region_name="us-east-1", streaming=False, **config)


def provider(name: str) -> Any:
    """``(model, wire)`` for one provider, with a hosted tool configured."""
    if name == "openai":
        wire: Any = OpenAIWire()
        return openai_model(wire), wire
    if name == "gemini":
        wire = GeminiWire()
        return gemini_model(wire), wire
    model = bedrock_model()
    wire = BedrockWire(model)
    return model, wire


def structured_reply(wire: Any) -> None:
    if isinstance(wire, BedrockWire):
        wire.stubber.add_response("converse", bedrock_reply(
            [{"toolUse": {"toolUseId": "t1", "name": "Out", "input": {"answer": "x"}}}], "tool_use"))
        wire.stubber.activate()


# ── 1. the deprecated Agent.structured_output ────────────────────────


@pytest.mark.parametrize("name", ["openai", "gemini", "bedrock"])
def test_structured_output_reaches_the_provider_without_the_plugin(name):
    """The baseline the refusal below is measured against: without the
    plugin the call carries the hosted tool to the provider."""
    model, wire = provider(name)
    structured_reply(wire)
    agent = Agent(model=model, callback_handler=None)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        assert agent.structured_output(Out, "hi").answer == "x"
    assert len(wire.with_hosted_tool()) == 1


@pytest.mark.parametrize("name", ["openai", "gemini", "bedrock"])
def test_structured_output_is_refused(make_plugin, mock_apdp: MockApdpClient, name):
    model, wire = provider(name)
    structured_reply(wire)
    agent = Agent(model=model, plugins=[make_plugin("agent-root")], callback_handler=None)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        with pytest.raises(UngovernedModelCall, match="structured_output"):
            agent.structured_output(Out, "hi")
    assert wire.requests == []
    assert_refusal_recorded(mock_apdp, "UngovernedModelCall")


def test_structured_output_async_is_refused(make_plugin, mock_apdp: MockApdpClient):
    import asyncio

    wire = OpenAIWire()
    agent = Agent(model=openai_model(wire), plugins=[make_plugin("agent-root")], callback_handler=None)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        with pytest.raises(UngovernedModelCall):
            asyncio.run(agent.structured_output_async(Out, "hi"))
    assert wire.requests == []
    assert_refusal_recorded(mock_apdp, "UngovernedModelCall")


def test_structured_output_model_on_the_invocation_still_runs(make_plugin, mock_apdp: MockApdpClient):
    """The supported route is not caught by the refusal."""
    model = ScriptedModel([[("tool", "Out", {"answer": "x"})]])
    agent = Agent(model=model, plugins=[make_plugin("agent-root")], callback_handler=None)
    result = agent("hi", structured_output_model=Out)
    assert result.structured_output.answer == "x"


# ── 2. hosted tools of the static model configuration ────────────────


@pytest.mark.parametrize("name", ["openai", "gemini", "bedrock"])
def test_denied_config_hosted_tool_refuses_the_invocation(make_plugin, mock_apdp: MockApdpClient, name):
    mock_apdp.default_decision = "Deny"
    model, wire = provider(name)
    if isinstance(wire, BedrockWire):
        wire.stubber.add_response("converse", bedrock_reply([{"text": "ok"}]))
        wire.stubber.activate()
    agent = Agent(model=model, plugins=[make_plugin("agent-root")], callback_handler=None)
    calls: List[int] = []
    agent.hooks.add_callback(BeforeModelCallEvent, lambda e: calls.append(1))

    with pytest.raises(HostedToolRefused):
        agent("hi")

    assert wire.requests == [] and calls == []
    assert len(hosted_calls(mock_apdp)) == 1
    # The run that was opened is closed, as failed.
    assert [e["event_type"] for e in mock_apdp.published_events][-1] == "execution_failed"


@pytest.mark.parametrize("name", ["openai", "gemini", "bedrock"])
def test_allowed_config_hosted_tool_runs(make_plugin, mock_apdp: MockApdpClient, name):
    model, wire = provider(name)
    if isinstance(wire, BedrockWire):
        wire.stubber.add_response("converse", bedrock_reply([{"text": "ok"}]))
        wire.stubber.activate()
    wire.mock = mock_apdp
    agent = Agent(model=model, plugins=[make_plugin("agent-root")], callback_handler=None)
    agent("hi")
    assert len(wire.with_hosted_tool()) == 1
    # Decided when the invocation started, before the provider call.
    kind = "google_search" if name == "gemini" else "web_search"
    assert hosted_calls(mock_apdp)[0]["resource"] == f'Tool::"{kind}"'
    assert wire.decided_before[0] >= 1


def test_unreadable_model_config_refuses_the_invocation(make_plugin, mock_apdp: MockApdpClient):
    class Unreadable(ScriptedModel):
        def get_config(self) -> Any:
            raise RuntimeError("no config")

    model = Unreadable([[text("hi")]])
    agent = Agent(model=model, plugins=[make_plugin("agent-root")], callback_handler=None)
    with pytest.raises(UngovernedModelCall):
        agent("hi")
    assert model.calls == 0


# ── 2b. the summary SummarizingConversationManager writes ────────────


class OverflowOnce(Model):
    """A main model with no hosted tools whose first call overflows the
    context window, so Strands writes a summary."""

    def __init__(self) -> None:
        self.calls = 0

    def update_config(self, **kw: Any) -> None:
        return None

    def get_config(self) -> Any:
        return {}

    async def structured_output(self, *a: Any, **k: Any):  # type: ignore[override]
        raise NotImplementedError
        yield  # pragma: no cover

    async def stream(self, messages: Any, tool_specs: Any = None, system_prompt: Any = None, **kw: Any):  # type: ignore[override]
        self.calls += 1
        if self.calls == 1:
            raise ContextWindowOverflowException("too long")
        yield {"messageStart": {"role": "assistant"}}
        yield {"contentBlockDelta": {"delta": {"text": "ok"}}}
        yield {"contentBlockStop": {}}
        yield {"messageStop": {"stopReason": "end_turn"}}


def _history() -> List[Dict[str, Any]]:
    return [{"role": "user" if i % 2 == 0 else "assistant", "content": [{"text": f"m{i}"}]} for i in range(8)]


def _summarizing(**kw: Any) -> SummarizingConversationManager:
    return SummarizingConversationManager(summary_ratio=0.5, preserve_recent_messages=1, **kw)


@pytest.mark.skipif(not HAS_AUX_MODEL, reason="Agent(aux_model=...) arrived in Strands 1.62")
def test_aux_model_summary_reaches_the_provider_without_the_plugin():
    wire = OpenAIWire()
    agent = Agent(model=OverflowOnce(), aux_model=openai_model(wire), callback_handler=None,
                  conversation_manager=_summarizing(), messages=_history())
    agent("hi")
    assert len(wire.with_hosted_tool()) == 1


@pytest.mark.skipif(not HAS_AUX_MODEL, reason="Agent(aux_model=...) arrived in Strands 1.62")
def test_denied_aux_model_hosted_tool_refuses_before_the_summary(make_plugin, mock_apdp: MockApdpClient):
    mock_apdp.default_decision = "Deny"
    wire = OpenAIWire()
    main = OverflowOnce()
    agent = Agent(model=main, aux_model=openai_model(wire), plugins=[make_plugin("agent-root")],
                  callback_handler=None, conversation_manager=_summarizing(), messages=_history())
    with pytest.raises(HostedToolRefused):
        agent("hi")
    assert wire.requests == [] and main.calls == 0
    assert len(hosted_calls(mock_apdp)) == 1


def test_summary_with_the_main_model_is_covered_by_the_invocation_decision(make_plugin, mock_apdp: MockApdpClient):
    """Bedrock, default summary: the summary call (no BeforeModelCallEvent)
    carries the same configured hosted tool the invocation authorized."""
    model = bedrock_model()
    wire = BedrockWire(model)
    wire.stubber.add_client_error("converse", service_error_code="ValidationException",
                                  service_message="Input is too long for requested model.", http_status_code=400)
    wire.stubber.add_response("converse", bedrock_reply([{"text": "summary"}]))
    wire.stubber.add_response("converse", bedrock_reply([{"text": "final"}]))
    wire.stubber.activate()
    wire.mock = mock_apdp
    agent = Agent(model=model, plugins=[make_plugin("agent-root")], callback_handler=None,
                  conversation_manager=_summarizing(), messages=_history())
    gated: List[int] = []
    agent.hooks.add_callback(BeforeModelCallEvent, lambda e: gated.append(1))
    agent("hi")
    # Three provider calls (overflow, summary, retry), two model hooks: the
    # summary had none. The decision made when the invocation started came
    # before the first of them and covers the summary's configured tool.
    assert len(wire.with_hosted_tool()) == 3 and len(gated) == 2
    assert wire.decided_before[0] >= 1


def test_denied_hosted_tool_never_reaches_the_summary(make_plugin, mock_apdp: MockApdpClient):
    mock_apdp.default_decision = "Deny"
    model = bedrock_model()
    wire = BedrockWire(model)
    wire.stubber.activate()
    agent = Agent(model=model, plugins=[make_plugin("agent-root")], callback_handler=None,
                  conversation_manager=_summarizing(), messages=_history())
    with pytest.raises(HostedToolRefused):
        agent("hi")
    assert wire.requests == []


def test_summarization_agent_runs_as_a_governed_child(make_plugin, mock_apdp: MockApdpClient):
    summarizer = Agent(name="summarizer", model=ScriptedModel([[text("summary")]]), callback_handler=None)
    plugin = make_plugin("agent-root")
    agent = Agent(model=OverflowOnce(), plugins=[plugin], callback_handler=None,
                  conversation_manager=_summarizing(summarization_agent=summarizer), messages=_history())
    agent("hi")
    assert governing_plugin(summarizer) is plugin
    assert summarizer.model.calls == 1
    assert len(mock_apdp.spawn_subagent_calls) == 1


# ── 3. memory extraction ─────────────────────────────────────────────


def _extracting_store(extractor: Any = None) -> TestMemoryStore:
    config = ExtractionConfig(trigger=[InvocationTrigger()])
    config["extractor"] = extractor if extractor is not None else ModelExtractor()
    return TestMemoryStore(name="m", persist=False, extraction=config)


def _manager(store: Any) -> MemoryManager:
    return MemoryManager(stores=[store], injection=False, search_tool_config=False)


def test_extraction_reaches_the_provider_without_the_plugin():
    wire = OpenAIWire()
    agent = Agent(model=ScriptedModel([[text("ok")]]), callback_handler=None,
                  memory_manager=_manager(_extracting_store(ModelExtractor(model=openai_model(wire)))))
    agent("hi")
    assert len(wire.with_hosted_tool()) == 1


@pytest.mark.parametrize("own_model", [False, True])
def test_model_extraction_is_refused(make_plugin, mock_apdp: MockApdpClient, own_model):
    wire = OpenAIWire()
    model = openai_model(wire)
    extractor = ModelExtractor(model=openai_model(wire)) if own_model else ModelExtractor()
    agent = Agent(model=model, plugins=[make_plugin("agent-root")], callback_handler=None,
                  memory_manager=_manager(_extracting_store(extractor)))
    with pytest.raises(UngovernedModelCall, match="memory extraction"):
        agent("hi")
    assert wire.requests == []
    assert_refusal_recorded(mock_apdp, "UngovernedModelCall")


def test_model_extraction_as_a_plugin_is_refused(make_plugin, mock_apdp: MockApdpClient):
    wire = OpenAIWire()
    agent = Agent(model=openai_model(wire), callback_handler=None,
                  plugins=[_manager(_extracting_store()), make_plugin("agent-root")])
    with pytest.raises(UngovernedModelCall):
        agent("hi")
    assert wire.requests == []
    assert_refusal_recorded(mock_apdp, "UngovernedModelCall")


@pytest.mark.skipif(not HAS_AUX_MODEL, reason="Agent(aux_model=...) arrived in Strands 1.62")
def test_aux_model_extraction_is_refused(make_plugin, mock_apdp: MockApdpClient):
    wire = OpenAIWire()
    main = ScriptedModel([[text("ok")]])
    agent = Agent(model=main, aux_model=openai_model(wire), plugins=[make_plugin("agent-root")],
                  callback_handler=None, memory_manager=_manager(_extracting_store()))
    with pytest.raises(UngovernedModelCall):
        agent("hi")
    assert wire.requests == [] and main.calls == 0
    assert_refusal_recorded(mock_apdp, "UngovernedModelCall")


class RawMessageStore:
    """Store-side extraction: raw messages to ``add_messages``, no model."""

    name = "raw"
    description = None
    max_search_results = None
    writable = True

    def __init__(self) -> None:
        self.extraction = ExtractionConfig(trigger=[InvocationTrigger()])
        self.batches: List[Any] = []

    async def search(self, query: str, options: Any = None) -> list:
        return []

    async def add_messages(self, messages: Any, context: Any = None) -> None:
        self.batches.append(messages)


def test_store_side_extraction_is_not_refused(make_plugin, mock_apdp: MockApdpClient):
    store = RawMessageStore()
    model = ScriptedModel([[text("ok")]])
    agent = Agent(model=model, plugins=[make_plugin("agent-root")], callback_handler=None,
                  memory_manager=_manager(store))
    agent("hi")
    assert model.calls == 1 and store.batches


# ── the Strands surface these rules read ─────────────────────────────


def test_strands_surface_for_out_of_loop_model_calls():
    import inspect

    from strands.memory.extraction.coordinator import _ExtractionBinding

    # The deprecated entry points still fire BeforeInvocationEvent from
    # frames of these names (the refusal finds them on the frame chain).
    assert "BeforeInvocationEvent" in inspect.getsource(Agent.structured_output_async)
    assert Agent.structured_output_async.__code__.co_name == "structured_output_async"
    # Where the plugin finds memory managers and their extractors.
    agent = Agent(model=ScriptedModel(), callback_handler=None,
                  memory_manager=_manager(_extracting_store()))
    assert isinstance(agent._plugin_registry._plugins, dict)
    (binding,) = agent.memory_manager._extraction_stores
    assert isinstance(binding, _ExtractionBinding) and binding.config.extractor is not None
    assert hasattr(_summarizing(), "summarization_agent")
