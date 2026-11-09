"""Models Strands components call outside the agent loop, and memory
writes after the run.

These tests drive real Strands agents and the real OpenAI SDK. Only the
transport is a stand-in (``httpx.MockTransport``), so a request that
reaches the provider is recorded as it would be sent. Each component is
first shown to reach the provider without the plugin. The hosted tool is
``web_search`` (``params={"web_search_options": {}}``), and policy denies
only that tool unless a test says otherwise.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List

import httpx
import pytest
from conftest import ScriptedModel, events_of, text, tool_call
from strands import Agent, tool
from strands.agent.conversation_manager import SummarizingConversationManager
from strands.hooks import BeforeModelCallEvent
from strands.memory import ExtractionConfig, InvocationTrigger, MemoryManager
from watchlight_core.hosted_tools import HostedToolRefused
from watchlight_core_testing import MockApdpClient
from watchlight_strands import model_reach
from watchlight_strands.model_reach import MemoryWriteRefused, UngovernedModelUse


@tool
def lookup(q: str) -> str:
    """Look something up."""
    return "found"


class Wire:
    """The OpenAI SDK's transport: records every request body, and how many
    ``web_search`` decisions the backend had made when it arrived."""

    def __init__(self, mock: MockApdpClient) -> None:
        self.mock = mock
        self.requests: List[Dict[str, Any]] = []
        self.decided_before: List[int] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(json.loads(request.content or b"{}"))
        self.decided_before.append(len(web_search_decisions(self.mock)))
        chunks = [
            {"id": "c", "object": "chat.completion.chunk", "created": 0, "model": "m",
             "choices": [{"index": 0, "delta": {"role": "assistant", "content": "ok"}, "finish_reason": None}]},
            {"id": "c", "object": "chat.completion.chunk", "created": 0, "model": "m",
             "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]},
        ]
        sse = "".join(f"data: {json.dumps(c)}\n\n" for c in chunks) + "data: [DONE]\n\n"
        return httpx.Response(200, headers={"content-type": "text/event-stream"}, content=sse.encode())

    def with_hosted_tool(self) -> List[Dict[str, Any]]:
        return [r for r in self.requests if "web_search_options" in r]


def web_search_decisions(mock: MockApdpClient) -> List[Dict[str, Any]]:
    return [c for c in mock.authorize_calls if c["resource"] == 'Tool::"web_search"']


def openai_model(wire: Wire) -> Any:
    import openai
    from strands.models.openai import OpenAIModel

    client = openai.AsyncOpenAI(
        api_key="stand-in", http_client=httpx.AsyncClient(transport=httpx.MockTransport(wire.handler))
    )
    return OpenAIModel(client=client, model_id="gpt-4o", params={"web_search_options": {}})


def _history() -> List[Dict[str, Any]]:
    return [{"role": "user" if i % 2 == 0 else "assistant", "content": [{"text": "x" * 400}]} for i in range(10)]


# Each component: build an agent whose component holds ``inner`` as its own
# model, and the main model never has a hosted tool.


def _steering(inner: Any, plugins: List[Any]) -> Agent:
    from strands.vended_plugins.steering import LLMSteeringHandler

    return Agent(model=ScriptedModel([[tool_call("lookup", {"q": "a"})]]), tools=[lookup],
                 plugins=[LLMSteeringHandler(system_prompt="judge", model=inner), *plugins], callback_handler=None)


def _hitl(inner: Any, plugins: List[Any]) -> Agent:
    from strands.vended_interventions.hitl import HumanInTheLoop, LLMClassifierConfig

    hitl = HumanInTheLoop(classifier=LLMClassifierConfig(model=inner), ask=lambda *a, **k: "y")
    return Agent(model=ScriptedModel([[tool_call("lookup", {"q": "a"})]]), tools=[lookup],
                 interventions=[hitl], plugins=plugins, callback_handler=None)


def _web_fetch(inner: Any, plugins: List[Any]) -> Agent:
    pytest.importorskip("bs4", reason="web_fetch needs strands-agents[web-fetch]")
    from strands.vended_tools.web_fetch import make_web_fetch

    page = httpx.AsyncClient(transport=httpx.MockTransport(
        lambda r: httpx.Response(200, headers={"content-type": "text/html"}, content=b"<p>page</p>")))
    fetch = make_web_fetch(client=page, model=inner)
    return Agent(model=ScriptedModel([[tool_call("web_fetch", {"url": "https://example.test/", "prompt": "what"})]]),
                 tools=[fetch], plugins=plugins, callback_handler=None)


def _offload_summarize(inner: Any, plugins: List[Any]) -> Agent:
    from strands._context_manager.context_manager import ContextManager
    from strands._context_manager.strategies.offload import Offload

    manager = ContextManager(strategies=[Offload.summarize("*", {"model": inner}).when(threshold=1)])
    return Agent(model=ScriptedModel([[text("done")]]), plugins=plugins, callback_handler=None,
                 context_manager=manager, messages=_history())


COMPONENTS = {
    "steering": _steering,
    "hitl_classifier": _hitl,
    "web_fetch": _web_fetch,
    "offload_summarize": _offload_summarize,
}


@pytest.fixture
def deny_web_search(mock_apdp: MockApdpClient) -> MockApdpClient:
    mock_apdp.decisions[("execute", "web_search")] = "Deny"
    return mock_apdp


@pytest.mark.parametrize("name", list(COMPONENTS))
def test_component_model_reaches_the_provider_without_the_plugin(mock_apdp: MockApdpClient, name: str):
    wire = Wire(mock_apdp)
    agent = COMPONENTS[name](openai_model(wire), [])
    try:
        agent("hi")
    except Exception:  # noqa: BLE001 - the stand-in's reply may not parse as the component expects
        pass
    assert wire.with_hosted_tool()


@pytest.mark.parametrize("name", list(COMPONENTS))
def test_denied_hosted_tool_on_a_component_model_refuses_the_invocation(
    make_plugin, deny_web_search: MockApdpClient, name: str
):
    wire = Wire(deny_web_search)
    agent = COMPONENTS[name](openai_model(wire), [make_plugin("agent-root")])

    with pytest.raises(HostedToolRefused):
        agent("hi")

    assert wire.requests == []
    assert len(web_search_decisions(deny_web_search)) == 1
    # The refusal is on the run's lineage.
    (failed,) = events_of(deny_web_search, "execution_failed")
    assert "HostedToolRefused" in json.dumps(failed)


@pytest.mark.parametrize("name", list(COMPONENTS))
def test_allowed_component_model_is_decided_before_it_is_called(make_plugin, mock_apdp: MockApdpClient, name: str):
    wire = Wire(mock_apdp)
    agent = COMPONENTS[name](openai_model(wire), [make_plugin("agent-root")])
    try:
        agent("hi")
    except Exception:  # noqa: BLE001 - see the baseline test
        pass
    assert wire.with_hosted_tool()
    assert wire.decided_before[0] >= 1


def test_unreadable_component_model_refuses_the_invocation(make_plugin, mock_apdp: MockApdpClient):
    class Unreadable(ScriptedModel):
        def get_config(self) -> Any:
            raise RuntimeError("no config")

    inner = Unreadable([[text("x")]])
    agent = _steering(inner, [make_plugin("agent-root")])
    with pytest.raises(UngovernedModelUse):
        agent("hi")
    assert inner.calls == 0


def test_a_component_graph_too_large_to_walk_is_refused(make_plugin, mock_apdp: MockApdpClient, monkeypatch):
    monkeypatch.setattr(model_reach, "MAX_NODES", 3)
    model = ScriptedModel([[text("x")]])
    agent = Agent(model=model, plugins=[make_plugin("agent-root")], callback_handler=None)
    with pytest.raises(UngovernedModelUse, match="too large"):
        agent("hi")
    assert model.calls == 0


# ── the goal loop's judge runs after the run ─────────────────────────


def test_goal_loop_judge_is_refused(make_plugin, mock_apdp: MockApdpClient):
    from strands.vended_plugins.goal import GoalLoop

    wire = Wire(mock_apdp)
    main = ScriptedModel([[text("done")]])
    agent = Agent(model=main, plugins=[GoalLoop("say done", max_attempts=1), make_plugin("agent-root")],
                  aux_model=openai_model(wire), callback_handler=None) if hasattr(Agent, "aux_model") else \
        Agent(model=main, plugins=[GoalLoop("say done", max_attempts=1), make_plugin("agent-root")],
              callback_handler=None)
    with pytest.raises(UngovernedModelUse, match="GoalLoop"):
        agent("hi")
    assert main.calls == 0 and wire.requests == []
    assert events_of(mock_apdp, "execution_failed")


def test_goal_loop_with_a_validator_runs(make_plugin, mock_apdp: MockApdpClient):
    from strands.vended_plugins.goal import GoalLoop

    main = ScriptedModel([[text("done")]])
    goal = GoalLoop(lambda response, agent: True, max_attempts=1)
    agent = Agent(model=main, plugins=[goal, make_plugin("agent-root")], callback_handler=None)
    agent("hi")
    assert main.calls == 1


# ── memory writes after the run ──────────────────────────────────────


class RawMessageStore:
    """Store-side extraction: the raw conversation goes to ``add_messages``."""

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


def _raw_store_agent(store: RawMessageStore, plugin: Any) -> Agent:
    return Agent(model=ScriptedModel([[text("ok")]]), plugins=[plugin], callback_handler=None,
                 memory_manager=MemoryManager(stores=[store], injection=False, search_tool_config=False))


def test_store_write_after_the_run_is_authorized(make_plugin, mock_apdp: MockApdpClient):
    store = RawMessageStore()
    _raw_store_agent(store, make_plugin("agent-root"))("hi")
    (decision,) = [c for c in mock_apdp.authorize_calls if c["resource"] == 'Resource::"memory:raw"']
    assert decision["action"] == 'Action::"create"'
    assert store.batches


def test_denied_store_write_refuses_the_invocation(make_plugin, mock_apdp: MockApdpClient):
    mock_apdp.decisions[("create", "memory:raw")] = "Deny"
    store = RawMessageStore()
    agent = _raw_store_agent(store, make_plugin("agent-root"))
    with pytest.raises(MemoryWriteRefused):
        agent("hi")
    assert store.batches == [] and agent.model.calls == 0
    (failed,) = events_of(mock_apdp, "execution_failed")
    assert "MemoryWriteRefused" in json.dumps(failed)


# ── the model-turn check runs before proactive compression ───────────


def test_model_turn_check_runs_before_every_other_model_hook(make_plugin):
    agent = Agent(model=ScriptedModel(), plugins=[make_plugin("agent-root")], callback_handler=None,
                  conversation_manager=SummarizingConversationManager(proactive_compression=True))
    names = [getattr(c, "__name__", type(c).__name__) for c in agent.hooks.get_callbacks_for(
        BeforeModelCallEvent(agent=agent, invocation_state={}))]
    assert names[0] == "_model_turn_first"
    assert names.index("_model_turn_first") < names.index("_on_before_model_call_threshold")


def test_a_model_hook_never_runs_for_a_model_call_with_no_run(make_plugin):
    """An earlier hook (proactive compression, a summary) is not reached
    when the model call belongs to no governed run."""
    import asyncio

    from watchlight_core import GovernanceUnavailable

    reached: List[int] = []
    agent = Agent(model=ScriptedModel(), plugins=[make_plugin("agent-root")], callback_handler=None)
    agent.hooks.add_callback(BeforeModelCallEvent, lambda e: reached.append(1))
    with pytest.raises(GovernanceUnavailable):
        asyncio.run(agent.hooks.invoke_callbacks_async(BeforeModelCallEvent(agent=agent, invocation_state={})))
    assert reached == []


# ── agents a component holds ────────────────────────────────────────


def _unattachable_child() -> Any:
    from strands.hooks import HookRegistry

    # In-process stand-in for unit tests only: a registry that refuses
    # registration, as a broken or foreign registry would.
    class RefusingRegistry(HookRegistry):
        def add_callback(self, *args: Any, **kwargs: Any) -> None:
            raise RuntimeError("registration refused")

    child = Agent(name="helper", model=ScriptedModel([[text("child ran")]]), callback_handler=None)
    child.hooks = RefusingRegistry()
    return child


class CallsItsAgent:
    """A component that calls the agent it holds directly, from a hook,
    where no tool or node gate sees the call."""

    def __init__(self, child: Any) -> None:
        self.child = child

    async def on_model_call(self, event: Any) -> None:
        await self.child.invoke_async("x")


def test_an_unattachable_agent_a_component_calls_directly_refuses_the_invocation(
    make_plugin, mock_apdp: MockApdpClient
):
    child = _unattachable_child()
    component = CallsItsAgent(child)
    main = ScriptedModel([[text("done")]])
    agent = Agent(model=main, plugins=[make_plugin("agent-root")], callback_handler=None)
    agent.hooks.add_callback(BeforeModelCallEvent, component.on_model_call)

    with pytest.raises(UngovernedModelUse, match="cannot be governed"):
        agent("hi")

    assert child.model.calls == 0 and main.calls == 0
    (failed,) = events_of(mock_apdp, "execution_failed")
    assert "UngovernedModelUse" in json.dumps(failed)


class Holder:
    def __init__(self, value: Any) -> None:
        self.value = value


def test_an_unattachable_agent_behind_a_tool_the_gate_cannot_see_refuses_the_invocation(
    make_plugin, mock_apdp: MockApdpClient
):
    holder = Holder(_unattachable_child())

    @tool
    def ask(q: str) -> str:
        """Ask the helper."""
        return str(holder.value(q))

    main = ScriptedModel([[tool_call("ask", {"q": "x"})], [text("done")]])
    agent = Agent(model=main, tools=[ask], plugins=[make_plugin("agent-root")], callback_handler=None)

    with pytest.raises(UngovernedModelUse, match="can reach cannot be governed"):
        agent("hi")
    assert holder.value.model.calls == 0 and main.calls == 0


# ── how the walk reads containers ───────────────────────────────────


def _component_holding(value: Any, plugin: Any, main: Any = None) -> Agent:
    agent = Agent(model=main or ScriptedModel([[text("done")]]), plugins=[plugin], callback_handler=None)
    holder = Holder(value)
    agent.hooks.add_callback(BeforeModelCallEvent, lambda event: holder)
    return agent


def test_a_custom_mapping_is_walked_without_running_its_code(make_plugin, deny_web_search: MockApdpClient):
    from collections.abc import Mapping

    calls: List[str] = []

    class Store(Mapping):
        def __init__(self, model: Any) -> None:
            self._data = {"m": model}

        def __getitem__(self, key: Any) -> Any:
            calls.append("getitem")
            return self._data[key]

        def __iter__(self) -> Any:
            calls.append("iter")
            return iter(self._data)

        def __len__(self) -> int:
            calls.append("len")
            return 1

        def values(self) -> Any:
            calls.append("values")
            return self._data.values()

    wire = Wire(deny_web_search)
    agent = _component_holding(Store(openai_model(wire)), make_plugin("agent-root"))
    with pytest.raises(HostedToolRefused):
        agent("hi")
    assert calls == [] and wire.requests == []


def test_a_mappingproxy_is_read(make_plugin, deny_web_search: MockApdpClient):
    import types

    wire = Wire(deny_web_search)
    agent = _component_holding(types.MappingProxyType({"m": openai_model(wire)}), make_plugin("agent-root"))
    with pytest.raises(HostedToolRefused):
        agent("hi")


def test_a_live_weak_reference_is_followed(make_plugin, deny_web_search: MockApdpClient):
    import weakref

    wire = Wire(deny_web_search)
    model = openai_model(wire)
    agent = _component_holding(weakref.ref(model), make_plugin("agent-root"))
    with pytest.raises(HostedToolRefused):
        agent("hi")
    assert wire.requests == []


def test_a_dead_weak_reference_is_skipped(make_plugin, mock_apdp: MockApdpClient):
    import weakref

    class Gone:
        pass

    main = ScriptedModel([[text("done")]])
    agent = _component_holding(weakref.ref(Gone()), make_plugin("agent-root"), main)
    agent("hi")
    assert main.calls == 1


def test_a_c_container_is_read_through_its_references(make_plugin, mock_apdp: MockApdpClient):
    import array

    main = ScriptedModel([[text("done")]])
    agent = _component_holding(array.array("i", [1, 2]), make_plugin("agent-root"), main)
    agent("hi")
    assert main.calls == 1


def test_a_container_the_walk_cannot_read_refuses_the_invocation(
    make_plugin, mock_apdp: MockApdpClient, monkeypatch
):
    import array

    # A C container the garbage collector does not track: its references
    # cannot be read without running its code.
    monkeypatch.setattr(model_reach.gc, "is_tracked", lambda obj: not isinstance(obj, array.array))
    main = ScriptedModel([[text("done")]])
    agent = _component_holding(array.array("i", [1, 2]), make_plugin("agent-root"), main)
    with pytest.raises(UngovernedModelUse, match="cannot be checked"):
        agent("hi")
    assert main.calls == 0
