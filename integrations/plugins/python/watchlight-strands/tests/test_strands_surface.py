"""The Strands surface the plugin depends on.

Strands releases often. If an upgrade moves any of these, governance
could silently stop applying, so each is asserted here and CI fails
loudly instead.
"""

from __future__ import annotations

import inspect

from conftest import ScriptedModel
from strands import Agent
from strands.hooks import (
    AfterInvocationEvent,
    AfterMultiAgentInvocationEvent,
    AfterToolCallEvent,
    BeforeInvocationEvent,
    BeforeModelCallEvent,
    BeforeMultiAgentInvocationEvent,
    BeforeNodeCallEvent,
    BeforeToolCallEvent,
    HookOrder,
    HookRegistry,
)
from strands.multiagent import GraphBuilder, Swarm


def test_gate_fields_are_writable() -> None:
    agent = Agent(model=ScriptedModel(), callback_handler=None)
    tool_event = BeforeToolCallEvent(agent=agent, selected_tool=None, tool_use={"toolUseId": "t", "name": "x", "input": {}}, invocation_state={})
    tool_event.cancel_tool = "refused"
    assert tool_event.cancel_tool == "refused"
    assert callable(getattr(tool_event, "interrupt", None))
    invocation = BeforeInvocationEvent(agent=agent, invocation_state={})
    assert invocation.cancel is False
    model_event = BeforeModelCallEvent(agent=agent, invocation_state={})
    assert model_event.cancel is False


def test_registry_orders_callbacks() -> None:
    params = inspect.signature(HookRegistry.add_callback).parameters
    assert "order" in params
    assert HookOrder.SDK_LAST < 1_000_000.0
    assert HookOrder.SDK_FIRST > -1_000_000.0


def test_lifecycle_events_carry_what_the_plugin_reads() -> None:
    fields = {f for f in AfterInvocationEvent.__dataclass_fields__}
    assert {"invocation_state", "result"} <= fields
    assert {"selected_tool", "tool_use", "invocation_state", "duration"} <= set(AfterToolCallEvent.__dataclass_fields__)
    assert {"source", "invocation_state"} <= set(BeforeMultiAgentInvocationEvent.__dataclass_fields__)
    assert {"source", "invocation_state"} <= set(AfterMultiAgentInvocationEvent.__dataclass_fields__)
    assert {"source", "node_id", "cancel_node"} <= set(BeforeNodeCallEvent.__dataclass_fields__)


def test_agent_attributes_the_plugin_probes() -> None:
    plain = Agent(model=ScriptedModel(), callback_handler=None)
    # The background-tasks refusal reads ``_background_tasks``: wherever
    # Strands accepts ``background_tasks=``, the probe must see it.
    if "background_tasks" in inspect.signature(Agent.__init__).parameters:
        background = Agent(model=ScriptedModel(), background_tasks=True, callback_handler=None)
        assert getattr(plain, "_background_tasks", "missing") is None
        assert getattr(background, "_background_tasks", None) is not None
    # The interrupt-resume check reads ``_interrupt_state.activated``.
    assert hasattr(getattr(plain, "_interrupt_state", None), "activated")
    assert isinstance(plain.tool_names, list)
    assert isinstance(plain.hooks, HookRegistry)


def test_orchestrators_expose_their_nodes() -> None:
    a = Agent(name="a", model=ScriptedModel(), callback_handler=None)
    swarm = Swarm([a])
    assert swarm.nodes["a"].executor is a
    b = Agent(name="b", model=ScriptedModel(), callback_handler=None)
    builder = GraphBuilder()
    builder.add_node(b, "b")
    builder.set_entry_point("b")
    graph = builder.build()
    assert graph.nodes["b"].executor is b
    assert isinstance(swarm.hooks, HookRegistry) and isinstance(graph.hooks, HookRegistry)


def test_agent_as_tool_exposes_its_agent() -> None:
    child = Agent(name="child", model=ScriptedModel(), callback_handler=None)
    wrapped = child.as_tool()
    assert wrapped.tool_type == "agent"
    assert wrapped.agent is child


def test_the_public_surface_children_are_reached_through() -> None:
    from strands import tool

    @tool
    def probe(x: str) -> str:
        """Probe."""
        return x

    # Function tools expose the function they wrap (functools), which is how
    # the plugin finds the agents a tool body refers to.
    assert callable(probe.__wrapped__)
    agent = Agent(model=ScriptedModel(), tools=[probe], callback_handler=None)
    assert isinstance(agent.tool_registry.registry, dict)
    assert callable(agent.tool_registry.register_tool)
    # The hook registry is a public attribute and accepts registrations
    # after the agent was built.
    calls = []
    agent.hooks.add_callback(BeforeInvocationEvent, lambda event: calls.append(event))
    agent("go")
    assert len(calls) == 1


# ── the private invoke-model middleware the hosted-tool gate runs in ─────
#
# ``watchlight_strands.hosted_tools`` gates every model call from inside
# Strands' invoke-model middleware: the stage is public from Strands 1.62
# (private before), the agent's registry is private at every version. The
# plugin refuses the model call when it drifts; these tests make the drift
# fail CI first.


def _stages():
    from watchlight_strands.hosted_tools import _stage_modules

    modules = _stage_modules()
    if not modules:
        raise AssertionError("Strands has no invoke-model middleware stages module")
    return modules[0]


def test_the_invoke_model_middleware_the_gate_runs_in() -> None:
    import dataclasses

    InvokeModelContext, InvokeModelStage = _stages().InvokeModelContext, _stages().InvokeModelStage
    agent = Agent(model=ScriptedModel(), callback_handler=None)
    registry = agent._middleware_registry
    assert isinstance(registry._handlers, dict)
    assert callable(registry.add_middleware)
    assert InvokeModelStage.Input is not None
    fields = {f.name for f in dataclasses.fields(InvokeModelContext)}
    assert {"agent", "messages", "system_prompt", "tool_specs", "tool_choice", "invocation_state", "model"} <= fields


async def test_the_last_registered_wrap_handler_is_innermost() -> None:
    InvokeModelStage = _stages().InvokeModelStage
    order: list = []

    def wrap(name: str):
        async def handler(ctx, next_fn):
            order.append(name)
            async for event in next_fn(ctx):
                yield event

        return handler

    def as_input(ctx):
        order.append("input")
        return ctx

    registry = type(Agent(model=ScriptedModel(), callback_handler=None)._middleware_registry)()
    registry.add_middleware(InvokeModelStage, wrap("first"))
    registry.add_middleware(InvokeModelStage.Input, as_input)
    registry.add_middleware(InvokeModelStage, wrap("last"))
    assert [h.phase for h in registry._handlers[InvokeModelStage]] == ["wrap", "input", "wrap"]

    async def terminal(ctx):
        order.append("terminal")
        yield "result"

    events = [e async for e in registry.invoke(InvokeModelStage, object(), terminal)]
    assert events == ["result"]
    assert order == ["input", "first", "last", "terminal"]


def test_the_model_formatters_the_gate_reads_the_request_through() -> None:
    from strands.models.bedrock import BedrockModel
    from strands.models.gemini import GeminiModel
    from strands.types.content import split_system_prompt

    assert callable(split_system_prompt)
    expected = {
        BedrockModel.format_request: ["messages", "tool_specs", "system_prompt_content", "tool_choice"],
        GeminiModel._format_request: ["messages", "tool_specs", "system_prompt", "params"],
    }
    try:
        from strands.models.anthropic import AnthropicModel
        from strands.models.openai import OpenAIModel
        from strands.models.openai_responses import OpenAIResponsesModel
    except ImportError:  # pragma: no cover - the CI venv installs both SDKs
        pass
    else:
        expected[AnthropicModel.format_request] = ["messages", "tool_specs", "system_prompt"]
        expected[OpenAIModel.format_request] = ["messages", "tool_specs", "system_prompt", "tool_choice"]
        expected[OpenAIResponsesModel._format_request] = [
            "messages",
            "tool_specs",
            "system_prompt",
            "tool_choice",
            "model_state",
        ]
    for fn, names in expected.items():
        params = list(inspect.signature(fn).parameters)[1:]
        assert params[: len(names)] == names, fn.__qualname__
