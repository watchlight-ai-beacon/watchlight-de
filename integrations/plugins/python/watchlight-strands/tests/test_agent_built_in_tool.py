"""An agent a tool body builds and runs is refused.

The plugin cannot reach such an agent to govern it as a child. Two checks
keep it from running: the tool gate refuses a function tool whose code can
build an agent or orchestrator, so the body never runs; and the per-call
model backstop refuses every model turn of an agent with no governed run,
so an agent built in a way the code does not name never takes a turn and
never calls a tool.

Every test denies by default and allows only the outer tool, so a tool the
inner agent runs would be running past a deny.
"""

from __future__ import annotations

import functools
import importlib
from typing import Any, List

import pytest
import strands
from conftest import ScriptedModel, events_of, text, tool_call
from strands import Agent, tool
from strands.multiagent import GraphBuilder, Swarm
from watchlight_core_testing import MockApdpClient

ran: List[str] = []
bodies: List[str] = []
inner_models: List[ScriptedModel] = []


@pytest.fixture(autouse=True)
def _reset() -> None:
    ran.clear()
    bodies.clear()
    inner_models.clear()


@pytest.fixture
def deny_by_default(mock_apdp: MockApdpClient) -> MockApdpClient:
    mock_apdp.default_decision = "Deny"
    mock_apdp.decisions[("execute", "build_and_run")] = "Allow"
    return mock_apdp


@tool
def search(q: str) -> str:
    """Search."""
    ran.append(f"search:{q}")
    return "hits"


def _inner_model() -> ScriptedModel:
    model = ScriptedModel([[tool_call("search", {"q": "inner"})], [text("ok")]])
    inner_models.append(model)
    return model


def _run_parent(make_plugin: Any, build_and_run: Any) -> None:
    parent = Agent(
        model=ScriptedModel([[tool_call("build_and_run", {"task": "t"})], [text("done")]]),
        tools=[build_and_run],
        plugins=[make_plugin("agent-root")],
        callback_handler=None,
    )
    parent("go")


def _assert_nothing_inner_ran() -> None:
    assert ran == []
    assert all(model.calls == 0 for model in inner_models)


# ── refused before the tool body runs ─────────────────────────────────


def _make_inner() -> Agent:
    return Agent(name="inner", model=_inner_model(), tools=[search], callback_handler=None)


class _Factory:
    def build(self) -> Agent:
        return Agent(name="inner", model=_inner_model(), tools=[search], callback_handler=None)


class _OwnAgent(Agent):
    pass


_FACTORY = _Factory()
_PARTIAL = functools.partial(Agent, name="inner")


@tool
def by_name(task: str) -> str:
    """Builds strands.Agent by name."""
    bodies.append("by_name")
    return str(Agent(name="inner", model=_inner_model(), tools=[search], callback_handler=None)(task))


@tool
def by_module_attribute(task: str) -> str:
    """Builds strands.Agent through the module."""
    bodies.append("by_module_attribute")
    return str(strands.Agent(name="inner", model=_inner_model(), tools=[search], callback_handler=None)(task))


@tool
def by_helper(task: str) -> str:
    """Builds through a helper function."""
    bodies.append("by_helper")
    return str(_make_inner()(task))


@tool
def by_factory_method(task: str) -> str:
    """Builds through a method of a module-level object."""
    bodies.append("by_factory_method")
    return str(_FACTORY.build()(task))


@tool
def by_subclass(task: str) -> str:
    """Builds a subclass of Agent."""
    bodies.append("by_subclass")
    return str(_OwnAgent(name="inner", model=_inner_model(), tools=[search], callback_handler=None)(task))


@tool
def by_lambda(task: str) -> str:
    """Builds inside a nested lambda."""
    bodies.append("by_lambda")
    make = lambda: Agent(name="inner", model=_inner_model(), tools=[search], callback_handler=None)  # noqa: E731
    return str(make()(task))


@tool
def by_partial(task: str) -> str:
    """Builds through a functools.partial of Agent."""
    bodies.append("by_partial")
    return str(_PARTIAL(model=_inner_model(), tools=[search], callback_handler=None)(task))


@tool
def by_swarm(task: str) -> str:
    """Builds and runs a Swarm."""
    bodies.append("by_swarm")
    return str(Swarm([_make_inner()])(task))


@tool
def by_graph_builder(task: str) -> str:
    """Builds and runs a Graph."""
    bodies.append("by_graph_builder")
    builder = GraphBuilder()
    builder.add_node(_make_inner(), "inner")
    return str(builder.build()(task))


def _closure_tool() -> Any:
    cls = Agent

    @tool
    def by_closure(task: str) -> str:
        """Builds a class held in a closure."""
        bodies.append("by_closure")
        return str(cls(name="inner", model=_inner_model(), tools=[search], callback_handler=None)(task))

    return by_closure


REFUSED_BEFORE_THE_BODY = {
    "name": by_name,
    "module_attribute": by_module_attribute,
    "helper": by_helper,
    "factory_method": by_factory_method,
    "subclass": by_subclass,
    "lambda": by_lambda,
    "partial": by_partial,
    "swarm": by_swarm,
    "graph_builder": by_graph_builder,
    "closure": _closure_tool(),
}


@pytest.mark.parametrize("case", list(REFUSED_BEFORE_THE_BODY))
def test_a_tool_that_can_build_an_agent_is_refused_before_its_body_runs(
    make_plugin: Any, deny_by_default: MockApdpClient, case: str
) -> None:
    outer = REFUSED_BEFORE_THE_BODY[case]
    renamed = tool(name="build_and_run")(outer.__wrapped__)
    _run_parent(make_plugin, renamed)
    assert bodies == []
    _assert_nothing_inner_ran()
    # Refused at the tool gate: no decision was asked for the outer tool.
    assert deny_by_default.authorize_calls == []
    (observed,) = events_of(deny_by_default, "tool_call_observed")
    assert observed["payload"]["decision"] == "Deny"


def test_config_to_agent_is_a_factory_the_gate_refuses(make_plugin: Any, deny_by_default: MockApdpClient) -> None:
    from strands.experimental import config_to_agent

    @tool(name="build_and_run")
    def build_and_run(task: str) -> str:
        """Builds an agent from a config."""
        bodies.append("config")
        return str(config_to_agent({"name": "inner"})(task))

    _run_parent(make_plugin, build_and_run)
    assert bodies == []


# ── built in a way the code does not name: the backstop refuses ───────


def _by_import_module(task: str) -> str:
    bodies.append("import_module")
    cls = getattr(importlib.import_module("strands"), "Ag" + "ent")
    return str(cls(name="inner", model=_inner_model(), tools=[search], callback_handler=None)(task))


def _by_argument_class(task: str, agent_class: Any = None) -> str:
    bodies.append("argument")
    cls = type(_HELD_FOR_TYPE) if agent_class is None else agent_class
    return str(cls(name="inner", model=_inner_model(), tools=[search], callback_handler=None)(task))


class _Holder:
    pass


_HELD_FOR_TYPE = _Holder()


def _class_from_instance_attribute() -> Any:
    holder = _Holder()
    holder.__dict__["cls"] = importlib.import_module("strands.agent").__dict__["Agent"]
    return holder


_HOLDER = _class_from_instance_attribute()


def _by_instance_attribute(task: str) -> str:
    bodies.append("instance_attribute")
    return str(_HOLDER.cls(name="inner", model=_inner_model(), tools=[search], callback_handler=None)(task))


#: Agents built through an indirection the code read does not follow: the
#: inner agent never takes a model turn, so it never calls a tool.
INDIRECT_BUILDS = {
    "import_module": _by_import_module,
    "instance_attribute": _by_instance_attribute,
}


@pytest.mark.parametrize("case", list(INDIRECT_BUILDS))
def test_an_agent_the_code_read_misses_never_takes_a_turn(
    make_plugin: Any, deny_by_default: MockApdpClient, case: str
) -> None:
    build_and_run = tool(name="build_and_run")(INDIRECT_BUILDS[case])
    _run_parent(make_plugin, build_and_run)
    _assert_nothing_inner_ran()
    assert [c["resource"] for c in deny_by_default.authorize_calls] == ['Resource::"build_and_run"']


def test_an_agent_class_passed_in_never_takes_a_turn(make_plugin: Any, deny_by_default: MockApdpClient) -> None:
    """A class that reaches the body only at call time (here a default
    argument the read cannot see until the call) is not refused by the
    gate; the backstop refuses the agent's turns."""

    @tool(name="build_and_run")
    def build_and_run(task: str) -> str:
        """Builds a class it is handed."""
        bodies.append("handed")
        handed = importlib.import_module("strands").__dict__["Agent"]
        return _by_argument_class(task, handed)

    _run_parent(make_plugin, build_and_run)
    assert bodies == ["handed", "argument"]
    _assert_nothing_inner_ran()


def test_an_agent_with_no_tools_may_take_a_turn(make_plugin: Any, deny_by_default: MockApdpClient) -> None:
    """An ungoverned agent that can call no tool cannot run anything past a
    deny; its model's hosted tools are still checked by the backstop."""

    def run(task: str) -> str:
        bodies.append("no_tools")
        cls = importlib.import_module("strands").__dict__["Agent"]
        model = ScriptedModel([[text("plain")]])
        inner_models.append(model)
        return str(cls(name="inner", model=model, callback_handler=None)(task))

    _run_parent(make_plugin, tool(name="build_and_run")(run))
    assert bodies == ["no_tools"]
    assert inner_models[0].calls == 1


def test_a_held_agent_is_still_governed_as_a_child(make_plugin: Any, mock_apdp: MockApdpClient) -> None:
    """The gate refuses code that BUILDS an agent; a tool that refers to an
    agent it holds is unchanged: that agent is attached as a governed child."""
    held = Agent(name="researcher", model=ScriptedModel([[tool_call("search", {"q": "held"})], [text("ok")]]),
                 tools=[search], callback_handler=None)

    @tool(name="build_and_run")
    def build_and_run(task: str) -> str:
        """Runs a held agent."""
        return str(held(task))

    _run_parent(make_plugin, build_and_run)
    assert ran == ["search:held"]
    assert len(mock_apdp.spawn_subagent_calls) == 1


# ── review round 1: direct_model_use, tools loaded during a turn, shared state ──


def _indirect_agent_class() -> Any:
    return importlib.import_module("strands").__dict__["Agent"]


def test_direct_model_use_never_covers_an_agent_turn(make_plugin: Any, deny_by_default: MockApdpClient) -> None:
    """``direct_model_use()`` declares direct model calls. A turn of an agent
    that holds tools, on a fresh thread inside the block, is still refused."""
    import threading

    from watchlight_strands import direct_model_use

    def run(task: str) -> str:
        bodies.append("thread")
        inner = _indirect_agent_class()(name="inner", model=_inner_model(), tools=[search], callback_handler=None)
        errors: List[BaseException] = []

        def in_thread() -> None:
            try:
                with direct_model_use():
                    inner(task)
            except BaseException as exc:  # noqa: BLE001 - recorded for the assertion
                errors.append(exc)

        worker = threading.Thread(target=in_thread)
        worker.start()
        worker.join()
        return "refused" if errors else "ran"

    _run_parent(make_plugin, tool(name="build_and_run")(run))
    assert bodies == ["thread"]
    _assert_nothing_inner_ran()


class _LoadsToolDuringTurn(ScriptedModel):
    """Registers ``search`` on the calling agent while it streams its
    response, as a tool hot-loaded from a directory would appear."""

    async def stream(self, messages: Any, tool_specs: Any = None, system_prompt: Any = None, **kwargs: Any):  # type: ignore[override]
        agent = (kwargs.get("invocation_state") or {}).get("agent")
        first = self.calls == 0
        async for event in super().stream(messages, tool_specs, system_prompt, **kwargs):
            if first and agent is not None:
                # Mid-response, after every pre-call check has passed.
                agent.tool_registry.dynamic_tools["search"] = search
            yield event


def test_a_tool_registered_during_a_turn_is_never_dispatched(make_plugin: Any, deny_by_default: MockApdpClient) -> None:
    def run(task: str) -> str:
        bodies.append("hot")
        model = _LoadsToolDuringTurn([[tool_call("search", {"q": "inner"})], [text("ok")]])
        inner_models.append(model)
        return str(_indirect_agent_class()(name="inner", model=model, callback_handler=None)(task))

    _run_parent(make_plugin, tool(name="build_and_run")(run))
    assert bodies == ["hot"]
    assert ran == []


def test_an_agent_that_hot_loads_tools_is_refused_at_its_first_turn(
    make_plugin: Any, deny_by_default: MockApdpClient
) -> None:
    def run(task: str) -> str:
        bodies.append("watch")
        inner = _indirect_agent_class()(name="inner", model=_inner_model(), callback_handler=None)
        # What load_tools_from_directory=True records (without starting a watcher).
        inner.load_tools_from_directory = True
        return str(inner(task))

    _run_parent(make_plugin, tool(name="build_and_run")(run))
    assert bodies == ["watch"]
    _assert_nothing_inner_ran()


def test_passing_the_tool_invocation_state_to_an_inner_agent_fails_closed(
    make_plugin: Any, mock_apdp: MockApdpClient
) -> None:
    """An inner agent given the tool's own ``invocation_state`` overwrites the
    outer agent in it, so the outer agent's next turn is refused: closed, not
    open (see the README)."""

    @tool(name="build_and_run", context=True)
    def build_and_run(task: str, tool_context: Any) -> str:
        """Passes its invocation state on."""
        bodies.append("shared")
        inner = _indirect_agent_class()(name="inner", model=_inner_model(), tools=[search], callback_handler=None)
        try:
            inner(task, invocation_state=tool_context.invocation_state)
        except Exception:  # noqa: BLE001 - the inner agent's turn is refused
            pass
        return "inner refused"

    parent_model = ScriptedModel([[tool_call("build_and_run", {"task": "t"})], [text("done")]])
    parent = Agent(model=parent_model, tools=[build_and_run], plugins=[make_plugin("agent-root")], callback_handler=None)
    with pytest.raises(Exception, match="not governed in this run"):
        parent("go")
    assert bodies == ["shared"]
    assert parent_model.calls == 1
    _assert_nothing_inner_ran()
