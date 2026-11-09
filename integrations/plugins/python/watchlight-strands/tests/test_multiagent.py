"""Swarm and Graph: the plugin is installed once, on the orchestrator. It
attaches itself to every node (nested orchestrators included), each node
runs as a governed spawn under the orchestrator's run, and a node it cannot
govern is cancelled before it runs."""

from __future__ import annotations

from typing import Any, List

import pytest
from conftest import AGENTS, ScriptedModel, events_of, spawn_labels, spawned_agents, text, tool_call
from strands import Agent, tool
from strands.multiagent import GraphBuilder, Swarm
from strands.multiagent.base import Status
from watchlight_core_testing import MockApdpClient
from watchlight_strands import governing_plugin, labelled_spawn_supported

ran: List[str] = []


@pytest.fixture(autouse=True)
def _reset_ran() -> None:
    ran.clear()


@tool
def search(q: str) -> str:
    """Search."""
    ran.append(f"search:{q}")
    return "hits"


@tool
def summarize(text_in: str) -> str:
    """Summarize."""
    ran.append("summarize")
    return "summary"


def _started_children(mock: MockApdpClient, parent_exec: str) -> List[dict]:
    return [e for e in events_of(mock, "execution_started") if e.get("parent_execution_id") == parent_exec]


def _root_started(mock: MockApdpClient) -> dict:
    [root] = [e for e in events_of(mock, "execution_started") if not e.get("parent_execution_id")]
    return root


# In-process stand-in for unit tests only: an AgentBase executor the plugin
# cannot attach to (it has no Strands hook registry), like a remote A2AAgent.
class RemoteStandIn:
    name = "remote"

    def __init__(self) -> None:
        self.calls = 0

    async def invoke_async(self, prompt: Any = None, **kwargs: Any) -> Any:  # pragma: no cover
        self.calls += 1
        raise AssertionError("an ungovernable node must never run")

    def __call__(self, prompt: Any = None, **kwargs: Any) -> Any:  # pragma: no cover
        self.calls += 1
        raise AssertionError("an ungovernable node must never run")

    async def stream_async(self, prompt: Any = None, **kwargs: Any):  # pragma: no cover
        self.calls += 1
        raise AssertionError("an ungovernable node must never run")
        yield


def test_swarm_nodes_are_attached_and_spawned(make_plugin, mock_apdp: MockApdpClient):
    alpha = Agent(
        name="alpha",
        model=ScriptedModel(
            [
                [tool_call("search", {"q": "x"})],
                [tool_call("handoff_to_agent", {"agent_name": "beta", "message": "your turn"})],
                [text("alpha done")],
            ]
        ),
        tools=[search],
        callback_handler=None,
    )
    beta = Agent(
        name="beta",
        model=ScriptedModel([[tool_call("summarize", {"text_in": "t"})], [text("beta done")]]),
        tools=[summarize],
        callback_handler=None,
    )
    swarm = Swarm([alpha, beta], plugins=[make_plugin("agent-swarm", agent_map={"beta": "agent-child-b"})])
    assert governing_plugin(alpha) is governing_plugin(swarm) is governing_plugin(beta)

    result = swarm("work")

    assert result.status == Status.COMPLETED
    assert ran == ["search:x", "summarize"]
    root = _root_started(mock_apdp)
    assert root["agent_id"] == AGENTS["agent-swarm"]
    kids = _started_children(mock_apdp, root["execution_id"])
    assert len(kids) == 2
    # alpha spawned as the swarm's own agent, beta as its mapped agent.
    assert spawned_agents(mock_apdp) == [AGENTS["agent-swarm"], AGENTS["agent-child-b"]]
    if labelled_spawn_supported():
        # alpha is sent under its node id; beta by its mapped agent.
        assert spawn_labels(mock_apdp) == ["alpha", None]
    assert len(mock_apdp._closed_sessions) == 3


def test_an_ungovernable_swarm_node_is_cancelled(make_plugin, mock_apdp: MockApdpClient):
    import inspect

    if "background_tasks" not in inspect.signature(Agent.__init__).parameters:
        pytest.skip("this strands-agents release has no background tasks")
    model = ScriptedModel([[tool_call("search", {"q": "x"})], [text("done")]])
    alpha = Agent(name="alpha", model=model, tools=[search], background_tasks=True, callback_handler=None)
    swarm = Swarm([alpha], plugins=[make_plugin("agent-swarm")])

    result = swarm("work")

    assert result.status == Status.FAILED
    assert model.calls == 0 and ran == []
    assert events_of(mock_apdp, "execution_failed")


def test_graph_parallel_nodes_are_governed_spawns(make_plugin, mock_apdp: MockApdpClient):
    alpha = Agent(
        name="alpha",
        model=ScriptedModel([[tool_call("search", {"q": "a"})], [text("a done")]]),
        tools=[search],
        callback_handler=None,
    )
    beta = Agent(
        name="beta",
        model=ScriptedModel([[tool_call("summarize", {"text_in": "b"})], [text("b done")]]),
        tools=[summarize],
        callback_handler=None,
    )
    builder = GraphBuilder()
    builder.add_node(alpha, "alpha")
    builder.add_node(beta, "beta")
    builder.set_entry_point("alpha")
    builder.set_entry_point("beta")
    builder.set_plugins([make_plugin("agent-graph")])
    graph = builder.build()

    result = graph("work")

    assert result.status == Status.COMPLETED
    assert sorted(ran) == ["search:a", "summarize"]
    root = _root_started(mock_apdp)
    kids = _started_children(mock_apdp, root["execution_id"])
    assert len(kids) == 2
    by_resource = {c["resource"].split('"')[1]: c["execution_id"] for c in mock_apdp.authorize_calls}
    assert {by_resource["search"], by_resource["summarize"]} == {k["execution_id"] for k in kids}


def test_a_nested_orchestrator_and_its_nodes_are_governed(make_plugin, mock_apdp: MockApdpClient):
    inner_agent = Agent(
        name="inner",
        model=ScriptedModel([[tool_call("search", {"q": "nested"})], [text("inner done")]]),
        tools=[search],
        callback_handler=None,
    )
    inner_builder = GraphBuilder()
    inner_builder.add_node(inner_agent, "inner")
    inner_builder.set_entry_point("inner")
    inner_graph = inner_builder.build()
    builder = GraphBuilder()
    builder.add_node(inner_graph, "sub")
    builder.set_entry_point("sub")
    builder.set_plugins([make_plugin("agent-graph")])
    graph = builder.build()
    assert governing_plugin(inner_agent) is governing_plugin(graph)

    result = graph("work")

    assert result.status == Status.COMPLETED
    assert ran == ["search:nested"]
    assert len(mock_apdp.spawn_subagent_calls) == 2  # inner graph, then its node
    started = {e["execution_id"]: e for e in events_of(mock_apdp, "execution_started")}
    leaf = next(c for c in mock_apdp.authorize_calls if c["resource"].endswith('"search"'))
    depth, exec_id = 0, leaf["execution_id"]
    while started[exec_id].get("parent_execution_id"):
        exec_id = started[exec_id]["parent_execution_id"]
        depth += 1
    assert depth == 2


def test_an_ungovernable_graph_node_is_cancelled(make_plugin, mock_apdp: MockApdpClient):
    remote = RemoteStandIn()
    builder = GraphBuilder()
    builder.add_node(remote, "remote")
    builder.set_entry_point("remote")
    builder.set_plugins([make_plugin("agent-graph")])
    graph = builder.build()

    with pytest.raises(RuntimeError, match="cannot govern"):
        graph("work")
    assert remote.calls == 0


def test_a_node_added_after_install_is_attached_before_it_runs(make_plugin, mock_apdp: MockApdpClient):
    first = Agent(name="first", model=ScriptedModel([[text("first done")]]), callback_handler=None)
    swarm = Swarm([first], plugins=[make_plugin("agent-swarm")])
    late = Agent(
        name="late",
        model=ScriptedModel([[tool_call("search", {"q": "late"})], [text("late done")]]),
        tools=[search],
        callback_handler=None,
    )
    # Replace the entry node's executor after install (a node the plugin has
    # not seen yet); BeforeNodeCallEvent attaches to it before it runs.
    swarm.nodes["first"].executor = late
    assert governing_plugin(late) is None

    swarm("work")

    assert ran == ["search:late"]
    assert governing_plugin(late) is governing_plugin(swarm)
