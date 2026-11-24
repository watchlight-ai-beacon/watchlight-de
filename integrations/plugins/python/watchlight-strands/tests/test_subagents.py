"""Children: the plugin is installed once, on the root, and attaches itself to
every child the root reaches. A child runs as a governed spawn of its parent
with an attenuated scope and needs no registered slug; a child the plugin
cannot attach to never runs."""

from __future__ import annotations

import asyncio
import json
from typing import Any, List

import pytest
from conftest import AGENTS, ScriptedModel, events_of, spawn_labels, spawned_agents, text, tool_call
from strands import Agent, tool
from strands.hooks import HookRegistry
from watchlight_core import ScopeAttenuationDenied
from watchlight_core_testing import MockApdpClient
from watchlight_strands import AgentNotIdentified, governing_plugin, labelled_spawn_supported
from watchlight_strands.model_reach import UngovernedModelUse

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


def _principal(slug: str) -> str:
    return f'Agent::"{AGENTS[slug]}"'


def _started(mock: MockApdpClient) -> List[dict]:
    return events_of(mock, "execution_started")


def _child(name: str, turns, tools) -> Agent:
    return Agent(name=name, model=ScriptedModel(turns), tools=tools, callback_handler=None)


def test_an_agent_used_as_a_tool_is_attached_and_spawned(make_plugin, mock_apdp: MockApdpClient):
    child = _child("researcher", [[tool_call("search", {"q": "x"})], [text("child done")]], [search])
    parent = Agent(
        model=ScriptedModel([[tool_call("researcher", {"input": "look into x"})], [text("parent done")]]),
        tools=[child.as_tool()],
        plugins=[make_plugin("agent-root")],
        callback_handler=None,
    )
    plugin = governing_plugin(parent)
    # Attached at install time, before anything ran.
    assert governing_plugin(child) is plugin

    parent("go")

    assert ran == ["search:x"]
    # One spawn; with no agent_map entry the child runs as its parent's agent,
    # requesting exactly its own tools.
    [spawn] = mock_apdp.spawn_subagent_calls
    assert spawned_agents(mock_apdp) == [AGENTS["agent-root"]]
    if labelled_spawn_supported():
        # Sent under its Strands name; wl-apdp picks the agent.
        assert spawn_labels(mock_apdp) == ["researcher"]
        assert not spawn.get("child_agent_id")
    assert spawn["requested_scope"]["allowed_tools"] == ["search"]
    started = _started(mock_apdp)
    root = [e for e in started if not e.get("parent_execution_id")]
    kids = [e for e in started if e.get("parent_execution_id")]
    assert len(root) == 1 and len(kids) == 1
    assert kids[0]["parent_execution_id"] == root[0]["execution_id"]
    # The child's tool was authorized on the child's own run.
    search_call = next(c for c in mock_apdp.authorize_calls if c["resource"].endswith('"search"'))
    assert search_call["execution_id"] == kids[0]["execution_id"]
    assert len(events_of(mock_apdp, "execution_completed")) == 2


def test_agent_map_gives_a_child_its_own_registered_identity(make_plugin, mock_apdp: MockApdpClient):
    child = _child("researcher", [[tool_call("search", {"q": "x"})], [text("child done")]], [search])
    parent = Agent(
        model=ScriptedModel([[tool_call("researcher", {"input": "x"})], [text("done")]]),
        tools=[child.as_tool()],
        plugins=[make_plugin("agent-root", agent_map={"researcher": "agent-child"})],
        callback_handler=None,
    )

    parent("go")

    [spawn] = mock_apdp.spawn_subagent_calls
    assert spawn["child_agent_id"] == AGENTS["agent-child"]
    by_resource = {c["resource"].split('"')[1]: c["principal"] for c in mock_apdp.authorize_calls}
    assert by_resource["researcher"] == _principal("agent-root")
    assert by_resource["search"] == _principal("agent-child")


def test_nested_agents_as_tools_are_governed_at_every_depth(make_plugin, mock_apdp: MockApdpClient):
    grandchild = _child("fetcher", [[tool_call("search", {"q": "deep"})], [text("gc done")]], [search])
    child = _child(
        "researcher",
        [[tool_call("fetcher", {"input": "go"}), tool_call("summarize", {"text_in": "t"})], [text("c done")]],
        [grandchild.as_tool(), summarize],
    )
    parent = Agent(
        model=ScriptedModel([[tool_call("researcher", {"input": "go"})], [text("done")]]),
        tools=[child.as_tool()],
        plugins=[make_plugin("agent-root")],
        callback_handler=None,
    )

    parent("go")

    assert sorted(ran) == ["search:deep", "summarize"]
    assert len(mock_apdp.spawn_subagent_calls) == 2
    started = {e["execution_id"]: e for e in _started(mock_apdp)}
    leaf = next(c for c in mock_apdp.authorize_calls if c["resource"].endswith('"search"'))
    chain = []
    exec_id = leaf["execution_id"]
    while exec_id:
        chain.append(exec_id)
        exec_id = started[exec_id].get("parent_execution_id")
    assert len(chain) == 3, "grandchild -> child -> root"


def test_an_agent_tool_added_after_install_is_attached_before_it_runs(make_plugin, mock_apdp: MockApdpClient):
    parent = Agent(
        model=ScriptedModel([[tool_call("late", {"input": "x"})], [text("done")]]),
        tools=[],
        plugins=[make_plugin("agent-root")],
        callback_handler=None,
    )
    late = _child("late", [[tool_call("search", {"q": "late"})], [text("ok")]], [search])
    assert governing_plugin(late) is None
    parent.tool_registry.register_tool(late.as_tool())

    parent("go")

    assert ran == ["search:late"]
    assert governing_plugin(late) is governing_plugin(parent)
    assert len(mock_apdp.spawn_subagent_calls) == 1


def test_an_agent_a_tool_body_refers_to_is_governed(make_plugin, mock_apdp: MockApdpClient):
    summarizer = _child("summarizer", [[tool_call("summarize", {"text_in": "t"})], [text("child done")]], [summarize])

    @tool
    def delegate(task: str) -> str:
        """Delegate to the summarizer."""
        return str(summarizer(task))

    parent = Agent(
        model=ScriptedModel([[tool_call("delegate", {"task": "t"})], [text("done")]]),
        tools=[delegate],
        plugins=[make_plugin("agent-root")],
        callback_handler=None,
    )

    parent("go")

    assert ran == ["summarize"]
    assert len(mock_apdp.spawn_subagent_calls) == 1
    assert governing_plugin(summarizer) is governing_plugin(parent)


def test_a_refused_spawn_never_runs_the_child(make_plugin, mock_apdp: MockApdpClient):
    mock_apdp.spawn_error_override = ScopeAttenuationDenied("not a strict subset")
    child_model = ScriptedModel([[tool_call("search", {"q": "x"})]])
    child = Agent(name="researcher", model=child_model, tools=[search], callback_handler=None)
    parent = Agent(
        model=ScriptedModel([[tool_call("researcher", {"input": "look"})], [text("done")]]),
        tools=[child.as_tool()],
        plugins=[make_plugin("agent-root")],
        callback_handler=None,
    )

    parent("go")

    assert child_model.calls == 0 and ran == []
    assert len(mock_apdp._closed_sessions) == 1


def test_a_child_whose_attachment_fails_is_refused(make_plugin, mock_apdp: MockApdpClient):
    # In-process stand-in for unit tests only: a registry that refuses
    # registration, as a broken or foreign registry would.
    class RefusingRegistry(HookRegistry):
        def add_callback(self, *args: Any, **kwargs: Any) -> None:
            raise RuntimeError("registration refused")

    child_model = ScriptedModel([[tool_call("search", {"q": "x"})]])
    child = Agent(name="researcher", model=child_model, tools=[search], callback_handler=None)
    child.hooks = RefusingRegistry()
    parent_model = ScriptedModel([[tool_call("researcher", {"input": "x"})], [text("done")]])
    parent = Agent(
        model=parent_model,
        tools=[child.as_tool()],
        plugins=[make_plugin("agent-root")],
        callback_handler=None,
    )

    # The child is reachable when the parent starts, so the invocation is
    # refused before any model call: a component could call it directly.
    with pytest.raises(UngovernedModelUse, match="cannot be governed"):
        parent("go")

    assert child_model.calls == 0 and parent_model.calls == 0 and ran == []
    assert governing_plugin(child) is None
    (failed,) = events_of(mock_apdp, "execution_failed")
    assert "UngovernedModelUse" in json.dumps(failed)


def test_a_child_with_background_tasks_is_refused(make_plugin, mock_apdp: MockApdpClient):
    import inspect

    if "background_tasks" not in inspect.signature(Agent.__init__).parameters:
        pytest.skip("this strands-agents release has no background tasks")
    child_model = ScriptedModel([[tool_call("search", {"q": "x"})]])
    child = Agent(name="bg", model=child_model, tools=[search], background_tasks=True, callback_handler=None)
    parent_model = ScriptedModel([[tool_call("bg", {"input": "x"})], [text("done")]])
    parent = Agent(
        model=parent_model, tools=[child.as_tool()], plugins=[make_plugin("agent-root")], callback_handler=None
    )

    with pytest.raises(UngovernedModelUse, match="background_tasks"):
        parent("go")

    assert child_model.calls == 0 and parent_model.calls == 0 and ran == []


def test_configured_subagent_scope_is_requested(make_plugin, mock_apdp: MockApdpClient):
    child = _child("researcher", [[text("child done")]], [search, summarize])
    parent = Agent(
        model=ScriptedModel([[tool_call("researcher", {"input": "x"})], [text("done")]]),
        tools=[child.as_tool()],
        plugins=[
            make_plugin(
                "agent-root",
                subagent_scopes={"researcher": {"allowed_tools": ["search"], "max_depth": 0, "time_budget_seconds": 60}},
            )
        ],
        callback_handler=None,
    )

    parent("go")

    scope = mock_apdp.spawn_subagent_calls[0]["requested_scope"]
    assert scope["allowed_tools"] == ["search"]
    assert scope["max_depth"] == 0
    assert scope["time_budget_seconds"] == 60


def test_concurrent_children_each_use_their_own_run(make_plugin, mock_apdp: MockApdpClient):
    a = _child("alpha", [[tool_call("search", {"q": "a"})], [text("a done")]], [search])
    b = _child("beta", [[tool_call("summarize", {"text_in": "b"})], [text("b done")]], [summarize])
    parent = Agent(
        model=ScriptedModel([[tool_call("alpha", {"input": "x"}), tool_call("beta", {"input": "y"})], [text("done")]]),
        tools=[a.as_tool(), b.as_tool()],
        plugins=[make_plugin("agent-root", agent_map={"alpha": "agent-child", "beta": "agent-child-b"})],
        callback_handler=None,
    )

    parent("go")

    assert sorted(ran) == ["search:a", "summarize"]
    by_resource = {c["resource"].split('"')[1]: c for c in mock_apdp.authorize_calls}
    assert by_resource["search"]["principal"] == _principal("agent-child")
    assert by_resource["summarize"]["principal"] == _principal("agent-child-b")
    assert by_resource["search"]["execution_id"] != by_resource["summarize"]["execution_id"]
    assert len(mock_apdp.spawn_subagent_calls) == 2


def test_a_child_denial_does_not_leak_into_the_parent(make_plugin, mock_apdp: MockApdpClient):
    mock_apdp.decisions[("execute", "search")] = "Deny"
    child = _child("researcher", [[tool_call("search", {"q": "x"})], [text("child done")]], [search])
    parent = Agent(
        model=ScriptedModel([[tool_call("researcher", {"input": "x"})], [text("done")]]),
        tools=[child.as_tool()],
        plugins=[make_plugin("agent-root")],
        callback_handler=None,
    )

    parent("go")

    assert ran == []
    assert len(mock_apdp._closed_sessions) == 2


def test_a_child_invoked_outside_any_governed_run_is_refused(make_plugin, mock_apdp: MockApdpClient):
    """A child has no identity of its own unless agent_map gives it one."""
    child_model = ScriptedModel([[tool_call("search", {"q": "x"})]])
    child = Agent(name="researcher", model=child_model, tools=[search], callback_handler=None)
    Agent(model=ScriptedModel(), tools=[child.as_tool()], plugins=[make_plugin("agent-root")], callback_handler=None)

    with pytest.raises(AgentNotIdentified):
        child("on its own")
    assert child_model.calls == 0 and ran == []


def test_child_runs_still_open_end_with_the_parent(make_plugin, mock_apdp: MockApdpClient):
    from watchlight_strands.plugin import _ACTIVE_RUNS

    child = Agent(name="researcher", model=ScriptedModel(), callback_handler=None)
    parent = Agent(
        model=ScriptedModel(), tools=[child.as_tool()], plugins=[make_plugin("agent-root")], callback_handler=None
    )
    plugin = governing_plugin(parent)

    async def scenario() -> None:
        parent_run = await plugin._open_run(parent, {})
        child_run = await plugin._open_run(child, {})
        assert child_run.parent is parent_run
        await plugin._close_run(parent_run, None)
        assert child_run.closed
        assert _ACTIVE_RUNS.get() == ()

    asyncio.run(scenario())
    failed = events_of(mock_apdp, "execution_failed")
    assert len(failed) == 1 and failed[0].get("parent_execution_id")
    assert "EndedWithParent" in failed[0]["payload"]["error"]


def test_a_child_declares_an_intent_derived_from_its_description(make_plugin, mock_apdp: MockApdpClient):
    """Every spawn carries the child's intent: the agent's
    ``description`` is the objective, ``child_intent_category`` the category."""
    child = Agent(
        name="researcher",
        description="Research the market for widgets",
        model=ScriptedModel([[tool_call("search", {"q": "x"})], [text("child done")]]),
        tools=[search],
        callback_handler=None,
    )
    parent = Agent(
        model=ScriptedModel([[tool_call("researcher", {"input": "x"})], [text("done")]]),
        tools=[child.as_tool()],
        plugins=[make_plugin("agent-root", child_intent_category="research")],
        callback_handler=None,
    )

    parent("go")

    [spawn] = mock_apdp.spawn_subagent_calls
    assert spawn["child_intent"]["category"] == "research"
    assert spawn["child_intent"]["objective"] == "Research the market for widgets"


def test_a_child_without_a_description_or_category_uses_the_core_derivation(
    make_plugin, mock_apdp: MockApdpClient
):
    """No description: a fixed objective naming the child; no configured
    category: watchlight-core's derived default, which wl-apdp refuses
    outside the parent's intent bounds (the child then never runs)."""
    from watchlight_core.scope import DEFAULT_PLUGIN_CHILD_INTENT_CATEGORY

    child = _child("researcher", [[tool_call("search", {"q": "x"})], [text("child done")]], [search])
    parent = Agent(
        model=ScriptedModel([[tool_call("researcher", {"input": "x"})], [text("done")]]),
        tools=[child.as_tool()],
        plugins=[make_plugin("agent-root")],
        callback_handler=None,
    )

    parent("go")

    [spawn] = mock_apdp.spawn_subagent_calls
    assert spawn["child_intent"]["category"] == DEFAULT_PLUGIN_CHILD_INTENT_CATEGORY
    assert spawn["child_intent"]["objective"] == "strands task for researcher"


def test_a_scope_that_pins_one_intent_names_the_childs_category(make_plugin, mock_apdp: MockApdpClient):
    child = _child("researcher", [[tool_call("search", {"q": "x"})], [text("child done")]], [search])
    parent = Agent(
        model=ScriptedModel([[tool_call("researcher", {"input": "x"})], [text("done")]]),
        tools=[child.as_tool()],
        plugins=[
            make_plugin(
                "agent-root",
                child_intent_category="content_generation",
                subagent_scopes={"researcher": {"allowed_intents": ["data_analysis"]}},
            )
        ],
        callback_handler=None,
    )

    parent("go")

    [spawn] = mock_apdp.spawn_subagent_calls
    assert spawn["child_intent"]["category"] == "data_analysis"
    assert spawn["requested_scope"]["allowed_intents"] == ["data_analysis"]


def _declared_intent_parent(make_plugin, **plugin_kwargs: Any):
    child = Agent(
        name="researcher",
        description="Research the market for widgets",
        model=ScriptedModel([[tool_call("search", {"q": "x"})], [text("child done")]]),
        tools=[search],
        callback_handler=None,
    )
    return Agent(
        model=ScriptedModel([[tool_call("researcher", {"input": "x"})], [text("done")]]),
        tools=[child.as_tool()],
        plugins=[
            make_plugin(
                "agent-root",
                intent_objective="study the widget market",
                intent_category="research",
                **plugin_kwargs,
            )
        ],
        callback_handler=None,
    )


def _search_intents(mock_apdp: MockApdpClient) -> List[Any]:
    return [c["intent"] for c in mock_apdp.authorize_calls if '"search"' in c["resource"]]


def test_a_child_carries_its_own_derived_intent_not_the_runs(make_plugin, mock_apdp: MockApdpClient):
    """As every plugin: the run's declared intent is the root's. A child
    derives its category (scope pin, child_intent_category, the parent's
    derived category, the core default) and its calls carry its own derived
    intent, the one wl-apdp grants it, never the root's."""
    from watchlight_core.scope import DEFAULT_PLUGIN_CHILD_INTENT_CATEGORY

    _declared_intent_parent(make_plugin)("go")

    [spawn] = mock_apdp.spawn_subagent_calls
    assert spawn["child_intent"]["category"] == DEFAULT_PLUGIN_CHILD_INTENT_CATEGORY
    assert _search_intents(mock_apdp) == [
        {
            "objective": "Research the market for widgets",
            "category": {"custom": DEFAULT_PLUGIN_CHILD_INTENT_CATEGORY.split(":", 1)[1]},
        }
    ]


def test_a_child_with_a_configured_category_carries_it(make_plugin, mock_apdp: MockApdpClient):
    _declared_intent_parent(make_plugin, child_intent_category="data_analysis")("go")

    [spawn] = mock_apdp.spawn_subagent_calls
    assert spawn["child_intent"]["category"] == "data_analysis"
    assert _search_intents(mock_apdp) == [
        {"objective": "Research the market for widgets", "category": "data_analysis"}
    ]


def test_a_grandchild_derives_its_category_from_its_parent(make_plugin, mock_apdp: MockApdpClient):
    """An unpinned grandchild derives from its parent's derived category,
    never from the root's declared one (wl-apdp would refuse that as
    outside the parent's bounds)."""
    grandchild = Agent(
        name="digger",
        description="Dig into one source",
        model=ScriptedModel([[tool_call("search", {"q": "deep"})], [text("grandchild done")]]),
        tools=[search],
        callback_handler=None,
    )
    child = Agent(
        name="researcher",
        description="Research the market for widgets",
        model=ScriptedModel([[tool_call("digger", {"input": "x"})], [text("child done")]]),
        tools=[grandchild.as_tool()],
        callback_handler=None,
    )
    parent = Agent(
        model=ScriptedModel([[tool_call("researcher", {"input": "x"})], [text("done")]]),
        tools=[child.as_tool()],
        plugins=[
            make_plugin(
                "agent-root",
                intent_objective="study the widget market",
                intent_category="research",
                subagent_scopes={
                    "researcher": {"allowed_intents": ["data_analysis"], "max_depth": 1}
                },
            )
        ],
        callback_handler=None,
    )

    parent("go")

    assert ran == ["search:deep"]
    researcher, digger = mock_apdp.spawn_subagent_calls
    assert researcher["child_intent"]["category"] == "data_analysis"
    assert digger["child_intent"]["category"] == "data_analysis"
    assert _search_intents(mock_apdp) == [
        {"objective": "Dig into one source", "category": "data_analysis"}
    ]


@pytest.mark.parametrize("category", ["Research", "analysis", "custom:", "custom:bad name"])
def test_a_malformed_child_intent_category_is_refused_at_construction(make_plugin, category):
    with pytest.raises(ValueError, match="child_intent_category"):
        make_plugin("agent-root", child_intent_category=category)


def test_a_malformed_pinned_intent_is_refused_at_construction(make_plugin):
    with pytest.raises(ValueError, match="allowed_intents"):
        make_plugin("agent-root", subagent_scopes={"researcher": {"allowed_intents": ["Research"]}})


def test_a_child_whose_intent_cannot_be_recorded_is_ended_and_refused(
    make_plugin, mock_apdp: MockApdpClient, monkeypatch
):
    """The spawn succeeded but the child's intent cannot be stamped: the
    child's session is ended, the child never runs, and the parent's model
    sees the spawn refusal, never the raw error."""
    from watchlight_core import BaseRunHandle

    real = BaseRunHandle.record_declared_intent

    def refuse_for_children(self, objective, *args, **kwargs):
        if getattr(self, "granted_scope", None) is not None:
            raise ValueError("raw intent error text")
        return real(self, objective, *args, **kwargs)

    monkeypatch.setattr(BaseRunHandle, "record_declared_intent", refuse_for_children)
    child_model = ScriptedModel([[tool_call("search", {"q": "x"})]])
    child = Agent(name="researcher", model=child_model, tools=[search], callback_handler=None)
    parent_model = ScriptedModel([[tool_call("researcher", {"input": "x"})], [text("done")]])
    parent = Agent(
        model=parent_model,
        tools=[child.as_tool()],
        plugins=[make_plugin("agent-root")],
        callback_handler=None,
    )

    parent("go")

    assert child_model.calls == 0 and ran == []
    [spawn] = mock_apdp.spawn_subagent_calls
    texts = parent_model.tool_result_texts()
    assert any("the governed spawn of this agent was refused" in t for t in texts)
    assert not any("raw intent error text" in t for t in texts)
    assert any(r.startswith("run_failed: intent_refused") for _, r in mock_apdp._terminated_sessions)


def test_child_intent_category_must_be_a_non_empty_string(make_plugin):
    with pytest.raises(ValueError):
        make_plugin("agent-root", child_intent_category="  ")
