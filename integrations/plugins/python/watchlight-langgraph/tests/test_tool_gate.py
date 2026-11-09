"""In a governed run, every tool LangGraph's ``ToolNode`` runs is
decided before it runs, with no change to the user's agent code, and every
other tool start is refused by the shared LangChain backstop."""

from __future__ import annotations

import asyncio
import contextvars
import threading
from typing import Any, Dict, List, Optional, TypedDict

import pytest
from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, ToolMessage
from langchain_core.tools import tool
from langgraph.graph import END, StateGraph
from langgraph.prebuilt import ToolNode, create_react_agent
from watchlight_core import GovernanceUnavailable
from watchlight_core.langchain_tool_backstop import (
    UngovernedModelCall,
    UngovernedToolCall,
)
from watchlight_core_testing import MockApdpClient

from watchlight_langgraph import WatchlightLangGraphPlugin, tool_gate
from watchlight_langgraph.governance import ToolDenied, governed_tool_call

from .scripted_anthropic import ScriptedChat

AGENT_UUID = "11111111-1111-4111-8111-111111111111"

ran: List[str] = []


@tool
def lookup(q: str) -> str:
    """Look something up."""
    ran.append(f"lookup:{q}")
    return "found"


@tool
def send_email(to: str) -> str:
    """Send an email."""
    ran.append(f"send_email:{to}")
    return "sent"


@pytest.fixture(autouse=True)
def _clean() -> Any:
    ran.clear()
    yield
    ran.clear()


def _calls(*names: str) -> AIMessage:
    return AIMessage(
        content="",
        tool_calls=[
            {
                "name": n,
                "args": {"q": "x"} if n == "lookup" else {"to": "a@b"},
                "id": f"call_{n}",
            }
            for n in names
        ],
    )


def _model(*names: str) -> Any:
    return ScriptedChat(answers=[_calls(*names), AIMessage(content="done")])


class _Apdp(MockApdpClient):
    def __init__(
        self, decisions: Optional[Dict[str, str]] = None, reachable: bool = True
    ) -> None:
        super().__init__(default_decision="Allow")
        self.known_agents["research-analyst"] = AGENT_UUID
        for name, decision in (decisions or {}).items():
            self.decisions[("execute", name)] = decision
        self.reachable = reachable

    async def authorize(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        if not self.reachable:
            raise ConnectionError("policy service unreachable")
        return await super().authorize(*args, **kwargs)


def _plugin(apdp: MockApdpClient) -> WatchlightLangGraphPlugin:
    plugin = WatchlightLangGraphPlugin(apdp_url="https://apdp.test")
    plugin.apdp = apdp  # type: ignore[assignment]
    return plugin


def _decided(apdp: MockApdpClient) -> List[str]:
    return [
        c["resource"].split('"')[1]
        for c in apdp.authorize_calls
        if c["action"].endswith('"execute"')
    ]


def _backstop_refusals(apdp: MockApdpClient, kind: str = "tool") -> List[str]:
    key = "tool" if kind == "tool" else "resource"
    return [
        e["payload"][key]["identifier"]
        for e in apdp.published_events
        if (e.get("metadata") or {}).get("backstop") and key in (e.get("payload") or {})
    ]


async def _refused_in_the_graph(app: Any, kind: type) -> None:
    """The refusal either fails the graph or, with ``ToolNode`` error
    handling, comes back as an error ToolMessage; either way it is the
    backstop's."""
    try:
        out = await app.ainvoke({"messages": [HumanMessage("go")]})
    except kind:
        return
    errors = [
        m for m in out["messages"] if isinstance(m, ToolMessage) and m.status == "error"
    ]
    assert (
        errors
        and kind.__name__ in errors[0].content
        or "Watchlight refused" in errors[0].content
    )


class _S(TypedDict, total=False):
    messages: List[BaseMessage]


def _hand_built(model: Any, tools: List[Any]) -> Any:
    """A hand-built graph: a model node that binds the tools, and a ToolNode."""
    bound = model.bind_tools(tools)

    async def acall_model(state: _S) -> _S:
        return {
            "messages": state["messages"] + [await bound.ainvoke(state["messages"])]
        }

    node = ToolNode(tools)

    async def run_tools(state: _S) -> _S:
        out = await node.ainvoke({"messages": state["messages"]})
        return {"messages": state["messages"] + out["messages"]}

    graph = StateGraph(_S)
    graph.add_node("model", acall_model)
    graph.add_node("tools", run_tools)
    graph.set_entry_point("model")
    graph.add_conditional_edges(
        "model", lambda s: "tools" if s["messages"][-1].tool_calls else END
    )
    graph.add_edge("tools", "model")
    return graph.compile()


def _react(model: Any, tools: List[Any]) -> Any:
    return create_react_agent(model, tools)


def _create_agent(model: Any, tools: List[Any]) -> Any:
    agents = pytest.importorskip("langchain.agents")
    return agents.create_agent(model, tools)


BUILDERS = [
    ("hand_built", _hand_built),
    ("create_react_agent", _react),
    ("create_agent", _create_agent),
]


# ── unchanged user code: decided before it runs ─────────────────────


@pytest.mark.asyncio
@pytest.mark.parametrize("name,build", BUILDERS, ids=[b[0] for b in BUILDERS])
async def test_a_denied_tool_never_runs_and_an_allowed_one_does(
    name: str, build: Any
) -> None:
    apdp = _Apdp({"send_email": "Deny"})
    app = build(_model("lookup", "send_email"), [lookup, send_email])
    async with await _plugin(apdp).start_run(agent_slug="research-analyst"):
        with pytest.raises(ToolDenied):
            await app.ainvoke({"messages": [HumanMessage("go")]})
    assert "send_email:a@b" not in ran
    assert "send_email" in _decided(apdp)

    ran.clear()
    apdp = _Apdp()
    app = build(_model("lookup", "send_email"), [lookup, send_email])
    async with await _plugin(apdp).start_run(agent_slug="research-analyst"):
        await app.ainvoke({"messages": [HumanMessage("go")]})
    assert sorted(ran) == ["lookup:x", "send_email:a@b"]
    assert sorted(_decided(apdp)) == ["lookup", "send_email"]


@pytest.mark.asyncio
async def test_policy_unreachable_refuses_the_tool() -> None:
    apdp = _Apdp(reachable=False)
    app = _react(_model("lookup"), [lookup])
    async with await _plugin(apdp).start_run(agent_slug="research-analyst"):
        with pytest.raises((GovernanceUnavailable, ToolDenied)):
            await app.ainvoke({"messages": [HumanMessage("go")]})
    assert ran == []


@pytest.mark.asyncio
async def test_a_sync_tool_in_an_async_graph_is_decided_on_the_runs_loop() -> None:
    """``ToolNode`` runs a sync graph's tools on a worker thread; the
    decision is made on the run's loop."""
    apdp = _Apdp({"send_email": "Deny"})
    app = _react(_model("send_email"), [send_email])
    async with await _plugin(apdp).start_run(agent_slug="research-analyst"):
        with pytest.raises(ToolDenied):
            await asyncio.to_thread(app.invoke, {"messages": [HumanMessage("go")]})
    assert ran == [] and _decided(apdp) == ["send_email"]


@pytest.mark.asyncio
async def test_a_sync_graph_blocking_the_runs_loop_is_refused_at_the_decision_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``ToolNode`` runs the tool on a worker thread while the run's loop is
    blocked by the synchronous ``invoke``: the decision cannot run, so the
    call is refused when the decision timeout passes, never sent."""
    monkeypatch.setattr(tool_gate, "DECISION_TIMEOUT_SECONDS", 0.5)
    apdp = _Apdp()
    app = _react(_model("lookup"), [lookup])
    async with await _plugin(apdp).start_run(agent_slug="research-analyst"):
        with pytest.raises(GovernanceUnavailable):
            app.invoke({"messages": [HumanMessage("go")]})
    assert ran == []


@pytest.mark.asyncio
async def test_no_effect_with_no_governed_run() -> None:
    tool_gate.install()
    app = _react(_model("lookup", "send_email"), [lookup, send_email])
    await app.ainvoke({"messages": [HumanMessage("go")]})
    assert sorted(ran) == ["lookup:x", "send_email:a@b"]


# ── every other tool start is refused ───────────────────────────────


@pytest.mark.asyncio
async def test_a_tool_called_directly_in_a_run_is_refused_and_recorded() -> None:
    apdp = _Apdp()
    async with await _plugin(apdp).start_run(agent_slug="research-analyst"):
        with pytest.raises(UngovernedToolCall):
            lookup.invoke({"q": "direct"})
        with pytest.raises(UngovernedToolCall):
            lookup.invoke({"q": "no callbacks"}, config={"callbacks": []})
        with pytest.raises(UngovernedToolCall):
            await lookup.ainvoke({"q": "async"}, config={"callbacks": []})
        with pytest.raises(UngovernedToolCall):
            await asyncio.to_thread(
                lambda: contextvars.Context().run(lookup.invoke, {"q": "fresh"})
            )
        errors: List[BaseException] = []

        def bare() -> None:
            try:
                lookup.invoke({"q": "raw thread"})
            except BaseException as exc:  # noqa: BLE001 - asserted below
                errors.append(exc)

        thread = threading.Thread(target=bare)
        thread.start()
        thread.join(10)
        assert len(errors) == 1 and isinstance(errors[0], UngovernedToolCall)
    assert ran == []
    assert _backstop_refusals(apdp).count("lookup") == 5


@pytest.mark.asyncio
async def test_a_tool_started_inside_an_allowed_tools_body_is_refused() -> None:
    """``ToolNode`` turns the refusal into a ToolMessage; the inner tool's
    body never runs and the refusal is recorded."""

    @tool
    def outer(q: str) -> str:
        """Run another tool."""
        ran.append("outer")
        return send_email.invoke({"to": "x@y"})

    apdp = _Apdp()
    model = ScriptedChat(
        answers=[
            AIMessage(
                content="",
                tool_calls=[{"name": "outer", "args": {"q": "x"}, "id": "call_outer"}],
            ),
            AIMessage(content="done"),
        ]
    )
    app = _react(model, [outer])
    async with await _plugin(apdp).start_run(agent_slug="research-analyst"):
        await _refused_in_the_graph(app, UngovernedToolCall)
    assert ran == ["outer"]
    assert _backstop_refusals(apdp) == ["send_email"]


@pytest.mark.asyncio
async def test_an_agent_built_inside_a_tool_is_refused() -> None:
    @tool
    def research(q: str) -> str:
        """Run an inner agent."""
        ran.append("research")
        inner = create_react_agent(_model("send_email"), [send_email])
        inner.invoke({"messages": [HumanMessage(q)]})
        return "researched"

    apdp = _Apdp()
    model = ScriptedChat(
        answers=[
            AIMessage(
                content="",
                tool_calls=[{"name": "research", "args": {"q": "x"}, "id": "call_r"}],
            ),
            AIMessage(content="done"),
        ]
    )
    app = _react(model, [research])
    async with await _plugin(apdp).start_run(agent_slug="research-analyst"):
        await _refused_in_the_graph(app, UngovernedModelCall)
    assert ran == ["research"], "the inner agent's tool must never run"
    assert _backstop_refusals(apdp, "model") == ["scripted"] or _backstop_refusals(
        apdp, "model"
    )


def test_a_model_that_binds_tools_is_refused_off_the_runs_context_and_allowed_without_tools() -> (
    None
):
    apdp = _Apdp()
    errors: List[BaseException] = []

    async def main() -> None:
        async with await _plugin(apdp).start_run(agent_slug="research-analyst"):

            def bare() -> None:
                try:
                    _model("lookup").bind_tools([lookup]).invoke("hi")
                except BaseException as exc:  # noqa: BLE001 - asserted below
                    errors.append(exc)
                ScriptedChat(answers=[AIMessage(content="ok")]).invoke("no tools")

            thread = threading.Thread(target=bare)
            thread.start()
            thread.join(10)

    asyncio.run(main())
    assert len(errors) == 1 and isinstance(errors[0], UngovernedModelCall)


# ── the documented manual path keeps working ────────────────────────


@pytest.mark.asyncio
async def test_bind_tools_and_governed_tool_call_keep_working() -> None:
    apdp = _Apdp({"send_email": "Deny"})
    plugin = _plugin(apdp)
    async with await plugin.start_run(agent_slug="research-analyst") as handle:
        message = await _model("lookup").bind_tools([lookup]).ainvoke("hi")
        assert message.tool_calls
        result = await governed_tool_call(
            handle,
            "lookup",
            intent={},
            context={},
            impl=lookup.invoke,
            input={"q": "governed"},
        )
        assert result == "found"
        with pytest.raises(ToolDenied):
            await governed_tool_call(
                handle,
                "send_email",
                intent={},
                context={},
                impl=send_email.invoke,
                input={"to": "x"},
            )
        with pytest.raises(UngovernedToolCall):
            await governed_tool_call(
                handle,
                "lookup",
                intent={},
                context={},
                impl=lambda: (lookup.invoke({"q": "1"}), lookup.invoke({"q": "2"})),
            )
    assert ran == ["lookup:governed", "lookup:1"]


# ── runs do not release each other ──────────────────────────────────


@pytest.mark.asyncio
async def test_two_concurrent_runs_with_the_same_tool_call_id_do_not_release_each_other() -> (
    None
):
    allowed, denied = _Apdp(), _Apdp({"send_email": "Deny"})
    both_open = asyncio.Barrier(2)

    async def run(apdp: _Apdp) -> Optional[BaseException]:
        app = _react(_model("send_email"), [send_email])
        async with await _plugin(apdp).start_run(agent_slug="research-analyst"):
            await both_open.wait()
            try:
                await app.ainvoke({"messages": [HumanMessage("go")]})
            except BaseException as exc:  # noqa: BLE001 - asserted below
                return exc
        return None

    results = await asyncio.gather(run(allowed), run(denied))
    assert results[0] is None and isinstance(results[1], ToolDenied)
    assert ran == ["send_email:a@b"]


# ── the patch must be in place ──────────────────────────────────────


@pytest.mark.parametrize(
    "name,call",
    [("_execute_tool_sync", "tool.invoke("), ("_execute_tool_async", "tool.ainvoke(")],
)
def test_tripwire_the_wrapped_methods_are_the_ones_that_call_the_tool(
    name: str, call: str
) -> None:
    import inspect

    tool_gate.install()
    method = ToolNode.__dict__[name]
    assert getattr(method, tool_gate._MARK, False)
    assert call in inspect.getsource(inspect.unwrap(method))


@pytest.mark.asyncio
async def test_a_replaced_wrap_refuses_the_run(monkeypatch: pytest.MonkeyPatch) -> None:
    import inspect

    tool_gate.install()
    original = inspect.unwrap(ToolNode.__dict__["_execute_tool_async"])
    monkeypatch.setattr(ToolNode, "_execute_tool_async", original)
    with pytest.raises(GovernanceUnavailable):
        await _plugin(_Apdp()).start_run(agent_slug="research-analyst")


@pytest.mark.asyncio
async def test_a_missing_target_refuses_start_run(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(tool_gate, "_installed", False)
    monkeypatch.delattr(ToolNode, "_execute_tool_sync")
    with pytest.raises(GovernanceUnavailable):
        await _plugin(_Apdp()).start_run(agent_slug="research-analyst")


# ── what reaches the decision service ────────────────────


@pytest.mark.asyncio
async def test_no_argument_value_reaches_the_decision_service() -> None:
    apdp = _Apdp()
    secret = "sk-live-do-not-send-0123456789"
    model = ScriptedChat(
        answers=[
            AIMessage(
                content="",
                tool_calls=[{"name": "send_email", "args": {"to": secret}, "id": "c1"}],
            ),
            AIMessage(content="done"),
        ]
    )
    app = _react(model, [send_email])
    async with await _plugin(apdp).start_run(agent_slug="research-analyst"):
        await app.ainvoke({"messages": [HumanMessage("go")]})
    calls = [c for c in apdp.authorize_calls if c["action"].endswith('"execute"')]
    assert calls, "the tool call was decided"
    assert secret not in repr(calls)
    assert calls[0]["context"]["tool_args"] == {
        "arg_count": 1,
        "arg_names": ["to"],
        "arg_types": {"to": "str"},
    }


# ── a run not entered with ``async with`` ────────────────


@pytest.mark.asyncio
async def test_a_plain_agent_after_a_bare_start_run_is_refused() -> None:
    from watchlight_core import WatchlightError

    apdp = _Apdp()
    handle = await _plugin(apdp).start_run(agent_slug="research-analyst")
    app = _react(_model("lookup"), [lookup])
    try:
        with pytest.raises(WatchlightError, match="async with"):
            await app.ainvoke({"messages": [HumanMessage("go")]})
        with pytest.raises(UngovernedToolCall):
            await asyncio.to_thread(
                lambda: contextvars.Context().run(lookup.invoke, {"q": "fresh"})
            )
    finally:
        await handle.complete()
    assert ran == []
    # Once the run is closed, nothing is governed any more.
    await _react(_model("lookup"), [lookup]).ainvoke({"messages": [HumanMessage("go")]})
    assert ran == ["lookup:x"]


# ── sub-agents resolve through core's attribution ────────


class _SpawnApdp(_Apdp):
    def __init__(self) -> None:
        super().__init__()
        self.known_agents["child-agent"] = "22222222-2222-4222-8222-222222222222"


async def _spawn(root: Any, max_depth: int = 0) -> Any:
    return await root.spawn_subagent(
        "child-agent",
        child_intent={"category": "research", "objective": "Delegated sub-task"},
        allowed_tools=["lookup"],
        max_depth=max_depth,
    )


def _decided_runs(apdp: MockApdpClient) -> List[Any]:
    return [c["run"] for c in apdp.authorize_calls if c["action"].endswith('"execute"')]


@pytest.mark.asyncio
async def test_a_child_not_entered_is_decided_as_itself_never_its_parent() -> None:
    apdp = _SpawnApdp()
    async with await _plugin(apdp).start_run(agent_slug="research-analyst") as root:
        child = await _spawn(root)
        await _react(_model("lookup"), [lookup]).ainvoke(
            {"messages": [HumanMessage("go")]}
        )
        assert _decided_runs(apdp) == [child.run]
        await child.complete()
        # After the child completes, the parent acts again.
        await _react(_model("lookup"), [lookup]).ainvoke(
            {"messages": [HumanMessage("go")]}
        )
        assert _decided_runs(apdp) == [child.run, root.run]
    assert ran == ["lookup:x", "lookup:x"]


@pytest.mark.asyncio
async def test_a_second_live_sibling_in_one_context_is_refused() -> None:
    from watchlight_langgraph import SiblingSubagentLive

    apdp = _SpawnApdp()
    async with await _plugin(apdp).start_run(agent_slug="research-analyst") as root:
        first = await _spawn(root)
        with pytest.raises(SiblingSubagentLive):
            await _spawn(root)
        await _react(_model("lookup"), [lookup]).ainvoke(
            {"messages": [HumanMessage("go")]}
        )
        assert _decided_runs(apdp) == [first.run]
        await first.complete()


@pytest.mark.asyncio
async def test_live_siblings_each_in_their_own_task_are_each_decided_as_themselves() -> (
    None
):
    apdp = _SpawnApdp()
    async with await _plugin(apdp).start_run(agent_slug="research-analyst") as root:
        both = asyncio.Barrier(2)

        async def child_task() -> Any:
            child = await _spawn(root)
            await both.wait()  # both children live at once
            await _react(_model("lookup"), [lookup]).ainvoke(
                {"messages": [HumanMessage("go")]}
            )
            return child

        a, b = await asyncio.gather(child_task(), child_task())
        assert sorted(map(id, _decided_runs(apdp))) == sorted([id(a.run), id(b.run)])
        await a.complete()
        await b.complete()


# ── no other way past the gate ──────────────────────────────────────


@pytest.mark.asyncio
async def test_a_tool_node_subclass_that_calls_the_tool_itself_is_refused() -> None:
    class SelfRunningToolNode(ToolNode):
        async def _execute_tool_async(
            self, request: Any, input_type: Any, config: Any
        ) -> Any:
            out = request.tool.invoke(request.tool_call["args"])
            return ToolMessage(out, tool_call_id=request.tool_call["id"])

    apdp = _Apdp()
    app = _react(
        _model("lookup"), SelfRunningToolNode([lookup], handle_tool_errors=False)
    )
    async with await _plugin(apdp).start_run(agent_slug="research-analyst"):
        with pytest.raises(UngovernedToolCall):
            await app.ainvoke({"messages": [HumanMessage("go")]})
    assert ran == []


@pytest.mark.asyncio
async def test_watchlights_declare_intent_tool_runs_undecided_through_tool_node() -> (
    None
):
    from watchlight_langgraph.synthetic_tools import build_synthetic_langchain_tools

    apdp = _Apdp()
    async with await _plugin(apdp).start_run(agent_slug="research-analyst") as handle:
        synthetic = build_synthetic_langchain_tools(handle, mode="greenfield")
        assert synthetic
        call = {
            "name": synthetic[0].name,
            "args": {"objective": "audit invoices", "category": "data_analysis"},
            "id": "c_declare",
        }
        model = ScriptedChat(
            answers=[
                AIMessage(content="", tool_calls=[call]),
                AIMessage(content="done"),
            ]
        )
        out = await _react(model, synthetic).ainvoke({"messages": [HumanMessage("go")]})
        replies = [m for m in out["messages"] if isinstance(m, ToolMessage)]
        assert replies and replies[0].status != "error"
    assert _decided(apdp) == [], "the carve-out never round-trips to authorize"


@pytest.mark.asyncio
async def test_a_users_tool_named_like_declare_intent_is_still_decided() -> None:
    """The carve-out is Watchlight's own tool class, never a tool name."""
    from langchain_core.tools import StructuredTool

    def impostor(objective: str, category: str) -> str:
        ran.append("impostor")
        return "ok"

    tool_named_like_it = StructuredTool.from_function(
        impostor, name="watchlight.declare_intent", description="not Watchlight's"
    )
    apdp = _Apdp({"watchlight.declare_intent": "Deny"})
    call = {
        "name": "watchlight.declare_intent",
        "args": {"objective": "x", "category": "data_analysis"},
        "id": "c_imp",
    }
    model = ScriptedChat(
        answers=[AIMessage(content="", tool_calls=[call]), AIMessage(content="done")]
    )
    async with await _plugin(apdp).start_run(agent_slug="research-analyst"):
        with pytest.raises(ToolDenied):
            await _react(model, [tool_named_like_it]).ainvoke(
                {"messages": [HumanMessage("go")]}
            )
    assert ran == [] and _decided(apdp) == ["watchlight.declare_intent"]


@pytest.mark.asyncio
async def test_a_grant_releases_nothing_once_a_sub_agent_acts_in_its_context() -> None:
    """``governed_tool_call`` grants the parent one start of ``lookup``;
    after the call spawns a sub-agent there, that start belongs to the
    sub-agent, not the parent, and is refused."""
    apdp = _SpawnApdp()
    async with await _plugin(apdp).start_run(agent_slug="research-analyst") as root:

        async def impl() -> Any:
            child = await _spawn(root)
            try:
                return lookup.invoke({"q": "as the parent"})
            finally:
                await child.complete()

        with pytest.raises(UngovernedToolCall):
            await governed_tool_call(root, "lookup", intent={}, context={}, impl=impl)
    assert ran == []


def _impostor_body(objective: str, category: str) -> str:
    ran.append("impostor body")
    return "ran"


async def _aimpostor_body(objective: str, category: str) -> str:
    return _impostor_body(objective, category)


@pytest.mark.asyncio
@pytest.mark.parametrize("shape", ["subclass", "from_function_copy", "swapped_func"])
async def test_a_tool_made_to_look_like_declare_intent_is_decided(shape: str) -> None:
    """Only the exact tool the plugin built, unchanged, skips the decision."""
    from watchlight_langgraph import synthetic_tools

    apdp = _Apdp({"watchlight.declare_intent": "Deny"})
    async with await _plugin(apdp).start_run(agent_slug="research-analyst") as handle:
        built = synthetic_tools.build_synthetic_langchain_tools(
            handle, mode="greenfield"
        )[0]
        cls = type(built)
        if shape == "subclass":

            class Sub(cls):  # type: ignore[misc, valid-type]
                pass

            tool_ = Sub.from_function(
                func=_impostor_body,
                coroutine=_aimpostor_body,
                name=built.name,
                description="d",
            )
            tool_._watchlight_handle = handle
        elif shape == "from_function_copy":
            tool_ = cls.from_function(
                func=_impostor_body,
                coroutine=_aimpostor_body,
                name=built.name,
                description="d",
            )
            tool_._watchlight_handle = handle
        else:
            tool_ = built
            tool_.func = _impostor_body
            tool_.coroutine = _aimpostor_body
        assert not synthetic_tools.is_synthetic_tool(tool_)
        call = {
            "name": built.name,
            "args": {"objective": "x", "category": "data_analysis"},
            "id": "c_fake",
        }
        model = ScriptedChat(
            answers=[
                AIMessage(content="", tool_calls=[call]),
                AIMessage(content="done"),
            ]
        )
        with pytest.raises(ToolDenied):
            await _react(model, [tool_]).ainvoke({"messages": [HumanMessage("go")]})
    assert ran == [] and _decided(apdp) == ["watchlight.declare_intent"]


@pytest.mark.asyncio
async def test_a_live_grandchild_bound_here_refuses_a_spawn_from_the_root() -> None:
    from watchlight_langgraph import SiblingSubagentLive

    apdp = _SpawnApdp()
    async with await _plugin(apdp).start_run(agent_slug="research-analyst") as root:
        researcher = await _spawn(root, max_depth=1)
        collector = await _spawn(researcher)  # nesting: spawner is the bound one
        with pytest.raises(SiblingSubagentLive):
            await _spawn(root)
        await collector.complete()
        await researcher.complete()
        probe = await _spawn(root)  # both ended: allowed
        await probe.complete()


@pytest.mark.asyncio
async def test_the_delegated_drift_shape_spawns_probes_while_its_collector_lives() -> (
    None
):
    """The demo scenario: the collector is spawned in its own task, the
    researcher completes, and the root spawns probes while the collector is
    still live for a later check through its handle."""
    apdp = _SpawnApdp()
    async with await _plugin(apdp).start_run(agent_slug="research-analyst") as root:
        researcher = await _spawn(root, max_depth=1)
        collector = await asyncio.create_task(_spawn(researcher))
        await researcher.complete()
        for _ in range(2):
            probe = await _spawn(root)
            await probe.complete()
        assert collector.state.value == "active"
        await collector.complete()


@pytest.mark.asyncio
async def test_a_child_completed_in_another_context_does_not_block_a_spawn_here() -> (
    None
):
    """Completing a child in another task leaves its (ended) binding in
    this context; an ended binding never blocks a spawn."""
    apdp = _SpawnApdp()
    async with await _plugin(apdp).start_run(agent_slug="research-analyst") as root:
        child = await _spawn(root)
        await asyncio.create_task(child.complete())
        from watchlight_core.run_handle import _current_subagent_handle

        assert _current_subagent_handle.get() is child, "still bound here, but ended"
        sibling = await _spawn(root)
        await sibling.complete()
