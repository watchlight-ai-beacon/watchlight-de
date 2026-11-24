"""Parallel AgentTool calls keep their own identity.

google-adk runs each function call of one model response in its own task
(``flows/llm_flows/tools/_batch_executor.py``), so two ``AgentTool``
calls run their agents in parallel. The plugin used to keep one frame
stack per run: the two children pushed onto it, each authorized as
whichever had pushed last, and when one finished it popped the other's
frame and then its own, closing the ROOT while the other child still ran.
The child's next calls were then authorized as the root, under the
root's full, unattenuated scope.

Each agent now has a frame of its own in its own context. These tests
drive ADK's real ``InMemoryRunner`` with stand-in model, APDP and
lineage transport, with yields inside resolution, spawn and
authorization so the children interleave.
"""

from __future__ import annotations

import asyncio
import re
from typing import Any, Dict, List, Optional, Tuple

import pytest
from google.adk.agents import LlmAgent
from google.adk.models.llm_response import LlmResponse
from google.adk.runners import InMemoryRunner
from google.adk.tools.agent_tool import AgentTool
from google.genai import types

from watchlight_adk.plugin import WatchlightPlugin

from .test_root_run_terminal_events import _Apdp, fetch_url, search_web
from .test_subagent_time_budget import (
    APP_NAME,
    CHILD_NAME,
    CHILD_SLUG,
    CHILD_UUID,
    ROOT_NAME,
    ROOT_RUN_HANDLE,
    ROOT_SLUG,
    ROOT_UUID,
    _final,
    _RecordingScriptedLlm,
)
from .conftest import probed_args, run_for, stand_in_session, token_of

pytestmark = pytest.mark.usefixtures("probe_tool_args")

WRITER_NAME, WRITER_SLUG, WRITER_UUID = (
    "adk_writer",
    "agent-adk-writer",
    "00000000-0000-4000-8000-0000000000bb",
)
GRAND_NAME, GRAND_SLUG, GRAND_UUID = (
    "adk_fact_checker",
    "agent-adk-fact-checker",
    "00000000-0000-4000-8000-0000000000cc",
)
TERMINAL = ("execution_completed", "execution_failed")


def _call(name: str, args: Dict[str, Any]) -> LlmResponse:
    return LlmResponse(
        content=types.Content(
            role="model", parts=[types.Part.from_function_call(name=name, args=args)]
        )
    )


def _parallel_calls(*calls: Tuple[str, Dict[str, Any]]) -> LlmResponse:
    """ONE model response with several function calls: ADK runs them in
    parallel tasks."""
    return LlmResponse(
        content=types.Content(
            role="model",
            parts=[types.Part.from_function_call(name=n, args=a) for n, a in calls],
        )
    )


class _InterleavingApdp(_Apdp):
    """The stand-in, plus: the writer and the fact checker resolve; every
    resolution, spawn and authorization yields, so parallel agents
    interleave; each run gets its own root execution and ``sst_``; and
    each spawn records the credential of the handle it was made under."""

    def __init__(self) -> None:
        super().__init__()
        self._runs = 0
        self.spawns: List[Tuple[Optional[str], Dict[str, Any]]] = []
        self.child_run_handles: Dict[str, str] = {}
        resolve = self.resolve_agent.side_effect
        spawn = self.spawn_subagent.side_effect
        authorize = self.authorize.side_effect

        async def _resolve(slug: str) -> Optional[Dict[str, Any]]:
            await asyncio.sleep(0.003)
            extra = {WRITER_SLUG: WRITER_UUID, GRAND_SLUG: GRAND_UUID}
            if slug in extra:
                return {"id": extra[slug]}
            return await resolve(slug)

        async def _create_session(**_kwargs: Any) -> Dict[str, Any]:
            self._runs += 1
            n = self._runs
            await asyncio.sleep(0.003)
            return stand_in_session(
                f"ses_run{n}", f"sst_run{n}", execution_id=f"exec_run{n}", root_run_handle_id=ROOT_RUN_HANDLE
            )

        async def _spawn(parent: Any, body: Dict[str, Any]):
            session_token = token_of(parent)
            await asyncio.sleep(0.003)
            response = await spawn(parent, body)
            # Unique per spawn, and tied to the run the spawner belongs to.
            run = (session_token or "sst_run0").removeprefix("sst_").split("_c")[0]
            n = response["child_execution_id"].removeprefix("exec_child_")
            response.update(
                child_execution_id=f"exec_{run}_c{n}",
                root_execution_id=f"exec_{run}",
                child_session_id=f"ses_{run}_c{n}",
                child_run=run_for(f"sst_{run}_c{n}"),
            )
            self.spawns.append((session_token, body))
            self.child_run_handles[response["child_execution_id"]] = response[
                "child_run_handle_id"
            ]
            return response

        async def _authorize(**kwargs: Any) -> Dict[str, Any]:
            await asyncio.sleep(0.005)
            return await authorize(**kwargs)

        self.resolve_agent.side_effect = _resolve
        self.create_session.side_effect = _create_session
        self.spawn_subagent.side_effect = _spawn
        self.authorize.side_effect = _authorize


def _plugin(apdp: _InterleavingApdp) -> WatchlightPlugin:
    plugin = WatchlightPlugin(
        apdp_url="http://localhost:8081",
        tenant_id="t1",
        connect_proxy_url=None,
        log_decisions=False,
        agent_slug=ROOT_SLUG,
        root_agent_name=ROOT_NAME,
        subagent_slugs={
            CHILD_NAME: CHILD_SLUG,
            WRITER_NAME: WRITER_SLUG,
            GRAND_NAME: GRAND_SLUG,
        },
    )
    plugin.apdp = apdp  # type: ignore[assignment]
    plugin.lineage._apdp = apdp  # type: ignore[attr-defined]
    return plugin


def _model(label: str, turns: List[LlmResponse]) -> _RecordingScriptedLlm:
    return _RecordingScriptedLlm(model="scripted").script(label, [], turns)


def _parallel_tree(run: str) -> LlmAgent:
    """The root calls the researcher and the writer in ONE response (two
    parallel ``AgentTool`` calls); the writer runs longer. Then the root
    acts again as itself. Each agent names itself in its tool arguments."""
    researcher = LlmAgent(
        name=CHILD_NAME,
        model=_model("A", [_call("search_web", {"query": f"{run}:researcher"}), _final("A done")]),
        description="Researcher.",
        tools=[search_web],
    )
    writer = LlmAgent(
        name=WRITER_NAME,
        model=_model(
            "B",
            [_call("fetch_url", {"url": f"{run}:writer:{i}"}) for i in range(4)] + [_final("B done")],
        ),
        description="Writer.",
        tools=[fetch_url],
    )
    return LlmAgent(
        name=ROOT_NAME,
        model=_model(
            "R",
            [
                _parallel_calls((CHILD_NAME, {"request": "A"}), (WRITER_NAME, {"request": "B"})),
                _call("fetch_url", {"url": f"{run}:root"}),
                _final("done"),
            ],
        ),
        description="Orchestrator.",
        tools=[AgentTool(agent=researcher), AgentTool(agent=writer), fetch_url],
    )


def _three_level_tree() -> LlmAgent:
    """root -> AgentTool(researcher) -> AgentTool(fact checker); each
    level acts again after the level below returns."""
    checker = LlmAgent(
        name=GRAND_NAME,
        model=_model("G", [_call("search_web", {"query": "run1:fact_checker"}), _final("G done")]),
        description="Fact checker.",
        tools=[search_web],
    )
    researcher = LlmAgent(
        name=CHILD_NAME,
        model=_model(
            "A",
            [
                _call(GRAND_NAME, {"request": "check"}),
                _call("search_web", {"query": "run1:researcher"}),
                _final("A done"),
            ],
        ),
        description="Researcher.",
        tools=[AgentTool(agent=checker), search_web],
    )
    return LlmAgent(
        name=ROOT_NAME,
        model=_model(
            "R",
            [
                _call(CHILD_NAME, {"request": "research"}),
                _call("fetch_url", {"url": "run1:root"}),
                _final("done"),
            ],
        ),
        description="Orchestrator.",
        tools=[AgentTool(agent=researcher), fetch_url],
    )


async def _run(plugin: WatchlightPlugin, agent: LlmAgent, user: str) -> None:
    runner = InMemoryRunner(agent=agent, app_name=APP_NAME, plugins=[plugin])
    session = await runner.session_service.create_session(app_name=APP_NAME, user_id=user)
    message = types.Content(role="user", parts=[types.Part.from_text(text="go")])
    async for _ in runner.run_async(user_id=user, session_id=session.id, new_message=message):
        pass


AGENT_OF_MARKER = {
    "researcher": CHILD_UUID,
    "writer": WRITER_UUID,
    "fact_checker": GRAND_UUID,
    "root": ROOT_UUID,
}


def _assert_every_call_under_its_own_agent(apdp: _InterleavingApdp) -> Dict[str, Tuple[str, str]]:
    """Every authorize and every published event carries the identity
    of the agent that made it; each execution closes exactly once.
    Returns execution -> (agent, sst_)."""
    published = apdp.published()
    identity: Dict[str, Tuple[str, str]] = {}
    for event, token in published:
        if event["event_type"] == "execution_started":
            identity[event["execution_id"]] = (event["agent_id"], token)
    # Published: each event rides its own execution's credential and agent.
    for event, token in published:
        agent, sst = identity[event["execution_id"]]
        assert (event["agent_id"], token) == (agent, sst), event
    # Authorized: principal, credential and run handle are the execution's.
    for call in apdp.authorize.call_args_list:
        kwargs = call.kwargs
        execution_id = kwargs["execution_id"]
        assert execution_id in identity, kwargs
        agent, sst = identity[execution_id]
        assert kwargs["principal"] == f'Agent::"{agent}"', kwargs
        assert token_of(kwargs["run"]) == sst, kwargs
        run_handle = (kwargs.get("context") or {}).get("run_handle_id")
        assert run_handle == apdp.child_run_handles.get(execution_id), kwargs
        args = probed_args(kwargs.get("context"))
        for marker, marker_agent in AGENT_OF_MARKER.items():
            if f":{marker}" in args:
                assert agent == marker_agent, f"{args} authorized as {agent}"
    # Every run opened closes exactly once, under its own agent.
    for execution_id, (agent, sst) in identity.items():
        terminals = [
            (e["event_type"], e["agent_id"], t)
            for e, t in published
            if e["execution_id"] == execution_id and e["event_type"] in TERMINAL
        ]
        assert terminals == [("execution_completed", agent, sst)], (execution_id, terminals)
    return identity


def _assert_root_closes_last(apdp: _InterleavingApdp, root_execution: str) -> None:
    """The root's terminal event is published after every event of its
    run, children included: it never closes while a child still runs."""
    run_events = [
        (i, e) for i, (e, _) in enumerate(apdp.published())
        if e.get("root_execution_id", e["execution_id"]) == root_execution
        or e["execution_id"] == root_execution
    ]
    last_index, last = run_events[-1]
    assert (last["event_type"], last["execution_id"]) == ("execution_completed", root_execution)


@pytest.fixture(autouse=True)
def _budget(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(
        "WATCHLIGHT_DEFAULT_SUBAGENT_SCOPE", '{"time_budget_seconds": 300, "max_depth": 2}'
    )


@pytest.mark.asyncio
async def test_two_parallel_agent_tools_keep_their_own_identity():
    apdp = _InterleavingApdp()

    await _run(_plugin(apdp), _parallel_tree("run1"), "u")

    identity = _assert_every_call_under_its_own_agent(apdp)
    agents = sorted(agent for agent, _ in identity.values())
    assert agents == sorted([ROOT_UUID, CHILD_UUID, WRITER_UUID])
    # Both children were spawned under the ROOT's handle, never under
    # each other.
    assert [token for token, _ in apdp.spawns] == ["sst_run1", "sst_run1"]
    # Each child authorized its own tools; the root never acted for one.
    tool_calls = [
        (c.kwargs["principal"], probed_args(c.kwargs.get("context")))
        for c in apdp.authorize.call_args_list
        if c.kwargs["resource"].startswith("Tool::")
    ]
    assert any(p == f'Agent::"{WRITER_UUID}"' and "writer:3" in a for p, a in tool_calls)
    assert any(p == f'Agent::"{CHILD_UUID}"' and "researcher" in a for p, a in tool_calls)
    _assert_root_closes_last(apdp, "exec_run1")


@pytest.mark.asyncio
async def test_three_level_agent_tool_nesting():
    apdp = _InterleavingApdp()

    await _run(_plugin(apdp), _three_level_tree(), "u")

    identity = _assert_every_call_under_its_own_agent(apdp)
    by_agent = {agent: (execution, sst) for execution, (agent, sst) in identity.items()}
    assert set(by_agent) == {ROOT_UUID, CHILD_UUID, GRAND_UUID}
    # The fact checker was spawned under the RESEARCHER's handle.
    spawn_tokens = {body["child_agent_id"]: token for token, body in apdp.spawns}
    assert spawn_tokens[CHILD_UUID] == "sst_run1"
    assert spawn_tokens[GRAND_UUID] == by_agent[CHILD_UUID][1]
    started = {
        e["execution_id"]: e for e, _ in apdp.published() if e["event_type"] == "execution_started"
    }
    checker = started[by_agent[GRAND_UUID][0]]
    assert checker["parent_execution_id"] == by_agent[CHILD_UUID][0]
    assert checker["payload"]["depth"] == 2
    _assert_root_closes_last(apdp, "exec_run1")


@pytest.mark.asyncio
async def test_parallel_agent_tools_inside_concurrent_runs_on_one_plugin():
    """Three overlapping runs on ONE plugin, each with two parallel
    children: no identity crosses a run or a sibling."""
    apdp = _InterleavingApdp()
    plugin = _plugin(apdp)

    await asyncio.gather(
        *(_run(plugin, _parallel_tree(f"run{n}"), f"user-{n}") for n in range(3))
    )

    identity = _assert_every_call_under_its_own_agent(apdp)
    assert len(identity) == 9
    # Each tool call names its run: every call of one run was authorized
    # under that one run's credentials, and no two runs share them.
    run_of_label: Dict[str, str] = {}
    for call in apdp.authorize.call_args_list:
        args = probed_args(call.kwargs.get("context"))
        named = re.search(r"'(run\d+):", args)
        if named:
            run = token_of(call.kwargs["run"]).split("_c")[0]
            assert run_of_label.setdefault(named.group(1), run) == run, call.kwargs
    assert len(run_of_label) == 3 and len(set(run_of_label.values())) == 3
    for run_execution in {e for e in identity if "_c" not in e}:
        _assert_root_closes_last(apdp, run_execution)
