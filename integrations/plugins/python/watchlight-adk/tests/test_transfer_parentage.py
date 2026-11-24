"""A sub-agent's parent is its ADK tree parent, never a frame it inherits
by accident.

ADK starts a ``transfer_to_agent`` target in a context copied from the
task that ran the transfer. Inside an ``AgentTool`` child that task is
the CALLER's tool task, so the target's context still holds the caller's
frame. Parenting the target to that frame spawned it under the caller's
credential and scope: the child's attenuation and ``max_depth`` were
bypassed. The parent is now read from ADK's agent tree
(``agent.parent_agent``) in the agent's own invocation.

The APDP stand-in models wl-apdp's spawn checks: a child's requested
tools must be a subset of its spawner's grant, and a spawner granted
``max_depth`` 0 may spawn nothing.
"""

from __future__ import annotations

import asyncio
import time
from types import SimpleNamespace
from typing import Any, AsyncGenerator, Dict, List, Optional, Tuple
from unittest.mock import AsyncMock, MagicMock

import pytest
from pydantic import BaseModel
from google.adk.agents import BaseAgent, LlmAgent, ParallelAgent, SequentialAgent
from google.adk.events import Event, EventActions
from google.adk.models.llm_response import LlmResponse
from google.adk.plugins.base_plugin import BasePlugin
from google.adk.runners import InMemoryRunner
from google.adk.tools.tool_context import ToolContext
from google.adk.tools.agent_tool import AgentTool
from google.genai import types

from watchlight_core import ScopeAttenuationDenied, ScopeViolationDimension
from .test_parallel_agent_tools import (
    GRAND_NAME,
    GRAND_UUID,
    WRITER_NAME,
    WRITER_UUID,
    _assert_every_call_under_its_own_agent,
    _call,
    _InterleavingApdp,
    _model,
    _parallel_calls,
    _plugin,
    _run,
)
from .test_root_run_terminal_events import fetch_url, search_web
from .test_subagent_time_budget import APP_NAME, CHILD_NAME, CHILD_UUID, ROOT_NAME, ROOT_UUID, _final
from .conftest import probed_args, run_for, token_of

pytestmark = pytest.mark.usefixtures("probe_tool_args")

EDITOR_NAME, EDITOR_SLUG, EDITOR_UUID = (
    "adk_editor",
    "agent-adk-editor",
    "00000000-0000-4000-8000-0000000000dd",
)


class _AttenuatingApdp(_InterleavingApdp):
    """Spawns are checked against the spawner's grant, as wl-apdp does."""

    def __init__(self) -> None:
        super().__init__()
        # sst_ of a spawned child -> its grant (allowed_tools, max_depth).
        self.grants: Dict[str, Dict[str, Any]] = {}
        self.refused: List[Dict[str, Any]] = []
        resolve = self.resolve_agent.side_effect
        spawn = self.spawn_subagent.side_effect

        async def _resolve(slug: str) -> Optional[Dict[str, Any]]:
            if slug == EDITOR_SLUG:
                return {"id": EDITOR_UUID}
            return await resolve(slug)

        async def _spawn(parent: Any, body: Dict[str, Any]):
            session_token = token_of(parent)
            requested = body.get("requested_scope") or {}
            grant = self.grants.get(session_token or "")
            if grant is not None:
                if int(grant.get("max_depth") or 0) < 1:
                    self.refused.append({"token": session_token, "body": body})
                    raise ScopeAttenuationDenied(
                        "scope_attenuation_violation",
                        [ScopeViolationDimension.MAX_DEPTH],
                        reason_code="DELEGATION_DEPTH_EXCEEDED",
                    )
                wider = set(requested.get("allowed_tools") or []) - set(grant["allowed_tools"])
                if wider:
                    self.refused.append({"token": session_token, "body": body})
                    raise ScopeAttenuationDenied(
                        "scope_attenuation_violation", [ScopeViolationDimension.ALLOWED_TOOLS]
                    )
            response = await spawn(parent, body)
            self.grants[token_of(response["child_run"])] = {
                "allowed_tools": list(requested.get("allowed_tools") or []),
                "max_depth": int(requested.get("max_depth") or 0),
            }
            return response

        self.resolve_agent.side_effect = _resolve
        self.spawn_subagent.side_effect = _spawn
        decide = self._decide

        def _decide_with_transfer(action: str, resource: str, run_handle_id: Optional[str]):
            # This deployment grants the children ADK's transfer tool, so
            # the transfer itself runs and its target's spawn is what is
            # under test. (Ungranted, the transfer is denied outright.)
            if resource == 'Tool::"transfer_to_agent"':
                return {"decision": "Allow", "reason": "", "details": {}}
            return decide(action, resource, run_handle_id)

        self._decide = _decide_with_transfer  # type: ignore[method-assign]


def _plugin_with_editor(apdp: _AttenuatingApdp):
    plugin = _plugin(apdp)
    plugin.subagent_slugs = {**plugin.subagent_slugs, EDITOR_NAME: EDITOR_SLUG}
    return plugin


def _transferring_child(name: str, tools: List[Any], target: LlmAgent) -> LlmAgent:
    """An AgentTool child that hands the conversation to ``target``."""
    return LlmAgent(
        name=name,
        model=_model(name, [_call("transfer_to_agent", {"agent_name": target.name})]),
        description=name,
        tools=tools,
        sub_agents=[target],
    )


def _fact_checker() -> LlmAgent:
    """Declares fetch_url, which the researcher (search_web only) does not
    hold."""
    return LlmAgent(
        name=GRAND_NAME,
        model=_model("G", [_call("fetch_url", {"url": "run1:fact_checker"}), _final("G done")]),
        description="Fact checker.",
        tools=[fetch_url],
    )


def _editor() -> LlmAgent:
    """Declares search_web, which the writer (fetch_url only) does not hold."""
    return LlmAgent(
        name=EDITOR_NAME,
        model=_model("E", [_call("search_web", {"query": "run1:editor"}), _final("E done")]),
        description="Editor.",
        tools=[search_web],
    )


def _started(apdp: _InterleavingApdp) -> Dict[str, Dict[str, Any]]:
    """agent id -> its execution_started event."""
    return {
        e["agent_id"]: e for e, _ in apdp.published() if e["event_type"] == "execution_started"
    }


def _tool_decisions(apdp: _InterleavingApdp, agent: str) -> List[str]:
    return [
        c.kwargs["resource"]
        for c in apdp.authorize.call_args_list
        if c.kwargs["principal"] == f'Agent::"{agent}"' and c.kwargs["resource"].startswith("Tool::")
    ]


def _spawn_token(apdp: _InterleavingApdp, child: str) -> Optional[str]:
    tokens = [t for t, body in apdp.spawns if body.get("child_agent_id") == child]
    tokens += [r["token"] for r in getattr(apdp, "refused", []) if r["body"].get("child_agent_id") == child]
    assert len(tokens) == 1, tokens
    return tokens[0]


def _scope(monkeypatch: pytest.MonkeyPatch, max_depth: int) -> None:
    monkeypatch.setenv(
        "WATCHLIGHT_DEFAULT_SUBAGENT_SCOPE",
        '{"time_budget_seconds": 300, "max_depth": %d}' % max_depth,
    )


@pytest.mark.asyncio
async def test_a_transfer_inside_an_agent_tool_child_is_spawned_under_that_child(monkeypatch):
    _scope(monkeypatch, 2)
    apdp = _AttenuatingApdp()
    researcher = _transferring_child(CHILD_NAME, [search_web], _fact_checker())
    root = LlmAgent(
        name=ROOT_NAME,
        model=_model("R", [_call(CHILD_NAME, {"request": "x"}), _final("done")]),
        description="Orchestrator.",
        tools=[AgentTool(agent=researcher)],
    )

    await _run(_plugin_with_editor(apdp), root, "u")

    _assert_every_call_under_its_own_agent(apdp)
    started = _started(apdp)
    researcher_sst = apdp.grants and next(
        t for t, g in apdp.grants.items() if g["allowed_tools"] == ["search_web"]
    )
    # Spawned with the researcher's credential, requesting only what the
    # researcher holds (nothing of fetch_url).
    assert _spawn_token(apdp, GRAND_UUID) == researcher_sst
    body = next(b for _, b in apdp.spawns if b.get("child_agent_id") == GRAND_UUID)
    assert body["requested_scope"]["allowed_tools"] == []
    checker = started[GRAND_UUID]
    assert checker["parent_execution_id"] == started[CHILD_UUID]["execution_id"]
    assert checker["payload"]["depth"] == 2
    # fetch_url is outside the researcher's grant: denied.
    denied = [
        c.kwargs for c in apdp.authorize.call_args_list
        if c.kwargs["principal"] == f'Agent::"{GRAND_UUID}"' and "fetch_url" in c.kwargs["resource"]
    ]
    assert denied
    assert all(
        apdp._decide(k["action"], k["resource"], k["context"].get("run_handle_id"))["decision"] == "Deny"
        for k in denied
    )


@pytest.mark.asyncio
async def test_parallel_agent_tool_siblings_that_each_transfer(monkeypatch):
    _scope(monkeypatch, 2)
    apdp = _AttenuatingApdp()
    researcher = _transferring_child(CHILD_NAME, [search_web], _fact_checker())
    writer = _transferring_child(WRITER_NAME, [fetch_url], _editor())
    root = LlmAgent(
        name=ROOT_NAME,
        model=_model(
            "R",
            [
                _parallel_calls((CHILD_NAME, {"request": "A"}), (WRITER_NAME, {"request": "B"})),
                _final("done"),
            ],
        ),
        description="Orchestrator.",
        tools=[AgentTool(agent=researcher), AgentTool(agent=writer)],
    )

    await _run(_plugin_with_editor(apdp), root, "u")

    _assert_every_call_under_its_own_agent(apdp)
    started = _started(apdp)
    sst_of = {e["agent_id"]: t for e, t in apdp.published() if e["event_type"] == "execution_started"}
    for child, grandchild in ((CHILD_UUID, GRAND_UUID), (WRITER_UUID, EDITOR_UUID)):
        assert _spawn_token(apdp, grandchild) == sst_of[child]
        assert started[grandchild]["parent_execution_id"] == started[child]["execution_id"]
        assert started[grandchild]["payload"]["depth"] == 2
        body = next(b for _, b in apdp.spawns if b.get("child_agent_id") == grandchild)
        assert body["requested_scope"]["allowed_tools"] == []
    for c in apdp.authorize.call_args_list:
        k = c.kwargs
        if k["principal"] in (f'Agent::"{GRAND_UUID}"', f'Agent::"{EDITOR_UUID}"') and k["resource"].startswith("Tool::"):
            assert apdp._decide(k["action"], k["resource"], k["context"].get("run_handle_id"))["decision"] == "Deny"


@pytest.mark.asyncio
async def test_a_child_with_max_depth_zero_cannot_transfer_to_a_grandchild(monkeypatch):
    _scope(monkeypatch, 0)
    apdp = _AttenuatingApdp()
    researcher = _transferring_child(CHILD_NAME, [search_web], _fact_checker())
    root = LlmAgent(
        name=ROOT_NAME,
        model=_model("R", [_call(CHILD_NAME, {"request": "x"}), _final("done")]),
        description="Orchestrator.",
        tools=[AgentTool(agent=researcher)],
    )

    await _run(_plugin_with_editor(apdp), root, "u")

    started = _started(apdp)
    # The spawn was asked of the researcher's handle, and refused there:
    # the fact checker never ran and nothing ran as the root.
    assert _spawn_token(apdp, GRAND_UUID) == next(
        t for e, t in apdp.published() if e["agent_id"] == CHILD_UUID
    )
    assert GRAND_UUID not in started
    assert _tool_decisions(apdp, GRAND_UUID) == []
    assert all(e["agent_id"] != GRAND_UUID for e, _ in apdp.published())
    assert not any("fetch_url" in r for r in _tool_decisions(apdp, ROOT_UUID))


@pytest.mark.asyncio
async def test_a_sequential_child_after_a_transfer_is_parented_to_the_sequence(monkeypatch):
    """A SequentialAgent runs its children in one context, so the next
    child inherits the previous child's (transferred-to) frame. Its
    parent is still its tree parent, the sequence."""
    _scope(monkeypatch, 2)
    apdp = _AttenuatingApdp()
    researcher = _transferring_child(CHILD_NAME, [search_web, fetch_url], _fact_checker())
    writer = LlmAgent(
        name=WRITER_NAME,
        model=_model("W", [_call("fetch_url", {"url": "run1:writer"}), _final("W done")]),
        description="Writer.",
        tools=[fetch_url],
    )
    root = SequentialAgent(name=ROOT_NAME, sub_agents=[researcher, writer])

    await _run(_plugin_with_editor(apdp), root, "u")

    _assert_every_call_under_its_own_agent(apdp)
    started = _started(apdp)
    root_execution = started[ROOT_UUID]["execution_id"]
    assert started[WRITER_UUID]["parent_execution_id"] == root_execution
    assert started[WRITER_UUID]["payload"]["depth"] == 1
    assert started[GRAND_UUID]["parent_execution_id"] == started[CHILD_UUID]["execution_id"]
    assert started[GRAND_UUID]["payload"]["depth"] == 2


@pytest.mark.asyncio
async def test_an_empty_parent_grant_requests_no_tools(monkeypatch):
    """A parent granted NO tools is not a parent of unknown scope: its
    child requests nothing, never its full declared list."""
    from watchlight_adk.plugin import _Frame, _RunState

    _scope(monkeypatch, 2)
    apdp = _AttenuatingApdp()
    plugin = _plugin_with_editor(apdp)
    spawner = MagicMock()
    spawner.granted_scope = SimpleNamespace(allowed_tools=[])
    spawner.spawn_subagent = AsyncMock(return_value=MagicMock(run=run_for("sst_x")))
    state = _RunState()
    state._root_handle = MagicMock()
    state.default_subagent_scope = {"max_depth": 1}
    root = _Frame(state=state, parent=None, invocation_id="inv")
    parent = _Frame(state=state, parent=root, invocation_id="inv")
    parent.child_handle = spawner
    child = LlmAgent(name=GRAND_NAME, model=_model("G", []), tools=[fetch_url, search_web])

    await plugin._request_governed_spawn(child, child_uuid=GRAND_UUID, state=state, parent=parent)

    kwargs = spawner.spawn_subagent.await_args.kwargs
    assert kwargs["allowed_tools"] == []


# ─── Authority never widens through a transfer ────────────────
#
# A transfer to a peer, to an ancestor or back to the root agent spawns
# the target under the TRANSFERRING agent, narrowed to its grant; it
# never gets the target's tree parent's breadth or an existing frame's
# credential.


def _decided(apdp: _InterleavingApdp, kwargs: Dict[str, Any]) -> str:
    return apdp._decide(
        kwargs["action"], kwargs["resource"], (kwargs.get("context") or {}).get("run_handle_id")
    )["decision"]


def _starts(apdp: _InterleavingApdp) -> List[Tuple[Dict[str, Any], Optional[str]]]:
    return [(e, t) for e, t in apdp.published() if e["event_type"] == "execution_started"]


def _peer_tree() -> LlmAgent:
    """root (sub-agents researcher, writer) transfers to the researcher
    (search_web only), which transfers to its PEER, the writer (declares
    fetch_url and search_web)."""
    writer = LlmAgent(
        name=WRITER_NAME,
        model=_model(
            "W",
            [
                _call("fetch_url", {"url": "run1:writer"}),
                _call("search_web", {"query": "run1:writer"}),
                _final("W done"),
            ],
        ),
        description="Writer.",
        tools=[fetch_url, search_web],
    )
    researcher = LlmAgent(
        name=CHILD_NAME,
        model=_model("A", [_call("transfer_to_agent", {"agent_name": WRITER_NAME})]),
        description="Researcher.",
        tools=[search_web],
    )
    return LlmAgent(
        name=ROOT_NAME,
        model=_model("R", [_call("transfer_to_agent", {"agent_name": CHILD_NAME})]),
        description="Orchestrator.",
        tools=[fetch_url, search_web],
        sub_agents=[researcher, writer],
    )


@pytest.mark.asyncio
async def test_a_peer_transfer_from_a_narrowed_child_stays_narrowed(monkeypatch):
    _scope(monkeypatch, 2)
    apdp = _AttenuatingApdp()

    await _run(_plugin_with_editor(apdp), _peer_tree(), "u")

    _assert_every_call_under_its_own_agent(apdp)
    started = _started(apdp)
    sst_of = {e["agent_id"]: t for e, t in _starts(apdp)}
    # Spawned under the RESEARCHER (the transferor), not the root.
    assert _spawn_token(apdp, WRITER_UUID) == sst_of[CHILD_UUID]
    body = next(b for _, b in apdp.spawns if b.get("child_agent_id") == WRITER_UUID)
    assert body["requested_scope"]["allowed_tools"] == ["search_web"]
    assert started[WRITER_UUID]["parent_execution_id"] == started[CHILD_UUID]["execution_id"]
    assert started[WRITER_UUID]["payload"]["depth"] == 2
    decisions = {
        k["resource"]: _decided(apdp, k)
        for k in (c.kwargs for c in apdp.authorize.call_args_list)
        if k["principal"] == f'Agent::"{WRITER_UUID}"' and k["resource"].startswith("Tool::")
    }
    assert decisions == {'Tool::"fetch_url"': "Deny", 'Tool::"search_web"': "Allow"}


def _upward_tree() -> LlmAgent:
    """root -> researcher (search_web) -> fact checker (declares fetch_url,
    so granted nothing); the fact checker transfers back UP to the
    researcher, which then transfers back to the ROOT agent."""
    checker = LlmAgent(
        name=GRAND_NAME,
        model=_model("G", [_call("transfer_to_agent", {"agent_name": CHILD_NAME})]),
        description="Fact checker.",
        tools=[fetch_url],
    )
    researcher = LlmAgent(
        name=CHILD_NAME,
        model=_model(
            "A",
            [
                _call("transfer_to_agent", {"agent_name": GRAND_NAME}),
                # Re-entered under the fact checker:
                _call("search_web", {"query": "run1:researcher"}),
                _call("transfer_to_agent", {"agent_name": ROOT_NAME}),
            ],
        ),
        description="Researcher.",
        tools=[search_web],
        sub_agents=[checker],
    )
    return LlmAgent(
        name=ROOT_NAME,
        model=_model(
            "R",
            [
                _call("transfer_to_agent", {"agent_name": CHILD_NAME}),
                # Re-entered under the researcher's second run:
                _call("fetch_url", {"url": "run1:root"}),
                _final("done"),
            ],
        ),
        description="Orchestrator.",
        tools=[fetch_url, search_web],
        sub_agents=[researcher],
    )


@pytest.mark.asyncio
async def test_upward_transfers_to_the_parent_and_the_root_are_narrowed(monkeypatch):
    _scope(monkeypatch, 5)
    apdp = _AttenuatingApdp()

    await _run(_plugin_with_editor(apdp), _upward_tree(), "u")

    _assert_every_call_under_its_own_agent(apdp)
    starts = _starts(apdp)
    researcher_runs = [(e, t) for e, t in starts if e["agent_id"] == CHILD_UUID]
    root_runs = [(e, t) for e, t in starts if e["agent_id"] == ROOT_UUID]
    checker = next(e for e, _ in starts if e["agent_id"] == GRAND_UUID)
    checker_sst = next(t for e, t in starts if e["agent_id"] == GRAND_UUID)
    assert len(researcher_runs) == 2 and len(root_runs) == 2
    # The researcher re-entered: a NEW execution spawned under the fact
    # checker, narrowed to its (empty) grant; never its first frame's
    # credential.
    (first_a, first_a_sst), (second_a, second_a_sst) = researcher_runs
    assert second_a["execution_id"] != first_a["execution_id"]
    assert second_a_sst != first_a_sst
    assert second_a["parent_execution_id"] == checker["execution_id"]
    assert second_a["payload"]["depth"] == 3
    reentries = [(t, b) for t, b in apdp.spawns if b.get("child_agent_id") == CHILD_UUID]
    assert reentries[1][0] == checker_sst
    assert reentries[1][1]["requested_scope"]["allowed_tools"] == []
    # The root re-entered the same way, under the researcher's second
    # run: a new execution and credential, not the run's root.
    (root, root_sst), (root_again, root_again_sst) = root_runs
    assert root_again_sst != root_sst and root_again["execution_id"] != root["execution_id"]
    assert root_again["parent_execution_id"] == second_a["execution_id"]
    root_spawn = next((t, b) for t, b in apdp.spawns if b.get("child_agent_id") == ROOT_UUID)
    assert root_spawn[0] == second_a_sst
    assert root_spawn[1]["requested_scope"]["allowed_tools"] == []
    # Every tool call after the fact checker was denied: nothing widened.
    narrowed = (second_a["execution_id"], root_again["execution_id"])
    for k in (c.kwargs for c in apdp.authorize.call_args_list):
        if (
            k["execution_id"] in narrowed
            and k["resource"].startswith("Tool::")
            and "transfer_to_agent" not in k["resource"]
        ):
            assert _decided(apdp, k) == "Deny", k


@pytest.mark.asyncio
async def test_the_transferors_max_depth_bounds_a_peer_transfer(monkeypatch):
    _scope(monkeypatch, 0)
    apdp = _AttenuatingApdp()

    await _run(_plugin_with_editor(apdp), _peer_tree(), "u")

    sst_of = {e["agent_id"]: t for e, t in _starts(apdp)}
    # Asked of the researcher's handle and refused there: the writer
    # never ran, under any credential.
    assert _spawn_token(apdp, WRITER_UUID) == sst_of[CHILD_UUID]
    assert WRITER_UUID not in sst_of
    assert _tool_decisions(apdp, WRITER_UUID) == []


def test_the_root_slug_is_handed_to_a_nested_start_only_for_a_governed_reentry():
    from watchlight_adk.agent_slugs import configured_slug

    kwargs = {
        "agent_slug": "agent-root",
        "root_agent_name": ROOT_NAME,
        "subagent_slugs": {CHILD_NAME: "agent-child"},
    }
    assert configured_slug(ROOT_NAME, is_root=False, **kwargs) is None
    assert configured_slug(ROOT_NAME, is_root=False, governed_reentry=True, **kwargs) == "agent-root"
    assert configured_slug("other", is_root=False, governed_reentry=True, **kwargs) is None


# ─── A transfer is what ADK will run, observed from any tool ──
#
# ADK transfers whenever a tool sets ``actions.transfer_to_agent``, not
# only through its built-in ``transfer_to_agent`` tool. Several transfer
# calls in one response run in parallel and ADK keeps the last. So the
# plugin records the targets a turn asked for (from the tool context,
# after each tool), refuses a turn that named more than one, and never
# lets an LlmAgent's sub-agent start without an observed transfer.

PIPE_NAME, PIPE_SLUG, PIPE_UUID = (
    "adk_pipeline",
    "agent-adk-pipeline",
    "00000000-0000-4000-8000-0000000000ee",
)


def handoff(target: str, tool_context: ToolContext) -> dict:
    """Hand the conversation to another agent (a custom transfer tool)."""
    tool_context.actions.transfer_to_agent = target
    return {"handed_off_to": target}


class _HandoffApdp(_AttenuatingApdp):
    """Also resolves the pipeline, grants the custom ``handoff`` tool like
    ``transfer_to_agent``, and authorizes a transfer to the editor slowly
    (it finishes after a parallel transfer to the writer)."""

    def __init__(self) -> None:
        super().__init__()
        resolve = self.resolve_agent.side_effect
        decide = self._decide
        authorize = self.authorize.side_effect

        async def _resolve(slug: str) -> Optional[Dict[str, Any]]:
            if slug == PIPE_SLUG:
                return {"id": PIPE_UUID}
            return await resolve(slug)

        def _decide_handoff(action: str, resource: str, run_handle_id: Optional[str]):
            if resource == 'Tool::"handoff"':
                return {"decision": "Allow", "reason": "", "details": {}}
            return decide(action, resource, run_handle_id)

        async def _authorize(**kwargs: Any) -> Dict[str, Any]:
            if EDITOR_NAME in str(probed_args(kwargs.get("context"))):
                await asyncio.sleep(0.03)
            return await authorize(**kwargs)

        self.resolve_agent.side_effect = _resolve
        self._decide = _decide_handoff  # type: ignore[method-assign]
        self.authorize.side_effect = _authorize


def _handoff_plugin(apdp: _HandoffApdp):
    plugin = _plugin_with_editor(apdp)
    plugin.subagent_slugs = {**plugin.subagent_slugs, PIPE_NAME: PIPE_SLUG}
    return plugin


def _writer() -> LlmAgent:
    return LlmAgent(
        name=WRITER_NAME,
        model=_model(
            "W",
            [
                _call("fetch_url", {"url": "run1:writer"}),
                _call("search_web", {"query": "run1:writer"}),
                _final("W done"),
            ],
        ),
        description="Writer.",
        tools=[fetch_url, search_web],
    )


def _editor_tree(researcher_turns: List[LlmResponse]) -> SequentialAgent:
    """Sequential root -> editor (fetch_url, search_web), which transfers
    to the researcher (search_web, handoff); the researcher's turns are
    the scenario. The writer (fetch_url, search_web) is the researcher's
    peer under the editor."""
    researcher = LlmAgent(
        name=CHILD_NAME,
        model=_model("A", researcher_turns),
        description="Researcher.",
        tools=[search_web, handoff],
    )
    editor = LlmAgent(
        name=EDITOR_NAME,
        model=_model("E", [_call("transfer_to_agent", {"agent_name": CHILD_NAME})]),
        description="Editor.",
        tools=[fetch_url, search_web],
        sub_agents=[researcher, _writer()],
    )
    return SequentialAgent(name=ROOT_NAME, sub_agents=[editor])


def _writer_allowed(apdp: _InterleavingApdp) -> List[str]:
    return [
        k["resource"]
        for k in (c.kwargs for c in apdp.authorize.call_args_list)
        if k["principal"] == f'Agent::"{WRITER_UUID}"'
        and k["resource"].startswith("Tool::")
        and _decided(apdp, k) == "Allow"
    ]


@pytest.mark.asyncio
async def test_a_custom_handoff_tool_is_a_transfer_and_stays_narrowed(monkeypatch):
    """(a) ``handoff`` sets ``actions.transfer_to_agent``: the writer is
    spawned under the RESEARCHER, never under its tree parent (the
    editor, which holds fetch_url)."""
    _scope(monkeypatch, 3)
    apdp = _HandoffApdp()

    await _run(
        _handoff_plugin(apdp),
        _editor_tree([_call("handoff", {"target": WRITER_NAME})]),
        "u",
    )

    _assert_every_call_under_its_own_agent(apdp)
    sst_of = {e["agent_id"]: t for e, t in _starts(apdp)}
    started = _started(apdp)
    assert _spawn_token(apdp, WRITER_UUID) == sst_of[CHILD_UUID]
    body = next(b for _, b in apdp.spawns if b.get("child_agent_id") == WRITER_UUID)
    assert body["requested_scope"]["allowed_tools"] == ["search_web"]
    assert started[WRITER_UUID]["parent_execution_id"] == started[CHILD_UUID]["execution_id"]
    assert _writer_allowed(apdp) == ['Tool::"search_web"']


@pytest.mark.asyncio
async def test_two_transfers_in_one_turn_are_refused(monkeypatch):
    """(b) One response with transfer(editor) and transfer(writer): ADK
    runs the last, the editor's authorization finishes last. A turn that
    named two targets is ambiguous: the target is refused, and the writer
    never runs under the editor."""
    _scope(monkeypatch, 3)
    apdp = _HandoffApdp()

    await _run(
        _handoff_plugin(apdp),
        _editor_tree(
            [
                _parallel_calls(
                    ("transfer_to_agent", {"agent_name": EDITOR_NAME}),
                    ("transfer_to_agent", {"agent_name": WRITER_NAME}),
                )
            ]
        ),
        "u",
    )

    started = _started(apdp)
    assert WRITER_UUID not in started
    assert not [b for _, b in apdp.spawns if b.get("child_agent_id") == WRITER_UUID]
    assert _writer_allowed(apdp) == []
    # Only the one editor run (the root's child) ever started.
    assert [e for e, _ in _starts(apdp) if e["agent_id"] == EDITOR_UUID].__len__() == 1


@pytest.mark.asyncio
async def test_a_turn_naming_a_sequence_and_its_member_is_refused(monkeypatch):
    """(c) The editor asks for the writer AND the pipeline (a sequence
    containing the writer). ADK runs the pipeline; the turn named two
    targets, so it is refused, and no stale entry can later bind the
    writer to the editor's breadth."""
    _scope(monkeypatch, 3)
    apdp = _HandoffApdp()
    pipeline = SequentialAgent(name=PIPE_NAME, sub_agents=[_writer()])
    editor = LlmAgent(
        name=EDITOR_NAME,
        model=_model(
            "E",
            [
                _parallel_calls(
                    ("transfer_to_agent", {"agent_name": WRITER_NAME}),
                    ("transfer_to_agent", {"agent_name": PIPE_NAME}),
                )
            ],
        ),
        description="Editor.",
        tools=[fetch_url, search_web],
        sub_agents=[pipeline],
    )

    await _run(_handoff_plugin(apdp), SequentialAgent(name=ROOT_NAME, sub_agents=[editor]), "u")

    started = _started(apdp)
    assert PIPE_UUID not in started and WRITER_UUID not in started
    assert _writer_allowed(apdp) == []


@pytest.mark.asyncio
async def test_a_transfer_redirected_by_the_agents_callback_is_narrowed(monkeypatch):
    """The tool asked for the writer; the agent's own after-tool callback
    (which runs after the plugin's) changed the transfer to the pipeline.
    ADK acts on the pipeline, and the plugin takes the transfer from the
    event ADK acted on: the pipeline is spawned under the EDITOR, narrowed
    to its grant, and the writer inside it under the pipeline."""
    _scope(monkeypatch, 3)
    apdp = _HandoffApdp()
    pipeline = SequentialAgent(name=PIPE_NAME, sub_agents=[_writer()])

    def _redirect(tool: Any, args: Any, tool_context: Any, tool_response: Any) -> None:
        tool_context.actions.transfer_to_agent = PIPE_NAME
        return None

    editor = LlmAgent(
        name=EDITOR_NAME,
        model=_model("E", [_call("handoff", {"target": WRITER_NAME})]),
        description="Editor.",
        tools=[search_web, handoff],
        sub_agents=[pipeline],
        after_tool_callback=_redirect,
    )

    await _run(_handoff_plugin(apdp), SequentialAgent(name=ROOT_NAME, sub_agents=[editor]), "u")

    _assert_every_call_under_its_own_agent(apdp)
    started = _started(apdp)
    sst_of = {e["agent_id"]: t for e, t in _starts(apdp)}
    assert started[PIPE_UUID]["parent_execution_id"] == started[EDITOR_UUID]["execution_id"]
    assert _spawn_token(apdp, PIPE_UUID) == sst_of[EDITOR_UUID]
    # The editor holds no fetch_url, so nothing under it ever gets it.
    assert 'Tool::"fetch_url"' not in _writer_allowed(apdp)


@pytest.mark.asyncio
async def test_a_workflow_started_by_a_transfer_from_an_llm_root(monkeypatch):
    """An LlmAgent root (ADK 2.x runs a clone of it) transfers to a
    pipeline; the pipeline's members start under the pipeline (the
    workflow rule), narrowed to the pipeline's grant."""
    _scope(monkeypatch, 3)
    apdp = _HandoffApdp()
    pipeline = SequentialAgent(name=PIPE_NAME, sub_agents=[_writer()])
    root = LlmAgent(
        name=ROOT_NAME,
        model=_model("R", [_call("transfer_to_agent", {"agent_name": PIPE_NAME})]),
        description="Orchestrator.",
        tools=[fetch_url, search_web],
        sub_agents=[pipeline],
    )

    await _run(_handoff_plugin(apdp), root, "u")

    _assert_every_call_under_its_own_agent(apdp)
    started = _started(apdp)
    sst_of = {e["agent_id"]: t for e, t in _starts(apdp)}
    assert started[PIPE_UUID]["parent_execution_id"] == started[ROOT_UUID]["execution_id"]
    assert started[WRITER_UUID]["parent_execution_id"] == started[PIPE_UUID]["execution_id"]
    assert _spawn_token(apdp, WRITER_UUID) == sst_of[PIPE_UUID]


# ─── A transfer to a WORKFLOW child is still a transfer ───────
#
# The editor is a child of a SequentialAgent (a workflow parent). When a
# narrow agent transfers back to it, by any route the plugin's own tool
# hook may not see, ADK's event says so; the editor is re-entered under
# the narrow agent, never under the sequence with its own breadth.


def _workflow_child_tree(researcher_turns: List[LlmResponse], **researcher_kwargs: Any) -> SequentialAgent:
    """Sequential root -> editor (fetch_url, search_web), which transfers
    to the researcher (search_web, handoff). The researcher's turns send
    the conversation back to the editor; the editor's second run asks for
    fetch_url."""
    researcher = LlmAgent(
        name=CHILD_NAME,
        model=_model("A", researcher_turns),
        description="Researcher.",
        tools=[search_web, handoff],
        **researcher_kwargs,
    )
    editor = LlmAgent(
        name=EDITOR_NAME,
        model=_model(
            "E",
            [
                _call("transfer_to_agent", {"agent_name": CHILD_NAME}),
                # Re-entered:
                _call("fetch_url", {"url": "run1:editor"}),
                _final("E done"),
            ],
        ),
        description="Editor.",
        tools=[fetch_url, search_web],
        sub_agents=[researcher],
    )
    return SequentialAgent(name=ROOT_NAME, sub_agents=[editor])


def _assert_editor_reentry_narrowed(apdp: _HandoffApdp) -> None:
    starts = _starts(apdp)
    editors = [(e, t) for e, t in starts if e["agent_id"] == EDITOR_UUID]
    researcher = next(e for e, _ in starts if e["agent_id"] == CHILD_UUID)
    researcher_sst = next(t for e, t in starts if e["agent_id"] == CHILD_UUID)
    root_sst = next(t for e, t in starts if e["agent_id"] == ROOT_UUID)
    # Re-entered (or refused) — never spawned under the sequence again.
    editor_spawn_tokens = [t for t, b in apdp.spawns if b.get("child_agent_id") == EDITOR_UUID]
    assert editor_spawn_tokens.count(root_sst) == 1, editor_spawn_tokens
    if len(editors) == 2:
        reentry, _ = editors[1]
        assert reentry["parent_execution_id"] == researcher["execution_id"]
        assert editor_spawn_tokens[1] == researcher_sst
        body = [b for t, b in apdp.spawns if b.get("child_agent_id") == EDITOR_UUID][1]
        assert "fetch_url" not in body["requested_scope"]["allowed_tools"]
    # The editor's re-entry never gets fetch_url, by any route.
    for k in (c.kwargs for c in apdp.authorize.call_args_list):
        if "run1:editor" in str(probed_args(k.get("context"))):
            assert _decided(apdp, k) == "Deny", k


@pytest.mark.asyncio
async def test_a_callback_redirect_to_a_workflow_child_is_narrowed(monkeypatch):
    """The researcher's own after-tool callback sends the conversation
    back to the editor (ADK runs agent callbacks after plugin ones)."""
    _scope(monkeypatch, 4)
    apdp = _HandoffApdp()

    def _back_to_editor(tool: Any, args: Any, tool_context: Any, tool_response: Any) -> None:
        tool_context.actions.transfer_to_agent = EDITOR_NAME
        return None

    tree = _workflow_child_tree(
        [_call("search_web", {"query": "run1:researcher"}), _final("A done")],
        after_tool_callback=_back_to_editor,
    )
    await _run(_handoff_plugin(apdp), tree, "u")

    _assert_every_call_under_its_own_agent(apdp)
    _assert_editor_reentry_narrowed(apdp)


class _ShortCircuitPlugin(BasePlugin):
    """Another plugin listed BEFORE Watchlight that answers the tool and
    event hooks itself, so ADK skips Watchlight's for them."""

    def __init__(self) -> None:
        super().__init__(name="first_plugin")

    async def after_tool_callback(self, *, tool, tool_args, tool_context, result):
        return result if isinstance(result, dict) else {"result": result}

    async def on_event_callback(self, *, invocation_context, event):
        return event


@pytest.mark.asyncio
async def test_a_handoff_hidden_by_another_plugin_is_narrowed(monkeypatch):
    """Neither Watchlight's tool hook nor its event hook sees the handoff;
    the session's latest event still records the transfer ADK acted on."""
    _scope(monkeypatch, 4)
    apdp = _HandoffApdp()
    plugin = _handoff_plugin(apdp)
    tree = _workflow_child_tree([_call("handoff", {"target": EDITOR_NAME})])

    runner = InMemoryRunner(agent=tree, app_name=APP_NAME, plugins=[_ShortCircuitPlugin(), plugin])
    session = await runner.session_service.create_session(app_name=APP_NAME, user_id="u")
    message = types.Content(role="user", parts=[types.Part.from_text(text="go")])
    async for _ in runner.run_async(user_id="u", session_id=session.id, new_message=message):
        pass

    _assert_editor_reentry_narrowed(apdp)


@pytest.mark.asyncio
async def test_an_upward_transfer_to_a_workflow_child_is_narrowed(monkeypatch):
    """The narrow researcher transfers back up to the editor with the
    built-in tool."""
    _scope(monkeypatch, 4)
    apdp = _HandoffApdp()
    tree = _workflow_child_tree([_call("transfer_to_agent", {"agent_name": EDITOR_NAME})])

    await _run(_handoff_plugin(apdp), tree, "u")

    _assert_every_call_under_its_own_agent(apdp)
    _assert_editor_reentry_narrowed(apdp)


# ─── The context an agent starts in governs its parent ────────


class _Summary(BaseModel):
    text: str


@pytest.mark.asyncio
async def test_a_hidden_transfer_ending_in_a_structured_answer_stays_narrowed(monkeypatch):
    """ADK 2.5: an agent with an output schema emits handoff(editor) and
    set_model_response in ONE turn. ADK yields the transfer, then a final
    event without it, then starts the editor, so the session's latest
    event no longer shows the transfer; another plugin hides both the
    tool and the event hook. The editor starts inside the researcher's
    context: it is
    re-entered under the researcher, or refused; never under the
    sequence, never with fetch_url; the root closes last."""
    _scope(monkeypatch, 4)
    apdp = _HandoffApdp()
    decide = apdp._decide

    def _decide_structured(action: str, resource: str, run_handle_id: Optional[str]):
        if resource == 'Tool::"set_model_response"':
            return {"decision": "Allow", "reason": "", "details": {}}
        return decide(action, resource, run_handle_id)

    apdp._decide = _decide_structured  # type: ignore[method-assign]
    plugin = _handoff_plugin(apdp)
    tree = _workflow_child_tree(
        [
            _parallel_calls(
                ("handoff", {"target": EDITOR_NAME}),
                ("set_model_response", {"text": "summary"}),
            )
        ],
        output_schema=_Summary,
    )

    runner = InMemoryRunner(agent=tree, app_name=APP_NAME, plugins=[_ShortCircuitPlugin(), plugin])
    session = await runner.session_service.create_session(app_name=APP_NAME, user_id="u")
    message = types.Content(role="user", parts=[types.Part.from_text(text="go")])
    async for _ in runner.run_async(user_id="u", session_id=session.id, new_message=message):
        pass

    _assert_editor_reentry_narrowed(apdp)
    published = apdp.published()
    root_execution = next(e["execution_id"] for e, _ in _starts(apdp) if e["agent_id"] == ROOT_UUID)
    last_terminal = [e for e, _ in published if e["event_type"] in ("execution_completed", "execution_failed")][-1]
    assert last_terminal["execution_id"] == root_execution


def _frame(state: Any, name: str, invocation: str, parent: Any = None) -> Any:
    from watchlight_adk.plugin import _Frame

    frame = _Frame(state=state, parent=parent, invocation_id=invocation)
    frame._current_agent_name = name
    frame._current_agent_id = f"id-{name}"
    frame._current_execution_id = f"exec-{name}"
    state.frames_by_invocation.setdefault(invocation, []).append(frame)
    return frame


def _admission(plugin: Any, state: Any, context_frame: Any, agent: Any, invocation: str):
    """Run ``_admit_agent`` for ``agent`` in a context holding ``state``
    and ``context_frame``, isolated from the test's own context."""
    import contextvars

    def _go():
        plugin._run_var.set(state)
        plugin._frame_var.set(context_frame)
        return plugin._admit_agent(agent, SimpleNamespace(invocation_id=invocation))

    return contextvars.copy_context().run(_go)


def _run_state(invocation: str) -> Any:
    from watchlight_adk.plugin import _RunState

    state = _RunState()
    state.invocations.add(invocation)
    state.open_invocations.add(invocation)
    return state


def test_a_transfer_record_naming_another_author_than_the_context_is_refused():
    """The agent starts inside the researcher's context, but the transfer
    record says the WRITER asked for it: refused, never guessed."""
    plugin = _plugin_with_editor(_AttenuatingApdp())
    state = _run_state("inv")
    root = _frame(state, ROOT_NAME, "inv")
    researcher = _frame(state, CHILD_NAME, "inv", parent=root)
    _frame(state, WRITER_NAME, "inv", parent=root)
    state.transfer_events[("inv", None)] = (WRITER_NAME, EDITOR_NAME, None, time.time() + 1, None)
    editor = LlmAgent(name=EDITOR_NAME, model=_model("E", []), tools=[fetch_url])

    _, parent, admitted, _ = _admission(plugin, state, researcher, editor, "inv")

    assert (parent, admitted) == (None, False)


def test_a_stale_transfer_record_binds_nothing():
    """A record whose event is older than the last start here is stale:
    it no longer starts anything."""
    plugin = _plugin_with_editor(_AttenuatingApdp())
    state = _run_state("inv")
    root = _frame(state, ROOT_NAME, "inv")
    researcher = _frame(state, CHILD_NAME, "inv", parent=root)
    now = time.time()
    state.last_start[("inv", None)] = now
    state.transfer_events[("inv", None)] = (CHILD_NAME, EDITOR_NAME, None, now - 10, None)
    editor = LlmAgent(name=EDITOR_NAME, model=_model("E", []), tools=[fetch_url])

    _, parent, admitted, _ = _admission(plugin, state, None, editor, "inv")
    assert (parent, admitted) == (None, False)

    # A fresh record for the same transfer is honoured, under the researcher.
    state.transfer_events[("inv", None)] = (CHILD_NAME, EDITOR_NAME, None, time.time() + 1, None)
    _, parent, admitted, via_transfer = _admission(plugin, state, None, editor, "inv")
    assert (parent, admitted, via_transfer) == (researcher, True, True)


@pytest.mark.asyncio
async def test_a_root_agent_rerun_mid_invocation_is_refused():
    """ADK starting the root agent again inside a live run, with no frame
    in its context and no transfer record (ADK 2.10's workflow re-run
    after a root re-entry), is refused: it never reopens the run's root
    session or credential."""
    apdp = _AttenuatingApdp()
    plugin = _plugin_with_editor(apdp)
    state = _run_state("inv")
    _frame(state, ROOT_NAME, "inv")
    root_agent = LlmAgent(name=ROOT_NAME, model=_model("R", []), tools=[fetch_url])

    _, parent, admitted, _ = _admission(plugin, state, None, root_agent, "inv")

    assert (parent, admitted) == (None, False)
    apdp.create_session.assert_not_called()


@pytest.mark.asyncio
async def test_genuine_workflow_children_start_under_their_workflow(monkeypatch):
    """A ParallelAgent and a SequentialAgent start their own children:
    each child is parented to its workflow, unaffected by the transfer
    rules."""
    _scope(monkeypatch, 3)
    apdp = _HandoffApdp()
    first = LlmAgent(
        name=CHILD_NAME,
        model=_model("A", [_call("search_web", {"query": "run1:researcher"}), _final("A")]),
        tools=[search_web],
    )
    second = _writer()
    pipeline = SequentialAgent(
        name=PIPE_NAME,
        sub_agents=[
            LlmAgent(
                name=EDITOR_NAME,
                model=_model("E", [_call("search_web", {"query": "run1:editor"}), _final("E")]),
                tools=[search_web],
            )
        ],
    )
    root = ParallelAgent(name=ROOT_NAME, sub_agents=[first, second, pipeline])

    await _run(_handoff_plugin(apdp), root, "u")

    _assert_every_call_under_its_own_agent(apdp)
    started = _started(apdp)
    root_execution = started[ROOT_UUID]["execution_id"]
    for child in (CHILD_UUID, WRITER_UUID, PIPE_UUID):
        assert started[child]["parent_execution_id"] == root_execution
    assert started[EDITOR_UUID]["parent_execution_id"] == started[PIPE_UUID]["execution_id"]


# ─── Record freshness does not depend on any clock ────────────


@pytest.mark.asyncio
@pytest.mark.parametrize("skew_seconds", [-5.0, 5.0])
async def test_transfers_hold_with_adks_clock_skewed(monkeypatch, skew_seconds):
    """ADK stamps events with its own replaceable clock. With that clock
    5 s behind or ahead of wall time, transfers are still recognised
    (records are ordered by their place in the session) and still
    narrowed."""
    from google.adk.platform import time as platform_time

    _scope(monkeypatch, 4)
    platform_time.set_time_provider(lambda: time.time() + skew_seconds)
    try:
        # An LlmAgent root's transfer targets start with no frame in their
        # context: they are admitted on the transfer record alone.
        apdp = _AttenuatingApdp()
        await _run(_plugin_with_editor(apdp), _peer_tree(), "u")
        sst_of = {e["agent_id"]: t for e, t in _starts(apdp)}
        assert _spawn_token(apdp, WRITER_UUID) == sst_of[CHILD_UUID]

        # Upward transfers, re-entering the researcher and the root.
        apdp = _AttenuatingApdp()
        await _run(_plugin_with_editor(apdp), _upward_tree(), "u")
        assert len([e for e, _ in _starts(apdp) if e["agent_id"] == ROOT_UUID]) == 2

        # A handoff hidden from both Watchlight hooks (session record only).
        apdp = _HandoffApdp()
        runner = InMemoryRunner(
            agent=_workflow_child_tree([_call("handoff", {"target": EDITOR_NAME})]),
            app_name=APP_NAME,
            plugins=[_ShortCircuitPlugin(), _handoff_plugin(apdp)],
        )
        session = await runner.session_service.create_session(app_name=APP_NAME, user_id="u")
        message = types.Content(role="user", parts=[types.Part.from_text(text="go")])
        async for _ in runner.run_async(user_id="u", session_id=session.id, new_message=message):
            pass
        _assert_editor_reentry_narrowed(apdp)
        assert len([e for e, _ in _starts(apdp) if e["agent_id"] == EDITOR_UUID]) == 2
    finally:
        platform_time.reset_time_provider()


# ─── A transfer record ADK did not act on ─────────────────────


class _Announcer(BaseAgent):
    """A custom workflow step that emits an event carrying
    ``actions.transfer_to_agent``. ADK does not transfer from it: the
    sequence goes on to its next child."""

    async def _run_async_impl(self, ctx: Any) -> AsyncGenerator[Event, None]:
        yield Event(
            author=self.name,
            invocation_id=ctx.invocation_id,
            branch=ctx.branch,
            actions=EventActions(transfer_to_agent=WRITER_NAME),
            content=types.Content(role="model", parts=[types.Part.from_text(text="next: writer")]),
        )


@pytest.mark.asyncio
async def test_an_ignored_transfer_record_does_not_refuse_the_next_workflow_child(monkeypatch):
    """The record names the writer but its author is the custom step, not
    the frame the writer starts in (the sequence). It is ignored, and the
    writer, a genuine child of the sequence, starts under it. A record by
    another author still refuses an agent that is NOT the context's
    workflow child (see the other-author test above)."""
    _scope(monkeypatch, 3)
    apdp = _HandoffApdp()
    root = SequentialAgent(name=ROOT_NAME, sub_agents=[_Announcer(name=PIPE_NAME), _writer()])

    await _run(_handoff_plugin(apdp), root, "u")

    _assert_every_call_under_its_own_agent(apdp)
    started = _started(apdp)
    assert started[WRITER_UUID]["parent_execution_id"] == started[ROOT_UUID]["execution_id"]
    sst_of = {e["agent_id"]: t for e, t in _starts(apdp)}
    assert _spawn_token(apdp, WRITER_UUID) == sst_of[ROOT_UUID]
