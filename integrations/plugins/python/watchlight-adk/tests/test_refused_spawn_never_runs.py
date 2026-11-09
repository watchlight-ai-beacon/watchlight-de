"""A sub-agent whose governed spawn is refused never runs.

Driven through ADK's real ``InMemoryRunner``: the orchestrator transfers
to a researcher whose spawn wl-apdp refuses (``scope_attenuation``). The
researcher must get no model turn, dispatch no tool call and run no tool
body, and no authorize may be sent for it — not under the parent's run
credential and not with none (on the live stack that request was the
``400 missing_run_credential`` the ungoverned-request gate refuses). The
refusal text reaches the conversation, and the refusal holds on the
next user turn, when ADK routes the conversation to the refused child.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

import pytest
from google.adk.agents import LlmAgent
from google.adk.runners import InMemoryRunner
from google.genai import types

from watchlight_core import ScopeAttenuationDenied
from watchlight_adk.plugin import WatchlightPlugin

from .test_subagent_time_budget import (
    APP_NAME,
    CHILD_NAME,
    CHILD_SLUG,
    CHILD_UUID,
    ROOT_NAME,
    ROOT_SLUG,
    USER_ID,
    _call,
    _DeadlineAwareApdp,
    _final,
    _RecordingScriptedLlm,
)
from .conftest import token_of

EXECUTED: List[str] = []


def search_web(query: str) -> dict:
    """Search the web."""
    EXECUTED.append("search_web")
    return {"results": [query]}


def transfer_funds(account: str, amount: float) -> dict:
    """Move money (a tool the orchestrator does not hold)."""
    EXECUTED.append("transfer_funds")
    return {"ok": True}


class _RefusingApdp(_DeadlineAwareApdp):
    """wl-apdp refuses the child's spawn at the strict-subset check."""

    def __init__(self) -> None:
        super().__init__()

        async def _refuse(parent: Any, body: Dict[str, Any]):
            session_token = token_of(parent)
            self.spawn_bodies.append(body)
            raise ScopeAttenuationDenied(reason="scope_attenuation_violation", violations=[])

        self.spawn_subagent.side_effect = _refuse


def _build(apdp: _RefusingApdp, turns: List[str]):
    """The orchestrator → researcher tree with a refused researcher spawn,
    one scripted model per agent (each logs its turns into ``turns``)."""
    child_model = _RecordingScriptedLlm(model="scripted").script(
        CHILD_NAME,
        turns,
        [
            _call("search_web", {"query": "FY revenue"}),
            _call("search_web", {"query": "FY revenue again"}),
            _final("done"),
        ],
    )
    researcher = LlmAgent(
        name=CHILD_NAME,
        model=child_model,
        description="Research sub-agent.",
        tools=[search_web, transfer_funds],
    )
    root_model = _RecordingScriptedLlm(model="scripted").script(
        ROOT_NAME,
        turns,
        [_call("transfer_to_agent", {"agent_name": CHILD_NAME}), _final("ok")],
    )
    orchestrator = LlmAgent(
        name=ROOT_NAME,
        model=root_model,
        description="Orchestrator.",
        tools=[search_web],
        sub_agents=[researcher],
    )
    return orchestrator


def _plugin(apdp: _RefusingApdp) -> WatchlightPlugin:
    plugin = WatchlightPlugin(
        apdp_url="http://localhost:8081",
        tenant_id="t1",
        connect_proxy_url=None,
        log_decisions=False,
        agent_slug=ROOT_SLUG,
        root_agent_name=ROOT_NAME,
        subagent_slugs={CHILD_NAME: CHILD_SLUG},
    )
    plugin.apdp = apdp  # type: ignore[assignment]
    plugin.lineage._apdp = apdp  # type: ignore[attr-defined]
    return plugin


async def _turn(runner: InMemoryRunner, session_id: str, text: str):
    """One user turn; returns the researcher's ``(texts, function calls)``."""
    message = types.Content(role="user", parts=[types.Part.from_text(text=text)])
    child_texts: List[str] = []
    child_calls: List[str] = []
    async for event in runner.run_async(
        user_id=USER_ID, session_id=session_id, new_message=message
    ):
        if event.author != CHILD_NAME or not event.content or not event.content.parts:
            continue
        for part in event.content.parts:
            if part.text:
                child_texts.append(part.text)
            if part.function_call is not None:
                child_calls.append(part.function_call.name or "")
    return child_texts, child_calls


def _assert_child_never_ran(apdp: _RefusingApdp, turns: List[str], child_calls: List[str]) -> None:
    # No model turn, no tool call, no body.
    assert CHILD_NAME not in turns
    assert child_calls == []
    assert EXECUTED == []
    # Nothing was authorized as the researcher — no credential-less chat.
    assert not any(CHILD_UUID in c["principal"] for c in apdp.authorize_calls)
    # And it never opened a governed session of its own.
    assert all(
        (call.kwargs.get("agent_id") or (call.args[0] if call.args else None)) != CHILD_UUID
        for call in apdp.create_session.call_args_list
    )


@pytest.mark.asyncio
async def test_refused_spawn_child_gets_no_model_turn_tool_call_or_authorize():
    EXECUTED.clear()
    apdp = _RefusingApdp()
    turns: List[str] = []
    plugin = _plugin(apdp)
    runner = InMemoryRunner(agent=_build(apdp, turns), app_name=APP_NAME, plugins=[plugin])
    session = await runner.session_service.create_session(app_name=APP_NAME, user_id=USER_ID)
    try:
        child_texts, child_calls = await _turn(runner, session.id, "Research it.")
    finally:
        await plugin.close()

    # The spawn was attempted and refused.
    assert len(apdp.spawn_bodies) == 1
    _assert_child_never_ran(apdp, turns, child_calls)
    # The instructive refusal is what the researcher "said", and it names
    # the rule that refused it.
    assert any(
        "was not started" in t and CHILD_NAME in t and "strict subset" in t
        for t in child_texts
    )
    # The refused researcher owns no frame.
    assert plugin._subagent_stack == []
    assert plugin._lineage_stack == []


@pytest.mark.asyncio
@pytest.mark.parametrize("fresh_plugin", [False, True], ids=["same-plugin", "restarted-plugin"])
async def test_refused_child_stays_refused_on_the_next_user_turn(fresh_plugin: bool):
    """The refusal event is authored by the researcher, so ADK routes the
    NEXT user message straight to it. It must not run then either — not as
    a root of its own under its full agent-record scope, and not by a
    second spawn. ``restarted-plugin`` drops the plugin's in-process
    record and keeps only the ADK session, as a process restart with a
    persistent session service would."""
    EXECUTED.clear()
    apdp = _RefusingApdp()
    turns: List[str] = []
    plugin = _plugin(apdp)
    runner = InMemoryRunner(agent=_build(apdp, turns), app_name=APP_NAME, plugins=[plugin])
    session = await runner.session_service.create_session(app_name=APP_NAME, user_id=USER_ID)
    try:
        await _turn(runner, session.id, "Research it.")
        if fresh_plugin:
            plugin._refused_subagents.clear()
        child_texts, child_calls = await _turn(runner, session.id, "Try again, please.")
    finally:
        await plugin.close()

    _assert_child_never_ran(apdp, turns, child_calls)
    # Turn 2 made no new spawn request for the refused child.
    assert len(apdp.spawn_bodies) == 1
    # ADK routes turn 2 to the researcher (the last author) on every
    # supported version; it surfaces a refusal instead of running.
    assert child_texts
    if child_texts:
        assert any("was not started" in t and CHILD_NAME in t for t in child_texts)


@pytest.mark.asyncio
async def test_a_subagent_never_opens_a_run_of_its_own():
    """A mapped sub-agent that opens an invocation as the run's root (a
    different entrypoint, or ADK routing a turn to it) is refused: its
    authority only ever comes from a governed spawn under its parent."""
    EXECUTED.clear()
    apdp = _RefusingApdp()
    turns: List[str] = []
    orchestrator = _build(apdp, turns)
    researcher = orchestrator.sub_agents[0]
    plugin = _plugin(apdp)
    runner = InMemoryRunner(agent=researcher, app_name=APP_NAME, plugins=[plugin])
    session = await runner.session_service.create_session(app_name=APP_NAME, user_id=USER_ID)
    try:
        child_texts, child_calls = await _turn(runner, session.id, "Research it.")
    finally:
        await plugin.close()

    _assert_child_never_ran(apdp, turns, child_calls)
    assert apdp.spawn_bodies == []
    apdp.resolve_agent.assert_not_called()
    assert any("cannot open a run of its own" in t for t in child_texts)
