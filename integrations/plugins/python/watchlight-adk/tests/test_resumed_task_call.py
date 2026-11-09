"""A session holding an unresolved task delegation never resumes the task
agent outside a governed run (ADK 2.5.0).

ADK 2.5.0's chat coordinator replays a task-delegation function call that
has no response yet (``_find_unresolved_task_delegations`` in
``workflow/_llm_agent_wrapper.py``) before its first model turn. That
dispatches the task agent directly. These tests seed a session with such
a call and run it (a) on a Runner whose plugin manager holds no Watchlight
plugin while a governed run is live, and (b) on a Runner with the
Watchlight plugin whose governed root never opened. The task agent never
takes a model turn, its tool never runs, and no run or spawn reaches
lineage.
"""

from __future__ import annotations

from typing import Any, List

import pytest
from google.adk import Runner
from google.adk.agents import LlmAgent
from google.adk.events import Event
from google.adk.plugins.base_plugin import BasePlugin
from google.adk.runners import InMemoryRunner
from google.genai import types

from watchlight_adk import run_backstop

from .test_nested_runner_refused import _plugin
from .test_subagent_time_budget import (
    APP_NAME,
    ROOT_NAME,
    USER_ID,
    _call,
    _DeadlineAwareApdp,
    _final,
    _RecordingScriptedLlm,
)

TASK = "task_agent"
CALL_ID = "fc-task-1"
EXECUTED: List[str] = []


def task_danger(target: str) -> dict:
    """A tool policy would deny."""
    EXECUTED.append("task_danger")
    return {"ok": True}


def _coordinator(root_turns: List[str], task_turns: List[str]) -> LlmAgent:
    task_model = _RecordingScriptedLlm(model="scripted").script(
        TASK, task_turns, [_call("task_danger", {"target": "x"}), _final("done")]
    )
    task = LlmAgent(name=TASK, model=task_model, description="Task.", mode="task", tools=[task_danger])
    root_model = _RecordingScriptedLlm(model="scripted").script(ROOT_NAME, root_turns, [_final("ok")])
    return LlmAgent(name=ROOT_NAME, model=root_model, description="Root.", sub_agents=[task])


async def _resume(runner: Any, run_async: Any = None) -> List[Any]:
    """Seed a session whose coordinator delegated to the task agent with no
    response yet, then send the next user message."""
    session = await runner.session_service.create_session(app_name=runner.app_name, user_id=USER_ID)
    pending = Event(
        invocation_id="inv-earlier",
        author=ROOT_NAME,
        content=types.Content(
            role="model",
            parts=[types.Part(function_call=types.FunctionCall(id=CALL_ID, name=TASK, args={"request": "do it"}))],
        ),
    )
    await runner.session_service.append_event(session, pending)
    message = types.Content(role="user", parts=[types.Part.from_text(text="go on")])
    run = run_async or runner.run_async
    return [event async for event in run(user_id=USER_ID, session_id=session.id, new_message=message)]


@pytest.fixture(autouse=True)
def _reset() -> None:
    run_backstop.install()
    EXECUTED.clear()


@pytest.mark.asyncio
async def test_ungoverned_the_pending_task_call_is_replayed() -> None:
    """The route is real: with nothing governed, ADK runs the task agent."""
    root_turns: List[str] = []
    task_turns: List[str] = []
    await _resume(InMemoryRunner(agent=_coordinator(root_turns, task_turns), app_name=APP_NAME))
    assert task_turns, "ADK replays the unresolved task call"
    assert EXECUTED == ["task_danger"]


class _OtherPlugin(BasePlugin):
    """A plugin manager that holds no Watchlight plugin."""

    def __init__(self) -> None:
        super().__init__(name="other")


def _lineage_types(apdp: _DeadlineAwareApdp) -> List[str]:
    found: List[str] = []
    for call in apdp.publish_events.call_args_list:
        _scope, events = call.args
        found.extend(str(event["event_type"]) for event in events)
    return found


@pytest.mark.asyncio
async def test_a_non_watchlight_plugin_manager_never_resumes_the_task_agent_while_a_run_is_live() -> None:
    root_turns: List[str] = []
    task_turns: List[str] = []
    runner = InMemoryRunner(agent=_coordinator(root_turns, task_turns), app_name=APP_NAME, plugins=[_OtherPlugin()])
    run_backstop._enter()  # a governed run is live elsewhere in the process
    try:
        await _resume(runner)
    finally:
        run_backstop._leave()
    assert task_turns == []
    assert root_turns == []
    assert EXECUTED == []


def _governed_task_plugin(apdp: _DeadlineAwareApdp) -> Any:
    """The Watchlight plugin with a governed identity for the task agent, so
    only the missing governed run can stop it."""
    plugin = _plugin(apdp)
    plugin.root_agent_name = TASK
    return plugin


@pytest.mark.asyncio
async def test_a_governed_resume_runs_the_task_agent_under_its_run() -> None:
    """The control for the test below: through the wrapped
    ``Runner.run_async`` the resumed task agent runs governed, and its run
    reaches lineage."""
    apdp = _DeadlineAwareApdp()
    plugin = _governed_task_plugin(apdp)
    task_turns: List[str] = []
    runner = InMemoryRunner(agent=_coordinator([], task_turns), app_name=APP_NAME, plugins=[plugin])
    try:
        await _resume(runner)
    finally:
        await plugin.close()
    assert task_turns
    assert EXECUTED == ["task_danger"]
    assert any("task_danger" in c["resource"] for c in apdp.authorize_calls)
    assert "execution_started" in _lineage_types(apdp)


@pytest.mark.asyncio
async def test_with_no_governed_root_opened_the_task_agent_never_resumes() -> None:
    """The run did not start through the wrapped ``Runner.run_async``, so
    the backstop does not count it and ``before_run_callback`` refuses it.
    ADK 2.5.0 ignores that refusal for an LlmAgent root and dispatches the
    pending task call; ``before_agent_callback`` refuses the root there."""
    apdp = _DeadlineAwareApdp()
    plugin = _governed_task_plugin(apdp)
    root_turns: List[str] = []
    task_turns: List[str] = []
    runner = InMemoryRunner(agent=_coordinator(root_turns, task_turns), app_name=APP_NAME, plugins=[plugin])
    unwrapped = Runner.run_async.__wrapped__  # type: ignore[attr-defined]
    try:
        assert not run_backstop.live()
        await _resume(runner, run_async=lambda **kw: unwrapped(runner, **kw))
    finally:
        await plugin.close()
    assert task_turns == []
    assert root_turns == []
    assert EXECUTED == []
    assert apdp.spawn_bodies == []
    assert apdp.authorize_calls == []
    lineage = _lineage_types(apdp)
    assert "execution_started" not in lineage
    assert "agent_spawn_observed" not in lineage


@pytest.mark.asyncio
async def test_another_live_governed_run_does_not_let_an_unwrapped_run_resume_the_task_agent() -> None:
    """The root check is per run: with another governed run live in the
    process (any busy server), a run that did not start through the
    wrapped ``Runner.run_async`` is still refused."""
    apdp = _DeadlineAwareApdp()
    plugin = _governed_task_plugin(apdp)
    root_turns: List[str] = []
    task_turns: List[str] = []
    runner = InMemoryRunner(agent=_coordinator(root_turns, task_turns), app_name=APP_NAME, plugins=[plugin])
    unwrapped = Runner.run_async.__wrapped__  # type: ignore[attr-defined]
    run_backstop._enter()  # another governed run, live elsewhere in the process
    try:
        assert run_backstop.live() and not run_backstop.in_governed_run()
        await _resume(runner, run_async=lambda **kw: unwrapped(runner, **kw))
    finally:
        run_backstop._leave()
        await plugin.close()
    assert task_turns == []
    assert root_turns == []
    assert EXECUTED == []
    assert apdp.authorize_calls == []
    assert "execution_started" not in _lineage_types(apdp)


@pytest.mark.asyncio
async def test_the_marker_does_not_leak_into_the_caller_between_events() -> None:
    """The per-run marker is set for each step of a governed run only: the
    code iterating the run does not see it between events."""
    apdp = _DeadlineAwareApdp()
    plugin = _governed_task_plugin(apdp)
    runner = InMemoryRunner(agent=_coordinator([], []), app_name=APP_NAME, plugins=[plugin])
    session = await runner.session_service.create_session(app_name=APP_NAME, user_id=USER_ID)
    message = types.Content(role="user", parts=[types.Part.from_text(text="go")])
    seen: List[bool] = []
    try:
        async for _event in runner.run_async(user_id=USER_ID, session_id=session.id, new_message=message):
            seen.append(run_backstop.in_governed_run())
    finally:
        await plugin.close()
    assert seen and not any(seen)
