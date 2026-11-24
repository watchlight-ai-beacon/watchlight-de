"""Every ROOT run records its terminal lineage event.

Driven through ADK's real ``InMemoryRunner`` with the real plugin. The
ROOT run's ``execution_completed`` (or ``execution_failed``) must be
emitted under the ROOT agent, bound to the root run's own ``sst_``
credential, and PUBLISHED by the time the runner returns: the demo
workload can exit without ever calling ``plugin.close()``, so a terminal
event that only reaches ``/v1/events`` on close is a missing one.

On ADK 2.x a ``transfer_to_agent`` ends the orchestrator's agent run
without its ``after_agent_callback``, which is where the plugin used to
emit the root's completion; every root run that delegated to a sub-agent
(and every root whose spawn was refused) had no terminal event at all.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

import pytest
from google.adk.agents import LlmAgent
from google.adk.runners import InMemoryRunner
from google.genai import types

from watchlight_core import ScopeAttenuationDenied
from watchlight_adk.plugin import WatchlightPlugin

from .conftest import run_for, token_of
from .test_subagent_time_budget import (
    APP_NAME,
    CHILD_NAME,
    CHILD_SLUG,
    CHILD_UUID,
    ROOT_NAME,
    ROOT_SLUG,
    ROOT_UUID,
    USER_ID,
    _call,
    _DeadlineAwareApdp,
    _final,
    _RecordingScriptedLlm,
)

TERMINAL = ("execution_completed", "execution_failed")
ROOT_EXECUTION = "exec_root"
ROOT_TOKEN = "sst_root"


def search_web(query: str) -> dict:
    """Search the web."""
    return {"result": f"results for {query}"}


def fetch_url(url: str) -> dict:
    """Fetch a URL."""
    return {"result": f"body of {url}"}


def transfer_funds(account: str, amount: float) -> dict:
    """Move money."""
    return {"ok": True}


class _ToolBroke(RuntimeError):
    pass


def broken_tool(query: str) -> dict:
    """A tool whose body raises."""
    raise _ToolBroke("backend unavailable")


class _Apdp(_DeadlineAwareApdp):
    """The deadline-aware stand-in, plus: ``transfer_funds`` is denied,
    and the researcher's spawn can be refused."""

    def __init__(self, *, refuse_spawn: bool = False) -> None:
        super().__init__()
        decide = self._decide

        def _decide(action: str, resource: str, run_handle_id: Optional[str]) -> Dict[str, Any]:
            if "transfer_funds" in resource:
                return {"decision": "Deny", "reason": "forbid", "details": {}}
            return decide(action, resource, run_handle_id)

        self._decide = _decide  # type: ignore[method-assign]
        if refuse_spawn:

            async def _refuse(parent: Any, body: Dict[str, Any]):
                self.spawn_bodies.append(body)
                raise ScopeAttenuationDenied(
                    reason="scope_attenuation_violation", violations=[]
                )

            self.spawn_subagent.side_effect = _refuse

    def published(self) -> List[Tuple[Dict[str, Any], Optional[str]]]:
        """Every published event with the credential it rode."""
        out: List[Tuple[Dict[str, Any], Optional[str]]] = []
        for call in self.publish_events.call_args_list:
            run = call.args[0] if call.args else call.kwargs.get("run")
            events = call.args[1] if len(call.args) > 1 else call.kwargs.get("events", [])
            token = token_of(run)
            out.extend((event, token) for event in events)
        return out


def _plugin(apdp: _Apdp) -> WatchlightPlugin:
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


def _tree(root_turns, child_turns=None, root_tools=None) -> LlmAgent:
    log: List[str] = []
    sub_agents = []
    if child_turns is not None:
        sub_agents.append(
            LlmAgent(
                name=CHILD_NAME,
                model=_RecordingScriptedLlm(model="scripted").script(
                    CHILD_NAME, log, child_turns
                ),
                description="Research sub-agent.",
                tools=[search_web],
            )
        )
    return LlmAgent(
        name=ROOT_NAME,
        model=_RecordingScriptedLlm(model="scripted").script(ROOT_NAME, log, root_turns),
        description="Orchestrator.",
        tools=root_tools or [search_web, fetch_url, transfer_funds],
        sub_agents=sub_agents,
    )


async def _run(apdp: _Apdp, agent: LlmAgent) -> Optional[BaseException]:
    """One user turn through the real runner. ``plugin.close()`` is NOT
    called: whatever the assertions see was published by the run itself."""
    plugin = _plugin(apdp)
    runner = InMemoryRunner(agent=agent, app_name=APP_NAME, plugins=[plugin])
    session = await runner.session_service.create_session(app_name=APP_NAME, user_id=USER_ID)
    message = types.Content(role="user", parts=[types.Part.from_text(text="Research the FY revenue.")])
    try:
        async for _ in runner.run_async(
            user_id=USER_ID, session_id=session.id, new_message=message
        ):
            pass
    except Exception as exc:  # noqa: BLE001 — the error path is under test
        return exc
    return None


def _terminals(apdp: _Apdp, execution_id: str) -> List[Tuple[Dict[str, Any], Optional[str]]]:
    return [
        (event, token)
        for event, token in apdp.published()
        if event.get("execution_id") == execution_id and event.get("event_type") in TERMINAL
    ]


def _assert_root_terminal(apdp: _Apdp, event_type: str) -> Dict[str, Any]:
    terminals = _terminals(apdp, ROOT_EXECUTION)
    assert len(terminals) == 1, f"root run needs exactly one terminal event, got {terminals}"
    event, token = terminals[0]
    assert event["event_type"] == event_type
    # Under the ROOT agent and the root run's own credential.
    assert event["agent_id"] == ROOT_UUID
    assert token == ROOT_TOKEN
    assert event.get("root_execution_id") == ROOT_EXECUTION
    _assert_every_run_closes_under_its_own_agent(apdp)
    return event


def _assert_every_run_closes_under_its_own_agent(apdp: _Apdp) -> None:
    """The lineage structure rule, applied to everything the run published: every execution
    that published an ``execution_started`` has exactly one terminal
    event of its OWN, under the agent that started it and on the
    credential that started it. A completion from another agent (an
    ancestor's, or wl-proxy's on the root credential) does not end a
    run, so it would not count here either."""
    published = apdp.published()
    starts = {
        event["execution_id"]: (event["agent_id"], token)
        for event, token in published
        if event.get("event_type") == "execution_started"
    }
    assert ROOT_EXECUTION in starts
    for execution_id, (agent_id, token) in starts.items():
        terminals = _terminals(apdp, execution_id)
        assert [(e["agent_id"], t) for e, t in terminals] == [(agent_id, token)], (
            f"{execution_id} must close exactly once under its own agent "
            f"{agent_id} and credential {token}, got {terminals}"
        )
    # No terminal event for an execution that never started.
    for event, _ in published:
        if event.get("event_type") in TERMINAL:
            assert event["execution_id"] in starts, event


@pytest.fixture(autouse=True)
def _live_child_budget(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(
        "WATCHLIGHT_DEFAULT_SUBAGENT_SCOPE", '{"time_budget_seconds": 300, "max_depth": 0}'
    )


@pytest.mark.asyncio
async def test_a_root_run_that_transfers_to_a_sub_agent_records_its_completion():
    apdp = _Apdp()
    agent = _tree(
        [_call("fetch_url", {"url": "https://example.test/"}),
         _call("transfer_to_agent", {"agent_name": CHILD_NAME})],
        [_call("search_web", {"query": "FY revenue"}), _final("Summary.")],
    )

    assert await _run(apdp, agent) is None

    _assert_root_terminal(apdp, "execution_completed")
    # The child still closes under its own agent and its own credential.
    child = _terminals(apdp, "exec_child_1")
    assert [(e["event_type"], e["agent_id"], t) for e, t in child] == [
        ("execution_completed", CHILD_UUID, "sst_child_1")
    ]
    # The ROOT session is closed server-side too.
    closed = [c.args[0] for c in apdp.complete_session.call_args_list]
    assert run_for(ROOT_TOKEN) in closed
    # Only the run itself may close it: the root's own credential.
    apdp.complete_session.assert_any_await(run_for(ROOT_TOKEN))


@pytest.mark.asyncio
async def test_a_root_run_whose_spawn_is_refused_records_its_completion():
    apdp = _Apdp(refuse_spawn=True)
    agent = _tree(
        [_call("transfer_to_agent", {"agent_name": CHILD_NAME}), _final("ok")],
        [_call("search_web", {"query": "FY revenue"}), _final("Summary.")],
    )

    assert await _run(apdp, agent) is None

    _assert_root_terminal(apdp, "execution_completed")
    # The refused child never ran: nothing was published under it.
    assert [e for e, _ in apdp.published() if e.get("agent_id") == CHILD_UUID] == []


@pytest.mark.asyncio
async def test_a_root_run_with_a_denied_tool_records_its_completion():
    apdp = _Apdp()
    agent = _tree([_call("transfer_funds", {"account": "a", "amount": 1.0}), _final("done")])

    assert await _run(apdp, agent) is None

    event = _assert_root_terminal(apdp, "execution_completed")
    assert event["payload"]["actions_denied"] >= 1


@pytest.mark.asyncio
async def test_a_root_run_that_errors_records_its_failure():
    apdp = _Apdp()
    agent = _tree([_call("broken_tool", {"query": "x"}), _final("done")], root_tools=[broken_tool])

    error = await _run(apdp, agent)

    assert isinstance(error, _ToolBroke)
    event = _assert_root_terminal(apdp, "execution_failed")
    assert event["payload"]["error"]


@pytest.mark.asyncio
async def test_the_run_level_close_does_not_duplicate_a_closed_root():
    """``after_agent_callback`` closed the root: ``after_run_callback`` is
    a no-op, so the root still has exactly one terminal event."""
    apdp = _Apdp()
    agent = _tree([_call("search_web", {"query": "x"}), _final("done")])

    assert await _run(apdp, agent) is None

    _assert_root_terminal(apdp, "execution_completed")
    assert [c.args[0] for c in apdp.complete_session.call_args_list].count(run_for(ROOT_TOKEN)) == 1


# ─── AgentTool: a NESTED runner shares the plugin ──────


def _authorize_kwargs(apdp: _Apdp) -> List[Dict[str, Any]]:
    return [call.kwargs for call in apdp.authorize.call_args_list]


def _agent_tool_tree(child_tools=None) -> LlmAgent:
    """The root calls the researcher through ``AgentTool`` (a nested
    ``Runner`` that shares the plugin), then acts AGAIN as itself: a
    tool call and a final model turn after the child has returned."""
    from google.adk.tools.agent_tool import AgentTool

    log: List[str] = []
    child = LlmAgent(
        name=CHILD_NAME,
        model=_RecordingScriptedLlm(model="scripted").script(
            CHILD_NAME, log, [_call("search_web", {"query": "FY revenue"}), _final("Summary.")]
        ),
        description="Research sub-agent.",
        tools=child_tools or [search_web],
    )
    return LlmAgent(
        name=ROOT_NAME,
        model=_RecordingScriptedLlm(model="scripted").script(
            ROOT_NAME,
            log,
            [
                _call(CHILD_NAME, {"request": "Research the FY revenue."}),
                _call("fetch_url", {"url": "https://example.test/"}),
                _final("done"),
            ],
        ),
        description="Orchestrator.",
        tools=[AgentTool(agent=child), fetch_url],
    )


def _assert_never_blank(apdp: _Apdp) -> None:
    """No call ever reaches wl-apdp without an identity, an execution
    and a run credential."""
    for kwargs in _authorize_kwargs(apdp):
        assert kwargs["principal"] not in ('Agent::""', "Agent::\"\""), kwargs
        assert kwargs.get("execution_id"), kwargs
        assert token_of(kwargs.get("run")), kwargs


@pytest.mark.asyncio
async def test_an_agent_tool_child_does_not_close_the_calling_root():
    """The nested runner's ``after_run_callback`` closes only the frames
    ITS invocation opened. The root keeps its identity, execution and
    credential for every call after the child returns, and closes once,
    at the end of its own run."""
    apdp = _Apdp()

    assert await _run(apdp, _agent_tool_tree()) is None

    _assert_never_blank(apdp)
    root_calls = [k for k in _authorize_kwargs(apdp) if k["principal"] == f'Agent::"{ROOT_UUID}"']
    # chat x3 (call child, call fetch_url, final) + fetch_url.
    assert any(k["resource"] == 'Tool::"fetch_url"' for k in root_calls)
    for kwargs in root_calls:
        assert kwargs["execution_id"] == ROOT_EXECUTION
        assert token_of(kwargs["run"]) == ROOT_TOKEN
    # The root's terminal event is the LAST thing published for the root:
    # after its post-child tool call, never right after the child.
    root_events = [e["event_type"] for e, _ in apdp.published() if e.get("execution_id") == ROOT_EXECUTION]
    assert root_events[-1] == "execution_completed"
    assert root_events.count("execution_completed") == 1
    assert "tool_call_observed" in root_events[root_events.index("execution_started"):-1]
    _assert_root_terminal(apdp, "execution_completed")
    child = _terminals(apdp, "exec_child_1")
    assert [(e["event_type"], e["agent_id"], t) for e, t in child] == [
        ("execution_completed", CHILD_UUID, "sst_child_1")
    ]


@pytest.mark.asyncio
async def test_a_failing_agent_tool_child_fails_only_itself_when_the_root_recovers():
    """The nested runner's ``on_run_error_callback`` closes the child as
    failed and never the calling root. The root's own error callback
    recovers the tool call, so the root goes on and completes."""
    apdp = _Apdp()
    agent = _agent_tool_tree(child_tools=[broken_tool])
    # The child's model calls broken_tool instead of search_web.
    agent.tools[0].agent.model.script(
        CHILD_NAME, [], [_call("broken_tool", {"query": "x"}), _final("never")]
    )

    def _recover(tool: Any, args: Any, tool_context: Any, error: Exception) -> dict:
        return {"result": "the researcher is unavailable"}

    agent.on_tool_error_callback = _recover

    assert await _run(apdp, agent) is None

    _assert_never_blank(apdp)
    child = _terminals(apdp, "exec_child_1")
    assert [(e["event_type"], e["agent_id"], t) for e, t in child] == [
        ("execution_failed", CHILD_UUID, "sst_child_1")
    ]
    _assert_root_terminal(apdp, "execution_completed")


# ─── A recovered error is not a failure (one terminal event) ───


@pytest.mark.asyncio
async def test_a_tool_error_the_agent_recovers_records_one_completion():
    """An agent-level ``on_tool_error_callback`` turns the error into a
    result and the run goes on: the root records ONE terminal event,
    ``execution_completed``, and no ``execution_failed``."""
    apdp = _Apdp()
    agent = _tree([_call("broken_tool", {"query": "x"}), _final("done")], root_tools=[broken_tool])

    def _recover(tool: Any, args: Any, tool_context: Any, error: Exception) -> dict:
        return {"result": "backend unavailable, continuing"}

    agent.on_tool_error_callback = _recover

    assert await _run(apdp, agent) is None

    _assert_root_terminal(apdp, "execution_completed")


@pytest.mark.asyncio
async def test_an_unrecovered_tool_error_names_the_tool_hook():
    apdp = _Apdp()
    agent = _tree([_call("broken_tool", {"query": "x"}), _final("done")], root_tools=[broken_tool])

    assert isinstance(await _run(apdp, agent), _ToolBroke)

    event = _assert_root_terminal(apdp, "execution_failed")
    assert event["metadata"]["hook"] == "on_tool_error_callback"


# ─── Fail closed outside a run ────────────────────────────────────────


@pytest.mark.asyncio
async def test_a_call_outside_any_run_is_refused_without_authorizing():
    """With no open frame the plugin refuses locally; it never sends
    wl-apdp a call with a blank principal, execution or credential."""
    apdp = _Apdp()
    plugin = _plugin(apdp)

    class _Tool:
        name = "search_web"

    tool_result = await plugin.before_tool_callback(tool=_Tool(), tool_args={"query": "x"})
    model_result = await plugin.before_model_callback(callback_context=None, llm_request=None)

    assert "ACTION BLOCKED" in tool_result["result"]
    assert model_result is not None and model_result.turn_complete
    apdp.authorize.assert_not_called()
    apdp.publish_events.assert_not_called()


# ─── A close never emits twice ────────────────────────────────────────


@pytest.mark.asyncio
async def test_a_close_that_fails_after_the_completion_emits_no_failure():
    """``after_run_callback`` buffered the root's completion, then the
    session close raised. ``on_run_error_callback`` that follows finds
    the frame gone: one terminal event, the completion."""
    apdp = _Apdp()
    agent = _tree(
        [_call("fetch_url", {"url": "https://example.test/"}),
         _call("transfer_to_agent", {"agent_name": CHILD_NAME})],
        [_call("search_web", {"query": "FY revenue"}), _final("Summary.")],
    )

    async def _close_fails(run: Any) -> bool:
        if run == run_for(ROOT_TOKEN):
            raise RuntimeError("session store down")
        return True

    apdp.complete_session.side_effect = _close_fails

    error = await _run(apdp, agent)

    assert isinstance(error, RuntimeError)
    _assert_root_terminal(apdp, "execution_completed")


@pytest.mark.asyncio
async def test_a_lost_publish_is_counted_and_warned(caplog: pytest.LogCaptureFixture):
    apdp = _Apdp()
    apdp.publish_events.return_value = False
    plugin = _plugin(apdp)
    await plugin.lineage.emit_execution_completed(
        ROOT_EXECUTION, ROOT_UUID, duration_ms=1, actions_taken=0, actions_denied=0,
        root_execution_id=ROOT_EXECUTION, parent_execution_id=None, tenant_id="t1",
        run=run_for(ROOT_TOKEN),
    )

    with caplog.at_level("WARNING"):
        assert await plugin.lineage.flush() == 0

    assert plugin.lineage.lost_event_count == 1
    assert "execution_completed" in caplog.text
