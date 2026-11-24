"""Concurrent runs on ONE plugin instance keep their own identity.

ADK's API server caches one Runner per app, so every concurrent session
goes through one ``WatchlightPlugin``. Per-run state used to live on the
instance: two runs that overlapped (one awaiting its identity while the
other opened) both opened as roots, the second overwrote the first, and
the first run's model turns and tool calls were authorized and
published under the second run's execution and ``sst_`` credential.
The first run never recorded a terminal event.

Driven through ADK's real ``InMemoryRunner``s sharing one plugin, with
``asyncio.gather`` and a yield inside identity resolution and session
creation so the runs interleave.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import Any, Dict, List, Optional, Tuple

import pytest
from google.adk.agents import LlmAgent
from google.adk.runners import InMemoryRunner
from google.adk.tools.agent_tool import AgentTool
from google.genai import types

from watchlight_adk.plugin import _RUN_STATE_ATTRS, WatchlightPlugin

from .test_root_run_terminal_events import _Apdp, _plugin, fetch_url, search_web
from .test_subagent_time_budget import (
    APP_NAME,
    CHILD_NAME,
    CHILD_UUID,
    ROOT_NAME,
    ROOT_RUN_HANDLE,
    ROOT_UUID,
    _call,
    _final,
    _RecordingScriptedLlm,
)

TERMINAL = ("execution_completed", "execution_failed")
from .conftest import probed_args, run_for, stand_in_session, token_of

pytestmark = pytest.mark.usefixtures("probe_tool_args")


class _ConcurrentApdp(_Apdp):
    """The stand-in, minting a distinct execution and ``sst_`` per run
    (``exec_runN`` / ``sst_runN``, a child ``exec_runN_child`` /
    ``sst_runN_child``), and yielding inside identity resolution and
    session creation so overlapping runs interleave."""

    def __init__(self) -> None:
        super().__init__()
        self._runs = 0
        resolve = self.resolve_agent.side_effect
        spawn = self.spawn_subagent.side_effect

        async def _slow_resolve(slug: str) -> Optional[Dict[str, Any]]:
            await asyncio.sleep(0.01)
            return await resolve(slug)

        async def _create_session(**_kwargs: Any) -> Dict[str, Any]:
            self._runs += 1
            n = self._runs
            await asyncio.sleep(0.01)
            return stand_in_session(
                f"ses_run{n}", f"sst_run{n}", execution_id=f"exec_run{n}", root_run_handle_id=ROOT_RUN_HANDLE
            )

        async def _spawn(parent: Any, body: Dict[str, Any]):
            session_token = token_of(parent)
            run = (session_token or "").removeprefix("sst_")
            response = await spawn(parent, body)
            response.update(
                child_execution_id=f"exec_{run}_child",
                root_execution_id=f"exec_{run}",
                child_session_id=f"ses_{run}_child",
                child_run=run_for(f"sst_{run}_child"),
            )
            return response

        self.resolve_agent.side_effect = _slow_resolve
        self.create_session.side_effect = _create_session
        self.spawn_subagent.side_effect = _spawn


def _tree(run: int, *, with_agent_tool: bool) -> LlmAgent:
    """Run ``run``'s root: two ``fetch_url`` calls naming the run (so a
    tool authorization can be traced back to the run that made it),
    optionally a call to the researcher through ``AgentTool`` first."""
    log: List[str] = []
    turns = [
        _call("fetch_url", {"url": f"https://run{run}.test/a"}),
        _call("fetch_url", {"url": f"https://run{run}.test/b"}),
        _final("done"),
    ]
    tools: List[Any] = [fetch_url]
    if with_agent_tool:
        child = LlmAgent(
            name=CHILD_NAME,
            model=_RecordingScriptedLlm(model="scripted").script(
                CHILD_NAME, log, [_call("search_web", {"query": f"run{run}"}), _final("S")]
            ),
            description="Research sub-agent.",
            tools=[search_web],
        )
        turns.insert(0, _call(CHILD_NAME, {"request": f"run{run}"}))
        tools.insert(0, AgentTool(agent=child))
    return LlmAgent(
        name=ROOT_NAME,
        model=_RecordingScriptedLlm(model="scripted").script(ROOT_NAME, log, turns),
        description="Orchestrator.",
        tools=tools,
    )


async def _run_one(plugin: WatchlightPlugin, run: int, *, with_agent_tool: bool) -> None:
    runner = InMemoryRunner(
        agent=_tree(run, with_agent_tool=with_agent_tool), app_name=APP_NAME, plugins=[plugin]
    )
    user = f"user-{run}"
    session = await runner.session_service.create_session(app_name=APP_NAME, user_id=user)
    message = types.Content(role="user", parts=[types.Part.from_text(text="go")])
    async for _ in runner.run_async(user_id=user, session_id=session.id, new_message=message):
        pass


def _published(apdp: _Apdp) -> List[Tuple[Dict[str, Any], Optional[str]]]:
    return apdp.published()


def _assert_runs_isolated(apdp: _ConcurrentApdp, runs: int, child_runs: int) -> None:
    calls = [c.kwargs for c in apdp.authorize.call_args_list]
    assert calls
    run_of_execution: Dict[str, int] = {}
    for kwargs in calls:
        execution_id = kwargs.get("execution_id")
        token = token_of(kwargs.get("run"))
        # Never blank, and always the credential of the execution named.
        assert execution_id and token, kwargs
        assert token == execution_id.replace("exec_", "sst_", 1), kwargs
        expected_agent = CHILD_UUID if execution_id.endswith("_child") else ROOT_UUID
        assert kwargs["principal"] == f'Agent::"{expected_agent}"', kwargs
        # A tool call names its run in its arguments: it must be
        # authorized under that run's own execution.
        args = probed_args(kwargs.get("context"))
        for run in range(runs):
            if f"run{run}." in args or f"'run{run}'" in args:
                root_execution = execution_id.removesuffix("_child")
                assert run_of_execution.setdefault(root_execution, run) == run, (
                    f"{kwargs} authorized under another run's execution"
                )
    # Every run's tool calls were authorized, each under a distinct root.
    assert sorted(run_of_execution.values()) == list(range(runs))

    published = _published(apdp)
    starts: Dict[str, Tuple[str, Optional[str]]] = {}
    for event, token in published:
        execution_id = event["execution_id"]
        assert token == execution_id.replace("exec_", "sst_", 1), (event, token)
        expected_agent = CHILD_UUID if execution_id.endswith("_child") else ROOT_UUID
        assert event["agent_id"] == expected_agent, event
        if event["event_type"] == "execution_started":
            starts[execution_id] = (event["agent_id"], token)
    roots = [e for e in starts if not e.endswith("_child")]
    children = [e for e in starts if e.endswith("_child")]
    assert len(roots) == runs and len(children) == child_runs, starts
    for execution_id, (agent_id, token) in starts.items():
        terminals = [
            (e["event_type"], e["agent_id"], t)
            for e, t in published
            if e["execution_id"] == execution_id and e["event_type"] in TERMINAL
        ]
        assert terminals == [("execution_completed", agent_id, token)], (execution_id, terminals)
        if execution_id.endswith("_child"):
            started = next(
                e for e, _ in published
                if e["execution_id"] == execution_id and e["event_type"] == "execution_started"
            )
            assert started.get("root_execution_id") == execution_id.removesuffix("_child")


@pytest.fixture(autouse=True)
def _live_child_budget(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(
        "WATCHLIGHT_DEFAULT_SUBAGENT_SCOPE", '{"time_budget_seconds": 300, "max_depth": 0}'
    )


@pytest.mark.asyncio
async def test_two_concurrent_runs_on_one_plugin_keep_their_own_credentials():
    apdp = _ConcurrentApdp()
    plugin = _plugin(apdp)

    await asyncio.gather(
        _run_one(plugin, 0, with_agent_tool=False),
        _run_one(plugin, 1, with_agent_tool=False),
    )

    _assert_runs_isolated(apdp, runs=2, child_runs=0)


@pytest.mark.asyncio
async def test_many_concurrent_runs_one_with_an_agent_tool_child():
    """Eight overlapping runs on one plugin; run 3 also calls the
    researcher through ``AgentTool``, whose nested runner joins run 3
    and no other."""
    apdp = _ConcurrentApdp()
    plugin = _plugin(apdp)

    await asyncio.gather(
        *(_run_one(plugin, run, with_agent_tool=(run == 3)) for run in range(8))
    )

    _assert_runs_isolated(apdp, runs=8, child_runs=1)
    child = [c.kwargs for c in apdp.authorize.call_args_list if c.kwargs["execution_id"].endswith("_child")]
    assert child and all("run3" in str(probed_args(c.get("context"))) or "Model::" in c["resource"] for c in child)


@pytest.mark.asyncio
async def test_a_callback_for_another_invocation_is_refused_locally():
    """A callback naming an ADK invocation that is not this context's
    run is refused without reaching wl-apdp, even with a frame open."""
    apdp = _ConcurrentApdp()
    plugin = _plugin(apdp)
    plugin._begin_run("inv-a")
    plugin._current_invocation_id = "inv-a"
    plugin._current_agent_id = ROOT_UUID
    plugin._current_execution_id = "exec_run1"
    plugin._current_run = run_for("sst_run1")

    class _Tool:
        name = "fetch_url"

    result = await plugin.before_tool_callback(
        tool=_Tool(),
        tool_args={"url": "https://x.test/"},
        tool_context=SimpleNamespace(invocation_id="inv-b", function_call_id="c1"),
    )
    model = await plugin.before_model_callback(
        callback_context=SimpleNamespace(invocation_id="inv-b"), llm_request=None
    )

    assert "ACTION BLOCKED" in result["result"]
    assert model is not None and model.turn_complete
    apdp.authorize.assert_not_called()
    apdp.publish_events.assert_not_called()


def test_the_plugin_instance_holds_no_per_run_state():
    plugin = _plugin(_ConcurrentApdp())

    assert [name for name in _RUN_STATE_ATTRS if name in vars(plugin)] == []
    assert plugin._run_var.get() is None
