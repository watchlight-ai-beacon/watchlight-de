"""A governed run that cannot open never runs, on every entry point.

When the plugin cannot open the run's governance (the root session, or a
nested agent's spawn), the agent does not run: no model request, no tool
body, and nothing done on another agent's handle. The caller gets a typed
refusal, raised before the model is called.

Covered entry points: ``Agent.run``, ``Agent.run_sync``,
``Agent.run_stream``, ``Agent.iter`` and ``Agent.run_stream_sync`` (the
patched ones), plus ``Agent.run_stream_events``, which pydantic-ai drives
through ``run``, for a root run whose session
cannot be created and for a nested run whose spawn wl-apdp refuses
(``DELEGATION_DEPTH_EXCEEDED``). The happy path on each entry point is
checked too, so the refusal is not a side effect of a broken wrapper.

The plugin, the instrumentation and pydantic-ai are real. The backend is
the in-process ``MockApdpClient`` with a session create that raises (an
outage) or a spawn that applies a delegation-depth limit.
"""

from __future__ import annotations

import asyncio
import socket
from typing import Any, Callable, Dict, List, Optional

import pytest

pytest.importorskip("pydantic_ai")

from pydantic_ai import Agent  # noqa: E402
from pydantic_ai.models.test import TestModel  # noqa: E402

from watchlight_core import (  # noqa: E402
    GovernanceUnavailable,
    ScopeAttenuationDenied,
    WatchlightError,
)
from watchlight_core_testing import MockApdpClient  # noqa: E402
from watchlight_pydantic_ai import (  # noqa: E402
    WatchlightPydanticAIPlugin,
    current_handle,
    uninstall_instrumentation,
)
from watchlight_pydantic_ai.instrumentation import (  # noqa: E402
    _reset_contextvar_for_tests,
)

ENTRY_POINTS = ["run", "run_sync", "run_stream", "iter"]
ALL_ENTRY_POINTS = ENTRY_POINTS + ["run_stream_events", "run_stream_sync"]
SYNC_ENTRY_POINTS = ("run_sync", "run_stream_sync")

# pydantic-ai 2.61 and later (the plugin's floor) refuses ``run_sync`` and
# ``run_stream_sync`` inside a sync tool or other callback of a running agent
# with ``UserError``, raised before the nested run starts. The nested sync
# cases below check that the child never ran instead of checking that it ran
# governed. If a later release stops refusing them, those cases fail.

LEVEL_UUIDS = {
    f"lvl{i}": f"11111111-1111-4111-8111-{i:012d}" for i in range(4)
}
A_UUID = "22222222-2222-4222-8222-aaaaaaaaaaaa"
B_UUID = "22222222-2222-4222-8222-bbbbbbbbbbbb"


@pytest.fixture(autouse=True)
def _clean_instrumentation():
    uninstall_instrumentation()
    _reset_contextvar_for_tests()
    yield
    uninstall_instrumentation()
    _reset_contextvar_for_tests()


# ─── Backends ────────────────────────────────────────────────────────


class _OutageBackend(MockApdpClient):
    """The agent is registered, but wl-apdp cannot be reached to open
    the session. The transport text carries values that must never
    reach the caller."""

    async def create_session(self, *args: Any, **kwargs: Any) -> Any:
        raise ConnectionError("connect ECONNREFUSED 10.0.0.7:8081 token=abc")


class _DepthLimitedBackend(MockApdpClient):
    """Applies a delegation-depth limit the way wl-apdp does: a spawn
    whose child would sit deeper than ``max_delegation_depth`` is refused
    with ``DELEGATION_DEPTH_EXCEEDED``. The root is depth 0."""

    def __init__(self, max_delegation_depth: int) -> None:
        super().__init__()
        self.max_delegation_depth = max_delegation_depth
        self._depth_by_handle: Dict[str, int] = {}
        self.refused: List[int] = []

    async def spawn_subagent(
        self, parent: Any, request_body: Dict[str, Any]
    ) -> Dict[str, Any]:
        parent_id = str(request_body.get("parent_run_handle_id"))
        depth = self._depth_by_handle.get(parent_id, 0) + 1
        if depth > self.max_delegation_depth:
            self.spawn_subagent_calls.append(request_body)
            self.spawn_subagent_tokens.append(self.token_for(parent))
            self.refused.append(depth)
            raise ScopeAttenuationDenied(
                reason="delegation_depth_exceeded",
                reason_code="DELEGATION_DEPTH_EXCEEDED",
                observed_depth=depth,
                max_delegation_depth=self.max_delegation_depth,
            )
        response = await super().spawn_subagent(parent, request_body)
        self._depth_by_handle[str(response["child_run_handle_id"])] = depth
        return response


def _plugin(backend: MockApdpClient, agents: Dict[str, str]) -> WatchlightPydanticAIPlugin:
    for slug, uuid in agents.items():
        backend.known_agents[slug] = uuid
    plugin = WatchlightPydanticAIPlugin(apdp_url="http://localhost")
    plugin.apdp = backend
    return plugin


# ─── A model that records every request ──────────────────────────────


class _RecordingModel(TestModel):
    """``TestModel`` that records each model request it serves."""

    def __init__(self, label: str, log: List[str], **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._wl_label = label
        self._wl_log = log

    async def request(self, *args: Any, **kwargs: Any) -> Any:
        self._wl_log.append(self._wl_label)
        return await super().request(*args, **kwargs)

    def request_stream(self, *args: Any, **kwargs: Any) -> Any:
        self._wl_log.append(self._wl_label)
        return super().request_stream(*args, **kwargs)


# ─── Driving an agent through one entry point ────────────────────────


async def _drive_async(agent: Agent, entry: str, prompt: str) -> Any:
    """Drive ``agent`` to completion through an async-capable entry point."""
    if entry == "run":
        return (await agent.run(prompt)).output
    if entry == "run_stream":
        async with agent.run_stream(prompt) as stream:
            return await stream.get_output()
    if entry == "iter":
        async with agent.iter(prompt) as agent_run:
            async for _node in agent_run:
                pass
            return agent_run.result.output if agent_run.result else None
    if entry == "run_stream_events":
        output = None
        from pydantic_ai.run import AgentRunResultEvent

        events = agent.run_stream_events(prompt)
        if hasattr(events, "__aenter__"):
            async with events as stream:
                async for event in stream:
                    if isinstance(event, AgentRunResultEvent):
                        output = event.result.output
        else:  # older pydantic-ai: a plain async iterator
            async for event in events:
                if isinstance(event, AgentRunResultEvent):
                    output = event.result.output
        return output
    raise AssertionError(f"not an async entry point: {entry}")


def _drive(agent: Agent, entry: str, prompt: str) -> Any:
    """Drive ``agent`` from synchronous test code."""
    if entry == "run_sync":
        return agent.run_sync(prompt).output
    if entry == "run_stream_sync":
        return agent.run_stream_sync(prompt).get_output()
    return asyncio.run(_drive_async(agent, entry, prompt))


def _attach_child_call(
    parent: Agent, child: Agent, entry: str, on_call: Callable[[], None] = lambda: None
) -> Dict[str, Any]:
    """Give ``parent`` a tool that runs ``child`` through ``entry``.

    The tool records the refusal it sees and the handle that is current
    before and after the child call, so a test can show the parent's
    handle was neither replaced nor closed by the refused child.
    """
    seen: Dict[str, Any] = {"refusals": [], "before": [], "after": [], "parent_open": []}

    def _record_after(before: Any) -> None:
        after = current_handle()
        seen["after"].append(after)
        seen["parent_open"].append(after is before and not getattr(after, "_completed", True))

    if entry in ("run_sync", "run_stream_sync"):

        @parent.tool_plain
        def call_child(prompt: str) -> str:
            on_call()
            before = current_handle()
            seen["before"].append(before)
            try:
                _drive(child, entry, prompt)
            except WatchlightError as exc:
                seen["refusals"].append(exc)
                _record_after(before)
                return "child refused"
            _record_after(before)
            return "child ran"

    else:

        @parent.tool_plain
        async def call_child(prompt: str) -> str:  # type: ignore[no-redef]
            on_call()
            before = current_handle()
            seen["before"].append(before)
            try:
                await _drive_async(child, entry, prompt)
            except WatchlightError as exc:
                seen["refusals"].append(exc)
                _record_after(before)
                return "child refused"
            _record_after(before)
            return "child ran"

    return seen


def _nested_sync_is_rejected(entry: str) -> bool:
    return entry in SYNC_ENTRY_POINTS


def _drive_expecting_nested_sync_rejection(
    root: Agent,
    entry: str,
    backend: MockApdpClient,
    model_calls: List[str],
    tool_calls: List[str],
    child_slugs: List[str],
) -> None:
    """Drive ``root`` whose sync tool runs a child through ``entry``, on a
    pydantic-ai that rejects that nesting, and check that the child never
    ran: the caller gets an error, never a result; the child made no model
    request and ran no tool body; nothing was authorized; every session the
    plugin opened (the root's, and the child's spawn) was terminated, none
    completed; and no handle is left current."""
    from pydantic_ai.exceptions import UserError

    with pytest.raises(UserError) as excinfo:
        _drive(root, entry, "start")
    assert "cannot be used inside a synchronous tool" in str(excinfo.value)

    # Only the root's first model turn (the one that asked for the tool)
    # and the root's calling tool ran.
    assert model_calls == ["lvl0"], f"a child reached the model: {model_calls}"
    assert tool_calls == ["lvl0"], f"a child's tool body ran: {tool_calls}"
    for slug in child_slugs:
        assert slug not in model_calls and slug not in tool_calls
    assert backend.authorize_calls == []

    # The root session and at most the first child's spawn were opened, and
    # every one of them was terminated as a failed run; none was completed.
    opened = 1 + len(backend.spawn_subagent_calls)
    assert len(backend.spawn_subagent_calls) <= 1
    assert backend._closed_sessions == [], "a session was completed"
    assert len(backend._terminated_sessions) == opened
    assert {reason for _, reason in backend._terminated_sessions} == {
        "pydantic_ai_run_failed: UserError"
    }
    assert not any(
        e.get("event_type") == "execution_completed" for e in backend.published_events
    )
    assert current_handle() is None


# ─── 1. Root: the session cannot be opened ───────────────────────────


@pytest.mark.parametrize("entry", ALL_ENTRY_POINTS)
def test_root_outage_refuses_before_the_model_is_called(entry: str) -> None:
    backend = _OutageBackend()
    _plugin(backend, {"lvl0": LEVEL_UUIDS["lvl0"]})
    model_calls: List[str] = []
    tool_calls: List[str] = []

    agent = Agent(_RecordingModel("lvl0", model_calls), name="lvl0")

    @agent.tool_plain
    def lookup(q: str) -> str:
        tool_calls.append(q)
        return q

    with pytest.raises(GovernanceUnavailable) as excinfo:
        _drive(agent, entry, "please help")

    message = str(excinfo.value)
    assert "lvl0" in message and "was not started" in message
    assert "ECONNREFUSED" not in message and "token=abc" not in message
    assert model_calls == [], "the model was called for an ungoverned run"
    assert tool_calls == [], "a tool ran in an ungoverned run"
    assert backend.authorize_calls == []
    assert backend.published_events == []
    assert current_handle() is None


@pytest.mark.parametrize("entry", ALL_ENTRY_POINTS)
def test_root_unreachable_apdp_refuses(entry: str) -> None:
    """The real ``ApdpClient`` aimed at a closed port: the agent does
    not run and the caller gets a typed governance error."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    WatchlightPydanticAIPlugin(apdp_url=f"http://127.0.0.1:{port}")
    model_calls: List[str] = []
    tool_calls: List[str] = []
    agent = Agent(_RecordingModel("lvl0", model_calls), name="lvl0")

    @agent.tool_plain
    def lookup(q: str) -> str:
        tool_calls.append(q)
        return q

    with pytest.raises(WatchlightError):
        _drive(agent, entry, "please help")
    assert model_calls == []
    assert tool_calls == []
    assert current_handle() is None


# ─── 2. Nested: the spawn is refused (depth exceeded) ────────────────


def _level_chain(entry: str, backend: MockApdpClient):
    """lvl0 → lvl1 → lvl2 → lvl3, each level calling the next from a tool
    through ``entry``. Returns the root agent, per-level model and tool
    logs, and what each calling tool saw."""
    model_calls: List[str] = []
    tool_calls: List[str] = []
    agents = {
        name: Agent(_RecordingModel(name, model_calls), name=name)
        for name in ("lvl0", "lvl1", "lvl2", "lvl3")
    }

    @agents["lvl3"].tool_plain
    def leaf(q: str) -> str:
        tool_calls.append("lvl3")
        return q

    seen = {}
    for parent, child in (("lvl2", "lvl3"), ("lvl1", "lvl2"), ("lvl0", "lvl1")):
        seen[parent] = _attach_child_call(
            agents[parent],
            agents[child],
            entry,
            on_call=lambda p=parent: tool_calls.append(p),
        )
    return agents["lvl0"], model_calls, tool_calls, seen


@pytest.mark.parametrize("entry", ALL_ENTRY_POINTS)
def test_nested_depth_refusal_child_never_runs(entry: str) -> None:
    backend = _DepthLimitedBackend(max_delegation_depth=1)
    _plugin(backend, LEVEL_UUIDS)
    root, model_calls, tool_calls, seen = _level_chain(entry, backend)

    if _nested_sync_is_rejected(entry):
        # pydantic-ai refuses lvl1's nested sync run before it starts, so
        # the chain stops there: no level below the root ever ran.
        _drive_expecting_nested_sync_rejection(
            root, entry, backend, model_calls, tool_calls, ["lvl1", "lvl2", "lvl3"]
        )
        assert backend.refused == []
        return

    _drive(root, entry, "start")

    # lvl1 ran (depth 1 is allowed); its spawn of lvl2 was refused.
    assert backend.refused == [2]
    assert "lvl2" not in model_calls and "lvl3" not in model_calls
    assert "lvl2" not in tool_calls and "lvl3" not in tool_calls
    refusals = seen["lvl1"]["refusals"]
    assert len(refusals) == 1
    assert isinstance(refusals[0], ScopeAttenuationDenied)
    assert refusals[0].reason_code == "DELEGATION_DEPTH_EXCEEDED"

    # The refused child did not take over or close the parent's handle.
    before = seen["lvl1"]["before"][0]
    assert before is not None
    assert seen["lvl1"]["after"] == [before]
    assert seen["lvl1"]["parent_open"] == [True]
    assert str(before.agent_uuid) == LEVEL_UUIDS["lvl1"]

    # Nothing was started for lvl2/lvl3 and nothing authorized as them.
    for slug in ("lvl2", "lvl3"):
        started = [
            e
            for e in backend.published_events
            if e.get("event_type") == "execution_started"
            and e.get("agent_id") == LEVEL_UUIDS[slug]
        ]
        assert started == [], f"{slug} was started"
    assert current_handle() is None


def test_reentry_of_an_ancestor_agent_is_a_governed_spawn() -> None:
    """A → B → A. The inner A is a new sub-agent (depth 2) and must be
    spawned like any other; when the spawn is refused it never runs. It
    must not pass through as a re-entrant call and run on B's handle."""
    backend = _DepthLimitedBackend(max_delegation_depth=1)
    _plugin(backend, {"agent-a": A_UUID, "agent-b": B_UUID})
    model_calls: List[str] = []
    a_tool_handles: List[Any] = []

    agent_a = Agent(_RecordingModel("agent-a", model_calls), name="agent-a")
    agent_b = Agent(_RecordingModel("agent-b", model_calls), name="agent-b")

    seen_b = _attach_child_call(agent_b, agent_a, "run")

    @agent_a.tool_plain
    async def delegate(prompt: str) -> str:
        a_tool_handles.append(current_handle())
        if len(a_tool_handles) == 1:
            await agent_b.run(prompt)
        return "done"

    asyncio.run(agent_a.run("start"))

    assert backend.refused == [2]
    assert len(a_tool_handles) == 1, "the refused inner A ran its tool"
    assert len(seen_b["refusals"]) == 1
    assert model_calls.count("agent-a") == 2  # the outer A only: tool call + final


# ─── 3. Happy path on each entry point ───────────────────────────────


@pytest.mark.parametrize("entry", ALL_ENTRY_POINTS)
def test_happy_path_runs_governed(entry: str) -> None:
    backend = _DepthLimitedBackend(max_delegation_depth=8)
    _plugin(backend, LEVEL_UUIDS)
    root, model_calls, tool_calls, seen = _level_chain(entry, backend)

    if _nested_sync_is_rejected(entry):
        _drive_expecting_nested_sync_rejection(
            root, entry, backend, model_calls, tool_calls, ["lvl1", "lvl2", "lvl3"]
        )
        return

    _drive(root, entry, "start")

    assert backend.refused == []
    assert tool_calls == ["lvl0", "lvl1", "lvl2", "lvl3"]
    for name in ("lvl0", "lvl1", "lvl2", "lvl3"):
        assert name in model_calls
    assert len(backend.spawn_subagent_calls) == 3
    for parent in ("lvl0", "lvl1", "lvl2"):
        assert seen[parent]["refusals"] == []
        assert seen[parent]["parent_open"] == [True]
    assert current_handle() is None


# ─── 4. A successful run closes its handles ──────────────────────────


@pytest.mark.parametrize("entry", ALL_ENTRY_POINTS)
def test_successful_run_completes_root_and_child(entry: str) -> None:
    """After the call returns, the root's and the child's sessions are
    completed, ``execution_completed`` is emitted for each, and neither
    handle is active any more."""
    from watchlight_core import RunHandleState

    backend = _DepthLimitedBackend(max_delegation_depth=8)
    _plugin(backend, {"lvl0": LEVEL_UUIDS["lvl0"], "lvl1": LEVEL_UUIDS["lvl1"]})
    model_calls: List[str] = []
    handles: Dict[str, Any] = {}
    child = Agent(_RecordingModel("lvl1", model_calls), name="lvl1")

    @child.tool_plain
    def leaf(q: str) -> str:
        handles["lvl1"] = current_handle()
        return q

    root = Agent(_RecordingModel("lvl0", model_calls), name="lvl0")
    root_tool_calls: List[str] = []

    def _on_call() -> None:
        root_tool_calls.append("lvl0")
        handles.setdefault("lvl0", current_handle())

    _attach_child_call(root, child, entry, on_call=_on_call)

    if _nested_sync_is_rejected(entry):
        # Neither run returned, so neither may be completed: both are
        # terminated, and the child's tool never ran.
        _drive_expecting_nested_sync_rejection(
            root, entry, backend, model_calls, root_tool_calls, ["lvl1"]
        )
        assert set(handles) == {"lvl0"}
        assert handles["lvl0"]._completed
        return

    _drive(root, entry, "start")

    assert set(handles) == {"lvl0", "lvl1"}
    completed = {
        e.get("execution_id")
        for e in backend.published_events
        if e.get("event_type") == "execution_completed"
    }
    for name, handle in handles.items():
        assert handle is not None
        assert handle.session_id in backend._closed_sessions, f"{name} session not completed"
        assert handle.execution_id in completed, f"{name} has no execution_completed"
        assert handle._completed and handle.state == RunHandleState.COMPLETED, f"{name} still active"
    assert current_handle() is None


# ─── 5. A call that outlives its run ─────────────────────────────────


@pytest.mark.parametrize("callee", ["same-agent", "other-agent"])
def test_call_from_a_task_that_outlives_the_run_is_refused(callee: str) -> None:
    """A task created inside a tool inherits the run's context. When it
    calls an agent after the run has returned, it must not run on the
    closed handle: the same agent is refused at the re-entrant
    pass-through, and another agent is neither spawned from the closed
    handle nor promoted to a root."""
    backend = _DepthLimitedBackend(max_delegation_depth=8)
    _plugin(backend, {"agent-a": A_UUID, "agent-b": B_UUID})
    model_calls: List[str] = []
    a_tool_calls: List[Any] = []
    b_tool_calls: List[Any] = []
    agent_a = Agent(_RecordingModel("agent-a", model_calls), name="agent-a")
    agent_b = Agent(_RecordingModel("agent-b", model_calls), name="agent-b")
    target = agent_a if callee == "same-agent" else agent_b

    @agent_b.tool_plain
    def b_tool(q: str) -> str:
        b_tool_calls.append(q)
        return q

    async def _run() -> None:
        go = asyncio.Event()
        tasks: List[asyncio.Task] = []

        async def _late_call() -> None:
            await go.wait()
            await target.run("late")

        @agent_a.tool_plain
        async def a_tool(q: str) -> str:
            a_tool_calls.append(current_handle())
            if not tasks:
                tasks.append(asyncio.create_task(_late_call()))
            return q

        await agent_a.run("start")
        outer = a_tool_calls[0]
        assert outer._completed
        calls_before = list(model_calls)
        go.set()
        with pytest.raises(WatchlightError):
            await tasks[0]
        assert model_calls == calls_before, "the late call reached the model"
        assert len(a_tool_calls) == 1
        assert b_tool_calls == []
        assert backend.spawn_subagent_calls == []

    asyncio.run(_run())


# ─── 6. run_stream_sync closes its run deterministically ─────────────


def _stream_sync_setup(tool_error: Optional[Exception] = None):
    backend = _DepthLimitedBackend(max_delegation_depth=8)
    _plugin(backend, {"lvl0": LEVEL_UUIDS["lvl0"]})
    model_calls: List[str] = []
    seen: Dict[str, Any] = {}
    agent = Agent(
        _RecordingModel("lvl0", model_calls, custom_output_text="one two three four five"),
        name="lvl0",
    )

    @agent.tool_plain
    def lookup(q: str) -> str:
        seen["handle"] = current_handle()
        if tool_error is not None:
            raise tool_error
        return q

    return backend, agent, seen, model_calls


def _closed_as(backend: MockApdpClient, handle: Any) -> str:
    """``"completed"``, ``"terminated:<reason>"`` or ``"open"``."""
    terminated = [r for sid, r in backend._terminated_sessions if sid == handle.session_id]
    if terminated:
        assert handle.session_id not in backend._closed_sessions
        return f"terminated:{terminated[0]}"
    if handle.session_id in backend._closed_sessions:
        return "completed"
    return "open"


def test_run_stream_sync_full_consumption_completes() -> None:
    from watchlight_core import RunHandleState

    backend, agent, seen, _ = _stream_sync_setup()
    result = agent.run_stream_sync("start")
    from pydantic_ai.result import StreamedRunResultSync

    assert isinstance(result, StreamedRunResultSync)  # transparent re-type
    assert current_handle() is None  # the caller's context is untouched
    chunks = list(result.stream_text(debounce_by=None))
    assert chunks
    handle = seen["handle"]
    assert _closed_as(backend, handle) == "completed"
    assert handle.state == RunHandleState.COMPLETED
    assert any(
        e.get("event_type") == "execution_completed" and e.get("execution_id") == handle.execution_id
        for e in backend.published_events
    )
    # Attribute delegation keeps working after the close.
    assert result.all_messages()
    assert result.response is not None
    # A second consumer does not close the run again.
    result.get_output()
    assert backend._closed_sessions.count(handle.session_id) == 1
    assert current_handle() is None


def test_run_stream_sync_early_break_terminates() -> None:
    backend, agent, seen, _ = _stream_sync_setup()
    result = agent.run_stream_sync("start")
    for _chunk in result.stream_text(delta=True, debounce_by=None):
        break
    handle = seen["handle"]
    assert _closed_as(backend, handle) == "terminated:pydantic_ai_stream_closed_early"
    assert handle._completed
    del result
    import gc

    gc.collect()
    # The abandonment finalizer is a no-op after the early close.
    assert len(backend._terminated_sessions) == 1


def test_run_stream_sync_error_before_the_stream_terminates() -> None:
    """A tool error raised while run_stream_sync opens the stream."""

    class ToolBroke(Exception):
        pass

    backend, agent, seen, _ = _stream_sync_setup(tool_error=ToolBroke("boom"))
    with pytest.raises(ToolBroke):
        agent.run_stream_sync("start")
    handle = seen["handle"]
    assert _closed_as(backend, handle) == "terminated:pydantic_ai_run_failed: ToolBroke"


@pytest.mark.parametrize("consume", ["get_output", "stream_output"])
def test_run_stream_sync_error_while_consuming_terminates(consume: str) -> None:
    """An error raised after the stream was returned, while it is consumed."""

    class OutputBroke(Exception):
        pass

    backend, agent, seen, _ = _stream_sync_setup()

    @agent.output_validator
    def _reject(output: str) -> str:
        raise OutputBroke("no")

    result = agent.run_stream_sync("start")
    handle = seen["handle"]
    assert _closed_as(backend, handle) == "open"
    with pytest.raises(OutputBroke):
        if consume == "get_output":
            result.get_output()
        else:
            for _ in result.stream_output(debounce_by=None):
                pass
    assert _closed_as(backend, handle) == "terminated:pydantic_ai_run_failed: OutputBroke"


def test_run_stream_sync_abandoned_result_is_terminated_as_abandoned() -> None:
    import gc

    backend, agent, seen, _ = _stream_sync_setup()
    result = agent.run_stream_sync("start")
    handle = seen["handle"]
    assert _closed_as(backend, handle) == "open"
    del result
    gc.collect()
    assert _closed_as(backend, handle) == "terminated:pydantic_ai_stream_abandoned"
    assert not any(
        e.get("event_type") == "execution_completed" and e.get("execution_id") == handle.execution_id
        for e in backend.published_events
    )


# ─── 7. A terminated run_stream_sync run cannot be driven further ────


@pytest.fixture
def close_calls(monkeypatch: pytest.MonkeyPatch) -> Dict[str, List[Any]]:
    """Spy on ``RunHandle.terminate`` / ``complete``: every call, per handle."""
    from watchlight_pydantic_ai import RunHandle

    calls: Dict[str, List[Any]] = {"terminate": [], "complete": []}
    original_terminate = RunHandle.terminate
    original_complete = RunHandle.complete

    async def terminate(self: Any, *args: Any, **kwargs: Any) -> Any:
        calls["terminate"].append(self)
        return await original_terminate(self, *args, **kwargs)

    async def complete(self: Any, *args: Any, **kwargs: Any) -> Any:
        calls["complete"].append(self)
        return await original_complete(self, *args, **kwargs)

    monkeypatch.setattr(RunHandle, "terminate", terminate)
    monkeypatch.setattr(RunHandle, "complete", complete)
    return calls


def _text_then_tool_agent(ran: List[str]) -> Agent:
    """Streams text, then a tool call in the same response. With
    ``end_strategy="exhaustive"`` pydantic-ai runs that tool when the
    response is finished, e.g. by ``get_output()``."""
    from pydantic_ai.messages import ToolReturnPart
    from pydantic_ai.models.function import DeltaToolCall, FunctionModel

    async def stream_fn(messages: Any, info: Any) -> Any:
        if any(isinstance(p, ToolReturnPart) for m in messages for p in getattr(m, "parts", [])):
            yield "done"
            return
        yield "first "
        yield "second "
        yield {0: DeltaToolCall(name="side_effect", json_args='{"q": "x"}', tool_call_id="c1")}

    agent = Agent(FunctionModel(stream_function=stream_fn), name="lvl0", end_strategy="exhaustive")

    @agent.tool_plain
    def side_effect(q: str) -> str:
        ran.append(q)
        return q

    return agent


def test_run_stream_sync_after_early_stop_refuses_further_reads(close_calls) -> None:
    import gc

    backend = _DepthLimitedBackend(max_delegation_depth=8)
    _plugin(backend, {"lvl0": LEVEL_UUIDS["lvl0"]})
    ran: List[str] = []
    agent = _text_then_tool_agent(ran)

    result = agent.run_stream_sync("go")
    for _chunk in result.stream_text(delta=True, debounce_by=None):
        break
    assert len(close_calls["terminate"]) == 1
    handle = close_calls["terminate"][0]
    assert backend._terminated_sessions == [(handle.session_id, "pydantic_ai_stream_closed_early")]

    with pytest.raises(GovernanceUnavailable):
        result.get_output()
    with pytest.raises(GovernanceUnavailable):
        next(iter(result.stream_text(debounce_by=None)))
    with pytest.raises(GovernanceUnavailable):
        result.validate_response_output(result.response)
    assert ran == [], "a tool body ran on the terminated run"

    del result
    gc.collect()
    # Neither the refused calls nor the finalizer closed the run again.
    assert len(close_calls["terminate"]) == 1
    assert close_calls["complete"] == []


def test_run_stream_sync_iterator_obtained_before_the_stop_is_refused_per_item(close_calls) -> None:
    """An iterator taken before the run was terminated passes the
    method-level check; each of its items is checked again."""
    backend = _DepthLimitedBackend(max_delegation_depth=8)
    _plugin(backend, {"lvl0": LEVEL_UUIDS["lvl0"]})
    ran: List[str] = []
    agent = _text_then_tool_agent(ran)

    result = agent.run_stream_sync("go")
    taken_early = result.stream_text(debounce_by=None)
    for _chunk in result.stream_text(delta=True, debounce_by=None):
        break
    assert len(close_calls["terminate"]) == 1
    with pytest.raises(GovernanceUnavailable):
        list(taken_early)
    assert ran == [], "a tool body ran on the terminated run"
    assert len(close_calls["terminate"]) == 1


def test_run_stream_sync_after_error_refuses_another_call(close_calls) -> None:
    class OutputBroke(Exception):
        pass

    backend, agent, seen, _ = _stream_sync_setup()

    @agent.output_validator
    def _reject(output: str) -> str:
        raise OutputBroke("no")

    result = agent.run_stream_sync("start")
    with pytest.raises(OutputBroke):
        result.get_output()
    with pytest.raises(GovernanceUnavailable):
        result.get_output()
    with pytest.raises(GovernanceUnavailable):
        list(result.stream_output(debounce_by=None))
    assert len(close_calls["terminate"]) == 1
    assert close_calls["complete"] == []


def test_run_stream_sync_closes_exactly_once(close_calls) -> None:
    import gc

    backend, agent, seen, _ = _stream_sync_setup()
    result = agent.run_stream_sync("start")
    list(result.stream_text(debounce_by=None))
    result.get_output()  # the run already completed: allowed, no second close
    del result
    gc.collect()
    assert len(close_calls["complete"]) == 1
    assert close_calls["terminate"] == []


# ─── 8. The abandonment close reaches the run from any thread ────────


class _StubHandle:
    """Records closes; ``closed_event`` is set by the first one."""

    def __init__(self) -> None:
        import threading

        self.terminations: List[str] = []
        self.completions = 0
        self.closed_event = threading.Event()

    async def terminate(self, reason: str = "manual") -> None:
        self.terminations.append(reason)
        self.closed_event.set()

    async def complete(self) -> None:
        self.completions += 1
        self.closed_event.set()


def _stream_run(handle: _StubHandle, loop: asyncio.AbstractEventLoop):
    import contextvars

    from watchlight_pydantic_ai.instrumentation import _SyncStreamRun

    return _SyncStreamRun(handle, loop, contextvars.copy_context())  # type: ignore[arg-type]


def test_abandon_with_the_loop_running_on_another_thread() -> None:
    import threading

    loop = asyncio.new_event_loop()
    worker = threading.Thread(target=loop.run_forever, daemon=True)
    worker.start()
    try:
        handle = _StubHandle()
        run = _stream_run(handle, loop)
        run.abandon()
        assert run.closed
        assert handle.closed_event.wait(5), "the close never ran on the loop's thread"
        assert handle.terminations == ["pydantic_ai_stream_abandoned"]
    finally:
        loop.call_soon_threadsafe(loop.stop)
        worker.join(5)
        loop.close()


def test_abandon_on_the_loops_own_thread_while_it_runs() -> None:
    handle = _StubHandle()

    async def main() -> None:
        run = _stream_run(handle, asyncio.get_running_loop())
        run.abandon()  # e.g. a finalizer run by GC during a step
        assert run.closed
        for _ in range(50):
            if handle.terminations:
                break
            await asyncio.sleep(0.01)

    asyncio.run(main())
    assert handle.terminations == ["pydantic_ai_stream_abandoned"]


def test_abandon_while_another_loop_runs_on_this_thread() -> None:
    target = asyncio.new_event_loop()
    handle = _StubHandle()
    try:

        async def main() -> None:
            run = _stream_run(handle, target)
            run.abandon()
            assert run.closed

        asyncio.run(main())
        assert handle.terminations == ["pydantic_ai_stream_abandoned"]
    finally:
        target.close()


def test_abandon_after_the_runs_loop_closed() -> None:
    target = asyncio.new_event_loop()
    target.close()
    handle = _StubHandle()
    run = _stream_run(handle, target)
    run.abandon()
    assert run.closed
    assert handle.terminations == ["pydantic_ai_stream_abandoned"]


def test_a_close_that_could_not_be_scheduled_is_retried() -> None:
    handle = _StubHandle()
    run = _stream_run(handle, asyncio.new_event_loop())
    attempts: List[int] = []
    real_schedule = run._schedule

    def flaky(factory: Any) -> bool:
        attempts.append(1)
        if len(attempts) == 1:
            return False
        return real_schedule(factory)

    run._schedule = flaky  # type: ignore[method-assign]
    run.terminate("pydantic_ai_stream_closed_early")
    assert not run.closed and run.terminated and handle.terminations == []
    run.abandon()  # the finalizer retries the original close
    assert run.closed
    assert handle.terminations == ["pydantic_ai_stream_closed_early"]
    run.loop.close()


def test_worker_close_wait_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    """A slow close on the worker thread does not block the caller past
    the bound; it finishes in the background, counts as scheduled, and is
    never closed a second time."""
    import threading
    import time

    from watchlight_pydantic_ai import instrumentation

    monkeypatch.setattr(instrumentation, "_WORKER_CLOSE_TIMEOUT_S", 0.05)
    release = threading.Event()

    class _SlowHandle(_StubHandle):
        async def terminate(self, reason: str = "manual") -> None:
            while not release.is_set():
                await asyncio.sleep(0.01)
            await super().terminate(reason)

    target = asyncio.new_event_loop()
    target.close()  # forces the worker-thread path
    handle = _SlowHandle()
    run = _stream_run(handle, target)
    # Released on its own after 2s, so an unbounded wait fails instead of hanging.
    releaser = threading.Timer(2.0, release.set)
    releaser.start()
    started = time.monotonic()
    run.abandon()
    elapsed = time.monotonic() - started
    assert elapsed < 1.0, f"the caller waited {elapsed:.2f}s for the slow close"
    assert run.closed  # in flight counts as scheduled
    assert handle.terminations == []
    run.abandon()  # no second close while the first is in flight
    release.set()
    releaser.cancel()
    assert handle.closed_event.wait(5)
    time.sleep(0.05)
    assert handle.terminations == ["pydantic_ai_stream_abandoned"]
