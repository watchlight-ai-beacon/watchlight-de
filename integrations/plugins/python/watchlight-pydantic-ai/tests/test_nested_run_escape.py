"""A nested agent run that loses its run's context never starts as a root.

A governed root's tool body starts a specialist agent. Through ``await``,
``iter`` and ``asyncio.to_thread`` the run's context reaches the specialist
and it is spawned as a governed sub-agent. Through an executor, a thread or
a fresh ``contextvars.Context`` the context is lost: the specialist reaches
the entry point with no parent while the root is live. It is refused
(:class:`NestedRunEscapedError`) before its first model turn, never opened
as an independent root.

Every refusal case asserts zero specialist model calls, zero specialist
tool bodies, and no second root session. Independent roots at the same
time are declared with :class:`root_run`, decided by the server
(``open_declared_root``), and refused for an agent whose spawn was refused
while that tree is live.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import contextvars
import threading
from typing import Any, Callable, Dict, List, Optional

import pytest
from pydantic_ai import Agent
from pydantic_ai.models.test import TestModel
from watchlight_core import (
    DeclaredRootRefused,
    NestedRunEscapedError,
    ScopeAttenuationDenied,
    SpawnRefusedRootRunError,
)
from watchlight_core.errors import DECLARED_ROOT_FORBIDDEN, DECLARED_ROOT_UNSUPPORTED
from watchlight_core_testing import MockApdpClient

from watchlight_pydantic_ai import (
    WatchlightPydanticAIPlugin,
    guarded_tool,
    root_run,
    uninstall_instrumentation,
)

PARENT = "11111111-1111-4111-8111-aaaaaaaaaaaa"
SPEC = "11111111-1111-4111-8111-bbbbbbbbbbbb"


@pytest.fixture(autouse=True)
def _fresh_instrumentation():
    """Instrumentation binds to the first plugin built; each case builds its
    own."""
    uninstall_instrumentation()
    yield
    uninstall_instrumentation()


class _CountingModel(TestModel):
    """A TestModel that counts its model turns."""

    def __init__(self, turns: List[str], **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._turns = turns

    async def request(self, *args: Any, **kwargs: Any) -> Any:
        self._turns.append("turn")
        return await super().request(*args, **kwargs)


class _Case:
    """A plugin on a mock backend, a parent agent and a specialist."""

    def __init__(self, *, bound_credential: bool = False, slow_open: bool = False) -> None:
        # Instrumentation binds to the first plugin built: start clean.
        uninstall_instrumentation()
        self.plugin = WatchlightPydanticAIPlugin(apdp_url="http://localhost")
        self.mock = MockApdpClient(default_decision="Allow")
        self.mock.known_agents["parent"] = PARENT
        self.mock.known_agents["specialist"] = SPEC
        if bound_credential:
            self.mock.credential_agent = PARENT
        self.sessions: List[Optional[str]] = []
        original = self.mock.create_session

        async def create_session(*a: Any, **k: Any) -> Any:
            self.sessions.append(k.get("agent_id") or (a[0] if a else None))
            if slow_open:
                # A real session open suspends: let a concurrent root reach
                # its own admission while this one is in flight.
                await asyncio.sleep(0.01)
            return await original(*a, **k)

        self.mock.create_session = create_session  # type: ignore[method-assign]
        self.plugin.apdp = self.mock
        self.spec_turns: List[str] = []
        self.spec_tools: List[str] = []
        self.spec = self._specialist()

    def _specialist(self) -> Agent:
        spec = Agent(_CountingModel(self.spec_turns), name="specialist")
        ran = self.spec_tools

        @spec.tool_plain
        @guarded_tool()
        async def guarded_lookup(q: str) -> str:
            ran.append("guarded_lookup")
            return q

        @spec.tool_plain
        async def plain_lookup(q: str) -> str:
            ran.append("plain_lookup")
            return q

        return spec

    def parent(self, body: Callable[[], Any], tools: List[str] = ["consult"]) -> Agent:
        parent = Agent(TestModel(call_tools=tools), name="parent")

        @parent.tool_plain
        async def consult(p: str) -> str:
            await body()
            return "ok"

        return parent

    def assert_specialist_never_ran(self) -> None:
        assert self.spec_turns == []
        assert self.spec_tools == []
        # Only the parent's root was opened.
        assert len(self.sessions) == 1


def _in_thread(fn: Callable[[], Any], context: Optional[contextvars.Context] = None) -> Any:
    out: Dict[str, Any] = {}

    def target() -> None:
        try:
            out["r"] = context.run(fn) if context is not None else fn()
        except BaseException as exc:  # noqa: BLE001 — re-raised below
            out["e"] = exc

    thread = threading.Thread(target=target)
    thread.start()
    thread.join()
    if "e" in out:
        raise out["e"]
    return out["r"]


async def _executor(spec: Agent) -> Any:
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, spec.run_sync, "go")


async def _thread_pool(spec: Agent) -> Any:
    with concurrent.futures.ThreadPoolExecutor(1) as pool:
        return pool.submit(spec.run_sync, "go").result()


async def _thread(spec: Agent) -> Any:
    return _in_thread(lambda: spec.run_sync("go"))


async def _fresh_context(spec: Agent) -> Any:
    return _in_thread(lambda: contextvars.Context().run(asyncio.run, spec.run("go")))


ESCAPING_ROUTES = {
    "run_in_executor": _executor,
    "ThreadPoolExecutor.submit": _thread_pool,
    "threading.Thread": _thread,
    "contextvars.Context().run": _fresh_context,
}


async def _await(spec: Agent) -> Any:
    return await spec.run("go")


async def _iter(spec: Agent) -> Any:
    async with spec.iter("go") as run:
        nodes = [node async for node in run]
    assert nodes
    return run.result


async def _to_thread(spec: Agent) -> Any:
    return await asyncio.to_thread(spec.run_sync, "go")


SPAWNING_ROUTES = {"await": _await, "iter": _iter, "asyncio.to_thread": _to_thread}


@pytest.mark.parametrize("bound_credential", [False, True])
@pytest.mark.parametrize("route", sorted(ESCAPING_ROUTES))
def test_a_nested_run_that_loses_the_context_is_refused(route: str, bound_credential: bool) -> None:
    case = _Case(bound_credential=bound_credential)
    seen: List[BaseException] = []

    async def body() -> None:
        try:
            await ESCAPING_ROUTES[route](case.spec)
        except NestedRunEscapedError as exc:
            seen.append(exc)

    asyncio.run(case.parent(body).run("go"))
    assert len(seen) == 1
    assert seen[0].reason == "implicit_root_while_run_live"
    case.assert_specialist_never_ran()
    assert case.mock.spawn_subagent_calls == []


@pytest.mark.parametrize("route", sorted(SPAWNING_ROUTES))
def test_a_nested_run_that_keeps_the_context_is_spawned(route: str) -> None:
    case = _Case()

    async def body() -> None:
        await SPAWNING_ROUTES[route](case.spec)

    asyncio.run(case.parent(body).run("go"))
    assert len(case.sessions) == 1
    assert len(case.mock.spawn_subagent_calls) == 1
    # The specialist's guarded tool was decided as the specialist.
    assert any(SPEC in c["principal"] for c in case.mock.authorize_calls)


def test_a_deferred_start_after_the_tool_returned_is_refused() -> None:
    """The tool body starts a thread that waits; a later tool of the same,
    still-live run releases it. The specialist then starts with no context."""
    case = _Case()
    release = threading.Event()
    seen: List[BaseException] = []
    threads: List[threading.Thread] = []

    def deferred() -> None:
        release.wait(5)
        try:
            case.spec.run_sync("go")
        except NestedRunEscapedError as exc:
            seen.append(exc)

    parent = Agent(TestModel(call_tools=["arm", "fire"]), name="parent")

    @parent.tool_plain
    async def arm(p: str) -> str:
        thread = threading.Thread(target=deferred)
        thread.start()
        threads.append(thread)
        return "armed"

    @parent.tool_plain
    async def fire(p: str) -> str:
        release.set()
        await asyncio.to_thread(threads[0].join, 5)
        return "fired"

    asyncio.run(parent.run("go"))
    assert len(seen) == 1
    case.assert_specialist_never_ran()


def _parent_turns(body: Callable[[Agent], Any], *, bound_credential: bool) -> List[str]:
    """Run a counting parent whose tool calls ``body(parent)``; its turns."""
    case = _Case(bound_credential=bound_credential)
    turns: List[str] = []
    parent = Agent(_CountingModel(turns, call_tools=["consult"]), name="parent")

    @parent.tool_plain
    async def consult(p: str) -> str:
        await body(parent)
        return "ok"

    asyncio.run(parent.run("go"))
    assert len(case.sessions) == 1
    return turns


def test_the_same_agent_re_run_from_a_lost_context_is_refused() -> None:
    """The parent agent itself re-run from a thread, with a credential bound
    to it: it would open a second, unattenuated root of the same agent."""
    seen: List[BaseException] = []
    attempts: List[int] = []

    async def nothing(parent: Agent) -> None:
        return None

    async def rerun(parent: Agent) -> None:
        if attempts:
            # Re-run once: an escaped re-run must not recurse.
            return
        attempts.append(1)
        try:
            _in_thread(lambda: parent.run_sync("again"))
        except NestedRunEscapedError as exc:
            seen.append(exc)
        else:
            seen.append(RuntimeError("the re-run started"))

    baseline = _parent_turns(nothing, bound_credential=True)
    turns = _parent_turns(rerun, bound_credential=True)
    assert len(seen) == 1 and isinstance(seen[0], NestedRunEscapedError)
    # No model turn beyond the parent's own run: the re-run never started.
    assert turns == baseline


def test_two_undeclared_roots_at_once_open_only_one() -> None:
    """The breaking change: an undeclared concurrent root is refused, even
    while the first is still opening."""
    case = _Case(slow_open=True)
    other = Agent(_CountingModel(case.spec_turns), name="specialist")
    parent = Agent(TestModel(), name="parent")

    async def both() -> List[Any]:
        return await asyncio.gather(parent.run("a"), other.run("b"), return_exceptions=True)

    results = asyncio.run(both())
    refused = [r for r in results if isinstance(r, NestedRunEscapedError)]
    assert len(refused) == 1
    assert len(case.sessions) == 1


# ─── root_run ───────────────────────────────────────────────────────


def test_root_run_inside_a_live_run_is_refused() -> None:
    case = _Case()
    seen: List[BaseException] = []

    async def body() -> None:
        try:
            async with root_run():
                await case.spec.run("go")
        except NestedRunEscapedError as exc:
            seen.append(exc)

    asyncio.run(case.parent(body).run("go"))
    assert len(seen) == 1
    assert seen[0].reason == "declared_root_inside_live_run"
    case.assert_specialist_never_ran()
    assert case.mock.declared_root_calls == []


def test_concurrent_roots_declared_with_root_run_both_open() -> None:
    case = _Case()
    parent = Agent(TestModel(), name="parent")

    async def declared(agent: Agent, prompt: str) -> Any:
        async with root_run():
            return await agent.run(prompt)

    async def both() -> List[Any]:
        return await asyncio.gather(declared(parent, "a"), declared(case.spec, "b"))

    asyncio.run(both())
    assert len(case.sessions) == 2
    assert len(case.mock.declared_root_calls) == 2


def test_root_run_decorates_per_thread_roots() -> None:
    case = _Case()
    parent = Agent(TestModel(), name="parent")
    gate = threading.Barrier(2)

    @root_run()
    def worker(agent: Agent) -> Any:
        gate.wait(5)
        return agent.run_sync("go")

    with concurrent.futures.ThreadPoolExecutor(2) as pool:
        results = list(pool.map(worker, [parent, case.spec]))
    assert len(results) == 2
    assert len(case.mock.declared_root_calls) == 2


def test_an_async_function_decorated_with_root_run_is_declared() -> None:
    case = _Case()

    @root_run
    async def job() -> Any:
        return await case.spec.run("go")

    asyncio.run(job())
    assert case.mock.declared_root_calls == [[]]


def test_a_declared_root_names_the_live_roots() -> None:
    """A deliberate declaration from a thread while the parent is live opens
    a declared root that names the parent's root to the server."""
    case = _Case()
    roots: List[str] = []

    async def body() -> None:
        from watchlight_pydantic_ai import current_handle

        roots.append(current_handle().root_execution_id)

        def declared() -> Any:
            with root_run():
                return case.spec.run_sync("go")

        _in_thread(declared)

    asyncio.run(case.parent(body).run("go"))
    assert case.mock.declared_root_calls == [roots]
    assert len(case.sessions) == 2


def test_a_refused_spawn_cannot_start_as_a_declared_root_while_its_tree_is_live() -> None:
    case = _Case()
    case.mock.spawn_error_override = ScopeAttenuationDenied(
        reason="scope_attenuation_violation", violations=[]
    )
    seen: List[BaseException] = []

    async def body() -> None:
        with pytest.raises(ScopeAttenuationDenied):
            await case.spec.run("go")

        def declared() -> Any:
            with root_run():
                return case.spec.run_sync("go")

        try:
            _in_thread(declared)
        except SpawnRefusedRootRunError as exc:
            seen.append(exc)

    asyncio.run(case.parent(body).run("go"))
    assert len(seen) == 1
    assert seen[0].reason == "spawn_refused_in_live_tree"
    case.assert_specialist_never_ran()
    assert case.mock.declared_root_calls == []

    # Once the refusing tree has ended, the agent can be declared again.
    case.mock.spawn_error_override = None
    with root_run():
        case.spec.run_sync("go")
    assert case.mock.declared_root_calls == [[]]


def test_a_server_that_does_not_confirm_the_declaration_refuses_the_run() -> None:
    case = _Case()
    case.mock.declared_root_echo = False

    with pytest.raises(DeclaredRootRefused) as exc:
        with root_run():
            case.spec.run_sync("go")
    assert exc.value.code == DECLARED_ROOT_UNSUPPORTED
    assert case.spec_turns == [] and case.spec_tools == []
    # The session it was given was ended.
    assert len(case.mock._closed_sessions) == 1


def test_a_declaration_the_server_refuses_never_runs() -> None:
    case = _Case()
    case.mock.declared_root_error = DeclaredRootRefused(
        "denied", code=DECLARED_ROOT_FORBIDDEN
    )

    with pytest.raises(DeclaredRootRefused) as exc:
        with root_run():
            case.spec.run_sync("go")
    assert exc.value.code == DECLARED_ROOT_FORBIDDEN
    assert case.spec_turns == [] and case.spec_tools == []


def test_with_no_run_live_a_plain_root_opens_as_before() -> None:
    case = _Case()
    case.spec.run_sync("go")
    assert len(case.sessions) == 1
    assert case.mock.declared_root_calls == []
    # A second, later root is not concurrent: it opens too.
    case.spec.run_sync("again")
    assert len(case.sessions) == 2


# ─── One admission for every framework ──────────────────────────────


class _OtherFrameworkRun:
    """A governed run another framework plugin opened in this process."""

    def __init__(self) -> None:
        from watchlight_core import RunHandleState

        self._completed = False
        self.state = RunHandleState.ACTIVE
        self.root_execution_id = "exec_00000000-0000-4000-8000-000000000001"


def test_a_run_live_in_another_framework_refuses_an_implicit_root() -> None:
    """A tool body of another framework's governed run starts a pydantic-ai
    agent from a thread: the run is live in the shared admission, so the
    agent is refused, not opened as a root."""
    from watchlight_core import root_admission

    case = _Case()
    other = _OtherFrameworkRun()
    root_admission.register_run(other)
    with pytest.raises(NestedRunEscapedError):
        _in_thread(lambda: case.spec.run_sync("go"))
    assert case.sessions == [] and case.spec_turns == [] and case.spec_tools == []

    # Declared, it names the other framework's root.
    with root_run():
        case.spec.run_sync("go")
    assert case.mock.declared_root_calls == [[other.root_execution_id]]


def test_a_live_pydantic_ai_run_counts_for_other_frameworks() -> None:
    from watchlight_core import root_admission

    case = _Case()
    seen: List[BaseException] = []

    async def body() -> None:
        try:
            root_admission.reserve_root("other-framework-agent", declared=False, hint="")
        except NestedRunEscapedError as exc:
            seen.append(exc)

    asyncio.run(case.parent(body).run("go"))
    assert len(seen) == 1
