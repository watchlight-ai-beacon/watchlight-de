"""A governed deep agent started inside a live governed run never opens a root.

A governed root's tool body builds and invokes another governed deep agent
(``create_governed_deep_agent``). Before this fix, its middleware opened a
second root session, not linked to the parent and not attenuated, and ran
its tools under it. That happened on every route below. Now the nested
agent is refused (:class:`NestedRunEscapedError`) in ``before_agent``,
before its first model turn: sub-agents run through the governed ``task``
tool. Independent roots at the same time are declared with ``root_run``.

Every refusal case asserts zero inner model turns, zero inner tool bodies
and one session (the parent's).
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import contextvars
import threading
from typing import Any, Dict, List

import pytest

pytest.importorskip("deepagents")

from langchain_core.language_models.fake_chat_models import GenericFakeChatModel  # noqa: E402
from langchain_core.messages import AIMessage  # noqa: E402
from langchain_core.tools import tool  # noqa: E402

from watchlight_core import (  # noqa: E402
    DeclaredRootRefused,
    NestedRunEscapedError,
    ScopeAttenuationDenied,
    SpawnRefusedRootRunError,
)
from watchlight_core.errors import DECLARED_ROOT_UNSUPPORTED  # noqa: E402

from watchlight_deepagents import create_governed_deep_agent, root_run  # noqa: E402

from conftest import CHILD_SLUG, ROOT_SLUG  # noqa: E402

PROMPT = {"messages": [{"role": "user", "content": "go"}]}


class _Model(GenericFakeChatModel):
    """Scripted fake model. ``bind_mode`` "local" binds the real tool specs,
    as a provider model does; "none" leaves ``bind_tools`` a no-op."""

    bind_mode: str = "none"

    def bind_tools(self, tools: Any, **kwargs: Any) -> Any:
        if self.bind_mode == "local":
            from langchain_core.utils.function_calling import convert_to_openai_tool

            return self.bind(tools=[convert_to_openai_tool(t) for t in tools])
        return self


class _Counted(_Model):
    turns: List[int] = []

    def _generate(self, *args: Any, **kwargs: Any) -> Any:  # noqa: D102
        self.turns.append(1)
        return super()._generate(*args, **kwargs)


def _turns(*calls: Dict[str, Any]) -> Any:
    out = [AIMessage(content="", tool_calls=[{**c, "type": "tool_call"}]) for c in calls]
    return iter(out + [AIMessage(content="done")])


async def _in_plain_thread(fn: Any) -> None:
    thread = threading.Thread(target=fn)
    thread.start()
    await asyncio.to_thread(thread.join, 30)


class _Case:
    """Records sessions, inner model turns and inner tool bodies."""

    def __init__(self, plugin: Any, mock_apdp: Any, *, slow_open: bool = False) -> None:
        self.plugin = plugin
        self.mock = mock_apdp
        self.mock.default_decision = "Allow"
        self.sessions: List[Any] = []
        self.inner_turns: List[int] = []
        self.inner_tools: List[str] = []
        self.inner_errors: List[BaseException] = []
        original = mock_apdp.create_session

        async def create_session(*args: Any, **kwargs: Any) -> Any:
            self.sessions.append(kwargs.get("agent_id"))
            if slow_open:
                await asyncio.sleep(0.01)
            return await original(*args, **kwargs)

        mock_apdp.create_session = create_session

    def inner_agent(self, *, bind_mode: str = "none", slug: str = ROOT_SLUG) -> Any:
        ran = self.inner_tools

        @tool
        def inner_danger(query: str) -> str:
            """An inner tool."""
            ran.append("inner_danger")
            return "danger"

        model = _Counted(
            messages=_turns({"name": "inner_danger", "args": {"query": "s"}, "id": "i1"}),
            bind_mode=bind_mode,
            turns=self.inner_turns,
        )
        return create_governed_deep_agent(
            model=model, tools=[inner_danger], agent_slug=slug, plugin=self.plugin
        )

    def run_inner_sync(self, **kw: Any) -> None:
        """Run the inner agent on its own loop (for a thread), recording a
        refusal."""
        try:
            asyncio.run(self.inner_agent(**kw).ainvoke(PROMPT))
        except NestedRunEscapedError as exc:
            self.inner_errors.append(exc)

    async def run_inner(self, **kw: Any) -> None:
        try:
            await self.inner_agent(**kw).ainvoke(PROMPT)
        except NestedRunEscapedError as exc:
            self.inner_errors.append(exc)

    async def outer(self, *tools: Any, calls: List[Dict[str, Any]]) -> Any:
        agent = create_governed_deep_agent(
            model=_Model(messages=_turns(*calls)),
            tools=list(tools),
            agent_slug=ROOT_SLUG,
            plugin=self.plugin,
        )
        return await agent.ainvoke(PROMPT)

    def assert_inner_never_ran(self) -> None:
        assert len(self.inner_errors) == 1
        assert self.inner_errors[0].reason == "implicit_root_while_run_live"
        assert self.inner_turns == []
        assert self.inner_tools == []
        assert len(self.sessions) == 1


ROUTES = [
    "await",
    "run_in_executor",
    "ThreadPoolExecutor",
    "Thread",
    "Context.run",
    "deferred_Thread",
    "deferred_Thread_copied_ctx",
]


@pytest.mark.parametrize("bind_mode", ["none", "local"])
@pytest.mark.parametrize("route", ROUTES)
async def test_a_nested_governed_deep_agent_never_opens_a_second_root(
    route: str, bind_mode: str, plugin: Any, mock_apdp: Any
) -> None:
    case = _Case(plugin, mock_apdp)
    deferred: Dict[str, Any] = {}

    def fn() -> None:
        case.run_inner_sync(bind_mode=bind_mode)

    @tool
    async def outer(query: str) -> str:
        """Starts a nested governed deep agent."""
        loop = asyncio.get_running_loop()
        if route == "await":
            await case.run_inner(bind_mode=bind_mode)
        elif route == "run_in_executor":
            await loop.run_in_executor(None, fn)
        elif route == "ThreadPoolExecutor":
            with concurrent.futures.ThreadPoolExecutor(1) as pool:
                await asyncio.wrap_future(pool.submit(fn))
        elif route == "Thread":
            thread = threading.Thread(target=fn)
            thread.start()
            await asyncio.to_thread(thread.join, 30)
        elif route == "Context.run":
            task = contextvars.Context().run(
                loop.create_task, case.run_inner(bind_mode=bind_mode)
            )
            await task
        else:
            event = threading.Event()

            def waiter() -> None:
                event.wait(30)
                fn()

            target = waiter
            if route == "deferred_Thread_copied_ctx":
                context = contextvars.copy_context()

                def target() -> None:
                    context.run(waiter)

            thread = threading.Thread(target=target)
            thread.start()
            deferred.update(event=event, thread=thread)
        return "outer"

    @tool
    async def trigger(query: str) -> str:
        """A later step of the same run: releases the deferred nested run."""
        deferred["event"].set()
        await asyncio.to_thread(deferred["thread"].join, 30)
        return "triggered"

    calls = [{"name": "outer", "args": {"query": "q"}, "id": "c1"}]
    if route.startswith("deferred"):
        calls.append({"name": "trigger", "args": {"query": "q"}, "id": "c2"})
    await case.outer(outer, trigger, calls=calls)
    case.assert_inner_never_ran()
    assert mock_apdp.spawn_subagent_calls == []


async def test_two_undeclared_roots_at_once_open_only_one(plugin: Any, mock_apdp: Any) -> None:
    """The breaking change: an undeclared concurrent root is refused, even
    while the first is still opening."""
    case = _Case(plugin, mock_apdp, slow_open=True)
    first = case.inner_agent()
    second = case.inner_agent()
    results = await asyncio.gather(
        first.ainvoke(PROMPT), second.ainvoke(PROMPT), return_exceptions=True
    )
    refused = [r for r in results if isinstance(r, NestedRunEscapedError)]
    assert len(refused) == 1
    assert len(case.sessions) == 1


# ─── root_run ───────────────────────────────────────────────────────


async def test_concurrent_roots_declared_with_root_run_both_open(plugin: Any, mock_apdp: Any) -> None:
    case = _Case(plugin, mock_apdp, slow_open=True)

    async def declared() -> Any:
        async with root_run():
            return await case.inner_agent().ainvoke(PROMPT)

    await asyncio.gather(declared(), declared())
    assert len(case.sessions) == 2
    assert len(mock_apdp.declared_root_calls) == 2


async def test_root_run_decorates_an_async_function(plugin: Any, mock_apdp: Any) -> None:
    case = _Case(plugin, mock_apdp)

    @root_run
    async def job() -> Any:
        return await case.inner_agent().ainvoke(PROMPT)

    await job()
    assert mock_apdp.declared_root_calls == [[]]


async def test_root_run_inside_a_live_run_is_refused(plugin: Any, mock_apdp: Any) -> None:
    case = _Case(plugin, mock_apdp)
    seen: List[BaseException] = []

    @tool
    async def outer(query: str) -> str:
        """Declares a root inside the live run."""
        try:
            async with root_run():
                await case.inner_agent().ainvoke(PROMPT)
        except NestedRunEscapedError as exc:
            seen.append(exc)
        return "outer"

    await case.outer(outer, calls=[{"name": "outer", "args": {"query": "q"}, "id": "c1"}])
    assert len(seen) == 1 and seen[0].reason == "declared_root_inside_live_run"
    assert case.inner_turns == [] and case.inner_tools == []
    assert len(case.sessions) == 1
    assert mock_apdp.declared_root_calls == []


async def test_a_declared_root_from_a_thread_names_the_live_root(plugin: Any, mock_apdp: Any) -> None:
    """A deliberate declaration from a thread while the parent is live opens
    a declared root that names the parent's root to the server."""
    from watchlight_core import langchain_tool_backstop as backstop

    case = _Case(plugin, mock_apdp)
    roots: List[str] = []

    def declared() -> None:
        with root_run():
            asyncio.run(case.inner_agent().ainvoke(PROMPT))

    @tool
    async def outer(query: str) -> str:
        """Declares a root from a thread."""
        roots.append(backstop.tool_body_handle().root_execution_id)
        # A plain thread: the run's context is deliberately not carried.
        await _in_plain_thread(declared)
        return "outer"

    await case.outer(outer, calls=[{"name": "outer", "args": {"query": "q"}, "id": "c1"}])
    assert mock_apdp.declared_root_calls == [roots]
    assert len(case.sessions) == 2


async def test_a_refused_task_spawn_cannot_start_as_a_declared_root_while_its_tree_is_live(
    plugin: Any, mock_apdp: Any
) -> None:
    case = _Case(plugin, mock_apdp)
    mock_apdp.spawn_error_override = ScopeAttenuationDenied(
        reason="scope_attenuation_violation", violations=[]
    )
    seen: List[BaseException] = []

    def declared() -> None:
        try:
            with root_run():
                asyncio.run(case.inner_agent(slug=CHILD_SLUG).ainvoke(PROMPT))
        except SpawnRefusedRootRunError as exc:
            seen.append(exc)

    @tool
    async def escape(query: str) -> str:
        """After the refused task spawn, tries the refused agent as a root."""
        # A plain thread: the run's context is deliberately not carried.
        await _in_plain_thread(declared)
        return "escape"

    child = _Model(messages=_turns())
    agent = create_governed_deep_agent(
        model=_Model(
            messages=_turns(
                {"name": "task", "args": {"description": "find", "subagent_type": CHILD_SLUG}, "id": "t1"},
                {"name": "escape", "args": {"query": "q"}, "id": "e1"},
            )
        ),
        tools=[escape],
        subagents=[
            {
                "name": CHILD_SLUG,
                "description": "research",
                "system_prompt": "research",
                "tools": [],
                "model": child,
            }
        ],
        subagent_scopes={CHILD_SLUG: {"allowed_tools": [], "max_depth": 0}},
        agent_slug=ROOT_SLUG,
        plugin=plugin,
    )
    await agent.ainvoke(PROMPT)
    assert len(mock_apdp.spawn_subagent_calls) == 1
    assert len(seen) == 1 and seen[0].reason == "spawn_refused_in_live_tree"
    assert case.inner_turns == [] and case.inner_tools == []
    assert len(case.sessions) == 1
    assert mock_apdp.declared_root_calls == []

    # Once the refusing tree has ended, the agent can be declared again.
    async with root_run():
        await case.inner_agent(slug=CHILD_SLUG).ainvoke(PROMPT)
    assert mock_apdp.declared_root_calls == [[]]


async def test_a_server_that_does_not_confirm_the_declaration_refuses_the_run(
    plugin: Any, mock_apdp: Any
) -> None:
    case = _Case(plugin, mock_apdp)
    mock_apdp.declared_root_echo = False
    with pytest.raises(DeclaredRootRefused) as exc:
        async with root_run():
            await case.inner_agent().ainvoke(PROMPT)
    assert exc.value.code == DECLARED_ROOT_UNSUPPORTED
    assert case.inner_turns == [] and case.inner_tools == []
    # The session it was given was closed.
    assert len(mock_apdp._closed_sessions) == 1


async def test_with_no_run_live_a_plain_root_opens_as_before(plugin: Any, mock_apdp: Any) -> None:
    case = _Case(plugin, mock_apdp)
    await case.inner_agent().ainvoke(PROMPT)
    await case.inner_agent().ainvoke(PROMPT)
    assert len(case.sessions) == 2
    assert mock_apdp.declared_root_calls == []
    assert case.inner_tools == ["inner_danger", "inner_danger"]
