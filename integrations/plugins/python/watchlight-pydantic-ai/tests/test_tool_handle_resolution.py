"""Tool authorization resolves the governing handle at call time.

A tool must be authorized on the run that is actually driving the agent
when the tool is called: the root run for a top-level ``Agent.run``,
or the sub-agent's own handle for an agent run nested inside another
agent's tool. A handle captured when the tool was decorated must never
govern a sub-agent's tools (that would run them on the parent's
credential and scope), and a tool with no live governed run is refused.
"""

from __future__ import annotations

import asyncio
import warnings

import pytest

pytest.importorskip("pydantic_ai")

from pydantic_ai import Agent  # noqa: E402
from pydantic_ai.models.test import TestModel  # noqa: E402

from watchlight_core import GovernanceUnavailable  # noqa: E402
from watchlight_core_testing import MockApdpClient  # noqa: E402
from watchlight_pydantic_ai import (  # noqa: E402
    WatchlightPydanticAIPlugin,
    current_handle,
    uninstall_instrumentation,
)
from watchlight_pydantic_ai.instrumentation import (  # noqa: E402
    _reset_contextvar_for_tests,
)

PARENT = "11111111-1111-4111-8111-aaaaaaaaaaaa"
CHILD = "11111111-1111-4111-8111-bbbbbbbbbbbb"


@pytest.fixture(autouse=True)
def _clean_instrumentation():
    uninstall_instrumentation()
    _reset_contextvar_for_tests()
    yield
    uninstall_instrumentation()
    _reset_contextvar_for_tests()


def _make_plugin() -> tuple[WatchlightPydanticAIPlugin, MockApdpClient]:
    plugin = WatchlightPydanticAIPlugin(apdp_url="http://localhost")
    mock = MockApdpClient()
    mock.known_agents["parent"] = PARENT
    mock.known_agents["specialist"] = CHILD
    mock.default_decision = "Allow"
    plugin.apdp = mock
    return plugin, mock


def _calls_for(mock: MockApdpClient, tool: str) -> list[dict]:
    return [c for c in mock.authorize_calls if tool in c.get("resource", "")]


def test_handle_bound_tool_in_subagent_is_authorized_on_subagent_handle() -> None:
    """A sub-agent tool decorated with the root run's handle is still
    authorized on the sub-agent's own handle (never the parent's)."""

    async def _run() -> None:
        plugin, mock = _make_plugin()
        seen: list = []
        async with await plugin.start_run("parent") as root:
            specialist = Agent(TestModel(), name="specialist")

            with warnings.catch_warnings():
                warnings.simplefilter("ignore", DeprecationWarning)

                @specialist.tool_plain
                @root.guarded_tool()
                async def secret_query(q: str) -> str:
                    seen.append(current_handle())
                    return f"answered: {q}"

            parent = Agent(TestModel(), name="parent")

            @parent.tool_plain
            async def consult(p: str) -> str:
                r = await specialist.run(p)
                return str(r.output)

            await parent.run("trigger")

        calls = _calls_for(mock, "secret_query")
        assert calls, "the sub-agent's tool was never authorized"
        child = seen[0]
        assert child is not None and child.agent_uuid == CHILD
        for call in calls:
            assert CHILD in call["principal"], call["principal"]
            assert call["session_id"] == child.session_id
            assert call["session_id"] != root.session_id

    asyncio.run(_run())


def test_module_guarded_tool_authorizes_on_the_run_driving_the_model() -> None:
    """README quickstart shape: the tool and the model run under the
    same governed run (the one the instrumented ``agent.run`` opened)."""
    from watchlight_pydantic_ai import guarded_tool

    async def _run() -> None:
        plugin, mock = _make_plugin()
        driving: list = []
        agent = Agent(TestModel(), name="parent")

        @agent.tool_plain
        @guarded_tool()
        async def web_search(q: str) -> str:
            driving.append(current_handle())
            return "ok"

        await agent.run("question")

        calls = _calls_for(mock, "web_search")
        assert calls and driving and driving[0] is not None
        assert all(c["session_id"] == driving[0].session_id for c in calls)
        assert all(PARENT in c["principal"] for c in calls)

    asyncio.run(_run())


def test_module_guarded_tool_in_subagent_uses_subagent_handle() -> None:
    from watchlight_pydantic_ai import guarded_tool

    async def _run() -> None:
        plugin, mock = _make_plugin()
        specialist = Agent(TestModel(), name="specialist")

        @specialist.tool_plain
        @guarded_tool()
        async def secret_query(q: str) -> str:
            return "x"

        parent = Agent(TestModel(), name="parent")

        @parent.tool_plain
        async def consult(p: str) -> str:
            return str((await specialist.run(p)).output)

        await parent.run("trigger")
        calls = _calls_for(mock, "secret_query")
        assert calls
        assert all(CHILD in c["principal"] for c in calls)

    asyncio.run(_run())


def test_module_guarded_tool_refuses_without_a_governed_run() -> None:
    from watchlight_pydantic_ai import guarded_tool

    ran: list = []

    @guarded_tool()
    async def web_search(q: str) -> str:
        ran.append(q)
        return "ok"

    _make_plugin()
    with pytest.raises(GovernanceUnavailable):
        asyncio.run(web_search("x"))
    assert ran == []


def test_handle_bound_tool_refuses_after_its_run_ended() -> None:
    async def _run() -> None:
        plugin, mock = _make_plugin()
        async with await plugin.start_run("parent") as root:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", DeprecationWarning)

                @root.guarded_tool()
                async def web_search(q: str) -> str:
                    return "ok"

        before = len(mock.authorize_calls)
        with pytest.raises(GovernanceUnavailable):
            await web_search("x")
        assert len(mock.authorize_calls) == before

    asyncio.run(_run())


def test_handle_bound_guarded_tool_is_deprecated() -> None:
    async def _run() -> None:
        plugin, _ = _make_plugin()
        async with await plugin.start_run("parent") as root:
            with pytest.warns(DeprecationWarning, match="guarded_tool"):

                @root.guarded_tool()
                async def web_search(q: str) -> str:
                    return "ok"

    asyncio.run(_run())
