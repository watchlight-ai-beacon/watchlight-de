"""Nothing in the plugin assumes the networked backend or the concrete run
handle type. The Developer Edition builds the plugin with an in-process
backend (``governance=``) and a subclass whose ``start_run`` hands out a
delegating wrapper around each run handle; both must govern exactly as the
plain plugin does."""

from __future__ import annotations

from typing import Any, List

import pytest
from conftest import AGENTS, ScriptedModel, spawned_agents, text, tool_call
from strands import Agent, tool
from watchlight_core_testing import MockApdpClient
from watchlight_strands import WatchlightStrandsPlugin

ran: List[str] = []


@pytest.fixture(autouse=True)
def _reset_ran() -> None:
    ran.clear()


@tool
def search(q: str) -> str:
    """Search."""
    ran.append(q)
    return "hits"


# In-process stand-in for unit tests only: a delegating handle wrapper of
# the kind the Developer Edition hands out (not a BaseRunHandle subclass).
class DelegatingHandle:
    __slots__ = ("_inner", "wrapped_calls")

    def __init__(self, inner: Any) -> None:
        object.__setattr__(self, "_inner", inner)
        object.__setattr__(self, "wrapped_calls", [])

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)

    def __setattr__(self, name: str, value: Any) -> None:
        setattr(self._inner, name, value)

    async def __aenter__(self) -> "DelegatingHandle":  # noqa: PYI034 — mirrors the wrapper it stands in for
        await self._inner.__aenter__()
        return self

    async def __aexit__(self, *exc_info: object) -> Any:
        return await self._inner.__aexit__(*exc_info)

    async def authorize_action_detailed(self, *args: Any, **kwargs: Any) -> Any:
        self.wrapped_calls.append(kwargs.get("resource"))
        return await self._inner.authorize_action_detailed(*args, **kwargs)

    async def spawn_subagent(self, *args: Any, **kwargs: Any) -> Any:
        return DelegatingHandle(await self._inner.spawn_subagent(*args, **kwargs))


class WrappingPlugin(WatchlightStrandsPlugin):
    async def start_run(self, *args: Any, **kwargs: Any) -> Any:
        return DelegatingHandle(await super().start_run(*args, **kwargs))


def test_a_governance_backend_and_wrapped_handles_govern_the_whole_tree(mock_apdp: MockApdpClient) -> None:
    mock_apdp.decisions[("execute", "search")] = "Deny"
    mock_apdp.decisions[("execute", "search_ok")] = "Allow"
    child = Agent(
        name="researcher",
        model=ScriptedModel([[tool_call("search", {"q": "x"})], [text("child done")]]),
        tools=[search],
        callback_handler=None,
    )
    plugin = WrappingPlugin(
        apdp_url="http://localhost",
        agent_slug="agent-root",
        governance=mock_apdp,  # type: ignore[arg-type]
        log_decisions=False,
    )
    assert plugin.apdp is mock_apdp
    parent = Agent(
        model=ScriptedModel([[tool_call("researcher", {"input": "go"})], [text("done")]]),
        tools=[child.as_tool()],
        plugins=[plugin],
        callback_handler=None,
    )

    parent("go")

    assert ran == []  # the child's tool was denied through the wrapped child handle
    assert len(mock_apdp.spawn_subagent_calls) == 1
    # No agent_map entry: the child runs as its parent's agent.
    assert spawned_agents(mock_apdp) == [AGENTS["agent-root"]]
    assert len(mock_apdp._closed_sessions) == 2
