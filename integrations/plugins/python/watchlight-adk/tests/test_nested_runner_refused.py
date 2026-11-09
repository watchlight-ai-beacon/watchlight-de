"""A tool that would run an ADK agent outside Watchlight is refused.

Driven through ADK's real ``InMemoryRunner`` with the plugin on the root.
The root calls one tool, ``outer_tool``. In each case the tool's code builds
a Runner (or an App, a Workflow or an agent) with no Watchlight plugin and
runs an inner agent whose tool ``inner_danger`` would be denied. The plugin
must refuse ``outer_tool`` before its body runs, so the inner agent never
runs. The same holds for an ``AgentTool`` with ``include_plugins=False``.

A tool that could run a held agent under an invocation it makes itself
(a copied invocation context with the plugins stripped, or a fresh one) is
refused the same way.

What the code read cannot see (an agent class held in an instance
attribute, the invocation context reached by a string) is stopped by the
runtime backstop instead (``run_backstop``): the tool's body runs, but the
inner agent never takes a turn and its tool never runs. More backstop cases
are in ``test_run_backstop.py``.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any, List, Optional

import google.adk
import pytest
from google.adk import Runner
from google.adk.agents import LlmAgent
from google.adk.agents.invocation_context import InvocationContext
from google.adk.agents.run_config import RunConfig
from google.adk.apps import App
from google.adk.plugins.plugin_manager import PluginManager
from google.adk.runners import InMemoryRunner
from google.adk.sessions import InMemorySessionService
from google.adk.tools.agent_tool import AgentTool
from google.genai import types

from watchlight_adk.plugin import WatchlightPlugin

from .nested_layout import tools as layout

from .test_subagent_time_budget import (
    APP_NAME,
    ROOT_NAME,
    ROOT_SLUG,
    USER_ID,
    _call,
    _DeadlineAwareApdp,
    _final,
    _RecordingScriptedLlm,
)

EXECUTED: List[str] = []
BODIES: List[str] = []
INNER_TURNS: List[str] = []


@pytest.fixture(autouse=True)
def _reset() -> None:
    EXECUTED.clear()
    BODIES.clear()
    INNER_TURNS.clear()
    layout.BODIES.clear()


def inner_danger(target: str) -> dict:
    """A tool policy would deny."""
    EXECUTED.append("inner_danger")
    return {"ok": True}


def _inner_agent() -> LlmAgent:
    model = _RecordingScriptedLlm(model="scripted").script(
        "inner", INNER_TURNS, [_call("inner_danger", {"target": "x"}), _final("done")]
    )
    return LlmAgent(name="inner", model=model, description="Inner.", tools=[inner_danger])


async def _drain(runner: Any, text: str = "go") -> None:
    session = await runner.session_service.create_session(app_name=runner.app_name, user_id=USER_ID)
    message = types.Content(role="user", parts=[types.Part.from_text(text=text)])
    async for _ in runner.run_async(user_id=USER_ID, session_id=session.id, new_message=message):
        pass


def _plugin(apdp: _DeadlineAwareApdp) -> WatchlightPlugin:
    plugin = WatchlightPlugin(
        apdp_url="http://localhost:8081",
        tenant_id="t1",
        connect_proxy_url=None,
        log_decisions=False,
        agent_slug=ROOT_SLUG,
        root_agent_name=ROOT_NAME,
    )
    plugin.apdp = apdp  # type: ignore[assignment]
    plugin.lineage._apdp = apdp  # type: ignore[attr-defined]
    return plugin


async def _run_root(outer_tool: Any, root_turns: Optional[List[str]] = None) -> _DeadlineAwareApdp:
    apdp = _DeadlineAwareApdp()
    plugin = _plugin(apdp)
    root_turns = [] if root_turns is None else root_turns
    root_model = _RecordingScriptedLlm(model="scripted").script(
        ROOT_NAME, root_turns, [_call(outer_tool.__name__ if callable(outer_tool) else outer_tool.name, {"task": "t"}), _final("ok")]
    )
    root = LlmAgent(name=ROOT_NAME, model=root_model, description="Root.", tools=[outer_tool])
    runner = InMemoryRunner(agent=root, app_name=APP_NAME, plugins=[plugin])
    try:
        await _drain(runner)
    finally:
        await plugin.close()
    return apdp


def _assert_refused_before_the_body(apdp: _DeadlineAwareApdp) -> None:
    assert BODIES == []
    assert INNER_TURNS == []
    assert EXECUTED == []
    # Refused locally: nothing was authorized for the outer tool.
    assert not any("outer_tool" in c["resource"] for c in apdp.authorize_calls)


# ── refused before the tool body runs ─────────────────────────────────


async def _by_in_memory_runner(task: str) -> dict:
    BODIES.append("in_memory_runner")
    await _drain(InMemoryRunner(agent=_inner_agent(), app_name="nested"))
    return {"ok": True}


async def _by_runner(task: str) -> dict:
    BODIES.append("runner")
    await _drain(Runner(agent=_inner_agent(), app_name="nested", session_service=InMemorySessionService()))
    return {"ok": True}


async def _by_module_attribute(task: str) -> dict:
    BODIES.append("module_attribute")
    await _drain(google.adk.runners.InMemoryRunner(agent=_inner_agent(), app_name="nested"))
    return {"ok": True}


async def _by_app(task: str) -> dict:
    BODIES.append("app")
    await _drain(InMemoryRunner(app=App(name="nested", root_agent=_inner_agent())))
    return {"ok": True}


def _make_runner() -> Any:
    return InMemoryRunner(agent=_inner_agent(), app_name="nested")


async def _by_helper(task: str) -> dict:
    BODIES.append("helper")
    await _drain(_make_runner())
    return {"ok": True}


async def _by_agent_class(task: str) -> dict:
    """Builds only an agent (any BaseAgent subclass is refused)."""
    BODIES.append("agent_class")
    LlmAgent(name="inner2", model="gemini-2.0-flash")
    return {"ok": True}


REFUSED = {
    "in_memory_runner": _by_in_memory_runner,
    "runner": _by_runner,
    "module_attribute": _by_module_attribute,
    "app": _by_app,
    "helper": _by_helper,
    "agent_class": _by_agent_class,
}


def _as_outer(func: Any) -> Any:
    async def outer_tool(task: str) -> dict:
        """The tool the root may call."""
        return await func(task)

    return outer_tool


@pytest.mark.asyncio
@pytest.mark.parametrize("case", list(REFUSED))
async def test_a_tool_that_can_build_a_runner_is_refused_before_its_body_runs(case: str) -> None:
    apdp = await _run_root(_as_outer(REFUSED[case]))
    _assert_refused_before_the_body(apdp)


@pytest.mark.asyncio
async def test_an_agent_tool_without_plugins_is_refused() -> None:
    tool = AgentTool(agent=_inner_agent(), include_plugins=False)
    apdp = await _run_root(tool)
    assert INNER_TURNS == []
    assert EXECUTED == []
    assert not any('"inner"' in c["resource"] for c in apdp.authorize_calls)


@pytest.mark.asyncio
async def test_a_tool_that_refers_to_a_held_agent_is_not_refused() -> None:
    held = _inner_agent()

    async def outer_tool(task: str) -> dict:
        """Reads a held agent's name."""
        BODIES.append("held")
        return {"name": held.name}

    await _run_root(outer_tool)
    assert BODIES == ["held"]


# ── a held agent run under an invocation the tool makes itself ────────

_HELD_AGENT = SimpleNamespace(agent=None)


async def _held_with_plugins_stripped(task: str, tool_context: Any) -> dict:
    BODIES.append("stripped")
    ctx = tool_context._invocation_context.model_copy(update={"plugin_manager": PluginManager()})
    async for _ in _HELD_AGENT.agent.run_async(ctx):
        pass
    return {"ok": True}


async def _held_with_public_accessor(task: str, tool_context: Any) -> dict:
    BODIES.append("accessor")
    ctx = tool_context.get_invocation_context()
    async for _ in _HELD_AGENT.agent.run_async(ctx):
        pass
    return {"ok": True}


async def _held_with_fresh_context(task: str, tool_context: Any) -> dict:
    BODIES.append("fresh")
    ctx = InvocationContext(
        session_service=InMemorySessionService(),
        invocation_id="fresh",
        agent=_HELD_AGENT.agent,
        session=tool_context.session,
        run_config=RunConfig(),
    )
    async for _ in _HELD_AGENT.agent.run_async(ctx):
        pass
    return {"ok": True}


HELD_ROUTES = {
    "plugins_stripped": _held_with_plugins_stripped,
    "public_accessor": _held_with_public_accessor,
    "fresh_context": _held_with_fresh_context,
}


def _as_outer_with_context(func: Any) -> Any:
    async def outer_tool(task: str, tool_context: Any) -> dict:
        """The tool the root may call."""
        return await func(task, tool_context)

    return outer_tool


@pytest.mark.asyncio
@pytest.mark.parametrize("case", list(HELD_ROUTES))
async def test_a_tool_that_can_run_a_held_agent_under_its_own_invocation_is_refused(case: str) -> None:
    _HELD_AGENT.agent = _inner_agent()
    try:
        apdp = await _run_root(_as_outer_with_context(HELD_ROUTES[case]))
    finally:
        _HELD_AGENT.agent = None
    _assert_refused_before_the_body(apdp)


# ── the common application layout ─────────────────────────────────────


def _layout_context() -> None:
    layout.CONTEXT.update(
        drain=_drain,
        model=lambda: _RecordingScriptedLlm(model="scripted").script(
            "inner", INNER_TURNS, [_call("inner_danger", {"target": "x"}), _final("done")]
        ),
        tools=[inner_danger],
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "tool",
    [layout.tool_builds_through_an_import, layout.tool_builds_through_a_module_attribute],
    ids=["imported_factory", "helper_module_attribute"],
)
async def test_a_tool_in_a_module_that_does_not_import_adk_is_still_read(tool: Any) -> None:
    _layout_context()
    apdp = await _run_root(tool)
    assert layout.BODIES == []
    _assert_refused_before_the_body(apdp)


@pytest.mark.asyncio
async def test_a_plain_tool_in_that_layout_runs() -> None:
    await _run_root(layout.plain_tool)
    assert layout.BODIES == ["plain"]


# ── an AgentTool subclass is read like any other tool ─────────────────


class _RunsItsOwnRunner(AgentTool):
    async def run_async(self, *, args: Any, tool_context: Any) -> Any:
        BODIES.append("subclass")
        await _drain(InMemoryRunner(agent=self.agent, app_name="nested"))
        return {"ok": True}


@pytest.mark.asyncio
async def test_an_agent_tool_subclass_is_read() -> None:
    apdp = await _run_root(_RunsItsOwnRunner(agent=_inner_agent()))
    assert BODIES == []
    assert INNER_TURNS == []
    assert EXECUTED == []
    assert not any('"inner"' in c["resource"] for c in apdp.authorize_calls)


# ── indirection the read cannot see: the runtime backstop stops it ────

#: Classes held in an instance attribute: the read does not look inside
#: instances, so this tool's code names no ADK class.
_CLASSES = SimpleNamespace(agent=LlmAgent, runner=InMemoryRunner, llm=_RecordingScriptedLlm)


async def _by_instance_attribute(task: str) -> dict:
    BODIES.append("instance_attribute")
    model = _CLASSES.llm(model="scripted").script(
        "inner", INNER_TURNS, [_call("inner_danger", {"target": "x"}), _final("done")]
    )
    agent = _CLASSES.agent(name="inner", model=model, description="Inner.", tools=[inner_danger])
    await _drain(_CLASSES.runner(agent=agent, app_name="nested"))
    return {"ok": True}


BACKSTOPPED = {"instance_attribute": _by_instance_attribute}


async def _held_by_string_getattr(task: str, tool_context: Any) -> dict:
    """The reviewer's repro: the context reached by a string, so the code
    names no refused accessor, copied with the plugins replaced."""
    BODIES.append("string_getattr")
    ctx = getattr(tool_context, "_invocation" + "_context")
    plugins = type(getattr(ctx, "plugin" + "_manager"))()
    copied = ctx.model_copy(update={"plugin" + "_manager": plugins})
    async for _ in _HELD_AGENT.agent.run_async(copied):
        pass
    return {"ok": True}


@pytest.mark.asyncio
async def test_a_held_agent_under_a_copied_context_never_runs() -> None:
    _HELD_AGENT.agent = _inner_agent()
    try:
        await _run_root(_as_outer_with_context(_held_by_string_getattr))
    finally:
        _HELD_AGENT.agent = None
    assert BODIES == ["string_getattr"]
    assert INNER_TURNS == []
    assert EXECUTED == []


@pytest.mark.asyncio
@pytest.mark.parametrize("case", list(BACKSTOPPED))
async def test_an_indirect_runner_never_runs(case: str) -> None:
    await _run_root(_as_outer(BACKSTOPPED[case]))
    assert BODIES == [case]
    assert INNER_TURNS == []
    assert EXECUTED == []
