"""No agent runs outside Watchlight while a governed run is live.

The shared nested-agent conformance case, through ADK's real
``InMemoryRunner``: the root may call only ``outer_tool``. Its body runs an
inner agent whose tool ``inner_danger`` would be denied, by a route the code
read in ``nested_runs`` cannot see (classes held in an instance attribute,
the invocation context reached by a string). The inner agent must never take
a turn and its tool must never run, on every route:

* a Runner with no plugins, or with an explicitly empty plugin list;
* the run's own invocation context with the plugins stripped;
* a raw thread, and a fresh ``contextvars.Context``;
* an inner function call that reuses the outer tool call's id;
* a function call an agent callback makes up without a model turn.

Nothing changes while no governed run is live, and a governed run is
refused if a wrap was replaced. A governed ``AgentTool`` child still runs
with the backstop installed: ``test_concurrent_runs.py``
(``test_many_concurrent_runs_one_with_an_agent_tool_child``) authorizes its
tool calls under its own child execution.
"""

from __future__ import annotations

import asyncio
import contextvars
import threading
from types import SimpleNamespace
from typing import Any, List

import pytest
from google.adk.agents import LlmAgent
from google.adk.models.llm_request import LlmRequest
from google.adk.models.llm_response import LlmResponse
from google.adk.plugins.base_plugin import BasePlugin
from google.adk.plugins.plugin_manager import PluginManager
from google.adk.runners import InMemoryRunner
from google.genai import types

from watchlight_adk import run_backstop
from watchlight_adk.plugin import WatchlightPlugin

from .test_nested_runner_refused import (
    BODIES,
    EXECUTED,
    INNER_TURNS,
    _as_outer,
    _as_outer_with_context,
    _drain,
    _run_root,
    inner_danger,
)
from .test_subagent_time_budget import (
    APP_NAME,
    CHILD_NAME,
    CHILD_SLUG,
    ROOT_NAME,
    ROOT_RUN_HANDLE,
    ROOT_SLUG,
    _call,
    _DeadlineAwareApdp,
    _final,
    _RecordingScriptedLlm,
)


@pytest.fixture(autouse=True)
def _reset() -> None:
    # Installed by the first WatchlightPlugin; a test that builds none
    # still needs the wraps.
    run_backstop.install()
    EXECUTED.clear()
    BODIES.clear()
    INNER_TURNS.clear()


#: Held in an instance attribute, so the code read sees no ADK name.
_ADK = SimpleNamespace(
    runner=InMemoryRunner,
    plugins=PluginManager,
    agent=LlmAgent,
    llm=_RecordingScriptedLlm,
)


def _inner() -> Any:
    """The inner agent, built only through the held classes."""
    model = _ADK.llm(model="scripted").script(
        "inner", INNER_TURNS, [_call("inner_danger", {"target": "x"}), _final("done")]
    )
    return _ADK.agent(name="inner", model=model, description="Inner.", tools=[inner_danger])


def _assert_inner_never_ran(case: str) -> None:
    assert BODIES == [case], "the outer tool's body runs: the backstop, not the read, stops this"
    assert INNER_TURNS == []
    assert EXECUTED == []
    assert not run_backstop.live(), "the run is no longer live once it ends"


# ── routes the code read cannot see ───────────────────────────────────


async def _no_plugins(task: str) -> dict:
    BODIES.append("no_plugins")
    await _drain(_ADK.runner(agent=_inner(), app_name="nested"))
    return {"ok": True}


async def _empty_plugins(task: str) -> dict:
    BODIES.append("empty_plugins")
    await _drain(_ADK.runner(agent=_inner(), app_name="nested", plugins=[]))
    return {"ok": True}


def _in_thread(fresh_context: bool) -> Any:
    async def body(task: str) -> dict:
        BODIES.append("fresh_context" if fresh_context else "raw_thread")
        runner = _ADK.runner(agent=_inner(), app_name="nested")
        errors: List[BaseException] = []

        def target() -> None:
            try:
                if fresh_context:
                    contextvars.Context().run(asyncio.run, _drain(runner))
                else:
                    asyncio.run(_drain(runner))
            except BaseException as exc:  # noqa: BLE001 — reported below
                errors.append(exc)

        thread = threading.Thread(target=target)
        thread.start()
        await asyncio.get_running_loop().run_in_executor(None, thread.join)
        assert errors == []
        return {"ok": True}

    return body


class _LookAlike(BasePlugin):
    """A plugin that only looks like Watchlight's: the old class marker and
    the plugin's name, but never constructed as a ``WatchlightPlugin``."""

    _WATCHLIGHT_GOVERNS = True

    def __init__(self) -> None:
        super().__init__(name="watchlight_agent_runtime_governance")


async def _look_alike_plugin(task: str) -> dict:
    BODIES.append("look_alike_plugin")
    await _drain(_ADK.runner(agent=_inner(), app_name="nested", plugins=[_LookAlike()]))
    return {"ok": True}


ROUTES = {
    "no_plugins": _no_plugins,
    "empty_plugins": _empty_plugins,
    "look_alike_plugin": _look_alike_plugin,
    "raw_thread": _in_thread(False),
    "fresh_context": _in_thread(True),
}


@pytest.mark.asyncio
@pytest.mark.parametrize("case", list(ROUTES))
async def test_an_inner_runner_never_runs(case: str) -> None:
    await _run_root(_as_outer(ROUTES[case]))
    _assert_inner_never_ran(case)


async def _run_under(agent: Any, ctx: Any) -> List[Any]:
    """Run ``agent`` under ``ctx`` to the end."""
    return [event async for event in agent.run_async(ctx)]


def _stripped(ctx: Any) -> Any:
    plugins = _ADK.plugins()
    return ctx.model_copy(update={"plugin" + "_manager": plugins})


async def _reused_call_id(task: str, tool_context: Any) -> dict:
    """The inner model calls its tool with the outer call's id."""
    BODIES.append("reused_call_id")
    call_id = tool_context.function_call_id
    call = LlmResponse(
        content=types.Content(
            role="model",
            parts=[types.Part(function_call=types.FunctionCall(id=call_id, name="inner_danger", args={"target": "x"}))],
        )
    )
    model = _ADK.llm(model="scripted").script("inner", INNER_TURNS, [call, _final("done")])
    agent = _ADK.agent(name="inner", model=model, description="Inner.", tools=[inner_danger])
    ctx = getattr(tool_context, "_invocation" + "_context")
    await _run_under(agent, _stripped(ctx))
    return {"ok": True}


async def _callback_made_call(task: str, tool_context: Any) -> dict:
    """An agent callback answers the model turn with a function call, so no
    model is called."""
    BODIES.append("callback_made_call")

    def answer(**_kwargs: Any) -> LlmResponse:
        # Once, then a final answer, so the agent ends either way.
        INNER_TURNS.append("callback")
        if INNER_TURNS.count("callback") > 1:
            return _final("done")
        return _call("inner_danger", {"target": "x"})

    model = _ADK.llm(model="scripted").script("inner", INNER_TURNS, [_final("done")])
    agent = _ADK.agent(
        name="inner", model=model, description="Inner.", tools=[inner_danger], before_model_callback=answer
    )
    ctx = getattr(tool_context, "_invocation" + "_context")
    await _run_under(agent, _stripped(ctx))
    return {"ok": True}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "case,body",
    [("reused_call_id", _reused_call_id), ("callback_made_call", _callback_made_call)],
)
async def test_an_inner_agent_under_the_runs_own_context_never_runs(case: str, body: Any) -> None:
    await _run_root(_as_outer_with_context(body))
    _assert_inner_never_ran(case)


# ── the choke points themselves ───────────────────────────────────────


@pytest.mark.asyncio
async def test_with_a_run_live_an_ungoverned_tool_or_tool_binding_turn_is_refused() -> None:
    plugins = PluginManager()
    tool_req = LlmRequest(config=types.GenerateContentConfig(tools=[types.Tool(function_declarations=[])]))
    run_backstop._enter()
    try:
        assert run_backstop.live()
        refused = await plugins.run_before_tool_callback(tool=object(), tool_args={}, tool_context=object())
        assert refused == {"result": run_backstop.REFUSAL}
        turn = await plugins.run_before_model_callback(callback_context=object(), llm_request=tool_req)
        assert isinstance(turn, LlmResponse)
        # A turn that offers no tool (a summary) is not refused.
        plain = await plugins.run_before_model_callback(callback_context=object(), llm_request=LlmRequest())
        assert plain is None
    finally:
        run_backstop._leave()


def test_only_a_constructed_watchlight_plugin_governs() -> None:
    assert run_backstop.governs(PluginManager(plugins=[_LookAlike()])) is False
    plugin = WatchlightPlugin(
        apdp_url="http://localhost:8081", log_decisions=False, agent_slug=ROOT_SLUG, root_agent_name=ROOT_NAME
    )
    assert run_backstop.governs(PluginManager(plugins=[plugin])) is True
    assert run_backstop.governs(object()) is False


class _EqualToAll(BasePlugin):
    """Compares equal to any object and hashes like the real plugin."""

    def __init__(self, twin: Any) -> None:
        super().__init__(name="watchlight_agent_runtime_governance")
        self._twin = twin

    def __eq__(self, other: object) -> bool:
        return True

    def __hash__(self) -> int:
        return hash(self._twin)


def test_a_plugin_that_compares_equal_to_a_watchlight_plugin_does_not_govern() -> None:
    plugin = WatchlightPlugin(
        apdp_url="http://localhost:8081", log_decisions=False, agent_slug=ROOT_SLUG, root_agent_name=ROOT_NAME
    )
    assert run_backstop.governs(PluginManager(plugins=[_EqualToAll(plugin)])) is False
    assert run_backstop.governs(PluginManager(plugins=[plugin])) is True


def test_a_registry_entry_dropped_while_the_lock_is_held_does_not_hang() -> None:
    """The collector can run the weakref callback while this thread holds
    the backstop's lock (an allocation inside ``register`` or ``governs``)."""

    class _Plugin:
        pass

    done: List[bool] = []

    def drop_under_the_lock() -> None:
        plugin = _Plugin()
        run_backstop.register(plugin)
        with run_backstop._lock:
            del plugin  # the callback runs here, on this thread
            done.append(True)

    thread = threading.Thread(target=drop_under_the_lock, daemon=True)
    thread.start()
    thread.join(5)
    assert not thread.is_alive(), "the callback blocked on the lock its own thread holds"
    assert done == [True]


def test_an_unreadable_model_request_counts_as_binding_tools() -> None:
    assert run_backstop.binds_tools(object()) is True
    assert run_backstop.binds_tools(LlmRequest()) is False


# ── what still runs ───────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_with_no_governed_run_live_nothing_changes() -> None:
    assert not run_backstop.live()
    await _drain(InMemoryRunner(agent=_inner(), app_name="ungoverned"))
    assert EXECUTED == ["inner_danger"]


# ── the wraps stay in place ───────────────────────────────────────────


def test_installing_again_changes_nothing() -> None:
    before = PluginManager.run_before_tool_callback
    run_backstop.install()
    assert PluginManager.run_before_tool_callback is before
    assert run_backstop.intact()


@pytest.mark.asyncio
async def test_a_governed_run_is_refused_when_a_wrap_was_replaced(monkeypatch: pytest.MonkeyPatch) -> None:
    replaced = PluginManager.run_before_tool_callback.__wrapped__  # type: ignore[attr-defined]
    monkeypatch.setattr(PluginManager, "run_before_tool_callback", replaced)
    assert not run_backstop.intact()
    turns: List[str] = []
    await _run_root(_as_outer(_no_plugins), root_turns=turns)
    # Refused at the run (ADK 2.13) or at the root's first model turn (ADK
    # 2.5's node runtime ignores a run-level refusal): the root never calls
    # its tool, and no model is called.
    assert turns == []
    assert BODIES == []
    assert EXECUTED == []


# ── from inside a governed tool body ──────────────────────────────────

#: The governed run's plugin and an inner-agent builder, held where the
#: code read sees no ADK name.
_HELD = SimpleNamespace(plugin=None, inner_name="inner")


def _inner_named() -> Any:
    model = _ADK.llm(model="scripted").script(
        _HELD.inner_name, INNER_TURNS, [_call("inner_danger", {"target": "x"}), _final("done")]
    )
    return _ADK.agent(name=_HELD.inner_name, model=model, description="Inner.", tools=[inner_danger])


async def _run_governed_root(outer_tool: Any, **plugin_kwargs: Any) -> Any:
    """The root runs ``outer_tool`` under a governed run; the tool body
    can reach the run's own plugin through ``_HELD``."""
    apdp = _DeadlineAwareApdp()
    plugin = WatchlightPlugin(
        apdp_url="http://localhost:8081",
        tenant_id="t1",
        connect_proxy_url=None,
        log_decisions=False,
        agent_slug=ROOT_SLUG,
        root_agent_name=ROOT_NAME,
        **plugin_kwargs,
    )
    plugin.apdp = apdp  # type: ignore[assignment]
    plugin.lineage._apdp = apdp  # type: ignore[attr-defined]
    _HELD.plugin = plugin
    root_model = _RecordingScriptedLlm(model="scripted").script(
        ROOT_NAME, [], [_call(outer_tool.__name__, {"task": "t"}), _final("ok")]
    )
    root = LlmAgent(name=ROOT_NAME, model=root_model, description="Root.", tools=[outer_tool])
    try:
        await _drain(InMemoryRunner(agent=root, app_name=APP_NAME, plugins=[plugin]))
    finally:
        _HELD.plugin = None
        await plugin.close()
    return apdp


async def _fresh_runner_awaited(task: str) -> dict:
    BODIES.append("fresh_awaited")
    await _drain(_ADK.runner(agent=_inner(), app_name="nested"))
    return {"ok": True}


async def _fresh_runner_in_a_task(task: str) -> dict:
    BODIES.append("fresh_task")
    await asyncio.create_task(_drain(_ADK.runner(agent=_inner(), app_name="nested")))
    return {"ok": True}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "case,body", [("fresh_awaited", _fresh_runner_awaited), ("fresh_task", _fresh_runner_in_a_task)]
)
async def test_a_fresh_runner_without_watchlight_in_a_governed_tool_body_never_runs(case: str, body: Any) -> None:
    await _run_governed_root(_as_outer(body))
    _assert_inner_never_ran(case)


async def _same_plugin(task: str) -> dict:
    BODIES.append("same_plugin")
    await _drain(_ADK.runner(agent=_inner_named(), app_name="nested", plugins=[_HELD.plugin]))
    return {"ok": True}


@pytest.mark.asyncio
async def test_the_runs_own_plugin_on_an_unmapped_root_never_runs_it() -> None:
    """STRICT: the inner agent has no slug, so under the run's own plugin
    it has no governed identity and is refused."""
    _HELD.inner_name = "inner"
    apdp = await _run_governed_root(_as_outer(_same_plugin))
    _assert_inner_never_ran("same_plugin")
    assert apdp.spawn_bodies == []
    assert apdp.create_session.await_count == 1, "no second root session"


@pytest.mark.asyncio
async def test_the_runs_own_plugin_on_a_mapped_sub_agent_runs_it_as_a_spawn_never_a_root() -> None:
    _HELD.inner_name = CHILD_NAME
    try:
        apdp = await _run_governed_root(_as_outer(_same_plugin), subagent_slugs={CHILD_NAME: CHILD_SLUG})
    finally:
        _HELD.inner_name = "inner"
    assert BODIES == ["same_plugin"]
    assert INNER_TURNS, "the mapped sub-agent runs"
    assert len(apdp.spawn_bodies) == 1, "as one spawn under the tool's agent"
    assert apdp.create_session.await_count == 1, "never as a second root"
    child_calls = [c for c in apdp.authorize_calls if "inner_danger" in c["resource"]]
    assert child_calls and all(c["run_handle_id"] != ROOT_RUN_HANDLE for c in child_calls)
    assert not run_backstop.live()
