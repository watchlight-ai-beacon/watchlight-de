"""The per-call backstop on every ``strands`` model call.

Real Strands agents and the real OpenAI SDK; only the transport is a
stand-in (``httpx.MockTransport``). Each case is first shown to reach the
provider without the plugin. The model's configuration enables the hosted
tool ``web_search`` (``params={"web_search_options": {}}``).
"""

from __future__ import annotations

import asyncio
import contextvars
import json
import threading
import weakref
from concurrent.futures import ThreadPoolExecutor
from typing import Any, List

import pytest
from conftest import ScriptedModel, events_of, text, tool_call
from strands import Agent, tool
from strands.hooks import AfterInvocationEvent, BeforeModelCallEvent, BeforeToolCallEvent
from strands.models import Model
from test_reachable_models import Holder, Wire, openai_model, web_search_decisions
from watchlight_core.hosted_tools import HostedToolRefused
from watchlight_core_testing import MockApdpClient
from watchlight_strands import model_backstop
from watchlight_strands.aux_models import UngovernedModelCall
from watchlight_strands.model_reach import UngovernedModelUse

PROMPT = [{"role": "user", "content": [{"text": "hi"}]}]


async def _drain(model: Any) -> None:
    async for _ in model.stream(PROMPT):
        pass


@pytest.fixture
def deny_web_search(mock_apdp: MockApdpClient) -> MockApdpClient:
    mock_apdp.decisions[("execute", "web_search")] = "Deny"
    return mock_apdp


def test_every_model_class_is_wrapped_now_and_later(make_plugin):
    from strands.models.openai import OpenAIModel

    make_plugin("agent-root")
    assert getattr(OpenAIModel.__dict__["stream"], "__watchlight_backstop__", False)
    assert getattr(ScriptedModel.__dict__["stream"], "__watchlight_backstop__", False)

    class Later(ScriptedModel):
        async def stream(self, *args: Any, **kwargs: Any) -> Any:  # type: ignore[override]
            async for event in super().stream(*args, **kwargs):
                yield event

    assert getattr(Later.__dict__["stream"], "__watchlight_backstop__", False)


# ── a model built inside a tool body ────────────────────────────────


def _lazy_agent(wire: Wire, plugins: List[Any], main: Any) -> Agent:
    @tool
    def research(q: str) -> str:
        """Research with a model the body builds."""
        asyncio.run(_drain(openai_model(wire)))
        return "researched"

    return Agent(model=main, tools=[research], plugins=plugins, callback_handler=None)


def test_a_model_built_in_a_tool_body_reaches_the_provider_without_the_plugin(mock_apdp: MockApdpClient):
    wire = Wire(mock_apdp)
    main = ScriptedModel([[tool_call("research", {"q": "x"})], [text("done")]])
    _lazy_agent(wire, [], main)("hi")
    assert wire.with_hosted_tool()


def test_a_denied_hosted_tool_on_a_model_built_in_a_tool_body_never_reaches_the_provider(
    make_plugin, deny_web_search: MockApdpClient
):
    wire = Wire(deny_web_search)
    main = ScriptedModel([[tool_call("research", {"q": "x"})], [text("done")]])
    _lazy_agent(wire, [make_plugin("agent-root")], main)("hi")

    assert wire.requests == []
    assert len(web_search_decisions(deny_web_search)) == 1
    assert any("provider-hosted tool" in t for t in main.tool_result_texts())


def test_an_allowed_hosted_tool_on_a_model_built_in_a_tool_body_is_decided_first(
    make_plugin, mock_apdp: MockApdpClient
):
    wire = Wire(mock_apdp)
    main = ScriptedModel([[tool_call("research", {"q": "x"})], [text("done")]])
    _lazy_agent(wire, [make_plugin("agent-root")], main)("hi")
    assert wire.with_hosted_tool()
    assert wire.decided_before[0] == 1


# ── a model a component's method reads from a module global ─────────

GLOBAL: dict = {}


class Researcher:
    """Calls a module-level model from a method that is not registered
    anywhere, so the invocation-start walk does not reach it."""

    async def on_tool(self, event: Any) -> None:
        await self._ask()

    async def _ask(self) -> None:
        await _drain(GLOBAL["model"])


def test_a_module_level_model_a_method_uses_is_checked_when_called(make_plugin, deny_web_search: MockApdpClient):
    wire = Wire(deny_web_search)
    GLOBAL["model"] = openai_model(wire)
    try:
        main = ScriptedModel([[tool_call("noop", {})], [text("done")]])

        @tool
        def noop() -> str:
            """Do nothing."""
            return "ok"

        agent = Agent(model=main, tools=[noop], plugins=[make_plugin("agent-root")], callback_handler=None)
        agent.hooks.add_callback(BeforeToolCallEvent, Researcher().on_tool)
        # Strands wraps an error raised in the event loop.
        with pytest.raises(Exception) as raised:
            agent("hi")
        chain = [raised.value, raised.value.__cause__, raised.value.__context__]
        assert any(isinstance(e, HostedToolRefused) for e in chain) or "provider-hosted tool" in str(raised.value)
        assert wire.requests == []
        assert len(web_search_decisions(deny_web_search)) == 1
    finally:
        GLOBAL.clear()


# ── calls after the run ─────────────────────────────────────────────


def _post_run_agent(wire: Wire, plugins: List[Any]) -> Agent:
    model = openai_model(wire)
    agent = Agent(model=ScriptedModel([[text("done")]]), plugins=plugins, callback_handler=None)

    async def after(event: Any) -> None:
        await _drain(model)

    # Default order: after the plugin has closed the run.
    agent.hooks.add_callback(AfterInvocationEvent, after)
    return agent


def test_a_post_run_model_call_reaches_the_provider_without_the_plugin(mock_apdp: MockApdpClient):
    wire = Wire(mock_apdp)
    _post_run_agent(wire, [])("hi")
    assert wire.requests


def test_a_model_call_after_the_run_has_ended_is_refused(make_plugin, mock_apdp: MockApdpClient):
    wire = Wire(mock_apdp)
    agent = _post_run_agent(wire, [make_plugin("agent-root")])
    with pytest.raises(UngovernedModelCall, match="outside any open governed run"):
        agent("hi")
    assert wire.requests == []
    assert events_of(mock_apdp, "execution_completed") or events_of(mock_apdp, "execution_failed")


def test_a_model_call_outside_any_governed_invocation_is_not_checked(make_plugin, deny_web_search: MockApdpClient):
    make_plugin("agent-root")
    wire = Wire(deny_web_search)
    asyncio.run(_drain(openai_model(wire)))
    assert wire.requests and web_search_decisions(deny_web_search) == []


# ── what the invocation-start walk reads ────────────────────────────


def test_a_model_in_a_class_level_container_is_found_by_the_walk(make_plugin, deny_web_search: MockApdpClient):
    wire = Wire(deny_web_search)

    class Component:
        MODELS = {"judge": openai_model(wire)}

        def on_model(self, event: Any) -> None:
            pass

    main = ScriptedModel([[text("done")]])
    agent = Agent(model=main, plugins=[make_plugin("agent-root")], callback_handler=None)
    agent.hooks.add_callback(BeforeModelCallEvent, Component().on_model)
    with pytest.raises(HostedToolRefused):
        agent("hi")
    # Refused when the run opened, before the first model call.
    assert main.calls == 0 and wire.requests == []


def test_a_weak_reference_is_read_without_its_own_call(make_plugin, deny_web_search: MockApdpClient):
    calls: List[int] = []

    class Hostile(weakref.ref):
        def __call__(self) -> Any:
            calls.append(1)
            return None

    wire = Wire(deny_web_search)
    model = openai_model(wire)
    main = ScriptedModel([[text("done")]])
    agent = Agent(model=main, plugins=[make_plugin("agent-root")], callback_handler=None)
    holder = Holder(Hostile(model))
    agent.hooks.add_callback(BeforeModelCallEvent, lambda event: holder)
    with pytest.raises(HostedToolRefused):
        agent("hi")
    assert calls == [] and main.calls == 0


# ── agents reachable when the invocation starts ─────────────────────


def test_an_unattachable_agent_used_as_a_tool_refuses_the_invocation(make_plugin, mock_apdp: MockApdpClient):
    from test_reachable_models import _unattachable_child

    child = _unattachable_child()
    main = ScriptedModel([[tool_call("helper", {"input": "x"})], [text("done")]])
    agent = Agent(model=main, tools=[child.as_tool()], plugins=[make_plugin("agent-root")], callback_handler=None)
    with pytest.raises(UngovernedModelUse, match="can reach cannot be governed"):
        agent("hi")
    assert main.calls == 0 and child.model.calls == 0
    (failed,) = events_of(mock_apdp, "execution_failed")
    assert "UngovernedModelUse" in json.dumps(failed)


def test_backstop_marks_governed_contexts_only(make_plugin):
    make_plugin("agent-root")
    assert model_backstop.GOVERNED_CONTEXT.get() is False
    assert issubclass(ScriptedModel, Model)


# ── calls that lose the governed context ────────────────────────────


def _in_thread(fn: Any) -> None:
    thread = threading.Thread(target=fn)
    thread.start()
    thread.join()


def _spawn(kind: str, wire: Wire, outcome: List[Any]) -> Any:
    """A tool whose body builds a model and calls it through one spawn path,
    and records the call's outcome (``"ran"`` or the exception). The model
    exists only inside the call, so only the per-call backstop sees it."""

    def call_sync() -> None:
        try:
            asyncio.run(_drain(openai_model(wire)))
            outcome.append("ran")
        except Exception as exc:  # noqa: BLE001 - recorded for the test
            outcome.append(exc)

    async def call_async() -> None:
        try:
            await _drain(openai_model(wire))
            outcome.append("ran")
        except Exception as exc:  # noqa: BLE001 - recorded for the test
            outcome.append(exc)

    if kind == "thread":

        @tool
        def work() -> str:
            """Work in a thread."""
            _in_thread(call_sync)
            return "done"

    elif kind == "run_in_executor":

        @tool
        async def work() -> str:  # type: ignore[no-redef]
            """Work in the default executor."""
            await asyncio.get_running_loop().run_in_executor(None, call_sync)
            return "done"

    elif kind == "thread_pool":

        @tool
        def work() -> str:  # type: ignore[no-redef]
            """Work in a thread pool."""
            with ThreadPoolExecutor(max_workers=1) as pool:
                pool.submit(call_sync).result()
            return "done"

    elif kind == "fresh_context_task":

        @tool
        async def work() -> str:  # type: ignore[no-redef]
            """Work in a task with a fresh context."""
            await asyncio.get_running_loop().create_task(call_async(), context=contextvars.Context())
            return "done"

    else:  # to_thread: copies the context

        @tool
        async def work() -> str:  # type: ignore[no-redef]
            """Work through asyncio.to_thread."""
            await asyncio.to_thread(call_sync)
            return "done"

    return work


SPAWNS = ["thread", "run_in_executor", "thread_pool", "fresh_context_task"]


@pytest.mark.parametrize("kind", SPAWNS + ["to_thread"])
def test_a_spawned_model_call_reaches_the_provider_without_the_plugin(mock_apdp: MockApdpClient, kind: str):
    wire = Wire(mock_apdp)
    outcome: List[Any] = []
    main = ScriptedModel([[tool_call("work", {})], [text("done")]])
    Agent(model=main, tools=[_spawn(kind, wire, outcome)], callback_handler=None)("hi")
    assert outcome == ["ran"] and wire.with_hosted_tool()


@pytest.mark.parametrize("kind", SPAWNS)
def test_a_model_call_that_loses_the_governed_context_is_refused(make_plugin, mock_apdp: MockApdpClient, kind: str):
    wire = Wire(mock_apdp)
    outcome: List[Any] = []
    main = ScriptedModel([[tool_call("work", {})], [text("done")]])
    agent = Agent(model=main, tools=[_spawn(kind, wire, outcome)],
                  plugins=[make_plugin("agent-root")], callback_handler=None)
    agent("hi")
    (error,) = outcome
    assert isinstance(error, UngovernedModelCall) and "outside any open governed run" in str(error)
    assert wire.requests == []


def test_asyncio_to_thread_keeps_the_governed_run(make_plugin, deny_web_search: MockApdpClient):
    wire = Wire(deny_web_search)
    outcome: List[Any] = []
    main = ScriptedModel([[tool_call("work", {})], [text("done")]])
    agent = Agent(model=main, tools=[_spawn("to_thread", wire, outcome)],
                  plugins=[make_plugin("agent-root")], callback_handler=None)
    agent("hi")
    (error,) = outcome
    # Checked against the run: the hosted tool was decided and denied.
    assert isinstance(error, HostedToolRefused)
    assert len(web_search_decisions(deny_web_search)) == 1 and wire.requests == []


def test_direct_model_use_is_allowed_and_logged(make_plugin, mock_apdp: MockApdpClient, caplog):
    import watchlight_strands

    wire = Wire(mock_apdp)
    outcome: List[Any] = []

    def direct() -> None:
        with watchlight_strands.direct_model_use():
            asyncio.run(_drain(openai_model(wire)))
        outcome.append("ran")

    @tool
    def work() -> str:
        """Own direct model use in a thread."""
        _in_thread(direct)
        return "done"

    main = ScriptedModel([[tool_call("work", {})], [text("done")]])
    agent = Agent(model=main, tools=[work], plugins=[make_plugin("agent-root")], callback_handler=None)
    with caplog.at_level("WARNING"):
        agent("hi")
    assert outcome == ["ran"] and wire.requests
    assert web_search_decisions(mock_apdp) == []
    (record,) = [r for r in caplog.records if "direct model use declared" in r.getMessage()]
    assert "test_model_backstop.py:" in record.getMessage()


def test_direct_model_use_never_lifts_the_check_inside_a_live_run(make_plugin, deny_web_search: MockApdpClient):
    import watchlight_strands

    wire = Wire(deny_web_search)

    @tool
    async def work() -> str:
        """Claims direct use inside the governed run."""
        with watchlight_strands.direct_model_use():
            await _drain(openai_model(wire))
        return "done"

    main = ScriptedModel([[tool_call("work", {})], [text("done")]])
    Agent(model=main, tools=[work], plugins=[make_plugin("agent-root")], callback_handler=None)("hi")
    assert wire.requests == []
    assert len(web_search_decisions(deny_web_search)) == 1


# ── the live-run count goes back to zero on every exit ──────────────


def _live() -> int:
    return model_backstop.live_run_count()


def test_the_live_run_count_drops_after_a_normal_run(make_plugin, mock_apdp: MockApdpClient):
    seen: List[int] = []

    @tool
    def peek() -> str:
        """Record the count."""
        seen.append(_live())
        return "ok"

    assert _live() == 0
    main = ScriptedModel([[tool_call("peek", {})], [text("done")]])
    Agent(model=main, tools=[peek], plugins=[make_plugin("agent-root")], callback_handler=None)("hi")
    assert seen == [1] and _live() == 0


def test_the_live_run_count_drops_after_a_failed_run(make_plugin, mock_apdp: MockApdpClient):
    class Boom(ScriptedModel):
        async def stream(self, *args: Any, **kwargs: Any) -> Any:  # type: ignore[override]
            raise RuntimeError("model failed")
            yield  # noqa: unreachable - makes this an async generator

    assert _live() == 0
    agent = Agent(model=Boom([]), plugins=[make_plugin("agent-root")], callback_handler=None)
    with pytest.raises(Exception):
        agent("hi")
    assert _live() == 0


def test_the_live_run_count_drops_after_a_cancelled_run(make_plugin, mock_apdp: MockApdpClient):
    started = threading.Event()

    @tool
    async def slow() -> str:
        """Wait to be cancelled."""
        started.set()
        await asyncio.sleep(30)
        return "late"

    main = ScriptedModel([[tool_call("slow", {})], [text("done")]])
    agent = Agent(model=main, tools=[slow], plugins=[make_plugin("agent-root")], callback_handler=None)

    async def go() -> None:
        task = asyncio.ensure_future(agent.invoke_async("hi"))
        while not started.is_set():
            await asyncio.sleep(0.01)
        assert _live() == 1
        task.cancel()
        with pytest.raises(BaseException):
            await task

    assert _live() == 0
    asyncio.run(go())
    assert _live() == 0


# ── models whose calls would skip the backstop ──────────────────────


def test_a_model_whose_class_stream_was_replaced_is_refused(make_plugin, mock_apdp: MockApdpClient):
    class Replaced(ScriptedModel):
        pass

    async def raw_stream(self: Any, *args: Any, **kwargs: Any) -> Any:
        yield {"messageStart": {"role": "assistant"}}

    Replaced.stream = raw_stream  # type: ignore[method-assign]
    model = Replaced([[text("x")]])
    agent = Agent(model=model, plugins=[make_plugin("agent-root")], callback_handler=None)
    with pytest.raises(UngovernedModelCall, match="replaced"):
        agent("hi")


def test_a_model_with_an_instance_stream_is_refused(make_plugin, mock_apdp: MockApdpClient):
    main = ScriptedModel([[text("done")]])
    agent = Agent(model=main, plugins=[make_plugin("agent-root")], callback_handler=None)
    shadowed = ScriptedModel([[text("x")]])

    async def raw_stream(*args: Any, **kwargs: Any) -> Any:
        yield {"messageStart": {"role": "assistant"}}

    shadowed.stream = raw_stream  # type: ignore[method-assign]
    holder = Holder(shadowed)
    agent.hooks.add_callback(BeforeModelCallEvent, lambda event: holder)
    with pytest.raises(UngovernedModelCall, match="replaced"):
        agent("hi")
    assert main.calls == 0


# How Python resolves ``stream``, not only the instance and class dicts.


class _Skipped:
    """Records a call that skipped the backstop."""

    calls = 0


async def _raw_stream(self: Any, *args: Any, **kwargs: Any) -> Any:
    _Skipped.calls += 1
    yield {"messageStart": {"role": "assistant"}}


def _refused_and_never_called(model: Any, make_plugin: Any) -> None:
    _Skipped.calls = 0
    assert not model_backstop.has_backstop(model)
    agent = Agent(model=model, plugins=[make_plugin("agent-root")], callback_handler=None)
    with pytest.raises(UngovernedModelCall, match="replaced"):
        agent("hi")
    assert _Skipped.calls == 0


def test_a_property_over_stream_on_the_class_is_refused(make_plugin, mock_apdp: MockApdpClient):
    """A data descriptor on the class wins over the instance dict."""
    import types

    class Shadowed(ScriptedModel):
        pass

    model = Shadowed([[text("x")]])
    # the wrapped method in the instance dict, which the property hides
    model.__dict__["stream"] = types.MethodType(ScriptedModel.__dict__["stream"], model)
    Shadowed.stream = property(lambda self: types.MethodType(_raw_stream, self))  # type: ignore[assignment]
    _refused_and_never_called(model, make_plugin)


def test_a_class_that_redefines_getattribute_is_refused(make_plugin, mock_apdp: MockApdpClient):
    import types

    class Redirecting(ScriptedModel):
        def __getattribute__(self, name: str) -> Any:
            if name == "stream":
                return types.MethodType(_raw_stream, self)
            return super().__getattribute__(name)

    _refused_and_never_called(Redirecting([[text("x")]]), make_plugin)


def test_an_instance_stream_that_claims_the_wrap_mark_is_refused(make_plugin, mock_apdp: MockApdpClient):
    """The mark is read from the function itself, not through ``getattr``."""
    import types

    class Claims:
        def __init__(self, target: Any) -> None:
            self.target = target

        def __getattr__(self, name: str) -> Any:
            return True

        def __call__(self, *args: Any, **kwargs: Any) -> Any:
            return self.target(*args, **kwargs)

    model = ScriptedModel([[text("x")]])
    model.stream = Claims(types.MethodType(_raw_stream, model))  # type: ignore[method-assign]
    _refused_and_never_called(model, make_plugin)


def test_a_plain_model_and_a_bound_wrapped_stream_keep_the_backstop(make_plugin, mock_apdp: MockApdpClient):
    import types

    make_plugin("agent-root")
    model = ScriptedModel([[text("x")]])
    assert model_backstop.has_backstop(model)
    model.stream = types.MethodType(ScriptedModel.__dict__["stream"], model)  # type: ignore[method-assign]
    assert model_backstop.has_backstop(model)


def test_a_model_swapped_for_a_duck_typed_one_before_the_turn_is_refused(make_plugin, mock_apdp: MockApdpClient):
    class Duck:
        stateful = False

        def get_config(self) -> dict:
            return {}

        async def stream(self, *args: Any, **kwargs: Any) -> Any:
            yield {"messageStart": {"role": "assistant"}}

    main = ScriptedModel([[text("done")]])
    agent = Agent(model=main, plugins=[make_plugin("agent-root")], callback_handler=None)

    def swap(event: Any) -> None:
        event.agent.model = Duck()

    agent.hooks.add_callback(BeforeModelCallEvent, swap)
    with pytest.raises(Exception) as raised:
        agent("hi")
    assert "not a strands model" in str(raised.value) or isinstance(raised.value.__cause__, UngovernedModelCall)


def test_a_thread_started_before_an_approval_wait_is_refused_during_it(make_plugin, mock_apdp: MockApdpClient):
    mock_apdp.decisions[("execute", "wire_funds")] = "needs_approval"
    wire = Wire(mock_apdp)
    go = threading.Event()
    outcome: List[Any] = []

    def later() -> None:
        go.wait(10)
        try:
            asyncio.run(_drain(openai_model(wire)))
            outcome.append("ran")
        except Exception as exc:  # noqa: BLE001 - recorded for the test
            outcome.append(exc)

    worker = threading.Thread(target=later)

    @tool
    def start_worker() -> str:
        """Start background work."""
        worker.start()
        return "started"

    @tool
    def wire_funds(amount: int) -> str:
        """Wire funds."""
        return "wired"

    main = ScriptedModel([[tool_call("start_worker", {})], [tool_call("wire_funds", {"amount": 1})], [text("done")]])
    plugin = make_plugin("agent-root", intent_objective="pay", intent_category="financial_operation")
    agent = Agent(model=main, tools=[start_worker, wire_funds], plugins=[plugin], callback_handler=None)
    result = agent("pay")
    assert result.stop_reason == "interrupt"

    # The run waits for the approval; the worker's model call runs now.
    go.set()
    worker.join(10)
    (error,) = outcome
    assert isinstance(error, UngovernedModelCall) and wire.requests == []

    # Rejecting the approval ends the run, and the count with it.
    agent([{"interruptResponse": {"interruptId": i.id, "response": "rejected"}} for i in result.interrupts])
    assert model_backstop.live_run_count() == 0


def test_an_abandoned_approval_wait_is_released_with_its_agent(make_plugin, mock_apdp: MockApdpClient, caplog):
    """A run waiting for an approval stays live, but not forever: once the
    application drops the agent, the run goes with it."""
    import gc

    mock_apdp.decisions[("execute", "wire_funds")] = "needs_approval"

    @tool
    def wire_funds(amount: int) -> str:
        """Wire funds."""
        return "wired"

    main = ScriptedModel([[tool_call("wire_funds", {"amount": 1})], [text("done")]])
    plugin = make_plugin("agent-root", intent_objective="pay", intent_category="financial_operation")
    agent = Agent(model=main, tools=[wire_funds], plugins=[plugin], callback_handler=None)
    assert agent("pay").stop_reason == "interrupt"
    assert model_backstop.live_run_count() == 1

    plugin_ref = weakref.ref(plugin)
    del agent, plugin
    with caplog.at_level("WARNING"):
        gc.collect()
    assert plugin_ref() is None
    assert model_backstop.live_run_count() == 0
    assert any("abandoned" in r.getMessage() and "garbage collected" in r.getMessage() for r in caplog.records)


def test_an_approval_wait_nobody_resumes_is_abandoned_when_it_expires(
    make_plugin, mock_apdp: MockApdpClient, monkeypatch, caplog
):
    from watchlight_strands import plugin as plugin_module

    monkeypatch.setattr(plugin_module, "APPROVAL_WAIT_SECONDS", 0)
    mock_apdp.decisions[("execute", "wire_funds")] = "needs_approval"

    @tool
    def wire_funds(amount: int) -> str:
        """Wire funds."""
        return "wired"

    main = ScriptedModel([[tool_call("wire_funds", {"amount": 1})], [text("done")]])
    plugin = make_plugin("agent-root", intent_objective="pay", intent_category="financial_operation")
    agent = Agent(model=main, tools=[wire_funds], plugins=[plugin], callback_handler=None)
    assert agent("pay").stop_reason == "interrupt"
    with caplog.at_level("WARNING"):
        assert model_backstop.live_run_count() == 0
    assert any("approval wait was abandoned" in r.getMessage() for r in caplog.records)
    assert agent is not None  # the agent is still alive: the expiry released the run
