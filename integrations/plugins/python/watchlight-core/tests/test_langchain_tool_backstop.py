"""The shared LangChain tool backstop: while a governed run
is live, a tool start needs a single-use grant bound to that run, its
``tool_call_id`` and the tool name, consumed atomically."""

from __future__ import annotations

import asyncio
import contextvars
import threading
from typing import Any, List

import pytest

pytest.importorskip("langchain_core")

from langchain_core.callbacks import AsyncCallbackHandler, BaseCallbackHandler  # noqa: E402
from langchain_core.tools import tool  # noqa: E402

from watchlight_core import langchain_tool_backstop as backstop  # noqa: E402
from watchlight_core.langchain_tool_backstop import UngovernedToolCall  # noqa: E402


class _Runs:
    """One plugin's live runs, as a plugin registers them."""

    def __init__(self) -> None:
        self.live: List[Any] = []

    def __call__(self) -> List[Any]:
        return list(self.live)


_RUNS = _Runs()
_OTHER_PLUGIN = _Runs()
backstop.install(_RUNS)
backstop.install(_OTHER_PLUGIN)

ran: List[str] = []


@tool
def lookup(q: str) -> str:
    """Look something up."""
    ran.append(q)
    return "found"


def _call(call_id: str = "c1", q: str = "x") -> dict:
    return {"type": "tool_call", "id": call_id, "name": "lookup", "args": {"q": q}}


@pytest.fixture(autouse=True)
def _clean() -> Any:
    ran.clear()
    _RUNS.live.clear()
    _OTHER_PLUGIN.live.clear()
    yield
    _RUNS.live.clear()
    _OTHER_PLUGIN.live.clear()
    for handle in (RUN, OTHER_RUN):
        backstop.take_refusals(handle)


RUN = object()
OTHER_RUN = object()


def test_no_live_run_changes_nothing() -> None:
    assert lookup.invoke(_call()) is not None
    assert ran == ["x"]


@pytest.mark.parametrize("live_in", ["this_plugin", "another_plugin"])
def test_a_tool_start_without_a_grant_is_refused_while_any_plugin_has_a_live_run(
    live_in: str,
) -> None:
    (_RUNS if live_in == "this_plugin" else _OTHER_PLUGIN).live.append(RUN)
    with pytest.raises(UngovernedToolCall):
        lookup.invoke(_call())
    with pytest.raises(UngovernedToolCall):
        lookup.invoke(_call(), config={"callbacks": []})
    assert ran == []


def test_a_grant_releases_one_start_with_its_id_and_name() -> None:
    _RUNS.live.append(RUN)
    with backstop.grant_tool_start("c1", "lookup", RUN, body=False):
        lookup.invoke(_call("c1", "first"))
        with pytest.raises(UngovernedToolCall):
            lookup.invoke(_call("c1", "again"))
    with backstop.grant_tool_start("c2", "lookup", RUN, body=False):
        with pytest.raises(UngovernedToolCall):
            lookup.invoke(_call("c3", "other id"))
    with backstop.grant_tool_start("c4", "other_tool", RUN, body=False):
        with pytest.raises(UngovernedToolCall):
            lookup.invoke(_call("c4", "other name"))
    assert ran == ["first"]


def test_a_grant_for_a_run_that_has_ended_releases_nothing() -> None:
    _RUNS.live.append(OTHER_RUN)  # some run is live, but not the grant's
    with backstop.grant_tool_start("c1", "lookup", RUN, body=False):
        with pytest.raises(UngovernedToolCall):
            lookup.invoke(_call())
    assert ran == []


def test_a_grant_without_an_id_matches_only_a_start_without_one() -> None:
    _RUNS.live.append(RUN)
    with backstop.grant_tool_start(None, "lookup", RUN, body=False):
        with pytest.raises(UngovernedToolCall):
            lookup.invoke(_call("c1", "with id"))
    with backstop.grant_tool_start(None, "lookup", RUN, body=False):
        lookup.invoke({"q": "no id"})
        with pytest.raises(UngovernedToolCall):
            lookup.invoke({"q": "second"})
    assert ran == ["no id"]


def test_a_grant_copied_into_two_threads_releases_one_start() -> None:
    _RUNS.live.append(RUN)
    outcomes: List[str] = []
    start = threading.Barrier(8)

    def attempt() -> None:
        start.wait()
        try:
            lookup.invoke(_call("c1", "thread"))
            outcomes.append("ran")
        except UngovernedToolCall:
            outcomes.append("refused")

    with backstop.grant_tool_start("c1", "lookup", RUN, body=False):
        threads = [
            threading.Thread(target=contextvars.copy_context().run, args=(attempt,))
            for _ in range(8)
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(10)
    assert sorted(outcomes) == ["ran"] + ["refused"] * 7
    assert ran == ["thread"]


class _SyncRecorder(BaseCallbackHandler):
    def on_tool_start(self, *args: Any, **kwargs: Any) -> None:
        pass


class _AsyncRecorder(AsyncCallbackHandler):
    async def on_tool_start(self, *args: Any, **kwargs: Any) -> None:
        pass


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "handlers",
    [[], [_SyncRecorder()], [_AsyncRecorder()], [_SyncRecorder(), _AsyncRecorder()]],
)
async def test_arun_is_refused_whatever_handlers_the_caller_passes(
    handlers: List[Any],
) -> None:
    """The backstop raises on ``ainvoke`` too, with sync and async handlers
    of the caller's own alongside it."""
    _RUNS.live.append(RUN)
    with pytest.raises(UngovernedToolCall):
        await lookup.ainvoke(_call(), config={"callbacks": handlers})
    with backstop.grant_tool_start("c1", "lookup", RUN, body=False):
        await lookup.ainvoke(_call("c1", "granted"), config={"callbacks": handlers})
    assert ran == ["granted"]


def test_a_raw_thread_and_a_fresh_context_are_refused() -> None:
    _RUNS.live.append(RUN)
    errors: List[BaseException] = []

    def bare() -> None:
        try:
            lookup.invoke(_call())
        except BaseException as exc:  # noqa: BLE001 - asserted below
            errors.append(exc)

    with backstop.grant_tool_start("c1", "lookup", RUN, body=False):
        thread = threading.Thread(target=bare)  # does not copy the context
        thread.start()
        thread.join(10)
        contextvars.Context().run(bare)
    assert len(errors) == 2 and all(isinstance(e, UngovernedToolCall) for e in errors)
    assert ran == []


def test_installing_again_adds_no_second_handler() -> None:
    first = backstop._HANDLER_VAR
    backstop.install(_RUNS)
    assert backstop._HANDLER_VAR is first
    assert backstop._live_run_sources.count(_RUNS) == 1


def test_asyncio_task_keeps_the_grant() -> None:
    _RUNS.live.append(RUN)

    async def main() -> None:
        with backstop.grant_tool_start("c1", "lookup", RUN, body=False):
            await asyncio.create_task(lookup.ainvoke(_call("c1", "task")))

    asyncio.run(main())
    assert ran == ["task"]


def test_a_start_that_fails_before_the_body_leaves_nothing_to_start_later() -> None:
    """A caller's own handler, which LangChain runs before the backstop,
    fails the first start: the body never runs. Within the call, the same
    (run, id, name) may start once; a context copied during the call can
    never start it after the call ends."""

    class _Fails(BaseCallbackHandler):
        raise_error = True

        def on_tool_start(self, *args: Any, **kwargs: Any) -> None:
            raise RuntimeError("caller's handler failed")

    _RUNS.live.append(RUN)
    with backstop.grant_tool_start("c1", "lookup", RUN, body=False):
        with pytest.raises(RuntimeError):
            lookup.invoke(_call("c1", "first"), config={"callbacks": [_Fails()]})
        lookup.invoke(_call("c1", "retried once"))
        with pytest.raises(UngovernedToolCall):
            contextvars.copy_context().run(lookup.invoke, _call("c1", "twice"))
    with backstop.grant_tool_start("c2", "lookup", RUN, body=False):
        with pytest.raises(RuntimeError):
            lookup.invoke(_call("c2", "first"), config={"callbacks": [_Fails()]})
        later = contextvars.copy_context()
    with pytest.raises(UngovernedToolCall):
        later.run(lookup.invoke, _call("c2", "after the call"))
    assert ran == ["retried once"]
