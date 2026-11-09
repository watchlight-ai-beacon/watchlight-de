"""``require_hosted_request_allowed_blocking``: the hosted-tool gate for a
synchronous model call.

The decisions run on the backend's own I/O-loop thread when it has one,
else on the run's loop on another thread, else the call is refused. Every
test that could hang is bounded: a deadlock fails, it never hangs.
"""

from __future__ import annotations

import asyncio
import threading
import time
from types import SimpleNamespace
from typing import Any, List, Optional

import pytest

from watchlight_core import AgentQuarantinedError
from watchlight_core.hosted_tools import (
    HOSTED_TOOL_REFUSED_TIMEOUT,
    HOSTED_TOOL_REFUSED_UNAVAILABLE,
    HostedToolRefused,
    HostedToolTurn,
    require_hosted_request_allowed_blocking,
)
from watchlight_core.results import AuthorizeResult
from watchlight_core.sidecar_backend import _IoLoop

HOSTED = {"tools": [{"type": "web_search"}]}
PLAIN = {"tools": [{"type": "function", "name": "lookup", "parameters": {"type": "object"}}]}


class _Handle:
    """A run handle stand-in: records each decision and the thread it ran
    on. ``io`` gives it a backend with its own I/O loop."""

    def __init__(
        self, decision: str = "allow", *, io: Any = None, delay: float = 0.0, hold: float = 0.0, raises: Any = None
    ) -> None:
        self.decision = decision
        self.delay = delay
        self.hold = hold
        self.raises = raises
        self.calls: List[str] = []
        self.decided = threading.Event()
        self._plugin = SimpleNamespace(apdp=SimpleNamespace(_io=io, _forked=False) if io is not None else object())

    async def authorize_action_detailed(self, action: str, resource: str, *, context: Optional[dict] = None) -> Any:
        self.calls.append(threading.current_thread().name)
        if self.delay:
            await asyncio.sleep(self.delay)
        if self.hold:
            # Hold the loop thread inside the decision: no timeout on that
            # loop can fire until it returns.
            threading.Event().wait(self.hold)
        if self.raises is not None:
            raise self.raises
        self.decided.set()
        return AuthorizeResult(self.decision)


def _bounded(fn: Any, seconds: float = 10.0) -> Any:
    """Run ``fn`` on a thread and fail if it does not return in time."""
    box: dict = {}

    def run() -> None:
        try:
            box["value"] = fn()
        except BaseException as exc:  # noqa: BLE001 - re-raised below
            box["error"] = exc

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    thread.join(seconds)
    assert not thread.is_alive(), "the call hung"
    if "error" in box:
        raise box["error"]
    return box.get("value")


class _LoopThread:
    def __init__(self) -> None:
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=self.loop.run_forever, name="run-loop", daemon=True)
        self.thread.start()

    def stop(self) -> None:
        self.loop.call_soon_threadsafe(self.loop.stop)
        self.thread.join(5)
        self.loop.close()


@pytest.fixture
def run_loop():  # type: ignore[no-untyped-def]
    lt = _LoopThread()
    yield lt
    if not lt.loop.is_closed():
        lt.stop()


@pytest.fixture
def io_loop():  # type: ignore[no-untyped-def]
    io = _IoLoop()
    yield io
    io.stop()


def _gate(handle: Any, request: Any = HOSTED, **kw: Any) -> Any:
    return require_hosted_request_allowed_blocking(handle, request, HostedToolTurn(), **kw)


def _reason(refused: HostedToolRefused) -> str:
    return refused.gate.result.reason


# ── no hosted tool: nothing to decide ─────────────────────────────────


def test_a_call_without_hosted_tools_passes_with_no_loop() -> None:
    handle = _Handle("deny")
    assert _bounded(lambda: _gate(handle, PLAIN)).allowed
    assert handle.calls == []


# ── 1. the backend's own I/O loop ─────────────────────────────────────


def test_decided_on_the_backends_io_thread(io_loop: Any, run_loop: Any) -> None:
    handle = _Handle("allow", io=io_loop)
    assert _bounded(lambda: _gate(handle, run_loop=run_loop.loop)).allowed
    assert handle.calls == ["watchlight-sidecar-io"], "the I/O loop is preferred over the run's loop"


def test_a_deny_on_the_io_thread_refuses(io_loop: Any) -> None:
    handle = _Handle("deny", io=io_loop)
    with pytest.raises(HostedToolRefused):
        _bounded(lambda: _gate(handle))
    assert handle.calls == ["watchlight-sidecar-io"]


def test_called_on_the_io_thread_is_refused_without_hanging(io_loop: Any) -> None:
    handle = _Handle("allow", io=io_loop)
    done: dict = {}
    ready = threading.Event()

    def on_io_thread() -> None:
        try:
            _gate(handle)
        except HostedToolRefused as exc:
            done["reason"] = _reason(exc)
        finally:
            ready.set()

    io_loop.loop().call_soon_threadsafe(on_io_thread)
    assert ready.wait(10), "the call hung"
    assert done == {"reason": HOSTED_TOOL_REFUSED_UNAVAILABLE}
    assert handle.calls == []


# ── 2. the run's loop on another thread ───────────────────────────────


def test_decided_on_the_runs_loop_on_another_thread(run_loop: Any) -> None:
    handle = _Handle("allow")
    assert _bounded(lambda: _gate(handle, run_loop=run_loop.loop)).allowed
    assert handle.calls == ["run-loop"]


def test_a_deny_on_the_runs_loop_refuses(run_loop: Any) -> None:
    handle = _Handle("deny")
    with pytest.raises(HostedToolRefused):
        _bounded(lambda: _gate(handle, run_loop=run_loop.loop))


@pytest.mark.asyncio
async def test_called_on_the_runs_own_loop_thread_is_refused_without_hanging() -> None:
    handle = _Handle("allow")
    started = time.monotonic()
    with pytest.raises(HostedToolRefused) as refused:
        _gate(handle, run_loop=asyncio.get_running_loop())
    assert time.monotonic() - started < 2
    assert _reason(refused.value) == HOSTED_TOOL_REFUSED_UNAVAILABLE
    assert handle.calls == []


def test_a_run_ending_decision_raises_its_own_error(run_loop: Any) -> None:
    quarantined = AgentQuarantinedError.__new__(AgentQuarantinedError)
    Exception.__init__(quarantined, "quarantined")
    handle = _Handle(raises=quarantined)
    with pytest.raises(AgentQuarantinedError):
        _bounded(lambda: _gate(handle, run_loop=run_loop.loop))


# ── 3. otherwise refused ──────────────────────────────────────────────


def test_no_loop_refuses() -> None:
    handle = _Handle("allow")
    with pytest.raises(HostedToolRefused) as refused:
        _bounded(lambda: _gate(handle))
    assert _reason(refused.value) == HOSTED_TOOL_REFUSED_UNAVAILABLE
    assert handle.calls == []


def test_a_closed_loop_refuses(run_loop: Any) -> None:
    run_loop.stop()
    handle = _Handle("allow")
    with pytest.raises(HostedToolRefused):
        _bounded(lambda: _gate(handle, run_loop=run_loop.loop))
    assert handle.calls == []


def test_a_loop_that_is_not_running_refuses() -> None:
    loop = asyncio.new_event_loop()
    try:
        handle = _Handle("allow")
        with pytest.raises(HostedToolRefused):
            _bounded(lambda: _gate(handle, run_loop=loop))
        assert handle.calls == []
    finally:
        loop.close()


def test_a_slow_decision_refuses_at_the_timeout(run_loop: Any) -> None:
    handle = _Handle("allow", delay=5.0)
    with pytest.raises(HostedToolRefused) as refused:
        _bounded(lambda: _gate(handle, run_loop=run_loop.loop, timeout_seconds=0.2))
    assert _reason(refused.value) == HOSTED_TOOL_REFUSED_TIMEOUT


def test_a_blocked_loop_refuses_at_the_timeout(run_loop: Any) -> None:
    """The decision never starts (the loop is stuck): the wait itself is
    bounded."""
    run_loop.loop.call_soon_threadsafe(time.sleep, 3.0)
    handle = _Handle("allow")
    started = time.monotonic()
    with pytest.raises(HostedToolRefused) as refused:
        _bounded(lambda: _gate(handle, run_loop=run_loop.loop, timeout_seconds=0.2))
    assert time.monotonic() - started < 2.5
    assert _reason(refused.value) == HOSTED_TOOL_REFUSED_TIMEOUT


# ── every other error is a refusal, and a refusal seals the turn ───────


def test_an_unexpected_error_inside_the_gate_is_a_refusal(run_loop: Any) -> None:
    handle = _Handle(raises=KeyError("boom"))
    with pytest.raises(HostedToolRefused):
        _bounded(lambda: _gate(handle, run_loop=run_loop.loop))


def test_a_misused_turn_is_a_refusal(run_loop: Any) -> None:
    turn = HostedToolTurn()
    turn.seal()
    handle = _Handle("allow")
    with pytest.raises(HostedToolRefused):
        _bounded(lambda: require_hosted_request_allowed_blocking(handle, HOSTED, turn, run_loop=run_loop.loop))
    assert handle.calls == []


def test_an_unreadable_request_is_a_refusal(run_loop: Any) -> None:
    handle = _Handle("allow")
    with pytest.raises(HostedToolRefused):
        _bounded(lambda: _gate(handle, ["not", "a", "request"], run_loop=run_loop.loop))


def test_a_loop_stopped_mid_wait_refuses(io_loop: Any) -> None:
    handle = _Handle("allow", io=io_loop, delay=5.0)
    threading.Timer(0.3, io_loop.stop).start()
    started = time.monotonic()
    with pytest.raises(HostedToolRefused) as refused:
        _bounded(lambda: _gate(handle, timeout_seconds=8.0))
    assert time.monotonic() - started < 6
    assert _reason(refused.value) == HOSTED_TOOL_REFUSED_UNAVAILABLE


def test_a_late_allow_is_never_reused_on_the_same_turn(run_loop: Any) -> None:
    """The decision is still running when the caller gives up; it then
    allows, and the allow lands in the turn. The turn was sealed on the
    refusal, so a second gate on it is refused, not passed from the
    cache."""
    handle = _Handle("allow", hold=2.0)
    turn = HostedToolTurn()
    with pytest.raises(HostedToolRefused) as refused:
        _bounded(lambda: require_hosted_request_allowed_blocking(
            handle, HOSTED, turn, run_loop=run_loop.loop, timeout_seconds=0.2))
    assert _reason(refused.value) == HOSTED_TOOL_REFUSED_TIMEOUT
    assert handle.decided.wait(5), "the late allow never landed"
    # Let the gate's step that caches the allow finish on the loop.
    asyncio.run_coroutine_threadsafe(asyncio.sleep(0), run_loop.loop).result(5)
    assert turn.sealed
    with pytest.raises(HostedToolRefused):
        _bounded(lambda: require_hosted_request_allowed_blocking(
            handle, HOSTED, turn, run_loop=run_loop.loop, timeout_seconds=0.2))
    assert len(handle.calls) == 1, "the second gate must not decide again on a sealed turn"


def test_a_deny_seals_the_turn(run_loop: Any) -> None:
    turn = HostedToolTurn()
    with pytest.raises(HostedToolRefused):
        _bounded(lambda: require_hosted_request_allowed_blocking(_Handle("deny"), HOSTED, turn, run_loop=run_loop.loop))
    assert turn.sealed
