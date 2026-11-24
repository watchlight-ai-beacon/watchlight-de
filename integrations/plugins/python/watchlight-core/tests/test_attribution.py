"""``watchlight_core.attribution``: which run each egress request names.

Driven against the stand-in connector (``tests/wl_local_standin.py``) with a
real ``SidecarBackend``. The stand-in's ``egress_for`` points at a local
listener that records the source port of every connection it accepts, so the
tests see exactly what the connector would: which run each connection was
reported for, and that the report was recorded before the connection opened.

Client connections are made on worker threads (``asyncio.to_thread``, which
copies the context), because the stand-in connector runs on the test's event
loop and the report waits for its answer.
"""

from __future__ import annotations

import asyncio
import contextlib
import contextvars
import os
import secrets
import shutil
import socket
import sys
import tempfile
import threading
import weakref
from pathlib import Path
from typing import Any, AsyncIterator, Dict, List, Optional, Tuple

import pytest

ASYNC_TEST_TIMEOUT_S = 30

from watchlight_core import attribution as at
from watchlight_core import run_handle as rh
from watchlight_core.attribution import EgressConnectRefused, EgressRefused
from watchlight_core.decision import RunHandleState
from watchlight_core.sidecar_backend import SidecarBackend, SidecarEgress

from .wl_local_standin import StandInConnector

MARKER_HEADER = "Watchlight-Run-Marker"


def _token() -> str:
    return secrets.token_urlsafe(32)


@pytest.fixture
def base():
    d = Path(tempfile.mkdtemp(prefix="wla", dir="/tmp"))
    yield d
    shutil.rmtree(d, ignore_errors=True)


class Listener:
    """The connector's egress listener, reduced to what attribution needs:
    the source port of each accepted connection, in a log shared with the
    connector's report log so the order is visible."""

    def __init__(self, log: List[Tuple[str, Any]]) -> None:
        self.log = log
        self.server: Optional[asyncio.AbstractServer] = None
        self.port = 0

    async def start(self) -> "Listener":
        async def on_conn(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            self.log.append(("accept", writer.get_extra_info("peername")[1]))
            writer.close()

        self.server = await asyncio.start_server(on_conn, "127.0.0.1", 0)
        self.port = self.server.sockets[0].getsockname()[1]
        return self

    async def stop(self) -> None:
        if self.server is not None:
            self.server.close()
            await self.server.wait_closed()


@contextlib.asynccontextmanager
async def stack(base: Path) -> AsyncIterator[Tuple[StandInConnector, SidecarBackend, Listener, List[Tuple[str, Any]]]]:
    log: List[Tuple[str, Any]] = []
    connector = await StandInConnector(base).start()
    listener = await Listener(log).start()

    def egress_for(p: Dict[str, Any]) -> Dict[str, Any]:
        st = connector.runs[p["run"]]
        st["marker"], st["child_key"] = _token(), _token()
        return {"ok": {
            "proxy_url": f"http://127.0.0.1:{listener.port}",
            "marker_header": MARKER_HEADER,
            "marker": st["marker"],
            "child_proxy_url": f"http://wl:{st['child_key']}@127.0.0.1:{listener.port}",
        }}

    def report(p: Dict[str, Any]) -> None:
        log.append(("report", p["src_port"], p["run"]))
        return None  # answered normally by the stand-in

    connector.override["egress_for"] = egress_for
    connector.override["report_connection"] = report
    backend = SidecarBackend(socket_path=connector.socket_path)
    try:
        yield connector, backend, listener, log
    finally:
        await backend.close()
        await listener.stop()
        await connector.stop()


async def _run(backend: SidecarBackend, agent: str = "agent-1") -> Tuple[str, SidecarEgress]:
    info = await backend.create_session(agent)
    return info.run, await backend.fetch_egress(info.run)


class Handle:
    """A stand-in run handle: the fields attribution reads, set exactly as
    ``BaseRunHandle`` sets them (``_state`` holds a ``RunHandleState``;
    ``state`` is its read-only view; ``_completed`` and
    ``_run_end_decision`` as ``complete()`` and a policy end leave them).
    Spawning and completing bind and unbind the sub-agent context variable
    with the real ``BaseRunHandle`` code."""

    def __init__(self, egress: Any, parent: Optional["Handle"] = None, state: str = "active") -> None:
        self.egress = egress
        self._state = RunHandleState(state)
        self._completed = state != "active"
        self._run_end_decision = None
        self._is_subagent = parent is not None
        self._parent_handle_ref = weakref.ref(parent) if parent is not None else None
        self._subagent_cv_token = None
        self.session_id = "ses_stand_in"

    @property
    def state(self) -> RunHandleState:
        return self._state

    def bind_as_spawned_by(self, spawner: "Handle") -> None:
        """What ``BaseRunHandle.spawn_subagent`` does in the spawner's
        context: restore the spawner's own binding, then bind the child."""
        rh._current_subagent_handle.set(spawner if spawner._is_subagent else None)
        self._subagent_cv_token = rh._current_subagent_handle.set(self)

    def complete(self) -> None:
        """What ``BaseRunHandle.complete()`` does to the context binding and
        the state, in whatever context it is called from."""
        rh.BaseRunHandle._unbind_subagent_contextvar(self)  # type: ignore[arg-type]
        self._completed = True
        self._state = RunHandleState.COMPLETED


def _connect(port: int, prebind: bool = False) -> int:
    """Open a connection to ``port`` from this thread; return its source port."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        if prebind:
            s.bind(("127.0.0.1", 0))
        s.settimeout(5)
        s.connect(("127.0.0.1", port))
        return s.getsockname()[1]
    finally:
        s.close()


async def _settle(log: List[Tuple[str, Any]], accepts: int) -> None:
    for _ in range(200):
        if sum(1 for e in log if e[0] == "accept") >= accepts:
            return
        await asyncio.sleep(0.01)


def _reports(log: List[Tuple[str, Any]]) -> Dict[int, str]:
    return {e[1]: e[2] for e in log if e[0] == "report"}


def _in_context(fn, *args):
    """Run ``fn`` on a worker thread in a copy of the current context."""
    return asyncio.to_thread(fn, *args)


# ---------------------------------------------------------------------------
# Runs and sub-agents name themselves
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_concurrent_runs_each_report_and_mark_their_own_run(base):
    async with stack(base) as (connector, backend, listener, log):
        (run_a, eg_a), (run_b, eg_b) = await _run(backend), await _run(backend)

        async def worker(subject: Any, n: int) -> Tuple[List[int], Dict[str, str]]:
            with at.bound_run(subject):
                headers = at.marker_headers()
                ports = []
                for _ in range(n):
                    ports.append(await _in_context(_connect, listener.port))
                return ports, headers

        (ports_a, h_a), (ports_b, h_b) = await asyncio.gather(
            worker(Handle(eg_a), 5), worker(Handle(eg_b), 5)
        )
        await _settle(log, 10)
        assert h_a == {MARKER_HEADER: connector.runs[run_a]["marker"]}
        assert h_b == {MARKER_HEADER: connector.runs[run_b]["marker"]}
        reports = _reports(log)
        assert all(reports[p] == run_a for p in ports_a)
        assert all(reports[p] == run_b for p in ports_b)
        # Every report was recorded before its connection was accepted.
        for p in ports_a + ports_b:
            assert log.index(("report", p, reports[p])) < log.index(("accept", p))


@pytest.mark.asyncio
async def test_a_subagent_names_its_own_run_never_its_parents(base):
    async with stack(base) as (connector, backend, listener, log):
        run_root, eg_root = await _run(backend)
        spawn = await backend.spawn_subagent(run_root, {"child_agent_id": "agent-2"})
        run_child = spawn["child_run"]
        eg_child = await backend.fetch_egress(run_child)
        root = Handle(eg_root)
        child = Handle(eg_child, parent=root)
        with at.bound_run(root):
            token = rh._current_subagent_handle.set(child)
            try:
                assert at.marker_headers() == {MARKER_HEADER: connector.runs[run_child]["marker"]}
                child_url = at.proxy_env()["HTTPS_PROXY"]
                port_child = await _in_context(_connect, listener.port)
            finally:
                rh._current_subagent_handle.reset(token)
            # The parent's context is untouched.
            assert at.marker_headers() == {MARKER_HEADER: connector.runs[run_root]["marker"]}
            port_root = await _in_context(_connect, listener.port)
        await _settle(log, 2)
        assert _reports(log) == {port_child: run_child, port_root: run_root}
        assert connector.runs[run_child]["child_key"] in child_url
        assert connector.runs[run_root]["child_key"] not in child_url


@pytest.mark.asyncio
async def test_a_subagent_without_its_own_egress_is_refused_not_given_the_parents(base):
    """A child with no egress binding (no ``child_marker``) never runs on
    its parent's run: no marker, no child key and no report."""
    async with stack(base) as (connector, backend, listener, log):
        _run_root, eg_root = await _run(backend)
        root = Handle(eg_root)
        child = Handle(None, parent=root)
        with at.bound_run(root):
            token = rh._current_subagent_handle.set(child)
            try:
                with pytest.raises(EgressRefused) as exc:
                    at.marker_headers()
                assert exc.value.reason == "subagent_has_no_egress"
                with pytest.raises(EgressRefused):
                    at.proxy_env()
                await _in_context(_connect, listener.port)
            finally:
                rh._current_subagent_handle.reset(token)
        await _settle(log, 1)
        assert _reports(log) == {}


@pytest.mark.asyncio
async def test_a_completed_subagent_hands_back_to_its_parent_and_an_ended_one_refuses(base):
    async with stack(base) as (connector, backend, listener, log):
        run_root, eg_root = await _run(backend)
        root = Handle(eg_root)
        done = Handle(None, parent=root, state="completed")
        quarantined = Handle(None, parent=root, state="quarantined")
        with at.bound_run(root):
            token = rh._current_subagent_handle.set(done)
            try:
                assert at.marker_headers() == {MARKER_HEADER: connector.runs[run_root]["marker"]}
            finally:
                rh._current_subagent_handle.reset(token)
            token = rh._current_subagent_handle.set(quarantined)
            try:
                with pytest.raises(EgressRefused) as exc:
                    at.marker_headers()
                assert exc.value.reason == "run_not_live"
            finally:
                rh._current_subagent_handle.reset(token)
            # Completed with a decision (terminated, revoked): refused too.
            done._run_end_decision = object()
            token = rh._current_subagent_handle.set(done)
            try:
                with pytest.raises(EgressRefused):
                    at.marker_headers()
            finally:
                rh._current_subagent_handle.reset(token)


@pytest.mark.asyncio
async def test_a_spawner_whose_grandchild_completed_elsewhere_is_itself_never_the_root(base):
    """R -> S1 -> G. S1 spawns G in S1's context; G's work runs and
    completes in its own task, so S1's context still holds G. S1's later
    traffic must name S1 (G's nearest live ancestor), never R."""
    async with stack(base) as (connector, backend, listener, log):
        run_r, eg_r = await _run(backend)
        run_s1 = (await backend.spawn_subagent(run_r, {"child_agent_id": "agent-2"}))["child_run"]
        eg_s1 = await backend.fetch_egress(run_s1)
        run_g = (await backend.spawn_subagent(run_s1, {"child_agent_id": "agent-3"}))["child_run"]
        eg_g = await backend.fetch_egress(run_g)
        root = Handle(eg_r)
        s1 = Handle(eg_s1, parent=root)
        g = Handle(eg_g, parent=s1)

        def marker(run: str) -> Dict[str, str]:
            return {MARKER_HEADER: connector.runs[run]["marker"]}

        async def s1_work() -> Tuple[Dict[str, str], Dict[str, str], int]:
            s1.bind_as_spawned_by(root)
            assert at.marker_headers() == marker(run_s1)
            g.bind_as_spawned_by(s1)

            async def g_work() -> None:
                assert at.marker_headers() == marker(run_g)
                g.complete()

            await asyncio.create_task(g_work())
            # S1's context still holds the completed G, which the public
            # accessor hides.
            assert rh._current_subagent_handle.get() is g
            assert rh.current_subagent_handle() is None
            port = await _in_context(_connect, listener.port)
            return at.marker_headers(), at.proxy_env(), port

        with at.bound_run(root):
            headers, env, port = await asyncio.create_task(s1_work())
            # S1 completing normally hands its context to R.
            s1.complete()

            async def after_s1() -> Dict[str, str]:
                rh._current_subagent_handle.set(s1)
                return at.marker_headers()

            assert await asyncio.create_task(after_s1()) == marker(run_r)
        assert headers == marker(run_s1)
        assert connector.runs[run_s1]["child_key"] in env["HTTPS_PROXY"]
        assert connector.runs[run_r]["child_key"] not in env["HTTPS_PROXY"]
        await _settle(log, 1)
        assert _reports(log) == {port: run_s1}


# ---------------------------------------------------------------------------
# What cannot be attributed is refused
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_unbound_traffic_is_refused(base):
    async with stack(base) as (connector, backend, listener, log):
        _run_a, eg_a = await _run(backend)
        at.register_egress_endpoint(eg_a.proxy_url)
        with pytest.raises(EgressRefused) as exc:
            at.marker_headers()
        assert exc.value.reason == "no_run_bound"
        with pytest.raises(EgressRefused):
            at.proxy_env()
        await _in_context(_connect, listener.port)

        # A thread started without the context sees no binding either.
        with at.bound_run(Handle(eg_a)):
            ports: List[int] = []
            t = threading.Thread(target=lambda: ports.append(_connect(listener.port)))
            t.start()
            await asyncio.to_thread(t.join)
        await _settle(log, 2)
        assert _reports(log) == {}


@pytest.mark.asyncio
async def test_an_ended_run_is_refused(base):
    async with stack(base) as (connector, backend, listener, log):
        run_a, eg_a = await _run(backend)
        handle = Handle(eg_a)
        with at.bound_run(handle):
            assert at.marker_headers()
            assert await backend.complete_session(run_a) is True
            with pytest.raises(EgressRefused) as exc:
                at.marker_headers()
            assert exc.value.reason == "run_not_live"
            with pytest.raises(EgressRefused):
                at.proxy_env()
            # The report is refused, so the connection is never opened.
            with pytest.raises(EgressConnectRefused):
                await _in_context(_connect, listener.port)
        # The handle itself ending refuses as well, also for an
        # attribution decided before it ended.
        live = Handle(eg_b := (await _run(backend))[1])
        with at.bound_run(live):
            decided = at.resolve()
            assert decided.egress() is eg_b
            live._state = RunHandleState.SEVERED
            with pytest.raises(EgressRefused):
                decided.egress()
            with pytest.raises(EgressRefused):
                at.current_egress()
        await asyncio.sleep(0.05)
        assert _reports(log) == {}
        assert not [e for e in log if e[0] == "accept"]


@pytest.mark.asyncio
async def test_a_binding_of_the_egress_itself_works_until_the_run_ends(base):
    async with stack(base) as (connector, backend, listener, log):
        run_a, eg_a = await _run(backend)
        with at.bound_run(eg_a):
            port = await _in_context(_connect, listener.port, True)
            assert await backend.complete_session(run_a) is True
            with pytest.raises(EgressConnectRefused):
                await _in_context(_connect, listener.port)
        await _settle(log, 1)
        # The pre-bound socket reported its own port; after the end, nothing.
        assert _reports(log) == {port: run_a}
        assert [e for e in log if e[0] == "accept"] == [("accept", port)]


@pytest.mark.asyncio
async def test_only_connections_to_the_egress_listener_are_touched(base):
    async with stack(base) as (connector, backend, listener, log):
        _run_a, eg_a = await _run(backend)
        other = await Listener([]).start()
        try:
            with at.bound_run(Handle(eg_a)):
                await _in_context(_connect, other.port)
        finally:
            await other.stop()
        assert _reports(log) == {}
    for bad in ("https://127.0.0.1:1", "http://10.0.0.5:3128", "http://localhost:3128", None, "http://127.0.0.1"):
        assert at.register_egress_endpoint(bad) is False


@pytest.mark.asyncio
async def test_a_lost_connector_refuses_the_connect_locally(base):
    async with stack(base) as (connector, backend, listener, log):
        _run_a, eg_a = await _run(backend)
        with at.bound_run(Handle(eg_a)):
            connector.drop_all()
            await asyncio.sleep(0.05)
            with pytest.raises(EgressConnectRefused):
                await _in_context(_connect, listener.port)
        await asyncio.sleep(0.05)
        assert _reports(log) == {}
        assert not [e for e in log if e[0] == "accept"]


@pytest.mark.asyncio
@pytest.mark.parametrize("answer", ["refused", "silent"])
async def test_a_report_the_connector_did_not_record_aborts_the_connect(base, monkeypatch, answer):
    """Fail closed: a refused or timed-out report never lets the connection
    open, so a late report cannot attribute it (or a later one on its port)."""
    monkeypatch.setattr(at, "REPORT_TIMEOUT_S", 0.3)
    async with stack(base) as (connector, backend, listener, log):
        _run_a, eg_a = await _run(backend)
        connector.override["report_connection"] = (
            (lambda p: {"error": {"code": "internal"}}) if answer == "refused" else (lambda p: "silent")
        )
        with at.bound_run(Handle(eg_a)):
            with pytest.raises(EgressConnectRefused) as exc:
                await _in_context(_connect, listener.port)
        assert isinstance(exc.value, ConnectionRefusedError)
        assert exc.value.reason == "connection_report_not_recorded"
        await asyncio.sleep(0.05)
        assert not [e for e in log if e[0] == "accept"]


# ---------------------------------------------------------------------------
# Child processes and fork
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_proxy_env_carries_the_current_runs_child_key_only(base, monkeypatch):
    async with stack(base) as (connector, backend, listener, log):
        run_a, eg_a = await _run(backend)
        before = dict(os.environ)
        with at.bound_run(Handle(eg_a)):
            env = at.proxy_env()
        url = f"http://wl:{connector.runs[run_a]['child_key']}@127.0.0.1:{listener.port}"
        assert env == {**{n: url for n in at.PROXY_ENV_NAMES}, "NO_PROXY": "", "no_proxy": ""}
        assert dict(os.environ) == before


@pytest.mark.skipif(not hasattr(os, "fork"), reason="needs fork")
@pytest.mark.asyncio
async def test_a_forked_child_does_not_inherit_the_parents_binding(base):
    async with stack(base) as (connector, backend, listener, log):
        run_a, eg_a = await _run(backend)
        run_c = (await backend.spawn_subagent(run_a, {"child_agent_id": "agent-2"}))["child_run"]
        root = Handle(eg_a)
        child = Handle(await backend.fetch_egress(run_c), parent=root)
        with at.bound_run(root):
            assert at.marker_headers()
            r, w = os.pipe()
            # Another thread may hold the endpoint lock at the fork; the
            # child must not inherit it held.
            at._endpoints_lock.acquire()
            try:
                pid = os.fork()
            finally:
                if pid != 0:
                    at._endpoints_lock.release()
            if pid == 0:  # pragma: no cover - the child
                code = 0
                try:
                    os.close(r)
                    if at.resolve().refusal != "bound_in_another_process":
                        code = 1
                    try:
                        at.marker_headers()
                        code = 2
                    except EgressRefused:
                        pass

                    def as_subagent() -> Optional[str]:
                        rh._current_subagent_handle.set(child)
                        try:
                            at.current_egress()
                            return None
                        except EgressRefused as exc:
                            return exc.reason

                    if contextvars.copy_context().run(as_subagent) != "bound_in_another_process":
                        code = 4
                    if at._endpoints:
                        code = 3
                    if not at._endpoints_lock.acquire(blocking=False):
                        code = 5
                    os.write(w, bytes([code]))
                finally:
                    os._exit(0)
            os.close(w)
            got = await asyncio.to_thread(os.read, r, 1)
            os.close(r)
            await asyncio.to_thread(os.waitpid, pid, 0)
            assert got == b"\x00"
            # The parent keeps its binding.
            assert at.marker_headers()


@pytest.mark.asyncio
async def test_a_marker_holds_no_session_id_or_run(base: Path) -> None:
    async with stack(base) as (_connector, backend, _listener, _log):
        info = await backend.create_session("agent-1")
        marker = (await backend.fetch_egress(info.run)).marker()
        assert info.session_id not in marker
        assert info.run not in marker
