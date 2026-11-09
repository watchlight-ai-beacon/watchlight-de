"""``SidecarBackend``: the cases the adversarial review of the first
version found (timeouts that left runs behind, leaked request slots, runs
killed while they were being opened, Enterprise variables that did not
select the connector, fork, kill callbacks on the I/O thread, credential
values in pass-through answers), and tests that pin the remaining guards.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import re
import shutil
import tempfile
import threading
from pathlib import Path
from typing import Any, AsyncIterator, List, Tuple

import pytest

ASYNC_TEST_TIMEOUT_S = 30

from watchlight_core import _wl_local as wire
from watchlight_core import sidecar_backend as sb
from watchlight_core.backend import KillNotice
from watchlight_core.errors import GovernanceUnavailable
from watchlight_core.sidecar_backend import ENTERPRISE_ENV_VARS, SidecarBackend, select_backend

from .wl_local_standin import StandInConnector


@pytest.fixture
def base():
    d = Path(tempfile.mkdtemp(prefix="wlr", dir="/tmp"))
    yield d
    shutil.rmtree(d, ignore_errors=True)


@contextlib.asynccontextmanager
async def stack(base: Path, **kw: Any) -> AsyncIterator[Tuple[StandInConnector, SidecarBackend]]:
    connector = await StandInConnector(base).start()
    backend = SidecarBackend(socket_path=connector.socket_path, **kw)
    try:
        yield connector, backend
    finally:
        await backend.close()
        await connector.stop()


async def _wait_for(pred, timeout: float = 3.0) -> bool:
    loop = asyncio.get_running_loop()
    end = loop.time() + timeout
    while loop.time() < end:
        if pred():
            return True
        await asyncio.sleep(0.02)
    return pred()


# ---------------------------------------------------------------------------
# M1: a create or spawn that times out leaves no run on the connector
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_timed_out_create_session_leaves_no_live_run(base):
    async with stack(base, request_timeout_s=0.1) as (connector, backend):
        await backend.health_check()
        with pytest.raises(GovernanceUnavailable):
            await backend.create_session("slow-agent")
        # The connector would answer late (after 0.4 s); the run it was
        # making must not stay live.
        await asyncio.sleep(0.8)
        assert connector.live_runs() == []


@pytest.mark.asyncio
async def test_a_timed_out_spawn_leaves_no_live_child(base):
    async with stack(base, request_timeout_s=0.3) as (connector, backend):
        info = await backend.create_session("agent-1")

        orig = connector._answer

        async def slow_answer(conn, method, params):
            if method == "spawn_subagent":
                await asyncio.sleep(0.6)
            return await orig(conn, method, params)

        connector._answer = slow_answer  # type: ignore[method-assign]
        with pytest.raises(GovernanceUnavailable):
            await backend.spawn_subagent(info.run, {"child_agent_id": "c"})
        # The child made late is ended; the parent (and the connection) live on.
        assert await _wait_for(lambda: len(connector.runs) == 2 and connector.live_runs() == [info.run])


# ---------------------------------------------------------------------------
# M2: request slots are never leaked; a wedged connection is recycled
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_cancelled_callers_waiting_to_write_leak_no_slot(base):
    async with stack(base, request_timeout_s=2.0) as (connector, backend):
        info = await backend.create_session("agent-1")
        conn = backend._conn
        loop = backend._io.loop()
        asyncio.run_coroutine_threadsafe(conn._wlock.acquire(), loop).result(5)
        tasks = [asyncio.ensure_future(backend.authorize("ok", "a", "r", run=info.run)) for _ in range(20)]
        await asyncio.sleep(0.3)
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        loop.call_soon_threadsafe(conn._wlock.release)
        await asyncio.sleep(0.2)
        assert not conn._pending
        assert backend._conn is conn and not conn.closed
        assert (await backend.authorize("ok", "a", "r", run=info.run))["decision"] == "Allow"


@pytest.mark.asyncio
async def test_a_dead_connector_is_dropped_even_when_callers_went_away(base, monkeypatch):
    monkeypatch.setattr(sb._Connection, "probe_timeout_s", 0.3)
    async with stack(base, request_timeout_s=0.3) as (connector, backend):
        info = await backend.create_session("agent-1")
        notices: List[KillNotice] = []
        backend.subscribe_kill(info.run, notices.append)
        # The connector stops answering anything, the health probe included.
        connector.override["authorize"] = lambda p: "silent"
        connector.override["health"] = lambda p: "silent"
        for _ in range(3):
            t = asyncio.ensure_future(backend.authorize("ok", "a", "r", run=info.run))
            await asyncio.sleep(0.05)
            t.cancel()
            await asyncio.gather(t, return_exceptions=True)
        assert await _wait_for(lambda: notices, 3.0)
        assert notices[0].reason == "connection_lost"
        connector.override.clear()
        info2 = await backend.create_session("agent-1")
        assert (await backend.authorize("ok", "a", "r", run=info2.run))["decision"] == "Allow"


@pytest.mark.asyncio
async def test_a_slow_but_alive_connector_keeps_the_connection_and_its_runs(base):
    async with stack(base, request_timeout_s=0.2) as (connector, backend):
        info = await backend.create_session("agent-1")
        other = await backend.create_session("agent-1")
        notices: List[KillNotice] = []
        backend.subscribe_kill(other.run, notices.append)
        conn = backend._conn
        # A slow decision: the caller gets its Deny at the deadline.
        assert (await backend.authorize("sleep:600", "a", "r", run=info.run))["decision"] == "Deny"
        # A slow create: the caller is refused, and the run the connector
        # makes late is ended.
        with pytest.raises(GovernanceUnavailable):
            await backend.create_session("slow-agent")
        await asyncio.sleep(0.8)
        assert backend._conn is conn and not conn.closed
        assert notices == []
        assert (await backend.authorize("ok", "a", "r", run=other.run))["decision"] == "Allow"
        live = set(connector.live_runs())
        assert live == {info.run, other.run}
        # The late answers freed their slots.
        assert conn._in_flight == 0 and not conn._pending


@pytest.mark.asyncio
async def test_losing_the_connection_wakes_callers_waiting_for_a_slot(base):
    async with stack(base, request_timeout_s=10.0) as (connector, backend):
        info = await backend.create_session("agent-1")
        connector.override["authorize"] = lambda p: "silent"
        busy = [asyncio.ensure_future(backend.authorize("ok", "a", "r", run=info.run)) for _ in range(16)]
        await asyncio.sleep(0.3)
        waiter = asyncio.ensure_future(backend.authorize("ok", "a", "r", run=info.run))
        await asyncio.sleep(0.2)
        connector.drop_all()
        loop = asyncio.get_running_loop()
        t0 = loop.time()
        assert (await waiter)["decision"] == "Deny"
        assert loop.time() - t0 < 2.0
        await asyncio.gather(*busy, return_exceptions=True)


@pytest.mark.asyncio
async def test_slot_waiters_time_out_without_losing_a_slot(base):
    async with stack(base, request_timeout_s=0.5) as (connector, backend):
        info = await backend.create_session("agent-1")
        answers = await asyncio.gather(*[
            backend.authorize("sleep:200", "a", "r", context={"i": i}, run=info.run) for i in range(40)
        ])
        assert sum(a["decision"] == "Allow" for a in answers) >= 16
        conn = backend._conn
        assert conn is not None and not conn._pending and conn._in_flight == 0


# ---------------------------------------------------------------------------
# M3: a run killed while it is being opened is never handed out
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_run_killed_during_its_kill_subscription_is_refused(base):
    async with stack(base) as (connector, backend):
        connector.override["subscribe_kill"] = lambda p: ("kill_first", "run")
        assert await backend.create_session("agent-1") is None


@pytest.mark.asyncio
async def test_a_child_killed_during_its_kill_subscription_never_runs(base):
    async with stack(base) as (connector, backend):
        info = await backend.create_session("agent-1")
        connector.override["subscribe_kill"] = lambda p: ("kill_first", "run")
        with pytest.raises(GovernanceUnavailable):
            await backend.spawn_subagent(info.run, {"child_agent_id": "c"})


@pytest.mark.asyncio
async def test_a_refused_kill_subscription_refuses_the_run(base):
    async with stack(base) as (connector, backend):
        connector.override["subscribe_kill"] = lambda p: {"error": {"code": "internal"}}
        assert await backend.create_session("agent-1") is None
        assert await _wait_for(lambda: connector.runs and not connector.live_runs())


@pytest.mark.asyncio
async def test_a_child_of_a_parent_killed_mid_spawn_never_runs(base):
    async with stack(base) as (connector, backend):
        info = await backend.create_session("agent-1")
        connector.override["spawn_subagent"] = lambda p: ("kill_first", "parent_run")
        with pytest.raises(GovernanceUnavailable):
            await backend.spawn_subagent(info.run, {"child_agent_id": "c"})
        assert await _wait_for(lambda: not connector.live_runs())


@pytest.mark.asyncio
async def test_a_child_reusing_its_parents_marker_never_runs(base):
    async with stack(base) as (connector, backend):
        info = await backend.create_session("agent-1")
        parent_marker = connector.runs[info.run]["marker"]

        def reuse(p):
            child = connector._new_run(connector.conns[-1], parent=p["parent_run"])
            return {"ok": {
                "child_run": child["run"], "session_id": "ses_2", "execution_id": "exec_2",
                "scope": {"child_run_handle_id": "6f1c1a52-6b0a-4c4e-9b8e-6d3f0b2b0a11",
                          "granted_scope": {"max_depth": 1, "time_budget_seconds": 1}},
                "child_marker": parent_marker, "child_key": child["child_key"],
            }}

        connector.override["spawn_subagent"] = reuse
        with pytest.raises(GovernanceUnavailable):
            await backend.spawn_subagent(info.run, {"child_agent_id": "c"})
        assert await _wait_for(lambda: connector.live_runs() == [info.run])


# ---------------------------------------------------------------------------
# M4: every Enterprise variable selects the connector
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", ENTERPRISE_ENV_VARS)
def test_every_enterprise_variable_requires_the_connector(name):
    value = "127.0.0.1:41000" if name == "WATCHLIGHT_SIDECAR_ADDR" else "/run/wl/x"
    env = {name: value}
    if name == "WATCHLIGHT_SIDECAR_ADDR":
        env["WATCHLIGHT_SIDECAR_SECRET_FILE"] = "/run/wl/secret"
    if name == "WATCHLIGHT_SIDECAR_SECRET_FILE":
        env["WATCHLIGHT_SIDECAR_ADDR"] = "127.0.0.1:41000"
    marker = object()
    assert isinstance(select_backend(env=env, in_process=lambda: marker), SidecarBackend)
    with pytest.raises(GovernanceUnavailable):
        select_backend(env={**env, "WATCHLIGHT_BACKEND": "in_process"}, in_process=lambda: marker)


def test_the_enterprise_list_covers_what_the_plugins_read():
    """Every credential, endpoint, TLS or run-grant variable a plugin or the
    core reads must select the connector: none may leave a plugin on the
    in-process backend unnoticed."""
    root = Path(__file__).resolve().parents[2]
    pattern = re.compile(r"\b(WATCHLIGHT_[A-Z0-9_]+|WL_[A-Z_]*APDP[A-Z_]*)\b")
    enterprise = re.compile(r"TOKEN|URL|CREDENTIAL|MTLS|CA_|API_KEY|RUN_|TENANT|BEARER|PLAINTEXT|NO_PROXY|SIDECAR")
    found = set()
    for path in root.glob("*/watchlight_*/**/*.py"):
        for name in pattern.findall(path.read_text(encoding="utf-8")):
            if enterprise.search(name) and not name.endswith("_"):
                found.add(name)
    missing = sorted(found - set(ENTERPRISE_ENV_VARS) - {"WATCHLIGHT_BACKEND"})
    assert not missing, f"Enterprise variables that do not select the connector: {missing}"


# ---------------------------------------------------------------------------
# M5: fork
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_after_fork_kill_subscriptions_fire_and_egress_is_refused(base):
    async with stack(base) as (connector, backend):
        info = await backend.create_session("agent-1")
        egress = await backend.fetch_egress(info.run)
        sb._after_fork_in_child()
        try:
            notices: List[KillNotice] = []
            backend.subscribe_kill(info.run, notices.append)
            assert notices and notices[0].reason in ("forked", "run_ended", "unknown_run")
            assert backend.egress_for(info.run) is None
            with pytest.raises(GovernanceUnavailable):
                egress.marker()
            with pytest.raises(GovernanceUnavailable):
                egress.child_proxy_url()
        finally:
            backend._forked = False


# ---------------------------------------------------------------------------
# Lows
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_kill_callback_without_a_loop_does_not_run_on_the_io_thread(base):
    async with stack(base) as (connector, backend):
        info = await backend.create_session("agent-1")
        seen: List[str] = []
        t = threading.Thread(
            target=lambda: backend.subscribe_kill(info.run, lambda n: seen.append(threading.current_thread().name))
        )
        t.start()
        t.join()
        await connector.kill(info.run)
        assert await _wait_for(lambda: seen)
        assert seen[0] != "watchlight-sidecar-io"


@pytest.mark.asyncio
async def test_credential_values_in_pass_through_answers_are_refused(base):
    async with stack(base) as (connector, backend):
        info = await backend.create_session("agent-1")
        leak = "sst_LEAKED.token"
        connector.override["authorize"] = lambda p: {"ok": {"decision": {"decision": "Allow", "note": leak}}}
        connector.override["get_manifest"] = lambda p: {"ok": {"manifest": {"t": leak}}}
        connector.override["preflight_step"] = lambda p: {"ok": {"result": {"t": leak}}}
        connector.override["submit_plan"] = lambda p: {"ok": {"result": {"t": leak}}}
        connector.override["resolve_agent"] = lambda p: {"ok": {"agent": {"t": leak}}}
        decision = await backend.authorize("ok", "a", "r", run=info.run)
        assert decision["decision"] == "Deny" and leak not in str(decision)
        assert await backend.get_manifest("agent-1", run=info.run) is None
        assert await backend.preflight_step(info.run, "a", "r") is None
        assert await backend.submit_plan(info.run, [{"s": 1}]) is None
        assert await backend.resolve_agent("agent-1") is None


def test_the_secret_file_needs_safe_ancestors(base):
    open_dir = base / "open"
    open_dir.mkdir()
    os.chmod(open_dir, 0o777)
    private = open_dir / "wl"
    private.mkdir(mode=0o700)
    secret = private / "secret"
    fd = os.open(secret, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.write(fd, os.urandom(32).hex().encode() + b"\n")
    os.close(fd)
    with pytest.raises(wire.WireError):
        wire.read_secret_file(str(secret))
    os.chmod(open_dir, 0o755)
    assert len(wire.read_secret_file(str(secret))) == 32


@pytest.mark.asyncio
async def test_a_launched_connector_port_is_never_redialled(base):
    import sys

    root = str(Path(__file__).resolve().parents[1])
    argv = [sys.executable, "-c",
            f"import sys; sys.path.insert(0, {root!r}); "
            f"from tests.wl_local_standin import _main; import asyncio; asyncio.run(_main({str(base)!r}))"]
    backend = SidecarBackend.launch(argv)
    try:
        assert await backend.health_check() is True
        proc = backend._endpoint.proc
        host, port = backend._endpoint.host, backend._endpoint.port
        proc.kill()
        proc.wait(timeout=5)
        await asyncio.sleep(0.2)
        # Someone else takes the freed port.
        dialled: List[int] = []

        async def squatter(reader, writer):
            dialled.append(1)
            writer.close()

        server = await asyncio.start_server(squatter, host, port)
        try:
            with pytest.raises(GovernanceUnavailable):
                await backend.create_session("agent-1")
            await asyncio.sleep(0.2)
            assert dialled == []
        finally:
            server.close()
            await server.wait_closed()
    finally:
        await backend.close()


@pytest.mark.asyncio
async def test_a_create_answered_after_its_caller_left_is_ended(base):
    async with stack(base, request_timeout_s=5.0) as (connector, backend):
        await backend.health_check()
        conn = backend._conn
        loop = backend._io.loop()
        fut = asyncio.run_coroutine_threadsafe(
            conn.request("create_session", {"agent_id": "slow-agent", "ttl_seconds": 60}, 5.0), loop
        )
        await asyncio.sleep(0.1)
        fut.cancel()
        # The answer arrives at ~0.4 s with nobody waiting: the run is ended.
        assert await _wait_for(lambda: connector.runs and not connector.live_runs())
        assert not conn.closed
