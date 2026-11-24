"""``SidecarBackend``: the thin ``wl-local/1`` client of the Watchlight
connector, driven against a stand-in connector that follows the protocol
specification (``tests/wl_local_standin.py``).

Covers the normal flow on both transports and the adversarial cases: a
wrong or replayed server proof, an oversize or garbage frame, a socket or
directory with the wrong mode or owner, a connector that closes mid-request
or never answers, an unknown error reason or code, answers carrying extra
token-like fields, concurrent requests, kill pushes and connection loss,
cancellation, fork, and backend selection.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any, AsyncIterator, List, Tuple

import pytest

ASYNC_TEST_TIMEOUT_S = 30

from watchlight_core import _wl_local as wire
from watchlight_core import sidecar_backend as sb
from watchlight_core._lineage_retry import lineage_decision_path
from watchlight_core.backend import EgressBinding, GovernanceBackend, KillNotice, SessionInfo
from watchlight_core.errors import (
    AgentNotRegistered,
    GovernanceUnavailable,
    ParentRunUncredentialed,
    RunHandleInvalidated,
    ScopeAttenuationDenied,
)
from watchlight_core.scope import spawn_subagent_response_from_dict
from watchlight_core.sidecar_backend import SidecarBackend, SidecarEgress, select_backend

from .wl_local_standin import StandInConnector


@pytest.fixture
def base():
    # Short, private path: the Unix socket path limit is ~104 bytes.
    d = Path(tempfile.mkdtemp(prefix="wls", dir="/tmp"))
    yield d
    shutil.rmtree(d, ignore_errors=True)


@contextlib.asynccontextmanager
async def stack(base: Path, transport: str = "unix", **kw: Any) -> AsyncIterator[Tuple[StandInConnector, SidecarBackend]]:
    connector = await StandInConnector(base, transport).start()
    if transport == "unix":
        backend = SidecarBackend(socket_path=connector.socket_path, **kw)
    else:
        backend = SidecarBackend(address=connector.address, secret_file=connector.secret_path, **kw)
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


def _sent(connector: StandInConnector, method: str) -> List[dict]:
    return [f for f in connector.received if f["method"] == method]


# ---------------------------------------------------------------------------
# Normal flow
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize("transport", ["unix", "tcp"])
async def test_a_governed_run_end_to_end(base, transport):
    async with stack(base, transport) as (connector, backend):
        assert isinstance(backend, GovernanceBackend)
        assert await backend.health_check() is True
        assert (await backend.resolve_agent("agent-1"))["slug"] == "agent-1"
        assert await backend.resolve_agent("missing") is None

        info = await backend.create_session("agent-1", goal_id="g1", ttl_seconds=600)
        assert isinstance(info, SessionInfo)
        assert info.session_id.startswith("ses_") and info.execution_id.startswith("exec_")
        assert info.session["agent_id"] == "agent-1"
        run = info.run
        # The run was subscribed for kill pushes as part of opening it.
        assert _sent(connector, "subscribe_kill")[-1]["params"] == {"run": run}

        assert (await backend.authorize("ok", "read", "doc", run=run))["decision"] == "Allow"
        assert (await backend.authorize("deny", "read", "doc", run=run))["decision"] == "Deny"
        assert (await backend.get_manifest("agent-1", run=run)) == {"tool_allowlist": ["search"]}
        assert (await backend.preflight_step(run, "read", "doc"))["allowed"] is True
        assert (await backend.submit_plan(run, [{"tool": "search"}]))["allowed"] is True

        assert await backend.publish_events(run, [{"event_type": "a"}]) is True
        with lineage_decision_path():
            assert await backend.publish_events(run, [{"event_type": "b"}]) is True
        assert connector.runs[run]["modes"] == ["background", "decision_path"]
        await backend.drain(run, 1.0)

        assert await backend.complete_session(run) is True
        # Late lineage is still accepted for a short window; control is not.
        assert await backend.publish_events(run, [{"event_type": "terminal"}]) is True
        assert (await backend.authorize("ok", "read", "doc", run=run))["decision"] == "Deny"
        assert await backend.complete_session(run) is False
        assert connector.violations == []


@pytest.mark.asyncio
async def test_authorize_sends_execution_id_and_never_session_id(base):
    async with stack(base) as (connector, backend):
        info = await backend.create_session("agent-1")
        exec_id = "exec_0f0e0d0c-0b0a-4908-8706-050403020100"
        answer = await backend.authorize(
            "echo", "read", "doc", context={"k": 1}, execution_id=exec_id,
            session_id="ses_x", intent={"objective": "o"}, run=info.run,
        )
        sent = answer["echo"]
        assert sent["execution_id"] == exec_id and "session_id" not in sent
        assert sent["run"] == info.run and sent["intent"] == {"objective": "o"}
        # A malformed execution id is refused locally (fail closed).
        before = len(connector.received)
        bad = await backend.authorize("ok", "read", "doc", execution_id="EXEC-1", run=info.run)
        assert bad["decision"] == "Deny" and len(connector.received) == before


@pytest.mark.asyncio
async def test_publish_events_splits_large_batches_and_refuses_without_a_run(base):
    async with stack(base) as (connector, backend):
        info = await backend.create_session("agent-1")
        events = [{"event_type": "e", "i": i} for i in range(2500)]
        assert await backend.publish_events(info.run, events) is True
        frames = _sent(connector, "publish_events")
        assert [len(f["params"]["events"]) for f in frames] == [1000, 1000, 500]
        big = [{"blob": "x" * 400_000} for _ in range(5)]
        assert await backend.publish_events(info.run, big) is True
        assert all(len(wire.encode_frame(f)) <= wire.MAX_FRAME + 4 for f in _sent(connector, "publish_events"))
        assert await backend.publish_events(None, [{"event_type": "x"}]) is False
        assert await backend.publish_events(info.run, [{"blob": "x" * (wire.MAX_FRAME + 1)}]) is False


# ---------------------------------------------------------------------------
# Handshake and transport
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_wrong_server_proof_is_refused_and_nothing_else_is_sent(base, caplog):
    async with stack(base, "tcp") as (connector, backend):
        connector.wrong_proof = True
        with pytest.raises(GovernanceUnavailable):
            await backend.create_session("agent-1")
        assert await _wait_for(lambda: connector.bytes_after_challenge)
        assert connector.bytes_after_challenge == [0]
        assert not _sent(connector, "auth")
        assert (await backend.authorize("ok", "a", "r"))["decision"] == "Deny"


@pytest.mark.asyncio
async def test_a_replayed_challenge_does_not_verify(base):
    async with stack(base, "tcp") as (connector, backend):
        assert await backend.health_check() is True
        recorded = connector.recorded_challenges[0]
        await backend.close()
        # An impostor replays the connector's earlier challenge to a new
        # connection: it is bound to the old nonce_c and the old port.
        connector.replay_challenge = recorded
        with pytest.raises(GovernanceUnavailable):
            await backend.create_session("agent-1")
        assert await _wait_for(lambda: connector.bytes_after_challenge)
        assert connector.bytes_after_challenge == [0]
        # Each connection uses a fresh client nonce.
        assert len(set(connector.hello_nonces)) == len(connector.hello_nonces) == 2


@pytest.mark.asyncio
async def test_the_secret_never_crosses_the_connection_or_reaches_logs(base, caplog):
    caplog.set_level(logging.DEBUG)
    async with stack(base, "tcp") as (connector, backend):
        info = await backend.create_session("agent-1")
        await backend.authorize("ok", "a", "r", run=info.run)
        secret_hex = connector.secret.hex()
        assert secret_hex not in repr(connector.received)
        assert all("secret" not in f["params"] for f in connector.received)
        assert secret_hex not in caplog.text
        assert secret_hex not in repr(backend) and secret_hex not in repr(backend._endpoint)
        assert info.run not in caplog.text


@pytest.mark.asyncio
async def test_tcp_secret_file_must_be_private(base):
    connector = await StandInConnector(base, "tcp").start()
    try:
        os.chmod(connector.secret_path, 0o644)
        backend = SidecarBackend(address=connector.address, secret_file=connector.secret_path)
        with pytest.raises(GovernanceUnavailable):
            await backend.create_session("agent-1")
        await backend.close()
    finally:
        await connector.stop()


@pytest.mark.parametrize(
    "address",
    ["localhost:41000", "10.0.0.1:41000", "[::ffff:127.0.0.1]:41000", "127.0.0.1", "127.0.0.1:0", "wl:1"],
)
def test_only_loopback_ip_literals_are_dialled(address):
    with pytest.raises(GovernanceUnavailable):
        SidecarBackend(address=address, secret_file="/tmp/x/secret")


def test_configuration_is_explicit():
    with pytest.raises(GovernanceUnavailable):
        SidecarBackend(socket_path="/tmp/a/control.sock", address="127.0.0.1:1", secret_file="/tmp/s")
    with pytest.raises(GovernanceUnavailable):
        SidecarBackend(address="127.0.0.1:41000")
    with pytest.raises(GovernanceUnavailable):
        SidecarBackend(socket_path="relative/control.sock")
    with pytest.raises(GovernanceUnavailable):
        SidecarBackend(socket_path="/tmp/a/control.sock", secret_file="/tmp/s")


@pytest.mark.asyncio
@pytest.mark.parametrize("what", ["socket_mode", "dir_mode", "dir_symlink", "socket_owner", "peer_uid"])
async def test_an_unsafe_socket_is_never_connected(base, monkeypatch, what):
    connector = await StandInConnector(base).start()
    path = connector.socket_path
    try:
        if what == "socket_mode":
            os.chmod(path, 0o666)
        elif what == "dir_mode":
            os.chmod(connector.dir, 0o755)
        elif what == "dir_symlink":
            link = base / "link"
            link.symlink_to(connector.dir)
            path = str(link / "control.sock")
        elif what == "socket_owner":
            real = os.lstat
            uid = os.geteuid()

            def lstat_owned_by_another_user(p, *a, **k):
                st = real(p, *a, **k)
                if str(p) == path:
                    return os.stat_result((st.st_mode, st.st_ino, st.st_dev, st.st_nlink, uid + 1) + tuple(st)[5:10])
                return st

            monkeypatch.setattr(wire.os, "lstat", lstat_owned_by_another_user)
        elif what == "peer_uid":
            monkeypatch.setattr(wire, "peer_uid", lambda sock: os.geteuid() + 1)
        backend = SidecarBackend(socket_path=path)
        with pytest.raises(GovernanceUnavailable):
            await backend.create_session("agent-1")
        await backend.close()
        if what != "peer_uid":
            assert connector.received == []
        assert connector.live_runs() == []
    finally:
        await connector.stop()


def test_socket_checks_refuse_another_owner(base):
    d = base / "d"
    d.mkdir(mode=0o700)
    with pytest.raises(wire.WireError):
        wire.check_socket_path(str(d / "control.sock"), uid=os.geteuid() + 1)


def test_default_socket_path_follows_the_connector(monkeypatch):
    monkeypatch.setenv("XDG_RUNTIME_DIR", "/run/user/1000")
    assert str(wire.default_socket_path(1000)) == "/run/user/1000/watchlight/control.sock"
    monkeypatch.delenv("XDG_RUNTIME_DIR")
    assert str(wire.default_socket_path(1000)) == "/tmp/wl-1000/control.sock"


# ---------------------------------------------------------------------------
# Hostile or broken connector
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize("action", ["oversize", "garbage", "close"])
async def test_a_broken_frame_or_closed_connection_fails_closed_and_kills_runs(base, action):
    async with stack(base) as (connector, backend):
        info = await backend.create_session("agent-1")
        notices: List[KillNotice] = []
        backend.subscribe_kill(info.run, notices.append)
        connector.override["authorize"] = lambda p: action
        decision = await backend.authorize("ok", "a", "r", run=info.run)
        assert decision["decision"] == "Deny"
        assert await _wait_for(lambda: notices)
        assert notices[0].reason == "connection_lost"
        # Every run on the lost connection is gone; a new run reconnects.
        connector.override.clear()
        assert (await backend.authorize("ok", "a", "r", run=info.run))["decision"] == "Deny"
        info2 = await backend.create_session("agent-1")
        assert info2 is not None
        assert (await backend.authorize("ok", "a", "r", run=info2.run))["decision"] == "Allow"


@pytest.mark.asyncio
async def test_a_spawn_cut_off_mid_request_never_runs_the_child(base):
    async with stack(base) as (connector, backend):
        info = await backend.create_session("agent-1")
        connector.override["spawn_subagent"] = lambda p: "close"
        with pytest.raises(GovernanceUnavailable):
            await backend.spawn_subagent(info.run, {"child_agent_id": "c"})
        assert backend.egress_for(info.run) is None


@pytest.mark.asyncio
async def test_no_answer_in_time_is_a_deny(base):
    async with stack(base, request_timeout_s=0.3) as (connector, backend):
        info = await backend.create_session("agent-1")
        connector.override["authorize"] = lambda p: "silent"
        loop = asyncio.get_running_loop()
        t0 = loop.time()
        assert (await backend.authorize("ok", "a", "r", run=info.run))["decision"] == "Deny"
        assert loop.time() - t0 < 2
        # The connector still answers its health probe: the connection and
        # the run survive.
        connector.override.clear()
        await asyncio.sleep(0.5)
        assert (await backend.authorize("ok", "a", "r", run=info.run))["decision"] == "Allow"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "error",
    [
        {"code": "denied", "reason": "teapot"},
        {"code": "teapot"},
        {"code": "denied", "message": "internal detail"},
        {"code": "unavailable"},
        {"code": "internal", "reason": "revoked"},
    ],
)
async def test_an_unknown_or_malformed_error_is_a_safe_refusal(base, error):
    async with stack(base) as (connector, backend):
        info = await backend.create_session("agent-1")
        connector.override["authorize"] = lambda p: {"error": error}
        connector.override["spawn_subagent"] = lambda p: {"error": error}
        decision = await backend.authorize("ok", "a", "r", run=info.run)
        assert decision["decision"] == "Deny"
        assert "teapot" not in str(decision) and "internal detail" not in str(decision)
        with pytest.raises(GovernanceUnavailable) as exc:
            await backend.spawn_subagent(info.run, {"child_agent_id": "c"})
        assert not isinstance(exc.value, ScopeAttenuationDenied)
        # The connection stays usable.
        connector.override.clear()
        assert (await backend.authorize("ok", "a", "r", run=info.run))["decision"] == "Allow"


@pytest.mark.asyncio
async def test_extra_token_like_fields_never_surface(base, caplog):
    caplog.set_level(logging.DEBUG)
    async with stack(base) as (connector, backend):
        created: List[str] = []

        def leaky_create(p):
            state = connector._new_run(connector.conns[-1])
            created.append(state["run"])
            return {"ok": {
                "run": state["run"], "session_id": "ses_1", "execution_id": "exec_1",
                "root_execution_id": "exec_1", "scope": {}, "marker": state["marker"],
                "child_key": state["child_key"], "proxy_token": "sst_LEAKED.token",
            }}

        await backend.health_check()
        connector.override["create_session"] = leaky_create
        assert await backend.create_session("agent-1") is None
        # The run the connector made anyway is ended at once.
        assert await _wait_for(lambda: connector.runs[created[0]]["ended"])
        assert "sst_LEAKED" not in caplog.text

        connector.override.clear()
        info = await backend.create_session("agent-1")

        def leaky_spawn(p):
            child = connector._new_run(connector.conns[-1], parent=p["parent_run"])
            created.append(child["run"])
            return {"ok": {
                "child_run": child["run"], "session_id": "ses_2", "execution_id": "exec_2",
                "scope": {"child_run_handle_id": "6f1c1a52-6b0a-4c4e-9b8e-6d3f0b2b0a11",
                          "granted_scope": {"allowed_tools": ["sst_LEAKED.token"]}},
                "child_marker": child["marker"], "child_key": child["child_key"],
            }}

        connector.override["spawn_subagent"] = leaky_spawn
        with pytest.raises(GovernanceUnavailable) as exc:
            await backend.spawn_subagent(info.run, {"child_agent_id": "c"})
        assert "sst_" not in str(exc.value)
        assert await _wait_for(lambda: connector.runs[created[1]]["ended"])

        connector.override["egress_for"] = lambda p: {"ok": {
            "proxy_url": "http://127.0.0.1:41001", "marker_header": "Watchlight-Run-Marker",
            "marker": "M" * 43, "child_proxy_url": "http://wl:" + "K" * 43 + "@127.0.0.1:41001",
            "ca_bundle_path": "/etc/ssl/merged.pem",
        }}
        with pytest.raises(GovernanceUnavailable):
            await backend.fetch_egress(info.run)
        assert "sst_LEAKED" not in caplog.text and "merged.pem" not in caplog.text


@pytest.mark.asyncio
async def test_concurrent_requests_are_matched_and_bounded(base):
    async with stack(base) as (connector, backend):
        info = await backend.create_session("agent-1")
        ms = [(i * 37) % 120 for i in range(60)]
        answers = await asyncio.gather(*[
            backend.authorize(f"sleep:{m}", "a", "r", context={"i": i}, run=info.run)
            for i, m in enumerate(ms)
        ])
        assert [a["context"]["i"] for a in answers] == list(range(60))
        assert all(a["decision"] == "Allow" for a in answers)
        assert 1 < connector.max_in_flight_seen <= 16  # the spec limit, not the SDK constant
        assert connector.violations == []


@pytest.mark.asyncio
async def test_concurrent_callers_from_other_event_loops(base):
    async with stack(base) as (connector, backend):
        info = await backend.create_session("agent-1")

        def in_thread() -> str:
            return asyncio.run(backend.authorize("ok", "a", "r", run=info.run))["decision"]

        loop = asyncio.get_running_loop()
        results = await asyncio.gather(*[loop.run_in_executor(None, in_thread) for _ in range(4)])
        assert results == ["Allow"] * 4


# ---------------------------------------------------------------------------
# Sub-agents
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_spawn_maps_refusals_to_typed_errors(base):
    async with stack(base) as (connector, backend):
        info = await backend.create_session("agent-1")
        response = await backend.spawn_subagent(info.run, {"child_agent_id": "c"})
        parsed = spawn_subagent_response_from_dict(response)
        assert parsed.child_run == response["child_run"] != info.run
        assert parsed.child_session_id.startswith("ses_")
        assert set(response) <= set(sb._SPAWN_FIELDS) | {"child_run"}

        with pytest.raises(ScopeAttenuationDenied):
            await backend.spawn_subagent(info.run, {"overreach": True})
        connector.override["spawn_subagent"] = lambda p: {"error": {"code": "denied", "reason": "agent_not_registered"}}
        with pytest.raises(AgentNotRegistered):
            await backend.spawn_subagent(info.run, {"child_agent_id": "c"})
        connector.override["spawn_subagent"] = lambda p: {"error": {"code": "unavailable", "retry_after_ms": 100}}
        with pytest.raises(GovernanceUnavailable):
            await backend.spawn_subagent(info.run, {"child_agent_id": "c"})
        connector.override["spawn_subagent"] = lambda p: {"error": {"code": "unknown_run"}}
        with pytest.raises(ParentRunUncredentialed):
            await backend.spawn_subagent(info.run, {"child_agent_id": "c"})

        info2 = await backend.create_session("agent-1")
        connector.override.clear()
        with pytest.raises(RunHandleInvalidated):
            await backend.spawn_subagent(info2.run, {"invalidated": True})
        # The parent is ended locally: a later spawn is refused without a request.
        before = len(connector.received)
        with pytest.raises(GovernanceUnavailable):
            await backend.spawn_subagent(info2.run, {"child_agent_id": "c"})
        assert len(connector.received) == before


@pytest.mark.asyncio
async def test_ending_a_parent_ends_its_subtree(base):
    async with stack(base) as (connector, backend):
        info = await backend.create_session("agent-1")
        child = (await backend.spawn_subagent(info.run, {"child_agent_id": "c"}))["child_run"]
        grandchild = (await backend.spawn_subagent(child, {"child_agent_id": "g"}))["child_run"]
        notices: List[KillNotice] = []
        backend.subscribe_kill(grandchild, notices.append)
        assert await backend.complete_session(info.run) is True
        assert await _wait_for(lambda: notices)
        assert (await backend.authorize("ok", "a", "r", run=grandchild))["decision"] == "Deny"


# ---------------------------------------------------------------------------
# Kill, cancellation, dropped handles, fork
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_kill_push_ends_the_run(base):
    async with stack(base) as (connector, backend):
        info = await backend.create_session("agent-1")
        notices: List[KillNotice] = []
        backend.subscribe_kill(info.run, notices.append)
        await connector.kill(info.run, "operator")
        assert await _wait_for(lambda: notices)
        assert notices[0].source == "operator" and notices[0].run == info.run
        before = len(connector.received)
        assert (await backend.authorize("ok", "a", "r", run=info.run))["decision"] == "Deny"
        assert len(connector.received) == before
        # Subscribing to an ended run fires at once.
        late: List[KillNotice] = []
        backend.subscribe_kill(info.run, late.append)
        assert late and late[0].reason == "run_ended"


@pytest.mark.asyncio
async def test_a_cancelled_create_session_does_not_leave_a_run_behind(base):
    async with stack(base) as (connector, backend):
        await backend.health_check()
        task = asyncio.ensure_future(backend.create_session("slow-agent"))
        await asyncio.sleep(0.1)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert await _wait_for(lambda: connector.runs and not connector.live_runs())


@pytest.mark.asyncio
async def test_a_dropped_handle_ends_its_run(base):
    async with stack(base) as (connector, backend):
        info = await backend.create_session("agent-1")
        backend._release_dropped_run(info.run)
        assert await _wait_for(lambda: connector.runs[info.run]["ended"])
        assert (await backend.authorize("ok", "a", "r", run=info.run))["decision"] == "Deny"


@pytest.mark.asyncio
async def test_a_forked_child_cannot_use_the_parents_connection(base):
    async with stack(base) as (connector, backend):
        info = await backend.create_session("agent-1")
        sb._after_fork_in_child()
        try:
            assert (await backend.authorize("ok", "a", "r", run=info.run))["decision"] == "Deny"
            with pytest.raises(GovernanceUnavailable):
                await backend.create_session("agent-1")
        finally:
            backend._forked = False


@pytest.mark.asyncio
async def test_heartbeat_keeps_an_idle_connection(base, monkeypatch):
    monkeypatch.setattr(sb._Connection, "heartbeat_s", 0.1)
    async with stack(base) as (connector, backend):
        await backend.health_check()
        assert await _wait_for(lambda: len(_sent(connector, "health")) >= 3)


# ---------------------------------------------------------------------------
# Egress
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_egress_is_endpoint_info_only(base, monkeypatch):
    for name in ("SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "AWS_CA_BUNDLE", "NODE_EXTRA_CA_CERTS"):
        monkeypatch.delenv(name, raising=False)
    before_env = dict(os.environ)
    async with stack(base) as (connector, backend):
        info = await backend.create_session("agent-1")
        assert backend.egress_for(info.run) is None
        egress = await backend.fetch_egress(info.run)
        assert isinstance(egress, SidecarEgress) and isinstance(egress, EgressBinding)
        assert backend.egress_for(info.run) is egress
        assert egress.proxy_url == "http://127.0.0.1:41001"
        assert egress.marker_header == "Watchlight-Run-Marker"
        state = connector.runs[info.run]
        assert egress.marker() == state["marker"]
        assert egress.child_proxy_url().endswith("@127.0.0.1:41001")
        assert state["marker"] not in repr(egress) and state["child_key"] not in str(egress)
        assert not hasattr(egress, "ca_bundle_path")
        with pytest.raises(GovernanceUnavailable):
            egress.proxy_authorization()
        assert await backend.refresh_marker(info.run) is True
        assert egress.marker() == connector.runs[info.run]["marker"]
        assert await backend.report_connection(info.run, 50123) is True
        assert await backend.complete_session(info.run) is True
        with pytest.raises(GovernanceUnavailable):
            egress.marker()
        assert backend.egress_for(info.run) is None
    assert dict(os.environ) == before_env


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "proxy_url",
    ["http://10.0.0.5:41001", "https://127.0.0.1:41001", "http://localhost:41001", "http://127.0.0.1"],
)
async def test_a_non_local_egress_endpoint_is_refused(base, proxy_url):
    async with stack(base) as (connector, backend):
        info = await backend.create_session("agent-1")
        connector.override["egress_for"] = lambda p: {"ok": {
            "proxy_url": proxy_url, "marker_header": "Watchlight-Run-Marker",
            "marker": "M" * 43, "child_proxy_url": "http://wl:" + "K" * 43 + "@127.0.0.1:41001",
        }}
        with pytest.raises(GovernanceUnavailable):
            await backend.fetch_egress(info.run)
        assert backend.egress_for(info.run) is None


# ---------------------------------------------------------------------------
# Launch and selection
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_launched_connector_hands_its_secret_over_stdout_and_is_never_redialled(base):
    script = Path(__file__).with_name("wl_local_standin.py")
    env_path = str(Path(__file__).resolve().parents[1])
    argv = [sys.executable, "-c",
            f"import sys; sys.path.insert(0, {env_path!r}); "
            f"from tests.wl_local_standin import _main; import asyncio; asyncio.run(_main({str(base)!r}))"]
    assert script.exists()
    backend = SidecarBackend.launch(argv)
    try:
        info = await backend.create_session("agent-1")
        assert info is not None
        assert (await backend.authorize("ok", "a", "r", run=info.run))["decision"] == "Allow"
        proc = backend._endpoint.proc
        proc.kill()
        proc.wait(timeout=5)
        assert (await backend.authorize("ok", "a", "r", run=info.run))["decision"] == "Deny"
        with pytest.raises(GovernanceUnavailable):
            await backend.create_session("agent-1")
    finally:
        await backend.close()
    assert not any(backend._endpoint.launched_secret)


def test_select_backend():
    explicit = object()
    assert select_backend(explicit, env={"WATCHLIGHT_APDP_URL": "https://x"}) is explicit
    marker = object()
    assert select_backend(env={}, in_process=lambda: marker) is marker
    assert select_backend(env={"WATCHLIGHT_BACKEND": "in_process"}, in_process=lambda: marker) is marker
    for env in (
        {"WATCHLIGHT_BACKEND": "sidecar"},
        {"WATCHLIGHT_APDP_URL": "https://wl-apdp:8081"},
        {"WATCHLIGHT_PROXY_URL": "https://wl-proxy:8443"},
        {"WATCHLIGHT_SIDECAR_SOCKET": "/run/wl/control.sock"},
    ):
        assert isinstance(select_backend(env=env, in_process=lambda: marker), SidecarBackend)
    tcp = select_backend(env={"WATCHLIGHT_SIDECAR_ADDR": "127.0.0.1:41000",
                              "WATCHLIGHT_SIDECAR_SECRET_FILE": "/run/wl/secret"})
    assert tcp._endpoint.transport == "tcp"
    for env in (
        {"WATCHLIGHT_BACKEND": "apdp"},
        {"WATCHLIGHT_BACKEND": "in_process", "WATCHLIGHT_APDP_URL": "https://x"},
        {"WATCHLIGHT_SIDECAR_ADDR": "127.0.0.1:41000"},
        {"WATCHLIGHT_SIDECAR_ADDR": "127.0.0.1:41000", "WATCHLIGHT_SIDECAR_SOCKET": "/run/wl/c.sock",
         "WATCHLIGHT_SIDECAR_SECRET_FILE": "/run/wl/secret"},
    ):
        with pytest.raises(GovernanceUnavailable):
            select_backend(env=env, in_process=lambda: marker)


@pytest.mark.asyncio
async def test_selected_sidecar_without_a_connector_refuses_the_run(base):
    backend = select_backend(env={"WATCHLIGHT_SIDECAR_SOCKET": str(base / "none" / "control.sock")})
    try:
        with pytest.raises(GovernanceUnavailable):
            await backend.create_session("agent-1")
        assert (await backend.authorize("ok", "a", "r"))["decision"] == "Deny"
        assert await backend.health_check() is False
    finally:
        await backend.close()
