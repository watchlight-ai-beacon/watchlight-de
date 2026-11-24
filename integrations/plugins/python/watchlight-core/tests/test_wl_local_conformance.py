"""Client-side conformance with ``wl-local/1``.

* The golden fixtures in ``contracts/wl-local-1/fixtures`` (the same files
  the Rust connector tests run): every valid frame is accepted by the SDK's
  wire checks and every invalid one refused.
* The loopback-TCP handshake proofs match the ones the Rust core computed
  for the fixture (same label, field order, length prefixes and binding).
* A client conformance kit, the SDK-side mirror of the core's
  ``check_backend``: fresh run, marker and child key per session; no
  credential ever reaches the caller; a run is never served for a backend
  that did not create it; a child has its own run and marker; an ended run
  is refused locally without a request; ``health`` answers; and every frame
  the SDK sent was valid.
"""

from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path
from typing import Any, Dict

import pytest

ASYNC_TEST_TIMEOUT_S = 30

from watchlight_core import _wl_local as wire
from watchlight_core.backend import SessionInfo
from watchlight_core.sidecar_backend import SidecarBackend

from .wl_local_standin import StandInConnector

FIXTURES = Path(__file__).resolve().parents[3] / "contracts" / "wl-local-1" / "fixtures"


def test_the_protocol_fixtures_are_present():
    """A missing fixture directory fails, it never skips the conformance cases."""
    assert FIXTURES.is_dir(), f"{FIXTURES} is missing"
    assert any(FIXTURES.iterdir()), f"{FIXTURES} is empty"


def _load(kind: str):
    if not FIXTURES.is_dir():
        return []
    return [
        pytest.param(json.loads(p.read_text()), id=p.name)
        for p in sorted((FIXTURES / kind).glob("*.json"))
    ]


def _accepted(f: Dict[str, Any]) -> bool:
    body = f["frame_text"].encode() if "frame_text" in f else json.dumps(f["frame"]).encode()
    transport = f.get("transport")
    try:
        frame = wire.decode_json(body)
        if f["direction"] == "client":
            wire.validate_client_frame(frame, transport=transport)
            return True
        parsed = wire.parse_server_frame(frame)
        if isinstance(parsed, wire.KillPush):
            return True
        if parsed.error is not None:
            return parsed.error.valid
        method = f.get("in_reply_to")
        return method is not None and wire.validate_result(method, parsed.ok, transport=transport)
    except wire.WireError:
        return False


@pytest.mark.parametrize("fixture", _load("valid"))
def test_every_valid_fixture_is_accepted(fixture):
    assert _accepted(fixture)


@pytest.mark.parametrize("fixture", _load("invalid"))
def test_every_invalid_fixture_is_refused(fixture):
    assert not _accepted(fixture)


def test_every_request_method_has_a_valid_client_fixture():
    methods = {
        json.loads(p.read_text())["frame"]["method"]
        for p in (FIXTURES / "valid").glob("client-*.json")
        if "frame" in json.loads(p.read_text())
    }
    assert wire.METHODS <= methods


def test_tcp_handshake_proofs_match_the_rust_fixture():
    challenge = json.loads((FIXTURES / "valid" / "server-hello-tcp-challenge.json").read_text())
    hello = json.loads((FIXTURES / "valid" / "client-hello-tcp.json").read_text())
    auth = json.loads((FIXTURES / "valid" / "client-auth.json").read_text())
    b = challenge["binding"]
    host_c, port_c = b["client"].rsplit(":", 1)
    host_s, port_s = b["server"].rsplit(":", 1)
    binding = wire.ChannelBinding.of((host_c, int(port_c)), (host_s, int(port_s)))
    secret = bytes.fromhex(b["secret"])
    nonce_c = hello["frame"]["params"]["nonce_c"]
    nonce_s = challenge["frame"]["ok"]["nonce_s"]
    proof = challenge["frame"]["ok"]["server_proof"]
    assert wire.verify_server_proof(secret, wire.PROTO, nonce_c, nonce_s, binding, proof)
    assert wire.client_proof(secret, wire.PROTO, nonce_c, nonce_s, binding) == auth["frame"]["params"]["client_proof"]
    # Bound to both ends: another port or another address does not verify.
    for other in (
        wire.ChannelBinding.of((host_c, int(port_c) + 1), (host_s, int(port_s))),
        wire.ChannelBinding.of(("127.0.0.2", int(port_c)), (host_s, int(port_s))),
        wire.ChannelBinding.of((host_c, int(port_c)), (host_s, int(port_s) + 1)),
    ):
        assert not wire.verify_server_proof(secret, wire.PROTO, nonce_c, nonce_s, other, proof)
    # An IPv4-mapped IPv6 address counts as its IPv4 form.
    mapped = wire.ChannelBinding.of(("::ffff:" + host_c, int(port_c)), (host_s, int(port_s)))
    assert wire.verify_server_proof(secret, wire.PROTO, nonce_c, nonce_s, mapped, proof)


@pytest.mark.asyncio
async def test_client_conformance_kit():
    base = Path(tempfile.mkdtemp(prefix="wls", dir="/tmp"))
    connector = await StandInConnector(base).start()
    a = SidecarBackend(socket_path=connector.socket_path)
    b = SidecarBackend(socket_path=connector.socket_path)
    try:
        sessions = [await a.create_session("agent-1") for _ in range(3)]
        assert all(isinstance(s, SessionInfo) for s in sessions)
        # Fresh run, marker and child key per session; marker != child key.
        entries = [a._runs[s.run] for s in sessions]
        for key in ("run", "marker", "child_key"):
            assert len({getattr(e, key) for e in entries}) == 3
        assert all(e.marker != e.child_key for e in entries)
        # Nothing credential-like reaches the caller.
        for s in sessions:
            assert "sst_" not in repr(s) and "eyJ" not in repr(s)
            assert entries[0].marker not in repr(s)

        # A run is never served for a backend that did not create it, and
        # the refusal is local: nothing is sent.
        run1 = sessions[0].run
        sent = len(connector.received)
        assert (await b.authorize("p", "a", "r", run=run1))["decision"] == "Deny"
        assert await b.get_manifest("agent-1", run=run1) is None
        assert await b.publish_events(run1, [{"event_type": "x"}]) is False
        assert len(connector.received) == sent

        # A child has its own run and marker.
        child = await a.spawn_subagent(run1, {"child_agent_id": "agent-2"})
        assert child["child_run"] != run1
        assert a._runs[child["child_run"]].marker != a._runs[run1].marker

        # After complete / terminate the run is refused locally.
        assert await a.complete_session(run1) is True
        assert await a.terminate_session(sessions[1].run, "conformance") is True
        sent = len(connector.received)
        for run in (run1, sessions[1].run, child["child_run"]):
            assert (await a.authorize("p", "a", "r", run=run))["decision"] == "Deny"
            assert await a.preflight_step(run, "a", "r") is None
        assert len(connector.received) == sent

        assert await a.health_check() is True
        assert connector.violations == []
    finally:
        await a.close()
        await b.close()
        await connector.stop()
        shutil.rmtree(base, ignore_errors=True)
