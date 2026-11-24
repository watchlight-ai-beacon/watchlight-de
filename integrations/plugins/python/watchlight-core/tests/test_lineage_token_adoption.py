"""Execution-lineage integrity — the SDK adopts the
canonical root ``execution_id`` from its OWN wl-apdp proxy token so the
in-process emit stream and the wl-proxy egress lineage share one root id.

wl-apdp mints the id server-side and binds it into the signed proxy token
(``exec_id`` claim); wl-proxy derives the emitted ``execution_id`` from
that VERIFIED claim (never a client-settable header). These tests pin the
SDK adoption side.
"""

from __future__ import annotations

import base64
import json

import asyncio

import httpx

from watchlight_core import GovernanceTelemetry
from watchlight_core.apdp_client import (
    ApdpClient,
    decode_proxy_token_exec_id as _decode_proxy_token_exec_id,
)
from watchlight_core.run_handle import BaseRunHandle


# In-process stand-in for unit tests only.
def _stub_proxy_token(claims: dict) -> str:
    """Build a syntactically-valid (unsigned) JWT carrying ``claims``.

    The SDK reads its OWN token's payload without signature verification
    (it is learning the id wl-apdp assigned, not making a trust
    decision), so an unsigned 3-part token is sufficient for these tests.
    """

    def seg(obj: dict) -> str:
        raw = json.dumps(obj).encode("utf-8")
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")

    header = seg({"alg": "ES256", "typ": "JWT", "kid": "test"})
    payload = seg(claims)
    return f"{header}.{payload}.{'sig'}"


def _plugin() -> GovernanceTelemetry:
    class Plugin(GovernanceTelemetry):
        def __init__(self):
            super().__init__()
            self.apdp = ApdpClient("https://apdp.test")
            self.tenant_id = "acme"
            self.log_decisions = False

    return Plugin()


# ── _decode_proxy_token_exec_id ────────────────────────────────────────


def test_decode_reads_exec_id_claim():
    token = _stub_proxy_token(
        {"exec_id": "exec_aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", "sub": "agent"}
    )
    assert (
        _decode_proxy_token_exec_id(token)
        == "exec_aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
    )


def test_decode_returns_none_for_token_without_exec_id():
    token = _stub_proxy_token({"sub": "agent", "sid": "ses_x"})
    assert _decode_proxy_token_exec_id(token) is None


def test_decode_returns_none_for_malformed_inputs():
    assert _decode_proxy_token_exec_id(None) is None
    assert _decode_proxy_token_exec_id("") is None
    assert _decode_proxy_token_exec_id("not-a-jwt") is None
    assert _decode_proxy_token_exec_id("only.two") is None
    assert _decode_proxy_token_exec_id("a.!!!not-base64!!!.c") is None


# ── Adoption: ApdpClient reports the id, the handle takes it ─────────


def _session_client(response_body: dict) -> ApdpClient:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=response_body)

    apdp = ApdpClient("https://apdp.test")
    apdp._probed = True
    apdp._client = httpx.AsyncClient(
        base_url="https://apdp.test", transport=httpx.MockTransport(handler)
    )
    return apdp


def _open(response_body: dict):
    return asyncio.run(_session_client(response_body).create_session("uuid-x"))


def test_session_adopts_execution_id_from_proxy_token():
    token = _stub_proxy_token(
        {"exec_id": "exec_12345678-1234-1234-1234-123456789abc"}
    )
    info = _open({"session": {"id": "ses_x"}, "session_token": "sst_a.b", "proxy_token": token})
    assert info.execution_id == "exec_12345678-1234-1234-1234-123456789abc"
    h = BaseRunHandle(
        plugin=_plugin(),
        agent_uuid="uuid-x",
        session_id=info.session_id,
        run=info.run,
        execution_id=info.execution_id,
    )
    assert h.execution_id == "exec_12345678-1234-1234-1234-123456789abc"
    # Root defaults to the adopted id for a root run.
    assert h.root_execution_id == "exec_12345678-1234-1234-1234-123456789abc"


def test_server_execution_id_wins_over_token_claim():
    token = _stub_proxy_token({"exec_id": "exec_from-token"})
    info = _open(
        {
            "session": {"id": "ses_x"},
            "session_token": "sst_a.b",
            "proxy_token": token,
            "execution_id": "exec_explicit-wins",
        }
    )
    assert info.execution_id == "exec_explicit-wins"


def test_handle_self_mints_when_no_token():
    info = _open({"session": {"id": "ses_x"}, "session_token": "sst_a.b"})
    assert info.execution_id is None
    h = BaseRunHandle(plugin=_plugin(), agent_uuid="uuid-x", session_id="ses_x", run=info.run)
    assert h.execution_id.startswith("exec_")


def test_handle_self_mints_when_token_lacks_exec_id():
    token = _stub_proxy_token({"sub": "agent"})  # no exec_id claim
    info = _open({"session": {"id": "ses_x"}, "session_token": "sst_a.b", "proxy_token": token})
    assert info.execution_id is None
    h = BaseRunHandle(
        plugin=_plugin(),
        agent_uuid="uuid-x",
        session_id="ses_x",
        run=info.run,
        execution_id=info.execution_id,
    )
    assert h.execution_id.startswith("exec_")
    assert h.execution_id != "exec_"
