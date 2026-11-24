"""A refused agent never runs, in every governance mode.

The Watchlight connector (``wl-sidecar``) answers ``denied`` when wl-apdp
refuses an agent with ``401`` / ``403``, with the typed trust code as the
reason (``agent_trust_revoked``, ...). ``SidecarBackend`` used to turn a
refused manifest into ``None``, which
``WATCHLIGHT_PLAN_GOVERNANCE_MODE=degrade`` let through: the refused
agent's run opened and its model took turns. A refusal now raises
:class:`GovernanceRefused` carrying the code, and only an outage reads as
"no manifest".

The HTTP client gets the same treatment for a session wl-apdp refuses for
the agent's trust state (the server-side gate).
"""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path
from typing import Any, Dict, Optional

import httpx
import pytest

from watchlight_core import GovernanceRefused, GovernanceUnavailable
from watchlight_core import _wl_local as wire
from watchlight_core.apdp_client import ApdpClient
from watchlight_core.env import require_manifest
from watchlight_core.errors import ScopeAttenuationDenied
from watchlight_core.sidecar_backend import SidecarBackend

from .wl_local_standin import StandInConnector

ASYNC_TEST_TIMEOUT_S = 30

TRUST_CODES = ("agent_trust_revoked", "agent_quarantined", "agent_unverified")


@pytest.fixture
def base():
    d = Path(tempfile.mkdtemp(prefix="wlr", dir="/tmp"))
    yield d
    shutil.rmtree(d, ignore_errors=True)


async def _stack(base: Path):
    connector = await StandInConnector(base, "unix").start()
    return connector, SidecarBackend(socket_path=connector.socket_path)


def test_the_trust_codes_are_on_the_closed_reason_list() -> None:
    for code in TRUST_CODES + ("delegation_chain_not_trusted",):
        assert code in wire.ERROR_REASONS
        assert wire.parse_error_body({"code": "denied", "reason": code}).valid


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["strict", "degrade"])
@pytest.mark.parametrize("code", TRUST_CODES)
async def test_a_refused_manifest_refuses_the_run_in_every_mode(base, monkeypatch, mode, code):
    """The canonical plugin sequence (session → manifest → gate) never
    reaches ``require_manifest`` for a refused agent, so degrade cannot
    let it through: no handle, no model turn."""
    monkeypatch.setenv("WATCHLIGHT_PLAN_GOVERNANCE_MODE", mode)
    connector, backend = await _stack(base)
    try:
        info = await backend.create_session("agent-1")
        connector.override["get_manifest"] = lambda p: {"error": {"code": "denied", "reason": code}}
        gated = False
        with pytest.raises(GovernanceRefused) as exc:
            manifest = await backend.get_manifest("agent-1", run=info.run)
            gated = True
            require_manifest(manifest, agent_id="agent-1")
        assert gated is False
        assert exc.value.code == code
        assert exc.value.reason == code
        assert isinstance(exc.value, GovernanceUnavailable)
    finally:
        await backend.close()
        await connector.stop()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "error, expected",
    [
        # A refusal without a typed code is still a refusal.
        ({"code": "denied"}, GovernanceRefused),
        # A malformed answer cannot rule a refusal out.
        ({"code": "denied", "reason": "teapot"}, GovernanceUnavailable),
        ({"code": "teapot"}, GovernanceUnavailable),
        # The run is gone: refused, never degraded.
        ({"code": "run_ended"}, GovernanceUnavailable),
        ({"code": "unknown_run"}, GovernanceUnavailable),
        # Only an outage reads as "no manifest".
        ({"code": "unavailable", "retry_after_ms": 100}, None),
        ({"code": "internal"}, None),
    ],
)
async def test_manifest_answers_map_fail_closed(base, monkeypatch, error, expected):
    monkeypatch.setenv("WATCHLIGHT_PLAN_GOVERNANCE_MODE", "degrade")
    connector, backend = await _stack(base)
    try:
        info = await backend.create_session("agent-1")
        connector.override["get_manifest"] = lambda p: {"error": error}
        if expected is None:
            assert await backend.get_manifest("agent-1", run=info.run) is None
        else:
            with pytest.raises(expected) as exc:
                await backend.get_manifest("agent-1", run=info.run)
            if expected is GovernanceUnavailable:
                assert not isinstance(exc.value, GovernanceRefused) or error["code"] == "denied"
            assert "teapot" not in str(exc.value)
    finally:
        await backend.close()
        await connector.stop()


@pytest.mark.asyncio
@pytest.mark.parametrize("code", TRUST_CODES)
async def test_a_trust_refused_session_raises_with_its_code(base, code):
    connector, backend = await _stack(base)
    try:
        connector.override["create_session"] = lambda p: {"error": {"code": "denied", "reason": code}}
        with pytest.raises(GovernanceRefused) as exc:
            await backend.create_session("agent-1")
        assert exc.value.code == code
        # Any other refusal stays opaque: no session.
        connector.override["create_session"] = lambda p: {"error": {"code": "denied"}}
        assert await backend.create_session("agent-1") is None
    finally:
        await backend.close()
        await connector.stop()


@pytest.mark.asyncio
@pytest.mark.parametrize("code", ("delegation_chain_not_trusted",) + TRUST_CODES)
async def test_a_trust_refused_spawn_carries_the_real_code(base, code):
    connector, backend = await _stack(base)
    try:
        info = await backend.create_session("agent-1")
        connector.override["spawn_subagent"] = lambda p: {"error": {"code": "denied", "reason": code}}
        with pytest.raises(GovernanceRefused) as exc:
            await backend.spawn_subagent(info.run, {"child_agent_id": "c"})
        assert not isinstance(exc.value, ScopeAttenuationDenied)
        assert exc.value.code == code
    finally:
        await backend.close()
        await connector.stop()


def _http_client(status: int, body: Any) -> ApdpClient:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/health":
            return httpx.Response(200, json={"auth": "ok", "kind": "plugin"})
        return httpx.Response(status, json=body)

    client = ApdpClient("http://localhost", auto_probe=False)
    client._client = httpx.AsyncClient(  # type: ignore[attr-defined]
        base_url="http://localhost", transport=httpx.MockTransport(handler)
    )
    return client


@pytest.mark.asyncio
@pytest.mark.parametrize("code", TRUST_CODES)
async def test_http_a_trust_refused_session_raises_with_its_code(code) -> None:
    client = _http_client(
        403,
        {"error": {"type": "Agent trust has been revoked: x", "code": code, "status": 403}},
    )
    try:
        with pytest.raises(GovernanceRefused) as exc:
            await client.create_session("agent-1")
        assert exc.value.code == code
        assert exc.value.status_code == 403
        assert "Agent trust has been revoked" not in str(exc.value)
    finally:
        await client.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "status, body",
    [
        (403, {"error": "Forbidden: application membership refused"}),
        (403, {"error": {"code": "something_else"}}),
        (401, {}),
        (500, {"error": {"code": "agent_trust_revoked"}}),
    ],
)
async def test_http_any_other_session_refusal_stays_none(status: int, body: Dict[str, Any]) -> None:
    client = _http_client(status, body)
    try:
        result: Optional[object] = await client.create_session("agent-1")
        assert result is None
    finally:
        await client.close()
