"""A wl-apdp refusal reaches the caller with its typed code.

- A refused spawn surfaces both codes the server may send (``error`` and
  ``reason``), so ``{"error": "delegation_chain_not_trusted"}`` is no longer
  reported as a bare ``APDP returned 403``.
- A refused constraint-manifest fetch (a revoked agent) raises
  :class:`GovernanceRefused` with the server's code instead of turning into
  "no manifest", which degraded mode would let through.
- Only bounded snake_case codes are kept: never free text from the body.
"""

from __future__ import annotations

from typing import Any, Dict

import httpx
import pytest

from watchlight_core import GovernanceRefused, GovernanceUnavailable, WatchlightError
from watchlight_core.apdp_client import ApdpClient, typed_refusal
from watchlight_core_testing import register_test_run

_SPAWN_BODY: Dict[str, Any] = {
    "parent_agent_id": "00000000-0000-0000-0000-000000000001",
    "child_agent_id": "00000000-0000-0000-0000-000000000002",
    "parent_run_handle_id": "00000000-0000-0000-0000-000000000003",
    "requested_scope": {},
}


def _client(status: int, body: Any) -> ApdpClient:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/health":
            return httpx.Response(200, json={"auth": "ok", "kind": "plugin"})
        if isinstance(body, (dict, list)):
            return httpx.Response(status, json=body)
        return httpx.Response(status, content=body)

    client = ApdpClient("http://localhost", auto_probe=False)
    client._client = httpx.AsyncClient(  # type: ignore[attr-defined]
        base_url="http://localhost", transport=httpx.MockTransport(handler)
    )
    return client


@pytest.mark.parametrize(
    "body, expected",
    [
        ({"error": "delegation_chain_not_trusted"}, ("delegation_chain_not_trusted", None)),
        ({"reason": "run_handle_invalidated"}, (None, "run_handle_invalidated")),
        (
            {"error": {"type": "Agent trust revoked: x", "code": "agent_trust_revoked"}},
            ("agent_trust_revoked", None),
        ),
        (
            {"error": {"type": "ungoverned_agentic_request", "reason": "no_execution_id"}},
            (None, "no_execution_id"),
        ),
        # Free text is never a code.
        ({"error": "Forbidden: secret detail here"}, (None, None)),
        ({"error": {"type": "Agent trust revoked: x", "message": "m"}}, (None, None)),
        ({"reason": "x" * 65}, (None, None)),
        (["delegation_chain_not_trusted"], (None, None)),
        ("delegation_chain_not_trusted", (None, None)),
    ],
)
def test_typed_refusal_reads_only_codes(body: Any, expected: Any) -> None:
    assert typed_refusal(body) == expected


@pytest.mark.asyncio
async def test_a_refused_spawn_names_the_error_code() -> None:
    client = _client(403, {"error": "delegation_chain_not_trusted"})
    try:
        with pytest.raises(GovernanceRefused) as info:
            await client.spawn_subagent(
                register_test_run(client, "sst_parent.sig"), dict(_SPAWN_BODY)
            )
    finally:
        await client.close()
    err = info.value
    assert isinstance(err, GovernanceUnavailable)
    assert err.status_code == 403
    assert err.error == "delegation_chain_not_trusted"
    assert err.reason is None
    assert err.code == "delegation_chain_not_trusted"
    assert str(err) == "spawn_subagent: APDP returned 403: error=delegation_chain_not_trusted"


@pytest.mark.asyncio
async def test_a_refused_spawn_names_both_codes() -> None:
    client = _client(403, {"error": "not_authorized", "reason": "parent_ended_during_spawn"})
    try:
        with pytest.raises(GovernanceRefused) as info:
            await client.spawn_subagent(
                register_test_run(client, "sst_parent.sig"), dict(_SPAWN_BODY)
            )
    finally:
        await client.close()
    assert info.value.code == "parent_ended_during_spawn"
    assert "error=not_authorized" in str(info.value)
    assert "reason=parent_ended_during_spawn" in str(info.value)


@pytest.mark.asyncio
async def test_a_refused_spawn_never_echoes_free_text() -> None:
    client = _client(403, {"error": "Forbidden: internal detail sk-live-123"})
    try:
        with pytest.raises(GovernanceRefused) as info:
            await client.spawn_subagent(
                register_test_run(client, "sst_parent.sig"), dict(_SPAWN_BODY)
            )
    finally:
        await client.close()
    assert info.value.code is None
    assert "sk-live" not in str(info.value)
    assert str(info.value) == "spawn_subagent: APDP returned 403"


@pytest.mark.asyncio
async def test_a_spawn_outage_is_not_a_refusal() -> None:
    client = _client(503, b"upstream down")
    try:
        with pytest.raises(WatchlightError) as info:
            await client.spawn_subagent(
                register_test_run(client, "sst_parent.sig"), dict(_SPAWN_BODY)
            )
    finally:
        await client.close()
    assert not isinstance(info.value, GovernanceRefused)
    # An outage is the same typed refusal every backend raises for a spawn
    # it cannot complete: the child never runs.
    assert isinstance(info.value, GovernanceUnavailable)
    assert str(info.value) == "spawn_subagent: APDP returned 503"


@pytest.mark.asyncio
async def test_a_revoked_agent_manifest_refusal_carries_the_code() -> None:
    client = _client(
        403,
        {
            "error": {
                "type": "Agent trust revoked: Agent 'a' has had its trust revoked",
                "code": "agent_trust_revoked",
                "message": "Agent trust has been revoked",
                "status": 403,
            }
        },
    )
    try:
        with pytest.raises(GovernanceRefused) as info:
            await client.get_manifest("00000000-0000-0000-0000-000000000001")
    finally:
        await client.close()
    err = info.value
    assert isinstance(err, GovernanceUnavailable)
    assert (err.status_code, err.code) == (403, "agent_trust_revoked")
    # The server's free text is not carried.
    assert "has had its trust revoked" not in str(err)


@pytest.mark.asyncio
async def test_a_manifest_refusal_is_never_degraded(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WATCHLIGHT_PLAN_GOVERNANCE_MODE", "degrade")
    client = _client(401, {"error": {"type": "Unauthorized", "message": "m"}})
    try:
        with pytest.raises(GovernanceRefused) as info:
            await client.get_manifest("00000000-0000-0000-0000-000000000001")
    finally:
        await client.close()
    assert (info.value.status_code, info.value.code) == (401, None)


@pytest.mark.asyncio
async def test_a_manifest_outage_is_still_no_manifest() -> None:
    client = _client(503, b"down")
    try:
        assert await client.get_manifest("00000000-0000-0000-0000-000000000001") is None
    finally:
        await client.close()
