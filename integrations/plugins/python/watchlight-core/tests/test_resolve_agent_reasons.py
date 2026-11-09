"""A resolve the server could not answer is not "agent not registered":
a refused credential, a licence refusal, a server error or no
answer raises a typed governance error; only a real miss returns None."""

from __future__ import annotations

import httpx
import pytest

from watchlight_core import ApdpClient, GovernanceUnavailable
from watchlight_core.errors import GovernanceRefused


def _client_with(handler) -> ApdpClient:
    apdp = ApdpClient("http://localhost")
    apdp._probed = True
    apdp._client = httpx.AsyncClient(base_url="http://localhost", transport=httpx.MockTransport(handler))
    return apdp


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [404, 403])
async def test_a_miss_returns_none(status) -> None:
    apdp = _client_with(lambda request: httpx.Response(status, json={}))
    assert await apdp.resolve_agent("researcher") is None


@pytest.mark.asyncio
async def test_a_refused_credential_raises_governance_refused() -> None:
    apdp = _client_with(lambda request: httpx.Response(401, json={}))
    with pytest.raises(GovernanceRefused) as err:
        await apdp.resolve_agent("researcher")
    assert err.value.status_code == 401


@pytest.mark.asyncio
async def test_a_licence_refusal_raises_unavailable() -> None:
    apdp = _client_with(lambda request: httpx.Response(402, headers={"x-license-status": "missing"}))
    with pytest.raises(GovernanceUnavailable, match="licence") as err:
        await apdp.resolve_agent("researcher")
    assert not isinstance(err.value, GovernanceRefused)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "make_response",
    [
        lambda: httpx.Response(503),
        lambda: httpx.Response(500),
        lambda: (_ for _ in ()).throw(httpx.ConnectError("refused")),
        lambda: (_ for _ in ()).throw(httpx.ReadTimeout("slow")),
    ],
    ids=["503", "500", "connect_error", "read_timeout"],
)
async def test_no_answer_raises_unavailable(make_response) -> None:
    apdp = _client_with(lambda request: make_response())
    with pytest.raises(GovernanceUnavailable):
        await apdp.resolve_agent("researcher")
