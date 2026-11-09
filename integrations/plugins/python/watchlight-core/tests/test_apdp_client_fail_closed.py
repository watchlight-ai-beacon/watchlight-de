"""ApdpClient fails closed on every uncertain backend answer.

* ``authorize`` returns a Deny dict (never raises, never Allow) on a
  timeout, a protocol error, a non-JSON 200, or a 200 whose body is not
  a decision object.
* ``get_manifest`` returns ``None`` (so plan governance can refuse the
  run) instead of raising on a timeout-class or non-JSON answer.
* The backend httpx client ignores ``HTTP(S)_PROXY`` from the
  environment, so backend credentials never traverse the CONNECT
  sidecar / wl-proxy.
"""

from __future__ import annotations

import httpx
import pytest

from watchlight_core.apdp_client import ApdpClient


def _client_with(handler) -> ApdpClient:
    apdp = ApdpClient("http://localhost")
    apdp._probed = True
    apdp._client = httpx.AsyncClient(
        base_url="http://localhost", transport=httpx.MockTransport(handler)
    )
    return apdp


async def _authorize(apdp: ApdpClient) -> dict:
    return await apdp.authorize(
        principal='Agent::"a"',
        action='Action::"read"',
        resource='Resource::"r"',
        context={},
        execution_id="exec_x",
        session_id="ses_x",
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "exc",
    [
        httpx.ReadTimeout("slow"),
        httpx.ConnectTimeout("slow connect"),
        httpx.RemoteProtocolError("garbled"),
        httpx.ReadError("reset"),
    ],
    ids=["read_timeout", "connect_timeout", "protocol_error", "read_error"],
)
async def test_authorize_returns_deny_on_transport_failure(exc) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise exc

    result = await _authorize(_client_with(handler))
    assert result["decision"] == "Deny"


@pytest.mark.asyncio
async def test_authorize_returns_deny_on_non_json_200() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"<html>proxy login</html>")

    result = await _authorize(_client_with(handler))
    assert result["decision"] == "Deny"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "body",
    [[{"decision": "Allow"}], {"allowed": True}, {"decision": 1}, "Allow"],
    ids=["json_list", "no_decision_field", "non_string_decision", "json_string"],
)
async def test_authorize_returns_deny_on_unknown_response_shape(body) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=body)

    result = await _authorize(_client_with(handler))
    assert result["decision"] == "Deny"


@pytest.mark.asyncio
async def test_authorize_still_passes_a_well_formed_decision_through() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"decision": "Allow", "details": {}})

    result = await _authorize(_client_with(handler))
    assert result["decision"] == "Allow"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "make_response",
    [
        lambda: (_ for _ in ()).throw(httpx.RemoteProtocolError("garbled")),
        lambda: httpx.Response(200, content=b"not json"),
        lambda: httpx.Response(200, json=["not", "a", "manifest"]),
    ],
    ids=["protocol_error", "non_json_200", "non_object_manifest"],
)
async def test_get_manifest_returns_none_on_uncertain_answer(make_response) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return make_response()

    apdp = _client_with(handler)
    assert await apdp.get_manifest("agent-1") is None


@pytest.mark.asyncio
@pytest.mark.parametrize("call", ["preflight", "plan"])
@pytest.mark.parametrize(
    "make_response",
    [
        lambda: (_ for _ in ()).throw(httpx.ReadTimeout("slow")),
        lambda: (_ for _ in ()).throw(httpx.RemoteProtocolError("garbled")),
        lambda: httpx.Response(200, content=b"<html>proxy login</html>"),
        lambda: httpx.Response(200, json=["not", "an", "object"]),
    ],
    ids=["read_timeout", "protocol_error", "non_json_200", "non_object_200"],
)
async def test_preflight_and_plan_return_none_on_an_uncertain_answer(call, make_response) -> None:
    """Like resolve_agent and create_session: never a raw transport or JSON
    error, always ``None`` (the caller fails closed on it)."""

    def handler(request: httpx.Request) -> httpx.Response:
        return make_response()

    apdp = _client_with(handler)
    run = apdp._register_run(session_id="ses_x", agent_id="a", session_token="sst_x.y")
    if call == "preflight":
        assert await apdp.preflight_step(run, "read", "doc") is None
    else:
        assert await apdp.submit_plan(run, [{"action": "read"}]) is None


def test_backend_client_ignores_proxy_environment(monkeypatch) -> None:
    """Backend calls (carrying the plugin bearer and ``sst_`` run
    credentials) must never be routed through the CONNECT sidecar."""
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:9")
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:9")
    monkeypatch.setenv("ALL_PROXY", "http://127.0.0.1:9")
    apdp = ApdpClient("http://localhost:8081")
    client = apdp.client
    assert client.trust_env is False
    # No proxy transport mounted from the environment.
    assert not client._mounts


@pytest.mark.asyncio
async def test_hard_kill_escalator_ignores_proxy_environment(monkeypatch) -> None:
    """The wl-proxy internal token must not be sent through the CONNECT
    sidecar either."""
    from watchlight_core.kill_signal import httpx_hard_kill_escalator

    seen: dict = {}
    real = httpx.AsyncClient

    def _capture(*args, **kwargs):
        seen.update(kwargs)
        kwargs["transport"] = httpx.MockTransport(
            lambda request: httpx.Response(200, json={"status": "killed"})
        )
        return real(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", _capture)
    escalate = httpx_hard_kill_escalator("http://localhost:8078", "internal")
    await escalate("ses_x", "quarantine")
    assert seen.get("trust_env") is False
