"""Adopting a launcher-bound run inside a workload.

The agent inside an OpenShell sandbox holds only the run grant a launcher
handed it. ``adopt_run`` must open NO session and resolve NO slug, present
the run credential as its only credential (no tenant header, no plugin
token), and keep ``start_run`` exactly as it was.
"""

from __future__ import annotations

import base64
import json
from unittest.mock import AsyncMock

import httpx
import pytest

from watchlight_core import ApdpClient, InProcessClient, PluginCredential, RunGrant
from watchlight_langgraph import WatchlightLangGraphPlugin

AGENT = "5a952498-72e6-48d9-b3f5-7701b1e52aea"
SID = "ses_8d50df06-fcbc-4e47-aeb1-c2d008260dcc"
EID = "exec_71d67acb-7283-45ae-9818-d8c7ec0cb373"
HANDLE = "8d50df06-fcbc-4e47-aeb1-c2d008260dcc"


# In-process stand-in for unit tests only: an sst_-shaped run credential.
def _stand_in_grant() -> RunGrant:
    body = {"sid": SID, "aid": AGENT, "iat": 1, "exp": 2**40, "eid": EID, "tid": "t"}
    raw = base64.urlsafe_b64encode(json.dumps(body).encode()).rstrip(b"=").decode()
    return RunGrant(session_token=f"sst_{raw}.c2ln", root_run_handle_id=HANDLE)


def _recording_client(credential, seen: list) -> ApdpClient:
    client = ApdpClient("https://apdp.test", credential=credential)

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.url.path == "/authorize":
            return httpx.Response(200, json={"decision": "Allow", "reason": "ok"})
        if request.url.path == "/constraints/manifest":
            return httpx.Response(200, json={"manifest": {"agent_id": AGENT}})
        return httpx.Response(200, json={})

    client._probed = True
    client._client = httpx.AsyncClient(
        base_url="https://apdp.test",
        headers=client._build_auth_headers(),
        transport=httpx.MockTransport(handler),
    )
    return client


@pytest.mark.asyncio
async def test_adopt_run_opens_nothing_and_presents_only_the_run_credential():
    grant = _stand_in_grant()
    seen: list = []
    plugin = WatchlightLangGraphPlugin(
        governance=_recording_client(grant.credential(), seen), log_decisions=False
    )
    async with await plugin.adopt_run(grant) as handle:
        assert handle.session_id == SID
        assert handle.execution_id == EID
        # The handle names the run; the credential stays in the client.
        assert handle.run is not None
        assert not hasattr(handle, "session_token")
        assert handle.run_handle_id == HANDLE
        await handle.authorize_action("document_read", "q1-revenue")
    paths = [r.url.path for r in seen]
    assert "/sessions" not in paths and "/agents/resolve" not in paths, paths
    # The run is closed with the same credential.
    assert f"/sessions/{SID}/complete" in paths, paths
    for request in seen:
        assert request.headers["authorization"] == f"Bearer {grant.session_token}"
        assert "x-wl-tenant-id" not in request.headers
        assert "wlpa_" not in str(request.headers)
    authorize = next(r for r in seen if r.url.path == "/authorize")
    assert authorize.headers["x-wl-run-authorization"] == f"Bearer {grant.session_token}"
    assert json.loads(authorize.content)["principal"] == f'Agent::"{AGENT}"'


@pytest.mark.asyncio
async def test_adopt_run_refuses_a_client_holding_another_credential():
    grant = _stand_in_grant()
    plugin_token = PluginCredential.new(bearer_token="wlpa_" + "p" * 43, tenant_id="default")
    plugin = WatchlightLangGraphPlugin(
        governance=_recording_client(plugin_token, []), log_decisions=False
    )
    with pytest.raises(ValueError):
        await plugin.adopt_run(grant)
    other = _recording_client(RunGrant(session_token=grant.session_token + "x").credential(), [])
    with pytest.raises(ValueError):
        await WatchlightLangGraphPlugin(governance=other, log_decisions=False).adopt_run(grant)


@pytest.mark.asyncio
async def test_adopt_run_needs_an_explicit_grant(monkeypatch):
    """L3 — no implicit default: a credential in the environment is never
    picked up behind the caller's back."""
    grant = _stand_in_grant()
    monkeypatch.setenv("WATCHLIGHT_RUN_CREDENTIAL", grant.session_token)
    plugin = WatchlightLangGraphPlugin(
        governance=_recording_client(grant.credential(), []), log_decisions=False
    )
    with pytest.raises((TypeError, ValueError)):
        await plugin.adopt_run()  # type: ignore[call-arg]
    with pytest.raises(ValueError):
        await plugin.adopt_run(None)  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_the_in_process_engine_has_no_launcher_bound_runs():
    engine = InProcessClient.__new__(InProcessClient)  # no compiled engine needed
    plugin = WatchlightLangGraphPlugin(governance=engine, log_decisions=False)
    with pytest.raises(ValueError):
        await plugin.adopt_run(_stand_in_grant())


@pytest.mark.asyncio
async def test_start_run_is_unchanged():
    seen: list = []
    plugin = WatchlightLangGraphPlugin(apdp_url="http://localhost:8081", log_decisions=False)

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(
            200,
            json={"session": {"id": SID}, "session_token": "sst_x.y", "execution_id": EID},
        )

    plugin.apdp._probed = True
    plugin.apdp._client = httpx.AsyncClient(
        base_url="http://localhost:8081", transport=httpx.MockTransport(handler)
    )
    plugin.apdp.resolve_agent = AsyncMock(return_value={"id": AGENT})  # type: ignore[method-assign]
    plugin.apdp.get_manifest = AsyncMock(return_value={})  # type: ignore[method-assign]
    handle = await plugin.start_run("agent-x")
    assert [r.url.path for r in seen] == ["/sessions"]
    assert "workload_ref" not in json.loads(seen[0].content)
    assert handle.session_id == SID and handle.execution_id == EID
