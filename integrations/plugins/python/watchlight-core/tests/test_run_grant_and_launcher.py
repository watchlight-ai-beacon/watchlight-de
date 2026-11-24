"""Launcher-bound runs: the run grant and the launcher helper.

A launcher outside the workload opens the run with its ``workload:bind``
service credential and hands the agent ONLY the run grant. These tests pin
the client side of that contract: the grant keeps its secrets out of every
printable form, parses a closed shape, authenticates as the run credential
(no tenant header, no plugin token), and the launcher refuses anything but
a service credential, never sends ``bound_by``, and refuses a response
whose credential does not carry the binding it asked for.
"""

from __future__ import annotations

import base64
import io
import json
import pickle

import httpx
import pytest

from watchlight_core import (
    ApdpClient,
    Credential,
    GovernanceUnavailable,
    InvalidCredential,
    PluginCredential,
    RunGrant,
    ServiceCredential,
)
from watchlight_core.launcher import (
    LABEL_AGENT,
    LABEL_GOVERNED,
    LABEL_LAUNCH,
    new_launch_id,
    open_bound_run,
    workload_labels,
    workload_ref,
)

AGENT = "5a952498-72e6-48d9-b3f5-7701b1e52aea"
SID = "ses_8d50df06-fcbc-4e47-aeb1-c2d008260dcc"
EID = "exec_71d67acb-7283-45ae-9818-d8c7ec0cb373"
WREF = {
    "kind": "openshell",
    "source_id": "openshell-gw-demo",
    "workload_id": "sbx-3f2a9c",
    "launch_id": "lnch_0123456789abcdef",
    "bound_by": "watchlight-launcher",
}


# In-process stand-in for unit tests only: an sst_-shaped token. The client
# decodes its payload for ids and never verifies it — wl-apdp does.
def _stand_in_run_token(**claims) -> str:
    body = {"sid": SID, "aid": AGENT, "iat": 1, "exp": 2**40, "eid": EID, **claims}
    raw = base64.urlsafe_b64encode(json.dumps(body).encode()).rstrip(b"=").decode()
    return f"sst_{raw}.c2ln"


def test_the_grant_decodes_ids_and_never_prints_secrets():
    token = _stand_in_run_token(tid="tenant-a", wref=WREF)
    grant = RunGrant(session_token=token, proxy_token="eyJ.proxy.secret")
    assert grant.session_id == SID
    assert grant.agent_id == AGENT
    assert grant.execution_id == EID
    assert grant.tenant_id == "tenant-a"
    assert grant.workload_ref == WREF
    for text in (repr(grant), str(grant), f"{grant}", "{}".format(grant)):
        assert token not in text and "proxy.secret" not in text, text
    with pytest.raises(TypeError):
        pickle.dumps(grant)


def test_the_grant_round_trips_over_stdin_and_the_shape_is_closed():
    grant = RunGrant(
        session_token=_stand_in_run_token(),
        proxy_token="eyJ.proxy.secret",
        root_run_handle_id="8d50df06-fcbc-4e47-aeb1-c2d008260dcc",
    )
    again = RunGrant.from_stdin(io.StringIO(grant.to_json() + "\n"))
    assert again.session_token == grant.session_token
    assert again.proxy_token == grant.proxy_token
    assert again.root_run_handle_id == grant.root_run_handle_id
    for bad in (
        "",
        "not json",
        "[]",
        json.dumps({"session_token": "wlpa_" + "x" * 43}),
        json.dumps({"session_token": "sst_nosignature"}),
        json.dumps({"session_token": _stand_in_run_token(), "plugin_token": "wlpa_x"}),
        json.dumps({"session_token": "sst_" + "A" * 70000 + ".x"}),
    ):
        with pytest.raises(InvalidCredential):
            RunGrant.from_json(bad)


def test_from_env_reads_only_the_run_variables_and_unsets_them():
    token = _stand_in_run_token()
    env = {
        "WATCHLIGHT_RUN_CREDENTIAL": token,
        "WATCHLIGHT_RUN_PROXY_TOKEN": "eyJ.proxy.secret",
        "WATCHLIGHT_RUN_HANDLE_ID": "h",
        "OTHER": "kept",
    }
    grant = RunGrant.from_env(env)
    assert grant.session_token == token and grant.proxy_token == "eyJ.proxy.secret"
    # A child process started later does not inherit the credential.
    assert env == {"OTHER": "kept"}
    with pytest.raises(InvalidCredential):
        RunGrant.from_env({"WATCHLIGHT_PLUGIN_TOKEN": "wlpa_" + "x" * 43})


def test_the_run_credential_sends_no_tenant_header_and_no_plugin_token():
    grant = RunGrant(session_token=_stand_in_run_token(tid="tenant-a"))
    client = ApdpClient("https://apdp.test", credential=grant.credential())
    headers = client._build_auth_headers()
    assert headers["Authorization"] == f"Bearer {grant.session_token}"
    assert headers["X-Wl-Credential-Kind"] == "run"
    assert "X-Wl-Tenant-Id" not in headers


def test_workload_ref_is_bounded_and_never_carries_bound_by():
    ref = workload_ref(
        kind="openshell",
        source_id="openshell-gw-demo",
        workload_id="sbx-3f2a9c",
        launch_id=new_launch_id(),
        workload_name="orchestrator",
    )
    assert "bound_by" not in ref
    for kwargs in (
        {"kind": "docker"},
        {"source_id": "GW"},
        {"workload_id": "sbx/../x"},
        {"launch_id": "short"},
        {"workload_name": "<b>"},
    ):
        base = dict(kind="openshell", source_id="openshell-gw-demo", workload_id="sbx-1")
        base.update(kwargs)
        with pytest.raises(ValueError):
            workload_ref(**base)
    labels = workload_labels(tenant_id="t", agent_id=AGENT, launch_id="lnch_0123456789ab")
    assert labels[LABEL_AGENT] == AGENT
    assert labels[LABEL_LAUNCH] == "lnch_0123456789ab"
    assert labels[LABEL_GOVERNED] == "true"


def _client(credential: Credential, handler) -> ApdpClient:
    client = ApdpClient("https://apdp.test", credential=credential)
    client._probed = True
    client._client = httpx.AsyncClient(
        base_url="https://apdp.test",
        headers=client._build_auth_headers(),
        transport=httpx.MockTransport(handler),
    )
    return client


def _launcher_credential() -> Credential:
    return ServiceCredential.new(bearer_token="wlsa_" + "l" * 43, service_name="watchlight-launcher")


@pytest.mark.asyncio
async def test_open_bound_run_sends_the_binding_and_returns_only_the_run_grant():
    sent = []
    token = _stand_in_run_token(wref=WREF)

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append((request.url.path, request.headers.get("authorization"), json.loads(request.content)))
        return httpx.Response(
            200,
            json={
                "session": {"id": SID, "workload_ref": WREF},
                "session_token": token,
                "execution_id": EID,
                "root_run_handle_id": "8d50df06-fcbc-4e47-aeb1-c2d008260dcc",
            },
        )

    ref = {k: v for k, v in WREF.items() if k != "bound_by"}
    grant = await open_bound_run(
        _client(_launcher_credential(), handler), agent_id=AGENT, workload=ref
    )
    path, auth, body = sent[0]
    assert path == "/sessions"
    assert auth.startswith("Bearer wlsa_")
    assert body["workload_ref"] == ref and "bound_by" not in body["workload_ref"]
    assert grant.session_token == token
    assert grant.root_run_handle_id == "8d50df06-fcbc-4e47-aeb1-c2d008260dcc"
    assert "wlsa_" not in grant.to_json()


@pytest.mark.asyncio
async def test_open_bound_run_fails_closed():
    ref = {k: v for k, v in WREF.items() if k != "bound_by"}

    def refused(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, json={"error": {"type": "not authorized"}})

    with pytest.raises(GovernanceUnavailable):
        await open_bound_run(_client(_launcher_credential(), refused), agent_id=AGENT, workload=ref)

    # Only a service credential can be a launcher.
    plugin = PluginCredential.new(bearer_token="wlpa_" + "p" * 43, tenant_id="default")
    with pytest.raises(GovernanceUnavailable):
        await open_bound_run(_client(plugin, refused), agent_id=AGENT, workload=ref)

    # bound_by is the server's to set.
    with pytest.raises(ValueError):
        await open_bound_run(
            _client(_launcher_credential(), refused), agent_id=AGENT, workload=WREF
        )

    # A credential that does not carry the requested binding is refused.
    other = dict(WREF, workload_id="sbx-someone-else")

    def unbound(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, json={"session": {"id": SID}, "session_token": _stand_in_run_token(wref=other)}
        )

    with pytest.raises(GovernanceUnavailable):
        await open_bound_run(_client(_launcher_credential(), unbound), agent_id=AGENT, workload=ref)
