"""A run on behalf of a verified end user.

The SDK presents the identity-provider token on session creation as an RFC
8693 ``subject_token``; it never obtains or logs one. The in-process engine
refuses it: subject ingress is Enterprise-only.
"""

import asyncio
import json
import logging

import httpx
import pytest
from watchlight_core.apdp_client import ID_TOKEN_TYPE, ApdpClient
from watchlight_core.credentials import PluginCredential
from watchlight_core.errors import WatchlightContractError
from watchlight_core.in_process_client import InProcessClient


def _client(recorder: list, status: int = 200) -> ApdpClient:
    def handler(request: httpx.Request) -> httpx.Response:
        recorder.append(json.loads(request.content))
        return httpx.Response(status, json={"session": {"id": "ses_x"}, "session_token": "sst_x"})

    apdp = ApdpClient(
        "http://localhost",
        credential=PluginCredential.new("wlpa_shared_tenant_bearer", tenant_id="acme"),
    )
    apdp._probed = True
    apdp._client = httpx.AsyncClient(
        base_url="http://localhost",
        headers=apdp._build_auth_headers(),
        transport=httpx.MockTransport(handler),
    )
    return apdp


def test_the_token_rides_on_session_creation():
    sent: list = []
    asyncio.run(_client(sent).create_session("agent-1", subject_token="eyJ.subject.token"))
    assert sent[0]["subject_token"] == "eyJ.subject.token"
    assert sent[0]["subject_token_type"] == ID_TOKEN_TYPE


def test_without_a_token_the_body_is_unchanged():
    sent: list = []
    asyncio.run(_client(sent).create_session("agent-1"))
    assert "subject_token" not in sent[0] and "subject_token_type" not in sent[0]


def test_a_refused_token_is_never_logged(caplog):
    sent: list = []
    with caplog.at_level(logging.DEBUG):
        result = asyncio.run(
            _client(sent, status=401).create_session("agent-1", subject_token="eyJ.secret.token")
        )
    assert result is None
    assert "eyJ.secret.token" not in caplog.text


def test_the_in_process_engine_refuses_a_subject_token():
    with pytest.raises(WatchlightContractError):
        asyncio.run(InProcessClient.__new__(InProcessClient).create_session(
            "agent-1", subject_token="eyJ.subject.token"
        ))
