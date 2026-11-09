"""The plugin loads the default Watchlight credential when no key is given,
the same way the other plugins do (watchlight_core.load_default_credential)."""

from __future__ import annotations

import logging

import pytest

from watchlight_core import CredentialNotFound
from watchlight_claude_agent.plugin import WatchlightClaudeAgentSDKPlugin

TOKEN = "wlpa_aHR0cHM6Ly9hLmIvY3JlZGJ5dGVzMzJiaXRzcmFuZG9tCg"

_CRED_ENV = (
    "WATCHLIGHT_PLUGIN_TOKEN",
    "WATCHLIGHT_APDP_TOKEN",
    "WL_APDP_BEARER",
    "WL_STAGING_APDP_TOKEN",
    "WATCHLIGHT_TENANT_ID",
    "WATCHLIGHT_CREDENTIAL_FILE",
    "WATCHLIGHT_CREDENTIAL_AWS_SECRET_ID",
)


@pytest.fixture(autouse=True)
def _clean_credential_env(monkeypatch):
    for name in _CRED_ENV:
        monkeypatch.delenv(name, raising=False)


def _plugin() -> WatchlightClaudeAgentSDKPlugin:
    return WatchlightClaudeAgentSDKPlugin(apdp_url="http://localhost:8081")


def test_a_configured_credential_file_sends_its_bearer(monkeypatch, tmp_path):
    cred = tmp_path / "plugin.cred"
    cred.write_text(f"APDP_TOKEN={TOKEN}\nTENANT_ID=acme\n")
    cred.chmod(0o600)
    monkeypatch.setenv("WATCHLIGHT_CREDENTIAL_FILE", str(cred))
    headers = _plugin().apdp.client.headers
    assert headers["Authorization"] == f"Bearer {TOKEN}"
    assert headers["X-Wl-Credential-Kind"] == "plugin"


def test_an_explicit_key_still_wins(monkeypatch, tmp_path):
    cred = tmp_path / "plugin.cred"
    cred.write_text(f"APDP_TOKEN={TOKEN}\nTENANT_ID=acme\n")
    monkeypatch.setenv("WATCHLIGHT_CREDENTIAL_FILE", str(cred))
    plugin = WatchlightClaudeAgentSDKPlugin(apdp_url="http://localhost:8081", apdp_api_key="explicit-key")
    assert plugin.apdp.client.headers["Authorization"] == "Bearer explicit-key"


def test_a_configured_credential_that_cannot_be_loaded_raises(monkeypatch, tmp_path):
    bad = tmp_path / "plugin.cred"
    bad.write_text("wlpa_SECRETVALUE\n")
    monkeypatch.setenv("WATCHLIGHT_CREDENTIAL_FILE", str(bad))
    with pytest.raises(CredentialNotFound) as err:
        _plugin()
    assert "SECRETVALUE" not in str(err.value)
    assert err.value.__cause__ is None


def test_a_missing_configured_credential_file_raises(monkeypatch, tmp_path):
    monkeypatch.setenv("WATCHLIGHT_CREDENTIAL_FILE", str(tmp_path / "absent.cred"))
    with pytest.raises(CredentialNotFound):
        _plugin()


def test_a_malformed_token_in_the_environment_raises(monkeypatch):
    # A credential that is present but failing never goes anonymous.
    monkeypatch.setenv("WATCHLIGHT_PLUGIN_TOKEN", "not-a-token-SECRETVALUE")
    monkeypatch.setenv("WATCHLIGHT_TENANT_ID", "acme")
    with pytest.raises(CredentialNotFound) as err:
        _plugin()
    assert "SECRETVALUE" not in str(err.value)
    assert err.value.__cause__ is None


def test_nothing_configured_sends_no_credential(caplog):
    # Unchanged: no credential, so the server refuses the run (fail closed).
    with caplog.at_level(logging.WARNING):
        plugin = _plugin()
    assert "Authorization" not in plugin.apdp.client.headers
    assert "could not be loaded" not in " ".join(r.getMessage() for r in caplog.records)


# ─── Why a run was refused ──────────────────────────────────


def _plugin_answering(handler) -> WatchlightClaudeAgentSDKPlugin:
    import httpx

    plugin = _plugin()
    plugin.apdp._probed = True
    plugin.apdp._client = httpx.AsyncClient(base_url="http://localhost", transport=httpx.MockTransport(handler))
    return plugin


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "make_response",
    [
        lambda: __import__("httpx").Response(402, headers={"x-license-status": "missing"}),
        lambda: __import__("httpx").Response(503),
        lambda: (_ for _ in ()).throw(__import__("httpx").ConnectError("refused")),
    ],
    ids=["licence", "unavailable", "unreachable"],
)
async def test_a_server_that_cannot_answer_is_not_reported_as_an_unregistered_agent(make_response):
    from watchlight_core import AgentNotRegistered, GovernanceUnavailable

    plugin = _plugin_answering(lambda request: make_response())
    with pytest.raises(GovernanceUnavailable) as err:
        await plugin.start_run("research-agent")
    assert not isinstance(err.value, AgentNotRegistered)


@pytest.mark.asyncio
async def test_a_refused_credential_is_reported_as_a_refusal():
    import httpx

    from watchlight_core import AgentNotRegistered, GovernanceRefused

    plugin = _plugin_answering(lambda request: httpx.Response(401, json={}))
    with pytest.raises(GovernanceRefused) as err:
        await plugin.start_run("research-agent")
    assert err.value.status_code == 401
    assert not isinstance(err.value, AgentNotRegistered)


@pytest.mark.asyncio
async def test_an_unregistered_agent_is_still_reported_as_one():
    import httpx

    from watchlight_core import AgentNotRegistered

    plugin = _plugin_answering(lambda request: httpx.Response(404, json={}))
    with pytest.raises(AgentNotRegistered):
        await plugin.start_run("research-agent")
