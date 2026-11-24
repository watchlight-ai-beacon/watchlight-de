"""Bedrock plugin — CONNECT proxy auto-install wiring.

Mirror of `watchlight-langgraph` tests for the production-grade
CONNECT path. Bedrock's interest in this is BOTO3 — boto3 uses
botocore which uses urllib3 which honors HTTPS_PROXY, so once the
sidecar is installed the customer's `bedrock_client.invoke_model(...)`
calls auto-tunnel through wl-proxy.
"""

from __future__ import annotations

from unittest.mock import ANY, AsyncMock, patch

import pytest

from watchlight_bedrock import WatchlightBedrockPlugin

from .conftest import as_session


def _plugin_with_mocked_apdp(
    proxy_token_in_response: str | None,
    *,
    connect_proxy_url: str | None = None,
) -> WatchlightBedrockPlugin:
    plugin = WatchlightBedrockPlugin(
        apdp_url="http://localhost:8081", connect_proxy_url=connect_proxy_url
    )
    plugin.apdp.resolve_agent = AsyncMock(  # type: ignore[method-assign]
        return_value={"id": "agent-uuid"}
    )
    session_payload: dict = {"session": {"id": "ses_test"}}
    if proxy_token_in_response is not None:
        session_payload["proxy_token"] = proxy_token_in_response
        session_payload["proxy_token_expires_at"] = "2026-06-08T15:00:00Z"
    plugin.apdp.create_session = AsyncMock(return_value=as_session(plugin.apdp, session_payload))  # type: ignore[method-assign]
    plugin.apdp.get_manifest = AsyncMock(return_value={})  # type: ignore[method-assign]
    plugin.apdp.complete_session = AsyncMock(return_value=True)  # type: ignore[method-assign]
    return plugin


@pytest.mark.asyncio
async def test_installs_connect_proxy_when_both_url_and_token_present():
    plugin = _plugin_with_mocked_apdp(
        "eyJ.test.token", connect_proxy_url="http://wl-proxy:8080"
    )
    with patch("watchlight_core.install_connect_proxy") as mock_install:
        handle = await plugin.start_run("agent-x")
    mock_install.assert_called_once_with("http://wl-proxy:8080", "eyJ.test.token", egress=ANY)
    assert handle.egress.proxy_authorization() == "eyJ.test.token"
    assert "eyJ.test.token" not in repr(vars(handle))


@pytest.mark.asyncio
async def test_does_not_install_when_connect_proxy_url_unset():
    plugin = _plugin_with_mocked_apdp("eyJ.test.token", connect_proxy_url=None)
    with patch("watchlight_core.install_connect_proxy") as mock_install:
        await plugin.start_run("agent-x")
    mock_install.assert_not_called()


@pytest.mark.asyncio
async def test_refuses_run_when_apdp_omits_proxy_token():
    """A configured wl-proxy URL with no issued proxy token must refuse
    the run — never fall back to direct egress silently."""
    from watchlight_core import GovernanceUnavailable

    plugin = _plugin_with_mocked_apdp(
        None, connect_proxy_url="http://wl-proxy:8080"
    )
    with patch("watchlight_core.install_connect_proxy") as mock_install:
        with pytest.raises(GovernanceUnavailable):
            await plugin.start_run("agent-x")
    mock_install.assert_not_called()


@pytest.mark.asyncio
async def test_reads_connect_proxy_url_from_env_var(monkeypatch):
    monkeypatch.setenv("WATCHLIGHT_PROXY_URL", "http://wl-proxy.env:8080")
    plugin = _plugin_with_mocked_apdp("eyJ.test.token")
    assert plugin.connect_proxy_url == "http://wl-proxy.env:8080"
    with patch("watchlight_core.install_connect_proxy") as mock_install:
        await plugin.start_run("agent-x")
    mock_install.assert_called_once_with("http://wl-proxy.env:8080", "eyJ.test.token", egress=ANY)


def test_default_is_none_when_neither_set(monkeypatch):
    monkeypatch.delenv("WATCHLIGHT_PROXY_URL", raising=False)
    plugin = WatchlightBedrockPlugin(apdp_url="http://localhost:8081")
    assert plugin.connect_proxy_url is None
