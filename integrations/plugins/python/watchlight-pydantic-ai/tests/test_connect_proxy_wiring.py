"""Pydantic-AI plugin — CONNECT proxy auto-install wiring."""

from __future__ import annotations

from unittest.mock import ANY, AsyncMock, patch

import pytest

from watchlight_core import GovernanceUnavailable, SessionInfo
from watchlight_core_testing import register_test_run
from watchlight_pydantic_ai import WatchlightPydanticAIPlugin


def _plugin_with_mocked_apdp(
    proxy_token_in_response: str | None,
    *,
    connect_proxy_url: str | None = None,
) -> WatchlightPydanticAIPlugin:
    plugin = WatchlightPydanticAIPlugin(
        apdp_url="http://localhost:8081", connect_proxy_url=connect_proxy_url
    )
    plugin.apdp.resolve_agent = AsyncMock(  # type: ignore[method-assign]
        return_value={"id": "agent-uuid"}
    )
    # The real client holds the run's stand-in credentials; the plugin
    # gets only the RunRef.
    run = register_test_run(
        plugin.apdp, "sst_test.sig", "ses_test", proxy_token=proxy_token_in_response
    )
    plugin.test_run = run  # type: ignore[attr-defined]
    plugin.apdp.create_session = AsyncMock(  # type: ignore[method-assign]
        return_value=SessionInfo(run=run, session_id="ses_test", agent_id="agent-uuid")
    )
    plugin.apdp.get_manifest = AsyncMock(return_value={})  # type: ignore[method-assign]
    return plugin


@pytest.mark.asyncio
async def test_installs_connect_proxy_when_both_url_and_token_present():
    plugin = _plugin_with_mocked_apdp(
        "eyJ.test.token", connect_proxy_url="http://wl-proxy:8080"
    )
    with patch("watchlight_core.install_connect_proxy") as mock_install:
        handle = await plugin.start_run("agent-x")
    mock_install.assert_called_once_with("http://wl-proxy:8080", "eyJ.test.token", egress=ANY)
    # The handle holds the egress binding, never the token itself.
    assert handle.egress is not None
    assert handle.egress.proxy_authorization() == "eyJ.test.token"
    assert "eyJ.test.token" not in repr(handle.egress)


@pytest.mark.asyncio
async def test_does_not_install_when_connect_proxy_url_unset():
    plugin = _plugin_with_mocked_apdp("eyJ.test.token", connect_proxy_url=None)
    with patch("watchlight_core.install_connect_proxy") as mock_install:
        await plugin.start_run("agent-x")
    mock_install.assert_not_called()


@pytest.mark.asyncio
async def test_refuses_run_when_proxy_url_set_but_apdp_omits_proxy_token():
    """A configured proxy URL with no issued proxy token must not fall
    back to direct egress: the run is refused and the session closed."""
    plugin = _plugin_with_mocked_apdp(None, connect_proxy_url="http://wl-proxy:8080")
    plugin.apdp.complete_session = AsyncMock(return_value=True)  # type: ignore[method-assign]
    with patch("watchlight_core.install_connect_proxy") as mock_install:
        with pytest.raises(GovernanceUnavailable):
            await plugin.start_run("agent-x")
    mock_install.assert_not_called()
    plugin.apdp.complete_session.assert_awaited_once()
    assert plugin.apdp.complete_session.await_args.args[0] == plugin.test_run


@pytest.mark.asyncio
async def test_refuses_run_when_connect_proxy_install_fails():
    """A failed CONNECT sidecar install refuses the run (no fallback to
    direct egress) and never surfaces the token in the error."""
    plugin = _plugin_with_mocked_apdp(
        "eyJ.secret.token", connect_proxy_url="http://wl-proxy:8080"
    )
    plugin.apdp.complete_session = AsyncMock(return_value=True)  # type: ignore[method-assign]
    with patch(
        "watchlight_core.install_connect_proxy",
        side_effect=OSError("bind failed eyJ.secret.token"),
    ):
        with pytest.raises(GovernanceUnavailable) as info:
            await plugin.start_run("agent-x")
    assert "eyJ.secret.token" not in str(info.value)
    assert info.value.__cause__ is None
    plugin.apdp.complete_session.assert_awaited_once()


@pytest.mark.asyncio
async def test_failed_setup_after_session_create_terminates_session():
    """A failure after the session was opened (here: the manifest fetch)
    refuses the run and terminates the session instead of leaking it."""
    plugin = _plugin_with_mocked_apdp(None)
    plugin.apdp.get_manifest = AsyncMock(side_effect=RuntimeError("boom"))  # type: ignore[method-assign]
    plugin.apdp.complete_session = AsyncMock(return_value=True)  # type: ignore[method-assign]
    with pytest.raises(RuntimeError):
        await plugin.start_run("agent-x")
    plugin.apdp.complete_session.assert_awaited_once()


@pytest.mark.asyncio
async def test_refuses_run_when_session_create_fails():
    plugin = _plugin_with_mocked_apdp(None)
    plugin.apdp.create_session = AsyncMock(return_value=None)  # type: ignore[method-assign]
    with pytest.raises(GovernanceUnavailable):
        await plugin.start_run("agent-x")


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
    plugin = WatchlightPydanticAIPlugin(apdp_url="http://localhost:8081")
    assert plugin.connect_proxy_url is None


@pytest.mark.asyncio
async def test_missing_manifest_refuses_run_before_egress_and_closes_session(monkeypatch):
    monkeypatch.delenv("WATCHLIGHT_PLAN_GOVERNANCE_MODE", raising=False)
    plugin = _plugin_with_mocked_apdp(
        "eyJ.test.token", connect_proxy_url="http://wl-proxy:8080"
    )
    plugin.apdp.get_manifest = AsyncMock(return_value=None)  # type: ignore[method-assign]
    plugin.apdp.complete_session = AsyncMock(return_value=True)  # type: ignore[method-assign]
    with patch("watchlight_core.install_connect_proxy") as mock_install:
        with pytest.raises(GovernanceUnavailable):
            await plugin.start_run("agent-x")
    mock_install.assert_not_called()
    plugin.apdp.complete_session.assert_awaited_once()


@pytest.mark.asyncio
async def test_missing_manifest_runs_degraded_only_on_explicit_opt_in(monkeypatch):
    monkeypatch.setenv("WATCHLIGHT_PLAN_GOVERNANCE_MODE", "degrade")
    plugin = _plugin_with_mocked_apdp(None)
    plugin.apdp.get_manifest = AsyncMock(return_value=None)  # type: ignore[method-assign]
    await plugin.start_run("agent-x")
    assert plugin.last_governance_mode == "degraded"
