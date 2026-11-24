"""ADK plugin — CONNECT proxy auto-install wiring.

ADK uses BasePlugin callbacks rather than BaseRunHandle, so the
install hook lives in `_open_session_and_manifest`. The test
pattern is the same: mock APDP + assert `install_connect_proxy`
is called (or not called) per the configuration permutations.
"""

from __future__ import annotations

from unittest.mock import ANY, AsyncMock, MagicMock, patch

import pytest

from watchlight_core import GovernanceUnavailable
from watchlight_adk import WatchlightPlugin
from watchlight_core_testing import stub_session_info


def _plugin_with_mocked_apdp(
    proxy_token_in_response: str | None,
    *,
    connect_proxy_url: str | None = None,
) -> WatchlightPlugin:
    plugin = WatchlightPlugin(
        apdp_url="http://localhost:8081",
        connect_proxy_url=connect_proxy_url,
        agent_slug="agent-research-analyst",
        root_agent_name="research_analyst",
    )
    session = stub_session_info(
        plugin.apdp, "ses_test", proxy_token=proxy_token_in_response
    )
    plugin.apdp.create_session = AsyncMock(return_value=session)  # type: ignore[method-assign]
    plugin.apdp.get_manifest = AsyncMock(return_value={})  # type: ignore[method-assign]
    plugin.apdp.complete_session = AsyncMock(return_value=True)  # type: ignore[method-assign]
    plugin._current_agent_id = "agent-uuid"  # set by before_agent_callback normally
    plugin._current_execution_id = "exec_test"
    return plugin


# In-process stand-in for unit tests only.
def _stub_callback_context() -> MagicMock:
    ctx = MagicMock()
    ctx.state = {}  # ADK puts plugin state here
    return ctx


@pytest.mark.asyncio
async def test_installs_connect_proxy_when_both_url_and_token_present():
    plugin = _plugin_with_mocked_apdp(
        "eyJ.test.token", connect_proxy_url="http://wl-proxy:8080"
    )
    with patch("watchlight_core.install_connect_proxy") as mock_install:
        await plugin._open_session_and_manifest(_stub_callback_context())
    mock_install.assert_called_once_with("http://wl-proxy:8080", "eyJ.test.token", egress=ANY)


@pytest.mark.asyncio
async def test_does_not_install_when_connect_proxy_url_unset():
    plugin = _plugin_with_mocked_apdp("eyJ.test.token", connect_proxy_url=None)
    with patch("watchlight_core.install_connect_proxy") as mock_install:
        await plugin._open_session_and_manifest(_stub_callback_context())
    mock_install.assert_not_called()


@pytest.mark.asyncio
async def test_refuses_the_run_when_apdp_omits_proxy_token():
    """A configured CONNECT URL is a hard requirement: with no proxy
    token issued, the run would egress directly, so it is refused."""
    plugin = _plugin_with_mocked_apdp(
        None, connect_proxy_url="http://wl-proxy:8080"
    )
    with patch("watchlight_core.install_connect_proxy") as mock_install:
        with pytest.raises(GovernanceUnavailable):
            await plugin._open_session_and_manifest(_stub_callback_context())
    mock_install.assert_not_called()
    assert plugin._session_id is None


@pytest.mark.asyncio
async def test_install_failure_refuses_the_run():
    """If install_connect_proxy raises (e.g. wl-proxy unreachable at
    install time), the run is refused and its session closed: it never
    continues with direct egress."""
    plugin = _plugin_with_mocked_apdp(
        "eyJ.test.token", connect_proxy_url="http://wl-proxy:8080"
    )
    with patch(
        "watchlight_core.install_connect_proxy",
        side_effect=RuntimeError("sidecar startup failed"),
    ):
        with pytest.raises(GovernanceUnavailable):
            await plugin._open_session_and_manifest(_stub_callback_context())
    assert plugin._session_id is None
    plugin.apdp.complete_session.assert_awaited_once()


def test_reads_connect_proxy_url_from_env_var(monkeypatch):
    monkeypatch.setenv("WATCHLIGHT_PROXY_URL", "http://wl-proxy.env:8080")
    plugin = WatchlightPlugin(
        apdp_url="http://localhost:8081",
        agent_slug="agent-research-analyst",
        root_agent_name="research_analyst",
    )
    assert plugin.connect_proxy_url == "http://wl-proxy.env:8080"


def test_default_is_none_when_neither_set(monkeypatch):
    monkeypatch.delenv("WATCHLIGHT_PROXY_URL", raising=False)
    plugin = WatchlightPlugin(
        apdp_url="http://localhost:8081",
        agent_slug="agent-research-analyst",
        root_agent_name="research_analyst",
    )
    assert plugin.connect_proxy_url is None
