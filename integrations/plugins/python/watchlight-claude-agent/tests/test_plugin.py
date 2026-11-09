"""Plugin lifecycle tests.

Covers:
- start_run resolves slug → UUID + opens session
- start_run fails closed when slug unknown (AgentNotRegistered)
- start_run fails closed when session create rejected
- CONNECT-proxy wiring: install_connect_proxy called when both
  connect_proxy_url AND proxy_token present
- CONNECT-proxy wiring: NOT called when no proxy URL is configured
- A configured proxy URL with no proxy token refuses the run
- handle.egress resolves the run's proxy token (the handle never holds it)
- Install failure refuses the run (GovernanceUnavailable)
"""

from __future__ import annotations

from unittest.mock import ANY, AsyncMock, patch

import pytest

from watchlight_claude_agent import (
    RunHandle,
    WatchlightClaudeAgentSDKPlugin,
)
from watchlight_core import AgentNotRegistered, GovernanceUnavailable
from watchlight_core_testing import stub_session_info


def _plugin_with_mocked_apdp(
    *,
    proxy_token_in_response: str | None = None,
    connect_proxy_url: str | None = None,
    resolve_returns: dict | None = None,
    session_returns: object = object(),
) -> WatchlightClaudeAgentSDKPlugin:
    plugin = WatchlightClaudeAgentSDKPlugin(
        apdp_url="http://localhost:8081", connect_proxy_url=connect_proxy_url
    )
    plugin.apdp.resolve_agent = AsyncMock(  # type: ignore[method-assign]
        return_value=resolve_returns if resolve_returns is not None else {"id": "agent-uuid"}
    )
    if session_returns is None:
        session_payload = None
    elif session_returns.__class__ is not object:
        # An explicit session (a SessionInfo) supplied by the test.
        session_payload = session_returns
    else:
        # Default: minimal valid session + optional proxy token, held in
        # the client's run table (the plugin only gets the RunRef).
        session_payload = stub_session_info(
            plugin.apdp,
            "ses_test",
            session_token="sst_test.sig",
            proxy_token=proxy_token_in_response,
            agent_id="agent-uuid",
        )
    plugin.apdp.create_session = AsyncMock(return_value=session_payload)  # type: ignore[method-assign]
    plugin.apdp.get_manifest = AsyncMock(return_value={})  # type: ignore[method-assign]
    plugin.apdp.complete_session = AsyncMock(return_value=True)  # type: ignore[method-assign]
    return plugin


@pytest.mark.asyncio
async def test_start_run_happy_path_returns_runhandle():
    plugin = _plugin_with_mocked_apdp()
    handle = await plugin.start_run("agent-x")
    assert isinstance(handle, RunHandle)
    assert handle.agent_uuid == "agent-uuid"
    assert handle.session_id == "ses_test"


@pytest.mark.asyncio
async def test_start_run_unknown_slug_raises_agent_not_registered():
    plugin = _plugin_with_mocked_apdp(resolve_returns={})
    plugin.apdp.resolve_agent = AsyncMock(return_value=None)  # type: ignore[method-assign]
    with pytest.raises(AgentNotRegistered):
        await plugin.start_run("nope")


@pytest.mark.asyncio
async def test_start_run_session_failure_raises_governance_unavailable():
    plugin = _plugin_with_mocked_apdp(session_returns=None)
    with pytest.raises(GovernanceUnavailable):
        await plugin.start_run("agent-x")


@pytest.mark.asyncio
async def test_start_run_threads_proxy_token_through_to_handle():
    plugin = _plugin_with_mocked_apdp(
        proxy_token_in_response="eyJ.test.token",
        connect_proxy_url="http://wl-proxy:8080",
    )
    with patch("watchlight_core.install_connect_proxy"):
        handle = await plugin.start_run("agent-x")
    assert handle.egress is not None
    assert handle.egress.proxy_authorization() == "eyJ.test.token"
    assert "eyJ.test.token" not in repr(handle.egress)


@pytest.mark.asyncio
async def test_installs_connect_proxy_when_both_url_and_token_present():
    plugin = _plugin_with_mocked_apdp(
        proxy_token_in_response="eyJ.test.token",
        connect_proxy_url="http://wl-proxy:8080",
    )
    with patch("watchlight_core.install_connect_proxy") as mock_install:
        await plugin.start_run("agent-x")
    mock_install.assert_called_once_with("http://wl-proxy:8080", "eyJ.test.token", egress=ANY)


@pytest.mark.asyncio
async def test_does_not_install_when_connect_proxy_url_unset():
    plugin = _plugin_with_mocked_apdp(
        proxy_token_in_response="eyJ.test.token", connect_proxy_url=None
    )
    with patch("watchlight_core.install_connect_proxy") as mock_install:
        await plugin.start_run("agent-x")
    mock_install.assert_not_called()


@pytest.mark.asyncio
async def test_configured_proxy_without_proxy_token_refuses_run():
    """A configured wl-proxy URL with no issued proxy token must never
    fall back to direct egress: the run is refused."""
    plugin = _plugin_with_mocked_apdp(
        proxy_token_in_response=None,
        connect_proxy_url="http://wl-proxy:8080",
    )
    with patch("watchlight_core.install_connect_proxy") as mock_install:
        with pytest.raises(GovernanceUnavailable):
            await plugin.start_run("agent-x")
    mock_install.assert_not_called()
    plugin.apdp.complete_session.assert_awaited()


@pytest.mark.asyncio
async def test_install_failure_refuses_run():
    """If the CONNECT sidecar cannot be installed, start_run refuses the
    run instead of continuing with direct egress."""
    plugin = _plugin_with_mocked_apdp(
        proxy_token_in_response="eyJ.test.token",
        connect_proxy_url="http://wl-proxy:8080",
    )
    with patch(
        "watchlight_core.install_connect_proxy",
        side_effect=RuntimeError("sidecar startup failed"),
    ):
        with pytest.raises(GovernanceUnavailable) as excinfo:
            await plugin.start_run("agent-x")
    # The proxy token never appears in the refusal.
    assert "eyJ.test.token" not in str(excinfo.value)
    plugin.apdp.complete_session.assert_awaited()


@pytest.mark.asyncio
async def test_reads_connect_proxy_url_from_env_var(monkeypatch):
    monkeypatch.setenv("WATCHLIGHT_PROXY_URL", "http://wl-proxy.env:8080")
    plugin = WatchlightClaudeAgentSDKPlugin(apdp_url="http://localhost:8081")
    assert plugin.connect_proxy_url == "http://wl-proxy.env:8080"


def test_constructor_arg_takes_precedence_over_env(monkeypatch):
    monkeypatch.setenv("WATCHLIGHT_PROXY_URL", "http://env.example:8080")
    plugin = WatchlightClaudeAgentSDKPlugin(
        apdp_url="http://localhost:8081",
        connect_proxy_url="http://explicit:8080",
    )
    assert plugin.connect_proxy_url == "http://explicit:8080"


def test_default_connect_proxy_url_is_none(monkeypatch):
    monkeypatch.delenv("WATCHLIGHT_PROXY_URL", raising=False)
    plugin = WatchlightClaudeAgentSDKPlugin(apdp_url="http://localhost:8081")
    assert plugin.connect_proxy_url is None


# ─── no spawn_subagent override on the plugin RunHandle ──────────────


def test_run_handle_does_not_override_spawn_subagent():
    """The Claude Agent SDK plugin has no sub-agent primitive of its own.
    Its :class:`RunHandle` inherits the canonical
    :meth:`BaseRunHandle.spawn_subagent` directly so any spawn that
    DOES happen goes through the canonical wire shape. The spawn's
    ``agent_spawn_observed`` attestation (with the server-validated
    ``granted_scope``) is SERVER-emitted by wl-apdp's ``spawn_handler``
    as it processes the ``spawn_subagent`` round-trip — the plugin
    never emits that class.

    Locks the no-override contract: a plugin-side override of
    ``spawn_subagent`` MUST still route through the base round-trip so the
    server sees + attests the spawn, and MUST NOT emit ``agent_spawn_observed``
    itself (that class is rejected at ``/v1/events`` ingest). This plugin
    passes the invariant vacuously (zero spawn events emitted from the
    synthetic lifecycle)."""
    from watchlight_core.run_handle import BaseRunHandle

    # The shipped Claude Agent SDK plugin's RunHandle MUST NOT define
    # its own ``spawn_subagent`` — inheriting the canonical base
    # surface is the contract.
    assert (
        RunHandle.spawn_subagent  # type: ignore[attr-defined]
        is BaseRunHandle.spawn_subagent
    ), (
        "RunHandle.spawn_subagent has been overridden. Any override MUST "
        "route through the base spawn_subagent round-trip (so wl-apdp sees "
        "and server-attests the spawn) and MUST NOT emit `agent_spawn_observed` "
        "itself — that class is rejected at /v1/events ingest. "
        "Update this assertion only if the override preserves that contract."
    )


@pytest.mark.asyncio
async def test_start_run_refuses_and_closes_session_without_manifest(monkeypatch):
    monkeypatch.delenv("WATCHLIGHT_PLAN_GOVERNANCE_MODE", raising=False)
    plugin = _plugin_with_mocked_apdp(
        proxy_token_in_response="eyJ.test.token",
        connect_proxy_url="http://wl-proxy:8080",
    )
    plugin.apdp.get_manifest = AsyncMock(return_value=None)  # type: ignore[method-assign]
    with patch("watchlight_core.install_connect_proxy") as mock_install:
        with pytest.raises(GovernanceUnavailable):
            await plugin.start_run("agent-x")
    mock_install.assert_not_called()
    plugin.apdp.complete_session.assert_awaited_once()


@pytest.mark.asyncio
async def test_start_run_degraded_without_manifest_only_on_explicit_opt_in(monkeypatch):
    monkeypatch.setenv("WATCHLIGHT_PLAN_GOVERNANCE_MODE", "degrade")
    plugin = _plugin_with_mocked_apdp()
    plugin.apdp.get_manifest = AsyncMock(return_value=None)  # type: ignore[method-assign]
    await plugin.start_run("agent-x")
    assert plugin.last_governance_mode == "degraded"


@pytest.mark.asyncio
async def test_start_run_closes_session_on_any_open_failure():
    plugin = _plugin_with_mocked_apdp()
    plugin.apdp.get_manifest = AsyncMock(side_effect=RuntimeError("boom"))  # type: ignore[method-assign]
    with pytest.raises(RuntimeError):
        await plugin.start_run("agent-x")
    plugin.apdp.complete_session.assert_awaited_once()


# ─── A refused agent never runs, in every mode ──────────────


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["strict", "degrade"])
async def test_start_run_refused_manifest_refuses_in_every_mode(monkeypatch, mode):
    """A refused manifest (e.g. revoked trust) is a typed refusal, never
    "no manifest": even degrade mode returns no handle, and the session
    opened for it is closed."""
    from watchlight_core import GovernanceRefused

    monkeypatch.setenv("WATCHLIGHT_PLAN_GOVERNANCE_MODE", mode)
    plugin = _plugin_with_mocked_apdp()
    plugin.apdp.get_manifest = AsyncMock(  # type: ignore[method-assign]
        side_effect=GovernanceRefused("refused", status_code=403, error="agent_trust_revoked")
    )
    with pytest.raises(GovernanceRefused) as exc:
        await plugin.start_run("agent-x")
    assert exc.value.code == "agent_trust_revoked"
    plugin.apdp.complete_session.assert_awaited_once()
    assert plugin.last_governance_mode != "degraded"
