"""LangGraph plugin — wl-sidecar auto-install wiring.

The plugin's `start_run` MUST spawn the common wl-sidecar governance
binary via `install_sidecar(...)` when both `self.connect_proxy_url`
and `handle.proxy_token` are set. When EITHER is missing, the call must
be SKIPPED only when no proxy URL is configured. A configured proxy URL
with no issued proxy token refuses the run.

The `governed_proxy_hosts` allowlist is threaded from the pre-flight
manifest, and the wl-proxy CA from `WATCHLIGHT_PROXY_CA_CERT`.

These tests mock `install_sidecar` at the import-site in the plugin
module so we verify the call without actually spawning the binary.
"""

from __future__ import annotations

import os
import uuid
from unittest.mock import ANY, AsyncMock, patch

import pytest

from watchlight_core_testing import stub_session_info
from watchlight_langgraph import WatchlightLangGraphPlugin


def _plugin_with_mocked_apdp(
    proxy_token_in_response: str | None,
    *,
    connect_proxy_url: str | None = None,
    manifest: dict | None = None,
) -> WatchlightLangGraphPlugin:
    plugin = WatchlightLangGraphPlugin(
        apdp_url="http://localhost:8081", connect_proxy_url=connect_proxy_url
    )
    plugin.apdp.resolve_agent = AsyncMock(  # type: ignore[method-assign]
        return_value={"id": "agent-uuid"}
    )
    session_payload = stub_session_info(
        plugin.apdp,
        "ses_test",
        session_token="sst_test.sig",
        proxy_token=proxy_token_in_response,
    )
    plugin.apdp.create_session = AsyncMock(return_value=session_payload)  # type: ignore[method-assign]
    plugin.apdp.get_manifest = AsyncMock(return_value={} if manifest is None else manifest)  # type: ignore[method-assign]
    return plugin


@pytest.mark.asyncio
async def test_installs_sidecar_when_both_url_and_token_present(monkeypatch):
    monkeypatch.delenv("WATCHLIGHT_PROXY_CA_CERT", raising=False)
    plugin = _plugin_with_mocked_apdp(
        "eyJ.test.token", connect_proxy_url="https://wl-proxy:8443"
    )
    with patch("watchlight_core.install_sidecar") as mock_install:
        handle = await plugin.start_run("agent-x")
    mock_install.assert_called_once_with(
        "https://wl-proxy:8443",
        "eyJ.test.token",
        governed_proxy_hosts=None,
        ca_cert=None,
        egress=ANY,
    )
    assert handle.egress.proxy_authorization() == "eyJ.test.token"
    # The sidecar is owned by this run's own egress binding.
    assert mock_install.call_args.kwargs["egress"] is handle.egress


@pytest.mark.asyncio
async def test_threads_governed_hosts_and_ca_from_manifest_and_env(monkeypatch):
    monkeypatch.setenv("WATCHLIGHT_PROXY_CA_CERT", "/etc/watchlight/tls/ca.crt")
    plugin = _plugin_with_mocked_apdp(
        "eyJ.test.token",
        connect_proxy_url="https://wl-proxy:8443",
        manifest={"governed_proxy_hosts": ["proxy-mcp-web", "proxy-mcp-doc"]},
    )
    with patch("watchlight_core.install_sidecar") as mock_install:
        await plugin.start_run("agent-x")
    mock_install.assert_called_once_with(
        "https://wl-proxy:8443",
        "eyJ.test.token",
        governed_proxy_hosts=["proxy-mcp-web", "proxy-mcp-doc"],
        ca_cert="/etc/watchlight/tls/ca.crt",
        egress=ANY,
    )


@pytest.mark.asyncio
async def test_does_not_install_when_connect_proxy_url_unset():
    # No connect_proxy_url + no env var → install must be skipped.
    plugin = _plugin_with_mocked_apdp("eyJ.test.token", connect_proxy_url=None)
    with patch("watchlight_core.install_sidecar") as mock_install:
        await plugin.start_run("agent-x")
    mock_install.assert_not_called()


@pytest.mark.asyncio
async def test_refuses_run_when_proxy_configured_but_apdp_omits_proxy_token():
    # A configured proxy URL with no issued proxy token must refuse the
    # run, never fall back to direct egress.
    from watchlight_core import GovernanceUnavailable

    plugin = _plugin_with_mocked_apdp(None, connect_proxy_url="https://wl-proxy:8443")
    plugin.apdp.complete_session = AsyncMock(return_value=True)  # type: ignore[method-assign]
    with patch("watchlight_core.install_sidecar") as mock_install:
        with pytest.raises(GovernanceUnavailable):
            await plugin.start_run("agent-x")
    mock_install.assert_not_called()


@pytest.mark.asyncio
async def test_reads_connect_proxy_url_from_env_var(monkeypatch):
    monkeypatch.setenv("WATCHLIGHT_PROXY_URL", "https://wl-proxy.env:8443")
    monkeypatch.delenv("WATCHLIGHT_PROXY_CA_CERT", raising=False)
    plugin = _plugin_with_mocked_apdp("eyJ.test.token")
    assert plugin.connect_proxy_url == "https://wl-proxy.env:8443"
    with patch("watchlight_core.install_sidecar") as mock_install:
        await plugin.start_run("agent-x")
    mock_install.assert_called_once_with(
        "https://wl-proxy.env:8443",
        "eyJ.test.token",
        governed_proxy_hosts=None,
        ca_cert=None,
        egress=ANY,
    )


def test_constructor_arg_takes_precedence_over_env_var(monkeypatch):
    monkeypatch.setenv("WATCHLIGHT_PROXY_URL", "http://wl-proxy.env:8080")
    plugin = WatchlightLangGraphPlugin(
        apdp_url="http://localhost:8081",
        connect_proxy_url="http://wl-proxy.explicit:8080",
    )
    assert plugin.connect_proxy_url == "http://wl-proxy.explicit:8080"


def test_default_is_none_when_neither_set(monkeypatch):
    monkeypatch.delenv("WATCHLIGHT_PROXY_URL", raising=False)
    plugin = WatchlightLangGraphPlugin(apdp_url="http://localhost:8081")
    assert plugin.connect_proxy_url is None


# A stand-in for the Rust binary (tests only): appends the token it was
# handed on stdin to STUB_TOKEN_SINK, announces a port, then idles.
_STUB_SIDECAR = """#!/usr/bin/env python3
import os, sys, time
token = sys.stdin.readline().strip()
with open(os.environ["STUB_TOKEN_SINK"], "a") as f:
    f.write(token + "\\n")
print("127.0.0.1:54321", flush=True)
time.sleep(30)
"""


@pytest.mark.asyncio
async def test_a_second_run_in_the_process_is_refused_and_the_first_keeps_its_token(
    tmp_path, monkeypatch
):
    from watchlight_core import SidecarRunActive, uninstall_sidecar
    from watchlight_core_testing import MockApdpClient

    stub = tmp_path / "wl-sidecar"
    stub.write_text(_STUB_SIDECAR)
    stub.chmod(0o755)
    sink = tmp_path / "tokens"
    monkeypatch.setenv("WL_SIDECAR_BINARY", str(stub))
    monkeypatch.setenv("STUB_TOKEN_SINK", str(sink))
    monkeypatch.delenv("WATCHLIGHT_PROXY_CA_CERT", raising=False)
    for name in ("HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY", "no_proxy"):
        monkeypatch.delenv(name, raising=False)

    plugin = WatchlightLangGraphPlugin(
        apdp_url="https://localhost:8081", connect_proxy_url="https://wl-proxy:8443"
    )
    plugin.apdp = MockApdpClient()
    plugin.apdp.proxy_token_prefix = "wlp_standin"
    plugin.apdp.known_agents["agent-a"] = str(uuid.uuid4())
    plugin.apdp.known_agents["agent-b"] = str(uuid.uuid4())
    try:
        first = await plugin.start_run("agent-a")
        first_token = first.egress.proxy_authorization()
        sidecar_env = os.environ["HTTPS_PROXY"]

        with pytest.raises(SidecarRunActive):
            await plugin.start_run("agent-b")

        # The first run's egress is unchanged: the only token any sidecar
        # was handed is its own, and the process still routes to it.
        assert sink.read_text().splitlines() == [first_token]
        assert os.environ["HTTPS_PROXY"] == sidecar_env
        assert first.egress.run_live()
        # The refused run's session was closed, not left open.
        assert len(plugin.apdp._closed_sessions) == 1

        await first.complete()
        second = await plugin.start_run("agent-b")
        assert sink.read_text().splitlines() == [
            first_token,
            second.egress.proxy_authorization(),
        ]
    finally:
        uninstall_sidecar()
