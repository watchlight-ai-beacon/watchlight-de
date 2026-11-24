"""The registry client never takes a proxy from the environment."""

import pytest

from watchlight_adk.registry_client import RegistryClient


@pytest.mark.asyncio
async def test_registry_client_ignores_proxy_environment(monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://corp-proxy.example:3128")
    monkeypatch.setenv("https_proxy", "http://corp-proxy.example:3128")
    client = RegistryClient("https://wl-registry.example").client
    try:
        assert client._trust_env is False
        transport = client._transport_for_url(client._merge_url("/api/v1/agents/x/tools"))
        assert transport is client._transport
    finally:
        await client.aclose()
