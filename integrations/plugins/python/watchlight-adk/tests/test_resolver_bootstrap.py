"""Tests for the slug → UUID resolver and the plugin's bootstrap flow.

Every identifier inside Watchlight is a UUID. The single
exception is `POST /agents/resolve`, which SDK plugins call **once** at
run start to bootstrap from a human-readable slug to the canonical UUID.

These tests cover:
  * `ApdpClient.resolve_agent` happy path / 404 / transport failure
  * `WatchlightPlugin.before_agent_callback` — successful bootstrap puts
    UUID on `_current_agent_id` and slug on `_current_agent_slug`
  * Failed resolution → fail-closed refusal (returns Content)
"""

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from watchlight_adk.apdp_client import ApdpClient
from watchlight_core import GovernanceUnavailable
from watchlight_core_testing import stub_session_info

# These tests call the plugin's callbacks directly: a governed run is live.
pytestmark = pytest.mark.usefixtures("governed_run_live")


# ─── ApdpClient.resolve_agent ────────────────────────────────────────


@pytest.mark.asyncio
async def test_resolve_agent_returns_dict_on_200():
    client = ApdpClient(base_url="https://apdp.test")
    stub = AsyncMock()
    stub.post = AsyncMock(
        return_value=MagicMock(
            status_code=200,
            json=lambda: {
                "id": "1d2bdf18-1a89-4bd1-81ad-33269b484266",
                "slug": "research-analyst",
                "name": "Research Analyst",
                "trust_state": "trusted",
            },
            raise_for_status=lambda: None,
        )
    )
    with patch.object(ApdpClient, "client", new_callable=lambda: property(lambda self: stub)):
        out = await client.resolve_agent("research-analyst")
    assert out is not None
    assert out["id"] == "1d2bdf18-1a89-4bd1-81ad-33269b484266"
    stub.post.assert_called_once_with("/agents/resolve", json={"slug": "research-analyst"})


@pytest.mark.asyncio
async def test_resolve_agent_returns_none_on_404():
    client = ApdpClient(base_url="https://apdp.test")
    stub = AsyncMock()
    stub.post = AsyncMock(return_value=MagicMock(status_code=404))
    with patch.object(ApdpClient, "client", new_callable=lambda: property(lambda self: stub)):
        out = await client.resolve_agent("nonexistent-agent")
    assert out is None


@pytest.mark.asyncio
async def test_resolve_agent_raises_governance_unavailable_on_5xx():
    """A server error is not "not registered": it raises, and the
    run is refused."""
    client = ApdpClient(base_url="https://apdp.test")
    err_response = MagicMock(status_code=500, text="upstream error")

    def raise_500():
        raise httpx.HTTPStatusError(
            "500 Server Error", request=MagicMock(), response=err_response
        )

    err_response.raise_for_status = raise_500
    stub = AsyncMock()
    stub.post = AsyncMock(return_value=err_response)
    with patch.object(ApdpClient, "client", new_callable=lambda: property(lambda self: stub)):
        with pytest.raises(GovernanceUnavailable):
            await client.resolve_agent("any-slug")


@pytest.mark.asyncio
async def test_resolve_agent_raises_governance_unavailable_on_connect_error():
    """No answer is not "not registered"."""
    client = ApdpClient(base_url="https://apdp.test")
    stub = AsyncMock()
    stub.post = AsyncMock(side_effect=httpx.ConnectError("unreachable"))
    with patch.object(ApdpClient, "client", new_callable=lambda: property(lambda self: stub)):
        with pytest.raises(GovernanceUnavailable):
            await client.resolve_agent("any-slug")


# ─── WatchlightPlugin.before_agent_callback bootstrap ────────────────


@pytest.fixture
def plugin():
    """A WatchlightPlugin instance with the apdp + lineage + registry
    methods stubbed. We don't need real network calls — we're testing
    the bootstrap logic, not the I/O."""
    from watchlight_adk import WatchlightPlugin

    p = WatchlightPlugin(
        apdp_url="https://apdp.test",
        agent_slug="agent-research-analyst",
        root_agent_name="research_analyst",
    )
    # Replace the apdp client methods used by before_agent_callback.
    p.apdp.resolve_agent = AsyncMock()
    p.apdp.check_agent_trust = AsyncMock(return_value={"trusted": True, "reason": ""})
    p.lineage.connect = AsyncMock()
    p.lineage.emit_execution_started = AsyncMock()
    # _open_session_and_manifest does its own apdp calls; stub the inner ones.
    p.apdp.create_session = AsyncMock(
        return_value=stub_session_info(p.apdp, "ses_test", session_token="sst_test")
    )
    p.apdp.get_manifest = AsyncMock(return_value={"tool_allowlist": []})
    return p


@pytest.fixture
def adk_agent():
    """A stub ADK agent with a name attribute. Mirrors what the runner
    passes to before_agent_callback."""

    class _Agent:
        name = "research_analyst"  # ADK uses underscores
        tools = []

    return _Agent()


@pytest.fixture
def callback_ctx():
    """Minimal CallbackContext stub. Only `state` is touched by
    _open_session_and_manifest; we let it be a regular dict."""

    class _Ctx:
        state = {}

    return _Ctx()


@pytest.mark.asyncio
async def test_bootstrap_resolves_slug_and_stores_uuid(plugin, adk_agent, callback_ctx):
    plugin.apdp.resolve_agent.return_value = {
        "id": "1d2bdf18-1a89-4bd1-81ad-33269b484266",
        "slug": "agent-research-analyst",
        "name": "Research Analyst",
        "trust_state": "trusted",
    }

    result = await plugin.before_agent_callback(
        agent=adk_agent, callback_context=callback_ctx
    )

    # Returns None to allow the agent to proceed
    assert result is None
    # Resolver was called with the CONFIGURED slug — never one derived
    # from ``agent.name``.
    plugin.apdp.resolve_agent.assert_called_once_with("agent-research-analyst")
    # Plugin state has UUID + slug
    assert plugin._current_agent_id == "1d2bdf18-1a89-4bd1-81ad-33269b484266"
    assert plugin._current_agent_slug == "agent-research-analyst"
    # The trust state came from the resolver payload, so the control-plane
    # route (`GET /agents/:id`, which a data-plane bearer cannot read) was
    # never called.
    plugin.apdp.check_agent_trust.assert_not_called()


@pytest.mark.asyncio
async def test_bootstrap_fails_closed_when_agent_not_registered(plugin, adk_agent, callback_ctx):
    """Unknown slug → resolve_agent returns None → plugin returns
    Content (refusal), agent does NOT proceed.

    The configured slug is asked for ONCE. There is no second candidate
    to fall back to: a "did you mean" retry is how an agent lands on a
    registered identity that is not its own.
    """
    plugin.apdp.resolve_agent.return_value = None

    result = await plugin.before_agent_callback(
        agent=adk_agent, callback_context=callback_ctx
    )

    # Refusal returned (non-None means short-circuit the agent)
    assert result is not None
    assert [c.args[0] for c in plugin.apdp.resolve_agent.call_args_list] == [
        "agent-research-analyst",
    ]
    assert "not registered" in result.parts[0].text
    # Trust check was NOT called — we never proceeded past resolution
    plugin.apdp.check_agent_trust.assert_not_called()
    # No session was opened
    plugin.apdp.create_session.assert_not_called()


@pytest.mark.asyncio
async def test_bootstrap_uuid_propagates_to_session_creation(plugin, adk_agent, callback_ctx):
    """Once UUID is resolved, create_session is called with the UUID
    (not the slug). This proves end-to-end UUID-only flow inside the
    plugin's lifecycle."""
    plugin.apdp.resolve_agent.return_value = {
        "id": "1d2bdf18-1a89-4bd1-81ad-33269b484266",
        "slug": "research-analyst",
        "name": "Research Analyst",
        "trust_state": "trusted",
    }

    await plugin.before_agent_callback(agent=adk_agent, callback_context=callback_ctx)

    # _open_session_and_manifest calls apdp.create_session with the UUID
    plugin.apdp.create_session.assert_called_once()
    kwargs = plugin.apdp.create_session.call_args.kwargs
    assert kwargs["agent_id"] == "1d2bdf18-1a89-4bd1-81ad-33269b484266"
    # Manifest fetch also uses UUID
    plugin.apdp.get_manifest.assert_called_once()
    assert (
        plugin.apdp.get_manifest.call_args.args[0]
        == "1d2bdf18-1a89-4bd1-81ad-33269b484266"
    )
