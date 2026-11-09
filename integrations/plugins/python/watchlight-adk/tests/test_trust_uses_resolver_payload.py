"""The trust gate reads the resolver payload, not a control-plane route.

`GET /agents/:id` answers 401 for a plugin's data-plane bearer. The client
turned that into `trusted: False`, so every ADK run in a correctly
registered deployment was refused with a transport error dressed up as a
trust decision. `/agents/resolve` already returns `trust_state`.
"""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from watchlight_adk import WatchlightPlugin
from watchlight_core_testing import stub_session_info

# These tests call the plugin's callbacks directly: a governed run is live.
pytestmark = pytest.mark.usefixtures("governed_run_live")


class _Agent:
    def __init__(self, name: str = "adk_orchestrator"):
        self.name = name


def _plugin() -> WatchlightPlugin:
    p = WatchlightPlugin(
        apdp_url="https://apdp.test",
        agent_slug="agent-adk-orchestrator",
        root_agent_name="adk_orchestrator",
    )
    p.apdp.check_agent_trust = AsyncMock(
        return_value={"trusted": True, "trust_state": "trusted", "reason": ""}
    )
    p.lineage.connect = AsyncMock()
    p.lineage.emit_execution_started = AsyncMock()
    p.apdp.create_session = AsyncMock(
        return_value=stub_session_info(p.apdp, "ses_test", session_token="sst_test")
    )
    p.apdp.get_manifest = AsyncMock(return_value={"tool_allowlist": []})
    return p


def _resolved(**extra) -> dict:
    return {
        "id": "956e1538-3b43-490d-912c-12934d2da2d9",
        "slug": "agent-adk-orchestrator",
        "name": "adk-orchestrator",
        **extra,
    }


@pytest.mark.asyncio
async def test_a_trusted_resolve_never_calls_the_control_plane_route():
    p = _plugin()
    p.apdp.resolve_agent = AsyncMock(return_value=_resolved(trust_state="trusted"))

    refusal = await p.before_agent_callback(agent=_Agent(), callback_context=None)

    assert refusal is None, "a trusted agent is not refused"
    p.apdp.check_agent_trust.assert_not_awaited()


@pytest.mark.asyncio
async def test_an_untrusted_resolve_still_refuses():
    p = _plugin()
    p.apdp.resolve_agent = AsyncMock(return_value=_resolved(trust_state="quarantined"))

    refusal = await p.before_agent_callback(agent=_Agent(), callback_context=None)

    assert refusal is not None, "a quarantined agent is refused"
    p.apdp.check_agent_trust.assert_not_awaited()


@pytest.mark.asyncio
async def test_a_payload_without_a_trust_state_falls_back_to_the_client():
    """The in-process engine carries no trust state and answers locally."""
    p = _plugin()
    p.apdp.resolve_agent = AsyncMock(return_value=_resolved())

    refusal = await p.before_agent_callback(agent=_Agent(), callback_context=None)

    assert refusal is None
    p.apdp.check_agent_trust.assert_awaited_once()
