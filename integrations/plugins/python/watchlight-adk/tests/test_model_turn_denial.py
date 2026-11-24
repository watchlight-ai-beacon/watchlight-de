"""A denied model turn fails closed.

``before_model_callback`` authorizes ``Action::"chat"`` on
``Model::"gemini-chat"`` before every LLM call. A Deny used to be logged
and then let through ("blocking LLM breaks the agent entirely"), which
made the model-turn decision advisory. It now short-circuits the model
call the way the tool path short-circuits a denied tool: the callback
returns an ``LlmResponse`` the ADK runtime surfaces as the turn's
response. The response names the agent and the outcome, never the
server's reason (opaque deny).
"""

from __future__ import annotations

from typing import Any, Dict, List
from unittest.mock import AsyncMock, MagicMock

import pytest
from google.adk.models.llm_request import LlmRequest
from google.adk.models.llm_response import LlmResponse

from watchlight_adk.plugin import WatchlightPlugin
from ._contexts import non_live_context

SERVER_REASON = "scope_attenuation_violation (policy adk-researcher-model-chat did not match)"


class _ScriptedApdp:
    """An ApdpClient stand-in whose ``authorize`` returns a scripted decision."""

    def __init__(self, decision: str, reason: str = "") -> None:
        self.authorize_calls: List[Dict[str, Any]] = []

        async def _authorize(**kwargs: Any) -> Dict[str, Any]:
            self.authorize_calls.append(kwargs)
            return {"decision": decision, "reason": reason, "details": {}}

        self.authorize = AsyncMock(side_effect=_authorize)
        self.publish_events = AsyncMock(return_value=True)
        self.get_manifest = AsyncMock(return_value={})


def _plugin(apdp: _ScriptedApdp, **kwargs: Any) -> WatchlightPlugin:
    kwargs.setdefault("agent_slug", "agent-research-analyst")
    kwargs.setdefault("root_agent_name", "research_analyst")
    plugin = WatchlightPlugin(apdp_url="http://localhost:8081", tenant_id="t1", **kwargs)
    plugin.apdp = apdp  # type: ignore[assignment]
    plugin.lineage._apdp = apdp  # type: ignore[attr-defined]
    plugin._current_agent_id = "agent-uuid"
    plugin._current_execution_id = "exec_test"
    return plugin


def _text(response: LlmResponse) -> str:
    assert response.content is not None and response.content.parts
    return "".join(part.text or "" for part in response.content.parts)


@pytest.mark.asyncio
async def test_a_denied_model_turn_returns_a_response_that_skips_the_model():
    apdp = _ScriptedApdp("Deny", SERVER_REASON)
    plugin = _plugin(apdp)

    result = await plugin.before_model_callback(
        callback_context=non_live_context(), llm_request=MagicMock()
    )

    assert isinstance(result, LlmResponse)
    assert result.content.role == "model"
    assert "denied" in _text(result)
    assert "agent-uuid" in _text(result)
    assert plugin._denied_count == 1
    # The decision was asked for chat on the model, under the tenant.
    call = apdp.authorize_calls[0]
    assert call["action"] == 'Action::"chat"'
    assert call["resource"] == 'Model::"gemini-chat"'
    assert call["context"]["tenant_id"] == "t1"


@pytest.mark.asyncio
async def test_the_denial_carries_no_server_reason():
    plugin = _plugin(_ScriptedApdp("Deny", SERVER_REASON))

    result = await plugin.before_model_callback(
        callback_context=non_live_context(), llm_request=MagicMock()
    )

    text = _text(result)
    assert SERVER_REASON not in text
    assert "adk-researcher-model-chat" not in text
    assert "scope_attenuation_violation" not in text


@pytest.mark.asyncio
async def test_an_allowed_model_turn_proceeds():
    plugin = _plugin(_ScriptedApdp("Allow"))

    result = await plugin.before_model_callback(
        callback_context=non_live_context(), llm_request=LlmRequest()
    )

    assert result is None
    assert plugin._denied_count == 0


@pytest.mark.asyncio
async def test_an_unreachable_apdp_fails_closed_by_default():
    plugin = _plugin(_ScriptedApdp("Deny", "APDP unreachable: connection refused"))

    result = await plugin.before_model_callback(
        callback_context=non_live_context(), llm_request=MagicMock()
    )

    assert isinstance(result, LlmResponse)


def test_there_is_no_fail_open_option():
    """``fail_closed=False`` used to turn an unreachable wl-apdp into
    Allow on the tool and model paths. The option is gone: an unreachable
    wl-apdp is always a Deny."""
    with pytest.raises(TypeError):
        _plugin(_ScriptedApdp("Allow"), fail_closed=False)
