"""Plan governance in the ADK plugin.

``WATCHLIGHT_PLAN_GOVERNANCE_MODE`` only decides what happens when the
plan pipeline fails: ``strict`` (the default) refuses, ``degrade``
(explicit opt-in) continues with action-time enforcement. Whether a
model turn must carry a ``/*PLANNING*/`` block is not a global-mode
question; the constraint manifest has no field that requires a plan, so
a turn without one is not refused (its tool calls are still authorized
one by one).
"""

from __future__ import annotations

from typing import Any, Dict, Optional
from unittest.mock import AsyncMock, MagicMock

import pytest
from google.adk.models.llm_response import LlmResponse
from google.genai import types as genai_types

from watchlight_adk.plugin import WatchlightPlugin

PLAN_TEXT = (
    "/*PLANNING*/\n"
    '[{"step_id": "s1", "action": "search_web", "resource": "Web::\\"x\\""}]\n'
    "/*ACTION*/"
)


class _PlanApdp:
    def __init__(self, submit: Any) -> None:
        self.submit_plan = AsyncMock(side_effect=submit)
        self.publish_events = AsyncMock(return_value=True)
        self.get_manifest = AsyncMock(return_value={})
        self.authorize = AsyncMock(return_value={"decision": "Allow"})


def _plugin(apdp: _PlanApdp) -> WatchlightPlugin:
    plugin = WatchlightPlugin(
        apdp_url="http://localhost:8081",
        tenant_id="t1",
        agent_slug="agent-research-analyst",
        root_agent_name="research_analyst",
        log_decisions=False,
    )
    plugin.apdp = apdp  # type: ignore[assignment]
    plugin.lineage._apdp = apdp  # type: ignore[attr-defined]
    plugin._current_agent_id = "agent-uuid"
    plugin._current_execution_id = "exec_test"
    plugin._session_id = "ses_test"
    return plugin


def _response(text: str) -> LlmResponse:
    return LlmResponse(
        content=genai_types.Content(
            role="model", parts=[genai_types.Part.from_text(text=text)]
        )
    )


def _text(response: LlmResponse) -> str:
    assert response.content is not None and response.content.parts
    return "".join(part.text or "" for part in response.content.parts)


async def _after(plugin: WatchlightPlugin, text: str) -> Optional[Any]:
    return await plugin.after_model_callback(
        callback_context=MagicMock(), llm_response=_response(text)
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", [None, "strict", "degrade"])
async def test_a_turn_without_a_plan_block_is_not_refused(monkeypatch, mode):
    if mode is None:
        monkeypatch.delenv("WATCHLIGHT_PLAN_GOVERNANCE_MODE", raising=False)
    else:
        monkeypatch.setenv("WATCHLIGHT_PLAN_GOVERNANCE_MODE", mode)
    apdp = _PlanApdp(lambda *a, **k: None)
    plugin = _plugin(apdp)

    assert await _after(plugin, "Here is the final answer.") is None
    apdp.submit_plan.assert_not_awaited()


async def _none(*_a: Any, **_k: Any) -> None:
    return None


async def _raise(*_a: Any, **_k: Any) -> None:
    raise TimeoutError("read timed out")


@pytest.mark.asyncio
@pytest.mark.parametrize("submit", [_none, _raise], ids=["falsy", "raises"])
async def test_a_failed_plan_submission_refuses_the_turn_in_strict_mode(monkeypatch, submit):
    monkeypatch.delenv("WATCHLIGHT_PLAN_GOVERNANCE_MODE", raising=False)
    apdp = _PlanApdp(submit)
    plugin = _plugin(apdp)

    result = await _after(plugin, PLAN_TEXT)

    assert isinstance(result, LlmResponse)
    assert "could not validate your plan" in _text(result)
    # The replacement carries no function call from the refused turn.
    assert not any(p.function_call for p in result.content.parts)
    apdp.submit_plan.assert_awaited_once()


@pytest.mark.asyncio
@pytest.mark.parametrize("submit", [_none, _raise], ids=["falsy", "raises"])
async def test_a_failed_plan_submission_continues_only_under_degrade(monkeypatch, submit):
    monkeypatch.setenv("WATCHLIGHT_PLAN_GOVERNANCE_MODE", "degrade")
    plugin = _plugin(_PlanApdp(submit))

    assert await _after(plugin, PLAN_TEXT) is None


@pytest.mark.asyncio
async def test_a_denied_plan_returns_an_llm_response(monkeypatch):
    async def _deny(*_a: Any, **_k: Any) -> Dict[str, Any]:
        return {
            "validation": {
                "decision": {"decision": "deny"},
                "violations": [{"message": "not allowed"}],
            }
        }

    plugin = _plugin(_PlanApdp(_deny))

    result = await _after(plugin, PLAN_TEXT)

    assert isinstance(result, LlmResponse)
    assert "denied your plan" in _text(result)
    # Opaque deny: the server's violation messages are not shown.
    assert "not allowed" not in _text(result)
