"""Tools that run outside ``before_tool_callback`` are authorized per
model turn: a local code executor (anything but ``BuiltInCodeExecutor``),
raw Python callables in the request config, and built-in tools added to
the request after the plugin's own callback (by an agent-level
``before_model_callback`` or a later plugin)."""

from __future__ import annotations

from typing import Any, Dict, List
from unittest.mock import AsyncMock, MagicMock

import pytest
from google.adk.agents import LlmAgent
from google.adk.code_executors.built_in_code_executor import BuiltInCodeExecutor
from google.adk.code_executors.unsafe_local_code_executor import UnsafeLocalCodeExecutor
from google.adk.models.llm_request import LlmRequest
from google.adk.models.llm_response import LlmResponse
from google.genai import types

from watchlight_adk.plugin import CODE_EXECUTOR_TOOL, WatchlightPlugin
from ._contexts import non_live_context


class _Apdp:
    def __init__(self, deny: set) -> None:
        self.calls: List[Dict[str, Any]] = []

        async def _authorize(**kw: Any) -> Dict[str, Any]:
            self.calls.append(kw)
            if kw["resource"] in deny:
                return {"decision": "Deny", "reason": "no", "details": {}}
            return {"decision": "Allow", "reason": "", "details": {}}

        self.authorize = AsyncMock(side_effect=_authorize)
        self.publish_events = AsyncMock(return_value=True)
        self.get_manifest = AsyncMock(return_value={})

    def resources(self) -> List[str]:
        return [c["resource"] for c in self.calls]


def _plugin(apdp: _Apdp) -> WatchlightPlugin:
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
    return plugin


def _ctx(agent: Any) -> MagicMock:
    ctx = non_live_context()
    ctx._invocation_context.agent = agent
    return ctx


CODE_RESOURCE = f'Tool::"{CODE_EXECUTOR_TOOL}"'


@pytest.mark.asyncio
async def test_a_local_code_executor_is_authorized_every_turn_and_a_deny_refuses():
    apdp = _Apdp(deny={CODE_RESOURCE})
    plugin = _plugin(apdp)
    agent = LlmAgent(name="coder", code_executor=UnsafeLocalCodeExecutor())

    result = await plugin.before_model_callback(
        callback_context=_ctx(agent), llm_request=LlmRequest()
    )

    assert isinstance(result, LlmResponse)
    assert CODE_RESOURCE in apdp.resources()


@pytest.mark.asyncio
async def test_an_allowed_local_code_executor_lets_the_turn_proceed():
    apdp = _Apdp(deny=set())
    plugin = _plugin(apdp)
    agent = LlmAgent(name="coder", code_executor=UnsafeLocalCodeExecutor())

    for _ in range(2):
        assert (
            await plugin.before_model_callback(
                callback_context=_ctx(agent), llm_request=LlmRequest()
            )
            is None
        )
    assert apdp.resources().count(CODE_RESOURCE) == 2


@pytest.mark.asyncio
async def test_the_built_in_code_executor_is_not_a_local_executor():
    apdp = _Apdp(deny={CODE_RESOURCE})
    plugin = _plugin(apdp)
    agent = LlmAgent(name="coder", code_executor=BuiltInCodeExecutor())

    result = await plugin.before_model_callback(
        callback_context=_ctx(agent), llm_request=LlmRequest()
    )

    assert result is None
    assert CODE_RESOURCE not in apdp.resources()


def _send_report(text: str) -> str:
    return text


@pytest.mark.asyncio
async def test_a_raw_callable_in_the_request_config_is_authorized_by_name():
    apdp = _Apdp(deny={'Tool::"callable:_send_report"'})
    plugin = _plugin(apdp)
    req = LlmRequest()
    req.config = types.GenerateContentConfig(tools=[_send_report])

    result = await plugin.before_model_callback(
        callback_context=_ctx(None), llm_request=req
    )

    assert isinstance(result, LlmResponse)
    assert 'Tool::"callable:_send_report"' in apdp.resources()


@pytest.mark.asyncio
async def test_a_builtin_added_by_an_agent_callback_is_rechecked_last():
    apdp = _Apdp(deny={'Tool::"google_search"'})
    plugin = _plugin(apdp)

    def add_search(callback_context: Any, llm_request: Any) -> None:
        llm_request.config.tools = list(llm_request.config.tools or []) + [
            types.Tool(google_search=types.GoogleSearch())
        ]
        return None

    agent = LlmAgent(name="sneaky", before_model_callback=add_search)
    req = LlmRequest()
    req.config = types.GenerateContentConfig(tools=[])
    ctx = _ctx(agent)

    # The plugin's own check sees no built-in tool and allows the turn.
    assert await plugin.before_model_callback(callback_context=ctx, llm_request=req) is None
    callbacks = agent.canonical_before_model_callbacks
    assert callbacks[0] is add_search
    assert getattr(callbacks[-1], "__func__", None) is WatchlightPlugin._final_request_recheck

    # ADK then runs the agent's callbacks in order.
    result = None
    for cb in callbacks:
        out = cb(callback_context=ctx, llm_request=req)
        if hasattr(out, "__await__"):
            out = await out
        if out is not None:
            result = out
            break
    assert isinstance(result, LlmResponse)
    assert 'Tool::"google_search"' in apdp.resources()

    # Installing it again keeps exactly one re-check, still last.
    await plugin.before_model_callback(callback_context=ctx, llm_request=LlmRequest())
    ours = [
        cb
        for cb in agent.canonical_before_model_callbacks
        if getattr(cb, "__func__", None) is WatchlightPlugin._final_request_recheck
    ]
    assert len(ours) == 1


def test_the_prompt_summary_carries_no_prompt_text():
    req = LlmRequest(
        contents=[
            types.Content(role="user", parts=[types.Part.from_text(text="my SSN is 123-45-6789")])
        ]
    )
    summary = WatchlightPlugin._extract_prompt_summary(req)
    assert summary == "1 contents"
    assert "123-45" not in summary
