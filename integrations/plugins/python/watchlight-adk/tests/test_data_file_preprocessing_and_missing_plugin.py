"""ADK's data-file preprocessing is authorized when the agent starts,
and the request re-check names the missing plugin when a governed agent
object is later run without it."""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from google.adk.agents import LlmAgent
from google.adk.code_executors.base_code_executor import BaseCodeExecutor
from google.adk.models.llm_request import LlmRequest
from google.adk.models.llm_response import LlmResponse

from watchlight_adk.plugin import DATA_FILE_PREPROCESSING_TOOL, WatchlightPlugin

from .test_subagent_spawn_chokepoint import _agent, _make_plugin, _SpawnApdp
from ._contexts import non_live_context

# These tests call the plugin's callbacks directly: a governed run is live.
pytestmark = pytest.mark.usefixtures("governed_run_live")

RESOURCE = f'Tool::"{DATA_FILE_PREPROCESSING_TOOL}"'


class _LocalExecutor(BaseCodeExecutor):
    """Test stand-in for a local executor that supports data-file
    preprocessing (as the container and Vertex executors do)."""

    def execute_code(self, invocation_context: Any, code_execution_input: Any) -> Any:
        raise AssertionError("never executed in these tests")


def _preprocessing_root(optimize: bool) -> Any:
    agent = _agent("root_agent")
    agent.code_executor = _LocalExecutor(optimize_data_file=optimize)
    return agent


def _deny_resource(apdp: _SpawnApdp, resource: str) -> None:
    real = apdp.authorize

    async def _authorize(**kw: Any) -> Any:
        if kw.get("resource") == resource:
            apdp.authorize_calls.append({"resource": resource})
            return {"decision": "Deny", "reason": "not permitted"}
        return await real(**kw)

    apdp.authorize = AsyncMock(side_effect=_authorize)


@pytest.mark.asyncio
async def test_data_file_preprocessing_is_refused_unless_authorized():
    apdp = _SpawnApdp()
    _deny_resource(apdp, RESOURCE)
    plugin = _make_plugin(apdp)

    refusal = await plugin.before_agent_callback(
        agent=_preprocessing_root(True), callback_context=non_live_context()
    )

    assert refusal is not None
    assert "optimize_data_file" in "".join(p.text or "" for p in refusal.parts)
    assert any(c["resource"] == RESOURCE for c in apdp.authorize_calls)


@pytest.mark.asyncio
async def test_authorized_data_file_preprocessing_starts_the_agent():
    apdp = _SpawnApdp()
    plugin = _make_plugin(apdp)

    result = await plugin.before_agent_callback(
        agent=_preprocessing_root(True), callback_context=non_live_context()
    )

    assert result is None
    assert any(c["resource"] == RESOURCE for c in apdp.authorize_calls)


@pytest.mark.asyncio
async def test_no_preprocessing_no_extra_authorization():
    apdp = _SpawnApdp()
    plugin = _make_plugin(apdp)

    assert (
        await plugin.before_agent_callback(
            agent=_preprocessing_root(False), callback_context=non_live_context()
        )
        is None
    )
    assert not any(c["resource"] == RESOURCE for c in apdp.authorize_calls)


@pytest.mark.asyncio
async def test_recheck_names_the_missing_plugin_and_fails_closed():
    plugin = WatchlightPlugin(
        apdp_url="http://localhost:8081",
        agent_slug="agent-research-analyst",
        root_agent_name="research_analyst",
        log_decisions=False,
    )
    agent = LlmAgent(name="research_analyst")
    plugin._ensure_final_request_recheck(agent)
    recheck = agent.canonical_before_model_callbacks[-1]

    ctx = MagicMock()
    ctx._invocation_context.plugin_manager.plugins = []  # a runner without the plugin
    result = await recheck(callback_context=ctx, llm_request=LlmRequest())

    assert isinstance(result, LlmResponse)
    text = "".join(p.text or "" for p in result.content.parts)
    assert "plugin is not registered" in text


@pytest.mark.asyncio
async def test_recheck_with_the_plugin_registered_but_no_run_still_refuses():
    plugin = WatchlightPlugin(
        apdp_url="http://localhost:8081",
        agent_slug="agent-research-analyst",
        root_agent_name="research_analyst",
        log_decisions=False,
    )
    agent = LlmAgent(name="research_analyst")
    plugin._ensure_final_request_recheck(agent)
    recheck = agent.canonical_before_model_callbacks[-1]

    ctx = MagicMock()
    ctx._invocation_context.plugin_manager.plugins = [plugin]
    result = await recheck(callback_context=ctx, llm_request=LlmRequest())

    assert isinstance(result, LlmResponse)
    text = "".join(p.text or "" for p in result.content.parts)
    assert "plugin is not registered" not in text
