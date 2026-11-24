"""Every provider-hosted tool on a model call is authorized before the call
(conformance invariant 19).

The ADK plugin reads the request through the shared hosted-tool gate
(``watchlight_core.hosted_tools``): Gemini built-ins, raw callables,
remote ``mcp_servers`` and ``http_options.extra_body`` passthrough. The
egress-parity tests drive ADK's real ``InMemoryRunner`` and the real
``Gemini`` model class over an ``httpx.MockTransport``: every hosted tool
in a captured request body must have an Allow from this turn, and a
refusal means no HTTP request at all.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Set
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest
from google import genai
from google.adk.agents import LlmAgent
from google.adk.models.google_llm import Gemini
from google.adk.models.llm_request import LlmRequest
from google.adk.models.llm_response import LlmResponse
from google.adk.runners import InMemoryRunner
from google.adk.tools import google_search
from google.genai import types

from watchlight_core import HostedToolTurn
from watchlight_adk.plugin import HOSTED_TOOL_NOT_AUTHORIZED, WatchlightPlugin
from watchlight_adk.traces import translate_adk_event

from .test_subagent_time_budget import (
    APP_NAME,
    ROOT_NAME,
    ROOT_SLUG,
    USER_ID,
    _DeadlineAwareApdp,
)
from ._contexts import non_live_context

MCP_URL = "https://mcp.example.test/mcp"


class _Apdp:
    def __init__(self, deny: Set[str] = frozenset()) -> None:  # type: ignore[assignment]
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


def _plugin(apdp: Any, **kwargs: Any) -> WatchlightPlugin:
    plugin = WatchlightPlugin(
        apdp_url="http://localhost:8081",
        tenant_id="t1",
        agent_slug="agent-research-analyst",
        root_agent_name="research_analyst",
        log_decisions=False,
        **kwargs,
    )
    plugin.apdp = apdp  # type: ignore[assignment]
    plugin.lineage._apdp = apdp  # type: ignore[attr-defined]
    plugin._current_agent_id = "agent-uuid"
    plugin._current_execution_id = "exec_test"
    return plugin


def _ctx() -> MagicMock:
    ctx = non_live_context()
    ctx._invocation_context.agent = None
    return ctx


def _request(*tools: Any, **config: Any) -> LlmRequest:
    req = LlmRequest()
    req.config = types.GenerateContentConfig(tools=list(tools), **config)
    return req


def _mcp_tool() -> types.Tool:
    return types.Tool(
        mcp_servers=[
            types.McpServer(
                name="docs", streamable_http_transport=types.StreamableHttpTransport(url=MCP_URL)
            )
        ]
    )


# ── The gate on one model turn ───────────────────────────────────────


def test_the_plugin_declares_the_gemini_hosted_tool_gate():
    assert WatchlightPlugin.supports_hosted_tools is True
    assert WatchlightPlugin.hosted_tool_provider == "gemini"


@pytest.mark.asyncio
async def test_a_denied_builtin_refuses_the_turn_under_the_turns_identity():
    apdp = _Apdp(deny={'Tool::"google_search"'})
    plugin = _plugin(apdp)

    result = await plugin.before_model_callback(
        callback_context=_ctx(),
        llm_request=_request(types.Tool(google_search=types.GoogleSearch())),
    )

    assert isinstance(result, LlmResponse)
    call = next(c for c in apdp.calls if c["resource"] == 'Tool::"google_search"')
    assert call["principal"] == 'Agent::"agent-uuid"'
    assert call["action"] == 'Action::"execute"'
    assert call["execution_id"] == "exec_test"
    assert call["context"]["tenant_id"] == "t1"
    assert call["context"]["builtin_tool"] is True
    assert call["context"]["hosted_tool"] == {"provider": "gemini", "kind": "google_search"}
    assert plugin._denied_count == 1


@pytest.mark.asyncio
async def test_an_unregistered_mcp_server_refuses_the_turn_before_any_decision():
    apdp = _Apdp()
    plugin = _plugin(apdp)

    result = await plugin.before_model_callback(
        callback_context=_ctx(), llm_request=_request(_mcp_tool())
    )

    assert isinstance(result, LlmResponse)
    assert not [r for r in apdp.resources() if r.startswith('Resource::"mcp://')]


@pytest.mark.asyncio
async def test_a_registered_mcp_server_is_authorized_by_its_registered_name():
    apdp = _Apdp()
    plugin = _plugin(apdp, registered_mcp_servers={MCP_URL: "docs"})

    result = await plugin.before_model_callback(
        callback_context=_ctx(), llm_request=_request(_mcp_tool())
    )

    assert result is None
    assert 'Resource::"mcp://docs/"' in apdp.resources()


@pytest.mark.asyncio
async def test_a_hosted_tool_in_extra_body_is_authorized():
    apdp = _Apdp(deny={'Tool::"code_execution"'})
    plugin = _plugin(apdp)
    req = _request(
        http_options=types.HttpOptions(extra_body={"tools": [{"codeExecution": {}}]})
    )

    result = await plugin.before_model_callback(callback_context=_ctx(), llm_request=req)

    assert isinstance(result, LlmResponse)
    assert 'Tool::"code_execution"' in apdp.resources()


@pytest.mark.asyncio
async def test_a_cached_content_reference_is_authorized():
    apdp = _Apdp(deny={'Tool::"cached_content"'})
    plugin = _plugin(apdp)

    result = await plugin.before_model_callback(
        callback_context=_ctx(), llm_request=_request(cached_content="cachedContents/abc")
    )

    assert isinstance(result, LlmResponse)
    assert 'Tool::"cached_content"' in apdp.resources()


@pytest.mark.asyncio
async def test_a_request_the_gate_cannot_read_refuses_the_turn():
    plugin = _plugin(_Apdp())

    result = await plugin.before_model_callback(
        callback_context=_ctx(), llm_request=MagicMock()
    )

    assert isinstance(result, LlmResponse)
    assert plugin._denied_count == 1


@pytest.mark.asyncio
async def test_a_gate_failure_refuses_the_turn(monkeypatch: pytest.MonkeyPatch):
    import watchlight_adk.plugin as plugin_module

    async def _broken(*_a: Any, **_kw: Any) -> Any:
        raise RuntimeError("gate failure")

    monkeypatch.setattr(plugin_module, "authorize_hosted_request", _broken)
    plugin = _plugin(_Apdp())

    result = await plugin.before_model_callback(
        callback_context=_ctx(), llm_request=_request()
    )

    assert isinstance(result, LlmResponse)


@pytest.mark.asyncio
async def test_the_final_recheck_reuses_the_turns_allows_and_refuses_after_the_turn():
    apdp = _Apdp()
    plugin = _plugin(apdp)
    ctx = _ctx()
    req = _request(types.Tool(google_search=types.GoogleSearch()))
    plugin._registered_on = lambda _ctx: True  # type: ignore[method-assign]

    assert await plugin.before_model_callback(callback_context=ctx, llm_request=req) is None
    assert await plugin._final_request_recheck(callback_context=ctx, llm_request=req) is None
    assert apdp.resources().count('Tool::"google_search"') == 1

    # The response seals the turn: a model call it did not open is refused.
    await plugin.after_model_callback(callback_context=ctx, llm_response=LlmResponse())
    refused = await plugin._final_request_recheck(callback_context=ctx, llm_request=req)
    assert isinstance(refused, LlmResponse)


# ── Lineage ──────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_a_hosted_tool_the_response_shows_ran_is_recorded_without_values():
    plugin = _plugin(_Apdp())
    ctx = _ctx()
    req = _request(
        types.Tool(google_search=types.GoogleSearch()),
        types.Tool(url_context=types.UrlContext()),
    )
    assert await plugin.before_model_callback(callback_context=ctx, llm_request=req) is None
    plugin.lineage._captures.clear()  # type: ignore[attr-defined]

    response = LlmResponse(
        content=types.Content(role="model", parts=[types.Part(text="answer")]),
        grounding_metadata=types.GroundingMetadata(web_search_queries=["secret query"]),
    )
    await plugin.after_model_callback(callback_context=ctx, llm_response=response)

    captures = [
        c
        for c in plugin.lineage._captures  # type: ignore[attr-defined]
        if c["hook"] == "hosted_tool_observed"
    ]
    assert len(captures) == 1  # url_context was enabled but did not run
    event = translate_adk_event(capture=captures[0], execution_id="exec_test", agent_id="agent-uuid")
    assert event is not None
    assert event["event_type"] == "tool_call_observed"
    assert event["metadata"]["hosted_tool"] is True
    assert event["payload"]["tool"]["identifier"] == "google_search"
    assert "secret query" not in json.dumps(event)


@pytest.mark.asyncio
async def test_a_hosted_tool_the_turn_did_not_authorize_is_recorded_as_not_authorized():
    # The request enables no hosted tool; the response shows search ran.
    plugin = _plugin(_Apdp())
    ctx = _ctx()
    assert await plugin.before_model_callback(callback_context=ctx, llm_request=_request()) is None
    plugin.lineage._captures.clear()  # type: ignore[attr-defined]

    response = LlmResponse(
        content=types.Content(role="model", parts=[types.Part(text="answer")]),
        grounding_metadata=types.GroundingMetadata(web_search_queries=["secret query"]),
    )
    await plugin.after_model_callback(callback_context=ctx, llm_response=response)

    captures = [
        c
        for c in plugin.lineage._captures  # type: ignore[attr-defined]
        if c["hook"] == "hosted_tool_observed"
    ]
    assert len(captures) == 1
    event = translate_adk_event(capture=captures[0], execution_id="exec_test", agent_id="agent-uuid")
    assert event is not None
    assert event["event_type"] == "tool_call_observed"
    assert event["payload"]["tool"]["identifier"] == "google_search"
    assert event["payload"]["decision"] == HOSTED_TOOL_NOT_AUTHORIZED != "Allow"
    assert "secret query" not in json.dumps(event)


@pytest.mark.asyncio
async def test_no_llm_request_refuses_the_turn():
    plugin = _plugin(_Apdp())
    assert plugin._hosted_request(None) is None
    result = await plugin.before_model_callback(callback_context=_ctx(), llm_request=None)
    assert isinstance(result, LlmResponse)


# ── Egress parity through ADK's runner and the real Gemini client ────


class _GateApdp(_DeadlineAwareApdp):
    """The runner stand-in, denying the resources in ``deny``."""

    def __init__(self, deny: Set[str] = frozenset()) -> None:  # type: ignore[assignment]
        super().__init__()
        self._deny = set(deny)

    def _decide(self, action: str, resource: str, run_handle_id: Optional[str]) -> Dict[str, Any]:
        if resource in self._deny:
            return {"decision": "Deny", "reason": "no", "details": {}}
        return super()._decide(action, resource, run_handle_id)


def _gemini(client: genai.Client) -> Gemini:
    """The real ``Gemini`` model class over ``client`` (ADK's documented
    way to supply a client; ``Gemini(client=)`` is newer than the floor)."""

    class _Model(Gemini):
        @property
        def api_client(self) -> genai.Client:  # type: ignore[override]
            return client

    return _Model(model="gemini-2.5-flash")


def _snake(name: str) -> str:
    return "".join("_" + c.lower() if c.isupper() else c for c in name)


def _hosted_in_body(body: Dict[str, Any]) -> Set[str]:
    """The ``Tool::"<kind>"`` resources a Gemini request body enables."""
    found: Set[str] = set()
    for entry in body.get("tools") or []:
        for key in entry:
            if key != "functionDeclarations":
                found.add(f'Tool::"{_snake(key)}"')
    return found


async def _run(apdp: _GateApdp, agent_callback: Any = None, tools: Any = ()) -> List[Dict[str, Any]]:
    """One user turn through ``InMemoryRunner`` over the real ``Gemini``
    model; returns the request bodies that left for the provider."""
    bodies: List[Dict[str, Any]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        bodies.append(json.loads(request.content))
        return httpx.Response(
            200,
            json={
                "candidates": [
                    {
                        "content": {"role": "model", "parts": [{"text": "done"}]},
                        "finishReason": "STOP",
                    }
                ]
            },
        )

    client = genai.Client(
        api_key="test-key",
        http_options=types.HttpOptions(
            httpx_async_client=httpx.AsyncClient(transport=httpx.MockTransport(handler))
        ),
    )
    agent = LlmAgent(
        name=ROOT_NAME,
        model=_gemini(client),
        tools=list(tools),
        before_model_callback=agent_callback,
    )
    plugin = WatchlightPlugin(
        apdp_url="http://localhost:8081",
        tenant_id="t1",
        log_decisions=False,
        agent_slug=ROOT_SLUG,
        root_agent_name=ROOT_NAME,
    )
    plugin.apdp = apdp  # type: ignore[assignment]
    plugin.lineage._apdp = apdp  # type: ignore[attr-defined]
    runner = InMemoryRunner(agent=agent, app_name=APP_NAME, plugins=[plugin])
    session = await runner.session_service.create_session(app_name=APP_NAME, user_id=USER_ID)
    message = types.Content(role="user", parts=[types.Part.from_text(text="Look it up.")])
    try:
        async for _event in runner.run_async(
            user_id=USER_ID, session_id=session.id, new_message=message
        ):
            pass
    finally:
        await plugin.close()
    return bodies


def _allowed(apdp: _GateApdp) -> Set[str]:
    return {c["resource"] for c in apdp.authorize_calls if c["decision"] == "Allow"}


def _add_code_execution(callback_context: Any, llm_request: Any) -> None:
    llm_request.config.http_options = types.HttpOptions(
        extra_body={"tools": [{"codeExecution": {}}]}
    )


def _add_url_context(callback_context: Any, llm_request: Any) -> None:
    llm_request.config.tools = list(llm_request.config.tools or []) + [
        types.Tool(url_context=types.UrlContext())
    ]


@pytest.mark.asyncio
async def test_every_hosted_tool_that_leaves_was_allowed_first():
    apdp = _GateApdp()

    bodies = await _run(apdp, tools=[google_search])

    assert len(bodies) == 1
    hosted = _hosted_in_body(bodies[0])
    assert 'Tool::"google_search"' in hosted
    assert hosted <= _allowed(apdp)


@pytest.mark.asyncio
async def test_a_denied_builtin_sends_no_request():
    apdp = _GateApdp(deny={'Tool::"google_search"'})

    assert await _run(apdp, tools=[google_search]) == []


@pytest.mark.asyncio
async def test_a_builtin_added_by_an_agent_callback_is_allowed_before_it_leaves():
    apdp = _GateApdp()

    bodies = await _run(apdp, agent_callback=_add_url_context)

    assert len(bodies) == 1
    assert 'Tool::"url_context"' in _hosted_in_body(bodies[0])
    assert _hosted_in_body(bodies[0]) <= _allowed(apdp)


@pytest.mark.asyncio
async def test_a_denied_builtin_added_by_an_agent_callback_sends_no_request():
    apdp = _GateApdp(deny={'Tool::"url_context"'})

    assert await _run(apdp, agent_callback=_add_url_context) == []


@pytest.mark.asyncio
async def test_a_denied_hosted_tool_in_extra_body_sends_no_request():
    apdp = _GateApdp(deny={'Tool::"code_execution"'})

    assert await _run(apdp, agent_callback=_add_code_execution) == []


@pytest.mark.asyncio
async def test_an_allowed_hosted_tool_in_extra_body_leaves_after_its_allow():
    apdp = _GateApdp()

    bodies = await _run(apdp, agent_callback=_add_code_execution)

    assert len(bodies) == 1
    assert 'Tool::"code_execution"' in _hosted_in_body(bodies[0])
    assert _hosted_in_body(bodies[0]) <= _allowed(apdp)


def test_a_fresh_turn_is_unsealed():
    # Guards the per-turn reset in before_model_callback.
    assert HostedToolTurn().sealed is False
