"""A live invocation (``Runner.run_live``) is refused before it connects.

ADK's live flow opens the model connection with ``llm.connect(llm_request)``
without running ``before_model_callback``, and its receive path does not run
``after_model_callback``. ``Gemini.connect`` copies ``config.tools`` into the
live connection setup, so the connection would enable built-in tools (and
reach the model at all) with no chat decision and no hosted-tool gate. Until
the live path can be gated, the plugin refuses live invocations in
``before_run_callback``: the model connection is never opened.

Driven through ADK's real ``InMemoryRunner.run_live`` with a stand-in live
model (no network) that records every ``connect``.
"""

from __future__ import annotations

import asyncio
import contextlib
from typing import Any, AsyncGenerator, Dict, List, Optional, Sequence, Set

from unittest.mock import MagicMock

import pytest
from google.adk.agents import LlmAgent
from google.adk.agents.live_request_queue import LiveRequestQueue
from google.adk.agents.run_config import RunConfig
from google.adk.code_executors import BuiltInCodeExecutor
from google.adk.models.base_llm import BaseLlm
from google.adk.models.base_llm_connection import BaseLlmConnection
from google.adk.models.llm_request import LlmRequest
from google.adk.models.llm_response import LlmResponse
from google.adk.plugins.base_plugin import BasePlugin
from google.adk.runners import InMemoryRunner
from google.adk.tools import google_search
from google.genai import types

from watchlight_adk.plugin import _LIVE_REFUSAL, WatchlightPlugin

from .test_subagent_time_budget import (
    APP_NAME,
    ROOT_NAME,
    ROOT_SLUG,
    USER_ID,
    _DeadlineAwareApdp,
)

CONNECTS: List[LlmRequest] = []


class _GateApdp(_DeadlineAwareApdp):
    """The runner stand-in, denying the resources in ``deny``."""

    def __init__(self, deny: Set[str] = frozenset()) -> None:  # type: ignore[assignment]
        super().__init__()
        self._deny = set(deny)

    def _decide(self, action: str, resource: str, run_handle_id: Optional[str]) -> Dict[str, Any]:
        if resource in self._deny:
            return {"decision": "Deny", "reason": "no", "details": {}}
        return super()._decide(action, resource, run_handle_id)


class _LiveConnection(BaseLlmConnection):
    async def send_history(self, history: list[types.Content]) -> None:
        return None

    async def send_content(self, content: types.Content) -> None:
        return None

    async def send_realtime(self, blob: types.Blob) -> None:
        return None

    async def receive(self) -> AsyncGenerator[LlmResponse, None]:
        yield LlmResponse(
            content=types.Content(role="model", parts=[types.Part(text="live answer")]),
            turn_complete=True,
        )

    async def close(self) -> None:
        return None


class _LiveModel(BaseLlm):
    """A live model stand-in: records each ``connect`` request."""

    async def generate_content_async(
        self, llm_request: LlmRequest, stream: bool = False
    ) -> AsyncGenerator[LlmResponse, None]:
        raise AssertionError("a live test makes no non-live model call")
        yield  # pragma: no cover

    @contextlib.asynccontextmanager
    async def connect(self, llm_request: LlmRequest) -> AsyncGenerator[BaseLlmConnection, None]:
        CONNECTS.append(llm_request)
        yield _LiveConnection()


class _AnswersBeforeRun(BasePlugin):
    """A plugin registered before Watchlight whose ``before_run_callback``
    returns a value that is not ``Content``: ADK stops at it, so
    Watchlight's ``before_run_callback`` never runs, and the runner goes on
    into the agent."""

    def __init__(self) -> None:
        super().__init__(name="answers_before_run")

    async def before_run_callback(self, *, invocation_context: Any) -> Any:
        return {"handled": True}


async def _run_live(apdp: _GateApdp, before: Sequence[BasePlugin] = ()) -> List[Any]:
    CONNECTS.clear()
    agent = LlmAgent(name=ROOT_NAME, model=_LiveModel(model="gemini-live-2.5-flash"), tools=[google_search])
    plugin = WatchlightPlugin(
        apdp_url="http://localhost:8081",
        tenant_id="t1",
        log_decisions=False,
        agent_slug=ROOT_SLUG,
        root_agent_name=ROOT_NAME,
    )
    plugin.apdp = apdp  # type: ignore[assignment]
    plugin.lineage._apdp = apdp  # type: ignore[attr-defined]
    runner = InMemoryRunner(agent=agent, app_name=APP_NAME, plugins=[*before, plugin])
    session = await runner.session_service.create_session(app_name=APP_NAME, user_id=USER_ID)
    queue = LiveRequestQueue()
    queue.send_content(types.Content(role="user", parts=[types.Part.from_text(text="Look it up.")]))
    events: List[Any] = []

    async def _drain() -> None:
        async for event in runner.run_live(
            user_id=USER_ID,
            session_id=session.id,
            live_request_queue=queue,
            run_config=RunConfig(response_modalities=["TEXT"]),
        ):
            events.append(event)
            if getattr(event, "turn_complete", False):
                queue.close()

    try:
        await asyncio.wait_for(_drain(), timeout=5)
    finally:
        queue.close()
        await plugin.close()
    return events


@pytest.mark.asyncio
async def test_a_live_invocation_never_opens_the_model_connection():
    # Policy denies the model turn and the built-in tool: neither may reach
    # the model, and a live connection would carry both.
    apdp = _GateApdp(deny={'Model::"gemini-chat"', 'Tool::"google_search"'})

    events = await _run_live(apdp)

    assert CONNECTS == []
    assert _texts(events) == [_LIVE_REFUSAL]


@pytest.mark.asyncio
async def test_a_live_invocation_is_refused_even_when_policy_allows_everything():
    apdp = _GateApdp()

    events = await _run_live(apdp)

    assert CONNECTS == []
    assert _texts(events) == [_LIVE_REFUSAL]
    # No run is opened: no session, no decision asked for.
    assert apdp.authorize_calls == []
    apdp.create_session.assert_not_called()


@pytest.mark.asyncio
async def test_a_live_invocation_is_refused_at_the_agent_when_an_earlier_plugin_answers_first():
    # Watchlight's before_run_callback never runs here: its agent-level
    # check is what keeps the model connection closed.
    apdp = _GateApdp()

    events = await _run_live(apdp, before=[_AnswersBeforeRun()])

    assert CONNECTS == []
    assert _LIVE_REFUSAL in _texts(events)
    assert apdp.authorize_calls == []


async def _run_async_cfc(apdp: _GateApdp, before: Sequence[BasePlugin] = ()) -> List[Any]:
    """``run_async`` with ``RunConfig(support_cfc=True)``: ADK opens a live
    model connection from inside the model call."""
    CONNECTS.clear()
    agent = LlmAgent(
        name=ROOT_NAME,
        model=_LiveModel(model="gemini-2.5-flash"),
        code_executor=BuiltInCodeExecutor(),
        tools=[google_search],
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
    runner = InMemoryRunner(agent=agent, app_name=APP_NAME, plugins=[*before, plugin])
    session = await runner.session_service.create_session(app_name=APP_NAME, user_id=USER_ID)
    events: List[Any] = []

    async def _drain() -> None:
        async for event in runner.run_async(
            user_id=USER_ID,
            session_id=session.id,
            new_message=types.Content(role="user", parts=[types.Part.from_text(text="Look it up.")]),
            run_config=RunConfig(support_cfc=True),
        ):
            events.append(event)

    await asyncio.wait_for(_drain(), timeout=5)
    return events


@pytest.mark.asyncio
async def test_run_async_with_support_cfc_is_refused_before_it_connects():
    apdp = _GateApdp()

    events = await _run_async_cfc(apdp)

    assert CONNECTS == []
    assert _LIVE_REFUSAL in _texts(events)
    assert apdp.authorize_calls == []


@pytest.mark.asyncio
async def test_support_cfc_is_refused_at_the_agent_when_an_earlier_plugin_answers_first():
    apdp = _GateApdp()

    events = await _run_async_cfc(apdp, before=[_AnswersBeforeRun()])

    assert CONNECTS == []
    assert _LIVE_REFUSAL in _texts(events)
    assert apdp.authorize_calls == []


@pytest.mark.asyncio
async def test_a_support_cfc_model_call_is_refused_at_before_model():
    # The last line: a model call whose run config sets support_cfc is
    # refused even when the run and agent callbacks were never reached.
    plugin = WatchlightPlugin(
        apdp_url="http://localhost:8081",
        tenant_id="t1",
        log_decisions=False,
        agent_slug=ROOT_SLUG,
        root_agent_name=ROOT_NAME,
    )
    ctx = MagicMock()
    ctx._invocation_context.live_request_queue = None
    ctx._invocation_context.run_config = RunConfig(support_cfc=True)

    result = await plugin.before_model_callback(callback_context=ctx, llm_request=LlmRequest())

    assert isinstance(result, LlmResponse)
    assert result.content.parts[0].text == _LIVE_REFUSAL


def _texts(events: List[Any]) -> List[str]:
    return [
        part.text
        for event in events
        if event.content and event.content.parts
        for part in event.content.parts
        if part.text
    ]
