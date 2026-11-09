"""A refused tool call is recorded in lineage as refused, never as an Allow.

ADK runs every plugin's ``after_tool_callback`` even when a
``before_tool_callback`` refused the call and the tool body never ran. The
plugin must then record nothing more: the refusal is recorded once, when it
is made, with the decision it got. An allowed call is recorded once, as an
Allow. Driven through ADK's real ``InMemoryRunner``.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

import pytest
from google.adk.agents import LlmAgent
from google.adk.plugins.base_plugin import BasePlugin
from google.adk.runners import InMemoryRunner
from google.genai import types

from watchlight_adk import plugin as plugin_module
from watchlight_adk.plugin import WatchlightPlugin
from watchlight_adk.traces import translate_adk_event

from .test_subagent_time_budget import (
    APP_NAME,
    ROOT_NAME,
    ROOT_SLUG,
    USER_ID,
    _call,
    _DeadlineAwareApdp,
    _final,
    _RecordingScriptedLlm,
)

BODIES: List[str] = []


@pytest.fixture(autouse=True)
def _reset() -> None:
    BODIES.clear()
    RAISE.clear()


RAISE: List[bool] = []


def lookup(query: str) -> dict:
    """The tool under test."""
    BODIES.append("lookup")
    if RAISE:
        raise RuntimeError("tool failed")
    return {"ok": True}


class _Apdp(_DeadlineAwareApdp):
    """Answers ``decision`` for ``Tool::"lookup"``; everything else as the
    stand-in does."""

    def __init__(self, decision: str) -> None:
        super().__init__()
        self._lookup_decision = decision

    def _decide(self, action: str, resource: str, run_handle_id: Optional[str]) -> Dict[str, Any]:
        if resource == 'Tool::"lookup"':
            return {"decision": self._lookup_decision, "reason": "policy", "details": {}}
        return super()._decide(action, resource, run_handle_id)


def _plugin(apdp: _DeadlineAwareApdp) -> WatchlightPlugin:
    plugin = WatchlightPlugin(
        apdp_url="http://localhost:8081",
        tenant_id="t1",
        connect_proxy_url=None,
        log_decisions=False,
        agent_slug=ROOT_SLUG,
        root_agent_name=ROOT_NAME,
    )
    plugin.apdp = apdp  # type: ignore[assignment]
    plugin.lineage._apdp = apdp  # type: ignore[attr-defined]
    return plugin


async def _run(decision: str) -> List[Dict[str, Any]]:
    """One root turn that calls ``lookup``; the ``tool_call_observed``
    payloads published for it."""
    return [event["payload"] for event in await _run_events(decision)]


async def _run_events(decision: str, before: Optional[List[Any]] = None) -> List[Dict[str, Any]]:
    """As :func:`_run`, the whole events. ``before`` are plugins
    registered ahead of Watchlight."""
    apdp = _Apdp(decision)
    plugin = _plugin(apdp)
    turns: List[str] = []
    model = _RecordingScriptedLlm(model="scripted").script(
        ROOT_NAME, turns, [_call("lookup", {"query": "secret-value"}), _final("ok")]
    )
    root = LlmAgent(name=ROOT_NAME, model=model, description="Root.", tools=[lookup])
    runner = InMemoryRunner(agent=root, app_name=APP_NAME, plugins=[*(before or []), plugin])
    session = await runner.session_service.create_session(app_name=APP_NAME, user_id=USER_ID)
    message = types.Content(role="user", parts=[types.Part.from_text(text="go")])
    try:
        [e async for e in runner.run_async(user_id=USER_ID, session_id=session.id, new_message=message)]
    except RuntimeError:
        if not RAISE:
            raise
    finally:
        await plugin.close()
    observed = []
    for call in apdp.publish_events.call_args_list:
        for event in call.args[1]:
            if event["event_type"] == "tool_call_observed" and event["payload"]["tool"]["identifier"] == "lookup":
                observed.append(event)
    return observed


@pytest.mark.asyncio
@pytest.mark.parametrize("decision", ["Deny", "Quarantine"])
async def test_a_refused_call_is_recorded_once_with_its_decision(decision: str) -> None:
    observed = await _run(decision)
    assert BODIES == []
    assert [p.get("decision") for p in observed] == [decision]


@pytest.mark.asyncio
async def test_a_refused_call_is_recorded_without_argument_values() -> None:
    (payload,) = await _run("Deny")
    assert "secret-value" not in repr(payload)
    assert payload.get("arg_key_summary") == "query"


@pytest.mark.asyncio
async def test_an_allowed_call_is_recorded_once_as_an_allow() -> None:
    observed = await _run("Allow")
    assert BODIES == ["lookup"]
    assert [p.get("decision") for p in observed] == ["Allow"]


@pytest.mark.asyncio
async def test_an_allowed_call_whose_tool_raises_is_recorded_as_a_failed_allow() -> None:
    RAISE.append(True)
    events = await _run_events("Allow")
    assert BODIES == ["lookup"]
    assert [(e["payload"].get("decision"), e["metadata"].get("outcome")) for e in events] == [
        ("Allow", "failed")
    ]


@pytest.mark.asyncio
async def test_a_refused_call_without_a_function_call_id_is_recorded_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(plugin_module, "_function_call_id_of", lambda context: None)
    observed = await _run("Deny")
    assert BODIES == []
    assert [p.get("decision") for p in observed] == ["Deny"]


def test_a_tool_event_without_a_decision_is_never_recorded_as_an_allow() -> None:
    event = translate_adk_event(
        capture={"hook": "after_tool_callback", "tool_name": "lookup", "action_verb": "query"},
        execution_id="exec_1",
        agent_id="00000000-0000-4000-8000-000000000001",
    )
    assert event is not None
    assert "decision" not in event["payload"]


# ─── Every refusal path, and calls the plugin never decided ──────────


@pytest.mark.asyncio
async def test_any_refusal_from_the_gate_is_recorded_as_a_deny(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every refusal path (no run, nested run, refused spawn, preflight,
    policy) returns through ``_before_tool``; one that records no decision
    of its own is a Deny, and never an Allow."""

    async def refuse(self: Any, **_kwargs: Any) -> dict:
        return {"result": "ACTION BLOCKED: a refusal path added later"}

    monkeypatch.setattr(WatchlightPlugin, "_before_tool", refuse)
    observed = await _run("Allow")
    assert BODIES == []
    assert [p.get("decision") for p in observed] == ["Deny"]


class _ShortCircuit(BasePlugin):
    """A plugin registered ahead of Watchlight that answers every tool
    call itself, so ADK never calls Watchlight's ``before_tool_callback``
    but still calls its ``after_tool_callback``."""

    def __init__(self) -> None:
        super().__init__(name="short_circuit")

    async def before_tool_callback(self, *, tool: Any, tool_args: dict, tool_context: Any) -> Optional[dict]:
        return {"result": "answered by another plugin"}


@pytest.mark.asyncio
async def test_a_call_another_plugin_answered_first_is_never_an_allow() -> None:
    events = await _run_events("Allow", before=[_ShortCircuit()])
    assert BODIES == []
    assert [e["payload"].get("decision") for e in events] in ([], [None])
    assert all(e["payload"].get("decision") != "Allow" for e in events)


@pytest.mark.asyncio
async def test_a_call_with_no_call_id_another_plugin_answered_is_never_an_allow(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(plugin_module, "_function_call_id_of", lambda context: None)
    events = await _run_events("Allow", before=[_ShortCircuit()])
    assert BODIES == []
    assert all(e["payload"].get("decision") != "Allow" for e in events)


@pytest.mark.asyncio
async def test_an_allowed_call_without_a_call_id_is_never_an_allow(monkeypatch: pytest.MonkeyPatch) -> None:
    """With no call id the plugin cannot tie the after-callback to its own
    Allow, so it records no decision (fail closed), never an Allow."""
    monkeypatch.setattr(plugin_module, "_function_call_id_of", lambda context: None)
    observed = await _run("Allow")
    assert BODIES == ["lookup"]
    assert all(p.get("decision") != "Allow" for p in observed)
    assert len(observed) == 1


@pytest.mark.asyncio
async def test_a_refused_sub_agent_call_is_recorded_as_a_deny(monkeypatch: pytest.MonkeyPatch) -> None:
    """The tool gate for a sub-agent whose governed spawn was refused (the
    second line behind ``before_agent_callback``)."""
    in_tool_gate: List[bool] = []
    original = WatchlightPlugin._before_tool

    async def gate(self: Any, **kwargs: Any) -> Any:
        in_tool_gate.append(True)
        try:
            return await original(self, **kwargs)
        finally:
            in_tool_gate.pop()

    # Refused only at the tool gate, so the root's model turn still asks
    # for the call.
    monkeypatch.setattr(WatchlightPlugin, "_before_tool", gate)
    monkeypatch.setattr(WatchlightPlugin, "_refused_subagent_name", lambda self: "child" if in_tool_gate else None)
    observed = await _run("Allow")
    assert BODIES == []
    assert [p.get("decision") for p in observed] == ["Deny"]


class _AnswersAfter(BasePlugin):
    """A plugin registered ahead of Watchlight whose after-callback answers,
    so ADK never calls Watchlight's: the refusal's key is never popped."""

    def __init__(self) -> None:
        super().__init__(name="answers_after")

    async def after_tool_callback(self, *, tool: Any, tool_args: dict, tool_context: Any, result: dict) -> Optional[dict]:
        return {"result": "rewritten by another plugin"}


@pytest.mark.asyncio
async def test_a_closed_frame_keeps_no_per_call_keys() -> None:
    """A key whose after-callback never came is dropped when the frame
    closes, so the set cannot grow and no key carries into a later run."""
    apdp = _Apdp("Deny")
    plugin = _plugin(apdp)
    frames: List[Any] = []
    original = plugin_module.WatchlightPlugin._close_frame

    async def spy(self: Any, frame: Any, *args: Any, **kwargs: Any) -> None:
        frames.append(frame)
        await original(self, frame, *args, **kwargs)

    plugin._close_frame = spy.__get__(plugin)  # type: ignore[method-assign]
    turns: List[str] = []
    model = _RecordingScriptedLlm(model="scripted").script(
        ROOT_NAME, turns, [_call("lookup", {"query": "q"}), _final("ok")]
    )
    root = LlmAgent(name=ROOT_NAME, model=model, description="Root.", tools=[lookup])
    runner = InMemoryRunner(agent=root, app_name=APP_NAME, plugins=[_AnswersAfter(), plugin])
    session = await runner.session_service.create_session(app_name=APP_NAME, user_id=USER_ID)
    message = types.Content(role="user", parts=[types.Part.from_text(text="go")])
    try:
        events = [e async for e in runner.run_async(user_id=USER_ID, session_id=session.id, new_message=message)]
    finally:
        await plugin.close()
    assert events
    assert frames
    assert all(not f.tools_recorded and not f.tools_in_flight for f in frames)
