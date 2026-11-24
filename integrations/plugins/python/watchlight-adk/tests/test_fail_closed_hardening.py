"""Fail-closed hardening for the ADK plugin.

* There is no option that turns an unreachable wl-apdp into Allow.
* A root run whose governance session cannot be opened never runs: no
  model turn, no tool call.
* A configured wl-proxy CONNECT URL is a hard requirement: a failed
  install, or a session that issued no proxy token, refuses the run
  instead of letting the agent egress directly.
* Tool arguments reach wl-apdp and the lineage translator as value-free
  metadata only.
* A root whose handle fails to build after its session opened is refused
  and the session is closed; a degraded run (no manifest,
  explicit opt-in) still authorizes every tool call.
* Gemini built-in tools (Google Search, code execution, ...) run on
  Google's side and never fire ``before_tool_callback``; each model turn
  that carries one is authorized for it, and a denial refuses the turn.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from google.adk.agents import LlmAgent
from google.adk.models.llm_request import LlmRequest
from google.adk.models.llm_response import LlmResponse
from google.adk.runners import InMemoryRunner
from google.genai import types

from watchlight_core import GovernanceUnavailable
from watchlight_adk import translate_adk_event
from watchlight_adk.plugin import WatchlightPlugin

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
from watchlight_core_testing import stub_session_info
from ._contexts import non_live_context

SECRET = "sk-live-0123456789abcdef"
EXECUTED: List[str] = []


def send_email(to: str, api_key: str) -> dict:
    """Send an email."""
    EXECUTED.append("send_email")
    return {"ok": True}


def _root(turns: List[str], script: List[LlmResponse]) -> LlmAgent:
    model = _RecordingScriptedLlm(model="scripted").script(ROOT_NAME, turns, script)
    return LlmAgent(name=ROOT_NAME, model=model, description="Root.", tools=[send_email])


def _plugin(apdp: Any, **kwargs: Any) -> WatchlightPlugin:
    kwargs.setdefault("connect_proxy_url", None)
    plugin = WatchlightPlugin(
        apdp_url="http://localhost:8081",
        tenant_id="t1",
        log_decisions=False,
        agent_slug=ROOT_SLUG,
        root_agent_name=ROOT_NAME,
        **kwargs,
    )
    plugin.apdp = apdp  # type: ignore[assignment]
    plugin.lineage._apdp = apdp  # type: ignore[attr-defined]
    return plugin


async def _run(plugin: WatchlightPlugin, agent: LlmAgent, text: str = "Go.") -> List[str]:
    runner = InMemoryRunner(agent=agent, app_name=APP_NAME, plugins=[plugin])
    session = await runner.session_service.create_session(app_name=APP_NAME, user_id=USER_ID)
    texts: List[str] = []
    try:
        async for event in runner.run_async(
            user_id=USER_ID,
            session_id=session.id,
            new_message=types.Content(role="user", parts=[types.Part.from_text(text=text)]),
        ):
            if event.content and event.content.parts:
                texts.extend(p.text for p in event.content.parts if p.text)
    finally:
        await plugin.close()
    return texts


# ── No fail-open option (unreachable wl-apdp never becomes Allow) ─────


def test_the_fail_closed_option_no_longer_exists():
    with pytest.raises(TypeError):
        WatchlightPlugin(  # type: ignore[call-arg]
            apdp_url="http://localhost:8081",
            agent_slug=ROOT_SLUG,
            root_agent_name=ROOT_NAME,
            fail_closed=False,
        )


class _UnreachableToolApdp(_DeadlineAwareApdp):
    """Model turns are allowed; every tool authorize reports wl-apdp as
    unreachable, the way the client used to synthesize it."""

    def __init__(self) -> None:
        super().__init__()

        async def _authorize(*, resource: str, **_kw: Any) -> Dict[str, Any]:
            self.authorize_calls.append({"resource": resource, **_kw})
            if resource.startswith("Model::"):
                return {"decision": "Allow", "reason": "", "details": {}}
            return {"decision": "Deny", "reason": "APDP unreachable: connection refused", "details": {}}

        self.authorize.side_effect = _authorize


@pytest.mark.asyncio
async def test_an_unreachable_apdp_never_lets_a_tool_run_even_with_the_old_flag_forced():
    EXECUTED.clear()
    apdp = _UnreachableToolApdp()
    plugin = _plugin(apdp)
    # Whatever an integrator sets on the instance, no flag reopens it.
    plugin.fail_closed = False  # type: ignore[attr-defined]
    turns: List[str] = []
    agent = _root(
        turns,
        [_call("send_email", {"to": "a@b.c", "api_key": "k"}), _final("done")],
    )
    await _run(plugin, agent)
    assert EXECUTED == []


@pytest.mark.asyncio
async def test_an_unreachable_apdp_never_lets_a_model_turn_through_even_with_the_old_flag_forced():
    apdp = MagicMock()
    apdp.authorize = AsyncMock(
        return_value={"decision": "Deny", "reason": "APDP unreachable: connection refused", "details": {}}
    )
    apdp.publish_events = AsyncMock(return_value=True)
    plugin = _plugin(apdp)
    plugin.fail_closed = False  # type: ignore[attr-defined]
    plugin._current_agent_id = "agent-uuid"
    plugin._current_execution_id = "exec_test"

    result = await plugin.before_model_callback(
        callback_context=non_live_context(), llm_request=MagicMock()
    )
    assert isinstance(result, LlmResponse)


# ── A root whose session cannot open never runs ─────────────────────


class _NoSessionApdp(_DeadlineAwareApdp):
    def __init__(self, failure: str) -> None:
        super().__init__()

        async def _create_session(**_kw: Any) -> Dict[str, Any]:
            if failure == "raise":
                raise ConnectionError("wl-apdp unreachable")
            return {}

        self.create_session.side_effect = _create_session


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["raise", "empty"])
async def test_a_root_whose_session_fails_gets_no_model_turn_or_tool_call(failure: str):
    EXECUTED.clear()
    apdp = _NoSessionApdp(failure)
    plugin = _plugin(apdp)
    turns: List[str] = []
    agent = _root(turns, [_call("send_email", {"to": "a", "api_key": "k"}), _final("done")])

    texts = await _run(plugin, agent)

    assert turns == []  # the model was never called
    assert EXECUTED == []
    assert apdp.authorize_calls == []  # nothing ungoverned reached wl-apdp
    assert plugin.last_governance_mode == "unavailable"
    assert any("governance is unavailable" in t for t in texts)


@pytest.mark.asyncio
async def test_a_refused_root_leaves_no_open_frame_and_the_next_run_can_open():
    apdp = _NoSessionApdp("raise")
    plugin = _plugin(apdp)
    turns: List[str] = []
    await _run(plugin, _root(turns, [_final("done")]))
    assert turns == []

    # Governance comes back: the next run opens normally.
    healthy = _DeadlineAwareApdp()
    plugin2 = _plugin(healthy)
    turns2: List[str] = []
    await _run(plugin2, _root(turns2, [_final("done")]))
    assert turns2 == [ROOT_NAME]


# ── CONNECT proxy: configured means required ─────────────────────────


def _session_plugin(
    proxy_token: Optional[str], *, connect_proxy_url: Optional[str]
) -> WatchlightPlugin:
    plugin = WatchlightPlugin(
        apdp_url="http://localhost:8081",
        connect_proxy_url=connect_proxy_url,
        agent_slug=ROOT_SLUG,
        root_agent_name=ROOT_NAME,
        log_decisions=False,
    )
    session = stub_session_info(
        plugin.apdp, "ses_test", session_token="sst_test", proxy_token=proxy_token
    )
    plugin.apdp.create_session = AsyncMock(return_value=session)  # type: ignore[method-assign]
    plugin.apdp.get_manifest = AsyncMock(return_value={})  # type: ignore[method-assign]
    plugin.apdp.complete_session = AsyncMock(return_value=True)  # type: ignore[method-assign]
    plugin._current_agent_id = "agent-uuid"
    plugin._current_execution_id = "exec_test"
    return plugin


def _ctx() -> MagicMock:
    ctx = non_live_context()
    ctx.state = {}
    return ctx


@pytest.mark.asyncio
async def test_a_failed_connect_install_refuses_the_run_and_closes_the_session():
    plugin = _session_plugin("eyJ.test.token", connect_proxy_url="http://wl-proxy:8080")
    with patch(
        "watchlight_core.install_connect_proxy",
        side_effect=RuntimeError("sidecar startup failed"),
    ):
        with pytest.raises(GovernanceUnavailable):
            await plugin._open_session_and_manifest(_ctx())
    plugin.apdp.complete_session.assert_awaited_once()
    # The run it opened, named by its reference (session ses_test).
    assert (
        plugin.apdp.complete_session.call_args.args[0]
        == plugin.apdp.create_session.return_value.run
    )
    assert plugin.apdp.create_session.return_value.session_id == "ses_test"
    assert plugin._session_id is None
    assert plugin._current_run is None
    assert plugin.last_governance_mode == "unavailable"


@pytest.mark.asyncio
async def test_a_missing_manifest_refuses_the_run_before_egress_and_closes_the_session(
    monkeypatch,
):
    monkeypatch.delenv("WATCHLIGHT_PLAN_GOVERNANCE_MODE", raising=False)
    plugin = _session_plugin("eyJ.test.token", connect_proxy_url="http://wl-proxy:8080")
    plugin.apdp.get_manifest = AsyncMock(return_value=None)  # type: ignore[method-assign]
    with patch("watchlight_core.install_connect_proxy") as mock_install:
        with pytest.raises(GovernanceUnavailable):
            await plugin._open_session_and_manifest(_ctx())
    mock_install.assert_not_called()
    plugin.apdp.complete_session.assert_awaited_once()
    assert plugin._session_id is None


@pytest.mark.asyncio
async def test_a_missing_manifest_runs_degraded_only_on_explicit_opt_in(monkeypatch):
    monkeypatch.setenv("WATCHLIGHT_PLAN_GOVERNANCE_MODE", "degrade")
    plugin = _session_plugin(None, connect_proxy_url=None)
    plugin.apdp.get_manifest = AsyncMock(return_value=None)  # type: ignore[method-assign]
    await plugin._open_session_and_manifest(_ctx())
    assert plugin.last_governance_mode == "degraded"
    plugin.apdp.complete_session.assert_not_awaited()


@pytest.mark.asyncio
async def test_a_configured_proxy_with_no_issued_token_refuses_the_run():
    plugin = _session_plugin(None, connect_proxy_url="http://wl-proxy:8080")
    with patch("watchlight_core.install_connect_proxy") as mock_install:
        with pytest.raises(GovernanceUnavailable):
            await plugin._open_session_and_manifest(_ctx())
    mock_install.assert_not_called()
    plugin.apdp.complete_session.assert_awaited_once()
    assert plugin._session_id is None


@pytest.mark.asyncio
async def test_a_proxy_configured_by_env_with_no_token_refuses_the_run(monkeypatch):
    monkeypatch.setenv("WATCHLIGHT_PROXY_URL", "http://wl-proxy.env:8080")
    plugin = _session_plugin(None, connect_proxy_url=None)
    with pytest.raises(GovernanceUnavailable):
        await plugin._open_session_and_manifest(_ctx())


class _ProxyTokenlessApdp(_DeadlineAwareApdp):
    """Opens a session but issues no proxy token."""


@pytest.mark.asyncio
async def test_a_root_with_a_configured_proxy_and_no_token_gets_no_model_turn():
    EXECUTED.clear()
    apdp = _ProxyTokenlessApdp()
    plugin = _plugin(apdp, connect_proxy_url="http://wl-proxy:8080")
    turns: List[str] = []
    with patch("watchlight_core.install_connect_proxy") as mock_install:
        texts = await _run(plugin, _root(turns, [_final("done")]))
    mock_install.assert_not_called()
    assert turns == []
    assert apdp.authorize_calls == []
    apdp.complete_session.assert_awaited()  # the opened session is closed
    assert any("governance is unavailable" in t for t in texts)


# ── Tool arguments are value-free ────────────────────────────────────


@pytest.mark.asyncio
async def test_tool_authorize_context_carries_no_argument_values():
    EXECUTED.clear()
    apdp = _DeadlineAwareApdp()
    seen: List[Dict[str, Any]] = []
    inner = apdp.authorize.side_effect

    async def _record(**kw: Any) -> Dict[str, Any]:
        seen.append(kw)
        return await inner(**kw)

    apdp.authorize.side_effect = _record
    plugin = _plugin(apdp)
    turns: List[str] = []
    agent = _root(
        turns,
        [_call("send_email", {"to": "ceo@example.com", "api_key": SECRET}), _final("done")],
    )
    await _run(plugin, agent)

    tool_calls = [c for c in seen if c["resource"].startswith("Tool::")]
    assert tool_calls, "the tool was authorized"
    ctx = tool_calls[0]["context"]
    assert SECRET not in repr(ctx)
    assert "ceo@example.com" not in repr(ctx)
    assert "tool_args" not in ctx
    assert ctx["tool_arg_metadata"]["arg_names"] == ["api_key", "to"]
    assert ctx["tool_arg_metadata"]["arg_types"] == {"to": "str", "api_key": "str"}


def test_the_plan_event_rationale_carries_no_argument_values():
    result = translate_adk_event(
        capture={
            "hook": "before_tool_callback",
            "tool_name": "send_email",
            "action_verb": "send",
            "tool_args": {"api_key": SECRET},
        },
        execution_id="exec",
        agent_id="agent-1",
    )
    assert result is not None
    assert SECRET not in repr(result)
    assert result["payload"]["rationale"] == "1 args: api_key(str)"


# ── Gemini built-in tools are authorized at the model turn ───────────


class _BuiltinApdp:
    def __init__(self, deny_builtin: bool) -> None:
        self.calls: List[Dict[str, Any]] = []

        async def _authorize(**kw: Any) -> Dict[str, Any]:
            self.calls.append(kw)
            if kw["resource"].startswith("Tool::") and deny_builtin:
                return {"decision": "Deny", "reason": "not permitted", "details": {}}
            return {"decision": "Allow", "reason": "", "details": {}}

        self.authorize = AsyncMock(side_effect=_authorize)
        self.publish_events = AsyncMock(return_value=True)


def _builtin_request() -> LlmRequest:
    req = LlmRequest()
    req.config = types.GenerateContentConfig(
        tools=[
            types.Tool(google_search=types.GoogleSearch()),
            types.Tool(code_execution=types.ToolCodeExecution()),
            types.Tool(
                function_declarations=[types.FunctionDeclaration(name="send_email")]
            ),
        ]
    )
    return req


def _builtin_plugin(apdp: _BuiltinApdp) -> WatchlightPlugin:
    plugin = _plugin(apdp)
    plugin._current_agent_id = "agent-uuid"
    plugin._current_execution_id = "exec_test"
    return plugin


@pytest.mark.asyncio
async def test_a_denied_builtin_tool_refuses_the_model_turn():
    apdp = _BuiltinApdp(deny_builtin=True)
    plugin = _builtin_plugin(apdp)
    result = await plugin.before_model_callback(
        callback_context=non_live_context(), llm_request=_builtin_request()
    )
    assert isinstance(result, LlmResponse)
    resources = [c["resource"] for c in apdp.calls]
    assert 'Tool::"google_search"' in resources


@pytest.mark.asyncio
async def test_allowed_builtin_tools_are_each_authorized_and_the_turn_proceeds():
    apdp = _BuiltinApdp(deny_builtin=False)
    plugin = _builtin_plugin(apdp)
    result = await plugin.before_model_callback(
        callback_context=non_live_context(), llm_request=_builtin_request()
    )
    assert result is None
    resources = [c["resource"] for c in apdp.calls]
    assert 'Tool::"google_search"' in resources
    assert 'Tool::"code_execution"' in resources
    # Function tools are authorized at their own before_tool_callback.
    assert 'Tool::"send_email"' not in resources
    builtin = [c for c in apdp.calls if c["resource"] == 'Tool::"google_search"'][0]
    assert builtin["context"]["builtin_tool"] is True
    assert builtin["run"] == plugin._current_run


# ── A root whose handle fails to build closes its session ─────


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "fault",
    [
        ImportError("watchlight_core unavailable"),
        ValueError("unparseable root run handle"),
    ],
)
async def test_a_root_handle_that_fails_to_build_closes_the_root_session(fault):
    """``create_session`` succeeded, then building the root handle raised.
    The run is refused and the session it opened is closed with its own
    run reference, never left open until it expires."""
    plugin = _session_plugin(None, connect_proxy_url=None)
    session = plugin.apdp.create_session.return_value
    with patch.object(plugin, "_build_root_handle_and_registry", side_effect=fault):
        with pytest.raises(GovernanceUnavailable):
            await plugin._open_session_and_manifest(_ctx())
    plugin.apdp.complete_session.assert_awaited_once()
    assert plugin.apdp.complete_session.call_args.args[0] == session.run
    assert plugin._session_id is None
    assert plugin._current_run is None
    assert plugin._root_handle is None
    assert plugin.last_governance_mode == "unavailable"


@pytest.mark.asyncio
async def test_a_root_handle_class_that_raises_closes_the_root_session():
    """The same, through the real builder: the handle constructor raises."""
    plugin = _session_plugin(None, connect_proxy_url=None)
    with patch("watchlight_core.BaseRunHandle", side_effect=RuntimeError("boom")):
        with pytest.raises(GovernanceUnavailable):
            await plugin._open_session_and_manifest(_ctx())
    plugin.apdp.complete_session.assert_awaited_once()
    assert plugin._session_id is None


class _DegradedDenyingApdp(_DeadlineAwareApdp):
    """No constraint manifest; model turns are allowed and every tool call
    is denied, so a tool that runs proves it was never authorized."""

    def __init__(self) -> None:
        super().__init__()
        self.get_manifest = AsyncMock(return_value=None)

        async def _authorize(*, resource: str, **_kw: Any) -> Dict[str, Any]:
            self.authorize_calls.append({"resource": resource, **_kw})
            if resource.startswith("Model::"):
                return {"decision": "Allow", "reason": "", "details": {}}
            return {"decision": "Deny", "reason": "denied by policy", "details": {}}

        self.authorize.side_effect = _authorize


@pytest.mark.asyncio
async def test_a_degraded_run_still_authorizes_every_tool_call(monkeypatch):
    """Degraded mode (no manifest, explicit opt-in) drops plan governance
    only: every tool call still goes to wl-apdp under the run, and a deny
    still blocks it. Degraded is never ungoverned."""
    monkeypatch.setenv("WATCHLIGHT_PLAN_GOVERNANCE_MODE", "degrade")
    EXECUTED.clear()
    apdp = _DegradedDenyingApdp()
    plugin = _plugin(apdp)
    turns: List[str] = []
    agent = _root(
        turns,
        [_call("send_email", {"to": "a@b.c", "api_key": SECRET}), _final("done")],
    )
    await _run(plugin, agent)
    assert plugin.last_governance_mode == "degraded"
    assert turns, "the degraded run did start"
    tool_calls = [c for c in apdp.authorize_calls if not c["resource"].startswith("Model::")]
    assert [c["resource"] for c in tool_calls] == ['Tool::"send_email"']
    assert tool_calls[0].get("run") is not None, "the decision is bound to the run"
    assert EXECUTED == []
