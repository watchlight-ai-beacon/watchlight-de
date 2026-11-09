"""The fail-closed matrix (proposal §5): missing config, unregistered
agent, APDP unreachable, no-handle tool call, and the synchronous
invocation path all refuse rather than run ungoverned."""

from __future__ import annotations

import pytest

from watchlight_core import AgentNotRegistered, GovernanceUnavailable

from conftest import (
    RecordingHandler,
    make_root_middleware,
    make_tool_call_request,
)
from watchlight_deepagents.plugin import WatchlightDeepAgentsPlugin


def test_from_env_fails_loud_without_apdp_url(monkeypatch):
    monkeypatch.delenv("WATCHLIGHT_APDP_URL", raising=False)
    with pytest.raises(GovernanceUnavailable):
        WatchlightDeepAgentsPlugin.from_env()


async def test_start_run_unregistered_agent_refuses(plugin, mock_apdp):
    mock_apdp.known_agents.clear()  # nothing registered
    mw = make_root_middleware(plugin)
    with pytest.raises(AgentNotRegistered):
        await mw.abefore_agent({}, runtime=None)


async def test_apdp_unreachable_at_start_refuses(plugin, mock_apdp):
    async def _no_session(*a, **k):
        return None

    mock_apdp.create_session = _no_session  # type: ignore[assignment]
    mw = make_root_middleware(plugin)
    with pytest.raises(GovernanceUnavailable):
        await mw.abefore_agent({}, runtime=None)


async def test_tool_call_without_handle_denies(plugin, mock_apdp):
    from langchain_core.messages import ToolMessage
    from watchlight_deepagents.middleware import _ACTIVE_HANDLE

    _ACTIVE_HANDLE.set(None)  # ensure no fallback handle in context
    mw = make_root_middleware(plugin)

    handler = RecordingHandler()
    # State carries NO run token → no handle resolvable.
    req = make_tool_call_request("search", state={})
    result = await mw.awrap_tool_call(req, handler)

    assert handler.ran is False
    assert isinstance(result, ToolMessage)
    assert result.status == "error"


def test_sync_hooks_fail_closed(plugin):
    mw = make_root_middleware(plugin)
    for call in (
        lambda: mw.before_agent({}, None),
        lambda: mw.wrap_tool_call(object(), None),
        lambda: mw.wrap_model_call(object(), None),
    ):
        with pytest.raises(GovernanceUnavailable):
            call()
