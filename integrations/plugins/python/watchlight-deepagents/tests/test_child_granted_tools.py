"""A sub-agent may call only the tools its spawn granted.

The plugin checks the child's granted ``allowed_tools`` before it asks the
backend, because the in-process engine (Developer Edition) does not check a
child's granted tools on each call. An empty grant is no tools at all."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from conftest import (
    RecordingHandler,
    make_child_middleware,
    make_root_middleware,
    make_tool_call_request,
    start_root,
)
from watchlight_deepagents.middleware import _within_granted_tools
from watchlight_deepagents.plugin import WatchlightDeepAgentsPlugin


async def _child_call(plugin, mock_apdp, scopes, tool_name):
    """Spawn ``researcher`` under ``scopes`` and make one child tool call.

    Returns the child's handler and the authorize calls the child made."""
    mock_apdp.default_decision = "Allow"
    root_mw = make_root_middleware(plugin, subagent_scopes=scopes)
    root_state = await start_root(root_mw)
    child_mw = make_child_middleware(plugin)
    handler = RecordingHandler()
    seen = {}

    async def _run_child(request):
        child_state = await child_mw.abefore_agent({}, runtime=None)
        before = len(mock_apdp.authorize_calls)
        seen["result"] = await child_mw.awrap_tool_call(
            make_tool_call_request(tool_name, state=child_state), handler
        )
        seen["authorized"] = mock_apdp.authorize_calls[before:]
        return "ok"

    await root_mw.awrap_tool_call(
        make_tool_call_request("task", {"subagent_type": "researcher"}, state=root_state),
        _run_child,
    )
    return handler, seen


async def test_a_child_calls_a_granted_tool(plugin, mock_apdp):
    handler, seen = await _child_call(
        plugin, mock_apdp, {"researcher": {"allowed_tools": ["search"]}}, "search"
    )
    assert handler.ran
    assert len(seen["authorized"]) == 1


async def test_a_child_is_refused_a_tool_it_was_not_granted(plugin, mock_apdp):
    handler, seen = await _child_call(
        plugin, mock_apdp, {"researcher": {"allowed_tools": ["search"]}}, "send_email"
    )
    assert not handler.ran
    assert seen["result"].status == "error"
    assert "not granted" in seen["result"].content
    # Refused before the backend is asked: no Allow can override it.
    assert seen["authorized"] == []


async def test_a_child_spawned_with_no_scope_may_call_no_tool(plugin, mock_apdp):
    handler, seen = await _child_call(plugin, mock_apdp, {}, "search")
    assert not handler.ran
    assert seen["authorized"] == []


@pytest.mark.parametrize(
    "handle, allowed",
    [
        # A root run: no granted scope, decided by policy alone.
        (SimpleNamespace(granted_scope=None, spawned_execution_id=None), True),
        # A spawned handle whose scope cannot be read is refused.
        (SimpleNamespace(granted_scope=None, spawned_execution_id="exec_1"), False),
        (SimpleNamespace(granted_scope=SimpleNamespace(allowed_tools=None)), False),
        (SimpleNamespace(granted_scope=SimpleNamespace(allowed_tools=[])), False),
        # The tool name or the resource may be granted. The action is a
        # generic verb and never grants a tool: a grant naming a tool called
        # ``read`` or ``execute`` does not pass every call made with it.
        (SimpleNamespace(granted_scope=SimpleNamespace(allowed_tools=["search_web"])), True),
        (SimpleNamespace(granted_scope=SimpleNamespace(allowed_tools=["read"])), False),
        (SimpleNamespace(granted_scope=SimpleNamespace(allowed_tools=["execute"])), False),
        (
            SimpleNamespace(
                granted_scope=SimpleNamespace(allowed_tools=["deepagents://tool/search_web"])
            ),
            True,
        ),
        (SimpleNamespace(granted_scope=SimpleNamespace(allowed_tools=["send_email"])), False),
    ],
)
def test_granted_tools_match(handle, allowed):
    assert (
        _within_granted_tools(handle, "search_web", "read", "deepagents://tool/search_web")
        is allowed
    )


def test_a_governance_backend_is_used_as_given():
    backend = object()
    plugin = WatchlightDeepAgentsPlugin(governance=backend)
    assert plugin.apdp is backend


def test_an_execute_named_grant_passes_only_the_execute_tool():
    # DeepAgents' sandbox shell tool is literally named ``execute``.
    handle = SimpleNamespace(granted_scope=SimpleNamespace(allowed_tools=["execute"]))
    assert _within_granted_tools(handle, "execute", "execute", "deepagents://tool/execute")
    assert not _within_granted_tools(
        handle, "transfer_funds", "execute", "deepagents://tool/transfer_funds"
    )
