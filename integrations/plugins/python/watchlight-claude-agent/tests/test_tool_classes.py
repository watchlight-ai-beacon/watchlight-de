"""Tools that start work outside these hooks, and unclassified
tools, are refused before any decision.

The classification is pinned to the Claude Code release the locked
``claude-agent-sdk`` bundles, and kept equal to the shared fixture the
TypeScript plugin uses.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from watchlight_claude_agent import tool_classes
from watchlight_claude_agent.tool_classes import (
    CLASSIFIED_CLI_VERSION,
    NEVER_OFFERED_TOOLS,
    TOOL_CLASSES,
    LOCAL_ISOLATION,
    classify_tool,
    isolation_refusal,
    with_never_offered_tools,
)

from .test_governance_hooks import CHILD_SLUG, _denied, _fire, _plugin, _root, _task, _tool

FIXTURE = (
    Path(__file__).resolve().parents[2]
    / "watchlight-core"
    / "tests"
    / "fixtures"
    / "claude_code_tool_classes.json"
)

#: The tools Claude Code 2.1.310 reports at ``system/init`` with a stored
#: claude.ai login (with an API key it is the same list without
#: ``RemoteTrigger``).
CLI_2_1_310_TOOLS = [
    "Task", "Bash", "CronCreate", "CronDelete", "CronList", "Edit", "EnterWorktree",
    "ExitWorktree", "ListAgents", "Monitor", "NotebookEdit", "Read", "RemoteTrigger",
    "ReportFindings", "ScheduleWakeup", "SendMessage", "Skill", "TaskCreate", "TaskGet",
    "TaskList", "TaskStop", "TaskUpdate", "ToolSearch", "WebFetch", "WebSearch",
    "Workflow", "Write",
]


def _refusals(apdp):
    return [
        (e["payload"].get("decision"), e["metadata"].get("refusal_reason"), e["payload"]["tool"]["identifier"])
        for e in apdp.published_events
        if e.get("event_type") == "tool_call_observed" and (e.get("metadata") or {}).get("refusal_reason")
    ]


# ── the pin ──────────────────────────────────────────────────────────


def test_checked_against_the_cli_the_locked_sdk_bundles():
    from claude_agent_sdk._cli_version import __cli_version__

    assert __cli_version__ == CLASSIFIED_CLI_VERSION


def test_equal_to_the_shared_fixture():
    fixture = json.loads(FIXTURE.read_text())
    assert dict(TOOL_CLASSES) == fixture["tools"]
    assert fixture["classified_cli_versions"]["python"] == CLASSIFIED_CLI_VERSION
    assert fixture["refusal_reasons"] == {
        "refused": tool_classes.REMOTE_DISPATCH_REFUSED,
        "unclassified": tool_classes.UNCLASSIFIED_TOOL,
        "unknown_isolation": tool_classes.UNKNOWN_ISOLATION,
    }
    assert sorted(LOCAL_ISOLATION) == fixture["local_isolation"]


def test_every_tool_the_cli_reports_is_classified():
    assert [t for t in CLI_2_1_310_TOOLS if classify_tool(t) is None] == []
    assert classify_tool("RemoteTrigger") == "refused"
    assert classify_tool("Agent") == classify_tool("Task") == "spawn"


@pytest.mark.parametrize(
    "name",
    ["NewCloudTool", "watchlight.declare_intent", "mcp__tools", "mcp__a\n__b", "mcp__a\r__b", "__class__", ""],
)
def test_names_it_does_not_list_are_unclassified(name):
    assert classify_tool(name) is None


def test_mcp_tools_are_governed():
    assert classify_tool("mcp__tools__fetch") == "governed"


def test_refused_tools_are_never_offered_and_the_host_list_is_kept():
    assert NEVER_OFFERED_TOOLS == ("RemoteTrigger",)
    assert with_never_offered_tools(None) == ["RemoteTrigger"]
    assert with_never_offered_tools(["Bash"]) == ["Bash", "RemoteTrigger"]
    assert with_never_offered_tools(["RemoteTrigger", "Bash"]) == ["RemoteTrigger", "Bash"]
    assert with_never_offered_tools("Bash") == ["RemoteTrigger"]


@pytest.mark.asyncio
async def test_governed_options_never_offer_the_refused_tools():
    plugin, _ = _plugin()
    root = await _root(plugin)
    opts = plugin.governed_options(root, {"disallowed_tools": ["WebFetch"]})
    assert opts["disallowed_tools"] == ["WebFetch", "RemoteTrigger"]
    assert plugin.governed_options(root, {})["disallowed_tools"] == ["RemoteTrigger"]


# ── the gate ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
@pytest.mark.parametrize("action", ["run", "create", "update", "list"])
async def test_remote_trigger_is_refused_before_any_decision(action):
    plugin, apdp = _plugin()
    root = await _root(plugin)
    hooks = plugin.governance_hooks(root)
    out = await _fire(hooks, "PreToolUse", _tool("RemoteTrigger", {"action": action}), "t")
    assert _denied(out)
    assert "remote sessions" in out[0]["hookSpecificOutput"]["permissionDecisionReason"]
    assert apdp.authorize_calls == []
    assert _refusals(apdp) == [("Deny", "remote_dispatch_refused", "RemoteTrigger")]


@pytest.mark.asyncio
async def test_an_unclassified_tool_is_refused_before_any_decision():
    plugin, apdp = _plugin()
    root = await _root(plugin)
    hooks = plugin.governance_hooks(root)
    out = await _fire(hooks, "PreToolUse", _tool("SomeNewCloudTool", {"x": 1}), "t")
    assert _denied(out)
    assert "has not classified" in out[0]["hookSpecificOutput"]["permissionDecisionReason"]
    assert apdp.authorize_calls == []
    assert _refusals(apdp) == [("Deny", "unclassified_tool", "SomeNewCloudTool")]


@pytest.mark.asyncio
async def test_an_mcp_tool_still_goes_to_the_decision():
    plugin, apdp = _plugin()
    root = await _root(plugin)
    hooks = plugin.governance_hooks(root)
    out = await _fire(hooks, "PreToolUse", _tool("mcp__tools__lookup", {"q": "x"}), "t")
    assert not _denied(out)
    assert [c["resource"] for c in apdp.authorize_calls] == ['Resource::"mcp__tools__lookup"']
    assert _refusals(apdp) == []


@pytest.mark.asyncio
@pytest.mark.parametrize("tool_name", ["Task", "Agent"])
async def test_a_remote_sub_agent_is_refused_before_any_decision(tool_name):
    plugin, apdp = _plugin()
    root = await _root(plugin)
    hooks = plugin.governance_hooks(root)
    data = _task(tool_name=tool_name)
    data["tool_input"]["isolation"] = "remote"
    out = await _fire(hooks, "PreToolUse", data, "toolu_r")
    assert _denied(out)
    assert apdp.authorize_calls == []
    assert _refusals(apdp) == [("Deny", "remote_dispatch_refused", tool_name)]
    # A local launch still goes to the spawn gate.
    out = await _fire(hooks, "PreToolUse", _task(tool_name=tool_name), "toolu_l")
    assert not _denied(out)


@pytest.mark.parametrize(
    "tool_input, expected",
    [
        ({}, None),
        ({"isolation": "worktree"}, None),
        ({"isolation": "remote"}, "remote_dispatch_refused"),
        ({"isolation": "cloud"}, "unknown_isolation"),
        ({"isolation": "Worktree"}, "unknown_isolation"),
        ({"isolation": None}, "unknown_isolation"),
        ({"isolation": ["worktree"]}, "unknown_isolation"),
        ({"isolation": ""}, "unknown_isolation"),
    ],
)
def test_isolation_is_an_allowlist(tool_input, expected):
    assert isolation_refusal(tool_input) == expected


@pytest.mark.asyncio
@pytest.mark.parametrize("value", ["cloud", None])
async def test_an_unknown_isolation_is_refused_before_any_decision(value):
    plugin, apdp = _plugin()
    root = await _root(plugin)
    hooks = plugin.governance_hooks(root)
    data = _task(tool_name="Agent")
    data["tool_input"]["isolation"] = value
    out = await _fire(hooks, "PreToolUse", data, "toolu_u")
    assert _denied(out)
    assert apdp.authorize_calls == []
    assert _refusals(apdp) == [("Deny", "unknown_isolation", "Agent")]
    data["tool_input"]["isolation"] = "worktree"
    assert not _denied(await _fire(hooks, "PreToolUse", data, "toolu_w"))


@pytest.mark.asyncio
async def test_remote_trigger_from_a_sub_agent_is_refused_and_recorded_on_the_child():
    plugin, apdp = _plugin()
    root = await _root(plugin)
    hooks = plugin.governance_hooks(root)
    assert not _denied(await _fire(hooks, "PreToolUse", _task(), "toolu_1"))
    await _fire(
        hooks,
        "SubagentStart",
        {"hook_event_name": "SubagentStart", "agent_id": "a1", "agent_type": CHILD_SLUG},
    )
    child = plugin.resolve_subagent(root, "a1")
    assert child is not None and child is not root
    child._aentered = True
    before = len(apdp.authorize_calls)
    out = await _fire(hooks, "PreToolUse", _tool("RemoteTrigger", {"action": "run"}, agent_id="a1"), "toolu_2")
    assert _denied(out)
    assert len(apdp.authorize_calls) == before
    refused = [
        e for e in apdp.published_events if (e.get("metadata") or {}).get("refusal_reason") == "remote_dispatch_refused"
    ]
    assert len(refused) == 1
    assert refused[0]["execution_id"] == child.execution_id


@pytest.mark.asyncio
async def test_the_refusal_stands_when_the_record_cannot_be_sent():
    plugin, apdp = _plugin()
    root = await _root(plugin)
    hooks = plugin.governance_hooks(root)

    async def broken(*_a, **_k):
        raise RuntimeError("events endpoint down")

    root.publish_observation = broken  # type: ignore[method-assign]
    out = await _fire(hooks, "PreToolUse", _tool("RemoteTrigger", {"action": "run"}), "t")
    assert _denied(out)
    assert apdp.authorize_calls == []
