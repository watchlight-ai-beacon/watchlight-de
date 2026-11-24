"""Every Claude Code tool the plugin knows, by how it is governed.

The list is checked against Claude Code :data:`CLASSIFIED_CLI_VERSION`
(the CLI bundled with the locked ``claude-agent-sdk``). It is the shared
fixture ``watchlight-core/tests/fixtures/claude_code_tool_classes.json``,
the same list the TypeScript plugin uses; a test keeps the two equal. A
tool the list does not name is refused before any decision: a new CLI
tool may start work these hooks never see, so it runs only once it has
been reviewed and classified here.

* ``governed``: decided by Watchlight policy at ``PreToolUse``.
* ``spawn``: starts a local sub-agent; governed as a spawn before the
  child starts.
* ``refused``: starts work outside this process's hooks; refused before
  any decision, whatever the policy says, and never offered to the model.

MCP tools (``mcp__<server>__<tool>``) are the caller's own tools, run in
this process through its MCP servers: ``governed``.
"""

from __future__ import annotations

import re
from types import MappingProxyType
from typing import Any, List, Mapping, Optional

#: The Claude Code release this list is checked against.
CLASSIFIED_CLI_VERSION = "2.1.310"

#: Why a refused tool was refused, recorded value-free in lineage.
REMOTE_DISPATCH_REFUSED = "remote_dispatch_refused"
UNCLASSIFIED_TOOL = "unclassified_tool"
UNKNOWN_ISOLATION = "unknown_isolation"

#: The ``isolation`` values of a sub-agent launch that run the sub-agent in
#: this process, under these hooks. Any other value is refused: ``remote``
#: runs it on Anthropic's cloud, and a value this list does not name may
#: too.
LOCAL_ISOLATION = frozenset({"worktree"})

TOOL_CLASSES: Mapping[str, str] = MappingProxyType(
    {
        # Local sub-agents (older releases name the tool ``Task``).
        "Agent": "spawn",
        "Task": "spawn",
        # Starts, runs or schedules a Claude Code session on Anthropic's cloud.
        "RemoteTrigger": "refused",
        "AskUserQuestion": "governed",
        "Bash": "governed",
        "CronCreate": "governed",
        "CronDelete": "governed",
        "CronList": "governed",
        "Edit": "governed",
        "EnterPlanMode": "governed",
        "EnterWorktree": "governed",
        "ExitPlanMode": "governed",
        "ExitWorktree": "governed",
        "Glob": "governed",
        "Grep": "governed",
        "ListAgents": "governed",
        "ListMcpResourcesTool": "governed",
        "Monitor": "governed",
        "NotebookEdit": "governed",
        "PushNotification": "governed",
        "Read": "governed",
        "ReadMcpResourceDirTool": "governed",
        "ReadMcpResourceTool": "governed",
        "ReportFindings": "governed",
        "ScheduleWakeup": "governed",
        "SendMessage": "governed",
        "Skill": "governed",
        "TaskCreate": "governed",
        "TaskGet": "governed",
        "TaskList": "governed",
        "TaskStop": "governed",
        "TaskUpdate": "governed",
        "TodoWrite": "governed",
        "ToolSearch": "governed",
        "WebFetch": "governed",
        "WebSearch": "governed",
        # Runs in this process: a workflow's agents fire SubagentStart and
        # their tool calls reach these hooks, which deny every call of an
        # agent the spawn gate did not start (probe). The CLI
        # compiles out remote workflows (``remote``), checked by a test.
        "Workflow": "governed",
        "Write": "governed",
    }
)

#: Tools never offered to the model (``disallowed_tools``).
NEVER_OFFERED_TOOLS = tuple(name for name, cls in TOOL_CLASSES.items() if cls == "refused")

# The TypeScript pattern ``/^mcp__.+__.+$/``: its ``.`` matches no line
# terminator, so neither does this one.
_ANY = r"[^\n\r\u2028\u2029]"
_MCP_TOOL = re.compile(rf"mcp__{_ANY}+__{_ANY}+")


def classify_tool(tool_name: str) -> Optional[str]:
    """How ``tool_name`` is governed, or ``None`` for a tool the list does not name."""
    cls = TOOL_CLASSES.get(tool_name)
    if cls is not None:
        return cls
    return "governed" if _MCP_TOOL.fullmatch(tool_name) else None


def isolation_refusal(tool_input: Any) -> Optional[str]:
    """Why a sub-agent launch with this input is refused for its
    ``isolation``, or ``None`` when it has none or a local one. Fails
    closed: a value that is not a listed string (including ``None``) is
    refused."""
    if not isinstance(tool_input, dict) or "isolation" not in tool_input:
        return None
    value = tool_input["isolation"]
    if isinstance(value, str) and value in LOCAL_ISOLATION:
        return None
    return REMOTE_DISPATCH_REFUSED if value == "remote" else UNKNOWN_ISOLATION


def with_never_offered_tools(host: Any) -> List[str]:
    """The host's ``disallowed_tools`` plus :data:`NEVER_OFFERED_TOOLS`.

    A host value that is not a list is replaced: the refused tools are
    never offered either way."""
    out = [t for t in host if isinstance(t, str)] if isinstance(host, (list, tuple)) else []
    for name in NEVER_OFFERED_TOOLS:
        if name not in out:
            out.append(name)
    return out
