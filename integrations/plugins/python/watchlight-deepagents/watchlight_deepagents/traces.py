"""Resource-URI namespacing + action-verb resolution for deepagents.

Conformance invariant #4 requires tool URIs to start with the framework
scheme ``deepagents://``. The deepagents virtual-filesystem tools, the
customer tools, and the ``task`` sub-agent tool each get a stable,
namespaced resource identity:

- ``deepagents://fs/<path>``      — virtual-filesystem tools
  (``read_file`` / ``write_file`` / ``edit_file`` / ``ls`` / search).
- ``deepagents://task/<type>``    — the ``task`` sub-agent spawn tool.
- ``deepagents://tool/<name>``    — every other (customer / planning) tool.

The action verb is resolved from the tool name by convention
(``read_*`` → ``read``, ``write_*``/``edit_*`` → ``write``, …) with a
fail-safe ``execute`` default — matching the ADK reference's
convention-based ``resolve_action``.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

# Shared with the other plugins; re-exported here.
from watchlight_core import redacted_arg_metadata

#: deepagents virtual-filesystem tool names (FilesystemMiddleware).
_FS_TOOLS = frozenset({"ls", "read_file", "write_file", "edit_file", "glob", "grep"})

#: Cap on the number of argument-name entries surfaced in the redacted
#: metadata, so a tool with a pathological arg count can't blow the
#: bounded-size conformance budget.
_MAX_ARG_NAMES = 32


def resolve_action_verb(tool_name: Optional[str]) -> str:
    """Resolve a Cedar action verb from a deepagents tool name.

    Convention-based with a fail-safe ``execute`` default so an
    unrecognised tool is still governed (never silently un-verbed).
    """
    name = (tool_name or "").lower()
    if name in ("ls", "glob", "grep") or name.startswith(
        ("read", "get", "list", "search", "find")
    ):
        return "read"
    if name.startswith(("write", "edit", "create", "update", "delete", "put")):
        return "write"
    return "execute"


def tool_resource_uri(tool_name: Optional[str], tool_args: Dict[str, Any]) -> str:
    """Build the namespaced ``deepagents://`` resource URI for a tool.

    Virtual-filesystem tools carry their path (governance-relevant — a
    path-scoped Cedar policy must see it); we do NOT normalise the path
    away. Other tools namespace on the tool name.
    """
    name = tool_name or "unknown"
    if name in _FS_TOOLS:
        path = ""
        if isinstance(tool_args, dict):
            path = (
                tool_args.get("file_path")
                or tool_args.get("path")
                or tool_args.get("pattern")
                or ""
            )
        return f"deepagents://fs/{path}" if path else f"deepagents://fs/{name}"
    return f"deepagents://tool/{name}"


def task_resource_uri(subagent_type: str) -> str:
    """Namespaced URI for a ``task`` sub-agent spawn."""
    return f"deepagents://task/{subagent_type}"


def redacted_input_summary(tool_args: Any) -> str:
    """Build a bounded, **value-free** ``input_summary`` for the
    ``tool_call_observed`` event.

    Renders ``"<n> args: name(type), name(type), …"`` — argument key
    names and value types only, never a value. Bounded via
    ``watchlight_core.truncate_summary`` (120-char conformance cap).
    """
    from watchlight_core import truncate_summary

    if isinstance(tool_args, dict):
        n = len(tool_args)
        parts = [
            f"{k}({type(v).__name__})"
            for k, v in list(tool_args.items())[:_MAX_ARG_NAMES]
        ]
        summary = f"{n} args: " + ", ".join(parts) if parts else "0 args"
    else:
        summary = f"1 arg: ({type(tool_args).__name__})"
    return truncate_summary(summary) or summary[:120]


__all__ = [
    "resolve_action_verb",
    "tool_resource_uri",
    "task_resource_uri",
    "redacted_arg_metadata",
    "redacted_input_summary",
]
