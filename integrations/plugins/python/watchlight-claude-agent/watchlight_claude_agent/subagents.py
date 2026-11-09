"""Governed sub-agent routing for the Claude Agent SDK plugin.

The Claude Agent SDK exposes a *native* sub-agent primitive: the
``Task`` tool spawns a nested agent loop that re-enters
``UserPromptSubmit`` / ``PreToolUse`` / ``SubagentStop`` at a deeper
``depth``. Before this module, those Task sub-agents ran UN-attenuated
— their tool calls authorized under the ROOT run handle (a privilege
escalation: a sub-agent must never inherit the root's authority) and
their spawn was never server-attested.

This module wires the SDK's ``SubagentStart`` / ``PreToolUse`` /
``SubagentStop`` captures through the governed ``spawn_subagent``
chokepoint using the shared :class:`watchlight_core.SubagentRegistry`
primitive. On ``SubagentStart`` the spawn routes through the
direct parent's handle so wl-apdp attests the spawn (server-emitted
``agent_spawn_observed`` + strict-subset scope attenuation) and mints a
per-child ``sst_`` credential; on
``PreToolUse`` the child's tool call authorizes under the CHILD handle
(its own ``run_handle_id`` + per-child credential), never the root's;
on ``SubagentStop`` the child handle is closed.

The plugin (:mod:`watchlight_claude_agent.plugin`) owns the async
orchestration (it needs the APDP client to resolve the sub-agent's
principal + the tenant id + loud logging). This module holds the pure,
side-effect-free capture-parsing helpers so they are unit-testable in
isolation.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

__all__ = [
    "subagent_id_from_capture",
    "subagent_slug_from_capture",
    "parent_key_from_capture",
    "derive_requested_scope",
]

# The Claude Agent SDK's ``SubagentStart`` hook does not commit to a
# single spelling for the child id / agent type / parent id across
# releases, and a customer's own hook-capture shim may relay either the
# snake_case wire field or a camelCase copy. We tolerate the known
# spellings on the READ path only — nothing here is trusted for
# authority (the resolved principal is validated + resolved against the
# registry, and the server attests the spawn).
_SUBAGENT_ID_KEYS = ("subagent_id", "agent_id", "subagentId", "agentId")
_SUBAGENT_SLUG_KEYS = (
    "agent_type",
    "subagent_type",
    "agent_slug",
    "subagent_slug",
    "agentType",
    "subagentType",
)
_PARENT_KEY_KEYS = (
    "parent_subagent_id",
    "parent_agent_id",
    "parentSubagentId",
    "parentAgentId",
)

# The Task tool's per-spawn tool restriction. When the SDK (or the
# customer's capture shim) surfaces it, it is the authoritative
# per-spawn requested scope; the server still strict-subsets it against
# the parent's granted scope.
_ALLOWED_TOOLS_KEYS = ("allowed_tools", "allowed-tools", "allowedTools")


def _first_str(capture: Dict[str, Any], keys: tuple) -> Optional[str]:
    """Return the first non-empty string value among ``keys``."""
    for key in keys:
        value = capture.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def subagent_id_from_capture(capture: Dict[str, Any]) -> Optional[str]:
    """Extract the SDK's opaque sub-agent id — the ``child_key`` the
    registry uses to resolve the child handle on later ``PreToolUse`` /
    ``SubagentStop`` captures. ``None`` when the capture surfaces none
    (the spawn cannot be governed → the caller fails closed)."""
    if not isinstance(capture, dict):
        return None
    return _first_str(capture, _SUBAGENT_ID_KEYS)


def subagent_slug_from_capture(capture: Dict[str, Any]) -> Optional[str]:
    """Extract the sub-agent's agent-type / slug — the child principal
    resolved to a registered agent UUID before the governed spawn.
    ``None`` when absent (the caller falls back to the sub-agent id)."""
    if not isinstance(capture, dict):
        return None
    return _first_str(capture, _SUBAGENT_SLUG_KEYS)


def parent_key_from_capture(capture: Dict[str, Any]) -> Optional[str]:
    """Extract the spawning agent's id when the capture surfaces it —
    the EXPLICIT ``parent_key`` the registry needs for a correct
    depth-≥2 parent attribution.

    Framework wirings SHOULD pass an explicit ``parent_key`` (the
    registry fails closed on an unknown/denied explicit parent). When
    the SDK does not surface the spawner, ``None`` lets the registry
    fall back to its best-effort stack-top → root ladder."""
    if not isinstance(capture, dict):
        return None
    return _first_str(capture, _PARENT_KEY_KEYS)


def _coerce_tool_list(value: Any) -> Optional[List[str]]:
    """Coerce a surfaced ``allowed-tools`` value into a list of tool
    name strings. Returns ``None`` when the value is absent/unusable so
    the caller can distinguish "no per-spawn scope surfaced" (fall back
    to the operator default) from "an explicit empty list" (a
    deliberate zero-tool child)."""
    if value is None:
        return None
    if isinstance(value, str):
        # A single tool name, or a comma-separated list.
        parts = [p.strip() for p in value.split(",")]
        return [p for p in parts if p]
    if isinstance(value, (list, tuple, set)):
        return [str(v).strip() for v in value if str(v).strip()]
    return None


def _extract_allowed_tools(capture: Dict[str, Any]) -> Optional[List[str]]:
    """Find the Task tool's ``allowed-tools`` on the capture — at the
    top level OR nested under the Task tool's ``tool_input`` — tolerating
    the known key spellings. ``None`` when no key is present."""
    for key in _ALLOWED_TOOLS_KEYS:
        if key in capture:
            coerced = _coerce_tool_list(capture.get(key))
            if coerced is not None:
                return coerced
    tool_input = capture.get("tool_input")
    if isinstance(tool_input, dict):
        for key in _ALLOWED_TOOLS_KEYS:
            if key in tool_input:
                coerced = _coerce_tool_list(tool_input.get(key))
                if coerced is not None:
                    return coerced
    return None


def derive_requested_scope(
    capture: Dict[str, Any],
) -> Optional[Dict[str, Any]]:
    """Derive the per-spawn requested scope from a ``SubagentStart``
    capture (locked decision).

    * When the capture surfaces the Task tool's ``allowed-tools``, the
      requested scope is ``{"allowed_tools": [...]}`` — the exact tool
      set the Task was launched with. The server strict-subsets it
      against the parent's granted scope, so this can only NARROW
      authority, never widen it. An explicit empty ``allowed-tools``
      yields ``{"allowed_tools": []}`` (a deliberate zero-tool child).
    * When no ``allowed-tools`` is surfaced, returns ``None`` so the
      caller falls back to the operator ``default_subagent_scope`` knob
      (which defaults to EMPTY → fail-closed: the child's first tool
      call is denied until an operator scopes it).

    The parent's scope is NEVER inherited unchanged — the two branches
    above are the only two sources of a child's requested scope."""
    if not isinstance(capture, dict):
        return None
    tools = _extract_allowed_tools(capture)
    if tools is None:
        return None
    return {"allowed_tools": tools}


#: Task tool input keys that carry the task the parent hands the child, in
#: precedence order: the short description first, then the full prompt.
_TASK_OBJECTIVE_KEYS = ("description", "prompt")


def task_objective_from_tool_input(tool_input: Any) -> Optional[str]:
    """The objective a ``Task``/``Agent`` tool call gives its sub-agent:
    its ``description``, else its ``prompt``. ``None`` when neither is a
    non-blank string. The value is bounded and cleaned by
    :func:`watchlight_core.plugin_child_intent` before it is sent."""
    if not isinstance(tool_input, dict):
        return None
    for key in _TASK_OBJECTIVE_KEYS:
        value = tool_input.get(key)
        if isinstance(value, str) and value.strip():
            return value
    return None


def task_objective_from_capture(capture: Dict[str, Any]) -> Optional[str]:
    """The objective a ``SubagentStart`` capture carries: the Task tool's
    description or prompt, at the top level or under ``tool_input``."""
    if not isinstance(capture, dict):
        return None
    return task_objective_from_tool_input(capture.get("tool_input")) or (
        task_objective_from_tool_input(capture)
    )
