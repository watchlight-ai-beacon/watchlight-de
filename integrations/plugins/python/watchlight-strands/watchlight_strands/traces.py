"""Strands hook captures → canonical ``ExecutionEvent`` shapes.

Pure functions, no I/O. The plugin builds every lineage payload it emits
with the helpers here, and :func:`translate_strands_event` wraps the same
payloads in the canonical envelope for callers (and the conformance
runner) that translate captured hook data themselves.

Nothing here ever renders an argument VALUE. Tool arguments can carry
bearer tokens, API keys or personal data, and truncating a value is not
redaction. The helpers describe only the shape of the arguments: their
names, their count and the type of each value.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Mapping, Optional

from watchlight_core import EventType, summarize_arg_keys, truncate_summary

logger = logging.getLogger("watchlight_strands.traces")

__all__ = [
    "SOURCE_TAG",
    "URI_SCHEME",
    "build_tool_call_payload",
    "redacted_arg_metadata",
    "redacted_input_summary",
    "tool_resource_uri",
    "translate_strands_event",
    "translate_strands_events",
]

#: ``metadata.source`` of the events this plugin emits through its own
#: translator (conformance invariant 2). The run handle's own events carry
#: ``strands.workload`` and ``strands.run_handle_*``; every tag starts with
#: the framework tag ``strands``.
SOURCE_TAG: str = "strands.hook"

#: Resource URI scheme of tool references (conformance invariant 4).
URI_SCHEME: str = "strands"

#: Cap on the argument names surfaced in the redacted metadata, so a tool
#: with a pathological argument count stays inside the bounded sizes.
_MAX_ARG_NAMES = 32


def tool_resource_uri(tool_name: str, tool_type: Optional[str] = None) -> str:
    """The namespaced ``strands://`` URI for a tool on a lineage event.

    An agent used as a tool and an MCP tool get their own path segment, so
    a lineage query can tell them from a Python function tool.
    """
    kind = "tool"
    if tool_type == "agent":
        kind = "agent"
    elif tool_type == "mcp":
        kind = "mcp"
    return f"{URI_SCHEME}://{kind}/{tool_name or 'unknown'}"


def redacted_arg_metadata(tool_args: Any) -> Dict[str, Any]:
    """Value-free metadata of a tool call's arguments.

    A mapping surfaces its key names (sorted, at most 32), the count and
    each value's type name. Anything else surfaces only its type and a
    count of one. No value is ever rendered, so the result is safe to send
    to wl-apdp as authorize context and to put on a lineage event.
    """
    if isinstance(tool_args, Mapping):
        names: List[str] = [str(k) for k in tool_args]
        meta: Dict[str, Any] = {
            "arg_count": len(names),
            "arg_names": sorted(names)[:_MAX_ARG_NAMES],
            "arg_types": {
                str(k): type(v).__name__
                for k, v in list(tool_args.items())[:_MAX_ARG_NAMES]
            },
        }
        if len(names) > _MAX_ARG_NAMES:
            meta["arg_names_truncated"] = True
        return meta
    if tool_args is None:
        return {"arg_count": 0, "arg_names": []}
    return {"arg_count": 1, "arg_names": [], "arg_type": type(tool_args).__name__}


def redacted_input_summary(tool_args: Any) -> str:
    """A bounded, value-free one-line summary of a tool call's arguments:
    ``"<n> args: name(type), ..."``, at most 120 characters."""
    if isinstance(tool_args, Mapping):
        parts = [
            f"{k}({type(v).__name__})"
            for k, v in list(tool_args.items())[:_MAX_ARG_NAMES]
        ]
        summary = f"{len(tool_args)} args: " + ", ".join(parts) if parts else "0 args"
    elif tool_args is None:
        summary = "0 args"
    else:
        summary = f"1 arg: ({type(tool_args).__name__})"
    return truncate_summary(summary) or summary[:120]


def build_tool_call_payload(
    *,
    tool_name: str,
    tool_type: Optional[str],
    tool_args: Any,
    action: str,
    decision: str,
    duration_ms: Optional[int] = None,
) -> Dict[str, Any]:
    """The canonical ``tool_call_observed`` payload for one Strands tool call.

    ``decision`` is ``"Allow"`` or ``"Deny"``: what Watchlight decided for
    the call, not whether the tool body succeeded.
    """
    payload: Dict[str, Any] = {
        "tool": {
            "resource_type": "tool",
            "identifier": tool_name or "unknown",
            "endpoint": tool_resource_uri(tool_name, tool_type),
        },
        "action": {"action": action},
        "decision": decision,
        "input_summary": redacted_input_summary(tool_args),
    }
    arg_keys = summarize_arg_keys(tool_args)
    if arg_keys:
        payload["arg_key_summary"] = arg_keys
    if duration_ms is not None:
        payload["duration_ms"] = max(0, int(duration_ms))
    return payload


# ─── Translator ─────────────────────────────────────────────────────────


def translate_strands_event(
    hook_dict: Dict[str, Any],
    *,
    execution_id: str,
    agent_id: str,
    session_id: Optional[str] = None,
    tenant_id: Optional[str] = None,
    parent_execution_id: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """Map one captured Strands hook to one canonical event, or ``None``.

    Recognised ``hook`` values:

    * ``"after_tool_call"`` / ``"before_tool_call"``: a ``tool_call_observed``
      event. Keys: ``tool_name``, ``tool_type``, ``input`` (the tool-use
      input mapping; only its shape is used), ``decision`` (default
      ``"Allow"``), ``duration_ms``.
    * ``"before_invocation"``: an ``execution_started`` event. Key:
      ``depth`` (default 0).

    Anything else returns ``None``.
    """
    hook = hook_dict.get("hook")
    if hook in ("after_tool_call", "before_tool_call"):
        envelope = _envelope(
            EventType.TOOL_CALL_OBSERVED,
            execution_id=execution_id,
            agent_id=agent_id,
            session_id=session_id,
            tenant_id=tenant_id,
            parent_execution_id=parent_execution_id,
        )
        envelope["payload"] = build_tool_call_payload(
            tool_name=str(hook_dict.get("tool_name") or "unknown"),
            tool_type=hook_dict.get("tool_type"),
            tool_args=hook_dict.get("input"),
            action=str(hook_dict.get("action") or "execute"),
            decision=str(hook_dict.get("decision") or "Allow"),
            duration_ms=hook_dict.get("duration_ms"),
        )
        return envelope
    if hook == "before_invocation":
        envelope = _envelope(
            EventType.EXECUTION_STARTED,
            execution_id=execution_id,
            agent_id=agent_id,
            session_id=session_id,
            tenant_id=tenant_id,
            parent_execution_id=parent_execution_id,
        )
        envelope["payload"] = {
            "principal": {"principal_type": "agent", "id": agent_id},
            "depth": int(hook_dict.get("depth") or 0),
        }
        return envelope
    logger.debug("watchlight_strands: unrecognised hook %r", hook)
    return None


def translate_strands_events(
    events: List[Dict[str, Any]],
    *,
    execution_id: str,
    agent_id: str,
    session_id: Optional[str] = None,
    tenant_id: Optional[str] = None,
    parent_execution_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Batch form of :func:`translate_strands_event`; ``None`` results
    and captures that fail to translate are dropped."""
    out: List[Dict[str, Any]] = []
    for ev in events:
        try:
            translated = translate_strands_event(
                ev,
                execution_id=execution_id,
                agent_id=agent_id,
                session_id=session_id,
                tenant_id=tenant_id,
                parent_execution_id=parent_execution_id,
            )
        except Exception:
            logger.debug("watchlight_strands: translator raised", exc_info=True)
            continue
        if translated is not None:
            out.append(translated)
    return out


def _envelope(
    event_type: EventType,
    *,
    execution_id: str,
    agent_id: str,
    session_id: Optional[str],
    tenant_id: Optional[str],
    parent_execution_id: Optional[str],
) -> Dict[str, Any]:
    envelope: Dict[str, Any] = {
        "event_id": f"evt_{uuid.uuid4()}",
        "event_type": event_type.value,
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "execution_id": execution_id,
        "agent_id": agent_id,
        "metadata": {"source": SOURCE_TAG},
    }
    if session_id is not None:
        envelope["session_id"] = session_id
    if tenant_id is not None:
        envelope["tenant_id"] = tenant_id
    if parent_execution_id is not None:
        envelope["parent_execution_id"] = parent_execution_id
    return envelope
