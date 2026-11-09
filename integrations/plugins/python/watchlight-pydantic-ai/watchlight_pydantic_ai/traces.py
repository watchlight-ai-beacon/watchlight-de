"""Pydantic AI event-capture translator.

Pydantic AI exposes an ``agent.iter()`` interface that streams
run events. Customers who prefer post-hoc translation (over
inline ``guarded_tool``) can capture those events into dicts and
feed them through :func:`translate_pydantic_ai_events` to get
canonical :class:`watchlight_core.ExecutionEvent` shapes.

The expected capture-dict shape is documented in each builder's
docstring. Conformance invariants 1-7 hold on every output.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from watchlight_core import (
    EventType,
    PlanKind,
    PlanValidationError,
    build_plan_payload,
    filter_valid_tool_names,
    get_logger,
    summarize_arg_keys,
    truncate_rationale,
    redacted_input_summary,
)

logger = get_logger("watchlight_pydantic_ai.traces")

__all__ = [
    "SOURCE_TAG",
    "URI_SCHEME",
    "translate_pydantic_ai_event",
    "translate_pydantic_ai_events",
]


SOURCE_TAG: str = "pydantic-ai.callback"
URI_SCHEME: str = "pydantic-ai"


def translate_pydantic_ai_event(
    capture: Dict[str, Any],
    *,
    execution_id: str,
    agent_id: str,
    session_id: Optional[str] = None,
    tenant_id: Optional[str] = None,
    parent_execution_id: Optional[str] = None,
    root_execution_id: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """Map one Pydantic AI run-event capture to a canonical
    :class:`ExecutionEvent` dict.

    Expected ``capture`` shapes:

    - ``{"hook": "tool_call", "tool_name": str, "args": dict,
      "result": Any | None, "decision": str | None,
      "duration_ms": int | None}`` → ``tool_call_observed``
    - ``{"hook": "tool_planned", "intended_tools": list[str],
      "rationale": str | None, "plan_kind": str | None}`` →
      ``plan_observed``
    - ``{"hook": "run_started", "depth": int}`` →
      ``execution_started``
    - ``{"hook": "run_completed", "duration_ms": int,
      "actions_taken": int}`` → ``execution_completed``

    Returns the event dict on success, ``None`` to drop.
    """
    hook = capture.get("hook")
    if not isinstance(hook, str):
        return None

    kwargs = dict(
        execution_id=execution_id,
        agent_id=agent_id,
        session_id=session_id,
        tenant_id=tenant_id,
        parent_execution_id=parent_execution_id,
        root_execution_id=root_execution_id,
    )

    if hook == "tool_call":
        return _build_tool_call_observed(capture, **kwargs)
    if hook == "tool_planned":
        return _build_plan_observed(capture, **kwargs)
    if hook == "run_started":
        return _build_execution_started(capture, **kwargs)
    if hook == "run_completed":
        return _build_execution_completed(capture, **kwargs)

    logger.debug("watchlight_pydantic_ai: unrecognized hook %r", hook)
    return None


def translate_pydantic_ai_events(
    events: List[Dict[str, Any]],
    *,
    execution_id: str,
    agent_id: str,
    session_id: Optional[str] = None,
    tenant_id: Optional[str] = None,
    parent_execution_id: Optional[str] = None,
    root_execution_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Batch variant of :func:`translate_pydantic_ai_event`."""
    out: List[Dict[str, Any]] = []
    for ev in events:
        try:
            translated = translate_pydantic_ai_event(
                ev,
                execution_id=execution_id,
                agent_id=agent_id,
                session_id=session_id,
                tenant_id=tenant_id,
                parent_execution_id=parent_execution_id,
                root_execution_id=root_execution_id,
            )
        except Exception:  # noqa: BLE001
            logger.exception(
                "watchlight_pydantic_ai: translator raised on %r", ev.get("hook")
            )
            continue
        if translated is not None:
            out.append(translated)
    return out


# ─── Envelope + per-event-type builders ───────────────────────────────


def _build_envelope(
    *,
    event_type: EventType,
    execution_id: str,
    agent_id: str,
    session_id: Optional[str],
    tenant_id: Optional[str],
    parent_execution_id: Optional[str],
    root_execution_id: Optional[str] = None,
    metadata_extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    envelope: Dict[str, Any] = {
        "event_id": f"evt_{uuid.uuid4()}",
        "event_type": event_type.value,
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "execution_id": execution_id,
        "agent_id": agent_id,
    }
    if session_id is not None:
        envelope["session_id"] = session_id
    if tenant_id is not None:
        envelope["tenant_id"] = tenant_id
    if parent_execution_id is not None:
        envelope["parent_execution_id"] = parent_execution_id
    # Lineage linkage — when the caller threads the workflow root
    # through ``translate_pydantic_ai_event(..., root_execution_id=...)``
    # (typical for sub-agent handles minted alongside an
    # orchestrator), every event stitches into the orchestrator's tree
    # in ``wl-execution-graph``. Optional — standalone Pydantic AI runs
    # ARE their own root.
    if root_execution_id is not None:
        envelope["root_execution_id"] = root_execution_id

    metadata: Dict[str, Any] = {"source": SOURCE_TAG}
    if metadata_extra:
        metadata.update(metadata_extra)
    envelope["metadata"] = metadata
    return envelope


def _build_tool_call_observed(
    capture: Dict[str, Any],
    **envelope_kwargs: Any,
) -> Dict[str, Any]:
    tool_name = capture.get("tool_name") or "unknown"
    args_repr = capture.get("args")
    # Value-free: argument names and value types only, never a value.
    summary = redacted_input_summary(args_repr)

    envelope = _build_envelope(
        event_type=EventType.TOOL_CALL_OBSERVED,
        **envelope_kwargs,
    )
    payload: Dict[str, Any] = {
        "tool": {
            "resource_type": "tool",
            "identifier": tool_name,
            "endpoint": f"{URI_SCHEME}://tool/{tool_name}",
        },
        "action": {"action": "execute"},
    }
    if summary:
        payload["input_summary"] = summary
    # Sorted, comma-joined argument KEYS (never values) — the
    # behavioural feature Watchlight's drift detector consumes for
    # arg-shape scoring. None when args aren't a structured mapping.
    arg_key_summary = summarize_arg_keys(args_repr)
    if arg_key_summary:
        payload["arg_key_summary"] = arg_key_summary
    if "decision" in capture and capture["decision"]:
        payload["decision"] = capture["decision"]
    if "duration_ms" in capture and isinstance(capture["duration_ms"], int):
        payload["duration_ms"] = capture["duration_ms"]
    envelope["payload"] = payload
    return envelope


def _build_plan_observed(
    capture: Dict[str, Any],
    **envelope_kwargs: Any,
) -> Optional[Dict[str, Any]]:
    intended = capture.get("intended_tools") or []
    if not isinstance(intended, list):
        return None
    intended = filter_valid_tool_names(intended)
    if not intended:
        return None

    rationale = capture.get("rationale")
    plan_kind = capture.get("plan_kind") or PlanKind.INCREMENTAL
    if isinstance(plan_kind, PlanKind):
        plan_kind = plan_kind.value if hasattr(plan_kind, "value") else str(plan_kind)

    try:
        payload = build_plan_payload(
            intended_tools=intended,
            plan_kind=plan_kind,
            rationale=truncate_rationale(rationale),
        )
    except PlanValidationError as exc:
        logger.debug("watchlight_pydantic_ai: plan validation failed: %s", exc)
        return None

    envelope = _build_envelope(
        event_type=EventType.PLAN_OBSERVED,
        **envelope_kwargs,
    )
    envelope["payload"] = payload
    return envelope


def _build_execution_started(
    capture: Dict[str, Any],
    **envelope_kwargs: Any,
) -> Dict[str, Any]:
    envelope = _build_envelope(
        event_type=EventType.EXECUTION_STARTED,
        **envelope_kwargs,
    )
    envelope["payload"] = {
        "principal": {
            "principal_type": "agent",
            "id": envelope_kwargs.get("agent_id", ""),
        },
        "depth": int(capture.get("depth") or 0),
    }
    return envelope


def _build_execution_completed(
    capture: Dict[str, Any],
    **envelope_kwargs: Any,
) -> Dict[str, Any]:
    envelope = _build_envelope(
        event_type=EventType.EXECUTION_COMPLETED,
        **envelope_kwargs,
    )
    envelope["payload"] = {
        "duration_ms": int(capture.get("duration_ms") or 0),
        "actions_taken": int(capture.get("actions_taken") or 0),
        "actions_denied": int(capture.get("actions_denied") or 0),
    }
    return envelope
