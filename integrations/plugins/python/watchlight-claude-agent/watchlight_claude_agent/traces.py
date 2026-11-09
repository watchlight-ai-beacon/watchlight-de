"""Claude Agent SDK hook-event translator.

Customers running the Claude Agent SDK capture hook events
(PreToolUse / PostToolUse / UserPromptSubmit / Stop / SubagentStart
/ SubagentStop / PostToolUseFailure) into dicts during their run,
then feed those captures through :func:`translate_claude_agent_events`
to get canonical :class:`watchlight_core.ExecutionEvent` shapes
that publish through the APDP /v1/events endpoint.

Conformance invariants 1-7 hold on every output.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from watchlight_core import (
    EventType,
    IntentProvenance,
    PlanKind,
    PlanValidationError,
    build_plan_payload,
    filter_valid_tool_names,
    get_logger,
    summarize_arg_keys,
    truncate_rationale,
    redacted_error_summary,
    redacted_input_summary,
)

from .intent import extract_intent_from_user_prompt_submit

logger = get_logger("watchlight_claude_agent.traces")

__all__ = [
    "SOURCE_TAG",
    "URI_SCHEME",
    "translate_claude_agent_event",
    "translate_claude_agent_events",
]


SOURCE_TAG: str = "claude-agent-sdk.hook"
URI_SCHEME: str = "claude-agent-sdk"


def translate_claude_agent_event(
    capture: Dict[str, Any],
    *,
    execution_id: str,
    agent_id: str,
    session_id: Optional[str] = None,
    tenant_id: Optional[str] = None,
    parent_execution_id: Optional[str] = None,
    root_execution_id: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """Map one Claude Agent SDK hook capture to a canonical
    :class:`ExecutionEvent` dict.

    Expected ``capture`` shapes (discriminator: ``hook`` key,
    mirroring the SDK's ``hook_event_name``):

    - ``{"hook": "PreToolUse", "tool_name": str,
      "tool_input": dict, "decision": str | None}`` →
      ``tool_call_observed`` tagged source ``...pre_tool_use``
    - ``{"hook": "PostToolUse", "tool_name": str,
      "tool_input": dict, "duration_ms": int | None}`` →
      ``tool_call_observed`` tagged source ``...post_tool_use``
    - ``{"hook": "PostToolUseFailure", "tool_name": str,
      "tool_input": dict, "error": str | None}`` →
      ``tool_call_observed`` with decision ``Failed: <error class>``
      (the error text itself is never recorded)
    - ``{"hook": "UserPromptSubmit", "depth": int | None,
      "intended_tools": list[str] | None}`` →
      ``execution_started`` (+ optional ``plan_observed`` if
      intended_tools provided)
    - ``{"hook": "SubagentStart", ...}`` → dropped. Spawn attestation is
      SERVER-emitted only (wl-apdp's ``spawn_handler`` mints the
      authoritative ``agent_spawn_observed``); a plugin-emitted
      ``agent_spawn_observed`` is REJECTED at ``/v1/events`` ingest. The
      subagent's own ``execution_started`` is produced by its
      ``UserPromptSubmit`` hook.
    - ``{"hook": "Stop", "actions_taken": int | None,
      "actions_denied": int | None, "duration_ms": int | None}``
      → ``execution_completed``

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

    if hook in ("PreToolUse", "pre_tool_use"):
        return _build_tool_call_observed(capture, source_suffix="pre_tool_use", **kwargs)
    if hook in ("PostToolUse", "post_tool_use"):
        return _build_tool_call_observed(capture, source_suffix="post_tool_use", **kwargs)
    if hook in ("PostToolUseFailure", "post_tool_use_failure"):
        return _build_tool_call_observed(
            capture, source_suffix="post_tool_use_failure", **kwargs
        )
    if hook in ("UserPromptSubmit", "user_prompt_submit"):
        return _build_execution_started(capture, **kwargs)
    if hook in ("SubagentStart", "subagent_start"):
        # Spawn attestation is SERVER-emitted only. wl-apdp's
        # ``spawn_handler`` emits the single authoritative
        # ``agent_spawn_observed`` when a spawn is routed through the
        # governed ``spawn_subagent`` chokepoint; a per-plugin
        # ``agent_spawn_observed`` is redundant, forgeable, and REJECTED
        # at ``/v1/events`` ingest (``lineage_event_class_not_permitted``).
        # The subagent's OWN ``execution_started`` is already produced by
        # its ``UserPromptSubmit`` hook (``depth`` > 0), so this
        # observational ``SubagentStart`` hook is dropped.
        logger.debug(
            "watchlight_claude_agent: SubagentStart is server-attested; "
            "dropping — child execution_started comes from the "
            "subagent's UserPromptSubmit hook"
        )
        return None
    if hook in ("Stop", "stop"):
        return _build_execution_completed(capture, **kwargs)
    if hook in ("PlanObserved", "plan_observed"):
        return _build_plan_observed(capture, **kwargs)

    logger.debug("watchlight_claude_agent: unrecognized hook %r", hook)
    return None


def translate_claude_agent_events(
    events: List[Dict[str, Any]],
    *,
    execution_id: str,
    agent_id: str,
    session_id: Optional[str] = None,
    tenant_id: Optional[str] = None,
    parent_execution_id: Optional[str] = None,
    root_execution_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Batch variant of :func:`translate_claude_agent_event`."""
    out: List[Dict[str, Any]] = []
    for ev in events:
        try:
            translated = translate_claude_agent_event(
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
                "watchlight_claude_agent: translator raised on %r",
                ev.get("hook"),
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
    # LINEAGE LINKAGE — propagate `root_execution_id`
    # verbatim on every event the caller emits for this run. When the
    # caller threads it through `translate_claude_agent_event(...,
    # root_execution_id=...)` from a sub-agent's run, every event the
    # sub-agent emits stitches into the orchestrator's tree.
    # `wl-execution-graph` back-fills it for root events (where the
    # parent is absent), so leaving it `None` for top-level runs is
    # safe — but explicit is better.
    if root_execution_id is not None:
        envelope["root_execution_id"] = root_execution_id

    metadata: Dict[str, Any] = {"source": SOURCE_TAG}
    if metadata_extra:
        metadata.update(metadata_extra)
    envelope["metadata"] = metadata
    return envelope


def _build_tool_call_observed(
    capture: Dict[str, Any],
    *,
    source_suffix: str,
    **envelope_kwargs: Any,
) -> Dict[str, Any]:
    tool_name = capture.get("tool_name") or "unknown"
    tool_input = capture.get("tool_input")
    # Value-free: argument names and value types only, never a value.
    summary = redacted_input_summary(tool_input)

    envelope = _build_envelope(
        event_type=EventType.TOOL_CALL_OBSERVED,
        metadata_extra={"source": f"claude-agent-sdk.{source_suffix}"},
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
    # Arg-SHAPE drift contract: sorted argument KEY names, no values —
    # identical to wl-proxy's MCP path and the other SDK plugins, so
    # wl-drift can score this vantage. PostToolUse repeats the same call
    # and one observation per call is the contract, so populate on the
    # pre_tool_use event only.
    if source_suffix == "pre_tool_use":
        arg_key_summary = summarize_arg_keys(tool_input)
        if arg_key_summary:
            payload["arg_key_summary"] = arg_key_summary
    if "decision" in capture and capture["decision"]:
        payload["decision"] = capture["decision"]
    elif "error" in capture and capture["error"]:
        # Value-free: the SDK's error text can echo tool input or output.
        payload["decision"] = f"Failed: {redacted_error_summary(capture['error'])}"
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
    plan_kind = capture.get("plan_kind") or PlanKind.INFERRED
    if isinstance(plan_kind, PlanKind):
        plan_kind = plan_kind.value if hasattr(plan_kind, "value") else str(plan_kind)

    try:
        payload = build_plan_payload(
            intended_tools=intended,
            plan_kind=plan_kind,
            rationale=truncate_rationale(rationale),
        )
    except PlanValidationError as exc:
        logger.debug(
            "watchlight_claude_agent: plan validation failed: %s", exc
        )
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
        metadata_extra={"source": "claude-agent-sdk.user_prompt_submit"},
        **envelope_kwargs,
    )
    payload: Dict[str, Any] = {
        "principal": {
            "principal_type": "agent",
            "id": envelope_kwargs.get("agent_id", ""),
        },
        # FRAMEWORK-SOURCED spawn-tree depth — never hardcoded. This
        # integration is post-hoc: the customer's hook loop captures each
        # ``UserPromptSubmit`` and stamps ``capture["depth"]`` from the
        # Claude Agent SDK's nesting signal (0 for the top-level run, +1
        # for each Task sub-agent's own loop — the SDK re-enters
        # ``UserPromptSubmit`` inside a spawned Task). The translator
        # passes it through verbatim; wl-execution-graph stores
        # ``payload.depth`` as-is, so a Task sub-agent renders at its
        # real DEPTH on the dashboard, not 0. ``or 0`` is
        # only the root default when a capture omits the key — it is NOT a
        # sub-agent fallback, and the translator never clobbers a supplied
        # depth to 0.
        "depth": int(capture.get("depth") or 0),
    }
    # Extract the user prompt as the run's intent_objective and
    # tag the provenance so Cedar policies can gate on whether the
    # objective was Declared / PluginDerived / ProxyInferred / Absent.
    # The conformance gate requires the two fields to remain
    # consistent: a populated objective MUST carry a non-Absent
    # provenance, an absent objective MUST carry Absent. The helper in
    # `intent.py` is the single point of computation so this holds by
    # construction.
    objective, provenance = extract_intent_from_user_prompt_submit(capture)
    if objective is not None:
        payload["intent_objective"] = objective
        payload["intent_provenance"] = provenance.value
    elif provenance != IntentProvenance.ABSENT:
        # Defensive: should never happen — the extractor only returns a
        # non-Absent provenance alongside a non-None objective. Recorded
        # for completeness.
        payload["intent_provenance"] = provenance.value
    # else: absent + None — emit no intent_provenance field; the wire
    # default (missing) is equivalent to IntentProvenance.ABSENT and
    # matches the backward-compatible shape.
    envelope["payload"] = payload
    return envelope


def _build_execution_completed(
    capture: Dict[str, Any],
    **envelope_kwargs: Any,
) -> Dict[str, Any]:
    envelope = _build_envelope(
        event_type=EventType.EXECUTION_COMPLETED,
        metadata_extra={"source": "claude-agent-sdk.stop"},
        **envelope_kwargs,
    )
    envelope["payload"] = {
        "duration_ms": int(capture.get("duration_ms") or 0),
        "actions_taken": int(capture.get("actions_taken") or 0),
        "actions_denied": int(capture.get("actions_denied") or 0),
    }
    return envelope
