"""Translate LangGraph / LangChain callback events into canonical
Watchlight :class:`ExecutionEvent` dicts.

# Overview

LangGraph builds on LangChain's `BaseCallbackHandler` interface.
The handler fires hooks at well-defined points in the execution
lifecycle. Unlike Bedrock's post-hoc ``agentTrace``, LangGraph
callbacks fire **synchronously and in-process**, giving us
coverage at all three agentic stages:

==========================  ==========================  =================================
LangChain callback hook     Agentic stage               Canonical Watchlight event
==========================  ==========================  =================================
``on_chain_start``          Plan (top-level only)       ``ExecutionStarted``
``on_agent_action``         Plan                        ``PlanObserved`` (incremental plan kind, one tool per event)
``on_chat_model_start``     Act                         ``ApiRequestObserved`` (LLM call)
``on_llm_start``            Act                         ``ApiRequestObserved`` (LLM call)
``on_tool_start``           Act                         ``ToolCallObserved`` (if not already emitted by ``on_agent_action``)
``on_tool_end``             Observe                     ``ToolCallObserved`` updated with duration + summary (replaces prior buffered event)
``on_chain_end``            Observe (top-level only)    ``ExecutionCompleted``
``on_agent_finish``         Observe (terminal)          ``ExecutionCompleted``
``on_chain_error``          Observe (failure)           ``ExecutionFailed``
``on_tool_error``           Observe (failure)           ``ExecutionFailed``
``on_llm_error``            Observe (failure)           ``ExecutionFailed``
==========================  ==========================  =================================

Hooks deliberately NOT emitted (with reasoning):

- ``on_text`` — free-form text bursts; too noisy and rarely actionable for governance
- ``on_llm_new_token`` — streaming tokens; would emit thousands of events per LLM call
- ``on_retry`` — captured as metadata on the next event, not as a discrete event (Bedrock parity)
- ``on_chain_start`` / ``on_chain_end`` for **nested** chains — only the top-level (no ``parent_run_id``) emits ``ExecutionStarted`` / ``ExecutionCompleted``; nested chains land as metadata on whatever tool/LLM events fall under them

# Determinism

Given the same sequence of callback events, the translator produces
the same ordered list of canonical events (modulo fresh
``event_id`` UUIDs). Required for SOC 2 CC7.x replayability and
EU AI Act Annex IV traceability.

# Failure modes

Malformed callback inputs (missing fields, unexpected shapes from
a future LangChain SDK revision) are logged at ``debug`` and
skipped. The translator never raises. Partial coverage beats no
coverage when upstream ships a shape change — the same posture the
other Watchlight framework translators take.

# Bounded per-event size

All free-form text fields (tool input summaries, LLM prompts,
error messages) are capped at the same limits every Watchlight
translator uses: 120 chars for input summaries, 512 chars for error
messages. Attacker-controlled (or framework-bug-controlled)
payloads cannot inflate per-event audit log size.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from watchlight_core import (
    IntentProvenance,
    PlanKind,
    PlanValidationError,
    build_plan_payload,
    get_logger,
    redacted_error_summary,
    redacted_input_summary,
)

logger = get_logger(__name__)


# ─── Canonical event schema constants ─────────────────────────────────
#
# These strings are the wire format expected by wl-apdp's /v1/events
# endpoint and by every downstream consumer (the Watchlight lineage
# service, SIEM exporters, drift detection). The discriminator is
# lowercase snake_case to match the canonical event schema.

_EVENT_TYPE_STARTED = "execution_started"
_EVENT_TYPE_COMPLETED = "execution_completed"
_EVENT_TYPE_FAILED = "execution_failed"
_EVENT_TYPE_TOOL_CALL = "tool_call_observed"
_EVENT_TYPE_API_REQUEST = "api_request_observed"
# Canonical plan event, kept distinct from ToolCallObserved so
# plan-stage signals are never conflated with act-stage execution.
# Consumed by the Watchlight lineage service's plan-vs-act correlator.
_EVENT_TYPE_PLAN = "plan_observed"

# Resource ref prefixes — `langgraph://` for in-process tools so
# they can be distinguished from Bedrock's `bedrock://tool/...`
# or proxy-observed `mcp://...` references downstream.

_RESOURCE_PREFIX_TOOL = "langgraph://tool/"
_RESOURCE_PREFIX_LLM = "langgraph://llm/"

# Bounded sizes — matched across the Watchlight translators for
# cross-plugin shape consistency. Tests pin these.
_MAX_INPUT_SUMMARY_LEN = 120
_MAX_ERROR_MESSAGE_LEN = 512

# Source attribution for event provenance binding (helps detect
# plugin-side event fabrication). Every event emitted by this
# translator carries this string under metadata.source.
_PROVENANCE_TAG = "langgraph.callback"


# ─── Public API ────────────────────────────────────────────────────────


def translate_langgraph_event(
    *,
    event: Dict[str, Any],
    execution_id: str,
    agent_id: str,
    session_id: Optional[str] = None,
    tenant_id: Optional[str] = None,
    parent_execution_id: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """Translate a single LangGraph / LangChain callback event into
    one canonical :class:`ExecutionEvent` dict (or ``None`` if the
    event type isn't mapped).

    Args:
        event: A callback-event dict. Schema (produced by
            :class:`WatchlightCallbackHandler`):
            ``{"hook": "on_tool_start", ...hook-specific fields...}``.
        execution_id: Watchlight execution id to attribute the
            event to.
        agent_id: Watchlight agent UUID.
        session_id: Optional Watchlight session id for correlation.
        tenant_id: Optional tenant id for multi-tenant routing.
        parent_execution_id: Optional parent execution id (for
            nested runs).

    Returns:
        A canonical ``ExecutionEvent`` dict, or ``None`` if the
        hook type is intentionally unmapped (e.g. ``on_text``,
        ``on_llm_new_token``) or the event was malformed.

    Never raises. Malformed events are logged at debug and return
    ``None``.
    """
    try:
        return _translate_one(
            event=event,
            execution_id=execution_id,
            agent_id=agent_id,
            session_id=session_id,
            tenant_id=tenant_id,
            parent_execution_id=parent_execution_id,
        )
    except Exception as exc:  # noqa: BLE001 — defensive on upstream-shape drift
        logger.debug(
            "langgraph translator skipped event %s due to %s: %s",
            event.get("hook"),
            type(exc).__name__,
            exc,
        )
        return None


def translate_langgraph_events(
    *,
    events: List[Dict[str, Any]],
    execution_id: str,
    agent_id: str,
    session_id: Optional[str] = None,
    tenant_id: Optional[str] = None,
    parent_execution_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Batch-translate a list of callback events into a list of
    canonical ``ExecutionEvent`` dicts.

    Order is preserved. Events that don't map (unhandled hook
    types, malformed inputs) are silently dropped — they do NOT
    cause subsequent events to be dropped. Same posture as the
    Bedrock translator: partial coverage beats no coverage.
    """
    out: List[Dict[str, Any]] = []
    for ev in events:
        translated = translate_langgraph_event(
            event=ev,
            execution_id=execution_id,
            agent_id=agent_id,
            session_id=session_id,
            tenant_id=tenant_id,
            parent_execution_id=parent_execution_id,
        )
        if translated is not None:
            out.append(translated)
    return out


# ─── Per-hook translators ─────────────────────────────────────────────


def _translate_one(
    *,
    event: Dict[str, Any],
    execution_id: str,
    agent_id: str,
    session_id: Optional[str],
    tenant_id: Optional[str],
    parent_execution_id: Optional[str],
) -> Optional[Dict[str, Any]]:
    """Internal: dispatch a single event by its hook field. Wrapped
    by :func:`translate_langgraph_event` for exception safety."""
    hook = event.get("hook")
    if not isinstance(hook, str):
        return None

    # The unmapped hooks return None silently. Centralized here so
    # the table in the module docstring is the single source of
    # truth.
    _UNMAPPED_HOOKS = {"on_text", "on_llm_new_token", "on_retry"}
    if hook in _UNMAPPED_HOOKS:
        return None

    if hook == "on_chain_start":
        return _on_chain_start(
            event, execution_id, agent_id, session_id, tenant_id, parent_execution_id
        )
    if hook == "on_chain_end":
        return _on_chain_end(
            event, execution_id, agent_id, session_id, tenant_id, parent_execution_id
        )
    if hook == "on_chain_error":
        return _on_error(
            event, execution_id, agent_id, session_id, tenant_id, parent_execution_id
        )
    if hook == "on_tool_start":
        return _on_tool_start(
            event, execution_id, agent_id, session_id, tenant_id, parent_execution_id
        )
    if hook == "on_tool_end":
        return _on_tool_end(
            event, execution_id, agent_id, session_id, tenant_id, parent_execution_id
        )
    if hook == "on_tool_error":
        return _on_error(
            event, execution_id, agent_id, session_id, tenant_id, parent_execution_id
        )
    if hook == "on_agent_action":
        return _on_agent_action(
            event, execution_id, agent_id, session_id, tenant_id, parent_execution_id
        )
    if hook == "on_agent_finish":
        return _on_agent_finish(
            event, execution_id, agent_id, session_id, tenant_id, parent_execution_id
        )
    if hook in ("on_llm_start", "on_chat_model_start"):
        return _on_llm_start(
            event, execution_id, agent_id, session_id, tenant_id, parent_execution_id
        )
    if hook == "on_llm_error":
        return _on_error(
            event, execution_id, agent_id, session_id, tenant_id, parent_execution_id
        )

    # Hook is a string but we don't recognize it. Could be a new
    # callback type from a future LangChain version. Logged for
    # observability but no event emitted.
    logger.debug("langgraph translator: unrecognized hook %s", hook)
    return None


def _on_chain_start(
    event: Dict[str, Any],
    execution_id: str,
    agent_id: str,
    session_id: Optional[str],
    tenant_id: Optional[str],
    parent_execution_id: Optional[str],
) -> Optional[Dict[str, Any]]:
    """Emit ExecutionStarted only for the top-level chain (no
    ``parent_run_id``). Nested chains are noise at the canonical-
    event level — operators care about agent executions, not
    every internal Runnable composition."""
    if event.get("parent_run_id") is not None:
        return None
    chain_name = str(event.get("name") or event.get("serialized", {}).get("name") or "chain")

    # PrincipalRef shape expected by the canonical event schema —
    # wl-apdp's /v1/events rejects the request with 422 if these field
    # names don't line up (untagged enum variant resolution).
    payload: Dict[str, Any] = {
        "principal": {"principal_type": "agent", "id": agent_id},
        # This translator only fires for the TOP-LEVEL graph run (the root
        # execution), which is depth 0 by definition. Sub-agent
        # ``execution_started`` events are emitted by the spawn path with the
        # auto-calculated child depth (see ``_emit_child_started`` in
        # plugin.py), never here — so a root is 0, and no sub-agent depth is
        # ever a literal.
        "depth": 0,
    }

    # Apply the intent precedence chain to populate the canonical
    # execution_started payload's intent_objective + intent_provenance
    # fields:
    #
    #   1. customer-declared (start_run(intent_objective=…))
    #   2. plugin-derived (extracted from on_chain_start.inputs)
    #   3. absent (default — Cedar policies decide)
    #
    # Whichever lane fires first stamps both the objective string and
    # the matching IntentProvenance enum. Empty strings are treated
    # as "no signal" so an empty inputs dict doesn't masquerade as
    # plugin-derived (which would break the conformance invariant that
    # every provenance value reflects a real signal).
    declared = event.get("_intent_declared") if isinstance(event.get("_intent_declared"), str) else None
    extracted = event.get("_intent_extracted") if isinstance(event.get("_intent_extracted"), str) else None
    if declared:
        payload["intent_objective"] = declared
        payload["intent_provenance"] = IntentProvenance.DECLARED.value
    elif extracted:
        payload["intent_objective"] = extracted
        payload["intent_provenance"] = IntentProvenance.PLUGIN_DERIVED.value
    # Absent case: leave both fields off the payload. Omitting the
    # intent_provenance key is byte-identical to
    # IntentProvenance.ABSENT in the canonical execution_started
    # schema, so the backend treats it as "no intent declared".

    return _build_event(
        event_type=_EVENT_TYPE_STARTED,
        execution_id=execution_id,
        agent_id=agent_id,
        session_id=session_id,
        tenant_id=tenant_id,
        parent_execution_id=parent_execution_id,
        payload=payload,
        metadata={
            "source": _PROVENANCE_TAG,
            "chain_name": chain_name,
        },
    )


def _on_chain_end(
    event: Dict[str, Any],
    execution_id: str,
    agent_id: str,
    session_id: Optional[str],
    tenant_id: Optional[str],
    parent_execution_id: Optional[str],
) -> Optional[Dict[str, Any]]:
    """Top-level chain complete → ExecutionCompleted."""
    if event.get("parent_run_id") is not None:
        return None
    duration_ms = int(event.get("duration_ms") or 0)
    actions_taken = int(event.get("actions_taken") or 0)
    return _build_event(
        event_type=_EVENT_TYPE_COMPLETED,
        execution_id=execution_id,
        agent_id=agent_id,
        session_id=session_id,
        tenant_id=tenant_id,
        parent_execution_id=parent_execution_id,
        payload={
            "duration_ms": duration_ms,
            "actions_taken": actions_taken,
        },
        metadata={
            "source": _PROVENANCE_TAG,
        },
    )


def _on_tool_start(
    event: Dict[str, Any],
    execution_id: str,
    agent_id: str,
    session_id: Optional[str],
    tenant_id: Optional[str],
    parent_execution_id: Optional[str],
) -> Optional[Dict[str, Any]]:
    """Tool invocation began → ToolCallObserved. The input summary is
    value-free (argument names and value types, at most 120 chars): a
    truncated argument value can still hold a credential."""
    tool_name = str(event.get("name") or event.get("serialized", {}).get("name") or "unknown")
    input_summary = event.get("input_summary")
    if input_summary is None:
        raw = event.get("inputs")
        if not isinstance(raw, dict):
            raw = event.get("input_str") or event.get("input")
        input_summary = redacted_input_summary(raw)
    else:
        input_summary = _truncate_summary(str(input_summary))
    # Sorted, comma-joined argument KEYS (never values) — computed at
    # capture time from the structured `inputs` kwarg (see callbacks.py).
    # This is the behavioural feature Watchlight's drift detector's
    # arg-shape scorer consumes; None on older langchain-core that
    # doesn't pass `inputs`.
    arg_key_summary = event.get("arg_key_summary")

    payload: Dict[str, Any] = {
        # ResourceRef + ActionRef shapes required by the canonical
        # event schema. Earlier code flattened these under
        # `resource`/`action` keys; wl-apdp's deserializer expects the
        # typed `resource_type` + `identifier` (and `action` for ActionRef).
        "tool": {
            "resource_type": "tool",
            "identifier": tool_name,
            "endpoint": f"{_RESOURCE_PREFIX_TOOL}{tool_name}",
        },
        "action": {"action": "invoke"},
    }
    if input_summary:
        payload["input_summary"] = input_summary
    if arg_key_summary:
        payload["arg_key_summary"] = arg_key_summary

    return _build_event(
        event_type=_EVENT_TYPE_TOOL_CALL,
        execution_id=execution_id,
        agent_id=agent_id,
        session_id=session_id,
        tenant_id=tenant_id,
        parent_execution_id=parent_execution_id,
        payload=payload,
        metadata={
            "source": _PROVENANCE_TAG,
            "tool_name": tool_name,
        },
    )


def _on_tool_end(
    event: Dict[str, Any],
    execution_id: str,
    agent_id: str,
    session_id: Optional[str],
    tenant_id: Optional[str],
    parent_execution_id: Optional[str],
) -> Optional[Dict[str, Any]]:
    """Tool returned → emit a follow-up ToolCallObserved that
    includes duration_ms. Operators correlate by run_id to pair
    this with the prior on_tool_start event."""
    tool_name = str(event.get("name") or "unknown")
    duration_ms = event.get("duration_ms")

    payload: Dict[str, Any] = {
        # ResourceRef + ActionRef shapes required by the canonical
        # event schema. Earlier code flattened these under
        # `resource`/`action` keys; wl-apdp's deserializer expects the
        # typed `resource_type` + `identifier` (and `action` for ActionRef).
        "tool": {
            "resource_type": "tool",
            "identifier": tool_name,
            "endpoint": f"{_RESOURCE_PREFIX_TOOL}{tool_name}",
        },
        "action": {"action": "invoke"},
        "decision": "completed",
    }
    if isinstance(duration_ms, (int, float)) and duration_ms >= 0:
        payload["duration_ms"] = int(duration_ms)

    return _build_event(
        event_type=_EVENT_TYPE_TOOL_CALL,
        execution_id=execution_id,
        agent_id=agent_id,
        session_id=session_id,
        tenant_id=tenant_id,
        parent_execution_id=parent_execution_id,
        payload=payload,
        metadata={
            "source": _PROVENANCE_TAG,
            "tool_name": tool_name,
            "phase": "completed",
        },
    )


def _on_agent_action(
    event: Dict[str, Any],
    execution_id: str,
    agent_id: str,
    session_id: Optional[str],
    tenant_id: Optional[str],
    parent_execution_id: Optional[str],
) -> Optional[Dict[str, Any]]:
    """Agent decided on an action — plan-stage signal.

    Emits a canonical `PlanObserved` event, kept distinct from
    `ToolCallObserved` so plan-stage signals are never conflated with
    act-stage execution.

    LangGraph ReAct agents decide one tool at a time, so `plan_kind`
    is `"incremental"` and `intended_tools` carries a single tool
    name. The Watchlight lineage service's correlator unions these
    across the execution to form the plan set.

    Returns ``None`` and logs at debug if the tool name fails
    validation, so an adversarial tool description cannot form a
    malformed plan event.
    """
    tool_name = str(event.get("tool") or "unknown")

    # Rationale is operator-legibility only; the correlator ignores it.
    tool_input = event.get("tool_input")
    rationale: Optional[str] = None
    if tool_input is not None:
        summary = _truncate_summary(tool_input)
        if summary:
            rationale = summary

    try:
        payload = build_plan_payload(
            intended_tools=[tool_name],
            plan_kind=PlanKind.INCREMENTAL,
            rationale=rationale,
        )
    except PlanValidationError as exc:
        logger.debug("plan_observed dropped: %s", exc)
        return None

    return _build_event(
        event_type=_EVENT_TYPE_PLAN,
        execution_id=execution_id,
        agent_id=agent_id,
        session_id=session_id,
        tenant_id=tenant_id,
        parent_execution_id=parent_execution_id,
        payload=payload,
        metadata={
            "source": _PROVENANCE_TAG,
            "tool_name": tool_name,
        },
    )


def _on_agent_finish(
    event: Dict[str, Any],
    execution_id: str,
    agent_id: str,
    session_id: Optional[str],
    tenant_id: Optional[str],
    parent_execution_id: Optional[str],
) -> Optional[Dict[str, Any]]:
    """Agent reached a terminal state → ExecutionCompleted with
    outcome summary. Distinct from on_chain_end so we capture
    "agent decided to stop" vs "outer graph finished"."""
    duration_ms = int(event.get("duration_ms") or 0)
    return_values = event.get("return_values")
    outcome = _truncate_summary(return_values) if return_values is not None else None

    payload: Dict[str, Any] = {
        "duration_ms": duration_ms,
        "actions_taken": int(event.get("actions_taken") or 0),
    }
    if outcome:
        payload["outcome"] = outcome

    return _build_event(
        event_type=_EVENT_TYPE_COMPLETED,
        execution_id=execution_id,
        agent_id=agent_id,
        session_id=session_id,
        tenant_id=tenant_id,
        parent_execution_id=parent_execution_id,
        payload=payload,
        metadata={
            "source": _PROVENANCE_TAG,
            "terminal": "agent_finish",
        },
    )


def _on_llm_start(
    event: Dict[str, Any],
    execution_id: str,
    agent_id: str,
    session_id: Optional[str],
    tenant_id: Optional[str],
    parent_execution_id: Optional[str],
) -> Optional[Dict[str, Any]]:
    """LLM call began → ApiRequestObserved. The LLM provider
    (model name) goes into resource ref; prompt summary into
    metadata (bounded). This is how we get LLM cost / model-
    choice telemetry without storing full prompts."""
    model_name = str(
        event.get("model")
        or event.get("invocation_params", {}).get("model")
        or event.get("name")
        or "unknown"
    )
    prompts = event.get("prompts") or event.get("messages")
    prompt_summary = _truncate_summary(prompts) if prompts is not None else None

    # ResourceRef shape from the canonical event schema — `resource_type`
    # + `identifier`, not flattened. ApiRequestObservedPayload's
    # ``resource`` field carries this same ResourceRef shape.
    payload: Dict[str, Any] = {
        "resource": {
            "resource_type": "llm_api",
            "identifier": model_name,
            "endpoint": f"{_RESOURCE_PREFIX_LLM}{model_name}",
        },
        "method": "POST",
        "path": "/completion",
    }
    if prompt_summary:
        # Stash prompt summary in metadata; the canonical payload
        # for ApiRequestObserved doesn't include a body field, by
        # design (PII risk). Metadata is operator-facing.
        pass

    return _build_event(
        event_type=_EVENT_TYPE_API_REQUEST,
        execution_id=execution_id,
        agent_id=agent_id,
        session_id=session_id,
        tenant_id=tenant_id,
        parent_execution_id=parent_execution_id,
        payload=payload,
        metadata={
            "source": _PROVENANCE_TAG,
            "model": model_name,
            "prompt_summary": prompt_summary,
        },
    )


def _on_error(
    event: Dict[str, Any],
    execution_id: str,
    agent_id: str,
    session_id: Optional[str],
    tenant_id: Optional[str],
    parent_execution_id: Optional[str],
) -> Optional[Dict[str, Any]]:
    """Any callback error hook → ExecutionFailed with bounded
    error message. Handles on_chain_error, on_tool_error,
    on_llm_error uniformly because they all carry the same
    interesting field shape (an `error` object)."""
    error_obj = event.get("error")
    # Value-free: the exception class only, never its message (which
    # can carry argument values, response bodies or credentials).
    error_excerpt = redacted_error_summary(error_obj)[:_MAX_ERROR_MESSAGE_LEN]

    return _build_event(
        event_type=_EVENT_TYPE_FAILED,
        execution_id=execution_id,
        agent_id=agent_id,
        session_id=session_id,
        tenant_id=tenant_id,
        parent_execution_id=parent_execution_id,
        payload={
            "error": error_excerpt,
            # ``ExecutionFailedPayload`` models the error CATEGORY as
            # ``error_type``; ``error_code`` is not a field on the server
            # struct, so serde dropped it silently.
            "error_type": type(error_obj).__name__ if error_obj is not None else None,
        },
        metadata={
            "source": _PROVENANCE_TAG,
            "hook": event.get("hook"),
        },
    )


# ─── Helpers ───────────────────────────────────────────────────────────


def _truncate_summary(value: Any) -> Optional[str]:
    """Render an arbitrary value as a bounded string suitable for
    audit-event input/prompt summaries.

    Inputs are coerced via ``str()`` — dicts and lists render as
    Python's repr, which is fine for forensic correlation but
    not for downstream consumption. The 120-char cap is shared across
    the Watchlight translators so cross-plugin shape is consistent.
    """
    if value is None:
        return None
    rendered = str(value)
    if not rendered:
        return None
    if len(rendered) > _MAX_INPUT_SUMMARY_LEN:
        return rendered[:_MAX_INPUT_SUMMARY_LEN]
    return rendered


def _build_event(
    *,
    event_type: str,
    execution_id: str,
    agent_id: str,
    session_id: Optional[str],
    tenant_id: Optional[str],
    parent_execution_id: Optional[str],
    payload: Dict[str, Any],
    metadata: Dict[str, Any],
) -> Dict[str, Any]:
    """Construct one ExecutionEvent dict matching the canonical
    flat-envelope JSON shape expected by wl-apdp's /v1/events.

    Wire contract: field names + nesting MUST match the canonical
    ``ExecutionEvent`` schema exactly. The cross-framework conformance
    suite pins this across all plugin emitters, so this builder is
    intentionally identical to the equivalent builder in the other
    Watchlight framework plugins.
    """
    envelope: Dict[str, Any] = {
        "event_id": f"evt_{uuid.uuid4()}",
        "event_type": event_type,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "execution_id": execution_id,
        "agent_id": agent_id,
    }
    if session_id is not None:
        envelope["session_id"] = session_id
    if tenant_id is not None:
        envelope["tenant_id"] = tenant_id
    if parent_execution_id is not None:
        envelope["parent_execution_id"] = parent_execution_id
    cleaned_metadata = {k: v for k, v in metadata.items() if v not in (None, "")}
    if cleaned_metadata:
        envelope["metadata"] = cleaned_metadata
    return {**envelope, "payload": payload}
