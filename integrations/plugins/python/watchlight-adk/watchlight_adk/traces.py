"""Translate Google ADK callback events into canonical Watchlight
:class:`ExecutionEvent` dicts.

# Overview

Google ADK exposes a callback protocol via ``BasePlugin``. The
:class:`WatchlightPlugin` (``plugin.py``) subclasses ``BasePlugin``
and implements the relevant hooks:

==========================  ==========================  =================================
ADK callback hook           Agentic stage               Canonical Watchlight event
==========================  ==========================  =================================
``before_agent_callback``   Plan (top-level)            ``ExecutionStarted`` + ``PolicyDecisionMade``
``before_tool_callback``    Plan / Act                  ``PolicyDecisionMade`` (decision)
``after_tool_callback``     Observe                     ``ToolCallObserved``
``before_model_callback``   Act                         ``ApiRequestObserved`` (LLM call)
``hosted_tool_observed``    Observe                     ``ToolCallObserved`` (a hosted tool the response shows ran)
``after_agent_callback``    Observe                     ``ExecutionCompleted``
``on_tool_error_callback``  Observe (failure)           ``ExecutionFailed`` (hook name only)
``on_model_error_callback`` Observe (failure)           ``ExecutionFailed`` (hook name only)
``on_agent_error_callback`` Observe (failure)           ``ExecutionFailed``
==========================  ==========================  =================================

Hooks deliberately NOT translated to discrete events (with reasoning):

- ``on_user_message_callback`` — captured as metadata on the
  subsequent ``before_agent_callback`` if needed; not a governance
  event per the canonical schema
- ``before_run_callback`` / ``after_run_callback`` — outer-runner
  bookends; ``before_agent_callback`` / ``after_agent_callback``
  already capture the agent-execution boundary. The plugin's
  ``after_run_callback`` / ``on_run_error_callback`` close any frame an
  ``after_agent_callback`` left open by emitting the same
  ``after_agent_callback`` / ``on_agent_error_callback`` captures,
  so the run hooks themselves never reach the translator.
  They close only the frames their own invocation opened: an
  ``AgentTool``'s nested runner never closes the calling agent
- ``on_tool_error_callback`` / ``on_model_error_callback`` — they emit
  no terminal event of their own: an agent-level error callback can
  still recover the call. Each execution gets exactly one terminal
  event, from the frame's close; when the run did fail, its
  ``ExecutionFailed`` names the tool or model hook that first saw the
  error in ``metadata.hook``
- ``after_model_callback`` — captured for plan-governance side
  effects in the plugin but not emitted as a discrete LLM-complete
  event today (LLM completion is implicit in the
  ``ApiRequestObserved`` emitted at ``before_model_callback``)
- ``on_event_callback`` — too noisy; ADK fires it for every
  intermediate event in the execution

# Determinism

Given the same callback-capture dict, the translator produces the
same canonical event (modulo a fresh ``event_id`` UUID). Required
for SOC 2 CC7.x replayability.

# Failure modes

Malformed capture dicts (missing fields, unexpected types) are
logged at ``debug`` and return ``None``. The translator never
raises. Same posture as the LangGraph and Bedrock plugins:
partial coverage beats no coverage when upstream ships a shape
change.

# Bounded per-event size

All free-form text fields are capped at the same limits as the
LangGraph and Bedrock translators: 120 chars for input summaries,
512 chars for error messages. Attacker-controlled payloads cannot
inflate per-event audit log size.
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
)

from .redaction import redacted_input_summary

logger = get_logger(__name__)


# ─── Canonical event schema constants ─────────────────────────────────
#
# Wire format strings — must match the canonical event wire format
# APDP expects. Lowercase snake_case for the discriminator.

_EVENT_TYPE_STARTED = "execution_started"
_EVENT_TYPE_COMPLETED = "execution_completed"
_EVENT_TYPE_FAILED = "execution_failed"
_EVENT_TYPE_TOOL_CALL = "tool_call_observed"
_EVENT_TYPE_API_REQUEST = "api_request_observed"
# Canonical plan event. Emitted from ADK's
# ``before_tool_callback`` (one tool per event → ``incremental``
# plan kind), replacing the prior ``decision="planned"`` overload
# on ``ToolCallObserved``.
_EVENT_TYPE_PLAN = "plan_observed"

# Resource ref prefixes — namespaced by framework so downstream
# consumers can distinguish ``adk://tool/...`` from
# ``langgraph://tool/...`` or ``bedrock://tool/...`` without
# special-casing.

_RESOURCE_PREFIX_TOOL = "adk://tool/"
_RESOURCE_PREFIX_LLM = "adk://llm/"

# Bounded sizes — matched to the LangGraph and Bedrock plugins
# for cross-plugin shape consistency. Cross-plugin conformance
# tests pin these.
_MAX_INPUT_SUMMARY_LEN = 120
_MAX_ERROR_MESSAGE_LEN = 512

# Source attribution for provenance binding. Every event
# carries this tag under metadata.source so downstream consumers
# can attribute and detect fabrication.
_PROVENANCE_TAG = "adk.callback"


# ─── Public API ────────────────────────────────────────────────────────


def translate_adk_event(
    *,
    capture: Dict[str, Any],
    execution_id: str,
    agent_id: str,
    session_id: Optional[str] = None,
    tenant_id: Optional[str] = None,
    parent_execution_id: Optional[str] = None,
    root_execution_id: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """Translate a single ADK callback capture into one canonical
    :class:`ExecutionEvent` dict (or ``None`` if the hook isn't
    mapped or the capture is malformed).

    Args:
        capture: A callback-capture dict. Schema:
            ``{"hook": "before_agent_callback", ...hook-specific fields...}``.
            Produced by the plugin's callback methods (which thinly
            wrap the ADK callback parameters into this shape).
        execution_id: Watchlight execution id to attribute the
            event to.
        agent_id: Watchlight agent UUID.
        session_id: Optional Watchlight session id.
        tenant_id: Optional tenant id for multi-tenant routing.
        parent_execution_id: Optional parent execution id (for
            nested ADK sub-agent runs).
        root_execution_id: Optional root of the execution tree
            (denormalized for fast lineage queries).

    Returns:
        Canonical ``ExecutionEvent`` dict, or ``None`` if the hook
        is intentionally unmapped or the capture was malformed.

    Never raises. Malformed captures are logged at debug.
    """
    try:
        return _translate_one(
            capture=capture,
            execution_id=execution_id,
            agent_id=agent_id,
            session_id=session_id,
            tenant_id=tenant_id,
            parent_execution_id=parent_execution_id,
            root_execution_id=root_execution_id,
        )
    except Exception as exc:  # noqa: BLE001 — defensive on upstream-shape drift
        logger.debug(
            "adk translator skipped capture %s due to %s: %s",
            capture.get("hook"),
            type(exc).__name__,
            exc,
        )
        return None


def translate_adk_events(
    *,
    captures: List[Dict[str, Any]],
    execution_id: str,
    agent_id: str,
    session_id: Optional[str] = None,
    tenant_id: Optional[str] = None,
    parent_execution_id: Optional[str] = None,
    root_execution_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Batch-translate a list of ADK callback captures. Order
    preserved; unmapped or malformed captures silently dropped.
    Same posture as the LangGraph and Bedrock batch translators."""
    out: List[Dict[str, Any]] = []
    for cap in captures:
        translated = translate_adk_event(
            capture=cap,
            execution_id=execution_id,
            agent_id=agent_id,
            session_id=session_id,
            tenant_id=tenant_id,
            parent_execution_id=parent_execution_id,
            root_execution_id=root_execution_id,
        )
        if translated is not None:
            out.append(translated)
    return out


# ─── Per-hook translators ─────────────────────────────────────────────


def _translate_one(
    *,
    capture: Dict[str, Any],
    execution_id: str,
    agent_id: str,
    session_id: Optional[str],
    tenant_id: Optional[str],
    parent_execution_id: Optional[str],
    root_execution_id: Optional[str],
) -> Optional[Dict[str, Any]]:
    """Dispatch a capture by its hook field. Wrapped by the public
    entrypoints for exception safety."""
    hook = capture.get("hook")
    if not isinstance(hook, str):
        return None

    # Centralized unmapped-hook table. The reasoning for each
    # exclusion lives in the module docstring.
    _UNMAPPED_HOOKS = {
        "on_user_message_callback",
        "before_run_callback",
        "after_run_callback",
        "after_model_callback",  # plan-governance side effect, not a discrete event
        "on_event_callback",
    }
    if hook in _UNMAPPED_HOOKS:
        return None

    if hook == "before_agent_callback":
        return _on_before_agent(
            capture,
            execution_id,
            agent_id,
            session_id,
            tenant_id,
            parent_execution_id,
            root_execution_id,
        )
    if hook == "after_agent_callback":
        return _on_after_agent(
            capture,
            execution_id,
            agent_id,
            session_id,
            tenant_id,
            parent_execution_id,
            root_execution_id,
        )
    if hook == "before_tool_callback":
        return _on_before_tool(
            capture,
            execution_id,
            agent_id,
            session_id,
            tenant_id,
            parent_execution_id,
            root_execution_id,
        )
    if hook == "after_tool_callback":
        return _on_after_tool(
            capture,
            execution_id,
            agent_id,
            session_id,
            tenant_id,
            parent_execution_id,
            root_execution_id,
        )
    if hook == "hosted_tool_observed":
        return _on_hosted_tool(
            capture,
            execution_id,
            agent_id,
            session_id,
            tenant_id,
            parent_execution_id,
            root_execution_id,
        )
    if hook == "before_model_callback":
        return _on_before_model(
            capture,
            execution_id,
            agent_id,
            session_id,
            tenant_id,
            parent_execution_id,
            root_execution_id,
        )
    if hook in (
        "on_tool_error_callback",
        "on_model_error_callback",
        "on_agent_error_callback",
    ):
        return _on_error(
            capture,
            execution_id,
            agent_id,
            session_id,
            tenant_id,
            parent_execution_id,
            root_execution_id,
        )
    # NOTE: there is deliberately no ``policy_decision`` arm.
    # ``policy_decision_made`` is SERVER-attested only (wl-apdp is the sole
    # decision authority) and is BLOCKED at ``/v1/events`` ingest, so the
    # plugin never produces that class.

    logger.debug("adk translator: unrecognized hook %s", hook)
    return None


def _on_before_agent(
    capture: Dict[str, Any],
    execution_id: str,
    agent_id: str,
    session_id: Optional[str],
    tenant_id: Optional[str],
    parent_execution_id: Optional[str],
    root_execution_id: Optional[str],
) -> Dict[str, Any]:
    """Agent execution begin → ExecutionStarted.

    Fires for the root run AND every nested sub-agent transfer (ADK
    re-enters ``before_agent_callback`` for each). The ``depth`` is
    FRAMEWORK-SOURCED: the plugin stamps the real spawn-tree depth on the
    capture (``len(_lineage_stack)`` at emit time — root 0, each nesting
    +1), never a literal. ``or 0`` is only the root default for a capture
    that omits the key; it is not a sub-agent fallback.
    """
    depth = int(capture.get("depth") or 0)
    intent_category = capture.get("intent_category")
    intent_objective = capture.get("intent_objective")
    # Provenance plumbing. The capture may carry an explicit
    # provenance string (the plugin's before_agent_callback resolves it
    # from declared > plugin_derived > absent). When absent we fall
    # back to the legacy behaviour (no provenance field on the payload,
    # which the canonical schema interprets as Absent).
    intent_provenance = capture.get("intent_provenance")

    payload: Dict[str, Any] = {
        # Canonical ``PrincipalRef`` shape — ``principal_type`` + ``id``.
        # wl-lineage's ``PrincipalRef`` requires
        # BOTH. The legacy ``{"agent_id": ...}`` shape fails to deserialize
        # at ``POST /v1/events`` and takes the WHOLE batch down with it
        # (422, ``IngestExecutionEventsRequest``), so the run never reaches
        # lineage at all.
        "principal": {"principal_type": "agent", "id": agent_id},
        "depth": depth,
    }
    if intent_category:
        payload["intent_category"] = str(intent_category)
    if intent_objective:
        truncated = _truncate_summary(intent_objective)
        if truncated:
            payload["intent_objective"] = truncated
            # When the caller didn't tell us the provenance,
            # infer Plugin-Derived: the only way a populated objective
            # reaches the translator without an explicit provenance is
            # via the plugin's framework-signal extraction lane. The
            # declared lane (start_run(intent_objective=…)) stamps
            # IntentProvenance.DECLARED explicitly.
            resolved_provenance = intent_provenance or IntentProvenance.PLUGIN_DERIVED.value
            payload["intent_provenance"] = resolved_provenance
    elif intent_provenance and intent_provenance != IntentProvenance.ABSENT.value:
        # Defensive: a non-Absent provenance with no objective would
        # violate the intent conformance invariant (a populated
        # objective and a non-Absent provenance must co-occur). Drop the
        # provenance rather than emit an inconsistent payload — the
        # canonical schema treats absence-of-provenance as
        # IntentProvenance.ABSENT.
        pass

    return _build_event(
        event_type=_EVENT_TYPE_STARTED,
        execution_id=execution_id,
        agent_id=agent_id,
        session_id=session_id,
        tenant_id=tenant_id,
        parent_execution_id=parent_execution_id,
        root_execution_id=root_execution_id,
        payload=payload,
        metadata={
            "source": _PROVENANCE_TAG,
            "agent_name": capture.get("agent_name"),
        },
    )


def _on_after_agent(
    capture: Dict[str, Any],
    execution_id: str,
    agent_id: str,
    session_id: Optional[str],
    tenant_id: Optional[str],
    parent_execution_id: Optional[str],
    root_execution_id: Optional[str],
) -> Dict[str, Any]:
    """Top-level agent execution end → ExecutionCompleted."""
    duration_ms = int(capture.get("duration_ms") or 0)
    actions_taken = int(capture.get("actions_taken") or 0)
    actions_denied = int(capture.get("actions_denied") or 0)
    outcome = capture.get("outcome")

    payload: Dict[str, Any] = {
        "duration_ms": duration_ms,
        "actions_taken": actions_taken,
        "actions_denied": actions_denied,
    }
    if outcome:
        payload["outcome"] = _truncate_summary(outcome)

    return _build_event(
        event_type=_EVENT_TYPE_COMPLETED,
        execution_id=execution_id,
        agent_id=agent_id,
        session_id=session_id,
        tenant_id=tenant_id,
        parent_execution_id=parent_execution_id,
        root_execution_id=root_execution_id,
        payload=payload,
        metadata={
            "source": _PROVENANCE_TAG,
        },
    )


def _on_before_tool(
    capture: Dict[str, Any],
    execution_id: str,
    agent_id: str,
    session_id: Optional[str],
    tenant_id: Optional[str],
    parent_execution_id: Optional[str],
    root_execution_id: Optional[str],
) -> Optional[Dict[str, Any]]:
    """Tool invocation about to begin — plan-stage signal.

    Emits a canonical ``PlanObserved`` event (was previously
    a ``ToolCallObserved`` with ``decision="planned"``, which
    conflated plan-stage signals with act-stage execution).

    ADK's ``before_tool_callback`` fires once per tool invocation, so
    ``plan_kind`` is ``incremental`` and ``intended_tools`` carries a
    single tool name. The wl-execution-graph correlator
    unions these across the execution to form the plan set.

    Returns ``None`` and logs at debug if the tool name fails
    validation — adversarial tool descriptions cannot form
    a malformed plan event.
    """
    tool_name = str(capture.get("tool_name") or "unknown")

    # Rationale = bounded, value-free summary of the tool args (argument
    # names and types only, never a value: raw arguments can carry
    # credentials or personal data). Operator legibility only; the
    # correlator never matches on it.
    tool_args = capture.get("tool_args")
    rationale: Optional[str] = None
    if tool_args is not None:
        summary = redacted_input_summary(tool_args)
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
        root_execution_id=root_execution_id,
        payload=payload,
        metadata={
            "source": _PROVENANCE_TAG,
            "tool_name": tool_name,
        },
    )


def _on_after_tool(
    capture: Dict[str, Any],
    execution_id: str,
    agent_id: str,
    session_id: Optional[str],
    tenant_id: Optional[str],
    parent_execution_id: Optional[str],
    root_execution_id: Optional[str],
) -> Dict[str, Any]:
    """Tool returned → ToolCallObserved (completed phase) with
    duration_ms."""
    tool_name = str(capture.get("tool_name") or "unknown")
    action_verb = str(capture.get("action_verb") or "invoke")
    duration_ms = capture.get("duration_ms")
    # Never a default decision: a call whose decision is unknown is
    # recorded without one, never as an Allow.
    decision = capture.get("decision")

    payload: Dict[str, Any] = {
        # Canonical ``ResourceRef`` — typed ``resource_type`` + ``identifier``,
        # with the framework-namespaced URI on ``endpoint``. A flattened
        # ``{"resource": "<uri>"}`` is not a ``ResourceRef`` and is rejected
        # at ingest.
        "tool": {
            "resource_type": "tool",
            "identifier": tool_name,
            "endpoint": f"{_RESOURCE_PREFIX_TOOL}{tool_name}",
        },
        "action": {"action": action_verb},
    }
    if isinstance(decision, str) and decision:
        payload["decision"] = decision
    if isinstance(duration_ms, (int, float)) and duration_ms >= 0:
        payload["duration_ms"] = int(duration_ms)
    # Sorted, comma-joined argument KEYS (never values) — the behavioural
    # feature Watchlight's drift detector consumes for arg-shape scoring.
    # Computed at capture time from the structured tool_args (see
    # plugin.after_tool_callback).
    arg_key_summary = capture.get("arg_key_summary")
    if arg_key_summary:
        payload["arg_key_summary"] = arg_key_summary

    return _build_event(
        event_type=_EVENT_TYPE_TOOL_CALL,
        execution_id=execution_id,
        agent_id=agent_id,
        session_id=session_id,
        tenant_id=tenant_id,
        parent_execution_id=parent_execution_id,
        root_execution_id=root_execution_id,
        payload=payload,
        metadata={
            "source": _PROVENANCE_TAG,
            "tool_name": tool_name,
            "phase": "completed",
            # "failed" when an allowed call's tool raised.
            "outcome": capture.get("outcome"),
        },
    )


def _on_hosted_tool(
    capture: Dict[str, Any],
    execution_id: str,
    agent_id: str,
    session_id: Optional[str],
    tenant_id: Optional[str],
    parent_execution_id: Optional[str],
    root_execution_id: Optional[str],
) -> Optional[Dict[str, Any]]:
    """A provider-hosted tool the model response shows ran →
    ToolCallObserved with the shared value-free payload
    (``watchlight_core.hosted_tool_observation``) and
    ``metadata.hosted_tool = true``."""
    payload = capture.get("hosted_payload")
    if not isinstance(payload, dict):
        return None
    return _build_event(
        event_type=_EVENT_TYPE_TOOL_CALL,
        execution_id=execution_id,
        agent_id=agent_id,
        session_id=session_id,
        tenant_id=tenant_id,
        parent_execution_id=parent_execution_id,
        root_execution_id=root_execution_id,
        payload=dict(payload),
        metadata={"source": _PROVENANCE_TAG, "hosted_tool": True, "phase": "completed"},
    )


def _on_before_model(
    capture: Dict[str, Any],
    execution_id: str,
    agent_id: str,
    session_id: Optional[str],
    tenant_id: Optional[str],
    parent_execution_id: Optional[str],
    root_execution_id: Optional[str],
) -> Dict[str, Any]:
    """LLM invocation began → ApiRequestObserved. Captures model
    identity + bounded prompt summary."""
    model_name = str(capture.get("model") or "unknown")
    prompt_summary = capture.get("prompt_summary")
    if prompt_summary is not None:
        prompt_summary = _truncate_summary(prompt_summary)

    payload: Dict[str, Any] = {
        # ``ApiRequestObservedPayload.resource`` carries the same canonical
        # ``ResourceRef`` shape as ``tool`` above.
        "resource": {
            "resource_type": "llm_api",
            "identifier": model_name,
            "endpoint": f"{_RESOURCE_PREFIX_LLM}{model_name}",
        },
        "method": "POST",
        "path": "/completion",
    }

    return _build_event(
        event_type=_EVENT_TYPE_API_REQUEST,
        execution_id=execution_id,
        agent_id=agent_id,
        session_id=session_id,
        tenant_id=tenant_id,
        parent_execution_id=parent_execution_id,
        root_execution_id=root_execution_id,
        payload=payload,
        metadata={
            "source": _PROVENANCE_TAG,
            "model": model_name,
            "prompt_summary": prompt_summary,
        },
    )


def _on_error(
    capture: Dict[str, Any],
    execution_id: str,
    agent_id: str,
    session_id: Optional[str],
    tenant_id: Optional[str],
    parent_execution_id: Optional[str],
    root_execution_id: Optional[str],
) -> Dict[str, Any]:
    """Any ADK error callback → ExecutionFailed with bounded
    error message."""
    error_obj = capture.get("error")
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
        root_execution_id=root_execution_id,
        payload={
            "error": error_excerpt,
            # ``ExecutionFailedPayload`` models the error CATEGORY as
            # ``error_type``. The old ``error_code`` key is not a field on
            # the server struct, so serde dropped it silently and the class
            # never reached lineage.
            "error_type": type(error_obj).__name__ if error_obj is not None else None,
        },
        metadata={
            "source": _PROVENANCE_TAG,
            "hook": capture.get("hook"),
        },
    )


# ─── Helpers ───────────────────────────────────────────────────────────


def _truncate_summary(value: Any) -> Optional[str]:
    """Coerce arbitrary value to bounded string. 120-char cap
    matches the LangGraph and Bedrock plugins for cross-plugin parity."""
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
    root_execution_id: Optional[str],
    payload: Dict[str, Any],
    metadata: Dict[str, Any],
) -> Dict[str, Any]:
    """Construct one ExecutionEvent dict matching the canonical
    flat-envelope JSON shape expected by wl-apdp /v1/events.

    Wire contract: field names + nesting MUST match the canonical
    ``ExecutionEvent`` wire format APDP expects exactly. Cross-plugin
    conformance with the LangGraph and Bedrock plugins is pinned by
    the cross-plugin conformance test suite.
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
    if root_execution_id is not None:
        envelope["root_execution_id"] = root_execution_id
    cleaned_metadata = {k: v for k, v in metadata.items() if v not in (None, "")}
    if cleaned_metadata:
        envelope["metadata"] = cleaned_metadata
    return {**envelope, "payload": payload}
