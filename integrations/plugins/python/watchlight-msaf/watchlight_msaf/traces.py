"""Translate Microsoft Agent Framework (MAF) lifecycle events into
canonical Watchlight :class:`ExecutionEvent` dicts.

# Overview

MAF exposes a middleware + observability hook surface around three
primitives:

- **ChatAgent** — single-turn or multi-turn conversation agent
- **Workflow** — orchestration of one or more agents + tools
- **Tool** — invokable capability surfaced to the agent

Like the other framework plugins (``watchlight-langgraph``,
``watchlight-adk``, ``watchlight-bedrock``), this translator is a
pure function that takes a capture dict and returns at most one
canonical event. The actual MAF middleware shim — which produces the
capture dicts from MAF's hook callbacks — is a separate optional
install (``pip install watchlight-msaf[msaf]``) that lands in a
follow-up release once MAF's post-GA hook API stabilises.

# Hook mapping

==============================  ==========================  =================================
MAF observability hook          Agentic stage               Canonical Watchlight event
==============================  ==========================  =================================
``workflow_run_start``          Plan (top-level only)       ``ExecutionStarted``
``workflow_run_complete``       Observe (terminal)          ``ExecutionCompleted``
``workflow_run_error``          Observe (failure)           ``ExecutionFailed``
``agent_step_start``            Plan                        ``ExecutionStarted`` (sub-agent, when ``parent_run_id`` set)
``agent_step_complete``         Observe                     ``ExecutionCompleted`` (sub-agent)
``tool_invocation_start``       Plan                        ``PlanObserved`` (incremental kind, one tool per event)
``tool_invocation_complete``    Observe                     ``ToolCallObserved`` with ``input_summary`` + ``duration_ms``
``chat_completion_request``     Act                         ``ApiRequestObserved`` (LLM call)
``chat_completion_complete``    Observe                     ``ApiRequestObserved`` with ``response_status`` + ``duration_ms``
==============================  ==========================  =================================

Hooks deliberately NOT emitted (with reasoning):

- ``token_stream`` — streaming-token events; would emit hundreds per
  completion. Captured via OTLP aggregation in a follow-up release.
- ``durable_checkpoint`` — DurableExecution checkpoints; deferred
  until MAF GA-locks the schema. Tracked separately so operators
  can opt in once they need persistent-workflow audit.
- ``multi_agent_handoff`` — fanned-out delegation FSM; deferred
  until there is user feedback on which fields need to be surfaced
  (the raw payload changes between MAF minor versions).

# Determinism

Given the same sequence of captures, the translator produces the
same ordered list of canonical events (modulo fresh ``event_id``
UUIDs). Required for SOC 2 CC7.x replayability + EU AI Act Annex IV
traceability — same posture as the other framework plugins.

# Failure modes

Malformed captures (missing fields, unexpected types) are logged at
``debug`` and skipped. The translator never raises. Partial coverage
beats no coverage when MAF ships a hook-shape change.

# Bounded per-event size

All free-form fields (tool args, error messages) are capped at the
same limits as the other plugins (120 chars for input summaries,
512 chars for error messages, 1024 bytes for plan rationale). An
attacker-controlled MAF tool input cannot inflate per-event audit
log size.
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
    summarize_arg_keys,
)

from .intent import extract_intent_from_messages

logger = get_logger(__name__)


# ─── Canonical event schema constants ─────────────────────────────────
#
# Wire-format discriminator strings — lowercase snake_case, matching
# the canonical event schema the Watchlight lineage pipeline expects.

_EVENT_TYPE_STARTED = "execution_started"
_EVENT_TYPE_COMPLETED = "execution_completed"
_EVENT_TYPE_FAILED = "execution_failed"
_EVENT_TYPE_TOOL_CALL = "tool_call_observed"
_EVENT_TYPE_API_REQUEST = "api_request_observed"
# MAF's per-tool pre-invocation hook becomes a canonical PlanObserved
# event — the same mapping the LangGraph, Bedrock, and ADK plugins use.
_EVENT_TYPE_PLAN = "plan_observed"

# Resource ref prefixes — namespaced by framework so downstream
# consumers can distinguish ``msaf://tool/...`` from
# ``langgraph://tool/...``, ``adk://tool/...``, or
# ``bedrock://tool/...`` without special-casing.

_RESOURCE_PREFIX_TOOL = "msaf://tool/"
_RESOURCE_PREFIX_LLM = "msaf://llm/"
_RESOURCE_PREFIX_WORKFLOW = "msaf://workflow/"

# Bounded sizes — matched to the LangGraph, Bedrock, and ADK plugins
# for cross-plugin shape consistency. Cross-plugin conformance tests
# pin these.
_MAX_INPUT_SUMMARY_LEN = 120
_MAX_ERROR_MESSAGE_LEN = 512

# Source attribution for provenance binding. Every event carries this
# tag under metadata.source so downstream consumers can attribute
# events (and detect fabrication). Distinct from the other plugins'
# tags — the value is part of the cross-plugin contract.
_PROVENANCE_TAG = "msaf.callback"


# ─── Public API ────────────────────────────────────────────────────────


def translate_msaf_event(
    *,
    capture: Dict[str, Any],
    execution_id: str,
    agent_id: str,
    session_id: Optional[str] = None,
    tenant_id: Optional[str] = None,
    parent_execution_id: Optional[str] = None,
    root_execution_id: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """Translate a single MAF capture into one canonical
    :class:`ExecutionEvent` dict (or ``None`` if the hook isn't
    mapped or the capture is malformed).

    Args:
        capture: A capture dict produced by the MAF middleware shim.
            Schema: ``{"hook": "<hook_name>", ...hook-specific fields...}``.
        execution_id: Watchlight execution id.
        agent_id: Watchlight agent UUID.
        session_id: Optional Watchlight session id.
        tenant_id: Optional tenant id for multi-tenant routing.
        parent_execution_id: Optional parent execution id (nested
            MAF sub-agent runs).
        root_execution_id: Optional root of the execution tree.

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
            "msaf translator skipped capture %s due to %s: %s",
            capture.get("hook"),
            type(exc).__name__,
            exc,
        )
        return None


def translate_msaf_events(
    *,
    captures: List[Dict[str, Any]],
    execution_id: str,
    agent_id: str,
    session_id: Optional[str] = None,
    tenant_id: Optional[str] = None,
    parent_execution_id: Optional[str] = None,
    root_execution_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Batch-translate a list of MAF captures. Order preserved;
    unmapped or malformed captures silently dropped. Same posture
    as the other framework plugins' batch translators."""
    out: List[Dict[str, Any]] = []
    for cap in captures:
        translated = translate_msaf_event(
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


# ─── Per-hook dispatch ────────────────────────────────────────────────


# Hooks that are deliberately unmapped — see module docstring for the
# rationale on each.
_UNMAPPED_HOOKS = {
    "token_stream",
    "durable_checkpoint",
    "multi_agent_handoff",
}


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
    hook = capture.get("hook")
    if not isinstance(hook, str):
        return None
    if hook in _UNMAPPED_HOOKS:
        return None

    args = (
        capture,
        execution_id,
        agent_id,
        session_id,
        tenant_id,
        parent_execution_id,
        root_execution_id,
    )

    if hook in ("workflow_run_start", "agent_step_start"):
        return _on_run_start(*args)
    if hook in ("workflow_run_complete", "agent_step_complete"):
        return _on_run_complete(*args)
    if hook == "workflow_run_error":
        return _on_run_error(*args)
    if hook == "tool_invocation_start":
        return _on_tool_start(*args)
    if hook == "tool_invocation_complete":
        return _on_tool_complete(*args)
    if hook in ("chat_completion_request", "chat_completion_complete"):
        return _on_chat(*args)

    return None


# ─── Per-hook translators ─────────────────────────────────────────────


def _on_run_start(
    capture: Dict[str, Any],
    execution_id: str,
    agent_id: str,
    session_id: Optional[str],
    tenant_id: Optional[str],
    parent_execution_id: Optional[str],
    root_execution_id: Optional[str],
) -> Optional[Dict[str, Any]]:
    """workflow_run_start / agent_step_start → ExecutionStarted.

    For agent_step_start with a ``parent_run_id`` set, this fires
    a nested ExecutionStarted — the same shape LangGraph + ADK use
    for sub-agent spawns.

    Intent precedence chain (declared > plugin_derived > absent). The
    capture may carry:

    - ``intent_objective``: a pre-resolved string the (not yet
      shipped) middleware shim extracted from the user's
      ``ChatAgent`` invocation. When set, treated as plugin-derived
      unless the capture also carries ``intent_provenance``.
    - ``intent_provenance``: the explicit enum string (``declared``,
      ``plugin_derived``, ``proxy_inferred``, ``absent``). The
      declared lane stamps this verbatim.
    - ``messages``: an MSAF message list. When ``intent_objective``
      is absent but ``messages`` is present, the in-process
      extractor (:func:`.intent.extract_intent_from_messages`) is
      consulted as a fallback so the shim can hand off raw messages
      rather than re-implementing extraction.

    Absent everything: the canonical payload omits both fields, which
    Cedar treats as :attr:`IntentProvenance.ABSENT`.
    """
    declared_objective_raw = capture.get("intent_objective")
    explicit_provenance = capture.get("intent_provenance")
    intent_objective: Optional[str] = _bounded(declared_objective_raw, _MAX_INPUT_SUMMARY_LEN)

    # Fallback extraction path — the middleware shim may forward the
    # MSAF ``messages`` list directly rather than pre-extracting on
    # its side. When ``intent_objective`` was not pre-resolved, walk
    # the list ourselves. A future shim can use either lane; the
    # contract on this translator is the same.
    derived_from_messages = False
    if not intent_objective:
        extracted = extract_intent_from_messages(capture.get("messages"))
        if extracted:
            intent_objective = extracted
            derived_from_messages = True

    # FRAMEWORK-SOURCED spawn-tree depth — never a literal. watchlight-msaf
    # is a pure, stateless translator (it holds no lifecycle stack of its
    # own), so the MSAF middleware shim MUST stamp the real depth on the
    # capture: 0 for the root run, +1 per nested ``agent_step_start`` whose
    # ``parent_run_id`` is set. The translator passes it through verbatim
    # (wl-execution-graph stores ``payload.depth`` as-is), so a sub-agent
    # renders at its real DEPTH. The guard below is only the root default
    # for a capture that omits the key; a sub-agent (this function was
    # called with a ``parent_execution_id``, i.e. an agent_step_start with
    # a parent) that also omits depth is at least one level deep, so we
    # floor it to 1 rather than mis-render it as the root.
    depth = capture.get("depth")
    if not isinstance(depth, int) or depth < 0:
        depth = 1 if parent_execution_id else 0
    payload: Dict[str, Any] = {
        # Canonical ``PrincipalRef`` shape — ``principal_type`` + ``id``.
        # wl-lineage's ``PrincipalRef`` requires
        # BOTH, and derives the Cedar reference (``Agent::"<id>"``) itself.
        # Emitting a pre-rendered Cedar string here fails to deserialize at
        # ``POST /v1/events`` and takes the WHOLE batch down with it (422,
        # ``IngestExecutionEventsRequest``), so the run never reaches
        # lineage at all.
        "principal": {"principal_type": "agent", "id": agent_id},
        "depth": depth,
    }
    if intent_objective:
        payload["intent_objective"] = intent_objective
        # Resolve provenance: explicit string from the capture wins,
        # otherwise plugin-derived (the only path that lands an
        # objective without an explicit provenance is the framework-
        # signal extraction).
        if isinstance(explicit_provenance, str) and explicit_provenance:
            payload["intent_provenance"] = explicit_provenance
        else:
            payload["intent_provenance"] = IntentProvenance.PLUGIN_DERIVED.value
    # A non-Absent provenance without an objective is inconsistent —
    # drop the orphan rather than emit a payload that fails downstream
    # validation.
    if isinstance(capture.get("intent_category"), str):
        payload["intent_category"] = capture["intent_category"]
    # Touch the local for type-checkers; the value is informational
    # only (left in place so a future follow-up can log/metric on
    # message-derived intent without re-deriving).
    _ = derived_from_messages

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
            "hook": capture.get("hook"),
        },
    )


def _on_run_complete(
    capture: Dict[str, Any],
    execution_id: str,
    agent_id: str,
    session_id: Optional[str],
    tenant_id: Optional[str],
    parent_execution_id: Optional[str],
    root_execution_id: Optional[str],
) -> Optional[Dict[str, Any]]:
    """workflow_run_complete / agent_step_complete → ExecutionCompleted."""
    duration_ms = _to_int(capture.get("duration_ms")) or 0
    actions_taken = _to_int(capture.get("actions_taken")) or 0
    outcome = _bounded(capture.get("outcome"), _MAX_INPUT_SUMMARY_LEN)
    payload: Dict[str, Any] = {
        "duration_ms": duration_ms,
        "actions_taken": actions_taken,
        "actions_denied": _to_int(capture.get("actions_denied")) or 0,
    }
    if outcome:
        payload["outcome"] = outcome
    tools_used = capture.get("tools_used")
    if isinstance(tools_used, list):
        payload["tools_used"] = [t for t in tools_used if isinstance(t, str)]

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
            "hook": capture.get("hook"),
        },
    )


def _on_run_error(
    capture: Dict[str, Any],
    execution_id: str,
    agent_id: str,
    session_id: Optional[str],
    tenant_id: Optional[str],
    parent_execution_id: Optional[str],
    root_execution_id: Optional[str],
) -> Optional[Dict[str, Any]]:
    """workflow_run_error → ExecutionFailed."""
    error_obj = capture.get("error")
    # Value-free: the exception class only, never its message.
    error_msg = _bounded(redacted_error_summary(error_obj), _MAX_ERROR_MESSAGE_LEN) or "unknown"

    payload: Dict[str, Any] = {
        "error": error_msg,
        "policy_denied": bool(capture.get("policy_denied", False)),
    }
    if isinstance(capture.get("error_type"), str):
        payload["error_type"] = capture["error_type"]
    duration_ms = _to_int(capture.get("duration_ms"))
    if duration_ms is not None:
        payload["duration_ms"] = duration_ms

    return _build_event(
        event_type=_EVENT_TYPE_FAILED,
        execution_id=execution_id,
        agent_id=agent_id,
        session_id=session_id,
        tenant_id=tenant_id,
        parent_execution_id=parent_execution_id,
        root_execution_id=root_execution_id,
        payload=payload,
        metadata={
            "source": _PROVENANCE_TAG,
            "hook": capture.get("hook"),
        },
    )


def _on_tool_start(
    capture: Dict[str, Any],
    execution_id: str,
    agent_id: str,
    session_id: Optional[str],
    tenant_id: Optional[str],
    parent_execution_id: Optional[str],
    root_execution_id: Optional[str],
) -> Optional[Dict[str, Any]]:
    """tool_invocation_start → PlanObserved (incremental).

    MAF's tool middleware fires once per tool invocation, so this
    emits a single-tool plan event. Invalid tool names (e.g. names
    with shell metacharacters) drop the event silently, the same as
    the other plugins.
    """
    tool_name = str(capture.get("tool_name") or "unknown")
    tool_args = capture.get("tool_args")
    rationale: Optional[str] = None
    if tool_args is not None:
        # Value-free: argument names and value types only.
        rationale = redacted_input_summary(tool_args)

    try:
        payload = build_plan_payload(
            intended_tools=[tool_name],
            plan_kind=PlanKind.INCREMENTAL,
            rationale=rationale,
        )
    except PlanValidationError as exc:
        logger.debug("msaf plan_observed dropped: %s", exc)
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


def _on_tool_complete(
    capture: Dict[str, Any],
    execution_id: str,
    agent_id: str,
    session_id: Optional[str],
    tenant_id: Optional[str],
    parent_execution_id: Optional[str],
    root_execution_id: Optional[str],
) -> Optional[Dict[str, Any]]:
    """tool_invocation_complete → ToolCallObserved with duration."""
    tool_name = str(capture.get("tool_name") or "unknown")
    action_verb = str(capture.get("action_verb") or "invoke")
    duration_ms = _to_int(capture.get("duration_ms"))
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
    if isinstance(decision, str):
        payload["decision"] = decision
    if duration_ms is not None:
        payload["duration_ms"] = duration_ms
    tool_args = capture.get("tool_args")
    if tool_args is not None:
        # Value-free: argument names and value types, never a value.
        summary = redacted_input_summary(tool_args)
        if summary:
            payload["input_summary"] = summary
        # Sorted, comma-joined argument KEYS (never values) — the
        # behavioural feature Watchlight's argument-shape drift
        # detection consumes. None when tool_args isn't a structured
        # mapping.
        arg_key_summary = summarize_arg_keys(tool_args)
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
        },
    )


def _on_chat(
    capture: Dict[str, Any],
    execution_id: str,
    agent_id: str,
    session_id: Optional[str],
    tenant_id: Optional[str],
    parent_execution_id: Optional[str],
    root_execution_id: Optional[str],
) -> Optional[Dict[str, Any]]:
    """chat_completion_request / chat_completion_complete →
    ApiRequestObserved.

    Models are addressed under the ``msaf://llm/`` scheme; the host
    is the model name (so a request to Azure OpenAI gpt-4o lands as
    ``msaf://llm/gpt-4o`` regardless of the actual endpoint URL).
    """
    model = str(capture.get("model") or "unknown")
    duration_ms = _to_int(capture.get("duration_ms"))
    response_status = _to_int(capture.get("response_status"))

    payload: Dict[str, Any] = {
        # ``ApiRequestObservedPayload.resource`` carries the same canonical
        # ``ResourceRef`` shape as ``tool`` above.
        "resource": {
            "resource_type": "llm_api",
            "identifier": model,
            "endpoint": f"{_RESOURCE_PREFIX_LLM}{model}",
        },
        "method": "POST",
        "path": "/v1/chat/completions",
        "fields_scrubbed": 0,
        "pii_redacted": 0,
    }
    if duration_ms is not None:
        payload["duration_ms"] = duration_ms
    if response_status is not None:
        payload["response_status"] = response_status

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
            "model": model,
            "phase": "completed" if capture.get("hook") == "chat_completion_complete" else "request",
        },
    )


# ─── Helpers ──────────────────────────────────────────────────────────


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
    """Assemble the canonical envelope. Cross-plugin contract —
    every event must carry:
    event_id, event_type, timestamp, execution_id, agent_id, payload.

    Optional envelope fields included when set: session_id,
    tenant_id, parent_execution_id, root_execution_id, metadata.
    """
    event: Dict[str, Any] = {
        "event_id": f"evt_{uuid.uuid4()}",
        "event_type": event_type,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "execution_id": execution_id,
        "agent_id": agent_id,
        "payload": payload,
        "metadata": metadata,
    }
    if session_id is not None:
        event["session_id"] = session_id
    if tenant_id is not None:
        event["tenant_id"] = tenant_id
    if parent_execution_id is not None:
        event["parent_execution_id"] = parent_execution_id
    if root_execution_id is not None:
        event["root_execution_id"] = root_execution_id
    return event


def _bounded(s: Any, max_chars: int) -> Optional[str]:
    """Truncate any value to a bounded string. Returns None for None
    or empty inputs. Defensive cap mirrors the other plugins."""
    if s is None:
        return None
    text = str(s)
    if not text:
        return None
    return text[:max_chars]


def _to_int(value: Any) -> Optional[int]:
    """Coerce a captured value to int. Returns None on failure —
    MAF callback payloads sometimes carry ints as strings."""
    if value is None:
        return None
    if isinstance(value, bool):
        # bool is a subclass of int — Python footgun; reject so a
        # boolean tool_args slip doesn't get serialised as 0/1 in
        # the duration_ms field.
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return None
    return None
