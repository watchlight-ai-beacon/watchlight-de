"""Translate AWS Bedrock Agents ``agentTrace`` payloads into canonical
Watchlight :class:`ExecutionEvent` dicts.

# Overview

Bedrock Agents emit reasoning + tool-invocation traces in the
streaming response of ``bedrock-agent-runtime.invoke_agent``. Each
stream chunk may include a ``trace`` field with structured sub-types:

==========================  =================================================
Bedrock trace sub-type      Canonical Watchlight event
==========================  =================================================
``orchestrationTrace``
  ↳ ``actionGroupInvocationInput``     → ``ToolCallObserved``
  ↳ ``knowledgeBaseLookupInput``       → ``ToolCallObserved``
  ↳ ``agentCollaboratorInvocationInput``  → dropped (see below)
``failureTrace``                       → ``ExecutionFailed``
==========================  =================================================

Spawn attestation is SERVER-emitted only: wl-apdp's ``spawn_handler``
mints the authoritative ``agent_spawn_observed`` for spawns routed
through the governed ``spawn_subagent`` chokepoint, and a
plugin-emitted ``agent_spawn_observed`` is REJECTED at ``/v1/events``
ingest. Bedrock collaborator invocations are native to Bedrock's
multi-agent orchestration and are NOT routed through ``spawn_subagent``,
so this translator DROPS them rather than emitting a rejected event.

Bedrock's planning is internal — the agent's plan is opaque to us
even with full trace coverage. This translator therefore produces
**observe-stage** coverage: we see what the agent decided to do
after it decided, not the deliberation itself.

# Determinism

The translation is a pure function of the response payload. Given
the same ``response`` dict, the same translation runs produce the
same ordered list of events (event IDs are generated fresh, but
otherwise the wire-shape is identical). Required for replay + SOC 2
CC7.x audit evidence.

# Failure modes

A malformed trace entry — missing fields, unexpected shape from a
future Bedrock SDK revision — is logged at ``debug`` and skipped.
The translator never raises on malformed input. We prefer
**partial coverage** over **no coverage** when the upstream SDK
ships shape changes.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from watchlight_core import (
    PlanKind,
    PlanValidationError,
    build_plan_payload,
    get_logger,
    redacted_input_summary,
    summarize_arg_keys,
)

logger = get_logger(__name__)


# ─── Canonical event schema constants ─────────────────────────────────
#
# These string values are the wire format expected by ``wl-apdp``'s
# ``/v1/events`` endpoint and by every downstream consumer
# (``wl-execution-graph``, SIEM exporters, drift detection). The
# discriminator is lowercase snake_case.

_EVENT_TYPE_TOOL_CALL = "tool_call_observed"
_EVENT_TYPE_EXECUTION_FAILED = "execution_failed"
# Canonical plan event. Emitted alongside each tool_call_observed when
# the orchestrationTrace chunk carries a rationale, signalling the
# agent has decided to act. Bedrock's rationale-then-invocationInput
# sequence makes the plan signal incremental (one per action), not
# upfront — preProcessingTrace's parsedResponse is free-form text and
# unsafe to parse as a structured plan list. The wl-execution-graph
# correlator unions plan events per execution to form the allowed-tools
# set.
_EVENT_TYPE_PLAN = "plan_observed"

# Resource and action refs — short, grep-friendly. Match the format
# emitted by ``wl-proxy`` so downstream consumers don't need
# per-source quirks.

_RESOURCE_PREFIX_BEDROCK_TOOL = "bedrock://tool/"
_RESOURCE_PREFIX_BEDROCK_KB = "bedrock://knowledge-base/"


# ─── Public API ────────────────────────────────────────────────────────


def translate_bedrock_trace(
    *,
    response: Dict[str, Any],
    execution_id: str,
    agent_id: str,
    session_id: Optional[str] = None,
    tenant_id: Optional[str] = None,
    parent_execution_id: Optional[str] = None,
    root_execution_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Translate a Bedrock ``InvokeAgent`` response into a list of
    canonical ``ExecutionEvent`` dicts.

    Args:
        response: The ``invoke_agent`` boto3 response dict. May or may
            not include trace data; an empty ``completion`` field
            yields an empty event list.
        execution_id: The Watchlight execution_id (typically
            ``RunHandle.execution_id``).
        agent_id: The Watchlight agent UUID (typically
            ``RunHandle.agent_uuid``).
        session_id: Optional Watchlight session id for correlation.
        tenant_id: Optional tenant id for multi-tenant routing.
        parent_execution_id: Optional parent execution id (for
            nested runs spawned via ``submit_plan``).

    Returns:
        Ordered list of ``ExecutionEvent`` dicts. Order matches the
        order the traces appeared in the Bedrock stream. Empty list
        if no recognizable traces are present.

    Never raises. Malformed individual traces are skipped with a
    debug log; the rest of the response continues to translate.
    """
    chunks = _collect_trace_chunks(response)
    events: List[Dict[str, Any]] = []
    for chunk in chunks:
        try:
            # A single Bedrock chunk can yield multiple canonical
            # events — an orchestration chunk with both
            # a rationale and an invocationInput produces a
            # plan_observed followed by a tool_call_observed so the
            # plan-vs-act correlator sees them in order.
            evs = _translate_chunk(
                chunk=chunk,
                execution_id=execution_id,
                agent_id=agent_id,
                session_id=session_id,
                tenant_id=tenant_id,
                parent_execution_id=parent_execution_id,
                root_execution_id=root_execution_id,
            )
            events.extend(evs)
        except Exception as exc:  # noqa: BLE001 — defensive on upstream-shape drift
            logger.debug(
                "bedrock trace translation skipped a chunk due to %s: %s",
                type(exc).__name__,
                exc,
            )
    return events


# ─── Internal helpers ──────────────────────────────────────────────────


def _collect_trace_chunks(response: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Walk the response shape and yield each ``trace`` dict.

    Bedrock's response can carry traces in two shapes depending on
    whether the SDK call was streaming or whether the caller pre-
    consumed the stream:

    1. **Stream-consumed**: ``response["completion"]`` is a list of
       chunk dicts, each potentially carrying ``{"trace": {...}}``.
       This is the shape ``RunHandle.publish_trace`` sees when the
       caller has iterated through the EventStream.
    2. **Raw response**: ``response["trace"]`` directly — observed
       in some non-streaming endpoint variants.

    We handle both. Unknown shapes return an empty list rather
    than raising.
    """
    chunks: List[Dict[str, Any]] = []

    # Shape 1: stream-consumed (``completion`` is a list of chunks).
    completion = response.get("completion")
    if isinstance(completion, list):
        for chunk in completion:
            if isinstance(chunk, dict) and isinstance(chunk.get("trace"), dict):
                trace = chunk["trace"]
                # The trace dict itself may have an outer
                # ``trace`` key (Bedrock's structure is a bit
                # nested — payload sits under
                # ``chunk["trace"]["trace"]`` per the SDK schema).
                inner = trace.get("trace") if "trace" in trace else trace
                if isinstance(inner, dict):
                    chunks.append(inner)

    # Shape 2: raw response (less common).
    raw_trace = response.get("trace")
    if isinstance(raw_trace, dict):
        inner = raw_trace.get("trace") if "trace" in raw_trace else raw_trace
        if isinstance(inner, dict):
            chunks.append(inner)

    return chunks


def _translate_chunk(
    *,
    chunk: Dict[str, Any],
    execution_id: str,
    agent_id: str,
    session_id: Optional[str],
    tenant_id: Optional[str],
    parent_execution_id: Optional[str],
    root_execution_id: Optional[str],
) -> List[Dict[str, Any]]:
    """Translate one trace chunk into zero or more ExecutionEvents.

    The recognized sub-types are mutually exclusive within a single
    trace chunk per Bedrock's schema (the trace dict contains
    exactly one of orchestrationTrace, failureTrace, etc.). Most
    chunks yield exactly one event; orchestration chunks that
    contain both a rationale and an invocationInput yield two — a
    plan_observed followed by the tool_call_observed.
    Unrecognized sub-types yield an empty list — the caller skips
    silently.
    """
    if "failureTrace" in chunk:
        ev = _translate_failure_trace(
            failure=chunk["failureTrace"],
            execution_id=execution_id,
            agent_id=agent_id,
            session_id=session_id,
            tenant_id=tenant_id,
            parent_execution_id=parent_execution_id,
            root_execution_id=root_execution_id,
        )
        return [ev] if ev is not None else []

    if "orchestrationTrace" in chunk:
        return _translate_orchestration_trace(
            orchestration=chunk["orchestrationTrace"],
            execution_id=execution_id,
            agent_id=agent_id,
            session_id=session_id,
            tenant_id=tenant_id,
            parent_execution_id=parent_execution_id,
            root_execution_id=root_execution_id,
        )

    # preProcessingTrace, postProcessingTrace, guardrailTrace,
    # customOrchestrationTrace: not emitted as discrete events in
    # v1. They land in the audit chain via the per-call trace dump
    # already captured by wl-apdp; promoting them to explicit
    # events is a follow-up that requires adding new canonical
    # event-type variants.
    return []


def _translate_orchestration_trace(
    *,
    orchestration: Dict[str, Any],
    execution_id: str,
    agent_id: str,
    session_id: Optional[str],
    tenant_id: Optional[str],
    parent_execution_id: Optional[str],
    root_execution_id: Optional[str],
) -> List[Dict[str, Any]]:
    """Translate an orchestrationTrace sub-payload.

    The interesting fields are ``invocationInput`` (the agent
    decided to call something) and ``observation`` (the call
    returned). For v1 we emit on ``invocationInput`` so the event
    timestamps the *decision* to invoke; the return-value
    observation is captured in the trace audit but not promoted to
    an explicit event yet.

    When the chunk's invocation produces a tool/KB call
    (i.e., names a tool), emit a ``plan_observed`` event first so
    the wl-execution-graph correlator sees the plan signal in
    order. Collaborator-spawn invocations don't get a plan event —
    spawning a sub-agent is a different control signal from calling
    a tool.
    """
    invocation = orchestration.get("invocationInput")
    if not isinstance(invocation, dict):
        return []

    rationale = _extract_rationale(orchestration)

    # actionGroupInvocationInput → PlanObserved + ToolCallObserved.
    if "actionGroupInvocationInput" in invocation:
        events: List[Dict[str, Any]] = []
        tool_name = _action_group_plan_name(invocation["actionGroupInvocationInput"])
        if tool_name is not None:
            plan_ev = _build_plan_event(
                tool_name=tool_name,
                rationale=rationale,
                execution_id=execution_id,
                agent_id=agent_id,
                session_id=session_id,
                tenant_id=tenant_id,
                parent_execution_id=parent_execution_id,
                root_execution_id=root_execution_id,
            )
            if plan_ev is not None:
                events.append(plan_ev)
        events.append(
            _translate_action_group_invocation(
                input_=invocation["actionGroupInvocationInput"],
                execution_id=execution_id,
                agent_id=agent_id,
                session_id=session_id,
                tenant_id=tenant_id,
                parent_execution_id=parent_execution_id,
                root_execution_id=root_execution_id,
            )
        )
        return events

    # knowledgeBaseLookupInput → PlanObserved + ToolCallObserved.
    if "knowledgeBaseLookupInput" in invocation:
        events = []
        kb_name = _kb_plan_name(invocation["knowledgeBaseLookupInput"])
        if kb_name is not None:
            plan_ev = _build_plan_event(
                tool_name=kb_name,
                rationale=rationale,
                execution_id=execution_id,
                agent_id=agent_id,
                session_id=session_id,
                tenant_id=tenant_id,
                parent_execution_id=parent_execution_id,
                root_execution_id=root_execution_id,
            )
            if plan_ev is not None:
                events.append(plan_ev)
        events.append(
            _translate_kb_lookup(
                lookup=invocation["knowledgeBaseLookupInput"],
                execution_id=execution_id,
                agent_id=agent_id,
                session_id=session_id,
                tenant_id=tenant_id,
                parent_execution_id=parent_execution_id,
                root_execution_id=root_execution_id,
            )
        )
        return events

    # agentCollaboratorInvocationInput → dropped. Spawn attestation is
    # SERVER-emitted only: wl-apdp's ``spawn_handler`` mints the
    # authoritative ``agent_spawn_observed`` for spawns routed through
    # the governed ``spawn_subagent`` chokepoint. A plugin-emitted
    # ``agent_spawn_observed`` is REJECTED at ``/v1/events`` ingest
    # (``lineage_event_class_not_permitted``). Bedrock collaborator
    # invocations are native to Bedrock's multi-agent orchestration and do
    # NOT route through ``spawn_subagent``, so this observational signal
    # is dropped rather than emitted as a rejected event.
    if "agentCollaboratorInvocationInput" in invocation:
        return []

    # codeInterpreterInvocationInput, etc. — not in v1.
    return []


# ─── plan-event helpers ──────────────────────────────────────────────


def _extract_rationale(orchestration: Dict[str, Any]) -> Optional[str]:
    """Pull the agent's reasoning text from an orchestration chunk.

    Bedrock places it at ``rationale.text``. Operator-legibility
    only; the correlator never matches on it.
    """
    rat = orchestration.get("rationale")
    if isinstance(rat, dict):
        text = rat.get("text")
        if isinstance(text, str) and text.strip():
            return text
    return None


def _action_group_plan_name(input_: Dict[str, Any]) -> Optional[str]:
    """Derive a canonical plan-event tool name from an action-group
    invocation. The name must satisfy
    ``PLAN_TOOL_NAME_RE`` — see watchlight_core.plan_event. We use
    the action_group + function form (e.g.
    ``payments.transfer_funds``) so multiple functions under one
    action group remain distinguishable in plan-vs-act comparisons.
    """
    group = str(input_.get("actionGroupName") or "").strip()
    fn = str(input_.get("function") or "").strip()
    if not group:
        return None
    return f"{group}.{fn}" if fn else group


def _kb_plan_name(lookup: Dict[str, Any]) -> Optional[str]:
    """Derive a canonical plan-event tool name from a knowledge-base
    lookup. Format: ``kb.<knowledgeBaseId>``. The KB id from Bedrock
    is alphanumeric so it satisfies the canonical regex without
    further sanitization."""
    kb_id = str(lookup.get("knowledgeBaseId") or "").strip()
    if not kb_id:
        return None
    return f"kb.{kb_id}"


def _build_plan_event(
    *,
    tool_name: str,
    rationale: Optional[str],
    execution_id: str,
    agent_id: str,
    session_id: Optional[str],
    tenant_id: Optional[str],
    parent_execution_id: Optional[str],
    root_execution_id: Optional[str],
) -> Optional[Dict[str, Any]]:
    """Construct a ``plan_observed`` event for one Bedrock action.

    Validation happens via the shared ``build_plan_payload`` —
    invalid tool names (e.g. action_group names with shell
    metacharacters) drop the event silently, preventing injection via
    crafted tool names.
    """
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
            "source": "bedrock.agentTrace",
            "tool_name": tool_name,
        },
    )


def _translate_action_group_invocation(
    *,
    input_: Dict[str, Any],
    execution_id: str,
    agent_id: str,
    session_id: Optional[str],
    tenant_id: Optional[str],
    parent_execution_id: Optional[str],
    root_execution_id: Optional[str],
) -> Dict[str, Any]:
    action_group = str(input_.get("actionGroupName") or "unknown")
    api_path = str(input_.get("apiPath") or input_.get("function") or "")
    verb = str(input_.get("verb") or input_.get("executionType") or "invoke").lower()

    tool_ref = f"{_RESOURCE_PREFIX_BEDROCK_TOOL}{action_group}{api_path}"

    payload: Dict[str, Any] = {
        # Canonical ``ResourceRef`` — typed ``resource_type`` +
        # ``identifier``, with the framework-namespaced URI on
        # ``endpoint``. A flattened ``{"resource": "<uri>"}`` is not a
        # ``ResourceRef`` and is rejected at ``POST /v1/events``, which
        # takes the whole batch down with it.
        "tool": {
            "resource_type": "tool",
            "identifier": f"{action_group}{api_path}",
            "endpoint": tool_ref,
        },
        "action": {"action": verb},
        # decision = None: this is the observed call, not an
        # authorization-decision event. The plugin's Lambda-
        # side decorator emits the authorization decision
        # separately.
    }
    # Sorted, comma-joined argument KEYS (never values) — the behavioural
    # feature wl-drift's arg-shape scorer consumes. Bedrock exposes the
    # call's arguments as a list of {name, type, value} parameter dicts;
    # project the NAMES into a mapping so the shared helper (which is
    # Mapping-only) can bound + sort them. Values are dropped.
    parameters = input_.get("parameters")
    if isinstance(parameters, list):
        arg_keys = {
            str(p["name"]): None
            for p in parameters
            if isinstance(p, dict) and p.get("name")
        }
        arg_key_summary = summarize_arg_keys(arg_keys)
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
            "source": "bedrock.agentTrace",
            "action_group": action_group,
            "api_path": api_path,
        },
    )


def _translate_kb_lookup(
    *,
    lookup: Dict[str, Any],
    execution_id: str,
    agent_id: str,
    session_id: Optional[str],
    tenant_id: Optional[str],
    parent_execution_id: Optional[str],
    root_execution_id: Optional[str],
) -> Dict[str, Any]:
    kb_id = str(lookup.get("knowledgeBaseId") or "unknown")
    text = lookup.get("text")
    # Value-free: the query text can carry personal data or secrets, so
    # only its type is recorded, never its content.
    input_summary = (
        redacted_input_summary({"text": text}) if isinstance(text, str) and text else None
    )

    tool_ref = f"{_RESOURCE_PREFIX_BEDROCK_KB}{kb_id}"

    payload: Dict[str, Any] = {
        # Canonical ``ResourceRef`` — see the action-group translator above.
        "tool": {
            "resource_type": "tool",
            "identifier": kb_id,
            "endpoint": tool_ref,
        },
        "action": {"action": "query"},
    }
    if input_summary:
        payload["input_summary"] = input_summary

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
            "source": "bedrock.agentTrace",
            "knowledge_base_id": kb_id,
        },
    )


def _translate_failure_trace(
    *,
    failure: Dict[str, Any],
    execution_id: str,
    agent_id: str,
    session_id: Optional[str],
    tenant_id: Optional[str],
    parent_execution_id: Optional[str],
    root_execution_id: Optional[str],
) -> Dict[str, Any]:
    # Value-free: Bedrock's failureReason is free text that can echo
    # the request; only the failure code (a category) is recorded.
    failure_code = failure.get("failureCode")
    error_excerpt = (
        f"bedrock_failure:{failure_code}"[:512] if failure_code else "bedrock_failure"
    )

    return _build_event(
        event_type=_EVENT_TYPE_EXECUTION_FAILED,
        execution_id=execution_id,
        agent_id=agent_id,
        session_id=session_id,
        tenant_id=tenant_id,
        parent_execution_id=parent_execution_id,
        root_execution_id=root_execution_id,
        payload={
            "error": error_excerpt,
            # ``ExecutionFailedPayload`` models the error CATEGORY as
            # ``error_type``; ``error_code`` is not a field on the server
            # struct, so serde dropped it silently.
            "error_type": failure.get("failureCode"),
        },
        metadata={
            "source": "bedrock.agentTrace",
        },
    )


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
    flat-envelope JSON shape expected by wl-apdp's ``/v1/events``.

    Critical: this is the wire contract. Field names + nesting MUST
    match the ``ExecutionEvent`` wire shape expected by
    ``wl-apdp``'s ``/v1/events`` endpoint exactly. If the schema
    evolves, this function evolves with it.
    """
    envelope = {
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
    # Lineage linkage — when the caller threads the workflow root
    # through ``publish_trace(root_execution_id=...)``,
    # every event emitted from a Bedrock invocation carries the root
    # of the orchestrator's tree. This is what lets
    # ``wl-execution-graph`` stitch root → Bedrock-agent →
    # collaborator-sub-agent into one lineage view. Optional: a
    # standalone Bedrock invocation IS its own root, and the
    # normalizer back-fills the field.
    if root_execution_id is not None:
        envelope["root_execution_id"] = root_execution_id
    # Drop empty / None values from metadata so the JSON stays compact.
    cleaned_metadata = {k: v for k, v in metadata.items() if v not in (None, "")}
    if cleaned_metadata:
        envelope["metadata"] = cleaned_metadata
    return {**envelope, "payload": payload}
