"""Unit tests for the MSAF translator.

Synthetic captures — the tests don't depend on the MAF SDK. The
production middleware shim that produces real captures lands in a
follow-up release.
"""

import json
from typing import Any, Dict

from watchlight_msaf.traces import translate_msaf_event, translate_msaf_events


# ─── Fixtures ──────────────────────────────────────────────────────


def _workflow_start(
    *, intent_objective: str = "Summarise Q3 metrics", depth: int = 0
) -> Dict[str, Any]:
    return {
        "hook": "workflow_run_start",
        "intent_objective": intent_objective,
        "intent_category": "research",
        "depth": depth,
    }


def _workflow_complete(
    *, duration_ms: int = 1500, actions_taken: int = 5
) -> Dict[str, Any]:
    return {
        "hook": "workflow_run_complete",
        "duration_ms": duration_ms,
        "actions_taken": actions_taken,
        "actions_denied": 0,
        "outcome": "summary delivered",
        "tools_used": ["fetch_news", "summarize"],
    }


def _workflow_error(reason: str = "timeout") -> Dict[str, Any]:
    return {
        "hook": "workflow_run_error",
        "error": reason,
        "error_type": "TimeoutError",
        "policy_denied": False,
        "duration_ms": 800,
    }


def _tool_start(name: str = "fetch_news", args: Any = None) -> Dict[str, Any]:
    return {
        "hook": "tool_invocation_start",
        "tool_name": name,
        "tool_args": args if args is not None else {"q": "Q3 revenue"},
    }


def _tool_complete(
    name: str = "fetch_news",
    duration_ms: int = 250,
    decision: str = "Allow",
) -> Dict[str, Any]:
    return {
        "hook": "tool_invocation_complete",
        "tool_name": name,
        "action_verb": "query",
        "decision": decision,
        "duration_ms": duration_ms,
        "tool_args": {"q": "Q3 revenue"},
    }


def _chat_request(model: str = "gpt-4o") -> Dict[str, Any]:
    return {
        "hook": "chat_completion_request",
        "model": model,
    }


def _chat_complete(
    model: str = "gpt-4o", status: int = 200, duration_ms: int = 350
) -> Dict[str, Any]:
    return {
        "hook": "chat_completion_complete",
        "model": model,
        "response_status": status,
        "duration_ms": duration_ms,
    }


# ─── Envelope ──────────────────────────────────────────────────────


def test_event_envelope_has_required_fields():
    """Cross-plugin contract: every event must carry the canonical 6
    envelope fields. Pinning here ensures this plugin doesn't drift
    away from the other framework plugins."""
    result = translate_msaf_event(
        capture=_workflow_start(),
        execution_id="exec_1",
        agent_id="agent-1",
    )
    assert result is not None
    for key in ("event_id", "event_type", "timestamp", "execution_id", "agent_id", "payload"):
        assert key in result, f"missing envelope field: {key}"
    assert result["event_id"].startswith("evt_"), "event_id must use evt_ prefix"


def test_event_carries_provenance_metadata():
    """Every event names its source so downstream consumers can
    attribute it (and detect fabrication)."""
    result = translate_msaf_event(
        capture=_workflow_start(),
        execution_id="exec_1",
        agent_id="agent-1",
    )
    assert result is not None
    assert result["metadata"]["source"] == "msaf.callback"


def test_optional_envelope_fields_attach_when_provided():
    result = translate_msaf_event(
        capture=_tool_complete("calc"),
        execution_id="exec_1",
        agent_id="agent-1",
        session_id="sess_42",
        tenant_id="acme",
        parent_execution_id="exec_parent",
        root_execution_id="exec_root",
    )
    assert result is not None
    assert result["session_id"] == "sess_42"
    assert result["tenant_id"] == "acme"
    assert result["parent_execution_id"] == "exec_parent"
    assert result["root_execution_id"] == "exec_root"


# ─── ExecutionStarted ──────────────────────────────────────────────


def test_workflow_start_emits_execution_started():
    result = translate_msaf_event(
        capture=_workflow_start(intent_objective="Find Q3 metrics", depth=0),
        execution_id="exec_root",
        agent_id="orchestrator",
    )
    assert result is not None
    assert result["event_type"] == "execution_started"
    assert result["payload"]["depth"] == 0
    assert result["payload"]["intent_objective"] == "Find Q3 metrics"
    assert result["payload"]["intent_category"] == "research"


def test_agent_step_start_emits_nested_execution_started():
    """agent_step_start with a non-zero depth shows up as a nested
    ExecutionStarted — the same shape ADK + LangGraph use for
    sub-agent spawns."""
    result = translate_msaf_event(
        capture={
            "hook": "agent_step_start",
            "intent_objective": "Drill into outliers",
            "depth": 1,
        },
        execution_id="exec_child",
        agent_id="researcher",
        parent_execution_id="exec_root",
    )
    assert result is not None
    assert result["event_type"] == "execution_started"
    assert result["payload"]["depth"] == 1
    assert result["parent_execution_id"] == "exec_root"


def test_workflow_start_truncates_long_intent():
    long_intent = "x" * 500
    result = translate_msaf_event(
        capture={"hook": "workflow_run_start", "intent_objective": long_intent},
        execution_id="exec",
        agent_id="agent-1",
    )
    assert result is not None
    assert len(result["payload"]["intent_objective"]) == 120


def test_workflow_start_clamps_negative_depth_to_zero():
    """Defense in depth — a faulty middleware shim providing a
    negative depth should produce a valid event (depth=0), not a
    payload that fails downstream validation."""
    result = translate_msaf_event(
        capture={"hook": "workflow_run_start", "depth": -5},
        execution_id="exec",
        agent_id="agent-1",
    )
    assert result is not None
    assert result["payload"]["depth"] == 0


# ─── ExecutionCompleted ────────────────────────────────────────────


def test_workflow_complete_emits_execution_completed():
    result = translate_msaf_event(
        capture=_workflow_complete(duration_ms=2200, actions_taken=7),
        execution_id="exec",
        agent_id="agent-1",
    )
    assert result is not None
    assert result["event_type"] == "execution_completed"
    assert result["payload"]["duration_ms"] == 2200
    assert result["payload"]["actions_taken"] == 7
    assert result["payload"]["outcome"] == "summary delivered"
    assert result["payload"]["tools_used"] == ["fetch_news", "summarize"]


def test_workflow_complete_coerces_string_int_fields():
    """MAF middleware sometimes hands ints as strings — the
    translator coerces silently rather than dropping the event."""
    result = translate_msaf_event(
        capture={
            "hook": "workflow_run_complete",
            "duration_ms": "1234",
            "actions_taken": "3",
        },
        execution_id="exec",
        agent_id="agent-1",
    )
    assert result is not None
    assert result["payload"]["duration_ms"] == 1234
    assert result["payload"]["actions_taken"] == 3


def test_workflow_complete_rejects_boolean_int():
    """bool is a subclass of int in Python — a boolean slip in the
    capture must NOT become duration_ms=0/1 in the payload. The
    coercion helper rejects bools explicitly."""
    result = translate_msaf_event(
        capture={
            "hook": "workflow_run_complete",
            "duration_ms": True,
            "actions_taken": False,
        },
        execution_id="exec",
        agent_id="agent-1",
    )
    assert result is not None
    # Defaults applied because bools rejected.
    assert result["payload"]["duration_ms"] == 0
    assert result["payload"]["actions_taken"] == 0


# ─── ExecutionFailed ───────────────────────────────────────────────


def test_workflow_error_emits_execution_failed():
    result = translate_msaf_event(
        capture=_workflow_error("upstream API timeout"),
        execution_id="exec",
        agent_id="agent-1",
    )
    assert result is not None
    assert result["event_type"] == "execution_failed"
    # Value-free: a plain error string is withheld entirely.
    assert result["payload"]["error"] == "error_detail_withheld"
    assert "upstream API timeout" not in repr(result)
    assert result["payload"]["error_type"] == "TimeoutError"
    assert result["payload"]["policy_denied"] is False


def test_workflow_error_accepts_exception_object():
    result = translate_msaf_event(
        capture={
            "hook": "workflow_run_error",
            "error": RuntimeError("backend offline"),
        },
        execution_id="exec",
        agent_id="agent-1",
    )
    assert result is not None
    assert "backend offline" not in repr(result)
    assert result["payload"]["error"] == "RuntimeError"


def test_workflow_error_truncates_long_message():
    huge = "x" * 4096
    result = translate_msaf_event(
        capture={"hook": "workflow_run_error", "error": huge},
        execution_id="exec",
        agent_id="agent-1",
    )
    assert result is not None
    assert len(result["payload"]["error"]) <= 512


# ─── PlanObserved ──────────────────────────────────────────────────


def test_tool_invocation_start_emits_plan_observed():
    """MAF's tool middleware fires per-invocation, so the plan event
    is incremental (one tool per event). Parity with the LangGraph
    and ADK plugins."""
    result = translate_msaf_event(
        capture=_tool_start("bank_transfer"),
        execution_id="exec",
        agent_id="agent-1",
    )
    assert result is not None
    assert result["event_type"] == "plan_observed"
    assert result["payload"]["intended_tools"] == ["bank_transfer"]
    assert result["payload"]["plan_kind"] == "incremental"


def test_tool_invocation_start_invalid_name_returns_none():
    """Tool names with shell metacharacters drop the event rather
    than form a malformed plan."""
    for bad in ("tool with space", "tool;rm -rf", "tool/path", "tool\nnewline"):
        result = translate_msaf_event(
            capture=_tool_start(bad),
            execution_id="exec",
            agent_id="agent-1",
        )
        assert result is None, f"expected None for invalid tool name {bad!r}"


def test_tool_invocation_start_summarises_args_as_rationale():
    """The plan's rationale describes the tool args by name and type
    only (bounded); no argument value reaches the event."""
    result = translate_msaf_event(
        capture=_tool_start("fetch_news", args={"q": "Q3 revenue", "limit": 5}),
        execution_id="exec",
        agent_id="agent-1",
    )
    assert result is not None
    rationale = result["payload"].get("rationale", "")
    assert rationale == "2 args: q(str), limit(int)"
    assert "Q3 revenue" not in repr(result)


def test_tool_invocation_start_truncates_rationale_at_120():
    result = translate_msaf_event(
        capture=_tool_start("fetch_news", args={"q": "x" * 500}),
        execution_id="exec",
        agent_id="agent-1",
    )
    assert result is not None
    assert len(result["payload"]["rationale"]) <= 120


# ─── ToolCallObserved ──────────────────────────────────────────────


def test_tool_invocation_complete_emits_tool_call_observed_with_duration():
    result = translate_msaf_event(
        capture=_tool_complete("calc", duration_ms=42, decision="Allow"),
        execution_id="exec",
        agent_id="agent-1",
    )
    assert result is not None
    assert result["event_type"] == "tool_call_observed"
    assert result["payload"]["tool"] == {
        "resource_type": "tool",
        "identifier": "calc",
        "endpoint": "msaf://tool/calc",
    }
    assert result["payload"]["action"]["action"] == "query"
    assert result["payload"]["decision"] == "Allow"
    assert result["payload"]["duration_ms"] == 42
    assert result["metadata"]["phase"] == "completed"


# ─── ApiRequestObserved (LLM call) ─────────────────────────────────


def test_chat_completion_request_emits_api_request_observed():
    result = translate_msaf_event(
        capture=_chat_request("gpt-4o"),
        execution_id="exec",
        agent_id="agent-1",
    )
    assert result is not None
    assert result["event_type"] == "api_request_observed"
    assert result["payload"]["resource"] == {
        "resource_type": "llm_api",
        "identifier": "gpt-4o",
        "endpoint": "msaf://llm/gpt-4o",
    }
    assert result["payload"]["method"] == "POST"
    assert result["payload"]["path"] == "/v1/chat/completions"
    assert result["metadata"]["phase"] == "request"


def test_chat_completion_complete_carries_status_and_duration():
    result = translate_msaf_event(
        capture=_chat_complete("gpt-4o", status=200, duration_ms=350),
        execution_id="exec",
        agent_id="agent-1",
    )
    assert result is not None
    assert result["payload"]["response_status"] == 200
    assert result["payload"]["duration_ms"] == 350
    assert result["metadata"]["phase"] == "completed"


# ─── Unmapped + malformed ───────────────────────────────────────────


def test_unmapped_hooks_silently_return_none():
    """token_stream, durable_checkpoint, multi_agent_handoff are
    deliberately deferred per the module docstring. Translator
    silently drops them — partial coverage beats no coverage."""
    for hook in ("token_stream", "durable_checkpoint", "multi_agent_handoff"):
        result = translate_msaf_event(
            capture={"hook": hook, "data": "anything"},
            execution_id="exec",
            agent_id="agent-1",
        )
        assert result is None, f"hook {hook!r} should be unmapped"


def test_missing_hook_field_returns_none():
    result = translate_msaf_event(
        capture={"not_a_hook": "anything"},
        execution_id="exec",
        agent_id="agent-1",
    )
    assert result is None


def test_translator_never_raises_on_malformed_capture():
    """Defense in depth — give the translator garbage and it logs
    + drops, never raises."""
    for bad in (
        {"hook": 123},
        {"hook": "tool_invocation_complete", "duration_ms": object()},
        {"hook": "workflow_run_error", "error": None},
    ):
        result = translate_msaf_event(
            capture=bad,
            execution_id="exec",
            agent_id="agent-1",
        )
        # Either None or a valid event — never an exception bubble.
        if result is not None:
            assert "event_type" in result


# ─── Batch translator ──────────────────────────────────────────────


def test_translate_msaf_events_preserves_order():
    captures = [
        _workflow_start(),
        _tool_start("fetch"),
        _tool_complete("fetch"),
        _chat_request("gpt-4o"),
        _chat_complete("gpt-4o"),
        _workflow_complete(),
    ]
    events = translate_msaf_events(
        captures=captures,
        execution_id="exec",
        agent_id="agent-1",
    )
    types = [e["event_type"] for e in events]
    assert types == [
        "execution_started",
        "plan_observed",
        "tool_call_observed",
        "api_request_observed",
        "api_request_observed",
        "execution_completed",
    ]


def test_translate_msaf_events_drops_unmapped_silently():
    """Mixed batches with some unmapped + some mapped emit only
    the mapped ones — never crashes mid-batch."""
    captures = [
        _workflow_start(),
        {"hook": "token_stream", "token": "a"},
        _workflow_complete(),
        {"hook": "durable_checkpoint", "checkpoint_id": "c1"},
    ]
    events = translate_msaf_events(
        captures=captures,
        execution_id="exec",
        agent_id="agent-1",
    )
    assert [e["event_type"] for e in events] == [
        "execution_started",
        "execution_completed",
    ]


# ─── Serialisability ────────────────────────────────────────────────


def test_all_events_are_json_serialisable():
    """Wire contract: events must serialise via json.dumps to land
    on the NATS subject / OTLP collector."""
    captures = [
        _workflow_start(),
        _tool_start(),
        _tool_complete(),
        _chat_request(),
        _chat_complete(),
        _workflow_error(),
        _workflow_complete(),
    ]
    events = translate_msaf_events(
        captures=captures,
        execution_id="exec",
        agent_id="agent-1",
    )
    for ev in events:
        # Round-trip must succeed without raising.
        json.loads(json.dumps(ev))


# ─── Server-contract regression ──────────────────────────────────────


def test_every_translated_event_matches_the_server_payload_struct():
    """Every event this translator builds must deserialize into the
    canonical payload struct its ``event_type`` selects.

    The regression lock for the defect where ``execution_started``
    carried ``{"principal": {"principal": 'Agent::"<id>"'}}``: wl-apdp
    answered ``422 … data did not match any variant of untagged enum
    IngestExecutionEventsRequest``, which rejects the WHOLE batch, and
    because lineage publish is non-blocking the run simply never appeared
    in the execution-lineage view.
    """
    from watchlight_core_testing import assert_payload_matches_schema

    captures = [
        _workflow_start(),
        _tool_start(),
        _tool_complete(),
        _chat_request(),
        _chat_complete(),
        _workflow_complete(),
        _workflow_error(),
    ]
    events = translate_msaf_events(
        captures=captures,
        execution_id="exec",
        agent_id="agent-1",
    )
    assert events
    for ev in events:
        assert_payload_matches_schema(ev)


def test_execution_started_principal_is_the_canonical_principal_ref():
    """Pins the exact shape. ``PrincipalRef`` requires
    ``principal_type`` + ``id``; the server derives the Cedar reference
    (``Agent::"<id>"``) itself, so a pre-rendered Cedar string is not a
    ``PrincipalRef`` and was rejected."""
    from watchlight_core.events_schema import ExecutionStartedPayload

    result = translate_msaf_event(
        capture=_workflow_start(),
        execution_id="exec",
        agent_id="agent-1",
    )
    assert result is not None
    assert result["payload"]["principal"] == {
        "principal_type": "agent",
        "id": "agent-1",
    }
    ExecutionStartedPayload.model_validate(result["payload"])


def test_tool_invocation_complete_input_summary_is_value_free():
    capture = _tool_start("fetch_news", args={"q": "sk-live-SECRET"})
    capture["hook"] = "tool_invocation_complete"
    result = translate_msaf_event(
        capture=capture, execution_id="exec", agent_id="agent-1"
    )
    assert result is not None
    assert result["payload"]["input_summary"] == "1 args: q(str)"
    assert "sk-live-SECRET" not in repr(result)
