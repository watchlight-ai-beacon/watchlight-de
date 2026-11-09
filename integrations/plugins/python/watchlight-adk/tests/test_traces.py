"""Tests for the ADK callback → ExecutionEvent translator."""

from __future__ import annotations

import json
from typing import Any, Dict

from watchlight_adk.traces import translate_adk_event, translate_adk_events


# ─── Fixtures ──────────────────────────────────────────────────────────


def _before_agent(name: str = "research-analyst", depth: int = 0) -> Dict[str, Any]:
    return {
        "hook": "before_agent_callback",
        "agent_name": name,
        "depth": depth,
        "intent_category": "research",
        "intent_objective": "answer the user's question",
    }


def _after_agent(duration_ms: int = 1500, actions_taken: int = 3) -> Dict[str, Any]:
    return {
        "hook": "after_agent_callback",
        "duration_ms": duration_ms,
        "actions_taken": actions_taken,
        "actions_denied": 0,
        "outcome": "summary delivered",
    }


def _before_tool(name: str = "web_search", action: str = "query") -> Dict[str, Any]:
    return {
        "hook": "before_tool_callback",
        "tool_name": name,
        "action_verb": action,
        "tool_args": {"query": "Q3 revenue"},
    }


def _after_tool(name: str = "web_search", duration_ms: int = 250) -> Dict[str, Any]:
    return {
        "hook": "after_tool_callback",
        "tool_name": name,
        "action_verb": "query",
        "decision": "Allow",
        "duration_ms": duration_ms,
    }


def _before_model(model: str = "gemini-1.5-pro") -> Dict[str, Any]:
    return {
        "hook": "before_model_callback",
        "model": model,
        "prompt_summary": "Tell me about Q3 revenue.",
    }


def _tool_error() -> Dict[str, Any]:
    return {
        "hook": "on_tool_error_callback",
        "error": RuntimeError("upstream API timeout"),
    }


def _model_error() -> Dict[str, Any]:
    return {
        "hook": "on_model_error_callback",
        "error": ValueError("model returned malformed output"),
    }


def _policy_decision(decision: str = "Allow") -> Dict[str, Any]:
    return {
        "hook": "policy_decision",
        "principal": 'Agent::"research-analyst"',
        "action": 'Action::"query"',
        "resource": 'Tool::"web_search"',
        "decision": decision,
        "reason": "Within authorized intent_category",
        "evaluation_ms": 12,
    }


# ─── Empty / unmapped ──────────────────────────────────────────────────


def test_unmapped_hook_returns_none():
    for hook in (
        "on_user_message_callback",
        "before_run_callback",
        "after_run_callback",
        "after_model_callback",
        "on_event_callback",
    ):
        result = translate_adk_event(
            capture={"hook": hook},
            execution_id="exec",
            agent_id="agent-1",
        )
        assert result is None, f"hook {hook} should be deliberately unmapped"


def test_unknown_hook_returns_none_without_raising():
    """Future ADK versions might add new hooks. Don't crash."""
    result = translate_adk_event(
        capture={"hook": "on_future_callback"},
        execution_id="exec",
        agent_id="agent-1",
    )
    assert result is None


def test_non_string_hook_returns_none():
    result = translate_adk_event(
        capture={"hook": 42},
        execution_id="exec",
        agent_id="agent-1",
    )
    assert result is None


def test_missing_hook_returns_none():
    result = translate_adk_event(
        capture={},
        execution_id="exec",
        agent_id="agent-1",
    )
    assert result is None


# ─── ExecutionStarted from before_agent_callback ─────────────────────


def test_before_agent_emits_execution_started():
    result = translate_adk_event(
        capture=_before_agent(),
        execution_id="exec_x",
        agent_id="agent-1",
        session_id="sess_42",
        tenant_id="acme",
    )
    assert result is not None
    assert result["event_type"] == "execution_started"
    assert result["execution_id"] == "exec_x"
    assert result["agent_id"] == "agent-1"
    assert result["session_id"] == "sess_42"
    assert result["tenant_id"] == "acme"
    assert result["payload"]["depth"] == 0
    assert result["payload"]["principal"] == {
        "principal_type": "agent",
        "id": "agent-1",
    }
    assert result["payload"]["intent_category"] == "research"
    assert result["metadata"]["source"] == "adk.callback"
    assert result["metadata"]["agent_name"] == "research-analyst"


def test_intent_objective_truncated_at_120_chars():
    long_objective = "x" * 500
    result = translate_adk_event(
        capture={
            "hook": "before_agent_callback",
            "intent_objective": long_objective,
        },
        execution_id="exec",
        agent_id="agent-1",
    )
    assert result is not None
    assert len(result["payload"]["intent_objective"]) == 120


# ─── ExecutionCompleted from after_agent_callback ────────────────────


def test_after_agent_emits_execution_completed():
    result = translate_adk_event(
        capture=_after_agent(duration_ms=2500, actions_taken=5),
        execution_id="exec",
        agent_id="agent-1",
    )
    assert result is not None
    assert result["event_type"] == "execution_completed"
    assert result["payload"]["duration_ms"] == 2500
    assert result["payload"]["actions_taken"] == 5
    assert result["payload"]["outcome"]  # truncated str preserved


def test_outcome_truncated_at_120_chars():
    huge_outcome = "x" * 500
    result = translate_adk_event(
        capture={
            "hook": "after_agent_callback",
            "duration_ms": 100,
            "actions_taken": 1,
            "outcome": huge_outcome,
        },
        execution_id="exec",
        agent_id="agent-1",
    )
    assert result is not None
    assert len(result["payload"]["outcome"]) == 120


# ─── PlanObserved (was tool_call_observed/planned) ──────────────────


def test_before_tool_emits_plan_observed():
    """``before_tool_callback`` represents the plan-stage decision —
    the agent has chosen a tool, but invocation hasn't started yet.
    Emits a canonical PlanObserved event (was tool_call_observed with
    decision=planned)."""
    result = translate_adk_event(
        capture=_before_tool("bank_transfer", "transfer"),
        execution_id="exec",
        agent_id="agent-1",
    )
    assert result is not None
    assert result["event_type"] == "plan_observed"
    assert result["payload"]["intended_tools"] == ["bank_transfer"]
    assert result["payload"]["plan_kind"] == "incremental"
    assert result["metadata"]["tool_name"] == "bank_transfer"
    # The legacy decision/phase overload is gone.
    assert "decision" not in result["payload"]
    assert "phase" not in result["metadata"]


def test_before_tool_invalid_tool_name_returns_none():
    """Tool names with shell metacharacters drop the
    event rather than form a malformed plan. Empty / falsy names
    hit the pre-existing 'unknown' fallback and are accepted, so
    the test list covers names that survive that fallback."""
    for bad in ("tool with space", "tool;rm -rf", "tool/path", "tool\nnewline"):
        result = translate_adk_event(
            capture=_before_tool(bad, "invoke"),
            execution_id="exec",
            agent_id="agent-1",
        )
        assert result is None, f"expected None for invalid tool name {bad!r}"


def test_after_tool_emits_completed_tool_call_with_duration():
    result = translate_adk_event(
        capture=_after_tool("calc", duration_ms=42),
        execution_id="exec",
        agent_id="agent-1",
    )
    assert result is not None
    assert result["event_type"] == "tool_call_observed"
    assert result["payload"]["decision"] == "Allow"
    assert result["payload"]["duration_ms"] == 42
    assert result["metadata"]["phase"] == "completed"


def test_tool_args_rationale_is_value_free_and_capped_at_120_chars():
    """``tool_args`` is summarised into ``rationale`` (not
    ``input_summary``) on a plan_observed event: argument names and
    types only, never a value, capped at 120 chars."""
    long_args = {f"k{i}": "x" * 500 for i in range(40)}
    result = translate_adk_event(
        capture={
            "hook": "before_tool_callback",
            "tool_name": "search",
            "action_verb": "query",
            "tool_args": long_args,
        },
        execution_id="exec",
        agent_id="agent-1",
    )
    assert result is not None
    assert result["event_type"] == "plan_observed"
    rationale = result["payload"]["rationale"]
    assert len(rationale) == 120
    assert "xxx" not in rationale
    assert rationale.startswith("40 args: k0(str)")


# ─── ApiRequestObserved from before_model_callback ───────────────────


def test_before_model_emits_api_request_observed():
    result = translate_adk_event(
        capture=_before_model("gemini-2.0-flash"),
        execution_id="exec",
        agent_id="agent-1",
    )
    assert result is not None
    assert result["event_type"] == "api_request_observed"
    assert result["payload"]["resource"] == {
        "resource_type": "llm_api",
        "identifier": "gemini-2.0-flash",
        "endpoint": "adk://llm/gemini-2.0-flash",
    }
    assert result["payload"]["method"] == "POST"
    assert result["payload"]["path"] == "/completion"
    assert result["metadata"]["model"] == "gemini-2.0-flash"


def test_prompt_summary_truncated():
    long_prompt = "Tell me about " + ("x" * 500)
    result = translate_adk_event(
        capture={
            "hook": "before_model_callback",
            "model": "gemini",
            "prompt_summary": long_prompt,
        },
        execution_id="exec",
        agent_id="agent-1",
    )
    assert result is not None
    assert len(result["metadata"]["prompt_summary"]) == 120


# ─── ExecutionFailed from error hooks ────────────────────────────────


def test_tool_error_emits_execution_failed():
    result = translate_adk_event(
        capture=_tool_error(),
        execution_id="exec",
        agent_id="agent-1",
    )
    assert result is not None
    assert result["event_type"] == "execution_failed"
    # Value-free: the exception class, never its message.
    assert result["payload"]["error"] == "RuntimeError"
    assert "upstream API timeout" not in repr(result)
    assert result["payload"]["error_type"] == "RuntimeError"
    assert result["metadata"]["hook"] == "on_tool_error_callback"


def test_model_error_emits_execution_failed():
    result = translate_adk_event(
        capture=_model_error(),
        execution_id="exec",
        agent_id="agent-1",
    )
    assert result is not None
    assert result["event_type"] == "execution_failed"
    assert result["payload"]["error_type"] == "ValueError"
    assert result["metadata"]["hook"] == "on_model_error_callback"


def test_error_message_truncated_at_512_chars():
    huge_error = RuntimeError("x" * 2000)
    result = translate_adk_event(
        capture={
            "hook": "on_tool_error_callback",
            "error": huge_error,
        },
        execution_id="exec",
        agent_id="agent-1",
    )
    assert result is not None
    assert len(result["payload"]["error"]) <= 512
    assert "xxxx" not in result["payload"]["error"]


# ─── PolicyDecisionMade ───────────────────────────────────────────────


def test_policy_decision_hook_is_dropped_server_attested():
    """``policy_decision_made`` is SERVER-attested only (wl-apdp
    is the sole decision authority) and is BLOCKED at ``/v1/events``
    ingest. The translator therefore DROPS the ``policy_decision`` hook
    rather than producing a rejected event."""
    result = translate_adk_event(
        capture=_policy_decision("Deny"),
        execution_id="exec",
        agent_id="agent-1",
    )
    assert result is None


# ─── Ordering, batch, regression ──────────────────────────────────────


def test_batch_translation_preserves_order():
    captures = [
        _before_agent(),
        _before_model(),
        _before_tool(),
        _after_tool(),
        _after_agent(),
    ]
    translated = translate_adk_events(
        captures=captures, execution_id="exec", agent_id="agent-1"
    )
    types = [e["event_type"] for e in translated]
    assert types == [
        "execution_started",
        "api_request_observed",
        "plan_observed",  # was tool_call_observed/planned
        "tool_call_observed",  # completed
        "execution_completed",
    ]


def test_unmapped_in_batch_silently_dropped():
    captures = [
        _before_agent(),
        {"hook": "on_event_callback", "noise": True},
        _after_agent(),
    ]
    translated = translate_adk_events(
        captures=captures, execution_id="exec", agent_id="agent-1"
    )
    assert len(translated) == 2


def test_malformed_capture_skipped_not_fatal():
    captures = [
        _before_agent(),
        {"hook": "before_tool_callback", "tool_args": {"__weird__": object()}},
        _after_agent(),
    ]
    # The middle capture has a tool_args dict containing an
    # un-stringifiable value. Some str()-coercions still succeed
    # (object's default repr), but the test's contract is "doesn't
    # break subsequent translations" — both ends translate.
    translated = translate_adk_events(
        captures=captures, execution_id="exec", agent_id="agent-1"
    )
    types = [e["event_type"] for e in translated]
    assert "execution_started" in types
    assert "execution_completed" in types


# ─── Wire-format invariants ───────────────────────────────────────────


def test_every_emission_carries_source_metadata():
    captures = [
        _before_agent(),
        _before_tool(),
        _after_tool(),
        _before_model(),
        _after_agent(),
        _tool_error(),
        _model_error(),
        _policy_decision(),
    ]
    translated = translate_adk_events(
        captures=captures, execution_id="exec", agent_id="agent-1"
    )
    assert len(translated) > 0
    for ev in translated:
        assert ev.get("metadata", {}).get("source") == "adk.callback", (
            f"missing or wrong source on {ev['event_type']}"
        )


def test_event_ids_are_unique():
    captures = [_before_agent(), _before_agent()]
    translated = translate_adk_events(
        captures=captures, execution_id="exec", agent_id="agent-1"
    )
    assert translated[0]["event_id"] != translated[1]["event_id"]
    for ev in translated:
        assert ev["event_id"].startswith("evt_")


def test_serializable_to_json():
    captures = [
        _before_agent(),
        _before_tool(),
        _after_tool(),
        _before_model(),
        _tool_error(),
        _after_agent(),
    ]
    translated = translate_adk_events(
        captures=captures, execution_id="exec", agent_id="agent-1"
    )
    for ev in translated:
        round_trip = json.loads(json.dumps(ev))
        assert round_trip == ev


def test_envelope_extras_propagate():
    result = translate_adk_event(
        capture=_before_agent(),
        execution_id="exec_child",
        agent_id="agent-1",
        session_id="sess",
        tenant_id="acme",
        parent_execution_id="exec_parent",
        root_execution_id="exec_root",
    )
    assert result is not None
    assert result["execution_id"] == "exec_child"
    assert result["session_id"] == "sess"
    assert result["tenant_id"] == "acme"
    assert result["parent_execution_id"] == "exec_parent"
    assert result["root_execution_id"] == "exec_root"


# ─── Server-contract regression ──────────────────────────────────────


def test_every_translated_event_matches_the_server_payload_struct():
    """Every event this translator builds must deserialize into the
    canonical payload struct its ``event_type`` selects.

    The regression lock for the defect where ``execution_started``
    carried ``{"principal": {"agent_id": ...}}``: wl-apdp answered
    ``422 … data did not match any variant of untagged enum
    IngestExecutionEventsRequest``, which rejects the WHOLE batch, and
    because lineage publish is fail-open the run simply never appeared
    in the execution-lineage view.
    """
    from watchlight_core_testing import assert_payload_matches_schema

    captures = [
        _before_agent(),
        _before_tool(),
        _after_tool(),
        _before_model("gemini-2.0-flash"),
        _after_agent(),
    ]
    events = translate_adk_events(
        captures=captures,
        execution_id="exec",
        agent_id="agent-1",
    )
    assert events
    for ev in events:
        assert_payload_matches_schema(ev)


def test_execution_started_principal_is_the_canonical_principal_ref():
    """Pins the exact shape. ``PrincipalRef`` requires
    ``principal_type`` + ``id``; the legacy ``{"agent_id": ...}`` is
    what the server rejected."""
    from watchlight_core.events_schema import ExecutionStartedPayload

    result = translate_adk_event(
        capture=_before_agent(),
        execution_id="exec",
        agent_id="agent-1",
    )
    assert result is not None
    assert result["payload"]["principal"] == {
        "principal_type": "agent",
        "id": "agent-1",
    }
    ExecutionStartedPayload.model_validate(result["payload"])
