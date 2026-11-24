"""Tests for the LangGraph callback → ExecutionEvent translator."""

from __future__ import annotations

import json
from typing import Any, Dict

import pytest

from watchlight_langgraph.traces import (
    translate_langgraph_event,
    translate_langgraph_events,
)


# ─── Fixtures ──────────────────────────────────────────────────────────


def _top_level_chain_start(name: str = "agent_executor") -> Dict[str, Any]:
    return {
        "hook": "on_chain_start",
        "serialized": {"name": name},
        "name": name,
        "run_id": "run_1",
        "parent_run_id": None,  # top-level
    }


def _nested_chain_start(name: str = "sub_chain") -> Dict[str, Any]:
    return {
        "hook": "on_chain_start",
        "serialized": {"name": name},
        "name": name,
        "run_id": "run_2",
        "parent_run_id": "run_1",  # nested
    }


def _top_level_chain_end(duration_ms: int = 1500) -> Dict[str, Any]:
    return {
        "hook": "on_chain_end",
        "outputs_summary": "done",
        "run_id": "run_1",
        "parent_run_id": None,
        "duration_ms": duration_ms,
        "actions_taken": 3,
    }


def _tool_start(name: str = "web_search", input_str: str = "Q3 revenue") -> Dict[str, Any]:
    return {
        "hook": "on_tool_start",
        "serialized": {"name": name},
        "name": name,
        "input_str": input_str,
        "run_id": "run_3",
        "parent_run_id": "run_1",
    }


def _tool_end(name: str = "web_search", duration_ms: int = 200) -> Dict[str, Any]:
    return {
        "hook": "on_tool_end",
        "output_summary": "{'results': ['...']}",
        "name": name,
        "duration_ms": duration_ms,
        "run_id": "run_3",
        "parent_run_id": "run_1",
    }


def _tool_error(name: str = "web_search") -> Dict[str, Any]:
    return {
        "hook": "on_tool_error",
        "error": RuntimeError("upstream API timeout"),
        "run_id": "run_3",
        "parent_run_id": "run_1",
    }


def _agent_action(tool: str = "web_search", tool_input: str = "Q3 revenue") -> Dict[str, Any]:
    return {
        "hook": "on_agent_action",
        "tool": tool,
        "tool_input": tool_input,
        "log": "thought: I should search...",
        "run_id": "run_4",
        "parent_run_id": "run_1",
    }


def _agent_finish() -> Dict[str, Any]:
    return {
        "hook": "on_agent_finish",
        "return_values": {"output": "$2.4B"},
        "log": "Final answer: $2.4B",
        "run_id": "run_5",
        "parent_run_id": "run_1",
        "duration_ms": 1500,
        "actions_taken": 3,
    }


def _llm_start(model: str = "gpt-4") -> Dict[str, Any]:
    return {
        "hook": "on_llm_start",
        "serialized": {"name": "ChatOpenAI"},
        "name": "ChatOpenAI",
        "model": model,
        "invocation_params": {"model": model, "temperature": 0},
        "prompts": ["You are a helpful research analyst."],
        "run_id": "run_6",
        "parent_run_id": "run_1",
    }


def _chain_error() -> Dict[str, Any]:
    return {
        "hook": "on_chain_error",
        "error": ValueError("planner produced invalid output"),
        "run_id": "run_1",
        "parent_run_id": None,
    }


# ─── Empty / unmapped cases ────────────────────────────────────────────


def test_empty_input_yields_no_events():
    events = translate_langgraph_events(
        events=[], execution_id="exec", agent_id="agent-1"
    )
    assert events == []


def test_unmapped_hook_returns_none():
    """on_text, on_llm_new_token, on_retry are deliberately
    unmapped (noisy / not actionable for governance)."""
    for hook in ("on_text", "on_llm_new_token", "on_retry"):
        result = translate_langgraph_event(
            event={"hook": hook},
            execution_id="exec",
            agent_id="agent-1",
        )
        assert result is None, f"hook {hook} should be unmapped"


def test_unknown_hook_returns_none_without_raising():
    """A future LangChain version could ship a new callback type.
    The translator must not crash; it logs at debug and returns
    None. Same posture as Bedrock's malformed-chunk handling."""
    result = translate_langgraph_event(
        event={"hook": "on_future_callback_that_doesnt_exist_yet"},
        execution_id="exec",
        agent_id="agent-1",
    )
    assert result is None


def test_non_string_hook_returns_none():
    result = translate_langgraph_event(
        event={"hook": 42}, execution_id="exec", agent_id="agent-1"
    )
    assert result is None


def test_missing_hook_returns_none():
    result = translate_langgraph_event(
        event={}, execution_id="exec", agent_id="agent-1"
    )
    assert result is None


# ─── ExecutionStarted from top-level on_chain_start ───────────────────


def test_top_level_chain_start_emits_execution_started():
    result = translate_langgraph_event(
        event=_top_level_chain_start("planner"),
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
    # Canonical PrincipalRef shape (resource_type + id), not the
    # legacy flat {"agent_id": ...}.
    assert result["payload"]["principal"] == {
        "principal_type": "agent",
        "id": "agent-1",
    }
    assert result["metadata"]["source"] == "langgraph.callback"
    assert result["metadata"]["chain_name"] == "planner"


def test_nested_chain_start_does_not_emit_execution_started():
    """Nested chains (parent_run_id set) are not top-level
    executions — they're internal Runnable composition. We
    emit ExecutionStarted only for top-level chains."""
    result = translate_langgraph_event(
        event=_nested_chain_start(),
        execution_id="exec",
        agent_id="agent-1",
    )
    assert result is None


# ─── ExecutionCompleted from top-level on_chain_end + on_agent_finish ──


def test_top_level_chain_end_emits_execution_completed():
    result = translate_langgraph_event(
        event=_top_level_chain_end(duration_ms=2500),
        execution_id="exec",
        agent_id="agent-1",
    )
    assert result is not None
    assert result["event_type"] == "execution_completed"
    assert result["payload"]["duration_ms"] == 2500
    assert result["payload"]["actions_taken"] == 3


def test_nested_chain_end_does_not_emit():
    result = translate_langgraph_event(
        event={
            "hook": "on_chain_end",
            "outputs_summary": "internal",
            "run_id": "run_2",
            "parent_run_id": "run_1",
        },
        execution_id="exec",
        agent_id="agent-1",
    )
    assert result is None


def test_agent_finish_emits_execution_completed():
    result = translate_langgraph_event(
        event=_agent_finish(), execution_id="exec", agent_id="agent-1"
    )
    assert result is not None
    assert result["event_type"] == "execution_completed"
    assert result["payload"]["actions_taken"] == 3
    assert result["payload"]["duration_ms"] == 1500
    assert result["payload"]["outcome"]  # truncated str of return_values dict


# ─── PlanObserved from on_agent_action ──────────────────────────────────


def test_agent_action_emits_plan_observed():
    """on_agent_action represents the plan-stage decision (agent
    decided to call tool). Emits a canonical PlanObserved event, kept
    distinct from ToolCallObserved. The Watchlight lineage service's
    plan-vs-act correlator unions these across the execution."""
    result = translate_langgraph_event(
        event=_agent_action(tool="bank_transfer", tool_input="$10000"),
        execution_id="exec",
        agent_id="agent-1",
    )
    assert result is not None
    assert result["event_type"] == "plan_observed"
    assert result["payload"]["intended_tools"] == ["bank_transfer"]
    assert result["payload"]["plan_kind"] == "incremental"
    assert result["payload"]["rationale"] == "$10000"
    assert result["metadata"]["tool_name"] == "bank_transfer"
    # The legacy `decision` and `phase` fields are gone — the new
    # canonical shape is explicit about the plan signal.
    assert "decision" not in result["payload"]
    assert "phase" not in result["metadata"]


def test_agent_action_with_invalid_tool_name_returns_none():
    """Tool names with shell metacharacters / spaces / other invalid
    bytes drop the event rather than form a malformed plan. Validation
    matches the server-side tool-name regex.

    Empty / falsy tool names hit the pre-existing ``or "unknown"``
    fallback in the translator — they're not "invalid" from this
    test's perspective, they're coerced to a valid sentinel. The
    list below covers names that survive the fallback but fail the
    plan-event regex.
    """
    for bad in ("tool with space", "tool;rm -rf", "tool/path", "tool\nnewline"):
        result = translate_langgraph_event(
            event=_agent_action(tool=bad, tool_input="anything"),
            execution_id="exec",
            agent_id="agent-1",
        )
        assert result is None, f"expected None for invalid tool name {bad!r}"


def test_agent_action_emits_plan_without_rationale_when_no_input():
    """Rationale is optional; an empty tool_input produces a plan
    event without the field rather than carrying an empty string."""
    result = translate_langgraph_event(
        event={
            "hook": "on_agent_action",
            "tool": "fetch_news",
            "tool_input": None,
            "run_id": "run_4",
            "parent_run_id": "run_1",
        },
        execution_id="exec",
        agent_id="agent-1",
    )
    assert result is not None
    assert result["event_type"] == "plan_observed"
    assert result["payload"]["intended_tools"] == ["fetch_news"]
    assert "rationale" not in result["payload"]


def test_tool_start_emits_tool_call_observed():
    result = translate_langgraph_event(
        event=_tool_start("web_search", "Q3 revenue figures"),
        execution_id="exec",
        agent_id="agent-1",
    )
    assert result is not None
    assert result["event_type"] == "tool_call_observed"
    # Canonical ResourceRef shape — `endpoint` carries the
    # namespaced URI; `resource_type` + `identifier` are the typed
    # fields the Watchlight event-schema deserializer expects.
    assert result["payload"]["tool"]["resource_type"] == "tool"
    assert result["payload"]["tool"]["identifier"] == "web_search"
    assert result["payload"]["tool"]["endpoint"] == "langgraph://tool/web_search"
    # Value-free: the argument's type, never its text.
    assert result["payload"]["input_summary"] == "1 arg: (str)"
    assert "Q3 revenue" not in repr(result)


def test_tool_end_emits_completed_tool_call_with_duration():
    result = translate_langgraph_event(
        event=_tool_end("web_search", duration_ms=250),
        execution_id="exec",
        agent_id="agent-1",
    )
    assert result is not None
    assert result["event_type"] == "tool_call_observed"
    assert result["payload"]["decision"] == "completed"
    assert result["payload"]["duration_ms"] == 250
    assert result["metadata"]["phase"] == "completed"


def test_tool_input_summary_is_value_free_and_bounded():
    """Bounded per-event size, and no argument value on the event: a
    truncated value can still carry a credential."""
    long_input = "x" * 500
    result = translate_langgraph_event(
        event=_tool_start("calc", long_input),
        execution_id="exec",
        agent_id="agent-1",
    )
    assert result is not None
    assert len(result["payload"]["input_summary"]) <= 120
    assert "xxxx" not in repr(result)


def test_structured_inputs_summarise_names_and_types_only():
    event = _tool_start("send", "ignored")
    event["inputs"] = {"to": "a@example.test", "token": "sk-live-SECRET"}
    result = translate_langgraph_event(
        event=event, execution_id="exec", agent_id="agent-1"
    )
    assert result["payload"]["input_summary"] == "2 args: to(str), token(str)"
    assert "sk-live-SECRET" not in repr(result)
    assert "a@example.test" not in repr(result)


# ─── ApiRequestObserved from LLM hooks ────────────────────────────────


def test_llm_start_emits_api_request_observed():
    result = translate_langgraph_event(
        event=_llm_start("gpt-4-turbo"),
        execution_id="exec",
        agent_id="agent-1",
    )
    assert result is not None
    assert result["event_type"] == "api_request_observed"
    assert result["payload"]["resource"]["resource_type"] == "llm_api"
    assert result["payload"]["resource"]["identifier"] == "gpt-4-turbo"
    assert result["payload"]["resource"]["endpoint"] == "langgraph://llm/gpt-4-turbo"
    assert result["metadata"]["model"] == "gpt-4-turbo"


def test_chat_model_start_emits_api_request_observed():
    """on_chat_model_start is the chat-model variant of
    on_llm_start. Both produce ApiRequestObserved with the same
    resource shape so downstream consumers can correlate without
    special-casing."""
    result = translate_langgraph_event(
        event={
            "hook": "on_chat_model_start",
            "serialized": {"name": "ChatAnthropic"},
            "model": "claude-3-5-sonnet",
            "invocation_params": {"model": "claude-3-5-sonnet"},
            "messages": [[{"role": "user", "content": "hi"}]],
            "run_id": "run_x",
            "parent_run_id": "run_1",
        },
        execution_id="exec",
        agent_id="agent-1",
    )
    assert result is not None
    assert result["event_type"] == "api_request_observed"
    assert result["payload"]["resource"]["resource_type"] == "llm_api"
    assert result["payload"]["resource"]["identifier"] == "claude-3-5-sonnet"
    assert result["payload"]["resource"]["endpoint"] == "langgraph://llm/claude-3-5-sonnet"


# ─── ExecutionFailed from error hooks ─────────────────────────────────


def test_chain_error_emits_execution_failed():
    result = translate_langgraph_event(
        event=_chain_error(), execution_id="exec", agent_id="agent-1"
    )
    assert result is not None
    assert result["event_type"] == "execution_failed"
    # Value-free: the exception class, never its message.
    assert result["payload"]["error"] == "ValueError"
    assert "planner produced" not in repr(result)
    assert result["payload"]["error_type"] == "ValueError"


def test_tool_error_emits_execution_failed():
    result = translate_langgraph_event(
        event=_tool_error(), execution_id="exec", agent_id="agent-1"
    )
    assert result is not None
    assert result["event_type"] == "execution_failed"
    assert result["payload"]["error"] == "RuntimeError"
    assert "upstream API timeout" not in repr(result)
    assert result["payload"]["error_type"] == "RuntimeError"


def test_llm_error_emits_execution_failed():
    result = translate_langgraph_event(
        event={
            "hook": "on_llm_error",
            "error": Exception("rate limited"),
            "run_id": "run_x",
            "parent_run_id": "run_1",
        },
        execution_id="exec",
        agent_id="agent-1",
    )
    assert result is not None
    assert result["event_type"] == "execution_failed"


def test_error_message_truncated_at_512_chars():
    huge_error = ValueError("x" * 2000)
    result = translate_langgraph_event(
        event={
            "hook": "on_chain_error",
            "error": huge_error,
            "run_id": "run_1",
            "parent_run_id": None,
        },
        execution_id="exec",
        agent_id="agent-1",
    )
    assert result is not None
    assert len(result["payload"]["error"]) <= 512
    assert "xxxx" not in result["payload"]["error"]


# ─── Ordering, batch, regression ──────────────────────────────────────


def test_batch_translation_preserves_order():
    """Multi-event flows must preserve ordering — drift detection
    and forensic replay both rely on it."""
    events = [
        _top_level_chain_start("planner"),
        _agent_action(tool="search"),
        _tool_start("search"),
        _tool_end("search"),
        _agent_finish(),
        _top_level_chain_end(),
    ]
    translated = translate_langgraph_events(
        events=events, execution_id="exec", agent_id="agent-1"
    )
    types = [e["event_type"] for e in translated]
    assert types == [
        "execution_started",
        "plan_observed",  # agent_action (plan-stage, distinct from tool_call_observed)
        "tool_call_observed",  # tool_start
        "tool_call_observed",  # tool_end (completed)
        "execution_completed",  # agent_finish
        "execution_completed",  # chain_end
    ]


def test_unmapped_events_are_dropped_silently_in_batch():
    """A batch with some unmapped + some mapped events emits only
    the mapped ones — never crashes mid-batch."""
    events = [
        _top_level_chain_start(),
        {"hook": "on_text", "text": "noise"},  # unmapped
        _tool_start("calc"),
        {"hook": "on_llm_new_token", "token": "a"},  # unmapped
        _top_level_chain_end(),
    ]
    translated = translate_langgraph_events(
        events=events, execution_id="exec", agent_id="agent-1"
    )
    assert len(translated) == 3
    assert [e["event_type"] for e in translated] == [
        "execution_started",
        "tool_call_observed",
        "execution_completed",
    ]


def test_malformed_event_does_not_break_subsequent_events():
    """Same robustness posture as the Bedrock translator: a single
    malformed event is skipped, subsequent events continue."""
    events = [
        _top_level_chain_start(),
        {"hook": "on_tool_start"},  # missing required fields — degrades gracefully
        _top_level_chain_end(),
    ]
    translated = translate_langgraph_events(
        events=events, execution_id="exec", agent_id="agent-1"
    )
    # The translator is permissive about missing fields; on_tool_start
    # with no name still emits with name="unknown". The key
    # robustness guarantee is "subsequent events succeed."
    types = [e["event_type"] for e in translated]
    assert "execution_started" in types
    assert "execution_completed" in types


# ─── Wire-format invariants ───────────────────────────────────────────


def test_every_emission_carries_source_metadata():
    """Provenance binding: every emitted event must name its source
    so downstream consumers can attribute it and detect
    fabrication."""
    events = [
        _top_level_chain_start(),
        _agent_action(),
        _tool_start(),
        _tool_end(),
        _llm_start(),
        _agent_finish(),
        _top_level_chain_end(),
        _chain_error(),
    ]
    translated = translate_langgraph_events(
        events=events, execution_id="exec", agent_id="agent-1"
    )
    assert len(translated) > 0
    for ev in translated:
        assert ev.get("metadata", {}).get("source") == "langgraph.callback", (
            f"missing source on {ev['event_type']}"
        )


def test_event_ids_are_unique():
    """Smoke check that event_id generation isn't cached/reused."""
    events = [_top_level_chain_start(), _top_level_chain_start()]
    translated = translate_langgraph_events(
        events=events, execution_id="exec", agent_id="agent-1"
    )
    assert translated[0]["event_id"] != translated[1]["event_id"]
    for ev in translated:
        assert ev["event_id"].startswith("evt_")


def test_serializable_to_json():
    """Wire contract: every event must round-trip through JSON
    cleanly. If anything emits a non-JSON-serializable value,
    the wl-apdp /v1/events POST will fail."""
    events = [
        _top_level_chain_start(),
        _tool_start("calc", "1+1"),
        _tool_end("calc"),
        _llm_start(),
        _chain_error(),
        _top_level_chain_end(),
    ]
    translated = translate_langgraph_events(
        events=events, execution_id="exec", agent_id="agent-1"
    )
    for ev in translated:
        round_trip = json.loads(json.dumps(ev))
        assert round_trip == ev


def test_parent_execution_id_propagates():
    result = translate_langgraph_event(
        event=_top_level_chain_start(),
        execution_id="exec_child",
        agent_id="agent-1",
        parent_execution_id="exec_parent",
    )
    assert result is not None
    assert result["execution_id"] == "exec_child"
    assert result["parent_execution_id"] == "exec_parent"
