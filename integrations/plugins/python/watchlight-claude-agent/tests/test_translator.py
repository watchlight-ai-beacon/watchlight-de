"""Tests for the Claude Agent SDK hook-event translator.

Covers all six hook types + the seven canonical conformance
invariants on the produced events.
"""

from __future__ import annotations

from watchlight_claude_agent import (
    SOURCE_TAG,
    URI_SCHEME,
    translate_claude_agent_event,
    translate_claude_agent_events,
)


COMMON = {
    "execution_id": "exec_test",
    "agent_id": "agent-uuid",
    "session_id": "ses_test",
    "tenant_id": "default",
}


def test_pre_tool_use_translates_to_tool_call_observed():
    out = translate_claude_agent_event(
        {
            "hook": "PreToolUse",
            "tool_name": "fetch_data",
            "tool_input": {"url": "https://example.com"},
            "decision": "Allow",
        },
        **COMMON,
    )
    assert out is not None
    assert out["event_type"] == "tool_call_observed"
    assert out["payload"]["tool"]["identifier"] == "fetch_data"
    assert out["payload"]["tool"]["endpoint"].startswith(URI_SCHEME)
    assert out["payload"]["decision"] == "Allow"
    assert out["metadata"]["source"] == "claude-agent-sdk.pre_tool_use"
    assert out["event_id"].startswith("evt_")
    # Arg-shape drift contract: the sorted argument KEYS, never values.
    assert out["payload"]["arg_key_summary"] == "url"
    assert "example.com" not in out["payload"]["arg_key_summary"]


def test_pre_tool_use_arg_key_summary_is_sorted_keys_only_and_absent_without_input():
    out = translate_claude_agent_event(
        {
            "hook": "PreToolUse",
            "tool_name": "write",
            "tool_input": {"path": "/tmp/x", "encoding": "utf8", "content": "secret"},
        },
        **COMMON,
    )
    assert out["payload"]["arg_key_summary"] == "content,encoding,path"
    # Values live only in the redacted input_summary, never in the key summary.
    assert "secret" not in out["payload"]["arg_key_summary"]
    out = translate_claude_agent_event(
        {"hook": "PreToolUse", "tool_name": "noop", "tool_input": {}},
        **COMMON,
    )
    assert "arg_key_summary" not in out["payload"]
    out = translate_claude_agent_event(
        {"hook": "PostToolUse", "tool_name": "write", "tool_input": {"path": "/tmp/x"}},
        **COMMON,
    )
    assert "arg_key_summary" not in out["payload"]


def test_post_tool_use_carries_duration_and_source_suffix():
    out = translate_claude_agent_event(
        {
            "hook": "PostToolUse",
            "tool_name": "summarize",
            "tool_input": {"text": "hello world"},
            "duration_ms": 42,
        },
        **COMMON,
    )
    assert out is not None
    assert out["payload"]["duration_ms"] == 42
    assert out["metadata"]["source"] == "claude-agent-sdk.post_tool_use"


def test_post_tool_use_failure_carries_error_decision():
    out = translate_claude_agent_event(
        {
            "hook": "PostToolUseFailure",
            "tool_name": "publish",
            "tool_input": {},
            "error": "Rate limit exceeded",
        },
        **COMMON,
    )
    assert out is not None
    # Value-free: the SDK's error text is withheld.
    assert out["payload"]["decision"] == "Failed: error_detail_withheld"
    assert "Rate limit" not in repr(out)
    assert out["metadata"]["source"] == "claude-agent-sdk.post_tool_use_failure"


def test_user_prompt_submit_translates_to_execution_started():
    out = translate_claude_agent_event(
        {"hook": "UserPromptSubmit", "depth": 0},
        **COMMON,
    )
    assert out is not None
    assert out["event_type"] == "execution_started"
    assert out["payload"]["principal"]["principal_type"] == "agent"
    assert out["payload"]["depth"] == 0


def test_user_prompt_submit_preserves_subagent_depth():
    """Regression for the SUB-AGENT · DEPTH 0 dashboard bug.

    A Task sub-agent re-enters ``UserPromptSubmit`` inside its own loop;
    the customer's hook capture carries the SDK's real nesting depth. The
    translator MUST pass that depth through un-clobbered (wl-execution-
    graph stores ``payload.depth`` verbatim) — never floor it to 0.
    """
    # First-level Task sub-agent.
    child = translate_claude_agent_event(
        {"hook": "UserPromptSubmit", "depth": 1},
        **COMMON,
    )
    assert child is not None
    assert child["event_type"] == "execution_started"
    assert child["payload"]["depth"] == 1

    # Nested (sub-sub-agent) — depth ≥ 2 must survive too.
    grandchild = translate_claude_agent_event(
        {"hook": "UserPromptSubmit", "depth": 2},
        **COMMON,
    )
    assert grandchild is not None
    assert grandchild["payload"]["depth"] == 2

    # No depth key ⇒ root default 0 (the ``or 0`` fallback), never applied
    # to a capture that supplies a real depth.
    root = translate_claude_agent_event(
        {"hook": "UserPromptSubmit"},
        **COMMON,
    )
    assert root is not None
    assert root["payload"]["depth"] == 0


def test_stop_translates_to_execution_completed_with_counters():
    out = translate_claude_agent_event(
        {
            "hook": "Stop",
            "duration_ms": 1234,
            "actions_taken": 3,
            "actions_denied": 1,
        },
        **COMMON,
    )
    assert out is not None
    assert out["event_type"] == "execution_completed"
    assert out["payload"]["actions_taken"] == 3
    assert out["payload"]["actions_denied"] == 1


def test_subagent_start_is_dropped_server_attested():
    """Spawn attestation is SERVER-emitted only. wl-apdp's
    ``spawn_handler`` mints the authoritative ``agent_spawn_observed``;
    a plugin-emitted one is REJECTED at ``/v1/events`` ingest. The
    translator therefore DROPS the observational ``SubagentStart`` hook
    (the subagent's own ``execution_started`` comes from its
    ``UserPromptSubmit`` hook)."""
    out = translate_claude_agent_event(
        {
            "hook": "SubagentStart",
            "subagent_id": "sub-agent-1",
            "subagent_execution_id": "exec_sub_1",
        },
        **COMMON,
    )
    assert out is None


def test_subagent_start_drops_when_required_fields_missing():
    out = translate_claude_agent_event(
        {"hook": "SubagentStart"},  # missing subagent_id + exec
        **COMMON,
    )
    assert out is None


def test_plan_observed_translates_with_intended_tools():
    out = translate_claude_agent_event(
        {
            "hook": "PlanObserved",
            "intended_tools": ["fetch_data", "summarize"],
            "rationale": "Research then summarise.",
        },
        **COMMON,
    )
    assert out is not None
    assert out["event_type"] == "plan_observed"
    assert "fetch_data" in out["payload"]["intended_tools"]


def test_unknown_hook_returns_none():
    out = translate_claude_agent_event({"hook": "WhateverEvent"}, **COMMON)
    assert out is None


def test_translate_events_batch_filters_none_and_continues_on_error():
    captures = [
        {"hook": "UserPromptSubmit"},
        {"hook": "Unknown"},
        {"hook": "PostToolUse", "tool_name": "x", "tool_input": {}},
        {"hook": "Stop", "duration_ms": 100},
    ]
    out = translate_claude_agent_events(captures, **COMMON)
    # Unknown dropped; others kept.
    assert len(out) == 3
    types = [e["event_type"] for e in out]
    assert types == ["execution_started", "tool_call_observed", "execution_completed"]


def test_metadata_source_uses_canonical_tag_when_not_overridden():
    """Plan / spawn events that don't override source_extra should
    fall back to SOURCE_TAG (claude-agent-sdk.hook)."""
    out = translate_claude_agent_event(
        {
            "hook": "PlanObserved",
            "intended_tools": ["fetch"],
        },
        **COMMON,
    )
    assert out is not None
    assert out["metadata"]["source"] == SOURCE_TAG


def test_tool_call_input_summary_is_value_free():
    out = translate_claude_agent_event(
        {
            "hook": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "curl -H 'Authorization: Bearer sk-live-SECRET'"},
        },
        **COMMON,
    )
    assert out is not None
    assert out["payload"]["input_summary"] == "1 args: command(str)"
    assert "sk-live-SECRET" not in repr(out)
