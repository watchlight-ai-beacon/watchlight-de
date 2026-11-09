"""Tests for the LangGraph prompt extractor + its end-to-end
wiring into the canonical ``execution_started`` event.

Two layers under test:

1. ``watchlight_langgraph.intent.extract_intent_from_langgraph_inputs``
   — pure function, no I/O. Exercises the priority-key walk + the
   message-list special case + UTF-8 byte truncation.
2. The full callback → translator pipeline — confirms that an
   extracted prompt lands on the canonical ``execution_started``
   event's ``intent_objective`` + ``intent_provenance`` fields, and
   that the customer-declared override wins (declared >
   plugin_derived > absent).
"""

from __future__ import annotations

from typing import Any, Dict

from watchlight_core import INTENT_OBJECTIVE_MAX_BYTES, IntentProvenance
from watchlight_langgraph.callbacks import _capture_chain_start, _EventBuffer
from watchlight_langgraph.intent import extract_intent_from_langgraph_inputs
from watchlight_langgraph.traces import translate_langgraph_event


# ─── Unit tests — extract_intent_from_langgraph_inputs ────────────────


class _StubHumanMessage:
    """Stand-in for ``langchain_core.messages.HumanMessage``.

    The real class has ``.type == "human"`` and ``.content``;
    constructing it directly here pulls langchain_core into the test
    dep graph, which the existing test suite already does — but
    making our own stub keeps the test self-contained and the
    extraction logic doesn't actually care about the concrete class
    (only the duck-typed attributes)."""

    type = "human"

    def __init__(self, content: str) -> None:
        self.content = content


class _StubAiMessage:
    """Stand-in for the LangChain ``AIMessage`` — same shape but
    ``.type == "ai"``. Used to verify the extractor skips
    AI-authored entries when finding the last HUMAN message."""

    type = "ai"

    def __init__(self, content: str) -> None:
        self.content = content


def test_inputs_with_input_string_extracts_intent():
    """Single-prompt graph shape: ``{"input": "..."}``."""
    result = extract_intent_from_langgraph_inputs({"input": "audit Q3 invoices"})
    assert result == "audit Q3 invoices"


def test_inputs_with_messages_list_extracts_last_human_message():
    """Chat-style graph: latest HUMAN message wins regardless of
    interleaving AI responses."""
    inputs = {
        "messages": [
            _StubHumanMessage("first user turn"),
            _StubAiMessage("here is my response"),
            _StubHumanMessage("now do the audit"),
            _StubAiMessage("ok working on it"),
        ]
    }
    result = extract_intent_from_langgraph_inputs(inputs)
    assert result == "now do the audit"


def test_inputs_with_messages_list_extracts_dict_user_role():
    """OpenAI-style raw dict messages with ``role`` / ``content`` —
    the extractor recognises ``role == "user"`` as a human turn."""
    inputs = {
        "messages": [
            {"role": "system", "content": "you are an audit assistant"},
            {"role": "user", "content": "summarise the Q3 finding"},
            {"role": "assistant", "content": "starting now"},
        ]
    }
    result = extract_intent_from_langgraph_inputs(inputs)
    assert result == "summarise the Q3 finding"


def test_inputs_with_messages_list_falls_back_to_last_when_no_human():
    """When no HUMAN message exists (system + AI only), the last
    message of any kind is used so the agent's most recent context
    is still captured. Operator-legibility beats strict filtering."""
    inputs = {
        "messages": [
            {"role": "system", "content": "boot prompt"},
            _StubAiMessage("ai-only conversation start"),
        ]
    }
    result = extract_intent_from_langgraph_inputs(inputs)
    assert result == "ai-only conversation start"


def test_inputs_with_question_key_extracts_intent():
    """RAG-Q&A graph: ``{"question": "..."}``."""
    result = extract_intent_from_langgraph_inputs({"question": "what is the loan policy?"})
    assert result == "what is the loan policy?"


def test_inputs_with_query_key_extracts_intent():
    """Retrieval graph: ``{"query": "..."}``."""
    result = extract_intent_from_langgraph_inputs({"query": "find recent compliance docs"})
    assert result == "find recent compliance docs"


def test_inputs_with_prompt_key_extracts_intent():
    """Older completions-style graphs: ``{"prompt": "..."}``."""
    result = extract_intent_from_langgraph_inputs({"prompt": "draft a memo"})
    assert result == "draft a memo"


def test_priority_order_input_wins_over_messages():
    """When both ``input`` and ``messages`` are present the priority
    pass picks ``input`` first — single-prompt convention dominates."""
    inputs = {
        "input": "primary prompt",
        "messages": [_StubHumanMessage("secondary turn")],
    }
    result = extract_intent_from_langgraph_inputs(inputs)
    assert result == "primary prompt"


def test_inputs_with_only_non_string_values_returns_absent():
    """Dict with no recognised key and no string value → None.
    Treated as IntentProvenance.ABSENT downstream."""
    inputs: Dict[str, Any] = {
        "config": {"some": "nested"},
        "options": [1, 2, 3],
        "callback_count": 5,
    }
    assert extract_intent_from_langgraph_inputs(inputs) is None


def test_inputs_with_arbitrary_string_value_falls_back():
    """Deterministic fallback to the first string-valued key in
    sorted order when no priority key matches."""
    inputs = {"user_text": "do this thing", "metadata": {"opt": True}}
    result = extract_intent_from_langgraph_inputs(inputs)
    assert result == "do this thing"


def test_customer_supplied_intent_objective_wins_over_extraction():
    """Intent precedence chain: customer-declared > plugin-derived.

    The translator at on_chain_start time picks the higher-precedence
    lane. ``_intent_declared`` from the buffered event MUST beat
    ``_intent_extracted`` even when both are populated.
    """
    buffer = _EventBuffer()
    _capture_chain_start(
        buffer,
        serialized={"name": "agent"},
        inputs={"input": "auto-extracted prompt"},
        run_id="run_1",
        parent_run_id=None,
        declared_intent_objective="customer-declared objective",
    )
    captured = buffer.drain()[0]

    event = translate_langgraph_event(
        event=captured,
        execution_id="exec_x",
        agent_id="agent-1",
    )
    assert event is not None
    assert event["event_type"] == "execution_started"
    assert event["payload"]["intent_objective"] == "customer-declared objective"
    assert event["payload"]["intent_provenance"] == "declared"


def test_byte_truncation_handles_unicode_boundary():
    """Multi-byte UTF-8 input is byte-truncated without splitting a
    codepoint. The intent-objective contract caps at 256 UTF-8 BYTES,
    not chars."""
    # The check mark "✓" is 3 bytes in UTF-8. 100 of them = 300 bytes,
    # which exceeds the 256-byte cap. The result MUST still be valid
    # UTF-8 (no half-codepoint) and must be ≤ 256 bytes.
    pad = "✓" * 100
    result = extract_intent_from_langgraph_inputs({"input": pad})
    assert result is not None
    encoded = result.encode("utf-8")
    assert len(encoded) <= INTENT_OBJECTIVE_MAX_BYTES
    # The truncated string must still be valid UTF-8 (decode round-
    # trips without ``errors="ignore"`` skipping anything).
    assert result == encoded.decode("utf-8")
    # 256 // 3 = 85 full codepoints fit; the result is therefore 85
    # check marks long.
    assert len(result) == INTENT_OBJECTIVE_MAX_BYTES // 3


def test_byte_truncation_no_op_when_under_cap():
    """A prompt that fits under the byte cap is returned verbatim."""
    short = "hello world"
    assert extract_intent_from_langgraph_inputs({"input": short}) == short


def test_empty_inputs_results_in_absent():
    """Empty dict → None; downstream stamps IntentProvenance.ABSENT
    (i.e. omits the field from the canonical payload entirely)."""
    assert extract_intent_from_langgraph_inputs({}) is None


def test_non_dict_inputs_returns_none():
    """Defensive: a non-dict ``inputs`` (LangChain SDK shape drift,
    upstream bug, etc.) returns None without raising. The callback
    path MUST never raise."""
    assert extract_intent_from_langgraph_inputs(None) is None
    assert extract_intent_from_langgraph_inputs("not a dict") is None
    assert extract_intent_from_langgraph_inputs(["a", "list"]) is None


def test_empty_string_input_returns_none():
    """Empty-string value under a priority key does NOT produce a
    populated objective. The conformance invariant forbids
    ``intent_objective is not None && provenance == Absent``;
    this is the inverse case where the extractor would otherwise
    produce empty + PluginDerived."""
    assert extract_intent_from_langgraph_inputs({"input": ""}) is None


# ─── End-to-end pipeline tests ────────────────────────────────────────


def test_capture_and_translate_emits_intent_with_plugin_derived_provenance():
    """Full pipeline: buffered on_chain_start → translator →
    canonical execution_started. Confirms intent_objective + the
    canonical IntentProvenance.PLUGIN_DERIVED wire string land on
    the payload."""
    buffer = _EventBuffer()
    _capture_chain_start(
        buffer,
        serialized={"name": "audit_agent"},
        inputs={"input": "review the audit findings"},
        run_id="run_1",
        parent_run_id=None,
    )
    captured = buffer.drain()
    assert len(captured) == 1
    event = translate_langgraph_event(
        event=captured[0],
        execution_id="exec_x",
        agent_id="agent-1",
        session_id="sess",
        tenant_id="acme",
    )
    assert event is not None
    assert event["event_type"] == "execution_started"
    assert event["payload"]["intent_objective"] == "review the audit findings"
    # Wire-string pinning — Cedar templates match on this exact
    # lowercase value. Keep this assertion verbatim.
    assert event["payload"]["intent_provenance"] == "plugin_derived"
    assert event["payload"]["intent_provenance"] == IntentProvenance.PLUGIN_DERIVED.value


def test_empty_inputs_pipeline_results_in_absent_payload():
    """With no extractable prompt, the canonical payload contains
    NEITHER ``intent_objective`` nor ``intent_provenance`` — the
    Cedar-canonical "Absent" shape. The dashboard + Cedar treat
    absence as IntentProvenance.ABSENT."""
    buffer = _EventBuffer()
    _capture_chain_start(
        buffer,
        serialized={"name": "agent"},
        inputs={},
        run_id="run_1",
        parent_run_id=None,
    )
    captured = buffer.drain()[0]
    event = translate_langgraph_event(
        event=captured,
        execution_id="exec_x",
        agent_id="agent-1",
    )
    assert event is not None
    assert event["event_type"] == "execution_started"
    assert "intent_objective" not in event["payload"]
    assert "intent_provenance" not in event["payload"]
