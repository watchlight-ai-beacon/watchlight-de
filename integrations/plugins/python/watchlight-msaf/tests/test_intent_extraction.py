"""Tests for the MSAF intent extractor + its end-to-end wiring into
the canonical ``execution_started`` event.

**Status**: MSAF's middleware shim that produces real synthetic
captures is not yet shipped (deferred to a follow-up release). The
extractor + translator wiring is the surface the future shim will
call; these tests pin the contract so the shim has a stable target.

Two layers under test:

1. ``watchlight_msaf.intent.extract_intent_from_messages`` —
   pure-function walker over MSAF-shaped ``ChatMessage`` lists.
2. The full capture → translator pipeline — confirms an extracted
   prompt lands on the canonical ``execution_started`` event's
   ``intent_objective`` + ``intent_provenance`` fields with the
   correct precedence chain.
"""

from __future__ import annotations

from types import SimpleNamespace

from watchlight_core import INTENT_OBJECTIVE_MAX_BYTES, IntentProvenance
from watchlight_msaf.intent import (
    extract_intent_from_messages,
    truncate_intent_objective,
)
from watchlight_msaf.traces import translate_msaf_event


# ─── Stubs ────────────────────────────────────────────────────────────


class _StubTextContent:
    """Stand-in for MSAF's ``TextContent`` part."""

    def __init__(self, text: str) -> None:
        self.text = text


def _msg(role: str, *texts: str) -> SimpleNamespace:
    """Build a stub MSAF ``ChatMessage`` with the given role + text
    parts. Attribute-shape (mirrors the dataclass form MSAF exposes
    in-process)."""
    return SimpleNamespace(
        role=role,
        contents=[_StubTextContent(t) for t in texts],
    )


def _dict_msg(role: str, content: str) -> dict:
    """Build a round-tripped-through-JSON dict MSAF message."""
    return {"role": role, "content": content}


# ─── Unit tests — extract_intent_from_messages ────────────────────────


def test_messages_list_extracts_latest_user_turn():
    """Multi-turn conversation: the LATEST user message wins
    (operator-relevant intent is the most recent utterance, not
    earlier context the model has already consumed)."""
    messages = [
        _msg("user", "first turn"),
        _msg("assistant", "hello! how can I help?"),
        _msg("user", "now do the audit"),
        _msg("assistant", "starting the audit now"),
    ]
    assert extract_intent_from_messages(messages) == "now do the audit"


def test_messages_list_dict_user_role_extracts():
    """Dict-shape messages (round-tripped through JSON by an HTTP
    shim) work the same as the attribute-shape."""
    messages = [
        _dict_msg("system", "you are an audit assistant"),
        _dict_msg("user", "summarise the Q3 finding"),
        _dict_msg("assistant", "ok"),
    ]
    assert extract_intent_from_messages(messages) == "summarise the Q3 finding"


def test_messages_list_with_no_user_role_returns_none():
    """Lists with only system + assistant turns have no extractable
    user intent. Returns None → IntentProvenance.ABSENT downstream."""
    messages = [
        _msg("system", "system prompt"),
        _msg("assistant", "no user turn yet"),
    ]
    assert extract_intent_from_messages(messages) is None


def test_multi_part_user_content_concatenated():
    """User message with multiple TextContent parts produces a single
    concatenated intent objective."""
    messages = [_msg("user", "audit", "Q3 invoices")]
    assert extract_intent_from_messages(messages) == "audit Q3 invoices"


def test_non_text_content_part_is_skipped():
    """Function-call / image parts (no ``.text``) are skipped; text
    parts still extract."""
    function_call_part = SimpleNamespace(function_call={"name": "fetch"})
    user_msg = SimpleNamespace(
        role="user",
        contents=[function_call_part, _StubTextContent("actual prompt")],
    )
    assert extract_intent_from_messages([user_msg]) == "actual prompt"


def test_enum_role_object_recognised():
    """MSAF's ``Role`` enum stringifies as ``Role.USER``. The
    extractor matches the trailing ``user`` substring case-
    insensitively rather than depending on exact equality."""

    class _RoleEnum:
        name = "USER"

        def __str__(self) -> str:
            return "Role.USER"

    user_msg = SimpleNamespace(role=_RoleEnum(), contents=[_StubTextContent("hi")])
    assert extract_intent_from_messages([user_msg]) == "hi"


def test_none_messages_returns_none():
    assert extract_intent_from_messages(None) is None


def test_non_iterable_returns_none():
    assert extract_intent_from_messages(42) is None


def test_empty_messages_returns_none():
    assert extract_intent_from_messages([]) is None


def test_empty_text_in_user_message_returns_none():
    """A user message with empty (after strip) content is not a
    valid intent signal — return None rather than masquerade as
    plugin-derived intent. (An empty-but-populated objective with
    PluginDerived provenance would also be a contract violation.)"""
    messages = [_msg("user", "   ")]
    assert extract_intent_from_messages(messages) is None


def test_iteration_failure_returns_none():
    """A pathological messages object that raises on iteration is
    treated as 'no signal' rather than propagating."""

    class _Exploder:
        def __iter__(self):
            raise RuntimeError("simulated shim shape drift")

    assert extract_intent_from_messages(_Exploder()) is None


# ─── Truncation invariants ────────────────────────────────────────────


def test_truncate_returns_none_on_none():
    assert truncate_intent_objective(None) is None


def test_truncate_returns_none_on_whitespace_only():
    assert truncate_intent_objective("   \n") is None


def test_truncate_byte_safe_on_unicode_boundary():
    """The check mark ``✓`` is 3 bytes UTF-8. 100 of them = 300
    bytes; truncation must drop the partial codepoint and stay
    ≤ 256 bytes."""
    pad = "✓" * 100
    result = truncate_intent_objective(pad)
    assert result is not None
    encoded = result.encode("utf-8")
    assert len(encoded) <= INTENT_OBJECTIVE_MAX_BYTES
    assert result == encoded.decode("utf-8")  # round-trip valid
    assert len(result) == INTENT_OBJECTIVE_MAX_BYTES // 3


# ─── End-to-end translator wiring tests ───────────────────────────────


def test_translator_emits_plugin_derived_for_pre_resolved_objective():
    """Capture carries ``intent_objective`` but no explicit
    ``intent_provenance`` → translator stamps PLUGIN_DERIVED. This is
    the path the shim will exercise once shipped (extract on its
    side, hand off the pre-resolved string)."""
    capture = {
        "hook": "workflow_run_start",
        "intent_objective": "review the audit findings",
        "depth": 0,
    }
    result = translate_msaf_event(
        capture=capture,
        execution_id="exec_x",
        agent_id="agent-1",
    )
    assert result is not None
    assert result["payload"]["intent_objective"] == "review the audit findings"
    assert result["payload"]["intent_provenance"] == "plugin_derived"
    assert result["payload"]["intent_provenance"] == IntentProvenance.PLUGIN_DERIVED.value


def test_translator_honours_declared_provenance_override():
    """Capture with explicit ``intent_provenance`` is preserved
    verbatim — the declared lane (synthetic
    ``watchlight.declare_intent`` tool / explicit start_run kwarg)
    stamps DECLARED here."""
    capture = {
        "hook": "workflow_run_start",
        "intent_objective": "customer-declared objective",
        "intent_provenance": IntentProvenance.DECLARED.value,
        "depth": 0,
    }
    result = translate_msaf_event(
        capture=capture,
        execution_id="exec_x",
        agent_id="agent-1",
    )
    assert result is not None
    assert result["payload"]["intent_objective"] == "customer-declared objective"
    assert result["payload"]["intent_provenance"] == "declared"


def test_translator_extracts_from_messages_fallback():
    """Capture carries raw ``messages`` (no pre-resolved objective)
    → translator runs in-process extraction and stamps PLUGIN_DERIVED.
    This is the alternative shim contract: hand off raw messages,
    let the translator extract."""
    capture = {
        "hook": "workflow_run_start",
        "messages": [
            _msg("system", "boot"),
            _msg("user", "find Q3 outliers"),
        ],
        "depth": 0,
    }
    result = translate_msaf_event(
        capture=capture,
        execution_id="exec_x",
        agent_id="agent-1",
    )
    assert result is not None
    assert result["payload"]["intent_objective"] == "find Q3 outliers"
    assert result["payload"]["intent_provenance"] == "plugin_derived"


def test_translator_emits_absent_when_no_intent_anywhere():
    """No ``intent_objective``, no ``messages``, no explicit
    provenance → both fields omitted from the payload. Cedar
    treats absence-of-provenance as IntentProvenance.ABSENT."""
    capture = {
        "hook": "workflow_run_start",
        "depth": 0,
    }
    result = translate_msaf_event(
        capture=capture,
        execution_id="exec_x",
        agent_id="agent-1",
    )
    assert result is not None
    assert result["event_type"] == "execution_started"
    assert "intent_objective" not in result["payload"]
    assert "intent_provenance" not in result["payload"]


def test_translator_drops_orphan_provenance_without_objective():
    """A non-Absent provenance without a populated objective is
    inconsistent. The translator drops the orphan rather than emit a
    payload that violates the canonical schema's Pydantic invariant."""
    capture = {
        "hook": "workflow_run_start",
        "intent_provenance": IntentProvenance.PLUGIN_DERIVED.value,
        "depth": 0,
    }
    result = translate_msaf_event(
        capture=capture,
        execution_id="exec_x",
        agent_id="agent-1",
    )
    assert result is not None
    assert "intent_objective" not in result["payload"]
    assert "intent_provenance" not in result["payload"]


def test_explicit_objective_wins_over_messages_extraction():
    """When both ``intent_objective`` and ``messages`` are present,
    the pre-resolved objective wins (the shim already extracted —
    don't second-guess)."""
    capture = {
        "hook": "workflow_run_start",
        "intent_objective": "shim-extracted",
        "messages": [_msg("user", "secondary turn")],
        "depth": 0,
    }
    result = translate_msaf_event(
        capture=capture,
        execution_id="exec_x",
        agent_id="agent-1",
    )
    assert result is not None
    assert result["payload"]["intent_objective"] == "shim-extracted"
    assert result["payload"]["intent_provenance"] == "plugin_derived"
