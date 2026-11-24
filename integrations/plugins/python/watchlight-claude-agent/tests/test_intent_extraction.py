"""Intent-extraction tests for the Claude Agent SDK (Python lane).

The Claude Agent SDK fires ``UserPromptSubmit`` after ``SessionStart``.
The Python plugin's translator is post-hoc — the customer captures hook
events into a list and feeds them through
:func:`translate_claude_agent_events`. The translator mints
``execution_started`` *from* the ``UserPromptSubmit`` capture, not from
any earlier ``SessionStart`` (Option (a) — defer the
``execution_started`` emission until the prompt is in hand, so the
event carries a populated ``intent_objective`` + non-Absent
``intent_provenance`` from the first byte rather than back-filling
later). These tests pin that contract.

Five tests:

1. ``user_prompt_submit_populates_intent_objective``
2. ``byte_truncation_handles_unicode``
3. ``empty_prompt_emits_absent_provenance``
4. ``start_run_deferred_until_prompt_arrives`` (Option (a) design)
5. ``session_start_before_prompt_does_not_double_emit`` (regression)
"""

from __future__ import annotations

from watchlight_claude_agent import (
    extract_intent_from_user_prompt_submit,
    translate_claude_agent_event,
    translate_claude_agent_events,
    truncate_intent_objective,
)
from watchlight_core import INTENT_OBJECTIVE_MAX_BYTES, IntentProvenance


COMMON = dict(
    execution_id="exec_test",
    agent_id="agent-uuid-test",
    session_id="ses_test",
    tenant_id="tenant-test",
)


# ─── 1. user_prompt_submit_populates_intent_objective ─────────────────


def test_user_prompt_submit_populates_intent_objective():
    """A UserPromptSubmit capture with a non-empty prompt mints an
    execution_started event carrying the prompt as
    ``intent_objective`` and ``intent_provenance: plugin_derived``.
    """
    out = translate_claude_agent_event(
        {"hook": "UserPromptSubmit", "prompt": "audit Q3 invoices"},
        **COMMON,
    )
    assert out is not None
    assert out["event_type"] == "execution_started"
    assert out["payload"]["intent_objective"] == "audit Q3 invoices"
    assert out["payload"]["intent_provenance"] == IntentProvenance.PLUGIN_DERIVED.value


def test_extractor_returns_objective_and_plugin_derived_provenance():
    """Direct extractor unit — sanity check the tuple shape and the
    enum value (the conformance gate requires consistency between the
    two)."""
    obj, prov = extract_intent_from_user_prompt_submit(
        {"prompt": "open the day's quarantine queue"}
    )
    assert obj == "open the day's quarantine queue"
    assert prov == IntentProvenance.PLUGIN_DERIVED


# ─── 2. byte_truncation_handles_unicode ───────────────────────────────


def test_byte_truncation_handles_unicode():
    """A prompt heavier than 256 UTF-8 bytes after encoding gets
    byte-truncated. The result is valid UTF-8 (no replacement chars
    introduced) and strictly ≤ ``INTENT_OBJECTIVE_MAX_BYTES``.
    """
    # Each "✓" is 3 UTF-8 bytes. 100 of them = 300 bytes > 256 cap.
    prompt = "✓" * 100
    assert len(prompt.encode("utf-8")) == 300
    out = translate_claude_agent_event(
        {"hook": "UserPromptSubmit", "prompt": prompt},
        **COMMON,
    )
    assert out is not None
    truncated = out["payload"]["intent_objective"]
    # Byte-length must respect the cap.
    encoded = truncated.encode("utf-8")
    assert len(encoded) <= INTENT_OBJECTIVE_MAX_BYTES
    # Must still be valid UTF-8 (no U+FFFD replacement chars introduced
    # by a naive mid-codepoint cut).
    assert "�" not in truncated
    # Must consist entirely of the original ✓ codepoint — boundary back-
    # up dropped any partial bytes.
    assert set(truncated) == {"✓"}
    # 256 bytes / 3 bytes-per-✓ → 85 full ✓ codepoints (255 bytes used,
    # 1 byte unused because 256 is not divisible by 3).
    assert len(truncated) == 85
    # Provenance still plugin_derived.
    assert out["payload"]["intent_provenance"] == IntentProvenance.PLUGIN_DERIVED.value


def test_truncate_intent_objective_returns_none_for_empty_or_whitespace():
    """Helper-level: empty / whitespace-only input collapses to None
    (the caller treats None as the Absent-provenance signal)."""
    assert truncate_intent_objective(None) is None
    assert truncate_intent_objective("") is None
    assert truncate_intent_objective("   ") is None
    assert truncate_intent_objective("\n\t\r ") is None


def test_truncate_intent_objective_passthrough_under_cap():
    """A prompt under the cap is returned verbatim (only stripped)."""
    assert truncate_intent_objective("hello world") == "hello world"
    # Leading/trailing whitespace is stripped — the audit row shouldn't
    # carry attacker-injected padding.
    assert truncate_intent_objective("  audit Q3  ") == "audit Q3"


# ─── 3. empty_prompt_emits_absent_provenance ──────────────────────────


def test_empty_prompt_emits_absent_provenance():
    """A UserPromptSubmit capture with an empty / missing prompt emits
    an execution_started event with NO ``intent_objective`` field and
    NO ``intent_provenance`` field (the wire default — missing — is
    equivalent to ``IntentProvenance.ABSENT`` per the event schema).
    """
    out = translate_claude_agent_event(
        {"hook": "UserPromptSubmit", "prompt": ""},
        **COMMON,
    )
    assert out is not None
    assert out["event_type"] == "execution_started"
    # Conformance gate — absent objective + no provenance set.
    assert "intent_objective" not in out["payload"]
    assert "intent_provenance" not in out["payload"]


def test_missing_prompt_field_emits_absent_provenance():
    """A UserPromptSubmit capture with no ``prompt`` key at all is
    treated the same as an empty prompt — Absent provenance."""
    out = translate_claude_agent_event(
        {"hook": "UserPromptSubmit", "depth": 0},
        **COMMON,
    )
    assert out is not None
    assert "intent_objective" not in out["payload"]
    assert "intent_provenance" not in out["payload"]


def test_non_string_prompt_emits_absent_provenance():
    """A ``prompt`` field that isn't a string (e.g. accidentally a
    dict or None) is treated as no-signal → Absent. Defensive against
    SDK shape drift."""
    for bogus in (None, 42, ["nope"], {"text": "no"}):
        out = translate_claude_agent_event(
            {"hook": "UserPromptSubmit", "prompt": bogus},
            **COMMON,
        )
        assert out is not None, f"bogus prompt {bogus!r} should not drop event"
        assert "intent_objective" not in out["payload"]
        assert "intent_provenance" not in out["payload"]


# ─── 4. start_run_deferred_until_prompt_arrives (Option (a) design) ───


def test_start_run_deferred_until_prompt_arrives():
    """Verifies the Option (a) design decision: the translator does NOT
    mint an ``execution_started`` event from a ``SessionStart`` hook.
    The event is deferred until ``UserPromptSubmit`` so it can carry
    populated ``intent_objective`` + non-Absent ``intent_provenance``
    from the first byte. SessionStart, if surfaced as an unknown hook,
    is dropped — there is no transient ``intent_provenance: absent``
    emission to clean up later.
    """
    # SessionStart capture should NOT produce an execution_started event.
    session_start_out = translate_claude_agent_event(
        {"hook": "SessionStart"},
        **COMMON,
    )
    assert session_start_out is None, (
        "SessionStart MUST NOT mint an execution_started event in Option (a). "
        "The event is deferred until UserPromptSubmit so intent_objective "
        "can be populated from the first emission."
    )

    # UserPromptSubmit then mints the populated execution_started event.
    user_prompt_out = translate_claude_agent_event(
        {"hook": "UserPromptSubmit", "prompt": "summarize the daily report"},
        **COMMON,
    )
    assert user_prompt_out is not None
    assert user_prompt_out["event_type"] == "execution_started"
    assert user_prompt_out["payload"]["intent_objective"] == "summarize the daily report"
    assert (
        user_prompt_out["payload"]["intent_provenance"]
        == IntentProvenance.PLUGIN_DERIVED.value
    )


# ─── 5. session_start_before_prompt_does_not_double_emit (regression) ─


def test_session_start_before_prompt_does_not_double_emit():
    """Regression: a typical SDK lifecycle that fires SessionStart
    before UserPromptSubmit yields EXACTLY ONE execution_started event
    — the one minted from UserPromptSubmit, carrying populated intent
    fields. SessionStart contributes no transient ``Absent``-provenance
    event that would later need overwriting.
    """
    captures = [
        {"hook": "SessionStart"},
        {"hook": "UserPromptSubmit", "prompt": "research the Q4 outlook"},
        {"hook": "PostToolUse", "tool_name": "fetch", "tool_input": {"url": "x"}},
        {"hook": "Stop", "duration_ms": 50},
    ]
    events = translate_claude_agent_events(captures, **COMMON)
    execution_started_events = [
        e for e in events if e["event_type"] == "execution_started"
    ]
    assert (
        len(execution_started_events) == 1
    ), "Expected exactly one execution_started event from the UserPromptSubmit capture."
    only_started = execution_started_events[0]
    # Populated intent, non-Absent provenance — the conformance contract.
    assert only_started["payload"]["intent_objective"] == "research the Q4 outlook"
    assert (
        only_started["payload"]["intent_provenance"]
        == IntentProvenance.PLUGIN_DERIVED.value
    )


def test_back_to_back_prompts_each_get_own_intent():
    """Defensive: if the customer somehow captures two
    ``UserPromptSubmit`` events in one batch (multi-turn agent), each
    mints its own execution_started with its own
    ``intent_objective`` — the second does not silently inherit the
    first.
    """
    captures = [
        {"hook": "UserPromptSubmit", "prompt": "first goal"},
        {"hook": "UserPromptSubmit", "prompt": "second goal"},
    ]
    events = translate_claude_agent_events(captures, **COMMON)
    assert len(events) == 2
    assert events[0]["payload"]["intent_objective"] == "first goal"
    assert events[1]["payload"]["intent_objective"] == "second goal"


# ─── conformance gate — consistency between fields ────────────────────


def test_intent_objective_and_provenance_are_always_consistent():
    """The conformance invariant: if ``intent_objective``
    is set on the event payload, ``intent_provenance`` MUST be set
    AND MUST NOT be ``Absent``. If ``intent_objective`` is absent,
    ``intent_provenance`` MUST be absent (or Absent).
    """
    cases = [
        # Non-empty prompt → both populated, provenance plugin_derived.
        ("audit something", True, IntentProvenance.PLUGIN_DERIVED.value),
        # Whitespace-only → both absent.
        ("   ", False, None),
        # Empty string → both absent.
        ("", False, None),
    ]
    for prompt, expect_objective, expect_provenance in cases:
        out = translate_claude_agent_event(
            {"hook": "UserPromptSubmit", "prompt": prompt},
            **COMMON,
        )
        assert out is not None, f"prompt={prompt!r}"
        payload = out["payload"]
        if expect_objective:
            assert "intent_objective" in payload, f"prompt={prompt!r}"
            assert payload["intent_provenance"] == expect_provenance, (
                f"prompt={prompt!r}"
            )
            assert payload["intent_provenance"] != IntentProvenance.ABSENT.value
        else:
            assert "intent_objective" not in payload, f"prompt={prompt!r}"
            # The wire-absent shape — provenance simply omitted.
            assert "intent_provenance" not in payload, f"prompt={prompt!r}"
