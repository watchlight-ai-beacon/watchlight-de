"""Tests for the ADK prompt extractor + its end-to-end wiring
into the canonical ``execution_started`` event.

Two layers under test:

1. ``watchlight_adk.intent.extract_intent_from_callback_context`` — the
   pure-function walker over ADK's ``CallbackContext`` shapes. Covers
   modern ADK (``user_content`` on the Context directly), the legacy
   ``invocation_context.user_content`` path, the string-only
   ``user_input`` fallback, and the ``session.events`` reverse-walk.
2. The full callback → translator pipeline — confirms an extracted
   prompt lands on the canonical ``execution_started`` event's
   ``intent_objective`` + ``intent_provenance`` fields, that the
   provenance-override path works (a caller can stamp ``DECLARED``
   directly), and that empty inputs leave both fields off the payload
   (the Absent shape).
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any, List, Optional

from watchlight_core import INTENT_OBJECTIVE_MAX_BYTES, IntentProvenance
from watchlight_adk.intent import (
    extract_intent_from_callback_context,
    truncate_intent_objective,
)
from watchlight_adk.traces import translate_adk_event


# ─── Stubs that mimic ADK's surface without pulling in the SDK ────────


class _StubPart:
    """Stand-in for ``google.genai.types.Part``. Real Part has a
    ``.text`` attribute; the extractor duck-types on it."""

    def __init__(self, text: Optional[str] = None) -> None:
        self.text = text


class _StubContent:
    """Stand-in for ``google.genai.types.Content``. Carries
    ``role`` + ``parts``."""

    def __init__(self, role: str, parts: List[_StubPart]) -> None:
        self.role = role
        self.parts = parts


class _StubEvent:
    """Stand-in for an ADK Session ``Event``."""

    def __init__(
        self,
        author: Optional[str],
        content: Optional[_StubContent],
    ) -> None:
        self.author = author
        self.content = content


class _StubSession:
    def __init__(self, events: List[_StubEvent]) -> None:
        self.events = events


def _make_user_content(text: str) -> _StubContent:
    return _StubContent(role="user", parts=[_StubPart(text=text)])


def _ctx_modern(text: str) -> SimpleNamespace:
    """Modern ADK: ``user_content`` directly on the CallbackContext."""
    return SimpleNamespace(user_content=_make_user_content(text))


def _ctx_legacy_invocation(text: str) -> SimpleNamespace:
    """Legacy ADK: ``user_content`` lives under ``invocation_context``."""
    return SimpleNamespace(
        user_content=None,
        invocation_context=SimpleNamespace(user_content=_make_user_content(text)),
    )


def _ctx_user_input(text: str) -> SimpleNamespace:
    """Older ADK: only the string ``user_input`` is exposed."""
    return SimpleNamespace(
        user_content=None,
        invocation_context=SimpleNamespace(
            user_content=None,
            user_input=text,
        ),
    )


def _ctx_session_events(events: List[_StubEvent]) -> SimpleNamespace:
    return SimpleNamespace(
        user_content=None,
        invocation_context=SimpleNamespace(
            user_content=None,
            user_input=None,
            session=_StubSession(events),
        ),
    )


# ─── Unit tests — extract_intent_from_callback_context ────────────────


def test_modern_user_content_extracts_intent():
    """``CallbackContext.user_content`` carries the user message."""
    ctx = _ctx_modern("audit Q3 invoices")
    assert extract_intent_from_callback_context(ctx) == "audit Q3 invoices"


def test_legacy_invocation_context_user_content_extracts_intent():
    """Older ADK exposes the same Content via ``invocation_context``."""
    ctx = _ctx_legacy_invocation("review the audit findings")
    assert extract_intent_from_callback_context(ctx) == "review the audit findings"


def test_user_input_string_fallback_extracts_intent():
    """Oldest path: ``invocation_context.user_input`` as a plain string."""
    ctx = _ctx_user_input("draft the policy memo")
    assert extract_intent_from_callback_context(ctx) == "draft the policy memo"


def test_session_events_reverse_walk_picks_latest_user_turn():
    """When the user_content/user_input lanes are empty, walk the
    session's event list in REVERSE and return the latest user-
    authored turn — the operator-relevant intent is the most recent
    user utterance, not earlier turns the model has already consumed.
    """
    events = [
        _StubEvent(author="user", content=_make_user_content("first turn")),
        _StubEvent(
            author="research-agent",
            content=_StubContent(role="model", parts=[_StubPart(text="thinking…")]),
        ),
        _StubEvent(author="user", content=_make_user_content("now do the audit")),
        _StubEvent(
            author="research-agent",
            content=_StubContent(role="model", parts=[_StubPart(text="ok")]),
        ),
    ]
    ctx = _ctx_session_events(events)
    assert extract_intent_from_callback_context(ctx) == "now do the audit"


def test_session_events_no_user_turn_returns_none():
    """Session with only model/tool turns has no extractable intent.
    Returns None → IntentProvenance.ABSENT at the translator."""
    events = [
        _StubEvent(
            author="research-agent",
            content=_StubContent(role="model", parts=[_StubPart(text="hi")]),
        ),
    ]
    ctx = _ctx_session_events(events)
    assert extract_intent_from_callback_context(ctx) is None


def test_user_authored_event_without_author_attribute_falls_back_to_role():
    """Some ADK builds set ``Content.role == "user"`` but leave
    ``Event.author`` unset. The extractor must still recognise the
    turn as user-authored via the Content's role."""
    events = [
        _StubEvent(author=None, content=_make_user_content("infer me by role")),
    ]
    ctx = _ctx_session_events(events)
    assert extract_intent_from_callback_context(ctx) == "infer me by role"


def test_multi_part_user_content_concatenated():
    """A user message with multiple text Parts should produce a single
    concatenated prompt (multi-part inline instructions are still one
    intent objective)."""
    ctx = SimpleNamespace(
        user_content=_StubContent(
            role="user",
            parts=[_StubPart(text="audit"), _StubPart(text="Q3 invoices")],
        )
    )
    assert extract_intent_from_callback_context(ctx) == "audit Q3 invoices"


def test_non_text_part_is_skipped():
    """A Part without a ``text`` attribute (function call, image) is
    skipped; remaining text Parts still extract."""
    function_call_part = SimpleNamespace(function_call={"name": "f"})
    ctx = SimpleNamespace(
        user_content=_StubContent(
            role="user",
            parts=[function_call_part, _StubPart(text="the user's actual prompt")],
        )
    )
    assert extract_intent_from_callback_context(ctx) == "the user's actual prompt"


def test_non_user_role_content_returns_none():
    """A Content with role==model on the user_content surface is NOT
    user intent — defensively reject so an upstream bug doesn't let
    model output masquerade as user intent."""
    ctx = SimpleNamespace(
        user_content=_StubContent(
            role="model",
            parts=[_StubPart(text="this is the model talking")],
        )
    )
    assert extract_intent_from_callback_context(ctx) is None


def test_none_context_returns_none():
    """Defensive: ``None`` Context never raises."""
    assert extract_intent_from_callback_context(None) is None


def test_empty_string_user_content_returns_none():
    """An empty prompt (after strip) is NOT plugin-derived intent.
    The intent conformance invariant forbids a populated objective
    with Absent provenance — and a present-but-empty objective with
    PluginDerived provenance is the inverse pathology we also
    forbid by treating empty-after-strip as no signal."""
    ctx = _ctx_modern("   ")
    assert extract_intent_from_callback_context(ctx) is None


def test_attribute_error_does_not_propagate():
    """A pathological Context whose attribute access raises (test
    harness mock, partial SDK upgrade) is treated as 'no signal'
    rather than propagating into the callback path."""

    class _Exploder:
        @property
        def user_content(self) -> Any:
            raise RuntimeError("simulated SDK shape drift")

        @property
        def invocation_context(self) -> Any:
            raise RuntimeError("also exploding")

    assert extract_intent_from_callback_context(_Exploder()) is None


# ─── Truncation invariants ────────────────────────────────────────────


def test_truncate_returns_none_on_none():
    assert truncate_intent_objective(None) is None


def test_truncate_returns_none_on_whitespace_only():
    assert truncate_intent_objective("   \n\t") is None


def test_truncate_short_string_passthrough():
    assert truncate_intent_objective("hello world") == "hello world"


def test_truncate_byte_safe_on_unicode_boundary():
    """The check mark ``✓`` is 3 bytes in UTF-8. 100 of them = 300
    bytes, exceeding the 256-byte cap. The truncation must stay
    UTF-8-valid (no half-codepoint) and never exceed the cap."""
    pad = "✓" * 100
    result = truncate_intent_objective(pad)
    assert result is not None
    encoded = result.encode("utf-8")
    assert len(encoded) <= INTENT_OBJECTIVE_MAX_BYTES
    assert result == encoded.decode("utf-8")  # round-trip valid
    # 256 // 3 = 85 full codepoints fit, exact ceiling.
    assert len(result) == INTENT_OBJECTIVE_MAX_BYTES // 3


def test_extract_truncates_long_prompt():
    """End-to-end: a long extracted prompt is byte-truncated at the
    256-byte cap before the canonical event is built."""
    long_prompt = "a" * 1000
    ctx = _ctx_modern(long_prompt)
    result = extract_intent_from_callback_context(ctx)
    assert result is not None
    assert len(result.encode("utf-8")) <= INTENT_OBJECTIVE_MAX_BYTES


# ─── End-to-end translator wiring tests ───────────────────────────────


def test_translator_emits_intent_with_plugin_derived_provenance():
    """A capture that carries an extracted ``intent_objective`` (no
    explicit ``intent_provenance``) lands on the canonical event as
    PluginDerived. Wire-string pin: the Cedar intent templates match on
    the lowercase ``"plugin_derived"`` literal."""
    capture = {
        "hook": "before_agent_callback",
        "agent_name": "research-analyst",
        "depth": 0,
        "intent_objective": "review the audit findings",
    }
    result = translate_adk_event(
        capture=capture,
        execution_id="exec_x",
        agent_id="agent-1",
    )
    assert result is not None
    assert result["event_type"] == "execution_started"
    assert result["payload"]["intent_objective"] == "review the audit findings"
    assert result["payload"]["intent_provenance"] == "plugin_derived"
    assert result["payload"]["intent_provenance"] == IntentProvenance.PLUGIN_DERIVED.value


def test_translator_honours_declared_provenance_override():
    """When the capture carries an explicit ``intent_provenance``
    string (the declared lane) the translator preserves it. This is
    the precedence-chain seam: declared > plugin_derived > absent."""
    capture = {
        "hook": "before_agent_callback",
        "agent_name": "research-analyst",
        "depth": 0,
        "intent_objective": "customer-declared objective",
        "intent_provenance": IntentProvenance.DECLARED.value,
    }
    result = translate_adk_event(
        capture=capture,
        execution_id="exec_x",
        agent_id="agent-1",
    )
    assert result is not None
    assert result["payload"]["intent_objective"] == "customer-declared objective"
    assert result["payload"]["intent_provenance"] == "declared"


def test_translator_emits_absent_when_no_intent_extracted():
    """No ``intent_objective`` in the capture → the canonical payload
    omits BOTH ``intent_objective`` and ``intent_provenance``. The
    legacy wire shape is byte-identical to IntentProvenance.ABSENT
    per the canonical events schema."""
    capture = {
        "hook": "before_agent_callback",
        "agent_name": "research-analyst",
        "depth": 0,
    }
    result = translate_adk_event(
        capture=capture,
        execution_id="exec_x",
        agent_id="agent-1",
    )
    assert result is not None
    assert result["event_type"] == "execution_started"
    assert "intent_objective" not in result["payload"]
    assert "intent_provenance" not in result["payload"]


def test_translator_drops_inconsistent_provenance_without_objective():
    """Intent conformance invariant: a populated objective MUST
    carry a non-Absent provenance, AND a non-Absent provenance MUST
    carry a populated objective. A capture with provenance set but
    NO objective should produce neither field on the wire — the
    translator drops the orphaned provenance rather than emit an
    inconsistent payload."""
    capture = {
        "hook": "before_agent_callback",
        "agent_name": "research-analyst",
        "depth": 0,
        "intent_provenance": IntentProvenance.PLUGIN_DERIVED.value,
    }
    result = translate_adk_event(
        capture=capture,
        execution_id="exec_x",
        agent_id="agent-1",
    )
    assert result is not None
    assert "intent_objective" not in result["payload"]
    assert "intent_provenance" not in result["payload"]
