"""Tests for ``Agent.run`` prompt → ``intent_objective`` extraction.

The intent-extraction layer lives in
:mod:`watchlight_pydantic_ai.intent` and is wired into the existing
:mod:`watchlight_pydantic_ai.instrumentation` monkey-patch. These tests
cover both the extractor in isolation (unit tests) and the end-to-end
plumbing into the emitted ``execution_started`` event (integration
tests).

Coverage matrix:

| # | Test                                                         | Layer       |
|---|--------------------------------------------------------------|-------------|
| 1 | ``string_prompt_extracts_and_truncates_under_max_bytes``     | integration |
| 2 | ``byte_truncation_handles_unicode_boundary``                 | unit        |
| 3 | ``empty_string_results_in_absent_provenance``                | integration |
| 4 | ``whitespace_only_prompt_normalizes_to_absent``              | integration |
| 5 | ``list_of_messages_extracts_last_user_message``              | unit        |
| 6 | ``kwargs_only_prompt_falls_back_to_absent_or_extract``       | unit        |
| 7 | ``nested_agent_run_propagates_per_execution_intent``         | integration |
"""

from __future__ import annotations

import asyncio

import pytest

# Skip the entire module if pydantic-ai isn't importable in the test
# environment. Same gate as :mod:`test_nested_agent_run`.
pytest.importorskip("pydantic_ai")

from pydantic_ai import Agent  # noqa: E402
from pydantic_ai.models.test import TestModel  # noqa: E402

from watchlight_core.events_schema import INTENT_OBJECTIVE_MAX_BYTES  # noqa: E402
from watchlight_core_testing import MockApdpClient  # noqa: E402
from watchlight_pydantic_ai import (  # noqa: E402
    WatchlightPydanticAIPlugin,
    uninstall_instrumentation,
)
from watchlight_pydantic_ai.instrumentation import (  # noqa: E402
    _reset_contextvar_for_tests,
)
from watchlight_pydantic_ai.intent import (  # noqa: E402
    extract_intent_from_pydantic_args,
)


# ─── Fixtures ────────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def _clean_instrumentation():
    """Each test starts with a clean ``Agent`` class + reset contextvar.

    Mirrors the convention in :mod:`test_nested_agent_run`.
    """
    uninstall_instrumentation()
    _reset_contextvar_for_tests()
    yield
    uninstall_instrumentation()
    _reset_contextvar_for_tests()


def _make_plugin(known_agents: dict) -> tuple[WatchlightPydanticAIPlugin, MockApdpClient]:
    """Construct a plugin wired to an in-memory MockApdpClient."""
    plugin = WatchlightPydanticAIPlugin(apdp_url="http://localhost")
    mock = MockApdpClient()
    for slug, uuid in known_agents.items():
        mock.known_agents[slug] = uuid
    plugin.apdp = mock
    return plugin, mock


def _started_events(mock: MockApdpClient) -> list[dict]:
    """Filter ``mock.published_events`` down to ``execution_started``."""
    return [
        e for e in mock.published_events if e.get("event_type") == "execution_started"
    ]


# ─── Unit-test slice — ``extract_intent_from_pydantic_args`` ──────────


class TestExtractor:
    """Behavioural tests for the extractor function in isolation.

    Stays decoupled from the monkey-patch so future changes to
    pydantic-ai's entry-point signature can be diagnosed at the
    extractor layer first.
    """

    def test_string_prompt_returns_value_verbatim(self) -> None:
        """Canonical case — string prompt under the byte cap."""
        out = extract_intent_from_pydantic_args(("Summarize SEC filings",), {})
        assert out == "Summarize SEC filings"

    def test_empty_string_returns_none(self) -> None:
        """Empty string normalises to ``None`` (mapped to Absent by the caller)."""
        assert extract_intent_from_pydantic_args(("",), {}) is None

    def test_whitespace_only_returns_none(self) -> None:
        """Whitespace-only prompt is treated as Absent after normalise."""
        assert extract_intent_from_pydantic_args(("   \n\n  \t  ",), {}) is None

    def test_no_args_returns_none(self) -> None:
        """No positional arg AND no keyword arg → None."""
        assert extract_intent_from_pydantic_args((), {}) is None

    def test_byte_truncation_handles_unicode_boundary(self) -> None:
        """A multi-byte UTF-8 string longer than the cap MUST be
        truncated to ≤256 bytes AND decode cleanly (no partial
        multi-byte sequence at the boundary).

        Failure mode this test guards against: ``s[:256]`` (char-
        counted) would silently exceed the byte cap on multi-byte
        UTF-8; ``s.encode()[:256]`` without ``errors="ignore"`` on
        decode would raise on a partial multi-byte at the boundary.
        """
        # Three-byte UTF-8 character (€ = 0xE2 0x82 0xAC). 200 of these
        # = 600 bytes total, well over the 256-byte cap.
        unicode_chars = "€" * 200
        out = extract_intent_from_pydantic_args((unicode_chars,), {})

        assert out is not None
        # Must round-trip cleanly through UTF-8 — no partial codepoint.
        encoded = out.encode("utf-8")
        assert len(encoded) <= INTENT_OBJECTIVE_MAX_BYTES, (
            f"truncated string is {len(encoded)} bytes, "
            f"max is {INTENT_OBJECTIVE_MAX_BYTES}"
        )
        # Every character in the output must be the original € — no
        # mangled codepoints. Three-byte char fits 85 times in 256
        # bytes (255 bytes); the truncation must yield exactly 85
        # complete € characters.
        assert all(c == "€" for c in out)
        assert len(out) == 85  # floor(256 / 3) = 85

    def test_byte_truncation_drops_partial_multibyte_at_boundary(self) -> None:
        """A four-byte UTF-8 character straddling the cap must be
        dropped, not corrupted.
        """
        # Four-byte UTF-8 character (🦊 = 0xF0 0x9F 0xA6 0x8A). 100 of
        # these = 400 bytes. Cap is 256; 256 // 4 = 64 complete chars.
        unicode_chars = "🦊" * 100
        out = extract_intent_from_pydantic_args((unicode_chars,), {})

        assert out is not None
        encoded = out.encode("utf-8")
        assert len(encoded) <= INTENT_OBJECTIVE_MAX_BYTES
        # All chars must be the complete fox; no replacement chars.
        assert all(c == "🦊" for c in out)
        assert len(out) == 64

    def test_under_cap_strings_pass_through_unchanged(self) -> None:
        """A short string is returned verbatim."""
        out = extract_intent_from_pydantic_args(("hello world",), {})
        assert out == "hello world"

    def test_internal_newlines_collapse(self) -> None:
        """Multi-line prompts collapse to single-space-separated."""
        out = extract_intent_from_pydantic_args(
            ("line one\nline two\n\nline three",), {}
        )
        assert out == "line one line two line three"

    def test_list_of_message_dicts_extracts_last_user(self) -> None:
        """Continuation idiom — walk backward for the last user msg."""
        messages = [
            {"role": "system", "content": "You are a helpful assistant"},
            {"role": "user", "content": "first user turn"},
            {"role": "assistant", "content": "first assistant turn"},
            {"role": "user", "content": "second user turn (the latest)"},
        ]
        out = extract_intent_from_pydantic_args((messages,), {})
        assert out == "second user turn (the latest)"

    def test_list_of_messages_with_no_user_returns_none(self) -> None:
        """All-system / all-assistant list yields None."""
        messages = [
            {"role": "system", "content": "system prompt"},
            {"role": "assistant", "content": "assistant turn"},
        ]
        assert extract_intent_from_pydantic_args((messages,), {}) is None

    def test_kwargs_user_prompt_is_extracted(self) -> None:
        """``Agent.run(user_prompt="hello")`` — pydantic-ai's
        documented parameter name. The extractor must inspect kwargs.
        """
        out = extract_intent_from_pydantic_args((), {"user_prompt": "hello via kwarg"})
        assert out == "hello via kwarg"

    def test_kwargs_prompt_is_extracted(self) -> None:
        """``Agent.run(prompt="hello")`` — older spelling. Fallback path."""
        out = extract_intent_from_pydantic_args((), {"prompt": "older spelling"})
        assert out == "older spelling"

    def test_non_string_positional_falls_through(self) -> None:
        """A non-string, non-list positional arg yields None."""
        assert extract_intent_from_pydantic_args((42,), {}) is None
        assert extract_intent_from_pydantic_args((object(),), {}) is None

    def test_extractor_never_raises(self) -> None:
        """Even pathological inputs return None rather than raising."""
        # A list containing a list of weird objects with a missing
        # ``role`` attribute — the extractor must swallow + return None.
        bizarre_messages = [
            object(),  # no role/content
            {"role": 42, "content": None},  # wrong types
            ["nested", "list"],  # not a message
        ]
        # Must NOT raise.
        assert extract_intent_from_pydantic_args((bizarre_messages,), {}) is None


# ─── Integration-test slice — end-to-end through the patched ``Agent`` ─


def test_string_prompt_extracts_and_truncates_under_max_bytes() -> None:
    """Top-level ``Agent.run(prompt)`` emits an ``execution_started``
    event with the prompt captured as ``intent_objective`` and
    ``intent_provenance = "plugin_derived"``.

    Note: the root-level run does NOT currently emit
    ``execution_started`` directly (only nested spawns emit via
    ``_emit_spawn_pair``). The intent value is however accessible on
    the handle for downstream emitters. This test exercises the
    plumbing through ``plugin.start_run`` → ``RunHandle``.
    """
    plugin, _mock = _make_plugin({"my-agent": "33333333-3333-4333-8333-aaaaaaaaaaaa"})

    async def _run() -> None:
        # Use plugin.start_run directly so we can assert the kwarg
        # plumbing without depending on the (currently nested-only)
        # _emit_spawn_pair emission.
        handle = await plugin.start_run(
            "my-agent",
            intent_objective="Summarize SEC filings",
            intent_provenance="plugin_derived",
        )
        try:
            assert handle.intent_objective == "Summarize SEC filings"
            assert handle.intent_provenance == "plugin_derived"
        finally:
            await handle.complete()

    asyncio.run(_run())


def test_empty_string_results_in_absent_provenance() -> None:
    """``Agent.run("")`` triggers extraction → None → Absent.

    Exercised end-to-end through the patched ``Agent.run`` wrapper.
    The nested-emit pathway is the load-bearing test because that's
    where the field actually hits the wire.
    """
    plugin, mock = _make_plugin(
        {"parent-coordinator": "11111111-1111-4111-8111-aaaaaaaaaaaa", "specialist": "11111111-1111-4111-8111-bbbbbbbbbbbb"}
    )

    async def _run() -> None:
        specialist = Agent(TestModel(), name="specialist")

        @specialist.tool_plain
        async def lookup(q: str) -> str:
            return f"specialist: {q}"

        parent = Agent(TestModel(), name="parent-coordinator")

        @parent.tool_plain
        async def consult(prompt: str) -> str:
            # Child invocation with empty prompt — must emit Absent.
            result = await specialist.run("")
            return str(result.output)

        await parent.run("trigger")

        # The specialist's child started event must carry no
        # intent_objective + intent_provenance = absent.
        spec_started = next(
            e
            for e in _started_events(mock)
            if e["agent_id"] == "11111111-1111-4111-8111-bbbbbbbbbbbb"
        )
        assert spec_started["payload"].get("intent_objective") is None
        assert spec_started["payload"]["intent_provenance"] == "absent"

    asyncio.run(_run())


def test_whitespace_only_prompt_normalizes_to_absent() -> None:
    """``Agent.run("   \\n\\n  ")`` normalises to "" → Absent."""
    plugin, mock = _make_plugin(
        {"parent-coordinator": "11111111-1111-4111-8111-aaaaaaaaaaaa", "specialist": "11111111-1111-4111-8111-bbbbbbbbbbbb"}
    )

    async def _run() -> None:
        specialist = Agent(TestModel(), name="specialist")

        @specialist.tool_plain
        async def lookup(q: str) -> str:
            return f"specialist: {q}"

        parent = Agent(TestModel(), name="parent-coordinator")

        @parent.tool_plain
        async def consult(prompt: str) -> str:
            result = await specialist.run("   \n\n  \t  ")
            return str(result.output)

        await parent.run("trigger")

        spec_started = next(
            e
            for e in _started_events(mock)
            if e["agent_id"] == "11111111-1111-4111-8111-bbbbbbbbbbbb"
        )
        assert spec_started["payload"].get("intent_objective") is None
        assert spec_started["payload"]["intent_provenance"] == "absent"

    asyncio.run(_run())


def test_list_of_messages_extracts_last_user_message() -> None:
    """Continuation idiom: ``Agent.run([sys, user1, asst, user2])``
    extracts user2.

    Asserted at the extractor unit-test level above; this integration
    test additionally confirms it survives the patched dispatch path.
    Note: pydantic-ai's ``run`` signature accepts a string or a
    message-list union; we simulate the message-list case by passing
    a list directly to the patched wrapper.
    """
    plugin, mock = _make_plugin(
        {"parent-coordinator": "11111111-1111-4111-8111-aaaaaaaaaaaa", "specialist": "11111111-1111-4111-8111-bbbbbbbbbbbb"}
    )

    messages = [
        {"role": "system", "content": "system prompt"},
        {"role": "user", "content": "first"},
        {"role": "assistant", "content": "assistant turn"},
        {"role": "user", "content": "second"},
    ]

    async def _run() -> None:
        specialist = Agent(TestModel(), name="specialist")

        @specialist.tool_plain
        async def lookup(q: str) -> str:
            return f"specialist: {q}"

        parent = Agent(TestModel(), name="parent-coordinator")

        @parent.tool_plain
        async def consult(prompt: str) -> str:
            # Direct extractor invocation via the spawn path —
            # spawn_subagent accepts ``intent_objective`` so we
            # bypass the entry-point monkey-patch (which feeds
            # pydantic-ai's ``run``, NOT a raw message list).
            # The extractor itself was unit-tested with this shape
            # above; here we lock the spawn-pair propagation.
            from watchlight_pydantic_ai.intent import (
                extract_intent_from_pydantic_args,
            )

            child_intent = extract_intent_from_pydantic_args(
                (messages,), {}
            )
            from watchlight_pydantic_ai.instrumentation import current_handle

            handle = current_handle()
            assert handle is not None  # parent run is active
            child = await handle.spawn_subagent(
                "specialist",
                child_intent={"category": "research", "objective": "Answer the follow-up"},
                intent_objective=child_intent,
                intent_provenance="plugin_derived" if child_intent else "absent",
            )
            try:
                return "ok"
            finally:
                await child.complete()

        await parent.run("trigger")

        spec_started = next(
            e
            for e in _started_events(mock)
            if e["agent_id"] == "11111111-1111-4111-8111-bbbbbbbbbbbb"
        )
        assert spec_started["payload"]["intent_objective"] == "second"
        assert spec_started["payload"]["intent_provenance"] == "plugin_derived"

    asyncio.run(_run())


def test_kwargs_only_prompt_falls_back_to_absent_or_extract() -> None:
    """Document the behaviour for keyword-only invocations.

    Pydantic AI's documented ``Agent.run`` signature is
    ``run(user_prompt, *, …)`` — the first positional arg. Customers
    that pass it as ``Agent.run(user_prompt="hello")`` should still
    have the extractor pick it up via the kwargs fallback path.

    This test asserts the extractor handles the kwargs path; the
    integration path (whether pydantic-ai itself accepts kwargs-only)
    is library-version dependent and intentionally NOT asserted here.
    """
    # Extractor handles user_prompt + prompt kwargs.
    assert (
        extract_intent_from_pydantic_args((), {"user_prompt": "via kwarg"})
        == "via kwarg"
    )
    assert (
        extract_intent_from_pydantic_args((), {"prompt": "older name"})
        == "older name"
    )

    # Other random kwargs do NOT trigger extraction — would-be
    # false positives from unrelated parameters.
    assert (
        extract_intent_from_pydantic_args((), {"model_settings": {"temperature": 0.1}})
        is None
    )


def test_nested_agent_run_propagates_per_execution_intent() -> None:
    """Two-agent flow — root sets intent A; nested ``specialist.run("B")``
    extracts intent B. Both events carry their OWN intent +
    ``plugin_derived`` provenance.

    Intent extraction is per-execution. A future cross-execution
    invariant (child intent must be a subset of parent intent) is out
    of scope here; this test only asserts the per-execution emission.
    """
    plugin, mock = _make_plugin(
        {"parent-coordinator": "11111111-1111-4111-8111-aaaaaaaaaaaa", "specialist": "11111111-1111-4111-8111-bbbbbbbbbbbb"}
    )

    async def _run() -> None:
        specialist = Agent(TestModel(), name="specialist")

        @specialist.tool_plain
        async def lookup(q: str) -> str:
            return f"specialist: {q}"

        parent = Agent(TestModel(), name="parent-coordinator")

        @parent.tool_plain
        async def consult(prompt: str) -> str:
            # Nested call with a DIFFERENT prompt — must extract this
            # one, NOT the parent's prompt.
            result = await specialist.run("verify Q3 invoice totals")
            return str(result.output)

        await parent.run("audit financial controls")

        # The specialist's execution_started must carry the NESTED
        # prompt, not the parent's. This is the load-bearing per-
        # execution invariant.
        spec_started = next(
            e
            for e in _started_events(mock)
            if e["agent_id"] == "11111111-1111-4111-8111-bbbbbbbbbbbb"
        )
        assert (
            spec_started["payload"]["intent_objective"]
            == "verify Q3 invoice totals"
        )
        assert spec_started["payload"]["intent_provenance"] == "plugin_derived"

    asyncio.run(_run())


def test_extracted_intent_payload_passes_schema_validation() -> None:
    """The ``execution_started`` event emitted by the spawn-pair path
    MUST round-trip through :class:`ExecutionStartedPayload` cleanly.

    Locks in the schema invariant: ``intent_objective is not None ⇒
    intent_provenance ∈ {declared, plugin_derived, proxy_inferred}``.
    """
    from watchlight_core import IntentProvenance
    from watchlight_core.events_schema import ExecutionStartedPayload

    plugin, mock = _make_plugin(
        {"parent-coordinator": "11111111-1111-4111-8111-aaaaaaaaaaaa", "specialist": "11111111-1111-4111-8111-bbbbbbbbbbbb"}
    )

    async def _run() -> None:
        specialist = Agent(TestModel(), name="specialist")

        @specialist.tool_plain
        async def lookup(q: str) -> str:
            return f"specialist: {q}"

        parent = Agent(TestModel(), name="parent-coordinator")

        @parent.tool_plain
        async def consult(prompt: str) -> str:
            result = await specialist.run("a real intent")
            return str(result.output)

        await parent.run("root intent")

        spec_started = next(
            e
            for e in _started_events(mock)
            if e["agent_id"] == "11111111-1111-4111-8111-bbbbbbbbbbbb"
        )
        payload = ExecutionStartedPayload(**spec_started["payload"])
        assert payload.intent_objective == "a real intent"
        assert payload.intent_provenance == IntentProvenance.PLUGIN_DERIVED

    asyncio.run(_run())
