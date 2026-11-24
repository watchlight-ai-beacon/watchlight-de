"""Bedrock intent_objective extraction tests.

Covers the two surfaces intent extraction wires up:

1. The :func:`watchlight_bedrock_action` Lambda decorator: when the
   decorator falls back to bootstrapping a fresh APDP session (i.e.
   the orchestrator didn't propagate session attributes), it parses
   ``event["inputText"]`` and threads the value into
   :meth:`WatchlightBedrockPlugin.start_run` as the
   ``intent_objective`` kwarg. The plugin emits an
   ``execution_started`` canonical event with the byte-truncated
   objective and :attr:`IntentProvenance.PLUGIN_DERIVED`.

2. The manual handle path:
   :meth:`WatchlightBedrockPlugin.start_run` accepts an explicit
   ``intent_objective`` kwarg (and an optional
   :class:`IntentProvenance`) so customers driving Bedrock from
   their own orchestrator can declare or pass through intent.

The byte-truncation invariant (≤256 UTF-8 bytes, codepoint-safe)
is the load-bearing schema guarantee — the Pydantic validator on
:class:`watchlight_core.events_schema.ExecutionStartedPayload`
rejects oversized objectives, so the plugin MUST truncate before
the publish hits the wire.
"""

from unittest.mock import AsyncMock, patch

import pytest

from watchlight_bedrock import WatchlightBedrockPlugin, watchlight_bedrock_action
from watchlight_bedrock.plugin import (
    _normalize_intent_objective,
    _resolve_intent_provenance,
)
from watchlight_core import INTENT_OBJECTIVE_MAX_BYTES, IntentProvenance

from .conftest import as_session


# ─── Fixtures ─────────────────────────────────────────────────────────


@pytest.fixture
def plugin() -> WatchlightBedrockPlugin:
    """Plugin with every APDP method mocked. ``publish_events`` is
    mocked too — the plugin adds an emission on ``start_run`` when
    intent context is present, so the tests assert on the call shape
    rather than letting it round-trip to a live APDP."""
    p = WatchlightBedrockPlugin(apdp_url="https://apdp.test", tenant_id="acme")
    p.apdp.resolve_agent = AsyncMock(
        return_value={"id": "agent-uuid-001", "slug": "research-analyst"}
    )
    p.apdp.create_session = AsyncMock(return_value=as_session(p.apdp, {"session": {"id": "ses_m46"}}))
    p.apdp.get_manifest = AsyncMock(return_value={"tool_allowlist": ["read"]})
    p.apdp.complete_session = AsyncMock(return_value=True)
    p.apdp.terminate_session = AsyncMock(return_value=True)
    p.apdp.publish_events = AsyncMock(return_value=True)
    p.apdp.authorize = AsyncMock(return_value={"decision": "Allow"})
    return p


def _bedrock_event(input_text: str | None = "search for X") -> dict:
    """Canonical Bedrock REST-style event used to drive the Lambda
    decorator path. ``session_attributes`` is intentionally empty so
    the decorator takes the fallback bootstrap branch — that is the
    code path that threads ``inputText`` through."""
    event: dict = {
        "messageVersion": "1.0",
        "agent": {
            "id": "AG12345",
            "name": "research-analyst",
            "alias": "PROD",
            "version": "1",
        },
        "actionGroup": "research_tools",
        "apiPath": "/search",
        "httpMethod": "POST",
        "parameters": [{"name": "q", "type": "string", "value": "watchlight"}],
        "sessionId": "bedrock-session-123",
        "sessionState": {"sessionAttributes": {}},  # forces fallback bootstrap
    }
    if input_text is not None:
        event["inputText"] = input_text
    return event


# ─── _normalize_intent_objective unit tests ───────────────────────────


class TestNormalizeIntentObjective:
    """Unit-test the helper that underpins both the Lambda + manual
    path emissions. The helper is the load-bearing primitive — every
    one of the public surfaces calls it before the publish."""

    def test_none_returns_none(self) -> None:
        assert _normalize_intent_objective(None) is None

    def test_empty_string_returns_none(self) -> None:
        assert _normalize_intent_objective("") is None

    def test_whitespace_only_returns_none(self) -> None:
        """A whitespace-only Bedrock ``inputText`` is operator-equivalent
        to a missing field; the plugin treats it as Absent rather than
        propagating an empty objective."""
        assert _normalize_intent_objective("   \n\t  ") is None

    def test_short_string_passes_through_stripped(self) -> None:
        assert _normalize_intent_objective("  audit Q3 invoices  ") == "audit Q3 invoices"

    def test_string_at_byte_cap_is_unchanged(self) -> None:
        text = "x" * INTENT_OBJECTIVE_MAX_BYTES
        assert _normalize_intent_objective(text) == text

    def test_long_ascii_truncates_at_byte_cap(self) -> None:
        """ASCII case: 1 byte per char, so the truncation lands at the
        cap exactly."""
        text = "x" * (INTENT_OBJECTIVE_MAX_BYTES + 100)
        out = _normalize_intent_objective(text)
        assert out is not None
        assert len(out.encode("utf-8")) == INTENT_OBJECTIVE_MAX_BYTES
        assert out == "x" * INTENT_OBJECTIVE_MAX_BYTES

    def test_byte_truncation_handles_unicode_boundary(self) -> None:
        """Multi-byte UTF-8 case: ``✓`` is 3 bytes per char. The
        truncation MUST NOT split a codepoint — the result decodes
        cleanly under strict UTF-8."""
        # 100 characters of ``✓`` = 300 bytes. Truncated at 256 must
        # land on a codepoint boundary: 256 // 3 = 85 complete chars,
        # which is 255 bytes (leftover byte gets dropped because it
        # would be a continuation).
        text = "✓" * 100
        out = _normalize_intent_objective(text)
        assert out is not None
        encoded = out.encode("utf-8")
        assert len(encoded) <= INTENT_OBJECTIVE_MAX_BYTES
        # The final byte MUST be a complete codepoint — strict UTF-8
        # decode must succeed.
        out.encode("utf-8").decode("utf-8")  # would raise on bad cut
        assert out == "✓" * 85

    def test_byte_truncation_at_256_bytes_for_long_input(self) -> None:
        """The defensive cap: arbitrary long Bedrock ``inputText`` is
        bounded to 256 bytes before the publish constructs the
        canonical event. This is what defends against an upstream
        Lambda that surfaces a multi-KB prompt — the wire payload
        stays bounded, and the Pydantic validator on
        :class:`ExecutionStartedPayload` will accept the result."""
        # Realistic Bedrock prompt (could be a 4KB system+user blob in
        # production); the helper produces a 256-byte string regardless.
        text = "audit Q3 invoices and flag anomalies " * 200  # ~7000 bytes
        out = _normalize_intent_objective(text)
        assert out is not None
        assert len(out.encode("utf-8")) <= INTENT_OBJECTIVE_MAX_BYTES
        # The prefix of the original is preserved (truncation, not
        # alteration — the operator can read the first ~250 chars).
        assert text.startswith(out)


# ─── _resolve_intent_provenance unit tests ────────────────────────────


class TestResolveIntentProvenance:
    """Provenance-inference helper. Drives both the Lambda decorator's
    PluginDerived stamp and the manual-path DECLARED override."""

    def test_objective_with_no_explicit_provenance_is_plugin_derived(self) -> None:
        assert (
            _resolve_intent_provenance("audit Q3", None)
            == IntentProvenance.PLUGIN_DERIVED
        )

    def test_no_objective_no_explicit_is_absent(self) -> None:
        assert _resolve_intent_provenance(None, None) == IntentProvenance.ABSENT

    def test_explicit_declared_wins_over_inference(self) -> None:
        """Customer-declared intent on the orchestrator side stays
        DECLARED — the helper never down-grades it to PluginDerived."""
        assert (
            _resolve_intent_provenance("audit Q3", IntentProvenance.DECLARED)
            == IntentProvenance.DECLARED
        )

    def test_explicit_absent_is_respected(self) -> None:
        """If the caller explicitly stamps ABSENT, we don't override."""
        assert (
            _resolve_intent_provenance(None, IntentProvenance.ABSENT)
            == IntentProvenance.ABSENT
        )


# ─── start_run manual-path tests ──────────────────────────────────────


class TestManualHandlePath:
    """Customers driving Bedrock from their own orchestrator pass
    ``intent_objective`` to :meth:`start_run` directly. The plugin
    emits an ``execution_started`` event carrying the intent fields."""

    @pytest.mark.asyncio
    async def test_manual_handle_creation_accepts_intent_objective_kwarg(
        self, plugin: WatchlightBedrockPlugin
    ) -> None:
        """The kwarg exists, the call succeeds, and the publish
        carries the objective + the PluginDerived default provenance."""
        handle = await plugin.start_run(
            agent_slug="research-analyst",
            intent_objective="summarise Q3 audit findings",
        )
        assert handle.session_id == "ses_m46"

        plugin.apdp.publish_events.assert_awaited_once()
        events = plugin.apdp.publish_events.await_args.args[1]
        assert len(events) == 1
        event = events[0]
        assert event["event_type"] == "execution_started"
        assert event["session_id"] == "ses_m46"
        assert event["agent_id"] == "agent-uuid-001"
        assert event["tenant_id"] == "acme"
        assert event["payload"]["intent_objective"] == "summarise Q3 audit findings"
        # No explicit provenance on this call → default PluginDerived.
        assert event["payload"]["intent_provenance"] == "plugin_derived"

    @pytest.mark.asyncio
    async def test_manual_path_with_explicit_declared_provenance(
        self, plugin: WatchlightBedrockPlugin
    ) -> None:
        """Customer-declared intent: the orchestrator passed both the
        objective AND the DECLARED enum. The wire event records
        ``declared`` — Cedar's greenfield-Custodial template fires
        on this provenance only."""
        await plugin.start_run(
            agent_slug="research-analyst",
            intent_objective="audit Q3 invoices",
            intent_provenance=IntentProvenance.DECLARED,
        )

        events = plugin.apdp.publish_events.await_args.args[1]
        assert events[0]["payload"]["intent_provenance"] == "declared"
        assert events[0]["payload"]["intent_objective"] == "audit Q3 invoices"

    @pytest.mark.asyncio
    async def test_manual_path_truncates_oversize_objective(
        self, plugin: WatchlightBedrockPlugin
    ) -> None:
        """A multi-KB customer-supplied objective is truncated before
        the publish — defends against the Pydantic byte-cap validator
        on :class:`ExecutionStartedPayload`."""
        await plugin.start_run(
            agent_slug="research-analyst",
            intent_objective="a" * (INTENT_OBJECTIVE_MAX_BYTES + 500),
        )
        events = plugin.apdp.publish_events.await_args.args[1]
        assert (
            len(events[0]["payload"]["intent_objective"].encode("utf-8"))
            <= INTENT_OBJECTIVE_MAX_BYTES
        )

    @pytest.mark.asyncio
    async def test_manual_path_no_intent_emits_no_execution_started(
        self, plugin: WatchlightBedrockPlugin
    ) -> None:
        """Customers that never declared intent see the previous wire
        posture: no ``execution_started`` event on ``start_run``. The
        audit log stays free of empty-intent emissions when the
        customer opted out."""
        await plugin.start_run(agent_slug="research-analyst")
        plugin.apdp.publish_events.assert_not_awaited()


# ─── Lambda decorator path tests ──────────────────────────────────────


def _published_types(plugin) -> list:
    return [
        e["event_type"]
        for call in plugin.apdp.publish_events.await_args_list
        for e in call.args[1]
    ]


class TestLambdaDecoratorPath:
    """The Lambda decorator's fallback bootstrap path: when the
    orchestrator didn't propagate session attributes and the
    decorator was configured with a ``fallback_agent_slug``, the
    decorator pulls ``event["inputText"]`` and forwards it as the
    ``intent_objective``. Customer Lambda code touches NOTHING."""

    def test_lambda_decorator_extracts_input_text_to_intent(
        self, plugin: WatchlightBedrockPlugin
    ) -> None:
        """End-to-end: a Bedrock event with ``inputText="search for X"``
        and no session attributes produces a ``start_run`` call
        carrying that exact string, which emits an
        ``execution_started`` event with provenance=plugin_derived.

        Sync test because Lambda handlers are sync — the
        :func:`watchlight_bedrock_action` decorator uses
        :func:`asyncio.run` internally to drive the async APDP calls,
        which would crash from inside a running event loop."""

        # Patch the cached-plugin factory so the decorator uses our
        # mocked plugin instance instead of constructing a real one.
        with patch(
            "watchlight_bedrock.plugin._get_cached_plugin",
            return_value=plugin,
        ):

            @watchlight_bedrock_action(
                apdp_url="https://apdp.test",
                fallback_agent_slug="research-analyst",
                fallback_allowed_actions=["research_tools/search"],
            )
            def handler(event: dict, context):
                return {"messageVersion": "1.0", "response": {"ok": True}}

            event = _bedrock_event(input_text="process the day's loan applications")
            result = handler(event, None)

        # The wrapped handler ran (decision was Allow via the fixture).
        assert result["response"]["ok"] is True

        # start_run was called with the extracted inputText threaded
        # through as intent_objective.
        plugin.apdp.create_session.assert_awaited_once()

        # The execution_started event carried the objective + the
        # PluginDerived provenance.
        # The fallback root is closed after the invocation, so the
        # first publish is execution_started and the last is
        # execution_completed.
        events = plugin.apdp.publish_events.await_args_list[0].args[1]
        assert events[0]["event_type"] == "execution_started"
        plugin.apdp.complete_session.assert_awaited_once()
        assert events[0]["payload"]["intent_objective"] == (
            "process the day's loan applications"
        )
        assert events[0]["payload"]["intent_provenance"] == "plugin_derived"

    def test_empty_input_text_results_in_absent_provenance(
        self, plugin: WatchlightBedrockPlugin
    ) -> None:
        """``inputText = ""`` is operator-equivalent to a missing
        field. The decorator does NOT emit an ``execution_started``
        event — provenance is Absent, no objective, the no-intent wire
        posture is preserved."""

        with patch(
            "watchlight_bedrock.plugin._get_cached_plugin",
            return_value=plugin,
        ):

            @watchlight_bedrock_action(
                apdp_url="https://apdp.test",
                fallback_agent_slug="research-analyst",
                fallback_allowed_actions=["research_tools/search"],
            )
            def handler(event: dict, context):
                return {"messageVersion": "1.0", "response": {"ok": True}}

            event = _bedrock_event(input_text="")
            handler(event, None)

        plugin.apdp.create_session.assert_awaited_once()
        assert _published_types(plugin) == ["execution_completed"]

    def test_missing_input_text_field_results_in_absent(
        self, plugin: WatchlightBedrockPlugin
    ) -> None:
        """``event["inputText"]`` is structurally missing from the
        Bedrock payload (e.g. older Bedrock SDK, function-style
        action group where the field isn't always populated). Same
        treatment as the empty-string case: Absent, no emission."""

        with patch(
            "watchlight_bedrock.plugin._get_cached_plugin",
            return_value=plugin,
        ):

            @watchlight_bedrock_action(
                apdp_url="https://apdp.test",
                fallback_agent_slug="research-analyst",
                fallback_allowed_actions=["research_tools/search"],
            )
            def handler(event: dict, context):
                return {"messageVersion": "1.0", "response": {"ok": True}}

            event = _bedrock_event(input_text=None)
            assert "inputText" not in event
            handler(event, None)

        plugin.apdp.create_session.assert_awaited_once()
        assert _published_types(plugin) == ["execution_completed"]

    def test_decorator_publish_failure_does_not_break_session(
        self, plugin: WatchlightBedrockPlugin
    ) -> None:
        """Best-effort emission: if APDP rejects the
        ``execution_started`` publish, the Lambda invocation must
        still succeed. Observability MUST NOT break the control plane."""

        plugin.apdp.publish_events.side_effect = RuntimeError("apdp down")

        with patch(
            "watchlight_bedrock.plugin._get_cached_plugin",
            return_value=plugin,
        ):

            @watchlight_bedrock_action(
                apdp_url="https://apdp.test",
                fallback_agent_slug="research-analyst",
                fallback_allowed_actions=["research_tools/search"],
            )
            def handler(event: dict, context):
                return {"messageVersion": "1.0", "response": {"ok": True}}

            event = _bedrock_event(input_text="audit something")
            result = handler(event, None)

        assert result["response"]["ok"] is True
        assert _published_types(plugin)[0] == "execution_started"
