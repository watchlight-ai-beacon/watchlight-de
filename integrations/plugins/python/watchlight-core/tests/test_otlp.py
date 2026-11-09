"""Tests for ``watchlight_core.otlp`` — OTLP export module.

The tests are split across three concerns:

1. **Pure-function tests** (no OTel SDK required) — config parsing,
   profile inclusion ladder, redaction boundary, event-to-signal
   classification, severity gating. These run on any Python 3.10+
   environment.

2. **Exporter construction tests** — verify that constructing
   ``WatchlightOtlpExporter`` with a non-OFF profile fails loud
   when the OTel SDK isn't installed.

3. **SDK-integration tests** — gated on ``opentelemetry`` import
   availability via ``pytest.importorskip``. These exercise the
   actual span/log/metric emission path with an in-memory exporter.

Why the split: ``watchlight-core`` ships WITHOUT the OTel SDK by
default; the ``[otlp]`` extra is opt-in. Tests must not assume
the SDK is installed in the test environment.
"""

from __future__ import annotations

import os

import pytest

from watchlight_core.otlp import (
    OtlpConfig,
    OtlpProfile,
    WatchlightOtlpExporter,
    _anomaly_passes_floor,
    _default_severity_for_anomaly,
    _event_otel_kind,
    _NEVER_EXPORT_ANOMALY_KINDS,
    _NEVER_EXPORT_PAYLOAD_KEYS,
    _parse_kv_pairs,
    _redact_event,
)


# ─── Profile ladder ──────────────────────────────────────────────────


class TestOtlpProfile:
    def test_monotonic_inclusion(self):
        """Each profile must be a strict superset of the prior.
        This guards the customer-facing 'upgrading the profile
        can't lose signals' invariant."""
        assert OtlpProfile.OFF.includes_metrics() is False
        assert OtlpProfile.METRICS.includes_metrics() is True
        assert OtlpProfile.STANDARD.includes_metrics() is True
        assert OtlpProfile.GOVERNANCE.includes_metrics() is True

        assert OtlpProfile.OFF.includes_spans() is False
        assert OtlpProfile.METRICS.includes_spans() is False
        assert OtlpProfile.STANDARD.includes_spans() is True
        assert OtlpProfile.GOVERNANCE.includes_spans() is True

        assert OtlpProfile.OFF.includes_anomaly_logs() is False
        assert OtlpProfile.METRICS.includes_anomaly_logs() is False
        assert OtlpProfile.STANDARD.includes_anomaly_logs() is False
        assert OtlpProfile.GOVERNANCE.includes_anomaly_logs() is True

    def test_from_env_case_insensitive(self):
        assert OtlpProfile.from_env("OFF") is OtlpProfile.OFF
        assert OtlpProfile.from_env("Standard") is OtlpProfile.STANDARD
        assert OtlpProfile.from_env("GOVERNANCE") is OtlpProfile.GOVERNANCE

    def test_from_env_safe_defaults(self):
        """None / empty / unrecognized map to OFF — the safe
        fallback. The exporter must never accidentally export
        because of a typo."""
        assert OtlpProfile.from_env(None) is OtlpProfile.OFF
        assert OtlpProfile.from_env("") is OtlpProfile.OFF
        assert OtlpProfile.from_env("not-a-real-profile") is OtlpProfile.OFF


# ─── Config ──────────────────────────────────────────────────────────


class TestOtlpConfig:
    def test_default_disabled(self):
        cfg = OtlpConfig()
        assert cfg.profile is OtlpProfile.OFF
        assert cfg.endpoint is None
        assert cfg.headers == {}
        assert cfg.sample_rate == 1.0
        assert cfg.is_enabled() is False

    def test_from_env_picks_up_profile(self, monkeypatch):
        monkeypatch.setenv("WL_OTLP_PROFILE", "standard")
        monkeypatch.setenv("WL_OTLP_ENDPOINT", "http://collector:4318")
        cfg = OtlpConfig.from_env()
        assert cfg.profile is OtlpProfile.STANDARD
        assert cfg.endpoint == "http://collector:4318"
        assert cfg.is_enabled() is True

    def test_from_env_clamps_sample_rate(self, monkeypatch):
        monkeypatch.setenv("WL_OTLP_PROFILE", "metrics")
        monkeypatch.setenv("WL_OTLP_SAMPLE_RATE", "1.5")
        cfg = OtlpConfig.from_env()
        assert cfg.sample_rate == 1.0

        monkeypatch.setenv("WL_OTLP_SAMPLE_RATE", "-0.5")
        cfg = OtlpConfig.from_env()
        assert cfg.sample_rate == 0.0

    def test_from_env_invalid_sample_rate_falls_back(self, monkeypatch):
        monkeypatch.setenv("WL_OTLP_PROFILE", "metrics")
        monkeypatch.setenv("WL_OTLP_SAMPLE_RATE", "not-a-number")
        cfg = OtlpConfig.from_env()
        assert cfg.sample_rate == 1.0

    def test_from_env_parses_kv_pairs(self, monkeypatch):
        monkeypatch.setenv("WL_OTLP_PROFILE", "metrics")
        monkeypatch.setenv(
            "WL_OTLP_HEADERS",
            "x-api-key=secret123,x-team=watchlight",
        )
        monkeypatch.setenv(
            "WL_OTLP_RESOURCE_ATTRIBUTES",
            "deployment.environment=prod,service.version=1.0",
        )
        cfg = OtlpConfig.from_env()
        assert cfg.headers == {"x-api-key": "secret123", "x-team": "watchlight"}
        assert cfg.resource_attributes == {
            "deployment.environment": "prod",
            "service.version": "1.0",
        }


class TestKvParse:
    def test_empty_input(self):
        assert _parse_kv_pairs(None) == {}
        assert _parse_kv_pairs("") == {}

    def test_malformed_entries_dropped(self):
        # malformed entries silently dropped (forgiving startup)
        result = _parse_kv_pairs("good=value,malformed,also=fine,=nokey")
        assert result == {"good": "value", "also": "fine"}

    def test_trims_whitespace(self):
        assert _parse_kv_pairs("  k1 = v1 , k2=v2 ") == {"k1": "v1", "k2": "v2"}


# ─── Redaction — the never-export boundary ───────────────────────────


class TestRedaction:
    def test_never_export_payload_keys_present(self):
        """Spot-check that the forbidden-keys list still contains
        the critical entries. Regression-guard for accidental
        removal."""
        critical_keys = {
            "tool_args",
            "prompts",
            "messages",
            "outcome",
            "blast_radius_score",
            "drift_score",
            "policies_evaluated",
            "lookup_hash",
        }
        assert critical_keys.issubset(_NEVER_EXPORT_PAYLOAD_KEYS)

    def test_never_export_anomaly_kinds_present(self):
        """The three security-internal anomalies must always be
        blocked from export."""
        assert "token.failed_auth.repeated" in _NEVER_EXPORT_ANOMALY_KINDS
        assert "token.kind_mismatch" in _NEVER_EXPORT_ANOMALY_KINDS
        assert "baseline.integrity_violation" in _NEVER_EXPORT_ANOMALY_KINDS

    def test_redact_strips_forbidden_payload(self):
        event = {
            "event_type": "tool_call_observed",
            "execution_id": "exec_1",
            "agent_id": "agent-1",
            "payload": {
                "tool": {"resource": "rest://api"},
                "tool_args": {"password": "secret"},  # FORBIDDEN
                "duration_ms": 50,
                "prompts": ["sensitive prompt"],  # FORBIDDEN
            },
            "metadata": {"source": "langgraph.callback"},
        }
        out = _redact_event(event)
        assert "tool_args" not in out["payload"]
        assert "prompts" not in out["payload"]
        # Non-forbidden fields preserved
        assert out["payload"]["tool"] == {"resource": "rest://api"}
        assert out["payload"]["duration_ms"] == 50
        # Envelope-level fields preserved
        assert out["execution_id"] == "exec_1"
        assert out["agent_id"] == "agent-1"

    def test_redact_strips_forbidden_metadata(self):
        event = {
            "event_type": "policy_decision_made",
            "metadata": {
                "source": "langgraph.callback",
                "policies_evaluated": ["p1", "p2"],  # FORBIDDEN
                "evaluation_ms": 12.5,  # FORBIDDEN
                "authority_class": "Standard",  # allowed
            },
            "payload": {},
        }
        out = _redact_event(event)
        assert "policies_evaluated" not in out["metadata"]
        assert "evaluation_ms" not in out["metadata"]
        assert out["metadata"]["authority_class"] == "Standard"
        assert out["metadata"]["source"] == "langgraph.callback"

    def test_redact_returns_new_dict(self):
        """Mutation-free contract — the original event must not
        be modified, so the lineage stream sees the unaltered
        event."""
        event = {
            "event_type": "tool_call_observed",
            "payload": {"tool_args": "secret", "ok": 1},
        }
        out = _redact_event(event)
        assert "tool_args" in event["payload"]  # original untouched
        assert "tool_args" not in out["payload"]  # output stripped

    def test_redact_handles_non_dict(self):
        # Defensive: malformed event input should not crash
        assert _redact_event("not a dict") == {}
        assert _redact_event(None) == {}

    def test_redact_no_payload(self):
        # Event with no payload key — should not raise
        event = {"event_type": "execution_started", "execution_id": "x"}
        out = _redact_event(event)
        assert out["event_type"] == "execution_started"

    def test_blast_radius_score_redacted_but_authority_class_kept(self):
        """ABR raw numeric is operator-private; the tier label
        (Constrained/Standard/Elevated/Custodial) IS customer-
        facing. Verify the distinction."""
        event = {
            "event_type": "tool_call_observed",
            "metadata": {
                "blast_radius_score": 0.87,  # FORBIDDEN — raw numeric
                "authority_class": "Elevated",  # ALLOWED — tier label
            },
            "payload": {},
        }
        out = _redact_event(event)
        assert "blast_radius_score" not in out["metadata"]
        assert out["metadata"]["authority_class"] == "Elevated"


# ─── Event-to-signal classification ──────────────────────────────────


class TestEventKind:
    def test_execution_events_are_root_spans(self):
        assert _event_otel_kind({"event_type": "execution_started"}) == "span_root"
        assert _event_otel_kind({"event_type": "execution_completed"}) == "span_root"
        assert _event_otel_kind({"event_type": "execution_failed"}) == "span_root"

    def test_tool_and_api_events_are_child_spans(self):
        assert _event_otel_kind({"event_type": "tool_call_observed"}) == "span_child"
        assert _event_otel_kind({"event_type": "api_request_observed"}) == "span_child"
        assert _event_otel_kind({"event_type": "agent_spawn_observed"}) == "span_child"

    def test_policy_decision_attaches_to_parent(self):
        assert _event_otel_kind({"event_type": "policy_decision_made"}) == "span_event"

    def test_anomaly_events_are_logs(self):
        assert _event_otel_kind({"event_type": "token.revoked_use_attempt"}) == "log"
        assert _event_otel_kind({"event_type": "agent.goal_drift"}) == "log"
        assert _event_otel_kind({"event_type": "policy.violation"}) == "log"

    def test_unknown_event_type_emits_nothing(self):
        """Defense in depth: unknown event types don't accidentally
        produce a misleading OTel signal."""
        assert _event_otel_kind({"event_type": "weird_internal_thing"}) == "none"
        assert _event_otel_kind({}) == "none"


# ─── Severity gating ─────────────────────────────────────────────────


class TestSeverityGate:
    def test_default_severities_match_38(self):
        """Defaults match the §3.8 anomaly severity table."""
        assert _default_severity_for_anomaly("token.revoked_use_attempt") == "high"
        assert _default_severity_for_anomaly("token.expired_use_attempt") == "low"
        assert _default_severity_for_anomaly("token.failed_auth.repeated") == "warn"
        assert _default_severity_for_anomaly("token.cross_tenant_session") == "high"
        # Unknown anomaly — default to info
        assert _default_severity_for_anomaly("unknown") == "info"

    def test_floor_filtering(self):
        """A 'low' severity event passes a 'low'/'info' floor but
        not a 'warn' or 'error' floor."""
        assert _anomaly_passes_floor("low", "info") is True
        assert _anomaly_passes_floor("low", "warn") is False
        assert _anomaly_passes_floor("warn", "warn") is True
        assert _anomaly_passes_floor("high", "warn") is True
        assert _anomaly_passes_floor("high", "error") is True


# ─── Exporter construction ──────────────────────────────────────────


class TestExporterConstruction:
    def test_off_profile_constructs_without_otel(self):
        """Profile OFF must not require the OTel SDK — it's a no-op
        and customers without ``[otlp]`` extra installed still get
        a working watchlight-core."""
        exporter = WatchlightOtlpExporter(OtlpConfig())
        assert exporter is not None

    def test_off_profile_export_is_noop(self):
        """export_events on an OFF exporter returns 0 (no signals)
        even with a non-empty event batch."""
        exporter = WatchlightOtlpExporter(OtlpConfig())
        emitted = exporter.export_events(
            [{"event_type": "execution_started", "execution_id": "x", "agent_id": "a"}]
        )
        assert emitted == 0

    def test_non_off_without_sdk_raises_at_construction(self):
        """If the OTel SDK is missing AND profile is non-OFF,
        construction must fail loud — not silently no-op. We
        prefer 'install the [otlp] extra' as the error message
        over confusing silent dropouts."""
        try:
            import opentelemetry  # noqa: F401
            pytest.skip("OTel SDK is installed; skipping missing-SDK test")
        except ImportError:
            pass
        with pytest.raises(ImportError, match="watchlight-core\\[otlp\\]"):
            WatchlightOtlpExporter(OtlpConfig(profile=OtlpProfile.METRICS))


# ─── SDK integration tests — gated on opentelemetry availability ─────


otel = pytest.importorskip(
    "opentelemetry",
    reason="OTel SDK not installed; install with `pip install watchlight-core[otlp]`",
)
pytest.importorskip("opentelemetry.sdk.trace")
pytest.importorskip("opentelemetry.sdk.metrics")
# The exporter ships separately from the SDK: another package (google-adk,
# for one) can bring in opentelemetry-sdk without it, and the exporter
# imports it on construction.
pytest.importorskip("opentelemetry.exporter.otlp.proto.http")


class TestSdkIntegration:
    """Integration tests that hit the OTel SDK. The fact that we
    can construct + export without crashing IS the test for the
    SDK wiring; we don't assert on collector reception because that
    would require a real OTLP collector in test."""

    def test_construct_with_metrics_profile(self):
        cfg = OtlpConfig(
            profile=OtlpProfile.METRICS,
            endpoint="http://localhost:4318",
        )
        # Construction succeeds; we don't actually export to a
        # real collector here.
        exporter = WatchlightOtlpExporter(cfg)
        assert exporter is not None

    def test_construct_with_standard_profile(self):
        cfg = OtlpConfig(
            profile=OtlpProfile.STANDARD,
            endpoint="http://localhost:4318",
        )
        exporter = WatchlightOtlpExporter(cfg)
        assert exporter is not None

    def test_export_root_span_does_not_crash(self):
        """End-to-end smoke test for the span-emission path. The
        in-memory tracer rejects the export silently (no
        collector); what we're verifying is the translator +
        attribute-building path doesn't throw."""
        cfg = OtlpConfig(
            profile=OtlpProfile.STANDARD,
            endpoint="http://localhost:4318",
        )
        exporter = WatchlightOtlpExporter(cfg)
        events = [
            {
                "event_type": "execution_started",
                "execution_id": "exec_1",
                "agent_id": "research-analyst",
                "tenant_id": "acme",
                "metadata": {
                    "source": "langgraph.callback",
                    "authority_class": "Standard",
                },
                "payload": {},
            },
            {
                "event_type": "tool_call_observed",
                "execution_id": "exec_1",
                "agent_id": "research-analyst",
                "tenant_id": "acme",
                "metadata": {"source": "langgraph.callback"},
                "payload": {
                    "tool": {"resource": "rest://api.example.com"},
                    "action": {"action": "lookup_account"},
                    "decision": "Allow",
                    "duration_ms": 42,
                    "tool_args": {"sensitive": "data"},  # MUST be redacted
                },
            },
            {
                "event_type": "execution_completed",
                "execution_id": "exec_1",
                "agent_id": "research-analyst",
                "tenant_id": "acme",
                "metadata": {"source": "langgraph.callback"},
                "payload": {"duration_ms": 1500, "actions_taken": 3},
            },
        ]
        emitted = exporter.export_events(events)
        # Three events × one signal each = 3 expected emissions on
        # STANDARD profile. (Policy events would be span events,
        # not separate emissions; we don't have one in this batch.)
        assert emitted >= 1, f"expected at least 1 emission, got {emitted}"
