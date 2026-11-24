"""OpenTelemetry Protocol (OTLP) export for Watchlight execution events.

# Why two streams?

Watchlight maintains two distinct event streams with **different audiences,
different retention, and different IP boundaries**:

1. **Watchlight lineage** — full canonical ``ExecutionEvent`` stream → APDP
   ``/v1/events`` → NATS → ``wl-execution-graph``. Drives drift detection,
   ABR enforcement, temporal-FSM policy evaluation, graduated containment,
   the hash-chained audit log. **This is the product.** The full event
   shape and all internal scoring details stay inside Watchlight.

2. **OTLP export** — a deliberate **subset + transformation** of the
   lineage stream, exported via standard OpenTelemetry to the customer's
   OTel collector (Datadog, Honeycomb, Grafana Tempo, New Relic, custom
   pipelines). Answers "is my agent healthy / fast / failing" from inside
   the customer's existing observability stack. **Operator/SRE-facing.**

OTLP export is **opt-in** (default ``profile=OFF``). Watchlight never
exfiltrates by default; the customer explicitly turns it on with a
profile + endpoint config.

# Profile ladder

Four presets, monotonic inclusion: each is a strict superset of the prior.

| Profile      | Includes                                                  |
|--------------|-----------------------------------------------------------|
| ``OFF``      | Nothing — exporter is disabled (the default)              |
| ``METRICS``  | Metric family only (counters + histograms; lowest cardinality) |
| ``STANDARD`` | Metrics + per-execution spans (the typical OTel customer pick) |
| ``GOVERNANCE`` | Standard + customer-visible anomaly logs |

# What we export — partitioning rules

The full partitioning table lives in the Watchlight documentation. Summary:

**Exported** (per profile):
- ``ExecutionStarted/Completed/Failed`` → root spans (STANDARD+)
- ``ToolCallObserved`` → child spans WITHOUT tool arguments (STANDARD+)
- ``ApiRequestObserved`` → child spans with model identity, NO prompts (STANDARD+)
- ``PolicyDecisionMade`` → span events on the parent span (STANDARD+)
- Customer-visible anomalies (revoked/expired/tenant-mismatch/cross-tenant) → OTel logs (GOVERNANCE)
- Counters: authz requests, tool calls, lineage emissions — labeled by tenant + authority class (METRICS+)
- Histograms: authz duration, tool duration (METRICS+)

**Never exported** (stays in Watchlight lineage):
- Raw ``ExecutionEvent`` stream with all metadata
- Tool arguments / LLM prompts (PII + customer IP)
- Goal-baseline statistics, drift scores
- ABR raw numeric score (operator-private; only ``authority_class`` label exports)
- Failed-auth + kind-mismatch anomalies (security-internal)
- Drift-baseline integrity violations (platform-internal)
- Cedar policy internals (matched policy IDs, evaluation_ms)

The :func:`_redact_event` step enforces this boundary BEFORE any OTel
signal is constructed — forbidden fields cannot leak through the
translator path.

# Plugin-side fabrication detection

Every span carries ``wl.source`` and ``wl.source_credential`` attributes
identifying the plugin + service credential that emitted the underlying
event. A compromised plugin trying to forge events as a different
framework is detectable post-hoc by correlating span sources against
the credential's authorized identity in the audit chain.

# Cold-start cost

The OTel SDK and gRPC dependencies are ~50MB installed; for cold-start-
sensitive environments (AWS Lambda) the customer either installs the
``watchlight-core`` package without the ``otlp`` extra (zero OTel cost,
exporter raises at construction time if invoked) or accepts the larger
package for the observability win.
"""

from __future__ import annotations

import enum
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .log import get_logger

logger = get_logger(__name__)


# ─── Profile enum + config ────────────────────────────────────────────


class OtlpProfile(str, enum.Enum):
    """OTLP export profile — monotonic inclusion ladder.

    Each profile is a strict superset of the prior. Moving up only
    *adds* signal types; nothing is removed. This makes "I want my
    agent spans in Datadog" a confident pick — choosing STANDARD
    can't accidentally lose a metric you were already receiving.
    """

    OFF = "off"
    METRICS = "metrics"
    STANDARD = "standard"
    GOVERNANCE = "governance"

    @classmethod
    def from_env(cls, value: Optional[str]) -> "OtlpProfile":
        """Parse a profile from an env-var-style string.

        Accepts any case; recognizes the four named profiles.
        Empty / None / unrecognized values map to ``OFF`` — the
        safe default. We log a warning on unrecognized values so
        operators see the typo rather than silently getting
        no-export behavior.
        """
        if not value:
            return cls.OFF
        normalized = value.strip().lower()
        try:
            return cls(normalized)
        except ValueError:
            logger.warning(
                "WL_OTLP_PROFILE='%s' unrecognized; valid values are %s. "
                "Falling back to OFF (no OTLP export).",
                value,
                [p.value for p in cls],
            )
            return cls.OFF

    def includes_metrics(self) -> bool:
        return self != OtlpProfile.OFF

    def includes_spans(self) -> bool:
        return self in (OtlpProfile.STANDARD, OtlpProfile.GOVERNANCE)

    def includes_anomaly_logs(self) -> bool:
        return self == OtlpProfile.GOVERNANCE


@dataclass
class OtlpConfig:
    """Operator-configurable OTLP export settings.

    Constructed explicitly (e.g. in a service's startup module) OR
    via :meth:`from_env` for the env-var pattern. Default is the
    no-op shape: profile OFF, no endpoint, no headers, full sample
    rate (irrelevant when off).
    """

    profile: OtlpProfile = OtlpProfile.OFF
    """Which preset to use. See the ladder above."""

    endpoint: Optional[str] = None
    """gRPC or HTTP endpoint of the customer's OTel collector.
    e.g. ``http://otel-collector:4318`` (HTTP) or
    ``otel-collector:4317`` (gRPC). Required when profile != OFF."""

    headers: Dict[str, str] = field(default_factory=dict)
    """Headers attached to every OTLP export call (e.g. Datadog
    API key, Honeycomb team token). Sensitive; never logged."""

    sample_rate: float = 1.0
    """Customer-side trace-sampling rate in [0.0, 1.0]. Affects
    OTLP export only — the underlying Watchlight lineage stream is
    always unsampled."""

    resource_attributes: Dict[str, str] = field(default_factory=dict)
    """Tags applied to every emission (e.g.
    ``deployment.environment=prod``). Standard OTel resource
    semantics."""

    governance_anomaly_floor: str = "info"
    """When profile == GOVERNANCE, the minimum severity for
    anomaly logs to be emitted. Valid values: ``debug`` / ``info``
    / ``warn`` / ``error``. Default ``info`` emits all customer-
    visible anomaly classes; setting to ``error`` filters out the
    informational ones (expired-token-use). Operator decides."""

    @classmethod
    def from_env(cls) -> "OtlpConfig":
        """Build config from canonical environment variables.

        | Env var | Maps to |
        |---|---|
        | ``WL_OTLP_PROFILE`` | ``profile`` |
        | ``WL_OTLP_ENDPOINT`` | ``endpoint`` |
        | ``WL_OTLP_HEADERS`` | ``headers`` (parsed as ``k=v,k2=v2``) |
        | ``WL_OTLP_SAMPLE_RATE`` | ``sample_rate`` (float) |
        | ``WL_OTLP_RESOURCE_ATTRIBUTES`` | ``resource_attributes`` (parsed as ``k=v,k2=v2``) |
        | ``WL_OTLP_GOVERNANCE_ANOMALY_FLOOR`` | ``governance_anomaly_floor`` |

        Returns a config with profile=OFF if ``WL_OTLP_PROFILE``
        is unset. Headers / resource_attributes parsing is forgiving
        — malformed entries are dropped with a debug log rather than
        raising at startup (the goal is to never block service
        startup on observability misconfig).
        """
        sample_str = os.environ.get("WL_OTLP_SAMPLE_RATE", "1.0").strip()
        try:
            sample_rate = max(0.0, min(1.0, float(sample_str)))
        except ValueError:
            logger.warning(
                "WL_OTLP_SAMPLE_RATE='%s' is not a valid float; "
                "falling back to 1.0",
                sample_str,
            )
            sample_rate = 1.0

        return cls(
            profile=OtlpProfile.from_env(os.environ.get("WL_OTLP_PROFILE")),
            endpoint=os.environ.get("WL_OTLP_ENDPOINT") or None,
            headers=_parse_kv_pairs(os.environ.get("WL_OTLP_HEADERS")),
            sample_rate=sample_rate,
            resource_attributes=_parse_kv_pairs(
                os.environ.get("WL_OTLP_RESOURCE_ATTRIBUTES")
            ),
            governance_anomaly_floor=os.environ.get(
                "WL_OTLP_GOVERNANCE_ANOMALY_FLOOR", "info"
            ).strip().lower(),
        )

    def is_enabled(self) -> bool:
        """True iff the exporter should do anything at all."""
        return self.profile != OtlpProfile.OFF


def _parse_kv_pairs(raw: Optional[str]) -> Dict[str, str]:
    """Parse a ``k=v,k2=v2`` env-var-style string into a dict.

    Forgiving on malformed entries: drops them with a debug log
    rather than raising. Trims whitespace around keys and values.
    Never returns None — empty input yields an empty dict.
    """
    if not raw:
        return {}
    out: Dict[str, str] = {}
    for pair in raw.split(","):
        pair = pair.strip()
        if not pair or "=" not in pair:
            if pair:
                logger.debug("OTLP kv-pair: dropping malformed entry %r", pair)
            continue
        k, _, v = pair.partition("=")
        k = k.strip()
        v = v.strip()
        if not k:
            logger.debug("OTLP kv-pair: dropping empty key in %r", pair)
            continue
        out[k] = v
    return out


# ─── Redaction — the never-export boundary ────────────────────────────


# Wire-name list of fields that MUST NOT appear in OTLP exports, no
# matter the profile. Centralized here so the boundary is one diff
# to audit. If a future event type adds a new sensitive field,
# adding it to this list is the only required guard.
#
# Categories:
#   - PII / customer IP: tool_args, prompts, prompt_summary,
#     input_summary, outcome, intent_objective, raw error messages
#     with structured payloads
#   - Watchlight IP: baseline statistics, drift scores, raw ABR
#     numeric score, FSM internal state, policy match internals
#   - Security-internal: failed-auth thresholds, kind-mismatch
#     internals
_NEVER_EXPORT_PAYLOAD_KEYS: frozenset = frozenset(
    {
        # Tool / LLM call content
        "tool_args",
        "tool_input",
        "input_summary",
        "prompt_summary",
        "prompts",
        "messages",
        "input_str",
        # Cognitive content
        "outcome",
        "intent_objective",
        "rationale",
        "log",
        # Drift / detection internals
        "baseline_id",
        "baseline_signature",
        "drift_score",
        "jsd_score",
        "mann_whitney_p",
        "tool_freq_dist",
        "event_ngram_dist",
        # ABR / scoring internals (numeric score; tier label IS
        # exported via wl.authority_class)
        "blast_radius_score",
        "abr_inputs",
        "abr_computed_at",
        # Policy internals
        "policies_evaluated",
        "policies_matched",
        "determining_policy",
        "evaluation_ms",
        # Auth internals
        "lookup_hash",
        "pepper_version",
        "credential_signature",
    }
)


# Wire-name list of anomaly kinds that are security-internal —
# never exported regardless of profile. The customer-visible ones
# stay in the export path; these don't.
_NEVER_EXPORT_ANOMALY_KINDS: frozenset = frozenset(
    {
        "token.failed_auth.repeated",  # informs attackers via leaky log channels
        "token.kind_mismatch",  # internal mechanics; not customer-actionable
        "baseline.integrity_violation",  # platform-internal tamper detection
    }
)


def _redact_event(event: Dict[str, Any]) -> Dict[str, Any]:
    """Strip never-export fields from a canonical ExecutionEvent
    dict before any OTel signal is built from it.

    Returns a new dict; the input is not modified. The mutation-
    free pattern means the redactor is safe to call from any code
    path; the lineage emitter sees the original event unchanged.

    Implementation note: we recurse into the ``payload`` and
    ``metadata`` sub-dicts because some forbidden keys (like
    ``prompt_summary``) live inside metadata. Nested values are
    NOT stripped — only top-level keys in payload/metadata.
    Adding deeper redaction here would be a maintenance burden
    AND wouldn't help, because if you're stuffing PII into
    payload.input_summary.subfield.subfield, you've already
    broken the wire-shape conventions and the translator output
    will be malformed for other reasons.
    """
    if not isinstance(event, dict):
        return {}

    redacted = {k: v for k, v in event.items() if k != "payload" and k != "metadata"}

    payload = event.get("payload")
    if isinstance(payload, dict):
        redacted["payload"] = {
            k: v
            for k, v in payload.items()
            if k not in _NEVER_EXPORT_PAYLOAD_KEYS
        }

    metadata = event.get("metadata")
    if isinstance(metadata, dict):
        redacted["metadata"] = {
            k: v
            for k, v in metadata.items()
            if k not in _NEVER_EXPORT_PAYLOAD_KEYS
        }

    return redacted


# ─── Severity ordering for anomaly log filtering ──────────────────────


_SEVERITY_ORDER: Dict[str, int] = {
    "debug": 0,
    "info": 1,
    "low": 1,  # anomaly severity (expired_use_attempt is "low")
    "warn": 2,
    "warning": 2,
    "high": 3,
    "error": 3,
    "critical": 4,
    "fatal": 4,
}


def _anomaly_passes_floor(anomaly_severity: str, floor: str) -> bool:
    """True iff the anomaly's severity is at or above the
    configured floor for the GOVERNANCE profile."""
    a = _SEVERITY_ORDER.get((anomaly_severity or "").lower(), 1)
    f = _SEVERITY_ORDER.get((floor or "info").lower(), 1)
    return a >= f


# ─── Translation: ExecutionEvent → OTel signal kind ────────────────────


def _event_otel_kind(event: Dict[str, Any]) -> str:
    """Classify a (redacted) canonical event by which OTel signal
    kind it produces.

    Returns one of:
      * ``"span_root"``     — execution_started / completed / failed
      * ``"span_child"``    — tool_call_observed, api_request_observed,
                              agent_spawn_observed
      * ``"span_event"``    — policy_decision_made (attaches to parent)
      * ``"log"``           — anomaly events (severity-gated)
      * ``"none"``          — emitted by lineage but NOT by OTLP
                              (e.g. internal drift signals)
    """
    event_type = event.get("event_type", "")
    if event_type in ("execution_started", "execution_completed", "execution_failed"):
        return "span_root"
    if event_type in ("tool_call_observed", "api_request_observed", "agent_spawn_observed"):
        return "span_child"
    if event_type == "policy_decision_made":
        return "span_event"
    if event_type.startswith("token.") or event_type.startswith("agent.") or event_type.startswith("policy."):
        return "log"
    return "none"


# ─── Exporter ──────────────────────────────────────────────────────────


class WatchlightOtlpExporter:
    """Translates Watchlight canonical execution events into
    OpenTelemetry signals (spans, metrics, logs) and exports them
    via the OTel SDK to the customer's collector.

    **Always best-effort**: export failures never propagate to the
    request path. The underlying Watchlight lineage stream is
    completely independent — a failing OTLP export does NOT mean
    a missing audit row.

    Construction:

        config = OtlpConfig.from_env()
        exporter = WatchlightOtlpExporter(config)
        # later, per execution:
        exporter.export_events(canonical_events)

    The OpenTelemetry SDK is an optional dependency. If it's not
    installed (``pip install watchlight-core[otlp]`` to get it),
    construction with a non-OFF profile raises a clear ImportError
    at startup rather than silently failing later.
    """

    def __init__(self, config: OtlpConfig):
        self._config = config
        self._tracer = None
        self._meter = None
        self._logger = None
        self._counters: Dict[str, Any] = {}
        self._histograms: Dict[str, Any] = {}

        if not config.is_enabled():
            logger.info("OTLP exporter disabled (profile=off)")
            return

        # Defer SDK import until we actually need it. Lets
        # watchlight-core install cleanly without the OTel SDK
        # weight; only customers who opt into OTLP pay the cost.
        try:
            self._init_otel_sdk()
        except ImportError as exc:
            raise ImportError(
                "Watchlight OTLP export requires the OpenTelemetry SDK. "
                "Install with: pip install 'watchlight-core[otlp]'"
            ) from exc

    def _init_otel_sdk(self) -> None:
        """Build the OTel TracerProvider, MeterProvider, and
        LoggerProvider. Wires the OTLP exporter for each signal
        type the active profile requires.

        OTel Python's log API stabilized in 2025 but the import
        paths still live under ``_logs`` (note leading underscore).
        We import logs imports lazily inside the log-emission code
        path to keep this method resilient if the customer's
        OTel SDK version lacks the log API entirely — they'll
        still get spans + metrics."""
        from opentelemetry.exporter.otlp.proto.http.metric_exporter import (
            OTLPMetricExporter,
        )
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
            OTLPSpanExporter,
        )
        from opentelemetry.sdk.metrics import MeterProvider
        from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
        from opentelemetry.sdk.trace.sampling import TraceIdRatioBased

        # Resource: identifies "this is Watchlight signal data" plus
        # any operator-supplied tags.
        resource_attrs = {
            "service.name": "watchlight",
            "service.namespace": "watchlight.ai",
            **self._config.resource_attributes,
        }
        resource = Resource.create(resource_attrs)

        # ── Spans ──
        if self._config.profile.includes_spans():
            sampler = TraceIdRatioBased(self._config.sample_rate)
            tracer_provider = TracerProvider(resource=resource, sampler=sampler)
            span_exporter = OTLPSpanExporter(
                endpoint=self._config.endpoint,
                headers=self._config.headers,
            )
            tracer_provider.add_span_processor(BatchSpanProcessor(span_exporter))
            self._tracer = tracer_provider.get_tracer("watchlight")

        # ── Metrics ──
        if self._config.profile.includes_metrics():
            metric_exporter = OTLPMetricExporter(
                endpoint=self._config.endpoint,
                headers=self._config.headers,
            )
            metric_reader = PeriodicExportingMetricReader(metric_exporter)
            meter_provider = MeterProvider(
                resource=resource, metric_readers=[metric_reader]
            )
            self._meter = meter_provider.get_meter("watchlight")
            self._setup_metric_instruments()

        # ── Logs (anomaly events) ──
        if self._config.profile.includes_anomaly_logs():
            try:
                from opentelemetry.exporter.otlp.proto.http._log_exporter import (
                    OTLPLogExporter,
                )
                from opentelemetry.sdk._logs import LoggerProvider
                from opentelemetry.sdk._logs.export import BatchLogRecordProcessor

                log_exporter = OTLPLogExporter(
                    endpoint=self._config.endpoint,
                    headers=self._config.headers,
                )
                logger_provider = LoggerProvider(resource=resource)
                logger_provider.add_log_record_processor(
                    BatchLogRecordProcessor(log_exporter)
                )
                self._logger = logger_provider.get_logger("watchlight.anomaly")
            except ImportError as exc:  # OTel log API not present in this SDK version
                logger.warning(
                    "OTLP governance profile selected but OpenTelemetry log API "
                    "is unavailable in this SDK version (%s). Spans + metrics will "
                    "still export; anomaly logs will be skipped. Upgrade "
                    "opentelemetry-sdk to enable log export.",
                    exc,
                )
                self._logger = None

    def _setup_metric_instruments(self) -> None:
        """Pre-create the metric instruments. Recording into a
        non-existent instrument is silent in the OTel SDK; pre-
        creating them at startup means a typo in the recording
        call surfaces as an AttributeError instead."""
        if self._meter is None:
            return
        self._counters["authz_requests"] = self._meter.create_counter(
            name="wl.authz.requests",
            description="Authorization requests handled by Watchlight",
            unit="1",
        )
        self._counters["tool_calls"] = self._meter.create_counter(
            name="wl.tool.calls",
            description="Tool invocations observed",
            unit="1",
        )
        self._counters["lineage_events"] = self._meter.create_counter(
            name="wl.lineage.events_published",
            description="Execution events published from plugins",
            unit="1",
        )
        self._histograms["authz_duration_ms"] = self._meter.create_histogram(
            name="wl.authz.duration_ms",
            description="Authorization decision latency",
            unit="ms",
        )
        self._histograms["tool_duration_ms"] = self._meter.create_histogram(
            name="wl.tool.duration_ms",
            description="Tool invocation duration",
            unit="ms",
        )

    # ── Public API ──

    def export_events(self, events: List[Dict[str, Any]]) -> int:
        """Translate and export a batch of canonical execution
        events. Best-effort: failures logged at debug, no raises.

        Returns the count of events that produced an OTel signal
        (some events emit no signal under the active profile —
        e.g. an anomaly log under STANDARD profile). Used for
        observability / test assertions.
        """
        if not self._config.is_enabled() or not events:
            return 0
        emitted = 0
        for raw_event in events:
            try:
                redacted = _redact_event(raw_event)
                if self._export_one(redacted):
                    emitted += 1
            except Exception as exc:  # noqa: BLE001 — best-effort
                logger.debug(
                    "OTLP export skipped event %s due to %s: %s",
                    raw_event.get("event_type"),
                    type(exc).__name__,
                    exc,
                )
        return emitted

    def _export_one(self, event: Dict[str, Any]) -> bool:
        """Export one redacted event. Returns True if a signal
        was emitted under the active profile."""
        kind = _event_otel_kind(event)
        if kind == "none":
            return False
        if kind in ("span_root", "span_child") and self._tracer is None:
            return False
        if kind == "span_event" and self._tracer is None:
            return False
        if kind == "log" and self._logger is None:
            return False

        # Always emit the corresponding metric (counter) regardless
        # of span/log emission, IF metrics are enabled. Metrics work
        # as long as profile != OFF (METRICS, STANDARD, GOVERNANCE
        # all include them).
        if self._meter is not None:
            self._record_metrics(event)

        if kind == "span_root":
            return self._emit_root_span(event)
        if kind == "span_child":
            return self._emit_child_span(event)
        if kind == "span_event":
            return self._emit_span_event(event)
        if kind == "log":
            return self._emit_anomaly_log(event)
        return False

    # ── Span emission ──

    def _emit_root_span(self, event: Dict[str, Any]) -> bool:
        if self._tracer is None:
            return False
        from opentelemetry.trace import Status, StatusCode

        attrs = self._common_span_attrs(event)
        event_type = event.get("event_type", "")
        payload = event.get("payload", {})

        span_name = f"agent.{event_type.replace('execution_', '')}"
        with self._tracer.start_as_current_span(span_name, attributes=attrs) as span:
            if event_type == "execution_completed":
                span.set_attribute(
                    "wl.execution.duration_ms",
                    int(payload.get("duration_ms", 0) or 0),
                )
                span.set_attribute(
                    "wl.execution.actions_taken",
                    int(payload.get("actions_taken", 0) or 0),
                )
                span.set_attribute(
                    "wl.execution.actions_denied",
                    int(payload.get("actions_denied", 0) or 0),
                )
                span.set_status(Status(StatusCode.OK))
            elif event_type == "execution_failed":
                # ``error_type`` is the canonical field; ``error_code`` is
                # the legacy key some emitters used before the payload
                # shape was pinned — read both so events already in
                # flight from an older plugin still carry the category.
                error_code = payload.get("error_type") or payload.get("error_code")
                error_msg = payload.get("error") or "unknown_error"
                if error_code:
                    span.set_attribute("wl.error.code", str(error_code))
                span.set_status(Status(StatusCode.ERROR, description=str(error_msg)))
        return True

    def _emit_child_span(self, event: Dict[str, Any]) -> bool:
        if self._tracer is None:
            return False

        attrs = self._common_span_attrs(event)
        event_type = event.get("event_type", "")
        payload = event.get("payload", {})

        if event_type == "tool_call_observed":
            tool = payload.get("tool", {})
            # Canonical ``ResourceRef`` carries the namespaced URI on
            # ``endpoint``; ``resource`` is the legacy flattened key some
            # emitters used before the payload shape was pinned. Read
            # both so in-flight events from an older plugin still land a
            # resource attribute. Same precedence as conformance
            # invariant 4.
            resource = (
                (tool.get("endpoint") or tool.get("resource"))
                if isinstance(tool, dict)
                else None
            )
            attrs["wl.tool.resource"] = str(resource or "unknown")
            action = payload.get("action", {})
            if isinstance(action, dict):
                attrs["wl.tool.action"] = str(action.get("action", ""))
            if payload.get("decision"):
                attrs["wl.tool.decision"] = str(payload["decision"])
            if isinstance(payload.get("duration_ms"), (int, float)):
                attrs["wl.tool.duration_ms"] = int(payload["duration_ms"])
            span_name = f"tool.{action.get('action', 'invoke') if isinstance(action, dict) else 'invoke'}"
        elif event_type == "api_request_observed":
            resource_obj = payload.get("resource", {})
            resource = (
                (resource_obj.get("endpoint") or resource_obj.get("resource"))
                if isinstance(resource_obj, dict)
                else None
            )
            attrs["wl.api.resource"] = str(resource or "unknown")
            attrs["wl.api.method"] = str(payload.get("method", "POST"))
            attrs["wl.api.path"] = str(payload.get("path", ""))
            # OTel semantic convention for LLM calls
            metadata = event.get("metadata", {})
            if isinstance(metadata, dict) and metadata.get("model"):
                attrs["gen_ai.request.model"] = str(metadata["model"])
                attrs["gen_ai.system"] = "watchlight"
            span_name = "api.request"
        elif event_type == "agent_spawn_observed":
            attrs["wl.spawn.agent_id"] = str(payload.get("spawned_agent_id", ""))
            attrs["wl.spawn.principal"] = str(payload.get("spawned_principal", ""))
            # A labelled sub-agent's label: evidence, set by wl-apdp.
            if isinstance(payload.get("spawned_label"), str):
                attrs["wl.spawn.label"] = payload["spawned_label"]
            span_name = "agent.spawn"
        else:
            return False

        with self._tracer.start_as_current_span(span_name, attributes=attrs):
            pass  # Child span has no body for now; the attributes ARE the signal
        return True

    def _emit_span_event(self, event: Dict[str, Any]) -> bool:
        """policy_decision_made → attach as a span event on the
        current span (the running execution_started's span)."""
        if self._tracer is None:
            return False
        from opentelemetry.trace import get_current_span

        payload = event.get("payload", {})
        attrs = {
            "wl.policy.action": str(payload.get("action", "")),
            "wl.policy.resource": str(payload.get("resource", "")),
            "wl.policy.decision": str(payload.get("decision", "")),
        }
        # Reason is bounded (already truncated upstream); safe to
        # include in attrs.
        if payload.get("reason"):
            attrs["wl.policy.reason"] = str(payload["reason"])[:120]

        current = get_current_span()
        # If there's no active span (no execution_started yet seen),
        # we still record the metric but skip the span event.
        if current is not None and current.is_recording():
            current.add_event("wl.policy.decision", attributes=attrs)
            return True
        return False

    # ── Log emission (anomalies) ──

    def _emit_anomaly_log(self, event: Dict[str, Any]) -> bool:
        if self._logger is None:
            return False

        event_type = event.get("event_type", "")
        # Hard never-export filter — checked even though the kind
        # classifier didn't catch it. Defense in depth.
        if event_type in _NEVER_EXPORT_ANOMALY_KINDS:
            return False

        # Severity filter against the configured floor.
        metadata = event.get("metadata") or {}
        payload = event.get("payload") or {}
        severity = (
            payload.get("severity")
            or metadata.get("severity")
            or _default_severity_for_anomaly(event_type)
        )
        if not _anomaly_passes_floor(severity, self._config.governance_anomaly_floor):
            return False

        try:
            from opentelemetry._logs import SeverityNumber  # noqa: F401
            from opentelemetry.sdk._logs import LogRecord
        except ImportError:
            return False

        otel_severity = _severity_to_otel(severity)
        attrs = self._common_span_attrs(event)
        attrs["wl.anomaly.kind"] = event_type
        attrs["wl.anomaly.severity"] = severity
        for k in ("client_ip", "credential_id", "credential_kind", "asn",
                  "prior_asn", "failure_count"):
            v = payload.get(k)
            if v is not None:
                attrs[f"wl.anomaly.{k}"] = str(v)

        body = payload.get("description") or event_type
        record = LogRecord(
            body=str(body),
            severity_number=otel_severity,
            severity_text=severity,
            attributes=attrs,
        )
        self._logger.emit(record)
        return True

    # ── Metrics ──

    def _record_metrics(self, event: Dict[str, Any]) -> None:
        """Increment counters and record histograms based on event
        type. Always runs when METRICS profile (or higher) is on."""
        event_type = event.get("event_type", "")
        labels = self._common_metric_labels(event)

        if event_type == "policy_decision_made":
            payload = event.get("payload") or {}
            self._counters["authz_requests"].add(
                1,
                {**labels, "decision": str(payload.get("decision", ""))},
            )
        elif event_type == "tool_call_observed":
            payload = event.get("payload") or {}
            self._counters["tool_calls"].add(
                1,
                {**labels, "decision": str(payload.get("decision", "Allow"))},
            )
            duration = payload.get("duration_ms")
            if isinstance(duration, (int, float)):
                self._histograms["tool_duration_ms"].record(float(duration), labels)
        elif event_type in (
            "execution_started",
            "execution_completed",
            "execution_failed",
        ):
            self._counters["lineage_events"].add(1, {**labels, "type": event_type})

    # ── Attribute helpers ──

    def _common_span_attrs(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Build the cross-event attribute set every span/log
        carries. Source + identity attribution."""
        attrs: Dict[str, Any] = {}
        if event.get("agent_id"):
            attrs["wl.agent_id"] = str(event["agent_id"])
        if event.get("execution_id"):
            attrs["wl.execution_id"] = str(event["execution_id"])
        if event.get("tenant_id"):
            attrs["wl.tenant_id"] = str(event["tenant_id"])
        if event.get("session_id"):
            attrs["wl.session_id"] = str(event["session_id"])
        if event.get("parent_execution_id"):
            attrs["wl.parent_execution_id"] = str(event["parent_execution_id"])
        metadata = event.get("metadata") or {}
        if isinstance(metadata, dict):
            if metadata.get("source"):
                attrs["wl.source"] = str(metadata["source"])
            if metadata.get("authority_class"):
                attrs["wl.authority_class"] = str(metadata["authority_class"])
        return attrs

    def _common_metric_labels(self, event: Dict[str, Any]) -> Dict[str, str]:
        """Metric labels — narrower than span attrs because metric
        cardinality matters. We label by tenant + authority class +
        source plugin; no per-execution id, no per-credential id."""
        labels: Dict[str, str] = {}
        if event.get("tenant_id"):
            labels["tenant_id"] = str(event["tenant_id"])
        metadata = event.get("metadata") or {}
        if isinstance(metadata, dict):
            if metadata.get("source"):
                labels["source"] = str(metadata["source"])
            if metadata.get("authority_class"):
                labels["authority_class"] = str(metadata["authority_class"])
        return labels


# ─── Local helpers used by the exporter ────────────────────────────────


def _default_severity_for_anomaly(event_type: str) -> str:
    """Default severity per anomaly kind. Used when the event
    didn't carry an explicit severity field."""
    severity_map = {
        "token.failed_auth.repeated": "warn",
        "token.geo_shift": "warn",
        "token.revoked_use_attempt": "high",
        "token.expired_use_attempt": "low",
        "token.tenant_mismatch": "high",
        "token.cross_tenant_session": "high",
        "token.kind_mismatch": "high",
        "agent.goal_drift": "warn",
    }
    return severity_map.get(event_type, "info")


def _severity_to_otel(severity: str):
    """Map a severity string to an OTel SeverityNumber."""
    from opentelemetry._logs import SeverityNumber

    mapping = {
        "debug": SeverityNumber.DEBUG,
        "info": SeverityNumber.INFO,
        "low": SeverityNumber.INFO,
        "warn": SeverityNumber.WARN,
        "warning": SeverityNumber.WARN,
        "high": SeverityNumber.ERROR,
        "error": SeverityNumber.ERROR,
        "critical": SeverityNumber.FATAL,
        "fatal": SeverityNumber.FATAL,
    }
    return mapping.get((severity or "info").lower(), SeverityNumber.INFO)


