"""Pydantic mirror of the canonical ``ExecutionEvent`` wire format.

The authoritative schema lives in Rust at
the wl-lineage event schema; this module reproduces it as
``pydantic.BaseModel`` classes so Python plugin authors get:

  - **Typed construction** — `ExecutionEvent(event_id="evt_...", ...)`
    validates fields at build time, not at the receiving service.
  - **Single source of truth** for bounded-size constants
    (``PLAN_RATIONALE_MAX_BYTES``, ``PLAN_INTENDED_TOOLS_MAX``, etc.)
    so plugins import from one place rather than duplicating
    constants per package.
  - **JSON-serialisable** via pydantic's standard ``.model_dump()``
    / ``.model_dump_json()`` — what goes on the wire matches what
    the receiving wl-execution-graph + APDP services deserialise.

**Drift discipline**: when the wl-lineage event schema changes,
this file changes in the same PR. The cross-plugin conformance
suite at ``tests/test_cross_plugin_conformance.py`` is the
contract: anything that test asserts, this schema MUST allow; any
shape this schema permits, the test SHOULD assert.

The Rust side is the canonical truth-on-the-wire; pydantic models
here are the typed Python interface to that wire.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel, ConfigDict, Field, model_validator

__all__ = [
    # Bounded-size constants (lockstep with wl-lineage::events)
    "INPUT_SUMMARY_MAX_CHARS",
    "ERROR_MESSAGE_MAX_CHARS",
    "PLAN_RATIONALE_MAX_BYTES",
    "PLAN_INTENDED_TOOLS_MAX",
    "PLAN_TOOL_NAME_PATTERN",
    "PLAN_TOOL_NAME_RE",
    "EVENT_ID_PATTERN",
    "EVENT_ID_RE",
    # Quarantine event constants (lockstep with wl-lineage::events)
    "REASON_MAX_BYTES",
    "LIFT_REASON_MAX_BYTES",
    "MAX_CONTRIBUTING_FEATURES",
    # Intent-provenance constant (lockstep with wl-lineage::events)
    "INTENT_OBJECTIVE_MAX_BYTES",
    # Enum types
    "EventType",
    "PlanKind",
    # Intent provenance enum
    "IntentProvenance",
    # Reference types
    "PrincipalRef",
    "ResourceRef",
    "ActionRef",
    "CredentialRef",
    # Payload variants
    "ExecutionStartedPayload",
    "ToolCallObservedPayload",
    "ApiRequestObservedPayload",
    "PolicyDecisionMadePayload",
    "AgentSpawnObservedPayload",
    "ExecutionCompletedPayload",
    "ExecutionFailedPayload",
    "PlanObservedPayload",
    # Quarantine payload mirrors (lockstep with wl-lineage::events)
    "FeatureContribution",
    "ExecutionQuarantinedPayload",
    "ExecutionResumedPayload",
    # Envelope + composite
    "EventEnvelope",
    "ExecutionEvent",
    # Helpers
    "truncate_summary",
    "redacted_error_summary",
    "redacted_input_summary",
    "summarize_arg_keys",
    "truncate_error_message",
    # Payload-schema enforcement (conformance invariant 16)
    "payload_model_for",
    "validate_event_payload",
    "unknown_payload_keys",
    "PayloadSchemaError",
]


# ─── Bounded-size constants (lockstep with wl-lineage::events) ────────
# These mirror the Rust constants in the wl-lineage event schema.
# Changing one without the other splits the wire contract.

#: Maximum chars in ``ToolCallObservedPayload.input_summary``. Defends
#: against adversarial input padding and caps downstream
#: consumer memory.
INPUT_SUMMARY_MAX_CHARS: int = 120

#: Maximum chars in ``ExecutionFailedPayload.error``. Operator-
#: legibility cap; full stack traces belong in trace exporters, not
#: in the audit event itself.
ERROR_MESSAGE_MAX_CHARS: int = 512

#: Maximum byte length of ``PlanObservedPayload.rationale``. Byte-
#: counted (not char-counted) so multi-byte UTF-8 doesn't blow past
#: the cap. Plugins truncate at the byte boundary; this module's
#: :func:`truncate_rationale` does the truncation safely.
PLAN_RATIONALE_MAX_BYTES: int = 1024

#: Maximum number of tool names in a single ``intended_tools`` list.
#: ``Upfront`` plans can list dozens; ``Incremental`` plans usually
#: list one. The cap defends against adversarial padding.
PLAN_INTENDED_TOOLS_MAX: int = 64

#: Regex pattern for valid tool names in ``intended_tools``. Same
#: charset the Rust side uses — see ``wl-lineage::events``.
PLAN_TOOL_NAME_PATTERN: str = r"^[A-Za-z0-9_.\-]{1,128}$"
PLAN_TOOL_NAME_RE = re.compile(PLAN_TOOL_NAME_PATTERN)

#: Regex pattern for canonical ``event_id`` values. ``evt_`` prefix +
#: UUID v4 hex. SIEM correlation rules grep for the prefix.
EVENT_ID_PATTERN: str = r"^evt_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
EVENT_ID_RE = re.compile(EVENT_ID_PATTERN)

#: Maximum byte-length of the operator-readable summary in
#: ``ExecutionQuarantinedPayload.reason``. Mirrors
#: ``wl-lineage::events::REASON_MAX_BYTES``. Byte-counted (not char-
#: counted) so multi-byte UTF-8 doesn't blow past the cap.
REASON_MAX_BYTES: int = 512

#: Maximum byte-length of the operator-supplied lift reason
#: in ``ExecutionResumedPayload.lift_reason``. Mirrors
#: ``wl-lineage::events::LIFT_REASON_MAX_BYTES``. Larger than
#: ``REASON_MAX_BYTES`` because operators tend to document false-
#: positive lifts at greater length.
LIFT_REASON_MAX_BYTES: int = 1024

#: Maximum number of ``FeatureContribution`` entries allowed
#: on a single ``execution_quarantined`` event. Mirrors
#: ``wl-lineage::events::MAX_CONTRIBUTING_FEATURES``. Bounded against
#: an attacker padding the event to inflate downstream consumer load.
MAX_CONTRIBUTING_FEATURES: int = 3

#: Maximum byte length of
#: ``ExecutionStartedPayload.intent_objective``. Mirrors
#: ``wl-lineage::events::INTENT_OBJECTIVE_MAX_BYTES``. Byte-counted
#: (not char-counted) so multi-byte UTF-8 doesn't blow past the cap.
#: Operator-legibility bound — longer prompts belong in trace
#: exporters, not the audit event.
INTENT_OBJECTIVE_MAX_BYTES: int = 256


# ─── Enum discriminators ──────────────────────────────────────────────


class EventType(str, Enum):
    """Canonical event-type discriminator. Mirrors
    ``wl-lineage::events::EventType``.

    The ten values here are exhaustive. Plugins MUST NOT invent
    new event types — extend via ``metadata`` if you need more
    granular categorisation for a specific framework.

    ``execution_quarantined`` and ``execution_resumed`` support the
    adaptive-authorization kill-switch flow. Plugins
    emit ``execution_quarantined`` when a ``BaseRunHandle``
    transitions to the Quarantined state on a wl-apdp Quarantine
    decision; the dashboard emits ``execution_resumed`` when an
    operator lifts a quarantine.
    """

    EXECUTION_STARTED = "execution_started"
    TOOL_CALL_OBSERVED = "tool_call_observed"
    API_REQUEST_OBSERVED = "api_request_observed"
    POLICY_DECISION_MADE = "policy_decision_made"
    AGENT_SPAWN_OBSERVED = "agent_spawn_observed"
    EXECUTION_COMPLETED = "execution_completed"
    EXECUTION_FAILED = "execution_failed"
    PLAN_OBSERVED = "plan_observed"
    EXECUTION_QUARANTINED = "execution_quarantined"
    EXECUTION_RESUMED = "execution_resumed"


class PlanKind(str, Enum):
    """How a plan was captured. Mirrors
    ``wl-lineage::events::PlanKind`` — the correlator uses this to
    decide whether to treat the plan as authoritative
    (``upfront``) or to union with prior plans for the same
    execution (``incremental``).
    """

    UPFRONT = "upfront"
    INCREMENTAL = "incremental"
    INFERRED = "inferred"


class IntentProvenance(str, Enum):
    """Provenance of ``ExecutionStartedPayload.intent_objective``.
    Mirrors ``wl-lineage::events::IntentProvenance``.

    Cedar policies key on this for tier-graded enforcement: a
    Custodial agent in greenfield mode may require ``declared``
    provenance; in brownfield mode ``proxy_inferred`` may be
    acceptable.

    Wire format: snake-case strings so multi-word variants render
    legibly on the JSON envelope. Cedar templates pattern-
    match on these exact wire strings.

    Backward compatibility: older ``execution_started`` events on
    the wire have NO ``intent_provenance`` field; those deserialise
    as ``intent_provenance=None`` which Cedar policies treat as
    equivalent to :attr:`ABSENT`.
    """

    #: Customer explicitly declared via
    #: ``start_run(intent_objective="...")`` or via the synthetic
    #: ``watchlight.declare_intent`` tool path. Highest authority.
    DECLARED = "declared"

    #: Plugin extracted from a natural framework signal — first arg to
    #: Pydantic AI ``Agent.run(prompt)``, LangGraph
    #: ``on_chain_start.inputs``, Claude Agent SDK
    #: ``UserPromptSubmit`` hook event, Bedrock Lambda
    #: ``event["inputText"]``, etc. Zero customer-code touch.
    PLUGIN_DERIVED = "plugin_derived"

    #: wl-proxy ``IntentExtractingInterceptor`` parsed the request
    #: body during MITM termination on the first LLM call.
    #: Heuristic-only in v1.
    PROXY_INFERRED = "proxy_inferred"

    #: No source produced an intent for this execution. Cedar
    #: policies in greenfield mode MAY forbid at Elevated+;
    #: brownfield mode warns. Treated as the default when the field
    #: is missing on the wire (backward compatibility).
    ABSENT = "absent"


# ─── Reference types (PrincipalRef, ResourceRef, ActionRef) ───────────


class PrincipalRef(BaseModel):
    """A reference to an agent or human principal. Mirrors
    ``wl-lineage::types::PrincipalRef``.

    ``principal_type`` is one of ``agent`` / ``human`` /
    ``service``. ``id`` is the canonical UUID. Optional ``idp``
    identifies the identity provider for human principals.

    Every field below is one the Rust struct models. A mirror
    NARROWER than the Rust struct is not a safe default: with
    ``extra="forbid"`` it rejects payloads the server accepts, and it
    hides the drift it is supposed to make visible.
    """

    model_config = ConfigDict(extra="forbid")

    principal_type: str
    id: str
    idp: Optional[str] = None
    #: Agent role in the execution (orchestrator, planner, worker,
    #: reviewer).
    role: Optional[str] = None
    #: Registry slug for the principal (``agent-data-collector``), and
    #: its display name. wl-apdp's spawn handler populates both from
    #: the resolved ``identity.agents`` row, so a canonical event can
    #: carry them and the dashboard can label a UUID it has not cached.
    slug: Optional[str] = None
    name: Optional[str] = None


class ResourceRef(BaseModel):
    """A reference to a tool or external resource. Mirrors
    ``wl-lineage::types::ResourceRef``.

    The ``endpoint`` field carries the namespaced URI
    (``<framework>://`` for plugins, ``mcp://`` for wl-proxy MCP).
    Conformance invariant 4 (URI namespacing) is enforced on this
    field.
    """

    model_config = ConfigDict(extra="forbid")

    resource_type: str
    identifier: str
    #: FK to the wl-registry ``servers`` row, for an ``mcp_server``
    #: resource.
    server_id: Optional[str] = None
    endpoint: Optional[str] = None


class ActionRef(BaseModel):
    """A reference to an action being performed. Mirrors
    ``wl-lineage::types::ActionRef``.
    """

    model_config = ConfigDict(extra="forbid")

    action: str
    #: HTTP method, when the action is an HTTP call.
    http_method: Optional[str] = None


class CredentialRef(BaseModel):
    """A reference to a credential used in a call. Mirrors
    ``wl-lineage::types::CredentialRef``. Used in
    ``ApiRequestObservedPayload`` to record which secret was
    injected by WSB.

    Names a credential; never carries one.
    """

    model_config = ConfigDict(extra="forbid")

    #: Secret Capability Token id issued by WSB.
    sct_id: Optional[str] = None
    secret_ref: str
    #: Secret backend: ``openbao``, ``aws_secrets_manager``, ``env``.
    backend: Optional[str] = None
    #: Decision ids for audit correlation — WSB's, and the APDP
    #: decision that authorized the credential.
    wsb_decision_id: Optional[str] = None
    apdp_decision_id: Optional[str] = None


# ─── Payload variants — one per EventType ─────────────────────────────


class ExecutionStartedPayload(BaseModel):
    """Payload for ``EventType.EXECUTION_STARTED``. Mirrors
    ``wl-lineage::events::ExecutionStartedPayload``.

    The ``intent_provenance`` field records where the intent came
    from — see :class:`IntentProvenance`.
    The invariant ``intent_objective is not None ⇒ intent_provenance
    is set AND not ABSENT`` is enforced by
    :meth:`_validate_intent_provenance_consistency`.
    """

    model_config = ConfigDict(extra="forbid")

    principal: PrincipalRef
    depth: int = 0
    intent_category: Optional[str] = None
    intent_objective: Optional[str] = None
    #: Provenance of :attr:`intent_objective`. ``None`` is
    #: treated by Cedar as equivalent to :attr:`IntentProvenance.ABSENT`
    #: for backward wire compatibility. New emitters SHOULD set the
    #: explicit enum.
    intent_provenance: Optional[IntentProvenance] = None
    goal_id: Optional[str] = None
    delegation_chain_id: Optional[str] = None

    @model_validator(mode="after")
    def _validate_m46_intent_invariants(self) -> "ExecutionStartedPayload":
        """Intent-provenance invariants.

        1. ``intent_objective`` byte-length MUST NOT exceed
           :data:`INTENT_OBJECTIVE_MAX_BYTES`. Byte-counted to mirror
           the Rust ``String::len`` cap — multi-byte UTF-8 cannot
           slip past a char-counted ``max_length``.

        2. If ``intent_objective`` is set, ``intent_provenance`` MUST
           be set AND MUST NOT be :attr:`IntentProvenance.ABSENT` —
           an objective without a recorded source defeats the intent
           enforcement matrix.
        """
        if self.intent_objective is not None:
            byte_len = len(self.intent_objective.encode("utf-8"))
            if byte_len > INTENT_OBJECTIVE_MAX_BYTES:
                raise ValueError(
                    f"intent_objective is {byte_len} bytes "
                    f"(max {INTENT_OBJECTIVE_MAX_BYTES})"
                )
            if (
                self.intent_provenance is None
                or self.intent_provenance == IntentProvenance.ABSENT
            ):
                raise ValueError(
                    "intent_objective set but provenance is Absent — "
                    "provenance must be one of declared / plugin_derived / proxy_inferred"
                )
        return self


class ToolCallObservedPayload(BaseModel):
    """Payload for ``EventType.TOOL_CALL_OBSERVED``. Mirrors
    ``wl-lineage::events::ToolCallObservedPayload``.

    ``input_summary`` is bounded to
    :data:`INPUT_SUMMARY_MAX_CHARS`; the pydantic validator enforces
    it.
    """

    model_config = ConfigDict(extra="forbid")

    tool: ResourceRef
    action: ActionRef
    decision: Optional[str] = None
    determining_policy: Optional[str] = None
    input_summary: Optional[str] = Field(
        default=None, max_length=INPUT_SUMMARY_MAX_CHARS
    )
    #: Canonical argument-KEY summary for behavioural drift detection: the tool
    #: call's argument keys, sorted and comma-joined (no values), e.g.
    #: ``"encoding,path"``. Mirrors ``wl-lineage`` and the wl-proxy MCP path so
    #: arg-shape drift works whether a call is SDK-emitted or proxy-observed.
    #: Absent ⇒ no arg-shape contribution.
    arg_key_summary: Optional[str] = Field(
        default=None, max_length=INPUT_SUMMARY_MAX_CHARS
    )
    duration_ms: Optional[int] = None


class ApiRequestObservedPayload(BaseModel):
    """Payload for ``EventType.API_REQUEST_OBSERVED``. Mirrors
    ``wl-lineage::events::ApiRequestObservedPayload``. Emitted by
    wl-proxy on every HTTP request through a configured route.
    """

    model_config = ConfigDict(extra="forbid")

    resource: ResourceRef
    method: str
    path: str
    response_status: Optional[int] = None
    credential: Optional[CredentialRef] = None
    fields_scrubbed: int = 0
    pii_redacted: int = 0
    duration_ms: Optional[int] = None


class PolicyDecisionMadePayload(BaseModel):
    """Payload for ``EventType.POLICY_DECISION_MADE``. Mirrors
    ``wl-lineage::events::PolicyDecisionMadePayload``. Emitted by
    wl-apdp after Cedar evaluation. Plugins typically don't emit
    this directly — APDP does.
    """

    model_config = ConfigDict(extra="forbid")

    principal: str
    action: str
    resource: str
    decision: str  # "Allow" | "Deny"
    reason: Optional[str] = None
    policies_evaluated: List[str] = Field(default_factory=list)
    policies_matched: List[str] = Field(default_factory=list)
    determining_policy: Optional[str] = None
    trust_state: Optional[str] = None
    delegation_chain_id: Optional[str] = None
    intent_aligned: Optional[bool] = None
    evaluation_ms: Optional[int] = None
    # Where the decision was enforced (`gateway`, `secrets_broker`); wl-apdp
    # derives it from the caller's verified credential. Absent when none.
    enforcement_point: Optional[str] = None


class AgentSpawnObservedPayload(BaseModel):
    """Payload for ``EventType.AGENT_SPAWN_OBSERVED``. Mirrors
    ``wl-lineage::events::AgentSpawnObservedPayload``. Emitted by
    a parent agent's plugin when it spawns a sub-agent (the
    spawn-subagent primitive).
    """

    model_config = ConfigDict(extra="forbid")

    spawned_agent: PrincipalRef
    spawner: PrincipalRef
    child_execution_id: str
    delegation_scope: Optional[Dict[str, Any]] = None
    #: The scope APDP granted the sub-agent at spawn time.
    #: Untyped here (the Rust side models it as ``GrantedScope``); the
    #: mirror only has to agree on the KEY so the payload round-trips.
    granted_scope: Optional[Dict[str, Any]] = None
    #: ``True`` when the spawn named no time budget and the child inherited
    #: the parent's remaining time; ``granted_scope`` carries the resolved
    #: budget either way. Absent on events written before the field existed.
    time_budget_inherited: Optional[bool] = None
    #: The child's intent and goal as wl-apdp validated them against the
    #: parent's at the spawn (``SubagentDerivedIntent`` in Rust). Untyped here,
    #: like ``granted_scope``. Absent when the spawn declared no child intent.
    derived_intent: Optional[Dict[str, Any]] = None
    reason: Optional[str] = None
    #: The child's type or label (``spawn_subagent(child_label=...)``), set
    #: by wl-apdp from the spawn it validated. Evidence only, never an
    #: authority. Absent for a child spawned without a label.
    spawned_label: Optional[str] = None


class ExecutionCompletedPayload(BaseModel):
    """Payload for ``EventType.EXECUTION_COMPLETED``. Mirrors
    ``wl-lineage::events::ExecutionCompletedPayload``.

    **Not modelled here, deliberately**: the completing
    agent's tree ``depth`` and the id of the agent that spawned it.
    Two plugins used to put ``depth`` and ``spawned_by_agent_id`` on
    this payload; the Rust struct models neither and does not set
    ``deny_unknown_fields``, so serde accepted the event and silently
    dropped both keys. The spawner belongs on the ENVELOPE's
    ``parent_agent_id``; the depth is computed server-side by
    wl-execution-graph and served on ``lineage.executions.depth``.
    """

    model_config = ConfigDict(extra="forbid")

    duration_ms: int
    actions_taken: int
    actions_denied: int = 0
    tools_used: List[str] = Field(default_factory=list)
    outcome: Optional[str] = None
    #: Response-scrubber accounting: the NAMES of the fields
    #: wl-proxy removed and of the PII detectors that fired. Never a
    #: field VALUE.
    scrubbing_fields_removed: List[str] = Field(default_factory=list)
    pii_patterns_redacted: List[str] = Field(default_factory=list)


class ExecutionFailedPayload(BaseModel):
    """Payload for ``EventType.EXECUTION_FAILED``. Mirrors
    ``wl-lineage::events::ExecutionFailedPayload``.

    ``error`` is bounded to :data:`ERROR_MESSAGE_MAX_CHARS`; the
    pydantic validator enforces it.
    """

    model_config = ConfigDict(extra="forbid")

    error: str = Field(..., max_length=ERROR_MESSAGE_MAX_CHARS)
    duration_ms: Optional[int] = None
    error_type: Optional[str] = None
    policy_denied: bool = False
    determining_policy: Optional[str] = None
    #: Same response-scrubber accounting as
    #: :class:`ExecutionCompletedPayload`, for a run that failed.
    scrubbing_fields_removed: List[str] = Field(default_factory=list)
    pii_patterns_redacted: List[str] = Field(default_factory=list)


class PlanObservedPayload(BaseModel):
    """Payload for ``EventType.PLAN_OBSERVED``. Mirrors
    ``wl-lineage::events::PlanObservedPayload``.

    Bounded by :data:`PLAN_INTENDED_TOOLS_MAX` (count of tool
    names) and :data:`PLAN_RATIONALE_MAX_BYTES` (rationale size).
    Each name in ``intended_tools`` MUST match
    :data:`PLAN_TOOL_NAME_PATTERN`.
    """

    model_config = ConfigDict(extra="forbid")

    intended_tools: List[str] = Field(
        ..., min_length=1, max_length=PLAN_INTENDED_TOOLS_MAX
    )
    plan_kind: PlanKind
    rationale: Optional[str] = None

    @model_validator(mode="after")
    def _validate_tool_names_and_rationale(self) -> "PlanObservedPayload":
        for name in self.intended_tools:
            if not PLAN_TOOL_NAME_RE.match(name):
                raise ValueError(
                    f"intended_tools entry {name!r} does not match "
                    f"{PLAN_TOOL_NAME_PATTERN}"
                )
        if self.rationale is not None:
            encoded = self.rationale.encode("utf-8")
            if len(encoded) > PLAN_RATIONALE_MAX_BYTES:
                raise ValueError(
                    f"rationale is {len(encoded)} bytes (max "
                    f"{PLAN_RATIONALE_MAX_BYTES})"
                )
        return self


# ─── Quarantine payload mirrors ───────────────────────────────────────
#
# These mirror the Rust types in
# ``wl-lineage::events::{FeatureContribution,
# ExecutionQuarantinedPayload, ExecutionResumedPayload}``. When
# wl-apdp returns ``decision: "Quarantine"`` the SDK's
# ``BaseRunHandle`` emits an ``execution_quarantined`` event using
# ``ExecutionQuarantinedPayload`` so the dashboard and audit chain
# carry the same anomaly-attribution context Cedar saw at decision
# time. The dashboard emits ``execution_resumed`` (via wl-apdp's
# Lift endpoint) when an operator lifts the quarantine.


class FeatureContribution(BaseModel):
    """Per-feature contribution to an IF anomaly score. Mirrors
    ``wl-lineage::events::FeatureContribution``.

    Surfaced on ``ExecutionQuarantinedPayload.contributing_features``
    so the dashboard can render "why was the agent quarantined" with
    the top contributors next to baseline percentiles, without a
    follow-up query to wl-drift.
    """

    model_config = ConfigDict(extra="forbid")

    name: str
    value: float
    baseline_median: float
    baseline_p95: float
    contribution: float


class ExecutionQuarantinedPayload(BaseModel):
    """Payload for ``EventType.EXECUTION_QUARANTINED``. Mirrors
    ``wl-lineage::events::ExecutionQuarantinedPayload``.

    Emitted when the plugin's ``BaseRunHandle`` flips to the
    Quarantined state on a wl-apdp ``Quarantine`` decision. Carries
    enough context for the dashboard
    quarantine card to render without a follow-up query.

    Bounded by:

    - ``reason`` length (UTF-8 bytes) ≤ :data:`REASON_MAX_BYTES`
    - ``contributing_features`` count ≤ :data:`MAX_CONTRIBUTING_FEATURES`
    - ``anomaly_score`` and ``threshold`` in the unit interval [0.0, 1.0]
    """

    model_config = ConfigDict(extra="forbid")

    policy_id: str = Field(..., min_length=1)
    anomaly_score: float = Field(..., ge=0.0, le=1.0)
    threshold: float = Field(..., ge=0.0, le=1.0)
    # Optional — a STRUCTURAL Cedar quarantine has no IF model. Mirrors
    # wl-lineage (`Option<Uuid>`, absent on the wire when none); an empty
    # string is not a model version and is rejected here so the SDK never
    # emits the shape wl-apdp used to refuse (422).
    model_version: Optional[str] = None
    # either UUID or str at construction; we type as str because the
    # wire format is JSON and the receiving end stores it as text.
    contributing_features: List[FeatureContribution] = Field(default_factory=list)
    reason: str = Field(..., min_length=1)

    @model_validator(mode="after")
    def _validate_bounded_sizes(self) -> "ExecutionQuarantinedPayload":
        if len(self.contributing_features) > MAX_CONTRIBUTING_FEATURES:
            raise ValueError(
                f"contributing_features has {len(self.contributing_features)} "
                f"entries (max {MAX_CONTRIBUTING_FEATURES})"
            )
        encoded = self.reason.encode("utf-8")
        if len(encoded) > REASON_MAX_BYTES:
            raise ValueError(
                f"reason is {len(encoded)} bytes (max {REASON_MAX_BYTES})"
            )
        if self.model_version is not None and not self.model_version.strip():
            raise ValueError(
                "model_version must be a UUID string or omitted (None) — never empty"
            )
        return self


class ExecutionResumedPayload(BaseModel):
    """Payload for ``EventType.EXECUTION_RESUMED``. Mirrors
    ``wl-lineage::events::ExecutionResumedPayload``.

    Emitted by wl-apdp (via the dashboard Lift endpoint) when
    an operator lifts a quarantine. The SDK re-exports this type so
    plugin authors and dashboard renderers can typecheck the payload
    after fetching audit events.

    Bounded by:

    - ``lift_reason`` length (UTF-8 bytes) ≤ :data:`LIFT_REASON_MAX_BYTES`
    - ``lift_reason`` MUST be non-empty (the dashboard dialog
      requires it; defended at the wire boundary too).
    """

    model_config = ConfigDict(extra="forbid")

    quarantined_event_id: str  # UUID stringified
    lifted_by: str  # operator user UUID stringified
    lift_reason: str = Field(..., min_length=1)
    override_policy_id: Optional[str] = None

    @model_validator(mode="after")
    def _validate_lift_reason_size(self) -> "ExecutionResumedPayload":
        encoded = self.lift_reason.encode("utf-8")
        if len(encoded) > LIFT_REASON_MAX_BYTES:
            raise ValueError(
                f"lift_reason is {len(encoded)} bytes "
                f"(max {LIFT_REASON_MAX_BYTES})"
            )
        return self


# ─── Envelope + composite event ───────────────────────────────────────


# All payload variants in one union. ``ExecutionEvent.payload`` resolves
# the right variant via the ``event_type`` discriminator (handled by
# the model_validator below — pydantic's discriminated-union sugar
# doesn't quite fit because the payload variants share no common
# discriminator FIELD).
PayloadUnion = Union[
    ExecutionStartedPayload,
    ToolCallObservedPayload,
    ApiRequestObservedPayload,
    PolicyDecisionMadePayload,
    AgentSpawnObservedPayload,
    ExecutionCompletedPayload,
    ExecutionFailedPayload,
    PlanObservedPayload,
    ExecutionQuarantinedPayload,
    ExecutionResumedPayload,
]


_EVENT_TYPE_TO_PAYLOAD: Dict[EventType, type] = {
    EventType.EXECUTION_STARTED: ExecutionStartedPayload,
    EventType.TOOL_CALL_OBSERVED: ToolCallObservedPayload,
    EventType.API_REQUEST_OBSERVED: ApiRequestObservedPayload,
    EventType.POLICY_DECISION_MADE: PolicyDecisionMadePayload,
    EventType.AGENT_SPAWN_OBSERVED: AgentSpawnObservedPayload,
    EventType.EXECUTION_COMPLETED: ExecutionCompletedPayload,
    EventType.EXECUTION_FAILED: ExecutionFailedPayload,
    EventType.PLAN_OBSERVED: PlanObservedPayload,
    EventType.EXECUTION_QUARANTINED: ExecutionQuarantinedPayload,
    EventType.EXECUTION_RESUMED: ExecutionResumedPayload,
}


class EventEnvelope(BaseModel):
    """Common envelope fields. Mirrors
    ``wl-lineage::events::EventEnvelope``.

    The required set (event_id, event_type, timestamp,
    execution_id, agent_id) is enforced by pydantic field defaults
    being absent. Optional fields are listed explicitly so the
    closed-set conformance invariant (#7) holds.

    **Deliberately narrower than the Rust struct.** ``EventEnvelope``
    in Rust also carries ``subject``, ``actor_chain``,
    ``entitlements``, ``application_id``, ``workload_ref``, ``signature`` and the
    ``extra`` catch-all. Every one of those is stamped SERVER-side by
    wl-apdp from the verified run credential, or at ingest; none is an
    emitter's to set, and the delegation chain in particular is
    server-derived precisely so it cannot be asserted by the agent it
    describes. Modelling them here would invite a plugin to populate
    them — which conformance invariant 7 rejects anyway. This gap is
    not mirror drift; leave it.
    """

    # Pydantic forbids extra keys by default for this model — the
    # closed-set envelope is part of the contract.
    model_config = ConfigDict(extra="forbid")

    event_id: str = Field(..., pattern=EVENT_ID_PATTERN)
    event_type: EventType
    timestamp: datetime
    execution_id: str
    agent_id: str

    # Optional envelope fields (use when known).
    parent_execution_id: Optional[str] = None
    root_execution_id: Optional[str] = None
    parent_agent_id: Optional[str] = None
    session_id: Optional[str] = None
    request_id: Optional[str] = None
    tenant_id: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


class ExecutionEvent(BaseModel):
    """The canonical wire format. Mirrors
    ``wl-lineage::events::ExecutionEvent``.

    On the wire, the envelope fields are FLATTENED to the top
    level (matching Rust's ``#[serde(flatten)]`` on the
    ``envelope`` field). This pydantic model accepts that flat
    shape natively because the envelope's optional fields and the
    ``payload`` field don't conflict.

    Construct via the typed initializer; serialize via
    ``.model_dump()`` for a dict ready to POST to APDP's
    ``/v1/events`` endpoint.
    """

    # ``allow`` here is deliberate: the model accepts the flattened
    # envelope keys at the top level. The conformance assertion in
    # ``conformance.assert_no_unknown_keys`` is what enforces the
    # closed-set invariant on emitted events — this model is the
    # typed CONSTRUCTOR; the conformance check is the
    # contract-enforcement.
    model_config = ConfigDict(extra="allow")

    event_id: str = Field(..., pattern=EVENT_ID_PATTERN)
    event_type: EventType
    timestamp: datetime
    execution_id: str
    agent_id: str
    payload: Dict[str, Any]

    # Optional envelope fields.
    parent_execution_id: Optional[str] = None
    root_execution_id: Optional[str] = None
    parent_agent_id: Optional[str] = None
    session_id: Optional[str] = None
    request_id: Optional[str] = None
    tenant_id: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None

    @model_validator(mode="after")
    def _validate_payload_matches_event_type(self) -> "ExecutionEvent":
        """Validate ``payload`` against the variant that matches
        ``event_type``. This catches the most common plugin bug:
        emitting a ``tool_call_observed`` event with the wrong
        payload shape."""
        payload_cls = _EVENT_TYPE_TO_PAYLOAD.get(self.event_type)
        if payload_cls is None:
            # Unknown event_type — pydantic's enum validation
            # should have caught it; defensive check.
            raise ValueError(f"unknown event_type: {self.event_type}")
        try:
            payload_cls.model_validate(self.payload)
        except Exception as exc:  # noqa: BLE001
            raise ValueError(
                f"payload does not match {self.event_type.value}: {exc}"
            ) from exc
        return self


# ─── Payload-schema enforcement ───────────────────────────────────────


class PayloadSchemaError(ValueError):
    """A built event's ``payload`` does not match the canonical
    payload struct its ``event_type`` selects.

    This is the shape of bug that takes a whole lineage batch down:
    wl-apdp's ``POST /v1/events`` dispatches the payload on
    ``event_type`` and fails closed (``422 … did not match any variant
    of untagged enum IngestExecutionEventsRequest``) when the payload
    does not deserialize into that struct. A single malformed event
    means NONE of the batch is written, so the whole run silently
    vanishes from the execution-lineage view.

    Raised by :func:`validate_event_payload`, and by
    :func:`payload_model_for` for an event type outside the canonical
    set. Surfaced as conformance invariant 16 by
    :func:`watchlight_core_testing.assert_canonical_event`.
    """


def payload_model_for(event_type: Any) -> type:
    """Return the pydantic payload model for ``event_type``.

    ``event_type`` may be an :class:`EventType` or its wire string.

    Raises:
        PayloadSchemaError: when ``event_type`` is not in the closed
            canonical set (so an invented event type can never slip
            past the schema check unvalidated).
    """
    try:
        resolved = EventType(event_type)
    except ValueError as exc:
        raise PayloadSchemaError(
            f"event_type {event_type!r} is not in the canonical set "
            f"({sorted(e.value for e in EventType)})"
        ) from exc
    model = _EVENT_TYPE_TO_PAYLOAD.get(resolved)
    if model is None:  # pragma: no cover — the map is exhaustive
        raise PayloadSchemaError(
            f"no payload model registered for event_type {resolved.value!r}"
        )
    return model


def validate_event_payload(event_type: Any, payload: Any) -> None:
    """Validate ``payload`` against the canonical struct ``event_type``
    selects — the same dispatch wl-apdp's ``/v1/events`` performs.

    This is the single enforcement point for the DESERIALIZATION
    contract on the Python side. Every plugin's built events flow
    through it via the conformance suite, so a plugin that builds a
    payload the server would reject fails loudly in its own test run
    rather than silently at runtime.

    **Scope: what serde rejects, and nothing else.** Two classes of
    error are deliberately excluded, because each is owned elsewhere and
    neither produces the 422:

    * ``value_error`` — this module's own ``@model_validator`` semantic
      rules (intent-provenance pairing, bounded sizes, plan tool-name
      pattern). Rust keeps those in explicit ``validate()`` methods that
      run separately from ``Deserialize``; on the Python side they are
      conformance invariants 6 and 12 (and #12 has an opt-out hatch this
      check must not bypass).
    * ``extra_forbidden`` — an unknown payload key. Rust's payload
      structs do not set ``deny_unknown_fields``, so serde accepts the
      event and silently DROPS the key. That is a data-loss smell, not a
      rejection; :func:`unknown_payload_keys` reports it separately.

    Raises:
        PayloadSchemaError: when ``payload`` is not a mapping, when
            ``event_type`` is not canonical, or when the payload fails
            structurally — a missing required field, a wrong type, or a
            typed sub-struct in the wrong shape.
    """
    model = payload_model_for(event_type)
    if not isinstance(payload, Mapping):
        raise PayloadSchemaError(
            f"payload for {event_type} must be a mapping, got "
            f"{type(payload).__name__}"
        )
    try:
        model.model_validate(dict(payload))
    except PayloadSchemaError:
        raise
    except Exception as exc:  # noqa: BLE001 — pydantic ValidationError
        errors = getattr(exc, "errors", None)
        if not callable(errors):
            raise PayloadSchemaError(
                f"payload does not match {model.__name__}: {exc}"
            ) from exc
        structural = [
            e
            for e in errors()
            if e.get("type") not in ("value_error", "extra_forbidden")
        ]
        if not structural:
            return
        detail = "; ".join(
            f"{'.'.join(str(p) for p in e.get('loc', ())) or '<root>'}: "
            f"{e.get('msg')} [{e.get('type')}]"
            for e in structural
        )
        raise PayloadSchemaError(
            f"payload does not match {model.__name__}: {detail}"
        ) from exc


def unknown_payload_keys(event_type: Any, payload: Any) -> List[str]:
    """Return the ``payload`` keys the server does not model, sorted.

    Rust's payload structs do not set ``deny_unknown_fields``, so an
    unknown key does NOT reject the event — serde drops it on the floor
    and the value never reaches lineage. Every consumer downstream then
    reads a field that is never there, which is how a "the dashboard
    surfaces this inline" comment stays true-looking for months while
    the value is discarded at the wire.

    Silent data loss on an audit record is not a lesser bug than a
    rejected batch, so :func:`watchlight_core_testing.assert_canonical_event`
    treats a non-empty result as a conformance FAILURE, not a warning.
    """
    model = payload_model_for(event_type)
    if not isinstance(payload, Mapping):
        return []
    known = set(model.model_fields)
    return sorted(str(k) for k in payload.keys() if str(k) not in known)


# ─── Helpers — bounded-size truncation ────────────────────────────────


def truncate_summary(text: Optional[str]) -> Optional[str]:
    """Bound a free-form summary to
    :data:`INPUT_SUMMARY_MAX_CHARS`. Returns None if input is None
    or empty after stripping. Used by all plugins'
    ``tool_call_observed`` emitters.
    """
    if text is None:
        return None
    cleaned = text.strip()
    if not cleaned:
        return None
    if len(cleaned) <= INPUT_SUMMARY_MAX_CHARS:
        return cleaned
    return cleaned[:INPUT_SUMMARY_MAX_CHARS]


def redacted_error_summary(error: Any) -> str:
    """A **value-free** description of an error for a lineage event.

    An exception is described by its class name only; its message can
    carry argument values, response bodies, credentials or personal
    data. A plain string (a framework's error text) is withheld
    entirely. Never returns the message content.
    """
    if error is None:
        return "unknown_error"
    if isinstance(error, BaseException):
        return type(error).__name__
    if isinstance(error, type) and issubclass(error, BaseException):
        return error.__name__
    return "error_detail_withheld"


#: At most this many argument names in :func:`redacted_arg_metadata`.
_MAX_ARG_NAMES_METADATA = 32


def redacted_arg_metadata(tool_args: Any) -> Dict[str, Any]:
    """Return **value-free** metadata describing a tool call's arguments.

    Security: raw tool arguments may carry bearer tokens, API
    keys, or PII. Truncation is NOT redaction — a 200-char prefix can
    still capture a secret. This helper surfaces only the argument
    *shape* — key names, count, and value *types* — and NEVER a value.
    The output is safe to send to wl-apdp as authorize ``context`` and to
    persist on an ``ExecutionEvent``.

    Non-dict args (a bare positional value the framework passed as a
    scalar) surface only their type and count, never the value.
    """
    if isinstance(tool_args, dict):
        names: List[str] = [str(k) for k in tool_args.keys()]
        truncated = len(names) > _MAX_ARG_NAMES_METADATA
        shown = sorted(names)[:_MAX_ARG_NAMES_METADATA]
        meta: Dict[str, Any] = {
            "arg_count": len(names),
            "arg_names": shown,
            "arg_types": {
                str(k): type(v).__name__
                for k, v in list(tool_args.items())[:_MAX_ARG_NAMES_METADATA]
            },
        }
        if truncated:
            meta["arg_names_truncated"] = True
        return meta
    # Non-dict (positional / scalar) — never stringify the value.
    return {"arg_count": 1, "arg_names": [], "arg_type": type(tool_args).__name__}


def redacted_input_summary(args: Any) -> Optional[str]:
    """A bounded, **value-free** ``input_summary`` for a
    ``tool_call_observed`` event.

    Renders ``"<n> args: name(type), name(type), ..."`` for a mapping and
    ``"1 arg: (type)"`` for anything else: argument names and value type
    names only, never a value (a truncated value is not redaction; its
    prefix can still hold a credential or personal data). Bounded to
    :data:`INPUT_SUMMARY_MAX_CHARS`. Returns ``None`` for ``None``.
    """
    if args is None:
        return None
    if isinstance(args, Mapping):
        items = list(args.items())
        parts = [f"{k}({type(v).__name__})" for k, v in items[:32]]
        summary = f"{len(items)} args: " + ", ".join(parts) if parts else "0 args"
    else:
        summary = f"1 arg: ({type(args).__name__})"
    return truncate_summary(summary)


def summarize_arg_keys(args: Any) -> Optional[str]:
    """Sorted, comma-joined argument KEYS of a tool call — never the
    values.

    This is the privacy-safe behavioural feature wl-drift's arg-shape
    scorer consumes. wl-drift builds a per-``(agent, tool)`` distribution
    over the SHAPE of each call (which parameters were supplied, keyed by
    parameter NAME only) and scores divergence from the learned baseline.
    Argument *values* never leave the plugin process — only the set of
    keys, sorted so the summary is order-independent.

    Populates the dedicated ``arg_key_summary`` field on
    :class:`ToolCallObservedPayload` (NOT ``input_summary``, which carries
    a redacted/bounded rendering of the *values* for human/audit display).
    Every SDK emitter and ``wl-proxy``'s MCP translator populate this field
    identically so the two vantages produce comparable distributions.

    Accepts the structured tool arguments as a mapping (the common case:
    a framework callback that exposes ``inputs`` / ``args`` as a dict).
    Returns the sorted keys joined by ``,`` (e.g. ``"format,text"``),
    bounded to :data:`INPUT_SUMMARY_MAX_CHARS`. Returns ``None`` when:

    * ``args`` is not a mapping (no structured keys to summarize — e.g.
      the framework only exposed a positional/string rendering), or
    * the mapping is empty (a no-argument call contributes no shape).
    """
    if not isinstance(args, Mapping):
        return None
    keys = sorted(str(k) for k in args.keys())
    if not keys:
        return None
    return truncate_summary(",".join(keys))


def truncate_error_message(text: Optional[str]) -> Optional[str]:
    """Bound an error message to
    :data:`ERROR_MESSAGE_MAX_CHARS`. Returns None if input is None
    or empty after stripping.
    """
    if text is None:
        return None
    cleaned = text.strip()
    if not cleaned:
        return None
    if len(cleaned) <= ERROR_MESSAGE_MAX_CHARS:
        return cleaned
    return cleaned[:ERROR_MESSAGE_MAX_CHARS]
