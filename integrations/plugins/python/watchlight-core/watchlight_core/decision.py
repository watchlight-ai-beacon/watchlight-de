"""Typed authorization-decision union + :class:`AgentQuarantinedError`.

This module is the SDK's load-bearing type surface. It exists so that:

1.  A Quarantine response from wl-apdp (wire shape: ``decision``
    field ``"Quarantine"`` + ``details.quarantine`` payload) is
    deserialised into a typed :class:`QuarantineDecision` rather than
    a free-form dict that plugin authors have to introspect.
2.  Plugins (and the customer agent code they govern) can raise and
    catch :class:`AgentQuarantinedError` consistently regardless of
    framework.
3.  The :class:`RunHandleState` enum makes the state machine in
    :class:`watchlight_core.BaseRunHandle` observable and testable
    from outside.

The wire contract:

.. code-block:: json

    {
      "decision": "Quarantine",
      "reason": "Agent quarantined by policy ... (anomaly_score=0.910)",
      "details": {
        "quarantine": {
          "reason": "...",
          "anomaly_score": 0.91,
          "contributing_features": [
            {
              "name": "tool_diversity",
              "value": 12.0,
              "baseline_median": 3.0,
              "baseline_p95": 6.0,
              "contribution": 0.42
            }
          ],
          "model_version": "uuid-or-null",
          "policy_id": "forbid-quarantined-agent-all-actions"
        }
      }
    }

The SDK does the typing on the client side because wl-apdp's
``AuthorizationResponse`` (deliberately) keeps ``details`` as a
free-form ``serde_json::Value`` so the payload shape can evolve
without forcing a wl-apdp release on every plugin tweak.

Compat note — the Quarantine decision is a newer addition. Customer
agent code that catches plugin authorize results today MUST now also
handle :class:`AgentQuarantinedError` (or call
``handle.authorize_action_detailed()`` and branch on
``result.kind == "quarantine"``). This is a breaking change for
older integrations.
"""

from __future__ import annotations

from enum import Enum
from typing import Annotated, Any, Dict, List, Literal, Optional, Tuple, Union

from pydantic import BaseModel, ConfigDict, Field

from .events_schema import (
    MAX_CONTRIBUTING_FEATURES,
    FeatureContribution,
)

__all__ = [
    "RunHandleState",
    "Escalation",
    "Observation",
    "Attenuation",
    "AllowDecision",
    "DenyDecision",
    "NeedsApprovalDecision",
    "QuarantineDecision",
    "TerminateDecision",
    "SeverSubtreeDecision",
    "RevokeDecision",
    "AuthorizationDecision",
    "AgentQuarantinedError",
    "ExecutionTerminatedError",
    "SubtreeSeveredError",
    "AgentRevokedError",
    "parse_authorization_decision",
]


# ─── Run-handle state machine ────────────────────────────────────────


class RunHandleState(str, Enum):
    """Lifecycle states for :class:`watchlight_core.BaseRunHandle`.

    The state machine is intentionally narrow:

    - ``ACTIVE`` — normal operation, ``authorize_action`` round-trips
      to wl-apdp.
    - ``QUARANTINED`` — wl-apdp returned ``Quarantine`` (or a parent
      handle propagated quarantine down via ``spawn_subagent``).
      Every ``authorize_action`` / ``spawn_subagent`` call SHORT-
      CIRCUITS — it raises :class:`AgentQuarantinedError`
      immediately, WITHOUT round-tripping to wl-apdp. Recovery is
      operator-driven via the Lift quarantine dashboard endpoint;
      the SDK has no in-process recovery path.
    - ``COMPLETED`` — the handle has been closed via ``complete()``
      or ``terminate()``. Calls on a completed handle are idempotent
      no-ops.
    - ``SEVERED`` — wl-apdp returned ``SeverSubtree`` and this handle
      is a node in the collapsed sub-agent spawn tree (the root that
      received the decision, OR a descendant severed transitively by
      the depth-first walk). Like ``COMPLETED`` this is a TERMINAL
      state — every ``authorize_action`` / ``spawn_subagent`` short-
      circuits — but it is DISTINCT from ``COMPLETED`` so audit/replay
      can tell a policy-driven multi-agent containment collapse apart
      from a natural close. Severing is NOT quarantine: there is NO
      durable agent-bag and a fresh ``start_run`` afterward is clean.

    State transitions:

    ::

        ACTIVE ─── quarantine ─────▶ QUARANTINED
           │                              │
           ├── complete/terminate ────────┴──▶ COMPLETED
           │
           └── sever_subtree (self or ancestor) ──▶ SEVERED
    """

    ACTIVE = "active"
    QUARANTINED = "quarantined"
    COMPLETED = "completed"
    SEVERED = "severed"


# ─── Side-effect axis: Escalate ──────────────────────────────────────


class Escalation(BaseModel):
    """A single side-effect-class escalation raised on an authorize call
    — the SDK-visible projection of one ``Escalate`` enforcement effect
    (``@enforcement_effect("escalate")``).

    Escalate is on the SIDE-EFFECT axis of the two-axis enforcement
    model: it raises a high-priority
    SOC/HITL alert ALONGSIDE the decision WITHOUT changing it. A Deny
    stays a Deny, a Quarantine stays a Quarantine — the escalation is
    additive, NON-throwing metadata surfaced here (and via the run
    handle's observability). There is deliberately NO ``EscalatedError``.
    """

    model_config = ConfigDict(extra="ignore")

    #: Cedar policy id of the forbid that carried the escalate effect.
    policy_id: Optional[str] = None
    #: Operator-readable justification for the escalation.
    reason: str = ""


class Observation(BaseModel):
    """A single allow-downgrade-class observation recorded on an authorize
    call — the SDK-visible projection of one ``Observe`` enforcement effect
    (``@enforcement_effect("observe")``).

    Observe is on the ALLOW-DOWNGRADE axis: when it is the SOLE reason a
    Cedar Deny was reached, wl-apdp DOWNGRADES the decision to ``Allow``
    (monitor / shadow mode — the action proceeds) and records this "this
    policy WOULD have denied" signal. Crucially the observation is ALSO
    recorded when a co-occurring HARD forbid kept the deny (the fail-closed
    invariant: observe never rescues a real deny, but the monitor signal is
    never lost). It is additive, NON-throwing metadata surfaced here (and
    via the run handle's observability). There is deliberately NO terminal
    error.
    """

    model_config = ConfigDict(extra="ignore")

    #: Cedar policy id of the forbid that carried the observe effect.
    policy_id: Optional[str] = None
    #: Operator-readable justification for the observation.
    reason: str = ""


class Attenuation(BaseModel):
    """A single allow-downgrade-class attenuation recorded on an authorize
    call — the SDK-visible projection of one ``Attenuate`` enforcement
    effect (``@enforcement_effect("attenuate")``).

    Attenuate is on the ALLOW-DOWNGRADE axis: when it is the SOLE reason a
    Cedar Deny was reached, wl-apdp DOWNGRADES the decision to ``Allow``
    (the action proceeds) AND durably NARROWS the run's sub-agent RunHandle
    scope to a strict subset for the rest of the execution. Every
    SUBSEQUENT authorize is then enforced against the tighter grant by the
    server-side membership check — the SDK does not need to re-enforce it
    locally.

    Like an :class:`Observation`, an attenuation is ALSO recorded when a
    co-occurring HARD forbid kept the deny (the fail-closed invariant:
    attenuate never rescues a real deny). ``narrowed`` distinguishes a
    successful narrowing (``True`` — the run's authority was tightened)
    from a fail-closed attenuation (``False`` — no run handle to narrow, no
    parseable target, or the narrowed scope would not be a strict subset;
    the forbid then stayed a real deny). It is additive, NON-throwing
    metadata surfaced here (and via the run handle's observability). There
    is deliberately NO terminal error.
    """

    model_config = ConfigDict(extra="ignore")

    #: Cedar policy id of the forbid that carried the attenuate effect.
    policy_id: Optional[str] = None
    #: Operator-readable justification for the attenuation.
    reason: str = ""
    #: ``True`` iff the run's granted scope was actually narrowed (a strict
    #: subset applied). ``False`` on a fail-closed attenuation (no handle /
    #: no target / not a strict subset) — the forbid then stayed a real deny.
    narrowed: bool = False
    #: The number of descendant RunHandles re-narrowed or invalidated by the
    #: cascade. ``0`` when the narrowing failed or the run had no descendants.
    descendants_affected: int = 0


class _EscalationCarrier(BaseModel):
    """Mixin adding the additive side-effect-axis ``escalations`` and
    allow-downgrade-axis ``observations`` fields to every decision variant.
    Both Escalate and Observe are orthogonal to the decision, so ALL
    variants may carry them additively (present regardless of which variant
    the decision axis resolved). Empty in the common case; NON-throwing.
    """

    #: Side-effect-axis escalations raised on this authorize call. Empty
    #: when no escalation fired; NEVER changes the decision variant.
    escalations: Tuple[Escalation, ...] = ()
    #: Allow-downgrade-axis observations recorded on this authorize call.
    #: Empty when no observe forbid matched; NEVER changes the decision
    #: variant. Present even when a co-occurring hard forbid kept the deny.
    observations: Tuple[Observation, ...] = ()
    #: Allow-downgrade-axis attenuations recorded on this authorize call.
    #: Empty when no attenuate forbid matched; NEVER changes the decision
    #: variant. Present even when a co-occurring hard forbid kept the deny
    #: (the narrowing still happened) or when the attenuation failed
    #: fail-closed (``narrowed=False``, surfaced for attribution).
    attenuations: Tuple[Attenuation, ...] = ()


# ─── Discriminated-union decision model ──────────────────────────────


class AllowDecision(_EscalationCarrier):
    """The action is permitted. Mirrors wl-apdp's ``"Allow"``."""

    model_config = ConfigDict(extra="forbid")

    kind: Literal["allow"] = "allow"
    reason: Optional[str] = None


class DenyDecision(_EscalationCarrier):
    """The action is denied. Mirrors wl-apdp's ``"Deny"`` (without an
    approval-request id).
    """

    model_config = ConfigDict(extra="forbid")

    kind: Literal["deny"] = "deny"
    reason: Optional[str] = None


class NeedsApprovalDecision(_EscalationCarrier):
    """Human approval is required before the action can proceed.

    Mirrors wl-apdp's ``"Deny"`` + ``details.escalation_required`` +
    ``details.approval_request_id``. The SDK collapses this case into
    a distinct variant so plugin authors can branch on it explicitly.
    """

    model_config = ConfigDict(extra="forbid")

    kind: Literal["needs_approval"] = "needs_approval"
    approval_request_id: str
    reason: Optional[str] = None


class QuarantineDecision(_EscalationCarrier):
    """The agent has been quarantined — every subsequent action is
    denied without wl-apdp round-trip until an operator lifts the
    quarantine.

    Mirrors wl-apdp's ``"Quarantine"`` decision (wire format).
    Carries enough context that the plugin can:

    - Construct :class:`AgentQuarantinedError` with the full anomaly
      attribution (operators reading the audit trail can replay why
      the agent was quarantined without a follow-up query).
    - Emit ``execution_quarantined`` with the same payload
      shape the dashboard expects.
    """

    model_config = ConfigDict(extra="forbid")

    kind: Literal["quarantine"] = "quarantine"
    reason: str = Field(..., min_length=1)
    anomaly_score: float = Field(..., ge=0.0, le=1.0)
    contributing_features: List[FeatureContribution] = Field(default_factory=list)
    model_version: Optional[str] = None
    policy_id: str = Field(..., min_length=1)


class TerminateDecision(_EscalationCarrier):
    """The current run/execution is terminated by a policy-driven
    ``Terminate`` enforcement effect.

    Mirrors wl-apdp's ``"Terminate"`` decision (a halt/contain
    enforcement effect).
    Terminate ends the CURRENT run — the in-flight LLM call is aborted
    via the kill signal (``reason=policy_terminate``) and the session
    is closed — but, unlike Quarantine, the agent is **not** bagged:
    there is NO durable quarantine state, the RunHandle transitions
    toward ``COMPLETED`` (not ``QUARANTINED``), and a fresh
    ``start_run`` afterward is clean.

    The wire shape carries the enforcement block rather than a
    quarantine block:

    .. code-block:: json

        {
          "decision": "Terminate",
          "reason": "Execution terminated by policy ...",
          "details": {
            "enforcement": {
              "effect": "terminate",
              "severity": 1,
              "reason": "policy_terminate",
              "lift_required": false,
              "policy_id": "forbid-... "
            }
          }
        }

    Only the ``reason`` and ``policy_id`` are load-bearing for the SDK
    outcome (:class:`ExecutionTerminatedError`); the ``severity`` /
    ``lift_required`` fields are consumed by dashboard / audit
    surfaces and do not change the SDK's terminal transition.
    """

    model_config = ConfigDict(extra="forbid")

    kind: Literal["terminate"] = "terminate"
    reason: str = Field(default="Execution terminated")
    policy_id: Optional[str] = None


class SeverSubtreeDecision(_EscalationCarrier):
    """The sub-agent spawn TREE rooted at this agent is severed by a
    policy-driven ``SeverSubtree`` enforcement effect — multi-agent
    containment.

    Mirrors wl-apdp's ``"SeverSubtree"`` decision (a halt/contain
    enforcement effect).
    SeverSubtree is the THIRD rung of the halt/contain severity ladder
    (ordinal 3 — above Quarantine): it collapses the whole in-process
    RunHandle tree, not one run. On receiving it, the SDK transitively
    severs the current RunHandle AND every descendant it spawned (depth-
    first over the child registry), aborting each descendant's in-
    flight LLM call via the kill signal (``reason=sever_subtree``) and
    driving each to the terminal ``SEVERED`` state.

    Like Terminate — and UNLIKE Quarantine — the agent is **not**
    bagged: there is NO durable state, and a fresh ``start_run``
    re-spawns a clean tree. wl-apdp performs zero durable writes
    (CQRS-neutral) and does NOT itself hold the runtime spawn tree —
    it emits only the decision + a structured governance/audit event;
    the tree traversal + kill is SDK-owned.

    The wire shape carries the enforcement block:

    .. code-block:: json

        {
          "decision": "SeverSubtree",
          "reason": "Sub-agent spawn tree severed by policy ...",
          "details": {
            "enforcement": {
              "effect": "sever_subtree",
              "severity": 3,
              "reason": "sever_subtree",
              "lift_required": false,
              "policy_id": "forbid-... "
            }
          }
        }

    Only ``reason`` and ``policy_id`` are load-bearing for the SDK
    outcome (:class:`SubtreeSeveredError`); ``severity`` /
    ``lift_required`` are consumed by dashboard / audit surfaces.
    """

    model_config = ConfigDict(extra="forbid")

    kind: Literal["sever_subtree"] = "sever_subtree"
    reason: str = Field(default="Subtree severed")
    policy_id: Optional[str] = None


class RevokeDecision(_EscalationCarrier):
    """The agent's identity TRUST is revoked by a policy-driven
    ``Revoke`` enforcement effect — the terminal, most-severe verb on
    the halt/contain severity ladder (ordinal 4).

    Mirrors wl-apdp's ``"Revoke"`` decision (a halt/contain
    enforcement effect).
    On receiving it, the SDK ends the current run — the in-flight LLM
    call is aborted via the kill signal (``reason=revoke``) — and
    surfaces :class:`AgentRevokedError`.

    **Durable + CQRS.** UNLIKE Terminate / SeverSubtree (ephemeral) and
    Quarantine (durable in wl-apdp's anomaly store), a Revoke's durable
    state lives in **wl-registry** (`identity.agents.trust_state`), which
    it is the sole writer of. wl-apdp EMITS an ``agent.trust.revoke``
    event; wl-registry sets ``trust_state=Revoked``. Thereafter EVERY
    subsequent authorize for the agent is denied by wl-apdp's pre-Cedar
    trust gate — across every goal, across process restarts — until an
    operator explicitly re-trusts. The SDK therefore needs **no durable
    local state**: the deny is enforced server-side by the durable trust
    store, so a revoked agent stays denied even after the plugin process
    restarts. ``lift_required`` is ``true`` (operator re-trust only).

    The wire shape carries the enforcement block:

    .. code-block:: json

        {
          "decision": "Revoke",
          "reason": "Agent trust revoked by policy ...",
          "details": {
            "enforcement": {
              "effect": "revoke",
              "severity": 4,
              "reason": "revoke",
              "lift_required": true,
              "policy_id": "forbid-... "
            }
          }
        }

    Only ``reason`` and ``policy_id`` are load-bearing for the SDK
    outcome (:class:`AgentRevokedError`); ``severity`` / ``lift_required``
    are consumed by dashboard / audit surfaces.
    """

    model_config = ConfigDict(extra="forbid")

    kind: Literal["revoke"] = "revoke"
    reason: str = Field(default="Agent trust revoked")
    policy_id: Optional[str] = None


#: Discriminated-union of the seven authorization-decision variants.
#: Pydantic v2 picks the right variant from the ``kind`` field.
AuthorizationDecision = Annotated[
    Union[
        AllowDecision,
        DenyDecision,
        NeedsApprovalDecision,
        QuarantineDecision,
        TerminateDecision,
        SeverSubtreeDecision,
        RevokeDecision,
    ],
    Field(discriminator="kind"),
]


# ─── Wire-format parser ──────────────────────────────────────────────


def parse_authorization_decision(
    payload: Dict[str, Any],
) -> Union[
    AllowDecision,
    DenyDecision,
    NeedsApprovalDecision,
    QuarantineDecision,
    TerminateDecision,
    SeverSubtreeDecision,
    RevokeDecision,
]:
    """Parse a wl-apdp ``/v1/authorize`` response into a typed decision.

    Tolerates the three legacy shapes wl-apdp has emitted historically
    (Allow / Deny / needs_approval), the Quarantine shape, and
    the enforcement-effect Terminate shape.

    Decision precedence (the same wl-apdp would apply):

    1.  ``decision`` field == ``"Quarantine"`` (case-insensitive)
        → :class:`QuarantineDecision`. Reads from
        ``details.quarantine`` for the typed payload; falls back to
        top-level fields if the legacy shape is in use.
    2.  ``decision`` field == ``"Terminate"`` (case-insensitive)
        → :class:`TerminateDecision`. Reads ``policy_id`` from
        ``details.enforcement`` (where ``effect == "terminate"``) and
        ``reason`` from the top-level ``reason`` field.
    3.  ``decision`` field == ``"SeverSubtree"`` (case-insensitive)
        → :class:`SeverSubtreeDecision`. Reads ``policy_id`` from
        ``details.enforcement`` (where ``effect == "sever_subtree"``)
        and ``reason`` from the top-level ``reason`` field.
    4.  ``decision`` == ``"Deny"`` + ``details.escalation_required``
        + ``details.approval_request_id`` →
        :class:`NeedsApprovalDecision`.
    5.  ``decision`` == ``"Allow"`` → :class:`AllowDecision`.
    6.  Anything else → :class:`DenyDecision` (fail-closed —
        unknown decisions are treated as Deny, never silently allowed).

    The Terminate path — like Quarantine — is NEVER reached unless
    wl-apdp explicitly emits ``decision: "Terminate"`` (which it only
    does when a Cedar policy carrying
    ``@enforcement_effect("terminate")`` determines the decision). We
    do NOT promote a Deny + ``details.enforcement`` to Terminate; the
    top-level ``decision`` discriminator is authoritative and a
    misconfigured wl-apdp cannot accidentally trip the kill signal.

    The Quarantine path is NEVER reached unless wl-apdp explicitly
    emits ``decision: "Quarantine"`` — which it only does when a
    Cedar forbid policy on the quarantine signature matches. We
    do NOT promote a Deny + ``details.quarantine`` to Quarantine
    (that would let a misconfigured wl-apdp accidentally trip the
    kill switch).

    Raises :class:`pydantic.ValidationError` if the Quarantine
    payload is malformed (missing required fields, anomaly_score
    outside [0, 1], etc.). Plugins should treat a malformed
    Quarantine response as a transport failure and fail closed —
    they MUST NOT silently downgrade it to a plain Deny, because
    that would let an attacker who can corrupt the response payload
    bypass the kill switch.

    **Side-effect axis (Escalate).** Independently of the decision
    variant, ``details.enforcement.escalations`` is read and attached to
    the returned decision's ``escalations`` field (additive, NON-
    throwing). It NEVER changes which variant is returned — an Escalate
    fires alongside a Deny / Quarantine / etc. without altering it.
    """
    decision = _resolve_decision_variant(payload)
    escalations = _parse_escalations(payload)
    if escalations:
        # ``escalations`` is a declared field on every variant (via the
        # ``_EscalationCarrier`` mixin), so this is a plain attribute set
        # — the decision variant is untouched.
        decision.escalations = escalations
    observations = _parse_observations(payload)
    if observations:
        # ``observations`` (allow-downgrade axis) is likewise a declared
        # field on every variant. Attached additively — NON-throwing, and
        # NEVER changes which variant was resolved. Present even when a
        # co-occurring hard forbid kept the deny (fail-closed invariant).
        decision.observations = observations
    attenuations = _parse_attenuations(payload)
    if attenuations:
        # ``attenuations`` (allow-downgrade axis) is likewise a declared
        # field on every variant. Attached additively — NON-throwing, and
        # NEVER changes which variant was resolved. Present even when the
        # attenuation failed fail-closed (``narrowed=False``) or a
        # co-occurring hard forbid kept the deny.
        decision.attenuations = attenuations
    return decision


def _parse_escalations(payload: Dict[str, Any]) -> Tuple[Escalation, ...]:
    """Extract side-effect-axis escalations from
    ``details.enforcement.escalations``. Returns an empty tuple
    when none fired (the common case). Fail-safe: malformed entries are
    skipped, never raise.
    """
    details = payload.get("details") or {}
    if not isinstance(details, dict):
        return ()
    enforcement = details.get("enforcement") or {}
    if not isinstance(enforcement, dict):
        return ()
    raw = enforcement.get("escalations")
    if not isinstance(raw, list) or not raw:
        return ()
    escalations = []
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        try:
            escalations.append(Escalation.model_validate(entry))
        except Exception:  # noqa: BLE001 — fail-safe: skip malformed entry
            continue
    return tuple(escalations)


def _parse_observations(payload: Dict[str, Any]) -> Tuple[Observation, ...]:
    """Extract allow-downgrade-axis observations from
    ``details.enforcement.observations``. Returns an empty tuple
    when none matched (the common case). Fail-safe: malformed entries are
    skipped, never raise.
    """
    details = payload.get("details") or {}
    if not isinstance(details, dict):
        return ()
    enforcement = details.get("enforcement") or {}
    if not isinstance(enforcement, dict):
        return ()
    raw = enforcement.get("observations")
    if not isinstance(raw, list) or not raw:
        return ()
    observations = []
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        try:
            observations.append(Observation.model_validate(entry))
        except Exception:  # noqa: BLE001 — fail-safe: skip malformed entry
            continue
    return tuple(observations)


def _parse_attenuations(payload: Dict[str, Any]) -> Tuple[Attenuation, ...]:
    """Extract allow-downgrade-axis attenuations from
    ``details.enforcement.attenuations``. Returns an empty tuple
    when none matched (the common case). Fail-safe: malformed entries are
    skipped, never raise.
    """
    details = payload.get("details") or {}
    if not isinstance(details, dict):
        return ()
    enforcement = details.get("enforcement") or {}
    if not isinstance(enforcement, dict):
        return ()
    raw = enforcement.get("attenuations")
    if not isinstance(raw, list) or not raw:
        return ()
    attenuations = []
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        try:
            attenuations.append(Attenuation.model_validate(entry))
        except Exception:  # noqa: BLE001 — fail-safe: skip malformed entry
            continue
    return tuple(attenuations)


def _resolve_decision_variant(
    payload: Dict[str, Any],
) -> Union[
    AllowDecision,
    DenyDecision,
    NeedsApprovalDecision,
    QuarantineDecision,
    TerminateDecision,
    SeverSubtreeDecision,
    RevokeDecision,
]:
    """Resolve the decision-axis variant. The side-effect-axis
    escalations are attached separately by
    :func:`parse_authorization_decision`, so this stays a pure decision
    resolver — byte-identical to the pre-two-axis behaviour.
    """
    decision_str = (payload.get("decision") or "").strip()
    decision_lower = decision_str.lower()
    reason = payload.get("reason") or ""
    details = payload.get("details") or {}
    if not isinstance(details, dict):
        details = {}

    # ── Quarantine ──
    if decision_lower == "quarantine":
        q = details.get("quarantine") or {}
        if not isinstance(q, dict):
            q = {}
        # Defensive: tolerate the legacy "top-level" shape where the
        # quarantine fields were flattened onto details (early wire
        # drafts). Pull from details directly if the nested
        # quarantine block is empty.
        if not q and "anomaly_score" in details:
            q = {
                "reason": details.get("reason") or reason,
                "anomaly_score": details.get("anomaly_score"),
                "contributing_features": details.get("contributing_features") or [],
                "model_version": details.get("model_version"),
                "policy_id": details.get("policy_id"),
            }
        # Pydantic does the heavy lifting (anomaly_score range,
        # contributing_features count, reason length, policy_id
        # non-empty). A malformed payload raises ValidationError,
        # which plugin code MUST catch as fail-closed.
        return QuarantineDecision(
            reason=q.get("reason") or reason or "Agent quarantined",
            anomaly_score=float(q.get("anomaly_score") or 0.0),
            contributing_features=[
                FeatureContribution.model_validate(fc)
                for fc in (q.get("contributing_features") or [])
            ],
            model_version=q.get("model_version"),
            policy_id=q.get("policy_id") or "",
        )

    # ── Terminate (enforcement-effect wire) ──
    if decision_lower == "terminate":
        enforcement = details.get("enforcement") or {}
        if not isinstance(enforcement, dict):
            enforcement = {}
        # ``policy_id`` lives in the enforcement block; the
        # determining-policy id may also be surfaced at the top level
        # as ``determining_policy_id`` on some wire drafts — prefer the
        # enforcement block (the effect's own carrier) and fall back to
        # the top-level id. Only trust ``enforcement`` when it is
        # actually a terminate effect; otherwise leave ``policy_id``
        # unset rather than mis-attributing a different effect's id.
        effect = enforcement.get("effect")
        policy_id: Optional[str] = None
        if effect == "terminate":
            policy_id = enforcement.get("policy_id")
        if not policy_id:
            top_pid = payload.get("determining_policy_id")
            policy_id = top_pid if isinstance(top_pid, str) and top_pid else None
        return TerminateDecision(
            reason=reason or "Execution terminated",
            policy_id=policy_id,
        )

    # ── SeverSubtree (enforcement-effect wire) ──
    #
    # Never reached unless wl-apdp explicitly emits
    # ``decision: "SeverSubtree"`` (only when a Cedar forbid carrying
    # ``@enforcement_effect("sever_subtree")`` determines the decision).
    # We do NOT promote a Deny + ``details.enforcement`` to
    # SeverSubtree — the top-level ``decision`` discriminator is
    # authoritative, so a misconfigured wl-apdp cannot accidentally
    # collapse a spawn tree.
    #
    # wl-apdp emits the CamelCase decision string ``"SeverSubtree"``
    # (mirroring ``"Terminate"`` / ``"Quarantine"``); lowercased that is
    # ``"seversubtree"`` (no underscore). Accept the snake_case form too
    # for robustness against any wire draft that emits it.
    if decision_lower in ("seversubtree", "sever_subtree"):
        enforcement = details.get("enforcement") or {}
        if not isinstance(enforcement, dict):
            enforcement = {}
        # Only trust ``enforcement`` when it is actually a sever_subtree
        # effect; otherwise leave ``policy_id`` unset rather than
        # mis-attributing a different effect's id.
        effect = enforcement.get("effect")
        sever_policy_id: Optional[str] = None
        if effect == "sever_subtree":
            sever_policy_id = enforcement.get("policy_id")
        if not sever_policy_id:
            top_pid = payload.get("determining_policy_id")
            sever_policy_id = top_pid if isinstance(top_pid, str) and top_pid else None
        return SeverSubtreeDecision(
            reason=reason or "Subtree severed",
            policy_id=sever_policy_id,
        )

    # ── Revoke (enforcement-effect wire) ──
    #
    # Never reached unless wl-apdp explicitly emits ``decision:
    # "Revoke"`` (only when a Cedar forbid carrying
    # ``@enforcement_effect("revoke")`` determines the decision). We do
    # NOT promote a Deny + ``details.enforcement`` to Revoke — the
    # top-level ``decision`` discriminator is authoritative, so a
    # misconfigured wl-apdp cannot accidentally withdraw an agent's
    # identity trust.
    if decision_lower == "revoke":
        enforcement = details.get("enforcement") or {}
        if not isinstance(enforcement, dict):
            enforcement = {}
        # Only trust ``enforcement`` when it is actually a revoke effect;
        # otherwise leave ``policy_id`` unset rather than mis-attributing
        # a different effect's id.
        effect = enforcement.get("effect")
        revoke_policy_id: Optional[str] = None
        if effect == "revoke":
            revoke_policy_id = enforcement.get("policy_id")
        if not revoke_policy_id:
            top_pid = payload.get("determining_policy_id")
            revoke_policy_id = top_pid if isinstance(top_pid, str) and top_pid else None
        return RevokeDecision(
            reason=reason or "Agent trust revoked",
            policy_id=revoke_policy_id,
        )

    # ── NeedsApproval (Deny + escalation_required + approval_request_id) ──
    escalation_required = bool(details.get("escalation_required"))
    approval_request_id = details.get("approval_request_id")
    if (
        decision_lower == "deny"
        and escalation_required
        and isinstance(approval_request_id, str)
        and approval_request_id
    ):
        return NeedsApprovalDecision(
            approval_request_id=approval_request_id,
            reason=reason or None,
        )

    # ── Allow ──
    if decision_lower == "allow":
        return AllowDecision(reason=reason or None)

    # ── Deny (incl. fail-closed for unknown decisions) ──
    return DenyDecision(reason=reason or None)


# ─── Typed error ─────────────────────────────────────────────────────


class AgentQuarantinedError(Exception):
    """Raised when ``authorize_action`` (or ``spawn_subagent``) is
    called on a quarantined run handle, or when wl-apdp returns a
    Quarantine decision in response to ``authorize_action``.

    Carries the full anomaly attribution so the customer's
    framework can surface a meaningful operator message and so the
    audit trail captures the contributors that drove the quarantine.

    Customer agent code should catch this and surface to its
    orchestrator (or let it propagate — the right behaviour is
    almost always to fail the in-flight run). The handle is terminal
    until the parent or operator lifts the quarantine via the
    dashboard; there is no in-process recovery path.

    Attributes:
        reason: Operator-readable summary (bounded to
            :data:`REASON_MAX_BYTES`).
        anomaly_score: IF anomaly score in [0.0, 1.0] that triggered
            the quarantine.
        contributing_features: Top-N (max
            :data:`MAX_CONTRIBUTING_FEATURES`) features that drove
            the score.
        model_version: IF model UUID (stringified) or None.
        policy_id: Cedar policy id of the forbid that fired.
    """

    def __init__(
        self,
        reason: str,
        anomaly_score: float,
        contributing_features: List[FeatureContribution],
        model_version: Optional[str],
        policy_id: str,
    ) -> None:
        # Truthful invariant: we trust the caller to have validated
        # via QuarantineDecision (which uses the same bounds). Do
        # NOT re-validate here — the goal of this constructor is to
        # be cheap and unconditional so it's safe to call from the
        # short-circuit code path.
        self.reason = reason
        self.anomaly_score = anomaly_score
        self.contributing_features = list(contributing_features)
        self.model_version = model_version
        self.policy_id = policy_id
        super().__init__(self._format_message())

    def _format_message(self) -> str:
        """Opaque message: no server reason, policy id or anomaly
        detail (it can reach the model through a framework's
        tool-error path). Those stay on the attributes for operator
        code, and in the server's audit trail."""
        return "Agent quarantined by Watchlight policy; all further actions are refused."

    @classmethod
    def from_decision(cls, decision: QuarantineDecision) -> "AgentQuarantinedError":
        """Construct from a parsed :class:`QuarantineDecision`. Used by
        :class:`watchlight_core.BaseRunHandle` on the quarantine
        transition.
        """
        return cls(
            reason=decision.reason,
            anomaly_score=decision.anomaly_score,
            contributing_features=decision.contributing_features,
            model_version=decision.model_version,
            policy_id=decision.policy_id,
        )


class ExecutionTerminatedError(Exception):
    """Raised when wl-apdp returns a ``Terminate`` enforcement effect in
    response to ``authorize_action`` — the current run/execution is
    ended immediately.

    Terminate is the second rung of the halt/contain severity ladder:
    it ends the CURRENT execution and aborts the in-flight LLM call via
    the kill signal (``reason=policy_terminate``), but — CRITICALLY —
    it does NOT bag the agent. Unlike :class:`AgentQuarantinedError`:

    - There is NO durable quarantine state; the handle transitions
      toward ``COMPLETED``, not ``QUARANTINED``.
    - There is no cross-execution short-circuit; a fresh ``start_run``
      after a Terminate is clean.
    - No parent-chain propagation; Terminate is scoped to the current
      run only.

    **Error-hierarchy contract.** This mirrors
    :class:`AgentQuarantinedError`, which subclasses :class:`Exception`
    directly and is the deny-class signal for the Quarantine effect in
    this lane (there is no shared ``AuthorizationDenied`` base class in
    the Python lane — the deny path returns a typed
    :class:`watchlight_core.results.AuthorizeResult` rather than
    raising, so the only exception-raising deny-class signals are these
    typed effect errors). ``ExecutionTerminatedError`` therefore also
    subclasses :class:`Exception` directly so that a generic
    ``except Exception`` handler (the pattern customer agent code and
    the SDK's own tests use to catch the quarantine / terminate raise)
    catches it, while an effect-aware handler can
    ``except ExecutionTerminatedError`` to react precisely to a
    Terminate versus a Quarantine.

    Customer agent code should catch this and surface the terminal run
    to its orchestrator (or let it propagate — failing the in-flight
    run is almost always correct). Because the agent is not bagged, the
    orchestrator MAY start a fresh run afterward.

    Attributes:
        reason: Operator-readable summary (bounded to
            :data:`REASON_MAX_BYTES`).
        policy_id: Cedar policy id of the ``@enforcement_effect("terminate")``
            policy that fired, or ``None`` if wl-apdp did not surface
            one.
    """

    def __init__(
        self,
        reason: str,
        policy_id: Optional[str] = None,
    ) -> None:
        # Truthful invariant: we trust the caller to have validated via
        # TerminateDecision. Keep the constructor cheap and
        # unconditional so it's safe to call from the terminate code
        # path (mirrors AgentQuarantinedError.__init__).
        self.reason = reason
        self.policy_id = policy_id
        super().__init__(self._format_message())

    def _format_message(self) -> str:
        """Opaque message: no server reason, policy id or anomaly
        detail (it can reach the model through a framework's
        tool-error path). Those stay on the attributes for operator
        code, and in the server's audit trail."""
        return "Execution terminated by Watchlight policy."

    @classmethod
    def from_decision(
        cls, decision: "TerminateDecision"
    ) -> "ExecutionTerminatedError":
        """Construct from a parsed :class:`TerminateDecision`. Used by
        :class:`watchlight_core.BaseRunHandle` on the terminate
        transition.
        """
        return cls(
            reason=decision.reason,
            policy_id=decision.policy_id,
        )


class SubtreeSeveredError(Exception):
    """Raised when wl-apdp returns a ``SeverSubtree`` enforcement effect
    in response to ``authorize_action`` — the sub-agent spawn TREE
    rooted at this agent is collapsed (multi-agent containment).

    SeverSubtree is the THIRD rung of the halt/contain severity ladder
    (ordinal 3 — above Quarantine). On
    the raise, the RunHandle has already transitively severed itself AND
    every descendant it spawned (depth-first over the child
    registry), aborting each descendant's in-flight LLM call via the
    kill signal (``reason=sever_subtree``) and driving each to the
    terminal ``SEVERED`` state.

    Like :class:`ExecutionTerminatedError` — and UNLIKE
    :class:`AgentQuarantinedError` — the agent is **not** bagged:

    - There is NO durable quarantine state; the severed handles
      transition to ``SEVERED`` (a terminal state), NOT ``QUARANTINED``.
    - There is no cross-execution short-circuit; a fresh ``start_run``
      re-spawns a clean tree.
    - Propagation is DOWN the spawn tree (to descendants), NOT up to
      the parent — the offending agent's subtree is contained, its
      ancestors are untouched.

    **Fail-closed containment.** If the RunHandle cannot enumerate a
    descendant (a dead/garbage-collected weak child ref), it still
    severs everything it CAN reach and surfaces the gap on
    :attr:`unreachable_descendants` (a count) — it must NEVER silently
    under-collapse and leave a compromised descendant alive.

    **Error-hierarchy contract.** Mirrors
    :class:`AgentQuarantinedError` / :class:`ExecutionTerminatedError`,
    which subclass :class:`Exception` directly (there is no shared
    ``AuthorizationDenied`` base in the Python lane). ``SubtreeSeveredError``
    also subclasses :class:`Exception` directly so a generic
    ``except Exception`` handler catches it, while an effect-aware
    handler can ``except SubtreeSeveredError`` to react precisely.

    Attributes:
        reason: Operator-readable summary (bounded to
            :data:`REASON_MAX_BYTES`).
        policy_id: Cedar policy id of the
            ``@enforcement_effect("sever_subtree")`` policy that fired,
            or ``None`` if wl-apdp did not surface one.
        descendants_severed: Count of descendant RunHandles the
            depth-first walk severed (excludes the root that received
            the decision). ``0`` when the offending agent had no live
            descendants.
        unreachable_descendants: Count of child refs the walk could not
            resolve (dead weak refs). Non-zero signals a partial
            enumeration that was surfaced loudly rather than silently
            under-collapsed.
    """

    def __init__(
        self,
        reason: str,
        policy_id: Optional[str] = None,
        descendants_severed: int = 0,
        unreachable_descendants: int = 0,
    ) -> None:
        # Truthful invariant: we trust the caller to have validated via
        # SeverSubtreeDecision. Keep the constructor cheap and
        # unconditional so it's safe to call from the sever code path
        # (mirrors ExecutionTerminatedError.__init__).
        self.reason = reason
        self.policy_id = policy_id
        self.descendants_severed = descendants_severed
        self.unreachable_descendants = unreachable_descendants
        super().__init__(self._format_message())

    def _format_message(self) -> str:
        """Opaque message: no server reason, policy id or anomaly
        detail (it can reach the model through a framework's
        tool-error path). Those stay on the attributes for operator
        code, and in the server's audit trail."""
        return "Sub-agent subtree severed by Watchlight policy."

    @classmethod
    def from_decision(
        cls,
        decision: "SeverSubtreeDecision",
        descendants_severed: int = 0,
        unreachable_descendants: int = 0,
    ) -> "SubtreeSeveredError":
        """Construct from a parsed :class:`SeverSubtreeDecision`. Used by
        :class:`watchlight_core.BaseRunHandle` on the sever transition,
        after the depth-first descendant walk has run, so the counts
        reflect the actual collapse.
        """
        return cls(
            reason=decision.reason,
            policy_id=decision.policy_id,
            descendants_severed=descendants_severed,
            unreachable_descendants=unreachable_descendants,
        )


class AgentRevokedError(Exception):
    """Raised when wl-apdp returns a ``Revoke`` enforcement effect in
    response to ``authorize_action`` — the agent's identity TRUST is
    withdrawn (the terminal, most-severe verb on the halt/contain
    severity ladder, ordinal 4).

    On the raise, the RunHandle has ended the current run — the
    in-flight LLM call is aborted via the kill signal (``reason=revoke``)
    and the handle transitions to the terminal ``COMPLETED`` state.

    **Durable server-side deny (no local state needed).** UNLIKE
    :class:`AgentQuarantinedError` (which the SDK short-circuits in
    process via a durable-in-wl-apdp quarantine bag), a revoke's durable
    state lives in **wl-registry** (`identity.agents.trust_state`).
    wl-apdp EMITS an ``agent.trust.revoke`` event; wl-registry (the sole
    writer of agent trust) sets
    ``trust_state=Revoked``. Thereafter wl-apdp's pre-Cedar trust gate
    denies EVERY subsequent authorize for the agent — across every goal,
    **across process restarts** — until an operator explicitly
    re-trusts. The SDK therefore does NOT need durable local state: a
    revoked agent stays denied even after the plugin process restarts,
    because the deny is enforced server-side by the durable trust store.

    **Error-hierarchy contract.** Mirrors
    :class:`AgentQuarantinedError` / :class:`ExecutionTerminatedError` /
    :class:`SubtreeSeveredError`, which subclass :class:`Exception`
    directly (there is no shared ``AuthorizationDenied`` base in the
    Python lane). ``AgentRevokedError`` also subclasses :class:`Exception`
    directly so a generic ``except Exception`` handler catches it, while
    an effect-aware handler can ``except AgentRevokedError`` to react
    precisely.

    Attributes:
        reason: Operator-readable summary (bounded to
            :data:`REASON_MAX_BYTES`).
        policy_id: Cedar policy id of the ``@enforcement_effect("revoke")``
            policy that fired, or ``None`` if wl-apdp did not surface one.
    """

    def __init__(self, reason: str, policy_id: Optional[str] = None) -> None:
        # Cheap, unconditional constructor (mirrors the sibling errors):
        # the caller has already validated via RevokeDecision.
        self.reason = reason
        self.policy_id = policy_id
        super().__init__(self._format_message())

    def _format_message(self) -> str:
        """Opaque message: no server reason, policy id or anomaly
        detail (it can reach the model through a framework's
        tool-error path). Those stay on the attributes for operator
        code, and in the server's audit trail."""
        return "Agent trust revoked by Watchlight policy; re-trust is operator-only."

    @classmethod
    def from_decision(cls, decision: "RevokeDecision") -> "AgentRevokedError":
        """Construct from a parsed :class:`RevokeDecision`. Used by
        :class:`watchlight_core.BaseRunHandle` on the revoke transition.
        """
        return cls(reason=decision.reason, policy_id=decision.policy_id)


# Silence linters about unused imports — re-exported names are part
# of the module's public surface.
_ = (
    AuthorizationDecision,
    MAX_CONTRIBUTING_FEATURES,
)
