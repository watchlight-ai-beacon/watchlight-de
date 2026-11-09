"""Result wrappers for plan validation and preflight checks.

The HTTP wire format for ``/sessions/:id/plan`` and
``/sessions/:id/preflight`` is shared across every framework plugin,
so the result-shape parsing is consolidated here.

Both wrappers tolerate a ``None`` (transport-failure) construction
path via the ``deny_transport_failure`` / ``transport_failure`` class
methods so the calling plugin never has to invent its own
fail-closed sentinel.
"""

from typing import Any, Dict, List, Optional


class PlanResult:
    """Outcome of ``ApdpClient.submit_plan``.

    Mirrors the APDP ``PlanValidationResult`` shape with helper
    predicates so the caller can branch cleanly:
    ``if result.is_allow(): ...``.

    Defensive against three legacy / drift shapes APDP has emitted
    over the life of the validator:

    - ``decision`` as a typed dict ``{"decision": "allow", ...}`` (current)
    - ``decision`` as a bare string ``"allow"`` (very early APDP)
    - missing ``violations``/``escalations`` (early validators)
    """

    def __init__(self, validation: Dict[str, Any]):
        self.raw: Dict[str, Any] = validation
        decision_block = validation.get("decision") or {}
        if isinstance(decision_block, dict):
            self.decision: str = (decision_block.get("decision") or "").lower()
            self.modified_plan: List[Dict[str, Any]] = (
                decision_block.get("modified_plan") or []
            )
            self.modifications: List[Dict[str, Any]] = (
                decision_block.get("modifications") or []
            )
        else:
            # Defensive: legacy shape where decision is a bare string.
            self.decision = str(decision_block).lower()
            self.modified_plan = []
            self.modifications = []
        self.violations: List[Dict[str, Any]] = validation.get("violations") or []
        self.escalations: List[Dict[str, Any]] = validation.get("escalations") or []
        self.plan_hash: Optional[str] = validation.get("plan_hash")

    def is_allow(self) -> bool:
        return self.decision == "allow"

    def is_modify(self) -> bool:
        return self.decision == "modify"

    def is_deny(self) -> bool:
        return self.decision == "deny"

    @classmethod
    def deny_transport_failure(cls) -> "PlanResult":
        """Synthetic Deny when APDP is unreachable.

        Forces fail-closed behaviour in the caller without conflating
        it with a policy-driven Deny. Carries a single violation with
        ``code: apdp_unreachable`` so plugin code can distinguish
        transport failure from a policy decision.
        """
        return cls(
            {
                "decision": {"decision": "deny"},
                "violations": [
                    {
                        "rule_family": "transport",
                        "code": "apdp_unreachable",
                        "message": (
                            "APDP did not respond to plan submission. "
                            "Treating as Deny per fail-closed semantics."
                        ),
                    }
                ],
                "escalations": [],
                "plan_hash": None,
            }
        )


def authorize_response_problem(body: Any) -> Optional[str]:
    """Why an authorize answer cannot be trusted as a decision, or ``None``.

    wl-apdp answers with an object whose ``decision`` is a string, whose
    ``details`` (when present) is an object, whose ``reason`` (when present)
    is a string, and which never carries ``error`` next to a decision. An
    answer that breaks any of these was truncated, rewritten in transit or
    produced by a broken backend; it is refused (a Deny), never read as the
    decision it appears to name.
    """
    if not isinstance(body, dict):
        return f"the answer is a {type(body).__name__}, not an object"
    if not isinstance(body.get("decision"), str):
        return "the answer carries no decision string"
    details = body.get("details")
    if details is not None and not isinstance(details, dict):
        return "the answer's details are not an object"
    reason = body.get("reason")
    if reason is not None and not isinstance(reason, str):
        return "the answer's reason is not a string"
    if body.get("error") is not None:
        return "the answer reports an error alongside its decision"
    return None


class AuthorizeResult:
    """Rich-result variant of an APDP authorize call.

    ``BaseRunHandle.authorize_action`` collapses APDP's response to a
    bool for backwards compat. ``authorize_action_detailed`` returns
    this object so callers can branch on three distinct outcomes:

    * ``allow``       — proceed with the action.
    * ``deny``        — halt; ``reason`` carries the policy id or
                        validation message.
    * ``needs_approval`` — APDP signalled escalation_required + minted
                        an approval_request_id. The caller's framework
                        chooses how to pause: LangGraph plugins use
                        :func:`langgraph.types.interrupt`; ADK plugins
                        surface a HumanApprovalRequired exception;
                        bare CLI scripts can poll
                        ``GET /approvals/:id`` until the operator
                        decides, then retry with
                        ``intent.approval_token = approval_request_id``.

    Security model — the ``approval_request_id`` is the secret used
    to satisfy APDP's intent-approval gate on retry. Treat it like a
    bearer credential: never log it at info; never include it in
    error messages surfaced to untrusted callers. The approval is
    single-use and bound to the request it was minted for; the server
    does not expire it on a TTL, so do not keep it longer than the
    retry needs.
    """

    __slots__ = ("decision", "reason", "approval_request_id", "escalation_required")

    def __init__(
        self,
        decision: str,
        reason: str = "",
        approval_request_id: Optional[str] = None,
        escalation_required: bool = False,
    ):
        # Decision is canonicalized to one of the three states; any
        # unknown response from APDP fails closed to ``deny`` rather
        # than passing through a string we never tested against.
        canonical = decision.lower()
        if canonical not in ("allow", "deny", "needs_approval"):
            canonical = "deny"
        self.decision: str = canonical
        self.reason: str = reason
        self.approval_request_id: Optional[str] = approval_request_id
        self.escalation_required: bool = escalation_required

    @classmethod
    def from_apdp(cls, payload: Dict[str, Any]) -> "AuthorizeResult":
        """Build from the JSON response of ``ApdpClient.authorize``.

        APDP surfaces ``escalation_required`` and the freshly-minted
        ``approval_request_id`` inside ``response.details`` when the
        intent-validator says approval is needed (see
        wl-apdp's request evaluation). We pluck both
        here and synthesize the ``needs_approval`` decision so the
        caller doesn't have to introspect the JSON shape.
        """
        decision_str = (payload.get("decision") or "").lower()
        reason = payload.get("reason") or ""
        details = payload.get("details") or {}
        escalation_required = bool(details.get("escalation_required"))
        approval_request_id = details.get("approval_request_id")

        # An approval-request response from APDP is technically a
        # Deny, but distinguishing "deny — needs approval" from
        # "deny — policy forbids" is the whole point of this type.
        if decision_str == "deny" and escalation_required and approval_request_id:
            return cls(
                "needs_approval",
                reason=reason,
                approval_request_id=approval_request_id,
                escalation_required=True,
            )
        return cls(
            decision_str,
            reason=reason,
            approval_request_id=approval_request_id if isinstance(approval_request_id, str) else None,
            escalation_required=escalation_required,
        )

    @classmethod
    def deny_transport_failure(cls) -> "AuthorizeResult":
        """Fail-closed when APDP is unreachable / returns malformed."""
        return cls("deny", reason="APDP unreachable — authorize defaulted to deny")

    def is_allow(self) -> bool:
        return self.decision == "allow"

    def is_deny(self) -> bool:
        return self.decision == "deny"

    def needs_approval(self) -> bool:
        return self.decision == "needs_approval"


class PreflightResult:
    """Outcome of ``ApdpClient.preflight_step``.

    Read-only check (does not consume budget or write to audit). Used
    by plugin code to surface diagnostics before invoking a tool.
    """

    def __init__(self, preflight: Dict[str, Any]):
        self.allowed: bool = bool(preflight.get("allowed", False))
        self.reason: str = preflight.get("explanation") or preflight.get("reason_code") or ""
        self.escalation_required: bool = preflight.get("escalation_required") is not None

    @classmethod
    def transport_failure(cls) -> "PreflightResult":
        """Synthetic deny when APDP is unreachable. Same fail-closed
        semantics as :meth:`PlanResult.deny_transport_failure` — the
        caller sees a deterministic ``allowed=False`` rather than
        having to handle a separate transport-failure sentinel.
        """
        r = cls.__new__(cls)
        r.allowed = False
        r.reason = "APDP unreachable — preflight defaulted to deny"
        r.escalation_required = False
        return r
