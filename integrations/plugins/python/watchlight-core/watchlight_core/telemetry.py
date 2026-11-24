"""Plugin telemetry contract — the seven ``last_*`` attributes the
Beacon Dashboard / Streamlit governance card reads.

Every framework plugin (ADK, LangGraph, Bedrock, future plugins) must
expose this attribute set so the framework-agnostic
``governance_card`` widget can render a uniform view across plugins.

Exposed two ways:

- :class:`GovernanceTelemetry` — a mixin / dataclass with the
  attributes pre-declared and a ``reset()`` helper. Plugin classes
  inherit from this and inherit the contract for free.
- :class:`TelemetryProtocol` — a runtime-checkable Protocol so type
  checkers and tests can assert "this thing has the seven attrs"
  without coupling to the mixin.

Tests use the Protocol; production plugins use the mixin.
"""

from typing import Any, Dict, List, Optional, Protocol, runtime_checkable


class GovernanceTelemetry:
    """Mixin / dataclass exposing the seven governance-card attributes.

    Plugin classes call :meth:`_reset_telemetry` at the start of every
    new run so stale state from a prior run cannot bleed into the
    current card.

    The seven attributes:

    - ``last_governance_mode`` — ``"strong"`` / ``"degraded"`` / ``"unavailable"``
    - ``last_session_id`` — APDP session UUID for this run
    - ``last_manifest`` — ``ConstraintManifest`` returned by APDP
    - ``last_plan_validation`` — ``PlanValidationResult`` payload
    - ``last_proposed_plan`` — the plan in ``ProposedStep[]`` shape
    - ``last_actions_allowed`` / ``last_actions_denied`` — counters
    """

    last_governance_mode: str
    last_session_id: Optional[str]
    last_manifest: Optional[Dict[str, Any]]
    last_plan_validation: Optional[Dict[str, Any]]
    last_proposed_plan: Optional[List[Dict[str, Any]]]
    last_actions_allowed: int
    last_actions_denied: int

    def __init__(self) -> None:
        self._reset_telemetry()

    def _reset_telemetry(self) -> None:
        """Clear all seven attributes back to their fresh-run defaults.

        Plugin lifecycle code calls this at the start of every new run
        (typically the first line of ``start_run`` / ``before_agent``).
        Forgetting to reset is a common bug; centralising it here means
        no plugin has to reinvent the reset list.
        """
        self.last_governance_mode = "unknown"
        self.last_session_id = None
        self.last_manifest = None
        self.last_plan_validation = None
        self.last_proposed_plan = None
        self.last_actions_allowed = 0
        self.last_actions_denied = 0


@runtime_checkable
class TelemetryProtocol(Protocol):
    """Runtime-checkable protocol for the seven governance-card attrs.

    Use in tests: ``isinstance(plugin, TelemetryProtocol)`` will return
    True only when all seven attributes are present. Useful as a smoke
    check that a new plugin is wired into the contract correctly.
    """

    last_governance_mode: str
    last_session_id: Optional[str]
    last_manifest: Optional[Dict[str, Any]]
    last_plan_validation: Optional[Dict[str, Any]]
    last_proposed_plan: Optional[List[Dict[str, Any]]]
    last_actions_allowed: int
    last_actions_denied: int
