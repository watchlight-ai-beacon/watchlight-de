"""Framework-agnostic ``GovernanceState`` shape + adapter.

The Streamlit / Beacon Dashboard governance card consumes a
normalised dict so the same widget renders for every framework
plugin. This module:

- Declares the shape as a :class:`TypedDict` so type checkers catch
  drift across plugins at static-analysis time.
- Provides :func:`state_from_attrs` — a one-liner replacement for
  the ``state_from_<framework>_plugin`` adapters each plugin used to
  hand-roll. Pass any object with the seven ``last_*`` attributes
  (or ``None``) plus a framework name; the adapter returns the
  normalised dict.

Why a TypedDict instead of a dataclass: the contract crosses HTTP
and Streamlit boundaries as JSON-shaped dicts; a dataclass would
require .to_dict() at every boundary. TypedDict gives static checking
without runtime overhead.
"""

from typing import Any, Dict, List, Optional

try:
    from typing import TypedDict  # Python ≥3.11 has it directly.
except ImportError:  # pragma: no cover — 3.10 fallback
    from typing_extensions import TypedDict  # type: ignore[assignment]


class GovernanceState(TypedDict):
    """Normalised governance-card payload, framework-agnostic.

    Every framework plugin's adapter MUST return exactly this shape.
    The frontend governance_card widget reads only these keys; adding
    framework-specific fields is forbidden — render them through
    ``manifest`` or ``plan_validation`` if they need to surface.
    """

    mode: str
    """``"strong"`` / ``"degraded"`` / ``"unavailable"`` — governance posture."""

    session_id: Optional[str]
    """APDP session UUID; ``None`` before any run starts."""

    framework: str
    """Plugin framework name: ``"adk"`` / ``"langgraph"`` / ``"aws_bedrock"`` / ..."""

    manifest: Optional[Dict[str, Any]]
    """``ConstraintManifest`` payload from APDP; ``None`` when fetch failed."""

    plan_validation: Optional[Dict[str, Any]]
    """``PlanValidationResult`` payload; ``None`` if no plan submitted yet."""

    proposed_plan: Optional[List[Dict[str, Any]]]
    """The submitted plan in ``ProposedStep[]`` shape."""

    actions_allowed: int
    """Cumulative ``Allow`` count for this run."""

    actions_denied: int
    """Cumulative ``Deny`` count for this run."""

    dashboard_base_url: str
    """Beacon Dashboard URL the card uses for deep-link buttons."""


def state_from_attrs(
    plugin: Optional[Any],
    framework: str,
    dashboard_base_url: str = "http://localhost:3000",
) -> GovernanceState:
    """Adapt any object exposing the seven ``last_*`` attributes
    (see :class:`watchlight_core.GovernanceTelemetry`) into a
    :class:`GovernanceState` dict.

    ``plugin`` may be ``None`` — the adapter returns an
    ``mode="unavailable"`` state so the host UI shows a fail-closed
    banner rather than blank space. This is the single replacement
    for every per-framework ``state_from_<framework>_plugin`` adapter
    that used to live in each plugin package.

    ``framework`` MUST be a stable string. Recommended values:
    ``"adk"``, ``"langgraph"``, ``"aws_bedrock"``, ``"crewai"``.
    Drift in this string breaks the dashboard's framework filter.

    Tolerant of partial telemetry: if the plugin is missing one of
    the ``last_*`` attributes (e.g. a bare object that pre-dated the
    contract), the adapter normalises to safe defaults rather than
    raising.
    """
    if plugin is None:
        return GovernanceState(
            mode="unavailable",
            session_id=None,
            framework=framework,
            manifest=None,
            plan_validation=None,
            proposed_plan=None,
            actions_allowed=0,
            actions_denied=0,
            dashboard_base_url=dashboard_base_url,
        )

    return GovernanceState(
        mode=getattr(plugin, "last_governance_mode", "unavailable") or "unavailable",
        session_id=getattr(plugin, "last_session_id", None),
        framework=framework,
        manifest=getattr(plugin, "last_manifest", None),
        plan_validation=getattr(plugin, "last_plan_validation", None),
        proposed_plan=getattr(plugin, "last_proposed_plan", None),
        actions_allowed=int(getattr(plugin, "last_actions_allowed", 0) or 0),
        actions_denied=int(getattr(plugin, "last_actions_denied", 0) or 0),
        dashboard_base_url=dashboard_base_url,
    )
