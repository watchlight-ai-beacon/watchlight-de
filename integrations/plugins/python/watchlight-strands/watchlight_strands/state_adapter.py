"""Dashboard governance-state adapter for the Strands plugin."""

from __future__ import annotations

from typing import Any, Optional

from watchlight_core import GovernanceState, state_from_attrs

__all__ = ["state_from_strands_plugin"]


def state_from_strands_plugin(
    plugin: Any,
    dashboard_base_url: Optional[str] = None,
) -> GovernanceState:
    """Adapter for the Watchlight Beacon dashboard's governance card.

    Pass a :class:`WatchlightStrandsPlugin` after a run; the card reads its
    ``last_*`` telemetry fields.
    """
    return state_from_attrs(
        plugin,
        framework="strands",
        dashboard_base_url=dashboard_base_url,
    )
