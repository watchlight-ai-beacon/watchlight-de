"""Dashboard governance-state adapter for Pydantic AI plugin."""

from __future__ import annotations

from typing import Any, Optional

from watchlight_core import GovernanceState, state_from_attrs

__all__ = ["state_from_pydantic_ai_plugin"]


def state_from_pydantic_ai_plugin(
    plugin: Any,
    dashboard_base_url: Optional[str] = None,
) -> GovernanceState:
    """Adapter for the Watchlight Beacon dashboard's governance
    card. Pass the :class:`WatchlightPydanticAIPlugin` instance
    after a run completes; the card reads the seven ``last_*``
    telemetry fields.
    """
    return state_from_attrs(
        plugin,
        framework="pydantic-ai",
        dashboard_base_url=dashboard_base_url,
    )
