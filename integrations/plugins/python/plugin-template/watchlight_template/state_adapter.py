"""Dashboard governance-state adapter (one-liner).

The Watchlight Beacon dashboard renders a per-plugin governance
card with the seven ``last_*`` telemetry fields. This adapter
wraps the plugin's :class:`GovernanceTelemetry` into the
dashboard's :class:`GovernanceState` shape.

When you fork: replace the framework name string ``"template"``
with your framework's identifier. That's it.
"""

from __future__ import annotations

from typing import Any, Optional

from watchlight_core import GovernanceState, state_from_attrs

__all__ = ["state_from_template_plugin"]


def state_from_template_plugin(
    plugin: Any,
    dashboard_base_url: Optional[str] = None,
) -> GovernanceState:
    """Adapter for the Watchlight Beacon dashboard's governance card.

    Usage in customer code (Streamlit / FastAPI / whatever)::

        state = state_from_template_plugin(plugin)
        render_governance_card(state)
    """
    return state_from_attrs(
        plugin,
        framework="template",
        dashboard_base_url=dashboard_base_url,
    )
