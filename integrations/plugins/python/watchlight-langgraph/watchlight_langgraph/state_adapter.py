"""Adapter from :class:`WatchlightLangGraphPlugin` → ``GovernanceState``.

Thin wrapper around :func:`watchlight_core.state_from_attrs` that
fills in ``framework="langgraph"``. The actual key set + ``None``
handling lives in core so every framework plugin renders the same
shape.
"""

from typing import Any

from watchlight_core import GovernanceState, state_from_attrs


def state_from_langgraph_plugin(
    plugin: Any, dashboard_base_url: str = "http://localhost:3000"
) -> GovernanceState:
    """LangGraph-flavoured ``state_from_attrs`` adapter.

    Returns the framework-agnostic :class:`GovernanceState` dict the
    Beacon Dashboard / Streamlit governance card consumes.
    """
    return state_from_attrs(
        plugin,
        framework="langgraph",
        dashboard_base_url=dashboard_base_url,
    )
