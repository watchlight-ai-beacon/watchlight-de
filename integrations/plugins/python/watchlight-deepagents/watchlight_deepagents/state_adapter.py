"""Adapter from :class:`WatchlightDeepAgentsPlugin` → ``GovernanceState``.

Thin wrapper around :func:`watchlight_core.state_from_attrs` that fills
in ``framework="deepagents"``. The key set + ``None`` handling live in
core so every framework plugin renders the same ``governance_card``.
"""

from __future__ import annotations

from typing import Any

from watchlight_core import GovernanceState, state_from_attrs


def state_from_deepagents_plugin(
    plugin: Any, dashboard_base_url: str = "http://localhost:3000"
) -> GovernanceState:
    """deepagents-flavoured ``state_from_attrs`` adapter."""
    return state_from_attrs(
        plugin,
        framework="deepagents",
        dashboard_base_url=dashboard_base_url,
    )


__all__ = ["state_from_deepagents_plugin"]
