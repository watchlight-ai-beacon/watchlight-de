"""Adapter from :class:`WatchlightBedrockPlugin` → ``GovernanceState``.

Thin wrapper around :func:`watchlight_core.state_from_attrs` that
fills in ``framework="aws_bedrock"``. Key set + ``None`` handling
live in core so every framework plugin renders identically.
"""

from typing import Any

from watchlight_core import GovernanceState, state_from_attrs


def state_from_bedrock_plugin(
    plugin: Any, dashboard_base_url: str = "http://localhost:3000"
) -> GovernanceState:
    """Bedrock-flavoured ``state_from_attrs`` adapter."""
    return state_from_attrs(
        plugin,
        framework="aws_bedrock",
        dashboard_base_url=dashboard_base_url,
    )
