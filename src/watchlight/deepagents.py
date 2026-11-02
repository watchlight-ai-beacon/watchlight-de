"""Govern a deepagents deep agent in-process, with zero infrastructure.

    from watchlight.deepagents import governed_plugin
    from watchlight_deepagents import create_governed_deep_agent

    plugin = governed_plugin("watchlight.policy.json")
    agent = create_governed_deep_agent(
        model=model, tools=[search_web], agent_slug="research-orchestrator", plugin=plugin,
    )

The returned object is a standard ``WatchlightDeepAgentsPlugin`` wired to the
in-process engine (local Cedar policies, local value-free audit). Set
``WATCHLIGHT_APDP_URL`` to a networked policy service and the same code runs
against a remote APDP.

Requires the deepagents extra: ``pip install 'watchlight[deepagents]'``.
"""

from __future__ import annotations

# The implementation lives in ``watchlight.integrations.deepagents``, on the
# framework-integration contract; this module is its stable public name.
from .integrations.deepagents import governed_plugin

__all__ = ["governed_plugin"]
