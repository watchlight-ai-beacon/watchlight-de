"""Watchlight ADK — Governance plugin for Google Agent Development Kit.

Drop-in governance for any Google ADK agent. Enforces Cedar policies,
tracks execution lineage, and manages agent trust — all through a single
plugin registration.

Usage::

    from watchlight_adk import WatchlightPlugin
    from google.adk.runners import Runner

    plugin = WatchlightPlugin(
        apdp_url="http://localhost:8081",
        agent_slug="agent-my-orchestrator",          # the root's registered slug
        root_agent_name="my_orchestrator",           # the root ADK agent.name
        subagent_slugs={"researcher": "agent-my-researcher"},
    )
    runner = Runner(agent=my_agent, plugins=[plugin])

The HTTP client and shared governance primitives live in
:mod:`watchlight_core` (the shared Watchlight agent-SDK package).
This package owns only the ADK-specific surface: the lifecycle plugin,
the ``PlanReActPlanner`` parser, the manifest-driven toolset, and the
ADK-flavoured ``state_from_plugin`` helper.
"""

from typing import Any

from watchlight_core import (
    AgentNotRegistered,
    GovernanceState,
    GovernanceUnavailable,
    PlanResult,
    PreflightResult,
    WatchlightError,
    governance_mode,
    state_from_attrs,
)

from watchlight_adk.actions import ACTION_CONVENTIONS, resolve_action
from watchlight_adk.agent_slugs import (
    REGISTRY_SLUG_PREFIX,
    configured_slug,
    normalize_subagent_slugs,
)
from watchlight_adk.lineage import LineageEmitter
from watchlight_adk.plan_parser import (
    PLAN_PROMPT_ADDENDUM,
    parse_planning_block,
)
from watchlight_adk.plugin import WatchlightPlugin
from watchlight_adk.registry_client import RegistryClient
from watchlight_adk.synthetic_intent_tool import (
    WatchlightDeclareIntentTool,
    inject_declare_intent_tool,
)
from watchlight_adk.toolset import ManifestDrivenToolset
from watchlight_adk.traces import translate_adk_event, translate_adk_events


def state_from_plugin(
    plugin: Any, dashboard_base_url: str = "http://localhost:3000"
) -> GovernanceState:
    """ADK-shape ``state_from_attrs`` helper.

    Thin convenience wrapper around
    :func:`watchlight_core.state_from_attrs` that fills in
    ``framework="adk"``. Provided so callers using the previous
    per-plugin state-helper pattern keep their import unchanged.
    """
    return state_from_attrs(
        plugin, framework="adk", dashboard_base_url=dashboard_base_url
    )


__all__ = [
    "WatchlightPlugin",
    "ACTION_CONVENTIONS",
    "resolve_action",
    # Governed identity: ADK agent.name → registered Watchlight slug.
    "REGISTRY_SLUG_PREFIX",
    "configured_slug",
    "normalize_subagent_slugs",
    "RegistryClient",
    "ManifestDrivenToolset",
    "PLAN_PROMPT_ADDENDUM",
    "governance_mode",
    "parse_planning_block",
    # Re-exported from watchlight_core for backwards-compat
    "AgentNotRegistered",
    "GovernanceUnavailable",
    "WatchlightError",
    "PlanResult",
    "PreflightResult",
    "GovernanceState",
    # ADK-flavoured state helper
    "state_from_plugin",
    # Lineage translator + emitter for advanced users
    # composing custom emission pipelines.
    "LineageEmitter",
    "translate_adk_event",
    "translate_adk_events",
    # Synthetic ``watchlight.declare_intent`` tool surface.
    "WatchlightDeclareIntentTool",
    "inject_declare_intent_tool",
]
__version__ = "0.4.3"
