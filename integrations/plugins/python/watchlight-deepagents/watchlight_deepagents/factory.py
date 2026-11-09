"""``create_governed_deep_agent`` — the one-import drop-in factory.

Wraps ``deepagents.create_deep_agent`` so the customer's only changes
are: one import swap, one ``agent_slug`` argument, and ≤3 env knobs. The
factory:

  (a) constructs the :class:`WatchlightDeepAgentsPlugin` from env
      (fail-loud on missing ``WATCHLIGHT_APDP_URL``);
  (b) prepends the root governance ``AgentMiddleware`` to ``middleware=``;
  (c) pre-registers a **governed** ``general-purpose`` sub-agent so
      deepagents does not auto-add its own *ungoverned* one;
  (d) injects a child governance middleware into every ``SubAgent``'s
      own ``middleware`` list so sub-agents authorize against their own
      attenuated handle — **refusing** (fail-closed) any sub-agent that
      cannot be governed by injection (``CompiledSubAgent`` /
      ``AsyncSubAgent``);
  (e) leaves tool bodies, sub-agent prompts, and the model loop
      untouched (customers never modify their agent's tool code).

This factory is the **single governed-construction path** — the only
one that guarantees every spawnable sub-agent is attenuated. The
standalone ``plugin.middleware()`` ("Option B") governs the root agent
but **refuses sub-agent spawns** (it cannot reach ``subagents=`` to
inject child governance); use this factory whenever the agent delegates.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence

from .middleware import build_governance_middleware
from .plugin import WatchlightDeepAgentsPlugin
from .subagents import (
    ensure_general_purpose_subagent,
    inject_child_governance_middleware,
)


def create_governed_deep_agent(
    *,
    agent_slug: str,
    subagent_scopes: Optional[Dict[str, Dict[str, Any]]] = None,
    subagent_slugs: Optional[Dict[str, str]] = None,
    plugin: Optional[WatchlightDeepAgentsPlugin] = None,
    middleware: Sequence[Any] = (),
    subagents: Optional[List[Any]] = None,
    **create_deep_agent_kwargs: Any,
) -> Any:
    """Build a governed ``deepagents`` agent — the recommended drop-in.

    Args:
        agent_slug: The registered Watchlight slug for the root agent
            (the ONE required extra arg). Resolved server-side to a
            UUID — never inferred from the model's prompt.
        subagent_scopes: Per-subagent attenuation keyed by deepagents
            subagent ``name`` (strict subset; fail-closed when omitted).
        subagent_slugs: Optional deepagents subagent ``name`` → Watchlight
            slug map. Defaults to the subagent name.
        plugin: An explicit plugin instance. Defaults to
            :meth:`WatchlightDeepAgentsPlugin.from_env` — fail-loud on
            missing config.
        middleware: The customer's own middleware list; the root
            governance middleware is prepended.
        subagents: The ``subagents=`` value; each entry gets a child
            governance middleware injected.
        **create_deep_agent_kwargs: Forwarded verbatim to
            ``deepagents.create_deep_agent`` (``model``, ``tools``,
            ``system_prompt``, ``backend``, …).

    Returns:
        The ``CompiledStateGraph`` from ``create_deep_agent`` — the same
        object the customer would otherwise have used, now governed.
    """
    from deepagents import create_deep_agent

    if plugin is None:
        plugin = WatchlightDeepAgentsPlugin.from_env()

    scopes = subagent_scopes or {}
    slugs = subagent_slugs or {}

    def _child_mw_factory() -> Any:
        return build_governance_middleware(
            plugin=plugin,
            agent_slug=agent_slug,
            subagent_scopes=scopes,
            subagent_slugs=slugs,
            is_child=True,
        )

    # Pre-register a GOVERNED ``general-purpose`` sub-agent so
    # deepagents does not auto-add its own UNGOVERNED one (which would
    # carry the main agent's full tool set with no ``watchlight_governance``
    # slot). Zero-privilege unless the operator scopes ``general-purpose``.
    governed_subagents = ensure_general_purpose_subagent(subagents)

    # Inject child governance into EVERY spawnable
    # sub-agent (custom + the general-purpose we just registered). This
    # RAISES (fail-closed) on any spec that cannot be governed by
    # injection (CompiledSubAgent / AsyncSubAgent) — an un-attenuable
    # sub-agent aborts construction rather than running ungoverned. Only
    # once this returns can we truthfully mark child governance
    # guaranteed on the root middleware.
    inject_child_governance_middleware(governed_subagents, _child_mw_factory)

    root_mw = build_governance_middleware(
        plugin=plugin,
        agent_slug=agent_slug,
        subagent_scopes=scopes,
        subagent_slugs=slugs,
        is_child=False,
        # The factory is the ONE governed-construction path: every
        # spawnable sub-agent above has a child governance middleware.
        # This unlocks the root ``task``-tool interception (Option B,
        # which cannot inject, leaves this False and refuses spawns).
        child_governance_guaranteed=True,
    )

    merged_middleware = [root_mw, *middleware]
    return create_deep_agent(
        middleware=merged_middleware,
        subagents=governed_subagents,
        **create_deep_agent_kwargs,
    )


__all__ = ["create_governed_deep_agent"]
