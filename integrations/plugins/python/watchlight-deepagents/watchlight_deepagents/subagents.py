"""Sub-agent attenuation — the ``task``-tool interception surface.

Two complementary bindings enforce "authorize with the sub-agent's own
RunHandle, never the root's":

1. **At the parent**, the governance middleware intercepts the ``task``
   tool call and calls ``parent_handle.spawn_subagent(child_slug, ...)``
   — wl-apdp's strict-subset validator gates the spawn
   server-side and mints the child ``run_handle_id`` with the
   server-attested ``granted_scope``. This module resolves the
   deepagents ``subagent_type`` → the registered child slug and the
   per-subagent **attenuated** requested scope. Scope is declared in
   plugin config, **never** inferred from the ``task`` call's free-text
   ``description``.

2. **At the child**, :func:`inject_child_governance_middleware` appends a
   child-scoped governance middleware to every ``SubAgent``'s own
   ``middleware`` list so the sub-agent loop authorizes against the
   child handle.

Fail-closed default: a subagent with no declared
scope gets a zero-privilege child — empty ``allowed_tools``,
``max_depth=0``.

Fail-closed injection: a sub-agent spec that **cannot** be
governed by child-middleware injection (a pre-compiled ``runnable`` or a
remote ``graph_id`` graph, whose loops never see our injected
middleware) is **refused** at construction rather than run ungoverned.
A sub-agent that cannot be attenuated must not run.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from watchlight_core import GovernanceUnavailable, get_logger

logger = get_logger("watchlight_deepagents.subagents")

#: The deepagents sub-agent spawn tool name
#: (``SubAgentMiddleware._build_task_tool``).
TASK_TOOL_NAME = "task"

#: The name deepagents uses for its auto-added general-purpose subagent
#: (``deepagents.middleware.subagents.GENERAL_PURPOSE_SUBAGENT["name"]``).
#: deepagents auto-appends a general-purpose subagent — carrying the main
#: agent's FULL tool set and its own middleware stack that does NOT
#: inherit our ``watchlight_governance`` slot — whenever the caller has
#: not registered one. Left alone, that subagent runs UNGOVERNED. We
#: pre-register a governed one under this exact name so deepagents skips
#: the auto-add (``create_deep_agent`` checks
#: ``not any(spec["name"] == GENERAL_PURPOSE_SUBAGENT["name"] …)``).
GENERAL_PURPOSE_SUBAGENT_NAME = "general-purpose"

#: Description / prompt for the governed general-purpose spec we inject.
#: Kept faithful to deepagents' own stock text so operators who *do*
#: scope ``general-purpose`` get the expected behaviour — every action
#: is still gated by the child handle.
_GENERAL_PURPOSE_DESCRIPTION = (
    "General-purpose agent for researching complex questions, searching "
    "for files and content, and executing multi-step tasks. Governed by "
    "Watchlight: every action is authorized against an attenuated child "
    "handle (zero-privilege unless 'general-purpose' is scoped in "
    "subagent_scopes)."
)
_GENERAL_PURPOSE_PROMPT = (
    "In order to complete the objective that the user asks of you, you "
    "have access to a number of standard tools. The calling agent only "
    "sees your final assistant message. Ensure your final response "
    "contains the complete answer."
)

#: Canonical attenuation scope keys accepted per subagent.
_SCOPE_KEYS = (
    "allowed_tools",
    "allowed_resources",
    "allowed_intents",
    "max_depth",
    "time_budget_seconds",
)


def resolve_subagent_slug(subagent_type: str, subagent_slugs: Dict[str, str]) -> str:
    """Map a deepagents ``subagent_type`` → its Watchlight registry slug.

    Defaults to the subagent name itself when unmapped — the operator
    registers a Watchlight agent under the same slug. Never inferred
    from prompt text.
    """
    return subagent_slugs.get(subagent_type, subagent_type)


def requested_scope_for_subagent(
    subagent_type: str, subagent_scopes: Dict[str, Dict[str, Any]]
) -> Dict[str, Any]:
    """Return the canonical attenuated scope for ``subagent_type``.

    Fail-closed: a subagent with no config entry gets the zero-privilege
    default (``allowed_tools=[]``, ``max_depth=0``) so a buggy or absent
    config can never widen a child's authority.
    """
    raw = subagent_scopes.get(subagent_type)
    if not raw:
        return {"allowed_tools": [], "max_depth": 0}
    return {k: raw[k] for k in _SCOPE_KEYS if k in raw}


def ensure_general_purpose_subagent(
    subagents: Optional[List[Any]],
) -> List[Any]:
    """Return a subagents list guaranteed to contain a ``general-purpose``
    spec, so deepagents does **not** auto-add its own UNGOVERNED one.

    Security: ``create_deep_agent`` auto-appends a ``general-purpose``
    subagent with the main agent's full tool set and a middleware stack
    that never inherits our ``watchlight_governance`` slot. The plugin
    must not rely on "general-purpose happens to be unregistered" for
    safety. By pre-registering a governed spec under the same name we
    force deepagents to skip its auto-add; the spec then flows through
    :func:`inject_child_governance_middleware` like any other, so its
    loop is governed by the child handle and is zero-privilege unless the
    operator explicitly scopes ``general-purpose`` in ``subagent_scopes``.

    If the caller already registered a ``general-purpose`` subagent, it is
    left untouched here (and will be governed / refused by the injector
    like any other spec) — the operator's explicit registration wins.

    The injected spec deliberately omits ``tools`` so deepagents fills it
    from the main agent's tools; capability is still gated by the child
    handle's (fail-closed) scope, not by the tool list.
    """
    specs: List[Any] = list(subagents or [])
    for spec in specs:
        if isinstance(spec, dict) and spec.get("name") == GENERAL_PURPOSE_SUBAGENT_NAME:
            return specs
    specs.append(
        {
            "name": GENERAL_PURPOSE_SUBAGENT_NAME,
            "description": _GENERAL_PURPOSE_DESCRIPTION,
            "system_prompt": _GENERAL_PURPOSE_PROMPT,
        }
    )
    return specs


def inject_child_governance_middleware(
    subagents: Optional[List[Any]],
    child_middleware_factory,
) -> Optional[List[Any]]:
    """Append a child governance middleware to every ``SubAgent``'s own
    ``middleware`` list so the sub-agent loop is governed by the child
    handle.

    Accepts the ``subagents=`` value as passed to ``create_deep_agent``
    — a list of ``SubAgent`` TypedDicts (``{"name": ..., ...}``) or
    already-compiled specs. Mutates raw ``SubAgent`` dict specs in place
    (adding a ``middleware`` key when absent).

    Fail-closed: a spec that **cannot** be
    governed by injection is **refused** (raises
    :class:`GovernanceUnavailable`) instead of being warned-about and
    left to run ungoverned:

    - ``CompiledSubAgent`` (a dict with a ``runnable`` key) — deepagents
      runs the pre-compiled graph verbatim and never applies our injected
      middleware, so the injection would be a silent no-op.
    - ``AsyncSubAgent`` (a dict with a ``graph_id`` key) — the sub-agent
      runs out-of-process on a remote host; an in-process middleware
      cannot govern it.
    - a non-dict spec exposing no reachable ``middleware`` list.

    Such sub-agents must be governed by their own Watchlight plugin
    instance on their host, or registered as a raw ``SubAgent`` spec —
    they are refused here rather than run un-attenuated.

    Returns the same list object for call-site chaining.
    """
    if not subagents:
        return subagents
    for spec in subagents:
        if isinstance(spec, dict):
            if "runnable" in spec:
                raise GovernanceUnavailable(
                    f"Sub-agent {spec.get('name', spec)!r} is a "
                    f"CompiledSubAgent (pre-compiled `runnable`). deepagents "
                    f"runs that graph verbatim, so Watchlight cannot inject "
                    f"child governance and the sub-agent cannot be "
                    f"attenuated. Refusing to build an under-governed agent "
                    f"(fail-closed). Register it as a raw SubAgent spec, or "
                    f"govern the runnable with its own Watchlight plugin "
                    f"instance."
                )
            if "graph_id" in spec:
                raise GovernanceUnavailable(
                    f"Sub-agent {spec.get('name', spec)!r} is an AsyncSubAgent "
                    f"(remote `graph_id`) that runs out-of-process. The "
                    f"in-process child governance middleware cannot govern "
                    f"it. Refusing to build an under-governed agent "
                    f"(fail-closed). Govern the remote graph with its own "
                    f"Watchlight plugin instance on its host."
                )
            existing = list(spec.get("middleware") or [])
            existing.append(child_middleware_factory())
            spec["middleware"] = existing
        else:
            mw = getattr(spec, "middleware", None)
            if isinstance(mw, list):
                mw.append(child_middleware_factory())
            else:
                raise GovernanceUnavailable(
                    f"Sub-agent {getattr(spec, 'name', spec)!r} exposes no "
                    f"reachable middleware list; Watchlight cannot inject "
                    f"child governance, so the sub-agent cannot be "
                    f"attenuated. Refusing to run it ungoverned (fail-closed)."
                )
    return subagents


__all__ = [
    "TASK_TOOL_NAME",
    "GENERAL_PURPOSE_SUBAGENT_NAME",
    "resolve_subagent_slug",
    "requested_scope_for_subagent",
    "ensure_general_purpose_subagent",
    "inject_child_governance_middleware",
]
