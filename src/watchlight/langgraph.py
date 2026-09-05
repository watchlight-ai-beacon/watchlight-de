"""Govern a LangGraph agent in-process, with zero infrastructure.

    from watchlight.langgraph import governed_plugin

    plugin = governed_plugin("watchlight.policy.json")
    async with await plugin.start_run("research-agent") as handle:
        if not await handle.authorize_action("read", "tool/web_search"):
            raise PermissionError("denied before it executed")
        ...  # run the tool

The returned object is a standard ``WatchlightLangGraphPlugin`` wired to the
in-process engine (local Cedar policies, local value-free audit). Set
``WATCHLIGHT_APDP_URL`` to a networked policy service and the same code runs
against a remote APDP.

Requires the LangGraph extra: ``pip install 'watchlight[langgraph]'``.
"""

from __future__ import annotations

from typing import Any, Optional

from .inprocess import Policies, _select_backend_kwargs


def governed_plugin(
    policies: Policies = None,
    *,
    audit_path: Optional[str] = ".watchlight/audit.jsonl",
    **plugin_kwargs: Any,
) -> Any:
    """Return a governed ``WatchlightLangGraphPlugin``.

    **What this path can express.** The intent (the ``action``), the resource
    and Cedar ``context`` — each a per-call term, supplied on the run handle::

        async with await plugin.start_run("research-agent") as handle:
            ok = await handle.authorize_action(
                "read", "tool/web_search",
                context={"caller": user_id, "owner": record_owner},
            )

    A policy whose verdict depends on ``context.*`` is therefore satisfiable
    through this plugin. (``tenant_id`` is the plugin's own and always wins over
    a value passed here.)

    **What it cannot express: an acting subject.** Every decision a framework
    plugin makes is attributed to the agent it runs — ``Agent::"<agent>"`` —
    and there is no per-call principal, at construction or on the handle. For a
    policy that must name the person or tenant a call is made FOR, govern that
    call with :meth:`watchlight.Watchlight.tool` (which takes ``principal``,
    ``resource`` and ``context``) instead of, or alongside, this plugin.

    ``watchlight_langgraph.governed_tool_call(handle, tool_name, intent=...,
    context=...)`` carries the same per-call ``context`` into a tool node, and
    the same limit applies to it.

    :param policies: local Cedar policies — a path to a JSON policy file or an
        in-memory list of ``{"name", "code"}`` objects. ``None`` → fail-closed.
    :param audit_path: local JSONL lineage sink (value-free). ``None`` disables.
    :param plugin_kwargs: forwarded to ``WatchlightLangGraphPlugin`` (e.g.
        ``tenant_id``, ``log_decisions``).
    """
    try:
        from watchlight_langgraph import WatchlightLangGraphPlugin
    except ImportError as exc:  # pragma: no cover - import-guard message
        raise ImportError(
            "governed LangGraph support requires the langgraph extra: "
            "pip install 'watchlight[langgraph]'"
        ) from exc
    return WatchlightLangGraphPlugin(
        **_select_backend_kwargs(policies, audit_path, plugin_kwargs)
    )
