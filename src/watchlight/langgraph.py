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
