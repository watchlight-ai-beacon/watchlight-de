"""Govern a Claude Agent SDK agent in-process, with zero infrastructure.

    from watchlight.claude_agent import governed_plugin

    plugin = governed_plugin("watchlight.policy.json")
    async with await plugin.start_run("research-agent") as handle:
        if not await handle.authorize_action("read", "tool/web_search"):
            raise PermissionError("denied before it executed")
        ...  # run the tool

The returned object is an ordinary ``WatchlightClaudeAgentSDKPlugin`` — the SAME
plugin you ship to production, wired here to the in-process engine (local Cedar
policies, local value-free audit). Set ``WATCHLIGHT_APDP_URL`` to a running
policy service and the identical code runs against production APDP — one
environment variable, not a rewrite.

Requires the Claude Agent extra: ``pip install 'watchlight[claude-agent]'``.
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
    """Return a governed ``WatchlightClaudeAgentSDKPlugin``.

    :param policies: local Cedar policies — a path to a JSON policy file or an
        in-memory list of ``{"name", "code"}`` objects. ``None`` → fail-closed.
    :param audit_path: local JSONL lineage sink (value-free). ``None`` disables.
    :param plugin_kwargs: forwarded to ``WatchlightClaudeAgentSDKPlugin`` (e.g.
        ``tenant_id``, ``log_decisions``).
    """
    try:
        from watchlight_claude_agent import WatchlightClaudeAgentSDKPlugin
    except ImportError as exc:  # pragma: no cover - import-guard message
        raise ImportError(
            "governed Claude Agent support requires the claude-agent extra: "
            "pip install 'watchlight[claude-agent]'"
        ) from exc
    return WatchlightClaudeAgentSDKPlugin(
        **_select_backend_kwargs(policies, audit_path, plugin_kwargs)
    )
