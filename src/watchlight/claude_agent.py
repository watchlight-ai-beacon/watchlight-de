"""Govern a Claude Agent SDK agent in-process, with zero infrastructure.

    from watchlight.claude_agent import governed_plugin

    plugin = governed_plugin("watchlight.policy.json")
    async with await plugin.start_run("research-agent") as handle:
        if not await handle.authorize_action("read", "tool/web_search"):
            raise PermissionError("denied before it executed")
        ...  # run the tool

The returned object is a standard ``WatchlightClaudeAgentSDKPlugin`` wired to the
in-process engine (local Cedar policies, local value-free audit). Set
``WATCHLIGHT_APDP_URL`` to a networked policy service and the same code runs
against a remote APDP.

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

    **The acting subject: also per call, on the handle.** Pass ``principal`` to
    name the person or tenant a call is made FOR::

        await handle.authorize_action(
            "read", "tool/read_ticket", principal=f'User::"{user_id}"',
        )

    Omitted, the subject defaults to the agent that runs — ``Agent::"<agent
    uuid>"`` — so an existing call is unchanged. Requires
    ``watchlight-agent-sdk`` 0.7.0 or later.

    **Name the entity type.** ``principal``, ``resource`` and the action reach
    the engine exactly as given. A typed reference such as ``User::"u-1"``
    discriminates: a policy naming a different type with the same id does not
    match it. A BARE name is a wildcard that matches every entity type with
    that id, which is a convenience for a scratch policy and the wrong thing
    for a decision you rely on.

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
