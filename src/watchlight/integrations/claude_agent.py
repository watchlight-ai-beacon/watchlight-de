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

from ..inprocess import Policies
from ._contract import FrameworkIntegration, build_governed_plugin

INTEGRATION = FrameworkIntegration(
    name="claude_agent",
    extra="claude-agent",
    display_name="Claude Agent",
    plugin_module="watchlight_claude_agent",
    plugin_class="WatchlightClaudeAgentSDKPlugin",
)


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
    match it. A BARE name matches a policy naming that id under ``User``,
    ``Agent``, ``Group`` or ``Role``, and when it matches more than one an
    allow beats a forbid — the wrong thing for a decision you rely on.

    :param policies: local Cedar policies — a path to a JSON policy file or an
        in-memory list of ``{"name", "code"}`` objects. ``None`` → fail-closed.
    :param audit_path: the local audit file (value-free). ``None`` disables it.
        Every ``handle.authorize_action`` writes one decision record to it — the
        record ``Watchlight.authorize`` writes, plus the run's ``execution_id``
        — next to the run's lifecycle lines.
    :param plugin_kwargs: forwarded to ``WatchlightClaudeAgentSDKPlugin`` (e.g.
        ``tenant_id``, ``log_decisions``) — except ``audit_sink``,
        ``audit_sink_batch`` and ``audit_sink_interval``, which configure the
        audit trail exactly as they do on ``Watchlight`` and are never
        forwarded.
    """
    return build_governed_plugin(
        INTEGRATION, policies, audit_path=audit_path, plugin_kwargs=plugin_kwargs
    )


# The public home of this factory is ``watchlight.claude_agent``, where it has
# always lived: its repr, pickle and ``inspect.getmodule`` name it there.
# (A traceback shows the file the code is in, this one.)
governed_plugin.__module__ = "watchlight.claude_agent"
