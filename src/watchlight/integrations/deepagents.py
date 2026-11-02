"""Govern a deepagents deep agent in-process, with zero infrastructure.

    from watchlight.deepagents import governed_plugin
    from watchlight_deepagents import create_governed_deep_agent

    plugin = governed_plugin("watchlight.policy.json")
    agent = create_governed_deep_agent(
        model=model,
        tools=[search_web, send_email],
        subagents=[researcher],
        subagent_scopes={"researcher": {"allowed_tools": ["search_web"]}},
        agent_slug="research-orchestrator",
        plugin=plugin,
    )
    result = await agent.ainvoke({"messages": [...]})

The returned object is a standard ``WatchlightDeepAgentsPlugin`` wired to the
in-process engine (local Cedar policies, local value-free audit). Every tool,
filesystem and ``task`` sub-agent call the agent makes is authorized before it
runs, and a sub-agent may call only the tools its spawn granted. Set
``WATCHLIGHT_APDP_URL`` to a networked policy service and the same code runs
against a remote APDP.

Requires the deepagents extra: ``pip install 'watchlight[deepagents]'``.
"""

from __future__ import annotations

from typing import Any, Optional

from ..inprocess import Policies
from ._contract import FrameworkIntegration, build_governed_plugin

INTEGRATION = FrameworkIntegration(
    name="deepagents",
    extra="deepagents",
    display_name="deepagents",
    plugin_module="watchlight_deepagents",
    plugin_class="WatchlightDeepAgentsPlugin",
)


def governed_plugin(
    policies: Policies = None,
    *,
    audit_path: Optional[str] = ".watchlight/audit.jsonl",
    **plugin_kwargs: Any,
) -> Any:
    """Return a governed ``WatchlightDeepAgentsPlugin``.

    Pass it to ``watchlight_deepagents.create_governed_deep_agent(plugin=...)``.
    That factory installs governance in the root agent and in every sub-agent,
    including deepagents' own ``general-purpose`` sub-agent.

    **What is decided, and when.** Each tool and filesystem call is authorized
    before it runs: the action is a verb read from the tool name (``read``,
    ``write`` or ``execute``), the resource is ``deepagents://tool/<name>`` (or
    ``deepagents://fs/<path>`` for a filesystem tool), and the Cedar
    ``context`` carries only the argument names, count and types, never their
    values. A denial returns an error to the model, and the tool never runs.
    A ``task`` call opens a sub-agent run under the parent with the scope named
    for it in ``subagent_scopes``. A sub-agent with no scope there may call no
    tool. Model turns are not authorized one by one. Only the async runtime is
    governed: a synchronous ``invoke`` is refused.

    **The subject and context of the agent's own calls.** The governed deep
    agent sends no subject or context of yours: each of its calls is decided
    with the running agent as the principal, ``Agent::"<agent uuid>"`` (the
    uuid5 of its slug), so write ``principal is Agent`` (or name the uuid) in a
    policy that should match it.

    **Your own checks: per call, on a run handle.** The intent (the
    ``action``), the resource, the acting subject and Cedar ``context`` are
    per-call terms. For a check of your own that names them, open a run on the
    same plugin and ask its handle::

        async with await plugin.start_run("support-agent") as handle:
            ok = await handle.authorize_action(
                "read", "tool/read_ticket",
                principal=principals.user(user_id),
                context={"owner": record_owner},
            )

    **Name the entity type.** ``principal``, ``resource`` and the action reach
    the engine exactly as given, and the engine parses each one strictly. A
    typed reference such as ``User::"u-1"`` discriminates: a policy naming a
    different type with the same id does not match it. Build it with
    :mod:`watchlight.principals`, which escapes a quote, an apostrophe or a
    backslash in the id and refuses an id with a character the engine cannot
    read; an unescaped quote makes the request invalid. A BARE principal is read as
    a ``User`` and never matches a policy of another type, so write the type to
    name an agent, a group or a role.

    :param policies: local Cedar policies — a path to a JSON policy file or an
        in-memory list of ``{"name", "code"}`` objects. ``None`` → fail-closed.
    :param audit_path: the local audit file (value-free). ``None`` disables it.
        Every decision writes one decision record to it — the record
        ``Watchlight.authorize`` writes, plus the run's ``execution_id`` — next
        to the run's lifecycle lines.
    :param plugin_kwargs: forwarded to ``WatchlightDeepAgentsPlugin`` (e.g.
        ``tenant_id``, ``log_decisions``) — except ``audit_sink``,
        ``audit_sink_batch`` and ``audit_sink_interval``, which configure the
        audit trail exactly as they do on ``Watchlight`` and are never
        forwarded.
    """
    return build_governed_plugin(
        INTEGRATION, policies, audit_path=audit_path, plugin_kwargs=plugin_kwargs
    )


# The public home of this factory is ``watchlight.deepagents``: its repr,
# pickle and ``inspect.getmodule`` name it there. (A traceback shows the file
# the code is in, this one.)
governed_plugin.__module__ = "watchlight.deepagents"
