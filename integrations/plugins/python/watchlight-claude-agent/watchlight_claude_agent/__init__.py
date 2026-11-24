"""Watchlight governance plugin for the Claude Agent SDK.

Target framework:
https://code.claude.com/docs/en/agent-sdk/overview — Anthropic's
official Claude Agent SDK (Python).

# Public surface

- :class:`WatchlightClaudeAgentSDKPlugin` — instantiated by customer
  code; calls :meth:`start_run(agent_slug)` to open a governed
  session.
- :class:`RunHandle` — inherits the full lifecycle from
  :class:`watchlight_core.BaseRunHandle`.
- :func:`translate_claude_agent_event(s)` — translator that maps
  Claude-Agent-SDK hook captures (PreToolUse, PostToolUse,
  UserPromptSubmit, Stop, SubagentStart, SubagentStop) to canonical
  :class:`watchlight_core.ExecutionEvent` shapes.

# Quickstart

The Python SDK has no plugin-loader contract, so enforcement ships as
a hook map. ``plugin.governed_options(handle, options)`` merges the
Watchlight ``PreToolUse`` / ``SubagentStart`` / ``SubagentStop`` hooks
into your ``ClaudeAgentOptions``: every tool call is authorized before
it runs, and a ``Task``/``Agent`` call performs the governed sub-agent
spawn first and is denied when the spawn is refused.

::

    from claude_agent_sdk import ClaudeAgentOptions
    from watchlight_claude_agent import WatchlightClaudeAgentSDKPlugin

    plugin = WatchlightClaudeAgentSDKPlugin(
        apdp_url=os.environ["WATCHLIGHT_APDP_URL"],
        apdp_api_key=os.environ["WATCHLIGHT_API_KEY"],
        connect_proxy_url=os.environ.get("WATCHLIGHT_PROXY_URL"),
    )

    async with await plugin.start_run("my-claude-agent") as handle:
        async for message in plugin.governed_query(
            handle, prompt="...", options=ClaudeAgentOptions()
        ):
            ...
"""

from .intent import (
    extract_intent_from_user_prompt_submit,
    truncate_intent_objective,
)
from .hooks import (
    SUBAGENT_TOOL_NAMES,
    GovernanceHookGate,
    deny_output,
    is_deny_output,
)
from .plugin import RunHandle, WatchlightClaudeAgentSDKPlugin
from .session_guard import GovernanceBypassDetected, UngovernableSession
from .subagents import (
    derive_requested_scope,
    parent_key_from_capture,
    subagent_id_from_capture,
    subagent_slug_from_capture,
)
from .synthetic_tools import (
    DECLARE_INTENT_RESPONSE_STATUS,
    DECLARE_INTENT_TOOL_NAME,
    WATCHLIGHT_DECLARE_INTENT_TOOL,
    intercept_tool_call,
    is_synthetic_tool_capture,
    merge_synthetic_tools,
    synthetic_tool_definitions,
)
from .traces import (
    SOURCE_TAG,
    URI_SCHEME,
    translate_claude_agent_event,
    translate_claude_agent_events,
)

__all__ = [
    "WatchlightClaudeAgentSDKPlugin",
    "RunHandle",
    "GovernanceBypassDetected",
    "UngovernableSession",
    # Shipped enforcement hooks
    "GovernanceHookGate",
    "SUBAGENT_TOOL_NAMES",
    "deny_output",
    "is_deny_output",
    "translate_claude_agent_event",
    "translate_claude_agent_events",
    "SOURCE_TAG",
    "URI_SCHEME",
    # Intent-objective extraction helpers
    "extract_intent_from_user_prompt_submit",
    "truncate_intent_objective",
    # Synthetic declare_intent tool injection
    "DECLARE_INTENT_RESPONSE_STATUS",
    "DECLARE_INTENT_TOOL_NAME",
    "WATCHLIGHT_DECLARE_INTENT_TOOL",
    "intercept_tool_call",
    "is_synthetic_tool_capture",
    "merge_synthetic_tools",
    "synthetic_tool_definitions",
    # Native Task sub-agent governed-spawn wiring helpers
    "derive_requested_scope",
    "subagent_id_from_capture",
    "subagent_slug_from_capture",
    "parent_key_from_capture",
]

__version__ = "0.3.2"
