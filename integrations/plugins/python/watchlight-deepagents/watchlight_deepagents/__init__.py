"""Watchlight deepagents — governance plugin for LangChain ``deepagents``.

``deepagents`` is LangChain's opinionated agent harness built on
``langchain.agents.create_agent`` + a LangGraph runtime. It standardises
on the ``AgentMiddleware`` protocol and exposes a first-class
``middleware=`` insertion slot, so this plugin is **auto-registering** —
no monkey-patching, zero customer tool-code changes.

Two integration surfaces:

**Drop-in factory (recommended)** ::

    from watchlight_deepagents import create_governed_deep_agent

    agent = create_governed_deep_agent(
        model="anthropic:claude-sonnet-4",
        tools=[search, fetch],
        subagents=[researcher],
        agent_slug="research-orchestrator",   # the ONE required extra arg
    )

**Explicit middleware — ROOT-ONLY** (for customers who build their own
``middleware=`` and do **not** delegate to sub-agents) ::

    from deepagents import create_deep_agent
    from watchlight_deepagents import WatchlightDeepAgentsPlugin

    wl = WatchlightDeepAgentsPlugin.from_env()
    agent = create_deep_agent(
        ..., middleware=[wl.middleware(agent_slug="research-orchestrator")]
    )

.. warning::

   This "Option B" path governs the **root agent only**. deepagents does
   not propagate the root ``middleware=`` list into sub-agents, so this
   path cannot attenuate them — it therefore **refuses every ``task``
   sub-agent spawn** (fail-closed). Any agent that delegates to
   sub-agents MUST be built with :func:`create_governed_deep_agent`,
   which injects child governance into every spawnable sub-agent
   (including deepagents' otherwise-ungoverned auto ``general-purpose``).

With the factory, every model turn, every FS/tool/task call, and every
sub-agent action is governed, authorized against the correct (root or
attenuated-child) RunHandle, audited, and — with ``WATCHLIGHT_PROXY_URL``
set — egress-enforced at wl-proxy.
"""

from watchlight_core.langchain_tool_backstop import (
    UngovernedModelCall,
    UngovernedToolCall,
    direct_model_use,
)
from watchlight_deepagents.factory import create_governed_deep_agent
from watchlight_deepagents.middleware import (
    STATE_TOKEN_KEY,
    build_governance_middleware,
    current_active_handle,
)
from watchlight_deepagents.plugin import RunHandle, WatchlightDeepAgentsPlugin
from watchlight_deepagents.state_adapter import state_from_deepagents_plugin
from watchlight_deepagents.subagents import (
    GENERAL_PURPOSE_SUBAGENT_NAME,
    TASK_TOOL_NAME,
    ensure_general_purpose_subagent,
    inject_child_governance_middleware,
    requested_scope_for_subagent,
    resolve_subagent_slug,
)
from watchlight_deepagents.synthetic_tools import build_declare_intent_tool
from watchlight_deepagents.traces import (
    redacted_arg_metadata,
    redacted_input_summary,
    resolve_action_verb,
    task_resource_uri,
    tool_resource_uri,
)

__all__ = [
    "WatchlightDeepAgentsPlugin",
    "RunHandle",
    "create_governed_deep_agent",
    "direct_model_use",
    "UngovernedModelCall",
    "UngovernedToolCall",
    "build_governance_middleware",
    "current_active_handle",
    "STATE_TOKEN_KEY",
    "state_from_deepagents_plugin",
    "TASK_TOOL_NAME",
    "GENERAL_PURPOSE_SUBAGENT_NAME",
    "resolve_subagent_slug",
    "requested_scope_for_subagent",
    "ensure_general_purpose_subagent",
    "inject_child_governance_middleware",
    "build_declare_intent_tool",
    "resolve_action_verb",
    "tool_resource_uri",
    "task_resource_uri",
    "redacted_arg_metadata",
    "redacted_input_summary",
]
__version__ = "0.1.2"
