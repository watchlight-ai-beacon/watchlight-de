"""Watchlight LangGraph — Governance plugin for LangGraph plan-and-execute agents.

Provides governance primitives — `start_run`, `submit_plan`,
`preflight_step`, `authorize_action`, `complete` — that the customer
threads into their LangGraph topology. Unlike the Google ADK plugin
(register-and-forget callbacks), LangGraph's extensibility is via graph
composition, so we expose explicit primitives and let the customer wire
them into the nodes that need governance.

Example::

    from watchlight_langgraph import WatchlightLangGraphPlugin

    wl = WatchlightLangGraphPlugin(apdp_url="http://localhost:8081")

    async def run_agent(question: str):
        async with await wl.start_run(agent_slug="research-analyst") as handle:
            state = await graph.ainvoke({"input": question})
            result = await handle.submit_plan(state["plan"])
            if result.is_deny():
                raise PermissionError(f"Plan denied: {result.violations}")
            if result.is_modify():
                state["plan"] = result.modified_plan
            # ... continue execution

The plugin populates the same `last_*` attributes as the Google ADK
plugin (`watchlight_adk`) so a shared governance-card UI widget can
render both frameworks identically.
"""

from watchlight_langgraph.apdp_client import ApdpClient
from watchlight_langgraph.callbacks import (
    WatchlightAsyncCallbackHandler,
    WatchlightCallbackHandler,
    WatchlightHandlerBase,
    active_handler,
    attached_handler,
    ensure_configure_hook_registered,
    fresh_execution_id,
    reset_active_handler,
    set_active_handler,
)
from watchlight_langgraph.plugin import (
    AgentNotRegistered,
    GovernanceUnavailable,
    PlanResult,
    PreflightResult,
    RunHandle,
    WatchlightError,
    WatchlightLangGraphPlugin,
    governance_mode,
)
from watchlight_langgraph.state_adapter import state_from_langgraph_plugin
from watchlight_langgraph.tool_gate import SiblingSubagentLive
from watchlight_langgraph.synthetic_tools import (
    build_synthetic_langchain_tools,
    merge_customer_tools_with_synthetic,
    should_skip_authorize_for_tool_call,
)
from watchlight_langgraph.traces import (
    translate_langgraph_event,
    translate_langgraph_events,
)

__all__ = [
    "ApdpClient",
    "AgentNotRegistered",
    "GovernanceUnavailable",
    "PlanResult",
    "PreflightResult",
    "RunHandle",
    "SiblingSubagentLive",
    "WatchlightAsyncCallbackHandler",
    "WatchlightCallbackHandler",
    "WatchlightError",
    "WatchlightHandlerBase",
    "WatchlightLangGraphPlugin",
    "active_handler",
    "attached_handler",
    "build_synthetic_langchain_tools",
    "ensure_configure_hook_registered",
    "fresh_execution_id",
    "governance_mode",
    "merge_customer_tools_with_synthetic",
    "reset_active_handler",
    "set_active_handler",
    "should_skip_authorize_for_tool_call",
    "state_from_langgraph_plugin",
    "translate_langgraph_event",
    "translate_langgraph_events",
]
__version__ = "0.5.1"
