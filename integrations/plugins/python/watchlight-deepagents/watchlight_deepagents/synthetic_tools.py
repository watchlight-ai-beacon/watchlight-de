"""Synthetic ``watchlight.declare_intent`` tool for greenfield mode.

Reuses the ``watchlight_core`` framework-agnostic primitives (the tool
contract, the ``handle_declare_intent_call`` side-effect, the
mode-resolution helper) and bridges them into a LangChain
:class:`langchain_core.tools.StructuredTool` — the same shape
``deepagents`` (via LangChain) expects on the middleware ``tools`` slot.

The load-bearing detail: the tool closes over a **handle getter**, not a
handle — the run handle does not exist at graph-construction time (when
the middleware's ``tools`` attribute is read). The getter resolves the
active handle at *invocation* time. The tool's invocation NEVER
round-trips to ``authorize_action`` (the declare_intent carve-out): the middleware's
``wrap_tool_call`` short-circuits it via ``is_declare_intent_tool_name``,
and the tool body calls ``handle_declare_intent_call`` directly.

Brownfield mode (the locked default) injects nothing — the returned list
is empty and the model never sees the tool.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional

from watchlight_core import (
    DECLARE_INTENT_TOOL_DESCRIPTION,
    DECLARE_INTENT_TOOL_NAME,
    get_logger,
    handle_declare_intent_call,
    should_inject_synthetic_tool,
)

logger = get_logger("watchlight_deepagents.synthetic_tools")


def build_declare_intent_tool(
    *,
    mode: Optional[str],
    handle_getter: Callable[[], Any],
) -> List[Any]:
    """Return the synthetic-tool list for the effective enforcement mode.

    Empty in brownfield. In greenfield: a one-element list with the
    ``watchlight.declare_intent`` :class:`StructuredTool`, whose callable
    resolves the active handle via ``handle_getter`` at invocation time
    and stamps the declared objective onto it.
    """
    if not should_inject_synthetic_tool(mode):
        return []

    try:
        from langchain_core.tools import StructuredTool
    except ImportError:  # pragma: no cover — defensive
        logger.debug("langchain_core not importable; skipping synthetic tool")
        return []

    def declare_intent(objective: str, category: str, justification: Optional[str] = None) -> Dict[str, Any]:
        """Declare your goal for this session.

        ``category`` is one of ``watchlight_core.INTENT_CATEGORIES`` or
        ``custom:<name>`` (wl-apdp requires it). Stamps the declared
        objective and category on the audit log and propagates them
        to authorization decisions so the greenfield Cedar gate clears.
        """
        handle = handle_getter()
        if handle is None:
            return {
                "status": "error",
                "error": "no active Watchlight run handle for declare_intent",
            }
        return handle_declare_intent_call(
            handle, {"objective": objective, "category": category, "justification": justification}
        )

    async def adeclare_intent(objective: str, category: str, justification: Optional[str] = None) -> Dict[str, Any]:
        """Async variant — see sync docstring."""
        return declare_intent(objective, category, justification)

    tool = StructuredTool.from_function(
        func=declare_intent,
        coroutine=adeclare_intent,
        name=DECLARE_INTENT_TOOL_NAME,
        description=DECLARE_INTENT_TOOL_DESCRIPTION,
        infer_schema=True,
    )
    return [tool]


__all__ = ["build_declare_intent_tool"]
