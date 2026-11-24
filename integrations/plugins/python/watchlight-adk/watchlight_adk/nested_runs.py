"""Tool calls that would run an ADK agent outside the plugin's reach.

A Runner that a tool body builds gets only the plugins it is given, and ADK
has no global plugin registry or other public hook through which this
plugin could reach it. An agent such a Runner runs is not governed: its
tools run with no decision. So before a tool runs, the plugin refuses the
call when:

* the tool's code can build a ``Runner``, an ``App``, a ``Workflow`` or an
  agent (any ``BaseAgent`` subclass, ``LlmAgent`` included), read without
  running it through the shared ``watchlight_core.agent_construction``
  check;
* the code can run an agent under an invocation it makes itself: it names
  ``PluginManager`` or ``InvocationContext``, or reaches the run's
  invocation context (``_invocation_context``, ``get_invocation_context``,
  ``plugin_manager``), from which ``held.run_async(ctx.model_copy(...))``
  could run a held agent with the plugins stripped;
* the tool is an ``AgentTool`` with ``include_plugins=False``, whose child
  Runner gets no plugins. A subclass of ``AgentTool`` is read like any other
  tool, since it can override how the child runs.

An agent instance the code only refers to is not refused.

What the read cannot see runs ungoverned: a class or the invocation context
reached by indirection (``getattr`` with a string, ``vars()``,
``sys.modules``, an instance attribute, a tool argument or session state),
or a factory in an installed package that does not import ADK. In
particular, a tool can reach the run's invocation context by
``getattr(tool_context, "_invocation_context")``, copy it with the plugins
replaced, and run an agent it holds. The runtime backstop in
``run_backstop`` refuses what the read misses: while a governed run is live,
an agent, a tool-binding model turn or a tool call outside the plugin's reach
is refused before it runs.
"""

from __future__ import annotations

from typing import Any, Callable, Optional

from google.adk import Runner, Workflow
from google.adk.agents import BaseAgent
from google.adk.agents.invocation_context import InvocationContext
from google.adk.apps import App
from google.adk.plugins.plugin_manager import PluginManager
from google.adk.tools.agent_tool import AgentTool
from google.adk.tools.function_tool import FunctionTool
from watchlight_core.agent_construction import Builders, can_build_agents

_BUILDER_TYPES = (Runner, App, Workflow, BaseAgent, PluginManager, InvocationContext)

#: How tool code reaches the run's invocation context or its plugins.
_CONTEXT_NAMES = frozenset({"_invocation_context", "get_invocation_context", "plugin_manager"})


def _builds(obj: Any) -> bool:
    return isinstance(obj, type) and issubclass(obj, _BUILDER_TYPES)


def _held(obj: Any) -> bool:
    return isinstance(obj, BaseAgent)


def _function_of(obj: Any) -> Optional[Callable[..., Any]]:
    """The function behind a ``FunctionTool``, read from the instance
    dictionary (no attribute hook runs)."""
    if not isinstance(obj, FunctionTool):
        return None
    try:
        func = object.__getattribute__(obj, "__dict__").get("func")
    except AttributeError:
        return None
    return func if callable(func) else None


ADK_BUILDERS = Builders(
    prefixes=("google.adk",),
    builds=_builds,
    held=_held,
    tool_function=_function_of,
    refused_names=_CONTEXT_NAMES,
)


def nested_run_refusal(tool: Any) -> Optional[str]:
    """Why a call of ``tool`` would run an agent the plugin cannot govern,
    or ``None``. Fails closed: a read that cannot finish refuses."""
    if isinstance(tool, AgentTool):
        try:
            include = object.__getattribute__(tool, "__dict__").get("include_plugins", True)
        except AttributeError:
            include = None
        if include is not True:
            return "an AgentTool with include_plugins=False runs its agent without Watchlight"
        if type(tool) is AgentTool:
            return None
    if can_build_agents(tool, ADK_BUILDERS):
        return "the tool's code can build an agent or Runner Watchlight cannot reach"
    return None
