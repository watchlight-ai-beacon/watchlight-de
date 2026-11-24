"""Watchlight governance plugin for Pydantic AI.

Target framework:
https://github.com/pydantic/pydantic-ai — the official Pydantic AI
agent framework.

Public surface:

  * :class:`WatchlightPydanticAIPlugin` — instantiated by customer
    code; calls ``start_run(agent_slug)`` to open a governed session.
    Constructing the plugin auto-installs runtime instrumentation
    that stitches every nested ``Agent.run()`` into one lineage tree
    under one workflow root, with each sub-agent's tool calls
    authorized against the sub-agent's own principal.
  * :func:`guarded_tool` — authorization-pre-call tool decorator;
    each call is authorized on the run (or sub-agent) driving the
    agent at call time.
  * :class:`RunHandle` — adds :meth:`RunHandle.guarded_tool`
    (deprecated; resolves the current run at call time) and :meth:`RunHandle.spawn_subagent` (explicit
    child-handle primitive, also called automatically by the
    runtime instrumentation).
  * :func:`current_handle` — read the active handle for diagnostics
    + customer code that wants to surface "what run am I in?".
  * :func:`uninstall_instrumentation` — restore the original
    ``pydantic_ai.Agent`` entry points. Useful for tests + customer
    cleanup paths.
  * :func:`translate_pydantic_ai_event(s)` — translator that maps
    Pydantic AI's tool-event captures to canonical
    :class:`watchlight_core.ExecutionEvent` shapes.
  * :func:`state_from_pydantic_ai_plugin` — adapter for the
    Watchlight Beacon dashboard's governance card.
"""

from .instrumentation import (
    current_handle,
    inject_synthetic_tools,
    install_instrumentation,
    is_instrumented,
    uninstall_instrumentation,
)
from .intent import extract_intent_from_pydantic_args
from .plugin import RunHandle, WatchlightPydanticAIPlugin, guarded_tool
from .state_adapter import state_from_pydantic_ai_plugin
from .traces import (
    SOURCE_TAG,
    URI_SCHEME,
    translate_pydantic_ai_event,
    translate_pydantic_ai_events,
)

__all__ = [
    "WatchlightPydanticAIPlugin",
    "RunHandle",
    "guarded_tool",
    "current_handle",
    "extract_intent_from_pydantic_args",
    "inject_synthetic_tools",
    "install_instrumentation",
    "is_instrumented",
    "uninstall_instrumentation",
    "translate_pydantic_ai_event",
    "translate_pydantic_ai_events",
    "state_from_pydantic_ai_plugin",
    "SOURCE_TAG",
    "URI_SCHEME",
]

__version__ = "0.4.1"
