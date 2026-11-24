"""Watchlight governance plugin for Strands Agents.

Target framework: https://github.com/strands-agents/sdk-python (the
``strands-agents`` package). Independent plugin, not affiliated with or
endorsed by Amazon Web Services.

Public surface:

  * :class:`WatchlightStrandsPlugin` — install it once, on the root agent or
    Swarm/Graph orchestrator (``plugins=[...]`` or ``hooks=[...]``). It
    attaches itself to every child the root reaches, opens a governed run
    for every invocation, authorizes every tool call before it runs, and
    runs children as attenuated governed spawns, fail-closed.
  * :class:`RunHandle` — the run handle the plugin opens; also returned by
    ``WatchlightStrandsPlugin.start_run``.
  * :func:`governing_plugin` — the Watchlight plugin governing a Strands
    object, or ``None``.
  * :class:`AgentNotIdentified`, :class:`UngovernableChild` — the refusals
    for an agent with no governed identity and a child that cannot be
    attached.
  * :data:`APPROVAL_INTERRUPT_NAME` — the name of the Strands interrupt
    raised when a tool call needs human approval.
  * :func:`translate_strands_event(s)` — map captured hook data to
    canonical :class:`watchlight_core.ExecutionEvent` shapes.
  * :func:`state_from_strands_plugin` — adapter for the Watchlight Beacon
    dashboard's governance card.
"""

from .plugin import (
    APPROVAL_INTERRUPT_NAME,
    AgentNotIdentified,
    RunHandle,
    UngovernableChild,
    WatchlightStrandsPlugin,
    governing_plugin,
    labelled_spawn_supported,
)
from .model_backstop import direct_model_use
from .state_adapter import state_from_strands_plugin
from .traces import (
    SOURCE_TAG,
    URI_SCHEME,
    translate_strands_event,
    translate_strands_events,
)

__all__ = [
    "APPROVAL_INTERRUPT_NAME",
    "SOURCE_TAG",
    "URI_SCHEME",
    "AgentNotIdentified",
    "RunHandle",
    "UngovernableChild",
    "WatchlightStrandsPlugin",
    "direct_model_use",
    "governing_plugin",
    "labelled_spawn_supported",
    "state_from_strands_plugin",
    "translate_strands_event",
    "translate_strands_events",
]

__version__ = "0.1.2"
