"""Watchlight plugin template — fork this, rename, fill the TODOs.

Public surface:

  * :class:`WatchlightTemplatePlugin` — instantiate in customer code:
    ``plugin = WatchlightTemplatePlugin(apdp_url="https://apdp.your-org")``.
  * :class:`RunHandle` — returned by ``plugin.start_run()``; the
    customer threads this through their framework-specific lifecycle.
  * :func:`translate_template_event(s)` — pure functions that map
    framework callbacks to canonical
    :class:`watchlight_core.ExecutionEvent` dicts.
  * :func:`state_from_template_plugin` — adapter for the Watchlight
    Beacon dashboard's governance card.

When you fork: rename ``template`` → your framework's name and update
:data:`SOURCE_TAG` to the canonical T-RD9 tag the conformance suite
will assert on.
"""

from .plugin import RunHandle, WatchlightTemplatePlugin
from .state_adapter import state_from_template_plugin
from .traces import (
    SOURCE_TAG,
    URI_SCHEME,
    dropped_event_counts,
    translate_template_event,
    translate_template_events,
)

__all__ = [
    "WatchlightTemplatePlugin",
    "RunHandle",
    "translate_template_event",
    "translate_template_events",
    "dropped_event_counts",
    "state_from_template_plugin",
    "SOURCE_TAG",
    "URI_SCHEME",
]

__version__ = "0.1.0"
