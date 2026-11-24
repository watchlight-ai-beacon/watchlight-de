"""Watchlight event translator for the Microsoft Agent Framework (MAF).

This package only translates events: it does not hook into MAF, does not
call an authorization backend, and never blocks or denies an action.
Authorization is the caller's job, through ``watchlight-agent-sdk``.

This package translates Microsoft Agent Framework (MAF) lifecycle
events into canonical Watchlight :class:`ExecutionEvent` dicts. It
mirrors the surface of the other framework plugins
(:mod:`watchlight_langgraph`, :mod:`watchlight_bedrock`,
:mod:`watchlight_adk`):

- :func:`translate_msaf_event` — single-capture translator
- :func:`translate_msaf_events` — batch translator preserving order

The translator is a pure function and doesn't import the MAF SDK
itself. The optional ``msaf`` extra installs only the framework; no
middleware shim ships yet, so the caller builds the capture dicts this
package consumes. That split lets the translator's unit tests run
without pulling in the heavy MAF runtime, and lets operators on
different MAF release cadences pin compatible versions.

Current scope:

- ``ChatAgent`` + ``Workflow`` lifecycle events
- Plan emission via the canonical ``plan_observed`` event, driven
  from the per-step pre-tool hook
- Tool invocation events with a bounded ``arg_key_summary`` (argument
  key names only, never values)

Deferred to a follow-up release:

- DurableExecution checkpoint events
- Multi-agent FSM orchestration events
- Real OTLP exporter wiring (the ``otlp`` extra installs the deps but
  the wiring lands later)

Provenance: every event carries ``metadata.source = "msaf.callback"``.
Resource URIs use the ``msaf://`` scheme so downstream consumers can
distinguish MAF tool calls from LangGraph / ADK / Bedrock / MCP.
"""

from .traces import translate_msaf_event, translate_msaf_events

__all__ = [
    "translate_msaf_event",
    "translate_msaf_events",
]

__version__ = "0.1.1"
