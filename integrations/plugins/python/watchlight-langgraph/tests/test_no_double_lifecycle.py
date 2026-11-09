"""Integration — LangGraph callback handler dedup contract.

Verifies the end-to-end behaviour: when a translated
``execution_completed`` / ``execution_failed`` lands via the
:meth:`WatchlightCallbackHandler.flush` → ``apdp.publish_events``
path AND the customer's framework subsequently closes the handle via
:meth:`BaseRunHandle.complete` / :meth:`BaseRunHandle.terminate`, the
audit trail carries EXACTLY ONE terminal lifecycle event for the
handle's :attr:`execution_id` — no double-emit.

This is the LangGraph-specific lane of the lifecycle-dedup
integration matrix; the cross-plugin invariant is exercised in the
``watchlight_core`` test suite.
"""

from __future__ import annotations

from typing import Any, Dict, List

import pytest

from watchlight_core import BaseRunHandle
from watchlight_core.telemetry import GovernanceTelemetry
from watchlight_core_testing import MockApdpClient
from watchlight_langgraph.callbacks import WatchlightAsyncCallbackHandler


class _Plugin(GovernanceTelemetry):
    def __init__(self) -> None:
        super().__init__()
        self.apdp = MockApdpClient()
        self.tenant_id = "tenant-langgraph"
        self.log_decisions = False
        self.kill_signal_registry = None


class _LangGraphLikeHandle(BaseRunHandle):
    """Stand-in for `watchlight_langgraph.RunHandle` with the
    canonical ``langgraph.workload`` source tag so the defensive
    emit's ``metadata.source`` satisfies the source-attribution
    conformance invariant.
    """

    _observation_source = "langgraph.workload"


def _completion_events(
    events: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    return [e for e in events if e.get("event_type") == "execution_completed"]


def _failure_events(
    events: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    return [e for e in events if e.get("event_type") == "execution_failed"]


@pytest.mark.asyncio
async def test_callback_flush_then_handle_complete_no_double() -> None:
    """When the LangGraph callback handler's ``flush()`` emits the
    translated ``execution_completed`` (the framework path), and the
    customer's `async with` block exits cleanly (triggering
    ``handle.complete()`` via ``__aexit__``), the audit trail carries
    EXACTLY ONE ``execution_completed`` event."""
    plugin = _Plugin()
    handle = _LangGraphLikeHandle(
        plugin=plugin,
        agent_uuid="agent-uuid-langgraph",
        session_id="ses_lg_001",
        execution_id="exec_lg_test",
    )
    handler = WatchlightAsyncCallbackHandler(
        apdp_client=plugin.apdp,
        execution_id=handle.execution_id,
        agent_id=handle.agent_uuid,
        session_id=handle.session_id,
        tenant_id=plugin.tenant_id,
        run_handle=handle,
    )

    # Simulate the callback path: capture a top-level on_chain_end
    # and flush.
    handler._buffer.append(
        {
            "hook": "on_chain_start",
            "name": "test-graph",
            "run_id": "run-1",
            "parent_run_id": None,
            "ts": 0.0,
        }
    )
    handler._buffer.append(
        {
            "hook": "on_chain_end",
            "name": "test-graph",
            "run_id": "run-1",
            "parent_run_id": None,
            "ts": 1.0,
            "duration_ms": 1000,
            "actions_taken": 1,
        }
    )
    flushed = await handler.flush()
    assert flushed >= 2  # at least started + completed

    # Now close the handle as the customer's `async with` would.
    await handle.complete()

    events = _completion_events(plugin.apdp.published_events)
    assert len(events) == 1, (
        f"expected exactly one execution_completed, got {len(events)}: "
        f"{[e.get('metadata', {}).get('source') for e in events]}"
    )
    # The single emit is the framework's (the handler's flush set the
    # ``mark_execution_completed_emitted`` before publishing). The
    # exact framework-tag prefix is owned by the translator
    # (``langgraph.callback``); the load-bearing assertion is that
    # there's only ONE emit and it's from the framework lane, not the
    # SDK fallback.
    source = str(events[0]["metadata"]["source"])
    assert source.startswith("langgraph."), source
    assert "run_handle_close" not in source, (
        "SDK defensive emit must be suppressed when callback fired first"
    )


@pytest.mark.asyncio
async def test_callback_flush_then_handle_terminate_no_double() -> None:
    """When the callback's ``flush()`` emits a translated
    ``execution_failed`` (from ``on_chain_error``) and the customer's
    exception path calls ``handle.terminate()``, the audit trail
    carries EXACTLY ONE ``execution_failed`` event.
    """
    plugin = _Plugin()
    handle = _LangGraphLikeHandle(
        plugin=plugin,
        agent_uuid="agent-uuid-langgraph",
        session_id="ses_lg_002",
        execution_id="exec_lg_fail",
    )
    handler = WatchlightAsyncCallbackHandler(
        apdp_client=plugin.apdp,
        execution_id=handle.execution_id,
        agent_id=handle.agent_uuid,
        session_id=handle.session_id,
        tenant_id=plugin.tenant_id,
        run_handle=handle,
    )

    handler._buffer.append(
        {
            "hook": "on_chain_error",
            "name": "test-graph",
            "run_id": "run-1",
            "parent_run_id": None,
            "ts": 1.0,
            "error_class": "RuntimeError",
            "error_message": "synthetic failure",
        }
    )
    await handler.flush()

    await handle.terminate(reason="run_failed: RuntimeError")

    events = _failure_events(plugin.apdp.published_events)
    assert len(events) == 1
    source = str(events[0]["metadata"]["source"])
    assert source.startswith("langgraph."), source
    assert "run_handle_terminate" not in source, (
        "SDK defensive emit must be suppressed when callback fired first"
    )


@pytest.mark.asyncio
async def test_handle_complete_without_callback_emit_still_lands() -> None:
    """The defensive SDK emit fires when the customer never wired a
    callback handler (the historical Bedrock / MSAF / Pydantic-AI
    top-level gap). The audit trail contains the SDK's
    ``execution_completed`` so the row transitions from ``started``
    to ``completed`` on the projection side.
    """
    plugin = _Plugin()
    handle = _LangGraphLikeHandle(
        plugin=plugin,
        agent_uuid="agent-uuid-langgraph",
        session_id="ses_lg_003",
        execution_id="exec_lg_solo",
    )
    # No callback handler wired — straight to close.
    await handle.complete()

    events = _completion_events(plugin.apdp.published_events)
    assert len(events) == 1
    assert (
        events[0]["metadata"]["source"]
        == "langgraph.run_handle_close"
    )
    assert events[0]["execution_id"] == "exec_lg_solo"


@pytest.mark.asyncio
async def test_callback_without_run_handle_falls_back_to_sdk_emit() -> None:
    """A callback handler constructed WITHOUT a ``run_handle=...``
    (legacy callers that predate the run_handle wiring) MUST keep
    working — its flush translates events as before; the customer's subsequent
    ``handle.complete()`` then fires the SDK's defensive emit (so
    TWO ``execution_completed`` events land for legacy code paths,
    which is the deliberate backwards-compat trade-off: the projection
    layer's ``ON CONFLICT`` makes both writes idempotent on the
    ``lineage.executions`` row).
    """
    plugin = _Plugin()
    handle = _LangGraphLikeHandle(
        plugin=plugin,
        agent_uuid="agent-uuid-langgraph",
        session_id="ses_lg_004",
        execution_id="exec_lg_legacy",
    )
    # Legacy constructor — no run_handle wiring.
    handler = WatchlightAsyncCallbackHandler(
        apdp_client=plugin.apdp,
        execution_id=handle.execution_id,
        agent_id=handle.agent_uuid,
        session_id=handle.session_id,
        tenant_id=plugin.tenant_id,
        # run_handle intentionally omitted
    )
    handler._buffer.append(
        {
            "hook": "on_chain_start",
            "name": "g",
            "run_id": "r",
            "parent_run_id": None,
            "ts": 0.0,
        }
    )
    handler._buffer.append(
        {
            "hook": "on_chain_end",
            "name": "g",
            "run_id": "r",
            "parent_run_id": None,
            "ts": 1.0,
            "duration_ms": 10,
            "actions_taken": 0,
        }
    )
    await handler.flush()
    await handle.complete()

    # Two events land — projection layer dedupes via the upsert.
    events = _completion_events(plugin.apdp.published_events)
    assert len(events) == 2
