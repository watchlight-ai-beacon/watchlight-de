"""Tests for `WatchlightCallbackHandler` + `WatchlightAsyncCallbackHandler`
plus the `RunHandle.callback_handler()` integration."""

from __future__ import annotations

from typing import Any, Dict, List
from unittest.mock import AsyncMock, MagicMock

import pytest

from watchlight_langgraph import (
    RunHandle,
    WatchlightAsyncCallbackHandler,
    WatchlightCallbackHandler,
)


# ─── Fixtures ──────────────────────────────────────────────────────────


# In-process stand-in for unit tests only.
class _StubApdp:
    """Mock ApdpClient that records published-event batches."""

    def __init__(self, succeed: bool = True):
        self.succeed = succeed
        self.published_batches: List[List[Dict[str, Any]]] = []

        async def _capture(run, events):
            # The SDK names the run on the emission path; accept + record it.
            self.published_batches.append(list(events))
            self.last_run = run
            return self.succeed

        self.publish_events = AsyncMock(side_effect=_capture)


def _build_handler(
    *,
    async_handler: bool = False,
    succeed_publish: bool = True,
    execution_id: str = "exec_test",
    parent_execution_id: str = None,
):
    """Construct a handler with a stub APDP client."""
    apdp = _StubApdp(succeed=succeed_publish)
    cls = WatchlightAsyncCallbackHandler if async_handler else WatchlightCallbackHandler
    handler = cls(
        apdp_client=apdp,
        execution_id=execution_id,
        agent_id="agent-1",
        session_id="sess_42",
        tenant_id="acme",
        parent_execution_id=parent_execution_id,
    )
    return handler, apdp


def _build_run_handle():
    """Bypass the production constructor — populate the fields
    the callback_handler() factory method reads."""
    plugin = MagicMock()
    plugin.apdp = _StubApdp()
    plugin.tenant_id = "acme"
    handle = RunHandle.__new__(RunHandle)
    handle._plugin = plugin
    handle.agent_uuid = "agent-1"
    handle.session_id = "sess_42"
    handle._completed = False
    # Every real handle carries a canonical ``execution_id`` (minted in
    # ``BaseRunHandle.__init__``). ``callback_handler()`` now defaults
    # its execution_id to this value so the callback stream shares the
    # handle's canonical root (see ``test_lineage_single_root_execution_id``).
    handle.execution_id = "exec_root-fixture"
    return handle


# ─── Buffering + capture behavior ─────────────────────────────────────


def test_handler_starts_with_empty_buffer():
    handler, _ = _build_handler()
    assert handler.buffered_count() == 0
    assert handler.snapshot() == []


def test_on_chain_start_captures_into_buffer():
    handler, _ = _build_handler()
    handler.on_chain_start(
        serialized={"name": "agent"}, inputs={"q": "x"}, run_id="r1"
    )
    assert handler.buffered_count() == 1
    captured = handler.snapshot()
    assert captured[0]["hook"] == "on_chain_start"
    assert captured[0]["name"] == "agent"


def test_on_tool_start_and_end_capture():
    handler, _ = _build_handler()
    handler.on_tool_start(
        serialized={"name": "search"},
        input_str="hello",
        run_id="r1",
        parent_run_id="root",
    )
    handler.on_tool_end(output="world", run_id="r1", parent_run_id="root", name="search")
    captured = handler.snapshot()
    assert len(captured) == 2
    assert captured[0]["hook"] == "on_tool_start"
    assert captured[1]["hook"] == "on_tool_end"


def test_on_tool_start_buffers_no_argument_value():
    handler, _ = _build_handler()
    handler.on_tool_start(
        serialized={"name": "send"},
        input_str="{'token': 'sk-live-SECRET'}",
        inputs={"token": "sk-live-SECRET"},
        run_id="r1",
        parent_run_id="root",
    )
    captured = handler.snapshot()
    assert "sk-live-SECRET" not in repr(captured)
    assert captured[0]["input_summary"] == "1 args: token(str)"


def test_error_hook_captures_error_object():
    handler, _ = _build_handler()
    handler.on_tool_error(error=ValueError("oops"), run_id="r1")
    captured = handler.snapshot()
    assert captured[0]["hook"] == "on_tool_error"
    assert isinstance(captured[0]["error"], ValueError)


def test_agent_action_extracts_attributes_defensively():
    """on_agent_action receives an AgentAction object whose shape
    could shift across LangChain versions. The handler uses
    getattr to extract .tool and .tool_input, degrading to None
    if the object doesn't have them — never raising."""

    # In-process stand-in for unit tests only.
    class StubAction:
        tool = "search"
        tool_input = "Q3 revenue"
        log = "thought: ..."

    handler, _ = _build_handler()
    handler.on_agent_action(action=StubAction(), run_id="r1", parent_run_id="root")
    captured = handler.snapshot()
    assert captured[0]["hook"] == "on_agent_action"
    assert captured[0]["tool"] == "search"
    assert captured[0]["tool_input"] == "Q3 revenue"


def test_agent_action_with_missing_attributes_degrades_to_none():
    """Defense against future shape drift: an AgentAction-like
    object missing .tool / .tool_input shouldn't crash. The
    handler captures None for those fields."""

    class WeirdAction:
        pass

    handler, _ = _build_handler()
    handler.on_agent_action(action=WeirdAction(), run_id="r1", parent_run_id="root")
    captured = handler.snapshot()
    assert captured[0]["tool"] is None
    assert captured[0]["tool_input"] is None


# ─── Hook robustness — never raises ───────────────────────────────────


def test_hooks_never_raise_on_malformed_input():
    """LangChain callback machinery is the parent of these calls.
    A raised exception interrupts customer code. Every hook must
    catch broadly. This test exercises each hook with degenerate
    inputs and asserts none raise."""
    handler, _ = _build_handler()

    # None / unexpected types
    handler.on_chain_start(serialized=None, inputs=None)
    handler.on_chain_end(outputs=None)
    handler.on_chain_error(error=None)
    handler.on_tool_start(serialized=None, input_str=None)
    handler.on_tool_end(output=None)
    handler.on_tool_error(error=None)
    handler.on_llm_start(serialized=None, prompts=None)
    handler.on_chat_model_start(serialized=None, messages=None)
    handler.on_llm_error(error=None)
    handler.on_agent_action(action=None)
    handler.on_agent_finish(finish=None)
    # If we got here, no hook raised. That's the guarantee.


# ─── flush() behavior ─────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_flush_translates_and_publishes():
    handler, apdp = _build_handler()
    handler.on_chain_start(
        serialized={"name": "agent"}, inputs={"q": "x"}, run_id="r1", parent_run_id=None
    )
    handler.on_tool_start(
        serialized={"name": "search"},
        input_str="hello",
        run_id="r2",
        parent_run_id="r1",
    )
    handler.on_chain_end(outputs={"out": "ok"}, run_id="r1", parent_run_id=None)

    count = await handler.flush()
    assert count == 3

    assert len(apdp.published_batches) == 1
    published = apdp.published_batches[0]
    types = [e["event_type"] for e in published]
    assert types == ["execution_started", "tool_call_observed", "execution_completed"]


@pytest.mark.asyncio
async def test_flush_with_empty_buffer_returns_zero():
    handler, apdp = _build_handler()
    count = await handler.flush()
    assert count == 0
    # And no POST to /v1/events — saving an empty-list round trip.
    apdp.publish_events.assert_not_called()


@pytest.mark.asyncio
async def test_flush_drains_buffer():
    """After flush, the buffer is empty. Subsequent captures
    accumulate fresh."""
    handler, apdp = _build_handler()
    handler.on_chain_start(serialized={"name": "x"}, inputs={}, run_id="r1", parent_run_id=None)
    await handler.flush()
    assert handler.buffered_count() == 0

    handler.on_chain_end(outputs={}, run_id="r2", parent_run_id=None)
    assert handler.buffered_count() == 1


@pytest.mark.asyncio
async def test_flush_returns_zero_on_publish_failure():
    """Best-effort lineage: a publish failure returns 0; caller's
    success path never depends on the audit pipeline's health —
    governance-mechanism failures degrade gracefully."""
    handler, _ = _build_handler(succeed_publish=False)
    handler.on_chain_start(
        serialized={"name": "x"}, inputs={}, run_id="r1", parent_run_id=None
    )
    count = await handler.flush()
    assert count == 0


@pytest.mark.asyncio
async def test_flush_never_raises_on_apdp_exception():
    """If the APDP client itself throws, flush catches it and
    returns 0."""
    handler, apdp = _build_handler()
    apdp.publish_events.side_effect = RuntimeError("network down")
    handler.on_chain_start(
        serialized={"name": "x"}, inputs={}, run_id="r1", parent_run_id=None
    )
    count = await handler.flush()
    assert count == 0


@pytest.mark.asyncio
async def test_flush_drops_unmapped_events_without_publishing():
    """If the buffer only contains unmapped hooks (on_text etc.),
    the translation yields zero events. flush() returns 0 AND
    does NOT POST an empty list to APDP."""
    handler, apdp = _build_handler()
    # Inject capture events directly via the internal buffer
    # to simulate hooks our handler doesn't expose (defensive
    # against future LangChain versions adding hooks we don't
    # capture).
    handler._buffer.append({"hook": "on_text", "text": "noise"})
    handler._buffer.append({"hook": "on_llm_new_token", "token": "a"})
    count = await handler.flush()
    assert count == 0
    apdp.publish_events.assert_not_called()


# ─── Async handler parity ─────────────────────────────────────────────


@pytest.mark.asyncio
async def test_async_handler_captures_same_as_sync():
    """The async handler must produce wire-identical capture
    output to the sync handler for the same hook sequence. Both
    delegate to the same _capture_* free functions; this test
    pins the parity."""
    handler, apdp = _build_handler(async_handler=True)
    await handler.on_chain_start(
        serialized={"name": "agent"}, inputs={"q": "x"}, run_id="r1", parent_run_id=None
    )
    await handler.on_tool_start(
        serialized={"name": "search"}, input_str="hello", run_id="r2", parent_run_id="r1"
    )
    await handler.on_chain_end(outputs={"out": "ok"}, run_id="r1", parent_run_id=None)

    count = await handler.flush()
    assert count == 3


@pytest.mark.asyncio
async def test_async_handler_never_raises():
    handler, _ = _build_handler(async_handler=True)
    await handler.on_chain_start(serialized=None, inputs=None)
    await handler.on_chain_end(outputs=None)
    await handler.on_chain_error(error=None)
    await handler.on_tool_start(serialized=None, input_str=None)
    await handler.on_tool_end(output=None)
    await handler.on_tool_error(error=None)
    await handler.on_llm_start(serialized=None, prompts=None)
    await handler.on_chat_model_start(serialized=None, messages=None)
    await handler.on_llm_error(error=None)
    await handler.on_agent_action(action=None)
    await handler.on_agent_finish(finish=None)


# ─── RunHandle.callback_handler() integration ─────────────────────────


def test_run_handle_callback_handler_returns_sync_by_default():
    handle = _build_run_handle()
    handler = handle.callback_handler()
    assert isinstance(handler, WatchlightCallbackHandler)
    assert not isinstance(handler, WatchlightAsyncCallbackHandler)


def test_run_handle_callback_handler_returns_async_when_requested():
    handle = _build_run_handle()
    handler = handle.callback_handler(async_handler=True)
    assert isinstance(handler, WatchlightAsyncCallbackHandler)


def test_run_handle_callback_handler_binds_session_agent_tenant():
    handle = _build_run_handle()
    handler = handle.callback_handler()
    # Reach inside to verify the binding — the handler is what
    # the customer attaches, so the bound fields drive every
    # subsequent event.
    assert handler._agent_id == "agent-1"
    assert handler._session_id == "sess_42"
    assert handler._tenant_id == "acme"
    # No explicit execution_id → defaults to the handle's OWN canonical
    # execution_id (not a fresh one), so the callback stream shares the
    # run's single root.
    assert handler._execution_id == handle.execution_id
    assert handler._execution_id.startswith("exec_")


def test_run_handle_callback_handler_uses_explicit_execution_id():
    handle = _build_run_handle()
    handler = handle.callback_handler(execution_id="exec_explicit")
    assert handler._execution_id == "exec_explicit"


def test_run_handle_callback_handler_propagates_parent_execution_id():
    handle = _build_run_handle()
    handler = handle.callback_handler(parent_execution_id="exec_parent")
    assert handler._parent_execution_id == "exec_parent"


@pytest.mark.asyncio
async def test_run_handle_handler_captures_events_with_bound_identity():
    """End-to-end: handler returned by RunHandle captures events,
    and on flush the published events carry the bound session +
    agent + tenant. Critical because multi-tenant routing
    downstream depends on these being right."""
    handle = _build_run_handle()
    handler = handle.callback_handler(execution_id="exec_X")

    handler.on_chain_start(
        serialized={"name": "agent"}, inputs={"q": "x"}, run_id="r1", parent_run_id=None
    )
    handler.on_chain_end(outputs={"out": "y"}, run_id="r1", parent_run_id=None)

    count = await handler.flush()
    assert count == 2

    apdp: _StubApdp = handle._plugin.apdp
    published = apdp.published_batches[0]
    for ev in published:
        assert ev["execution_id"] == "exec_X"
        assert ev["agent_id"] == "agent-1"
        assert ev["session_id"] == "sess_42"
        assert ev["tenant_id"] == "acme"


# ─── Cross-plugin shape conformance ──────────────────────────────────


@pytest.mark.asyncio
async def test_published_events_have_required_envelope_fields():
    """Every emitted event must carry the canonical envelope
    fields that wl-apdp /v1/events expects."""
    handler, apdp = _build_handler()
    handler.on_chain_start(
        serialized={"name": "agent"}, inputs={"q": "x"}, run_id="r1", parent_run_id=None
    )
    handler.on_tool_start(
        serialized={"name": "search"}, input_str="x", run_id="r2", parent_run_id="r1"
    )
    handler.on_chain_end(outputs={}, run_id="r1", parent_run_id=None)
    await handler.flush()

    required_envelope = {"event_id", "event_type", "timestamp", "execution_id", "agent_id"}
    for batch in apdp.published_batches:
        for ev in batch:
            assert required_envelope.issubset(ev.keys()), (
                f"event {ev.get('event_type')} missing envelope fields: "
                f"{required_envelope - ev.keys()}"
            )
            assert "payload" in ev
            assert ev["metadata"]["source"] == "langgraph.callback"


# ─── OTLP integration ────────────────────────────────────────────────


class _RecordingOtlp:
    """Stand-in for ``WatchlightOtlpExporter`` — records the
    batches it would have exported."""

    def __init__(self):
        self.batches: List[List[Dict[str, Any]]] = []

    def export_events(self, events: List[Dict[str, Any]]) -> int:
        self.batches.append(list(events))
        return len(events)


@pytest.mark.asyncio
async def test_handler_routes_to_otlp_on_flush():
    """When an otlp_exporter is wired, flush() publishes to APDP
    AND routes the same translated events to OTLP."""
    apdp = _StubApdp()
    otlp = _RecordingOtlp()
    handler = WatchlightCallbackHandler(
        apdp_client=apdp,
        execution_id="exec_otlp_1",
        agent_id="agent-1",
        session_id="s",
        tenant_id="acme",
        otlp_exporter=otlp,
    )
    handler.on_chain_start(serialized={"name": "agent"}, inputs={}, run_id="r")
    handler.on_chain_end(outputs={}, run_id="r")
    await handler.flush()

    # APDP got the events; OTLP got them too.
    assert len(apdp.published_batches) == 1
    assert len(otlp.batches) == 1
    assert otlp.batches[0] == apdp.published_batches[0]


@pytest.mark.asyncio
async def test_otlp_failure_does_not_affect_apdp_outcome():
    """OTLP is opt-in customer obs; its failure cannot regress the
    lineage publish result (the source of truth for Watchlight)."""

    class _FailingOtlp:
        def export_events(self, events):
            raise RuntimeError("collector down")

    apdp = _StubApdp()
    handler = WatchlightCallbackHandler(
        apdp_client=apdp,
        execution_id="exec_otlp_2",
        agent_id="agent-1",
        session_id="s",
        tenant_id="acme",
        otlp_exporter=_FailingOtlp(),
    )
    handler.on_chain_start(serialized={"name": "agent"}, inputs={}, run_id="r")
    handler.on_chain_end(outputs={}, run_id="r")
    emitted = await handler.flush()
    # Customer still sees a successful flush count from APDP
    assert emitted >= 1


@pytest.mark.asyncio
async def test_no_otlp_keeps_handler_otlp_free():
    """The default (no otlp_exporter) path must not depend on the
    OTel SDK in any way."""
    handler, apdp = _build_handler()  # no otlp_exporter
    handler.on_chain_start(serialized={"name": "agent"}, inputs={}, run_id="r")
    handler.on_chain_end(outputs={}, run_id="r")
    emitted = await handler.flush()
    assert emitted >= 1
    # No otlp side-effect because none was wired


def test_run_handle_callback_handler_propagates_otlp_exporter():
    """RunHandle.callback_handler(otlp_exporter=...) must forward
    the exporter through to the returned handler instance."""
    handle = _build_run_handle()
    sentinel = _RecordingOtlp()
    handler = handle.callback_handler(otlp_exporter=sentinel)
    # Reach into the private slot — sanity check the wiring
    assert handler._otlp is sentinel  # noqa: SLF001
