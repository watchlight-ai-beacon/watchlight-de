"""Tests for `LineageEmitter` batching, flush, and best-effort
publish semantics."""

from __future__ import annotations

from typing import Any, Dict, List
from unittest.mock import AsyncMock

import pytest

from watchlight_adk.lineage import LineageEmitter

from .conftest import run_for, token_of


# In-process stand-in for unit tests only.
class _StubApdp:
    """Mock ApdpClient capturing published batches."""

    def __init__(self, succeed: bool = True):
        self.succeed = succeed
        self.published_batches: List[List[Dict[str, Any]]] = []
        # The emitter groups by run and names the run on each publish;
        # capture the stand-in credential that run carries too.
        self.session_tokens: List[Any] = []

        async def _capture(run, events):
            self.published_batches.append(list(events))
            self.session_tokens.append(token_of(run))
            if not self.succeed:
                raise RuntimeError("simulated publish failure")
            return True

        self.publish_events = AsyncMock(side_effect=_capture)


def _make_emitter(succeed: bool = True):
    apdp = _StubApdp(succeed=succeed)
    return LineageEmitter(apdp_client=apdp), apdp


# ─── Buffering + captures ─────────────────────────────────────────────


def test_emitter_starts_empty():
    emitter, _ = _make_emitter()
    assert emitter.buffered_count() == 0
    assert emitter.snapshot() == []


@pytest.mark.asyncio
async def test_emit_execution_started_buffers_capture():
    emitter, _ = _make_emitter()
    await emitter.emit_execution_started(
        "exec_test",
        "agent-1",
        depth=0,
        intent_category="research",
    )
    assert emitter.buffered_count() == 1
    captured = emitter.snapshot()
    assert captured[0]["hook"] == "before_agent_callback"
    assert captured[0]["intent_category"] == "research"


@pytest.mark.asyncio
async def test_emit_tool_call_captures_phase():
    emitter, _ = _make_emitter()
    await emitter.emit_tool_call(
        "exec",
        "agent-1",
        tool_name="search",
        action="query",
        phase="planned",
        decision="Allow",
    )
    captured = emitter.snapshot()
    # Translator routes phase=planned → before_tool_callback hook
    assert captured[0]["hook"] == "before_tool_callback"

    await emitter.emit_tool_call(
        "exec",
        "agent-1",
        tool_name="search",
        action="query",
        phase="completed",
        decision="Allow",
    )
    assert emitter.snapshot()[1]["hook"] == "after_tool_callback"


@pytest.mark.asyncio
async def test_emit_execution_failed_captures_error():
    emitter, _ = _make_emitter()
    await emitter.emit_execution_failed(
        "exec",
        "agent-1",
        error=ValueError("bad input"),
        hook="on_tool_error_callback",
    )
    captured = emitter.snapshot()
    assert captured[0]["hook"] == "on_tool_error_callback"
    assert isinstance(captured[0]["error"], ValueError)


@pytest.mark.asyncio
async def test_emit_api_request_captures_model():
    emitter, _ = _make_emitter()
    await emitter.emit_api_request(
        "exec",
        "agent-1",
        model="gemini-1.5-pro",
        prompt_summary="hello",
    )
    captured = emitter.snapshot()
    assert captured[0]["hook"] == "before_model_callback"
    assert captured[0]["model"] == "gemini-1.5-pro"


# ─── Flush behavior ───────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_flush_translates_and_publishes_all_captures():
    emitter, apdp = _make_emitter()
    await emitter.emit_execution_started("exec", "agent-1")
    await emitter.emit_api_request("exec", "agent-1", model="gemini")
    await emitter.emit_tool_call("exec", "agent-1", "search", "query", "Allow")
    await emitter.emit_execution_completed("exec", "agent-1", duration_ms=100, actions_taken=1)

    count = await emitter.flush()
    assert count == 4
    assert emitter.buffered_count() == 0

    batch = apdp.published_batches[0]
    types = [e["event_type"] for e in batch]
    assert types == [
        "execution_started",
        "api_request_observed",
        "tool_call_observed",
        "execution_completed",
    ]


@pytest.mark.asyncio
async def test_flush_with_empty_buffer_returns_zero_no_post():
    emitter, apdp = _make_emitter()
    count = await emitter.flush()
    assert count == 0
    apdp.publish_events.assert_not_called()


@pytest.mark.asyncio
async def test_flush_clears_buffer_even_on_publish_failure():
    """Best-effort lineage: a publish failure must NOT leave the
    buffer unbounded. We clear regardless so sustained APDP
    unavailability doesn't OOM the host."""
    emitter, _ = _make_emitter(succeed=False)
    await emitter.emit_execution_started("exec", "agent-1")
    count = await emitter.flush()
    assert count == 0
    assert emitter.buffered_count() == 0  # cleared despite failure


@pytest.mark.asyncio
async def test_flush_drops_captures_missing_execution_id():
    """Defensive: a capture lacking _execution_id/_agent_id is
    silently dropped, not crashed on. Edge case if an emit
    method is called incorrectly."""
    emitter, apdp = _make_emitter()
    # Directly inject a malformed capture
    emitter._captures.append({"hook": "before_agent_callback"})  # missing both IDs
    count = await emitter.flush()
    assert count == 0


@pytest.mark.asyncio
async def test_close_calls_flush():
    emitter, apdp = _make_emitter()
    await emitter.emit_execution_started("exec", "agent-1")
    await emitter.close()
    assert apdp.publish_events.called
    assert emitter.buffered_count() == 0


@pytest.mark.asyncio
async def test_envelope_extras_propagate_through_emitter():
    emitter, apdp = _make_emitter()
    await emitter.emit_execution_started(
        "exec_child",
        "agent-1",
        session_id="sess_42",
        tenant_id="acme",
        parent_execution_id="exec_parent",
        root_execution_id="exec_root",
    )
    await emitter.flush()
    ev = apdp.published_batches[0][0]
    assert ev["session_id"] == "sess_42"
    assert ev["tenant_id"] == "acme"
    assert ev["parent_execution_id"] == "exec_parent"
    assert ev["root_execution_id"] == "exec_root"


# ─── OTLP integration ─────────────────────────────────────────────────


class _RecordingOtlp:
    """Stand-in for `WatchlightOtlpExporter` — records the
    batches it would have exported. Same shape as the langgraph
    + bedrock integration tests so cross-plugin parity is
    enforced by inspection."""

    def __init__(self):
        self.batches: List[List[Dict[str, Any]]] = []

    def export_events(self, events):
        self.batches.append(list(events))
        return len(events)


@pytest.mark.asyncio
async def test_lineage_routes_to_otlp_after_apdp_publish():
    """When an `otlp_exporter` is wired, `flush()` publishes to
    APDP AND routes the same translated events to OTLP."""
    apdp = _StubApdp()
    otlp = _RecordingOtlp()
    emitter = LineageEmitter(apdp_client=apdp, otlp_exporter=otlp)
    await emitter.emit_execution_started("exec_1", "agent-1")
    await emitter.emit_tool_call(
        "exec_1",
        "agent-1",
        tool_name="fs.read",
        action="invoke",
        decision="Allow",
    )
    await emitter.emit_execution_completed("exec_1", "agent-1", duration_ms=10, actions_taken=1)
    await emitter.flush()

    # APDP got one batch; OTLP got the same one batch.
    assert len(apdp.published_batches) == 1
    assert len(otlp.batches) == 1
    assert otlp.batches[0] == apdp.published_batches[0]


@pytest.mark.asyncio
async def test_otlp_export_failure_does_not_affect_apdp_outcome():
    """OTLP is opt-in customer observability; its failure cannot
    regress the lineage publish result (the source of truth for
    Watchlight). Same invariant the langgraph + bedrock tests
    enforce."""

    class _FailingOtlp:
        def export_events(self, events):
            raise RuntimeError("collector down")

    apdp = _StubApdp()
    emitter = LineageEmitter(apdp_client=apdp, otlp_exporter=_FailingOtlp())
    await emitter.emit_execution_started("exec_1", "agent-1")
    emitted = await emitter.flush()
    # Customer sees a successful flush count from APDP regardless
    # of OTLP outcome.
    assert emitted >= 1


@pytest.mark.asyncio
async def test_no_otlp_exporter_keeps_emitter_otlp_free():
    """The default path (no `otlp_exporter`) must not depend on
    the OTel SDK in any way. Without an exporter, the field is
    None and the OTLP branch is short-circuited."""
    apdp = _StubApdp()
    emitter = LineageEmitter(apdp_client=apdp)  # no otlp_exporter
    await emitter.emit_execution_started("exec_1", "agent-1")
    emitted = await emitter.flush()
    assert emitted >= 1


@pytest.mark.asyncio
async def test_otlp_path_only_runs_after_apdp_publish_succeeds():
    """If the APDP publish fails, the OTLP path should NOT run —
    OTLP is a downstream tap on the lineage stream, not a
    parallel destination. Without successful lineage, there's
    nothing to observe operationally."""
    apdp = _StubApdp(succeed=False)
    otlp = _RecordingOtlp()
    emitter = LineageEmitter(apdp_client=apdp, otlp_exporter=otlp)
    await emitter.emit_execution_started("exec_1", "agent-1")
    await emitter.flush()
    # APDP attempted (and failed); OTLP never invoked
    assert len(apdp.published_batches) == 1
    assert otlp.batches == []


# ─── Nested-run token isolation ───────────────────────────────────────


@pytest.mark.asyncio
async def test_nested_runs_publish_as_separate_token_bound_batches():
    """One emitter buffer can hold captures from
    MULTIPLE runs (a root plus a nested sub-agent, each of which opened
    its OWN session with its OWN ``sst_``). ``flush`` MUST group by the
    bound ``run`` and publish each group under that run —
    batching cross-run events under one token would make wl-apdp's
    ``/v1/events`` identity-binding gate refuse whichever events don't
    match. This locks in that grouping with a dedicated test."""
    emitter, apdp = _make_emitter()

    # Root run events (token sst_root), then a nested sub-agent's events
    # (token sst_child) interleaved back to the root — mirrors ADK firing
    # root → sub-agent → back-to-root within one buffer.
    await emitter.emit_execution_started(
        "exec_root", "agent-root", depth=0, run=run_for("sst_root")
    )
    await emitter.emit_execution_started(
        "exec_child", "agent-child", depth=1, run=run_for("sst_child")
    )
    await emitter.emit_tool_call(
        "exec_child",
        "agent-child",
        tool_name="get_x",
        action="read",
        run=run_for("sst_child"),
        decision="Allow",
    )
    await emitter.emit_execution_completed(
        "exec_root",
        "agent-root",
        duration_ms=5,
        actions_taken=1,
        run=run_for("sst_root"),
    )

    published = await emitter.flush()
    assert published == 4

    # Exactly two token-bound publish calls — one per run's credential.
    assert len(apdp.published_batches) == 2
    by_token = {
        tok: batch
        for tok, batch in zip(apdp.session_tokens, apdp.published_batches)
    }
    assert set(by_token) == {"sst_root", "sst_child"}

    # Each batch carries ONLY its own run's events — no cross-run leakage.
    root_exec_ids = {e["execution_id"] for e in by_token["sst_root"]}
    child_exec_ids = {e["execution_id"] for e in by_token["sst_child"]}
    assert root_exec_ids == {"exec_root"}
    assert child_exec_ids == {"exec_child"}
    # And the token groups don't cross-contaminate event types either.
    assert {e["event_type"] for e in by_token["sst_child"]} == {
        "execution_started",
        "tool_call_observed",
    }
