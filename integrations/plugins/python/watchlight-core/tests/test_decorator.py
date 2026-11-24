"""Tests for ``@watchlight`` decorator (custom-agent SDK polish).

Coverage:
  - Async function emits execution_started → execution_completed
  - Sync function emits execution_started → execution_completed
  - Exception path emits execution_failed with bounded error message
  - Return value passthrough preserved
  - Optional OTLP exporter routed alongside APDP
  - APDP failure does not abort the wrapped function (best-effort lineage)
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List

import pytest

from watchlight_core.decorator import watchlight


# ─── Test doubles ────────────────────────────────────────────────────


class _RecordingApdp:
    """Minimal stand-in for ApdpClient that records publish calls
    and can be configured to fail."""

    def __init__(self, *, fail: bool = False):
        self.batches: List[List[Dict[str, Any]]] = []
        self._fail = fail

    async def publish_events(self, run: Any, events: List[Dict[str, Any]]) -> bool:
        self.batches.append(list(events))
        if self._fail:
            raise RuntimeError("simulated APDP failure")
        return True

    def all_events(self) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for batch in self.batches:
            out.extend(batch)
        return out

    def event_types(self) -> List[str]:
        return [e["event_type"] for e in self.all_events()]


class _RecordingOtlp:
    """Minimal stand-in for WatchlightOtlpExporter."""

    def __init__(self):
        self.batches: List[List[Dict[str, Any]]] = []

    def export_events(self, events: List[Dict[str, Any]]) -> int:
        self.batches.append(list(events))
        return len(events)


# ─── Async path ──────────────────────────────────────────────────────


class TestAsyncDecorator:
    @pytest.mark.asyncio
    async def test_emits_started_and_completed(self):
        apdp = _RecordingApdp()

        @watchlight(agent_id="agent-async-1", apdp_client=apdp)
        async def run(value: int) -> int:
            return value * 2

        result = await run(21)
        assert result == 42
        assert apdp.event_types() == ["execution_started", "execution_completed"]

    @pytest.mark.asyncio
    async def test_envelope_fields_set(self):
        apdp = _RecordingApdp()

        @watchlight(
            agent_id="agent-1",
            apdp_client=apdp,
            session_id="sess-1",
            tenant_id="acme",
            parent_execution_id="exec_parent",
        )
        async def run() -> str:
            return "ok"

        await run()
        events = apdp.all_events()
        assert len(events) == 2
        for e in events:
            assert e["agent_id"] == "agent-1"
            assert e["session_id"] == "sess-1"
            assert e["tenant_id"] == "acme"
            assert e["parent_execution_id"] == "exec_parent"
            assert e["execution_id"].startswith("exec_")
            assert e["metadata"]["source"] == "watchlight.decorator"
        # Same execution_id across the two events
        assert events[0]["execution_id"] == events[1]["execution_id"]

    @pytest.mark.asyncio
    async def test_exception_emits_failed_and_reraises(self):
        apdp = _RecordingApdp()

        @watchlight(agent_id="agent-1", apdp_client=apdp)
        async def run() -> None:
            raise ValueError("kaboom")

        with pytest.raises(ValueError, match="kaboom"):
            await run()

        types = apdp.event_types()
        assert types == ["execution_started", "execution_failed"]
        failed = apdp.all_events()[1]
        assert failed["payload"]["error_type"] == "ValueError"
        # Value-free: the exception class, never its message.
        assert failed["payload"]["error"] == "ValueError"
        assert "kaboom" not in repr(failed)

    @pytest.mark.asyncio
    async def test_error_message_bounded(self):
        """Exception messages larger than 512 chars are truncated
        — protects the event channel from gigantic payloads."""
        apdp = _RecordingApdp()

        @watchlight(agent_id="agent-1", apdp_client=apdp)
        async def run() -> None:
            raise RuntimeError("X" * 10000)

        with pytest.raises(RuntimeError):
            await run()
        failed = apdp.all_events()[1]
        assert len(failed["payload"]["error"]) <= 512
        assert "XXXX" not in failed["payload"]["error"]

    @pytest.mark.asyncio
    async def test_apdp_failure_does_not_abort_function(self):
        """Lineage emission is best-effort. APDP failure must not
        propagate to the customer's agent — that would couple
        their availability to ours."""
        apdp = _RecordingApdp(fail=True)

        @watchlight(agent_id="agent-1", apdp_client=apdp)
        async def run() -> int:
            return 7

        result = await run()
        assert result == 7  # function still completed

    @pytest.mark.asyncio
    async def test_otlp_exporter_invoked(self):
        apdp = _RecordingApdp()
        otlp = _RecordingOtlp()

        @watchlight(agent_id="agent-1", apdp_client=apdp, otlp_exporter=otlp)
        async def run() -> str:
            return "done"

        await run()
        # OTLP receives the same events APDP did, once per emit
        assert len(otlp.batches) == 2
        assert otlp.batches[0][0]["event_type"] == "execution_started"
        assert otlp.batches[1][0]["event_type"] == "execution_completed"


# ─── Sync path ───────────────────────────────────────────────────────


class TestSyncDecorator:
    def test_sync_function_emits_lifecycle(self):
        apdp = _RecordingApdp()

        @watchlight(agent_id="agent-sync-1", apdp_client=apdp)
        def run(value: int) -> int:
            return value + 1

        result = run(10)
        assert result == 11
        # In sync mode, emission runs through asyncio.run; both
        # events are flushed before the wrapper returns.
        assert apdp.event_types() == ["execution_started", "execution_completed"]

    def test_sync_function_exception_path(self):
        apdp = _RecordingApdp()

        @watchlight(agent_id="agent-1", apdp_client=apdp)
        def run() -> None:
            raise KeyError("missing")

        with pytest.raises(KeyError):
            run()
        assert "execution_failed" in apdp.event_types()


# ─── Metadata + identity attribution ─────────────────────────────────


class TestDecoratorMetadata:
    @pytest.mark.asyncio
    async def test_custom_metadata_merged(self):
        apdp = _RecordingApdp()

        @watchlight(
            agent_id="agent-1",
            apdp_client=apdp,
            metadata={"authority_class": "Standard", "extra": "tag"},
        )
        async def run() -> None:
            return None

        await run()
        started = apdp.all_events()[0]
        # Customer-supplied metadata merged with the default
        # "watchlight.decorator" source attribution
        assert started["metadata"]["source"] == "watchlight.decorator"
        assert started["metadata"]["authority_class"] == "Standard"
        assert started["metadata"]["extra"] == "tag"
