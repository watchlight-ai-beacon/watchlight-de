""":class:`BaseRunHandle.complete()` and :meth:`terminate()` emit
canonical ``execution_completed`` / ``execution_failed`` events
idempotently.

Closes the lineage-projection gap where ``lineage.executions`` rows
would stay at ``status='started'`` indefinitely for any plugin lane
whose framework didn't already emit the terminal event via its own
callback (Bedrock, MSAF, Pydantic-AI, …). The defensive SDK emit is
the load-bearing fallback; framework translators that DO emit the
event from a callback signal that via
:meth:`mark_execution_completed_emitted` /
:meth:`mark_execution_failed_emitted` so the SDK suppresses its own
emit and no row receives two lifecycle events for the same logical
close.

The tests cover the full edge-case enumeration from the design:

  1. Normal complete() → execution_completed lands
  2. Normal terminate() → execution_failed lands
  3. Framework mark before complete() → SDK skips, no double
  4. SDK complete() before framework callback emit → framework's
     subsequent ``flush()`` can still emit (the SDK can only suppress
     its own emit; framework code is responsible for its own dedup)
  5. terminate-then-complete → execution_failed lands; complete is
     a no-op for the lifecycle event
  6. complete-then-terminate → execution_completed lands; terminate
     is a no-op (existing ``_completed`` guard)
  7. Sub-agent complete() emits child's execution_id (not root's)
  8. NATS down → emit failure logged + close still completes
  9. __aexit__ normal path calls complete()
 10. __aexit__ exception path calls terminate()
 11. Quarantine path: ``execution_quarantined`` + the quarantined
     ``execution_completed`` continue to use the handle's stable
     execution_id; no double-emit from the defensive emit.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, List, Optional

import pytest

from watchlight_core import BaseRunHandle, WatchlightError
from watchlight_core.telemetry import GovernanceTelemetry
from watchlight_core_testing import MockApdpClient
from watchlight_core_testing import bind_test_run


# ─── Plugin fixture ────────────────────────────────────────────────────


class _Plugin(GovernanceTelemetry):
    """Minimal :class:`GovernedPlugin` for lifecycle-emit tests. The plugin
    advertises a framework-tagged ``observation_source`` via a handle
    subclass so the defensive emit's ``metadata.source`` satisfies
    invariant 2's framework-prefix rule.
    """

    def __init__(self, tenant_id: Optional[str] = "tenant-acme") -> None:
        super().__init__()
        self.apdp = MockApdpClient()
        self.tenant_id = tenant_id
        self.log_decisions = False
        self.kill_signal_registry = None


class _M47Handle(BaseRunHandle):
    """Handle whose ``_observation_source`` carries the per-framework
    tag so the defensive emit's ``metadata.source`` is
    framework-namespaced (``testfw.run_handle_close`` /
    ``testfw.run_handle_terminate``).
    """

    _observation_source = "testfw.workload"


@pytest.fixture
def plugin() -> _Plugin:
    return _Plugin()


@pytest.fixture
def handle(plugin: _Plugin) -> _M47Handle:
    return bind_test_run(
        _M47Handle(
            plugin=plugin,
            agent_uuid="agent-uuid-001",
            session_id="ses_m47_001",
            execution_id="exec_m47_test_root",
        ),
        "sst_m47.sig",
    )


def _completion_events(plugin: _Plugin) -> List[Dict[str, Any]]:
    return [
        e
        for e in plugin.apdp.published_events
        if e.get("event_type") == "execution_completed"
    ]


def _failure_events(plugin: _Plugin) -> List[Dict[str, Any]]:
    return [
        e
        for e in plugin.apdp.published_events
        if e.get("event_type") == "execution_failed"
    ]


# ─── Test 1 — complete() emits execution_completed ───────────────────


@pytest.mark.asyncio
async def test_complete_emits_execution_completed(
    plugin: _Plugin, handle: _M47Handle
) -> None:
    """Calling ``complete()`` emits exactly one canonical
    ``execution_completed`` envelope for the handle's
    :attr:`execution_id`. The envelope satisfies the canonical
    flat-shape contract: top-level ``execution_id`` / ``agent_id`` /
    ``session_id`` / ``tenant_id``, nested ``payload`` carrying the
    plugin's running action counters, and a framework-namespaced
    ``metadata.source``.
    """
    await handle.complete()

    events = _completion_events(plugin)
    assert len(events) == 1, (
        f"expected exactly one execution_completed, got {len(events)} "
        f"({[e.get('event_type') for e in plugin.apdp.published_events]})"
    )
    event = events[0]
    assert event["execution_id"] == "exec_m47_test_root"
    assert event["agent_id"] == "agent-uuid-001"
    assert event["session_id"] == "ses_m47_001"
    assert event["tenant_id"] == "tenant-acme"
    assert event["metadata"]["source"] == "testfw.run_handle_close"
    assert event["metadata"]["kind"] == "sdk_lifecycle_emit"
    assert event["payload"]["outcome"] == "completed"
    # event_id matches the canonical ``evt_<uuid>`` pattern.
    assert event["event_id"].startswith("evt_")


# ─── Test 2 — terminate() emits execution_failed ─────────────────────


@pytest.mark.asyncio
async def test_terminate_emits_execution_failed(
    plugin: _Plugin, handle: _M47Handle
) -> None:
    """Calling ``terminate(reason)`` emits exactly one canonical
    ``execution_failed`` envelope with the truncated reason in
    ``payload.error`` (the schema's required field) and the handle's
    stable :attr:`execution_id`.
    """
    await handle.terminate(reason="run_failed: KeyError")

    events = _failure_events(plugin)
    assert len(events) == 1
    event = events[0]
    assert event["execution_id"] == "exec_m47_test_root"
    assert event["payload"]["error"] == "run_failed: KeyError"
    assert event["metadata"]["source"] == "testfw.run_handle_terminate"


# ─── Test 3 — framework mark before complete() suppresses double-emit ─


@pytest.mark.asyncio
async def test_complete_idempotent_when_framework_already_emitted(
    plugin: _Plugin, handle: _M47Handle
) -> None:
    """When a framework translator calls
    :meth:`mark_execution_completed_emitted` BEFORE the SDK's
    ``complete()`` runs, the defensive emit is suppressed — the audit
    trail shows the framework's emit (which the test simulates by
    leaving an external event in ``published_events``) and no SDK
    duplicate.
    """
    # Simulate the framework's own emit landing in the audit stream
    # via the plugin's APDP client (mirrors what LangGraph's
    # ``flush()`` does at the end of on_chain_end translation).
    framework_event = {
        "event_id": "evt_framework_emit_001",
        "event_type": "execution_completed",
        "timestamp": "2026-06-18T00:00:00Z",
        "execution_id": handle.execution_id,
        "agent_id": handle.agent_uuid,
        "session_id": handle.session_id,
        "tenant_id": "tenant-acme",
        "metadata": {"source": "testfw.on_chain_end"},
        "payload": {"duration_ms": 0, "actions_taken": 0},
    }
    handle.mark_execution_completed_emitted()
    await plugin.apdp.publish_events(None, [framework_event])

    await handle.complete()

    events = _completion_events(plugin)
    assert len(events) == 1, (
        "expected the framework's emit only; SDK must NOT double-emit"
    )
    assert events[0]["metadata"]["source"] == "testfw.on_chain_end"


# ─── Test 4 — terminate-then-complete: failure wins ──────────────────


@pytest.mark.asyncio
async def test_terminate_followed_by_complete_is_no_op_for_complete(
    plugin: _Plugin, handle: _M47Handle
) -> None:
    """``terminate()`` followed by ``complete()`` lands the
    ``execution_failed`` and the subsequent ``complete()`` is a no-op
    (existing ``_completed`` guard) — no ``execution_completed``
    event is added.
    """
    await handle.terminate(reason="manual-stop")
    await handle.complete()

    assert len(_failure_events(plugin)) == 1
    assert len(_completion_events(plugin)) == 0


# ─── Test 5 — complete-then-terminate: complete wins ─────────────────


@pytest.mark.asyncio
async def test_complete_followed_by_terminate_terminate_is_noop(
    plugin: _Plugin, handle: _M47Handle
) -> None:
    """``complete()`` followed by ``terminate()`` lands the
    ``execution_completed`` and the subsequent ``terminate()`` is a
    no-op — no ``execution_failed`` event is added.

    This is the edge-case decision documented in the design:
    the first close wins for the lifecycle event; subsequent calls
    are short-circuited by the existing ``_completed`` flag.
    """
    await handle.complete()
    await handle.terminate(reason="late-terminate")

    assert len(_completion_events(plugin)) == 1
    assert len(_failure_events(plugin)) == 0


# ─── Test 6 — sub-agent complete() emits child's execution_id ────────


@pytest.mark.asyncio
async def test_subagent_complete_emits_child_execution_completed(
    plugin: _Plugin,
) -> None:
    """A sub-agent handle's ``complete()`` emits an
    ``execution_completed`` for the CHILD's :attr:`execution_id`
    (not the root's) and stamps ``parent_execution_id`` +
    ``root_execution_id`` so the dashboard's recursive CTE stitches
    the row into the spawn tree.

    Locked decision: child handles own their own lineage emit; the
    root's ``complete()`` does NOT auto-close children — that's the
    explicit-ownership invariant for sub-agent scope attenuation.
    """
    root = _M47Handle(
        plugin=plugin,
        agent_uuid="root-uuid",
        session_id="ses_root",
        execution_id="exec_root_001",
    )
    child = _M47Handle(
        plugin=plugin,
        agent_uuid="child-uuid",
        session_id="ses_child",
        execution_id="exec_child_001",
        root_execution_id="exec_root_001",
        parent_execution_id="exec_root_001",
        parent_handle=root,
    )

    await child.complete()

    events = _completion_events(plugin)
    assert len(events) == 1
    event = events[0]
    assert event["execution_id"] == "exec_child_001"
    assert event["parent_execution_id"] == "exec_root_001"
    assert event["root_execution_id"] == "exec_root_001"
    # Root MUST remain open — parent's complete() was not called.
    assert not root._completed


# ─── Test 7 — NATS down: emit fails, close still completes ────────────


@pytest.mark.asyncio
async def test_complete_with_publish_failure_logs_warning_and_continues(
    plugin: _Plugin,
    handle: _M47Handle,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """When the APDP transport fails the lifecycle emit, ``complete()``
    logs a warning and still flips the handle's ``_completed`` flag —
    the customer's framework cleanup MUST complete even when
    observability is degraded.
    """
    original_publish = plugin.apdp.publish_events

    async def boom(events: List[Dict[str, Any]]) -> bool:
        raise ConnectionError("NATS unavailable")

    plugin.apdp.publish_events = boom  # type: ignore[assignment]

    caplog.set_level(logging.WARNING, logger="watchlight.core.run_handle")
    await handle.complete()
    plugin.apdp.publish_events = original_publish  # type: ignore[assignment]

    assert handle._completed
    # The defensive emit is recorded in the tracker even on transport
    # failure (we tried, but observability dropped the event).
    assert "execution_completed" in handle.execution_lifecycle_emitted
    warnings = [r for r in caplog.records if r.levelname == "WARNING"]
    assert any("lifecycle emit failed" in r.getMessage() for r in warnings)


# ─── Test 8 — __aexit__ normal path calls complete() ─────────────────


@pytest.mark.asyncio
async def test_aexit_normal_calls_complete(
    plugin: _Plugin, handle: _M47Handle
) -> None:
    """The async-context-manager exit on a clean run path invokes
    ``complete()`` which in turn emits ``execution_completed``."""

    async def _runtime() -> None:
        # ``handle.__aenter__`` is implicit in the fixture's handle;
        # explicitly call __aexit__ with no exception.
        await handle.__aexit__(None, None, None)

    await _runtime()
    assert len(_completion_events(plugin)) == 1


# ─── Test 9 — __aexit__ exception path calls terminate() ─────────────


@pytest.mark.asyncio
async def test_aexit_exception_calls_terminate(
    plugin: _Plugin, handle: _M47Handle
) -> None:
    """The async-context-manager exit on an exception path invokes
    ``terminate(reason=…)`` which emits ``execution_failed`` with the
    exception name in the reason."""
    err = RuntimeError("boom")
    await handle.__aexit__(type(err), err, None)

    events = _failure_events(plugin)
    assert len(events) == 1
    assert "RuntimeError" in events[0]["payload"]["error"]


# ─── Test 10 — public mark methods are idempotent ────────────────────


def test_mark_execution_completed_emitted_is_idempotent(
    handle: _M47Handle,
) -> None:
    """Multiple ``mark_execution_completed_emitted`` calls keep the
    tracker set at a single entry — the set semantics guarantee at-
    most-once even when a translator's hook fires more than once."""
    handle.mark_execution_completed_emitted()
    handle.mark_execution_completed_emitted()
    handle.mark_execution_completed_emitted()
    snapshot = handle.execution_lifecycle_emitted
    assert snapshot == {"execution_completed"}


def test_mark_execution_failed_emitted_is_idempotent(
    handle: _M47Handle,
) -> None:
    """Mirror of the completed-mark test."""
    handle.mark_execution_failed_emitted()
    handle.mark_execution_failed_emitted()
    assert handle.execution_lifecycle_emitted == {"execution_failed"}


# ─── Test 11 — concurrent complete()/terminate() races ───────────────


@pytest.mark.asyncio
async def test_concurrent_complete_terminate_first_wins(
    plugin: _Plugin, handle: _M47Handle
) -> None:
    """Concurrent ``complete()`` and ``terminate()`` calls race; the
    asyncio.Lock serialises them and the FIRST one wins. The second
    short-circuits at the ``self._completed`` guard. The audit trail
    has exactly one lifecycle event from the SDK emit (no double).
    """
    await asyncio.gather(handle.complete(), handle.terminate("race"))

    total_lifecycle = len(_completion_events(plugin)) + len(
        _failure_events(plugin)
    )
    assert total_lifecycle == 1


# ─── Test 12 — quarantine path uses stable execution_id ──────────────


@pytest.mark.asyncio
async def test_quarantine_event_uses_handle_execution_id(
    plugin: _Plugin,
) -> None:
    """The ``execution_quarantined`` event now carries the handle's
    stable :attr:`execution_id` (not a freshly-minted phantom). This
    closes the wl-execution-graph phantom-row pattern that the
    audit surfaced.
    """
    from watchlight_core.decision import QuarantineDecision

    handle = _M47Handle(
        plugin=plugin,
        agent_uuid="qa-agent",
        session_id="ses_qa",
        execution_id="exec_quarantine_test",
    )
    decision = QuarantineDecision(
        policy_id="qa.test.policy",
        anomaly_score=0.92,
        contributing_features=[],
        model_version=None,
        reason="test quarantine",
    )
    await handle._emit_quarantine_event(decision)

    quarantine_events = [
        e
        for e in plugin.apdp.published_events
        if e.get("event_type") == "execution_quarantined"
    ]
    assert len(quarantine_events) == 1
    assert quarantine_events[0]["execution_id"] == "exec_quarantine_test"


# ─── Test 13 — quarantined complete() does not double-emit ───────────


@pytest.mark.asyncio
async def test_quarantined_complete_does_not_double_emit(
    plugin: _Plugin,
) -> None:
    """When a handle is QUARANTINED, ``complete()`` emits the
    quarantined-completion event (via
    :meth:`_emit_quarantined_completion_event`) and the
    defensive ``execution_completed`` is suppressed — the
    quarantined-completion IS the terminal ``execution_completed``
    for the lineage row; the defensive SDK emit would be a duplicate.
    """
    from watchlight_core.decision import (
        QuarantineDecision,
        RunHandleState,
    )

    handle = _M47Handle(
        plugin=plugin,
        agent_uuid="qa-agent",
        session_id="ses_qa",
        execution_id="exec_qa_complete",
    )
    handle._state = RunHandleState.QUARANTINED
    handle._quarantine_decision = QuarantineDecision(
        policy_id="qa.test.policy",
        anomaly_score=0.92,
        contributing_features=[],
        model_version=None,
        reason="test",
    )

    await handle.complete()

    events = _completion_events(plugin)
    # Exactly one execution_completed event: the quarantined-complete
    # one carrying the policy_id in metadata. The defensive
    # emit must NOT add a second one.
    assert len(events) == 1
    assert events[0]["metadata"].get("kind") == "quarantined_complete"


# ─── Test 14 — terminate then concurrent complete (lock) ─────────────


@pytest.mark.asyncio
async def test_terminate_serialises_via_lifecycle_lock(
    plugin: _Plugin, handle: _M47Handle
) -> None:
    """The lifecycle lock prevents interleaving of complete and
    terminate. The second caller observes ``_completed=True`` after
    the first releases the lock and short-circuits without a second
    APDP round-trip.
    """

    async def run_complete() -> None:
        await handle.complete()

    async def run_terminate() -> None:
        await handle.terminate(reason="late")

    # Schedule both; the lock ensures the second one short-circuits.
    await asyncio.gather(run_complete(), run_terminate())
    # APDP's mock records calls — there must be exactly ONE
    # complete_session call (the first one).
    assert len(plugin.apdp._closed_sessions) + len(
        plugin.apdp._terminated_sessions
    ) == 1


@pytest.mark.asyncio
async def test_execution_started_carries_the_goal_id_when_the_run_has_one(
    plugin: _Plugin,
) -> None:
    """``start_run(goal_id=...)`` reaches lineage: ``execution_started``
    carries ``goal_id`` so wl-execution-graph can render the goal per
    execution without a session lookup. Absent when the run has none."""
    with_goal = _M47Handle(
        plugin=plugin,
        agent_uuid="agent-uuid-001",
        session_id="ses_goal_001",
        execution_id="exec_goal_test",
        goal_id="11111111-1111-4111-8111-111111111101",
    )
    await with_goal._emit_execution_started(with_goal.execution_id)
    started = [
        e for e in plugin.apdp.published_events if e["event_type"] == "execution_started"
    ]
    assert len(started) == 1
    assert started[0]["payload"]["goal_id"] == "11111111-1111-4111-8111-111111111101"

    plugin.apdp.published_events.clear()
    without = _M47Handle(
        plugin=plugin,
        agent_uuid="agent-uuid-001",
        session_id="ses_goal_002",
        execution_id="exec_goal_test_2",
    )
    await without._emit_execution_started(without.execution_id)
    started = [
        e for e in plugin.apdp.published_events if e["event_type"] == "execution_started"
    ]
    assert len(started) == 1
    assert "goal_id" not in started[0]["payload"]
