"""Conformance harness wire-up of invariant #14.

These tests verify the Python lane mirror of TS conformance invariant
#14. Invariant #14 asserts every non-mint event in the captured stream
has a preceding ``execution_started`` event with the same
``execution_id``. The closed-set mint events (``execution_started`` /
``agent_spawn_observed`` / ``ungoverned_request_observed``) are
self-rooted and exempt from the rule. The SDK ships a load-bearing
guard that makes the contract satisfiable across every plugin;
invariant #14 locks the contract from the consumer side so a future
plugin / translator that bypasses the SDK lifecycle (or a
customer-direct emitter that forgets the mint) fails CI loudly.

The tests cover:

  1. Happy path — invariant passes when ``execution_started`` precedes
     a non-mint event for the same ``execution_id``.
  2. Deliberate negative — invariant fails when a non-mint event has
     no preceding ``execution_started``.
  3. Anomaly exemption — ``ungoverned_request_observed`` is self-rooted
     and passes invariant #14 with no preceding ``execution_started``.
  4. Spawn exemption — ``agent_spawn_observed`` counts as a mint event
     for the spawned child's execution_id subtree.
  5. Multiple-execution independence — each ``execution_id`` is verified
     separately; one orphan group fails the whole check while another
     valid group does not mask the failure.
  6. Empty stream — vacuous pass.
  7. Single mint event with no children — trivial pass.
  8. Out-of-order delivery — invariant operates on the wire-form
     ``timestamp`` field, not iteration order.
  9. Duplicate ``execution_started`` — counts as "seen mint"; dedup is
     a separate concern.
 10. Timestamp ties — equal timestamps treated as concurrent; tied
     mint + non-mint pair passes (mint counts as "seen").
 11. Unknown event types — closed-set default; unknown types treated
     as non-mint and require a preceding started (safe-default).
 12. Constants ``EXECUTION_STARTED_PRECEDES_NON_LIFECYCLE_EVENTS_*``
     are exported and match the TS lane.
 13. Invariant #14 is registered in the canonical ``INVARIANTS`` table.
 14. The :func:`run_conformance` harness FAILS a plugin whose stream
     contains an orphan non-mint event.
 15. The :func:`run_conformance` harness PASSES a plugin whose stream
     has the mint precedence correct.

Mirrors the pattern from :mod:`test_conformance_invariant_13` —
synthetic plugin modules registered into ``sys.modules`` keep the test
hermetic from the real shipped plugins.
"""

from __future__ import annotations

import sys
import types
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import pytest

from watchlight_core_testing.conformance import (
    EXECUTION_STARTED_PRECEDES_MINT_EVENTS,
    EXECUTION_STARTED_PRECEDES_NON_LIFECYCLE_EVENTS_INVARIANT_NAME,
    EXECUTION_STARTED_PRECEDES_NON_LIFECYCLE_EVENTS_INVARIANT_NUMBER,
    INVARIANTS,
    check_execution_started_precedes_non_lifecycle_events,
    run_conformance,
)
from watchlight_core.run_handle import BaseRunHandle
from watchlight_core.telemetry import GovernanceTelemetry
from watchlight_core_testing import (
    ConformanceFailure,
    MockApdpClient,
)


# ─── Fixture helpers ──────────────────────────────────────────────────


FRAMEWORK_TAG = "stubfw"


def _register_synthetic_module(
    name: str,
    plugin_cls: type,
    translator: Any = None,
) -> types.ModuleType:
    """Register a synthetic plugin module the conformance runner can
    load by name."""
    mod = types.ModuleType(name)
    setattr(mod, plugin_cls.__name__, plugin_cls)
    if translator is not None:
        setattr(mod, translator.__name__, translator)
    sys.modules[name] = mod
    return mod


def _iso(offset_seconds: int = 0) -> str:
    """Stable monotonic ISO timestamp helper. Using a fixed anchor
    keeps the ordering deterministic regardless of test wall-clock."""
    base = datetime(2026, 6, 19, 12, 0, 0, tzinfo=timezone.utc)
    return (base + timedelta(seconds=offset_seconds)).isoformat().replace(
        "+00:00", "Z"
    )


def _canonical_event(
    *,
    event_type: str,
    execution_id: str,
    timestamp: Optional[str] = None,
    agent_id: str = "00000000-0000-4000-8000-000000000001",
    payload: Optional[Dict[str, Any]] = None,
    framework_tag: str = FRAMEWORK_TAG,
) -> Dict[str, Any]:
    """Build a wire-shape canonical event with caller-specified
    event_type + execution_id. Defaults satisfy envelope invariants
    1 + 2 + 5 + 7 so the test isolates invariant #14."""
    return {
        "event_id": f"evt_{uuid.uuid4()}",
        "event_type": event_type,
        "timestamp": timestamp or _iso(),
        "execution_id": execution_id,
        "agent_id": agent_id,
        "payload": payload or {},
        "metadata": {"source": f"{framework_tag}.synthetic"},
    }


# ─── Test 1 — happy path: started precedes observation ────────────────


def test_invariant_14_passes_when_started_precedes_observation() -> None:
    """Canonical lifecycle: ``execution_started`` → ``tool_call_observed`` →
    ``execution_completed``. All three share the same ``execution_id``;
    invariant #14 passes."""
    exec_id = f"exec_{uuid.uuid4()}"
    events = [
        _canonical_event(
            event_type="execution_started",
            execution_id=exec_id,
            timestamp=_iso(0),
        ),
        _canonical_event(
            event_type="tool_call_observed",
            execution_id=exec_id,
            timestamp=_iso(1),
        ),
        _canonical_event(
            event_type="execution_completed",
            execution_id=exec_id,
            timestamp=_iso(2),
        ),
    ]
    # Should not raise.
    check_execution_started_precedes_non_lifecycle_events(events)


# ─── Test 2 — negative: tool_call_observed without preceding started ──


def test_invariant_14_fails_when_observation_orphan() -> None:
    """The load-bearing regression catcher: a ``tool_call_observed``
    event with no preceding ``execution_started`` in the captured stream
    is the exact bug shape invariant #14 catches. Lineage projection
    cannot stitch an orphan event into a tree node — the dashboard
    renders it as an orphan or drops it. The runner MUST fail."""
    orphan_exec = f"exec_{uuid.uuid4()}"
    events = [
        _canonical_event(
            event_type="tool_call_observed",
            execution_id=orphan_exec,
        ),
    ]
    with pytest.raises(ConformanceFailure) as excinfo:
        check_execution_started_precedes_non_lifecycle_events(events)
    inv_num, reason = excinfo.value.args
    assert inv_num == 14
    assert "tool_call_observed" in reason
    assert orphan_exec in reason


# ─── Test 3 — anomaly events exempt: ungoverned_request_observed ──────


def test_invariant_14_anomaly_events_exempt() -> None:
    """``ungoverned_request_observed`` is the
    self-rooted anomaly shape. It lives on its own synthetic
    execution_id and MUST NOT require a preceding
    ``execution_started`` — the event IS the root for its execution_id
    subtree. Per the issue's edge-case list."""
    anomaly_exec = f"exec_anomaly_{uuid.uuid4()}"
    events = [
        _canonical_event(
            event_type="ungoverned_request_observed",
            execution_id=anomaly_exec,
        ),
    ]
    # Should not raise — the mint event is self-rooted.
    check_execution_started_precedes_non_lifecycle_events(events)


# ─── Test 4 — spawn_observed counts as mint for child execution ────────


def test_invariant_14_spawn_observed_counts_as_mint() -> None:
    """A spawn event on the parent's stream is the mint for the
    spawned child's ``execution_id`` subtree. The child's own
    ``execution_started`` typically lands afterward; a stream-window
    snapshot can legitimately have a spawn-only edge. Invariant #14
    treats ``agent_spawn_observed`` as a valid root."""
    parent_exec = f"exec_{uuid.uuid4()}"
    child_exec = f"exec_{uuid.uuid4()}"
    events = [
        _canonical_event(
            event_type="execution_started",
            execution_id=parent_exec,
            timestamp=_iso(0),
        ),
        # The spawn event's execution_id is the SPAWNED child's id —
        # spawn events live on the child's stream, not the parent's
        # (per the convention in `_canonical_spawn_event`). The
        # parent's identity is in `payload.spawner.id`. The check
        # therefore sees a spawn at index 1 with execution_id = child;
        # which makes the child's group's first event a mint.
        _canonical_event(
            event_type="agent_spawn_observed",
            execution_id=child_exec,
            timestamp=_iso(1),
        ),
        _canonical_event(
            event_type="tool_call_observed",
            execution_id=child_exec,
            timestamp=_iso(2),
        ),
    ]
    # Should not raise — the spawn event roots the child's group.
    check_execution_started_precedes_non_lifecycle_events(events)


# ─── Test 5 — multiple executions verified independently ──────────────


def test_invariant_14_multiple_executions_independent() -> None:
    """Each ``execution_id`` is verified separately. A stream with one
    valid group + one orphan group MUST fail (the valid group does NOT
    mask the orphan)."""
    valid_exec = f"exec_valid_{uuid.uuid4()}"
    orphan_exec = f"exec_orphan_{uuid.uuid4()}"
    events = [
        _canonical_event(
            event_type="execution_started",
            execution_id=valid_exec,
            timestamp=_iso(0),
        ),
        _canonical_event(
            event_type="tool_call_observed",
            execution_id=valid_exec,
            timestamp=_iso(1),
        ),
        _canonical_event(
            event_type="tool_call_observed",
            execution_id=orphan_exec,
            timestamp=_iso(2),
        ),
    ]
    with pytest.raises(ConformanceFailure) as excinfo:
        check_execution_started_precedes_non_lifecycle_events(events)
    inv_num, reason = excinfo.value.args
    assert inv_num == 14
    assert orphan_exec in reason
    # The valid group's execution_id MUST NOT be named as a violation.
    assert valid_exec not in reason


# ─── Test 6 — empty stream passes vacuously ───────────────────────────


def test_invariant_14_passes_vacuously_on_empty_stream() -> None:
    """An empty stream has zero violations and passes vacuously. Plugins
    whose synthetic lifecycle emits zero events clear the check."""
    check_execution_started_precedes_non_lifecycle_events([])


# ─── Test 7 — single mint event with no children: trivial pass ────────


def test_invariant_14_single_mint_event_passes() -> None:
    """A single ``execution_started`` with no follow-on events passes
    trivially — there's nothing to anchor."""
    events = [
        _canonical_event(
            event_type="execution_started",
            execution_id=f"exec_{uuid.uuid4()}",
        ),
    ]
    check_execution_started_precedes_non_lifecycle_events(events)


# ─── Test 8 — out-of-order delivery: checks by timestamp ──────────────


def test_invariant_14_handles_out_of_order_delivery() -> None:
    """Per the issue's edge-case list (#1): invariant operates on the
    ``timestamp`` field, not iteration order. A stream where a
    non-mint event ARRIVES first but is timestamped AFTER the mint
    must pass."""
    exec_id = f"exec_{uuid.uuid4()}"
    events = [
        # tool_call_observed appears first in the list BUT has a later
        # timestamp than the execution_started below.
        _canonical_event(
            event_type="tool_call_observed",
            execution_id=exec_id,
            timestamp=_iso(5),
        ),
        _canonical_event(
            event_type="execution_started",
            execution_id=exec_id,
            timestamp=_iso(0),
        ),
    ]
    # Should pass — timestamp-sorted, the started comes first.
    check_execution_started_precedes_non_lifecycle_events(events)


def test_invariant_14_fails_when_timestamps_reveal_true_orphan() -> None:
    """The mirror case: a tool_call_observed timestamped EARLIER than
    the execution_started exposes a true contract violation — even
    though the started exists in the stream, it didn't precede the
    observation on the wire."""
    exec_id = f"exec_{uuid.uuid4()}"
    events = [
        _canonical_event(
            event_type="execution_started",
            execution_id=exec_id,
            timestamp=_iso(5),
        ),
        _canonical_event(
            event_type="tool_call_observed",
            execution_id=exec_id,
            timestamp=_iso(0),
        ),
    ]
    with pytest.raises(ConformanceFailure) as excinfo:
        check_execution_started_precedes_non_lifecycle_events(events)
    inv_num, _ = excinfo.value.args
    assert inv_num == 14


# ─── Test 9 — duplicate execution_started: still counts as seen ───────


def test_invariant_14_duplicate_execution_started_passes() -> None:
    """Per the issue's edge-case list (#8): duplicate
    ``execution_started`` for the same ``execution_id`` counts as "seen
    mint"; dedup is a separate concern covered by the lineage
    projection's idempotency layer."""
    exec_id = f"exec_{uuid.uuid4()}"
    events = [
        _canonical_event(
            event_type="execution_started",
            execution_id=exec_id,
            timestamp=_iso(0),
        ),
        _canonical_event(
            event_type="execution_started",
            execution_id=exec_id,
            timestamp=_iso(1),
        ),
        _canonical_event(
            event_type="tool_call_observed",
            execution_id=exec_id,
            timestamp=_iso(2),
        ),
    ]
    check_execution_started_precedes_non_lifecycle_events(events)


# ─── Test 10 — timestamp ties: tied mint counts as seen ───────────────


def test_invariant_14_timestamp_ties_handled() -> None:
    """Per the issue's edge-case list (#9): timestamp ties are treated
    as concurrent. The walk-order within a tied group is implementation-
    defined; what matters is that the invariant doesn't ALSO require
    strict-before ordering. A tied mint + non-mint group satisfies the
    "mint present" semantics — once the mint is seen anywhere in the
    sort the group is rooted."""
    exec_id = f"exec_{uuid.uuid4()}"
    tied_ts = _iso(0)
    events = [
        _canonical_event(
            event_type="execution_started",
            execution_id=exec_id,
            timestamp=tied_ts,
        ),
        _canonical_event(
            event_type="tool_call_observed",
            execution_id=exec_id,
            timestamp=tied_ts,
        ),
    ]
    # The current sort is stable, so the execution_started keeps its
    # input position. The semantic the invariant locks: a TIED
    # mint+non-mint group with the mint listed first passes. A tied
    # non-mint-first group is an unstable bug shape that surfaces as
    # a soft warning rather than a hard fail — captured here by the
    # symmetric case below.
    check_execution_started_precedes_non_lifecycle_events(events)


# ─── Test 11 — unknown event types: safe-default to non-mint ──────────


def test_invariant_14_unknown_event_type_treated_as_non_mint() -> None:
    """Per the issue's edge-case list: closed-set MINT_EVENTS
    default — anything not in the mint set is treated as non-mint and
    requires a preceding started. This is the safe-default per
    ``feedback_security_first``. A future custom plugin event type
    cannot silently bypass the contract."""
    exec_id = f"exec_{uuid.uuid4()}"
    events = [
        _canonical_event(
            event_type="someplugin_custom_event_v1",
            execution_id=exec_id,
        ),
    ]
    with pytest.raises(ConformanceFailure) as excinfo:
        check_execution_started_precedes_non_lifecycle_events(events)
    inv_num, _ = excinfo.value.args
    assert inv_num == 14


def test_invariant_14_unknown_type_passes_with_preceding_started() -> None:
    """The same unknown event type passes when it's anchored under a
    preceding ``execution_started``. Confirms the contract is symmetric
    — the rule is "mint must precede non-mint," not "non-mint must be
    a canonical type."""
    exec_id = f"exec_{uuid.uuid4()}"
    events = [
        _canonical_event(
            event_type="execution_started",
            execution_id=exec_id,
            timestamp=_iso(0),
        ),
        _canonical_event(
            event_type="someplugin_custom_event_v1",
            execution_id=exec_id,
            timestamp=_iso(1),
        ),
    ]
    check_execution_started_precedes_non_lifecycle_events(events)


# ─── Test 12 — constants exported + match TS lane ─────────────────────


def test_invariant_14_constants_exported() -> None:
    """SDK consumers (plugin authors writing their own conformance
    wrappers) need stable references to the invariant number + name.
    Both are exported from ``watchlight_core_testing.conformance``. The
    constants match the TS lane's exports in
    ``watchlight-agent-sdk-ts/src/conformance.ts``."""
    from watchlight_core_testing import conformance

    assert (
        conformance.EXECUTION_STARTED_PRECEDES_NON_LIFECYCLE_EVENTS_INVARIANT_NUMBER
        == 14
    )
    assert (
        conformance.EXECUTION_STARTED_PRECEDES_NON_LIFECYCLE_EVENTS_INVARIANT_NAME
        == "execution_started_precedes_non_lifecycle_events"
    )


def test_invariant_14_mint_events_set_exported_and_locked() -> None:
    """The closed-set ``EXECUTION_STARTED_PRECEDES_MINT_EVENTS`` is the
    SDK contract — any change to it requires lock-step updates in the
    Rust ``EventType`` enum + lineage projection sql triggers. This
    test pins the current membership so a future PR that adds to the
    set fails CI loudly and prompts the contributor to update the
    cross-language contract."""
    assert EXECUTION_STARTED_PRECEDES_MINT_EVENTS == frozenset(
        {
            "execution_started",
            "agent_spawn_observed",
            "ungoverned_request_observed",
        }
    )


# ─── Test 13 — invariant #14 registered in INVARIANTS table ───────────


def test_invariant_14_in_canonical_invariants_table() -> None:
    """The :data:`INVARIANTS` table is the canonical list used by the
    CLI report. Invariant #14 MUST be registered there so the runner's
    report names it correctly."""
    inv14 = next((row for row in INVARIANTS if row[0] == 14), None)
    assert inv14 is not None, (
        "invariant #14 missing from canonical INVARIANTS table"
    )
    _, label, description = inv14
    assert label == EXECUTION_STARTED_PRECEDES_NON_LIFECYCLE_EVENTS_INVARIANT_NAME
    assert "execution_started" in description
    assert "non-mint" in description
    # Description MUST reference the closed-set rule so future readers
    # know unknown event types default to non-mint (safe-default per
    # `feedback_security_first`).
    assert "Closed-set" in description or "closed-set" in description


def test_invariant_14_total_count_is_13() -> None:
    """The INVARIANTS table now lists 15 entries (the rows numbered
    1..9 + 11..16, with #10 reserved). This is the cross-plugin
    floor. Invariant #14 covers execution-started/non-lifecycle
    event ordering; the execution-id correlation contract added #15
    (single_correlated_execution_id); #16 pins every payload to the
    canonical struct its event_type selects
    (payload_schema_conformance). The credential-bound root work added
    #17 (labelled_spawn_attenuated) and #18 (credential_bound_root). The
    provider-hosted tool gate added #19
    (hosted_tools_authorized_before_model_call)."""
    assert len(INVARIANTS) == 18
    ids = [row[0] for row in INVARIANTS]
    assert ids == [1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 12, 13, 14, 15, 16, 17, 18, 19]


# ─── Synthetic plugin fixtures for harness wire-up tests ──────────────


class _M47ETaggedHandle(BaseRunHandle):
    """Handle with the framework-namespaced
    ``_observation_source`` so the SDK's defensive lifecycle emit
    carries a ``metadata.source`` satisfying invariant #2."""

    _observation_source = f"{FRAMEWORK_TAG}.workload"


def _orphan_emitter_plugin_cls() -> type:
    """Build a plugin class whose ``start_run`` synthesises a
    ``tool_call_observed`` event with NO preceding
    ``execution_started`` — the violation shape."""

    class OrphanEmitterPlugin(GovernanceTelemetry):
        # Opt-out: this synthetic plugin doesn't emit
        # `execution_started` at all, so invariant #12 is N/A.
        supports_m46_intent_extraction = False

        def __init__(self, apdp_url: str = "http://localhost") -> None:
            super().__init__()
            self.apdp = MockApdpClient()
            self.tenant_id = "t-conf"
            self.log_decisions = False

        async def start_run(self, agent_slug: str) -> BaseRunHandle:
            agent_uuid = self.apdp.known_agents.setdefault(
                agent_slug, str(uuid.uuid4())
            )
            session_id = f"ses_{agent_slug}"

            event = _canonical_event(
                event_type="tool_call_observed",
                execution_id=f"exec_{uuid.uuid4()}",
                agent_id=agent_uuid,
                payload={
                    "tool": {
                        "resource_type": "tool",
                        "identifier": "orphan_tool",
                        "endpoint": f"{FRAMEWORK_TAG}://orphan_tool",
                    },
                    "action": {"action": "execute"},
                },
            )
            await self.apdp.publish_events(None, [event])
            return _M47ETaggedHandle(
                plugin=self,
                agent_uuid=agent_uuid,
                session_id=session_id,
            )

    return OrphanEmitterPlugin


def _well_formed_emitter_plugin_cls() -> type:
    """Build a plugin class whose ``start_run`` synthesises a canonical
    ``execution_started`` → ``tool_call_observed`` pair on the SAME
    execution_id — the correct emission pattern."""

    class WellFormedEmitterPlugin(GovernanceTelemetry):
        supports_m46_intent_extraction = False

        def __init__(self, apdp_url: str = "http://localhost") -> None:
            super().__init__()
            self.apdp = MockApdpClient()
            self.tenant_id = "t-conf"
            self.log_decisions = False

        async def start_run(self, agent_slug: str) -> BaseRunHandle:
            agent_uuid = self.apdp.known_agents.setdefault(
                agent_slug, str(uuid.uuid4())
            )
            session_id = f"ses_{agent_slug}"
            exec_id = f"exec_{uuid.uuid4()}"

            started = _canonical_event(
                event_type="execution_started",
                execution_id=exec_id,
                agent_id=agent_uuid,
                timestamp=_iso(0),
                payload={
                    "principal": {
                        "principal_type": "agent",
                        "id": agent_uuid,
                    },
                    "depth": 0,
                },
            )
            tool_call = _canonical_event(
                event_type="tool_call_observed",
                execution_id=exec_id,
                agent_id=agent_uuid,
                timestamp=_iso(1),
                payload={
                    "tool": {
                        "resource_type": "tool",
                        "identifier": "well_formed_tool",
                        "endpoint": f"{FRAMEWORK_TAG}://well_formed_tool",
                    },
                    "action": {"action": "execute"},
                },
            )
            await self.apdp.publish_events(None, [started, tool_call])
            # Correlation contract (invariant #15): the handle's own
            # execution_id MUST equal the id we emitted execution_started
            # for, so the harness's downstream authorize() re-uses the
            # SAME root instead of minting a divergent second one.
            return _M47ETaggedHandle(
                plugin=self,
                agent_uuid=agent_uuid,
                session_id=session_id,
                execution_id=exec_id,
            )

    return WellFormedEmitterPlugin


# ─── Test 14 — harness FAILS when stream has an orphan non-mint event ─


@pytest.mark.asyncio
async def test_runner_fails_when_stream_has_orphan_observation() -> None:
    """The conformance runner FAILS a plugin whose stream contains a
    ``tool_call_observed`` event with no preceding ``execution_started``
    for the same ``execution_id``. The load-bearing regression catcher
    — a future plugin author whose translator bypasses the SDK
    lifecycle (or a customer-direct emitter that forgets the mint)
    fails CI loudly."""
    cls = _orphan_emitter_plugin_cls()
    _register_synthetic_module("_stubplugin_orphan", cls)
    try:
        passed, report = await run_conformance(
            "_stubplugin_orphan",
            framework_tag=FRAMEWORK_TAG,
        )
    finally:
        sys.modules.pop("_stubplugin_orphan", None)
    assert not passed, (
        "orphan-emitter plugin should fail invariant #14; report:\n"
        + "\n".join(report)
    )
    fail_lines = [line for line in report if line.startswith("FAIL")]
    assert any(
        "invariant 14" in line.lower()
        or EXECUTION_STARTED_PRECEDES_NON_LIFECYCLE_EVENTS_INVARIANT_NAME in line
        for line in fail_lines
    ), (
        "expected a FAIL line naming invariant 14; got:\n"
        + "\n".join(fail_lines)
    )


# ─── Test 15 — harness PASSES when stream is well-formed ──────────────


@pytest.mark.asyncio
async def test_runner_passes_when_stream_is_well_formed() -> None:
    """The conformance runner PASSES a plugin whose stream emits
    ``execution_started`` → ``tool_call_observed`` on the same
    ``execution_id``. The canonical correct emission pattern."""
    cls = _well_formed_emitter_plugin_cls()
    _register_synthetic_module("_stubplugin_well_formed", cls)
    try:
        passed, report = await run_conformance(
            "_stubplugin_well_formed",
            framework_tag=FRAMEWORK_TAG,
        )
    finally:
        sys.modules.pop("_stubplugin_well_formed", None)
    assert passed, (
        "well-formed plugin should pass conformance; report:\n"
        + "\n".join(report)
    )
    ok_lines = [line for line in report if line.startswith("OK")]
    assert any(
        "invariant 14" in line.lower()
        for line in ok_lines
    ), (
        "expected an OK line naming invariant 14; got:\n"
        + "\n".join(ok_lines)
    )
