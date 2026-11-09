"""Regression tests for the lineage contract.

The contract: every ``policy_decision_made`` event MUST attach to an
execution whose ``execution_started`` event was emitted earlier on
the wire. Without this linkage, the dashboard's ``/lineage`` view
renders no node for the deny — the operator sees no
audit row, which is the worst observability outcome for a Cedar
deny.

Two enforcement layers are tested here:

1.  **SDK defensive emit** — :meth:`watchlight_core.BaseRunHandle.__aenter__`
    publishes an ``execution_started`` event for the handle's own
    ``execution_id``; :meth:`authorize_action_detailed` mints one
    on-demand for any new ``execution_id`` the workload threads
    through. Both paths populate
    ``self._emitted_execution_started_for`` so duplicates are
    suppressed.

2.  **SDK fail-closed guard** — :meth:`authorize_action_detailed`
    raises :class:`watchlight_core.WatchlightContractError` when
    called outside the ``async with`` block (``_aentered = False``)
    unless ``allow_no_run_handle=True`` is passed.

Plus the cross-scenario invariant harness in
:func:`assert_no_orphan_policy_decisions` — given a list of emitted
events, asserts that every ``policy_decision_made`` event has an
earlier ``execution_started`` with the same ``execution_id``. This
is the load-bearing regression test that future scenario authors can
adopt to lock the contract in their own workloads.
"""

from __future__ import annotations

from typing import Any, Dict, List

import pytest

from watchlight_core import (
    BaseRunHandle,
    GovernanceTelemetry,
    WatchlightContractError,
)
from watchlight_core_testing import MockApdpClient, stub_handle


# ─── Test plugin ─────────────────────────────────────────────────────


class _Plugin(GovernanceTelemetry):
    """Minimal plugin satisfying the ``GovernedPlugin`` Protocol."""

    def __init__(self, apdp: MockApdpClient) -> None:
        super().__init__()
        self.apdp = apdp
        self.tenant_id = "tenant-test"
        self.log_decisions = False


# ─── Helpers ─────────────────────────────────────────────────────────


def assert_no_orphan_policy_decisions(
    events: List[Dict[str, Any]],
) -> None:
    """Regression-test harness: assert every ``policy_decision_made``
    event has a preceding ``execution_started`` event with the same
    ``execution_id``.

    Workloads adopt this harness by capturing the
    ``MockApdpClient.published_events`` buffer at the end of a
    scenario run and asserting the invariant. A failure here surfaces
    a scenario that bypasses the SDK's defensive
    ``execution_started`` emission AND publishes a
    ``policy_decision_made`` event manually — the exact orphan-event
    regression shape this suite guards against.

    Order matters — the assertion is "for every
    ``policy_decision_made``, exists an earlier ``execution_started``
    in the same event stream that shares the ``execution_id``". This
    mirrors the SQL invariant:

        SELECT count(*) FROM lineage.execution_events e
        WHERE e.event_type = 'policy_decision_made'
        AND NOT EXISTS (
            SELECT 1 FROM lineage.execution_events s
            WHERE s.event_type = 'execution_started'
              AND s.execution_id = e.execution_id
              AND s.timestamp <= e.timestamp
        );

    The harness intentionally ignores events with no
    ``execution_id`` — those are SDK-internal probes that don't
    participate in the lineage contract.
    """
    started_by_exec: Dict[str, int] = {}  # execution_id → first-seen index
    orphans: List[Dict[str, Any]] = []
    for i, event in enumerate(events):
        event_type = event.get("event_type")
        execution_id = event.get("execution_id")
        if not isinstance(execution_id, str):
            continue
        if event_type == "execution_started":
            started_by_exec.setdefault(execution_id, i)
        elif event_type == "policy_decision_made":
            started_idx = started_by_exec.get(execution_id)
            if started_idx is None or started_idx > i:
                orphans.append({
                    "index": i,
                    "execution_id": execution_id,
                    "event_id": event.get("event_id"),
                })

    if orphans:
        diag = "\n  ".join(
            f"event[{o['index']}] policy_decision_made "
            f"execution_id={o['execution_id']!r} "
            f"(no earlier execution_started)"
            for o in orphans
        )
        raise AssertionError(
            f"Contract violation — {len(orphans)} orphan "
            f"policy_decision_made event(s):\n  {diag}\n\n"
            f"Every policy_decision_made event MUST attach to an "
            f"execution whose execution_started was emitted earlier."
        )


# ─── SDK defensive emit ─────────────────────────────────────────────


@pytest.mark.asyncio
async def test_aenter_emits_execution_started_for_handle_own_id() -> None:
    """Entering an ``async with`` block on a handle emits an
    ``execution_started`` event for the handle's own ``execution_id``
    so any subsequent direct authorize call has a parent execution
    row.
    """
    apdp = MockApdpClient()
    apdp.known_agents["agent-1"] = "uuid-1"
    plugin = _Plugin(apdp)
    handle = BaseRunHandle(
        plugin=plugin, agent_uuid="uuid-1", session_id="ses_1"
    )
    handle_exec_id = handle.execution_id

    async with handle:
        # The defensive mint fired on __aenter__.
        started_events = [
            e for e in apdp.published_events
            if e.get("event_type") == "execution_started"
            and e.get("execution_id") == handle_exec_id
        ]
        assert len(started_events) == 1, (
            f"expected exactly one execution_started for the handle's own "
            f"exec_id; got {len(started_events)}"
        )


@pytest.mark.asyncio
async def test_authorize_action_mints_execution_started_for_new_exec_id() -> None:
    """When the workload threads a NEW ``execution_id`` into
    ``authorize_action_detailed``, the SDK mints an
    ``execution_started`` for it BEFORE the APDP round-trip.
    """
    apdp = MockApdpClient()
    apdp.known_agents["agent-1"] = "uuid-1"
    plugin = _Plugin(apdp)
    handle = BaseRunHandle(
        plugin=plugin, agent_uuid="uuid-1", session_id="ses_1"
    )
    workload_root_exec_id = "exec_workload-root-xxxxxxxxxxxxxxxxxxxxxxxxxx"

    async with handle:
        apdp.published_events.clear()
        # The workload threads its own root_execution_id.
        await handle.authorize_action_detailed(
            action="execute",
            resource="some_tool",
            execution_id=workload_root_exec_id,
        )

        started_events = [
            e for e in apdp.published_events
            if e.get("event_type") == "execution_started"
            and e.get("execution_id") == workload_root_exec_id
        ]
        assert len(started_events) == 1, (
            f"expected one execution_started for the workload-threaded "
            f"exec_id; got {len(started_events)}"
        )


@pytest.mark.asyncio
async def test_repeated_authorize_calls_do_not_duplicate_execution_started() -> None:
    """The defensive mint is idempotent per (handle, execution_id).
    Multiple authorize calls with the same ``execution_id`` produce
    exactly one ``execution_started`` on the wire.
    """
    apdp = MockApdpClient()
    apdp.known_agents["agent-1"] = "uuid-1"
    plugin = _Plugin(apdp)
    handle = BaseRunHandle(
        plugin=plugin, agent_uuid="uuid-1", session_id="ses_1"
    )
    workload_root_exec_id = "exec_workload-root-yyyyyyyyyyyyyyyyyyyyyyyy"

    async with handle:
        apdp.published_events.clear()
        for _ in range(5):
            await handle.authorize_action_detailed(
                action="execute",
                resource="tool",
                execution_id=workload_root_exec_id,
            )

        started_events = [
            e for e in apdp.published_events
            if e.get("event_type") == "execution_started"
            and e.get("execution_id") == workload_root_exec_id
        ]
        assert len(started_events) == 1, (
            f"expected exactly one execution_started across 5 authorize "
            f"calls; got {len(started_events)}"
        )


# ─── SDK fail-closed guard ──────────────────────────────────────────


@pytest.mark.asyncio
async def test_authorize_without_async_with_raises_contract_error() -> None:
    """Calling ``authorize_action`` on a handle that was never
    entered raises :class:`WatchlightContractError`. The error
    message points the caller at the ``async with`` block + the
    lineage contract doc.
    """
    apdp = MockApdpClient()
    apdp.known_agents["agent-1"] = "uuid-1"
    plugin = _Plugin(apdp)
    handle = BaseRunHandle(
        plugin=plugin, agent_uuid="uuid-1", session_id="ses_1"
    )

    # NOTE: no ``async with handle:``.
    with pytest.raises(WatchlightContractError) as exc_info:
        await handle.authorize_action("execute", "tool")

    assert "async with" in str(exc_info.value)
    assert "lineage" in str(exc_info.value).lower()


@pytest.mark.asyncio
async def test_authorize_without_async_with_detailed_raises_contract_error() -> None:
    """Mirror of the above for ``authorize_action_detailed``."""
    apdp = MockApdpClient()
    apdp.known_agents["agent-1"] = "uuid-1"
    plugin = _Plugin(apdp)
    handle = BaseRunHandle(
        plugin=plugin, agent_uuid="uuid-1", session_id="ses_1"
    )

    with pytest.raises(WatchlightContractError):
        await handle.authorize_action_detailed(
            action="execute", resource="tool"
        )


@pytest.mark.asyncio
async def test_authorize_after_async_with_exit_raises_contract_error() -> None:
    """After the ``async with`` block exits, subsequent authorize
    calls raise — the session is closing and any authorize is a bug.
    """
    apdp = MockApdpClient()
    apdp.known_agents["agent-1"] = "uuid-1"
    plugin = _Plugin(apdp)
    handle = BaseRunHandle(
        plugin=plugin, agent_uuid="uuid-1", session_id="ses_1"
    )

    async with handle:
        pass  # enter + exit cleanly

    with pytest.raises(WatchlightContractError):
        await handle.authorize_action("execute", "tool")


@pytest.mark.asyncio
async def test_allow_no_run_handle_kwarg_opts_out_of_guard() -> None:
    """The ``allow_no_run_handle=True`` escape hatch lets legitimate
    bootstrap / setup paths call authorize without entering. The
    SDK's defensive ``execution_started`` mint still fires.
    """
    apdp = MockApdpClient()
    apdp.known_agents["agent-1"] = "uuid-1"
    plugin = _Plugin(apdp)
    handle = BaseRunHandle(
        plugin=plugin, agent_uuid="uuid-1", session_id="ses_1"
    )

    # Should NOT raise.
    result = await handle.authorize_action(
        "execute", "bootstrap_tool", allow_no_run_handle=True
    )
    assert isinstance(result, bool)
    # The defensive mint still fired.
    started = [
        e for e in apdp.published_events
        if e.get("event_type") == "execution_started"
    ]
    assert started, "expected execution_started even with opt-out kwarg"


# ─── Cross-scenario invariant harness ───────────────────────────────


@pytest.mark.asyncio
async def test_no_orphans_after_typical_authorize_sequence() -> None:
    """End-to-end: a typical workload that opens a handle, threads
    a root_execution_id, and calls authorize multiple times produces
    zero orphan ``policy_decision_made`` events.

    Mirrors the `denied`-style scenario shape that is the canonical
    regression case for this contract.
    """
    apdp = MockApdpClient()
    apdp.known_agents["agent-1"] = "uuid-1"
    apdp.default_decision = "Deny"
    plugin = _Plugin(apdp)
    handle = BaseRunHandle(
        plugin=plugin, agent_uuid="uuid-1", session_id="ses_1"
    )

    async with handle:
        # ``authorize_action_detailed`` still accepts a
        # workload-root execution_id distinct from the handle's own
        # (the SDK mints a defensive ``execution_started`` for it via
        # the per-handle idempotent helper). The ``publish_observation``
        # contract, however, is tightened: the wire envelope MUST
        # attribute to the open handle's ``execution_id`` so the
        # observation lands under the handle's own tree (the workload's
        # cross-execution observation surface is
        # ``publish_observation_for_execution(...)``). Omitting the
        # kwarg defaults to ``handle.execution_id``, which is the
        # canonical contract pattern.
        await handle.authorize_action_detailed(
            action="execute",
            resource="some_tool",
        )
        # Simulate the workload publishing the canonical
        # policy_decision_made event (mirror of what wl-apdp emits
        # post-/authorize). PolicyDecisionMadePayload uses string
        # principal/action/resource (Cedar-form quoted), not the
        # PrincipalRef/ResourceRef objects used elsewhere.
        await handle.publish_observation(
            "policy_decision_made",
            payload={
                "decision": "Deny",
                "principal": 'Agent::"uuid-1"',
                "resource": 'Resource::"some_tool"',
                "action": 'Action::"execute"',
                "reason": "test",
            },
            parent_execution_id=handle.execution_id,
        )

    # Run the invariant harness over the captured events.
    assert_no_orphan_policy_decisions(apdp.published_events)


def test_harness_flags_an_orphan_policy_decision() -> None:
    """Negative test: the harness ACTUALLY catches the regression
    shape. A ``policy_decision_made`` event without an earlier
    ``execution_started`` for the same ``execution_id`` raises.
    """
    events = [
        {
            "event_type": "policy_decision_made",
            "execution_id": "exec_orphan",
            "event_id": "evt_1",
        },
    ]
    with pytest.raises(AssertionError) as exc_info:
        assert_no_orphan_policy_decisions(events)
    assert "orphan" in str(exc_info.value).lower()
    assert "exec_orphan" in str(exc_info.value)


def test_harness_accepts_proper_ordering() -> None:
    """Positive: the harness passes when each
    ``policy_decision_made`` has an earlier matching
    ``execution_started``.
    """
    events = [
        {
            "event_type": "execution_started",
            "execution_id": "exec_a",
            "event_id": "evt_1",
        },
        {
            "event_type": "policy_decision_made",
            "execution_id": "exec_a",
            "event_id": "evt_2",
        },
        {
            "event_type": "policy_decision_made",
            "execution_id": "exec_a",
            "event_id": "evt_3",
        },
    ]
    # Should not raise.
    assert_no_orphan_policy_decisions(events)


def test_harness_flags_out_of_order_emission() -> None:
    """The contract requires the ``execution_started`` to appear
    BEFORE the ``policy_decision_made``. An out-of-order emission
    (a sceanrio that publishes the decision first, then the
    started) is flagged.
    """
    events = [
        {
            "event_type": "policy_decision_made",
            "execution_id": "exec_a",
            "event_id": "evt_1",
        },
        {
            "event_type": "execution_started",
            "execution_id": "exec_a",
            "event_id": "evt_2",
        },
    ]
    with pytest.raises(AssertionError):
        assert_no_orphan_policy_decisions(events)


# ─── Compatibility — stub_handle and conformance opt-out ────────────


@pytest.mark.asyncio
async def test_stub_handle_bypasses_guard_for_unit_tests() -> None:
    """The :func:`stub_handle` factory creates handles with the
    fail-closed flag pre-flipped so unit tests can call
    ``authorize_action`` directly without an ``async with`` block.
    """
    apdp = MockApdpClient()
    plugin = _Plugin(apdp)
    h = stub_handle(plugin)
    # Should NOT raise.
    await h.authorize_action("read", "doc")


__all__ = [
    "assert_no_orphan_policy_decisions",
]
