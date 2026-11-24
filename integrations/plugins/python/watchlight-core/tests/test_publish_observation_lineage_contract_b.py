"""Dedicated tests for the lineage-contract guard in
:meth:`watchlight_core.BaseRunHandle.publish_observation`.

Promotes the ``_ensure_execution_started_emitted`` SDK guard from
:meth:`BaseRunHandle.authorize_action_detailed` to
:meth:`BaseRunHandle.publish_observation`. The guard ensures every
non-lifecycle event the SDK emits attaches to an execution whose
``execution_started`` was emitted earlier — closing the
``policy_decision_made``-style orphan-event observability gap for
the ``publish_observation`` lane.

The eight cases below mirror the contract surfaces:

1. **Happy path** — open RunHandle → call ``publish_observation`` →
   both ``execution_started`` (idempotent) AND the observation event
   are published exactly once.
2. **Without RunHandle** — standalone ``publish_observation`` call
   without entering the handle → raises
   :class:`WatchlightContractError` (fail-closed).
3. **Mismatched ``execution_id``** — explicit ``execution_id`` kwarg
   that differs from ``handle.execution_id`` → raises
   :class:`WatchlightContractError` (no orphan into another tree).
4. **Idempotency** — two consecutive ``publish_observation`` calls on
   the same handle → ``execution_started`` is emitted exactly ONCE
   total.
5. **Concurrent** — two ``asyncio.gather``'d ``publish_observation``
   calls → ``execution_started`` is emitted exactly ONCE (the
   per-handle :class:`asyncio.Lock` serialises the helper).
6. **Sub-agent** — child handle's ``publish_observation`` uses the
   child's ``execution_id`` and emits the child's own
   ``execution_started`` (NOT the parent's).
7. **Quarantine event path** — :meth:`_emit_quarantine_event`
   continues to work (no regression on the quarantine emission lane).
8. **Network failure on started emit** — fail-loud: the observation
   is NOT silently published when the started emit fails; the error
   propagates to the caller.

Per ``feedback_security_first`` (fail-closed on ambiguity) and
``feedback_enterprise_agent_runtime_governance_bar`` (every event
attached to an execution), the SDK refuses unsafe states at the
boundary rather than producing orphans.
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Optional

import pytest

from watchlight_core import (
    BaseRunHandle,
    WatchlightContractError,
    WatchlightError,
)
from watchlight_core.decision import QuarantineDecision
from watchlight_core.telemetry import GovernanceTelemetry
from watchlight_core_testing import MockApdpClient


# ─── Plugin fixture ────────────────────────────────────────────────────


class _Plugin(GovernanceTelemetry):
    """Minimal :class:`GovernedPlugin` mirroring the test_publish_observation
    fixture so these assertions don't fight the existing
    helper test surface.
    """

    def __init__(self, tenant_id: Optional[str] = "tenant-acme") -> None:
        super().__init__()
        self.apdp = MockApdpClient()
        self.tenant_id = tenant_id
        self.log_decisions = False
        self.kill_signal_registry = None


@pytest.fixture
def plugin() -> _Plugin:
    return _Plugin()


def _entered_handle(
    plugin: _Plugin,
    *,
    agent_uuid: str = "agent-uuid-lineage-contract",
    session_id: str = "ses_lineage_contract",
    execution_id: Optional[str] = None,
) -> BaseRunHandle:
    """Construct a handle and flip ``_aentered`` so the contract guard
    accepts direct ``publish_observation`` calls. Real customer code
    uses ``async with await plugin.start_run(...) as handle:`` which
    calls ``__aenter__`` for the same effect.
    """
    h = BaseRunHandle(
        plugin=plugin,
        agent_uuid=agent_uuid,
        session_id=session_id,
        execution_id=execution_id,
    )
    h._aentered = True
    return h


def _started_events(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [e for e in events if e["event_type"] == "execution_started"]


def _observation_events(
    events: List[Dict[str, Any]], event_type: str
) -> List[Dict[str, Any]]:
    return [e for e in events if e["event_type"] == event_type]


_VALID_TOOL_PAYLOAD: Dict[str, Any] = {
    "tool": {"resource_type": "tool", "identifier": "web_search"},
    "action": {"action": "execute"},
}


# ─── Case 1 — Happy path ──────────────────────────────────────────────


@pytest.mark.asyncio
async def test_happy_path_emits_execution_started_then_observation(
    plugin: _Plugin,
) -> None:
    """An open RunHandle → ``publish_observation`` MUST emit BOTH the
    defensive ``execution_started`` (idempotent) AND the observation
    event itself. The two events MUST carry the same ``execution_id``
    so wl-execution-graph stitches the observation under the right
    parent.
    """
    handle = _entered_handle(plugin)

    await handle.publish_observation(
        "tool_call_observed",
        payload=_VALID_TOOL_PAYLOAD,
    )

    started = _started_events(plugin.apdp.published_events)
    obs = _observation_events(plugin.apdp.published_events, "tool_call_observed")

    assert len(started) == 1, (
        f"defensive execution_started must land exactly once; "
        f"got {len(started)} events"
    )
    assert len(obs) == 1, (
        f"observation event must land exactly once; got {len(obs)}"
    )
    # Same execution_id ties the observation to its parent row.
    assert started[0]["execution_id"] == obs[0]["execution_id"]
    assert started[0]["execution_id"] == handle.execution_id
    # The defensive emission stamps the SDK
    # discriminator so the conformance harness can tell it apart from
    # a primary framework emission.
    assert (
        started[0]["metadata"].get("kind")
        == "execution_started_lineage_contract"
    )


# ─── Case 2 — Without RunHandle (fail-closed) ────────────────────────


@pytest.mark.asyncio
async def test_publish_observation_without_run_handle_raises_contract_error(
    plugin: _Plugin,
) -> None:
    """A standalone ``publish_observation`` call on a handle that has
    NOT been entered (``_aentered = False``) MUST raise
    :class:`WatchlightContractError`. Per the locked direction in
    ``project_ungoverned_request_gate_locked`` there is NO
    ``allow_no_run_handle=True`` escape hatch.
    """
    handle = BaseRunHandle(
        plugin=plugin,
        agent_uuid="agent-uuid-unentered",
        session_id="ses_unentered",
    )
    # ``_aentered`` defaults to False; we don't flip it.
    assert handle._aentered is False

    with pytest.raises(
        WatchlightContractError,
        match="publish_observation\\(\\) called without an open RunHandle",
    ):
        await handle.publish_observation(
            "tool_call_observed",
            payload=_VALID_TOOL_PAYLOAD,
        )

    # No event hit the wire — the guard refused at the boundary.
    assert plugin.apdp.published_events == []


# ─── Case 3 — Mismatched execution_id (fail-closed) ──────────────────


@pytest.mark.asyncio
async def test_publish_observation_with_mismatched_execution_id_raises(
    plugin: _Plugin,
) -> None:
    """An explicit ``execution_id`` kwarg that does NOT match
    ``self.execution_id`` MUST raise :class:`WatchlightContractError`.
    Workloads with a genuine cross-execution observation need will get
    a dedicated ``publish_observation_for_execution(execution_id, ...)``
    method.
    """
    handle = _entered_handle(
        plugin, execution_id="exec_handle_owned_001"
    )

    with pytest.raises(WatchlightContractError) as excinfo:
        await handle.publish_observation(
            "tool_call_observed",
            payload=_VALID_TOOL_PAYLOAD,
            execution_id="exec_some_other_tree_999",
        )

    msg = str(excinfo.value)
    assert "execution_id='exec_some_other_tree_999'" in msg
    assert "exec_handle_owned_001" in msg
    assert "publish_observation_for_execution" in msg, (
        "the typed error MUST point operators at the upcoming "
        "publish_observation_for_execution() method so they know "
        "the migration path"
    )

    # No event hit the wire.
    assert plugin.apdp.published_events == []


@pytest.mark.asyncio
async def test_publish_observation_with_matching_execution_id_is_accepted(
    plugin: _Plugin,
) -> None:
    """Passing the handle's OWN ``execution_id`` is fine — it's the
    same identity the SDK would auto-fill on omission. Confirms the
    guard fires only on mismatch, not on every explicit kwarg.
    """
    handle = _entered_handle(
        plugin, execution_id="exec_handle_owned_002"
    )

    await handle.publish_observation(
        "tool_call_observed",
        payload=_VALID_TOOL_PAYLOAD,
        execution_id="exec_handle_owned_002",
    )

    obs = _observation_events(plugin.apdp.published_events, "tool_call_observed")
    assert len(obs) == 1
    assert obs[0]["execution_id"] == "exec_handle_owned_002"


# ─── Case 4 — Idempotency across two sequential calls ────────────────


@pytest.mark.asyncio
async def test_two_sequential_publish_observation_calls_emit_started_once(
    plugin: _Plugin,
) -> None:
    """Two consecutive ``publish_observation`` calls on the same
    handle MUST produce exactly ONE ``execution_started`` event. The
    set guard in :meth:`_ensure_execution_started_emitted` makes the
    helper idempotent per (handle, execution_id).
    """
    handle = _entered_handle(plugin)

    await handle.publish_observation(
        "tool_call_observed",
        payload=_VALID_TOOL_PAYLOAD,
    )
    await handle.publish_observation(
        "tool_call_observed",
        payload={
            "tool": {"resource_type": "tool", "identifier": "doc_read"},
            "action": {"action": "execute"},
        },
    )

    started = _started_events(plugin.apdp.published_events)
    obs = _observation_events(plugin.apdp.published_events, "tool_call_observed")

    assert len(started) == 1, (
        f"execution_started must be emitted exactly ONCE across two "
        f"publish_observation calls; got {len(started)}"
    )
    assert len(obs) == 2
    # Both observations carry the handle's execution_id.
    assert all(e["execution_id"] == handle.execution_id for e in obs)


# ─── Case 5 — Concurrent calls under asyncio.gather ──────────────────


@pytest.mark.asyncio
async def test_concurrent_publish_observation_calls_emit_started_once(
    plugin: _Plugin,
) -> None:
    """Two ``asyncio.gather``'d ``publish_observation`` calls on the
    same handle MUST produce exactly ONE ``execution_started`` event.
    The per-handle :class:`asyncio.Lock` in
    :meth:`_ensure_execution_started_emitted` serialises the helper
    even under microtask interleaving.
    """
    handle = _entered_handle(plugin)

    await asyncio.gather(
        handle.publish_observation(
            "tool_call_observed",
            payload=_VALID_TOOL_PAYLOAD,
        ),
        handle.publish_observation(
            "tool_call_observed",
            payload={
                "tool": {"resource_type": "tool", "identifier": "doc_read"},
                "action": {"action": "execute"},
            },
        ),
    )

    started = _started_events(plugin.apdp.published_events)
    obs = _observation_events(plugin.apdp.published_events, "tool_call_observed")

    assert len(started) == 1, (
        f"execution_started must be emitted exactly ONCE under "
        f"asyncio.gather; got {len(started)} — the per-handle Lock "
        f"is not serialising the helper"
    )
    assert len(obs) == 2


# ─── Case 6 — Sub-agent attribution ──────────────────────────────────


@pytest.mark.asyncio
async def test_subagent_publish_observation_emits_child_execution_started(
    plugin: _Plugin,
) -> None:
    """``feedback_subagents_must_be_governed`` — when
    ``publish_observation`` is called on a sub-agent handle, the
    defensive ``execution_started`` MUST be emitted for the CHILD's
    ``execution_id`` and attributed to the CHILD's identity, NEVER
    the parent's. The child has its own
    ``_emitted_execution_started_for`` set.
    """
    parent = _entered_handle(
        plugin,
        agent_uuid="agent-parent-uuid",
        session_id="ses_parent",
        execution_id="exec_parent_001",
    )
    child = BaseRunHandle(
        plugin=plugin,
        agent_uuid="agent-child-uuid",
        session_id="ses_child",
        parent_handle=parent,
        execution_id="exec_child_001",
        parent_execution_id=parent.execution_id,
        root_execution_id=parent.root_execution_id,
        parent_agent_id=parent.agent_uuid,
    )
    child._aentered = True  # synthetic test child

    await child.publish_observation(
        "tool_call_observed",
        payload=_VALID_TOOL_PAYLOAD,
    )

    started = _started_events(plugin.apdp.published_events)
    obs = _observation_events(plugin.apdp.published_events, "tool_call_observed")

    assert len(started) == 1
    assert len(obs) == 1
    # Sub-agent attribution invariant — both events MUST be on the
    # child's identity, never the parent's.
    for event in (started[0], obs[0]):
        assert event["agent_id"] == "agent-child-uuid", (
            f"event {event['event_type']!r} attributed to "
            f"{event['agent_id']!r}; sub-agent governance invariant "
            f"requires the child's identity"
        )
        assert event["session_id"] == "ses_child"
        assert event["execution_id"] == "exec_child_001"
    # The started event carries the canonical parent linkage so
    # wl-execution-graph stitches the row under the parent's tree.
    assert started[0]["parent_execution_id"] == "exec_parent_001"


# ─── Case 7 — Quarantine event path (no regression) ──────────────────


@pytest.mark.asyncio
async def test_quarantine_event_emission_unaffected_by_m47b_guard(
    plugin: _Plugin,
) -> None:
    """The ``_emit_quarantine_event`` path (load-bearing quarantine
    emission) continues to work independently of the lineage-contract guard.
    The quarantine event has its own idempotence (the
    ``_quarantine_event_emitted`` flag) and does NOT route through
    ``publish_observation``; this test asserts there's no regression
    from the new ``_ensure_execution_started_emitted`` plumbing.
    """
    handle = _entered_handle(plugin)

    decision = QuarantineDecision(
        reason="quarantine regression probe",
        anomaly_score=0.91,
        contributing_features=[],
        model_version="probe-v1",
        policy_id="test.regression",
    )

    await handle._emit_quarantine_event(decision)
    # Idempotent — second call is a no-op.
    await handle._emit_quarantine_event(decision)

    quarantined = [
        e for e in plugin.apdp.published_events
        if e["event_type"] == "execution_quarantined"
    ]
    assert len(quarantined) == 1, (
        f"execution_quarantined must be emitted exactly ONCE per "
        f"handle; got {len(quarantined)}"
    )
    # The defensive execution_started is NOT minted on this path —
    # quarantine events stand alone in the audit trail (they mint
    # their own surrogate execution_id and the dashboard renders
    # them on the Anomalies surface, not the lineage tree).
    assert _started_events(plugin.apdp.published_events) == []


# ─── Case 8 — Fail-loud on started emit transport failure ────────────


@pytest.mark.asyncio
async def test_publish_observation_fails_loud_when_started_emit_fails(
    plugin: _Plugin,
) -> None:
    """When the defensive ``execution_started`` emit fails (transport
    failure, APDP unreachable, NATS down), the observation MUST NOT
    be silently published. The error propagates to the caller so a
    flaky transport surfaces as a clean failure rather than an
    orphan event the operator would have to debug.

    Per ``feedback_enterprise_agent_runtime_governance_bar``: every
    event attached to an execution — no exceptions.
    """
    handle = _entered_handle(plugin)

    async def _failing_publish(
        _events: List[Dict[str, Any]], session_token=None
    ) -> bool:
        return False

    plugin.apdp.publish_events = _failing_publish  # type: ignore[assignment]

    with pytest.raises(
        WatchlightError,
        match="APDP rejected execution_started defensive emission",
    ):
        await handle.publish_observation(
            "tool_call_observed",
            payload=_VALID_TOOL_PAYLOAD,
        )

    # The slot was NOT reserved — a retry has a clean slate to
    # attempt the emit again. We verify by swapping the mock back to
    # a working one and confirming the second attempt emits started
    # exactly once.
    plugin.apdp.publish_events = MockApdpClient().publish_events
    # Note: re-installing the bound method requires using the type's
    # publish_events on the original mock so we re-create a fresh
    # buffer.
    fresh_mock = MockApdpClient()
    plugin.apdp = fresh_mock  # type: ignore[assignment]

    await handle.publish_observation(
        "tool_call_observed",
        payload=_VALID_TOOL_PAYLOAD,
    )

    started = _started_events(fresh_mock.published_events)
    obs = _observation_events(fresh_mock.published_events, "tool_call_observed")
    assert len(started) == 1, (
        "after the transport failure cleared, a retry MUST emit "
        "execution_started exactly once — the slot must NOT have "
        "been pre-reserved on the failed attempt"
    )
    assert len(obs) == 1


# ─── Bonus — fail-loud on observation publish transport failure ──────


@pytest.mark.asyncio
async def test_publish_observation_fails_loud_when_observation_publish_fails(
    plugin: _Plugin,
) -> None:
    """When the observation's own publish fails (started emit
    succeeded), the SDK raises :class:`WatchlightError` with the
    canonical "APDP rejected publish_observation" message so workload
    code can branch on the failure mode distinctly from the started
    emit failure path.
    """
    handle = _entered_handle(plugin)
    # Pre-mark the handle's ``execution_started`` as emitted so the
    # defensive mint is suppressed; the only publish that happens is
    # the observation itself.
    handle.mark_execution_started_emitted(handle.execution_id)

    async def _failing_publish(
        _events: List[Dict[str, Any]], session_token=None
    ) -> bool:
        return False

    plugin.apdp.publish_events = _failing_publish  # type: ignore[assignment]

    with pytest.raises(
        WatchlightError,
        match="APDP rejected publish_observation",
    ):
        await handle.publish_observation(
            "tool_call_observed",
            payload=_VALID_TOOL_PAYLOAD,
        )
