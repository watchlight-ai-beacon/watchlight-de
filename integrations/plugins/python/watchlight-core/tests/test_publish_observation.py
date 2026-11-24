"""Tests for :meth:`watchlight_core.BaseRunHandle.publish_observation`.

The helper is the canonical workload-emission path: workloads call it
instead of constructing :class:`ExecutionEvent` envelopes by hand. The
helper:

* Constructs the canonical flat envelope + ``payload`` shape from the
  handle's session / agent / tenant context.
* Validates the result via :class:`watchlight_core.events_schema.ExecutionEvent`
  BEFORE the network call so shape mismatches raise at the call site
  rather than asynchronously from APDP's 422 reject.
* Stamps ``envelope.metadata.source`` from the handle subclass's
  :attr:`_observation_source` so downstream consumers can attribute
  events to the originating framework without parsing the payload.
* Posts the event via :meth:`ApdpClient.publish_events`.

This suite covers each of these contract surfaces. Sub-agent
governance (the load-bearing
``feedback_subagents_must_be_governed`` invariant) is exercised in
:func:`test_publish_observation_attributes_to_subagent_identity`.
"""

from __future__ import annotations

from typing import Any, List, Optional

import pytest
from pydantic import ValidationError

from watchlight_core import BaseRunHandle, WatchlightError
from watchlight_core.telemetry import GovernanceTelemetry
from watchlight_core_testing import MockApdpClient


# ─── Plugin fixture ────────────────────────────────────────────────────


class _Plugin(GovernanceTelemetry):
    """Minimal :class:`GovernedPlugin` for the helper tests.

    The helper reads ``tenant_id`` off the plugin and routes the
    publish through ``plugin.apdp.publish_events(None, [event])``.
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


@pytest.fixture
def handle(plugin: _Plugin) -> BaseRunHandle:
    h = BaseRunHandle(
        plugin=plugin,
        agent_uuid="agent-uuid-001",
        session_id="ses_pub_obs_001",
    )
    # Synthetic test handle bypasses the production
    # ``async with`` entry path; flip the fail-closed flag so the
    # lineage contract guard in ``publish_observation`` accepts the
    # test's direct emission. The new dedicated guard tests (see
    # ``test_publish_observation_lineage_contract_b.py``) construct
    # their own handles WITHOUT setting this flag so they can assert
    # the refusal path.
    h._aentered = True
    return h


# ─── Test 1 — Envelope shape + source tag ─────────────────────────────


@pytest.mark.asyncio
async def test_publish_observation_emits_canonical_envelope_with_default_source(
    plugin: _Plugin,
) -> None:
    """The envelope is flat (event_id at top level + payload nested) and
    carries the base-class default observation source.

    The explicit ``execution_id`` kwarg MUST match the
    handle's own ``execution_id``; the test constructs the handle
    with the matching value rather than relying on the auto-mint.
    """
    # A sub-agent handle (it has a parent), so a parent is stamped.
    handle = BaseRunHandle(
        plugin=plugin,
        agent_uuid="agent-uuid-001",
        session_id="ses_pub_obs_001",
        execution_id="exec_canonical_001",
        parent_execution_id="exec_root_001",
    )
    handle._aentered = True
    await handle.publish_observation(
        "tool_call_observed",
        payload={
            "tool": {"resource_type": "tool", "identifier": "web_search"},
            "action": {"action": "execute"},
            "input_summary": "q=hello",
        },
        execution_id="exec_canonical_001",
        parent_execution_id="exec_root_001",
    )

    # The first event MUST be the defensive ``execution_started``
    # mint from the lineage contract guard; the tool_call_observed
    # event follows.
    started = [
        e for e in plugin.apdp.published_events
        if e["event_type"] == "execution_started"
    ]
    obs = [
        e for e in plugin.apdp.published_events
        if e["event_type"] == "tool_call_observed"
    ]
    assert len(started) == 1
    assert started[0]["execution_id"] == "exec_canonical_001"
    assert len(obs) == 1
    event = obs[0]

    # Envelope keys at the top level (flat shape per Rust's
    # ``#[serde(flatten)]`` wire layout).
    assert event["event_type"] == "tool_call_observed"
    assert event["execution_id"] == "exec_canonical_001"
    assert event["agent_id"] == "agent-uuid-001"
    assert event["session_id"] == "ses_pub_obs_001"
    assert event["tenant_id"] == "tenant-acme"
    assert event["parent_execution_id"] == "exec_root_001"

    # event_id matches the canonical ``evt_<uuid>`` pattern.
    assert event["event_id"].startswith("evt_")
    assert len(event["event_id"]) == len("evt_") + 36  # uuid len

    # Payload is nested.
    assert event["payload"]["tool"]["identifier"] == "web_search"

    # Metadata.source defaults to the base-class identifier when no
    # subclass override has been applied.
    assert event["metadata"]["source"] == "watchlight-core.publish_observation"


# ─── Test 2 — Plugin subclass override of _observation_source ─────────


class _LangGraphLikeHandle(BaseRunHandle):
    """Mirrors the per-plugin override pattern documented in the brief."""

    _observation_source = "langgraph.workload"


@pytest.mark.asyncio
async def test_publish_observation_uses_subclass_observation_source(
    plugin: _Plugin,
) -> None:
    """Plugin RunHandle subclasses override
    :attr:`_observation_source` to identify the emitting framework on
    ``envelope.metadata.source``.
    """
    handle = _LangGraphLikeHandle(
        plugin=plugin,
        agent_uuid="agent-langgraph-001",
        session_id="ses_lg_001",
    )
    handle._aentered = True  # synthetic test handle

    await handle.publish_observation(
        "plan_observed",
        payload={
            "intended_tools": ["web_search", "document_read"],
            "plan_kind": "upfront",
        },
    )

    plan_events = [
        e for e in plugin.apdp.published_events
        if e["event_type"] == "plan_observed"
    ]
    assert len(plan_events) == 1
    event = plan_events[0]
    assert event["metadata"]["source"] == "langgraph.workload"


# ─── Test 3 — extra_metadata merges into envelope.metadata ────────────


@pytest.mark.asyncio
async def test_publish_observation_merges_extra_metadata(
    plugin: _Plugin,
    handle: BaseRunHandle,
) -> None:
    """``extra_metadata`` keys merge into the envelope metadata
    alongside the default ``source`` tag.
    """
    await handle.publish_observation(
        "tool_call_observed",
        payload={
            "tool": {"resource_type": "tool", "identifier": "doc_read"},
            "action": {"action": "execute"},
        },
        extra_metadata={
            "scenario": "denied",
            "step": 1,
            "operator_note": "Cedar gate fired",
        },
    )

    obs = [
        e for e in plugin.apdp.published_events
        if e["event_type"] == "tool_call_observed"
    ]
    assert len(obs) == 1
    metadata = obs[0]["metadata"]
    assert metadata["source"] == "watchlight-core.publish_observation"
    assert metadata["scenario"] == "denied"
    assert metadata["step"] == 1
    assert metadata["operator_note"] == "Cedar gate fired"


# ─── Test 4 — Pydantic validation raises on payload shape mismatch ────


@pytest.mark.asyncio
async def test_publish_observation_raises_on_payload_shape_mismatch(
    plugin: _Plugin,
    handle: BaseRunHandle,
) -> None:
    """The helper validates the constructed event BEFORE the network
    call. A payload that doesn't match the variant for the
    ``event_type`` raises :class:`pydantic.ValidationError` so the
    workload sees the diagnostic at the call site.
    """
    with pytest.raises(ValidationError):
        await handle.publish_observation(
            # ToolCallObservedPayload requires a ``tool`` field, not
            # the ApiRequestObservedPayload's ``resource`` field.
            "tool_call_observed",
            payload={
                "resource": {"resource_type": "http", "identifier": "x"},
                "method": "POST",
                "path": "/v1/x",
            },
        )

    # APDP must NOT have been called — validation runs before the
    # network round-trip.
    assert plugin.apdp.published_events == []


@pytest.mark.asyncio
async def test_publish_observation_raises_on_unknown_event_type(
    plugin: _Plugin,
    handle: BaseRunHandle,
) -> None:
    """An ``event_type`` outside the closed set raises before the
    network call.
    """
    with pytest.raises(ValidationError):
        await handle.publish_observation(
            "i_invented_this",
            payload={},
        )
    assert plugin.apdp.published_events == []


# ─── Test 5 — event_id format ─────────────────────────────────────────


@pytest.mark.asyncio
async def test_publish_observation_event_id_matches_canonical_pattern(
    plugin: _Plugin,
    handle: BaseRunHandle,
) -> None:
    """``event_id`` must match ``evt_<uuid v4>``. The conformance
    invariant #5 of the SDK contract anchors on this — SIEM
    correlation rules grep for the prefix.
    """
    import re

    pattern = re.compile(
        r"^evt_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
    )

    await handle.publish_observation(
        "execution_failed",
        payload={
            "duration_ms": 12,
            "error": "transient transport blip",
            "error_type": "TransportError",
            "policy_denied": False,
        },
    )

    # The SDK publishes a defensive ``execution_started`` before the
    # observation; assert the pattern on every event, not just the
    # first.
    for event in plugin.apdp.published_events:
        event_id = event["event_id"]
        assert pattern.match(event_id), (
            f"event_id {event_id!r} does not match canonical pattern"
        )


# ─── Test 6 — Auto-mints execution_id when omitted ────────────────────


@pytest.mark.asyncio
async def test_publish_observation_auto_mints_execution_id_when_omitted(
    plugin: _Plugin,
    handle: BaseRunHandle,
) -> None:
    """When ``execution_id`` is not passed the helper falls back to the
    handle's own ``execution_id`` so the envelope never goes out with
    a missing required field. (The wire envelope MUST attach to the
    handle's lineage; an auto-mint of a fresh ``exec_<uuid>`` would
    have orphaned the observation.)
    """
    await handle.publish_observation(
        "execution_failed",
        payload={
            "duration_ms": 0,
            "error": "test",
            "policy_denied": False,
        },
    )

    failed = [
        e for e in plugin.apdp.published_events
        if e["event_type"] == "execution_failed"
    ]
    assert len(failed) == 1
    exec_id = failed[0]["execution_id"]
    assert exec_id == handle.execution_id, (
        "publish_observation MUST attribute the event to the "
        "handle's own execution_id when no override is supplied; a "
        "fresh-uuid mint would orphan the event"
    )
    assert exec_id.startswith("exec_")


# ─── Test 7 — APDP rejection raises WatchlightError ───────────────────


@pytest.mark.asyncio
async def test_publish_observation_raises_watchlight_error_on_apdp_reject(
    plugin: _Plugin,
    handle: BaseRunHandle,
) -> None:
    """When ``publish_events`` returns ``False`` for the observation
    event itself (the defensive ``execution_started`` having already
    landed), the helper raises :class:`watchlight_core.WatchlightError`
    so workload code can branch on the failure mode (distinct from
    the :class:`ValidationError` path that signals shape mismatch).

    Pre-mark the handle's ``execution_started`` as
    emitted so the only failing publish is the observation itself —
    isolating the ``"APDP rejected publish_observation"`` branch.
    The transport-failure-on-started-emit branch is covered by
    ``test_publish_observation_fails_loud_when_started_emit_fails`` in
    ``test_publish_observation_lineage_contract_b.py``.
    """

    async def _failing_publish(_events: List[dict], session_token=None) -> bool:
        return False

    # Pre-mark the handle's ``execution_started`` as emitted so the
    # defensive mint is suppressed; the only publish that
    # happens is the observation itself.
    handle.mark_execution_started_emitted(handle.execution_id)

    plugin.apdp.publish_events = _failing_publish  # type: ignore[assignment]

    with pytest.raises(WatchlightError, match="APDP rejected publish_observation"):
        await handle.publish_observation(
            "execution_failed",
            payload={
                "duration_ms": 0,
                "error": "anything",
                "policy_denied": False,
            },
        )


# ─── Test 8 — Sub-agent attribution (governed sub-agent invariant) ────


@pytest.mark.asyncio
async def test_publish_observation_attributes_to_subagent_identity(
    plugin: _Plugin,
) -> None:
    """``feedback_subagents_must_be_governed`` — when the helper is
    called on a sub-agent handle, the event MUST be attributed to the
    SUB-AGENT's agent_uuid/session_id, NEVER the parent's. Using the
    parent's identity would be a privilege-attribution bug that
    breaks the audit trail.

    This test constructs a parent + child handle pair (mirroring the
    spawn-subagent topology) and asserts the child's emission carries
    the child's identity, not the parent's.
    """
    parent = BaseRunHandle(
        plugin=plugin,
        agent_uuid="agent-parent-uuid",
        session_id="ses_parent",
    )
    parent._aentered = True  # synthetic test parent handle
    child = BaseRunHandle(
        plugin=plugin,
        agent_uuid="agent-child-uuid",
        session_id="ses_child",
        parent_handle=parent,
    )
    child._aentered = True  # synthetic test child handle

    await child.publish_observation(
        "tool_call_observed",
        payload={
            "tool": {"resource_type": "tool", "identifier": "doc_read"},
            "action": {"action": "execute"},
        },
    )

    # The SDK publishes the defensive ``execution_started`` first; the
    # tool_call_observed event is the second event but BOTH must be
    # attributed to the SUB-AGENT, never the parent.
    for event in plugin.apdp.published_events:
        assert event["agent_id"] == "agent-child-uuid", (
            f"publish_observation event {event['event_type']!r} must "
            f"attribute to the SUB-AGENT's identity, never the parent's "
            f"— privilege attribution invariant "
            f"(feedback_subagents_must_be_governed)"
        )
        assert event["session_id"] == "ses_child"


# ─── Test 9 — timestamp is RFC3339 UTC with Z suffix ──────────────────


@pytest.mark.asyncio
async def test_publish_observation_timestamp_is_rfc3339_utc_with_z_suffix(
    plugin: _Plugin,
    handle: BaseRunHandle,
) -> None:
    """The wire timestamp is RFC3339 UTC. Rust's chrono parser expects
    a trailing ``Z`` for UTC; Python's ``isoformat()`` emits ``+00:00``.
    The helper normalises to the ``Z`` shape so APDP's deserialiser
    accepts the event without an additional canonicaliser.
    """
    await handle.publish_observation(
        "execution_failed",
        payload={
            "duration_ms": 0,
            "error": "x",
            "policy_denied": False,
        },
    )
    # The SDK publishes a defensive ``execution_started`` before the
    # observation; assert the canonical RFC3339-Z shape on every
    # event.
    for event in plugin.apdp.published_events:
        timestamp = event["timestamp"]
        assert isinstance(timestamp, str)
        assert timestamp.endswith("Z"), (
            f"timestamp {timestamp!r} must end with 'Z' for canonical "
            f"RFC3339 UTC encoding (chrono parses this; +00:00 also works "
            f"but Z is the canonical form)"
        )


# ─── Test 10 — payload variants are all rejected when wrong ───────────


@pytest.mark.parametrize(
    "event_type,bad_payload",
    [
        ("api_request_observed", {"foo": "bar"}),  # missing resource/method/path
        ("policy_decision_made", {"decision": "Allow"}),  # missing principal/action/resource
        ("execution_completed", {"actions_taken": 1}),  # missing duration_ms
        ("plan_observed", {"intended_tools": []}),  # empty list fails min_length
    ],
)
@pytest.mark.asyncio
async def test_publish_observation_rejects_invalid_payload_variants(
    plugin: _Plugin,
    handle: BaseRunHandle,
    event_type: str,
    bad_payload: dict,
) -> None:
    """Every closed-set event_type has a strict payload variant. The
    helper enforces each one — workloads that get the payload shape
    wrong see the diagnostic at the call site.
    """
    with pytest.raises(ValidationError):
        await handle.publish_observation(event_type, payload=bad_payload)
    assert plugin.apdp.published_events == []
