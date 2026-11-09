"""Tests for :meth:`BaseRunHandle.publish_observation_for_execution` —
the documented escape hatch for legitimate cross-execution observations.

The strict :meth:`publish_observation` method refuses any divergent
``execution_id`` kwarg by design — the locked contract in
``project_ungoverned_request_gate_locked`` forbids loosening the main
helper. The dedicated escape hatch is this method, with intentional
naming (``_for_execution`` is the deliberate intent signal at the
call site).

The cases below cover every contract surface of the escape hatch:

1. **Happy path** — open RunHandle → call with cross-execution id →
   event lands with the EXPLICIT ``execution_id`` (not the handle's).
2. **Without RunHandle** — call outside the handle's ``async with``
   block → raises :class:`WatchlightContractError`. Even the escape
   hatch refuses to emit observations without an open governance
   context.
3. **Matching execution_id (degenerate)** — caller passes the
   handle's OWN ``execution_id`` to the cross-execution method →
   accepted; emits with the handle's id (no behaviour difference).
4. **Cross-execution does NOT auto-mint execution_started** — the
   method does NOT call ``_ensure_execution_started_emitted`` for an
   external ``execution_id`` (precedence enforcement is the
   ingest gateway's job; the SDK does not have visibility on the
   target's lifecycle).
5. **Same-execution DOES auto-mint execution_started** — the
   degenerate case where ``execution_id == self.execution_id`` keeps
   the defensive mint behaviour to stay drop-in compatible.
6. **parent_execution_id / root_execution_id propagate** — caller
   can stamp the lineage tree hints on the envelope.
7. **extra_metadata propagates** — same merge semantics as the
   strict ``publish_observation`` helper.
8. **APDP transport failure** — fail-loud per
   ``feedback_enterprise_agent_runtime_governance_bar`` (the
   observation is NOT silently dropped; the error propagates).
9. **Pydantic validation runs BEFORE the network call** — a shape
   mismatch surfaces at the call site, not asynchronously from
   APDP's reject.
10. **Identity attribution stays with the handle** — the wire
    envelope carries this handle's ``agent_id`` / ``session_id``
    regardless of the cross-execution ``execution_id`` (per
    ``feedback_subagents_must_be_governed``).

Per ``feedback_security_first`` and
``feedback_enterprise_agent_runtime_governance_bar`` the escape
hatch ships with the same fail-closed guards as the strict method
on every surface where the contract is unambiguous; the only
loosening is the one explicitly required by the locked contract
(cross-execution ``execution_id`` is the entire point of this
method).
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

import pydantic
import pytest

from watchlight_core import (
    BaseRunHandle,
    WatchlightContractError,
    WatchlightError,
)
from watchlight_core.telemetry import GovernanceTelemetry
from watchlight_core_testing import MockApdpClient


# ─── Plugin fixture ────────────────────────────────────────────────────


class _Plugin(GovernanceTelemetry):
    """Minimal plugin shell, mirrors the publish_observation test fixture
    so the cross-execution cases share the same scaffolding."""

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
    agent_uuid: str = "agent-uuid-followup",
    session_id: str = "ses_followup",
    execution_id: Optional[str] = None,
    parent_execution_id: Optional[str] = None,
) -> BaseRunHandle:
    """Construct a handle and flip ``_aentered`` so the contract guard
    accepts direct ``publish_observation_for_execution`` calls.
    Real customer code uses
    ``async with await plugin.start_run(...) as handle:``.
    """
    h = BaseRunHandle(
        plugin=plugin,
        agent_uuid=agent_uuid,
        session_id=session_id,
        execution_id=execution_id,
        parent_execution_id=parent_execution_id,
    )
    h._aentered = True
    return h


def _started_events(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [e for e in events if e["event_type"] == "execution_started"]


def _events_of_type(
    events: List[Dict[str, Any]], event_type: str
) -> List[Dict[str, Any]]:
    return [e for e in events if e["event_type"] == event_type]


_VALID_PLAN_PAYLOAD: Dict[str, Any] = {
    "intended_tools": ["web_search", "document_read"],
    "plan_kind": "upfront",
    "rationale": "plan-act demo scenario",
}

_VALID_TOOL_PAYLOAD: Dict[str, Any] = {
    "tool": {"resource_type": "tool", "identifier": "web_search"},
    "action": {"action": "execute"},
}


# ─── Case 1 — Happy path ──────────────────────────────────────────────


@pytest.mark.asyncio
async def test_happy_path_cross_execution_id_lands_on_target(
    plugin: _Plugin,
) -> None:
    """An open RunHandle → ``publish_observation_for_execution`` with
    an explicit cross-execution ``execution_id`` MUST emit the
    observation event with the EXPLICIT id stamped on the envelope
    (NOT the handle's own id). The escape hatch's whole purpose is
    cross-execution attribution.
    """
    handle = _entered_handle(plugin, execution_id="exec_handle_owned_001")

    target_execution_id = "exec_workflow_root_aabb"

    await handle.publish_observation_for_execution(
        "plan_observed",
        execution_id=target_execution_id,
        payload=_VALID_PLAN_PAYLOAD,
        parent_execution_id=target_execution_id,
    )

    plan_events = _events_of_type(plugin.apdp.published_events, "plan_observed")
    assert len(plan_events) == 1
    # The observation lands on the TARGET id, not the handle's own id.
    assert plan_events[0]["execution_id"] == target_execution_id
    # A parent equal to the event's own execution is dropped
    # (wl-apdp would refuse the whole /v1/events batch).
    assert "parent_execution_id" not in plan_events[0]
    # Identity attribution stays with the calling handle.
    assert plan_events[0]["agent_id"] == handle.agent_uuid
    assert plan_events[0]["session_id"] == handle.session_id


# ─── Case 2 — Without RunHandle (fail-closed) ────────────────────────


@pytest.mark.asyncio
async def test_publish_observation_for_execution_without_run_handle_raises(
    plugin: _Plugin,
) -> None:
    """A standalone call on a handle that has NOT been entered
    (``_aentered = False``) MUST raise :class:`WatchlightContractError`.
    Even the explicit escape hatch refuses to emit observations
    without an open governance context — the SDK is the first
    enforcement layer per the closed-set lineage contract.
    """
    handle = BaseRunHandle(
        plugin=plugin,
        agent_uuid="agent-uuid-unentered-followup",
        session_id="ses_unentered_followup",
    )
    # ``_aentered`` defaults to False; we don't flip it.
    assert handle._aentered is False

    with pytest.raises(
        WatchlightContractError,
        match=(
            "publish_observation_for_execution\\(\\) called without an "
            "open RunHandle"
        ),
    ):
        await handle.publish_observation_for_execution(
            "plan_observed",
            execution_id="exec_workflow_root_xyz",
            payload=_VALID_PLAN_PAYLOAD,
        )

    # No event hit the wire — the guard refused at the boundary.
    assert plugin.apdp.published_events == []


# ─── Case 3 — Matching execution_id (degenerate but legal) ────────────


@pytest.mark.asyncio
async def test_matching_execution_id_is_accepted(plugin: _Plugin) -> None:
    """Passing the handle's OWN ``execution_id`` to the cross-execution
    method is legal — the method does NOT enforce
    ``execution_id != self.execution_id`` (that would be the wrong
    semantics; the caller has explicitly opted into the escape hatch
    and is allowed to land on the same execution as the handle).

    Same-id IS the migration sweet spot for callers who want one
    code path that works for both same-execution and cross-execution
    emits without an if-else.
    """
    handle = _entered_handle(plugin, execution_id="exec_handle_owned_002")

    await handle.publish_observation_for_execution(
        "tool_call_observed",
        execution_id="exec_handle_owned_002",  # same as handle
        payload=_VALID_TOOL_PAYLOAD,
    )

    obs = _events_of_type(plugin.apdp.published_events, "tool_call_observed")
    assert len(obs) == 1
    assert obs[0]["execution_id"] == "exec_handle_owned_002"


# ─── Case 4 — Cross-execution does NOT auto-mint started ─────────────


@pytest.mark.asyncio
async def test_cross_execution_id_does_not_auto_mint_execution_started(
    plugin: _Plugin,
) -> None:
    """When the explicit ``execution_id`` differs from the handle's
    own, the SDK MUST NOT auto-mint an ``execution_started`` for the
    target id. The target's precedence is enforced at the
    ingest gateway (the right layer — it has visibility across all
    handles and services); minting one here would stamp it with THIS
    handle's identity, which is the wrong attribution.
    """
    handle = _entered_handle(plugin, execution_id="exec_handle_owned_003")

    await handle.publish_observation_for_execution(
        "plan_observed",
        execution_id="exec_external_target_999",
        payload=_VALID_PLAN_PAYLOAD,
    )

    started = _started_events(plugin.apdp.published_events)
    # No defensive execution_started landed for the external target.
    assert started == [], (
        f"cross-execution publish must NOT auto-mint execution_started "
        f"for an external target; got {started}"
    )
    # The handle's set should NOT have the external id added — we
    # leave precedence enforcement to the ingest gateway.
    assert (
        "exec_external_target_999"
        not in handle._emitted_execution_started_for
    )


# ─── Case 5 — Same-execution DOES auto-mint started ──────────────────


@pytest.mark.asyncio
async def test_same_execution_id_does_auto_mint_execution_started(
    plugin: _Plugin,
) -> None:
    """When the caller passes the handle's own ``execution_id``
    (degenerate but legal case 3), the defensive mint still
    runs. Drop-in compatibility for callers who migrate to the
    escape hatch but only sometimes pass a cross-execution id.
    """
    handle = _entered_handle(plugin, execution_id="exec_handle_owned_004")

    await handle.publish_observation_for_execution(
        "tool_call_observed",
        execution_id="exec_handle_owned_004",  # same as handle
        payload=_VALID_TOOL_PAYLOAD,
    )

    started = _started_events(plugin.apdp.published_events)
    assert len(started) == 1, (
        f"same-execution publish via escape hatch MUST still mint the "
        f"defensive execution_started; got {len(started)}"
    )
    assert started[0]["execution_id"] == "exec_handle_owned_004"


# ─── Case 6 — Lineage tree hints propagate ───────────────────────────


@pytest.mark.asyncio
async def test_parent_and_root_execution_id_propagate_on_envelope(
    plugin: _Plugin,
) -> None:
    """``parent_execution_id`` and ``root_execution_id`` MUST be stamped
    on the envelope so wl-execution-graph stitches the event into the
    correct lineage tree position. Both are optional per the schema
    (``events_schema.ExecutionEvent``).
    """
    # A SUB-AGENT handle (it has a parent) keeps a genuine parent.
    handle = _entered_handle(
        plugin,
        execution_id="exec_handle_owned_005",
        parent_execution_id="exec_parent_node_88",
    )

    await handle.publish_observation_for_execution(
        "plan_observed",
        execution_id="exec_child_node_77",
        payload=_VALID_PLAN_PAYLOAD,
        parent_execution_id="exec_parent_node_88",
        root_execution_id="exec_workflow_root_aa",
    )

    obs = _events_of_type(plugin.apdp.published_events, "plan_observed")
    assert len(obs) == 1
    assert obs[0]["execution_id"] == "exec_child_node_77"
    assert obs[0]["parent_execution_id"] == "exec_parent_node_88"
    assert obs[0]["root_execution_id"] == "exec_workflow_root_aa"


@pytest.mark.asyncio
async def test_a_root_handle_never_stamps_a_parent(plugin: _Plugin) -> None:
    """A ROOT run's credential disproves any parent (wl-apdp
    refuses the whole batch), so a root handle drops a caller parent."""
    handle = _entered_handle(plugin, execution_id="exec_root_handle_006")

    await handle.publish_observation_for_execution(
        "plan_observed",
        execution_id="exec_child_node_78",
        payload=_VALID_PLAN_PAYLOAD,
        parent_execution_id="exec_parent_node_89",
    )

    obs = _events_of_type(plugin.apdp.published_events, "plan_observed")
    assert len(obs) == 1
    assert "parent_execution_id" not in obs[0]


# ─── Case 7 — extra_metadata propagates ──────────────────────────────


@pytest.mark.asyncio
async def test_extra_metadata_merges_into_envelope_metadata(
    plugin: _Plugin,
) -> None:
    """``extra_metadata`` merges into ``envelope.metadata``, mirroring
    the strict :meth:`publish_observation` behaviour. Caller-supplied
    keys override the default ``source`` tag.
    """
    handle = _entered_handle(plugin, execution_id="exec_handle_owned_006")

    await handle.publish_observation_for_execution(
        "api_request_observed",
        execution_id="exec_workflow_root_bb",
        payload={
            "resource": {
                "resource_type": "llm_api",
                "identifier": "proxy-llm",
            },
            "method": "POST",
            "path": "/v1/chat/completions",
            "response_status": 200,
        },
        extra_metadata={
            "transport_path": "connect_via_wl_proxy",
            "tls_handling": "passthrough",
        },
    )

    obs = _events_of_type(
        plugin.apdp.published_events, "api_request_observed"
    )
    assert len(obs) == 1
    md = obs[0]["metadata"]
    # Default source stays present (since extra_metadata did not
    # override it).
    assert md.get("source") == handle._observation_source
    # Caller-supplied tags merged through.
    assert md.get("transport_path") == "connect_via_wl_proxy"
    assert md.get("tls_handling") == "passthrough"


# ─── Case 8 — APDP transport failure is fail-loud ────────────────────


class _FailingApdp(MockApdpClient):
    """Mock APDP that returns False (publish rejected) for every call.
    Used to assert the escape hatch propagates a typed
    :class:`WatchlightError` instead of silently swallowing.
    """

    async def publish_events(self, run, events):  # type: ignore[override]
        # Still record the attempted events so the test can inspect
        # what would have shipped.
        self.published_events.extend(events)
        return False


@pytest.mark.asyncio
async def test_apdp_transport_failure_propagates_watchlight_error() -> None:
    """If APDP rejects the publish, the escape hatch MUST raise
    :class:`WatchlightError` so the workload can branch on the
    failure. Fail-loud per
    ``feedback_enterprise_agent_runtime_governance_bar``: an
    observation is never silently dropped.
    """
    plugin = _Plugin()
    plugin.apdp = _FailingApdp()
    handle = _entered_handle(plugin, execution_id="exec_handle_owned_007")

    with pytest.raises(WatchlightError) as excinfo:
        await handle.publish_observation_for_execution(
            "plan_observed",
            execution_id="exec_workflow_root_cc",
            payload=_VALID_PLAN_PAYLOAD,
        )

    msg = str(excinfo.value)
    assert "APDP rejected" in msg
    assert "plan_observed" in msg


# ─── Case 9 — Pydantic validation runs before the network call ───────


@pytest.mark.asyncio
async def test_invalid_payload_shape_raises_validation_error_before_emit(
    plugin: _Plugin,
) -> None:
    """A payload that does not match the canonical event-type variant
    MUST raise a Pydantic :class:`ValidationError` BEFORE any wire
    I/O. The diagnostic lands at the call site, not asynchronously
    from APDP's 422.
    """
    handle = _entered_handle(plugin, execution_id="exec_handle_owned_008")

    # ``plan_observed`` requires ``intended_tools`` (list) +
    # ``plan_kind``; passing a tool-call shape is a clean shape
    # mismatch.
    with pytest.raises(pydantic.ValidationError):
        await handle.publish_observation_for_execution(
            "plan_observed",
            execution_id="exec_workflow_root_dd",
            payload={  # tool_call_observed shape — wrong for plan_observed
                "tool": {"resource_type": "tool", "identifier": "x"},
                "action": {"action": "execute"},
            },
        )

    # No event hit the wire — validation refused at the boundary.
    assert plugin.apdp.published_events == []


# ─── Case 10 — Identity attribution stays with the calling handle ────


@pytest.mark.asyncio
async def test_identity_attribution_stays_with_calling_handle(
    plugin: _Plugin,
) -> None:
    """Cross-execution attribution changes the ``execution_id`` on the
    envelope but NOT the ``agent_id`` / ``session_id``. Per
    ``feedback_subagents_must_be_governed`` the principal identity is
    a load-bearing audit-trail field; emitting an event with the
    target execution's id but THIS handle's identity is the correct
    semantics (the caller is observing something about the target
    execution from their own principal context).
    """
    handle = _entered_handle(
        plugin,
        agent_uuid="agent-uuid-orchestrator",
        session_id="ses_orchestrator_run_xyz",
        execution_id="exec_handle_owned_009",
    )

    await handle.publish_observation_for_execution(
        "plan_observed",
        execution_id="exec_workflow_root_ee",
        payload=_VALID_PLAN_PAYLOAD,
    )

    obs = _events_of_type(plugin.apdp.published_events, "plan_observed")
    assert len(obs) == 1
    # The execution_id is the cross-execution target.
    assert obs[0]["execution_id"] == "exec_workflow_root_ee"
    # But the identity attribution is the calling handle's.
    assert obs[0]["agent_id"] == "agent-uuid-orchestrator"
    assert obs[0]["session_id"] == "ses_orchestrator_run_xyz"


# ─── Case 11 — Tenant context is stamped on the envelope ─────────────


@pytest.mark.asyncio
async def test_tenant_id_propagates_from_plugin_context() -> None:
    """Multi-tenant safety: the envelope MUST carry the plugin's
    ``tenant_id`` so wl-apdp's tenant scope filter applies on the
    cross-execution emit too.
    """
    plugin = _Plugin(tenant_id="tenant-multi-abc")
    handle = _entered_handle(plugin, execution_id="exec_handle_owned_010")

    await handle.publish_observation_for_execution(
        "plan_observed",
        execution_id="exec_workflow_root_ff",
        payload=_VALID_PLAN_PAYLOAD,
    )

    obs = _events_of_type(plugin.apdp.published_events, "plan_observed")
    assert len(obs) == 1
    assert obs[0]["tenant_id"] == "tenant-multi-abc"
