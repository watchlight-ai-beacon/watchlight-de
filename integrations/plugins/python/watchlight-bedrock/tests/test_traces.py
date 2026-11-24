"""Tests for the Bedrock agentTrace → ExecutionEvent translator."""

from __future__ import annotations

import json
from typing import Any, Dict, List
from unittest.mock import AsyncMock, MagicMock

import pytest

from watchlight_bedrock import RunHandle
from watchlight_bedrock.traces import translate_bedrock_trace


# ─── Fixtures ──────────────────────────────────────────────────────────


def _wrap_trace(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Wrap a raw trace sub-payload (e.g. orchestrationTrace) in the
    shape Bedrock emits: response["completion"][N]["trace"]["trace"]"""
    return {
        "completion": [
            {"trace": {"trace": payload}},
        ],
    }


def _orch_action_group(
    *,
    action_group: str = "PaymentTools",
    api_path: str = "/transfer",
    verb: str = "POST",
) -> Dict[str, Any]:
    return {
        "orchestrationTrace": {
            "invocationInput": {
                "actionGroupInvocationInput": {
                    "actionGroupName": action_group,
                    "apiPath": api_path,
                    "verb": verb,
                }
            }
        }
    }


def _orch_kb_lookup(
    *, kb_id: str = "kb-finance-docs", query: str = "Q3 net revenue"
) -> Dict[str, Any]:
    return {
        "orchestrationTrace": {
            "invocationInput": {
                "knowledgeBaseLookupInput": {
                    "knowledgeBaseId": kb_id,
                    "text": query,
                }
            }
        }
    }


def _orch_collaborator(*, name: str = "research-analyst") -> Dict[str, Any]:
    return {
        "orchestrationTrace": {
            "invocationInput": {
                "agentCollaboratorInvocationInput": {
                    "agentCollaboratorName": name,
                    "agentCollaboratorAliasArn": f"arn:aws:bedrock:us-east-1:000000000000:agent/{name}",
                }
            }
        }
    }


def _failure(reason: str = "ModelInvocationTimeout") -> Dict[str, Any]:
    return {
        "failureTrace": {
            "failureReason": reason,
            "failureCode": "TIMEOUT",
        }
    }


# ─── Empty / no-trace cases ────────────────────────────────────────────


def test_empty_response_yields_no_events():
    """A response with no completion/trace fields produces nothing.

    This is the steady-state for `enableTrace=False` calls — the
    translator must not invent events when the caller didn't ask
    for tracing. CISOs care: "do we silently fabricate audit data
    when the source said nothing?" — the answer is no.
    """
    events = translate_bedrock_trace(
        response={},
        execution_id="exec_test",
        agent_id="agent-1",
    )
    assert events == []


def test_completion_with_empty_chunks_yields_no_events():
    response = {"completion": [{"chunk": {"bytes": b"hello"}}]}
    events = translate_bedrock_trace(
        response=response,
        execution_id="exec_test",
        agent_id="agent-1",
    )
    assert events == []


def test_unrecognized_trace_subtype_yields_no_events():
    """Pre/post-processing + guardrail traces are not in the v1
    emission set. The translator must skip them silently rather
    than crashing on the unknown shape."""
    response = _wrap_trace(
        {"preProcessingTrace": {"modelInvocationInput": {"text": "hi"}}}
    )
    events = translate_bedrock_trace(
        response=response,
        execution_id="exec_test",
        agent_id="agent-1",
    )
    assert events == []


# ─── ToolCallObserved from actionGroupInvocation ──────────────────────


def test_action_group_invocation_emits_plan_then_tool_call():
    """Each action-group invocation produces two canonical events —
    a plan_observed (the agent decided to act) followed by a
    tool_call_observed (the wire trace of the act). The plan-vs-act
    correlator consumes both."""
    response = _wrap_trace(_orch_action_group(action_group="bank", api_path="/transfer"))
    events = translate_bedrock_trace(
        response=response,
        execution_id="exec_X",
        agent_id="agent-1",
        session_id="sess_42",
        tenant_id="acme",
    )
    assert len(events) == 2

    plan_ev, tool_ev = events
    assert plan_ev["event_type"] == "plan_observed"
    assert plan_ev["payload"]["plan_kind"] == "incremental"
    # action_group only (no `function` field on this fixture) — the
    # plan-name builder uses ``action_group.function`` when both are
    # present so multiple functions under one action group remain
    # distinguishable in plan-vs-act comparisons.
    assert plan_ev["payload"]["intended_tools"] == ["bank"]
    assert plan_ev["metadata"]["source"] == "bedrock.agentTrace"

    assert tool_ev["event_type"] == "tool_call_observed"
    assert tool_ev["agent_id"] == "agent-1"
    assert tool_ev["execution_id"] == "exec_X"
    assert tool_ev["session_id"] == "sess_42"
    assert tool_ev["tenant_id"] == "acme"
    # Resource ref carries the action-group identity so downstream
    # consumers can correlate by tool name without re-parsing.
    assert tool_ev["payload"]["tool"] == {
        "resource_type": "tool",
        "identifier": "bank/transfer",
        "endpoint": "bedrock://tool/bank/transfer",
    }
    assert tool_ev["payload"]["action"]["action"] == "post"
    # Source metadata is mandatory — every event must trace back to
    # the framework that emitted it (provenance).
    assert tool_ev["metadata"]["source"] == "bedrock.agentTrace"
    assert tool_ev["metadata"]["action_group"] == "bank"


def test_event_id_is_unique_per_event():
    """Same payload run twice produces distinct event_ids — a
    smoke check that the translator isn't accidentally caching
    or reusing IDs across calls.
    """
    response = _wrap_trace(_orch_action_group())
    events_a = translate_bedrock_trace(
        response=response, execution_id="exec", agent_id="agent-1"
    )
    events_b = translate_bedrock_trace(
        response=response, execution_id="exec", agent_id="agent-1"
    )
    # Each action-group chunk emits plan_observed +
    # tool_call_observed; pick the tool_call_observed for the
    # event_id uniqueness check.
    tool_a = next(e for e in events_a if e["event_type"] == "tool_call_observed")
    tool_b = next(e for e in events_b if e["event_type"] == "tool_call_observed")
    assert tool_a["event_id"] != tool_b["event_id"]
    assert tool_a["event_id"].startswith("evt_")


# ─── ToolCallObserved from knowledgeBaseLookup ─────────────────────────


def test_kb_lookup_emits_plan_then_tool_call_with_query_summary():
    """KB lookups produce a plan_observed + tool_call_observed
    pair, mirroring the action-group invocation shape."""
    response = _wrap_trace(
        _orch_kb_lookup(kb_id="kb-1", query="Show me Q3 revenue figures")
    )
    events = translate_bedrock_trace(
        response=response, execution_id="exec", agent_id="agent-1"
    )
    assert len(events) == 2

    plan_ev, tool_ev = events
    assert plan_ev["event_type"] == "plan_observed"
    # KB plan name is canonicalized as `kb.<knowledgeBaseId>` so the
    # correlator can distinguish KB reads from action-group calls.
    assert plan_ev["payload"]["intended_tools"] == ["kb.kb-1"]

    assert tool_ev["event_type"] == "tool_call_observed"
    assert tool_ev["payload"]["tool"] == {
        "resource_type": "tool",
        "identifier": "kb-1",
        "endpoint": "bedrock://knowledge-base/kb-1",
    }
    assert tool_ev["payload"]["action"]["action"] == "query"
    # Value-free: the query's type, never its text.
    assert tool_ev["payload"]["input_summary"] == "1 args: text(str)"
    assert "Q3 revenue" not in repr(tool_ev)
    assert tool_ev["metadata"]["knowledge_base_id"] == "kb-1"


def test_kb_lookup_summary_is_value_free_and_bounded():
    long_query = "x" * 500
    response = _wrap_trace(_orch_kb_lookup(query=long_query))
    events = translate_bedrock_trace(
        response=response, execution_id="exec", agent_id="agent-1"
    )
    # 120-char cap per the translator. Prevents an attacker-
    # controlled query from blowing up per-event size. The
    # tool_call_observed event is the second of the two emitted per
    # KB-lookup chunk; pick it explicitly so the test is robust to
    # ordering refactors.
    tool_ev = next(e for e in events if e["event_type"] == "tool_call_observed")
    assert len(tool_ev["payload"]["input_summary"]) <= 120
    assert "xxxx" not in repr(tool_ev)


# ─── AgentSpawnObserved from agentCollaboratorInvocation ──────────────


def test_collaborator_invocation_is_dropped_server_attested():
    """Spawn attestation is SERVER-emitted only. wl-apdp's
    ``spawn_handler`` mints the authoritative ``agent_spawn_observed``
    for spawns routed through ``spawn_subagent``; a plugin-emitted one is
    REJECTED at ``/v1/events`` ingest. Bedrock collaborator invocations
    are native multi-agent (not routed through ``spawn_subagent``), so the
    translator DROPS them rather than emitting a rejected event."""
    response = _wrap_trace(_orch_collaborator(name="research-analyst"))
    events = translate_bedrock_trace(
        response=response, execution_id="exec", agent_id="agent-1"
    )
    assert events == []
    assert all(e["event_type"] != "agent_spawn_observed" for e in events)


# ─── ExecutionFailed from failureTrace ─────────────────────────────────


def test_failure_trace_emits_execution_failed():
    response = _wrap_trace(_failure(reason="ModelInvocationTimeout"))
    events = translate_bedrock_trace(
        response=response, execution_id="exec", agent_id="agent-1"
    )
    assert len(events) == 1
    ev = events[0]
    assert ev["event_type"] == "execution_failed"
    # Value-free: the failure code only, never Bedrock's free-text reason.
    assert ev["payload"]["error"] == "bedrock_failure:TIMEOUT"
    assert "ModelInvocationTimeout" not in repr(ev)
    assert ev["payload"]["error_type"] == "TIMEOUT"


def test_failure_trace_truncates_very_long_error_messages():
    """Bounded per-event size — attacker-controlled (or framework-
    bug-controlled) failure messages cannot blow up audit log
    rows. 512-char cap per the translator."""
    huge_reason = "x" * 2000
    response = _wrap_trace(_failure(reason=huge_reason))
    events = translate_bedrock_trace(
        response=response, execution_id="exec", agent_id="agent-1"
    )
    assert len(events[0]["payload"]["error"]) <= 512
    assert huge_reason[:40] not in repr(events[0])


# ─── Ordering + multi-trace ────────────────────────────────────────────


def test_multi_trace_response_preserves_order():
    """A real Bedrock response can carry multiple trace chunks in
    one streaming response. Order matters: SOC analysts and drift
    detectors rely on the sequence to reconstruct the agent's
    flow. The translator MUST emit events in trace-order.

    Action-group and KB chunks emit plan_observed followed by
    tool_call_observed, so the action-group chunk contributes 2
    events and the KB chunk contributes 2."""
    response = {
        "completion": [
            {"trace": {"trace": _orch_action_group(action_group="A")}},
            {"chunk": {"bytes": b"intermediate text"}},  # non-trace chunk skipped
            {"trace": {"trace": _orch_kb_lookup(kb_id="kb-2")}},
            # collaborator spawn is dropped (server-attested only),
            # so it contributes NO event to the ordered stream.
            {"trace": {"trace": _orch_collaborator(name="helper")}},
            {"trace": {"trace": _failure(reason="ExternalApiError")}},
        ],
    }
    events = translate_bedrock_trace(
        response=response, execution_id="exec", agent_id="agent-1"
    )
    # action_group plan + tool (2) + KB plan + tool (2) + collaborator
    # DROPPED (0) + failure (1) = 5 events total.
    assert len(events) == 5
    types = [e["event_type"] for e in events]
    assert types == [
        "plan_observed",         # action_group A plan
        "tool_call_observed",    # action_group A act
        "plan_observed",         # KB-2 plan
        "tool_call_observed",    # KB-2 act
        "execution_failed",      # failure (collaborator spawn dropped)
    ]
    assert events[1]["metadata"]["action_group"] == "A"
    assert events[3]["metadata"]["knowledge_base_id"] == "kb-2"


# ─── Robustness against shape drift ───────────────────────────────────


def test_malformed_chunk_does_not_break_subsequent_chunks():
    """A single malformed chunk must not poison the rest of the
    translation. The translator skips broken chunks with a debug
    log and continues. Coverage decisions must not be all-or-
    nothing — partial coverage with a logged gap is better than
    no coverage on a recoverable shape mismatch.

    Action-group chunks emit two events (plan + tool), so a first +
    third valid chunk produces 3 total events with the malformed
    middle skipped."""
    response = {
        "completion": [
            {"trace": {"trace": _orch_action_group()}},
            {"trace": {"trace": "this-is-not-a-dict"}},  # malformed
            {"trace": {"trace": _failure()}},
        ],
    }
    events = translate_bedrock_trace(
        response=response, execution_id="exec", agent_id="agent-1"
    )
    # First chunk → plan_observed + tool_call_observed (2),
    # second chunk → silently skipped,
    # third chunk → execution_failed (1). Total: 3.
    assert len(events) == 3
    types = [e["event_type"] for e in events]
    assert types == ["plan_observed", "tool_call_observed", "execution_failed"]


def test_serializable_to_json():
    """Every produced event must be JSON-serializable — that's the
    wire contract with wl-apdp's /v1/events endpoint. Smoke
    test against the canonical encoder."""
    response = {
        "completion": [
            {"trace": {"trace": _orch_action_group()}},
            {"trace": {"trace": _orch_kb_lookup()}},
            {"trace": {"trace": _orch_collaborator()}},
            {"trace": {"trace": _failure()}},
        ],
    }
    events = translate_bedrock_trace(
        response=response, execution_id="exec", agent_id="agent-1"
    )
    # Round-trip through JSON; if any field is non-serializable
    # this will raise.
    for ev in events:
        round_trip = json.loads(json.dumps(ev))
        assert round_trip == ev


# ─── RunHandle.publish_trace integration ──────────────────────────────


# In-process stand-in for unit tests only.
class _StubApdp:
    """Mock ApdpClient capturing publish_events calls."""

    def __init__(self, succeed: bool = True):
        self.publish_events = AsyncMock(return_value=succeed)
        self.captured_events: List[Dict[str, Any]] = []

        async def _capture(run, events):
            self.captured_events.extend(events)
            self.last_run = run
            return succeed

        self.publish_events.side_effect = _capture


def _build_run_handle(*, succeed_publish: bool = True) -> RunHandle:
    """Bypass the production constructor by populating fields
    directly. The plugin's only role in publish_trace is to expose
    `.apdp` and `.tenant_id`; both are set explicitly here.
    """
    stub_plugin = MagicMock()
    stub_plugin.apdp = _StubApdp(succeed=succeed_publish)
    stub_plugin.tenant_id = "acme"

    handle = RunHandle.__new__(RunHandle)
    handle._plugin = stub_plugin
    handle.agent_uuid = "agent-1"
    handle.session_id = "sess_42"
    # Execution-lineage integrity — the run's SERVER-minted
    # execution_id + its own `sst_` credential, threaded onto every
    # `/v1/events` emit so wl-apdp's identity-binding gate accepts them.
    handle.execution_id = "exec_server_root"
    handle.run = "run_cred"
    handle._completed = False
    return handle


@pytest.mark.asyncio
async def test_publish_trace_emits_translated_events():
    """An action-group chunk produces two events
    (plan_observed + tool_call_observed); both flow through
    publish_trace to APDP."""
    handle = _build_run_handle()
    response = _wrap_trace(_orch_action_group(action_group="bank"))

    count = await handle.publish_trace(response)
    assert count == 2

    captured = handle._plugin.apdp.captured_events
    assert len(captured) == 2
    plan_ev, tool_ev = captured
    assert plan_ev["event_type"] == "plan_observed"
    assert tool_ev["event_type"] == "tool_call_observed"
    assert tool_ev["agent_id"] == "agent-1"
    assert tool_ev["session_id"] == "sess_42"
    # tenant_id was picked up from the plugin — pinned because
    # multi-tenant routing downstream depends on it being right.
    assert tool_ev["tenant_id"] == "acme"


@pytest.mark.asyncio
async def test_publish_trace_returns_zero_when_no_traces():
    handle = _build_run_handle()
    count = await handle.publish_trace({"completion": []})
    assert count == 0
    # And the APDP client was NOT called — no events means no
    # network round-trip. Important: we don't want to spam APDP
    # with empty-list POSTs.
    handle._plugin.apdp.publish_events.assert_not_called()


@pytest.mark.asyncio
async def test_publish_trace_uses_explicit_execution_id_when_provided():
    handle = _build_run_handle()
    response = _wrap_trace(_orch_action_group())
    await handle.publish_trace(response, execution_id="exec_explicit")
    captured = handle._plugin.apdp.captured_events
    assert captured[0]["execution_id"] == "exec_explicit"


@pytest.mark.asyncio
async def test_publish_trace_defaults_to_server_execution_id_when_omitted():
    """When no explicit execution_id is passed, publish_trace defaults
    to the run's SERVER-minted execution_id (NOT a self-minted
    exec_<uuid>) so the emit passes wl-apdp's identity-binding gate, and
    authenticates the batch with the run's own `sst_` credential."""
    handle = _build_run_handle()
    response = _wrap_trace(_orch_action_group())
    await handle.publish_trace(response)
    captured = handle._plugin.apdp.captured_events
    assert captured[0]["execution_id"] == "exec_server_root"
    # The emit named the run (the backend authenticates with its credential).
    assert handle._plugin.apdp.last_run == "run_cred"


@pytest.mark.asyncio
async def test_publish_trace_returns_zero_on_publish_failure():
    """Best-effort lineage: a publish failure returns 0 rather
    than raising. The caller's success path must not depend on
    the audit pipeline's health (governance mechanism failures
    degrade gracefully)."""
    handle = _build_run_handle(succeed_publish=False)
    response = _wrap_trace(_orch_action_group())
    count = await handle.publish_trace(response)
    assert count == 0


@pytest.mark.asyncio
async def test_publish_trace_never_raises_on_apdp_exception():
    """If the APDP client itself raises (network error, malformed
    response, etc.), publish_trace catches it and returns 0. This
    is best-effort lineage — failures cannot propagate to the
    caller's request path."""
    handle = _build_run_handle()
    handle._plugin.apdp.publish_events.side_effect = RuntimeError("transport down")
    response = _wrap_trace(_orch_action_group())
    count = await handle.publish_trace(response)
    assert count == 0


@pytest.mark.asyncio
async def test_publish_trace_propagates_parent_execution_id():
    """Nested-run support: when an agent spawns a sub-agent, the
    sub-agent's events carry the parent's execution_id for the
    delegation-tree edges that drive the dashboard's execution
    timeline view."""
    handle = _build_run_handle()
    response = _wrap_trace(_orch_action_group())
    await handle.publish_trace(
        response,
        execution_id="exec_child",
        parent_execution_id="exec_parent",
    )
    captured = handle._plugin.apdp.captured_events
    assert captured[0]["execution_id"] == "exec_child"
    assert captured[0]["parent_execution_id"] == "exec_parent"


# ─── OTLP integration ─────────────────────────────────────────────────


class _RecordingOtlp:
    """Stand-in for `WatchlightOtlpExporter` — records the batches
    it would have exported. Same shape as the langgraph + adk
    integration tests for cross-plugin parity."""

    def __init__(self):
        self.batches: List[List[Dict[str, Any]]] = []

    def export_events(self, events):
        self.batches.append(list(events))
        return len(events)


def _build_run_handle_with_otlp(otlp_exporter, *, succeed_publish: bool = True) -> RunHandle:
    stub_plugin = MagicMock()
    stub_plugin.apdp = _StubApdp(succeed=succeed_publish)
    stub_plugin.tenant_id = "acme"
    stub_plugin.otlp = otlp_exporter

    handle = RunHandle.__new__(RunHandle)
    handle._plugin = stub_plugin
    handle.agent_uuid = "agent-1"
    handle.session_id = "sess_42"
    handle.execution_id = "exec_server_root"
    handle.run = "run_cred"
    handle._completed = False
    return handle


@pytest.mark.asyncio
async def test_publish_trace_routes_to_otlp_after_apdp_publish():
    """When the plugin has an `otlp` exporter wired,
    `publish_trace()` routes the same translated events through
    OTLP after the APDP publish succeeds."""
    otlp = _RecordingOtlp()
    handle = _build_run_handle_with_otlp(otlp)
    response = _wrap_trace(_orch_action_group())
    count = await handle.publish_trace(response)
    assert count >= 1

    # APDP got the events; OTLP got the same batch
    apdp_events = handle._plugin.apdp.captured_events
    assert len(otlp.batches) == 1
    assert otlp.batches[0] == apdp_events


@pytest.mark.asyncio
async def test_publish_trace_no_otlp_keeps_handle_otlp_free():
    """The default path (no `otlp` on the plugin) must not depend
    on the OTel SDK in any way. Without an exporter, the OTLP
    branch is short-circuited."""
    # No otlp attribute on the stub plugin → getattr returns None
    handle = _build_run_handle()
    response = _wrap_trace(_orch_action_group())
    count = await handle.publish_trace(response)
    assert count >= 1
    # No otlp side-effect: nothing to assert beyond it not crashing


@pytest.mark.asyncio
async def test_publish_trace_otlp_failure_does_not_affect_apdp_outcome():
    """OTLP is opt-in customer obs; its failure cannot regress the
    lineage-publish result. Same invariant the langgraph + adk
    tests enforce."""

    class _FailingOtlp:
        def export_events(self, events):
            raise RuntimeError("collector down")

    handle = _build_run_handle_with_otlp(_FailingOtlp())
    response = _wrap_trace(_orch_action_group())
    count = await handle.publish_trace(response)
    # Customer sees a successful publish count from APDP regardless
    # of OTLP outcome.
    assert count >= 1


@pytest.mark.asyncio
async def test_publish_trace_otlp_skipped_when_apdp_raises():
    """If the APDP publish raises (transport down / network error
    — strongest signal that events did NOT reach Watchlight),
    OTLP must NOT run. OTLP is a downstream tap on a successful
    lineage publish, not a parallel destination.

    Note the distinction from `succeed=False` — that's APDP
    returning False (soft fail), which still runs OTLP because
    the events might have partially landed. An exception means
    we never even completed the call.
    """
    otlp = _RecordingOtlp()
    handle = _build_run_handle_with_otlp(otlp)
    # Override the default AsyncMock to raise instead of returning
    handle._plugin.apdp.publish_events.side_effect = RuntimeError("transport down")
    response = _wrap_trace(_orch_action_group())
    count = await handle.publish_trace(response)
    assert count == 0
    assert otlp.batches == []
