"""Cross-plugin conformance suite.

This module is the **single source of truth** for the canonical
`ExecutionEvent` wire shape. Every framework plugin (LangGraph /
Bedrock / ADK / future MSAF) and every non-plugin emitter
(`wl-proxy` MCP decoding) MUST satisfy the invariants asserted
here.

The bilateral and three-way cross-emitter checks that previously
lived in each plugin's own test directory have been consolidated
here. The full contract is documented separately; this file
enforces it.

# Invariants under test

1. **Envelope shape** — every emitted event carries the
   canonical 6 required fields (`event_id`, `event_type`,
   `timestamp`, `execution_id`, `agent_id`, `payload`) and
   restricts optional fields to a closed set.
2. **Source attribution** — each emitter uses a distinct
   `metadata.source` tag. Forgery between emitters is post-hoc
   detectable by correlating against the service credential
   that authenticated the call.
3. **Canonical event types** — a tool call is a
   `tool_call_observed` regardless of source.
4. **Resource-URI scheme** — every emitter namespaces its
   resource URIs by source (`langgraph://tool/...`,
   `adk://tool/...`, `bedrock://...`, `mcp://...`).
5. **event_id format** — `evt_<uuid>` consistently. SIEM
   correlation rules grep for this; format drift silently
   breaks them.
6. **Bounded sizes** — input_summary capped at 120 chars,
   error messages at 512 chars. Cap mismatch between emitters
   means downstream consumers see inconsistent payload sizes.
7. **No unknown top-level keys** — the envelope is a closed
   set. Extensions go in `metadata`, not as new top-level keys.

# Skip-on-missing-plugin semantics

watchlight-core ships without the per-framework plugins
installed. CI's per-plugin matrix shard installs only ONE
plugin alongside watchlight-core, so the three-way assertions
that reach into sibling plugins must skip cleanly when those
siblings aren't present. We achieve this with
`pytest.importorskip` at module scope — if any plugin import
fails, this entire file is skipped. The implication is that
**this suite only runs when all three plugins are co-installed**,
typically in a workspace dev environment or the integration
CI shard.
"""

from __future__ import annotations

from typing import Any, Dict, List

import pytest

# All three Python plugins are required for the three-way harness.
# `importorskip` silently skips the entire module when one isn't
# present, so the per-plugin CI matrix shard still passes.
pytest.importorskip(
    "watchlight_adk",
    reason="conformance requires watchlight_adk installed",
)
pytest.importorskip(
    "watchlight_langgraph",
    reason="conformance requires watchlight_langgraph installed",
)
pytest.importorskip(
    "watchlight_bedrock",
    reason="conformance requires watchlight_bedrock installed",
)
pytest.importorskip(
    "watchlight_msaf",
    reason="conformance requires watchlight_msaf installed",
)

from watchlight_adk.traces import translate_adk_events  # noqa: E402
from watchlight_bedrock.traces import translate_bedrock_trace  # noqa: E402
from watchlight_langgraph.traces import translate_langgraph_events  # noqa: E402
from watchlight_msaf.traces import translate_msaf_events  # noqa: E402


# ─── Canonical schema (the contract) ─────────────────────────────────


def _required_envelope_fields() -> set[str]:
    """Fields every canonical ExecutionEvent MUST carry. This is the
    minimum closed set."""
    return {
        "event_id",
        "event_type",
        "timestamp",
        "execution_id",
        "agent_id",
        "payload",
    }


def _optional_envelope_fields() -> set[str]:
    """Optional envelope fields. Emitters bind them when the
    information is available; absence is acceptable."""
    return {
        "session_id",
        "tenant_id",
        "parent_execution_id",
        "root_execution_id",
        "parent_agent_id",
        "request_id",
        "metadata",
    }


def _expected_source_tags() -> Dict[str, str]:
    """The source-tag registry. Each emitter has exactly one
    stable tag; further emitters require extending both this map
    and the canonical schema doc."""
    return {
        "adk": "adk.callback",
        "langgraph": "langgraph.callback",
        "bedrock": "bedrock.agentTrace",
        "msaf": "msaf.callback",
        "wl-proxy.mcp": "wl-proxy.mcp",
    }


# ─── Synthetic input fixtures per emitter ────────────────────────────


def _adk_tool_captures() -> List[Dict[str, Any]]:
    """``before_tool_callback`` now produces a
    ``plan_observed`` event; ``after_tool_callback`` produces the
    ``tool_call_observed``. The full lifecycle yields both — the
    conformance suite asserts on both."""
    return [
        {
            "hook": "before_tool_callback",
            "tool_name": "web_search",
            "action_verb": "query",
            "tool_args": {"q": "Q3 revenue"},
        },
        {
            "hook": "after_tool_callback",
            "tool_name": "web_search",
            "action_verb": "query",
            "decision": "Allow",
            "duration_ms": 42,
        },
    ]


def _langgraph_tool_events() -> List[Dict[str, Any]]:
    """A realistic LangGraph trace pairs an
    ``on_agent_action`` (plan signal → ``plan_observed``) with the
    ``on_tool_start`` (act signal → ``tool_call_observed``). The
    conformance suite asserts on both."""
    return [
        {
            "hook": "on_agent_action",
            "tool": "web_search",
            "tool_input": "Q3 revenue",
            "run_id": "run_x",
            "parent_run_id": "root",
        },
        {
            "hook": "on_tool_start",
            "serialized": {"name": "web_search"},
            "name": "web_search",
            "input_str": "Q3 revenue",
            "run_id": "run_x",
            "parent_run_id": "root",
        },
    ]


def _bedrock_tool_response() -> Dict[str, Any]:
    return {
        "completion": [
            {
                "trace": {
                    "trace": {
                        "orchestrationTrace": {
                            "invocationInput": {
                                "actionGroupInvocationInput": {
                                    "actionGroupName": "search",
                                    "apiPath": "/query",
                                    "verb": "POST",
                                }
                            }
                        }
                    }
                }
            }
        ]
    }


def _wl_proxy_mcp_event() -> Dict[str, Any]:
    """**Hand-written canonical wl-proxy MCP-emitted event.**

    wl-proxy's Rust MCP translator
    produces this exact JSON shape when it decodes an MCP
    `tools/call` request body. We inline it here so the Python
    conformance harness can assert the cross-language wire
    contract holds — the Rust emitter must serialize to bytes
    that match this fixture's shape (the Rust-side test
    `on_wire_envelope_matches_framework_plugin_schema` pins
    the other side).

    This is the **fourth emitter** in the harness alongside
    the three Python plugins.
    """
    return {
        "event_id": "evt_00000000-0000-0000-0000-000000000001",
        "event_type": "tool_call_observed",
        "timestamp": "2026-05-13T18:30:00Z",
        "execution_id": "exec_proxy_1",
        "agent_id": "research-agent",
        "session_id": "sess_42",
        "tenant_id": "acme",
        "metadata": {
            "source": "wl-proxy.mcp",
            "mcp.tool": "fs.read_file",
            "mcp.arg_count": 2,
        },
        "payload": {
            "tool": {
                "resource_type": "tool",
                "identifier": "fs.read_file",
                "endpoint": "mcp://fs-mcp.local/fs.read_file",
            },
            "action": {"action": "invoke"},
            "decision": "Allow",
            "input_summary": "encoding,path",
        },
    }


# ─── Per-emitter event materialization ───────────────────────────────


def _adk_events(**envelope_extras: Any) -> List[Dict[str, Any]]:
    return translate_adk_events(
        captures=_adk_tool_captures(),
        execution_id="exec",
        agent_id="agent-1",
        **envelope_extras,
    )


def _langgraph_events(**envelope_extras: Any) -> List[Dict[str, Any]]:
    return translate_langgraph_events(
        events=_langgraph_tool_events(),
        execution_id="exec",
        agent_id="agent-1",
        **envelope_extras,
    )


def _bedrock_events(**envelope_extras: Any) -> List[Dict[str, Any]]:
    return translate_bedrock_trace(
        response=_bedrock_tool_response(),
        execution_id="exec",
        agent_id="agent-1",
        **envelope_extras,
    )


def _msaf_tool_captures() -> List[Dict[str, Any]]:
    """MAF's per-tool middleware fires twice — once
    pre-invocation (producing PlanObserved) and once post
    (producing ToolCallObserved). Conformance asserts on both
    shapes, same as ADK."""
    return [
        {
            "hook": "tool_invocation_start",
            "tool_name": "web_search",
            "tool_args": {"q": "Q3 revenue"},
        },
        {
            "hook": "tool_invocation_complete",
            "tool_name": "web_search",
            "action_verb": "query",
            "decision": "Allow",
            "duration_ms": 42,
            "tool_args": {"q": "Q3 revenue"},
        },
    ]


def _msaf_events(**envelope_extras: Any) -> List[Dict[str, Any]]:
    return translate_msaf_events(
        captures=_msaf_tool_captures(),
        execution_id="exec",
        agent_id="agent-1",
        **envelope_extras,
    )


def _all_emitter_events() -> Dict[str, List[Dict[str, Any]]]:
    """Materialize one event per emitter. The wl-proxy MCP event is
    a fixture (not generated from Python); the four plugins' events
    come from their actual translators."""
    return {
        "adk": _adk_events(),
        "langgraph": _langgraph_events(),
        "bedrock": _bedrock_events(),
        "msaf": _msaf_events(),
        "wl-proxy.mcp": [_wl_proxy_mcp_event()],
    }


# ─── Invariant tests ─────────────────────────────────────────────────


def test_all_emitters_carry_required_envelope_fields():
    """Foundation invariant: every event from every emitter has
    the canonical 6 envelope fields. Any future plugin author
    who forgets one fails this test."""
    required = _required_envelope_fields()
    for emitter, events in _all_emitter_events().items():
        assert events, f"{emitter} produced no events"
        for ev in events:
            missing = required - ev.keys()
            assert not missing, (
                f"{emitter} event missing required fields {missing}: {ev}"
            )


def test_all_emitters_emit_distinct_provenance_source_tags():
    """Every emitter tags events with a unique
    `metadata.source` value. Forgery — one emitter claiming to
    be another — is post-hoc detectable by cross-checking the
    source tag against the authenticating service credential."""
    expected = _expected_source_tags()
    seen: Dict[str, str] = {}
    for emitter, events in _all_emitter_events().items():
        # First event of each emitter (they all share the
        # source tag within an emitter).
        source = events[0]["metadata"]["source"]
        seen[emitter] = source

    # Tags match the registry exactly
    assert seen == expected

    # All tags are distinct (no overlap)
    assert len(set(seen.values())) == len(seen)


def test_all_emitters_use_canonical_event_type_for_tool_call():
    """A tool call is a `tool_call_observed` regardless of
    source. Future drift here (an emitter shipping its own
    framework-specific event_type variant) would silently break
    downstream consumers that filter on event_type."""
    for emitter, events in _all_emitter_events().items():
        tool_events = [e for e in events if e["event_type"] == "tool_call_observed"]
        assert tool_events, (
            f"{emitter} produced no tool_call_observed events from the "
            f"synthetic tool-call input"
        )


def test_all_emitters_produce_namespaced_resource_uris():
    """Resource URIs are namespaced by source so downstream graph
    queries can filter on framework. Without the scheme prefix, an
    operator looking at the graph DB can't tell a langgraph tool
    call from an adk tool call.

    The location of the URI differs slightly by emitter — Python
    plugins use `payload.tool.resource` (a string); wl-proxy MCP
    uses `payload.tool.endpoint` (the `ResourceRef` shape from
    `wl-lineage`). The invariant is the prefix, not the path."""
    expected_prefixes = {
        "adk": "adk://",
        "langgraph": "langgraph://",
        "bedrock": "bedrock://",
        "msaf": "msaf://",
        "wl-proxy.mcp": "mcp://",
    }
    for emitter, events in _all_emitter_events().items():
        tool_ev = next(
            (e for e in events if e["event_type"] == "tool_call_observed"),
            None,
        )
        assert tool_ev is not None, f"{emitter} has no tool_call_observed event"

        tool_payload = tool_ev["payload"]["tool"]
        # The URI lives at `payload.tool.resource` (Python plugins'
        # ResourceRef shape) OR `payload.tool.endpoint` (wl-proxy
        # MCP via the wl-lineage Rust ResourceRef). Either is OK
        # as long as the URI itself uses the expected prefix.
        uri = tool_payload.get("resource") or tool_payload.get("endpoint")
        assert isinstance(uri, str), (
            f"{emitter} tool URI is not a string: {tool_payload!r}"
        )
        assert uri.startswith(expected_prefixes[emitter]), (
            f"{emitter} URI {uri!r} missing prefix {expected_prefixes[emitter]!r}"
        )


def test_all_emitters_use_evt_uuid_format_for_event_id():
    """Every event_id starts with `evt_`. SIEM correlation
    rules grep for this prefix; format drift silently falls
    out of those rules."""
    for emitter, events in _all_emitter_events().items():
        for ev in events:
            assert ev["event_id"].startswith("evt_"), (
                f"{emitter} event_id format drift: {ev['event_id']!r}"
            )


def test_envelope_is_a_closed_set_no_unknown_top_level_keys():
    """The envelope vocabulary is closed. Extensions go into
    `metadata`, not as new top-level keys. Schema drift here
    would force every downstream consumer to learn the new key."""
    allowed = _required_envelope_fields() | _optional_envelope_fields()

    extras = {
        "session_id": "sess",
        "tenant_id": "tenant",
        "parent_execution_id": "parent",
        "root_execution_id": "root",
    }
    runs = {
        "adk": _adk_events(**extras),
        "langgraph": _langgraph_events(
            session_id="sess",
            tenant_id="tenant",
            parent_execution_id="parent",
        ),
        "bedrock": _bedrock_events(
            session_id="sess",
            tenant_id="tenant",
            parent_execution_id="parent",
        ),
        "wl-proxy.mcp": [_wl_proxy_mcp_event()],
    }

    for emitter, events in runs.items():
        for ev in events:
            unknown = ev.keys() - allowed
            assert not unknown, (
                f"{emitter} emitted unknown top-level keys: {unknown} in {ev}"
            )


def test_all_emitters_share_input_summary_truncation_limit():
    """All emitters cap argument summaries at 120 chars and carry no
    argument value (a truncated value can still hold a credential).

    The summary lives at different keys per event type:
    ``tool_call_observed`` uses ``input_summary``;
    ``plan_observed`` uses ``rationale``.
    """
    long = "x" * 500

    # ADK before_tool_callback → plan_observed with bounded rationale.
    adk_events = translate_adk_events(
        captures=[
            {
                "hook": "before_tool_callback",
                "tool_name": "calc",
                "action_verb": "compute",
                "tool_args": long,
            }
        ],
        execution_id="exec",
        agent_id="agent-1",
    )
    adk_plan = next(e for e in adk_events if e["event_type"] == "plan_observed")
    assert len(adk_plan["payload"]["rationale"]) <= 120
    assert "xxxx" not in adk_plan["payload"]["rationale"]

    # LangGraph on_tool_start → tool_call_observed with input_summary.
    lang_events = translate_langgraph_events(
        events=[
            {
                "hook": "on_tool_start",
                "serialized": {"name": "calc"},
                "name": "calc",
                "input_str": long,
                "run_id": "r1",
                "parent_run_id": "root",
            }
        ],
        execution_id="exec",
        agent_id="agent-1",
    )
    lang_tool = next(e for e in lang_events if e["event_type"] == "tool_call_observed")
    assert len(lang_tool["payload"]["input_summary"]) <= 120
    assert "xxxx" not in lang_tool["payload"]["input_summary"]

    # Bedrock KB lookup → plan_observed + tool_call_observed pair;
    # the tool_call_observed carries the input_summary on the wire
    # (the plan_observed carries no rationale here because Bedrock's
    # orchestration trace doesn't expose the rationale field on this
    # synthetic fixture).
    bedrock_events = translate_bedrock_trace(
        response={
            "completion": [
                {
                    "trace": {
                        "trace": {
                            "orchestrationTrace": {
                                "invocationInput": {
                                    "knowledgeBaseLookupInput": {
                                        "knowledgeBaseId": "kb-1",
                                        "text": long,
                                    }
                                }
                            }
                        }
                    }
                }
            ]
        },
        execution_id="exec",
        agent_id="agent-1",
    )
    bedrock_tool = next(
        e for e in bedrock_events if e["event_type"] == "tool_call_observed"
    )
    assert len(bedrock_tool["payload"]["input_summary"]) <= 120
    assert "xxxx" not in bedrock_tool["payload"]["input_summary"]


# ─── plan_observed conformance ────────────────────────────────────────


def test_all_framework_plugins_emit_plan_observed_with_canonical_shape():
    """Every framework plugin (LangGraph, ADK, Bedrock)
    emits a ``plan_observed`` event for plan-stage signals with the
    canonical payload shape:

    - ``intended_tools``: non-empty ``list[str]``, each name matching
      ``PLAN_TOOL_NAME_PATTERN``
    - ``plan_kind``: one of ``upfront`` / ``incremental`` / ``inferred``
    - ``rationale``: optional, ≤1024 bytes when present

    Drift here (a plugin emitting a different field name or a
    free-form plan shape) silently breaks the wl-execution-graph
    plan-vs-act correlator. wl-proxy MCP is intentionally
    excluded — direct MCP traffic has no plan signal (``inferred``
    is reserved for that case in the wl-execution-graph
    correlator's mismatch logic).
    """
    from watchlight_core import (
        PLAN_TOOL_NAME_RE,
        PlanKind,
    )

    plugin_emitters = {
        "adk": _adk_events,
        "langgraph": _langgraph_events,
        "bedrock": _bedrock_events,
        "msaf": _msaf_events,
    }
    for emitter, events_fn in plugin_emitters.items():
        events = events_fn()
        plan_events = [e for e in events if e["event_type"] == "plan_observed"]
        assert plan_events, (
            f"{emitter} produced no plan_observed events from the synthetic "
            f"plan-stage input — wl-execution-graph correlator will not see "
            f"plans from this framework"
        )
        plan_ev = plan_events[0]

        payload = plan_ev["payload"]
        intended = payload.get("intended_tools")
        assert isinstance(intended, list) and intended, (
            f"{emitter} plan_observed.intended_tools is not a non-empty list: {intended!r}"
        )
        for name in intended:
            assert isinstance(name, str) and PLAN_TOOL_NAME_RE.match(name), (
                f"{emitter} plan_observed tool name {name!r} fails canonical regex"
            )

        plan_kind = payload.get("plan_kind")
        assert plan_kind in PlanKind.ALL, (
            f"{emitter} plan_observed.plan_kind {plan_kind!r} not in {PlanKind.ALL}"
        )

        rationale = payload.get("rationale")
        if rationale is not None:
            assert isinstance(rationale, str)
            assert len(rationale.encode("utf-8")) <= 1024, (
                f"{emitter} plan_observed.rationale exceeds 1024-byte cap"
            )

        # Provenance + tool_name in metadata mirror the
        # tool_call_observed contract — same fields, same locations.
        assert plan_ev["metadata"]["source"], f"{emitter} plan event missing source"


# ─── wl-proxy MCP cross-language parity ──────────────────────────────


def test_wl_proxy_mcp_event_satisfies_canonical_envelope():
    """Pin the cross-language contract: the JSON wl-proxy MCP
    produces from Rust must satisfy every Python-plugin invariant.

    If the Rust translator's output drifts away from this fixture,
    this test fails — even though no Python code changed. The
    sibling Rust test
    wl-proxy's ``on_wire_envelope_matches_framework_plugin_schema`` test
    asserts the same envelope from the Rust side; the two tests
    are the two ends of the same wire contract."""
    ev = _wl_proxy_mcp_event()
    required = _required_envelope_fields()
    missing = required - ev.keys()
    assert not missing, f"wl-proxy MCP fixture missing required fields: {missing}"
    assert ev["event_type"] == "tool_call_observed"
    assert ev["event_id"].startswith("evt_")
    assert ev["metadata"]["source"] == "wl-proxy.mcp"
    assert ev["payload"]["tool"]["endpoint"].startswith("mcp://")
    assert ev["payload"]["action"]["action"] == "invoke"


# ─── invariant #13 vacuous-pass for non-spawning plugins ─────────────


def test_invariant_13_vacuous_for_non_spawning_translators():
    """Invariant #13 (scope_attenuation_propagation) requires
    every ``agent_spawn_observed`` event to carry a populated
    ``delegation_scope`` payload field. Plugins whose framework has no
    sub-agent primitive emit zero ``agent_spawn_observed`` events and
    pass invariant #13 vacuously.

    Locks the vacuous-pass contract for ADK, Bedrock, MSAF (the
    Python-side translators wired into the harness above). The
    LangGraph plugin has a ``spawn_subagent`` primitive and is
    exercised non-vacuously by its own ``test_conformance.py``;
    Pydantic AI does the same via its own ``test_conformance.py``.
    """
    from watchlight_core_testing.conformance import check_scope_attenuation_propagation

    for emitter, events in _all_emitter_events().items():
        spawn_events = [
            e for e in events if e.get("event_type") == "agent_spawn_observed"
        ]
        assert spawn_events == [], (
            f"{emitter} translator emitted agent_spawn_observed event(s); "
            f"invariant #13 needs a non-vacuous test in the plugin's own "
            f"suite. Got: {spawn_events}"
        )
        # The check function itself passes on a vacuous stream — locks the
        # contract from both sides.
        check_scope_attenuation_propagation(events)


# ─── invariant #14 (execution_started precedes non-lifecycle events) ─


def test_invariant_14_translator_streams_when_anchored_pass():
    """Invariant #14 requires every non-mint event to
    have a preceding ``execution_started`` event with the same
    ``execution_id``.

    The shipped translators (ADK / LangGraph / Bedrock / MSAF) are
    stateless — they translate raw framework events into canonical
    ones and do NOT mint an ``execution_started`` themselves; that's
    the SDK's job via :meth:`BaseRunHandle._emit_execution_started`.
    The translators' raw output on a tool-only fixture therefore IS
    the invariant #14 violation shape — invariant #14 catches it
    correctly. This test pins the contract: when each translator's
    output is prepended with a canonical ``execution_started``
    carrying the SAME ``execution_id``, invariant #14 passes.

    Mirrors the invariant #13 vacuous-pass test pattern above; locks
    the invariant from both directions (passes when anchored, fails
    when the SDK guard is bypassed).
    """
    from watchlight_core_testing.conformance import (
        check_execution_started_precedes_non_lifecycle_events,
    )
    from watchlight_core_testing import ConformanceFailure

    for emitter, events in _all_emitter_events().items():
        if not events:
            continue

        # Sanity check: every event in the stream uses the same
        # execution_id (the translators thread one id through the
        # whole batch). This is a load-bearing precondition for the
        # anchored test below.
        exec_ids = {ev.get("execution_id") for ev in events}
        assert len(exec_ids) == 1, (
            f"{emitter} translator emitted events with mixed execution_ids "
            f"{exec_ids}; invariant #14 anchoring would fail for the "
            f"un-shared ids."
        )
        exec_id = next(iter(exec_ids))

        # Without an anchor, the translator's raw output is the
        # invariant #14 violation shape — confirm the check rejects.
        # EXCEPTION: an event whose type is ITSELF a mint event
        # (e.g. an emitter that produces only an execution_started)
        # passes vacuously; skip the negative assertion when the
        # translator's stream is mint-only.
        non_mint = [
            ev for ev in events
            if ev.get("event_type") not in (
                "execution_started",
                "agent_spawn_observed",
                "ungoverned_request_observed",
            )
        ]
        if non_mint:
            with pytest.raises(ConformanceFailure):
                check_execution_started_precedes_non_lifecycle_events(events)

        # With an anchor prepended, invariant #14 passes — this is
        # the canonical pattern: SDK mints `execution_started` first,
        # then translator-emitted events follow on the same
        # execution_id.
        anchored = [
            {
                "event_id": "evt_00000000-0000-0000-0000-000000000999",
                "event_type": "execution_started",
                "timestamp": "2026-01-01T00:00:00Z",
                "execution_id": exec_id,
                "agent_id": "agent-1",
                "payload": {
                    "principal": {
                        "principal_type": "agent",
                        "id": "agent-1",
                    },
                    "depth": 0,
                },
                "metadata": {"source": f"{emitter}.session_start"},
            },
            *events,
        ]
        # Should not raise.
        check_execution_started_precedes_non_lifecycle_events(anchored)


def test_no_emitter_carries_forbidden_payload_keys():
    """Defense in depth against `_NEVER_EXPORT_PAYLOAD_KEYS`
    leakage. The OTLP redactor enforces this at the export
    boundary; the canonical event SHOULD already not carry
    these fields, but pinning it here means a future translator
    change that accidentally surfaces tool arguments fails
    this test even before OTLP gets involved.

    Spot-check the most sensitive ones."""
    forbidden_payload_keys = {
        "tool_args",
        "tool_input",
        "prompts",
        "messages",
        "blast_radius_score",
        "policies_evaluated",
        "lookup_hash",
    }
    forbidden_metadata_keys = {
        "blast_radius_score",
        "drift_score",
        "policies_evaluated",
    }
    for emitter, events in _all_emitter_events().items():
        for ev in events:
            payload_keys = set(ev.get("payload", {}).keys()) if isinstance(
                ev.get("payload"), dict
            ) else set()
            leaked_payload = forbidden_payload_keys & payload_keys
            assert not leaked_payload, (
                f"{emitter} payload leaked forbidden keys: {leaked_payload}"
            )

            metadata_keys = set(ev.get("metadata", {}).keys()) if isinstance(
                ev.get("metadata"), dict
            ) else set()
            leaked_metadata = forbidden_metadata_keys & metadata_keys
            assert not leaked_metadata, (
                f"{emitter} metadata leaked forbidden keys: {leaked_metadata}"
            )


# ─── Invariant 16 — payload schema conformance ───────────────────────
#
# The regression lock for the defect where a plugin's
# ``execution_started`` carried a non-canonical ``principal`` and wl-apdp
# answered:
#
#   422 Failed to deserialize the JSON body into the target type:
#   data did not match any variant of untagged enum
#   IngestExecutionEventsRequest
#
# One malformed event rejects the WHOLE batch, and lineage publish is
# fail-open, so the entire run vanished from the execution-lineage view
# with only a WARNING in the plugin's log. The same defect had already
# been fixed once in the LangGraph plugin (see plugins/CHANGELOG.md) and
# survived in two others, so the check lives here — one place, every
# emitter — rather than as a per-plugin assertion.


def _execution_started_by_emitter() -> Dict[str, Dict[str, Any]]:
    """One ``execution_started`` event per emitter, straight out of
    each plugin's real translator."""
    adk = translate_adk_events(
        captures=[
            {
                "hook": "before_agent_callback",
                "agent_name": "research-analyst",
                "depth": 0,
            }
        ],
        execution_id="exec",
        agent_id="agent-1",
    )
    msaf = translate_msaf_events(
        captures=[{"hook": "workflow_run_start", "depth": 0}],
        execution_id="exec",
        agent_id="agent-1",
    )
    langgraph = translate_langgraph_events(
        events=[{"hook": "on_chain_start", "run_id": "root", "serialized": {}}],
        execution_id="exec",
        agent_id="agent-1",
    )
    out: Dict[str, Dict[str, Any]] = {}
    for name, events in (
        ("adk", adk),
        ("msaf", msaf),
        ("langgraph", langgraph),
    ):
        started = [e for e in events if e["event_type"] == "execution_started"]
        assert started, f"{name} translator produced no execution_started event"
        out[name] = started[0]
    return out


def test_every_emitter_execution_started_matches_the_server_struct():
    """Pins the exact server contract: the ``execution_started``
    payload each plugin builds validates against
    ``events_schema.ExecutionStartedPayload``, the Python mirror of the
    Rust struct ``POST /v1/events`` decodes it as."""
    from watchlight_core.events_schema import ExecutionStartedPayload

    for emitter, event in _execution_started_by_emitter().items():
        payload = event["payload"]
        # The canonical PrincipalRef: principal_type + id, both required.
        assert payload["principal"] == {
            "principal_type": "agent",
            "id": "agent-1",
        }, f"{emitter} emitted a non-canonical principal: {payload['principal']!r}"
        ExecutionStartedPayload.model_validate(payload)


@pytest.mark.parametrize(
    "legacy_principal",
    [
        # The ADK plugin's shape before the fix.
        {"agent_id": "agent-1"},
        # The MSAF plugin's shape before the fix — a pre-rendered Cedar
        # reference, which the server derives itself from the ref.
        {"principal": 'Agent::"agent-1"'},
    ],
    ids=["legacy_agent_id", "legacy_cedar_string"],
)
def test_legacy_principal_shapes_fail_the_server_struct(legacy_principal):
    """The other half of the contract: the shapes that caused the 422
    MUST fail the model. Without this, a check that silently accepted
    everything would look green forever."""
    import pydantic

    from watchlight_core.events_schema import ExecutionStartedPayload

    with pytest.raises(pydantic.ValidationError):
        ExecutionStartedPayload.model_validate(
            {"principal": legacy_principal, "depth": 0}
        )


def test_every_emitted_event_payload_matches_its_event_type_struct():
    """Invariant 16 across every emitter and every event type — not
    just ``execution_started``. ``assert_payload_matches_schema``
    dispatches on ``event_type`` exactly as wl-apdp does."""
    from watchlight_core_testing import assert_payload_matches_schema

    streams = dict(_all_emitter_events())
    streams["lifecycle"] = list(_execution_started_by_emitter().values())
    for emitter, events in streams.items():
        for ev in events:
            try:
                assert_payload_matches_schema(ev)
            except Exception as exc:  # noqa: BLE001
                raise AssertionError(
                    f"{emitter} built a {ev.get('event_type')!r} event whose "
                    f"payload wl-apdp would reject: {exc}"
                ) from exc


# ─── No emitter may send a key the server drops ──────────────


def test_no_emitter_payload_carries_a_key_the_server_does_not_model():
    """Conformance invariant 16, silent-data-loss half.

    Rust's payload structs do NOT set ``deny_unknown_fields``, so an
    unknown payload key is not rejected at ingest: serde accepts the
    event and drops the key. Nothing is logged, nothing 4xxs, and a
    consumer written against the key reads nothing forever. That
    happened once — two plugins put ``depth`` and
    ``spawned_by_agent_id`` on an ``execution_completed`` payload and
    the dashboard timeline composed "depth N · spawned by Y" from two
    values that never arrived.

    So the sweep runs over every emitter, not the one that was
    reported: a dropped key is a bug class, not an incident.
    """
    from watchlight_core.events_schema import unknown_payload_keys

    for emitter, events in _all_emitter_events().items():
        for ev in events:
            dropped = unknown_payload_keys(ev.get("event_type"), ev.get("payload"))
            assert not dropped, (
                f"{emitter} builds a {ev.get('event_type')!r} payload carrying "
                f"key(s) the server does not model: {dropped}. serde drops "
                f"them silently. Add the field to the lineage event schema and "
                f"its mirror in watchlight_core.events_schema, emit the fact on "
                f"the canonical field that already models it, or move it under "
                f"the envelope's `metadata`, which does round-trip."
            )


# ─── Invariant 19 — provider-hosted tools ────────────────────────────


@pytest.mark.parametrize("framework", ["adk", "langgraph", "bedrock", "msaf"])
def test_hosted_tool_observation_is_canonical_in_every_plugin_namespace(framework):
    """A hosted tool invocation recorded with the core builder is a
    canonical ``tool_call_observed`` event under the plugin's own URI
    namespace (invariant 4), with a payload the server models in full
    (invariant 16), whichever plugin records it."""
    import uuid

    from watchlight_core import HOSTED_TOOL_METADATA, hosted_tool_observation, normalize_hosted_tools
    from watchlight_core.events_schema import unknown_payload_keys
    from watchlight_core_testing import assert_canonical_event, assert_payload_matches_schema

    tools = normalize_hosted_tools(
        [
            {"type": "web_search"},
            {"type": "code_execution_20250522", "name": "code_execution"},
            {"type": "mcp", "server_label": "docs", "server_url": "https://mcp.example.com/mcp"},
        ]
    )
    for tool in tools:
        event = {
            "event_id": f"evt_{uuid.uuid4()}",
            "event_type": "tool_call_observed",
            "timestamp": "2026-10-27T00:00:00Z",
            "execution_id": "exec_hosted",
            "agent_id": "agent-uuid",
            "payload": hosted_tool_observation(tool, framework=framework, decision="Allow"),
            "metadata": {"source": f"{framework}.plugin", **HOSTED_TOOL_METADATA},
        }
        assert_canonical_event(event, expected_uri_prefix=f"{framework}://")
        assert_payload_matches_schema(event)
        assert not unknown_payload_keys(event["event_type"], event["payload"])


def test_hosted_tools_invariant_is_numbered_like_the_ts_lane():
    from watchlight_core_testing.conformance import (
        HOSTED_TOOLS_AUTHORIZED_INVARIANT_NAME,
        HOSTED_TOOLS_AUTHORIZED_INVARIANT_NUMBER,
        INVARIANTS,
    )

    assert (HOSTED_TOOLS_AUTHORIZED_INVARIANT_NUMBER, HOSTED_TOOLS_AUTHORIZED_INVARIANT_NAME) == (
        19,
        "hosted_tools_authorized_before_model_call",
    )
    assert any(n == 19 for n, _, _ in INVARIANTS)
