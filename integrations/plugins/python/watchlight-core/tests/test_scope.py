"""Wire-shape parity tests for the Python `scope` module.

These tests pin the JSON wire shape so it stays equivalent to the
**canonical Rust shapes in wl-lineage** (re-exported by wl-apdp) and the
TypeScript SDK mirror (``watchlight-agent-sdk-ts/src/scope.ts``).

The fixture timestamps and UUIDs match the Rust test fixtures
verbatim so cross-lane equality can be asserted by string comparison
where useful.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from uuid import UUID

import pytest

from watchlight_core.scope import (
    GrantedScope,
    ParentSignature,
    RequestedScope,
    ResourceMatcher,
    SpawnSubagentRequest,
    SpawnSubagentResponse,
    granted_scope_from_dict,
    granted_scope_to_dict,
    parent_signature_from_dict,
    parent_signature_to_dict,
    requested_scope_from_dict,
    requested_scope_to_dict,
    spawn_subagent_request_from_dict,
    spawn_subagent_request_to_dict,
    spawn_subagent_response_from_dict,
    spawn_subagent_response_to_dict,
)


# ─── Fixtures ────────────────────────────────────────────────────


FIXED_TS = datetime(2026, 6, 15, 0, 0, 0, tzinfo=timezone.utc)
NIL_UUID = UUID("00000000-0000-0000-0000-000000000000")


# ─── RequestedScope ──────────────────────────────────────────────


def test_requested_scope_default_is_empty_fail_closed() -> None:
    """Locked invariant #2 — bare ``RequestedScope()`` must grant
    zero privileges along every dimension. Mirrors the canonical
    wl-lineage shape semantics: empty allowlists + 0 depth, and no time
    budget (the child inherits the parent's remaining time, never more)."""
    s = RequestedScope()
    assert s.allowed_tools == []
    assert s.allowed_resources == []
    assert s.allowed_intents == []
    assert s.max_depth == 0
    assert s.time_budget_seconds is None
    assert s.is_empty()


def test_requested_scope_from_empty_dict() -> None:
    """Decode ``{}`` → fail-closed default. The wire-side anchor for
    locked invariant #2."""
    s = requested_scope_from_dict({})
    assert s == RequestedScope()


def test_requested_scope_from_partial_dict() -> None:
    """Decoder accepts subsets of fields; missing fields fall back to
    the empty / 0 default."""
    s = requested_scope_from_dict({"allowed_tools": ["search.web"]})
    assert s.allowed_tools == ["search.web"]
    assert s.allowed_resources == []
    assert s.max_depth == 0


def test_requested_scope_round_trip() -> None:
    s = RequestedScope(
        allowed_tools=["search.web", "summarize.text"],
        allowed_resources=[
            ResourceMatcher(matcher="doc::*"),
            ResourceMatcher(matcher="url::https://*"),
        ],
        allowed_intents=["audit q3 invoices"],
        max_depth=1,
        time_budget_seconds=300,
    )
    encoded = json.dumps(requested_scope_to_dict(s))
    decoded = requested_scope_from_dict(json.loads(encoded))
    assert decoded == s


def test_requested_scope_wire_shape_is_snake_case() -> None:
    """Mirror parity with Rust + TS — every field uses the canonical
    snake_case name. An absent time budget stays off the wire."""
    d = requested_scope_to_dict(RequestedScope())
    for key in (
        "allowed_tools",
        "allowed_resources",
        "allowed_intents",
        "max_depth",
    ):
        assert key in d, f"missing wire-shape field {key!r}"
    assert "time_budget_seconds" not in d
    d = requested_scope_to_dict(RequestedScope(time_budget_seconds=30))
    assert d["time_budget_seconds"] == 30


@pytest.mark.parametrize("value", [1.5, "10", True, -1, 2**32, 10**20])
def test_requested_scope_refuses_a_budget_that_is_not_an_integer_in_range(value) -> None:
    """wl-apdp reads the budget as a ``u32`` and answers 422 to anything
    else; the decoder refuses it the same way instead of coercing it."""
    with pytest.raises(ValueError):
        requested_scope_from_dict({"time_budget_seconds": value})


def test_requested_scope_absent_or_null_budget_is_none() -> None:
    assert requested_scope_from_dict({}).time_budget_seconds is None
    assert requested_scope_from_dict({"time_budget_seconds": None}).time_budget_seconds is None
    assert requested_scope_from_dict({"time_budget_seconds": 0}).time_budget_seconds == 0


def test_requested_scope_is_empty_helper() -> None:
    s = RequestedScope()
    assert s.is_empty()
    s.allowed_tools.append("a")
    assert not s.is_empty()


def test_requested_scope_decode_tolerates_explicit_none_lists() -> None:
    """A wire payload that sends ``allowed_tools: null`` (rare but
    legal — some clients can't distinguish "missing" from
    "explicit None") decodes to an empty list, not a TypeError."""
    s = requested_scope_from_dict({"allowed_tools": None})
    assert s.allowed_tools == []


def test_requested_scope_resources_are_canonical_objects() -> None:
    """The canonical wl-lineage shape encodes resources as
    ``{"matcher": "..."}`` objects, NOT bare strings."""
    s = RequestedScope(
        allowed_resources=[ResourceMatcher(matcher="doc::*")],
    )
    d = requested_scope_to_dict(s)
    assert d["allowed_resources"] == [{"matcher": "doc::*"}]


def test_requested_scope_decodes_bare_string_resources_for_backcompat() -> None:
    """Backwards-compat: decoder accepts both bare strings (the
    early preview shape) AND canonical objects. Encoder always
    emits the canonical object form."""
    s = requested_scope_from_dict(
        {"allowed_resources": ["doc::*", {"matcher": "url::https://*"}]},
    )
    assert s.allowed_resources == [
        ResourceMatcher(matcher="doc::*"),
        ResourceMatcher(matcher="url::https://*"),
    ]


# ─── GrantedScope ────────────────────────────────────────────────


def _granted(**overrides) -> GrantedScope:  # type: ignore[no-untyped-def]
    base: dict = {
        "allowed_tools": [],
        "allowed_resources": [],
        "allowed_intents": [],
        "max_depth": 0,
        "time_budget_seconds": 0,
        "deadline": FIXED_TS,
        "parent_run_handle_id": "00000000-0000-0000-0000-000000000099",
        "depth": 0,
    }
    base.update(overrides)
    return GrantedScope(**base)


def test_granted_scope_round_trip() -> None:
    g = _granted(
        allowed_tools=["search.web"],
        allowed_resources=[ResourceMatcher(matcher="doc::*")],
        allowed_intents=["audit q3"],
        max_depth=1,
        time_budget_seconds=300,
        depth=1,
    )
    encoded = json.dumps(granted_scope_to_dict(g))
    decoded = granted_scope_from_dict(json.loads(encoded))
    assert decoded == g


def test_granted_scope_skips_none_deadline_and_handle() -> None:
    """Mirror parity with Rust
    ``#[serde(skip_serializing_if = "Option::is_none")]`` — ``None``
    ``deadline`` and ``parent_run_handle_id`` MUST be omitted."""
    g = GrantedScope(
        allowed_tools=[],
        allowed_resources=[],
        allowed_intents=[],
        max_depth=0,
        time_budget_seconds=0,
        deadline=None,
        parent_run_handle_id=None,
        depth=0,
    )
    d = granted_scope_to_dict(g)
    assert "deadline" not in d
    assert "parent_run_handle_id" not in d


def test_granted_scope_emits_present_deadline() -> None:
    g = _granted(deadline=FIXED_TS)
    d = granted_scope_to_dict(g)
    assert d.get("deadline", "").endswith("Z")


def test_granted_scope_wire_shape_canonical() -> None:
    """The canonical wl-lineage `GrantedScope` carries `deadline` +
    `parent_run_handle_id` + `depth` (NOT the early-preview
    `expires_at` / `parent_signature`)."""
    d = granted_scope_to_dict(_granted())
    for key in (
        "allowed_tools",
        "allowed_resources",
        "allowed_intents",
        "max_depth",
        "time_budget_seconds",
        "depth",
        "deadline",
        "parent_run_handle_id",
    ):
        assert key in d, f"missing canonical wire field {key!r}"
    # Deferred — parent_signature does NOT appear on the
    # canonical wire shape today.
    assert "parent_signature" not in d
    # The early-preview field name was `expires_at`; the canonical
    # shape uses `deadline`.
    assert "expires_at" not in d


def test_granted_scope_decodes_chrono_z_suffix() -> None:
    """Decoder must accept both the chrono Z suffix and the Python
    +00:00 suffix on `deadline`."""
    base = {
        "allowed_tools": [],
        "allowed_resources": [],
        "allowed_intents": [],
        "max_depth": 0,
        "time_budget_seconds": 0,
        "depth": 0,
    }
    a = granted_scope_from_dict({**base, "deadline": "2026-06-15T00:00:00Z"})
    b = granted_scope_from_dict({**base, "deadline": "2026-06-15T00:00:00+00:00"})
    assert a == b


# ─── ParentSignature ─────────────────────────────────────────────


def test_parent_signature_round_trip() -> None:
    """``ParentSignature`` is scaffolded for a future signing
    cutover — its wire-shape round-trip must stay stable so SDK
    consumers can decode a future signed response without
    a schema migration."""
    sig = ParentSignature(
        kid="agent-123",
        algorithm="Ed25519",
        signature_b64="AAAAAAA",
        signed_at=FIXED_TS,
    )
    encoded = json.dumps(parent_signature_to_dict(sig))
    decoded = parent_signature_from_dict(json.loads(encoded))
    assert decoded == sig


def test_parent_signature_wire_shape_is_snake_case() -> None:
    sig = ParentSignature(
        kid="agent-123",
        algorithm="Ed25519",
        signature_b64="AAAA",
        signed_at=FIXED_TS,
    )
    d = parent_signature_to_dict(sig)
    for key in ("kid", "algorithm", "signature_b64", "signed_at"):
        assert key in d


# ─── SpawnSubagentRequest ────────────────────────────────────────


def test_spawn_subagent_request_round_trip() -> None:
    req = SpawnSubagentRequest(
        parent_agent_id=NIL_UUID,
        child_agent_id=NIL_UUID,
        parent_run_handle_id=NIL_UUID,
        requested_scope=RequestedScope(),
    )
    encoded = json.dumps(spawn_subagent_request_to_dict(req))
    decoded = spawn_subagent_request_from_dict(json.loads(encoded))
    assert decoded == req


def test_spawn_subagent_request_wire_shape_is_snake_case() -> None:
    req = SpawnSubagentRequest(
        parent_agent_id=NIL_UUID,
        child_agent_id=NIL_UUID,
        parent_run_handle_id=NIL_UUID,
        requested_scope=RequestedScope(),
    )
    d = spawn_subagent_request_to_dict(req)
    for key in (
        "parent_agent_id",
        "child_agent_id",
        "parent_run_handle_id",
        "requested_scope",
    ):
        assert key in d


def test_spawn_subagent_request_decodes_with_omitted_scope_fields() -> None:
    """End-to-end fail-closed: a wire body that omits every scope
    dimension produces a valid SpawnSubagentRequest whose
    requested_scope is empty."""
    body = {
        "parent_agent_id": "00000000-0000-0000-0000-000000000001",
        "child_agent_id": "00000000-0000-0000-0000-000000000002",
        "parent_run_handle_id": "00000000-0000-0000-0000-000000000003",
        "requested_scope": {},
    }
    req = spawn_subagent_request_from_dict(body)
    assert req.requested_scope.is_empty()


# ─── Lineage stitching ────────────────────────────────────
#
# When the plugin passes ``child_execution_id`` + ``parent_execution_id``
# + ``root_execution_id`` through the request, the wire shape must
# carry them. APDP uses them to stamp the
# ``agent_spawn_observed`` envelope so the dashboard renders ONE
# child execution row, not the orphan top-level card the previous
# behaviour produced.


def test_spawn_subagent_request_wire_shape_carries_only_core_fields() -> None:
    """Execution-lineage integrity. The request wire
    shape carries ONLY the parent identity + handle + requested scope. The
    former ``child_execution_id`` / ``parent_execution_id`` /
    ``root_execution_id`` fields are REMOVED — the child's tree position is
    SERVER-derived from the parent's VERIFIED credential, never
    client-supplied. (Deleted with these fields: the old
    ``..._threads_lineage_fields_through_wire`` and
    ``..._decodes_missing_lineage_fields_as_none`` tests.)"""
    req = SpawnSubagentRequest(
        parent_agent_id=NIL_UUID,
        child_agent_id=NIL_UUID,
        parent_run_handle_id=NIL_UUID,
        requested_scope=RequestedScope(),
    )
    d = spawn_subagent_request_to_dict(req)
    assert set(d.keys()) == {
        "parent_agent_id",
        "child_agent_id",
        "parent_run_handle_id",
        "requested_scope",
    }
    assert "child_execution_id" not in d
    assert "parent_execution_id" not in d
    assert "root_execution_id" not in d
    # Round-trips through the decoder without the removed fields.
    assert spawn_subagent_request_from_dict(d) == req


# ─── SpawnSubagentResponse ───────────────────────────────────────


def test_spawn_subagent_response_round_trip() -> None:
    resp = SpawnSubagentResponse(
        child_run_handle_id=NIL_UUID,
        granted_scope=_granted(),
        lineage_event_id=None,
    )
    encoded = json.dumps(spawn_subagent_response_to_dict(resp))
    decoded = spawn_subagent_response_from_dict(json.loads(encoded))
    assert decoded == resp


def test_spawn_subagent_response_skips_none_lineage_event_id() -> None:
    resp = SpawnSubagentResponse(
        child_run_handle_id=NIL_UUID,
        granted_scope=_granted(),
        lineage_event_id=None,
    )
    d = spawn_subagent_response_to_dict(resp)
    assert "lineage_event_id" not in d


# ─── Cross-lane fixture parity ───────────────────────────────────


def test_cross_lane_canonical_fixture_decodes() -> None:
    """The canonical fixture used in the Rust + TS tests must decode
    cleanly here. Any change to the wire shape that breaks this test
    is a cross-lane regression and must be reverted."""
    fixture = {
        "parent_agent_id": "00000000-0000-0000-0000-000000000001",
        "child_agent_id": "00000000-0000-0000-0000-000000000002",
        "parent_run_handle_id": "00000000-0000-0000-0000-000000000003",
        "requested_scope": {
            "allowed_tools": ["search.web", "summarize.text"],
            "allowed_resources": [
                {"matcher": "doc::*"},
                {"matcher": "url::https://*"},
            ],
            "allowed_intents": ["audit q3 invoices"],
            "max_depth": 1,
            "time_budget_seconds": 300,
        },
    }
    req = spawn_subagent_request_from_dict(fixture)
    assert req.parent_agent_id == UUID("00000000-0000-0000-0000-000000000001")
    assert req.child_agent_id == UUID("00000000-0000-0000-0000-000000000002")
    assert req.parent_run_handle_id == UUID("00000000-0000-0000-0000-000000000003")
    assert req.requested_scope.allowed_tools == ["search.web", "summarize.text"]
    assert req.requested_scope.allowed_resources == [
        ResourceMatcher(matcher="doc::*"),
        ResourceMatcher(matcher="url::https://*"),
    ]
    assert req.requested_scope.max_depth == 1
    assert req.requested_scope.time_budget_seconds == 300


@pytest.mark.parametrize(
    "field_name,bad_value",
    [
        ("parent_agent_id", "not-a-uuid"),
        ("child_agent_id", "not-a-uuid"),
        ("parent_run_handle_id", "not-a-uuid"),
    ],
)
def test_spawn_subagent_request_rejects_invalid_uuid(
    field_name: str, bad_value: str,
) -> None:
    """Defensive — invalid UUID strings must surface as ValueError
    at decode time, not silently coerce. The validator trusts
    the decoder; a silent coerce would let a malformed body reach the
    enforcement gate with stale identifiers."""
    body = {
        "parent_agent_id": "00000000-0000-0000-0000-000000000001",
        "child_agent_id": "00000000-0000-0000-0000-000000000002",
        "parent_run_handle_id": "00000000-0000-0000-0000-000000000003",
        "requested_scope": {},
    }
    body[field_name] = bad_value
    with pytest.raises(ValueError):
        spawn_subagent_request_from_dict(body)
