"""Tests for sub-agent scope attenuation and ``max_delegation_depth``.

The strict-subset math is done by the real ``watchlight-engine``; these tests
assert the wrapper's contract: subsets clamp, supersets are denied, the tree is
bounded by ``max_delegation_depth`` (a governance control, default 8), a hop past
it is a deny with reason code ``DELEGATION_DEPTH_EXCEEDED``, and every
attenuation is audited.
"""
import json
import pathlib

import pytest

pytest.importorskip("watchlight_engine")

from watchlight import (
    DEFAULT_MAX_DELEGATION_DEPTH,
    DELEGATION_DEPTH_EXCEEDED,
    AttenuationDenied,
    DelegationDepthExceeded,
    Watchlight,
)


def _gov(tmp_path: pathlib.Path, **opts) -> Watchlight:
    return Watchlight(agent="test-agent", audit_dir=str(tmp_path / ".watchlight"), **opts)


def _records(tmp_path: pathlib.Path) -> list[dict]:
    audit = tmp_path / ".watchlight" / "audit.jsonl"
    return [json.loads(line) for line in audit.read_text().splitlines()]


def test_attenuate_clamps_to_strict_subset(tmp_path):
    root = _gov(tmp_path).scope(tools=["read", "write", "search"], intents=["research"])
    child = root.attenuate(tools=["read"])
    assert child.allowed_tools == ["read"]
    assert child.depth == 1


def test_attenuate_denies_a_superset(tmp_path):
    root = _gov(tmp_path).scope(tools=["read"], intents=["research"])
    with pytest.raises(AttenuationDenied) as ei:
        root.attenuate(tools=["read", "delete"])
    assert "AllowedTools" in ei.value.violations


def test_default_max_delegation_depth_is_eight(tmp_path):
    g = _gov(tmp_path)
    assert DEFAULT_MAX_DELEGATION_DEPTH == 8
    assert g.max_delegation_depth == 8
    root = g.scope(tools=["read"], intents=["research"])
    assert root.max_delegation_depth == 8


def test_a_chain_deeper_than_five_within_the_limit_is_permitted_and_attenuated(tmp_path):
    # Eight hops under the default limit — past the old depth-5 cap — each one a
    # real engine-validated strict subset of its parent.
    s = _gov(tmp_path).scope(tools=["read", "write", "search"], intents=["research", "summarize"])
    wanted = [
        ["read", "search"],
        ["read", "search"],
        ["read"],
        ["read"],
        ["read"],
        ["read"],
        ["read"],
        ["read"],
    ]
    for depth, tools in enumerate(wanted, start=1):
        parent_tools = set(s.allowed_tools)
        s = s.attenuate(tools=tools, intents=["research"])
        assert s.depth == depth
        assert set(s.allowed_tools) == set(tools) and set(s.allowed_tools) <= parent_tools
        assert s.allowed_intents == ["research"]
    assert s.depth == 8


def test_a_hop_past_the_default_limit_is_denied_with_the_reason_code(tmp_path):
    s = _gov(tmp_path).scope(tools=["read"], intents=["research"])
    for _ in range(DEFAULT_MAX_DELEGATION_DEPTH):
        s = s.attenuate(tools=["read"])
    with pytest.raises(DelegationDepthExceeded) as ei:
        s.attenuate(tools=["read"])
    err = ei.value
    assert isinstance(err, AttenuationDenied)  # a deny, caught like any other
    assert err.code == DELEGATION_DEPTH_EXCEEDED == "DELEGATION_DEPTH_EXCEEDED"
    assert (err.depth, err.limit) == (9, 8)
    assert err.violations == ["MaxDepth"]


def test_a_custom_lower_limit_denies_sooner(tmp_path):
    s = _gov(tmp_path, max_delegation_depth=3).scope(tools=["read"], intents=["research"])
    for _ in range(3):
        s = s.attenuate(tools=["read"])
    with pytest.raises(DelegationDepthExceeded) as ei:
        s.attenuate(tools=["read"])
    assert (ei.value.depth, ei.value.limit) == (4, 3)


def test_the_depth_deny_is_recorded_with_the_observed_depth_and_the_limit(tmp_path):
    s = _gov(tmp_path, max_delegation_depth=3).scope(tools=["read"], intents=["research"])
    for _ in range(3):
        s = s.attenuate(tools=["read"])
    with pytest.raises(DelegationDepthExceeded):
        s.attenuate(tools=["read"])
    last = _records(tmp_path)[-1]
    assert last["event"] == "attenuation"
    assert last["decision"] == "Deny"
    assert last["reason_code"] == "DELEGATION_DEPTH_EXCEEDED"
    assert last["depth"] == 4
    assert last["max_delegation_depth"] == 3
    assert last["parent_id"] == s.node_id
    assert "sales@" not in last["reason"] and "Enterprise" not in last["reason"]


def test_a_strict_subset_refusal_carries_no_depth_reason_code(tmp_path):
    root = _gov(tmp_path).scope(tools=["read"], intents=["research"])
    with pytest.raises(AttenuationDenied) as ei:
        root.attenuate(tools=["read", "delete"])
    assert not isinstance(ei.value, DelegationDepthExceeded)
    assert "reason_code" not in _records(tmp_path)[-1]


def test_strict_subset_still_applies_below_the_limit_past_depth_five(tmp_path):
    s = _gov(tmp_path).scope(tools=["read", "write"], intents=["research"])
    for _ in range(6):
        s = s.attenuate(tools=["read"])
    with pytest.raises(AttenuationDenied) as ei:
        s.attenuate(tools=["read", "write"])  # widening at depth 7 is still refused
    assert not isinstance(ei.value, DelegationDepthExceeded)
    assert "AllowedTools" in ei.value.violations


def test_scope_can_lower_the_limit_but_never_raise_it(tmp_path):
    g = _gov(tmp_path, max_delegation_depth=4)
    low = g.scope(tools=["read"], max_depth=2)
    assert low.max_delegation_depth == 2
    low = low.attenuate(tools=["read"]).attenuate(tools=["read"])
    with pytest.raises(DelegationDepthExceeded) as ei:
        low.attenuate(tools=["read"])
    assert ei.value.limit == 2
    assert g.scope(tools=["read"], max_depth=50).max_delegation_depth == 4


def test_zero_allows_no_sub_agents(tmp_path):
    root = _gov(tmp_path, max_delegation_depth=0).scope(tools=["read"])
    with pytest.raises(DelegationDepthExceeded) as ei:
        root.attenuate(tools=["read"])
    assert (ei.value.depth, ei.value.limit) == (1, 0)


@pytest.mark.parametrize("bad, exc", [(-1, ValueError), (65, ValueError), (True, TypeError), ("8", TypeError)])
def test_an_invalid_limit_is_rejected(tmp_path, bad, exc):
    with pytest.raises(exc):
        _gov(tmp_path, max_delegation_depth=bad)


def test_attenuation_is_audited(tmp_path):
    root = _gov(tmp_path).scope(tools=["read", "write"], intents=["research"])
    root.attenuate(tools=["read"])
    audit = tmp_path / ".watchlight" / "audit.jsonl"
    records = [json.loads(line) for line in audit.read_text().splitlines()]
    assert records, "attenuation must be recorded"
    last = records[-1]
    assert last["event"] == "attenuation"
    assert last["decision"] == "Allow"
    assert last["agent"] == "test-agent"
    # Value-free: only capability names, never argument values.
    assert "arguments" not in last


def test_records_carry_parent_child_lineage(tmp_path):
    root = _gov(tmp_path).scope(tools=["read", "write"], intents=["research"])
    child = root.attenuate(tools=["read"])
    audit = tmp_path / ".watchlight" / "audit.jsonl"
    recs = [json.loads(line) for line in audit.read_text().splitlines()]
    root_rec, child_rec = recs[0], recs[-1]
    assert "parent_id" not in root_rec  # a root scope is parent-less
    assert root_rec["node_id"] == root.node_id
    assert child_rec["parent_id"] == root.node_id  # child links to its parent
    assert child_rec["node_id"] == child.node_id
    assert child_rec["tools"] == ["read"]


def test_console_reconstructs_the_tree(tmp_path):
    from watchlight.cli import _attenuation

    root = _gov(tmp_path).scope(tools=["read", "write"])
    child = root.attenuate(tools=["read"])
    grandchild = child.attenuate(tools=["read"])
    nodes = {n["id"]: n for n in _attenuation(tmp_path / ".watchlight" / "audit.jsonl")}
    assert {root.node_id, child.node_id, grandchild.node_id} <= set(nodes)
    assert nodes[root.node_id]["parent"] is None
    assert nodes[child.node_id]["parent"] == root.node_id
    assert nodes[grandchild.node_id]["parent"] == child.node_id
    assert nodes[grandchild.node_id]["depth"] == 2


def test_console_marks_a_depth_limit_refusal(tmp_path):
    from watchlight.cli import _attenuation

    root = _gov(tmp_path, max_delegation_depth=1).scope(tools=["read"])
    child = root.attenuate(tools=["read"])
    with pytest.raises(DelegationDepthExceeded):
        child.attenuate(tools=["read"])
    nodes = _attenuation(tmp_path / ".watchlight" / "audit.jsonl")
    refused = [n for n in nodes if not n["allowed"]]
    assert len(refused) == 1 and refused[0]["depth_limit"] is True
    assert all(not n["depth_limit"] for n in nodes if n["allowed"])


def test_attenuate_with_resources_round_trips_matchers(tmp_path):
    # The engine's resource dimension is a list of {"matcher": ...} structs; the
    # Scope API keeps plain strings on both sides of the call.
    root = _gov(tmp_path).scope(tools=["read"], resources=["docs/*", "crm/*"], intents=["research"])
    child = root.attenuate(resources=["docs/*"])
    assert child.allowed_resources == ["docs/*"]
    with pytest.raises(AttenuationDenied):
        root.attenuate(resources=["docs/*", "hr/*"])
