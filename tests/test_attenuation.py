"""Tests for Developer-Edition sub-agent scope attenuation (the depth-5 ceiling).

The strict-subset math is done by the real ``watchlight-engine``; these tests
assert the DE wrapper's contract: subsets clamp, supersets are denied, the tree
is governed up to depth 5, and every attenuation is audited.
"""
import json
import pathlib

import pytest

pytest.importorskip("watchlight_engine")

from watchlight import AttenuationDenied, DE_MAX_DEPTH, DevEditionCeiling, Watchlight


def _gov(tmp_path: pathlib.Path) -> Watchlight:
    return Watchlight(agent="test-agent", audit_dir=str(tmp_path / ".watchlight"))


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


def test_depth_five_allowed_sixth_hits_the_ceiling(tmp_path):
    s = _gov(tmp_path).scope(tools=["read"], intents=["research"])
    for _ in range(DE_MAX_DEPTH):  # five levels all succeed
        s = s.attenuate(tools=["read"])
    assert s.depth == DE_MAX_DEPTH
    with pytest.raises(DevEditionCeiling) as ei:
        s.attenuate(tools=["read"])
    assert ei.value.cap == DE_MAX_DEPTH
    assert "sales@watchlight.ai" in str(ei.value)


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


def test_ceiling_is_recorded_as_a_deny_with_the_upsell(tmp_path):
    s = _gov(tmp_path).scope(tools=["read"], intents=["research"])
    for _ in range(DE_MAX_DEPTH):
        s = s.attenuate(tools=["read"])
    with pytest.raises(DevEditionCeiling):
        s.attenuate(tools=["read"])
    audit = tmp_path / ".watchlight" / "audit.jsonl"
    last = json.loads(audit.read_text().splitlines()[-1])
    assert last["decision"] == "Deny"
    assert last["depth"] == DE_MAX_DEPTH + 1
    assert "sales@watchlight.ai" in last["reason"]


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
