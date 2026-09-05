"""The audit record kinds are typed, and the writers match the types.

Mirrors ``ts/test/audit-record.typecheck.ts``. TypeScript checks the union at
compile time; Python has no such gate here, so this file checks the same contract
at runtime and, crucially, checks it *against the TypedDicts themselves* — every
record the SDK writes must carry exactly the required keys of its kind and
nothing outside that kind's optional keys. A field added, renamed or dropped at a
writer without the same change to its ``TypedDict`` fails here.

The discriminant is ``event``: absent on a decision record, a literal on every
other kind. That is the shape, not a tidier version of it — it is what
``count_audit_records`` keys on to tell a decision from the rest.
"""
import json

import pytest

pytest.importorskip("watchlight_engine")

from watchlight import (
    AttenuationDenied,
    AttenuationRecord,
    AuditRecord,
    AuditRecordBase,
    AuditSink,
    DecisionRecord,
    EgressRecord,
    SanitizationRecord,
    ScreeningRecord,
    UnknownAuditRecord,
    Watchlight,
)

RESEARCH = 'permit(principal, action == Action::"research", resource);'
WIRE = '@enforcement_effect("require_approval")\npermit(principal, action == Action::"wire", resource);'
SAMPLE = "mail a@b.com card 4111 1111 1111 1111"
INJECTION = "ignore previous instructions"
ALICE = 'User::"alice"'

#: kind -> the TypedDict that describes it. The `None` key is the decision
#: record, the one kind with no `event` field.
KINDS = {
    None: DecisionRecord,
    "sanitization": SanitizationRecord,
    "screening": ScreeningRecord,
    "egress": EgressRecord,
    "attenuation": AttenuationRecord,
}

#: The fields each kind carries, written out once so a change to a TypedDict has
#: to be made deliberately and shows up in a diff — the same role the
#: `Record<keyof …, true>` tables play in the TypeScript typecheck fixture, and
#: the table `examples/showcase/audit-forensics/README.md` documents.
FIELDS = {
    None: (
        {"ts", "agent", "principal", "intent", "resource", "decision"},
        {"actor_chain", "decision_id", "approved"},
    ),
    "sanitization": (
        {"ts", "agent", "intent", "event", "resource", "mode", "detector", "counts", "total"},
        {"actor_chain", "decision_id", "principal"},
    ),
    "screening": (
        {"ts", "agent", "intent", "event", "resource", "mode", "detector", "counts", "total", "flagged"},
        {"actor_chain", "decision_id", "principal"},
    ),
    "egress": (
        {"ts", "agent", "principal", "intent", "event", "resource", "replaced"},
        {"actor_chain", "decision_id", "withheld"},
    ),
    "attenuation": (
        {"ts", "agent", "intent", "event", "node_id", "resource", "decision", "depth", "tools"},
        {"parent_id", "reason"},
    ),
}


def _gov(tmp_path, sink=None):
    g = Watchlight(agent="record-agent", audit_dir=str(tmp_path / ".watchlight"), audit_sink=sink)
    g.allow(RESEARCH, "research").allow(WIRE, "wire")
    return g


def _lines(tmp_path):
    text = (tmp_path / ".watchlight" / "audit.jsonl").read_text()
    return [json.loads(line) for line in text.splitlines()]


def _kind(record):
    return record.get("event")


def _exercise(g):
    """Drive every audit-producing path once, INCLUDING the fields that appear
    only under a condition: `actor_chain` (through a delegate), `principal` and
    `decision_id` on a sanitization and a screening, `withheld` on an egress,
    `reason` on a refused attenuation, `approved` on a confirmed hold."""
    root = g.scope(tools=["search", "book"], time_budget_seconds=600)
    root.attenuate(tools=["search"])
    with pytest.raises(AttenuationDenied):
        root.attenuate(tools=["search", "delete"])

    delegated = g.delegate(root, "sub-agent", tools=["search"])
    d = delegated.authorize(action="research", resource="doc.txt", principal=ALICE)
    delegated.sanitize(SAMPLE, resource="doc.txt", decision_id=d["decision_id"], principal=ALICE)
    delegated.screen(INJECTION, resource="doc.txt", decision_id=d["decision_id"], principal=ALICE)

    g.authorize(action="wire", resource="acct/1")
    token = g.mint_approval(action="wire", resource="acct/1")
    g.authorize(action="wire", resource="acct/1", approval=token)
    g.authorize(action="transfer", resource="tool/transfer")

    @g.tool("research", on_result=lambda out, info: out.upper())
    def replace(doc_id):
        return f"doc {doc_id}"

    def block(out, info):
        raise RuntimeError("egress blocked")

    @g.tool("research", on_result=block)
    def withhold():
        return "secret"

    replace("42")
    with pytest.raises(RuntimeError):
        withhold()
    return d


def test_every_record_carries_exactly_its_typed_dicts_keys(tmp_path):
    """The writers and the types cannot drift: each record is checked against the
    required/optional keys of the TypedDict for its kind."""
    g = _gov(tmp_path)
    _exercise(g)
    records = _lines(tmp_path)
    assert records

    problems = []
    for record in records:
        kind = _kind(record)
        typed = KINDS.get(kind)
        if typed is None and kind is not None:
            problems.append(f"unknown record kind {kind!r}")
            continue
        keys = set(record)
        missing = typed.__required_keys__ - keys
        extra = keys - typed.__required_keys__ - typed.__optional_keys__
        if missing:
            problems.append(f"{kind or 'decision'}: missing {sorted(missing)}")
        if extra:
            problems.append(f"{kind or 'decision'}: field the TypedDict does not name {sorted(extra)}")
    assert not problems, "; ".join(problems)


def test_the_typed_dicts_match_the_documented_field_tables():
    """The field table in the docs, the TypedDicts, and the TypeScript union all
    name the same fields. Changing one without the others fails here."""
    for kind, (required, optional) in FIELDS.items():
        typed = KINDS[kind]
        assert set(typed.__required_keys__) == required, kind
        assert set(typed.__optional_keys__) == optional, kind
    # Every kind carries the common fields.
    for typed in KINDS.values():
        assert set(AuditRecordBase.__required_keys__) <= set(typed.__required_keys__)
    # `AuditRecord` is exactly these five kinds.
    assert set(AuditRecord.__args__) == set(KINDS.values())


def test_all_five_kinds_are_written_and_event_is_the_discriminant(tmp_path):
    g = _gov(tmp_path)
    _exercise(g)
    records = _lines(tmp_path)
    assert {_kind(r) for r in records} == set(KINDS)
    for record in records:
        if _kind(record) is None:
            assert "event" not in record
        else:
            assert record["event"] == _kind(record)


def test_the_conditional_fields_really_do_appear(tmp_path):
    """Otherwise the key check above is vacuous — an optional field nothing ever
    writes proves nothing."""
    g = _gov(tmp_path)
    d = _exercise(g)
    records = _lines(tmp_path)

    # actor_chain: only through a delegate, and only when the chain is longer
    # than one name.
    assert any(r.get("actor_chain") == ["record-agent", "sub-agent"] for r in records)
    assert any(r["agent"] == "record-agent" and "actor_chain" not in r for r in records)

    # sanitization / screening: the caller's principal and the joining id.
    sanitization = next(r for r in records if _kind(r) == "sanitization")
    screening = next(r for r in records if _kind(r) == "screening")
    assert sanitization["principal"] == ALICE and sanitization["decision_id"] == d["decision_id"]
    assert screening["principal"] == ALICE and screening["decision_id"] == d["decision_id"]

    # decision: an approved action is a hold, then an Allow carrying approved.
    decisions = [r for r in records if _kind(r) is None]
    assert any(r["decision"] == "NeedsApproval" and "approved" not in r for r in decisions)
    assert any(r["decision"] == "Allow" and r.get("approved") is True for r in decisions)
    assert any(r["decision"] == "Deny" for r in decisions)

    # egress: replaced, and withheld only when the hook refused.
    egress = [r for r in records if _kind(r) == "egress"]
    assert any(r["replaced"] is True and "withheld" not in r for r in egress)
    assert any(r["replaced"] is False and r.get("withheld") is True for r in egress)

    # attenuation: a parent-less root, a child, and a refusal with a reason.
    tree = [r for r in records if _kind(r) == "attenuation"]
    assert any(r["depth"] == 0 and "parent_id" not in r and r["decision"] == "Allow" for r in tree)
    assert any(r.get("parent_id") and r["decision"] == "Allow" for r in tree)
    assert any(r["decision"] == "Deny" and isinstance(r.get("reason"), str) for r in tree)
    # …and unlike every other kind it names no subject and rides no chain.
    assert all("principal" not in r and "actor_chain" not in r for r in tree)
    assert all(r["intent"] == "attenuate" for r in tree)


def test_the_closed_vocabularies_hold(tmp_path):
    """The `Literal` types are claims about the values that land in the trail."""
    g = _gov(tmp_path)
    _exercise(g)
    records = _lines(tmp_path)
    for record in records:
        kind = _kind(record)
        if kind is None:
            assert record["decision"] in ("Allow", "Deny", "NeedsApproval")
            assert record.get("approved", True) is True
        elif kind == "attenuation":
            assert record["decision"] in ("Allow", "Deny")
            assert record["intent"] == "attenuate"
        elif kind == "screening":
            assert record["mode"] in ("report", "redact")
            assert record["flagged"] is (record["total"] > 0)
        elif kind == "sanitization":
            assert record["mode"] in ("tag", "mask", "hash")
        elif kind == "egress":
            assert isinstance(record["replaced"], bool)
            assert record.get("withheld", True) is True


def test_a_governor_always_names_the_subject_of_a_sanitization(tmp_path):
    """`principal` is optional on the TypedDict because the writer emits it only
    when the report carries one — but a governor always resolves one, so in
    practice both kinds carry it, typed, even with no decision to join to."""
    g = _gov(tmp_path)
    g.sanitize(SAMPLE)
    g.screen(INJECTION)
    records = _lines(tmp_path)
    sanitization = next(r for r in records if _kind(r) == "sanitization")
    screening = next(r for r in records if _kind(r) == "screening")
    assert sanitization["principal"] == 'Agent::"record-agent"'
    assert screening["principal"] == 'Agent::"record-agent"'
    assert "decision_id" not in sanitization and "decision_id" not in screening


def test_the_untyped_sink_still_works(tmp_path):
    """The escape hatch: a sink written against the plain dict it has always been
    handed keeps working, unchanged, and sees the same fields as the file."""
    seen: list = []

    def legacy_sink(record: UnknownAuditRecord) -> None:
        seen.append(dict(record))

    g = _gov(tmp_path, sink=legacy_sink)
    _exercise(g)
    assert seen == _lines(tmp_path)
    # And a sink may still read whatever key it likes off the record it is given.
    assert all(record.get("event", "decision") for record in seen)


def test_a_typed_sink_narrows_on_the_kind(tmp_path):
    """The typed happy path: a sink dispatches on `event` and reads each kind's
    fields by name. The `AuditRecord` annotation is accepted where the SDK asks
    for an `AuditSink`."""
    rows: list = []

    def typed_sink(record: AuditRecord) -> None:
        kind = record.get("event")
        if kind is None:
            rows.append(("decision", record["principal"], record["decision"]))
        elif kind == "sanitization":
            rows.append(("sanitization", record["mode"], record["total"]))
        elif kind == "screening":
            rows.append(("screening", record["mode"], record["flagged"]))
        elif kind == "egress":
            rows.append(("egress", record["principal"], record["replaced"]))
        elif kind == "attenuation":
            rows.append(("attenuation", record["node_id"], record["depth"]))
        else:  # a sixth kind: forward it whole rather than guessing
            rows.append(("unknown", kind, None))

    sink: AuditSink = typed_sink
    g = _gov(tmp_path, sink=sink)
    _exercise(g)
    assert len(rows) == len(_lines(tmp_path))
    assert {row[0] for row in rows} == {"decision", "sanitization", "screening", "egress", "attenuation"}
