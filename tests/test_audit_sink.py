"""``audit_sink`` (Python), mirroring the TS suite.

Every record kind — decision, approved decision, sanitization, attenuation
Allow/Deny — reaches the sink with EXACTLY the fields the ``audit.jsonl`` line
carries; the sink gets its own copy and can't alter the file; a raising sink, a
failing async sink, and an async sink with no event loop never change a decision
and are reported once; a slow async sink never delays ``authorize``
(fire-and-forget). Runs the real ``watchlight_engine``.
"""
import asyncio
import json
import time
import warnings

import pytest

pytest.importorskip("watchlight_engine")

from watchlight import AttenuationDenied, DE_MAX_DEPTH, DevEditionCeiling, Watchlight

RESEARCH = 'permit(principal, action == Action::"research", resource);'
WIRE = '@enforcement_effect("require_approval")\npermit(principal, action == Action::"wire", resource);'
SAMPLE = "mail a@b.com card 4111 1111 1111 1111"
WARNING = "audit sink failed"


def _gov(tmp_path, sink=None):
    g = Watchlight(agent="sink-agent", audit_dir=str(tmp_path / ".watchlight"), audit_sink=sink)
    g.allow(RESEARCH, "research").allow(WIRE, "wire")
    return g


def _lines(tmp_path):
    text = (tmp_path / ".watchlight" / "audit.jsonl").read_text()
    return [json.loads(line) for line in text.splitlines()]


def _shape(r):
    """Everything about a record except the per-run ids/timestamps."""
    return (r.get("event", "decision"), r["intent"], r["resource"], r.get("decision"), r.get("approved", False), r.get("depth"))


def _exercise(g):
    """Drive every audit-producing path once; return the decision outcomes."""
    allow = g.authorize(action="research", resource="tool/web_search")
    deny = g.authorize(action="transfer", resource="tool/transfer", context={"amount": 1000})
    held = g.authorize(action="wire", resource="acct/1")
    token = g.mint_approval(action="wire", resource="acct/1")
    approved = g.authorize(action="wire", resource="acct/1", approval=token)

    @g.tool("research")
    def web_search(q):
        return f"r:{q}"

    web_search("cedar policies")
    g.sanitize(SAMPLE, resource="doc.txt")
    root = g.scope(tools=["read", "write"])
    child = root.attenuate(tools=["read"])
    with pytest.raises(AttenuationDenied):
        root.attenuate(tools=["read", "delete"])
    s = child
    for _ in range(child.depth, DE_MAX_DEPTH):
        s = s.attenuate(tools=["read"])
    with pytest.raises(DevEditionCeiling):
        s.attenuate(tools=["read"])
    return [allow["decision"], deny["decision"], held["decision"], approved["decision"], approved["approved"]]


def test_every_record_kind_reaches_the_sink_with_identical_fields(tmp_path):
    seen = []
    g = _gov(tmp_path, sink=seen.append)
    _exercise(g)
    file = _lines(tmp_path)
    assert seen == file, "sink must see every file line, same order, same fields"
    assert any("event" not in r and r["decision"] == "Allow" for r in seen)
    assert any("event" not in r and r["decision"] == "Deny" for r in seen)
    assert any(r["decision"] == "NeedsApproval" for r in seen)
    assert any(r.get("approved") is True and r["decision"] == "Allow" for r in seen)
    assert any(r.get("event") == "sanitization" and r["counts"]["EMAIL"] == 1 for r in seen)
    assert any(r.get("event") == "attenuation" and r["decision"] == "Allow" and r["resource"] == "root scope" for r in seen)
    assert sum(1 for r in seen if r.get("event") == "attenuation" and r["decision"] == "Deny" and r.get("reason")) == 2
    blob = json.dumps(seen)
    assert "a@b.com" not in blob and "4111" not in blob and "cedar policies" not in blob  # value-free


def test_sink_receives_a_copy_and_cannot_alter_the_file(tmp_path):
    def sink(rec):
        rec["decision"] = "Allow"
        rec["injected"] = True
        if "counts" in rec:
            rec["counts"].clear()

    g = _gov(tmp_path, sink=sink)
    _exercise(g)
    file = _lines(tmp_path)
    assert any(r["decision"] == "Deny" for r in file)
    assert not any("injected" in r for r in file)
    assert any(r.get("event") == "sanitization" and r["counts"]["EMAIL"] == 1 for r in file)


def test_raising_sink_changes_nothing_and_warns_once(tmp_path, capsys):
    control = _exercise(_gov(tmp_path / "control"))
    control_shapes = [_shape(r) for r in _lines(tmp_path / "control")]
    calls = {"n": 0}

    def sink(rec):
        calls["n"] += 1
        raise ValueError("sink down: tool/web_search")

    results = _exercise(_gov(tmp_path / "sink", sink=sink))
    assert results == control
    assert [_shape(r) for r in _lines(tmp_path / "sink")] == control_shapes
    assert calls["n"] == len(control_shapes), "the sink is still invoked for every record"
    err = capsys.readouterr().err
    assert err.count(WARNING) == 1
    assert "ValueError" in err
    assert "web_search" not in err and "sink down" not in err  # error type only, never content


def test_failing_async_sink_in_a_running_loop_changes_nothing_and_warns_once(tmp_path, capsys):
    control = _exercise(_gov(tmp_path / "control"))
    seen = []

    async def sink(rec):
        seen.append(rec)
        raise TypeError("nope")

    async def main():
        g = _gov(tmp_path / "sink", sink=sink)
        results = _exercise(g)
        for _ in range(3):  # let the scheduled sink tasks run and fail
            await asyncio.sleep(0)
        return results

    results = asyncio.run(main())
    assert results == control
    assert seen == _lines(tmp_path / "sink"), "every record delivered before the failure"
    err = capsys.readouterr().err
    assert err.count(WARNING) == 1 and "TypeError" in err


def test_async_sink_without_an_event_loop_is_dropped_with_one_warning(tmp_path, capsys):
    async def sink(rec):  # pragma: no cover — never runs: there is no loop
        pass

    g = _gov(tmp_path, sink=sink)
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        r1 = g.authorize(action="research", resource="tool/web_search")
        r2 = g.authorize(action="transfer", resource="tool/transfer")
    assert r1["decision"] == "Allow" and r2["decision"] == "Deny"
    assert len(_lines(tmp_path)) == 2, "the file is still written"
    assert not [w for w in caught if "never awaited" in str(w.message)], "coroutine is closed cleanly"
    err = capsys.readouterr().err
    assert err.count(WARNING) == 1 and "RuntimeError" in err


def test_slow_async_sink_never_delays_authorize(tmp_path):
    async def sink(rec):
        await asyncio.sleep(10)

    async def main():
        g = _gov(tmp_path, sink=sink)
        t0 = time.monotonic()
        r = g.authorize(action="research", resource="tool/web_search")
        return r["decision"], time.monotonic() - t0

    decision, elapsed = asyncio.run(main())  # asyncio.run cancels the pending sink task
    assert decision == "Allow"
    assert elapsed < 2.0


def test_spoofed_exception_class_name_never_reaches_the_warning(tmp_path, capsys):
    """The class name is sink-controlled text: a name carrying record content is
    replaced by the literal ``Error``."""
    def sink(rec):
        # Identifier-shaped, so a pure isidentifier() filter would let it through.
        leak = type("LEAK_" + rec["intent"] + "_" + rec["resource"].replace("/", "_"), (Exception,), {})
        raise leak()

    g = _gov(tmp_path, sink=sink)
    g.authorize(action="research", resource="tool/web_search")
    err = capsys.readouterr().err
    assert err.count(WARNING) == 1
    assert "(Error)" in err
    assert "LEAK" not in err and "web_search" not in err and "research" not in err

    # A non-identifier spoof (the review probe) is replaced the same way.
    def sink2(rec):
        raise type("LEAK_ssn_123", (Exception,), {"__module__": "LEAK.mod " + rec["intent"]})()

    g2 = _gov(tmp_path / "b", sink=sink2)
    g2.authorize(action="research", resource="tool/web_search")
    err = capsys.readouterr().err
    assert "(Error)" in err and "LEAK" not in err and "research" not in err


def test_warning_is_once_per_error_kind_not_per_governor(tmp_path, capsys):
    kinds = iter([ValueError, ValueError, KeyError])

    def sink(rec):
        raise next(kinds)()

    g = _gov(tmp_path, sink=sink)
    for _ in range(3):
        g.authorize(action="research", resource="tool/web_search")
    err = capsys.readouterr().err
    assert err.count(WARNING) == 2 and "ValueError" in err and "KeyError" in err


def test_no_loop_warning_does_not_silence_a_later_real_failure(tmp_path, capsys):
    async def async_sink(rec):
        pass

    trail_holder = {}

    def sink(rec):
        if not trail_holder:
            trail_holder["once"] = True
            return async_sink(rec)  # no loop → RuntimeError kind
        raise ValueError("real failure")

    g = _gov(tmp_path, sink=sink)
    g.authorize(action="research", resource="tool/web_search")
    g.authorize(action="research", resource="tool/web_search")
    err = capsys.readouterr().err
    assert "RuntimeError" in err and "ValueError" in err and err.count(WARNING) == 2


def test_funnel_never_raises_on_an_unserializable_record(tmp_path):
    from watchlight._audit import AuditTrail

    seen = []
    trail = AuditTrail(tmp_path / "audit.jsonl", sink=seen.append)
    trail.write({"ts": "x", "bad": object()})  # must not raise; nothing to write or send
    assert not (tmp_path / "audit.jsonl").exists() and seen == []


def test_inflight_async_sink_task_is_held_strongly(tmp_path):
    import gc

    delivered = []

    async def sink(rec):
        await asyncio.sleep(0.01)
        delivered.append(rec)

    async def main():
        g = _gov(tmp_path, sink=sink)
        g.authorize(action="research", resource="tool/web_search")
        assert len(g._trail._tasks) == 1
        gc.collect()
        await asyncio.sleep(0.05)
        assert len(g._trail._tasks) == 0

    asyncio.run(main())
    assert len(delivered) == 1 and delivered[0]["intent"] == "research"


def test_egress_and_sanitize_decision_id_flow_through_the_sink(tmp_path):
    seen = []
    g = _gov(tmp_path, sink=seen.append)

    @g.tool("research", on_result=lambda out, info: out.upper())
    def fetch_doc(doc_id):
        return f"doc {doc_id}"

    def block(out, info):
        raise RuntimeError("egress blocked")

    @g.tool("research", on_result=block)
    def withheld():
        return "secret"

    fetch_doc("42")
    with pytest.raises(RuntimeError):
        withheld()
    d = g.authorize(action="research", resource="doc.txt")
    g.sanitize(SAMPLE, resource="doc.txt", decision_id=d["decision_id"])
    file = _lines(tmp_path)
    assert seen == file
    egress = [r for r in seen if r.get("event") == "egress"]
    assert len(egress) == 2 and egress[0]["replaced"] is True and egress[1].get("withheld") is True
    assert all(isinstance(r.get("decision_id"), str) for r in egress)
    assert "DOC 42" not in json.dumps(egress) and "secret" not in json.dumps(egress)
    san = next(r for r in seen if r.get("event") == "sanitization")
    assert isinstance(d["decision_id"], str) and san["decision_id"] == d["decision_id"]
