"""`on_result` egress hook on `@govern.tool` (Python), mirroring the TS suite.

The hook runs AFTER the body returns and BEFORE the result is handed back: a
returned value replaces the payload, ``None`` passes it through, an exception
withholds it (fail-closed). A value-free ``egress`` audit record joins the
decision record on ``decision_id``. Runs the real watchlight_engine.
"""
import asyncio
import json

import pytest

from watchlight import Watchlight

READ = 'permit(principal, action == Action::"read", resource);'
WIRE = '@enforcement_effect("require_approval")\npermit(principal, action == Action::"wire", resource);'


def _gov(tmp_path):
    g = Watchlight(agent="egress-agent", audit_dir=str(tmp_path))
    g.allow(READ, "read")
    g.allow(WIRE, "wire")
    return g


def _records(tmp_path):
    return [json.loads(line) for line in (tmp_path / "audit.jsonl").read_text().splitlines()]


def test_replacement_reaches_caller_and_joins_decision(tmp_path):
    g = _gov(tmp_path)
    seen = []

    @g.tool("read", resource=lambda doc_id: f"doc/{doc_id}",
            on_result=lambda result, info: (seen.append(info), result.replace("SECRET", "<REDACTED>"))[1])
    def read_doc(doc_id):
        return f"SECRET-{doc_id}"

    assert read_doc("7") == "<REDACTED>-7"
    info = seen[0]
    assert info["intent"] == "read" and info["resource"] == "doc/7" and info["principal"] == "egress-agent"
    assert isinstance(info["decision_id"], str) and info["decision_id"]

    recs = _records(tmp_path)
    decision = next(r for r in recs if r.get("resource") == "doc/7" and r.get("decision") == "Allow")
    egress = next(r for r in recs if r.get("event") == "egress" and r.get("resource") == "doc/7")
    assert egress["decision_id"] == decision["decision_id"] == info["decision_id"]
    assert egress["replaced"] is True and "withheld" not in egress
    assert egress["principal"] == "egress-agent" and egress["intent"] == "read"


def test_none_return_passes_payload_through(tmp_path):
    g = _gov(tmp_path)

    @g.tool("read", on_result=lambda result, info: None)
    def plain():
        return "plain"

    assert plain() == "plain"
    egress = next(r for r in _records(tmp_path) if r.get("event") == "egress")
    assert egress["resource"] == "tool/plain" and egress["replaced"] is False and "withheld" not in egress


def test_no_hook_no_egress_record(tmp_path):
    g = _gov(tmp_path)

    @g.tool("read")
    def nohook():
        return "nohook"

    assert nohook() == "nohook"
    assert not any(r.get("event") == "egress" for r in _records(tmp_path))


def test_raising_hook_fails_closed(tmp_path):
    g = _gov(tmp_path)
    ran = {"n": 0}

    def screen(result, info):
        raise RuntimeError("classifier unavailable")

    @g.tool("read", on_result=screen)
    def leaky():
        ran["n"] += 1
        return "RAW-PAYLOAD"

    with pytest.raises(RuntimeError, match="classifier unavailable"):
        leaky()
    assert ran["n"] == 1  # the body ran; its result was withheld, not returned
    egress = next(r for r in _records(tmp_path) if r.get("event") == "egress")
    assert egress["resource"] == "tool/leaky" and egress["replaced"] is False and egress["withheld"] is True
    raw = (tmp_path / "audit.jsonl").read_text()
    assert "RAW-PAYLOAD" not in raw and "classifier" not in raw


def test_approval_path_joins_the_approved_decision(tmp_path):
    g = _gov(tmp_path)
    seen = []

    @g.tool("wire", resource="acct/1", on_needs_approval=lambda d: True,
            on_result=lambda result, info: seen.append(info))
    def wire():
        return "wired"

    assert wire() == "wired"
    recs = _records(tmp_path)
    approved = next(r for r in recs if r.get("resource") == "acct/1" and r.get("approved") is True)
    egress = next(r for r in recs if r.get("event") == "egress" and r.get("resource") == "acct/1")
    assert seen[0]["decision_id"] == approved["decision_id"] == egress["decision_id"]


def test_async_body_and_async_hook(tmp_path):
    g = _gov(tmp_path)

    async def redact(result, info):
        return result.replace("SECRET", "<REDACTED>")

    @g.tool("read", on_result=redact)
    async def fetch():
        return "SECRET-async"

    assert asyncio.run(fetch()) == "<REDACTED>-async"
    egress = next(r for r in _records(tmp_path) if r.get("event") == "egress")
    assert egress["replaced"] is True

    async def boom(result, info):
        raise ValueError("no")

    @g.tool("read", on_result=boom)
    async def fetch2():
        return "RAW"

    with pytest.raises(ValueError):
        asyncio.run(fetch2())
    assert any(r.get("event") == "egress" and r.get("withheld") is True for r in _records(tmp_path))


def test_egress_audit_is_value_free(tmp_path):
    g = _gov(tmp_path)

    @g.tool("read", on_result=lambda result, info: "[replacement-text]")
    def read_it():
        return "ORIGINAL-TEXT"

    assert read_it() == "[replacement-text]"
    raw = (tmp_path / "audit.jsonl").read_text()
    assert "ORIGINAL-TEXT" not in raw and "replacement-text" not in raw
    assert '"event": "egress"' in raw and '"replaced": true' in raw
