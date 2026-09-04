"""Governed action gate + sanitize (Python), mirroring the TS suite.

Runtime context, per-call principal, correlation id, three-state
Allow/Deny/NeedsApproval verdict + single-use HITL token, and value-free audit.
Runs the real watchlight_engine.
"""
import json

import pytest

from watchlight import DECISION_ID_MAX_LENGTH, Denied, NeedsApproval, SanitizeError, Watchlight, sanitize

FUNDED = 'permit(principal, action == Action::"book", resource) when { context.amount <= context.limit };'
ALICE = 'permit(principal == User::"alice", action == Action::"pay", resource);'
WIRE = '@enforcement_effect("require_approval")\npermit(principal, action == Action::"wire", resource) when { context.amount > 1000 };'


def _gov(tmp_path):
    g = Watchlight(agent="booking-agent", audit_dir=str(tmp_path))
    g.allow(FUNDED, "funded")
    g.allow(ALICE, "alice")
    g.allow(WIRE, "wire")
    return g


def test_runtime_context(tmp_path):
    g = _gov(tmp_path)
    ran = {"n": 0}

    @g.tool("book", context=lambda order: {"amount": order["amount"], "limit": 100})
    def book(order):
        ran["n"] += 1
        return "booked " + order["id"]

    assert book({"id": "t1", "amount": 50}) == "booked t1"
    with pytest.raises(Denied):
        book({"id": "t2", "amount": 200})
    assert ran["n"] == 1  # denied body never ran


def test_per_call_principal(tmp_path):
    g = _gov(tmp_path)

    @g.tool("pay", principal=lambda req: f'User::"{req["user"]}"')
    def pay(req):
        return "paid"

    assert pay({"user": "alice"}) == "paid"
    with pytest.raises(Denied):
        pay({"user": "bob"})


def test_correlation_id(tmp_path):
    g = _gov(tmp_path)
    r = g.authorize(action="book", resource="trip/9", context={"amount": 1, "limit": 100})
    assert r["decision"] == "Allow" and isinstance(r["decision_id"], str) and r["decision_id"]


def test_three_state_and_hitl_token(tmp_path):
    g = _gov(tmp_path)
    w = g.authorize(action="wire", resource="acct/1", context={"amount": 5000})
    assert w["decision"] == "NeedsApproval" and not w["allowed"]

    tok = g.mint_approval(action="wire", resource="acct/1")
    ap = g.authorize(action="wire", resource="acct/1", context={"amount": 5000}, approval=tok)
    assert ap["decision"] == "Allow" and ap["approved"]
    # single-use
    assert g.authorize(action="wire", resource="acct/1", context={"amount": 5000}, approval=tok)["decision"] == "NeedsApproval"
    # bound to resource
    wrong = g.mint_approval(action="wire", resource="acct/other")
    assert g.authorize(action="wire", resource="acct/1", context={"amount": 5000}, approval=wrong)["decision"] == "NeedsApproval"


def test_on_needs_approval_hook(tmp_path):
    g = _gov(tmp_path)
    ran = {"n": 0}

    @g.tool("wire", resource=lambda r: f'acct/{r["to"]}', context=lambda r: {"amount": r["amount"]}, on_needs_approval=lambda d: True)
    def wire_yes(r):
        ran["n"] += 1
        return "wired"

    assert wire_yes({"to": "z", "amount": 5000}) == "wired" and ran["n"] == 1

    @g.tool("wire", resource=lambda r: f'acct/{r["to"]}', context=lambda r: {"amount": r["amount"]}, on_needs_approval=lambda d: False)
    def wire_no(r):
        ran["n"] += 1
        return "x"

    with pytest.raises(NeedsApproval):
        wire_no({"to": "y", "amount": 5000})
    assert ran["n"] == 1  # declined body never ran


def test_deny_reason_is_opaque(tmp_path):
    """SECURITY: the caller-facing deny reason is uniform and non-revealing. It
    must never disclose WHY a request was denied — a failed condition and a
    missing policy report the IDENTICAL string, so a caller probing the
    authorization boundary learns nothing to tune an attack against."""
    g = _gov(tmp_path)
    over_limit = g.authorize(action="book", resource="trip/9", context={"amount": 999, "limit": 100})
    no_policy = g.authorize(action="delete", resource="trip/9")
    assert over_limit["decision"] == "Deny" and no_policy["decision"] == "Deny"
    assert over_limit["reason"] == no_policy["reason"] == "not authorized"

    @g.tool("delete")
    def delete_it():  # pragma: no cover - body must never run
        return "gone"

    with pytest.raises(Denied) as ei:
        delete_it()
    assert ei.value.reason == "not authorized"
    # no cause-revealing phrasing leaks through the exception text
    for leak in ("no matching policy", "Policy evaluation completed", "forbid", "condition"):
        assert leak not in str(ei.value)


def test_sanitize(tmp_path):
    g = _gov(tmp_path)
    s = g.sanitize("email a@b.com card 4111 1111 1111 1111 ssn 123-45-6789", resource="statement.pdf")
    assert s["report"]["counts"].get("EMAIL") == 1
    assert s["report"]["counts"].get("CREDIT_CARD") == 1
    assert "a@b.com" not in s["text"] and "123-45-6789" not in s["text"]
    # pure function + fail-closed
    with pytest.raises(Exception):
        sanitize(12345)  # non-string


def test_sanitize_correlates_with_decision(tmp_path):
    """A read governed by authorize, then sanitize(decision_id=...), yields two
    audit lines that join on the same decision_id."""
    g = _gov(tmp_path)
    g.allow('permit(principal, action == Action::"read", resource);', "read")
    decision = g.authorize(action="read", resource="statement.pdf")
    assert decision["decision"] == "Allow" and decision["decision_id"]
    s = g.sanitize("email a@b.com", resource="statement.pdf", decision_id=decision["decision_id"])
    assert s["report"]["decision_id"] == decision["decision_id"]
    lines = [json.loads(l) for l in (tmp_path / "audit.jsonl").read_text().splitlines()]
    auth_line = next(l for l in lines if l.get("decision") == "Allow" and "event" not in l)
    san_line = next(l for l in lines if l.get("event") == "sanitization")
    assert auth_line["decision_id"] == san_line["decision_id"] == decision["decision_id"]
    # existing sanitization fields are untouched; still value-free
    assert san_line["mode"] == "tag" and san_line["detector"] and san_line["counts"]["EMAIL"] == 1
    assert "a@b.com" not in json.dumps(lines)
    # no decision_id on the report or the audit line when none is supplied
    g.sanitize("x a@b.com", resource="doc")
    last = json.loads((tmp_path / "audit.jsonl").read_text().splitlines()[-1])
    assert "decision_id" not in last and "decision_id" not in sanitize("a@b.com")["report"]


def test_sanitize_rejects_malformed_decision_id(tmp_path):
    """decision_id is opaque but bounded: no control characters (audit-line
    injection), capped length, str only. Fail-closed — nothing is written."""
    g = Watchlight(agent="doc-agent", audit_dir=str(tmp_path))
    for bad in ('dec-1\n{"decision": "Allow"}', "dec\x00id", "dec\x7fid", "dec\x85id", "dec\u2028id", "dec\u2029id", "", 42, {},
                "x" * (DECISION_ID_MAX_LENGTH + 1)):
        with pytest.raises(SanitizeError):
            sanitize("a@b.com", decision_id=bad)
        with pytest.raises(SanitizeError):
            g.sanitize("a@b.com", decision_id=bad)
    assert not (tmp_path / "audit.jsonl").exists()
    assert sanitize("a@b.com", decision_id="x" * DECISION_ID_MAX_LENGTH)["report"]["decision_id"]


def test_audit_value_free_with_correlation(tmp_path):
    g = _gov(tmp_path)
    g.authorize(action="pay", principal='User::"alice"', resource="acct/1")
    tok = g.mint_approval(action="wire", resource="acct/1")
    g.authorize(action="wire", resource="acct/1", context={"amount": 5000}, approval=tok)
    g.sanitize("x a@b.com", resource="doc")
    raw = (tmp_path / "audit.jsonl").read_text()
    assert '"decision_id"' in raw
    assert '"principal": "User::\\"alice\\""' in raw
    assert '"approved": true' in raw
    assert '"event": "sanitization"' in raw
    # value-free: no context amounts / PII values in the trail
    assert "5000" not in raw and "a@b.com" not in raw and "4111" not in raw
