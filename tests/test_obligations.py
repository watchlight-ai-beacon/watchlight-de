"""Obligations on verdicts (Python), mirroring the TS suite.

A permit annotated ``@obligate_redact("ssn")`` / ``@obligate_max_items("8")`` /
``@obligate_log_values("false")`` / ``@obligate_<name>("raw")`` surfaces as
``result["obligations"]`` on an Allow.

The derivation is exercised from STUBBED decision payloads — the shared
``tests/fixtures/obligations.json``, consumed byte-for-byte by the TS suite too —
so it does not depend on the installed engine version: the end-to-end path swaps
the governor's engine for a stub that returns those payloads. A final
live-engine probe asserts the real thing when the installed ``watchlight_engine``
emits the field, and skips when it predates it.
"""
import json
import os
import pathlib
import subprocess
import sys

import pytest

from watchlight import Watchlight, run_policy_tests
from watchlight import _derive_obligations
from watchlight.policytest import normalize_expected_obligations

FIXTURE = json.loads((pathlib.Path(__file__).parent / "fixtures" / "obligations.json").read_text())


def _canon(v):
    return json.dumps(v, sort_keys=True, separators=(",", ":"))


def _wire(o):
    """Sort ``redact`` (the merge is a set union) so both lanes compare the same string."""
    if not o:
        return None
    w = dict(o)
    if "redact" in w:
        w["redact"] = sorted(w["redact"])
    return w


@pytest.mark.parametrize("case", FIXTURE["cases"], ids=[c["name"] for c in FIXTURE["cases"]])
def test_shared_fixture_derivation_is_byte_identical(case):
    assert _canon(_wire(_derive_obligations(case["details"]))) == _canon(case["expected"])


class _StubEngine:
    """Answers ``authorize`` with the fixture payload selected by the action."""

    def __init__(self, by_action):
        self.by_action = by_action

    def authorize(self, request_json):
        action = json.loads(request_json)["action"]
        return json.dumps(self.by_action[action])


def _stubbed(tmp_path):
    g = Watchlight(agent="oblig-agent", audit_dir=str(tmp_path))
    stubs = FIXTURE["stub_decisions"]
    g._engine = _StubEngine({
        "allow": stubs["allow_with_obligations"],
        "deny": stubs["deny_with_stray_obligations"],
        "hold": stubs["needs_approval_with_obligations"],
    })
    return g


def test_allow_carries_obligations_and_extra_passes_through(tmp_path):
    a = _stubbed(tmp_path).authorize(action="allow", resource="doc/1")
    assert a["decision"] == "Allow"
    assert a["obligations"] == {"redact": ["ssn"], "extra": {"ttl": "30"}}


def test_deny_never_carries_obligations(tmp_path):
    d = _stubbed(tmp_path).authorize(action="deny", resource="doc/1")
    assert d["decision"] == "Deny" and "obligations" not in d


def test_needs_approval_never_carries_obligations_but_the_approved_allow_does(tmp_path):
    g = _stubbed(tmp_path)
    h = g.authorize(action="hold", resource="doc/1")
    assert h["decision"] == "NeedsApproval" and "obligations" not in h
    token = g.mint_approval(action="hold", resource="doc/1")
    ap = g.authorize(action="hold", resource="doc/1", approval=token)
    assert ap["decision"] == "Allow" and ap["approved"] is True
    assert ap["obligations"] == {"redact": ["ssn"], "max_items": 4}


def test_on_result_can_honour_a_redact_obligation(tmp_path):
    g = _stubbed(tmp_path)

    def redact_if_obliged(text, info):
        again = g.authorize(action="allow", resource=info["resource"])
        if "ssn" in (again.get("obligations") or {}).get("redact", []):
            return g.sanitize(text, resource=info["resource"], types=["SSN"])["text"]
        return text

    @g.tool("allow", resource=lambda doc_id: f"doc/{doc_id}", on_result=redact_if_obliged)
    def read_doc(doc_id):
        return f"SSN 123-45-6789 for {doc_id}"

    out = read_doc("7")
    assert "<SSN_1>" in out and "123-45-6789" not in out


def test_govern_test_asserts_obligations_end_to_end(tmp_path):
    report = _stubbed(tmp_path).test([
        {"name": "redact ssn", "action": "allow", "resource": "doc/1", "expect": "Allow",
         "obligations": {"redact": ["ssn"], "extra": {"ttl": "30"}}},
        {"name": "deny carries none", "action": "deny", "resource": "doc/1", "expect": "Deny"},
        {"name": "hold carries none", "action": "hold", "resource": "doc/1", "expect": "NeedsApproval", "obligations": {}},
        {"name": "approved carries them (camelCase spelling)", "action": "hold", "resource": "doc/1",
         "approved": True, "expect": "Allow", "obligations": {"redact": ["ssn"], "maxItems": 4}},
    ])
    assert report["failed"] == 0, [r for r in report["results"] if not r["ok"]]
    first = report["results"][0]
    assert first["obligations"]["redact"] == ["ssn"] and first["expected_obligations"]["redact"] == ["ssn"]


# ── run_policy_tests with a pure stub decide ─────────────────────────────

ALLOW_SSN = {"redact": ["ssn", "dob"], "max_items": 8, "log_values": False, "extra": {"ttl": "30"}}


def _decide_with(obligations):
    def decide(**_):
        d = {"decision": "Allow", "reason": ""}
        if obligations is not None:
            d["obligations"] = obligations
        return d
    return decide


def _mint(**_):
    return "tok"


def _run(decide, case):
    return run_policy_tests(decide, _mint, [dict(action="x", **case)])


def test_exact_match_passes_and_redact_is_order_insensitive():
    r = _run(_decide_with(ALLOW_SSN), {"expect": "Allow", "obligations": {
        "redact": ["dob", "ssn"], "max_items": 8, "log_values": False, "extra": {"ttl": "30"}}})
    assert r["failed"] == 0, r


def test_camel_case_spellings_are_accepted():
    r = _run(_decide_with(ALLOW_SSN), {"expect": "Allow", "obligations": {
        "redact": ["dob", "ssn"], "maxItems": 8, "logValues": False, "extra": {"ttl": "30"}}})
    assert r["failed"] == 0, r


def test_subset_expectation_fails_exact_match():
    r = _run(_decide_with(ALLOW_SSN), {"expect": "Allow", "obligations": {"redact": ["ssn"]}})
    assert r["failed"] == 1 and r["results"][0]["actual"] == "Allow"


def test_differing_extra_value_fails():
    r = _run(_decide_with(ALLOW_SSN), {"expect": "Allow", "obligations": {
        "redact": ["dob", "ssn"], "max_items": 8, "log_values": False, "extra": {"ttl": "60"}}})
    assert r["failed"] == 1


def test_no_expectation_means_no_comparison_but_actual_is_reported():
    r = _run(_decide_with(ALLOW_SSN), {"expect": "Allow"})
    assert r["failed"] == 0 and r["results"][0]["obligations"]["max_items"] == 8
    assert "expected_obligations" not in r["results"][0]


def test_empty_expectation_asserts_none():
    assert _run(_decide_with(ALLOW_SSN), {"expect": "Allow", "obligations": {}})["failed"] == 1
    assert _run(_decide_with(None), {"expect": "Allow", "obligations": {}})["failed"] == 0
    deny = lambda **_: {"decision": "Deny", "reason": "not authorized"}
    assert _run(deny, {"expect": "Deny", "obligations": {}})["failed"] == 0


def test_expected_but_absent_fails():
    assert _run(_decide_with(None), {"expect": "Allow", "obligations": {"redact": ["ssn"]}})["failed"] == 1


@pytest.mark.parametrize("obligations, match", [
    ("ssn", "must be an object"),
    ({"redakt": ["ssn"]}, "unknown obligations key 'redakt'"),
    ({"redact": []}, "redact"),
    ({"redact": ["ssn", " "]}, "redact"),
    ({"redact": [1]}, "redact"),
    ({"maxItems": 0}, "maxItems"),
    ({"max_items": "8"}, "maxItems"),
    ({"max_items": True}, "maxItems"),
    ({"logValues": "false"}, "logValues"),
    ({"maxItems": 8, "max_items": 3}, "disagree"),
    ({"extra": {"ttl": 30}}, "extra"),
    ({"extra": ["ttl"]}, "extra"),
])
def test_malformed_expectation_raises(obligations, match):
    with pytest.raises(ValueError, match=match):
        _run(_decide_with(ALLOW_SSN), {"expect": "Allow", "obligations": obligations})


def test_non_empty_obligations_on_a_non_allow_expectation_raises():
    with pytest.raises(ValueError, match="only be expected on an Allow"):
        _run(_decide_with(ALLOW_SSN), {"expect": "Deny", "obligations": {"redact": ["ssn"]}})
    with pytest.raises(ValueError, match="only be expected on an Allow"):
        _run(_decide_with(ALLOW_SSN), {"expect": "NeedsApproval", "obligations": {"max_items": 1}})


def test_normalize_expected_obligations_canonicalizes_to_wire_spelling():
    assert normalize_expected_obligations(
        {"redact": [" ssn ", "ssn"], "maxItems": 2, "logValues": True, "extra": {}}, "f"
    ) == {"redact": ["ssn"], "max_items": 2, "log_values": True}


# ── CLI ───────────────────────────────────────────────────────────────────

def _run_cli(suite_path):
    env = dict(os.environ)
    env["PYTHONPATH"] = "src" + os.pathsep + env.get("PYTHONPATH", "")
    env["NO_COLOR"] = "1"
    return subprocess.run(
        [sys.executable, "-m", "watchlight.cli", "policy", "test", str(suite_path)],
        capture_output=True, text=True, env=env,
    )


PLAIN = [{"name": "p", "code": 'permit(principal, action == Action::"read", resource);'}]


def test_cli_malformed_obligations_expectation_exits_two(tmp_path):
    suite = tmp_path / "mal.json"
    suite.write_text(json.dumps({"policies": PLAIN, "tests": [{"action": "read", "expect": "Allow", "obligations": "ssn"}]}))
    r = _run_cli(suite)
    assert r.returncode == 2, r.stdout + r.stderr


def test_cli_reports_an_obligations_mismatch(tmp_path):
    suite = tmp_path / "mismatch.json"
    suite.write_text(json.dumps({"policies": PLAIN, "tests": [
        {"name": "plain permit carries none", "action": "read", "expect": "Allow", "obligations": {"redact": ["ssn"]}}]}))
    r = _run_cli(suite)
    assert r.returncode == 1, r.stdout + r.stderr
    assert "expected obligations" in r.stdout and '"redact"' in r.stdout


# ── live engine ───────────────────────────────────────────────────────────

ANNOTATED = (
    '@obligate_redact("ssn, dob")\n@obligate_max_items("8")\n@obligate_log_values("false")\n'
    '@obligate_retention("30d")\npermit(principal, action == Action::"read", resource);'
)


def test_live_engine_surfaces_obligate_annotations(tmp_path):
    g = Watchlight(agent="oblig-live", audit_dir=str(tmp_path))
    g.allow(ANNOTATED, "annotated")
    r = g.authorize(action="read", resource="doc/1")
    assert r["decision"] == "Allow"
    if "obligations" not in r:
        pytest.skip("installed watchlight_engine reports no obligations field")
    assert sorted(r["obligations"]["redact"]) == ["dob", "ssn"]
    assert r["obligations"]["max_items"] == 8 and r["obligations"]["log_values"] is False
    assert r["obligations"]["extra"] == {"retention": "30d"}
    report = g.test([{"action": "read", "expect": "Allow", "obligations": {
        "redact": ["ssn", "dob"], "max_items": 8, "log_values": False, "extra": {"retention": "30d"}}}])
    assert report["failed"] == 0, report["results"]


def test_live_engine_unannotated_permit_carries_none(tmp_path):
    g = Watchlight(agent="oblig-plain", audit_dir=str(tmp_path))
    g.allow(PLAIN[0]["code"], "plain")
    r = g.authorize(action="read")
    assert r["decision"] == "Allow" and "obligations" not in r
