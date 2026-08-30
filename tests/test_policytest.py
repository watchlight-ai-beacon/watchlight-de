"""Policy test harness (Python), mirroring the TS suite.

Golden fixtures asserting Allow/Deny/NeedsApproval against the real
watchlight_engine, the audit-free guarantee, and the `watchlight policy test`
CLI. No mocks.
"""
import json
import os
import subprocess
import sys

from watchlight import Watchlight, load_test_suite, run_policy_tests

# A representative money-movement policy set (the Joywend funded-check shape).
POLICIES = [
    {"name": "funded-book",
     "code": 'permit(principal, action == Action::"book", resource) when { context.amount <= context.limit && context.refundable };'},
    {"name": "big-wire-approval",
     "code": '@enforcement_effect("require_approval")\npermit(principal, action == Action::"wire", resource) when { context.amount > 1000 };'},
    {"name": "alice-pays",
     "code": 'permit(principal == User::"alice", action == Action::"pay", resource);'},
]

CASES = [
    {"name": "book under limit + refundable allows", "action": "book",
     "context": {"amount": 200, "limit": 500, "refundable": True}, "expect": "Allow"},
    {"name": "book over limit denies", "action": "book",
     "context": {"amount": 800, "limit": 500, "refundable": True}, "expect": "Deny"},
    {"name": "book non-refundable denies", "action": "book",
     "context": {"amount": 200, "limit": 500, "refundable": False}, "expect": "Deny"},
    {"name": "big wire needs approval", "action": "wire",
     "context": {"amount": 2000}, "expect": "NeedsApproval"},
    {"name": "big wire with human approval allows", "action": "wire",
     "context": {"amount": 2000}, "approved": True, "expect": "Allow"},
    {"name": "small wire denies", "action": "wire",
     "context": {"amount": 500}, "expect": "Deny"},
    {"name": "alice may pay", "action": "pay", "principal": 'User::"alice"', "expect": "Allow"},
    {"name": "bob may not pay", "action": "pay", "principal": 'User::"bob"', "expect": "Deny"},
]


def _gov(tmp_path):
    g = Watchlight(agent="policy-test", audit_dir=str(tmp_path))
    for p in POLICIES:
        g.allow(p["code"], p["name"])
    return g


def test_all_fixtures_pass_against_real_engine(tmp_path):
    report = _gov(tmp_path).test(CASES)
    failures = [r for r in report["results"] if not r["ok"]]
    assert report["failed"] == 0, failures
    assert report["total"] == len(CASES)
    assert report["passed"] + report["failed"] == report["total"]


def test_wrong_expectation_is_reported_as_failure(tmp_path):
    bad = _gov(tmp_path).test([
        {"name": "deny expected but allows", "action": "book",
         "context": {"amount": 10, "limit": 500, "refundable": True}, "expect": "Deny"},
    ])
    assert bad["failed"] == 1
    assert bad["results"][0]["ok"] is False
    assert bad["results"][0]["actual"] == "Allow"


def test_test_does_not_write_audit_trail(tmp_path):
    g = _gov(tmp_path)
    g.test(CASES)
    audit = tmp_path / "audit.jsonl"
    assert not audit.exists()
    # sanity: a real authorize() DOES write, proving the path is wired
    g.authorize(action="pay", principal='User::"alice"')
    assert audit.exists()


def test_case_insensitive_expectations(tmp_path):
    report = _gov(tmp_path).test([
        {"action": "pay", "principal": 'User::"alice"', "expect": "allow"},
        {"action": "pay", "principal": 'User::"bob"', "expect": "DENY"},
    ])
    assert report["failed"] == 0


def test_load_test_suite_shapes(tmp_path):
    # object form with camelCase policyFile
    obj = tmp_path / "suite.json"
    obj.write_text(json.dumps({"policyFile": "p.json", "tests": [{"action": "x", "expect": "Deny"}]}))
    s = load_test_suite(obj)
    assert s["policy_file"] == "p.json" and len(s["tests"]) == 1
    # bare-array form
    arr = tmp_path / "arr.json"
    arr.write_text(json.dumps([{"action": "x", "expect": "Deny"}]))
    assert len(load_test_suite(arr)["tests"]) == 1


def _cli_env(**extra):
    env = dict(os.environ)
    env["PYTHONPATH"] = "src" + os.pathsep + env.get("PYTHONPATH", "")
    env.update(extra)
    return env


def _run_cli(suite_path):
    return subprocess.run(
        [sys.executable, "-m", "watchlight.cli", "policy", "test", str(suite_path)],
        capture_output=True, text=True, env=_cli_env(NO_COLOR="1"),
    )


def test_cli_passing_suite_exits_zero(tmp_path):
    suite = tmp_path / "pass.json"
    suite.write_text(json.dumps({"policies": POLICIES, "tests": CASES}))
    r = _run_cli(suite)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "8 passed, 0 failed" in r.stdout


def test_cli_failing_suite_exits_one(tmp_path):
    suite = tmp_path / "fail.json"
    suite.write_text(json.dumps({"policies": POLICIES,
        "tests": [{"name": "wrong", "action": "book",
                   "context": {"amount": 10, "limit": 500, "refundable": True}, "expect": "Deny"}]}))
    r = _run_cli(suite)
    assert r.returncode == 1, r.stdout + r.stderr


def test_cli_resolves_policy_file_relative_to_suite(tmp_path):
    (tmp_path / "watchlight.policy.json").write_text(json.dumps(POLICIES))
    suite = tmp_path / "ref.json"
    suite.write_text(json.dumps({"policyFile": "watchlight.policy.json",
        "tests": [{"name": "alice pays", "action": "pay", "principal": 'User::"alice"', "expect": "Allow"}]}))
    r = _run_cli(suite)
    assert r.returncode == 0, r.stdout + r.stderr


def test_cli_missing_arg_is_usage_error(tmp_path):
    r = subprocess.run(
        [sys.executable, "-m", "watchlight.cli", "policy", "test"],
        capture_output=True, text=True, env=_cli_env(),
    )
    assert r.returncode == 2


def test_duplicate_approved_fixtures_both_pass(tmp_path):
    # Two identical approved fixtures must both downgrade — the per-mint nonce
    # keeps their tokens distinct even when minted in the same millisecond.
    report = _gov(tmp_path).test([
        {"name": "A", "action": "wire", "context": {"amount": 3000}, "approved": True, "expect": "Allow"},
        {"name": "B", "action": "wire", "context": {"amount": 3000}, "approved": True, "expect": "Allow"},
    ])
    assert report["failed"] == 0, report["results"]


def test_malformed_fixture_raises(tmp_path):
    import pytest
    with pytest.raises(ValueError):
        _gov(tmp_path).test([{"action": "book"}])  # missing expect
    with pytest.raises(ValueError):
        _gov(tmp_path).test([{"expect": "Deny"}])  # missing action


def test_cli_malformed_fixture_exits_two(tmp_path):
    suite = tmp_path / "mal.json"
    suite.write_text(json.dumps({"policies": POLICIES, "tests": [{"action": "book"}]}))
    r = _run_cli(suite)
    assert r.returncode == 2, r.stdout + r.stderr
