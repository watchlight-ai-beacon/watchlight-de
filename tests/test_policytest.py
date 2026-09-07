"""Policy test harness (Python), mirroring the TS suite.

Golden fixtures asserting Allow/Deny/NeedsApproval against the real
watchlight_engine, the audit-free guarantee, and the `watchlight policy test`
CLI. No mocks.
"""
import json
import os
import subprocess
import sys

import pytest

from watchlight import PolicyError, Watchlight, load_test_suite, run_policy_tests

# A representative money-movement policy set: a funded-balance check.
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


# ── a fixture can name the actor, and an unknown key is refused ─────

ACTOR_POLICY = (
    'permit(principal, action == Action::"review", resource) '
    'when { context.actor == "document-reader" };'
)


def _actor_governor():
    gov = Watchlight(agent="orchestrator", audit_file=False)
    gov.allow(ACTOR_POLICY)
    return gov


def test_a_fixture_can_be_evaluated_as_a_named_actor():
    # The policy the 0.8 identity model exists to enable. Without `actor` the
    # case runs as the governor's own agent and reads as a denial, so a suite
    # could only ever assert the negative half.
    report = _actor_governor().test(
        [{"action": "review", "actor": "document-reader", "expect": "Allow"}]
    )
    assert report["failed"] == 0, report["results"]


def test_a_different_actor_is_denied_by_the_same_policy():
    report = _actor_governor().test(
        [{"action": "review", "actor": "auditor", "expect": "Deny"}]
    )
    assert report["failed"] == 0, report["results"]


def test_an_actorless_case_still_runs_as_the_governor():
    report = _actor_governor().test([{"action": "review", "expect": "Deny"}])
    assert report["failed"] == 0, report["results"]


def test_an_unknown_fixture_key_is_refused_rather_than_dropped():
    # The defect: a misspelled or unsupported key was dropped, so the case
    # passed while proving something other than what it said.
    with pytest.raises(ValueError) as exc:
        _actor_governor().test([{"action": "review", "expect": "Deny", "actr": "x"}])
    assert "actr" in str(exc.value)


def test_a_blank_actor_is_refused():
    with pytest.raises(ValueError):
        _actor_governor().test([{"action": "review", "actor": "  ", "expect": "Deny"}])


def test_the_bare_runner_refuses_an_actor_it_cannot_resolve():
    # `run_policy_tests` called without a resolver must not silently evaluate
    # the case under the wrong identity.
    with pytest.raises(ValueError) as exc:
        run_policy_tests(
            lambda **req: {"decision": "Deny"},
            lambda **ch: "",
            [{"action": "review", "actor": "document-reader", "expect": "Deny"}],
        )
    assert "actor" in str(exc.value)


def test_the_cli_runs_an_actor_scoped_suite(tmp_path):
    suite = tmp_path / "actor.json"
    suite.write_text(
        json.dumps(
            {
                "policies": [{"name": "reader-only", "code": ACTOR_POLICY}],
                "tests": [
                    {"action": "review", "actor": "document-reader", "expect": "Allow"},
                    {"action": "review", "actor": "auditor", "expect": "Deny"},
                ],
            }
        )
    )
    r = _run_cli(suite)
    assert r.returncode == 0, r.stdout + r.stderr


def test_the_cli_rejects_an_unknown_fixture_key(tmp_path):
    suite = tmp_path / "unknown.json"
    suite.write_text(
        json.dumps({"policies": POLICIES, "tests": [{"action": "book", "expect": "Deny", "ctx": {}}]})
    )
    r = _run_cli(suite)
    assert r.returncode == 2, r.stdout + r.stderr


# ── reload: replacing the set, not adding to it ─────────────────────

WIDE = [
    {"name": "read", "code": 'permit(principal, action == Action::"read", resource);'},
    {"name": "write", "code": 'permit(principal, action == Action::"write", resource);'},
]
NARROW = [WIDE[0]]


def _reload_gov():
    return Watchlight(agent="svc", audit_file=False, audit_sink=lambda record: None)


def _reload_decide(gov, action):
    return gov.authorize(action=action, principal='User::"u"', resource='Resource::"r"')["decision"]


def _reload_write(tmp_path, name, entries):
    p = tmp_path / name
    p.write_text(json.dumps(entries))
    return p


def test_reload_can_narrow_authority(tmp_path):
    # The whole point: with only load/allow a live reload could add a permit but
    # never remove one, so it could only ever WIDEN authority.
    gov = _reload_gov()
    gov.load(_reload_write(tmp_path, "wide.json", WIDE))
    assert _reload_decide(gov, "write") == "Allow"
    gov.reload(_reload_write(tmp_path, "narrow.json", NARROW))
    assert _reload_decide(gov, "write") == "Deny"
    assert _reload_decide(gov, "read") == "Allow"
    assert gov.policy_count == 1


def test_reload_drops_inline_policies_too(tmp_path):
    gov = _reload_gov()
    gov.allow('permit(principal, action == Action::"delete", resource);')
    assert _reload_decide(gov, "delete") == "Allow"
    gov.reload(_reload_write(tmp_path, "narrow.json", NARROW))
    assert _reload_decide(gov, "delete") == "Deny"


def test_reload_accepts_an_in_memory_bundle():
    gov = _reload_gov()
    gov.reload(policies=NARROW)
    assert _reload_decide(gov, "read") == "Allow" and gov.policy_count == 1


def test_a_failed_reload_leaves_the_set_exactly_as_it_was(tmp_path):
    # Atomic: the new set is compiled into a fresh engine before anything is
    # swapped, so there is no window holding half of either set.
    gov = _reload_gov()
    gov.load(_reload_write(tmp_path, "wide.json", WIDE))
    bad = _reload_write(tmp_path, "bad.json",
                 [{"name": "x", "code": '@enforcement_effect("nope")\npermit(principal, action, resource);'}])
    with pytest.raises(PolicyError):
        gov.reload(bad)
    assert _reload_decide(gov, "read") == "Allow" and _reload_decide(gov, "write") == "Allow"
    assert gov.policy_count == 2


def test_reload_refuses_to_empty_the_set(tmp_path):
    # Cedar default-denies, so an accidental empty reload would be safe but
    # total — every governed call in the process refused.
    gov = _reload_gov()
    gov.load(_reload_write(tmp_path, "wide.json", WIDE))
    with pytest.raises(ValueError):
        gov.reload(policies=[])
    with pytest.raises(ValueError):
        gov.reload(_reload_write(tmp_path, "empty.json", []))
    with pytest.raises(FileNotFoundError):
        gov.reload(tmp_path / "absent.json")
    assert _reload_decide(gov, "read") == "Allow" and gov.policy_count == 2


def test_reload_takes_exactly_one_source(tmp_path):
    gov = _reload_gov()
    with pytest.raises(ValueError):
        gov.reload()
    with pytest.raises(ValueError):
        gov.reload(_reload_write(tmp_path, "n.json", NARROW), policies=NARROW)


def test_a_renamed_view_shares_the_reload(tmp_path):
    gov = _reload_gov()
    gov.load(_reload_write(tmp_path, "wide.json", WIDE))
    view = gov.as_("worker")
    gov.reload(_reload_write(tmp_path, "narrow.json", NARROW))
    assert _reload_decide(view, "write") == "Deny"


def test_reload_clears_the_load_memo(tmp_path):
    gov = _reload_gov()
    wide = _reload_write(tmp_path, "wide.json", WIDE)
    gov.load(wide)
    gov.reload(policies=NARROW)
    gov.load(wide)  # loadable again without force: the memo went with the set
    assert _reload_decide(gov, "write") == "Allow"
