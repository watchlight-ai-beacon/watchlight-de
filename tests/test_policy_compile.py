"""A policy that does not compile never leaves a set that decides without it.

The engine cannot drop a policy, so a file that fails part-way would leave the
policies before the error loaded and the ones after it missing. A missing
``forbid`` is a widened decision. ``load`` compiles the whole file into a
scratch engine first and raises :class:`PolicyCompileError`, adding nothing;
``reload`` compiles before the swap and keeps the old set.

The TypeScript twin is ``ts/test/policy-compile.test.mjs``.
"""

from __future__ import annotations

import json

import pytest

from watchlight import PolicyCompileError, Watchlight, principals
from watchlight.cli import main as cli_main

PERMIT_ALL = "permit(principal, action, resource);"
FORBID_WIRE = 'forbid(principal, action == Action::"wire", resource);'
BROKEN_FORBID = 'forbid(principal, action == Action::"delete", resource) when { ;'


def _gov(tmp_path) -> Watchlight:
    return Watchlight(agent="compiler", audit_dir=str(tmp_path))


def _write(tmp_path, name, entries):
    p = tmp_path / name
    p.write_text(json.dumps(entries))
    return p


def _decision(gov, action):
    return gov.authorize(action=action, principal=principals.user("u"))["allowed"]


def test_a_file_with_a_broken_forbid_loads_nothing(tmp_path):
    p = _write(tmp_path, "mixed.json", [
        {"name": "all", "code": PERMIT_ALL},
        {"name": "no-delete", "code": BROKEN_FORBID},
    ])
    gov = _gov(tmp_path)
    with pytest.raises(PolicyCompileError) as exc:
        gov.load(p)
    assert exc.value.policy == "no-delete"
    assert exc.value.source == str(p)
    assert "no-delete" in str(exc.value) and "mixed.json" in str(exc.value)
    assert isinstance(exc.value, RuntimeError)          # what the engine raised before
    assert gov.policy_count == 0
    assert _decision(gov, "read") is False               # the permit did not load
    assert _decision(gov, "delete") is False


def test_a_refused_file_is_not_remembered(tmp_path):
    p = _write(tmp_path, "p.json", [{"name": "bad", "code": BROKEN_FORBID}])
    gov = _gov(tmp_path)
    with pytest.raises(PolicyCompileError):
        gov.load(p)
    p.write_text(json.dumps([{"name": "all", "code": PERMIT_ALL}]))
    assert gov.load(p).policy_count == 1


def test_a_later_broken_file_keeps_the_earlier_forbids(tmp_path):
    first = _write(tmp_path, "first.json", [
        {"name": "all", "code": PERMIT_ALL},
        {"name": "no-wire", "code": FORBID_WIRE},
    ])
    second = _write(tmp_path, "second.json", [
        {"name": "read", "code": 'permit(principal, action == Action::"read", resource);'},
        {"name": "no-delete", "code": BROKEN_FORBID},
    ])
    gov = _gov(tmp_path).load(first)
    with pytest.raises(PolicyCompileError):
        gov.load(second)
    assert gov.policy_count == 2
    assert _decision(gov, "wire") is False                # the first file's forbid holds
    assert _decision(gov, "read") is True


def test_reload_with_a_broken_forbid_keeps_the_previous_set(tmp_path):
    gov = _gov(tmp_path).allow(PERMIT_ALL).allow(FORBID_WIRE)
    with pytest.raises(PolicyCompileError) as exc:
        gov.reload(policies=[{"name": "all", "code": PERMIT_ALL},
                             {"name": "no-delete", "code": BROKEN_FORBID}])
    assert exc.value.policy == "no-delete" and exc.value.source is None
    p = _write(tmp_path, "r.json", [{"name": "no-delete", "code": BROKEN_FORBID}])
    with pytest.raises(PolicyCompileError) as exc:
        gov.reload(p)
    assert exc.value.source == str(p)
    assert gov.policy_count == 2
    assert _decision(gov, "wire") is False and _decision(gov, "read") is True


def test_allow_raises_on_a_broken_policy_and_adds_nothing(tmp_path):
    gov = _gov(tmp_path).allow(PERMIT_ALL)
    with pytest.raises(PolicyCompileError):
        gov.allow(BROKEN_FORBID, "no-delete")
    assert gov.policy_count == 1


def test_cli_exits_2_on_a_policy_that_does_not_compile(tmp_path, capsys):
    _write(tmp_path, "p.json", [{"name": "all", "code": PERMIT_ALL},
                                {"name": "no-delete", "code": BROKEN_FORBID}])
    suite = tmp_path / "suite.json"
    suite.write_text(json.dumps({"policyFile": "p.json",
                                 "tests": [{"action": "delete", "expect": "Deny"}]}))
    assert cli_main(["policy", "test", str(suite)]) == 2
    assert "no-delete" in capsys.readouterr().err
