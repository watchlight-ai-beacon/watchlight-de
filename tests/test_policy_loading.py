"""Loading a policy file never leaves a governor empty by accident.

A missing path, a directory, invalid JSON, an unrecognised shape, a malformed
entry, and a file that holds no policies all raise, naming the file — they used
to load nothing without a word, and a governor with no policies denies every
call. An empty set loads only with ``allow_empty=True``. One policy object per
file (the MCP PEP's shape) loads as one policy.

The TypeScript twin is ``ts/test/policy-loading.test.mjs``.
"""

from __future__ import annotations

import json
import pathlib

import pytest

from watchlight import Watchlight, principals
from watchlight.cli import main as cli_main

EXAMPLES = pathlib.Path(__file__).resolve().parent.parent / "examples"
READ = 'permit(principal, action == Action::"read", resource);'


def _gov(tmp_path) -> Watchlight:
    return Watchlight(agent="loader", audit_dir=str(tmp_path))


def _write(tmp_path, name, data) -> pathlib.Path:
    p = tmp_path / name
    p.write_text(data if isinstance(data, str) else json.dumps(data))
    return p


def _allowed(gov, action="read") -> bool:
    return gov.authorize(action=action, principal=principals.user("u"))["allowed"]


# ── the accepted shapes ──────────────────────────────────────────────


@pytest.mark.parametrize(
    "data",
    [
        [{"name": "read", "code": READ}],
        {"policies": [{"name": "read", "code": READ}]},
        {"name": "read", "code": READ},
        {"id": "read", "name": "read", "description": "d", "code": READ, "active": True},
    ],
    ids=["list", "policies-object", "single-object", "single-object-pep-fields"],
)
def test_each_documented_shape_loads(tmp_path, data):
    gov = _gov(tmp_path).load(_write(tmp_path, "p.json", data))
    assert gov.policy_count == 1
    assert _allowed(gov)


def test_the_mcp_example_loads_one_policy(tmp_path):
    gov = _gov(tmp_path).load(EXAMPLES / "mcp.policy.json")
    assert gov.policy_count == 1
    allowed = gov.authorize(
        action="call", principal=principals.user("u"),
        context={"mcp": {"tool": "search_repositories"}},
    )["allowed"]
    denied = gov.authorize(
        action="call", principal=principals.user("u"),
        context={"mcp": {"tool": "delete_repository"}},
    )["allowed"]
    assert allowed is True and denied is False


@pytest.mark.parametrize("name", sorted(p.name for p in EXAMPLES.glob("*.policy.json")))
def test_every_example_policy_file_loads_at_least_one_policy(tmp_path, name):
    assert _gov(tmp_path).load(EXAMPLES / name).policy_count >= 1


# ── refusals, each naming the file ───────────────────────────────────


def test_a_missing_file_raises_and_is_not_remembered(tmp_path):
    gov = _gov(tmp_path)
    later = tmp_path / "later.policy.json"
    with pytest.raises(FileNotFoundError, match="later.policy.json"):
        gov.load(later)
    assert gov.policy_count == 0
    _write(tmp_path, "later.policy.json", [{"name": "read", "code": READ}])
    assert gov.load(later).policy_count == 1


def test_a_directory_raises(tmp_path):
    with pytest.raises(IsADirectoryError, match="directory"):
        _gov(tmp_path).load(tmp_path)


def test_invalid_json_raises_naming_the_file(tmp_path):
    p = _write(tmp_path, "broken.json", "[{")
    with pytest.raises(ValueError, match="broken.json is not valid JSON"):
        _gov(tmp_path).load(p)


@pytest.mark.parametrize(
    "data, fragment",
    [
        ([], "defines no policies"),
        ({"policies": []}, "defines no policies"),
        ({}, 'neither "policies" nor "code"'),
        ({"name": "x"}, 'neither "policies" nor "code"'),
        ({"policyFile": "p.json", "tests": []}, "policy test suite"),
        ({"policies": {"name": "x", "code": READ}}, '"policies" must be a list'),
        ({"policies": [], "code": READ}, 'both "policies" and "code"'),
        ("permit(principal, action, resource);", "is a string"),
        (None, "is null"),
        ([READ], "is a string, not"),
        ([{"name": "x"}], 'no Cedar "code"'),
        ([{"name": "x", "code": "   "}], 'no Cedar "code"'),
        ([{"name": 7, "code": READ}], '"name" must be a string'),
        ([{"name": "off", "code": READ, "active": False}], '"active": false'),
    ],
    ids=[
        "empty-list", "empty-policies", "empty-object", "object-without-code",
        "suite-with-policyFile", "policies-not-a-list", "policies-and-code",
        "json-string", "json-null", "entry-is-string", "entry-without-code",
        "entry-blank-code", "entry-name-not-string", "entry-inactive",
    ],
)
def test_a_file_that_is_not_a_usable_policy_set_raises(tmp_path, data, fragment):
    p = _write(tmp_path, "bad.policy.json", json.dumps(data))
    gov = _gov(tmp_path)
    with pytest.raises(ValueError) as exc:
        gov.load(p)
    assert fragment in str(exc.value)
    assert "bad.policy.json" in str(exc.value)
    assert gov.policy_count == 0
    # Not remembered: the fixed file loads without force.
    p.write_text(json.dumps([{"name": "read", "code": READ}]))
    assert gov.load(p).policy_count == 1


def test_one_bad_entry_loads_none_of_the_file(tmp_path):
    p = _write(tmp_path, "p.json", [{"name": "read", "code": READ}, {"name": "broken"}])
    gov = _gov(tmp_path)
    with pytest.raises(ValueError, match='policy "broken"'):
        gov.load(p)
    assert gov.policy_count == 0 and not _allowed(gov)


def test_an_inactive_policy_is_never_enforced(tmp_path):
    # Loading it as active would widen authority; skipping it would hide it.
    p = _write(tmp_path, "p.json", {"name": "read", "code": READ, "active": False})
    gov = _gov(tmp_path)
    with pytest.raises(ValueError, match="inactive"):
        gov.load(p)
    assert not _allowed(gov)


# ── an empty set, on purpose ─────────────────────────────────────────


def test_allow_empty_loads_an_explicitly_empty_set(tmp_path):
    gov = _gov(tmp_path)
    p = _write(tmp_path, "none.json", {"policies": []})
    assert gov.load(p, allow_empty=True).policy_count == 0
    assert not _allowed(gov)


def test_allow_empty_does_not_excuse_a_missing_file_or_a_bad_shape(tmp_path):
    gov = _gov(tmp_path)
    with pytest.raises(FileNotFoundError):
        gov.load(tmp_path / "absent.json", allow_empty=True)
    with pytest.raises(ValueError):
        gov.load(_write(tmp_path, "obj.json", {"name": "x"}), allow_empty=True)


# ── reload reads the same shapes ─────────────────────────────────────


def test_reload_accepts_a_single_policy_object(tmp_path):
    gov = _gov(tmp_path).allow('permit(principal, action == Action::"list", resource);')
    gov.reload(_write(tmp_path, "one.json", {"name": "read", "code": READ}))
    assert gov.policy_count == 1
    assert _allowed(gov) and not _allowed(gov, "list")


def test_reload_refuses_a_malformed_file_and_keeps_the_set(tmp_path):
    gov = _gov(tmp_path).allow(READ)
    for data in ({"name": "x"}, [{"name": "x"}], {"name": "r", "code": READ, "active": False}):
        with pytest.raises(ValueError):
            gov.reload(_write(tmp_path, "bad.json", data))
        assert gov.policy_count == 1 and _allowed(gov)


def test_reload_refuses_a_malformed_in_memory_entry(tmp_path):
    gov = _gov(tmp_path).allow(READ)
    with pytest.raises(ValueError, match='no Cedar "code"'):
        gov.reload(policies=[{"name": "x"}])
    assert gov.policy_count == 1


# ── the CLI ──────────────────────────────────────────────────────────


def _suite(tmp_path, **fields) -> str:
    fields.setdefault("tests", [{"action": "read", "expect": "Allow"}])
    return str(_write(tmp_path, "suite.json", fields))


@pytest.mark.parametrize(
    "fields, fragment",
    [
        ({"policyFile": "absent.json"}, "no such policy file"),
        ({"policyFile": "empty.json"}, "defines no policies"),
        ({"policies": []}, "defines no policies"),
        ({"policies": [{"name": "x"}]}, 'no Cedar "code"'),
        ({}, "declares no policies"),
    ],
    ids=["missing-policyFile", "empty-policyFile", "empty-inline", "bad-inline", "none"],
)
def test_cli_exits_2_on_a_suite_with_no_usable_policies(tmp_path, capsys, fields, fragment):
    _write(tmp_path, "empty.json", [])
    assert cli_main(["policy", "test", _suite(tmp_path, **fields)]) == 2
    assert fragment in capsys.readouterr().err


def test_cli_loads_a_single_object_policy_file(tmp_path, capsys):
    _write(tmp_path, "one.json", {"name": "read", "code": READ})
    assert cli_main(["policy", "test", _suite(tmp_path, policyFile="one.json")]) == 0
