"""`@enforcement_effect` is refused at load when the engine cannot honour it
(Python), mirroring the TS suite `ts/test/policy-annotations.test.mjs`.

The defect this answers: an `@enforcement_effect` value the engine did not
implement was dropped. For the verbs that escalate a `forbid` that is the
closed direction, but for `require_approval` on a `permit` it is the OPEN one:
a dropped hold leaves an unconditional allow. A misspelled annotation NAME did
the same, because Cedar accepts any annotation name.

The engine (`watchlight-engine` >= 0.2.3) now refuses both when a policy is
added, with a typed error. The SDK maps it to `PolicyError`. What is asserted:

* every accepted value still loads, and `require_approval` still yields
  NeedsApproval — a correct policy is untouched;
* a value the engine does not implement raises `PolicyError` with code
  `UNRECOGNISED_ENFORCEMENT_EFFECT`, naming the policy;
* an annotation name that is a near miss for `enforcement_effect` raises
  `PolicyError` with code `ENFORCEMENT_EFFECT_NAME_NEAR_MISS`; any other
  annotation is the developer's own and loads;
* the same text inside a Cedar string or a comment is not an annotation;
* `load()` and `reload()` are atomic: one refused policy loads none of the set;
* a Cedar syntax error is a `PolicyCompileError`, never a `PolicyError`;
* the cases are shared with the TypeScript lane through one fixture.
"""

from __future__ import annotations

import json
import pathlib
import subprocess
import sys

import pytest

import watchlight_engine
from watchlight import (
    ENFORCEMENT_EFFECT_ANNOTATION,
    ENFORCEMENT_EFFECT_NAME_NEAR_MISS,
    POLICY_ERROR_CODES,
    UNRECOGNISED_ENFORCEMENT_EFFECT,
    PolicyCompileError,
    PolicyError,
    Watchlight,
)

HERE = pathlib.Path(__file__).parent
FIXTURE = json.loads((HERE / "fixtures" / "enforcement_effects.json").read_text())

PERMIT = 'permit(principal, action == Action::"wire", resource);'

pytestmark = pytest.mark.skipif(
    not hasattr(watchlight_engine, "PolicyAnnotationError"),
    reason="needs watchlight-engine >= 0.2.3",
)


def _governor(tmp_path):
    return Watchlight(agent="probe", audit_dir=str(tmp_path))


def _decide(gov):
    return gov.authorize(action="wire", resource="acct")["decision"]


def _annotated(name, value):
    return f'@{name}("{value}")\n{PERMIT}'


# ── a correct policy is untouched ──────────────────────────────────────────


def test_correct_value_still_holds_the_permit_for_a_human(tmp_path):
    gov = _governor(tmp_path).allow(_annotated(ENFORCEMENT_EFFECT_ANNOTATION, "require_approval"))
    assert _decide(gov) == "NeedsApproval"


@pytest.mark.parametrize("effect", FIXTURE["accepted_values"])
def test_every_accepted_value_loads(tmp_path, effect):
    _governor(tmp_path).allow(_annotated(ENFORCEMENT_EFFECT_ANNOTATION, effect))


def test_a_policy_with_no_annotation_at_all_is_untouched(tmp_path):
    assert _decide(_governor(tmp_path).allow(PERMIT)) == "Allow"


@pytest.mark.parametrize("name", FIXTURE["not_near_miss_names"])
def test_an_ordinary_user_annotation_loads(tmp_path, name):
    assert _decide(_governor(tmp_path).allow(_annotated(name, "1"))) == "Allow"


# ── refused, with a typed code ─────────────────────────────────────────────


@pytest.mark.parametrize("value", FIXTURE["rejected_values"])
def test_a_value_the_engine_does_not_implement_is_refused_at_load(tmp_path, value):
    gov = _governor(tmp_path)
    with pytest.raises(PolicyError) as caught:
        gov.allow(_annotated(ENFORCEMENT_EFFECT_ANNOTATION, value), "wire-approval")
    assert caught.value.code == UNRECOGNISED_ENFORCEMENT_EFFECT
    assert caught.value.policy == "wire-approval"
    assert gov.policy_count == 0
    # Fail closed: the refused policy decides nothing, so nothing is allowed.
    assert _decide(gov) != "Allow"


@pytest.mark.parametrize("name", FIXTURE["near_miss_names"])
def test_a_near_miss_annotation_name_is_refused_at_load(tmp_path, name):
    gov = _governor(tmp_path)
    with pytest.raises(PolicyError) as caught:
        gov.allow(_annotated(name, "require_approval"), "typo")
    assert caught.value.code == ENFORCEMENT_EFFECT_NAME_NEAR_MISS
    assert caught.value.policy == "typo"
    assert gov.policy_count == 0


def test_the_message_names_the_policy_and_not_the_engine_internals(tmp_path):
    with pytest.raises(PolicyError) as caught:
        _governor(tmp_path).allow(
            _annotated(ENFORCEMENT_EFFECT_ANNOTATION, "needs_approval"), "wire-approval"
        )
    message = str(caught.value)
    assert message.startswith('policy "wire-approval": ')
    assert "needs_approval" in message
    assert "add_policy failed" not in message


def test_the_codes_are_the_engines():
    assert set(POLICY_ERROR_CODES) == set(watchlight_engine.POLICY_ANNOTATION_ERROR_CODES)
    assert set(POLICY_ERROR_CODES) == set(FIXTURE["codes"].values())


def test_policy_error_is_a_value_error_and_not_a_compile_error(tmp_path):
    with pytest.raises(ValueError):
        _governor(tmp_path).allow(_annotated(ENFORCEMENT_EFFECT_ANNOTATION, "nope"))
    with pytest.raises(PolicyCompileError) as caught:
        _governor(tmp_path).allow("permit(principal, action ==", "broken")
    assert not isinstance(caught.value, PolicyError)


# ── read, not grepped ──────────────────────────────────────────────────────


def test_the_annotation_text_inside_a_cedar_string_is_not_an_annotation(tmp_path):
    code = (
        'permit(principal, action == Action::"wire", resource) '
        'when { context.note == "@enforcement_effect(\\"needs_approval\\")" };'
    )
    _governor(tmp_path).allow(code)


def test_the_annotation_in_a_comment_is_not_an_annotation(tmp_path):
    _governor(tmp_path).allow(f'// @enforcement_effect("needs_approval")\n{PERMIT}')


# ── whole sets ─────────────────────────────────────────────────────────────


def test_load_refuses_a_file_and_adds_none_of_it(tmp_path):
    policy_file = tmp_path / "watchlight.policy.json"
    policy_file.write_text(
        json.dumps(
            [
                {"name": "good", "code": PERMIT},
                {"name": "bad", "code": _annotated(ENFORCEMENT_EFFECT_ANNOTATION, "needs_approval")},
            ]
        )
    )
    gov = _governor(tmp_path)
    with pytest.raises(PolicyError) as caught:
        gov.load(policy_file)
    assert caught.value.policy == "bad"
    assert caught.value.source == str(policy_file)
    assert gov.policy_count == 0, "a file is loaded whole or not at all"

    # …and the source was not remembered, so fixing the file and loading again works.
    policy_file.write_text(json.dumps([{"name": "good", "code": PERMIT}]))
    gov.load(policy_file)
    assert gov.policy_count == 1


def test_load_refuses_a_near_miss_and_adds_none_of_the_file(tmp_path):
    policy_file = tmp_path / "watchlight.policy.json"
    policy_file.write_text(
        json.dumps(
            [
                {"name": "good", "code": PERMIT},
                {"name": "typo", "code": _annotated("enforcment_effect", "require_approval")},
            ]
        )
    )
    gov = _governor(tmp_path)
    with pytest.raises(PolicyError) as caught:
        gov.load(policy_file)
    assert caught.value.code == ENFORCEMENT_EFFECT_NAME_NEAR_MISS
    assert gov.policy_count == 0


def test_reload_keeps_the_old_set_when_the_new_one_is_refused(tmp_path):
    gov = _governor(tmp_path).allow(PERMIT, "old")
    with pytest.raises(PolicyError):
        gov.reload(
            policies=[{"name": "bad", "code": _annotated("Enforcement_Effect", "terminate")}]
        )
    assert gov.policy_count == 1
    assert _decide(gov) == "Allow"


def test_load_of_a_correct_file_is_unaffected(tmp_path):
    policy_file = tmp_path / "watchlight.policy.json"
    policy_file.write_text(
        json.dumps(
            [{"name": "wire", "code": _annotated(ENFORCEMENT_EFFECT_ANNOTATION, "require_approval")}]
        )
    )
    gov = _governor(tmp_path)
    gov.load(policy_file)
    assert gov.policy_count == 1
    assert _decide(gov) == "NeedsApproval"


# ── the CLI ─────────────────────────────────────────────────────────────────


def test_the_cli_reports_the_refusal_instead_of_testing_a_different_policy(tmp_path):
    suite = tmp_path / "suite.json"
    suite.write_text(
        json.dumps(
            {
                "policies": [
                    {
                        "name": "wire",
                        "code": _annotated(ENFORCEMENT_EFFECT_ANNOTATION, "needs_approval"),
                    }
                ],
                "tests": [{"action": "wire", "resource": "acct", "expect": "NeedsApproval"}],
            }
        )
    )
    done = subprocess.run(
        [sys.executable, "-m", "watchlight.cli", "policy", "test", str(suite)],
        capture_output=True,
        text=True,
        cwd=tmp_path,
    )
    assert done.returncode == 2
    assert 'policy "wire"' in done.stderr
    assert "needs_approval" in done.stderr
