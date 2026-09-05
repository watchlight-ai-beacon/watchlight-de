"""`@enforcement_effect` is checked when a policy loads (Python), mirroring the
TS suite `ts/test/policy-annotations.test.mjs`.

The defect this answers: the engine maps an `@enforcement_effect` value it does
not implement to no effect at all. For the verbs that escalate a `forbid` that
is the closed direction — a dropped `terminate` leaves a plain deny. For
`require_approval` on a `permit` it is the OPEN direction: a dropped hold leaves
an unconditional allow. So a one-character typo in the value silently turned a
human-in-the-loop gate into a permit, with no error and no warning.

What is asserted here:

* every accepted value still loads, and `require_approval` still yields
  NeedsApproval — a correct policy is untouched;
* a value the engine does not implement raises `PolicyError` at load, naming the
  value, the accepted set and the policy;
* the annotation is READ, not grepped: the same text inside a Cedar string
  literal, or in a comment, is not an annotation and is not rejected;
* a near miss for the annotation NAME warns and still loads (an arbitrary
  annotation is legitimate Cedar, so this can never throw);
* `load()` is atomic: one bad policy in a file loads none of it;
* both lanes carry the same accepted set and the same wording — proven against
  `ts/src/annotations.ts` and the shared fixture, so the two cannot drift.
"""

from __future__ import annotations

import json
import pathlib
import re
import subprocess
import sys

import pytest

from watchlight import ENFORCEMENT_EFFECTS, ENFORCEMENT_EFFECT_ANNOTATION, PolicyError, Watchlight
from watchlight._annotations import (
    is_near_miss,
    near_miss_message,
    parse_policy_annotations,
    unrecognized_effect_message,
)

HERE = pathlib.Path(__file__).parent
REPO = HERE.parent
FIXTURE = json.loads((HERE / "fixtures" / "enforcement_effects.json").read_text())

PERMIT = 'permit(principal, action == Action::"wire", resource);'


def _governor(tmp_path):
    return Watchlight(agent="probe", audit_dir=str(tmp_path))


def _decide(gov):
    return gov.authorize(action="wire", resource="acct")["decision"]


# ── the reproduction, closed ────────────────────────────────────────────────


def test_correct_value_still_holds_the_permit_for_a_human(tmp_path):
    gov = _governor(tmp_path)
    gov.allow(f'@enforcement_effect("require_approval")\n{PERMIT}', "wire-approval")
    assert gov.policy_count == 1
    assert _decide(gov) == "NeedsApproval"


@pytest.mark.parametrize("value", FIXTURE["rejected_values"])
def test_a_value_the_engine_does_not_implement_is_refused_at_load(tmp_path, value):
    gov = _governor(tmp_path)
    with pytest.raises(PolicyError) as caught:
        gov.allow(f'@enforcement_effect("{value}")\n{PERMIT}', "wire-approval")
    assert gov.policy_count == 0, "a refused policy must not count as loaded"
    assert caught.value.value == value
    assert caught.value.policy == "wire-approval"
    assert caught.value.accepted == ENFORCEMENT_EFFECTS


def test_the_message_names_the_value_the_accepted_set_and_the_policy(tmp_path):
    gov = _governor(tmp_path)
    with pytest.raises(PolicyError) as caught:
        gov.allow(f'@enforcement_effect("needs_approval")\n{PERMIT}', "wire-approval")
    message = str(caught.value)
    assert '"needs_approval"' in message
    assert 'policy "wire-approval"' in message
    for effect in ENFORCEMENT_EFFECTS:
        assert effect in message


@pytest.mark.parametrize("effect", ENFORCEMENT_EFFECTS)
def test_every_accepted_value_loads(tmp_path, effect):
    gov = _governor(tmp_path)
    gov.allow(f'@enforcement_effect("{effect}")\n{PERMIT}', "p")
    assert gov.policy_count == 1


def test_a_policy_with_no_annotation_at_all_is_untouched(tmp_path):
    gov = _governor(tmp_path)
    gov.allow(PERMIT, "plain")
    assert gov.policy_count == 1
    assert _decide(gov) == "Allow"


# ── read, do not grep ───────────────────────────────────────────────────────


def test_the_annotation_text_inside_a_cedar_string_is_not_an_annotation(tmp_path):
    """The one that a regex gets wrong: a policy BODY quoting the annotation.

    `context.note == "@enforcement_effect(\\"not_a_real_value\\")"` is a string
    comparison, not an annotation, and the policy must load and decide normally.
    """
    code = (
        '@enforcement_effect("require_approval")\n'
        'permit(principal, action == Action::"wire", resource)\n'
        'when { context.note == "@enforcement_effect(\\"not_a_real_value\\")" };'
    )
    gov = _governor(tmp_path)
    gov.allow(code, "quoted")  # must not raise
    assert gov.policy_count == 1
    assert (
        gov.authorize(
            action="wire",
            resource="acct",
            context={"note": '@enforcement_effect("not_a_real_value")'},
        )["decision"]
        == "NeedsApproval"
    ), "the real annotation still governs; the quoted one is just a string"


def test_a_bogus_value_quoted_inside_the_body_of_an_unannotated_policy_is_ignored(tmp_path):
    code = (
        'permit(principal, action == Action::"wire", resource)\n'
        'when { context.note == "@enforcement_effect(\\"not_a_real_value\\")" };'
    )
    gov = _governor(tmp_path)
    gov.allow(code, "quoted-only")  # must not raise
    assert gov.policy_count == 1


def test_the_annotation_in_a_comment_is_not_an_annotation(tmp_path):
    code = f'// @enforcement_effect("not_a_real_value")\n{PERMIT}'
    gov = _governor(tmp_path)
    gov.allow(code, "commented")
    assert gov.policy_count == 1


def test_a_value_carrying_an_escape_is_left_to_the_engine(tmp_path):
    """We read literals raw, so we cannot say what the engine decodes an escape
    to. Staying quiet is the only option that cannot refuse a policy the engine
    would have accepted."""
    gov = _governor(tmp_path)
    gov.allow(r'@enforcement_effect("require\u{5f}approval")' + f"\n{PERMIT}", "escaped")
    assert gov.policy_count == 1


def test_a_semicolon_inside_a_string_does_not_start_a_new_policy(tmp_path):
    code = (
        '@enforcement_effect("require_approval")\n'
        'permit(principal, action == Action::"wire", resource)\n'
        'when { context.note == "a;b" };'
    )
    gov = _governor(tmp_path)
    gov.allow(code, "semicolon")
    assert gov.policy_count == 1
    assert (
        gov.authorize(action="wire", resource="acct", context={"note": "a;b"})["decision"]
        == "NeedsApproval"
    )


# ── several policies in one source ──────────────────────────────────────────


def test_a_bad_effect_on_a_later_policy_in_the_source_is_still_caught(tmp_path):
    """The engine takes one policy per `allow`, but the parser reads a whole
    source, so a pasted pair is checked to the end rather than only at the top."""
    code = (
        f'@enforcement_effect("require_approval")\n{PERMIT}\n'
        '@enforcement_effect("not_a_real_value")\n'
        'permit(principal, action == Action::"read", resource);'
    )
    with pytest.raises(PolicyError) as caught:
        _governor(tmp_path).allow(code, "wire-set")
    assert caught.value.value == "not_a_real_value"
    assert 'policy "wire-set"' in str(caught.value)


def test_an_annotated_forbid_loads(tmp_path):
    gov = _governor(tmp_path)
    gov.allow(
        '@enforcement_effect("terminate")\nforbid(principal, action == Action::"read", resource);',
        "kill",
    )
    assert gov.policy_count == 1


# ── the annotation NAME ─────────────────────────────────────────────────────


@pytest.mark.parametrize("name", FIXTURE["near_miss_names"])
def test_a_near_miss_name_warns_and_still_loads(tmp_path, capsys, name):
    gov = _governor(tmp_path)
    gov.allow(f'@{name}("require_approval")\n{PERMIT}', "typo")
    assert gov.policy_count == 1, "an unknown annotation is legitimate Cedar; it must load"
    assert is_near_miss(name)
    err = capsys.readouterr().err
    assert f"`@{name}`" in err
    assert "near miss" in err


@pytest.mark.parametrize("name", FIXTURE["not_near_miss_names"])
def test_an_ordinary_user_annotation_is_silent(tmp_path, capsys, name):
    gov = _governor(tmp_path)
    # "8" so the value is legal for every name here, `@obligate_max_items` included.
    gov.allow(f'@{name}("8")\n{PERMIT}', "annotated")
    assert gov.policy_count == 1
    assert not is_near_miss(name)
    assert "near miss" not in capsys.readouterr().err


def test_the_exact_name_never_warns(tmp_path, capsys):
    gov = _governor(tmp_path)
    gov.allow(f'@enforcement_effect("require_approval")\n{PERMIT}', "correct")
    assert "near miss" not in capsys.readouterr().err
    assert not is_near_miss(ENFORCEMENT_EFFECT_ANNOTATION)


def test_a_near_miss_name_never_raises(tmp_path):
    """The line the check must not cross: an annotation the SDK does not read is
    valid Cedar, so a name it cannot vouch for is a warning, never a refusal."""
    gov = _governor(tmp_path)
    gov.allow(f'@enforcment_effect("not_a_real_value_either")\n{PERMIT}', "typo")
    assert gov.policy_count == 1


# ── load() ──────────────────────────────────────────────────────────────────


def test_load_refuses_a_file_and_adds_none_of_it(tmp_path):
    policy_file = tmp_path / "watchlight.policy.json"
    policy_file.write_text(
        json.dumps(
            [
                {"name": "good", "code": PERMIT},
                {"name": "bad", "code": f'@enforcement_effect("needs_approval")\n{PERMIT}'},
            ]
        )
    )
    gov = _governor(tmp_path)
    with pytest.raises(PolicyError) as caught:
        gov.load(policy_file)
    assert caught.value.policy == "bad"
    assert gov.policy_count == 0, "a file is loaded whole or not at all"

    # …and the source was not remembered, so fixing the file and loading again works.
    policy_file.write_text(json.dumps([{"name": "good", "code": PERMIT}]))
    gov.load(policy_file)
    assert gov.policy_count == 1


def test_load_of_a_correct_file_is_unaffected(tmp_path):
    policy_file = tmp_path / "watchlight.policy.json"
    policy_file.write_text(
        json.dumps(
            [{"name": "wire", "code": f'@enforcement_effect("require_approval")\n{PERMIT}'}]
        )
    )
    gov = _governor(tmp_path)
    gov.load(policy_file)
    assert gov.policy_count == 1
    assert _decide(gov) == "NeedsApproval"


def test_load_warns_once_for_a_near_miss(tmp_path, capsys):
    policy_file = tmp_path / "watchlight.policy.json"
    policy_file.write_text(
        json.dumps([{"name": "typo", "code": f'@enforcment_effect("require_approval")\n{PERMIT}'}])
    )
    _governor(tmp_path).load(policy_file)
    assert capsys.readouterr().err.count("near miss") == 1


# ── the CLI ─────────────────────────────────────────────────────────────────


def test_the_cli_reports_the_refusal_instead_of_testing_a_different_policy(tmp_path):
    suite = tmp_path / "suite.json"
    suite.write_text(
        json.dumps(
            {
                "policies": [
                    {"name": "wire", "code": f'@enforcement_effect("needs_approval")\n{PERMIT}'}
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
    assert "needs_approval" in done.stderr
    assert "is not an effect this engine implements" in done.stderr


# ── the parser, directly ────────────────────────────────────────────────────


def test_the_parser_returns_one_entry_per_policy_in_source_order():
    parsed = parse_policy_annotations(
        f'@a("1")\n@b("2")\n{PERMIT}\n@c\nforbid(principal, action, resource);'
    )
    assert parsed == [[("a", "1"), ("b", "2")], [("c", None)]]


def test_the_parser_hands_an_unreadable_source_to_the_engine():
    assert parse_policy_annotations('@enforcement_effect("unterminated') is None
    assert parse_policy_annotations('@enforcement_effect("x"') is None
    assert parse_policy_annotations("@123bad\npermit(principal, action, resource);") is None


# ── the two lanes cannot drift ──────────────────────────────────────────────


def test_the_typescript_lane_carries_the_same_accepted_set():
    """The accepted set lives in exactly two places. This reads the other one."""
    source = REPO / "ts" / "src" / "annotations.ts"
    if not source.exists():  # pragma: no cover - the wheel ships no TS source
        pytest.skip("the TypeScript lane is not present in this checkout")
    block = re.search(
        r"export const ENFORCEMENT_EFFECTS = \[(.*?)\] as const;", source.read_text(), re.S
    )
    assert block, "ENFORCEMENT_EFFECTS is not where the Python lane expects it"
    assert tuple(re.findall(r'"([^"]+)"', block.group(1))) == ENFORCEMENT_EFFECTS


def test_the_wording_matches_the_shared_fixture():
    where = FIXTURE["where"].format(policy="wire-approval")
    assert unrecognized_effect_message(where, "needs_approval") == FIXTURE[
        "error_template"
    ].format(
        where=where,
        annotation=ENFORCEMENT_EFFECT_ANNOTATION,
        value="needs_approval",
        accepted=", ".join(ENFORCEMENT_EFFECTS),
    )
    assert near_miss_message(where, "enforcment_effect") == FIXTURE["warning_template"].format(
        where=where,
        annotation=ENFORCEMENT_EFFECT_ANNOTATION,
        written="enforcment_effect",
    )
    assert FIXTURE["annotation"] == ENFORCEMENT_EFFECT_ANNOTATION
