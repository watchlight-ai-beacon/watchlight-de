"""Every Cedar policy in the docs and examples decides its own scenario.

A policy example is an instruction: a reader copies it. An example whose
principal, action or condition never matches the request its page describes is
broken in one of two ways. A ``permit`` that never matches denies, which is safe
but useless. A ``forbid`` that never matches forbids nothing, which looks like
protection and is none.

This test extracts every Cedar statement from the Markdown pages (``README.md``,
``ts/README.md``, ``docs/``, ``examples/``), wherever it appears: a ``cedar``
block, a ``"code"`` value in a ``json`` block, or a quoted policy in a code
sample. Each statement must have a scenario in
``tests/fixtures/doc_policy_scenarios.json``, written as the page describes the
call. The statement is loaded on its own and decided by the engine:

- a ``permit`` must allow its scenario (or, when the page says so, return
  ``NeedsApproval``);
- a ``forbid`` is loaded next to ``permit(principal, action, resource);`` and
  must deny its scenario, so the test proves the forbid itself matched. Its
  ``@enforcement_effect`` annotation is removed first, because the question is
  whether its scope and condition match; ``test_enforcement_effects.py``
  covers the effects.

A scenario that expects anything else names its reason in ``why`` (for
example, a "before" example in the migration notes).

A scenario names the path the page describes:

- ``governor`` (the default): the ``watchlight`` package, through
  ``Watchlight(agent=...).test``. A call that names no principal is decided as
  ``Agent::"<agent name>"``.
- ``engine``: the request goes to the engine exactly as the scenario writes it.
  It is used where the principal is built outside the governor: by the MCP PEP
  (``Agent::"<Watchlight-Agent-Id>"``) and by a framework plugin
  (``Agent::"<agent id>"``, the id the backend resolves, never the name).

A page that gains a policy without a scenario, or a scenario whose policy left
its page, fails here.
"""

from __future__ import annotations

import json
import pathlib
import re
from typing import Dict, List, Tuple

import pytest

import watchlight_engine
from watchlight import Watchlight

ROOT = pathlib.Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "doc_policy_scenarios.json"

#: Markdown read for policies, relative to the repository root.
DOC_GLOBS = ("README.md", "ts/README.md", "docs/**/*.md", "examples/**/*.md")

#: Fences whose policies are not examples to load. A ``diff`` shows an edit
#: (in ``policy-tests-ci``, the weakening the CI gate catches), not a policy set.
SKIPPED_FENCES = {"diff"}

FENCE = re.compile(r"^(`{3,})([^\s`]*)[^\n]*\n(.*?)^\1[ \t]*$", re.S | re.M)
STATEMENT_START = re.compile(r"\b(?:permit|forbid)\s*\(")
QUOTED = re.compile(r"'((?:[^'\\\n]|\\.)*)'")
EFFECT_ANNOTATION = re.compile(r'@enforcement_effect\(\s*"[^"]*"\s*\)\s*')
CATCH_ALL = "permit(principal, action, resource);"

VERDICTS = {"Allow", "Deny", "NeedsApproval"}
CASE_KEYS = {"actor", "principal", "resource", "context", "approved"}
SCENARIO_KEYS = CASE_KEYS | {
    "file", "policy", "path", "agent", "action", "expect", "why", "substitute",
}


def _normalize(statement: str) -> str:
    return " ".join(statement.split())


def _strip_comments(text: str) -> str:
    """Remove ``//`` comments, leaving any ``//`` inside a string."""
    out: List[str] = []
    in_string = False
    i = 0
    while i < len(text):
        ch = text[i]
        if in_string:
            out.append(ch)
            if ch == "\\" and i + 1 < len(text):
                out.append(text[i + 1])
                i += 1
            elif ch == '"':
                in_string = False
        elif ch == '"':
            in_string = True
            out.append(ch)
        elif text.startswith("//", i):
            while i < len(text) and text[i] != "\n":
                i += 1
            continue
        else:
            out.append(ch)
        i += 1
    return "".join(out)


def _split_statements(cedar: str) -> List[str]:
    """Split Cedar text into statements on the ``;`` outside a string."""
    statements: List[str] = []
    current: List[str] = []
    in_string = False
    i = 0
    text = _strip_comments(cedar)
    while i < len(text):
        ch = text[i]
        current.append(ch)
        if in_string:
            if ch == "\\" and i + 1 < len(text):
                current.append(text[i + 1])
                i += 1
            elif ch == '"':
                in_string = False
        elif ch == '"':
            in_string = True
        elif ch == ";":
            statements.append("".join(current))
            current = []
        i += 1
    tail = "".join(current).strip()
    if tail:
        raise AssertionError(f"Cedar text ends without a ';': {tail!r}")
    return [_normalize(s) for s in statements if s.strip()]


def _json_codes(value) -> List[str]:
    if isinstance(value, dict):
        found = []
        for key, item in value.items():
            if key == "code" and isinstance(item, str):
                found.append(item)
            else:
                found.extend(_json_codes(item))
        return found
    if isinstance(value, list):
        return [code for item in value for code in _json_codes(item)]
    return []


def _fence_statements(lang: str, body: str) -> List[str]:
    if lang == "cedar":
        return _split_statements(body)
    if lang == "json":
        texts = _json_codes(json.loads(body))
    else:
        texts = [m.group(1) for m in QUOTED.finditer(body) if STATEMENT_START.search(m.group(1))]
    return [s for text in texts for s in _split_statements(text)]


def doc_files() -> List[pathlib.Path]:
    seen = set()
    files = []
    for pattern in DOC_GLOBS:
        for path in sorted(ROOT.glob(pattern)):
            if "node_modules" in path.parts or path in seen:
                continue
            seen.add(path)
            files.append(path)
    return files


def extract() -> Dict[Tuple[str, str], int]:
    """``(file, statement) -> occurrences`` for every policy in the docs."""
    found: Dict[Tuple[str, str], int] = {}
    for path in doc_files():
        rel = path.relative_to(ROOT).as_posix()
        text = path.read_text(encoding="utf-8")
        for match in FENCE.finditer(text):
            lang, body = match.group(2).lower(), match.group(3)
            if lang in SKIPPED_FENCES or not STATEMENT_START.search(body):
                continue
            statements = _fence_statements(lang, body)
            # Every `permit(` / `forbid(` in the fence must have been read as a
            # statement: a policy in a shape this reader does not know would
            # otherwise go unchecked.
            line = text[: match.start()].count("\n") + 1
            expected = len(STATEMENT_START.findall(_strip_comments(body) if lang == "cedar" else body))
            assert len(statements) == expected, (
                f"{rel}:{line}: read {len(statements)} policy statements from a "
                f"`{lang}` block that has {expected}; teach this test the block's shape"
            )
            for statement in statements:
                found[(rel, statement)] = found.get((rel, statement), 0) + 1
    return found


def load_scenarios() -> List[dict]:
    scenarios = json.loads(FIXTURE.read_text(encoding="utf-8"))
    for i, scenario in enumerate(scenarios):
        where = f"{FIXTURE.name}[{i}]"
        unknown = set(scenario) - SCENARIO_KEYS
        assert not unknown, f"{where}: unknown keys {sorted(unknown)}"
        for key in ("file", "policy", "action"):
            assert key in scenario, f"{where}: missing {key!r}"
        assert scenario.get("path", "governor") in ("governor", "engine"), where
        scenario["policy"] = _normalize(scenario["policy"])
        kind = "forbid" if re.search(r"(^|\s)forbid\s*\(", scenario["policy"]) else "permit"
        default = "Deny" if kind == "forbid" else "Allow"
        expect = scenario.setdefault("expect", default)
        assert expect in VERDICTS, f"{where}: expect must be one of {sorted(VERDICTS)}"
        if expect != default and not (kind == "permit" and expect == "NeedsApproval"):
            assert scenario.get("why"), f"{where}: a {kind} expecting {expect} must say why"
        scenario["kind"] = kind
    return scenarios


SCENARIOS = load_scenarios()


def test_every_doc_policy_has_a_scenario():
    in_docs = set(extract())
    in_fixture = {(s["file"], s["policy"]) for s in SCENARIOS}
    missing = sorted(in_docs - in_fixture)
    stale = sorted(in_fixture - in_docs)
    assert not missing, (
        "policies in the docs with no scenario in "
        f"{FIXTURE.relative_to(ROOT)}:\n" + "\n".join(f"  {f}: {p}" for f, p in missing)
    )
    assert not stale, (
        "scenarios whose policy is no longer in its page:\n"
        + "\n".join(f"  {f}: {p}" for f, p in stale)
    )


def test_the_reader_finds_policies_in_every_shape():
    found = extract()
    langs_seen = {f for f, _ in found}
    # One page per shape, so a reader regression cannot pass as "no policies".
    assert "docs/policies.md" in langs_seen  # cedar blocks
    assert "docs/existing-mcp-gateway.md" in langs_seen  # json "code" values
    assert "README.md" in langs_seen  # a quoted policy in a code sample
    assert len(found) >= 60


def _loaded(policy: str, kind: str) -> List[str]:
    if kind == "forbid":
        return [CATCH_ALL, EFFECT_ANNOTATION.sub("", policy)]
    return [policy]


def _substituted(scenario: dict) -> str:
    policy = scenario["policy"]
    for placeholder, value in scenario.get("substitute", {}).items():
        assert placeholder in policy, f"{placeholder!r} is not in {policy!r}"
        policy = policy.replace(placeholder, value)
    return policy


def _decide_governor(scenario: dict, policies: List[str], tmp_path) -> str:
    gov = Watchlight(agent=scenario.get("agent", "docs-agent"), audit_dir=str(tmp_path))
    for code in policies:
        gov.allow(code)
    case = {k: scenario[k] for k in CASE_KEYS if k in scenario}
    case.update(action=scenario["action"], expect=scenario["expect"])
    report = gov.test([case])
    return report["results"][0]["actual"]


def _decide_engine(scenario: dict, policies: List[str]) -> str:
    engine = watchlight_engine.PolicyEngine()
    for i, code in enumerate(policies):
        engine.add_policy(json.dumps({"id": f"p{i}", "name": f"p{i}", "code": code}))
    request = {
        "principal": scenario["principal"],
        "action": f'Action::"{scenario["action"]}"',
        "resource": scenario.get("resource", "resource"),
        "context": scenario.get("context", {}),
    }
    return json.loads(engine.authorize(json.dumps(request)))["decision"]


@pytest.mark.parametrize(
    "scenario",
    SCENARIOS,
    ids=[f"{s['file']}:{s['kind']}:{s['action']}" for s in SCENARIOS],
)
def test_doc_policy_decides_its_scenario(scenario, tmp_path):
    policies = _loaded(_substituted(scenario), scenario["kind"])
    if scenario.get("path", "governor") == "engine":
        assert "principal" in scenario, "an engine scenario names its principal"
        actual = _decide_engine(scenario, policies)
    else:
        actual = _decide_governor(scenario, policies, tmp_path)
    assert actual == scenario["expect"], (
        f"{scenario['file']}: {scenario['policy']}\n"
        f"expected {scenario['expect']} for its scenario, the engine said {actual}"
    )


def test_a_forbid_that_misses_its_agent_fails_here(tmp_path):
    """The check this file exists for: a forbid naming the agent by a name the
    path never sends forbids nothing, and its scenario fails."""
    scenario = {
        "path": "engine",
        "principal": 'Agent::"2c586ae3-8a2a-5aea-a1a7-211d4c0faed4"',
        "action": "delete",
        "policy": 'forbid(principal == Agent::"research-agent", action == Action::"delete", resource);',
    }
    assert _decide_engine(scenario, _loaded(scenario["policy"], "forbid")) == "Allow"
