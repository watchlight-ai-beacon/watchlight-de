"""The SDK never writes a line the counters cannot read.

A line the counters cannot read counts toward every quota, and never ages out of
a window, so a write path that could produce one would let a caller exhaust
every quota. This file makes "the SDK never writes an unreadable line" a tested
invariant:

* the worst case of every record kind — every name at its bound, the longest
  delegation chain, the characters JSON escapes most — is built through the
  public API and measured against ``MAX_COUNTERS_LINE_BYTES``;
* every public write path is driven with oversized and odd inputs, and the trail
  is then checked line by line with the counters' own reader;
* the two lanes classify crafted lines identically (the shared fixture
  ``tests/fixtures/counters-parity.jsonl``, asserted by
  ``ts/test/counters.test.mjs`` too);
* ``watchlight audit check`` reports unreadable lines, value-free.
"""

import asyncio
import json
import pathlib

import pytest

from watchlight import (
    MAX_ACTOR_CHAIN_BYTES,
    MAX_AGENT_NAME_BYTES,
    MAX_COUNTERS_LINE_BYTES,
    MAX_NAME_BYTES,
    MAX_SCOPE_LIST_BYTES,
    Watchlight,
    count_audit_records,
    find_unreadable_lines,
    parse_window_seconds,
)
from watchlight.cli import main as cli_main

FIXTURES = pathlib.Path(__file__).parent / "fixtures"
SECRET = "k" * 48
#: Characters that cost the most once escaped: two-byte é becomes é in
#: Python's output (3x), a quote or backslash doubles (and doubles again inside
#: the engine's reason text), an astral character becomes a surrogate pair.
FILLS = ["é", '"', "\\", "\U0001f600"]


def fill(ch, nbytes):
    """The longest run of ``ch`` that fits ``nbytes`` of UTF-8."""
    return ch * (nbytes // len(ch.encode("utf-8")))


def trail_lines(tmp_path):
    path = tmp_path / "audit.jsonl"
    return path.read_bytes().split(b"\n")[:-1] if path.exists() else []


def assert_every_line_readable(tmp_path):
    lines = trail_lines(tmp_path)
    longest = max((len(line) for line in lines), default=0)
    assert longest < MAX_COUNTERS_LINE_BYTES, longest
    found = find_unreadable_lines(tmp_path / "audit.jsonl")
    assert found["total"] == 0, found
    return longest


# ── the worst case of every record kind ─────────────────────────────────────

def deepest_governor(tmp_path, ch):
    """A governor delegated 64 levels deep (the longest chain, 65 names) whose
    chain holds MAX_ACTOR_CHAIN_BYTES, every name of characters ``ch``."""
    per_name = MAX_ACTOR_CHAIN_BYTES // 65
    names = [fill(ch, per_name - 2) + f"{i:02d}" for i in range(65)]
    assert sum(len(n.encode()) for n in names) <= MAX_ACTOR_CHAIN_BYTES
    g = Watchlight(agent=names[0], audit_dir=str(tmp_path), max_delegation_depth=64,
                   signing_secret=SECRET)
    g.allow("permit(principal, action, resource);")
    tools = [fill(ch, MAX_NAME_BYTES - 2) + f"{i:02d}" for i in range(MAX_SCOPE_LIST_BYTES // MAX_NAME_BYTES)]
    gov = g.delegate(g.scope(tools=tools, resources=tools, intents=tools), names[1])
    for name in names[2:]:
        gov = g.delegate(gov, name)
    assert len(gov.actor_chain) == 65
    return gov, tools


@pytest.mark.parametrize("ch", FILLS)
def test_the_worst_case_of_every_record_kind_fits_the_line_limit(tmp_path, ch):
    gov, tools = deepest_governor(tmp_path, ch)
    name = fill(ch, MAX_NAME_BYTES)
    principal = 'User::"' + fill(ch, MAX_NAME_BYTES - len('User::""')) + '"'
    # decision
    assert gov.authorize(action=name, principal=principal, resource=name)["allowed"]

    # egress, from a hook that tries to rewrite the names it is handed
    def hook(_result, info):
        info["intent"] = info["resource"] = "x" * (2 * MAX_COUNTERS_LINE_BYTES)

    @gov.tool(intent=name, principal=principal, resource=name, on_result=hook)
    def body():
        return "ok"

    assert body() == "ok"
    # sanitization and screening
    gov.sanitize("mail a@example.com", intent=name, resource=name, principal="p" * 128,
                 decision_id="d" * 128)
    gov.screen("hello", intent=name, resource=name, principal="p" * 128, decision_id="d" * 128)
    # attenuation: a refused request whose reason echoes names from every list,
    # recorded with the full chain; and a granted one.
    scope = gov.delegated_scope
    outside = [fill(ch, MAX_NAME_BYTES - 3) + f"z{i:02d}" for i in range(MAX_SCOPE_LIST_BYTES // MAX_NAME_BYTES)]
    with pytest.raises(Exception):
        scope.attenuate(tools=outside, resources=outside, intents=outside, time_budget_seconds=10**9)
    longest = assert_every_line_readable(tmp_path)
    # The margin, for the record: well inside the limit.
    assert longest < 0.5 * MAX_COUNTERS_LINE_BYTES, longest


def test_a_decision_at_every_bound_measures(tmp_path):
    """The decision record alone, with the longest names everywhere and the
    longest chain, in the character Python escapes most (é → \\u00e9)."""
    gov, _tools = deepest_governor(tmp_path, "é")
    name = fill("é", MAX_NAME_BYTES)
    principal = 'User::"' + fill("é", MAX_NAME_BYTES - 9) + '"'
    gov.authorize(action=name, principal=principal, resource=name)
    decision = json.loads(trail_lines(tmp_path)[-1])
    assert decision["event"] == "decision" and len(decision["actor_chain"]) == 65
    assert len(trail_lines(tmp_path)[-1]) < 0.35 * MAX_COUNTERS_LINE_BYTES


# ── every public write path, driven with odd inputs ─────────────────────────

HUGE = "h" * (2 * MAX_COUNTERS_LINE_BYTES)
ODD = [
    HUGE,
    "a\nb",
    "\x00",
    " ",
    "\ud800",
    "",
    "   ",
    {"blob": HUGE},
    [HUGE],
    10 ** 5000,
    b"bytes",
    3.5,
    float("nan"),
    None,
    True,
]


def _attempt(fn):
    try:
        out = fn()
        if asyncio.iscoroutine(out):
            asyncio.run(out)
    except Exception:  # noqa: BLE001 — refusals are expected; the trail is what is checked
        pass


def test_no_public_write_path_writes_an_unreadable_line(tmp_path, capsys):
    g = Watchlight(agent="w", audit_dir=str(tmp_path), signing_secret=SECRET)
    g.allow("permit(principal, action, resource);")
    root = g.scope(tools=["a", "b"])
    sub = g.delegate(root, "sub", tools=["a"])
    for x in ODD:
        _attempt(lambda: Watchlight(agent=x, audit_dir=str(tmp_path)))
        _attempt(lambda: g.as_(x))
        _attempt(lambda: g.authorize(action=x))
        _attempt(lambda: g.authorize(action="read", resource=x))
        _attempt(lambda: g.authorize(action="read", principal=x))
        _attempt(lambda: g.authorize(action="read", agent=x))
        _attempt(lambda: g.authorize(action="read", context={"k": x}))
        _attempt(lambda: g.authorize(action="read", approval=x))
        _attempt(lambda: sub.authorize(action=x, resource=x))
        _attempt(lambda: g.mint_approval(action=x, resource=x, principal=x))
        _attempt(lambda: g.tool(intent=x)(lambda: "r")())
        _attempt(lambda: g.tool(intent="read", resource=lambda: x)(lambda: "r")())
        _attempt(lambda: g.tool(intent="read", principal=lambda: x)(lambda: "r")())

        def mutate(_r, info, x=x):
            for key in ("intent", "resource", "principal", "decision_id"):
                info[key] = x

        _attempt(lambda: g.tool(intent="read", on_result=mutate)(lambda: "r")())

        async def body():
            return "r"

        _attempt(lambda: g.tool(intent="read", on_result=mutate)(body)())
        _attempt(lambda: g.tool(intent="read", on_result=mutate, on_result_timeout_ms=1000)(lambda: "r")())
        for kw in ("intent", "resource", "principal", "decision_id", "agent"):
            _attempt(lambda: g.sanitize("a@example.com", **{kw: x}))
            _attempt(lambda: g.screen("hello", **{kw: x}))
        _attempt(lambda: g.sanitize(x))
        _attempt(lambda: g.screen(x))
        for kw in ("tools", "resources", "intents"):
            _attempt(lambda: g.scope(**{kw: x}))
            _attempt(lambda: g.scope(**{kw: [x]}))
            _attempt(lambda: root.attenuate(**{kw: [x]}))
            _attempt(lambda: g.delegate(root, "d", **{kw: [x]}))
        _attempt(lambda: g.scope(tools=["a"], time_budget_seconds=x))
        _attempt(lambda: root.attenuate(tools=["a"], agent=x))
        _attempt(lambda: root.attenuate(tools=["a"], time_budget_seconds=x))
        _attempt(lambda: g.delegate(root, x))
        _attempt(lambda: g.delegate(sub, x))
        _attempt(lambda: g.scope_from_token(x))
    capsys.readouterr()
    assert trail_lines(tmp_path)  # the battery did write records
    assert_every_line_readable(tmp_path)


# ── the two lanes classify crafted lines identically ────────────────────────

def test_crafted_lines_classify_as_in_typescript():
    expected = json.loads((FIXTURES / "counters-parity.expected.json").read_text())
    found = find_unreadable_lines(FIXTURES / "counters-parity.jsonl")
    assert found["lines"] == expected["lines"]
    assert found["findings"] == expected["expected"]
    r = count_audit_records(FIXTURES / "counters-parity.jsonl", 'User::"alice"', "read",
                            now="2026-01-15T12:00:00.000Z")
    # The five well-formed matching decisions count; so do the three with an
    # unreadable ts (they match) and the six lines that cannot be read at all.
    assert (r["count"], r["unreadable"]) == (14, 9)


@pytest.mark.parametrize("spec", ["1h\n", "١h", "１h", "1١"])
def test_window_grammar_is_ascii_only(spec):
    with pytest.raises(ValueError):
        parse_window_seconds(spec)


def test_the_integer_limit_does_not_depend_on_the_interpreter(monkeypatch, tmp_path):
    """Python's own int limit can be changed by the environment; the counters
    apply 4300 digits regardless."""
    import sys

    if not hasattr(sys, "set_int_max_str_digits"):
        pytest.skip("no int digit limit on this interpreter")
    old = sys.get_int_max_str_digits()
    try:
        for limit in (0, 640, 100_000):
            sys.set_int_max_str_digits(limit)
            found = find_unreadable_lines(FIXTURES / "counters-parity.jsonl")
            expected = json.loads((FIXTURES / "counters-parity.expected.json").read_text())
            assert found["findings"] == expected["expected"], limit
    finally:
        sys.set_int_max_str_digits(old)


# ── watchlight audit check ──────────────────────────────────────────────────

def test_audit_check_lists_unreadable_lines_value_free(tmp_path, capsys):
    path = tmp_path / "audit.jsonl"
    secret_word = "s3cr3t-value"
    path.write_bytes(
        b'{"ts":"2026-01-15T11:59:00Z","principal":"p","decision":"Allow"}\n'
        + b'{"x":"' + secret_word.encode() + b'"' + b"\n"
        + b'{"pad":"' + b"p" * MAX_COUNTERS_LINE_BYTES + b'"}\n'
        + b'"' + b"\xff" + b'"\n'
        + b"[" * 40 + b"]" * 40 + b"\n"
        + b"[1]\n"
        + b'{"ts":"never","principal":"p","decision":"Allow","note":"' + secret_word.encode() + b'"}\n'
        + b'{"event_type":"execution_started"}\n'
    )
    assert cli_main(["audit", "check", str(path)]) == 1
    out = capsys.readouterr().out
    assert secret_word not in out and "ppp" not in out
    for line, reason in [(2, "not JSON"), (3, f"longer than {MAX_COUNTERS_LINE_BYTES} bytes"),
                         (4, "not valid UTF-8"), (5, "nested deeper than 32 levels"),
                         (6, "not a JSON object"), (7, "a decision whose ts cannot be read")]:
        assert f"line {line}: {reason}" in out
    assert "line 1:" not in out and "line 8:" not in out
    assert "never age out of a window" in out
    # The same reader as the counters: what it lists is exactly what counts.
    r = count_audit_records(path, "p", now="2026-01-15T12:00:00Z")
    assert r["unreadable"] == 6

    assert cli_main(["audit", "check", str(path), "--limit", "2"]) == 1
    assert "and 4 more" in capsys.readouterr().out

    clean = tmp_path / "clean.jsonl"
    clean.write_text('{"ts":"2026-01-15T11:59:00Z","principal":"p","decision":"Allow"}\n')
    assert cli_main(["audit", "check", str(clean)]) == 0
    assert cli_main(["audit", "check", str(tmp_path / "missing.jsonl")]) == 0
    assert cli_main(["audit", "check", str(tmp_path)]) == 2
    capsys.readouterr()
