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
* ``watchlight audit check`` reports unreadable lines, value-free;
* behind the entry checks, the audit funnel itself never writes a line over
  ``MAX_AUDIT_RECORD_BYTES``: it writes a shortened record marked
  ``"oversized": true``, which counts toward every quota.
"""

import asyncio
import hashlib
import json
import pathlib

import pytest

from watchlight import (
    MAX_ACTOR_CHAIN_BYTES,
    MAX_AGENT_NAME_BYTES,
    MAX_COUNTERS_LINE_BYTES,
    MAX_NAME_BYTES,
    MAX_SCOPE_LIST_BYTES,
    SanitizeError,
    ScreenError,
    Watchlight,
    count_audit_records,
    find_unreadable_lines,
    parse_window_seconds,
)
from watchlight._audit import MAX_AUDIT_RECORD_BYTES, AuditTrail
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


class Flip:
    """An iterable that yields one thing on its first pass and another after:
    whatever is checked must be what is used."""

    def __init__(self, first, later):
        self.passes = 0
        self.first, self.later = first, later

    def __iter__(self):
        self.passes += 1
        return iter(self.first if self.passes == 1 else self.later)


class Sneaky(str):
    """A str subclass whose own methods lie about it."""

    def __len__(self):
        return 1

    def encode(self, *a, **k):
        return b"x"

    def strip(self, *a):
        return "x"

    def __str__(self):
        return HUGE

    def __format__(self, spec):
        return HUGE

    def __eq__(self, other):
        return True

    def __hash__(self):
        return 0


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
        _attempt(lambda: g.sanitize("a@example.com", mode=x))
        _attempt(lambda: g.sanitize("a@example.com", types=x))
        _attempt(lambda: g.sanitize("a@example.com", types=[x]))
        _attempt(lambda: g.sanitize("a@example.com", known=x))
        _attempt(lambda: g.sanitize("a@example.com", known=[x]))
        _attempt(lambda: g.sanitize("a@example.com", person_exclusions=x))
        _attempt(lambda: g.sanitize("a@example.com", person_exclusions=[x]))
        _attempt(lambda: g.screen("hello", mode=x))
        _attempt(lambda: g.screen("hello", families=x))
        _attempt(lambda: g.screen("hello", families=[x]))
    # Iterables that change between passes, and str subclasses that lie.
    for flip in (lambda: Flip(["a"], [HUGE]), lambda: Flip(["a"], ["a"] * 10_000)):
        for kw in ("tools", "resources", "intents"):
            _attempt(lambda: g.scope(**{kw: flip()}))
            _attempt(lambda: root.attenuate(**{kw: flip()}))
            _attempt(lambda: g.delegate(root, "f", **{kw: flip()}))
            _attempt(lambda: g.preview_scope(**{kw: flip()}))
    sneaky_short = Sneaky("ok")
    sneaky_long = Sneaky("y" * (2 * MAX_COUNTERS_LINE_BYTES))
    for x in (sneaky_short, sneaky_long):
        _attempt(lambda: Watchlight(agent=x, audit_dir=str(tmp_path)).authorize(action="read"))
        _attempt(lambda: g.as_(x).authorize(action="read"))
        _attempt(lambda: g.authorize(action=x))
        _attempt(lambda: g.authorize(action="read", resource=x, principal=x))
        _attempt(lambda: g.tool(intent=x, resource=x, principal=x)(lambda: "r")())
        _attempt(lambda: g.sanitize("a@example.com", intent=x, resource=x, principal=x, decision_id=x, mode=x))
        _attempt(lambda: g.screen("hello", intent=x, resource=x, principal=x, decision_id=x, mode=x, families=[x]))
        _attempt(lambda: g.scope(tools=[x]))
        _attempt(lambda: root.attenuate(tools=["a"], agent=x))
        _attempt(lambda: g.delegate(root, x))
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


# ── checked once, used once ─────────────────────────────────────────────────

def test_a_scope_list_is_read_once_and_the_checked_list_is_used(tmp_path):
    g = Watchlight(agent="w", audit_dir=str(tmp_path))
    g.allow("permit(principal, action, resource);")
    flip = Flip(["a", "b"], ["x" * (2 * MAX_COUNTERS_LINE_BYTES)])
    root = g.scope(tools=flip)
    assert root.allowed_tools == ["a", "b"] and flip.passes == 1
    flip = Flip(["a"], ["b"])
    child = root.attenuate(tools=flip)
    assert child.allowed_tools == ["a"] and flip.passes == 1
    assert g.preview_scope(tools=Flip(["a"], [])).allowed_tools == ["a"]
    # A generator is read once and used, as it was before these checks.
    assert g.scope(tools=(t for t in ["a", "b"])).allowed_tools == ["a", "b"]
    assert root.attenuate(tools=(t for t in ["a"])).allowed_tools == ["a"]
    assert g.delegate(root, "sub", tools=(t for t in ["b"])).delegated_scope.allowed_tools == ["b"]
    assert_every_line_readable(tmp_path)


def test_a_str_subclass_cannot_misreport_its_length(tmp_path):
    g = Watchlight(agent="w", audit_dir=str(tmp_path))
    g.allow("permit(principal, action, resource);")
    long_one = Sneaky("y" * (MAX_NAME_BYTES + 1))
    for kw in ({"action": long_one}, {"action": "read", "resource": long_one},
               {"action": "read", "principal": long_one}):
        with pytest.raises(TypeError, match="longer than the maximum"):
            g.authorize(**kw)
    with pytest.raises(TypeError, match="longer than the maximum"):
        Watchlight(agent=long_one, audit_dir=str(tmp_path))
    with pytest.raises(SanitizeError):
        g.sanitize("a@example.com", decision_id=Sneaky("d" * 200))
    # A short one is recorded as the plain characters it holds.
    g.authorize(action=Sneaky("read"), resource=Sneaky("doc/1"))
    rec = json.loads(trail_lines(tmp_path)[-1])
    assert (rec["intent"], rec["resource"]) == ("read", "doc/1")


# ── sanitize and screen options ─────────────────────────────────────────────

@pytest.mark.parametrize("mode", ["x" * (2 * MAX_COUNTERS_LINE_BYTES), "TAG", "", 5, None, ["tag"], Sneaky("tag")])
def test_sanitize_refuses_an_unknown_mode_before_any_record(tmp_path, mode):
    g = Watchlight(agent="w", audit_dir=str(tmp_path))
    if isinstance(mode, Sneaky):
        # Its underlying characters are "tag": accepted, recorded as plain "tag".
        g.sanitize("a@example.com", mode=mode)
        assert json.loads(trail_lines(tmp_path)[-1])["mode"] == "tag"
        return
    with pytest.raises(SanitizeError, match="unknown mode"):
        g.sanitize("a@example.com", mode=mode)
    assert trail_lines(tmp_path) == []


@pytest.mark.parametrize("bad", ["EMAIL", [5], 7, b"EMAIL"])
def test_sanitize_refuses_malformed_types(tmp_path, bad):
    g = Watchlight(agent="w", audit_dir=str(tmp_path))
    with pytest.raises(SanitizeError, match="types must be"):
        g.sanitize("a@example.com", types=bad)
    assert trail_lines(tmp_path) == []


@pytest.mark.parametrize("kw", [{"mode": "x" * 5000}, {"mode": 5}, {"families": "ROLE_SWITCH"},
                                {"families": [5]}, {"families": 7}, {"families": ["x" * 5000]}])
def test_screen_refuses_malformed_options_before_any_record(tmp_path, kw):
    g = Watchlight(agent="w", audit_dir=str(tmp_path))
    with pytest.raises(ScreenError):
        g.screen("hello", **kw)
    assert trail_lines(tmp_path) == []


# ── the funnel backstop ─────────────────────────────────────────────────────

def test_the_funnel_shortens_an_oversized_record_and_never_drops_it(tmp_path):
    """Calls the funnel directly, past every entry check, with a 2 MiB field."""
    seen = []
    trail = AuditTrail(tmp_path / "audit.jsonl", sink=seen.append)
    huge = "p" * (2 * 1024 * 1024)
    trail.write({"ts": "2026-01-15T11:59:00.000Z", "agent": "a", "principal": huge, "intent": "read",
                 "event": "decision", "resource": "doc/1", "decision": "Allow"})
    [line] = trail_lines(tmp_path)
    assert len(line) <= MAX_AUDIT_RECORD_BYTES
    rec = json.loads(line)
    digest = hashlib.sha256(huge.encode()).hexdigest()
    assert rec == {"ts": "2026-01-15T11:59:00.000Z", "agent": "a",
                   "principal": {"omitted": "oversized", "bytes": len(huge), "sha256": digest},
                   "intent": "read", "event": "decision", "resource": "doc/1", "decision": "Allow",
                   "oversized": True}
    assert seen == [rec]  # the sink gets exactly the line
    assert huge[:64].encode() not in line  # value-free
    # It counts toward every query, whatever the principal, filters or outcome.
    for principal, outcome in (("p", "allowed"), ('User::"x"', "denied"), ("q", "all")):
        r = count_audit_records(tmp_path / "audit.jsonl", principal, "anything", now="2026-01-15T12:00:00Z",
                                outcome=outcome)
        assert (r["count"], r["unreadable"]) == (1, 1)
    assert find_unreadable_lines(tmp_path / "audit.jsonl")["findings"] == [{"line": 1, "reason": "oversized-record"}]


def test_the_funnel_shortens_the_largest_fields_first(tmp_path):
    trail = AuditTrail(tmp_path / "audit.jsonl")
    record = {"ts": "t", "event": "attenuation"}
    record.update({f"f{i}": "v" * (100 * 1024 + i) for i in range(10)})  # ~1 MiB in total
    record["bad"] = float("nan")  # not JSON: replaced, never written as NaN
    trail.write(record)
    [line] = trail_lines(tmp_path)
    rec = json.loads(line)
    assert len(line) <= MAX_AUDIT_RECORD_BYTES and rec["oversized"] is True
    assert rec["bad"] == {"omitted": "unserializable"}
    shortened = sorted(k for k, v in rec.items() if isinstance(v, dict))
    kept = sorted(k for k in rec if k.startswith("f") and isinstance(rec[k], str))
    # The largest went first; the rest were kept whole.
    assert all(int(a[1:]) > int(b[1:]) for a in shortened if a != "bad" for b in kept)
    assert kept and (rec["ts"], rec["event"]) == ("t", "attenuation")


def test_a_record_within_the_bound_is_written_unchanged(tmp_path):
    trail = AuditTrail(tmp_path / "audit.jsonl")
    record = {"ts": "t", "principal": "p" * (MAX_AUDIT_RECORD_BYTES - 64)}
    trail.write(record)
    assert json.loads(trail_lines(tmp_path)[0]) == record


def test_audit_check_limit_and_missing_subcommand(tmp_path, capsys):
    assert cli_main(["audit", "check", str(tmp_path / "x.jsonl"), "--limit", "-1"]) == 2
    assert "non-negative" in capsys.readouterr().err
    assert cli_main(["audit"]) == 2
    assert "missing subcommand" in capsys.readouterr().err


# ── the backstop: linear, depth-bounded, collision-free, same threshold ─────

def test_shortening_is_linear_in_the_number_of_fields():
    import time

    from watchlight._audit import bounded_line

    record = {f"k{i}": "v" * 300 for i in range(6000)}
    started = time.perf_counter()
    line = bounded_line(record)
    elapsed = time.perf_counter() - started
    assert elapsed < 0.5, elapsed
    assert len(line) <= MAX_AUDIT_RECORD_BYTES and json.loads(line)["oversized"] is True


def _nested(depth):
    value = []
    for _ in range(depth - 1):
        value = [value]
    return value


def test_the_backstop_never_writes_a_line_nested_too_deep(tmp_path):
    from watchlight import _audit, _counters

    assert _audit._MAX_NESTING == _counters.MAX_COUNTERS_NESTING
    trail = AuditTrail(tmp_path / "audit.jsonl")
    # A value 31 deep sits at depth 32 in the record: the deepest the counters accept.
    trail.write({"ts": "t", "x": _nested(31)})
    trail.write({"ts": "t", "x": _nested(32), "y": "kept"})
    trail.write({"ts": "t", "x": _nested(5000)})
    first, second, third = (json.loads(line) for line in trail_lines(tmp_path))
    assert first == {"ts": "t", "x": _nested(31)}
    assert second["x"]["omitted"] == "too-deep" and second["y"] == "kept" and second["oversized"] is True
    assert third["x"]["omitted"] in ("too-deep", "unserializable") and third["oversized"] is True
    found = find_unreadable_lines(tmp_path / "audit.jsonl")
    assert found["findings"] == [{"line": 2, "reason": "oversized-record"}, {"line": 3, "reason": "oversized-record"}]


def test_a_renamed_key_never_overwrites_another():
    from watchlight._audit import bounded_line

    record = {1: "one", "field_0": "kept", 2: "x" * (600 * 1024), "k" * 65: "long key"}
    out = json.loads(bounded_line(record))
    assert out["field_0"] == "kept"
    values = sorted(str(v) for k, v in out.items() if k != "oversized" and not isinstance(v, dict))
    assert values == ["kept", "long key", "one"]
    assert len(out) == 5  # four fields, none lost, plus "oversized"


@pytest.mark.parametrize("count,shortened", [(87_000, False), (88_000, True)])
def test_the_threshold_is_measured_as_written_and_matches_typescript(count, shortened):
    """é is written as \\u00e9 (6 bytes): 87,000 of them fit 512 KiB, 88,000 do
    not. The TypeScript lane measures the same way (ts/test/counters.test.mjs)."""
    from watchlight._audit import bounded_line

    out = json.loads(bounded_line({"ts": "t", "principal": "é" * count}))
    assert ("oversized" in out) is shortened


# ── the framework-plugin path ───────────────────────────────────────────────

PLUGIN_POLICIES = [
    {"name": "everything", "code": "permit(principal, action, resource);"},
    {
        "name": "quarantine-on-exfiltrate",
        "code": '@enforcement_effect("quarantine")\n'
        'forbid(principal, action == Action::"exfiltrate", resource);',
    },
]


def _plugin_modules():
    import importlib

    from watchlight.integrations import INTEGRATIONS

    modules = []
    for name in sorted(INTEGRATIONS):
        try:
            importlib.import_module(INTEGRATIONS[name].plugin_module)
        except ImportError:
            continue
        modules.append(importlib.import_module(f"watchlight.{name}"))
    return modules


async def _attempt_async(fn):
    try:
        await fn()
    except Exception:  # noqa: BLE001 — refusals are expected; the trail is what is checked
        pass


def test_no_plugin_decision_writes_an_unreadable_or_oversized_line(tmp_path, monkeypatch, capsys):
    """The plugin path applies the direct path's bounds at the decision: an odd
    principal, action, resource or execution id is refused before the engine,
    and nothing it writes is unreadable or shortened."""
    pytest.importorskip("watchlight_core")
    from watchlight.inprocess import in_process_backend

    monkeypatch.delenv("WATCHLIGHT_APDP_URL", raising=False)
    audit = tmp_path / "audit.jsonl"
    backend = in_process_backend(PLUGIN_POLICIES, audit_path=str(audit))
    odd = [x for x in ODD if x is not None] + [Sneaky("y" * (2 * MAX_COUNTERS_LINE_BYTES)), Sneaky("ok")]

    async def drive():
        assert (await backend.authorize('Agent::"a"', 'Action::"read"', 'Tool::"x"'))["decision"] == "Allow"
        for x in odd:
            await _attempt_async(lambda: backend.authorize(x, 'Action::"read"', 'Tool::"x"'))
            await _attempt_async(lambda: backend.authorize('Agent::"a"', x, 'Tool::"x"'))
            await _attempt_async(lambda: backend.authorize('Agent::"a"', 'Action::"read"', x))
            await _attempt_async(lambda: backend.authorize('Agent::"a"', 'Action::"read"', 'Tool::"x"', execution_id=x))
        for module in _plugin_modules():
            plugin = module.governed_plugin(PLUGIN_POLICIES, audit_path=str(audit))
            async with await plugin.start_run("battery-agent") as handle:
                for x in odd:
                    await _attempt_async(lambda: handle.authorize_action(x, 'Tool::"x"'))
                    await _attempt_async(lambda: handle.authorize_action('Action::"read"', x))
                    await _attempt_async(lambda: handle.authorize_action('Action::"read"', 'Tool::"x"', principal=x))
                    await _attempt_async(lambda: handle.authorize_action_detailed(x, x, principal=x))

    asyncio.run(drive())
    capsys.readouterr()
    assert trail_lines(tmp_path)
    assert_every_line_readable(tmp_path)


def test_plugin_refusals_after_a_quarantine_never_record_an_oversized_name(tmp_path, monkeypatch, capsys):
    """After a quarantine the handle refuses calls itself, without asking the
    backend; those refusals are recorded from the call's own terms. A term that
    breaks the bounds is replaced by a value-free marker and the record is
    marked oversized, so it counts toward every quota and is never written."""
    pytest.importorskip("watchlight_core")
    from watchlight_core import AgentQuarantinedError, SubtreeSeveredError

    monkeypatch.delenv("WATCHLIGHT_APDP_URL", raising=False)
    modules = _plugin_modules()
    if not modules:
        pytest.skip("no framework plugin installed")
    audit = tmp_path / "audit.jsonl"
    plugin = modules[0].governed_plugin(PLUGIN_POLICIES, audit_path=str(audit))
    huge = "z" * (2 * MAX_COUNTERS_LINE_BYTES)

    async def run():
        async with await plugin.start_run("contained-agent") as handle:
            with pytest.raises((AgentQuarantinedError, SubtreeSeveredError)):
                await handle.authorize_action('Action::"exfiltrate"', 'Tool::"x"')
            for args in ((huge, 'Tool::"x"'), ('Action::"read"', huge), ('Action::"read"', 'Tool::"a\nb"')):
                with pytest.raises((AgentQuarantinedError, SubtreeSeveredError)):
                    await handle.authorize_action(*args)

    asyncio.run(run())
    capsys.readouterr()
    lines = trail_lines(tmp_path)
    assert all(len(line) < 64 * 1024 for line in lines)
    decisions = [json.loads(line) for line in lines if b'"event": "decision"' in line]
    assert [d.get("oversized") for d in decisions] == [None, True, True, True]
    assert huge[:64].encode() not in audit.read_bytes()
    # Each marked refusal counts toward every quota (fail-closed), so a refusal
    # with a refused name can never make a denied-count under-count.
    r = count_audit_records(audit, 'User::"anyone"', outcome="denied")
    assert (r["count"], r["unreadable"]) == (3, 3)


def test_a_plugin_agent_name_is_never_refused_and_never_written_oversized(tmp_path, monkeypatch, capsys):
    """Agent names come from start_run, which must never raise for them (a
    framework's instrumentation may swallow the error). One over the bound is
    replaced by a marker in the record, which is marked oversized."""
    pytest.importorskip("watchlight_core")
    monkeypatch.delenv("WATCHLIGHT_APDP_URL", raising=False)
    modules = _plugin_modules()
    if not modules:
        pytest.skip("no framework plugin installed")
    audit = tmp_path / "audit.jsonl"
    plugin = modules[0].governed_plugin(PLUGIN_POLICIES, audit_path=str(audit))
    long_name = "n" * (MAX_AGENT_NAME_BYTES + 1)

    async def run():
        async with await plugin.start_run(long_name) as handle:
            assert await handle.authorize_action('Action::"read"', 'Tool::"x"')

    asyncio.run(run())
    capsys.readouterr()
    [decision] = [json.loads(line) for line in trail_lines(tmp_path) if b'"event": "decision"' in line]
    assert decision["oversized"] is True and decision["agent"]["omitted"] == "oversized"
    assert long_name.encode() not in audit.read_bytes()
