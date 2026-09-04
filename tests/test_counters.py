"""``govern.counters`` / ``count_audit_records`` (Python), mirroring the TS suite.

The shared fixture ``tests/fixtures/audit-trail.jsonl`` is asserted to the SAME
numbers as ``ts/test/counters.test.mjs`` — the two packages classify every line
identically. The live-governor tests run the real ``watchlight_engine``.
"""
import datetime
import json
import pathlib
import resource
import time

import pytest

from watchlight import (
    DEFAULT_COUNTERS_MAX_BYTES,
    MAX_COUNTERS_LINE_BYTES,
    MAX_COUNTERS_NESTING,
    MAX_COUNTERS_WINDOW_SECONDS,
    AuditTrailUnreadable,
    count_audit_records,
    parse_window_seconds,
)

FIXTURE = pathlib.Path(__file__).parent / "fixtures" / "audit-trail.jsonl"
NOW = "2026-01-15T12:00:00.000Z"
ALICE = 'User::"alice"'


def at(**kw):
    kw.setdefault("principal", ALICE)
    kw.setdefault("now", NOW)
    return count_audit_records(FIXTURE, **kw)


# ── window grammar ──────────────────────────────────────────────────────────

@pytest.mark.parametrize(
    "spec,seconds",
    [("15m", 900), ("1h", 3600), ("24h", 86400), ("7d", 604800), ("90", 90), (3600, 3600),
     ("366d", MAX_COUNTERS_WINDOW_SECONDS)],
)
def test_window_grammar(spec, seconds):
    assert parse_window_seconds(spec) == seconds


@pytest.mark.parametrize(
    "bad", ["0", "0h", "-1h", "1w", "", "1.5h", "1h ", " 1h", "1H", 0, -5, 1.5, "367d", None, True, {}]
)
def test_window_rejects(bad):
    with pytest.raises(ValueError):
        parse_window_seconds(bad)


# ── fixture: counting semantics (shared with TS) ────────────────────────────

def test_alice_read_allowed_1h():
    r = at(intent="read", window="1h")
    assert r["count"] == 6
    assert r["window"] == {"seconds": 3600, "start": "2026-01-15T11:00:00.000Z", "end": NOW}
    assert (r["principal"], r["intent"], r["resource"], r["outcome"]) == (ALICE, "read", None, "allowed")
    assert r["records"] == 19
    assert r["skipped"] == 6
    assert r["truncated"] is False


@pytest.mark.parametrize(
    "kw,count",
    [
        (dict(intent="read", outcome="denied"), 1),
        (dict(intent="read", outcome="all"), 7),
        (dict(), 8),                                   # any intent: + write + approved wire
        (dict(outcome="denied"), 2),                   # Deny + NeedsApproval hold
        (dict(outcome="all"), 10),                     # allowed + denied == all
        (dict(intent="read", resource="doc/1"), 4),
        (dict(intent="read", resource="doc"), 0),      # exact, not prefix
        (dict(principal='User::"bob"', intent="read"), 1),
        (dict(principal='User::"carol"', intent="read", outcome="denied"), 1),
        (dict(principal='User::"carol"', intent="read"), 0),
        (dict(principal='User::"dave"'), 0),
        (dict(principal="alice"), 0),                  # exact, not substring
        (dict(intent="read", window="15m"), 3),
        (dict(intent="read", window="24h"), 8),        # start boundary + older records
        (dict(intent="read", window=3600), 6),
        (dict(intent="read", window="3600"), 6),
        (dict(intent="read", now="2026-01-15T14:00:00.000+02:00"), 6),
        (dict(intent="read", now="2026-01-15T11:30:00.000Z"), 5),
    ],
)
def test_counts(kw, count):
    assert at(**kw)["count"] == count


def test_default_window_is_1h():
    assert at(intent="read")["count"] == 6


def test_now_as_aware_datetime():
    now = datetime.datetime(2026, 1, 15, 12, 0, 0, tzinfo=datetime.timezone.utc)
    assert at(intent="read", now=now)["count"] == 6
    plus2 = datetime.timezone(datetime.timedelta(hours=2))
    assert at(intent="read", now=datetime.datetime(2026, 1, 15, 14, 0, 0, tzinfo=plus2))["count"] == 6


@pytest.mark.parametrize("bad", [datetime.datetime(2026, 1, 15, 12), "2026-01-15T12:00:00", "yesterday", 5])
def test_now_rejects(bad):
    with pytest.raises(ValueError):
        at(now=bad)


def test_argument_validation():
    with pytest.raises(ValueError):
        at(outcome="any")
    with pytest.raises(TypeError):
        count_audit_records(FIXTURE, principal="", now=NOW)
    with pytest.raises(TypeError):
        count_audit_records(FIXTURE, principal=None, now=NOW)
    with pytest.raises(TypeError):
        at(intent=5)
    with pytest.raises(ValueError):
        at(max_bytes=0)


def test_value_free(capsys):
    r = at(intent="read")
    assert capsys.readouterr() == ("", "")
    s = json.dumps(r)
    assert "not json" not in s and "doc/" not in s and '"d1"' not in s
    assert "11:05" not in s  # only the window bounds carry timestamps


# ── bounded read ────────────────────────────────────────────────────────────

def test_bounded_read():
    size = FIXTURE.stat().st_size
    first_line = len(FIXTURE.read_bytes().split(b"\n")[0]) + 1
    assert DEFAULT_COUNTERS_MAX_BYTES == 64 * 1024 * 1024
    assert at(intent="read", max_bytes=size) == at(intent="read")
    cut = at(intent="read", max_bytes=size - 10)
    assert (cut["count"], cut["records"], cut["skipped"], cut["truncated"]) == (5, 18, 6, True)
    edge = at(intent="read", max_bytes=size - first_line)
    assert (edge["count"], edge["records"], edge["skipped"], edge["truncated"]) == (5, 18, 6, True)
    one = at(intent="read", max_bytes=size - 1)
    assert (one["count"], one["records"], one["truncated"]) == (5, 18, True)
    tiny = at(intent="read", max_bytes=5)
    assert (tiny["count"], tiny["records"], tiny["skipped"], tiny["truncated"]) == (0, 0, 0, True)


def test_multi_chunk_stream(tmp_path):
    p = tmp_path / "audit.jsonl"
    line = json.dumps({"ts": "2026-01-15T11:59:00.000Z", "agent": "a", "principal": ALICE, "intent": "read",
                       "resource": "doc/x".ljust(120, "x"), "decision": "Allow"})
    n = 3000  # ~600 KiB → many 64 KiB chunks, lines split across them
    p.write_text("\n".join([line] * n) + "\n")
    r = count_audit_records(p, ALICE, "read", now=NOW)
    assert (r["count"], r["records"], r["skipped"], r["truncated"]) == (n, n, 0, False)
    p.write_text("\n".join([line] * n))  # no trailing newline
    assert count_audit_records(p, ALICE, now=NOW)["count"] == n
    p.write_text("\n\n   \n")
    r = count_audit_records(p, ALICE, now=NOW)
    assert (r["records"], r["skipped"]) == (0, 0)
    p.write_bytes(b'{"ts":"2026-01-15T11:59:00.000Z","principal":"' + b"\xff\xfe" + b'","decision":"Allow"}\n')
    assert count_audit_records(p, ALICE, now=NOW)["skipped"] == 1


# ── hostile lines are bounded ───────────────────────────────────────────────

def _rec(extra=""):
    return ('{"ts":"2026-01-15T11:59:00.000Z","agent":"a","principal":' + json.dumps(ALICE)
            + ',"intent":"read","resource":"doc/1","decision":"Allow"' + extra + "}")


def _cs(p, **kw):
    r = count_audit_records(p, ALICE, "read", now=NOW, **kw)
    return r["count"], r["skipped"]


def test_bom_line_is_skipped(tmp_path):
    p = tmp_path / "audit.jsonl"
    p.write_text("\ufeff" + _rec() + "\n" + _rec() + "\n", encoding="utf-8")
    assert _cs(p) == (1, 1)


def test_line_and_nesting_caps(tmp_path):
    assert (MAX_COUNTERS_LINE_BYTES, MAX_COUNTERS_NESTING) == (1024 * 1024, 32)
    p = tmp_path / "audit.jsonl"
    p.write_text(_rec(',"pad":"' + "p" * (900 * 1024) + '"') + "\n" + _rec() + "\n")
    assert _cs(p) == (2, 0)  # large but legitimate
    p.write_text("x" * (MAX_COUNTERS_LINE_BYTES + 1) + "\n" + _rec() + "\n" + _rec() + "\n")
    assert _cs(p) == (2, 1)  # over the cap: skipped once, the rest counts
    deep = lambda d: "[" * d + "]" * d
    p.write_text(_rec(',"x":' + deep(5)) + "\n" + _rec(',"x":' + deep(MAX_COUNTERS_NESTING + 1)) + "\n"
                 + _rec(',"x":"' + "[" * 200 + '"') + "\n")
    assert _cs(p) == (2, 1)  # brackets inside strings are not nesting
    p.write_text("{" * 100_000 + "\n" + _rec() + "\n")
    assert _cs(p) == (1, 1)  # skipped without parsing (no RecursionError)


def test_newline_free_tail_is_bounded(tmp_path):
    """A newline-free tail as large as the scan bound: one skipped line, finished
    quickly, and at most the line cap held in memory (not the whole tail)."""
    big = 24 * 1024 * 1024
    p = tmp_path / "audit.jsonl"
    p.write_bytes(b"x" * big)
    rss_before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    t0 = time.monotonic()
    r = count_audit_records(p, ALICE, "read", now=NOW, max_bytes=big)
    elapsed = time.monotonic() - t0
    rss_after = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    assert (r["count"], r["records"], r["skipped"], r["truncated"]) == (0, 0, 1, False)
    assert elapsed < 5.0, elapsed
    # ru_maxrss is bytes on macOS and KiB on Linux; either way far below the tail size.
    growth = rss_after - rss_before
    assert growth < 16 * 1024 * 1024, growth


# ── missing vs unreadable ───────────────────────────────────────────────────

def test_missing_file_is_zero(tmp_path):
    r = count_audit_records(tmp_path / "nope" / "audit.jsonl", ALICE, "read", now=NOW)
    assert (r["count"], r["records"], r["skipped"], r["truncated"], r["window"]["seconds"]) == (0, 0, 0, False, 3600)


def test_directory_is_unreadable(tmp_path):
    with pytest.raises(AuditTrailUnreadable) as ei:
        count_audit_records(tmp_path, ALICE, now=NOW)
    assert ei.value.path == str(tmp_path)
    assert str(ei.value) == "audit trail is not readable"  # fixed text; the path stays on the object
    assert isinstance(ei.value, RuntimeError)


# ── live governor (real engine) ─────────────────────────────────────────────

def test_live_quota(tmp_path):
    pytest.importorskip("watchlight_engine")
    from watchlight import Denied, Watchlight

    g = Watchlight(agent="quota-agent", audit_dir=str(tmp_path / ".watchlight"))
    g.allow('permit(principal, action == Action::"read", resource) when { context.reads_this_hour < 3 };', "quota")
    verdicts = []
    for _ in range(5):
        c = g.counters(principal=ALICE, intent="read", window="1h")
        d = g.authorize(action="read", principal=ALICE, resource="doc/1", context={"reads_this_hour": c["count"]})
        verdicts.append(f"{c['count']}:{d['decision']}")
    assert verdicts == ["0:Allow", "1:Allow", "2:Allow", "3:Deny", "3:Deny"]
    assert g.counters(principal=ALICE, intent="read")["count"] == 3
    assert g.counters(principal=ALICE, intent="read", outcome="denied")["count"] == 2
    assert g.counters(principal=ALICE, intent="read", outcome="all")["count"] == 5
    g.sanitize("mail a@b.com", resource="doc/1")
    assert g.counters(principal=ALICE, intent="read", outcome="all")["count"] == 5
    assert g.counters(principal=ALICE, intent="read")["records"] == 6  # the sanitization line is read, not counted
    assert g.counters(principal='User::"bob"', intent="read")["count"] == 0

    @g.tool("read", principal=lambda: 'User::"bob"', resource=lambda: "doc/2",
            context=lambda: {"reads_this_hour": g.counters(principal='User::"bob"', intent="read")["count"]})
    def read():
        return "body ran"

    out = []
    for _ in range(4):
        try:
            out.append(read())
        except Denied as e:
            out.append(type(e).__name__)
    assert out == ["body ran", "body ran", "body ran", "Denied"]
