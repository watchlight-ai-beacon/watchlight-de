"""Names are bounded: a principal, action, resource or agent name longer than
``MAX_NAME_BYTES`` (UTF-8) is refused before anything is decided or recorded, so
no record the governor writes is too long for the counters to read back. The
TypeScript suite (``ts/test/counters.test.mjs``, "names are bounded") asserts
the same bounds.
"""

import json

import pytest

from watchlight import (
    MAX_COUNTERS_LINE_BYTES,
    MAX_NAME_BYTES,
    SanitizeError,
    ScreenError,
    Watchlight,
    principals,
)

OVER = "x" * (MAX_NAME_BYTES + 1)
AT_LIMIT = "x" * MAX_NAME_BYTES
ALICE = 'User::"alice"'


def governor(tmp_path, agent="bounded"):
    g = Watchlight(agent=agent, audit_dir=str(tmp_path))
    g.allow("permit(principal, action, resource);")
    return g


def lines(tmp_path):
    path = tmp_path / "audit.jsonl"
    return path.read_text().splitlines() if path.exists() else []


def test_the_bound():
    assert MAX_NAME_BYTES == 4096 == principals.MAX_NAME_BYTES
    # Far below the line the counters read: every field at the bound, escaped as
    # the trail escapes it, still fits many times over.
    assert 16 * MAX_NAME_BYTES * 6 < MAX_COUNTERS_LINE_BYTES


@pytest.mark.parametrize(
    "kw,field",
    [
        (dict(action=OVER), "action"),
        (dict(action="read", resource=OVER), "resource"),
        (dict(action="read", principal='User::"' + OVER + '"'), "principal"),
    ],
)
def test_authorize_refuses_an_oversized_name_before_any_record(tmp_path, kw, field):
    g = governor(tmp_path)
    with pytest.raises(TypeError) as err:
        g.authorize(**kw)
    # Value-free: names the field and the bound, never the value.
    assert str(err.value) == f"{field} is longer than the maximum of {MAX_NAME_BYTES} bytes"
    assert "xxxx" not in str(err.value)
    assert lines(tmp_path) == []


def test_the_bound_is_utf8_bytes(tmp_path):
    g = governor(tmp_path)
    two_byte = "é"  # é: two bytes of UTF-8
    assert g.authorize(action="read", resource=two_byte * (MAX_NAME_BYTES // 2))["allowed"]
    with pytest.raises(TypeError):
        g.authorize(action="read", resource=two_byte * (MAX_NAME_BYTES // 2 + 1))
    four_byte = "\U0001f600"
    assert g.authorize(action="read", resource=four_byte * (MAX_NAME_BYTES // 4))["allowed"]
    with pytest.raises(TypeError):
        g.authorize(action="read", resource=four_byte * (MAX_NAME_BYTES // 4) + "x")
    assert len(lines(tmp_path)) == 2


def test_a_name_at_the_bound_is_decided_recorded_and_counted(tmp_path):
    g = governor(tmp_path)
    for _ in range(3):
        assert g.authorize(action="read", principal=ALICE, resource=AT_LIMIT)["allowed"]
    recs = [json.loads(line) for line in lines(tmp_path)]
    assert [r["resource"] for r in recs] == [AT_LIMIT] * 3
    c = g.counters(principal=ALICE, intent="read", resource=AT_LIMIT)
    assert (c["count"], c["unreadable"], c["skipped"]) == (3, 0, 0)


def test_a_governed_tool_with_an_oversized_name_never_runs(tmp_path):
    g = governor(tmp_path)
    ran = []

    @g.tool(intent="read", resource=lambda name: name)
    def fetch(name):
        ran.append(name)
        return "ok"

    with pytest.raises(TypeError):
        fetch(OVER)

    @g.tool(intent=OVER)
    def other():
        ran.append("other")

    with pytest.raises(TypeError):
        other()

    @g.tool(intent="read", principal=lambda: 'User::"' + OVER + '"')
    def third():
        ran.append("third")

    with pytest.raises(TypeError):
        third()
    assert ran == []
    assert lines(tmp_path) == []


def test_an_oversized_agent_name_is_refused(tmp_path):
    with pytest.raises(TypeError, match="agent is longer than the maximum"):
        Watchlight(agent=OVER, audit_dir=str(tmp_path))
    g = governor(tmp_path)
    with pytest.raises(TypeError, match="agent is longer"):
        g.as_(OVER)
    with pytest.raises(TypeError, match="agent is longer"):
        g.authorize(action="read", agent=OVER)
    with pytest.raises(TypeError, match="agent is longer"):
        g.delegate(g, OVER)
    assert Watchlight(agent=AT_LIMIT, audit_dir=str(tmp_path)).agent == AT_LIMIT
    assert lines(tmp_path) == []


def test_an_oversized_agent_name_from_the_environment_is_refused(tmp_path, monkeypatch):
    monkeypatch.setenv("WATCHLIGHT_AGENT", OVER)
    with pytest.raises(TypeError, match="agent is longer"):
        Watchlight(audit_dir=str(tmp_path))


def test_sanitize_and_screen_refuse_oversized_names_before_any_record(tmp_path):
    g = governor(tmp_path)
    with pytest.raises(SanitizeError, match="intent is longer"):
        g.sanitize("mail me at a@example.com", intent=OVER)
    with pytest.raises(SanitizeError, match="resource is longer"):
        g.sanitize("mail me at a@example.com", resource=OVER)
    with pytest.raises(ScreenError, match="intent is longer"):
        g.screen("hello", intent=OVER)
    with pytest.raises(ScreenError, match="resource is longer"):
        g.screen("hello", resource=OVER)
    assert lines(tmp_path) == []


def test_oversized_names_cannot_make_a_quota_under_count(tmp_path):
    """The end-to-end shape of the hardening: a caller cannot slip Allows past a
    quota by making their records too long to count. Oversized names are refused
    before a record exists, and a trail that holds an over-limit line anyway (a
    damaged or foreign one) counts it toward the limit."""
    g = governor(tmp_path)
    for _ in range(3):
        with pytest.raises(TypeError):
            g.authorize(action="read", principal=ALICE, resource="r" * (MAX_COUNTERS_LINE_BYTES + 1))
    assert g.counters(principal=ALICE, intent="read")["count"] == 0  # nothing was allowed
    for _ in range(2):
        assert g.authorize(action="read", principal=ALICE, resource="doc/1")["allowed"]
    # Append an over-limit line by hand, as a damaged trail would hold one.
    with (tmp_path / "audit.jsonl").open("a") as fh:
        fh.write(json.dumps({"ts": "2026-01-15T11:59:00.000Z", "principal": ALICE, "intent": "read",
                             "resource": "r" * MAX_COUNTERS_LINE_BYTES, "decision": "Allow"}) + "\n")
    c = g.counters(principal=ALICE, intent="read")
    assert (c["count"], c["unreadable"]) == (3, 1)
