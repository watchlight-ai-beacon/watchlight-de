"""Names are bounded: a principal, action, resource or agent name longer than
``MAX_NAME_BYTES`` (UTF-8) is refused before anything is decided or recorded, so
no record the governor writes is too long for the counters to read back. The
TypeScript suite (``ts/test/counters.test.mjs``, "names are bounded") asserts
the same bounds.
"""

import json

import pytest

from watchlight import (
    MAX_ACTOR_CHAIN_BYTES,
    MAX_AGENT_NAME_BYTES,
    MAX_COUNTERS_LINE_BYTES,
    MAX_NAME_BYTES,
    MAX_SCOPE_ENTRIES,
    MAX_SCOPE_LIST_BYTES,
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


def test_the_bounds():
    assert MAX_NAME_BYTES == 4096 == principals.MAX_NAME_BYTES
    # Agent::"<name>" must itself be a bounded name.
    assert MAX_AGENT_NAME_BYTES == MAX_NAME_BYTES - len('Agent::""') == 4087
    assert (MAX_SCOPE_ENTRIES, MAX_SCOPE_LIST_BYTES, MAX_ACTOR_CHAIN_BYTES) == (256, 65536, 65536)
    # What the worst case of each record kind measures is asserted in
    # tests/test_record_bounds.py.


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
    at_agent_limit = "a" * MAX_AGENT_NAME_BYTES
    g2 = Watchlight(agent=at_agent_limit, audit_dir=str(tmp_path))
    assert g2.agent == at_agent_limit
    with pytest.raises(TypeError, match="agent is longer than the maximum of 4087 bytes"):
        Watchlight(agent="a" * (MAX_AGENT_NAME_BYTES + 1), audit_dir=str(tmp_path))
    assert lines(tmp_path) == []


def test_an_agent_at_its_limit_derives_a_principal_within_the_name_limit(tmp_path):
    """The principal a call that names none is recorded under, Agent::"<name>",
    fits MAX_NAME_BYTES, so the decision is recorded (and an approval token is
    never spent on a decision that then fails to record)."""
    agent = "a" * MAX_AGENT_NAME_BYTES
    g = Watchlight(agent=agent, audit_dir=str(tmp_path))
    g.allow('@enforcement_effect("require_approval") permit(principal, action == Action::"wire", resource);')
    g.allow('permit(principal, action == Action::"read", resource);')
    assert g.authorize(action="read")["allowed"]
    held = g.authorize(action="wire")
    assert held["needs_approval"]
    token = g.mint_approval(action="wire")
    assert g.authorize(action="wire", approval=token)["approved"]
    recs = [json.loads(line) for line in lines(tmp_path)]
    assert [r["principal"] for r in recs] == [principals.agent(agent)] * 3
    assert len(principals.agent(agent).encode()) == MAX_NAME_BYTES


@pytest.mark.parametrize("bad", [{"k": "v"}, ["a"], 5, b"bytes", 3.5])
def test_a_non_string_action_or_resource_is_refused_before_the_engine(tmp_path, bad):
    g = governor(tmp_path)
    with pytest.raises(TypeError, match="action must be a string"):
        g.authorize(action=bad)
    with pytest.raises(TypeError, match="resource must be a string"):
        g.authorize(action="read", resource=bad)
    ran = []

    @g.tool(intent="read", resource=lambda: {"blob": "x" * (2 * MAX_COUNTERS_LINE_BYTES)})
    def fetch():
        ran.append(1)

    with pytest.raises(TypeError, match="resource must be a string"):
        fetch()
    assert ran == [] and lines(tmp_path) == []


@pytest.mark.parametrize("field", ["action", "resource"])
def test_control_characters_in_action_or_resource_are_refused(tmp_path, field):
    g = governor(tmp_path)
    kw = {"action": "read", field: "a\nb"}
    with pytest.raises(TypeError, match=f"{field} must not contain control characters"):
        g.authorize(**kw)
    assert lines(tmp_path) == []


def test_attenuate_checks_the_sub_agent_name(tmp_path):
    g = governor(tmp_path)
    root = g.scope(tools=["a", "b"])
    for bad in ["x" * (MAX_AGENT_NAME_BYTES + 1), "a\nb", "a\x00b", 5, "   "]:
        with pytest.raises(TypeError, match="attenuate"):
            root.attenuate(tools=["a"], agent=bad)
        with pytest.raises(TypeError, match="preview_attenuate"):
            root.preview_attenuate(tools=["a"], agent=bad)
    assert len(lines(tmp_path)) == 1  # the root only: nothing else was recorded


def test_scope_lists_are_bounded(tmp_path):
    g = governor(tmp_path)
    for kw in [
        {"tools": ["t"] * (MAX_SCOPE_ENTRIES + 1)},
        {"resources": ["r"] * (MAX_SCOPE_ENTRIES + 1)},
        {"intents": ["i"] * (MAX_SCOPE_ENTRIES + 1)},
        {"tools": ["x" * MAX_NAME_BYTES] * 17},  # 17 x 4096 > 64 KiB
        {"tools": ["x" * (MAX_NAME_BYTES + 1)]},
        {"tools": ["a\nb"]},
        {"tools": [{"name": "t"}]},
        {"tools": "search"},  # a bare string is not a list of names
    ]:
        with pytest.raises(TypeError):
            g.scope(**kw)
        with pytest.raises(TypeError):
            g.preview_scope(**kw)
    assert lines(tmp_path) == []
    # At the bounds: accepted.
    g.scope(tools=[f"t{i}" for i in range(MAX_SCOPE_ENTRIES)])
    g.scope(tools=["x" * MAX_NAME_BYTES] * 16)
    root = g.scope(tools=["a"])
    with pytest.raises(TypeError):
        root.attenuate(tools=["a"] * (MAX_SCOPE_ENTRIES + 1))
    with pytest.raises(TypeError):
        g.delegate(root, "sub", tools=["x" * (MAX_NAME_BYTES + 1)])
    assert len(lines(tmp_path)) == 3


def test_the_delegation_chain_is_bounded_in_bytes(tmp_path):
    g = Watchlight(agent="root", audit_dir=str(tmp_path), max_delegation_depth=64)
    g.allow("permit(principal, action, resource);")
    name = "n" * 4000
    gov = g.delegate(g.scope(tools=["a"]), name + "0")
    hops = 1
    with pytest.raises(TypeError, match="delegation chain is longer than the maximum of 65536 bytes"):
        while True:
            gov = g.delegate(gov, name + str(hops))
            hops += 1
    assert sum(len(n.encode()) for n in gov.actor_chain) <= MAX_ACTOR_CHAIN_BYTES
    assert hops == MAX_ACTOR_CHAIN_BYTES // 4002  # every hop that fitted was granted


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
