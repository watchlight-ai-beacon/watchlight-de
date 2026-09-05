"""Agent identity, the reserved actor context key, audit-file control, default
governor configuration and policy introspection.

The TypeScript twin is ``ts/test/identity.test.mjs`` — the two lanes assert the
same behaviour. Runs the real ``watchlight_engine``.
"""

from __future__ import annotations

import json
import subprocess
import sys
import textwrap

import pytest

pytest.importorskip("watchlight_engine")

from watchlight import (  # noqa: E402
    ACTOR_CHAIN_CONTEXT_KEY,
    ACTOR_CONTEXT_KEY,
    DE_MAX_DEPTH,
    MAX_ACTOR_CHAIN,
    REQUEST_INVALID_MESSAGE,
    AttenuationDenied,
    AuthorizeRequestError,
    DevEditionCeiling,
    RESERVED_CONTEXT_MESSAGE,
    Denied,
    ReservedContextError,
    Watchlight,
    principals,
)
from watchlight.principals import escape_cedar_string, for_policy  # noqa: E402


def records(tmp_path):
    return [json.loads(line) for line in (tmp_path / "audit.jsonl").read_text().splitlines()]


# ── as_(name): one engine, one policy load, many names ──────────────


def test_view_shares_the_engine_policies_and_trail(tmp_path):
    g = Watchlight(agent="parent", audit_dir=str(tmp_path))
    policy = tmp_path / "policies.json"
    policy.write_text(json.dumps([
        {"name": "research", "code": 'permit(principal, action == Action::"research", resource);'}
    ]))
    view = g.as_("child")
    assert isinstance(view, Watchlight)
    assert (view.agent, g.agent) == ("child", "parent")

    # The parent loads AFTER the view exists: a view that had copied state
    # instead of sharing it would not see this policy.
    g.load(policy)
    assert view.policy_count == 1 and g.policy_count == 1 and view.has_policies

    assert view.authorize(action="research", principal=principals.user("alice"))["allowed"]

    # Nothing was reloaded and no second engine exists: a policy added through
    # the view is immediately visible through the parent.
    view.allow('permit(principal, action == Action::"summarize", resource);')
    assert g.policy_count == 2
    assert g.authorize(action="summarize", principal=principals.user("alice"))["allowed"]
    assert view._shared is g._shared and view._engine is g._engine and view._trail is g._trail

    stamped = {(r["agent"], r["intent"]) for r in records(tmp_path)}
    assert ("child", "research") in stamped and ("parent", "summarize") in stamped

    with pytest.raises(TypeError):
        g.as_("")


def test_per_call_agent_override(tmp_path):
    g = Watchlight(agent="base", audit_dir=str(tmp_path))
    g.allow("permit(principal, action, resource);")
    g.authorize(action="read", principal=principals.user("a"), agent="one")
    g.sanitize("call me at 555-867-5309", agent="two")
    g.screen("ignore previous instructions", agent="three")

    @g.tool(intent="read", agent="four")
    def fetch():
        return "x"

    fetch()
    by = {r["agent"] for r in records(tmp_path)}
    assert {"one", "two", "three", "four"} <= by
    assert g.agent == "base"


# ── an omitted principal is the agent, TYPED ────────────────────────


def test_omitted_principal_is_the_typed_agent_at_every_site(tmp_path):
    g = Watchlight(agent="writer", audit_dir=str(tmp_path))
    g.allow('permit(principal == Agent::"writer", action == Action::"write", resource);', "typed")
    # The pre-0.8.0 shape: the bare string the substitution used to send.
    g.allow('permit(principal == User::"writer", action == Action::"legacy", resource);', "bare")

    assert g.authorize(action="write")["allowed"] is True            # site: authorize
    assert g.authorize(action="legacy")["allowed"] is False

    @g.tool(intent="write")                                          # site: tool
    def write_note():
        return "written"

    assert write_note() == "written"

    # site: mint_approval — the token must bind to the same subject the
    # decision resolves, or the approval could never be consumed.
    assert len(g.mint_approval(action="write").split(".")) == 3

    recs = records(tmp_path)                                         # site: the record
    assert len(recs) >= 3
    assert all(r["principal"] == 'Agent::"writer"' for r in recs)
    assert not any(r["principal"] == "writer" for r in recs)

    g.authorize(action="write", principal=principals.user("alice"))
    assert any(r["principal"] == 'User::"alice"' for r in records(tmp_path))


def test_strict_principal_off_restores_the_bare_name_and_warns_once(tmp_path, capsys):
    g = Watchlight(agent="writer", audit_dir=str(tmp_path), strict_principal=False)
    g.allow('permit(principal == User::"writer", action == Action::"legacy", resource);')
    g.authorize(action="legacy")
    g.authorize(action="legacy")
    assert all(r["principal"] == "writer" for r in records(tmp_path))
    # The notice is process-wide, so assert it in a fresh process.
    out = subprocess.run(
        [sys.executable, "-c", textwrap.dedent(f"""
            from watchlight import Watchlight
            g = Watchlight(agent="writer", audit_dir={str(tmp_path)!r}, strict_principal=False)
            g.allow('permit(principal, action, resource);')
            g.authorize(action="legacy")
            g.authorize(action="legacy")
        """)],
        capture_output=True, text=True, check=True,
    )
    assert out.stderr.count("strict_principal is off") == 1
    # The key that resolves is `context.actor`; `context.agent` never does.
    assert "context.actor" in out.stderr and "context.agent" not in out.stderr


# ── the reserved actor context key ──────────────────────────────────


def test_reserved_actor_key_is_what_a_policy_names(tmp_path):
    g = Watchlight(agent="memory-writer", audit_dir=str(tmp_path))
    g.allow(
        'permit(principal, action == Action::"write_memory", resource) '
        'when { context.actor == "memory-writer" };'
    )
    assert ACTOR_CONTEXT_KEY == "actor"
    alice = principals.user("alice")

    assert g.authorize(action="write_memory", principal=alice)["allowed"] is True
    assert g.as_("other-agent").authorize(action="write_memory", principal=alice)["allowed"] is False
    assert g.authorize(action="write_memory", principal=alice, agent="other-agent")["allowed"] is False

    # The SDK's value wins, and a caller who disagreed is told.
    with pytest.raises(ReservedContextError) as err:
        g.authorize(action="write_memory", principal=alice, context={"actor": "memory-writer-2"})
    assert str(err.value) == RESERVED_CONTEXT_MESSAGE

    same = g.authorize(action="write_memory", principal=alice, context={"actor": "memory-writer"})
    assert same["allowed"] is True

    # One value in three places: the record, the view, and the context.
    recs = [r for r in records(tmp_path) if r["intent"] == "write_memory"]
    assert recs[0]["agent"] == "memory-writer"
    assert any(r["agent"] == "other-agent" for r in recs)

    @g.tool(intent="write_memory", principal=lambda: alice, agent="impostor")
    def write_memory():
        return "ok"

    with pytest.raises(Denied):
        write_memory()


# ── RFC 8693 shapes: subject vs actor ───────────────────────────────


def test_the_three_cases_are_distinguishable(tmp_path):
    g = Watchlight(agent="flight-booker", audit_dir=str(tmp_path))
    # The agent acting ALONE — its own subject.
    g.allow('permit(principal == Agent::"flight-booker", action == Action::"cache", resource);')
    # The agent acting FOR a person: any user subject, this actor only.
    g.allow(
        'permit(principal is User, action == Action::"book", resource) '
        'when { context.actor == "flight-booker" };'
    )
    alice = principals.user("alice")

    assert g.authorize(action="cache")["allowed"] is True                      # case 1
    assert g.authorize(action="book", principal=alice)["allowed"] is True      # case 2
    # case 3: a sub-agent is another actor — the delegation policy names one.
    assert g.as_("seat-picker").authorize(action="book", principal=alice)["allowed"] is False
    assert g.authorize(action="book")["allowed"] is False

    recs = records(tmp_path)
    alone = next(r for r in recs if r["intent"] == "cache")
    for_user = next(r for r in recs if r["intent"] == "book" and r["decision"] == "Allow")
    assert alone["principal"] == 'Agent::"flight-booker"' and alone["agent"] == "flight-booker"
    assert for_user["principal"] == 'User::"alice"' and for_user["agent"] == "flight-booker"


# ── entity-reference helpers ────────────────────────────────────────


def test_entity_reference_helpers(tmp_path):
    # What a verified identity can actually carry: a quote, a backslash, a space.
    sub = 'a"b\\c d'
    assert principals.user(sub) == 'User::"a"b\\c d"'
    assert principals.agent("r-a") == 'Agent::"r-a"'
    assert for_policy("User", sub) == 'User::"a\\"b\\\\c d"'
    assert escape_cedar_string("a\nb\tc") == "a\\nb\\tc"
    for bad in [("Not A Type", "x"), ("User", ""), ("User", "a\nb")]:
        with pytest.raises(TypeError):
            principals.entity(*bad)

    # The two forms are two spellings of ONE entity: a policy written with the
    # escaped form matches a request built with the verbatim form.
    g = Watchlight(agent="esc", audit_dir=str(tmp_path))
    g.allow(f'permit(principal == {for_policy("User", sub)}, action == Action::"read", resource);')
    assert g.authorize(action="read", principal=principals.user(sub))["allowed"] is True
    assert g.authorize(action="read", principal=principals.user('a"b\\c e'))["allowed"] is False


# ── load() is idempotent per resolved source ────────────────────────


def test_load_is_idempotent_per_source(tmp_path):
    policy = tmp_path / "watchlight.policy.json"
    policy.write_text(json.dumps({"policies": [
        {"name": "p1", "code": 'permit(principal, action == Action::"read", resource);'},
        {"name": "p2", "code": 'permit(principal, action == Action::"list", resource);'},
    ]}))
    g = Watchlight(agent="loader", audit_dir=str(tmp_path))
    g.load(policy).load(policy)
    assert g.policy_count == 2
    g.load(tmp_path / "." / "watchlight.policy.json")
    assert g.policy_count == 2               # the key is the RESOLVED path
    g.as_("view").load(policy)
    assert g.policy_count == 2               # a view shares the load memo

    copy = tmp_path / "copy.policy.json"
    copy.write_text(policy.read_text())
    g2 = Watchlight(agent="loader2", audit_dir=str(tmp_path))
    g2.load(policy, source_id="the-set").load(copy, source_id="the-set")
    assert g2.policy_count == 2              # an explicit source_id joins two paths

    later = tmp_path / "later.policy.json"
    g3 = Watchlight(agent="loader3", audit_dir=str(tmp_path))
    g3.load(later)
    assert g3.policy_count == 0 and g3.has_policies is False
    later.write_text(json.dumps([{"name": "p", "code": "permit(principal, action, resource);"}]))
    g3.load(later)
    assert g3.policy_count == 1              # a missing source is not remembered
    assert g3.allow("permit(principal, action, resource);").policy_count == 2


# ── audit_file=False — the sink is the sole destination ─────────────


def test_audit_file_false_makes_the_sink_the_sole_destination(tmp_path):
    seen = []
    g = Watchlight(
        agent="sink-only", audit_dir=str(tmp_path), audit_sink=seen.append, audit_file=False
    )
    g.allow("permit(principal, action, resource);")
    g.authorize(action="read", principal=principals.user("a"))
    g.sanitize("call 555-867-5309")
    assert not (tmp_path / "audit.jsonl").exists()
    assert len(seen) == 2
    assert seen[0]["agent"] == "sink-only" and seen[0]["decision"] == "Allow"
    assert seen[1]["event"] == "sanitization"
    with pytest.raises(RuntimeError):
        g.counters(principal=principals.user("a"))


def test_no_file_and_no_sink_warns_once(tmp_path, capsys):
    g = Watchlight(agent="nowhere", audit_dir=str(tmp_path), audit_file=False)
    g.allow("permit(principal, action, resource);")
    g.authorize(action="read", principal=principals.user("a"))
    g.authorize(action="read", principal=principals.user("a"))
    err = capsys.readouterr().err
    assert err.count("audit records are discarded") == 1
    assert not (tmp_path / "audit.jsonl").exists()


# ── the default governor is configurable, once, before first use ────

_DEFAULT_SCRIPT = """
import json, pathlib, sys
from watchlight import govern, configure_default

seen = []
assert govern.policy_count == 0
configure_default(agent="configured", audit_dir=sys.argv[1], audit_sink=seen.append)
assert govern.agent == "configured"
# A second call naming only the directory must not drop the sink.
configure_default(audit_dir=sys.argv[2])
govern.allow('permit(principal, action == Action::"read", resource);')
govern.authorize(action="read", principal='User::"a"')
assert len(seen) == 1, seen
assert (pathlib.Path(sys.argv[2]) / "audit.jsonl").exists()
assert not (pathlib.Path(sys.argv[1]) / "audit.jsonl").exists()
try:
    configure_default(audit_dir=sys.argv[1])
    raise AssertionError("configuring after the first record must raise")
except RuntimeError:
    pass
assert govern.policy_count == 1
print("OK")
"""

_UNCONFIGURED_SCRIPT = """
import sys
from watchlight import govern, configure_default

configure_default(audit_dir=sys.argv[1])          # no sink
govern.allow('permit(principal, action, resource);')
govern.authorize(action="read", principal='User::"a"')
govern.authorize(action="read", principal='User::"a"')
print("OK")
"""


def _run(script, *args):
    return subprocess.run(
        [sys.executable, "-c", script, *[str(a) for a in args]],
        capture_output=True, text=True, check=True,
    )


def test_configure_default_routes_records_merges_and_then_locks(tmp_path):
    # The default governor is a module-level singleton, so each scenario runs in
    # its own process.
    second = tmp_path / "second"
    out = _run(_DEFAULT_SCRIPT, tmp_path, second)
    assert "OK" in out.stdout
    assert (second / "audit.jsonl").exists()


def test_unconfigured_default_warns_exactly_once(tmp_path):
    out = _run(_UNCONFIGURED_SCRIPT, tmp_path)
    assert "OK" in out.stdout
    assert out.stderr.count("no audit_sink is configured") == 1


def test_unconfigured_default_warns_exactly_once(tmp_path):
    out = _run(_UNCONFIGURED_SCRIPT, tmp_path)
    assert "OK" in out.stdout
    assert out.stderr.count("no audit_sink is configured") == 1


# ── the actor CHAIN: delegation through a spawned scope ─────────────


def test_delegation_records_the_ordered_chain_and_the_leaf(tmp_path):
    g = Watchlight(agent="flight-booker", audit_dir=str(tmp_path))
    # "who made this call" — the leaf actor.
    g.allow(
        'permit(principal is User, action == Action::"pick_seat", resource) '
        'when { context.actor == "seat-picker" };'
    )
    # "whose delegation is this" — membership anywhere in the chain.
    g.allow(
        'permit(principal is User, action == Action::"trace", resource) '
        'when { context.actor_chain.contains("flight-booker") };'
    )
    assert ACTOR_CHAIN_CONTEXT_KEY == "actor_chain"
    assert MAX_ACTOR_CHAIN == DE_MAX_DEPTH + 1
    alice = principals.user("alice")

    root = g.scope(tools=["search", "book"], time_budget_seconds=600)
    assert root.actor_chain == ("flight-booker",)

    picker = g.delegate(root, "seat-picker", tools=["search"])
    assert isinstance(picker, Watchlight) and picker.policy_count == g.policy_count
    assert picker.actor_chain == ("flight-booker", "seat-picker")
    assert picker.agent == "seat-picker"
    assert picker.delegated_scope.depth == 1
    assert "book" not in picker.delegated_scope.allowed_tools

    assert picker.authorize(action="pick_seat", principal=alice)["allowed"] is True   # leaf
    assert picker.authorize(action="trace", principal=alice)["allowed"] is True       # membership
    assert g.authorize(action="pick_seat", principal=alice)["allowed"] is False
    assert g.as_("rogue").authorize(action="trace", principal=alice)["allowed"] is False

    recs = records(tmp_path)
    seat = next(r for r in recs if r["intent"] == "pick_seat" and r["decision"] == "Allow")
    assert seat["agent"] == "seat-picker"
    assert seat["actor_chain"] == ["flight-booker", "seat-picker"]
    assert seat["principal"] == 'User::"alice"'
    # A call outside any delegation keeps the record shape it always had.
    assert any(r["agent"] == "flight-booker" and "actor_chain" not in r for r in recs)
    assert g.actor_chain == ("flight-booker",)

    picker.sanitize("call me at 555-867-5309")
    sanit = next(r for r in records(tmp_path) if r.get("event") == "sanitization")
    assert sanit["actor_chain"] == ["flight-booker", "seat-picker"]


def test_a_caller_can_neither_supply_nor_extend_the_chain(tmp_path):
    g = Watchlight(agent="flight-booker", audit_dir=str(tmp_path))
    g.allow(
        'permit(principal is User, action == Action::"trace", resource) '
        'when { context.actor_chain.contains("flight-booker") };'
    )
    alice = principals.user("alice")
    root = g.scope(tools=["search"])
    picker = g.delegate(root, "seat-picker")

    # claiming a delegation this governor does not have
    with pytest.raises(ReservedContextError) as err:
        g.authorize(
            action="trace", principal=alice,
            context={"actor_chain": ["flight-booker", "seat-picker"]},
        )
    assert str(err.value) == RESERVED_CONTEXT_MESSAGE
    with pytest.raises(ReservedContextError):
        picker.authorize(
            action="trace", principal=alice,
            context={"actor_chain": ["flight-booker", "seat-picker", "smuggled"]},
        )
    echoed = picker.authorize(
        action="trace", principal=alice,
        context={"actor_chain": ["flight-booker", "seat-picker"]},
    )
    assert echoed["allowed"] is True


def test_the_chain_is_bounded_by_the_attenuation_ceiling(tmp_path):
    g = Watchlight(agent="flight-booker", audit_dir=str(tmp_path))
    deep = g.delegate(g.scope(tools=["search"]), "level-1")
    for i in range(2, DE_MAX_DEPTH + 1):
        deep = g.delegate(deep, f"level-{i}")
    assert len(deep.actor_chain) == MAX_ACTOR_CHAIN
    with pytest.raises(DevEditionCeiling):
        g.delegate(deep, "too-deep")


def test_delegation_is_still_attenuation(tmp_path):
    g = Watchlight(agent="flight-booker", audit_dir=str(tmp_path))
    picker = g.delegate(g.scope(tools=["search", "book"]), "seat-picker", tools=["search"])
    with pytest.raises(AttenuationDenied):
        g.delegate(picker, "greedy", tools=["search", "book"])
    with pytest.raises(TypeError):
        g.delegate(g, "orphan")          # not itself a delegate
    with pytest.raises(TypeError):
        g.delegate(picker, "")

    # A delegate cannot be renamed — that would drop the chain it was granted.
    with pytest.raises(TypeError):
        picker.as_("disguise")
    with pytest.raises(TypeError):
        picker.authorize(action="read", principal=principals.user("a"), agent="disguise")
    with pytest.raises(TypeError):
        picker.sanitize("555-867-5309", agent="disguise")
    assert picker.actor_chain == ("flight-booker", "seat-picker")


# ── review fixes: names, sources, and requests the engine refuses ────


def test_an_unusable_agent_name_is_refused_at_the_name(tmp_path):
    for bad in ["", "   ", "a\nb", "a\x00b"]:
        with pytest.raises(TypeError):
            Watchlight(agent=bad, audit_dir=str(tmp_path))
    g = Watchlight(agent="ok", audit_dir=str(tmp_path))
    for bad in ["", "a\x7fb"]:
        with pytest.raises(TypeError):
            g.as_(bad)


def test_a_request_the_engine_cannot_evaluate_is_typed_and_audited(tmp_path):
    g = Watchlight(agent="typed", audit_dir=str(tmp_path))
    g.allow("permit(principal, action, resource);")
    with pytest.raises(AuthorizeRequestError) as err:
        g.authorize(action="read", principal='Service::"svc"')
    # Fixed message: the engine's own text is never echoed to the caller.
    assert str(err.value) == REQUEST_INVALID_MESSAGE
    assert any(
        r["decision"] == "Deny" and r["principal"] == 'Service::"svc"' for r in records(tmp_path)
    )

    ran = []

    @g.tool(intent="read", principal='Service::"svc"')
    def call_service():
        ran.append(1)
        return "x"

    with pytest.raises(AuthorizeRequestError):
        call_service()
    assert ran == []          # fail-closed: the body never ran


def test_load_is_keyed_on_identity_not_content(tmp_path):
    policy = tmp_path / "p.json"
    one = [{"name": "read", "code": 'permit(principal, action == Action::"read", resource);'}]
    policy.write_text(json.dumps(one))
    g = Watchlight(agent="loader", audit_dir=str(tmp_path))
    g.load(policy)
    policy.write_text(json.dumps(one + [
        {"name": "list", "code": 'permit(principal, action == Action::"list", resource);'}
    ]))
    g.load(policy)
    assert g.policy_count == 1                                   # a CHANGED file is not reloaded
    assert g.authorize(action="list", principal=principals.user("a"))["allowed"] is False
    g.load(policy, force=True)
    assert g.policy_count == 3                                   # force loads it again, additively
    assert g.authorize(action="list", principal=principals.user("a"))["allowed"] is True

    # Two names for ONE file are one source — symlinks resolved.
    link = tmp_path / "link.json"
    link.symlink_to(policy)
    g2 = Watchlight(agent="loader2", audit_dir=str(tmp_path))
    g2.load(policy).load(link)
    assert g2.policy_count == 2
