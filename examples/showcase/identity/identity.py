#!/usr/bin/env python3
"""The identity model, running — subject, actor, and delegation chain.

    pip install watchlight
    python examples/showcase/identity/identity.py

Runs offline: no API key, no network, no identity provider. ONE governor and
ONE policy set for the whole example; every named agent is a view of the same
engine. The script prints, for each call, the verdict and the identity fields
of the audit record it produced, and exits non-zero if any verdict or record
shape changes.

It makes the three cases of `docs/identity-model.md` concrete:

  1. an agent acting alone        principal = Agent::"flight-booker"
  2. the same agent for a person  principal = User::"…", same actor
  3. a sub-agent under a parent   principal unchanged, ordered actor chain

then shows the four things a caller cannot do (supply the actor key, extend
the chain, rename a delegate, rename it through a per-call override), and the
two identity sources — a verified token's subject claim and a local session
lookup — producing the identical call.

The policies and their golden tests live in one file:

    watchlight policy test examples/showcase/identity/policy.suite.json
"""

from __future__ import annotations

import json
import pathlib
import sys

from watchlight import ReservedContextError, Watchlight, principals

HERE = pathlib.Path(__file__).resolve().parent
AUDIT_DIR = HERE / ".watchlight"

# Resources this example authorizes against. Nothing here is a real system:
# the point is which identity the engine reads, not what the action does.
TRIP = "trip/AX8821"
ITINERARY = "itinerary/AX8821"
SEAT = "seat/AX8821"
TRACE = "trace/AX8821"
NOTES = "memory/traveller-notes"
ROUTE = "route/AMS-LIS"


# ── one engine, one policy set, many named agents ────────────────────────────

# Every audit record — from every named agent and every delegate — arrives
# here, because a view shares the trail and the sink with the governor it came
# from. That shared stream, told apart by `agent` and `actor_chain`, is what
# makes the three cases comparable below.
records: list[dict] = []

govern = Watchlight(agent="trip-platform", audit_dir=AUDIT_DIR, audit_sink=records.append)
govern.load(HERE / "policy.suite.json")  # {"policies": [...]} — the file the suite tests

POLICIES_AFTER_LOAD = govern.policy_count

# Naming agents costs nothing: `as_` returns a VIEW of this governor — same
# engine, same compiled policies, same trail, same sink — with a different name
# stamped on the records and read by the policies as `context.actor`.
booker = govern.as_("flight-booker")
memory = govern.as_("memory-writer")

POLICIES_AFTER_NAMING = govern.policy_count


# ── assertions ───────────────────────────────────────────────────────────────

failures: list[str] = []


def check(condition: bool, what: str) -> None:
    print(f"  {'OK ' if condition else 'FAIL'} {what}")
    if not condition:
        failures.append(what)


def identity_of(record: dict) -> str:
    """The identity fields of an audit record, in one line: who acted, through
    whose delegation, and on whose behalf."""
    chain = record.get("actor_chain")
    return (
        f"agent={record.get('agent', '-'):<14} "
        f"chain={'[' + ' > '.join(chain) + ']' if chain else '(none)':<34} "
        f"principal={record.get('principal', '-')}"
    )


def decide(gov: Watchlight, action: str, resource: str, *, principal: str | None = None,
           context: dict | None = None) -> tuple[dict, dict]:
    """One governed decision, plus the audit record it wrote."""
    before = len(records)
    result = gov.authorize(action=action, principal=principal, resource=resource, context=context)
    record = records[-1] if len(records) > before else {}
    print(f"    {action:<14} -> {result['decision']:<6} {identity_of(record)}")
    return result, record


def refused(what: str, thunk, expected: type) -> None:
    """Assert that a call the SDK must refuse raises, and writes nothing."""
    before = len(records)
    try:
        thunk()
        print(f"    {what}: NOT refused")
        failures.append(what)
        return
    except expected as error:
        print(f"    {what}\n      -> {type(error).__name__}: {error}")
    check(len(records) == before, f"{what} — refused before the engine, so no record was written")


# ── the three cases ──────────────────────────────────────────────────────────

def three_cases() -> dict[str, dict]:
    """An agent alone, the same agent for a person, a sub-agent under it."""
    traveller = principals.user("db:4412")

    print("\ncase 1 — the agent acting alone (no principal: the agent is the subject)")
    alone, alone_record = decide(booker, "cache", ROUTE)
    # The same agent, acting alone, may NOT book: the booking policy wants a
    # person subject. A narrower grant for the autonomous case, same runtime.
    denied_alone, _ = decide(booker, "book", TRIP)

    print("\ncase 2 — the same agent acting for a person (same actor, different subject)")
    for_person, person_record = decide(booker, "book", TRIP, principal=traveller)

    print("\ncase 3 — a sub-agent under the booking agent (subject unchanged, chain extended)")
    # `scope` is the parent's authority; `delegate` narrows it AND appends the
    # sub-agent to the actor chain, so one call produces both the confined
    # authority and the delegated identity.
    root = booker.scope(tools=["search", "book", "pick_seat", "trace"])
    picker = booker.delegate(root, "seat-picker", tools=["search", "pick_seat", "trace"])
    sub, sub_record = decide(picker, "pick_seat", SEAT, principal=traveller)
    # The delegate is not the booking runtime, so the booking policy — which
    # names the LEAF actor — does not match it.
    sub_book, _ = decide(picker, "book", TRIP, principal=traveller)

    check(alone["decision"] == "Allow", "case 1: the agent alone may warm the cache")
    check(denied_alone["decision"] == "Deny", "case 1: the agent alone may not book")
    check(alone_record["principal"] == 'Agent::"flight-booker"',
          'case 1: the subject is the typed agent reference Agent::"flight-booker"')
    check("actor_chain" not in alone_record,
          "case 1: no actor_chain on the record — the call is outside any delegation")

    check(for_person["decision"] == "Allow", "case 2: the same agent may book for a person")
    check(person_record["principal"] == 'User::"db:4412"',
          'case 2: the subject is the person, User::"db:4412"')
    check(person_record["agent"] == alone_record["agent"] == "flight-booker",
          "case 2: the actor is unchanged — one runtime, two subjects")
    check("actor_chain" not in person_record, "case 2: still no actor_chain")

    check(sub["decision"] == "Allow", "case 3: the sub-agent may pick a seat for the person")
    check(sub_book["decision"] == "Deny", "case 3: the sub-agent may not book")
    check(sub_record["agent"] == "seat-picker", "case 3: the leaf actor is the sub-agent")
    check(sub_record["actor_chain"] == ["flight-booker", "seat-picker"],
          "case 3: the ordered chain is [flight-booker > seat-picker], root first")
    check(sub_record["principal"] == person_record["principal"],
          "case 3: the subject is unchanged — delegation adds an actor, not a subject")
    check(picker.actor_chain == ("flight-booker", "seat-picker"),
          "case 3: the governor carries the same chain the record does")

    return {"alone": alone_record, "for a person": person_record, "sub-agent": sub_record,
            "picker": picker}


# ── one policy per identity field ────────────────────────────────────────────

def policies_per_field(picker: Watchlight) -> None:
    traveller = principals.user("db:4412")
    other = principals.user("sso:8f3c2b7e")

    print("\na person's own authority — the acting runtime is irrelevant")
    own, _ = decide(booker, "cancel_trip", TRIP, principal=traveller)
    own_other_runtime, _ = decide(memory, "cancel_trip", TRIP, principal=traveller)
    not_theirs, _ = decide(booker, "cancel_trip", TRIP, principal=other)
    check(own["decision"] == "Allow", "the traveller may cancel their own trip")
    check(own_other_runtime["decision"] == "Allow",
          "a different runtime acting for the same traveller is allowed too")
    check(not_theirs["decision"] == "Deny", "another traveller may not cancel that trip")

    print("\na tool restricted to one runtime — context.actor, whoever it acts for")
    writer, _ = decide(memory, "write_memory", NOTES, principal=traveller)
    non_writer, _ = decide(booker, "write_memory", NOTES, principal=traveller)
    check(writer["decision"] == "Allow", "the memory-writer runtime may write memory")
    check(non_writer["decision"] == "Deny", "another runtime may not, for the same person")

    print("\nmembership anywhere in the chain — context.actor_chain.contains(...)")
    delegated, _ = decide(picker, "trace", TRACE, principal=traveller)
    outside, _ = decide(memory, "trace", TRACE, principal=traveller)
    check(delegated["decision"] == "Allow",
          "the sub-agent may trace: the booking agent is in its chain")
    check(outside["decision"] == "Deny",
          "an agent outside that delegation may not, though the subject is the same")


# ── what a caller cannot do ──────────────────────────────────────────────────

def caller_cannot(picker: Watchlight) -> None:
    """The actor keys are the SDK's. A caller can neither invent a delegation
    nor extend one through the context, and cannot rename a delegate."""
    traveller = principals.user("db:4412")

    print("\nsupplying the actor key through context")
    refused("context={'actor': 'memory-writer'} on a flight-booker call",
            lambda: booker.authorize(action="write_memory", resource=NOTES,
                                     principal=traveller, context={"actor": "memory-writer"}),
            ReservedContextError)

    print("\nextending the chain through context")
    refused("context={'actor_chain': [...]} claiming a delegation that did not happen",
            lambda: memory.authorize(action="trace", resource=TRACE, principal=traveller,
                                     context={"actor_chain": ["flight-booker", "memory-writer"]}),
            ReservedContextError)

    print("\nrenaming a delegate")
    refused("picker.as_('row-checker')", lambda: picker.as_("row-checker"), TypeError)
    refused("the same rename through the per-call agent override",
            lambda: picker.authorize(action="trace", resource=TRACE, principal=traveller,
                                     agent="row-checker"),
            TypeError)

    print("\n(an identical value is not a conflict — the guard refuses disagreement, not the key)")
    same, _ = decide(booker, "book", TRIP, principal=traveller, context={"actor": "flight-booker"})
    check(same["decision"] == "Allow", "a context.actor equal to the SDK's own value is accepted")


# ── both identity sources, one call ──────────────────────────────────────────

# A stand-in for a token your application has ALREADY verified — this example
# verifies nothing and implies no particular identity provider. Only the
# subject claim is used: a username or an email can be reassigned, which would
# point an old audit record at a different person; `sub` does not move.
VERIFIED_CLAIMS = {"sub": "8f3c2b7e", "preferred_username": "traveller-42"}

# A stand-in for a local session store and users table — the case with no
# identity provider at all. The row's primary key is the subject, not the
# display name, for the same reason.
SESSIONS = {"session-1f2e": {"user_id": 4412}}
USERS = {4412: {"id": 4412, "display_name": "window-seat regular", "tier": "gold"}}


def subject_from_token(claims: dict) -> str:
    """Namespaced so two identity sources can never collide on one id."""
    return principals.user(f"sso:{claims['sub']}")


def subject_from_session(session_id: str) -> str:
    row = USERS[SESSIONS[session_id]["user_id"]]   # your session store, then the row
    return principals.user(f"db:{row['id']}")      # the primary key, never the display name


def read_itinerary(subject: str) -> tuple[dict, dict]:
    """ONE call site. Whatever established the subject, the call is identical."""
    return decide(booker, "read_itinerary", ITINERARY, principal=subject)


def identity_sources() -> None:
    print("\ntwo identity sources, one call")
    from_token, token_record = read_itinerary(subject_from_token(VERIFIED_CLAIMS))
    from_session, session_record = read_itinerary(subject_from_session("session-1f2e"))

    check(from_token["decision"] == from_session["decision"] == "Allow",
          "both subjects reach the same Allow")
    def shape(record: dict) -> dict:
        return {k: v for k, v in record.items() if k not in ("ts", "decision_id", "principal")}

    check(shape(token_record) == shape(session_record),
          "the two records differ in the subject id and nothing else")
    check(token_record["principal"] == 'User::"sso:8f3c2b7e"'
          and session_record["principal"] == 'User::"db:4412"',
          "each subject is namespaced by the source that established it")


# ── main ─────────────────────────────────────────────────────────────────────

def main() -> int:
    print("one engine, one policy set, many named agents")
    print(f"    policies loaded              {POLICIES_AFTER_LOAD}")
    print("    named agents                 flight-booker, memory-writer (views of one engine)")
    print(f"    policies after naming them   {POLICIES_AFTER_NAMING}")
    check(POLICIES_AFTER_LOAD == 7, "the policy set is the 7 policies in policy.suite.json")
    check(POLICIES_AFTER_NAMING == POLICIES_AFTER_LOAD,
          "naming agents did not reload or recompile a single policy")
    check(booker.policy_count == memory.policy_count == govern.policy_count,
          "every view reports the same policy count — it is the same engine")

    cases = three_cases()
    picker = cases.pop("picker")
    check(govern.policy_count == POLICIES_AFTER_LOAD,
          "delegating did not grow the policy set either")

    policies_per_field(picker)
    caller_cannot(picker)
    identity_sources()

    print("\nthe three cases, side by side in the one audit stream")
    for label, record in cases.items():
        line = {k: record[k] for k in ("agent", "actor_chain", "principal", "intent", "decision")
                if k in record}
        print(f"    {label:<13} {json.dumps(line)}")

    print()
    if failures:
        print(f"FAILED: {len(failures)} assertion(s) did not hold")
        return 1
    print("OK — three cases, three identities, one engine and one policy set.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
