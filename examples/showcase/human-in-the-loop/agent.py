#!/usr/bin/env python3
"""Human-in-the-loop, end to end: hold, approve out of band, resume exactly once.

    pip install watchlight
    cd examples/showcase/human-in-the-loop
    export APPROVER_SECRET="$(openssl rand -hex 32)"

    python agent.py request     # 1. NeedsApproval → pending request written; nothing deleted
    python approve.py           # 2. a human signs a grant for that request
    python agent.py resume      # 3. grant verified → approved decision → the delete runs ONCE
                                #    then: the same grant replayed → refused; an SDK token
                                #    replayed → refused

The `delete` permit in policy.suite.json carries
`@enforcement_effect("require_approval")`, so the engine answers NeedsApproval
instead of Allow. The SDK then calls `on_needs_approval` BEFORE the tool body:

  * no grant on disk    → write the pending request, return False → the SDK raises
                          NeedsApproval; the body never runs;
  * a verified grant    → return True → the SDK mints a single-use approval token
                          in this process, re-authorizes, and only then runs the
                          body once, writing an `approved: true` decision record.

Every phase exits non-zero if the record store's delete counter, the audit
records, or a replay check contradicts the expected outcome.

The same file that the agent loads is also a policy test suite:

    watchlight policy test examples/showcase/human-in-the-loop/policy.suite.json
"""

from __future__ import annotations

import json
import sys

from watchlight import NeedsApproval, Watchlight

import hitl

RECORD = "rec-42"


class RecordStore:
    """Stands in for the system of record. Every delete increments `deletes`."""

    def __init__(self) -> None:
        self.deletes = 0

    def delete(self, record_id: str) -> str:
        self.deletes += 1
        return f"delete #{self.deletes}: record/{record_id} removed"


store = RecordStore()

govern = Watchlight(agent="records-agent", audit_dir=hitl.AUDIT_DIR)
govern.load(hitl.HERE / "policy.suite.json")  # {"policies": [...]} — the file the suite tests


def hold_or_resume(decision_id: str, principal: str, action: str, resource: str) -> bool:
    """The approval hook. Runs on a NeedsApproval verdict, before the body."""
    if hitl.peek_grant() is None:
        hitl.write_pending(decision_id, principal, action, resource)
        print(f"hold:    pending request written to {hitl.PENDING.relative_to(hitl.HERE)}; the delete did not run")
        return False
    grant, why = hitl.take_grant(principal, action, resource, hitl.approver_secret())
    if grant is None:
        # A grant that does not verify is discarded — it is not a new request.
        print(f"refused: {why}; the delete did not run")
        return False
    print(f"resume:  grant verified and consumed — approves pending {grant['pending_decision_id']}")
    return True


def delete_record(record_id: str) -> str:
    """Govern one delete. The Python hook receives only the decision, so the
    resource is bound here where it is known and handed to the hook."""
    resource = f"record/{record_id}"
    governed = govern.tool(
        "delete",
        resource=resource,
        on_needs_approval=lambda decision: hold_or_resume(decision["decision_id"], govern.agent, "delete", resource),
    )(store.delete)
    return governed(record_id)


# ── assertions ───────────────────────────────────────────────────────────────

failures: list[str] = []


def check(condition: bool, what: str) -> None:
    print(f"  {'✓' if condition else '✗'} {what}")
    if not condition:
        failures.append(what)


def finish() -> int:
    print()
    if failures:
        print(f"FAILED: {len(failures)} assertion(s) did not hold")
        return 1
    print("OK")
    return 0


# ── phase 1: request ─────────────────────────────────────────────────────────

def request() -> int:
    hitl.reset()
    print(f"attempt: delete record/{RECORD}")
    before = len(hitl.audit_lines())
    try:
        delete_record(RECORD)
        check(False, "the delete was held for approval")
    except NeedsApproval as held:
        print(f"held:    {held}")
        line = hitl.audit_line(held.decision_id) or "(no record written)"
        print(f"pending decision record:\n  {line}")
        check(store.deletes == 0, f"the record store never received the delete (deletes={store.deletes})")
        check(hitl.read_pending() is not None, "a pending request is on disk for the approver")
        record = json.loads(line) if line.startswith("{") else {}
        check(record.get("decision") == "NeedsApproval", "the audit record is a NeedsApproval hold")
        check(len(hitl.audit_lines()) - before == 1, "exactly one decision record was written")
    print("\nnext: python approve.py   (then: python agent.py resume)")
    return finish()


# ── phase 2: resume ──────────────────────────────────────────────────────────

def resume() -> int:
    grant = hitl.peek_grant()
    if grant is None:
        print("no grant on disk — run 'python agent.py request', then 'python approve.py'")
        return 2
    pending_id = grant["pending_decision_id"]
    replay_copy = dict(grant)  # what anyone who read the file would hold

    print(f"attempt: delete record/{RECORD} (grant on disk for pending {pending_id})")
    before = len(hitl.audit_lines())
    try:
        outcome = delete_record(RECORD)
    except NeedsApproval:
        # The grant on disk did not verify (tampered, expired, wrong request).
        # It has been discarded; nothing ran. Start over with 'request'.
        check(False, "the grant verified and the delete resumed")
        return finish()
    print(f"result:  {outcome}")

    new_lines = hitl.audit_lines()[before:]
    approved_line = new_lines[-1] if new_lines else ""
    approved = json.loads(approved_line) if approved_line else {}
    pending_line = hitl.audit_line(pending_id) or ""
    pending = json.loads(pending_line) if pending_line else {}

    print("\npending decision record (written by 'request'):")
    print(f"  {pending_line or '(not found)'}")
    print("approved decision record (written now):")
    print(f"  {approved_line or '(none)'}")
    print(f"join:    grant.pending_decision_id {pending_id} → approved decision {approved.get('decision_id')}")

    check(store.deletes == 1, f"the delete ran exactly once (deletes={store.deletes})")
    check(pending.get("decision") == "NeedsApproval", "the pending record is a NeedsApproval hold")
    check(approved.get("decision") == "Allow" and approved.get("approved") is True,
          "the approved record is Allow with approved: true")
    check(
        (pending.get("principal"), pending.get("intent"), pending.get("resource"))
        == (approved.get("principal"), approved.get("intent"), approved.get("resource")),
        "both records name the same principal, intent and resource",
    )
    check(len(new_lines) == 2 and json.loads(new_lines[0]).get("decision") == "NeedsApproval",
          "the resume re-evaluated the policy (a fresh hold) before applying the approval")
    check(hitl.peek_grant() is None, "the grant was consumed")

    # Replay 1: present the consumed grant again.
    print("\nreplay: presenting the consumed grant again")
    hitl.plant_grant(replay_copy)
    try:
        delete_record(RECORD)
        check(False, "the replayed grant was refused")
    except NeedsApproval:
        check(store.deletes == 1, f"the replayed grant was refused; deletes still {store.deletes}")
    check(hitl.read_pending() is None, "a refused replay does not open a new pending request")

    # Replay 2: a well-signed grant naming a request that is not the outstanding one. Anyone
    # holding the secret can sign one (see README); the agent still refuses it.
    print("\nreplay: presenting a signed grant for a request that is not the outstanding one")
    hitl.write_grant(
        {"decision_id": "00000000-0000-4000-8000-000000000000", "principal": govern.agent,
         "action": "delete", "resource": f"record/{RECORD}"},
        hitl.approver_secret(),
    )
    try:
        delete_record(RECORD)
        check(False, "the grant for a non-outstanding request was refused")
    except NeedsApproval:
        check(store.deletes == 1, f"the grant for a non-outstanding request was refused; deletes still {store.deletes}")

    # Replay 3: present the same SDK approval token twice.
    print("\nreplay: presenting the same SDK approval token twice (probe resource)")
    probe = "record/rec-probe"
    token = govern.mint_approval(action="delete", resource=probe)
    first = govern.authorize(action="delete", resource=probe, approval=token)
    second = govern.authorize(action="delete", resource=probe, approval=token)
    check(first["decision"] == "Allow" and first["approved"] is True,
          "a fresh token downgrades NeedsApproval to Allow once")
    check(second["decision"] == "NeedsApproval" and second["approved"] is False,
          "the same token presented again is refused (single use)")

    return finish()


def main(argv: list[str]) -> int:
    phase = argv[0] if argv else ""
    if phase == "request":
        return request()
    if phase == "resume":
        return resume()
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
