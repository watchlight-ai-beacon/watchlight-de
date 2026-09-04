#!/usr/bin/env python3
"""The out-of-band approver: show the human what the agent is asking for, then
sign a grant for exactly that request.

    export APPROVER_SECRET="$(openssl rand -hex 32)"   # same shell as 'agent.py resume'
    python approve.py            # approve the pending request → grant.json (pending stays until consumed)
    python approve.py --deny     # refuse it → pending removed, no grant, nothing runs

The pending request names the action, the resource and the decision id — never
the tool's arguments. The grant is signed with HMAC-SHA256 under
$APPROVER_SECRET, is bound to the pending request's (principal, action,
resource), expires after five minutes and can be consumed once.
"""

from __future__ import annotations

import sys

import hitl


def main(argv: list[str]) -> int:
    pending = hitl.read_pending()
    if pending is None:
        print(f"no pending request at {hitl.PENDING.relative_to(hitl.HERE)} — run 'python agent.py request' first")
        return 2

    print("pending request")
    for key in ("decision_id", "principal", "action", "resource"):
        print(f"  {key:12} {pending[key]}")

    if "--deny" in argv:
        hitl.PENDING.unlink(missing_ok=True)
        print("\ndenied — pending request removed; no grant written, the action will not run")
        return 0

    grant = hitl.write_grant(pending, hitl.approver_secret())
    print(f"\napproved — grant written to {hitl.GRANT.relative_to(hitl.HERE)}")
    print(f"  pending_decision_id {grant['pending_decision_id']}")
    print(f"  bound to            {grant['principal']} / {grant['action']} / {grant['resource']}")
    print(f"  valid for           {hitl.GRANT_TTL_MS // 1000}s, single use")
    print("\nnow run: python agent.py resume")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
