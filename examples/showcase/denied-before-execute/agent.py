#!/usr/bin/env python3
"""Denied before it executed — a governed transfer against a stub bank.

    pip install watchlight
    python examples/showcase/denied-before-execute/agent.py

Runs offline: no API key, no network. A stub "bank" stands in for a payments
API; the only thing it does is count the calls it receives. The `transfer`
tool is governed, so the engine authorizes every call against
`policy.suite.json` BEFORE the function body runs:

  * a transfer above the threshold matches a `forbid` — the call is refused
    and the stub's counter stays at 0;
  * a small transfer matches the `permit` — the stub is called exactly once.

The script prints, for each attempt, the verdict, the decision id and the
exact audit line the engine wrote, and exits non-zero if the stub's counter
contradicts either verdict or if the audit line carries the call's arguments.

The same file that the agent loads is also a policy test suite:

    watchlight policy test examples/showcase/denied-before-execute/policy.suite.json
"""

from __future__ import annotations

import json
import pathlib
import sys

from watchlight import Denied, Watchlight

HERE = pathlib.Path(__file__).resolve().parent
AUDIT_DIR = HERE / ".watchlight"
AUDIT_PATH = AUDIT_DIR / "audit.jsonl"


class StubBank:
    """Stands in for the payments API. Every call increments `calls`."""

    def __init__(self) -> None:
        self.calls = 0

    def transfer(self, to: str, amount: int) -> str:
        self.calls += 1
        return f"transfer #{self.calls} settled to account/{to}"


bank = StubBank()

govern = Watchlight(agent="payments-agent", audit_dir=AUDIT_DIR)
govern.load(HERE / "policy.suite.json")  # {"policies": [...]} — the file the suite tests


@govern.tool(
    "transfer",
    resource=lambda to, amount: f"account/{to}",
    context=lambda to, amount: {"amount": amount},
)
def transfer(to: str, amount: int) -> str:
    # Runs only after the engine returns Allow for (payments-agent, transfer,
    # account/<to>) with context.amount. On Deny the SDK raises before this line.
    return bank.transfer(to, amount)


# ── assertions ───────────────────────────────────────────────────────────────

failures: list[str] = []


def check(condition: bool, what: str) -> None:
    print(f"  {'✓' if condition else '✗'} {what}")
    if not condition:
        failures.append(what)


def audit_lines() -> list[str]:
    if not AUDIT_PATH.exists():
        return []
    return [line for line in AUDIT_PATH.read_text().splitlines() if line.strip()]


def attempt(to: str, amount: int, *, expect: str) -> None:
    """Make one governed call and compare what happened with the verdict."""
    print(f"\nattempt: transfer amount={amount} → account/{to}")
    lines_before = len(audit_lines())
    calls_before = bank.calls

    try:
        outcome = transfer(to, amount)
        verdict = "Allow"
        print(f"result:  {outcome}")
    except Denied as denied:
        verdict = "Deny"
        print(f"refused: {denied}")

    new_lines = audit_lines()[lines_before:]
    line = new_lines[-1] if new_lines else ""
    record = json.loads(line) if line else {}
    print(f"verdict: {verdict}    decision_id: {record.get('decision_id')}")
    print(f"audit:   {line or '(no record written)'}")

    check(verdict == expect, f"verdict is {expect}")
    check(len(new_lines) == 1 and record.get("decision") == expect,
          "exactly one decision record was written for this call")
    check("amount" not in record and "context" not in record,
          "the audit line is value-free (no amount, no arguments)")
    if expect == "Deny":
        check(bank.calls == calls_before,
              f"the stub bank never received the call (calls={bank.calls})")
    else:
        check(bank.calls == calls_before + 1,
              f"the stub bank received the call exactly once (calls={bank.calls})")


def main() -> int:
    print(f"stub bank calls at start: {bank.calls}")

    # 1. The large transfer: forbidden by policy, refused before the body runs.
    attempt("acct-b", 25000, expect="Deny")
    check(bank.calls == 0, "stub bank calls == 0 after the denied transfer")

    # 2. A small transfer: permitted, reaches the stub exactly once.
    attempt("acct-b", 250, expect="Allow")
    check(bank.calls == 1, "stub bank calls == 1 after the allowed transfer")

    print()
    if failures:
        print(f"FAILED: {len(failures)} assertion(s) did not hold")
        return 1
    print("OK — the large transfer was denied before it executed; the small one ran once.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
