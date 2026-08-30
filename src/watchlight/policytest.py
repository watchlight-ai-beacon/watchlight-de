"""Policy test harness — golden tests for DE policies.

A policy is the only thing standing between an agent and a real action, so it
deserves the same unit-testing discipline as the code around it. This module runs
a list of fixtures against the loaded policies and reports which pass: each case
asserts the expected verdict (``Allow`` / ``Deny`` / ``NeedsApproval``) for a
``(principal, action, resource, context)``. It contains ZERO decision logic —
every verdict comes from the engine, via the same decision core :meth:`authorize`
uses — and it never writes to the audit trail, so CI runs leave no residue.

    from watchlight import govern

    govern.load("watchlight.policy.json")
    report = govern.test([
        {"name": "under limit allows", "action": "book",
         "context": {"amount": 200, "limit": 500, "refundable": True}, "expect": "Allow"},
    ])
    assert report["failed"] == 0, report

Or from CI, with the ``watchlight`` CLI::

    watchlight policy test suite.json
"""

from __future__ import annotations

import json
import pathlib
from typing import Any, Callable, Optional, Sequence


def _normalize_verdict(value: Any) -> str:
    """Canonicalize a verdict string. An unrecognized value is returned verbatim
    so a typo in a fixture fails loudly rather than silently passing."""
    s = str(value or "").strip().lower()
    if s in ("allow", "permit"):
        return "Allow"
    if s == "deny":
        return "Deny"
    if s in ("needsapproval", "needs_approval", "approve", "approval"):
        return "NeedsApproval"
    return value if value else "Deny"


def run_policy_tests(
    decide: Callable[..., dict],
    mint: Callable[..., str],
    cases: Sequence[dict],
) -> dict:
    """Run policy fixtures through a decision function and report pass/fail.

    ``decide(action=, principal=, resource=, context=, approval=)`` returns the
    engine verdict dict; ``mint(action=, principal=, resource=)`` mints a valid
    approval token (used when a case sets ``"approved": True``). A verdict
    mismatch is recorded as a failed result rather than raised — inspect
    ``report["failed"]``. A fixture missing a required key (``action`` or
    ``expect``) is a malformed suite and raises ``ValueError``.
    """
    results: list[dict] = []
    for index, case in enumerate(cases):
        for required in ("action", "expect"):
            if required not in case:
                raise ValueError(
                    f"fixture {index} ({case.get('name', '?')}): missing required key '{required}'"
                )
        expected = _normalize_verdict(case["expect"])
        action = case["action"]
        principal = case.get("principal")
        resource = case.get("resource")
        context = case.get("context")
        approval = (
            mint(action=action, principal=principal, resource=resource)
            if case.get("approved")
            else None
        )
        decision = decide(
            action=action,
            principal=principal,
            resource=resource,
            context=context,
            approval=approval,
        )
        actual = _normalize_verdict(decision.get("decision"))
        results.append(
            {
                "name": case.get("name") or f"{action} on {resource or 'resource'}",
                "expected": expected,
                "actual": actual,
                "ok": actual == expected,
                "reason": decision.get("reason", ""),
            }
        )
    passed = sum(1 for r in results if r["ok"])
    return {
        "total": len(results),
        "passed": passed,
        "failed": len(results) - passed,
        "results": results,
    }


def load_test_suite(path: str | pathlib.Path) -> dict:
    """Load a suite file. Accepts ``{"policies"?, "policyFile"? | "policy_file"?,
    "tests"}`` (a bare list of tests is also accepted). Raises on malformed JSON
    so a broken suite fails the CI step rather than silently passing."""
    data = json.loads(pathlib.Path(path).read_text())
    if isinstance(data, list):
        return {"policies": None, "policy_file": None, "tests": data}
    return {
        "policies": data.get("policies"),
        "policy_file": data.get("policyFile") or data.get("policy_file"),
        "tests": data.get("tests") or data.get("cases") or [],
    }
