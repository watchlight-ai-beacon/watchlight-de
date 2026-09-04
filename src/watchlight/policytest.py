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


_EXPECTED_OBLIGATION_KEYS = {"redact", "maxItems", "max_items", "logValues", "log_values", "extra"}


_ABSENT = object()


def _one_spelling(o: dict, camel: str, snake: str, where: str) -> Any:
    """Pick one of two spellings of the same key; both given with different
    values is a contradiction and therefore malformed. Presence-based: a key
    set to ``null`` is present (and then ill-typed), exactly as in the TS lane."""
    a, b = o.get(camel, _ABSENT), o.get(snake, _ABSENT)
    if a is not _ABSENT and b is not _ABSENT and a != b:
        raise ValueError(f"{where}: '{camel}' and '{snake}' disagree")
    return a if a is not _ABSENT else b


def normalize_expected_obligations(raw: Any, where: str = "fixture") -> dict:
    """Validate and canonicalize a fixture's ``obligations`` expectation into
    wire spelling (``redact`` / ``max_items`` / ``log_values`` / ``extra``, the
    last as ``{name: [values]}``; a single string stands for a one-element list).
    Strict: an unknown key, an ill-typed or ``null`` value, or a contradiction
    between the camelCase and snake_case spellings is a malformed suite and
    raises ``ValueError`` — a typo must never pass as "no expectation". Returns
    ``{}`` for an expectation of "no obligations"."""
    if not isinstance(raw, dict):
        raise ValueError(f"{where}: 'obligations' must be an object")
    unknown = set(raw) - _EXPECTED_OBLIGATION_KEYS
    if unknown:
        raise ValueError(f"{where}: unknown obligations key '{sorted(unknown)[0]}'")
    out: dict = {}
    if "redact" in raw:
        redact = raw["redact"]
        if (not isinstance(redact, list) or not redact
                or any(not isinstance(v, str) or not v.strip() for v in redact)):
            raise ValueError(f"{where}: 'obligations.redact' must be a non-empty array of non-blank strings")
        out["redact"] = list(dict.fromkeys(v.strip() for v in redact))
    max_items = _one_spelling(raw, "maxItems", "max_items", where)
    if max_items is not _ABSENT:
        if not isinstance(max_items, int) or isinstance(max_items, bool) or max_items < 1:
            raise ValueError(f"{where}: 'obligations.maxItems' must be a positive integer")
        out["max_items"] = max_items
    log_values = _one_spelling(raw, "logValues", "log_values", where)
    if log_values is not _ABSENT:
        if not isinstance(log_values, bool):
            raise ValueError(f"{where}: 'obligations.logValues' must be a boolean")
        out["log_values"] = log_values
    if "extra" in raw:
        extra = raw["extra"]
        if not isinstance(extra, dict):
            raise ValueError(f"{where}: 'obligations.extra' must be an object of string or string-list values")
        clean: dict[str, list[str]] = {}
        for k, v in extra.items():
            vs = [v] if isinstance(v, str) else v
            if not isinstance(vs, list) or not vs or any(not isinstance(x, str) for x in vs):
                raise ValueError(f"{where}: 'obligations.extra' must be an object of string or string-list values")
            clean[k] = sorted(set(vs))
        if clean:
            out["extra"] = clean
    return out


def _canonical_obligations(o: Optional[dict]) -> str:
    """Canonical, order-independent rendering for exact comparison: ``redact``
    as a sorted set, ``extra`` with sorted keys."""
    c: dict = {}
    if o:
        if o.get("redact"):
            c["redact"] = sorted(set(o["redact"]))
        if "max_items" in o:
            c["max_items"] = o["max_items"]
        if "log_values" in o:
            c["log_values"] = o["log_values"]
        if o.get("extra"):
            c["extra"] = {k: sorted(set(v)) for k, v in sorted(o["extra"].items())}
    return json.dumps(c, sort_keys=True, separators=(",", ":"))


def run_policy_tests(
    decide: Callable[..., dict],
    mint: Callable[..., str],
    cases: Sequence[dict],
) -> dict:
    """Run policy fixtures through a decision function and report pass/fail.

    ``decide(action=, principal=, resource=, context=, approval=)`` returns the
    engine verdict dict; ``mint(action=, principal=, resource=)`` mints a valid
    approval token (used when a case sets ``"approved": True``). A verdict
    mismatch — or, when the case states ``"obligations"``, an obligations
    mismatch — is recorded as a failed result rather than raised — inspect
    ``report["failed"]``. A fixture missing a required key (``action`` or
    ``expect``), or carrying an ill-typed ``obligations`` expectation, is a
    malformed suite and raises ``ValueError``.
    """
    results: list[dict] = []
    for index, case in enumerate(cases):
        where = f"fixture {index} ({case.get('name', '?')})"
        for required in ("action", "expect"):
            if required not in case:
                raise ValueError(f"{where}: missing required key '{required}'")
        expected = _normalize_verdict(case["expect"])
        expected_obligations = (
            normalize_expected_obligations(case["obligations"], where)
            if "obligations" in case else None
        )
        if expected_obligations and expected != "Allow":
            raise ValueError(f"{where}: 'obligations' can only be expected on an Allow, not {expected}")
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
        obligations_ok = expected_obligations is None or (
            _canonical_obligations(expected_obligations)
            == _canonical_obligations(decision.get("obligations"))
        )
        result = {
            "name": case.get("name") or f"{action} on {resource or 'resource'}",
            "expected": expected,
            "actual": actual,
            "ok": actual == expected and obligations_ok,
            "reason": decision.get("reason", ""),
        }
        if decision.get("obligations"):
            result["obligations"] = decision["obligations"]
        if expected_obligations is not None:
            result["expected_obligations"] = expected_obligations
        results.append(result)
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
