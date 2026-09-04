"""watchlight — Developer Edition.

Govern an AI agent in-process, with zero infrastructure. Decorate a tool with
an *intent*, load a local policy, run your script, and the policy engine
authorizes every call — allowing what a policy permits and refusing everything
else **before the tool body runs**.

    from watchlight import govern, Denied

    govern.load("watchlight.policy.json")     # or govern.allow("permit(...);")

    @govern.tool(intent="research")
    def web_search(query: str) -> str:
        ...

The engine is the Watchlight authorization engine (Cedar evaluation plus the
surrounding pipeline) embedded via the ``watchlight-engine`` extension — the
same authorization model that runs in production, in-process. Point it at a
networked policy service to run the same code against a remote APDP.

Guarantees that are identical to production and MUST NOT be relaxed here:
  * **Fail-closed** — no matching policy denies; an unreachable decision denies.
  * **Explicit intent** — a tool is governed by the intent you declare, never
    inferred from its name or body.
  * **Value-free audit** — argument *values* never enter the trail; only who,
    what intent, which resource, and the decision.
"""

from __future__ import annotations

import datetime
import functools
import hashlib
import hmac
import inspect
import json
import os
import pathlib
import re
import secrets
import time
from typing import Any, Callable, Optional, Sequence, TypeVar, Union

import watchlight_engine as _engine

from ._audit import AuditSink, AuditTrail
from ._counters import (
    DEFAULT_COUNTERS_MAX_BYTES,
    MAX_COUNTERS_LINE_BYTES,
    MAX_COUNTERS_NESTING,
    MAX_COUNTERS_WINDOW_SECONDS,
    AuditTrailUnreadable,
    count_audit_records,
    parse_window_seconds,
)
from .attenuation import DE_MAX_DEPTH, AttenuationDenied, DevEditionCeiling, Scope
from .policytest import load_test_suite, run_policy_tests
from .scope_token import ScopeTokenError, normalize_secret, require_secret, same_set, verify_scope_token

__all__ = [
    "Watchlight",
    "AuditSink",
    "AuditTrailUnreadable",
    "count_audit_records",
    "parse_window_seconds",
    "DEFAULT_COUNTERS_MAX_BYTES",
    "MAX_COUNTERS_LINE_BYTES",
    "MAX_COUNTERS_NESTING",
    "MAX_COUNTERS_WINDOW_SECONDS",
    "Denied",
    "NeedsApproval",
    "AuthorizeError",
    "OBLIGATIONS_INVALID_MESSAGE",
    "MAX_REDACT_ENTRIES",
    "sanitize",
    "SanitizeError",
    "DECISION_ID_MAX_LENGTH",
    "DETECTOR_VERSION",
    "DEFAULT_PII_TYPES",
    "HEURISTIC_PII_TYPES",
    "screen",
    "ScreenError",
    "govern",
    "Scope",
    "AttenuationDenied",
    "DevEditionCeiling",
    "ScopeTokenError",
    "DE_MAX_DEPTH",
    "run_policy_tests",
    "load_test_suite",
]

_F = TypeVar("_F", bound=Callable[..., Any])


class Denied(PermissionError):
    """Raised when the policy engine refuses a governed tool call (fail-closed).

    The decorated function's body never runs — the refusal happens *before* the
    side effect.
    """

    def __init__(self, tool: str, intent: str, reason: str) -> None:
        self.tool = tool
        self.intent = intent
        self.reason = reason
        super().__init__(f"watchlight denied intent '{intent}' on tool/{tool}: {reason}")


class NeedsApproval(PermissionError):
    """Raised when a governed call is permitted only after a human confirmation
    (the matched permit carries the ``require_approval`` enforcement effect) and
    no valid approval was supplied. Fail-closed: the body never ran."""

    def __init__(self, tool: str, intent: str, decision_id: Optional[str], reason: str) -> None:
        self.tool = tool
        self.intent = intent
        self.decision_id = decision_id
        self.reason = reason
        super().__init__(f"watchlight requires human approval for intent '{intent}' on tool/{tool}")


# ── approval tokens (DE: local, single-use, HMAC, TTL) ──────────────────────
# Enterprise mints these KMS-signed and records them in signed lineage.
_APPROVAL_SECRET = secrets.token_bytes(32)
_USED_APPROVALS: set[str] = set()


def _mint_approval_token(principal: str, action: str, resource: str, ttl_ms: int) -> str:
    exp = int(time.time() * 1000) + ttl_ms
    # A per-mint nonce makes every token unique, so two approvals for the same
    # (principal, action, resource) minted in the same millisecond never collide
    # — and "single-use" is genuinely per-mint, not per-(challenge, exp).
    nonce = secrets.token_hex(8)
    payload = f"{principal} {action} {resource} {exp} {nonce}".encode()
    sig = hmac.new(_APPROVAL_SECRET, payload, hashlib.sha256).hexdigest()
    return f"{exp}.{nonce}.{sig}"


def _consume_approval_token(token: str, principal: str, action: str, resource: str) -> bool:
    """Verify + consume (single-use). Bound to the exact (principal, action,
    resource); rejects expired, tampered, or reused tokens."""
    parts = token.split(".")
    if len(parts) != 3:
        return False
    exp_str, nonce, sig = parts
    try:
        exp = int(exp_str)
    except ValueError:
        return False
    if int(time.time() * 1000) > exp:
        return False
    payload = f"{principal} {action} {resource} {exp} {nonce}".encode()
    expected = hmac.new(_APPROVAL_SECRET, payload, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected):
        return False
    if token in _USED_APPROVALS:
        return False
    _USED_APPROVALS.add(token)
    return True


def _needs_approval(details: Any) -> bool:
    """A permitting policy result (``applicable: true``) annotated
    ``require_approval``. A non-matching require_approval policy elsewhere in the
    set must not flag this decision."""
    results = (details or {}).get("policy_results") if isinstance(details, dict) else None
    if not isinstance(results, list):
        return False
    return any(
        isinstance(r, dict) and r.get("applicable") is True
        and r.get("enforcement_effect") == "require_approval"
        for r in results
    )


# `@obligate_max_items` upper bound, as validated by the engine at policy load.
_MAX_ITEMS_UPPER_BOUND = 4294967295
# Bound on a `redact` list — beyond it the payload is treated as unreadable.
MAX_REDACT_ENTRIES = 10000
# Fixed, value-free message of :class:`AuthorizeError`.
OBLIGATIONS_INVALID_MESSAGE = "invalid obligations on an Allow decision"


class AuthorizeError(RuntimeError):
    """An ``Allow`` carries a known obligation (``redact``, ``max_items``,
    ``log_values``) the SDK cannot read. The constraint cannot be honoured, so
    the decision fails closed instead of silently losing it."""

    def __init__(self) -> None:
        super().__init__(OBLIGATIONS_INVALID_MESSAGE)


def _read_obligations(wire: Any) -> Optional[dict]:
    """Read one engine obligations object. A known key that is present but
    unreadable — ``redact`` not a non-empty list of non-blank strings (or longer
    than :data:`MAX_REDACT_ENTRIES`), ``max_items`` not an integer in
    1..=4294967295, ``log_values`` not a boolean — raises :class:`AuthorizeError`:
    a constraint the SDK cannot read must not be silently dropped. ``extra``
    keeps its string values and ignores the rest (uninterpreted by contract).
    An absent field reads as no obligations."""
    if wire is None:
        return None
    if not isinstance(wire, dict):
        raise AuthorizeError()
    out: dict = {}
    if "redact" in wire:
        redact = wire["redact"]
        if not isinstance(redact, list) or not redact or len(redact) > MAX_REDACT_ENTRIES:
            raise AuthorizeError()
        if any(not isinstance(v, str) or not v.strip() for v in redact):
            raise AuthorizeError()
        out["redact"] = list(dict.fromkeys(v.strip() for v in redact))
    if "max_items" in wire:
        max_items = wire["max_items"]
        if (not isinstance(max_items, int) or isinstance(max_items, bool)
                or not 1 <= max_items <= _MAX_ITEMS_UPPER_BOUND):
            raise AuthorizeError()
        out["max_items"] = max_items
    if "log_values" in wire:
        if not isinstance(wire["log_values"], bool):
            raise AuthorizeError()
        out["log_values"] = wire["log_values"]
    extra = wire.get("extra")
    if isinstance(extra, dict):
        clean: dict[str, list[str]] = {}
        for k, v in extra.items():
            if not isinstance(k, str):
                continue
            if isinstance(v, str):
                clean[k] = [v]
            elif isinstance(v, list) and v and all(isinstance(x, str) for x in v):
                clean[k] = sorted(set(v))
        if clean:
            out["extra"] = clean
    return out or None


def _merge_obligations(parts: Sequence[dict]) -> Optional[dict]:
    """Merge every carrier's obligations to the strictest reading: ``redact``
    union (first-seen order), ``max_items`` minimum, ``log_values`` logical
    AND, ``extra`` the sorted distinct values per key."""
    out: dict = {}
    redact: dict[str, None] = {}
    extra_values: dict[str, set[str]] = {}
    for part in parts:
        redact.update(dict.fromkeys(part.get("redact", [])))
        if "max_items" in part:
            out["max_items"] = min(out.get("max_items", part["max_items"]), part["max_items"])
        if "log_values" in part:
            out["log_values"] = out.get("log_values", True) and part["log_values"]
        for k, vs in part.get("extra", {}).items():
            extra_values.setdefault(k, set()).update(vs)
    if redact:
        out["redact"] = list(redact)
    if extra_values:
        out["extra"] = {k: sorted(extra_values[k]) for k in sorted(extra_values)}
    return out or None


def _derive_obligations(details: Any) -> Optional[dict]:
    """The obligations attached to an ``Allow`` — ``{"redact", "max_items",
    "log_values", "extra"}`` (wire spelling), or ``None`` when there is nothing
    to honour.

    Every carrier is merged to the strictest reading — the engine's own merged
    ``details.obligations`` (present on a final Allow) together with the
    ``obligations`` of every permit that determined the decision
    (``policy_results[]`` with ``applicable: true``, exactly as
    :func:`_needs_approval` reads ``enforcement_effect``). A backend that emits
    only one of the two sources therefore yields the same result as one that
    emits both, and a stricter per-policy key is never lost to the engine merge.
    Raises :class:`AuthorizeError` when a known key is present but unreadable.
    Call it only for a decision that may carry obligations — an Allow."""
    if not isinstance(details, dict):
        return None
    parts: list[dict] = []
    results = details.get("policy_results")
    if isinstance(results, list):
        for r in results:
            if isinstance(r, dict) and r.get("applicable") is True:
                o = _read_obligations(r.get("obligations"))
                if o:
                    parts.append(o)
    merged = _read_obligations(details.get("obligations"))
    if merged:
        parts.append(merged)
    return _merge_obligations(parts)


def _resolve(binding: Any, args: tuple, kwargs: dict) -> Optional[str]:
    """Resolve a per-call binding: a fixed value, or a callable of the tool's
    ``(*args, **kwargs)``."""
    if binding is None:
        return None
    return binding(*args, **kwargs) if callable(binding) else binding


# ── sanitize: deterministic PII redaction (mirrors the TS detector) ─────────
# Structured, high-precision rules (email, phone, SSN, credit card w/ Luhn, IBAN,
# IPv4, API keys, labelled passport numbers + MRZ lines, labelled dates of
# birth), an application-supplied dictionary of KNOWN values, and OPT-IN
# heuristics (PERSON, ADDRESS — lower precision, off by default). Regex safety:
# every repetition is either bounded, or anchored on a literal prefix / run
# start so a failed attempt cannot rescan the same run (EMAIL's local part is
# bounded to 64 and may only start where a run of local-part characters
# starts). No nested unbounded repetition; the test suite asserts adversarial
# 100k-character inputs complete in well under 100 ms.
DETECTOR_VERSION = "de-rules-2"

#: Heuristic detectors: lower precision, OFF unless listed in ``types``.
HEURISTIC_PII_TYPES: tuple[str, ...] = ("PERSON", "ADDRESS")


class SanitizeError(RuntimeError):
    """Fail-closed: sanitization could not complete; do NOT use raw content."""


# Bounds on a caller-supplied ``decision_id``: an opaque correlation token, never
# interpreted. Length-capped and free of control characters so it can be written
# to the audit line without letting the caller inject or bloat it.
DECISION_ID_MAX_LENGTH = 128
# U+2028/U+2029 included for parity with the TypeScript lane, whose JSON
# serializer emits them raw (line-oriented readers would split the record).
_DECISION_ID_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f-\x9f\u2028\u2029]")


def _validate_decision_id(decision_id: Any, *, error: type = SanitizeError) -> Optional[str]:
    """Fail-closed check of a correlation id before it reaches the audit line.
    Accepts ``None`` (no correlation); rejects anything that is not a short,
    control-character-free ``str`` by raising ``error`` (the calling
    primitive's own exception type). The id is never parsed."""
    if decision_id is None:
        return None
    if not isinstance(decision_id, str) or not 1 <= len(decision_id) <= DECISION_ID_MAX_LENGTH:
        raise error(f"decision_id must be a string of 1-{DECISION_ID_MAX_LENGTH} characters")
    if _DECISION_ID_CONTROL_CHARS.search(decision_id):
        raise error("decision_id must not contain control characters")
    return decision_id


def _luhn_ok(digits: str) -> bool:
    total, alt = 0, False
    for ch in reversed(digits):
        if not ch.isdigit():
            return False
        d = int(ch)
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


# ── shared shapes (bounded quantifiers only) ──
_MONTH = r"(?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]{0,6}\.?"
_DAY_ORD = r"\d{1,2}(?:st|nd|rd|th)?"
_DATE_SHAPE = (
    r"(?:\d{4}[/.-]\d{1,2}[/.-]\d{1,2}"  # 1985-03-15
    r"|\d{1,2}[/.-]\d{1,2}[/.-]\d{2,4}"  # 03/15/1985, 15.03.85
    rf"|{_DAY_ORD}[ \t]{{1,3}}{_MONTH}[ \t]{{1,3}}\d{{4}}"  # 15 March 1985
    rf"|{_MONTH}[ \t]{{1,3}}{_DAY_ORD},?[ \t]{{1,3}}\d{{4}})"  # March 15, 1985
)
_DOB_LABEL = r"(?:d\.?o\.?b\.?|date[ \t]{1,3}of[ \t]{1,3}birth|birth[ \t]?date|birthday|born(?:[ \t]{1,3}on)?)"
_CAP_WORD = r"[A-Z][a-z]{1,20}"
# "Ada", "O'Neil", "D'Angelo", "McDonald", "Lovelace-Smith", "McDonald-Lee".
_NAME_PART = rf"{_CAP_WORD}(?:{_CAP_WORD})?"
_NAME_WORD = rf"(?:[A-Z]')?{_NAME_PART}(?:[-']{_NAME_PART})?"
_HONORIFIC = r"(?:Mr|Mrs|Ms|Miss|Mx|Dr|Prof|Sir|Dame|Rev|Hon)\.?"
# Case-tolerant label (the pattern itself is case-sensitive so name words stay Title Case).
_PERSON_LABEL = (
    r"(?:[Nn]ame|[Pp]atient|[Cc]ustomer|[Cc]lient|[Ee]mployee|[Cc]ontact|[Aa]ttn|ATTN"
    r"|[Aa]ttention|[Aa]pplicant|[Bb]eneficiary)"
)
_STREET_SUFFIX = (
    r"(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Way|Place|Pl"
    r"|Terrace|Ter|Circle|Cir|Parkway|Pkwy|Highway|Hwy|Square|Sq|Trail|Trl|Close|Crescent|Cres)"
)

# Common capitalized sentence starters / calendar words that are not names.
# Leading stop words are trimmed off a candidate; the remaining name is kept.
_PERSON_STOP = frozenset(
    "The This That These Those There Then Thanks Thank Please Dear Hello Hi Hey Our Your Their "
    "His Her New Re Subject From To Date Sent Cc Bcc Note Notes Summary Total Amount Invoice Order "
    "Account Card Page Section Chapter Table Figure See Also However "
    "Monday Tuesday Wednesday Thursday Friday Saturday Sunday "
    "January February March April May June July August September October November December".split()
)


def _plausible_date(m: str) -> bool:
    """Plausibility check for numeric date shapes (labelled contexts only)."""
    if not m[:1].isdigit() or not re.fullmatch(r"[\d/.-]+", m):
        return True  # textual month: shape already strict
    try:
        parts = [int(p) for p in re.split(r"[/.-]", m)]
    except ValueError:
        return False
    if len(parts) != 3:
        return False
    year_idx = next((i for i, p in enumerate(parts) if p >= 1000), -1)
    small = [p for i, p in enumerate(parts) if i != year_idx]
    if year_idx >= 0 and not (1900 <= parts[year_idx] <= 2099):
        return False
    if year_idx < 0:
        small.pop()  # two-digit year in last position
    return all(1 <= p <= 31 for p in small) and min(small) <= 12


def _trim_person_stop(m: str) -> Optional[str]:
    """Strip leading stop words; drop the candidate if fewer than two words remain."""
    v = m
    while True:
        ws = re.search(r"[ \t]", v)
        if ws is None:
            return None  # single word left → not a name candidate
        if v[: ws.start()] not in _PERSON_STOP:
            return v
        v = v[ws.start():].lstrip(" \t")


# (type, pattern, validator, redact_group_1, default_on[, front_trim]). A group-1
# or trimmed span is always the LAST component of the match (a label such as
# ``DOB:`` precedes it and is kept).
_DETECTORS: list[tuple] = [
    # Local part bounded (RFC 5321: 64) and only attempted where a run of
    # local-part characters begins, so a long run without "@" is scanned once.
    ("EMAIL", re.compile(r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,24}\b"),
     None, False, True),
    ("API_KEY", re.compile(r"\b(?:sk-[A-Za-z0-9]{16,}|ghp_[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16})\b"),
     None, False, True),
    ("SSN", re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"), None, False, True),
    ("CREDIT_CARD", re.compile(r"\b(?:\d[ -]?){13,19}\b"),
     lambda m: 13 <= len(re.sub(r"[ -]", "", m)) <= 19 and _luhn_ok(re.sub(r"[ -]", "", m)), False, True),
    ("IBAN", re.compile(r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Za-z0-9]{4}){2,7}(?:[ ]?[A-Za-z0-9]{1,3})?\b"), None, False, True),
    ("IPV4", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
     lambda m: all(int(o) <= 255 for o in m.split(".")), False, True),
    # PASSPORT (a): a number labelled as a passport — 6–9 alphanumerics with at
    # least one digit. Bare unlabelled numbers are NOT detected (too ambiguous;
    # list held numbers in ``known``).
    ("PASSPORT",
     re.compile(r"\bpassport(?:[ \t]{1,3}(?:no|number|num|nr))?\.?[ \t]{0,4}[:#-]{0,2}[ \t]{0,4}([A-Za-z0-9]{6,9})(?![A-Za-z0-9])",
                re.IGNORECASE),
     lambda m: any(ch.isdigit() for ch in m), True, True),
    # PASSPORT (b): ICAO 9303 TD3 machine-readable-zone lines (44 chars), as
    # produced by OCR of a passport data page.
    ("PASSPORT",
     re.compile(r"(?<![A-Z0-9<])(?:P[A-Z<][A-Z]{3}[A-Z<]{39}|[A-Z0-9<]{9}\d[A-Z<]{3}\d{7}[MF<]\d{7}[A-Z0-9<]{14}\d{2})(?![A-Z0-9<])"),
     None, False, True),
    # DOB: a date in a birth-date context (``DOB:``, ``date of birth``, ``born on``).
    # Bare dates are not detected — a statement date is not a birth date.
    ("DOB", re.compile(rf"\b{_DOB_LABEL}[ \t]{{0,4}}[:#=-]?[ \t]{{0,4}}({_DATE_SHAPE})(?!\d)", re.IGNORECASE),
     _plausible_date, True, True),
    ("PHONE", re.compile(r"(?<!\d)(?:\+?\d{1,3}[ .-]?)?(?:\(\d{2,4}\)[ .-]?)?\d{3}[ .-]?\d{4}(?!\d)"),
     lambda m: len(re.sub(r"\D", "", m)) >= 10, False, True),
    # ── opt-in heuristics (default OFF; list in ``types`` to enable) ──
    # ADDRESS: "<number> <Capitalized words> <street suffix>[, unit][, City, ST 12345]"
    # and "P.O. Box <n>". Misses unnumbered / lower-case / non-Latin addresses.
    ("ADDRESS",
     re.compile(
         rf"\b(?:\d{{1,6}}[A-Za-z]?[ \t]{{1,3}}(?:{_CAP_WORD}[ \t]{{1,3}}){{1,4}}{_STREET_SUFFIX}\b\.?"
         rf"(?:,?[ \t]{{1,3}}(?:Apt|Suite|Ste|Unit|#)\.?[ \t]{{0,3}}[A-Za-z0-9-]{{1,8}})?"
         rf"(?:,[ \t]{{1,3}}{_CAP_WORD}(?:[ \t]{_CAP_WORD}){{0,2}},?[ \t]{{1,3}}[A-Z]{{2}}[ \t]{{1,3}}\d{{5}}(?:-\d{{4}})?)?"
         rf"|\bP\.?[ \t]?O\.?[ \t]{{1,3}}Box[ \t]{{1,3}}\d{{1,6}}\b)"
     ),
     None, False, False),
    # PERSON (a): honorific- or label-anchored names ("Dr. Ada Lovelace", "Patient: Ada Lovelace").
    ("PERSON",
     re.compile(
         rf"\b(?:{_HONORIFIC}|{_PERSON_LABEL}[ \t]{{0,3}}[:#-]?)[ \t]{{1,4}}"
         rf"({_NAME_WORD}(?:[ \t]{{1,3}}[A-Z]\.)?(?:[ \t]{{1,3}}{_NAME_WORD}){{0,2}})(?![A-Za-z])"
     ),
     None, True, False),
    # PERSON (b): bare "First [M.] Last [Last]" capitalized runs. Inherently low
    # precision (any Title Case phrase); a stop-list trims sentence starters.
    ("PERSON", re.compile(rf"\b{_NAME_WORD}(?:[ \t][A-Z]\.)?(?:[ \t]{_NAME_WORD}){{1,2}}(?![A-Za-z])"),
     None, False, False, _trim_person_stop),
]

#: The structured (default-on) detector types, in priority order.
DEFAULT_PII_TYPES: tuple[str, ...] = tuple(dict.fromkeys(d[0] for d in _DETECTORS if d[4]))


_END = object()


def _trie_regex(values: Sequence[str]) -> str:
    """Escaped prefix-trie alternation over the values: at each position the
    regex walks the trie (cost bounded by the trie's branching, not the
    dictionary size) and prefers the longest value (children before the empty
    branch)."""
    root: dict = {}
    for v in values:
        node = root
        for ch in v:
            node = node.setdefault(ch, {})
        node[_END] = True

    def render(node: dict) -> str:
        alts = [re.escape(ch) + render(node[ch]) for ch in sorted(k for k in node if k is not _END)]
        if _END in node:
            alts.append("")
        return alts[0] if len(alts) == 1 and alts[0] != "" else "(?:" + "|".join(alts) + ")"

    return render(root)


def _detect_known(text: str, known: Sequence[str]) -> list[tuple[int, int, str, str]]:
    """Every occurrence of every known value, case-insensitive; overlapping
    occurrences merge into one span. One escaped trie alternation compiled once
    per call; at each position the longest value wins and the scan resumes one
    character later, so every occurrence of every value is covered. Values are
    never logged or raised."""
    values = list(dict.fromkeys(v for v in known if v.strip()))
    if not values:
        return []
    pat = re.compile(_trie_regex(values), re.IGNORECASE)
    raw: list[tuple[int, int]] = []
    pos = 0
    while (m := pat.search(text, pos)) is not None:
        raw.append((m.start(), m.end()))
        pos = m.start() + 1  # also find overlapping occurrences
    merged: list[list[int]] = []
    for s, e in raw:
        if merged and s < merged[-1][1]:
            if e > merged[-1][1]:
                merged[-1][1] = e
        else:
            merged.append([s, e])
    return [(s, e, "KNOWN", text[s:e]) for s, e in merged]


def sanitize(
    text: str,
    *,
    mode: str = "tag",
    types: Optional[Sequence[str]] = None,
    decision_id: Optional[str] = None,
    known: Optional[Sequence[str]] = None,
) -> dict:
    """Redact PII from ``text``. Deterministic, fail-closed. Returns
    ``{"text": ..., "report": {mode, detector_version, counts, total}}`` where the
    report is value-free (counts by type — never the values). ``mode`` is
    ``tag`` (consistent ``<EMAIL_1>``), ``mask`` (``[EMAIL]``), or ``hash``.
    ``types`` restricts the detectors (default: every structured type; the
    heuristics ``PERSON`` / ``ADDRESS`` run only when listed). ``known`` is an
    application-supplied dictionary of exact strings to redact — matched
    case-insensitively as substrings, every occurrence covered, counted under
    ``KNOWN``; the values never appear in the output, report, or audit trail.
    Dictionary matching is simple (ASCII-style) case-insensitive; Unicode case
    folding differs between the Python and TypeScript lanes.
    ``decision_id`` — the correlation id of the :meth:`Watchlight.authorize`
    decision that governed this read — is validated (1-128 code points, no control or line-separator
    characters) and echoed onto ``report["decision_id"]``."""
    if not isinstance(text, str):
        raise SanitizeError("input must be a string (extract document text first)")
    decision_id = _validate_decision_id(decision_id)
    if known is not None and isinstance(known, (str, bytes)):
        # A bare string is a Sequence[str] of characters — never what was meant.
        raise SanitizeError("known must be a sequence of strings")
    known_values = list(known) if known is not None else []
    if not all(isinstance(v, str) for v in known_values):
        # Value-free by design: the message never echoes the offending entry.
        raise SanitizeError("known must be a sequence of strings")
    enabled = set(types) if types is not None else set(DEFAULT_PII_TYPES)
    try:
        # KNOWN first: an application-supplied value is the most authoritative
        # label when it ties with a structured detector on the same span.
        spans: list[tuple[int, int, str, str]] = _detect_known(text, known_values) if known_values else []
        for det in _DETECTORS:
            typ, pat, valid, group, _default = det[:5]
            trim = det[5] if len(det) > 5 else None
            if typ not in enabled:
                continue
            for m in pat.finditer(text):
                val: Optional[str] = m.group(1) if group else m.group(0)
                if trim is not None:
                    val = trim(val)
                if val is None:
                    continue
                # group / trimmed spans are the LAST component of the match
                start = m.end() - len(val)
                if valid and not valid(val):
                    continue
                spans.append((start, start + len(val), typ, val))
        # Resolve overlaps as a UNION: earliest start, then longest (ties keep
        # detector order via stable sort). A span fully inside one already kept
        # is dropped; one extending past it is clipped to the uncovered tail and
        # kept under its own type — so no character matched by any enabled
        # detector (or dictionary value) survives, whatever else overlaps it.
        spans.sort(key=lambda s: (s[0], -(s[1] - s[0])))
        kept: list[tuple[int, int, str, str]] = []
        last_end = -1
        for s in spans:
            if s[0] >= last_end:
                kept.append(s)
                last_end = s[1]
            elif s[1] > last_end:
                kept.append((last_end, s[1], s[2], text[last_end:s[1]]))
                last_end = s[1]
        counters: dict[str, str] = {}
        per_type: dict[str, int] = {}
        counts: dict[str, int] = {}
        out, cursor = [], 0
        for start, end, typ, val in kept:
            out.append(text[cursor:start])
            # KNOWN values were matched case-insensitively, so hash and tag keys are too.
            key_value = val.lower() if typ == "KNOWN" else val
            if mode == "mask":
                rep = f"[{typ}]"
            elif mode == "hash":
                rep = f"<{typ}_{hashlib.sha256(key_value.encode()).hexdigest()[:8]}>"
            else:
                key = f"{typ}:{key_value}"
                rep = counters.get(key)
                if rep is None:
                    per_type[typ] = per_type.get(typ, 0) + 1
                    rep = f"<{typ}_{per_type[typ]}>"
                    counters[key] = rep
            out.append(rep)
            cursor = end
            counts[typ] = counts.get(typ, 0) + 1
        out.append(text[cursor:])
        report: dict[str, Any] = {
            "mode": mode, "detector_version": DETECTOR_VERSION, "counts": counts, "total": len(kept),
        }
        if decision_id is not None:
            report["decision_id"] = decision_id
        return {"text": "".join(out), "report": report}
    except Exception as exc:  # noqa: BLE001 - fail-closed
        raise SanitizeError(str(exc)) from exc


# ── caller-facing decision reasons (SECURITY: uniform + non-revealing) ──────
# The reason surfaced to the caller NEVER explains WHY a request was denied — a
# specific reason ("no matching policy" vs "forbidden by X" vs "amount exceeds
# limit") would leak the authorization boundary to an attacker probing it, who
# could then tune an attack. Every denial returns the SAME opaque reason; the
# Denied message still names the caller's own request (intent + tool), which is
# their input, not a leak. Operators reconstruct the true cause from signed
# lineage / the decisionId (Enterprise), never from this string.
DENY_REASON = "not authorized"
APPROVAL_REASON = "approval required"


def _reason_for_verdict(verdict: str) -> str:
    if verdict == "Deny":
        return DENY_REASON
    if verdict == "NeedsApproval":
        return APPROVAL_REASON
    return ""


# ── screen: rule-based prompt-injection / output screening (mirrors TS) ─────
# Screen text BEFORE it (re-)enters the model — a retrieved page, a tool result,
# a document — and screen what the model PRODUCES before it leaves. Deterministic,
# in-process, rule-based, fail-closed. Same value-free contract as ``sanitize``:
# the report carries counts per rule family and never the matched text, offsets,
# or the input.
#
# Honest bound: a RULE-BASED detector for well-known injection phrasings, not an
# ML classifier. Robust to case, run-on whitespace / line breaks and zero-width
# characters; does NOT decode leetspeak, homoglyphs, encodings or paraphrase.
# Text that QUOTES an attack string verbatim is flagged — by design. Treat
# ``flagged`` as a signal to route, refuse or log, not as a verdict on intent.
# ``redact`` marks the TRIGGER (a whole <script>…</script> element when its body
# has no '<'); it does not neutralise HTML. Markers can be spoofed by input text:
# consumers decide from the report, never by scanning for markers. Only known
# divergence from TS: Python's re case-folds the Turkish dotted capital İ
# (U+0130) onto ``i``; JavaScript does not.
SCREEN_DETECTOR_VERSION = "de-screen-1"

SCREEN_FAMILIES: tuple[str, ...] = (
    "INSTRUCTION_OVERRIDE",
    "ROLE_SWITCH",
    "PROMPT_EXFILTRATION",
    "JAILBREAK_MARKER",
    "AUTHORITY_IMPERSONATION",
    "HTML_INJECTION",
    "PROMPT_LEAK",
)


class ScreenError(RuntimeError):
    """Fail-closed: screening could not complete; do NOT treat the content as clean."""


# Normalization: zero-width characters removed, every whitespace run collapsed to
# ONE space, with an index map back to the original so ``redact`` replaces the
# ORIGINAL span. Both sets are spelled out (not ``\s``) to match the TS twin exactly.
_ZERO_WIDTH = "\u00ad\u200b-\u200f\u2060-\u2064\ufeff"
_WHITESPACE = "\t\n\v\f\r \u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000"
_SKIP_RUN = re.compile(f"[{_ZERO_WIDTH}{_WHITESPACE}]+")
_HAS_WS = re.compile(f"[{_WHITESPACE}]")


def _screen_normalize(text: str) -> tuple[str, list[int]]:
    parts: list[str] = []
    idx: list[int] = []
    cursor = 0
    for m in _SKIP_RUN.finditer(text):
        s, e = m.span()
        if s > cursor:
            parts.append(text[cursor:s])
            idx.extend(range(cursor, s))
        ws = _HAS_WS.search(m.group(0))
        if ws:  # a run with any whitespace → one space; zero-width-only → vanishes
            parts.append(" ")
            idx.append(s + ws.start())
        cursor = e
    if cursor < len(text):
        parts.append(text[cursor:])
        idx.extend(range(cursor, len(text)))
    return "".join(parts), idx


# Rules: case-insensitive alternations of LITERAL tokens joined by single spaces,
# optional groups and only BOUNDED repetition — never a nested unbounded
# quantifier — so matching is linear. ``_B``/``_E`` are ASCII word boundaries as
# lookarounds so Python and JS agree (``\b`` is Unicode-aware here, ASCII in JS).
_B = "(?<![a-z0-9_])"
_E = "(?![a-z0-9_])"
_FILL = "(?:[a-z-]+,? ){0,3}"
_PROMPT_NOUN = (
    "(?:system prompt|initial prompt|original prompt|hidden prompt|secret prompt|developer prompt|"
    "system message|system instructions|initial instructions|original instructions|hidden instructions|"
    "secret instructions|developer instructions|pre-?prompt|meta-?prompt)"
)
_PROMPT_ADJ = "(?:(?:full|entire|complete|exact|whole|original|hidden|secret|internal|verbatim) )?"
# Output-side nouns: a prompt noun, or a generic noun qualified as system/hidden.
_LEAK_NOUN = (
    f"(?:{_PROMPT_NOUN}|(?:system|hidden|secret|initial|original|developer|internal|underlying) "
    "(?:instructions|guidelines|rules|configuration|prompt|directives))"
)

_SCREEN_RULES: list[tuple[str, re.Pattern]] = [
    (fam, re.compile(src, re.IGNORECASE))
    for fam, src in [
        # ── INSTRUCTION_OVERRIDE ──
        ("INSTRUCTION_OVERRIDE",
         f"{_B}(?:ignore|disregard|forget|override|bypass|discard|do not follow|don't follow|stop following) "
         "(?:all |any |the |your |my |these |those |all of your |all of the |any of your )?"
         "(?:previous|prior|above|earlier|preceding|initial|original|system|foregoing|existing) "
         f"(?:instructions?|prompts?|rules|directions|directives|guidelines|guidance|constraints|context|programming|training|messages?){_E}"),
        ("INSTRUCTION_OVERRIDE",
         f"{_B}(?:ignore|disregard|forget|override|bypass|discard) (?:all|any|everything) (?:of )?(?:your |the |my )?"
         f"(?:instructions|prompts|rules|directions|directives|guidelines|constraints|programming|training|you were told|you have been told|above|before){_E}"),
        ("INSTRUCTION_OVERRIDE", f"{_B}disregard the above{_E}"),
        ("INSTRUCTION_OVERRIDE", f"{_B}(?:your |the )?new (?:instructions?|directives?|rules) ?:"),
        ("INSTRUCTION_OVERRIDE",
         f"{_B}(?:instead|rather than that|from now on),? (?:you must|you will|you should|you have to|always) (?:only )?(?:do|say|respond|reply|answer|output|write|follow){_E}"),
        # ── ROLE_SWITCH ──
        ("ROLE_SWITCH",
         f"{_B}you are now (?:a |an |the |my )?{_FILL}(?:assistant|ai|bot|chatbot|agent|persona|hacker){_E}"),
        ("ROLE_SWITCH",
         f"{_B}(?:act|behave|respond|answer|reply|roleplay|role-play|role play) as (?:a |an |the |if you were |if you are ){_FILL}"
         f"(?:assistant|ai|bot|chatbot|agent|persona|hacker){_E}"),
        ("ROLE_SWITCH",
         f"{_B}pretend (?:to be|you are|you're|that you are|that you're) (?:a |an |the |my )?{_FILL}"
         f"(?:assistant|ai|bot|chatbot|agent|persona|character|hacker|human|person|unrestricted|unfiltered|uncensored){_E}"),
        ("ROLE_SWITCH",
         f"{_B}(?:enter|switch to|activate|enable) (?:the )?{_FILL}(?:persona|character|roleplay|role-play) (?:mode|now){_E}"),
        # ── PROMPT_EXFILTRATION ──
        ("PROMPT_EXFILTRATION",
         f"{_B}(?:reveal|show|print|display|output|repeat|recite|disclose|leak|dump|expose|share|tell|give|send|write|spell|paste|echo|return|summarize|summarise|translate|encode|quote) "
         "(?:me |us |back |out |it )?(?:all |all of |the full |the entire |the complete |the exact |the whole )?"
         f"(?:your|the|this) {_PROMPT_ADJ}{_PROMPT_NOUN}{_E}"),
        ("PROMPT_EXFILTRATION",
         f"{_B}what (?:is|are|were|was|does|do) (?:your|the) {_PROMPT_ADJ}{_PROMPT_NOUN}(?: say| contain| include)?{_E}"),
        ("PROMPT_EXFILTRATION",
         f"{_B}(?:repeat|print|output|show|reveal|display|echo|copy|paste) (?:everything|all the text|the text|all text|all words|everything written|the words|the content|the conversation) "
         f"(?:above|before this|before your|preceding this|so far){_E}"),
        ("PROMPT_EXFILTRATION",
         f"{_B}(?:your|the) {_PROMPT_NOUN} (?:verbatim|word for word|word-for-word|in full|exactly as written){_E}"),
        # ── JAILBREAK_MARKER ──
        ("JAILBREAK_MARKER",
         f"{_B}(?:dan|jailbreak|jailbroken|unrestricted|unfiltered|uncensored|evil|opposite|no[- ]rules|no[- ]filter|anti[- ]?gpt) mode{_E}"),
        ("JAILBREAK_MARKER", f"{_B}developer mode (?:enabled|output|activated|unlocked|response){_E}"),
        ("JAILBREAK_MARKER", f"{_B}do anything now{_E}"),
        ("JAILBREAK_MARKER", f"{_B}you are (?:now )?dan(?: [0-9]+(?:\\.[0-9]+)?)?{_E}"),
        ("JAILBREAK_MARKER",
         f"{_B}(?:an?|the) (?:unrestricted|unfiltered|uncensored|jailbroken) (?:ai|assistant|model|chatbot|bot|agent){_E}"),
        ("JAILBREAK_MARKER",
         f"{_B}you (?:are (?:now )?(?:free (?:of|from)|without|not bound by|no longer bound by|not restricted by|not limited by|not subject to|exempt from)) "
         f"(?:all |any |your |the )?(?:restrictions|rules|guidelines|filters|limitations|limits|content polic(?:y|ies)|safety (?:guidelines|rules|filters|measures|training)|ethical (?:guidelines|constraints|considerations)|guardrails|censorship){_E}"),
        ("JAILBREAK_MARKER",
         f"{_B}(?:respond|answer|reply|act|operate|behave|write|continue|proceed) (?:without|with no|free of|ignoring|bypassing|regardless of) "
         f"(?:any |all |your |the )?(?:restrictions|filters|guardrails|limits|limitations|censorship|content polic(?:y|ies)|safety (?:guidelines|rules|filters|measures)|ethical (?:guidelines|constraints|considerations)|moral (?:guidelines|constraints)){_E}"),
        ("JAILBREAK_MARKER",
         f"{_B}you (?:have no|no longer have) (?:any |all |your |the )?(?:restrictions|filters|guardrails|censorship|content polic(?:y|ies)|safety (?:guidelines|rules|filters|measures|training)|ethical (?:guidelines|constraints|considerations)){_E}"),
        ("JAILBREAK_MARKER", f"{_B}you (?:are|have been|are now) (?:jailbroken|unrestricted|unfiltered|uncensored){_E}"),
        # ── AUTHORITY_IMPERSONATION ──
        ("AUTHORITY_IMPERSONATION",
         f"{_B}(?:as|i am|i'm|this is|speaking as|on behalf of|message from|note from|instructions? from|directive from|order from) your "
         f"(?:(?:system|new|lead|senior|chief|head) )?(?:administrator|admin|sysadmin|operator|developer|developers|creator|creators|owner|maintainer|programmer|engineer|supervisor|trainer|security team|safety team){_E}"),
        ("AUTHORITY_IMPERSONATION",
         f"{_B}(?:you (?:are|have been|are now) (?:granted|given|authorized with|authorised with)|i (?:hereby )?(?:grant|give) you|granting you) "
         f"(?:full|elevated|root|admin|administrator|administrative|operator|developer|unrestricted|special|complete) (?:access|privileges|permissions|clearance|authority|rights){_E}"),
        ("AUTHORITY_IMPERSONATION",
         f"{_B}(?:system|admin|administrator|operator|root|sudo|maintenance|debug|security|safety) (?:override(?: (?:code|engaged|activated|enabled|accepted|authorized|authorised|granted)|:)|command mode|access granted|privileges granted|authorization granted|authorisation granted|mode activated){_E}"),
        ("AUTHORITY_IMPERSONATION",
         f"{_B}this (?:message|instruction|request|command) (?:is|comes|was|has been) (?:authori[sz]ed|approved|sanctioned|verified|signed) by (?:your|the) "
         f"(?:administrator|admin|operator|developers?|creators?|owner|security team|compliance team|safety team){_E}"),
        # ── HTML_INJECTION ──
        ("HTML_INJECTION", "<script[^<>]{0,200}>[^<]{0,5000}</script ?>"),
        ("HTML_INJECTION", "</?(?:script|iframe|object|embed|applet|frame|frameset)(?=[ >/])"),
        ("HTML_INJECTION", "<meta [^<>]{0,200}?http-equiv"),
        ("HTML_INJECTION",
         "(?<=[ \"'/<>])on(?:load|error|click|dblclick|mouseover|mouseenter|mouseleave|mousedown|mouseup|focus|blur|input|change|submit|reset|keydown|keyup|keypress|abort|animationstart|animationend|transitionend|toggle|pointerdown|pointerup|touchstart|touchend|wheel|scroll|beforeunload|unload|hashchange|message|resize|select|drag|drop|copy|paste|cut) ?="),
        ("HTML_INJECTION", f"{_B}(?:javascript|vbscript|livescript):(?=[^ ])"),
        ("HTML_INJECTION", f"{_B}data:text/html"),
        ("HTML_INJECTION",
         "style ?= ?[\"']?[^\"'<>]{0,200}?(?:display ?: ?none|visibility ?: ?hidden|font-size ?: ?0(?:px|pt|em|rem|%)?(?![0-9.])|opacity ?: ?0(?:\\.0+)?(?![0-9.])|color ?: ?transparent)"),
        ("HTML_INJECTION", "<[a-z][a-z0-9]{0,20}[^<>]{0,200}? hidden(?=[ >/=])"),
        # ── PROMPT_LEAK (output side) ──
        ("PROMPT_LEAK",
         f"{_B}my {_PROMPT_ADJ}{_LEAK_NOUN} "
         f"(?:is|are|was|were|reads?|says?|states?|begins?|starts?|includes?|tells? me|specif(?:y|ies)|require[s]?){_E}"),
        ("PROMPT_LEAK",
         f"{_B}here (?:is|are) my {_PROMPT_ADJ}{_LEAK_NOUN}{_E}"),
        ("PROMPT_LEAK",
         f"{_B}(?:system prompt|system message|system instructions|initial prompt|hidden prompt|developer message|developer prompt|pre-?prompt) ?:"),
        ("PROMPT_LEAK",
         f"{_B}i (?:was|am|have been|were) (?:instructed|programmed|configured) (?:not to|never to|to (?:never|not|keep|only|refuse|avoid|always|withhold|hide|conceal|decline)|by (?:my|the) (?:developers?|creators?|operator|administrator|system prompt)){_E}"),
    ]
]


def screen(
    text: str,
    *,
    mode: str = "report",
    families: Optional[Sequence[str]] = None,
    decision_id: Optional[str] = None,
) -> dict:
    """Screen ``text`` for prompt-injection / output-leak shapes. Deterministic,
    fail-closed. Returns ``{"text": ..., "report": {mode, detector_version,
    counts, total, flagged}}`` — the report is value-free (counts per family,
    never the matched text). ``mode`` is ``report`` (text untouched, default) or
    ``redact`` (each match replaced by ``[FAMILY]`` in the ORIGINAL text).

    ``decision_id`` — the correlation id of the :meth:`Watchlight.authorize`
    decision that governed the read. Opaque and never interpreted; validated
    (1-128 characters, no control characters, else :class:`ScreenError`) and
    echoed onto ``report["decision_id"]``."""
    if not isinstance(text, str):
        raise ScreenError("input must be a string")
    if mode not in ("report", "redact"):
        raise ScreenError("unknown mode (expected 'report' or 'redact')")
    requested = tuple(families) if families is not None else SCREEN_FAMILIES
    if not requested:
        raise ScreenError("families must name at least one family")
    for fam in requested:
        if fam not in SCREEN_FAMILIES:
            raise ScreenError("unknown family")
    enabled = set(requested)
    decision_id = _validate_decision_id(decision_id, error=ScreenError)
    try:
        norm, idx = _screen_normalize(text)
        spans: list[tuple[int, int, str]] = []
        for fam, pat in _SCREEN_RULES:
            if fam not in enabled:
                continue
            for m in pat.finditer(norm):
                if m.end() > m.start():
                    spans.append((m.start(), m.end(), fam))
        # resolve overlaps: earliest start, then longest; rule order breaks ties
        spans.sort(key=lambda s: (s[0], -(s[1] - s[0])))
        kept: list[tuple[int, int, str]] = []
        last_end = -1
        for s in spans:
            if s[0] >= last_end:
                kept.append(s)
                last_end = s[1]
        counts: dict[str, int] = {}
        for _, _, fam in kept:
            counts[fam] = counts.get(fam, 0) + 1
        out = text
        if mode == "redact" and kept:
            parts, cursor = [], 0
            for start, end, fam in kept:
                o_start, o_end = idx[start], idx[end - 1] + 1
                parts.append(text[cursor:o_start])
                parts.append(f"[{fam}]")
                cursor = o_end
            parts.append(text[cursor:])
            out = "".join(parts)
        report: dict[str, Any] = {
            "mode": mode,
            "detector_version": SCREEN_DETECTOR_VERSION,
            "counts": counts,
            "total": len(kept),
            "flagged": len(kept) > 0,
        }
        if decision_id is not None:
            report["decision_id"] = decision_id
        return {"text": out, "report": report}
    except ScreenError:
        raise
    except Exception as exc:  # noqa: BLE001 - fail-closed
        raise ScreenError(str(exc)) from exc


class Watchlight:
    """An in-process policy decision point for a single agent.

    Wraps the ``watchlight-engine`` in-process authorization core. Policies are
    loaded from a local file or added inline; each governed tool call is
    authorized against them.
    """

    def __init__(
        self,
        agent: str | None = None,
        audit_dir: str | os.PathLike[str] = ".watchlight",
        audit_sink: Optional[AuditSink] = None,
        *,
        token_secret: Union[str, bytes, None] = None,
    ) -> None:
        """:param agent: stable agent identity for the audit trail (default
            ``$WATCHLIGHT_AGENT`` or ``"my-agent"``).
        :param audit_dir: directory for the audit trail; ``audit.jsonl`` is
            written inside it.
        :param audit_sink: additive destination for every audit record —
            decisions, sanitizations and attenuations (including those of scopes
            derived via :meth:`scope` or rebuilt via :meth:`scope_from_token`).
            Receives its own copy of exactly the fields the ``audit.jsonl`` line
            carries; the local file stays on. Fire-and-forget: an awaitable it
            returns is scheduled on the running event loop (never awaited
            inline), and an exception or rejection is reported once and never
            blocks or changes a decision.
        :param token_secret: shared secret (≥ 16 bytes) for
            :meth:`~watchlight.attenuation.Scope.to_token` /
            :meth:`scope_from_token` — lets an attenuated scope cross a process
            boundary with integrity. Defaults to ``$WATCHLIGHT_TOKEN_SECRET``.
            When unset, minting and verifying scope tokens fail closed; there is
            no built-in default. Never logged or written."""
        self._engine = _engine.PolicyEngine()
        self.agent = agent or os.environ.get("WATCHLIGHT_AGENT", "my-agent")
        self._audit_path = pathlib.Path(audit_dir) / "audit.jsonl"
        self._trail = AuditTrail(self._audit_path, audit_sink)
        self._announced = False
        self._policy_count = 0
        self._token_secret = normalize_secret(
            token_secret if token_secret is not None else os.environ.get("WATCHLIGHT_TOKEN_SECRET")
        )

    # ── policy loading ──────────────────────────────────────────────

    def allow(self, cedar_code: str, name: str | None = None) -> "Watchlight":
        """Add one Cedar policy inline. Returns self for chaining."""
        self._engine.add_policy(
            json.dumps({"name": name or f"policy-{self._policy_count}", "code": cedar_code})
        )
        self._policy_count += 1
        return self

    def load(self, path: str | os.PathLike[str]) -> "Watchlight":
        """Load policies from a JSON file — a list of ``{"name", "code"}`` objects
        (or ``{"policies": [...]}``). Fail-closed: a missing file loads nothing,
        so every governed call is denied until a policy permits it."""
        p = pathlib.Path(path)
        if not p.exists():
            return self
        data = json.loads(p.read_text())
        entries = data if isinstance(data, list) else data.get("policies", [])
        for entry in entries:
            self.allow(entry["code"], entry.get("name"))
        return self

    # ── sub-agent scope attenuation ─────────────────────────────────

    def scope(
        self,
        *,
        tools: Sequence[str] | None = None,
        resources: Sequence[str] | None = None,
        intents: Sequence[str] | None = None,
        max_depth: int = DE_MAX_DEPTH,
        time_budget_seconds: int = 3600,
    ) -> Scope:
        """Create a root capability scope for this agent, from which sub-agent
        scopes are attenuated (strict-subset).

        The Developer Edition governs the tree up to depth
        :data:`~watchlight.attenuation.DE_MAX_DEPTH` (5); Enterprise removes the
        ceiling and enforces it server-side. See
        :class:`~watchlight.attenuation.Scope`.
        """
        root = Scope(
            engine=self._engine,
            audit_path=self._audit_path,
            audit=self._trail,  # one funnel: attenuations reach the same audit_sink
            agent=self.agent,
            allowed_tools=tools,
            allowed_resources=resources,
            allowed_intents=intents,
            max_depth=min(int(max_depth), DE_MAX_DEPTH),
            time_budget_seconds=time_budget_seconds,
            depth=0,
            token_secret=self._token_secret,
        )
        root._emit_root()  # record the tree's starting authority for `watchlight dev`
        return root

    def scope_from_token(self, token: str) -> Scope:
        """Re-establish a scope minted by
        :meth:`~watchlight.attenuation.Scope.to_token` in another process.

        Verifies the token's format, HMAC (constant-time), agent binding,
        ``iat``/``exp`` window and lifetime bound, then rebuilds the root grant
        and replays every level of the chain through the engine's strict-subset
        attenuation — exactly as if ``attenuate()`` had been called here. The
        engine, not the token, decides whether each level is a subset: a widened
        chain raises :class:`AttenuationDenied` even with a valid signature, and
        a chain whose engine-granted result differs from the token's claim is
        rejected. Raises :class:`ScopeTokenError` when ``token_secret`` is unset
        (fail-closed) or the token is malformed, tampered, expired, or bound to a
        different agent. The returned scope cannot outlive the token's ``exp``."""
        secret = require_secret(self._token_secret)
        claims = verify_scope_token(token, secret, agent=self.agent)
        root = claims["root"]
        scope = self.scope(
            tools=root["tools"],
            resources=root["resources"],
            intents=root["intents"],
            max_depth=root["max_depth"],
            time_budget_seconds=root["time_budget_seconds"],
        )
        for step in claims["chain"]:
            scope = scope.attenuate(
                tools=step["tools"],
                resources=step["resources"],
                intents=step["intents"],
                time_budget_seconds=step["time_budget_seconds"],
            )
        # The engine's grant must be exactly what the token claimed for this level.
        claimed = claims["chain"][-1] if claims["chain"] else root
        if (
            scope.depth != claims["depth"]
            or not same_set(scope.allowed_tools, claimed["tools"])
            or not same_set(scope.allowed_resources, claimed["resources"])
            or not same_set(scope.allowed_intents, claimed["intents"])
            or scope.time_budget_seconds != claimed["time_budget_seconds"]
            or (not claims["chain"] and scope.max_depth != root["max_depth"])
        ):
            raise ScopeTokenError("mismatch", "engine grant does not match the token's claim")
        scope._bind_expiry(claims["exp"])
        return scope

    # ── governing tools ─────────────────────────────────────────────

    def tool(
        self,
        intent: str,
        *,
        principal: Union[str, Callable[..., str], None] = None,
        resource: Union[str, Callable[..., str], None] = None,
        context: Union[dict, Callable[..., dict], None] = None,
        on_needs_approval: Optional[Callable[[dict], bool]] = None,
        on_result: Optional[Callable[[Any, dict], Any]] = None,
    ) -> Callable[[_F], _F]:
        """Decorate a function as a governed tool.

        ``principal`` / ``resource`` / ``context`` may each be a fixed value or a
        callable of the tool's ``(*args, **kwargs)`` — so per-call runtime facts
        (amount, refundable, acting user, …) flow into Cedar evaluation. On a
        ``NeedsApproval`` decision, ``on_needs_approval(decision)`` (if given) is
        called; return ``True`` to proceed after a human confirms. Fail-closed:
        DENY raises :class:`Denied`; unconfirmed approval raises
        :class:`NeedsApproval`; the body never runs in either case.

        ``on_result(result, info)`` is the egress hook: called AFTER the body
        returns and BEFORE the result is handed back, with ``info = {"intent",
        "resource", "principal", "decision_id", "obligations"}`` — the
        ``decision_id`` and the obligations (a dict, or ``None``) of the
        decision that let the body run. This is where you run ``sanitize``, a
        screen, or a second ``authorize`` against the result's classification.
        Return a value to replace the payload; return ``None`` to pass it
        through; raise to withhold it — the exception propagates and the raw
        result is never returned (fail-closed). A value-free ``egress`` audit
        record is written, joined to the decision record by ``decision_id``. If
        the body is a coroutine the hook runs once it is awaited (an awaitable
        hook return is awaited too). An async hook on a *synchronous* body is
        refused fail-closed: the payload is withheld and ``TypeError`` is raised.
        """

        def decorator(fn: _F) -> _F:
            name = fn.__name__

            @functools.wraps(fn)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                prin = _resolve(principal, args, kwargs) or self.agent
                res = _resolve(resource, args, kwargs) or f"tool/{name}"
                ctx = context(*args, **kwargs) if callable(context) else (context or {})

                def run(d: dict) -> Any:
                    # Run the body, then the egress hook (if any) over its result.
                    out = fn(*args, **kwargs)
                    if on_result is None:
                        return out
                    info = {
                        "intent": intent,
                        "resource": res,
                        "principal": prin,
                        "decision_id": d.get("decision_id"),
                        "obligations": d.get("obligations"),
                    }
                    if inspect.isawaitable(out):
                        return self._apply_on_result_async(out, on_result, info)
                    return self._apply_on_result(out, on_result, info)[0]

                d = self.authorize(action=intent, principal=prin, resource=res, context=ctx)
                if d["allowed"]:
                    return run(d)
                if d["needs_approval"]:
                    if on_needs_approval is not None and on_needs_approval(d):
                        token = self.mint_approval(action=intent, principal=prin, resource=res)
                        d2 = self.authorize(
                            action=intent, principal=prin, resource=res, context=ctx, approval=token
                        )
                        if d2["allowed"]:
                            return run(d2)
                    raise NeedsApproval(name, intent, d.get("decision_id"), d["reason"])
                raise Denied(name, intent, d["reason"] or DENY_REASON)

            return wrapper  # type: ignore[return-value]

        return decorator

    def authorize(
        self,
        *,
        action: str,
        principal: Optional[str] = None,
        resource: Optional[str] = None,
        context: Optional[dict] = None,
        approval: Optional[str] = None,
    ) -> dict:
        """Authorize an action with full control — per-call ``principal``,
        ``resource``, and Cedar ``context`` — returning a three-state verdict and
        a correlation id. ``NeedsApproval`` (matched permit annotated
        ``require_approval``) is downgraded to ``Allow`` when a valid single-use
        ``approval`` token (from :meth:`mint_approval`, after a human confirms) is
        supplied. Fail-closed and audited (value-free).

        The result is ``{"decision", "allowed", "needs_approval", "approved",
        "decision_id", "reason"}`` plus, on an ``Allow`` whose permitting
        policies declare ``@obligate_*`` annotations, ``"obligations"``:
        ``{"redact": [...], "max_items": n, "log_values": bool, "extra": {name:
        [raw, ...]}}`` (each key only when set) — constraints the caller must
        honour when acting on the Allow. Never present on ``Deny`` or
        ``NeedsApproval``. An Allow whose known obligations cannot be read raises
        :class:`AuthorizeError` instead of returning."""
        result, prin, res, decision_id = self._decide(
            action=action, principal=principal, resource=resource, context=context, approval=approval
        )
        self._audit(
            action, res, result["decision"], result["reason"],
            principal=prin, decision_id=decision_id, approved=result["approved"],
        )
        return result

    def _decide(
        self,
        *,
        action: str,
        principal: Optional[str] = None,
        resource: Optional[str] = None,
        context: Optional[dict] = None,
        approval: Optional[str] = None,
    ) -> tuple[dict, str, str, Optional[str]]:
        """The pure decision core behind :meth:`authorize`: run the engine, apply
        the approval-token downgrade, and compute the three-state verdict —
        WITHOUT writing to the audit trail. Used by :meth:`authorize` (which then
        audits) and by :meth:`test` (which must not pollute the trail)."""
        prin = principal or self.agent
        res = resource or "resource"
        raw = json.loads(
            self._engine.authorize(
                json.dumps({"principal": prin, "action": action, "resource": res, "context": context or {}})
            )
        )
        decision_id = raw.get("request_id")
        allowed = raw.get("decision") == "Allow"
        # Only an Allow can carry obligations; an unreadable known key raises
        # AuthorizeError here (fail-closed) rather than being dropped.
        obligations = _derive_obligations(raw.get("details")) if allowed else None
        needs = allowed and _needs_approval(raw.get("details"))
        approved = False
        if needs:
            if approval and _consume_approval_token(approval, prin, action, res):
                approved, needs = True, False
            else:
                allowed = False
        verdict = "Allow" if allowed else ("NeedsApproval" if needs else "Deny")
        # Non-revealing, uniform reason (never the engine's specific one).
        reason = _reason_for_verdict(verdict)
        result = {
            "decision": verdict,
            "allowed": allowed,
            "needs_approval": needs,
            "approved": approved,
            "decision_id": decision_id,
            "reason": reason,
        }
        # Obligations ride only on a final Allow: a NeedsApproval hold or a Deny
        # has nothing to honour, whatever the matched permits declared.
        if verdict == "Allow" and obligations:
            result["obligations"] = obligations
        return result, prin, res, decision_id

    def test(self, cases: Sequence[dict]) -> dict:
        """Run policy fixtures against the loaded policies and report which pass —
        a golden-test harness for CI, so a policy change is verified before it
        gates a real action. Each case is a dict with ``action`` and ``expect``
        (``"Allow"`` / ``"Deny"`` / ``"NeedsApproval"``), plus optional
        ``principal`` / ``resource`` / ``context``; set ``"approved": True`` to
        mint a valid approval token and assert the human-confirmed downgrade;
        set ``"obligations": {"redact": [...], "max_items": n, "log_values":
        bool, "extra": {...}}`` to also assert the obligations an ``Allow`` must
        carry. Does NOT write to the audit trail. A verdict mismatch is a failed
        result (inspect ``report["failed"]`` and assert on it in your test
        runner); a malformed fixture — missing ``action`` or ``expect``, or an
        ill-typed ``obligations`` — raises ``ValueError``."""
        return run_policy_tests(
            lambda **req: self._decide(**req)[0],
            lambda **ch: self.mint_approval(**ch),
            cases,
        )

    def mint_approval(
        self,
        *,
        action: str,
        principal: Optional[str] = None,
        resource: Optional[str] = None,
        ttl_ms: int = 120_000,
    ) -> str:
        """Mint a single-use approval token bound to ``(principal, action,
        resource)``, to pass to :meth:`authorize` after a human confirms a
        ``NeedsApproval``. Local HMAC, TTL-bounded (default 2 min)."""
        return _mint_approval_token(principal or self.agent, action, resource or "resource", ttl_ms)

    def sanitize(
        self,
        content: str,
        *,
        intent: str = "read",
        resource: str = "document",
        mode: str = "tag",
        types: Optional[Sequence[str]] = None,
        decision_id: Optional[str] = None,
        known: Optional[Sequence[str]] = None,
    ) -> dict:
        """Strip PII from text before an agent reads it (governed data
        minimization). Fail-closed; writes a value-free ``sanitization`` audit
        record (counts by type — never the values, including ``known`` ones).
        Extract a document to text first (never a "redacted PDF").
        Pass the ``decision_id`` returned by :meth:`authorize` to join the
        ``sanitization`` audit line to the decision that governed the read."""
        # decision_id is validated (bounded, no control chars) inside sanitize()
        # before it is echoed onto the report and written to the audit line.
        result = sanitize(content, mode=mode, types=types, decision_id=decision_id, known=known)
        self._audit_sanitize(intent, resource, result)
        return result

    def screen(
        self,
        content: str,
        *,
        intent: str = "read",
        resource: str = "content",
        mode: str = "report",
        families: Optional[Sequence[str]] = None,
        decision_id: Optional[str] = None,
    ) -> dict:
        """Screen text for prompt-injection / output-leak shapes before it
        (re-)enters the model. Fail-closed; writes a value-free ``screening``
        audit record (counts per family + ``flagged`` — never the text). Pass the
        ``decision_id`` returned by :meth:`authorize` to join the two records."""
        # decision_id is validated (bounded, no control chars) inside screen()
        # before it is echoed onto the report and written to the audit line.
        result = screen(content, mode=mode, families=families, decision_id=decision_id)
        self._audit_screen(intent, resource, result)
        return result

    # ── internals ───────────────────────────────────────────────────

    def counters(
        self,
        principal: str,
        intent: Optional[str] = None,
        resource: Optional[str] = None,
        window: Union[str, int] = "1h",
        *,
        outcome: str = "allowed",
        now: Union[None, datetime.datetime, str] = None,
        max_bytes: int = DEFAULT_COUNTERS_MAX_BYTES,
    ) -> dict:
        """Fold this governor's local audit trail into a count the caller places
        in Cedar ``context`` — the input to a quota policy such as
        ``permit(...) when { context.reads_this_hour < 100 }``.

        Counts DECISION records (never ``sanitization`` / ``egress`` /
        ``attenuation``) for exactly this ``principal`` — and, when given, this
        ``intent`` and ``resource`` — whose ``ts`` falls in ``(now - window,
        now]``. ``outcome`` selects ``"allowed"`` (default), ``"denied"`` (Deny +
        NeedsApproval holds) or ``"all"``. Reads only the local file (an
        ``audit_sink`` mirrors records elsewhere but is never read back), streams
        it, and scans at most ``max_bytes`` from its end — ``truncated`` flags a
        lower bound. Malformed lines are skipped and counted in ``skipped``,
        never echoed. A missing file is zero counts; an unreadable one raises
        :class:`AuditTrailUnreadable`. See :func:`watchlight.count_audit_records`.
        """
        return count_audit_records(
            self._audit_path,
            principal,
            intent,
            resource,
            window,
            outcome=outcome,
            now=now,
            max_bytes=max_bytes,
        )

    def _apply_on_result(self, result: Any, on_result: Callable[[Any, dict], Any], info: dict) -> tuple[Any, bool]:
        """Run an egress hook over a governed tool's result and audit the outcome
        (shared by every governed wrapper so they behave identically). ``None``
        passes the payload through; any other value replaces it. If the hook
        raises, the exception propagates and NO value is returned — the raw
        result is withheld (fail-closed) — after an ``egress`` record marks the
        payload as withheld. Value-free: never the result, nor anything derived
        from it. Internal — not part of the public API."""
        try:
            replacement = on_result(result, info)
        except BaseException:
            self._audit_egress(info, replaced=False, withheld=True)
            raise
        if inspect.isawaitable(replacement):
            # An async hook on a synchronous body: there is no loop to await it
            # on, and handing back the coroutine object as the "payload" would
            # release nothing and audit a replacement that never happened.
            # Fail closed: withhold, and say so with a fixed, payload-free message.
            close = getattr(replacement, "close", None)
            if callable(close):
                close()
            self._audit_egress(info, replaced=False, withheld=True)
            raise TypeError(
                "on_result returned an awaitable for a synchronous tool body; "
                "an async hook requires an async tool body"
            )
        replaced = replacement is not None
        self._audit_egress(info, replaced=replaced)
        return (replacement if replaced else result), replaced

    async def _apply_on_result_async(self, awaitable: Any, on_result: Callable[[Any, dict], Any], info: dict) -> Any:
        """:meth:`_apply_on_result` for a coroutine body: await the result, run
        the hook (awaiting its return if awaitable), same fail-closed semantics."""
        result = await awaitable
        try:
            replacement = on_result(result, info)
            if inspect.isawaitable(replacement):
                replacement = await replacement
        except BaseException:
            self._audit_egress(info, replaced=False, withheld=True)
            raise
        replaced = replacement is not None
        self._audit_egress(info, replaced=replaced)
        return replacement if replaced else result

    def _audit_egress(self, info: dict, *, replaced: bool, withheld: bool = False) -> None:
        self._announce()
        disposition = "withheld" if withheld else ("replaced" if replaced else "passthrough")
        print(f"watchlight: EGRESS {info['intent']:9} {info['resource']}     {disposition}")
        # Value-free: the disposition of the payload only — never the payload,
        # its size, or anything derived from it. `decision_id` joins this line to
        # the call's decision record.
        record: dict[str, Any] = {
            "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "agent": self.agent,
            "principal": info["principal"],
            "intent": info["intent"],
            "event": "egress",
            "resource": info["resource"],
            "replaced": replaced,
        }
        if info.get("decision_id"):
            record["decision_id"] = info["decision_id"]
        if withheld:
            record["withheld"] = True
        self._write_audit(record)

    def _announce(self) -> None:
        if not self._announced:
            print(f"watchlight: governing '{self.agent}' (dev mode, in-process engine)")
            self._announced = True

    def _audit(
        self,
        intent: str,
        resource: str,
        decision: str,
        reason: str,
        *,
        principal: Optional[str] = None,
        decision_id: Optional[str] = None,
        approved: bool = False,
    ) -> None:
        self._announce()
        if decision == "Allow":
            tag = "OK✓" if approved else "ALLOW"
        elif decision == "NeedsApproval":
            tag = "APPRV?"
        else:
            tag = "DENY"
        trailer = "" if decision == "Allow" else f"     {reason or DENY_REASON}"
        print(f"watchlight: {tag:6} {intent:9} {resource}{trailer}")
        # Value-free audit: argument VALUES never enter the trail — only the
        # governance decision + correlation id. Mirrors the production contract.
        record: dict[str, Any] = {
            "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "agent": self.agent,
            "principal": principal or self.agent,
            "intent": intent,
            "resource": resource,
            "decision": decision,
        }
        if decision_id:
            record["decision_id"] = decision_id
        if approved:
            record["approved"] = True
        self._write_audit(record)

    def _audit_sanitize(self, intent: str, resource: str, result: dict) -> None:
        self._announce()
        report = result["report"]
        print(
            f"watchlight: SANIT  {intent:9} {resource}"
            f"     redacted {report['total']} ({report['mode']})"
        )
        # Value-free: counts by PII type + mode only — never the PII values.
        record: dict[str, Any] = {
            "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "agent": self.agent,
            "intent": intent,
            "event": "sanitization",
            "resource": resource,
            "mode": report["mode"],
            "detector": report["detector_version"],
            "counts": report["counts"],
            "total": report["total"],
        }
        # Same key as the authorize line, so the two records join on decision_id.
        if report.get("decision_id"):
            record["decision_id"] = report["decision_id"]
        self._write_audit(record)

    def _audit_screen(self, intent: str, resource: str, result: dict) -> None:
        self._announce()
        report = result["report"]
        print(
            f"watchlight: SCREEN {intent:9} {resource}"
            f"     flagged {report['total']} ({report['mode']})"
        )
        # Value-free: counts per rule family + mode + flagged — never the text.
        record: dict[str, Any] = {
            "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "agent": self.agent,
            "intent": intent,
            "event": "screening",
            "resource": resource,
            "mode": report["mode"],
            "detector": report["detector_version"],
            "counts": report["counts"],
            "total": report["total"],
            "flagged": report["flagged"],
        }
        # Same key as the authorize line, so the two records join on decision_id.
        if report.get("decision_id"):
            record["decision_id"] = report["decision_id"]
        self._write_audit(record)

    def _write_audit(self, record: dict) -> None:
        """The single funnel for every audit record this governor produces: the
        local ``audit.jsonl`` append, then the optional ``audit_sink``
        (fire-and-forget). See :mod:`watchlight._audit`."""
        self._trail.write(record)


# A ready-to-use default governor so `from watchlight import govern` just works.
# It starts with NO policies — fail-closed by default — until you `govern.load(...)`
# a policy file or `govern.allow(...)` a policy inline.
govern = Watchlight()
