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
import inspect
import json
import os
import pathlib
import re
import sys
from typing import Any, Callable, Optional, Sequence, TypeVar, Union

import watchlight_engine as _engine

from . import principals
from ._approval import (
    APPROVAL_KEY_LABEL,
    APPROVAL_MIN_SECRET_BYTES,
    APPROVAL_PAYLOAD_VERSION,
    ApprovalError,
    ApprovalStore,
    ApprovalTokens,
    resolve_approval_key,
)
from ._audit import AuditSink, AuditTrail
from ._counters import (
    DEFAULT_COUNTERS_MAX_BYTES,
    MAX_COUNTERS_LINE_BYTES,
    MAX_COUNTERS_NESTING,
    MAX_COUNTERS_WINDOW_SECONDS,
    AuditTrailUnreadable,
    MAX_COUNTER_VALUE,
    CounterSource,
    CounterSourceError,
    count_audit_records,
    count_from_source,
    count_from_source_async,
    parse_window_seconds,
)
from .attenuation import DE_MAX_DEPTH, AttenuationDenied, DevEditionCeiling, Scope
from .policytest import load_test_suite, run_policy_tests
from .scope_token import ScopeTokenError, normalize_secret, require_secret, same_set, verify_scope_token

__all__ = [
    "Watchlight",
    "configure_default",
    "principals",
    "ACTOR_CONTEXT_KEY",
    "ACTOR_CHAIN_CONTEXT_KEY",
    "MAX_ACTOR_CHAIN",
    "RESERVED_CONTEXT_MESSAGE",
    "ReservedContextError",
    "AuthorizeRequestError",
    "REQUEST_INVALID_MESSAGE",
    "AuditSink",
    "AuditTrailUnreadable",
    "ApprovalError",
    "ApprovalStore",
    "APPROVAL_KEY_LABEL",
    "APPROVAL_MIN_SECRET_BYTES",
    "APPROVAL_PAYLOAD_VERSION",
    "CounterSource",
    "CounterSourceError",
    "MAX_COUNTER_VALUE",
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
    "SCREEN_FAMILIES",
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

_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")


def _assert_agent_name(agent: Any, where: str) -> str:
    """Reject an agent name that cannot be recorded or referenced unambiguously —
    in the constructor, in :meth:`Watchlight.as_` and in
    :meth:`Watchlight.delegate` alike, so it fails at the name rather than later,
    inside the engine."""
    if not isinstance(agent, str) or not agent.strip():
        raise TypeError(f"{where}: agent must be a non-empty string")
    if _CONTROL_CHARS.search(agent):
        raise TypeError(f"{where}: agent must not contain control characters")
    return agent

#: The Cedar ``context`` key the SDK reserves for the ACTOR — the runtime that
#: made the call, as distinct from the subject it acted for. The pair follows
#: RFC 8693 (OAuth 2.0 Token Exchange), which separates the subject (``sub``,
#: here ``principal``) from the actor (``act``, here ``context.actor``)::
#:
#:     permit(principal, action == Action::"book", resource)
#:     when { context.actor == "flight-booker" };
#:
#: Every governed call carries it, so an agent acting alone
#: (``principal = Agent::"flight-booker"``) and the same agent acting for a
#: person (``principal = User::"alice"``) are one policy vocabulary and two
#: distinct lines in the trail. It is a context key rather than an entity
#: attribute because ``context.*`` with ``==``, ``is``, ``like`` and set
#: ``contains`` is the operator surface the engine resolves.
ACTOR_CONTEXT_KEY = "actor"

#: The Cedar ``context`` key the SDK reserves for the ordered ACTOR CHAIN, root
#: first — RFC 8693's nested ``act``, flattened into the shape the engine
#: resolves. A set-valued entry supports ``contains``, so a policy can ask
#: whether an agent was anywhere in the delegation::
#:
#:     permit(principal is User, action == Action::"pick_seat", resource)
#:     when { context.actor_chain.contains("flight-booker") };
#:
#: ``context.actor`` answers a different question — *which* agent made this call
#: — and remains the leaf, so policies written against it are unaffected. Both
#: keys are set on every authorization; the chain of a call made outside any
#: delegation is the single-element ``[agent]``.
ACTOR_CHAIN_CONTEXT_KEY = "actor_chain"

#: The longest an actor chain can be: the root agent plus one entry per
#: attenuation level, bounded by the Developer-Edition depth ceiling.
MAX_ACTOR_CHAIN = DE_MAX_DEPTH + 1

#: Fixed, value-free message of :class:`AuthorizeRequestError`.
REQUEST_INVALID_MESSAGE = (
    "the authorization request is not valid for the engine (check the principal "
    "and resource entity types)"
)


class AuthorizeRequestError(RuntimeError):
    """Raised when the engine cannot evaluate the request at all — most often an
    entity type it does not recognise, e.g. ``Service::"x"`` as a principal. The
    call is refused (fail-closed, the tool body never runs) and the refusal is
    audited as a ``Deny`` like any other. The engine's own message is never
    echoed: it is not a caller-facing reason."""

    def __init__(self) -> None:
        super().__init__(REQUEST_INVALID_MESSAGE)


#: Fixed, value-free message of :class:`ReservedContextError`.
RESERVED_CONTEXT_MESSAGE = (
    "context keys 'actor' and 'actor_chain' are reserved for the acting agent "
    "and are set by the SDK"
)


class ReservedContextError(ValueError):
    """Raised when a caller's ``context`` sets a reserved actor key to a value
    that differs from the governor's own — the acting agent, or the delegation
    chain of the scope the call was made through. Refused rather than
    overwritten, so a policy reading either key can trust it. An identical value
    is fine."""

    def __init__(self) -> None:
        super().__init__(RESERVED_CONTEXT_MESSAGE)


def _with_actor_context(context: Optional[dict], actor: str, chain: Sequence[str]) -> dict:
    """The caller's context with the reserved actor keys stamped on it."""
    out = dict(context or {})
    # The SDK's values always win — and a caller who disagreed is told, never
    # silently overruled. The chain is derived from the scope the call was made
    # through, so a caller can neither supply nor extend one.
    if ACTOR_CONTEXT_KEY in out and out[ACTOR_CONTEXT_KEY] != actor:
        raise ReservedContextError()
    if ACTOR_CHAIN_CONTEXT_KEY in out and list(out[ACTOR_CHAIN_CONTEXT_KEY] or []) != list(chain):
        raise ReservedContextError()
    out[ACTOR_CONTEXT_KEY] = actor
    out[ACTOR_CHAIN_CONTEXT_KEY] = list(chain)
    return out


class _GovernorState:
    """Everything a governor owns that is NOT its name: the engine and its
    compiled policies, the audit trail (file + sink), the scope-token secret,
    and the counters. A view made by :meth:`Watchlight.as_` shares this object
    by reference, so it is provably the same engine, the same policies, the same
    trail, the same approval store and the same counter source — only the name
    stamped on records and decisions differs."""

    __slots__ = (
        "engine",
        "trail",
        "audit_path",
        "token_secret",
        "approval",
        "counter_source",
        "policy_count",
        "announced",
        "sources",
        "strict_principal",
        "audit_options",
        "is_default",
        "wrote_record",
        "warned_default_sink",
    )

    def __init__(self) -> None:
        self.engine: Any = None
        self.trail: Optional[AuditTrail] = None
        self.audit_path: Optional[pathlib.Path] = None
        self.token_secret: Optional[bytes] = None
        #: The approval signing key + seen-token store. On the SHARED state, so
        #: an approval minted through one view is consumed — and, once consumed,
        #: refused — through every other view of the same governor. A view with
        #: its own store would let one token be spent once per name.
        self.approval: Any = None
        #: The read side of the trail, shared for the same reason:
        #: ``counters()`` must answer the same number whichever name asks.
        self.counter_source: Optional[CounterSource] = None
        self.policy_count = 0
        self.announced = False
        #: Resolved sources already loaded — the key of ``load()``'s idempotence.
        self.sources: set[str] = set()
        self.strict_principal = True
        #: The audit options in force, so ``_configure`` can apply one of them
        #: without dropping the others.
        self.audit_options: dict[str, Any] = {}
        self.is_default = False
        self.wrote_record = False
        self.warned_default_sink = False


#: One process-wide notice that the bare agent name is standing in for a missing
#: subject — the transitional ``strict_principal=False`` behaviour.
_warned_lenient_principal = False


def _warn_lenient_principal() -> None:
    global _warned_lenient_principal
    if _warned_lenient_principal:
        return
    _warned_lenient_principal = True
    print(
        "watchlight: strict_principal is off, so the BARE agent name is recorded as the "
        'acting principal of calls that name none, instead of the typed Agent::"<name>". '
        "The bare name binds to an unpredictable one of the entity types your policies "
        "name it with, and the same policy set can decide differently in different "
        "processes. This is transitional and is removed in a later version: name the "
        "subject at the "
        "call site with `principal` (see `principals.user`), and write agent-scoped "
        'policies against Agent::"<name>" or the reserved `context.actor` key.',
        file=sys.stderr,
    )


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
# Minting, verification, the signing key and the seen-token store all live in
# ``watchlight._approval`` — including the per-process defaults and what they do
# NOT cover (a second process, a second replica). Enterprise mints these
# KMS-signed and records them in signed lineage.


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


def _validate_opaque_id(
    value: Any, *, field: str = "decision_id", error: type = SanitizeError
) -> Optional[str]:
    """Fail-closed check of a caller-supplied opaque id — a ``decision_id``, a
    ``principal`` — before it reaches the audit line. Accepts ``None`` (the field
    is simply absent); rejects anything that is not a short,
    control-character-free ``str`` by raising ``error`` (the calling primitive's
    own exception type) with a fixed message that never echoes the value. The id
    is never parsed. Shared by ``sanitize`` and ``screen``, so both primitives
    apply exactly the same bounds to both fields."""
    if value is None:
        return None
    if not isinstance(value, str) or not 1 <= len(value) <= DECISION_ID_MAX_LENGTH:
        raise error(f"{field} must be a string of 1-{DECISION_ID_MAX_LENGTH} characters")
    if _DECISION_ID_CONTROL_CHARS.search(value):
        raise error(f"{field} must not contain control characters")
    return value


def _validate_decision_id(decision_id: Any, *, error: type = SanitizeError) -> Optional[str]:
    """:func:`_validate_opaque_id` for the ``decision_id`` field."""
    return _validate_opaque_id(decision_id, field="decision_id", error=error)


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
    principal: Optional[str] = None,
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
    principal = _validate_opaque_id(principal, field="principal")
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
        if principal is not None:
            report["principal"] = principal
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
    principal: Optional[str] = None,
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
    principal = _validate_opaque_id(principal, field="principal", error=ScreenError)
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
        if principal is not None:
            report["principal"] = principal
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
        approval_secret: Union[str, bytes, None] = None,
        approval_store: Optional[ApprovalStore] = None,
        counter_source: Optional[CounterSource] = None,
        audit_file: bool = True,
        strict_principal: bool = True,
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
            no built-in default. Never logged or written.
        :param approval_secret: shared secret (>= 16 bytes) that approval tokens
            are signed under, so a token minted in one process verifies in
            another and survives a redeploy inside its TTL. Defaults to
            ``$WATCHLIGHT_APPROVAL_SECRET``, then to ``token_secret`` — one
            secret configures both, because the approval key is
            ``HMAC-SHA256(secret, "watchlight-de:approval-token:v1")`` and never
            the secret itself. With nothing configured a RANDOM PER-PROCESS key
            is used: tokens then never cross a process boundary, and a restart
            invalidates every outstanding approval. A token presented to a
            governor holding a different key is refused exactly like an expired
            one — the decision stays ``NeedsApproval`` with the uniform
            ``approval required`` reason. Never logged or written. Shared with
            every view made by :meth:`as_`.
        :param approval_store: where consumed approval-token ids are reserved,
            which is what makes an approval single-use. Defaults to an
            IN-PROCESS dict shared by every governor in this process and by
            nothing else — atomic within the process (of N consumes of one token
            exactly one is approved) but behind two replicas the same token can
            be consumed once on each. Supply a shared store
            (:class:`~watchlight._approval.ApprovalStore`) and single-use holds
            across every replica. Its ``add(id, expires_at)`` MUST be an atomic
            check-and-set returning ``True`` when the reservation was new and
            ``False`` when the id was already present — a read followed by an
            unconditional write cannot enforce single use. Fail-closed:
            ``False``, a raise, or a non-boolean return all refuse the approval;
            none of them admits one. Shared with every view made by
            :meth:`as_`, so a token minted through one name and consumed through
            another is refused as a replay rather than admitted twice.
        :param counter_source: read side of ``audit_sink``: where
            :meth:`counters` gets its number. Defaults to folding the local
            ``audit.jsonl``. Configure it and ``counters`` folds your durable
            store instead — the same store the sink writes to — so a quota spans
            every replica and survives a redeploy, and ``audit_file=False``
            stops being an obstacle to counting. A source that raises, or
            returns anything but a non-negative ``int``, fails the read closed
            (:class:`CounterSourceError`); it never falls back to the local file.
            An async source is read with :meth:`counters_async`. Shared with
            every view made by :meth:`as_`.
        :param audit_file: write the local ``audit.jsonl`` at all (default
            ``True``). ``False`` makes ``audit_sink`` the SOLE destination: no
            ``.watchlight`` directory and no file are created, and
            :meth:`counters` — which reads the local file — raises. With the
            file off and no sink, records have nowhere to go and the SDK says so
            once. Every governor pointed at the same directory — concurrent
            instances in one process included — appends to the same file, so
            those records interleave and are told apart only by their fields.
        :param strict_principal: how a call that names no ``principal`` is
            recorded (default ``True``): the agent is the subject and is
            recorded as a TYPED entity reference, ``Agent::"<name>"`` (build one
            with :mod:`watchlight.principals`). ``False`` restores the previous
            behaviour, where the BARE agent name — untyped, and
            indistinguishable on sight from a user id — stood in for the missing
            subject; that is transitional, warns once per process, and is
            removed in a later version. See "Breaking in 0.8.0" in the identity
            model: https://github.com/watchlight-ai-beacon/watchlight-de/blob/main/docs/identity-model.md"""
        state = _GovernorState()
        self._shared = state
        # An explicitly passed name is validated as given — an empty one is a
        # mistake, not a request for the default.
        if agent is not None:
            _assert_agent_name(agent, "Watchlight(agent=…)")
        self.agent = _assert_agent_name(
            agent or os.environ.get("WATCHLIGHT_AGENT") or "my-agent", "Watchlight(agent=…)"
        )
        #: The delegation chain this governor acts under, root first; the last
        #: entry is :attr:`agent`. A governor that was not delegated to acts
        #: alone, so its chain is just its own name. Set by :meth:`delegate`
        #: from the scope the sub-agent was spawned under — never by a caller.
        self.actor_chain: tuple[str, ...] = (self.agent,)
        #: The scope a delegated governor acts under (``None`` otherwise).
        self.delegated_scope: Optional[Scope] = None
        state.engine = _engine.PolicyEngine()
        state.audit_options = {"dir": audit_dir, "file": audit_file, "sink": audit_sink}
        state.audit_path = (pathlib.Path(audit_dir) / "audit.jsonl") if audit_file else None
        state.trail = AuditTrail(state.audit_path, audit_sink)
        state.strict_principal = bool(strict_principal)
        state.token_secret = normalize_secret(
            token_secret if token_secret is not None else os.environ.get("WATCHLIGHT_TOKEN_SECRET")
        )
        state.approval = ApprovalTokens(
            resolve_approval_key(
                approval_secret, state.token_secret, os.environ.get("WATCHLIGHT_APPROVAL_SECRET")
            ),
            approval_store,
        )
        state.counter_source = counter_source

    # The state below is reached through properties so that a view from
    # :meth:`as_` and the governor it came from read and write ONE copy of it.

    @property
    def _engine(self) -> Any:
        return self._shared.engine

    @_engine.setter
    def _engine(self, engine: Any) -> None:
        self._shared.engine = engine

    @property
    def _trail(self) -> AuditTrail:
        return self._shared.trail

    @property
    def _audit_path(self) -> Optional[pathlib.Path]:
        return self._shared.audit_path

    @property
    def _token_secret(self) -> Optional[bytes]:
        return self._shared.token_secret

    @property
    def _approval(self) -> ApprovalTokens:
        return self._shared.approval

    @property
    def _counter_source(self) -> Optional[CounterSource]:
        return self._shared.counter_source

    @property
    def _announced(self) -> bool:
        return self._shared.announced

    @_announced.setter
    def _announced(self, value: bool) -> None:
        self._shared.announced = value

    @property
    def _policy_count(self) -> int:
        return self._shared.policy_count

    @_policy_count.setter
    def _policy_count(self, value: int) -> None:
        self._shared.policy_count = value

    def as_(self, agent: str) -> "Watchlight":
        """A view of THIS governor acting under a different agent name.

        The view shares the engine, the compiled policies, the audit trail, the
        sink, the scope-token secret and the policy count by reference — nothing
        is reloaded, no second engine is constructed, and a policy added through
        either one is immediately visible to both. Only the name stamped on
        audit records and passed to the engine differs, so any number of names
        costs one engine and one policy load::

            billing = govern.as_("billing-agent")
            research = govern.as_("research-agent")   # same engine

        (``as`` is a Python keyword, hence the trailing underscore; the
        TypeScript SDK spells it ``govern.as("name")``.)
        """
        _assert_agent_name(agent, "as_(agent)")
        # A delegate's name is what the delegation granted. Renaming it —
        # directly, or through a per-call ``agent`` override, which lands here —
        # would drop the actor chain from the context and the record, so it is
        # refused rather than silently losing the delegation.
        if len(self.actor_chain) > 1:
            raise TypeError(
                "as_(agent): a delegated governor cannot be renamed — its name is part "
                "of the actor chain. Use delegate(parent, agent) to spawn a sub-agent "
                "under it."
            )
        view = object.__new__(Watchlight)
        view.agent = agent
        # A rename is not a delegation: the view acts alone under its own name.
        view.actor_chain = (agent,)
        view.delegated_scope = None
        # Shared BY REFERENCE — the whole point of the view.
        view._shared = self._shared
        return view

    def delegate(
        self,
        parent: Union[Scope, "Watchlight"],
        agent: str,
        *,
        tools: Sequence[str] | None = None,
        resources: Sequence[str] | None = None,
        intents: Sequence[str] | None = None,
        time_budget_seconds: int | None = None,
    ) -> "Watchlight":
        """Spawn a governor for a SUB-AGENT under ``parent``, and record the
        delegation.

        The sub-agent's authority is ``parent`` narrowed by the dimensions you
        pass — the engine's strict-subset attenuation, so it can never hold what
        its parent lacks — and its identity is the parent's
        :attr:`actor_chain` with ``agent`` appended. Every decision and every
        record it produces then carries the ordered chain (root first) alongside
        the leaf actor, and a policy can ask either question:
        ``context.actor == "seat-picker"`` (who made this call) or
        ``context.actor_chain.contains("flight-booker")`` (whose delegation is
        this)::

            root = govern.scope(tools=["search", "book"])
            picker = govern.delegate(root, "seat-picker", tools=["search"])
            picker.authorize(action="pick_seat", principal=principals.user("alice"))
            govern.delegate(picker, "row-checker")      # one level deeper

        ``parent`` is a :class:`~watchlight.attenuation.Scope` or a governor that
        was itself delegated. The engine, the compiled policies, the audit trail
        and the sink are shared with this governor, exactly as for :meth:`as_`.
        Raises :class:`AttenuationDenied` if the request widens the scope and
        :class:`DevEditionCeiling` past the depth ceiling — which also bounds the
        chain at :data:`MAX_ACTOR_CHAIN` entries.
        """
        _assert_agent_name(agent, "delegate(parent, agent)")
        scope = parent.delegated_scope if isinstance(parent, Watchlight) else parent
        if scope is None:
            raise TypeError(
                "delegate(parent, agent): `parent` must be a scope, or a governor that "
                "was itself delegated"
            )
        child = scope.attenuate(
            tools=tools,
            resources=resources,
            intents=intents,
            time_budget_seconds=time_budget_seconds,
            agent=agent,
        )
        view = object.__new__(Watchlight)
        view.agent = agent
        view.actor_chain = tuple(child.actor_chain)
        view.delegated_scope = child
        view._shared = self._shared
        return view

    @property
    def policy_count(self) -> int:
        """How many policies this governor holds — the count shared with every
        view from :meth:`as_`. Counts what was added, not what the engine
        merged."""
        return self._shared.policy_count

    @property
    def has_policies(self) -> bool:
        """Whether any policy is loaded. ``False`` means every call is denied
        (fail-closed), which is a configuration mistake worth asserting on at
        start-up."""
        return self._shared.policy_count > 0

    def _principal(self, explicit: Optional[str] = None) -> str:
        """The subject of a call that named none: a TYPED reference to this
        agent, ``Agent::"<name>"`` — when no human is on whose behalf the call
        runs, the agent is the subject, and typing it says so on sight and in a
        policy. Transitionally, ``strict_principal=False`` restores the bare,
        untyped agent name (warned once per process)."""
        if explicit:
            return explicit
        if self._shared.strict_principal:
            return principals.agent(self.agent)
        _warn_lenient_principal()
        return self.agent

    # ── policy loading ──────────────────────────────────────────────

    def allow(self, cedar_code: str, name: str | None = None) -> "Watchlight":
        """Add one Cedar policy inline. Returns self for chaining. Always
        additive: calling it twice with the same code adds it twice (use
        :meth:`load` for a set you may load more than once)."""
        self._engine.add_policy(
            json.dumps({"name": name or f"policy-{self._policy_count}", "code": cedar_code})
        )
        self._policy_count += 1
        return self

    def load(
        self,
        path: str | os.PathLike[str],
        *,
        source_id: str | None = None,
        force: bool = False,
    ) -> "Watchlight":
        """Load policies from a JSON file — a list of ``{"name", "code"}`` objects
        (or ``{"policies": [...]}``). Fail-closed: a missing file loads nothing,
        so every governed call is denied until a policy permits it.

        IDEMPOTENT PER SOURCE: the source is remembered under its real path
        (symlinks resolved), or under ``source_id`` when you give one, and
        loading the same source again is a no-op — priming an engine in a
        factory and loading the same file again from an initialiser cannot
        double the set. A file that does not exist is not remembered, so it
        loads once it appears. Two different paths to the same file are one
        source; two files with the same content are two, unless you give them a
        shared ``source_id``. The memo is shared with every view from
        :meth:`as_`.

        The memo is keyed on identity, not content: EDITING a file already
        loaded and calling ``load`` again is a no-op, and the new policies do
        not apply. Pass ``force=True`` to load it again — policies are only ever
        added, so the previous copy stays and ``policy_count`` grows; construct
        a fresh governor when you need the old set gone."""
        p = pathlib.Path(path)
        key = source_id if source_id is not None else str(p.resolve())
        if key in self._shared.sources and not force:
            return self
        if not p.exists():
            return self
        data = json.loads(p.read_text())
        entries = data if isinstance(data, list) else data.get("policies", [])
        for entry in entries:
            self.allow(entry["code"], entry.get("name"))
        self._shared.sources.add(key)
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
        agent: Optional[str] = None,
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
        "resource", "principal", "decision_id"}`` plus ``"obligations"`` when
        the decision that let the body run carries any (the key is absent
        otherwise — read it with ``info.get("obligations")``). This is where
        you run ``sanitize``, a
        screen, or a second ``authorize`` against the result's classification.
        Return a value to replace the payload; return ``None`` to pass it
        through; raise to withhold it — the exception propagates and the raw
        result is never returned (fail-closed). A value-free ``egress`` audit
        record is written, joined to the decision record by ``decision_id``. If
        the body is a coroutine the hook runs once it is awaited (an awaitable
        hook return is awaited too). An async hook on a *synchronous* body is
        refused fail-closed: the payload is withheld and ``TypeError`` is raised.
        """

        # A per-tool `agent` is exactly a view of this governor (same engine,
        # same policies, same trail) with a different name on it.
        gov = self.as_(agent) if agent else self

        def decorator(fn: _F) -> _F:
            name = fn.__name__

            @functools.wraps(fn)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                prin = gov._principal(_resolve(principal, args, kwargs))
                res = _resolve(resource, args, kwargs) or f"tool/{name}"
                ctx = context(*args, **kwargs) if callable(context) else (context or {})

                def run(d: dict) -> Any:
                    # Run the body, then the egress hook (if any) over its result.
                    out = fn(*args, **kwargs)
                    if on_result is None:
                        return out
                    info = {"intent": intent, "resource": res, "principal": prin, "decision_id": d.get("decision_id")}
                    if d.get("obligations"):
                        info["obligations"] = d["obligations"]  # only when the Allow carries any
                    if inspect.isawaitable(out):
                        return gov._apply_on_result_async(out, on_result, info)
                    return gov._apply_on_result(out, on_result, info)[0]

                d = gov.authorize(action=intent, principal=prin, resource=res, context=ctx)
                if d["allowed"]:
                    return run(d)
                if d["needs_approval"]:
                    if on_needs_approval is not None and on_needs_approval(d):
                        token = gov.mint_approval(action=intent, principal=prin, resource=res)
                        d2 = gov.authorize(
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
        agent: Optional[str] = None,
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
        :class:`AuthorizeError` instead of returning.

        ``agent`` names the acting agent for this one call, overriding the
        governor's — the same view :meth:`as_` returns, applied to a single
        decision. It is what the record carries and what the policy reads as
        ``context.actor``."""
        if agent and agent != self.agent:
            return self.as_(agent).authorize(
                action=action,
                principal=principal,
                resource=resource,
                context=context,
                approval=approval,
            )
        try:
            result, prin, res, decision_id = self._decide(
                action=action, principal=principal, resource=resource, context=context,
                approval=approval,
            )
        except (ReservedContextError, AuthorizeError):
            # The caller's own context, refused before anything reached the
            # engine — raised as-is.
            raise
        except Exception:
            # A request the engine cannot evaluate is a refusal like any other:
            # it is recorded, then raised typed.
            self._audit(
                action, resource or "resource", "Deny", DENY_REASON, principal=principal
            )
            raise AuthorizeRequestError() from None
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
        prin = self._principal(principal)
        res = resource or "resource"
        # The acting agent is the ACTOR, and its delegation chain the ACTOR
        # CHAIN — reserved context keys the SDK owns, so a policy can name the
        # runtime (`context.actor == "…"`) or its delegation
        # (`context.actor_chain.contains("…")`) independently of the subject it
        # acts for. A caller value that disagrees with either is refused.
        ctx = _with_actor_context(context, self.agent, self.actor_chain)
        raw = json.loads(
            self._engine.authorize(
                json.dumps({"principal": prin, "action": action, "resource": res, "context": ctx})
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
            if approval and self._approval.consume(approval, prin, action, res):
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
        ``NeedsApproval``. Local HMAC, TTL-bounded (default 2 min).

        SCOPE OF THE DEFAULTS — both are per-process, and neither is upgraded
        silently:

        * **The signing key.** With no ``approval_secret`` (or ``token_secret``)
          the key is random and per-process: a token minted here is refused by
          any other process, and a redeploy invalidates every outstanding
          approval — indistinguishably from a genuine hold, since the reason is
          uniform. Configure ``approval_secret`` to mint in one process and
          consume in another.
        * **Single use.** "Used once" is recorded in the ``approval_store``,
          which defaults to a dict in THIS process. Behind two replicas the same
          token can therefore be consumed once on EACH — single-use is
          per-replica, not per token, and that degrades silently under a routine
          scaling change. Configure ``approval_store`` with a store every replica
          shares and single-use holds across all of them.

        Both live on the state a view made by :meth:`as_` shares, so a token
        minted through one name and consumed through another is the SAME token:
        the second use is refused as a replay, not admitted twice.
        """
        return self._approval.mint(
            self._principal(principal), action, resource or "resource", ttl_ms
        )

    def sanitize(
        self,
        content: str,
        *,
        intent: str = "read",
        resource: str = "document",
        mode: str = "tag",
        types: Optional[Sequence[str]] = None,
        decision_id: Optional[str] = None,
        principal: Optional[str] = None,
        known: Optional[Sequence[str]] = None,
        agent: Optional[str] = None,
    ) -> dict:
        """Strip PII from text before an agent reads it (governed data
        minimization). Fail-closed; writes a value-free ``sanitization`` audit
        record (counts by type — never the values, including ``known`` ones).
        Extract a document to text first (never a "redacted PDF").
        Pass the ``decision_id`` returned by :meth:`authorize` to join the
        ``sanitization`` audit line to the decision that governed the read.

        ``principal`` names WHO the text was sanitized for and is written to the
        record under the same key the decision line uses, so "what was redacted,
        for whom" is answerable from that record alone — including when the
        sanitization runs BEFORE any decision exists to join to. Omit it and the
        agent is the subject, recorded as ``Agent::"<name>"`` exactly as a
        decision with no named principal is. It is an identifier the caller
        supplies; never anything derived from the content."""
        if agent and agent != self.agent:
            return self.as_(agent).sanitize(
                content,
                intent=intent,
                resource=resource,
                mode=mode,
                types=types,
                decision_id=decision_id,
                principal=principal,
                known=known,
            )
        # The subject the redaction was performed FOR. A call that names none has
        # this agent as its subject — recorded as the TYPED Agent::"<name>", the
        # same reference the decision line carries, never a bare name.
        # decision_id and principal are validated (bounded, no control chars)
        # inside sanitize() before they are echoed onto the report and written to
        # the audit line.
        result = sanitize(
            content,
            mode=mode,
            types=types,
            decision_id=decision_id,
            principal=self._principal(principal),
            known=known,
        )
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
        principal: Optional[str] = None,
        agent: Optional[str] = None,
    ) -> dict:
        """Screen text for prompt-injection / output-leak shapes before it
        (re-)enters the model. Fail-closed; writes a value-free ``screening``
        audit record (counts per family + ``flagged`` — never the text). Pass the
        ``decision_id`` returned by :meth:`authorize` to join the two records, and
        ``principal`` to name whom the text was screened for (the agent, typed,
        when the call names no subject — as on :meth:`sanitize`)."""
        if agent and agent != self.agent:
            return self.as_(agent).screen(
                content,
                intent=intent,
                resource=resource,
                mode=mode,
                families=families,
                decision_id=decision_id,
                principal=principal,
            )
        # As in sanitize(): the subject the screening was performed for, typed
        # when the call names none. decision_id and principal are validated
        # (bounded, no control chars) inside screen().
        result = screen(
            content,
            mode=mode,
            families=families,
            decision_id=decision_id,
            principal=self._principal(principal),
        )
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
        :class:`AuditTrailUnreadable`. Counters are folded from the LOCAL file;
        with ``audit_file=False`` there is nothing to fold and this raises,
        rather than reading as zero and silently widening a quota. See
        :func:`watchlight.count_audit_records`.

        With a ``counter_source`` configured this folds THAT store instead of the
        local file — same query, same filters, same window — and
        ``result["source"]`` says which; ``audit_file=False`` then stops being an
        obstacle, since the number no longer comes from the file. A source that
        raises or returns a non-count raises :class:`CounterSourceError`; an
        asynchronous source raises too, naming :meth:`counters_async`, rather
        than quietly handing back a local number. The source lives on the shared
        state, so every view made by :meth:`as_` counts from the same place.
        """
        if self._counter_source is not None:
            return count_from_source(
                self._counter_source,
                principal=principal,
                intent=intent,
                resource=resource,
                window=window,
                outcome=outcome,
                now=now,
                max_bytes=max_bytes,
            )
        return count_audit_records(
            self._local_audit_path(),
            principal,
            intent,
            resource,
            window,
            outcome=outcome,
            now=now,
            max_bytes=max_bytes,
        )

    async def counters_async(
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
        """:meth:`counters` for an asynchronous ``counter_source`` — the only way
        to read one that returns an awaitable. Identical in every other respect,
        and identical to :meth:`counters` when no source is configured (the local
        file is read synchronously either way), so a caller can use it
        unconditionally. Await it BEFORE the call whose ``context`` it feeds; a
        ``context`` binding itself is synchronous."""
        if self._counter_source is not None:
            return await count_from_source_async(
                self._counter_source,
                principal=principal,
                intent=intent,
                resource=resource,
                window=window,
                outcome=outcome,
                now=now,
                max_bytes=max_bytes,
            )
        return count_audit_records(
            self._local_audit_path(),
            principal,
            intent,
            resource,
            window,
            outcome=outcome,
            now=now,
            max_bytes=max_bytes,
        )

    def _local_audit_path(self) -> pathlib.Path:
        """The local file counters fold when no ``counter_source`` is configured.
        A quota that cannot be counted must not read as zero — that would
        silently widen it — so ``audit_file=False`` fails closed here, unless a
        source answers instead, which is exactly the pairing that option calls
        for: the sink holds the records and the source counts them."""
        if self._audit_path is None:
            raise RuntimeError(
                "counters() reads the local audit file, which is disabled by "
                "audit_file=False; configure a counter_source to count your own "
                "sink's records instead"
            )
        return self._audit_path

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
            **self._chain_field(),
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

    def _chain_field(self) -> dict:
        """``actor_chain`` for a record, and nothing at all when this governor is
        not a delegate — a call outside any delegation keeps the record shape it
        has always had, and its chain is the single-element ``[agent]``
        anyway."""
        return {"actor_chain": list(self.actor_chain)} if len(self.actor_chain) > 1 else {}

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
            **self._chain_field(),
            # Never the agent standing in for an unnamed subject: `_principal`
            # has already resolved it (to the typed Agent::"<name>" by default).
            "principal": self._principal(principal),
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
            **self._chain_field(),
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
        # Same key, and the same typed vocabulary, as the authorize line: the
        # record names its subject even with no decision to join to.
        if report.get("principal"):
            record["principal"] = report["principal"]
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
            **self._chain_field(),
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
        # Same key, and the same typed vocabulary, as the authorize line: the
        # record names its subject even with no decision to join to.
        if report.get("principal"):
            record["principal"] = report["principal"]
        self._write_audit(record)

    def _write_audit(self, record: dict) -> None:
        """The single funnel for every audit record this governor produces: the
        local ``audit.jsonl`` append, then the optional ``audit_sink``
        (fire-and-forget). See :mod:`watchlight._audit`."""
        state = self._shared
        if not state.wrote_record:
            state.wrote_record = True
            # The module-level default governor is pre-constructed, so nothing
            # has had a chance to give it a durable destination. Say it once,
            # the first time it writes — a trail that exists only in the working
            # directory is a configuration choice, not an accident.
            if state.is_default and not self._trail.has_sink and not state.warned_default_sink:
                state.warned_default_sink = True
                print(
                    "watchlight: the default governor writes only to the local audit file — "
                    "no audit_sink is configured. Call configure_default(audit_sink=...) "
                    "before the first governed call to send records to a durable destination.",
                    file=sys.stderr,
                )
        self._trail.write(record)

    def _configure(
        self,
        *,
        agent: Optional[str] = None,
        audit_dir: Union[str, "os.PathLike[str]", None] = None,
        audit_sink: Optional[AuditSink] = None,
        audit_file: Optional[bool] = None,
        token_secret: Union[str, bytes, None] = None,
        strict_principal: Optional[bool] = None,
    ) -> None:
        """Apply options to a governor that has not written an audit record yet.
        Behind :func:`configure_default`; not part of the public surface."""
        state = self._shared
        if state.wrote_record:
            raise RuntimeError(
                "configure_default must run before the default governor writes its first "
                "audit record — the records already written would not reach the new "
                "destination"
            )
        if agent is not None:
            self.agent = _assert_agent_name(agent, "configure_default(agent=…)")
            self.actor_chain = (self.agent,)
        if audit_dir is not None or audit_sink is not None or audit_file is not None:
            # MERGE: a later call that names only one audit option must not drop
            # the sink (or the directory) an earlier one configured.
            audit = state.audit_options
            if audit_dir is not None:
                audit["dir"] = audit_dir
            if audit_file is not None:
                audit["file"] = audit_file
            if audit_sink is not None:
                audit["sink"] = audit_sink
            keep_file = audit.get("file", True) is not False
            directory = pathlib.Path(audit.get("dir") or ".watchlight")
            state.audit_path = (directory / "audit.jsonl") if keep_file else None
            state.trail = AuditTrail(state.audit_path, audit.get("sink"))
        if token_secret is not None:
            state.token_secret = normalize_secret(token_secret)
        if strict_principal is not None:
            state.strict_principal = bool(strict_principal)


# A ready-to-use default governor so `from watchlight import govern` just works.
# It starts with NO policies — fail-closed by default — until you `govern.load(...)`
# a policy file or `govern.allow(...)` a policy inline, and with no audit sink
# until `configure_default(...)` gives it one.
govern = Watchlight()
# Marked so the first record it writes can point out that it has no sink.
govern._shared.is_default = True


def configure_default(
    *,
    agent: Optional[str] = None,
    audit_dir: Union[str, "os.PathLike[str]", None] = None,
    audit_sink: Optional[AuditSink] = None,
    audit_file: Optional[bool] = None,
    token_secret: Union[str, bytes, None] = None,
    strict_principal: Optional[bool] = None,
) -> "Watchlight":
    """Configure the module-level :data:`govern` — the one governor an
    application never constructs, and therefore the one that could not otherwise
    be given an ``audit_sink``, an ``audit_dir``, a ``token_secret`` or a name::

        from watchlight import govern, configure_default

        configure_default(agent="billing-agent", audit_sink=ship)

    Call it once, before the first governed call. It raises ``RuntimeError`` if
    the default governor has already written an audit record: records written
    before the sink existed cannot be sent to it, and a trail split across two
    destinations reads like a data bug. Only the options you pass are applied,
    and they MERGE with any earlier call's — configuring ``audit_dir`` after an
    ``audit_sink`` keeps the sink. Policies already added survive."""
    govern._configure(
        agent=agent,
        audit_dir=audit_dir,
        audit_sink=audit_sink,
        audit_file=audit_file,
        token_secret=token_secret,
        strict_principal=strict_principal,
    )
    return govern
