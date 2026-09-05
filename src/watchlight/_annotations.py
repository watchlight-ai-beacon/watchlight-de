"""The Cedar policy ANNOTATIONS the SDK reads at load, and the check that a
policy cannot silently mean something other than what it says.

Why this check exists
---------------------
``@enforcement_effect("<verb>")`` changes the VERDICT. On a ``permit``,
``require_approval`` turns an Allow into a NeedsApproval that a human has to
release.

The engine maps a value it does not implement to *no effect at all*. That is
the fail-CLOSED direction for the verbs that escalate a ``forbid`` —
``terminate``, ``quarantine``, ``sever_subtree`` and ``revoke`` all take a deny
and make it stronger, so dropping one leaves a plain deny. It is the fail-OPEN
direction for the verb that holds back a ``permit``: dropping
``require_approval`` leaves a plain allow. One rule, fail-closed for one family
and fail-open for the other — and a one-character typo in the value is enough to
turn a human-in-the-loop gate into an unconditional permit, with no error and no
warning.

So the SDK refuses a policy whose effect it cannot read, at load, before the
engine ever sees it. That is deliberately unlike an unknown ``@obligate_*``,
which the engine preserves and hands to the caller as an uninterpreted extra:
an obligation the engine does not interpret still has a reader (the caller), so
passing it through is meaningful. An effect verb nothing implements has no
reader — the engine makes the decision, and it would make it wrongly.

A misspelled annotation NAME cannot be told apart from a legitimate user
annotation in general, so a near miss for ``@enforcement_effect`` warns and
nothing else does. It never raises: an arbitrary annotation is valid Cedar.

VERSION COUPLING — read this before adding a verb
-------------------------------------------------
:data:`ENFORCEMENT_EFFECTS` is the set the PINNED engine implements (the
``watchlight-engine`` range in ``pyproject.toml``). The SDK and the engine are
released together, so shipping the list here is safe, but it makes adding a verb
a TWO-PLACE change:

    1. ``src/watchlight/_annotations.py``   (this list)
    2. ``ts/src/annotations.ts``            (the identical list, TypeScript)

Both lanes must carry the same set, in the same order, or the same policy is
accepted in one language and refused in the other.
"""

from __future__ import annotations

import re
import sys
from typing import List, Optional, Tuple

#: The annotation whose value the engine turns into an enforcement effect.
ENFORCEMENT_EFFECT_ANNOTATION = "enforcement_effect"

#: Every ``@enforcement_effect`` value the pinned engine implements, sorted so
#: the error message lists them the same way every time. See the module
#: docstring: adding one here is half a change — ``ts/src/annotations.ts`` holds
#: the other half.
ENFORCEMENT_EFFECTS: Tuple[str, ...] = (
    "attenuate",
    "escalate",
    "observe",
    "quarantine",
    "require_approval",
    "revoke",
    "sever_subtree",
    "terminate",
)

#: How close a misspelled annotation name has to be to ``enforcement_effect``
#: before it is called a near miss and warned about. Two edits over an
#: 18-character name means a candidate must be 16 to 20 characters long and at
#: least ~89% identical, which covers every realistic typo — a dropped, doubled,
#: transposed or substituted character, ``-`` for ``_``, camelCase, a trailing
#: plural, the wrong case — while no ordinary annotation (``description``,
#: ``owner``, ``severity``, ``obligate_redact``) comes anywhere near it.
NEAR_MISS_MAX_EDITS = 2

_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


class PolicyError(ValueError):
    """Raised at policy load by :meth:`~watchlight.Watchlight.allow` and
    :meth:`~watchlight.Watchlight.load` when a policy carries an
    ``@enforcement_effect`` value the engine does not implement.

    It is raised *before* the policy reaches the engine, so a policy set that
    would decide differently from what it says never loads at all. Carries the
    offending ``value``, the ``policy`` name it came from, and the ``accepted``
    set.
    """

    def __init__(self, message: str, *, value: str, policy: str) -> None:
        super().__init__(message)
        self.value = value
        self.policy = policy
        self.accepted: Tuple[str, ...] = ENFORCEMENT_EFFECTS


# ── the parser ──────────────────────────────────────────────────────────────
#
# Annotations are read, never grepped. A policy BODY can contain the literal
# text `@enforcement_effect("terminate")` inside a Cedar string —
#
#     permit(principal, action, resource)
#     when { context.note == "@enforcement_effect(\"terminate\")" };
#
# — and that is a string, not an annotation. So the source is walked with a
# small scanner that knows three things: annotations are only legal at the HEAD
# of a policy (before `permit`/`forbid`), string literals are skipped over with
# their escapes, and `//` runs to end of line. Anything the scanner cannot read
# is handed to the engine unjudged rather than guessed at.


def _skip_trivia(code: str, i: int) -> int:
    """Advance past whitespace and ``//`` comments (Cedar has no block comment)."""
    n = len(code)
    while i < n:
        if code[i].isspace():
            i += 1
        elif code.startswith("//", i):
            nl = code.find("\n", i)
            i = n if nl < 0 else nl + 1
        else:
            break
    return i


def _read_string(code: str, i: int) -> Tuple[Optional[str], int]:
    """Read the Cedar string literal starting at the opening quote ``code[i]``.

    Returns ``(raw_contents, index_after_the_closing_quote)``, where the
    contents are RAW — escapes are left as written. Returns ``(None, -1)`` on an
    unterminated literal, which makes the whole policy unreadable to us and
    therefore the engine's business, not ours.
    """
    n = len(code)
    i += 1  # past the opening quote
    start = i
    while i < n:
        c = code[i]
        if c == "\\":
            i += 2  # an escaped character never ends the literal
            continue
        if c == '"':
            return code[start:i], i + 1
        i += 1
    return None, -1


def parse_policy_annotations(code: str) -> Optional[List[List[Tuple[str, Optional[str]]]]]:
    """Every annotation on every policy in ``code``, in source order.

    Returns one list of ``(name, value)`` pairs per policy — ``value`` is
    ``None`` for a valueless ``@name`` — or ``None`` when the source cannot be
    read, in which case nothing is judged and the engine reports whatever is
    actually wrong with it.
    """
    n = len(code)
    policies: List[List[Tuple[str, Optional[str]]]] = []
    current: List[Tuple[str, Optional[str]]] = []
    head = True  # annotations are only legal here, before the policy's effect
    depth = 0  # brace depth, so a `;` inside `when { … }` is not a terminator
    seen = False  # anything at all in the policy under construction?
    i = 0

    while i < n:
        i = _skip_trivia(code, i)
        if i >= n:
            break
        c = code[i]

        if head and c == "@":
            i += 1
            m = _IDENT.match(code, i)
            if not m:
                return None
            name = m.group(0)
            i = _skip_trivia(code, m.end())
            value: Optional[str] = None
            if i < n and code[i] == "(":
                i = _skip_trivia(code, i + 1)
                if i >= n or code[i] != '"':
                    return None
                value, i = _read_string(code, i)
                if value is None:
                    return None
                i = _skip_trivia(code, i)
                if i >= n or code[i] != ")":
                    return None
                i += 1
            current.append((name, value))
            seen = True
            continue

        # Past the annotation block: this is the policy itself.
        head = False
        seen = True
        if c == '"':
            _, i = _read_string(code, i)
            if i < 0:
                return None
            continue
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
        elif c == ";" and depth <= 0:
            policies.append(current)
            current = []
            head = True
            seen = False
            i += 1
            continue
        i += 1

    if current or seen:
        policies.append(current)
    return policies


# ── the checks ──────────────────────────────────────────────────────────────


def _edit_distance(a: str, b: str, limit: int) -> int:
    """Levenshtein distance between ``a`` and ``b``, saturating at ``limit + 1``."""
    if abs(len(a) - len(b)) > limit:
        return limit + 1
    previous = list(range(len(b) + 1))
    for x, ca in enumerate(a, start=1):
        current = [x]
        for y, cb in enumerate(b, start=1):
            current.append(
                min(
                    previous[y] + 1,  # delete
                    current[y - 1] + 1,  # insert
                    previous[y - 1] + (0 if ca == cb else 1),  # substitute
                )
            )
        if min(current) > limit:
            return limit + 1
        previous = current
    return previous[-1]


def is_near_miss(name: str) -> bool:
    """Whether ``name`` is a near miss for ``enforcement_effect`` — close enough
    to be a typo of it, and not it. Case is folded first, so a name that differs
    only in case is a near miss too."""
    if name == ENFORCEMENT_EFFECT_ANNOTATION:
        return False
    lowered = name.lower()
    return _edit_distance(lowered, ENFORCEMENT_EFFECT_ANNOTATION, NEAR_MISS_MAX_EDITS) <= (
        NEAR_MISS_MAX_EDITS
    )


def unrecognized_effect_message(where: str, value: str) -> str:
    """The one wording both lanes use, so the same mistake reads the same way in
    Python and in TypeScript."""
    return (
        f'{where}: @{ENFORCEMENT_EFFECT_ANNOTATION}("{value}") is not an effect this '
        f"engine implements. Accepted: {', '.join(ENFORCEMENT_EFFECTS)}. An effect the "
        "engine does not implement is dropped, and on a `permit` that turns an approval "
        "hold into an unconditional allow — so the policy is refused here rather than "
        "deciding differently from what it says."
    )


def near_miss_message(where: str, written: str) -> str:
    """The one wording both lanes use for an annotation NAME that looks like a
    typo of ``@enforcement_effect``."""
    return (
        f"watchlight: {where}: `@{written}` is not an annotation Watchlight reads, and it "
        f"is a near miss for `@{ENFORCEMENT_EFFECT_ANNOTATION}`. As written it is inert — "
        "the policy decides as if the effect were absent, so an approval gate would be a "
        "plain allow. Fix the spelling, or ignore this if the annotation is your own."
    )


def check_policy_annotations(code: str, policy_name: str, *, warn: bool = True) -> None:
    """Refuse a policy whose ``@enforcement_effect`` the engine cannot honour,
    and warn on an annotation name that looks like a typo of it.

    Silent on every correct policy, on every annotation that is not ours, and on
    a source this parser cannot read — the engine reports that.

    ``warn=False`` raises the same way and says nothing: it is the pass
    :meth:`~watchlight.Watchlight.load` makes over a whole file BEFORE adding
    any of it, so a file with one bad policy loads none of it and the near-miss
    warnings are still printed exactly once, by the load itself.
    """
    if not isinstance(code, str) or "@" not in code:
        return  # no annotation can be present; skip the walk entirely
    parsed = parse_policy_annotations(code)
    if parsed is None:
        return
    where = f'policy "{policy_name}"'
    for annotations in parsed:
        for name, value in annotations:
            if name == ENFORCEMENT_EFFECT_ANNOTATION:
                _check_effect_value(value, where, policy_name)
                continue
            if warn and is_near_miss(name):
                print(near_miss_message(where, name), file=sys.stderr)


def _check_effect_value(value: Optional[str], where: str, policy_name: str) -> None:
    written = "" if value is None else value
    if "\\" in written:
        # An escape sequence in the value: we read literals raw, so we cannot say
        # what the engine will decode this to. No verb needs an escape, so this
        # is not a shape anyone writes on purpose — judging it would risk
        # refusing a policy the engine accepts, which is worse than staying quiet.
        return
    if written in ENFORCEMENT_EFFECTS:
        return
    raise PolicyError(
        unrecognized_effect_message(where, written), value=written, policy=policy_name
    )

