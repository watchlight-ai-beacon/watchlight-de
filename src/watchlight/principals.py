"""Cedar entity references for the acting subject — built here so callers never
paste an untrusted id into one by hand.

``principal`` is a free-form string at every layer, and the id in it is usually
taken from an identity the application has already verified (the ``sub`` of a
token, say), which is an arbitrary string: it may contain a quote, a backslash
or a space.

A request and a policy write a Cedar entity reference the same way. The engine
reads every request principal, action and resource with the same strict parser
it uses for policy text, so the id inside the quotes is a Cedar string literal
on both sides. The request parser is stricter than the policy parser: it
accepts only one spelling of each id. A quote, an apostrophe and a backslash
must be written ``\\"``, ``\\'`` and ``\\\\``, and a character that is not
printable (a control, format, separator, private-use or unassigned character,
a space other than U+0020, or a combining mark at the start) must be written
``\\u{…}``. The id ``a"b`` is written ``User::"a\\"b"`` in a request and in a
policy alike. A reference in any other spelling, such as ``User::"a"b"`` or
``User::"o'b"``, is not read as some other entity: the engine refuses the
request as invalid.

So build every reference from an outside id with :func:`user`, :func:`agent` or
:func:`entity`. They escape a quote, an apostrophe and a backslash, and they
refuse, with a fixed message, an id holding a character that would need
``\\u{…}``. :func:`for_policy` returns the
same string as :func:`entity` for every id :func:`entity` accepts, so a
reference built for a request matches the same reference written into a policy::

    principals.user("db:4412")             ->  User::"db:4412"
    principals.user('a"b')                 ->  User::"a\\"b"
    principals.user("o'brien@example.com") ->  User::"o\\'brien@example.com"
    principals.user("a\\u00a0b")            ->  TypeError (NBSP is not printable)
    principals.agent("research-agent")     ->  Agent::"research-agent"
    principals.for_policy("User", 'a"b')   ->  User::"a\\"b"

A BARE principal, one written without ``Type::"…"``, is read by the engine as a
``User``: ``team-42`` is the entity ``User::"team-42"``. It matches
``principal is User`` and a policy naming ``User::"team-42"``, and never a
policy of another type. Write the type to name anything other than a user. In
the same way a bare action is read as an ``Action`` and a bare resource as a
``Resource``. A bare name that holds a quote, or ``::``, is refused as invalid.

The vocabulary the SDK writes and the audit trail carries:

* ``User::"<subject>"`` — the person a call runs on behalf of (RFC 8693 ``sub``);
  a stable, opaque id — a primary key, an account id, a subject claim — never an
  email address or a username, both of which move and make an old audit row point
  at someone else. Namespace it (``db:``, ``sso:``) when more than one identity
  source can produce subjects
* ``Agent::"<name>"`` — the agent acting on its own behalf; what a call that
  names no subject records
* which runtime executed the call is NOT the principal: it is the reserved
  ``context.actor`` key (RFC 8693 ``act.sub``; see
  :data:`watchlight.ACTOR_CONTEXT_KEY`).
"""

from __future__ import annotations

import re
import unicodedata
from typing import Any, Callable, List, Optional

__all__ = [
    "MAX_ACTOR_CHAIN_BYTES",
    "MAX_AGENT_NAME_BYTES",
    "MAX_NAME_BYTES",
    "MAX_SCOPE_ENTRIES",
    "MAX_SCOPE_LIST_BYTES",
    "NAME_TOO_LONG_MESSAGE",
    "assert_agent_name",
    "assert_actor_chain",
    "assert_name",
    "assert_name_length",
    "assert_name_list",
    "escape_cedar_string",
    "entity_key",
    "entity",
    "for_policy",
    "user",
    "agent",
]

# ── bounds on what the SDK records ──────────────────────────────────────────
#
# Every audit record the SDK writes must stay below the line limit the counters
# read (``MAX_COUNTERS_LINE_BYTES``, 1 MiB): a line over it counts toward every
# quota (fail-closed), so a record that could exceed it would let a caller
# exhaust every quota. These bounds are what guarantee it. The worst case each
# record kind can reach is built and measured by ``tests/test_record_bounds.py``
# (and ``ts/test/counters.test.mjs`` in TypeScript): under 400,000 bytes with
# Python's escaping and under 270,000 with TypeScript's, at most about 38% of the
# limit. All bounds are measured in UTF-8 bytes, so both language packages draw
# every line in exactly the same place.

#: The longest name the SDK decides on or records: a principal, an action
#: (intent), a resource, and each entry of a scope's tool, resource and intent
#: lists. Real names are a few dozen bytes; 4 KiB leaves room for a long URL or
#: path as a resource. A longer name is refused before anything is decided or
#: recorded.
MAX_NAME_BYTES = 4096

#: The longest agent name: short enough that the principal derived from it,
#: ``Agent::"<name>"``, is itself within :data:`MAX_NAME_BYTES`. The bound applies
#: to the escaped name too (a quote or a backslash counts two bytes there).
MAX_AGENT_NAME_BYTES = MAX_NAME_BYTES - len('Agent::""')

#: The most entries a scope's ``tools``, ``resources`` or ``intents`` list may hold.
MAX_SCOPE_ENTRIES = 256

#: The most UTF-8 bytes the entries of one scope list may hold in total.
MAX_SCOPE_LIST_BYTES = 64 * 1024

#: The most UTF-8 bytes the agent names of one delegation chain may hold in
#: total. The chain is written on every record a delegated governor produces.
MAX_ACTOR_CHAIN_BYTES = 64 * 1024

#: The fixed, value-free message a name over :data:`MAX_NAME_BYTES` is refused with.
NAME_TOO_LONG_MESSAGE = f"is longer than the maximum of {MAX_NAME_BYTES} bytes"

_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")


# Every measurement below calls the `str` methods themselves, never the value's
# own: a `str` subclass can override `__len__` or `encode`, but what is
# serialised into a record is always its underlying characters.


def _utf8_length(value: str) -> int:
    # `surrogatepass` so a lone surrogate counts 3 bytes, as the TypeScript lane
    # counts it, instead of raising here.
    return len(str.encode(value, "utf-8", "surrogatepass"))


def _too_long(value: str, limit: int) -> bool:
    # Cheap first test: a string of at most limit / 4 characters cannot exceed
    # the bound, whatever it holds.
    return str.__len__(value) * 4 > limit and _utf8_length(value) > limit


def assert_name_length(
    value: Any,
    field: str,
    make_error: Callable[[str], BaseException] = TypeError,
    limit: int = MAX_NAME_BYTES,
) -> Any:
    """Refuse a string ``value`` longer than ``limit`` (default
    :data:`MAX_NAME_BYTES`) UTF-8 bytes and return it unchanged otherwise. A
    non-string passes through: the type is each caller's own rule. The message
    names the field and the bound, never the value."""
    if isinstance(value, str) and _too_long(value, limit):
        raise make_error(f"{field} is longer than the maximum of {limit} bytes")
    return value


def assert_name(
    value: Any, field: str, make_error: Callable[[str], BaseException] = TypeError
) -> str:
    """A name the SDK decides on and records — an action, a resource, a scope
    entry: a string, with no control characters, of at most
    :data:`MAX_NAME_BYTES`. Refused value-free otherwise; returned unchanged."""
    if not isinstance(value, str):
        raise make_error(f"{field} must be a string")
    if _CONTROL_RE.search(value):
        raise make_error(f"{field} must not contain control characters")
    assert_name_length(value, field, make_error)
    # A plain `str` from here on: a subclass's own methods never run again.
    return str.__str__(value)


def assert_agent_name(value: Any, where: str) -> str:
    """An agent name: a non-empty string with no control characters, of at most
    :data:`MAX_AGENT_NAME_BYTES`, whose principal ``Agent::"<name>"`` (with the
    name escaped, see :func:`entity`) is at most :data:`MAX_NAME_BYTES`. Raises
    ``TypeError`` prefixed with ``where``."""
    if not isinstance(value, str) or not str.strip(value):
        raise TypeError(f"{where}: agent must be a non-empty string")
    if _CONTROL_RE.search(value):
        raise TypeError(f"{where}: agent must not contain control characters")
    assert_name_length(value, f"{where}: agent", TypeError, MAX_AGENT_NAME_BYTES)
    value = str.__str__(value)
    # A quote or a backslash takes two bytes once escaped, so a name of at most
    # MAX_AGENT_NAME_BYTES can still make a longer principal. It is refused
    # here, at the name, rather than later when the principal is built.
    # The name becomes an entity id, so it follows the request helpers' rule.
    if _has_unprintable(value):
        raise TypeError(f"{where}: agent {_UNPRINTABLE_RULE}")
    if _too_long(escape_cedar_string(value), MAX_AGENT_NAME_BYTES):
        raise TypeError(
            f"{where}: agent is longer than the maximum of {MAX_AGENT_NAME_BYTES} "
            "bytes once escaped for its entity reference"
        )
    return value


def assert_actor_chain(chain: Any, where: str) -> None:
    """Refuse a delegation chain whose agent names hold more than
    :data:`MAX_ACTOR_CHAIN_BYTES` in total."""
    if sum(_utf8_length(name) for name in chain) > MAX_ACTOR_CHAIN_BYTES:
        raise TypeError(
            f"{where}: the delegation chain is longer than the maximum of "
            f"{MAX_ACTOR_CHAIN_BYTES} bytes"
        )


def assert_name_list(values: Any, field: str) -> Optional[List[str]]:
    """A scope's ``tools`` / ``resources`` / ``intents``: ``None`` (inherit), or
    at most :data:`MAX_SCOPE_ENTRIES` names (each checked by :func:`assert_name`)
    of at most :data:`MAX_SCOPE_LIST_BYTES` in total.

    Returns the list it checked — read from ``values`` exactly once — and the
    caller must use THAT list: iterating ``values`` again could yield something
    else (an iterable that changes between passes), or nothing (a generator
    already used up)."""
    if values is None:
        return None
    if isinstance(values, (str, bytes)) or not hasattr(values, "__iter__"):
        raise TypeError(f"{field} must be a list of strings")
    items = list(values)
    if len(items) > MAX_SCOPE_ENTRIES:
        raise TypeError(f"{field} holds more than the maximum of {MAX_SCOPE_ENTRIES} entries")
    total = 0
    for index, item in enumerate(items):
        items[index] = assert_name(item, f"{field} entry")
        total += _utf8_length(items[index])
    if total > MAX_SCOPE_LIST_BYTES:
        raise TypeError(f"{field} is longer than the maximum of {MAX_SCOPE_LIST_BYTES} bytes in total")
    return items


_TYPE_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(::[A-Za-z_][A-Za-z0-9_]*)*$")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
# The spelling the engine's strict entity parser accepts for each character
# that must be escaped. It is the canonical form and the only one it accepts:
# `\'` and not `'`, `\0` and not `\u{0}`.
_ESCAPES = {
    "\\": "\\\\",
    '"': '\\"',
    "'": "\\'",
    "\n": "\\n",
    "\r": "\\r",
    "\t": "\\t",
    "\0": "\\0",
}

# ── characters an id may not carry in a request ─────────────────────────────
#
# The engine's strict parser accepts a non-ASCII character raw only when it is
# printable; every other character must be written as `\u{…}`, and a raw one
# makes the request invalid. The request helpers do not write `\u{…}`: they
# refuse such an id with a fixed message instead. The rule, measured against
# watchlight-engine / @watchlight/engine 0.2.3 code point by code point, is:
#
# * anywhere in the id: general category Cc, Cf, Zl, Zp, Co, Cn or Cs, a Zs
#   space other than U+0020, or a default-ignorable code point outside those
#   categories (_DEFAULT_IGNORABLE_EXTRA);
# * as the first character: also a combining mark (Mn, Me) or another
#   grapheme extender (_GRAPHEME_EXTEND_EXTRA).
#
# The two tables are fixed, and the TypeScript lane (ts/src/principals.ts)
# holds the same ones. The general category comes from each runtime's own
# Unicode data, so the lanes and the engine can disagree about a code point
# assigned in a recent Unicode version. Either way it fails closed: a lane with
# older data refuses a character the engine would accept, and a character a
# lane accepts but the engine does not is refused by the engine as an invalid
# request. Nothing is ever read as a different id.
_REFUSED_CATEGORIES = frozenset({"Cc", "Cf", "Zl", "Zp", "Co", "Cn", "Cs"})
_LEADING_REFUSED_CATEGORIES = frozenset({"Mn", "Me"})
_DEFAULT_IGNORABLE_EXTRA = (
    (0x034F, 0x034F), (0x115F, 0x1160), (0x17B4, 0x17B5), (0x180B, 0x180D),
    (0x180F, 0x180F), (0x3164, 0x3164), (0xFE00, 0xFE0F), (0xFFA0, 0xFFA0),
    (0xE0100, 0xE01EF),
)
_GRAPHEME_EXTEND_EXTRA = (
    (0x09BE, 0x09BE), (0x09D7, 0x09D7), (0x0B3E, 0x0B3E), (0x0B57, 0x0B57),
    (0x0BBE, 0x0BBE), (0x0BD7, 0x0BD7), (0x0CC0, 0x0CC0), (0x0CC2, 0x0CC2),
    (0x0CC7, 0x0CC8), (0x0CCA, 0x0CCB), (0x0CD5, 0x0CD6), (0x0D3E, 0x0D3E),
    (0x0D57, 0x0D57), (0x0DCF, 0x0DCF), (0x0DDF, 0x0DDF), (0x1715, 0x1715),
    (0x1734, 0x1734), (0x1B35, 0x1B35), (0x1B3B, 0x1B3B), (0x1B3D, 0x1B3D),
    (0x1B43, 0x1B44), (0x1BAA, 0x1BAA), (0x1BF2, 0x1BF3), (0x302E, 0x302F),
    (0xA953, 0xA953), (0xA9C0, 0xA9C0), (0xFF9E, 0xFF9F), (0x111C0, 0x111C0),
    (0x11235, 0x11235), (0x1133E, 0x1133E), (0x1134D, 0x1134D), (0x11357, 0x11357),
    (0x113B8, 0x113B8), (0x113C2, 0x113C2), (0x113C5, 0x113C5), (0x113C7, 0x113C9),
    (0x113CF, 0x113CF), (0x114B0, 0x114B0), (0x114BD, 0x114BD), (0x115AF, 0x115AF),
    (0x116B6, 0x116B6), (0x11930, 0x11930), (0x1193D, 0x1193D), (0x11F41, 0x11F41),
    (0x16FF0, 0x16FF1), (0x1D165, 0x1D166), (0x1D16D, 0x1D172),
)

_UNPRINTABLE_RULE = (
    "must not contain a character the engine requires escaped as \\u{...} (a "
    "control, format, separator, private-use, surrogate or unassigned character, "
    "a space other than U+0020, a default-ignorable character, or a combining "
    "mark at the start)"
)

#: The fixed, value-free message an id with such a character is refused with.
UNPRINTABLE_ID_MESSAGE = f"entity reference: id {_UNPRINTABLE_RULE}"


def _in(ranges: Any, cp: int) -> bool:
    return any(low <= cp <= high for low, high in ranges)


def _unprintable(ch: str, first: bool) -> bool:
    category = unicodedata.category(ch)
    if category in _REFUSED_CATEGORIES:
        return True
    if category == "Zs" and ch != " ":
        return True
    cp = ord(ch)
    if _in(_DEFAULT_IGNORABLE_EXTRA, cp):
        return True
    return first and (category in _LEADING_REFUSED_CATEGORIES or _in(_GRAPHEME_EXTEND_EXTRA, cp))


def _has_unprintable(value: str) -> bool:
    """True when ``value`` holds a character the request helpers refuse (see
    above). An ASCII id holds none once control characters are excluded."""
    if str.isascii(value):
        return False
    return any(_unprintable(ch, index == 0) for index, ch in enumerate(value))


def escape_cedar_string(value: str) -> str:
    """Escape a Cedar string literal's contents: a quote, an apostrophe and a
    backslash, plus the C0 control characters and DEL, each in the one spelling
    the engine's strict request parser accepts (``\\"``, ``\\'``, ``\\\\``,
    ``\\n``, ``\\r``, ``\\t``, ``\\0``, and ``\\u{…}`` for the rest). Every
    other character is written as it is. The request helpers use it after they
    have refused the ids it cannot make valid for a request (see
    :func:`entity`); :func:`for_policy` uses it for policy text, where those
    ids are allowed."""
    out = []
    for ch in str(value):
        if ch in _ESCAPES:
            out.append(_ESCAPES[ch])
        elif _CONTROL.match(ch):
            out.append(f"\\u{{{ord(ch):x}}}")
        else:
            out.append(ch)
    return "".join(out)


def _check_type(entity_type: str) -> None:
    if not isinstance(entity_type, str) or not _TYPE_NAME.fullmatch(entity_type):
        raise TypeError("entity reference: type must be a Cedar entity type name")


#: The fixed, value-free message an entity reference over
#: :data:`MAX_NAME_BYTES` is refused with.
ENTITY_TOO_LONG_MESSAGE = (
    f"entity reference: the escaped reference is longer than the maximum of "
    f"{MAX_NAME_BYTES} bytes"
)


def _reference(entity_type: str, entity_id: str) -> str:
    # The id is read as a plain `str` once, so a subclass's own `__str__` can
    # never change what is escaped after it was checked.
    return f'{entity_type}::"{escape_cedar_string(entity_id)}"'


def entity(entity_type: str, entity_id: str) -> str:
    """A Cedar entity reference, ``<Type>::"<id>"``, for a request.

    The id is escaped exactly as :func:`for_policy` escapes it, in the one
    spelling the engine's strict request parser accepts: a quote, an
    apostrophe and a backslash become ``\\"``, ``\\'`` and ``\\\\``. Every
    other character the helper accepts is printable and is written as it is.
    For every id this function accepts, the engine accepts the returned
    reference and reads it back as exactly ``entity_id``, so a crafted id can
    never name another entity or another type.

    These ids are refused with a fixed message rather than silently changed:

    * an empty id;
    * an id with C0 control characters or DEL;
    * an id with a character the engine accepts only as ``\\u{…}``: another
      control, format, separator, private-use, surrogate or unassigned
      character, a space other than U+0020, a default-ignorable character, or a
      combining mark at the start (see :data:`UNPRINTABLE_ID_MESSAGE`);
    * an id whose escaped reference is longer than :data:`MAX_NAME_BYTES`
      bytes of UTF-8, because the reference is recorded on every audit row.
    """
    _check_type(entity_type)
    if not isinstance(entity_id, str) or entity_id == "":
        raise TypeError("entity reference: id must be a non-empty string")
    entity_id = str.__str__(entity_id)
    if _CONTROL.search(entity_id):
        raise TypeError("entity reference: id must not contain control characters")
    if _has_unprintable(entity_id):
        raise TypeError(UNPRINTABLE_ID_MESSAGE)
    reference = _reference(entity_type, entity_id)
    if _too_long(reference, MAX_NAME_BYTES):
        raise TypeError(ENTITY_TOO_LONG_MESSAGE)
    return reference


def for_policy(entity_type: str, entity_id: str) -> str:
    """The reference written into the text of a policy you generate.

    For every id :func:`entity` accepts, this returns the same string as
    :func:`entity`: requests and policies spell a reference the same way, so
    ``principals.user(sub)`` in a request matches
    ``principals.for_policy("User", sub)`` in a policy. Both names stay public.
    The difference is that policy text is not a request, and the policy
    parser accepts more than the strict request parser. A C0 control character
    or DEL is escaped here (``\\n``, ``\\0``, ``\\u{1b}``) instead of refused,
    any other character the request helpers refuse is written raw, which the
    policy parser accepts, and the length is not bounded. Such a policy matches
    only a request whose principal is written by hand in the escaped form the
    engine accepts, for example ``User::"a\\nb"``: :func:`assert_principal`
    refuses a raw control character, not an escaped one."""
    _check_type(entity_type)
    if not isinstance(entity_id, str) or entity_id == "":
        raise TypeError("entity reference: id must be a non-empty string")
    return _reference(entity_type, str.__str__(entity_id))


#: What a caller-supplied ``principal`` must satisfy at EVERY boundary that takes
#: one — the same two rules :func:`entity` already applies to an id, applied to
#: the whole reference. The message is fixed and never echoes the value.
PRINCIPAL_EMPTY_MESSAGE = "principal must be a non-empty string"
PRINCIPAL_CONTROL_MESSAGE = "principal must not contain control characters"


def assert_principal(value: Any, make_error: Callable[[str], BaseException] = TypeError) -> str:
    """Check a caller-supplied ``principal`` and return it unchanged.

    The principal is recorded verbatim and is the subject of every audit row, so
    a value that cannot be a subject is refused at the boundary rather than
    written. Three rules:

    * it must be a non-empty string — blank (or whitespace-only) is a mistake,
      never a request for the default. ``user.id or ""`` reaching a governed call
      used to be recorded as the AGENT, attributing a person's action to the
      runtime;
    * it must carry no control characters, which no reference can represent
      unambiguously;
    * it must be at most :data:`MAX_NAME_BYTES` bytes of UTF-8, so the record
      that carries it stays short enough to be read back and counted.

    It is not parsed here; the engine parses it when it decides. A typed
    reference must be well formed, with the id escaped as :func:`entity`
    escapes it, or the engine refuses the request. A bare identifier is read as
    a ``User`` (see ``docs/identity-model.md``). What was checked is what is
    recorded: the record carries the principal exactly as the caller wrote it.

    ``make_error`` lets a primitive raise its own typed error; the default is the
    :class:`TypeError` the identity builders raise.
    """
    if not isinstance(value, str) or not str.strip(value):
        raise make_error(PRINCIPAL_EMPTY_MESSAGE)
    if _CONTROL.search(value):
        raise make_error(PRINCIPAL_CONTROL_MESSAGE)
    assert_name_length(value, "principal", make_error)
    # A plain `str`: what is checked is what is recorded.
    return str.__str__(value)


def user(subject: str) -> str:
    """The person a call runs on behalf of — the subject an application takes
    from an identity it has already verified. ``User::"<subject>"``, with the
    subject escaped as :func:`entity` escapes it."""
    return entity("User", subject)


def agent(name: str) -> str:
    """The agent acting on its own behalf. ``Agent::"<name>"``, with the name
    escaped as :func:`entity` escapes it."""
    return entity("Agent", name)


# ── one entity, every spelling ──────────────────────────────────────────────
#
# The engine reads a bare name as a typed one: a bare principal is a ``User``, a
# bare action an ``Action`` and a bare resource a ``Resource``. So ``u1`` and
# ``User::"u1"`` are the same principal, and a raw no-break space in a bare name
# is the same character as ``\u{a0}`` inside a reference. The counters compare
# names by the entity they stand for, so a caller cannot widen a quota by
# switching between spellings. Records keep the name exactly as it was written.

#: The type the engine gives a bare principal, action and resource.
BARE_PRINCIPAL_TYPE = "User"
BARE_ACTION_TYPE = "Action"
BARE_RESOURCE_TYPE = "Resource"

_UNESCAPES = {"\\": "\\", '"': '"', "'": "'", "n": "\n", "r": "\r", "t": "\t", "0": "\0"}
_UNICODE_ESCAPE = re.compile(r"u\{([0-9A-Fa-f]{1,6})\}")


def _decode_id(body: str) -> Optional[str]:
    """The id inside a reference's quotes, with its escapes decoded, or ``None``
    when the text is not a string the engine could read (a raw quote, or an
    escape it does not know)."""
    if "\\" not in body:
        # The common case: nothing to decode.
        return None if '"' in body else body
    out = []
    i = 0
    while i < len(body):
        ch = body[i]
        if ch == '"':
            return None
        if ch != "\\":
            out.append(ch)
            i += 1
            continue
        nxt = body[i + 1 : i + 2]
        if nxt in _UNESCAPES and nxt:
            out.append(_UNESCAPES[nxt])
            i += 2
            continue
        m = _UNICODE_ESCAPE.match(body, i + 1)
        if not m:
            return None
        cp = int(m.group(1), 16)
        if cp > 0x10FFFF or 0xD800 <= cp <= 0xDFFF:
            return None
        out.append(chr(cp))
        i = m.end()
    return "".join(out)


def entity_key(value: str, bare_type: str) -> tuple:
    """The entity a name stands for, as ``(type, id)``, however it is spelled.

    ``User::"a\\"b"`` is ``("User", 'a"b')``. A bare name is read as the engine
    reads it, as ``bare_type``: ``entity_key("u1", "User")`` is
    ``("User", "u1")``, the same key as ``User::"u1"``. Escapes are decoded, so
    the key does not depend on the runtime's Unicode data. A name the engine
    cannot read as an entity (a bare name holding a quote or ``::``, or a
    reference with an escape the parser does not know) is its own key,
    ``("", value)``, and matches only itself.

    The counters compare names with it, and a ``counter_source`` that filters
    on ``intent`` or ``resource`` should too (bare type ``"Action"`` /
    ``"Resource"``)."""
    value = str.__str__(value)
    sep = value.find('::"')
    if sep >= 0:
        entity_type = value[:sep]
        if _TYPE_NAME.fullmatch(entity_type) and value.endswith('"') and len(value) >= sep + 4:
            entity_id = _decode_id(value[sep + 3 : -1])
            if entity_id is not None:
                return (entity_type, entity_id)
        return ("", value)
    if '"' in value or "::" in value:
        return ("", value)
    return (bare_type, value)


def _canonical_escape(entity_id: str) -> str:
    """The one spelling of ``entity_id`` the engine's strict parser accepts:
    :func:`escape_cedar_string`, plus ``\\u{…}`` for a character the engine
    accepts only escaped."""
    out = []
    for index, ch in enumerate(entity_id):
        if ch in _ESCAPES:
            out.append(_ESCAPES[ch])
        elif _CONTROL.match(ch) or (not ch.isascii() and _unprintable(ch, index == 0)):
            out.append(f"\\u{{{ord(ch):x}}}")
        else:
            out.append(ch)
    return "".join(out)


def entity_spellings(value: str, bare_type: str) -> List[str]:
    """Every spelling a record can carry for the entity ``value`` names, the
    given one first: the given text, the typed reference in the engine's
    spelling, and the bare name when the entity is a ``bare_type`` whose id can
    be written bare. A counter source is asked once for each, so a store that
    holds an older spelling still counts it. Internal."""
    value = str.__str__(value)
    entity_type, entity_id = entity_key(value, bare_type)
    out = [value]
    if not entity_type:
        return out
    typed = f'{entity_type}::"{_canonical_escape(entity_id)}"'
    if typed not in out:
        out.append(typed)
    # No blank check: a spelling nobody wrote answers 0, so asking for it
    # can never over-count, and both lanes ask the same questions.
    if (
        entity_type == bare_type
        and entity_id
        and '"' not in entity_id
        and "::" not in entity_id
        and not _CONTROL.search(entity_id)
        and entity_id not in out
    ):
        out.append(entity_id)
    return out
