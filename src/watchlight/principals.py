"""Cedar entity references for the acting subject — built here so callers never
paste an untrusted id into one by hand.

``principal`` is a free-form string at every layer, and the id in it is usually
taken from an identity the application has already verified (the ``sub`` of a
token, say), which is an arbitrary string: it may contain a quote, a backslash
or a space.

The two sides of a Cedar entity reference are NOT written the same way:

* a REQUEST (what the SDK sends and records) carries the id verbatim —
  ``User::"a"b"`` is the id ``a"b``;
* a POLICY is Cedar source, so the same id must be escaped for the parser —
  ``permit(principal == User::"a\\"b", …)``.

So build the request side with :func:`user` / :func:`agent`, and the policy side
with :func:`for_policy` (or :func:`escape_cedar_string`). A reference built with
one matches a reference built with the other::

    principals.user("db:4412")             ->  User::"db:4412"
    principals.agent("research-agent")     ->  Agent::"research-agent"
    principals.for_policy("User", sub)     ->  User::"…" for policy text

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
from typing import Any, Callable

__all__ = [
    "MAX_NAME_BYTES",
    "NAME_TOO_LONG_MESSAGE",
    "assert_name_length",
    "escape_cedar_string",
    "entity",
    "for_policy",
    "user",
    "agent",
]

#: The longest name the SDK decides on or records, in bytes of UTF-8: a
#: principal, an action (intent), a resource, an agent name. Real names are a
#: few dozen bytes; 4 KiB leaves room for a long URL or path as a resource. The
#: bound keeps every audit record far below the line limit the counters read
#: (``MAX_COUNTERS_LINE_BYTES``, 1 MiB), so no record the SDK writes is too long
#: to be counted. A longer name is refused before anything is decided or
#: recorded. Measured in UTF-8 bytes so both language packages draw the line at
#: exactly the same place.
MAX_NAME_BYTES = 4096

#: The fixed, value-free message a name over :data:`MAX_NAME_BYTES` is refused with.
NAME_TOO_LONG_MESSAGE = f"is longer than the maximum of {MAX_NAME_BYTES} bytes"


def _utf8_length(value: str) -> int:
    # `surrogatepass` so a lone surrogate counts 3 bytes, as the TypeScript lane
    # counts it, instead of raising here.
    return len(value.encode("utf-8", "surrogatepass"))


def assert_name_length(
    value: Any, field: str, make_error: Callable[[str], BaseException] = TypeError
) -> Any:
    """Refuse a string ``value`` longer than :data:`MAX_NAME_BYTES` (UTF-8 bytes)
    and return it unchanged otherwise. A non-string passes through: the type is
    each caller's own rule. The message names the field and the bound, never the
    value."""
    # Cheap first test: a string of at most MAX_NAME_BYTES / 4 characters cannot
    # exceed the bound, whatever it holds.
    if isinstance(value, str) and len(value) * 4 > MAX_NAME_BYTES and _utf8_length(value) > MAX_NAME_BYTES:
        raise make_error(f"{field} {NAME_TOO_LONG_MESSAGE}")
    return value

_TYPE_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(::[A-Za-z_][A-Za-z0-9_]*)*$")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_ESCAPES = {"\\": "\\\\", '"': '\\"', "\n": "\\n", "\r": "\\r", "\t": "\\t"}


def escape_cedar_string(value: str) -> str:
    """Escape a Cedar string literal's contents for POLICY TEXT: the two
    characters that would end or re-open the literal, plus the control
    characters a literal cannot carry raw. Use it when an id from outside goes
    into a policy you generate."""
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
    if not isinstance(entity_type, str) or not _TYPE_NAME.match(entity_type):
        raise TypeError("entity reference: type must be a Cedar entity type name")


def entity(entity_type: str, entity_id: str) -> str:
    """A Cedar entity reference for a REQUEST — ``<Type>::"<id>"``, id verbatim,
    which is how the engine reads the principal of an authorization. An empty
    id, or one carrying control characters (which no reference can represent
    unambiguously), is refused rather than silently mangled."""
    _check_type(entity_type)
    if not isinstance(entity_id, str) or entity_id == "":
        raise TypeError("entity reference: id must be a non-empty string")
    if _CONTROL.search(entity_id):
        raise TypeError("entity reference: id must not contain control characters")
    return f'{entity_type}::"{entity_id}"'


def for_policy(entity_type: str, entity_id: str) -> str:
    """The same reference as Cedar SOURCE, for a policy you generate: the id is
    escaped so the parser reads it back exactly. ``principals.user(sub)`` in a
    request matches ``principals.for_policy("User", sub)`` in a policy."""
    _check_type(entity_type)
    if not isinstance(entity_id, str) or entity_id == "":
        raise TypeError("entity reference: id must be a non-empty string")
    return f'{entity_type}::"{escape_cedar_string(entity_id)}"'


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

    It is deliberately NOT parsed: a bare identifier is a valid, opaque principal
    (see ``docs/identity-model.md``), and only a typed ``Type::"id"`` reference
    discriminates by type.

    ``make_error`` lets a primitive raise its own typed error; the default is the
    :class:`TypeError` the identity builders raise.
    """
    if not isinstance(value, str) or not value.strip():
        raise make_error(PRINCIPAL_EMPTY_MESSAGE)
    if _CONTROL.search(value):
        raise make_error(PRINCIPAL_CONTROL_MESSAGE)
    assert_name_length(value, "principal", make_error)
    return value


def user(subject: str) -> str:
    """The person a call runs on behalf of — the subject an application takes
    from an identity it has already verified."""
    return entity("User", subject)


def agent(name: str) -> str:
    """The agent acting on its own behalf."""
    return entity("Agent", name)
