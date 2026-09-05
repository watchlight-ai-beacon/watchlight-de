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

    principals.user("alice@example.com")   ->  User::"alice@example.com"
    principals.agent("research-agent")     ->  Agent::"research-agent"
    principals.for_policy("User", sub)     ->  User::"…" for policy text

The vocabulary the SDK writes and the audit trail carries:

* ``User::"<subject>"`` — the person a call runs on behalf of (RFC 8693 ``sub``)
* ``Agent::"<name>"`` — the agent acting on its own behalf; what a call that
  names no subject records
* which runtime executed the call is NOT the principal: it is the reserved
  ``context.actor`` key (RFC 8693 ``act.sub``; see
  :data:`watchlight.ACTOR_CONTEXT_KEY`).
"""

from __future__ import annotations

import re

__all__ = ["escape_cedar_string", "entity", "for_policy", "user", "agent"]

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


def user(subject: str) -> str:
    """The person a call runs on behalf of — the subject an application takes
    from an identity it has already verified."""
    return entity("User", subject)


def agent(name: str) -> str:
    """The agent acting on its own behalf."""
    return entity("Agent", name)
