"""Cedar entity-reference shaping — the ONE place that decides whether a
principal / action / resource term is already TYPED or is a BARE name, and
whether a backend wants the terms wrapped before it sees them.

Why this module exists
----------------------
``RunHandle`` used to force-wrap every term before handing it to the backend
(``Agent::"<uuid>"`` / ``Action::"<action>"`` / ``Resource::"<resource>"``) and
:class:`~watchlight_core.in_process_client.InProcessClient` stripped the wrapper
straight back off. The two halves cancelled, so every term reached the compiled
engine BARE — and a bare term is a wildcard that matches any entity type with
that name. A policy naming ``User::"u1"`` therefore allowed a principal of
``Agent::"u1"``: the entity-type distinction the identity model rests on was not
enforced on the in-process lane at all.

The fix is to stop inventing types on the caller's behalf where it matters,
WITHOUT changing what any backend receives today. ``RunHandle`` still shapes the
terms — it is the call site that has always done so — but the shape is now
chosen by the BACKEND, which declares what it wants:

* a backend that sets :data:`VERBATIM_ATTR` to ``True`` receives the caller's
  terms untouched. ``InProcessClient`` declares this: a bare name reaches the
  engine bare (unchanged behaviour) and a typed reference keeps its type and
  discriminates.
* a backend that declares NOTHING — ``ApdpClient``, ``MockApdpClient``, and any
  third-party or custom backend — receives the historical wrapping. This is the
  default precisely so that a backend nobody has updated cannot be affected.

Shaping is deliberately NOT done inside ``ApdpClient.authorize``. That is a
published public method, and rewriting a caller's principal/action/resource
inside it would change what wl-apdp evaluates for anyone calling it directly.
wl-apdp gives a BARE term one fixed type for its position (a principal is a
``User``, an action an ``Action``, a resource a ``Resource``), and takes a TYPED one at face value, so
the rewrite can flip a decision. For example, a bare principal ``u1`` is
``User::"u1"``, while the wrapped default is ``Agent::"u1"``.
"""

from __future__ import annotations

import re
from typing import Any

__all__ = ["VERBATIM_ATTR", "is_typed_entity", "shape_for_backend", "wire_entity"]

#: The attribute a backend sets to ``True`` to declare that it wants
#: ``principal`` / ``action`` / ``resource`` VERBATIM — no Cedar wrapping
#: applied on its behalf. Absent or falsy means the historical wrapping, so a
#: backend that declares nothing is unaffected.
VERBATIM_ATTR = "cedar_entities_verbatim"

# A Cedar entity UID: a `::`-separated namespace path followed by a quoted id,
# e.g. `User::"u1"`, `Agent::"…"`, `My::Namespace::Document::"d1"`. Deliberately
# strict — anything that does not match this shape is treated as a BARE name, so
# an ordinary resource string that happens to contain `::` or a quote is never
# mistaken for a typed reference.
_CEDAR_UID = re.compile(r'^[_A-Za-z][_A-Za-z0-9]*(?:::[_A-Za-z][_A-Za-z0-9]*)*::"[^"]*"$')


def is_typed_entity(term: str) -> bool:
    """True when ``term`` is already a Cedar entity reference (``Type::"id"``).

    A term that is NOT a typed entity is a bare name — the caller expressed no
    entity type, and whether one may be invented for them is the backend's call.
    """
    return bool(_CEDAR_UID.match(term))


def wire_entity(term: str, default_type: str) -> str:
    """Apply the historical Cedar wrapping to ``term``.

    An already-typed reference is passed through untouched; a bare name is
    wrapped in ``default_type`` — reproducing byte-for-byte what the SDK has
    always handed a networked backend for a bare term.
    """
    return term if is_typed_entity(term) else f'{default_type}::"{term}"'


def wants_verbatim(backend: Any) -> bool:
    """True when ``backend`` declared that it wants unshaped terms.

    Defaults to ``False`` — the historical wrapping — for any backend that
    declares nothing, including third-party and custom implementations.
    """
    return bool(getattr(backend, VERBATIM_ATTR, False))


def shape_for_backend(
    backend: Any, principal: str, action: str, resource: str
) -> tuple[str, str, str]:
    """Shape the three terms the way ``backend`` declared it wants them.

    Returns ``(principal, action, resource)`` — verbatim for a backend that set
    :data:`VERBATIM_ATTR`, Cedar-wrapped otherwise.
    """
    if wants_verbatim(backend):
        return principal, action, resource
    return (
        wire_entity(principal, "Agent"),
        wire_entity(action, "Action"),
        wire_entity(resource, "Resource"),
    )
