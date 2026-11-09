"""Zero-touch intent extraction from Google ADK's
``CallbackContext`` user content.

Google ADK delivers the user's prompt via the ``CallbackContext``
passed to ``before_agent_callback``. The canonical signal is the
``user_content`` attribute (a ``google.genai.types.Content`` value
with ``role == "user"`` and a list of ``parts`` whose ``text`` field
carries the prompt body). The extractor below walks every ADK
release shape we've encountered:

- ``ctx.user_content`` — modern ADK (2026.5+) exposes the user
  message directly on the ``CallbackContext``.
- ``ctx.invocation_context.user_content`` — the same Content object
  routed through the ``invocation_context`` wrapper on older
  releases.
- ``ctx.invocation_context.user_input`` — string-only fallback on
  ADK releases that pre-date the structured user-content surface.
- ``ctx.invocation_context.session.events`` — when neither of the
  above is set (e.g. the runner attached a session without
  surfacing the latest user turn yet), walk the session's event
  list in REVERSE and return the first user-role Content found.

Returns the truncated, UTF-8-safe prompt or ``None`` when nothing
extractable is present. The caller (``plugin.before_agent_callback``)
maps ``None`` to :attr:`IntentProvenance.ABSENT` on the emitted
``ExecutionStartedPayload``.

# Why this lives in the ADK plugin (not watchlight-core)

The walk shape is ADK-specific — the priority chain mirrors the
release-specific ``CallbackContext`` surfaces. Other plugins
(LangGraph, Pydantic AI, Claude Agent SDK, Bedrock) keep their own
framework-shaped extractors in their own ``intent`` modules. The
byte-safe UTF-8 truncation is the only piece that's shared, and
that's via the :data:`watchlight_core.INTENT_OBJECTIVE_MAX_BYTES`
constant.

# Failure modes

This module is best-effort: an attribute access that raises (bug
in an unreleased ADK build, a partially-constructed ``Content``
instance, etc.) is caught and treated as "no signal" rather than
propagated. The callback chain in ``plugin.before_agent_callback``
MUST NOT raise on intent-extraction failure.
"""

from __future__ import annotations

from typing import Any, Iterable, Optional

from watchlight_core import INTENT_OBJECTIVE_MAX_BYTES, get_logger

logger = get_logger(__name__)


__all__ = [
    "extract_intent_from_callback_context",
    "truncate_intent_objective",
]


def truncate_intent_objective(text: Optional[str]) -> Optional[str]:
    """Byte-truncate an intent-objective string to
    :data:`INTENT_OBJECTIVE_MAX_BYTES`.

    Returns ``None`` on ``None`` / empty / whitespace-only input.
    Truncation is UTF-8-safe: the slice is taken at a byte boundary
    and then re-decoded with ``errors='ignore'`` so any partial
    multi-byte codepoint at the boundary is dropped. The result is
    therefore valid UTF-8 and never larger than
    :data:`INTENT_OBJECTIVE_MAX_BYTES` bytes.

    Mirrors the ``truncate_intent_objective`` helpers in the other
    plugin lanes (Pydantic AI, LangGraph, Claude Agent SDK, Bedrock)
    so cross-plugin conformance fixtures yield byte-identical
    results.
    """
    if text is None:
        return None
    cleaned = text.strip()
    if not cleaned:
        return None
    encoded = cleaned.encode("utf-8")
    if len(encoded) <= INTENT_OBJECTIVE_MAX_BYTES:
        return cleaned
    # Slice at the byte boundary, then decode with errors='ignore' so
    # any split codepoint at the cut is dropped (yielding valid UTF-8
    # strictly shorter than the cap).
    truncated = encoded[:INTENT_OBJECTIVE_MAX_BYTES].decode(
        "utf-8", errors="ignore"
    )
    return truncated or None


def extract_intent_from_callback_context(
    callback_context: Any,
) -> Optional[str]:
    """Extract an intent objective from an ADK ``CallbackContext``.

    Walks the documented + release-historical attribute paths in
    priority order. Returns ``None`` if nothing extractable is
    present or extraction raises.

    Args:
        callback_context: The ``CallbackContext`` argument ADK
            passes to ``before_agent_callback``. Defensively
            handles ``None`` and non-Context inputs.

    Returns:
        A string ≤ :data:`INTENT_OBJECTIVE_MAX_BYTES` bytes
        (truncated at a UTF-8 codepoint boundary), or ``None`` if
        no extractable prompt is present.

    Never raises — every attribute access is wrapped so a partial
    ADK Context (early in the lifecycle, mock test harness, future
    SDK shape drift) returns ``None`` rather than crashing the
    plugin's before_agent_callback path.
    """
    try:
        return _extract_inner(callback_context)
    except Exception:  # noqa: BLE001 — extraction must never break the run
        logger.debug(
            "watchlight_adk: intent extraction raised; treating as Absent",
            exc_info=True,
        )
        return None


def _extract_inner(callback_context: Any) -> Optional[str]:
    if callback_context is None:
        return None

    # Path 1 — modern ADK (2026.5+) exposes ``user_content`` directly
    # on the CallbackContext.
    text = _text_from_content(getattr(callback_context, "user_content", None))
    if text:
        return truncate_intent_objective(text)

    # Path 2 — invocation_context wrapper (the older ADK Context
    # plumbing that some current releases still use).
    invocation_context = getattr(callback_context, "invocation_context", None)
    if invocation_context is not None:
        text = _text_from_content(getattr(invocation_context, "user_content", None))
        if text:
            return truncate_intent_objective(text)

        # Path 2b — string-only fallback on older ADK releases.
        user_input = getattr(invocation_context, "user_input", None)
        if isinstance(user_input, str) and user_input.strip():
            return truncate_intent_objective(user_input)

        # Path 3 — session.events walk. ADK runners attach a Session
        # to the invocation context; the session carries the
        # conversation event history. Walk in REVERSE and return the
        # first user-role Content we find — the most recent user
        # turn carries the operator-relevant intent; earlier turns
        # are context the model has already consumed.
        session = getattr(invocation_context, "session", None)
        if session is not None:
            events = getattr(session, "events", None)
            if isinstance(events, Iterable):
                text = _scan_events_for_latest_user_content(events)
                if text:
                    return truncate_intent_objective(text)

    return None


def _scan_events_for_latest_user_content(events: Iterable[Any]) -> Optional[str]:
    """Walk an iterable of ADK session events in REVERSE and return
    the first user-role Content's text.

    ADK ``Event`` objects expose ``.content`` (a ``Content`` value)
    and ``.author`` (the producer label — ``"user"`` for inbound
    user turns, otherwise the agent name). The author check is the
    load-bearing filter: an agent-authored event's Content can still
    carry ``role == "user"`` in some SDK paths, so we filter on
    author first and fall back to content role only when author is
    missing.
    """
    # Materialise so we can reverse — ADK's events list is typically
    # short (one execution worth of turns), but in case it's a
    # generator we exhaust it once.
    try:
        materialised = list(events)
    except Exception:  # noqa: BLE001
        return None
    for event in reversed(materialised):
        if not _is_user_authored(event):
            continue
        text = _text_from_content(getattr(event, "content", None))
        if text:
            return text
    return None


def _is_user_authored(event: Any) -> bool:
    """True iff the ADK Event was produced by the human user.

    Checks ``event.author`` first (the canonical attribution), then
    falls back to ``event.content.role == "user"`` when author is
    missing. Both forms appear across ADK releases.
    """
    author = getattr(event, "author", None)
    if isinstance(author, str) and author.lower() == "user":
        return True
    if author is not None:
        # Author is set to something non-user (an agent name) — this
        # is a model/tool turn, skip.
        return False
    # No author attribute — fall back to the Content's role.
    content = getattr(event, "content", None)
    role = getattr(content, "role", None)
    return isinstance(role, str) and role.lower() == "user"


def _text_from_content(content: Any) -> Optional[str]:
    """Extract the concatenated text from a ``Content`` value.

    ADK's ``Content`` carries ``parts: List[Part]``; each ``Part``
    may have a ``.text`` attribute (the canonical text shape) or be
    a non-text part (function call, image, etc.). We concatenate
    every text-shaped part — multi-part user messages with inline
    instructions land as a single intent objective.

    Returns ``None`` when ``content`` is missing, has the wrong
    role, or has no text-shaped parts.
    """
    if content is None:
        return None
    # Role filter — only user-role Contents are user-supplied
    # intent. Agent/model/tool roles are excluded; their text is
    # output, not intent.
    role = getattr(content, "role", None)
    if isinstance(role, str) and role.lower() not in ("user", ""):
        return None

    parts = getattr(content, "parts", None)
    if not isinstance(parts, Iterable):
        # Some ADK builds expose a string-shaped Content directly.
        if isinstance(content, str):
            return content.strip() or None
        return None

    chunks = []
    for part in parts:
        if part is None:
            continue
        # Path A — Part with a ``.text`` attribute (the genai_types
        # canonical shape).
        text_attr = getattr(part, "text", None)
        if isinstance(text_attr, str) and text_attr.strip():
            chunks.append(text_attr.strip())
            continue
        # Path B — dict-shaped Part (some SDK paths use a plain dict
        # rather than a Part instance).
        if isinstance(part, dict):
            t = part.get("text")
            if isinstance(t, str) and t.strip():
                chunks.append(t.strip())
                continue
        # Path C — raw string Part (defensive).
        if isinstance(part, str) and part.strip():
            chunks.append(part.strip())

    if not chunks:
        return None
    # Join with a single space — multi-Part user messages render as
    # a continuous prompt rather than concatenated-no-separator.
    return " ".join(chunks)
