"""Intent extraction helpers for the Microsoft Agent Framework (MSAF)
translator.

# Status

The MSAF Watchlight package today is **translator-only**: it ships
:func:`watchlight_msaf.traces.translate_msaf_event` and consumes
synthetic capture dicts produced by an *optional, not-yet-shipped*
middleware shim (see the :mod:`watchlight_msaf` package docstring for
the current scope and what is deferred). Until that middleware shim
lands, MSAF has **no live framework signal** to extract from — the
prompt body lives inside the MSAF agent process and never reaches the
Watchlight package boundary.

This module exists so that, when the middleware shim ships, it has
a single, tested, byte-safe extraction surface to call. The shim
will pass an MSAF ``ChatAgent`` invocation's message list to
:func:`extract_intent_from_messages` and forward the result on the
``workflow_run_start`` / ``agent_step_start`` capture. The
translator (:func:`watchlight_msaf.traces._on_run_start`) then
stamps the canonical ``intent_objective`` +
:class:`IntentProvenance` fields on the ``execution_started``
payload.

The shape mirrors the intent extractors in the LangGraph and Claude
Agent plugins — message-list walks in REVERSE for the latest user
turn, byte-safe UTF-8 truncation, declared > plugin_derived > absent
precedence.

# Why this lives in the MSAF plugin (not watchlight_core)

The walk shape is MSAF-specific — MSAF ``ChatAgent`` exposes
messages as a list of ``ChatMessage`` instances with ``role``
("user" / "assistant" / "system" / "tool") and ``contents``
(a list of content parts). The walk consults the MSAF-flavoured
shape, not LangGraph's or Pydantic AI's. Byte-safe UTF-8
truncation is shared via :data:`watchlight_core.INTENT_OBJECTIVE_MAX_BYTES`.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping, Optional

from watchlight_core import INTENT_OBJECTIVE_MAX_BYTES, get_logger

logger = get_logger(__name__)


__all__ = [
    "extract_intent_from_messages",
    "truncate_intent_objective",
]


def truncate_intent_objective(text: Optional[str]) -> Optional[str]:
    """Byte-truncate an intent-objective string to
    :data:`INTENT_OBJECTIVE_MAX_BYTES`.

    Returns ``None`` on ``None`` / empty / whitespace-only input.
    Truncation is UTF-8-safe: any partial multi-byte codepoint at
    the boundary is dropped via ``errors='ignore'``. Mirrors the
    sibling helpers in the ADK / LangGraph / Claude Agent / Bedrock
    plugins.
    """
    if text is None:
        return None
    cleaned = text.strip()
    if not cleaned:
        return None
    encoded = cleaned.encode("utf-8")
    if len(encoded) <= INTENT_OBJECTIVE_MAX_BYTES:
        return cleaned
    truncated = encoded[:INTENT_OBJECTIVE_MAX_BYTES].decode(
        "utf-8", errors="ignore"
    )
    return truncated or None


def extract_intent_from_messages(messages: Any) -> Optional[str]:
    """Extract the latest user-authored message's text from an MSAF
    ``ChatAgent`` message list.

    Args:
        messages: An iterable of MSAF ``ChatMessage`` objects (or
            equivalents — dataclasses with ``role`` + ``contents``,
            or dicts with the same keys). Defensively handles ``None``
            and non-iterable inputs.

    Returns:
        The truncated, UTF-8-safe text of the latest user-role
        message, or ``None`` when nothing extractable is present.

    Walks in REVERSE so the most-recent user utterance wins — earlier
    user turns are context the model has already consumed. Returns
    ``None`` when no user-role message is found (e.g. a list with
    only system + assistant turns).

    Never raises — shape drift in MSAF's released types is treated
    as "no signal" rather than propagated.
    """
    if messages is None:
        return None
    try:
        materialised = list(messages)
    except TypeError:
        return None
    except Exception:  # noqa: BLE001
        logger.debug(
            "watchlight_msaf: messages iteration raised; treating as Absent",
            exc_info=True,
        )
        return None

    for msg in reversed(materialised):
        if not _is_user_authored(msg):
            continue
        text = _text_of_message(msg)
        if text:
            return truncate_intent_objective(text)
    return None


def _is_user_authored(msg: Any) -> bool:
    """True iff the MSAF message has ``role == "user"``.

    Handles both the dataclass form (``msg.role``) and the dict
    form (``msg["role"]``) that the middleware shim may produce
    when round-tripping through JSON.
    """
    role = None
    if isinstance(msg, Mapping):
        role = msg.get("role")
    else:
        role = getattr(msg, "role", None)
    # MSAF's ``Role`` enum stringifies as its name (``Role.USER`` →
    # "Role.USER"). Tolerate both the enum-string + a plain lowercase
    # "user" by lowercasing + matching the trailing identifier.
    if isinstance(role, str):
        return role.lower().endswith("user")
    # Enum value with a ``.name`` attribute.
    name = getattr(role, "name", None)
    if isinstance(name, str) and name.lower() == "user":
        return True
    value = getattr(role, "value", None)
    return isinstance(value, str) and value.lower() == "user"


def _text_of_message(msg: Any) -> Optional[str]:
    """Extract the concatenated text from an MSAF ``ChatMessage``.

    MSAF messages carry a ``contents: List[Content]`` list (or
    ``text: str`` in older builds). Each content part may be a
    ``TextContent`` (with ``.text``) or another kind (function
    call, image, etc.); the non-text kinds are skipped.

    Returns ``None`` if no text-shaped content is present.
    """
    # Dict-shape (round-tripped JSON): use ``content``/``text`` keys.
    if isinstance(msg, Mapping):
        text = msg.get("text")
        if isinstance(text, str) and text.strip():
            return text
        content = msg.get("content")
        if isinstance(content, str) and content.strip():
            return content
        contents = msg.get("contents")
        if isinstance(contents, Iterable):
            return _join_text_parts(contents)
        return None

    # Attribute-shape: ``msg.text`` or ``msg.contents``.
    text = getattr(msg, "text", None)
    if isinstance(text, str) and text.strip():
        return text
    contents = getattr(msg, "contents", None)
    if contents is None:
        # Some MSAF release variants expose ``content`` (singular).
        contents = getattr(msg, "content", None)
        if isinstance(contents, str) and contents.strip():
            return contents
    if isinstance(contents, Iterable):
        return _join_text_parts(contents)
    return None


def _join_text_parts(parts: Iterable[Any]) -> Optional[str]:
    """Concatenate text from a list of MSAF content parts."""
    chunks = []
    try:
        for part in parts:
            if part is None:
                continue
            # Attribute-shape (``TextContent.text``).
            t = getattr(part, "text", None)
            if isinstance(t, str) and t.strip():
                chunks.append(t.strip())
                continue
            # Dict-shape.
            if isinstance(part, Mapping):
                t = part.get("text")
                if isinstance(t, str) and t.strip():
                    chunks.append(t.strip())
                    continue
            # Raw-string-shape (defensive).
            if isinstance(part, str) and part.strip():
                chunks.append(part.strip())
    except Exception:  # noqa: BLE001
        return None
    if not chunks:
        return None
    return " ".join(chunks)
