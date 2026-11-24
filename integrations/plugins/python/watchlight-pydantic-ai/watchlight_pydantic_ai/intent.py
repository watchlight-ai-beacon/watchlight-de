"""Extract ``intent_objective`` from Pydantic AI ``Agent.run`` args.

The instrumentation layer in :mod:`.instrumentation` already monkey-patches
``Agent.run`` / ``run_sync`` / ``run_stream`` / ``iter`` to open a governed
``RunHandle`` for every (top-level OR nested) invocation. This module extends
that wrapper with a step BEFORE the handle is opened: pluck the prompt
string out of the ``Agent.run`` call's positional arg, normalise it,
truncate to the byte-cap mirrored from :data:`INTENT_OBJECTIVE_MAX_BYTES`,
and forward as the ``intent_objective`` kwarg.

The extraction is deliberately conservative — failures fall through to
``IntentProvenance.ABSENT`` rather than raising. The customer's agent
code must keep running even if the plugin can't infer an intent (e.g.
the prompt arg is a model object pydantic-ai doesn't document, or the
caller invokes ``Agent.run()`` with no positional arg from a programmatic
test harness).

Extraction algorithm:

1. **String case** — ``Agent.run("audit Q3 invoices")``. ``args[0]`` is
   the prompt verbatim. Return it normalised + byte-truncated.

2. **List-of-messages case** — ``Agent.run([SystemMessage(...),
   UserMessage("first turn"), AssistantMessage(...), UserMessage(
   "second turn")])`` — pydantic-ai's continuation-of-conversation idiom.
   We walk the list in REVERSE and return the FIRST user-role message
   we find. The reverse walk is load-bearing for multi-turn conversations
   — the most-recent user turn carries the operator-relevant intent;
   earlier turns are context the model has already consumed.

3. **Keyword-only case** — ``Agent.run(prompt="hello")``. Pydantic AI's
   public signature only documents the positional arg, but a robust
   plugin checks ``kwargs["prompt"]`` and ``kwargs["user_prompt"]`` as
   a fallback. Returns ``None`` if neither key is set.

4. **Anything else** — return ``None``. The instrumentation maps
   ``None`` to ``IntentProvenance.ABSENT``.

Truncation uses :data:`INTENT_OBJECTIVE_MAX_BYTES` (256, byte-counted)
mirrored from ``wl-lineage::events::INTENT_OBJECTIVE_MAX_BYTES``. UTF-8
boundaries are respected via the ``decode("utf-8", errors="ignore")``
pattern — a partial multi-byte at the cap is silently dropped rather
than raising or corrupting the event envelope.
"""

from __future__ import annotations

import re
from typing import Any, Optional, Sequence

from watchlight_core import get_logger
from watchlight_core.events_schema import INTENT_OBJECTIVE_MAX_BYTES

logger = get_logger("watchlight_pydantic_ai.intent")

__all__ = [
    "extract_intent_from_pydantic_args",
]


# Collapse runs of whitespace (incl. newlines, tabs) into a single space.
# Operator-legibility — multi-line prompts otherwise render as
# ``"line 1\\nline 2"`` in the dashboard's intent column.
_WHITESPACE_RUN = re.compile(r"\s+")


def extract_intent_from_pydantic_args(
    args: Sequence[Any],
    kwargs: dict,
) -> Optional[str]:
    """Extract a normalised, byte-truncated intent objective.

    See the module docstring for the full algorithm. Returns ``None``
    when no usable intent could be derived; the caller should map
    ``None`` to ``IntentProvenance.ABSENT`` on the emitted event.

    This function MUST NOT raise on any input shape — extraction is
    advisory, not control-plane. Pydantic AI's public ``Agent.run``
    signature is stable but the internal wrapping layers might change;
    the plugin's contract is "best-effort extract, fail-safe to
    Absent".
    """
    try:
        return _extract_inner(args, kwargs)
    except Exception:  # noqa: BLE001 — extraction must never break the run
        logger.debug(
            "watchlight_pydantic_ai: intent extraction raised; treating "
            "as Absent",
            exc_info=True,
        )
        return None


def _extract_inner(
    args: Sequence[Any],
    kwargs: dict,
) -> Optional[str]:
    # Path 1 — positional first arg is the prompt.
    if args:
        raw = args[0]
        # 1a — plain string prompt (the canonical case).
        if isinstance(raw, str):
            return _normalize_and_truncate(raw)
        # 1b — list-of-messages (continuation idiom). Walk backward
        # to find the most-recent user-role message.
        if isinstance(raw, (list, tuple)):
            text = _extract_last_user_text(raw)
            if text is not None:
                return _normalize_and_truncate(text)
            return None
        # 1c — any other shape (e.g. a pydantic-ai-specific dataclass
        # we don't recognise). Fall through to keyword args, then
        # ultimately Absent.

    # Path 2 — keyword-only invocation. Pydantic AI's documented
    # parameter name is ``user_prompt`` (the function signature
    # exposes ``run(user_prompt, ...)`` even though customers usually
    # pass positionally). Check both ``prompt`` and ``user_prompt``
    # for forward compatibility with older releases that used the
    # shorter spelling.
    for key in ("user_prompt", "prompt"):
        candidate = kwargs.get(key)
        if isinstance(candidate, str):
            return _normalize_and_truncate(candidate)
        if isinstance(candidate, (list, tuple)):
            text = _extract_last_user_text(candidate)
            if text is not None:
                return _normalize_and_truncate(text)

    return None


def _extract_last_user_text(messages: Sequence[Any]) -> Optional[str]:
    """Walk ``messages`` in reverse and return the first user-role
    message's text content.

    Pydantic AI's message types are dataclasses with ``role`` +
    ``content`` attributes in some releases, plain dicts with the
    same shape in others (continuation calls round-tripped through
    JSON). We try both shapes.

    Returns ``None`` if no user-role message is found (e.g. the
    list contains only system + assistant turns).
    """
    for msg in reversed(messages):
        role = _msg_role(msg)
        if role != "user":
            continue
        text = _msg_text(msg)
        if isinstance(text, str) and text.strip():
            return text
    return None


def _msg_role(msg: Any) -> Optional[str]:
    """Read a ``role`` field off either a dataclass or dict message."""
    if isinstance(msg, dict):
        role = msg.get("role")
        return role if isinstance(role, str) else None
    role = getattr(msg, "role", None)
    if isinstance(role, str):
        return role
    # Pydantic AI's ``UserPromptPart`` / ``ModelRequest`` shapes don't
    # always expose a ``role`` attribute on the outer object — the
    # role is encoded in the type name. As a defensive fallback,
    # treat any class whose name contains "User" as a user turn.
    cls_name = type(msg).__name__
    if "User" in cls_name:
        return "user"
    if "System" in cls_name:
        return "system"
    if "Assistant" in cls_name or "Model" in cls_name:
        return "assistant"
    return None


def _msg_text(msg: Any) -> Optional[str]:
    """Read a ``content`` / ``text`` field off either a dataclass or
    dict message. Pydantic AI uses ``content`` in its dict form and
    ``content`` or ``parts[*].content`` on the dataclass form.
    """
    if isinstance(msg, dict):
        content = msg.get("content")
        if isinstance(content, str):
            return content
        if isinstance(content, list):
            # OpenAI-style ``[{type: 'text', text: '...'}]`` shape.
            for part in content:
                if isinstance(part, dict):
                    text = part.get("text") or part.get("content")
                    if isinstance(text, str):
                        return text
        return None
    content = getattr(msg, "content", None)
    if isinstance(content, str):
        return content
    # Pydantic AI ``UserPromptPart(content="...")`` exposes
    # ``content`` directly. Some releases wrap the prompt in
    # ``parts=[UserPromptPart(content=...)]``.
    parts = getattr(msg, "parts", None)
    if isinstance(parts, (list, tuple)):
        for part in parts:
            part_content = getattr(part, "content", None)
            if isinstance(part_content, str):
                return part_content
    return None


def _normalize_and_truncate(s: str) -> Optional[str]:
    """Strip + collapse whitespace, byte-truncate to
    :data:`INTENT_OBJECTIVE_MAX_BYTES`, drop a partial multi-byte at
    the boundary.

    Returns ``None`` when normalisation produces the empty string —
    an empty intent is treated as ABSENT, not as ``Some("")``.
    """
    if not isinstance(s, str):
        return None
    collapsed = _WHITESPACE_RUN.sub(" ", s).strip()
    if not collapsed:
        return None
    encoded = collapsed.encode("utf-8")
    if len(encoded) <= INTENT_OBJECTIVE_MAX_BYTES:
        return collapsed
    # Truncate to the byte cap. ``decode("utf-8", errors="ignore")``
    # silently drops any partial multi-byte sequence at the boundary,
    # so the returned string is always valid UTF-8 and never longer
    # than the cap when re-encoded.
    truncated_bytes = encoded[:INTENT_OBJECTIVE_MAX_BYTES]
    truncated = truncated_bytes.decode("utf-8", errors="ignore")
    # Re-strip in case the truncate left trailing whitespace.
    truncated = truncated.rstrip()
    return truncated or None
