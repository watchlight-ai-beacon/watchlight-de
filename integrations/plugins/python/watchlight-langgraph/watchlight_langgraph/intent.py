"""Zero-touch intent extraction from LangGraph's
``on_chain_start.inputs`` payload.

The LangChain / LangGraph callback ``on_chain_start`` delivers the
graph's input dict to every registered handler. For the
overwhelmingly common single-prompt + chat-style topologies that
shape is well-known:

- ``{"input": "user prompt string"}`` — single-prompt graphs (the
  vanilla LangGraph quickstart). Top key produced by
  ``StateGraph(...).invoke({"input": "..."})``.
- ``{"messages": [HumanMessage(content="..."), ...]}`` — chat-style
  graphs (LangGraph's ``MessageGraph`` + every LangChain
  message-list convention). Pulls the LAST human message's content
  since the LATEST utterance is what the agent is acting on.
- ``{"question": "..."}`` / ``{"query": "..."}`` — domain-specific
  keys commonly used by retrieval-augmented Q&A graphs.

The extractor walks these keys in priority order, then falls back
to the first string-valued value in the dict (sorted by key for
determinism). Returns ``None`` if nothing extractable.

# Why this lives in the LangGraph plugin (not watchlight-core)

The extraction shape is LangGraph-specific — the priority keys
(``"input"``, ``"messages"``, ``"question"``, ``"query"``) are
chosen for LangGraph's idioms. Other plugins (Pydantic AI,
Claude Agent SDK, Bedrock) have their own framework-specific
entry points and live in their own ``intent`` modules.

Byte-safe UTF-8 truncation is shared across plugins; the
:data:`watchlight_core.INTENT_OBJECTIVE_MAX_BYTES` constant is the
single source of truth and matches the cap the Watchlight backend
enforces on the intent-objective field.

# Failure modes

This module is best-effort: malformed inputs (the
LangChain SDK ships a shape we don't expect, an attacker-controlled
dict tries to pad the extraction, etc.) return ``None``. The caller
(``_capture_chain_start``) treats ``None`` as
:attr:`IntentProvenance.ABSENT` on the resulting
``ExecutionStartedPayload``. Never raises.
"""

from __future__ import annotations

from typing import Any, List, Mapping, Optional

from watchlight_core import INTENT_OBJECTIVE_MAX_BYTES, get_logger

logger = get_logger(__name__)


# Priority-ordered keys we consult on the inputs dict. The order
# matches the documented LangGraph conventions: ``"input"`` for
# single-prompt graphs first, then chat-style, then domain-specific.
# If none match, the fallback (§ ``_first_string_value``) handles
# arbitrary single-string dicts deterministically.
_PRIORITY_KEYS = ("input", "messages", "question", "query", "prompt")


def extract_intent_from_langgraph_inputs(inputs: Any) -> Optional[str]:
    """Extract an intent objective from a LangGraph
    ``on_chain_start.inputs`` payload.

    Args:
        inputs: The ``inputs`` argument LangChain passes to
            ``on_chain_start``. Documented as a dict but defensively
            handles non-dict inputs (return ``None`` rather than
            raising — the callback path MUST NOT raise).

    Returns:
        A string ≤ :data:`watchlight_core.INTENT_OBJECTIVE_MAX_BYTES`
        bytes (truncated at a UTF-8 codepoint boundary), or ``None``
        if no extractable prompt is present.

    Truncation semantics:
        Byte-counted (not char-counted) — multi-byte UTF-8 input
        cannot slip past the cap. When truncation would split a
        multi-byte codepoint, the cut happens at the prior
        boundary so the resulting string remains valid UTF-8.
    """
    if not isinstance(inputs, Mapping):
        return None

    # Priority pass — try the well-known LangGraph + LangChain keys
    # first. Each helper extracts a single string or returns None.
    for key in _PRIORITY_KEYS:
        if key not in inputs:
            continue
        value = inputs[key]
        candidate = _coerce_value_to_prompt(value)
        if candidate:
            return _truncate_utf8(candidate, INTENT_OBJECTIVE_MAX_BYTES)

    # Deterministic fallback — first string-valued key in sorted
    # order. Sorting keeps the behaviour reproducible across Python
    # versions and dict-ordering quirks (Python 3.7+ preserves
    # insertion order, but for testability we prefer alphabetical
    # determinism when no priority key matched).
    for key in sorted(inputs.keys(), key=_safe_key_sort):
        if key in _PRIORITY_KEYS:
            continue  # already tried above
        value = inputs[key]
        if isinstance(value, str) and value:
            return _truncate_utf8(value, INTENT_OBJECTIVE_MAX_BYTES)

    return None


def _coerce_value_to_prompt(value: Any) -> Optional[str]:
    """Coerce a known-key value into a prompt string.

    Two shapes get special handling:

    - ``str`` — used as-is.
    - ``list`` of LangChain-style Message objects (``HumanMessage``,
      raw dicts with ``role``/``content``, etc.) — the LATEST
      human-authored content is extracted. Falling back to the last
      message of any kind if no human message is present, since the
      most recent utterance is what the agent is acting on now.

    Everything else returns ``None``. We deliberately do NOT
    ``str(value)`` arbitrary objects because that would let opaque
    payloads (dicts, lists of non-message junk) be captured as
    pseudo-intent and pollute the audit log.
    """
    if isinstance(value, str):
        return value or None
    if isinstance(value, list):
        return _extract_from_message_list(value)
    return None


def _extract_from_message_list(messages: List[Any]) -> Optional[str]:
    """Pull the latest human-authored content from a LangChain-style
    message list.

    Each entry can be:

    - A LangChain ``BaseMessage`` (has ``.type == "human"`` and
      ``.content``).
    - A raw dict ``{"role": "user", "content": "..."}`` (OpenAI-
      style — also used by some LangGraph nodes).
    - Something else — skipped.

    Walks the list in REVERSE order so the latest human message
    wins (consistent with how LLM chat APIs interpret message
    history: the last user turn is the active request). If no
    human message is found, falls back to the last message of any
    type so the agent's most recent input is still captured —
    operator-legibility beats strict filtering here.
    """
    last_any: Optional[str] = None
    for entry in reversed(messages):
        content = _content_of_message(entry)
        if content is None:
            continue
        if _is_human_message(entry):
            return content
        if last_any is None:
            last_any = content
    return last_any


def _is_human_message(entry: Any) -> bool:
    """True iff the entry is a human/user-authored message.

    Recognises:
    - LangChain ``HumanMessage`` (``.type == "human"``).
    - OpenAI-style dict (``{"role": "user", ...}``).
    """
    msg_type = getattr(entry, "type", None)
    if isinstance(msg_type, str) and msg_type.lower() == "human":
        return True
    if isinstance(entry, Mapping):
        role = entry.get("role")
        if isinstance(role, str) and role.lower() in ("user", "human"):
            return True
    return False


def _content_of_message(entry: Any) -> Optional[str]:
    """Extract the textual content from a message entry, regardless
    of whether it's a LangChain Message object or a dict.

    LangChain's ``BaseMessage.content`` can be a list of content
    blocks (e.g. multimodal); in that case we pick the first
    text-shaped block. Anything that doesn't render to a non-empty
    string returns ``None``.
    """
    # Attribute access path — LangChain BaseMessage instances.
    content = getattr(entry, "content", None)
    if content is None and isinstance(entry, Mapping):
        content = entry.get("content")
    if isinstance(content, str):
        return content or None
    if isinstance(content, list):
        # Multimodal — pick the first text block.
        for block in content:
            if isinstance(block, str) and block:
                return block
            if isinstance(block, Mapping):
                text = block.get("text")
                if isinstance(text, str) and text:
                    return text
    return None


def _safe_key_sort(key: Any) -> str:
    """Sort key for the fallback pass that tolerates non-string
    dict keys (PEP-3119: dict keys can be any hashable). Coerce to
    a string so the comparator is total."""
    return str(key)


def _truncate_utf8(value: str, max_bytes: int) -> str:
    """Byte-safe UTF-8 truncation: return a prefix of ``value``
    encoding to at most ``max_bytes`` UTF-8 bytes.

    If the natural cut would split a multi-byte codepoint, back up
    to the nearest codepoint boundary so the result is always
    valid UTF-8.

    Returns the input unchanged when it already fits.
    """
    encoded = value.encode("utf-8")
    if len(encoded) <= max_bytes:
        return value
    # Back up to a codepoint boundary. UTF-8 continuation bytes are
    # 10xxxxxx (i.e. byte & 0xC0 == 0x80); the boundary is the byte
    # immediately before the first non-continuation byte.
    cut = max_bytes
    while cut > 0 and (encoded[cut] & 0xC0) == 0x80:
        cut -= 1
    return encoded[:cut].decode("utf-8", errors="ignore")
