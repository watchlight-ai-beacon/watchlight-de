"""Claude Agent SDK prompt → intent extraction (Python lane).

When the Claude Agent SDK fires a ``UserPromptSubmit`` hook event, the
user's submitted prompt is captured under ``capture["prompt"]``. This
module extracts that prompt and byte-truncates it to
:data:`watchlight_core.INTENT_OBJECTIVE_MAX_BYTES` so the resulting
``execution_started`` event carries:

  - ``payload.intent_objective`` — the (truncated, UTF-8-safe) prompt
  - ``payload.intent_provenance`` — :attr:`IntentProvenance.PLUGIN_DERIVED`
    when a non-empty prompt was extracted, :attr:`IntentProvenance.ABSENT`
    otherwise

The conformance gate requires the two fields to be consistent:
a populated ``intent_objective`` MUST carry a non-Absent provenance, and
an absent objective MUST carry :attr:`IntentProvenance.ABSENT`. The
helpers in this module are the single point of computation so the gate
holds by construction.

# SessionStart vs UserPromptSubmit timing

The Claude Agent SDK fires ``SessionStart`` *before* ``UserPromptSubmit``.
The Python plugin's translator is post-hoc — the customer captures hook
events and feeds them through ``translate_claude_agent_events`` — so the
translator naturally builds ``execution_started`` from the
``UserPromptSubmit`` capture, not from any earlier ``SessionStart``. There
is no "deferred start_run" coordination required on the Python lane; the
``execution_started`` event is minted at translation time once the prompt
is in hand.

The TypeScript lane has a different lifecycle (the SDK invokes hooks
live), and its equivalent module defers ``plugin.startRun(...)`` to
``UserPromptSubmit`` rather than ``SessionStart`` for the same reason —
pre-prompt actions are extremely rare in practice, and deferring keeps
the audit trail clean (single emit, populated provenance) at the cost of
a deferred session-open.
"""

from __future__ import annotations

from typing import Any, Mapping, Optional, Tuple

from watchlight_core import INTENT_OBJECTIVE_MAX_BYTES, IntentProvenance

__all__ = [
    "extract_intent_from_user_prompt_submit",
    "truncate_intent_objective",
]


def truncate_intent_objective(text: Optional[str]) -> Optional[str]:
    """Byte-truncate an intent-objective string to
    :data:`INTENT_OBJECTIVE_MAX_BYTES`.

    Returns ``None`` on ``None`` / empty / whitespace-only input.
    Truncation is UTF-8-safe: the slice is taken at a byte boundary and
    then re-decoded with ``errors='ignore'`` so any partial multi-byte
    codepoint at the boundary is dropped. The result is therefore valid
    UTF-8 and never larger than :data:`INTENT_OBJECTIVE_MAX_BYTES` bytes.

    Mirrors ``watchlight_core.truncate_rationale`` in shape — same
    byte-boundary discipline, different size bound.
    """
    if text is None:
        return None
    cleaned = text.strip()
    if not cleaned:
        return None
    encoded = cleaned.encode("utf-8")
    if len(encoded) <= INTENT_OBJECTIVE_MAX_BYTES:
        return cleaned
    # Slice at the byte boundary, then decode with errors='ignore' so a
    # split codepoint at the cut is dropped (yielding a valid UTF-8
    # string strictly shorter than the cap).
    return encoded[:INTENT_OBJECTIVE_MAX_BYTES].decode("utf-8", errors="ignore")


def extract_intent_from_user_prompt_submit(
    capture: Mapping[str, Any],
) -> Tuple[Optional[str], IntentProvenance]:
    """Extract ``(intent_objective, intent_provenance)`` from a
    ``UserPromptSubmit`` hook capture.

    The Claude Agent SDK exposes the user's prompt body on the hook
    event under the ``prompt`` key (matching the SDK's
    ``UserPromptSubmitHookInput`` hook-input shape).
    A non-string / missing / empty-after-strip value is treated as
    "no intent signal" and returns
    ``(None, IntentProvenance.ABSENT)``; the corresponding
    ``execution_started`` event will be emitted with no
    ``intent_objective`` field and ``intent_provenance: absent``, which
    audit consumers tolerate gracefully (the field is optional
    on the wire).

    Truncation is byte-counted via :func:`truncate_intent_objective`.

    :returns: a 2-tuple of ``(objective, provenance)``. When the prompt
        is non-empty, ``provenance`` is
        :attr:`IntentProvenance.PLUGIN_DERIVED`; otherwise
        :attr:`IntentProvenance.ABSENT`.
    """
    prompt = capture.get("prompt")
    if not isinstance(prompt, str):
        return (None, IntentProvenance.ABSENT)

    objective = truncate_intent_objective(prompt)
    if objective is None:
        return (None, IntentProvenance.ABSENT)
    return (objective, IntentProvenance.PLUGIN_DERIVED)
