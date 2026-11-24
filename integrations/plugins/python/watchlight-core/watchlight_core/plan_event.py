"""Canonical ``plan_observed`` event-payload helpers.

Every framework plugin (LangGraph, Bedrock, ADK) emits the same
canonical ``plan_observed`` event shape so the wl-execution-graph
plan-vs-act correlator sees one wire contract regardless of
provenance. This module owns the validation + bounds; plugins
import it instead of re-implementing the constraints.

Wire shape (the ``payload`` block of an ``ExecutionEvent``):

.. code-block:: json

    {
        "intended_tools": ["fetch_news", "summarize"],
        "plan_kind": "incremental",
        "rationale": "user asked for X; I'll fetch then summarize"
    }

The constants here MUST stay in lockstep with the equivalent
Rust-side and TypeScript-lane constants so every lane emits the
identical wire contract.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Iterable, Optional, Sequence

__all__ = [
    "PLAN_TOOL_NAME_PATTERN",
    "PLAN_TOOL_NAME_RE",
    "PLAN_INTENDED_TOOLS_MAX",
    "PLAN_RATIONALE_MAX_BYTES",
    "PlanKind",
    "PlanValidationError",
    "build_plan_payload",
    "is_valid_tool_name",
    "truncate_rationale",
]

# ─── Constants (lockstep with the Rust and TypeScript lanes) ───────────

#: Regex source for a valid tool name. The compiled
#: form sits below for fast hot-path use.
PLAN_TOOL_NAME_PATTERN = r"^[A-Za-z0-9_.\-]{1,128}$"

#: Compiled regex. Used by ``is_valid_tool_name``; exposed as a
#: module attribute so plugins that want to short-circuit can match
#: directly.
PLAN_TOOL_NAME_RE = re.compile(PLAN_TOOL_NAME_PATTERN)

#: Maximum number of names in ``intended_tools``. Caps event size
#: against an attacker padding the plan to inflate the allowed set.
PLAN_INTENDED_TOOLS_MAX = 64

#: Maximum byte length of ``rationale``. Operator-legibility only;
#: the correlator never matches on rationale text.
PLAN_RATIONALE_MAX_BYTES = 1024


class PlanKind:
    """String constants for ``plan_kind`` — value type, not an enum,
    because the wire form is a plain JSON string and stringifying
    enums everywhere adds noise without value.

    The framework→kind mapping:

    - ``upfront`` — full plan emitted before any tool execution
      (Bedrock ``preProcessingTrace``).
    - ``incremental`` — one tool at a time (LangGraph ReAct,
      ADK ``before_tool_callback``).
    - ``inferred`` — no plan signal from the framework (MCP-direct
      traffic). Carried for completeness so the correlator can
      distinguish "plugin sent empty plan" from "plugin didn't emit".
    """

    UPFRONT = "upfront"
    INCREMENTAL = "incremental"
    INFERRED = "inferred"

    ALL = (UPFRONT, INCREMENTAL, INFERRED)


class PlanValidationError(ValueError):
    """Raised by ``build_plan_payload`` when constraints don't hold.

    Plugins catch this and drop the event (logging at ``debug``) so a
    malformed plan never makes it onto the wire. Mirrors the Rust-side
    ``PlanValidationError`` enum.
    """


def is_valid_tool_name(name: str) -> bool:
    """Cheap pre-check against the documented regex. Plugins use this
    to filter out adversarial tool descriptions before constructing
    the full payload."""
    if not isinstance(name, str):
        return False
    return PLAN_TOOL_NAME_RE.match(name) is not None


def truncate_rationale(rationale: Optional[str]) -> Optional[str]:
    """Bound rationale to ``PLAN_RATIONALE_MAX_BYTES``. Returns None
    if input is None or empty after stripping. Truncation is
    byte-safe (str slicing in Python on ASCII / UTF-8 boundary
    handling is sufficient for the rationale's expected shape — short
    English-language explanations)."""
    if rationale is None:
        return None
    cleaned = rationale.strip()
    if not cleaned:
        return None
    if len(cleaned.encode("utf-8")) <= PLAN_RATIONALE_MAX_BYTES:
        return cleaned
    # Truncate to bytes, then back to str. Safe because we re-decode
    # with errors='ignore' to drop any partial multi-byte char at
    # the boundary.
    return cleaned.encode("utf-8")[:PLAN_RATIONALE_MAX_BYTES].decode(
        "utf-8", errors="ignore"
    )


def build_plan_payload(
    intended_tools: Sequence[str],
    plan_kind: str,
    rationale: Optional[str] = None,
) -> Dict[str, Any]:
    """Validate + build a ``plan_observed`` event payload.

    Raises ``PlanValidationError`` if any constraint fails. Plugins
    SHOULD catch and log+drop rather than propagating.

    The returned dict is safe to nest directly under ``payload`` in
    the canonical event envelope.
    """
    if plan_kind not in PlanKind.ALL:
        raise PlanValidationError(
            f"plan_kind must be one of {PlanKind.ALL}; got {plan_kind!r}"
        )

    tools_list = list(intended_tools)
    if not tools_list:
        raise PlanValidationError("intended_tools must be non-empty")
    if len(tools_list) > PLAN_INTENDED_TOOLS_MAX:
        raise PlanValidationError(
            f"intended_tools has {len(tools_list)} entries (max "
            f"{PLAN_INTENDED_TOOLS_MAX})"
        )

    for name in tools_list:
        if not is_valid_tool_name(name):
            raise PlanValidationError(
                f"tool name {name!r} does not match {PLAN_TOOL_NAME_PATTERN}"
            )

    payload: Dict[str, Any] = {
        "intended_tools": tools_list,
        "plan_kind": plan_kind,
    }
    bounded_rationale = truncate_rationale(rationale)
    if bounded_rationale:
        payload["rationale"] = bounded_rationale
    return payload


def filter_valid_tool_names(names: Iterable[str]) -> list[str]:
    """Drop invalid names, keep valid ones, preserving order +
    deduplicating while keeping first-seen order.

    Plugins that extract plans from free-form sources (Bedrock's
    parsed model rationale text) call this to defensively clean the
    extracted list before building the event payload.
    """
    seen: set[str] = set()
    out: list[str] = []
    for name in names:
        if not isinstance(name, str):
            continue
        if name in seen:
            continue
        if is_valid_tool_name(name):
            seen.add(name)
            out.append(name)
    return out
