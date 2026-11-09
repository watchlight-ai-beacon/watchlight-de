"""Synthetic ``watchlight.declare_intent`` tool contract.

This module is the single source of truth for the synthetic-tool wire
shape that every framework plugin injects into the agent's tool list
when the agent's effective intent-enforcement mode is **greenfield**.
The tool, when invoked by the agent, mutates the run-handle's stored
intent fields and bumps :class:`IntentProvenance` to
:attr:`IntentProvenance.DECLARED` — which then satisfies the
greenfield Cedar gate that forbids actions until intent is declared,
on the agent's next ``authorize_action()`` call.

Why this lives in ``watchlight_core``
=====================================

The contract is uniform across plugins — the tool's name, parameter
shape, response shape, byte cap, and side effect are framework-agnostic.
Only the per-framework auto-registration is plugin-specific (LangGraph
binds via ``bind_tools``, Pydantic AI extends the agent's tool list,
Claude Agent SDK injects via ``query`` options, etc.).

By centralising the contract here:

- A schema drift between plugins is structurally impossible — every
  plugin imports :data:`WATCHLIGHT_DECLARE_INTENT_TOOL` verbatim.
- The truncation logic reuses
  :data:`watchlight_core.events_schema.INTENT_OBJECTIVE_MAX_BYTES`,
  which mirrors the same constant on the Rust side.
- Conformance tests can assert the wire shape across every
  shipped plugin from a single import path.

Security carve-out
==================

A call to ``watchlight.declare_intent`` MUST NOT itself round-trip to
``authorize_action()`` — that would chicken-and-egg with the greenfield
Cedar gate (the gate forbids on ``provenance != "declared"``; the
agent's first declarative call would be denied before it could declare).

The plugin layer is responsible for short-circuiting the synthetic
tool call BEFORE the authorize path fires. This module provides the
:func:`is_declare_intent_tool_call` predicate plugins use for that
short-circuit; the audit trail still captures the call via the
plugin's ``tool_call_observed`` emission, so an operator sees every
``declare_intent`` invocation on the audit log.

The accepted risk is captured in the Watchlight security documentation.

Mode resolution
===============

The plugin decides whether to inject the synthetic tool based on the
agent's effective intent-enforcement mode. The mode comes from
operator configuration — either a constructor argument on the plugin
class or the ``WATCHLIGHT_INTENT_ENFORCEMENT_MODE`` env variable.

Mode resolution lives at the plugin construction boundary, not at
session start, so the tool is in the agent's tool list before the
agent's first turn. Brownfield agents never see the tool — its
presence in greenfield mode is the load-bearing operator signal.
"""

from __future__ import annotations

import os
import re
from typing import Any, Dict, Optional

from .errors import IntentRefused
from .events_schema import INTENT_OBJECTIVE_MAX_BYTES, IntentProvenance
from .log import get_logger

logger = get_logger("watchlight_core.declare_intent")

__all__ = [
    "WATCHLIGHT_DECLARE_INTENT_TOOL",
    "DECLARE_INTENT_TOOL_NAME",
    "DECLARE_INTENT_TOOL_DESCRIPTION",
    "DECLARE_INTENT_RESPONSE_STATUS",
    "INTENT_ENFORCEMENT_MODE_ENV_VAR",
    "GREENFIELD",
    "BROWNFIELD",
    "handle_declare_intent_call",
    "is_declare_intent_tool_name",
    "is_declare_intent_tool_call",
    "should_inject_synthetic_tool",
    "resolve_intent_enforcement_mode",
    "truncate_intent_objective",
    "INTENT_CATEGORIES",
    "CUSTOM_INTENT_CATEGORY_PREFIX",
    "normalize_intent_category",
    "typed_intent",
    "wire_intent",
    "normalize_intent_justification",
    "INTENT_JUSTIFICATION_MAX_BYTES",
]

#: Upper bound on a declared justification (UTF-8 bytes) kept and sent.
INTENT_JUSTIFICATION_MAX_BYTES: int = 1024


#: Canonical tool name. The leading namespace prefix (``watchlight.``)
#: prevents collision with any customer-defined tool — operators
#: scanning their tool list for the synthetic tool key on the exact
#: literal here.
DECLARE_INTENT_TOOL_NAME: str = "watchlight.declare_intent"

#: Operator-facing description rendered into the LLM's tool-list view.
#: Phrasing emphasises the BEFORE-other-tools ordering — the gate is
#: useless if the agent calls a privileged tool before declaring.
DECLARE_INTENT_TOOL_DESCRIPTION: str = (
    "Declare your goal for this session. You MUST call this BEFORE any "
    "other tool. Provide a short objective (<=256 bytes) describing what "
    "you intend to accomplish and the category it falls under. The "
    "objective and category are stamped on the audit log and propagated "
    "to authorization decisions."
)

#: wl-apdp's ``IntentCategory`` variants, in their wire (snake_case) form.
#: Pinned against wl-apdp and the compiled engine by a platform contract
#: test so the two cannot drift.
INTENT_CATEGORIES: tuple = (
    "customer_support",
    "data_analysis",
    "content_generation",
    "system_administration",
    "financial_operation",
    "external_integration",
    "research",
    "code_generation",
    "security_compliance",
)

#: The string form a model gives a custom category in: ``custom:<name>``.
#: On the wire it becomes wl-apdp's ``{"custom": "<name>"}``.
CUSTOM_INTENT_CATEGORY_PREFIX: str = "custom:"

_CUSTOM_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.\-]{0,63}$")


def normalize_intent_category(value: Any) -> Any:
    """The wire form of an intent category, or ``None`` when it is not one.

    wl-apdp's ``IntentDeclaration.category`` is required and is either one
    of :data:`INTENT_CATEGORIES` or ``{"custom": "<name>"}``. Accepted here:
    a listed name, ``"custom:<name>"`` (the string form tool schemas can
    carry) and ``{"custom": "<name>"}``. Anything else is ``None``: the
    caller sends no intent rather than one wl-apdp would refuse."""
    if isinstance(value, str):
        text = value.strip()
        if text in INTENT_CATEGORIES:
            return text
        if text.startswith(CUSTOM_INTENT_CATEGORY_PREFIX):
            name = text[len(CUSTOM_INTENT_CATEGORY_PREFIX):].strip()
            if _CUSTOM_NAME.match(name):
                return {"custom": name}
        return None
    if isinstance(value, dict) and set(value) == {"custom"}:
        name = value.get("custom")
        if isinstance(name, str) and _CUSTOM_NAME.match(name.strip()):
            return {"custom": name.strip()}
    return None


def _normalize_text(text: Any, max_bytes: int) -> Optional[str]:
    if not isinstance(text, str):
        return None
    collapsed = _WHITESPACE_RUN_EARLY.sub(" ", text).strip()
    if not collapsed:
        return None
    encoded = collapsed.encode("utf-8")
    if len(encoded) <= max_bytes:
        return collapsed
    return encoded[:max_bytes].decode("utf-8", errors="ignore").rstrip() or None


_WHITESPACE_RUN_EARLY = re.compile(r"\s+")


def normalize_intent_justification(value: Any) -> Optional[str]:
    """A justification as sent (whitespace collapsed, byte-capped), or
    ``None`` when it is not a non-empty string."""
    return _normalize_text(value, INTENT_JUSTIFICATION_MAX_BYTES)


def typed_intent(
    objective: Any, category: Any, justification: Any = None, **extra: Any
) -> Optional[Dict[str, Any]]:
    """An ``intent`` wl-apdp can parse (``objective`` + ``category``, an
    optional ``justification``, plus ``extra`` fields such as
    ``approval_token``), or ``None`` when the objective or category is
    missing or invalid, or a justification is given but is not a string.
    Never an untyped intent: wl-apdp answers a category-less intent with
    422."""
    obj = truncate_intent_objective(objective)
    cat = normalize_intent_category(category)
    if obj is None or cat is None:
        return None
    intent: Dict[str, Any] = {k: v for k, v in extra.items() if v is not None}
    intent["objective"] = obj
    intent["category"] = cat
    if justification is not None:
        just = normalize_intent_justification(justification)
        if just is None:
            return None
        intent["justification"] = just
    return intent


_TYPED_KEYS = ("objective", "category", "justification")


def wire_intent(
    intent: Optional[Dict[str, Any]],
    declared_objective: Any = None,
    declared_category: Any = None,
    declared_justification: Any = None,
) -> Optional[Dict[str, Any]]:
    """The ``intent`` to put on an authorize request, or ``None`` for none.

    * No caller intent (``None`` or ``{}``): the declared intent, typed
      (objective, category and any justification), or ``None`` when the run
      declared none.
    * A caller intent that names neither ``objective`` nor ``category``
      (an approval retry that only adds ``approval_token``): the declared
      intent with the caller's fields added. Without a declared intent there
      is nothing to carry them in, and :class:`IntentRefused` is raised.
    * A caller intent that names ``objective`` or ``category`` (even as
      ``null``): it must name BOTH, valid, itself. A caller objective is
      never sent under the declared category. Otherwise
      :class:`IntentRefused`.

    Raising, not dropping, is the point: sending nothing in place of a
    malformed intent would make wl-apdp skip intent validation and the
    approval gates it carries."""
    if intent is None or intent == {}:
        if declared_objective is None and declared_category is None:
            return None
        declared = typed_intent(declared_objective, declared_category, declared_justification)
        if declared is None:
            raise IntentRefused("the declared intent is not a typed intent; nothing was sent")
        return declared
    if not isinstance(intent, dict):
        raise IntentRefused(
            f"the intent is a {type(intent).__name__}, not an object; nothing was sent"
        )
    extra = {k: v for k, v in intent.items() if k not in _TYPED_KEYS}
    if "objective" not in intent and "category" not in intent:
        if declared_objective is None and declared_category is None:
            raise IntentRefused(
                "the intent carries no objective or category and the run declared "
                "none, so it cannot be sent; nothing was sent"
            )
        justification = intent.get("justification", declared_justification)
        typed = typed_intent(declared_objective, declared_category, justification, **extra)
        if typed is None:
            raise IntentRefused("the intent could not be typed; nothing was sent")
        return typed
    typed = typed_intent(
        intent.get("objective"), intent.get("category"), intent.get("justification"), **extra
    )
    if typed is None:
        raise IntentRefused(
            "the intent must carry both a non-empty objective and a category wl-apdp "
            "accepts (one of " + ", ".join(INTENT_CATEGORIES) + ", or custom:NAME), "
            "and any justification must be a string; nothing was sent"
        )
    return typed

#: Status field returned to the agent after a successful declare call.
DECLARE_INTENT_RESPONSE_STATUS: str = "intent_declared"

#: Env-var operators set to flip the plugin into greenfield mode.
#: Mirrors the Rust ``IntentEnforcementMode`` wire spelling
#: (``brownfield`` | ``greenfield``).
INTENT_ENFORCEMENT_MODE_ENV_VAR: str = "WATCHLIGHT_INTENT_ENFORCEMENT_MODE"

#: Wire string for greenfield mode. Matches the Rust
#: ``IntentEnforcementMode::Greenfield`` JSON form.
GREENFIELD: str = "greenfield"

#: Wire string for brownfield mode. Matches the Rust
#: ``IntentEnforcementMode::Brownfield`` JSON form.
BROWNFIELD: str = "brownfield"


#: JSON Schema shape for the synthetic tool. Plugins translate this
#: into the framework-native tool-definition shape (LangChain's
#: ``StructuredTool``, Pydantic AI's ``Tool``, Bedrock's function-call
#: schema, etc.) but they all derive from this single source. The
#: keys mirror the Anthropic / OpenAI tool-call convention so the
#: shape is recognisable to any LLM-side tool-binding layer.
WATCHLIGHT_DECLARE_INTENT_TOOL: Dict[str, Any] = {
    "name": DECLARE_INTENT_TOOL_NAME,
    "description": DECLARE_INTENT_TOOL_DESCRIPTION,
    "parameters": {
        "type": "object",
        "properties": {
            "objective": {
                "type": "string",
                "description": (
                    "Your declared goal for this session. Truncated to "
                    "256 bytes (UTF-8) for the audit log."
                ),
                "maxLength": INTENT_OBJECTIVE_MAX_BYTES,
            },
            "justification": {
                "type": "string",
                "description": (
                    "Optional: why this goal is needed. Some categories "
                    "(financial_operation, system_administration, "
                    "security_compliance) are refused without one."
                ),
                "maxLength": INTENT_JUSTIFICATION_MAX_BYTES,
            },
            "category": {
                "type": "string",
                "description": (
                    "The category of your goal: one of "
                    + ", ".join(INTENT_CATEGORIES)
                    + ", or custom:NAME for anything else."
                ),
                "pattern": (
                    "^(" + "|".join(INTENT_CATEGORIES)
                    + r"|custom:[A-Za-z0-9][A-Za-z0-9_.\-]{0,63})$"
                ),
            },
        },
        "required": ["objective", "category"],
        "additionalProperties": False,
    },
}


#: Whitespace collapser — multi-line / tab-padded objectives render
#: as one space-separated line on the dashboard, mirroring the
#: server-side extractor.
_WHITESPACE_RUN = re.compile(r"\s+")


def truncate_intent_objective(text: Optional[Any]) -> Optional[str]:
    """Normalise + byte-truncate an objective string.

    Mirrors :func:`watchlight_pydantic_ai.intent._normalize_and_truncate`
    so the declared-path truncation is byte-identical to the
    plugin-derived path. Returns ``None`` on:

    - non-string input,
    - empty string,
    - whitespace-only input (after collapse),
    - any string that normalises to empty after truncation.

    A partial multi-byte UTF-8 sequence at the byte cap is dropped via
    ``decode("utf-8", errors="ignore")`` — the returned string is
    always valid UTF-8 and never exceeds
    :data:`INTENT_OBJECTIVE_MAX_BYTES` when re-encoded.
    """
    if not isinstance(text, str):
        return None
    collapsed = _WHITESPACE_RUN.sub(" ", text).strip()
    if not collapsed:
        return None
    encoded = collapsed.encode("utf-8")
    if len(encoded) <= INTENT_OBJECTIVE_MAX_BYTES:
        return collapsed
    truncated = encoded[:INTENT_OBJECTIVE_MAX_BYTES].decode("utf-8", errors="ignore")
    truncated = truncated.rstrip()
    return truncated or None


def is_declare_intent_tool_name(name: Optional[str]) -> bool:
    """Return ``True`` iff ``name`` matches the synthetic tool's
    canonical name.

    Plugins call this on every tool invocation to decide whether to
    take the synthetic-tool short-circuit (and skip ``authorize_action``)
    or forward to the customer's normal tool handler. Case-insensitive
    match to defend against framework-specific capitalisation
    normalisation, but the canonical wire spelling is lowercase.
    """
    if not isinstance(name, str):
        return False
    return name.strip().lower() == DECLARE_INTENT_TOOL_NAME


def is_declare_intent_tool_call(tool_call: Any) -> bool:
    """Convenience predicate for tool-call dicts.

    Accepts any of the common framework shapes:

    - ``{"name": "watchlight.declare_intent", "arguments": {...}}``
      (Anthropic / OpenAI canonical).
    - ``{"tool": "watchlight.declare_intent", ...}`` (LangChain
      convention).
    - ``{"function": {"name": "watchlight.declare_intent", ...}}``
      (OpenAI legacy nested shape).

    Returns ``False`` on any unrecognised shape so the calling plugin's
    short-circuit defaults to "forward to customer handler" — safer
    than incorrectly bypassing authorize on a misdetected call.
    """
    if not isinstance(tool_call, dict):
        return False
    if is_declare_intent_tool_name(tool_call.get("name")):
        return True
    if is_declare_intent_tool_name(tool_call.get("tool")):
        return True
    fn = tool_call.get("function")
    if isinstance(fn, dict) and is_declare_intent_tool_name(fn.get("name")):
        return True
    return False


def should_inject_synthetic_tool(mode: Optional[str]) -> bool:
    """Return ``True`` iff a plugin in the given mode MUST inject the
    synthetic tool into the agent's tool list.

    The current contract: synthetic tool is injected only when
    ``mode == "greenfield"``. Brownfield agents never see the tool —
    the brownfield Cedar matrix accepts inferred provenance at every
    tier and the synthetic-tool gate would be inert there anyway.

    Unrecognised modes ("strict", typos, ``None``) fall through to
    ``False`` — fail-safe in the sense that the agent keeps running
    with no synthetic tool but a misconfigured greenfield deployment
    would also miss the gate. The PR body documents this trade-off;
    the alternative (raising on unknown mode) would break customers
    whose ``WATCHLIGHT_INTENT_ENFORCEMENT_MODE`` env var has a typo.
    """
    if not isinstance(mode, str):
        return False
    return mode.strip().lower() == GREENFIELD


def resolve_intent_enforcement_mode(
    explicit: Optional[str] = None,
) -> str:
    """Resolve the agent's effective intent-enforcement mode.

    Resolution order (highest authority first):

    1. ``explicit`` argument — the plugin's constructor kwarg (operator
       opted into the wiring explicitly).
    2. ``WATCHLIGHT_INTENT_ENFORCEMENT_MODE`` env var — the
       deployment-level knob.
    3. ``"brownfield"`` — the locked default (chosen for safety and
       low onboarding friction).

    Returns the canonical lowercase wire string. Unrecognised values
    log a warning and fall back to ``"brownfield"`` — see the rationale
    on :func:`should_inject_synthetic_tool`.
    """
    if isinstance(explicit, str) and explicit.strip():
        candidate = explicit.strip().lower()
    else:
        raw = os.environ.get(INTENT_ENFORCEMENT_MODE_ENV_VAR, "").strip()
        candidate = raw.lower() if raw else BROWNFIELD

    if candidate in (BROWNFIELD, GREENFIELD):
        return candidate

    logger.warning(
        "Unrecognised intent-enforcement mode %r; defaulting to %r",
        candidate,
        BROWNFIELD,
    )
    return BROWNFIELD


def handle_declare_intent_call(
    handle: Any,
    arguments: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Process a ``watchlight.declare_intent`` invocation.

    Mutates ``handle`` by stamping
    :attr:`IntentProvenance.DECLARED` on the run handle's stored
    intent fields. Returns the synthetic tool's response dict —
    plugins forward this to the agent as the tool's output.

    Parameters
    ----------
    handle:
        The :class:`BaseRunHandle` (or sub-agent handle) whose
        execution context should be stamped with the declared
        objective. Must be the handle for the EXACT sub-agent that
        called the tool — using the root handle on a sub-agent's
        call is a privilege escalation
        (``feedback_subagents_must_be_governed``).
    arguments:
        The tool's argument dict as the LLM emitted it. Expected
        shape: ``{"objective": "<string>"}``. Any other shape (or a
        missing/empty objective) is treated as a no-op declaration
        and the handle's provenance is unchanged — the greenfield gate
        will still forbid the agent's next action, which is the
        correct fail-closed behaviour.

    Returns
    -------
    dict
        ``{"status": "intent_declared", "objective": "<truncated>"}``
        on success; ``{"status": "rejected", "reason": "<why>"}`` on
        any input-shape failure. The agent sees the status and can
        retry with a corrected objective.
    """
    arguments = arguments or {}
    raw_objective = arguments.get("objective")
    objective = truncate_intent_objective(raw_objective)
    category = normalize_intent_category(arguments.get("category"))
    raw_justification = arguments.get("justification")
    justification = normalize_intent_justification(raw_justification)
    if raw_justification is not None and justification is None:
        return {
            "status": "rejected",
            "reason": "justification, when given, must be a non-empty string",
        }
    previous = getattr(handle, "_intent_category", None)
    if previous is not None and category is not None and category != previous:
        # The category is fixed for the run once declared: re-declaring a
        # different one is intent drift, refused and recorded. A refined
        # objective under the same category is allowed.
        logger.warning(
            "intent drift: watchlight.declare_intent tried to change the run's "
            "intent category; refused, the declared intent is unchanged",
            extra={
                "event": "intent_drift",
                "declared_category": previous,
                "attempted_category": category,
            },
        )
        return {
            "status": "rejected",
            "reason": (
                "the intent category is fixed for this run once declared; "
                "re-declaring a different category is refused"
            ),
        }
    if objective is not None and category is None:
        logger.info(
            "watchlight.declare_intent called without a valid category; "
            "provenance unchanged (Absent)."
        )
        return {
            "status": "rejected",
            "reason": (
                "category is required: one of "
                + ", ".join(INTENT_CATEGORIES)
                + ", or custom:NAME"
            ),
        }
    if objective is None:
        logger.info(
            "watchlight.declare_intent called with empty/invalid "
            "objective; provenance unchanged (Absent)."
        )
        return {
            "status": "rejected",
            "reason": (
                "objective is required and must be a non-empty string"
            ),
        }

    # Mutate the run handle. The attributes default to ``None`` on
    # BaseRunHandle; we set them unconditionally so the subsequent
    # authorize_action() call auto-injects ``intent={"objective": ...}``
    # into the APDP request body. That hits the Cedar context
    # projection's "caller-declared inline intent" branch, which stamps
    # ``intent_provenance: "declared"`` and clears the greenfield
    # Custodial gate.
    handle._intent_objective = objective
    handle._intent_category = category
    handle._intent_justification = justification
    handle._intent_provenance = IntentProvenance.DECLARED

    logger.info(
        "watchlight.declare_intent: objective stamped (%d bytes); "
        "subsequent authorize_action() calls will carry "
        "provenance=Declared.",
        len(objective.encode("utf-8")),
    )

    return {
        "status": DECLARE_INTENT_RESPONSE_STATUS,
        "objective": objective,
        "category": category,
        **({"justification": justification} if justification is not None else {}),
    }
