"""Synthetic tool injection for the Claude Agent SDK (Python lane).

This module wires the framework-agnostic synthetic ``watchlight.declare_intent``
contract from :mod:`watchlight_core.declare_intent` into the Claude Agent
SDK's tool-list + tool-call surface.

# How the integration shape works

The Python ``claude-agent-sdk`` runs its loop on the customer's side: the
customer drives ``query(prompt=..., options=...)`` and feeds the resulting
hook events (PreToolUse / PostToolUse / UserPromptSubmit / Stop /
SubagentStart / SubagentStop / PostToolUseFailure) through
:func:`translate_claude_agent_events` to publish canonical lineage.

To inject the synthetic tool zero-code from the customer's perspective, we
expose two primitives:

1. :func:`synthetic_tool_definitions` — returns the list of synthetic tool
   shapes the agent should see for this run. The customer unions this with
   their own ``options["tools"]`` when calling ``query()``.

2. :func:`intercept_tool_call` — short-circuits a tool-call capture if it's
   the synthetic tool. Mutates the run-handle's intent state via
   :func:`watchlight_core.handle_declare_intent_call` and returns the
   LLM-visible tool response. The customer's loop short-circuits BEFORE
   calling ``handle.authorize_action()`` on the synthetic tool (the
   intentional authorization carve-out described below).

Both helpers are also reachable as methods on
:class:`WatchlightClaudeAgentSDKPlugin` for ergonomic call sites in
customer code.

# Why the synthetic tool bypasses authorization

A call to ``watchlight.declare_intent`` MUST NOT round-trip to
``authorize_action()`` — that would create a chicken-and-egg problem with
the intent-enforcement Cedar gate (the gate forbids on
``provenance != "declared"``; the agent's first
declarative call would be denied before it could declare). The customer's
hook loop calls :func:`intercept_tool_call` BEFORE the authorize path
fires; the audit trail still captures the call via the plugin's
``tool_call_observed`` translation, so an operator sees every
``declare_intent`` invocation on the audit log.

# Mode resolution

Mode resolution sits at the plugin construction boundary, not at session
start, so the tool is in the agent's tool list before the agent's first
turn. The plugin's ``intent_enforcement_mode`` constructor argument wins;
otherwise the helper reads
:func:`watchlight_core.resolve_intent_enforcement_mode` which falls back
to the ``WATCHLIGHT_INTENT_ENFORCEMENT_MODE`` env var and finally to the
locked brownfield default.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional

from watchlight_core import (
    BaseRunHandle,
    get_logger,
    handle_declare_intent_call,
    is_declare_intent_tool_call,
    is_declare_intent_tool_name,
    resolve_intent_enforcement_mode,
    should_inject_synthetic_tool,
)
from watchlight_core.declare_intent import (
    DECLARE_INTENT_RESPONSE_STATUS,
    DECLARE_INTENT_TOOL_NAME,
    WATCHLIGHT_DECLARE_INTENT_TOOL,
)

logger = get_logger("watchlight_claude_agent.synthetic_tools")

__all__ = [
    "DECLARE_INTENT_TOOL_NAME",
    "DECLARE_INTENT_RESPONSE_STATUS",
    "WATCHLIGHT_DECLARE_INTENT_TOOL",
    "synthetic_tool_definitions",
    "merge_synthetic_tools",
    "intercept_tool_call",
    "is_synthetic_tool_capture",
]


def synthetic_tool_definitions(
    mode: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Return the synthetic Watchlight-managed tool definitions the agent
    should see for this run.

    When the agent's effective intent-enforcement mode is
    greenfield, the list contains the
    :data:`watchlight_core.WATCHLIGHT_DECLARE_INTENT_TOOL` definition.
    Brownfield agents see an empty list — the synthetic-tool gate is
    inert in brownfield because the matrix accepts inferred provenance
    at every tier.

    The dict shape uses the Anthropic / OpenAI tool-use convention
    (``name`` + ``description`` + ``parameters``), which the Claude
    Agent SDK accepts directly — no per-framework translation required.

    Parameters
    ----------
    mode:
        Override the SDK's mode-resolution helper. When ``None`` (the
        default), reads :func:`watchlight_core.resolve_intent_enforcement_mode`
        which falls back to the ``WATCHLIGHT_INTENT_ENFORCEMENT_MODE``
        env var, then to the locked brownfield default.

    Returns
    -------
    list of dict
        Empty in brownfield. In greenfield: a single-element list
        containing :data:`WATCHLIGHT_DECLARE_INTENT_TOOL`. Each dict is
        a fresh copy so customer mutation cannot leak back into the SDK
        primitive.
    """
    effective_mode = (
        mode if isinstance(mode, str) else resolve_intent_enforcement_mode()
    )
    if not should_inject_synthetic_tool(effective_mode):
        return []
    return [dict(WATCHLIGHT_DECLARE_INTENT_TOOL)]


def merge_synthetic_tools(
    customer_tools: Optional[Iterable[Dict[str, Any]]] = None,
    mode: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Union the customer's tools with the synthetic ones for the given
    mode.

    Tool ordering: synthetic tools come FIRST so the LLM's tool-list
    view surfaces ``watchlight.declare_intent`` at the top. Anthropic's
    documented LLM tool-discovery heuristic biases toward earlier
    entries; placing the gate up front maximises the chance the agent
    actually calls it before any privileged tool.

    Defensive deduplication: if the customer already registered a tool
    named ``watchlight.declare_intent`` (shouldn't happen — the
    namespace is reserved), the customer's entry is dropped in favour
    of the SDK's canonical definition. This avoids the LLM seeing two
    distinct tool definitions with the same name (an SDK-level validation
    error on most frameworks).

    Parameters
    ----------
    customer_tools:
        Iterable of customer-defined tool definitions. May be ``None``
        for the "synthetic-only" case (e.g. the agent has no
        customer-defined tools and just needs the declare-intent gate).
    mode:
        Mode override, mirrors :func:`synthetic_tool_definitions`.
    """
    synthetic = synthetic_tool_definitions(mode=mode)
    if customer_tools is None:
        return synthetic

    # De-dupe: drop any customer tool whose name matches the synthetic
    # reserved name. Cheap (O(n)) and runs only at session-construction
    # time, not per-turn.
    customer_kept: List[Dict[str, Any]] = []
    for tool in customer_tools:
        name = tool.get("name") if isinstance(tool, dict) else None
        if is_declare_intent_tool_name(name):
            logger.warning(
                "watchlight: customer tool %r collides with the reserved "
                "synthetic tool name; dropping the customer entry in favour "
                "of the SDK definition.",
                name,
            )
            continue
        customer_kept.append(tool)

    return [*synthetic, *customer_kept]


def is_synthetic_tool_capture(capture: Optional[Dict[str, Any]]) -> bool:
    """Return ``True`` iff a hook capture describes a call to the
    synthetic ``watchlight.declare_intent`` tool.

    Accepts the canonical Claude Agent SDK ``PreToolUse`` /
    ``PostToolUse`` capture shape (``{"hook": ..., "tool_name": ...,
    "tool_input": ...}``) AND the framework-agnostic
    ``{"name": ..., "arguments": ...}`` shape — so the same predicate
    works whether the customer captured the raw hook dict or pre-
    transformed it into a tool-call envelope.

    Defensive default: returns ``False`` on any unrecognised shape so
    the calling loop's short-circuit defaults to "forward to customer
    handler" — safer than incorrectly bypassing authorize on a
    misdetected call.
    """
    if not isinstance(capture, dict):
        return False
    # Claude Agent SDK hook-capture shape.
    tool_name = capture.get("tool_name")
    if isinstance(tool_name, str) and is_declare_intent_tool_name(tool_name):
        return True
    # Framework-agnostic tool-call shape — defer to the SDK predicate
    # which accepts every common variant.
    return is_declare_intent_tool_call(capture)


def intercept_tool_call(
    handle: BaseRunHandle,
    capture: Optional[Dict[str, Any]],
) -> Optional[Dict[str, Any]]:
    """Short-circuit handling for the synthetic ``watchlight.declare_intent``
    tool call.

    Customer's hook loop calls this BEFORE invoking
    ``handle.authorize_action()`` on any tool call. When the capture is
    the synthetic tool, this helper:

    1. Mutates the handle's intent state via
       :func:`watchlight_core.handle_declare_intent_call` — the next
       ``authorize_action()`` call will auto-inject
       the typed ``intent={"objective", "category"}`` into the APDP request
       body (only when both were declared) and
       satisfy the intent-enforcement Cedar gate.
    2. Returns the LLM-visible tool response dict —
       ``{"status": "intent_declared", "objective": "...", "category": ...}``
       on success;
       ``{"status": "rejected", "reason": "..."}`` on invalid input.

    When the capture is NOT the synthetic tool, returns ``None`` so the
    caller's loop falls through to its normal authorize + translate path.

    Parameters
    ----------
    handle:
        The :class:`BaseRunHandle` for the sub-agent (or root) that
        emitted the tool call. Sub-agent governance: ALWAYS pass the
        sub-agent's handle when the sub-agent emits the call — using
        the root handle on a sub-agent's call is a privilege escalation
        (a sub-agent must never inherit the root's authority).
    capture:
        The raw hook capture or tool-call envelope. Accepts both the
        Claude Agent SDK ``{"hook": "PreToolUse", "tool_name": ...,
        "tool_input": ...}`` shape AND the framework-agnostic
        ``{"name": ..., "arguments": ...}`` shape.

    Returns
    -------
    dict or None
        ``None`` for non-synthetic tool calls (customer's loop handles
        them normally). A response dict for synthetic tool calls.
    """
    if not is_synthetic_tool_capture(capture):
        return None
    assert isinstance(capture, dict)  # is_synthetic_tool_capture guards this

    # Pull arguments from whichever shape the capture used. SDK hook
    # captures use ``tool_input``; framework-agnostic envelopes use
    # ``arguments`` (Anthropic / OpenAI) or ``args`` (LangChain).
    arguments = (
        capture.get("tool_input")
        or capture.get("arguments")
        or capture.get("args")
        or {}
    )
    if not isinstance(arguments, dict):
        arguments = {}

    response = handle_declare_intent_call(handle, arguments)
    # Audit trail — operator visibility. Logged at INFO so the
    # synthetic-tool firing is observable in the customer's runtime
    # without needing the wl-apdp /v1/events round-trip. The wire-shape
    # audit is captured separately by translate_claude_agent_event() on
    # the PreToolUse hook capture.
    if response.get("status") == DECLARE_INTENT_RESPONSE_STATUS:
        logger.info(
            "watchlight: synthetic declare_intent succeeded — "
            "subsequent authorize_action() calls carry provenance=declared."
        )
    else:
        logger.info(
            "watchlight: synthetic declare_intent rejected (%s); "
            "handle's intent state unchanged.",
            response.get("reason"),
        )
    return response
