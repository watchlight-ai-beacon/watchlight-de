"""Per-framework synthetic ``watchlight.declare_intent`` tool
for Google Agent Development Kit.

This module provides the ADK-native translation of the canonical
:data:`watchlight_core.WATCHLIGHT_DECLARE_INTENT_TOOL` schema into a
real :class:`google.adk.tools.base_tool.BaseTool` subclass that the
plugin injects into the agent's ``tools`` list at construction time
(``before_agent_callback``).

# Why subclass ``BaseTool`` directly (not ``FunctionTool``)
==========================================================

ADK's :class:`google.adk.tools.FunctionTool` derives the tool name
from ``func.__name__`` of the wrapped Python callable. The canonical
wire name is ``watchlight.declare_intent`` (with a dot) — that's not a
legal Python identifier, so a ``FunctionTool`` wrapper would always
re-publish under a synthetic name like ``declare_intent`` and break
the cross-plugin contract (Cedar templates and the
:func:`watchlight_core.is_declare_intent_tool_name` predicate both
key on the exact literal ``"watchlight.declare_intent"``).

Subclassing :class:`BaseTool` lets us:

* Set ``name`` to the exact canonical literal.
* Author a :class:`google.genai.types.FunctionDeclaration` by hand
  from the canonical JSON Schema in
  :data:`watchlight_core.WATCHLIGHT_DECLARE_INTENT_TOOL` so the
  shape advertised to the LLM is byte-identical across plugins.
* Implement ``run_async`` to delegate to
  :func:`watchlight_core.handle_declare_intent_call` and return the
  ``{"status": "intent_declared", "objective": ...}`` shape verbatim
  — every plugin produces the same response.

This avoids monkey-patching: we use ADK's first-class tool
registration (``BaseTool``) rather than reaching into any agent or
framework internals.

# The declare-intent authorize carve-out
=======================================

The plugin's :meth:`before_tool_callback` short-circuits BEFORE the
APDP ``/authorize`` round-trip when the tool name is the canonical
declare-intent name. The carve-out is required because the greenfield
Cedar gate FORBIDS Custodial actions in greenfield mode until
``intent_provenance == "declared"`` — and an agent's very first
``watchlight.declare_intent`` call would otherwise be denied before
it could declare. The plugin's short-circuit invokes this tool's
``run_async`` (which mutates the plugin's intent state via
:func:`watchlight_core.handle_declare_intent_call`) and returns the
tool's response dict directly to ADK.

The synthetic tool's invocation IS still surfaced on the audit log
via the plugin's ``after_tool_callback`` emission, so operators see
every ``watchlight.declare_intent`` call. The short-circuit only
elides the ``/authorize`` round-trip — observability is unaffected.

# Idempotent injection
======================

The plugin's :meth:`before_agent_callback` may run multiple times in
the lifetime of a single agent (once per turn / per sub-agent
invocation). The injector keys on the canonical tool name to avoid
re-adding the synthetic tool on subsequent invocations — a single
turn-life instance is enough.
"""

from __future__ import annotations

from typing import Any, List, Optional

from watchlight_core import (
    DECLARE_INTENT_TOOL_DESCRIPTION,
    DECLARE_INTENT_TOOL_NAME,
    WATCHLIGHT_DECLARE_INTENT_TOOL,
    get_logger,
    handle_declare_intent_call,
    is_declare_intent_tool_name,
)

logger = get_logger("watchlight_adk.synthetic_intent_tool")


__all__ = [
    "WatchlightDeclareIntentTool",
    "inject_declare_intent_tool",
]


# ─── ADK-native synthetic tool ────────────────────────────────────────


try:  # pragma: no cover — import-shape compatibility across ADK versions
    from google.adk.tools.base_tool import BaseTool
    from google.adk.tools.tool_context import ToolContext
    from google.genai import types as genai_types

    _ADK_AVAILABLE = True
except ImportError:  # pragma: no cover
    # ADK is a required dependency, but the fallback keeps unit
    # tests importable in environments where the SDK isn't installed
    # (e.g. wheel-only CI lanes).
    BaseTool = object  # type: ignore[assignment,misc]
    ToolContext = object  # type: ignore[assignment,misc]
    genai_types = None  # type: ignore[assignment]
    _ADK_AVAILABLE = False


class WatchlightDeclareIntentTool(BaseTool):  # type: ignore[misc]
    """ADK :class:`BaseTool` carrying the canonical
    ``watchlight.declare_intent`` schema.

    The tool exposes itself to the LLM via a hand-authored
    :class:`google.genai.types.FunctionDeclaration` that mirrors the
    JSON Schema in
    :data:`watchlight_core.WATCHLIGHT_DECLARE_INTENT_TOOL`. The
    declaration carries:

    * ``name = "watchlight.declare_intent"`` (canonical wire literal).
    * The full description string from the contract.
    * Exactly one required parameter: ``objective: str`` capped at
      :data:`watchlight_core.INTENT_OBJECTIVE_MAX_BYTES` bytes.

    When the LLM invokes the tool, ``run_async`` delegates to the
    plugin's intent-state surface via
    :func:`watchlight_core.handle_declare_intent_call`. The plugin
    instance is the "handle" — it carries the mirror attributes
    (``_intent_objective`` / ``_intent_provenance``) the helper
    mutates and that ``before_tool_callback`` reads when auto-injecting
    ``intent={"objective": ...}`` into the APDP ``/authorize`` request
    body.

    The plugin is passed in at construction so a single tool instance
    is bound to a single plugin; reusing the same instance across
    plugins would create cross-talk on the declared-intent state.
    """

    def __init__(self, plugin: Any) -> None:
        if not _ADK_AVAILABLE:
            raise RuntimeError(
                "WatchlightDeclareIntentTool requires google-adk to be "
                "installed. Install with `pip install google-adk`."
            )
        super().__init__(
            name=DECLARE_INTENT_TOOL_NAME,
            description=DECLARE_INTENT_TOOL_DESCRIPTION,
        )
        # Bound plugin — provides the ``_intent_objective`` /
        # ``_intent_provenance`` mirror state that
        # ``handle_declare_intent_call`` mutates. We hold a strong
        # reference because the tool's lifetime is bounded by the
        # plugin's lifetime: when the plugin goes away, the tool goes
        # with it.
        self._plugin = plugin

    def _get_declaration(self) -> Optional[Any]:
        """Return the FunctionDeclaration ADK advertises to the LLM.

        Hand-authored from the canonical
        :data:`watchlight_core.WATCHLIGHT_DECLARE_INTENT_TOOL`
        schema so the cross-plugin contract is byte-identical: any
        framework that imports the same schema renders the same
        declaration shape to its LLM provider.
        """
        if genai_types is None:  # pragma: no cover
            return None
        schema = WATCHLIGHT_DECLARE_INTENT_TOOL["parameters"]
        objective_schema = schema["properties"]["objective"]
        category_schema = schema["properties"]["category"]
        justification_schema = schema["properties"]["justification"]
        return genai_types.FunctionDeclaration(
            name=DECLARE_INTENT_TOOL_NAME,
            description=DECLARE_INTENT_TOOL_DESCRIPTION,
            parameters=genai_types.Schema(
                type=genai_types.Type.OBJECT,
                properties={
                    "objective": genai_types.Schema(
                        type=genai_types.Type.STRING,
                        description=objective_schema["description"],
                        max_length=objective_schema["maxLength"],
                    ),
                    # wl-apdp requires a category on every intent: a listed
                    # name or ``custom:<name>``.
                    "category": genai_types.Schema(
                        type=genai_types.Type.STRING,
                        description=category_schema["description"],
                        pattern=category_schema["pattern"],
                    ),
                    # Optional: some categories are refused without one.
                    "justification": genai_types.Schema(
                        type=genai_types.Type.STRING,
                        description=justification_schema["description"],
                        max_length=justification_schema["maxLength"],
                    ),
                },
                required=list(schema["required"]),
            ),
        )

    async def run_async(
        self,
        *,
        args: dict,
        tool_context: Any = None,  # noqa: ARG002 — kept for ADK signature
    ) -> dict:
        """Process the LLM's invocation by stamping declared intent
        onto the bound plugin.

        Delegates to :func:`watchlight_core.handle_declare_intent_call`
        with the plugin as the handle. The helper mutates the
        plugin's ``_intent_objective`` + ``_intent_provenance``
        attributes; the plugin's :meth:`before_tool_callback` reads
        them on the next non-synthetic tool call and auto-injects
        ``intent={"objective": <stored>}`` into the APDP
        ``/authorize`` request body.

        Returns the canonical synthetic-tool response:
        ``{"status": "intent_declared", "objective": "<truncated>"}``
        on success; ``{"status": "rejected", "reason": "..."}`` on
        empty / invalid input. The agent sees the response and can
        retry with a corrected objective.

        Note: this method MUST NOT round-trip to APDP ``/authorize``
        — the declare-intent carve-out. The plugin's ``before_tool_callback``
        also short-circuits to skip the authorize call before reaching
        this method. The short-circuit + the carve-out are
        complementary: even if ADK invoked ``run_async`` directly
        (bypassing ``before_tool_callback``), the response would be
        the canonical declare-intent shape and the plugin's intent
        state would still be mutated.
        """
        return handle_declare_intent_call(self._plugin, args or {})


# ─── Tool-list injection ──────────────────────────────────────────────


def inject_declare_intent_tool(
    agent: Any,
    plugin: Any,
) -> bool:
    """Add the synthetic ``watchlight.declare_intent`` tool to an
    ADK agent's ``tools`` list.

    Idempotent: if a tool with the canonical name is already on the
    agent (e.g. because ``before_agent_callback`` ran on a previous
    turn for the same agent instance), this is a no-op and returns
    ``False``.

    Args:
        agent: The ADK agent to mutate. Expected to expose a mutable
            ``tools`` list (the canonical attribute on
            ``google.adk.agents.LlmAgent``). Agents without a ``tools``
            attribute are skipped — the plugin logs and continues,
            so a custom agent class with a non-standard tool surface
            doesn't crash the run.
        plugin: The :class:`watchlight_adk.WatchlightPlugin` instance
            that will receive the declared-intent state when the tool
            is invoked. Passed to the tool's constructor so a single
            tool instance is bound to exactly one plugin.

    Returns:
        ``True`` if the tool was newly added; ``False`` if it was
        already present or the agent shape is unsupported.

    Failure mode: best-effort. An exception during inspection or
    mutation is caught, logged, and surfaced as ``False``. A failing
    injection means the agent runs WITHOUT the synthetic tool — in
    greenfield mode the Cedar gate will FORBID the agent's first
    Custodial action, which is the correct fail-closed behaviour:
    operator sees the deny in the dashboard and investigates rather
    than the agent silently proceeding.
    """
    if agent is None:
        return False
    try:
        tools = getattr(agent, "tools", None)
        if tools is None:
            logger.debug(
                "watchlight_adk: agent has no 'tools' attribute; "
                "skipping synthetic tool injection"
            )
            return False
        if not isinstance(tools, list):
            # Some ADK agent subclasses may expose a tuple or other
            # collection. We don't attempt mutation in that case;
            # the operator's agent definition is unusual and should
            # be reviewed.
            logger.debug(
                "watchlight_adk: agent.tools is not a list (%s); "
                "skipping synthetic tool injection",
                type(tools).__name__,
            )
            return False

        # Idempotency check — look for any existing tool whose name
        # matches the canonical wire literal. Cover the common cases:
        # ``BaseTool`` with a ``.name`` attribute, and dict-shaped
        # tool entries (defensive).
        for existing in tools:
            existing_name = _tool_name(existing)
            if is_declare_intent_tool_name(existing_name):
                logger.debug(
                    "watchlight_adk: synthetic declare_intent tool already "
                    "present on agent; not re-injecting"
                )
                return False

        synthetic = WatchlightDeclareIntentTool(plugin)
        tools.append(synthetic)
        logger.info(
            "watchlight_adk: injected synthetic %s tool into agent",
            DECLARE_INTENT_TOOL_NAME,
        )
        return True
    except Exception as exc:  # noqa: BLE001 — injection is best-effort
        logger.warning(
            "watchlight_adk: synthetic tool injection failed (%s); "
            "agent will run without the declare_intent surface",
            exc,
            exc_info=True,
        )
        return False


def _tool_name(tool: Any) -> Optional[str]:
    """Best-effort extraction of a tool's canonical name."""
    if tool is None:
        return None
    name = getattr(tool, "name", None)
    if isinstance(name, str) and name:
        return name
    if isinstance(tool, dict):
        candidate = tool.get("name")
        if isinstance(candidate, str) and candidate:
            return candidate
    return None
