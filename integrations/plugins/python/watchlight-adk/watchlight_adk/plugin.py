"""WatchlightPlugin — governance plugin for Google Agent Development Kit.

Registers on an ADK Runner and intercepts every agent invocation,
tool call, and LLM request to enforce Cedar policies via WL-APDP
and track execution lineage.

Usage:
    from watchlight_adk import WatchlightPlugin
    from google.adk.runners import Runner

    plugin = WatchlightPlugin(
        apdp_url="http://localhost:8081",
        agent_slug="agent-my-orchestrator",
        root_agent_name="my_orchestrator",       # the root ADK agent.name
        subagent_slugs={"researcher": "agent-my-researcher"},
    )
    runner = Runner(agent=my_agent, plugins=[plugin])
"""

import asyncio
import contextvars
import time
import uuid
from typing import Any, Dict, List, Mapping, Optional, Set, Tuple

from google.adk.agents.callback_context import CallbackContext
from google.adk.models.llm_response import LlmResponse
from google.adk.plugins.base_plugin import BasePlugin
from google.adk.tools.base_tool import BaseTool
from google.genai import types

from watchlight_core import (
    ApdpClient,
    AuthorizeResult,
    HostedTool,
    HostedToolGateResult,
    HostedToolTurn,
    authorize_hosted_request,
    hosted_tool_observation,
    application_id_from_env,
    resolve_application_id,
    DECLARE_INTENT_RESPONSE_STATUS,
    GovernanceTelemetry,
    GovernanceUnavailable,
    IntentProvenance,
    get_logger,
    handle_declare_intent_call,
    is_declare_intent_tool_name,
    resolve_intent_enforcement_mode,
    should_inject_synthetic_tool,
    summarize_arg_keys,
    require_manifest,
    wire_intent,
    trust_from_resolved,
)
from watchlight_core.backend import RunRef, SessionInfo, egress_binding_for

from .actions import resolve_action
from .agent_slugs import configured_slug, normalize_subagent_slugs
from .intent import extract_intent_from_callback_context
from .lineage import LineageEmitter, _execution_id
from .nested_runs import nested_run_refusal
from . import run_backstop
from .plan_parser import PLAN_PROMPT_ADDENDUM, governance_mode, parse_planning_block
from .redaction import redacted_arg_metadata
from .registry_client import RegistryClient
from .synthetic_intent_tool import inject_declare_intent_tool

logger = get_logger("watchlight_adk")

#: Resource name a local code executor is authorized under, every model
#: turn (``Tool::"code_executor"``).
CODE_EXECUTOR_TOOL = "code_executor"

#: Resource name ADK's data-file preprocessing (a local code executor with
#: ``optimize_data_file=True``) is authorized under when the agent starts.
DATA_FILE_PREPROCESSING_TOOL = "optimize_data_file"

#: wl-registry's cap on ``tools[].description`` (``POST
#: /api/v1/agents/{id}/tools``, the inventory report, validates it
#: server-side). A longer
#: docstring is truncated here rather than rejecting the whole batch.
_TOOL_DESCRIPTION_MAX_CHARS = 2000


#: The refusal for a call made outside any open Watchlight run. Opaque:
#: it states the outcome, not the internal state that caused it.
_PLUGIN_MISSING_REFUSAL = (
    "ACTION BLOCKED: this agent was set up under Watchlight AI Agent Runtime "
    "Governance, but the Watchlight plugin is not registered on the runner "
    "running it now, so its model turn is refused. Register the Watchlight "
    "plugin on this runner (or build a fresh agent object for ungoverned use)."
)
_NO_RUN_REFUSAL = (
    "ACTION BLOCKED: Watchlight AI Agent Runtime Governance denied this "
    "request. Tell the user: 'This action was denied by Watchlight AI "
    "Agent Runtime Governance.'"
)

#: A tool call that would run an agent the plugin cannot reach.
_BACKSTOP_REFUSAL = (
    "Refused by Watchlight: the run cannot be governed because the nested-run "
    "backstop is not in place."
)
_NESTED_RUN_REFUSAL = (
    "ACTION BLOCKED: Watchlight AI Agent Runtime Governance refused this "
    "tool because it would run an agent that Watchlight cannot govern. Tell "
    "the user: 'This action was denied by Watchlight AI Agent Runtime "
    "Governance.'"
)

#: A live invocation (``Runner.run_live``), refused before it connects.
_LIVE_REFUSAL = (
    "Request refused by Watchlight AI Agent Runtime Governance: live "
    "(streaming) sessions, including RunConfig(support_cfc=True), are not "
    "governed yet, so this session was not started. Use run_async without "
    "support_cfc, or contact an operator."
)

#: A root run refused because governance is unavailable (no session, or
#: a configured CONNECT route that could not be put in place).
_GOVERNANCE_UNAVAILABLE_REFUSAL = (
    "Request refused by Watchlight AI Agent Runtime Governance: governance "
    "is unavailable for this run, so the agent was not started. Tell the "
    "user to try again later or contact an operator."
)


def _is_llm_agent(value: Any) -> bool:
    """``value`` is an ADK ``LlmAgent``: its sub-agents start only through
    a transfer (workflow agents start theirs themselves)."""
    try:
        from google.adk.agents import LlmAgent
    except ImportError:  # pragma: no cover — google-adk is a dependency
        return False
    return isinstance(value, LlmAgent)


#: ``_session_transfer`` could not read the session (a real ADK context).
_UNKNOWN = object()


def _session_transfer(
    context: Any, invocation_id: Optional[str], branch: Optional[str]
) -> Any:
    """``(author, target, event_id, time, index)`` of the session's latest
    event in this invocation and branch when it carries
    ``actions.transfer_to_agent`` (``index``: its position in the
    session's events);
    ``None`` when it does not (or there is no ADK session, for a host
    driving callbacks directly); :data:`_UNKNOWN` when a real ADK
    callback context's session cannot be read."""
    try:
        from google.adk.agents.readonly_context import ReadonlyContext
    except ImportError:  # pragma: no cover — google-adk is a dependency
        ReadonlyContext = None  # type: ignore[assignment]
    real = ReadonlyContext is not None and isinstance(context, ReadonlyContext)
    try:
        session = getattr(context, "session", None)
        events = getattr(session, "events", None)
        if not isinstance(events, list):
            return _UNKNOWN if real else None
        for index in range(len(events) - 1, -1, -1):
            event = events[index]
            if invocation_id is not None and getattr(event, "invocation_id", None) != invocation_id:
                continue
            if (getattr(event, "branch", None) or None) != branch:
                continue
            target = getattr(getattr(event, "actions", None), "transfer_to_agent", None)
            if isinstance(target, str) and target:
                return (
                    getattr(event, "author", None),
                    target,
                    getattr(event, "id", None),
                    _event_time(event),
                    index,
                )
            return None
        return None
    except Exception:  # noqa: BLE001 — unreadable: uncertain
        return _UNKNOWN if real else None


def _session_events(context: Any) -> Optional[List[Any]]:
    """The ADK session's events for a callback context, or ``None``."""
    try:
        events = getattr(getattr(context, "session", None), "events", None)
    except Exception:  # noqa: BLE001
        return None
    return events if isinstance(events, list) else None


def _adk_now() -> float:
    """ADK's own clock (``google.adk.platform.time``, which an app may
    replace and which stamps ``Event.timestamp``), else wall time."""
    try:
        from google.adk.platform import time as platform_time

        return float(platform_time.get_time())
    except Exception:  # noqa: BLE001 — older or missing hook
        return time.time()


def _event_time(event: Any) -> float:
    """An ADK event's creation time (``Event.timestamp``, seconds), or
    +inf when it has none: an untimed record is never treated as stale."""
    value = getattr(event, "timestamp", None)
    return float(value) if isinstance(value, (int, float)) else float("inf")


def _branch_of(context: Any) -> Optional[str]:
    """ADK's branch for a callback or invocation context, or ``None``."""
    invocation_context = getattr(context, "_invocation_context", None) or context
    value = getattr(invocation_context, "branch", None)
    return value if isinstance(value, str) and value else None


def _is_adk_agent(value: Any) -> bool:
    """``value`` is a real ADK agent (an agent tree node)."""
    try:
        from google.adk.agents import BaseAgent
    except ImportError:  # pragma: no cover — google-adk is a dependency
        return False
    return isinstance(value, BaseAgent)


#: The decision a refusal in ``_before_tool`` records for its lineage
#: event, when it is not a plain Deny (Quarantine; the synthetic
#: declare_intent answer, which is an Allow). Set per tool call by
#: ``before_tool_callback``; a refusal that records nothing is a Deny.
_TOOL_DECISION: contextvars.ContextVar[Optional[List[str]]] = contextvars.ContextVar(
    "watchlight_adk_tool_decision", default=None
)


def _record_tool_decision(decision: str) -> None:
    holder = _TOOL_DECISION.get()
    if holder is not None:
        holder.append(decision)


def _tool_call_key(context: Any) -> Any:
    """One tool call's key: its function-call id, else the tool context
    object ADK passes to every callback of that call (held only until the
    call's ``after_tool_callback``)."""
    call_id = _function_call_id_of(context)
    return call_id if call_id is not None else ("context", id(context))


def _function_call_id_of(context: Any) -> Optional[str]:
    """The id of the function call a ``ToolContext`` belongs to, or
    ``None``."""
    value = getattr(context, "function_call_id", None)
    return value if isinstance(value, str) and value else None


def _is_live(context: Any) -> bool:
    """A callback or invocation context belongs to a live invocation: its
    invocation context carries a live request queue (``run_live``), or its
    run config sets ``support_cfc``. With ``support_cfc``, ``run_async``
    opens a live model connection from inside the model call, after
    ``before_model_callback`` has passed and with a request built afresh,
    and the live flow then runs model turns no model callback sees; the
    live request queue is set only at that point."""
    invocation_context = getattr(context, "_invocation_context", None) or context
    if getattr(invocation_context, "live_request_queue", None) is not None:
        return True
    run_config = getattr(invocation_context, "run_config", None)
    return getattr(run_config, "support_cfc", False) is not False


def _invocation_id_of(context: Any) -> Optional[str]:
    """The ADK invocation id a callback or invocation context belongs to,
    or ``None`` when the context carries none. ``CallbackContext`` and
    ``InvocationContext`` both expose ``invocation_id``."""
    value = getattr(context, "invocation_id", None)
    return value if isinstance(value, str) and value else None

class _Frame:
    """One governed agent run: the root agent's, or one sub-agent's.

    Every identity a callback acts under is read from the frame of its
    OWN agent, held by ``WatchlightPlugin._frame_var`` in that agent's
    context. ADK runs each agent's callbacks, and each of its tool
    calls, in tasks copied from the context ``before_agent_callback``
    ran in, so the frame set there is the one all of them see. Two
    ``AgentTool`` calls of one agent run in parallel tasks; each nested
    agent sets its own frame in its own task, so neither ever sees the
    other's. A frame never changes owner: it is closed, never popped
    into another agent's identity.
    """

    def __init__(
        self,
        *,
        state: "_RunState",
        parent: Optional["_Frame"],
        invocation_id: Optional[str],
    ) -> None:
        self.state = state
        self.parent = parent
        self.invocation_id = invocation_id
        self.closed = False
        # Function-call ids of this agent's allowed tool calls between
        # ``before_tool_callback`` and their after/error hook. A runner
        # starting while one is in flight is that tool's nested
        # (``AgentTool``) runner.
        self.tools_in_flight: Set[str] = set()
        #: Tool calls (by :func:`_tool_call_key`) already recorded in
        #: lineage: a refusal, or an allowed call whose tool raised. ADK
        #: still runs ``after_tool_callback`` for them, which must then
        #: record nothing.
        self.tools_recorded: Set[Any] = set()
        # A sub-agent's governed spawn: the key, the child run handle and
        # the single-child SubagentRegistry it was spawned through (under
        # its parent's handle, never a sibling's). None for the root.
        self.child_key: Optional[str] = None
        self.child_handle: Optional[Any] = None
        self.child_registry: Optional[Any] = None
        # The ADK agent object this frame runs, and every object its
        # sub-agents name as ``parent_agent`` (ADK 2.x runs a CLONE of an
        # LlmAgent root, whose sub-agents still point at the original).
        # Matched by identity, so two agents that share a name never bind
        # to each other's frame.
        self.agent: Any = None
        self.parent_aliases: List[Any] = []
        # ADK's branch (``ParallelAgent`` branches differ; a transfer
        # target inherits its transferor's branch).
        self.branch: Optional[str] = None
        # Model turns of this agent (one per ``before_model_callback``),
        # and the transfer targets ADK was asked for in a turn: read from
        # ``tool_context.actions.transfer_to_agent`` after each tool, any
        # tool. The target that starts next in this invocation and branch
        # is spawned under THIS frame; a turn that named more than one
        # distinct target is ambiguous and its target is refused.
        self.turn: int = 0
        self.transfer_turn: Optional[int] = None
        self.transfer_targets: Set[str] = set()
        # A local code executor authorized for the current model turn;
        # the final re-check after every other callback re-checks the
        # request.
        self.turn_authorized_builtins: Set[str] = set()
        # The hosted-tool gate's state for the current model turn: one
        # ``HostedToolTurn`` (its allows cover the final re-check) bound
        # to one gate handle, and the hosted tools the turn allowed (for
        # lineage when the response shows one ran). Sealed when the
        # response arrives.
        self.hosted_turn: Optional[HostedToolTurn] = None
        self.hosted_handle: Any = None
        self.hosted_tools: Tuple[HostedTool, ...] = ()

        # Every identifier inside Watchlight is a UUID. The framework
        # gives us a slug; it is resolved to a UUID once in
        # ``before_agent_callback`` via /agents/resolve and the UUID is
        # used for every later call. ``_current_agent_slug`` is for logs.
        self._current_agent_id: str = ""
        self._current_agent_slug: str = "unknown"
        self._current_agent_name: Optional[str] = None
        self._current_execution_id: str = ""
        self._current_parent_execution_id: Optional[str] = None
        # The agent run's reference (its credentials stay in the
        # governance backend): the root's from ``create_session``, a
        # sub-agent's from its governed spawn.
        self._current_run: Optional[RunRef] = None
        self._action_count: int = 0
        self._denied_count: int = 0
        self._start_time: float = 0
        # Plan governance (the root's ExecutionSession).
        self._session_id: Optional[str] = None
        self._manifest: Optional[dict] = None
        self._plan: Optional[list] = None
        self._plan_decision: Optional[str] = None
        # Declared intent (the synthetic ``watchlight.declare_intent`` tool).
        self._intent_objective: Optional[str] = None
        # The declared category, in wl-apdp's wire form (a listed name or
        # ``{"custom": name}``); wl-apdp requires it on every intent.
        self._intent_category: Optional[Any] = None
        # The declared justification (optional), carried with the intent.
        self._intent_justification: Optional[str] = None
        self._intent_provenance: Optional[IntentProvenance] = None

    @property
    def _current_invocation_id(self) -> Optional[str]:
        return self.invocation_id

    @_current_invocation_id.setter
    def _current_invocation_id(self, value: Optional[str]) -> None:
        self.invocation_id = value

    def is_open(self) -> bool:
        return (
            not self.closed
            and bool(self._current_execution_id and self._current_agent_id)
        )

    def depth(self) -> int:
        depth, frame = 0, self.parent
        while frame is not None:
            depth, frame = depth + 1, frame.parent
        return depth

    def is_parent_object(self, candidate: Any) -> bool:
        return candidate is not None and (
            candidate is self.agent
            or any(candidate is alias for alias in self.parent_aliases)
        )


class _RunState:
    """What one governed run's agents share: the root handle,
    the ADK invocations that belong to the run, and every open frame by
    invocation. Identity is never read from here; it lives in each
    agent's own :class:`_Frame`.

    A plugin instance is shared by every run of its Runner (ADK's API
    server caches one Runner per app), so this lives in a ContextVar
    (``WatchlightPlugin._run_var``), created by ``before_run_callback``
    in the run's own context before any await. An ``AgentTool``'s
    nested runner joins the run whose tool call started it.
    """

    def __init__(self) -> None:
        self.invocations: Set[str] = set()
        self.open_invocations: Set[str] = set()
        # ADK invocation id -> the open frames opened in it, in opening
        # order. Within one invocation frames nest strictly (a root and
        # the sub-agents it transferred to); parallel AgentTool calls each
        # get an invocation of their own.
        self.frames_by_invocation: Dict[Optional[str], List[_Frame]] = {}
        # (invocation, branch) -> (author, target) of the latest event that
        # carried ``actions.transfer_to_agent``: what ADK acted on, recorded
        # by ``on_event_callback`` before the target starts.
        self.transfer_events: Dict[
            Tuple[Optional[str], Optional[str]],
            Tuple[Optional[str], str, Optional[str], float, Optional[int]],
        ] = {}
        # (invocation, branch) -> where the session stood (number of
        # events) and ADK's clock when an agent last started there. A
        # transfer record counts only if its event came after: by session
        # position, or by ADK's clock when the event is not in the session.
        self.last_start_index: Dict[Tuple[Optional[str], Optional[str]], Optional[int]] = {}
        self.last_start: Dict[Tuple[Optional[str], Optional[str]], float] = {}
        # The root slot: taken synchronously when the root agent starts.
        self.root_reserved: bool = False
        self._root_execution_id: str = ""
        self._root_handle: Optional[Any] = None
        self._root_run_handle_id: Optional[str] = None
        self.default_subagent_scope: Dict[str, Any] = {}
        # One terminal event per execution, and the error hook
        # that first saw a failure in each execution.
        self._closed_executions: Set[str] = set()
        self._frame_error_hooks: Dict[str, str] = {}

    def open_frames(self) -> List[_Frame]:
        return [
            frame
            for frames in self.frames_by_invocation.values()
            for frame in frames
            if not frame.closed
        ]

    def has_open_frame(self) -> bool:
        return bool(self.open_frames())

    def last_open_frame(self, invocation_id: Optional[str]) -> Optional[_Frame]:
        for frame in reversed(self.frames_by_invocation.get(invocation_id, [])):
            if not frame.closed:
                return frame
        return None


#: Per-agent state: properties over the current context's :class:`_Frame`.
_FRAME_ATTRS = (
    "_current_agent_id",
    "_current_agent_slug",
    "_current_agent_name",
    "_current_execution_id",
    "_current_parent_execution_id",
    "_current_run",
    "_current_invocation_id",
    "_action_count",
    "_denied_count",
    "_start_time",
    "_session_id",
    "_manifest",
    "_plan",
    "_plan_decision",
    "_intent_objective",
    "_intent_category",
    "_intent_justification",
    "_intent_provenance",
)

#: Per-run state: properties over the current context's :class:`_RunState`.
_STATE_ATTRS = (
    "_root_execution_id",
    "_root_handle",
    "_root_run_handle_id",
    "_closed_executions",
    "_frame_error_hooks",
)

#: Everything per run or per agent: none of it may live on the instance.
_RUN_STATE_ATTRS = _FRAME_ATTRS + _STATE_ATTRS


def _frame_attr(name: str) -> property:
    def _get(self: "WatchlightPlugin") -> Any:
        frame = self._frame_var.get()
        if frame is None:
            # Outside any agent run: the fresh default, never another's.
            return getattr(_Frame(state=_RunState(), parent=None, invocation_id=None), name)
        return getattr(frame, name)

    def _set(self: "WatchlightPlugin", value: Any) -> None:
        setattr(self._writable_frame(), name, value)

    return property(_get, _set, doc=f"Per-agent state ``{name}`` (see _Frame).")


def _state_attr(name: str) -> property:
    def _get(self: "WatchlightPlugin") -> Any:
        state = self._run_var.get()
        if state is None:
            return getattr(_RunState(), name)
        return getattr(state, name)

    def _set(self: "WatchlightPlugin", value: Any) -> None:
        setattr(self._writable_run_state(), name, value)

    return property(_get, _set, doc=f"Per-run state ``{name}`` (see _RunState).")


def _tool_name(tool: Any) -> str:
    """Return the name the plugin governs a declared tool under.

    ``agent.tools`` on a real :class:`google.adk.agents.LlmAgent` holds
    whatever the host declared: ``BaseTool`` instances or the plain
    callables ADK wraps into ``FunctionTool`` only at request time. The
    precedence is ADK's own (``google.adk.tools._function_tool_declarations
    .get_callable_name``, which names the wrapper): a ``BaseTool`` is
    governed under its ``.name``; any other callable under its
    ``__name__``, else its class name (a callable instance). A stray
    ``.name`` attribute on a plain function is ignored, exactly as ADK
    ignores it, so the governed name is always the name ADK dispatches
    the tool under and the ``Tool::"<name>"`` resource it is authorized
    as. There is no ``str(tool)`` fallback: a function repr is never a
    tool name.
    """
    if isinstance(tool, BaseTool):
        return tool.name
    fn_name = getattr(tool, "__name__", None)
    if isinstance(fn_name, str) and fn_name:
        return fn_name
    return type(tool).__name__


def _deny_answer(reason: str) -> Dict[str, Any]:
    return {"decision": "Deny", "reason": reason, "details": {}}


def _checked_answer(answer: Any) -> Dict[str, Any]:
    """The backend's authorize answer, or a Deny when it is not one.

    The plugin calls ``apdp.authorize`` itself (ADK has no run handle), so
    it reads the answer here, failing closed: anything but an object whose
    ``decision`` is a string, whose ``details`` (when present) is an object
    and which carries no ``error`` is a Deny. wl-apdp never sends ``error``
    alongside a decision, so an Allow that carries one contradicts itself.
    """
    if not isinstance(answer, dict):
        return _deny_answer("governance backend returned no decision object")
    if not isinstance(answer.get("decision"), str):
        return _deny_answer("governance backend returned no decision")
    if answer.get("error") is not None:
        return _deny_answer("governance backend answer carries an error")
    details = answer.get("details", {})
    if details is None:
        details = {}
    if not isinstance(details, dict):
        return _deny_answer("governance backend returned malformed details")
    reason = answer.get("reason", "")
    checked = dict(answer)
    checked["details"] = details
    checked["reason"] = reason if isinstance(reason, str) else ""
    return checked


#: The lineage capture hook for a hosted tool a model response shows ran.
_HOSTED_TOOL_HOOK = "hosted_tool_observed"

#: The lineage ``decision`` of a hosted tool a model response shows ran
#: although the turn did not authorize it. Never ``Allow``: the dashboard
#: and exec-graph treat any decision other than ``Allow`` as not allowed.
HOSTED_TOOL_NOT_AUTHORIZED = "NotAuthorized"

#: Gemini search tools report the same grounding evidence.
_SEARCH_KIND = "google_search"
_SEARCH_FAMILY = frozenset({"google_search", "enterprise_web_search", "google_search_retrieval"})

#: ``types.ToolType`` (a Gemini ``tool_call`` part) -> hosted tool kind.
_TOOL_TYPE_KINDS = {
    "GOOGLE_SEARCH_WEB": _SEARCH_KIND,
    "GOOGLE_SEARCH_IMAGE": _SEARCH_KIND,
    "URL_CONTEXT": "url_context",
    "GOOGLE_MAPS": "google_maps",
    "FILE_SEARCH": "file_search",
}


def _hosted_kinds_used(llm_response: Any) -> Set[str]:
    """The hosted tool kinds a Gemini response shows ran: code execution
    parts, ``tool_call`` parts, and search, maps and retrieval grounding."""
    used: Set[str] = set()
    content = getattr(llm_response, "content", None)
    for part in getattr(content, "parts", None) or []:
        if getattr(part, "executable_code", None) is not None or getattr(
            part, "code_execution_result", None
        ) is not None:
            used.add("code_execution")
        tool_call = getattr(part, "tool_call", None)
        tool_type = getattr(getattr(tool_call, "tool_type", None), "value", None)
        if isinstance(tool_type, str) and tool_type in _TOOL_TYPE_KINDS:
            used.add(_TOOL_TYPE_KINDS[tool_type])
    grounding = getattr(llm_response, "grounding_metadata", None)
    if grounding is not None:
        if getattr(grounding, "web_search_queries", None) or getattr(
            grounding, "search_entry_point", None
        ):
            used.add(_SEARCH_KIND)
        if getattr(grounding, "google_maps_widget_context_token", None):
            used.add("google_maps")
        if getattr(grounding, "retrieval_queries", None) or getattr(
            grounding, "retrieval_metadata", None
        ):
            used.add("retrieval")
    return used


class _HostedToolGateHandle:
    """The run handle the shared hosted-tool gate authorizes through.

    ADK authorizes with lifecycle callbacks, not a
    ``watchlight_core.BaseRunHandle``: this answers the gate's
    ``authorize_action_detailed`` through the plugin's own fail-closed
    authorize, under the turn's agent, execution and run credential (and
    an active sub-agent's ``run_handle_id``), as every other decision of
    the turn is made. Anything but Allow is a deny with its reason.
    """

    def __init__(
        self,
        plugin: "WatchlightPlugin",
        *,
        agent_id: str,
        active_handle: Optional[Any],
        execution_id: str,
        run: Optional[Any],
    ) -> None:
        self._plugin = plugin
        self._agent_id = agent_id
        self._active_handle = active_handle
        self._execution_id = execution_id
        self._run = run

    async def authorize_action_detailed(
        self, action: str, resource: str, *, context: Optional[Dict[str, Any]] = None, **_: Any
    ) -> AuthorizeResult:
        plugin = self._plugin
        merged: Dict[str, Any] = {"tenant_id": plugin.tenant_id, **(context or {})}
        if self._active_handle is not None:
            merged["run_handle_id"] = self._active_handle.run_handle_id
        answer = await plugin._authorize_checked(
            principal=f'Agent::"{self._agent_id}"',
            action=action,
            resource=resource,
            context=merged,
            execution_id=self._execution_id,
            run=self._run,
        )
        plugin._action_count += 1
        if answer.get("decision") == "Allow":
            return AuthorizeResult("allow")
        return AuthorizeResult("deny", reason=str(answer.get("reason") or ""))


class WatchlightPlugin(BasePlugin, GovernanceTelemetry):
    """Watchlight AI governance plugin for Google ADK.

    One instance may serve any number of concurrent runs: all per-run
    state is held per run context (:class:`_RunState`), never on the
    instance.

    Enforces Cedar policies, checks agent trust state, and emits
    execution lineage events — all transparently via ADK's plugin hooks.

    Action verbs are resolved per tool call using convention-based defaults
    (get_* -> read, execute_* -> execute, search_* -> search, etc.) with
    explicit overrides via action_map. This ensures correct composition with
    Beacon's intent validation, delegation scoping, and Cedar policies.

    Args:
        apdp_url: WL-APDP endpoint (e.g., "http://localhost:8081").
            All communication flows through APDP — policy evaluation,
            event publishing, and trust checks. No direct NATS needed.
        agent_slug: REQUIRED. The registered Watchlight slug of the ROOT
            agent this plugin governs. Explicit configuration — a
            governed identity is never derived from an ADK agent's
            display name, at any level of configuration. Mirrors
            ``watchlight_deepagents``' ``agent_slug=``.
        root_agent_name: REQUIRED alongside ``agent_slug``. The ADK
            ``agent.name`` that ``agent_slug`` belongs to, so the slug is
            bound to an identity rather than to whichever agent happens
            to open an invocation.
        subagent_slugs: ADK ``agent.name`` → registered Watchlight slug,
            for every other agent in the tree. Mirrors
            ``watchlight_deepagents``' ``subagent_slugs=``. The plugin is
            always STRICT: an ADK agent with no mapping is refused as a
            deployment configuration error (see
            :mod:`watchlight_adk.agent_slugs`).
        (There is no fail-open option. An unreachable wl-apdp is always
        a Deny: the tool call or model turn is refused.)
        log_decisions: Log Allow/Deny decisions to stdout
        tenant_id: Multi-tenant scope identifier
        action_map: Explicit tool-name-to-action overrides. Keys are tool
            function names, values are Cedar action verbs (e.g.,
            {"get_market_data": "read", "execute_trade": "execute"}).
            Takes precedence over convention-based resolution.
        apdp_api_key: Optional API key for APDP authentication. When set,
            all requests to APDP include an Authorization: Bearer header.
            Required when APDP has AUTH_REQUIRE_AUTH=true.
        registry_url: Optional WL-Registry URL. When set, the plugin reports
            the agent's tools to the registry inventory on agent start. The
            report is inventory only and grants the agent nothing.
        registry_api_key: API key for WL-Registry authentication.
        intent_enforcement_mode: Operator opt-in for greenfield
            intent enforcement. When ``"greenfield"`` (or env
            ``WATCHLIGHT_INTENT_ENFORCEMENT_MODE=greenfield``), the
            plugin injects the synthetic
            ``watchlight.declare_intent`` tool into the agent's tool
            list and routes calls to it via the
            ``handle_declare_intent_call`` helper without
            round-tripping to APDP. Brownfield (the default) leaves
            the agent's tools untouched. Operators opt into greenfield
            deliberately; the default is brownfield.
        registered_mcp_servers: Remote MCP servers a model call may
            enable, as ``{server_url: name}``. Each model turn authorizes
            every provider-hosted tool on the request (Gemini built-ins,
            ``mcp_servers``, a context cache) before the model is called;
            a remote MCP server not listed here refuses the turn.
    """

    #: Invariant 19: every provider-hosted tool on a model call is
    #: authorized before the call (``watchlight_core.hosted_tools``).
    supports_hosted_tools = True
    hosted_tool_provider = "gemini"

    for _name in _FRAME_ATTRS:
        locals()[_name] = _frame_attr(_name)
    for _name in _STATE_ATTRS:
        locals()[_name] = _state_attr(_name)
    del _name

    def __init__(
        self,
        apdp_url: str = "http://localhost:8081",
        log_decisions: bool = True,
        tenant_id: Optional[str] = None,
        action_map: Optional[dict[str, str]] = None,
        apdp_api_key: Optional[str] = None,
        registry_url: Optional[str] = None,
        registry_api_key: str = "",
        otlp_exporter: Optional[Any] = None,
        connect_proxy_url: Optional[str] = None,
        intent_enforcement_mode: Optional[str] = None,
        application_id: Optional[str] = None,
        agent_slug: Optional[str] = None,
        root_agent_name: Optional[str] = None,
        subagent_slugs: Optional[dict[str, str]] = None,
        child_intent_category: Optional[str] = None,
        registered_mcp_servers: Optional[Mapping[str, str]] = None,
    ):
        super().__init__(name="watchlight_agent_runtime_governance")
        # Remote MCP servers a model call may enable (Gemini
        # ``mcp_servers``): server URL -> the name policy sees as
        # ``Resource::"mcp://<name>/"``. A server not listed refuses the
        # model turn before any decision; a malformed registry refuses
        # every turn.
        self.registered_mcp_servers: Optional[Mapping[str, str]] = registered_mcp_servers
        # The intent category declared for a native ADK sub-agent spawn
        # (``None``: the parent's own derived category, else
        # ``DEFAULT_PLUGIN_CHILD_INTENT_CATEGORY``). The objective is the
        # sub-agent's ADK ``description``. wl-apdp refuses a category
        # outside the parent run's intent bounds.
        self.child_intent_category: Optional[str] = child_intent_category
        # GOVERNED IDENTITY IS CONFIGURATION. The Watchlight slug the
        # plugin resolves at run start comes from here — never from the
        # ADK agent object's display name, at any level of
        # configuration. There is no derivation fallback and no opt-in
        # switch to bring one back: a name-derived slug that happens to
        # resolve hands the run another registered agent's UUID, trust
        # state, session, tool allowlist, policies and lineage
        # attribution, which is execution under someone else's identity
        # rather than the fail-closed refusal it replaced. See
        # :mod:`watchlight_adk.agent_slugs` for the lookup contract.
        self.agent_slug = (agent_slug or "").strip() or None
        self.root_agent_name = (root_agent_name or "").strip() or None
        if not self.agent_slug:
            raise ValueError(
                "WatchlightPlugin requires an explicit governed identity. Pass "
                "agent_slug='<registered-slug>' (the ROOT agent's registered "
                "Watchlight slug) and root_agent_name='<the root ADK "
                "agent.name>', plus subagent_slugs={'<adk agent.name>': "
                "'<registered-slug>'} for every other agent in the tree. The "
                "slug is never derived from an ADK agent's display name: a "
                "derived slug that resolves would run the agent under another "
                "registered agent's identity, trust state and policies."
            )
        if not self.root_agent_name:
            raise ValueError(
                "WatchlightPlugin requires root_agent_name='<the root ADK "
                f"agent.name>' alongside agent_slug='{self.agent_slug}', so "
                "the slug is bound to one agent identity rather than to "
                "whichever agent happens to open an invocation. Without it, an "
                "agent missing from subagent_slugs that becomes the root of a "
                "run would authorize as the root instead of being refused."
            )
        self.subagent_slugs = normalize_subagent_slugs(
            subagent_slugs, agent_slug=self.agent_slug
        )
        # Authentication precedence for the ApdpClient (mirrors the
        # other Watchlight framework plugins):
        #   1. An explicit ``apdp_api_key=`` kwarg (legacy / tests) wins.
        #   2. Otherwise, if a unified credential is present in the
        #      environment (``WATCHLIGHT_PLUGIN_TOKEN`` + the kind-specific
        #      claims), load it via ``Credential.from_env()`` so the client
        #      emits ``Authorization: Bearer`` and ``X-Wl-Credential-Kind``
        #      (no tenant header) — the headers wl-apdp's pepper-gated
        #      ``routed_auth_middleware`` requires once a credential pepper
        #      is loaded.
        #   3. Otherwise fall back to the unauthenticated client (local /
        #      dev stacks where wl-apdp runs without a pepper).
        #
        # Fail-soft on (2): a missing/malformed env credential must not
        # crash construction — we degrade to the unauthenticated path so
        # pepper-less local stacks still run. The server is the authority;
        # if it requires a credential it will 401.
        credential = None
        if apdp_api_key is None:
            try:
                from watchlight_core import Credential, CredentialNotFound

                try:
                    credential = Credential.from_default()
                except CredentialNotFound:
                    credential = None
                except Exception:  # noqa: BLE001 — malformed env → unauth
                    credential = None
            except ImportError:
                credential = None

        if credential is not None:
            self.apdp = ApdpClient(apdp_url, credential=credential)
        else:
            self.apdp = ApdpClient(apdp_url, api_key=apdp_api_key)
        # wl-proxy CONNECT mode. ADK uses its own HTTP client(s) under the
        # hood; the local sidecar's HTTPS_PROXY route works as long
        # as the underlying library honors the env var (requests,
        # urllib3, httpx all do). Zero customer agent-code touches.
        # Env fallback: WATCHLIGHT_PROXY_URL.
        import os as _os
        self.connect_proxy_url = connect_proxy_url or _os.getenv(
            "WATCHLIGHT_PROXY_URL"
        )
        # AI application attribution. The application every
        # root run opened by this plugin belongs to; forwarded on
        # session create so wl-apdp binds it to the run credential.
        # ADK opens the run from ``before_agent_callback`` (no
        # ``start_run``), so this constructor kwarg is the entry point.
        # Explicit configuration only — never inferred from prompts or
        # agent names. Env fallback: ``WATCHLIGHT_APPLICATION_ID``.
        # ``None`` / empty / whitespace ⇒ unset, the field is not sent.
        # A non-UUID raises ``ValueError`` here (client-side format
        # check only — wl-apdp stays the authority on membership).
        self.application_id = (
            resolve_application_id(application_id) or application_id_from_env()
        )
        # Optional OTLP exporter — opt-in customer observability.
        # Lineage emission to APDP is always-on; OTLP is the deliberate
        # subset/transformation customers wire to their OTel collector.
        # The same `WatchlightOtlpExporter` instance can be shared across
        # multiple plugins to keep the OTel SDK initialization cost
        # one-shot per process.
        self.otlp = otlp_exporter
        self.lineage = LineageEmitter(self.apdp, otlp_exporter=otlp_exporter)
        # No agent runs outside Watchlight while a governed run is live.
        run_backstop.install()
        self.log_decisions = log_decisions
        self.tenant_id = tenant_id
        self.action_map = action_map
        self.registry = RegistryClient(registry_url, api_key=registry_api_key) if registry_url else None

        # Per-run state lives in a _RunState held per run context, never
        # on the instance (see _RunState). The ContextVar is per instance,
        # so two plugin instances in one context never share a run.
        self._run_var: contextvars.ContextVar[Optional[_RunState]] = (
            contextvars.ContextVar(f"watchlight_adk_run_{id(self):x}", default=None)
        )
        # The current agent's frame, set by its ``before_agent_callback``
        # in that agent's own context (see _Frame).
        self._frame_var: contextvars.ContextVar[Optional[_Frame]] = (
            contextvars.ContextVar(f"watchlight_adk_frame_{id(self):x}", default=None)
        )
        self._initialized = False
        # ADK session id -> sub-agent names whose spawn was refused in that
        # session. They stay refused; see ``_record_spawn_refusal``.
        # Keyed by the ADK session, so it is shared across runs on purpose.
        self._refused_subagents: Dict[str, Set[str]] = {}

        # Public — host applications (e.g. the Streamlit demo) read these
        # after a run to render governance UI. They mirror the captured
        # state above with extra context the host needs:
        #   last_governance_mode  — "strong" (plan submitted) | "degraded"
        #                            (no plan, action-time PEP only)
        #   last_session_id       — the APDP session this run used
        #   last_manifest         — the constraint manifest fetched at run start
        #   last_plan_validation  — full APDP submit_plan response or None
        #   last_proposed_plan    — the plan parsed from the LLM (pre-validation)
        #   last_actions_allowed  — count of allowed tool calls this run
        #   last_actions_denied   — count of denied tool calls this run
        # All five reset on each before_agent_callback. Kept on the plugin
        # instance (not in callback_context state) because Streamlit's
        # session lifecycle and ADK's InvocationContext don't share state.
        # They are a display snapshot only: governance never reads them.
        # With concurrent runs they show whichever run wrote last; a host
        # that renders per-run cards needs one plugin per session.
        self.last_governance_mode: str = "unknown"
        self.last_session_id: Optional[str] = None
        self.last_manifest: Optional[dict] = None
        self.last_plan_validation: Optional[dict] = None
        self.last_proposed_plan: Optional[list[dict]] = None
        self.last_actions_allowed: int = 0
        self.last_actions_denied: int = 0

        # Kill-signal registry. Defaults ON: in-process cancellation
        # is free until an interceptor registers a request, whereas
        # leaving it unwired makes the quarantine path a SILENT no-op.
        # Proxy-side hard-kill escalation stays opt-in — assign a
        # registry built with ``httpx_hard_kill_escalator`` to enable
        # it. Set to ``None`` to disable interruption entirely.
        from watchlight_core import default_kill_signal_registry

        self.kill_signal_registry = default_kill_signal_registry()

        # Intent-enforcement mode resolution. Reads the
        # constructor kwarg first, then the
        # ``WATCHLIGHT_INTENT_ENFORCEMENT_MODE`` env var, then falls
        # back to the locked "brownfield" default. Resolved ONCE at
        # construction so the synthetic-tool decision is stable across
        # the plugin's lifetime — operators don't get to flip modes
        # mid-run.
        self.intent_enforcement_mode = resolve_intent_enforcement_mode(
            explicit=intent_enforcement_mode
        )
        # Last: a plugin manager holding this instance is governed.
        run_backstop.register(self)

    # ─── Per-run and per-agent state lookup ───────────────────
    #
    # A host must not interleave two runners' generators in ONE task
    # (manually stepping two ``run_async`` iterators from the same
    # coroutine): both runs would then share that task's context. Run
    # concurrent runs as separate tasks (``asyncio.gather``, one request
    # handler per session), as ADK's own servers do.

    def _writable_run_state(self) -> _RunState:
        """The current context's run state, created when there is none
        (only for a host or test that drives callbacks without a Runner;
        plugin code writes only from admitted callbacks)."""
        state = self._run_var.get()
        if state is None:
            state = _RunState()
            self._run_var.set(state)
        return state

    def _writable_frame(self) -> _Frame:
        """The current context's agent frame, created when there is none
        (same caveat as :meth:`_writable_run_state`)."""
        frame = self._frame_var.get()
        if frame is None:
            frame = _Frame(
                state=self._writable_run_state(), parent=None, invocation_id=None
            )
            self._frame_var.set(frame)
        return frame

    def _begin_run(self, invocation_id: Optional[str]) -> _RunState:
        """Open a run in this context, or, for a runner started from an
        agent's in-flight tool call (``AgentTool``), join that agent's
        run. Synchronous: no await between the read and the write."""
        caller = self._frame_var.get()
        if caller is not None and caller.is_open() and caller.tools_in_flight:
            state = caller.state
        else:
            previous = self._run_var.get()
            if previous is not None and previous.has_open_frame():
                logger.warning(
                    "[RUN] a run left open in this context (no after_run) is "
                    "abandoned; the new run gets its own state"
                )
            state = _RunState()
            self._frame_var.set(None)
        self._run_var.set(state)
        if invocation_id is not None:
            state.invocations.add(invocation_id)
            state.open_invocations.add(invocation_id)
        return state

    def _enter(self, context: Any) -> Optional[_Frame]:
        """The open frame a callback acts under, or ``None`` (fail
        closed): no frame in this context, a closed one, or a callback
        naming an ADK invocation that is not its frame's. The caller then
        refuses locally: nothing is sent to wl-apdp, nothing published."""
        frame = self._frame_var.get()
        if frame is None or frame.closed:
            return None
        invocation_id = _invocation_id_of(context)
        if (
            invocation_id is not None
            and frame.invocation_id is not None
            and invocation_id != frame.invocation_id
        ):
            logger.warning(
                "[REFUSE] callback for an ADK invocation that is not its "
                "agent's; refused"
            )
            return None
        return frame

    def _enter_run(self, context: Any) -> Optional[_RunState]:
        """The run a run-level hook (``after_run`` / ``on_run_error``)
        belongs to, or ``None`` when its invocation is not this context's
        run."""
        state = self._run_var.get()
        if state is None:
            return None
        invocation_id = _invocation_id_of(context)
        if (
            invocation_id is not None
            and state.invocations
            and invocation_id not in state.invocations
        ):
            logger.warning(
                "[REFUSE] run hook for an ADK invocation that is not this "
                "context's run; refused"
            )
            return None
        return state

    def _admit_agent(
        self, agent: Any, context: Any
    ) -> Tuple[Optional[_RunState], Optional[_Frame], bool, bool]:
        """Resolve, synchronously, the run and the parent frame of an agent
        starting now: ``(state, parent, admitted, via_transfer)``.
        ``parent`` ``None`` with ``admitted`` means a root; ``admitted``
        ``False`` means refuse.

        Authority never widens through a transfer. The parent is
        governed by the CONTEXT the agent starts in, which ADK copies from
        whatever started it (verified on google-adk 2.5.0 and 2.10.0):

        * **A live frame of this invocation in the agent's context.** The
          agent runs nested inside that frame's agent, so that frame is its
          parent, or the agent is refused. It is accepted as:

          - a TRANSFER from it: a transfer record (the event ADK acted on,
            from ``on_event_callback`` or the session's latest event, or
            the frame's own tool-observed transfer) names this agent, and
            every such record's author is that frame's agent. A record
            naming another author, or a turn that named several targets,
            refuses the agent;
          - a WORKFLOW child: the frame is the open frame of the agent's
            tree parent, and that parent is a workflow agent (Sequential,
            Parallel, Loop, custom), not an ``LlmAgent``.

          Anything else is refused: it never falls through to another
          frame or to the tree parent's breadth.
        * **No live frame of this invocation in its context.**

          - The first agent of its invocation (the runner's root, or the
            agent an ``AgentTool`` wraps) takes the context frame (the
            caller), or none (a root).
          - Otherwise only a transfer can have started it (an ``LlmAgent``
            root's transfer target starts with no frame in its context):
            its parent is the open frame of the transfer record's single
            author, narrowed, or it is refused.

        Transfer records are single-use and bound to time: one counts only
        if its event is newer than the last agent start in the same
        invocation and branch.
        """
        invocation_id = _invocation_id_of(context)
        state = self._run_var.get()
        if state is None or (
            not state.open_invocations
            and not state.has_open_frame()
            and not state.root_reserved
        ):
            # A host driving callbacks without a Runner opens its run here.
            state = self._begin_run(invocation_id)
        elif (
            invocation_id is not None
            and state.invocations
            and invocation_id not in state.invocations
        ):
            return None, None, False, False
        if invocation_id is not None and not state.invocations:
            state.invocations.add(invocation_id)

        context_frame = self._frame_var.get()
        if context_frame is not None and (
            context_frame.closed or context_frame.state is not state
        ):
            context_frame = None

        agent_name = getattr(agent, "name", None)
        branch = _branch_of(context)
        key = (invocation_id, branch)
        events = _session_events(context)
        since_index = state.last_start_index.get(key)
        since_time = state.last_start.get(key, float("-inf"))
        state.last_start_index[key] = len(events) if events is not None else None
        state.last_start[key] = _adk_now()

        def fresh(item: Tuple[Optional[str], str, Optional[str], float, Optional[int]]) -> bool:
            """The record's event came after the last start here."""
            _, _, event_id, event_time, index = item
            if index is None and events is not None and event_id is not None:
                index = next(
                    (i for i, e in enumerate(events) if getattr(e, "id", None) == event_id),
                    None,
                )
            if index is not None and since_index is not None:
                return index >= since_index
            return event_time > since_time

        # Transfer records naming this agent, newer than the last start here.
        recorded = state.transfer_events.pop(key, None)
        tail = _session_transfer(context, invocation_id, branch)
        records = [
            item
            for item in (recorded, None if tail is _UNKNOWN else tail)
            if item is not None
            and agent_name is not None
            and item[1] == agent_name
            and fresh(item)
        ]
        authors = {item[0] for item in records}
        # Tool-observed transfers in this invocation and branch: used up by
        # this start, consumed or stale.
        tool_transferors: List[_Frame] = []
        ambiguous = False
        for frame in state.open_frames():
            if (invocation_id is None or frame.invocation_id == invocation_id) and frame.branch == branch:
                if agent_name is not None and agent_name in frame.transfer_targets:
                    tool_transferors.append(frame)
                    if len(frame.transfer_targets) > 1:
                        ambiguous = True
                elif frame._current_agent_name in authors and len(frame.transfer_targets) > 1:
                    ambiguous = True
                frame.transfer_targets = set()
                frame.transfer_turn = None

        def refuse(why: str) -> Tuple[Optional[_RunState], Optional[_Frame], bool, bool]:
            logger.warning("[REFUSE] ADK agent '%s': %s; refused", agent_name, why)
            return state, None, False, False

        live = context_frame
        if live is not None and invocation_id is not None and live.invocation_id != invocation_id:
            live = None

        if live is not None:
            # Nested inside ``live``'s agent: it is the parent, or refuse.
            # A transfer FROM the agent it runs in. Mixed evidence (records
            # by it and by another author, or another agent's tool-observed
            # transfer alongside) refuses the transfer.
            if live._current_agent_name in authors or live in tool_transferors:
                if ambiguous:
                    return refuse("its transfer named more than one target")
                if authors - {live._current_agent_name}:
                    return refuse("its transfer was also attributed to another agent")
                if tool_transferors and tool_transferors != [live]:
                    return refuse("another agent asked for this transfer")
                return state, live, True, True
            # Records naming only OTHER authors cannot make it a transfer
            # of the agent it runs in. They are ignored (ADK did not act on
            # them here), and only the strict workflow-child check below can
            # admit it: it never widens.
            tree_parent = getattr(agent, "parent_agent", None)
            if (
                _is_adk_agent(tree_parent)
                and not _is_llm_agent(tree_parent)
                and live.is_parent_object(tree_parent)
            ):
                return state, live, True, False
            if not _is_adk_agent(agent):
                # A host driving the callbacks with agents outside ADK.
                return state, live, True, False
            return refuse("it is neither a workflow child nor a transfer of the agent it runs in")

        if state.last_open_frame(invocation_id) is None:
            # The first agent of its invocation: the runner's root, or an
            # AgentTool-wrapped agent (parented to its caller).
            return state, context_frame, True, False

        # Mid-invocation with no live frame in its context: only a
        # transfer can have started it.
        if records or tool_transferors:
            if ambiguous:
                return refuse("its transfer named more than one target")
            names = set(authors) | {frame._current_agent_name for frame in tool_transferors}
            if len(names) != 1:
                return refuse("its transferor is ambiguous")
            transferor = self._innermost_open_frame(state, invocation_id, branch, next(iter(names)))
            if transferor is None:
                return refuse("its transferor is not a live governed agent")
            return state, transferor, True, True
        if not _is_adk_agent(agent):
            # A host driving the callbacks with agents outside ADK.
            return state, state.last_open_frame(invocation_id), True, False
        if tail is _UNKNOWN:
            return refuse("how it was started cannot be read")
        return refuse("it started mid-run with no parent and no transfer")

    @staticmethod
    def _innermost_open_frame(
        state: _RunState,
        invocation_id: Optional[str],
        branch: Optional[str],
        agent_name: Optional[str],
    ) -> Optional[_Frame]:
        """The most recently opened open frame of ``agent_name`` in this
        invocation and branch (the one running), or ``None``."""
        for frame in reversed(state.frames_by_invocation.get(invocation_id, [])):
            if (
                not frame.closed
                and frame.branch == branch
                and frame._current_agent_name == agent_name
            ):
                return frame
        return None

    async def _ensure_initialized(self):
        if not self._initialized:
            await self.lineage.connect()
            self._initialized = True

    def _maybe_inject_synthetic_intent_tool(self, agent: Any) -> None:
        """Inject the synthetic ``watchlight.declare_intent``
        tool into ``agent.tools`` when greenfield mode is active.

        Idempotent (the injector checks for the canonical tool name
        already on the agent) and best-effort (failures are logged but
        never raise). Called from :meth:`before_agent_callback` so the
        tool is in the agent's tool list before ADK reads it on the
        first LLM turn.

        Brownfield agents see no change — the synthetic tool gate is
        inert in brownfield (the matrix accepts inferred provenance at
        every tier), so surfacing the tool there would just confuse
        operators.

        The injection mutates ``agent.tools`` in-place rather than
        constructing a new agent — ADK agents are stateful and rebuilt
        only by the host; the plugin is a runtime governance layer and
        works against the live agent instance the host registered.
        """
        if not should_inject_synthetic_tool(self.intent_enforcement_mode):
            return
        inject_declare_intent_tool(agent, self)

    async def _report_tool_inventory(self, agent):
        """Report the agent's tools to WL-Registry as INVENTORY.

        The report lets operators see which tools the agent runs and lets an
        AI application declare them. It grants nothing: the registry stores
        it as ``reported_by = plugin`` and wl-apdp never reads it into the
        agent's capabilities. What the agent may call comes only from
        operator data (``allowed_tools``, grants, application ceilings).
        """
        if not self.registry:
            return
        try:
            agent_tools = getattr(agent, "tools", None) or []
            tools = []
            for tool in agent_tools:
                name = _tool_name(tool)
                action_verb = resolve_action(name, self.action_map)
                tool_entry = {
                    "name": name,
                    "action_verb": action_verb,
                }
                desc = getattr(tool, "description", None)
                if isinstance(desc, str) and desc:
                    # The registry caps a tool description; a docstring
                    # over the cap would reject the whole batch and leave
                    # every tool of this agent out of the inventory.
                    tool_entry["description"] = desc[:_TOOL_DESCRIPTION_MAX_CHARS]
                tools.append(tool_entry)
            if tools:
                ok = await self.registry.report_tool_inventory(
                    self._current_agent_id,
                    tools,
                    framework="google_adk",
                )
                if not ok:
                    logger.warning(
                        "Tool inventory report rejected for agent '%s' (%d tool(s)); "
                        "the registry inventory does not list them (non-blocking)",
                        self._current_agent_id,
                        len(tools),
                    )
        except Exception as e:
            logger.warning(
                "Tool inventory report failed for agent '%s' (non-blocking; the "
                "registry inventory does not list its tools): %s",
                self._current_agent_id,
                e,
            )

    # ── ADK Plugin Hooks ──────────────────────────────────────────────

    async def on_event_callback(
        self, *, invocation_context: Any = None, event: Any = None, **kwargs
    ) -> None:
        """Record a transfer ADK is acting on.

        ADK transfers on ``actions.transfer_to_agent`` however it was set
        (the built-in tool, any custom tool, an agent's own callback, or
        another plugin). The event carrying it reaches this hook before
        the target starts (verified on google-adk 2.5.0 and 2.10.0), so
        the target is admitted under the event's author, narrowed. The
        session's latest event is checked too, in case another plugin
        consumed this hook first. Never changes the event."""
        state = self._enter_run(invocation_context)
        actions = getattr(event, "actions", None)
        target = getattr(actions, "transfer_to_agent", None)
        if state is None or not isinstance(target, str) or not target:
            return None
        key = (getattr(event, "invocation_id", None) or _invocation_id_of(invocation_context),
               getattr(event, "branch", None) or None)
        state.transfer_events[key] = (
            getattr(event, "author", None),
            target,
            getattr(event, "id", None),
            _event_time(event),
            None,
        )
        return None

    async def before_run_callback(
        self, *, invocation_context: Any = None, **kwargs
    ) -> None:
        """Open this run's state in the run's own context.

        Synchronous up to the return: the run's :class:`_RunState` exists
        before any other callback of the run can await. A runner started
        from inside a tool call of a live run (``AgentTool``) joins that
        run's state instead.

        A live invocation (``Runner.run_live``) is refused here, before
        ADK opens the model connection. ADK's live flow calls
        ``llm.connect`` without ``before_model_callback`` and its receive
        path skips ``after_model_callback``, while the connection setup
        carries the agent's tools: neither the model-turn decision nor
        the hosted-tool gate could run. The returned ``Content`` ends the
        invocation (ADK's early exit) and no run is opened.
        """
        if _is_live(invocation_context):
            logger.warning(
                "[REFUSE] live invocation (run_live): live sessions are not "
                "governed yet; refused before the model connection"
            )
            return types.Content(role="model", parts=[types.Part.from_text(text=_LIVE_REFUSAL)])
        # The backstop must be in place, and this run must have started
        # through the wrapped ``Runner.run_async``; otherwise an
        # agent a tool starts could run ungoverned, so the run is refused.
        # The check is per run: another governed run being live is not
        # enough.
        if not run_backstop.intact() or not run_backstop.in_governed_run():
            logger.warning(
                "[REFUSE] run: the nested-run backstop is not in place (a wrap was replaced, "
                "or the run did not start through Runner.run_async)"
            )
            return types.Content(role="model", parts=[types.Part.from_text(text=_BACKSTOP_REFUSAL)])
        self._begin_run(_invocation_id_of(invocation_context))
        return None

    async def before_agent_callback(
        self, *, agent, callback_context: CallbackContext, **kwargs
    ):
        """Admit the agent into this context's run, resolve its parent
        frame and reserve the root slot synchronously, then run
        :meth:`_before_agent`.

        A live invocation is refused here too, before anything else: an
        agent run without ``before_run_callback`` (``agent.run_live(ctx)``
        with no Runner, or a plugin registered before Watchlight that
        answered ``before_run_callback`` first) still reaches this
        callback, and the returned ``Content`` ends the invocation before
        ADK's live flow opens the model connection.
        """
        if _is_live(callback_context):
            logger.warning(
                "[REFUSE] live invocation reached an agent: live sessions are not "
                "governed yet; refused before the model connection"
            )
            return self._refusal_response(_LIVE_REFUSAL)
        state, parent, admitted, via_transfer = self._admit_agent(agent, callback_context)
        if state is None or not admitted:
            return self._refusal_response(_NO_RUN_REFUSAL)
        is_root = parent is None
        if is_root and (not run_backstop.intact() or not run_backstop.in_governed_run()):
            # ``before_run_callback``'s refusal, enforced again here: ADK
            # 2.5.0 ignores a run-level refusal for an LlmAgent root (its
            # node runtime does not take the early exit), so the root would
            # open with the backstop not counting the run.
            logger.warning(
                "[REFUSE] root agent: the nested-run backstop is not in place (a wrap was "
                "replaced, or the run did not start through Runner.run_async)"
            )
            return self._refusal_response(_BACKSTOP_REFUSAL)
        if is_root:
            if state.root_reserved:
                # A root is already opening in this run: never a second.
                logger.warning("[REFUSE] a second root agent in one run; refused")
                return self._refusal_response(_NO_RUN_REFUSAL)
            state.root_reserved = True
        opened: List[bool] = []
        try:
            result = await self._before_agent(
                agent=agent,
                callback_context=callback_context,
                state=state,
                parent=parent,
                opened=opened,
                via_transfer=via_transfer,
            )
            if result is None and self._preprocesses_data_files(agent):
                # ADK's data-file preprocessing runs code through the
                # agent's local executor in a request processor, before
                # any model callback. Gate it here, once the agent is
                # governed, before ADK reaches that processor. A refusal
                # ends the invocation; ``after_run_callback`` closes the
                # opened frame.
                result = await self._authorize_data_file_preprocessing(agent)
            return result
        finally:
            if is_root and not opened:
                # The root was refused before it opened: free the slot.
                state.root_reserved = False

    async def _before_agent(
        self,
        *,
        agent: Any,
        callback_context: CallbackContext,
        state: _RunState,
        parent: Optional[_Frame],
        opened: List[bool],
        via_transfer: bool = False,
    ):
        """Called before every agent invocation.

        - Checks agent trust state via WL-APDP
        - Starts execution tracking
        - Emits ExecutionStarted event

        Returns types.Content to short-circuit, or None to proceed.
        """
        from google.genai import types as genai_types

        await self._ensure_initialized()

        agent_name = agent.name if hasattr(agent, "name") else str(agent)

        # ─── Which Watchlight identity is this ADK agent? ────────────────
        # CONFIGURATION, never derivation. ADK's ``agent.name`` is a
        # display name the host chose for its own orchestration; the
        # Watchlight slug is the registry key policy is written against.
        # The old code turned the former into the latter
        # (``agent.name.replace("_", "-")``), which asked
        # ``/agents/resolve`` for a slug wl-registry never mints — it
        # prefixes every slug it derives with ``agent-`` — so a correctly
        # registered agent was refused as unregistered.
        #
        # The parent frame was resolved by ``before_agent_callback`` from
        # this agent's own context, before any await. Nothing is mutated
        # until resolution passes (the fail-closed ordering below).
        is_root = parent is None

        # ─── A sub-agent never runs without a governed spawn ─────
        # (1) Its spawn was already refused in this ADK session: it stays
        #     refused, with no new spawn request.
        # (2) A mapped sub-agent opening an invocation as the run's root —
        #     ADK routes the NEXT user turn to whichever agent authored the
        #     last event, which for a refused child is the child itself.
        #     With plugin state torn down it would otherwise open its own
        #     ROOT session under its full agent-record scope, unattenuated.
        #     Only ``root_agent_name`` may open a run.
        # Both refuse before any state is touched (ADK skips
        # ``after_agent_callback`` for a short-circuited agent).
        refusal_cause: Optional[str] = None
        if self._spawn_refused_in_session(callback_context, agent_name):
            refusal_cause = "previously_refused"
        elif is_root and agent_name in self.subagent_slugs and agent_name != self.root_agent_name:
            refusal_cause = "no_governed_spawn"
        if refusal_cause is not None:
            if self.log_decisions:
                logger.warning(
                    "[SPAWN-DENIED] sub-agent '%s' refused (%s) — it is not "
                    "started (no model turn, no tool call)",
                    agent_name,
                    refusal_cause,
                )
            return genai_types.Content(
                role="model",
                parts=[genai_types.Part.from_text(
                    text=self._spawn_refusal_text(agent_name, refusal_cause)
                )],
            )

        chosen_slug = configured_slug(
            agent_name,
            agent_slug=self.agent_slug,
            subagent_slugs=self.subagent_slugs,
            root_agent_name=self.root_agent_name,
            is_root=is_root,
            governed_reentry=via_transfer,
        )
        if chosen_slug is None:
            # STRICT, always: this ADK agent has no governed identity here:
            # it is not among the configured slugs, or it is the root agent
            # re-entered without a governed transfer. There is no derivation
            # fallback: guessing a slug off ``agent.name`` would, on a hit,
            # run this agent under whatever registered agent owns that
            # spelling.
            #
            # Opaque-deny contract: the agent and its model get only the
            # fixed refusal. The operator's detail (a DEPLOYMENT error,
            # never "not registered", which would send an operator to the
            # registry for an agent that is already there) goes to the log.
            if not is_root and (via_transfer or agent_name == self.root_agent_name):
                logger.error(
                    "[REFUSE] ADK agent '%s' has no governed identity here: a "
                    "transfer target with no Watchlight slug configured, or the "
                    "root agent re-entered without a governed transfer",
                    agent_name,
                )
            else:
                logger.error(
                    "[REFUSE] ADK agent '%s' has no Watchlight slug configured "
                    "(root=%s), so it has no governed identity. Configure the "
                    "plugin with agent_slug='<registered-slug>' + "
                    "root_agent_name='%s' (root agent) or subagent_slugs="
                    "{'%s': '<registered-slug>'} (sub-agent). This is a "
                    "deployment configuration error, not a policy decision.",
                    agent_name,
                    is_root,
                    agent_name,
                    agent_name,
                )
            return self._refusal_response(_NO_RUN_REFUSAL)

        # ─── Slug → UUID bootstrap + trust — FAIL CLOSED *BEFORE* any
        #     lifecycle-state mutation ─────────────────────────────────
        # Resolve + trust MUST run before we push the lineage frame, mint
        # the execution id, or reset per-run state. ADK SKIPS
        # ``after_agent_callback`` for an agent that short-circuits from
        # ``before_agent_callback`` (it sets ``end_invocation=True`` and
        # returns before the after-callback fires). So ANY lifecycle state
        # we mutated before refusing would LEAK — a frame that is never
        # closed would keep the run looking live, and the NEXT top-level
        # run would misclassify itself as a sub-agent of it (fail-closed,
        # but a persistent availability defect). A refused agent emits no
        # ``execution_started``, so it must own NO lifecycle state at all:
        # we compute against locals and commit only once resolution passes.
        # In Watchlight's identity model the slug is a label and the UUID
        # is the canonical identifier.
        # EXACTLY ONE slug leaves the plugin: the configured one. The
        # plugin never tries a second spelling — a "did you mean" retry is
        # how an unmapped agent lands on a registered identity that is not
        # its own.
        agent_slug = chosen_slug
        resolved = await self.apdp.resolve_agent(agent_slug)
        if resolved is None:
            if self.log_decisions:
                logger.warning(
                    "[REFUSE] Agent '%s' is not registered with Watchlight "
                    "(ADK agent '%s')",
                    agent_slug,
                    agent_name,
                )
            return genai_types.Content(
                role="model",
                parts=[genai_types.Part.from_text(
                    text=(
                        f"Request refused by Watchlight AI Agent Runtime "
                        f"Governance. Agent '{agent_slug}' is "
                        f"not registered. Have an operator register the "
                        f"agent before invoking it."
                    )
                )],
            )
        agent_uuid = resolved["id"]  # canonical UUID

        # Trust state — taken from the resolver payload we already have.
        # `/agents/resolve` returns it, so a second request is redundant;
        # worse, the `GET /agents/:id` this used to call is a control-plane
        # read that a plugin's data-plane bearer is not authorized for. It
        # answered 401, the client turned that into `trusted: False`, and
        # every ADK run in a correctly-registered deployment was refused
        # with a transport error dressed up as a trust decision.
        # `trust_from_resolved` returns None only when the transport
        # carries no trust state at all (the in-process engine), and then
        # we ask the client, which answers locally.
        trust = trust_from_resolved(resolved) or await self.apdp.check_agent_trust(
            agent_uuid
        )
        if not trust["trusted"]:
            if self.log_decisions:
                logger.warning(
                    "[DENY] Agent '%s' not trusted: %s", agent_uuid, trust["reason"]
                )
            # The trust CHECK stays (it fail-closes the run), but the
            # local ``policy_decision_made`` EMIT is removed. wl-apdp is the
            # sole decision authority: it server-attests policy decisions,
            # and the ``policy_decision_made`` class is BLOCKED at
            # ``/v1/events`` ingest (a plugin-emitted one is refused). Emitting
            # it here would be a rejected, forgeable duplicate.
            # Return Content to short-circuit the agent
            return genai_types.Content(
                role="model",
                parts=[genai_types.Part.from_text(
                    text=f"Request denied by Watchlight AI Agent Runtime Governance. "
                    f"Agent '{agent_uuid}' is not trusted."
                )],
            )

        # ─── GOVERNED SPAWN — before any lifecycle-state mutation ────────
        # A native ADK sub-agent transfer is routed through wl-apdp's
        # governed ``spawn_subagent`` chokepoint (server attestation +
        # strict-subset scope attenuation). A refused spawn means the
        # child holds no server-minted run handle and no ``sst_`` of its
        # own, so it must not run at all: no model turn, no tool
        # call, no body. It is short-circuited HERE, before the commit
        # below, so it owns no lifecycle frame (ADK skips
        # ``after_agent_callback`` for a short-circuited agent) and the
        # parent's context is untouched. It never falls back to the
        # parent's credential or to none.
        spawn_handle = None
        spawn_registry = None
        if not is_root:
            spawn_handle, spawn_registry, spawn_cause = await self._request_governed_spawn(
                agent, child_uuid=agent_uuid, state=state, parent=parent
            )
            if spawn_handle is None:
                if self.log_decisions:
                    logger.warning(
                        "[SPAWN-DENIED] sub-agent '%s' spawn was refused (%s) "
                        "— the sub-agent is not started (no model turn, no "
                        "tool call)",
                        agent_name,
                        spawn_cause,
                    )
                # It stays refused for the rest of this ADK session.
                self._record_spawn_refusal(callback_context, agent_name)
                return genai_types.Content(
                    role="model",
                    parts=[genai_types.Part.from_text(
                        text=self._spawn_refusal_text(agent_name, spawn_cause)
                    )],
                )

        # ─── Resolution passed — COMMIT this agent's frame ───────────────
        # The agent gets a frame of its OWN, set in its own context: its
        # model turns, tool calls and nested runners read it, and nothing
        # it does touches its parent's or a sibling's frame. The child's
        # events carry ``parent_execution_id = parent.execution_id`` and
        # the run's root, so ``wl-execution-graph`` stitches the tree.
        frame = _Frame(
            state=state,
            parent=parent,
            invocation_id=_invocation_id_of(callback_context),
        )
        frame.agent = agent
        frame.parent_aliases = [
            getattr(sub, "parent_agent", None)
            for sub in (getattr(agent, "sub_agents", None) or [])
        ]
        frame.branch = _branch_of(callback_context)
        state.frames_by_invocation.setdefault(frame.invocation_id, []).append(frame)
        self._frame_var.set(frame)
        opened.append(True)
        self._current_parent_execution_id = (
            parent._current_execution_id if parent is not None else None
        )
        self._current_agent_slug = agent_slug
        self._current_agent_id = agent_uuid
        self._current_agent_name = agent_name
        self._current_execution_id = _execution_id()
        if not self._root_execution_id:
            self._root_execution_id = self._current_execution_id
        self._action_count = 0
        self._denied_count = 0
        self._start_time = time.monotonic()

        # Reset per-turn plan-governance state. Critical for the host
        # UI: stale state from a prior turn must never bleed into the
        # current turn's governance card. ``_reset_telemetry`` clears
        # the seven public ``last_*`` attributes contributed by the
        # ``watchlight_core.GovernanceTelemetry`` mixin; the four
        # private fields below are ADK-specific lifecycle state.
        self._session_id = None
        self._current_run = None
        self._manifest = None
        self._plan = None
        self._plan_decision = None
        # Reset declared-intent state. A new agent run must
        # start with no declaration so a stale objective from a
        # previous run can't leak into the current authorize path.
        # The agent is expected to call ``watchlight.declare_intent``
        # again as its first tool call.
        self._intent_objective = None
        self._intent_category = None
        self._intent_justification = None
        self._intent_provenance = None
        self._reset_telemetry()

        # Zero-touch intent extraction from ADK's
        # ``CallbackContext`` user content. The extractor walks the
        # documented release-historical surfaces (``user_content``,
        # ``invocation_context.user_content`` /
        # ``invocation_context.user_input`` /
        # ``invocation_context.session.events``) and returns the
        # latest user-role Content's text, truncated to the
        # canonical 256-byte cap. Returns ``None`` when no signal
        # is present — the translator stamps IntentProvenance.ABSENT
        # by omitting the field on the canonical payload.
        #
        # Precedence: customer-declared intent is not surfaced here
        # today (ADK has no ``start_run(intent_objective=...)``
        # equivalent — the plugin attaches via Runner config rather
        # than a per-run handle), so the plugin-derived lane is the
        # only producer. Future ADK-flavoured declared-intent surfaces
        # (e.g. a wrapping ``start_run`` helper) override by passing
        # an explicit provenance string to ``emit_execution_started``.
        extracted_objective = extract_intent_from_callback_context(callback_context)
        intent_provenance: Optional[str] = (
            IntentProvenance.PLUGIN_DERIVED.value
            if extracted_objective is not None
            else None
        )

        # NOTE: the ``execution_started`` emit is deferred to AFTER the
        # session opens (see below), so it carries the SERVER-minted
        # ``execution_id`` + the run's ``sst_`` credential and passes
        # wl-apdp's `/v1/events` identity-binding gate.

        # Inject the synthetic ``watchlight.declare_intent``
        # tool when the effective enforcement mode is greenfield. The
        # injection is idempotent (no-op when the tool is already on
        # the agent) so it's safe to run on every ``before_agent_callback``
        # firing (including nested sub-agent invocations on the same
        # agent instance). Brownfield agents never see the tool — the
        # brownfield Cedar matrix accepts inferred provenance at every
        # tier and the gate would be inert.
        self._maybe_inject_synthetic_intent_tool(agent)

        # Report the agent's tools to the WL-Registry inventory
        # (best-effort, non-blocking; grants nothing). MUST run AFTER
        # synthetic tool injection so the declare_intent surface is visible
        # in the operator's tool inventory too.
        await self._report_tool_inventory(agent)

        # ─── Session bootstrap: ROOT session vs GOVERNED SUB-AGENT SPAWN ──
        if not is_root:
            # Native ADK sub-agent transfer, spawned (granted) above through
            # the governed ``spawn_subagent`` chokepoint instead of opening
            # a fresh, uncorrelated, unattenuated root session. Adopt the
            # child handle's server-minted ``execution_id`` + per-child
            # ``sst_`` so this sub-agent's lineage stitches under the parent
            # and its authorizations present the child's ``run_handle_id``.
            self._adopt_spawned_subagent(agent, spawn_handle, spawn_registry)
        else:
            # ROOT run. Open the ExecutionSession + fetch the manifest,
            # then build the governed root handle + the spawn registry that
            # any nested sub-agent transfer will route through.
            #   1. Open ExecutionSession on APDP (correlates plan + actions)
            #   2. Fetch ConstraintManifest (drives ManifestDrivenToolset)
            # FAIL CLOSED: when governance is unavailable (no session, or a
            # configured CONNECT route that cannot be put in place) the
            # root agent is refused here. It gets no model turn and makes
            # no tool call; its frame is withdrawn (ADK skips
            # ``after_agent_callback`` for a short-circuited agent).
            try:
                await self._open_session_and_manifest(callback_context)
            except GovernanceUnavailable:
                self._withdraw_refused_root_frame(frame, opened)
                if self.log_decisions:
                    logger.warning(
                        "[REFUSE] root agent '%s' not started: governance is "
                        "unavailable for this run",
                        agent_name,
                    )
                return self._refusal_response(_GOVERNANCE_UNAVAILABLE_REFUSAL)

        # Emit execution started — AFTER the session opened so it carries
        # the SERVER-minted ``execution_id`` (adopted in
        # ``_open_session_and_manifest``) and rides the run's ``sst_``
        # credential, passing wl-apdp's `/v1/events` identity-binding gate.
        #
        # FRAMEWORK-SOURCED spawn-tree depth — never a literal. ADK fires
        # ``before_agent_callback`` for BOTH the root run and every nested
        # sub-agent; each frame links to its parent's, so the number of
        # ancestors IS the depth: the root ⇒ 0, a first sub-agent ⇒ 1,
        # and so on. The translator stores this
        # verbatim (wl-execution-graph reads ``payload.depth`` directly),
        # so it MUST be the real depth — the
        # old hardcoded ``depth=0`` rendered every sub-agent as
        # SUB-AGENT · DEPTH 0 on the dashboard.
        await self.lineage.emit_execution_started(
            self._current_execution_id,
            self._current_agent_id,
            depth=frame.depth(),
            intent_objective=extracted_objective,
            intent_provenance=intent_provenance,
            root_execution_id=self._root_execution_id,
            parent_execution_id=self._current_parent_execution_id,
            tenant_id=self.tenant_id,
            run=self._current_run,
        )

        if self.log_decisions:
            logger.info(
                "[START] Agent '%s' execution %s",
                self._current_agent_id,
                self._current_execution_id,
            )

        return None  # Allow agent to proceed

    async def before_tool_callback(
        self,
        *,
        tool: BaseTool,
        tool_args: dict,
        tool_context: Any = None,
        **kwargs,
    ) -> Optional[dict]:
        """Gate the tool call on this context's run, then authorize it
        (:meth:`_before_tool`). An allowed call is tracked as in flight
        until its after/error hook."""
        if not run_backstop.intact():
            # A replaced backstop wrap could let a nested agent run
            # ungoverned: no tool runs. The run-level refusal is
            # not enough, since ADK 2.5's node runtime ignores it.
            logger.warning("[REFUSE] tool call: the nested-run backstop is not in place")
            return {"result": _BACKSTOP_REFUSAL}
        state = self._enter(tool_context)
        if state is None:
            return {"result": _NO_RUN_REFUSAL}
        decision: List[str] = []
        token = _TOOL_DECISION.set(decision)
        try:
            result = await self._before_tool(
                tool=tool, tool_args=tool_args, tool_context=tool_context
            )
        finally:
            _TOOL_DECISION.reset(token)
        call_id = _function_call_id_of(tool_context)
        if result is None:
            if call_id is not None:
                state.tools_in_flight.add(call_id)
            return None
        # A refusal (or the synthetic declare_intent answer): record it now
        # with the decision it got. ADK still runs after_tool_callback for
        # it, which then records nothing for this call.
        state.tools_recorded.add(_tool_call_key(tool_context))
        await self._observe_tool(tool, tool_args, decision[-1] if decision else "Deny")
        return result

    async def _observe_tool(
        self, tool: Any, tool_args: Any, decision: Optional[str], *, outcome: Optional[str] = None
    ) -> None:
        """Record a value-free ``tool_call_observed`` with ``decision`` on
        the current frame, when one is open (a refusal with no open run
        has no execution to record it on)."""
        if not self._frame_is_open():
            return
        tool_name = tool.name if hasattr(tool, "name") else str(tool)
        await self.lineage.emit_tool_call(
            self._current_execution_id,
            self._current_agent_id,
            tool_name=tool_name,
            action=resolve_action(tool_name, self.action_map),
            decision=decision,
            # Sorted arg KEYS only (never values) — arg-shape drift feature.
            arg_key_summary=summarize_arg_keys(tool_args),
            outcome=outcome,
            root_execution_id=self._root_execution_id,
            parent_execution_id=self._current_parent_execution_id,
            tenant_id=self.tenant_id,
            run=self._current_run,
        )

    async def _before_tool(
        self,
        *,
        tool: BaseTool,
        tool_args: dict,
        tool_context: Any = None,
    ) -> Optional[dict]:
        """Called before every tool execution.

        - Plan-time preflight (when a session is open) — catches
          policy/capability issues before /authorize is consulted
        - Evaluates Cedar policy via WL-APDP /authorize
        - Returns error dict to block denied tool calls
        - Emits PolicyDecisionMade event
        """
        await self._ensure_initialized()

        tool_name = tool.name if hasattr(tool, "name") else str(tool)
        agent_id = self._current_agent_id

        # ─── No open run frame: refuse, never authorize with blanks ──────
        # Every governed call runs inside a frame ``before_agent_callback``
        # opened (an identity, an execution id, a run credential). Without
        # one the call would reach wl-apdp as ``Agent::""`` with no
        # execution and no credential: an ungoverned request. Refuse it
        # locally instead (fail closed).
        if not self._frame_is_open():
            self._denied_count += 1
            logger.warning(
                "[DENY-NO-RUN] tool '%s' called with no open Watchlight run; refused",
                tool_name,
            )
            return {"result": _NO_RUN_REFUSAL}

        # ─── A tool that would run an agent outside the plugin's reach ────
        # A Runner a tool body builds gets no Watchlight plugin and ADK has
        # no hook that reaches it, so its agent would run ungoverned; an
        # AgentTool with include_plugins=False likewise.
        nested = nested_run_refusal(tool)
        if nested is not None:
            self._denied_count += 1
            logger.warning("[DENY-NESTED] tool '%s': %s; refused", tool_name, nested)
            return {"result": _NESTED_RUN_REFUSAL}

        # ─── GOVERNED SPAWN — fail-closed gate for denied sub-agents ──────
        # When the currently-executing agent is a native ADK sub-agent
        # whose governed spawn FAILED CLOSED (server denied the scope
        # attenuation, or the spawn parent was itself denied/unknown), the
        # registry resolves its handle to ``None`` — the ungoverned-request
        # gate default. Deny EVERY tool call (including the synthetic
        # ``declare_intent``) so a sub-agent whose spawn was refused can
        # take no action. This is a tool-call deny (a dict return), NOT an
        # exception into ADK's orchestration.
        # ``before_agent_callback`` no longer starts such a
        # sub-agent; this gate is the second line, and it also refuses a
        # sub-agent whose credential is not its own.
        refused_child = self._refused_subagent_name()
        if refused_child is not None:
            self._denied_count += 1
            if self.log_decisions:
                logger.warning(
                    "[DENY-SPAWN] %s → %s: sub-agent '%s' holds no governed "
                    "run credential and may take no action",
                    agent_id,
                    tool_name,
                    refused_child,
                )
            return {"result": "ACTION BLOCKED: " + self._spawn_refusal_text(refused_child, "unavailable")}

        # ─── Synthetic ``watchlight.declare_intent`` short-circuit ──
        # Declare-intent carve-out: the synthetic tool MUST NOT round-trip
        # to APDP ``/authorize``. The greenfield Cedar gate forbids
        # Custodial actions in greenfield mode until ``provenance == "declared"``;
        # the agent's first ``declare_intent`` call would otherwise be
        # denied before it could declare. We process the call inline:
        #
        #   1. Delegate to ``handle_declare_intent_call`` (passing the
        #      plugin as the duck-typed handle) — this mutates the
        #      plugin's ``_intent_objective`` + ``_intent_provenance``
        #      mirror state.
        #   2. Return the synthetic-tool response dict; ADK's contract
        #      for ``before_tool_callback`` returning a dict is to
        #      SHORT-CIRCUIT the underlying tool's execution and surface
        #      the dict as the tool's result. The agent observes the
        #      ``intent_declared`` status and proceeds with its actual
        #      task.
        #
        # The synthetic tool's invocation is still surfaced on the
        # audit trail via the underlying ADK ``after_tool_callback``
        # emission (the lineage event), so operators see every
        # ``declare_intent`` call. Only the authorize round-trip is
        # elided — observability is unaffected.
        #
        # Predicate is case-insensitive (defends against framework
        # capitalisation normalisation) but the canonical wire
        # spelling is lowercase.
        if is_declare_intent_tool_name(tool_name):
            response = handle_declare_intent_call(self, tool_args or {})
            if self.log_decisions:
                logger.info(
                    "[INTENT-DECLARED] %s -> %s (status=%s)",
                    agent_id,
                    tool_name,
                    response.get("status"),
                )
            # Increment allowed counter — the synthetic call IS a
            # successful tool invocation from the agent's PoV, just
            # not one that round-trips to APDP. Symmetric to how a
            # plan-validated tool call is counted: it succeeded
            # without an APDP authorize hop.
            if response.get("status") == DECLARE_INTENT_RESPONSE_STATUS:
                self._action_count += 1
                _record_tool_decision("Allow")
            return response

        # Resolve action verb from tool name using convention + explicit overrides
        action_verb = resolve_action(tool_name, self.action_map)
        cedar_action = f'Action::"{action_verb}"'

        # ─── Plan-time preflight ─────────────────────────────────
        # When a plan is on file, run preflight first. It's a
        # read-only check against the manifest + intent surface and
        # gives us friendlier diagnostics than a raw /authorize Deny.
        if self._session_id and self._plan_decision in ("allow", "modify"):
            preflight = await self.apdp.preflight_step(
                run=self._current_run,
                action=action_verb,
                resource=f'Tool::"{tool_name}"',
            )
            if preflight and not preflight.get("preflight", {}).get("allowed", True):
                pf = preflight["preflight"]
                explanation = pf.get("explanation") or "preflight rejected the step"
                if self.log_decisions:
                    logger.warning(
                        "[DENY-PREFLIGHT] %s → %s: %s", agent_id, tool_name, explanation
                    )
                self._denied_count += 1
                return {
                    "result": (
                        f"ACTION BLOCKED (plan preflight): {explanation}. "
                        f"Tell the user: 'This action was blocked at plan-time by Watchlight."
                    )
                }

        # Auto-inject the declared-intent objective into the
        # APDP ``/authorize`` request body when the agent has called
        # the synthetic ``watchlight.declare_intent`` tool. Mirrors the
        # auto-inject path on :class:`watchlight_core.BaseRunHandle`:
        # APDP's Cedar context projection reads
        # ``request.intent.objective`` and stamps
        # ``provenance: "declared"`` on the evaluation context — which
        # clears the greenfield-Custodial gate. Absent declaration →
        # no field is sent and the projection treats the call as
        # ``provenance: "absent"`` (gate forbids in greenfield).
        # wl-apdp's intent is typed (objective AND category); an
        # objective-only intent is answered 422, so it is never sent.
        intent_payload: Optional[dict] = wire_intent(
            None, self._intent_objective, self._intent_category, self._intent_justification
        )

        # GOVERNED SPAWN — authorize under the ACTIVE governed handle.
        # ``_current_agent_id`` / ``_current_execution_id`` already carry
        # the child's identity when a sub-agent is executing (its own
        # frame, adopted in ``_adopt_spawned_subagent``). Present the child's
        # server-minted ``run_handle_id`` in the Cedar context so wl-apdp's
        # ``check_subagent_scope`` enforces the child's attenuated,
        # server-attested scope (an out-of-scope tool → Deny under the
        # child ``run_handle_id``). A sub-agent that presents no
        # handle is DENIED rather than falling through to the root's full
        # Cedar scope — presenting it here is what makes scope attenuation
        # real end-to-end for ADK.
        # Value-free argument metadata only: raw argument values can carry
        # credentials or personal data and never leave the process.
        authz_context: dict = {
            "tenant_id": self.tenant_id,
            "tool_arg_metadata": redacted_arg_metadata(tool_args),
        }
        active_handle = self._active_subagent_handle()
        if active_handle is not None:
            authz_context["run_handle_id"] = active_handle.run_handle_id

        # Call APDP for authorization (measure round-trip time)
        authz_start = time.monotonic()
        result = await self._authorize_checked(
            principal=f'Agent::"{agent_id}"',
            action=cedar_action,
            resource=f'Tool::"{tool_name}"',
            context=authz_context,
            execution_id=self._current_execution_id,
            intent=intent_payload,
            # The run: the backend attaches its sst_, and wl-apdp binds the
            # decision to the run, and its RunHandle, only from that
            # verified credential.
            run=self._current_run,
        )
        evaluation_ms = int((time.monotonic() - authz_start) * 1000)

        decision = result.get("decision", "Deny")
        reason = result.get("reason", "")

        # Extract determining policy name from APDP response
        details = result.get("details", {})
        determining_policy = None
        policy_results = details.get("policy_results", [])
        if not isinstance(policy_results, list):
            policy_results = []
        for pr in policy_results:
            if isinstance(pr, dict) and pr.get("applicable"):
                determining_policy = pr.get("policy_name") or pr.get("policy_id")
                break

        # An unreachable wl-apdp is a Deny like any other: there is no
        # fail-open mode.

        # Note: APDP emits PolicyDecisionMade events to NATS when it evaluates
        # /authorize — the plugin does NOT emit duplicate policy decision events.

        self._action_count += 1

        # ── Quarantine handling ─────────────────────────────────────
        # ADK doesn't use BaseRunHandle (it uses lifecycle callbacks),
        # so the SDK's automatic Quarantine → kill-signal wiring
        # doesn't apply here. We invoke the kill signal explicitly
        # when wl-apdp returns Quarantine.
        #
        # Note: ADK's ``before_tool_callback`` contract is to RETURN a
        # blocking result dict, not to raise. Raising would break ADK's
        # internal lifecycle. We surface Quarantine as a strongly-
        # worded block (so the agent can't proceed) AND fire the kill
        # signal so any in-flight LLM call from the agent's framework
        # is aborted within the interceptor's graceful window. The
        # Quarantine state lives in wl-apdp's anomaly cache — every
        # subsequent before_tool_callback round-trips and gets the
        # same Quarantine response until the operator lifts via the
        # Watchlight dashboard. This is the correct behaviour for ADK
        # because ADK callbacks have no equivalent of a long-lived
        # BaseRunHandle to short-circuit on.
        if decision == "Quarantine":
            self._denied_count += 1
            _record_tool_decision("Quarantine")
            self._fire_kill_signal_quarantine()
            if self.log_decisions:
                logger.warning(
                    "[QUARANTINE] %s → %s (%s): %s",
                    agent_id,
                    tool_name,
                    action_verb,
                    reason,
                )
            return {
                "result": (
                    "AGENT QUARANTINED: Watchlight AI Agent Runtime Governance "
                    "has quarantined this agent due to anomalous behaviour. "
                    "All subsequent actions will be blocked until an operator "
                    "lifts the quarantine via the Watchlight dashboard. "
                    "STOP all activity and inform the user that the agent "
                    "has been quarantined for review."
                )
            }

        if decision != "Allow":
            self._denied_count += 1
            if self.log_decisions:
                logger.warning(
                    "[DENY] %s → %s (%s): %s (policy: %s)",
                    agent_id, tool_name, action_verb, decision, reason,
                )
            return {
                "result": f"ACTION BLOCKED: Watchlight AI Agent Runtime Governance denied this request. "
                f"Agent '{agent_id}' does not have permission to {action_verb} '{tool_name}'. "
                f"This is a permanent policy restriction. "
                f"Do not attempt this action again. "
                f"Tell the user: 'This action was denied by Watchlight AI Agent Runtime Governance. "
                f"The {agent_id} role is not authorized to {action_verb} {tool_name}.'"
            }

        if self.log_decisions:
            logger.info("[ALLOW] %s → %s (%s)", agent_id, tool_name, action_verb)

        return None  # Allow tool execution

    async def _authorize_checked(self, **kwargs: Any) -> Dict[str, Any]:
        """``apdp.authorize``, failing closed: an exception from the
        backend, or an answer that is not a clean decision object, is a
        Deny (never an exception into ADK, never an Allow)."""
        try:
            answer = await self.apdp.authorize(**kwargs)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 — fail closed
            logger.warning(
                "governance backend authorize failed (%s); failing closed to Deny",
                type(exc).__name__,
            )
            return _deny_answer("governance backend failed; refusing the action")
        checked = _checked_answer(answer)
        if checked.get("decision") == "Deny" and not (
            isinstance(answer, dict) and answer.get("decision") == "Deny"
        ):
            # The backend did not say Deny; the answer itself was refused.
            logger.warning(
                "governance backend returned an unusable authorize answer (%s); "
                "failing closed to Deny",
                checked.get("reason"),
            )
        return checked

    # ─── Kill-signal invocation ──────────────────────────────────────

    def _fire_kill_signal_quarantine(self) -> None:
        """Fire the plugin's :class:`InterceptorKillRegistry` if wired.

        ADK uses lifecycle callbacks rather than
        :class:`watchlight_core.BaseRunHandle`, so the SDK's automatic
        Quarantine → kill-signal wiring doesn't apply. The callback
        invokes this method explicitly when wl-apdp returns Quarantine.

        Best-effort + non-blocking: the cancel coroutine is scheduled
        on the running event loop and we return immediately. Plugins
        without a wired registry (the common test-fixture case) treat
        this as a no-op.
        """
        registry = getattr(self, "kill_signal_registry", None)
        if registry is None:
            return
        import asyncio

        from watchlight_core import LLM_CALL_INTERRUPTED_REASON_QUARANTINE

        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            logger.debug(
                "ADK kill-signal fired without a running loop; "
                "cancel skipped (sync test path)"
            )
            return
        loop.create_task(registry.cancel(LLM_CALL_INTERRUPTED_REASON_QUARANTINE))

    async def after_tool_callback(
        self, *, tool: BaseTool, tool_args: dict, tool_context: Any = None, result: Any = None, **kwargs
    ) -> Optional[dict]:
        """Called after every tool execution. Emits ToolCallObserved event,
        and records a transfer the tool asked ADK for."""
        state = self._enter(tool_context)
        if state is None:
            return None
        call_id = _function_call_id_of(tool_context)
        key = _tool_call_key(tool_context)
        if key in state.tools_recorded:
            # Already in lineage: refused before it ran, or an allowed call
            # whose tool raised and was then recovered.
            state.tools_recorded.discard(key)
            state.tools_in_flight.discard(call_id)
            self._observe_transfer(state, tool_context)
            return None
        allowed = call_id is not None and call_id in state.tools_in_flight
        state.tools_in_flight.discard(call_id)
        self._observe_transfer(state, tool_context)
        # Allow only for a call before_tool_callback let through; a call
        # this plugin has no decision for is recorded without one.
        await self._observe_tool(tool, tool_args, "Allow" if allowed else None)
        return None

    async def after_model_callback(
        self,
        *,
        callback_context: CallbackContext,
        llm_response: Any = None,
        **kwargs,
    ) -> Optional[Any]:
        """Called after every LLM response. Plan governance entry point.

        Nothing happens for a callback outside this context's run.

        When the response includes a parseable plan (typically from
        `PlanReActPlanner` plus our prompt addendum), submit it to APDP
        for validation and act on the decision.

        Behaviour by `governance.plan_modify_ux` config (env override
        `WL_PLAN_MODIFY_UX`):
          * `rewrite` (default) — on Modify, splice the corrected plan
            back into the response so the agent continues with it.
          * `deny_and_replan` — on Modify, treat as Deny and let the
            agent re-plan from the violations on the next turn.

        A turn without a ``/*PLANNING*/`` block is not refused: the
        constraint manifest carries no field that requires a plan, and
        every tool call the turn makes is still authorized at action
        time. ``WATCHLIGHT_PLAN_GOVERNANCE_MODE`` only decides what
        happens when the plan pipeline itself fails: a plan submission
        that fails in transit refuses the turn (``strict``, the default)
        or continues with action-time enforcement (``degrade``, explicit
        opt-in only).
        """
        frame = self._enter(callback_context)
        if frame is None:
            return None
        await self._close_hosted_turn(frame, llm_response)
        if not self._session_id:
            # No open session: the run was refused before it started (a
            # degraded run still has its session). Nothing to govern here.
            return None

        text = self._extract_response_text(llm_response)
        if not text:
            return None

        plan = parse_planning_block(text)
        if plan is None:
            # No /*PLANNING*/ block this turn. Whether a run must plan is
            # policy, not the global mode, and the manifest has no field
            # that says so; the turn's tool calls are still authorized one
            # by one at action time.
            return None

        if not plan:
            # Empty plan — nothing to validate, nothing to do.
            return None

        # Submit the parsed plan.
        try:
            result = await self.apdp.submit_plan(self._current_run, plan)
        except asyncio.CancelledError:
            raise
        except Exception as e:  # noqa: BLE001 — handled as a failed submission
            logger.warning("plan submit raised %s", type(e).__name__)
            result = None
        if not result:
            # The plan could not be validated. Only an explicit degrade
            # opt-in continues with action-time enforcement alone.
            if governance_mode() == "degrade":
                logger.warning(
                    "plan submit failed — continuing with action-time "
                    "enforcement (WATCHLIGHT_PLAN_GOVERNANCE_MODE=degrade)"
                )
                return None
            logger.warning("[STRICT] plan submit failed — refusing this turn")
            return self._refusal_llm_response(
                "Watchlight could not validate your plan, so this turn was "
                "refused. Try again later."
            )

        validation = result.get("validation") or {}
        decision_block = validation.get("decision") or {}
        decision_kind = (
            decision_block.get("decision")
            if isinstance(decision_block, dict)
            else str(decision_block)
        )

        self._plan_decision = decision_kind
        self._plan = plan

        # Surface to the host UI. last_proposed_plan is the parsed plan
        # *before* validation; last_plan_validation is the full APDP
        # response (decision + modifications + violations + plan_hash).
        self.last_proposed_plan = plan
        self.last_plan_validation = validation

        if decision_kind == "deny":
            violations = validation.get("violations") or []
            if self.log_decisions:
                logger.warning(
                    "[PLAN-DENY] %s: %d violation(s)",
                    self._current_agent_id,
                    len(violations),
                )
            # Opaque deny: the server's violation messages stay in its
            # audit trail; the agent sees a generic refusal.
            return self._refusal_llm_response(
                "Watchlight denied your plan. "
                "Replan within your declared capabilities and try again."
            )

        if decision_kind == "modify":
            modified_plan = decision_block.get("modified_plan") or []
            modifications = decision_block.get("modifications") or []
            self._plan = modified_plan
            ux = self._modify_ux()
            if self.log_decisions:
                logger.info(
                    "[PLAN-MODIFY] %s: %d modification(s); ux=%s",
                    self._current_agent_id,
                    len(modifications),
                    ux,
                )
            if ux == "deny_and_replan":
                # Treat Modify as Deny; let the agent see violations.
                return self._refusal_llm_response(
                    "Watchlight modified your plan. Replan with these "
                    f"constraints: {modifications}"
                )
            # ux == "rewrite" — leave the LLM response untouched. The
            # corrected plan is what we'll preflight against; the agent
            # still steps through what it emitted, but our preflight
            # gate (before_tool_callback) only honours the modified
            # plan. Rewriting LlmResponse text is upstream-version
            # fragile; the safer hook is letting the gate enforce.
            return None

        if self.log_decisions:
            logger.info("[PLAN-ALLOW] %s: %d steps", self._current_agent_id, len(plan))
        return None

    async def before_model_callback(
        self, *, callback_context: CallbackContext, llm_request: Any = None, **kwargs
    ) -> Optional[Any]:
        """Called before every LLM call. Checks LLM access policy and
        injects the Watchlight plan-governance prompt addendum.

        Uses Action::"chat" with Model:: resource type, aligning with the
        Cedar schema where 'chat' applies to Model and Conversation types.
        This enables intent-aware LLM governance: only intent categories that
        allow 'chat' (CustomerSupport, ContentGeneration) permit direct LLM access.

        When a session is open, also appends the plan prompt addendum to
        the system instruction so `PlanReActPlanner` agents emit a
        machine-readable plan that `after_model_callback` can validate.
        """
        if _is_live(callback_context):
            # A live model connection is opened after this callback, from
            # a request it never sees: refused before it opens.
            logger.warning(
                "[REFUSE] live model call (support_cfc): live sessions are not "
                "governed yet; refused before the model connection"
            )
            return LlmResponse(
                content=self._refusal_response(_LIVE_REFUSAL), turn_complete=True
            )
        if not run_backstop.intact():
            # As in ``before_tool_callback``: no model turn.
            logger.warning("[REFUSE] model turn: the nested-run backstop is not in place")
            return LlmResponse(
                content=self._refusal_response(_BACKSTOP_REFUSAL), turn_complete=True
            )
        frame = self._enter(callback_context)
        if frame is None:
            # Not a turn of this context's run: refused locally.
            return self._no_run_llm_response()
        frame.turn += 1
        frame.transfer_targets = set()
        frame.transfer_turn = None
        await self._ensure_initialized()

        # Inject the plan-prompt addendum once per agent invocation when
        # we have an open session. This is a best-effort upgrade — it's
        # harmless if the agent isn't using PlanReActPlanner, and it's
        # crucial when it is.
        if self._session_id and llm_request is not None and not self._plan_decision:
            self._inject_plan_addendum(llm_request)

        agent_id = self._current_agent_id

        # No open run frame: the model turn is refused locally, never
        # authorized as ``Agent::""`` with no execution or credential.
        if not self._frame_is_open():
            self._denied_count += 1
            logger.warning(
                "[DENY-NO-RUN] model turn with no open Watchlight run; refused"
            )
            return self._no_run_llm_response()

        # GOVERNED SPAWN — a sub-agent with no server-minted handle or no
        # run credential of its own never gets a model turn. The
        # model is not called and nothing is sent to wl-apdp: authorizing
        # it with no credential (or the parent's) is exactly the
        # ungoverned request the server refuses.
        refused_child = self._refused_subagent_name()
        if refused_child is not None:
            self._denied_count += 1
            if self.log_decisions:
                logger.warning(
                    "[DENY-SPAWN] %s → gemini-chat: sub-agent '%s' holds no "
                    "governed run credential; the model turn is refused",
                    agent_id,
                    refused_child,
                )
            return self._subagent_refusal_llm_response(refused_child)

        # GOVERNED SPAWN — present the active sub-agent's ``run_handle_id``
        # so the chat authorization is evaluated under the child's
        # attenuated, server-attested scope too (mirrors the tool path).
        chat_context: dict = {"tenant_id": self.tenant_id}
        active_handle = self._active_subagent_handle()
        if active_handle is not None:
            chat_context["run_handle_id"] = active_handle.run_handle_id

        authz_start = time.monotonic()
        result = await self._authorize_checked(
            principal=f'Agent::"{agent_id}"',
            action='Action::"chat"',
            resource='Model::"gemini-chat"',
            context=chat_context,
            execution_id=self._current_execution_id,
            run=self._current_run,
        )
        evaluation_ms = int((time.monotonic() - authz_start) * 1000)

        decision = result.get("decision", "Deny")
        reason = result.get("reason", "")

        # An unreachable wl-apdp is a Deny: there is no fail-open mode.

        # Note: APDP emits PolicyDecisionMade events to NATS when it evaluates
        # /authorize — the plugin does NOT emit duplicate policy decision events.

        self._action_count += 1

        if decision != "Allow":
            self._denied_count += 1
            if self.log_decisions:
                logger.warning("[DENY] %s → gemini-chat (LLM chat): %s", agent_id, reason)
            # Fail closed, like the tool path: the model is never called
            # and the runtime surfaces the denial as the turn's response.
            return self._model_turn_denial(agent_id)

        if self.log_decisions:
            logger.info("[ALLOW] %s → gemini-chat (chat)", agent_id)

        # ─── Provider-hosted tools ───────────────────────────────────
        # Built-in tools (Google Search, code execution, URL context,
        # remote MCP servers, ...) run on Google's side inside the model
        # call and never fire ``before_tool_callback``. Each one this
        # request enables is authorized here through the shared
        # hosted-tool gate, under the same run credential, before the
        # model is called; a refusal refuses the whole model turn.
        #
        # A code executor other than ``BuiltInCodeExecutor`` runs the code
        # the model writes locally, from ADK's response processor, with no
        # tool callback: it is authorized as ``Tool::"code_executor"``
        # every turn, before the model can write any.
        frame.turn_authorized_builtins = set()
        frame.hosted_turn = HostedToolTurn()
        frame.hosted_handle = _HostedToolGateHandle(
            self,
            agent_id=agent_id,
            active_handle=active_handle,
            execution_id=self._current_execution_id,
            run=self._current_run,
        )
        frame.hosted_tools = ()
        turn_agent = frame.agent or self._agent_of(callback_context)
        denial = await self._authorize_provider_side_tools(
            frame,
            llm_request,
            active_handle,
            include_code_executor=True,
            code_executor_agent=turn_agent,
        )
        if denial is not None:
            return denial
        # Agent-level callbacks (and plugins registered after this one)
        # run after this callback and may still change the request: a
        # final agent callback re-checks it just before the model call.
        self._ensure_final_request_recheck(turn_agent)

        # Emit ApiRequestObserved so the LLM call is
        # visible in the downstream event stream. The plugin
        # extracts the model name from llm_request when available;
        # otherwise defaults to "gemini-chat" matching the
        # authorization resource above.
        model_name = self._extract_model_name(llm_request) or "gemini-chat"
        prompt_summary = self._extract_prompt_summary(llm_request)
        await self.lineage.emit_api_request(
            self._current_execution_id,
            self._current_agent_id,
            model=model_name,
            prompt_summary=prompt_summary,
            root_execution_id=self._root_execution_id,
            parent_execution_id=self._current_parent_execution_id,
            tenant_id=self.tenant_id,
            run=self._current_run,
        )

        return None

    async def on_tool_error_callback(
        self,
        *,
        tool: Any = None,
        tool_args: Any = None,
        tool_context: Any = None,
        error: Optional[BaseException] = None,
        **kwargs,
    ) -> None:
        """Record that a tool call raised in the current frame.

        No terminal event here: an agent-level ``on_tool_error_callback``
        can still recover the call (it returns a result), and the run then
        goes on and completes. The frame's close decides the ONE terminal
        event: ``execution_failed`` when the error ends the agent
        (``on_agent_error_callback`` / ``on_run_error_callback``),
        ``execution_completed`` when the run recovered."""
        state = self._enter(tool_context)
        if state is None:
            return None
        call_id = _function_call_id_of(tool_context)
        allowed = call_id is not None and call_id in state.tools_in_flight
        state.tools_in_flight.discard(call_id)
        self._note_frame_error("on_tool_error_callback", error)
        key = _tool_call_key(tool_context)
        if key not in state.tools_recorded:
            # The call ran and raised: record it with its decision and a
            # failed outcome. If a later callback recovers the call, its
            # after_tool_callback then records nothing more.
            state.tools_recorded.add(key)
            await self._observe_tool(tool, tool_args, "Allow" if allowed else None, outcome="failed")

    async def on_model_error_callback(
        self,
        *,
        callback_context: Any = None,
        error: Optional[BaseException] = None,
        **kwargs,
    ) -> None:
        """Record that a model call raised in the current frame. As for
        tools, the frame's close emits the terminal event."""
        if self._enter(callback_context) is None:
            return None
        self._note_frame_error("on_model_error_callback", error)

    def _observe_transfer(self, frame: _Frame, tool_context: Any) -> None:
        """Record the agent ADK was asked to transfer to by this tool call
        (``tool_context.actions.transfer_to_agent``, set by
        ``transfer_to_agent`` or any custom tool), for this model turn."""
        actions = getattr(tool_context, "actions", None)
        target = getattr(actions, "transfer_to_agent", None)
        if not isinstance(target, str) or not target:
            return
        if frame.transfer_turn != frame.turn:
            frame.transfer_turn = frame.turn
            frame.transfer_targets = set()
        frame.transfer_targets.add(target)

    def _note_frame_error(self, hook: str, error: Optional[BaseException]) -> None:
        if not error or not self._frame_is_open():
            return
        self._writable_run_state()._frame_error_hooks.setdefault(
            self._current_execution_id, hook
        )
        if self.log_decisions:
            logger.info(
                "[ERROR] %s in execution %s (%s)",
                hook,
                self._current_execution_id,
                type(error).__name__,
            )

    @staticmethod
    def _extract_model_name(llm_request: Any) -> Optional[str]:
        """Best-effort model name extraction from an ADK
        ``LlmRequest``. Different ADK versions expose this
        differently; we try the common attribute paths and
        return ``None`` if nothing matches (the caller falls
        back to a default)."""
        if llm_request is None:
            return None
        for attr in ("model", "model_name"):
            value = getattr(llm_request, attr, None)
            if isinstance(value, str) and value:
                return value
            # Some ADK versions nest under .config
            config = getattr(llm_request, "config", None)
            if config is not None:
                value = getattr(config, attr, None)
                if isinstance(value, str) and value:
                    return value
        return None

    @staticmethod
    def _extract_prompt_summary(llm_request: Any) -> Optional[str]:
        """Value-free prompt summary: how many entries the request
        carries (``"3 contents"``), never their text. None when the
        request shape isn't recognized — the event still emits, just
        without a prompt summary in metadata."""
        if llm_request is None:
            return None
        # Common attribute paths across ADK versions
        # Value-free: the prompt text can carry personal data or secrets,
        # so only the number of entries (or the value's type) is recorded.
        for attr in ("contents", "messages", "prompt"):
            value = getattr(llm_request, attr, None)
            if value is not None:
                if isinstance(value, (list, tuple)):
                    return f"{len(value)} {attr}"
                return f"1 {attr} ({type(value).__name__})"
        return None

    async def after_agent_callback(
        self, *, agent, callback_context: CallbackContext, **kwargs
    ):
        """Close THIS agent's frame (never another's)."""
        frame = self._enter(callback_context)
        if frame is None:
            return None
        if getattr(agent, "name", None) != frame._current_agent_name:
            logger.warning("[REFUSE] after_agent for an agent that is not its frame's")
            return None
        await self._close_frame(frame)
        return None

    async def after_run_callback(self, *, invocation_context: Any = None, **kwargs):
        """Close the frames THIS invocation left open.

        ADK does not always fire ``after_agent_callback`` for an agent
        that handed the conversation to a sub-agent: on ADK 2.x a
        ``transfer_to_agent`` ends the parent's own agent run without its
        after-callback. The runner fires ``after_run_callback`` once per
        invocation after every agent of that invocation has stopped, so a
        frame of THIS invocation still open here is closed now, innermost
        first, each under its own agent and its own credential. An
        ``AgentTool``'s nested runner has an invocation of its own, so it
        never closes the calling agent's frame.

        A transferring agent's frame therefore stays open until here (in a
        ``LoopAgent``, until the loop ends): it is the parent its transfer
        target was spawned under, and closing it earlier would complete
        that handle. Only the terminal event's timing is affected.
        """
        state = self._enter_run(invocation_context)
        if state is None:
            return None
        invocation_id = _invocation_id_of(invocation_context)
        try:
            await self._close_invocation_frames(state, invocation_id)
        finally:
            state.open_invocations.discard(invocation_id)
        return None

    async def on_agent_error_callback(
        self,
        *,
        agent: Any = None,
        callback_context: Any = None,
        error: Optional[BaseException] = None,
        **kwargs,
    ) -> None:
        """An unhandled exception escaped an agent: close THAT agent's
        frame with ``execution_failed``. ADK skips
        ``after_agent_callback`` for the failing agent and re-raises the
        error after this notification."""
        frame = self._enter(callback_context)
        if frame is None or getattr(agent, "name", None) != frame._current_agent_name:
            return None
        try:
            await self._close_frame(
                frame,
                error=error or RuntimeError("agent_error"),
                hook="on_agent_error_callback",
            )
        except Exception as exc:  # noqa: BLE001 — notification only
            logger.warning("on_agent_error_callback close failed: %s", exc)
        return None

    async def on_run_error_callback(
        self,
        *,
        invocation_context: Any = None,
        error: Optional[BaseException] = None,
        **kwargs,
    ) -> None:
        """An unhandled exception escaped the runner: every frame THIS
        invocation left open is closed with ``execution_failed`` and
        flushed. ADK re-raises the error after this
        notification."""
        state = self._enter_run(invocation_context)
        if state is None:
            return None
        invocation_id = _invocation_id_of(invocation_context)
        try:
            await self._close_invocation_frames(
                state,
                invocation_id,
                error=error or RuntimeError("run_error"),
                hook="on_run_error_callback",
            )
        except Exception as exc:  # noqa: BLE001 — notification only
            logger.warning("on_run_error_callback close failed: %s", exc)
        finally:
            state.open_invocations.discard(invocation_id)
        return None

    async def _close_invocation_frames(
        self,
        state: _RunState,
        invocation_id: Optional[str],
        error: Optional[BaseException] = None,
        hook: Optional[str] = None,
    ) -> None:
        """Close the open frames ``invocation_id`` opened, innermost
        first. Frames of other invocations are never touched."""
        for frame in list(reversed(state.frames_by_invocation.get(invocation_id, []))):
            if not frame.closed:
                await self._close_frame(frame, error=error, hook=hook)

    async def _close_frame(
        self,
        frame: _Frame,
        error: Optional[BaseException] = None,
        hook: Optional[str] = None,
    ) -> None:
        """Emit ``frame``'s terminal event, close its session, flush, and
        release it. Everything is read from ``frame`` itself, never from
        the context, so the close is right whichever task runs it.

        The frame is marked closed first (synchronously), so a second
        close of the same frame does nothing; each execution gets at most
        ONE terminal event. It is released even when the session
        close or the flush fails.
        """
        if frame.closed:
            return
        frame.closed = True
        # Per-call bookkeeping ends with the frame: nothing is left to grow,
        # and no key (a call id, or a tool context's id) carries into a
        # later run.
        frame.tools_in_flight.clear()
        frame.tools_recorded.clear()
        state = frame.state
        try:
            execution_id = frame._current_execution_id
            if execution_id and execution_id not in state._closed_executions:
                state._closed_executions.add(execution_id)
                await self._emit_terminal(frame, error, hook)
            await self._finish_frame_session(frame)
        finally:
            await self._release_frame(frame, error)

    async def _emit_terminal(
        self, frame: _Frame, error: Optional[BaseException], hook: Optional[str]
    ) -> None:
        elapsed_ms = int((time.monotonic() - frame._start_time) * 1000)
        envelope: Dict[str, Any] = dict(
            root_execution_id=frame.state._root_execution_id,
            parent_execution_id=frame._current_parent_execution_id,
            tenant_id=self.tenant_id,
            run=frame._current_run,
        )
        if error is None:
            await self.lineage.emit_execution_completed(
                frame._current_execution_id,
                frame._current_agent_id,
                duration_ms=elapsed_ms,
                actions_taken=frame._action_count,
                actions_denied=frame._denied_count,
                **envelope,
            )
        else:
            await self.lineage.emit_execution_failed(
                frame._current_execution_id,
                frame._current_agent_id,
                error=error,
                hook=frame.state._frame_error_hooks.get(frame._current_execution_id)
                or hook
                or "on_agent_error_callback",
                **envelope,
            )

    async def _finish_frame_session(self, frame: _Frame) -> None:
        """Snapshot counters, close the frame's governance session (the
        root's ExecutionSession), flush."""
        elapsed_ms = int((time.monotonic() - frame._start_time) * 1000)
        # Display snapshot for the host UI (never read by governance).
        self.last_actions_allowed = max(0, frame._action_count - frame._denied_count)
        self.last_actions_denied = frame._denied_count

        # The close carries the closed run's own credential (wl-apdp
        # refuses one without it): the frame's for its session, the root
        # handle's for the root's.
        session_to_close = frame._session_id
        run_to_close = frame._current_run
        if session_to_close is None and frame.parent is None and frame.state._root_handle is not None:
            session_to_close = getattr(frame.state._root_handle, "session_id", None)
            run_to_close = getattr(frame.state._root_handle, "run", None)
        try:
            if session_to_close:
                ok = await self.apdp.complete_session(run_to_close)
                if self.log_decisions:
                    logger.info(
                        "[SESSION] %s -> %s",
                        session_to_close,
                        "completed" if ok else "complete-failed",
                    )
                frame._session_id = None
                frame._manifest = None
                frame._plan = None
                frame._plan_decision = None
        finally:
            # Flush every buffered event, the terminal one included, even
            # when the session close failed.
            await self.lineage.flush()

        if self.log_decisions:
            logger.info(
                "[DONE] Agent '%s' completed in %dms (%d actions, %d denied)",
                frame._current_agent_id, elapsed_ms, frame._action_count, frame._denied_count,
            )

    async def _release_frame(self, frame: _Frame, error: Optional[BaseException]) -> None:
        """Drop a closed frame from its run; close a sub-agent's governed
        handle; tear the run down when the root's frame closes."""
        state = frame.state
        state._frame_error_hooks.pop(frame._current_execution_id, None)
        frames = state.frames_by_invocation.get(frame.invocation_id, [])
        if frame in frames:
            frames.remove(frame)
        if self._frame_var.get() is frame:
            # This context goes on as the parent (a host driving the
            # callbacks in one context), never as a sibling.
            parent = frame.parent
            self._frame_var.set(parent if parent is not None and not parent.closed else None)
        if frame.parent is not None:
            # GOVERNED SPAWN — suppress the child handle's defensive
            # terminal event (the plugin emitted it above) and complete the
            # child handle (closes the child session server-side).
            handle = frame.child_handle
            if handle is not None:
                try:
                    if error is None:
                        handle.mark_execution_completed_emitted()
                    else:
                        handle.mark_execution_failed_emitted()
                except Exception as exc:  # noqa: BLE001 — best-effort
                    logger.debug("sub-agent completion-suppress failed: %s", exc)
            if frame.child_registry is not None and frame.child_key is not None:
                await frame.child_registry.on_stop(frame.child_key)
        else:
            # The root closed: this run is over. Tear down its governed
            # root handle so nothing can spawn under it again.
            state.root_reserved = False
            state._root_handle = None
            state._root_run_handle_id = None
            state._root_execution_id = ""

    # ─── Governed sub-agent spawn ─────────────────────────────────────

    def _build_root_handle_and_registry(self, session_resp: SessionInfo) -> None:
        """Build the governed ROOT :class:`BaseRunHandle` + the
        :class:`SubagentRegistry` for the current run.

        Called once per root run from :meth:`_open_session_and_manifest`
        after the root session opens. The registry is the chokepoint every
        nested ADK sub-agent transfer routes its native spawn through. When
        the root session was unavailable (no ``session_id`` / ``agent_id``),
        both stay ``None`` so sub-agents fail closed.

        The ADK plugin drives lineage through its own emitter and never
        enters the handle's ``async with`` block, so we flip the handle's
        fail-closed ``_aentered`` flag (permitting ``spawn_subagent``) and
        mark ``execution_started`` already-emitted (the plugin emits it via
        the lineage emitter — the handle's defensive mint must not
        duplicate).
        """
        from watchlight_core import (
            BaseRunHandle,
            SubagentRegistry,
            default_subagent_scope_from_env,
        )

        if not (self._current_agent_id and self._session_id):
            self._root_handle = None
            self._root_run_handle_id = None
            return

        root_run_handle_id = session_resp.root_run_handle_id
        root_handle = BaseRunHandle(
            plugin=self,
            agent_uuid=self._current_agent_id,
            session_id=self._session_id,
            run=self._current_run,
            egress=egress_binding_for(self.apdp, self._current_run),
            execution_id=self._current_execution_id,
            root_execution_id=self._root_execution_id or self._current_execution_id,
            run_handle_id=root_run_handle_id,
            server_run_handle=root_run_handle_id is not None,
        )
        # The plugin never wraps the handle in ``async with``; permit
        # ``spawn_subagent`` and suppress the handle's own defensive
        # ``execution_started`` (the plugin emits it itself).
        root_handle._aentered = True
        root_handle.mark_execution_started_emitted(root_handle.execution_id)

        self._root_handle = root_handle
        self._root_run_handle_id = root_run_handle_id
        # Each sub-agent is spawned through a SubagentRegistry of its own,
        # under its direct parent's handle (see _request_governed_spawn).
        self._writable_run_state().default_subagent_scope = (
            default_subagent_scope_from_env()
        )
        # Fail fast here if the registry type is unavailable.
        assert SubagentRegistry is not None

    def _derive_subagent_allowed_tools(self, agent: Any) -> Optional[List[str]]:
        """Derive a sub-agent's requested ``allowed_tools`` from its
        DECLARED tool list (the same list :meth:`_report_tool_inventory` reads).

        Locked decision — ADK auto-derives a child's scope from what tools
        the child agent actually declares. The entries are TOOL NAMES
        (``_tool_name``: the name ADK dispatches the tool under and the
        ``Tool::"<name>"`` resource it authorizes as), not action verbs:
        wl-apdp's spawn-time strict-subset check compares each requested
        entry literally against the parent's effective ``allowed_tools``,
        which an operator sets (tool names; never the plugin's inventory
        report), and its authorize-time membership check accepts the
        resource name. The request only narrows: a child can never be
        granted a tool the parent's operator-set scope lacks. A verb such as ``search`` never appears in that
        allowlist, so requesting verbs made every live sub-agent spawn
        fail closed. Returns the de-duplicated, order-preserving list, or
        ``None`` when the tool list is unreadable/empty so the caller
        falls back to the operator ``default_subagent_scope`` (empty
        default = fail-closed: the child authorizes NO tools until
        scoped). Failures are logged loudly and never raise.
        """
        child_key = agent.name if hasattr(agent, "name") else str(agent)
        tools = getattr(agent, "tools", None)
        if not tools:
            logger.warning(
                "[SPAWN] sub-agent '%s' declares no readable tool list — "
                "falling back to the operator default sub-agent scope "
                "(empty default = fail-closed: child authorizes no tools)",
                child_key,
            )
            return None
        try:
            derived = [_tool_name(tool) for tool in tools]
        except Exception as exc:  # noqa: BLE001 — fail closed on unreadable tools
            logger.warning(
                "[SPAWN] could not read sub-agent '%s' tool list (%s) — "
                "falling back to default sub-agent scope",
                child_key,
                exc,
            )
            return None
        seen: set[str] = set()
        deduped: List[str] = []
        for action in derived:
            if action not in seen:
                seen.add(action)
                deduped.append(action)
        return deduped

    async def _request_governed_spawn(
        self,
        agent: Any,
        *,
        child_uuid: str,
        state: _RunState,
        parent: _Frame,
    ) -> Tuple[Optional[Any], Optional[Any], Optional[str]]:
        """Ask wl-apdp to spawn this native ADK sub-agent through the
        governed ``spawn_subagent`` chokepoint, under its DIRECT parent.

        Returns ``(handle, registry, None)`` with the child's server-minted
        handle and the single-child SubagentRegistry it was spawned
        through, or ``(None, None, cause)`` when the spawn was refused or
        could not be made (``cause`` is the coarse refusal class).

        The spawner is the parent frame's own handle: the root handle for
        a child of the root, the parent sub-agent's handle otherwise. A
        registry is built per spawn so its spawner is exactly that handle;
        a run-wide registry would resolve an implicit parent to whichever
        sibling spawned last, and parallel ``AgentTool`` calls would spawn
        under each other. The requested scope is the child's
        declared tools intersected with the parent's granted scope.

        Runs BEFORE ``before_agent_callback`` commits any state:
        a refused child owns no frame. Never raises into ADK.
        """
        from watchlight_core import SubagentRegistry

        child_key = agent.name if hasattr(agent, "name") else str(agent)
        root_handle = state._root_handle
        spawner = parent.child_handle if parent.parent is not None else root_handle
        if root_handle is None or spawner is None:
            logger.warning(
                "[SPAWN] no governed parent handle for sub-agent '%s' — it is "
                "refused (it holds no run credential)",
                child_key,
            )
            return None, None, "unavailable"

        registry = SubagentRegistry(
            spawner,
            dict(state.default_subagent_scope),
            child_intent_category=getattr(self, "child_intent_category", None),
        )
        requested_scope: Optional[dict] = None
        derived_tools = self._derive_subagent_allowed_tools(agent)
        if derived_tools is not None:
            # Intersect with the direct parent's server-granted scope when
            # known. The root carries no granted scope (its full
            # agent-record scope applies), so no intersection there.
            # An EMPTY grant is a grant of nothing (the child requests
            # nothing), never "unknown".
            granted = getattr(spawner, "granted_scope", None)
            parent_tools = getattr(granted, "allowed_tools", None) if granted else None
            if parent_tools is not None:
                parent_set = set(parent_tools)
                derived_tools = [a for a in derived_tools if a in parent_set]
            base = dict(registry.default_subagent_scope)
            base["allowed_tools"] = derived_tools
            requested_scope = base

        try:
            handle = await registry.on_spawn(
                child_key=child_key,
                child_slug=child_uuid,
                requested_scope=requested_scope,
                parent_key=None,
                # The child's objective is what its ADK definition says it
                # does (the parent delegates to it for exactly that).
                objective=(
                    agent.description
                    if isinstance(getattr(agent, "description", None), str)
                    else None
                ),
            )
        except Exception as exc:  # noqa: BLE001 — fail closed, never
            # raise into ADK's orchestration (transport error, malformed
            # response, bad child UUID). Server denials are already
            # converted to a ``None`` return by ``on_spawn``.
            logger.warning(
                "[SPAWN-ERROR] sub-agent '%s' spawn failed (%s) — the "
                "sub-agent is refused and will not run",
                child_key,
                type(exc).__name__,
            )
            return None, None, "unavailable"
        if handle is None:
            refusal_class = getattr(registry, "refusal_class", None)
            cause = refusal_class(child_key) if callable(refusal_class) else None
            return None, None, cause or "unavailable"
        return handle, registry, None

    def _adopt_spawned_subagent(self, agent: Any, handle: Any, registry: Any) -> None:
        """Commit a GRANTED spawn onto this agent's frame: the child's
        server-minted execution, its own ``sst_`` and its run handle, so
        every event it emits carries the child's identity and every
        authorization presents the child's ``run_handle_id``. Only ever
        called with a real handle (a refused spawn never gets here)."""
        frame = self._writable_frame()
        frame.child_key = agent.name if hasattr(agent, "name") else str(agent)
        frame.child_handle = handle
        frame.child_registry = registry
        self._current_execution_id = handle.execution_id
        self._current_parent_execution_id = handle.parent_execution_id
        self._current_run = handle.run
        if self.log_decisions:
            logger.info(
                "[SPAWN] governed sub-agent '%s' spawned exec=%s run_handle=%s",
                frame.child_key,
                handle.execution_id,
                handle.run_handle_id,
            )
        # Sub-agents never own a ``create_session`` ExecutionSession; plan
        # governance + ``complete_session`` are root-only.
        self._session_id = None

    #: Refusal class → (why, what to do). Coarse classes only: the text
    #: never repeats wl-apdp's decision detail (opaque deny), it names the
    #: rule that applies and the remedies.
    _SPAWN_REFUSAL_REASONS: Dict[str, Tuple[str, str]] = {
        "scope_attenuation": (
            "A sub-agent may only request a strict subset of its parent's "
            "granted scope, and this request is not one.",
            "narrow the tools this sub-agent declares to ones its parent "
            "holds, or ask an operator to review the parent's scope, then retry",
        ),
        "delegation_depth": (
            "The delegation tree is already at its depth limit, so this "
            "sub-agent cannot be spawned beneath its parent.",
            "run the work in an agent higher in the tree, or ask an operator "
            "to review the delegation depth limit",
        ),
        "unsatisfiable_scope": (
            "The scope this sub-agent would be granted authorizes nothing "
            "(for example a zero time budget).",
            "ask an operator to set the sub-agent scope defaults "
            "(default_subagent_scope) for this deployment",
        ),
        "parent_invalidated": (
            "Its parent's run is no longer valid.",
            "start a fresh run",
        ),
        "parent_refused": (
            "Its parent was itself refused, so nothing may run beneath it.",
            "resolve the parent's refusal first",
        ),
        "parent_unknown": (
            "Its parent is not a live governed agent.",
            "start the sub-agent from its governed parent",
        ),
        "unavailable": (
            "Watchlight could not establish a governed spawn for it "
            "(governance is unavailable for this run).",
            "check that the run's governed session opened and that "
            "Watchlight is reachable, then retry",
        ),
        "no_governed_spawn": (
            "A sub-agent runs only through a governed spawn from its parent; "
            "it cannot open a run of its own.",
            "send the request to the root agent, which delegates to this "
            "sub-agent through a governed spawn",
        ),
        "previously_refused": (
            "Its spawn was already refused in this session.",
            "start a new session once the cause is fixed",
        ),
    }

    @classmethod
    def _spawn_refusal_text(cls, agent_name: str, cause: Optional[str] = None) -> str:
        """The instructive message a refused sub-agent surfaces instead of
        running, for the refusal class ``cause`` (see
        :meth:`SubagentRegistry.refusal_class`, plus the plugin's own
        ``unavailable`` / ``no_governed_spawn`` / ``previously_refused``)."""
        why, fix = cls._SPAWN_REFUSAL_REASONS.get(
            cause or "", cls._SPAWN_REFUSAL_REASONS["unavailable"]
        )
        return (
            "Request refused by Watchlight AI Agent Runtime Governance. "
            f"Sub-agent '{agent_name}' was not started, so it holds no run "
            "credential and may take no action (no model turn, no tool "
            f"call). {why} To proceed, {fix}. Tell the user: 'This sub-agent "
            "was denied by Watchlight AI Agent Runtime Governance.'"
        )

    #: ADK session-state key listing the sub-agents refused in a session.
    _REFUSED_STATE_KEY = "watchlight_refused_subagents"
    #: Bound on the in-process refusal record (sessions tracked).
    _REFUSED_SESSIONS_MAX = 4096

    @staticmethod
    def _adk_session_id(callback_context: Any) -> Optional[str]:
        try:
            session = callback_context._invocation_context.session
            session_id = getattr(session, "id", None)
            return str(session_id) if session_id else None
        except Exception:  # noqa: BLE001 — a bare context has no session
            return None

    def _record_spawn_refusal(self, callback_context: Any, agent_name: str) -> None:
        """Remember that ``agent_name``'s spawn was refused in this ADK
        session: in the plugin (authoritative for this process) and in
        the session state (carried by the refusal event, so a persistent
        session service keeps it across processes)."""
        session_id = self._adk_session_id(callback_context)
        if session_id is not None:
            refused = self._refused_subagents.setdefault(session_id, set())
            refused.add(agent_name)
            while len(self._refused_subagents) > self._REFUSED_SESSIONS_MAX:
                self._refused_subagents.pop(next(iter(self._refused_subagents)))
        try:
            state = callback_context.state
            current = list(state.get(self._REFUSED_STATE_KEY) or [])
            if agent_name not in current:
                state[self._REFUSED_STATE_KEY] = current + [agent_name]
        except Exception as exc:  # noqa: BLE001 — the in-process record stands
            logger.debug("could not record the spawn refusal in session state: %s", exc)

    def _spawn_refused_in_session(self, callback_context: Any, agent_name: str) -> bool:
        session_id = self._adk_session_id(callback_context)
        if session_id is not None and agent_name in self._refused_subagents.get(session_id, ()):
            return True
        try:
            recorded = callback_context.state.get(self._REFUSED_STATE_KEY)
        except Exception:  # noqa: BLE001
            return False
        return isinstance(recorded, (list, tuple)) and agent_name in recorded

    def _refused_subagent_name(self) -> Optional[str]:
        """The name of the executing sub-agent when it holds no
        server-minted handle or no run credential of its own, else
        ``None``.

        ``before_agent_callback`` does not let such a sub-agent start;
        the model and tool gates re-check it so a sub-agent can
        never act on the parent's credential or with none at all.
        """
        frame = self._frame_var.get()
        if frame is None or frame.parent is None:
            return None
        handle = self._active_subagent_handle()
        if handle is None:
            return frame.child_key or frame._current_agent_name or "sub-agent"
        child_run = getattr(handle, "run", None)
        if not child_run or frame._current_run != child_run:
            return frame.child_key or frame._current_agent_name or "sub-agent"
        return None

    def _active_subagent_handle(self) -> Optional[Any]:
        """The governed handle of the sub-agent this context runs, or
        ``None``: at the root, or (for a sub-agent frame) when its spawn
        failed closed, in which case the caller MUST deny."""
        frame = self._frame_var.get()
        if frame is None or frame.parent is None:
            return None
        if frame.child_registry is None or frame.child_key is None:
            return None
        return frame.child_registry.resolve(frame.child_key)

    # ─── Plan governance helpers ──────────────────────────────────────

    def _withdraw_refused_root_frame(self, frame: "_Frame", opened: List[bool]) -> None:
        """Undo the commit of a root frame whose run was refused before it
        started, so the refused run leaves no open frame behind."""
        state = frame.state
        frame.closed = True
        frames = state.frames_by_invocation.get(frame.invocation_id, [])
        if frame in frames:
            frames.remove(frame)
        if not frames:
            state.frames_by_invocation.pop(frame.invocation_id, None)
        if self._frame_var.get() is frame:
            self._frame_var.set(None)
        state._root_handle = None
        state._root_run_handle_id = None
        state._root_execution_id = ""
        # ``before_agent_callback`` frees the root slot when nothing opened.
        opened.clear()

    async def _abandon_root_session(self) -> None:
        """Close a root session that cannot be used and clear the run's
        governance state, so the refused run holds no credential."""
        session_id = self._session_id
        run = self._current_run
        self._session_id = None
        self._current_run = None
        self._manifest = None
        self._root_handle = None
        self._root_run_handle_id = None
        self.last_governance_mode = "unavailable"
        self.last_session_id = None
        self.last_manifest = None
        if session_id:
            try:
                await self.apdp.complete_session(run)
            except Exception as e:  # noqa: BLE001 — the run is refused either way
                logger.warning(
                    "could not close the refused run's session (%s)", type(e).__name__
                )

    async def _open_session_and_manifest(self, callback_context: CallbackContext) -> None:
        """Open the root ExecutionSession and fetch the constraint manifest.

        Fail closed: when the session cannot be opened, or a wl-proxy
        CONNECT URL is configured and the CONNECT route cannot be put in
        place (no proxy token issued, or the install failed), any opened
        session is closed and :class:`GovernanceUnavailable` is raised.
        The caller refuses the run; it never proceeds ungoverned or with
        direct egress. A missing constraint manifest refuses the run the
        same way, unless the operator explicitly set
        ``WATCHLIGHT_PLAN_GOVERNANCE_MODE=degrade`` (then the run is
        "degraded": action-time enforcement only).
        """
        session_resp: Optional[SessionInfo] = None
        try:
            session_resp = await self.apdp.create_session(
                agent_id=self._current_agent_id,
                metadata={
                    "framework": "google_adk",
                    "execution_id": self._current_execution_id,
                    "tenant_id": self.tenant_id,
                },
                # AI application attribution. Only when set, so
                # an older watchlight-agent-sdk still works.
                **(
                    {"application_id": self.application_id}
                    if self.application_id is not None
                    else {}
                ),
            )
        except Exception as e:  # noqa: BLE001 — any failure refuses the run
            logger.warning("session create failed: %s", type(e).__name__)
            session_resp = None

        if isinstance(session_resp, SessionInfo):
            self._session_id = session_resp.session_id
            # Held from here on so a refusal below closes the session it
            # opened (``_abandon_root_session``).
            self._current_run = session_resp.run
        if not self._session_id:
            await self._abandon_root_session()
            raise GovernanceUnavailable(
                "the root governance session could not be opened"
            )
        assert session_resp is not None

        try:
            # Execution-lineage identity binding.
            # `/v1/events` binds each event to the run its per-run `sst_`
            # credential opened, and rejects events whose `execution_id`
            # doesn't match the run the token authenticates. So we (a)
            # keep the run reference (the backend holds its token) and
            # (b) ADOPT the SERVER-minted
            # canonical `execution_id` in place of ADK's self-minted one
            # (from `before_agent_callback`). This runs BEFORE the
            # `execution_started` emit, so every event this run emits
            # carries the server id + rides the run token.
            server_execution_id = session_resp.execution_id
            if server_execution_id:
                prior_execution_id = self._current_execution_id
                self._current_execution_id = server_execution_id
                # Keep the root pinned to the adopted id when THIS run is
                # the root (the self-minted id was provisionally stored
                # as the root in `before_agent_callback`).
                if self._root_execution_id == prior_execution_id:
                    self._root_execution_id = server_execution_id

            # The run credential bounds the manifest by the run's
            # grant. A missing manifest refuses the run (before any
            # egress is set up) unless the operator explicitly opted into
            # WATCHLIGHT_PLAN_GOVERNANCE_MODE=degrade.
            self._manifest = await self.apdp.get_manifest(
                self._current_agent_id,
                run=self._current_run,
            )
            governance_level = require_manifest(
                self._manifest, agent_id=str(self._current_agent_id)
            )

            # wl-proxy CONNECT route. A configured proxy URL is a hard
            # requirement: with no proxy token issued, or a failed
            # install, the agent would egress directly, so the run is
            # refused instead. The token is never logged.
            if self.connect_proxy_url:
                egress = egress_binding_for(self.apdp, self._current_run)
                if egress is None:
                    raise GovernanceUnavailable(
                        "a wl-proxy CONNECT URL is configured but wl-apdp "
                        "issued no proxy token for this run"
                    )
                from watchlight_core import SidecarRunActive, install_connect_proxy

                try:
                    install_connect_proxy(
                        self.connect_proxy_url,
                        egress.proxy_authorization(),
                        egress=egress,
                    )
                except SidecarRunActive:
                    raise
                except Exception as ee:  # noqa: BLE001
                    raise GovernanceUnavailable(
                        "the wl-proxy CONNECT route could not be installed "
                        f"({type(ee).__name__})"
                    ) from None

            # GOVERNED SPAWN — build the governed root run handle + the
            # sub-agent spawn registry for THIS run from the same session
            # response (root run-handle id + proxy token). Any nested ADK
            # sub-agent transfer routes its spawn through
            # ``root_handle.spawn_subagent`` so children are
            # server-attested + scope-attenuated.
            self._build_root_handle_and_registry(session_resp)
        except GovernanceUnavailable as refusal:
            logger.warning("[REFUSE] governance unavailable for this run: %s", refusal)
            await self._abandon_root_session()
            raise
        except Exception as e:  # noqa: BLE001
            logger.warning(
                "[REFUSE] the root run could not be set up (%s)", type(e).__name__
            )
            await self._abandon_root_session()
            raise GovernanceUnavailable(
                "the root governance session could not be set up"
            ) from e

        # Surface manifest on the callback context so ManifestDrivenToolset
        # can read it (best-effort — the toolset degrades gracefully if
        # this slot is empty).
        try:
            state = getattr(callback_context, "state", None)
            if state is not None and self._manifest is not None:
                gov = state.setdefault("wl_governance", {}) if hasattr(state, "setdefault") else None
                if gov is None and hasattr(state, "__setitem__"):
                    state["wl_governance"] = {"manifest": self._manifest}
                else:
                    state["wl_governance"]["manifest"] = self._manifest  # type: ignore[index]
        except Exception as e:
            logger.debug("could not stash manifest on ctx.state: %s", e)

        # The governance mode from the manifest gate:
        #   * strong   — session opened AND manifest fetched
        #   * degraded — no manifest, run only because the operator set
        #                WATCHLIGHT_PLAN_GOVERNANCE_MODE=degrade
        #                (action-time enforcement only)
        # A failed session or a missing manifest in strict mode refused
        # the run above with GovernanceUnavailable.
        mode = governance_level
        self.last_governance_mode = mode
        self.last_session_id = self._session_id
        self.last_manifest = self._manifest
        if self.log_decisions:
            logger.info(
                "[GOVERNANCE-MODE] %s — session=%s manifest=%s",
                mode,
                bool(self._session_id),
                bool(self._manifest),
            )

    @staticmethod
    def _modify_ux() -> str:
        """Read the modify-UX flag (default: rewrite)."""
        import os

        v = os.getenv("WL_PLAN_MODIFY_UX", "").strip().lower()
        return "deny_and_replan" if v == "deny_and_replan" else "rewrite"

    @staticmethod
    def _extract_response_text(llm_response: Any) -> str:
        """Best-effort extraction of the LLM's text payload.

        ADK / google-genai response shapes vary: prefer `.text`, then
        `.parts[0].text`, then string-cast.
        """
        if llm_response is None:
            return ""
        text = getattr(llm_response, "text", None)
        if isinstance(text, str) and text:
            return text
        parts = getattr(llm_response, "parts", None) or getattr(llm_response, "content", None)
        if hasattr(parts, "parts"):
            parts = parts.parts
        if isinstance(parts, list) and parts:
            joined = []
            for p in parts:
                t = getattr(p, "text", None)
                if isinstance(t, str):
                    joined.append(t)
            if joined:
                return "\n".join(joined)
        try:
            return str(llm_response)
        except Exception:
            return ""

    def _frame_is_open(self) -> bool:
        """This context's agent frame is open: the call has an agent
        identity and an execution id to be governed under."""
        frame = self._frame_var.get()
        return frame is not None and frame.is_open()

    @property
    def _lineage_stack(self) -> List[_Frame]:
        """Read-only view: the current frame's open ancestors, root
        first (diagnostics and tests)."""
        chain: List[_Frame] = []
        frame = self._frame_var.get()
        ancestor = frame.parent if frame is not None else None
        while ancestor is not None:
            chain.append(ancestor)
            ancestor = ancestor.parent
        return list(reversed(chain))

    @property
    def _subagent_stack(self) -> List[Tuple[Optional[str], Optional[Any]]]:
        """Read-only view: ``(child_key, child_handle)`` of the open
        sub-agent frames from the root's child down to the current
        frame (diagnostics and tests)."""
        chain: List[Tuple[Optional[str], Optional[Any]]] = []
        frame = self._frame_var.get()
        while frame is not None and frame.parent is not None:
            if not frame.closed:
                chain.append((frame.child_key, frame.child_handle))
            frame = frame.parent
        return list(reversed(chain))

    @staticmethod
    def _no_run_llm_response() -> LlmResponse:
        """The response that refuses a model turn outside any run."""
        from google.genai import types as genai_types

        return LlmResponse(
            content=genai_types.Content(
                role="model",
                parts=[genai_types.Part.from_text(text=_NO_RUN_REFUSAL)],
            ),
            turn_complete=True,
        )

    @staticmethod
    def _model_turn_denial(agent_id: str) -> LlmResponse:
        """The response that fails a denied model turn closed.

        ADK's ``before_model_callback`` contract: a non-``None``
        ``LlmResponse`` skips the model call and is surfaced as the
        model's response, so the denied agent produces this text and
        nothing else. Mirrors the tool path's deny dict: it names the
        agent and the outcome, never the server's reason (opaque deny).
        """
        from google.genai import types as genai_types

        return LlmResponse(
            content=genai_types.Content(
                role="model",
                parts=[
                    genai_types.Part.from_text(
                        text=(
                            "ACTION BLOCKED: Watchlight AI Agent Runtime Governance "
                            f"denied this request. Agent '{agent_id}' is not authorized "
                            "to use the model. This is a permanent policy restriction. "
                            "Tell the user: 'This action was denied by Watchlight AI "
                            "Agent Runtime Governance.'"
                        )
                    )
                ],
            ),
            turn_complete=True,
        )

    @classmethod
    def _subagent_refusal_llm_response(cls, agent_name: str) -> LlmResponse:
        """Fail a refused sub-agent's model turn closed: the model is never
        called and the instructive spawn-refusal text is the turn's only
        output."""
        from google.genai import types as genai_types

        return LlmResponse(
            content=genai_types.Content(
                role="model",
                parts=[genai_types.Part.from_text(text=cls._spawn_refusal_text(agent_name, "unavailable"))],
            ),
            turn_complete=True,
        )

    async def _authorize_provider_side_tools(
        self,
        frame: Any,
        llm_request: Any,
        active_handle: Optional[Any],
        *,
        include_code_executor: bool,
        code_executor_agent: Any = None,
    ) -> Optional[LlmResponse]:
        """Authorize every tool this model turn would run outside
        ``before_tool_callback``: the provider-hosted tools the request
        enables (through the shared gate) and, when asked, a local code
        executor. Allows already given this turn are not asked again.
        Returns the turn's denial response on the first refusal."""
        agent_id = self._current_agent_id
        if frame.hosted_turn is None or frame.hosted_turn.sealed:
            # A model call this plugin's callback did not open a turn for.
            return self._model_turn_denial(agent_id)
        request = self._hosted_request(llm_request)
        gate = (
            None
            if request is None
            else await self._gate_hosted_request(
                frame.hosted_handle,
                request,
                frame.hosted_turn,
                registered_mcp_servers=self.registered_mcp_servers,
            )
        )
        if gate is None or not gate.allowed:
            self._denied_count += 1
            if self.log_decisions:
                refused = (
                    gate.refused_tool.summary
                    if gate is not None and gate.refused_tool is not None
                    else "unreadable request"
                )
                logger.warning(
                    "[DENY] %s → provider-side tool '%s': the model turn is refused",
                    agent_id,
                    refused,
                )
            return self._model_turn_denial(agent_id)
        frame.hosted_tools = gate.tools
        if include_code_executor and self._runs_model_code_locally(code_executor_agent):
            if CODE_EXECUTOR_TOOL not in frame.turn_authorized_builtins:
                context: dict = {"tenant_id": self.tenant_id, "builtin_tool": True}
                if active_handle is not None:
                    context["run_handle_id"] = active_handle.run_handle_id
                result = await self._authorize_checked(
                    principal=f'Agent::"{agent_id}"',
                    action=f'Action::"{resolve_action(CODE_EXECUTOR_TOOL, self.action_map)}"',
                    resource=f'Tool::"{CODE_EXECUTOR_TOOL}"',
                    context=context,
                    execution_id=self._current_execution_id,
                    run=self._current_run,
                )
                self._action_count += 1
                if result.get("decision", "Deny") != "Allow":
                    self._denied_count += 1
                    if self.log_decisions:
                        logger.warning(
                            "[DENY] %s → local code executor: the model turn is refused",
                            agent_id,
                        )
                    return self._model_turn_denial(agent_id)
                frame.turn_authorized_builtins.add(CODE_EXECUTOR_TOOL)
        return None

    async def _close_hosted_turn(self, frame: Any, llm_response: Any) -> None:
        """Seal the turn's hosted-tool gate state and record each allowed
        hosted tool the response shows ran (value-free; see
        :func:`watchlight_core.hosted_tool_observation`)."""
        turn = frame.hosted_turn
        if turn is None or turn.sealed:
            return
        turn.seal()
        used = _hosted_kinds_used(llm_response)
        if not used:
            return
        for tool in frame.hosted_tools:
            kind = _SEARCH_KIND if tool.kind in _SEARCH_FAMILY else tool.kind
            if kind not in used:
                continue
            used.discard(kind)
            await self.lineage.emit(
                hook=_HOSTED_TOOL_HOOK,
                execution_id=self._current_execution_id,
                agent_id=self._current_agent_id,
                run=self._current_run,
                hosted_payload=hosted_tool_observation(
                    tool, framework="adk", decision="Allow", action_map=self.action_map
                ),
                root_execution_id=self._root_execution_id,
                parent_execution_id=self._current_parent_execution_id,
                tenant_id=self.tenant_id,
            )
        for kind in sorted(used):
            # The gate authorizes every hosted tool the request enables,
            # so this means the provider reported a tool it was not asked
            # for: say so loudly, and record it in lineage as not
            # authorized (value-free, never as an allow).
            logger.warning(
                "[HOSTED] %s: the model response shows hosted tool '%s', which this "
                "turn did not authorize",
                self._current_agent_id,
                kind,
            )
            provider = self.hosted_tool_provider
            await self.lineage.emit(
                hook=_HOSTED_TOOL_HOOK,
                execution_id=self._current_execution_id,
                agent_id=self._current_agent_id,
                run=self._current_run,
                hosted_payload=hosted_tool_observation(
                    HostedTool(provider, kind, kind, f"{provider}:{kind}"),
                    framework="adk",
                    decision=HOSTED_TOOL_NOT_AUTHORIZED,
                    action_map=self.action_map,
                ),
                root_execution_id=self._root_execution_id,
                parent_execution_id=self._current_parent_execution_id,
                tenant_id=self.tenant_id,
            )

    async def _gate_hosted_request(
        self,
        handle: Any,
        request: Dict[str, Any],
        turn: HostedToolTurn,
        *,
        registered_mcp_servers: Optional[Mapping[str, str]],
    ) -> Optional[HostedToolGateResult]:
        """The shared hosted-tool gate on ``request``. ``None`` when the
        request could not be read or the gate failed: a refusal, never an
        exception into ADK and never an Allow."""
        try:
            return await authorize_hosted_request(
                handle,
                request,
                turn,
                provider=self.hosted_tool_provider,
                registered_mcp_servers=registered_mcp_servers,
                action_map=self.action_map,
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 — fail closed
            logger.warning(
                "hosted-tool gate refused the model turn (%s)", type(exc).__name__
            )
            return None

    @staticmethod
    def _hosted_request(llm_request: Any) -> Optional[Dict[str, Any]]:
        """The part of an ADK ``LlmRequest`` that reaches the provider and
        can enable a hosted tool: its ``config``, read as Gemini (tools,
        raw callables, ``mcp_servers``, ``cached_content``,
        ``http_options.extra_body``). ADK's own context cache is built
        from this same config, so it carries no tool this gate has not
        authorized. ``None`` (the turn is refused) when there is no
        request to read: ADK never passes one, and an unreadable request
        refuses."""
        if llm_request is None:
            return None
        config = getattr(llm_request, "config", None)
        return {} if config is None else {"config": config}

    async def conformance_hosted_tool_call(self, probe: Any) -> None:
        """Invariant 19: one governed model call of ``probe.request``
        through the gate wiring every model turn uses."""
        handle = probe.wrap(
            _HostedToolGateHandle(
                self, agent_id="conformance", active_handle=None, execution_id="", run=None
            )
        )
        turn = HostedToolTurn()
        gate = await self._gate_hosted_request(
            handle, probe.request, turn, registered_mcp_servers=probe.registered_mcp_servers
        )
        if gate is None or not gate.allowed:
            return
        await probe.model_client.call(probe.request)
        turn.seal()

    @classmethod
    def conformance_hosted_tool_instance(cls) -> "WatchlightPlugin":
        """An instance for the hosted-tool conformance check (the
        constructor needs a governed identity)."""
        return cls(
            apdp_url="http://localhost",
            agent_slug="conformance-root",
            root_agent_name="conformance_root",
        )

    async def _final_request_recheck(
        self, *, callback_context: Any, llm_request: Any = None, **kwargs: Any
    ) -> Optional[LlmResponse]:
        """Last agent-level ``before_model_callback``: authorize any
        built-in tool or raw callable added to the request after this
        plugin's own callback (by an agent callback or a later plugin)."""
        if not self._registered_on(callback_context):
            # The agent object carries this re-check from an earlier
            # governed run but is now run by a runner without the plugin.
            # Fail closed, and say why.
            logger.warning(
                "[REFUSE] model turn of a Watchlight-governed agent run without "
                "the Watchlight plugin; refused"
            )
            return self._plain_llm_response(_PLUGIN_MISSING_REFUSAL)
        frame = self._enter(callback_context)
        if frame is None:
            return self._no_run_llm_response()
        if not self._frame_is_open():
            return self._no_run_llm_response()
        return await self._authorize_provider_side_tools(
            frame,
            llm_request,
            self._active_subagent_handle(),
            include_code_executor=False,
        )

    def _ensure_final_request_recheck(self, agent: Any) -> None:
        """Make :meth:`_final_request_recheck` the agent's last
        ``before_model_callback`` (idempotent; keeps the agent's own
        callbacks in their order)."""
        if agent is None or not hasattr(agent, "before_model_callback"):
            return
        current = getattr(agent, "before_model_callback", None)
        if current is None:
            callbacks: List[Any] = []
        elif isinstance(current, list):
            callbacks = list(current)
        else:
            callbacks = [current]

        def _is_ours(cb: Any) -> bool:
            return getattr(cb, "__self__", None) is self and getattr(
                cb, "__func__", None
            ) is WatchlightPlugin._final_request_recheck

        if callbacks and _is_ours(callbacks[-1]):
            return
        callbacks = [cb for cb in callbacks if not _is_ours(cb)]
        callbacks.append(self._final_request_recheck)
        try:
            agent.before_model_callback = callbacks
        except Exception as exc:  # noqa: BLE001 — the turn still ran the plugin check
            logger.warning(
                "could not install the final model-request re-check on agent "
                "(%s); tools added by later callbacks are not re-checked",
                type(exc).__name__,
            )

    def _registered_on(self, callback_context: Any) -> bool:
        """This plugin instance is registered on the runner driving
        ``callback_context``. An unknown context shape is treated as
        registered (the frame check that follows still fails closed)."""
        ctx = getattr(callback_context, "_invocation_context", None)
        manager = getattr(ctx, "plugin_manager", None) if ctx is not None else None
        plugins = getattr(manager, "plugins", None) if manager is not None else None
        if not isinstance(plugins, list):
            return True
        return any(p is self for p in plugins)

    @staticmethod
    def _plain_llm_response(message: str) -> LlmResponse:
        from google.genai import types as genai_types

        return LlmResponse(
            content=genai_types.Content(
                role="model", parts=[genai_types.Part.from_text(text=message)]
            ),
            turn_complete=True,
        )

    @staticmethod
    def _agent_of(callback_context: Any) -> Any:
        ctx = getattr(callback_context, "_invocation_context", None)
        return getattr(ctx, "agent", None) if ctx is not None else None

    @classmethod
    def _preprocesses_data_files(cls, agent: Any) -> bool:
        """The agent's local code executor has ADK's data-file
        preprocessing (``optimize_data_file``) enabled."""
        if not cls._runs_model_code_locally(agent):
            return False
        return bool(getattr(getattr(agent, "code_executor", None), "optimize_data_file", False))

    async def _authorize_data_file_preprocessing(self, agent: Any) -> Optional[Any]:
        """Authorize ``Tool::"optimize_data_file"`` for this agent; return
        the agent's refusal on anything but Allow (``None`` = allowed)."""
        agent_id = self._current_agent_id
        context: dict = {"tenant_id": self.tenant_id, "builtin_tool": True}
        active_handle = self._active_subagent_handle()
        if active_handle is not None:
            context["run_handle_id"] = active_handle.run_handle_id
        try:
            result = await self._authorize_checked(
                principal=f'Agent::"{agent_id}"',
                action=f'Action::"{resolve_action(DATA_FILE_PREPROCESSING_TOOL, self.action_map)}"',
                resource=f'Tool::"{DATA_FILE_PREPROCESSING_TOOL}"',
                context=context,
                execution_id=self._current_execution_id,
                run=self._current_run,
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 — fail closed
            logger.warning(
                "data-file preprocessing authorization failed (%s)", type(exc).__name__
            )
            result = {"decision": "Deny"}
        self._action_count += 1
        if result.get("decision", "Deny") == "Allow":
            return None
        self._denied_count += 1
        if self.log_decisions:
            logger.warning(
                "[DENY] %s → %s: the agent is not started",
                agent_id,
                DATA_FILE_PREPROCESSING_TOOL,
            )
        return self._refusal_response(
            "ACTION BLOCKED: Watchlight AI Agent Runtime Governance denied this "
            f"request. Agent '{agent_id}' is not authorized to run data-file "
            "preprocessing code (optimize_data_file)."
        )

    @staticmethod
    def _runs_model_code_locally(agent: Any) -> bool:
        """The agent has a code executor that runs model-written code
        outside the model provider (anything but ``BuiltInCodeExecutor``)."""
        executor = getattr(agent, "code_executor", None) if agent is not None else None
        if executor is None:
            return False
        try:
            from google.adk.code_executors.base_code_executor import BaseCodeExecutor
            from google.adk.code_executors.built_in_code_executor import (
                BuiltInCodeExecutor,
            )
        except Exception:  # noqa: BLE001 — unknown ADK layout: treat as local
            return True
        return isinstance(executor, BaseCodeExecutor) and not isinstance(
            executor, BuiltInCodeExecutor
        )

    @staticmethod
    def _refusal_llm_response(message: str) -> LlmResponse:
        """The response that replaces a refused model turn.

        ``after_model_callback`` must return an ``LlmResponse`` (ADK
        reads ``.content`` from it); the replacement carries only the
        refusal text, so none of the refused turn's function calls run.
        """
        from google.genai import types as genai_types

        return LlmResponse(
            content=genai_types.Content(
                role="model",
                parts=[genai_types.Part.from_text(text=message)],
            ),
            turn_complete=True,
        )

    @staticmethod
    def _refusal_response(message: str) -> Any:
        """Construct a model-side LlmResponse that short-circuits the agent."""
        try:
            from google.genai import types as genai_types

            return genai_types.Content(
                role="model",
                parts=[genai_types.Part.from_text(text=message)],
            )
        except Exception:
            # If the import shape is unavailable, fall back to a dict that
            # ADK's tolerant runtime will surface as a model response.
            return {"role": "model", "parts": [{"text": message}]}

    @staticmethod
    def _inject_plan_addendum(llm_request: Any) -> None:
        """Append the Watchlight plan-prompt addendum to the system instruction.

        ADK's `LlmRequest` usually carries a `system_instruction` field
        (string). We append rather than overwrite. Best-effort: if the
        request doesn't expose that field, we silently skip — the
        plugin still works without the addendum, just less reliably.
        """
        for attr in ("system_instruction", "system_instructions"):
            if hasattr(llm_request, attr):
                current = getattr(llm_request, attr) or ""
                if isinstance(current, str) and PLAN_PROMPT_ADDENDUM not in current:
                    try:
                        setattr(llm_request, attr, current + "\n\n" + PLAN_PROMPT_ADDENDUM)
                    except Exception:
                        pass
                return

    # ── Lifecycle ─────────────────────────────────────────────────────

    async def close(self):
        """Clean up resources."""
        await self.apdp.close()
        await self.lineage.close()
        if self.registry:
            await self.registry.close()
