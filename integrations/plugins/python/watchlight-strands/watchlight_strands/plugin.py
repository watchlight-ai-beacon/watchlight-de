"""WatchlightStrandsPlugin + RunHandle: governance for Strands Agents.

Install the plugin ONCE, on the root agent or orchestrator. It governs that
root and everything the root reaches, with no change to the agent code.

Strands gives every agent and orchestrator its own public hook registry
(``agent.hooks`` / ``orchestrator.hooks``, a ``HookRegistry``). The plugin
registers its callbacks on the root's registry when the root is built, and
on each child's registry before the child can run, through the public
``HookRegistry.add_callback``:

* the agents and orchestrators the root can already see (its agents used as
  tools, the agents and orchestrators its function tools refer to, the nodes
  of a Swarm or Graph), recursively, when the root is built;
* an agent used as a tool, again in ``BeforeToolCallEvent`` before the tool
  runs, which covers tools added after the root was built;
* the agents and orchestrators a function tool refers to (its closure and
  the module names it uses), again in ``BeforeToolCallEvent`` before the
  tool body runs;
* a Swarm or Graph node's executor, again in ``BeforeNodeCallEvent`` before
  the node runs.

A child the plugin cannot attach to (an unsupported agent type such as a
remote ``A2AAgent``, an agent with background tasks, a failed attachment) is
refused: the tool call or node is cancelled before it runs.

Identity comes from the server and from configuration, never from code.
The root runs as the registered agent named by ``agent_slug=`` /
``WATCHLIGHT_AGENT_SLUG``, or by ``agent_map`` / ``WATCHLIGHT_AGENT_MAP``
for its name. (A root bound to the process's verified credential, with no
slug at all, comes with watchlight-core's credential-bound ``start_run``.)
A child never needs a registered slug: it runs as a governed spawn of its
parent with an attenuated scope, as the registered agent ``agent_map`` names
for it, else under a label (``spawn_subagent(child_label=...)``) where
watchlight-core supports it, else as its parent's own registered agent. An
agent that cannot be identified is refused.

What each hook does:

``BeforeInvocationEvent`` / ``BeforeMultiAgentInvocationEvent`` (last)
    Opens the governed run: a root run, or a governed spawn when a governed
    run is active in the calling context. Any failure raises, so the agent
    never reaches its model. Model calls Strands makes outside the agent
    loop are handled here too (``aux_models``): the deprecated
    ``structured_output`` and model-based memory extraction are refused on
    the open run, which closes as failed so lineage records it; the hosted tools of the static configuration of
    ``agent.model`` and ``agent.aux_model`` are authorized on the run; a
    ``summarization_agent`` is attached as a governed child.
``BeforeToolCallEvent`` (last)
    Attaches to any child the tool will run, refuses a function tool whose
    code can build an agent (``agent_construction``), then authorizes the
    call on the invocation's own run; anything but allow sets
    ``cancel_tool``.
``AfterToolCallEvent``
    Emits ``tool_call_observed`` lineage.
``BeforeModelCallEvent`` (last)
    Refuses a model turn with no live run, or a quarantined or severed run.
``BeforeNodeCallEvent`` (last)
    Attaches to the node's executor; a node it cannot govern is cancelled.
``AfterInvocationEvent`` / ``AfterMultiAgentInvocationEvent`` (first)
    Closes the run; sub-agent runs still open end with it. An interrupted
    invocation keeps its run for the resume.
"""

from __future__ import annotations

import asyncio
import contextvars
import functools
import hashlib
import inspect
import json
import math
import os
import threading
import weakref
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterator, List, Mapping, Optional, Set, Tuple, Union
from uuid import UUID

from strands.agent import Agent
from strands.hooks import (
    AfterInvocationEvent,
    AfterMultiAgentInvocationEvent,
    AfterToolCallEvent,
    AgentInitializedEvent,
    BeforeInvocationEvent,
    BeforeModelCallEvent,
    BeforeMultiAgentInvocationEvent,
    BeforeNodeCallEvent,
    BeforeToolCallEvent,
    HookRegistry,
    MultiAgentInitializedEvent,
)
from strands.interrupt import InterruptException
from strands.multiagent.base import MultiAgentBase, Status
from strands.plugins import MultiAgentPlugin as _StrandsMultiAgentPlugin
from strands.plugins import Plugin as _StrandsPlugin
from strands.tools.structured_output.structured_output_tool import StructuredOutputTool
from watchlight_core import (
    AgentNotRegistered,
    AgentQuarantinedError,
    ApdpClient,
    AuthorizeResult,
    BaseRunHandle,
    ChildIntent,
    GovernanceBackend,
    GovernanceTelemetry,
    GovernanceUnavailable,
    WatchlightError,
    application_id_from_env,
    get_logger,
    normalize_intent_category,
    plugin_child_intent,
    require_manifest,
    resolve_application_id,
    typed_intent,
)
from watchlight_core.backend import egress_binding_for
from watchlight_core.hosted_tools import HostedToolTurn, require_hosted_request_allowed

from .hosted_tools import GATE_MARKER, final_request, pin_innermost, require_innermost
from watchlight_core.decision import (
    AgentRevokedError,
    ExecutionTerminatedError,
    SubtreeSeveredError,
)
from watchlight_core.errors import RunHandleInvalidated
from watchlight_core.hosted_tools import (
    HostedToolTurn,
    normalize_hosted_request,
    require_hosted_request_allowed,
)
from watchlight_core.scope import ResourceMatcher

from .aux_models import (
    UngovernedModelCall,
    models_to_gate,
    refuse_deprecated_structured_output,
    refuse_memory_extraction,
    static_hosted_requests,
    summarization_agent,
)
from . import model_backstop
from .agent_construction import can_build_agents
from .traces import build_tool_call_payload, redacted_arg_metadata

logger = get_logger("watchlight_strands")

#: ``metadata.source`` of the events the run handle emits itself.
_OBSERVATION_SOURCE = "strands.workload"

#: Hook order of the gates. Strands runs lower orders first, so the gates run
#: after every other hook, including Strands' own (``HookOrder.SDK_LAST`` is
#: 100) and intervention handlers (90): they authorize what the other hooks
#: settled on. Only a hook registered later at an infinite order runs after.
_GATE_ORDER = math.inf

#: "Use the plugin's own setting" for an optional keyword argument.
_DEFAULT: Any = object()


class _ConformanceHandle:
    """The run handle under the hosted-tool conformance probe: the probe
    answers the hosted-tool decisions; anything else is refused."""

    async def authorize_action_detailed(self, *_args: Any, **_kw: Any) -> AuthorizeResult:
        return AuthorizeResult("deny", reason="conformance_probe_only")

#: Hook order of the closing hooks and the tool observation: first, so a
#: later cleanup hook that raises cannot skip the close.
_CLOSE_ORDER = -math.inf

#: Name of the Strands interrupt raised for an approval-required decision.
APPROVAL_INTERRUPT_NAME = "watchlight-approval"

#: Interrupt responses that mean "the operator approved; retry". The retry is
#: still decided by Watchlight: a response alone never lets a tool run.
_APPROVED_RESPONSES = frozenset({"approve", "approved", "yes", "y"})

#: Canonical sub-agent scope keys a ``subagent_scopes`` entry may set.
_SCOPE_KEYS = (
    "allowed_tools",
    "allowed_resources",
    "allowed_intents",
    "max_depth",
    "time_budget_seconds",
)

#: Environment fallbacks (deployment configuration, never code).
ENV_AGENT_SLUG = "WATCHLIGHT_AGENT_SLUG"
ENV_AGENT_MAP = "WATCHLIGHT_AGENT_MAP"

#: Strands' default agent name. It names no agent, so ``agent_map`` never
#: matches it.
_DEFAULT_AGENT_NAME = "Strands Agents"

#: Verdicts that end the run rather than one tool call.
_TERMINAL_ERRORS: Tuple[type, ...] = (
    AgentQuarantinedError,
    ExecutionTerminatedError,
    SubtreeSeveredError,
    AgentRevokedError,
    RunHandleInvalidated,
)

# Model-facing refusal texts (the cancelled tool's result). Opaque: the
# decision's reason stays in Watchlight's audit trail.
_DENIED_TEXT = "Denied by Watchlight policy. The tool was not run."
_NO_RUN_TEXT = (
    "Refused by Watchlight: no governed run is active for this tool call, "
    "so the tool was not run."
)
_UNAVAILABLE_TEXT = (
    "Refused by Watchlight: the authorization could not be completed, so "
    "the tool was not run."
)
_UNKNOWN_TOOL_TEXT = (
    "Refused by Watchlight: the requested tool is not registered on this "
    "agent, so nothing was run."
)
_REWRITTEN_TEXT = (
    "Refused by Watchlight: another hook changed which tool this call runs, "
    "so the call could not be attributed to one tool and was not run."
)
_UNGOVERNABLE_CHILD_TEXT = (
    "Refused by Watchlight: this call would run an agent that Watchlight "
    "cannot govern, so it was not run."
)
_SPAWN_REFUSED_TEXT = (
    "Refused by Watchlight: the governed spawn of this agent was refused, "
    "so it was not run."
)
_ROOT_INTENT_REFUSED_TEXT = (
    "Refused by Watchlight: the run's declared intent could not be recorded, "
    "so the agent was not run."
)
_APPROVAL_UNREDEEMABLE_TEXT = (
    "Refused by Watchlight: this action needs human approval, and an "
    "approval can only be redeemed with the declared intent it was requested "
    "under (configure intent_objective and intent_category), so the tool was "
    "not run."
)
_APPROVAL_REFUSED_TEXT = (
    "Refused by Watchlight: this action needs human approval and was not "
    "approved, so the tool was not run."
)


class AgentNotIdentified(GovernanceUnavailable):
    """No governed identity could be established for an agent, so it was not
    run: no configured root slug, no ``agent_map`` entry, and no governed
    parent run to spawn under."""


class UngovernableChild(WatchlightError):
    """A child the plugin cannot attach to: an unsupported agent type, an
    agent with background tasks, or a failed hook registration."""


# ─── Run handle ─────────────────────────────────────────────────────────


class RunHandle(BaseRunHandle):
    """Strands-flavoured run handle. Inherits the lifecycle from
    :class:`watchlight_core.BaseRunHandle`; :meth:`spawn_subagent` also
    accepts a registry slug."""

    _observation_source = _OBSERVATION_SOURCE

    async def spawn_subagent(  # type: ignore[override]
        self,
        child_agent_id: Union[str, UUID, None] = None,
        *,
        child_label: Optional[str] = None,
        child_intent: Union[ChildIntent, Dict[str, Any]],
        allowed_tools: Optional[List[str]] = None,
        allowed_resources: Optional[List[Union[ResourceMatcher, str]]] = None,
        allowed_intents: Optional[List[str]] = None,
        max_depth: Optional[int] = None,
        time_budget_seconds: Optional[int] = None,
        parent_execution_id: Optional[str] = None,
    ) -> "RunHandle":
        """Open a governed sub-agent run under this handle.

        ``child_agent_id`` is the child's agent UUID or registry slug (a slug
        is resolved; an unknown one raises :class:`AgentNotRegistered`). The
        scope arguments are the requested attenuation; omitted ones are the
        fail-closed default. Watchlight grants only a strict subset of this
        run's scope. ``parent_execution_id`` is ignored: the child's place in
        the tree comes from this run's verified credential.

        ``child_intent`` is required: the child's own intent and goal, which
        wl-apdp accepts only within this run's intent bounds (see
        :meth:`watchlight_core.BaseRunHandle.spawn_subagent`).

        ``child_label`` names an unregistered child; it is passed through
        only to a watchlight-core that supports labelled spawns
        (:func:`labelled_spawn_supported`).
        """
        del parent_execution_id
        scope = {
            "child_intent": child_intent,
            "allowed_tools": allowed_tools,
            "allowed_resources": allowed_resources,
            "allowed_intents": allowed_intents,
            "max_depth": max_depth,
            "time_budget_seconds": time_budget_seconds,
        }
        if child_agent_id is None:
            if child_label is None or not labelled_spawn_supported():
                raise AgentNotIdentified(
                    "spawn_subagent needs the child's registered agent, or a "
                    "child_label on a watchlight-core that supports labelled spawns"
                )
            return await super().spawn_subagent(child_label=child_label, **scope)  # type: ignore[call-arg,return-value]
        if isinstance(child_agent_id, UUID):
            child_uuid = child_agent_id
        else:
            try:
                child_uuid = UUID(str(child_agent_id))
            except (ValueError, TypeError):
                resolved = await self._plugin.apdp.resolve_agent(str(child_agent_id))
                if resolved is None:
                    raise AgentNotRegistered(
                        f"Sub-agent {child_agent_id!r} is not registered with "
                        "Watchlight. Register it before spawning it."
                    ) from None
                child_uuid = UUID(str(resolved["id"]))
        child = await super().spawn_subagent(child_uuid, **scope)
        return child  # type: ignore[return-value]


def labelled_spawn_supported() -> bool:
    """Whether the installed watchlight-core spawns an unregistered child
    under a label (``BaseRunHandle.spawn_subagent(child_label=...)``)."""
    try:
        return "child_label" in inspect.signature(BaseRunHandle.spawn_subagent).parameters
    except (TypeError, ValueError):
        return False


# ─── Run bookkeeping ────────────────────────────────────────────────────


class InvocationFailed(Exception):
    """Recorded on the lineage when an invocation ends without a result."""


class InvocationCancelled(Exception):
    """Recorded on the lineage when an invocation was cancelled."""


class EndedWithParent(Exception):
    """Recorded on the lineage when a sub-agent run is still open as its
    parent run closes: the sub-agent run ends with it."""


@dataclass(eq=False)
class _Run:
    """One governed run: one invocation of one agent or orchestrator. Holds
    the run handle and what the hooks need to find it; never a credential."""

    plugin: "WatchlightStrandsPlugin"
    handle: Any
    owner: Any
    invocation_state: Optional[Dict[str, Any]]
    parent: Optional["_Run"]
    children: List["_Run"] = field(default_factory=list)
    #: toolUseId -> the tool name authorized for it.
    allowed_tool_uses: Dict[str, str] = field(default_factory=dict)
    #: toolUseId -> approval request id. A bearer value: it stays in this
    #: process and never goes into an interrupt, a log line or an error.
    pending_approvals: Dict[str, str] = field(default_factory=dict)
    #: Provider-hosted tools a model's configuration enables that were
    #: allowed on this run (read by ``model_backstop``).
    allowed_hosted: Set[Any] = field(default_factory=set)
    closed: bool = False
    suspended: bool = False


#: The governed runs active in this context, innermost last. Asyncio tasks
#: copy it when created and Strands' sync entry points copy it into their
#: worker thread, so a nested invocation finds its parent run.
_ACTIVE_RUNS: contextvars.ContextVar[Tuple[_Run, ...]] = contextvars.ContextVar(
    "watchlight_strands_active_runs", default=()
)

#: The root session's lifetime. A run waiting for a human approval that
#: nobody resumes within it is abandoned (see ``model_backstop``).
SESSION_TTL_SECONDS = 3600
APPROVAL_WAIT_SECONDS = SESSION_TTL_SECONDS

#: Every hook registry a Watchlight plugin is registered on, and which one.
#: The plugin is held weakly too: it holds its root, which holds the
#: registry, so a strong value would keep every governed agent alive
#: forever. The registry's own callbacks keep the plugin alive as long as
#: the registry is.
_GOVERNED_REGISTRIES: "weakref.WeakKeyDictionary[HookRegistry, weakref.ReferenceType[WatchlightStrandsPlugin]]" = (
    weakref.WeakKeyDictionary()
)


def _registry_owner(registry: Any) -> Optional["WatchlightStrandsPlugin"]:
    ref = _GOVERNED_REGISTRIES.get(registry)
    return ref() if ref is not None else None
_REGISTRY_LOCK = threading.RLock()


def governing_plugin(obj: Any) -> Optional["WatchlightStrandsPlugin"]:
    """The Watchlight plugin governing a Strands agent or orchestrator, or
    ``None``."""
    registry = getattr(obj, "hooks", None)
    if not isinstance(registry, HookRegistry):
        return None
    with _REGISTRY_LOCK:
        plugin = _registry_owner(registry)
    if plugin is None or not plugin.governs(obj):
        return None
    return plugin


def _push_run(run: _Run) -> None:
    _ACTIVE_RUNS.set(_ACTIVE_RUNS.get() + (run,))
    model_backstop.mark_governed()


async def _check_model_call(
    model: Any, invocation_state: Any = None
) -> Optional[Callable[[], None]]:
    """The per-call backstop's check (see ``model_backstop``): the innermost
    governed run of this context is open and live, a turn of an agent's loop
    comes from an agent with an open governed run, and every hosted tool
    the model's configuration enables is allowed on it. Returns a check the
    backstop runs again after the model's response, before Strands
    dispatches any tool it asked for, or ``None``."""
    from .model_reach import config_requests

    # Strands passes the calling agent in ``invocation_state["agent"]`` on
    # every turn of an agent's loop.
    caller = invocation_state.get("agent") if isinstance(invocation_state, dict) else None
    stack = _ACTIVE_RUNS.get()
    run = stack[-1] if stack else None
    if run is None:
        # No governed run in this context. Unchecked only when no governed
        # run is live in the process and this context never had one, or
        # inside an explicit, logged direct_model_use() block. That block
        # covers direct model calls, never a turn of an agent that can run
        # tools.
        if not model_backstop.GOVERNED_CONTEXT.get() and model_backstop.live_run_count() == 0:
            return None
        if model_backstop.direct_use_declared():
            if caller is None:
                return None
            if _calls_no_tools(caller):
                return functools.partial(_require_no_tools, caller)
            raise UngovernedModelCall(_UNGOVERNED_AGENT_TURN)
        raise UngovernedModelCall(
            "Watchlight refused a model call made outside any open governed run. A thread, "
            "executor or fresh context does not carry the governed run; use asyncio.to_thread, "
            "or wrap your own direct model use in watchlight_strands.direct_model_use()."
        )
    if run.closed or run.suspended:
        raise UngovernedModelCall(
            "Watchlight refused a model call made outside any open governed run."
        )
    # Inside a governed run, the calling agent must have an open governed
    # run of its own: an agent built and run inside a tool body has none, so
    # it never takes a turn and never calls a tool.
    recheck: Optional[Callable[[], None]] = None
    if caller is not None:
        governing = governing_plugin(caller)
        ungoverned = governing is None or governing._find_run(caller, invocation_state) is None
        # Strands' own components (the steering handler, the HITL risk
        # classifier) run a plain agent whose only tool is the structured
        # output tool, which runs no code of its own. Its model was decided
        # at the invocation start and its hosted tools are checked below.
        # The tools are checked again once the response is in, before any
        # dispatch, so a tool registered during the turn is refused too.
        if ungoverned:
            if not _calls_no_tools(caller):
                raise UngovernedModelCall(_UNGOVERNED_AGENT_TURN)
            recheck = functools.partial(_require_no_tools, caller)
    handle = run.handle
    if handle.is_quarantined and handle.quarantine_decision is not None:
        raise AgentQuarantinedError.from_decision(handle.quarantine_decision)
    if handle.is_severed and handle.sever_decision is not None:
        raise SubtreeSeveredError.from_decision(handle.sever_decision)
    for request, provider in config_requests(model):
        try:
            hosted = normalize_hosted_request(request, provider)
        except Exception as exc:  # noqa: BLE001 - fail closed
            raise UngovernedModelCall(
                "Watchlight refused a model call: the model's configuration could not be "
                "read for provider-hosted tools"
            ) from exc
        if not hosted or all(tool in run.allowed_hosted for tool in hosted):
            continue
        turn = HostedToolTurn()
        try:
            gate = await require_hosted_request_allowed(
                handle,
                request,
                turn,
                provider=provider,
                registered_mcp_servers=getattr(run.plugin, "registered_mcp_servers", None),
                timeout_seconds=run.plugin.authorize_timeout_seconds,
            )
        finally:
            turn.seal()
        run.allowed_hosted.update(gate.tools)
    return recheck


_UNGOVERNED_AGENT_TURN = (
    "Watchlight refused a model turn of an agent that is not governed in this run. "
    "An agent built and run inside a tool body cannot be reached; build it outside "
    "the tool function or pass it as a tool."
)


def _require_no_tools(agent: Any) -> None:
    """The check after a response: the agent still holds no tool but the
    structured output tool, so nothing it asked for can be dispatched."""
    if not _calls_no_tools(agent):
        raise UngovernedModelCall(_UNGOVERNED_AGENT_TURN)


def _calls_no_tools(agent: Any) -> bool:
    """Whether every tool ``agent`` could run on a model's request is the
    structured output tool, and none can be loaded during a turn (tools
    hot-loaded from a directory). Fails closed: a registry it cannot read
    counts as tools."""
    try:
        own = object.__getattribute__(agent, "__dict__")
    except AttributeError:
        return False
    if own.get("load_tools_from_directory") or own.get("tool_watcher") is not None:
        return False
    registry = getattr(agent, "tool_registry", None)
    tools: List[Any] = []
    for name in ("registry", "dynamic_tools"):
        held = getattr(registry, name, None)
        if not isinstance(held, dict):
            return False
        tools.extend(held.values())
    return all(type(tool) is StructuredOutputTool for tool in tools)


def _pop_run(run: _Run) -> None:
    """Remove a run from this context's active runs, by identity: runs can
    close out of order (a parent ending its open children)."""
    stack = _ACTIVE_RUNS.get()
    if run in stack:
        _ACTIVE_RUNS.set(tuple(r for r in stack if r is not run))


def _approval_ref(approval_request_id: str) -> str:
    """A short one-way reference to an approval request."""
    return hashlib.sha256(approval_request_id.encode("utf-8")).hexdigest()[:12]


def _is_approved(response: Any) -> bool:
    if response is True:
        return True
    if isinstance(response, str):
        return response.strip().lower() in _APPROVED_RESPONSES
    if isinstance(response, Mapping):
        return response.get("approved") is True
    return False


def _interrupt_active(obj: Any) -> bool:
    """Whether a Strands object is resuming from an interrupt (read-only
    probe; absent means "not resuming", which opens a fresh run)."""
    state = getattr(obj, "_interrupt_state", None)
    return bool(getattr(state, "activated", False))


def _strands_name(obj: Any) -> Optional[str]:
    """The configured name ``agent_map`` keys on: an agent's ``name``, an
    orchestrator's ``id``."""
    if isinstance(obj, Agent):
        name = getattr(obj, "name", None)
        return None if name == _DEFAULT_AGENT_NAME else name
    if isinstance(obj, MultiAgentBase):
        return getattr(obj, "id", None)
    return None


def _governable(obj: Any) -> bool:
    return isinstance(obj, (Agent, MultiAgentBase))


def _referenced_strands_objects(tool: Any) -> Iterator[Any]:
    """Agents and orchestrators a function tool refers to: the names its body
    uses from its closure and its module (``inspect.getclosurevars``), and one
    level into lists, tuples, sets and dict values held there. An agent the
    tool body creates itself is not visible here."""
    func = getattr(tool, "__wrapped__", None)
    if func is None or not callable(func):
        return
    try:
        refs = inspect.getclosurevars(func)
    except (TypeError, ValueError):
        return
    for value in list(refs.nonlocals.values()) + list(refs.globals.values()):
        if _governable(value):
            yield value
        elif isinstance(value, (list, tuple, set, frozenset)):
            yield from (v for v in value if _governable(v))
        elif isinstance(value, dict):
            yield from (v for v in value.values() if _governable(v))


def _tool_kind(tool: Any) -> str:
    """``agent``, ``mcp`` or ``function``. Labels the lineage URI only."""
    if getattr(tool, "tool_type", None) == "agent":
        return "agent"
    if getattr(tool, "mcp_client", None) is not None:
        return "mcp"
    return "function"


def _tool_names(owner: Any, _seen: Optional[Set[int]] = None) -> Set[str]:
    """Tool names an agent (or every agent of an orchestrator) can call."""
    seen = _seen if _seen is not None else set()
    if id(owner) in seen:
        return set()
    seen.add(id(owner))
    if isinstance(owner, Agent):
        return set(owner.tool_names)
    names: Set[str] = set()
    nodes = getattr(owner, "nodes", None)
    if isinstance(nodes, Mapping):
        for node in nodes.values():
            names |= _tool_names(getattr(node, "executor", None), seen)
    return names


def _load_agent_map(value: Union[None, str, Mapping[str, str]]) -> Dict[str, str]:
    """``agent_map``: a mapping, or the path of a JSON object file. Falls back
    to the file named by ``WATCHLIGHT_AGENT_MAP``."""
    if value is None:
        path = os.environ.get(ENV_AGENT_MAP, "").strip()
        if not path:
            return {}
        value = path
    if isinstance(value, str):
        try:
            with open(value, encoding="utf-8") as fh:
                value = json.load(fh)
        except (OSError, ValueError) as exc:
            raise ValueError(
                f"agent_map file could not be read ({type(exc).__name__})"
            ) from None
    if not isinstance(value, Mapping):
        raise TypeError("agent_map must map agent names to registered agents")
    out: Dict[str, str] = {}
    for key, slug in value.items():
        if not isinstance(key, str) or not key.strip() or not isinstance(slug, str) or not slug.strip():
            raise ValueError("agent_map entries must be non-empty strings")
        out[key] = slug.strip()
    return out


# ─── The plugin ─────────────────────────────────────────────────────────


class WatchlightStrandsPlugin(GovernanceTelemetry, _StrandsPlugin, _StrandsMultiAgentPlugin):
    """Watchlight governance for a Strands agent tree. Install it once, on the
    root agent or orchestrator.

    Usage::

        from strands import Agent
        from watchlight_strands import WatchlightStrandsPlugin

        researcher = Agent(name="researcher", tools=[web_search])
        writer = Agent(
            name="writer",
            tools=[researcher.as_tool()],
            plugins=[WatchlightStrandsPlugin()],
        )
        writer("Write a short brief on agent governance")

    It attaches as a Strands ``Plugin`` (``plugins=[...]``), a
    ``MultiAgentPlugin`` (``Swarm(..., plugins=[...])``,
    ``GraphBuilder().set_plugins([...])``) or a ``HookProvider``
    (``hooks=[...]``), and attaches itself to every child the root reaches.

    Identity (see the module docstring): the credential's agent, else
    ``agent_slug`` / ``WATCHLIGHT_AGENT_SLUG`` for the root, else
    ``agent_map`` / ``WATCHLIGHT_AGENT_MAP`` by name; children spawn under
    their parent. ``subagent_scopes`` maps a child's name to the scope it
    requests (keys ``allowed_tools``, ``allowed_resources``,
    ``allowed_intents``, ``max_depth``, ``time_budget_seconds``); by default
    a child requests its own tool names.
    """

    #: Strands plugin name.
    name = "watchlight-governance"

    #: Invariant 19: every provider-hosted tool on a model call is
    #: authorized before the call. The provider follows each agent's model
    #: class, so none is fixed here.
    supports_hosted_tools = True
    hosted_tool_provider: Optional[str] = None

    def __init__(
        self,
        apdp_url: str = "http://localhost:8081",
        *,
        agent_slug: Optional[str] = None,
        agent_map: Union[None, str, Mapping[str, str]] = None,
        subagent_scopes: Optional[Mapping[str, Mapping[str, Any]]] = None,
        tenant_id: Optional[str] = None,
        apdp_api_key: Optional[str] = None,
        log_decisions: bool = True,
        connect_proxy_url: Optional[str] = None,
        governance: Optional[GovernanceBackend] = None,
        application_id: Optional[str] = None,
        authorize_timeout_seconds: float = 30.0,
        child_intent_category: Optional[str] = None,
        intent_objective: Optional[str] = None,
        intent_category: Any = None,
        intent_justification: Optional[str] = None,
        registered_mcp_servers: Optional[Mapping[str, str]] = None,
    ) -> None:
        GovernanceTelemetry.__init__(self)
        # Remote MCP servers a model call may enable: server URL -> the name
        # policy sees as ``Resource::"mcp://<name>/"``. A server not listed
        # refuses the model call before any decision.
        self.registered_mcp_servers: Optional[Mapping[str, str]] = registered_mcp_servers

        # The hosted-tool gate, registered as the innermost invoke-model
        # middleware of every governed agent (see ``hosted_tools``). A plain
        # function carrying the marker the registry check looks for.
        async def _hosted_tool_gate(ctx: Any, next_fn: Any) -> Any:
            async for event in self._gate_model_call(ctx, next_fn):
                yield event

        setattr(_hosted_tool_gate, GATE_MARKER, True)
        self._hosted_tool_gate = _hosted_tool_gate
        # The run's declared intent, typed as wl-apdp requires (objective AND
        # category). Every run of this plugin declares it, so its authorize
        # calls carry it and an approval can be redeemed on retry.
        self._declared_intent: Optional[Dict[str, Any]] = None
        if any(v is not None for v in (intent_objective, intent_category, intent_justification)):
            self._declared_intent = typed_intent(
                intent_objective, intent_category, intent_justification
            )
            if self._declared_intent is None:
                raise ValueError(
                    "intent_objective and intent_category must be given together: a "
                    "non-empty objective and a category wl-apdp accepts (see "
                    "watchlight_core.INTENT_CATEGORIES, or custom:NAME)"
                )
        if agent_slug is None:
            agent_slug = os.environ.get(ENV_AGENT_SLUG) or None
        if agent_slug is not None and (not isinstance(agent_slug, str) or not agent_slug.strip()):
            raise ValueError(
                "agent_slug must be a non-empty string: Watchlight refuses to run "
                "an agent without an identity"
            )
        self.agent_slug: Optional[str] = agent_slug.strip() if agent_slug else None
        self.agent_map: Dict[str, str] = _load_agent_map(agent_map)
        self.subagent_scopes: Dict[str, Dict[str, Any]] = {
            str(k): self._validate_scope(v) for k, v in (subagent_scopes or {}).items()
        }
        if isinstance(authorize_timeout_seconds, bool) or not (
            isinstance(authorize_timeout_seconds, (int, float)) and authorize_timeout_seconds > 0
        ):
            raise ValueError("authorize_timeout_seconds must be a positive number")
        self.authorize_timeout_seconds = float(authorize_timeout_seconds)
        if child_intent_category is not None and (
            not isinstance(child_intent_category, str)
            or normalize_intent_category(child_intent_category) is None
        ):
            raise ValueError(
                "child_intent_category must be a category wl-apdp accepts (see "
                "watchlight_core.INTENT_CATEGORIES, or custom:NAME)"
            )
        # The intent category a spawned child declares; wl-apdp refuses one
        # outside the parent's intent bounds.
        self.child_intent_category: Optional[str] = (
            child_intent_category.strip() if child_intent_category else None
        )

        # Authentication (as the other Watchlight plugins): an explicit
        # ``apdp_api_key`` wins; else a configured credential; else the
        # unauthenticated client. An explicitly configured credential that
        # cannot be loaded raises; it never degrades silently.
        credential = None
        if apdp_api_key is None and governance is None:
            from watchlight_core import Credential, CredentialNotFound

            explicitly_configured = bool(
                os.environ.get("WATCHLIGHT_CREDENTIAL_AWS_SECRET_ID", "").strip()
                or os.environ.get("WATCHLIGHT_CREDENTIAL_FILE", "").strip()
            )
            try:
                credential = Credential.from_default()
            except Exception as exc:  # noqa: BLE001 — classified below
                if explicitly_configured:
                    raise CredentialNotFound(
                        "watchlight_strands: the configured credential could "
                        f"not be loaded ({type(exc).__name__})"
                    ) from None
                if not isinstance(exc, CredentialNotFound):
                    logger.warning(
                        "watchlight_strands: the configured credential could not "
                        "be loaded (%s); continuing unauthenticated, the server "
                        "decides whether that is allowed.",
                        type(exc).__name__,
                    )
                credential = None

        if governance is not None:
            # Developer Edition / in-process seam: the supplied backend (e.g.
            # ``watchlight_core.InProcessClient``) is used as is. A custom
            # networked backend passed here must secure its own transport.
            self.apdp: Any = governance
        elif credential is not None:
            self.apdp = ApdpClient(apdp_url, credential=credential)
        else:
            self.apdp = ApdpClient(apdp_url, api_key=apdp_api_key)
        self.tenant_id = tenant_id
        self.log_decisions = log_decisions
        self.connect_proxy_url = connect_proxy_url or os.getenv("WATCHLIGHT_PROXY_URL")
        self.application_id = (
            resolve_application_id(application_id) or application_id_from_env()
        )
        from watchlight_core import default_kill_signal_registry

        self.kill_signal_registry = default_kill_signal_registry()

        self._lock = threading.RLock()
        self._root: Optional["weakref.ReferenceType[Any]"] = None
        self._attached: "weakref.WeakSet[Any]" = weakref.WeakSet()
        self._open_runs: List[_Run] = []
        # Every model call in a governed context is checked (see
        # model_backstop).
        model_backstop.install(_check_model_call)
        self._suspended: Dict[int, _Run] = {}

        # Strands plugin bases last: their discovery reads attributes.
        _StrandsPlugin.__init__(self)
        _StrandsMultiAgentPlugin.__init__(self)

    # ── configuration ───────────────────────────────────────────────

    @staticmethod
    def _validate_scope(scope: Any) -> Dict[str, Any]:
        if not isinstance(scope, Mapping):
            raise TypeError("a subagent scope must be a mapping")
        unknown = sorted(set(scope) - set(_SCOPE_KEYS))
        if unknown:
            raise ValueError(f"subagent scope has unknown keys {unknown}; allowed: {list(_SCOPE_KEYS)}")
        budget = scope.get("time_budget_seconds")
        if budget is not None and (isinstance(budget, bool) or not isinstance(budget, int) or budget <= 0):
            raise ValueError("time_budget_seconds must be a positive integer")
        depth = scope.get("max_depth")
        if depth is not None and (isinstance(depth, bool) or not isinstance(depth, int) or depth < 0):
            raise ValueError("max_depth must be a non-negative integer")
        for key in ("allowed_tools", "allowed_intents", "allowed_resources"):
            value = scope.get(key)
            if value is not None and not isinstance(value, (list, tuple)):
                raise ValueError(f"{key} must be a list")
        # A pinned intent becomes the child's category: refuse one wl-apdp
        # would not accept here, not at the spawn.
        for intent in scope.get("allowed_intents") or ():
            if not isinstance(intent, str) or normalize_intent_category(intent) is None:
                raise ValueError(
                    f"allowed_intents entry {intent!r} is not a category wl-apdp accepts "
                    "(see watchlight_core.INTENT_CATEGORIES, or custom:NAME)"
                )
        return {k: (list(v) if isinstance(v, tuple) else v) for k, v in scope.items()}

    # ── opening a root run (the SDK primitive) ──────────────────────

    async def start_run(
        self,
        agent_slug: str,
        *,
        application_id: Optional[str] = None,
    ) -> RunHandle:
        """Open a governed root run for a registered agent (slug or UUID).

        Fail closed: an unknown slug raises :class:`AgentNotRegistered`; a
        refused or unreachable session, a missing manifest, or egress that
        cannot be governed raises :class:`GovernanceUnavailable`, and a
        session opened before the failure is closed.
        """
        self._reset_telemetry()
        try:
            agent_uuid = str(UUID(str(agent_slug)))
        except (ValueError, TypeError):
            resolved = await self.apdp.resolve_agent(agent_slug)
            if resolved is None:
                raise AgentNotRegistered(
                    f"Agent {agent_slug!r} is not registered with Watchlight. "
                    "Register it before invoking it."
                ) from None
            agent_uuid = resolved["id"]
        app_id = resolve_application_id(application_id) or self.application_id
        session = await self.apdp.create_session(
            agent_id=agent_uuid,
            ttl_seconds=SESSION_TTL_SECONDS,
            metadata={"framework": "strands", "tenant_id": self.tenant_id},
            **({"application_id": app_id} if app_id is not None else {}),
        )
        if session is None:
            raise GovernanceUnavailable(
                "WL-APDP did not accept the session create. Check that it is "
                "reachable and configured."
            )
        session_id = session.session_id
        run = session.run
        try:
            manifest = await self.apdp.get_manifest(agent_uuid, run=run)
            governance_level = require_manifest(manifest, agent_id=agent_uuid)
            egress = egress_binding_for(self.apdp, run)
            if self.connect_proxy_url:
                if egress is None:
                    raise GovernanceUnavailable(
                        "A wl-proxy URL is configured but WL-APDP issued no proxy "
                        "token for this session; refusing to run with direct egress."
                    )
                from watchlight_core import SidecarRunActive, install_sidecar

                try:
                    install_sidecar(
                        self.connect_proxy_url,
                        egress.proxy_authorization(),
                        governed_proxy_hosts=(manifest or {}).get("governed_proxy_hosts"),
                        ca_cert=os.getenv("WATCHLIGHT_PROXY_CA_CERT"),
                        egress=egress,
                    )
                except SidecarRunActive:
                    raise
                except Exception as exc:  # noqa: BLE001 — any failure refuses
                    raise GovernanceUnavailable(
                        "The wl-sidecar could not be installed "
                        f"({type(exc).__name__}); refusing to run with direct egress."
                    ) from None
        except BaseException as exc:
            try:
                await self.apdp.complete_session(run)
            except Exception:  # noqa: BLE001 — the refusal is what matters
                logger.warning(
                    "watchlight_strands: could not close session %s after a "
                    "refused run setup (%s)",
                    session_id,
                    type(exc).__name__,
                )
            raise

        self.last_governance_mode = governance_level
        self.last_session_id = session_id
        self.last_manifest = manifest
        if self.log_decisions:
            logger.info(
                "[GOVERNANCE-MODE] %s — session=%s manifest=%s agent=%s",
                governance_level,
                session_id,
                bool(manifest),
                agent_uuid,
            )
        return RunHandle(
            plugin=self,
            agent_uuid=agent_uuid,
            session_id=session_id,
            run_handle_id=session.root_run_handle_id,
            server_run_handle=session.root_run_handle_id is not None,
            run=run,
            egress=egress,
            execution_id=session.execution_id,
        )

    # ── installing and attaching ────────────────────────────────────

    def register_hooks(self, registry: HookRegistry, **kwargs: Any) -> None:
        """``HookProvider`` entry point: register the governance callbacks.

        Idempotent for this plugin. A registry that already carries another
        Watchlight plugin is refused: one object has one governor.
        """
        with _REGISTRY_LOCK:
            owner = _registry_owner(registry)
            if owner is self:
                return
            if owner is not None:
                raise ValueError(
                    "This Strands object already carries a Watchlight plugin; "
                    "install one WatchlightStrandsPlugin, on the root."
                )
            registry.add_callback(AgentInitializedEvent, self._on_agent_initialized)
            registry.add_callback(MultiAgentInitializedEvent, self._on_multi_agent_initialized)
            registry.add_callback(BeforeInvocationEvent, self._before_invocation, order=_GATE_ORDER)
            # After the run opens (registered later at the same order).
            registry.add_callback(
                BeforeInvocationEvent, self._govern_reachable_models, order=_GATE_ORDER
            )
            registry.add_callback(AfterInvocationEvent, self._after_invocation, order=_CLOSE_ORDER)
            registry.add_callback(BeforeModelCallEvent, self._before_model_call, order=_GATE_ORDER)
            # First too, so no earlier hook (proactive compression) calls a
            # model for a run that is gone, quarantined or severed.
            registry.add_callback(BeforeModelCallEvent, self._model_turn_first, order=_CLOSE_ORDER)
            registry.add_callback(BeforeToolCallEvent, self._before_tool_call, order=_GATE_ORDER)
            registry.add_callback(AfterToolCallEvent, self._after_tool_call, order=_CLOSE_ORDER)
            registry.add_callback(
                BeforeMultiAgentInvocationEvent,
                self._before_multi_agent_invocation,
                order=_GATE_ORDER,
            )
            registry.add_callback(BeforeNodeCallEvent, self._before_node_call, order=_GATE_ORDER)
            registry.add_callback(
                AfterMultiAgentInvocationEvent,
                self._after_multi_agent_invocation,
                order=_CLOSE_ORDER,
            )
            # Claimed only once every callback is registered: a registry is
            # never reported as governed with half its gates.
            _GOVERNED_REGISTRIES[registry] = weakref.ref(self)

    def init_agent(self, agent: Any) -> None:
        """``Plugin`` entry point (``Agent(plugins=[...])``)."""
        self._install(agent)

    def init_multi_agent(self, orchestrator: Any) -> None:
        """``MultiAgentPlugin`` entry point (``Swarm(..., plugins=[...])``)."""
        self._install(orchestrator)

    def _on_agent_initialized(self, event: AgentInitializedEvent) -> None:
        self._install(event.agent)

    def _on_multi_agent_initialized(self, event: MultiAgentInitializedEvent) -> None:
        self._install(event.source)

    @property
    def governed_object(self) -> Any:
        """The root this plugin was installed on, if any."""
        ref = self._root
        return ref() if ref is not None else None

    def governs(self, obj: Any) -> bool:
        """Whether ``obj`` is this plugin's root or a child it attached to."""
        if obj is None:
            return False
        if obj is self.governed_object:
            return True
        with self._lock:
            return obj in self._attached

    def _install(self, root: Any) -> None:
        """Install on the root: refuse what cannot be governed, register the
        callbacks, and attach to every child the root can already see."""
        self._check_governable(root)
        with self._lock:
            current = self.governed_object
            if current is not None and current is not root:
                raise ValueError(
                    "This WatchlightStrandsPlugin is already installed on another "
                    "root. Install it once, on the root agent or orchestrator; it "
                    "governs everything beneath it."
                )
            self._root = weakref.ref(root)
        self.register_hooks(root.hooks)
        self._attach_reachable(root, strict=False)

    @staticmethod
    def _check_governable(obj: Any) -> None:
        if isinstance(obj, Agent):
            # Background tool calls run after their governed run has ended.
            # Read-only probe; tests/test_strands_surface.py pins it.
            if getattr(obj, "_background_tasks", None) is not None:
                raise UngovernableChild(
                    "Watchlight does not govern Agent(background_tasks=...): a "
                    "background tool call runs after its governed run has ended."
                )
            return
        if isinstance(obj, MultiAgentBase):
            return
        raise UngovernableChild(
            f"Watchlight governs strands.Agent and Swarm/Graph orchestrators; "
            f"{type(obj).__name__} is not supported."
        )

    def _attach(self, child: Any) -> None:
        """Attach to one child through its public hook registry, then to what
        it can reach. Raises :class:`UngovernableChild` when that fails."""
        if governing_plugin(child) is not None:
            return
        self._check_governable(child)
        registry = getattr(child, "hooks", None)
        if not isinstance(registry, HookRegistry):
            raise UngovernableChild("the child exposes no Strands hook registry")
        try:
            self.register_hooks(registry)
        except Exception as exc:  # noqa: BLE001 — any failure refuses the child
            raise UngovernableChild(
                f"could not register on the child's hook registry ({type(exc).__name__})"
            ) from None
        with self._lock:
            self._attached.add(child)
        if governing_plugin(child) is None:
            raise UngovernableChild("the child's hook registration did not take effect")
        self._attach_reachable(child, strict=False)

    def _attach_reachable(self, obj: Any, *, strict: bool, _seen: Optional[Set[int]] = None) -> None:
        """Attach to the agents and orchestrators ``obj`` can reach: its
        agents used as tools and the ones its function tools refer to, or an
        orchestrator's node executors. Non-strict at install time (a child
        that cannot be attached is refused when it is reached); the gates
        attach strictly before running a child."""
        seen = _seen if _seen is not None else set()
        if id(obj) in seen:
            return
        seen.add(id(obj))
        for child in self._reachable(obj):
            if id(child) in seen:
                continue
            try:
                self._attach(child)
            except UngovernableChild:
                if strict:
                    raise
                logger.warning(
                    "watchlight_strands: a %s reachable from the root cannot be "
                    "governed; it will be refused if it is called",
                    type(child).__name__,
                )

    @staticmethod
    def _reachable(obj: Any) -> List[Any]:
        found: List[Any] = []
        if isinstance(obj, Agent):
            registry = getattr(getattr(obj, "tool_registry", None), "registry", None) or {}
            for tool in list(registry.values()):
                if getattr(tool, "tool_type", None) == "agent":
                    child = getattr(tool, "agent", None)
                    if child is not None:
                        found.append(child)
                else:
                    found.extend(_referenced_strands_objects(tool))
        elif isinstance(obj, MultiAgentBase):
            nodes = getattr(obj, "nodes", None)
            if isinstance(nodes, Mapping):
                for node in nodes.values():
                    executor = getattr(node, "executor", None)
                    if executor is not None:
                        found.append(executor)
        return found

    # ── identity ────────────────────────────────────────────────────

    def _mapped(self, owner: Any) -> Optional[str]:
        name = _strands_name(owner)
        return self.agent_map.get(name) if name else None

    def _root_identity(self, owner: Any) -> str:
        """The registered agent a root run opens as: the root's configured
        slug, else the ``agent_map`` entry for its name. Otherwise refused."""
        if owner is self.governed_object and self.agent_slug:
            return self.agent_slug
        mapped = self._mapped(owner)
        if mapped:
            return mapped
        raise AgentNotIdentified(
            "Watchlight could not identify this agent, so it was not run. Set "
            "agent_slug (or WATCHLIGHT_AGENT_SLUG) for the root, or map its name "
            "in agent_map (or WATCHLIGHT_AGENT_MAP)."
        )

    def _requested_scope(self, owner: Any) -> Dict[str, Any]:
        scope: Dict[str, Any] = {"allowed_tools": sorted(_tool_names(owner))}
        name = _strands_name(owner)
        if name and name in self.subagent_scopes:
            scope.update(self.subagent_scopes[name])
        return scope

    def _child_intent(self, owner: Any, parent_handle: Any, scope: Dict[str, Any]) -> ChildIntent:
        """The intent a child declares, derived from what Strands gives: the
        agent's ``description`` is the objective. A scope that pins exactly
        one intent names the category (wl-apdp requires ``allowed_intents``
        to be empty or exactly that category); else ``child_intent_category``,
        else the parent's own derived category, else the core default (the
        same order as every other plugin, through ``plugin_child_intent``).
        The server refuses a category outside the parent's bounds, so the
        child then never runs."""
        description = getattr(owner, "description", None)
        scoped_intents = list(scope.get("allowed_intents") or [])
        name = _strands_name(owner) or type(owner).__name__
        return plugin_child_intent(
            description if isinstance(description, str) else None,
            category=scoped_intents[0] if len(scoped_intents) == 1 else self.child_intent_category,
            parent=parent_handle,
            fallback_objective=f"strands task for {name}",
        )

    # ── run lookup and lifecycle ────────────────────────────────────

    def _find_run(self, owner: Any, invocation_state: Optional[Dict[str, Any]]) -> Optional[_Run]:
        """The open run of ``owner`` for this invocation: by the invocation's
        own state dict (the same dict reaches every hook of one invocation,
        concurrent tool calls included), else the innermost run of ``owner``
        active in this context."""
        with self._lock:
            open_runs = [r for r in self._open_runs if not r.closed and not r.suspended]
        if invocation_state is not None:
            for run in reversed(open_runs):
                if run.owner is owner and run.invocation_state is invocation_state:
                    return run
        for run in reversed(_ACTIVE_RUNS.get()):
            if run.owner is owner and run in open_runs:
                return run
        return None

    async def _open_run(self, owner: Any, invocation_state: Optional[Dict[str, Any]]) -> _Run:
        """Open (or resume) the run of one invocation and make it the active
        run of this context. Raises on any failure; nothing stays open."""
        self._check_governable(owner)
        stack = _ACTIVE_RUNS.get()
        parent = stack[-1] if stack else None
        with self._lock:
            suspended = self._suspended.pop(id(owner), None)
        if suspended is not None:
            if (
                not suspended.closed
                and suspended.owner is owner
                and suspended.parent is parent
                and _interrupt_active(owner)
            ):
                suspended.suspended = False
                suspended.invocation_state = invocation_state
                with self._lock:
                    if suspended not in self._open_runs:
                        self._open_runs.append(suspended)
                model_backstop.run_live(suspended)
                _push_run(suspended)
                return suspended
            await self._close_run(suspended, InvocationCancelled("superseded"))

        if parent is not None and (parent.closed or parent.suspended):
            raise GovernanceUnavailable(
                "Watchlight refused to start this agent: the governed run it "
                "would belong to has already ended, so it was not run."
            )

        child_intent: Optional[ChildIntent] = None
        if parent is None:
            handle = await self.start_run(self._root_identity(owner))
        else:
            # A child runs as a governed spawn of its parent, attenuated: as
            # the registered agent agent_map names for it, else under a label
            # where watchlight-core supports it, else as the parent's agent.
            scope = self._requested_scope(owner)
            child_intent = self._child_intent(owner, parent.handle, scope)
            scope["child_intent"] = child_intent
            mapped = self._mapped(owner)
            try:
                if mapped:
                    handle = await parent.handle.spawn_subagent(mapped, **scope)
                elif labelled_spawn_supported():
                    label = _strands_name(owner) or type(owner).__name__
                    handle = await parent.handle.spawn_subagent(child_label=label, **scope)
                else:
                    handle = await parent.handle.spawn_subagent(parent.handle.agent_uuid, **scope)
            except _TERMINAL_ERRORS:
                raise
            except Exception as exc:  # noqa: BLE001 — every refused spawn reads the same
                # Strands hands an agent-as-tool's exception text to the
                # parent's model. Give it one clear refusal, never the
                # backend's own error text.
                logger.warning(
                    "[DENY-SPAWN] %s: the governed spawn was refused (%s); not run",
                    _strands_name(owner) or type(owner).__name__,
                    type(exc).__name__,
                )
                raise GovernanceUnavailable(_SPAWN_REFUSED_TEXT) from exc
        try:
            # The intent the run's calls carry. A root run carries the
            # declared run intent (when configured). A child always carries
            # its own derived intent: wl-apdp grants it exactly that category
            # and refuses (and ends) a child whose call names another, so its
            # calls stay inside its grant and an approval stays redeemable.
            if child_intent is not None:
                handle.record_declared_intent(child_intent.objective, child_intent.category)
            elif self._declared_intent is not None:
                handle.record_declared_intent(
                    self._declared_intent["objective"],
                    self._declared_intent["category"],
                    self._declared_intent.get("justification"),
                )
        except Exception as exc:  # noqa: BLE001 — the run never starts
            try:
                await handle.terminate(reason="run_failed: intent_refused")
            except Exception:  # noqa: BLE001 — the refusal below wins
                logger.warning("watchlight_strands: closing a run whose intent was refused failed")
            logger.warning(
                "[DENY-SPAWN] %s: the run's intent could not be recorded (%s); not run",
                _strands_name(owner) or type(owner).__name__,
                type(exc).__name__,
            )
            raise GovernanceUnavailable(
                _SPAWN_REFUSED_TEXT if parent is not None else _ROOT_INTENT_REFUSED_TEXT
            ) from exc
        try:
            await handle.__aenter__()
        except BaseException:
            try:
                await handle.terminate(reason="run_failed: lineage_bind")
            except Exception:  # noqa: BLE001 — the refusal below wins
                logger.warning("watchlight_strands: closing an unbound run failed")
            raise

        run = _Run(
            plugin=self,
            handle=handle,
            owner=owner,
            invocation_state=invocation_state,
            parent=parent,
        )
        with self._lock:
            self._open_runs.append(run)
        model_backstop.run_live(run)
        if parent is not None:
            parent.children.append(run)
        _push_run(run)
        if self.log_decisions:
            logger.info(
                "[RUN-OPEN] %s %s execution=%s",
                "spawn" if parent is not None else "root",
                type(owner).__name__,
                handle.execution_id,
            )
        return run

    async def _suspend_run(self, run: _Run) -> None:
        """Keep an interrupted invocation's run open for its resume."""
        _pop_run(run)
        run.suspended = True
        # It stays live until it closes: a thread or pool its tools started
        # keeps running during the wait, and its model calls must not pass
        # unchecked. A wait nobody resumes is abandoned when the session
        # expires (or when the agent is garbage collected).
        model_backstop.run_suspended(run, APPROVAL_WAIT_SECONDS)
        with self._lock:
            previous = self._suspended.get(id(run.owner))
            self._suspended[id(run.owner)] = run
        if previous is not None and previous is not run:
            await self._close_run(previous, InvocationCancelled("superseded"))

    async def _close_run(self, run: _Run, failure: Optional[BaseException]) -> None:
        """Close a run (idempotent). Open sub-agent runs end with it."""
        if run.closed:
            return
        run.closed = True
        run.suspended = False
        model_backstop.run_ended(run)
        for child in list(run.children):
            if not child.closed:
                await child.plugin._close_run(child, EndedWithParent("ended_with_parent"))
        _pop_run(run)
        with self._lock:
            if run in self._open_runs:
                self._open_runs.remove(run)
            if self._suspended.get(id(run.owner)) is run:
                del self._suspended[id(run.owner)]
        try:
            if failure is None or run.handle.is_quarantined:
                # A quarantined run closes through ``complete``, which records
                # the quarantine as its outcome and releases the session.
                await run.handle.__aexit__(None, None, None)
            else:
                await run.handle.__aexit__(type(failure), failure, None)
        except Exception as exc:  # noqa: BLE001 — never mask the outcome
            logger.warning(
                "watchlight_strands: closing run %s raised %s",
                run.handle.session_id,
                type(exc).__name__,
            )
        if self.log_decisions:
            logger.info(
                "[RUN-CLOSE] execution=%s outcome=%s",
                run.handle.execution_id,
                "completed" if failure is None else type(failure).__name__,
            )

    # ── agent invocation hooks ──────────────────────────────────────

    async def _before_invocation(self, event: BeforeInvocationEvent) -> None:
        if event.cancel:
            return
        agent = event.agent
        run = await self._open_run(agent, event.invocation_state)
        try:
            # Model calls Strands makes outside the agent loop (see
            # aux_models): the ones no decision can reach are refused on the
            # open run, which then closes as failed so its lineage records
            # the refusal. Nothing has called a model yet.
            refuse_deprecated_structured_output(agent)
            refuse_memory_extraction(agent)
            summarizer = summarization_agent(agent)
            if summarizer is not None:
                # The summary runs as this agent's governed child.
                self._attach(summarizer)
            await self._gate_static_hosted_tools(run, agent)
        except BaseException as exc:
            await self._close_run(run, exc)
            raise

    async def _gate_static_hosted_tools(self, run: _Run, agent: Any) -> None:
        """Authorize every provider-hosted tool the static configuration of
        ``agent.model`` and ``agent.aux_model`` enables, on the run, before
        the invocation starts. That configuration is sent with every call of
        the model, including the calls Strands makes with no
        ``BeforeModelCallEvent`` (a summary). Any refusal raises."""
        turn = HostedToolTurn()
        try:
            for model in models_to_gate(agent):
                for request, provider in static_hosted_requests(model):
                    try:
                        hosted = normalize_hosted_request(request, provider)
                    except Exception as exc:  # noqa: BLE001 - fail closed
                        raise UngovernedModelCall(
                            "Watchlight refused the invocation: the model configuration "
                            "could not be read for provider-hosted tools"
                        ) from exc
                    if not hosted:
                        continue
                    gate = await require_hosted_request_allowed(
                        run.handle,
                        request,
                        turn,
                        provider=provider,
                        # Set by the per-call hosted-tool gate where present.
                        registered_mcp_servers=getattr(self, "registered_mcp_servers", None),
                        timeout_seconds=self.authorize_timeout_seconds,
                    )
                    run.allowed_hosted.update(gate.tools)
        finally:
            turn.seal()

    async def _after_invocation(self, event: AfterInvocationEvent) -> None:
        run = self._find_run(event.agent, event.invocation_state)
        if run is None:
            return
        result = event.result
        stop_reason = getattr(result, "stop_reason", None) if result is not None else None
        if stop_reason == "interrupt":
            await self._suspend_run(run)
        elif result is None:
            await self._close_run(run, InvocationFailed("no_result"))
        elif stop_reason == "cancelled":
            await self._close_run(run, InvocationCancelled("cancelled"))
        else:
            await self._close_run(run, None)

    async def _before_model_call(self, event: BeforeModelCallEvent) -> None:
        if event.cancel:
            return
        run = self._find_run(event.agent, event.invocation_state)
        if run is None or run.closed:
            raise GovernanceUnavailable(
                "Watchlight refused a model call that belongs to no governed run."
            )
        # The model this turn calls must reach the per-call backstop.
        model_backstop.require_backstop(event.agent.model)
        handle = run.handle
        if handle.is_quarantined and handle.quarantine_decision is not None:
            raise AgentQuarantinedError.from_decision(handle.quarantine_decision)
        if handle.is_severed and handle.sever_decision is not None:
            raise SubtreeSeveredError.from_decision(handle.sever_decision)
        # The hosted-tool gate runs inside the invoke-model middleware, after
        # every handler that can change the call: pin it innermost again.
        pin_innermost(event.agent, self._hosted_tool_gate)

    async def _gate_model_call(self, ctx: Any, next_fn: Any) -> Any:
        """The innermost invoke-model handler: authorize every hosted tool
        the final request enables, then call the model. Any refusal or
        failure raises before ``next_fn``."""
        run = self._find_run(ctx.agent, ctx.invocation_state)
        if run is None or run.closed:
            raise GovernanceUnavailable(
                "Watchlight refused a model call that belongs to no governed run."
            )
        require_innermost(ctx.agent)
        try:
            request, provider = final_request(ctx)
        except Exception as exc:  # noqa: BLE001 - fail closed
            raise GovernanceUnavailable(
                "Watchlight refused the model call: the request it would send could not be read"
            ) from exc
        turn = HostedToolTurn()
        try:
            await self._gate_request(run.handle, request, turn, provider=provider)
            # A model swapped in by middleware must reach the per-model
            # backstop too, as every model reachable at run open must.
            model_backstop.require_backstop(ctx.model)
            async for event in next_fn(ctx):
                yield event
        finally:
            turn.seal()

    async def _gate_request(
        self,
        handle: Any,
        request: Any,
        turn: HostedToolTurn,
        *,
        provider: Optional[str],
        registered_mcp_servers: Any = _DEFAULT,
    ) -> None:
        """``require_hosted_request_allowed`` on ``request``; raises on any
        refusal."""
        await require_hosted_request_allowed(
            handle,
            request,
            turn,
            provider=provider,
            registered_mcp_servers=(
                self.registered_mcp_servers
                if registered_mcp_servers is _DEFAULT
                else registered_mcp_servers
            ),
            timeout_seconds=self.authorize_timeout_seconds,
        )

    async def conformance_hosted_tool_call(self, probe: Any) -> None:
        """Invariant 19: one governed model call of ``probe.request``
        through the gate every model call uses."""
        turn = HostedToolTurn()
        await self._gate_request(
            probe.wrap(_ConformanceHandle()),
            probe.request,
            turn,
            provider=probe.provider,
            registered_mcp_servers=probe.registered_mcp_servers,
        )
        await probe.model_client.call(probe.request)
        turn.seal()

    # ── the tool gate ───────────────────────────────────────────────

    def _refuse_tool(self, event: BeforeToolCallEvent, text: str) -> None:
        event.cancel_tool = text
        self.last_actions_denied += 1

    def _attach_tool_children(self, tool: Any) -> None:
        """Attach to every child this tool can run, strictly, before it runs."""
        if getattr(tool, "tool_type", None) == "agent":
            child = getattr(tool, "agent", None)
            if child is None:
                raise UngovernableChild("an agent tool without an agent")
            self._attach(child)
            return
        for child in _referenced_strands_objects(tool):
            self._attach(child)
        if can_build_agents(tool):
            raise UngovernableChild("the tool's code can build an agent the plugin cannot reach")

    async def _before_tool_call(self, event: BeforeToolCallEvent) -> None:
        if event.cancel_tool:
            return
        tool_use = event.tool_use
        tool_use_id = str(tool_use.get("toolUseId"))
        run = self._find_run(event.agent, event.invocation_state)
        if run is None or run.closed:
            logger.warning("[DENY-NO-RUN] tool call with no governed run; refused")
            self._refuse_tool(event, _NO_RUN_TEXT)
            return
        tool = event.selected_tool
        if tool is None:
            self._refuse_tool(event, _UNKNOWN_TOOL_TEXT)
            return
        tool_name = getattr(tool, "tool_name", None)
        if not isinstance(tool_name, str) or tool_name != tool_use.get("name"):
            self._refuse_tool(event, _REWRITTEN_TEXT)
            return
        tool_type = _tool_kind(tool)
        tool_args = tool_use.get("input")
        try:
            self._attach_tool_children(tool)
        except UngovernableChild as exc:
            logger.warning("[DENY-CHILD] tool %s: %s; refused", tool_name, exc)
            self._refuse_tool(event, _UNGOVERNABLE_CHILD_TEXT)
            await self._observe(run, tool_name, tool_type, tool_args, "Deny")
            return

        approval_id = run.pending_approvals.get(tool_use_id)
        try:
            if approval_id is None:
                result = await self._authorize(run, tool_name, tool_args)
                if result.needs_approval() and result.approval_request_id:
                    approval_id = result.approval_request_id
                    run.pending_approvals[tool_use_id] = approval_id
                    logger.info(
                        "tool %s requires human approval (approval_ref=%s); interrupting",
                        tool_name,
                        _approval_ref(approval_id),
                    )
            if approval_id is not None:
                # Raises InterruptException until the invocation is resumed
                # with a response; then returns that response.
                response = event.interrupt(
                    APPROVAL_INTERRUPT_NAME,
                    reason={
                        "type": "watchlight_approval_required",
                        "tool_name": tool_name,
                        "approval_ref": _approval_ref(approval_id),
                    },
                )
                run.pending_approvals.pop(tool_use_id, None)
                if not _is_approved(response):
                    self._refuse_tool(event, _APPROVAL_REFUSED_TEXT)
                    await self._observe(run, tool_name, tool_type, tool_args, "Deny")
                    return
                # wl-apdp reads the token from the request's typed intent and
                # binds the approval to that intent's objective: the retry
                # carries the run's declared intent with the token, never a
                # bare token (an untyped intent is answered 422).
                # The handle completes the token-only intent with the run's
                # declared objective, category and justification.
                if run.handle.declared_intent_category is None:
                    self._refuse_tool(event, _APPROVAL_UNREDEEMABLE_TEXT)
                    await self._observe(run, tool_name, tool_type, tool_args, "Deny")
                    return
                result = await self._authorize(
                    run, tool_name, tool_args, intent={"approval_token": approval_id}
                )
        except InterruptException:
            raise
        except _TERMINAL_ERRORS:
            self.last_actions_denied += 1
            raise
        except Exception as exc:  # noqa: BLE001 — every other failure refuses
            logger.warning(
                "[DENY-UNAVAILABLE] tool %s: authorization failed (%s); refused",
                tool_name,
                type(exc).__name__,
            )
            self._refuse_tool(event, _UNAVAILABLE_TEXT)
            return

        if result.is_allow():
            run.allowed_tool_uses[tool_use_id] = tool_name
            if self.log_decisions:
                logger.info("[ALLOW] %s", tool_name)
            return
        if self.log_decisions:
            logger.warning("[DENY] %s", tool_name)
        event.cancel_tool = _APPROVAL_REFUSED_TEXT if result.needs_approval() else _DENIED_TEXT
        await self._observe(run, tool_name, tool_type, tool_args, "Deny")

    async def _authorize(
        self,
        run: _Run,
        tool_name: str,
        tool_args: Any,
        intent: Optional[Dict[str, Any]] = None,
    ) -> AuthorizeResult:
        """Authorize one tool call on the run. Only argument names and value
        types go to Watchlight, never a value."""
        result = await asyncio.wait_for(
            run.handle.authorize_action_detailed(
                action="execute",
                resource=tool_name,
                intent=intent,
                context={"tool_args": redacted_arg_metadata(tool_args)},
            ),
            timeout=self.authorize_timeout_seconds,
        )
        if not isinstance(result, AuthorizeResult):
            raise WatchlightError("authorization returned an unexpected result")
        return result

    async def _after_tool_call(self, event: AfterToolCallEvent) -> None:
        tool_use_id = str(event.tool_use.get("toolUseId"))
        run = self._find_run(event.agent, event.invocation_state)
        if run is None:
            return
        authorized = run.allowed_tool_uses.pop(tool_use_id, None)
        if authorized is None:
            return
        tool = event.selected_tool
        ran = getattr(tool, "tool_name", None) or event.tool_use.get("name")
        if ran != authorized:
            # A hook registered after the gate at an infinite order ran a
            # different tool: its result is withheld and the mismatch logged.
            logger.error(
                "[GATE-MISMATCH] authorized %r but %r ran; result withheld",
                authorized,
                ran,
            )
            event.result = {
                "toolUseId": tool_use_id,
                "status": "error",
                "content": [{"text": _REWRITTEN_TEXT}],
            }
            return
        duration = event.duration
        await self._observe(
            run,
            authorized,
            _tool_kind(tool),
            event.tool_use.get("input"),
            "Allow",
            duration_ms=int(duration * 1000) if isinstance(duration, (int, float)) else None,
        )

    async def _observe(
        self,
        run: _Run,
        tool_name: str,
        tool_type: Optional[str],
        tool_args: Any,
        decision: str,
        *,
        duration_ms: Optional[int] = None,
    ) -> None:
        """Emit ``tool_call_observed`` on the run (best-effort)."""
        try:
            await run.handle.publish_observation(
                event_type="tool_call_observed",
                payload=build_tool_call_payload(
                    tool_name=tool_name,
                    tool_type=tool_type,
                    tool_args=tool_args,
                    action="execute",
                    decision=decision,
                    duration_ms=duration_ms,
                ),
            )
        except Exception:
            logger.debug("tool_call_observed emit failed", exc_info=True)

    # ── models and memory writes outside the agent loop ─────────────

    async def _model_turn_first(self, event: BeforeModelCallEvent) -> None:
        """The model-turn check, before every other ``BeforeModelCallEvent``
        hook: a hook that runs earlier (the conversation manager's proactive
        compression) can call a model itself. It runs again last, after
        hooks that might have changed the run."""
        await self._before_model_call(event)

    async def _govern_reachable_models(self, event: BeforeInvocationEvent) -> None:
        """Govern every model the agent can call outside the agent loop and
        every memory write it makes after the run (see ``model_reach``), on
        the run the invocation just opened. Any refusal closes the run as
        failed (its lineage records the refusal) and raises before the
        first model call."""
        if event.cancel:
            return
        run = self._find_run(event.agent, event.invocation_state)
        if run is None or run.closed:
            raise GovernanceUnavailable(
                "Watchlight refused the invocation: it has no governed run."
            )
        try:
            await self._gate_reachable_models(run, event.agent)
            await self._authorize_memory_writes(run, event.agent)
        except BaseException as exc:
            await self._close_run(run, exc)
            raise

    async def _gate_reachable_models(self, run: _Run, agent: Any) -> None:
        from watchlight_core.hosted_tools import (
            HostedToolTurn,
            normalize_hosted_request,
            require_hosted_request_allowed,
        )

        from .model_reach import (
            UngovernedModelUse,
            config_requests,
            reachable,
            refuse_post_run_model_calls,
        )

        reach = reachable(agent)
        refuse_post_run_model_calls(reach.components)
        # Every model this agent can call must reach the per-call backstop:
        # a replaced stream (on the class or the instance) or a model that
        # is not a strands Model would skip it.
        for model in [*models_to_gate(agent), *reach.models.values()]:
            model_backstop.require_backstop(model)
        # Every agent reachable now must attach, or the invocation is
        # refused before it starts: a component (or a tool body) can fetch
        # one and call it past the tool and node gates. An agent that only
        # appears later is still attached strictly by those gates.
        for other in [*reach.held_agents.values(), *reach.tool_agents.values()]:
            try:
                self._attach(other)
            except UngovernableChild as exc:
                raise UngovernedModelUse(
                    f"Watchlight refused the invocation: a {type(other).__name__} this agent "
                    f"can reach cannot be governed ({exc})"
                ) from None
        turn = HostedToolTurn()
        try:
            for model in reach.models.values():
                for request, provider in config_requests(model):
                    try:
                        hosted = normalize_hosted_request(request, provider)
                    except Exception as exc:  # noqa: BLE001 - fail closed
                        raise UngovernedModelUse(
                            "Watchlight refused the invocation: a model's configuration could "
                            "not be read for provider-hosted tools"
                        ) from exc
                    if hosted:
                        gate = await require_hosted_request_allowed(
                            run.handle,
                            request,
                            turn,
                            provider=provider,
                            registered_mcp_servers=getattr(self, "registered_mcp_servers", None),
                            timeout_seconds=self.authorize_timeout_seconds,
                        )
                        run.allowed_hosted.update(gate.tools)
        finally:
            turn.seal()

    async def _authorize_memory_writes(self, run: _Run, agent: Any) -> None:
        """One decision per memory store the agent writes to after its run
        (extracted facts or the raw conversation): action ``create`` on
        ``memory:<store name>``. Anything but allow refuses the invocation."""
        from .model_reach import MemoryWriteRefused, extraction_stores, memory_managers

        for manager in memory_managers(agent):
            for name, mode in extraction_stores(manager):
                try:
                    result = await asyncio.wait_for(
                        run.handle.authorize_action_detailed(
                            action="create",
                            resource=f"memory:{name}",
                            context={"memory_write": {"store": name, "mode": mode}},
                        ),
                        timeout=self.authorize_timeout_seconds,
                    )
                except _TERMINAL_ERRORS:
                    raise
                except Exception as exc:  # noqa: BLE001 - fail closed
                    raise MemoryWriteRefused(
                        f"Watchlight refused the invocation: the write to memory store "
                        f"'{name}' could not be authorized"
                    ) from exc
                if not isinstance(result, AuthorizeResult) or not result.is_allow():
                    raise MemoryWriteRefused(
                        f"Watchlight refused the invocation: writing to memory store '{name}' "
                        f"after the run is not allowed"
                    )

    # ── multi-agent orchestrator hooks ──────────────────────────────

    async def _before_multi_agent_invocation(self, event: BeforeMultiAgentInvocationEvent) -> None:
        await self._open_run(event.source, event.invocation_state)

    async def _before_node_call(self, event: BeforeNodeCallEvent) -> None:
        if event.cancel_node:
            return
        run = self._find_run(event.source, event.invocation_state)
        if run is None or run.closed:
            event.cancel_node = _NO_RUN_TEXT
            return
        nodes = getattr(event.source, "nodes", None) or {}
        node = nodes.get(event.node_id) if isinstance(nodes, Mapping) else None
        executor = getattr(node, "executor", None)
        try:
            self._attach(executor)
        except UngovernableChild as exc:
            logger.warning("[DENY-NODE] node %r: %s; cancelled", event.node_id, exc)
            event.cancel_node = (
                f"Refused by Watchlight: node {event.node_id!r} runs an agent "
                "Watchlight cannot govern, so it was not run."
            )

    async def _after_multi_agent_invocation(self, event: AfterMultiAgentInvocationEvent) -> None:
        run = self._find_run(event.source, event.invocation_state)
        if run is None:
            return
        state = getattr(event.source, "state", None)
        status = getattr(state, "completion_status", None) or getattr(state, "status", None)
        if status == Status.INTERRUPTED:
            await self._suspend_run(run)
        elif status == Status.COMPLETED:
            await self._close_run(run, None)
        else:
            await self._close_run(run, InvocationFailed(str(getattr(status, "value", status))))
