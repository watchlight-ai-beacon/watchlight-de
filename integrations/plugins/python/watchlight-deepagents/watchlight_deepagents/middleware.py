"""``WatchlightGovernanceMiddleware`` — the in-process decision layer.

Binds Watchlight governance to ``deepagents`` through the public
LangChain v1 ``AgentMiddleware`` protocol — **no monkey-patching**
(``deepagents`` is not the Pydantic-AI exception). The hook mapping:

===========================  =========================================
Hook                         Governance concern
===========================  =========================================
``before_agent``             ``start_run`` — open the APDP session,
                             fetch the pre-flight ConstraintManifest,
                             mint the root ``RunHandle``, install the
                             sidecar. Fail-closed: APDP down /
                             unregistered slug ⇒ raise, the model loop
                             never starts.
``before_model``             Quarantine check — halt if the handle was
                             quarantined mid-run.
``wrap_model_call``          ``api_request_observed`` (the real egress
                             governance of the LLM HTTP call is done
                             out-of-process at the wl-proxy sidecar).
``wrap_tool_call``           ``authorize_action`` — the authoritative
                             Cedar gate. Deny ⇒ a ``ToolMessage`` error
                             instead of running the tool. Special-cases
                             the ``task`` tool (sub-agent spawn) and the
                             synthetic ``watchlight.declare_intent``.
``after_agent``              ``complete`` / ``terminate`` — close the
                             session, emit the terminal lifecycle event.
``tools``                    Registers the synthetic
                             ``watchlight.declare_intent`` tool in
                             greenfield mode.
===========================  =========================================

The load-bearing sub-agent invariant: the ``task`` tool interception
spawns an **attenuated child handle** (strict-subset gated server-side
at wl-apdp) and the child governance middleware injected into each
``SubAgent.middleware`` authorizes every child action against the
**child's** handle, never the root's.

``deepagents`` runs on the async LangGraph runtime. Governance is bound
to the **async** hook variants (``abefore_agent`` / ``awrap_tool_call``
/ …), which fire on ``ainvoke`` / ``astream`` — the supported governed
path for v1. The **sync** hooks fail closed (they refuse rather than run
ungoverned) — see :func:`_sync_unsupported` and the open question in the
package README.
"""

from __future__ import annotations

import contextvars
import uuid
from dataclasses import dataclass
from typing import Any, Dict, Optional

from watchlight_core import GovernanceUnavailable, get_logger, summarize_arg_keys

from watchlight_core import langchain_tool_backstop as backstop
from watchlight_core import root_admission
from .plugin import RunHandle, WatchlightDeepAgentsPlugin
from .subagents import (
    TASK_TOOL_NAME,
    requested_scope_for_subagent,
    resolve_subagent_slug,
)
from .synthetic_tools import build_declare_intent_tool
from .traces import (
    redacted_arg_metadata,
    redacted_input_summary,
    resolve_action_verb,
    tool_resource_uri,
)

logger = get_logger("watchlight_deepagents.middleware")

#: State-schema key threaded through the graph carrying the run token
#: that keys the active :class:`RunHandle` in the process-local registry.
#: A serialisable string (not the handle object) so a checkpointer can
#: persist the state channel without choking on a live client.
STATE_TOKEN_KEY = "wl_run_token"


@dataclass
class _RunEntry:
    handle: RunHandle
    cvtoken: contextvars.Token
    is_root: bool


#: Process-local registry of active run handles keyed by run token. The
#: token lives in graph state; the handle stays out of the (potentially
#: checkpointed) state channel.
_HANDLE_REGISTRY: Dict[str, _RunEntry] = {}

#: Best-effort contextvar copy of the active handle. Read by the
#: synthetic ``declare_intent`` tool (which has no access to graph
#: state) and as a fallback when the state token is missing. Within a
#: single ``ainvoke`` the contextvar is stable across all hooks
#: (same task tree); concurrent sub-agent tasks copy it independently.
_ACTIVE_HANDLE: contextvars.ContextVar[Optional[RunHandle]] = contextvars.ContextVar(
    "watchlight_deepagents._active_handle", default=None
)


@dataclass
class _SpawnGrant:
    """The child handle one ``task`` spawn produced, granted to exactly
    one child graph while that ``task`` call is running."""

    handle: RunHandle
    claimed: bool = False
    revoked: bool = False


#: Set by the parent's ``task`` interception for the duration of the
#: sub-agent graph it runs, and reset when that call ends. The child
#: governance middleware accepts ONLY the handle granted here — never
#: whatever happens to be in the SDK's sub-agent context variable, which
#: can still hold an earlier sibling's handle.
_SPAWN_GRANT: contextvars.ContextVar[Optional[_SpawnGrant]] = contextvars.ContextVar(
    "watchlight_deepagents._spawn_grant", default=None
)


#: How a nested deep agent stays governed, for the escaped-root refusal.
_ESCAPE_HINT = (
    "Run sub-agents through the governed task tool "
    "(create_governed_deep_agent(subagents=...)) so they run as attenuated "
    "sub-agents, or wrap an independent run in watchlight_deepagents.root_run()."
)


class root_run(root_admission.RootRun):
    """Declare an independent governed root deep agent run.

    While a governed run is live in the process, a governed deep agent that
    would open a root outside it (built and invoked inside a tool, from a
    thread, an executor or a fresh ``contextvars.Context``) is refused with
    :class:`watchlight_core.NestedRunEscapedError` before its first model
    turn. Independent roots that run at the same time are declared::

        async with root_run():
            await agent.ainvoke({...})

    Also a decorator (``@root_run()`` or ``@root_run``) on a sync or async
    function. The server decides ``Action::"open_declared_root"`` with the root
    execution ids live in the process. Refused inside a live governed run,
    and for an agent whose sub-agent spawn was refused in a run tree that
    is still live.
    """

    def _in_live_run(self) -> bool:
        # A tool body does not see ``_ACTIVE_HANDLE`` (LangGraph runs the
        # tools node in its own context); the backstop marks it instead.
        return any(
            root_admission.handle_is_live(handle)
            for handle in (_ACTIVE_HANDLE.get(), backstop.tool_body_handle())
        )

    def _enter_context(self) -> None:
        self._context_tokens = (_ACTIVE_HANDLE.set(None), _SPAWN_GRANT.set(None))

    def _exit_context(self) -> None:
        handle, grant = self._context_tokens
        _SPAWN_GRANT.reset(grant)
        _ACTIVE_HANDLE.reset(handle)


def current_active_handle() -> Optional[RunHandle]:
    """Return the governance handle active in the current async context,
    or ``None``. Public read-only accessor used by the synthetic tool.
    """
    return _ACTIVE_HANDLE.get()


def _state_token(state: Any) -> Optional[str]:
    """The run token carried in graph ``state``, or ``None``."""
    if isinstance(state, dict):
        return state.get(STATE_TOKEN_KEY)
    return getattr(state, STATE_TOKEN_KEY, None)


def _is_graph_control_flow(exc: BaseException) -> bool:
    """LangGraph's control-flow exceptions (``interrupt()``, a
    ``Command`` to the parent graph) pause or redirect a run; they do not
    end it, so they never close the run."""
    try:
        from langgraph.errors import GraphBubbleUp
    except ImportError:  # pragma: no cover — stub-only environments
        return False
    return isinstance(exc, GraphBubbleUp)


async def _close_run_on_escape(state: Any, exc: BaseException) -> None:
    """Close the run whose token ``state`` carries when an exception
    escapes a governance hook and ends the agent run.

    LangGraph never runs ``after_agent`` for a run that raised, so without
    this a failing run recorded no terminal lineage event and its handle
    stayed in the registry. The run closes under its OWN handle (its own
    agent and credential): ``execution_failed`` for an ordinary failure,
    the quarantined ``execution_completed`` for a quarantined handle.
    Only a handle found by the run's own token is closed, never the
    contextvar fallback, so an error can never close another run.
    Best-effort: the original exception is always re-raised by the
    caller.
    """
    if _is_graph_control_flow(exc):
        return
    token = _state_token(state)
    entry = _HANDLE_REGISTRY.pop(token, None) if token else None
    if entry is None:
        return
    try:
        _ACTIVE_HANDLE.reset(entry.cvtoken)
    except (ValueError, LookupError):  # different context — best-effort
        pass
    handle = entry.handle
    await _publish_backstop_refusals(handle)
    try:
        if handle.is_quarantined:
            # ``terminate`` is a no-op on a quarantined handle; the
            # quarantined completion is its terminal event.
            await handle.complete()
        if entry.is_root:
            await handle.__aexit__(type(exc), exc, exc.__traceback__)
        else:
            await handle.terminate(reason=f"run_failed: {type(exc).__name__}")
    except Exception:  # noqa: BLE001 — teardown must not mask the error
        logger.debug("close on escaped exception failed", exc_info=True)


def _resolve_handle(state: Any) -> Optional[RunHandle]:
    """Resolve the active handle from graph ``state`` (via the run
    token) with a contextvar fallback. Returns ``None`` when no handle
    is bound — callers MUST fail closed on ``None``.
    """
    token = _state_token(state)
    if token is not None:
        entry = _HANDLE_REGISTRY.get(token)
        if entry is not None:
            return entry.handle
    return _ACTIVE_HANDLE.get()


def _within_granted_tools(
    handle: Any, tool_name: Optional[str], action: str, resource: str
) -> bool:
    """Whether ``handle`` may call this tool under its granted scope.

    A root run has no granted scope and is decided by policy alone. A
    sub-agent may call a tool only when its spawn granted it: the tool
    name or the resource is in ``granted_scope.allowed_tools``. The action
    is never matched: it is a generic verb (``execute``, ``read``,
    ``write``) that says how a tool is invoked, not which tool, so a grant
    naming the sandbox shell tool ``execute`` must not pass every call this
    plugin authorizes as ``execute`` (wl-apdp matches on the tool identity
    the same way). An empty list grants nothing. A spawned handle with no
    readable granted scope is refused (fail-closed).
    """
    granted = getattr(handle, "granted_scope", None)
    if granted is None:
        return getattr(handle, "spawned_execution_id", None) is None
    allowed = getattr(granted, "allowed_tools", None)
    if not isinstance(allowed, (list, tuple)):
        return False
    del action  # a generic verb, never the tool (see above)
    names = {name for name in (tool_name, resource) if name}
    return any(isinstance(t, str) and t in names for t in allowed)


def _sync_unsupported(hook: str) -> None:
    """Fail closed on the synchronous invocation path.

    ``deepagents`` runs on the async LangGraph runtime; Watchlight
    governance in v1 binds to the async hook variants. A synchronous
    ``invoke`` would otherwise reach these no-op sync hooks and run
    **ungoverned** — a governance bypass. Per the enterprise
    fail-closed mandate we refuse rather than degrade.
    """
    raise GovernanceUnavailable(
        f"WatchlightGovernanceMiddleware.{hook} was called on the "
        f"synchronous invocation path. Watchlight governance for "
        f"deepagents binds to the async runtime — invoke the agent with "
        f"`await agent.ainvoke(...)` / `agent.astream(...)`. Synchronous "
        f"`invoke` is refused rather than run ungoverned (fail-closed)."
    )


def _resolve_agent_middleware_base() -> type:
    """Import the real LangChain v1 ``AgentMiddleware`` base class.

    Imported lazily so ``import watchlight_deepagents`` succeeds without
    ``deepagents`` / ``langchain`` installed — the stub-based unit tests
    build the middleware against a local stub base instead.
    """
    try:
        from langchain.agents.middleware.types import AgentMiddleware
    except ImportError as exc:  # pragma: no cover — defensive
        raise ImportError(
            "watchlight_deepagents requires `deepagents` (which pulls in "
            "langchain>=1.3). Install via `pip install watchlight-deepagents` "
            "or `pip install deepagents`."
        ) from exc
    return AgentMiddleware


def _live_handles() -> list:
    """The governed runs live in this process (for the backstop)."""
    return [entry.handle for entry in list(_HANDLE_REGISTRY.values())]


async def _publish_backstop_refusals(handle: RunHandle) -> None:
    """Publish, value-free, what the backstop refused under ``handle``."""
    for refusal in backstop.take_refusals(handle):
        try:
            if refusal.kind == "tool":
                await handle.publish_observation(
                    event_type="tool_call_observed",
                    payload={
                        "tool": {
                            "resource_type": "tool",
                            "identifier": refusal.name,
                            "endpoint": tool_resource_uri(refusal.name, {}),
                        },
                        "action": {"action": resolve_action_verb(refusal.name)},
                        "decision": "Deny",
                    },
                    extra_metadata={"backstop": True},
                )
            else:
                await handle.publish_observation(
                    event_type="api_request_observed",
                    payload={
                        "resource": {
                            "resource_type": "model",
                            "identifier": refusal.name,
                            "endpoint": f"deepagents://model/{refusal.name}",
                        },
                        "method": "POST",
                        "path": "/v1/messages",
                        "response_status": 403,
                    },
                    extra_metadata={"backstop": True, "decision": "Deny"},
                )
        except Exception:  # noqa: BLE001 — the refusal itself already held
            # The refusal stood, but lineage misses it: an audit gap, so it
            # is logged at warning and counted (backstop.emit_failures()).
            backstop.record_emit_failure()
            logger.warning(
                "backstop refusal could not be published to lineage (kind=%s)",
                refusal.kind,
                exc_info=True,
            )


def build_governance_middleware(
    *,
    plugin: WatchlightDeepAgentsPlugin,
    agent_slug: str,
    subagent_scopes: Dict[str, Dict[str, Any]],
    subagent_slugs: Dict[str, str],
    is_child: bool,
    child_governance_guaranteed: bool = False,
    base_cls: Optional[type] = None,
) -> Any:
    """Build a :class:`WatchlightGovernanceMiddleware` instance.

    ``child_governance_guaranteed`` MUST be ``True`` only when the caller
    has *already* injected a child governance middleware into every
    spawnable sub-agent (i.e. the governed :func:`create_governed_deep_agent`
    factory path). When ``False`` (the default, and the only safe value
    for the standalone ``plugin.middleware()`` / "Option B" path, which
    cannot reach the ``subagents=`` list) the middleware **refuses every
    ``task`` sub-agent spawn** at runtime — because it cannot prove the
    child loop is governed by an attenuated handle, and a sub-agent that
    might run ungoverned must not run (fail-closed).

    ``base_cls`` lets tests inject a stub ``AgentMiddleware`` base so the
    governance logic is exercised without installing ``deepagents``. In
    production it defaults to the real LangChain base.
    """
    if base_cls is None:
        base_cls = _resolve_agent_middleware_base()
    # Once per process: refuse tool and model starts no governed agent
    # authorized while a governed run is live.
    backstop.install(_live_handles)
    cls = _make_middleware_class(base_cls)
    return cls(
        plugin=plugin,
        agent_slug=agent_slug,
        subagent_scopes=subagent_scopes,
        subagent_slugs=subagent_slugs,
        is_child=is_child,
        child_governance_guaranteed=child_governance_guaranteed,
    )


#: Cache the generated subclass per base so repeated binds reuse it
#: (and ``isinstance`` checks stay stable).
_CLASS_CACHE: Dict[type, type] = {}


def _governance_state_schema(base_cls: type) -> Optional[type]:
    """The graph-state schema that carries :data:`STATE_TOKEN_KEY`.

    LangGraph keeps only the state keys some middleware DECLARES: a node
    update for an undeclared key is dropped. Without this schema the run
    token ``abefore_agent`` returns never reached graph state, so on a
    real ``deepagents`` graph every tool call found no run handle and
    was refused, and ``aafter_agent`` found no token and never closed
    the run: no terminal lineage event for the root.

    The key is ``PrivateStateAttr`` (omitted from the graph's input and
    output schema): a caller cannot inject a token through ``ainvoke``
    input, a run's token never leaks in its result, and deepagents does
    not copy it into a sub-agent's state or back out of it (the child
    registers its own).

    Returns ``None`` for a stub base (unit tests) or when LangChain's
    middleware types are unavailable; the base's own schema then stands.
    """
    try:
        from langchain.agents.middleware.types import AgentMiddleware

        from ._state_schema import WatchlightGovernanceState
    except ImportError:  # pragma: no cover — stub-only environments
        return None
    if not (isinstance(base_cls, type) and issubclass(base_cls, AgentMiddleware)):
        return None
    if STATE_TOKEN_KEY not in WatchlightGovernanceState.__annotations__:
        raise RuntimeError(  # pragma: no cover — a rename must move both
            f"governance state schema does not declare {STATE_TOKEN_KEY!r}"
        )
    return WatchlightGovernanceState


def _make_middleware_class(base_cls: type) -> type:
    """Define ``WatchlightGovernanceMiddleware`` as a subclass of the
    supplied ``AgentMiddleware`` base (real or stub)."""
    cached = _CLASS_CACHE.get(base_cls)
    if cached is not None:
        return cached

    state_schema = _governance_state_schema(base_cls)

    class WatchlightGovernanceMiddleware(base_cls):  # type: ignore[valid-type,misc]
        """Watchlight governance bound to the ``AgentMiddleware`` protocol."""

        # Stable identity used in resolved-stack logs + conformance.
        name = "watchlight_governance"

        def __init__(
            self,
            *,
            plugin: WatchlightDeepAgentsPlugin,
            agent_slug: str,
            subagent_scopes: Dict[str, Dict[str, Any]],
            subagent_slugs: Dict[str, str],
            is_child: bool,
            child_governance_guaranteed: bool = False,
        ) -> None:
            super().__init__()
            self._plugin = plugin
            self._agent_slug = agent_slug
            self._subagent_scopes = subagent_scopes
            self._subagent_slugs = subagent_slugs
            self._is_child = is_child
            self._child_governance_guaranteed = child_governance_guaranteed
            if state_schema is not None:
                # Declare the run-token key so LangGraph keeps it.
                self.state_schema = state_schema
            # Greenfield: contribute the synthetic declare_intent tool.
            # The tool closes over the active-handle contextvar, resolved
            # at call time (the handle does not exist at construction).
            self.tools = build_declare_intent_tool(
                mode=plugin.intent_enforcement_mode,
                handle_getter=current_active_handle,
            )
            # Security: the declare_intent authorize short-circuit keys on
            # this EXACT synthetic-tool INSTANCE, never on a tool-name
            # string. A customer tool that collides with the reserved
            # ``watchlight.declare_intent`` name is NOT our instance, so it
            # does not bypass the Cedar gate.
            self._declare_intent_tool = self.tools[0] if self.tools else None

        # ── lifecycle ────────────────────────────────────────────────

        async def abefore_agent(
            self, state: Any, runtime: Any
        ) -> Optional[Dict[str, Any]]:
            if self._is_child:
                return await self._child_before_agent(state, runtime)
            return await self._root_before_agent(state, runtime)

        async def _root_before_agent(self, state: Any, runtime: Any) -> Dict[str, Any]:
            # start_run establishes the root execution_id BEFORE any
            # model / tool call can fire (ungoverned-request gate). A
            # failure here (APDP down, unregistered agent) propagates —
            # the agent graph never enters the model loop.
            #
            # Admitted first: while a governed run is live in the
            # process, a root outside it is refused here (the agent graph
            # never reaches its model), unless declared with root_run().
            declared = root_admission.declared_root_requested()
            live_roots = root_admission.reserve_root(
                self._agent_slug, declared=declared, hint=_ESCAPE_HINT
            )
            handle: Optional[RunHandle] = None
            try:
                handle = await self._plugin.start_run(
                    self._agent_slug,
                    **({"declared_root": live_roots} if declared else {}),
                )
            finally:
                root_admission.release_root(handle)
            await handle.__aenter__()
            return self._register(handle, is_root=True)

        async def _child_before_agent(self, state: Any, runtime: Any) -> Dict[str, Any]:
            # The child governance middleware authorizes against the
            # CHILD's handle — granted by the parent's ``task``
            # interception for this spawn only. Fail closed unless the
            # grant exists, is unclaimed, is still in force (the ``task``
            # call is running) and its handle is live. A handle merely
            # present in the SDK's sub-agent context variable (for
            # example a completed sibling's) is never accepted.
            from watchlight_core import RunHandleState

            grant = _SPAWN_GRANT.get()
            child = grant.handle if grant is not None else None
            # The grant is set only by this module, from the handle its own
            # ``spawn_subagent`` call returned, so the handle is not checked
            # by type: a host may hand out a delegating wrapper around the
            # SDK's handle (the Developer Edition records refusals that way).
            if (
                grant is None
                or grant.claimed
                or grant.revoked
                or child is None
                or getattr(child, "state", None) != RunHandleState.ACTIVE
            ):
                raise GovernanceUnavailable(
                    "Sub-agent started without a live Watchlight handle "
                    "granted by its own `task` spawn. Refusing to run the "
                    "sub-agent (fail-closed)."
                )
            grant.claimed = True
            # The child handle is already 'entered' by spawn_subagent.
            return self._register(child, is_root=False)

        def _register(self, handle: RunHandle, *, is_root: bool) -> Dict[str, Any]:
            token = f"wlrun_{uuid.uuid4().hex}"
            cvtoken = _ACTIVE_HANDLE.set(handle)
            _HANDLE_REGISTRY[token] = _RunEntry(handle, cvtoken, is_root)
            return {STATE_TOKEN_KEY: token}

        async def aafter_agent(
            self, state: Any, runtime: Any
        ) -> Optional[Dict[str, Any]]:
            token = state.get(STATE_TOKEN_KEY) if isinstance(state, dict) else None
            entry = _HANDLE_REGISTRY.pop(token, None) if token else None
            if entry is None:
                return None
            try:
                _ACTIVE_HANDLE.reset(entry.cvtoken)
            except (ValueError, LookupError):  # different context — best-effort
                pass
            await _publish_backstop_refusals(entry.handle)
            try:
                if entry.is_root:
                    await entry.handle.__aexit__(None, None, None)
                else:
                    await entry.handle.complete()
            except Exception:  # noqa: BLE001 — teardown must not raise
                logger.debug("aafter_agent close failed", exc_info=True)
            return None

        async def abefore_model(
            self, state: Any, runtime: Any
        ) -> Optional[Dict[str, Any]]:
            # Quarantine is sticky and fail-closed: a handle quarantined
            # mid-run (by a prior authorize) must halt the loop. The
            # ``is_quarantined`` predicate is a local read; the actual
            # AgentQuarantinedError is raised by ``authorize_action`` on
            # the short-circuit path, but we surface it early here too.
            handle = _resolve_handle(state)
            if handle is not None and handle.is_quarantined:
                from watchlight_core import AgentQuarantinedError

                decision = handle.quarantine_decision
                if decision is not None:
                    exc = AgentQuarantinedError.from_decision(decision)
                    await _close_run_on_escape(state, exc)
                    raise exc
            return None

        async def awrap_model_call(self, request: Any, handler: Any) -> Any:
            # Observe the model turn. The authoritative egress governance
            # of the actual LLM HTTP call is done out-of-process by the
            # wl-proxy sidecar; this hook is the in-process observe point.
            state = getattr(request, "state", None)
            handle = _resolve_handle(state)
            if handle is None:
                # No governed run for this model turn — fail closed.
                raise GovernanceUnavailable(
                    "No active Watchlight run handle for this model turn; "
                    "refusing (fail-closed)."
                )
            await self._emit_api_request_observed(handle, request)
            try:
                with backstop.governed_model_call():
                    return await handler(request)
            except Exception as exc:
                # A model call that raises ends the run.
                await _close_run_on_escape(state, exc)
                raise

        async def _emit_api_request_observed(
            self, handle: RunHandle, request: Any
        ) -> None:
            try:
                model = getattr(request, "model", None)
                model_name = (
                    getattr(model, "model_name", None)
                    or getattr(model, "model", None)
                    or (model if isinstance(model, str) else None)
                    or "unknown"
                )
                await handle.publish_observation(
                    event_type="api_request_observed",
                    payload={
                        "resource": {
                            "resource_type": "model",
                            "identifier": str(model_name),
                            "endpoint": f"deepagents://model/{model_name}",
                        },
                        "method": "POST",
                        "path": "/v1/messages",
                    },
                )
            except Exception:  # noqa: BLE001 — observability is best-effort
                logger.debug("api_request_observed emit failed", exc_info=True)

        async def _emit_tool_call_observed(
            self,
            handle: RunHandle,
            tool_name: Optional[str],
            tool_args: Dict[str, Any],
            action: str,
            resource: str,
            decision: str,
        ) -> None:
            try:
                await handle.publish_observation(
                    event_type="tool_call_observed",
                    payload={
                        "tool": {
                            "resource_type": "tool",
                            "identifier": tool_name or "unknown",
                            "endpoint": resource,
                        },
                        "action": {"action": action},
                        "decision": decision,
                        # Value-free summary (arg names + types only).
                        # Never stringify raw arg VALUES onto a persisted
                        # ExecutionEvent: a truncated prefix can still
                        # capture a bearer token / PII. Redaction ≠
                        # truncation.
                        "input_summary": redacted_input_summary(tool_args),
                        # Sorted, comma-joined argument KEYS (never values
                        # or types) — the behavioural feature wl-drift's
                        # arg-shape scorer keys its distribution on. None
                        # (field omitted) when tool_args isn't a mapping.
                        **(
                            {"arg_key_summary": _aks}
                            if (_aks := summarize_arg_keys(tool_args))
                            else {}
                        ),
                    },
                )
            except Exception:  # noqa: BLE001 — observability is best-effort
                logger.debug("tool_call_observed emit failed", exc_info=True)

        # ── the authoritative tool gate ──────────────────────────────

        async def awrap_tool_call(self, request: Any, handler: Any) -> Any:
            handle = _resolve_handle(getattr(request, "state", None))
            try:
                return await self._awrap_tool_call(request, handler)
            except Exception as exc:
                # An exception escaping the tool gate (the tool body, a
                # sub-agent run under ``task``, or a quarantine raised by
                # authorize) ends the run.
                if handle is not None:
                    await _publish_backstop_refusals(handle)
                await _close_run_on_escape(getattr(request, "state", None), exc)
                raise
            finally:
                # What the backstop refused inside this call's body.
                if handle is not None:
                    await _publish_backstop_refusals(handle)

        async def _awrap_tool_call(self, request: Any, handler: Any) -> Any:
            tool_call = getattr(request, "tool_call", None) or {}
            tool_name = tool_call.get("name") if isinstance(tool_call, dict) else None
            tool_call_id = (
                tool_call.get("id") if isinstance(tool_call, dict) else None
            ) or "unknown"
            tool_args = (
                tool_call.get("args") if isinstance(tool_call, dict) else None
            ) or {}
            state = getattr(request, "state", None)
            handle = _resolve_handle(state)

            if handle is None:
                # No governed handle for this call — fail closed.
                return self._deny_tool_message(
                    tool_call_id,
                    tool_name,
                    "No active Watchlight run handle; refusing tool call "
                    "(fail-closed).",
                )

            # declare_intent carve-out — the synthetic declare_intent tool
            # MUST NOT round-trip to authorize. It runs inline (mutating
            # the handle's declared intent) and returns to the model.
            #
            # Security: key the short-circuit on our OWN synthetic-tool
            # INSTANCE, not a tool-name string compare. A customer tool
            # that happens to be named ``watchlight.declare_intent`` is a
            # different object, so it falls through to the authoritative
            # Cedar gate below and can never bypass authorization by name
            # collision.
            invoked_tool = getattr(request, "tool", None)
            if (
                self._declare_intent_tool is not None
                and invoked_tool is self._declare_intent_tool
            ):
                with backstop.grant_tool_start(tool_call_id, tool_name, handle, body=True):
                    return await handler(request)

            # The ``task`` tool = sub-agent spawn. Intercept it and let
            # wl-apdp gate the strict-subset attenuation server-side.
            if tool_name == TASK_TOOL_NAME:
                return await self._govern_task_spawn(
                    handle, request, handler, tool_args, tool_call_id
                )

            # Ordinary tool call (customer tool, FS tool, planning). The
            # authoritative Cedar gate.
            return await self._govern_tool_call(
                handle, request, handler, tool_name, tool_args, tool_call_id
            )

        async def _govern_tool_call(
            self,
            handle: RunHandle,
            request: Any,
            handler: Any,
            tool_name: Optional[str],
            tool_args: Dict[str, Any],
            tool_call_id: str,
        ) -> Any:
            action = resolve_action_verb(tool_name)
            resource = tool_resource_uri(tool_name, tool_args)
            from watchlight_core import AgentQuarantinedError

            if not _within_granted_tools(handle, tool_name, action, resource):
                # A sub-agent may call only the tools its spawn granted
                # (empty = none). Checked here as well as by the backend:
                # the in-process engine does not check a child's granted
                # tools on each call, so without this a child could call a
                # tool the parent never gave it.
                await self._emit_tool_call_observed(
                    handle, tool_name, tool_args, action, resource, "Deny"
                )
                return self._deny_tool_message(
                    tool_call_id,
                    tool_name,
                    "Denied by Watchlight: this sub-agent was not granted "
                    "this tool.",
                )

            try:
                result = await handle.authorize_action_detailed(
                    action=action,
                    resource=resource,
                    # Send only value-free arg METADATA (key names, count,
                    # types) to APDP. Raw arg values may carry secrets /
                    # PII; truncating a ``str(tool_args)`` prefix is NOT
                    # redaction and must never reach the authorize context
                    # or the audit log.
                    context={"tool_args": redacted_arg_metadata(tool_args)},
                )
            except AgentQuarantinedError:
                # Sticky quarantine — surface as a hard block and re-raise
                # so the loop halts (quarantine is not a replan-able deny).
                raise
            decision = "Allow" if result.is_allow() else "Deny"
            await self._emit_tool_call_observed(
                handle, tool_name, tool_args, action, resource, decision
            )
            if result.is_allow():
                # Grant this call its one tool start, and mark its body:
                # the process-wide backstop refuses any other.
                with backstop.grant_tool_start(tool_call_id, tool_name, handle, body=True):
                    return await handler(request)
            if result.needs_approval():
                # Human-in-the-loop — do not work around. deepagents'
                # native HumanInTheLoopMiddleware / interrupt_on owns the
                # pause; here we return an error ToolMessage so the model
                # observes the approval requirement rather than silently
                # proceeding.
                return self._deny_tool_message(
                    tool_call_id,
                    tool_name,
                    "Action requires human approval (Watchlight). Pausing; "
                    "resume only on governed operator approval.",
                )
            # Deny — return a ToolMessage so the model observes the
            # refusal and can replan; the tool handler never runs.
            return self._deny_tool_message(
                tool_call_id,
                tool_name,
                # Opaque deny: the server's reason stays in its audit trail.
                "Denied by Watchlight policy.",
            )

        async def _govern_task_spawn(
            self,
            handle: RunHandle,
            request: Any,
            handler: Any,
            tool_args: Dict[str, Any],
            tool_call_id: str,
        ) -> Any:
            # Refuse the spawn unless child governance was guaranteed at
            # construction (the
            # governed factory injected a child middleware into EVERY
            # spawnable sub-agent, including deepagents' auto-added
            # ``general-purpose``). The standalone ``plugin.middleware()``
            # / Option B path cannot reach the ``subagents=`` list, so it
            # cannot prove the child loop is attenuated — spawning would
            # run a child graph with NO Watchlight middleware (its
            # attenuated handle orphaned; its egress attributed to the
            # ROOT's egress token). A sub-agent that might run ungoverned
            # must not run.
            if not self._child_governance_guaranteed:
                return self._deny_tool_message(
                    tool_call_id,
                    TASK_TOOL_NAME,
                    "Sub-agent spawn refused: this agent was constructed "
                    "without guaranteed child governance, so a spawned "
                    "sub-agent could run UNGOVERNED (its attenuated handle "
                    "orphaned). Build the agent with "
                    "`watchlight_deepagents.create_governed_deep_agent(...)`, "
                    "which injects child governance into every sub-agent "
                    "(fail-closed).",
                )
            subagent_type = tool_args.get("subagent_type")
            if not subagent_type:
                return self._deny_tool_message(
                    tool_call_id,
                    TASK_TOOL_NAME,
                    "task tool call missing `subagent_type`; refusing spawn "
                    "(fail-closed).",
                )
            child_slug = resolve_subagent_slug(subagent_type, self._subagent_slugs)
            scope = requested_scope_for_subagent(subagent_type, self._subagent_scopes)
            from watchlight_core import (
                AgentNotRegistered,
                AgentQuarantinedError,
                ScopeAttenuationDenied,
            )

            # The child's intent derives from the task the parent hands it:
            # the ``task`` tool's description is the objective. A scope that
            # pins exactly one intent names the category (wl-apdp requires
            # ``allowed_intents`` to be empty or exactly that category).
            from watchlight_core import plugin_child_intent

            scoped_intents = list(scope.get("allowed_intents") or [])
            child_intent = plugin_child_intent(
                tool_args.get("description") if isinstance(tool_args.get("description"), str) else None,
                category=(
                    scoped_intents[0]
                    if len(scoped_intents) == 1
                    else getattr(self._plugin, "child_intent_category", None)
                ),
                parent=handle,
                fallback_objective=f"deepagents task for {subagent_type}",
            )
            try:
                try:
                    child = await handle.spawn_subagent(
                        child_slug,
                        child_intent=child_intent,
                        allowed_tools=scope.get("allowed_tools"),
                        allowed_resources=scope.get("allowed_resources"),
                        allowed_intents=scope.get("allowed_intents"),
                        max_depth=scope.get("max_depth"),
                        time_budget_seconds=scope.get("time_budget_seconds"),
                        reason=f"deepagents task → {subagent_type}",
                    )
                except BaseException:
                    # The refused child never runs, not even as a declared
                    # root while this tree is live.
                    root_admission.record_refused_spawn(child_slug, handle)
                    raise
                root_admission.register_run(child)
            except ScopeAttenuationDenied as exc:
                # wl-apdp's strict-subset validator rejected the spawn —
                # the requested scope was not a strict subset. No child
                # graph runs.
                return self._deny_tool_message(
                    tool_call_id,
                    TASK_TOOL_NAME,
                    f"Sub-agent spawn denied: the scope requested for "
                    f"'{subagent_type}' is more than the parent can give "
                    f"({exc}).",
                )
            except AgentNotRegistered as exc:
                return self._deny_tool_message(
                    tool_call_id, TASK_TOOL_NAME, f"Sub-agent not registered: {exc}"
                )
            except AgentQuarantinedError:
                raise
            # Grant the child handle to the sub-agent graph this call
            # runs. The child governance middleware (injected into the
            # SubAgent) claims it once in its own before_agent and
            # authorizes the child's actions against it. The grant ends
            # with this call, so no later graph can pick the handle up.
            grant = _SpawnGrant(child)
            grant_token = _SPAWN_GRANT.set(grant)
            try:
                # The ``task`` tool's own start is granted; its body runs a
                # governed sub-agent, so it is not marked as a tool body.
                with backstop.grant_tool_start(tool_call_id, TASK_TOOL_NAME, handle, body=False):
                    return await handler(request)
            finally:
                grant.revoked = True
                try:
                    _SPAWN_GRANT.reset(grant_token)
                except (ValueError, LookupError):  # different context
                    pass
                if not grant.claimed:
                    # No child graph claimed the handle: close it so the
                    # spawned run does not stay open.
                    try:
                        await child.complete()
                    except Exception:  # noqa: BLE001 — best-effort close
                        logger.debug("unclaimed child close failed", exc_info=True)

        def _deny_tool_message(
            self, tool_call_id: str, tool_name: Optional[str], content: str
        ) -> Any:
            from langchain_core.messages import ToolMessage

            return ToolMessage(
                content=content,
                tool_call_id=tool_call_id,
                name=tool_name or "unknown",
                status="error",
            )

        # ── sync path — fail closed (no ungoverned bypass) ───────────

        def before_agent(self, state: Any, runtime: Any) -> Any:
            _sync_unsupported("before_agent")

        def wrap_tool_call(self, request: Any, handler: Any) -> Any:
            _sync_unsupported("wrap_tool_call")

        def wrap_model_call(self, request: Any, handler: Any) -> Any:
            _sync_unsupported("wrap_model_call")

    _CLASS_CACHE[base_cls] = WatchlightGovernanceMiddleware
    return WatchlightGovernanceMiddleware


__all__ = [
    "build_governance_middleware",
    "current_active_handle",
    "STATE_TOKEN_KEY",
]
