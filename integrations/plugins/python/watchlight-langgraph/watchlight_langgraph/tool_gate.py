"""Every tool LangGraph's ``ToolNode`` runs inside a governed run is decided
before it runs.

``create_agent``, ``create_react_agent`` and hand-built graphs all execute
tools through ``ToolNode``. Its two innermost methods,
``_execute_tool_sync`` and ``_execute_tool_async``, are the ones that call
``tool.invoke`` / ``tool.ainvoke``, after any ``wrap_tool_call`` the user
added. They are wrapped once, at class level, when the first run starts.
The run a tool call acts for is the one core's attribution resolver names
in the calling context (:func:`watchlight_core.attribution.resolve_run`,
the resolver egress uses): the sub-agent ``spawn_subagent`` bound there,
its nearest live ancestor once it completed normally, else the root
``start_run`` bound. The wrap authorizes the call against that run, with
the semantics of ``governed_tool_call``:

* Allow: the tool runs, under a single-use grant for this run, call id and
  tool name, and with its body marked.
* Deny: :class:`ToolDenied`, and the tool body never runs.
* Needs approval: the graph pauses through ``interrupt()``; on resume the
  call is authorized again with the approval token.
* Policy unreachable: refused.

Every other tool start in the process, while any governed run is live, is
refused by the shared LangChain backstop
(:mod:`watchlight_core.langchain_tool_backstop`): a plain
``BaseTool.invoke``, ``callbacks=[]``, a raw thread, a fresh context.
A model start that binds tools is the acting run's own turn; inside that
run's tool body (unless a sub-agent spawned there is acting), or in a
context with no run, it is refused. A refusal never falls back to another
run.

With no governed run live, nothing changes. If LangGraph no longer has the
two methods, ``start_run`` refuses: the plugin never falls back to only
observing.
"""

from __future__ import annotations

import asyncio
import functools
import threading
from typing import Any, Callable, Dict, List, Optional, Tuple

from watchlight_core import (
    GovernanceUnavailable,
    WatchlightError,
    redacted_arg_metadata,
)
from watchlight_core import attribution
from watchlight_core import langchain_tool_backstop as backstop

#: The wrapped ``ToolNode`` methods: (name, is_async).
_TARGETS: Tuple[Tuple[str, bool], ...] = (
    ("_execute_tool_sync", False),
    ("_execute_tool_async", True),
)
_MARK = "__watchlight_tool_gate__"

#: Seconds a synchronous tool call waits for its decision on the run's loop.
DECISION_TIMEOUT_SECONDS = 30.0

_lock = threading.Lock()
#: Every LangGraph run open now, from the moment ``start_run``,
#: ``adopt_run`` or ``spawn_subagent`` returns it until it completes or
#: is terminated, whether or not it was entered with ``async with``.
_live: List["_Run"] = []
_installed = False


class SiblingSubagentLive(GovernanceUnavailable):
    """``spawn_subagent`` was called in a context where another live
    sub-agent is bound. The new child would take over that context, and
    that sub-agent's later work there would be made with the new child's
    authority, so the spawn is refused."""


class _Run:
    """An open run: its handle and the loop it was opened on."""

    def __init__(self, handle: Any, loop: asyncio.AbstractEventLoop) -> None:
        self.handle = handle
        self.loop = loop


def _live_handles() -> List[Any]:
    with _lock:
        return [run.handle for run in _live]


def _entry(handle: Any) -> Optional[_Run]:
    with _lock:
        for run in _live:
            if run.handle is handle:
                return run
    return None


def _acting() -> Optional[_Run]:
    """The LangGraph run acting in this context, as core's attribution
    resolver decides it (the bound sub-agent, its nearest live ancestor
    after a normal completion, else the bound root). ``None`` when
    resolution refuses or names a run of another plugin."""
    handle = attribution.resolve_run().run_handle()
    return _entry(handle) if handle is not None else None


def _acting_handle() -> Optional[Any]:
    run = _acting()
    return run.handle if run is not None else None


def register(handle: Any) -> None:
    """Mark ``handle`` open, on the running loop. Called when a run or
    sub-agent handle is handed to the caller."""
    run = _Run(handle, asyncio.get_running_loop())
    with _lock:
        if not any(r.handle is handle for r in _live):
            _live.append(run)


def unregister(handle: Any) -> None:
    with _lock:
        _live[:] = [r for r in _live if r.handle is not handle]


def refuse_live_sibling(spawner: Any) -> None:
    """Raise :class:`SiblingSubagentLive` when the sub-agent bound in this
    context is live and is not ``spawner``: a sibling, a grandchild, or any
    other live binding. The new child would take over the context and that
    sub-agent's later work here would act with the new child's authority.
    Nesting (the bound sub-agent spawning its own child) and a bound child
    that has ended are not affected."""
    from watchlight_core.run_handle import _current_subagent_handle

    bound = _current_subagent_handle.get()
    if bound is None or bound is spawner:
        return
    if attribution.resolve_run().run_handle() is not bound:
        return  # ended, normally or by a decision: it no longer acts here
    raise SiblingSubagentLive(
        "Watchlight refused the spawn: another live sub-agent is bound in this "
        "context, and the new one would act with its authority. Complete it "
        "first, or spawn each sub-agent in an asyncio task created before any "
        "sub-agent is bound."
    )


# ─── Install and verify ─────────────────────────────────────────────


def _tool_node_class() -> Any:
    try:
        from langgraph.prebuilt import ToolNode
    except Exception as exc:  # noqa: BLE001 - fail closed
        raise GovernanceUnavailable(
            "Watchlight refused the run: LangGraph's ToolNode could not be imported, "
            "so its tool calls cannot be decided"
        ) from exc
    return ToolNode


def install() -> None:
    """Wrap ``ToolNode``'s tool execution once, and register the runs with
    the shared backstop. Raises :class:`GovernanceUnavailable` if LangGraph
    lacks a target."""
    global _installed
    tool_node = _tool_node_class()
    with _lock:
        if not _installed:
            for name, is_async in _TARGETS:
                original = tool_node.__dict__.get(name)
                if original is None or not callable(original):
                    raise GovernanceUnavailable(
                        f"Watchlight refused the run: LangGraph's ToolNode has no {name}, "
                        "so its tool calls cannot be decided"
                    )
                if not getattr(original, _MARK, False):
                    setattr(tool_node, name, _wrap(original, is_async))
            _installed = True
    backstop.install(_live_handles, acting_run=_acting_handle)
    verify()


def verify() -> None:
    """Refuse with :class:`GovernanceUnavailable` unless both wraps are in
    place on ``ToolNode``."""
    tool_node = _tool_node_class()
    for name, _ in _TARGETS:
        if not getattr(tool_node.__dict__.get(name), _MARK, False):
            raise GovernanceUnavailable(
                f"Watchlight refused the run: the tool gate on ToolNode.{name} is not in place"
            )


# ─── The decision ───────────────────────────────────────────────────


def _call_of(request: Any) -> Tuple[str, Any, Optional[str]]:
    call = getattr(request, "tool_call", None)
    if not isinstance(call, dict) or not isinstance(call.get("name"), str):
        raise GovernanceUnavailable("Watchlight refused a tool call it could not read")
    call_id = call.get("id")
    return call["name"], call.get("args"), call_id if isinstance(call_id, str) else None


def _context(args: Any, call_id: Optional[str]) -> Dict[str, Any]:
    """Authorize context: value-free argument metadata (names, count,
    types), the same key and shape as the other plugins. An argument
    value may hold a credential or personal data and never leaves."""
    return {"tool_args": redacted_arg_metadata(args)}


async def _authorize(
    handle: Any, name: str, context: Dict[str, Any], token: Optional[str]
) -> Any:
    intent = {"approval_token": token} if token is not None else None
    return await handle.authorize_action_detailed(
        action="execute", resource=name, intent=intent, context=context
    )


def _outcome(result: Any, name: str, retry: bool) -> Optional[str]:
    """``None`` to run the tool, or the approval request id to pause on.
    Raises :class:`ToolDenied` for anything else."""
    from .governance import ToolDenied

    if result.is_allow():
        return None
    if result.is_deny() or retry:
        raise ToolDenied(name, result.reason or "policy denied")
    if not result.approval_request_id:
        raise ToolDenied(
            name, "needs_approval signalled but no approval_request_id was provided"
        )
    return result.approval_request_id


def _pause(name: str, result: Any) -> str:
    """Pause the graph for a human approval; the resumed approval token."""
    from langgraph.types import interrupt

    from .governance import ToolDenied, build_interrupt_payload

    token = interrupt(build_interrupt_payload(tool_name=name, intent={}, result=result))
    if not isinstance(token, str) or not token:
        raise ToolDenied(
            name, "workflow resumed with an invalid approval_token; refusing the action"
        )
    return token


async def _decide_async(run: _Run, request: Any) -> Tuple[str, Optional[str]]:
    name, args, call_id = _call_of(request)
    context = _context(args, call_id)
    result = await _authorize(run.handle, name, context, None)
    if _outcome(result, name, retry=False) is not None:
        token = _pause(name, result)
        _outcome(await _authorize(run.handle, name, context, token), name, retry=True)
    return name, call_id


def _decide_sync(run: _Run, request: Any) -> Tuple[str, Optional[str]]:
    """The same decision for a synchronous tool call: authorized on the
    run's loop (where its backend client lives), never on that loop's own
    thread, which would wait on itself."""
    name, args, call_id = _call_of(request)
    context = _context(args, call_id)

    def on_run_loop(token: Optional[str]) -> Any:
        loop = run.loop
        if loop.is_closed() or not loop.is_running():
            raise GovernanceUnavailable(
                "Watchlight refused a tool call: its run's loop has stopped"
            )
        try:
            running = asyncio.get_running_loop()
        except RuntimeError:
            running = None
        if running is loop:
            raise GovernanceUnavailable(
                "Watchlight refused a synchronous tool call on its run's own event loop "
                "thread: the decision would wait on itself"
            )
        future = asyncio.run_coroutine_threadsafe(
            _authorize(run.handle, name, context, token), loop
        )
        try:
            return future.result(DECISION_TIMEOUT_SECONDS)
        except BaseException:
            future.cancel()
            raise

    result = on_run_loop(None)
    if _outcome(result, name, retry=False) is not None:
        token = _pause(name, result)
        _outcome(on_run_loop(token), name, retry=True)
    return name, call_id


def _refused(exc: BaseException) -> BaseException:
    """``exc`` unchanged when it is a decision, a Watchlight refusal (one
    that says how to fix it, such as a run not entered) or a graph
    interrupt; any other failure refuses the call (fail closed)."""
    from langgraph.errors import GraphBubbleUp

    from .governance import ToolDenied

    if isinstance(exc, (ToolDenied, WatchlightError, GraphBubbleUp)):
        return exc
    return GovernanceUnavailable(
        "Watchlight refused a tool call: it could not be decided"
    )


def _is_synthetic(request: Any) -> bool:
    """Watchlight's own ``declare_intent`` tool: never authorized (its
    carve-out); it grants its own start, for its own run only."""
    from .synthetic_tools import is_synthetic_tool

    return is_synthetic_tool(getattr(request, "tool", None))


def _publish_soon(run: _Run) -> None:
    """From a synchronous tool call: publish this run's backstop refusals
    on its loop without waiting. Whatever cannot be scheduled is published
    when the run completes or is terminated."""
    loop = run.loop
    if loop.is_closed() or not loop.is_running():
        return
    try:
        asyncio.run_coroutine_threadsafe(publish_tool_gate_refusals(run.handle), loop)
    except RuntimeError:
        pass


# ─── The wraps ──────────────────────────────────────────────────────


def _wrap(original: Callable[..., Any], is_async: bool) -> Callable[..., Any]:
    """With no LangGraph run acting in this context, the call goes on to
    LangChain's tool start, where the backstop refuses it while any
    governed run is live. Nothing falls back to another run."""
    if is_async:

        @functools.wraps(original)
        async def execute_async(
            self: Any, request: Any, *args: Any, **kwargs: Any
        ) -> Any:
            run = _acting()
            if run is None or _is_synthetic(request):
                return await original(self, request, *args, **kwargs)
            try:
                name, call_id = await _decide_async(run, request)
            except BaseException as exc:
                refusal = _refused(exc)
                if refusal is exc:
                    raise
                raise refusal from exc
            try:
                with backstop.grant_tool_start(
                    call_id, name, run.handle, body="binding"
                ):
                    return await original(self, request, *args, **kwargs)
            finally:
                await publish_tool_gate_refusals(run.handle)

        wrapped: Callable[..., Any] = execute_async
    else:

        @functools.wraps(original)
        def execute_sync(self: Any, request: Any, *args: Any, **kwargs: Any) -> Any:
            run = _acting()
            if run is None or _is_synthetic(request):
                return original(self, request, *args, **kwargs)
            try:
                name, call_id = _decide_sync(run, request)
            except BaseException as exc:
                refusal = _refused(exc)
                if refusal is exc:
                    raise
                raise refusal from exc
            try:
                with backstop.grant_tool_start(
                    call_id, name, run.handle, body="binding"
                ):
                    return original(self, request, *args, **kwargs)
            finally:
                _publish_soon(run)

        wrapped = execute_sync
    setattr(wrapped, _MARK, True)
    return wrapped


# ─── Lineage ────────────────────────────────────────────────────────


async def publish_tool_gate_refusals(handle: Any) -> None:
    """Publish, value-free, what the backstop refused under ``handle``. The
    refusal itself already held; a failure to publish is counted and
    logged, never raised."""
    from watchlight_core import get_logger

    from .traces import _RESOURCE_PREFIX_TOOL

    for refusal in backstop.take_refusals(handle):
        try:
            if refusal.kind == "tool":
                await handle.publish_observation(
                    event_type="tool_call_observed",
                    payload={
                        "tool": {
                            "resource_type": "tool",
                            "identifier": refusal.name,
                            "endpoint": f"{_RESOURCE_PREFIX_TOOL}{refusal.name}",
                        },
                        "action": {"action": "invoke"},
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
                            "endpoint": f"langgraph://model/{refusal.name}",
                        },
                        "method": "POST",
                        "path": "/v1/messages",
                        "response_status": 403,
                    },
                    extra_metadata={"backstop": True, "decision": "Deny"},
                )
        except Exception:  # noqa: BLE001 - the refusal itself already held
            backstop.record_emit_failure()
            get_logger("watchlight_langgraph.tool_gate").warning(
                "backstop refusal could not be published to lineage (kind=%s)",
                refusal.kind,
                exc_info=True,
            )
