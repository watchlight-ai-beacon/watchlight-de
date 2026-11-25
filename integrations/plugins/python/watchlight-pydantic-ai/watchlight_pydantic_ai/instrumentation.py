"""Runtime auto-instrumentation for Pydantic AI ``Agent`` entry points.

This module is the key innovation that lets Watchlight govern
Pydantic AI's multi-agent "agent as composable callable" pattern
with **zero customer code changes**.

Pydantic AI's multi-agent idiom is: a parent agent's ``@agent.tool``
body calls another agent's ``.run()`` directly. The framework has
no native ``spawn_subagent`` hook the plugin could subscribe to —
so without runtime instrumentation, nested ``Agent.run()`` calls
emit as INDEPENDENT root executions with no link back to the
caller's lineage tree.

The fix: a module-private :class:`contextvars.ContextVar` carries
the active parent :class:`watchlight_pydantic_ai.RunHandle`. When
a ``WatchlightPydanticAIPlugin`` is constructed, every entry point
on ``pydantic_ai.Agent`` that starts a run is monkey-patched with
a wrapper that:

1. Reads the active handle from the contextvar.
2. If ``None`` → this call is a root execution; ``plugin.start_run``
   opens a fresh handle just like today.
3. If set (a parent handle is on the stack) → this call is a
   nested invocation; ``parent.spawn_subagent`` opens a child
   handle that propagates ``root_execution_id`` and sets
   ``parent_execution_id``.
4. Pushes the new handle onto the contextvar for the duration of
   the call. ``contextvars.Token``-based reset in a ``try/finally``
   guarantees the parent's handle is restored even on exceptions
   and ``asyncio.gather`` doesn't cross-pollinate concurrent runs
   (each task gets its own logical context).
5. Calls ``handle.complete()`` on success / ``handle.terminate()``
   on exception so the audit chain reflects the actual outcome.

The patch is **idempotent**: each ``Agent`` method is tagged with
a sentinel attribute after first install; subsequent installs
detect the tag and skip. This is essential because the
``WatchlightPydanticAIPlugin`` constructor is the install point —
operators creating two plugin instances in the same process (test
harnesses, multi-tenant fanout) would otherwise double-wrap.

The patch is also **reversible**: :func:`uninstall_instrumentation`
restores the original bound methods. Useful for tests that need a
clean slate and for customer-side cleanup if they want to remove
governance for a specific code path.

Customer code stays vanilla — they keep writing
``await agent.run(...)`` at every level of their multi-agent
graph. The plugin transparently stitches each call into one
lineage tree under one workflow root.
"""

from __future__ import annotations

import asyncio
import contextvars
import functools
import threading
import weakref
from typing import TYPE_CHECKING, Any, Callable, Dict, List, Optional, Tuple

from watchlight_core import (
    GovernanceUnavailable,
    RunHandleState,
    WatchlightError,
    get_logger,
    root_admission,
)

if TYPE_CHECKING:
    from .plugin import RunHandle, WatchlightPydanticAIPlugin

logger = get_logger("watchlight_pydantic_ai.instrumentation")

__all__ = [
    "current_handle",
    "root_run",
    "install_instrumentation",
    "uninstall_instrumentation",
    "is_instrumented",
    "resolve_agent_slug",
    "inject_synthetic_tools",
]


# ─── Contextvar carrying the active parent RunHandle ──────────────────

# Module-private ContextVar. Pydantic AI users never touch this — the
# instrumentation wrapper sets it on entry and resets it on exit. The
# Python contextvars module guarantees the value is isolated per
# logical context, which means:
#
#   * Concurrent ``asyncio.gather([agent_a.run(), agent_b.run()])``
#     calls each run in a child context and never observe each
#     other's parent handle.
#   * Within a single coroutine, ``await`` points propagate the
#     contextvar transparently so a nested call deep inside the
#     parent's tool body still sees the parent's handle.
#   * ``run_sync`` triggers a fresh asyncio loop via
#     ``asyncio.run`` (or its equivalent) — contextvars are
#     inherited across that boundary too.
_current_handle: contextvars.ContextVar[Optional["RunHandle"]] = (
    contextvars.ContextVar("watchlight_pydantic_ai.current_handle", default=None)
)

# Re-entrancy guard. Pydantic AI implements ``Agent.run`` internally
# as ``async with self.iter(...)`` (and likewise for ``run_stream``)
# — so a single user-facing ``await agent.run(...)`` call hits TWO
# of our patched entry points on the SAME ``Agent`` instance
# (``run`` then ``iter``). Without a guard, that would open two
# nested handles for the same logical invocation and the audit
# trail would double-emit.
#
# Fix: record ``id(agent)`` of the agent whose wrapper opened the
# handle that is current in this context. When a wrapped entry-point
# fires, it compares its ``self`` with that value:
#
#   * SAME agent → pydantic-ai's own internal re-entrant call
#     (run → iter), on the agent's own handle. Pass through without
#     opening a new handle.
#   * Anything else → a fresh top-level call OR a nested
#     ``other_agent.run(...)`` from inside a parent's tool body. Open a
#     handle (root, or a governed spawn).
#
# Only the innermost governing agent counts. An ancestor further up the
# chain (A → B → A) is a new sub-agent: it is spawned under B like any
# other child, and does not run if that spawn is refused. Tracking every
# agent on the chain instead would let the inner A pass through and run
# on B's handle.
#
# Stored in a ContextVar so concurrent ``asyncio.gather`` calls each get
# their own value.
_governing_agent: contextvars.ContextVar[Optional[int]] = contextvars.ContextVar(
    "watchlight_pydantic_ai.governing_agent", default=None
)


def current_handle() -> Optional["RunHandle"]:
    """Return the :class:`RunHandle` active for the calling context.

    Public read-only accessor for the module-private contextvar.
    Useful for diagnostics + customer code that wants to surface
    "what run am I in?" without threading a handle through every
    callable. Returns ``None`` outside an instrumented
    ``Agent.run()`` call.
    """
    return _current_handle.get()


# ─── Sentinel marker stamped on patched methods ───────────────────────

# The tag is checked at patch time to enforce idempotency. We store
# the original bound method on the patched function so
# ``uninstall_instrumentation`` can restore it.
_WL_PATCH_MARKER = "__watchlight_original__"


# Per-process registry of (Agent class, attribute name, original
# function) so install/uninstall don't have to re-import pydantic_ai
# (which is potentially expensive on systems where the framework
# eagerly loads heavy provider modules).
_installed_patches: List[Tuple[type, str, Any]] = []


def is_instrumented() -> bool:
    """Return ``True`` if instrumentation is currently installed."""
    return bool(_installed_patches)


# ─── Agent-slug resolution ───────────────────────────────────────────

def resolve_agent_slug(agent: Any) -> str:
    """Pick a stable identifier for a Pydantic AI ``Agent`` instance.

    Pydantic AI's ``Agent.name`` attribute is the customer-supplied
    friendly name (``Agent(model, name="researcher")``). When the
    customer sets it, use it verbatim — this is the slug they'll
    have registered against wl-registry.

    Falls back to ``f"pydantic-ai-{id(agent)}"`` for unnamed
    agents, emitting a one-time warning per process. The id-based
    fallback is **process-stable** but not durable across restarts;
    customers who care about long-lived audit attribution should
    set ``name=``.
    """
    name = getattr(agent, "name", None)
    if isinstance(name, str) and name:
        return name
    fallback = f"pydantic-ai-{id(agent)}"
    logger.warning(
        "watchlight_pydantic_ai: Agent has no `name`; falling back to "
        "process-id-derived slug %r. Register agents with "
        "Agent(..., name='your-agent-slug') for stable audit "
        "attribution.",
        fallback,
    )
    return fallback


# ─── Install / uninstall ─────────────────────────────────────────────


def install_instrumentation(plugin: "WatchlightPydanticAIPlugin") -> None:
    """Monkey-patch ``pydantic_ai.Agent`` entry points so nested
    ``Agent.run()`` calls automatically open child handles linked
    to the calling parent.

    Idempotent: a second call is a no-op. ``WatchlightPydanticAIPlugin``
    calls this from its constructor; the contract documented in the
    plugin's README is "constructing the plugin enables governance
    automatically".

    The patch covers FIVE entry points on the ``Agent`` class
    (``run_stream_events`` is governed through ``run``, which
    pydantic-ai drives it with):

    - ``run`` — async one-shot. The canonical entry.
    - ``run_sync`` — sync wrapper. Backed by ``asyncio.run`` under
      the hood; contextvars propagate across that boundary.
    - ``run_stream`` — async context manager yielding a streamed
      result. Nested in a tool body to stream from a sub-agent.
    - ``iter`` — async context manager yielding the full
      ``AgentRun`` event stream. Same nested-tool shape.
    - ``run_stream_sync`` — sync streamed result. pydantic-ai never
      exits the ``run_stream`` it enters, so the plugin owns the run and
      closes it with the result (see :func:`_patch_stream_sync_entry`).

    We do NOT monkey-patch private helpers such as ``_agent_graph``
    — the public entry points are the only documented surface and
    have stable signatures across pydantic-ai 2.x (the floor is 2.61). If
    pydantic-ai adds a new public entry point in a future release,
    this list MUST be extended.
    """
    try:
        from pydantic_ai import Agent
    except ImportError:  # pragma: no cover - exercised via test env
        logger.warning(
            "watchlight_pydantic_ai: pydantic_ai is not importable; "
            "skipping instrumentation. Install pydantic-ai to enable "
            "nested-run lineage stitching."
        )
        return

    # Idempotency gate — if ANY of the entry points is already
    # tagged, assume the full set is patched and skip. This handles
    # the multi-plugin-instance case (two ``WatchlightPydanticAIPlugin``
    # constructed in the same process) without double-wrapping.
    if any(
        hasattr(getattr(Agent, name, None), _WL_PATCH_MARKER)
        for name in ("run", "run_sync", "run_stream", "iter")
    ):
        logger.debug(
            "watchlight_pydantic_ai: instrumentation already installed; "
            "skipping double-install."
        )
        return

    _patch_async_entry(Agent, "run", plugin)
    _patch_sync_entry(Agent, "run_sync", plugin)
    _patch_asyncgen_entry(Agent, "run_stream", plugin)
    _patch_asyncgen_entry(Agent, "iter", plugin)
    _patch_stream_sync_entry(Agent, "run_stream_sync", plugin)


def uninstall_instrumentation() -> None:
    """Restore the original ``pydantic_ai.Agent`` entry points.

    Public uninstall path useful in three scenarios:

    1. Tests — guarantee a clean slate between cases.
    2. Customer-side cleanup — remove governance for a specific
       code path (e.g. a background batch worker that doesn't go
       through APDP).
    3. Multi-tenant teardown — when a tenant's plugin is GC'd,
       drop the patch so the rest of the process isn't affected.

    Idempotent: a second call against an already-uninstalled
    pydantic-ai is a no-op.
    """
    global _installed_patches
    for klass, attr_name, original in _installed_patches:
        try:
            setattr(klass, attr_name, original)
        except Exception:  # noqa: BLE001 — best-effort restore
            logger.exception(
                "watchlight_pydantic_ai: failed to restore %s.%s",
                klass.__name__,
                attr_name,
            )
    _installed_patches = []


# ─── Per-entry-point wrappers ────────────────────────────────────────


def _patch_async_entry(
    klass: type,
    attr_name: str,
    plugin: "WatchlightPydanticAIPlugin",
) -> None:
    """Patch a coroutine-returning method like ``Agent.run``."""
    original = getattr(klass, attr_name)

    @functools.wraps(original)
    async def wrapper(self: Any, *args: Any, **kwargs: Any) -> Any:
        # Re-entrancy gate keyed on ``id(self)`` — see the
        # ``_governing_agent`` comment for the rationale. This
        # specific Agent is already being driven by an outer
        # wrapper for this task → pass through.
        agent_marker = id(self)
        if _governing_agent.get() == agent_marker:
            _require_live_governing_handle(self)
            return await original(self, *args, **kwargs)

        active_token = _governing_agent.set(agent_marker)
        # Forward the user's positional + keyword args to the
        # handle-open helper so it can extract the prompt for
        # ``intent_objective``. The wrapper still passes
        # ``args, kwargs`` verbatim into ``original`` below; the
        # extraction is read-only.
        try:
            handle, handle_token = await _open_handle_for_call(
                plugin, self, args, kwargs
            )
        except BaseException:
            # A refused sub-agent spawn: the agent does not run.
            _governing_agent.reset(active_token)
            raise
        try:
            # ``result`` first, then close: a ``return`` inside the ``try``
            # would skip an ``else`` branch, leaving every successful run
            # ACTIVE (no ``complete_session``, no ``execution_completed``).
            result = await original(self, *args, **kwargs)
        except BaseException as exc:
            await _close_handle_on_exception(handle, exc)
            raise
        else:
            await _close_handle_on_success(handle)
            return result
        finally:
            if handle_token is not None:
                _current_handle.reset(handle_token)
            _governing_agent.reset(active_token)

    setattr(wrapper, _WL_PATCH_MARKER, original)
    setattr(klass, attr_name, wrapper)
    _installed_patches.append((klass, attr_name, original))


def _patch_sync_entry(
    klass: type,
    attr_name: str,
    plugin: "WatchlightPydanticAIPlugin",
) -> None:
    """Patch a sync method like ``Agent.run_sync``.

    ``run_sync`` is the sync API surface. Internally pydantic-ai
    drives it through ``asyncio.run`` (or the equivalent) — so to
    keep handle open/close on the same logical context, we use
    ``asyncio.run`` ourselves to drive a small async coroutine that
    opens the handle, calls the original ``run_sync`` (which spins
    its own loop), closes the handle, and returns the result.

    Importantly, the handle's lifecycle methods (``start_run``,
    ``complete``) are async — so we MUST be on an event loop to
    call them. We arrange that here.
    """
    original = getattr(klass, attr_name)

    @functools.wraps(original)
    def wrapper(self: Any, *args: Any, **kwargs: Any) -> Any:
        import asyncio

        # Re-entrancy gate keyed on ``id(self)`` — same as the
        # async wrapper.
        agent_marker = id(self)
        if _governing_agent.get() == agent_marker:
            _require_live_governing_handle(self)
            return original(self, *args, **kwargs)

        # Detect the most common misuse — calling ``run_sync`` from
        # inside a running event loop. Pydantic AI itself raises in
        # this case; we surface the same error before opening any
        # handle to keep the audit chain clean.
        try:
            asyncio.get_running_loop()
            in_loop = True
        except RuntimeError:
            in_loop = False
        if in_loop:
            return original(self, *args, **kwargs)

        async def _governed() -> Any:
            active_token = _governing_agent.set(agent_marker)
            # Forward args/kwargs for prompt extraction.
            try:
                handle, handle_token = await _open_handle_for_call(
                    plugin, self, args, kwargs
                )
            except BaseException:
                # A refused sub-agent spawn: the agent does not run.
                _governing_agent.reset(active_token)
                raise
            try:
                # ``run_sync`` internally spawns its own asyncio
                # loop; we drive ``original`` synchronously via
                # ``asyncio.to_thread`` so the parent's contextvars
                # propagate.
                result = await asyncio.to_thread(
                    original, self, *args, **kwargs
                )
                await _close_handle_on_success(handle)
                return result
            except BaseException as exc:
                await _close_handle_on_exception(handle, exc)
                raise
            finally:
                if handle_token is not None:
                    _current_handle.reset(handle_token)
                _governing_agent.reset(active_token)

        return asyncio.run(_governed())

    setattr(wrapper, _WL_PATCH_MARKER, original)
    setattr(klass, attr_name, wrapper)
    _installed_patches.append((klass, attr_name, original))


def _patch_asyncgen_entry(
    klass: type,
    attr_name: str,
    plugin: "WatchlightPydanticAIPlugin",
) -> None:
    """Patch an async-context-manager method like ``Agent.run_stream``.

    Pydantic AI's ``run_stream`` and ``iter`` are
    ``@asynccontextmanager``-decorated functions that yield exactly
    once. We wrap the same shape — an ``@asynccontextmanager`` that
    opens the handle, delegates to the original, and closes the
    handle on exit.

    Why ``@asynccontextmanager`` and not ``async def`` returning the
    inner generator: the original's return type is an async-context-
    manager, and customer code uses ``async with agent.run_stream(...) as
    s:``. We must preserve that shape.
    """
    from contextlib import asynccontextmanager

    original = getattr(klass, attr_name)

    @functools.wraps(original)
    @asynccontextmanager
    async def wrapper(self: Any, *args: Any, **kwargs: Any) -> Any:
        # Re-entrancy gate keyed on ``id(self)``. Pydantic AI's
        # ``run`` and ``run_stream`` are implemented as
        # ``async with self.iter(...)`` — the inner ``iter`` call
        # is on the SAME ``self``, so the gate catches it.
        agent_marker = id(self)
        if _governing_agent.get() == agent_marker:
            _require_live_governing_handle(self)
            async with original(self, *args, **kwargs) as value:
                yield value
            return

        active_token = _governing_agent.set(agent_marker)
        # Forward args/kwargs for prompt extraction.
        try:
            handle, handle_token = await _open_handle_for_call(
                plugin, self, args, kwargs
            )
        except BaseException:
            # A refused sub-agent spawn: the agent does not run.
            _governing_agent.reset(active_token)
            raise
        try:
            async with original(self, *args, **kwargs) as value:
                yield value
        except BaseException as exc:
            await _close_handle_on_exception(handle, exc)
            raise
        else:
            await _close_handle_on_success(handle)
        finally:
            if handle_token is not None:
                _current_handle.reset(handle_token)
            _governing_agent.reset(active_token)

    setattr(wrapper, _WL_PATCH_MARKER, original)
    setattr(klass, attr_name, wrapper)
    _installed_patches.append((klass, attr_name, original))


# ─── ``run_stream_sync`` ──────────────────────────────────────────────


def _pydantic_sync_loop() -> asyncio.AbstractEventLoop:
    """The event loop pydantic-ai's sync APIs drive (``_utils.get_event_loop``).

    The handle is opened and closed on the same loop the stream runs on,
    so the backend client never crosses loops.
    """
    from pydantic_ai._utils import get_event_loop

    return get_event_loop()


# Closes scheduled on a running loop (a task, or a future from another
# thread). Referenced here until done, so they are never garbage-collected
# mid-flight.
_pending_closes: set = set()

# Longest the calling thread waits for a close run on a worker thread.
_WORKER_CLOSE_TIMEOUT_S = 5.0


class _SyncStreamRun:
    """Lifecycle of the governed run behind one ``run_stream_sync`` call.

    The outcome is decided once, whichever happens first: the stream is
    consumed (complete), an error is raised (terminate), the caller stops
    early (complete if the run had finished, else terminate), or the
    result object is dropped unconsumed (terminate as abandoned, from a
    ``weakref.finalize``). Once the run is terminated, the result refuses
    to drive it any further. Holds no reference to the result object.

    ``outcome`` is set when the outcome is decided; ``closed`` only once
    the close has run or been scheduled. A close that could not be
    scheduled is retried by the next close attempt (or the finalizer).
    """

    def __init__(
        self,
        handle: "RunHandle",
        loop: asyncio.AbstractEventLoop,
        ctx: contextvars.Context,
    ) -> None:
        self.handle = handle
        self.loop = loop
        self.ctx = ctx
        self.outcome: Optional[str] = None
        self.closed = False
        self._close_factory: Optional[Callable[[], Any]] = None

    @property
    def terminated(self) -> bool:
        return self.outcome == "terminated"

    def refuse_if_terminated(self, slug: str) -> None:
        """Raise before a terminated run is driven any further."""
        if self.terminated:
            raise GovernanceUnavailable(
                f"Watchlight AI Agent Runtime Governance ended the governed "
                f"run of agent {slug!r} (stopped early, failed or abandoned), "
                f"so its stream cannot be read further (no model turn, no "
                f"tool call). Start a new run."
            )

    def _schedule(self, factory: Callable[[], Any]) -> bool:
        """Run or schedule the close. ``True`` once it is done or scheduled."""
        loop = self.loop
        try:
            running: Optional[asyncio.AbstractEventLoop] = asyncio.get_running_loop()
        except RuntimeError:
            running = None
        try:
            if not loop.is_closed() and loop.is_running():
                if running is loop:
                    # On the loop's own thread (e.g. the finalizer ran while
                    # a step was executing): schedule, never block.
                    pending: Any = loop.create_task(factory())
                else:
                    # The loop runs on another thread.
                    pending = asyncio.run_coroutine_threadsafe(factory(), loop)
                _pending_closes.add(pending)
                pending.add_done_callback(_pending_closes.discard)
                return True
            if running is None and not loop.is_closed():
                loop.run_until_complete(factory())
                return True
            # This thread is running another loop, or the run's loop is
            # closed: run the close on a worker thread with its own loop.
            self._close_on_worker(factory)
            return True
        except Exception:  # noqa: BLE001 — the close is retried; never raise from a close
            logger.exception(
                "watchlight_pydantic_ai: closing a run_stream_sync run failed; "
                "it will be retried."
            )
            return False

    @staticmethod
    def _close_on_worker(factory: Callable[[], Any]) -> None:
        """Run the close on a daemon worker thread with its own loop.

        The wait is bounded (``_WORKER_CLOSE_TIMEOUT_S``): the calling
        thread may be the one running garbage collection, and must not
        block for as long as the backend client's timeout. A close still
        running when the wait ends is in flight, so it counts as
        scheduled; the worker finishes it on its own and logs a failure.
        """
        errors: List[BaseException] = []
        waited_out = threading.Event()

        def _target() -> None:
            try:
                asyncio.run(factory())
            except BaseException as exc:  # noqa: BLE001 — re-raised or logged below
                errors.append(exc)
                if waited_out.is_set():
                    logger.warning(
                        "watchlight_pydantic_ai: a run_stream_sync close that "
                        "outlived its wait failed (%s).",
                        type(exc).__name__,
                    )

        worker = threading.Thread(target=_target, name="wl-pydantic-ai-close", daemon=True)
        worker.start()
        worker.join(_WORKER_CLOSE_TIMEOUT_S)
        if worker.is_alive():
            waited_out.set()
            logger.warning(
                "watchlight_pydantic_ai: a run_stream_sync close is still "
                "running after %.0fs; it continues in the background.",
                _WORKER_CLOSE_TIMEOUT_S,
            )
            return
        if errors:
            raise errors[0]

    def _finish(self, outcome: str, factory: Callable[[], Any]) -> None:
        if self.outcome is None:
            self.outcome = outcome
            self._close_factory = factory
        if self.closed or self._close_factory is None:
            return
        if self._schedule(self._close_factory):
            self.closed = True

    def complete(self) -> None:
        handle = self.handle
        self._finish("completed", lambda: _close_handle_on_success(handle))

    def terminate(self, reason: str) -> None:
        handle = self.handle
        self._finish("terminated", lambda: _terminate_handle(handle, reason))

    def fail(self, exc: BaseException) -> None:
        self.terminate(f"pydantic_ai_run_failed: {type(exc).__name__}")

    def abandon(self) -> None:
        """``weakref.finalize`` callback: the result was dropped unconsumed."""
        if self.outcome is None:
            logger.warning(
                "watchlight_pydantic_ai: a run_stream_sync result was dropped "
                "before its stream was consumed; the run is terminated as "
                "abandoned."
            )
        self.terminate("pydantic_ai_stream_abandoned")


# Methods of ``StreamedRunResultSync`` that drive the event loop. They run
# inside the governed run's context, so the run's model turns and tool
# calls see its handle.
_STREAM_ITERATOR_METHODS = ("stream_output", "stream_text", "stream_response", "stream_responses")
_STREAM_TERMINAL_METHODS = ("get_output",)
_STREAM_LOOP_METHODS = ("validate_response_output",)
_governed_result_types: Dict[type, type] = {}


def _governed_result_type(base: type) -> type:
    """A subclass of the result's own type that closes the run.

    Subclassing (rather than a proxy) keeps every attribute, property and
    ``isinstance`` check of the pydantic-ai object; only the methods that
    drive the stream are overridden.
    """
    cached = _governed_result_types.get(base)
    if cached is not None:
        return cached

    def _iterator_method(name: str) -> Callable[..., Any]:
        base_method = getattr(base, name)

        @functools.wraps(base_method)
        def method(self: Any, *args: Any, **kwargs: Any) -> Any:
            run: _SyncStreamRun = self.__dict__["_wl_stream_run"]
            run.refuse_if_terminated(self.__dict__["_wl_agent_slug"])
            inner = run.ctx.run(base_method, self, *args, **kwargs)

            def _governed_iter() -> Any:
                finished = False
                try:
                    while True:
                        # Another iterator or call may have terminated the
                        # run since the last item.
                        run.refuse_if_terminated(self.__dict__["_wl_agent_slug"])
                        try:
                            item = run.ctx.run(next, inner)
                        except StopIteration:
                            finished = True
                            return
                        yield item
                except GeneratorExit:
                    raise
                except GovernanceUnavailable:
                    raise
                except BaseException as exc:
                    run.fail(exc)
                    raise
                finally:
                    if finished:
                        run.complete()
                    elif run.outcome is None:
                        # The caller stopped early (break, close, dropped
                        # iterator). A run that already produced its final
                        # result completed; otherwise it ended early.
                        if getattr(self, "is_complete", False):
                            run.complete()
                        else:
                            run.terminate("pydantic_ai_stream_closed_early")

            return _governed_iter()

        return method

    def _terminal_method(name: str) -> Callable[..., Any]:
        base_method = getattr(base, name)

        @functools.wraps(base_method)
        def method(self: Any, *args: Any, **kwargs: Any) -> Any:
            run: _SyncStreamRun = self.__dict__["_wl_stream_run"]
            run.refuse_if_terminated(self.__dict__["_wl_agent_slug"])
            try:
                value = run.ctx.run(base_method, self, *args, **kwargs)
            except BaseException as exc:
                run.fail(exc)
                raise
            run.complete()
            return value

        return method

    def _loop_method(name: str) -> Callable[..., Any]:
        base_method = getattr(base, name)

        @functools.wraps(base_method)
        def method(self: Any, *args: Any, **kwargs: Any) -> Any:
            run: _SyncStreamRun = self.__dict__["_wl_stream_run"]
            run.refuse_if_terminated(self.__dict__["_wl_agent_slug"])
            return run.ctx.run(base_method, self, *args, **kwargs)

        return method

    namespace: Dict[str, Any] = {"__module__": __name__}
    for name in _STREAM_ITERATOR_METHODS:
        if hasattr(base, name):
            namespace[name] = _iterator_method(name)
    for name in _STREAM_TERMINAL_METHODS:
        if hasattr(base, name):
            namespace[name] = _terminal_method(name)
    for name in _STREAM_LOOP_METHODS:
        if hasattr(base, name):
            namespace[name] = _loop_method(name)
    governed = type(f"Governed{base.__name__}", (base,), namespace)
    _governed_result_types[base] = governed
    return governed


def _govern_stream_result(result: Any, run: _SyncStreamRun, slug: str) -> Any:
    """Re-type ``result`` as its governed subclass, keeping its state."""
    governed_type = _governed_result_type(type(result))
    governed = object.__new__(governed_type)
    governed.__dict__.update(result.__dict__)
    governed.__dict__["_wl_stream_run"] = run
    governed.__dict__["_wl_agent_slug"] = slug
    # Last resort: an object dropped before its stream was consumed
    # terminates the run as abandoned. Idempotent with every other close.
    weakref.finalize(governed, run.abandon)
    return governed


def _patch_stream_sync_entry(
    klass: type,
    attr_name: str,
    plugin: "WatchlightPydanticAIPlugin",
) -> None:
    """Patch ``Agent.run_stream_sync``.

    pydantic-ai enters ``run_stream`` inside ``run_stream_sync`` and never
    exits it, so the asyncgen wrapper's close never runs. This wrapper owns
    the run instead: it opens the handle (failing closed before the model
    is called), runs the original in a private context that names the run,
    so the inner ``run_stream`` passes through on it, and returns the
    result re-typed so the run closes deterministically (see
    :class:`_SyncStreamRun`). The caller's own context is never modified.
    """
    original = getattr(klass, attr_name)

    @functools.wraps(original)
    def wrapper(self: Any, *args: Any, **kwargs: Any) -> Any:
        agent_marker = id(self)
        if _governing_agent.get() == agent_marker:
            _require_live_governing_handle(self)
            return original(self, *args, **kwargs)

        try:
            asyncio.get_running_loop()
            in_loop = True
        except RuntimeError:
            in_loop = False
        if in_loop:
            # pydantic-ai refuses run_stream_sync inside a running loop.
            # The inner run_stream is still governed if it ever runs.
            return original(self, *args, **kwargs)

        loop = _pydantic_sync_loop()
        # The open reads the caller's current handle (root or spawn) and
        # raises on any failure, before the model is called.
        handle, _ = loop.run_until_complete(
            _open_handle_for_call(plugin, self, args, kwargs)
        )
        ctx = contextvars.copy_context()
        ctx.run(_governing_agent.set, agent_marker)
        ctx.run(_current_handle.set, handle)
        run = _SyncStreamRun(handle, loop, ctx)
        try:
            result = ctx.run(original, self, *args, **kwargs)
        except BaseException as exc:
            run.fail(exc)
            raise
        return _govern_stream_result(result, run, resolve_agent_slug(self))

    setattr(wrapper, _WL_PATCH_MARKER, original)
    setattr(klass, attr_name, wrapper)
    _installed_patches.append((klass, attr_name, original))


# ─── Shared handle-open / handle-close helpers ───────────────────────


def _handle_is_live(handle: Optional["RunHandle"]) -> bool:
    """``True`` while ``handle`` can still govern calls: opened, not
    completed or terminated, not quarantined or severed."""
    if handle is None or getattr(handle, "_completed", True):
        return False
    state = getattr(handle, "state", None)
    return state is None or state == RunHandleState.ACTIVE


def _require_live_governing_handle(agent: Any) -> None:
    """Gate for the re-entrant pass-through.

    The pass-through runs the agent on the handle its outer call opened.
    That is only sound while that handle is live. A task created inside a
    tool can outlive the run: when it calls the same agent again after
    the run has returned, the contextvars still name the agent and its
    now-closed handle. That call is refused. Opening a new root instead
    would drop the run's lineage and, for a sub-agent, its attenuated
    scope.
    """
    if _handle_is_live(_current_handle.get()):
        return
    _refuse_after_run_ended(resolve_agent_slug(agent))


def _refuse_after_run_ended(slug: str) -> None:
    """Refuse a call whose governing run is no longer live."""
    logger.warning(
        "watchlight_pydantic_ai: agent %r was called from a governed run "
        "that is no longer live; the call does not run.",
        slug,
    )
    raise GovernanceUnavailable(
        f"Watchlight AI Agent Runtime Governance refused a call to agent "
        f"{slug!r}: the governed run it was called from is no longer live "
        f"(ended, quarantined or severed), so it was not "
        f"started (no model turn, no tool call). Call the agent from a live "
        f"run, or start a new run outside the finished one."
    )



def _nested_time_budget(plugin: Any, parent: Any) -> Optional[int]:
    """The time budget a nested agent's spawn names: ``None`` (inherit the
    parent's remaining time) unless the plugin sets
    ``nested_agent_time_budget_seconds``, which is sent exactly as
    configured. It is never shortened here: wl-apdp (or the in-process
    engine) grants it exactly, or refuses the spawn when it is more than the
    parent's granted budget, its remaining time or the tenant threshold, and
    the nested agent then does not run."""
    del parent  # the budget is the configured one, whatever the parent has
    return getattr(plugin, "nested_agent_time_budget_seconds", None)


# ─── Root admission ─────────────────────────────────────────
#
# ``_current_handle`` names the run a call belongs to only while the call
# stays in that run's context. Code that drops the context (an executor,
# a thread, a fresh ``contextvars.Context``) reaches the entry points with
# no parent. Opening a root there would run the nested agent with none of
# its parent's attenuation and no link to its lineage. Every root goes
# through ``watchlight_core.root_admission``, the process-wide admission
# shared by every framework plugin, so a run live in any of them counts.

_ESCAPE_HINT = (
    "Call the agent from the run with await, iter or asyncio.to_thread so it "
    "runs as a governed sub-agent, or wrap an independent run in "
    "watchlight_pydantic_ai.root_run()."
)


class root_run(root_admission.RootRun):
    """Declare an independent governed root run.

    While a governed run is live in the process, an agent run with no
    governed run in its context is refused
    (:class:`watchlight_core.NestedRunEscapedError`). Runs that are meant
    to be independent roots at the same time (``asyncio.gather`` of two
    agents, one agent per worker thread) are declared::

        async with root_run():
            await agent.run("...")

        @root_run()
        def worker(prompt):
            return agent.run_sync(prompt)

    A context manager (sync or async) and a decorator (sync or async
    functions). A run started in it with no governed run in its context
    opens as a declared root: the server decides
    ``Action::"open_declared_root"`` with the root execution ids of the
    governed runs live in this process and records the
    declaration. A refusal raises :class:`watchlight_core.DeclaredRootRefused`
    and the agent does not run. Refused when entered inside a live
    governed run (an agent called there is a governed sub-agent), and for
    an agent whose sub-agent spawn was refused in a governed run that is
    still live.
    """

    def _in_live_run(self) -> bool:
        return _handle_is_live(_current_handle.get())

    def _enter_context(self) -> None:
        self._context_tokens = (_current_handle.set(None), _governing_agent.set(None))

    def _exit_context(self) -> None:
        handle, agent = self._context_tokens
        _governing_agent.reset(agent)
        _current_handle.reset(handle)


async def _open_handle_for_call(
    plugin: "WatchlightPydanticAIPlugin",
    agent: Any,
    call_args: Tuple[Any, ...] = (),
    call_kwargs: Optional[dict] = None,
) -> Tuple[Optional["RunHandle"], Optional[contextvars.Token]]:
    """Open a child or root handle for one ``Agent.run`` invocation.

    ``call_args`` and ``call_kwargs`` are the user's args
    forwarded verbatim from the patched ``Agent.run`` wrapper. The
    helper inspects ``call_args[0]`` (or ``call_kwargs["prompt"]``,
    etc.) via
    :func:`watchlight_pydantic_ai.intent.extract_intent_from_pydantic_args`
    to derive ``intent_objective``; the corresponding
    ``intent_provenance`` is ``"plugin_derived"`` when an objective
    was found, ``"absent"`` otherwise. Both are forwarded to either
    ``plugin.start_run`` (root) or ``parent.spawn_subagent``
    (nested).

    Returns ``(handle, token)``. A failed open RAISES, root or nested,
    so the agent never runs ungoverned: a typed
    :class:`watchlight_core.WatchlightError` (a refused spawn, an
    unregistered agent) propagates unchanged, and any other failure is
    raised as :class:`watchlight_core.GovernanceUnavailable` with an
    instructive message (never the transport's raw text).
    """
    slug = resolve_agent_slug(agent)
    parent = _current_handle.get()

    # Extract intent from the prompt arg. Returns ``None``
    # if extraction fails for any reason; the helper is exception-
    # safe so the customer's run is never broken by intent inference.
    intent_objective: Optional[str] = None
    intent_provenance: str = "absent"
    if call_args or call_kwargs:
        from .intent import extract_intent_from_pydantic_args

        intent_objective = extract_intent_from_pydantic_args(
            call_args, call_kwargs or {}
        )
        if intent_objective is not None:
            intent_provenance = "plugin_derived"

    if parent is not None and not _handle_is_live(parent):
        # A nested call whose parent run has ended (a task that outlived
        # the tool that created it), or whose parent is quarantined or
        # severed. It is not spawned from that handle and not promoted to
        # a root: it does not run.
        _refuse_after_run_ended(slug)

    handle: Optional["RunHandle"] = None
    try:
        if parent is None:
            # Admitted before anything is sent: an implicit root
            # while a governed run is live, or a declared root for a refused
            # agent, raises here and the agent does not run.
            declared = root_admission.declared_root_requested()
            live_roots = root_admission.reserve_root(slug, declared=declared, hint=_ESCAPE_HINT)
            try:
                handle = await plugin.start_run(
                    slug,
                    intent_objective=intent_objective,
                    intent_provenance=intent_provenance,
                    **({"declared_root": live_roots} if declared else {}),
                )
            finally:
                root_admission.release_root(handle)
        else:
            from watchlight_core import plugin_child_intent

            try:
                handle = await parent.spawn_subagent(
                    slug,
                    child_intent=plugin_child_intent(
                        intent_objective,
                        category=getattr(plugin, "child_intent_category", None),
                        parent=parent,
                        fallback_objective=f"Nested agent run of {slug}",
                    ),
                    intent_objective=intent_objective,
                    intent_provenance=intent_provenance,
                    time_budget_seconds=_nested_time_budget(plugin, parent),
                )
            except BaseException:
                # The refused child never runs, not even as a declared root
                # while this tree is live.
                root_admission.record_refused_spawn(slug, parent)
                raise
            root_admission.register_run(handle)
    except WatchlightError:
        # A typed refusal — a refused spawn (scope attenuation, delegation
        # depth, an invalidated parent), an unregistered agent, a session
        # wl-apdp would not open — propagates unchanged. The agent
        # does not run: continuing would run a sub-agent's model and tools
        # under the PARENT's handle and ``sst_`` (the ``_current_handle``
        # contextvar still names the parent), or a root run with no
        # governance at all.
        logger.warning(
            "watchlight_pydantic_ai: Watchlight refused to open a governed "
            "run for agent %r; the agent does not run.",
            slug,
        )
        raise
    except Exception as exc:  # noqa: BLE001 — every other failure fails closed too
        logger.warning(
            "watchlight_pydantic_ai: could not open a governed run for agent "
            "%r (%s); the agent does not run.",
            slug,
            type(exc).__name__,
        )
        role = "sub-agent" if parent is not None else "agent"
        raise GovernanceUnavailable(
            f"Watchlight AI Agent Runtime Governance could not open a governed "
            f"run for {role} {slug!r}, so it was not started (no model turn, "
            f"no tool call). Check that the agent is registered and that "
            f"Watchlight is reachable from this process, then retry."
        ) from exc

    # The pydantic-ai instrumentation wraps ``Agent.run``
    # transparently; the customer never wires an ``async with`` block,
    # which is the only place :meth:`BaseRunHandle.__aenter__` flips
    # the fail-closed flag. The instrumentation lifecycle IS the
    # entry-point semantically — handle open → run body → close — so
    # flip the flag here so the customer's tool calls (which route
    # through ``handle.authorize_action``) don't raise
    # :class:`watchlight_core.WatchlightContractError`. The close
    # paths (``_close_handle_on_success`` /
    # ``_close_handle_on_exception``) flip it back to keep the
    # post-close authorize-call guard accurate.
    handle._aentered = True

    token = _current_handle.set(handle)

    # Inject the synthetic ``watchlight.declare_intent`` tool
    # into the agent's tool list BEFORE the original ``Agent.run`` body
    # runs, so the agent's first turn sees it as one of the available
    # tools. The injection is idempotent (re-running against an agent
    # already carrying the synthetic tool is a no-op), greenfield-
    # only (brownfield agents get an empty descriptor list and the
    # call short-circuits), and contextvar-driven (the tool's fire-
    # time handle is resolved from ``_current_handle`` so a nested
    # sub-agent's declare-intent call mutates the sub-agent's handle,
    # never the root's).
    try:
        inject_synthetic_tools(agent, handle)
    except Exception:  # noqa: BLE001 — observability is best-effort
        # A failure to inject MUST NOT break the customer's run; the
        # greenfield Cedar gate will simply deny subsequent actions
        # without a satisfaction path, which is the correct fail-
        # closed posture (the operator will see denies on the audit
        # log and investigate).
        logger.exception(
            "watchlight_pydantic_ai: synthetic tool injection raised "
            "for agent %r; the agent will run without the synthetic "
            "tool.",
            slug,
        )
    return handle, token


async def _close_handle_on_success(handle: Optional["RunHandle"]) -> None:
    """Idempotent close on the success path."""
    if handle is None:
        return
    try:
        await handle.complete()
    except Exception:  # noqa: BLE001 — observability is best-effort
        logger.exception(
            "watchlight_pydantic_ai: handle.complete() raised on success "
            "path; this is a plugin bug — please report."
        )


async def _terminate_handle(handle: Optional["RunHandle"], reason: str) -> None:
    """Terminate ``handle`` with ``reason``. Idempotent, best-effort."""
    if handle is None:
        return
    try:
        await handle.terminate(reason=reason)
    except Exception:  # noqa: BLE001 — observability is best-effort
        logger.exception(
            "watchlight_pydantic_ai: handle.terminate() raised on "
            "exception path."
        )


async def _close_handle_on_exception(
    handle: Optional["RunHandle"],
    exc: BaseException,
) -> None:
    """Terminate the handle when the wrapped call raised.

    Uses ``terminate`` (not ``complete``) so wl-execution-graph
    transitions the row to a failed state rather than a clean
    completion.
    """
    if handle is None:
        return
    try:
        await handle.terminate(
            reason=f"pydantic_ai_run_failed: {type(exc).__name__}"
        )
    except Exception:  # noqa: BLE001 — observability is best-effort
        logger.exception(
            "watchlight_pydantic_ai: handle.terminate() raised on "
            "exception path."
        )


# ─── Synthetic ``watchlight.declare_intent`` tool injection ───────────


# Sentinel attribute stamped on the ``Tool`` we register so a second
# pass (e.g. the same Agent invoked twice, or a re-entrant ``Agent.iter``
# call) can detect the tool is already installed and skip
# re-registration. The marker also lets ``test_*_injection`` tests
# verify the tool is the synthetic one we own — not a customer-supplied
# function with a colliding name.
_WL_SYNTHETIC_TOOL_MARKER = "__watchlight_synthetic_tool__"


def inject_synthetic_tools(
    agent: Any,
    handle: "RunHandle",
    mode: Optional[str] = None,
) -> List[str]:
    """Inject every Watchlight-managed synthetic tool into ``agent``'s
    tool list for the given enforcement mode.

    When ``mode`` resolves to ``"greenfield"``, registers a
    Pydantic AI :class:`pydantic_ai.tools.Tool` for every descriptor
    returned by :meth:`watchlight_core.BaseRunHandle.synthetic_tools`
    on the Agent's internal ``_function_toolset``. In brownfield mode
    (the locked default) the synthetic-tool list is empty and the
    function is a no-op.

    Tool-translation mechanism
    --------------------------

    Pydantic AI exposes three tool-registration surfaces:

    1. The ``@agent.tool`` / ``@agent.tool_plain`` decorators —
       customer-facing; require a defined Python function at decoration
       time and bake the function's docstring + signature into the
       LLM-visible tool schema.
    2. ``Agent._function_toolset.add_function(fn, name=..., description=...)``
       — runtime accessor that derives the JSON schema from the
       function's type-annotated signature.
    3. ``Agent._function_toolset.add_tool(Tool(...))`` — explicit
       :class:`pydantic_ai.tools.Tool` construction.

    We use option **3** because the canonical synthetic-tool descriptor
    in :data:`watchlight_core.WATCHLIGHT_DECLARE_INTENT_TOOL` carries
    the tool's name + description + parameter schema directly — there
    is no customer-supplied Python function whose signature we want
    Pydantic AI to introspect. Routing through ``Tool(...)`` lets us:

    - Pass an explicit ``name=`` (the ``watchlight.declare_intent``
      namespaced spelling) without reading it back from a function's
      ``__name__``.
    - Pass an explicit ``description=`` from the canonical descriptor
      so all framework plugins surface the SAME operator-facing copy.
    - Stamp our sentinel marker
      (:data:`_WL_SYNTHETIC_TOOL_MARKER`) on the registered Tool so
      a re-injection pass can detect-and-skip.

    The wrapped callable is a thin async function that delegates to
    :func:`watchlight_core.handle_declare_intent_call`. The handle
    passed to the call is read from the contextvar
    :data:`_current_handle` at tool-fire time — that's the
    contextvar-driven nested-handle pattern (instead of closing over
    the handle passed to ``inject_synthetic_tools``), so a nested
    sub-agent's declare-intent call mutates the SUB-AGENT's handle
    rather than the root's. This keeps every sub-agent governed under
    its own handle.

    Authorize-bypass mechanism
    --------------------------

    Pydantic AI does NOT run an always-on ``authorize_action`` per
    tool — its authorize integration is via the
    :meth:`watchlight_pydantic_ai.RunHandle.guarded_tool` decorator,
    which customers apply explicitly to the tools they want governed.
    The synthetic tool is registered WITHOUT ``guarded_tool``, so the
    APDP authorize round-trip is short-circuited STRUCTURALLY — there
    is no authorize call site to intercept. This is deliberate: a
    ``watchlight.declare_intent`` call MUST NOT itself round-trip to
    ``authorize_action``, because the greenfield Cedar gate would
    forbid the call before the agent had a chance to declare its
    intent — a chicken-and-egg deadlock.

    Idempotency
    -----------

    Re-invocation against the same agent is a no-op if the tool is
    already registered (detected via the sentinel marker on the
    Pydantic AI ``Tool`` instance). This protects against the
    re-entrant ``Agent.run`` → ``Agent.iter`` pattern in pydantic-ai
    where our wrapper fires twice for the same logical call.

    Returns the list of tool names that were newly registered (empty
    in brownfield, empty on idempotent re-registration). Tests assert
    on this to confirm injection happened.
    """
    try:
        # ``synthetic_tools(mode)`` returns the canonical descriptors
        # for the resolved mode. In brownfield this is ``[]`` so we
        # exit fast. In greenfield it carries the single
        # ``WATCHLIGHT_DECLARE_INTENT_TOOL`` descriptor today; future
        # additions land here without changing the plugin call site.
        descriptors = handle.synthetic_tools(mode)
    except Exception:  # noqa: BLE001 — observability is best-effort
        logger.exception(
            "watchlight_pydantic_ai: handle.synthetic_tools(%r) raised; "
            "skipping synthetic tool injection.",
            mode,
        )
        return []

    if not descriptors:
        return []

    # Lazy-import Pydantic AI's ``Tool`` so the plugin module can be
    # imported in environments that haven't installed pydantic-ai
    # (e.g. doc tooling). The wrapped ``Agent.run`` path already
    # guards on the pydantic-ai import at install time, so by the
    # time we get here, the import is guaranteed available.
    try:
        from pydantic_ai.tools import Tool
    except ImportError:  # pragma: no cover - guarded at install time
        logger.warning(
            "watchlight_pydantic_ai: pydantic_ai.tools.Tool unavailable; "
            "synthetic tool injection skipped."
        )
        return []

    function_toolset = getattr(agent, "_function_toolset", None)
    if function_toolset is None:
        logger.warning(
            "watchlight_pydantic_ai: Agent has no _function_toolset "
            "attribute; pydantic-ai may have changed its internal "
            "structure. Synthetic tool injection skipped."
        )
        return []

    existing_tools = getattr(function_toolset, "tools", None)
    if not isinstance(existing_tools, dict):
        logger.warning(
            "watchlight_pydantic_ai: Agent._function_toolset.tools is "
            "not a dict; pydantic-ai may have changed its internal "
            "structure. Synthetic tool injection skipped."
        )
        return []

    registered: List[str] = []
    for descriptor in descriptors:
        name = descriptor.get("name")
        description = descriptor.get("description") or ""
        if not isinstance(name, str) or not name:
            logger.warning(
                "watchlight_pydantic_ai: synthetic tool descriptor "
                "missing a name; skipping. descriptor=%r",
                descriptor,
            )
            continue

        # Idempotency — if a tool by this name is already on the
        # agent, check the sentinel marker:
        #   * Marker present → we already injected; skip.
        #   * Marker absent → customer registered a tool with the
        #     reserved ``watchlight.*`` namespace. Refuse to overwrite
        #     (the customer's tool is theirs); log a loud warning so
        #     the operator sees the collision. The synthetic-tool
        #     gate will be inert for this agent — which is a known
        #     misconfiguration the operator can fix by renaming.
        if name in existing_tools:
            preexisting = existing_tools[name]
            if getattr(preexisting, _WL_SYNTHETIC_TOOL_MARKER, False):
                # Our own prior injection — skip silently.
                continue
            logger.warning(
                "watchlight_pydantic_ai: a customer-defined tool named "
                "%r is already registered on agent %r. The Watchlight "
                "synthetic tool is reserved in the ``watchlight.`` "
                "namespace; refusing to overwrite. Rename the customer "
                "tool to avoid this collision.",
                name,
                resolve_agent_slug(agent),
            )
            continue

        # Build the Pydantic AI Tool descriptor. The async callable
        # below is the load-bearing wire — it reads the active handle
        # from the contextvar (not the one closed over at injection
        # time) so a nested sub-agent's ``watchlight.declare_intent``
        # call mutates the SUB-AGENT's handle, never the root's.
        try:
            tool = Tool(
                _build_declare_intent_callable(name),
                name=name,
                description=description,
            )
        except Exception:  # noqa: BLE001
            logger.exception(
                "watchlight_pydantic_ai: failed to build synthetic Tool "
                "for descriptor %r; skipping.",
                name,
            )
            continue

        # Stamp the sentinel so a future ``inject_synthetic_tools``
        # pass against the same agent (e.g. a second ``Agent.run``
        # call on the same instance) can detect-and-skip.
        try:
            setattr(tool, _WL_SYNTHETIC_TOOL_MARKER, True)
        except Exception:  # noqa: BLE001 — non-fatal; idempotency
            # degrades to "re-register, no-op via tool-name collision".
            logger.debug(
                "watchlight_pydantic_ai: could not stamp synthetic "
                "marker on Tool; relying on name-collision idempotency.",
                exc_info=True,
            )

        try:
            function_toolset.add_tool(tool)
        except Exception:  # noqa: BLE001
            logger.exception(
                "watchlight_pydantic_ai: function_toolset.add_tool "
                "raised for %r; skipping.",
                name,
            )
            continue
        registered.append(name)

    if registered:
        logger.debug(
            "watchlight_pydantic_ai: injected %d synthetic tool(s) "
            "into agent %r: %s",
            len(registered),
            resolve_agent_slug(agent),
            ", ".join(registered),
        )
    return registered


def _build_declare_intent_callable(
    tool_name: str,
) -> Callable[..., Any]:
    """Build the async function Pydantic AI will invoke when the agent
    calls the synthetic tool.

    The callable's signature MUST match the JSON schema in
    :data:`watchlight_core.WATCHLIGHT_DECLARE_INTENT_TOOL` so Pydantic
    AI's signature-driven JSON-schema synthesis produces the canonical
    shape (one required ``objective`` string parameter). Pydantic AI
    derives the schema from the typed signature, so we expose
    ``objective: str`` verbatim.

    At call time the callable:

    1. Reads the active handle from the contextvar
       :data:`_current_handle` (the contextvar-driven nested-handle
       pattern). Falls back to a rejected response if no handle is
       active — that should be impossible inside an instrumented
       ``Agent.run`` invocation but we fail-safe rather than
       AttributeError on a corrupt context.
    2. Delegates to :func:`watchlight_core.handle_declare_intent_call`
       to (a) byte-truncate the objective, (b) stamp the run
       handle's intent fields with provenance ``Declared``, and
       (c) return the canonical response dict.
    3. Returns the response dict to Pydantic AI, which surfaces it
       to the agent as the tool's output.

    The tool name parameter is kept for log-message clarity if the
    plugin ever extends to multiple synthetic tools.
    """

    async def _watchlight_declare_intent(objective: str, category: str, justification: Optional[str] = None) -> Dict[str, Any]:
        """Declare the agent's intent for this session.

        ``category`` is one of ``watchlight_core.INTENT_CATEGORIES`` or
        ``custom:<name>``; wl-apdp requires it. Stamps the objective
        and category onto the run handle so the next
        ``authorize_action`` call auto-injects
        the typed ``intent={"objective", "category"}`` into the APDP
        request body.
        That lets the Cedar context projection see a caller-declared
        inline intent and stamp the evaluation context with
        ``provenance: "declared"``, which clears greenfield policies
        that forbid actions until an intent has been declared.
        """
        # Lazy import to avoid a hard dep at module-import time on
        # callers that only consume the extractor (e.g. doc tooling).
        from watchlight_core import handle_declare_intent_call

        active_handle = _current_handle.get()
        if active_handle is None:
            # Defensive fail-safe — the contextvar should always be
            # populated when a tool fires inside an instrumented run.
            # If it isn't, the customer either uninstalled the
            # instrumentation mid-flight or invoked the tool from
            # outside Pydantic AI's normal lifecycle. We don't mutate
            # state we can't attribute; the agent sees the rejected
            # response and can retry.
            logger.warning(
                "watchlight_pydantic_ai: %s called with no active "
                "run handle in the contextvar; rejecting.",
                tool_name,
            )
            return {
                "status": "rejected",
                "reason": (
                    "no active Watchlight run handle in the calling "
                    "context"
                ),
            }
        return handle_declare_intent_call(
            active_handle,
            {"objective": objective, "category": category, "justification": justification},
        )

    return _watchlight_declare_intent


# ─── Test helpers ────────────────────────────────────────────────────


def _reset_contextvar_for_tests() -> None:
    """Reset the contextvars to their defaults. Test-only helper.

    Useful when a previous test left state stamped on the
    process-global context (typically via a bug or a forced
    teardown). Not part of the public API; named with a leading
    underscore.
    """
    _current_handle.set(None)
    _governing_agent.set(None)
