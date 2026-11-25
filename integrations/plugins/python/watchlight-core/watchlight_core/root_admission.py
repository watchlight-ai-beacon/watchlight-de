"""Root admission: a nested run that lost its run's context never becomes a root.

Framework plugins link a nested agent run to its parent through context
(a ``contextvars.ContextVar``, a graph state key). Code that drops that
context (an executor, a thread, a fresh ``contextvars.Context``, a deferred
start) reaches the plugin's root path with no parent. Opening a root there
would run the nested agent with none of its parent's attenuation and no
link to its lineage.

This module is the shared, process-wide admission every plugin's root path
goes through:

* :func:`reserve_root` admits a root before anything is sent. An implicit
  root is refused (:class:`~watchlight_core.NestedRunEscapedError`) while
  any governed run is live or opening in the process. A declared root
  (inside :class:`RootRun`) gets the live root execution ids to declare to
  the server (``Action::"open_declared_root"``), and is refused for an agent
  whose sub-agent spawn was refused in a run tree that is still live.
* :func:`release_root` ends the reservation and registers the opened run in
  the same step; :func:`register_run` registers a spawned sub-agent.
* :func:`record_refused_spawn` remembers a refused spawn for the life of its
  root tree, never for the life of the process.
* :class:`RootRun` is the declaration: a context manager (sync or async) and
  a decorator. Plugins subclass it to say what "inside a live run" means in
  their own context.
"""

from __future__ import annotations

import asyncio
import contextvars
import functools
import threading
import weakref
from typing import Any, Callable, List, Optional, Set, Tuple

from .decision import RunHandleState
from .errors import (
    DECLARED_ROOT_INVALID,
    DeclaredRootRefused,
    NestedRunEscapedError,
    SpawnRefusedRootRunError,
)
from .log import get_logger

logger = get_logger("watchlight_core.root_admission")

__all__ = [
    "MAX_DECLARED_LIVE_ROOTS",
    "RootRun",
    "declared_root_requested",
    "handle_is_live",
    "record_refused_spawn",
    "register_run",
    "release_root",
    "reserve_root",
]

#: The server's bound on ``declared_root.live_execution_ids``.
MAX_DECLARED_LIVE_ROOTS = 64

_lock = threading.Lock()
# Every governed run a plugin opened. Weak, so a dropped handle never pins
# a run as live; liveness is read from the handle itself.
_runs: "weakref.WeakSet[Any]" = weakref.WeakSet()
# Roots whose session open is in flight: they count as live, so two roots
# racing to open cannot both see an empty registry.
_pending_roots = 0
# (agent slug, root execution id) for every refused sub-agent spawn. An
# entry holds while its root tree has a live run, then it is dropped.
_refused_spawns: Set[Tuple[str, str]] = set()

# Set inside :class:`RootRun`: a root path in this context opens a declared
# root.
_declared_root: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "watchlight_core.declared_root", default=False
)


def handle_is_live(handle: Any) -> bool:
    """``True`` while ``handle`` can still govern calls: opened, not
    completed or terminated, not quarantined or severed."""
    if handle is None or getattr(handle, "_completed", True):
        return False
    state = getattr(handle, "state", None)
    return state is None or state == RunHandleState.ACTIVE


def declared_root_requested() -> bool:
    """Whether the calling context is inside :class:`RootRun`."""
    return _declared_root.get()


def _live_root_ids_locked() -> Set[str]:
    roots: Set[str] = set()
    for handle in list(_runs):
        if handle_is_live(handle):
            root = getattr(handle, "root_execution_id", None)
            if isinstance(root, str) and root:
                roots.add(root)
    return roots


def reserve_root(slug: str, *, declared: bool, hint: str) -> Optional[List[str]]:
    """Admit a root for agent ``slug`` before anything is sent.

    Returns ``None`` for an admitted implicit root, or the sorted live root
    execution ids for an admitted declared root. Either way a pending slot
    is reserved; the caller MUST call :func:`release_root` exactly once
    afterwards, whether the run opened or not. Raises, reserving nothing,
    when the root is refused. ``hint`` tells the caller how this
    framework keeps a nested run governed.
    """
    global _pending_roots
    with _lock:
        live_roots = _live_root_ids_locked()
        stale = {entry for entry in _refused_spawns if entry[1] not in live_roots}
        _refused_spawns.difference_update(stale)
        if not declared:
            if live_roots or _pending_roots:
                _refuse_escaped_root(slug, hint)
            _pending_roots += 1
            return None
        if any(entry[0] == slug for entry in _refused_spawns):
            logger.warning(
                "agent %r was refused as a sub-agent in a governed run that is "
                "still live; it does not start as a declared root",
                slug,
            )
            raise SpawnRefusedRootRunError(
                f"Watchlight AI Agent Runtime Governance refused a declared root "
                f"for agent {slug!r}: its sub-agent spawn was refused in a "
                f"governed run that is still live, so it was not started (no "
                f"model turn, no tool call)."
            )
        if len(live_roots) > MAX_DECLARED_LIVE_ROOTS:
            raise DeclaredRootRefused(
                f"Watchlight AI Agent Runtime Governance cannot declare a root "
                f"for agent {slug!r} while more than {MAX_DECLARED_LIVE_ROOTS} "
                f"governed runs are live in this process; it was not started.",
                code=DECLARED_ROOT_INVALID,
            )
        _pending_roots += 1
        return sorted(live_roots)


def release_root(handle: Optional[Any]) -> None:
    """End a :func:`reserve_root` reservation, registering the opened root
    (when there is one) in the same step so it is never unaccounted for."""
    global _pending_roots
    with _lock:
        if handle is not None:
            _runs.add(handle)
        _pending_roots -= 1


def register_run(handle: Any) -> None:
    """Register a governed run opened outside :func:`reserve_root` (a
    spawned sub-agent)."""
    with _lock:
        _runs.add(handle)


def record_refused_spawn(slug: str, parent: Any) -> None:
    """Remember that agent ``slug`` was refused as a sub-agent of
    ``parent``, for as long as ``parent``'s root tree has a live run."""
    root = getattr(parent, "root_execution_id", None)
    if isinstance(root, str) and root:
        with _lock:
            _refused_spawns.add((slug, root))


def _refuse_escaped_root(slug: str, hint: str) -> None:
    logger.warning(
        "agent %r was started with no governed run in its context while a "
        "governed run is live in this process; it does not start as a new root",
        slug,
    )
    raise NestedRunEscapedError(
        f"Watchlight AI Agent Runtime Governance refused to start agent "
        f"{slug!r}: a governed run is live in this process but this call is "
        f"outside its context (an executor, a thread or a fresh "
        f"contextvars.Context drops it), so it would start as an independent "
        f"root. It was not started (no model turn, no tool call). {hint}",
        reason="implicit_root_while_run_live",
    )


class RootRun:
    """Declare an independent governed root run.

    A context manager (sync or async) and a decorator (``@root_run()`` or
    ``@root_run`` on a sync or async function). A root a plugin opens in it
    is declared to the server with the live root execution ids. Refused on
    entry when the calling context is inside a live governed run: an agent
    started there is a governed sub-agent.

    Plugins subclass it and override :meth:`_in_live_run` (how the plugin
    sees the run in the current context) and, when the plugin keeps other
    per-context state, :meth:`_enter_context` / :meth:`_exit_context`.
    """

    def __init__(self, func: Optional[Callable[..., Any]] = None) -> None:
        self._tokens: List[contextvars.Token] = []
        self._func = func
        if func is not None:
            functools.update_wrapper(self, func)

    # Plugin hooks ------------------------------------------------------

    def _in_live_run(self) -> bool:
        return False

    def _enter_context(self) -> None:
        return None

    def _exit_context(self) -> None:
        return None

    # Protocol ----------------------------------------------------------

    def _enter(self) -> None:
        if self._in_live_run():
            raise NestedRunEscapedError(
                "Watchlight AI Agent Runtime Governance refused root_run(): it "
                "was entered inside a live governed run, where an agent runs "
                "as a governed sub-agent. Call the agent directly instead.",
                reason="declared_root_inside_live_run",
            )
        self._tokens.append(_declared_root.set(True))
        self._enter_context()

    def _exit(self) -> None:
        self._exit_context()
        _declared_root.reset(self._tokens.pop())

    def __enter__(self) -> "RootRun":
        self._enter()
        return self

    def __exit__(self, *exc: Any) -> None:
        self._exit()

    async def __aenter__(self) -> "RootRun":
        self._enter()
        return self

    async def __aexit__(self, *exc: Any) -> None:
        self._exit()

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        cls = type(self)
        if self._func is None:
            # ``@root_run()``: decorate the function.
            (func,) = args
            return cls(func)
        func = self._func
        if asyncio.iscoroutinefunction(func):

            async def _declared() -> Any:
                async with cls():
                    return await func(*args, **kwargs)

            return _declared()
        with cls():
            return func(*args, **kwargs)
