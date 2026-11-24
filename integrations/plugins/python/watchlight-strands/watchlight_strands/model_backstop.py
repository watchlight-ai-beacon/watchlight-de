"""The per-call backstop: every ``strands`` model call.

The invocation-start gates (``model_reach``, ``aux_models``) find the models
an agent can call by walking what it holds. Some model calls cannot be
found that way:

- a model a tool body or a component method builds at call time;
- a model a component's method reads from a module global (the walk follows
  functions it reaches, not every method of every class);
- a model held where the walk does not read (a suspended generator, or an
  object that hides an attribute behind a property, slot or metaclass
  trick);
- a call made after the governed run has ended (a hook that runs after the
  plugin closes the run, or a background task).

So the plugin also wraps ``stream`` and ``structured_output`` on every
``strands.models.Model`` subclass: the ones already defined when the first
plugin is created, and every later one (through ``Model.__init_subclass__``).
Before the model runs, the wrapper checks the call:

- **A governed run for the call.** A context that opens a governed run is
  marked, and the mark never resets in that context. A marked call needs
  the context's innermost governed run to be open, not suspended,
  quarantined or severed; that covers calls after the run has ended.
  Asyncio tasks and ``asyncio.to_thread`` inherit the mark. A plain
  ``threading.Thread``, ``loop.run_in_executor``,
  ``ThreadPoolExecutor.submit``, a task created with a fresh
  ``contextvars.Context()`` and a child process start without it. So
  while any governed run is live in the process (open, or suspended while
  it waits for a human approval), a call with no governed
  run in its context is refused, wherever it comes from. The only way
  past that is :func:`direct_model_use`, which logs a warning on every
  entry. With no governed run live in the process, a call with no mark is
  not checked (direct model use, see the README).
- **Configured hosted tools.** Every provider-hosted tool the model's
  configuration enables must have been allowed on that run. The
  invocation-start gates record what they allowed. Anything else is
  authorized on the run now, through the shared
  ``watchlight_core.hosted_tools`` gate, and a refusal stops the call. A
  configuration that cannot be read refuses the call.

The tool specs and payload of a call made through the agent loop are the
per-call gate's job; the backstop reads the model's configuration.
"""

from __future__ import annotations

import contextlib
import contextvars
import functools
import os
import sys
import threading
import time
import types
import weakref
from typing import Any, Callable, Dict, Iterator, Optional, Tuple

from watchlight_core import get_logger

from .aux_models import UngovernedModelCall

logger = get_logger("watchlight_strands")

#: Set inside :func:`direct_model_use`.
_DIRECT_USE: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "watchlight_strands_direct_model_use", default=False
)

#: Every governed run that is live in the process, from any plugin: open,
#: including one suspended while it waits for a human approval. Keyed by
#: ``id(run)``: a weak reference to the run, and for a suspended run the
#: monotonic time its wait is abandoned (``None`` while it runs).
_live_runs: Dict[int, Tuple["weakref.ReferenceType[Any]", Optional[float]]] = {}
#: Re-entrant: a weak-reference callback can fire inside a locked section.
_live_lock = threading.RLock()


def _collected(key: int) -> Callable[[Any], None]:
    def callback(ref: Any) -> None:
        with _live_lock:
            entry = _live_runs.get(key)
            if entry is None or entry[0] is not ref:
                return
            del _live_runs[key]
        logger.warning(
            "watchlight_strands: a governed run left the live set because it was abandoned "
            "(its agent was garbage collected without the run ending)"
        )

    return callback


def run_live(run: Any) -> None:
    """A governed run opened or resumed."""
    key = id(run)
    with _live_lock:
        entry = _live_runs.get(key)
        ref = entry[0] if entry is not None and entry[0]() is run else weakref.ref(run, _collected(key))
        _live_runs[key] = (ref, None)


def run_suspended(run: Any, wait_seconds: float) -> None:
    """A governed run waits for a human approval. It stays live; if it is
    not resumed or closed within ``wait_seconds`` its wait is abandoned and
    it leaves the live set."""
    key = id(run)
    with _live_lock:
        entry = _live_runs.get(key)
        if entry is not None and entry[0]() is run:
            _live_runs[key] = (entry[0], time.monotonic() + max(0.0, wait_seconds))


def run_ended(run: Any) -> None:
    """A governed run closed (completed, failed, cancelled or superseded)."""
    key = id(run)
    with _live_lock:
        entry = _live_runs.get(key)
        if entry is not None and entry[0]() is run:
            del _live_runs[key]


def live_run_count() -> int:
    """The live governed runs, after removing every suspended run whose
    approval wait was abandoned (each logged)."""
    now = time.monotonic()
    with _live_lock:
        expired = [k for k, (_, deadline) in _live_runs.items() if deadline is not None and deadline <= now]
        for key in expired:
            del _live_runs[key]
        count = len(_live_runs)
    for _ in expired:
        logger.warning(
            "watchlight_strands: a governed run left the live set because its approval wait "
            "was abandoned (not resumed before its session expired)"
        )
    return count


def direct_use_declared() -> bool:
    return _DIRECT_USE.get()


@contextlib.contextmanager
def direct_model_use() -> Iterator[None]:
    """Declare that the model calls in this block are your own direct model
    use, outside any governed run. While a governed run is live in the
    process, a model call with no governed run in its context is refused
    unless it is made inside this block. A call inside a live governed run
    is always checked; this block never lifts that. Every entry logs a
    warning (with its call site, no values), so the escape is auditable.
    The block covers its own context only: a thread it starts needs its own
    block."""
    caller = sys._getframe(2) if hasattr(sys, "_getframe") else None
    where = (
        f"{os.path.basename(caller.f_code.co_filename)}:{caller.f_lineno}" if caller else "unknown"
    )
    logger.warning(
        "watchlight_strands: direct model use declared at %s while %d governed run(s) are "
        "live; model calls in this block are not governed by Watchlight",
        where,
        live_run_count(),
    )
    token = _DIRECT_USE.set(True)
    try:
        yield
    finally:
        _DIRECT_USE.reset(token)


def _class_lookup(mro: Any, name: str) -> Tuple[Any, Any]:
    """``(owner, value)`` for ``name`` in the class namespaces of ``mro``, read
    raw (no descriptor is invoked); ``(None, None)`` when no class has it."""
    for klass in mro:
        namespace = type.__dict__["__dict__"].__get__(klass)
        if name in namespace:
            return klass, namespace[name]
    return None, None


def _is_data_descriptor(value: Any) -> bool:
    kind = type(value)
    return any(_class_lookup(type.__dict__["__mro__"].__get__(kind), m)[0] is not None for m in ("__set__", "__delete__"))


def has_backstop(model: Any) -> bool:
    """Whether calls to ``model`` go through the backstop: it is a
    ``strands`` ``Model``, attribute lookup on it is the default one, and the
    ``stream`` and ``structured_output`` that lookup resolves to are wrapped.

    Resolved as Python does: a data descriptor on the class (a ``property``)
    wins over the instance, then an instance attribute, then the class. A
    class that redefines ``__getattribute__`` could resolve them to
    anything, so it is refused, as is a data descriptor."""
    from strands.models import Model

    if not issubclass(type(model), Model):
        return False
    mro = type.__dict__["__mro__"].__get__(type(model))
    if _class_lookup(mro, "__getattribute__")[0] not in (object, Model):
        return False
    # ``__getattr__`` is not consulted: both names always resolve.
    try:
        own = object.__getattribute__(model, "__dict__")
    except AttributeError:
        own = {}
    for name in _METHODS:
        _, on_class = _class_lookup(mro, name)
        if _is_data_descriptor(on_class):
            return False
        method = own[name] if name in own else on_class
        if not _is_wrapped(method):
            return False
    return True


def _is_wrapped(method: Any) -> bool:
    """Is ``method`` the backstop's wrap (or a bound method of it)? Read raw:
    an object with its own ``__getattr__`` could claim the mark."""
    if type(method) is types.MethodType:
        method = object.__getattribute__(method, "__func__")
    if type(method) is not types.FunctionType:
        return False
    return object.__getattribute__(method, "__dict__").get(_WRAPPED_MARK) is True


def require_backstop(model: Any) -> None:
    """Refuse a model whose calls would not reach the backstop."""
    if not has_backstop(model):
        raise UngovernedModelCall(
            f"Watchlight refused the call: the model ({type(model).__name__}) is not a strands "
            "model, or its stream or structured_output was replaced after the plugin wrapped it"
        )

#: Set when a governed run opens in a context, and never cleared there, so
#: a caller that awaits an invocation in its own task keeps it afterwards.
#: Asyncio tasks and ``asyncio.to_thread`` inherit it; plain threads,
#: executors and fresh contexts do not (the live-run count covers those).
GOVERNED_CONTEXT: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "watchlight_strands_governed_context", default=False
)

#: The methods wrapped on each model class.
_METHODS = ("stream", "structured_output")
_WRAPPED_MARK = "__watchlight_backstop__"

_install_lock = threading.Lock()
_installed = False


#: Returns the innermost run of the current context (or ``None``), and
#: checks one call (the model, and the invocation_state Strands passed) against
#: it. Set by the plugin when it installs.
_check_call: Optional[Callable[[Any, Any], Any]] = None


def _wrap(method: Callable[..., Any]) -> Callable[..., Any]:
    @functools.wraps(method)
    async def governed(self: Any, *args: Any, **kwargs: Any) -> Any:
        check = _check_call
        if check is None:  # pragma: no cover - set before any wrap
            raise UngovernedModelCall("Watchlight refused the model call: no plugin is installed")
        recheck = await check(self, kwargs.get("invocation_state"))
        async for event in method(self, *args, **kwargs):
            yield event
        if recheck is not None:
            # Before Strands dispatches any tool the response asked for.
            recheck()

    setattr(governed, _WRAPPED_MARK, True)
    return governed


def _wrap_class(cls: type) -> None:
    """Wrap the methods ``cls`` defines itself (inherited ones are wrapped
    where they are defined)."""
    namespace = type.__dict__["__dict__"].__get__(cls)
    for name in _METHODS:
        method = namespace.get(name)
        if method is None or getattr(method, _WRAPPED_MARK, False):
            continue
        if not callable(method) or getattr(method, "__isabstractmethod__", False):
            continue
        type.__setattr__(cls, name, _wrap(method))


def _all_subclasses(root: type) -> list:
    found, stack = [], [root]
    while stack:
        cls = stack.pop()
        for sub in type.__subclasses__(cls):
            if sub not in found:
                found.append(sub)
                stack.append(sub)
    return found


def install(check_call: Callable[[Any], Any]) -> None:
    """Wrap every ``Model`` subclass, now and later. Idempotent."""
    global _installed, _check_call
    with _install_lock:
        _check_call = check_call
        if _installed:
            return
        from strands.models import Model

        original = type.__dict__["__dict__"].__get__(Model).get("__init_subclass__")

        def __init_subclass__(cls: type, **kwargs: Any) -> None:
            if original is not None:
                original.__func__(cls, **kwargs)
            else:
                super(Model, cls).__init_subclass__(**kwargs)
            _wrap_class(cls)

        type.__setattr__(Model, "__init_subclass__", classmethod(__init_subclass__))
        for cls in _all_subclasses(Model):
            _wrap_class(cls)
        _installed = True


def mark_governed() -> None:
    """Mark the current context as inside a governed invocation."""
    GOVERNED_CONTEXT.set(True)
