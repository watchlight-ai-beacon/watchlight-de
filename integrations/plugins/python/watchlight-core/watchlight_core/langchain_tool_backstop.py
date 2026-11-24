"""Process-wide LangChain backstop: refuse tool calls no governed agent
authorized. Shared by every LangChain-based plugin
(watchlight-deepagents, watchlight-langgraph); import it only where
``langchain-core`` is installed.

A LangChain agent that skips a plugin's governed path (one a tool body
builds and runs, a plain ``create_agent``, a ``ToolNode``) gets no
Watchlight middleware, so its tools would run with no decision.
LangChain offers a public, process-wide extension point that reaches it:
``langchain_core.tracers.context.register_configure_hook``. Every callback
manager LangChain configures, the inner agent's included, gets the handler
held in the registered context variable, even when the inner agent is
invoked with ``callbacks=[]`` or on a new thread (the handler is the
variable's default). This module registers one such handler, once, when
a plugin first installs. No framework class is patched. Each plugin
registers how to list its live governed runs; the backstop acts while any
plugin has one.

While at least one governed run is live in the process:

* **Tool starts.** A plugin's governed path grants exactly one tool start
  per authorized call: a single-use grant binding the call's run, its
  ``tool_call_id`` and the tool name, set around the call. The first
  ``on_tool_start`` with that id and name, while that run is still live,
  consumes it, atomically. Any other tool start is refused before the tool
  runs: no grant, a used grant, a different id or name, or a run that has
  ended. A grant made with no id (``governed_tool_call``, which has none)
  matches only a start that carries no id.
* **Model turns inside a governed tool body.** The middleware marks the
  body of each ordinary tool call it allows. A chat-model or LLM start
  under that mark is refused: it is an agent the tool body runs, or a
  model the tool calls directly. A tool that must call a model directly
  wraps the call in :func:`direct_model_use`; a request that binds tools
  is refused even then, so it never covers an agent's turn.
* **Model turns that bind tools.** A model start that binds tools (local
  or provider-hosted: ``tools``, ``functions`` or ``tool_choice``; an
  unreadable request counts as binding) must run inside a governed
  agent's own model call, which the middleware marks; otherwise it is
  refused. Provider-hosted tools run on the provider's side with no tool
  start, so this is the only place to stop them. A model call that binds
  no tools outside a tool body, such as deepagents' summarization, is
  not affected.

With no governed run live, the handler does nothing.

The handler is synchronous with ``raise_error=True`` and
``run_inline=True``: LangChain swallows an exception an async handler
raises, and runs a sync handler's raise straight into the tool or model
call. Its checks are local and never wait on I/O. Each refusal is queued
and published, value-free, by the middleware when the governed tool call
that contained it returns, or when the run ends.

Limits (see the README): the state is process-wide, so an ungoverned agent
running concurrently in the same process is refused too. A model call that
binds no tools on a raw thread, or under a fresh ``contextvars.Context``,
started from a tool body carries no mark and is not refused (it can run no
tool: its tool starts are refused, and it binds no hosted tool). A
governed agent's own summarization is refused when that agent runs inside
another governed agent's ordinary tool body (fail closed). The grant is
single use, so a retry must re-enter the governance middleware: a wrapper
placed inside it that retries a tool within the same call has the retry
refused. LangChain runs the caller's own callback handlers before this
one, so a start that fails in an earlier handler leaves the grant usable
once until the call returns (at most one body still runs for that run,
call id and tool name); the grant is spent when the call ends. Code that
calls a tool's private ``_run``, a model's private ``_generate``, or a provider SDK directly bypasses LangChain's callbacks,
and code that deliberately edits LangChain's configure hooks or these
context variables can remove the backstop.
"""

from __future__ import annotations

import contextlib
import contextvars
import threading
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterator, List, Optional, Union

from langchain_core.callbacks import BaseCallbackHandler
from langchain_core.tracers.context import register_configure_hook

from .errors import GovernanceUnavailable


class UngovernedToolCall(GovernanceUnavailable):
    """A tool started that no governed agent authorized."""


class UngovernedModelCall(GovernanceUnavailable):
    """A model was called inside a governed tool body."""


@dataclass
class ToolGrant:
    """The one tool start a governed tool call may make, for its run."""

    tool_call_id: Optional[str]
    tool_name: Optional[str]
    handle: Any
    used: bool = False


@dataclass
class ToolBody:
    """Marks the body of a governed tool call. ``models`` is which model
    starts the body refuses: ``"all"`` (deepagents: an agent built in a
    tool), or ``"binding"`` (watchlight-langgraph: only a start that binds
    tools, so a tool may still call a model to summarize)."""

    handle: Any
    direct_model_use: bool = False
    models: str = "all"


@dataclass
class Refusal:
    """One refusal, waiting to be published (names only, no values)."""

    kind: str  # "tool" | "model"
    name: str
    handle: Any


_TOOL_GRANT: contextvars.ContextVar[Optional[ToolGrant]] = contextvars.ContextVar(
    "watchlight_core.langchain_tool_backstop.tool_grant", default=None
)
_TOOL_BODY: contextvars.ContextVar[Optional[ToolBody]] = contextvars.ContextVar(
    "watchlight_core.langchain_tool_backstop.tool_body", default=None
)
_GOVERNED_MODEL_CALL: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "watchlight_core.langchain_tool_backstop.governed_model_call", default=False
)

_lock = threading.Lock()
_pending: List[Refusal] = []


#: One callable per plugin, each listing that plugin's live governed runs.
_live_run_sources: List[Callable[[], List[Any]]] = []
#: One callable per plugin that has one: the plugin's run acting in this
#: context (core's attribution resolver), or ``None``.
_acting_sources: List[Callable[[], Optional[Any]]] = []
_installed = False


def _live_handles() -> List[Any]:
    """Every governed run live now, across the plugins that registered."""
    with _lock:
        sources = list(_live_run_sources)
    live: List[Any] = []
    for source in sources:
        live.extend(source())
    return live


def _consume(grant: Optional[ToolGrant], call_id: Any, name: str) -> bool:
    """Use ``grant`` for this tool start if it matches, atomically: a grant
    whose context was copied into two threads releases one start only."""
    if grant is None:
        return False
    if grant.tool_call_id is None:
        if call_id is not None:
            return False
    elif not isinstance(call_id, str) or call_id != grant.tool_call_id:
        return False
    if name != grant.tool_name:
        return False
    if not any(handle is grant.handle for handle in _live_handles()):
        return False
    acting = _acting_run()
    if acting is not None and acting is not grant.handle:
        # Another run acts here now (a sub-agent spawned in the tool's
        # body): the grant was for this call under its own run only.
        return False
    with _lock:
        if grant.used:
            return False
        grant.used = True
    return True


def _queue(kind: str, name: str, handle: Any) -> None:
    """Queue a refusal for the run it happened under; with none known (a
    raw thread), for every run live now."""
    handles = [handle] if handle is not None else list(_live_handles())
    with _lock:
        _pending.extend(Refusal(kind, name, h) for h in handles)


_emit_failures = 0


def record_emit_failure() -> None:
    """Count a refusal that could not be published to lineage."""
    global _emit_failures
    with _lock:
        _emit_failures += 1


def emit_failures() -> int:
    """How many refusals this process could not publish to lineage
    (process-lifetime, value-free). Non-zero means a lineage gap."""
    with _lock:
        return _emit_failures


def take_refusals(handle: Any) -> List[Refusal]:
    """Remove and return the queued refusals that belong to ``handle``."""
    with _lock:
        mine = [r for r in _pending if r.handle is handle]
        _pending[:] = [r for r in _pending if r.handle is not handle]
    return mine


def _tool_name(serialized: Any, kwargs: Dict[str, Any]) -> str:
    name = kwargs.get("name")
    if not isinstance(name, str) and isinstance(serialized, dict):
        name = serialized.get("name")
    return name if isinstance(name, str) and name else "unknown"


_TOOL_KEYS = ("tools", "functions", "tool_choice")


def _names_tools(mapping: Any) -> bool:
    """Whether ``mapping``, or a ``model_kwargs`` mapping inside it, names
    tools."""
    if not isinstance(mapping, dict):
        return False
    if any(mapping.get(key) for key in _TOOL_KEYS):
        return True
    nested = mapping.get("model_kwargs")
    return isinstance(nested, dict) and any(nested.get(key) for key in _TOOL_KEYS)


def _binds_tools(serialized: Any, kwargs: Dict[str, Any]) -> bool:
    """Whether a model request binds tools, local or provider-hosted. An
    unreadable request counts as binding them (fail closed)."""
    params = kwargs.get("invocation_params")
    if not isinstance(params, dict):
        return True
    serialized_kwargs = (
        serialized.get("kwargs") if isinstance(serialized, dict) else None
    )
    return _names_tools(params) or _names_tools(serialized_kwargs)


class _Backstop(BaseCallbackHandler):
    raise_error = True
    run_inline = True

    def on_tool_start(self, serialized: Any, input_str: str, **kwargs: Any) -> None:
        if not _live_handles():
            return
        name = _tool_name(serialized, kwargs)
        grant = _TOOL_GRANT.get()
        if _consume(grant, kwargs.get("tool_call_id"), name):
            return
        _queue("tool", name, grant.handle if grant is not None else _body_handle())
        raise UngovernedToolCall(
            f"Watchlight refused tool {name!r}: no governed agent authorized this call"
        )

    def on_chat_model_start(
        self, serialized: Any, messages: Any, **kwargs: Any
    ) -> None:
        self._model_start(serialized, kwargs)

    def on_llm_start(self, serialized: Any, prompts: Any, **kwargs: Any) -> None:
        self._model_start(serialized, kwargs)

    def _model_start(self, serialized: Any, kwargs: Dict[str, Any]) -> None:
        if not _live_handles():
            return
        binds = _binds_tools(serialized, kwargs)
        body = _TOOL_BODY.get()
        acting = _acting_run()
        if body is not None and acting is not None and acting is not body.handle:
            # A sub-agent spawned inside the tool acts here: its turn.
            body = None
        if body is not None:
            if not binds and (body.direct_model_use or body.models == "binding"):
                return
            reason = (
                "inside a governed tool body: an agent built in a tool runs ungoverned"
            )
        elif _GOVERNED_MODEL_CALL.get() or acting is not None:
            return
        elif binds:
            reason = "that binds tools outside a governed agent's model call"
        else:
            return
        _queue(
            "model",
            _tool_name(serialized, kwargs),
            body.handle if body is not None else None,
        )
        raise UngovernedModelCall(f"Watchlight refused a model call {reason}")


def _acting_run() -> Optional[Any]:
    """The run acting in this context, by the first plugin that names one."""
    with _lock:
        sources = list(_acting_sources)
    for source in sources:
        handle = source()
        if handle is not None:
            return handle
    return None


def _body_handle() -> Any:
    body = _TOOL_BODY.get()
    return body.handle if body is not None else None


#: Holds the handler; its default is the handler itself once installed, so
#: every context, a new thread's included, carries it.
_HANDLER_VAR: Optional[contextvars.ContextVar[Optional[BaseCallbackHandler]]] = None


def install(
    live_handles: Callable[[], List[Any]],
    *,
    acting_run: Optional[Callable[[], Optional[Any]]] = None,
) -> None:
    """Register the backstop once per process, and once per callable:
    ``live_handles`` (one plugin's governed runs live now) and, for a
    plugin that resolves its acting run through core's attribution,
    ``acting_run`` (that run in this context, or ``None``)."""
    global _installed, _HANDLER_VAR
    with _lock:
        if live_handles not in _live_run_sources:
            _live_run_sources.append(live_handles)
        if acting_run is not None and acting_run not in _acting_sources:
            _acting_sources.append(acting_run)
        if _installed:
            return
        _HANDLER_VAR = contextvars.ContextVar(
            "watchlight_core.langchain_tool_backstop.handler", default=_Backstop()
        )
        register_configure_hook(_HANDLER_VAR, True)
        _installed = True


@contextlib.contextmanager
def grant_tool_start(
    tool_call_id: Optional[str],
    tool_name: Optional[str],
    handle: Any,
    *,
    body: Union[bool, str],
) -> Iterator[None]:
    """Around an authorized call: grant its one tool start, and mark the
    tool body unless ``body`` is false (a governed ``task`` spawn).
    ``body=True`` refuses every model start in the body; ``"binding"``
    refuses only one that binds tools."""
    grant = ToolGrant(tool_call_id, tool_name, handle)
    grant_token = _TOOL_GRANT.set(grant)
    marked = (
        ToolBody(handle, models="binding" if body == "binding" else "all")
        if body
        else None
    )
    body_token = _TOOL_BODY.set(marked)
    mark_token = _GOVERNED_MODEL_CALL.set(False)
    try:
        yield
    finally:
        # Spent when the call ends, used or not: a context copied during
        # the call (where a start that failed before the backstop saw it
        # left the grant unused) can never start the tool later.
        with _lock:
            grant.used = True
        _GOVERNED_MODEL_CALL.reset(mark_token)
        _TOOL_BODY.reset(body_token)
        _TOOL_GRANT.reset(grant_token)


@contextlib.contextmanager
def governed_model_call() -> Iterator[None]:
    """Around a governed agent's own model call (``handler(request)`` in
    the middleware's model wrap): marked governed, and not a tool body."""
    body_token = _TOOL_BODY.set(None)
    mark_token = _GOVERNED_MODEL_CALL.set(True)
    try:
        yield
    finally:
        _GOVERNED_MODEL_CALL.reset(mark_token)
        _TOOL_BODY.reset(body_token)


@contextlib.contextmanager
def direct_model_use() -> Iterator[None]:
    """Let the enclosed code call a model directly from inside a governed
    tool body. A model request that binds tools is still refused, so this
    never covers an agent's turn."""
    body = _TOOL_BODY.get()
    if body is None:
        yield
        return
    token = _TOOL_BODY.set(ToolBody(body.handle, direct_model_use=True))
    try:
        yield
    finally:
        _TOOL_BODY.reset(token)
