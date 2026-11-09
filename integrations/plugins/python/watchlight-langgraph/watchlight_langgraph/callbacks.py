"""`WatchlightCallbackHandler` — LangChain / LangGraph callback
handler that captures execution events and publishes them as
canonical Watchlight :class:`ExecutionEvent` dicts via APDP.

# Design

LangChain's :class:`BaseCallbackHandler` fires hooks at well-
defined points in execution. The customer attaches an instance of
:class:`WatchlightCallbackHandler` to their graph compile or
runnable invocation; the handler captures each hook event,
buffers them internally, and publishes the translated batch on
``flush()`` (called explicitly by the customer or implicitly by
the RunHandle's context manager exit).

We deliberately buffer + flush rather than POST per-callback for
two reasons:

1. **Audit-log efficiency** — a single LangGraph execution can
   generate dozens of callback events. Posting each one would
   create a thrash pattern on ``wl-apdp /v1/events``. Buffering
   into a single batch POST is the same shape as ``wl-proxy``'s
   audit emission.
2. **Atomicity per execution** — flushing once at the end of an
   execution lets downstream consumers reason about an execution
   as a unit. Drift detection, in particular, runs per
   completed execution; receiving events in batches that
   correspond to executions makes the consumer's job simpler.

If a customer needs near-real-time emission, they can call
``flush()`` periodically (e.g. after every tool invocation). The
buffer is reset on flush, so partial flushes don't lose events.

# Two handler classes

LangChain exposes both ``BaseCallbackHandler`` (sync) and
``AsyncCallbackHandler`` (async). We export both with identical
buffering behavior so customers can use whichever matches their
runtime. Sync handlers used in async code work (LangChain bridges
them), but async-native is cleaner.

# Failure modes

Hook methods MUST NOT raise. LangChain's callback machinery is
permissive about handler exceptions in some versions and strict
in others; either way, an exception thrown from our handler
would interrupt customer code. Every hook catches and logs
broadly.

``flush()`` is best-effort: a publish failure returns the count
of events attempted (so the customer can observe), but does not
raise.
"""

from __future__ import annotations

import time
import uuid
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any, Dict, Iterator, List, Optional, cast

# `langchain_core.callbacks.BaseCallbackHandler` is the public
# interface; LangGraph transits this dependency. If a customer's
# environment is missing langchain_core, the import will fail at
# plugin load — which is fine, because they'd also be unable to
# use LangGraph at all.
try:
    from langchain_core.callbacks import (
        AsyncCallbackHandler,
        BaseCallbackHandler,
    )
except ImportError as exc:  # pragma: no cover — defensive only
    raise ImportError(
        "watchlight_langgraph.callbacks requires langchain_core; "
        "install via `pip install langchain-core` or use the plugin "
        "with the langgraph extra (already a transitive dep)."
    ) from exc

from watchlight_core import get_logger, redacted_input_summary, summarize_arg_keys

from .intent import extract_intent_from_langgraph_inputs
from .traces import translate_langgraph_events

logger = get_logger("watchlight_langgraph.callbacks")


# Internal: a buffered-events container shared between the sync
# and async handlers. Keeping the buffering logic out of the
# callback methods keeps both handler classes thin.
class _EventBuffer:
    """Thread-safe-enough buffer for callback events.

    LangChain callback methods can fire from multiple threads in
    async-paired-with-sync setups. We use a list + lock pattern
    rather than a queue because the consumer (``flush``) wants the
    whole batch at once, and we never drain incrementally.
    """

    def __init__(self) -> None:
        self._events: List[Dict[str, Any]] = []
        # No explicit Lock: CPython's GIL serializes list appends,
        # which is enough for our use (we never iterate while
        # appending; ``flush`` swaps the whole list atomically).

    def append(self, event: Dict[str, Any]) -> None:
        self._events.append(event)

    def drain(self) -> List[Dict[str, Any]]:
        """Atomically swap the buffer for an empty list, returning
        the prior contents."""
        prior = self._events
        self._events = []
        return prior

    def __len__(self) -> int:
        return len(self._events)


def _capture_chain_start(
    buffer: _EventBuffer,
    serialized: Dict[str, Any],
    inputs: Dict[str, Any],
    *,
    run_id: Any = None,
    parent_run_id: Any = None,
    tags: Optional[List[str]] = None,
    metadata: Optional[Dict[str, Any]] = None,
    declared_intent_objective: Optional[str] = None,
    **kwargs: Any,
) -> None:
    # Zero-touch intent extraction. The captured event stashes BOTH
    # the extracted-from-inputs objective and any customer-declared
    # override; the translator (_on_chain_start) picks the
    # higher-precedence one when it builds the canonical
    # execution_started payload. Precedence chain:
    #
    #   declared (start_run(intent_objective=…))
    #   > plugin-derived (extracted from inputs — THIS hook)
    #   > absent (no signal anywhere)
    #
    # The customer-declared lane is plumbed via the handler's
    # constructor today, not via this kwarg directly — see
    # ``WatchlightCallbackHandler.__init__``. The kwarg here is the
    # internal seam.
    extracted_objective: Optional[str] = None
    try:
        extracted_objective = extract_intent_from_langgraph_inputs(inputs)
    except Exception as exc:  # noqa: BLE001 — extraction is best-effort
        logger.debug("intent extraction failed: %s", exc)

    buffer.append(
        {
            "hook": "on_chain_start",
            "serialized": serialized or {},
            "name": (serialized or {}).get("name"),
            "inputs_summary": _summarize(inputs),
            # Stash both signals on the buffered event so the
            # translator at flush time can apply precedence. Internal
            # keys (single-underscore prefix); the translator strips
            # them before building the canonical envelope.
            "_intent_declared": declared_intent_objective,
            "_intent_extracted": extracted_objective,
            "run_id": str(run_id) if run_id is not None else None,
            "parent_run_id": str(parent_run_id) if parent_run_id is not None else None,
            "tags": list(tags or []),
            "_start_time": time.monotonic(),
        }
    )


def _capture_chain_end(
    buffer: _EventBuffer,
    outputs: Dict[str, Any],
    *,
    run_id: Any = None,
    parent_run_id: Any = None,
    **kwargs: Any,
) -> None:
    buffer.append(
        {
            "hook": "on_chain_end",
            "outputs_summary": _summarize(outputs),
            "run_id": str(run_id) if run_id is not None else None,
            "parent_run_id": str(parent_run_id) if parent_run_id is not None else None,
        }
    )


def _capture_chain_error(
    buffer: _EventBuffer,
    error: BaseException,
    *,
    run_id: Any = None,
    parent_run_id: Any = None,
    **kwargs: Any,
) -> None:
    buffer.append(
        {
            "hook": "on_chain_error",
            "error": error,
            "run_id": str(run_id) if run_id is not None else None,
            "parent_run_id": str(parent_run_id) if parent_run_id is not None else None,
        }
    )


def _capture_tool_start(
    buffer: _EventBuffer,
    serialized: Dict[str, Any],
    input_str: str,
    *,
    run_id: Any = None,
    parent_run_id: Any = None,
    inputs: Optional[Dict[str, Any]] = None,
    **kwargs: Any,
) -> None:
    # langchain-core >= 0.2 passes the STRUCTURED tool arguments as the
    # ``inputs`` kwarg (a dict) alongside the string ``input_str``. That
    # dict is the only place the argument KEYS are available in a
    # structured form — ``input_str`` is a flat rendering. Compute the
    # sorted-key summary HERE and buffer only the resulting string, so
    # argument VALUES are never retained beyond this callback frame.
    # Absent on older langchain-core → arg_key_summary stays None
    # (back-compat: the event simply omits the field).
    # The buffered ``input_summary`` is value-free (argument names and
    # value types only); the raw ``input_str`` is never retained.
    arg_key_summary = summarize_arg_keys(inputs)
    buffer.append(
        {
            "hook": "on_tool_start",
            "serialized": serialized or {},
            "name": (serialized or {}).get("name"),
            "input_summary": redacted_input_summary(
                inputs if isinstance(inputs, dict) else input_str
            ),
            "arg_key_summary": arg_key_summary,
            "run_id": str(run_id) if run_id is not None else None,
            "parent_run_id": str(parent_run_id) if parent_run_id is not None else None,
        }
    )


def _capture_tool_end(
    buffer: _EventBuffer,
    output: str,
    *,
    run_id: Any = None,
    parent_run_id: Any = None,
    name: Optional[str] = None,
    **kwargs: Any,
) -> None:
    buffer.append(
        {
            "hook": "on_tool_end",
            "output_summary": _summarize(output),
            "name": name,
            "run_id": str(run_id) if run_id is not None else None,
            "parent_run_id": str(parent_run_id) if parent_run_id is not None else None,
        }
    )


def _capture_tool_error(
    buffer: _EventBuffer,
    error: BaseException,
    *,
    run_id: Any = None,
    parent_run_id: Any = None,
    **kwargs: Any,
) -> None:
    buffer.append(
        {
            "hook": "on_tool_error",
            "error": error,
            "run_id": str(run_id) if run_id is not None else None,
            "parent_run_id": str(parent_run_id) if parent_run_id is not None else None,
        }
    )


def _capture_llm_start(
    buffer: _EventBuffer,
    serialized: Dict[str, Any],
    prompts: List[str],
    *,
    run_id: Any = None,
    parent_run_id: Any = None,
    invocation_params: Optional[Dict[str, Any]] = None,
    **kwargs: Any,
) -> None:
    buffer.append(
        {
            "hook": "on_llm_start",
            "serialized": serialized or {},
            "name": (serialized or {}).get("name"),
            "model": (invocation_params or {}).get("model"),
            "invocation_params": invocation_params or {},
            "prompts": prompts,
            "run_id": str(run_id) if run_id is not None else None,
            "parent_run_id": str(parent_run_id) if parent_run_id is not None else None,
        }
    )


def _capture_chat_model_start(
    buffer: _EventBuffer,
    serialized: Dict[str, Any],
    messages: List[List[Any]],
    *,
    run_id: Any = None,
    parent_run_id: Any = None,
    invocation_params: Optional[Dict[str, Any]] = None,
    **kwargs: Any,
) -> None:
    buffer.append(
        {
            "hook": "on_chat_model_start",
            "serialized": serialized or {},
            "name": (serialized or {}).get("name"),
            "model": (invocation_params or {}).get("model"),
            "invocation_params": invocation_params or {},
            "messages": messages,
            "run_id": str(run_id) if run_id is not None else None,
            "parent_run_id": str(parent_run_id) if parent_run_id is not None else None,
        }
    )


def _capture_llm_error(
    buffer: _EventBuffer,
    error: BaseException,
    *,
    run_id: Any = None,
    parent_run_id: Any = None,
    **kwargs: Any,
) -> None:
    buffer.append(
        {
            "hook": "on_llm_error",
            "error": error,
            "run_id": str(run_id) if run_id is not None else None,
            "parent_run_id": str(parent_run_id) if parent_run_id is not None else None,
        }
    )


def _capture_agent_action(
    buffer: _EventBuffer,
    action: Any,
    *,
    run_id: Any = None,
    parent_run_id: Any = None,
    **kwargs: Any,
) -> None:
    # action is typically an AgentAction with .tool and .tool_input.
    # Use getattr for defensive shape handling — if the upstream
    # changes the type, we degrade to a generic event with no
    # tool/tool_input populated.
    buffer.append(
        {
            "hook": "on_agent_action",
            "tool": getattr(action, "tool", None),
            "tool_input": getattr(action, "tool_input", None),
            "log": getattr(action, "log", None),
            "run_id": str(run_id) if run_id is not None else None,
            "parent_run_id": str(parent_run_id) if parent_run_id is not None else None,
        }
    )


def _capture_agent_finish(
    buffer: _EventBuffer,
    finish: Any,
    *,
    run_id: Any = None,
    parent_run_id: Any = None,
    **kwargs: Any,
) -> None:
    buffer.append(
        {
            "hook": "on_agent_finish",
            "return_values": getattr(finish, "return_values", None),
            "log": getattr(finish, "log", None),
            "run_id": str(run_id) if run_id is not None else None,
            "parent_run_id": str(parent_run_id) if parent_run_id is not None else None,
        }
    )


def _summarize(value: Any) -> Optional[str]:
    """Render arbitrary callback payload (dict/list/str/etc.)
    as a bounded str for capture. The actual size-bound is applied
    by the translator (120 chars); here we just coerce. Returns
    None for None to keep capture rows compact."""
    if value is None:
        return None
    rendered = str(value)
    return rendered or None


# ─── Undisplaceable attachment ────────────────────────────────────────
#
# The documented way to attach a handler used to be a callbacks LIST:
#
#     graph.compile(callbacks=[handler])
#     graph.invoke(..., config={"callbacks": [handler]})
#
# That list is a value the *caller* supplies, and LangChain treats an
# explicit non-``None`` ``callbacks`` as a REPLACEMENT for whatever was
# inherited — see ``langchain_core.callbacks.manager._configure``, which
# rebuilds the manager from ``inheritable_callbacks`` and never merges
# it with an ambient one. A host that builds its own ``RunnableConfig``
# and passes ``callbacks=[]`` on the tool invocation therefore drops our
# handler on the floor. Nothing raises and nothing warns: the tools run,
# the graph returns, and the execution emits no ``tool_call_observed``
# and no intent provenance — an ungoverned run that looks governed.
# NVIDIA's NeMo Agent Toolkit is a real host that does exactly this: its
# LangChain agent base pins ``self.callbacks = callbacks or []``, builds
# a ``RunnableConfig`` from it, and nothing ever populates that list.
#
# The mechanism that survives is ``register_configure_hook`` — what NeMo
# itself uses for its own handler. It appends to the module-level
# ``langchain_core.tracers.context._configure_hooks`` list, and
# ``_configure`` walks that list AFTER it has built the manager from the
# caller's callbacks, unconditionally, on every path — including the
# tool path (``BaseTool.run`` / ``BaseTool.arun`` →
# ``CallbackManager.configure`` → ``_configure``). A caller-supplied
# list cannot displace it, because the caller never sees it.
#
# Double-invocation is prevented by ``_configure`` itself. We register
# with ``handle_class=WatchlightHandlerBase`` (the marker both handler
# flavours inherit), which makes ``_configure`` skip the hook handler
# whenever the manager ALREADY holds a Watchlight handler:
#
#     elif not any(isinstance(h, handler_class) for h in cm.handlers):
#         cm.add_handler(var_handler, inheritable)
#
# So an explicitly-passed handler wins for that call and the ambient one
# stands down — the same instance passed twice, or a *different*
# Watchlight instance scoped to one sub-graph, each capture exactly
# once. ``env_var=None`` keeps ``_configure``'s construct-one branch
# dead, so langchain_core never instantiates a handler of its own
# accord (it could not: our handlers need an APDP client).
#
# Lifecycle. ``_configure_hooks`` is append-only with no unregister API,
# so hook REGISTRATION is process-wide and permanent. That is made
# harmless by keeping the registration inert: the hook fires only while
# the ContextVar holds a handler, and the ContextVar is set by
# ``RunHandle.callback_handler()`` and reset by the same handle's
# ``complete()`` / ``terminate()`` — i.e. on ``async with`` exit.
# Registration is lazy (nothing at import time, only on first attach)
# and idempotent. Because a ContextVar is task-local, two concurrent
# runs in one process each see their own handler, so a multi-tenant
# host does not leak one tenant's handler into another tenant's run.


class WatchlightHandlerBase:
    """Marker base shared by the sync and async handlers.

    Exists so ``_configure``'s ``isinstance`` de-duplication treats both
    flavours as one family: a sync handler already on the manager
    suppresses an ambient async one and vice versa. Carries no
    behaviour.
    """

    __slots__ = ()


#: Holds the handler the configure hook injects into every callback
#: manager built while it is set. ``None`` = nothing attached.
_ACTIVE_HANDLER: "ContextVar[Optional[WatchlightHandlerBase]]" = ContextVar(
    "watchlight_langgraph_active_callback_handler", default=None
)

_HOOK_REGISTERED = False


def ensure_configure_hook_registered() -> bool:
    """Register the Watchlight configure hook with langchain_core.

    Idempotent and lazy. Returns ``True`` when the hook is registered
    (now or previously), ``False`` when this langchain_core has no
    ``register_configure_hook`` — in which case the caller falls back to
    the displaceable explicit-list attach, and says so loudly.
    """
    global _HOOK_REGISTERED
    if _HOOK_REGISTERED:
        return True
    try:
        from langchain_core.tracers.context import register_configure_hook
    except ImportError:  # pragma: no cover — very old langchain_core
        logger.warning(
            "langchain_core has no tracers.context.register_configure_hook; "
            "the Watchlight callback handler can only be attached through an "
            "explicit callbacks list, which a host that supplies its own "
            "callbacks on the invocation config will silently drop. Upgrade "
            "langchain-core to restore undisplaceable attachment."
        )
        return False
    register_configure_hook(
        _ACTIVE_HANDLER,
        True,  # inheritable — child runs (tool calls under a node) see it
        cast("Any", WatchlightHandlerBase),
    )
    _HOOK_REGISTERED = True
    return True


def set_active_handler(handler: Any) -> Optional[Any]:
    """Attach ``handler`` to the current context.

    Returns the ContextVar token to hand to :func:`reset_active_handler`,
    or ``None`` when the hook could not be registered — the handler is
    then NOT attached and the caller is on the explicit-list path.
    """
    if not ensure_configure_hook_registered():
        return None
    return _ACTIVE_HANDLER.set(handler)


def reset_active_handler(token: Optional[Any]) -> None:
    """Detach whatever :func:`set_active_handler` attached.

    Best-effort: a token can only be reset in the Context that created
    it, so a handler attached on one task and closed on another falls
    back to clearing the var outright.
    """
    if token is None:
        return
    try:
        _ACTIVE_HANDLER.reset(token)
    except (ValueError, RuntimeError):
        try:
            _ACTIVE_HANDLER.set(None)
        except Exception:  # noqa: BLE001 — detach must never break a run
            logger.debug(
                "reset_active_handler: clearing the var failed", exc_info=True
            )


def active_handler() -> Optional[Any]:
    """The handler the configure hook would inject right now, if any."""
    return _ACTIVE_HANDLER.get()


@contextmanager
def attached_handler(handler: Any) -> Iterator[Any]:
    """Scope an attachment to a block.

    ``with attached_handler(handle.callback_handler(attach=False)) as h:``
    for callers who want the undisplaceable attach without tying it to
    the run handle's own lifetime.
    """
    token = set_active_handler(handler)
    try:
        yield handler
    finally:
        reset_active_handler(token)


# ─── Public handlers ──────────────────────────────────────────────────


class WatchlightCallbackHandler(WatchlightHandlerBase, BaseCallbackHandler):
    """Synchronous LangChain callback handler.

    Captures execution events and publishes them via the provided
    APDP client when :meth:`flush` is called.

    Typical wiring via ``RunHandle.callback_handler()``::

        async with await wl.start_run("research-analyst") as handle:
            handler = handle.callback_handler()
            result = graph.invoke({"input": "..."}, config={"callbacks": [handler]})
            # Flush happens automatically on context-manager exit, but
            # the customer can call handler.flush() earlier if needed.

    The handler is **stateful** per-run. Do not share a handler
    across concurrent runs — create a fresh one per execution via
    :meth:`RunHandle.callback_handler`.
    """

    # LangChain treats raise_error=True as "let exceptions
    # propagate." Our handler should never raise; this signals
    # that intent explicitly even though we also catch broadly.
    raise_error: bool = False

    # LangChain's callback machinery may call hooks before init
    # completes in some edge cases; this default makes the
    # condition observable rather than fatal.
    run_inline: bool = True

    def __init__(
        self,
        *,
        apdp_client: Any,
        execution_id: str,
        agent_id: str,
        session_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
        parent_execution_id: Optional[str] = None,
        otlp_exporter: Optional[Any] = None,
        declared_intent_objective: Optional[str] = None,
        run_handle: Optional[Any] = None,
    ):
        super().__init__()
        self._apdp = apdp_client
        self._execution_id = execution_id
        self._agent_id = agent_id
        self._session_id = session_id
        self._tenant_id = tenant_id
        self._parent_execution_id = parent_execution_id
        # Optional `WatchlightOtlpExporter`; when present, flush() also
        # routes the translated events through OTLP for customer-facing
        # observability. APDP emission remains the source of truth for
        # Watchlight lineage; OTLP is opt-in customer observability.
        self._otlp = otlp_exporter
        # Customer-declared intent objective (precedence: highest).
        # If the caller passed ``start_run(intent_objective=…)`` (the
        # synthetic declare_intent path) it lands here and ALWAYS wins
        # over the plugin-derived extraction from
        # ``on_chain_start.inputs``. ``None`` means "no declared
        # intent" and the extraction lane is consulted.
        self._declared_intent_objective = declared_intent_objective
        # Optional reference to the owning :class:`BaseRunHandle`.
        # When supplied, the handler calls ``mark_execution_completed_emitted``
        # / ``mark_execution_failed_emitted`` on the handle BEFORE
        # publishing a translated ``execution_completed`` /
        # ``execution_failed`` event so the SDK's defensive lifecycle
        # emit (from :meth:`BaseRunHandle.complete` /
        # :meth:`BaseRunHandle.terminate`) does NOT double-emit. Set
        # automatically by :meth:`RunHandle.callback_handler`; callers
        # constructing the handler by hand can pass ``run_handle=...``
        # to opt in. ``None`` is supported for backwards compatibility
        # and falls back to defensive SDK emission only.
        self._run_handle = run_handle
        self._buffer = _EventBuffer()

    # ── Hook implementations — all delegate to free functions
    #    so the sync and async handlers share identical capture
    #    logic. Each is wrapped in a broad try/except because
    #    LangChain customer code is the parent of these calls
    #    and an exception escaping here would interrupt the
    #    customer's graph execution. ──────────────────────────────

    def on_chain_start(self, serialized, inputs, **kwargs) -> None:  # noqa: D401, ANN001
        try:
            _capture_chain_start(
                self._buffer,
                serialized,
                inputs,
                declared_intent_objective=self._declared_intent_objective,
                **kwargs,
            )
        except Exception as exc:  # noqa: BLE001
            logger.debug("on_chain_start capture failed: %s", exc)

    def on_chain_end(self, outputs, **kwargs) -> None:  # noqa: ANN001
        try:
            _capture_chain_end(self._buffer, outputs, **kwargs)
        except Exception as exc:  # noqa: BLE001
            logger.debug("on_chain_end capture failed: %s", exc)

    def on_chain_error(self, error, **kwargs) -> None:  # noqa: ANN001
        try:
            _capture_chain_error(self._buffer, error, **kwargs)
        except Exception as exc:  # noqa: BLE001
            logger.debug("on_chain_error capture failed: %s", exc)

    def on_tool_start(self, serialized, input_str, **kwargs) -> None:  # noqa: ANN001
        try:
            _capture_tool_start(self._buffer, serialized, input_str, **kwargs)
        except Exception as exc:  # noqa: BLE001
            logger.debug("on_tool_start capture failed: %s", exc)

    def on_tool_end(self, output, **kwargs) -> None:  # noqa: ANN001
        try:
            _capture_tool_end(self._buffer, output, **kwargs)
        except Exception as exc:  # noqa: BLE001
            logger.debug("on_tool_end capture failed: %s", exc)

    def on_tool_error(self, error, **kwargs) -> None:  # noqa: ANN001
        try:
            _capture_tool_error(self._buffer, error, **kwargs)
        except Exception as exc:  # noqa: BLE001
            logger.debug("on_tool_error capture failed: %s", exc)

    def on_llm_start(self, serialized, prompts, **kwargs) -> None:  # noqa: ANN001
        try:
            _capture_llm_start(self._buffer, serialized, prompts, **kwargs)
        except Exception as exc:  # noqa: BLE001
            logger.debug("on_llm_start capture failed: %s", exc)

    def on_chat_model_start(self, serialized, messages, **kwargs) -> None:  # noqa: ANN001
        try:
            _capture_chat_model_start(self._buffer, serialized, messages, **kwargs)
        except Exception as exc:  # noqa: BLE001
            logger.debug("on_chat_model_start capture failed: %s", exc)

    def on_llm_error(self, error, **kwargs) -> None:  # noqa: ANN001
        try:
            _capture_llm_error(self._buffer, error, **kwargs)
        except Exception as exc:  # noqa: BLE001
            logger.debug("on_llm_error capture failed: %s", exc)

    def on_agent_action(self, action, **kwargs) -> None:  # noqa: ANN001
        try:
            _capture_agent_action(self._buffer, action, **kwargs)
        except Exception as exc:  # noqa: BLE001
            logger.debug("on_agent_action capture failed: %s", exc)

    def on_agent_finish(self, finish, **kwargs) -> None:  # noqa: ANN001
        try:
            _capture_agent_finish(self._buffer, finish, **kwargs)
        except Exception as exc:  # noqa: BLE001
            logger.debug("on_agent_finish capture failed: %s", exc)

    # ── Public consumer API ──────────────────────────────────────

    def buffered_count(self) -> int:
        """Current number of captured events not yet flushed.
        Useful for tests + ad-hoc observability."""
        return len(self._buffer)

    def snapshot(self) -> List[Dict[str, Any]]:
        """Return a copy of the current buffer WITHOUT draining.
        Used by tests to inspect what was captured before flush."""
        # Reach inside _EventBuffer for test introspection. Public
        # callers should use ``flush()`` which returns the translated
        # canonical events, not raw captures.
        return list(self._buffer._events)  # noqa: SLF001

    def _mark_lifecycle_on_handle(
        self, events: List[Dict[str, Any]]
    ) -> None:
        """Scan the translated events and tell the owning
        :class:`BaseRunHandle` which lifecycle event types are about to
        land via this flush so the SDK's defensive lifecycle emit
        suppresses itself.

        Called BEFORE :meth:`apdp.publish_events` so the suppression
        decision is in place by the time the framework's close path
        invokes :meth:`BaseRunHandle.complete` /
        :meth:`BaseRunHandle.terminate` — even if the close runs
        concurrently with this flush.

        No-op when no :attr:`_run_handle` is wired (e.g. callers that
        constructed the handler by hand without this plumbing).
        """
        handle = self._run_handle
        if handle is None:
            return
        for event in events:
            etype = event.get("event_type")
            try:
                if etype == "execution_completed":
                    handle.mark_execution_completed_emitted()
                elif etype == "execution_failed":
                    handle.mark_execution_failed_emitted()
            except Exception:  # noqa: BLE001 — defensive
                logger.debug(
                    "mark_execution_*_emitted raised", exc_info=True
                )

    async def flush(self) -> int:
        """Translate the captured events into canonical
        :class:`ExecutionEvent` dicts and publish them via APDP.

        Returns the count of events emitted (``>= 0``). Zero
        indicates either nothing was captured or the publish
        failed. Best-effort: failures are logged at debug; never
        raises.

        After flush, the internal buffer is empty. The handler
        can continue capturing more events from subsequent runs
        — but customers should create a fresh handler per
        execution via ``RunHandle.callback_handler()``.
        """
        raw = self._buffer.drain()
        if not raw:
            return 0
        events = translate_langgraph_events(
            events=raw,
            execution_id=self._execution_id,
            agent_id=self._agent_id,
            session_id=self._session_id,
            tenant_id=self._tenant_id,
            parent_execution_id=self._parent_execution_id,
        )
        if not events:
            return 0
        # Declare lifecycle emissions on the owning handle BEFORE the
        # network publish so a concurrent close path's defensive SDK
        # emit is suppressed without a race.
        self._mark_lifecycle_on_handle(events)
        # Execution-lineage integrity. Name the owning run, so the backend
        # attaches that run's per-run credential and wl-apdp binds these
        # translated events to the run's session (refusing cross-run /
        # forged events fail-closed). ``None`` when no handle is wired.
        _run = getattr(self._run_handle, "run", None)
        try:
            ok = await self._apdp.publish_events(_run, events)
        except Exception as exc:  # noqa: BLE001 — best-effort lineage
            logger.debug("flush() publish failed: %s", exc)
            return 0
        # Optional OTLP export — runs only if customer wired an exporter.
        # OTLP failure does not affect the APDP outcome we report back.
        if self._otlp is not None:
            try:
                self._otlp.export_events(events)
            except Exception as exc:  # noqa: BLE001
                logger.debug("flush() OTLP export failed: %s", exc)
        return len(events) if ok else 0


class WatchlightAsyncCallbackHandler(WatchlightHandlerBase, AsyncCallbackHandler):
    """Asynchronous LangChain callback handler. Wire-identical to
    :class:`WatchlightCallbackHandler`; pick this one if your
    LangGraph/runnable invocation is async-native (``ainvoke`` /
    ``astream``) and you want true async hook execution.

    The capture logic is identical to the sync handler — both
    classes delegate to the same ``_capture_*`` free functions.
    """

    raise_error: bool = False
    run_inline: bool = True

    def __init__(
        self,
        *,
        apdp_client: Any,
        execution_id: str,
        agent_id: str,
        session_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
        parent_execution_id: Optional[str] = None,
        otlp_exporter: Optional[Any] = None,
        declared_intent_objective: Optional[str] = None,
        run_handle: Optional[Any] = None,
    ):
        super().__init__()
        self._apdp = apdp_client
        self._execution_id = execution_id
        self._agent_id = agent_id
        self._session_id = session_id
        self._tenant_id = tenant_id
        self._parent_execution_id = parent_execution_id
        self._otlp = otlp_exporter
        # Customer-declared intent objective; see sync handler for the
        # precedence chain. Mirrors the sync constructor verbatim.
        self._declared_intent_objective = declared_intent_objective
        # See sync handler docstring for the lifecycle-emit contract
        # this reference enables.
        self._run_handle = run_handle
        self._buffer = _EventBuffer()

    async def on_chain_start(self, serialized, inputs, **kwargs) -> None:  # noqa: ANN001
        try:
            _capture_chain_start(
                self._buffer,
                serialized,
                inputs,
                declared_intent_objective=self._declared_intent_objective,
                **kwargs,
            )
        except Exception as exc:  # noqa: BLE001
            logger.debug("on_chain_start (async) capture failed: %s", exc)

    async def on_chain_end(self, outputs, **kwargs) -> None:  # noqa: ANN001
        try:
            _capture_chain_end(self._buffer, outputs, **kwargs)
        except Exception as exc:  # noqa: BLE001
            logger.debug("on_chain_end (async) capture failed: %s", exc)

    async def on_chain_error(self, error, **kwargs) -> None:  # noqa: ANN001
        try:
            _capture_chain_error(self._buffer, error, **kwargs)
        except Exception as exc:  # noqa: BLE001
            logger.debug("on_chain_error (async) capture failed: %s", exc)

    async def on_tool_start(self, serialized, input_str, **kwargs) -> None:  # noqa: ANN001
        try:
            _capture_tool_start(self._buffer, serialized, input_str, **kwargs)
        except Exception as exc:  # noqa: BLE001
            logger.debug("on_tool_start (async) capture failed: %s", exc)

    async def on_tool_end(self, output, **kwargs) -> None:  # noqa: ANN001
        try:
            _capture_tool_end(self._buffer, output, **kwargs)
        except Exception as exc:  # noqa: BLE001
            logger.debug("on_tool_end (async) capture failed: %s", exc)

    async def on_tool_error(self, error, **kwargs) -> None:  # noqa: ANN001
        try:
            _capture_tool_error(self._buffer, error, **kwargs)
        except Exception as exc:  # noqa: BLE001
            logger.debug("on_tool_error (async) capture failed: %s", exc)

    async def on_llm_start(self, serialized, prompts, **kwargs) -> None:  # noqa: ANN001
        try:
            _capture_llm_start(self._buffer, serialized, prompts, **kwargs)
        except Exception as exc:  # noqa: BLE001
            logger.debug("on_llm_start (async) capture failed: %s", exc)

    async def on_chat_model_start(self, serialized, messages, **kwargs) -> None:  # noqa: ANN001
        try:
            _capture_chat_model_start(self._buffer, serialized, messages, **kwargs)
        except Exception as exc:  # noqa: BLE001
            logger.debug("on_chat_model_start (async) capture failed: %s", exc)

    async def on_llm_error(self, error, **kwargs) -> None:  # noqa: ANN001
        try:
            _capture_llm_error(self._buffer, error, **kwargs)
        except Exception as exc:  # noqa: BLE001
            logger.debug("on_llm_error (async) capture failed: %s", exc)

    async def on_agent_action(self, action, **kwargs) -> None:  # noqa: ANN001
        try:
            _capture_agent_action(self._buffer, action, **kwargs)
        except Exception as exc:  # noqa: BLE001
            logger.debug("on_agent_action (async) capture failed: %s", exc)

    async def on_agent_finish(self, finish, **kwargs) -> None:  # noqa: ANN001
        try:
            _capture_agent_finish(self._buffer, finish, **kwargs)
        except Exception as exc:  # noqa: BLE001
            logger.debug("on_agent_finish (async) capture failed: %s", exc)

    # Reuse the sync handler's consumer-facing API verbatim via
    # explicit copy rather than inheritance — keeps the two
    # handler classes as siblings without async/sync method
    # mixing concerns.

    def buffered_count(self) -> int:
        return len(self._buffer)

    def snapshot(self) -> List[Dict[str, Any]]:
        return list(self._buffer._events)  # noqa: SLF001

    def _mark_lifecycle_on_handle(
        self, events: List[Dict[str, Any]]
    ) -> None:
        """Mirrors the sync handler. See its docstring."""
        handle = self._run_handle
        if handle is None:
            return
        for event in events:
            etype = event.get("event_type")
            try:
                if etype == "execution_completed":
                    handle.mark_execution_completed_emitted()
                elif etype == "execution_failed":
                    handle.mark_execution_failed_emitted()
            except Exception:  # noqa: BLE001 — defensive
                logger.debug(
                    "mark_execution_*_emitted raised", exc_info=True
                )

    async def flush(self) -> int:
        raw = self._buffer.drain()
        if not raw:
            return 0
        events = translate_langgraph_events(
            events=raw,
            execution_id=self._execution_id,
            agent_id=self._agent_id,
            session_id=self._session_id,
            tenant_id=self._tenant_id,
            parent_execution_id=self._parent_execution_id,
        )
        if not events:
            return 0
        # See sync handler for rationale.
        self._mark_lifecycle_on_handle(events)
        # Execution-lineage integrity. Name the owning run, so the backend
        # attaches that run's per-run credential and wl-apdp binds these
        # translated events to the run's session (refusing cross-run /
        # forged events fail-closed). ``None`` when no handle is wired.
        _run = getattr(self._run_handle, "run", None)
        try:
            ok = await self._apdp.publish_events(_run, events)
        except Exception as exc:  # noqa: BLE001 - best-effort lineage
            logger.debug("flush() (async) publish failed: %s", exc)
            return 0
        if self._otlp is not None:
            try:
                self._otlp.export_events(events)
            except Exception as exc:  # noqa: BLE001
                logger.debug("flush() (async) OTLP export failed: %s", exc)
        return len(events) if ok else 0


def fresh_execution_id() -> str:
    """Generate a fresh execution_id matching the
    ``exec_<uuid>`` convention used across all Watchlight
    framework plugins. Exposed so the customer or
    ``RunHandle.callback_handler()`` can mint one without
    having to import ``uuid`` directly."""
    return f"exec_{uuid.uuid4()}"
