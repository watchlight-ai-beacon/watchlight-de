"""LangChain model calls in a governed run, for every plugin built on
langchain_core (LangGraph, Deep Agents).

Provider-hosted tools are decided where the request leaves the process, in
the provider SDK (:mod:`watchlight_core.provider_sdk_gate`), on the body
actually sent. This module is the LangChain side of that:

* :func:`enter_run` marks the run's context for the SDK gate
  (:func:`~watchlight_core.provider_sdk_gate.attach_run`) and records which
  chat model classes the operator allowed beyond the built-in ones;
  :func:`leave_run` ends it.
* Every LangChain chat model call (``invoke``, ``ainvoke``, ``stream``,
  ``astream``, ``batch``, ``abatch``) reports its start through
  ``CallbackManager.on_chat_model_start`` or
  ``AsyncCallbackManager.on_chat_model_start`` before the provider is
  called. Both are wrapped once, at class level. In a governed context the
  wrap reads the chat model from its caller, one of ``BaseChatModel``'s own
  entry points, and refuses the call with :class:`UnknownModelClassRefused`
  unless the model's class is a known one (:data:`KNOWN_MODEL_CLASSES`,
  whose requests go through a provider SDK the gate wraps) or one the
  operator allowed for the run. A start reported from anywhere else is
  treated as an unknown class.

A class is known only as itself: a subclass can send its requests another
way, so it needs the operator's allow-list. An allowed class is plain chat
only: the SDK gate may not see its requests, so a call of it that binds any
tool is refused. Allowing a class is the operator's statement that it has
no hosted capability, including one set on the model itself (such as an
MCP server field). Each allowed class is logged when the run opens.

Governed context, as in the SDK gate:

* the run's own context (the marker, open or ended): an unknown class is
  refused;
* no marker while a governed run is live in the process: an unknown class
  is refused when the call binds tools, with
  :class:`~watchlight_core.provider_sdk_gate.UnmarkedToolBindingRefused`
  (logged and counted; the live run goes on);
* no governed run live: nothing changes.

A chat model that calls its provider without reporting a start (a direct
``_generate`` call, or a client called from a tool) fires no callback: the
SDK gate still sees its request when it goes through a wrapped SDK.

``langchain_core`` is imported only by :func:`install`: ``watchlight_core``
does not depend on it.
"""

from __future__ import annotations

import asyncio
import functools
import logging
import re
import sys
import threading
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Any, FrozenSet, Iterable, Mapping, Optional, Tuple

from . import provider_sdk_gate
from .errors import GovernanceUnavailable, WatchlightError

__all__ = [
    "KNOWN_MODEL_CLASSES",
    "LangChainRun",
    "UnknownModelClassRefused",
    "binds_tools",
    "enter_run",
    "install",
    "intact",
    "leave_run",
    "model_class_names",
]

logger = logging.getLogger(__name__)

#: The chat model classes whose requests go through a provider SDK the
#: gate wraps (``module:QualName``). Matched by the exact class.
KNOWN_MODEL_CLASSES: Tuple[str, ...] = (
    "langchain_anthropic.chat_models:ChatAnthropic",
    "langchain_openai.chat_models.base:ChatOpenAI",
    "langchain_openai.chat_models.azure:AzureChatOpenAI",
    "langchain_xai.chat_models:ChatXAI",
    "langchain_google_genai.chat_models:ChatGoogleGenerativeAI",
)

#: Set on the wrappers this module installs (see :func:`intact`).
_MARK = "__watchlight_langchain_backstop__"

#: ``BaseChatModel`` methods that report a chat model start.
_ENTRY_POINTS = (
    "stream",
    "astream",
    "generate",
    "agenerate",
    "_chat_model_stream_v3",
    "_achat_model_stream_v3",
)

_IDENT = r"[A-Za-z_][A-Za-z0-9_]*"
_CLASS_NAME = re.compile(rf"{_IDENT}(?:\.{_IDENT})*:{_IDENT}(?:\.{_IDENT})*")

#: Invocation-parameter keys that bind tools (a non-empty value).
_TOOL_KEYS = (
    "tools",
    "functions",
    "tool_choice",
    "tool_config",
    "toolConfig",
    "function_call",
)

_lock = threading.Lock()
_installed = False
_entry_codes: FrozenSet[Any] = frozenset()

#: The model classes the operator allowed for the run marked in this
#: context, beyond :data:`KNOWN_MODEL_CLASSES`.
_ALLOWED: "ContextVar[FrozenSet[str]]" = ContextVar(
    "watchlight_langchain_allowed", default=frozenset()
)


class UnknownModelClassRefused(WatchlightError):
    """A chat model call in a governed run used a class that is neither
    known nor allowed by the operator; the model call was not made."""

    def __init__(self, class_name: str, *, binds_tools: bool = False) -> None:
        self.class_name = class_name
        self.binds_tools = binds_tools
        if binds_tools:
            message = (
                f"Watchlight refused a model call with the allowed chat model class '{class_name}' "
                "in a governed run: an allowed class is plain chat only and may not bind tools"
            )
        else:
            message = (
                f"Watchlight refused a model call with the chat model class '{class_name}' in a "
                "governed run; allow it in the plugin's allowed_model_classes if it is plain chat "
                "with no hosted capability"
            )
        super().__init__(message)


def model_class_names(names: Optional[Iterable[str]]) -> FrozenSet[str]:
    """The operator's ``allowed_model_classes`` as ``module:QualName``
    strings. Raises ``ValueError`` for an entry of another form."""
    if isinstance(names, str):
        raise ValueError(
            "allowed_model_classes is a list of 'module:ClassName' strings, not one string"
        )
    out = set()
    for name in names or ():
        if not isinstance(name, str) or not _CLASS_NAME.fullmatch(name):
            raise ValueError(
                f"allowed_model_classes entries are 'module:ClassName', not {name!r}"
            )
        out.add(name)
    return frozenset(out)


def _name_of(cls: type) -> str:
    return f"{cls.__module__}:{cls.__qualname__}"


def _resolves_to(name: str, cls: type) -> bool:
    """Is ``cls`` the class ``name`` names, imported from its module (not a
    class of the same name defined elsewhere)?"""
    module_name, _, qualname = name.partition(":")
    obj: Any = sys.modules.get(module_name)
    for part in qualname.split("."):
        obj = getattr(obj, part, None)
    return obj is cls


def _known(cls: type) -> bool:
    name = _name_of(cls)
    return name in KNOWN_MODEL_CLASSES and _resolves_to(name, cls)


def _allowed(cls: type, allowed: FrozenSet[str]) -> bool:
    name = _name_of(cls)
    return name in allowed and _resolves_to(name, cls)


def binds_tools(params: Any) -> bool:
    """Do these invocation parameters offer the model any tool? Parameters
    that cannot be read count as binding tools."""
    if not isinstance(params, Mapping):
        return True
    try:
        if any(params.get(key) for key in _TOOL_KEYS):
            return True
        extra = params.get("model_kwargs")
        if extra is None:
            return False
        if not isinstance(extra, Mapping):
            return True
        return any(extra.get(key) for key in _TOOL_KEYS)
    except Exception:  # noqa: BLE001 - unreadable: fail closed
        return True


# ─── Runs ────────────────────────────────────────────────────────────


@dataclass
class LangChainRun:
    """What :func:`enter_run` returns; pass it to :func:`leave_run`."""

    sdk: provider_sdk_gate.RunAttachment
    token: Any = field(repr=False)
    open: bool = True


def enter_run(
    handle: Any,
    *,
    run_loop: Optional[asyncio.AbstractEventLoop] = None,
    registered_mcp_servers: Optional[Mapping[str, str]] = None,
    allowed_model_classes: Optional[Iterable[str]] = None,
) -> LangChainRun:
    """Mark the current context as the governed run ``handle`` for the SDK
    gate and for LangChain model calls. Raises
    :class:`~watchlight_core.errors.GovernanceUnavailable` when a wrap was
    replaced, and ``ValueError`` for a malformed allow-list entry."""
    allowed = model_class_names(allowed_model_classes)
    install()
    if not intact():
        raise GovernanceUnavailable(
            "the Watchlight LangChain model-call wrap was replaced; refusing the run"
        )
    for name in sorted(allowed - set(KNOWN_MODEL_CLASSES)):
        logger.warning(
            "[ALLOWED-MODEL-CLASS] %s is allowed by the operator as plain chat with no hosted "
            "capability; a call of it that binds any tool is refused",
            name,
        )
    sdk = provider_sdk_gate.attach_run(
        handle, run_loop=run_loop, registered_mcp_servers=registered_mcp_servers
    )
    return LangChainRun(sdk, _ALLOWED.set(allowed))


def leave_run(run: LangChainRun) -> None:
    """End the run :func:`enter_run` marked. Idempotent."""
    if not run.open:
        return
    run.open = False
    provider_sdk_gate.detach_run(run.sdk)
    try:
        _ALLOWED.reset(run.token)
    except (ValueError, RuntimeError):  # reset from another context
        pass


# ─── The wraps ───────────────────────────────────────────────────────


def _model_class(frame: Any) -> Optional[type]:
    """The chat model class whose start ``frame`` (the caller of
    ``on_chat_model_start``) reports, or ``None`` when the caller is not
    one of ``BaseChatModel``'s entry points."""
    if frame is None or frame.f_code not in _entry_codes:
        return None
    model = frame.f_locals.get("self")
    return type(model) if model is not None else None


def _check(frame: Any, params: Any) -> None:
    marker = provider_sdk_gate._RUN.get()
    if marker is None and not provider_sdk_gate.live():
        return
    cls = _model_class(frame)
    if cls is not None and _known(cls):
        return
    if marker is None:
        if binds_tools(params):
            provider_sdk_gate._refuse_unmarked()
        return
    tools = binds_tools(params)
    if cls is not None and _allowed(cls, _ALLOWED.get()) and not tools:
        return
    name = _name_of(cls) if cls is not None else "<not a chat model entry point>"
    allowed_with_tools = cls is not None and _allowed(cls, _ALLOWED.get())
    if not marker.closed:
        provider_sdk_gate._count_denied(marker)
    logger.warning(
        "[REFUSE-MODEL-CLASS] %s %s",
        name,
        "is allowed as plain chat only and binds tools"
        if allowed_with_tools
        else "is not a known or allowed chat model class",
    )
    raise UnknownModelClassRefused(name, binds_tools=allowed_with_tools)


def _wrap_sync(original: Any) -> Any:
    @functools.wraps(original)
    def on_chat_model_start(
        self: Any, serialized: Any, messages: Any, *args: Any, **kwargs: Any
    ) -> Any:
        _check(sys._getframe(1), kwargs.get("invocation_params"))
        return original(self, serialized, messages, *args, **kwargs)

    setattr(on_chat_model_start, _MARK, True)
    return on_chat_model_start


def _wrap_async(original: Any) -> Any:
    @functools.wraps(original)
    async def on_chat_model_start(
        self: Any, serialized: Any, messages: Any, *args: Any, **kwargs: Any
    ) -> Any:
        _check(sys._getframe(1), kwargs.get("invocation_params"))
        return await original(self, serialized, messages, *args, **kwargs)

    setattr(on_chat_model_start, _MARK, True)
    return on_chat_model_start


def _managers() -> Tuple[Any, Any]:
    from langchain_core.callbacks.manager import AsyncCallbackManager, CallbackManager

    return CallbackManager, AsyncCallbackManager


def install() -> None:
    """Install the SDK gate and both wraps once; installing again does
    nothing."""
    global _installed, _entry_codes
    provider_sdk_gate.install()
    with _lock:
        if _installed:
            return
        from langchain_core.language_models.chat_models import BaseChatModel

        _entry_codes = frozenset(
            BaseChatModel.__dict__[name].__code__
            for name in _ENTRY_POINTS
            if name in BaseChatModel.__dict__
        )
        sync_manager, async_manager = _managers()
        sync_manager.on_chat_model_start = _wrap_sync(
            sync_manager.__dict__["on_chat_model_start"]
        )  # type: ignore[method-assign]
        async_manager.on_chat_model_start = _wrap_async(
            async_manager.__dict__["on_chat_model_start"]
        )  # type: ignore[method-assign]
        _installed = True


def intact() -> bool:
    """Are both wraps, and every SDK gate wrap, still in place?"""
    try:
        managers = _managers()
    except ImportError:
        return False
    return provider_sdk_gate.intact() and all(
        getattr(m.__dict__.get("on_chat_model_start"), _MARK, False) is True
        for m in managers
    )
