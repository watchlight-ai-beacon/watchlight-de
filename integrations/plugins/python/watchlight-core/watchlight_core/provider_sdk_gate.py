"""Provider-hosted tools, decided on the request each provider SDK sends.

A provider runs a hosted tool (web search, code execution, a remote MCP
server) on its own servers, inside the model call. A framework sees only
part of what its model integration sends: an integration can add fields of
its own (``ChatAnthropic(mcp_servers=...)``), and a plugin can't know every
such field for every integration. So the decision is made where the request
leaves the process: in the provider SDK, on the request body it is about to
send. This module wraps, once and at class level, the method every request
of a supported SDK passes through:

* ``anthropic`` and ``openai``: ``SyncAPIClient.request`` and
  ``AsyncAPIClient.request`` (every resource method: create, stream, parse,
  beta, batches), reading ``options.json_data`` merged with ``extra_body``
  the way the SDK merges it;
* ``google-genai``: ``BaseApiClient.request``, ``async_request``,
  ``request_streamed`` and ``async_request_streamed``, reading the REST
  body;
* the socket APIs whose tools are set over the socket (OpenAI Realtime,
  Google Live), which are refused in a governed context.

Each request is classified by its endpoint (:data:`ENDPOINTS`):

* a model call is **decided**: every provider-hosted tool it enables needs an
  allow (:func:`~watchlight_core.hosted_tools.require_hosted_request_allowed`;
  a synchronous request waits on
  :func:`~watchlight_core.hosted_tools.require_hosted_request_allowed_blocking`).
  An Anthropic message batch is decided request by request, and refused
  whole when one is refused;
* an API whose tools live server-side or arrive outside the send (stored
  agents and assistants, Responses that continue a stored response or
  conversation, file-based batches, realtime sessions) is **refused**;
* an endpoint that sends no tools (files, embeddings, ...) **passes**;
* any other write is refused: an API this module does not know is never
  assumed to be safe.

The governed context is the **run marker**, a context variable a plugin
sets for the life of a run (:func:`attach_run`):

* marker set, run open: decide (or refuse) as above;
* marker set, run ended (a task that outlived its run): refuse every request
  that binds a tool, and every refused API;
* no marker, a governed run live anywhere in the process: the backstop
  refuses every request that binds any tool, and every refused API, with
  :class:`UnmarkedToolBindingRefused` (logged at WARNING with the reason
  ``unmarked_tool_binding``, and counted); it does not end the live run;
* no marker, no governed run live: nothing changes.

The framework layer of each plugin sets the marker and checks its own entry
points; it does not decide hosted tools itself. ``watchlight_core`` imports
none of the SDKs; :func:`install` wraps the ones that are installed.
"""

from __future__ import annotations

import asyncio
import functools
import importlib.util
import inspect
import logging
import re
import threading
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Mapping, Optional, Tuple
from urllib.parse import urlsplit

from .errors import GovernanceUnavailable, WatchlightError
from .hosted_tools import (
    DEFAULT_TIMEOUT_SECONDS,
    HOSTED_TOOL_REFUSED_UNAVAILABLE,
    HostedToolRefused,
    HostedToolTurn,
    _refused,
    _run_ending_errors,
    normalize_hosted_request,
    require_hosted_request_allowed,
    require_hosted_request_allowed_blocking,
)

__all__ = [
    "ENDPOINTS",
    "UNMARKED_TOOL_BINDING",
    "ProviderApiRefused",
    "RunAttachment",
    "UnmarkedToolBindingRefused",
    "attach_run",
    "binds_tools",
    "classify",
    "current_run",
    "detach_run",
    "install",
    "intact",
    "live",
    "unmarked_refusals",
]

logger = logging.getLogger(__name__)

#: The reason logged for a refused request that
#: binds tools outside any run's context while a governed run is live.
UNMARKED_TOOL_BINDING = "unmarked_tool_binding"

#: Set on every wrapper this module installs (see :func:`intact`).
_MARK = "__watchlight_provider_sdk_gate__"

#: How long a request waits for each hosted tool's decision before it is
#: refused. Read at every request.
DECISION_TIMEOUT_SECONDS: float = DEFAULT_TIMEOUT_SECONDS

_lock = threading.Lock()
_live = 0
_refusals = 0
_installed: Dict[str, bool] = {}

#: Request keys that bind tools when present and not empty.
_TOOL_KEYS = (
    "tools",
    "functions",
    "function_call",
    "tool_choice",
    "tool_config",
    "toolConfig",
    "tool_resources",
)


# ─── Errors ─────────────────────────────────────────────────────────


class ProviderApiRefused(WatchlightError):
    """A provider API whose tools live server-side or arrive outside the
    request (or an API this gate does not know) was called in a governed
    context. The request was not sent."""

    def __init__(self, api: str) -> None:
        self.api = api
        super().__init__(
            f"Watchlight refused the provider API '{api}' in a governed run; the request was not sent"
        )


class UnmarkedToolBindingRefused(WatchlightError):
    """A provider request that binds tools, made outside any governed run's
    context while a governed run is live in the process (or from a task that
    outlived its run), was refused before it was sent."""

    def __init__(self) -> None:
        super().__init__(
            "Watchlight refused a model request that binds tools outside the governed "
            "run's context; the request was not sent"
        )


# ─── The run marker ─────────────────────────────────────────────────


@dataclass
class _RunMarker:
    handle: Any
    run_loop: Optional[asyncio.AbstractEventLoop]
    registered_mcp_servers: Optional[Mapping[str, str]]
    closed: bool = False


@dataclass
class RunAttachment:
    """What :func:`attach_run` returns; pass it to :func:`detach_run`."""

    marker: _RunMarker
    token: Any = field(repr=False)
    live: bool = True


_RUN: "ContextVar[Optional[_RunMarker]]" = ContextVar(
    "watchlight_provider_sdk_run", default=None
)


def live() -> bool:
    """Is a governed run live anywhere in this process?"""
    with _lock:
        return _live > 0


def unmarked_refusals() -> int:
    """How many requests the backstop refused in this process."""
    with _lock:
        return _refusals


def current_run() -> Optional[Any]:
    """The run handle of the open run marked in this context, if any."""
    marker = _RUN.get()
    return marker.handle if marker is not None and not marker.closed else None


def attach_run(
    handle: Any,
    *,
    run_loop: Optional[asyncio.AbstractEventLoop] = None,
    registered_mcp_servers: Optional[Mapping[str, str]] = None,
) -> RunAttachment:
    """Mark the current context as running ``handle`` and count the run as
    live. Installs the wraps first, and raises
    :class:`~watchlight_core.errors.GovernanceUnavailable` when one of them
    was replaced. ``run_loop`` is the loop the run was opened on (a
    synchronous request is decided there); ``registered_mcp_servers`` maps a
    remote MCP server URL to the name policy sees."""
    global _live
    install()
    if not intact():
        raise GovernanceUnavailable(
            "a Watchlight provider SDK wrap was replaced; refusing the run"
        )
    if run_loop is None:
        try:
            run_loop = asyncio.get_running_loop()
        except RuntimeError:
            run_loop = None
    marker = _RunMarker(handle, run_loop, registered_mcp_servers)
    with _lock:
        _live += 1
    return RunAttachment(marker, _RUN.set(marker))


def detach_run(attachment: RunAttachment) -> None:
    """End the run marked by :func:`attach_run`. Idempotent. A task that
    still carries the marker is refused any request that binds a tool."""
    global _live
    attachment.marker.closed = True
    if attachment.live:
        attachment.live = False
        with _lock:
            _live = max(0, _live - 1)
    try:
        _RUN.reset(attachment.token)
    except (ValueError, RuntimeError):  # reset from another context: clear this one
        if _RUN.get() is attachment.marker:
            _RUN.set(None)


# ─── Reading a request ──────────────────────────────────────────────


def binds_tools(request: Any, provider: Optional[str] = None) -> bool:
    """Does this request body offer the model any tool, or enable a hosted
    tool at request level? A body that cannot be read counts as binding
    tools."""
    try:
        if not isinstance(request, Mapping):
            return True
        if any(request.get(key) for key in _TOOL_KEYS):
            return True
        return bool(normalize_hosted_request(request, provider))
    except Exception:  # noqa: BLE001 - unreadable: fail closed
        return True


_UNREADABLE = object()

#: The installed SDKs' own "not given" sentinel classes (filled by
#: :func:). A body can hold them until the SDK serializes it, which
#: leaves them out. Matched by class identity, never by name.
_SENTINELS: Tuple[type, ...] = ()


def _is_sentinel(value: Any) -> bool:
    return isinstance(value, _SENTINELS)


def _without_sentinels(value: Any) -> Any:
    """value as the SDK serializes it: sentinel entries left out."""
    if isinstance(value, Mapping):
        return {
            k: _without_sentinels(v) for k, v in value.items() if not _is_sentinel(v)
        }
    if isinstance(value, (list, tuple)):
        return [_without_sentinels(v) for v in value if not _is_sentinel(v)]
    return value


def _stainless_body(options: Any) -> Any:
    """The JSON body a Stainless SDK (anthropic, openai) sends for
    ``options``: ``json_data`` merged with ``extra_json`` (``extra_body``),
    the extra side winning, as the SDK's ``_build_request`` merges them."""
    body = getattr(options, "json_data", None)
    extra = getattr(options, "extra_json", None)
    if body is None and extra is None:
        return {} if getattr(options, "content", None) is None else _UNREADABLE
    if body is None:
        body = {}
    if not isinstance(body, Mapping) or (
        extra is not None and not isinstance(extra, Mapping)
    ):
        return _UNREADABLE
    merged = dict(body)
    for key, value in (extra or {}).items():
        if _is_sentinel(value):
            merged.pop(key, None)
        else:
            merged[key] = value
    return _without_sentinels(merged)


# ─── Endpoints ──────────────────────────────────────────────────────

#: How each write to a provider endpoint is treated in a governed context:
#: ``decide`` (every hosted tool needs an allow), ``decide_each`` (each
#: request of a batch), ``refuse`` (tools server-side or outside the send),
#: ``pass`` (sends no tools). A write that matches nothing is refused.
#: Reads (GET, HEAD) and deletes always pass. Paths are matched without the
#: version prefix and query.
ENDPOINTS: Dict[str, Tuple[Tuple[str, str, str], ...]] = {
    "anthropic": (
        (r"messages", "decide", "Messages"),
        (r"messages/count_tokens", "decide", "Messages count tokens"),
        (r"messages/batches", "decide_each", "Message Batches"),
        (r"messages/batches/[^/]+/cancel", "pass", "cancel a message batch"),
        (r"files", "pass", "Files"),
        (r"skills(/.*)?", "pass", "Skills API (a skill a model call loads is decided per skill)"),
    ),
    "openai": (
        (r"chat/completions", "decide", "Chat Completions"),
        (r"chat/completions/[^/]+", "pass", "update a stored chat completion"),
        (r"responses", "decide", "Responses"),
        (r"responses/input_tokens", "decide", "Responses input tokens"),
        (r"responses/[^/]+/cancel", "pass", "cancel a response"),
        (r"completions", "decide", "Completions (legacy)"),
        (r"embeddings", "pass", "Embeddings"),
        (r"moderations", "pass", "Moderations"),
        (r"audio/(speech|transcriptions|translations)", "pass", "Audio"),
        (r"images/(generations|edits|variations)", "pass", "Images"),
        (r"files(/.*)?", "pass", "Files"),
        (r"uploads(/.*)?", "pass", "Uploads"),
        (r"vector_stores(/.*)?", "pass", "Vector stores"),
        (r"containers(/.*)?", "pass", "Containers"),
        (r"conversations(/.*)?", "pass", "Conversations (items are stored, not run)"),
        (r"batches", "refuse", "Batches (file-based: requests not readable at send)"),
        (r"assistants(/.*)?", "refuse", "Assistants (tools stored server-side)"),
        (
            r"threads(/.*)?",
            "refuse",
            "Assistants threads and runs (tools stored server-side)",
        ),
        (r"realtime(/.*)?", "refuse", "Realtime sessions (tools set over the socket)"),
    ),
    "google": (
        (
            r".*:(generateContent|streamGenerateContent)",
            "decide",
            "Gemini generateContent",
        ),
        (r".*:countTokens", "decide", "Gemini countTokens"),
        (r".*:(embedContent|batchEmbedContents)", "pass", "Gemini embeddings"),
        (
            r"cachedContents(/.*)?",
            "decide",
            "Gemini cached contents (tools stored for later calls)",
        ),
        (
            r".*:batchGenerateContent|batches(/.*)?|batchPredictionJobs(/.*)?",
            "refuse",
            "Gemini batches",
        ),
    ),
}

_COMPILED = {
    sdk: tuple((re.compile(pattern), kind, api) for pattern, kind, api in rows)
    for sdk, rows in ENDPOINTS.items()
}

_PROVIDER = {"anthropic": "anthropic", "openai": "openai", "google": "gemini"}

#: A request path the HTTP client may rewrite before sending: a ``.`` or
#: ``..`` segment, an empty segment, a percent-encoded dot, slash or
#: backslash (either case), or a backslash. The path sent would not be the
#: path classified (``files/../responses`` is sent to ``responses``), so such
#: a path is refused, never normalised.
_UNSAFE_PATH = re.compile(r"(?:^|/)\.{1,2}(?:/|$)|//|./$|%2e|%2f|%5c|\\", re.IGNORECASE)
_UNSAFE_PATH_API = "a request path with dot or empty segments, or encoded separators"


def _path_part(path: str) -> str:
    """The path of a request URL, absolute or relative, without the query or
    fragment."""
    text = str(path)
    if "://" in text:
        text = urlsplit(text).path
    else:
        text = re.split(r"[?#]", text, maxsplit=1)[0]
    return text


def _endpoint_path(sdk: str, path: str) -> str:
    path = str(path).split("?", 1)[0].strip("/")
    if sdk == "anthropic" and path.startswith("v1/"):
        path = path[3:]
    if sdk == "openai" and path.startswith("v1/"):
        path = path[3:]
    if sdk == "google":
        path = re.sub(r"^v\d+[a-z0-9]*/", "", path)
        path = re.sub(r"^projects/[^/]+/locations/[^/]+/", "", path)
    return path


def classify(sdk: str, method: str, path: str, body: Any) -> Tuple[str, str, List[Any]]:
    """``(kind, api, requests)`` for one SDK request: ``kind`` is ``pass``,
    ``decide`` or ``refuse``; ``requests`` are the request bodies to decide
    (one, or one per batch entry). A path the HTTP client may rewrite is
    refused before anything else."""
    if _UNSAFE_PATH.search(_path_part(path)):
        return "refuse", _UNSAFE_PATH_API, []
    if str(method).upper() in ("GET", "HEAD", "DELETE", "OPTIONS"):
        return "pass", "read", []
    endpoint = _endpoint_path(sdk, path)
    for pattern, kind, api in _COMPILED[sdk]:
        if not pattern.fullmatch(endpoint):
            continue
        if kind == "pass":
            return "pass", api, []
        if kind == "refuse":
            return "refuse", api, []
        if body is _UNREADABLE or not isinstance(body, Mapping):
            return "decide", api, [_UNREADABLE]
        if kind == "decide_each":
            entries = body.get("requests")
            if not isinstance(entries, list) or not entries:
                return "decide", api, [_UNREADABLE]
            params = [
                e.get("params") if isinstance(e, Mapping) else _UNREADABLE
                for e in entries
            ]
            return (
                "decide",
                api,
                [p if isinstance(p, Mapping) else _UNREADABLE for p in params],
            )
        if (
            sdk == "openai"
            and endpoint == "responses"
            and (body.get("previous_response_id") or body.get("conversation"))
        ):
            return (
                "refuse",
                "Responses continuing a stored response or conversation",
                [],
            )
        return "decide", api, [body]
    return "refuse", f"{sdk} {endpoint or '/'} (not a known endpoint)", []


def _provider(sdk: str, client: Any) -> Optional[str]:
    if sdk == "openai":
        base = str(getattr(client, "base_url", "") or "")
        if "x.ai" in base:
            return "xai"
    return _PROVIDER[sdk]


# ─── The decision ───────────────────────────────────────────────────


def _report_unmarked_binding() -> None:
    """The refusal of an unmarked tool binding is logged and counted."""
    return None


def _refuse_unmarked() -> None:
    global _refusals
    with _lock:
        _refusals += 1
    logger.warning(
        "[REFUSE-UNGOVERNED] reason=%s: a model request binds tools outside the governed run's "
        "context while a governed run is live; the request was not sent",
        UNMARKED_TOOL_BINDING,
    )
    _report_unmarked_binding()
    raise UnmarkedToolBindingRefused()


def _refuse_api(api: str) -> None:
    logger.warning(
        "[REFUSE-PROVIDER-API] %s is refused in a governed run; the request was not sent",
        api,
    )
    raise ProviderApiRefused(api)


def _count_denied(marker: _RunMarker) -> None:
    plugin = getattr(marker.handle, "_plugin", None)
    if plugin is not None and isinstance(
        getattr(plugin, "last_actions_denied", None), int
    ):
        plugin.last_actions_denied += 1


def _run_ending_only() -> Tuple[type, ...]:
    from .errors import WatchlightContractError

    return tuple(e for e in _run_ending_errors() if e is not WatchlightContractError)


def _precheck(
    sdk: str, method: str, path: str, body: Any, provider: Optional[str]
) -> Optional[Tuple[_RunMarker, List[Any]]]:
    """Refuse what is refused, and return ``(marker, requests)`` when the
    request must be decided; ``None`` lets it through."""
    kind, api, requests = classify(sdk, method, path, body)
    marker = _RUN.get()
    governed = marker is not None or live()
    if kind == "pass" or not governed:
        return None
    if kind == "refuse":
        if marker is not None and not marker.closed:
            _count_denied(marker)
        _refuse_api(api)
    if marker is None or marker.closed:
        if any(r is _UNREADABLE or binds_tools(r, provider) for r in requests):
            _refuse_unmarked()
        return None
    return marker, requests


def _unreadable_refusal(marker: _RunMarker) -> HostedToolRefused:
    _count_denied(marker)
    return _refused(
        (), HOSTED_TOOL_REFUSED_UNAVAILABLE, "the provider request could not be read"
    )


async def _decide(
    marker: _RunMarker, requests: List[Any], provider: Optional[str]
) -> None:
    if _off_run_loop(marker):
        # The run's backend client belongs to the run's loop, and this
        # request runs on another one (a framework that drives its own loop
        # on a worker thread): decide there, with the blocking gate, from a
        # worker thread so neither loop waits on itself.
        await asyncio.to_thread(_decide_blocking, marker, requests, provider)
        return
    for request in requests:
        if request is _UNREADABLE:
            raise _unreadable_refusal(marker)
        turn = HostedToolTurn()
        try:
            await require_hosted_request_allowed(
                marker.handle,
                request,
                turn,
                provider=provider,
                registered_mcp_servers=marker.registered_mcp_servers,
                timeout_seconds=DECISION_TIMEOUT_SECONDS,
            )
        except (HostedToolRefused, *_run_ending_only()):
            _count_denied(marker)
            raise
        except Exception:  # noqa: BLE001 - fail closed: any error refuses the request
            _count_denied(marker)
            raise _refused(
                (),
                HOSTED_TOOL_REFUSED_UNAVAILABLE,
                "the provider request could not be decided",
            ) from None
        finally:
            turn.seal()


def _off_run_loop(marker: _RunMarker) -> bool:
    """Is this async request running on a loop other than its run's?"""
    if marker.run_loop is None:
        return False
    try:
        return asyncio.get_running_loop() is not marker.run_loop
    except RuntimeError:
        return True


def _decide_blocking(
    marker: _RunMarker, requests: List[Any], provider: Optional[str]
) -> None:
    for request in requests:
        if request is _UNREADABLE:
            raise _unreadable_refusal(marker)
        turn = HostedToolTurn()
        try:
            require_hosted_request_allowed_blocking(
                marker.handle,
                request,
                turn,
                run_loop=marker.run_loop,
                provider=provider,
                registered_mcp_servers=marker.registered_mcp_servers,
                timeout_seconds=DECISION_TIMEOUT_SECONDS,
            )
        except BaseException:
            _count_denied(marker)
            raise
        finally:
            turn.seal()


# ─── The wraps ──────────────────────────────────────────────────────


def _stainless_wrap(
    sdk: str, original: Callable[..., Any], is_async: bool
) -> Callable[..., Any]:
    def _read(
        client: Any, args: tuple, kwargs: dict
    ) -> Tuple[str, str, Any, Optional[str]]:
        # request(self, cast_to, options, ...)
        options = args[2] if len(args) > 2 else kwargs.get("options")
        return (
            str(getattr(options, "method", "post")),
            str(getattr(options, "url", "")),
            _stainless_body(options),
            _provider(sdk, client),
        )

    if is_async:

        @functools.wraps(original)
        async def request(*args: Any, **kwargs: Any) -> Any:
            method, path, body, provider = _read(args[0], args, kwargs)
            pending = _precheck(sdk, method, path, body, provider)
            if pending is not None:
                await _decide(pending[0], pending[1], provider)
            return await original(*args, **kwargs)

    else:

        @functools.wraps(original)
        def request(*args: Any, **kwargs: Any) -> Any:
            method, path, body, provider = _read(args[0], args, kwargs)
            pending = _precheck(sdk, method, path, body, provider)
            if pending is not None:
                _decide_blocking(pending[0], pending[1], provider)
            return original(*args, **kwargs)

    setattr(request, _MARK, True)
    return request


def _google_wrap(original: Callable[..., Any]) -> Callable[..., Any]:
    def _read(args: tuple, kwargs: dict) -> Tuple[str, str, Any]:
        names = ("http_method", "path", "request_dict")
        values = list(args[1:4]) + [None] * (3 - len(args[1:4]))
        method, path, body = (kwargs.get(n, v) for n, v in zip(names, values))
        return (
            str(method),
            str(path),
            _without_sentinels(body) if isinstance(body, Mapping) else _UNREADABLE,
        )

    if inspect.isasyncgenfunction(original):

        @functools.wraps(original)
        async def wrapped_agen(*args: Any, **kwargs: Any) -> Any:
            method, path, body = _read(args, kwargs)
            pending = _precheck("google", method, path, body, "gemini")
            if pending is not None:
                await _decide(pending[0], pending[1], "gemini")
            async for item in original(*args, **kwargs):
                yield item

        wrapped: Callable[..., Any] = wrapped_agen
    elif inspect.iscoroutinefunction(original):

        @functools.wraps(original)
        async def wrapped_async(*args: Any, **kwargs: Any) -> Any:
            method, path, body = _read(args, kwargs)
            pending = _precheck("google", method, path, body, "gemini")
            if pending is not None:
                await _decide(pending[0], pending[1], "gemini")
            return await original(*args, **kwargs)

        wrapped = wrapped_async
    else:

        @functools.wraps(original)
        def wrapped_sync(*args: Any, **kwargs: Any) -> Any:
            method, path, body = _read(args, kwargs)
            pending = _precheck("google", method, path, body, "gemini")
            if pending is not None:
                _decide_blocking(pending[0], pending[1], "gemini")
            return original(*args, **kwargs)

        wrapped = wrapped_sync
    setattr(wrapped, _MARK, True)
    return wrapped


def _socket_refusal(api: str, original: Callable[..., Any]) -> Callable[..., Any]:
    """A socket API whose tools are set over the socket: refused in a
    governed context, unchanged otherwise."""

    def check() -> None:
        marker = _RUN.get()
        if marker is not None or live():
            if marker is not None and not marker.closed:
                _count_denied(marker)
            _refuse_api(api)

    if inspect.iscoroutinefunction(original):

        @functools.wraps(original)
        async def wrapped_async(*args: Any, **kwargs: Any) -> Any:
            check()
            return await original(*args, **kwargs)

        wrapped: Callable[..., Any] = wrapped_async
    else:

        @functools.wraps(original)
        def wrapped_sync(*args: Any, **kwargs: Any) -> Any:
            check()
            return original(*args, **kwargs)

        wrapped = wrapped_sync
    setattr(wrapped, _MARK, True)
    return wrapped


def _sdk_modules(sdk: str) -> Tuple[Any, Any]:
    """``(base client module, types module)`` of a Stainless SDK."""
    if sdk == "anthropic":
        import anthropic._base_client as base
        import anthropic._types as types_module
    else:
        import openai._base_client as base  # type: ignore[no-redef]
        import openai._types as types_module  # type: ignore[no-redef]
    return base, types_module


def _openai_realtime_modules() -> List[Any]:
    """The OpenAI Realtime modules this SDK release has (GA and beta)."""
    out = []
    try:
        import openai.resources.realtime.realtime as ga

        out.append(ga)
    except ImportError:
        pass
    try:
        import openai.resources.beta.realtime.realtime as beta

        out.append(beta)
    except ImportError:
        pass
    return out


def _targets(
    sdk: str,
) -> List[Tuple[Any, str, Callable[[Callable[..., Any]], Callable[..., Any]]]]:
    """``(class, attribute, make_wrapper)`` for every method wrapped in an
    installed SDK."""
    if sdk in ("anthropic", "openai"):
        base = _sdk_modules(sdk)[0]
        out: List[
            Tuple[Any, str, Callable[[Callable[..., Any]], Callable[..., Any]]]
        ] = [
            (base.SyncAPIClient, "request", lambda f: _stainless_wrap(sdk, f, False)),
            (base.AsyncAPIClient, "request", lambda f: _stainless_wrap(sdk, f, True)),
        ]
        if sdk == "openai":
            for rt in _openai_realtime_modules():
                out.append(
                    (
                        rt.RealtimeConnectionManager,
                        "__enter__",
                        functools.partial(_socket_refusal, "OpenAI Realtime"),
                    )
                )
                out.append(
                    (
                        rt.AsyncRealtimeConnectionManager,
                        "__aenter__",
                        functools.partial(_socket_refusal, "OpenAI Realtime"),
                    )
                )
        return out
    import google.genai._api_client as api_client
    import google.genai.live as live_module

    names = ("request", "async_request", "request_streamed", "async_request_streamed")
    out = [(api_client.BaseApiClient, name, _google_wrap) for name in names]
    out.append(
        (
            live_module.AsyncLive,
            "connect",
            functools.partial(_socket_refusal, "Gemini Live"),
        )
    )
    return out


_SDKS = {"anthropic": "anthropic", "openai": "openai", "google": "google.genai"}


def _sdk_installed(module: str) -> bool:
    try:
        return importlib.util.find_spec(module) is not None
    except (ImportError, ValueError):
        return False


def install() -> None:
    """Wrap every installed supported SDK once; installing again does
    nothing. An SDK that is not installed is skipped."""
    global _SENTINELS
    with _lock:
        for sdk, module in _SDKS.items():
            if _installed.get(sdk) or not _sdk_installed(module):
                continue
            if sdk in ("anthropic", "openai"):
                types_module = _sdk_modules(sdk)[1]
                _SENTINELS = _SENTINELS + tuple(
                    getattr(types_module, n)
                    for n in ("Omit", "NotGiven")
                    if hasattr(types_module, n)
                )
            for cls, name, make in _targets(sdk):
                current = cls.__dict__.get(name)
                if current is None or getattr(current, _MARK, False):
                    continue
                setattr(cls, name, make(current))
            _installed[sdk] = True


def intact() -> bool:
    """Is every wrap of every installed supported SDK still in place?"""
    for sdk, module in _SDKS.items():
        if not _sdk_installed(module):
            continue
        try:
            targets = _targets(sdk)
        except ImportError:
            return False
        for cls, name, _make in targets:
            if getattr(cls.__dict__.get(name), _MARK, False) is not True:
                return False
    return True
