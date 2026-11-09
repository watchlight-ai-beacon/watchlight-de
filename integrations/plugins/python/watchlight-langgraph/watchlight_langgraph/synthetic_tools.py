"""Synthetic ``watchlight.declare_intent`` tool injection at
graph-construction time.

The framework-agnostic primitives live in ``watchlight_core``:

- :data:`watchlight_core.WATCHLIGHT_DECLARE_INTENT_TOOL` — the
  contract JSON schema.
- :meth:`watchlight_core.BaseRunHandle.synthetic_tools` — returns
  the synthetic-tool list for the agent's effective enforcement
  mode.
- :func:`watchlight_core.handle_declare_intent_call` — the
  side-effect that stamps :attr:`IntentProvenance.DECLARED` on the
  run handle.
- :func:`watchlight_core.is_declare_intent_tool_name` /
  :func:`watchlight_core.is_declare_intent_tool_call` — predicates
  the plugin uses to short-circuit the tool-call routing.

This module bridges those primitives into the LangGraph world.

# Why this lives in the LangGraph plugin

Each framework binds tools to its model differently. LangGraph uses
LangChain's :class:`langchain_core.tools.StructuredTool` + the
``ChatModel.bind_tools([...])`` contract. Translating
:data:`WATCHLIGHT_DECLARE_INTENT_TOOL` into a ``StructuredTool``
instance whose callable mutates the run-handle is LangGraph-shaped,
not generic, so it lands here.

# Zero-touch customer code

The customer's vanilla code looks like::

    tools = [my_tool_1, my_tool_2]
    model_with_tools = model.bind_tools(tools)

To wire Watchlight governance with synthetic-tool injection, the
customer's code becomes::

    async with await wl.start_run("research-analyst") as handle:
        tools = [my_tool_1, my_tool_2]
        model_with_tools = handle.bind_tools(model, tools)

That's the only delta. The customer never imports the synthetic
tool, never wires the side-effect callable, never thinks about
intent enforcement modes. The plugin handles all of that
internally via :meth:`watchlight_langgraph.RunHandle.bind_tools`
(implemented in ``plugin.py``).

# Authorize-bypass mechanism

A call to ``watchlight.declare_intent`` MUST NOT itself round-trip
to :meth:`authorize_action` — see the rationale in the
:mod:`watchlight_core.declare_intent` module docstring. The
mechanism here is structural: the StructuredTool's ``func`` is a
direct closure over :func:`handle_declare_intent_call` and never
emits an authorize call. The LangGraph plugin's authorize flow is
explicit (the customer's graph calls ``handle.authorize_action``
on the privileged tool nodes); the synthetic tool's node simply
doesn't make that call. So the bypass is the absence of a wire,
not a special-case branch in an authorize middleware.

For belt-and-braces, the plugin also exposes
:func:`should_skip_authorize_for_tool_call` so callers wiring
their own per-tool authorize middleware (e.g., a custom
``on_tool_start`` callback path) can short-circuit on the
synthetic tool's name. The default behaviour does not need it.

# Failure modes

This module is best-effort about input shapes — a malformed
``handle.synthetic_tools(mode)`` payload returns an empty list
rather than raising. The plugin's customer-facing surface
(:meth:`watchlight_langgraph.RunHandle.bind_tools`) tolerates
``None``/missing customer-tools list and returns the model
unchanged when neither customer tools nor synthetic tools apply.
"""

from __future__ import annotations

import contextlib
import threading
import weakref
from typing import Any, Callable, Dict, List, Optional, Tuple

from watchlight_core import (
    DECLARE_INTENT_TOOL_DESCRIPTION,
    DECLARE_INTENT_TOOL_NAME,
    get_logger,
    handle_declare_intent_call,
    is_declare_intent_tool_name,
)

logger = get_logger("watchlight_langgraph.synthetic_tools")

# Imported lazily — ``langchain_core.tools`` is a heavy import and
# this module is imported at plugin-load time, well before any tool
# binding is needed. Lazy import also keeps the watchlight-langgraph
# import graph honest about which surface area actually needs the
# heavier deps.
_STRUCTURED_TOOL_CLS: Optional[type] = None


def _load_structured_tool_cls() -> type:
    """Lazy-import :class:`langchain_core.tools.StructuredTool`.

    Cached at module level after first load. Raises
    :class:`ImportError` if ``langchain_core`` is missing — but the
    plugin's other surfaces (callbacks) already require it, so any
    customer with the plugin installed has it.
    """
    global _STRUCTURED_TOOL_CLS
    if _STRUCTURED_TOOL_CLS is None:
        try:
            from langchain_core.tools import StructuredTool
        except ImportError as exc:  # pragma: no cover — defensive
            raise ImportError(
                "watchlight_langgraph.synthetic_tools requires "
                "langchain_core (transitive via langgraph). Install "
                "via `pip install langchain-core`."
            ) from exc
        _STRUCTURED_TOOL_CLS = StructuredTool
    return _STRUCTURED_TOOL_CLS


def build_synthetic_langchain_tools(
    handle: Any,
    *,
    mode: Optional[str] = None,
) -> List[Any]:
    """Translate the handle's synthetic-tool list into LangChain
    :class:`StructuredTool` instances ready for ``bind_tools``.

    The returned tools' callables are closures over ``handle``: when
    the agent invokes ``watchlight.declare_intent``, the tool's
    ``func`` calls
    :func:`watchlight_core.handle_declare_intent_call(handle, ...)`
    directly. This is the load-bearing authorize-bypass carve-out —
    the tool invocation NEVER round-trips to
    :meth:`authorize_action`. See module docstring.

    Parameters
    ----------
    handle:
        The :class:`BaseRunHandle` (typically
        :class:`watchlight_langgraph.RunHandle`) whose intent state
        should be mutated on tool invocation. MUST be the handle for
        the exact agent / sub-agent the tools will be bound on —
        using a parent handle on a sub-agent's tool list is a
        privilege escalation.
    mode:
        Override the SDK's mode-resolution helper. ``None`` (default)
        falls through to
        :func:`watchlight_core.resolve_intent_enforcement_mode`.

    Returns
    -------
    list of langchain_core.tools.StructuredTool
        The tools to union with the customer's tool list before
        ``bind_tools``. Empty in brownfield (the contract from
        :meth:`BaseRunHandle.synthetic_tools`) — the customer's
        agent never sees the synthetic tool.
    """
    descriptors = handle.synthetic_tools(mode) if handle is not None else []
    if not descriptors:
        return []

    StructuredTool = _load_structured_tool_cls()
    out: List[Any] = []
    for descriptor in descriptors:
        try:
            tool = _structured_tool_from_descriptor(
                descriptor=descriptor,
                handle=handle,
                structured_tool_cls=StructuredTool,
            )
        except Exception as exc:  # noqa: BLE001 — best-effort
            # An exotic descriptor shape (e.g., a future sub-agent
            # scope-attenuation tool that we haven't taught this
            # translator yet) MUST NOT break the customer's run. Log and skip;
            # the customer's tools still bind and the agent continues
            # — the Cedar gate will still fire if intent stays absent.
            logger.warning(
                "synthetic tool descriptor translation failed; skipping: %s",
                exc,
                exc_info=True,
            )
            continue
        out.append(tool)
    return out


def _structured_tool_from_descriptor(
    *,
    descriptor: Dict[str, Any],
    handle: Any,
    structured_tool_cls: type,
) -> Any:
    """Build one :class:`StructuredTool` from a descriptor dict.

    Currently only the canonical ``watchlight.declare_intent`` shape
    is supported. Future synthetic tools (e.g. a scope-attenuation
    surface) would extend the branch dispatch here.
    """
    name = descriptor.get("name")
    if not is_declare_intent_tool_name(name):
        raise ValueError(
            f"unknown synthetic tool descriptor name: {name!r}"
        )

    description = descriptor.get("description") or DECLARE_INTENT_TOOL_DESCRIPTION

    # The StructuredTool's func receives the argument dict that
    # ``args_schema`` materialised from the JSON Schema. We rebuild
    # the dict from the typed kwargs LangChain hands us so the
    # downstream `handle_declare_intent_call` API stays
    # framework-agnostic.
    sync_func = _make_declare_intent_sync_func(handle)
    async_coroutine = _make_declare_intent_async_func(handle)

    tool = _declare_intent_tool_cls(structured_tool_cls).from_function(
        func=sync_func,
        coroutine=async_coroutine,
        name=DECLARE_INTENT_TOOL_NAME,
        description=description,
        # ``infer_schema=True`` reads the function's type hints to
        # build a pydantic ``args_schema``. Our function signature
        # is ``def declare_intent(objective: str, category: str, justification: Optional[str] = None)``
        # (both required; category is one of INTENT_CATEGORIES or
        # ``custom:<name>``) so the schema
        # matches the canonical
        # :data:`WATCHLIGHT_DECLARE_INTENT_TOOL` parameters block.
        infer_schema=True,
    )
    tool._watchlight_handle = handle
    _record_built(tool, sync_func, async_coroutine, handle)
    return tool


_DECLARE_INTENT_TOOL_CLS: Optional[type] = None

#: Every synthetic tool this module built, by ``id``: a weak reference to
#: the tool and the func, coroutine and handle it was built with. Its
#: fields are mutable, so they are checked against this record, never
#: trusted.
_BUILT: Dict[int, Tuple[Any, Any, Any, Any]] = {}
_BUILT_LOCK = threading.Lock()


def _record_built(tool: Any, func: Any, coroutine: Any, handle: Any) -> None:
    key = id(tool)

    def forget(_: Any) -> None:
        with _BUILT_LOCK:
            entry = _BUILT.get(key)
            if entry is not None and entry[0]() is None:
                del _BUILT[key]

    with _BUILT_LOCK:
        _BUILT[key] = (weakref.ref(tool, forget), func, coroutine, handle)


def _built_handle(tool: Any) -> Optional[Any]:
    """The run handle ``tool`` was built for, if ``tool`` is exactly a
    synthetic tool this module built and still has the name, func and
    coroutine it was built with; else ``None``."""
    cls = _DECLARE_INTENT_TOOL_CLS
    if cls is None or type(tool) is not cls:
        return None
    with _BUILT_LOCK:
        entry = _BUILT.get(id(tool))
    if entry is None:
        return None
    ref, func, coroutine, handle = entry
    if (
        ref() is not tool
        or tool.name != DECLARE_INTENT_TOOL_NAME
        or tool.func is not func
        or tool.coroutine is not coroutine
        or getattr(tool, "_watchlight_handle", None) is not handle
    ):
        return None
    return handle


def _declare_intent_tool_cls(structured_tool_cls: type) -> type:
    """The synthetic tool's own class. It never round-trips to
    ``authorize_action`` (the carve-out above), so the ``ToolNode`` tool
    gate recognises it by this class, never by its name, and lets it run
    undecided. Each start grants itself, for the run it was built for
    only: the shared backstop refuses it while another run acts in the
    context or once its run has ended."""
    global _DECLARE_INTENT_TOOL_CLS
    if _DECLARE_INTENT_TOOL_CLS is None:
        from pydantic import PrivateAttr
        from watchlight_core import langchain_tool_backstop as backstop

        class DeclareIntentTool(structured_tool_cls):  # type: ignore[valid-type, misc]
            _watchlight_handle: Any = PrivateAttr(default=None)

            def _self_grant(self, kwargs: Dict[str, Any]) -> Any:
                # Only the exact tool this module built grants itself;
                # anything else (a subclass, a copy, a swapped func) gets
                # no grant and is refused like any other ungranted start.
                handle = _built_handle(self)
                if handle is None:
                    return contextlib.nullcontext()
                return backstop.grant_tool_start(
                    kwargs.get("tool_call_id"), DECLARE_INTENT_TOOL_NAME, handle, body=False
                )

            def run(self, *args: Any, **kwargs: Any) -> Any:
                with self._self_grant(kwargs):
                    return super().run(*args, **kwargs)

            async def arun(self, *args: Any, **kwargs: Any) -> Any:
                with self._self_grant(kwargs):
                    return await super().arun(*args, **kwargs)

        _DECLARE_INTENT_TOOL_CLS = DeclareIntentTool
    return _DECLARE_INTENT_TOOL_CLS


def is_synthetic_tool(tool: Any) -> bool:
    """Is ``tool`` exactly a synthetic tool this module built, unchanged?
    Never decided by its name or class alone."""
    return _built_handle(tool) is not None


def _make_declare_intent_sync_func(handle: Any) -> Callable[..., Dict[str, Any]]:
    """Build the synchronous tool callable.

    Returns a function that LangChain's StructuredTool will invoke
    with the agent's tool arguments. The closure captures ``handle``
    so the mutation lands on the right sub-agent's intent state.
    """

    def declare_intent(objective: str, category: str, justification: Optional[str] = None) -> Dict[str, Any]:
        """Declare your goal for this session.

        ``category`` is one of ``watchlight_core.INTENT_CATEGORIES`` or
        ``custom:<name>``. Stamps the declared objective on the audit log and propagates
        it to authorization decisions so the Cedar intent-declaration
        gate clears.
        """
        return handle_declare_intent_call(
            handle, {"objective": objective, "category": category, "justification": justification}
        )

    return declare_intent


def _make_declare_intent_async_func(handle: Any) -> Callable[..., Any]:
    """Build the async tool callable.

    LangChain's ``StructuredTool.from_function`` accepts both ``func``
    and ``coroutine``; the async variant is used when the model is
    invoked via ``ainvoke``. The mutation itself is synchronous on the
    handle so this is just a thin async wrapper.
    """

    async def declare_intent(objective: str, category: str, justification: Optional[str] = None) -> Dict[str, Any]:
        """Async variant — see sync docstring."""
        return handle_declare_intent_call(
            handle, {"objective": objective, "category": category, "justification": justification}
        )

    return declare_intent


def merge_customer_tools_with_synthetic(
    customer_tools: Optional[List[Any]],
    handle: Any,
    *,
    mode: Optional[str] = None,
) -> List[Any]:
    """Return ``[customer_tools..., synthetic_tools...]``.

    Concatenates the customer's tool list with any synthetic tools
    the handle's mode mandates. ``customer_tools=None`` is treated
    as an empty list (the customer-passes-nothing path is rare but
    happens in greenfield demos that lean on the synthetic tool
    alone). Synthetic tools land AFTER the customer's tools so the
    customer's tool ordering — load-bearing for some prompt
    templates — is preserved.

    The synthetic tools are constructed via
    :func:`build_synthetic_langchain_tools`; see that function's
    docstring for the authorize-bypass carve-out rationale.
    """
    customer = list(customer_tools) if customer_tools else []
    synthetic = build_synthetic_langchain_tools(handle, mode=mode)
    return customer + synthetic


def should_skip_authorize_for_tool_call(tool_name: Optional[str]) -> bool:
    """Return ``True`` iff the named tool call is the synthetic
    ``watchlight.declare_intent`` invocation and MUST bypass the
    :meth:`authorize_action` round-trip.

    Plugins that wire a per-tool authorize middleware (e.g., a
    custom ``on_tool_start`` callback that calls
    ``handle.authorize_action`` before forwarding to the tool's
    handler) MUST consult this predicate to short-circuit. The
    canonical LangGraph plugin's authorize flow is explicit (the
    customer's graph calls ``authorize_action`` on the tool nodes
    they want governed), so the default plugin code path doesn't
    need this — the synthetic tool's node simply doesn't have an
    authorize call wired. But the predicate is exposed for callers
    extending the plugin's middleware.

    The authorize-bypass carve-out is documented in the
    :mod:`watchlight_core.declare_intent` module docstring.
    """
    return is_declare_intent_tool_name(tool_name)


__all__ = [
    "build_synthetic_langchain_tools",
    "merge_customer_tools_with_synthetic",
    "should_skip_authorize_for_tool_call",
]
