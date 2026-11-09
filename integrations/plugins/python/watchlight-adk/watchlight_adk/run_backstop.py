"""No ADK agent runs outside Watchlight while a governed run is live.

A tool body can run an agent the plugin was never given: it can build a
``Runner`` with no plugins, or run an agent it holds under a copy of the
run's invocation context with the plugins stripped. ADK has no global plugin
registry, so the plugin's callbacks never see that agent. The code read in
``nested_runs`` refuses the tools it can see doing this; this module is the
runtime backstop for what the read cannot see.

Every agent start, model call and tool start in ADK passes through the
invocation's ``PluginManager`` (``run_before_agent_callback``,
``run_before_model_callback``, ``run_before_tool_callback``), and every run
through ``run_before_run_callback``. These are wrapped once, at class level,
when the plugin is installed. While a governed run is live anywhere in the
process, a plugin manager that holds no Watchlight plugin is refused:

* a run ends before it starts (ADK's early exit);
* an agent is skipped before its first model turn;
* a model turn that binds tools gets a refusal instead of a model call (a
  turn with no tools, such as a summary, is allowed);
* a tool call gets a refusal instead of running.

``Runner.run_async`` is wrapped as well: a governed runner's run counts as
live from its first step until it ends (``Runner.run`` and ``run_debug`` go
through it). A runner with no Watchlight plugin started while a run is live
is refused at its ``run_before_run_callback``, before any agent starts, so
the governed run that started it carries on.

Where ADK ignores a run-level refusal (google-adk 2.5.0, an ``LlmAgent``
root run through ``run_async``), ``run_before_agent_callback`` refuses the
agent instead, before its first model turn. The plugin does the same for
its own root: a root agent outside a step of a governed runner's
``run_async`` (:func:`in_governed_run`) is refused at
``before_agent_callback``. That check is per run, not process-wide, so
another governed run being live does not let an unwrapped run through.

"Live" is process-wide, not per task or thread, so a raw thread or a fresh
``contextvars.Context`` is covered. The cost is that an unrelated ungoverned
agent in the same process is refused while a governed run is live: run such
agents in a separate process. With no governed run live, nothing changes.

At each run start the plugin checks that these wraps are still installed
and refuses the run if one was replaced (:func:`intact`). Removing them
deliberately is turning governance off and is out of scope.
"""

from __future__ import annotations

import contextvars
import functools
import logging
import threading
import weakref
from typing import Any, AsyncGenerator, Callable

from google.adk import Runner
from google.adk.models.llm_response import LlmResponse
from google.adk.plugins.plugin_manager import PluginManager
from google.genai import types

logger = logging.getLogger(__name__)

REFUSAL = (
    "Refused by Watchlight: an agent ran outside Watchlight governance while a "
    "governed run was live. Give its Runner the Watchlight plugin, or use an AgentTool."
)

#: Set on the wrappers this module installs (see :func:`intact`).
_MARK = "__watchlight_adk_backstop__"

# Reentrant: the garbage collector can run a registry entry's weakref
# callback (``_forget``) on a thread that already holds this lock.
_lock = threading.RLock()
_live = 0
#: The Watchlight plugins that were actually constructed, by identity
#: (``id`` → weak reference, matched with ``is``, never ``==``). A plugin
#: manager is governed only when it holds one of them: a class attribute,
#: a look-alike object or one that compares equal is not enough.
_governing: "dict[int, weakref.ref[Any]]" = {}


def _forget(key: int) -> Callable[[Any], None]:
    def drop(ref: Any) -> None:
        with _lock:
            if _governing.get(key) is ref:
                del _governing[key]

    return drop


def register(plugin: Any) -> None:
    """Record a fully constructed Watchlight plugin (its ``__init__``
    calls this last)."""
    key = id(plugin)
    with _lock:
        _governing[key] = weakref.ref(plugin, _forget(key))
_installed = False

#: Set while a governed runner's ``run_async`` is making a step, in the
#: context that step runs in (and so in every task it creates). Unlike
#: ``live()``, it says that THIS run started through the wrapped
#: ``Runner.run_async``, not that some governed run somewhere is live.
_governed_run: "contextvars.ContextVar[bool]" = contextvars.ContextVar(
    "watchlight_adk_governed_run", default=False
)


def live() -> bool:
    """Is a governed run live anywhere in this process?"""
    with _lock:
        return _live > 0


def in_governed_run() -> bool:
    """Is the code calling this running inside a step of a governed
    runner's ``Runner.run_async``?"""
    return _governed_run.get()


def _enter() -> None:
    global _live
    with _lock:
        _live += 1


def _leave() -> None:
    global _live
    with _lock:
        _live = max(0, _live - 1)


def governs(plugin_manager: Any) -> bool:
    """Does this plugin manager hold a constructed Watchlight plugin
    (:func:`register`)? Anything that is not a readable ``PluginManager``
    does not."""
    try:
        plugins = object.__getattribute__(plugin_manager, "plugins")
    except AttributeError:
        return False
    try:
        held = list(plugins)
        with _lock:
            return any(_is_governing(p) for p in held)
    except TypeError:
        return False


def _is_governing(plugin: Any) -> bool:
    ref = _governing.get(id(plugin))
    return ref is not None and ref() is plugin


def binds_tools(llm_request: Any) -> bool:
    """Does this model request offer the model any tool? A request that
    cannot be read counts as binding tools."""
    try:
        if llm_request.tools_dict:
            return True
        config = llm_request.config
        if config is None:
            return False
        return bool(config.tools) or config.tool_config is not None
    except Exception:  # noqa: BLE001 — unreadable: fail closed
        return True


def _refused(plugin_manager: Any) -> bool:
    return live() and not governs(plugin_manager)


def _content() -> types.Content:
    return types.Content(role="model", parts=[types.Part.from_text(text=REFUSAL)])


def _wrap(name: str, decide: Callable[..., Any]) -> None:
    original = getattr(PluginManager, name)

    @functools.wraps(original)
    async def wrapper(self: Any, **kwargs: Any) -> Any:
        refusal = decide(self, kwargs)
        if refusal is not None:
            logger.warning("[REFUSE-UNGOVERNED] %s: no Watchlight plugin while a governed run is live", name)
            return refusal
        return await original(self, **kwargs)

    setattr(wrapper, _MARK, True)
    setattr(PluginManager, name, wrapper)


def _on_run(pm: Any, _kw: dict) -> Any:
    return _content() if _refused(pm) else None


def _on_agent(pm: Any, _kw: dict) -> Any:
    return _content() if _refused(pm) else None


def _on_model(pm: Any, kw: dict) -> Any:
    # A turn that offers the model no tool can only return text: it cannot
    # call a tool or start an agent, and each of those is refused at its own
    # callback here. Refusing it would break ADK's own tool-less turns (a
    # summary) without stopping any action. Its network egress is governed
    # only through wl-proxy, like any model call.
    if _refused(pm) and binds_tools(kw.get("llm_request")):
        return LlmResponse(content=_content(), turn_complete=True)
    return None


def _on_tool(pm: Any, _kw: dict) -> Any:
    return {"result": REFUSAL} if _refused(pm) else None


def _wrap_runner() -> None:
    run_async = Runner.run_async

    @functools.wraps(run_async)
    async def wrapped_run_async(self: Any, *args: Any, **kwargs: Any) -> AsyncGenerator[Any, None]:
        if not governs(getattr(self, "plugin_manager", None)):
            async for event in run_async(self, *args, **kwargs):
                yield event
            return
        _enter()
        steps = run_async(self, *args, **kwargs)
        try:
            while True:
                # The marker is set for each step only, so it never leaks
                # into the caller's context between events, and each reset
                # runs in the context its set ran in.
                token = _governed_run.set(True)
                try:
                    event = await steps.__anext__()
                except StopAsyncIteration:
                    break
                finally:
                    _governed_run.reset(token)
                yield event
        finally:
            try:
                await steps.aclose()
            finally:
                _leave()

    setattr(wrapped_run_async, _MARK, True)
    Runner.run_async = wrapped_run_async  # type: ignore[method-assign]


_WRAPPED = (
    (PluginManager, "run_before_run_callback"),
    (PluginManager, "run_before_agent_callback"),
    (PluginManager, "run_before_model_callback"),
    (PluginManager, "run_before_tool_callback"),
    (Runner, "run_async"),
)


def install() -> None:
    """Install the wraps once; installing again does nothing."""
    global _installed
    with _lock:
        if _installed:
            return
        _wrap("run_before_run_callback", _on_run)
        _wrap("run_before_agent_callback", _on_agent)
        _wrap("run_before_model_callback", _on_model)
        _wrap("run_before_tool_callback", _on_tool)
        _wrap_runner()
        _installed = True


def intact() -> bool:
    """Are all the wraps still in place?"""
    return all(getattr(getattr(cls, name, None), _MARK, False) is True for cls, name in _WRAPPED)
