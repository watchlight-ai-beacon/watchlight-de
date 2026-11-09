"""The provider-hosted tool gate for Strands model calls.

Every provider-hosted tool a model call enables (a web search, code
execution, a remote MCP server, a passthrough field such as ``extra_body``
or Bedrock's ``additionalModelRequestFields``) is authorized through
``watchlight_core.hosted_tools`` before the model is called. A refusal
raises, so the model is never called.

Where the gate runs
-------------------
``BeforeModelCallEvent`` is too early. After it, Strands runs the model
call through its invoke-model middleware chain (``InvokeModelStage``), and
Strands' own features change the call there: the router model swaps
``ctx.model``, background tasks rewrite ``ctx.tool_specs``. The gate is a
Watchlight wrap handler that is the INNERMOST layer of that chain, so it
reads the final model, tool specs, system prompt and tool choice that the
terminal call sends. ``BeforeModelCallEvent`` re-pins the handler last on
every model call; the handler itself refuses the call when anything is
registered inside it.

The stage is public from Strands 1.62 (``strands.middleware``) and private
before it (``strands._middleware``, 1.55 to 1.61). Re-pinning and the
innermost check read the agent's registry, which is private at every
version (``agent._middleware_registry`` and its handler list). Its shape is
checked on every model call: when the registry, the stage or the handler
list is missing or different, the model call is refused. There is no
fallback to a check in ``BeforeModelCallEvent`` alone.

What the gate reads
-------------------
For a model class Strands ships and this plugin knows (Bedrock, Anthropic,
OpenAI Chat Completions and Responses, Gemini, and their subclasses), the
gate reads the request the model's own formatter builds, called as that
model's ``stream()`` calls it: the provider payload, constructor and
``params`` passthrough included. For any other model class it reads
``model.get_config()``.
"""

from __future__ import annotations

import copy
import inspect
from typing import Any, Callable, Dict, Optional, Tuple

from watchlight_core import GovernanceUnavailable, get_logger

logger = get_logger("watchlight_strands")

#: The handler attribute that marks the Watchlight gate in the registry.
GATE_MARKER = "__watchlight_hosted_tool_gate__"


class MiddlewareDrift(GovernanceUnavailable):
    """Strands' invoke-model middleware does not have the shape this plugin
    governs model calls through; the model call is refused."""


def _stage_modules() -> list[Any]:
    """The Strands modules that may hold ``InvokeModelStage``, in order:
    public from 1.62, private before. Each import names its module
    literally."""
    import importlib

    found: list[Any] = []
    try:
        found.append(importlib.import_module("strands.middleware.stages"))
    except ImportError:
        pass
    try:
        found.append(importlib.import_module("strands._middleware.stages"))
    except ImportError:
        pass
    return found


def invoke_model_stage() -> Any:
    """Strands' ``InvokeModelStage`` token."""
    for module in _stage_modules():
        stage = getattr(module, "InvokeModelStage", None)
        if stage is not None:
            return stage
    raise MiddlewareDrift(
        "Watchlight refused the model call: Strands' invoke-model middleware "
        "is not available in this Strands version"
    )


def _handler_list(agent: Any) -> list:
    """The registry's handler list for ``InvokeModelStage``, checked."""
    registry = getattr(agent, "_middleware_registry", None)
    handlers_by_stage = getattr(registry, "_handlers", None)
    if registry is None or not isinstance(handlers_by_stage, dict) or not callable(
        getattr(registry, "add_middleware", None)
    ):
        raise MiddlewareDrift(
            "Watchlight refused the model call: this agent's middleware registry "
            "does not have the shape Watchlight governs model calls through"
        )
    stage = invoke_model_stage()
    handlers = handlers_by_stage.get(stage)
    if handlers is None:
        return []
    if not isinstance(handlers, list) or not all(
        isinstance(getattr(h, "phase", None), str) and callable(getattr(h, "handler", None))
        for h in handlers
    ):
        raise MiddlewareDrift(
            "Watchlight refused the model call: Strands' invoke-model handlers do "
            "not have the shape Watchlight governs model calls through"
        )
    return handlers


def _is_gate(entry: Any) -> bool:
    return getattr(getattr(entry, "handler", None), GATE_MARKER, False) is True


def pin_innermost(agent: Any, gate: Callable[..., Any]) -> None:
    """Make ``gate`` the innermost ``InvokeModelStage`` handler of
    ``agent``: drop any earlier registration of it and register it again,
    as a wrap handler (wrap runs after input and output handlers, and the
    last registered wrap is the innermost)."""
    handlers = _handler_list(agent)
    handlers[:] = [h for h in handlers if not _is_gate(h)]
    agent._middleware_registry.add_middleware(invoke_model_stage(), gate)
    require_innermost(agent)


def require_innermost(agent: Any) -> None:
    """Raise :class:`MiddlewareDrift` unless the Watchlight gate is the
    last handler the chain runs before the terminal model call."""
    handlers = _handler_list(agent)
    phases = {h.phase for h in handlers}
    if not phases <= {"input", "output", "wrap"}:
        raise MiddlewareDrift(
            "Watchlight refused the model call: Strands' invoke-model middleware "
            "has a phase Watchlight does not know"
        )
    wraps = [h for h in handlers if h.phase == "wrap"]
    if not wraps or not _is_gate(wraps[-1]) or sum(1 for h in handlers if _is_gate(h)) != 1:
        raise MiddlewareDrift(
            "Watchlight refused the model call: a middleware handler is registered "
            "inside the Watchlight gate, so the gate would not see the final request"
        )


# ── the final provider request ──────────────────────────────────────


def _call(fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
    """Call ``fn`` with the keyword arguments its signature accepts (older
    Strands releases take fewer)."""
    params = inspect.signature(fn).parameters
    if not any(p.kind is inspect.Parameter.VAR_KEYWORD for p in params.values()):
        kwargs = {k: v for k, v in kwargs.items() if k in params}
    return fn(*args, **kwargs)


def _split_system_prompt(system_prompt: Any) -> Tuple[Any, Any]:
    from strands.types.content import split_system_prompt

    return split_system_prompt(system_prompt)


def _bedrock(model: Any, ctx: Any, specs: Any) -> Any:
    _, content = _split_system_prompt(ctx.system_prompt)
    return _call(
        model.format_request,
        ctx.messages,
        specs,
        content,
        ctx.tool_choice,
        dynamic_trailing_blocks=getattr(ctx, "dynamic_trailing_blocks", 0),
    )


def _anthropic(model: Any, ctx: Any, specs: Any) -> Any:
    text, content = _split_system_prompt(ctx.system_prompt)
    return _call(
        model.format_request,
        ctx.messages,
        specs,
        text,
        system_prompt_content=content,
        tool_choice=ctx.tool_choice,
        dynamic_trailing_blocks=getattr(ctx, "dynamic_trailing_blocks", 0),
    )


def _openai(model: Any, ctx: Any, specs: Any) -> Any:
    text, _ = _split_system_prompt(ctx.system_prompt)
    return _call(model.format_request, ctx.messages, specs, text, ctx.tool_choice)


def _openai_responses(model: Any, ctx: Any, specs: Any) -> Any:
    text, _ = _split_system_prompt(ctx.system_prompt)
    model_state = copy.deepcopy(getattr(ctx.agent, "_model_state", None))
    return _call(model._format_request, ctx.messages, specs, text, ctx.tool_choice, model_state)


def _gemini(model: Any, ctx: Any, specs: Any) -> Any:
    text, _ = _split_system_prompt(ctx.system_prompt)
    config = model.get_config()
    params = config.get("params") if isinstance(config, dict) else None
    return _call(model._format_request, ctx.messages, specs, text, params, tool_choice=ctx.tool_choice)


#: Model classes Strands ships, by ``module.qualname``: the provider the
#: gate reads the request as, and the request the model's ``stream()``
#: builds. A subclass matches its nearest known base.
_KNOWN_MODELS: Dict[str, Tuple[str, Callable[[Any, Any, Any], Any]]] = {
    "strands.models.bedrock.BedrockModel": ("bedrock", _bedrock),
    "strands.models.anthropic.AnthropicModel": ("anthropic", _anthropic),
    "strands.models.openai.OpenAIModel": ("openai", _openai),
    "strands.models.openai_responses.OpenAIResponsesModel": ("openai", _openai_responses),
    "strands.models.gemini.GeminiModel": ("gemini", _gemini),
}


def final_request(ctx: Any) -> Tuple[Any, Optional[str]]:
    """``(request, provider)`` for the model call ``ctx`` describes: what
    the terminal call sends. Raises when the request cannot be built."""
    model = ctx.model
    # ``stream_messages`` passes no tool specs when the list is empty.
    specs = ctx.tool_specs if ctx.tool_specs else None
    for cls in type(model).__mro__:
        known = _KNOWN_MODELS.get(f"{cls.__module__}.{cls.__qualname__}")
        if known is not None:
            provider, build = known
            return build(model, ctx, specs), provider
    return model.get_config(), None
