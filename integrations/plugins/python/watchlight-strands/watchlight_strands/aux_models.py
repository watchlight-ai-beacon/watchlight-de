"""Model calls Strands makes outside the agent loop.

Strands calls a model in three places that fire no ``BeforeModelCallEvent``
and run no invoke-model middleware, so no per-call gate sees them:

1. ``Agent.structured_output`` / ``structured_output_async`` (deprecated)
   call ``agent.model.structured_output`` directly.
2. ``SummarizingConversationManager`` without a ``summarization_agent``
   calls ``agent.aux_model.stream()`` directly (``agent.model`` before
   Strands 1.62). With a ``summarization_agent``, that agent runs the
   summary.
3. Memory extraction (a ``MemoryManager`` store with an extractor) calls
   ``stream_messages`` on ``agent.aux_model`` (``agent.model`` before 1.62)
   or the extractor's own model, in a background task that runs after the
   invocation, so after its governed run has closed.

How the plugin governs them, at ``BeforeInvocationEvent``:

* path 1 is refused: the invocation raises before any model call;
* every provider-hosted tool the static configuration of ``agent.model``
  and ``agent.aux_model`` enables (Bedrock ``additional_request_fields``,
  the ``params`` passthrough of OpenAI, Anthropic, Gemini and the other
  providers, Gemini ``gemini_tools``) is authorized on the run before the
  invocation starts, through the shared ``watchlight_core.hosted_tools``
  gate. A refusal ends the invocation before any model call. This covers
  the summary call of path 2, which runs inside the run with that model;
* a ``summarization_agent`` is attached as a governed child (refused when
  it cannot be);
* path 3 is refused whenever a store extracts with a model-calling
  extractor: the call runs after the run has closed and no hook reaches
  it. Store-side extraction (no extractor, raw messages to
  ``add_messages``) makes no model call here and is not refused.

Nothing here falls back to allowing: a configuration the plugin cannot read
refuses the invocation.
"""

from __future__ import annotations

import inspect
from typing import Any, Iterator, List, Mapping, Optional, Tuple

from watchlight_core import GovernanceUnavailable

#: Frame names of the deprecated structured-output entry points.
_STRUCTURED_OUTPUT_FRAMES = frozenset({"structured_output", "structured_output_async"})

#: Model classes Strands ships, by ``module.qualname``, and the provider the
#: hosted-tool gate reads their configuration as. A subclass matches its
#: nearest known base; any other class is read with no provider hint.
_PROVIDERS = {
    "strands.models.bedrock.BedrockModel": "bedrock",
    "strands.models.anthropic.AnthropicModel": "anthropic",
    "strands.models.openai.OpenAIModel": "openai",
    "strands.models.openai_responses.OpenAIResponsesModel": "openai",
    "strands.models.gemini.GeminiModel": "gemini",
}


class UngovernedModelCall(GovernanceUnavailable):
    """A model call the plugin cannot put a governance decision in front
    of; the invocation was refused before any model call."""


def calling_deprecated_structured_output(agent: Any) -> bool:
    """True when this ``BeforeInvocationEvent`` comes from the deprecated
    ``Agent.structured_output`` / ``structured_output_async`` of ``agent``.

    Strands awaits hook callbacks directly, so the entry point's frame is on
    the callback's frame chain."""
    frame = inspect.currentframe()
    try:
        while frame is not None:
            if frame.f_code.co_name in _STRUCTURED_OUTPUT_FRAMES and frame.f_locals.get("self") is agent:
                return True
            frame = frame.f_back
        return False
    finally:
        del frame


def refuse_deprecated_structured_output(agent: Any) -> None:
    if calling_deprecated_structured_output(agent):
        raise UngovernedModelCall(
            "Watchlight refused Agent.structured_output: it calls the model outside the "
            "governed model path. Pass structured_output_model= to the agent invocation instead."
        )


# ── memory extraction ───────────────────────────────────────────────


def _memory_managers(agent: Any) -> List[Any]:
    """Every Strands ``MemoryManager`` on ``agent``: ``agent.memory_manager``
    and any registered as a plugin. Raises when the plugin registry cannot
    be read."""
    try:
        from strands.memory import MemoryManager
    except ImportError:  # pragma: no cover - every supported release has it
        return []
    found: List[Any] = []
    manager = getattr(agent, "memory_manager", None)
    if manager is not None:
        found.append(manager)
    registry = getattr(agent, "_plugin_registry", None)
    plugins = getattr(registry, "_plugins", None)
    if not isinstance(plugins, Mapping):
        raise UngovernedModelCall(
            "Watchlight refused the invocation: this agent's plugins cannot be read, so a "
            "memory extraction model call could not be ruled out"
        )
    found.extend(p for p in plugins.values() if isinstance(p, MemoryManager))
    return found


def _extracts_with_a_model(manager: Any) -> bool:
    """True when ``manager`` has a store that extracts through an extractor
    (a model call in a background task). Unreadable shapes count as True."""
    bindings = getattr(manager, "_extraction_stores", None)
    if not isinstance(bindings, list):
        return True
    for binding in bindings:
        config = getattr(binding, "config", None)
        if config is None or not hasattr(config, "extractor"):
            return True
        if config.extractor is not None:
            return True
    return False


def refuse_memory_extraction(agent: Any) -> None:
    for manager in _memory_managers(agent):
        if _extracts_with_a_model(manager):
            raise UngovernedModelCall(
                "Watchlight refused the invocation: memory extraction with an extractor calls a "
                "model in the background after the governed run has ended, where no decision can "
                "be made. Use store-side extraction (no extractor) or turn extraction off."
            )


# ── static model configuration ──────────────────────────────────────


def _provider(model: Any) -> Optional[str]:
    for cls in type(model).__mro__:
        provider = _PROVIDERS.get(f"{cls.__module__}.{cls.__qualname__}")
        if provider is not None:
            return provider
    return None


def static_hosted_requests(model: Any) -> Iterator[Tuple[Any, Optional[str]]]:
    """``(request, provider)`` for every part of ``model``'s configuration
    that is sent with each of its calls and can enable a provider-hosted
    tool: the configuration itself, its ``params`` passthrough (merged into
    the request body by every Strands provider that has one), Bedrock's
    ``additional_request_fields`` (sent as ``additionalModelRequestFields``)
    and Gemini's ``gemini_tools`` (sent in ``config.tools``).

    Raises :class:`UngovernedModelCall` when the configuration cannot be
    read."""
    try:
        config = model.get_config()
    except Exception as exc:  # noqa: BLE001 - fail closed
        raise UngovernedModelCall(
            "Watchlight refused the invocation: the model configuration could not be read"
        ) from exc
    if config is None:
        config = {}
    if not isinstance(config, Mapping):
        raise UngovernedModelCall(
            "Watchlight refused the invocation: the model configuration is not a mapping"
        )
    provider = _provider(model)
    yield dict(config), provider
    params = config.get("params")
    if params is not None:
        if not isinstance(params, Mapping):
            raise UngovernedModelCall(
                "Watchlight refused the invocation: the model's params are not a mapping"
            )
        yield dict(params), provider
    fields = config.get("additional_request_fields")
    if fields is not None:
        yield {"additionalModelRequestFields": fields}, provider
    gemini_tools = config.get("gemini_tools")
    if gemini_tools is not None:
        yield {"config": {"tools": gemini_tools}}, provider or "gemini"


def models_to_gate(agent: Any) -> List[Any]:
    """``agent.model`` and, where Strands has one (1.62 and later),
    ``agent.aux_model`` when it is a different model."""
    models = [agent.model]
    if isinstance(getattr(type(agent), "aux_model", None), property):
        aux = agent.aux_model
        if aux is not None and aux is not agent.model:
            models.append(aux)
    return models


def summarization_agent(agent: Any) -> Any:
    """The ``summarization_agent`` of the agent's conversation manager, or
    ``None``."""
    manager = getattr(agent, "conversation_manager", None)
    return getattr(manager, "summarization_agent", None)
