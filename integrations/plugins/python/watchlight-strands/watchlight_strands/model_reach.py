"""Every model an agent can call, and the memory writes it makes.

Strands components take a model of their own and call it outside the
agent loop, either directly or through a plain ``Agent`` the plugin is not
on. Examples are the steering LLM handler (``model=``), the HITL risk
classifier (``LLMClassifierConfig(model=...)``), the context manager's
offload summarize strategy (``{"model": ...}``), the agentic ``web_fetch``
tool (``make_web_fetch(model=...)``), the goal loop's judge
(``JudgeConfig(model=...)``), a memory ``ModelExtractor(model=...)``, and
any component that falls back to ``agent.aux_model``. No model hook fires
for those calls, so the hosted tools their models are configured with
would reach the provider with no decision.

At ``BeforeInvocationEvent``, once the run is open, the plugin walks
everything reachable from the agent object (its plugins, hook callbacks,
interventions, conversation and context managers, memory manager, tools
and their closures, middleware) and collects every ``strands`` ``Model``.
Each model's static configuration is read for provider-hosted tools and
authorized on the run through the shared ``watchlight_core.hosted_tools``
gate. Components with a fixed post-run model call are refused, and each
memory store that writes after the run is authorized as a store write.

The walk fails closed: a configuration that cannot be read, an object
graph too large to walk completely (:data:`MAX_NODES`), an agent found
there that the plugin cannot attach to, a container whose contents cannot
be read without running its code, or a registry that is not the shape the
walk reads refuses the invocation.

The walk never runs code of the objects it visits. It reads instance
``__dict__`` and slot values, function closures, defaults and the module
globals a function names. It reads the contents of ``dict``, ``list``,
``tuple``, ``set``, ``frozenset`` and ``deque``, and of subclasses of them,
through the built-in methods of those types, never through a subclass
override, and it dereferences weak references. Any other mapping or
iterable is never iterated: its ``__dict__`` and slots are walked like any
object's. One that has neither (a container implemented in C, such as a
``mappingproxy``) is read through ``gc.get_referents``, the garbage
collector's C traversal, which runs no Python code; one the collector does
not track refuses the invocation.
"""

from __future__ import annotations

import functools
import gc
import inspect
import itertools
import types
import weakref
from collections import abc as cabc
from collections import deque
from typing import Any, Dict, Iterator, List, Mapping, Optional, Set, Tuple

from watchlight_core import GovernanceUnavailable

#: Objects the walk visits at most; more refuses the invocation.
MAX_NODES = 50_000

#: Top-level packages the walk does not descend into: transport clients,
#: SDK internals and runtime machinery, which hold no ``strands`` model a
#: component configured. A ``Model`` instance is still recognized wherever
#: the walk meets one.
_OPAQUE_PACKAGES = frozenset(
    {
        "abc", "aiohttp", "anthropic", "anyio", "asyncio", "boto3", "botocore",
        "concurrent", "contextvars", "google", "grpc", "h11", "h2", "httpcore", "httpx",
        "jsonschema", "litellm", "logging", "mcp", "mistralai", "multiprocessing", "ollama",
        "openai", "opentelemetry", "pydantic", "pydantic_core", "queue", "requests",
        "s3transfer", "socket", "ssl", "threading", "typing", "urllib3", "watchlight_core",
        "watchlight_strands", "writerai",
    }
)

#: Agent attributes that hold conversation data, never a component.
_DATA_ATTRIBUTES = frozenset({"messages", "state"})


class UngovernedModelUse(GovernanceUnavailable):
    """A model the agent can call could not be read or governed; the
    invocation was refused."""


class MemoryWriteRefused(GovernanceUnavailable):
    """A memory store write the agent makes after its run was not allowed;
    the invocation was refused."""


def _strands_types() -> Tuple[Any, Any, Any]:
    from strands.agent import Agent
    from strands.models import Model
    from strands.multiagent.base import MultiAgentBase

    return Model, Agent, MultiAgentBase


def _package(obj: Any) -> str:
    module = getattr(type(obj), "__module__", "") or ""
    return module.split(".", 1)[0]


def _slot_values(obj: Any) -> Iterator[Any]:
    for cls in type(obj).__mro__:
        for name in cls.__dict__.get("__slots__", ()) or ():
            if isinstance(name, str) and name not in ("__dict__", "__weakref__"):
                try:
                    yield object.__getattribute__(obj, name)
                except AttributeError:
                    continue


def _function_refs(func: types.FunctionType) -> Iterator[Any]:
    for cell in func.__closure__ or ():
        try:
            yield cell.cell_contents
        except ValueError:
            continue
    yield from func.__defaults__ or ()
    yield from (func.__kwdefaults__ or {}).values()
    # The module globals the body names (as ``inspect.getclosurevars``).
    names: Set[str] = set()
    codes = [func.__code__]
    while codes:
        code = codes.pop()
        names.update(code.co_names)
        codes.extend(c for c in code.co_consts if isinstance(c, types.CodeType))
    module_globals = func.__globals__
    for name in names:
        if name in module_globals:
            yield module_globals[name]


#: Built-in containers whose contents the walk reads through the type's own
#: built-in methods, so a subclass override never runs.
_DICT_TYPES = (dict,)
_SEQUENCE_TYPES = (list, tuple, set, frozenset, deque)


def _is(obj: Any, kinds: Any) -> bool:
    """``isinstance`` on the real type: never reads ``obj.__class__``,
    which a property can override."""
    return issubclass(type(obj), kinds)


def _builtin_contents(obj: Any) -> Optional[List[Any]]:
    """The contents of a built-in container (or a subclass of one), read
    with the built-in type's methods; ``None`` for anything else."""
    if _is(obj, dict):
        return list(dict.keys(obj)) + list(dict.values(obj))
    for kind in _SEQUENCE_TYPES:
        if _is(obj, kind):
            return list(kind.__iter__(obj))
    return None


def _instance_values(obj: Any, root: Any) -> List[Any]:
    """``obj``'s instance ``__dict__`` and slot values."""
    values: List[Any] = []
    try:
        attrs = object.__getattribute__(obj, "__dict__")
    except AttributeError:
        attrs = None
    if _is(attrs, dict):
        for name, value in list(dict.items(attrs)):
            if obj is root and name in _DATA_ATTRIBUTES:
                continue
            values.append(value)
    values.extend(_slot_values(obj))
    return values


#: ``type``'s own descriptors for a class's namespace and bases.
_TYPE_DICT = type.__dict__["__dict__"].__get__
_TYPE_MRO = type.__dict__["__mro__"].__get__


class _Kinds:
    """Whether a type is a ``strands`` model or agent, and the models or
    agents each class carries as class attributes, cached for one walk."""

    def __init__(self) -> None:
        Model, Agent, MultiAgentBase = _strands_types()
        self._model, self._agents = Model, (Agent, MultiAgentBase)
        self._kinds: Dict[type, int] = {}
        self._held: Dict[type, List[Any]] = {}

    def kind(self, obj: Any) -> int:
        """1 for a model, 2 for an agent or orchestrator, else 0."""
        cls = type(obj)
        kind = self._kinds.get(cls)
        if kind is None:
            kind = 1 if issubclass(cls, self._model) else 2 if issubclass(cls, self._agents) else 0
            self._kinds[cls] = kind
        return kind

    def class_held(self, obj: Any) -> List[Any]:
        """What a component class carries as class attributes that can hold
        a model: models, agents and orchestrators, weak references, and
        built-in containers (walked like any other). Dunder attributes and
        functions are not followed: a module-level model a method uses is
        caught when it is called (see ``model_backstop``). The class and its
        bases are read through ``type``'s own descriptors, so a metaclass
        cannot shadow them."""
        cls = type(obj)
        held = self._held.get(cls)
        if held is None:
            held = []
            for klass in _TYPE_MRO(cls):
                if klass is object:
                    continue
                for name, value in list(_TYPE_DICT(klass).items()):
                    if not _is(name, str) or (name.startswith("__") and name.endswith("__")):
                        continue
                    if self.kind(value) or _is(value, weakref.ref) or _builtin_contents(value) is not None:
                        held.append(value)
            self._held[cls] = held
        return held


def _children(obj: Any, root: Any, kinds: _Kinds) -> List[Any]:
    """The values ``obj`` holds, read without running any of its code.
    Raises :class:`UngovernedModelUse` for a container whose contents only
    its own code can read."""
    contents = _builtin_contents(obj)
    if contents is not None:
        # A subclass may also carry attributes.
        return contents + _instance_values(obj, root)
    if _is(obj, weakref.ref):
        # ``ref``'s own call, never a subclass's ``__call__``; a dead
        # reference gives None.
        referent = weakref.ref.__call__(obj)
        return [] if referent is None else [referent]
    if _is(obj, types.MethodType):
        return [obj.__self__, obj.__func__]
    if _is(obj, types.FunctionType):
        return list(_function_refs(obj))
    if _is(obj, functools.partial):
        return [obj.func, *obj.args, *(obj.keywords or {}).values()]
    values = _instance_values(obj, root)
    if not values and _is(obj, (cabc.Mapping, cabc.Iterable)):
        # A container implemented in C (a mappingproxy, an extension
        # type): its references, through the garbage collector's C
        # traversal, which runs no Python code.
        if gc.is_tracked(obj):
            return [r for r in gc.get_referents(obj) if not _is(r, type)]
        raise UngovernedModelUse(
            f"Watchlight refused the invocation: a {type(obj).__name__} held by the agent's "
            "components keeps its contents where they cannot be checked for a model"
        )
    values.extend(kinds.class_held(obj))
    return values


#: Iterables that provably hold no object: their items are numbers or bytes.
_SCALAR_ITERABLES = (str, bytes, bytearray, memoryview, range, itertools.count)


def _skip(obj: Any) -> bool:
    if obj is None or _is(obj, (int, float, complex, bool, *_SCALAR_ITERABLES)):
        return True
    if _is(obj, (type, types.ModuleType, types.BuiltinFunctionType, types.CodeType)):
        return True
    if _is(obj, (types.CoroutineType, types.GeneratorType, types.AsyncGeneratorType)):
        return True
    return False


def _always_walked(obj: Any) -> bool:
    """Objects walked whatever package their type comes from."""
    return (
        _builtin_contents(obj) is not None
        or _is(obj, (weakref.ref, types.MethodType, types.FunctionType, functools.partial))
    )


#: The agent attribute that holds its tools. An agent reached only through
#: it runs as a tool (or from a tool function), and the tool gate attaches
#: to it strictly before the call.
_TOOL_REGISTRY = "tool_registry"


class Reach:
    """What :func:`reachable` found."""

    def __init__(self) -> None:
        self.models: Dict[int, Any] = {}
        #: Agents and orchestrators a component other than a tool holds. A
        #: component can call one directly, past every gate.
        self.held_agents: Dict[int, Any] = {}
        #: Agents and orchestrators reached only through the tools.
        self.tool_agents: Dict[int, Any] = {}
        self.components: List[Any] = []


def reachable(agent: Any) -> Reach:
    """Every ``strands`` ``Model`` reachable from ``agent``, and every other
    ``Agent`` or orchestrator reachable from it (not descended into; the
    caller attaches each). Components other than the tools are walked
    first, so an agent one of them holds is never classed as a tool's.

    Raises :class:`UngovernedModelUse` when the graph is larger than
    :data:`MAX_NODES` or holds a container that cannot be read."""
    kinds = _Kinds()
    reach = Reach()
    seen: Set[int] = {id(agent)}
    try:
        attrs = object.__getattribute__(agent, "__dict__")
    except AttributeError:
        attrs = None
    if not _is(attrs, dict):
        raise UngovernedModelUse(
            "Watchlight refused the invocation: this agent's components cannot be read"
        )
    tools = dict.get(attrs, _TOOL_REGISTRY)
    visited = 0
    for phase, start in (("held", [c for c in _children(agent, agent, kinds) if c is not tools]), ("tools", [tools])):
        queue: deque = deque(start)
        while queue:
            obj = queue.popleft()
            if _skip(obj) or id(obj) in seen:
                continue
            seen.add(id(obj))
            visited += 1
            if visited > MAX_NODES:
                raise UngovernedModelUse(
                    "Watchlight refused the invocation: the agent's components are too large to "
                    "check every model they can call"
                )
            reach.components.append(obj)
            kind = kinds.kind(obj)
            if kind == 1:
                reach.models[id(obj)] = obj
            elif kind == 2:
                (reach.held_agents if phase == "held" else reach.tool_agents)[id(obj)] = obj
                continue
            if not _always_walked(obj) and _package(obj) in _OPAQUE_PACKAGES:
                continue
            queue.extend(_children(obj, agent, kinds))
    return reach


# ── the static configuration of one model ───────────────────────────

#: Model classes Strands ships, by ``module.qualname``, and the provider the
#: hosted-tool gate reads their configuration as.
_PROVIDERS = {
    "strands.models.bedrock.BedrockModel": "bedrock",
    "strands.models.anthropic.AnthropicModel": "anthropic",
    "strands.models.openai.OpenAIModel": "openai",
    "strands.models.openai_responses.OpenAIResponsesModel": "openai",
    "strands.models.gemini.GeminiModel": "gemini",
}


def _provider(model: Any) -> Optional[str]:
    for cls in type(model).__mro__:
        provider = _PROVIDERS.get(f"{cls.__module__}.{cls.__qualname__}")
        if provider is not None:
            return provider
    return None


def config_requests(model: Any) -> Iterator[Tuple[Any, Optional[str]]]:
    """``(request, provider)`` for each part of ``model``'s configuration
    that is sent with every call and can enable a provider-hosted tool: the
    configuration, its ``params`` passthrough, Bedrock's
    ``additional_request_fields`` and Gemini's ``gemini_tools``. Raises
    :class:`UngovernedModelUse` when it cannot be read."""
    try:
        config = model.get_config()
    except Exception as exc:  # noqa: BLE001 - fail closed
        raise UngovernedModelUse(
            "Watchlight refused the invocation: a model's configuration could not be read"
        ) from exc
    if config is None:
        config = {}
    if not isinstance(config, Mapping):
        raise UngovernedModelUse(
            "Watchlight refused the invocation: a model's configuration is not a mapping"
        )
    provider = _provider(model)
    yield dict(config), provider
    params = config.get("params")
    if params is not None:
        if not isinstance(params, Mapping):
            raise UngovernedModelUse(
                "Watchlight refused the invocation: a model's params are not a mapping"
            )
        yield dict(params), provider
    fields = config.get("additional_request_fields")
    if fields is not None:
        yield {"additionalModelRequestFields": fields}, provider
    gemini_tools = config.get("gemini_tools")
    if gemini_tools is not None:
        yield {"config": {"tools": gemini_tools}}, provider or "gemini"


# ── components that call a model after the run ──────────────────────


def refuse_post_run_model_calls(objects: List[Any]) -> None:
    """Refuse a ``GoalLoop`` with a natural-language goal: its judge calls
    a model in ``AfterInvocationEvent``, after the governed run has closed.
    A ``GoalLoop`` with a validator function runs your own code instead and
    is not refused."""
    try:
        from strands.vended_plugins.goal import GoalLoop
    except ImportError:  # pragma: no cover - every supported release has it
        return
    for obj in objects:
        if _is(obj, GoalLoop):
            validator = getattr(obj, "_validator", inspect.Parameter.empty)
            if validator is None or validator is inspect.Parameter.empty:
                raise UngovernedModelUse(
                    "Watchlight refused the invocation: a GoalLoop with a natural-language goal "
                    "calls its judge model after the governed run has ended. Use a validator "
                    "function instead."
                )


def memory_managers(agent: Any) -> List[Any]:
    """Every ``MemoryManager`` on ``agent``: ``agent.memory_manager`` and any
    registered as a plugin. Raises when the plugins cannot be read."""
    try:
        from strands.memory import MemoryManager
    except ImportError:  # pragma: no cover - every supported release has it
        return []
    found: List[Any] = []
    manager = getattr(agent, "memory_manager", None)
    if isinstance(manager, MemoryManager):
        found.append(manager)
    plugins = getattr(getattr(agent, "_plugin_registry", None), "_plugins", None)
    if not isinstance(plugins, Mapping):
        raise UngovernedModelUse(
            "Watchlight refused the invocation: this agent's plugins cannot be read"
        )
    found.extend(p for p in plugins.values() if isinstance(p, MemoryManager) and p not in found)
    return found


def extraction_stores(manager: Any) -> List[Tuple[str, str]]:
    """``(store name, mode)`` for each store ``manager`` writes to after
    the run: ``"extractor"`` (facts via ``add``) or ``"messages"`` (the raw
    conversation via ``add_messages``). Raises when the shape cannot be
    read."""
    bindings = getattr(manager, "_extraction_stores", None)
    if not isinstance(bindings, list):
        raise UngovernedModelUse(
            "Watchlight refused the invocation: the memory manager's stores cannot be read"
        )
    out: List[Tuple[str, str]] = []
    for binding in bindings:
        store = getattr(binding, "store", None)
        config = getattr(binding, "config", None)
        name = getattr(store, "name", None)
        if not isinstance(name, str) or config is None or not hasattr(config, "extractor"):
            raise UngovernedModelUse(
                "Watchlight refused the invocation: a memory store's extraction cannot be read"
            )
        out.append((name, "extractor" if config.extractor is not None else "messages"))
    return out
