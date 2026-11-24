"""Tools whose code can build a Strands agent.

An agent that a tool body builds and runs exists only inside the body.
Strands has no public hook through which the plugin could reach it, so the
plugin cannot govern it as a child. Two checks keep it from running:

* the per-call model backstop refuses every model turn of an agent that is
  not governed in the current run (``plugin._check_model_call``), so such an
  agent never takes a turn and never calls a tool;
* before a function tool runs, this module reads the tool's code and
  refuses the call when that code can build an agent or orchestrator. The
  tool body then never runs at all.

The read never runs code. Starting from the tool function, it reads each
code object's names (including nested functions, lambdas and
comprehensions) and resolves them in the function's module globals and
closure cells, and it reads defaults, ``functools.partial`` arguments, and
the methods of classes it finds. It follows functions and classes only from
modules that import Strands (anything else cannot name a Strands class),
and never into Strands itself. The call is refused when the code names:

* ``strands.Agent``, a Swarm, a Graph or any subclass of them;
* a Strands factory that returns one (:data:`_STRANDS_FACTORIES`);
* an attribute of a Strands module that resolves to one of those (for
  example ``strands.Agent(...)`` or ``strands.multiagent.Swarm(...)``).

A read that does not finish within :data:`MAX_NODES` objects refuses too.

Not caught (the model backstop still refuses the agent's turns): an agent
class reached by indirection the code does not name, such as
``importlib.import_module``, ``getattr`` with a computed name,
``sys.modules``, ``eval`` or ``exec``, a class passed in as a tool argument
or through ``invocation_state``, a factory in a module that does not import
Strands itself, or one implemented in C.
"""

from __future__ import annotations

import functools
import sys
import types
from typing import Any, Dict, Iterator, List, Optional, Set

from strands.agent import Agent
from strands.multiagent.base import MultiAgentBase
from strands.types.tools import AgentTool

#: Objects read before the check gives up and refuses.
MAX_NODES = 4096

#: Strands callables that build and return an agent or orchestrator.
_STRANDS_FACTORIES = (
    ("strands.experimental.agent_config", "config_to_agent"),
    ("strands.multiagent.graph", "GraphBuilder"),
)


class _TooLarge(Exception):
    pass


def _is_strands_module_name(name: Any) -> bool:
    return isinstance(name, str) and (name == "strands" or name.startswith("strands."))


def _builds(obj: Any) -> bool:
    """``obj`` is an agent or orchestrator class, or a Strands factory."""
    if isinstance(obj, type):
        try:
            if issubclass(obj, (Agent, MultiAgentBase)):
                return True
        except TypeError:
            return False
    elif not isinstance(obj, types.FunctionType):
        return False
    module = getattr(obj, "__module__", None)
    qualname = getattr(obj, "__qualname__", None)
    return (module, qualname) in _STRANDS_FACTORIES


def _imports_strands(module_name: Any) -> bool:
    """Whether the module named ``module_name`` holds a Strands module or a
    Strands object in its globals (read from its ``__dict__``, never through
    a module ``__getattr__``)."""
    if not isinstance(module_name, str) or _is_strands_module_name(module_name):
        return False
    module = sys.modules.get(module_name)
    namespace = getattr(module, "__dict__", None)
    if not isinstance(namespace, dict):
        return False
    for value in list(namespace.values()):
        if isinstance(value, types.ModuleType):
            if _is_strands_module_name(value.__name__):
                return True
        elif _is_strands_module_name(getattr(value, "__module__", None)):
            return True
    return False


def _code_names(code: types.CodeType) -> Iterator[str]:
    """Every global and attribute name a code object and the code objects
    nested in it (functions, lambdas, comprehensions, classes) use."""
    stack = [code]
    while stack:
        current = stack.pop()
        yield from current.co_names
        stack.extend(c for c in current.co_consts if isinstance(c, types.CodeType))


def _in_strands_modules(roots: List[types.ModuleType], names: Set[str]) -> bool:
    """Whether a name the code uses resolves, through a Strands module it
    refers to, to something that builds an agent."""
    seen: Set[int] = set()
    stack = list(roots)
    while stack:
        module = stack.pop()
        if id(module) in seen:
            continue
        seen.add(id(module))
        namespace = getattr(module, "__dict__", None)
        if not isinstance(namespace, dict):
            continue
        for name in names:
            value = namespace.get(name)
            if value is None:
                continue
            if isinstance(value, types.ModuleType):
                if _is_strands_module_name(value.__name__):
                    stack.append(value)
            elif _builds(value):
                return True
    return False


class _Reader:
    def __init__(self) -> None:
        self.seen: Set[int] = set()
        self.count = 0
        self.walk_module: Dict[str, bool] = {}

    def _follows(self, obj: Any) -> bool:
        module = getattr(obj, "__module__", None)
        if not isinstance(module, str) or _is_strands_module_name(module):
            return False
        if module not in self.walk_module:
            self.walk_module[module] = _imports_strands(module)
        return self.walk_module[module]

    def builds(self, start: Any) -> bool:
        stack = [start]
        while stack:
            obj = stack.pop()
            if id(obj) in self.seen:
                continue
            self.seen.add(id(obj))
            self.count += 1
            if self.count > MAX_NODES:
                raise _TooLarge()
            if _builds(obj):
                return True
            stack.extend(self._children(obj))
        return False

    def _children(self, obj: Any) -> List[Any]:
        if isinstance(obj, functools.partial):
            return [obj.func, *obj.args, *obj.keywords.values()]
        if isinstance(obj, (Agent, MultiAgentBase)):
            # An agent the tool holds is attached as a child by the tool gate.
            return []
        if isinstance(obj, types.MethodType):
            owner = obj.__self__
            if isinstance(owner, (Agent, MultiAgentBase)):
                return []
            return [obj.__func__, owner if isinstance(owner, type) else type(owner)]
        if isinstance(obj, (staticmethod, classmethod)):
            return [obj.__func__]
        if isinstance(obj, property):
            return [f for f in (obj.fget, obj.fset, obj.fdel) if f is not None]
        if isinstance(obj, (list, tuple, set, frozenset)):
            return list(obj)
        if isinstance(obj, dict):
            return list(obj.values())
        if isinstance(obj, types.FunctionType):
            return self._function_children(obj) if self._follows(obj) else []
        if isinstance(obj, type):
            if not self._follows(obj):
                return []
            namespace = type.__dict__["__dict__"].__get__(obj)
            return list(namespace.values()) + list(type.__dict__["__bases__"].__get__(obj))
        if isinstance(obj, (types.ModuleType, types.BuiltinFunctionType, str, bytes, int, float, bool)):
            return []
        func = tool_function(obj)
        if func is not None:
            # Another function tool the code calls.
            return [func]
        # An instance: the methods of its class.
        return [type(obj)]

    def _function_children(self, func: types.FunctionType) -> List[Any]:
        names = set(_code_names(func.__code__))
        globals_ = func.__globals__
        out: List[Any] = []
        strands_modules: List[types.ModuleType] = []
        for name in names:
            if name not in globals_:
                continue
            value = globals_[name]
            if isinstance(value, types.ModuleType):
                if _is_strands_module_name(value.__name__):
                    strands_modules.append(value)
                continue
            out.append(value)
        for cell in func.__closure__ or ():
            try:
                value = cell.cell_contents
            except ValueError:
                continue
            if isinstance(value, types.ModuleType):
                if _is_strands_module_name(value.__name__):
                    strands_modules.append(value)
                continue
            out.append(value)
        if strands_modules and _in_strands_modules(strands_modules, names):
            # A sentinel that _builds() accepts: the agent class itself.
            out.append(Agent)
        out.extend(func.__defaults__ or ())
        out.extend((func.__kwdefaults__ or {}).values())
        return out


def tool_function(tool: Any) -> Optional[Any]:
    """The Python callable behind a function tool (``@tool`` or a
    ``PythonAgentTool``), or ``None`` for other tools."""
    if not isinstance(tool, AgentTool):
        return None
    try:
        namespace = object.__getattribute__(tool, "__dict__")
    except AttributeError:
        return None
    for key in ("__wrapped__", "_tool_func"):
        func = namespace.get(key)
        if callable(func):
            return func
    return None


def can_build_agents(tool: Any) -> bool:
    """Whether the function tool's code can build an agent or orchestrator.
    ``True`` when the read could not finish."""
    func = tool_function(tool)
    if func is None:
        return False
    try:
        return _Reader().builds(func)
    except _TooLarge:
        return True
