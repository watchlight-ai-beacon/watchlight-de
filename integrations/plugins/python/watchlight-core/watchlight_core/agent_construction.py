"""Whether a tool function's code can build an agent.

An agent, runner or orchestrator that a tool body builds and runs exists
only inside the body. No framework offers a public hook through which a
governance plugin could reach it to govern it as a child, so a plugin
refuses the tool call before the body runs when the tool's code can build
one. Each framework plugin supplies what "building an agent" means for its
framework (:class:`Builders`); this module reads the code.

The read never runs code. Starting from the tool function, it reads each
code object's names (including nested functions, lambdas and
comprehensions) and resolves them in the function's module globals and
closure cells, through module attributes (``helpers.run_sub()``), and it
reads defaults, ``functools.partial`` arguments, and the methods of classes
it finds. The tool function itself is always read. Beyond it, the read
follows functions and classes from the application's own code: any module
outside the standard library and installed packages, any module in the tool
function's own top-level package, and any module that imports the
framework. It never reads the standard library, other installed packages,
or the framework itself. The code can build an agent when it names:

* a class or factory the framework's ``builds`` predicate accepts;
* an attribute of a framework module, or of a package above it, that
  resolves to one (for example ``strands.Agent(...)`` or
  ``google.adk.Runner(...)``);
* a name in :data:`INDIRECTION_NAMES` (``__import__``, ``import_module``,
  ``exec``, ``eval``), through which code can reach any class by a computed
  name, or a name in the framework's own ``refused_names``.

A read that does not finish within :data:`MAX_NODES` objects counts as able
to build one, so the caller refuses.

Not seen: a class reached by other indirection, such as ``getattr`` with a
computed name or ``sys.modules``, a class held in an instance attribute,
passed in as a tool argument or read from runtime state, a factory in an
installed package that does not import the framework, or one implemented
in C.
"""

from __future__ import annotations

import functools
import os
import sys
import sysconfig
import types
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterator, List, Optional, Set, Tuple

#: Objects read before the check gives up and counts the code as able to
#: build an agent.
MAX_NODES = 4096

#: Names through which code can reach any class by a computed name. Code the
#: read follows that uses one counts as able to build an agent.
INDIRECTION_NAMES = frozenset({"__import__", "import_module", "exec", "eval"})


def _library_roots(keys: Tuple[str, ...]) -> Tuple[str, ...]:
    """Directories of the standard library and installed packages."""
    roots: Set[str] = set()
    for key in keys:
        path = sysconfig.get_paths().get(key)
        if path:
            roots.add(os.path.realpath(path))
    if "purelib" in keys:
        for path in sys.path:
            if path and os.path.basename(path) in ("site-packages", "dist-packages"):
                roots.add(os.path.realpath(path))
    return tuple(sorted(roots))


def _under(path: Optional[str], roots: Tuple[str, ...]) -> bool:
    if not isinstance(path, str):
        return True  # built in or frozen: the standard library
    path = os.path.realpath(path)
    return any(path == root or path.startswith(root + os.sep) for root in roots)


_STDLIB_ROOTS = _library_roots(("stdlib", "platstdlib"))
_LIBRARY_ROOTS = _library_roots(("stdlib", "platstdlib", "purelib", "platlib"))


def _module_file(module_name: Any) -> Optional[str]:
    return getattr(sys.modules.get(module_name), "__file__", None) if isinstance(module_name, str) else None


@dataclass(frozen=True)
class Builders:
    """What building an agent means for one framework.

    ``prefixes``: the framework's top-level module names (``"strands"``,
    ``"google.adk"``); a module is the framework's when its name is one of
    them or starts with one followed by a dot.
    ``builds``: called with a class or a plain function only; ``True`` when
    calling it builds an agent, runner or orchestrator.
    ``held``: an object the tool may refer to without building anything (an
    agent instance the plugin governs as a child); never descended into.
    ``tool_function``: the Python function behind a framework tool object,
    or ``None``; it must read stored values only.
    ``refused_names``: attribute or global names that, used anywhere in the
    code the read follows, count as able to build an agent (for example the
    accessor of a framework's internal run context).
    """

    prefixes: Tuple[str, ...]
    builds: Callable[[Any], bool]
    held: Callable[[Any], bool] = lambda obj: False
    tool_function: Callable[[Any], Optional[Callable[..., Any]]] = lambda obj: None
    refused_names: frozenset = frozenset()

    def owns_module(self, name: Any) -> bool:
        return isinstance(name, str) and any(
            name == prefix or name.startswith(prefix + ".") for prefix in self.prefixes
        )

    def leads_to(self, name: Any) -> bool:
        """The framework's own module, or a package above it (``google`` for
        ``google.adk``), through which code can name a framework class."""
        return self.owns_module(name) or (
            isinstance(name, str) and any(prefix.startswith(name + ".") for prefix in self.prefixes)
        )


class _TooLarge(Exception):
    pass


#: Stands for "a framework module attribute the code names builds an agent"
#: in the read's work list.
_BUILDS = object()


def _code_names(code: types.CodeType) -> Iterator[str]:
    """Every global and attribute name a code object and the code objects
    nested in it (functions, lambdas, comprehensions, classes) use."""
    stack = [code]
    while stack:
        current = stack.pop()
        yield from current.co_names
        stack.extend(c for c in current.co_consts if isinstance(c, types.CodeType))


class _Reader:
    def __init__(self, builders: Builders) -> None:
        self.b = builders
        self.seen: Set[int] = set()
        self.count = 0
        self.walk_module: Dict[str, bool] = {}
        self.refused = INDIRECTION_NAMES | builders.refused_names
        #: Objects read whatever their module (the tool function itself).
        self.always: Set[int] = set()
        #: The tool function's top-level package: the application's own.
        self.own_package: Optional[str] = None

    def start(self, tool: Any) -> None:
        plain = isinstance(tool, (type, types.FunctionType, types.MethodType, functools.partial))
        func = None if plain else self.b.tool_function(tool)
        # An instance whose class defines the tool: its class is read.
        cls = type(tool) if not plain and func is None else None
        for obj in (tool, func, cls):
            if obj is None:
                continue
            target = obj.func if isinstance(obj, functools.partial) else obj
            if isinstance(target, types.MethodType):
                target = target.__func__
            module = getattr(target, "__module__", None)
            if not isinstance(module, str) or self.b.owns_module(module):
                continue
            if _under(_module_file(module), _STDLIB_ROOTS):
                continue  # a standard-library object is never the application's code
            self.always.add(id(target))
            if self.own_package is None:
                self.own_package = module.split(".", 1)[0]

    def _builds(self, obj: Any) -> bool:
        if obj is _BUILDS:
            return True
        if not isinstance(obj, (type, types.FunctionType)):
            return False
        try:
            return bool(self.b.builds(obj))
        except TypeError:
            return False

    def _imports_framework(self, module_name: str) -> bool:
        """Whether the module holds a framework module or a framework object
        in its globals (read from its ``__dict__``, never through a module
        ``__getattr__``)."""
        namespace = getattr(sys.modules.get(module_name), "__dict__", None)
        if not isinstance(namespace, dict):
            return False
        for value in list(namespace.values()):
            if isinstance(value, types.ModuleType):
                if self.b.owns_module(value.__name__):
                    return True
            elif isinstance(value, (type, types.FunctionType)) and self.b.owns_module(
                getattr(value, "__module__", None)
            ):
                return True
        return False

    def _is_application_module(self, module_name: str) -> bool:
        """Outside the standard library and installed packages, or in the
        tool function's own top-level package."""
        if self.own_package is not None and module_name.split(".", 1)[0] == self.own_package:
            return True
        return not _under(_module_file(module_name), _LIBRARY_ROOTS)

    def _follows_module(self, module_name: Any) -> bool:
        if not isinstance(module_name, str) or self.b.owns_module(module_name):
            return False
        if module_name not in self.walk_module:
            self.walk_module[module_name] = self._is_application_module(
                module_name
            ) or self._imports_framework(module_name)
        return self.walk_module[module_name]

    def _follows(self, obj: Any) -> bool:
        if id(obj) in self.always:
            return True
        return self._follows_module(getattr(obj, "__module__", None))

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
            if self._builds(obj):
                return True
            stack.extend(self._children(obj))
        return False

    def _children(self, obj: Any) -> List[Any]:
        if self.b.held(obj):
            return []
        if isinstance(obj, functools.partial):
            return [obj.func, *obj.args, *obj.keywords.values()]
        if isinstance(obj, types.MethodType):
            owner = obj.__self__
            if self.b.held(owner):
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
        func = self.b.tool_function(obj)
        if func is not None:
            # Another framework tool the code calls.
            return [func]
        # An instance: the methods of its class.
        return [type(obj)]

    def _module_attributes(self, roots: List[types.ModuleType], names: Set[str]) -> List[Any]:
        """What the names the code uses resolve to through the modules it
        refers to (``helpers.run_sub``, ``google.adk.runners.Runner``).
        A framework attribute that builds an agent comes back as
        :data:`_BUILDS`; an attribute of an application module comes back
        to be read like any other value. Read from each module's
        ``__dict__``, so no module ``__getattr__`` runs."""
        seen: Set[int] = set()
        stack = list(roots)
        out: List[Any] = []
        while stack:
            module = stack.pop()
            if id(module) in seen:
                continue
            seen.add(id(module))
            self.count += 1
            if self.count > MAX_NODES:
                raise _TooLarge()
            namespace = getattr(module, "__dict__", None)
            if not isinstance(namespace, dict):
                continue
            module_name = getattr(module, "__name__", None)
            framework = self.b.owns_module(module_name)
            for name in names:
                value = namespace.get(name)
                if value is None:
                    continue
                if isinstance(value, types.ModuleType):
                    if self._reaches(value):
                        stack.append(value)
                elif framework:
                    if self._builds(value):
                        return [_BUILDS]
                else:
                    out.append(value)
        return out

    def _reaches(self, module: types.ModuleType) -> bool:
        """A module through which code can name a framework class or the
        application's own code."""
        name = getattr(module, "__name__", None)
        if self.b.leads_to(name):
            return True
        if isinstance(name, str) and sys.modules.get(name) is not module:
            # A module object not registered under its name: judge it by
            # its own file.
            return not self.b.owns_module(name) and not _under(getattr(module, "__file__", None), _LIBRARY_ROOTS)
        return self._follows_module(name)

    def _function_children(self, func: types.FunctionType) -> List[Any]:
        names = set(_code_names(func.__code__))
        if names & self.refused:
            return [_BUILDS]
        globals_ = func.__globals__
        values: List[Any] = [globals_[name] for name in names if name in globals_]
        for cell in func.__closure__ or ():
            try:
                values.append(cell.cell_contents)
            except ValueError:
                continue
        out: List[Any] = []
        modules: List[types.ModuleType] = []
        for value in values:
            if isinstance(value, types.ModuleType):
                if self._reaches(value):
                    modules.append(value)
                continue
            out.append(value)
        if modules:
            out.extend(self._module_attributes(modules, names))
        out.extend(func.__defaults__ or ())
        out.extend((func.__kwdefaults__ or {}).values())
        return out


def can_build_agents(tool: Any, builders: Builders) -> bool:
    """Whether the code of ``tool`` (a framework tool object, a function, or
    an instance whose class defines the tool) can build an agent, runner or
    orchestrator of the framework ``builders`` describes. ``True`` when the
    read could not finish."""
    reader = _Reader(builders)
    try:
        reader.start(tool)
        return reader.builds(tool)
    except _TooLarge:
        return True
