"""Provider-hosted tools: normalize them, authorize them before each model
call, and record them in lineage.

Model providers run some tools on their own servers, inside the model call:
web search, code execution, file search, image generation, remote MCP. No
framework tool hook fires for them, so a plugin must authorize every such
tool enabled on a model call *before* it sends the call. This module is the
shared primitive every plugin uses for that; the TypeScript SDK carries an
identical copy in ``hosted-tools.ts``, and both read the same fixtures.

The documented wiring is one call, as the last step before every model call,
with the FULL request the plugin is about to send (not just its ``tools``):

.. code-block:: python

    turn = HostedToolTurn()
    await require_hosted_request_allowed(handle, request, turn,
                                         registered_mcp_servers=servers)
    response = await model.call(request)   # only reached when allowed
    turn.seal()

Parts:

- :func:`normalize_hosted_request` reads a whole model request: its tools
  and the request-level fields that enable a hosted capability without a
  tool entry (OpenAI ``web_search_options`` and stored ``prompt``,
  Anthropic ``mcp_servers``, Gemini ``cached_content``, xAI
  ``search_parameters``). :func:`normalize_hosted_tools` reads a tools list.
  Function and custom tools are left out (the framework's tool hook governs
  them). A tool of an unknown shape is reported by its type name, never
  dropped, so policy decides it (and denies it unless a policy allows it).
- :func:`require_hosted_request_allowed` (raising) and
  :func:`authorize_hosted_request` (returning a result) make one ``/authorize`` decision per distinct hosted
  tool through the run handle. Anything but Allow (Deny, approval required,
  an error, a timeout, an unregistered MCP server, an invalid tool
  configuration) refuses the whole model call. The gate never removes a
  tool from the call to make it pass.
- :func:`hosted_tool_observation` / :func:`publish_hosted_tool_observed`
  build and publish a value-free ``tool_call_observed`` event for a hosted
  tool invocation seen in a model response.

Every summary is value-free: kinds, names, counts, and for remote MCP the
server label, the server host (never the URL path, which can carry a
token) and the allowed tool names. Arguments, headers and tokens are never
read into it.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import dataclasses
import logging
import functools
import inspect
import json
import re
import weakref
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple, Type

from pydantic import BaseModel
from pydantic_core import SchemaSerializer

from .actions import resolve_action
from .errors import WatchlightError
from .results import AuthorizeResult

__all__ = [
    "ALLOWED_TOOLS_INVALID",
    "MCP_SERVER_AMBIGUOUS",
    "HOSTED_MCP_SERVER_UNREGISTERED",
    "HOSTED_TOOL_CONFIG_INVALID",
    "HOSTED_TOOL_METADATA",
    "HOSTED_TOOL_PROVIDERS",
    "HOSTED_TOOL_REFUSED_TIMEOUT",
    "HOSTED_TOOL_REFUSED_UNAVAILABLE",
    "HostedTool",
    "HostedToolGateResult",
    "HostedToolRefused",
    "HostedToolRequest",
    "HostedToolTurn",
    "authorize_hosted_request",
    "authorize_hosted_tools",
    "hosted_tool_identity",
    "hosted_tool_observation",
    "hosted_tool_request",
    "normalize_hosted_request",
    "normalize_hosted_tools",
    "normalize_mcp_server_url",
    "publish_hosted_tool_observed",
    "require_hosted_request_allowed",
    "require_hosted_request_allowed_blocking",
]

#: Provider hints the normalizers accept.
HOSTED_TOOL_PROVIDERS: Tuple[str, ...] = (
    "openai",
    "anthropic",
    "gemini",
    "xai",
    "bedrock",
    "pydantic_ai",
)

#: Refusal reasons the gate sets on the :class:`AuthorizeResult` it returns
#: when it refuses without a policy decision. Identical in the TS SDK.
HOSTED_MCP_SERVER_UNREGISTERED = "hosted_mcp_server_unregistered"
HOSTED_TOOL_CONFIG_INVALID = "hosted_tool_config_invalid"

#: Why a remote MCP tool's configuration is refused (``HostedTool.problem``).
ALLOWED_TOOLS_INVALID = "allowed_tools_invalid"
MCP_SERVER_AMBIGUOUS = "mcp_server_ambiguous"
#: Why a ``file_search`` tool is refused (``HostedTool.problem``): its store
#: ids are not a list of at most 64 plain tokens.
VECTOR_STORE_IDS_INVALID = "vector_store_ids_invalid"
HOSTED_TOOL_REFUSED_TIMEOUT = "hosted_tool_authorization_timeout"
HOSTED_TOOL_REFUSED_UNAVAILABLE = "hosted_tool_authorization_unavailable"

#: Metadata stamped on a hosted tool's ``tool_call_observed`` event.
HOSTED_TOOL_METADATA: Mapping[str, Any] = {"hosted_tool": True}

#: The default deadline for each hosted-tool decision.
DEFAULT_TIMEOUT_SECONDS = 30.0

#: Cap on a summary: the ``input_summary`` cap of ``tool_call_observed``.
SUMMARY_MAX_CHARS = 120
TOKEN_MAX_CHARS = 128
URL_MAX_CHARS = 2048
ALLOWED_TOOLS_MAX = 64
#: Cap on the store ids of one ``file_search`` tool and on the skills of
#: one request's ``container``.
VECTOR_STORE_IDS_MAX = 64
SKILLS_MAX = 64
#: The Anthropic skill types (``container.skills[].type``).
SKILL_TYPES = ("anthropic", "custom")

UNKNOWN_PROVIDER = "unknown"

#: How deep the passthrough scopes of a request are followed.
SCOPE_MAX_DEPTH = 3

_TOKEN_UNSAFE = re.compile(r"[^A-Za-z0-9_.:/@+\-]")

#: A function name a provider accepts for a function declaration (Gemini: a
#: letter or underscore, then letters, digits, ``_``, ``.``, ``:`` or ``-``,
#: at most 64 characters). A callable named otherwise is reported as unknown.
_CALLABLE_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_.:\-]{0,63}")
_ANTHROPIC_VERSIONED = re.compile(r"([a-z][a-z0-9_]*?)_([0-9]{8})")
_URL = re.compile(r"([A-Za-z][A-Za-z0-9+.\-]*)://([^/?#]*)([^?#]*)")
_HOST_PORT = re.compile(r"([A-Za-z0-9.\-]+)(?::([0-9]{1,5}))?")
_IPV6_PORT = re.compile(r"\[([0-9A-Fa-f:.]+)\](?::([0-9]{1,5}))?")
_CAMEL = re.compile(r"(?<=[a-z0-9])([A-Z])")
_SERVER_NAME = re.compile(r"[A-Za-z0-9_.:@+\-]{1,128}")
_FRAMEWORK = re.compile(r"[a-z][a-z0-9_\-]{0,63}")
_DEFAULT_PORTS = {"https": 443, "http": 80, "wss": 443, "ws": 80}

_OPENAI_EXACT = (
    "file_search",
    "code_interpreter",
    "image_generation",
    "local_shell",
    "shell",
    "apply_patch",
)
_XAI_EXACT = ("x_search", "collections_search", "code_execution", "document_search")
_GEMINI_FIELDS = (
    "retrieval",
    "google_search_retrieval",
    "google_search",
    "code_execution",
    "url_context",
    "computer_use",
    "file_search",
    "enterprise_web_search",
    "google_maps",
    "parallel_ai_search",
    "exa_ai_search",
    "mcp_servers",
)
_FUNCTION_SCHEMA_KEYS = ("input_schema", "inputSchema", "parameters", "description")
#: Every key (snake_case; a camelCase key is compared after conversion) that
#: some provider lane reads as a hosted tool on a tool entry: the Gemini
#: ``types.Tool`` fields, the remote MCP fields of OpenAI, xAI and Anthropic
#: entries, and Bedrock's ``systemTool``. A tool entry classified by any
#: other shape must not carry one, or a provider SDK that copies the keys
#: it knows would send a hosted tool the gate never decided.
_HOSTED_TOOL_KEYS = frozenset(_GEMINI_FIELDS) | frozenset(
    ("server_label", "server_url", "connector_id", "mcp_server_name", "system_tool")
)
_PYDANTIC_AI_BASES = ("AbstractNativeTool", "AbstractBuiltinTool")


#: The full canonical MCP server URL of each :class:`HostedTool` that has
#: one, keyed by the tool's ``id`` with a weak reference to the tool, and
#: dropped when the tool is collected. A lookup whose weak reference does
#: not point at the same tool (an ``id`` reused after collection) finds no
#: URL, so the tool is refused as unregistered.
#: It lives outside the dataclass fields, so ``dataclasses.asdict``,
#: ``vars``, ``copy`` and ``pickle`` never carry it: a copy or an unpickled
#: tool has no URL and is refused as unregistered (fail closed).
_SERVER_URLS: Dict[int, Tuple["weakref.ReferenceType[HostedTool]", str]] = {}


def _server_url_of(tool: "HostedTool") -> Optional[str]:
    entry = _SERVER_URLS.get(id(tool))
    if entry is None or entry[0]() is not tool:
        return None
    return entry[1]


def _drop_server_url(key: int, ref: "weakref.ReferenceType[HostedTool]") -> None:
    entry = _SERVER_URLS.get(key)
    if entry is not None and entry[0] is ref:
        del _SERVER_URLS[key]


def _with_server_url(tool: "HostedTool", url: Optional[str]) -> "HostedTool":
    if url is not None:
        key = id(tool)

        def _collected(dead: "weakref.ReferenceType[HostedTool]") -> None:
            _drop_server_url(key, dead)

        _SERVER_URLS[key] = (weakref.ref(tool, _collected), url)
    return tool


@dataclass(frozen=True, eq=False)
class HostedTool:
    """One provider-hosted tool enabled on a model call.

    ``provider`` is the provider shape it came from (``openai``,
    ``anthropic``, ``gemini``, ``xai``, ``bedrock``, ``pydantic_ai``, or
    ``unknown``). ``kind`` is the stable family a policy names
    (``web_search``, ``code_execution``, ``mcp``, ...; ``Tool::"<kind>"``).
    ``name`` is the raw type or field name. ``summary`` is value-free.

    For remote MCP (``kind == "mcp"``), ``server_origin`` is the server's
    canonical ``scheme://host[:port]`` (or ``connector:<id>``; ``None`` when
    the call names none or one that is refused), ``server_label`` the label
    the call gives it, and ``allowed_tools`` the tool names the call allows
    (``None``: every tool). For ``file_search``, ``vector_store_ids`` are
    the stores it searches (sorted, without repeats; OpenAI
    ``vector_store_ids``, Gemini ``file_search_store_names``, Pydantic AI
    ``file_store_ids``). For an Anthropic skill (``kind == "skill"``, read
    from the request's ``container.skills``), ``name`` is the skill type and
    ``skill_id`` the skill. Store ids and skill ids are part of what one
    decision covers and go to the decision's context only: like a server URL,
    they never appear in a summary or ``to_dict``. ``problem`` names a
    configuration the gate refuses (``allowed_tools_invalid``,
    ``mcp_server_ambiguous``, ``vector_store_ids_invalid``). The full
    canonical URL is kept private: the gate uses it only to look the server
    up in the registry, and it never appears in a summary or ``to_dict``.
    """

    provider: str
    kind: str
    name: str
    summary: str
    server_origin: Optional[str] = None
    server_label: Optional[str] = None
    allowed_tools: Optional[Tuple[str, ...]] = None
    problem: Optional[str] = None
    # Decision context only, never shown: kept out of ``repr`` like the
    # server URL.
    vector_store_ids: Optional[Tuple[str, ...]] = field(default=None, repr=False)
    skill_id: Optional[str] = field(default=None, repr=False)

    @property
    def _server_url(self) -> Optional[str]:
        return _server_url_of(self)

    def _identity(self) -> Tuple[Any, ...]:
        return (
            self.provider,
            self.kind,
            self.name,
            self.summary,
            self.server_origin,
            self.server_label,
            self.allowed_tools,
            self.problem,
            self.vector_store_ids,
            self.skill_id,
            _server_url_of(self),
        )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, HostedTool):
            return NotImplemented
        return self._identity() == other._identity()

    def __hash__(self) -> int:
        return hash(self._identity())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "provider": self.provider,
            "kind": self.kind,
            "name": self.name,
            "summary": self.summary,
            "server_origin": self.server_origin,
            "server_label": self.server_label,
            "allowed_tools": (
                list(self.allowed_tools) if self.allowed_tools is not None else None
            ),
            "problem": self.problem,
        }


# ─── Normalizer ──────────────────────────────────────────────────────


def _token(value: str, limit: int = TOKEN_MAX_CHARS) -> str:
    return _TOKEN_UNSAFE.sub("_", value)[:limit]


def _snake(key: str) -> str:
    return _CAMEL.sub(lambda m: "_" + m.group(1).lower(), key)


def _is_dict(value: Any) -> bool:
    """Whether ``value`` is a dict the gate reads. Only an exact ``dict``
    with ``str`` keys is: any other mapping (a dict subclass, a custom
    ``Mapping``) raises ``TypeError``, because it can hide a key from the
    gate's iteration while the provider SDK's serializer still sends it.
    The TypeScript lane refuses symbol, non-enumerable and accessor keys
    for the same reason."""
    if type(value) is dict:
        for key, item in value.items():
            if type(key) is not str:
                raise TypeError("a hosted-tool request dict carries a key that is not a string")
            if callable(item):
                # No request value is callable; the TypeScript lane refuses
                # a function value, which ``JSON.stringify`` can call
                # (``toJSON``).
                raise TypeError(f"a hosted-tool request dict carries the callable `{key}`")
        return True
    if isinstance(value, Mapping):
        raise TypeError(f"a hosted-tool request carries a {type(value).__name__}, not a plain dict")
    return False


def _is_list(value: Any) -> bool:
    """Whether ``value`` is a list or tuple the gate reads. A subclass raises
    ``TypeError``: its ``__iter__`` can show the gate other entries than the
    serializer sends."""
    if type(value) in (list, tuple):
        return True
    if isinstance(value, (list, tuple)):
        raise TypeError(f"a hosted-tool request carries a {type(value).__name__}, not a plain list")
    return False


try:  # pydantic's placeholder until a deferred model class is built
    from pydantic._internal._mock_val_ser import MockValSer as _MockValSer
except ImportError:  # pragma: no cover - older pydantic
    _MockValSer = SchemaSerializer

#: ``BaseModel`` methods a model class must not replace: each can make what
#: the gate reads differ from what the provider SDK serializes.
_MODEL_HOOKS: Tuple[str, ...] = ("__getattribute__", "__getattr__", "model_dump", "model_dump_json")


@functools.lru_cache(maxsize=512)
def _refuse_unprovable_model(cls: type) -> None:
    """Raise ``TypeError`` unless the gate can prove that a model class
    serializes exactly its ``__dict__`` and extras, under the field names
    the gate reads: no replaced attribute or serializer hook, no custom
    model or field serializer, no computed field (serialized, never in
    ``__dict__``), and no alias that names another field once converted to
    snake_case (google-genai's camelCase aliases pass), and no excluded
    field (kept in ``__dict__``, never serialized)."""
    for name in _MODEL_HOOKS:
        if getattr(cls, name) is not getattr(BaseModel, name):
            raise TypeError(f"a hosted-tool request model {cls.__name__} replaces {name}")
    if not isinstance(getattr(cls, "__pydantic_serializer__", None), (SchemaSerializer, _MockValSer)):
        raise TypeError(f"a hosted-tool request model {cls.__name__} replaces its serializer")
    decorators = getattr(cls, "__pydantic_decorators__", None)
    if decorators is None or decorators.model_serializers or decorators.field_serializers:
        raise TypeError(f"a hosted-tool request model {cls.__name__} has a custom serializer")
    if cls.model_computed_fields:
        raise TypeError(f"a hosted-tool request model {cls.__name__} has a computed field")
    for name, info in cls.model_fields.items():
        if info.exclude or getattr(info, "exclude_if", None) is not None:
            raise TypeError(
                f"a hosted-tool request model {cls.__name__} excludes `{name}` from serialization"
            )
        alias = info.serialization_alias or info.alias
        if alias is not None and _snake(alias) != name:
            raise TypeError(
                f"a hosted-tool request model {cls.__name__} serializes `{name}` as `{alias}`"
            )


def _model_values(model: Any) -> Dict[str, Any]:
    """What pydantic-core serializes for ``model``: its declared fields from
    ``__dict__`` and its extras from ``__pydantic_extra__``, read past any
    attribute hook (see :func:`_refuse_unprovable_model`)."""
    _refuse_unprovable_model(type(model))
    values = dict(object.__getattribute__(model, "__dict__"))
    extra = object.__getattribute__(model, "__pydantic_extra__")
    if extra:
        for key, value in extra.items():
            if type(key) is not str or key in values:
                raise TypeError("a hosted-tool request model carries an unreadable extra field")
            values[key] = value
    return values


def _get(obj: Any, *keys: str) -> Any:
    """The first present, non-None value of ``keys`` on a mapping or object."""
    model = _model_values(obj) if _is_model(obj) else None
    for key in keys:
        if _is_dict(obj):
            value = obj.get(key)
        elif model is not None:
            value = model.get(key)
        else:
            value = getattr(obj, key, None)
        if value is not None:
            return value
    return None


def normalize_mcp_server_url(url: Any) -> Optional[str]:
    """The canonical form of an MCP server URL, or ``None`` (refused).

    Refused: anything but a string; any backslash, whitespace, control or
    non-ASCII character; credentials (``user@``) in the authority; a host
    that is not a plain DNS name or bracketed IP; a port outside 1-65535;
    more than 2048 characters.
    Kept: ``scheme://host[:port]/path`` with scheme and host lowercased, one
    trailing dot removed from the host, the scheme's default port dropped
    and trailing slashes removed; query and fragment are dropped. A
    ``connector:`` reference is not a URL and is refused here.
    """
    if not isinstance(url, str) or not url or len(url) > URL_MAX_CHARS:
        return None
    if any(ord(c) <= 0x20 or ord(c) >= 0x7F or c == "\\" for c in url):
        return None
    m = _URL.match(url)
    if m is None:
        return None
    scheme, authority, path = m.group(1).lower(), m.group(2), m.group(3)
    if "@" in authority:
        return None
    hp = _IPV6_PORT.fullmatch(authority)
    if hp is not None:
        host = "[" + hp.group(1).lower() + "]"
    else:
        hp = _HOST_PORT.fullmatch(authority)
        if hp is None:
            return None
        host = hp.group(1).lower()
        if host.endswith("."):
            host = host[:-1]
        if not host or host.endswith(".") or host.startswith("."):
            return None
    port_text = hp.group(2)
    port = ""
    if port_text is not None:
        number = int(port_text)
        if number < 1 or number > 65535:
            return None
        if _DEFAULT_PORTS.get(scheme) != number:
            port = f":{number}"
    return f"{scheme}://{host}{port}{path.rstrip('/')}"


def _connector_key(connector_id: Any) -> Optional[str]:
    """``connector:<id>`` for an OpenAI connector id that is a plain token."""
    if not isinstance(connector_id, str) or not connector_id or _token(connector_id) != connector_id:
        return None
    return "connector:" + connector_id


def _registry_key(url: Any) -> Optional[str]:
    """The key a registry entry is stored under: a canonical URL, or a
    ``connector:<id>`` reference."""
    if isinstance(url, str) and url.startswith("connector:"):
        return _connector_key(url[len("connector:") :])
    return normalize_mcp_server_url(url)


def _server_origin(server_url: Optional[str]) -> Optional[str]:
    if server_url is None or server_url.startswith("connector:"):
        return server_url
    m = _URL.match(server_url)
    return f"{m.group(1)}://{m.group(2)}" if m is not None else None


def _server_host(server_url: str) -> str:
    m = _URL.match(server_url)
    return m.group(2) if m is not None else ""


def _allowed_tool_names(value: Any) -> Tuple[Optional[Tuple[str, ...]], bool]:
    """``(names, ok)``. ``None`` names = every tool. Refused (``ok`` False):
    more than 64 names, a name that is not a string, empty, or not already
    a plain token, or a value of another shape."""
    if value is None:
        return None, True
    if _is_dict(value):
        if "tool_names" not in value or value.get("tool_names") is None:
            return None, True
        value = value.get("tool_names")
    if not _is_list(value):
        return None, False
    if len(value) > ALLOWED_TOOLS_MAX:
        return None, False
    for v in value:
        if not isinstance(v, str) or not v or _token(v) != v:
            return None, False
    return tuple(value), True


def _summary(
    provider: str,
    kind: str,
    name: str,
    *,
    fields: Optional[int] = None,
    server_url: Optional[str] = None,
    server_label: Optional[str] = None,
    allowed_tools: Optional[Tuple[str, ...]] = None,
    problem: Optional[str] = None,
) -> str:
    parts = [f"{provider}:{kind}"]
    if name and name != kind:
        parts.append(f"name={name}")
    if kind == "mcp":
        if server_label:
            parts.append(f"server_label={server_label}")
        if server_url:
            if server_url.startswith("connector:"):
                parts.append(f"connector={server_url[len('connector:'):]}")
            else:
                parts.append(f"server_host={_server_host(server_url)}")
        if allowed_tools is not None:
            parts.append(f"allowed_tools={len(allowed_tools)}:{','.join(allowed_tools)}")
    elif fields is not None:
        parts.append(f"fields={fields}")
    if problem:
        parts.append(f"problem={problem}")
    return " ".join(parts)[:SUMMARY_MAX_CHARS]


def _tool(provider: str, kind: str, name: str, *, fields: Optional[int] = None) -> HostedTool:
    provider, kind, name = _token(provider), _token(kind), _token(name)
    return HostedTool(provider, kind, name, _summary(provider, kind, name, fields=fields))


def _mcp_tool(
    provider: str,
    name: str,
    *,
    server_url: Optional[str],
    server_label: Any,
    allowed_tools: Any = None,
    problem: Optional[str] = None,
) -> HostedTool:
    provider, name = _token(provider), _token(name)
    label = _token(server_label) if isinstance(server_label, str) and server_label else None
    names, ok = _allowed_tool_names(allowed_tools)
    if problem is None and not ok:
        problem = ALLOWED_TOOLS_INVALID
    tool = HostedTool(
        provider,
        "mcp",
        name,
        _summary(
            provider,
            "mcp",
            name,
            server_url=server_url,
            server_label=label,
            allowed_tools=names,
            problem=problem,
        ),
        server_origin=_server_origin(server_url),
        server_label=label,
        allowed_tools=names,
        problem=problem,
    )
    return _with_server_url(tool, server_url)


def _store_ids(value: Any) -> Tuple[Tuple[str, ...], bool]:
    """``(ids, ok)`` for a ``file_search`` tool's store ids: sorted, without
    repeats. Absent is no stores. Refused (``ok`` False): more than 64 ids,
    an id that is not a string, empty, or not already a plain token, or a
    value of another shape."""
    if value is None:
        return (), True
    if not _is_list(value) or len(value) > VECTOR_STORE_IDS_MAX:
        return (), False
    for v in value:
        if not isinstance(v, str) or not v or _token(v) != v:
            return (), False
    return tuple(sorted(set(value))), True


def _file_search_tool(
    provider: str, name: str, stores: Any, *, fields: Optional[int] = None, readable: bool = True
) -> HostedTool:
    """A ``file_search`` tool carrying the stores it searches."""
    ids, ok = _store_ids(stores) if readable else ((), False)
    base = _tool(provider, "file_search", name, fields=fields)
    problem = None if ok else VECTOR_STORE_IDS_INVALID
    summary = base.summary if ok else _summary(
        base.provider, base.kind, base.name, fields=fields, problem=problem
    )
    return HostedTool(
        base.provider,
        base.kind,
        base.name,
        summary,
        problem=problem,
        vector_store_ids=ids if ok else None,
    )


def _gemini_file_search(value: Any, hint: Optional[str], name: str) -> HostedTool:
    """A Gemini ``file_search`` field (``file_search_store_names``)."""
    if not _is_scope(value):
        return _file_search_tool(hint or "gemini", name, None, readable=False)
    return _file_search_tool(
        hint or "gemini", name, _one(value, "file_search_store_names", "fileSearchStoreNames")
    )


_CONTAINER_KEYS = ("id", "skills")
_SKILL_KEYS = ("type", "skill_id", "version")


def _container_skills(container: Any, hint: Optional[str]) -> List[HostedTool]:
    """One ``skill`` tool per skill in an Anthropic ``container``: a
    container id (a plain token), or ``{id, skills}`` whose skills are
    ``{type, skill_id, version}``. Anything else raises ``TypeError``: a
    container the gate cannot read could load a skill it never decided."""
    if isinstance(container, str):
        if not container or _token(container) != container:
            raise TypeError("the request's `container` id is not a plain token")
        return []
    if not _is_scope(container):
        raise TypeError("the request's `container` is not a container id or a mapping")
    values = _model_values(container) if _is_model(container) else container
    for key, value in values.items():
        if key not in _CONTAINER_KEYS and value is not None:
            raise TypeError(f"the request's `container` carries an unknown key `{key}`")
    cid = values.get("id")
    if cid is not None and (not isinstance(cid, str) or not cid or _token(cid) != cid):
        raise TypeError("the request's `container.id` is not a plain token")
    skills = values.get("skills")
    if skills is None:
        return []
    if not _is_list(skills) or len(skills) > SKILLS_MAX:
        raise TypeError("the request's `container.skills` is not a list of at most 64 skills")
    out: List[HostedTool] = []
    provider = _token(hint or "anthropic")
    for skill in skills:
        if not _is_scope(skill):
            raise TypeError("a `container.skills` entry is not a mapping")
        entry = _model_values(skill) if _is_model(skill) else skill
        for key, value in entry.items():
            if key not in _SKILL_KEYS and value is not None:
                raise TypeError(f"a `container.skills` entry carries an unknown key `{key}`")
        stype, sid, version = entry.get("type"), entry.get("skill_id"), entry.get("version")
        if stype not in SKILL_TYPES:
            raise TypeError("a `container.skills` entry has no known `type`")
        if not isinstance(sid, str) or not sid or _token(sid) != sid:
            raise TypeError("a `container.skills` entry's `skill_id` is not a plain token")
        if version is not None and not isinstance(version, str):
            raise TypeError("a `container.skills` entry's `version` is not a string")
        out.append(HostedTool(provider, "skill", stype, _summary(provider, "skill", stype), skill_id=sid))
    return out


def _unknown(provider: Optional[str], type_name: str) -> HostedTool:
    return _tool(provider or UNKNOWN_PROVIDER, type_name, type_name)


def _type_name(entry: Any) -> str:
    """The name an unknown entry is reported by; the same in both SDKs for
    the JSON types (``str``, ``null``, ``list``, ``dict``, ``int``,
    ``float``, ``bool``)."""
    if entry is None:
        return "null"
    if isinstance(entry, bool):
        return "bool"
    if isinstance(entry, str):
        return "str"
    if isinstance(entry, int):
        return "int"
    if isinstance(entry, float):
        return "float"
    if isinstance(entry, (list, tuple)):
        return "list"
    if isinstance(entry, Mapping):
        return "dict"
    if isinstance(entry, type):
        return entry.__name__
    return type(entry).__name__


def _gemini_mcp_servers(servers: Any, hint: Optional[str]) -> List[HostedTool]:
    """One ``mcp`` tool per Gemini ``McpServer`` (``name`` and
    ``streamable_http_transport.url``), objects or dicts in either case."""
    provider = hint or "gemini"
    if not _is_list(servers):
        return [_mcp_tool(provider, "mcp_servers", server_url=None, server_label=None)]
    out: List[HostedTool] = []
    for server in servers:
        transport = _one(server, "streamable_http_transport", "streamableHttpTransport")
        url = _get(transport, "url") if transport is not None else None
        out.append(
            _mcp_tool(
                provider,
                "mcp_servers",
                server_url=normalize_mcp_server_url(url),
                server_label=_get(server, "name"),
            )
        )
    return out


def _from_mcp_server_entry(d: Any, hint: Optional[str], name: str) -> HostedTool:
    """An Anthropic ``mcp_servers`` entry (``type: url``)."""
    if not _is_dict(d):
        return _mcp_tool(hint or "anthropic", name, server_url=None, server_label=None)
    cfg = d.get("tool_configuration")
    allowed = cfg.get("allowed_tools") if _is_dict(cfg) else None
    return _mcp_tool(
        hint or "anthropic",
        name,
        server_url=normalize_mcp_server_url(d.get("url")),
        server_label=d.get("name"),
        allowed_tools=allowed,
    )


def _refuse_mixed_shape(d: Mapping[str, Any], shape: str, own: Tuple[str, ...] = ()) -> None:
    """Raise ``TypeError`` when a tool entry classified as ``shape`` also
    carries a hosted-tool key that is not part of that shape."""
    for key in d:
        if not isinstance(key, str):
            continue
        snaked = _snake(key)
        if snaked in _HOSTED_TOOL_KEYS and snaked not in own:
            raise TypeError(f"a {shape} tool entry also carries the hosted-tool key `{snaked}`")


def _from_mapping(d: Mapping[str, Any], hint: Optional[str]) -> List[HostedTool]:
    if "type" in d:
        t = d.get("type")
        if t == "mcp":
            _refuse_mixed_shape(d, "mcp", ("server_label", "server_url", "connector_id"))
        elif t == "mcp_toolset":
            _refuse_mixed_shape(d, "mcp_toolset", ("mcp_server_name",))
        else:
            _refuse_mixed_shape(d, "typed")
        if not isinstance(t, str) or not t:
            return [_unknown(hint, "dict")]
        if t in ("function", "custom"):
            return []
        fields = len([k for k in d if k != "type"])
        if t == "mcp":
            raw_url, connector = d.get("server_url"), d.get("connector_id")
            problem = None
            if raw_url is not None and connector is not None:
                # Both a URL and a connector: which one the provider uses
                # is not ours to guess.
                url, problem = None, MCP_SERVER_AMBIGUOUS
            elif raw_url is not None:
                url = normalize_mcp_server_url(raw_url)
            else:
                url = _connector_key(connector)
            return [
                _mcp_tool(
                    hint or "openai",
                    t,
                    server_url=url,
                    server_label=d.get("server_label"),
                    allowed_tools=d.get("allowed_tools"),
                    problem=problem,
                )
            ]
        if t == "mcp_toolset":
            # Anthropic: the tools of an ``mcp_servers`` entry, named by
            # ``mcp_server_name``. The decision is for the whole server.
            return [
                _mcp_tool(
                    hint or "anthropic",
                    t,
                    server_url=None,
                    server_label=d.get("mcp_server_name"),
                )
            ]
        if t == "url" and "url" in d:
            return [_from_mcp_server_entry(d, hint, t)]
        m = _ANTHROPIC_VERSIONED.fullmatch(t)
        if m is not None:
            return [_tool(hint or "anthropic", m.group(1), t, fields=fields)]
        if t.startswith("web_search"):
            return [_tool(hint or "openai", "web_search", t, fields=fields)]
        if t.startswith("computer_use"):
            return [_tool(hint or "openai", "computer_use", t, fields=fields)]
        if t == "file_search":
            return [_file_search_tool(hint or "openai", t, d.get("vector_store_ids"), fields=fields)]
        if t in _OPENAI_EXACT:
            return [_tool(hint or "openai", t, t, fields=fields)]
        if t in _XAI_EXACT:
            return [_tool(hint or "xai", t, t, fields=fields)]
        return [_tool(hint or UNKNOWN_PROVIDER, t, t, fields=fields)]

    if "systemTool" in d:
        _refuse_mixed_shape(d, "systemTool", ("system_tool",))
        if "toolSpec" in d:
            # A Bedrock tool is one union member; both is not ours to guess.
            raise TypeError("a tool entry carries both `systemTool` and `toolSpec`")
        st = d.get("systemTool")
        st_name = st.get("name") if _is_dict(st) else None
        kind = st_name if isinstance(st_name, str) and st_name else "system_tool"
        inner = len([k for k in st if k != "name"]) if _is_dict(st) else 0
        return [_tool(hint or "bedrock", kind, kind, fields=inner)]
    if "toolSpec" in d:
        _refuse_mixed_shape(d, "toolSpec")
        return []
    if "cachePoint" in d and len(d) == 1:
        return []
    if "name" in d and any(k in d for k in _FUNCTION_SCHEMA_KEYS):
        _refuse_mixed_shape(d, "function")
        return []
    raw_keys = list(d)
    keys = [(_snake(k) if isinstance(k, str) else k) for k in raw_keys]
    if keys and all(k == "function_declarations" or k in _GEMINI_FIELDS for k in keys):
        out: List[HostedTool] = []
        for raw_key, key in zip(raw_keys, keys):
            value = d[raw_key]
            if key == "function_declarations" or value is None:
                continue
            if key == "mcp_servers":
                out.extend(_gemini_mcp_servers(value, hint))
            elif key == "file_search":
                out.append(_gemini_file_search(value, hint, key))
            else:
                out.append(_tool(hint or "gemini", key, key))
        return out
    _refuse_mixed_shape(d, "unknown")
    return [_unknown(hint, "dict")]


def _is_gemini_tool(entry: Any) -> bool:
    return _is_model(entry) and "function_declarations" in type(entry).model_fields


def _is_pydantic_ai_native(entry: Any) -> bool:
    return not isinstance(entry, type) and any(
        c.__name__ in _PYDANTIC_AI_BASES for c in type(entry).__mro__[1:]
    )


def _native_values(entry: Any) -> Dict[str, Any]:
    """A pydantic-ai native tool's dataclass fields, read from its
    ``__dict__``. A class that hooks attribute access or shadows a field
    with a descriptor (a property, say) is refused, so the fields read
    here are the ones any attribute read returns."""
    cls = type(entry)
    if not dataclasses.is_dataclass(entry):
        raise TypeError(f"a pydantic-ai native tool {cls.__name__} is not a dataclass")
    if cls.__getattribute__ is not object.__getattribute__ or hasattr(cls, "__getattr__"):
        raise TypeError(f"a pydantic-ai native tool {cls.__name__} hooks attribute access")
    try:
        stored = object.__getattribute__(entry, "__dict__")
    except AttributeError:
        raise TypeError(f"a pydantic-ai native tool {cls.__name__} has no instance fields") from None
    values: Dict[str, Any] = {}
    for f in dataclasses.fields(entry):
        attr = inspect.getattr_static(cls, f.name, None)
        if hasattr(type(attr), "__get__") and (
            hasattr(type(attr), "__set__") or hasattr(type(attr), "__delete__")
        ):
            raise TypeError(
                f"a pydantic-ai native tool {cls.__name__} shadows `{f.name}` with a descriptor"
            )
        if f.name not in stored:
            raise TypeError(f"a pydantic-ai native tool {cls.__name__} hides `{f.name}`")
        values[f.name] = stored[f.name]
    return values


def _from_object(entry: Any, hint: Optional[str]) -> List[HostedTool]:
    if _is_gemini_tool(entry):
        # The ADK reading: every ``types.Tool`` field other than
        # ``function_declarations`` that is set is a built-in; each MCP
        # server is its own tool.
        out: List[HostedTool] = []
        for name, value in _model_values(entry).items():
            if name == "function_declarations":
                continue
            if value is None:
                continue
            if name == "mcp_servers":
                out.extend(_gemini_mcp_servers(value, hint))
            elif name == "file_search":
                out.append(_gemini_file_search(value, hint, name))
            else:
                out.append(_tool(hint or "gemini", name, name))
        return out
    if _is_pydantic_ai_native(entry):
        native = _native_values(entry)
        kind = native.get("kind")
        cls_name = type(entry).__name__
        if not isinstance(kind, str):
            return [_unknown(hint or "pydantic_ai", cls_name)]
        if kind == "mcp_server":
            return [
                _mcp_tool(
                    hint or "pydantic_ai",
                    cls_name,
                    server_url=normalize_mcp_server_url(native.get("url")),
                    server_label=native.get("id"),
                    allowed_tools=native.get("allowed_tools"),
                )
            ]
        if kind == "file_search":
            return [_file_search_tool(hint or "pydantic_ai", cls_name, native.get("file_store_ids"))]
        return [_tool(hint or "pydantic_ai", kind, cls_name)]
    which_oneof = getattr(entry, "WhichOneof", None)
    if callable(which_oneof) and not isinstance(entry, type):
        # An xAI SDK ``chat_pb2.Tool``: the set ``tool`` oneof names it.
        try:
            which = which_oneof("tool")
        except Exception:  # noqa: BLE001 - an unknown message is reported, not dropped
            which = None
        if which == "function":
            return []
        if which == "mcp":
            sub = getattr(entry, "mcp", None)
            # An empty repeated field allows every tool on the server.
            allowed = list(getattr(sub, "allowed_tool_names", None) or []) or None
            return [
                _mcp_tool(
                    hint or "xai",
                    "mcp",
                    server_url=normalize_mcp_server_url(getattr(sub, "server_url", None)),
                    server_label=getattr(sub, "server_label", None),
                    allowed_tools=allowed,
                )
            ]
        if isinstance(which, str) and which:
            return [_tool(hint or "xai", which, which)]
        return [_unknown(hint, _type_name(entry))]
    if inspect.isfunction(entry) or inspect.ismethod(entry):
        if hint == "gemini":
            # A Python function in a Gemini request config is run by the
            # client's automatic function calling, never through a tool
            # hook: authorize it by name, as the ADK plugin does. A name
            # outside the provider's function-name rule could not be
            # decided as sent.
            raw = getattr(entry, "__name__", None)
            if isinstance(raw, str) and _CALLABLE_NAME.fullmatch(raw):
                name = "callable:" + raw
                return [_tool(hint, name, name)]
            return [_unknown(hint, "callable")]
        return []
    return [_unknown(hint, _type_name(entry))]


def _resolve_toolsets(tools: List[HostedTool]) -> List[HostedTool]:
    """Give an Anthropic ``mcp_toolset`` the URL of the ``mcp_servers``
    entry it names, when that entry was passed with the tools."""
    urls = {
        t.server_label: t._server_url
        for t in tools
        if t.kind == "mcp" and t.name in ("url", "mcp_servers") and t.provider == "anthropic"
        and t.server_label and t._server_url
    }
    out: List[HostedTool] = []
    for t in tools:
        if t.kind == "mcp" and t.name == "mcp_toolset" and t._server_url is None and t.server_label in urls:
            url = urls[t.server_label]
            t = _with_server_url(HostedTool(
                t.provider,
                t.kind,
                t.name,
                _summary(
                    t.provider,
                    t.kind,
                    t.name,
                    server_url=url,
                    server_label=t.server_label,
                    allowed_tools=t.allowed_tools,
                    problem=t.problem,
                ),
                server_origin=_server_origin(url),
                server_label=t.server_label,
                allowed_tools=t.allowed_tools,
                problem=t.problem,
            ), url)
        out.append(t)
    return out


def _check_provider(provider: Optional[str]) -> None:
    if provider is not None and provider not in HOSTED_TOOL_PROVIDERS:
        raise ValueError(f"unknown hosted-tool provider {provider!r}")


def _entries(tools: Any) -> List[Any]:
    if tools is None:
        return []
    if _is_list(tools):
        return list(tools)
    if (
        _is_dict(tools)
        or _is_model(tools)
        or isinstance(tools, (str, bytes))
        or not isinstance(tools, Iterable)
    ):
        return [tools]
    # Any other iterable could show the gate one set of entries and the
    # SDK, which iterates it again, another: refuse it, as list and tuple
    # subclasses are refused.
    raise TypeError(
        f"a hosted-tool list must be a list or tuple, not {type(tools).__name__}"
    )


def _normalize_entries(entries: Iterable[Any], provider: Optional[str]) -> List[HostedTool]:
    found: List[HostedTool] = []
    for entry in entries:
        if isinstance(entry, HostedTool):
            found.append(entry)
        elif _is_dict(entry):
            found.extend(_from_mapping(entry, provider))
        elif entry is None or isinstance(entry, (str, bytes, int, float)) or _is_list(entry):
            found.append(_unknown(provider, _type_name(entry)))
        else:
            found.extend(_from_object(entry, provider))
    return found


def _dedupe(tools: List[HostedTool]) -> List[HostedTool]:
    out: List[HostedTool] = []
    for t in _resolve_toolsets(tools):
        if t not in out:
            out.append(t)
    return out


def normalize_hosted_tools(tools: Any, provider: Optional[str] = None) -> List[HostedTool]:
    """The provider-hosted tools in a ``tools`` list.

    Reads OpenAI Responses tool dicts, Anthropic tool dicts, Gemini
    ``types.Tool`` objects or dicts (snake or camelCase, including
    ``mcp_servers``), xAI tool dicts or SDK messages, Bedrock Converse
    ``toolConfig.tools`` entries and Pydantic AI native tools. ``None`` is
    no tools; a single entry is a one-element list; a :class:`HostedTool`
    passes through. ``provider`` (one of :data:`HOSTED_TOOL_PROVIDERS`)
    names the provider when a shape is shared.

    This reads a tools list only and misses request-level hosted tools; use
    :func:`normalize_hosted_request` (and :func:`require_hosted_request_allowed`)
    for a full request.
    """
    _check_provider(provider)
    return _dedupe(_normalize_entries(_entries(tools), provider))


def _is_model(value: Any) -> bool:
    """A pydantic model instance (the request types of the google-genai,
    OpenAI and Anthropic SDKs), read field by field."""
    return not isinstance(value, type) and isinstance(value, BaseModel)


def _is_scope(value: Any) -> bool:
    """A mapping or a pydantic model. Any other object (a class instance, a
    namespace, a sequence, a scalar) is not a request scope."""
    return _is_dict(value) or _is_model(value)


def _present(scope: Any, key: str) -> bool:
    if _is_dict(scope):
        return key in scope
    if _is_model(scope):
        return _model_values(scope).get(key) is not None
    return getattr(scope, key, None) is not None


def _one(scope: Any, *keys: str) -> Any:
    """``_get`` for a key read under more than one spelling (snake_case
    and camelCase). A scope that carries two spellings of one key is
    refused: the gate must not read one while the provider SDK sends the
    other."""
    if sum(1 for key in keys if _present(scope, key)) > 1:
        raise TypeError(
            "hosted-tool request carries more than one spelling of `" + "` / `".join(keys) + "`"
        )
    return _get(scope, *keys)


def _child_scope(value: Any, key: str) -> Any:
    """``value`` as a scope, ``None`` when absent; a present value of any
    other type is refused (it could carry tools the gate cannot read)."""
    if value is None or _is_scope(value):
        return value
    raise TypeError(f"hosted-tool request field `{key}` is not a mapping")


def _scopes(request: Any, provider: Optional[str]) -> List[Tuple[Any, Optional[str]]]:
    """The request and every passthrough scope that can carry hosted tools,
    each with the provider hint its entries are read with, breadth first:
    ``config`` (Gemini, so its entries are read as Gemini), ``extra_body``,
    ``additionalModelRequestFields`` / ``additional_model_request_fields``
    (Bedrock Converse) and ``http_options.extra_body`` (Gemini).

    Raises ``TypeError`` when a passthrough field is present but not a
    mapping, or when scopes nest deeper than :data:`SCOPE_MAX_DEPTH`: the
    gate refuses what it cannot read instead of skipping it."""
    out: List[Tuple[Any, Optional[str]]] = [(request, provider)]
    frontier: List[Tuple[Any, Optional[str]]] = [(request, provider)]
    depth = 0
    while frontier:
        nxt: List[Tuple[Any, Optional[str]]] = []
        for scope, hint in frontier:
            children: List[Tuple[Any, Optional[str]]] = [
                (_child_scope(_get(scope, "config"), "config"), hint or "gemini"),
                (_child_scope(_one(scope, "extra_body", "extraBody"), "extra_body"), hint),
                (
                    _child_scope(
                        _one(scope, "additionalModelRequestFields", "additional_model_request_fields"),
                        "additionalModelRequestFields",
                    ),
                    hint,
                ),
            ]
            http = _child_scope(_one(scope, "http_options", "httpOptions"), "http_options")
            if http is not None:
                children.append(
                    (
                        _child_scope(_one(http, "extra_body", "extraBody"), "http_options.extra_body"),
                        hint or "gemini",
                    )
                )
            nxt.extend((child, child_hint) for child, child_hint in children if child is not None)
        if nxt and depth >= SCOPE_MAX_DEPTH:
            raise TypeError(
                f"hosted-tool request scopes nest deeper than {SCOPE_MAX_DEPTH} levels"
            )
        out.extend(nxt)
        frontier = nxt
        depth += 1
    return out


def normalize_hosted_request(request: Any, provider: Optional[str] = None) -> List[HostedTool]:
    """The provider-hosted tools a whole model request enables.

    ``request`` is the mapping (or pydantic model) the plugin is about to
    send. Read from it and from every passthrough scope in it (``config``,
    whose entries are read as Gemini; ``extra_body``;
    ``additionalModelRequestFields``; ``http_options.extra_body``):
    ``tools``, ``toolConfig.tools`` (Bedrock Converse), and the
    request-level fields:

    - ``web_search_options`` (OpenAI Chat Completions): ``web_search``;
    - ``prompt`` that is not a string (an OpenAI Responses stored prompt, which can
      carry its own tools): ``stored_prompt``, refused unless a policy
      allows ``Tool::"stored_prompt"``;
    - ``mcp_servers`` (Anthropic): one ``mcp`` tool per server entry;
    - ``cached_content`` / ``cachedContent`` (Gemini, which can carry
      tools): ``cached_content``, refused unless a policy allows
      ``Tool::"cached_content"``;
    - ``search_parameters`` (xAI Live Search): ``live_search``;
    - ``container`` (Anthropic): one ``skill`` per ``container.skills``
      entry, decided per skill id; a container that is neither a plain-token
      id nor ``{id, skills}`` of well-formed skills raises ``TypeError``.

    Raises ``TypeError`` when ``request`` is not a mapping or pydantic
    model, or looks like a single tool (a top-level string ``type``): a
    tools list or tool passed by mistake would otherwise read as no tools.
    Also raises ``TypeError`` when a scope carries two spellings of one key
    it reads (``extra_body`` and ``extraBody``, ``http_options`` and
    ``httpOptions``, ``toolConfig`` and ``tool_config``,
    ``additionalModelRequestFields`` and ``additional_model_request_fields``,
    ``cached_content`` and ``cachedContent``), when a passthrough scope or ``toolConfig`` is
    present but not a mapping or pydantic model (another object, a list or
    a string), or when scopes nest deeper than :data:`SCOPE_MAX_DEPTH`.
    Unlike the TypeScript lane, which reads plain objects only, a pydantic
    model is read field by field, because the Python SDKs' request types
    (``google.genai.types.GenerateContentConfig``, for one) are pydantic
    models.
    """
    _check_provider(provider)
    if not _is_scope(request):
        raise TypeError(
            "normalize_hosted_request() needs the request mapping (or pydantic model), not its tools"
        )
    if isinstance(_get(request, "type"), str):
        raise TypeError("normalize_hosted_request() got a tool, not a request")
    found: List[HostedTool] = []
    extras: List[HostedTool] = []
    for scope, hint in _scopes(request, provider):
        found.extend(_normalize_entries(_entries(_get(scope, "tools")), hint))
        tool_config = _child_scope(_one(scope, "toolConfig", "tool_config"), "toolConfig")
        if tool_config is not None:
            found.extend(_normalize_entries(_entries(_get(tool_config, "tools")), hint))
        if _get(scope, "web_search_options") is not None:
            extras.append(_tool(hint or "openai", "web_search", "web_search_options"))
        prompt = _get(scope, "prompt")
        if prompt is not None and not isinstance(prompt, str):
            extras.append(_tool(hint or "openai", "stored_prompt", "prompt"))
        servers = _get(scope, "mcp_servers")
        if servers is not None:
            for server in _entries(servers):
                extras.append(_from_mcp_server_entry(server, hint, "mcp_servers"))
        if _one(scope, "cached_content", "cachedContent") is not None:
            extras.append(_tool(hint or "gemini", "cached_content", "cached_content"))
        if _get(scope, "search_parameters") is not None:
            extras.append(_tool(hint or "xai", "live_search", "search_parameters"))
        container = _get(scope, "container")
        if container is not None:
            extras.extend(_container_skills(container, hint))
    return _dedupe(found + extras)


# ─── Gate ────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class HostedToolRequest:
    """The ``/authorize`` request for one hosted tool."""

    action: str
    resource: str
    context: Dict[str, Any]

    @property
    def key(self) -> str:
        return json.dumps(
            {"action": self.action, "resource": self.resource, "context": self.context},
            sort_keys=True,
        )


def _registered_servers(registered: Optional[Mapping[str, str]]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for url, name in (registered or {}).items():
        key = _registry_key(url)
        if key is None:
            raise _contract_error("a registered MCP server URL is not an accepted URL")
        if not isinstance(name, str) or not _SERVER_NAME.fullmatch(name):
            raise _contract_error("a registered MCP server name is not a plain name")
        if key in out:
            raise _contract_error("two registered MCP server URLs name the same server")
        out[key] = name
    return out


def hosted_tool_identity(
    tool: HostedTool, registered_mcp_servers: Optional[Mapping[str, str]] = None
) -> Tuple[str, str, Optional[str]]:
    """``(provider, kind, server)``: what one decision covers. ``server`` is
    the registered name of a remote MCP server (``None`` otherwise, or
    when the server is not registered)."""
    server = None
    if tool.kind == "mcp":
        server = _registered_servers(registered_mcp_servers).get(tool._server_url or "")
    return tool.provider, tool.kind, server


def hosted_tool_request(
    tool: HostedTool,
    *,
    registered_mcp_servers: Optional[Mapping[str, str]] = None,
    action_map: Optional[Mapping[str, str]] = None,
) -> Optional[HostedToolRequest]:
    """The ``/authorize`` request for ``tool``, or ``None`` for a remote MCP
    server that is not registered.

    ``Action`` is :func:`resolve_action` of the kind; the resource is
    ``Tool::"<kind>"``, or ``Resource::"mcp://<server>/"`` for remote MCP,
    where ``<server>`` is the operator's name for the server
    (``registered_mcp_servers`` maps server URL to that name; the label the
    model call gives a server is never trusted as its name). The context is
    ``{builtin_tool: true, hosted_tool: {provider, kind}}``, plus ``server``
    and ``allowed_tools`` for MCP, ``vector_store_ids`` for ``file_search``,
    and ``skill_type`` and ``skill_id`` for a skill. The run handle adds ``tenant_id`` and,
    where the run has one, ``run_handle_id``.
    """
    hosted: Dict[str, Any] = {"provider": tool.provider, "kind": tool.kind}
    action = f'Action::"{resolve_action(tool.kind, action_map)}"'
    if tool.kind == "mcp":
        name = _registered_servers(registered_mcp_servers).get(tool._server_url or "")
        if name is None:
            return None
        hosted["server"] = name
        if tool.allowed_tools is not None:
            hosted["allowed_tools"] = list(tool.allowed_tools)
        resource = f'Resource::"mcp://{name}/"'
    else:
        resource = f'Tool::"{tool.kind}"'
        if tool.vector_store_ids is not None:
            hosted["vector_store_ids"] = list(tool.vector_store_ids)
        if tool.skill_id is not None:
            hosted["skill_type"] = tool.name
            hosted["skill_id"] = tool.skill_id
    return HostedToolRequest(action, resource, {"builtin_tool": True, "hosted_tool": hosted})


class HostedToolTurn:
    """The decisions of one model call (one turn).

    Create one per model call and pass it to every gate call for that model
    call (for example a first check and a final re-check after later
    callbacks changed the request): a hosted tool already allowed in this
    turn is not asked again. Call :meth:`seal` once the model call is made;
    a sealed turn refuses further use. A turn is bound to the first handle
    it is used with.
    """

    __slots__ = ("_allowed", "_handle", "_sealed")

    def __init__(self) -> None:
        self._allowed: set = set()
        self._handle: Any = None
        self._sealed = False

    @property
    def allowed_keys(self) -> frozenset:
        return frozenset(self._allowed)

    @property
    def sealed(self) -> bool:
        return self._sealed

    def seal(self) -> None:
        """End the turn: its allows can never be reused."""
        self._sealed = True
        self._allowed.clear()


@dataclass(frozen=True)
class HostedToolGateResult:
    """The outcome of a gate call.

    ``allowed`` is ``True`` only when every hosted tool on the call was
    allowed. Otherwise ``result`` is the refusal (a deny, or
    ``needs_approval`` with its approval request id, which is a bearer
    secret: never log it) and ``refused_tool`` the tool it refused; the
    caller must not call the model. Testing the result itself for truth
    raises ``TypeError``: test ``allowed``.
    """

    result: AuthorizeResult
    refused_tool: Optional[HostedTool] = None
    tools: Tuple[HostedTool, ...] = field(default_factory=tuple)

    @property
    def allowed(self) -> bool:
        return self.refused_tool is None and self.result.is_allow()

    def __bool__(self) -> bool:
        raise TypeError(
            "a HostedToolGateResult has no truth value; test .allowed, or use "
            "require_hosted_request_allowed()"
        )


class HostedToolRefused(WatchlightError):
    """A provider-hosted tool on a model call was refused: the model call
    must not be made. ``gate`` is the :class:`HostedToolGateResult`
    (``gate.result`` carries a ``needs_approval`` id when approval is
    required; never log it). The message names the tool's kind only."""

    def __init__(self, gate: HostedToolGateResult) -> None:
        self.gate = gate
        kind = gate.refused_tool.kind if gate.refused_tool is not None else "unknown"
        super().__init__(
            f"Watchlight refused the provider-hosted tool '{kind}'; the model call was not made"
        )


def _run_ending_errors() -> Tuple[Type[BaseException], ...]:
    from .decision import (
        AgentQuarantinedError,
        AgentRevokedError,
        ExecutionTerminatedError,
        SubtreeSeveredError,
    )
    from .errors import WatchlightContractError

    return (
        AgentQuarantinedError,
        AgentRevokedError,
        ExecutionTerminatedError,
        SubtreeSeveredError,
        WatchlightContractError,
    )


def _contract_error(message: str) -> Exception:
    from .errors import WatchlightContractError

    return WatchlightContractError(message)


async def _gate(
    handle: Any,
    hosted: Tuple[HostedTool, ...],
    turn: HostedToolTurn,
    *,
    registered_mcp_servers: Optional[Mapping[str, str]],
    action_map: Optional[Mapping[str, str]],
    timeout_seconds: Optional[float],
) -> HostedToolGateResult:
    if not isinstance(turn, HostedToolTurn):
        raise _contract_error("the hosted-tool gate needs a HostedToolTurn")
    if turn._sealed:
        raise _contract_error("this HostedToolTurn is sealed; create one per model call")
    if turn._handle is None:
        turn._handle = handle
    elif turn._handle is not handle:
        raise _contract_error("a HostedToolTurn is bound to one run handle; create one per model call")
    # A misconfigured registry refuses every call, not only one with MCP.
    _registered_servers(registered_mcp_servers)

    requests: List[Tuple[HostedTool, HostedToolRequest]] = []
    for tool in hosted:
        if tool.problem is not None:
            return HostedToolGateResult(
                AuthorizeResult("deny", reason=HOSTED_TOOL_CONFIG_INVALID), tool, hosted
            )
        request = hosted_tool_request(
            tool, registered_mcp_servers=registered_mcp_servers, action_map=action_map
        )
        if request is None:
            return HostedToolGateResult(
                AuthorizeResult("deny", reason=HOSTED_MCP_SERVER_UNREGISTERED), tool, hosted
            )
        requests.append((tool, request))

    run_ending = _run_ending_errors()
    for tool, request in requests:
        key = request.key
        if key in turn._allowed:
            continue
        try:
            call = handle.authorize_action_detailed(
                request.action, request.resource, context=request.context
            )
            if timeout_seconds is None:
                result = await call
            else:
                result = await asyncio.wait_for(call, timeout_seconds)
        except asyncio.CancelledError:
            raise
        except run_ending:
            raise
        except asyncio.TimeoutError:
            result = AuthorizeResult("deny", reason=HOSTED_TOOL_REFUSED_TIMEOUT)
        except Exception:  # noqa: BLE001 - fail closed: an error refuses the call
            result = AuthorizeResult("deny", reason=HOSTED_TOOL_REFUSED_UNAVAILABLE)
        if not isinstance(result, AuthorizeResult):
            result = AuthorizeResult("deny", reason=HOSTED_TOOL_REFUSED_UNAVAILABLE)
        if not result.is_allow():
            return HostedToolGateResult(result, tool, hosted)
        turn._allowed.add(key)
    return HostedToolGateResult(AuthorizeResult("allow", reason=""), None, hosted)


async def authorize_hosted_tools(
    handle: Any,
    tools: Any,
    turn: HostedToolTurn,
    *,
    provider: Optional[str] = None,
    registered_mcp_servers: Optional[Mapping[str, str]] = None,
    action_map: Optional[Mapping[str, str]] = None,
    timeout_seconds: Optional[float] = DEFAULT_TIMEOUT_SECONDS,
) -> HostedToolGateResult:
    """Authorize every provider-hosted tool in a ``tools`` list.

    This reads a tools list only and misses request-level hosted tools; use
    :func:`require_hosted_request_allowed` for a full request. Same rules
    as :func:`authorize_hosted_request`.
    """
    hosted = tuple(normalize_hosted_tools(tools, provider))
    return await _gate(
        handle,
        hosted,
        turn,
        registered_mcp_servers=registered_mcp_servers,
        action_map=action_map,
        timeout_seconds=timeout_seconds,
    )


async def authorize_hosted_request(
    handle: Any,
    request: Any,
    turn: HostedToolTurn,
    *,
    provider: Optional[str] = None,
    registered_mcp_servers: Optional[Mapping[str, str]] = None,
    action_map: Optional[Mapping[str, str]] = None,
    timeout_seconds: Optional[float] = DEFAULT_TIMEOUT_SECONDS,
) -> HostedToolGateResult:
    """Authorize every provider-hosted tool a model request enables, before
    the call (see :func:`normalize_hosted_request` for what is read).

    One decision per distinct hosted tool through
    ``handle.authorize_action_detailed`` (see :func:`hosted_tool_request`),
    in call order, stopping at the first refusal. When ``allowed`` is
    ``False`` the caller must not call the model. A refusal is: a Deny, a
    ``needs_approval``, an invalid tool configuration (refused before any
    decision), a remote MCP server not in ``registered_mcp_servers``
    (refused before any decision), an error from the backend, or no answer
    within ``timeout_seconds``. A run-ending decision (quarantine,
    terminate, sever, revoke) raises its typed error. The gate never
    removes a tool from the call to make it pass.
    """
    hosted = tuple(normalize_hosted_request(request, provider))
    return await _gate(
        handle,
        hosted,
        turn,
        registered_mcp_servers=registered_mcp_servers,
        action_map=action_map,
        timeout_seconds=timeout_seconds,
    )


async def require_hosted_request_allowed(
    handle: Any,
    request: Any,
    turn: HostedToolTurn,
    *,
    provider: Optional[str] = None,
    registered_mcp_servers: Optional[Mapping[str, str]] = None,
    action_map: Optional[Mapping[str, str]] = None,
    timeout_seconds: Optional[float] = DEFAULT_TIMEOUT_SECONDS,
) -> HostedToolGateResult:
    """The documented wiring: :func:`authorize_hosted_request`, raising
    :class:`HostedToolRefused` (carrying the result) on any refusal.
    Returns the allowed result."""
    gate = await authorize_hosted_request(
        handle,
        request,
        turn,
        provider=provider,
        registered_mcp_servers=registered_mcp_servers,
        action_map=action_map,
        timeout_seconds=timeout_seconds,
    )
    if not gate.allowed:
        raise HostedToolRefused(gate)
    return gate


_logger = logging.getLogger("watchlight_core.hosted_tools")


def _refused(hosted: Tuple[HostedTool, ...], reason: str, why: str) -> HostedToolRefused:
    _logger.warning("hosted-tool gate (blocking): %s; the model call is refused", why)
    tool = hosted[0] if hosted else None
    return HostedToolRefused(HostedToolGateResult(AuthorizeResult("deny", reason=reason), tool, hosted))


def _io_loop_of(handle: Any) -> Tuple[Optional[asyncio.AbstractEventLoop], bool]:
    """The backend's own I/O loop, when it has one (the Enterprise
    ``SidecarBackend``), and whether the caller is on that loop's thread."""
    backend = getattr(getattr(handle, "_plugin", None), "apdp", None)
    io = getattr(backend, "_io", None)
    if io is None or not callable(getattr(io, "loop", None)):
        return None, False
    if getattr(backend, "_forked", False):
        return None, False
    in_thread = getattr(io, "in_loop_thread", None)
    return io.loop(), bool(callable(in_thread) and in_thread())


def _caller_loop() -> Optional[asyncio.AbstractEventLoop]:
    try:
        return asyncio.get_running_loop()
    except RuntimeError:
        return None


def require_hosted_request_allowed_blocking(
    handle: Any,
    request: Any,
    turn: HostedToolTurn,
    *,
    run_loop: Optional[asyncio.AbstractEventLoop] = None,
    provider: Optional[str] = None,
    registered_mcp_servers: Optional[Mapping[str, str]] = None,
    action_map: Optional[Mapping[str, str]] = None,
    timeout_seconds: Optional[float] = DEFAULT_TIMEOUT_SECONDS,
) -> HostedToolGateResult:
    """:func:`require_hosted_request_allowed` for a synchronous model call:
    the same decisions, made on an event loop on another thread while the
    calling thread waits. Raises :class:`HostedToolRefused` on any
    refusal; returns the allowed result.

    A request that enables no hosted tool passes without any loop. Otherwise
    the decisions run, in this order of preference:

    1. on the backend's own I/O-loop thread, when it has one (the
       Enterprise sidecar backend): it is never the caller's loop, so the
       wait cannot deadlock;
    2. on ``run_loop`` (the loop the run was opened on), when it is running
       on another thread.

    Otherwise the call is refused: there is no such loop, the caller is on
    that loop's thread (waiting there would deadlock), the loop is closed
    or stopping, or no answer came within the timeout. ``timeout_seconds``
    applies to each decision, and bounds the whole wait (``None`` means the
    default). Python only: the TypeScript SDK has no synchronous model call.

    Any other error (a misused turn, an unreadable request, a failure inside
    the gate) is a refusal too, so a caller that catches ``Exception`` can
    never send the call by mistake; a run-ending decision (quarantine,
    terminate, sever, revoke) raises its own typed error. Every refusal
    seals ``turn``, so a decision that lands after the wait gave up can
    never be reused.
    """
    from .errors import WatchlightContractError

    run_ending = tuple(e for e in _run_ending_errors() if e is not WatchlightContractError)
    try:
        return _decide_blocking(
            handle,
            request,
            turn,
            run_loop=run_loop,
            provider=provider,
            registered_mcp_servers=registered_mcp_servers,
            action_map=action_map,
            timeout_seconds=timeout_seconds,
        )
    except (HostedToolRefused, *run_ending):
        _seal(turn)
        raise
    except Exception:  # noqa: BLE001 - fail closed: any error refuses the call
        _seal(turn)
        raise _refused((), HOSTED_TOOL_REFUSED_UNAVAILABLE, "the gate failed") from None


def _seal(turn: Any) -> None:
    if isinstance(turn, HostedToolTurn):
        turn.seal()


def _decide_blocking(
    handle: Any,
    request: Any,
    turn: HostedToolTurn,
    *,
    run_loop: Optional[asyncio.AbstractEventLoop],
    provider: Optional[str],
    registered_mcp_servers: Optional[Mapping[str, str]],
    action_map: Optional[Mapping[str, str]],
    timeout_seconds: Optional[float],
) -> HostedToolGateResult:
    hosted = tuple(normalize_hosted_request(request, provider))
    if not hosted:
        _registered_servers(registered_mcp_servers)
        return HostedToolGateResult(AuthorizeResult("allow", reason=""), None, hosted)
    per_call = DEFAULT_TIMEOUT_SECONDS if timeout_seconds is None else timeout_seconds
    caller = _caller_loop()

    loop, on_io_thread = _io_loop_of(handle)
    if loop is None or loop.is_closed():
        loop = None
        if run_loop is not None and not run_loop.is_closed() and run_loop.is_running():
            if run_loop is caller:
                raise _refused(hosted, HOSTED_TOOL_REFUSED_UNAVAILABLE, "called on the run's own loop thread")
            loop = run_loop
    elif on_io_thread or loop is caller:
        raise _refused(hosted, HOSTED_TOOL_REFUSED_UNAVAILABLE, "called on the backend's I/O thread")
    if loop is None:
        raise _refused(hosted, HOSTED_TOOL_REFUSED_UNAVAILABLE, "no event loop on another thread to decide on")

    gate = _gate(
        handle,
        hosted,
        turn,
        registered_mcp_servers=registered_mcp_servers,
        action_map=action_map,
        timeout_seconds=per_call,
    )
    try:
        future = asyncio.run_coroutine_threadsafe(gate, loop)
    except RuntimeError:  # the loop closed between the check and the submit
        gate.close()
        raise _refused(hosted, HOSTED_TOOL_REFUSED_UNAVAILABLE, "the event loop is closed") from None
    try:
        result = future.result(timeout=per_call * len(hosted) + 1.0)
    except concurrent.futures.TimeoutError:
        future.cancel()
        raise _refused(hosted, HOSTED_TOOL_REFUSED_TIMEOUT, "no decision within the timeout") from None
    except concurrent.futures.CancelledError:
        raise _refused(hosted, HOSTED_TOOL_REFUSED_UNAVAILABLE, "the event loop stopped") from None
    if not result.allowed:
        raise HostedToolRefused(result)
    return result


# ─── Lineage ─────────────────────────────────────────────────────────


def hosted_tool_observation(
    tool: HostedTool,
    *,
    framework: str,
    decision: Optional[str] = None,
    action_map: Optional[Mapping[str, str]] = None,
) -> Dict[str, Any]:
    """A value-free ``tool_call_observed`` payload for a hosted tool
    invocation seen in a model response.

    ``framework`` is the plugin's URI namespace (``langgraph``,
    ``pydantic_ai``, ...): the endpoint is
    ``<framework>://hosted/<provider>/<kind>``. ``input_summary`` is the
    tool's value-free summary (an MCP server appears by host, never by URL
    path). Publish it with ``extra_metadata=HOSTED_TOOL_METADATA`` (or use
    :func:`publish_hosted_tool_observed`).
    """
    if not isinstance(framework, str) or not _FRAMEWORK.fullmatch(framework):
        raise ValueError("framework must be a lowercase URI scheme name")
    payload: Dict[str, Any] = {
        "tool": {
            "resource_type": "hosted_tool",
            "identifier": tool.kind,
            "endpoint": f"{framework}://hosted/{tool.provider}/{tool.kind}",
        },
        "action": {"action": resolve_action(tool.kind, action_map)},
        "input_summary": tool.summary[:SUMMARY_MAX_CHARS],
    }
    if decision is not None:
        payload["decision"] = decision
    return payload


async def publish_hosted_tool_observed(
    handle: Any,
    tool: HostedTool,
    *,
    framework: str,
    decision: Optional[str] = None,
    action_map: Optional[Mapping[str, str]] = None,
) -> None:
    """Publish :func:`hosted_tool_observation` for ``tool`` through the run
    handle's signed publish path, with ``metadata.hosted_tool = true``."""
    await handle.publish_observation(
        "tool_call_observed",
        hosted_tool_observation(
            tool, framework=framework, decision=decision, action_map=action_map
        ),
        extra_metadata=dict(HOSTED_TOOL_METADATA),
    )
