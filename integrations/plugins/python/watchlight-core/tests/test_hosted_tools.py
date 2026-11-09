"""Provider-hosted tools: the normalizer, the per-model-call gate, the
lineage builder and conformance invariant 19.

The shared fixture ``fixtures/hosted_tool_shapes.json`` is checked here and
by the TypeScript SDK's ``tests/hosted-tools.test.ts``, so both SDKs read
every shape and build every request identically.
"""

from __future__ import annotations

import asyncio
import copy
import dataclasses
import json
import pickle
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    computed_field,
    field_serializer,
    model_serializer,
)
from pydantic.fields import FieldInfo

from watchlight_core import (
    AgentQuarantinedError,
    AuthorizeResult,
    BaseRunHandle,
    HOSTED_MCP_SERVER_UNREGISTERED,
    HOSTED_TOOL_CONFIG_INVALID,
    HOSTED_TOOL_REFUSED_TIMEOUT,
    HOSTED_TOOL_REFUSED_UNAVAILABLE,
    HostedTool,
    HostedToolGateResult,
    HostedToolRefused,
    HostedToolTurn,
    WatchlightContractError,
    authorize_hosted_request,
    authorize_hosted_tools,
    hosted_tool_identity,
    hosted_tool_observation,
    normalize_hosted_request,
    normalize_hosted_tools,
    normalize_mcp_server_url,
    publish_hosted_tool_observed,
    require_hosted_request_allowed,
    resolve_action,
)
from watchlight_core_testing.conformance import (
    HOSTED_TOOL_PENDING,
    HOSTED_TOOL_PENDING_CORE_VERSION,
    HOSTED_TOOL_PLUGINS_PENDING,
    HOSTED_TOOL_PLUGINS_REQUIRED,
    HOSTED_TOOLS_AUTHORIZED_INVARIANT_NUMBER,
    INVARIANTS,
    HostedToolConformanceProbe,
    RecordingModelClient,
    check_hosted_tool_gate_wired,
    check_required_hosted_tool_plugin,
    check_hosted_tools_authorized_before_model_call,
)
from watchlight_core.events_schema import ToolCallObservedPayload
from watchlight_core.hosted_tools import hosted_tool_request
from watchlight_core.telemetry import GovernanceTelemetry
from watchlight_core_testing import (
    ConformanceFailure,
    MockApdpClient,
    assert_canonical_event,
)

FIXTURE = json.loads(
    (Path(__file__).parent / "fixtures" / "hosted_tool_shapes.json").read_text()
)

#: Values the fixture's tool configs carry that no summary may repeat.
SECRETS = ("secret", "sk-", "tok-", "token=abc", "frag", "user:", "Bearer", "col_1", "vs_1")


# ─── Stand-ins ───────────────────────────────────────────────────────


class StandInHandle:
    """Records each authorize request and answers from ``answers``
    (resource → AuthorizeResult, exception, or awaitable factory)."""

    def __init__(self, answers: Optional[Dict[str, Any]] = None) -> None:
        self.answers = answers or {}
        self.calls: List[Dict[str, Any]] = []
        self.published: List[Dict[str, Any]] = []

    async def authorize_action_detailed(
        self, action: str, resource: str, context: Optional[Dict[str, Any]] = None, **_: Any
    ) -> Any:
        self.calls.append({"action": action, "resource": resource, "context": context})
        answer = self.answers.get(resource, AuthorizeResult("allow"))
        if callable(answer):
            return await answer()
        if isinstance(answer, BaseException):
            raise answer
        return answer

    async def publish_observation(self, event_type: str, payload: Dict[str, Any], **kw: Any) -> None:
        self.published.append({"event_type": event_type, "payload": payload, **kw})


# ─── Normalizer: shared fixture ──────────────────────────────────────


@pytest.mark.parametrize("case", FIXTURE["normalize"], ids=lambda c: c["name"])
def test_normalizer_matches_the_shared_fixture(case: Dict[str, Any]) -> None:
    got = [
        dict(t.to_dict(), action=resolve_action(t.kind))
        for t in normalize_hosted_tools(case["tools"], case["provider"])
    ]
    assert got == case["expected"]


@pytest.mark.parametrize("case", FIXTURE["requests"], ids=lambda c: c["name"])
def test_request_normalizer_matches_the_shared_fixture(case: Dict[str, Any]) -> None:
    got = [
        dict(t.to_dict(), action=resolve_action(t.kind))
        for t in normalize_hosted_request(case["request"], case["provider"])
    ]
    assert got == case["expected"]


def _value_free_view(tools: List[HostedTool]) -> str:
    # The full server URL is private to the HostedTool (the gate matches it
    # against the registry); every public field and summary is value-free.
    return json.dumps([t.to_dict() for t in tools])


@pytest.mark.parametrize(
    "case",
    [dict(c, kind="tools") for c in FIXTURE["normalize"]]
    + [dict(c, kind="request") for c in FIXTURE["requests"]],
    ids=lambda c: f'{c["kind"]}-{c["name"]}',
)
def test_summaries_are_value_free(case: Dict[str, Any]) -> None:
    if case["kind"] == "request":
        got = normalize_hosted_request(case["request"], case["provider"])
    else:
        got = normalize_hosted_tools(case["tools"], case["provider"])
    text = _value_free_view(got)
    for secret in SECRETS:
        assert secret not in text, secret
    for t in got:
        assert len(t.summary) <= 120
        assert "/mcp" not in t.summary and "/sse" not in t.summary


@pytest.mark.parametrize("case", FIXTURE["mcp_urls"], ids=lambda c: repr(c["url"]))
def test_mcp_urls_match_the_shared_fixture(case: Dict[str, Any]) -> None:
    assert normalize_mcp_server_url(case["url"]) == case["expected"]


@pytest.mark.asyncio
@pytest.mark.parametrize("registry", FIXTURE["registry_refused"])
async def test_refused_registries_match_the_shared_fixture(registry: Dict[str, str]) -> None:
    with pytest.raises(WatchlightContractError):
        await authorize_hosted_tools(StandInHandle(), [{"type": "web_search"}], HostedToolTurn(),
                                     registered_mcp_servers=registry)


@pytest.mark.asyncio
@pytest.mark.parametrize("case", FIXTURE["gate"], ids=lambda c: c["name"])
async def test_gate_matches_the_shared_fixture(case: Dict[str, Any]) -> None:
    handle = StandInHandle()
    if "request" in case:
        gate = await authorize_hosted_request(
            handle,
            case["request"],
            HostedToolTurn(),
            provider=case["provider"],
            registered_mcp_servers=case["registered_mcp_servers"],
        )
    else:
        gate = await authorize_hosted_tools(
            handle,
            case["tools"],
            HostedToolTurn(),
            provider=case["provider"],
            registered_mcp_servers=case["registered_mcp_servers"],
        )
    assert handle.calls == case["expected_requests"]
    assert gate.allowed is case["expected_allowed"]
    assert gate.result.reason == case["expected_reason"]
    assert (gate.refused_tool.kind if gate.refused_tool else None) == case["expected_refused_kind"]


@pytest.mark.parametrize("wrong", FIXTURE["requests_refused"], ids=repr)
def test_requests_refused_match_the_shared_fixture(wrong: Any) -> None:
    with pytest.raises(TypeError):
        normalize_hosted_request(wrong)


def test_a_class_or_a_set_is_not_a_request() -> None:
    for wrong in (dict, {"tools"}, b"x"):
        with pytest.raises(TypeError):
            normalize_hosted_request(wrong)


def test_a_config_scope_is_read_as_gemini() -> None:
    def lookup_weather() -> None:  # pragma: no cover - never called
        return None

    got = normalize_hosted_request({"config": {"tools": [lookup_weather]}})
    assert [(t.provider, t.kind) for t in got] == [("gemini", "callable:lookup_weather")]
    # At the top level, with no hint, a function is left to the tool hook.
    assert normalize_hosted_request({"tools": [lookup_weather]}) == []


def test_the_full_server_url_is_private() -> None:
    (t,) = normalize_hosted_tools(
        [{"type": "mcp", "server_url": "https://mcp.example.com/api/mcp/s/sk-secret-path-token/mcp"}]
    )
    assert t.server_origin == "https://mcp.example.com"
    assert "sk-secret" not in json.dumps(t.to_dict()) and "sk-secret" not in repr(t)
    # Two servers on one host with different paths stay two tools.
    two = normalize_hosted_tools(
        [{"type": "mcp", "server_url": "https://h.example/a"}, {"type": "mcp", "server_url": "https://h.example/b"}]
    )
    assert len(two) == 2


class _Box:
    """A plain class instance carrying a mapping's keys as attributes."""

    def __init__(self, values: Dict[str, Any]) -> None:
        self.__dict__.update(values)


def _as_instance(request: Dict[str, Any], path: List[str]) -> Any:
    if not path:
        return _Box(request)
    out = copy.deepcopy(request)
    parent = out
    for key in path[:-1]:
        parent = parent[key]
    parent[path[-1]] = _Box(parent[path[-1]])
    return out


@pytest.mark.parametrize(
    "case", FIXTURE["requests_refused_as_instance"], ids=lambda c: "/".join(c["path"]) or "request"
)
def test_class_instance_scopes_are_refused_like_the_shared_fixture(case: Dict[str, Any]) -> None:
    with pytest.raises(TypeError):
        normalize_hosted_request(_as_instance(case["request"], case["path"]))


class _HidingDict(dict):
    """A dict subclass that hides one key from iteration and membership.
    ``json.dumps`` still sends the key: it reads ``items()``."""

    hidden: Optional[str] = None

    def __iter__(self) -> Any:
        return (k for k in dict.__iter__(self) if k != self.hidden)

    def __contains__(self, key: object) -> bool:
        return key != self.hidden and dict.__contains__(self, key)

    def get(self, key: Any, default: Any = None) -> Any:
        return default if key == self.hidden else dict.get(self, key, default)


class _HidingMapping(Mapping):
    """A custom mapping whose iteration leaves one key out."""

    def __init__(self, data: Dict[str, Any], hidden: str) -> None:
        self._data = dict(data)
        self._hidden = hidden

    def __getitem__(self, key: str) -> Any:
        return self._data[key]

    def __iter__(self) -> Any:
        return (k for k in self._data if k != self._hidden)

    def __len__(self) -> int:
        return len(self._data) - 1


class _HidingList(list):
    """A list subclass whose iteration is empty; ``json.dumps`` reads its
    items directly."""

    def __iter__(self) -> Any:
        return iter(())


class _Tuple(tuple):
    pass


def _hiding_variants(container: Any, key: Optional[str]) -> List[Any]:
    """Each way this language lets a reader miss what a serializer sends:
    the TypeScript test plants its own (non-enumerable, accessor and
    symbol keys, an own iterator, an array subclass)."""
    if key is None:
        return [_HidingList(container), _Tuple(container)]
    hiding = _HidingDict(container)
    hiding.hidden = key
    return [hiding, _HidingMapping(container, key), {**container, 1: "not a string key"}]


def _planted(request: Dict[str, Any], path: List[str], value: Any) -> Any:
    if not path:
        return value
    out = copy.deepcopy(request)
    parent: Any = out
    for key in path[:-1]:
        parent = parent[int(key)] if isinstance(parent, list) else parent[key]
    last = path[-1]
    if isinstance(parent, list):
        parent[int(last)] = value
    else:
        parent[last] = value
    return out


def _at(request: Dict[str, Any], path: List[str]) -> Any:
    value: Any = request
    for key in path:
        value = value[int(key)] if isinstance(value, list) else value[key]
    return value


@pytest.mark.parametrize("case", FIXTURE["requests_refused_hidden"], ids=lambda c: c["name"])
def test_hidden_keys_are_refused_like_the_shared_fixture(case: Dict[str, Any]) -> None:
    container = _at(case["request"], case["path"])
    for variant in _hiding_variants(container, case["key"]):
        with pytest.raises(TypeError):
            normalize_hosted_request(_planted(case["request"], case["path"], variant))


def _callable_variant(container: Any, key: Optional[str], variant: str) -> Any:
    base = copy.deepcopy(container)
    if variant == "function_value":
        hosted = base[key]
        return {**base, key: lambda: hosted}
    hosted = base.pop(key)
    return {**base, "toJSON": lambda: {**base, key: hosted}}


@pytest.mark.parametrize(
    "case",
    [c for c in FIXTURE["requests_refused_callable"] if not c.get("ts_only")],
    ids=lambda c: c["name"],
)
def test_a_callable_value_is_refused_like_the_shared_fixture(case: Dict[str, Any]) -> None:
    container = _at(case["request"], case["path"])
    variant = _callable_variant(container, case["key"], case["variant"])
    with pytest.raises(TypeError):
        normalize_hosted_request(_planted(case["request"], case["path"], variant))


def test_a_hiding_dict_shows_the_serializer_what_it_hides_from_the_gate() -> None:
    """Why a dict subclass is refused: the provider SDK's JSON body carries
    the hosted tool that iteration leaves out."""
    hiding = _HidingDict({"type": "function", "name": "f", "googleSearch": {}})
    hiding.hidden = "googleSearch"
    assert "googleSearch" not in list(hiding)
    assert "googleSearch" in json.loads(json.dumps(hiding))
    with pytest.raises(TypeError):
        normalize_hosted_tools([hiding])


def _unprovable_config_models() -> List[Any]:
    """Python only: model scopes whose serialized form the gate cannot
    prove from ``__dict__``. Each would send ``tools: [{google_search}]``
    (or could) while showing the gate no tools."""
    hosted = [{"google_search": {}}]

    class HidesByGetattribute(BaseModel):
        tools: Optional[List[Dict[str, Any]]] = None

        def __getattribute__(self, name: str) -> Any:
            return None if name == "tools" else super().__getattribute__(name)

    class HasGetattr(BaseModel):
        tools: Optional[List[Dict[str, Any]]] = None

        def __getattr__(self, name: str) -> Any:
            return None

    class ReplacesModelDump(BaseModel):
        notes: Optional[str] = None

        def model_dump(self, **kw: Any) -> Dict[str, Any]:
            return {"tools": hosted}

    class ReplacesModelDumpJson(BaseModel):
        notes: Optional[str] = None

        def model_dump_json(self, **kw: Any) -> str:
            return json.dumps({"tools": hosted})

    class ReplacesSerializer(BaseModel):
        notes: Optional[str] = None

    ReplacesSerializer.__pydantic_serializer__ = object()  # type: ignore[assignment]

    class ModelSerializer(BaseModel):
        notes: Optional[str] = None

        @model_serializer
        def _out(self) -> Dict[str, Any]:
            return {"tools": hosted}

    class FieldSerializer(BaseModel):
        tools: Optional[List[Dict[str, Any]]] = None

        @field_serializer("tools")
        def _tools(self, value: Any) -> Any:
            return hosted

    class ComputedTools(BaseModel):
        notes: Optional[str] = None

        @computed_field  # type: ignore[prop-decorator]
        @property
        def tools(self) -> List[Dict[str, Any]]:
            return hosted

    class AliasedToTools(BaseModel):
        notes: Optional[List[Dict[str, Any]]] = Field(default=None, serialization_alias="tools")

    return [
        HidesByGetattribute(),
        HasGetattr(),
        ReplacesModelDump(),
        ReplacesModelDumpJson(),
        ReplacesSerializer(),
        ModelSerializer(),
        FieldSerializer(),
        ComputedTools(),
        AliasedToTools(notes=hosted),
    ]


@pytest.mark.parametrize("model", _unprovable_config_models(), ids=lambda m: type(m).__name__)
def test_a_model_scope_the_gate_cannot_prove_is_refused(model: Any) -> None:
    with pytest.raises(TypeError):
        normalize_hosted_request({"config": model})
    with pytest.raises(TypeError):
        normalize_hosted_request(model)


def _excluding_config_models() -> List[Any]:
    """Python only: a field pydantic-core never serializes but ``__dict__``
    keeps. An excluded ``allowed_tools`` shows the gate a narrowed scope
    while the provider receives an unscoped server."""
    server = {"type": "mcp", "server_url": "https://mcp.example.com/mcp"}

    class ExcludedScope(BaseModel):
        model_config = ConfigDict(extra="allow")
        allowed_tools: Optional[List[str]] = Field(default=None, exclude=True)

    models: List[Any] = [ExcludedScope(tools=[server], allowed_tools=["read"])]
    if "exclude_if" in getattr(FieldInfo, "__slots__", ()):

        class ExcludedIfScope(BaseModel):
            model_config = ConfigDict(extra="allow")
            allowed_tools: Optional[List[str]] = Field(
                default=None, exclude_if=lambda v: True
            )

        models.append(ExcludedIfScope(tools=[server], allowed_tools=["read"]))
    return models


@pytest.mark.parametrize("model", _excluding_config_models(), ids=lambda m: type(m).__name__)
def test_a_model_with_an_excluded_field_is_refused(model: Any) -> None:
    assert "allowed_tools" not in model.model_dump()
    with pytest.raises(TypeError):
        normalize_hosted_request({"config": model})
    with pytest.raises(TypeError):
        normalize_hosted_request(model)


class _ShowsTheGateOneList:
    """An iterable that yields a function tool on its first pass and a
    hosted tool on every later one (the SDK's)."""

    def __init__(self) -> None:
        self.passes = 0

    def __iter__(self) -> Any:
        self.passes += 1
        if self.passes == 1:
            return iter([{"type": "function", "name": "lookup"}])
        return iter([{"type": "web_search"}])


@pytest.mark.parametrize(
    "tools",
    [_ShowsTheGateOneList, lambda: (t for t in [{"type": "web_search"}]), lambda: {"a": 1}.keys()],
    ids=["re_iterable", "generator", "dict_keys"],
)
def test_a_tool_list_that_is_not_a_list_or_tuple_is_refused(tools: Any) -> None:
    with pytest.raises(TypeError):
        normalize_hosted_request({"tools": tools()}, "openai")
    with pytest.raises(TypeError):
        normalize_hosted_tools(tools(), "openai")


def test_a_model_scope_is_read_from_what_pydantic_serializes() -> None:
    """Declared fields come from ``__dict__`` and extras from
    ``__pydantic_extra__``, so an allowed extra field is gated too."""

    class Config(BaseModel):
        model_config = ConfigDict(extra="allow")
        notes: Optional[str] = None

    got = normalize_hosted_request({"config": Config(tools=[{"google_search": {}}])})
    assert [(t.provider, t.kind) for t in got] == [("gemini", "google_search")]


def test_pydantic_model_scopes_are_read_field_by_field() -> None:
    """Python only: the SDKs' request types are pydantic models."""

    class HttpOptions(BaseModel):
        extra_body: Optional[Dict[str, Any]] = None

    class Config(BaseModel):
        tools: Optional[List[Dict[str, Any]]] = None
        http_options: Optional[HttpOptions] = None

    request = {
        "config": Config(
            tools=[{"google_search": {}}],
            http_options=HttpOptions(extra_body={"tools": [{"url_context": {}}]}),
        )
    }
    got = normalize_hosted_request(request)
    assert [(t.provider, t.kind) for t in got] == [("gemini", "google_search"), ("gemini", "url_context")]
    assert normalize_hosted_request(Config(tools=[{"code_execution": {}}]))[0].kind == "code_execution"


def test_the_full_server_url_is_not_a_dataclass_field() -> None:
    url = "https://mcp.example.com/api/mcp/s/sk-secret-path-token/mcp"
    (t,) = normalize_hosted_tools([{"type": "mcp", "server_url": url}])
    assert t._server_url == "https://mcp.example.com/api/mcp/s/sk-secret-path-token/mcp"
    assert "sk-secret" not in repr(dataclasses.asdict(t))
    assert "sk-secret" not in repr(vars(t))
    assert all(f.name != "_server_url" for f in dataclasses.fields(t))
    # nosemgrep: community.python.lang.security.deserialization.avoid-pickle pickle of a tool this test just built, to prove the secret URL is not serialized
    assert b"sk-secret" not in pickle.dumps(t)
    # A copy carries no URL, so it can only be refused as unregistered.
    # nosemgrep: community.python.lang.security.deserialization.avoid-pickle round-trips a tool this test just built; no outside data
    for other in (copy.copy(t), copy.deepcopy(t), pickle.loads(pickle.dumps(t))):
        assert other._server_url is None and other != t


@pytest.mark.asyncio
async def test_a_reused_id_finds_no_server_url() -> None:
    """The side table is keyed by id(), which can be reused after a tool is
    collected: an entry whose weak reference points at another tool is
    ignored, so the tool is refused as unregistered."""
    import weakref

    from watchlight_core import hosted_tools
    from watchlight_core.hosted_tools import HOSTED_MCP_SERVER_UNREGISTERED

    registry = {"https://mcp.example.com/mcp": "docs"}
    (owner,) = normalize_hosted_tools([{"type": "mcp", "server_url": "https://mcp.example.com/mcp"}])
    (reuser,) = normalize_hosted_tools([{"type": "mcp", "server_url": "https://other.example/mcp"}])
    # Stand in for an id reused after collection: reuser's slot names owner.
    hosted_tools._SERVER_URLS[id(reuser)] = (weakref.ref(owner), "https://mcp.example.com/mcp")
    assert reuser._server_url is None
    handle = StandInHandle()
    gate = await authorize_hosted_tools(handle, [reuser], HostedToolTurn(), registered_mcp_servers=registry)
    assert not gate.allowed and gate.result.reason == HOSTED_MCP_SERVER_UNREGISTERED
    assert handle.calls == []
    # A collected tool leaves no entry behind.
    key = id(owner)
    del owner
    import gc

    gc.collect()
    assert key not in hosted_tools._SERVER_URLS


def test_a_stale_collection_callback_keeps_a_newer_entry() -> None:
    """``_drop_server_url`` removes an entry only when it still holds the
    collected tool's reference: a late callback for a tool whose id was
    reused must not remove the newer tool's URL."""
    import weakref

    from watchlight_core import hosted_tools

    (newer,) = normalize_hosted_tools([{"type": "mcp", "server_url": "https://mcp.example.com/mcp"}])
    (other,) = normalize_hosted_tools([{"type": "web_search"}])
    stale = weakref.ref(other)
    hosted_tools._drop_server_url(id(newer), stale)
    assert newer._server_url == "https://mcp.example.com/mcp"
    # The entry's own reference does remove it.
    hosted_tools._drop_server_url(id(newer), hosted_tools._SERVER_URLS[id(newer)][0])
    assert newer._server_url is None


@pytest.mark.asyncio
async def test_a_copied_mcp_tool_is_refused_as_unregistered() -> None:
    from watchlight_core.hosted_tools import HOSTED_MCP_SERVER_UNREGISTERED

    registry = {"https://mcp.example.com/mcp": "docs"}
    (t,) = normalize_hosted_tools([{"type": "mcp", "server_url": "https://mcp.example.com/mcp"}])
    ok = await authorize_hosted_tools(StandInHandle(), [t], HostedToolTurn(), registered_mcp_servers=registry)
    assert ok.allowed
    handle = StandInHandle()
    # nosemgrep: community.python.lang.security.deserialization.avoid-pickle round-trips a tool this test just built; no outside data
    copied = pickle.loads(pickle.dumps(t))
    gate = await authorize_hosted_tools(handle, [copied], HostedToolTurn(), registered_mcp_servers=registry)
    assert not gate.allowed and gate.result.reason == HOSTED_MCP_SERVER_UNREGISTERED
    assert handle.calls == []


# ─── Normalizer: object shapes (Python only) ─────────────────────────


class GeminiTransport(BaseModel):
    url: Optional[str] = None
    headers: Optional[dict] = None


class GeminiMcpServer(BaseModel):
    name: Optional[str] = None
    streamable_http_transport: Optional[GeminiTransport] = None


class GeminiTool(BaseModel):
    """Stand-in for ``google.genai.types.Tool`` (same field reading)."""

    function_declarations: Optional[list] = None
    google_search: Optional[dict] = None
    code_execution: Optional[dict] = None
    url_context: Optional[dict] = None
    parallel_ai_search: Optional[dict] = None
    mcp_servers: Optional[List[GeminiMcpServer]] = None


def test_gemini_tool_objects_report_every_set_field_but_function_declarations() -> None:
    tools = [
        GeminiTool(function_declarations=[{"name": "f"}]),
        GeminiTool(google_search={}, code_execution={}, parallel_ai_search={}),
    ]
    got = normalize_hosted_tools(tools)
    assert [(t.provider, t.kind, t.name) for t in got] == [
        ("gemini", "google_search", "google_search"),
        ("gemini", "code_execution", "code_execution"),
        ("gemini", "parallel_ai_search", "parallel_ai_search"),
    ]


def test_gemini_mcp_server_objects_read_like_their_dicts() -> None:
    server = {"name": "docs", "streamable_http_transport": {"url": "https://Docs.Example.com:443/mcp/",
                                                            "headers": {"Authorization": "Bearer sk-secret"}}}
    from_object = normalize_hosted_tools([GeminiTool(mcp_servers=[GeminiMcpServer.model_validate(server)])])
    from_dict = normalize_hosted_tools([{"mcp_servers": [server]}])
    assert from_object == from_dict
    (t,) = from_object
    assert (t.kind, t.server_origin, t.server_label) == ("mcp", "https://docs.example.com", "docs")


def test_real_gemini_tool_objects_when_installed() -> None:
    # google-genai is in the python-plugins CI lock, so this runs in CI.
    types = pytest.importorskip("google.genai.types")
    got = normalize_hosted_tools(
        [
            types.Tool(google_search=types.GoogleSearch()),
            types.Tool(function_declarations=[]),
            types.Tool(
                mcp_servers=[
                    types.McpServer(
                        name="docs",
                        streamable_http_transport=types.StreamableHttpTransport(
                            url="https://docs.example.com/mcp", headers={"Authorization": "Bearer sk-secret"}
                        ),
                    )
                ]
            ),
        ]
    )
    assert [(t.kind, t.server_origin) for t in got] == [
        ("google_search", None),
        ("mcp", "https://docs.example.com"),
    ]
    assert "sk-secret" not in _value_free_view(got)
    if "parallel_ai_search" in types.Tool.model_fields:
        got = normalize_hosted_tools(
            [types.Tool.model_validate({"parallel_ai_search": {}})]
        )
        assert [t.kind for t in got] == ["parallel_ai_search"]


def test_a_raw_callable_is_hosted_only_for_gemini() -> None:
    def lookup_weather() -> None:  # pragma: no cover - never called
        return None

    assert [t.kind for t in normalize_hosted_tools([lookup_weather], "gemini")] == [
        "callable:lookup_weather"
    ]
    assert normalize_hosted_tools([lookup_weather]) == []
    assert normalize_hosted_tools([lookup_weather], "openai") == []


@pytest.mark.parametrize("case", FIXTURE["callable_names"], ids=lambda c: repr(c["name"]))
def test_a_gemini_callable_is_named_as_the_shared_fixture_says(case: Dict[str, Any]) -> None:
    def fn() -> None:  # pragma: no cover - never called
        return None

    fn.__name__ = case["name"]
    got = normalize_hosted_tools([fn], "gemini")
    assert [(t.provider, t.kind) for t in got] == [("gemini", case["kind"])]


def test_callable_instances_and_classes_are_reported_not_dropped() -> None:
    class HostedThing:
        def __call__(self) -> None:  # pragma: no cover - never called
            return None

    got = normalize_hosted_tools([HostedThing(), HostedThing])
    assert [(t.provider, t.kind) for t in got] == [("unknown", "HostedThing")]
    assert len(normalize_hosted_tools([HostedThing()])) == 1
    assert len(normalize_hosted_tools([HostedThing])) == 1


class AbstractNativeTool:
    """Stand-in base with Pydantic AI's class name (matched by name)."""


@dataclass
class WebSearchTool(AbstractNativeTool):
    search_context_size: str = "high"
    kind: str = "web_search"


@dataclass
class MCPServerTool(AbstractNativeTool):
    id: str = "deepwiki"
    url: str = "https://mcp.deepwiki.com/mcp?key=secret"
    authorization_token: Optional[str] = "secret-token"
    allowed_tools: Optional[List[str]] = field(default_factory=lambda: ["ask_question"])
    headers: Optional[Dict[str, str]] = field(default_factory=lambda: {"X-Key": "secret"})
    kind: str = "mcp_server"


def _unprovable_native_tools() -> List[Any]:
    """Python only: pydantic-ai native tools whose attribute reads can
    differ from their dataclass fields."""

    class ShadowsScope(MCPServerTool):
        @property
        def allowed_tools(self) -> List[str]:  # type: ignore[override]
            return ["ask_question"]

    shadow = object.__new__(ShadowsScope)
    vars(shadow).update(vars(MCPServerTool(allowed_tools=None)))

    @dataclass
    class HooksGetattribute(MCPServerTool):
        def __getattribute__(self, name: str) -> Any:
            if name == "allowed_tools":
                return ["ask_question"]
            return super().__getattribute__(name)

    @dataclass
    class HooksGetattr(WebSearchTool):
        def __getattr__(self, name: str) -> Any:
            return None

    class NotADataclass(AbstractNativeTool):
        kind = "web_search"

    return [shadow, HooksGetattribute(allowed_tools=None), HooksGetattr(), NotADataclass()]


@pytest.mark.parametrize("tool", _unprovable_native_tools(), ids=lambda t: type(t).__name__)
def test_a_native_tool_the_gate_cannot_read_as_plain_data_is_refused(tool: Any) -> None:
    with pytest.raises(TypeError):
        normalize_hosted_tools([tool])


def test_pydantic_ai_native_tools() -> None:
    got = normalize_hosted_tools([WebSearchTool(), MCPServerTool()])
    assert [(t.provider, t.kind, t.name) for t in got] == [
        ("pydantic_ai", "web_search", "WebSearchTool"),
        ("pydantic_ai", "mcp", "MCPServerTool"),
    ]
    mcp = got[1]
    assert mcp.server_origin == "https://mcp.deepwiki.com"
    assert mcp.server_label == "deepwiki"
    assert mcp.allowed_tools == ("ask_question",)
    assert "secret" not in json.dumps(mcp.to_dict())


def _two_stores() -> List[str]:
    return ["vs_b", "vs_a"]


@dataclass
class FileSearchTool(AbstractNativeTool):
    file_store_ids: Any = field(default_factory=_two_stores)
    kind: str = "file_search"


def test_a_pydantic_ai_file_search_is_decided_with_its_stores() -> None:
    (got,) = normalize_hosted_tools([FileSearchTool()])
    assert (got.provider, got.kind, got.name) == ("pydantic_ai", "file_search", "FileSearchTool")
    assert hosted_tool_request(got).context["hosted_tool"]["vector_store_ids"] == ["vs_a", "vs_b"]
    assert "vs_a" not in json.dumps(got.to_dict()) and "vs_a" not in got.summary
    (bad,) = normalize_hosted_tools([FileSearchTool(file_store_ids="vs_a")])
    assert bad.problem == "vector_store_ids_invalid"


class _XaiMcp:
    server_url = "https://mcp.deepwiki.com/mcp"
    server_label = "deepwiki"
    allowed_tool_names: List[str] = []
    authorization = "secret"


class XaiTool:
    """Stand-in for an xAI SDK ``chat_pb2.Tool`` message."""

    def __init__(self, which: Optional[str]) -> None:
        self._which = which
        self.mcp = _XaiMcp()

    def WhichOneof(self, name: str) -> Optional[str]:  # noqa: N802 - protobuf API
        assert name == "tool"
        return self._which


def test_xai_sdk_messages() -> None:
    got = normalize_hosted_tools(
        [XaiTool("function"), XaiTool("web_search"), XaiTool("x_search"), XaiTool("mcp"), XaiTool(None)]
    )
    assert [(t.provider, t.kind) for t in got] == [
        ("xai", "web_search"),
        ("xai", "x_search"),
        ("xai", "mcp"),
        ("unknown", "XaiTool"),
    ]
    assert got[2].allowed_tools is None
    assert got[2].server_origin == "https://mcp.deepwiki.com"


def test_unknown_objects_are_reported_by_type_name_never_dropped() -> None:
    class SomeHostedThing:
        pass

    got = normalize_hosted_tools([SomeHostedThing(), "web_search", 7])
    assert [t.kind for t in got] == ["SomeHostedThing", "str", "int"]
    assert all(t.provider == "unknown" for t in got)


def test_a_hosted_tool_passes_through_and_a_bad_provider_hint_is_refused() -> None:
    tool = normalize_hosted_tools([{"type": "web_search"}])[0]
    assert normalize_hosted_tools([tool]) == [tool]
    with pytest.raises(ValueError):
        normalize_hosted_tools([], "not-a-provider")


def test_mcp_server_urls_are_canonical_or_refused() -> None:
    assert normalize_mcp_server_url("HTTPS://Host.Example:8443/a/b/?q=1#f") == "https://host.example:8443/a/b"
    assert normalize_mcp_server_url("HTTPS://u:p@Host.Example:8443/a/b") is None
    assert normalize_mcp_server_url("https://attacker.com\\@good.com/mcp") is None
    assert normalize_mcp_server_url("https://" + "a" * 2050 + ".com/mcp") is None
    assert normalize_mcp_server_url("not a url") is None
    assert normalize_mcp_server_url("https:///nohost") is None
    assert normalize_mcp_server_url(None) is None
    assert normalize_mcp_server_url("connector:connector_gmail") is None


# ─── Gate ────────────────────────────────────────────────────────────

WEB = 'Tool::"web_search"'
CODE = 'Tool::"code_interpreter"'
TOOLS = [{"type": "web_search"}, {"type": "code_interpreter"}]


@pytest.mark.asyncio
async def test_all_allowed_lets_the_call_proceed() -> None:
    handle = StandInHandle()
    gate = await authorize_hosted_tools(handle, TOOLS, HostedToolTurn())
    assert gate.allowed
    assert [c["resource"] for c in handle.calls] == [WEB, CODE]
    assert all(c["context"]["builtin_tool"] is True for c in handle.calls)


@pytest.mark.asyncio
async def test_no_hosted_tools_makes_no_request() -> None:
    handle = StandInHandle()
    gate = await authorize_hosted_tools(
        handle, [{"type": "function", "name": "f", "parameters": {}}], HostedToolTurn()
    )
    assert gate.allowed and handle.calls == [] and gate.tools == ()


@pytest.mark.asyncio
async def test_a_deny_refuses_the_call_and_stops() -> None:
    handle = StandInHandle({WEB: AuthorizeResult("deny", reason="policy")})
    gate = await authorize_hosted_tools(handle, TOOLS, HostedToolTurn())
    assert not gate.allowed
    assert gate.result.is_deny()
    assert gate.refused_tool is not None and gate.refused_tool.kind == "web_search"
    assert [c["resource"] for c in handle.calls] == [WEB]


@pytest.mark.asyncio
async def test_needs_approval_refuses_the_call_and_keeps_the_approval() -> None:
    pending = AuthorizeResult("needs_approval", approval_request_id="appr_1", escalation_required=True)
    handle = StandInHandle({CODE: pending})
    gate = await authorize_hosted_tools(handle, TOOLS, HostedToolTurn())
    assert not gate.allowed
    assert gate.result.needs_approval()
    assert gate.result.approval_request_id == "appr_1"


@pytest.mark.asyncio
async def test_an_error_refuses_the_call() -> None:
    handle = StandInHandle({WEB: ConnectionError("down")})
    gate = await authorize_hosted_tools(handle, TOOLS, HostedToolTurn())
    assert not gate.allowed
    assert gate.result.reason == HOSTED_TOOL_REFUSED_UNAVAILABLE


@pytest.mark.asyncio
async def test_a_malformed_answer_refuses_the_call() -> None:
    handle = StandInHandle({WEB: {"decision": "Allow"}})
    gate = await authorize_hosted_tools(handle, TOOLS, HostedToolTurn())
    assert not gate.allowed
    assert gate.result.reason == HOSTED_TOOL_REFUSED_UNAVAILABLE


@pytest.mark.asyncio
async def test_a_timeout_refuses_the_call() -> None:
    async def slow() -> AuthorizeResult:
        await asyncio.sleep(5)
        return AuthorizeResult("allow")  # pragma: no cover

    handle = StandInHandle({WEB: slow})
    gate = await authorize_hosted_tools(handle, TOOLS, HostedToolTurn(), timeout_seconds=0.05)
    assert not gate.allowed
    assert gate.result.reason == HOSTED_TOOL_REFUSED_TIMEOUT


@pytest.mark.asyncio
async def test_a_run_ending_decision_raises_its_typed_error() -> None:
    quarantined = AgentQuarantinedError(
        reason="r", anomaly_score=0.9, contributing_features=[], model_version=None, policy_id="p"
    )
    handle = StandInHandle({WEB: quarantined})
    with pytest.raises(AgentQuarantinedError):
        await authorize_hosted_tools(handle, TOOLS, HostedToolTurn())


@pytest.mark.asyncio
async def test_allows_are_cached_within_one_turn_only() -> None:
    handle = StandInHandle()
    turn = HostedToolTurn()
    await authorize_hosted_tools(handle, [{"type": "web_search"}], turn)
    # A re-check in the same turn asks only for the tool added since.
    gate = await authorize_hosted_tools(handle, TOOLS, turn)
    assert gate.allowed
    assert [c["resource"] for c in handle.calls] == [WEB, CODE]
    # The next model call is a new turn: everything is asked again.
    await authorize_hosted_tools(handle, TOOLS, HostedToolTurn())
    assert [c["resource"] for c in handle.calls] == [WEB, CODE, WEB, CODE]


@pytest.mark.asyncio
async def test_a_deny_is_never_cached() -> None:
    handle = StandInHandle({WEB: AuthorizeResult("deny")})
    turn = HostedToolTurn()
    await authorize_hosted_tools(handle, TOOLS, turn)
    await authorize_hosted_tools(handle, TOOLS, turn)
    assert [c["resource"] for c in handle.calls] == [WEB, WEB]


@pytest.mark.asyncio
async def test_a_turn_is_bound_to_one_handle() -> None:
    turn = HostedToolTurn()
    await authorize_hosted_tools(StandInHandle(), TOOLS, turn)
    with pytest.raises(WatchlightContractError):
        await authorize_hosted_tools(StandInHandle(), TOOLS, turn)
    with pytest.raises(WatchlightContractError):
        await authorize_hosted_tools(StandInHandle(), TOOLS, object())  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_an_unregistered_mcp_server_is_refused_before_any_decision() -> None:
    handle = StandInHandle()
    tools = [
        {"type": "web_search"},
        {"type": "mcp", "server_label": "registered-name", "server_url": "https://other.example.net/mcp"},
    ]
    gate = await authorize_hosted_tools(
        handle, tools, HostedToolTurn(), registered_mcp_servers={"https://mcp.example.com/mcp": "registered-name"}
    )
    assert not gate.allowed
    assert gate.result.reason == HOSTED_MCP_SERVER_UNREGISTERED
    assert handle.calls == []
    # With no registry at all, every remote MCP server is refused.
    gate = await authorize_hosted_tools(handle, tools[1:], HostedToolTurn())
    assert gate.result.reason == HOSTED_MCP_SERVER_UNREGISTERED
    # A toolset whose server definition was not passed has no URL: refused.
    gate = await authorize_hosted_tools(
        handle, [{"type": "mcp_toolset", "mcp_server_name": "x"}], HostedToolTurn(),
        registered_mcp_servers={"https://mcp.example.com/mcp": "registered-name"},
    )
    assert gate.result.reason == HOSTED_MCP_SERVER_UNREGISTERED
    assert handle.calls == []


@pytest.mark.asyncio
async def test_registered_server_names_must_be_plain() -> None:
    tools = [{"type": "mcp", "server_url": "https://mcp.example.com/mcp"}]
    for bad in (
        {"https://mcp.example.com/mcp": 'x"y'},
        {"not a url": "ok"},
        {"https://mcp.example.com/mcp": "a", "https://MCP.example.com:443/mcp/": "b"},
    ):
        with pytest.raises(WatchlightContractError):
            await authorize_hosted_tools(StandInHandle(), tools, HostedToolTurn(), registered_mcp_servers=bad)


@pytest.mark.asyncio
async def test_invalid_allowed_tools_refuse_before_any_decision() -> None:
    handle = StandInHandle()
    tools = [{"type": "mcp", "server_url": "https://mcp.example.com/mcp", "allowed_tools": ["t%d" % i for i in range(65)]}]
    gate = await authorize_hosted_tools(
        handle, tools, HostedToolTurn(), registered_mcp_servers={"https://mcp.example.com/mcp": "m"}
    )
    assert not gate.allowed and gate.result.reason == HOSTED_TOOL_CONFIG_INVALID
    assert handle.calls == []


@pytest.mark.asyncio
async def test_a_synchronous_error_from_the_handle_refuses_the_call() -> None:
    class Throws(StandInHandle):
        def authorize_action_detailed(self, *a: Any, **kw: Any) -> Any:  # type: ignore[override]
            raise RuntimeError("sync failure")

    gate = await authorize_hosted_tools(Throws(), TOOLS, HostedToolTurn())
    assert not gate.allowed and gate.result.reason == HOSTED_TOOL_REFUSED_UNAVAILABLE


@pytest.mark.asyncio
async def test_the_result_has_no_truth_value() -> None:
    gate = await authorize_hosted_tools(StandInHandle({WEB: AuthorizeResult("deny")}), TOOLS, HostedToolTurn())
    with pytest.raises(TypeError):
        bool(gate)
    with pytest.raises(TypeError):
        if gate:  # pragma: no cover - the test is that this raises
            pass
    assert gate.allowed is False


@pytest.mark.asyncio
async def test_require_raises_a_typed_refusal_carrying_the_result() -> None:
    pending = AuthorizeResult("needs_approval", approval_request_id="appr_secret")
    with pytest.raises(HostedToolRefused) as err:
        await require_hosted_request_allowed(StandInHandle({CODE: pending}), {"tools": TOOLS}, HostedToolTurn())
    assert isinstance(err.value.gate, HostedToolGateResult)
    assert err.value.gate.result.approval_request_id == "appr_secret"
    assert "appr_secret" not in str(err.value)
    assert "code_interpreter" in str(err.value)
    ok = await require_hosted_request_allowed(StandInHandle(), {"tools": TOOLS}, HostedToolTurn())
    assert ok.allowed


@pytest.mark.asyncio
async def test_a_sealed_turn_refuses_further_use() -> None:
    handle = StandInHandle()
    turn = HostedToolTurn()
    await authorize_hosted_tools(handle, TOOLS, turn)
    turn.seal()
    assert turn.sealed and turn.allowed_keys == frozenset()
    with pytest.raises(WatchlightContractError):
        await authorize_hosted_tools(handle, TOOLS, turn)


@pytest.mark.asyncio
async def test_action_map_overrides_the_verb() -> None:
    handle = StandInHandle()
    await authorize_hosted_tools(handle, [{"type": "web_search"}], HostedToolTurn(), action_map={"web_search": "search"})
    assert handle.calls[0]["action"] == 'Action::"search"'


# ─── Gate through a real run handle ──────────────────────────────────


class _Plugin(GovernanceTelemetry):
    def __init__(self) -> None:
        super().__init__()
        self.apdp = MockApdpClient()
        self.apdp.default_decision = "Allow"
        self.tenant_id = "tenant-acme"
        self.log_decisions = False
        self.framework = "standin"


def _handle(plugin: _Plugin) -> BaseRunHandle:
    h = BaseRunHandle(plugin=plugin, agent_uuid="uuid-x", session_id="ses_x")
    h._aentered = True
    return h


@pytest.mark.asyncio
async def test_the_gate_through_a_run_handle_sends_the_adk_wire_shape() -> None:
    plugin = _Plugin()
    gate = await authorize_hosted_tools(_handle(plugin), TOOLS, HostedToolTurn())
    assert gate.allowed
    call = plugin.apdp.authorize_calls[0]
    assert call["action"] == 'Action::"execute"'
    assert call["resource"] == WEB
    assert call["context"]["builtin_tool"] is True
    assert call["context"]["hosted_tool"] == {"provider": "openai", "kind": "web_search"}
    assert call["context"]["tenant_id"] == "tenant-acme"


@pytest.mark.asyncio
async def test_a_deny_through_a_run_handle_refuses() -> None:
    plugin = _Plugin()
    plugin.apdp.decisions[("execute", "code_interpreter")] = "Deny"
    gate = await authorize_hosted_tools(_handle(plugin), TOOLS, HostedToolTurn())
    assert not gate.allowed and gate.refused_tool is not None
    assert gate.refused_tool.kind == "code_interpreter"


# ─── Lineage ─────────────────────────────────────────────────────────


def _mcp_tool() -> HostedTool:
    return normalize_hosted_tools(FIXTURE["normalize"][1]["tools"])[0]


def test_the_observation_is_value_free_and_matches_the_payload_schema() -> None:
    payload = hosted_tool_observation(_mcp_tool(), framework="langgraph", decision="Allow")
    ToolCallObservedPayload.model_validate(payload)
    assert payload["tool"]["endpoint"] == "langgraph://hosted/openai/mcp"
    assert payload["tool"]["resource_type"] == "hosted_tool"
    text = json.dumps(payload)
    for secret in SECRETS:
        assert secret not in text
    with pytest.raises(ValueError):
        hosted_tool_observation(_mcp_tool(), framework="Not A Scheme")


@pytest.mark.asyncio
async def test_publish_stamps_hosted_tool_metadata() -> None:
    handle = StandInHandle()
    await publish_hosted_tool_observed(handle, _mcp_tool(), framework="langgraph")
    (event,) = handle.published
    assert event["event_type"] == "tool_call_observed"
    assert event["extra_metadata"] == {"hosted_tool": True}


@pytest.mark.asyncio
async def test_publish_through_a_run_handle_is_a_canonical_event() -> None:
    plugin = _Plugin()
    handle = _handle(plugin)
    handle.mark_execution_started_emitted(handle.execution_id)
    await publish_hosted_tool_observed(handle, _mcp_tool(), framework="standin", decision="Allow")
    events = [e for e in plugin.apdp.published_events if e["event_type"] == "tool_call_observed"]
    assert len(events) == 1
    assert events[0]["metadata"]["hosted_tool"] is True
    assert_canonical_event(events[0], expected_uri_prefix="standin://")


# ─── Conformance invariant 19 ────────────────────────────────────────


def _auth(kind: str, decision: str, provider: str = "openai") -> Dict[str, Any]:
    return {
        "step": "authorize",
        "context": {"builtin_tool": True, "hosted_tool": {"provider": provider, "kind": kind}},
        "decision": decision,
    }


def _mcp_auth(server: str, decision: str = "Allow") -> Dict[str, Any]:
    return {
        "step": "authorize",
        "context": {"builtin_tool": True, "hosted_tool": {"provider": "openai", "kind": "mcp", "server": server}},
        "decision": decision,
    }


def test_invariant_19_is_registered() -> None:
    assert (19, "hosted_tools_authorized_before_model_call") in [(n, name) for n, name, _ in INVARIANTS]


def test_invariant_19_passes_when_every_hosted_tool_is_allowed_first() -> None:
    web = normalize_hosted_tools([{"type": "web_search"}])[0]
    check_hosted_tools_authorized_before_model_call(
        [
            _auth("web_search", "Allow"),
            {"step": "model_call", "hosted_tools": [web]},
            {"step": "authorize", "context": {"tenant_id": "t"}, "decision": "Deny"},
            {"step": "model_call", "hosted_tools": []},
        ]
    )


@pytest.mark.parametrize(
    "steps",
    [
        # The allow belongs to the previous turn.
        [_auth("web_search", "Allow"), {"step": "model_call", "hosted_tools": []},
         {"step": "model_call", "hosted_tools": [{"provider": "openai", "kind": "web_search"}]}],
        # A refused hosted tool, then the model call anyway.
        [_auth("web_search", "Deny"), {"step": "model_call", "hosted_tools": []}],
        [_auth("web_search", "error"), {"step": "model_call", "hosted_tools": []}],
        # Allowed for another provider only.
        [_auth("web_search", "Allow", "xai"),
         {"step": "model_call", "hosted_tools": [{"provider": "openai", "kind": "web_search"}]}],
        [{"step": "something_else"}],
        # Allowed for one MCP server, the call enables another.
        [_mcp_auth("docs"),
         {"step": "model_call", "hosted_tools": [{"provider": "openai", "kind": "mcp", "server": "other"}]}],
        # An MCP tool with no registered server never matches.
        [_mcp_auth("docs"),
         {"step": "model_call", "hosted_tools": [{"provider": "openai", "kind": "mcp", "server": None}]}],
        [_mcp_auth("docs"),
         {"step": "model_call", "hosted_tools": normalize_hosted_tools(
             [{"type": "mcp", "server_url": "https://docs.example.com/mcp"}])}],
    ],
)
def test_invariant_19_fails_closed(steps: List[Dict[str, Any]]) -> None:
    with pytest.raises(ConformanceFailure) as err:
        check_hosted_tools_authorized_before_model_call(steps)
    assert err.value.args[0] == HOSTED_TOOLS_AUTHORIZED_INVARIANT_NUMBER


@pytest.mark.asyncio
async def test_the_core_gate_satisfies_invariant_19() -> None:
    steps: List[Dict[str, Any]] = []

    class Recording(StandInHandle):
        async def authorize_action_detailed(self, action: str, resource: str, context: Any = None, **kw: Any) -> Any:
            result = await super().authorize_action_detailed(action, resource, context, **kw)
            steps.append({"step": "authorize", "context": context, "decision": "Allow" if result.is_allow() else "Deny"})
            return result

    for answers in ({}, {CODE: AuthorizeResult("deny")}):
        handle = Recording(answers)
        gate = await authorize_hosted_tools(handle, TOOLS, HostedToolTurn())
        if gate.allowed:
            steps.append({"step": "model_call", "hosted_tools": list(gate.tools)})
    check_hosted_tools_authorized_before_model_call(steps)


def test_invariant_19_keys_mcp_tools_on_their_server() -> None:
    registry = {"https://docs.example.com/mcp": "docs"}
    (tool,) = normalize_hosted_tools([{"type": "mcp", "server_url": "https://docs.example.com/mcp"}])
    provider, kind, server = hosted_tool_identity(tool, registry)
    check_hosted_tools_authorized_before_model_call(
        [_mcp_auth("docs"), {"step": "model_call", "hosted_tools": [
            {"provider": provider, "kind": kind, "server": server}]}]
    )


# ─── Invariant 19 against a plugin (recording model client) ──────────


class _GatedPlugin:
    """A plugin stand-in whose model call goes through the core gate."""

    supports_hosted_tools = True

    async def conformance_hosted_tool_call(self, probe: HostedToolConformanceProbe) -> None:
        handle = probe.wrap(StandInHandle())
        turn = HostedToolTurn()
        await require_hosted_request_allowed(
            handle, probe.request, turn,
            provider=probe.provider, registered_mcp_servers=probe.registered_mcp_servers,
        )
        await probe.model_client.call(probe.request)
        turn.seal()


class _UngatedPlugin(_GatedPlugin):
    """Declares hosted-tool support but calls the model with no gate."""

    async def conformance_hosted_tool_call(self, probe: HostedToolConformanceProbe) -> None:
        await probe.model_client.call(probe.request)


class _ResultIgnoringPlugin(_GatedPlugin):
    """Calls the gate but ignores its result."""

    async def conformance_hosted_tool_call(self, probe: HostedToolConformanceProbe) -> None:
        await authorize_hosted_request(
            probe.wrap(StandInHandle()), probe.request, HostedToolTurn(),
            registered_mcp_servers=probe.registered_mcp_servers,
        )
        await probe.model_client.call(probe.request)


class _ToolsOnlyPlugin(_GatedPlugin):
    """Gates only ``request["tools"]``: misses the request-level tools."""

    async def conformance_hosted_tool_call(self, probe: HostedToolConformanceProbe) -> None:
        handle = probe.wrap(StandInHandle())
        gate = await authorize_hosted_tools(
            handle, probe.request["tools"], HostedToolTurn(),
            registered_mcp_servers=probe.registered_mcp_servers,
        )
        if gate.allowed:
            await probe.model_client.call(probe.request)


class _HintingPlugin(_GatedPlugin):
    """Passes a provider hint to the gate, and declares it."""

    hosted_tool_provider = "anthropic"


class _UndeclaredHintPlugin(_GatedPlugin):
    """Passes a hint to the gate without declaring it."""

    async def conformance_hosted_tool_call(self, probe: HostedToolConformanceProbe) -> None:
        handle = probe.wrap(StandInHandle())
        await require_hosted_request_allowed(
            handle, probe.request, HostedToolTurn(),
            provider="anthropic", registered_mcp_servers=probe.registered_mcp_servers,
        )
        await probe.model_client.call(probe.request)


class _RefusedOnAllowPlugin(_GatedPlugin):
    """Raises the typed refusal even though every hosted tool is allowed."""

    async def conformance_hosted_tool_call(self, probe: HostedToolConformanceProbe) -> None:
        from watchlight_core.hosted_tools import HostedToolGateResult

        raise HostedToolRefused(HostedToolGateResult(AuthorizeResult("deny")))


class _NoHookPlugin:
    supports_hosted_tools = True


class _UndeclaredPlugin:
    pass


@pytest.mark.asyncio
async def test_a_plugin_that_calls_the_gate_passes_invariant_19() -> None:
    assert await check_hosted_tool_gate_wired(_GatedPlugin()) == "ok"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "plugin",
    [_UngatedPlugin(), _ResultIgnoringPlugin(), _NoHookPlugin(), _ToolsOnlyPlugin(), _UndeclaredHintPlugin()],
    ids=lambda p: type(p).__name__,
)
async def test_a_plugin_that_skips_the_gate_fails_invariant_19(plugin: Any) -> None:
    with pytest.raises(ConformanceFailure) as err:
        await check_hosted_tool_gate_wired(plugin)
    assert err.value.args[0] == HOSTED_TOOLS_AUTHORIZED_INVARIANT_NUMBER


@pytest.mark.asyncio
async def test_a_hook_that_raises_on_the_allow_probe_fails_invariant_19() -> None:
    with pytest.raises(ConformanceFailure) as err:
        await check_hosted_tool_gate_wired(_RefusedOnAllowPlugin())
    assert err.value.args[0] == HOSTED_TOOLS_AUTHORIZED_INVARIANT_NUMBER
    assert "hook raised HostedToolRefused" in err.value.args[1]


class _ViolationOnDenyPlugin(_GatedPlugin):
    """Its hook reports a conformance violation on the deny probe, and
    makes no model call."""

    async def conformance_hosted_tool_call(self, probe: HostedToolConformanceProbe) -> None:
        if probe.decision == "Deny":
            raise ConformanceFailure(HOSTED_TOOLS_AUTHORIZED_INVARIANT_NUMBER, "violation found in the hook")
        await super().conformance_hosted_tool_call(probe)


@pytest.mark.asyncio
async def test_a_violation_raised_in_the_hook_on_the_deny_probe_fails_the_run() -> None:
    # The deny path swallowed every exception, including the
    # ConformanceFailure a hook raised, so the check passed.
    with pytest.raises(ConformanceFailure) as err:
        await check_hosted_tool_gate_wired(_ViolationOnDenyPlugin())
    assert err.value.args == (HOSTED_TOOLS_AUTHORIZED_INVARIANT_NUMBER, "violation found in the hook")


@pytest.mark.asyncio
async def test_a_plugin_that_does_not_declare_hosted_tools_is_skipped() -> None:
    assert await check_hosted_tool_gate_wired(_UndeclaredPlugin()) is None


@pytest.mark.asyncio
async def test_the_recording_model_client_records_identities() -> None:
    steps: List[Dict[str, Any]] = []
    client = RecordingModelClient(steps, registered_mcp_servers={"https://docs.example.com/mcp": "docs"})
    await client.call({"tools": [{"type": "web_search"}, {"type": "mcp", "server_url": "https://docs.example.com/mcp"}]})
    assert steps == [{"step": "model_call", "hosted_tools": [
        {"provider": "openai", "kind": "web_search", "server": None},
        {"provider": "openai", "kind": "mcp", "server": "docs"},
    ]}]


@pytest.mark.asyncio
async def test_a_plugin_that_declares_its_provider_hint_passes() -> None:
    assert await check_hosted_tool_gate_wired(_HintingPlugin()) == "ok"


@pytest.mark.asyncio
async def test_a_required_plugin_must_declare_hosted_tools(monkeypatch: pytest.MonkeyPatch) -> None:
    from watchlight_core_testing import conformance

    assert set(HOSTED_TOOL_PLUGINS_REQUIRED) >= {
        "watchlight-adk", "watchlight-bedrock", "watchlight-deepagents",
        "watchlight-langgraph", "watchlight-pydantic-ai", "watchlight-strands",
    }
    # While a required plugin is pending it is reported, not failed.
    monkeypatch.setattr(conformance, "HOSTED_TOOL_PLUGINS_PENDING", ("watchlight-langgraph",))
    assert await check_hosted_tool_gate_wired(_UndeclaredPlugin(), "watchlight_langgraph") == HOSTED_TOOL_PENDING
    # Once it is no longer pending, not declaring support fails.
    monkeypatch.setattr(conformance, "HOSTED_TOOL_PLUGINS_PENDING", ())
    with pytest.raises(ConformanceFailure):
        await check_hosted_tool_gate_wired(_UndeclaredPlugin(), "watchlight_langgraph")
    # A plugin that is not on the list is skipped.
    assert await check_hosted_tool_gate_wired(_UndeclaredPlugin(), "watchlight_msaf") is None


def _standin_plugin_module(monkeypatch: pytest.MonkeyPatch, name: str, cls: type) -> None:
    import sys
    import types

    module = types.ModuleType(name)
    setattr(module, cls.__name__, cls)
    monkeypatch.setitem(sys.modules, name, module)


@pytest.mark.asyncio
async def test_the_required_plugin_check_fails_and_never_skips(monkeypatch: pytest.MonkeyPatch) -> None:
    from watchlight_core_testing import conformance

    dist = "watchlight-standin-hosted"
    monkeypatch.setattr(conformance, "HOSTED_TOOL_PLUGINS_REQUIRED", (dist,))
    monkeypatch.setattr(conformance, "HOSTED_TOOL_PLUGINS_PENDING", ())
    # Not on the list: refused.
    with pytest.raises(ConformanceFailure):
        await check_required_hosted_tool_plugin("watchlight_msaf")
    # Listed but not importable: a failure, not a skip.
    with pytest.raises(ConformanceFailure, match="could not be loaded"):
        await check_required_hosted_tool_plugin("watchlight_standin_hosted")

    class StandInHostedPlugin(GovernanceTelemetry):
        supports_hosted_tools = True

        @classmethod
        def conformance_hosted_tool_instance(cls) -> Any:
            return _GatedPlugin()

    _standin_plugin_module(monkeypatch, "watchlight_standin_hosted", StandInHostedPlugin)
    assert await check_required_hosted_tool_plugin("watchlight_standin_hosted") == "ok"

    class UndeclaredHostedPlugin(GovernanceTelemetry):
        def __init__(self, **_: Any) -> None:  # pragma: no cover - never built
            raise AssertionError("an undeclared plugin is not built")

    _standin_plugin_module(monkeypatch, "watchlight_standin_hosted", UndeclaredHostedPlugin)
    with pytest.raises(ConformanceFailure, match="must declare"):
        await check_required_hosted_tool_plugin("watchlight_standin_hosted")
    monkeypatch.setattr(conformance, "HOSTED_TOOL_PLUGINS_PENDING", (dist,))
    assert await check_required_hosted_tool_plugin("watchlight_standin_hosted") == HOSTED_TOOL_PENDING

    class UnbuildableHostedPlugin(GovernanceTelemetry):
        supports_hosted_tools = True

        def __init__(self, **_: Any) -> None:
            raise ValueError("needs an explicit identity")

    _standin_plugin_module(monkeypatch, "watchlight_standin_hosted", UnbuildableHostedPlugin)
    with pytest.raises(ConformanceFailure, match="could not be built"):
        await check_required_hosted_tool_plugin("watchlight_standin_hosted")


def test_no_plugin_is_still_pending_at_the_next_core_release() -> None:
    """The pending list lets the core ship before the plugins wire the gate.
    It must be empty before the next core release: bumping the core version
    with a plugin still pending fails here."""
    import re

    pyproject = (Path(__file__).parent.parent / "pyproject.toml").read_text()
    version = re.search(r'^version = "([^"]+)"', pyproject, re.M)
    assert version is not None
    assert set(HOSTED_TOOL_PLUGINS_PENDING) <= set(HOSTED_TOOL_PLUGINS_REQUIRED)
    if HOSTED_TOOL_PLUGINS_PENDING:
        assert version.group(1) == HOSTED_TOOL_PENDING_CORE_VERSION, (
            "plugins still pending hosted-tool wiring: "
            + ", ".join(HOSTED_TOOL_PLUGINS_PENDING)
        )


def test_store_and_skill_ids_stay_out_of_repr():
    """Store and skill ids go to the decision context only, like the server
    URL: never into a ``repr`` that could reach a log."""
    search = normalize_hosted_request(
        {"tools": [{"type": "file_search", "vector_store_ids": ["vs_secret_1"]}]}, "openai"
    )[0]
    skill = normalize_hosted_request(
        {"container": {"skills": [{"type": "custom", "skill_id": "skill_secret_1"}]}}, "anthropic"
    )[0]
    assert search.vector_store_ids == ("vs_secret_1",) and skill.skill_id == "skill_secret_1"
    assert "vs_secret_1" not in repr(search) and "skill_secret_1" not in repr(skill)
