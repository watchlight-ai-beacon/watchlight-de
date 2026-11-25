"""The run marker on each provider SDK request.

Every test drives a real SDK client (anthropic, openai, google-genai) through
``provider_sdk_gate``, with a transport that records the headers that reached
the wire, so "refused" means nothing was sent and "named" means that header
was on that request. The egress binding is a stand-in that answers with its
own marker; the real connector is covered by ``test_attribution_e2e.py``.
"""

from __future__ import annotations

import asyncio
import os
import sys
import weakref
from typing import Any, Dict, List, Optional

import pytest

from watchlight_core import attribution as at
from watchlight_core import egress_route
from watchlight_core import provider_sdk_gate as gate
from watchlight_core import run_handle as rh
from watchlight_core.attribution import EgressRefused
from watchlight_core.errors import GovernanceUnavailable
from watchlight_core.hosted_tools import HostedToolRefused
from watchlight_core.results import AuthorizeResult

anthropic = pytest.importorskip("anthropic")
openai = pytest.importorskip("openai")
genai = pytest.importorskip("google.genai")

HEADER = "Watchlight-Run-Marker"
PROXY_URL = "http://127.0.0.1:41999"
MESSAGE = {
    "id": "msg_1",
    "type": "message",
    "role": "assistant",
    "model": "m",
    "content": [{"type": "text", "text": "ok"}],
    "stop_reason": "end_turn",
    "stop_sequence": None,
    "usage": {"input_tokens": 1, "output_tokens": 1},
}
COMPLETION = {
    "id": "c1",
    "object": "chat.completion",
    "created": 0,
    "model": "m",
    "choices": [
        {
            "index": 0,
            "finish_reason": "stop",
            "message": {"role": "assistant", "content": "ok"},
        }
    ],
}
GEMINI = {"candidates": [{"content": {"role": "model", "parts": [{"text": "ok"}]}}]}
WEB_SEARCH = {"type": "web_search_20250305", "name": "web_search", "max_uses": 1}


@pytest.fixture(autouse=True)
def _route_checked_elsewhere(monkeypatch: pytest.MonkeyPatch) -> None:
    # These clients answer through MockTransport. test_egress_route.py proves
    # the route with real clients through a real listener.
    monkeypatch.setattr(egress_route, "require_httpx_route", lambda *a: None)
    monkeypatch.setattr(egress_route, "require_aiohttp_route", lambda *a: None)


class _Egress:
    """A connector egress binding, as ``SidecarEgress`` presents it."""

    marker_header = HEADER
    proxy_url = PROXY_URL

    def __init__(self, marker: str) -> None:
        self.value = marker
        self.ended = False
        self.owner_pid = os.getpid()

    def marker(self) -> str:
        if self.ended:
            raise GovernanceUnavailable("the run ended")
        return self.value

    def child_proxy_url(self) -> str:
        raise AssertionError("not used here")

    def report_connection_blocking(self, src_port: int, timeout_s: float = 2.0) -> bool:
        return True


class _Handle:
    """A run or sub-agent handle, as attribution reads one."""

    def __init__(self, egress: Optional[_Egress], parent: Any = None) -> None:
        self.egress = egress
        self._state = "active"
        self._is_subagent = parent is not None
        self._parent_handle_ref = weakref.ref(parent) if parent is not None else None


class _Decider:
    def __init__(self, decision: str) -> None:
        self.decision = decision

    async def authorize_action_detailed(self, action: str, resource: str, *, context: Any = None) -> Any:
        return AuthorizeResult(self.decision)


class _Wire:
    def __init__(self, body: Dict[str, Any]) -> None:
        self.body = body
        self.markers: List[Optional[str]] = []

    def __call__(self, request: Any) -> Any:
        self.markers.append(request.headers.get(HEADER))
        return sys.modules[type(request).__module__.split(".")[0]].Response(200, json=self.body)


def _httpx_of(sdk: Any) -> Any:
    return getattr(sdk._base_client, "httpx2", None) or sdk._base_client.httpx


def _anthropic(wire: _Wire, *, asynchronous: bool = False) -> Any:
    hx = _httpx_of(anthropic)
    transport = hx.MockTransport(wire)
    if asynchronous:
        return anthropic.AsyncAnthropic(
            api_key="k", http_client=hx.AsyncClient(transport=transport), max_retries=0
        )
    return anthropic.Anthropic(api_key="k", http_client=hx.Client(transport=transport), max_retries=0)


def _openai(wire: _Wire) -> Any:
    hx = _httpx_of(openai)
    return openai.OpenAI(
        api_key="k", http_client=hx.Client(transport=hx.MockTransport(wire)), max_retries=0
    )


def _gemini(wire: _Wire, *, asynchronous: bool = False) -> Any:
    import httpx
    from google.genai import types

    transport = httpx.MockTransport(wire)
    options = (
        types.HttpOptions(httpx_async_client=httpx.AsyncClient(transport=transport))
        if asynchronous
        else types.HttpOptions(httpx_client=httpx.Client(transport=transport))
    )
    return genai.Client(api_key="k", http_options=options)


def _ms(**kw: Any) -> Dict[str, Any]:
    return {"model": "m", "max_tokens": 16, "messages": [{"role": "user", "content": "hi"}], **kw}


@pytest.fixture(autouse=True)
def _installed() -> None:
    gate.install()


def _on_the_connector() -> None:
    assert at.register_egress_endpoint(PROXY_URL)


def test_an_anthropic_request_names_the_run_acting_here() -> None:
    wire = _Wire(MESSAGE)
    with at.bound_run(_Egress("marker-a")):
        _anthropic(wire).messages.create(**_ms())
    assert wire.markers == ["marker-a"]


def test_an_openai_request_names_the_run_acting_here() -> None:
    wire = _Wire(COMPLETION)
    with at.bound_run(_Egress("marker-a")):
        _openai(wire).chat.completions.create(
            model="m", messages=[{"role": "user", "content": "hi"}]
        )
    assert wire.markers == ["marker-a"]


def test_a_gemini_request_names_the_run_acting_here() -> None:
    wire = _Wire(GEMINI)
    with at.bound_run(_Egress("marker-a")):
        _gemini(wire).models.generate_content(model="m", contents="hi")
    assert wire.markers == ["marker-a"]


@pytest.mark.asyncio
async def test_an_async_gemini_request_names_the_run_acting_here() -> None:
    wire = _Wire(GEMINI)
    with at.bound_run(_Egress("marker-a")):
        await _gemini(wire, asynchronous=True).aio.models.generate_content(model="m", contents="hi")
    assert wire.markers == ["marker-a"]


@pytest.mark.asyncio
async def test_runs_sharing_one_client_each_name_themselves() -> None:
    wire = _Wire(MESSAGE)
    client = _anthropic(wire, asynchronous=True)

    async def run(marker: str) -> None:
        with at.bound_run(_Egress(marker)):
            for _ in range(3):
                await client.messages.create(**_ms())
                await asyncio.sleep(0)

    await asyncio.gather(*(asyncio.create_task(run(m)) for m in ("marker-a", "marker-b")))
    assert sorted(wire.markers) == ["marker-a"] * 3 + ["marker-b"] * 3


def test_a_sub_agent_names_itself_never_its_parent() -> None:
    wire = _Wire(MESSAGE)
    root = _Handle(_Egress("marker-root"))
    child = _Handle(_Egress("marker-child"), parent=root)
    with at.bound_run(root):
        token = rh._current_subagent_handle.set(child)
        try:
            _anthropic(wire).messages.create(**_ms())
        finally:
            rh._current_subagent_handle.reset(token)
    assert wire.markers == ["marker-child"]


def test_a_sub_agent_with_no_egress_of_its_own_sends_nothing() -> None:
    wire = _Wire(MESSAGE)
    root = _Handle(_Egress("marker-root"))
    child = _Handle(None, parent=root)
    with at.bound_run(root):
        token = rh._current_subagent_handle.set(child)
        try:
            with pytest.raises(EgressRefused, match="subagent_has_no_egress"):
                _anthropic(wire).messages.create(**_ms())
        finally:
            rh._current_subagent_handle.reset(token)
    assert wire.markers == []


def test_a_run_that_ended_sends_nothing() -> None:
    wire = _Wire(MESSAGE)
    egress = _Egress("marker-a")
    with at.bound_run(egress):
        egress.ended = True
        with pytest.raises(EgressRefused, match="run_not_live"):
            _anthropic(wire).messages.create(**_ms())
    assert wire.markers == []


def test_no_run_in_this_context_sends_nothing_on_the_connector() -> None:
    _on_the_connector()
    wire = _Wire(MESSAGE)
    with pytest.raises(EgressRefused, match="no_run_bound"):
        _anthropic(wire).messages.create(**_ms())
    assert wire.markers == []


def test_a_gemini_request_with_no_run_sends_nothing_on_the_connector() -> None:
    _on_the_connector()
    wire = _Wire(GEMINI)
    with pytest.raises(EgressRefused, match="no_run_bound"):
        _gemini(wire).models.generate_content(model="m", contents="hi")
    assert wire.markers == []


def test_with_no_run_on_the_connector_a_request_is_unchanged() -> None:
    wire = _Wire(MESSAGE)
    _anthropic(wire).messages.create(**_ms())
    assert wire.markers == [None]


def test_the_callers_options_keep_no_marker() -> None:
    from anthropic._models import FinalRequestOptions

    wire = _Wire(MESSAGE)
    options = FinalRequestOptions(method="post", url="/v1/messages", json_data=_ms())
    with at.bound_run(_Egress("marker-a")):
        _anthropic(wire).request(anthropic.types.Message, options)
    assert wire.markers == ["marker-a"]
    assert HEADER not in (options.headers if isinstance(options.headers, dict) else {})


@pytest.mark.asyncio
async def test_a_denied_request_is_refused_by_its_decision_not_the_marker() -> None:
    wire = _Wire(MESSAGE)
    client = _anthropic(wire, asynchronous=True)
    loop = asyncio.get_running_loop()
    with at.bound_run(_Egress("marker-a")):
        attachment = gate.attach_run(_Decider("deny"), run_loop=loop)
        try:
            with pytest.raises(HostedToolRefused):
                await client.messages.create(**_ms(tools=[WEB_SEARCH]))
        finally:
            gate.detach_run(attachment)
    assert wire.markers == []


def test_a_callers_own_spelling_of_the_header_never_travels_beside_the_marker() -> None:
    seen: List[List[Any]] = []

    def wire(request: Any) -> Any:
        seen.append([v for k, v in request.headers.raw if k.lower() == HEADER.lower().encode()])
        return sys.modules[type(request).__module__.split(".")[0]].Response(200, json=MESSAGE)

    hx = _httpx_of(anthropic)
    client = anthropic.Anthropic(
        api_key="k",
        http_client=hx.Client(transport=hx.MockTransport(wire)),
        max_retries=0,
    )
    with at.bound_run(_Egress("marker-a")):
        client.messages.create(**_ms(), extra_headers={HEADER.lower(): "from-the-call"})
    # A client's own default_headers aren't reached here, and older SDKs merge
    # them case-sensitively: both values then go, and the connector refuses
    # two markers.
    assert seen == [[b"marker-a"]]
