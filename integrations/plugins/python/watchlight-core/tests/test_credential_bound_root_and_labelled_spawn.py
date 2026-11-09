"""Install once at the root: a credential-bound root run and labelled sub-agents.

Pins the SDK side of the contract:

* ``create_session()`` with no agent sends no ``agent_id`` and adopts the
  agent wl-apdp names; a credential bound to no agent is the typed
  :class:`CredentialBindsNoAgent`; a named agent is an override the server
  must confirm.
* :func:`open_root_session` is the shared primitive plugins call.
* ``spawn_subagent(child_label=...)`` needs no registered agent; the label is
  checked before anything is sent; the child runs as the agent the server
  names, which must agree with what was asked for (fail closed).
* The Developer Edition (``InProcessClient``) behaves the same, with the
  process's configured identity standing in for the credential's agent.
"""

from __future__ import annotations

import json
import uuid
from typing import Any, Dict, List, Optional

import httpx
import pytest

from watchlight_core import (
    ApdpClient,
    BaseRunHandle,
    CredentialBindsNoAgent,
    GovernanceRefused,
    GovernanceUnavailable,
    InterceptorKillRegistry,
    WatchlightContractError,
    open_root_session,
    validate_child_label,
)
from watchlight_core.scope import (
    ChildIntent,
    RequestedScope,
    SpawnSubagentRequest,
    spawn_subagent_request_from_dict,
    spawn_subagent_request_to_dict,
    spawn_subagent_response_from_dict,
)
from watchlight_core_testing import MockApdpClient

BOUND = "11111111-1111-4111-8111-111111111111"
OTHER = "33333333-3333-4333-8333-333333333333"
# Every spawn declares the child's intent.
CHILD_INTENT = ChildIntent(category="research", objective="Delegated sub-task")
PARENT = "00000000-0000-0000-0000-000000000001"
MAPPED = "44444444-4444-4444-8444-444444444444"
REGISTERED = "22222222-2222-4222-8222-222222222222"


# ─── Labels ─────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "label",
    ["general-purpose", "research-agent", "my_adk_agent", "node:summarise", "team/writer",
     "critic@v2", "Plan Reviewer", "a", "a" * 128],
)
def test_framework_child_names_are_valid_labels(label: str) -> None:
    assert validate_child_label(label) == label


@pytest.mark.parametrize(
    "label",
    ["", " leading", "-dash", "new\nline", "quote\"", "semi;colon", 'Agent::"x"',
     "ünïcode", "a" * 129, None, 7],
)
def test_malformed_labels_are_refused(label: Any) -> None:
    with pytest.raises(ValueError):
        validate_child_label(label)


def test_spawn_request_needs_a_child_and_checks_the_label() -> None:
    base = dict(
        parent_agent_id=uuid.UUID(PARENT),
        parent_run_handle_id=uuid.uuid4(),
        requested_scope=RequestedScope(),
        child_intent=CHILD_INTENT,
    )
    with pytest.raises(ValueError):
        spawn_subagent_request_to_dict(SpawnSubagentRequest(child_agent_id=None, **base))
    with pytest.raises(ValueError):
        spawn_subagent_request_to_dict(
            SpawnSubagentRequest(child_agent_id=None, child_label="bad;label", **base)
        )
    body = spawn_subagent_request_to_dict(
        SpawnSubagentRequest(child_agent_id=None, child_label="research-agent", **base)
    )
    assert "child_agent_id" not in body
    assert body["child_label"] == "research-agent"
    assert spawn_subagent_request_from_dict(body).child_label == "research-agent"
    with pytest.raises(ValueError):
        spawn_subagent_request_from_dict({k: v for k, v in body.items() if k != "child_label"})


# ─── ApdpClient wire ────────────────────────────────────────────────


class _Wire:
    def __init__(self, *, served_agent: Optional[str] = BOUND, status: int = 200,
                 body: Optional[Dict[str, Any]] = None) -> None:
        self.served_agent = served_agent
        self.status = status
        self.body = body
        self.requests: List[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if request.url.path == "/sessions":
            if self.status != 200:
                return httpx.Response(self.status, json=self.body or {})
            session: Dict[str, Any] = {"id": "ses_root", "status": "active"}
            if self.served_agent is not None:
                session["agent_id"] = self.served_agent
            return httpx.Response(
                200,
                json={"session": session, "session_token": "sst_ROOT.c2ln",
                      "execution_id": "exec_root"},
            )
        return httpx.Response(200, json={})

    def session_body(self) -> Dict[str, Any]:
        (req,) = [r for r in self.requests if r.url.path == "/sessions"]
        return json.loads(req.content)


def _client(wire: _Wire) -> ApdpClient:
    apdp = ApdpClient("https://apdp.test")
    apdp._probed = True
    apdp._client = httpx.AsyncClient(
        base_url="https://apdp.test", transport=httpx.MockTransport(wire)
    )
    return apdp


@pytest.mark.asyncio
async def test_a_root_with_no_agent_sends_none_and_adopts_the_credentials_agent() -> None:
    wire = _Wire()
    info = await _client(wire).create_session()
    assert "agent_id" not in wire.session_body()
    assert info is not None and info.agent_id == BOUND


@pytest.mark.asyncio
async def test_a_named_agent_is_sent_and_must_be_the_one_served() -> None:
    wire = _Wire()
    info = await _client(wire).create_session(agent_id=BOUND)
    assert wire.session_body()["agent_id"] == BOUND
    assert info is not None and info.agent_id == BOUND
    # The server opened the run for another agent: refused, never registered.
    assert await _client(_Wire()).create_session(agent_id=OTHER) is None


@pytest.mark.asyncio
async def test_a_root_whose_answer_names_no_agent_is_refused() -> None:
    assert await _client(_Wire(served_agent=None)).create_session() is None


@pytest.mark.asyncio
async def test_a_credential_bound_to_no_agent_is_a_typed_refusal() -> None:
    body = {"error": {"type": "credential_binds_no_agent", "code": "credential_binds_no_agent",
                      "message": "x", "status": 403}}
    with pytest.raises(CredentialBindsNoAgent) as info:
        await _client(_Wire(status=403, body=body)).create_session()
    assert info.value.code == "credential_binds_no_agent"
    assert info.value.status_code == 403
    assert isinstance(info.value, GovernanceRefused)


@pytest.mark.asyncio
async def test_a_mismatched_named_agent_stays_opaque() -> None:
    body = {"error": {"type": "not authorized", "message": "not authorized", "status": 403}}
    assert await _client(_Wire(status=403, body=body)).create_session(agent_id=OTHER) is None


# ─── open_root_session ──────────────────────────────────────────────


@pytest.mark.asyncio
async def test_open_root_session_defaults_to_the_credentials_agent() -> None:
    apdp = MockApdpClient()
    apdp.credential_agent = BOUND
    session = await open_root_session(apdp, goal_id="g")
    assert session.agent_id == BOUND


@pytest.mark.asyncio
async def test_open_root_session_refuses_when_the_credential_binds_no_agent() -> None:
    with pytest.raises(CredentialBindsNoAgent):
        await open_root_session(MockApdpClient())


@pytest.mark.asyncio
async def test_open_root_session_keeps_the_slug_override() -> None:
    apdp = MockApdpClient()
    apdp.known_agents["writer"] = BOUND
    assert (await open_root_session(apdp, agent_slug="writer")).agent_id == BOUND
    from watchlight_core import AgentNotRegistered

    with pytest.raises(AgentNotRegistered):
        await open_root_session(apdp, agent_slug="unknown")
    # A slug the agent-bound credential does not match is refused.
    apdp.credential_agent = OTHER
    with pytest.raises(GovernanceUnavailable):
        await open_root_session(apdp, agent_slug="writer")
    with pytest.raises(ValueError):
        await open_root_session(apdp, agent_slug="writer", agent_id=BOUND)


@pytest.mark.asyncio
async def test_open_root_session_refuses_a_session_for_another_agent() -> None:
    apdp = MockApdpClient()
    real = apdp.create_session

    async def lying(**kwargs: Any) -> Any:
        info = await real(**kwargs)
        from dataclasses import replace

        return replace(info, agent_id=OTHER)

    apdp.create_session = lying  # type: ignore[method-assign]
    with pytest.raises(GovernanceUnavailable):
        await open_root_session(apdp, agent_id=BOUND)


# ─── Labelled spawn through BaseRunHandle ───────────────────────────


class _Plugin:
    def __init__(self, apdp: Any) -> None:
        self.apdp = apdp
        self.tenant_id = "tenant-a"
        self.log_decisions = False
        self.last_governance_mode = "unmeasured"
        self.last_session_id: Optional[str] = None
        self.last_manifest: Optional[Dict[str, Any]] = None
        self.last_plan_validation: Optional[Dict[str, Any]] = None
        self.last_proposed_plan: Optional[Any] = None
        self.last_actions_allowed = 0
        self.last_actions_denied = 0
        self.kill_signal_registry: Optional[InterceptorKillRegistry] = None


def _handle(apdp: Any) -> BaseRunHandle:
    handle = BaseRunHandle(
        plugin=_Plugin(apdp),
        agent_uuid=PARENT,
        session_id=f"ses_{uuid.uuid4()}",
        run_handle_id=str(uuid.uuid4()),
    )
    handle._aentered = True
    return handle


@pytest.mark.asyncio
async def test_an_anonymous_labelled_child_runs_as_its_parent() -> None:
    apdp = MockApdpClient()
    child = await _handle(apdp).spawn_subagent(
        child_label="research-agent", child_intent=CHILD_INTENT, allowed_tools=["search"]
    )
    body = apdp.spawn_subagent_calls[0]
    assert "child_agent_id" not in body
    assert body["child_label"] == "research-agent"
    assert child.agent_uuid == PARENT
    assert child.child_label == "research-agent"
    assert child.child_identity == "anonymous"
    assert child.granted_scope.allowed_tools == ["search"]


@pytest.mark.asyncio
async def test_a_mapped_labelled_child_runs_as_the_mapped_agent() -> None:
    apdp = MockApdpClient()
    apdp.subagent_label_map["critic"] = MAPPED
    child = await _handle(apdp).spawn_subagent(child_label="critic", child_intent=CHILD_INTENT)
    assert child.agent_uuid == MAPPED
    assert child.child_identity == "mapped"


@pytest.mark.asyncio
async def test_the_registered_child_path_is_unchanged() -> None:
    apdp = MockApdpClient()
    child = await _handle(apdp).spawn_subagent(REGISTERED, child_label="writer", child_intent=CHILD_INTENT)
    body = apdp.spawn_subagent_calls[0]
    assert body["child_agent_id"] == REGISTERED and body["child_label"] == "writer"
    assert child.agent_uuid == REGISTERED
    assert child.child_identity == "registered"


@pytest.mark.asyncio
@pytest.mark.parametrize("label", [None, "bad;label", ""])
async def test_a_child_without_a_valid_identity_sends_nothing(label: Optional[str]) -> None:
    apdp = MockApdpClient()
    with pytest.raises(ValueError):
        await _handle(apdp).spawn_subagent(child_label=label, child_intent=CHILD_INTENT)
    assert apdp.spawn_subagent_calls == []


def _override(**fields: Any) -> Dict[str, Any]:
    response: Dict[str, Any] = {
        "child_run_handle_id": str(uuid.uuid4()),
        "granted_scope": {"allowed_tools": [], "allowed_resources": [], "allowed_intents": [],
                          "max_depth": 0, "time_budget_seconds": 60, "depth": 1},
        "child_execution_id": f"exec_{uuid.uuid4()}",
        "child_session_token": "sst_mock_child",
    }
    response.update(fields)
    return response


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "fields",
    [
        # A labelled child the server names no agent for.
        {"child_label": "research-agent", "child_identity": "anonymous"},
        # An "anonymous" child running as someone other than its parent.
        {"child_agent_id": OTHER, "child_label": "research-agent", "child_identity": "anonymous"},
        # The label came back changed.
        {"child_agent_id": PARENT, "child_label": "admin", "child_identity": "anonymous"},
        # An identity kind the SDK does not know.
        {"child_agent_id": PARENT, "child_label": "research-agent", "child_identity": "root"},
        # No identity kind for a labelled child.
        {"child_agent_id": MAPPED, "child_label": "research-agent"},
    ],
)
async def test_a_server_account_that_disagrees_refuses_the_spawn(fields: Dict[str, Any]) -> None:
    apdp = MockApdpClient()
    apdp.spawn_response_override = _override(**fields)
    with pytest.raises(GovernanceUnavailable):
        await _handle(apdp).spawn_subagent(child_label="research-agent", child_intent=CHILD_INTENT)


@pytest.mark.asyncio
async def test_a_registered_child_served_as_another_agent_is_refused() -> None:
    apdp = MockApdpClient()
    apdp.spawn_response_override = _override(child_agent_id=OTHER, child_identity="registered")
    with pytest.raises(GovernanceUnavailable):
        await _handle(apdp).spawn_subagent(REGISTERED, child_intent=CHILD_INTENT)


def test_the_response_parser_reads_the_identity_fields() -> None:
    parsed = spawn_subagent_response_from_dict(
        _override(child_agent_id=PARENT, child_label="x", child_identity="anonymous")
    )
    assert (parsed.child_agent_id, parsed.child_label, parsed.child_identity) == (
        PARENT, "x", "anonymous"
    )


# ─── Sidecar backend ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_the_connector_backend_refuses_a_slug_less_root_locally() -> None:
    from watchlight_core.sidecar_backend import SidecarBackend

    backend = object.__new__(SidecarBackend)
    with pytest.raises(WatchlightContractError):
        await backend.create_session()


# ─── Developer Edition (InProcessClient) ────────────────────────────


def _engine_client(tmp_path: Any, **kwargs: Any) -> Any:
    pytest.importorskip("watchlight_engine")
    from watchlight_core import InProcessClient

    return InProcessClient(audit_path=str(tmp_path / "audit.jsonl"), **kwargs)


def _de_uuid(slug: str) -> str:
    from watchlight_core.in_process_client import _AGENT_NS

    return str(uuid.uuid5(_AGENT_NS, slug))


@pytest.mark.asyncio
async def test_de_root_with_no_agent_uses_the_configured_identity(
    tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("WATCHLIGHT_AGENT", raising=False)
    client = _engine_client(tmp_path, agent="orchestrator")
    info = await client.create_session()
    assert info.agent_id == _de_uuid("orchestrator")
    assert info.agent_id == (await client.resolve_agent("orchestrator"))["id"]
    # The env var is the fallback identity.
    monkeypatch.setenv("WATCHLIGHT_AGENT", "from-env")
    assert (await _engine_client(tmp_path).create_session()).agent_id == _de_uuid("from-env")


@pytest.mark.asyncio
async def test_de_root_with_no_identity_is_refused(
    tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("WATCHLIGHT_AGENT", raising=False)
    client = _engine_client(tmp_path)
    with pytest.raises(CredentialBindsNoAgent):
        await client.create_session()
    # Naming the agent still works without an identity.
    assert (await client.create_session(agent_id=BOUND)).agent_id == BOUND


@pytest.mark.asyncio
async def test_de_refuses_a_named_agent_other_than_its_identity(
    tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("WATCHLIGHT_AGENT", raising=False)
    client = _engine_client(tmp_path, agent="orchestrator")
    with pytest.raises(GovernanceRefused):
        await client.create_session(agent_id=BOUND)
    info = await client.create_session(agent_id=_de_uuid("orchestrator"))
    assert info.agent_id == _de_uuid("orchestrator")


async def _de_spawn(client: Any, run: Any, handle: str, tools: List[str], **child: Any) -> Dict[str, Any]:
    body = spawn_subagent_request_to_dict(
        SpawnSubagentRequest(
            parent_agent_id=uuid.UUID(PARENT),
            child_agent_id=child.pop("child_agent_id", None),
            parent_run_handle_id=uuid.UUID(handle),
            requested_scope=RequestedScope(allowed_tools=tools, max_depth=1),
            child_label=child.pop("child_label", None),
            child_intent=CHILD_INTENT,
        )
    )
    return await client.spawn_subagent(run, body)


@pytest.mark.asyncio
async def test_de_anonymous_child_runs_as_its_parent_and_is_attenuated(tmp_path: Any) -> None:
    from watchlight_core import ScopeAttenuationDenied

    client = _engine_client(tmp_path, agent="orchestrator")
    root = await client.create_session()
    child = await _de_spawn(client, root.run, root.root_run_handle_id, ["search", "read"],
                            child_label="research-agent")
    assert child["child_agent_id"] == root.agent_id
    assert child["child_identity"] == "anonymous"
    assert child["child_label"] == "research-agent"
    # A label never widens: the grandchild can't ask for more than its parent.
    with pytest.raises(ScopeAttenuationDenied):
        await _de_spawn(client, child["child_run"], child["child_run_handle_id"],
                        ["search", "delete"], child_label="research-agent")
    records = [json.loads(line) for line in (tmp_path / "audit.jsonl").read_text().splitlines()]
    labelled = [r for r in records if r.get("event") == "attenuation"]
    assert labelled and all(r.get("child_label") == "research-agent" for r in labelled), labelled


@pytest.mark.asyncio
async def test_de_mapped_child_runs_as_the_mapped_agent(tmp_path: Any) -> None:
    client = _engine_client(tmp_path, agent="orchestrator",
                            subagent_agents={"critic": "critic-agent"})
    root = await client.create_session()
    child = await _de_spawn(client, root.run, root.root_run_handle_id, ["read"],
                            child_label="critic")
    assert child["child_agent_id"] == _de_uuid("critic-agent")
    assert child["child_identity"] == "mapped"


@pytest.mark.asyncio
async def test_de_labelled_children_decide_as_their_agent_with_its_trusted_name(
    tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The configured identity and the mapped agents carry
    their trusted name without a resolve_agent call; preflight decides an
    anonymous child as its parent's agent and a mapped child as the mapped
    agent, each with that agent's name."""
    monkeypatch.delenv("WATCHLIGHT_AGENT", raising=False)
    policies = [
        {"name": "orchestrator-only",
         "code": 'permit(principal, action, resource) when { principal.name == "orchestrator" };'},
    ]
    client = _engine_client(tmp_path, policies=policies, agent="orchestrator",
                            subagent_agents={"critic": "critic-agent"})
    root = await client.create_session()
    anon = await _de_spawn(client, root.run, root.root_run_handle_id, ["read"],
                           child_label="research-agent")
    mapped = await _de_spawn(client, root.run, root.root_run_handle_id, ["read"],
                             child_label="critic")

    async def decision(run: Any) -> str:
        return (await client.preflight_step(run, "execute", "read"))["preflight"]["decision"]

    assert await decision(root.run) == "Allow"
    assert await decision(anon["child_run"]) == "Allow"
    assert await decision(mapped["child_run"]) == "Deny"
    # The granted-scope check still comes first: an ungranted tool is denied
    # before any policy could allow it.
    out = await client.preflight_step(anon["child_run"], "execute", "write")
    assert out["preflight"]["decision"] == "Deny"
    assert out["preflight"]["reason"].startswith("scope_attenuation_violation")


@pytest.mark.asyncio
async def test_de_sets_the_label_as_policy_evidence_never_the_callers(tmp_path: Any) -> None:
    client = _engine_client(tmp_path, agent="orchestrator")
    seen: List[Dict[str, Any]] = []
    real = client._decide

    def spy(principal: str, action: str, resource: str, context: Dict[str, Any]) -> Any:
        seen.append(dict(context))
        return real(principal, action, resource, context)

    client._decide = spy  # type: ignore[method-assign]
    root = await client.create_session()
    # The grant names the tool the call names (its resource): a generic verb
    # such as ``read`` never grants a tool.
    child = await _de_spawn(client, root.run, root.root_run_handle_id, ["read_doc"],
                            child_label="research-agent")
    await client.authorize("Agent::\"a\"", "execute", "read_doc",
                           context={"subagent_label": "forged"}, run=child["child_run"])
    await client.authorize("Agent::\"a\"", "execute", "read_doc",
                           context={"subagent_label": "forged"}, run=root.run)
    assert seen[0]["subagent_label"] == "research-agent"
    assert "subagent_label" not in seen[1]


def test_de_refuses_a_malformed_label_mapping(tmp_path: Any) -> None:
    with pytest.raises(ValueError):
        _engine_client(tmp_path, subagent_agents={"bad;label": "x"})
    with pytest.raises(ValueError):
        _engine_client(tmp_path, subagent_agents={"ok": ""})
