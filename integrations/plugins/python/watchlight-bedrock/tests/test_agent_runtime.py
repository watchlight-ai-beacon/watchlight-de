"""Hosted capabilities on Bedrock Agents: GovernedBedrockAgentRuntime.

A ``bedrock-agent-runtime`` client and a ``bedrock-agent`` client, both
answered by botocore's Stubber. The agent's definition is read before
every ``invoke_agent``, and every hosted capability it enables (code
interpreter, user input, the Anthropic computer/bash/editor tools,
knowledge-base retrieval) is authorized before the call is made.
"""

from __future__ import annotations

import uuid

import boto3
import pytest
from botocore import UNSIGNED
from botocore.awsrequest import AWSResponse
from botocore.config import Config
from botocore.stub import Stubber
from watchlight_core import AgentQuarantinedError, HostedToolRefused
from watchlight_core_testing import MockApdpClient

from watchlight_bedrock import (
    BedrockRequestRefused,
    GovernedBedrockAgentRuntime,
    RunHandle,
    WatchlightBedrockPlugin,
)

AGENT = "AGENT12345"
ALIAS = "ALIAS12345"
KB = "KB12345678"


@pytest.fixture
def apdp() -> MockApdpClient:
    return MockApdpClient(default_decision="Allow")


@pytest.fixture
def handle(apdp: MockApdpClient) -> RunHandle:
    plugin = WatchlightBedrockPlugin(apdp_url="https://apdp.test")
    plugin.apdp = apdp
    agent = "1d2bdf18-1a89-4bd1-81ad-33269b484266"
    sid = f"ses_{uuid.uuid4()}"
    h = RunHandle(plugin=plugin, agent_uuid=agent, session_id=sid, run=apdp.open_run(sid, agent))
    h._aentered = True  # the test enters the run directly, as stub_handle does
    return h


def _client(service: str):
    return boto3.client(service, region_name="us-east-1", config=Config(signature_version=UNSIGNED))


@pytest.fixture
def rt_client():
    return _client("bedrock-agent-runtime")


@pytest.fixture
def agent_client():
    return _client("bedrock-agent")


class _Answers:
    """Answers ``InvokeAgent`` / ``InvokeInlineAgent`` on the real client.
    Stubber cannot stub an event stream, so a ``before-call`` responder
    answers instead (after the governed hook), checking the parameters
    the call was built from."""

    _OPS = {"invoke_agent": "InvokeAgent", "invoke_inline_agent": "InvokeInlineAgent"}

    def __init__(self, client) -> None:
        self._queue: list = []
        self._params: dict = {}
        for op in self._OPS.values():
            client.meta.events.register(f"before-parameter-build.bedrock-agent-runtime.{op}", self._seen)
            client.meta.events.register(f"before-call.bedrock-agent-runtime.{op}", self._respond)

    def _seen(self, params=None, model=None, **_):
        self._params[model.name] = dict(params)

    def _respond(self, model=None, **_):
        if not self._queue:
            raise AssertionError(f"unexpected {model.name}")
        op, response, expected = self._queue.pop(0)
        assert op == model.name, (op, model.name)
        if expected is not None:
            assert self._params[op] == expected
        return (AWSResponse("https://bedrock-agent-runtime.test", 200, {}, None), response)

    def add_response(self, op: str, response: dict, expected_params: dict = None) -> None:
        self._queue.append((self._OPS[op], response, expected_params))

    def assert_no_pending_responses(self) -> None:
        if self._queue:
            raise AssertionError(f"{len(self._queue)} responses not used")


@pytest.fixture
def rt(rt_client):
    return _Answers(rt_client)


@pytest.fixture
def ag(agent_client):
    with Stubber(agent_client) as s:
        yield s


@pytest.fixture
def governed(handle, rt_client, agent_client) -> GovernedBedrockAgentRuntime:
    return handle.bedrock_agent_runtime(rt_client, agent_client=agent_client, authorize_timeout_seconds=0.5)


# ── stubbed definitions ─────────────────────────────────────────────


def _alias(ag: Stubber, version: str) -> None:
    ag.add_response(
        "get_agent_alias",
        {
            "agentAlias": {
                "agentId": AGENT,
                "agentAliasId": ALIAS,
                "agentAliasName": "live",
                "agentAliasArn": f"arn:aws:bedrock:us-east-1:111122223333:agent-alias/{AGENT}/{ALIAS}",
                "routingConfiguration": [{"agentVersion": version}],
                "createdAt": "2026-10-01T00:00:00Z",
                "updatedAt": "2026-10-01T00:00:00Z",
                "agentAliasStatus": "PREPARED",
            }
        },
        {"agentId": AGENT, "agentAliasId": ALIAS},
    )


def _agent(ag: Stubber, version: str, collaboration: str = "DISABLED", **extra) -> None:
    body = {
        "agentId": AGENT,
        "agentName": "research",
        "agentArn": f"arn:aws:bedrock:us-east-1:111122223333:agent/{AGENT}",
        "instruction": "x" * 40,
        "agentStatus": "PREPARED",
        "foundationModel": "anthropic.claude-sonnet-4-5-20250929-v1:0",
        "idleSessionTTLInSeconds": 600,
        "agentResourceRoleArn": "arn:aws:iam::111122223333:role/agent",
        "createdAt": "2026-10-01T00:00:00Z",
        "updatedAt": "2026-10-01T00:00:00Z",
        "agentCollaboration": collaboration,
        **extra,
    }
    ag.add_response("get_agent", {"agent": {**body, "agentVersion": "DRAFT"}}, {"agentId": AGENT})
    if version != "DRAFT":
        # A version does not report its orchestration type.
        snapshot = {k: v for k, v in body.items() if k not in ("orchestrationType", "customOrchestration")}
        ag.add_response(
            "get_agent_version",
            {"agentVersion": {**snapshot, "version": version}},
            {"agentId": AGENT, "agentVersion": version},
        )


def _groups(ag: Stubber, version: str, groups: list) -> None:
    """``groups``: (id, signature or None, state)."""
    ag.add_response(
        "list_agent_action_groups",
        {
            "actionGroupSummaries": [
                {"actionGroupId": gid, "actionGroupName": gid.lower(), "actionGroupState": state,
                 "updatedAt": "2026-10-01T00:00:00Z"}
                for gid, _sig, state in groups
            ]
        },
        {"agentId": AGENT, "agentVersion": version},
    )
    for gid, sig, state in groups:
        if state != "ENABLED":
            continue
        group = {
            "agentId": AGENT,
            "agentVersion": version,
            "actionGroupId": gid,
            "actionGroupName": gid.lower(),
            "createdAt": "2026-10-01T00:00:00Z",
            "updatedAt": "2026-10-01T00:00:00Z",
            "actionGroupState": state,
        }
        if sig is not None:
            group["parentActionSignature"] = sig
        ag.add_response(
            "get_agent_action_group",
            {"agentActionGroup": group},
            {"agentId": AGENT, "agentVersion": version, "actionGroupId": gid},
        )


def _kbs(ag: Stubber, version: str, kbs: list) -> None:
    ag.add_response(
        "list_agent_knowledge_bases",
        {
            "agentKnowledgeBaseSummaries": [
                {"knowledgeBaseId": kb, "knowledgeBaseState": state, "updatedAt": "2026-10-01T00:00:00Z"}
                for kb, state in kbs
            ]
        },
        {"agentId": AGENT, "agentVersion": version},
    )


def _definition(ag: Stubber, version: str, groups: list = (), kbs: list = (), collaboration: str = "DISABLED"):
    _agent(ag, version, collaboration)
    _groups(ag, version, list(groups))
    _kbs(ag, version, list(kbs))


def _invoke_ok(rt: Stubber) -> None:
    rt.add_response(
        "invoke_agent",
        {"completion": [], "contentType": "application/json", "sessionId": "s1"},
    )


def _permit(apdp: MockApdpClient, version: str) -> None:
    """Policy names this agent version."""
    apdp.decisions[("invoke_agent_version", f"bedrock://agent/{AGENT}/version/{version}")] = "Allow"


def _hosted_calls(apdp: MockApdpClient) -> list:
    return [c for c in apdp.authorize_calls if c["resource"].startswith('Tool::"')]


async def _invoke(governed, **extra):
    return await governed.invoke_agent(agentId=AGENT, agentAliasId=ALIAS, sessionId="s1", inputText="go", **extra)


# ── invoke_agent ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_a_denied_code_interpreter_refuses_the_call_before_it_is_made(governed, rt, ag, apdp):
    apdp.default_decision = "Deny"
    _permit(apdp, "3")
    _alias(ag, "3")
    _definition(ag, "3", groups=[("CI", "AMAZON.CodeInterpreter", "ENABLED")])
    _invoke_ok(rt)

    with pytest.raises(HostedToolRefused):
        await _invoke(governed)

    with pytest.raises(AssertionError):
        rt.assert_no_pending_responses()  # invoke_agent was never called
    calls = _hosted_calls(apdp)
    assert [c["resource"] for c in calls] == ['Tool::"code_interpreter"']
    assert calls[0]["context"]["builtin_tool"] is True


@pytest.mark.asyncio
async def test_allowed_capabilities_are_each_decided_then_the_call_is_made(governed, rt, ag, apdp):
    _alias(ag, "3")
    _definition(
        ag,
        "3",
        groups=[
            ("CI", "AMAZON.CodeInterpreter", "ENABLED"),
            ("ASK", "AMAZON.UserInput", "ENABLED"),
            ("LAMBDA", None, "ENABLED"),
            ("OFF", "ANTHROPIC.Bash", "DISABLED"),
        ],
        kbs=[(KB, "ENABLED"), ("KBOFF00000", "DISABLED")],
    )
    _invoke_ok(rt)

    await _invoke(governed)

    rt.assert_no_pending_responses()
    assert sorted(c["resource"] for c in _hosted_calls(apdp)) == [
        'Tool::"code_interpreter"',
        'Tool::"knowledge_base_retrieval"',
        'Tool::"user_input"',
    ]


@pytest.mark.asyncio
async def test_the_anthropic_signatures_are_hosted_capabilities(governed, rt, ag, apdp):
    _alias(ag, "3")
    _definition(
        ag,
        "3",
        groups=[
            ("PC", "ANTHROPIC.Computer", "ENABLED"),
            ("SH", "ANTHROPIC.Bash", "ENABLED"),
            ("ED", "ANTHROPIC.TextEditor", "ENABLED"),
        ],
    )
    _invoke_ok(rt)

    await _invoke(governed)

    assert sorted(c["resource"] for c in _hosted_calls(apdp)) == [
        'Tool::"bash"',
        'Tool::"computer_use"',
        'Tool::"text_editor"',
    ]


@pytest.mark.asyncio
async def test_an_unreadable_definition_refuses_the_call(governed, rt, ag, apdp):
    _alias(ag, "3")
    _agent(ag, "3")
    ag.add_client_error("list_agent_action_groups", service_error_code="AccessDeniedException", http_status_code=403)
    _invoke_ok(rt)

    with pytest.raises(BedrockRequestRefused) as exc:
        await _invoke(governed)

    assert exc.value.reason == "agent_definition_unreadable"
    with pytest.raises(AssertionError):
        rt.assert_no_pending_responses()


@pytest.mark.asyncio
async def test_an_unresolvable_alias_refuses_the_call(governed, rt, ag, apdp):
    ag.add_client_error("get_agent_alias", service_error_code="ResourceNotFoundException", http_status_code=404)
    _invoke_ok(rt)

    with pytest.raises(BedrockRequestRefused) as exc:
        await _invoke(governed)

    assert exc.value.reason == "agent_definition_unreadable"


@pytest.mark.asyncio
async def test_the_definition_is_cached_per_version_but_the_alias_is_read_every_call(governed, rt, ag, apdp):
    _alias(ag, "3")
    _definition(ag, "3", groups=[("CI", "AMAZON.CodeInterpreter", "ENABLED")])
    _invoke_ok(rt)
    _alias(ag, "3")  # the second call reads the alias again, and nothing else
    _invoke_ok(rt)

    await _invoke(governed)
    await _invoke(governed)

    ag.assert_no_pending_responses()
    rt.assert_no_pending_responses()


@pytest.mark.asyncio
async def test_a_repointed_alias_is_gated_on_the_new_version(governed, rt, ag, apdp):
    _alias(ag, "3")
    _definition(ag, "3")
    _invoke_ok(rt)
    await _invoke(governed)
    assert _hosted_calls(apdp) == []

    apdp.default_decision = "Deny"
    _permit(apdp, "4")
    _alias(ag, "4")
    _definition(ag, "4", groups=[("CI", "AMAZON.CodeInterpreter", "ENABLED")])
    _invoke_ok(rt)

    with pytest.raises(HostedToolRefused):
        await _invoke(governed)


@pytest.mark.asyncio
async def test_draft_is_never_cached(governed, rt, ag, apdp):
    for _ in range(2):
        _alias(ag, "DRAFT")
        _definition(ag, "DRAFT", groups=[("CI", "AMAZON.CodeInterpreter", "ENABLED")])
        _invoke_ok(rt)

    await _invoke(governed)
    await _invoke(governed)

    ag.assert_no_pending_responses()


@pytest.mark.asyncio
async def test_an_unknown_signature_is_denied_without_a_decision(governed, rt, ag, apdp, monkeypatch):
    _alias(ag, "3")
    _definition(ag, "3", groups=[("NEW", "AMAZON.CodeInterpreter", "ENABLED")])
    _invoke_ok(rt)
    # A signature this plugin does not know (a future AWS value).
    import watchlight_bedrock.agent_runtime as ar

    monkeypatch.setattr(ar, "_SIGNATURE_KINDS", {})

    with pytest.raises(HostedToolRefused):
        await _invoke(governed)
    assert _hosted_calls(apdp) == []


@pytest.mark.asyncio
async def test_a_supervisor_agent_is_refused(governed, rt, ag, apdp):
    _alias(ag, "3")
    _definition(ag, "3", collaboration="SUPERVISOR_ROUTER")
    _invoke_ok(rt)

    with pytest.raises(BedrockRequestRefused) as exc:
        await _invoke(governed)

    assert exc.value.reason == "supervisor_unsupported"


@pytest.mark.asyncio
async def test_a_knowledge_base_passed_on_the_call_is_gated_even_when_the_agent_lists_none(governed, rt, ag, apdp):
    apdp.default_decision = "Deny"
    _permit(apdp, "3")
    _alias(ag, "3")
    _definition(ag, "3")
    _invoke_ok(rt)

    with pytest.raises(HostedToolRefused):
        await _invoke(governed, sessionState={"knowledgeBaseConfigurations": [
            {"knowledgeBaseId": KB, "retrievalConfiguration": {"vectorSearchConfiguration": {"numberOfResults": 3}}}
        ]})
    assert [c["resource"] for c in _hosted_calls(apdp)] == ['Tool::"knowledge_base_retrieval"']


@pytest.mark.asyncio
async def test_a_knowledge_base_on_the_call_without_an_id_is_refused(governed, rt, ag, apdp):
    _alias(ag, "3")
    _definition(ag, "3")
    _invoke_ok(rt)

    with pytest.raises(BedrockRequestRefused) as exc:
        await _invoke(governed, sessionState={"knowledgeBaseConfigurations": [{"knowledgeBaseId": ""}]})
    assert exc.value.reason == "knowledge_base_unresolved"


@pytest.mark.asyncio
async def test_a_run_ending_decision_raises_its_typed_error(governed, rt, ag, apdp):
    apdp.default_decision = "Quarantine"
    _alias(ag, "3")
    _definition(ag, "3", groups=[("CI", "AMAZON.CodeInterpreter", "ENABLED")])
    _invoke_ok(rt)

    with pytest.raises(AgentQuarantinedError):
        await _invoke(governed)


@pytest.mark.asyncio
async def test_the_wrapper_adds_the_session_attributes(governed, rt, ag, apdp, handle):
    _alias(ag, "3")
    _definition(ag, "3")
    rt.add_response(
        "invoke_agent",
        {"completion": [], "contentType": "application/json", "sessionId": "s1"},
        {
            "agentId": AGENT,
            "agentAliasId": ALIAS,
            "sessionId": "s1",
            "inputText": "go",
            "enableTrace": True,
            "sessionState": {"sessionAttributes": {
                "keep": "me",
                "watchlight_session_id": handle.session_id,
                "watchlight_agent_id": handle.agent_uuid,
            }},
        },
    )

    await _invoke(governed, sessionState={"sessionAttributes": {"keep": "me"}})

    rt.assert_no_pending_responses()


@pytest.mark.asyncio
async def test_a_caller_cannot_override_the_watchlight_session_attributes(governed, rt, ag, apdp):
    _invoke_ok(rt)

    with pytest.raises(BedrockRequestRefused) as exc:
        await _invoke(governed, sessionState={"sessionAttributes": {"watchlight_session_id": "ses_other"}})
    assert exc.value.reason == "session_attributes_conflict"


@pytest.mark.asyncio
async def test_a_direct_call_on_the_governed_client_is_refused(governed, rt_client, rt):
    _invoke_ok(rt)

    with pytest.raises(BedrockRequestRefused):
        rt_client.invoke_agent(agentId=AGENT, agentAliasId=ALIAS, sessionId="s1", inputText="go")


def test_the_session_attributes_are_not_handed_out_for_raw_calls(handle):
    assert not hasattr(handle, "bedrock_session_attributes")
    assert not hasattr(handle, "bedrock_collaborator_session_attributes")


def test_the_wrapper_needs_the_right_clients(handle, rt_client, agent_client):
    with pytest.raises(TypeError):
        handle.bedrock_agent_runtime(agent_client, agent_client=agent_client)
    with pytest.raises(TypeError):
        handle.bedrock_agent_runtime(rt_client, agent_client=rt_client)


# ── invoke_inline_agent ─────────────────────────────────────────────


def _inline_ok(rt: Stubber) -> None:
    rt.add_response("invoke_inline_agent", {"completion": [], "contentType": "application/json", "sessionId": "s1"})


async def _inline(governed, **extra):
    return await governed.invoke_inline_agent(
        sessionId="s1",
        foundationModel="anthropic.claude-sonnet-4-5-20250929-v1:0",
        instruction="x" * 40,
        inputText="go",
        **extra,
    )


@pytest.mark.asyncio
async def test_inline_capabilities_are_gated_from_the_request(governed, rt, apdp):
    apdp.default_decision = "Deny"
    _inline_ok(rt)

    with pytest.raises(HostedToolRefused):
        await _inline(governed, actionGroups=[
            {"actionGroupName": "ci", "parentActionGroupSignature": "AMAZON.CodeInterpreter"},
        ])
    with pytest.raises(AssertionError):
        rt.assert_no_pending_responses()


@pytest.mark.asyncio
async def test_inline_capabilities_and_knowledge_bases_are_each_decided(governed, rt, apdp):
    _inline_ok(rt)

    await _inline(
        governed,
        actionGroups=[
            {"actionGroupName": "ci", "parentActionGroupSignature": "AMAZON.CodeInterpreter"},
            {"actionGroupName": "plain", "actionGroupExecutor": {"customControl": "RETURN_CONTROL"},
             "functionSchema": {"functions": [{"name": "f"}]}},
        ],
        knowledgeBases=[{"knowledgeBaseId": KB, "description": "docs"}],
    )

    rt.assert_no_pending_responses()
    assert sorted(c["resource"] for c in _hosted_calls(apdp)) == [
        'Tool::"code_interpreter"',
        'Tool::"knowledge_base_retrieval"',
    ]


@pytest.mark.asyncio
async def test_inline_collaborators_are_refused(governed, rt, apdp):
    _inline_ok(rt)

    with pytest.raises(BedrockRequestRefused) as exc:
        await _inline(governed, agentCollaboration="SUPERVISOR", collaborators=[
            {"foundationModel": "anthropic.claude-sonnet-4-5-20250929-v1:0", "instruction": "x" * 40, "agentName": "c"},
        ])
    assert exc.value.reason == "supervisor_unsupported"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "extra, reason",
    [
        ({"orchestrationType": "CUSTOM_ORCHESTRATION",
          "customOrchestration": {"executor": {"lambda": "arn:aws:lambda:us-east-1:111122223333:function:orch"}}},
         "custom_orchestration_unsupported"),
        ({"promptOverrideConfiguration": {
            "overrideLambda": "arn:aws:lambda:us-east-1:111122223333:function:parser",
            "promptConfigurations": [{"promptType": "ORCHESTRATION", "parserMode": "OVERRIDDEN"}]}},
         "prompt_override_lambda_unsupported"),
    ],
)
async def test_an_agent_running_a_customer_lambda_in_its_loop_is_refused(governed, rt, ag, apdp, extra, reason):
    _alias(ag, "3")
    _agent(ag, "3", **extra)
    _invoke_ok(rt)

    with pytest.raises(BedrockRequestRefused) as exc:
        await _invoke(governed)

    assert exc.value.reason == reason
    with pytest.raises(AssertionError):
        rt.assert_no_pending_responses()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "extra, reason",
    [
        ({"orchestrationType": "CUSTOM_ORCHESTRATION",
          "customOrchestration": {"executor": {"lambda": "arn:aws:lambda:us-east-1:111122223333:function:orch"}}},
         "custom_orchestration_unsupported"),
        ({"promptOverrideConfiguration": {
            "overrideLambda": "arn:aws:lambda:us-east-1:111122223333:function:parser",
            "promptConfigurations": [{"promptType": "ORCHESTRATION", "parserMode": "OVERRIDDEN"}]}},
         "prompt_override_lambda_unsupported"),
    ],
)
async def test_an_inline_agent_running_a_customer_lambda_in_its_loop_is_refused(governed, rt, apdp, extra, reason):
    _inline_ok(rt)

    with pytest.raises(BedrockRequestRefused) as exc:
        await _inline(governed, **extra)

    assert exc.value.reason == reason
    with pytest.raises(AssertionError):
        rt.assert_no_pending_responses()


# ── a client nobody wrapped ─────────────────────────────────

_RUNS = [
    ("invoke_agent", {"agentId": AGENT, "agentAliasId": ALIAS, "sessionId": "s1", "inputText": "go"}),
    ("invoke_inline_agent", {"sessionId": "s1", "inputText": "go", "foundationModel": "m", "instruction": "i" * 40}),
    ("retrieve", {"knowledgeBaseId": KB, "retrievalQuery": {"text": "q"}}),
    ("invoke_flow", {"flowIdentifier": "FLOW123456", "flowAliasIdentifier": "ALIAS12345", "inputs": []}),
]


def _unwrapped(session: "boto3.Session | None" = None):
    make = session.client if session is not None else boto3.client
    return make("bedrock-agent-runtime", region_name="us-east-1", config=Config(signature_version=UNSIGNED))


@pytest.mark.parametrize("operation,params", _RUNS, ids=[op for op, _ in _RUNS])
@pytest.mark.parametrize("where", ["new_session", "default_session"])
def test_an_unwrapped_client_created_after_the_plugin_is_refused(operation, params, where):
    WatchlightBedrockPlugin(apdp_url="https://apdp.test")
    client = _unwrapped(boto3.Session() if where == "new_session" else None)
    sent: list = []

    def send(request, **_):
        sent.append(request)
        raise AssertionError("the request was sent")

    client.meta.events.register("before-send.bedrock-agent-runtime", send)
    with pytest.raises(BedrockRequestRefused) as refused:
        getattr(client, operation)(**params)
    assert refused.value.reason == "ungoverned_call"
    assert sent == []


def test_bookkeeping_on_an_unwrapped_client_is_not_refused():
    WatchlightBedrockPlugin(apdp_url="https://apdp.test")
    client = _unwrapped(boto3.Session())
    with Stubber(client) as stub:
        stub.add_response(
            "get_session",
            {
                "sessionId": "s1",
                "sessionArn": "arn:aws:bedrock:us-east-1:123456789012:session/s1",
                "sessionStatus": "ACTIVE",
                "createdAt": "2026-10-29T00:00:00Z",
                "lastUpdatedAt": "2026-10-29T00:00:00Z",
            },
        )
        assert client.get_session(sessionIdentifier="s1")["sessionId"] == "s1"


@pytest.mark.asyncio
async def test_a_wrapped_call_still_goes_through_on_a_client_created_after_the_plugin(handle, agent_client):
    client = _unwrapped(boto3.Session())
    rt = _Answers(client)
    governed = handle.bedrock_agent_runtime(client, agent_client=agent_client, authorize_timeout_seconds=0.5)
    with Stubber(agent_client) as ag:
        _alias(ag, "1")
        _definition(ag, "1")
        _invoke_ok(rt)
        await _invoke(governed)
    rt.assert_no_pending_responses()


def test_installing_the_guard_again_adds_nothing():
    from botocore import handlers

    from watchlight_bedrock.agent_runtime import install_unwrapped_call_guard

    assert install_unwrapped_call_guard() is True
    install_unwrapped_call_guard()
    guards = [s for s in handlers.BUILTIN_HANDLERS if s[0] == "before-parameter-build.bedrock-agent-runtime"]
    assert len(guards) == 1


def _without_event_guard(client):
    """As a client created before the plugin was: the event-level check
    was never registered on it, so only the class-level check applies."""
    from watchlight_bedrock.agent_runtime import _GUARD_EVENT, _refuse_unwrapped_call

    client.meta.events.unregister(_GUARD_EVENT, _refuse_unwrapped_call)
    return client


def _no_send(client) -> list:
    sent: list = []

    def send(request, **_):
        sent.append(request)
        raise AssertionError("the request was sent")

    client.meta.events.register("before-send.bedrock-agent-runtime", send)
    return sent


@pytest.mark.parametrize("operation,params", _RUNS, ids=[op for op, _ in _RUNS])
@pytest.mark.parametrize("made", ["client_before_the_plugin", "client_from_an_earlier_session"])
def test_a_client_that_predates_the_plugin_is_refused(operation, params, made):
    if made == "client_from_an_earlier_session":
        from watchlight_bedrock.agent_runtime import _GUARD_EVENT, _refuse_unwrapped_call

        earlier = boto3.Session()
        earlier.events.unregister(_GUARD_EVENT, _refuse_unwrapped_call)
        client = _unwrapped(earlier)
    else:
        client = _without_event_guard(_unwrapped(boto3.Session()))
    WatchlightBedrockPlugin(apdp_url="https://apdp.test")
    sent = _no_send(client)
    with pytest.raises(BedrockRequestRefused) as refused:
        getattr(client, operation)(**params)
    assert refused.value.reason == "ungoverned_call"
    assert sent == []


_STORED_OR_DESTRUCTIVE = [
    ("get_agent_memory", {"agentId": AGENT, "agentAliasId": ALIAS, "memoryType": "SESSION_SUMMARY", "memoryId": "m1"}),
    ("delete_agent_memory", {"agentId": AGENT, "agentAliasId": ALIAS}),
    ("delete_session", {"sessionIdentifier": "s1"}),
    ("get_invocation_step", {"sessionIdentifier": "s1", "invocationIdentifier": "i1", "invocationStepId": "st1"}),
    ("list_invocation_steps", {"sessionIdentifier": "s1"}),
    ("stop_flow_execution", {"flowIdentifier": "FLOW123456", "flowAliasIdentifier": "ALIAS12345", "executionIdentifier": "e1"}),
    ("list_flow_execution_events", {"flowIdentifier": "FLOW123456", "flowAliasIdentifier": "ALIAS12345", "executionIdentifier": "e1", "eventType": "Flow"}),
]


@pytest.mark.parametrize("operation,params", _STORED_OR_DESTRUCTIVE, ids=[op for op, _ in _STORED_OR_DESTRUCTIVE])
def test_stored_content_reads_deletes_and_flow_control_are_refused(operation, params):
    WatchlightBedrockPlugin(apdp_url="https://apdp.test")
    client = _without_event_guard(_unwrapped(boto3.Session()))
    sent = _no_send(client)
    with pytest.raises(BedrockRequestRefused):
        getattr(client, operation)(**params)
    assert sent == []


@pytest.mark.asyncio
async def test_a_call_on_another_client_made_inside_a_wrapped_call_is_refused(handle, agent_client):
    other = _without_event_guard(_unwrapped(boto3.Session()))
    other_sent = _no_send(other)
    client = _unwrapped(boto3.Session())
    rt = _Answers(client)
    inside: list = []

    def during_the_wrapped_call(**_):
        try:
            other.invoke_agent(agentId=AGENT, agentAliasId=ALIAS, sessionId="s2", inputText="go")
        except BedrockRequestRefused as exc:
            inside.append(exc.reason)

    client.meta.events.register_first("before-call.bedrock-agent-runtime.InvokeAgent", during_the_wrapped_call)
    governed = handle.bedrock_agent_runtime(client, agent_client=agent_client, authorize_timeout_seconds=0.5)
    with Stubber(agent_client) as ag:
        _alias(ag, "1")
        _definition(ag, "1")
        _invoke_ok(rt)
        await _invoke(governed)
    assert inside == ["ungoverned_call"]
    assert other_sent == []


def test_the_class_level_check_is_in_place():
    from botocore.client import BaseClient

    WatchlightBedrockPlugin(apdp_url="https://apdp.test")
    assert getattr(BaseClient._make_api_call, "__watchlight_guard__", False) is True
