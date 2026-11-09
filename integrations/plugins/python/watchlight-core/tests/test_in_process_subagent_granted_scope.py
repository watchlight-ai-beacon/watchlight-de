"""The in-process backend checks every sub-agent call against its grant.

wl-apdp refuses a sub-agent's call outside the tools (resources, intents)
its spawn granted, before Cedar runs, invalidates the sub-agent's run handle
on such a violation (every later call is refused) and records
``scope_violation_observed``; preflight previews the same check without
invalidating. The Developer Edition's ``InProcessClient`` does the same,
through the engine's ``check_scope_membership``, which parses the intent with
wl-apdp's own type, so the category comes only from the typed ``intent``.
"""

import json
from uuid import uuid4

import pytest

pytest.importorskip("watchlight_engine")

from watchlight_core.errors import ScopeAttenuationDenied  # noqa: E402
from watchlight_core.in_process_client import InProcessClient  # noqa: E402
from watchlight_core.scope import (  # noqa: E402
    ChildIntent,
    RequestedScope,
    SpawnSubagentRequest,
    spawn_subagent_request_to_dict,
)

ALLOW_ALL = [{"name": "allow-all", "code": "permit(principal, action, resource);"}]


def _request(parent_handle, tools, intents=(), max_depth=1, time_budget=600):
    return spawn_subagent_request_to_dict(
        SpawnSubagentRequest(
            parent_agent_id=uuid4(),
            child_agent_id=uuid4(),
            parent_run_handle_id=parent_handle,
            # Every spawn declares the child's intent; the child is
            # granted exactly its category, so a pinned intent names it.
            child_intent=ChildIntent(
                category=intents[0] if intents else "research",
                objective="Delegated sub-task",
            ),
            requested_scope=RequestedScope(
                allowed_tools=list(tools),
                allowed_resources=[],
                allowed_intents=list(intents),
                max_depth=max_depth,
                time_budget_seconds=time_budget,
            ),
        )
    )


async def _child(client, tools, intents=()):
    session = await client.create_session(agent_id=str(uuid4()))
    response = await client.spawn_subagent(
        session.run, _request(session.root_run_handle_id, tools, intents)
    )
    return session, response["child_run"], response["child_run_handle_id"]


async def _decide(client, run, resource, intent=None, context=None):
    return await client.authorize(
        principal='Agent::"a"', action="execute", resource=resource,
        context=context or {}, run=run, intent=intent,
    )


def _audit(path):
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


@pytest.mark.asyncio
async def test_a_child_is_refused_a_tool_its_spawn_did_not_grant(tmp_path):
    client = InProcessClient(ALLOW_ALL, audit_path=str(tmp_path / "a.jsonl"))
    root, child, _ = await _child(client, ["web_search"])

    assert (await _decide(client, child, "web_search"))["decision"] == "Allow"
    denied = await _decide(client, child, "send_email")
    assert denied["decision"] == "Deny"
    assert denied["reason"].startswith("scope_attenuation_violation (")
    # The root is not a sub-agent: policy alone decides.
    assert (await _decide(client, root.run, "send_email"))["decision"] == "Allow"


@pytest.mark.asyncio
async def test_a_violation_invalidates_the_child_and_is_recorded(tmp_path):
    audit = tmp_path / "a.jsonl"
    client = InProcessClient(ALLOW_ALL, audit_path=str(audit))
    _root, child, handle = await _child(client, ["web_search"])

    assert (await _decide(client, child, "send_email"))["decision"] == "Deny"
    # As wl-apdp: the handle is invalidated, so even a granted tool is
    # refused from now on, with the server's reason.
    later = await _decide(client, child, "web_search")
    assert later["decision"] == "Deny"
    assert later["reason"] == "run_handle_invalidated (out_of_scope_tool_call)"
    preflight = await client.preflight_step(child, "execute", "web_search")
    assert preflight["preflight"]["decision"] == "Deny"

    records = [r for r in _audit(audit) if r.get("event") == "scope_violation_observed"]
    assert len(records) == 1
    assert records[0]["node_id"] == handle
    assert records[0]["reason"] == "out_of_scope_tool_call"
    assert "AllowedTools" in records[0]["violations"]

    # An invalidated handle cannot spawn: the grandchild never runs.
    with pytest.raises(ScopeAttenuationDenied):
        await client.spawn_subagent(child, _request(handle, []))


@pytest.mark.asyncio
async def test_preflight_previews_a_violation_without_invalidating(tmp_path):
    audit = tmp_path / "a.jsonl"
    client = InProcessClient(ALLOW_ALL, audit_path=str(audit))
    _root, child, _ = await _child(client, ["web_search"])

    result = await client.preflight_step(child, "execute", "send_email")
    assert result["preflight"]["decision"] == "Deny"
    # Nothing was invalidated: the granted tool still runs.
    assert (await _decide(client, child, "web_search"))["decision"] == "Allow"
    assert not [r for r in _audit(audit) if r.get("event") == "scope_violation_observed"]


@pytest.mark.asyncio
async def test_the_intent_category_comes_only_from_the_typed_intent(tmp_path):
    client = InProcessClient(ALLOW_ALL, audit_path=str(tmp_path / "a.jsonl"))
    _root, child, _ = await _child(client, ["web_search"], intents=["research"])

    allowed = await _decide(
        client, child, "web_search", intent={"objective": "look", "category": "research"}
    )
    assert allowed["decision"] == "Allow"
    # A context field cannot stand in for the typed category.
    spoofed = await _decide(
        client, child, "web_search",
        intent={"objective": "pay", "category": "financial_operation"},
        context={"intent_category": "research"},
    )
    assert spoofed["decision"] == "Deny"
    assert "scope_attenuation_violation" in spoofed["reason"]


@pytest.mark.asyncio
async def test_a_custom_category_matches_as_the_server_renders_it(tmp_path):
    client = InProcessClient(ALLOW_ALL, audit_path=str(tmp_path / "a.jsonl"))
    _root, child, _ = await _child(client, ["web_search"], intents=["foo"])
    # wl-apdp cannot parse a bare "foo" category, so it refuses the request.
    raw = await _decide(client, child, "web_search", intent={"objective": "x", "category": "foo"})
    assert raw["decision"] == "Deny"
    assert raw["reason"].startswith("invalid_intent")

    other = InProcessClient(ALLOW_ALL, audit_path=str(tmp_path / "b.jsonl"))
    _root, child2, _ = await _child(other, ["web_search"], intents=["foo"])
    # A typed custom category renders as "custom:foo", which a grant of
    # "foo" does not name.
    typed = await _decide(
        other, child2, "web_search", intent={"objective": "x", "category": {"custom": "foo"}}
    )
    assert typed["decision"] == "Deny"

    third = InProcessClient(ALLOW_ALL, audit_path=str(tmp_path / "c.jsonl"))
    _root, child3, _ = await _child(third, ["web_search"], intents=["custom:foo"])
    granted = await _decide(
        third, child3, "web_search", intent={"objective": "x", "category": {"custom": "foo"}}
    )
    assert granted["decision"] == "Allow"


class _OlderEngine:
    """The engine as 0.2.3 shipped it: no check_scope_membership."""

    def __init__(self, inner):
        self._inner = inner

    def authorize(self, request):
        return self._inner.authorize(request)

    def attenuate_scope(self, parent, requested):
        return self._inner.attenuate_scope(parent, requested)


@pytest.mark.asyncio
async def test_an_engine_without_the_check_refuses_every_sub_agent_call(tmp_path):
    client = InProcessClient(ALLOW_ALL, audit_path=str(tmp_path / "a.jsonl"))
    root, child, _ = await _child(client, ["web_search"])
    client._engine = _OlderEngine(client._engine)
    denied = await _decide(client, child, "web_search")
    assert denied["decision"] == "Deny"
    assert "subagent_scope_unenforceable" in denied["reason"]
    assert (await _decide(client, root.run, "web_search"))["decision"] == "Allow"


@pytest.mark.asyncio
async def test_an_engine_without_the_check_refuses_the_spawn(tmp_path):
    client = InProcessClient(ALLOW_ALL, audit_path=str(tmp_path / "a.jsonl"))
    client._engine = _OlderEngine(client._engine)
    session = await client.create_session(agent_id=str(uuid4()))
    with pytest.raises(ScopeAttenuationDenied, match="not started"):
        await client.spawn_subagent(
            session.run, _request(session.root_run_handle_id, ["web_search"])
        )


@pytest.mark.asyncio
async def test_a_root_naming_a_child_handle_neither_borrows_nor_invalidates_it(tmp_path):
    """As wl-apdp (run_handle_principal_mismatch): another run's handle named
    in the context is refused before any scope check, so that call does not
    invalidate it."""
    client = InProcessClient(ALLOW_ALL, audit_path=str(tmp_path / "a.jsonl"))
    root, child, handle = await _child(client, ["web_search"])
    named = await _decide(client, root.run, "send_email", context={"run_handle_id": handle})
    assert named["decision"] == "Deny"
    assert named["reason"] == "run_handle_principal_mismatch"
    # The child is untouched: its granted tool still runs.
    assert (await _decide(client, child, "web_search"))["decision"] == "Allow"


@pytest.mark.asyncio
async def test_a_call_naming_no_run_never_invalidates_a_handle(tmp_path):
    client = InProcessClient(ALLOW_ALL, audit_path=str(tmp_path / "a.jsonl"))
    _root, child, handle = await _child(client, ["web_search"])
    named = await client.authorize(
        principal='Agent::"a"', action="execute", resource="send_email",
        context={"run_handle_id": handle},
    )
    assert named["decision"] == "Deny"
    assert (await _decide(client, child, "web_search"))["decision"] == "Allow"


@pytest.mark.asyncio
async def test_an_empty_intent_is_no_intent(tmp_path):
    # An empty intent is no intent: a derived child's call that names none
    # acts under its derived category (decision 5), the only one its
    # spawn granted.
    client = InProcessClient(ALLOW_ALL, audit_path=str(tmp_path / "a.jsonl"))
    _root, child, _ = await _child(client, ["web_search"], intents=["research"])
    allowed = await _decide(client, child, "web_search", intent={})
    assert allowed["decision"] == "Allow", allowed


@pytest.mark.asyncio
async def test_a_derived_child_without_an_intent_acts_under_its_derived_category(tmp_path):
    client = InProcessClient(ALLOW_ALL, audit_path=str(tmp_path / "a.jsonl"))
    _root, child, _ = await _child(client, ["web_search"], intents=["research"])
    assert (await _decide(client, child, "web_search"))["decision"] == "Allow"
    after = await _decide(
        client, child, "web_search", intent={"objective": "look up", "category": "research"}
    )
    assert after["decision"] == "Allow", after
    # The intent-less call still meets the tool dimension.
    denied = await _decide(client, child, "send_email")
    assert denied["decision"] == "Deny"
    assert "scope_attenuation_violation" in denied["reason"]
    # An intent outside the grant invalidates the handle.
    other = InProcessClient(ALLOW_ALL, audit_path=str(tmp_path / "b.jsonl"))
    _root, child2, _ = await _child(other, ["web_search"], intents=["research"])
    bad = await _decide(
        other, child2, "web_search", intent={"objective": "x", "category": "code_generation"}
    )
    assert "scope_attenuation_violation" in bad["reason"]
    gone = await _decide(
        other, child2, "web_search", intent={"objective": "look up", "category": "research"}
    )
    assert "run_handle_invalidated" in gone["reason"]


@pytest.mark.asyncio
async def test_a_model_turn_without_intent_is_exempt(tmp_path):
    client = InProcessClient(ALLOW_ALL, audit_path=str(tmp_path / "a.jsonl"))
    _root, child, _ = await _child(client, ["web_search"], intents=["research"])
    turn = await client.authorize(
        principal='Agent::"a"', action='Action::"chat"', resource='Model::"m"',
        context={}, run=child,
    )
    assert turn["decision"] == "Allow", turn


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "action",
    ['Action::"transfer_funds"', "transfer_funds", "execute",
     # Only the Cedar Action entity ``chat`` is a model turn, never another
     # entity type with the same id.
     'Document::"chat"', 'Tool::"chat"', 'Ns::Action::"chat"'],
)
async def test_only_the_chat_action_on_a_model_is_a_model_turn(tmp_path, action):
    # Another action on a Model:: resource is checked against the grant.
    client = InProcessClient(ALLOW_ALL, audit_path=str(tmp_path / "a.jsonl"))
    _root, child, _ = await _child(client, ["web_search"], intents=["research"])
    denied = await client.authorize(
        principal='Agent::"a"', action=action, resource='Model::"gemini-chat"',
        context={}, run=child,
    )
    assert denied["decision"] == "Deny", denied
    assert "scope_attenuation_violation" in denied["reason"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "resource",
    ['Resource::"deepagents://tool/delete_all"', 'Tool::"mcp://bank/transfer"',
     "mcp://bank/transfer", 'Resource::"transfer_funds "', 'Resource::"tr\u0430nsfer_funds"',
     'Resource::"transfer%5Ffunds"', "../transfer_funds", 'Ns::Tool::"transfer_funds"'],
)
async def test_a_granted_tool_as_action_reaches_no_other_tool(tmp_path, resource):
    client = InProcessClient(ALLOW_ALL, audit_path=str(tmp_path / "a.jsonl"))
    _root, child, _ = await _child(client, ["web_search"])
    denied = await client.authorize(
        principal='Agent::"a"', action="web_search", resource=resource, context={}, run=child
    )
    assert denied["decision"] == "Deny", resource


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "resource",
    ["transfer_funds", 'Resource::"transfer_funds"', 'Tool::"delete_all"', 'Secret::"prod"',
     'Document::"q3"', "deepagents://tool/delete_all"],
)
async def test_an_execute_named_grant_does_not_authorize_other_tools(tmp_path, resource):
    # DeepAgents' sandbox shell tool is literally named `execute`, and every
    # plugin authorizes a tool call as action="execute": the grant must be
    # matched on the tool, never on the verb.
    client = InProcessClient(ALLOW_ALL, audit_path=str(tmp_path / "a.jsonl"))
    _root, child, _ = await _child(client, ["execute"])
    denied = await _decide(client, child, resource)
    assert denied["decision"] == "Deny", resource
    assert "scope_attenuation_violation" in denied["reason"]


@pytest.mark.asyncio
async def test_an_execute_named_grant_authorizes_the_execute_tool(tmp_path):
    client = InProcessClient(ALLOW_ALL, audit_path=str(tmp_path / "a.jsonl"))
    _root, child, _ = await _child(client, ["execute"])
    assert (await _decide(client, child, "execute"))["decision"] == "Allow"


@pytest.mark.asyncio
@pytest.mark.parametrize("resource", ['Tool::"transfer_funds"', "transfer_funds", 'Secret::"prod"'])
async def test_a_search_grant_does_not_authorize_action_search_on_other_resources(
    tmp_path, resource
):
    client = InProcessClient(ALLOW_ALL, audit_path=str(tmp_path / "a.jsonl"))
    _root, child, _ = await _child(client, ["search"])
    denied = await client.authorize(
        principal='Agent::"a"', action="search", resource=resource, context={}, run=child
    )
    assert denied["decision"] == "Deny", resource
    assert "scope_attenuation_violation" in denied["reason"]
    # The tool named `search` itself is still granted.
    other = InProcessClient(ALLOW_ALL, audit_path=str(tmp_path / "b.jsonl"))
    _root, child2, _ = await _child(other, ["search"])
    ok = await other.authorize(
        principal='Agent::"a"', action="search", resource='Tool::"search"', context={}, run=child2
    )
    assert ok["decision"] == "Allow"


@pytest.mark.asyncio
async def test_a_typed_intent_on_a_sub_agent_is_checked_against_the_grant(tmp_path):
    client = InProcessClient(ALLOW_ALL, audit_path=str(tmp_path / "a.jsonl"))
    _root, child, _ = await _child(client, ["web_search"], intents=["research"])
    ok = await _decide(
        client, child, "web_search", intent={"objective": "look up", "category": "research"}
    )
    assert ok["decision"] == "Allow"
    other = InProcessClient(ALLOW_ALL, audit_path=str(tmp_path / "b.jsonl"))
    _root, child2, _ = await _child(other, ["web_search"], intents=["research"])
    bad = await _decide(
        other, child2, "web_search", intent={"objective": "x", "category": "code_generation"}
    )
    assert bad["decision"] == "Deny"
    assert "scope_attenuation_violation" in bad["reason"]


@pytest.mark.asyncio
async def test_a_grandchild_spawned_before_its_parent_was_invalidated_is_denied(tmp_path):
    client = InProcessClient(ALLOW_ALL, audit_path=str(tmp_path / "a.jsonl"))
    _root, child, handle = await _child(client, ["web_search"])
    grandchild = await client.spawn_subagent(
        child, _request(handle, ["web_search"], max_depth=0, time_budget=60)
    )
    grand_run = grandchild["child_run"]
    assert (await _decide(client, grand_run, "web_search"))["decision"] == "Allow"

    assert (await _decide(client, child, "send_email"))["decision"] == "Deny"
    later = await _decide(client, grand_run, "web_search")
    assert later["decision"] == "Deny"
    assert later["reason"] == "run_handle_invalidated (parent_handle_invalidated)"


@pytest.mark.asyncio
async def test_a_spawn_from_an_invalidated_handle_names_the_server_code(tmp_path):
    client = InProcessClient(ALLOW_ALL, audit_path=str(tmp_path / "a.jsonl"))
    _root, child, handle = await _child(client, ["web_search"])
    await _decide(client, child, "send_email")
    with pytest.raises(ScopeAttenuationDenied) as info:
        await client.spawn_subagent(child, _request(handle, []))
    assert info.value.reason == "parent_handle_invalidated"


@pytest.mark.asyncio
async def test_an_unknown_run_handle_is_refused(tmp_path):
    """As wl-apdp: a supplied run_handle_id with no record is refused
    (run_handle_not_found), on a run or on a call naming no run."""
    client = InProcessClient(ALLOW_ALL, audit_path=str(tmp_path / "a.jsonl"))
    root, _child_run, _ = await _child(client, ["web_search"])
    forged = str(uuid4())
    on_run = await _decide(client, root.run, "web_search", context={"run_handle_id": forged})
    assert on_run == {"decision": "Deny", "reason": "run_handle_not_found", "details": {}}
    no_run = await client.authorize(
        principal='Agent::"a"', action="execute", resource="web_search",
        context={"run_handle_id": forged},
    )
    assert no_run["reason"] == "run_handle_not_found"
    # The run's own root handle is accepted.
    own = await _decide(
        client, root.run, "web_search", context={"run_handle_id": root.root_run_handle_id}
    )
    assert own["decision"] == "Allow"
