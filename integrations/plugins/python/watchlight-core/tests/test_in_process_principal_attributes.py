"""InProcessClient gives the engine the agent's trusted name and slug.

``resolve_agent(slug)`` registers ``{"name": slug, "slug": slug}`` for
``Agent::"<uuid5(slug)>"`` with the engine (``set_principal_attributes``), the
in-process stand-in for the registry record wl-apdp reads. A policy scoped by
``principal.name`` or ``principal.slug`` then applies to that agent only, and
nothing in a request can set or change either.
"""

from __future__ import annotations

import json

import pytest

pytest.importorskip("watchlight_engine")

import watchlight_engine  # noqa: E402

from watchlight_core import InProcessClient  # noqa: E402

BY_NAME = 'permit(principal, action, resource) when { principal.name == "research-agent" };'
FORBID_BY_NAME = 'forbid(principal, action, resource) when { principal.name == "research-agent" };'
CATCH_ALL = "permit(principal, action, resource);"


def _client(*codes):
    return InProcessClient(
        [{"name": f"p{i}", "code": c} for i, c in enumerate(codes)], audit_path=None
    )


async def _decide(client, agent, context=None):
    me = f'Agent::"{agent["id"]}"'
    return (await client.authorize(me, "read", "dataset", context=context))["decision"]


@pytest.mark.asyncio
async def test_a_name_scoped_permit_allows_the_named_agent_only():
    client = _client(BY_NAME)
    research = await client.resolve_agent("research-agent")
    other = await client.resolve_agent("other-agent")
    assert await _decide(client, research) == "Allow"
    assert await _decide(client, other) == "Deny"


@pytest.mark.asyncio
async def test_a_name_scoped_forbid_applies():
    client = _client(CATCH_ALL, FORBID_BY_NAME)
    research = await client.resolve_agent("research-agent")
    other = await client.resolve_agent("other-agent")
    assert await _decide(client, research) == "Deny"
    assert await _decide(client, other) == "Allow"


@pytest.mark.asyncio
async def test_resolving_a_slug_again_is_idempotent():
    client = _client(BY_NAME)
    first = await client.resolve_agent("research-agent")
    second = await client.resolve_agent("research-agent")
    assert first == second
    assert await _decide(client, second) == "Allow"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "context",
    [
        {"agent_name": "research-agent"},
        {"name": "research-agent"},
        {"agent_slug": "research-agent"},
        {"tenant_id": "x", "agent_name": "research-agent"},
    ],
)
async def test_the_request_context_cannot_name_the_agent(context):
    client = _client(BY_NAME)
    await client.resolve_agent("research-agent")
    other = await client.resolve_agent("other-agent")
    assert await _decide(client, other, context) == "Deny"


@pytest.mark.asyncio
async def test_the_request_context_cannot_rename_the_agent_out_of_a_forbid():
    client = _client(CATCH_ALL, FORBID_BY_NAME)
    research = await client.resolve_agent("research-agent")
    for context in ({"agent_name": "other-agent"}, {"name": "other-agent"}):
        assert await _decide(client, research, context) == "Deny"


def test_the_engine_refuses_a_rename_and_a_taken_name():
    engine = watchlight_engine.PolicyEngine()
    a = 'Agent::"6d5c3f1e-2a4b-4c8d-9e0f-112233445566"'
    b = 'Agent::"7e6d4a2f-3b5c-4d9e-8f10-223344556677"'
    engine.set_principal_attributes(a, json.dumps({"name": "research-agent"}))
    engine.set_principal_attributes(a, json.dumps({"name": "research-agent"}))
    with pytest.raises(ValueError):
        engine.set_principal_attributes(a, json.dumps({"name": "renamed"}))
    with pytest.raises(ValueError):
        engine.set_principal_attributes(b, json.dumps({"name": "research-agent"}))
    with pytest.raises(ValueError):
        engine.set_principal_attributes('User::"alice"', json.dumps({"name": "x"}))
    with pytest.raises(ValueError):
        engine.set_principal_attributes(b, json.dumps({"name": "x", "trust_level": 9}))
    with pytest.raises(ValueError):
        engine.set_principal_attributes(b, "not json")


# ── preflight decides as authorize does ─────────────────────────────


async def _preflight(client, agent, action="read", resource="dataset"):
    session = await client.create_session(agent_id=agent["id"])
    result = await client.preflight_step(session.run, action, resource)
    return result["preflight"]["decision"]


@pytest.mark.asyncio
async def test_a_name_scoped_forbid_denies_at_preflight():
    client = _client(CATCH_ALL, FORBID_BY_NAME)
    research = await client.resolve_agent("research-agent")
    other = await client.resolve_agent("other-agent")
    assert await _preflight(client, research) == "Deny"
    assert await _preflight(client, other) == "Allow"


_MATRIX = [
    (BY_NAME,),
    (CATCH_ALL, FORBID_BY_NAME),
    ('permit(principal is Agent, action, resource) when { principal.slug == "research-agent" };',),
    (CATCH_ALL, 'forbid(principal, action, resource) when { principal.slug == "research-agent" };'),
    ('permit(principal is Agent, action, resource) when { principal.name like "research-*" };',),
    ('permit(principal is Agent, action == Action::"read", resource) '
     'when { principal has slug && principal.slug == "other-agent" };',),
    ('permit(principal is User, action, resource);',),
]


@pytest.mark.asyncio
@pytest.mark.parametrize("policies", _MATRIX, ids=[str(i) for i in range(len(_MATRIX))])
@pytest.mark.parametrize("action", ["read", "delete"])
async def test_preflight_and_authorize_agree(policies, action):
    client = _client(*policies)
    agents = [await client.resolve_agent(s) for s in ("research-agent", "other-agent")]
    for agent in agents:
        me = f'Agent::"{agent["id"]}"'
        decided = (await client.authorize(me, action, "dataset"))["decision"]
        assert await _preflight(client, agent, action) == decided, (agent["slug"], policies)
