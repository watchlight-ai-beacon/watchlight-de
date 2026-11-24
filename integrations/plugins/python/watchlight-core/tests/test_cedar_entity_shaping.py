"""Cedar entity-type shaping across the two backends.

Regression suite for the entity-type COLLAPSE: ``RunHandle`` force-wrapped every
term (``Agent::"…"`` / ``Action::"…"`` / ``Resource::"…"``) and
``InProcessClient`` stripped the wrapper straight back off, so every term reached
the compiled engine BARE — and a bare term is a WILDCARD that matches a policy
naming any entity type with that id. The in-process lane therefore silently
over-matched: a policy written ``permit(principal == User::"u1", …)`` allowed a
principal of ``Agent::"u1"``.

Three properties are pinned here, each proved against the REAL compiled engine
where the engine is what decides:

1. a BARE term reaches the engine bare, where it gets one fixed type for its
   position (a principal is a ``User``, an action an ``Action``, a
   resource a ``Resource``) instead of matching any type;
2. a TYPED term reaches the engine typed and DISCRIMINATES;
3. the default principal is typed ``Agent::"<uuid>"`` — the one deliberate
   tightening.

Plus the wire lane's counterpart: ``ApdpClient`` must still put the wrapped form
on the wire, because wl-apdp branches on whether a term carries ``::`` when it
resolves entity types.
"""

from __future__ import annotations

import asyncio
import json
import uuid as _uuid

import httpx
import pytest

from watchlight_core import ApdpClient
from watchlight_core._cedar_entities import (
    is_typed_entity,
    shape_for_backend,
    wire_entity,
)

# ── the pure shaping helper ─────────────────────────────────────────


@pytest.mark.parametrize(
    "term,typed",
    [
        ('User::"u1"', True),
        ('Agent::"3f2a-…"', True),
        ('My::Namespace::Document::"d1"', True),
        ('Document::""', True),
        ("read", False),
        ("dataset", False),
        # NOT a Cedar UID: no quoted id. Must stay a bare name, or a resource
        # that merely LOOKS namespaced would silently acquire a type.
        ("Document::x", False),
        ("", False),
        ('has"quote', False),
        ('trailing::"x"junk', False),
    ],
)
def test_is_typed_entity_recognises_only_real_cedar_uids(term, typed):
    assert is_typed_entity(term) is typed


def test_wire_entity_wraps_bare_and_leaves_typed_alone():
    assert wire_entity("read", "Action") == 'Action::"read"'
    assert wire_entity("dataset", "Resource") == 'Resource::"dataset"'
    assert wire_entity("uuid-x", "Agent") == 'Agent::"uuid-x"'
    assert wire_entity('Op::"read"', "Action") == 'Op::"read"'
    assert wire_entity('Document::"d1"', "Resource") == 'Document::"d1"'
    assert wire_entity('User::"alice"', "Agent") == 'User::"alice"'


class _Verbatim:
    cedar_entities_verbatim = True


class _Declares:
    """A backend that declares nothing — a third-party or custom client."""


def test_a_backend_that_declares_nothing_gets_the_historical_wrapping():
    """THE default. A backend that has never heard of the capability — every
    third-party or custom client — must be unaffected by this change."""
    assert shape_for_backend(_Declares(), "uuid-x", "read", "dataset") == (
        'Agent::"uuid-x"',
        'Action::"read"',
        'Resource::"dataset"',
    )
    # An explicit False is the same as absent.
    falsy = _Declares()
    falsy.cedar_entities_verbatim = False  # type: ignore[attr-defined]
    assert shape_for_backend(falsy, "uuid-x", "read", "dataset")[1] == 'Action::"read"'


def test_a_backend_that_declares_verbatim_gets_the_terms_untouched():
    assert shape_for_backend(_Verbatim(), "uuid-x", "read", "dataset") == (
        "uuid-x",
        "read",
        "dataset",
    )


def test_the_in_process_client_is_the_one_backend_declaring_verbatim():
    """Pin the wiring: the capability is what makes the in-process lane behave
    differently, and no networked or mock backend may declare it."""
    from watchlight_core import ApdpClient, InProcessClient
    from watchlight_core_testing import MockApdpClient

    assert InProcessClient.cedar_entities_verbatim is True
    assert getattr(ApdpClient, "cedar_entities_verbatim", False) is False
    assert getattr(MockApdpClient, "cedar_entities_verbatim", False) is False


# ── the wire lane: request body must be unchanged ───────────────────


def _recording_client(recorder: list) -> ApdpClient:
    def handler(request: httpx.Request) -> httpx.Response:
        recorder.append(json.loads(request.content))
        return httpx.Response(200, json={"decision": "Allow"})

    apdp = ApdpClient("http://localhost")
    apdp._probed = True
    apdp._client = httpx.AsyncClient(
        base_url="http://localhost", transport=httpx.MockTransport(handler)
    )
    return apdp


def _drive_run_handle(apdp, action: str, resource: str) -> None:
    """Drive a real ``BaseRunHandle`` over ``apdp`` for one authorize call."""
    from watchlight_core.telemetry import GovernanceTelemetry
    from watchlight_core_testing import bind_test_run, stub_handle

    class _Plugin(GovernanceTelemetry):
        def __init__(self) -> None:
            super().__init__()
            self.apdp = apdp
            self.tenant_id = "acme"
            self.log_decisions = False

    async def _run() -> None:
        handle = stub_handle(_Plugin(), agent_uuid="uuid-x", session_id="ses_x")
        # The defensive `execution_started` mint emits under the per-run
        # credential; give the synthetic handle one so it reaches the transport.
        bind_test_run(handle, "sst_run_x.signature")
        await handle.authorize_action(action, resource)

    asyncio.run(_run())


def _authorize_body(recorded: list) -> dict:
    """The ``/authorize`` body out of a recorder that also saw lineage posts."""
    bodies = [b for b in recorded if "principal" in b and "action" in b]
    assert bodies, f"no /authorize body recorded; saw {recorded!r}"
    return bodies[-1]


# ── check 1: end to end from a RunHandle ────────────────────────────


def test_wire_body_end_to_end_from_a_run_handle_is_unchanged_for_bare_terms():
    """THE backward-compatibility proof for the networked lane: drive a real
    ``BaseRunHandle`` over a real ``ApdpClient`` and assert the ``/authorize``
    body byte-for-byte. ``RunHandle`` still applies the wrapping for a backend
    that declares nothing, so the body an operator's wl-apdp receives is
    identical to before."""
    seen: list = []
    _drive_run_handle(_recording_client(seen), "read", "dataset")
    body = _authorize_body(seen)
    assert body["principal"] == 'Agent::"uuid-x"'
    assert body["action"] == 'Action::"read"'
    assert body["resource"] == 'Resource::"dataset"'


def test_wire_body_end_to_end_from_a_run_handle_is_unchanged_for_typed_terms():
    """A term that is ALREADY a Cedar reference now reaches the wire intact.

    This is the ONE end-to-end wire difference, and it is a capability, not a
    break: the old unconditional wrapping turned a typed term into a MALFORMED
    nested reference. Captured against published 0.6.0, ``authorize_action(
    'Action::"read"', 'Document::"d1"')`` put ``action='Action::"Action::"read"
    "'`` and ``resource='Resource::"Document::"d1""'`` on the wire — not valid
    Cedar entity UIDs, so no caller could have been relying on them."""
    seen: list = []
    _drive_run_handle(_recording_client(seen), 'Action::"read"', 'Document::"d1"')
    body = _authorize_body(seen)
    assert body["principal"] == 'Agent::"uuid-x"'
    assert body["action"] == 'Action::"read"'
    assert body["resource"] == 'Document::"d1"'


# ── check 2: ApdpClient.authorize called DIRECTLY ───────────────────
#
# ``ApdpClient`` is published on PyPI as ``watchlight-agent-sdk`` and
# ``authorize`` is a public method. It must put a direct caller's terms on the
# wire UNTOUCHED — wl-apdp gives a BARE term one fixed type for its position
# (``User`` / ``Action`` / ``Resource``) but takes a TYPED one at face
# value, so quietly wrapping a caller's bare terms here could flip their
# decision. These two tests are the
# guard: shaping belongs at the ``RunHandle`` call site, never in this method.


def test_apdp_client_authorize_passes_bare_terms_through_untouched():
    seen: list = []
    apdp = _recording_client(seen)
    asyncio.run(
        apdp.authorize(principal="research-agent", action="read", resource="dataset")
    )
    body = _authorize_body(seen)
    assert body["principal"] == "research-agent"
    assert body["action"] == "read"
    assert body["resource"] == "dataset"


def test_apdp_client_authorize_passes_typed_terms_through_untouched():
    seen: list = []
    apdp = _recording_client(seen)
    asyncio.run(
        apdp.authorize(
            principal='User::"alice"', action='Action::"read"', resource='Document::"d1"'
        )
    )
    body = _authorize_body(seen)
    assert body["principal"] == 'User::"alice"'
    assert body["action"] == 'Action::"read"'
    assert body["resource"] == 'Document::"d1"'


# ── the in-process lane: the real engine decides ────────────────────

pytest.importorskip("watchlight_engine")

from watchlight_core.in_process_client import _AGENT_NS, InProcessClient  # noqa: E402


def _client(policy_code: str, tmp_path) -> InProcessClient:
    return InProcessClient(
        [{"name": "p", "code": policy_code}], audit_path=str(tmp_path / "audit.jsonl")
    )


@pytest.mark.asyncio
async def test_engine_gives_a_bare_principal_one_fixed_type(tmp_path):
    """A bare principal is a ``User``, never the type a policy names.
    It used to match a policy naming ANY entity type with that id, the
    wildcard that made collapsing every term to bare an authorization defect."""
    user_policy = _client('permit(principal == User::"u1", action, resource);', tmp_path)
    agent_policy = _client('permit(principal == Agent::"u1", action, resource);', tmp_path)

    # Bare: a User, so it matches the User policy only.
    assert (await user_policy.authorize("u1", "read", "d"))["decision"] == "Allow"
    assert (await agent_policy.authorize("u1", "read", "d"))["decision"] == "Deny"

    # Typed: discriminates correctly in both directions.
    assert (await user_policy.authorize('User::"u1"', "read", "d"))["decision"] == "Allow"
    assert (await user_policy.authorize('Agent::"u1"', "read", "d"))["decision"] == "Deny"
    assert (await agent_policy.authorize('Agent::"u1"', "read", "d"))["decision"] == "Allow"
    assert (await agent_policy.authorize('User::"u1"', "read", "d"))["decision"] == "Deny"


#: Cedar constrains the ACTION term to the literal entity type ``Action`` — a
#: policy cannot write ``action == Op::"read"`` (the engine rejects it at
#: ``add_policy``), so ``Action`` is the only type an action can carry and the
#: over-match that hurt the principal has no analogue there. The RESOURCE term
#: is unconstrained, so that is where a resource type must be shown to
#: discriminate.
_TYPED_RESOURCE_POLICY = (
    'permit(principal, action == Action::"read", resource == Document::"d1");'
)


@pytest.mark.asyncio
async def test_typed_resource_discriminates_in_process(tmp_path):
    """The same collapse applied to ``resource``: a typed term now reaches the
    engine typed, and a policy naming a different type denies."""
    c = _client(_TYPED_RESOURCE_POLICY, tmp_path)
    assert (await c.authorize("u1", "read", 'Document::"d1"'))["decision"] == "Allow"
    assert (await c.authorize("u1", "read", 'File::"d1"'))["decision"] == "Deny"
    # THE reason the SDK's force-wrapping had to be removed rather than merely
    # left unstripped: imposing ``Resource::`` on a caller who never asked for a
    # type would deny every DE policy that names its own resource type.
    assert (await c.authorize("u1", "read", 'Resource::"d1"'))["decision"] == "Deny"


@pytest.mark.asyncio
async def test_bare_action_and_resource_get_their_fixed_types(tmp_path):
    """A bare action is an ``Action`` and a bare resource is a
    ``Resource``, never the type a policy names. A policy written
    ``resource == Document::"d1"`` matches only a caller who sends
    ``Document::"d1"``; the Developer Edition convention for bare resources is
    ``resource == Resource::"…"``."""
    c = _client(_TYPED_RESOURCE_POLICY, tmp_path)
    assert (await c.authorize("u1", "read", "d1"))["decision"] == "Deny"
    assert (await c.authorize("u1", 'Action::"read"', 'Document::"d1"'))["decision"] == "Allow"
    assert (await c.authorize("u1", "read", 'Document::"d1"'))["decision"] == "Allow"
    bare = _client(
        'permit(principal, action == Action::"read", resource == Resource::"d1");', tmp_path
    )
    assert (await bare.authorize("u1", "read", "d1"))["decision"] == "Allow"
    assert (await bare.authorize("u1", "read", 'Document::"d1"'))["decision"] == "Deny"


# ── the plugin lane end to end, through a real framework plugin ─────


def _pydantic_plugin():
    pytest.importorskip("watchlight_pydantic_ai")
    from watchlight_pydantic_ai import WatchlightPydanticAIPlugin

    return WatchlightPydanticAIPlugin(
        apdp_url="http://localhost:8081", auto_instrument=False
    )


@pytest.mark.asyncio
async def test_default_principal_is_the_typed_acting_agent(tmp_path):
    """DEFECT 2, fixed. With no caller principal the acting agent is the subject
    and is named TYPED, so a policy written for a ``User::`` with the agent's id
    no longer matches it. This is the deliberate tightening."""
    agent_id = str(_uuid.uuid5(_AGENT_NS, "research-agent"))

    async def _decide(policy_code: str) -> bool:
        plugin = _pydantic_plugin()
        plugin.apdp = InProcessClient(
            [{"name": "p", "code": policy_code}], audit_path=str(tmp_path / "a.jsonl")
        )
        async with await plugin.start_run("research-agent") as handle:
            return await handle.authorize_action("read", "dataset")

    assert (
        await _decide(
            f'permit(principal == User::"{agent_id}", action == Action::"read", resource);'
        )
        is False
    ), "a policy naming a User must NOT match the acting Agent"
    assert (
        await _decide(
            f'permit(principal == Agent::"{agent_id}", action == Action::"read", resource);'
        )
        is True
    ), "a policy naming the Agent must match it"


@pytest.mark.asyncio
async def test_per_call_principal_decides_on_the_subjects_authority(tmp_path):
    """DEFECT 1, fixed. The application can say WHO a call is for, and the
    policy decides on that subject's authority, not the runtime's."""
    plugin = _pydantic_plugin()
    plugin.apdp = InProcessClient(
        [
            {
                "name": "alice-reads",
                "code": 'permit(principal == User::"alice", action == Action::"read", resource);',
            }
        ],
        audit_path=str(tmp_path / "a.jsonl"),
    )
    async with await plugin.start_run("research-agent") as handle:
        assert await handle.authorize_action("read", "dataset") is False
        assert (
            await handle.authorize_action("read", "dataset", principal='User::"alice"')
            is True
        )
        assert (
            await handle.authorize_action("read", "dataset", principal='User::"mallory"')
            is False
        )
        # The type discriminates on the supplied subject too — naming alice as
        # an Agent must not borrow the User::"alice" grant.
        assert (
            await handle.authorize_action("read", "dataset", principal='Agent::"alice"')
            is False
        )


@pytest.mark.asyncio
async def test_bare_action_and_resource_still_work_through_the_plugin(tmp_path):
    """The unchanged path, proved end to end: an ordinary
    ``authorize_action("read", "dataset")`` against a policy written with the
    default ``Action::`` / ``Resource::`` types decides exactly as before."""
    agent_id = str(_uuid.uuid5(_AGENT_NS, "research-agent"))
    plugin = _pydantic_plugin()
    plugin.apdp = InProcessClient(
        [
            {
                "name": "p",
                "code": (
                    f'permit(principal == Agent::"{agent_id}", '
                    'action == Action::"read", resource == Resource::"dataset");'
                ),
            }
        ],
        audit_path=str(tmp_path / "a.jsonl"),
    )
    async with await plugin.start_run("research-agent") as handle:
        assert await handle.authorize_action("read", "dataset") is True
        assert await handle.authorize_action("delete", "dataset") is False


@pytest.mark.asyncio
async def test_supplied_subject_does_not_erase_which_agent_acted(tmp_path):
    """Attribution. A caller-supplied subject changes WHO the decision is about;
    it must not change the record of WHICH AGENT acted. The DE lineage names the
    acting agent on every event of the run."""
    audit = tmp_path / "audit.jsonl"
    agent_id = str(_uuid.uuid5(_AGENT_NS, "research-agent"))
    plugin = _pydantic_plugin()
    plugin.apdp = InProcessClient(
        [
            {
                "name": "alice-reads",
                "code": 'permit(principal == User::"alice", action == Action::"read", resource);',
            }
        ],
        audit_path=str(audit),
    )
    async with await plugin.start_run("research-agent") as handle:
        assert await handle.authorize_action("read", "d", principal='User::"alice"') is True

    records = [json.loads(line) for line in audit.read_text(encoding="utf-8").splitlines()]
    assert records, "the run must leave a lineage trail"
    # Every record names the acting agent, and none of them was rewritten to the
    # supplied subject.
    assert all(r.get("agent_id") == agent_id for r in records)
    started = [r for r in records if r.get("event_type") == "execution_started"]
    assert started and started[0]["payload"]["principal"] == {
        "principal_type": "agent",
        "id": agent_id,
    }
