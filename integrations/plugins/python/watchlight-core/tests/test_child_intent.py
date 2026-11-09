"""The child's intent is required on every spawn.

A spawn declares the child's own intent and goal (``child_intent``),
derived from the parent's. These tests pin the SDK side:

- a spawn without ``child_intent`` fails before any network call;
- the request body carries it in the wire shape;
- the ``derived_intent`` wl-apdp returns is kept on the child and stamped on
  the child's ``execution_started``, with a provenance never above the
  derived one (at most ``plugin_derived``);
- :func:`plugin_child_intent` bounds and cleans the framework's objective and
  resolves the category in order: configured, the parent's derived one, the
  default;
- :class:`SubagentRegistry` derives a child intent when none is given;
- a server refusal with ``CHILD_INTENT_REQUIRED`` surfaces as a typed
  :class:`ScopeAttenuationDenied`.
"""

from __future__ import annotations

import uuid
from typing import Any, Dict, List, Optional

import pytest

from watchlight_core import (
    DEFAULT_PLUGIN_CHILD_INTENT_CATEGORY,
    BaseRunHandle,
    ChildIntent,
    ScopeAttenuationDenied,
    SubagentRegistry,
    child_intent_from_dict,
    child_intent_to_dict,
    plugin_child_intent,
    spawn_subagent_request_from_dict,
)
from watchlight_core_testing import MockApdpClient, register_test_run

CHILD_UUID = "22222222-2222-2222-2222-222222222222"
INTENT = {"category": "research", "objective": "Collect the Q3 filings"}


class _Plugin:
    def __init__(self, apdp: MockApdpClient) -> None:
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
        self.kill_signal_registry = None


def _root(apdp: Optional[MockApdpClient] = None) -> BaseRunHandle:
    apdp = apdp or MockApdpClient()
    handle = BaseRunHandle(
        plugin=_Plugin(apdp),
        agent_uuid="00000000-0000-0000-0000-000000000001",
        session_id=f"ses_{uuid.uuid4()}",
        run_handle_id=str(uuid.uuid4()),
    )
    handle._aentered = True
    return handle


async def _started_payload(child: BaseRunHandle) -> Dict[str, Any]:
    captured: List[Dict[str, Any]] = []

    async def _capture(run: Any, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        captured.extend(events)
        return {"accepted": len(events)}

    child._plugin.apdp.publish_events = _capture  # type: ignore[assignment]
    await child._emit_execution_started(child.execution_id)
    started = [e for e in captured if e["event_type"] == "execution_started"]
    assert started, "the child must emit an execution_started"
    return started[-1]["payload"]


# ─── Required at the call site (fail closed, before any network call) ──


@pytest.mark.asyncio
async def test_spawn_without_child_intent_kwarg_is_a_type_error() -> None:
    root = _root()
    with pytest.raises(TypeError):
        await root.spawn_subagent(CHILD_UUID)  # type: ignore[call-arg]
    assert root._plugin.apdp.spawn_subagent_calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "bad",
    [
        None,
        {},
        {"category": "", "objective": "x"},
        {"category": "research", "objective": "   "},
        {"category": "research"},
        {"category": "research", "objective": "x", "max_actions": "3"},
        {"category": "research", "objective": "x", "max_actions": True},
        {"category": "research", "objective": "x", "provenance": "declared"},
        "research",
    ],
)
async def test_spawn_with_missing_or_malformed_child_intent_is_refused_locally(
    bad: Any,
) -> None:
    root = _root()
    with pytest.raises(ValueError):
        await root.spawn_subagent(CHILD_UUID, child_intent=bad)
    # Refused before the wire: nothing reached wl-apdp.
    assert root._plugin.apdp.spawn_subagent_calls == []


# ─── Wire shape ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_request_body_carries_child_intent() -> None:
    root = _root()
    await root.spawn_subagent(
        CHILD_UUID,
        child_intent=ChildIntent("research", "Collect the Q3 filings", max_actions=5),
        allowed_intents=["research"],
    )
    body = root._plugin.apdp.spawn_subagent_calls[-1]
    assert body["child_intent"] == {
        "category": "research",
        "objective": "Collect the Q3 filings",
        "max_actions": 5,
    }
    assert body["requested_scope"]["allowed_intents"] == ["research"]
    # And it round-trips through the decoder.
    assert spawn_subagent_request_from_dict(body).child_intent == ChildIntent(
        "research", "Collect the Q3 filings", 5
    )


@pytest.mark.asyncio
async def test_dict_child_intent_without_budget_omits_max_actions() -> None:
    root = _root()
    await root.spawn_subagent(CHILD_UUID, child_intent=INTENT)
    assert root._plugin.apdp.spawn_subagent_calls[-1]["child_intent"] == INTENT


def test_child_intent_dict_round_trip_and_unknown_fields_refused() -> None:
    intent = ChildIntent("custom:triage", "Sort the inbox", 2)
    assert child_intent_from_dict(child_intent_to_dict(intent)) == intent
    with pytest.raises(ValueError):
        child_intent_from_dict({"category": "a", "objective": "b", "scope": "*"})


# ─── derived_intent on the child ────────────────────────────────────────


@pytest.mark.asyncio
async def test_derived_intent_is_kept_on_the_child_and_stamped_on_started() -> None:
    root = _root()
    child = await root.spawn_subagent(CHILD_UUID, child_intent=INTENT)
    assert child.derived_intent is not None
    assert child.derived_intent["intent_category"] == "research"
    assert root.derived_intent is None
    payload = await _started_payload(child)
    assert payload["intent_category"] == "research"
    assert payload["intent_objective"] == "Collect the Q3 filings"
    assert payload["intent_provenance"] == "plugin_derived"


@pytest.mark.asyncio
async def test_a_child_that_declares_its_own_objective_keeps_the_derived_provenance() -> None:
    root = _root()
    child = await root.spawn_subagent(CHILD_UUID, child_intent=INTENT)
    # The child declares an objective of its own (the synthetic tool path).
    child._intent_objective = "Something the child decided"
    payload = await _started_payload(child)
    assert payload["intent_objective"] == "Something the child decided"
    assert payload["intent_provenance"] == "plugin_derived", (
        "a child never raises its provenance above the derived one"
    )
    assert payload["intent_provenance"] != "declared"


@pytest.mark.asyncio
@pytest.mark.parametrize("provenance", ["absent", None, "declared", "bogus"])
async def test_an_absent_or_unknown_derived_provenance_records_no_objective(
    provenance: Optional[str],
) -> None:
    root = _root()
    child = await root.spawn_subagent(CHILD_UUID, child_intent=INTENT)
    derived = dict(child.derived_intent or {})
    if provenance is None:
        derived.pop("provenance", None)
    else:
        derived["provenance"] = provenance
    child._derived_intent = derived
    child._intent_objective = "The child's own objective"
    payload = await _started_payload(child)
    assert payload["intent_category"] == "research"
    assert "intent_objective" not in payload
    assert "intent_provenance" not in payload


@pytest.mark.asyncio
async def test_proxy_inferred_derived_provenance_is_kept() -> None:
    root = _root()
    child = await root.spawn_subagent(CHILD_UUID, child_intent=INTENT)
    child._derived_intent = {**(child.derived_intent or {}), "provenance": "proxy_inferred"}
    payload = await _started_payload(child)
    assert payload["intent_provenance"] == "proxy_inferred"


# ─── plugin_child_intent ────────────────────────────────────────────────


def test_plugin_child_intent_bounds_the_objective_on_a_utf8_boundary() -> None:
    text = "é" * 300  # 600 bytes
    intent = plugin_child_intent(text)
    encoded = intent.objective.encode("utf-8")
    assert len(encoded) <= 256
    encoded.decode("utf-8")  # a whole number of characters
    assert intent.objective == "é" * 128


def test_plugin_child_intent_strips_control_characters_and_collapses_space() -> None:
    intent = plugin_child_intent("Find\x00 the\n\n filings\x1b[0m\u0085 now")
    assert intent.objective == "Find the filings [0m now"
    assert not any(ord(c) < 0x20 or 0x7F <= ord(c) <= 0x9F for c in intent.objective)


def test_plugin_child_intent_blank_objective_uses_the_fallback() -> None:
    assert plugin_child_intent("  \n ", fallback_objective="Task for x").objective == "Task for x"
    assert plugin_child_intent(None).objective == "Delegated sub-task"


def test_plugin_child_intent_category_order() -> None:
    class _Parent:
        derived_intent = {"intent_category": "data_analysis"}

    assert plugin_child_intent("x", category="research", parent=_Parent()).category == "research"
    assert plugin_child_intent("x", parent=_Parent()).category == "data_analysis"
    assert plugin_child_intent("x", parent=object()).category == DEFAULT_PLUGIN_CHILD_INTENT_CATEGORY
    assert plugin_child_intent("x").category == DEFAULT_PLUGIN_CHILD_INTENT_CATEGORY
    assert plugin_child_intent("x", max_actions=3).max_actions == 3


# ─── SubagentRegistry derives one ───────────────────────────────────────


@pytest.mark.asyncio
async def test_registry_derives_a_child_intent_when_none_is_given() -> None:
    root = _root()
    registry = SubagentRegistry(root, {"allowed_tools": ["search"]})
    child = await registry.on_spawn(
        child_key="k1", child_slug=CHILD_UUID, objective="Read the filings"
    )
    assert child is not None
    sent = root._plugin.apdp.spawn_subagent_calls[-1]["child_intent"]
    assert sent == {
        "category": DEFAULT_PLUGIN_CHILD_INTENT_CATEGORY,
        "objective": "Read the filings",
    }


@pytest.mark.asyncio
async def test_registry_uses_the_configured_category_and_a_slug_fallback() -> None:
    root = _root()
    registry = SubagentRegistry(root, {}, child_intent_category="research")
    await registry.on_spawn(child_key="k1", child_slug=CHILD_UUID)
    sent = root._plugin.apdp.spawn_subagent_calls[-1]["child_intent"]
    assert sent["category"] == "research"
    assert CHILD_UUID in sent["objective"]


@pytest.mark.asyncio
async def test_registry_takes_a_single_scoped_intent_as_the_category() -> None:
    root = _root()
    registry = SubagentRegistry(
        root, {"allowed_intents": ["data_analysis"]}, child_intent_category="research"
    )
    await registry.on_spawn(child_key="k1", child_slug=CHILD_UUID, objective="o")
    sent = root._plugin.apdp.spawn_subagent_calls[-1]
    assert sent["child_intent"]["category"] == "data_analysis"
    assert sent["requested_scope"]["allowed_intents"] == ["data_analysis"]


@pytest.mark.asyncio
async def test_registry_passes_an_explicit_child_intent_through() -> None:
    root = _root()
    registry = SubagentRegistry(root, {})
    await registry.on_spawn(
        child_key="k1", child_slug=CHILD_UUID, child_intent=INTENT, objective="ignored"
    )
    assert root._plugin.apdp.spawn_subagent_calls[-1]["child_intent"] == INTENT


@pytest.mark.asyncio
async def test_registry_fails_closed_on_a_refused_derivation() -> None:
    apdp = MockApdpClient()
    apdp.spawn_error_override = ScopeAttenuationDenied(
        "scope_attenuation_violation", [], reason_code="INTENT_NOT_DERIVED"
    )
    root = _root(apdp)
    registry = SubagentRegistry(root, {})
    assert await registry.on_spawn(child_key="k1", child_slug=CHILD_UUID) is None
    assert registry.resolve("k1") is None


# ─── Server refusal surfaces typed ──────────────────────────────────────


@pytest.mark.asyncio
async def test_stand_in_refuses_a_raw_spawn_without_child_intent() -> None:
    apdp = MockApdpClient()
    run = register_test_run(apdp, "sst_parent.sig")
    with pytest.raises(ScopeAttenuationDenied) as exc_info:
        await apdp.spawn_subagent(
            run,
            {
                "parent_agent_id": "00000000-0000-0000-0000-000000000001",
                "child_agent_id": CHILD_UUID,
                "parent_run_handle_id": str(uuid.uuid4()),
                "requested_scope": {},
            },
        )
    assert exc_info.value.reason_code == "CHILD_INTENT_REQUIRED"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "code", ["CHILD_INTENT_REQUIRED", "INTENT_NOT_DERIVED", "ACTION_BUDGET_EXCEEDS_PARENT", "INVALID_CHILD_INTENT"]
)
async def test_apdp_client_decodes_child_intent_refusal_codes(code: str) -> None:
    import httpx

    from watchlight_core.apdp_client import ApdpClient

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/health":
            return httpx.Response(200, json={"auth": "ok", "kind": "plugin"})
        return httpx.Response(
            403,
            json={
                "reason": "scope_attenuation_violation",
                "reason_code": code,
                "detail": "refused",
                "violations": ["allowed_intents"] if code == "INTENT_NOT_DERIVED" else [],
            },
        )

    client = ApdpClient("http://localhost", auto_probe=False)
    _ = client.client
    await client._client.aclose()  # type: ignore[union-attr]
    client._client = httpx.AsyncClient(
        base_url="http://localhost", transport=httpx.MockTransport(handler)
    )
    with pytest.raises(ScopeAttenuationDenied) as exc_info:
        await client.spawn_subagent(
            register_test_run(client, "sst_parent.sig"),
            {
                "parent_agent_id": "00000000-0000-0000-0000-000000000001",
                "child_agent_id": CHILD_UUID,
                "parent_run_handle_id": "00000000-0000-0000-0000-000000000003",
                "requested_scope": {},
            },
        )
    await client.close()
    assert exc_info.value.reason == "scope_attenuation_violation"
    assert exc_info.value.reason_code == code
