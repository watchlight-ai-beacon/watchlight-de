"""Conformance harness wire-up of invariant #13.

These tests verify the Python lane mirror of TS conformance invariant
#13 (see
``watchlight-agent-sdk-ts/src/conformance.ts``). Invariant #13
asserts every ``agent_spawn_observed`` event carries a populated
``delegation_scope`` payload field so audit replay can reconstruct
the effective authority at every depth in the spawn tree (invariant
#6, the sub-agent scope attenuation contract).

The tests cover:

  1. The :func:`check_scope_attenuation_propagation` function rejects
     spawn events missing ``delegation_scope``.
  2. The function rejects spawn events with ``delegation_scope=null``.
  3. The function rejects spawn events with an empty
     ``delegation_scope={}``.
  4. The function rejects non-dict ``delegation_scope`` values.
  5. The function accepts a populated ``delegation_scope`` shape.
  6. The function passes vacuously when no ``agent_spawn_observed``
     events appear in the stream.
  7. Constants ``SCOPE_ATTENUATION_PROPAGATION_INVARIANT_NUMBER`` +
     ``SCOPE_ATTENUATION_PROPAGATION_INVARIANT_NAME`` are exported and
     match the TS lane (13, ``scope_attenuation_propagation``).
  8. Invariant #13 is registered in the canonical ``INVARIANTS`` table.
  9. The :func:`run_conformance` harness FAILS a plugin whose
     ``agent_spawn_observed`` events carry a null/missing
     ``delegation_scope``.
 10. The :func:`run_conformance` harness PASSES a plugin whose
     ``agent_spawn_observed`` events carry a populated scope.
 11. The :func:`run_conformance` harness PASSES a plugin with no
     spawn events at all (vacuous pass for non-spawning frameworks).

Mirrors the pattern from :mod:`test_conformance_invariant_12` — synthetic
plugin modules registered into ``sys.modules`` keep the test hermetic
from the real shipped plugins.
"""

from __future__ import annotations

import sys
import types
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import pytest

from watchlight_core_testing.conformance import (
    INVARIANTS,
    SCOPE_ATTENUATION_PROPAGATION_INVARIANT_NAME,
    SCOPE_ATTENUATION_PROPAGATION_INVARIANT_NUMBER,
    check_scope_attenuation_propagation,
    run_conformance,
)
from watchlight_core.run_handle import BaseRunHandle
from watchlight_core.telemetry import GovernanceTelemetry
from watchlight_core_testing import (
    ConformanceFailure,
    MockApdpClient,
)


# ─── Fixture helpers ──────────────────────────────────────────────────


def _register_synthetic_module(
    name: str,
    plugin_cls: type,
    translator: Any = None,
) -> types.ModuleType:
    """Register a synthetic plugin module the conformance runner can
    load by name."""
    mod = types.ModuleType(name)
    setattr(mod, plugin_cls.__name__, plugin_cls)
    if translator is not None:
        setattr(mod, translator.__name__, translator)
    sys.modules[name] = mod
    return mod


def _canonical_spawn_event(
    *,
    delegation_scope: Any,
    omit_key: bool = False,
    framework_tag: str = "stubfw",
) -> Dict[str, Any]:
    """Build a wire-shape ``agent_spawn_observed`` event satisfying
    invariants 1-7 so the test isolates invariant #13 from unrelated
    envelope failures.

    When ``omit_key`` is True, the ``delegation_scope`` key is NOT
    inserted at all (the pre-scope-attenuation silent-omission
    shape)."""
    payload: Dict[str, Any] = {
        "spawned_agent": {
            "principal_type": "agent",
            "id": "00000000-0000-4000-8000-000000000002",
        },
        "spawner": {
            "principal_type": "agent",
            "id": "00000000-0000-4000-8000-000000000001",
        },
        "child_execution_id": f"exec_{uuid.uuid4()}",
    }
    if not omit_key:
        payload["delegation_scope"] = delegation_scope
    return {
        "event_id": f"evt_{uuid.uuid4()}",
        "event_type": "agent_spawn_observed",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "execution_id": f"exec_{uuid.uuid4()}",
        "agent_id": "00000000-0000-4000-8000-000000000001",
        "payload": payload,
        "metadata": {"source": f"{framework_tag}.synthetic"},
    }


# ─── Test 1 — function rejects missing delegation_scope key ───────────


def test_check_rejects_missing_delegation_scope_key() -> None:
    """An ``agent_spawn_observed`` event that OMITS the
    ``delegation_scope`` payload key entirely MUST fail invariant #13.
    Mirrors the invariant #6 contract — every spawn carries the
    granted scope on the wire."""
    event = _canonical_spawn_event(delegation_scope=None, omit_key=True)
    with pytest.raises(ConformanceFailure) as excinfo:
        check_scope_attenuation_propagation([event])
    inv_num, reason = excinfo.value.args
    assert inv_num == 13, f"expected invariant 13; got {inv_num}"
    assert "delegation_scope" in reason
    assert "missing" in reason.lower()


# ─── Test 2 — function rejects null delegation_scope ──────────────────


def test_check_rejects_null_delegation_scope() -> None:
    """An ``agent_spawn_observed`` event with
    ``delegation_scope=null`` is the pre-scope-attenuation
    unattested-scope shape and MUST fail invariant #13. Aware plugins
    stamp the
    server-attested grant; null is the regression shape."""
    event = _canonical_spawn_event(delegation_scope=None)
    with pytest.raises(ConformanceFailure) as excinfo:
        check_scope_attenuation_propagation([event])
    inv_num, reason = excinfo.value.args
    assert inv_num == 13
    assert "null" in reason.lower() or "none" in reason.lower()


# ─── Test 3 — function rejects empty dict delegation_scope ────────────


def test_check_rejects_empty_dict_delegation_scope() -> None:
    """An ``agent_spawn_observed`` event with ``delegation_scope={}``
    is indistinguishable from "scope omitted" for the dashboard
    overlay and MUST fail invariant #13. The canonical empty-shape
    (every key explicitly set with empty list / zero values) is the
    correct on-wire signal."""
    event = _canonical_spawn_event(delegation_scope={})
    with pytest.raises(ConformanceFailure) as excinfo:
        check_scope_attenuation_propagation([event])
    inv_num, reason = excinfo.value.args
    assert inv_num == 13
    assert "empty" in reason.lower()


# ─── Test 4 — function rejects non-dict delegation_scope ──────────────


@pytest.mark.parametrize(
    "scope_value",
    [
        ["allowed_tools", "web_search"],  # list
        "scope",  # string
        42,  # int
        True,  # bool
    ],
)
def test_check_rejects_non_dict_delegation_scope(scope_value: Any) -> None:
    """Invariant #13 enforces the canonical wire shape — a JSON object
    mirroring GrantedScope. Lists, strings, ints, bools all fail."""
    event = _canonical_spawn_event(delegation_scope=scope_value)
    with pytest.raises(ConformanceFailure) as excinfo:
        check_scope_attenuation_propagation([event])
    inv_num, reason = excinfo.value.args
    assert inv_num == 13
    assert "not a dict" in reason.lower()


# ─── Test 5 — function accepts a populated delegation_scope ───────────


def test_check_accepts_populated_delegation_scope() -> None:
    """The canonical wire shape — a non-empty dict mirroring
    GrantedScope — MUST pass invariant #13. This is the load-bearing
    positive case that locks the LangGraph + Pydantic AI emission
    contract."""
    event = _canonical_spawn_event(
        delegation_scope={
            "allowed_tools": ["web_search"],
            "allowed_resources": [{"matcher": "doc::*"}],
            "allowed_intents": ["research"],
            "max_depth": 2,
            "time_budget_seconds": 300,
        }
    )
    # Should not raise.
    check_scope_attenuation_propagation([event])


def test_check_accepts_fail_closed_canonical_shape() -> None:
    """The canonical fail-closed shape — every key explicitly set
    with empty list / zero values — MUST pass invariant #13. An
    explicit zero-privilege grant is distinguishable from "scope
    omitted" on the wire."""
    event = _canonical_spawn_event(
        delegation_scope={
            "allowed_tools": [],
            "allowed_resources": [],
            "allowed_intents": [],
            "max_depth": 0,
            "time_budget_seconds": 0,
        }
    )
    check_scope_attenuation_propagation([event])


# ─── Test 6 — function passes vacuously on empty / non-spawn streams ──


def test_check_passes_vacuously_on_empty_stream() -> None:
    """An empty event stream → invariant #13 holds vacuously. Plugins
    whose synthetic lifecycle emits zero events pass cleanly."""
    check_scope_attenuation_propagation([])


def test_check_passes_vacuously_when_no_spawn_events() -> None:
    """A stream containing other event types but no
    ``agent_spawn_observed`` → invariant #13 holds vacuously. Mirrors
    the OpenClaw / MSAF / Bedrock / ADK / Claude-Agent-SDK case
    (frameworks without a sub-agent primitive)."""
    check_scope_attenuation_propagation([
        {
            "event_id": f"evt_{uuid.uuid4()}",
            "event_type": "tool_call_observed",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "execution_id": f"exec_{uuid.uuid4()}",
            "agent_id": "00000000-0000-4000-8000-000000000001",
            "payload": {
                "tool": {
                    "resource_type": "tool",
                    "identifier": "noop",
                    "endpoint": "stubfw://noop",
                },
                "action": {"action": "execute"},
            },
            "metadata": {"source": "stubfw.synthetic"},
        },
    ])


# ─── Test 7 — constants exported + match TS lane ──────────────────────


def test_invariant_13_constants_exported() -> None:
    """SDK consumers (plugin authors writing their own conformance
    wrappers) need stable references to the invariant number + name.
    Both are exported from ``watchlight_core_testing.conformance``. The
    constants match the TS lane's exports in
    ``watchlight-agent-sdk-ts/src/conformance.ts``."""
    from watchlight_core_testing import conformance

    assert conformance.SCOPE_ATTENUATION_PROPAGATION_INVARIANT_NUMBER == 13
    assert (
        conformance.SCOPE_ATTENUATION_PROPAGATION_INVARIANT_NAME
        == "scope_attenuation_propagation"
    )


# ─── Test 8 — invariant #13 registered in canonical INVARIANTS table ──


def test_invariant_13_in_canonical_invariants_table() -> None:
    """The :data:`INVARIANTS` table is the canonical list used by the
    CLI report. Invariant #13 MUST be registered there so the runner's
    report names it correctly."""
    inv13 = next((row for row in INVARIANTS if row[0] == 13), None)
    assert inv13 is not None, (
        "invariant #13 missing from canonical INVARIANTS table"
    )
    _, label, description = inv13
    assert label == SCOPE_ATTENUATION_PROPAGATION_INVARIANT_NAME
    assert "delegation_scope" in description
    assert "audited at every depth" in description.lower()


# ─── Synthetic plugin fixtures for harness wire-up tests ──────────────


class _M43JTaggedHandle(BaseRunHandle):
    """Handle with the framework-namespaced
    ``_observation_source`` so the SDK's defensive lifecycle emit
    (from :meth:`BaseRunHandle.complete`) carries a
    ``metadata.source`` that satisfies invariant 2's framework-tag
    prefix rule. Real plugin subclasses follow the same pattern.
    """

    _observation_source = "stubfw.workload"


def _spawn_emitter_plugin_cls(
    *,
    delegation_scope: Any,
    omit_key: bool = False,
) -> type:
    """Build a plugin class whose ``start_run`` synthesises a single
    ``agent_spawn_observed`` event with the supplied
    ``delegation_scope`` shape. Used to exercise the runner's
    invariant #13 dispatch path against a controlled wire shape."""

    class SpawnEmitterPlugin(GovernanceTelemetry):
        def __init__(self, apdp_url: str = "http://localhost") -> None:
            super().__init__()
            self.apdp = MockApdpClient()
            self.tenant_id = "t-conf"
            self.log_decisions = False

        async def start_run(self, agent_slug: str) -> BaseRunHandle:
            agent_uuid = self.apdp.known_agents.setdefault(
                agent_slug, str(uuid.uuid4())
            )
            session_id = f"ses_{agent_slug}"

            event = _canonical_spawn_event(
                delegation_scope=delegation_scope,
                omit_key=omit_key,
                framework_tag="stubfw",
            )
            # Override the spawn-event execution_id + agent_id so the
            # envelope-shape invariants (#1, #2) match the framework tag.
            event["execution_id"] = f"exec_{uuid.uuid4()}"
            event["agent_id"] = agent_uuid
            await self.apdp.publish_events(None, [event])
            return _M43JTaggedHandle(
                plugin=self,
                agent_uuid=agent_uuid,
                session_id=session_id,
            )

    return SpawnEmitterPlugin


def _no_spawn_plugin_cls() -> type:
    """Build a plugin class whose lifecycle emits NO
    ``agent_spawn_observed`` events. Models the OpenClaw / MSAF /
    Bedrock / ADK / Claude-Agent-SDK case (vacuous-pass plugins)."""

    class NoSpawnPlugin(GovernanceTelemetry):
        def __init__(self, apdp_url: str = "http://localhost") -> None:
            super().__init__()
            self.apdp = MockApdpClient()
            self.tenant_id = "t-conf"
            self.log_decisions = False

        async def start_run(self, agent_slug: str) -> BaseRunHandle:
            agent_uuid = self.apdp.known_agents.setdefault(
                agent_slug, str(uuid.uuid4())
            )
            return _M43JTaggedHandle(
                plugin=self,
                agent_uuid=agent_uuid,
                session_id=f"ses_{agent_slug}",
            )

    return NoSpawnPlugin


class _RaisingAuthorizeHandle(_M43JTaggedHandle):
    async def authorize_action(self, *args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("authorize is broken")


def _broken_authorize_plugin_cls() -> type:
    """A plugin whose root handle raises on every authorize: it never
    emits the tool event the envelope invariants read."""

    class BrokenAuthorizePlugin(GovernanceTelemetry):
        def __init__(self, apdp_url: str = "https://localhost") -> None:
            super().__init__()
            self.apdp = MockApdpClient()
            self.tenant_id = "t-conf"
            self.log_decisions = False

        async def start_run(self, agent_slug: str) -> BaseRunHandle:
            agent_uuid = self.apdp.known_agents.setdefault(agent_slug, str(uuid.uuid4()))
            return _RaisingAuthorizeHandle(plugin=self, agent_uuid=agent_uuid, session_id=f"ses_{agent_slug}")

    return BrokenAuthorizePlugin


@pytest.mark.asyncio
async def test_runner_fails_a_plugin_whose_root_authorize_raises() -> None:
    """The runner swallowed a raise from the root handle's
    authorize, so a plugin that could not authorize at all left no tool
    event and passed the invariants over it vacuously."""
    _register_synthetic_module("_stubplugin_broken_authorize", _broken_authorize_plugin_cls())
    try:
        passed, report = await run_conformance("_stubplugin_broken_authorize", framework_tag="stubfw")
    finally:
        sys.modules.pop("_stubplugin_broken_authorize", None)
    assert not passed, "\n".join(report)
    fails = [line for line in report if line.startswith("FAIL")]
    assert any("invariant 4" in line and "root handle raised RuntimeError" in line for line in fails), fails


# ─── Test 9 — harness FAILS when spawn has null delegation_scope ──────


@pytest.mark.asyncio
async def test_runner_fails_when_spawn_has_null_delegation_scope() -> None:
    """The conformance runner FAILS a plugin whose
    ``agent_spawn_observed`` event carries ``delegation_scope=null``.
    This is the load-bearing regression catcher — a future plugin
    author whose ``spawn_subagent`` override forgets to stamp the
    granted scope on the audit event fails CI loudly."""
    cls = _spawn_emitter_plugin_cls(delegation_scope=None)
    _register_synthetic_module("_stubplugin_null_scope", cls)
    try:
        passed, report = await run_conformance(
            "_stubplugin_null_scope",
            framework_tag="stubfw",
        )
    finally:
        sys.modules.pop("_stubplugin_null_scope", None)
    assert not passed, (
        "null-scope plugin should fail invariant #13; report:\n"
        + "\n".join(report)
    )
    fail_lines = [line for line in report if line.startswith("FAIL")]
    assert any(
        "invariant 13" in line.lower()
        or "scope_attenuation_propagation" in line
        for line in fail_lines
    ), (
        "expected a FAIL line naming invariant 13; got:\n"
        + "\n".join(fail_lines)
    )


# ─── Test 10 — harness FAILS when spawn has empty delegation_scope ────


@pytest.mark.asyncio
async def test_runner_fails_when_spawn_has_empty_delegation_scope() -> None:
    """The conformance runner FAILS a plugin whose
    ``agent_spawn_observed`` event carries ``delegation_scope={}``."""
    cls = _spawn_emitter_plugin_cls(delegation_scope={})
    _register_synthetic_module("_stubplugin_empty_scope", cls)
    try:
        passed, report = await run_conformance(
            "_stubplugin_empty_scope",
            framework_tag="stubfw",
        )
    finally:
        sys.modules.pop("_stubplugin_empty_scope", None)
    assert not passed, (
        "empty-scope plugin should fail invariant #13; report:\n"
        + "\n".join(report)
    )


# ─── Test 11 — harness PASSES when spawn has populated scope ──────────


@pytest.mark.asyncio
async def test_runner_passes_when_spawn_has_populated_scope() -> None:
    """The conformance runner PASSES a plugin whose
    ``agent_spawn_observed`` event carries a populated
    ``delegation_scope`` — the LangGraph + Pydantic AI reference
    reference shape."""
    cls = _spawn_emitter_plugin_cls(
        delegation_scope={
            "allowed_tools": ["web_search"],
            "allowed_resources": [],
            "allowed_intents": ["research"],
            "max_depth": 1,
            "time_budget_seconds": 60,
        }
    )
    _register_synthetic_module("_stubplugin_populated_scope", cls)
    try:
        passed, report = await run_conformance(
            "_stubplugin_populated_scope",
            framework_tag="stubfw",
        )
    finally:
        sys.modules.pop("_stubplugin_populated_scope", None)
    assert passed, (
        "populated-scope plugin should pass conformance; report:\n"
        + "\n".join(report)
    )
    ok_lines = [line for line in report if line.startswith("OK")]
    assert any(
        "invariant 13" in line.lower()
        or "scope_attenuation_propagation" in line.lower()
        for line in ok_lines
    ), (
        "expected an OK line naming invariant 13; got:\n"
        + "\n".join(ok_lines)
    )


# ─── Test 12 — harness PASSES vacuously when no spawn events ──────────


@pytest.mark.asyncio
async def test_runner_passes_vacuously_when_no_spawn_events() -> None:
    """The conformance runner PASSES a plugin whose lifecycle emits
    no ``agent_spawn_observed`` events — frameworks without a
    sub-agent primitive (OpenClaw, MSAF v1, ADK, Bedrock,
    Claude Agent SDK / Plugin) clear invariant #13 cleanly."""
    cls = _no_spawn_plugin_cls()
    _register_synthetic_module("_stubplugin_no_spawn", cls)
    try:
        passed, report = await run_conformance(
            "_stubplugin_no_spawn",
            framework_tag="stubfw",
        )
    finally:
        sys.modules.pop("_stubplugin_no_spawn", None)
    assert passed, (
        "no-spawn plugin should pass conformance vacuously; report:\n"
        + "\n".join(report)
    )
    # The OK line must still fire — vacuous passes count.
    ok_lines = [line for line in report if line.startswith("OK")]
    assert any(
        "invariant 13" in line.lower()
        for line in ok_lines
    ), (
        "expected an OK line naming invariant 13 even on vacuous "
        "pass; got:\n" + "\n".join(ok_lines)
    )


# ─── Test 13 — multiple spawn events: ALL must carry scope ────────────


def test_check_rejects_when_ANY_spawn_in_stream_violates() -> None:
    """A stream containing one valid spawn + one violating spawn MUST
    fail invariant #13 — the check is per-event, not per-stream. A
    plugin that gets it right on the first spawn but drops the scope
    on a deeper spawn would otherwise slip through."""
    good = _canonical_spawn_event(
        delegation_scope={
            "allowed_tools": ["fetch_data"],
            "allowed_resources": [],
            "allowed_intents": [],
            "max_depth": 0,
            "time_budget_seconds": 0,
        }
    )
    bad = _canonical_spawn_event(delegation_scope=None)
    with pytest.raises(ConformanceFailure) as excinfo:
        check_scope_attenuation_propagation([good, bad])
    inv_num, _ = excinfo.value.args
    assert inv_num == 13


# ─── Test 14 — function tolerates missing payload key ──────────────────


def test_check_handles_event_with_missing_payload() -> None:
    """A spawn event whose ``payload`` key is missing or non-dict
    fails invariant #13 with a clear error pointing at the missing
    payload. Defensive check — the canonical wire shape always
    carries a payload, but a malformed translator could drop it."""
    bad_event = {
        "event_id": f"evt_{uuid.uuid4()}",
        "event_type": "agent_spawn_observed",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "execution_id": f"exec_{uuid.uuid4()}",
        "agent_id": "00000000-0000-4000-8000-000000000001",
        # NB: no payload key.
        "metadata": {"source": "stubfw.synthetic"},
    }
    with pytest.raises(ConformanceFailure) as excinfo:
        check_scope_attenuation_propagation([bad_event])
    inv_num, reason = excinfo.value.args
    assert inv_num == 13
    assert "payload" in reason.lower()
