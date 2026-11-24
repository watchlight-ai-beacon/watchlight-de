"""Conformance harness wire-up of invariant #11.

These tests verify the runner-side wiring for the quarantine
short-circuit contract:

  1. Invariant #11 FAILS the runner when a plugin's handle does
     not short-circuit after a Quarantine response.
  2. Invariant #11 PASSES the runner when a plugin uses
     :class:`watchlight_core.BaseRunHandle` (whose short-circuit
     is the load-bearing implementation).
  3. The opt-out attribute ``supports_m45_quarantine = False`` causes
     the runner to SKIP invariant #11 with a clear warning naming
     the kill-signal work as the tracking work.
  4. The synthetic-lifecycle Quarantine sub-test is driven against a
     fresh plugin/handle pair so the run_conformance event capture is
     not polluted.

Pre-existing invariant 1-9 checks are exercised by the in-tree
``test_cross_plugin_conformance.py`` and each plugin's own test
suite; this file scopes itself to invariant #11.
"""

from __future__ import annotations

import sys
import types
from typing import Any, Dict, Optional

import pytest

from watchlight_core_testing.conformance import (
    SUPPORTS_M45_QUARANTINE_ATTR,
    _KILL_SIGNAL_NOTE,
    check_handle_short_circuits_after_quarantine,
    run_conformance,
)
from watchlight_core.run_handle import BaseRunHandle
from watchlight_core.telemetry import GovernanceTelemetry
from watchlight_core_testing import (
    ConformanceFailure,
    MockApdpClient,
)


# ─── Fixture: synthetic plugin modules registered into sys.modules ────
#
# The runner loads a plugin by module name + discovers the *Plugin
# class. We register tiny synthetic modules in `sys.modules` so each
# test gets a clean conformance run without depending on the real
# shipped plugins (which are subject to changes outside this file's
# scope, e.g. the pre-existing invariant 9 failure on Pydantic-AI).


def _register_synthetic_module(
    name: str,
    plugin_cls: type,
    translator: Any = None,
) -> types.ModuleType:
    """Register a synthetic plugin module that the conformance
    runner can load by name.

    The module exposes:
      - ``<*>Plugin`` class — picked up by ``discover_plugin_class``.
      - Optional ``translate_<framework>_event`` translator — picked
        up by ``discover_translator`` so the runner reports the
        translator discovery line.
    """
    mod = types.ModuleType(name)
    setattr(mod, plugin_cls.__name__, plugin_cls)
    if translator is not None:
        setattr(mod, translator.__name__, translator)
    sys.modules[name] = mod
    return mod


def _well_behaved_plugin_cls() -> type:
    """Plugin class whose handle correctly short-circuits after
    Quarantine — uses the default :class:`BaseRunHandle`
    implementation.

    Overrides :attr:`_observation_source` with the framework
    tag so the SDK's defensive ``execution_completed`` lifecycle emit
    (from :meth:`BaseRunHandle.complete`) carries a framework-
    namespaced ``metadata.source`` and continues to satisfy invariant
    2 (``source_attribution``). Real plugins MUST do the same — the
    SDK's lifecycle emit is a framework signal and the conformance
    runner verifies the rule.
    """

    class _WellBehavedHandle(BaseRunHandle):
        _observation_source = "stubfw.workload"

    class WellBehavedPlugin(GovernanceTelemetry):
        def __init__(self, apdp_url: str = "http://localhost") -> None:
            super().__init__()
            self.apdp = MockApdpClient()
            self.tenant_id = "t-conf"
            self.log_decisions = False

        async def start_run(self, agent_slug: str) -> BaseRunHandle:
            agent_uuid = self.apdp.known_agents.setdefault(
                agent_slug, f"uuid-{agent_slug}"
            )
            return _WellBehavedHandle(
                plugin=self,
                agent_uuid=agent_uuid,
                session_id=f"ses_{agent_slug}",
            )

    return WellBehavedPlugin


def _falls_through_plugin_cls() -> type:
    """Plugin whose handle WRONGLY falls through after a Quarantine
    response — emulates the regression shape this suite is designed
    to catch."""

    class FallthroughHandle(BaseRunHandle):
        """Override authorize_action so it ALWAYS round-trips to APDP
        and never raises AgentQuarantinedError. This is the bug shape
        a future engineer might introduce by accidentally bypassing
        the BaseRunHandle short-circuit path."""

        _observation_source = "stubfw.workload"

        async def authorize_action(
            self,
            action: str,
            resource: str,
            *,
            intent: Optional[Dict[str, Any]] = None,
            context: Optional[Dict[str, Any]] = None,
        ) -> bool:
            # Direct APDP call, no short-circuit.
            await self._plugin.apdp.authorize(
                principal=f'Agent::"{self.agent_uuid}"',
                action=f'Action::"{action}"',
                resource=f'Resource::"{resource}"',
                context=context or {},
                execution_id=f"exec_{action}",
                session_id=self.session_id,
            )
            return True

    class FallsThroughPlugin(GovernanceTelemetry):
        def __init__(self, apdp_url: str = "http://localhost") -> None:
            super().__init__()
            self.apdp = MockApdpClient()
            self.tenant_id = "t-conf"
            self.log_decisions = False

        async def start_run(self, agent_slug: str) -> BaseRunHandle:
            agent_uuid = self.apdp.known_agents.setdefault(
                agent_slug, f"uuid-{agent_slug}"
            )
            return FallthroughHandle(
                plugin=self,
                agent_uuid=agent_uuid,
                session_id=f"ses_{agent_slug}",
            )

    return FallsThroughPlugin


def _opt_out_plugin_cls() -> type:
    """Plugin that opts out of invariant #11 by setting
    ``supports_m45_quarantine = False``."""

    class _OptOutHandle(BaseRunHandle):
        _observation_source = "stubfw.workload"

    class OptOutPlugin(GovernanceTelemetry):
        # Explicit class attribute — runner reads this off the class.
        supports_m45_quarantine: bool = False

        def __init__(self, apdp_url: str = "http://localhost") -> None:
            super().__init__()
            self.apdp = MockApdpClient()
            self.tenant_id = "t-conf"
            self.log_decisions = False

        async def start_run(self, agent_slug: str) -> BaseRunHandle:
            # NOTE: this plugin ALSO has the bug shape, but its opt-out
            # is the load-bearing assertion: the runner must SKIP, not
            # FAIL, when supports_m45_quarantine is False.
            agent_uuid = self.apdp.known_agents.setdefault(
                agent_slug, f"uuid-{agent_slug}"
            )
            return _OptOutHandle(
                plugin=self,
                agent_uuid=agent_uuid,
                session_id=f"ses_{agent_slug}",
            )

    return OptOutPlugin


# ─── Test 1 — invariant #11 fails when the plugin does NOT short-circuit ──


@pytest.mark.asyncio
async def test_invariant_11_fails_when_plugin_does_not_short_circuit() -> None:
    """A stub plugin that falls through after a Quarantine response
    MUST cause the conformance runner to FAIL on invariant #11. This
    is the load-bearing regression-catcher — any future plugin author
    whose framework override silently bypasses the short-circuit
    fails CI loudly."""
    _register_synthetic_module(
        "_stubplugin_fallthrough",
        _falls_through_plugin_cls(),
    )
    try:
        passed, report = await run_conformance(
            "_stubplugin_fallthrough",
            framework_tag="stubfw",
        )
    finally:
        sys.modules.pop("_stubplugin_fallthrough", None)
    assert not passed, (
        "falls-through plugin should fail invariant #11; report:\n"
        + "\n".join(report)
    )
    # Report should explicitly name invariant 11 in the FAIL line.
    fail_lines = [line for line in report if line.startswith("FAIL")]
    assert any(
        "invariant 11" in line.lower()
        or "handle_short_circuits_after_quarantine" in line
        for line in fail_lines
    ), (
        "expected a FAIL line naming invariant 11; got:\n"
        + "\n".join(fail_lines)
    )


# ─── Test 2 — invariant #11 passes when the plugin short-circuits ─────


@pytest.mark.asyncio
async def test_invariant_11_passes_when_plugin_short_circuits() -> None:
    """A plugin whose handle is a vanilla :class:`BaseRunHandle`
    MUST PASS invariant #11. The short-circuit logic is the
    load-bearing implementation; this test is the positive
    regression that catches a future BaseRunHandle change
    accidentally breaking the contract."""
    _register_synthetic_module(
        "_stubplugin_wellbehaved",
        _well_behaved_plugin_cls(),
    )
    try:
        passed, report = await run_conformance(
            "_stubplugin_wellbehaved",
            framework_tag="stubfw",
        )
    finally:
        sys.modules.pop("_stubplugin_wellbehaved", None)
    assert passed, (
        "well-behaved plugin should pass conformance; report:\n"
        + "\n".join(report)
    )
    # Report MUST include the OK line for invariant 11.
    ok_lines = [line for line in report if line.startswith("OK")]
    assert any(
        "invariant 11" in line.lower()
        and "Quarantine" in line
        for line in ok_lines
    ), (
        "expected an OK line naming invariant 11; got:\n"
        + "\n".join(ok_lines)
    )


# ─── Test 3 — opt-out attribute skips invariant #11 with a warning ────


@pytest.mark.asyncio
async def test_opt_out_skips_invariant_11_with_clear_warning() -> None:
    """A plugin that sets ``supports_m45_quarantine = False`` on its
    class MUST cause the runner to SKIP invariant #11 — not FAIL it —
    and the report MUST name the kill-signal work as the tracking
    work so an operator reading the report knows the gap is
    temporary, not silent.

    The opt-out is a temporary backwards-compat hatch; once the
    kill-signal work lands across every plugin the opt-out is
    deleted and any plugin still setting the attribute fails."""
    _register_synthetic_module(
        "_stubplugin_optout",
        _opt_out_plugin_cls(),
    )
    try:
        passed, report = await run_conformance(
            "_stubplugin_optout",
            framework_tag="stubfw",
        )
    finally:
        sys.modules.pop("_stubplugin_optout", None)
    # Opt-out plugin SHOULD pass the runner overall because invariant
    # #11 is SKIPPED, not FAILED. Other invariants are vacuous on the
    # empty event stream produced by the synthetic lifecycle.
    assert passed, (
        "opt-out plugin should pass conformance (invariant 11 SKIPPED, "
        "not FAILED); report:\n"
        + "\n".join(report)
    )
    skip_lines = [line for line in report if line.startswith("SKIP")]
    assert any(
        "invariant 11" in line.lower()
        and SUPPORTS_M45_QUARANTINE_ATTR in line
        for line in skip_lines
    ), (
        f"expected a SKIP line naming invariant 11 + the opt-out "
        f"attribute; got:\n"
        + "\n".join(skip_lines)
    )
    # And the SKIP line must carry the kill-signal tracking note so
    # engineers know where to follow up.
    note_skip_lines = [line for line in skip_lines if "kill-signal" in line]
    assert note_skip_lines, (
        "opt-out SKIP line must carry the kill-signal tracking note; got "
        "skip lines:\n" + "\n".join(skip_lines)
    )
    assert "Quarantine" in note_skip_lines[0], (
        "kill-signal note must describe the Quarantine handling gap; got: "
        f"{note_skip_lines[0]!r}"
    )


# ─── Test 4 — synthetic lifecycle exercises the full Quarantine path ──


@pytest.mark.asyncio
async def test_synthetic_lifecycle_includes_quarantine_path() -> None:
    """Invariant #11's lifecycle helper MUST drive the plugin through
    the full Quarantine sequence: open a handle, first authorize
    triggers Quarantine (raises + state transitions), subsequent
    authorize calls short-circuit (no APDP round-trip), spawn_subagent
    on a quarantined parent raises.

    This is the contract the harness wires into the runner — if the
    lifecycle helper ever skips a step, this test catches it."""
    cls = _well_behaved_plugin_cls()
    plugin = cls()
    # Drive the invariant manually to inspect its mid-flight behavior.
    apdp: MockApdpClient = plugin.apdp  # type: ignore[assignment]

    # Pre-condition: no authorize calls happened yet.
    assert apdp.authorize_calls == []

    # Run the invariant; it must complete without raising.
    await check_handle_short_circuits_after_quarantine(plugin)

    # Post-condition: the invariant function records exactly ONE
    # authorize call (the priming Quarantine round-trip). Every
    # subsequent call short-circuited. This is the load-bearing
    # "kill switch must not silently leak round-trips" assertion.
    quarantine_round_trips = [
        c for c in apdp.authorize_calls if "synthetic" in c.get("resource", "")
    ]
    assert len(quarantine_round_trips) == 1, (
        f"invariant 11 lifecycle should leak exactly 1 authorize "
        f"round-trip (the priming Quarantine call); saw "
        f"{len(quarantine_round_trips)}: {quarantine_round_trips!r}"
    )


# ─── Test 5 — opt-out constants surface for SDK consumers ─────────────


def test_opt_out_constants_are_exported() -> None:
    """SDK consumers (plugin authors writing their own conformance
    wrappers) need stable references to the opt-out attribute name +
    the kill-signal tracking note. Both are available from
    ``watchlight_core_testing.conformance`` so they don't have to grep the
    runner source for the magic string."""
    from watchlight_core_testing import conformance

    assert conformance.SUPPORTS_M45_QUARANTINE_ATTR == "supports_m45_quarantine"
    assert "kill-signal" in _KILL_SIGNAL_NOTE
    assert "Quarantine" in _KILL_SIGNAL_NOTE


# ─── Test 6 — invariant directly on a falls-through handle raises ─────


@pytest.mark.asyncio
async def test_invariant_function_raises_conformance_failure_on_fallthrough() -> None:
    """The underlying
    :func:`check_handle_short_circuits_after_quarantine` MUST raise
    :class:`ConformanceFailure` (invariant 11) when the plugin's
    handle does not short-circuit. This is the assertion the runner
    catches + converts into a FAIL line; the function-level test
    pins the contract."""
    cls = _falls_through_plugin_cls()
    plugin = cls()
    with pytest.raises(ConformanceFailure) as excinfo:
        await check_handle_short_circuits_after_quarantine(plugin)
    inv_num, reason = excinfo.value.args
    assert inv_num == 11, (
        f"expected ConformanceFailure for invariant 11; got {inv_num}"
    )
    assert "AgentQuarantinedError" in reason or "Quarantine" in reason, (
        f"reason should reference the Quarantine semantics; got {reason!r}"
    )
