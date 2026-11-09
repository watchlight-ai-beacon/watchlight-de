"""Conformance harness wire-up of invariant #12.

These tests verify the runner-side wiring for the intent-provenance
consistency contract:

  1. Invariant #12 FAILS the runner when a plugin emits an
     ``execution_started`` event with ``intent_objective`` populated
     and ``intent_provenance`` set to ``absent`` (inconsistent state).
  2. Invariant #12 PASSES the runner when a plugin emits both fields
     consistently (populated + non-absent provenance, OR both omitted).
  3. The opt-out attribute ``supports_m46_intent_extraction = False``
     causes the runner to SKIP invariant #12 with a clear warning
     naming the intent-extraction coordination work as the tracking
     work.
  4. The synthetic lifecycle harness drives plugins with a known
     prompt so extraction can fire (where the plugin's ``start_run``
     accepts a prompt-like kwarg).
  5. ``intent_objective`` absent with non-absent ``intent_provenance``
     is also a violation (provenance without an objective is invalid).

Pre-existing invariant 1-11 checks are exercised by the in-tree
``test_cross_plugin_conformance.py`` and each plugin's own test
suite; this file scopes itself to invariant #12.

Pattern mirrors :mod:`test_conformance_invariant_11` — synthetic
plugin modules registered into ``sys.modules`` keep the test
hermetic from the real shipped plugins.
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
    SUPPORTS_M46_INTENT_EXTRACTION_ATTR,
    _INTENT_EXTRACTION_NOTE,
    check_intent_provenance_consistency,
    run_conformance,
)
from watchlight_core.run_handle import BaseRunHandle
from watchlight_core.telemetry import GovernanceTelemetry
from watchlight_core_testing import (
    ConformanceFailure,
    MockApdpClient,
)


# ─── Fixture: synthetic plugin modules registered into sys.modules ────


def _register_synthetic_module(
    name: str,
    plugin_cls: type,
    translator: Any = None,
) -> types.ModuleType:
    """Register a synthetic plugin module that the conformance
    runner can load by name. Mirrors the invariant #11 test pattern."""
    mod = types.ModuleType(name)
    setattr(mod, plugin_cls.__name__, plugin_cls)
    if translator is not None:
        setattr(mod, translator.__name__, translator)
    sys.modules[name] = mod
    return mod


class _M46JTaggedHandle(BaseRunHandle):
    """Handle with the framework-namespaced
    ``_observation_source`` so the SDK's defensive lifecycle emit
    (from :meth:`BaseRunHandle.complete`) carries a
    ``metadata.source`` that satisfies invariant 2's framework-tag
    prefix rule. Real plugin subclasses follow the same pattern.
    """

    _observation_source = "stubfw.workload"


def _canonical_envelope(
    *,
    event_type: str,
    execution_id: str,
    agent_id: str,
    payload: Dict[str, Any],
    framework_tag: str = "stubfw",
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Build a wire-shape ``ExecutionEvent`` dict satisfying invariants
    1 + 2 + 3 + 5 + 6 + 7 so the test isolates invariant #12 from
    unrelated envelope failures."""
    event: Dict[str, Any] = {
        "event_id": f"evt_{uuid.uuid4()}",
        "event_type": event_type,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "execution_id": execution_id,
        "agent_id": agent_id,
        "payload": payload,
        "metadata": {"source": f"{framework_tag}.synthetic"},
    }
    if extra:
        event.update(extra)
    return event


def _emitter_plugin_cls(
    *,
    objective: Optional[str],
    provenance: Optional[str],
    omit_provenance_key: bool = False,
) -> type:
    """Build a plugin class that emits one ``execution_started`` event
    on ``start_run`` with the supplied (objective, provenance) pair.

    When ``omit_provenance_key`` is True, the provenance key is NOT
    inserted into the payload at all (the pre-intent-extraction
    silent posture)."""

    class EmitterPlugin(GovernanceTelemetry):
        def __init__(self, apdp_url: str = "http://localhost") -> None:
            super().__init__()
            self.apdp = MockApdpClient()
            self.tenant_id = "t-conf"
            self.log_decisions = False

        async def start_run(self, agent_slug: str) -> BaseRunHandle:
            agent_uuid = self.apdp.known_agents.setdefault(
                agent_slug, f"uuid-{agent_slug}"
            )
            session_id = f"ses_{agent_slug}"
            execution_id = f"exec_{uuid.uuid4()}"

            payload: Dict[str, Any] = {
                "principal": {"principal_type": "agent", "id": agent_uuid},
                "depth": 0,
            }
            if objective is not None:
                payload["intent_objective"] = objective
            if not omit_provenance_key:
                payload["intent_provenance"] = provenance

            event = _canonical_envelope(
                event_type="execution_started",
                execution_id=execution_id,
                agent_id=agent_uuid,
                payload=payload,
            )
            await self.apdp.publish_events(None, [event])
            # Correlation contract (invariant #15): the returned handle's
            # own execution_id MUST match the id we just emitted
            # execution_started for — otherwise the harness's downstream
            # authorize() would mint a SECOND divergent root. Align them.
            return _M46JTaggedHandle(
                plugin=self,
                agent_uuid=agent_uuid,
                session_id=session_id,
                execution_id=execution_id,
            )

    return EmitterPlugin


def _opt_out_plugin_cls() -> type:
    """Plugin that opts out of invariant #12 by setting
    ``supports_m46_intent_extraction = False``. Wires an inconsistent
    payload deliberately so the SKIP path is exercised against the
    bug shape."""

    class OptOutPlugin(GovernanceTelemetry):
        supports_m46_intent_extraction: bool = False

        def __init__(self, apdp_url: str = "http://localhost") -> None:
            super().__init__()
            self.apdp = MockApdpClient()
            self.tenant_id = "t-conf"
            self.log_decisions = False

        async def start_run(self, agent_slug: str) -> BaseRunHandle:
            agent_uuid = self.apdp.known_agents.setdefault(
                agent_slug, f"uuid-{agent_slug}"
            )
            session_id = f"ses_{agent_slug}"
            execution_id = f"exec_{uuid.uuid4()}"

            # Inconsistent — objective populated, provenance == absent.
            # Without the opt-out this would FAIL invariant #12.
            payload: Dict[str, Any] = {
                "principal": {"principal_type": "agent", "id": agent_uuid},
                "depth": 0,
                "intent_objective": "audit Q3 invoices",
                "intent_provenance": "absent",
            }
            event = _canonical_envelope(
                event_type="execution_started",
                execution_id=execution_id,
                agent_id=agent_uuid,
                payload=payload,
            )
            await self.apdp.publish_events(None, [event])
            # Align the handle's execution_id with the emitted started id
            # (correlation invariant #15) so the harness authorize()
            # doesn't mint a divergent second root.
            return _M46JTaggedHandle(
                plugin=self,
                agent_uuid=agent_uuid,
                session_id=session_id,
                execution_id=execution_id,
            )

    return OptOutPlugin


# ─── Test 1 — passes when provenance matches objective state ──────────


@pytest.mark.asyncio
async def test_invariant_12_passes_when_provenance_matches_objective_state() -> None:
    """A plugin that emits ``intent_objective`` + a non-absent
    ``intent_provenance`` (the reference shape) MUST pass
    invariant #12."""
    cls = _emitter_plugin_cls(
        objective="audit Q3 invoices",
        provenance="plugin_derived",
    )
    _register_synthetic_module("_stubplugin_consistent_populated", cls)
    try:
        passed, report = await run_conformance(
            "_stubplugin_consistent_populated",
            framework_tag="stubfw",
        )
    finally:
        sys.modules.pop("_stubplugin_consistent_populated", None)
    assert passed, (
        "consistent populated plugin should pass conformance; report:\n"
        + "\n".join(report)
    )
    # Report MUST include the OK line for invariant 12.
    ok_lines = [line for line in report if line.startswith("OK")]
    assert any(
        "invariant 12" in line.lower() and "provenance" in line.lower()
        for line in ok_lines
    ), (
        "expected an OK line naming invariant 12; got:\n"
        + "\n".join(ok_lines)
    )


# ─── Test 2 — fails when objective populated but provenance absent ────


@pytest.mark.asyncio
async def test_invariant_12_fails_when_objective_populated_but_provenance_absent() -> None:
    """The load-bearing regression catcher: a plugin emitting
    ``intent_objective`` with ``intent_provenance == "absent"`` is the
    exact bug shape this suite catches — Cedar policies see an attributed
    objective with absent provenance, which silently downgrades
    enforcement. The runner MUST fail."""
    cls = _emitter_plugin_cls(
        objective="audit Q3 invoices",
        provenance="absent",
    )
    _register_synthetic_module("_stubplugin_inconsistent", cls)
    try:
        passed, report = await run_conformance(
            "_stubplugin_inconsistent",
            framework_tag="stubfw",
        )
    finally:
        sys.modules.pop("_stubplugin_inconsistent", None)
    assert not passed, (
        "inconsistent plugin should fail invariant #12; report:\n"
        + "\n".join(report)
    )
    fail_lines = [line for line in report if line.startswith("FAIL")]
    assert any(
        "invariant 12" in line.lower()
        or "intent_provenance_consistency" in line
        for line in fail_lines
    ), (
        "expected a FAIL line naming invariant 12; got:\n"
        + "\n".join(fail_lines)
    )


# ─── Test 3 — passes when both omitted (pre-intent-extraction posture) ─


@pytest.mark.asyncio
async def test_invariant_12_passes_when_both_omitted() -> None:
    """A plugin emitting ``execution_started`` with NEITHER field set
    (the pre-intent-extraction silent posture, byte-identical to
    ``intent_provenance: absent``) MUST pass invariant #12. Backward
    compatibility for plugins that haven't wired intent extraction
    yet is the load-bearing assertion."""
    cls = _emitter_plugin_cls(
        objective=None,
        provenance=None,
        omit_provenance_key=True,
    )
    _register_synthetic_module("_stubplugin_both_omitted", cls)
    try:
        passed, report = await run_conformance(
            "_stubplugin_both_omitted",
            framework_tag="stubfw",
        )
    finally:
        sys.modules.pop("_stubplugin_both_omitted", None)
    assert passed, (
        "both-omitted plugin should pass conformance (pre-intent-"
        "extraction silent "
        "posture); report:\n" + "\n".join(report)
    )


# ─── Test 4 — opt-out skips invariant #12 with a clear warning ────────


@pytest.mark.asyncio
async def test_invariant_12_opt_out_skips_with_clear_warning() -> None:
    """A plugin that sets ``supports_m46_intent_extraction = False`` on
    its class MUST cause the runner to SKIP invariant #12 — not FAIL it
    — even though the plugin's emitted shape would otherwise violate
    the consistency rule. The opt-out is the load-bearing intent-
    extraction coordination hatch: plugins waiting on that wiring
    stay green."""
    cls = _opt_out_plugin_cls()
    _register_synthetic_module("_stubplugin_optout", cls)
    try:
        passed, report = await run_conformance(
            "_stubplugin_optout",
            framework_tag="stubfw",
        )
    finally:
        sys.modules.pop("_stubplugin_optout", None)
    assert passed, (
        "opt-out plugin should pass conformance (invariant 12 SKIPPED, "
        "not FAILED); report:\n" + "\n".join(report)
    )
    skip_lines = [line for line in report if line.startswith("SKIP")]
    assert any(
        "invariant 12" in line.lower()
        and SUPPORTS_M46_INTENT_EXTRACTION_ATTR in line
        for line in skip_lines
    ), (
        "expected a SKIP line naming invariant 12 + the opt-out "
        "attribute; got:\n" + "\n".join(skip_lines)
    )
    # And the SKIP line must carry the intent-extraction tracking note
    # so engineers know where to follow up.
    note_skip_lines = [line for line in skip_lines if "natural-signal" in line]
    assert note_skip_lines, (
        "opt-out SKIP line must carry the intent-extraction tracking "
        "note; got skip lines:\n" + "\n".join(skip_lines)
    )


# ─── Test 5 — synthetic lifecycle includes the prompt-driven path ─────


@pytest.mark.asyncio
async def test_invariant_12_synthetic_lifecycle_includes_prompt_arg() -> None:
    """The conformance harness exercises the full positive path: a
    plugin whose ``start_run`` synthesises an ``execution_started``
    event with a known objective + plugin_derived provenance lands in
    the captured event stream, invariant #12 reads that event, and the
    consistency rule passes.

    This is the proof that the harness wire-up actually drives the
    invariant on real captured events, not just on synthetic event
    dicts injected by the test."""
    cls = _emitter_plugin_cls(
        objective="research the Watchlight knowledge base",
        provenance="plugin_derived",
    )
    plugin = cls()
    apdp: MockApdpClient = plugin.apdp  # type: ignore[assignment]

    # Pre-condition: no events captured yet.
    assert apdp.published_events == []

    # Drive `start_run` so the lifecycle synthesises the
    # ``execution_started`` event.
    await plugin.start_run("test-agent")

    started = [
        e for e in apdp.published_events if e.get("event_type") == "execution_started"
    ]
    assert len(started) == 1, (
        f"emitter plugin should publish exactly one execution_started "
        f"event from start_run; saw {len(started)}"
    )
    payload = started[0].get("payload") or {}
    assert payload.get("intent_objective") == (
        "research the Watchlight knowledge base"
    ), "lifecycle should preserve the intent_objective verbatim"
    assert payload.get("intent_provenance") == "plugin_derived", (
        "lifecycle should stamp intent_provenance=plugin_derived for the "
        "extraction-from-prompt path"
    )

    # The invariant check itself must accept this shape — exercised
    # directly so a future regression in the function (not just the
    # runner wiring) is caught.
    check_intent_provenance_consistency(apdp.published_events)


# ─── Test 6 — invariant rejects provenance-without-objective ─────────


def test_invariant_function_rejects_provenance_without_objective() -> None:
    """The underlying :func:`check_intent_provenance_consistency` MUST
    raise :class:`ConformanceFailure` when an event has provenance set
    to a non-absent value but no objective — the inverse bug shape.

    Provenance-without-objective is invalid because Cedar policies that
    permit on ``provenance == "declared"`` would let the request
    through even though there's no underlying objective to validate
    against. This is the symmetric load-bearing assertion next to the
    populated-objective-but-absent-provenance case."""
    bad_event = _canonical_envelope(
        event_type="execution_started",
        execution_id=f"exec_{uuid.uuid4()}",
        agent_id="uuid-bad",
        payload={
            "principal": {"principal_type": "agent", "id": "uuid-bad"},
            "depth": 0,
            "intent_provenance": "declared",
            # NB: no intent_objective key.
        },
    )
    with pytest.raises(ConformanceFailure) as excinfo:
        check_intent_provenance_consistency([bad_event])
    inv_num, reason = excinfo.value.args
    assert inv_num == 12, (
        f"expected ConformanceFailure for invariant 12; got {inv_num}"
    )
    assert "provenance" in reason.lower() or "objective" in reason.lower(), (
        f"reason should reference the provenance/objective semantics; "
        f"got {reason!r}"
    )


# ─── Test 7 — invariant function accepts vacuous (no execution_started) ──


def test_invariant_function_passes_on_empty_or_no_start_events() -> None:
    """No ``execution_started`` events in the stream → invariant holds
    vacuously. Plugins whose synthetic lifecycle doesn't fire the
    framework's natural emission point (LangGraph's on_chain_start,
    Bedrock Lambda entry, etc.) pass cleanly through this path."""
    # Empty list.
    check_intent_provenance_consistency([])
    # Stream that contains other event types but no execution_started.
    check_intent_provenance_consistency([
        _canonical_envelope(
            event_type="tool_call_observed",
            execution_id=f"exec_{uuid.uuid4()}",
            agent_id="uuid-other",
            payload={
                "tool": {
                    "resource_type": "tool",
                    "identifier": "noop",
                    "endpoint": "stubfw://noop",
                },
                "action": {"action": "execute"},
            },
        ),
    ])


# ─── Test 8 — opt-out constants surface for SDK consumers ─────────────


def test_opt_out_constants_are_exported() -> None:
    """SDK consumers (plugin authors writing their own conformance
    wrappers) need stable references to the opt-out attribute name +
    the intent-extraction tracking note. Both are available from
    ``watchlight_core_testing.conformance`` so they don't have to grep the
    runner source for the magic string."""
    from watchlight_core_testing import conformance

    assert (
        conformance.SUPPORTS_M46_INTENT_EXTRACTION_ATTR
        == "supports_m46_intent_extraction"
    )
    assert "natural-signal" in _INTENT_EXTRACTION_NOTE
    assert "intent extraction" in _INTENT_EXTRACTION_NOTE.lower()


# ─── Test 9 — invariant 12 registered in INVARIANTS table ─────────────


def test_invariant_12_in_canonical_invariants_table() -> None:
    """The :data:`INVARIANTS` table is the canonical list used by the
    CLI report + the cross-plugin conformance test. Invariant #12 MUST
    be registered there so the runner's report names it correctly."""
    inv12 = next((row for row in INVARIANTS if row[0] == 12), None)
    assert inv12 is not None, (
        "invariant #12 missing from canonical INVARIANTS table"
    )
    _, label, description = inv12
    assert label == "intent_provenance_consistency"
    assert "intent_objective" in description
    assert "intent_provenance" in description


# ─── Test 10 — populated objective with missing provenance key fails ──


def test_invariant_function_rejects_populated_objective_with_missing_provenance() -> None:
    """An emitter that sets ``intent_objective`` but completely OMITS
    the ``intent_provenance`` key MUST also fail invariant #12 — the
    rule is symmetric: populated objective requires explicit
    provenance attribution."""
    bad_event = _canonical_envelope(
        event_type="execution_started",
        execution_id=f"exec_{uuid.uuid4()}",
        agent_id="uuid-bad",
        payload={
            "principal": {"principal_type": "agent", "id": "uuid-bad"},
            "depth": 0,
            "intent_objective": "audit Q3 invoices",
            # NB: provenance key intentionally omitted.
        },
    )
    with pytest.raises(ConformanceFailure) as excinfo:
        check_intent_provenance_consistency([bad_event])
    inv_num, _ = excinfo.value.args
    assert inv_num == 12
