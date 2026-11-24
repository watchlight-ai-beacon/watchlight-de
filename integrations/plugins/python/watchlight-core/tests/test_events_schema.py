"""Tests for the intent-provenance additions to ``events_schema``.

These tests pin the wire-format invariants that the Rust canonical
schema (``wl-lineage::events``) and the TypeScript zod mirror
(``watchlight-agent-sdk-ts/src/events.ts``) MUST also satisfy.
If any of these tests fail, the three SDKs have drifted on wire shape
and Cedar policies / dashboards will read inconsistent values.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from watchlight_core import (
    INTENT_OBJECTIVE_MAX_BYTES,
    IntentProvenance,
)
from watchlight_core.events_schema import (
    ExecutionStartedPayload,
    PrincipalRef,
)


def _principal() -> PrincipalRef:
    return PrincipalRef(principal_type="agent", id="agent-test")


class TestIntentProvenance:
    def test_wire_strings_match_rust_canonical(self) -> None:
        """The four wire strings are pinned by the design doc
        and by Cedar templates. Drift here breaks Cedar."""
        assert IntentProvenance.DECLARED.value == "declared"
        assert IntentProvenance.PLUGIN_DERIVED.value == "plugin_derived"
        assert IntentProvenance.PROXY_INFERRED.value == "proxy_inferred"
        assert IntentProvenance.ABSENT.value == "absent"

    def test_round_trips_via_str_value(self) -> None:
        """``str(Enum.value)`` is what ends up on the wire."""
        for variant in IntentProvenance:
            assert IntentProvenance(variant.value) == variant


class TestExecutionStartedPayloadM46B:
    def test_legacy_event_deserialises_with_no_provenance(self) -> None:
        """A legacy ``execution_started`` payload on the wire has NO
        ``intent_provenance`` field. The Pydantic model must accept
        that shape (intent_provenance=None) so existing audit-replay
        keeps working."""
        legacy = ExecutionStartedPayload.model_validate(
            {
                "principal": {"principal_type": "agent", "id": "agent-legacy"},
                "depth": 0,
            }
        )
        assert legacy.intent_provenance is None
        assert legacy.intent_objective is None

    def test_legacy_event_does_not_serialise_a_null_field(self) -> None:
        """``exclude_none=True`` (the default emission path) must NOT
        emit ``intent_provenance: null`` when the value is None — the
        wire shape MUST remain identical for emitters that
        haven't opted in. Bytes-on-the-wire MUST NOT grow without
        explicit emitter consent."""
        payload = ExecutionStartedPayload(principal=_principal(), depth=0)
        dumped = payload.model_dump(exclude_none=True)
        assert "intent_provenance" not in dumped
        assert "intent_objective" not in dumped

    def test_objective_with_provenance_passes(self) -> None:
        """The end-state happy path: objective + provenance both set."""
        p = ExecutionStartedPayload(
            principal=_principal(),
            intent_objective="audit Q3 invoices",
            intent_provenance=IntentProvenance.DECLARED,
        )
        assert p.intent_provenance == IntentProvenance.DECLARED
        assert p.intent_objective == "audit Q3 invoices"

    def test_objective_without_provenance_is_rejected(self) -> None:
        """The invariant: an unattributed objective silently
        downgrades enforcement and is forbidden at the wire boundary."""
        with pytest.raises(ValidationError) as excinfo:
            ExecutionStartedPayload(
                principal=_principal(),
                intent_objective="audit Q3 invoices",
                intent_provenance=None,
            )
        assert "provenance" in str(excinfo.value).lower()

    def test_objective_with_absent_provenance_is_rejected(self) -> None:
        """``Absent`` does NOT satisfy "recorded source" — emitters
        MUST pick declared / plugin_derived / proxy_inferred."""
        with pytest.raises(ValidationError):
            ExecutionStartedPayload(
                principal=_principal(),
                intent_objective="hi",
                intent_provenance=IntentProvenance.ABSENT,
            )

    def test_neither_field_set_passes(self) -> None:
        """The legacy / brownfield-Absent path: no objective, no
        provenance. Cedar treats this as ``IntentProvenance::Absent``
        and falls through to the brownfield warn-on-missing policy."""
        p = ExecutionStartedPayload(principal=_principal(), depth=0)
        assert p.intent_objective is None
        assert p.intent_provenance is None

    def test_absent_provenance_without_objective_passes(self) -> None:
        """Emitters that know the source is absent SHOULD set the
        explicit enum so Cedar reads a typed value."""
        p = ExecutionStartedPayload(
            principal=_principal(),
            intent_provenance=IntentProvenance.ABSENT,
        )
        assert p.intent_provenance == IntentProvenance.ABSENT

    @pytest.mark.parametrize(
        "prov",
        [
            IntentProvenance.DECLARED,
            IntentProvenance.PLUGIN_DERIVED,
            IntentProvenance.PROXY_INFERRED,
        ],
    )
    def test_each_concrete_provenance_accepts_objective(
        self, prov: IntentProvenance
    ) -> None:
        p = ExecutionStartedPayload(
            principal=_principal(),
            intent_objective="ok",
            intent_provenance=prov,
        )
        assert p.intent_provenance == prov

    def test_objective_over_byte_cap_is_rejected(self) -> None:
        """The byte-cap is operator-legibility plus padding-attack
        defence. 257 bytes of ASCII fails."""
        with pytest.raises(ValidationError) as excinfo:
            ExecutionStartedPayload(
                principal=_principal(),
                intent_objective="x" * (INTENT_OBJECTIVE_MAX_BYTES + 1),
                intent_provenance=IntentProvenance.DECLARED,
            )
        assert "intent_objective" in str(excinfo.value)

    def test_objective_byte_cap_is_byte_counted_not_char_counted(self) -> None:
        """Multi-byte UTF-8 must NOT slip past the cap by char-count.
        ``✓`` is 3 bytes per char; a string of 100 of them is 300
        bytes — over the 256 cap — and MUST fail."""
        with pytest.raises(ValidationError):
            ExecutionStartedPayload(
                principal=_principal(),
                intent_objective="✓" * 100,  # 300 bytes
                intent_provenance=IntentProvenance.DECLARED,
            )

    def test_objective_exactly_at_byte_cap_passes(self) -> None:
        p = ExecutionStartedPayload(
            principal=_principal(),
            intent_objective="x" * INTENT_OBJECTIVE_MAX_BYTES,
            intent_provenance=IntentProvenance.DECLARED,
        )
        assert len(p.intent_objective or "") == INTENT_OBJECTIVE_MAX_BYTES

    def test_serialisation_emits_snake_case_wire_string(self) -> None:
        """The dashboard + Cedar templates pattern-match on the
        snake_case form. Confirm the wire shape matches the doc."""
        p = ExecutionStartedPayload(
            principal=_principal(),
            intent_objective="hello",
            intent_provenance=IntentProvenance.PLUGIN_DERIVED,
        )
        dumped = p.model_dump(exclude_none=True)
        assert dumped["intent_provenance"] == "plugin_derived"

    def test_round_trip_via_dict(self) -> None:
        original = ExecutionStartedPayload(
            principal=_principal(),
            intent_objective="summarise Q3 audit",
            intent_provenance=IntentProvenance.PLUGIN_DERIVED,
        )
        round_tripped = ExecutionStartedPayload.model_validate(
            original.model_dump(exclude_none=True)
        )
        assert round_tripped.intent_provenance == IntentProvenance.PLUGIN_DERIVED
        assert round_tripped.intent_objective == "summarise Q3 audit"


class TestPublicReExports:
    def test_intent_provenance_is_re_exported(self) -> None:
        """The package-level import surface MUST expose the
        symbols so plugins import from ``watchlight_core`` directly,
        not from a sub-module."""
        import watchlight_core

        assert hasattr(watchlight_core, "IntentProvenance")
        assert hasattr(watchlight_core, "INTENT_OBJECTIVE_MAX_BYTES")
        assert watchlight_core.INTENT_OBJECTIVE_MAX_BYTES == 256
