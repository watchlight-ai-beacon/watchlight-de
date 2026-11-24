"""Plan governance is ``strict`` unless the operator explicitly opts
into ``degrade``; a missing constraint manifest refuses the run."""

from __future__ import annotations

import logging

import pytest

from watchlight_core import GovernanceUnavailable, governance_mode, require_manifest


class _Capture(logging.Handler):
    def __init__(self) -> None:
        super().__init__(logging.DEBUG)
        self.records: list = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


@pytest.fixture
def env_log():
    """Capture the env module's records directly (independent of whether
    another test turned off propagation on the ``watchlight`` tree)."""
    logger = logging.getLogger("watchlight.core.env")
    handler = _Capture()
    logger.addHandler(handler)
    yield handler
    logger.removeHandler(handler)


def test_governance_mode_is_strict_when_unset(monkeypatch) -> None:
    monkeypatch.delenv("WATCHLIGHT_PLAN_GOVERNANCE_MODE", raising=False)
    assert governance_mode() == "strict"


def test_governance_mode_unrecognised_value_is_strict(monkeypatch) -> None:
    monkeypatch.setenv("WATCHLIGHT_PLAN_GOVERNANCE_MODE", "degarde")
    assert governance_mode() == "strict"


def test_governance_mode_degrade_only_on_explicit_opt_in_and_logged(
    monkeypatch, env_log
) -> None:
    monkeypatch.setenv("WATCHLIGHT_PLAN_GOVERNANCE_MODE", " Degrade ")
    assert governance_mode() == "degrade"
    assert any(
        r.levelno >= logging.WARNING and "degrade" in r.getMessage().lower()
        for r in env_log.records
    )


def test_missing_manifest_refuses_run_by_default(monkeypatch) -> None:
    monkeypatch.delenv("WATCHLIGHT_PLAN_GOVERNANCE_MODE", raising=False)
    with pytest.raises(GovernanceUnavailable):
        require_manifest(None, agent_id="agent-1")


def test_missing_manifest_is_degraded_only_with_explicit_opt_in(
    monkeypatch, env_log
) -> None:
    monkeypatch.setenv("WATCHLIGHT_PLAN_GOVERNANCE_MODE", "degrade")
    assert require_manifest(None, agent_id="agent-1") == "degraded"
    assert any(
        r.levelno >= logging.WARNING and "agent-1" in r.getMessage()
        for r in env_log.records
    )


def test_present_manifest_is_strong(monkeypatch) -> None:
    monkeypatch.delenv("WATCHLIGHT_PLAN_GOVERNANCE_MODE", raising=False)
    assert require_manifest({"agent_id": "agent-1"}, agent_id="agent-1") == "strong"
