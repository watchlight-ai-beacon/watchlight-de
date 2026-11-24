"""The template's defaults fail closed: no plaintext policy-service URL, and
no event dropped without being logged and counted."""

from __future__ import annotations

import logging

import pytest

from watchlight_template import (
    WatchlightTemplatePlugin,
    dropped_event_counts,
    translate_template_events,
)
from watchlight_template import traces


def test_the_policy_service_url_has_no_default():
    with pytest.raises(TypeError):
        WatchlightTemplatePlugin()  # type: ignore[call-arg]


def test_the_install_ca_comes_from_the_argument_then_the_environment(tmp_path, monkeypatch):
    seen = []

    class Recording:
        def __init__(self, url, api_key=None, ca_bundle=None):
            seen.append(ca_bundle)

    monkeypatch.setattr("watchlight_template.plugin.ApdpClient", Recording)
    monkeypatch.setenv("WATCHLIGHT_APDP_TLS_CA_BUNDLE", "/etc/watchlight/ca.pem")
    WatchlightTemplatePlugin(apdp_url="https://policy.example")
    WatchlightTemplatePlugin(apdp_url="https://policy.example", ca_bundle=tmp_path / "ca.pem")
    monkeypatch.delenv("WATCHLIGHT_APDP_TLS_CA_BUNDLE")
    WatchlightTemplatePlugin(apdp_url="https://policy.example")
    assert seen == ["/etc/watchlight/ca.pem", tmp_path / "ca.pem", None]


def test_an_event_the_translator_raises_on_is_logged_at_error_and_counted(monkeypatch, caplog):
    def broken(*_args, **_kwargs):
        raise ValueError("bad callback")

    monkeypatch.setattr(traces, "translate_template_event", broken)
    before = dropped_event_counts().get("translator_error", 0)
    with caplog.at_level(logging.ERROR, logger="watchlight_template.traces"):
        out = translate_template_events([{"hook": "on_tool_start"}], execution_id="e", agent_id="a")
    assert out == []
    assert dropped_event_counts().get("translator_error", 0) == before + 1
    assert any(r.levelno == logging.ERROR and "dropped" in r.getMessage() for r in caplog.records)


@pytest.mark.parametrize("hook", [{"intended_tools": "not-a-list"}, {"intended_tools": []}])
def test_a_malformed_plan_is_logged_at_error_and_counted(hook, caplog):
    before = dropped_event_counts().get("plan_malformed", 0)
    with caplog.at_level(logging.ERROR, logger="watchlight_template.traces"):
        assert traces._build_plan_observed(hook, execution_id="e", agent_id="a") is None
    assert dropped_event_counts().get("plan_malformed", 0) == before + 1
    assert any(r.levelno == logging.ERROR for r in caplog.records)


def test_a_plan_that_fails_validation_is_logged_at_error_and_counted(monkeypatch, caplog):
    def invalid(**_kwargs):
        raise traces.PlanValidationError("too many tools")

    monkeypatch.setattr(traces, "build_plan_payload", invalid)
    before = dropped_event_counts().get("plan_invalid", 0)
    with caplog.at_level(logging.ERROR, logger="watchlight_template.traces"):
        assert traces._build_plan_observed({"intended_tools": ["search"]}, execution_id="e", agent_id="a") is None
    assert dropped_event_counts().get("plan_invalid", 0) == before + 1
    assert any(r.levelno == logging.ERROR and "validation" in r.getMessage() for r in caplog.records)
