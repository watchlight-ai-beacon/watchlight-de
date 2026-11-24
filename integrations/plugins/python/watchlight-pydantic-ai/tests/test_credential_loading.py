"""A configured credential that cannot be loaded never degrades silently."""

from __future__ import annotations

import logging

import pytest

from watchlight_pydantic_ai import WatchlightPydanticAIPlugin

_CRED_ENV = (
    "WATCHLIGHT_PLUGIN_TOKEN",
    "WATCHLIGHT_CREDENTIAL_FILE",
    "WATCHLIGHT_CREDENTIAL_AWS_SECRET_ID",
)


@pytest.fixture(autouse=True)
def _clean_credential_env(monkeypatch):
    for name in _CRED_ENV:
        monkeypatch.delenv(name, raising=False)


def test_a_malformed_configured_credential_file_raises(monkeypatch, tmp_path):
    bad = tmp_path / "plugin.cred"
    bad.write_text("wlpa_SECRETVALUE\n")
    monkeypatch.setenv("WATCHLIGHT_CREDENTIAL_FILE", str(bad))
    with pytest.raises(Exception) as err:
        WatchlightPydanticAIPlugin(apdp_url="http://localhost", auto_instrument=False)
    assert "SECRETVALUE" not in str(err.value)
    assert err.value.__cause__ is None


def test_a_missing_configured_credential_file_raises(monkeypatch, tmp_path):
    monkeypatch.setenv("WATCHLIGHT_CREDENTIAL_FILE", str(tmp_path / "absent.cred"))
    with pytest.raises(Exception):
        WatchlightPydanticAIPlugin(apdp_url="http://localhost", auto_instrument=False)


def test_an_unloadable_aws_secret_raises(monkeypatch):
    monkeypatch.setenv("WATCHLIGHT_CREDENTIAL_AWS_SECRET_ID", "no-such-secret")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "invalid")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "invalid")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    monkeypatch.setenv("AWS_ENDPOINT_URL", "http://127.0.0.1:9")
    monkeypatch.setenv("AWS_MAX_ATTEMPTS", "1")
    monkeypatch.setenv("AWS_RETRY_MODE", "standard")
    with pytest.raises(Exception):
        WatchlightPydanticAIPlugin(apdp_url="http://localhost", auto_instrument=False)


def test_a_malformed_env_credential_is_logged_not_silent(monkeypatch, caplog):
    monkeypatch.setenv("WATCHLIGHT_PLUGIN_TOKEN", "not-a-real-token")
    with caplog.at_level(logging.WARNING):
        WatchlightPydanticAIPlugin(apdp_url="http://localhost", auto_instrument=False)
    messages = " ".join(r.getMessage() for r in caplog.records)
    assert "could not be loaded" in messages
    assert "not-a-real-token" not in messages


def test_no_configured_credential_stays_quiet(caplog):
    with caplog.at_level(logging.WARNING):
        WatchlightPydanticAIPlugin(apdp_url="http://localhost", auto_instrument=False)
    assert "could not be loaded" not in " ".join(r.getMessage() for r in caplog.records)
