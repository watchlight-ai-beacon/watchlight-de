"""Credential.from_aws_secret / from_default with AWS Secrets Manager."""

from __future__ import annotations

import json
import sys
import types

import pytest

from watchlight_core.credentials import (
    Credential,
    CredentialNotFound,
    InvalidCredential,
)

TOKEN = "wlpa_" + "a" * 43


# In-process stand-in for unit tests only.
def _stub_boto3(monkeypatch, secret_string=None, error_code=None):
    calls = []

    class _Client:
        def get_secret_value(self, SecretId):
            calls.append(SecretId)
            if error_code:
                exc = Exception("boom")
                exc.response = {"Error": {"Code": error_code}}
                raise exc
            return {"SecretString": secret_string}

    module = types.ModuleType("boto3")
    module.client = lambda service: _Client()
    monkeypatch.setitem(sys.modules, "boto3", module)
    return calls


@pytest.fixture
def plugin_env(monkeypatch):
    for key in ("WATCHLIGHT_PLUGIN_TOKEN", "WATCHLIGHT_APDP_TOKEN", "WL_APDP_BEARER",
                "WL_STAGING_APDP_TOKEN", "WATCHLIGHT_CREDENTIAL_FILE"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("WATCHLIGHT_TENANT_ID", "default")
    monkeypatch.setenv("WATCHLIGHT_PLUGIN_KIND", "claims-agent")


def test_plain_string_secret(monkeypatch, plugin_env):
    calls = _stub_boto3(monkeypatch, secret_string=TOKEN + "\n")
    cred = Credential.from_aws_secret("beacon/agents/claims-agent")
    assert cred.bearer_token == TOKEN
    assert cred.tenant_id() == "default"
    assert calls == ["beacon/agents/claims-agent"]


def test_json_secret_with_token_field(monkeypatch, plugin_env):
    _stub_boto3(monkeypatch, secret_string=json.dumps({"token": TOKEN}))
    assert Credential.from_aws_secret("s").bearer_token == TOKEN


def test_default_loader_prefers_the_secret_over_env(monkeypatch, plugin_env):
    _stub_boto3(monkeypatch, secret_string=TOKEN)
    monkeypatch.setenv("WATCHLIGHT_PLUGIN_TOKEN", "wlpa_" + "b" * 43)
    monkeypatch.setenv("WATCHLIGHT_CREDENTIAL_AWS_SECRET_ID", "s")
    assert Credential.from_default().bearer_token == TOKEN


def test_aws_errors_do_not_leak_and_fail_closed(monkeypatch, plugin_env):
    _stub_boto3(monkeypatch, error_code="AccessDeniedException")
    with pytest.raises(CredentialNotFound) as err:
        Credential.from_aws_secret("s")
    assert "AccessDeniedException" in str(err.value)


def test_empty_secret_is_invalid(monkeypatch, plugin_env):
    _stub_boto3(monkeypatch, secret_string="   ")
    with pytest.raises(InvalidCredential):
        Credential.from_aws_secret("s")


def test_missing_boto3_says_how_to_install(monkeypatch, plugin_env):
    monkeypatch.setitem(sys.modules, "boto3", None)
    with pytest.raises(CredentialNotFound) as err:
        Credential.from_aws_secret("s")
    assert "watchlight-agent-sdk[aws]" in str(err.value)
