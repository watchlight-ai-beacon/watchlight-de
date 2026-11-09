"""The test-only distribution itself.

``MockApdpClient`` denies anything it was not told to allow, so a test
that forgets to configure it can never pass through an allow by omission.
The SDK keeps no copy of the doubles or the runner, and ``python -m
watchlight_core`` points at this package without importing it.
"""

from __future__ import annotations

import asyncio
import runpy

import pytest

from watchlight_core_testing import MockApdpClient


def _decide(client: MockApdpClient) -> str:
    response = asyncio.run(client.authorize(
        'Agent::"a"', 'Action::"execute"', 'Resource::"tool/x"', {}, "exec_1", "ses_1"))
    return response["decision"]


def test_a_bare_double_denies() -> None:
    assert _decide(MockApdpClient()) == "Deny"


def test_an_explicit_allow_allows() -> None:
    assert _decide(MockApdpClient(default_decision="Allow")) == "Allow"


def test_the_sdk_keeps_no_copy_of_the_doubles() -> None:
    with pytest.raises(ModuleNotFoundError):
        import watchlight_core.testing  # noqa: F401


def test_the_sdk_keeps_no_copy_of_the_runner() -> None:
    with pytest.raises(ModuleNotFoundError):
        import watchlight_core.conformance  # noqa: F401


def test_the_runner_is_importable_from_its_new_home() -> None:
    from watchlight_core_testing import conformance

    assert callable(conformance._main)


def test_python_m_watchlight_core_points_at_the_new_package(capsys: pytest.CaptureFixture) -> None:
    # It never imports the test package itself: the AST scan in
    # watchlight-core/tests/test_runtime_never_imports_testing.py covers
    # watchlight_core/__main__.py with the rest of the SDK.
    with pytest.raises(SystemExit) as exc:
        runpy.run_module("watchlight_core", run_name="__main__")
    assert exc.value.code == 2
    assert "pip install watchlight-agent-sdk-testing" in capsys.readouterr().err


@pytest.mark.parametrize("value", ["allow", "ALLOW", "permit", ""])
def test_an_unknown_default_decision_is_refused_at_construction(value: str) -> None:
    with pytest.raises(ValueError, match="default_decision must be one of"):
        MockApdpClient(default_decision=value)


def test_an_unknown_default_decision_is_refused_on_assignment() -> None:
    client = MockApdpClient()
    with pytest.raises(ValueError):
        client.default_decision = "allow"
    assert client.default_decision == "Deny"


@pytest.mark.parametrize("value", sorted(MockApdpClient.KNOWN_DECISIONS))
def test_every_known_decision_is_accepted(value: str) -> None:
    assert MockApdpClient(default_decision=value).default_decision == value
