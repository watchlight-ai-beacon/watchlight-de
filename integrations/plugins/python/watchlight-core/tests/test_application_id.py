"""``resolve_application_id`` — the one client-side reader for ``application_id``.

Every plugin passes the per-run argument, the constructor argument and
the ``WATCHLIGHT_APPLICATION_ID`` env var through this helper, so the
rules below hold at every entry point: ``None`` / empty / whitespace
mean unset, surrounding whitespace is trimmed, and a value that is not
a UUID is refused with ``ValueError`` before anything reaches the wire.
It is a format check only; wl-apdp stays the authority on membership.
"""

from __future__ import annotations

import pytest

from watchlight_core import (
    APPLICATION_ID_ENV_VAR,
    application_id_from_env,
    resolve_application_id,
)
from watchlight_core_testing import MockApdpClient

APP = "0b6f7c2e-5d1a-4c8e-9f3b-2a1d4e5f6a7b"


@pytest.fixture(autouse=True)
def _no_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(APPLICATION_ID_ENV_VAR, raising=False)


def test_the_env_var_name_is_the_one_every_plugin_documents() -> None:
    assert APPLICATION_ID_ENV_VAR == "WATCHLIGHT_APPLICATION_ID"


@pytest.mark.parametrize("value", [None, "", "   ", "\t\n"])
def test_none_empty_and_whitespace_mean_unset(value: str | None) -> None:
    assert resolve_application_id(value) is None


def test_a_uuid_passes_through_unchanged() -> None:
    assert resolve_application_id(APP) == APP


@pytest.mark.parametrize("value", [f"  {APP}", f"{APP}\n", f"\t {APP} \t"])
def test_surrounding_whitespace_is_trimmed(value: str) -> None:
    assert resolve_application_id(value) == APP


def test_the_value_is_not_canonicalised() -> None:
    # A format check only — the server decides the canonical form.
    assert resolve_application_id(APP.upper()) == APP.upper()


@pytest.mark.parametrize(
    "value",
    [
        "my-app",
        "0b6f7c2e",
        f"{APP}x",
        APP[:-1],
        "not a uuid at all",
        f"{APP} {APP}",
    ],
)
def test_a_non_uuid_is_refused(value: str) -> None:
    with pytest.raises(ValueError, match="^application_id must be a UUID$"):
        resolve_application_id(value)


def test_a_non_string_is_refused() -> None:
    with pytest.raises(ValueError, match="^application_id must be a UUID$"):
        resolve_application_id(123)  # type: ignore[arg-type]


def test_env_reader_returns_none_when_unset() -> None:
    assert application_id_from_env() is None


@pytest.mark.parametrize("value", ["", "   "])
def test_env_reader_treats_empty_and_whitespace_as_unset(
    monkeypatch: pytest.MonkeyPatch, value: str
) -> None:
    monkeypatch.setenv(APPLICATION_ID_ENV_VAR, value)
    assert application_id_from_env() is None


def test_env_reader_trims(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(APPLICATION_ID_ENV_VAR, f"  {APP} ")
    assert application_id_from_env() == APP


def test_env_reader_refuses_a_non_uuid(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(APPLICATION_ID_ENV_VAR, "my-app")
    with pytest.raises(ValueError, match="^application_id must be a UUID$"):
        application_id_from_env()


@pytest.mark.asyncio
async def test_mock_client_accepts_application_id_and_echoes_it() -> None:
    """The mock keeps the real ``ApdpClient.create_session`` signature.

    Every plugin forwards ``application_id`` when it resolves to a
    value, so a mock without the parameter raised ``TypeError`` for
    any developer with ``WATCHLIGHT_APPLICATION_ID`` exported.
    """
    mock = MockApdpClient()
    with_app = await mock.create_session(agent_id="agent-uuid", application_id=APP)
    assert with_app is not None
    assert with_app.session["application_id"] == APP

    without = await mock.create_session(agent_id="agent-uuid")
    assert without is not None
    assert without.session["application_id"] is None
