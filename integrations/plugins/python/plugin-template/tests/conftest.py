"""Shared fixtures for the template plugin's tests."""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _no_ambient_application_id(monkeypatch: pytest.MonkeyPatch) -> None:
    """A developer's shell must never change what these tests assert.

    ``WATCHLIGHT_APPLICATION_ID`` is a deployment default the plugin
    reads at construction. Tests that want it set it explicitly.
    """
    monkeypatch.delenv("WATCHLIGHT_APPLICATION_ID", raising=False)
