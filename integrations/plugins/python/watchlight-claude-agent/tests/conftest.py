"""Shared fixtures for watchlight-claude-agent tests."""

from __future__ import annotations

import os

import pytest


@pytest.fixture(autouse=True)
def _no_ambient_application_id(monkeypatch: pytest.MonkeyPatch) -> None:
    """A developer's shell must never change what these tests assert.

    ``WATCHLIGHT_APPLICATION_ID`` is a deployment default the plugin
    reads at construction. Tests that want it set it explicitly.
    """
    monkeypatch.delenv("WATCHLIGHT_APPLICATION_ID", raising=False)


@pytest.fixture(autouse=True)
def _no_ambient_claude_settings(monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
    """The developer's own Claude Code settings and bare-mode variable must
    never change what these tests assert: ``governed_options`` reads every
    settings source. Managed settings and MDM profiles point at
    empty test locations, and the working directory has no project
    settings."""
    from watchlight_claude_agent import session_guard
    from watchlight_claude_agent.cli_surface import ALLOWED_ENV, is_governed_env_name

    # A session started from inside Claude Code inherits its variables.
    for name in list(os.environ):
        if is_governed_env_name(name) and name not in ALLOWED_ENV:
            monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(tmp_path / "claude-config"))
    monkeypatch.setattr(session_guard, "_managed_dir", lambda: tmp_path / "managed")
    monkeypatch.setattr(session_guard, "_mdm_plist_paths", lambda: [])
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    monkeypatch.chdir(cwd)
