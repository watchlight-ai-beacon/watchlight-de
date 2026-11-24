"""The CI minimum-version pin is the declared floor.

CI runs this suite a second time with
``ci/min-versions.txt`` as pip constraints. That only tests the floor if
the pin IS the floor declared in ``pyproject.toml``.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _floor_in_pyproject() -> str:
    text = (ROOT / "pyproject.toml").read_text()
    found = re.findall(r'"google-adk>=([0-9][0-9.]*),<3"', text)
    assert len(found) == 1, found
    return found[0]


def _ci_pin() -> str:
    pins = [
        line.split("==", 1)[1].strip()
        for line in (ROOT / "ci" / "min-versions.txt").read_text().splitlines()
        if line.startswith("google-adk==")
    ]
    assert len(pins) == 1, pins
    return pins[0]


def test_the_ci_pin_is_the_declared_google_adk_floor():
    assert _ci_pin() == _floor_in_pyproject()


def test_the_floor_has_the_run_error_hooks_the_plugin_relies_on():
    """2.5.0 is the first google-adk with ``on_run_error_callback``: a
    run that raises records its terminal event only through it."""
    assert tuple(int(p) for p in _floor_in_pyproject().split(".")) >= (2, 5, 0)
    from google.adk.plugins.base_plugin import BasePlugin

    assert hasattr(BasePlugin, "on_run_error_callback")
    assert hasattr(BasePlugin, "on_agent_error_callback")
