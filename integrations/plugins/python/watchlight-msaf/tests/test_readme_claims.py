"""The msaf package translates events and enforces nothing.

Its README and package metadata must say so, and must not claim
authorization or fail-closed enforcement the package does not perform.
Samples keep credentials out of source code.
"""

from __future__ import annotations

import re
from pathlib import Path

import watchlight_msaf

_ROOT = Path(__file__).resolve().parent.parent


def test_readme_states_no_enforcement():
    text = (_ROOT / "README.md").read_text()
    assert "authorize every agent action" not in text
    assert "puts a Watchlight authorization decision in front of" not in text
    assert "It does not enforce anything" in text


def test_pyproject_description_does_not_claim_enforcement():
    text = (_ROOT / "pyproject.toml").read_text()
    desc = re.search(r'^description = "(.*)"', text, re.MULTILINE).group(1)
    assert "fail-closed" not in desc
    assert "authorize" not in desc


def test_package_docstring_states_no_enforcement():
    assert "does not" in watchlight_msaf.__doc__
    assert "never blocks or denies" in watchlight_msaf.__doc__


def test_readme_has_no_inline_api_key():
    text = (_ROOT / "README.md").read_text()
    assert not re.search(r"api_key\s*=\s*[\"']", text)
