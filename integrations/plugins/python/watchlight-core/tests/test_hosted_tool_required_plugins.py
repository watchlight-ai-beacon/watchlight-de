"""Invariant 19 for every plugin in ``HOSTED_TOOL_PLUGINS_REQUIRED``.

Some required plugins never call ``run_conformance``, so the required list
is checked here directly: each listed plugin is imported, built and driven
through ``check_hosted_tool_gate_wired``. A plugin still in
``HOSTED_TOOL_PLUGINS_PENDING`` reports PENDING; every other listed plugin
must pass.

The CI ``python-plugins`` job runs these tests in the venv that installs
every plugin, with ``WATCHLIGHT_REQUIRE_ENGINE`` set. There, and in any
venv where one required plugin is installed, a plugin that cannot be
imported is a FAILURE, never a skip. Only a core-only venv (no required
plugin installed, no CI signal) skips, so the core suite still runs on
its own locally.
"""

from __future__ import annotations

import importlib.util
import os

import pytest

from watchlight_core_testing.conformance import (
    HOSTED_TOOL_PENDING,
    HOSTED_TOOL_PLUGINS_PENDING,
    HOSTED_TOOL_PLUGINS_REQUIRED,
    check_required_hosted_tool_plugin,
)


def _module(dist: str) -> str:
    return dist.replace("-", "_")


def _installed(dist: str) -> bool:
    return importlib.util.find_spec(_module(dist)) is not None


def _plugins_required() -> bool:
    """True in the python-plugins CI job, or wherever any required plugin
    is installed: then a missing plugin fails instead of skipping."""
    signal = os.environ.get("WATCHLIGHT_REQUIRE_ENGINE", "").strip() not in ("", "0")
    return signal or any(_installed(d) for d in HOSTED_TOOL_PLUGINS_REQUIRED)


@pytest.mark.asyncio
@pytest.mark.parametrize("dist", HOSTED_TOOL_PLUGINS_REQUIRED)
async def test_a_required_plugin_passes_or_is_pending(dist: str) -> None:
    if not _plugins_required():
        pytest.skip("core-only venv: no required plugin installed")
    result = await check_required_hosted_tool_plugin(_module(dist))
    if dist in HOSTED_TOOL_PLUGINS_PENDING:
        assert result in (HOSTED_TOOL_PENDING, "ok")
    else:
        assert result == "ok"
