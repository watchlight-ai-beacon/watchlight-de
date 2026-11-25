"""Shared pytest setup for the watchlight-core tests.

**Engine required in CI.** The in-process tests (`test_in_process_client.py`
and the others that call `pytest.importorskip("watchlight_engine")`) skip
when the compiled engine is not installed, so a plain `pip install -e .[dev]`
still runs the rest of the suite. In CI a skip would hide them: CI installs
the engine (`watchlight-engine`) and sets WATCHLIGHT_REQUIRE_ENGINE=1 (any
non-empty value but "0" counts), and then a missing or broken engine fails
the run here instead of skipping.

**Per-test time bounds for the connector tests.** A module that sets
``ASYNC_TEST_TIMEOUT_S`` has each of its coroutine tests wrapped in
``asyncio.wait_for``, so a wedged connection fails the test fast instead of
hanging the suite (pytest-timeout is not a dependency).
"""

from __future__ import annotations

import asyncio
import functools
import inspect
import os

import pytest


def engine_required() -> bool:
    """Any non-empty WATCHLIGHT_REQUIRE_ENGINE other than "0" requires it."""
    return os.environ.get("WATCHLIGHT_REQUIRE_ENGINE", "").strip() not in ("", "0")


def pytest_configure(config: pytest.Config) -> None:
    if not engine_required():
        return
    try:
        import watchlight_engine  # noqa: F401, PLC0415 — optional compiled dep
    except ImportError as exc:
        raise pytest.UsageError(
            "WATCHLIGHT_REQUIRE_ENGINE is set but watchlight_engine does not import "
            f"({exc!r}); install it first (pip install watchlight-engine)"
        ) from exc


@pytest.fixture(autouse=True)
def _no_connector_endpoint_left_behind():
    """A connector endpoint stays registered for the life of a process, and
    the provider SDK gate then requires a run on every request. Each test
    gets a process that never met a connector."""
    from watchlight_core import attribution

    attribution._endpoints.clear()
    yield
    attribution._endpoints.clear()


def pytest_collection_modifyitems(config, items):
    for item in items:
        bound = getattr(getattr(item, "module", None), "ASYNC_TEST_TIMEOUT_S", None)
        fn = getattr(item, "obj", None)
        if bound is None or not inspect.iscoroutinefunction(fn):
            continue

        def wrap(f, seconds):
            @functools.wraps(f)
            async def bounded(*args, **kwargs):
                return await asyncio.wait_for(f(*args, **kwargs), seconds)

            return bounded

        item.obj = wrap(fn, bound)


@pytest.fixture(autouse=True)
def _fresh_root_admission():
    """Each test starts with no governed run live in the process.

    Many tests open a run and never close it; without this the next test's
    root would be refused as an escaped nested run.
    """
    _forget_live_runs()
    yield
    _forget_live_runs()


def _forget_live_runs() -> None:
    from watchlight_core import root_admission

    with root_admission._lock:
        root_admission._runs.clear()
        root_admission._refused_spawns.clear()
        root_admission._pending_roots = 0
