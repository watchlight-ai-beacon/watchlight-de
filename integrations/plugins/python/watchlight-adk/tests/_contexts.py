"""Callback contexts for tests that call the plugin's callbacks directly.

A bare ``MagicMock`` answers every attribute, ``live_request_queue`` and
``run_config.support_cfc`` included, so the plugin reads it as a live
invocation and refuses it.
"""

from __future__ import annotations

from unittest.mock import MagicMock


def non_live_context() -> MagicMock:
    """A callback context whose invocation is not live (``run_async``)."""
    ctx = MagicMock()
    ctx._invocation_context.live_request_queue = None
    ctx._invocation_context.run_config.support_cfc = False
    return ctx
