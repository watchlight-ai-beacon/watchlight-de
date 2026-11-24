"""Test doubles and the conformance runner for Watchlight plugins.

This distribution (``watchlight-agent-sdk-testing``) is for tests only.
It depends on ``watchlight-agent-sdk``; the SDK never depends on it, and
none of it ships in the SDK wheel. Install it in a test environment:

    pip install watchlight-agent-sdk-testing

``MockApdpClient`` denies by default: a test that needs an allow says so,
with ``default_decision="Allow"`` or a per-``(action, resource)`` rule.
"""

from __future__ import annotations

from . import _doubles
from ._doubles import *  # noqa: F401,F403 (the public test API)

__all__ = list(_doubles.__all__)
