"""Backwards-compatible re-export of :class:`ApdpClient` from
:mod:`watchlight_core`.

Earlier releases shipped a near-identical copy of the client in this
module. New code should import directly from ``watchlight_core``; this
shim exists only so existing
``from watchlight_langgraph.apdp_client import ApdpClient`` imports
continue to resolve.
"""

from watchlight_core import ApdpClient

__all__ = ["ApdpClient"]
