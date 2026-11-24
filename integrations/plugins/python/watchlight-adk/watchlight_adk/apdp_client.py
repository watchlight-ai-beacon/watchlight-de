"""Backwards-compatible re-export of :class:`ApdpClient` from
:mod:`watchlight_core`.

This module previously shipped a near-identical copy of the WL-APDP
HTTP client. The canonical implementation now lives in
``watchlight_core.ApdpClient`` and this module is a thin re-export
so existing ``from watchlight_adk.apdp_client import ApdpClient``
imports continue to work.

New code should import directly from ``watchlight_core``.
"""

from watchlight_core import ApdpClient

__all__ = ["ApdpClient"]
