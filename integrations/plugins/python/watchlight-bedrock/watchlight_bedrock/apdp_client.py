"""Backwards-compatible re-export of :class:`ApdpClient` from
:mod:`watchlight_core`.

This module previously shipped a near-identical copy. New code should
import directly from ``watchlight_core``.
"""

from watchlight_core import ApdpClient

__all__ = ["ApdpClient"]
