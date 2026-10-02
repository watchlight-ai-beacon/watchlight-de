"""Govern a LangGraph agent in-process — the public entry point.

    from watchlight.langgraph import governed_plugin

The implementation lives in :mod:`watchlight.integrations.langgraph`, on the
shared framework-integration contract. This module is its stable public name.
"""

from __future__ import annotations

from .integrations.langgraph import governed_plugin

__all__ = ["governed_plugin"]
