"""Framework integrations: one module per framework, all on one contract.

Each integration declares a :class:`FrameworkIntegration` and exposes a
documented ``governed_plugin`` factory built on :func:`build_governed_plugin`.
Users import it from its public alias, ``watchlight.<name>``.

:data:`INTEGRATIONS` is the registry. The test suite iterates it, so every
integration listed here is held to the same guarantees automatically.
"""

from __future__ import annotations

from types import MappingProxyType
from typing import Mapping

from ._contract import FrameworkIntegration, build_governed_plugin
from .langgraph import INTEGRATION as _LANGGRAPH

__all__ = ["FrameworkIntegration", "build_governed_plugin", "INTEGRATIONS"]

#: Every framework integration on the contract, by public module name.
INTEGRATIONS: Mapping[str, FrameworkIntegration] = MappingProxyType(
    {i.name: i for i in (_LANGGRAPH,)}
)
