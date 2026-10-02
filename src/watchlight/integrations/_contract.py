"""The contract a framework integration implements.

A framework integration is DATA, not code: it names the published framework
plugin (its module and class) and the extra that installs it. Everything that
governs — which backend the plugin talks to, the refusal of per-call terms at
construction time, the fail-closed default when no policy is loaded — lives in
exactly one place, :func:`build_governed_plugin`, so an integration cannot
skip it, weaken it, or drift from its siblings.

Adding a framework is therefore three small changes:

1. a module ``watchlight/integrations/<name>.py`` declaring a
   :class:`FrameworkIntegration` and a documented ``governed_plugin`` that calls
   :func:`build_governed_plugin`;
2. one line in ``watchlight/integrations/__init__.py`` registering it, and a
   two-line public alias ``watchlight/<name>.py``;
3. the extra in ``pyproject.toml``.

The registry-driven tests then hold the new integration to every guarantee its
siblings meet, without a test being written for it by hand.
"""

from __future__ import annotations

import importlib
import keyword
import re
from dataclasses import dataclass
from typing import Any, Dict, Optional

from ..inprocess import Policies, _select_backend_kwargs

_NAME = re.compile(r"^[a-z][a-z0-9_]*$")
_EXTRA = re.compile(r"^[a-z][a-z0-9-]*$")
_DOTTED = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$")
_CLASS = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


@dataclass(frozen=True)
class FrameworkIntegration:
    """One framework integration: which published plugin it builds, and how a
    user installs it.

    :param name: the public module name — users import
        ``watchlight.<name>.governed_plugin``.
    :param extra: the pip extra that installs the plugin —
        ``pip install 'watchlight[<extra>]'``.
    :param display_name: the framework's name as a user reads it in an error.
    :param plugin_module: the import path of the published plugin package.
    :param plugin_class: the plugin class in that module. It must accept
        ``governance=`` (the in-process backend) and ``apdp_url=`` (networked).
    """

    name: str
    extra: str
    display_name: str
    plugin_module: str
    plugin_class: str

    def __post_init__(self) -> None:
        # Validated where it is declared: a typo here would otherwise surface
        # only when a user calls the factory, as an import error naming a
        # package that does not exist.
        if not (isinstance(self.name, str) and _NAME.match(self.name) and not keyword.iskeyword(self.name)):
            raise ValueError(f"integration name must be a lowercase identifier, got {self.name!r}")
        if not (isinstance(self.extra, str) and _EXTRA.match(self.extra)):
            raise ValueError(f"integration extra must be a lowercase pip extra name, got {self.extra!r}")
        if not (isinstance(self.display_name, str) and self.display_name.strip()):
            raise ValueError("integration display_name must be a non-empty string")
        if not (isinstance(self.plugin_module, str) and _DOTTED.match(self.plugin_module)):
            raise ValueError(f"integration plugin_module must be a dotted module path, got {self.plugin_module!r}")
        if not (isinstance(self.plugin_class, str) and _CLASS.match(self.plugin_class)):
            raise ValueError(f"integration plugin_class must be an identifier, got {self.plugin_class!r}")

    @property
    def install_hint(self) -> str:
        return f"pip install 'watchlight[{self.extra}]'"


def _load_plugin_class(integration: FrameworkIntegration) -> Any:
    """Import the published plugin class lazily, so ``import watchlight`` never
    pulls a framework. A missing package OR a missing class is an ImportError
    naming the extra — never a half-built plugin."""
    try:
        module = importlib.import_module(integration.plugin_module)
        return getattr(module, integration.plugin_class)
    except (ImportError, AttributeError) as exc:
        raise ImportError(
            f"governed {integration.display_name} support requires the "
            f"{integration.extra} extra: {integration.install_hint}"
        ) from exc


def build_governed_plugin(
    integration: FrameworkIntegration,
    policies: Policies,
    *,
    audit_path: Optional[str],
    plugin_kwargs: Dict[str, Any],
) -> Any:
    """Build ``integration``'s published plugin, governed.

    The single path every ``watchlight.<framework>.governed_plugin`` takes:

    * ``WATCHLIGHT_APDP_URL`` set → the plugin's own networked client;
      otherwise → the in-process engine with a local, value-free audit trail.
    * ``policies=None`` → no policies, so every action is denied (fail-closed).
    * a per-call governance term (``principal``, ``context``, ``resource``)
      passed to the factory is refused by name before anything is built.
    """
    plugin_cls = _load_plugin_class(integration)
    return plugin_cls(**_select_backend_kwargs(policies, audit_path, plugin_kwargs))
