"""The contract a framework integration implements.

**Contributor surface, not a public API.** This module may change in any
release; users import ``watchlight.<framework>.governed_plugin`` instead.

A framework integration is DATA, not code: it names the published framework
plugin (its module and class) and the extra that installs it. The governance
decisions an integration depends on — which backend the plugin talks to, the
refusal of per-call terms at construction time, the fail-closed default when
no policy is loaded — are made in one function,
:func:`watchlight.inprocess._select_backend_kwargs`. Every framework
integration is on this contract and reaches it only through
:func:`build_governed_plugin`, which also refuses a keyword that would replace
the backend it chose. No integration imports its plugin or calls
``_select_backend_kwargs`` (or ``in_process_backend``) itself;
``tests/test_layering.py`` refuses both.

The registry-driven tests in ``tests/integrations/`` and the layering test
catch the mistakes we know how to look for: a missing refusal, a direct plugin
import, an import of governor internals. They are a check, not a proof — a
hand-written factory that ignores this contract can still be wrong, which is
why a new integration is reviewed against it.

Adding a framework:

1. a module ``watchlight/integrations/<name>.py`` declaring a
   :class:`FrameworkIntegration` and a documented ``governed_plugin`` that calls
   :func:`build_governed_plugin`;
2. one line in ``watchlight/integrations/__init__.py`` registering it, and a
   public alias module ``watchlight/<name>.py``;
3. the extra in ``pyproject.toml``.
"""

from __future__ import annotations

import importlib
import keyword
import re
from dataclasses import dataclass
from typing import Any, Dict, FrozenSet, Optional

from ..inprocess import Policies, _select_backend_kwargs

_NAME = re.compile(r"^[a-z][a-z0-9_]*$")
_EXTRA = re.compile(r"^[a-z][a-z0-9-]*$")
#: A published Watchlight framework plugin package: a top-level ``watchlight_*``
#: module. Never one of the packages below, which are not framework plugins.
PLUGIN_MODULE = re.compile(r"^watchlight_[a-z0-9_]+$")
NOT_A_PLUGIN: FrozenSet[str] = frozenset({"watchlight_engine", "watchlight_core"})
_CLASS = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

#: Keywords that select the governance backend. The backend is chosen by
#: ``_select_backend_kwargs`` (``WATCHLIGHT_APDP_URL`` or the in-process engine);
#: a caller passing one of these through ``**plugin_kwargs`` would silently
#: replace that choice, so they are refused.
BACKEND_KEYS: FrozenSet[str] = frozenset({"governance", "apdp_url"})


@dataclass(frozen=True)
class FrameworkIntegration:
    """One framework integration: which published plugin it builds, and how a
    user installs it.

    :param name: the public module name — users import
        ``watchlight.<name>.governed_plugin``.
    :param extra: the pip extra that installs the plugin —
        ``pip install 'watchlight[<extra>]'``.
    :param display_name: the framework's name as a user reads it in an error.
    :param plugin_module: the published plugin package, a top-level
        ``watchlight_*`` module (never ``watchlight_engine`` or ``watchlight_core``).
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
        # only when a user calls the factory.
        if not (isinstance(self.name, str) and _NAME.match(self.name) and not keyword.iskeyword(self.name)):
            raise ValueError(f"integration name must be a lowercase identifier, got {self.name!r}")
        if not (isinstance(self.extra, str) and _EXTRA.match(self.extra)):
            raise ValueError(f"integration extra must be a lowercase pip extra name, got {self.extra!r}")
        if not (isinstance(self.display_name, str) and self.display_name.strip()):
            raise ValueError("integration display_name must be a non-empty string")
        if not (
            isinstance(self.plugin_module, str)
            and PLUGIN_MODULE.match(self.plugin_module)
            and self.plugin_module not in NOT_A_PLUGIN
        ):
            raise ValueError(
                "integration plugin_module must be a top-level watchlight_* plugin package "
                f"(not {sorted(NOT_A_PLUGIN)}), got {self.plugin_module!r}"
            )
        if not (isinstance(self.plugin_class, str) and _CLASS.match(self.plugin_class)):
            raise ValueError(f"integration plugin_class must be an identifier, got {self.plugin_class!r}")

    @property
    def install_hint(self) -> str:
        return f"pip install 'watchlight[{self.extra}]'"


def _missing_extra(integration: FrameworkIntegration) -> ImportError:
    return ImportError(
        f"governed {integration.display_name} support requires the "
        f"{integration.extra} extra: {integration.install_hint}"
    )


def _load_plugin_class(integration: FrameworkIntegration) -> Any:
    """Import the published plugin class lazily, so ``import watchlight`` never
    pulls a framework.

    Only "the plugin package is not installed" and "it has no such class" become
    the install hint. Any other error raised while the plugin imports — a broken
    dependency inside it, a bug — propagates as itself, so it is not disguised
    as a missing extra."""
    # The one dynamic import in the package. tests/test_layering.py exempts this
    # module from its dynamic-import check and attributes this call to the
    # registered plugin packages, so a second dynamic import added here would
    # pass that check unseen: any such change needs a reviewer's eye.
    try:
        module = importlib.import_module(integration.plugin_module)
    except ModuleNotFoundError as exc:
        if exc.name != integration.plugin_module:
            raise
        raise _missing_extra(integration) from exc
    try:
        return getattr(module, integration.plugin_class)
    except AttributeError as exc:
        raise _missing_extra(integration) from exc


def _refuse_backend_overrides(plugin_kwargs: Dict[str, Any]) -> None:
    for key in sorted(BACKEND_KEYS & set(plugin_kwargs)):
        raise TypeError(
            f"governed_plugin() does not take `{key}` — the governance backend is "
            "chosen for you: set WATCHLIGHT_APDP_URL for a networked policy service, "
            "or leave it unset for the in-process engine."
        )


def build_governed_plugin(
    integration: FrameworkIntegration,
    policies: Policies,
    *,
    audit_path: Optional[str],
    plugin_kwargs: Dict[str, Any],
) -> Any:
    """Build ``integration``'s published plugin, governed.

    * a keyword that would replace the chosen backend (:data:`BACKEND_KEYS`) is
      refused before anything is built;
    * ``_select_backend_kwargs`` then refuses per-call governance terms
      (``principal``, ``context``, ``resource``) by name and picks the backend:
      ``WATCHLIGHT_APDP_URL`` set → the plugin's own networked client, otherwise
      the in-process engine with a local, value-free audit trail, where
      ``policies=None`` denies every action (fail-closed).
    """
    plugin_cls = _load_plugin_class(integration)
    _refuse_backend_overrides(plugin_kwargs)
    return plugin_cls(**_select_backend_kwargs(policies, audit_path, plugin_kwargs))
