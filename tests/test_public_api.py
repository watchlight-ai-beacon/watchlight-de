"""The public API, pinned.

``watchlight`` is on PyPI, so a refactor that moves code must not move a public
name. This file is the snapshot every such move is checked against: each name
in ``watchlight.__all__``, each public module path, and the module a public
class or function reports (``__module__`` shows in reprs and tracebacks and is
what pickle records). A move keeps these by re-exporting and, for an object
that relocates, setting ``__module__`` back to its public home.

Adding to the API means adding to this snapshot in the same change. Removing
from it needs a deprecation release first.
"""

from __future__ import annotations

import importlib
import inspect
import pickle

import pytest

import watchlight
import watchlight.inprocess

PUBLIC_NAMES = [
    "ACTOR_CHAIN_CONTEXT_KEY",
    "ACTOR_CONTEXT_KEY",
    "AGENT_ENV",
    "APPROVAL_KEY_LABEL",
    "APPROVAL_MIN_SECRET_BYTES",
    "APPROVAL_PAYLOAD_VERSION",
    "APPROVAL_PRUNE_GRACE_MS",
    "APPROVAL_PRUNE_INTERVAL_MS",
    "ASYNC_CONTEXT_MESSAGE",
    "AUDIT_DIR_ENV",
    "AUDIT_FILE_ENV",
    "ApprovalError",
    "ApprovalStore",
    "AttenuationDenied",
    "AttenuationRecord",
    "AuditRecord",
    "AuditRecordBase",
    "AuditSink",
    "AuditTrailUnreadable",
    "AuthorizeError",
    "AuthorizeRequestError",
    "CounterSource",
    "CounterSourceError",
    "DECISION_ID_MAX_LENGTH",
    "DEFAULT_COUNTERS_MAX_BYTES",
    "DEFAULT_MAX_DELEGATION_DEPTH",
    "DEFAULT_ON_RESULT_TIMEOUT_MS",
    "DEFAULT_PII_TYPES",
    "DELEGATION_DEPTH_EXCEEDED",
    "DETECTOR_VERSION",
    "DecisionRecord",
    "DelegationDepthExceeded",
    "Denied",
    "EGRESS_TIMEOUT_MESSAGE",
    "ENFORCEMENT_EFFECTS",
    "ENFORCEMENT_EFFECT_ANNOTATION",
    "EgressRecord",
    "EgressTimeout",
    "HEURISTIC_PII_TYPES",
    "MAX_ACTOR_CHAIN",
    "MAX_COUNTERS_LINE_BYTES",
    "MAX_COUNTERS_NESTING",
    "MAX_COUNTERS_WINDOW_SECONDS",
    "MAX_COUNTER_VALUE",
    "MAX_REDACT_ENTRIES",
    "NeedsApproval",
    "OBLIGATIONS_INVALID_MESSAGE",
    "PolicyError",
    "REQUEST_INVALID_MESSAGE",
    "RESERVED_CONTEXT_MESSAGE",
    "ReservedContextError",
    "SCREEN_FAMILIES",
    "SIGNING_SECRET_CONFLICT_MESSAGE",
    "SYNC_TIMEOUT_MESSAGE",
    "SanitizationRecord",
    "SanitizeError",
    "Scope",
    "ScopePreview",
    "ScopeTokenError",
    "ScreenError",
    "ScreeningRecord",
    "UNCONFIGURED_AGENT",
    "UNRESOLVED_CONTEXT_MESSAGE",
    "UnknownAuditRecord",
    "UnresolvedContextError",
    "Watchlight",
    "can_configure_default",
    "configure_default",
    "count_audit_records",
    "govern",
    "load_test_suite",
    "parse_window_seconds",
    "principals",
    "register_detector",
    "register_screen_family",
    "registered_detectors",
    "registered_screen_families",
    "run_policy_tests",
    "sanitize",
    "screen",
]

PUBLIC_MODULES = [
    "watchlight",
    "watchlight.attenuation",
    "watchlight.claude_agent",
    "watchlight.cli",
    "watchlight.inprocess",
    "watchlight.langgraph",
    "watchlight.policytest",
    "watchlight.principals",
    "watchlight.pydantic_ai",
    "watchlight.scope_token",
]

# The module every public class and function reports. ``__module__`` shows in
# reprs and tracebacks and is what pickle records, so a move must not change it.
PUBLIC_OBJECT_MODULES = {
    "ApprovalError": "watchlight._approval",
    "ApprovalStore": "watchlight._approval",
    "AttenuationDenied": "watchlight.attenuation",
    "AttenuationRecord": "watchlight._audit",
    "AuditRecordBase": "watchlight._audit",
    "AuditTrailUnreadable": "watchlight._counters",
    "AuthorizeError": "watchlight",
    "AuthorizeRequestError": "watchlight",
    "CounterSourceError": "watchlight._counters",
    "DecisionRecord": "watchlight._audit",
    "DelegationDepthExceeded": "watchlight.attenuation",
    "Denied": "watchlight",
    "EgressRecord": "watchlight._audit",
    "EgressTimeout": "watchlight",
    "NeedsApproval": "watchlight",
    "PolicyError": "watchlight._annotations",
    "ReservedContextError": "watchlight",
    "SanitizationRecord": "watchlight._audit",
    "SanitizeError": "watchlight",
    "Scope": "watchlight.attenuation",
    "ScopePreview": "watchlight.attenuation",
    "ScopeTokenError": "watchlight.scope_token",
    "ScreenError": "watchlight",
    "ScreeningRecord": "watchlight._audit",
    "UnresolvedContextError": "watchlight",
    "Watchlight": "watchlight",
    "can_configure_default": "watchlight",
    "configure_default": "watchlight",
    "count_audit_records": "watchlight._counters",
    "load_test_suite": "watchlight.policytest",
    "parse_window_seconds": "watchlight._counters",
    "register_detector": "watchlight",
    "register_screen_family": "watchlight",
    "registered_detectors": "watchlight",
    "registered_screen_families": "watchlight",
    "run_policy_tests": "watchlight.policytest",
    "sanitize": "watchlight",
    "screen": "watchlight",
}

# The framework entry points: every attribute each has always had (names a user
# may have imported from it), its first docstring line, and where its factory
# says it lives.
FRAMEWORK_ALIASES = {
    "watchlight.langgraph": "Govern a LangGraph agent in-process, with zero infrastructure.",
    "watchlight.pydantic_ai": "Govern a Pydantic AI agent in-process, with zero infrastructure.",
    "watchlight.claude_agent": "Govern a Claude Agent SDK agent in-process, with zero infrastructure.",
}
FRAMEWORK_ALIAS_ATTRS = {"Any", "Optional", "Policies", "_select_backend_kwargs", "annotations", "governed_plugin"}

# Contributor surface: importable, but NOT a public API — it may change in any
# release without deprecation. Pinned here only so that it is a decision, not
# an accident, when it moves.
CONTRIBUTOR_MODULES = ["watchlight.integrations", "watchlight.integrations._contract"]


def test_all_is_exactly_the_snapshot():
    assert sorted(watchlight.__all__) == PUBLIC_NAMES


@pytest.mark.parametrize("name", PUBLIC_NAMES)
def test_every_public_name_imports(name):
    assert hasattr(watchlight, name)


@pytest.mark.parametrize("module", PUBLIC_MODULES)
def test_every_public_module_imports(module):
    importlib.import_module(module)


def test_every_public_object_is_pinned():
    objects = {
        n for n in watchlight.__all__ if inspect.isclass(getattr(watchlight, n)) or inspect.isfunction(getattr(watchlight, n))
    }
    assert objects == set(PUBLIC_OBJECT_MODULES)


@pytest.mark.parametrize("name", sorted(PUBLIC_OBJECT_MODULES))
def test_public_objects_keep_their_module(name):
    assert getattr(watchlight, name).__module__ == PUBLIC_OBJECT_MODULES[name]


@pytest.mark.parametrize("module", sorted(FRAMEWORK_ALIASES))
def test_every_framework_entry_point_is_unchanged(module):
    mod = importlib.import_module(module)
    assert {n for n in vars(mod) if not n.startswith("__")} == FRAMEWORK_ALIAS_ATTRS
    assert not hasattr(mod, "__all__")  # `from watchlight.<framework> import *` unchanged
    assert mod.__doc__.splitlines()[0] == FRAMEWORK_ALIASES[module]
    assert callable(mod.governed_plugin)
    assert mod.governed_plugin.__module__ == module
    assert mod.governed_plugin.__qualname__ == "governed_plugin"
    assert mod.Policies is watchlight.inprocess.Policies
    assert mod._select_backend_kwargs is watchlight.inprocess._select_backend_kwargs


@pytest.mark.parametrize("module", sorted(FRAMEWORK_ALIASES))
def test_a_framework_factory_pickles_by_its_public_name(module):
    factory = importlib.import_module(module).governed_plugin
    assert pickle.loads(pickle.dumps(factory)) is factory


@pytest.mark.parametrize("module", CONTRIBUTOR_MODULES)
def test_the_contributor_surface_imports(module):
    importlib.import_module(module)


def test_the_backend_seam_keeps_its_names():
    from watchlight.inprocess import Policies, in_process_backend  # noqa: F401
