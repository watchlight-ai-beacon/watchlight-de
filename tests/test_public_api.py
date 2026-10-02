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

import pytest

import watchlight

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
    "watchlight.integrations",
    "watchlight.langgraph",
    "watchlight.policytest",
    "watchlight.principals",
    "watchlight.pydantic_ai",
    "watchlight.scope_token",
]

# Public classes and functions whose ``__module__`` is the package root today.
ROOT_DEFINED = [
    "AuthorizeError",
    "AuthorizeRequestError",
    "Denied",
    "EgressTimeout",
    "NeedsApproval",
    "ReservedContextError",
    "SanitizeError",
    "ScreenError",
    "UnresolvedContextError",
    "Watchlight",
    "can_configure_default",
    "configure_default",
    "register_detector",
    "register_screen_family",
    "registered_detectors",
    "registered_screen_families",
    "sanitize",
    "screen",
]


def test_all_is_exactly_the_snapshot():
    assert sorted(watchlight.__all__) == PUBLIC_NAMES


@pytest.mark.parametrize("name", PUBLIC_NAMES)
def test_every_public_name_imports(name):
    assert hasattr(watchlight, name)


@pytest.mark.parametrize("module", PUBLIC_MODULES)
def test_every_public_module_imports(module):
    importlib.import_module(module)


@pytest.mark.parametrize("name", ROOT_DEFINED)
def test_root_objects_keep_their_public_module(name):
    assert getattr(watchlight, name).__module__ == "watchlight"


@pytest.mark.parametrize("module", ["watchlight.langgraph", "watchlight.pydantic_ai", "watchlight.claude_agent"])
def test_every_framework_entry_point_keeps_governed_plugin(module):
    assert callable(importlib.import_module(module).governed_plugin)


def test_the_backend_seam_keeps_its_names():
    from watchlight.inprocess import Policies, in_process_backend  # noqa: F401
