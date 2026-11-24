"""Conformance runner — exercises a plugin against the canonical
invariants.

External plugins use this to self-certify:

.. code-block:: bash

    python -m watchlight_core_testing.conformance my_plugin_package

The runner loads the plugin module, drives a synthetic lifecycle
through it (start_run → authorize → emit events → spawn sub-agent
→ sub-agent authorize → complete), and asserts every invariant on
the emitted event stream plus the recorded authorize() calls.

Invariant 8 (sub-agent attribution) codifies the sub-agent
governance fix. It asserts that any authorize() call attributable
to a sub-agent's tool uses the sub-agent's principal, never the
root's.

Invariant 11 (handle short-circuits after Quarantine) runs against
a fresh plugin handle armed with a Quarantine response from
:class:`MockApdpClient`, then asserts every subsequent
``authorize_action`` call raises :class:`AgentQuarantinedError`
WITHOUT round-tripping to wl-apdp. That short-circuit is the
load-bearing semantic for the adaptive-authorization kill switch.
Plugins whose framework runtime hasn't yet wired the kill signal
can set ``supports_m45_quarantine = False`` on the plugin class to
mark invariant #11 SKIPPED with a warning. The opt-out is temporary
and is removed from the runner once every plugin wires the kill
signal.

Invariant 13 (scope_attenuation_propagation) is the Python lane
mirror of the TypeScript conformance invariant. It is an IF-PRESENT
check: any ``agent_spawn_observed`` event in the stream MUST carry a
populated ``delegation_scope`` payload field so audit replay can
reconstruct the effective authority at every depth in the spawn tree
(the sub-agent scope-attenuation contract, audited at every depth).

As of v0.9.12 spawn attestation is SERVER-emitted only:
wl-apdp's ``spawn_handler`` mints the single authoritative
``agent_spawn_observed`` — carrying the server-validated
``granted_scope`` — as it processes the ``POST /v1/spawn_subagent``
round-trip. Plugins MUST NOT emit ``agent_spawn_observed`` themselves;
the class is BLOCKED at ``/v1/events`` ingest
(``lineage_event_class_not_permitted``). So EVERY plugin's captured
stream now contains zero ``agent_spawn_observed`` events and this
invariant passes VACUOUSLY across the board. The guarantee is NOT
weakened — it is preserved server-side, where the scope is
server-validated before attestation rather than plugin-advised. The
invariant code is unchanged (still IF-present); it remains as a
consumer-side lock so that if a future stream ever carries an
``agent_spawn_observed`` event, its ``delegation_scope`` must still be
populated.

Invariant 14 (execution_started_precedes_non_lifecycle_events)
asserts every non-mint event in the captured stream has a preceding
``execution_started`` event with the same ``execution_id``. The
closed-set mint events (``execution_started`` /
``agent_spawn_observed`` / ``ungoverned_request_observed``) are
self-rooted; all other event types (including any future
plugin-emitted variants) default to non-mint and require an anchor
— a security-first safe default. The SDK's ``BaseRunHandle``
defensively emits ``execution_started`` before the first
``publish_observation`` / ``authorize_action_detailed`` round-trip,
which is the load-bearing SDK guard that makes this invariant
satisfiable; #14 locks the contract from the consumer side so a
future translator that bypasses the SDK lifecycle fails CI loudly.

Exit code:

  * ``0`` — all invariants passed (SKIPs do not count as failures).
  * ``1`` — at least one invariant failed; the report names which.
  * ``2`` — plugin couldn't be loaded (import error or missing
    canonical surface — see :func:`load_plugin_module`).

The same assertion helpers used here are imported by the in-repo
``tests/test_cross_plugin_conformance.py`` so the shipped plugins
exercise the exact same checks an external plugin runs.
"""

from __future__ import annotations

import argparse
import asyncio
import collections
import copy
import importlib
import sys
import uuid
from datetime import datetime, timezone
from types import ModuleType
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple

from watchlight_core.errors import AgentNotRegistered
from watchlight_core.scope import ChildIntent
from ._doubles import (
    ConformanceFailure,
    MockApdpClient,
    assert_canonical_event,
    assert_payload_matches_schema,
    capture_events,
)

__all__ = [
    "load_plugin_module",
    "discover_plugin_class",
    "discover_translator",
    "run_conformance",
    "check_handle_short_circuits_after_quarantine",
    "check_intent_provenance_consistency",
    "check_scope_attenuation_propagation",
    "check_execution_started_precedes_non_lifecycle_events",
    "check_single_correlated_execution_id",
    "assert_payload_schema_conformance",
    "PAYLOAD_SCHEMA_CONFORMANCE_INVARIANT_NUMBER",
    "PAYLOAD_SCHEMA_CONFORMANCE_INVARIANT_NAME",
    "INVARIANTS",
    "SUPPORTS_M45_QUARANTINE_ATTR",
    "SUPPORTS_M46_INTENT_EXTRACTION_ATTR",
    "SCOPE_ATTENUATION_PROPAGATION_INVARIANT_NUMBER",
    "SCOPE_ATTENUATION_PROPAGATION_INVARIANT_NAME",
    "EXECUTION_STARTED_PRECEDES_NON_LIFECYCLE_EVENTS_INVARIANT_NUMBER",
    "EXECUTION_STARTED_PRECEDES_NON_LIFECYCLE_EVENTS_INVARIANT_NAME",
    "EXECUTION_STARTED_PRECEDES_MINT_EVENTS",
    "SINGLE_CORRELATED_EXECUTION_ID_INVARIANT_NUMBER",
    "SINGLE_CORRELATED_EXECUTION_ID_INVARIANT_NAME",
    "LABELLED_SPAWN_ATTENUATED_INVARIANT_NUMBER",
    "LABELLED_SPAWN_ATTENUATED_INVARIANT_NAME",
    "check_labelled_spawn_attenuated",
    "CREDENTIAL_BOUND_ROOT_INVARIANT_NUMBER",
    "CREDENTIAL_BOUND_ROOT_INVARIANT_NAME",
    "check_credential_bound_root",
    "HOSTED_TOOLS_AUTHORIZED_INVARIANT_NUMBER",
    "HOSTED_TOOLS_AUTHORIZED_INVARIANT_NAME",
    "check_hosted_tools_authorized_before_model_call",
    "check_hosted_tool_gate_wired",
    "HOSTED_TOOL_CONFORMANCE_HOOK",
    "HOSTED_TOOL_PROBE_REQUEST",
    "HostedToolConformanceProbe",
    "RecordingModelClient",
    "SUPPORTS_HOSTED_TOOLS_ATTR",
    "HOSTED_TOOL_PENDING",
    "HOSTED_TOOL_PENDING_CORE_VERSION",
    "check_required_hosted_tool_plugin",
    "HOSTED_TOOL_CONFORMANCE_FACTORY",
    "HOSTED_TOOL_PLUGINS_PENDING",
    "HOSTED_TOOL_PLUGINS_REQUIRED",
    "HOSTED_TOOL_PROBE_MCP_URL",
    "HOSTED_TOOL_PROBE_REGISTRY",
    "HOSTED_TOOL_PROVIDER_ATTR",
]


# ─── Plugin discovery (load by import path) ───────────────────────────


def load_plugin_module(module_name: str) -> ModuleType:
    """Import the plugin's top-level module by name.

    Raises :class:`ImportError` if the module isn't installed.
    Raises :class:`AttributeError` if it doesn't expose the
    canonical SDK surface (a class ending in ``Plugin`` that
    subclasses :class:`GovernanceTelemetry`).
    """
    try:
        # nosemgrep: community.python.lang.security.audit.non-literal-import the conformance runner imports the plugin module its operator names on the command line; it is a test tool, never shipped in a runtime wheel
        return importlib.import_module(module_name)
    except ImportError as exc:
        raise ImportError(
            f"could not import plugin module {module_name!r}: {exc}. "
            f"Is it installed in the active environment?"
        ) from exc


def discover_plugin_class(module: ModuleType) -> type:
    """Find the plugin's main class.

    Convention: a single attribute whose name ends in ``Plugin``
    (e.g. ``WatchlightLangGraphPlugin``) and which is a subclass
    of :class:`GovernanceTelemetry`.

    Returns the class. Raises :class:`AttributeError` if zero or
    more than one match.
    """
    from watchlight_core.telemetry import GovernanceTelemetry  # local import — avoids
    # circular issues if GovernanceTelemetry is reorganised

    candidates = []
    for name in dir(module):
        if not name.endswith("Plugin"):
            continue
        attr = getattr(module, name)
        try:
            is_plugin = isinstance(attr, type) and issubclass(attr, GovernanceTelemetry)
        except TypeError:
            is_plugin = False
        if is_plugin:
            candidates.append(attr)

    if not candidates:
        raise AttributeError(
            f"{module.__name__} does not export a *Plugin class "
            f"subclassing GovernanceTelemetry"
        )
    if len(candidates) > 1:
        raise AttributeError(
            f"{module.__name__} exports multiple *Plugin classes "
            f"({[c.__name__ for c in candidates]}); the SDK convention "
            f"is one plugin class per package"
        )
    return candidates[0]


def discover_translator(module: ModuleType) -> Optional[Any]:
    """Find the plugin's event translator (optional).

    Convention: a function whose name matches the pattern
    ``translate_<framework>_event`` or ``translate_<framework>_events``
    (the plural variant for batch translators).

    Returns the function or None if the plugin doesn't expose one.
    Plugins that DON'T do canonical event emission (e.g. lifecycle-
    only plugins) are still conformant — they just skip the
    translator-shape invariants.
    """
    # Look for translate_*_events first (plural is preferred); fall
    # back to the singular.
    for suffix in ("_events", "_event"):
        for name in dir(module):
            if name.startswith("translate_") and name.endswith(suffix):
                attr = getattr(module, name)
                if callable(attr):
                    return attr
    return None


# ─── The seven invariants — same assertions as test_cross_plugin_conformance.py ──


def assert_envelope_shape(event: Dict[str, Any]) -> None:
    """Invariant 1: required + closed-set envelope fields."""
    assert_canonical_event(event)


def assert_source_tag(event: Dict[str, Any], expected_prefix: str) -> None:
    """Invariant 2: source attribution. ``expected_prefix``
    is the framework's tag prefix (e.g. ``"myframework"``)."""
    metadata = event.get("metadata") or {}
    source = metadata.get("source", "")
    if not isinstance(source, str) or not source.startswith(expected_prefix):
        raise ConformanceFailure(
            2,
            f"metadata.source {source!r} does not start with framework prefix "
            f"{expected_prefix!r}",
        )


def assert_canonical_event_type(event: Dict[str, Any]) -> None:
    """Invariant 3: event_type is in the closed canonical set."""
    # Bundled into assert_canonical_event for convenience.
    assert_canonical_event(event)


def assert_namespaced_uri(event: Dict[str, Any], framework: str) -> None:
    """Invariant 4: tool URI starts with ``<framework>://``.

    No-op for non-tool-call events.
    """
    if event.get("event_type") != "tool_call_observed":
        return
    assert_canonical_event(event, expected_uri_prefix=f"{framework}://")


def assert_event_id_format(event: Dict[str, Any]) -> None:
    """Invariant 5: event_id matches ``evt_<uuid>``."""
    assert_canonical_event(event)


def assert_bounded_sizes(event: Dict[str, Any]) -> None:
    """Invariant 6: bounded sizes on summaries, errors, plans."""
    assert_canonical_event(event)


def assert_no_unknown_keys(event: Dict[str, Any]) -> None:
    """Invariant 7: closed-set envelope keys."""
    assert_canonical_event(event)


#: Invariant #16 — exported number/name so plugin authors writing their
#: own conformance wrappers reference a stable identifier.
PAYLOAD_SCHEMA_CONFORMANCE_INVARIANT_NUMBER = 16
PAYLOAD_SCHEMA_CONFORMANCE_INVARIANT_NAME = "payload_schema_conformance"


def assert_payload_schema_conformance(event: Dict[str, Any]) -> None:
    """Invariant 16: the payload deserializes into the canonical
    payload struct its ``event_type`` selects.

    Thin re-export of
    :func:`watchlight_core_testing.assert_payload_matches_schema` so the
    invariant is addressable by name from this module like the others.
    ``assert_canonical_event`` already calls it, so every plugin that
    runs the conformance suite — in-repo or self-certifying via
    ``python -m watchlight_core_testing.conformance`` — is covered without
    per-plugin wiring.
    """
    assert_payload_matches_schema(event)


#: The canonical invariants in numbered order. Used by the CLI
#: report and the cross-plugin conformance test.
#:
#: Invariant 8 (sub-agent attribution) locks in the sub-agent
#: governance fix.
INVARIANTS: List[Tuple[int, str, str]] = [
    (1, "envelope_shape", "Every event carries the 6 required envelope fields"),
    (2, "source_attribution", "metadata.source is set + framework-namespaced"),
    (3, "canonical_event_type", "event_type is in the closed canonical set"),
    (4, "namespaced_resource_uri", "tool URI starts with <framework>://"),
    (5, "event_id_format", "event_id matches evt_<uuid>"),
    (6, "bounded_sizes", "input_summary, rationale, intended_tools within caps"),
    (7, "closed_set_envelope", "no unknown top-level keys"),
    (
        8,
        "subagent_authz_attribution",
        "sub-agent tool calls authorized against SUB-AGENT's principal",
    ),
    (
        9,
        "subagent_lineage_continuity",
        "sub-agent events carry root_execution_id + parent_execution_id "
        "matching the spawn tree",
    ),
    # Invariant 10 is reserved for a follow-up; numbered here so the
    # quarantine short-circuit check can claim 11 without renumbering.
    (
        11,
        "handle_short_circuits_after_quarantine",
        "after a handle transitions to Quarantined, every subsequent "
        "authorize_action / spawn_subagent call MUST short-circuit "
        "(raise AgentQuarantinedError) without round-tripping to wl-apdp",
    ),
    (
        12,
        "intent_provenance_consistency",
        "every execution_started event MUST satisfy: intent_objective "
        "populated ⇒ intent_provenance ∈ {declared, plugin_derived, "
        "proxy_inferred}; intent_objective absent ⇒ intent_provenance "
        "is absent OR omitted entirely. Inconsistent pairs (populated "
        "objective with provenance == absent, OR absent objective with "
        "non-absent provenance) are CONTRACT VIOLATIONS.",
    ),
    (
        13,
        "scope_attenuation_propagation",
        "every agent_spawn_observed event MUST carry a populated "
        "delegation_scope payload field so audit replay can "
        "reconstruct the effective authority at every depth in the "
        "spawn tree, audited at every depth. "
        "Plugins whose framework has no sub-agent primitive pass "
        "vacuously; plugins that DO spawn MUST stamp the "
        "server-attested granted scope.",
    ),
    (
        14,
        "execution_started_precedes_non_lifecycle_events",
        "every non-mint event (policy_decision_made, tool_call_observed, "
        "api_request_observed, execution_completed, execution_failed, "
        "plan_observed, execution_quarantined, execution_resumed, and "
        "any custom plugin-emitted event type) MUST have a preceding "
        "execution_started event with the same execution_id within the "
        "captured event stream. The closed-set mint events "
        "(execution_started, agent_spawn_observed, "
        "ungoverned_request_observed) are self-rooted: spawn mints a "
        "child execution, ungoverned_request_observed is the "
        "anomaly self-rooted shape. Lineage projection's recursive CTE "
        "cannot stitch the tree if a non-mint event lacks a started "
        "anchor — the dashboard would render the event as an orphan. "
        "Closed-set MINT_EVENTS by safe-default: any event type not in "
        "the mint set requires a preceding started (covers future "
        "plugin-emitted variants without silently downgrading the "
        "contract).",
    ),
    (
        15,
        "single_correlated_execution_id",
        "ONE canonical execution_id per run across every emitter (the "
        "execution-id correlation contract). Within one "
        "run's captured event stream, all ROOT execution_started events "
        "(those with no parent_execution_id) MUST share a single "
        "execution_id — the orchestrator handle's own id. A second, "
        "divergent root is the 'orphaned orchestrator execution' bug: "
        "wl-execution-graph mints one lineage.executions row per distinct "
        "execution_id, so two roots ⇒ two root rows ⇒ one orphan. Every "
        "SUB-agent execution_started (parent_execution_id set) MUST carry "
        "root_execution_id == that single root so the whole spawn tree "
        "groups under one root. Catches any emitter (SDK defensive mint, "
        "framework callback, spawn pair, or a future translator) that "
        "mints a fresh id for a run that already has a root.",
    ),
    (
        PAYLOAD_SCHEMA_CONFORMANCE_INVARIANT_NUMBER,
        PAYLOAD_SCHEMA_CONFORMANCE_INVARIANT_NAME,
        "every event's payload MUST deserialize into the canonical "
        "payload struct its event_type selects (the pydantic mirror in "
        "watchlight_core.events_schema, lockstep with "
        "the wl-lineage event schema). wl-apdp's POST /v1/events dispatches "
        "on event_type and fails closed on a mismatch — 422 'data did not "
        "match any variant of untagged enum "
        "IngestExecutionEventsRequest' — REJECTING THE WHOLE BATCH, so "
        "one malformed event erases a whole run from lineage. Lineage "
        "publish is fail-open by design (it must never block a run), so "
        "nothing surfaces to the operator: the emitter is the only place "
        "this can be caught. Covers the typed sub-structs (PrincipalRef "
        "needs principal_type + id, ResourceRef needs resource_type + "
        "identifier) and unknown payload keys the server would silently "
        "drop. Enforced inside assert_canonical_event so every plugin "
        "gets it from one check rather than a per-plugin copy.",
    ),
    (
        17,
        "labelled_spawn_attenuated",
        "every agent_spawn_observed event that carries a spawned_label "
        "(a sub-agent that is not a registered agent, identified by its "
        "parent run and its label) MUST carry a valid label and the "
        "granted_scope it was attenuated to under its parent. The label "
        "is evidence, never an authority. Vacuous when no labelled spawn "
        "appears in the stream (spawn events are server-emitted).",
    ),
    (
        18,
        "credential_bound_root",
        "a plugin starts its root run without naming an agent: the run "
        "is opened as the agent its verified credential is bound to, "
        "never an agent declared in code. Checked by "
        "check_credential_bound_root, which drives the start directly "
        "(not part of run_conformance).",
    ),
    (
        19,
        "hosted_tools_authorized_before_model_call",
        "every provider-hosted tool enabled on a model call (web search, "
        "code execution, file search, remote MCP, ...) has an Allow "
        "decision in that turn before the call is made, and a hosted tool "
        "refused in a turn (deny, approval required, error, timeout) means "
        "the model is not called in that turn. Checked by "
        "check_hosted_tools_authorized_before_model_call on a recorded "
        "trace of the plugin's model turns (not part of run_conformance).",
    ),
]

#: Invariant #17 — mirrors the TS lane's ``LABELLED_SPAWN_ATTENUATED_*``.
LABELLED_SPAWN_ATTENUATED_INVARIANT_NUMBER = 17
LABELLED_SPAWN_ATTENUATED_INVARIANT_NAME = "labelled_spawn_attenuated"
#: Invariant #18 — mirrors the TS lane's ``CREDENTIAL_BOUND_ROOT_*``.
CREDENTIAL_BOUND_ROOT_INVARIANT_NUMBER = 18
CREDENTIAL_BOUND_ROOT_INVARIANT_NAME = "credential_bound_root"


def check_labelled_spawn_attenuated(events: List[Dict[str, Any]]) -> None:
    """Invariant #17 — a labelled spawn is an attenuated spawn.

    Every ``agent_spawn_observed`` whose payload carries ``spawned_label``
    must carry a label that passes
    :func:`watchlight_core.validate_child_label` and a ``granted_scope``
    object: an unregistered child is always spawned under its parent with
    a strict subset of the parent's scope. Spawn events without a label
    are left to invariant #13. Vacuous when none appears.

    Raises :class:`ConformanceFailure` on the first violation.
    """
    from watchlight_core.root_identity import validate_child_label

    for i, event in enumerate(events):
        if event.get("event_type") != "agent_spawn_observed":
            continue
        payload = event.get("payload")
        if not isinstance(payload, dict) or "spawned_label" not in payload:
            continue
        label = payload.get("spawned_label")
        if label is None:
            continue
        try:
            validate_child_label(label)
        except ValueError:
            raise ConformanceFailure(
                LABELLED_SPAWN_ATTENUATED_INVARIANT_NUMBER,
                f"event[{i}] (agent_spawn_observed) spawned_label is not a valid label",
            ) from None
        scope = payload.get("granted_scope")
        if not isinstance(scope, dict):
            raise ConformanceFailure(
                LABELLED_SPAWN_ATTENUATED_INVARIANT_NUMBER,
                f"event[{i}] (agent_spawn_observed) is a labelled spawn without "
                "granted_scope; an unregistered child must be attenuated under its parent",
            )


async def check_credential_bound_root(
    start_run_without_slug: Callable[[], Awaitable[Any]],
    expected_agent_id: str,
) -> None:
    """Invariant #18 — the root run is the credential's agent.

    ``start_run_without_slug`` starts the plugin's root run naming no agent
    against a backend whose credential is bound to ``expected_agent_id``
    (e.g. :class:`~watchlight_core_testing.MockApdpClient` with
    ``credential_agent`` set) and returns the run handle (anything with an
    ``agent_uuid``) or a :class:`~watchlight_core.backend.SessionInfo`
    (``agent_id``). The run must be opened as that agent.

    Raises :class:`ConformanceFailure` when the start fails or opens the
    run as any other agent.
    """
    try:
        handle = await start_run_without_slug()
    except Exception as exc:  # noqa: BLE001 — reported as the failure
        raise ConformanceFailure(
            CREDENTIAL_BOUND_ROOT_INVARIANT_NUMBER,
            f"starting the root run with no slug failed: {type(exc).__name__}",
        ) from exc
    agent = getattr(handle, "agent_uuid", None) or getattr(handle, "agent_id", None)
    if agent != expected_agent_id:
        raise ConformanceFailure(
            CREDENTIAL_BOUND_ROOT_INVARIANT_NUMBER,
            f"the root run with no slug was opened as {agent!r}, not the "
            f"credential's agent {expected_agent_id!r}",
        )


# ─── Invariant 19 (hosted tools authorized before the model call) ─────

#: Invariant #19 — mirrors the TS lane's ``HOSTED_TOOLS_AUTHORIZED_*``.
HOSTED_TOOLS_AUTHORIZED_INVARIANT_NUMBER = 19
HOSTED_TOOLS_AUTHORIZED_INVARIANT_NAME = "hosted_tools_authorized_before_model_call"


def _hosted_identity(value: Any) -> Optional[Tuple[str, str, Optional[str]]]:
    """``(provider, kind, server)`` of a hosted tool, a ``{provider, kind,
    server}`` dict, or an authorize context's ``hosted_tool``."""
    if isinstance(value, dict):
        provider, kind, server = value.get("provider"), value.get("kind"), value.get("server")
    else:
        provider, kind = getattr(value, "provider", None), getattr(value, "kind", None)
        server = None
    if isinstance(provider, str) and isinstance(kind, str):
        return provider, kind, server if isinstance(server, str) else None
    return None


def _shown(identity: Tuple[str, str, Optional[str]]) -> str:
    provider, kind, server = identity
    return f"{provider}:{kind}" + (f"@{server}" if server else "")


def check_hosted_tools_authorized_before_model_call(steps: List[Dict[str, Any]]) -> None:
    """Invariant #19 — a model call runs only with every hosted tool allowed.

    ``steps`` is a plugin's recorded trace, in order, of two kinds of step:

    - ``{"step": "authorize", "context": {...}, "decision": "Allow"}``: an
      ``/authorize`` request the plugin made (its ``context`` as sent) and
      the decision it got (``Allow``, ``Deny``, ``needs_approval``, or
      ``error`` when the request failed or timed out).
    - ``{"step": "model_call", "hosted_tools": [...]}``: a model call the
      plugin made, with the hosted tools enabled on it
      (``{"provider", "kind", "server"}`` dicts, as
      :func:`watchlight_core.hosted_tool_identity` gives them, or
      ``HostedTool`` values, whose server is unknown).

    A turn is the authorize steps after the previous model call. Every
    hosted tool on a model call must have an ``Allow`` in its turn whose
    ``context.hosted_tool`` names the same provider, kind and (for remote
    MCP) registered server, and no hosted tool may have been refused in
    that turn. A remote MCP tool with no registered server never matches.

    Raises :class:`ConformanceFailure` on the first violation.
    """
    turn: List[Dict[str, Any]] = []
    for i, step in enumerate(steps):
        kind = step.get("step") if isinstance(step, dict) else None
        if kind == "authorize":
            turn.append(step)
            continue
        if kind != "model_call":
            raise ConformanceFailure(
                HOSTED_TOOLS_AUTHORIZED_INVARIANT_NUMBER,
                f"step[{i}] is neither an authorize nor a model_call step",
            )
        allowed = set()
        for auth in turn:
            raw_context = auth.get("context")
            context: Dict[str, Any] = raw_context if isinstance(raw_context, dict) else {}
            identity = _hosted_identity(context.get("hosted_tool"))
            if identity is None:
                continue
            if auth.get("decision") != "Allow":
                raise ConformanceFailure(
                    HOSTED_TOOLS_AUTHORIZED_INVARIANT_NUMBER,
                    f"step[{i}] (model_call) was made after hosted tool "
                    f"{_shown(identity)} was refused in the same turn",
                )
            allowed.add(identity)
        for tool in step.get("hosted_tools") or []:
            identity = _hosted_identity(tool)
            unmatched = identity is None or identity not in allowed
            if identity is not None and identity[1] == "mcp" and identity[2] is None:
                unmatched = True
            if unmatched:
                shown = _shown(identity) if identity else "an unnamed hosted tool"
                raise ConformanceFailure(
                    HOSTED_TOOLS_AUTHORIZED_INVARIANT_NUMBER,
                    f"step[{i}] (model_call) enables {shown} with no Allow in its turn",
                )
        turn = []


#: A plugin class attribute: ``True`` when the plugin's framework can put
#: provider-hosted tools on a model call. Such a plugin must define the
#: hook below, and the conformance run drives it with a recording probe.
SUPPORTS_HOSTED_TOOLS_ATTR = "supports_hosted_tools"

#: The plugin method the hosted-tool conformance check calls:
#: ``async def conformance_hosted_tool_call(self, probe)``. It makes ONE
#: governed model call of ``probe.request`` through the plugin's own
#: wiring, with ``probe.wrap(handle)`` as the run handle its gate uses,
#: ``probe.registered_mcp_servers`` as the gate's registry, and
#: ``probe.model_client.call(request)`` in place of the provider client.
HOSTED_TOOL_CONFORMANCE_HOOK = "conformance_hosted_tool_call"

#: A plugin class attribute naming the provider hint the plugin passes to
#: the gate (one of ``HOSTED_TOOL_PROVIDERS``), when it passes one. The
#: probe's recording model client reads the request with the same hint, so
#: the identities it records match the plugin's decisions.
HOSTED_TOOL_PROVIDER_ATTR = "hosted_tool_provider"
#: Optional classmethod a required plugin defines when its constructor
#: needs more than ``apdp_url``: it returns an instance to drive.
HOSTED_TOOL_CONFORMANCE_FACTORY = "conformance_hosted_tool_instance"

#: The MCP server the probe request carries, and the registry the hook must
#: pass to the gate (``probe.registered_mcp_servers``).
HOSTED_TOOL_PROBE_MCP_URL = "https://mcp.probe.example/mcp"
HOSTED_TOOL_PROBE_REGISTRY: Dict[str, str] = {HOSTED_TOOL_PROBE_MCP_URL: "probe-mcp"}

#: The request the probe hands a plugin: two hosted tools and a function in
#: ``tools``, plus two request-level hosted tools (``web_search_options``
#: and an ``mcp_servers`` entry), so a plugin that gates only
#: ``request["tools"]`` fails.
HOSTED_TOOL_PROBE_REQUEST: Dict[str, Any] = {
    "tools": [
        {"type": "web_search"},
        {"type": "code_interpreter", "container": {"type": "auto"}},
        {"type": "function", "name": "lookup", "parameters": {"type": "object"}},
    ],
    "web_search_options": {},
    "mcp_servers": [{"type": "url", "url": HOSTED_TOOL_PROBE_MCP_URL, "name": "probe"}],
}

#: Plugins whose framework can put provider-hosted tools on a model call.
#: Each must declare ``supports_hosted_tools = True`` and define the hook;
#: a listed plugin that does not is a conformance FAILURE, not a SKIP.
HOSTED_TOOL_PLUGINS_REQUIRED: Tuple[str, ...] = (
    "watchlight-adk",
    "watchlight-bedrock",
    "watchlight-deepagents",
    "watchlight-langgraph",
    "watchlight-pydantic-ai",
    "watchlight-strands",
)

#: Required plugins whose wiring has not landed yet: they are reported as
#: PENDING instead of failing, so the core can ship first. This set must be
#: empty before the next core release after
#: :data:`HOSTED_TOOL_PENDING_CORE_VERSION` (a core test enforces it), and
#: a plugin leaves it in the change that wires its hook.
HOSTED_TOOL_PLUGINS_PENDING: Tuple[str, ...] = (
    # One entry per line with a comment line between entries: each plugin
    # PR removes only its own line, and git merges deletions that an
    # unchanged line separates (adjacent deletions conflict).
    # -
    "watchlight-deepagents",
    # -
    "watchlight-pydantic-ai",
    # -
)

#: The last core version that may ship with a non-empty pending set.
HOSTED_TOOL_PENDING_CORE_VERSION = "0.10.2"


def _distribution_name(module_name: Optional[str]) -> Optional[str]:
    if not module_name:
        return None
    return module_name.split(".")[0].replace("_", "-")


class RecordingModelClient:
    """A stand-in model client: records each call as a ``model_call`` step
    with the hosted tools the request enables, and returns an empty
    response. It never contacts a provider. It reads the request with the
    plugin's provider hint and registry, as the plugin's gate does."""

    def __init__(
        self,
        steps: List[Dict[str, Any]],
        *,
        provider: Optional[str] = None,
        registered_mcp_servers: Optional[Dict[str, str]] = None,
    ) -> None:
        self._steps = steps
        self._provider = provider
        self._registered = registered_mcp_servers
        self.calls = 0

    async def call(self, request: Any) -> Dict[str, Any]:
        from watchlight_core.hosted_tools import hosted_tool_identity, normalize_hosted_request

        self.calls += 1
        tools = []
        for tool in normalize_hosted_request(request, self._provider):
            provider, kind, server = hosted_tool_identity(tool, self._registered)
            tools.append({"provider": provider, "kind": kind, "server": server})
        self._steps.append({"step": "model_call", "hosted_tools": tools})
        return {"output": []}


class _RecordingHandle:
    """Wraps a run handle: a hosted-tool ``/authorize`` request (its context
    carries ``hosted_tool``) gets the probe's decision and is recorded;
    every other call goes to the wrapped handle."""

    def __init__(self, inner: Any, probe: "HostedToolConformanceProbe") -> None:
        self._inner = inner
        self._probe = probe

    async def authorize_action_detailed(
        self,
        action: str,
        resource: str,
        *args: Any,
        context: Optional[Dict[str, Any]] = None,
        **kw: Any,
    ) -> Any:
        if isinstance(context, dict) and "hosted_tool" in context:
            from watchlight_core.results import AuthorizeResult

            self._probe.steps.append(
                {"step": "authorize", "context": dict(context), "decision": self._probe.decision}
            )
            if self._probe.decision == "Allow":
                return AuthorizeResult("allow")
            return AuthorizeResult("deny", reason="conformance_probe_deny")
        return await self._inner.authorize_action_detailed(
            action, resource, *args, context=context, **kw
        )

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)


class HostedToolConformanceProbe:
    """What the hosted-tool conformance check hands a plugin's
    :data:`HOSTED_TOOL_CONFORMANCE_HOOK`: the ``request`` to send, a
    ``model_client`` stand-in to send it with, :meth:`wrap` for the run
    handle the plugin's gate uses, and the ``registered_mcp_servers`` and
    ``provider`` the plugin's gate must use. ``decision`` (``Allow`` or
    ``Deny``) is what every hosted-tool decision returns in this probe."""

    def __init__(
        self,
        decision: str,
        *,
        request: Optional[Dict[str, Any]] = None,
        provider: Optional[str] = None,
    ) -> None:
        self.decision = decision
        self.request = (
            request if request is not None else copy.deepcopy(HOSTED_TOOL_PROBE_REQUEST)
        )
        self.provider = provider
        self.registered_mcp_servers = dict(HOSTED_TOOL_PROBE_REGISTRY)
        self.steps: List[Dict[str, Any]] = []
        self.model_client = RecordingModelClient(
            self.steps, provider=provider, registered_mcp_servers=self.registered_mcp_servers
        )

    def wrap(self, handle: Any) -> Any:
        return _RecordingHandle(handle, self)


#: What :func:`check_hosted_tool_gate_wired` returns for a required plugin
#: whose wiring is still pending.
HOSTED_TOOL_PENDING = "pending"


async def check_hosted_tool_gate_wired(
    plugin: Any, module_name: Optional[str] = None
) -> Optional[str]:
    """Invariant #19 against a live plugin.

    Returns ``"ok"`` when it passes, ``None`` when the plugin does not
    declare :data:`SUPPORTS_HOSTED_TOOLS_ATTR` and is not required (the
    caller reports a SKIP), and :data:`HOSTED_TOOL_PENDING` when it is a
    required plugin still in :data:`HOSTED_TOOL_PLUGINS_PENDING`. Raises
    :class:`ConformanceFailure` otherwise, including for a plugin in
    :data:`HOSTED_TOOL_PLUGINS_REQUIRED` (by ``module_name``) that does not
    declare support.

    The hook runs twice: with every hosted tool allowed it must make the
    model call, and the trace must satisfy
    :func:`check_hosted_tools_authorized_before_model_call`; with every
    hosted tool denied it must not make the model call.
    """
    dist = _distribution_name(module_name)
    if getattr(plugin, SUPPORTS_HOSTED_TOOLS_ATTR, False) is not True:
        if dist in HOSTED_TOOL_PLUGINS_PENDING:
            return HOSTED_TOOL_PENDING
        if dist in HOSTED_TOOL_PLUGINS_REQUIRED:
            raise ConformanceFailure(
                HOSTED_TOOLS_AUTHORIZED_INVARIANT_NUMBER,
                f"{dist} can put provider-hosted tools on a model call and must declare "
                f"`{SUPPORTS_HOSTED_TOOLS_ATTR} = True`",
            )
        return None
    hook = getattr(plugin, HOSTED_TOOL_CONFORMANCE_HOOK, None)
    if not callable(hook):
        raise ConformanceFailure(
            HOSTED_TOOLS_AUTHORIZED_INVARIANT_NUMBER,
            f"plugin declares `{SUPPORTS_HOSTED_TOOLS_ATTR} = True` but defines no "
            f"`{HOSTED_TOOL_CONFORMANCE_HOOK}(probe)` hook",
        )
    provider = getattr(plugin, HOSTED_TOOL_PROVIDER_ATTR, None)
    allow = HostedToolConformanceProbe("Allow", provider=provider)
    try:
        await hook(allow)
    except ConformanceFailure:
        raise
    except Exception as exc:  # noqa: BLE001 - any raise on the allow path fails the invariant
        raise ConformanceFailure(
            HOSTED_TOOLS_AUTHORIZED_INVARIANT_NUMBER,
            f"with every hosted tool allowed, the hook raised {type(exc).__name__}: {exc}",
        ) from exc
    if allow.model_client.calls == 0:
        raise ConformanceFailure(
            HOSTED_TOOLS_AUTHORIZED_INVARIANT_NUMBER,
            "with every hosted tool allowed, the plugin made no model call",
        )
    check_hosted_tools_authorized_before_model_call(allow.steps)
    deny = HostedToolConformanceProbe("Deny", provider=provider)
    try:
        await hook(deny)
    except ConformanceFailure:
        # A violation the probe found inside the hook fails the run; only
        # the plugin's own refusal error is expected here.
        raise
    except Exception:  # noqa: BLE001 - a refusal may surface as the plugin's own error
        pass
    if deny.model_client.calls != 0:
        raise ConformanceFailure(
            HOSTED_TOOLS_AUTHORIZED_INVARIANT_NUMBER,
            "with every hosted tool denied, the plugin still made the model call",
        )
    return "ok"


# ─── Invariant 13 (scope attenuation propagation) ─────────────────────


#: Invariant #13 — exported number/name for SDK consumers + tests.
#: Mirrors the TS lane's ``SCOPE_ATTENUATION_PROPAGATION_INVARIANT_NUMBER``
#: + ``SCOPE_ATTENUATION_PROPAGATION_INVARIANT_NAME`` exports in
#: the TypeScript SDK's conformance module. Plugin authors
#: writing their own conformance wrappers reference these so the
#: invariant number + name stay stable across SDK releases.
SCOPE_ATTENUATION_PROPAGATION_INVARIANT_NUMBER = 13
SCOPE_ATTENUATION_PROPAGATION_INVARIANT_NAME = "scope_attenuation_propagation"


def check_scope_attenuation_propagation(
    events: List[Dict[str, Any]],
) -> None:
    """Invariant #13 — IF-PRESENT: any ``agent_spawn_observed`` event
    that appears in the stream MUST carry a populated
    ``delegation_scope`` payload field.

    Python lane mirror of the TypeScript conformance invariant #13
    (see the TypeScript SDK's conformance module).
    Codifies the sub-agent scope-attenuation contract — *audited at
    every depth* — in the cross-plugin conformance suite. See the
    Watchlight documentation for the design contract.

    As of v0.9.12 spawn attestation is SERVER-emitted only —
    wl-apdp's ``spawn_handler`` mints the authoritative
    ``agent_spawn_observed`` (carrying the server-validated
    ``granted_scope``) while it processes ``POST /v1/spawn_subagent``,
    and the class is BLOCKED at ``/v1/events`` ingest. Plugins no longer
    emit it, so every plugin's stream passes this invariant VACUOUSLY.
    The code is intentionally UNCHANGED: it stays as a consumer-side
    lock so that if a stream ever DID carry an ``agent_spawn_observed``
    event, its ``delegation_scope`` would still be required present +
    non-empty. The guarantee is preserved server-side, not weakened.

    The check is structural: ``delegation_scope`` MUST be a non-empty
    dict. The wire schema (the wl-lineage event schema) accepts the
    field as ``Option<serde_json::Value>`` on the legacy
    ``delegation_scope`` channel and ``Option<GrantedScope>`` on the
    renamed ``granted_scope`` channel, both intentionally loose
    so historical audit rows replay cleanly. This conformance check
    tightens the per-call expectation: present + non-empty.

    Vacuous pass when no ``agent_spawn_observed`` events appear in
    the stream — which, today, is EVERY plugin (spawn attestation
    is server-emitted, never plugin-emitted). The dashboard lineage
    overlay still renders the parent's granted scope on each
    spawn edge, sourced from the server-attested event wl-apdp emits.

    The empty-object case (``delegation_scope == {}``) is also
    rejected — an empty scope is the fail-closed default, and
    emitting it as a literal ``{}`` is
    indistinguishable from "scope omitted" for the dashboard overlay.
    Stamping the canonical empty-shape (every key explicitly set with
    empty list / zero values) is the correct on-wire signal.

    Args:
        events: The list of canonical events captured during the
            synthetic lifecycle.

    Raises:
        ConformanceFailure: when any ``agent_spawn_observed`` event in
            the stream has a missing / null / non-dict / empty
            ``delegation_scope`` payload field.
    """
    for i, event in enumerate(events):
        if event.get("event_type") != "agent_spawn_observed":
            continue
        payload = event.get("payload")
        if payload is None or not isinstance(payload, dict):
            raise ConformanceFailure(
                SCOPE_ATTENUATION_PROPAGATION_INVARIANT_NUMBER,
                f"event[{i}] (agent_spawn_observed) has no payload — "
                f"cannot carry delegation_scope. The scope-attenuation "
                f"contract requires every spawn to carry the parent's "
                f"granted scope.",
            )
        # ``key in dict`` distinguishes "key explicitly None" (a wire
        # shape violation — the emitter chose to stamp null) from "key
        # missing" (also a violation but a different bug shape). Both
        # collapse to the same failure here; the message names them
        # apart so operators reading the report can trace the bug.
        if "delegation_scope" not in payload:
            raise ConformanceFailure(
                SCOPE_ATTENUATION_PROPAGATION_INVARIANT_NUMBER,
                f"event[{i}] (agent_spawn_observed) is missing the "
                f"delegation_scope payload key. The scope-attenuation "
                f"contract requires every spawn to carry the parent's "
                f"granted scope so audit replay can reason about "
                f"effective authority at every depth.",
            )
        scope = payload["delegation_scope"]
        if scope is None:
            raise ConformanceFailure(
                SCOPE_ATTENUATION_PROPAGATION_INVARIANT_NUMBER,
                f"event[{i}] (agent_spawn_observed) has "
                f"delegation_scope=null. The scope-attenuation "
                f"contract requires every spawn to carry the parent's "
                f"granted scope; null is the legacy unattested-scope "
                f"shape and is no longer acceptable. Stamp the canonical "
                f"empty-shape ({{'allowed_tools': [], "
                f"'allowed_resources': [], 'allowed_intents': [], "
                f"'max_depth': 0, 'time_budget_seconds': 0}}) if the "
                f"parent genuinely granted zero privileges.",
            )
        if not isinstance(scope, dict):
            raise ConformanceFailure(
                SCOPE_ATTENUATION_PROPAGATION_INVARIANT_NUMBER,
                f"event[{i}] (agent_spawn_observed) delegation_scope "
                f"is not a dict (got {type(scope).__name__}). The "
                f"canonical wire shape mirrors GrantedScope — a JSON "
                f"object with allowed_tools, allowed_resources, "
                f"allowed_intents, max_depth, time_budget_seconds.",
            )
        if not scope:
            raise ConformanceFailure(
                SCOPE_ATTENUATION_PROPAGATION_INVARIANT_NUMBER,
                f"event[{i}] (agent_spawn_observed) delegation_scope "
                f"is the empty dict {{}}. An empty scope is the "
                f"fail-closed default but the "
                f"conformance suite expects the plugin's runtime to "
                f"stamp the server-attested scope APDP minted. If the "
                f"parent genuinely granted zero privileges, stamp the "
                f"canonical empty-shape ({{'allowed_tools': [], "
                f"'allowed_resources': [], 'allowed_intents': [], "
                f"'max_depth': 0, 'time_budget_seconds': 0}}) so the "
                f"dashboard overlay can distinguish 'empty grant' "
                f"from 'scope omitted'.",
            )


# ─── Invariant 14 (execution_started precedes non-lifecycle events) ───


#: Invariant #14 — exported number/name for SDK consumers + tests.
#: Mirrors the TS lane's
#: ``EXECUTION_STARTED_PRECEDES_NON_LIFECYCLE_EVENTS_INVARIANT_NUMBER`` +
#: ``EXECUTION_STARTED_PRECEDES_NON_LIFECYCLE_EVENTS_INVARIANT_NAME``
#: exports in the TypeScript SDK's conformance module.
EXECUTION_STARTED_PRECEDES_NON_LIFECYCLE_EVENTS_INVARIANT_NUMBER = 14
EXECUTION_STARTED_PRECEDES_NON_LIFECYCLE_EVENTS_INVARIANT_NAME = (
    "execution_started_precedes_non_lifecycle_events"
)


#: Closed-set mint event types. A mint event is allowed to appear in a
#: captured stream WITHOUT a preceding ``execution_started`` for the
#: same ``execution_id`` because it IS the root of that execution_id's
#: subtree:
#:
#:   - ``execution_started`` — the canonical mint, by definition.
#:   - ``agent_spawn_observed`` — minted by the parent on behalf of the
#:     spawned child; the parent emits this BEFORE the child's own
#:     ``execution_started`` lands, so a stream-window snapshot can
#:     legitimately contain a spawn-only edge for a child execution_id.
#:     (Sub-agent lineage continuity — invariant #9 — covers the
#:     follow-on contract for the child's emitted events; invariant
#:     #14 only requires that any NON-mint event the child later emits
#:     has a started anchor by the time the stream is asserted on.)
#:   - ``ungoverned_request_observed`` — the ungoverned-request
#:     anomaly self-rooted shape. It lives on its own
#:     synthetic execution_id and is exempt from the started-precedes
#:     rule by construction; the event is the root.
#:
#: Closed-set by safe default (security-first): any
#: event type NOT in this set is treated as non-lifecycle and requires
#: a preceding ``execution_started``. Custom plugin event types — if
#: one ever lands — fall into the non-mint bucket so a new event type
#: cannot silently bypass the contract. The Cedar/lineage contract
#: explicitly limits future additions: a new mint requires adding the
#: name here AND extending the Rust ``EventType`` enum + the lineage
#: projection sql triggers in lock-step.
EXECUTION_STARTED_PRECEDES_MINT_EVENTS: frozenset[str] = frozenset(
    {
        "execution_started",
        "agent_spawn_observed",
        "ungoverned_request_observed",
    }
)


def check_execution_started_precedes_non_lifecycle_events(
    events: List[Dict[str, Any]],
) -> None:
    """Invariant #14 — every non-mint event in the captured stream MUST
    have a preceding ``execution_started`` event with the same
    ``execution_id``.

    The lineage projection's recursive CTE
    (``wl-execution-graph::projection``) cannot stitch a non-mint event
    into a tree node when no row exists in ``lineage.executions`` for
    its ``execution_id``. The dashboard ``/lineage`` view then renders
    the event as an orphan (or drops it). The SDK's ``BaseRunHandle``
    defensively emits ``execution_started`` before the first
    ``publish_observation`` / ``authorize_action_detailed`` round-trip;
    this invariant locks in the contract from the consumer side so
    future plugins / translators that bypass the SDK lifecycle (or a
    customer-direct emitter that forgets the mint) fail CI loudly.

    The check is per-execution_id, by-timestamp:

      1. Group events by ``execution_id``.
      2. Sort each group's events by ``timestamp`` (ISO 8601 sorts
         lexicographically). Out-of-order delivery is handled —
         invariant operates on the wire-form timestamp, not the
         iteration order.
      3. Walk each group; the first event MUST be a mint event
         (``execution_started`` / ``agent_spawn_observed`` /
         ``ungoverned_request_observed``) unless the group contains
         only mint events (handled implicitly — every event is mint).
      4. Once a mint event is seen in the group, the group is
         "rooted"; every subsequent non-mint event in the group passes.
      5. If a non-mint event appears BEFORE any mint event in the
         group's timestamp-sorted order, the invariant fails.

    Edge cases the check handles by construction:

      - **Empty stream**: zero violations; passes vacuously.
      - **Single mint event**: passes (no non-mint follow-ons to
        require an anchor).
      - **Duplicate ``execution_started`` for the same
        ``execution_id``**: counts as "seen mint" for invariant #14;
        deduplication is a separate concern (covered by the lineage
        projection's idempotency layer).
      - **Multiple executions in one stream**: each ``execution_id``
        verified independently. A root execution and a spawned child
        each get their own anchor check.
      - **Cross-execution references** (an event with
        ``parent_execution_id`` set): irrelevant to invariant #14 — the
        anchor check is on the event's OWN ``execution_id``.
      - **Timestamp ties**: equal timestamps are treated as concurrent;
        a tied mint + non-mint pair passes (the mint counts as
        "seen" for the tie). The invariant focuses on PRESENCE of a
        mint, not strict-before ordering.
      - **Unknown event types**: closed-set ``MINT_EVENTS`` default —
        anything not in the mint set is treated as non-mint and
        requires a started. This is the safe default (security-first).
      - **Missing ``execution_id``**: skipped (the envelope-shape
        invariant #1 catches this separately; not invariant #14's
        concern).
      - **Missing ``timestamp``**: events with no timestamp sort to
        the start of their group; the check still functions but a
        missing timestamp is also an invariant #1 violation that
        surfaces independently.

    Args:
        events: The list of canonical events captured during the
            synthetic lifecycle (or any wire-form capture).

    Raises:
        ConformanceFailure: when ANY ``execution_id`` group has a
            non-mint event preceding the first mint event in
            timestamp order. The exception carries the list of
            offending executions in its details payload via the
            second arg's string description.
    """
    # Group by execution_id; skip events with no execution_id (those
    # are invariant #1 violations surfaced separately).
    by_exec_id: Dict[str, List[Dict[str, Any]]] = collections.defaultdict(list)
    for ev in events:
        exec_id = ev.get("execution_id")
        if isinstance(exec_id, str) and exec_id:
            by_exec_id[exec_id].append(ev)

    violations: List[Dict[str, Any]] = []
    for exec_id, group in by_exec_id.items():
        # Sort by timestamp (ISO 8601 lex-sortable). Missing
        # timestamps sort first via the empty-string fallback — they
        # are an invariant #1 violation already; surfacing them here
        # too would double-count.
        group_sorted = sorted(
            group,
            key=lambda e: e.get("timestamp") or "",
        )
        seen_mint = False
        for ev in group_sorted:
            event_type = ev.get("event_type")
            if event_type in EXECUTION_STARTED_PRECEDES_MINT_EVENTS:
                seen_mint = True
                continue
            if not seen_mint:
                violations.append(
                    {
                        "execution_id": exec_id,
                        "first_orphan_event_id": ev.get("event_id"),
                        "first_orphan_event_type": event_type,
                        "first_orphan_timestamp": ev.get("timestamp"),
                    }
                )
                # One violation per execution_id — once we know the
                # group is orphaned the rest of the walk is
                # uninformative. Operators reading the report get the
                # first offending event; they fix the emitter and
                # rerun.
                break

    if violations:
        details = "; ".join(
            f"execution_id={v['execution_id']!r} first orphan="
            f"{v['first_orphan_event_type']!r} "
            f"(event_id={v['first_orphan_event_id']!r}, "
            f"timestamp={v['first_orphan_timestamp']!r})"
            for v in violations
        )
        raise ConformanceFailure(
            EXECUTION_STARTED_PRECEDES_NON_LIFECYCLE_EVENTS_INVARIANT_NUMBER,
            f"{len(violations)} execution(s) emitted non-mint event(s) "
            f"without a preceding execution_started in the captured "
            f"stream. The lineage projection cannot stitch these "
            f"events into a tree without an anchor row in "
            f"lineage.executions — the dashboard /lineage view would "
            f"render them as orphans or drop them. Closed-set mint "
            f"events: "
            f"{sorted(EXECUTION_STARTED_PRECEDES_MINT_EVENTS)!r}. "
            f"Violations: {details}.",
        )


# ─── Invariant 15 — single correlated execution_id ────────────────────


#: Invariant #15 — exported number/name for SDK consumers + tests.
#: The execution-id correlation contract (core product differentiator):
#: ONE canonical execution_id per run, propagated across every emitter.
#: See the Watchlight documentation.
SINGLE_CORRELATED_EXECUTION_ID_INVARIANT_NUMBER = 15
SINGLE_CORRELATED_EXECUTION_ID_INVARIANT_NAME = "single_correlated_execution_id"


def check_single_correlated_execution_id(
    events: List[Dict[str, Any]],
) -> None:
    """Invariant #15 — ONE canonical execution_id per run across every
    emitter (the execution-id correlation contract).

    This is the through-line of the "orphaned orchestrator execution"
    fix: a single logical run must reassemble into ONE lineage tree with
    a single root. wl-execution-graph upserts one ``lineage.executions``
    row per distinct ``execution_id``, so two divergent root ids for the
    same run render as two roots — one of them an orphan carrying only
    the orchestrator node, the other the real tree. See the
    Watchlight documentation.

    The check operates on a captured stream for a SINGLE run:

      1. A ROOT ``execution_started`` is one with no
         ``parent_execution_id``. Every emitter that legitimately roots
         the run (SDK ``__aenter__`` defensive mint, the framework
         callback's ``on_chain_start``, and wl-proxy's gateway emit when
         it reuses the propagated id) emits ``execution_started`` for the
         SAME id — so the set of distinct root ids MUST have size ≤ 1.
         Two or more distinct root ids = a divergent-root violation.

      2. A SUB-AGENT ``execution_started`` is one WITH a
         ``parent_execution_id``. It is its own execution (distinct id),
         but it MUST carry ``root_execution_id`` equal to the single
         root so the spawn tree groups under one root. A sub-agent whose
         ``root_execution_id`` is missing or points elsewhere is a
         broken-linkage violation.

    Vacuous pass when the stream contains no ``execution_started``
    events (a translator-only capture with no lifecycle mint).

    Note on scope: this guards the in-process SDK/plugin emit stream.
    The cross-service boundary (wl-proxy reusing vs. minting an
    ``execution_id``) is guarded by wl-proxy's own
    ``should_emit_execution_started`` unit test — the two lanes together
    enforce the full contract.

    Args:
        events: canonical events captured during ONE run's lifecycle.

    Raises:
        ConformanceFailure: on divergent roots or broken sub-agent root
            linkage. The message names the offending ids so the emitter
            can be fixed.
    """
    started = [
        e for e in events if e.get("event_type") == "execution_started"
    ]

    root_ids: set[str] = set()
    subagent_violations: List[Dict[str, Any]] = []
    for ev in started:
        exec_id = ev.get("execution_id")
        if not isinstance(exec_id, str) or not exec_id:
            # Missing execution_id is an invariant #1 violation surfaced
            # separately; don't double-count here.
            continue
        parent = ev.get("parent_execution_id")
        if not parent:
            # ROOT execution_started — no parent. Collect its id; all
            # roots for one run must agree.
            root_ids.add(exec_id)
        else:
            # SUB-AGENT execution_started — must point back at the run's
            # single root via root_execution_id. We validate the linkage
            # against the resolved root below (once we know it).
            subagent_violations.append(
                {
                    "execution_id": exec_id,
                    "parent_execution_id": parent,
                    "root_execution_id": ev.get("root_execution_id"),
                    "event_id": ev.get("event_id"),
                    "source": (ev.get("metadata") or {}).get("source"),
                }
            )

    # (1) Divergent-root check — the load-bearing invariant.
    if len(root_ids) > 1:
        raise ConformanceFailure(
            SINGLE_CORRELATED_EXECUTION_ID_INVARIANT_NUMBER,
            f"{len(root_ids)} divergent ROOT execution ids in one run's "
            f"event stream: {sorted(root_ids)!r}. Exactly one root "
            f"execution_started (the orchestrator handle's own "
            f"execution_id) is permitted — a second root is the "
            f"'orphaned orchestrator execution' bug (two "
            f"lineage.executions rows, one orphan). Every emitter (SDK "
            f"defensive mint, framework callback, wl-proxy) must reuse "
            f"the handle's execution_id; none may mint a fresh id for a "
            f"run that already has a root.",
        )

    # (2) Sub-agent root-linkage check — only meaningful once a single
    # root is established. When the capture has no root (translator-only
    # fixtures), we cannot assert the linkage target; skip it.
    if len(root_ids) == 1:
        root_id = next(iter(root_ids))
        broken = [
            v
            for v in subagent_violations
            if v["root_execution_id"] != root_id
        ]
        if broken:
            details = "; ".join(
                f"sub-agent execution_id={v['execution_id']!r} "
                f"(source={v['source']!r}) carries root_execution_id="
                f"{v['root_execution_id']!r}, expected {root_id!r}"
                for v in broken
            )
            raise ConformanceFailure(
                SINGLE_CORRELATED_EXECUTION_ID_INVARIANT_NUMBER,
                f"{len(broken)} sub-agent execution_started event(s) "
                f"carry a root_execution_id that does not point at the "
                f"run's single root {root_id!r} — the spawn tree would "
                f"not group under one root on /lineage. Propagate the "
                f"orchestrator's root_execution_id down every spawn. "
                f"Violations: {details}.",
            )


# ─── Synthetic lifecycle runner ───────────────────────────────────────


async def _run_synthetic_lifecycle(
    plugin: Any,
    framework_tag: str,
) -> Tuple[List[Dict[str, Any]], "MockApdpClient", str, str]:
    """Drive a synthetic plan → authorize → tool-call → complete
    lifecycle through the plugin. Captures every event the plugin
    emits via its ApdpClient and returns them.

    Conformance is exercised through this lifecycle because it's
    the same shape every real plugin invocation follows. A plugin
    that passes here passes a real APDP run.

    Returns a tuple of ``(events, mock_client, root_agent_uuid,
    subagent_uuid)`` so invariant 8 (sub-agent authz attribution)
    can assert which principal each authorize() call was made
    under.
    """
    # Inject a mock APDP client so the lifecycle doesn't touch a
    # real server. The lifecycle drives the allow path, so it says so:
    # the double denies by default.
    mock = MockApdpClient(default_decision="Allow")
    # Use canonical UUIDs so the plugins that override
    # ``spawn_subagent`` (LangGraph, Pydantic AI) can pass
    # through the strict-UUID validation in
    # :meth:`BaseRunHandle._perform_spawn_apdp_roundtrip`. The previous
    # ``f"uuid-root-{...}"`` slug-style ids were rejected by ``UUID()``,
    # which silently bailed the spawn step and let invariant #13 pass
    # vacuously on plugins that DO emit ``agent_spawn_observed``. With
    # real UUIDs the spawn succeeds end-to-end, the audit event lands,
    # and invariant #13 exercises the load-bearing assertion path.
    root_uuid = str(uuid.uuid4())
    subagent_uuid = str(uuid.uuid4())
    mock.known_agents["test-agent"] = root_uuid
    mock.known_agents["test-subagent"] = subagent_uuid
    plugin.apdp = mock

    captured: List[Dict[str, Any]] = []

    try:
        async with capture_events(mock) as events:
            # Step 1: start_run (root)
            handle = await plugin.start_run("test-agent")
            # Flip the contract-guard flag synthetically.
            # The conformance harness drives the handle without the
            # customer's ``async with`` block because it composes
            # multiple invariants and needs full control over the
            # lifecycle. In production customer code, the
            # ``async with`` block is mandatory; the fail-closed guard
            # in :meth:`BaseRunHandle.authorize_action_detailed` /
            # :meth:`BaseRunHandle.publish_observation` enforces it.
            handle._aentered = True

            # Step 2: optional plan submission
            try:
                await handle.submit_plan(["op_one", "op_two"])
            except Exception:  # noqa: BLE001 — plan submission is optional
                pass

            # Step 3: authorize one synthetic action on the ROOT handle.
            # The double allows it, so a raise is the plugin failing to
            # authorize; it fails the run. Swallowing it would leave no
            # tool event and let the invariants over that event pass
            # vacuously.
            try:
                await handle.authorize_action("execute", "test_tool")
            except Exception as exc:
                raise ConformanceFailure(
                    4,
                    "authorize_action on the root handle raised "
                    f"{type(exc).__name__}: {exc}. The harness allows this "
                    "call, so the plugin must authorize it.",
                ) from exc

            # Step 4: open a sub-agent handle and authorize against
            # the SUB-AGENT's principal. Locks in the sub-agent
            # governance invariant. Every plugin that exposes
            # start_run can do this; plugins
            # whose framework has an auto-detect hook surface (e.g.
            # the TS Claude Agent plugin) must additionally honor the
            # invariant at the hook layer, which their own unit tests
            # exercise.
            #
            # Opening the sub-agent is optional: invariant 8 passes
            # vacuously when the plugin's spawn or start_run path
            # rejects the sub-agent slug. Authorizing on a sub-agent
            # handle that DID open is not optional. A raise there is
            # the plugin failing the sub-agent governance invariant, so
            # it surfaces as a conformance failure instead of being
            # swallowed (fail closed).
            subhandle: Any = None
            try:
                if hasattr(handle, "spawn_subagent"):
                    # LangGraph reference path — use the explicit
                    # primitive so the spawn event lands in the audit
                    # trail alongside the per-handle authz.
                    #
                    # The canonical scope kwargs are
                    # passed so the LangGraph + Pydantic AI overrides'
                    # ``_build_audit_scope_payload`` emits a populated
                    # ``delegation_scope`` on the ``agent_spawn_observed``
                    # audit event. Invariant #13 reads this field; if
                    # we passed no scope kwargs, the audit shape would
                    # be ``delegation_scope = None`` and the invariant
                    # would fail — that would be a false positive on
                    # the conformance synthetic lifecycle, not on the
                    # plugin. Real customer code declares scope at
                    # every spawn (the demo workloads do this); the
                    # synthetic lifecycle now mirrors that contract.
                    #
                    # ``parent_execution_id`` is derived from the
                    # handle's own ``execution_id`` when present
                    # (Pydantic AI sets this in ``__init__``; the
                    # LangGraph handle does not — for LangGraph we
                    # mint a fresh one). This keeps invariant 9's
                    # lineage-continuity check happy across both
                    # plugins: the spawn event's ``execution_id``
                    # matches the parent's own ``execution_id``, and
                    # the child's events inherit the same root.
                    parent_exec = getattr(
                        handle, "execution_id", None
                    ) or f"exec_{uuid.uuid4()}"
                    subhandle = await handle.spawn_subagent(
                        "test-subagent",
                        child_intent=ChildIntent(
                            category="conformance",
                            objective="Conformance sub-agent probe",
                        ),
                        parent_execution_id=parent_exec,
                        allowed_tools=["test_subagent_tool"],
                        allowed_intents=["conformance"],
                        max_depth=0,
                        time_budget_seconds=60,
                    )
                else:
                    # Generic path — open a second governed run for
                    # the sub-agent. The plugin's contract is that
                    # each handle authorizes against its own agent
                    # principal.
                    subhandle = await plugin.start_run("test-subagent")
            except Exception:  # noqa: BLE001 — opening the sub-agent is
                # optional from the plugin's point of view; invariant
                # 8 passes vacuously if the plugin's spawn or
                # start_run path rejects the sub-agent slug.
                subhandle = None

            if subhandle is not None:
                # Synthetic test handle bypasses the production
                # ``async with`` entry path. ``spawn_subagent`` already
                # sets ``_aentered=True`` on the child; this redundant
                # assignment covers the ``plugin.start_run`` generic
                # branch where the plugin's own ``start_run`` would not
                # enter the handle.
                subhandle._aentered = True
                try:
                    await subhandle.authorize_action(
                        "execute", "test_subagent_tool"
                    )
                except Exception as exc:
                    raise ConformanceFailure(
                        8,
                        "authorize_action on the sub-agent handle raised "
                        f"{type(exc).__name__}: {exc}. A sub-agent handle "
                        "that opened must authorize under its own "
                        "principal; the harness does not treat this "
                        "failure as optional.",
                    ) from exc
                try:
                    await subhandle.complete()
                except Exception:  # noqa: BLE001
                    pass

            # Step 5: complete the root run
            try:
                await handle.complete()
            except Exception:  # noqa: BLE001
                pass

        captured = list(events)
    except AgentNotRegistered:
        # The plugin's start_run path SHOULD succeed against the
        # mock client. If it doesn't, that's its own conformance
        # bug; we surface it.
        raise ConformanceFailure(
            0,
            "plugin.start_run('test-agent') raised AgentNotRegistered "
            "against the mock client (the mock pre-registers 'test-agent'). "
            "This suggests the plugin's resolve_agent path is broken.",
        )

    return captured, mock, root_uuid, subagent_uuid


def _assert_subagent_authz_attribution(
    mock: "MockApdpClient",
    root_uuid: str,
    subagent_uuid: str,
) -> None:
    """Invariant 8 — every authorize() call to the SUB-AGENT's handle
    MUST carry the sub-agent's principal in Cedar form
    (``Agent::"<subagent_uuid>"``), never the root's.

    Skipped when the lifecycle never authorized against a sub-agent
    (e.g. the plugin's start_run path rejected the sub-agent slug or
    the plugin doesn't support a second concurrent handle). In that
    case the invariant passes vacuously — the sub-agent governance
    bug shape needs an actual sub-agent authz call to manifest.
    """
    # Did the plugin make any authz call attributed to the sub-agent?
    sub_principal_marker = subagent_uuid
    root_principal_marker = root_uuid

    sub_calls = [
        c for c in mock.authorize_calls if sub_principal_marker in c.get("principal", "")
    ]
    if not sub_calls:
        # No sub-agent authz happened — invariant 8 vacuously holds.
        # Plugins that have no second-handle path can still pass.
        return

    # If a sub-agent authz call DID happen, NO authz call may have
    # been made carrying the sub-agent's tool but the ROOT's
    # principal — that's the sub-agent privilege-escalation bug shape.
    for call in mock.authorize_calls:
        resource = call.get("resource", "")
        principal = call.get("principal", "")
        if "test_subagent_tool" in resource and root_principal_marker in principal:
            raise ConformanceFailure(
                8,
                f"authorize() for the sub-agent's tool was called with the "
                f"ROOT's principal {principal!r}. The sub-agent's tool calls "
                f"MUST be authorized against the sub-agent's own principal. "
                f"This is the sub-agent privilege-escalation bug.",
            )


def _assert_subagent_lineage_continuity(
    events: List[Dict[str, Any]],
) -> None:
    """Invariant 9 — sub-agent lineage continuity.

    When the synthetic lifecycle emits an ``agent_spawn_observed``
    event for a sub-agent S from parent P, every subsequent event
    emitted by S (``execution_started``, ``tool_call_observed``,
    ``execution_completed``, ``agent_spawn_observed`` when S itself
    becomes a spawner) MUST carry:

      - ``root_execution_id`` — the workflow root; the SAME value
        every event in the tree carries. When P is itself spawned,
        S inherits P's root. When P is the root, S's
        ``root_execution_id`` == P's ``execution_id``.
      - ``parent_execution_id`` — the direct spawner's
        ``execution_id``. At depth 1, this equals
        ``root_execution_id``. At depth 2+, it points at the
        intermediate sub-agent, NOT the root.

    Without this linkage, ``wl-execution-graph``'s recursive CTE
    cannot reconstruct the full delegation tree from one root row —
    the dashboard ``/lineage`` view renders the sub-agent as an
    orphan tree separate from the orchestrator.

    Passes vacuously when the lifecycle never emits
    ``agent_spawn_observed`` (the plugin's framework has no
    sub-agent primitive, or the synthetic lifecycle didn't spawn).
    The LangGraph plugin (``watchlight-langgraph``) is the reference
    implementation.
    """
    # Build a map of execution_id → event for fast parent lookup.
    by_exec: Dict[str, Dict[str, Any]] = {}
    for ev in events:
        exec_id = ev.get("execution_id")
        if isinstance(exec_id, str) and exec_id not in by_exec:
            by_exec[exec_id] = ev

    # Collect every spawn declaration: (parent_exec_id, child_exec_id).
    #
    # Spawn attestation is now SERVER-emitted only, so plugin
    # streams no longer carry ``agent_spawn_observed``. To keep this
    # invariant's coverage (rather than passing vacuously the moment the
    # spawn event moved server-side), we ALSO derive the (parent, child)
    # pair from the child's own ``execution_started`` — which the plugin
    # still emits, carrying ``parent_execution_id`` (the direct spawner)
    # and ``root_execution_id``. Both sources are unioned; the legacy
    # ``agent_spawn_observed`` path stays so a stream that somehow still
    # carries one (replay of historical audit rows) is checked too.
    spawn_set: set[Tuple[str, str]] = set()
    for ev in events:
        etype = ev.get("event_type")
        if etype == "agent_spawn_observed":
            payload = ev.get("payload") or {}
            parent_exec = ev.get("execution_id")
            child_exec = payload.get("child_execution_id")
            if isinstance(parent_exec, str) and isinstance(child_exec, str):
                spawn_set.add((parent_exec, child_exec))
        elif etype == "execution_started":
            # A child ``execution_started`` names its DIRECT spawner via
            # ``parent_execution_id``. The root's own started event has
            # ``parent_execution_id is None`` and is skipped.
            parent_exec = ev.get("parent_execution_id")
            child_exec = ev.get("execution_id")
            if isinstance(parent_exec, str) and isinstance(child_exec, str):
                spawn_set.add((parent_exec, child_exec))

    # Deterministic order (order-independence): sort the derived pairs.
    spawns: List[Tuple[str, str]] = sorted(spawn_set)

    if not spawns:
        # No spawns observed — invariant 9 holds vacuously.
        return

    # The expected root for each spawned child = the parent's root
    # if the parent is itself spawned, else the parent's execution_id.
    parent_of: Dict[str, str] = {child: parent for parent, child in spawns}
    children = set(parent_of.keys())

    def expected_root(exec_id: str) -> str:
        seen: set[str] = set()
        cur = exec_id
        # Walk up the parent chain. The root is the first ancestor
        # that is NOT itself a known spawned child.
        while cur in parent_of and cur not in seen:
            seen.add(cur)
            cur = parent_of[cur]
        return cur

    for child_exec in children:
        expected = expected_root(child_exec)
        # Every event emitted by this child must carry the linkage.
        # EXCEPTION: an ``agent_spawn_observed`` event emitted FROM
        # this execution declares a FURTHER spawn (child becoming a
        # spawner). Its own ``parent_execution_id`` is allowed to be
        # absent — the spawn event is an attribution boundary, not a
        # node in the tree. The LangGraph reference omits it
        # intentionally (`watchlight_langgraph/plugin.py` —
        # ``_emit_spawn_pair``). Its ``root_execution_id`` MUST still
        # be set so the graph builder back-fill walks the right tree.
        child_events = [e for e in events if e.get("execution_id") == child_exec]
        if not child_events:
            # No follow-up events for this spawned child. The spawn
            # declaration alone is fine — invariant only constrains
            # events the child emits.
            continue
        for ev in child_events:
            root = ev.get("root_execution_id")
            if root != expected:
                raise ConformanceFailure(
                    9,
                    f"event {ev.get('event_type')!r} from spawned "
                    f"execution {child_exec!r} carries "
                    f"root_execution_id={root!r}, expected {expected!r}. "
                    f"Sub-agent events MUST inherit the workflow root "
                    f"verbatim so wl-execution-graph stitches the tree.",
                )
            # Spawn-declaration events get a pass on parent_execution_id
            # — they're attribution events, not nodes in the tree.
            if ev.get("event_type") == "agent_spawn_observed":
                continue
            parent = ev.get("parent_execution_id")
            expected_parent = parent_of[child_exec]
            if parent != expected_parent:
                raise ConformanceFailure(
                    9,
                    f"event {ev.get('event_type')!r} from spawned "
                    f"execution {child_exec!r} carries "
                    f"parent_execution_id={parent!r}, expected "
                    f"{expected_parent!r} (the direct spawner). "
                    f"Sub-agent events MUST carry the DIRECT parent — "
                    f"depth-2 grandchildren attribute to the "
                    f"intermediate sub-agent, NOT the root.",
                )


# ─── Quarantine opt-out hatch (temporary) ────────────────────────────

#: Plugin-class attribute name used as an opt-out for invariant #11.
#: When a plugin class sets ``supports_m45_quarantine = False`` the
#: conformance runner SKIPS invariant #11 with a warning. The opt-out
#: exists so plugins whose framework runtime has not yet wired the
#: kill signal can stay green during the rollout — it is NOT a
#: long-term escape valve. Once every plugin wires the kill signal the
#: opt-out will be deleted from the runner and any plugin that still
#: sets the attribute will fail loudly.
SUPPORTS_M45_QUARANTINE_ATTR = "supports_m45_quarantine"

#: Human-readable tracking note surfaced in the runner's report
#: alongside the SKIPPED line for invariant #11. Names the in-flight
#: work so engineers reading the report can find it.
_KILL_SIGNAL_NOTE = (
    "plugin runtime Quarantine handling is not yet wired for this "
    "framework. Remove the opt-out and re-run conformance once the "
    "framework-specific kill-signal wiring lands."
)


# ─── Intent-extraction opt-out hatch (temporary) ─────────────────────

#: Plugin-class attribute name used as an opt-out for invariant #12.
#: When a plugin class sets ``supports_m46_intent_extraction = False``
#: the conformance runner SKIPS invariant #12 with a warning. The
#: opt-out exists so plugins whose framework runtime has not yet wired
#: intent extraction (ADK, MSAF, OpenClaw on the Python lane) can stay
#: green during the rollout — it is NOT a long-term escape valve.
#: Once every plugin wires intent extraction the opt-out will be
#: deleted from the runner and any plugin that still sets the
#: attribute will fail loudly.
SUPPORTS_M46_INTENT_EXTRACTION_ATTR = "supports_m46_intent_extraction"

#: Human-readable tracking note surfaced in the runner's report
#: alongside the SKIPPED line for invariant #12. Names the in-flight
#: work that ships intent extraction across the remaining plugins
#: (ADK, MSAF, OpenClaw — LangGraph, Bedrock, Claude Agent SDK, and
#: Pydantic AI are already covered).
_INTENT_EXTRACTION_NOTE = (
    "plugin-side intent extraction is not yet wired for ADK / MSAF / "
    "OpenClaw. Remove the opt-out and re-run conformance once the "
    "natural-signal extraction for the plugin's framework lands, or "
    "document the architectural gap that prevents extraction in the "
    "plugin's own documentation."
)


# ─── Invariant 12 (intent provenance consistency) ─────────────────────


def check_intent_provenance_consistency(
    events: List[Dict[str, Any]],
) -> None:
    """Invariant #12 — every plugin's ``execution_started`` event
    produces a consistent ``intent_objective`` + ``intent_provenance``
    pair.

    Locks the SDK contract for every plugin: a future plugin
    author whose ``start_run`` (or natural emission point) populates
    ``intent_objective`` without recording where it came from fails CI
    loudly. Mirrors the Python wire-shape validator at
    :class:`watchlight_core.events_schema.ExecutionStartedPayload`
    (``_validate_m46_intent_invariants``) so the conformance test
    catches the same bug shape that the wire schema would reject — the
    schema validator only fires when an emitter pushes the payload
    through pydantic; this conformance check fires on the raw dict.

    The consistency rule:

      - ``intent_objective`` populated ⇒ ``intent_provenance`` MUST be
        set AND MUST be one of ``declared`` / ``plugin_derived`` /
        ``proxy_inferred``.

      - ``intent_objective`` absent (``None`` or key missing) ⇒
        ``intent_provenance`` MUST be ``absent`` OR omitted entirely
        (the earlier silent posture, preserved verbatim).

      - Both fields populated with ``provenance == "absent"`` is
        INVALID — an unattributed objective silently downgrades
        enforcement.

      - ``intent_objective`` absent with ``provenance`` set to a
        non-``absent`` value is INVALID — provenance without an
        underlying objective is a contract violation (the emitter
        either had an objective and lost it, or is faking the
        provenance signal — both are bug shapes).

    Plugins whose framework can't surface a prompt signal can set
    ``supports_m46_intent_extraction = False`` on the plugin class to
    skip this invariant. The opt-out goes away once intent extraction
    lands across every plugin — see :data:`_INTENT_EXTRACTION_NOTE`.

    Vacuous when no ``execution_started`` events appear in the stream
    — plugins whose synthetic lifecycle doesn't drive the natural
    emission point (e.g. LangGraph's ``on_chain_start`` hook can't fire
    without a real graph invocation) pass cleanly. Real plugin runs
    DO emit ``execution_started`` and this check then exercises the
    full consistency rule. The shipped plugin-specific tests cover the
    "intent IS populated" path; this conformance check is the
    cross-plugin floor.

    Args:
        events: The list of canonical events captured during the
            synthetic lifecycle.

    Raises:
        ConformanceFailure: when any ``execution_started`` event in
            the stream violates the consistency rule.
    """
    # Local import to keep the module-level import graph lean — the
    # IntentProvenance enum is only needed inside the consistency
    # check, not at import time.
    from watchlight_core.events_schema import IntentProvenance

    # The wire form uses the snake-case enum values; the conformance
    # check matches against those strings (not the enum instance) so
    # plugins emitting raw dicts (the canonical wire shape) and plugins
    # emitting pydantic-validated payloads both fall through the same
    # gate.
    valid_populated_provenances = {
        IntentProvenance.DECLARED.value,
        IntentProvenance.PLUGIN_DERIVED.value,
        IntentProvenance.PROXY_INFERRED.value,
    }
    absent_marker = IntentProvenance.ABSENT.value

    for i, event in enumerate(events):
        if event.get("event_type") != "execution_started":
            continue
        payload = event.get("payload") or {}
        if not isinstance(payload, dict):
            continue

        # `key in dict` distinguishes "explicitly None" from "missing";
        # the consistency rule treats them as equivalent ("intent
        # absent") for the objective check, so we collapse to a single
        # boolean.
        objective = payload.get("intent_objective")
        provenance = payload.get("intent_provenance")
        objective_present = (
            objective is not None
            and isinstance(objective, str)
            and len(objective) > 0
        )

        if objective_present:
            # Rule A — populated objective requires a non-absent
            # provenance. ``None`` (missing key) is a violation here
            # because the emitter clearly produced an objective but
            # didn't record where it came from.
            if provenance is None:
                raise ConformanceFailure(
                    12,
                    f"event[{i}] (execution_started) has intent_objective "
                    f"set ({objective!r}) but intent_provenance is missing. "
                    f"The intent contract requires every populated objective "
                    f"to carry a provenance label (declared / plugin_derived / "
                    f"proxy_inferred). Emitting an objective without a "
                    f"provenance silently downgrades Cedar enforcement.",
                )
            if provenance == absent_marker:
                raise ConformanceFailure(
                    12,
                    f"event[{i}] (execution_started) has intent_objective "
                    f"set ({objective!r}) but intent_provenance=={absent_marker!r}. "
                    f"An attributed objective cannot have absent provenance — "
                    f"this is a known regression shape (objective populated "
                    f"in an error path that forgot to update provenance). "
                    f"Fix the emitter to stamp the matching provenance value.",
                )
            if provenance not in valid_populated_provenances:
                raise ConformanceFailure(
                    12,
                    f"event[{i}] (execution_started) has intent_provenance="
                    f"{provenance!r} which is not in the canonical set "
                    f"{sorted(valid_populated_provenances)!r}. "
                    f"The closed enum is defined by "
                    f"watchlight_core.events_schema.IntentProvenance.",
                )
        else:
            # Rule B — absent objective requires absent (or omitted)
            # provenance. Provenance-without-objective is a contract
            # violation: either the emitter had an objective and lost
            # it, or it's fabricating the provenance signal — both are
            # bug shapes Cedar policies must not see.
            if provenance is not None and provenance != absent_marker:
                raise ConformanceFailure(
                    12,
                    f"event[{i}] (execution_started) has no intent_objective "
                    f"but intent_provenance=={provenance!r}. Provenance "
                    f"without an underlying objective is invalid — the "
                    f"emitter either lost the objective in an error path or "
                    f"is fabricating the provenance signal. Set both fields "
                    f"to None / omit them entirely (the legacy silent posture) "
                    f"or stamp both consistently.",
                )


# ─── Invariant 11 (handle short-circuits after quarantine) ────────────


async def check_handle_short_circuits_after_quarantine(plugin: Any) -> None:
    """Invariant #11 — short-circuit semantics after quarantine.

    This function is wired into the cross-plugin conformance harness
    across every shipped plugin.

    The invariant: once a :class:`watchlight_core.BaseRunHandle`
    transitions to ``RunHandleState.QUARANTINED`` (because wl-apdp
    returned a Quarantine decision, or because a parent handle
    propagated quarantine down), every subsequent
    ``authorize_action`` / ``spawn_subagent`` call MUST raise
    :class:`AgentQuarantinedError` WITHOUT round-tripping to wl-apdp.
    This locks the bagged-agent semantics — a
    quarantined agent cannot silently fall through to a fresh
    Allow decision even if the wl-apdp anomaly cache has been
    cleared.

    Verification recipe (used by the conformance harness):

    1.  Build a plugin instance with a :class:`MockApdpClient` that
        returns a Quarantine response on the first ``authorize``
        call.
    2.  Open a handle, call ``authorize_action`` — expect
        :class:`AgentQuarantinedError`.
    3.  Snapshot the mock client's ``authorize_calls`` count.
    4.  Call ``authorize_action`` 5 more times — every call must
        raise :class:`AgentQuarantinedError` AND the mock client's
        ``authorize_calls`` count must NOT advance.
    5.  Call ``spawn_subagent`` (if the handle exposes it) — expect
        :class:`AgentQuarantinedError`.

    The conformance harness iterates this across every plugin's
    ``start_run`` path. This function is the load-bearing assertion.

    Args:
        plugin: An instantiated plugin with ``.apdp`` already swapped
            for a :class:`watchlight_core_testing.MockApdpClient`.

    Raises:
        ConformanceFailure: when the short-circuit invariant is
            violated (the handle round-tripped to wl-apdp after
            being quarantined).
    """
    # Local imports keep the module's import graph lean — testing
    # and decision aren't needed by the rest of conformance.py.
    from watchlight_core.decision import AgentQuarantinedError, RunHandleState
    from ._doubles import MockApdpClient

    apdp: Any = getattr(plugin, "apdp", None)
    if not isinstance(apdp, MockApdpClient):
        raise ConformanceFailure(
            11,
            "plugin.apdp must be a MockApdpClient for the invariant 11 "
            "check; the test harness installs it as part of the "
            "synthetic lifecycle setup.",
        )

    # Open a handle. We use the same slug the synthetic-lifecycle
    # runner registers so this function composes with the rest of
    # the harness. ``test-subagent`` is pre-registered too so the
    # slug-based spawn-step probe below can resolve through to
    # the QUARANTINED short-circuit (instead of bailing on an
    # ``AgentNotRegistered`` resolve_agent before the handle short-
    # circuit fires).
    apdp.known_agents.setdefault("test-agent", "uuid-quarantine-target")
    apdp.known_agents.setdefault(
        "test-subagent", "00000000-0000-0000-0000-000000000077"
    )
    handle = await plugin.start_run("test-agent")
    # Flip the contract-guard flag synthetically. The
    # conformance harness drives the handle WITHOUT the customer's
    # ``async with`` block because it composes multiple invariants
    # and needs full control over the lifecycle. In production
    # customer code, the ``async with`` block is mandatory; the
    # fail-closed guard in
    # :meth:`BaseRunHandle.authorize_action_detailed` enforces it.
    handle._aentered = True

    # Arm the mock to return a Quarantine response on the first
    # authorize() call.
    quarantine_response = {
        "decision": "Quarantine",
        "reason": "synthetic quarantine for invariant 11",
        "details": {
            "quarantine": {
                "reason": "synthetic quarantine for invariant 11",
                "anomaly_score": 0.92,
                "contributing_features": [],
                "model_version": None,
                "policy_id": "inv11.synthetic.quarantine",
            },
        },
    }

    original_authorize = apdp.authorize
    call_state = {"first": True}

    async def _patched(*args: Any, **kwargs: Any) -> Dict[str, Any]:
        if call_state["first"]:
            call_state["first"] = False
            # Still record the call for downstream invariants.
            apdp.authorize_calls.append(
                {
                    "principal": kwargs.get("principal") or (args[0] if args else ""),
                    "action": kwargs.get("action") or (args[1] if len(args) > 1 else ""),
                    "resource": kwargs.get("resource")
                    or (args[2] if len(args) > 2 else ""),
                    "execution_id": kwargs.get("execution_id"),
                    "session_id": kwargs.get("session_id"),
                }
            )
            return quarantine_response
        # Subsequent calls should NEVER reach this path because the
        # handle short-circuits. We return Allow so that a violation
        # surfaces as the right kind of failure (authorize_calls
        # count advancing) rather than as a downstream Deny that
        # looks superficially similar to the short-circuit raise.
        return await original_authorize(*args, **kwargs)

    apdp.authorize = _patched

    # Step 1 — first authorize MUST raise.
    try:
        await handle.authorize_action("execute", "synthetic")
    except AgentQuarantinedError:
        pass
    else:
        raise ConformanceFailure(
            11,
            "first authorize_action against a Quarantine response did NOT "
            "raise AgentQuarantinedError — the plugin's BaseRunHandle is "
            "not honouring the Quarantine wire decision.",
        )

    if handle.state != RunHandleState.QUARANTINED:
        raise ConformanceFailure(
            11,
            f"handle did not transition to QUARANTINED after a Quarantine "
            f"response (state={handle.state!r}).",
        )

    baseline_calls = len(apdp.authorize_calls)

    # Step 2 — five further authorize calls MUST all raise WITHOUT
    # advancing the mock's authorize_calls counter.
    for i in range(5):
        try:
            await handle.authorize_action(f"execute_{i}", f"synthetic_{i}")
        except AgentQuarantinedError:
            pass
        else:
            raise ConformanceFailure(
                11,
                f"authorize_action #{i + 2} on a QUARANTINED handle did NOT "
                f"raise AgentQuarantinedError. Short-circuit invariant "
                f"violated.",
            )
        if len(apdp.authorize_calls) != baseline_calls:
            raise ConformanceFailure(
                11,
                f"authorize_action #{i + 2} on a QUARANTINED handle "
                f"round-tripped to wl-apdp (authorize_calls advanced from "
                f"{baseline_calls} to {len(apdp.authorize_calls)}). "
                f"Short-circuit invariant violated — this is the kill-"
                f"switch bypass shape.",
            )

    # Step 3 — spawn_subagent must also raise on a QUARANTINED parent.
    # The canonical signature is kwargs-only with the child id as the
    # sole positional arg. Every plugin's spawn_subagent override
    # accepts the canonical kwargs surface, so the QUARANTINED
    # short-circuit fires BEFORE any signature-specific validation
    # runs. The base
    # ``BaseRunHandle.spawn_subagent`` and the LangGraph + Pydantic AI
    # overrides all short-circuit at the very top of the method, so
    # the spawn check is now unconditional — no signature-mismatch
    # opt-out remains.
    #
    # ``TypeError`` would still fire if a plugin's override signature
    # didn't include a positional child-id parameter (e.g. a
    # framework-specific shape with required kwargs); plugins that
    # don't expose ``spawn_subagent`` at all are still skipped via
    # the ``hasattr`` guard. The conformance contract is: if the
    # plugin exposes ``spawn_subagent``, a QUARANTINED call MUST
    # raise :class:`AgentQuarantinedError` BEFORE any other
    # validation.
    if hasattr(handle, "spawn_subagent"):
        # Slug-based plugins (LangGraph + Pydantic AI) accept a slug
        # as the first positional arg; the base class accepts a
        # UUID. Try both shapes and ensure SOME path raises the
        # AgentQuarantinedError before the spawn body runs.
        # ``test-subagent`` is registered into the mock by
        # ``_run_synthetic_lifecycle``; the UUID is the canonical
        # fail-closed shape.
        for child_id in (
            "test-subagent",
            "00000000-0000-0000-0000-000000000077",
        ):
            try:
                await handle.spawn_subagent(
                    child_id,
                    child_intent=ChildIntent(
                        category="conformance",
                        objective="Conformance quarantine probe",
                    ),
                    parent_execution_id="exec_inv11_quarantine",
                )
            except AgentQuarantinedError:
                break
            except TypeError:
                # The plugin's signature didn't accept this
                # positional/kwarg pair. Try the next shape.
                continue
            else:
                raise ConformanceFailure(
                    11,
                    "spawn_subagent on a QUARANTINED handle did NOT raise "
                    "AgentQuarantinedError. A quarantined agent must not "
                    "be permitted to delegate.",
                )


# ─── Public runner ────────────────────────────────────────────────────


async def check_required_hosted_tool_plugin(module_name: str) -> str:
    """Invariant #19 for one plugin in :data:`HOSTED_TOOL_PLUGINS_REQUIRED`,
    without the rest of the suite (some required plugins never call
    :func:`run_conformance`).

    Imports ``module_name`` and finds its plugin class. When the class
    does not declare :data:`SUPPORTS_HOSTED_TOOLS_ATTR` it is not built:
    the result is :data:`HOSTED_TOOL_PENDING` while the plugin is pending,
    a failure otherwise. When it declares support, it is built with its
    ``conformance_hosted_tool_instance()`` classmethod when it defines one
    (a plugin whose constructor needs more than an endpoint), else with
    ``apdp_url="http://localhost"``, and driven through
    :func:`check_hosted_tool_gate_wired`. Returns ``"ok"`` or
    :data:`HOSTED_TOOL_PENDING`. Raises :class:`ConformanceFailure` when
    the module is not a required plugin, cannot be imported, has no plugin
    class, cannot be built, or fails the invariant: never a skip.
    """
    dist = _distribution_name(module_name)
    if dist not in HOSTED_TOOL_PLUGINS_REQUIRED:
        raise ConformanceFailure(
            HOSTED_TOOLS_AUTHORIZED_INVARIANT_NUMBER,
            f"{module_name} is not in HOSTED_TOOL_PLUGINS_REQUIRED",
        )
    try:
        plugin_cls = discover_plugin_class(load_plugin_module(module_name))
    except Exception as exc:  # noqa: BLE001 - an import error fails, never skips
        raise ConformanceFailure(
            HOSTED_TOOLS_AUTHORIZED_INVARIANT_NUMBER,
            f"required plugin {dist} could not be loaded: {type(exc).__name__}: {exc}",
        ) from exc
    plugin: Any = plugin_cls
    if getattr(plugin_cls, SUPPORTS_HOSTED_TOOLS_ATTR, False) is True:
        factory = getattr(plugin_cls, HOSTED_TOOL_CONFORMANCE_FACTORY, None)
        try:
            plugin = factory() if callable(factory) else plugin_cls(apdp_url="http://localhost")
        except Exception as exc:  # noqa: BLE001 - a build error fails, never skips
            raise ConformanceFailure(
                HOSTED_TOOLS_AUTHORIZED_INVARIANT_NUMBER,
                f"required plugin {dist} could not be built: {type(exc).__name__}: {exc}",
            ) from exc
    result = await check_hosted_tool_gate_wired(plugin, module_name)
    if result is None:  # unreachable for a required plugin; fail closed regardless
        raise ConformanceFailure(
            HOSTED_TOOLS_AUTHORIZED_INVARIANT_NUMBER,
            f"required plugin {dist} was skipped",
        )
    return result


async def run_conformance(
    module_name: str,
    framework_tag: Optional[str] = None,
    verbose: bool = False,
) -> Tuple[bool, List[str]]:
    """Run the full conformance suite against a plugin module.

    Returns ``(passed, report_lines)``. The report lines are
    human-readable for the CLI.

    ``framework_tag`` is the prefix used for source attribution +
    URI namespacing checks (e.g. ``"langgraph"``). If None, it's
    inferred from the module name (``watchlight_<name>`` →
    ``<name>``).
    """
    report: List[str] = []

    # --- Step 1: load the plugin ----------------------------------------
    try:
        module = load_plugin_module(module_name)
    except ImportError as exc:
        report.append(f"FAIL: {exc}")
        return False, report
    report.append(f"OK   loaded module {module_name}")

    if framework_tag is None:
        framework_tag = (
            module_name.replace("watchlight_", "").replace("_", "-")
        )
    report.append(f"     framework_tag = {framework_tag!r}")

    # --- Step 2: discover the plugin class ------------------------------
    try:
        plugin_cls = discover_plugin_class(module)
    except AttributeError as exc:
        report.append(f"FAIL: {exc}")
        return False, report
    report.append(f"OK   plugin class = {plugin_cls.__name__}")

    # --- Step 3: instantiate the plugin ---------------------------------
    # Use ``http://localhost`` so the ApdpClient channel-safety guard
    # accepts the URL — the conformance harness never actually opens a
    # connection (the MockApdpClient takes over after instantiation),
    # but the constructor still validates the URL.
    try:
        plugin = plugin_cls(apdp_url="http://localhost")
    except Exception as exc:  # noqa: BLE001
        report.append(f"FAIL: could not instantiate plugin: {exc}")
        return False, report
    report.append("OK   plugin instantiated")

    # --- Step 4: discover translator (optional) ------------------------
    translator = discover_translator(module)
    if translator is not None:
        report.append(f"OK   translator = {translator.__name__}")
    else:
        report.append(
            "WARN no translate_*_event(s) function found — "
            "plugin emits no canonical events; only lifecycle "
            "invariants will be checked"
        )

    # --- Step 5: run the synthetic lifecycle ---------------------------
    try:
        events, mock, root_uuid, subagent_uuid = await _run_synthetic_lifecycle(
            plugin, framework_tag
        )
    except ConformanceFailure as exc:
        report.append(f"FAIL invariant {exc.args[0]}: {exc.args[1]}")
        return False, report
    except Exception as exc:  # noqa: BLE001
        report.append(f"FAIL lifecycle raised unexpectedly: {exc}")
        return False, report
    report.append(f"OK   synthetic lifecycle produced {len(events)} event(s)")

    # --- Step 5b: assert invariant 8 (sub-agent authz attribution) ----
    try:
        _assert_subagent_authz_attribution(mock, root_uuid, subagent_uuid)
    except ConformanceFailure as exc:
        inv_num, reason = exc.args
        inv_label = next(
            (label for n, label, _ in INVARIANTS if n == inv_num),
            "unknown",
        )
        report.append(
            f"FAIL invariant {inv_num} ({inv_label}): {reason}"
        )
        return False, report
    report.append("OK   invariant 8 (sub-agent authz attribution)")

    # --- Step 5c: assert invariant 9 (sub-agent lineage continuity) ---
    # When the synthetic lifecycle emits a spawn
    # event, every event the spawned execution emits must carry
    # root_execution_id and parent_execution_id matching the spawn
    # tree. Vacuous for plugins whose lifecycle doesn't spawn.
    try:
        _assert_subagent_lineage_continuity(events)
    except ConformanceFailure as exc:
        inv_num, reason = exc.args
        inv_label = next(
            (label for n, label, _ in INVARIANTS if n == inv_num),
            "unknown",
        )
        report.append(
            f"FAIL invariant {inv_num} ({inv_label}): {reason}"
        )
        return False, report
    report.append("OK   invariant 9 (sub-agent lineage continuity)")

    # --- Step 5d: assert invariant 11 (handle short-circuits after Quarantine) ─
    # Wires the invariant function into the runner so
    # every shipped plugin's existing conformance test exercises the
    # kill-switch semantics for free. The check runs against a fresh
    # plugin handle (so the synthetic lifecycle's captured events
    # above stay clean) with a MockApdpClient armed to return a
    # Quarantine decision on the first authorize call. The invariant
    # passes if and only if (a) the first call raises
    # AgentQuarantinedError, (b) the handle transitions to
    # QUARANTINED, (c) every subsequent call short-circuits with the
    # cached error WITHOUT round-tripping to wl-apdp.
    #
    # OPT-OUT (TEMPORARY): plugins that haven't yet wired their
    # framework runtime to consume AgentQuarantinedError can set
    # `supports_m45_quarantine = False` on the plugin class. Invariant
    # #11 is then SKIPPED with a warning. The opt-out is removed once
    # the kill-signal wiring lands across every plugin — we finish what
    # we start rather than leave a permanent escape valve.
    #
    # SKIP (NO `start_run`): plugins whose framework lifecycle doesn't
    # expose `plugin.start_run(slug)` (e.g. ADK, whose BasePlugin
    # surface is callback-only) will have failed the lifecycle step
    # earlier, so they never reach this branch. The check itself
    # guards `hasattr(plugin, "start_run")` defensively so a future
    # plugin shape doesn't accidentally make invariant #11 throw.
    supports_quarantine = getattr(plugin_cls, SUPPORTS_M45_QUARANTINE_ATTR, True)
    if not supports_quarantine:
        report.append(
            f"SKIP invariant 11 (handle_short_circuits_after_quarantine): "
            f"plugin class {plugin_cls.__name__} declares "
            f"`{SUPPORTS_M45_QUARANTINE_ATTR} = False` — {_KILL_SIGNAL_NOTE}"
        )
    elif not hasattr(plugin, "start_run"):
        report.append(
            "SKIP invariant 11 (handle_short_circuits_after_quarantine): "
            f"plugin {plugin_cls.__name__} exposes no `start_run` method, "
            "so the invariant cannot drive a handle through the Quarantine "
            "transition. This is fine for callback-only plugins (e.g. "
            "ADK's BasePlugin shape)."
        )
    else:
        # Build a fresh plugin instance for invariant #11 so the check
        # runs against a clean MockApdpClient state — re-using the
        # lifecycle's plugin would mix authorize_calls from the prior
        # steps and complicate the round-trip count assertion that's
        # load-bearing for the short-circuit invariant.
        try:
            inv11_plugin = plugin_cls(apdp_url="http://localhost")
        except Exception as exc:  # noqa: BLE001
            report.append(
                f"FAIL invariant 11: could not re-instantiate plugin for "
                f"the quarantine lifecycle: {exc}"
            )
            return False, report
        # Local imports keep the module's import graph lean.
        from ._doubles import MockApdpClient as _Mock

        inv11_plugin.apdp = _Mock()
        try:
            await check_handle_short_circuits_after_quarantine(inv11_plugin)
        except ConformanceFailure as exc:
            inv_num, reason = exc.args
            inv_label = next(
                (label for n, label, _ in INVARIANTS if n == inv_num),
                "unknown",
            )
            report.append(
                f"FAIL invariant {inv_num} ({inv_label}): {reason}"
            )
            return False, report
        except Exception as exc:  # noqa: BLE001
            report.append(
                f"FAIL invariant 11 lifecycle raised unexpectedly: {exc}"
            )
            return False, report
        report.append(
            "OK   invariant 11 (handle short-circuits after Quarantine)"
        )

    # --- Step 5e: assert invariant 12 (intent_objective + provenance consistency) ─
    # Every ``execution_started`` event in the captured lifecycle
    # stream MUST satisfy:
    #   - intent_objective populated  ⇒ intent_provenance ∈ {declared,
    #     plugin_derived, proxy_inferred}
    #   - intent_objective absent     ⇒ intent_provenance is absent OR
    #     omitted entirely
    #
    # The check runs against the events already captured in
    # ``_run_synthetic_lifecycle``. Plugins whose lifecycle doesn't
    # produce any ``execution_started`` events pass vacuously — the
    # invariant only constrains the events the plugin actually emits.
    # In practice, every shipped plugin's framework callback path emits
    # one execution_started per run, and this conformance check is the
    # cross-plugin floor that ensures the wire-shape invariant is
    # never silently violated.
    #
    # OPT-OUT (TEMPORARY): plugins where the intent-extraction wiring
    # hasn't shipped yet (ADK / MSAF / OpenClaw) can set
    # ``supports_m46_intent_extraction = False`` on the plugin class.
    # Invariant #12 is then SKIPPED with a warning. The opt-out is
    # removed once intent extraction lands across every plugin — we
    # finish what we start rather than leave a permanent escape valve.
    supports_intent = getattr(
        plugin_cls, SUPPORTS_M46_INTENT_EXTRACTION_ATTR, True
    )
    if not supports_intent:
        report.append(
            f"SKIP invariant 12 (intent_provenance_consistency): "
            f"plugin class {plugin_cls.__name__} declares "
            f"`{SUPPORTS_M46_INTENT_EXTRACTION_ATTR} = False` — {_INTENT_EXTRACTION_NOTE}"
        )
    else:
        try:
            check_intent_provenance_consistency(events)
        except ConformanceFailure as exc:
            inv_num, reason = exc.args
            inv_label = next(
                (label for n, label, _ in INVARIANTS if n == inv_num),
                "unknown",
            )
            report.append(
                f"FAIL invariant {inv_num} ({inv_label}): {reason}"
            )
            return False, report
        except Exception as exc:  # noqa: BLE001
            report.append(
                f"FAIL invariant 12 check raised unexpectedly: {exc}"
            )
            return False, report
        report.append(
            "OK   invariant 12 (intent_objective + provenance consistency)"
        )

    # --- Step 5f: assert invariant 13 (scope_attenuation_propagation) ─
    # Every ``agent_spawn_observed`` event in the captured
    # lifecycle stream MUST carry a populated ``delegation_scope``
    # payload field so audit replay can reconstruct the effective
    # authority at every depth in the spawn tree (the scope-attenuation
    # contract, audited at every depth).
    #
    # Plugins whose framework has no sub-agent primitive (Bedrock,
    # ADK, OpenClaw, MSAF, Claude Agent SDK / Plugin) emit no
    # ``agent_spawn_observed`` events from the synthetic lifecycle
    # and pass vacuously. Plugins that DO spawn (LangGraph + Pydantic
    # AI) MUST stamp the server-attested granted scope on
    # the wire event — the synthetic lifecycle drives a scoped spawn
    # through ``spawn_subagent`` so the override's
    # ``_build_audit_scope_payload`` lands a populated dict.
    #
    # Mirrors the TS lane's invariant #13
    # (the TypeScript SDK's conformance module). No
    # opt-out hatch — the propagation work has already
    # completed across the two Python plugins that override
    # ``spawn_subagent``, so no in-flight tracking issue blocks
    # adoption. Every plugin clears this gate (vacuously or by
    # stamping the scope) immediately.
    try:
        check_scope_attenuation_propagation(events)
    except ConformanceFailure as exc:
        inv_num, reason = exc.args
        inv_label = next(
            (label for n, label, _ in INVARIANTS if n == inv_num),
            "unknown",
        )
        report.append(
            f"FAIL invariant {inv_num} ({inv_label}): {reason}"
        )
        return False, report
    except Exception as exc:  # noqa: BLE001
        report.append(
            f"FAIL invariant 13 check raised unexpectedly: {exc}"
        )
        return False, report
    report.append(
        "OK   invariant 13 (scope_attenuation_propagation)"
    )

    # --- Step 5f': invariant 17 (a labelled spawn is attenuated) -------
    try:
        check_labelled_spawn_attenuated(events)
    except ConformanceFailure as exc:
        inv_num, reason = exc.args
        report.append(
            f"FAIL invariant {inv_num} ({LABELLED_SPAWN_ATTENUATED_INVARIANT_NAME}): {reason}"
        )
        return False, report
    report.append("OK   invariant 17 (labelled_spawn_attenuated)")

    # --- Step 5f'': invariant 19 (hosted tools authorized before the model call)
    # A plugin whose framework can put provider-hosted tools on a model
    # call declares ``supports_hosted_tools = True`` and defines the
    # ``conformance_hosted_tool_call(probe)`` hook; the check drives it
    # with a recording model client. A plugin that does not declare it is
    # skipped (each plugin's own hosted-tool change wires its hook).
    try:
        inv19_plugin = plugin_cls(apdp_url="http://localhost")
        inv19 = await check_hosted_tool_gate_wired(inv19_plugin, module_name)
    except ConformanceFailure as exc:
        inv_num, reason = exc.args
        report.append(
            f"FAIL invariant {inv_num} ({HOSTED_TOOLS_AUTHORIZED_INVARIANT_NAME}): {reason}"
        )
        return False, report
    except Exception as exc:  # noqa: BLE001
        report.append(f"FAIL invariant 19 check raised unexpectedly: {exc}")
        return False, report
    if inv19 == HOSTED_TOOL_PENDING:
        report.append(
            f"PENDING invariant 19 ({HOSTED_TOOLS_AUTHORIZED_INVARIANT_NAME}): this plugin "
            f"must declare `{SUPPORTS_HOSTED_TOOLS_ATTR} = True` before the next core release"
        )
    elif inv19 is None:
        report.append(
            f"SKIP invariant 19 ({HOSTED_TOOLS_AUTHORIZED_INVARIANT_NAME}): plugin "
            f"does not declare `{SUPPORTS_HOSTED_TOOLS_ATTR} = True`"
        )
    else:
        report.append(f"OK   invariant 19 ({HOSTED_TOOLS_AUTHORIZED_INVARIANT_NAME})")

    # --- Step 5g: assert invariant 14 (execution_started precedes non-lifecycle events) ─
    # Every non-mint event in the captured stream
    # MUST have a preceding ``execution_started`` event with the same
    # ``execution_id``. The closed-set mint events
    # (``execution_started`` / ``agent_spawn_observed`` /
    # ``ungoverned_request_observed``) are self-rooted; all other
    # event types (including future custom plugin variants) default
    # to non-mint and require an anchor.
    #
    # The SDK's ``BaseRunHandle``
    # defensively emits ``execution_started`` before the first
    # ``publish_observation`` / ``authorize_action_detailed``
    # round-trip — this invariant locks in the contract from the
    # consumer side so a future translator that bypasses the SDK
    # lifecycle, or a customer-direct emitter that forgets the mint,
    # fails CI loudly. No opt-out hatch — the guard has
    # already shipped across every plugin, so no in-flight tracking
    # issue blocks adoption.
    try:
        check_execution_started_precedes_non_lifecycle_events(events)
    except ConformanceFailure as exc:
        inv_num, reason = exc.args
        inv_label = next(
            (label for n, label, _ in INVARIANTS if n == inv_num),
            "unknown",
        )
        report.append(
            f"FAIL invariant {inv_num} ({inv_label}): {reason}"
        )
        return False, report
    except Exception as exc:  # noqa: BLE001
        report.append(
            f"FAIL invariant 14 check raised unexpectedly: {exc}"
        )
        return False, report
    report.append(
        "OK   invariant 14 (execution_started precedes non-lifecycle events)"
    )

    # --- Step 5h: assert invariant 15 (single correlated execution_id) ─
    # The execution-id correlation contract (core product
    # differentiator): ONE canonical execution_id per run across every
    # emitter. All root execution_started events for the run share one
    # id; every sub-agent's root_execution_id points at that single
    # root. Catches any emitter that mints a divergent root — the
    # "orphaned orchestrator execution" bug. See the Watchlight
    # documentation.
    try:
        check_single_correlated_execution_id(events)
    except ConformanceFailure as exc:
        inv_num, reason = exc.args
        inv_label = next(
            (label for n, label, _ in INVARIANTS if n == inv_num),
            "unknown",
        )
        report.append(
            f"FAIL invariant {inv_num} ({inv_label}): {reason}"
        )
        return False, report
    except Exception as exc:  # noqa: BLE001
        report.append(
            f"FAIL invariant 15 check raised unexpectedly: {exc}"
        )
        return False, report
    report.append(
        "OK   invariant 15 (single correlated execution_id)"
    )

    # --- Step 6: assert the seven invariants per event -----------------
    failed = False
    for i, event in enumerate(events):
        try:
            assert_canonical_event(
                event,
                expected_source=None,  # source CHECK is below
                expected_uri_prefix=(
                    f"{framework_tag}://"
                    if event.get("event_type") == "tool_call_observed"
                    else None
                ),
            )
            # Source-attribution check is done per-event here because
            # the expected tag prefix varies by event source.
            metadata = event.get("metadata") or {}
            source = metadata.get("source") or ""
            # SDK-emitted lineage-contract events
            # (defensive ``execution_started`` mints in
            # :meth:`watchlight_core.BaseRunHandle._emit_execution_started`)
            # legitimately bypass invariant 2's framework-tag prefix
            # check: these emissions originate from the SDK's
            # late-binding path, not the plugin's translator, so they
            # carry the plugin's ``_observation_source`` (which is
            # the SDK default ``"watchlight-core.publish_observation"``
            # for unbranded code paths or in conformance fixtures
            # that don't subclass BaseRunHandle). The discriminator
            # is ``metadata.kind == "execution_started_lineage_contract"``.
            if metadata.get("kind") == "execution_started_lineage_contract":
                continue
            if not source.startswith(framework_tag):
                raise ConformanceFailure(
                    2,
                    f"metadata.source {source!r} does not start with "
                    f"framework tag {framework_tag!r}",
                )
        except ConformanceFailure as exc:
            inv_num, reason = exc.args
            inv_label = next(
                (label for n, label, _ in INVARIANTS if n == inv_num),
                "unknown",
            )
            report.append(
                f"FAIL event[{i}] (event_type="
                f"{event.get('event_type','?')}) invariant "
                f"{inv_num} ({inv_label}): {reason}"
            )
            failed = True

    if not failed:
        report.append(
            f"OK   all 10 invariants (including 16, payload schema) pass on "
            f"{len(events)} event(s) "
            f"(invariants 11 + 12 + 13 + 14 + 15 reported separately)"
        )

    return not failed, report


def _print_report(report: List[str]) -> None:
    for line in report:
        print(line)


# ─── CLI ───────────────────────────────────────────────────────────────


def _main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m watchlight_core_testing.conformance",
        description="Run the canonical conformance invariant suite against a "
        "Watchlight plugin.",
    )
    parser.add_argument(
        "module",
        help="The plugin's importable module name (e.g. "
        "'watchlight_langgraph' or your custom plugin's package "
        "name).",
    )
    parser.add_argument(
        "--framework-tag",
        default=None,
        help="Override the framework tag used in source-attribution + "
        "URI-namespacing checks. Defaults to the package name minus "
        "the 'watchlight_' prefix (e.g. 'watchlight_langgraph' -> "
        "'langgraph').",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Print extra diagnostic info.",
    )
    args = parser.parse_args(argv)

    try:
        passed, report = asyncio.run(
            run_conformance(args.module, args.framework_tag, args.verbose)
        )
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130

    _print_report(report)

    if passed:
        print(f"\n✓ {args.module} PASSES the conformance suite")
        return 0
    print(f"\n✗ {args.module} FAILED conformance")
    return 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(_main())
