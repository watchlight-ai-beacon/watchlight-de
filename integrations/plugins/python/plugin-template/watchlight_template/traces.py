"""Framework callback → canonical ExecutionEvent translator.

Pure functions, no I/O. Plugin authors fill in the TODO 3 marker
with their framework's specific hook → canonical event mappings.

Wire shape produced here is the canonical
:class:`watchlight_core.ExecutionEvent` envelope — the seven
conformance invariants are asserted on it by
``watchlight_core_testing.assert_canonical_event``.
"""

from __future__ import annotations

import logging
import threading
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from watchlight_core import (
    PLAN_INTENDED_TOOLS_MAX,
    EventType,
    PlanKind,
    PlanValidationError,
    build_plan_payload,
    filter_valid_tool_names,
    truncate_rationale,
    redacted_input_summary,
)

logger = logging.getLogger("watchlight_template.traces")

__all__ = [
    "SOURCE_TAG",
    "URI_SCHEME",
    "dropped_event_counts",
    "translate_template_event",
    "translate_template_events",
]

# A dropped event is missing lineage. It must be visible: every drop is
# logged at ERROR and counted here by reason, so an operator (or a test)
# can see that the record of what the agent did is incomplete. Never drop
# an event quietly.
_drops: Dict[str, int] = {}
_drops_lock = threading.Lock()


def _count_drop(reason: str) -> None:
    with _drops_lock:
        _drops[reason] = _drops.get(reason, 0) + 1


def dropped_event_counts() -> Dict[str, int]:
    """How many events this process dropped, by reason (a copy)."""
    with _drops_lock:
        return dict(_drops)


#: T-RD9 source-tag for this plugin. The conformance suite asserts
#: ``metadata.source`` starts with this value on every emitted event.
#: When you fork the template, change ``template`` to your framework's
#: name (e.g. ``"myframework.callback"``) and update the conformance
#: registry in ``watchlight_core_testing/conformance.py`` accordingly.
SOURCE_TAG: str = "template.callback"

#: Resource URI scheme for tool references in
#: ``payload.tool.resource``. Conformance invariant 4 (URI
#: namespacing) asserts tool URIs start with ``<scheme>://``.
URI_SCHEME: str = "template"


# ─── Public translator: single + batch ────────────────────────────────


def translate_template_event(
    hook_dict: Dict[str, Any],
    *,
    execution_id: str,
    agent_id: str,
    session_id: Optional[str] = None,
    tenant_id: Optional[str] = None,
    parent_execution_id: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """Map one framework callback dict to one canonical
    ExecutionEvent.

    Returns the event dict (ready to ``POST`` to APDP's
    ``/v1/events``) on success, or ``None`` to drop the event
    (e.g. for callback types your plugin doesn't care about).

    TODO 3: dispatch on ``hook_dict`` to the right
    ``_build_*`` helper below. The reference plugins use a
    table of (hook_name → builder) for clean dispatch.
    """
    hook = hook_dict.get("hook")
    if not isinstance(hook, str):
        return None

    # TODO 3: add your framework's hook → builder mapping. The
    # builders below are starting points — you'll typically add /
    # rename them per the framework's lifecycle.

    if hook == "tool_start":
        return _build_tool_call_observed(
            hook_dict,
            execution_id=execution_id,
            agent_id=agent_id,
            session_id=session_id,
            tenant_id=tenant_id,
            parent_execution_id=parent_execution_id,
        )

    if hook == "plan_declared":
        return _build_plan_observed(
            hook_dict,
            execution_id=execution_id,
            agent_id=agent_id,
            session_id=session_id,
            tenant_id=tenant_id,
            parent_execution_id=parent_execution_id,
        )

    if hook == "execution_started":
        return _build_execution_started(
            hook_dict,
            execution_id=execution_id,
            agent_id=agent_id,
            session_id=session_id,
            tenant_id=tenant_id,
            parent_execution_id=parent_execution_id,
        )

    # Unknown hook — log at debug and drop. The conformance suite
    # doesn't penalize dropping events; it only penalizes BAD events.
    logger.debug("watchlight_template: unrecognized hook %r", hook)
    return None


def translate_template_events(
    events: List[Dict[str, Any]],
    *,
    execution_id: str,
    agent_id: str,
    session_id: Optional[str] = None,
    tenant_id: Optional[str] = None,
    parent_execution_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Batch translator. Same contract as
    :func:`translate_template_event`, applied to a list. ``None``
    returns are filtered out.
    """
    out: List[Dict[str, Any]] = []
    for ev in events:
        try:
            translated = translate_template_event(
                ev,
                execution_id=execution_id,
                agent_id=agent_id,
                session_id=session_id,
                tenant_id=tenant_id,
                parent_execution_id=parent_execution_id,
            )
        except Exception:  # noqa: BLE001 — translation must never crash
            # The event is lost: make it visible (see ``_drops``).
            _count_drop("translator_error")
            logger.exception(
                "watchlight_template: event dropped, the translator raised on %r",
                ev.get("hook"),
            )
            continue
        if translated is not None:
            out.append(translated)
    return out


# ─── Envelope builder + per-event-type helpers ────────────────────────


def _fresh_event_id() -> str:
    return f"evt_{uuid.uuid4()}"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _build_envelope(
    *,
    event_type: EventType,
    execution_id: str,
    agent_id: str,
    session_id: Optional[str],
    tenant_id: Optional[str],
    parent_execution_id: Optional[str],
    metadata_extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Build the common envelope dict shared across every event
    type. The T-RD9 ``metadata.source`` tag is always set here so
    plugin authors can't accidentally omit it (and silently fail
    conformance invariant 2).
    """
    envelope: Dict[str, Any] = {
        "event_id": _fresh_event_id(),
        "event_type": event_type.value,
        "timestamp": _now_iso(),
        "execution_id": execution_id,
        "agent_id": agent_id,
    }
    if session_id is not None:
        envelope["session_id"] = session_id
    if tenant_id is not None:
        envelope["tenant_id"] = tenant_id
    if parent_execution_id is not None:
        envelope["parent_execution_id"] = parent_execution_id

    metadata: Dict[str, Any] = {"source": SOURCE_TAG}
    if metadata_extra:
        metadata.update(metadata_extra)
    envelope["metadata"] = metadata
    return envelope


def _build_tool_call_observed(
    hook_dict: Dict[str, Any],
    **envelope_kwargs: Any,
) -> Dict[str, Any]:
    """TODO 3a: build a canonical ``tool_call_observed`` event
    from your framework's tool-start / tool-end callback.

    The minimum required payload fields are ``tool`` (a
    ResourceRef shape) and ``action`` (an ActionRef shape).
    ``input_summary`` is value-free (argument names and value types,
    bounded to 120 chars) via :func:`redacted_input_summary`: never put
    an argument value on a lineage event; a truncated value can still
    carry a credential or personal data.
    """
    tool_name = hook_dict.get("tool_name") or hook_dict.get("name") or "unknown"
    action_verb = hook_dict.get("action_verb") or "execute"
    tool_args = hook_dict.get("args")
    if tool_args is None:
        tool_args = hook_dict.get("input") or hook_dict.get("input_str")

    envelope = _build_envelope(
        event_type=EventType.TOOL_CALL_OBSERVED,
        **envelope_kwargs,
    )
    envelope["payload"] = {
        # ResourceRef shape — `endpoint` carries the namespaced URI
        # so conformance invariant 4 holds.
        "tool": {
            "resource_type": "tool",
            "identifier": tool_name,
            "endpoint": f"{URI_SCHEME}://tool/{tool_name}",
        },
        "action": {"action": action_verb},
        # Optional: APDP authorization outcome if your plugin
        # already knows it (e.g. the before_tool callback called
        # `handle.authorize_action` synchronously and you have the
        # result here).
        # "decision": "Allow",
        "input_summary": redacted_input_summary(tool_args),
    }
    return envelope


def _build_plan_observed(
    hook_dict: Dict[str, Any],
    **envelope_kwargs: Any,
) -> Optional[Dict[str, Any]]:
    """TODO 3b: build a canonical ``plan_observed`` event from
    your framework's plan-declaration callback.

    Bounded by :data:`PLAN_INTENDED_TOOLS_MAX` (64 tools) and
    the per-tool regex. Drop the event if the framework's plan
    is malformed — don't emit a malformed plan_observed.
    """
    intended = hook_dict.get("intended_tools") or []
    if not isinstance(intended, list):
        _count_drop("plan_malformed")
        logger.error("watchlight_template: plan_observed dropped, intended_tools is not a list")
        return None
    intended = filter_valid_tool_names(intended)
    if not intended:
        _count_drop("plan_malformed")
        logger.error("watchlight_template: plan_observed dropped, no valid tool names")
        return None

    rationale = hook_dict.get("rationale") or hook_dict.get("reason")

    plan_kind = hook_dict.get("plan_kind") or PlanKind.INCREMENTAL
    if isinstance(plan_kind, PlanKind):
        plan_kind = plan_kind.value if hasattr(plan_kind, "value") else str(plan_kind)

    try:
        payload = build_plan_payload(
            intended_tools=intended,
            plan_kind=plan_kind,
            rationale=truncate_rationale(rationale),
        )
    except PlanValidationError as exc:
        # The plan is lost: make it visible (see ``_drops``).
        _count_drop("plan_invalid")
        logger.error("watchlight_template: plan_observed dropped, plan validation failed: %s", exc)
        return None

    envelope = _build_envelope(
        event_type=EventType.PLAN_OBSERVED,
        **envelope_kwargs,
    )
    envelope["payload"] = payload
    return envelope


def _build_execution_started(
    hook_dict: Dict[str, Any],
    **envelope_kwargs: Any,
) -> Dict[str, Any]:
    """TODO 3c: build a canonical ``execution_started`` event
    from your framework's "agent run starting" callback.
    """
    envelope = _build_envelope(
        event_type=EventType.EXECUTION_STARTED,
        **envelope_kwargs,
    )
    envelope["payload"] = {
        "principal": {
            "principal_type": "agent",
            "id": envelope_kwargs.get("agent_id") or hook_dict.get("agent_id", ""),
        },
        "depth": int(hook_dict.get("depth") or 0),
    }
    return envelope
