"""Per-framework synthetic ``watchlight.declare_intent`` tool
for AWS Bedrock Agents.

This module is the Bedrock-native translation of the canonical
:data:`watchlight_core.WATCHLIGHT_DECLARE_INTENT_TOOL` contract. Unlike
frameworks whose tool surface is constructed in the same process the
plugin runs in, Bedrock's tool surface is defined **server-side on the
Bedrock Agent resource itself** via the AWS ``bedrock-agent``
control-plane API or the AWS console. At runtime the plugin can neither
add new action groups nor mutate the existing ones; the AWS service is
the authoritative tool registry.

Architectural consequence
=========================

The Bedrock injection is **structurally one-line opt-in** rather than
fully zero-touch, because Bedrock's tool surface is server-side.
Operators wire the synthetic action group ONCE at Bedrock Agent setup
(IaC or boto3 ``create_agent_action_group``) using
:func:`build_synthetic_action_group_schema` to render the exact AWS
shape. From that point on, ZERO customer agent code touches —
everything else is automatic:

- The customer's Bedrock Agent advertises ``watchlight/declare_intent``
  alongside their own tools to the LLM.
- When the LLM invokes the synthetic tool, the Bedrock service routes
  the call to either:

  1. The customer's existing action-group Lambda (the plugin's
     :func:`watchlight_bedrock_action` decorator detects the call via
     :func:`is_synthetic_bedrock_event` and short-circuits BEFORE the
     APDP ``/authorize`` round-trip — the synthetic-tool carve-out).
  2. A no-op pass-through Lambda the operator can stand up via the
     :func:`render_synthetic_lambda_handler` factory (returns a
     pre-wrapped Lambda body that just delegates to
     :func:`handle_synthetic_bedrock_invocation`).

The two paths converge: in both cases
:func:`watchlight_core.handle_declare_intent_call` is what mutates the
plugin's mirror-state and the response shape is the canonical
``{"status": "intent_declared", "objective": "..."}`` wrapped in
Bedrock's response envelope.

Naming convention
=================

Bedrock function names cannot contain the dot character (``.``) — they
must be valid AWS resource identifiers (``[A-Za-z0-9_-]+``). The
canonical wire literal is ``watchlight.declare_intent`` (with a dot,
matching every other framework's tool literal); the plugin renders
this as:

- **action group name** = ``watchlight_intent`` (operator-visible
  prefix in the Bedrock console)
- **function name** = ``declare_intent``
- **api path** (REST-style) = ``/declare_intent``

The canonical literal ``watchlight.declare_intent`` is still what the
audit log captures (the plugin re-projects from the Bedrock identifier
on its way to the lineage event) — the cross-plugin contract holds at
the Cedar level even though the AWS-facing identifier is dot-free.

Synthetic-tool carve-out
========================

The synthetic tool's invocation MUST NOT round-trip to APDP
``/authorize`` — in greenfield mode the Cedar policy forbids Custodial
actions until the session has declared intent
(``provenance == "declared"``). The plugin's
:func:`is_synthetic_bedrock_event` predicate fires the short-circuit
BEFORE the authorize hop.

Cross-Lambda-invocation state propagation
=========================================

The Lambda decorator runs in a stateless process — every invocation
starts a fresh decorator path. After the synthetic tool fires in
one Lambda, the NEXT Lambda call (for a real Custodial tool) needs
to know intent was declared so it can inject ``intent`` into the
APDP ``/authorize`` body. We use a SESSION-keyed in-process cache
keyed on ``watchlight_session_id`` — within a warm Lambda container,
multiple invocations against the same APDP session share the cache.

**Limitations (honest documentation):**

- Cold-start Lambdas lose the cache and the declared intent on the
  next invocation will not auto-inject. Mitigation: the orchestrator
  side should ALSO call
  :func:`watchlight_core.BaseRunHandle.record_declared_intent`
  before ``invoke_agent`` so the orchestrator's handle carries the
  intent state for the duration of the user conversation. The
  Lambda-side cache is a best-effort optimisation, NOT the load-bearing
  path.
- The cache is per Lambda container; concurrent containers serving the
  same Bedrock session won't share state. The Bedrock service serializes
  per-session traffic to one container at a time in practice, so this
  is rarely observable, but a multi-container fan-out would lose the
  declaration.

The reliable end-to-end path is **orchestrator declaration**:
``await handle.record_declared_intent(...)`` BEFORE
``invoke_agent``. The Lambda-side synthetic action group is the
zero-touch convenience layer for the common case (single warm
container, agent declares via LLM tool call).
"""

from __future__ import annotations

import json
from typing import Any, Callable, Dict, Optional

from watchlight_core import (
    DECLARE_INTENT_RESPONSE_STATUS,
    DECLARE_INTENT_TOOL_DESCRIPTION,
    DECLARE_INTENT_TOOL_NAME,
    INTENT_OBJECTIVE_MAX_BYTES,
    WATCHLIGHT_DECLARE_INTENT_TOOL,
    get_logger,
    handle_declare_intent_call,
    is_declare_intent_tool_name,
    resolve_intent_enforcement_mode,
    should_inject_synthetic_tool,
    typed_intent,
)

logger = get_logger("watchlight_bedrock.synthetic_intent_tool")


__all__ = [
    "SYNTHETIC_ACTION_GROUP_NAME",
    "SYNTHETIC_FUNCTION_NAME",
    "SYNTHETIC_API_PATH",
    "build_synthetic_action_group_schema",
    "build_synthetic_action_group_function_schema",
    "is_synthetic_bedrock_event",
    "extract_objective_from_bedrock_event",
    "extract_category_from_bedrock_event",
    "handle_synthetic_bedrock_invocation",
    "render_synthetic_bedrock_response",
    "render_synthetic_lambda_handler",
]


# ─── Bedrock identifier convention ────────────────────────────────────


#: Action-group name surfaced to the Bedrock Agent. Operator-visible
#: in the AWS console; chosen to be self-documenting + collision-free
#: with the customer's own action groups (they typically use names
#: like ``research_tools`` / ``trading_actions``).
SYNTHETIC_ACTION_GROUP_NAME: str = "watchlight_intent"

#: Function name within the action group. Dot-free per Bedrock's
#: ``[A-Za-z0-9_-]+`` constraint on AWS resource identifiers. The
#: canonical wire literal ``watchlight.declare_intent`` is preserved
#: at the audit-log level — the plugin re-projects from this
#: identifier when emitting the canonical ``tool_call_observed`` event.
SYNTHETIC_FUNCTION_NAME: str = "declare_intent"

#: REST-style ``apiPath`` for action groups defined via OpenAPI
#: ``apiSchema`` rather than the simpler ``functionSchema``. Bedrock
#: requires a leading slash and disallows the dot — same constraint
#: that drove the function name choice.
SYNTHETIC_API_PATH: str = "/declare_intent"


# ─── Action-group schema renderers ────────────────────────────────────


def build_synthetic_action_group_function_schema() -> Dict[str, Any]:
    """Render the synthetic tool's ``functionSchema`` for Bedrock's
    simpler function-style action-group definition.

    Returns the dict the operator passes to
    ``bedrock-agent.create_agent_action_group(functionSchema=...)``
    (or the equivalent CloudFormation / Terraform resource attribute).

    The shape matches AWS's
    `FunctionSchema <https://docs.aws.amazon.com/bedrock/latest/APIReference/API_agent_FunctionSchema.html>`_
    contract: one ``functions`` list, each function carrying ``name``,
    ``description``, and a ``parameters`` map keyed by parameter name.

    The synthetic tool exposes exactly one required parameter
    (``objective``) capped at
    :data:`watchlight_core.INTENT_OBJECTIVE_MAX_BYTES` bytes — byte-
    identical to the canonical
    :data:`watchlight_core.WATCHLIGHT_DECLARE_INTENT_TOOL` JSON
    Schema. Operators MUST NOT mutate the rendered dict before
    passing it to AWS; drift between the AWS-advertised shape and the
    plugin's interception predicate would let an attacker craft a
    declaration that bypasses
    :func:`handle_synthetic_bedrock_invocation`.
    """
    return {
        "functions": [
            {
                "name": SYNTHETIC_FUNCTION_NAME,
                "description": DECLARE_INTENT_TOOL_DESCRIPTION,
                "parameters": {
                    "objective": {
                        "description": (
                            "Your declared goal for this session. "
                            "Truncated to 256 bytes (UTF-8) for the "
                            "audit log."
                        ),
                        "type": "string",
                        "required": True,
                    },
                    # wl-apdp requires a category on every intent.
                    "category": {
                        "description": WATCHLIGHT_DECLARE_INTENT_TOOL["parameters"][
                            "properties"
                        ]["category"]["description"],
                        "type": "string",
                        "required": True,
                    },
                    # Optional: some categories are refused without one.
                    "justification": {
                        "description": WATCHLIGHT_DECLARE_INTENT_TOOL["parameters"][
                            "properties"
                        ]["justification"]["description"],
                        "type": "string",
                        "required": False,
                    },
                },
            }
        ]
    }


def build_synthetic_action_group_schema(
    mode: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """Top-level helper the operator calls from their IaC to wire the
    synthetic action group onto their Bedrock Agent.

    Returns a dict carrying the four AWS-facing fields the operator
    splats into ``bedrock-agent.create_agent_action_group``:

    - ``actionGroupName`` — :data:`SYNTHETIC_ACTION_GROUP_NAME`
    - ``description`` — operator-facing description
    - ``functionSchema`` — :func:`build_synthetic_action_group_function_schema`
    - ``actionGroupState`` — ``"ENABLED"``

    Returns ``None`` in brownfield mode — the operator can use this
    truthy-check to skip the action-group creation entirely when their
    deployment defaults to brownfield::

        ag = build_synthetic_action_group_schema(mode=plugin.intent_enforcement_mode)
        if ag is not None:
            bedrock_agent.create_agent_action_group(
                agentId=...,
                agentVersion="DRAFT",
                actionGroupExecutor={"customControl": "RETURN_CONTROL"},
                **ag,
            )

    The default mode resolution honours the standard SDK precedence
    (explicit > env var > brownfield) when ``mode`` is ``None``.
    """
    effective_mode = (
        mode if isinstance(mode, str) else resolve_intent_enforcement_mode()
    )
    if not should_inject_synthetic_tool(effective_mode):
        return None
    return {
        "actionGroupName": SYNTHETIC_ACTION_GROUP_NAME,
        "description": (
            "Watchlight AI synthetic intent-declaration tool. The "
            "agent MUST call watchlight_intent/declare_intent BEFORE "
            "any other tool in this session. Renders the canonical "
            "watchlight.declare_intent contract from "
            f"watchlight_core (v{INTENT_OBJECTIVE_MAX_BYTES}-byte cap)."
        ),
        "functionSchema": build_synthetic_action_group_function_schema(),
        "actionGroupState": "ENABLED",
    }


# ─── Bedrock event interception ───────────────────────────────────────


def is_synthetic_bedrock_event(event: Dict[str, Any]) -> bool:
    """Return ``True`` iff the Bedrock invocation event is targeting the
    synthetic ``watchlight_intent/declare_intent`` tool.

    Matches both Bedrock action-group flavours:

    - **Function-style**: ``event["actionGroup"] == "watchlight_intent"``
      AND ``event["function"] == "declare_intent"``.
    - **REST-style**: ``event["actionGroup"] == "watchlight_intent"``
      AND ``event["apiPath"]`` is ``"/declare_intent"`` (with or
      without the leading slash, case-insensitive — defends against
      operator typos in the OpenAPI schema).

    Returns ``False`` on any unrecognised shape so the plugin's
    decorator forwards to the normal authorize path — safer than a
    false positive that would bypass authorization on a non-synthetic
    tool. Also returns ``False`` for the canonical literal
    ``watchlight.declare_intent`` appearing in a non-Bedrock shape;
    the plugin's other framework lanes own that detection path via
    :func:`watchlight_core.is_declare_intent_tool_call`.
    """
    if not isinstance(event, dict):
        return False
    action_group = event.get("actionGroup")
    if not isinstance(action_group, str):
        return False
    if action_group.strip().lower() != SYNTHETIC_ACTION_GROUP_NAME:
        return False

    # Function-style detection
    function_name = event.get("function")
    if isinstance(function_name, str) and function_name.strip().lower() == SYNTHETIC_FUNCTION_NAME:
        return True

    # REST-style detection — tolerate ``/declare_intent`` or
    # ``declare_intent`` to defend against OpenAPI schema typos.
    api_path = event.get("apiPath")
    if isinstance(api_path, str):
        normalised = api_path.strip().lower().lstrip("/")
        if normalised == SYNTHETIC_FUNCTION_NAME:
            return True

    return False


def extract_objective_from_bedrock_event(
    event: Dict[str, Any],
) -> Optional[str]:
    """The raw ``objective`` argument of a synthetic-tool invocation (see
    :func:`_extract_bedrock_argument`)."""
    return _extract_bedrock_argument(event, "objective")


def extract_category_from_bedrock_event(
    event: Dict[str, Any],
) -> Optional[str]:
    """The raw ``category`` argument of a synthetic-tool invocation (see
    :func:`_extract_bedrock_argument`); normalised downstream."""
    return _extract_bedrock_argument(event, "category")


def _extract_bedrock_argument(
    event: Dict[str, Any],
    name: str,
) -> Optional[str]:
    """Extract the ``objective`` argument from a synthetic-tool Bedrock
    invocation event.

    Bedrock surfaces tool arguments in three places depending on the
    action-group flavour:

    1. Function-style with ``parameters``: a list of
       ``{"name", "type", "value"}`` dicts. Walk for ``name=="objective"``.
    2. REST-style with ``requestBody.content.<media>.properties``:
       same list shape. Walk for ``name=="objective"``.
    3. ``requestBody.content.<media>.body`` carrying a JSON-string
       payload. Some Bedrock variants use this for OpenAPI-defined
       bodies. Parse and read ``["objective"]``.

    Returns the raw objective string (NOT yet truncated; the
    :func:`watchlight_core.handle_declare_intent_call` helper
    truncates downstream). Returns ``None`` when no objective parameter
    is present — the caller treats that as an empty declaration and
    the synthetic-tool response carries ``status: rejected``.

    Best-effort across schema variants: an exotic shape that this
    extractor doesn't recognise returns ``None`` rather than raising,
    keeping the Lambda decorator's fail-closed envelope intact.
    """
    if not isinstance(event, dict):
        return None

    # (1) function-style parameters
    parameters = event.get("parameters")
    if isinstance(parameters, list):
        for param in parameters:
            if (
                isinstance(param, dict)
                and param.get("name") == name
                and isinstance(param.get("value"), str)
            ):
                return param["value"]

    # (2)/(3) REST-style requestBody
    request_body = event.get("requestBody")
    if isinstance(request_body, dict):
        content = request_body.get("content") or {}
        if isinstance(content, dict):
            for media in content.values():
                if not isinstance(media, dict):
                    continue
                # (2) properties list
                properties = media.get("properties")
                if isinstance(properties, list):
                    for prop in properties:
                        if (
                            isinstance(prop, dict)
                            and prop.get("name") == name
                            and isinstance(prop.get("value"), str)
                        ):
                            return prop["value"]
                # (3) JSON-encoded body
                body_raw = media.get("body")
                if isinstance(body_raw, str):
                    try:
                        parsed = json.loads(body_raw)
                        if isinstance(parsed, dict) and isinstance(
                            parsed.get(name), str
                        ):
                            return parsed[name]
                    except (json.JSONDecodeError, TypeError):
                        continue

    return None


# ─── Bedrock response shape ───────────────────────────────────────────


def render_synthetic_bedrock_response(
    event: Dict[str, Any],
    payload: Dict[str, Any],
    *,
    http_status: int = 200,
) -> Dict[str, Any]:
    """Wrap a synthetic-tool response dict in Bedrock's expected
    action-group response envelope.

    Bedrock's action-group response shape (see
    `BedrockAgent action-group docs
    <https://docs.aws.amazon.com/bedrock/latest/userguide/agents-action-create.html>`_):

    .. code-block:: python

        {
            "messageVersion": "1.0",
            "response": {
                "actionGroup": <str>,
                "apiPath": <str>,
                "httpMethod": <str>,
                "httpStatusCode": <int>,
                "responseBody": {
                    "application/json": {"body": "<JSON string>"},
                },
            },
        }

    Bedrock surfaces ``responseBody.application/json.body`` back into
    the agent's reasoning trace so the LLM sees the ``intent_declared``
    status and continues with its real task.

    Args:
        event: The original Bedrock invocation event. We reflect
            ``actionGroup`` / ``apiPath`` / ``httpMethod`` from it so
            Bedrock can route the response back to the right
            action-group context.
        payload: The dict to encode as the JSON body (typically the
            output of :func:`watchlight_core.handle_declare_intent_call`).
        http_status: Defaults to 200 for the canonical Allow path;
            use 4xx if you ever need to surface a synthetic-tool
            failure to Bedrock as a non-200 (the current
            implementation never emits non-200 — empty objective
            still returns 200 with ``status: rejected`` so the agent
            can retry without Bedrock's error-handling pathway
            interfering).
    """
    parsed = event if isinstance(event, dict) else {}
    body_payload = json.dumps(payload)
    return {
        "messageVersion": parsed.get("messageVersion", "1.0"),
        "response": {
            "actionGroup": SYNTHETIC_ACTION_GROUP_NAME,
            "apiPath": parsed.get("apiPath", SYNTHETIC_API_PATH),
            "httpMethod": parsed.get("httpMethod", "POST"),
            "httpStatusCode": http_status,
            "responseBody": {
                "application/json": {"body": body_payload},
            },
        },
    }


# ─── Cross-Lambda-invocation declared-intent cache ────────────────────


#: Warm-start cache of declared objectives, keyed on the APDP
#: ``watchlight_session_id``. See module docstring for the load-bearing
#: limitations.
_DECLARED_INTENT_CACHE: Dict[str, Dict[str, Any]] = {}


def record_session_declared_intent(
    session_id: str, objective: str, category: Any = None, justification: Any = None
) -> None:
    """Record a declared objective on the warm-start session cache.

    Called by :func:`handle_synthetic_bedrock_invocation` after the
    synthetic tool fires; read by the Lambda decorator's authorize
    path so the next non-synthetic tool call auto-injects
    ``intent={"objective": <stored>}`` into the APDP ``/authorize``
    request body.

    No-op on empty ``session_id`` — the orchestrator side is the
    load-bearing path for cold-start cases.
    """
    if not isinstance(session_id, str) or not session_id:
        return
    # Only a typed intent (objective AND category) is kept: wl-apdp answers
    # an objective-only intent with 422, so one is never sent.
    intent = typed_intent(objective, category, justification)
    if intent is None:
        return
    _DECLARED_INTENT_CACHE[session_id] = intent


def get_session_declared_intent(session_id: Optional[str]) -> Optional[Dict[str, Any]]:
    """Read the warm-start session cache: the declared typed intent
    (``{"objective", "category"}``), or ``None`` when the session has not
    declared (cold-start case included)."""
    if not isinstance(session_id, str) or not session_id:
        return None
    return _DECLARED_INTENT_CACHE.get(session_id)


def clear_session_declared_intent(session_id: Optional[str]) -> None:
    """Evict a session from the warm-start cache.

    Called on ``complete_session`` / ``terminate_session`` so a stale
    declaration from a finished session can't leak into a fresh one
    that re-uses the same session id within the same Lambda container.
    """
    if not isinstance(session_id, str) or not session_id:
        return
    _DECLARED_INTENT_CACHE.pop(session_id, None)


# ─── Synthetic-tool handler (short-circuit body) ──────────────────────


class _BedrockHandleShim:
    """Duck-typed minimal :class:`watchlight_core.BaseRunHandle`
    surface for :func:`watchlight_core.handle_declare_intent_call`.

    The helper only reads/writes ``_intent_objective`` +
    ``_intent_provenance`` on whatever object is passed as ``handle``.
    In the Bedrock Lambda lane there is no real ``BaseRunHandle`` —
    the decorator operates on the raw event without a long-lived run
    handle. This shim satisfies the helper's contract and lets us
    capture the truncated objective for the session cache.
    """

    def __init__(self) -> None:
        self._intent_objective: Optional[str] = None
        self._intent_category: Optional[Any] = None
        self._intent_justification: Optional[str] = None
        self._intent_provenance: Optional[Any] = None


def handle_synthetic_bedrock_invocation(
    event: Dict[str, Any],
    *,
    log_decisions: bool = True,
) -> Dict[str, Any]:
    """Process a synthetic ``watchlight_intent/declare_intent`` Bedrock
    invocation BEFORE the APDP ``/authorize`` round-trip.

    This is the synthetic-tool carve-out body. The function:

    1. Extracts the ``objective`` argument from the Bedrock event
       payload (function-style ``parameters`` OR REST-style
       ``requestBody`` shapes).
    2. Delegates to :func:`watchlight_core.handle_declare_intent_call`
       which truncates the objective to
       :data:`watchlight_core.INTENT_OBJECTIVE_MAX_BYTES` bytes and
       mutates the duck-typed handle shim.
    3. Records the truncated objective on the warm-start session
       cache (keyed on the APDP ``watchlight_session_id`` from
       ``sessionAttributes``) so subsequent Lambda invocations
       within the same warm container auto-inject the intent into
       their ``/authorize`` request body.
    4. Wraps the canonical response dict in Bedrock's action-group
       response envelope.

    Returns the Bedrock-shaped dict the Lambda handler returns
    verbatim. Bedrock surfaces the ``intent_declared`` status back
    into the LLM's reasoning trace so the agent sees the
    confirmation and proceeds with its real task.

    Never raises — the synthetic tool's invocation MUST NOT crash
    the Lambda. An exotic event shape falls through to the
    ``status: rejected`` path which Bedrock surfaces to the LLM as
    a retryable failure rather than a Lambda 500.
    """
    objective_arg = extract_objective_from_bedrock_event(event)
    category_arg = extract_category_from_bedrock_event(event)
    justification_arg = _extract_bedrock_argument(event, "justification")
    session_attrs = (
        event.get("sessionState", {}).get("sessionAttributes")
        or event.get("sessionAttributes")
        or {}
    )
    shim = _BedrockHandleShim()
    # The category already declared in this session (warm container): the
    # category is fixed for the session once declared.
    previous = get_session_declared_intent(session_attrs.get("watchlight_session_id"))
    if previous is not None:
        shim._intent_category = previous.get("category")
    response_payload = handle_declare_intent_call(
        shim,
        {"objective": objective_arg, "category": category_arg, "justification": justification_arg},
    )

    # Record on the session cache when the declaration succeeded —
    # rejected declarations leave the cache untouched so the agent
    # can retry without burning the slot.
    if (
        response_payload.get("status") == DECLARE_INTENT_RESPONSE_STATUS
        and shim._intent_objective
    ):
        session_id = session_attrs.get("watchlight_session_id")
        record_session_declared_intent(
            session_id, shim._intent_objective, shim._intent_category, shim._intent_justification
        )

    if log_decisions:
        logger.info(
            "[INTENT-DECLARED] bedrock synthetic tool fired; status=%s",
            response_payload.get("status"),
        )

    return render_synthetic_bedrock_response(event, response_payload)


# ─── Lambda-handler factory (zero customer-code path) ─────────────────


def render_synthetic_lambda_handler(
    *,
    log_decisions: bool = True,
) -> Callable[[Dict[str, Any], Any], Dict[str, Any]]:
    """Return a ready-made Lambda handler for the synthetic action
    group's executor.

    Operators who use Bedrock's ``actionGroupExecutor.lambda`` model
    (rather than ``customControl: RETURN_CONTROL``) can stand up the
    synthetic action group's executor with::

        # watchlight_intent_lambda.py
        from watchlight_bedrock.synthetic_intent_tool import (
            render_synthetic_lambda_handler,
        )
        lambda_handler = render_synthetic_lambda_handler()

    No customer code beyond that one line. The handler is a thin
    delegate to :func:`handle_synthetic_bedrock_invocation`; no APDP
    round-trip happens because the synthetic-tool carve-out elides it.

    Operators who prefer the Bedrock ``customControl: RETURN_CONTROL``
    flow (no Lambda executor at all) can instead call
    :func:`handle_synthetic_bedrock_invocation` directly from their
    orchestrator-side Return Control loop. The function signature is
    the same — Bedrock's Return Control payload carries the same
    ``actionGroup`` / ``function`` / ``parameters`` shape the Lambda
    event would.
    """

    def lambda_handler(event: Dict[str, Any], context: Any = None) -> Dict[str, Any]:
        # context is required by the AWS Lambda contract but the
        # synthetic-tool path doesn't read it. Suppress the unused-
        # argument lint via underscore-prefix wouldn't work because
        # Lambda dispatches by positional name; we read-then-discard.
        del context  # noqa: F841
        return handle_synthetic_bedrock_invocation(
            event, log_decisions=log_decisions
        )

    return lambda_handler


# ─── Canonical-name reflection (for the audit log) ────────────────────


def project_synthetic_to_canonical_name(action_or_path: Optional[str]) -> str:
    """Map a Bedrock action/path back to the canonical wire literal.

    Returns :data:`watchlight_core.DECLARE_INTENT_TOOL_NAME`
    (``"watchlight.declare_intent"``) when the input is the Bedrock-
    flavoured spelling; returns the input unchanged otherwise. Used
    by the lineage emitter so the canonical literal appears on the
    audit log regardless of which framework's identifier-spelling
    bypassed the dot.
    """
    if not isinstance(action_or_path, str):
        return action_or_path or ""
    candidate = action_or_path.strip().lstrip("/").lower()
    if (
        candidate == SYNTHETIC_FUNCTION_NAME
        or candidate == f"{SYNTHETIC_ACTION_GROUP_NAME}/{SYNTHETIC_FUNCTION_NAME}"
        or is_declare_intent_tool_name(action_or_path)
    ):
        return DECLARE_INTENT_TOOL_NAME
    return action_or_path
