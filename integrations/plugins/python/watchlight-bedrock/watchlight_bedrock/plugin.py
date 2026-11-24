"""WatchlightBedrockPlugin — governance for AWS Bedrock Agents.

Bedrock Agents integrate with Watchlight at two surfaces:

1. **Orchestrator-side** — wherever your code calls
   ``bedrock-agent-runtime.invoke_agent(...)``. You open a governed run
   with ``plugin.start_run(agent_slug)`` *before* invoking, and close
   it in a ``finally`` block. The returned :class:`RunHandle` provides
   ``submit_plan`` / ``preflight_step`` / ``authorize_action`` plus the
   Bedrock-specific :meth:`RunHandle.bedrock_agent_runtime` wrapper,
   the only supported way to call ``invoke_agent``: it authorizes the
   agent's hosted capabilities before the call and adds the Watchlight
   session attributes the action-group Lambdas read.

2. **Lambda action-group** — Bedrock orchestrates internally and calls
   out to your action-group Lambdas for tool execution. Wrap the
   Lambda handler with :func:`watchlight_bedrock_action` to enforce
   APDP ``/authorize`` on every Bedrock-initiated tool call. The
   decorator parses the Bedrock event envelope, maps it to an APDP
   authz call, and short-circuits with a properly-shaped Bedrock
   refusal response when policy denies.

Why two surfaces, not one: Bedrock's planning happens server-side and
is opaque (no plan handed to plugins). The orchestrator side gives us
session lifecycle and any plan we *do* have visibility into; the
Lambda side gives us authoritative per-action enforcement at the only
place customer code runs. Together they're equivalent in policy reach
to the ADK and LangGraph plugins, just split across two AWS-native
boundaries.

Shared HTTP client + result wrappers + plan normaliser + lifecycle
base class all live in :mod:`watchlight_core`. This module owns only
the Bedrock-specific surface: the plugin class with its
``bedrock_agent_runtime`` wrapper, the Lambda action-group
decorator, the Bedrock event parser, and the Bedrock-shaped deny
response builder.
"""

import asyncio
import functools
import json
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from watchlight_core.backend import RunRef, SessionInfo, egress_binding_for
from watchlight_core import (
    INTENT_OBJECTIVE_MAX_BYTES,
    AgentNotRegistered,
    ApdpClient,
    application_id_from_env,
    resolve_application_id,
    BaseRunHandle,
    GovernanceTelemetry,
    GovernanceUnavailable,
    IntentProvenance,
    PlanResult,
    PreflightResult,
    WatchlightError,
    get_logger,
    governance_mode,
    require_manifest,
    resolve_intent_enforcement_mode,
    should_inject_synthetic_tool,
    load_default_credential,
    wire_intent,
)

from .synthetic_intent_tool import (
    build_synthetic_action_group_schema,
    clear_session_declared_intent,
    get_session_declared_intent,
    handle_synthetic_bedrock_invocation,
    is_synthetic_bedrock_event,
)
from .agent_runtime import install_unwrapped_call_guard
from .traces import translate_bedrock_trace

logger = get_logger("watchlight_bedrock")


# ─── intent_objective extraction helpers ─────────────────────────────


# Tag stamped on the ``execution_started`` event's ``metadata.source``
# field so audit replay can distinguish plugin-derived intent from
# customer-declared intent without re-parsing the payload. Mirrors the
# convention used by ``_QUARANTINE_PROVENANCE_TAG`` in watchlight_core's
# BaseRunHandle.
_INTENT_PROVENANCE_TAG = "watchlight_bedrock.plugin.intent_extraction"


def _normalize_intent_objective(text: Optional[str]) -> Optional[str]:
    """Byte-safe truncate an extracted prompt to
    :data:`INTENT_OBJECTIVE_MAX_BYTES`.

    The canonical event schema caps ``intent_objective`` at 256 UTF-8
    bytes (see :data:`watchlight_core.INTENT_OBJECTIVE_MAX_BYTES`).
    The Pydantic validator rejects oversize values; we MUST truncate
    on the boundary BEFORE constructing the payload — otherwise a
    long Bedrock ``inputText`` would crash the
    :func:`watchlight_bedrock_action` decorator on a real Lambda
    invocation.

    Semantics:

    - ``None`` or empty (after strip) → ``None``. The caller maps
      ``None`` to :attr:`IntentProvenance.ABSENT`.
    - String shorter than the cap → returned unchanged (after strip).
    - String over the cap → truncated to the largest prefix whose
      UTF-8 encoding fits within the cap, without splitting a
      codepoint. ``"✓✓✓..." * N`` (3 bytes per char) never returns a
      string whose final byte is a continuation byte; we encode and
      decode-with-errors=ignore so the truncation lands on a
      character boundary.

    PII scrubbing of the extracted objective is deferred to a future
    release — this helper's deliverable is byte-truncation only, the
    same posture the canonical Pydantic validator enforces on declared
    intent today.
    """
    if text is None:
        return None
    cleaned = text.strip()
    if not cleaned:
        return None
    encoded = cleaned.encode("utf-8")
    if len(encoded) <= INTENT_OBJECTIVE_MAX_BYTES:
        return cleaned
    # Truncate on a UTF-8 codepoint boundary. `decode(..., errors="ignore")`
    # silently drops any incomplete trailing codepoint, which is exactly
    # the boundary-safety semantics we need — never emit a string whose
    # final byte is a continuation byte.
    return encoded[:INTENT_OBJECTIVE_MAX_BYTES].decode("utf-8", errors="ignore")


def _resolve_intent_provenance(
    normalized_objective: Optional[str],
    explicit_provenance: Optional[IntentProvenance],
) -> IntentProvenance:
    """Pick the :class:`IntentProvenance` enum to emit on
    ``execution_started``.

    Rules (matches the Pydantic invariant in
    :class:`watchlight_core.events_schema.ExecutionStartedPayload` —
    ``intent_objective is not None ⇒ provenance is set AND not
    ABSENT``):

    1. If the caller passed an explicit non-Absent
       :class:`IntentProvenance`, use it verbatim. Forwarding allows
       the orchestrator-side path (where the customer declared the
       intent) to stamp ``DECLARED`` directly.
    2. Caller passed :attr:`IntentProvenance.ABSENT` explicitly →
       respect it even if an objective was provided. (The objective
       would be dropped by that same invariant; the helper does NOT
       silently override the operator's choice.)
    3. Non-empty normalised objective and no explicit provenance →
       :attr:`IntentProvenance.PLUGIN_DERIVED`. This is the Lambda
       decorator's canonical case: the plugin extracted the prompt
       from ``event["inputText"]`` and we attribute it to that
       extraction source.
    4. No objective → :attr:`IntentProvenance.ABSENT`.
    """
    if explicit_provenance is not None:
        return explicit_provenance
    if normalized_objective:
        return IntentProvenance.PLUGIN_DERIVED
    return IntentProvenance.ABSENT


async def _emit_execution_started_event(
    *,
    plugin: "WatchlightBedrockPlugin",
    agent_uuid: str,
    session_id: str,
    execution_id: Optional[str],
    run: Optional[RunRef],
    intent_objective: Optional[str],
    intent_provenance: IntentProvenance,
) -> None:
    """Publish an ``execution_started`` canonical event carrying the
    intent fields.

    Mirrors the wire shape that wl-execution-graph expects — see the
    Pydantic mirror at
    :class:`watchlight_core.events_schema.ExecutionStartedPayload`.
    The plugin only emits this event when intent context is present
    (provenance != ABSENT OR an objective was set); sessions without
    intent stay silent so APDP and the dashboard don't see a new
    event-per-session that they would otherwise have ignored.

    Best-effort: an APDP transport failure is logged at debug and
    never raises. Observability MUST NOT break the customer's
    session-open path.
    """
    # Skip the emission entirely on the no-intent case. Sessions
    # without intent emit no ``execution_started`` from this plugin, so
    # holding that silent posture for ABSENT-with-no-objective keeps
    # the audit log free of an empty-intent stream when the customer
    # opted out of intent propagation.
    if intent_objective is None and intent_provenance == IntentProvenance.ABSENT:
        return

    timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    payload: Dict[str, Any] = {
        "principal": {"principal_type": "agent", "id": agent_uuid},
        # ROOT emitter — depth 0 by definition, NOT a hardcoded sub-agent
        # value. This is the sole ``execution_started`` this plugin emits,
        # fired once at session-open for the top-level Bedrock agent (the
        # Lambda action-group entry). Bedrock collaborator sub-agents are
        # native to Bedrock's multi-agent orchestration; they are not
        # routed through the governed ``spawn_subagent`` chokepoint, so
        # they never flow through this path and no sub-agent depth is ever
        # a literal here.
        "depth": 0,
    }
    if intent_objective is not None:
        payload["intent_objective"] = intent_objective
    # Always stamp the provenance enum on the wire so Cedar reads a
    # typed value rather than relying on the legacy null-as-absent
    # convention. The string form of the enum is the wire value
    # (snake_case per :class:`IntentProvenance`).
    payload["intent_provenance"] = intent_provenance.value

    # Execution-lineage integrity — adopt the SERVER-minted canonical
    # ``execution_id`` (from ``create_session``) instead of
    # self-minting, and emit under the run (the backend authenticates
    # with the run's own ``sst_`` credential). Without both, wl-apdp's ``/v1/events``
    # identity-binding gate REFUSES the event (the credential's ``eid``
    # would not match a self-minted id).
    event: Dict[str, Any] = {
        "event_id": f"evt_{uuid.uuid4()}",
        "event_type": "execution_started",
        "timestamp": timestamp,
        "execution_id": execution_id or f"exec_{uuid.uuid4()}",
        "agent_id": agent_uuid,
        "session_id": session_id,
        "tenant_id": getattr(plugin, "tenant_id", None),
        "metadata": {"source": _INTENT_PROVENANCE_TAG},
        "payload": payload,
    }
    try:
        await plugin.apdp.publish_events(run, [event])
    except Exception:  # noqa: BLE001 — observability is best-effort
        logger.debug(
            "execution_started event emission failed (intent_provenance=%s)",
            intent_provenance.value,
            exc_info=True,
        )


# ─── Plugin ──────────────────────────────────────────────────────────


class WatchlightBedrockPlugin(GovernanceTelemetry):
    """Governance plugin for AWS Bedrock Agents.

    Usage (orchestrator side)::

        wl = WatchlightBedrockPlugin(apdp_url="https://wl-apdp.example.com")

        async def run_research(question: str) -> dict:
            async with await wl.start_run("research-analyst") as handle:
                if outline:
                    result = await handle.submit_plan(outline)
                    if result.is_deny():
                        raise PermissionError(result.violations)

                agents = handle.bedrock_agent_runtime(
                    boto3.client("bedrock-agent-runtime"),
                    agent_client=boto3.client("bedrock-agent"),
                )
                response = await agents.invoke_agent(
                    agentId=...,
                    agentAliasId=...,
                    sessionId=handle.session_id,
                    inputText=question,
                )
                return _consume(response)

    Args:
        apdp_url: WL-APDP endpoint (default ``http://localhost:8081``).
        tenant_id: Multi-tenant scope identifier.
        apdp_api_key: Optional API key for APDP authentication.
        log_decisions: Log Allow/Deny decisions to stdout.
        otlp_exporter: Optional OTLP exporter for customer observability.
        connect_proxy_url: wl-proxy CONNECT sidecar URL. ``None`` disables.
        intent_enforcement_mode: Operator opt-in for greenfield
            intent enforcement. When ``"greenfield"`` (or env
            ``WATCHLIGHT_INTENT_ENFORCEMENT_MODE=greenfield``), the
            plugin surfaces :meth:`synthetic_action_group_schema` for
            the operator to add the Watchlight-managed action group to
            the Bedrock Agent at setup time (one-line IaC opt-in —
            Bedrock's tool surface is server-side and cannot be
            runtime-mutated). The Lambda decorator then auto-intercepts
            calls to the synthetic action group without round-tripping
            to APDP (the synthetic-tool carve-out). Brownfield (the
            default) keeps the Bedrock Agent surface untouched. The
            locked default is brownfield.
    """

    #: The plugin gates provider-hosted tools before every model call
    #: (``bedrock_runtime``) and every agent invocation
    #: (``bedrock_agent_runtime``). Conformance invariant 19.
    supports_hosted_tools = True
    hosted_tool_provider = "bedrock"

    def __init__(
        self,
        apdp_url: str = "http://localhost:8081",
        tenant_id: Optional[str] = None,
        apdp_api_key: Optional[str] = None,
        log_decisions: bool = True,
        otlp_exporter: Optional[Any] = None,
        connect_proxy_url: Optional[str] = None,
        intent_enforcement_mode: Optional[str] = None,
        application_id: Optional[str] = None,
    ):
        # GovernanceTelemetry.__init__ initialises the seven last_* attrs.
        super().__init__()
        # A bedrock-agent-runtime client nobody wrapped is refused too:
        # agent, flow, model and retrieval operations go through only when
        # bedrock_agent_runtime() makes them.
        install_unwrapped_call_guard()
        # With no key, load the default Watchlight credential. A
        # configured credential that cannot be loaded raises here; with
        # nothing configured the client runs unauthenticated and the server
        # refuses it.
        credential = load_default_credential("watchlight_bedrock") if apdp_api_key is None else None
        if credential is not None:
            self.apdp = ApdpClient(apdp_url, credential=credential)
        else:
            self.apdp = ApdpClient(apdp_url, api_key=apdp_api_key)
        self.tenant_id = tenant_id
        self.log_decisions = log_decisions
        # Optional OTLP exporter — opt-in customer observability.
        # Bedrock-flavoured `RunHandle.publish_trace()` reads this off
        # the plugin and routes translated events through it after the
        # APDP publish completes.
        self.otlp = otlp_exporter
        # wl-proxy CONNECT mode. When set AND wl-apdp issues a
        # proxy_token for the session, the plugin auto-installs the
        # local sidecar CONNECT proxy in `start_run`. From that point
        # on, EVERY Python HTTP library that honors `HTTPS_PROXY` —
        # including boto3 (via botocore via urllib3), requests, and
        # httpx — auto-routes its outbound HTTPS through wl-proxy
        # with `Proxy-Authorization: Bearer <token>`. **Zero customer
        # agent-code touches.** Env-var fallback: `WATCHLIGHT_PROXY_URL`.
        # `None` (default): CONNECT mode OFF; outbound HTTPS goes
        # direct, same posture as before.
        import os as _os
        self.connect_proxy_url = connect_proxy_url or _os.getenv(
            "WATCHLIGHT_PROXY_URL"
        )
        # AI application attribution. The application every run
        # opened by this plugin belongs to; forwarded on session create
        # so wl-apdp binds it to the run credential. Explicit
        # configuration only — never inferred from prompts or names.
        # ``start_run(application_id=...)`` overrides per run. Env
        # fallback: ``WATCHLIGHT_APPLICATION_ID``. ``None`` / empty /
        # whitespace ⇒ unset, the field is not sent. A non-UUID raises
        # ``ValueError`` here (client-side format check only — wl-apdp
        # stays the authority on membership).
        self.application_id = (
            resolve_application_id(application_id) or application_id_from_env()
        )
        # Kill-signal registry. Defaults ON: in-process cancellation
        # is free until an interceptor registers a request, whereas
        # leaving it unwired makes the BaseRunHandle quarantine
        # transition a SILENT no-op. Proxy-side hard-kill escalation
        # stays opt-in — assign a registry built with
        # ``httpx_hard_kill_escalator`` to enable it. Set to ``None``
        # to disable interruption entirely.
        from watchlight_core import default_kill_signal_registry

        self.kill_signal_registry = default_kill_signal_registry()

        # Intent-enforcement mode resolution. Reads the
        # constructor kwarg first, then the
        # ``WATCHLIGHT_INTENT_ENFORCEMENT_MODE`` env var, then falls
        # back to the locked ``"brownfield"`` default. Resolved ONCE
        # at construction so the synthetic-action-group decision is
        # stable across the plugin's lifetime; operators don't get to
        # flip modes mid-run.
        #
        # Bedrock's tool surface is server-side (configured on the
        # Bedrock Agent resource via AWS), not in-process. The plugin
        # exposes ``synthetic_action_group_schema()`` for operators to
        # consume at agent setup time — a one-line opt-in that Bedrock's
        # server-side tool model requires.
        self.intent_enforcement_mode = resolve_intent_enforcement_mode(
            explicit=intent_enforcement_mode
        )

    # ─── synthetic action-group surface ──────────────────────────────

    def synthetic_action_group_schema(self) -> Optional[Dict[str, Any]]:
        """Return the AWS-shape dict the operator splats into
        ``bedrock-agent.create_agent_action_group(...)`` to wire the
        synthetic ``watchlight.declare_intent`` tool onto a Bedrock
        Agent.

        Returns ``None`` in brownfield mode — the operator's IaC can
        use the truthy-check to skip the action-group creation
        entirely when the deployment defaults to brownfield. In
        greenfield mode the dict carries:

        - ``actionGroupName`` — :data:`SYNTHETIC_ACTION_GROUP_NAME`
          (``"watchlight_intent"``)
        - ``description`` — operator-facing description
        - ``functionSchema`` — exactly one function (``declare_intent``)
          carrying the canonical
          :data:`watchlight_core.WATCHLIGHT_DECLARE_INTENT_TOOL`
          shape
        - ``actionGroupState`` — ``"ENABLED"``

        This is the **one-line opt-in** that lets Bedrock surface the
        synthetic tool to the LLM. Bedrock's tool surface is
        server-side (configured on the Bedrock Agent resource), so the
        plugin cannot mutate it at runtime; the operator wires the
        action group ONCE at agent setup time (IaC / boto3 /
        CloudFormation / Terraform). From that point on, ZERO customer
        agent-code touches — the plugin's
        :func:`watchlight_bedrock_action` decorator detects calls to
        the synthetic action group via
        :func:`is_synthetic_bedrock_event` and processes them inline
        (the synthetic-tool carve-out).

        Honest architectural note: this is a partial zero-touch — the
        operator's first-time setup needs one line of IaC. Bedrock's
        structural model does not support runtime action-group
        injection.
        """
        return build_synthetic_action_group_schema(
            mode=self.intent_enforcement_mode
        )

    async def start_run(
        self,
        agent_slug: str,
        goal_id: Optional[str] = None,
        max_actions: Optional[int] = None,
        ttl_seconds: int = 3600,
        intent_objective: Optional[str] = None,
        intent_provenance: Optional[IntentProvenance] = None,
        application_id: Optional[str] = None,
    ) -> "RunHandle":
        """Open a governed run for the named agent.

        Resolves the slug to a UUID via ``/agents/resolve``, opens an
        APDP session, fetches the constraint manifest. Returns a
        :class:`RunHandle` carrying the Bedrock session-attributes
        helper.

        ``application_id``: the AI application this run belongs to.
        wl-apdp checks the agent is a member of it and refuses
        the session otherwise; an agent in exactly one application needs
        nothing here. Defaults to the plugin-level ``application_id``
        (constructor kwarg, else ``WATCHLIGHT_APPLICATION_ID``). The
        application is bound to the run credential and to every
        sub-agent the run spawns.

        Fail-closed:
          - Unknown slug → raises :class:`AgentNotRegistered`
          - APDP unreachable → raises :class:`GovernanceUnavailable`

        **intent_objective propagation**: when the caller
        passes a non-empty ``intent_objective``, the plugin emits an
        ``execution_started`` canonical event carrying the truncated
        objective and the :class:`IntentProvenance` enum. ``None``
        ``intent_provenance`` is inferred:

        - non-empty ``intent_objective`` →
          :attr:`IntentProvenance.PLUGIN_DERIVED` (the
          :func:`watchlight_bedrock_action` Lambda decorator passes
          extracted ``event["inputText"]`` here; customer code that
          wants to declare intent explicitly should pass
          :attr:`IntentProvenance.DECLARED`).
        - ``None`` / empty ``intent_objective`` →
          :attr:`IntentProvenance.ABSENT`.

        Event emission is best-effort: an APDP transport failure on
        the ``execution_started`` publish is logged at debug and
        swallowed; the session itself remains live.
        """
        # Reset per-run telemetry.
        self._reset_telemetry()

        resolved = await self.apdp.resolve_agent(agent_slug)
        if resolved is None:
            raise AgentNotRegistered(
                f"Agent '{agent_slug}' is not registered with Watchlight. "
                f"Register the agent before invoking it."
            )
        agent_uuid = resolved["id"]

        # Empty / whitespace ⇒ unset (the plugin default applies); a
        # non-UUID raises before any session is opened.
        app_id = resolve_application_id(application_id) or self.application_id
        session = await self.apdp.create_session(
            agent_id=agent_uuid,
            goal_id=goal_id,
            max_actions=max_actions,
            ttl_seconds=ttl_seconds,
            metadata={"framework": "aws_bedrock", "tenant_id": self.tenant_id},
            # Only when set, so an older watchlight-agent-sdk still works.
            **({"application_id": app_id} if app_id is not None else {}),
        )
        if session is None:
            raise GovernanceUnavailable(
                "WL-APDP did not accept the session create. Check that "
                "APDP is reachable and the data plane is configured."
            )
        session_id = session.session_id
        # Server-minted ROOT run-handle id (present when wl-apdp has a
        # run-handle store). Presented on every authorize so runtime
        # Attenuate applies to the root run; ``None`` on older wl-apdp →
        # prior behaviour (client-minted id, never presented).
        root_run_handle_id = session.root_run_handle_id

        # Everything after the session create fails closed: if the run
        # cannot be set up completely (missing manifest, egress that
        # cannot be governed, or any other error, including
        # cancellation), the session it opened is closed and the
        # failure propagates. It never proceeds ungoverned.
        try:
            return await self._open_run_handle(
                agent_uuid=agent_uuid,
                session=session,
                session_id=session_id,
                goal_id=goal_id,
                root_run_handle_id=root_run_handle_id,
                intent_objective=intent_objective,
                intent_provenance=intent_provenance,
            )
        except BaseException as exc:
            try:
                await self.apdp.complete_session(session.run)
            except Exception as e:  # noqa: BLE001 — best-effort close
                logger.warning(
                    "closing refused session %s failed: %s (%s)",
                    session_id,
                    type(e).__name__,
                    type(exc).__name__,
                )
            raise

    async def _open_run_handle(
        self,
        *,
        agent_uuid: str,
        session: SessionInfo,
        session_id: str,
        goal_id: Optional[str],
        root_run_handle_id: Optional[str],
        intent_objective: Optional[str],
        intent_provenance: Any,
    ) -> "RunHandle":
        """The fail-closed tail of :meth:`start_run`: the manifest gate,
        governed egress and the handle. The caller closes the session on
        any exception raised here."""
        # The run credential bounds the manifest by the run's grant.
        manifest = await self.apdp.get_manifest(agent_uuid, goal_id=goal_id, run=session.run)
        # A missing manifest refuses the run (before any egress is set
        # up) unless the operator explicitly opted into
        # WATCHLIGHT_PLAN_GOVERNANCE_MODE=degrade.
        governance_level = require_manifest(manifest, agent_id=agent_uuid)

        # Auto-install the wl-proxy CONNECT local sidecar. The sidecar
        # uses standard HTTPS_PROXY so boto3 (botocore's urllib3 client)
        # intercepts cleanly without any boto3-specific code. **Zero
        # customer agent-code touches.**
        #
        # Fail closed: when a wl-proxy URL is configured, egress MUST go
        # through it. A session without an issued proxy token, or a
        # sidecar that fails to come up, refuses the run — it never
        # proceeds with direct egress.
        egress = egress_binding_for(self.apdp, session.run)
        if self.connect_proxy_url:
            if egress is None:
                raise GovernanceUnavailable(
                    "A wl-proxy URL is configured but WL-APDP issued no proxy "
                    "token for this session; refusing to run with direct egress."
                )
            from watchlight_core import SidecarRunActive, install_connect_proxy

            try:
                install_connect_proxy(
                    self.connect_proxy_url,
                    egress.proxy_authorization(),
                    egress=egress,
                )
            except SidecarRunActive:
                raise
            except Exception as e:  # noqa: BLE001 — any failure refuses
                raise GovernanceUnavailable(
                    "The wl-proxy CONNECT sidecar could not be installed "
                    f"({type(e).__name__}); refusing to run with direct egress."
                ) from None

        # Bedrock has no plan-time hook (planning is opaque); a
        # successful handle.submit_plan() keeps the run "strong".
        self.last_governance_mode = governance_level
        self.last_session_id = session_id
        self.last_manifest = manifest

        if self.log_decisions:
            logger.info(
                "[GOVERNANCE-MODE] %s — session=%s manifest=%s agent=%s",
                self.last_governance_mode,
                session_id,
                bool(manifest),
                agent_uuid,
            )

        handle = RunHandle(
            plugin=self,
            agent_uuid=agent_uuid,
            session_id=session_id,
            run_handle_id=root_run_handle_id,
            server_run_handle=root_run_handle_id is not None,
            # Execution-lineage integrity — the run (its per-run `sst_`
            # credential stays in the backend), its egress binding, and
            # the server-minted canonical `execution_id` so emitted events
            # match the run the credential authenticates.
            run=session.run,
            egress=egress,
            execution_id=session.execution_id,
        )

        # intent_objective propagation. Truncate the caller-supplied
        # objective on the UTF-8 byte boundary (256 bytes per the
        # canonical schema), infer the provenance when not given,
        # and emit an ``execution_started`` canonical event carrying
        # both. Best-effort: an APDP transport failure on this publish
        # is logged at debug and never propagates — the session is
        # already open and the intent payload is observability data,
        # not a control-plane gate.
        normalized_objective = _normalize_intent_objective(intent_objective)
        resolved_provenance = _resolve_intent_provenance(
            normalized_objective, intent_provenance
        )
        await _emit_execution_started_event(
            plugin=self,
            agent_uuid=agent_uuid,
            session_id=session_id,
            # Execution-lineage integrity — emit under the run's
            # SERVER-minted execution_id + its own `sst_` credential so the
            # event passes wl-apdp's `/v1/events` identity-binding gate.
            execution_id=handle.execution_id,
            run=handle.run,
            intent_objective=normalized_objective,
            intent_provenance=resolved_provenance,
        )

        return handle


    async def conformance_hosted_tool_call(self, probe: Any) -> None:
        """Invariant 19: one governed model call of ``probe.request``
        through the gate every ``bedrock_runtime`` model call uses."""
        from .runtime import gate_hosted_request

        turn = await gate_hosted_request(
            probe.wrap(_ConformanceHandle()),
            probe.request,
            provider=self.hosted_tool_provider,
            registered_mcp_servers=probe.registered_mcp_servers,
            timeout_seconds=None,
        )
        await probe.model_client.call(probe.request)
        turn.seal()


class _ConformanceHandle:
    """The run the conformance probe wraps: the probe answers every
    hosted-tool decision, so any other call is a failure."""

    async def authorize_action_detailed(self, *args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("the conformance probe answers hosted-tool decisions only")


# ─── RunHandle ────────────────────────────────────────────────────────


class RunHandle(BaseRunHandle):
    """Bedrock-flavoured run handle.

    Inherits the lifecycle (``submit_plan``, ``preflight_step``,
    ``authorize_action``, ``complete``, ``terminate``, async context
    manager) from :class:`watchlight_core.BaseRunHandle`. Adds two
    Bedrock-specific helpers:

    1. :meth:`bedrock_agent_runtime` — the governed
       ``invoke_agent``: hosted capabilities are authorized before the
       call, and the APDP session is propagated into the Bedrock
       orchestrator → Lambda action-group boundary.
    2. :meth:`publish_trace` — translates the ``InvokeAgent``
       response's ``agentTrace`` into canonical
       :class:`ExecutionEvent` payloads and publishes them via
       APDP for downstream observability.

    Provenance: ad-hoc observation events emitted via
    :meth:`watchlight_core.BaseRunHandle.publish_observation` carry
    ``metadata.source = "bedrock.workload"`` via the per-class
    :attr:`_observation_source` override below.
    """

    #: Provenance tag stamped on every ad-hoc observation event emitted
    #: via :meth:`watchlight_core.BaseRunHandle.publish_observation`.
    #: Identifies Bedrock workloads on the canonical event stream.
    _observation_source = "bedrock.workload"

    def _bedrock_session_attributes(self) -> Dict[str, str]:
        """The dict :meth:`bedrock_agent_runtime` adds under
        ``sessionState.sessionAttributes`` on ``invoke_agent``. Internal:
        a raw ``invoke_agent`` call is not governed.

        Carries the Watchlight session+agent IDs across the AWS
        boundary so action-group Lambdas can reuse the same APDP
        session via the :func:`watchlight_bedrock_action` decorator.
        """
        return {
            "watchlight_session_id": self.session_id,
            "watchlight_agent_id": self.agent_uuid,
        }

    def bedrock_agent_runtime(
        self, client: Any, *, agent_client: Any, **kwargs: Any
    ) -> "GovernedBedrockAgentRuntime":
        """Govern a boto3 ``bedrock-agent-runtime`` client on this run:
        ``invoke_agent`` and ``invoke_inline_agent`` are made only
        after every hosted capability the agent enables (code interpreter,
        user input, computer, bash, text editor, knowledge bases) is
        allowed. ``agent_client`` is a boto3 ``bedrock-agent`` client used
        to read agent definitions. This is the only supported way to
        invoke a Bedrock agent under governance. ``kwargs`` go to
        :class:`~watchlight_bedrock.agent_runtime.GovernedBedrockAgentRuntime`."""
        from .agent_runtime import GovernedBedrockAgentRuntime

        return GovernedBedrockAgentRuntime(client, self, agent_client=agent_client, **kwargs)

    def bedrock_runtime(self, client: Any, **kwargs: Any) -> "GovernedBedrockRuntime":
        """Govern a boto3 ``bedrock-runtime`` client on this run:
        Converse, ConverseStream and InvokeModel tool use outside Bedrock
        Agents. ``kwargs`` go to
        :class:`~watchlight_bedrock.runtime.GovernedBedrockRuntime`."""
        from .runtime import GovernedBedrockRuntime

        return GovernedBedrockRuntime(client, self, **kwargs)

    def _bedrock_collaborator_session_attributes(self) -> Dict[str, str]:
        """Session attributes for invoking a Bedrock multi-agent
        COLLABORATOR under this run (cross-process pattern).

        A collaborator is a separate Bedrock agent in its own Lambda; the
        orchestrator cannot govern it in-process. This threads a
        NON-SENSITIVE reference to this run across the Bedrock boundary via
        ``sessionState.sessionAttributes`` so the collaborator's Lambda can
        identify its parent run (see :mod:`watchlight_bedrock.collaborator`).
        Internal: ``bedrock_agent_runtime().invoke_agent(collaborator=True)``
        adds it.

        Superset of :meth:`_bedrock_session_attributes`: it adds
        :data:`~watchlight_bedrock.collaborator.SESSION_ATTR_PARENT_RUN_HANDLE_ID`
        — the parent run-handle id, a non-sensitive identifier that cannot
        authenticate anything on its own.

        Security — NO credential crosses the boundary. wl-apdp authenticates
        ``POST /v1/spawn_subagent`` with the parent run's ``sst_``
        credential, but this method deliberately does **not** place that
        (or any) credential into session attributes: routing a run
        credential through the AWS control plane (CloudTrail-visible) is
        below our security bar. Consequently a *governed* cross-process
        spawn is not possible today — it is deferred to a forthcoming
        single-use, spawn-only, short-TTL spawn-authorization token
        (wl-apdp endpoint). Until then Bedrock collaborators are
        governed at the ACTION layer only (per-invocation
        trust + tool PEP via :func:`watchlight_bedrock_action`), NOT
        spawn-scope-attenuated, and the orchestrator does not fabricate a
        spawn. See the plugin README's "Multi-agent collaborators" section.
        """
        # Local import avoids a module-load cycle (collaborator imports
        # nothing from plugin at module load; this method imports the key
        # constant eagerly only at call time).
        from .collaborator import SESSION_ATTR_PARENT_RUN_HANDLE_ID

        attrs = self._bedrock_session_attributes()
        attrs[SESSION_ATTR_PARENT_RUN_HANDLE_ID] = self.run_handle_id
        return attrs

    async def publish_trace(
        self,
        bedrock_response: Dict[str, Any],
        *,
        execution_id: Optional[str] = None,
        parent_execution_id: Optional[str] = None,
        root_execution_id: Optional[str] = None,
    ) -> int:
        """Translate the Bedrock ``InvokeAgent`` response's
        ``agentTrace`` payload into canonical ``ExecutionEvent``
        dicts and publish them via APDP for downstream observability
        (drift detection, dashboards, SIEM export).

        Args:
            bedrock_response: The dict returned by
                ``bedrock-agent-runtime.invoke_agent``. For streaming
                responses, the caller is responsible for collecting
                the ``EventStream`` chunks into ``response["completion"]``
                before invoking this method.
            execution_id: Watchlight execution id to attribute the
                events to. Defaults to this handle's SERVER-minted
                ``execution_id`` (from ``create_session``) so emitted
                events match the run its ``sst_`` credential
                authenticates; pass an explicit value only to correlate
                with a different execution id.
            parent_execution_id: For nested runs (agent spawned by
                a parent agent), the parent's execution id.
            root_execution_id: The workflow root's execution id, used
                for lineage linkage. When the caller spawned this
                Bedrock agent under an orchestrator, pass the
                orchestrator's root execution id here so every event
                the Bedrock invocation emits stitches into the same
                lineage tree in ``wl-execution-graph``. Mirrors
                LangGraph's ``spawn_subagent`` propagation pattern.
                Optional (top-level Bedrock runs are their own root).

        Returns:
            Number of events successfully emitted (``>= 0``). Zero
            indicates either the response carried no trace data
            (likely ``enableTrace`` was not set on the
            ``invoke_agent`` call) or the publish failed
            (transport error, APDP unreachable — logged at debug).

        Never raises. This method is best-effort lineage telemetry,
        not a control-plane operation. Failures must not block the
        caller's success path.

        Typical usage::

            async with await wl.start_run(slug) as handle:
                agents = handle.bedrock_agent_runtime(runtime_client, agent_client=agent_client)
                response = await agents.invoke_agent(
                    agentId=...,
                    agentAliasId=...,
                    enableTrace=True,  # required: traces are off by default
                    ...
                )
                # ... consume the streaming response ...
                await handle.publish_trace(response)
        """
        # Execution-lineage integrity — default to the run's
        # SERVER-minted ``execution_id`` (never a self-minted
        # ``exec_<uuid>`` that the credential's ``eid`` wouldn't match) and
        # authenticate the emit with the run's own ``sst_`` credential.
        # Without both, wl-apdp's ``/v1/events`` identity-binding gate
        # REFUSES the batch.
        exec_id = execution_id or self.execution_id or f"exec_{uuid.uuid4()}"
        tenant_id = getattr(self._plugin, "tenant_id", None)
        events = translate_bedrock_trace(
            response=bedrock_response,
            execution_id=exec_id,
            agent_id=self.agent_uuid,
            session_id=self.session_id,
            tenant_id=tenant_id,
            parent_execution_id=parent_execution_id,
            root_execution_id=root_execution_id,
        )
        if not events:
            return 0
        try:
            ok = await self._plugin.apdp.publish_events(self.run, events)
        except Exception as exc:  # noqa: BLE001 - best-effort lineage
            logger.debug("publish_trace failed: %s", exc)
            return 0
        # Optional OTLP export — runs only if customer wired an exporter
        # on the plugin. OTLP failure does not affect the APDP-publish
        # outcome we report back. Same partitioning rules as langgraph
        # + adk: tool args / prompts / drift baselines / raw ABR are
        # already absent from the canonical event shape, so the exporter
        # sees a sanitized stream and the redactor in watchlight_core.otlp
        # is the final defense.
        otlp = getattr(self._plugin, "otlp", None)
        if otlp is not None:
            try:
                otlp.export_events(events)
            except Exception as exc:  # noqa: BLE001
                logger.debug("publish_trace OTLP export failed: %s", exc)
        return len(events) if ok else 0


# ─── Lambda action-group decorator ────────────────────────────────────


def watchlight_bedrock_action(
    *,
    apdp_url: Optional[str] = None,
    tenant_id: Optional[str] = None,
    apdp_api_key: Optional[str] = None,
    fallback_agent_slug: Optional[str] = None,
    fallback_allowed_actions: Optional[Sequence[str]] = None,
):
    """Decorator that enforces WL-APDP ``/authorize`` on a Bedrock
    action-group Lambda.

    Wrap your Lambda handler::

        @watchlight_bedrock_action(apdp_url=os.environ["APDP_URL"])
        def lambda_handler(event, context):
            return _do_real_work(event)

    Behavior on each invocation:

    1. Parse Bedrock event for ``actionGroup``, ``apiPath``,
       ``httpMethod``, ``sessionAttributes``, ``parameters``.
    2. Read the Watchlight attributes from ``sessionAttributes``.
       An orchestrator hand-off (``watchlight_session_id`` /
       ``watchlight_agent_id``, set by
       :meth:`RunHandle.bedrock_agent_runtime`) carries no run
       credential across the AWS boundary, so it is **refused** until a
       scoped hand-off token exists. Any Watchlight parent reference —
       complete or partial — is never replaced by a fresh root. Only an
       invocation with NO Watchlight attributes may use the fallback root
       (``fallback_agent_slug``), and only for actions listed in
       ``fallback_allowed_actions``.
    3. Call APDP ``/authorize`` with action ``{actionGroup}/{apiPath}``,
       resource ``Resource::"bedrock://..."``, context carrying the
       Bedrock parameters.
    4. **Allow** → invoke the wrapped function, return its response.
       **Deny** → return a Bedrock-shaped 403 response without
       invoking the wrapped function. **Transport failure** →
       fail-closed (deny).

    ``fallback_agent_slug`` opens a fresh root run for the named agent
    for each invocation (no plan, no budget tracking across calls) and
    closes it when the invocation ends. It requires an explicit
    ``fallback_allowed_actions`` scope — the ``"{actionGroup}/{apiPath}"``
    names this Lambda may serve under that root (``apiPath`` without its
    leading slash). An action outside that scope is refused before any
    session opens; an action inside it is still decided by WL-APDP.
    Passing ``fallback_agent_slug`` without a non-empty scope raises
    :class:`ValueError` at decoration time.

    The decorator caches the :class:`WatchlightBedrockPlugin` across
    Lambda warm starts via a module-level dict, so APDP connection
    state (httpx client, manifest cache) is reused.
    """
    base_url = apdp_url or os.environ.get("APDP_URL", "http://localhost:8081")
    fallback_scope: Optional[frozenset] = None
    if fallback_agent_slug:
        if isinstance(fallback_allowed_actions, str) or not fallback_allowed_actions:
            raise ValueError(
                "fallback_agent_slug requires an explicit, non-empty "
                "fallback_allowed_actions list (\"{actionGroup}/{apiPath}\" "
                "names). A fallback root without an explicit scope is refused."
            )
        fallback_scope = frozenset(str(a) for a in fallback_allowed_actions)

    def decorator(fn: Callable) -> Callable:
        @functools.wraps(fn)
        def wrapper(event: dict, context: Any = None):
            # ─── synthetic ``watchlight.declare_intent`` short-circuit ──
            # Synthetic-tool carve-out: when the Bedrock invocation
            # targets the synthetic action group, process the call
            # BEFORE the APDP ``/authorize`` round-trip. In greenfield
            # mode the Cedar policy forbids Custodial actions until the
            # session has declared intent (``provenance == "declared"``);
            # the agent's first ``declare_intent`` call would otherwise
            # be denied before it could declare.
            #
            # The synthetic-tool handler:
            #   1. Extracts the ``objective`` argument from the
            #      Bedrock event (function-style ``parameters`` OR
            #      REST-style ``requestBody``).
            #   2. Stamps the truncated objective on the warm-start
            #      session cache so the NEXT non-synthetic Lambda
            #      invocation against the same session auto-injects
            #      ``intent={"objective": ...}`` into its APDP
            #      ``/authorize`` request body.
            #   3. Returns the Bedrock-shaped ``intent_declared``
            #      response which Bedrock surfaces back into the
            #      agent's reasoning trace.
            #
            # The customer's wrapped ``fn`` is NEVER invoked for a
            # synthetic-tool call — Bedrock will route the LLM's
            # ``watchlight_intent/declare_intent`` invocation to the
            # action group, but the customer's Lambda body (which only
            # handles real tools) is bypassed. Operators using the
            # ``actionGroupExecutor.lambda`` model can stand up the
            # synthetic action group's executor with
            # :func:`render_synthetic_lambda_handler` from
            # ``synthetic_intent_tool``, which itself just calls
            # :func:`handle_synthetic_bedrock_invocation`.
            if is_synthetic_bedrock_event(event):
                try:
                    return handle_synthetic_bedrock_invocation(event)
                except Exception as e:  # noqa: BLE001 — synthetic
                    # tool MUST NOT crash the Lambda. Surface a
                    # canonical "rejected" payload instead so the
                    # agent can retry; the audit trail still captures
                    # the failure via the operator's CloudWatch lane.
                    logger.exception(
                        "synthetic declare_intent handler raised; "
                        "returning rejected payload: %s",
                        e,
                    )
                    return _bedrock_deny_response(
                        event,
                        f"Synthetic declare_intent handler error: "
                        f"{type(e).__name__}",
                        http_status=500,
                    )

            try:
                authorized, deny_response, finalize = _enforce_authz(
                    event=event,
                    apdp_url=base_url,
                    tenant_id=tenant_id,
                    apdp_api_key=apdp_api_key,
                    fallback_agent_slug=fallback_agent_slug,
                    fallback_allowed_actions=fallback_scope,
                )
            except Exception as e:  # noqa: BLE001 — fail-closed wrapper
                logger.exception("watchlight enforcement raised; failing closed: %s", e)
                return _bedrock_deny_response(
                    event,
                    f"Watchlight enforcement error: {type(e).__name__}",
                    http_status=500,
                )
            try:
                if not authorized:
                    return deny_response
                return fn(event, context)
            finally:
                if finalize is not None:
                    finalize()

        return wrapper

    return decorator


_PLUGIN_CACHE: Dict[str, WatchlightBedrockPlugin] = {}


def _get_cached_plugin(
    apdp_url: str, tenant_id: Optional[str], apdp_api_key: Optional[str]
) -> WatchlightBedrockPlugin:
    """Reuse a plugin instance across Lambda warm starts.

    Cache key includes ``apdp_url + tenant_id`` so a misconfigured
    Lambda flipping between two APDP backends doesn't accidentally
    serve cached sessions to the wrong one.
    """
    key = f"{apdp_url}|{tenant_id or ''}"
    if key not in _PLUGIN_CACHE:
        _PLUGIN_CACHE[key] = WatchlightBedrockPlugin(
            apdp_url=apdp_url,
            tenant_id=tenant_id,
            apdp_api_key=apdp_api_key,
            log_decisions=True,
        )
    return _PLUGIN_CACHE[key]


_WATCHLIGHT_ATTR_PREFIX = "watchlight_"


def _enforce_authz(
    event: dict,
    apdp_url: str,
    tenant_id: Optional[str],
    apdp_api_key: Optional[str],
    fallback_agent_slug: Optional[str],
    fallback_allowed_actions: Optional[frozenset] = None,
) -> Tuple[bool, Optional[dict], Optional[Callable[[], None]]]:
    """Returns ``(authorized, deny_response, finalize)``.

    On Deny, ``deny_response`` is the Bedrock-formatted 403 the Lambda
    should return verbatim. ``finalize`` (when not ``None``) closes the
    fallback root this invocation opened; the decorator calls it once the
    invocation ends, whether the call was allowed or denied.

    Fail-closed rules:

    * Any Watchlight attribute in ``sessionAttributes`` means a parent
      run handed this invocation off. That hand-off carries no run
      credential across the AWS boundary, so it is refused — and it is
      NEVER replaced by a fresh root (a collaborator must not run as a
      full-scope root of its own).
    * Only an invocation with no Watchlight attributes may open the
      fallback root, and only for an action in the explicit
      ``fallback_allowed_actions`` scope.
    """
    parsed = parse_bedrock_event(event)
    session_attrs = parsed["session_attributes"]
    action_name = f"{parsed['action_group']}/{parsed['api_path'].lstrip('/')}"
    finalize: Optional[Callable[[], None]] = None

    handoff_keys = sorted(
        str(k)
        for k in session_attrs
        if str(k).startswith(_WATCHLIGHT_ATTR_PREFIX)
        and session_attrs.get(k) not in (None, "")
    )
    if handoff_keys:
        from .collaborator import SESSION_ATTR_PARENT_RUN_HANDLE_ID

        if SESSION_ATTR_PARENT_RUN_HANDLE_ID in handoff_keys:
            reason = (
                "This invocation is a collaborator of a governed Watchlight "
                "run. A governed cross-process spawn is not available yet, so "
                "the collaborator is refused rather than run as an "
                "unattenuated root."
            )
        else:
            reason = (
                "This invocation carries a Watchlight run hand-off, but no run "
                "credential crosses the Bedrock boundary, so it cannot act "
                "under that run. Refusing the tool call."
            )
        return False, _bedrock_deny_response(event, reason), None

    if not fallback_agent_slug:
        return False, _bedrock_deny_response(
            event,
            "Watchlight session attributes missing and no fallback root is "
            "configured (fallback_agent_slug + fallback_allowed_actions); "
            "refusing tool call.",
        ), None
    if not fallback_allowed_actions or action_name not in fallback_allowed_actions:
        return False, _bedrock_deny_response(
            event,
            f"Action {action_name!r} is outside this Lambda's fallback scope; "
            "refusing tool call.",
        ), None

    # Fresh root for this invocation, closed by ``finalize``.
    plugin = _get_cached_plugin(apdp_url, tenant_id, apdp_api_key)

    # When the Lambda decorator bootstraps a fresh session via
    # ``fallback_agent_slug``, thread the parsed
    # ``event["inputText"]`` through ``start_run`` as the
    # intent_objective. The plugin's ``start_run`` byte-truncates
    # at 256 UTF-8 bytes and stamps :attr:`IntentProvenance.PLUGIN_DERIVED`
    # on the resulting ``execution_started`` event.
    fallback_intent_objective = parsed.get("input_text") or None

    async def _bootstrap() -> Optional["RunHandle"]:
        try:
            return await plugin.start_run(
                fallback_agent_slug,
                intent_objective=fallback_intent_objective,
            )
        except (AgentNotRegistered, GovernanceUnavailable) as e:
            logger.warning("fallback start_run failed: %s", type(e).__name__)
            return None

    handle = _run(_bootstrap())
    if handle is None or not handle.session_id or not handle.agent_uuid:
        return False, _bedrock_deny_response(
            event,
            "Fallback Watchlight session bootstrap failed; refusing tool call.",
        ), None

    def _finalize() -> None:
        try:
            _run(handle.complete())
        except Exception as e:  # noqa: BLE001 — closing must not mask the result
            logger.warning(
                "closing fallback session %s failed: %s",
                handle.session_id,
                type(e).__name__,
            )

    finalize = _finalize
    session_id: str = handle.session_id
    agent_uuid: str = handle.agent_uuid
    run: Optional[RunRef] = handle.run

    try:
        authorized, deny = _authorize_on_session(
            plugin=plugin,
            event=event,
            parsed=parsed,
            action_name=action_name,
            tenant_id=tenant_id,
            session_id=session_id,
            agent_uuid=agent_uuid,
            run=run,
            execution_id=handle.execution_id,
        )
    except BaseException:
        _finalize()
        raise
    return authorized, deny, finalize


def _authorize_on_session(
    *,
    plugin: "WatchlightBedrockPlugin",
    event: dict,
    parsed: dict,
    action_name: str,
    tenant_id: Optional[str],
    session_id: str,
    agent_uuid: str,
    run: Optional[RunRef],
    execution_id: Optional[str] = None,
) -> Tuple[bool, Optional[dict]]:
    resource_uri = (
        f"bedrock://agent/{parsed['agent_id']}/action/{parsed['action_group']}"
        f"{parsed['api_path']}"
    )

    # Auto-inject the declared-intent objective into the APDP
    # ``/authorize`` request body when the agent has called
    # ``watchlight.declare_intent`` earlier in this session. The
    # session-keyed warm-start cache lives in
    # :mod:`watchlight_bedrock.synthetic_intent_tool`; the read is a
    # plain dict lookup so the authorize hot-path stays sub-millisecond.
    #
    # This is the LOAD-BEARING wire path: APDP's intent projection
    # reads ``request.intent.objective`` and stamps
    # ``provenance: "declared"`` on the Cedar context, clearing the
    # greenfield-Custodial gate. Absent declaration → ``None``
    # → projection treats the call as ``provenance: "absent"`` and
    # the gate forbids in greenfield (which is the correct
    # fail-closed behaviour).
    #
    # Honest limitation: the cache is per-Lambda-container. Cold-start
    # invocations and cross-container fan-outs lose the declaration.
    # The orchestrator-side ``handle.record_declared_intent()`` path is
    # the reliable end-to-end signal; this cache is the zero-touch
    # convenience optimisation for the warm-container case.
    declared = get_session_declared_intent(session_id) or {}
    # Typed (objective AND category) or nothing: wl-apdp answers an
    # objective-only intent with 422.
    intent_payload: Optional[Dict[str, Any]] = wire_intent(
        None, declared.get("objective"), declared.get("category"), declared.get("justification")
    )

    import uuid as _uuid

    async def _do_authz() -> dict:
        return await plugin.apdp.authorize(
            principal=f'Agent::"{agent_uuid}"',
            action=f'Action::"{action_name}"',
            resource=f'Resource::"{resource_uri}"',
            context={
                "tenant_id": tenant_id,
                "bedrock": {
                    "agent_id": parsed["agent_id"],
                    "agent_alias": parsed["agent_alias"],
                    "action_group": parsed["action_group"],
                    "api_path": parsed["api_path"],
                    "http_method": parsed["http_method"],
                    # Value-free argument metadata only: names, count and
                    # declared types. Raw values may carry secrets or PII
                    # and never reach the authorize context or audit trail.
                    "parameters": redacted_parameter_metadata(
                        parsed["parameters"]
                    ),
                },
            },
            execution_id=execution_id or f"exec_{_uuid.uuid4()}",
            session_id=session_id,
            intent=intent_payload,
            # wl-apdp binds the decision to the run only from its verified
            # credential, which the backend attaches for this run.
            run=run,
        )

    decision_payload = _run(_do_authz())
    decision = _clean_decision(decision_payload)
    if decision == "allow":
        plugin.last_actions_allowed += 1
        return True, None
    plugin.last_actions_denied += 1
    # Opaque deny: the agent sees a generic refusal; the server's reason
    # stays in its audit trail.
    reason = "Denied by Watchlight policy."
    # Bedrock action-group Lambdas bypass BaseRunHandle (they call
    # apdp.authorize directly because the lifecycle is split across
    # orchestrator + Lambda boundaries). Fire the kill signal
    # here too so an in-flight LLM call originating from the Lambda's
    # process (uncommon but possible if the customer chains an LLM
    # call inside the Lambda) is aborted on Quarantine.
    if decision == "quarantine":
        _fire_kill_signal_best_effort(plugin)
    return False, _bedrock_deny_response(event, reason)


def _clean_decision(payload: Any) -> str:
    """The lower-cased decision of an ``/authorize`` answer, or ``"deny"``
    when the answer is not a well-formed decision.

    The Lambda path reads the backend's answer itself (it bypasses
    :class:`BaseRunHandle`), so it checks the shape itself and fails
    closed: the answer must be an object whose ``decision`` is a string,
    whose ``reason`` (when present) is a string, whose ``details`` (when
    present) is an object, and which carries no ``error``. wl-apdp never
    sends an ``error`` alongside a decision; an answer that does
    contradicts itself and is treated as a deny.
    """
    if not isinstance(payload, dict):
        return "deny"
    decision = payload.get("decision")
    if not isinstance(decision, str):
        return "deny"
    if payload.get("error") is not None:
        return "deny"
    if payload.get("reason") is not None and not isinstance(payload.get("reason"), str):
        return "deny"
    if payload.get("details") is not None and not isinstance(payload.get("details"), dict):
        return "deny"
    return decision.lower()


def _fire_kill_signal_best_effort(plugin: Any) -> None:
    """Fire the plugin's kill-signal registry if one is wired.

    Bedrock's Lambda decorator is the one path that bypasses
    :class:`BaseRunHandle` (the orchestrator side uses BaseRunHandle as
    normal; the Lambda side runs in a separate process with its own
    plugin instance). The decorator must therefore invoke the kill
    signal explicitly when wl-apdp returns Quarantine.

    Best-effort — a missing registry is a no-op so this works for the
    common case (Lambda without an in-flight LLM call) without forcing
    every Bedrock deployment to wire a registry.
    """
    from watchlight_core import LLM_CALL_INTERRUPTED_REASON_QUARANTINE

    registry = getattr(plugin, "kill_signal_registry", None)
    if registry is None:
        return
    try:
        _run(registry.cancel(LLM_CALL_INTERRUPTED_REASON_QUARANTINE))
    except Exception:  # noqa: BLE001 — kill-signal is best-effort
        # the AgentQuarantinedError envelope is the customer-visible
        # signal that the agent is quarantined; the kill-signal is
        # the in-flight LLM-call abort. We log + continue.
        logger.warning(
            "Bedrock Lambda kill-signal cancel failed",
            exc_info=True,
        )


def parse_bedrock_event(event: dict) -> dict:
    """Extract the fields the decorator cares about from a Bedrock event.

    Bedrock action-group event format reference:
    https://docs.aws.amazon.com/bedrock/latest/userguide/agents-lambda.html

    Tolerant of both REST-style (``apiPath`` + ``httpMethod``) and
    function-style (``function`` + ``parameters``) action groups; the
    function-style form is reported with apiPath ``/<function>`` and
    httpMethod ``POST`` to keep the authz call consistent.
    """
    agent_block = event.get("agent") or {}
    session_state = event.get("sessionState") or {}
    session_attrs = (
        session_state.get("sessionAttributes")
        or event.get("sessionAttributes")
        or {}
    )

    api_path = event.get("apiPath")
    http_method = event.get("httpMethod") or "POST"
    if not api_path:
        # function-style action group
        function_name = event.get("function") or "invoke"
        api_path = f"/{function_name}"

    parameters: List[Dict[str, Any]] = event.get("parameters") or []
    if not parameters and isinstance(event.get("requestBody"), dict):
        # Some Bedrock variants put params under requestBody.content.
        content = event["requestBody"].get("content") or {}
        for media in content.values():
            if isinstance(media, dict) and isinstance(media.get("properties"), list):
                parameters = media["properties"]
                break

    return {
        "agent_id": agent_block.get("id") or "unknown",
        "agent_name": agent_block.get("name") or "unknown",
        "agent_alias": agent_block.get("alias") or "TSTALIASID",
        "action_group": event.get("actionGroup") or "default",
        "api_path": api_path,
        "http_method": http_method,
        "parameters": parameters,
        "session_id_bedrock": event.get("sessionId"),
        "session_attributes": session_attrs,
        "input_text": event.get("inputText") or "",
        "message_version": event.get("messageVersion") or "1.0",
    }


_MAX_ARG_NAMES = 32
_MAX_TYPE_LEN = 32


def redacted_parameter_metadata(parameters: Any) -> Dict[str, Any]:
    """Return **value-free** metadata for a Bedrock call's parameters.

    Bedrock passes action-group arguments as a list of
    ``{"name", "type", "value"}`` dicts. Raw values may carry bearer
    tokens, API keys or PII, and truncation is not redaction, so this
    surfaces only the argument *shape*: names, count and the declared
    Bedrock type (or the Python type when none is declared). It never
    returns a value. Safe for the ``/authorize`` context and the audit
    trail.
    """
    names: List[str] = []
    types: Dict[str, str] = {}
    if isinstance(parameters, list):
        for p in parameters:
            if not isinstance(p, dict) or not p.get("name"):
                continue
            name = str(p["name"])
            names.append(name)
            declared = p.get("type")
            if isinstance(declared, str) and declared:
                types[name] = declared[:_MAX_TYPE_LEN]
            else:
                types[name] = type(p.get("value")).__name__
    elif isinstance(parameters, dict):
        for k, v in parameters.items():
            names.append(str(k))
            types[str(k)] = type(v).__name__
    else:
        return {"arg_count": 0 if parameters is None else 1, "arg_names": []}

    shown = sorted(names)[:_MAX_ARG_NAMES]
    meta: Dict[str, Any] = {
        "arg_count": len(names),
        "arg_names": shown,
        "arg_types": {k: types[k] for k in shown if k in types},
    }
    if len(names) > _MAX_ARG_NAMES:
        meta["arg_names_truncated"] = True
    return meta


def _bedrock_deny_response(event: dict, reason: str, http_status: int = 403) -> dict:
    """Bedrock-shaped refusal response.

    Customer's Lambda returns this verbatim when authorization denies.
    Bedrock surfaces the reason back into the agent's reasoning trace,
    so the agent can explain *which* tool got refused and why.
    """
    parsed = parse_bedrock_event(event) if isinstance(event, dict) else None
    body_payload = json.dumps({"error": "watchlight_denied", "reason": reason})
    return {
        "messageVersion": "1.0",
        "response": {
            "actionGroup": (parsed or {}).get("action_group", "default"),
            "apiPath": (parsed or {}).get("api_path", "/"),
            "httpMethod": (parsed or {}).get("http_method", "POST"),
            "httpStatusCode": http_status,
            "responseBody": {"application/json": {"body": body_payload}},
        },
    }


def _run(coro):
    """Run an async coroutine from a sync Lambda handler.

    Lambda guarantees no enclosing event loop, so ``asyncio.run`` is
    the correct primitive. Isolated in a helper so the rest of the
    plugin can stay async-native.
    """
    return asyncio.run(coro)


# ─── Re-exports from core for backwards-compat ────────────────────────

__all__ = [
    "WatchlightBedrockPlugin",
    "RunHandle",
    "watchlight_bedrock_action",
    "parse_bedrock_event",
    "PlanResult",
    "PreflightResult",
    "WatchlightError",
    "AgentNotRegistered",
    "GovernanceUnavailable",
    "governance_mode",
]
