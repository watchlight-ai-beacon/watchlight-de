"""WatchlightClaudeAgentSDKPlugin + RunHandle.

A thin wrapper around watchlight_core primitives. The Python Claude Agent
SDK has no plugin-loader contract, so enforcement ships as a hook map:
:meth:`WatchlightClaudeAgentSDKPlugin.governance_hooks` (or
:meth:`~WatchlightClaudeAgentSDKPlugin.governed_options`) returns the
``PreToolUse`` / ``SubagentStart`` / ``SubagentStop`` hooks that gate every
tool call and every sub-agent spawn. You pass them to
``ClaudeAgentOptions(hooks=...)``.

# Lifecycle

- :meth:`start_run(agent_slug)` resolves the slug → UUID via
  /agents/resolve, opens an APDP session, fetches the constraint
  manifest, and auto-installs the wl-proxy CONNECT sidecar if
  configured. Returns a :class:`RunHandle`.

# CONNECT auto-install

When `self.connect_proxy_url` is set, the plugin installs the local
sidecar HTTP CONNECT proxy from `watchlight_core.install_connect_proxy`
with the session's egress binding. If wl-apdp issued no proxy token, or
the install fails, `start_run` raises `GovernanceUnavailable`: a
configured proxy is never silently skipped.
From that point on, EVERY Python HTTP library that honors
`HTTPS_PROXY` (httpx, requests, urllib3, aiohttp, openai, anthropic,
boto3, …) auto-routes its outbound HTTPS through wl-proxy with
`Proxy-Authorization` (the run's proxy token, held by the governance
backend, never by the handle). **Zero customer
agent-code touches.** Env-var fallback: `WATCHLIGHT_PROXY_URL`.
"""

from __future__ import annotations

import os
import uuid
import warnings
from typing import Any, AsyncIterable, AsyncIterator, Dict, Iterable, List, Optional

from watchlight_core import (
    AgentNotRegistered,
    ApdpClient,
    load_default_credential,
    application_id_from_env,
    resolve_application_id,
    BaseRunHandle,
    GovernanceBackend,
    GovernanceTelemetry,
    GovernanceUnavailable,
    SubagentRegistry,
    default_subagent_scope_from_env,
    get_logger,
    require_manifest,
    resolve_intent_enforcement_mode,
)

from watchlight_core.backend import egress_binding_for

from .subagents import (
    derive_requested_scope,
    parent_key_from_capture,
    subagent_id_from_capture,
    subagent_slug_from_capture,
    task_objective_from_capture,
)
from .synthetic_tools import (
    intercept_tool_call,
    is_synthetic_tool_capture,
    merge_synthetic_tools,
    synthetic_tool_definitions,
)
from .traces import translate_claude_agent_events

logger = get_logger("watchlight_claude_agent")


class RunHandle(BaseRunHandle):
    """Claude-Agent-SDK-flavoured run handle.

    Inherits the full lifecycle (submit_plan, preflight_step,
    authorize_action, complete, terminate) from
    :class:`watchlight_core.BaseRunHandle`. No framework-specific
    helpers: tool calls are authorized by the hooks from
    :meth:`WatchlightClaudeAgentSDKPlugin.governance_hooks`.

    Provenance: ad-hoc observation events emitted via
    :meth:`watchlight_core.BaseRunHandle.publish_observation` carry
    ``metadata.source = "claude-agent-sdk.workload"`` via the
    per-class :attr:`_observation_source` override below.
    """

    #: Provenance tag stamped on every ad-hoc observation event emitted
    #: via :meth:`watchlight_core.BaseRunHandle.publish_observation`.
    #: Identifies Claude Agent SDK workloads on the canonical event
    #: stream.
    _observation_source = "claude-agent-sdk.workload"

    #: Per-run governed-spawn chokepoint. Attached by
    #: :meth:`WatchlightClaudeAgentSDKPlugin.start_run` on the ROOT run
    #: handle only; native Task sub-agents route through it. Declared
    #: here (not assigned) so the attribute is typed without every
    #: sub-agent handle carrying one — the plugin reads it via
    #: ``getattr(..., None)`` and fails closed when absent.
    subagent_registry: "SubagentRegistry"


class WatchlightClaudeAgentSDKPlugin(GovernanceTelemetry):
    """Watchlight governance plugin for the Claude Agent SDK.

    Construct once per process. Call :meth:`start_run` to open a
    governed session for each invocation of the underlying Claude
    Agent.
    """

    def __init__(
        self,
        apdp_url: str = "http://localhost:8081",
        tenant_id: Optional[str] = None,
        apdp_api_key: Optional[str] = None,
        log_decisions: bool = True,
        connect_proxy_url: Optional[str] = None,
        intent_enforcement_mode: Optional[str] = None,
        default_subagent_scope: Optional[Dict[str, Any]] = None,
        governance: Optional[GovernanceBackend] = None,
        application_id: Optional[str] = None,
        child_intent_category: Optional[str] = None,
    ) -> None:
        super().__init__()
        # The intent category declared for a Task sub-agent (``None``: the
        # spawner's own derived category, else
        # ``DEFAULT_PLUGIN_CHILD_INTENT_CATEGORY``). The objective is the
        # Task tool's description/prompt. wl-apdp refuses a category outside
        # the parent run's intent bounds.
        self.child_intent_category: Optional[str] = child_intent_category
        if governance is not None:
            # Developer-Edition / in-process seam: use the caller-supplied
            # GovernanceBackend (e.g. watchlight_core.InProcessClient over the
            # compiled watchlight-engine) verbatim, skipping the networked
            # ApdpClient. Same plugin, same agent code — only the backend
            # differs; going to production is swapping this back for an
            # ApdpClient (one config flip, not a rewrite). apdp_url /
            # apdp_api_key are ignored in this mode.
            # SECURITY: a supplied backend bypasses ApdpClient's channel-safety
            # guard. The shipped InProcessClient is network-free; a CUSTOM
            # networked backend passed here MUST enforce its own transport
            # security (TLS). Only pass a backend you trust to do so.
            self.apdp = governance
        else:
            # With no key, load the default Watchlight credential. A
            # configured credential that cannot be loaded raises here; with
            # nothing configured the client runs unauthenticated and the
            # server refuses it.
            credential = (
                load_default_credential("watchlight_claude_agent") if apdp_api_key is None else None
            )
            if credential is not None:
                self.apdp = ApdpClient(apdp_url, credential=credential)
            else:
                self.apdp = ApdpClient(apdp_url, api_key=apdp_api_key)
        self.tenant_id = tenant_id
        self.log_decisions = log_decisions
        # wl-proxy CONNECT mode. The plugin auto-installs the local
        # sidecar in start_run when this knob is set + wl-apdp issues a
        # proxy token. Env fallback: WATCHLIGHT_PROXY_URL.
        self.connect_proxy_url = connect_proxy_url or os.getenv(
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
        # stays the authority on membership). The in-process engine
        # (Developer Edition) refuses the field: attribution is an
        # Enterprise feature.
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
        # Effective intent-enforcement mode for this plugin
        # instance. Greenfield → synthetic ``watchlight.declare_intent``
        # tool injected into the agent's tool list + interception path
        # in customer's hook loop. Brownfield → synthetic-tool surface
        # is inert. Mode resolution order: constructor arg → env var
        # (``WATCHLIGHT_INTENT_ENFORCEMENT_MODE``) → ``"brownfield"`` default.
        # Resolved at plugin construction so the tool list is stable
        # across the run; flipping the env var mid-run does NOT take
        # effect until a new plugin is constructed.
        self.intent_enforcement_mode: str = resolve_intent_enforcement_mode(
            intent_enforcement_mode
        )
        # Operator knob for the per-spawn requested scope of
        # NATIVE Task sub-agents that surface no ``allowed-tools`` on
        # their ``SubagentStart`` capture. Resolution order:
        # constructor arg → env ``WATCHLIGHT_DEFAULT_SUBAGENT_SCOPE`` →
        # EMPTY. An EMPTY default is the deliberate, locked fail-closed
        # default: a sub-agent with no surfaced per-spawn scope AND no
        # operator default is spawned with zero tools, so its FIRST tool
        # call is denied at the server's scope-membership check until an
        # operator widens the knob. Resolved ONCE here so the value is
        # stable + inspectable across the process; a per-run
        # :class:`~watchlight_core.SubagentRegistry` is built from it in
        # :meth:`start_run`. This enforces the sub-agent-governance and
        # ungoverned-request-gate invariants: a sub-agent is never
        # spawned with unbounded authority.
        self.default_subagent_scope: Dict[str, Any] = (
            dict(default_subagent_scope)
            if default_subagent_scope is not None
            else default_subagent_scope_from_env()
        )

    async def start_run(
        self,
        agent_slug: str,
        goal_id: Optional[str] = None,
        max_actions: Optional[int] = None,
        ttl_seconds: int = 3600,
        application_id: Optional[str] = None,
    ) -> RunHandle:
        """Open a governed run for the named Claude agent.

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
          - proxy URL configured but no proxy token issued, or the
            CONNECT sidecar install fails → raises
            :class:`GovernanceUnavailable` (no direct egress)
        """
        self._reset_telemetry()

        resolved = await self.apdp.resolve_agent(agent_slug)
        if resolved is None:
            raise AgentNotRegistered(
                f"Agent {agent_slug!r} is not registered with Watchlight. "
                f"Register via wl-registry's /api/v1/agents/register before "
                f"invoking it."
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
            metadata={
                "framework": "claude-agent-sdk",
                "tenant_id": self.tenant_id,
            },
            # Only when set, so an older watchlight-agent-sdk still works.
            **({"application_id": app_id} if app_id is not None else {}),
        )
        if session is None:
            raise GovernanceUnavailable(
                "WL-APDP did not accept the session create. Check that "
                "APDP is reachable and the data plane is configured."
            )
        session_id = session.session_id
        run = session.run
        # The run's wl-proxy egress binding (``None`` when wl-apdp issued no
        # proxy token); the token itself stays in the backend.
        egress = egress_binding_for(self.apdp, run)
        # Server-minted ROOT run-handle id (present when
        # wl-apdp has a run-handle store). Presented on every authorize so
        # runtime Attenuate applies to the root run; ``None`` on older
        # wl-apdp → prior behaviour (client-minted id, never presented).
        root_run_handle_id = session.root_run_handle_id

        # Everything after the session create fails closed: if the run
        # cannot be set up completely (missing manifest, egress that
        # cannot be governed, or any other error, including
        # cancellation), the session it opened is closed and the
        # failure propagates. It never proceeds ungoverned.
        try:
            # The run credential bounds the manifest by the run's grant.
            manifest = await self.apdp.get_manifest(agent_uuid, goal_id=goal_id, run=run)
            # A missing manifest refuses the run (before any egress is set
            # up) unless the operator explicitly opted into
            # WATCHLIGHT_PLAN_GOVERNANCE_MODE=degrade.
            governance_level = require_manifest(manifest, agent_id=agent_uuid)

            # Auto-install the wl-proxy CONNECT sidecar. A configured proxy
            # URL means egress MUST go through wl-proxy: when wl-apdp issued
            # no proxy token, or the sidecar cannot be installed, the run is
            # refused rather than left to egress directly.
            if self.connect_proxy_url:
                if egress is None:
                    raise GovernanceUnavailable(
                        "A wl-proxy URL is configured but WL-APDP issued no proxy "
                        "token for this session; refusing to run with direct "
                        "egress."
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
                except Exception as e:  # noqa: BLE001 — refuse the run
                    raise GovernanceUnavailable(
                        "The wl-proxy CONNECT sidecar could not be installed "
                        f"({type(e).__name__}); refusing to run with direct "
                        "egress."
                    ) from None

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
                # Execution-lineage integrity — thread the run (whose
                # per-run ``sst_`` credential the backend presents on
                # ``/v1/events``) AND the server-minted canonical
                # ``execution_id`` so the root's emitted events bind to the
                # run its credential authenticates. This is ALSO load-bearing
                # for the native-sub-agent chokepoint below: the governed
                # spawn authenticates as the PARENT run and the child adopts
                # its lineage off the parent's — no run here would leave
                # every spawn unauthenticated (the shared tenant bearer is
                # refused on the spawn path).
                run=run,
                egress=egress,
                execution_id=session.execution_id,
            )
            # Attach the per-run governed-spawn chokepoint. Every NATIVE Task
            # sub-agent this run opens routes through this registry's
            # ``spawn_subagent`` call (server attests the spawn + strict-subset
            # scope attenuation), so the child's tool calls
            # authorize under its OWN attenuated handle, never the root's.
            # Bound to the root handle so a plugin instance shared across
            # concurrent runs keeps each run's sub-agent state isolated.
            handle.subagent_registry = SubagentRegistry(
                handle,
                default_subagent_scope=self.default_subagent_scope,
                child_intent_category=self.child_intent_category,
            )
        except BaseException as exc:
            logger.error(
                "watchlight_claude_agent: run setup refused (%s)", type(exc).__name__
            )
            try:
                await self.apdp.complete_session(run)
            except Exception:  # noqa: BLE001 — best-effort close
                logger.warning(
                    "watchlight_claude_agent: closing refused session %s failed",
                    session_id,
                )
            raise
        return handle

    # ─── synthetic declare_intent surface ────────────────────────────────

    def synthetic_tools(self) -> List[Dict[str, Any]]:
        """Return the synthetic Watchlight-managed tool definitions the
        agent should see for this run.

        Resolves against the plugin's :attr:`intent_enforcement_mode` —
        greenfield returns ``[WATCHLIGHT_DECLARE_INTENT_TOOL]``,
        brownfield returns ``[]``. The customer spreads the result into
        their ``options["tools"]`` when calling the Claude Agent SDK's
        ``query()``.

        See :func:`synthetic_tool_definitions` for the underlying
        contract — this method is the ergonomic plugin-level alias.
        """
        return synthetic_tool_definitions(mode=self.intent_enforcement_mode)

    def merge_synthetic_tools(
        self,
        customer_tools: Optional[Iterable[Dict[str, Any]]] = None,
    ) -> List[Dict[str, Any]]:
        """Union the customer's tools with the synthetic ones.

        Convenience wrapper used in customer integration code:

            options = {
                "tools": plugin.merge_synthetic_tools(my_tools),
                "hooks": my_hooks,
            }

        Synthetic tools are placed FIRST in the returned list so the
        LLM's tool-discovery heuristic surfaces ``watchlight.declare_intent``
        at the top. Customer-defined tools that collide with the reserved
        synthetic name are dropped (logged-warning) in favour of the
        canonical SDK definition.
        """
        return merge_synthetic_tools(
            customer_tools=customer_tools,
            mode=self.intent_enforcement_mode,
        )

    def intercept_tool_call(
        self,
        handle: BaseRunHandle,
        capture: Optional[Dict[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        """Short-circuit the synthetic tool BEFORE the customer's hook
        loop calls ``handle.authorize_action()``.

        Returns the LLM-visible tool response dict for synthetic calls
        (and mutates ``handle``'s intent state); returns ``None`` for
        every other tool call so the customer's loop continues to its
        normal authorize + translate path.

        Authorization carve-out: the synthetic tool MUST NOT round-trip
        to ``authorize_action()`` (that would create a chicken-and-egg
        problem with the intent-enforcement Cedar gate); the customer's
        loop short-circuits here instead.
        """
        return intercept_tool_call(handle, capture)

    @staticmethod
    def is_synthetic_tool_capture(
        capture: Optional[Dict[str, Any]],
    ) -> bool:
        """Predicate: does ``capture`` describe a synthetic tool call?

        Static for symmetry with the TS lane's
        :func:`isDeclareIntentToolCall`. Customer code may call this
        directly when it needs to branch on tool name before deciding
        whether to call :meth:`intercept_tool_call`.
        """
        return is_synthetic_tool_capture(capture)

    # ─── shipped enforcement hooks ───────────────────────────────────────

    def governance_hooks(
        self,
        handle: BaseRunHandle,
        existing_hooks: Optional[Dict[str, List[Any]]] = None,
    ) -> Dict[str, List[Any]]:
        """Return the Claude Agent SDK hook map that enforces Watchlight
        on this run.

        Pass it as ``ClaudeAgentOptions(hooks=...)``. It installs:

        * a ``PreToolUse`` gate on every tool. A ``Task``/``Agent`` call
          performs the governed sub-agent spawn first and is denied when
          the spawn is refused, so a refused sub-agent never starts. Every
          other tool is authorized on the acting agent's own handle and
          denied on a deny, a needs-approval decision, or any error;
        * ``SubagentStart`` / ``SubagentStop`` hooks that bind and close
          the governed sub-agent handles.

        ``existing_hooks`` (your own hook map) is merged in after the
        Watchlight matchers. A deny from any hook stops the tool call, so
        your hooks cannot turn a Watchlight deny into an allow.

        Use the handle returned by :meth:`start_run`, inside its
        ``async with`` block; a handle that was not entered cannot
        authorize and every tool call is denied.
        """
        from .hooks import GovernanceHookGate

        gate = getattr(handle, "_wl_hook_gate", None)
        if gate is None:
            gate = GovernanceHookGate(self, handle)
            handle._wl_hook_gate = gate  # type: ignore[attr-defined]
        merged: Dict[str, List[Any]] = {
            event: list(matchers) for event, matchers in gate.hooks().items()
        }
        for event, matchers in (existing_hooks or {}).items():
            merged.setdefault(event, []).extend(list(matchers or []))
        return merged

    def governed_options(self, handle: BaseRunHandle, options: Any = None) -> Any:
        """Return ``options`` with :meth:`governance_hooks` merged in, and the
        session made to prove the gate ran before every tool call.

        Accepts a ``ClaudeAgentOptions`` (dataclass) or a plain dict. With
        no ``options``, builds a ``ClaudeAgentOptions`` when the Claude
        Agent SDK is installed, else a dict.

        Raises :class:`~watchlight_claude_agent.session_guard.UngovernableSession`
        when the options would run Claude Code without the hooks (its bare
        mode) or take the permission callback away. Otherwise the returned
        options carry a ``permissions.ask`` rule for every tool and a
        ``can_use_tool`` callback that allows a call only after Watchlight's
        ``PreToolUse`` gate allowed it, and only when the session's own
        configuration would have run it without a prompt; any other call
        goes to your own ``can_use_tool``, or is denied. See
        ``session_guard``.
        """
        import dataclasses

        from .hooks import GovernanceHookGate
        from .session_guard import SessionPermissions, check_session_options, with_ask_every_tool
        from .tool_classes import with_never_offered_tools

        if options is None:
            try:
                from claude_agent_sdk import ClaudeAgentOptions  # type: ignore

                options = ClaudeAgentOptions()
            except Exception:  # noqa: BLE001 — SDK not installed
                options = {}
        if isinstance(options, dict):
            get = options.get
        elif dataclasses.is_dataclass(options):

            def get(name: str, default: Any = None) -> Any:
                return getattr(options, name, default)

        else:
            raise TypeError(
                "governed_options expects a ClaudeAgentOptions or a dict, got "
                f"{type(options).__name__}"
            )
        checked = check_session_options(
            extra_args=get("extra_args"),
            env=get("env"),
            settings=get("settings"),
            setting_sources=get("setting_sources"),
            permission_prompt_tool_name=get("permission_prompt_tool_name"),
            cwd=get("cwd"),
            cli_path=get("cli_path"),
        )
        hooks = self.governance_hooks(handle, get("hooks"))
        gate = handle._wl_hook_gate  # type: ignore[attr-defined]
        assert isinstance(gate, GovernanceHookGate)
        changes = {
            "hooks": hooks,
            # Refused tools are never offered to the model.
            "disallowed_tools": with_never_offered_tools(get("disallowed_tools")),
            "settings": with_ask_every_tool(checked.flag),
            "can_use_tool": gate.can_use_tool(
                SessionPermissions(
                    permission_mode=get("permission_mode"),
                    allowed_tools=get("allowed_tools"),
                    sources=checked.sources,
                    cwd=get("cwd"),
                    add_dirs=get("add_dirs"),
                ),
                get("can_use_tool"),
            ),
        }
        if isinstance(options, dict):
            return {**options, **changes}
        return dataclasses.replace(options, **changes)

    def governed_query(
        self,
        handle: BaseRunHandle,
        *,
        prompt: Any,
        options: Any = None,
        transport: Any = None,
    ) -> AsyncIterator[Any]:
        """The Claude Agent SDK's ``query()`` with every Watchlight layer.

        Builds the options with :meth:`governed_options` (raising
        ``UngovernableSession`` before anything starts), then yields the
        session's messages through :meth:`watch_messages`.

        ``transport`` must be ``None``: the SDK's own subprocess transport
        runs the session. A custom transport receives the initialize
        request that carries Watchlight's hooks and answers the permission
        callback's messages, so it could drop either; it is refused with
        ``UngovernableSession`` before anything starts.
        """
        from claude_agent_sdk import query

        from .session_guard import UngovernableSession

        if transport is not None:
            raise UngovernableSession(
                "Watchlight refused the Claude Code session: a custom transport "
                "could drop Watchlight's hooks or answer its permission check, "
                "which would run tools without the Watchlight gate."
            )
        governed = self.governed_options(handle, options)
        return self.watch_messages(handle, query(prompt=prompt, options=governed, transport=transport))

    def watch_messages(self, handle: BaseRunHandle, messages: AsyncIterable[Any]) -> AsyncIterator[Any]:
        """Yield the messages of a session started with
        :meth:`governed_options` (for example ``client.receive_response()``
        of a ``ClaudeSDKClient``), and end the session when they show it
        running without Watchlight: no ``UserPromptSubmit`` hook before the
        session started, or a tool result for a call the gate never
        decided. The run is then terminated and ``GovernanceBypassDetected``
        is raised. See ``stream_guard``.
        """
        from .session_guard import UngovernableSession
        from .stream_guard import guard_messages

        gate = getattr(handle, "_wl_hook_gate", None)
        if gate is None:
            raise UngovernableSession(
                "Watchlight refused to watch a Claude Code session that was not "
                "started with governed_options() on this run."
            )
        return guard_messages(gate, handle, messages)

    # ─── native Task sub-agent governed-spawn chokepoint ─────────────────

    @staticmethod
    def _registry_for(
        root_handle: BaseRunHandle,
    ) -> Optional[SubagentRegistry]:
        """Return the per-run :class:`SubagentRegistry` attached to
        ``root_handle`` in :meth:`start_run`, or ``None`` when the handle
        did not come from ``start_run`` (fail-closed: the caller then
        denies the sub-agent's tool calls)."""
        return getattr(root_handle, "subagent_registry", None)

    async def _resolve_subagent_principal(
        self, raw_slug: str
    ) -> Optional[str]:
        """Resolve a Task sub-agent's agent-type / slug to the canonical
        agent UUID the governed spawn requires.

        A UUID is passed through verbatim; any other string is resolved
        via the registry (``/agents/resolve``). ``None`` when the
        sub-agent is not a registered agent — the caller then refuses to
        spawn it and its tool calls fail closed. Registering sub-agents
        (not silently spawning an unregistered principal) is the
        enterprise-identity bar: every governed agent has a stable,
        resolvable identity."""
        try:
            uuid.UUID(str(raw_slug))
            return str(raw_slug)
        except (ValueError, TypeError):
            pass
        resolved = await self.apdp.resolve_agent(raw_slug)
        if resolved is None:
            return None
        return resolved.get("id")

    async def on_subagent_start(
        self,
        root_handle: BaseRunHandle,
        capture: Dict[str, Any],
    ) -> Optional[BaseRunHandle]:
        """Route a native Task sub-agent's ``SubagentStart`` capture
        through the governed ``spawn_subagent`` chokepoint.

        Call this from the customer's ``SubagentStart`` hook. It:

        1. resolves the sub-agent's agent-type/slug to a registered
           agent UUID (unregistered → fail closed, returns ``None``);
        2. derives the per-spawn requested scope from the Task tool's
           ``allowed-tools`` when surfaced, else falls back to the
           operator ``default_subagent_scope`` (EMPTY = fail-closed);
        3. calls :meth:`SubagentRegistry.on_spawn`, which routes the
           spawn through the DIRECT parent's handle so wl-apdp attests
           the spawn (server-emitted ``agent_spawn_observed`` +
           strict-subset scope attenuation) and mints the per-child
           ``sst_`` credential.

        Returns the governed CHILD :class:`BaseRunHandle` on success, or
        ``None`` when the spawn failed closed (unresolvable principal,
        missing sub-agent id, server scope-attenuation denial, or a
        denied/unknown explicit parent). On ``None`` the caller MUST
        deny the sub-agent's subsequent tool calls — :meth:`resolve_subagent`
        will keep returning ``None`` for it.

        .. deprecated:: 0.2.1
            ``SubagentStart`` fires after the sub-agent has started, so a
            refusal here cannot stop it from taking model turns. Use
            :meth:`governance_hooks`, which governs the spawn in the
            ``Task``/``Agent`` ``PreToolUse`` gate before it starts."""
        warnings.warn(
            "on_subagent_start governs the spawn after the sub-agent has "
            "started; use WatchlightClaudeAgentSDKPlugin.governance_hooks(), "
            "which refuses the Task/Agent tool call before the sub-agent "
            "starts.",
            DeprecationWarning,
            stacklevel=2,
        )
        registry = self._registry_for(root_handle)
        if registry is None:
            logger.error(
                "watchlight_claude_agent: SubagentStart received a handle "
                "with no attached SubagentRegistry — refusing to spawn "
                "ungoverned. Pass the handle returned by start_run(). The "
                "sub-agent's tool calls will be DENIED."
            )
            return None

        child_key = subagent_id_from_capture(capture)
        if child_key is None:
            logger.warning(
                "watchlight_claude_agent: SubagentStart surfaced no "
                "sub-agent id — cannot govern this spawn; the sub-agent's "
                "tool calls will be DENIED (ungoverned-request gate)."
            )
            return None

        raw_slug = subagent_slug_from_capture(capture) or child_key
        child_uuid = await self._resolve_subagent_principal(raw_slug)
        if child_uuid is None:
            logger.warning(
                "watchlight_claude_agent: sub-agent %r (agent %r) is not a "
                "registered Watchlight agent — refusing to spawn it "
                "ungoverned; its tool calls will be DENIED. Register the "
                "sub-agent via wl-registry before invoking it.",
                child_key,
                raw_slug,
            )
            return None

        requested_scope = derive_requested_scope(capture)
        parent_key = parent_key_from_capture(capture)

        if requested_scope is None:
            # No per-spawn ``allowed-tools`` surfaced → the operator
            # ``default_subagent_scope`` knob applies. Log loudly when it
            # is EMPTY: the child spawns with zero tools and its first
            # tool call is denied until an operator scopes it. Never log
            # token/credential values — only the tool-name knob.
            default_tools = self.default_subagent_scope.get("allowed_tools")
            if not default_tools:
                logger.warning(
                    "watchlight_claude_agent: sub-agent %r (agent %r) "
                    "surfaced no allowed-tools AND no operator "
                    "default_subagent_scope is set — spawning FAIL-CLOSED "
                    "(zero tools). The sub-agent's first tool call will be "
                    "DENIED until an operator widens default_subagent_scope "
                    "(constructor arg or env "
                    "WATCHLIGHT_DEFAULT_SUBAGENT_SCOPE) to a strict subset "
                    "of the parent's granted scope.",
                    child_key,
                    raw_slug,
                )
            else:
                logger.info(
                    "watchlight_claude_agent: sub-agent %r (agent %r) "
                    "surfaced no allowed-tools — applying the operator "
                    "default_subagent_scope (%d tool(s)).",
                    child_key,
                    raw_slug,
                    len(default_tools),
                )

        return await registry.on_spawn(
            child_key=child_key,
            child_slug=child_uuid,
            requested_scope=requested_scope,
            parent_key=parent_key,
            objective=task_objective_from_capture(capture),
        )

    def resolve_subagent(
        self,
        root_handle: BaseRunHandle,
        subagent_id: str,
    ) -> Optional[BaseRunHandle]:
        """Return the governed CHILD handle for ``subagent_id``, or
        ``None``.

        Call this from the customer's ``PreToolUse`` hook when the tool
        call belongs to a sub-agent. ``None`` means the caller MUST DENY
        the tool call — the ungoverned-request-gate default. It is
        returned for an unknown sub-agent id AND for one whose governed
        spawn failed closed (server scope-attenuation denial). On a
        non-``None`` handle, authorize the tool call against THAT handle
        (``await child.authorize_action(...)``) — its own
        ``run_handle_id`` + per-child ``sst_`` credential — never the
        root handle."""
        gate = getattr(root_handle, "_wl_hook_gate", None)
        if gate is not None:
            bound = gate.resolve(subagent_id)
            if bound is not None:
                return bound
        registry = self._registry_for(root_handle)
        if registry is None:
            return None
        return registry.resolve(subagent_id)

    async def on_subagent_stop(
        self,
        root_handle: BaseRunHandle,
        subagent_id: str,
    ) -> None:
        """Close out a native Task sub-agent.

        Call this from the customer's ``SubagentStop`` hook. Pops the
        registry's spawn stack, completes the child handle (closes its
        APDP session), and drops the entry. Idempotent and out-of-order
        safe."""
        registry = self._registry_for(root_handle)
        if registry is None:
            return
        await registry.on_stop(subagent_id)

    async def publish_subagent_events(
        self,
        root_handle: BaseRunHandle,
        subagent_id: str,
        captures: List[Dict[str, Any]],
    ) -> bool:
        """Translate + publish a sub-agent's hook captures under the
        CHILD handle's lineage.

        This is the load-bearing emission path for a sub-agent's own
        ``execution_started`` (from its ``UserPromptSubmit`` capture) and
        ``tool_call_observed`` events: they MUST carry the SERVER-minted
        child ``execution_id`` (so the ``/v1/events`` binding gate accepts
        them — the child credential's ``eid`` claim binds to it) and be
        published under the per-child ``sst_`` credential (so they can
        never be attributed to the parent). This method threads both off
        the resolved child handle rather than the root's, closing an
        earlier mis-attribution gap.

        Fail-closed: when ``subagent_id`` has no governed handle (denied
        or unknown spawn), returns ``False`` WITHOUT emitting — an
        ungoverned sub-agent's events do not reach the wire. Note the
        plugin never emits a client ``agent_spawn_observed``: spawn
        attestation is SERVER-emitted only, and the translator
        drops the ``SubagentStart`` capture."""
        child = self.resolve_subagent(root_handle, subagent_id)
        if child is None:
            logger.warning(
                "watchlight_claude_agent: refusing to publish events for "
                "ungoverned sub-agent %r (no governed handle — denied or "
                "unknown spawn). Its events are dropped (fail-closed).",
                subagent_id,
            )
            return False
        events = translate_claude_agent_events(
            captures,
            execution_id=child.execution_id,
            agent_id=child.agent_uuid,
            session_id=child.session_id,
            tenant_id=self.tenant_id,
            parent_execution_id=child.parent_execution_id,
            root_execution_id=child.root_execution_id,
        )
        for event in events:
            await self.apdp.publish_events(child.run, [event])
        return True
