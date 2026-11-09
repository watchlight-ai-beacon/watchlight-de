"""Plugin entry point — ``start_run`` + ``RunHandle``.

TODO marker layout:

  - **TODO 1**: ``WatchlightTemplatePlugin.start_run()`` — resolve
    agent slug, open session, return RunHandle.
  - **TODO 2**: framework lifecycle integration — show the customer
    where to call ``handle.authorize_action()``. Each framework's
    hook point differs (graph node body / before_tool callback /
    Lambda decorator / event-stream subscription); the four shipped
    reference plugins are the canonical examples.

Everything else inherits from :class:`watchlight_core.BaseRunHandle`.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Optional, Union

from watchlight_core import (
    AgentNotRegistered,
    ApdpClient,
    BaseRunHandle,
    GovernanceTelemetry,
    GovernanceUnavailable,
    application_id_from_env,
    require_manifest,
    resolve_application_id,
)

logger = logging.getLogger("watchlight_template")


class RunHandle(BaseRunHandle):
    """Template framework's RunHandle.

    Inherits the lifecycle primitives (``submit_plan``,
    ``preflight_step``, ``authorize_action``,
    ``authorize_action_detailed``, ``complete``, ``terminate``,
    async context-manager exit) from
    :class:`watchlight_core.BaseRunHandle`. Add framework-specific
    helpers here as methods on the subclass — the LangGraph plugin
    adds ``callback_handler()``; the Bedrock plugin adds
    ``bedrock_agent_runtime()``; etc.

    For the simplest plugin, leave this class empty and use
    BaseRunHandle directly.
    """

    #: ``metadata.source`` of the events the base handle emits itself
    #: (observations, the defensive close). It must start with this
    #: plugin's framework tag (conformance invariant 2); rename it with
    #: the rest of the template.
    _observation_source = "template.workload"

    # TODO 2 (optional): add a framework-specific method that
    # makes wiring into your agent code one line. Example:
    #
    #     def hook_into_my_framework(self, agent):
    #         agent.register_tool_hook(self._authorize_tool)
    #
    #     async def _authorize_tool(self, ev):
    #         await self.authorize_action(
    #             action=ev.action,
    #             resource=ev.tool_name,
    #         )
    #
    # Pick the attachment point by whether the HOST can displace it,
    # not by which one is easiest to write. Enforcement must not
    # depend on a value the caller supplies per invocation — a list
    # on a config object, a `hooks=` kwarg, a mutable registry the
    # host rebuilds — because the host may replace it and the run
    # then proceeds ungoverned with nothing raised and nothing
    # logged. That is what happened to the LangGraph plugin's
    # `callbacks=[handler]` attach: LangChain lets an explicit
    # `callbacks` value replace the inherited manager, so a host
    # passing its own list silently dropped the handler.
    #
    # Prefer, in order:
    #   1. an append-only registry the caller cannot rebuild (e.g.
    #      LangChain's `register_configure_hook`), or a binding made
    #      at construction and compiled into the agent;
    #   2. a decorator or wrapper baked into the tool/handler object
    #      itself;
    #   3. only if neither exists: the caller-supplied slot PLUS a
    #      check at run start that the hook actually fired, failing
    #      closed when it did not.
    # If you take option 3, say so in the plugin README.


class WatchlightTemplatePlugin(GovernanceTelemetry):
    """Watchlight governance plugin for the Template framework.

    Usage::

        plugin = WatchlightTemplatePlugin(
            apdp_url="https://apdp.your-org",
            tenant_id="your-tenant",
        )

        async with await plugin.start_run("my-agent") as handle:
            # ... wire `handle` into your framework's lifecycle ...
            pass
    """

    def __init__(
        self,
        apdp_url: str,
        tenant_id: Optional[str] = None,
        apdp_api_key: Optional[str] = None,
        log_decisions: bool = True,
        application_id: Optional[str] = None,
        ca_bundle: Optional[Union[str, Path]] = None,
    ):
        super().__init__()  # initialises the seven `last_*` telemetry attrs
        # ``apdp_url`` has no default: the operator names the policy
        # service, over ``https://``. The client refuses plain ``http://``
        # unless the operator opts in for local development. The CA that
        # signed the policy service's certificate comes from ``ca_bundle``,
        # then ``WATCHLIGHT_APDP_TLS_CA_BUNDLE``, then the system store.
        # Verification is always on; only the trusted CA is configurable.
        if ca_bundle is None:
            ca_bundle = os.environ.get("WATCHLIGHT_APDP_TLS_CA_BUNDLE") or None
        self.apdp = ApdpClient(apdp_url, api_key=apdp_api_key, ca_bundle=ca_bundle)
        self.tenant_id = tenant_id
        self.log_decisions = log_decisions
        # AI application attribution: the application every run
        # opened by this plugin belongs to; forwarded on session create
        # so wl-apdp binds it to the run credential. Explicit
        # configuration only — never inferred from prompts or names.
        # ``start_run(application_id=...)`` overrides per run. Env
        # fallback: ``WATCHLIGHT_APPLICATION_ID``. ``None`` / empty /
        # whitespace ⇒ unset, the field is not sent (an agent in exactly
        # one application needs nothing here). A non-UUID raises
        # ``ValueError`` here (client-side format check only — wl-apdp
        # stays the authority on membership).
        self.application_id = (
            resolve_application_id(application_id) or application_id_from_env()
        )

    async def start_run(
        self,
        agent_slug: str,
        *,
        application_id: Optional[str] = None,
    ) -> RunHandle:
        """Open a governed run for the named agent.

        TODO 1: this method is mostly boilerplate — leave it
        alone unless your framework needs custom session
        initialization (e.g. Bedrock attaches sessionState; ADK
        prefetches the constraint manifest into the Runner).

        ``application_id``: the AI application this run belongs to.
        Defaults to the plugin-level ``application_id``
        (constructor kwarg, else ``WATCHLIGHT_APPLICATION_ID``); sent
        only when set.

        Fail-closed: unknown slug raises ``AgentNotRegistered``;
        unreachable APDP raises ``GovernanceUnavailable``.
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
            ttl_seconds=3600,
            metadata={"framework": "template", "tenant_id": self.tenant_id},
            # Only when set, so an older watchlight-agent-sdk still works.
            **({"application_id": app_id} if app_id is not None else {}),
        )
        if session is None:
            raise GovernanceUnavailable(
                "The policy service did not accept the session create. Check that "
                "APDP is reachable and the data plane is configured."
            )
        session_id = session.session_id
        # The server-minted ROOT run-handle id (present when
        # wl-apdp has a run-handle store). Presented on every authorize so
        # runtime Attenuate applies to the root run; ``None`` on older
        # wl-apdp → prior behaviour (client-minted id, never presented).
        root_run_handle_id = session.root_run_handle_id
        # The run credential bounds the manifest by the run's grant.
        # A missing manifest refuses the run unless the operator explicitly
        # opted into WATCHLIGHT_PLAN_GOVERNANCE_MODE=degrade; the refused
        # run's session is closed. (Run every later setup step, such as
        # governed egress, inside this same try block.)
        try:
            manifest = await self.apdp.get_manifest(agent_uuid, run=session.run)
            governance_level = require_manifest(manifest, agent_id=agent_uuid)
        except BaseException:
            try:
                await self.apdp.complete_session(session.run)
            except Exception:  # noqa: BLE001 — the refusal is what matters
                logger.warning("closing the refused session %s failed", session_id)
            raise

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

        return RunHandle(
            plugin=self,
            agent_uuid=agent_uuid,
            session_id=session_id,
            run_handle_id=root_run_handle_id,
            server_run_handle=root_run_handle_id is not None,
            # The run reference names this run on every backend call; its
            # credentials stay inside the backend. Adopt the server-minted
            # execution id so emitted events bind to the run.
            run=session.run,
            execution_id=session.execution_id,
        )
