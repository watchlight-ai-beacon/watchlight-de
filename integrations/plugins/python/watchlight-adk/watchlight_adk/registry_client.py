"""Async client for WL-Registry tool inventory reports."""

from typing import Optional

import httpx

from watchlight_core import get_logger

logger = get_logger("watchlight_adk")


class RegistryClient:
    """Lightweight async client that reports an agent's tools to WL-Registry.

    The report is INVENTORY ONLY: it tells operators which tools the agent
    runs, and catalogues them so an AI application can declare them. It
    never grants the agent anything. WL-Registry stores the rows as
    ``reported_by = plugin`` and wl-apdp does not read them into the
    agent's capabilities; an operator grants capabilities and sets the
    agent's ``allowed_tools``.

    The report is best-effort: failures are logged but never block agent
    execution.
    """

    def __init__(
        self,
        base_url: str,
        api_key: str = "",
        timeout: float = 10.0,
    ):
        self._base_url = base_url
        self._api_key = api_key
        self._timeout = timeout
        self._client: httpx.AsyncClient | None = None

    @property
    def client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            # trust_env=False: the registry is an internal Watchlight
            # service; its requests must never be routed through a proxy
            # taken from the environment (the egress sidecar or a
            # customer's corporate proxy).
            self._client = httpx.AsyncClient(
                base_url=self._base_url, timeout=self._timeout, trust_env=False
            )
        return self._client

    async def report_tool_inventory(
        self,
        agent_id: str,
        tools: list[dict],
        framework: str = "",
    ) -> bool:
        """Report the tools an agent runs (``POST /api/v1/agents/{id}/tools``).

        Inventory only: the registry lists and catalogues the tools but
        grants none of them (see the class docstring).

        Args:
            agent_id: Agent slug (e.g., "research-analyst")
            tools: List of tool dicts with name, description, action_verb, input_schema
            framework: Framework name (e.g., "google_adk")

        Returns:
            True if the registry accepted the report, False otherwise.
        """
        headers = {"x-agent-id": agent_id}
        if self._api_key:
            headers["x-api-key"] = self._api_key

        payload = {"tools": tools}
        if framework:
            payload["framework"] = framework

        try:
            resp = await self.client.post(
                f"/api/v1/agents/{agent_id}/tools",
                json=payload,
                headers=headers,
            )
            if resp.status_code in (200, 201):
                data = resp.json()
                count = data.get("registered", len(tools))
                logger.info(
                    "Reported %d tool(s) to the registry inventory for agent '%s'",
                    count,
                    agent_id,
                )
                return True
            else:
                logger.warning(
                    "Registry tool inventory report failed: HTTP %d", resp.status_code
                )
                return False
        except httpx.ConnectError:
            logger.debug("Registry not reachable (ConnectError) — skipping tool inventory report")
            return False
        except Exception as e:
            logger.debug("Registry tool inventory report error: %s", type(e).__name__)
            return False

    async def close(self):
        if self._client and not self._client.is_closed:
            await self._client.aclose()
        self._client = None
