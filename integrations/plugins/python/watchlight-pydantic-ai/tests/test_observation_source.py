"""Per-plugin override of :attr:`BaseRunHandle._observation_source`.

Asserts that the Pydantic AI plugin's :class:`RunHandle` subclass
stamps ``metadata.source = "pydantic-ai.workload"`` on every event
emitted via
:meth:`watchlight_core.BaseRunHandle.publish_observation`.
"""

from __future__ import annotations

from typing import Optional

import pytest

from watchlight_core.telemetry import GovernanceTelemetry
from watchlight_core_testing import MockApdpClient
from watchlight_pydantic_ai import RunHandle


class _Plugin(GovernanceTelemetry):
    def __init__(self, tenant_id: Optional[str] = "tenant-acme") -> None:
        super().__init__()
        self.apdp = MockApdpClient()
        self.tenant_id = tenant_id
        self.log_decisions = False
        self.kill_signal_registry = None


def test_runhandle_observation_source_is_pydantic_ai_workload() -> None:
    """The class attribute MUST be exactly ``"pydantic-ai.workload"``."""
    assert RunHandle._observation_source == "pydantic-ai.workload"


@pytest.mark.asyncio
async def test_publish_observation_stamps_pydantic_ai_workload_source() -> None:
    """The emitted envelope's ``metadata.source`` carries the Pydantic
    AI plugin's identifier.
    """
    plugin = _Plugin()
    handle = RunHandle(
        plugin=plugin,
        agent_uuid="agent-uuid-pa",
        session_id="ses_pa",
    )
    handle._aentered = True  # synthetic test handle

    await handle.publish_observation(
        "execution_failed",
        payload={
            "duration_ms": 0,
            "error": "smoke",
            "policy_denied": False,
        },
    )

    # The handle publishes a defensive ``execution_started`` before the
    # observation; the source stamp must be present on the workload
    # event itself.
    obs = [
        e for e in plugin.apdp.published_events
        if e["event_type"] == "execution_failed"
    ]
    assert len(obs) == 1
    assert obs[0]["metadata"]["source"] == "pydantic-ai.workload"
