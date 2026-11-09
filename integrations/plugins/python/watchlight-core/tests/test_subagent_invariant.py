"""Unit tests for the sub-agent governance invariant (invariant 8).

Added 2026-06-13 as part of the conformance suite — locks in the
sub-agent privilege-escalation fix documented in the subagent
governance audit.

Exercises ``_assert_subagent_authz_attribution`` directly so the
invariant has explicit tests independent of the larger
``run_conformance`` harness.
"""

import pytest

from watchlight_core_testing.conformance import _assert_subagent_authz_attribution
from watchlight_core_testing import ConformanceFailure, MockApdpClient


def _root_call(uuid: str) -> dict:
    return {
        "principal": f'Agent::"{uuid}"',
        "action": 'Action::"execute"',
        "resource": 'Resource::"test_tool"',
        "execution_id": "exec_root",
        "session_id": "sess_root",
    }


def _subagent_call(uuid: str, *, resource: str) -> dict:
    return {
        "principal": f'Agent::"{uuid}"',
        "action": 'Action::"execute"',
        "resource": f'Resource::"{resource}"',
        "execution_id": "exec_subagent",
        "session_id": "sess_subagent",
    }


class TestSubagentInvariant:
    def test_passes_vacuously_when_no_subagent_authz_happens(self):
        mock = MockApdpClient()
        mock.authorize_calls.append(_root_call("uuid-root"))
        # No call for the sub-agent's resource — invariant passes.
        _assert_subagent_authz_attribution(
            mock, root_uuid="uuid-root", subagent_uuid="uuid-subagent"
        )

    def test_passes_when_subagent_authz_uses_subagent_principal(self):
        mock = MockApdpClient()
        mock.authorize_calls.append(_root_call("uuid-root"))
        mock.authorize_calls.append(
            _subagent_call("uuid-subagent", resource="test_subagent_tool")
        )
        _assert_subagent_authz_attribution(
            mock, root_uuid="uuid-root", subagent_uuid="uuid-subagent"
        )

    def test_fails_when_subagent_tool_authorized_against_root_principal(self):
        """Replicates the sub-agent privilege-escalation bug shape: a tool call attributed to the
        sub-agent's tool resource but authorized with the ROOT's
        principal must raise ConformanceFailure(8, ...).
        """
        mock = MockApdpClient()
        # Sub-agent's authz call uses the SUB-AGENT's principal (good)
        # — invariant 8 detects the bug only when sub-agent authz HAS
        # happened.
        mock.authorize_calls.append(
            _subagent_call("uuid-subagent", resource="test_subagent_tool")
        )
        # Then a second call for the sub-agent's tool gets authorized
        # against the ROOT — this is the bug.
        mock.authorize_calls.append(
            _subagent_call("uuid-root", resource="test_subagent_tool")
        )
        with pytest.raises(ConformanceFailure) as exc_info:
            _assert_subagent_authz_attribution(
                mock, root_uuid="uuid-root", subagent_uuid="uuid-subagent"
            )
        assert exc_info.value.args[0] == 8
        assert "privilege" in exc_info.value.args[1]


class TestMockApdpClientCapturesPrincipal:
    """Sanity-check: MockApdpClient now records every authorize call's
    principal so invariant 8 can introspect what was used."""

    @pytest.mark.asyncio
    async def test_authorize_records_principal(self):
        mock = MockApdpClient()
        await mock.authorize(
            principal='Agent::"uuid-1"',
            action='Action::"execute"',
            resource='Resource::"tool_x"',
            context={},
            execution_id="exec",
            session_id="sess",
        )
        assert len(mock.authorize_calls) == 1
        assert mock.authorize_calls[0]["principal"] == 'Agent::"uuid-1"'
        assert mock.authorize_calls[0]["resource"] == 'Resource::"tool_x"'
