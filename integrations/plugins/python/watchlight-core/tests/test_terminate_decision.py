"""Enforcement-effect Terminate — tests for the Python lane.

These tests pin down the Terminate enforcement effect
(A · Halt/contain) as it wires through the decision parser and
``BaseRunHandle``:

- The wl-apdp Terminate wire shape (``decision: "Terminate"`` +
  ``details.enforcement`` with ``effect == "terminate"``) deserialises
  into a typed :class:`TerminateDecision` carrying the ``policy_id``.
- A Terminate response ends the CURRENT run: ``authorize_action``
  raises :class:`ExecutionTerminatedError`, fires the kill signal with
  ``reason=policy_terminate``, and transitions the handle to
  :class:`RunHandleState.COMPLETED` — NOT ``QUARANTINED``. The agent is
  not bagged: ``handle.is_quarantined()`` stays ``False``.
- A fresh run after a Terminate is clean (a new handle authorizes
  normally — the agent was not durably contained).
- :class:`ExecutionTerminatedError` is catchable by the same generic
  ``except Exception`` handler pattern the deny/quarantine paths use,
  while an effect-aware handler can match the specific type.

Terminate contrasts with Quarantine at every load-bearing point, so
these mirror ``test_quarantine_decision.py`` / ``test_quarantine_kill_signal.py``
but assert the *differences*: no durable state, no parent propagation,
COMPLETED (not QUARANTINED), and a distinct kill-signal reason token.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import List, Optional

import pytest
import pytest_asyncio

from watchlight_core import (
    AgentQuarantinedError,
    BaseRunHandle,
    ExecutionTerminatedError,
    LLM_CALL_INTERRUPTED_REASON_POLICY_TERMINATE,
    RunHandleState,
    TerminateDecision,
    parse_authorization_decision,
)
from watchlight_core.telemetry import GovernanceTelemetry
from watchlight_core_testing import MockApdpClient


# ─── Stub kill-signal registry (mirrors test_quarantine_kill_signal) ─


@dataclass
class _CountingKillRegistry:
    """Counts ``cancel`` calls so tests assert on invocation shape."""

    cancel_calls: List[str] = field(default_factory=list)

    async def cancel(self, reason: str) -> list:
        self.cancel_calls.append(reason)
        return []


# ─── Plugin + handle fixtures ────────────────────────────────────────


class _Plugin(GovernanceTelemetry):
    """Minimal plugin satisfying the GovernedPlugin Protocol + the
    optional ``kill_signal_registry`` attribute.
    """

    def __init__(
        self,
        kill_signal_registry: Optional[_CountingKillRegistry] = None,
    ) -> None:
        super().__init__()
        self.apdp = MockApdpClient()
        self.apdp.known_agents["agent-x"] = "uuid-x"
        self.tenant_id = "tenant-acme"
        self.log_decisions = False
        self.kill_signal_registry = kill_signal_registry


@pytest.fixture
def registry() -> _CountingKillRegistry:
    return _CountingKillRegistry()


@pytest.fixture
def plugin(registry: _CountingKillRegistry) -> _Plugin:
    return _Plugin(kill_signal_registry=registry)


@pytest_asyncio.fixture
async def handle(plugin: _Plugin) -> BaseRunHandle:
    h = BaseRunHandle(plugin=plugin, agent_uuid="uuid-x", session_id="ses_x")
    # synthetic test handle bypasses the production ``async with``
    # entry path; flip the fail-closed flag so the contract guard
    # accepts the test's direct authorize calls.
    h._aentered = True
    return h


def _terminate_wire_payload() -> dict:
    """The exact wire shape wl-apdp emits on a policy-driven Terminate.

    Mirrors the enforcement-effects wire contract.
    """
    return {
        "decision": "Terminate",
        "reason": "Execution terminated by policy forbid-runaway-loop",
        "details": {
            "enforcement": {
                "effect": "terminate",
                "severity": 1,
                "reason": "policy_terminate",
                "lift_required": False,
                "policy_id": "forbid-runaway-loop",
            }
        },
    }


# ─── Test (a) — parser returns a TerminateDecision ───────────────────


def test_parse_terminate_wire_returns_terminate_decision() -> None:
    """The Terminate wire shape deserialises into a typed
    :class:`TerminateDecision` carrying the enforcement-block
    ``policy_id`` and the top-level ``reason``.
    """
    typed = parse_authorization_decision(_terminate_wire_payload())

    assert isinstance(typed, TerminateDecision)
    assert typed.kind == "terminate"
    assert typed.policy_id == "forbid-runaway-loop"
    assert typed.reason == "Execution terminated by policy forbid-runaway-loop"


def test_parse_terminate_falls_back_to_determining_policy_id() -> None:
    """When the enforcement block lacks a ``policy_id`` but the wire
    surfaces ``determining_policy_id`` at the top level, the parser
    uses that as the fallback.
    """
    payload = {
        "decision": "Terminate",
        "reason": "terminated",
        "determining_policy_id": "top-level-pid",
        "details": {"enforcement": {"effect": "terminate", "severity": 1}},
    }
    typed = parse_authorization_decision(payload)
    assert isinstance(typed, TerminateDecision)
    assert typed.policy_id == "top-level-pid"


def test_parse_terminate_ignores_non_terminate_effect_block() -> None:
    """Defensive: a ``Terminate`` decision whose enforcement block
    claims a *different* effect must not mis-attribute that effect's
    policy_id to the TerminateDecision. ``policy_id`` stays ``None``
    (no top-level fallback present).
    """
    payload = {
        "decision": "Terminate",
        "reason": "terminated",
        "details": {
            "enforcement": {"effect": "quarantine", "policy_id": "wrong-pid"}
        },
    }
    typed = parse_authorization_decision(payload)
    assert isinstance(typed, TerminateDecision)
    assert typed.policy_id is None


def test_parse_terminate_default_reason_when_absent() -> None:
    """A Terminate wire with no top-level reason gets the model's
    non-empty default rather than an empty string.
    """
    typed = parse_authorization_decision(
        {"decision": "Terminate", "details": {"enforcement": {"effect": "terminate"}}}
    )
    assert isinstance(typed, TerminateDecision)
    assert typed.reason == "Execution terminated"


# ─── Test (b) — authorize raises ExecutionTerminatedError, not bagged ─


@pytest.mark.asyncio
async def test_terminate_raises_error_and_does_not_bag_agent(
    plugin: _Plugin,
    handle: BaseRunHandle,
    registry: _CountingKillRegistry,
) -> None:
    """A Terminate response ends the current run:

    - ``authorize_action`` raises :class:`ExecutionTerminatedError`.
    - the kill signal fires with ``reason=policy_terminate``.
    - the handle transitions to ``COMPLETED`` (NOT ``QUARANTINED``).
    - ``is_quarantined()`` stays ``False`` — the agent is not bagged.
    """
    plugin.apdp.default_decision = "Terminate"

    with pytest.raises(ExecutionTerminatedError) as exc_info:
        await handle.authorize_action("execute", "Tool::scanner")

    # Yield so the create_task scheduled by _fire_kill_signal runs.
    await asyncio.sleep(0)

    # Terminal state is COMPLETED, NOT QUARANTINED.
    assert handle.state == RunHandleState.COMPLETED
    assert handle.is_quarantined is False
    # The stored quarantine decision was NOT populated — the agent is
    # not durably contained.
    assert handle.quarantine_decision is None

    # Kill signal fired with the policy_terminate reason token
    # (distinct from quarantine).
    assert registry.cancel_calls == [LLM_CALL_INTERRUPTED_REASON_POLICY_TERMINATE]

    # The typed error carries the policy id + reason.
    assert exc_info.value.policy_id == "synthetic.terminate"
    assert "terminate" in str(exc_info.value).lower()


@pytest.mark.asyncio
async def test_terminate_marks_run_completed_idempotently(
    plugin: _Plugin,
    handle: BaseRunHandle,
) -> None:
    """After a Terminate the run is already terminal — a subsequent
    ``terminate()`` / ``complete()`` is an idempotent no-op that does
    not round-trip to wl-apdp for a fresh session-close.
    """
    plugin.apdp.default_decision = "Terminate"

    with pytest.raises(ExecutionTerminatedError):
        await handle.authorize_action("execute", "Tool::scanner")
    await asyncio.sleep(0)

    closed_before = list(plugin.apdp._closed_sessions)
    terminated_before = list(plugin.apdp._terminated_sessions)

    # Both lifecycle methods short-circuit at the _completed guard —
    # no fresh session-close / terminate round-trip to wl-apdp.
    await handle.terminate("late")
    await handle.complete()

    assert plugin.apdp._closed_sessions == closed_before
    assert plugin.apdp._terminated_sessions == terminated_before
    assert handle.state == RunHandleState.COMPLETED


# ─── Test (c) — a fresh run after Terminate is clean ─────────────────


@pytest.mark.asyncio
async def test_fresh_run_after_terminate_is_clean(plugin: _Plugin) -> None:
    """Terminate does NOT bag the agent — a brand-new handle
    (representing a fresh ``start_run``) authorizes normally, proving
    there is no durable contained state leaking across executions.
    """
    plugin.apdp.default_decision = "Terminate"

    h1 = BaseRunHandle(plugin=plugin, agent_uuid="uuid-x", session_id="ses_1")
    h1._aentered = True
    with pytest.raises(ExecutionTerminatedError):
        await h1.authorize_action("execute", "Tool::scanner")
    await asyncio.sleep(0)
    assert h1.state == RunHandleState.COMPLETED
    assert h1.is_quarantined is False

    # Fresh run — now the policy no longer terminates (clean).
    plugin.apdp.default_decision = "Allow"
    h2 = BaseRunHandle(plugin=plugin, agent_uuid="uuid-x", session_id="ses_2")
    h2._aentered = True
    allowed = await h2.authorize_action("execute", "Tool::scanner")
    assert allowed is True
    assert h2.state == RunHandleState.ACTIVE
    assert h2.is_quarantined is False


# ─── Test (d) — generic + effect-aware handler both catch it ─────────


@pytest.mark.asyncio
async def test_terminate_error_caught_by_generic_handler(
    plugin: _Plugin,
    handle: BaseRunHandle,
) -> None:
    """:class:`ExecutionTerminatedError` is catchable by the same
    generic ``except Exception`` handler pattern customer agent code
    uses for the deny/quarantine raise path — while still being a
    distinct, effect-aware type.
    """
    plugin.apdp.default_decision = "Terminate"

    caught_generic = False
    try:
        await handle.authorize_action("execute", "Tool::scanner")
    except Exception as exc:  # noqa: BLE001 — intentional generic catch
        caught_generic = True
        # The generic handler still sees the specific type.
        assert isinstance(exc, ExecutionTerminatedError)
    assert caught_generic

    # And an effect-aware handler distinguishes Terminate from
    # Quarantine — an ExecutionTerminatedError is NOT an
    # AgentQuarantinedError (and vice-versa), so agent code can branch.
    assert not issubclass(ExecutionTerminatedError, AgentQuarantinedError)
    assert not issubclass(AgentQuarantinedError, ExecutionTerminatedError)


@pytest.mark.asyncio
async def test_terminate_does_not_propagate_to_parent(
    registry: _CountingKillRegistry,
) -> None:
    """Terminate is scoped to the CURRENT run only — unlike Quarantine
    it does NOT propagate up the parent chain. A parent handle stays
    ACTIVE and its registry is NOT fired when a child is terminated.
    """
    parent_registry = _CountingKillRegistry()
    child_registry = _CountingKillRegistry()

    parent_plugin = _Plugin(kill_signal_registry=parent_registry)
    child_plugin = _Plugin(kill_signal_registry=child_registry)

    parent = BaseRunHandle(
        plugin=parent_plugin, agent_uuid="uuid-root", session_id="ses_root"
    )
    parent._aentered = True
    child = BaseRunHandle(
        plugin=child_plugin,
        agent_uuid="uuid-child",
        session_id="ses_child",
        parent_handle=parent,
    )
    child._aentered = True

    child_plugin.apdp.default_decision = "Terminate"

    with pytest.raises(ExecutionTerminatedError):
        await child.authorize_action("execute", "Tool::scanner")
    await asyncio.sleep(0)

    # Child terminated; parent untouched.
    assert child.state == RunHandleState.COMPLETED
    assert parent.state == RunHandleState.ACTIVE
    assert child_registry.cancel_calls == [
        LLM_CALL_INTERRUPTED_REASON_POLICY_TERMINATE
    ]
    assert parent_registry.cancel_calls == []
