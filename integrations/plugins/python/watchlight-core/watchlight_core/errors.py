"""Shared error hierarchy for Watchlight framework plugins.

All plugin errors derive from :class:`WatchlightError`. Two
fail-closed signals every plugin must surface to its caller:

- :class:`AgentNotRegistered` — slug → UUID resolution failed; the
  agent isn't registered with Watchlight. Caller MUST refuse to run.
- :class:`GovernanceUnavailable` — APDP didn't accept the session
  create. Caller MUST refuse to run.

These two are the load-bearing fail-closed states; framework-specific
errors should subclass :class:`WatchlightError` directly rather than
overloading the meaning of these.

Two further typed signals cover the sub-agent scope attenuation lane:

- :class:`ScopeAttenuationDenied` — APDP rejected a
  ``POST /v1/spawn_subagent`` because ``requested_scope`` exceeded
  ``parent_effective_scope`` along one or more dimensions.
- :class:`RunHandleInvalidated` — APDP rejected the spawn because the
  parent's RunHandle has been invalidated (time budget expired, kill
  signal fired, or the parent itself was quarantined).

Both are deliberately typed (not strings) so plugin call sites can
``except`` the exact signal they want to surface to the agent.
"""

from __future__ import annotations

from enum import Enum
from typing import List, Optional


class WatchlightError(Exception):
    """Base class for all Watchlight plugin errors."""


class WatchlightContractError(WatchlightError):
    """Fail-closed signal that a Watchlight SDK contract was violated.

    Raised when the caller invokes an SDK primitive in a state that
    the contract forbids — typically because a required preceding
    step was skipped or a mutually-exclusive argument was supplied.

    Current uses:

    * Calling :meth:`watchlight_core.BaseRunHandle.authorize_action`
      (or ``authorize_action_detailed``) without first entering the
      handle's ``async with`` block. Per the closed-set lineage
      contract, every
      Cedar evaluation MUST attach to an execution whose
      ``execution_started`` was emitted earlier — and the handle's
      ``__aenter__`` is the only place that emission lands by
      default. Calling ``authorize_action`` outside the
      ``async with`` block silently produces a
      ``policy_decision_made`` event with no corresponding
      ``execution_started``, which the dashboard's ``/lineage`` view
      cannot render (the closed-set allowlist gate
      hides the orphan, so the operator sees no audit row at all —
      the worst observability outcome).

    * Calling :meth:`watchlight_core.BaseRunHandle.publish_observation`
      without first entering the handle's ``async with`` block, OR
      with an explicit ``execution_id`` that does NOT match the
      handle's own ``execution_id``. The wire envelope MUST attribute
      every event to the open handle's execution; a divergent value
      would emit an orphan into a different execution's tree.
      Workloads with a genuine cross-execution observation need will
      get a dedicated ``publish_observation_for_execution(...)``
      method (a planned follow-up). There is NO
      ``allow_no_run_handle`` escape hatch on
      ``publish_observation`` — the contract is locked at the
      boundary.

    Following a fail-closed-on-ambiguity discipline (refuse unsafe
    states at the boundary), the SDK raises this error rather than
    emitting a half-attributed event the operator would have to debug after
    the fact. Customers who legitimately need to call
    ``authorize_action`` outside the ``async with`` block (rare —
    typically bootstrap or setup paths) can pass
    ``allow_no_run_handle=True`` to opt out of the guard; the
    docstring on the kwarg carries the strong warning.
    """


class AgentNotRegistered(WatchlightError):
    """The agent slug isn't registered with Watchlight.

    Caller MUST fail closed — an unknown agent must not get to make
    tool calls. This is not a transient error; do not retry.
    """


class GovernanceUnavailable(WatchlightError):
    """APDP didn't accept the session create.

    Caller MUST refuse to proceed. This is potentially transient
    (network hiccup, APDP restart) but the right behaviour at the
    plugin layer is still fail-closed; let an outer retry layer
    decide whether to re-attempt the run.
    """


class IntentRefused(WatchlightError, ValueError):
    """An intent wl-apdp could not parse or that this SDK will not send.

    Raised before any request goes out when a caller passes an intent that
    is not a typed intent (an objective AND a category wl-apdp accepts, an
    optional string justification), or that mixes a caller objective with
    a declared category. Sending nothing in its place would skip the
    server's intent validation (and the approval gates it carries), so the
    action is refused instead. A ``ValueError`` too, so a programmatic
    caller passing a bad argument sees the usual type.
    """


class GovernanceRefused(GovernanceUnavailable):
    """wl-apdp answered with a definitive refusal (``401`` / ``403``).

    Not an outage: the server decided. Carries the server's typed refusal
    code so a caller can branch on it instead of matching message text:

    - ``status_code`` — the HTTP status.
    - ``error`` / ``reason`` — the snake_case codes the server sent, if any
      (``{"error": "delegation_chain_not_trusted"}``,
      ``{"reason": "..."}``, or ``{"error": {"code": "agent_trust_revoked"}}``).
      Only a bounded snake_case code is kept, never free text from the body.
    - ``code`` — ``reason`` when the server sent one, otherwise ``error``.

    Raised for a refused ``POST /v1/spawn_subagent`` and a refused
    constraint-manifest fetch. A refusal is never degraded: it refuses the
    run even when ``WATCHLIGHT_PLAN_GOVERNANCE_MODE=degrade``. A subclass of
    :class:`GovernanceUnavailable`, so code that already refuses on that
    error keeps refusing.
    """

    def __init__(
        self,
        message: str,
        *,
        status_code: int,
        error: Optional[str] = None,
        reason: Optional[str] = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.error = error
        self.reason = reason

    @property
    def code(self) -> Optional[str]:
        """The server's refusal code: ``reason``, else ``error``."""
        return self.reason or self.error


#: The refusal code wl-apdp sends when a run is opened without naming an
#: agent and the caller's credential is not bound to one agent.
CREDENTIAL_BINDS_NO_AGENT = "credential_binds_no_agent"


class CredentialBindsNoAgent(GovernanceRefused):
    """A root run was opened without naming an agent, and the credential
    it was opened with is not bound to one agent.

    wl-apdp opens a slug-less root run as the agent its caller's verified
    credential is bound to (an agent API key today; an AWS workload role
    mapping once that lands in wl-apdp). A credential that binds no
    single agent (a plugin credential shared by a tenant, a service
    credential) gets this refusal: nothing guesses an agent and there is
    no default one. Either name the agent, or use an agent-bound
    credential.

    In the Developer Edition (:class:`~watchlight_core.InProcessClient`)
    there is no credential: the equivalent is the process's configured
    identity (the ``agent=`` argument or ``WATCHLIGHT_AGENT``), and this
    error is raised when neither is set.

    A subclass of :class:`GovernanceRefused` (and so of
    :class:`GovernanceUnavailable`): code that already refuses on those
    keeps refusing. Not transient; do not retry.
    """

    def __init__(self, message: str, *, status_code: int = 403) -> None:
        super().__init__(
            message, status_code=status_code, error=CREDENTIAL_BINDS_NO_AGENT
        )


#: The refusal codes the server sends for a declared root: Cedar
#: denied ``Action::"open_declared_root"``, or the declaration was malformed
#: or named an id that is not a live root of the caller's tenant.
DECLARED_ROOT_FORBIDDEN = "declared_root_forbidden"
DECLARED_ROOT_INVALID = "declared_root_invalid"
#: Local code: the backend cannot open a declared root, or the server did
#: not confirm that it evaluated the declaration.
DECLARED_ROOT_UNSUPPORTED = "declared_root_unsupported"


class DeclaredRootRefused(GovernanceRefused):
    """A declared root run was not opened.

    ``code`` says why: ``declared_root_forbidden`` (policy denied
    ``Action::"open_declared_root"``), ``declared_root_invalid`` (the
    declaration was refused as given), or ``declared_root_unsupported``
    (this backend cannot open one, or the server answered without
    confirming it evaluated the declaration; any session it opened is
    ended). The agent does not run. Not transient; do not retry.
    """

    def __init__(self, message: str, *, code: str, status_code: int = 403) -> None:
        super().__init__(message, status_code=status_code, error=code)


class NestedRunEscapedError(WatchlightError):
    """An agent run was refused before its first model turn because it
    would open a root outside the governed run it came from.

    A run that resolves to no parent while a governed run is live in the
    process was started from code that lost the run's context (an
    executor, a thread, a fresh ``contextvars.Context``). It is never
    promoted to an independent root. Call the agent from the run (``await``,
    ``iter`` or ``asyncio.to_thread``) so it is spawned as a sub-agent, or
    declare an independent root explicitly where the framework plugin
    offers one.

    ``reason`` is a short code: ``implicit_root_while_run_live``,
    ``declared_root_inside_live_run`` or ``spawn_refused_in_live_tree``.
    """

    def __init__(self, message: str, *, reason: str) -> None:
        super().__init__(message)
        self.reason = reason


class SpawnRefusedRootRunError(NestedRunEscapedError):
    """A declared root was refused for an agent whose sub-agent spawn was
    refused in a governed run tree that is still live. A refused
    child never runs, including as a root of its own."""

    def __init__(self, message: str) -> None:
        super().__init__(message, reason="spawn_refused_in_live_tree")


class RunUncredentialed(GovernanceUnavailable):
    """A run without a run credential was refused locally.

    Every call a backend makes for a run carries that run's own ``sst_``
    credential; a run never acts on the shared plugin bearer alone. A
    session the server opened without a run credential is refused when it
    is registered, and no call is sent for a run whose credential is gone.
    A subclass of :class:`GovernanceUnavailable`.
    """


class ParentRunUncredentialed(RunUncredentialed):
    """A sub-agent spawn was refused locally: the parent run holds no run
    credential (it never got one, or it was cleared when the run ended or
    was dropped).

    The spawn is authenticated with the parent run's own credential, never
    with the shared tenant bearer, so no request is sent and the child
    never runs. A subclass of :class:`GovernanceUnavailable`: code that
    already refuses on that error keeps refusing.
    """


class SidecarRunActive(GovernanceUnavailable):
    """A run was refused locally: another governed run in this process
    still owns the egress sidecar.

    One ``wl-sidecar`` carries one run's egress credential, and every HTTP
    library in the process reaches it through the process-wide
    ``HTTP(S)_PROXY``. Starting a second sidecar would move that run's
    traffic onto the new run's credential, so the new run is refused
    before its sidecar is started, and the running one is left as it is.
    Run concurrent governed runs in separate processes. A subclass of
    :class:`GovernanceUnavailable`.
    """


class EngineVersionUnsupported(WatchlightError):
    """The installed ``watchlight-engine`` is older than this SDK requires.

    Raised when :class:`~watchlight_core.InProcessClient` is constructed, so
    an engine that lacks the SDK's hardening never answers a decision.
    Nothing falls back to a networked backend or to an allow: the client is
    not built. Upgrade with ``pip install "watchlight-engine>=0.2.5,<0.3"``.

    Not a subclass of :class:`ImportError`, so code that falls back when the
    engine is absent does not also fall back when the engine is too old.
    """

    def __init__(self, *, required: str, found: str) -> None:
        super().__init__(
            f"InProcessClient requires watchlight-engine {required} or later; "
            f"found {found}. Upgrade it with "
            f'`pip install "watchlight-engine>={required},<0.3"`.'
        )
        #: The lowest engine version this SDK accepts, e.g. ``"0.2.5"``.
        self.required: str = required
        #: The version the installed engine reported (``"unknown"`` when it
        #: reported none, or one that could not be read).
        self.found: str = found


class CredentialProbeFailed(WatchlightError):
    """The startup probe (``GET /health`` with credential headers) did
    not return a healthy 200.

    Raised by :meth:`ApdpClient.probe` and (when ``auto_probe=True``,
    the default) by the first authenticated method call after
    construction. Carries the HTTP status code so callers can branch:

    - ``401`` — credential is invalid, missing, expired, or revoked.
    - ``403`` — credential doesn't satisfy the server's required claims.
    - ``404`` — APDP isn't running at this URL.
    - ``None`` — transport failure (connection refused, DNS, TLS handshake).

    Follows the design rule that client construction fails on
    misconfiguration rather than silently producing 401s on every
    subsequent call.
    """

    def __init__(self, message: str, *, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


class InsecureChannelError(WatchlightError):
    """The configured APDP URL would send credentials over an insecure
    channel.

    Plain ``http://`` is rejected for any host that is not loopback
    (``localhost`` / ``127.0.0.1`` / ``::1``). The channel guard runs
    at :class:`ApdpClient` construction so misconfiguration fails
    fast at startup rather than leaking a bearer token over a single
    plaintext request.

    Matches the same rule enforced on the Rust server side.

    Operators who need a non-TLS channel for genuine local-dev /
    sidecar deployments should use ``http://localhost`` (the loopback
    exemption); production-style customer plugins must use
    ``https://``.
    """


# ─── sub-agent scope attenuation typed errors ────────────────


class ScopeViolationDimension(str, Enum):
    """Canonical dimension labels that the strict-subset validator
    stamps on each violation.

    The string values are the wire spelling — APDP returns them inside
    the 403 response's ``violations`` array so the Python lane can
    deserialise without an extra mapping table. Parity with the Rust
    enum of the same name is asserted by a cross-lane fixture.

    v1 dimensions:

    - ``allowed_tools`` — tool name not in parent's allowlist.
    - ``allowed_resources`` — resource matcher not in parent's
      allowlist (set-membership via the rendered string form).
    - ``allowed_intents`` — declared intent objective not in parent's
      allowlist (exact-string match).
    - ``max_depth`` — requested depth would exceed
      ``parent_effective.max_depth - 1``.
    - ``time_budget_seconds`` — requested time budget exceeds the
      tenant-configured ceiling OR the parent's remaining budget.
    - ``cross_tenant`` — child's principal record lives in a different
      tenant than the parent.
    - ``parent_handle_invalidated`` — parent's RunHandle is no longer
      valid (a spawn-time race; surfaced as a violation rather than its
      own typed exception when APDP folded both signals into one error
      envelope).
    """

    ALLOWED_TOOLS = "allowed_tools"
    ALLOWED_RESOURCES = "allowed_resources"
    ALLOWED_INTENTS = "allowed_intents"
    MAX_DEPTH = "max_depth"
    TIME_BUDGET_SECONDS = "time_budget_seconds"
    CROSS_TENANT = "cross_tenant"
    PARENT_HANDLE_INVALIDATED = "parent_handle_invalidated"

    @classmethod
    def from_wire(cls, value: object) -> "ScopeViolationDimension":
        """Decode a wire string into the enum, falling back to a
        best-effort match when APDP grew a new dimension before the
        SDK was updated. Unknown strings raise ``ValueError`` — the
        caller's intent is to surface the violation to the agent, not
        to silently downgrade.
        """
        if isinstance(value, cls):
            return value
        if not isinstance(value, str):
            raise ValueError(
                f"ScopeViolationDimension wire value must be str, "
                f"got {type(value).__name__}"
            )
        for member in cls:
            if member.value == value:
                return member
        # Wire-spelling aliases: the engine/validator emits the shorter
        # ``time_budget`` for what the SDK enum spells ``time_budget_seconds``.
        # Accept both so a time-budget overreach surfaces the typed dimension
        # (not just the ``reason`` string) on the in-process and networked paths.
        if value in _WIRE_ALIASES:
            return _WIRE_ALIASES[value]
        raise ValueError(
            f"unknown ScopeViolationDimension wire value {value!r}; "
            f"the SDK may be older than the APDP that returned it"
        )


#: Accepted wire spellings that differ from the canonical enum ``value``.
_WIRE_ALIASES = {"time_budget": ScopeViolationDimension.TIME_BUDGET_SECONDS}


class ScopeAttenuationDenied(WatchlightError):
    """APDP rejected ``POST /v1/spawn_subagent`` because the requested
    scope exceeded the parent's effective scope along one or more
    dimensions.

    The strict-subset validator returns this when, at spawn
    time, ``requested_scope ⊄ parent_effective_scope``. The
    ``violations`` list carries one
    :class:`ScopeViolationDimension` per offending axis so the agent's
    runtime can render a precise diagnostic — operator-grade detail,
    not a stringly-typed error.

    The corresponding wire shape is the 403 response:

    .. code-block:: json

        {
          "reason": "scope_attenuation_violation",
          "violations": ["allowed_tools", "max_depth"]
        }

    The error message is deliberately concise; the structured
    ``violations`` list is the canonical data carrier. The governing
    invariant is "fail closed + raise anomaly + show in lineage."
    """

    def __init__(
        self,
        reason: str,
        violations: Optional[List[ScopeViolationDimension]] = None,
        *,
        reason_code: Optional[str] = None,
        observed_depth: Optional[int] = None,
        max_delegation_depth: Optional[int] = None,
        message: Optional[str] = None,
    ) -> None:
        # ``reason`` is the stable code; ``message`` an optional sentence
        # for humans (the code when absent).
        super().__init__(message or reason or "scope_attenuation_violation")
        self.reason: str = reason or "scope_attenuation_violation"
        self.violations: List[ScopeViolationDimension] = list(violations or [])
        #: ``"DELEGATION_DEPTH_EXCEEDED"`` when the spawn was refused because the
        #: tree is already at its depth limit (a governance control, not a
        #: widening request); ``None`` for a scope that is not a strict subset.
        self.reason_code: Optional[str] = reason_code
        #: With ``reason_code``: the depth the refused child would have had
        #: (the root agent is depth 0).
        self.observed_depth: Optional[int] = observed_depth
        #: With ``reason_code``: the depth limit in force for the tree.
        self.max_delegation_depth: Optional[int] = max_delegation_depth

    def __repr__(self) -> str:  # pragma: no cover — diagnostic
        return (
            f"ScopeAttenuationDenied(reason={self.reason!r}, "
            f"violations={[v.value for v in self.violations]!r})"
        )


class RunHandleInvalidated(WatchlightError):
    """APDP rejected the spawn because the parent's RunHandle is no
    longer valid.

    Surfaces the race condition where the parent's scope was revoked
    between spawn-issuance and spawn-time, AND the kill-signal cascade
    (parent was quarantined; descendants are bagged with it).

    Carries an operator-facing reason string. The SDK does NOT retry —
    a parent whose handle is invalidated cannot delegate; the agent's
    framework MUST surface the failure to the orchestrator and let it
    decide whether to re-establish a parent run.
    """

    def __init__(self, reason: str) -> None:
        super().__init__(reason or "run_handle_invalidated")
        self.reason: str = reason or "run_handle_invalidated"
