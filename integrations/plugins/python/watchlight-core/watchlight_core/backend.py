"""The governance backend interface the SDK and the plugins call.

A plugin never holds a backend credential. A backend opens a run and hands
back an opaque :data:`RunRef`; every later call names the run by that
reference, and the backend resolves whatever credential the run needs
itself. Run references are not secrets and carry no meaning outside the
backend that issued them.

Two backends implement :class:`GovernanceBackend` today:

* :class:`watchlight_core.InProcessClient` (Developer Edition): the compiled
  engine in this process and a local audit file. It holds no credential.
* :class:`watchlight_core.ApdpClient` (Enterprise): keeps each run's
  credentials in an internal table keyed by :data:`RunRef`.

Fail closed: a backend refuses a run reference it did not issue, or one
whose run has ended, with the refusal its method already uses for an
uncertain answer (a ``Deny``, ``None``, ``False`` or a typed error). Two
documented exceptions:

* An ended run's late lineage (``publish_events``, ``drain``) is still
  accepted: a run's terminal event is published after its session closes.
  Backends keep ended runs for this within a fixed bound.
* ``run=None`` names no run at all (not an unknown one). ``ApdpClient``
  refuses to publish lineage for it (no run credential), and sends an
  ``authorize`` / ``get_manifest`` without a run credential. The in-process
  Developer Edition backend has no run credential to require, so it decides
  ``authorize`` and writes ``publish_events`` for ``run=None`` (the
  ``@watchlight`` decorator's events).

A run whose handle is garbage-collected without being closed is ended by
the backend (``_release_dropped_run``), so a dropped handle does not keep
its run live.
"""

from __future__ import annotations

import inspect
import math
from dataclasses import dataclass, field
from datetime import datetime
from typing import (
    Any,
    Callable,
    Dict,
    List,
    Mapping,
    NewType,
    Optional,
    Protocol,
    Sequence,
    runtime_checkable,
)

__all__ = [
    "RunRef",
    "SessionInfo",
    "PUBLIC_SESSION_KEYS",
    "public_session_record",
    "KillNotice",
    "KillCallback",
    "Unsubscribe",
    "EgressBinding",
    "GovernanceBackend",
    "KillSubscriptions",
    "egress_binding_for",
    "fetch_egress_binding",
]

#: An opaque reference to one run, issued by the backend that opened it.
#: It is not a credential: holding it grants nothing outside that backend.
RunRef = NewType("RunRef", str)

#: Removes a kill subscription. Calling it more than once is harmless.
Unsubscribe = Callable[[], None]


#: The session-record fields a backend hands its caller in
#: :attr:`SessionInfo.session`: wl-apdp's documented, non-secret
#: ``ExecutionSession`` fields. Anything else (an unknown or future field,
#: a token, the caller's free-form ``metadata``, the subject identity, the
#: plan body) is dropped.
PUBLIC_SESSION_KEYS = frozenset(
    {
        "id",
        "agent_id",
        "status",
        "goal_id",
        "tenant_id",
        "application_id",
        "max_actions",
        "action_count",
        "unplanned_actions",
        "ttl_seconds",
        "created_at",
        "expires_at",
        "ended_at",
        "termination_reason",
        "plan_hash",
    }
)

#: Prefixes of the credentials Watchlight issues (run ``sst_`` tokens,
#: agent ``wlapdp_`` keys, ``wlsa_`` service and ``wlpa_`` plugin keys) and
#: of HTTP authorization values.
_CREDENTIAL_PREFIXES = ("sst_", "wlapdp_", "wlsa_", "wlpa_", "bearer ", "basic ")


def _looks_like_credential(value: str) -> bool:
    lowered = value.strip().lower()
    if lowered.startswith(_CREDENTIAL_PREFIXES):
        return True
    # A JWS (3 parts) or JWE (5 parts) compact token, however it is labelled.
    stripped = value.strip()
    return stripped.startswith("eyJ") and len(stripped.split(".")) in (3, 5)


def public_session_record(session: Any) -> Dict[str, Any]:
    """The non-secret part of a backend's session record, for
    :attr:`SessionInfo.session`: only :data:`PUBLIC_SESSION_KEYS`, only
    scalar values (string, finite number, boolean, ``None``), and never a string
    shaped like a credential. Anything else is dropped (fail closed)."""
    if not isinstance(session, Mapping):
        return {}
    out: Dict[str, Any] = {}
    for key, value in session.items():
        if key not in PUBLIC_SESSION_KEYS:
            continue
        if isinstance(value, str):
            if _looks_like_credential(value):
                continue
        elif isinstance(value, float):
            if not math.isfinite(value):
                continue
        elif not (value is None or isinstance(value, (bool, int))):
            continue
        out[key] = value
    return out


@dataclass(frozen=True)
class SessionInfo:
    """A run the backend opened. Carries no credential.

    ``session`` is the backend's non-secret session record, restricted to
    :data:`PUBLIC_SESSION_KEYS` by :func:`public_session_record`;
    credentials and unknown fields are never part of it.
    """

    run: RunRef
    session_id: str
    agent_id: str
    execution_id: Optional[str] = None
    root_run_handle_id: Optional[str] = None
    session: Mapping[str, Any] = field(default_factory=dict)
    #: ``True`` only when the server evaluated and recorded a declared
    #: root for this session.
    declared_root: bool = False


@dataclass(frozen=True)
class KillNotice:
    """A run-ending decision delivered to a :meth:`GovernanceBackend.subscribe_kill`
    callback. ``reason`` and ``source`` are short codes, never values."""

    run: RunRef
    reason: str
    source: str


KillCallback = Callable[[KillNotice], Any]

_REDACTED = "<redacted>"


class EgressBinding:
    """Where a run's outbound traffic goes, and how it proves the run.

    The binding stores no credential. :meth:`proxy_authorization` asks the
    backend that issued the run for the run's current egress token at the
    moment it is needed, so the token stays in the backend's run table and
    is refused once the run has ended. ``repr``/``str`` never show it, and a
    binding does not pickle.
    """

    __slots__ = ("_proxy_url", "_expires_at", "_token_source")

    def __init__(
        self,
        *,
        proxy_url: Optional[str],
        expires_at: Optional[datetime],
        token_source: Callable[[], Optional[str]],
    ) -> None:
        self._proxy_url = proxy_url
        self._expires_at = expires_at
        self._token_source = token_source

    @property
    def proxy_url(self) -> Optional[str]:
        """The egress proxy the backend was configured with, if any."""
        return self._proxy_url

    @property
    def expires_at(self) -> Optional[datetime]:
        """When the run's egress token expires (not secret)."""
        return self._expires_at

    def proxy_authorization(self) -> str:
        """The run's egress token, for the egress installer only.

        Raises :class:`~watchlight_core.errors.GovernanceUnavailable` when the
        run has ended or the backend no longer knows it (fail closed).
        """
        token = self._token_source()
        if not isinstance(token, str) or not token:
            from .errors import GovernanceUnavailable

            raise GovernanceUnavailable(
                "the run's egress credential is not available (the run has "
                "ended or is unknown to its backend)"
            )
        return token

    def run_live(self) -> bool:
        """Does the backend still hold a token for this run? ``False`` once
        the run has ended or the backend no longer knows it. The token is
        never returned."""
        token = self._token_source()
        return isinstance(token, str) and bool(token)

    def __repr__(self) -> str:
        return (
            f"EgressBinding(proxy_url={self._proxy_url!r}, "
            f"expires_at={self._expires_at!r}, token={_REDACTED})"
        )

    __str__ = __repr__

    def __format__(self, format_spec: str) -> str:
        return self.__repr__()

    def __reduce__(self):  # pragma: no cover - exercised by the pickle test
        raise TypeError("an EgressBinding resolves a run credential and is not picklable")


class KillSubscriptions:
    """Bookkeeping for :meth:`GovernanceBackend.subscribe_kill`, shared by the
    backends in this package. Callbacks are kept per run; :meth:`notify`
    calls each one at most once and never lets a callback's exception
    escape."""

    def __init__(self) -> None:
        self._subs: Dict[str, List[KillCallback]] = {}

    def subscribe(self, run: RunRef, callback: KillCallback) -> Unsubscribe:
        callbacks = self._subs.setdefault(run, [])
        callbacks.append(callback)

        def _unsubscribe() -> None:
            current = self._subs.get(run)
            if current is None:
                return
            try:
                current.remove(callback)
            except ValueError:
                return
            if not current:
                self._subs.pop(run, None)

        return _unsubscribe

    def notify(self, notice: KillNotice) -> None:
        for callback in self._subs.pop(notice.run, []):
            fire_kill_callback(callback, notice)

    def discard(self, run: RunRef) -> None:
        self._subs.pop(run, None)


def fire_kill_callback(callback: KillCallback, notice: KillNotice) -> None:
    """Call ``callback`` with ``notice``; a callback error is logged by class
    only and never raised."""
    try:
        callback(notice)
    except Exception as exc:  # noqa: BLE001 - a listener never breaks the backend
        from .log import get_logger

        get_logger("watchlight_core.backend").warning(
            "kill subscription callback failed: %s", type(exc).__name__
        )


@runtime_checkable
class GovernanceBackend(Protocol):
    """The method surface the SDK and the plugins call on their backend.

    Every per-run method names the run by the :data:`RunRef` that
    :meth:`create_session` (or :meth:`spawn_subagent`, for a child)
    returned. A backend never hands a credential to its caller.

    **Optional capability: ``cedar_entities_verbatim``.** A backend may set
    this class attribute to ``True`` to tell the SDK to hand it
    ``principal`` / ``action`` / ``resource`` verbatim, instead of
    Cedar-wrapping a bare term into ``Agent::"…"`` / ``Action::"…"`` /
    ``Resource::"…"`` on its behalf. It is deliberately not a member of this
    protocol: absent or falsy (the default) means the historical wrapping.
    See :mod:`watchlight_core._cedar_entities`.
    """

    async def resolve_agent(self, slug: str) -> Optional[Dict[str, Any]]: ...

    async def create_session(
        self,
        agent_id: Optional[str] = None,
        goal_id: Optional[str] = None,
        max_actions: Optional[int] = None,
        ttl_seconds: int = 3600,
        metadata: Optional[Dict[str, Any]] = None,
        subject_token: Optional[str] = None,
        application_id: Optional[str] = None,
        declared_root: Optional[Sequence[str]] = None,
    ) -> Optional[SessionInfo]:
        """Open a root run. ``agent_id=None`` (the default) opens it as the
        agent the caller's verified credential is bound to; the returned
        ``SessionInfo.agent_id`` names it. A credential bound to no single
        agent raises :class:`~watchlight_core.CredentialBindsNoAgent`.

        ``declared_root`` declares an independent root while other
        governed runs are live: it lists their root execution ids, exactly
        as the server issued them. The server evaluates
        ``Action::"open_declared_root"`` and confirms it in the response
        (``SessionInfo.declared_root``). A backend that cannot open a
        declared root raises :class:`~watchlight_core.DeclaredRootRefused`."""
        ...

    async def get_manifest(
        self,
        agent_id: str,
        goal_id: Optional[str] = None,
        ttl_seconds: int = 3600,
        run: Optional[RunRef] = None,
        application_id: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]: ...

    async def authorize(
        self,
        principal: str,
        action: str,
        resource: str,
        context: Optional[Dict[str, Any]] = None,
        execution_id: Optional[str] = None,
        session_id: Optional[str] = None,
        intent: Optional[Dict[str, Any]] = None,
        run: Optional[RunRef] = None,
    ) -> Dict[str, Any]: ...

    async def preflight_step(
        self,
        run: RunRef,
        action: str,
        resource: str,
        resource_type: Optional[str] = None,
        intent: Optional[Dict[str, Any]] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]: ...

    async def submit_plan(
        self, run: RunRef, plan: List[Dict[str, Any]]
    ) -> Optional[Dict[str, Any]]: ...

    async def spawn_subagent(
        self, parent: RunRef, request: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Return the canonical spawn response with ``child_run`` (the
        child's :data:`RunRef`) and no credential."""
        ...

    async def publish_events(
        self, run: Optional[RunRef], events: List[Dict[str, Any]]
    ) -> bool: ...

    async def drain(self, run: RunRef, timeout_s: Optional[float] = None) -> None: ...

    async def complete_session(self, run: RunRef) -> bool: ...

    # Release any client-side bookkeeping for an abnormally-ended run. Not
    # a server-side session transition: ending a session is an
    # operator-plane verb, out of reach of agent credentials. The run's
    # abnormal end is recorded by the ``execution_failed`` lineage event.
    async def terminate_session(self, run: RunRef, reason: str = "manual") -> bool: ...

    def subscribe_kill(self, run: RunRef, callback: KillCallback) -> Unsubscribe: ...

    def egress_for(self, run: RunRef) -> Optional[EgressBinding]: ...

    async def health_check(self) -> bool: ...

    async def close(self) -> None: ...


def egress_binding_for(backend: Any, run: Optional[RunRef]) -> Optional[EgressBinding]:
    """``backend.egress_for(run)`` when the backend answers with an
    :class:`EgressBinding`; ``None`` otherwise (no run, no egress, or a
    backend without the method)."""
    if run is None:
        return None
    egress_for = getattr(backend, "egress_for", None)
    if not callable(egress_for):
        return None
    binding = egress_for(run)
    return binding if isinstance(binding, EgressBinding) else None


async def fetch_egress_binding(backend: Any, run: Optional[RunRef]) -> Optional[EgressBinding]:
    """:func:`egress_binding_for`, after asking a backend that issues egress
    on request (the connector) for this run's endpoint. Raises
    :class:`~watchlight_core.errors.GovernanceUnavailable` when it can't
    answer, gives no endpoint, or the process can't be routed to it (see
    :mod:`~watchlight_core.egress_route`)."""
    if run is None:
        return None
    fetch = getattr(backend, "fetch_egress", None)
    if not callable(fetch):
        return egress_binding_for(backend, run)
    result = fetch(run)
    if inspect.isawaitable(result):
        await result
    binding = egress_binding_for(backend, run)
    if binding is None:
        from .errors import GovernanceUnavailable

        raise GovernanceUnavailable(
            "The Watchlight connector gave this run no egress endpoint. "
            "Refusing it rather than letting its egress go direct."
        )
    from .sidecar_backend import SidecarEgress

    if isinstance(binding, SidecarEgress):
        from . import egress_route

        await egress_route.admit(binding.proxy_url)
    return binding
