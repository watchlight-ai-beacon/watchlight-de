"""Egress attribution: which run an outbound request is made for.

The Watchlight connector (``wl-sidecar``) is the agents' ``HTTPS_PROXY``.
It holds every run's egress token and attaches the token of the run that
made each request; this process never sees a token. This module is the
thin client side of that: it tells the connector which run is asking, over
the ``wl-local/1`` control protocol (``report_connection``) and the marker
header; the connector decides.

Three signals, all decided in the context of the code making the request:

* **The marker** (primary). :func:`marker_headers` returns the header that
  names the current run. A plugin adds it to each request through a
  supported framework hook. Every request names its run, so pooled
  connections are safe.
* **The connection report** (fallback, where no hook exists). A
  ``socket.connect`` audit hook (PEP 578, an observation API, not a patch)
  fires in the thread and ``contextvars`` context of the code opening a
  connection to the connector's egress listener. It binds the socket if it
  is still unbound (to learn its source port), and reports
  ``(source port, run)`` to the connector, waiting until the connector has
  recorded it, before the SYN is sent. The connector then serves exactly
  one request on that connection and closes it. If the report is not
  recorded (refused, timed out, connector unreachable), the hook raises
  :class:`EgressConnectRefused` out of ``socket.connect`` and the
  connection is never opened.
* **The child key** (child processes). :func:`proxy_env` returns proxy
  variables whose URL carries the current run's child key, with
  ``NO_PROXY`` cleared, for a process the agent spawns.

Who the current run is:

1. When a sub-agent handle is bound in the context (the raw run-handle
   binding, including one that has completed), the answer comes from its
   chain only: a live sub-agent egresses as itself, with its own marker; a
   sub-agent that completed normally hands over to its nearest live
   ancestor (so a spawner whose grandchild completed elsewhere is itself
   again, never the root). A sub-agent with no egress binding of its own is
   refused: it never borrows its parent's run. One that ended any other way
   (quarantined, terminated, revoked, severed) refuses.
2. Only when no sub-agent was ever bound in the context: the run bound
   with :func:`bind_run`, while it is live.
3. Otherwise nothing, and the request is refused: no marker is given, no
   report is made, and the connector refuses the request (407).

A run that has ended is refused: its marker and child key are no longer
handed out, and the connector refuses them too. After ``fork`` the child
process inherits no binding: every egress binding records the process it
was issued to (``SidecarEgress.owner_pid``), so the parent's runs and
sub-agents are refused in the child on every path, and the child binds
its own runs on its own backend.

Fail closed: :func:`marker_headers` and :func:`proxy_env` raise
:class:`EgressRefused`. The audit hook makes no report for a connection
it cannot attribute (the connector refuses it unless a request carries a
marker), and raises only when an attributed connection's report was not
recorded. Threads started without the context (``threading.Thread``,
``loop.run_in_executor``) see no binding and are refused;
``asyncio.to_thread`` and tasks copy the context and work.

Nothing here touches trust settings, the environment of this process or
any other module: the customer's interception CA is the customer's own
trust configuration.
"""

from __future__ import annotations

import contextlib
import contextvars
import ipaddress
import os
import sys
import threading
import weakref
from typing import Any, Dict, Iterator, Optional, Set, Tuple
from urllib.parse import urlsplit

from .errors import GovernanceUnavailable
from .log import get_logger

logger = get_logger("watchlight_core.attribution")

__all__ = [
    "EgressRefused",
    "EgressConnectRefused",
    "bind_run",
    "unbind_run",
    "bound_run",
    "current_egress",
    "resolve_run",
    "marker_headers",
    "proxy_env",
    "register_egress_endpoint",
]

#: The proxy variables :func:`proxy_env` sets (both spellings).
PROXY_ENV_NAMES = (
    "HTTPS_PROXY",
    "https_proxy",
    "HTTP_PROXY",
    "http_proxy",
    "ALL_PROXY",
    "all_proxy",
)

#: Cleared by :func:`proxy_env`, so a child inherits no bypass.
NO_PROXY_ENV_NAMES = ("NO_PROXY", "no_proxy")

#: How long the audit hook waits for the connector to record a report.
REPORT_TIMEOUT_S = 2.0

#: The longest parent chain walked from a closed sub-agent.
_MAX_WALK = 64


class EgressRefused(GovernanceUnavailable):
    """No live run or sub-agent can be named for egress in this context.
    ``reason`` is a short code, never a credential."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(f"egress refused: {reason}")


class EgressConnectRefused(EgressRefused, ConnectionRefusedError):
    """Raised by the audit hook out of ``socket.connect``: the connection
    was attributed but the connector did not record its report (refused,
    timed out, unreachable), so it is not opened. An ``OSError`` too, so
    HTTP clients surface it as a failed connection."""


# ---------------------------------------------------------------------------
# The binding
# ---------------------------------------------------------------------------

# (pid that made the binding, the subject). The pid makes a binding copied
# into a forked child worthless there.
_bound: contextvars.ContextVar[Optional[Tuple[int, Any]]] = contextvars.ContextVar(
    "watchlight_core.attribution._bound", default=None
)


def bind_run(subject: Any) -> contextvars.Token:
    """Bind ``subject`` as the run egress acts for in the current context
    (and every task or ``asyncio.to_thread`` call started from it).

    ``subject`` is a run handle whose ``egress`` is a connector egress
    binding (:class:`~watchlight_core.sidecar_backend.SidecarEgress`), or
    such a binding itself. Its egress listener is registered for the
    connection-report fallback. Returns the token for :func:`unbind_run`.
    """
    egress = subject if _is_connector_egress(subject) else _egress_of(subject)
    if egress is not None:
        register_egress_endpoint(getattr(egress, "proxy_url", None))
    return _bound.set((os.getpid(), subject))


def unbind_run(token: contextvars.Token) -> None:
    _bound.reset(token)


@contextlib.contextmanager
def bound_run(subject: Any) -> Iterator[None]:
    """``with bound_run(handle): ...`` binds for the block."""
    token = bind_run(subject)
    try:
        yield
    finally:
        unbind_run(token)


# ---------------------------------------------------------------------------
# Resolution
# ---------------------------------------------------------------------------


def _is_connector_egress(obj: Any) -> bool:
    return obj is not None and all(
        callable(getattr(obj, name, None))
        for name in ("marker", "child_proxy_url", "report_connection_blocking")
    ) and isinstance(getattr(obj, "marker_header", None), str)


def _issued_here(egress: Any) -> bool:
    """The binding was issued to this process (not inherited by fork)."""
    return getattr(egress, "owner_pid", None) == os.getpid()


def _egress_of(handle: Any) -> Optional[Any]:
    egress = getattr(handle, "egress", None)
    return egress if _is_connector_egress(egress) else None


def _state_value(handle: Any) -> Any:
    # ``_state`` is what the run handle's own accessors read; ``state`` is
    # its public view of the same value.
    state = getattr(handle, "_state", None)
    if state is None:
        state = getattr(handle, "state", None)
    return getattr(state, "value", state)


def _disposition(handle: Any) -> str:
    """``"live"`` (may egress), ``"closed"`` (completed normally: the
    context belongs to its parent again) or ``"refused"`` (ended by a
    decision, or unknown)."""
    value = _state_value(handle)
    if value == "active":
        return "live"
    if (
        value == "completed"
        and getattr(handle, "_completed", False)
        and getattr(handle, "_run_end_decision", None) is None
    ):
        return "closed"
    return "refused"


def _parent_of(handle: Any) -> Optional[Any]:
    ref = getattr(handle, "_parent_handle_ref", None)
    if ref is None:
        return None
    try:
        return ref()
    except TypeError:
        return None


def _is_subagent(handle: Any) -> bool:
    return bool(getattr(handle, "_is_subagent", False)) or _parent_of(handle) is not None


class Attribution:
    """Who egress acts for, decided in one context. Holds the egress
    binding (no credential) and re-checks liveness when used."""

    __slots__ = ("_egress", "_handle_ref", "refusal")

    def __init__(
        self, egress: Any = None, handle: Any = None, refusal: Optional[str] = None
    ) -> None:
        self._egress = egress
        self._handle_ref = weakref.ref(handle) if handle is not None else None
        self.refusal = refusal

    def egress(self) -> Any:
        """The live egress binding, or raise :class:`EgressRefused`."""
        if self.refusal is not None or self._egress is None:
            raise EgressRefused(self.refusal or "no_run_bound")
        if not _issued_here(self._egress):
            # Every path (bound run or sub-agent) ends here: a binding
            # inherited across fork is never used.
            raise EgressRefused("bound_in_another_process")
        if self._handle_ref is not None:
            h = self._handle_ref()
            if h is None or _disposition(h) != "live":
                raise EgressRefused("run_not_live")
        return self._egress

    def run_handle(self) -> Optional[Any]:
        """The live run handle acting in this context, or ``None`` when
        resolution refused (``refusal`` says why) or the run has ended."""
        if self.refusal is not None or self._handle_ref is None:
            return None
        h = self._handle_ref()
        if h is None or _disposition(h) != "live":
            return None
        return h


def _refuse(reason: str) -> Attribution:
    return Attribution(refusal=reason)


def _from_subject(subject: Any, *, need_egress: bool = True) -> Attribution:
    if _is_connector_egress(subject):
        if not need_egress:
            # A bare egress binding names no run handle to decide for.
            return _refuse("no_run_handle")
        return Attribution(egress=subject)
    h = subject
    for _ in range(_MAX_WALK):
        if h is None:
            return _refuse("no_live_run")
        disposition = _disposition(h)
        if disposition == "live":
            if not need_egress:
                return Attribution(handle=h)
            egress = _egress_of(h)
            if egress is None:
                # A sub-agent never borrows its parent's run.
                return _refuse(
                    "subagent_has_no_egress" if _is_subagent(h) else "run_has_no_egress"
                )
            return Attribution(egress=egress, handle=h)
        if disposition == "closed" and _is_subagent(h):
            h = _parent_of(h)
            continue
        return _refuse("run_not_live")
    return _refuse("no_live_run")


def _current_subagent() -> Any:
    # The raw binding, not ``current_subagent_handle()``: that accessor
    # hides a sub-agent that completed normally, and a caller would then
    # fall back to the bound ROOT. When a grandchild completes in its own
    # context, its spawner's context still holds it; walking up from it
    # reaches the spawner, the nearest live ancestor, never the root.
    from .run_handle import _current_subagent_handle

    return _current_subagent_handle.get()


def resolve() -> Attribution:
    """Decide, in the current context, which run egress acts for. Never
    raises; a refusal is carried in the result.

    While any sub-agent handle is bound in the context, the answer comes
    from that handle's chain (itself, or its nearest live ancestor when it
    completed normally); the bound root is used only when no sub-agent was
    ever bound here."""
    return _resolve(need_egress=True)


def resolve_run() -> Attribution:
    """The same decision as :func:`resolve`, for a run's own actions (a
    tool call) rather than its egress: the run handle acting in this
    context, whether or not it egresses through the connector. Read it
    with :meth:`Attribution.run_handle`. Never raises; a refusal never
    falls back to another run."""
    return _resolve(need_egress=False)


def _resolve(*, need_egress: bool) -> Attribution:
    try:
        sub = _current_subagent()
    except Exception:  # noqa: BLE001 - resolution must not raise
        return _refuse("resolution_failed")
    if sub is not None:
        return _from_subject(sub, need_egress=need_egress)
    bound = _bound.get()
    if bound is None:
        return _refuse("no_run_bound")
    pid, subject = bound
    if pid != os.getpid():
        return _refuse("bound_in_another_process")
    return _from_subject(subject, need_egress=need_egress)


def current_egress() -> Any:
    """The connector egress binding of the run or sub-agent acting in this
    context. Raises :class:`EgressRefused`."""
    return resolve().egress()


def marker_headers() -> Dict[str, str]:
    """``{marker header: marker}`` naming the run acting in this context,
    for a plugin's per-request hook. Raises :class:`EgressRefused` when no
    live run can be named (never another run's marker)."""
    egress = current_egress()
    try:
        marker = egress.marker()
    except GovernanceUnavailable:
        raise EgressRefused("run_not_live") from None
    return {egress.marker_header: marker}


def proxy_env() -> Dict[str, str]:
    """Proxy variables for a child process that egresses for the run acting
    in this context: every proxy variable (both spellings, ``ALL_PROXY``
    included) set to the connector's URL with that run's child key. The key
    dies with the run. Merge it into the child's environment; this
    process's environment is not changed. Raises :class:`EgressRefused`."""
    egress = current_egress()
    try:
        url = egress.child_proxy_url()
    except GovernanceUnavailable:
        raise EgressRefused("run_not_live") from None
    env = {name: url for name in PROXY_ENV_NAMES}
    # Nothing bypasses the connector: an inherited NO_PROXY would.
    env.update({name: "" for name in NO_PROXY_ENV_NAMES})
    return env


# ---------------------------------------------------------------------------
# The connection-report fallback (PEP 578 audit hook)
# ---------------------------------------------------------------------------

_endpoints_lock = threading.Lock()
_endpoints: Set[Tuple[str, int]] = set()
_hook_installed = False
_in_hook = threading.local()


def _endpoint_key(host: Any, port: Any) -> Optional[Tuple[str, int]]:
    if not isinstance(port, int) or not 0 < port < 65536 or not isinstance(host, str):
        return None
    try:
        ip = ipaddress.ip_address(host.strip("[]").split("%", 1)[0])
    except ValueError:
        return None
    if not ip.is_loopback:
        return None
    return (ip.compressed, port)


def register_egress_endpoint(proxy_url: Optional[str]) -> bool:
    """Watch connections to the connector's egress listener at ``proxy_url``
    (``http://`` on a loopback IP literal) for the connection-report
    fallback, and install the audit hook once. ``False`` (and nothing is
    watched) for any other URL."""
    if not isinstance(proxy_url, str):
        return False
    try:
        parts = urlsplit(proxy_url)
        key = _endpoint_key(parts.hostname, parts.port)
    except ValueError:
        return False
    if parts.scheme != "http" or key is None:
        return False
    with _endpoints_lock:
        _endpoints.add(key)
    _ensure_audit_hook()
    return True


def _ensure_audit_hook() -> None:
    global _hook_installed
    with _endpoints_lock:
        if _hook_installed:
            return
        _hook_installed = True
    sys.addaudithook(_audit_hook)


def _audit_hook(event: str, args: Tuple[Any, ...]) -> None:
    if event != "socket.connect" or not _endpoints:
        return
    if getattr(_in_hook, "active", False):
        return
    _in_hook.active = True
    try:
        _report(args)
    except EgressConnectRefused:
        # The one exception the hook raises: it aborts this connect.
        raise
    except Exception:  # noqa: BLE001 - nothing else escapes the hook
        pass
    finally:
        _in_hook.active = False


def _report(args: Tuple[Any, ...]) -> None:
    sock, address = args
    if not isinstance(address, tuple) or len(address) < 2:
        return
    key = _endpoint_key(address[0], address[1])
    if key is None:
        return
    with _endpoints_lock:
        if key not in _endpoints:
            return
    attribution = resolve()
    if attribution.refusal is not None:
        logger.debug("egress connection not attributed: %s", attribution.refusal)
        return
    try:
        egress = attribution.egress()
    except EgressRefused as exc:
        logger.debug("egress connection not attributed: %s", exc.reason)
        return
    local = sock.getsockname()
    port = local[1] if isinstance(local, tuple) and len(local) >= 2 else 0
    if not port:
        # Bind the unbound socket so its source port is known before the
        # SYN; only ever for a connection to the egress listener.
        sock.bind((address[0], 0, *address[2:4]))
        local = sock.getsockname()
        port = local[1] if isinstance(local, tuple) and len(local) >= 2 else 0
    if not port:
        return
    if not egress.report_connection_blocking(port, REPORT_TIMEOUT_S):
        # Fail closed: the connection is not opened. A report that lands
        # late must find no connection of ours on that port.
        raise EgressConnectRefused("connection_report_not_recorded")


def _after_fork_in_child() -> None:
    # The parent's endpoints (and the parent's runs) mean nothing here; a
    # binding copied into this process is refused by its pid. Never take
    # the lock here: another parent thread may have held it at the fork.
    global _endpoints_lock, _endpoints, _in_hook
    _endpoints_lock = threading.Lock()
    _endpoints = set()
    _in_hook = threading.local()


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_after_fork_in_child)
