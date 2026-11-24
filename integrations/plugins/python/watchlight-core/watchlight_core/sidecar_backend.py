"""``SidecarBackend``: the Enterprise :class:`~watchlight_core.backend.GovernanceBackend`.

``SidecarBackend`` is a thin client. It speaks the local control protocol
``wl-local/1`` to the Watchlight connector (``wl-sidecar``) running on the
same host or in the same pod, and the connector does the rest: it holds the
plugin credential, every run credential and every egress token, and talks to
wl-apdp and wl-proxy itself. This process only ever receives an opaque run
reference (:data:`~watchlight_core.backend.RunRef`), a run marker for egress
attribution, and the decisions it asked for.

How it connects (the SDK is told; it never guesses):

* **A Unix socket** (preferred). Before connecting, the SDK checks that the
  socket's directory is a real directory with mode 0700 owned by this user,
  that no ancestor lets another user replace it, and that the socket itself
  is ours with no group or world permissions. After connecting, it checks
  the peer's uid with the kernel (``SO_PEERCRED`` / ``LOCAL_PEERCRED``).
* **Loopback TCP** with a per-start secret. The secret is read from the
  connector's 0600 secret file, or from the connector's stdout pipe when
  this SDK launched it; never from argv or the environment, and it is never
  logged or sent. The SDK and the connector prove to each other that they
  know it (HMAC-SHA256 bound to both nonces and both ends of the
  connection). The SDK verifies the connector's proof before it sends
  anything else.

Fail closed: every error, timeout, malformed answer or lost connection is a
``Deny``, ``None``, ``False`` or a typed refusal. A refused sub-agent spawn
raises, so the child never runs. When the control connection is lost, every
run created on it is treated as killed.

The connection lives on a private event-loop thread, so the backend can be
called from any event loop (notebooks, ``asyncio.run`` per call, worker
threads). After ``fork`` a child process cannot use its parent's backend:
every call is refused there; the child creates its own.

Egress: :meth:`SidecarBackend.fetch_egress` asks the connector for the run's
egress endpoint (the local proxy URL and the marker header). It carries no CA
bundle and the SDK changes no trust settings: the interception CA belongs to
the customer, who distributes trust for it.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import ipaddress
import json
import os
import re
import socket
import subprocess
import threading
import time
import weakref
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, List, Mapping, Optional, Sequence, Set, Tuple, TypeVar
from urllib.parse import urlsplit

from . import _wl_local as wire
from ._lineage_retry import on_decision_path
from .backend import (
    EgressBinding,
    KillCallback,
    KillNotice,
    RunRef,
    SessionInfo,
    Unsubscribe,
    fire_kill_callback,
    public_session_record,
)
from .errors import (
    DECLARED_ROOT_UNSUPPORTED,
    AgentNotRegistered,
    DeclaredRootRefused,
    GovernanceRefused,
    GovernanceUnavailable,
    ParentRunUncredentialed,
    RunHandleInvalidated,
    ScopeAttenuationDenied,
    WatchlightContractError,
)
from .log import get_logger

logger = get_logger("watchlight_core.sidecar_backend")

#: The connector's ``denied`` reasons that carry wl-apdp's typed
#: trust refusal.
_TRUST_REASONS = frozenset(
    {"agent_trust_revoked", "agent_quarantined", "agent_unverified", "delegation_chain_not_trusted"}
)

__all__ = [
    "SidecarBackend",
    "SidecarEgress",
    "select_backend",
    "connector_configured",
    "ENV_BACKEND",
    "ENV_SIDECAR_SOCKET",
    "ENV_SIDECAR_ADDR",
    "ENV_SIDECAR_SECRET_FILE",
    "ENTERPRISE_ENV_VARS",
]

#: ``sidecar`` selects :class:`SidecarBackend`; ``in_process`` the
#: Developer Edition backend (only when no Enterprise variable is set).
ENV_BACKEND = "WATCHLIGHT_BACKEND"
#: The connector's control socket (absolute path).
ENV_SIDECAR_SOCKET = "WATCHLIGHT_SIDECAR_SOCKET"
#: The connector's loopback TCP control address (``127.0.0.1:41000`` or
#: ``[::1]:41000``), for platforms where a shared socket is not possible.
ENV_SIDECAR_ADDR = "WATCHLIGHT_SIDECAR_ADDR"
#: With ``WATCHLIGHT_SIDECAR_ADDR``: the PATH of the connector's 0600 secret
#: file. The secret itself is never put in the environment.
ENV_SIDECAR_SECRET_FILE = "WATCHLIGHT_SIDECAR_SECRET_FILE"

#: Any of these set means Enterprise: the connector is required, and its
#: absence refuses the run (never a quiet fall-back to in-process mode).
ENTERPRISE_ENV_VARS = (
    # Endpoints.
    "WATCHLIGHT_APDP_URL",
    "WATCHLIGHT_PROXY_URL",
    "WATCHLIGHT_GATEWAY_URL",
    # The plugin's own credential, however it is supplied.
    "WATCHLIGHT_PLUGIN_TOKEN",
    "WATCHLIGHT_SERVICE_TOKEN",
    "WATCHLIGHT_APDP_TOKEN",
    "WL_APDP_BEARER",
    "WL_STAGING_APDP_TOKEN",
    "WATCHLIGHT_API_KEY",
    "WATCHLIGHT_CREDENTIAL_FILE",
    "WATCHLIGHT_CREDENTIAL_AWS_SECRET_ID",
    "WATCHLIGHT_TENANT_ID",
    # A run granted by a launcher.
    "WATCHLIGHT_RUN_CREDENTIAL",
    "WATCHLIGHT_RUN_HANDLE_ID",
    "WATCHLIGHT_RUN_PROXY_TOKEN",
    # TLS to wl-apdp and wl-proxy.
    "WATCHLIGHT_APDP_MTLS_CERT_PATH",
    "WATCHLIGHT_APDP_MTLS_KEY_PATH",
    "WATCHLIGHT_APDP_TLS_CA_BUNDLE",
    "WATCHLIGHT_APDP_ALLOW_PLAINTEXT",
    "WATCHLIGHT_PROXY_MTLS_CERT_PATH",
    "WATCHLIGHT_PROXY_MTLS_KEY_PATH",
    "WATCHLIGHT_PROXY_TLS_CA_BUNDLE",
    "WATCHLIGHT_PROXY_CA_CERT",
    "WATCHLIGHT_PROXY_ALLOW_PLAINTEXT",
    "WATCHLIGHT_PROXY_NO_PROXY",
    # The connector.
    ENV_SIDECAR_SOCKET,
    ENV_SIDECAR_ADDR,
    ENV_SIDECAR_SECRET_FILE,
)

#: The fields of the canonical spawn response the connector forwards in
#: ``scope``.
_SPAWN_FIELDS = (
    "child_run_handle_id",
    "granted_scope",
    "lineage_event_id",
    "child_execution_id",
    "root_execution_id",
    "child_session_id",
    # Credential-bound root and labelled sub-agents: who the child runs as.
    "child_agent_id",
    "child_label",
    "child_identity",
)

#: Longer than the connector's own wl-apdp timeout (30 s by default): the
#: connector answers ``unavailable`` when an upstream call fails, so a
#: request it does not answer within this bound drops the connection.
_DEFAULT_REQUEST_TIMEOUT_S = 60.0
_DEFAULT_DRAIN_S = 30.0
#: Room left in a frame for the envelope around a batch of events.
_FRAME_OVERHEAD = 4096

T = TypeVar("T")


class _Unavailable(Exception):
    """The connector could not be reached, or the request got no answer."""


def _sdk_version() -> str:
    try:
        from importlib.metadata import version

        v = version("watchlight-agent-sdk")
    except Exception:  # noqa: BLE001 - not installed as a distribution
        v = "0"
    return v if wire.is_short_text(v) else "0"


def _short_reason(text: Any, fallback: str = "manual") -> str:
    """A ``terminate_session`` reason the protocol accepts: no control
    characters, at most 256 characters."""
    if not isinstance(text, str):
        return fallback
    cleaned = wire._CONTROL.sub(" ", text).strip()[:256]
    return cleaned or fallback


_TOKEN_PREFIXES = ("sst_", "wlapdp_", "wlsa_", "wlpa_")
_AUTH_VALUE = re.compile(r"(?i)(bearer|basic)\s+[A-Za-z0-9._~+/=-]{16,}")


def _credential_shaped(value: str) -> bool:
    """A Watchlight credential, an HTTP authorization value or a JWS/JWE,
    by shape. Narrower than ``_looks_like_credential`` so that ordinary
    text in a decision or manifest ("Basic research agent") is not taken
    for one."""
    v = value.strip()
    if v.lower().startswith(_TOKEN_PREFIXES) or _AUTH_VALUE.fullmatch(v):
        return True
    return v.startswith("eyJ") and len(v.split(".")) in (3, 5)


def _carries_credential(value: Any, depth: int = 0) -> bool:
    """Whether a pass-through answer holds a credential-shaped string
    anywhere (keys or values)."""
    if depth > wire.MAX_JSON_DEPTH:
        return True
    if isinstance(value, str):
        return _credential_shaped(value)
    if isinstance(value, dict):
        return any(
            _carries_credential(k, depth + 1) or _carries_credential(v, depth + 1)
            for k, v in value.items()
        )
    if isinstance(value, (list, tuple)):
        return any(_carries_credential(v, depth + 1) for v in value)
    return False


def _loopback_http_url(url: str, *, with_key: bool) -> bool:
    """The connector's egress listener: ``http://`` on a loopback IP literal
    with a port; with a ``wl:<key>`` user part for children."""
    try:
        parts = urlsplit(url)
        host = parts.hostname
        port = parts.port
    except ValueError:
        return False
    if parts.scheme != "http" or host is None or port is None:
        return False
    if parts.path not in ("", "/") or parts.query or parts.fragment:
        return False
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    loopback = (
        ip.is_loopback
        if isinstance(ip, ipaddress.IPv4Address)
        else ip == ipaddress.IPv6Address("::1")
    )
    if not loopback:
        return False
    if with_key:
        return parts.username == "wl" and wire.is_marker(parts.password)
    return parts.username is None and parts.password is None


# ---------------------------------------------------------------------------
# Egress binding
# ---------------------------------------------------------------------------


class SidecarEgress(EgressBinding):
    """A run's egress endpoint on the connector.

    ``proxy_url`` is the connector's local egress listener and
    ``marker_header`` the header that carries the run's marker. The marker
    and the child proxy URL (which embeds the child key) are resolved from
    the backend each time they are asked for, and are refused once the run
    has ended. There is no CA bundle and no token here: the connector holds
    the egress token, and trust for the customer's interception CA is the
    customer's own configuration.
    """

    __slots__ = ("_marker_header", "_backend", "_run", "_owner_pid")

    def __init__(
        self, *, proxy_url: str, marker_header: str, backend: "SidecarBackend", run: RunRef
    ) -> None:
        super().__init__(proxy_url=proxy_url, expires_at=None, token_source=lambda: None)
        self._marker_header = marker_header
        self._backend = backend
        self._run = run
        self._owner_pid = os.getpid()

    @property
    def owner_pid(self) -> int:
        """The process this binding was issued to. A forked child
        inherits the object but never the right to use it."""
        return self._owner_pid

    @property
    def marker_header(self) -> str:
        return self._marker_header

    def marker(self) -> str:
        """The run's current marker. Raises :class:`GovernanceUnavailable`
        when the run has ended or is unknown (fail closed)."""
        return self._backend._egress_secret(self._run, "marker")

    def child_proxy_url(self) -> str:
        """The proxy URL for a child process of this run
        (``http://wl:<child key>@127.0.0.1:<port>``). Raises
        :class:`GovernanceUnavailable` when the run has ended."""
        return self._backend._egress_secret(self._run, "child_proxy_url")

    def report_connection_blocking(self, src_port: int, timeout_s: float = 2.0) -> bool:
        """Tell the connector, and wait until it has recorded, that the
        egress connection from ``src_port`` belongs to this run (the
        attribution fallback, :mod:`watchlight_core.attribution`). ``False``
        on any failure, when the run has ended, or when called on the
        backend's own I/O thread (it would wait on itself). Never raises."""
        return self._backend._report_connection_blocking(self._run, src_port, timeout_s)

    def proxy_authorization(self) -> str:
        raise GovernanceUnavailable(
            "a connector run proves its egress with the run marker "
            "(SidecarEgress.marker), not with a proxy token"
        )

    def __repr__(self) -> str:
        return (
            f"SidecarEgress(proxy_url={self.proxy_url!r}, "
            f"marker_header={self._marker_header!r}, marker=<redacted>)"
        )

    __str__ = __repr__

    def __format__(self, format_spec: str) -> str:
        return self.__repr__()


# ---------------------------------------------------------------------------
# Endpoint
# ---------------------------------------------------------------------------


@dataclass
class _Endpoint:
    transport: str  # "unix" or "tcp"
    socket_path: Optional[str] = None
    host: Optional[str] = None
    port: Optional[int] = None
    secret_file: Optional[str] = None
    # Held only for a connector this SDK launched (its stdout secret).
    launched_secret: Optional[bytearray] = field(default=None, repr=False)
    proc: Optional["subprocess.Popen[bytes]"] = field(default=None, repr=False)

    def describe(self) -> str:
        if self.transport == "unix":
            return "unix socket"
        return f"loopback tcp {self.host}:{self.port}"

    def secret(self) -> bytearray:
        if self.launched_secret is not None:
            return bytearray(self.launched_secret)
        if self.secret_file is None:
            raise wire.WireError("no control secret is configured for TCP")
        return wire.read_secret_file(self.secret_file)

    def may_connect(self) -> bool:
        # Never reconnect over TCP after the connector we launched exited:
        # its port is free for anyone to take.
        return self.proc is None or self.proc.poll() is None

    def wipe(self) -> None:
        if self.launched_secret is not None:
            for i in range(len(self.launched_secret)):
                self.launched_secret[i] = 0


# ---------------------------------------------------------------------------
# The connection (runs on the backend's private event loop)
# ---------------------------------------------------------------------------


@dataclass
class _Pending:
    method: str
    future: "asyncio.Future[Optional[Tuple[wire.Response, Optional[str]]]]"
    #: The caller stopped waiting (cancelled): a run this request creates
    #: is then ended as soon as its answer arrives.
    abandoned: bool = False
    expiry: Optional[asyncio.TimerHandle] = None


class _Connection:
    """One authenticated control connection. Every coroutine here runs on
    the backend's I/O loop."""

    heartbeat_s = wire.HEARTBEAT_S
    #: How long the health probe after a missed deadline may take.
    probe_timeout_s = 5.0
    #: Slot waiters are woken together and race for free slots (no FIFO
    #: order): every waiter is bounded by its own deadline, so none waits
    #: forever, but a burst may starve an early waiter until it times out.

    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        transport: str,
        on_push: Callable[[wire.KillPush], None],
        on_lost: Callable[["_Connection"], None],
        features: List[str],
        on_orphan: Optional[Callable[[str], None]] = None,
    ) -> None:
        self._reader = reader
        self._writer = writer
        self.transport = transport
        self.features = features
        self._on_push = on_push
        self._on_lost = on_lost
        self._on_orphan = on_orphan
        self._pending: Dict[int, _Pending] = {}
        self._next_id = 2  # 0 and 1 were the handshake
        # Request slots: a plain counter (the truth) and waiters woken on
        # every change, so a cancelled or timed-out waiter can never lose
        # a slot.
        self._in_flight = 0
        self._slot_waiters: List["asyncio.Future[None]"] = []
        self._wlock = asyncio.Lock()
        self._last_send = asyncio.get_running_loop().time()
        self.closed = False
        self._closing = False
        self._probe_task: Optional["asyncio.Future[None]"] = None
        self._reader_task = asyncio.ensure_future(self._read_loop())
        self._heartbeat_task = asyncio.ensure_future(self._heartbeat())

    # -- opening ----------------------------------------------------------

    @classmethod
    async def open(
        cls,
        endpoint: _Endpoint,
        on_push: Callable[[wire.KillPush], None],
        on_lost: Callable[["_Connection"], None],
        on_orphan: Optional[Callable[[str], None]] = None,
    ) -> "_Connection":
        loop = asyncio.get_running_loop()
        deadline = loop.time() + wire.HANDSHAKE_TIMEOUT_S
        secret: Optional[bytearray] = None
        sock: Optional[socket.socket] = None
        writer: Optional[asyncio.StreamWriter] = None
        try:
            if endpoint.transport == "unix":
                assert endpoint.socket_path is not None
                wire.check_socket_path(endpoint.socket_path)
                sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                sock.setblocking(False)
                await asyncio.wait_for(
                    loop.sock_connect(sock, endpoint.socket_path), wire.HANDSHAKE_TIMEOUT_S
                )
                uid = wire.peer_uid(sock)
                if uid is None or uid != os.geteuid():
                    raise wire.WireError("the control socket's peer is not this user")
            else:
                assert endpoint.host is not None and endpoint.port is not None
                secret = endpoint.secret()
                family = socket.AF_INET6 if ":" in endpoint.host else socket.AF_INET
                sock = socket.socket(family, socket.SOCK_STREAM)
                sock.setblocking(False)
                await asyncio.wait_for(
                    loop.sock_connect(sock, (endpoint.host, endpoint.port)),
                    wire.HANDSHAKE_TIMEOUT_S,
                )
            binding = wire.ChannelBinding.from_socket(sock) if endpoint.transport == "tcp" else None
            reader, writer = await asyncio.open_connection(sock=sock)
            sock = None  # owned by the stream now
            features = await asyncio.wait_for(
                cls._handshake(reader, writer, endpoint.transport, secret, binding),
                max(0.0, deadline - loop.time()),
            )
        except BaseException:
            if writer is not None:
                writer.transport.abort()
            if sock is not None:
                sock.close()
            raise
        finally:
            if secret is not None:
                for i in range(len(secret)):
                    secret[i] = 0
        return cls(reader, writer, endpoint.transport, on_push, on_lost, features, on_orphan)

    @staticmethod
    async def _read_one(reader: asyncio.StreamReader, limit: int) -> Any:
        header = await reader.readexactly(4)
        n = wire.frame_length(header, limit)
        body = await asyncio.wait_for(reader.readexactly(n), wire.FRAME_TIMEOUT_S)
        return wire.parse_server_frame(wire.decode_json(body))

    @classmethod
    async def _handshake(
        cls,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        transport: str,
        secret: Optional[bytearray],
        binding: Optional[wire.ChannelBinding],
    ) -> List[str]:
        params: Dict[str, Any] = {
            "proto": wire.PROTO,
            "lang": "python",
            "sdk_version": _sdk_version(),
            "pid": os.getpid() & 0xFFFFFFFF,
            "required_features": list(wire.REQUIRED_FEATURES),
        }
        nonce_c = None
        if transport == "tcp":
            nonce_c = wire.random_nonce_hex()
            params["nonce_c"] = nonce_c
        wire.validate_request("hello", params, transport=transport)
        writer.write(wire.encode_frame({"id": 0, "method": "hello", "params": params}))
        await writer.drain()
        answer = await cls._read_one(reader, wire.MAX_HANDSHAKE_FRAME)
        if not isinstance(answer, wire.Response) or answer.id != 0:
            raise wire.WireError("the connector did not answer hello")
        if answer.error is not None:
            raise wire.WireError(f"the connector refused hello ({answer.error.code})")
        if transport == "tcp":
            assert secret is not None and binding is not None and nonce_c is not None
            if not wire.validate_result("hello", answer.ok, transport="tcp"):
                raise wire.WireError("the connector's challenge is malformed")
            if not wire.verify_server_proof(
                bytes(secret), wire.PROTO, nonce_c, answer.ok["nonce_s"], binding,
                answer.ok["server_proof"],
            ):
                # Not the connector we were told about: say nothing more.
                raise wire.WireError("the connector's proof does not verify")
            proof = wire.client_proof(bytes(secret), wire.PROTO, nonce_c, answer.ok["nonce_s"], binding)
            writer.write(
                wire.encode_frame({"id": 1, "method": "auth", "params": {"client_proof": proof}})
            )
            await writer.drain()
            answer = await cls._read_one(reader, wire.MAX_HANDSHAKE_FRAME)
            if not isinstance(answer, wire.Response) or answer.id != 1:
                raise wire.WireError("the connector did not answer auth")
            if answer.error is not None:
                raise wire.WireError(f"the connector refused auth ({answer.error.code})")
            if not wire.validate_result("auth", answer.ok):
                raise wire.WireError("the connector's hello answer is malformed")
        elif not wire.validate_result("hello", answer.ok, transport="unix"):
            raise wire.WireError("the connector's hello answer is malformed")
        proto = answer.ok["proto"]
        if not (proto == wire.PROTO or proto.startswith(wire.PROTO + ".")):
            raise wire.WireError("the connector speaks another protocol version")
        features = list(answer.ok["features"])
        if not set(wire.REQUIRED_FEATURES) <= set(features):
            raise wire.WireError("the connector lacks a required feature")
        return features

    # -- requests ---------------------------------------------------------

    async def request(
        self, method: str, params: Dict[str, Any], timeout: float
    ) -> Optional[Tuple[wire.Response, Optional[str]]]:
        """Send one request and wait for its answer. Returns ``None`` when the
        connection was lost; raises :class:`asyncio.TimeoutError` when no
        slot freed up or no answer came within ``timeout``, and
        :class:`wire.InvalidRequest` when the request was refused locally.

        **A late answer is not a dead connection.** Some connector paths are
        legitimately slow (a create or spawn that waits on wl-apdp and then
        closes an orphaned session; a decision-path publish or a session
        close retried for up to the connector's lineage retry budget, which
        operators can raise to 300 s). So at the deadline only THIS caller
        gets its fail-closed answer (the request is abandoned: a run it
        creates later is ended through ``on_orphan``, and its late answer
        still frees its slot). The connection is then probed with ``health``:
        if that also gets no answer within :attr:`probe_timeout_s`, the
        connector or the channel is wedged, a wedged channel cannot deliver
        kill pushes either, and the connection is dropped, which kills its
        runs (fail closed). A probe that cannot get a request slot in that
        time counts as no answer.

        The answer is ``(response, orphan_run)``: an ``ok`` body that is not
        exactly what the method may answer is replaced by a refusal, and
        ``orphan_run`` then names a run the connector created anyway (so the
        caller can end it)."""
        wire.validate_request(method, params, transport=self.transport)
        if self.closed:
            return None
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        if not await self._take_slot(deadline):
            return None
        try:
            rid = self._next_id
            data = wire.encode_frame({"id": rid, "method": method, "params": params})
        except BaseException:
            self._free_slot()
            raise
        self._next_id += 1
        fut: "asyncio.Future[Optional[Tuple[wire.Response, Optional[str]]]]" = loop.create_future()
        pending = _Pending(method, fut)
        self._pending[rid] = pending
        written = False
        try:
            async with self._wlock:
                if self.closed:
                    self._forget(rid)
                    return None
                self._writer.write(data)
                written = True
                await asyncio.wait_for(self._writer.drain(), wire.WRITE_TIMEOUT_S)
        except (OSError, asyncio.TimeoutError, RuntimeError):
            self.lose()
            return None
        except BaseException:
            # Cancelled. Before the write nothing reached the connector: the
            # slot is freed. After it, the connector will answer: the slot
            # stays taken until then (or until the request expires).
            if not written:
                self._forget(rid)
            else:
                pending.abandoned = True
                self._arm(rid, pending, loop.time() + timeout)
            raise
        self._last_send = loop.time()
        # The connector gets the full timeout from the moment the request
        # is written, however long it waited for a slot.
        answer_by = self._last_send + timeout
        self._arm(rid, pending, answer_by)
        try:
            return await asyncio.wait_for(asyncio.shield(fut), max(0.0, answer_by - loop.time()))
        except (asyncio.CancelledError, asyncio.TimeoutError):
            pending.abandoned = True
            raise

    async def _take_slot(self, deadline: float) -> bool:
        loop = asyncio.get_running_loop()
        while self._in_flight >= wire.MAX_IN_FLIGHT:
            if self.closed:
                return False
            waiter: "asyncio.Future[None]" = loop.create_future()
            self._slot_waiters.append(waiter)
            try:
                await asyncio.wait_for(waiter, max(0.0, deadline - loop.time()))
            finally:
                if waiter in self._slot_waiters:
                    self._slot_waiters.remove(waiter)
        if self.closed:
            return False
        self._in_flight += 1
        return True

    def _free_slot(self) -> None:
        self._in_flight = max(0, self._in_flight - 1)
        self._wake_slot_waiters()

    def _wake_slot_waiters(self) -> None:
        waiters, self._slot_waiters = self._slot_waiters, []
        for waiter in waiters:
            if not waiter.done():
                waiter.set_result(None)

    def _forget(self, rid: int) -> None:
        pending = self._pending.pop(rid, None)
        if pending is not None:
            if pending.expiry is not None:
                pending.expiry.cancel()
            self._free_slot()

    def _arm(self, rid: int, pending: _Pending, deadline: float) -> None:
        if pending.expiry is None and rid in self._pending:
            pending.expiry = asyncio.get_running_loop().call_at(deadline, self._expire, rid)

    def _expire(self, rid: int) -> None:
        pending = self._pending.get(rid)
        if pending is None or self.closed:
            return
        pending.abandoned = True
        logger.warning(
            "the connector did not answer %s within the request timeout; probing "
            "the control connection",
            pending.method,
        )
        if self._probe_task is None or self._probe_task.done():
            self._probe_task = asyncio.ensure_future(self._probe())

    async def _probe(self) -> None:
        """Drop the connection unless ``health`` answers within
        :attr:`probe_timeout_s`."""
        try:
            answer = await self.request("health", {}, self.probe_timeout_s)
        except asyncio.TimeoutError:
            answer = None
        except asyncio.CancelledError:
            return
        if answer is None and not self.closed:
            logger.warning(
                "the connector did not answer a health probe either; dropping the "
                "control connection (its runs are treated as killed)"
            )
            self.lose()

    async def _read_loop(self) -> None:
        try:
            while True:
                frame = await self._read_one(self._reader, wire.MAX_FRAME)
                if isinstance(frame, wire.KillPush):
                    self._on_push(frame)
                    continue
                if frame.id is None:
                    # The connector could not read one of our frames and is
                    # closing the connection.
                    raise wire.WireError("the connector refused a frame")
                pending = self._pending.pop(frame.id, None)
                if pending is None:
                    raise wire.WireError("an answer to no request")
                if pending.expiry is not None:
                    pending.expiry.cancel()
                self._free_slot()
                orphan: Optional[str] = None
                created = (
                    frame.ok.get("run") or frame.ok.get("child_run")
                    if frame.error is None
                    and isinstance(frame.ok, dict)
                    and pending.method in ("create_session", "spawn_subagent")
                    else None
                )
                if pending.abandoned:
                    # Nobody is waiting for this answer any more: a run it
                    # created must not stay live on the connector.
                    if wire.is_run_ref(created) and self._on_orphan is not None:
                        logger.warning(
                            "the connector answered %s after the caller stopped waiting; "
                            "ending the run it created",
                            pending.method,
                        )
                        self._on_orphan(str(created))
                    continue
                if frame.error is None and not wire.validate_result(pending.method, frame.ok):
                    if wire.is_run_ref(created):
                        orphan = created
                    logger.warning(
                        "the connector answered %s with a malformed result; refusing it",
                        pending.method,
                    )
                    frame = wire.Response(id=frame.id, error=wire.INVALID_ERROR)
                if not pending.future.done():
                    pending.future.set_result((frame, orphan))
        except asyncio.CancelledError:
            pass
        except (asyncio.IncompleteReadError, asyncio.TimeoutError, OSError, wire.WireError) as exc:
            if not self.closed and not self._closing:
                logger.warning("the control connection ended (%s)", type(exc).__name__)
        finally:
            self.lose()

    async def _heartbeat(self) -> None:
        loop = asyncio.get_running_loop()
        try:
            while not self.closed:
                await asyncio.sleep(self.heartbeat_s)
                if self.closed or self._pending:
                    continue
                if loop.time() - self._last_send < self.heartbeat_s:
                    continue
                try:
                    answer = await self.request("health", {}, wire.FRAME_TIMEOUT_S)
                except asyncio.TimeoutError:
                    answer = None
                if answer is None:
                    self.lose()
                    return
        except asyncio.CancelledError:
            pass

    def lose(self) -> None:
        """End the connection. Every waiting request gets ``None``; the
        backend is told once, and treats every run on it as killed."""
        if self.closed:
            return
        self.closed = True
        try:
            self._writer.transport.abort()
        except Exception:  # noqa: BLE001
            pass
        for pending in self._pending.values():
            if pending.expiry is not None:
                pending.expiry.cancel()
            if not pending.future.done():
                pending.future.set_result(None)
        self._pending.clear()
        self._in_flight = 0
        self._wake_slot_waiters()
        current = asyncio.current_task()
        for task in (self._reader_task, self._heartbeat_task, self._probe_task):
            if task is None:
                continue
            if task is not current and not task.done():
                task.cancel()
        self._on_lost(self)

    async def close(self) -> None:
        if self.closed:
            return
        self._closing = True
        try:
            await self.request("close", {}, 1.0)
        except Exception:  # noqa: BLE001 - closing anyway
            pass
        self.lose()


# ---------------------------------------------------------------------------
# The backend's private event loop
# ---------------------------------------------------------------------------


async def _cancel_all_tasks() -> None:
    current = asyncio.current_task()
    tasks = [t for t in asyncio.all_tasks() if t is not current]
    for task in tasks:
        task.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)


class _IoLoop:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._thread: Optional[threading.Thread] = None

    def loop(self) -> asyncio.AbstractEventLoop:
        with self._lock:
            if self._loop is None or self._loop.is_closed():
                loop = asyncio.new_event_loop()
                thread = threading.Thread(
                    target=loop.run_forever, name="watchlight-sidecar-io", daemon=True
                )
                thread.start()
                self._loop, self._thread = loop, thread
            return self._loop

    def running(self) -> Optional[asyncio.AbstractEventLoop]:
        with self._lock:
            loop = self._loop
        return loop if loop is not None and not loop.is_closed() else None

    def in_loop_thread(self) -> bool:
        return self._thread is not None and threading.current_thread() is self._thread

    def stop(self) -> None:
        with self._lock:
            loop, thread = self._loop, self._thread
            self._loop, self._thread = None, None
        if loop is None:
            return
        if thread is not None and thread is not threading.current_thread():
            # Let every task on the loop (the reader, the heartbeat) finish
            # its cancellation before the loop stops.
            try:
                asyncio.run_coroutine_threadsafe(_cancel_all_tasks(), loop).result(timeout=5)
            except Exception:  # noqa: BLE001 - stopping anyway
                pass
        loop.call_soon_threadsafe(loop.stop)
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=5)
            if not loop.is_running():
                loop.close()


# ---------------------------------------------------------------------------
# The backend
# ---------------------------------------------------------------------------


@dataclass
class _Run:
    run: RunRef
    session_id: str
    agent_id: str
    conn: _Connection
    marker: str = field(repr=False)
    child_key: str = field(repr=False)
    parent: Optional[RunRef] = None
    children: Set[RunRef] = field(default_factory=set)
    ended: bool = False
    ended_at: float = 0.0
    egress: Optional[SidecarEgress] = field(default=None, repr=False)
    child_proxy_url: Optional[str] = field(default=None, repr=False)


@dataclass
class _Sub:
    callback: KillCallback
    loop: Optional[asyncio.AbstractEventLoop]


_BACKENDS: "weakref.WeakSet[SidecarBackend]" = weakref.WeakSet()
_CALLBACKS: Optional[concurrent.futures.ThreadPoolExecutor] = None
_CALLBACKS_LOCK = threading.Lock()


def _callback_executor() -> concurrent.futures.ThreadPoolExecutor:
    """One thread for kill callbacks that have no event loop to run on."""
    global _CALLBACKS
    with _CALLBACKS_LOCK:
        if _CALLBACKS is None:
            _CALLBACKS = concurrent.futures.ThreadPoolExecutor(
                max_workers=1, thread_name_prefix="watchlight-kill-callback"
            )
        return _CALLBACKS


def _after_fork_in_child() -> None:
    global _CALLBACKS
    _CALLBACKS = None  # its thread does not exist in the child
    for backend in list(_BACKENDS):
        backend._forked = True


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_after_fork_in_child)


class SidecarBackend:
    """The Enterprise governance backend: a ``wl-local/1`` client of the
    Watchlight connector. See the module docstring for the transport and
    the fail-closed rules.

    Construct it with exactly one of ``socket_path`` (preferred) or
    ``address`` (loopback TCP, with ``secret_file``), or use
    :meth:`from_env` / :meth:`launch`. Nothing connects until the first
    call.
    """

    def __init__(
        self,
        *,
        socket_path: Optional[str] = None,
        address: Optional[str] = None,
        secret_file: Optional[str] = None,
        request_timeout_s: float = _DEFAULT_REQUEST_TIMEOUT_S,
        _endpoint: Optional[_Endpoint] = None,
    ) -> None:
        if _endpoint is None:
            _endpoint = self._endpoint_from(socket_path, address, secret_file)
        self._endpoint = _endpoint
        self._timeout = float(request_timeout_s)
        self._io = _IoLoop()
        self._lock = threading.RLock()
        self._runs: Dict[str, _Run] = {}
        self._ended: "OrderedDict[str, float]" = OrderedDict()
        self._subs: Dict[str, List[_Sub]] = {}
        self._conn: Optional[_Connection] = None
        self._connect_lock: Optional[asyncio.Lock] = None
        self._forked = False
        self._stopped_loops: "weakref.WeakSet[asyncio.AbstractEventLoop]" = weakref.WeakSet()
        _BACKENDS.add(self)

    # -- construction -----------------------------------------------------

    @staticmethod
    def _endpoint_from(
        socket_path: Optional[str], address: Optional[str], secret_file: Optional[str]
    ) -> _Endpoint:
        if socket_path and address:
            raise GovernanceUnavailable(
                "SidecarBackend: configure either the connector's socket or its "
                "TCP address, not both"
            )
        if address:
            if not secret_file:
                raise GovernanceUnavailable(
                    "SidecarBackend: a TCP connector address needs the path of the "
                    f"connector's secret file ({ENV_SIDECAR_SECRET_FILE})"
                )
            try:
                host, port = wire.parse_dial_addr(address)
            except wire.WireError as exc:
                raise GovernanceUnavailable(f"SidecarBackend: {exc}") from None
            return _Endpoint(transport="tcp", host=host, port=port, secret_file=secret_file)
        if secret_file:
            raise GovernanceUnavailable(
                "SidecarBackend: a secret file is only used with a TCP connector address"
            )
        path = socket_path or str(wire.default_socket_path())
        if not os.path.isabs(path):
            raise GovernanceUnavailable("SidecarBackend: the connector socket path must be absolute")
        return _Endpoint(transport="unix", socket_path=path)

    @classmethod
    def from_env(cls, env: Optional[Mapping[str, str]] = None, **kwargs: Any) -> "SidecarBackend":
        """Build from ``WATCHLIGHT_SIDECAR_SOCKET``, or
        ``WATCHLIGHT_SIDECAR_ADDR`` with ``WATCHLIGHT_SIDECAR_SECRET_FILE``;
        with neither, the connector's default socket path."""
        env = os.environ if env is None else env
        return cls(
            socket_path=env.get(ENV_SIDECAR_SOCKET) or None,
            address=env.get(ENV_SIDECAR_ADDR) or None,
            secret_file=env.get(ENV_SIDECAR_SECRET_FILE) or None,
            **kwargs,
        )

    @classmethod
    def launch(
        cls, argv: List[str], *, startup_timeout_s: float = 10.0, **kwargs: Any
    ) -> "SidecarBackend":
        """Launch the connector with ``argv`` (it must serve loopback TCP and
        print its address and secret on stdout) and connect to it. The
        secret is read from the stdout pipe, kept in memory only, and wiped
        on :meth:`close`. Once the launched connector exits, this backend
        never reconnects: its port is free for anyone to take.

        Not for a connector that also runs the relay (``--wl-proxy-url``):
        the relay prints its own address on stdout, so the control secret
        then goes to ``--control-secret-file`` and the backend is built
        with ``address`` and ``secret_file`` instead."""
        proc = subprocess.Popen(  # noqa: S603 - argv is the operator's connector command
            argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, close_fds=True
        )
        lines: List[bytes] = []

        def _read() -> None:
            assert proc.stdout is not None
            for _ in range(2):
                line = proc.stdout.readline(256)
                if not line:
                    return
                lines.append(line)

        reader = threading.Thread(target=_read, daemon=True)
        reader.start()
        reader.join(startup_timeout_s)
        try:
            if len(lines) != 2:
                raise wire.WireError("the connector did not print its address and secret")
            host, port = wire.parse_dial_addr(lines[0].decode("ascii", "replace"))
            secret = wire.parse_secret_hex(lines[1].decode("ascii", "replace"))
        except wire.WireError as exc:
            proc.kill()
            proc.wait(timeout=5)
            raise GovernanceUnavailable(f"SidecarBackend: could not start the connector: {exc}") from None
        finally:
            lines.clear()
            # The connector prints nothing else on stdout; its logs go to
            # stderr.
            if proc.stdout is not None:
                proc.stdout.close()
        endpoint = _Endpoint(transport="tcp", host=host, port=port, launched_secret=secret, proc=proc)
        return cls(_endpoint=endpoint, **kwargs)

    def __repr__(self) -> str:
        return f"SidecarBackend({self._endpoint.describe()})"

    # -- plumbing ---------------------------------------------------------

    async def _on_io(self, coro: Awaitable[T]) -> T:
        """Run ``coro`` on the backend's I/O loop and await it from the
        caller's loop."""
        if self._forked:
            close = getattr(coro, "close", None)
            if close is not None:
                close()
            raise _Unavailable("forked")
        loop = self._io.loop()
        fut: "concurrent.futures.Future[T]" = asyncio.run_coroutine_threadsafe(coro, loop)  # type: ignore[arg-type]
        try:
            return await asyncio.wrap_future(fut)
        except asyncio.CancelledError:
            # The I/O loop was shut down under this call (close()): that is
            # a refusal for the caller, not a cancellation of the caller.
            if fut.cancelled() and loop in self._stopped_loops:
                raise _Unavailable("closed") from None
            raise

    async def _connection(self) -> _Connection:
        if self._connect_lock is None:
            self._connect_lock = asyncio.Lock()
        async with self._connect_lock:
            conn = self._conn
            if conn is not None and not conn.closed:
                return conn
            if not self._endpoint.may_connect():
                raise _Unavailable("the launched connector has exited")
            try:
                conn = await _Connection.open(
                    self._endpoint, self._on_push, self._on_lost, self._on_orphan
                )
            except (OSError, asyncio.TimeoutError, asyncio.IncompleteReadError, wire.WireError) as exc:
                logger.error(
                    "cannot reach the Watchlight connector over its %s (%s)",
                    self._endpoint.describe(),
                    exc if isinstance(exc, wire.WireError) else type(exc).__name__,
                )
                raise _Unavailable("connect") from None
            self._conn = conn
            return conn

    async def _call(
        self, method: str, params: Dict[str, Any], timeout: Optional[float] = None
    ) -> Tuple[wire.Response, Optional[str], _Connection]:
        """One request on the I/O loop. Raises :class:`_Unavailable` when the
        connector cannot be reached, the connection is lost or no answer came
        in time; :class:`wire.InvalidRequest` when the request was refused
        locally."""
        conn = await self._connection()
        try:
            answer = await conn.request(method, params, self._timeout if timeout is None else timeout)
        except asyncio.TimeoutError:
            logger.warning("the connector did not answer %s in time; failing closed", method)
            raise _Unavailable("timeout") from None
        if answer is None:
            raise _Unavailable("lost")
        response, orphan = answer
        return response, orphan, conn

    def _sweep(self) -> None:
        now = time.monotonic()
        with self._lock:
            while self._ended:
                run, at = next(iter(self._ended.items()))
                if now - at < wire.ENDED_RUN_WINDOW_S:
                    break
                self._ended.popitem(last=False)
                self._runs.pop(run, None)
                self._subs.pop(run, None)

    def _live(self, run: Any) -> Optional[_Run]:
        if self._forked:
            return None
        self._sweep()
        with self._lock:
            entry = self._runs.get(run) if isinstance(run, str) else None
            if entry is None or entry.ended or entry.conn.closed:
                return None
            return entry

    def _known(self, run: Any) -> Optional[_Run]:
        """Live, or ended within the late-lineage window."""
        if self._forked:
            return None
        self._sweep()
        with self._lock:
            return self._runs.get(run) if isinstance(run, str) else None

    def _end_run(self, run: str, reason: str, source: str = "backend") -> None:
        """End ``run`` and its sub-agent subtree locally and tell their kill
        subscribers. Idempotent."""
        notices: List[Tuple[_Sub, KillNotice]] = []
        with self._lock:
            stack = [run]
            while stack:
                current = stack.pop()
                entry = self._runs.get(current)
                if entry is None or entry.ended:
                    continue
                entry.ended = True
                entry.ended_at = time.monotonic()
                entry.egress = None
                entry.child_proxy_url = None
                self._ended[current] = entry.ended_at
                stack.extend(entry.children)
                notice = KillNotice(run=RunRef(current), reason=reason, source=source)
                for sub in self._subs.pop(current, []):
                    notices.append((sub, notice))
        for sub, notice in notices:
            self._dispatch(sub, notice)

    @staticmethod
    def _dispatch(sub: _Sub, notice: KillNotice) -> None:
        """Run the callback on the loop it was subscribed from; without
        one, on a separate callback thread, never on the I/O thread (a
        callback that blocks, or calls back into the backend, must not
        stall the control connection)."""
        loop = sub.loop
        if loop is not None and not loop.is_closed():
            try:
                loop.call_soon_threadsafe(fire_kill_callback, sub.callback, notice)
                return
            except RuntimeError:
                pass
        _callback_executor().submit(fire_kill_callback, sub.callback, notice)

    def _on_push(self, push: wire.KillPush) -> None:
        with self._lock:
            known = push.run in self._runs
        if not known:
            return
        # The reason is the connector's short text; only the source (a
        # closed set) reaches the log.
        logger.warning("the connector ended a run (source=%s)", push.source)
        self._end_run(push.run, "killed", push.source)

    def _on_orphan(self, run: str) -> None:
        """A run the connector created for a caller that stopped waiting:
        end it (best effort)."""
        asyncio.ensure_future(self._discard_created(run))

    def _on_lost(self, conn: _Connection) -> None:
        if self._conn is conn:
            self._conn = None
        with self._lock:
            runs = [r for r, e in self._runs.items() if e.conn is conn and not e.ended]
        for run in runs:
            self._end_run(run, "connection_lost", "local")

    def _refused(self, method: str, response: wire.Response, run: Optional[str] = None) -> wire.ErrorBody:
        """Log a refusal (codes only) and end ``run`` locally when the
        connector says it is gone."""
        err = response.error or wire.INVALID_ERROR
        if run is not None and err.code in ("unknown_run", "run_ended"):
            self._end_run(run, err.reason or err.code)
        logger.warning(
            "the connector refused %s (code=%s, reason=%s)",
            method,
            err.code if err.valid else "malformed",
            err.reason or "-",
        )
        return err

    @staticmethod
    def _refusal(method: str, err: wire.ErrorBody, what: str) -> GovernanceRefused:
        """The :class:`GovernanceRefused` for a connector ``denied``
        answer (wl-apdp refused with ``401`` / ``403``). ``reason`` is the
        closed-list code the connector sent (e.g. ``agent_trust_revoked``),
        never server text. The connector reports a denial without its HTTP
        status, so ``status_code`` is ``403``."""
        reason = err.reason if err.valid else None
        return GovernanceRefused(
            f"{method}: Watchlight refused {what} (code={reason or 'denied'}); "
            "refusing the run",
            status_code=403,
            reason=reason,
        )

    def _register(
        self,
        conn: _Connection,
        run: str,
        session_id: str,
        agent_id: str,
        marker: str,
        child_key: str,
        parent: Optional[str] = None,
    ) -> bool:
        with self._lock:
            if run in self._runs:
                return False
            if parent is not None:
                parent_entry = self._runs.get(parent)
                if parent_entry is None or parent_entry.ended:
                    return False
                parent_entry.children.add(RunRef(run))
            self._runs[run] = _Run(
                run=RunRef(run),
                session_id=session_id,
                agent_id=agent_id,
                conn=conn,
                marker=marker,
                child_key=child_key,
                parent=RunRef(parent) if parent else None,
            )
        return True

    async def _discard_created(self, run: str) -> None:
        """End a run the connector created that this SDK will not use."""
        try:
            await self._call("terminate_session", {"run": run, "reason": "refused_by_sdk"}, 5.0)
        except Exception:  # noqa: BLE001 - the refusal is what counts
            pass
        self._end_run(run, "refused_by_sdk")

    async def _subscribe(self, run: str) -> bool:
        try:
            response, _o, _c = await self._call("subscribe_kill", {"run": run})
        except (_Unavailable, wire.InvalidRequest):
            return False
        if response.error is not None:
            self._refused("subscribe_kill", response, run)
            return False
        return True

    async def _cancel_safe(self, inner: "Callable[[], Awaitable[T]]", on_abandon: Callable[[T], Awaitable[None]]) -> T:
        """Run ``inner`` to completion even if the caller is cancelled; when
        the caller is gone, ``on_abandon`` gets what it made."""
        task = asyncio.ensure_future(inner())
        try:
            return await asyncio.shield(task)
        except asyncio.CancelledError:

            def _done(t: "asyncio.Future[T]") -> None:
                if not t.cancelled() and t.exception() is None:
                    asyncio.ensure_future(on_abandon(t.result()))

            task.add_done_callback(_done)
            raise

    # -- GovernanceBackend: identity and sessions -------------------------

    async def resolve_agent(self, slug: str) -> Optional[Dict[str, Any]]:
        """The connector's answer for ``slug``, or ``None`` when it is not
        registered or the connector refused or could not answer."""
        try:
            return await self._on_io(self._io_resolve_agent(slug))
        except _Unavailable:
            return None

    async def _io_resolve_agent(self, slug: str) -> Optional[Dict[str, Any]]:
        try:
            response, _o, _c = await self._call("resolve_agent", {"slug": slug})
        except wire.InvalidRequest:
            logger.warning("agent resolve refused locally: the slug is not a valid identifier")
            return None
        if response.error is not None:
            self._refused("resolve_agent", response)
            return None
        if _carries_credential(response.ok["agent"]):
            logger.error("the connector's answer to resolve_agent carries a credential-shaped value; refusing it")
            return None
        return response.ok["agent"]

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
        """Open a run on the connector. Returns its
        :class:`~watchlight_core.backend.SessionInfo` (no credential), or
        ``None`` when the connector refused it. Raises
        :class:`GovernanceUnavailable` when the connector cannot be
        reached.

        The connector's protocol names the agent of every run, so a run
        that names none (``agent_id=None``, the credential-bound root) is
        refused here with :class:`WatchlightContractError` before anything
        is sent: name the agent when the connector is the backend."""
        if declared_root is not None:
            # The connector protocol doesn't carry a declared root, so
            # refuse rather than open an undeclared independent root.
            raise DeclaredRootRefused(
                "The Watchlight connector (wl-sidecar) cannot open a declared root "
                "run yet; the agent was not started.",
                code=DECLARED_ROOT_UNSUPPORTED,
            )
        if agent_id is None:
            raise WatchlightContractError(
                "agent_id is required: the Watchlight connector (wl-sidecar) opens a run "
                "only for the agent it names. Name the agent (agent_id or a slug)."
            )
        params: Dict[str, Any] = {"agent_id": agent_id, "ttl_seconds": ttl_seconds}
        if goal_id:
            params["goal_id"] = goal_id
        if max_actions is not None:
            params["max_actions"] = max_actions
        if metadata:
            params["metadata"] = metadata
        if subject_token:
            params["subject_token"] = subject_token
        if application_id:
            params["application_id"] = application_id
        try:
            info = await self._on_io(self._io_create_session(agent_id, params))
        except _Unavailable:
            raise GovernanceUnavailable(
                "The Watchlight connector (wl-sidecar) is not reachable; refusing "
                "the run. Check that the connector is running and that "
                f"{ENV_SIDECAR_SOCKET} (or {ENV_SIDECAR_ADDR}) names it."
            ) from None
        if isinstance(info, GovernanceRefused):
            # wl-apdp refused to open a run for this agent (e.g. its
            # trust is revoked): a typed refusal, so the caller says why.
            raise info
        return info

    async def _io_create_session(
        self, agent_id: str, params: Dict[str, Any]
    ) -> "Optional[SessionInfo] | GovernanceRefused":
        refusal: List[GovernanceRefused] = []

        async def inner() -> Tuple[Optional[SessionInfo], Optional[str]]:
            try:
                response, orphan, conn = await self._call("create_session", params)
            except wire.InvalidRequest:
                logger.warning("session create refused locally: a parameter is not allowed by the protocol")
                return None, None
            if response.error is not None:
                err = self._refused("create_session", response)
                if orphan is not None:
                    await self._discard_created(orphan)
                if err.valid and err.code == "denied" and err.reason in _TRUST_REASONS:
                    refusal.append(self._refusal("create_session", err, f"a run for agent {agent_id}"))
                return None, None
            ok = response.ok
            run = ok["run"]
            if not self._register(conn, run, ok["session_id"], agent_id, ok["marker"], ok["child_key"]):
                logger.error("the connector reused a run reference; refusing the run")
                await self._discard_created(run)
                return None, None
            if not await self._subscribe(run):
                logger.error("the run's kill subscription was refused; refusing the run")
                await self._discard_created(run)
                return None, None
            if self._live(run) is None:
                # Killed while it was being opened: never hand it out.
                logger.warning("the run was ended while it was being opened; refusing it")
                await self._discard_created(run)
                return None, None
            scope = ok["scope"]
            root = scope.get("root_run_handle_id")
            info = SessionInfo(
                run=RunRef(run),
                session_id=ok["session_id"],
                agent_id=agent_id,
                execution_id=ok["execution_id"],
                root_run_handle_id=(
                    root if isinstance(root, str) and root and not _credential_shaped(root) else None
                ),
                session=public_session_record(scope.get("session")),
            )
            return info, run

        async def abandon(made: Tuple[Optional[SessionInfo], Optional[str]]) -> None:
            if made[1] is not None:
                await self._discard_created(made[1])

        info, _run = await self._cancel_safe(inner, abandon)
        if refusal:
            return refusal[0]
        return info

    async def get_manifest(
        self,
        agent_id: str,
        goal_id: Optional[str] = None,
        ttl_seconds: int = 3600,
        run: Optional[RunRef] = None,
        application_id: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """The run's pre-flight manifest, bounded by the run's grant. The
        connector derives the agent, goal and application from the run, so
        a call without a run (or for an unknown or ended one) is ``None``
        (plan governance then refuses the run unless the operator opted
        into degraded mode).

        A refusal raises, it is never ``None``. A ``denied`` answer
        (wl-apdp refused the manifest with ``401`` / ``403``, e.g.
        ``agent_trust_revoked``) raises
        :class:`~watchlight_core.errors.GovernanceRefused` carrying the code,
        so ``WATCHLIGHT_PLAN_GOVERNANCE_MODE=degrade`` never lets a refused
        agent run. A malformed answer, or one saying the run is gone,
        raises :class:`GovernanceUnavailable`. Only an outage (the connector
        unreachable, ``unavailable`` or ``internal``) is ``None``."""
        del agent_id, goal_id, ttl_seconds, application_id
        if run is None or self._live(run) is None:
            return None
        try:
            result = await self._on_io(self._io_manifest(run))
        except _Unavailable:
            return None
        if isinstance(result, BaseException):
            raise result
        return result

    async def _io_manifest(
        self, run: str
    ) -> "Optional[Dict[str, Any]] | GovernanceUnavailable":
        try:
            response, _o, _c = await self._call("get_manifest", {"run": run})
        except wire.InvalidRequest:
            logger.warning("get_manifest refused locally: a parameter is not allowed by the protocol")
            return None
        if response.error is not None:
            err = self._refused("get_manifest", response, run)
            if not err.valid:
                # A malformed answer cannot rule a refusal out: fail closed.
                return GovernanceUnavailable(
                    "get_manifest: the connector's answer is malformed; refusing the run"
                )
            if err.code == "denied":
                return self._refusal("get_manifest", err, "the constraint manifest")
            if err.code in ("unknown_run", "run_ended"):
                return GovernanceUnavailable(
                    f"get_manifest: the run has ended (code={err.code}, "
                    f"reason={err.reason or '-'}); refusing the run"
                )
            # An outage (`unavailable`, `internal`): no manifest.
            return None
        if _carries_credential(response.ok["manifest"]):
            logger.error("the connector's answer to get_manifest carries a credential-shaped value; refusing it")
            return None
        return response.ok["manifest"]

    async def _io_simple(self, method: str, params: Dict[str, Any], key: str, run: Optional[str]) -> Optional[Dict[str, Any]]:
        try:
            response, _o, _c = await self._call(method, params)
        except wire.InvalidRequest:
            logger.warning("%s refused locally: a parameter is not allowed by the protocol", method)
            return None
        if response.error is not None:
            self._refused(method, response, run)
            return None
        if _carries_credential(response.ok[key]):
            logger.error("the connector's answer to %s carries a credential-shaped value; refusing it", method)
            return None
        return response.ok[key]

    # -- GovernanceBackend: decisions -------------------------------------

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
    ) -> Dict[str, Any]:
        """wl-apdp's decision, through the connector. Always a dict with at
        least ``decision``; every failure is ``{"decision": "Deny", ...}``.
        ``session_id`` is not sent: the connector binds the decision to the
        run itself. An unknown or ended ``run`` is a Deny without a
        request."""
        del session_id
        params: Dict[str, Any] = {
            "principal": principal,
            "action": action,
            "resource": resource,
            "context": context or {},
        }
        if run is not None:
            if self._live(run) is None:
                return {"decision": "Deny", "reason": "unknown or ended run"}
            params["run"] = run
        if intent:
            params["intent"] = intent
        if execution_id:
            if not wire.is_execution_id(execution_id):
                logger.warning("authorize refused locally: the execution id is not exec_<uuid>")
                return {"decision": "Deny", "reason": "invalid execution id"}
            params["execution_id"] = execution_id
        try:
            return await self._on_io(self._io_authorize(params, run))
        except _Unavailable:
            return {"decision": "Deny", "reason": "governance connector unavailable"}
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 - a decision never fails open
            logger.error("authorize failed (%s); failing closed to Deny", type(exc).__name__)
            return {"decision": "Deny", "reason": "governance connector failure"}

    async def _io_authorize(self, params: Dict[str, Any], run: Optional[str]) -> Dict[str, Any]:
        try:
            response, _o, _c = await self._call("authorize", params)
        except wire.InvalidRequest:
            logger.warning("authorize refused locally: a parameter is not allowed by the protocol")
            return {"decision": "Deny", "reason": "invalid authorization request"}
        if response.error is not None:
            err = self._refused("authorize", response, run)
            if not err.valid:
                return {"decision": "Deny", "reason": "malformed connector answer"}
            if err.code == "unavailable":
                return {"decision": "Deny", "reason": "governance unavailable"}
            return {"decision": "Deny", "reason": err.reason or err.code}
        decision = response.ok["decision"]
        if _carries_credential(decision):
            logger.error("the connector's decision carries a credential-shaped value; failing closed to Deny")
            return {"decision": "Deny", "reason": "malformed connector answer"}
        if not isinstance(decision.get("decision"), str):
            logger.error("the connector's decision carries no decision; failing closed to Deny")
            return {"decision": "Deny", "reason": "unrecognised decision"}
        return decision

    async def preflight_step(
        self,
        run: RunRef,
        action: str,
        resource: str,
        resource_type: Optional[str] = None,
        intent: Optional[Dict[str, Any]] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        """A read-only check that the step would be permitted. ``None`` on
        any failure, or for an unknown or ended run (no request)."""
        if self._live(run) is None:
            return None
        params: Dict[str, Any] = {"run": run, "action": action, "resource": resource}
        if resource_type:
            params["resource_type"] = resource_type
        if intent:
            params["intent"] = intent
        if context:
            params["context"] = context
        try:
            return await self._on_io(self._io_simple("preflight_step", params, "result", run))
        except _Unavailable:
            return None

    async def submit_plan(self, run: RunRef, plan: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Submit the run's plan. ``None`` on any failure, or for an unknown
        or ended run (no request)."""
        if self._live(run) is None:
            return None
        try:
            return await self._on_io(
                self._io_simple("submit_plan", {"run": run, "plan": list(plan)}, "result", run)
            )
        except _Unavailable:
            return None

    # -- GovernanceBackend: sub-agents ------------------------------------

    async def spawn_subagent(self, parent: RunRef, request: Dict[str, Any]) -> Dict[str, Any]:
        """Ask the connector to spawn a sub-agent of ``parent``. Returns the
        canonical spawn response with ``child_run`` and no credential.

        Every refusal raises, so the child never runs:

        * :class:`ScopeAttenuationDenied` when the child asks for more than
          its parent has;
        * :class:`RunHandleInvalidated` when the parent's handle is no
          longer valid;
        * :class:`ParentRunUncredentialed` when the connector holds no run
          for the parent;
        * :class:`AgentNotRegistered` when the child agent is unknown;
        * :class:`GovernanceUnavailable` for an unknown or ended parent, an
          unreachable connector, a timeout or a malformed answer;
        * :class:`GovernanceRefused` for any other refusal (``denied``),
          carrying the connector's code, e.g. ``delegation_chain_not_trusted``
          or ``agent_trust_revoked``.
        """
        if self._live(parent) is None:
            raise GovernanceUnavailable(
                "spawn_subagent: the parent run is unknown or has ended; refusing the spawn"
            )
        try:
            return await self._on_io(self._io_spawn(parent, request))
        except _Unavailable:
            raise GovernanceUnavailable(
                "spawn_subagent: the Watchlight connector did not answer; the "
                "sub-agent was not started"
            ) from None

    async def _io_spawn(self, parent: str, request: Dict[str, Any]) -> Dict[str, Any]:
        async def inner() -> Tuple[Optional[Dict[str, Any]], Optional[BaseException], Optional[str]]:
            try:
                response, orphan, conn = await self._call(
                    "spawn_subagent", {"parent_run": parent, "request": request}
                )
            except wire.InvalidRequest:
                return None, GovernanceUnavailable(
                    "spawn_subagent: the request is not allowed by the protocol; "
                    "the sub-agent was not started"
                ), None
            if response.error is not None:
                if orphan is not None:
                    await self._discard_created(orphan)
                return None, self._spawn_refusal(parent, response), None
            ok = response.ok
            child = ok["child_run"]
            with self._lock:
                parent_entry = self._runs.get(parent)
                parent_marker = parent_entry.marker if parent_entry else None
            if child == parent or ok["child_marker"] == parent_marker:
                if child != parent:
                    await self._discard_created(child)
                return None, GovernanceUnavailable(
                    "spawn_subagent: the connector reused the parent's run or marker; "
                    "the sub-agent was not started"
                ), None
            scope = ok["scope"]
            out = {k: scope[k] for k in _SPAWN_FIELDS if k in scope}
            out["child_session_id"] = ok["session_id"]
            out["child_execution_id"] = ok["execution_id"]
            handle = out.get("child_run_handle_id")
            if (
                not isinstance(handle, str)
                or not handle
                or not isinstance(out.get("granted_scope"), dict)
                or _carries_credential(out)
            ):
                await self._discard_created(child)
                return None, GovernanceUnavailable(
                    "spawn_subagent: the connector's answer is not a canonical spawn "
                    "response; the sub-agent was not started"
                ), None
            # The agent the child runs as is the one wl-apdp names (a labelled
            # child's mapped agent, or its parent's for an anonymous child);
            # an older server that names none ran the requested agent.
            child_agent = out.get("child_agent_id") or (
                request.get("child_agent_id") if isinstance(request, Mapping) else None
            )
            if not self._register(
                conn, child, ok["session_id"],
                str(child_agent) if child_agent is not None else "",
                ok["child_marker"], ok["child_key"], parent=parent,
            ):
                # The parent ended while the spawn was in flight (or the
                # reference was reused): its authority to delegate is gone.
                await self._discard_created(child)
                return None, GovernanceUnavailable(
                    "spawn_subagent: the parent run ended while the spawn was in "
                    "flight; the sub-agent was not started"
                ), None
            if not await self._subscribe(child):
                await self._discard_created(child)
                return None, GovernanceUnavailable(
                    "spawn_subagent: the child's kill subscription was refused; the "
                    "sub-agent was not started"
                ), None
            if self._live(child) is None:
                await self._discard_created(child)
                return None, GovernanceUnavailable(
                    "spawn_subagent: the child (or its parent) was ended while it was "
                    "being opened; the sub-agent was not started"
                ), None
            out["child_run"] = RunRef(child)
            return out, None, child

        async def abandon(made: Tuple[Optional[Dict[str, Any]], Optional[BaseException], Optional[str]]) -> None:
            if made[2] is not None:
                await self._discard_created(made[2])

        out, error, _child = await self._cancel_safe(inner, abandon)
        if error is not None:
            raise error
        assert out is not None
        return out

    def _spawn_refusal(self, parent: str, response: wire.Response) -> BaseException:
        err = response.error or wire.INVALID_ERROR
        logger.warning(
            "the connector refused spawn_subagent (code=%s, reason=%s)",
            err.code if err.valid else "malformed",
            err.reason or "-",
        )
        if not err.valid:
            return GovernanceUnavailable(
                "spawn_subagent: the connector's answer is malformed; the sub-agent was not started"
            )
        if err.code == "denied":
            if err.reason == "scope_attenuation_violation":
                return ScopeAttenuationDenied(reason="scope_attenuation_violation")
            if err.reason == "agent_not_registered":
                return AgentNotRegistered(
                    "spawn_subagent: the child agent is not registered; the sub-agent was not started"
                )
            # A refusal (an untrusted delegation chain, a child
            # whose trust is revoked, ...) carries the real code; never a
            # scope violation. The child never runs.
            return GovernanceRefused(
                f"spawn_subagent: refused (code={err.reason or 'denied'}); the sub-agent was not started",
                status_code=403,
                reason=err.reason,
            )
        if err.code == "run_ended":
            self._end_run(parent, err.reason or "run_ended")
            if err.reason == "run_handle_invalidated":
                return RunHandleInvalidated(reason="run_handle_invalidated")
            return GovernanceUnavailable(
                f"spawn_subagent: the parent run has ended (reason={err.reason or 'run_ended'}); "
                "the sub-agent was not started"
            )
        if err.code == "unknown_run":
            self._end_run(parent, "unknown_run")
            return ParentRunUncredentialed(
                "spawn_subagent: the connector holds no run for the parent; refusing to run the sub-agent."
            )
        return GovernanceUnavailable(
            f"spawn_subagent: the connector could not decide ({err.code}); the sub-agent was not started"
        )

    # -- GovernanceBackend: lineage ---------------------------------------

    async def publish_events(self, run: Optional[RunRef], events: List[Dict[str, Any]]) -> bool:
        """Hand a batch of lineage events to the connector, which delivers
        them under the run's own credential. On the governance decision path
        (``lineage_decision_path``) the batch goes in ``decision_path`` mode
        (delivered at once with a short, bounded retry budget); otherwise in
        ``background`` mode (queued on the connector's retry lanes).

        ``True`` when every event was accepted; ``False`` for no run, an
        unknown run (an ended run's late lineage is still accepted for a
        short window), a refusal or any failure. Never raises, except
        :class:`asyncio.CancelledError`."""
        if not events:
            return True
        entry = self._known(run) if run is not None else None
        if run is None or entry is None or entry.conn.closed:
            logger.warning(
                "publish_events refused: no live or recently ended run for %d event(s)",
                len(events),
            )
            return False
        mode = "decision_path" if on_decision_path() else "background"
        batches = self._batches(list(events))
        if batches is None:
            return False
        try:
            return await self._on_io(self._io_publish(run, batches, mode))
        except _Unavailable:
            return False

    @staticmethod
    def _batches(events: List[Dict[str, Any]]) -> Optional[List[List[Dict[str, Any]]]]:
        """Split ``events`` into frames of at most 1000 events and 1 MiB."""
        budget = wire.MAX_FRAME - _FRAME_OVERHEAD
        out: List[List[Dict[str, Any]]] = []
        current: List[Dict[str, Any]] = []
        size = 0
        for event in events:
            if not wire.is_json_object(event):
                logger.warning("publish_events refused: an event is not a bounded JSON object")
                return None
            try:
                n = len(json.dumps(event, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")) + 1
            except (TypeError, ValueError):
                logger.warning("publish_events refused: an event is not JSON-serialisable")
                return None
            if n > budget:
                logger.warning("publish_events refused: one event exceeds the frame limit")
                return None
            if current and (size + n > budget or len(current) >= wire.MAX_EVENTS_PER_FRAME):
                out.append(current)
                current, size = [], 0
            current.append(event)
            size += n
        if current:
            out.append(current)
        return out

    async def _io_publish(self, run: str, batches: List[List[Dict[str, Any]]], mode: str) -> bool:
        for batch in batches:
            try:
                response, _o, _c = await self._call(
                    "publish_events", {"run": run, "events": batch, "mode": mode}
                )
            except wire.InvalidRequest:
                logger.warning("publish_events refused locally: a batch is not allowed by the protocol")
                return False
            if response.error is not None:
                self._refused("publish_events", response)
                return False
            if response.ok["accepted"] != len(batch):
                logger.warning(
                    "the connector accepted %d of %d event(s)", response.ok["accepted"], len(batch)
                )
                return False
        return True

    async def drain(self, run: RunRef, timeout_s: Optional[float] = None) -> None:
        """Wait (at most ``timeout_s``, capped at 60 s) for the connector to
        deliver the run's queued lineage."""
        entry = self._known(run)
        if entry is None or entry.conn.closed:
            return
        seconds = _DEFAULT_DRAIN_S if timeout_s is None else max(0.0, float(timeout_s))
        timeout_ms = int(min(seconds, wire.MAX_DRAIN_MS / 1000) * 1000)
        try:
            await self._on_io(self._io_drain(run, timeout_ms))
        except _Unavailable:
            return

    async def _io_drain(self, run: str, timeout_ms: int) -> None:
        try:
            response, _o, _c = await self._call(
                "drain", {"run": run, "timeout_ms": timeout_ms}, timeout_ms / 1000 + 5.0
            )
        except wire.InvalidRequest:
            return
        if response.error is not None:
            self._refused("drain", response)

    # -- GovernanceBackend: ending runs -----------------------------------

    async def complete_session(self, run: RunRef) -> bool:
        """Close the run. ``False`` for an unknown or ended run (no request)
        or a refusal. The run (and its sub-agents) is ended here either way;
        its late lineage still goes out for a short window."""
        if self._live(run) is None:
            return False
        try:
            return await self._on_io(self._io_end("complete_session", {"run": run}, run, "run_completed"))
        except _Unavailable:
            self._end_run(run, "run_completed")
            return False

    async def terminate_session(self, run: RunRef, reason: str = "manual") -> bool:
        """End the run abnormally (the connector closes it and its sub-agents).
        ``reason`` is a short code (control characters removed, at most 256
        characters)."""
        if self._live(run) is None:
            return False
        params = {"run": run, "reason": _short_reason(reason)}
        try:
            return await self._on_io(self._io_end("terminate_session", params, run, "run_terminated"))
        except _Unavailable:
            self._end_run(run, "run_terminated")
            return False

    async def revoke_session(self, run: RunRef) -> bool:
        """Revoke the run (``session.revoke``). Not part of
        :class:`~watchlight_core.backend.GovernanceBackend`."""
        if self._live(run) is None:
            return False
        try:
            return await self._on_io(self._io_end("session.revoke", {"run": run}, run, "revoked"))
        except _Unavailable:
            self._end_run(run, "revoked")
            return False

    async def _io_end(self, method: str, params: Dict[str, Any], run: str, reason: str) -> bool:
        try:
            response, _o, _c = await self._call(method, params)
        except wire.InvalidRequest:
            response = wire.Response(id=None, error=wire.INVALID_ERROR)
        finally:
            self._end_run(run, reason)
        if response.error is not None:
            self._refused(method, response)
            return False
        return True

    def _release_dropped_run(self, run: RunRef) -> None:
        """A run handle was garbage-collected without closing its run: end
        it here and ask the connector to terminate it. Never raises."""
        try:
            entry = self._live(run)
            if entry is None:
                return
            self._end_run(run, "handle_dropped")
            loop = self._io.running()
            if loop is None or self._forked:
                return

            def _send() -> None:
                if not entry.conn.closed:
                    asyncio.ensure_future(
                        entry.conn.request(
                            "terminate_session", {"run": run, "reason": "handle_dropped"}, 5.0
                        )
                    ).add_done_callback(lambda t: t.cancelled() or t.exception())

            loop.call_soon_threadsafe(_send)
        except Exception:  # noqa: BLE001 - a finalizer never raises
            pass

    # -- GovernanceBackend: kill ------------------------------------------

    def subscribe_kill(self, run: RunRef, callback: KillCallback) -> Unsubscribe:
        """Call ``callback`` once when the run ends: a ``kill`` pushed by the
        connector, a refusal that says the run is gone, its own end, or the
        loss of the control connection. The callback runs on the event loop
        it was subscribed from (when there was one). An unknown or ended run
        fires it at once (fail closed)."""
        try:
            loop: Optional[asyncio.AbstractEventLoop] = asyncio.get_running_loop()
        except RuntimeError:
            loop = None
        sub = _Sub(callback=callback, loop=loop)
        with self._lock:
            entry = self._runs.get(run) if isinstance(run, str) else None
            live = (
                not self._forked
                and entry is not None
                and not entry.ended
                and not entry.conn.closed
            )
            if live:
                self._subs.setdefault(run, []).append(sub)
        if not live:
            if self._forked:
                reason = "forked"
            else:
                reason = "unknown_run" if entry is None else "run_ended"
            fire_kill_callback(callback, KillNotice(run=run, reason=reason, source="backend"))
            return lambda: None

        def _unsubscribe() -> None:
            with self._lock:
                subs = self._subs.get(run)
                if subs and sub in subs:
                    subs.remove(sub)
                    if not subs:
                        self._subs.pop(run, None)

        return _unsubscribe

    # -- egress -----------------------------------------------------------

    def egress_for(self, run: RunRef) -> Optional[SidecarEgress]:
        """The run's egress binding from the last :meth:`fetch_egress`, or
        ``None`` when none was fetched or the run has ended."""
        entry = self._live(run)
        return entry.egress if entry is not None else None

    async def fetch_egress(self, run: RunRef) -> SidecarEgress:
        """Ask the connector for the run's egress endpoint (``egress_for``).
        This rotates the run's marker and child key. Raises
        :class:`GovernanceUnavailable` on any failure, or when the endpoint
        is not an ``http://`` loopback listener (nothing is sent elsewhere)."""
        if self._live(run) is None:
            raise GovernanceUnavailable("egress: the run is unknown or has ended")
        try:
            result = await self._on_io(self._io_simple_ok("egress_for", {"run": run}, run))
        except _Unavailable:
            result = None
        if result is None:
            raise GovernanceUnavailable("egress: the connector gave no egress endpoint for the run")
        if not _loopback_http_url(result["proxy_url"], with_key=False) or not _loopback_http_url(
            result["child_proxy_url"], with_key=True
        ):
            logger.error("the connector's egress endpoint is not a loopback http listener; refusing it")
            raise GovernanceUnavailable("egress: the connector's egress endpoint is not local")
        binding = SidecarEgress(
            proxy_url=result["proxy_url"], marker_header=result["marker_header"], backend=self, run=run
        )
        with self._lock:
            entry = self._runs.get(run)
            if entry is None or entry.ended:
                raise GovernanceUnavailable("egress: the run ended")
            entry.marker = result["marker"]
            entry.child_proxy_url = result["child_proxy_url"]
            entry.egress = binding
        return binding

    async def refresh_marker(self, run: RunRef) -> bool:
        """Rotate the run's marker (``session.refresh_marker``). ``False`` on
        any failure."""
        if self._live(run) is None:
            return False
        try:
            result = await self._on_io(self._io_simple_ok("session.refresh_marker", {"run": run}, run))
        except _Unavailable:
            return False
        if result is None:
            return False
        with self._lock:
            entry = self._runs.get(run)
            if entry is None or entry.ended:
                return False
            entry.marker = result["marker"]
        return True

    async def report_connection(self, run: RunRef, src_port: int) -> bool:
        """Tell the connector that the egress connection from ``src_port``
        belongs to ``run`` (the attribution fallback). ``False`` on any
        failure."""
        if self._live(run) is None:
            return False
        try:
            result = await self._on_io(
                self._io_simple_ok("report_connection", {"run": run, "src_port": src_port}, run)
            )
        except _Unavailable:
            return False
        return result is not None

    def _report_connection_blocking(self, run: RunRef, src_port: int, timeout_s: float) -> bool:
        """:meth:`report_connection` for synchronous callers on any thread
        but the I/O thread: it blocks until the connector answered, so the
        report is recorded before the caller's connection is opened.
        ``False`` on any failure. Never raises."""
        try:
            if self._io.in_loop_thread() or self._live(run) is None:
                return False
            if not isinstance(src_port, int) or not 0 < src_port < 65536:
                return False
            fut = asyncio.run_coroutine_threadsafe(
                self._io_simple_ok("report_connection", {"run": run, "src_port": src_port}, run),
                self._io.loop(),
            )
            try:
                result = fut.result(timeout=max(0.05, float(timeout_s)))
            except Exception:  # noqa: BLE001 - timeout, lost connection: no report
                fut.cancel()
                return False
            return result is not None
        except Exception:  # noqa: BLE001 - a report never raises into the caller
            return False

    async def _io_simple_ok(self, method: str, params: Dict[str, Any], run: Optional[str]) -> Optional[Dict[str, Any]]:
        try:
            response, _o, _c = await self._call(method, params)
        except wire.InvalidRequest:
            logger.warning("%s refused locally: a parameter is not allowed by the protocol", method)
            return None
        if response.error is not None:
            self._refused(method, response, run)
            return None
        return response.ok

    def _egress_secret(self, run: RunRef, what: str) -> str:
        entry = self._live(run)
        if entry is None or entry.egress is None:
            raise GovernanceUnavailable("egress: the run has ended or is unknown")
        value = entry.marker if what == "marker" else entry.child_proxy_url
        if not value:
            raise GovernanceUnavailable("egress: the run has no egress endpoint")
        return value

    # -- health and lifecycle ---------------------------------------------

    async def health_check(self) -> bool:
        """``True`` only when the connector answers ``ok``."""
        try:
            result = await self._on_io(self._io_simple_ok("health", {}, None))
        except _Unavailable:
            return False
        return result is not None and result.get("status") == "ok"

    async def close(self) -> None:
        """Close the control connection (every run on it ends), stop the I/O
        thread and, for a connector this backend launched, stop it and wipe
        its secret. A later call reconnects, except to a launched connector."""
        loop = self._io.running()
        if loop is not None and not self._forked:
            try:
                await self._on_io(self._io_close())
            except Exception:  # noqa: BLE001 - closing anyway
                pass
            self._stopped_loops.add(loop)
            await asyncio.get_running_loop().run_in_executor(None, self._io.stop)
        # The next call starts a new I/O loop: nothing bound to the old one
        # may be reused.
        self._conn = None
        self._connect_lock = None
        with self._lock:
            live = [r for r, e in self._runs.items() if not e.ended]
        for run in live:
            self._end_run(run, "backend_closed")
        proc = self._endpoint.proc
        if proc is not None and proc.poll() is None:
            proc.terminate()
            try:
                await asyncio.get_running_loop().run_in_executor(None, proc.wait, 5)
            except Exception:  # noqa: BLE001
                proc.kill()
        self._endpoint.wipe()

    async def _io_close(self) -> None:
        conn = self._conn
        if conn is not None:
            await conn.close()


# ---------------------------------------------------------------------------
# Backend selection
# ---------------------------------------------------------------------------


def connector_configured(env: Optional[Mapping[str, str]] = None) -> bool:
    """Does this deployment's configuration put a plugin on the connector?

    Only ``WATCHLIGHT_BACKEND=sidecar`` or the connector's own socket or
    address says so. Unlike :func:`select_backend`, the other
    :data:`ENTERPRISE_ENV_VARS` don't: an install with ``WATCHLIGHT_APDP_URL``
    or ``WATCHLIGHT_PROXY_URL`` and no connector stays on the relay. A run
    can't reach this: it reads the deployment's environment only.

    ``WATCHLIGHT_BACKEND=in_process`` with a connector variable, or any
    other value, raises :class:`GovernanceUnavailable`.
    """
    env = os.environ if env is None else env
    choice = (env.get(ENV_BACKEND) or "").strip().lower()
    if choice not in ("", "sidecar", "in_process"):
        raise GovernanceUnavailable(
            f"{ENV_BACKEND} must be 'sidecar' or 'in_process'; refusing to guess"
        )
    named = [n for n in (ENV_SIDECAR_SOCKET, ENV_SIDECAR_ADDR) if env.get(n)]
    if choice == "in_process" and named:
        raise GovernanceUnavailable(
            f"{ENV_BACKEND}=in_process conflicts with {', '.join(named)}; "
            "refusing to guess"
        )
    return choice == "sidecar" or bool(named)


def select_backend(
    governance: Optional[Any] = None,
    *,
    env: Optional[Mapping[str, str]] = None,
    in_process: Optional[Callable[[], Any]] = None,
) -> Any:
    """Pick a plugin's governance backend.

    1. An explicit ``governance`` backend wins.
    2. Otherwise, if ``WATCHLIGHT_BACKEND=sidecar`` or any variable in
       :data:`ENTERPRISE_ENV_VARS` is set (an endpoint, a plugin or run
       credential, a TLS setting, the connector's socket or address), the
       connector is required: the
       result is a :class:`SidecarBackend` built from the environment, and a
       misconfiguration raises :class:`GovernanceUnavailable`. An
       unreachable connector refuses the run when it starts.
    3. Otherwise the Developer Edition in-process backend (``in_process()``,
       by default :class:`~watchlight_core.InProcessClient`).

    ``WATCHLIGHT_BACKEND`` takes ``sidecar`` or ``in_process``; any other
    value, or ``in_process`` together with an Enterprise variable, raises
    :class:`GovernanceUnavailable` (it never falls back quietly).
    """
    if governance is not None:
        return governance
    env = os.environ if env is None else env
    choice = (env.get(ENV_BACKEND) or "").strip().lower()
    enterprise = [name for name in ENTERPRISE_ENV_VARS if env.get(name)]
    if choice not in ("", "sidecar", "in_process"):
        raise GovernanceUnavailable(
            f"{ENV_BACKEND} must be 'sidecar' or 'in_process'; refusing to guess"
        )
    if choice == "in_process" and enterprise:
        raise GovernanceUnavailable(
            f"{ENV_BACKEND}=in_process conflicts with {', '.join(enterprise)}; "
            "refusing to run without the Watchlight connector"
        )
    if choice == "sidecar" or enterprise:
        return SidecarBackend.from_env(env)
    if in_process is None:
        from .in_process_client import InProcessClient

        return InProcessClient()
    return in_process()
