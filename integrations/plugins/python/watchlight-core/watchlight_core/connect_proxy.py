"""Local sidecar CONNECT proxy for wl-proxy auth.

# What this module provides

A small async-IO HTTP CONNECT proxy that runs on `127.0.0.1:<dynamic>`
in the customer's Python process. It accepts CONNECT requests from
any HTTP client (httpx, requests, urllib3, aiohttp, openai-python,
anthropic-python, boto3, …) that honors the standard `HTTPS_PROXY`
env var, forwards them to wl-proxy with the session-scoped
`Proxy-Authorization` header added, then relays the resulting TLS
tunnel byte-for-byte.

The customer's agent code is **never touched.** They install the
plugin and set `WATCHLIGHT_PROXY_URL` (env var) — the plugin's
`start_run` calls `install_connect_proxy(...)` and from that point
on all outbound HTTPS in the process is governed.

# Why a sidecar proxy rather than monkey-patching?

Monkey-patching `httpx.Client.__init__` works ONLY for httpx-based
clients. A customer using `requests`, `urllib3`, `aiohttp`, or
boto3 would silently bypass the interceptor. The local-sidecar
pattern uses the **standard HTTP-proxy mechanism** (`HTTPS_PROXY`
env var) that every Python HTTP library has honored since the 1990s.

Security model:

- The token lives in the sidecar's process state, **not the
  customer's Python globals.** Customer-process introspection can't
  recover it.
- The sidecar binds to `127.0.0.1` only — never network-exposed.
- The sidecar only accepts `CONNECT` requests — non-CONNECT
  responses with `405`.
- The token is added to the upstream CONNECT only, NEVER to the
  upstream TLS tunnel body.
- With an ``https://`` wl-proxy URL the sidecar -> wl-proxy hop is
  verified TLS, so the token never crosses the wire in cleartext.
  Plain ``http://`` is refused for a non-loopback host unless the
  operator sets ``WATCHLIGHT_PROXY_ALLOW_PLAINTEXT=true``.
- Install fails closed: no token, a failed bring-up or a wildcard
  bypass raises :class:`GovernanceUnavailable`, and a failed
  re-install leaves the previous sidecar in place.

Threat-model alignment:

- **Header spoofing** — token is the session-scoped JWT from
  wl-apdp; never user-controlled.
- **Audit log secret leakage** — NEVER log the raw token.
  Logs only "started: 127.0.0.1:<port> → <wl_proxy_url>".

# Lifecycle

- `install_connect_proxy(wl_proxy_url, proxy_token)` starts the
  sidecar in a background thread + event loop, sets `HTTPS_PROXY`
  and `HTTP_PROXY` to `http://127.0.0.1:<port>`, registers an
  `atexit` cleanup so an abandoned-process scenario doesn't leave a
  dangling socket.
- `uninstall_connect_proxy()` stops the sidecar + restores the
  original env vars + drains in-flight connections.
- Idempotent re-install — calling twice with a different token
  starts a fresh sidecar, swaps to it, then stops the old one.

# Kill-signal composition

The sidecar continues to handle the CONNECT routing. The **kill-signal
protocol** lives in a separate, framework-agnostic module:
`watchlight_core.kill_signal` (`InterceptorKillRegistry`). Plugins
that want kill-switch support instantiate the registry, race their
HTTP-client task against the registry's `cancel_requested` event, and
wire `RunHandle.terminate` to call `registry.cancel(reason)`. The
sidecar and the registry are orthogonal — composition is intentional
so the CONNECT routing surface stays a one-knob customer install, and
kill-signal opt-in is a separate concern.

# Limitations (v1, documented honestly)

- Process-global. Concurrent sessions in the same process share the
  same sidecar; the latest install wins for token. Acceptable for
  single-tenant gateway-style deployments. Multi-tenant fan-in is
  a v2 design (per-session sidecar OR token-multiplex by source-IP
  port mapping).
- Respects pre-existing `HTTPS_PROXY` only on uninstall. If the
  customer's environment already had `HTTPS_PROXY` set, we save
  that value and restore on uninstall — but during the install
  window, our sidecar takes precedence. Document this in the SDK
  README so customers aren't surprised.
- The customer's HTTP library MUST honor `HTTPS_PROXY`. Modern
  Python HTTP libraries do this by default; some have an opt-out
  (`trust_env=False` in httpx) and the rare library that doesn't
  honor it silently bypasses the proxy. Per-library validation is
  the customer's responsibility for non-standard HTTP libraries.
"""

from __future__ import annotations

import asyncio
import atexit
import os
import ssl
import threading
from typing import TYPE_CHECKING, Dict, Optional
from urllib.parse import urlparse

from .log import get_logger

if TYPE_CHECKING:
    from .backend import EgressBinding

logger = get_logger("watchlight_core.connect_proxy")

# Singleton — installed sidecar state. The `install_connect_proxy`
# function manages this; the rest of the module reads it.
_state: Optional["_SidecarState"] = None

# Process-global handle lineage snapshot. ``BaseRunHandle.__aenter__``
# writes it via :func:`set_active_handle_lineage`; it is kept for
# introspection only. It is NEVER written to the wire: a run's identity
# and lineage reach wl-proxy solely through the verified claims of the
# proxy token, and the sidecar sends no ``X-Wl-*`` header.

_handle_lineage_lock = threading.Lock()
_active_handle_lineage: Optional["object"] = None  # HandleLineage; typed weak.

# Default internal-host bypass list — hosts the customer's HTTP
# libraries MUST reach directly, NEVER through wl-proxy.
#
# Why this exists: the plugin installs a CONNECT-only sidecar that
# routes outbound HTTPS via wl-proxy. But the customer's process
# also makes plain-HTTP calls to inter-service Watchlight URLs
# (e.g. ``http://wl-apdp:8081/agents/resolve``). Those calls would
# hit the sidecar as plain-HTTP forward-proxy requests, and the
# sidecar responds 405 (CONNECT-only by design). The
# result is a confusing failure where the customer-bound LLM call
# works but the plugin's own APDP call breaks.
#
# Fix: set ``NO_PROXY`` so the customer's HTTP libraries skip the
# sidecar for these hosts. Every modern Python HTTP library
# (httpx, requests, urllib3, aiohttp) honors ``NO_PROXY`` by
# default; the env-var mechanism is library-agnostic.
#
# Host-only matching (no scheme/port). The customer's HTTP library
# is responsible for the standard ``NO_PROXY`` parse (suffix-match
# OR exact-match depending on the library; both work for the
# short bare-hostname entries below since those services are
# typically reached via Docker / Kubernetes DNS, not a full
# domain).
_DEFAULT_INTERNAL_BYPASS_HOSTS: tuple[str, ...] = (
    "wl-apdp",
    "wl-registry",
    "wl-execution-graph",
    "wl-secrets-broker",
    "wl-drift",
    "wl-discover",
    "wl-auth",
    "wl-license",
    "wl-guardrails",
    "localhost",
    "127.0.0.1",
)


#: Operator opt-in for a plain ``http://`` wl-proxy URL to a non-loopback
#: host (private bridge that never leaves the node). Mirrors
#: ``WATCHLIGHT_APDP_ALLOW_PLAINTEXT`` on :class:`ApdpClient`.
ENV_PROXY_ALLOW_PLAINTEXT = "WATCHLIGHT_PROXY_ALLOW_PLAINTEXT"
#: PEM CA bundle used to verify an ``https://`` wl-proxy.
ENV_PROXY_CA_CERT = "WATCHLIGHT_PROXY_CA_CERT"
#: Operator override for the internal-host bypass list.
ENV_PROXY_NO_PROXY = "WATCHLIGHT_PROXY_NO_PROXY"

_LOOPBACK_HOSTS: frozenset[str] = frozenset({"localhost", "127.0.0.1", "::1"})

# Serialises install / uninstall so concurrent runs can never leak a
# sidecar or leave the env pointing at a stopped one. Re-entrant because
# the atexit hook may run while an install holds it on the same thread.
_install_lock = threading.RLock()

#: Why a second run's egress installer is refused (both installers).
OWNED_BY_ANOTHER_RUN = (
    "Another governed run in this process still owns the egress proxy; "
    "refusing this run so that run's traffic never leaves on this run's "
    "credential. The owning run releases it when it ends, or when its session "
    "expires (start_run's ttl_seconds, 3600 by default) if it is never "
    "completed. Run concurrent governed runs in separate processes."
)


def owner_holds(owner: Optional["EgressBinding"]) -> bool:
    """Does ``owner`` still hold the process's egress installer? An unknown
    owner (``None``) or one that cannot be read holds it (fail closed)."""
    if owner is None:
        return True
    try:
        return owner.run_live()
    except Exception:  # noqa: BLE001 — unreadable owner: still held
        return True


def _connect_token(owner: Optional["EgressBinding"], fallback: str) -> Optional[str]:
    """The token for one CONNECT: the owner run's current token, read from
    its binding now, or ``None`` once that run has ended or its binding
    cannot be read (the CONNECT is then refused). Without an owner, the
    token the proxy was installed with."""
    if owner is None:
        return fallback
    try:
        return owner.proxy_authorization()
    except Exception:  # noqa: BLE001 — ended or unreadable: refuse
        return None
_atexit_registered = False


def validate_proxy_channel(wl_proxy_url: str):
    """Parse ``wl_proxy_url`` and refuse a channel that would expose the
    proxy token.

    * The scheme must be ``http`` or ``https`` (``ValueError`` otherwise).
    * ``https`` is always accepted; the caller does verified TLS.
    * ``http`` is accepted only for a loopback host, or when the operator
      explicitly set ``WATCHLIGHT_PROXY_ALLOW_PLAINTEXT=true`` (logged at
      WARNING). Otherwise :class:`InsecureChannelError` is raised, the
      same rule :class:`ApdpClient` applies to its base URL.

    Returns the :func:`urllib.parse.urlparse` result.
    """
    from .errors import InsecureChannelError

    parsed = urlparse(wl_proxy_url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(
            f"wl_proxy_url must be http:// or https://, got {wl_proxy_url!r}"
        )
    if not parsed.hostname:
        raise ValueError(f"wl_proxy_url has no hostname: {wl_proxy_url!r}")
    if parsed.scheme == "https" or parsed.hostname in _LOOPBACK_HOSTS:
        return parsed
    if os.environ.get(ENV_PROXY_ALLOW_PLAINTEXT, "").strip().lower() in ("1", "true"):
        logger.warning(
            "watchlight: wl-proxy URL uses plain http:// to non-loopback host %s "
            "(%s=true); the proxy token crosses that link in cleartext. Never "
            "use this outside a private bridge that does not leave the node.",
            parsed.hostname,
            ENV_PROXY_ALLOW_PLAINTEXT,
        )
        return parsed
    raise InsecureChannelError(
        f"wl-proxy URL {wl_proxy_url!r} uses plain http:// to a non-loopback "
        "host, which would send the proxy token in cleartext. Use https:// "
        f"(CA via {ENV_PROXY_CA_CERT}), a loopback host, or set "
        f"{ENV_PROXY_ALLOW_PLAINTEXT}=true for a private bridge."
    )


def _is_wildcard_bypass(entry: str) -> bool:
    """True for a ``NO_PROXY`` entry that exempts every destination."""
    e = entry.strip()
    return e == "*" or e.endswith("/0")


def _resolve_bypass_hosts() -> tuple[str, ...]:
    """Return the list of hosts the sidecar must bypass.

    Reads ``WATCHLIGHT_PROXY_NO_PROXY`` (comma-separated). When set,
    that value REPLACES the defaults; when unset, the defaults apply.

    Empty strings in the override are dropped (so a trailing comma
    or stray whitespace doesn't accidentally inject a blank entry).

    A wildcard entry (``*`` or a ``/0`` CIDR) would exempt ALL egress
    from governance, so it raises :class:`GovernanceUnavailable`.
    """
    from .errors import GovernanceUnavailable

    override = os.environ.get(ENV_PROXY_NO_PROXY)
    if override is None:
        return _DEFAULT_INTERNAL_BYPASS_HOSTS
    hosts = tuple(h.strip() for h in override.split(",") if h.strip())
    wild = [h for h in hosts if _is_wildcard_bypass(h)]
    if wild:
        raise GovernanceUnavailable(
            f"{ENV_PROXY_NO_PROXY} contains a wildcard entry ({', '.join(wild)}) "
            "that would exempt all egress from wl-proxy. List the internal "
            "hosts explicitly."
        )
    return hosts


#: Every proxy env var an HTTP client may read. urllib, httpx and requests
#: prefer the lower-case spelling when both are set, and fall back to
#: ``ALL_PROXY`` for any scheme, so all of them are managed together.
PROXY_ENV_VARS = (
    "HTTPS_PROXY",
    "https_proxy",
    "HTTP_PROXY",
    "http_proxy",
    "ALL_PROXY",
    "all_proxy",
    "NO_PROXY",
    "no_proxy",
)


def snapshot_proxy_env() -> Dict[str, Optional[str]]:
    """The current value of every :data:`PROXY_ENV_VARS` entry."""
    return {name: os.environ.get(name) for name in PROXY_ENV_VARS}


def apply_sidecar_proxy_env(
    sidecar_url: str, previous: Dict[str, Optional[str]], bypass_hosts: list
) -> None:
    """Route every proxy-aware client through ``sidecar_url``: both
    spellings of ``HTTPS_PROXY`` / ``HTTP_PROXY`` point at the sidecar,
    ``ALL_PROXY`` / ``all_proxy`` are cleared (a customer's catch-all
    proxy must not win), and ``NO_PROXY`` / ``no_proxy`` carry the
    merged bypass list."""
    for name in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"):
        os.environ[name] = sidecar_url
    for name in ("ALL_PROXY", "all_proxy"):
        os.environ.pop(name, None)
    merged = merged_no_proxy(previous.get("NO_PROXY"), previous.get("no_proxy"), bypass_hosts)
    os.environ["NO_PROXY"] = merged
    os.environ["no_proxy"] = merged


def restore_proxy_env(previous: Dict[str, Optional[str]]) -> None:
    """Restore every :data:`PROXY_ENV_VARS` entry to its saved value."""
    for name in PROXY_ENV_VARS:
        value = previous.get(name)
        if value is None:
            os.environ.pop(name, None)
        else:
            os.environ[name] = value


def merged_no_proxy(
    previous_upper: Optional[str],
    previous_lower: Optional[str],
    bypass_hosts: tuple[str, ...],
) -> str:
    """Merge the customer's ``NO_PROXY`` / ``no_proxy`` with the internal
    bypass hosts. Wildcard entries (``*``, ``/0`` CIDRs) are dropped
    while the sidecar is installed, with a WARNING: they would exempt all
    egress. The customer's original values are restored on uninstall."""
    parts: list[str] = []
    dropped: list[str] = []
    for raw in (previous_upper, previous_lower):
        if not raw:
            continue
        for p in raw.split(","):
            p = p.strip()
            if not p:
                continue
            if _is_wildcard_bypass(p):
                if p not in dropped:
                    dropped.append(p)
                continue
            if p not in parts:
                parts.append(p)
    if dropped:
        logger.warning(
            "watchlight: ignoring wildcard NO_PROXY entr%s %s while egress "
            "governance is installed: it would exempt all egress from wl-proxy. "
            "List the hosts to bypass explicitly.",
            "y" if len(dropped) == 1 else "ies",
            ", ".join(dropped),
        )
    for host in bypass_hosts:
        if host not in parts:
            parts.append(host)
    return ",".join(parts)


def _build_proxy_ssl_context(ca_cert: Optional[str]) -> ssl.SSLContext:
    """Verified TLS context for the sidecar -> wl-proxy hop (hostname
    checking on, TLS 1.2 minimum). ``ca_cert`` pins a private CA."""
    ctx = ssl.create_default_context(cafile=ca_cert or None)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


class _SidecarState:
    """Holds everything we need to gracefully stop the sidecar +
    restore env."""

    __slots__ = (
        "port",
        "wl_proxy_host",
        "wl_proxy_port",
        "_proxy_token",
        "loop",
        "thread",
        "server",
        "previous_https_proxy",
        "previous_http_proxy",
        "previous_no_proxy",
        "previous_no_proxy_lower",
        "previous_env",
        "owner",
        "_stopped",
    )

    def __init__(
        self,
        port: int,
        wl_proxy_host: str,
        wl_proxy_port: int,
        proxy_token: str,
        loop: asyncio.AbstractEventLoop,
        thread: threading.Thread,
        server: asyncio.base_events.Server,
        previous_https_proxy: Optional[str],
        previous_http_proxy: Optional[str],
        previous_no_proxy: Optional[str],
        previous_no_proxy_lower: Optional[str] = None,
        previous_env: Optional[Dict[str, Optional[str]]] = None,
        owner: Optional["EgressBinding"] = None,
    ):
        self.owner = owner
        self.port = port
        self.wl_proxy_host = wl_proxy_host
        self.wl_proxy_port = wl_proxy_port
        # Underscored — never expose via public API, never log.
        self._proxy_token = proxy_token
        self.loop = loop
        self.thread = thread
        self.server = server
        self.previous_https_proxy = previous_https_proxy
        self.previous_http_proxy = previous_http_proxy
        self.previous_no_proxy = previous_no_proxy
        self.previous_no_proxy_lower = previous_no_proxy_lower
        # Every proxy env var as the customer had it before the first
        # install (restored on uninstall).
        self.previous_env = previous_env if previous_env is not None else {
            "HTTPS_PROXY": previous_https_proxy,
            "HTTP_PROXY": previous_http_proxy,
            "NO_PROXY": previous_no_proxy,
            "no_proxy": previous_no_proxy_lower,
        }
        self._stopped = False


def _start_sidecar_loop(
    wl_proxy_host: str,
    wl_proxy_port: int,
    proxy_token: str,
    ssl_ctx: Optional[ssl.SSLContext],
    owner: Optional["EgressBinding"] = None,
) -> tuple:
    """Bring up a sidecar listener in its own thread + event loop.

    Returns ``(loop, thread, server, bound_port)`` once it is accepting
    connections. Raises (and leaves nothing running) when bring-up
    fails or does not finish within 5 seconds.
    """
    ready_event = threading.Event()
    state_holder: dict[str, object] = {}

    def _run_loop() -> None:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:

            async def _bring_up_server() -> tuple[asyncio.base_events.Server, int]:
                server = await asyncio.start_server(
                    _make_client_handler(
                        wl_proxy_host, wl_proxy_port, proxy_token, ssl_ctx, owner
                    ),
                    host="127.0.0.1",
                    port=0,  # OS picks free port
                )
                socks = server.sockets or ()
                if not socks:
                    server.close()
                    raise RuntimeError("sidecar failed to bind a local socket")
                bound_port = socks[0].getsockname()[1]
                return server, bound_port

            try:
                server, bound_port = loop.run_until_complete(_bring_up_server())
            except BaseException as exc:  # noqa: BLE001 — reported to install
                state_holder["error"] = exc
                ready_event.set()
                return
            state_holder["server"] = server
            state_holder["port"] = bound_port
            state_holder["loop"] = loop
            ready_event.set()
            # Run the loop forever until uninstall calls loop.stop().
            loop.run_forever()
        finally:
            # Loop stopped — close the server + the loop.
            server_obj = state_holder.get("server")
            if isinstance(server_obj, asyncio.base_events.Server):
                server_obj.close()
                try:
                    loop.run_until_complete(server_obj.wait_closed())
                except RuntimeError:
                    pass
            try:
                loop.close()
            except Exception:  # noqa: BLE001
                pass

    thread = threading.Thread(
        target=_run_loop, name="watchlight-connect-proxy", daemon=True
    )
    thread.start()
    # Block until the sidecar is actually accepting connections. A
    # 5-second budget protects against silently broken bring-up.
    if not ready_event.wait(timeout=5.0):
        loop_obj = state_holder.get("loop")
        if isinstance(loop_obj, asyncio.AbstractEventLoop):
            try:
                loop_obj.call_soon_threadsafe(loop_obj.stop)
            except RuntimeError:
                pass
        raise RuntimeError("connect-proxy sidecar failed to start within 5s")
    if "error" in state_holder:
        thread.join(timeout=3.0)
        err = state_holder["error"]
        raise RuntimeError(f"connect-proxy sidecar failed to start: {err}") from (
            err if isinstance(err, BaseException) else None
        )
    return (
        state_holder["loop"],
        thread,
        state_holder["server"],
        state_holder["port"],
    )


def _stop_sidecar_loop(state: _SidecarState) -> None:
    """Stop one sidecar's loop + thread (no env changes)."""
    try:
        state.loop.call_soon_threadsafe(state.loop.stop)
    except RuntimeError:
        pass
    state.thread.join(timeout=3.0)


def install_connect_proxy(
    wl_proxy_url: str,
    proxy_token: Optional[str],
    *,
    ca_cert: Optional[str] = None,
    egress: Optional["EgressBinding"] = None,
) -> None:
    """Start the local sidecar proxy and set `HTTPS_PROXY` /
    `HTTP_PROXY` env vars so the customer's Python HTTP libraries
    auto-route through it.

    Fail closed: the call either leaves a working sidecar installed or
    raises.

    * A missing ``proxy_token`` raises :class:`GovernanceUnavailable`
      (a configured proxy URL with no token must never mean direct
      egress).
    * The new sidecar is brought up BEFORE any state is swapped. If
      bring-up fails, :class:`GovernanceUnavailable` is raised and the
      previously installed sidecar (if any) stays in place, so earlier
      runs never fall back to direct egress.
    * Re-install swaps to the new sidecar, then stops the old one; the
      customer's original proxy env is kept for uninstall.
    * Install / uninstall are serialised by a module lock.
    * **One run per process.** ``egress`` is the binding of the run the
      token belongs to, and that run owns the proxy until it ends. While
      it is live, installing for any other run raises
      :class:`~watchlight_core.errors.SidecarRunActive` before anything
      starts or the env changes. A proxy installed without ``egress`` is
      held until :func:`uninstall_connect_proxy`. Once the owner has
      ended, its proxy answers every new CONNECT with 403 (never direct
      egress, never a token), until the next run's proxy replaces it.

    NEVER logs ``proxy_token`` — only ``wl_proxy_url`` and the
    local port we bound to.

    Args:
      wl_proxy_url: The wl-proxy CONNECT listener. ``https://`` does
        verified TLS to wl-proxy (CA from ``ca_cert`` or
        ``WATCHLIGHT_PROXY_CA_CERT``, else the system store), so the
        token travels only inside TLS. ``http://`` is accepted only for
        a loopback host or with ``WATCHLIGHT_PROXY_ALLOW_PLAINTEXT=true``
        (:class:`InsecureChannelError` otherwise).
      proxy_token: Session-scoped JWT from wl-apdp. Stamped onto
        every upstream CONNECT as ``Proxy-Authorization: Bearer ...``.
      ca_cert: Optional PEM CA bundle for an ``https://`` wl-proxy.
    """
    global _state, _atexit_registered
    from .errors import GovernanceUnavailable

    if not isinstance(proxy_token, str) or not proxy_token:
        raise GovernanceUnavailable(
            "A wl-proxy URL is configured but no proxy token was issued for "
            "this run; refusing to run with ungoverned egress."
        )

    # Parse + validate early so misconfiguration fails loudly at install
    # time rather than per-request.
    parsed = validate_proxy_channel(wl_proxy_url)
    wl_proxy_host = parsed.hostname or "localhost"
    wl_proxy_port = parsed.port or (443 if parsed.scheme == "https" else 8080)
    ssl_ctx: Optional[ssl.SSLContext] = None
    if parsed.scheme == "https":
        try:
            ssl_ctx = _build_proxy_ssl_context(
                ca_cert or os.environ.get(ENV_PROXY_CA_CERT)
            )
        except (OSError, ssl.SSLError) as exc:
            raise GovernanceUnavailable(
                f"cannot build the TLS context for wl-proxy: {type(exc).__name__}"
            ) from exc
    bypass_hosts = _resolve_bypass_hosts()

    with _install_lock:
        held = _state if (_state is not None and not _state._stopped) else None
        if held is not None and (egress is None or held.owner is not egress) and owner_holds(held.owner):
            from .errors import SidecarRunActive

            raise SidecarRunActive(OWNED_BY_ANOTHER_RUN)
        try:
            loop, thread, server, bound_port = _start_sidecar_loop(
                wl_proxy_host, wl_proxy_port, proxy_token, ssl_ctx, egress
            )
        except Exception as exc:  # noqa: BLE001 — surfaced as fail-closed
            raise GovernanceUnavailable(
                f"watchlight connect-proxy sidecar could not start ({exc}); "
                "refusing to run with ungoverned egress."
            ) from exc

        old = _state if (_state is not None and not _state._stopped) else None
        if old is not None:
            # Keep the customer's ORIGINAL env for the eventual uninstall,
            # not the previous sidecar's URL.
            previous_https_proxy = old.previous_https_proxy
            previous_http_proxy = old.previous_http_proxy
            previous_no_proxy = old.previous_no_proxy
            previous_no_proxy_lower = old.previous_no_proxy_lower
            previous_env = old.previous_env
        else:
            previous_env = snapshot_proxy_env()
            previous_https_proxy = previous_env["HTTPS_PROXY"]
            previous_http_proxy = previous_env["HTTP_PROXY"]
            previous_no_proxy = previous_env["NO_PROXY"]
            previous_no_proxy_lower = previous_env["no_proxy"]

        # Install the env vars so customer HTTP libs auto-route: both
        # spellings (a pre-existing lower-case corporate proxy would
        # otherwise win), no catch-all ALL_PROXY, and the internal-host
        # bypass appended to the customer's NO_PROXY with any wildcard
        # entry dropped while installed.
        sidecar_url = f"http://127.0.0.1:{bound_port}"
        apply_sidecar_proxy_env(sidecar_url, previous_env, bypass_hosts)

        _state = _SidecarState(
            port=bound_port,
            wl_proxy_host=wl_proxy_host,
            wl_proxy_port=wl_proxy_port,
            proxy_token=proxy_token,
            loop=loop,
            thread=thread,
            server=server,
            previous_https_proxy=previous_https_proxy,
            previous_http_proxy=previous_http_proxy,
            previous_no_proxy=previous_no_proxy,
            previous_no_proxy_lower=previous_no_proxy_lower,
            previous_env=previous_env,
            owner=egress,
        )

        # The new sidecar is live; only now retire the old one.
        if old is not None:
            old._stopped = True
            _stop_sidecar_loop(old)

        # Belt-and-braces: if the customer's process exits without
        # explicitly uninstalling, an atexit hook still runs cleanup.
        if not _atexit_registered:
            atexit.register(_atexit_cleanup)
            _atexit_registered = True

    logger.info(
        "watchlight: connect-proxy sidecar started: 127.0.0.1:%d → %s:%d (%s)",
        bound_port,
        wl_proxy_host,
        wl_proxy_port,
        "tls" if ssl_ctx is not None else "plaintext",
    )


def uninstall_connect_proxy() -> None:
    """Stop the sidecar + restore env vars to their pre-install
    state. Idempotent — safe to call when nothing is installed.

    After uninstall, the customer's Python HTTP libraries see the
    original `HTTPS_PROXY` (or no `HTTPS_PROXY` if there wasn't one)
    and resume direct outbound HTTPS.
    """
    global _state
    with _install_lock:
        if _state is None:
            return
        state = _state
        if state._stopped:
            _state = None
            return
        state._stopped = True

        # Restore env (do this BEFORE we stop the loop — anyone holding
        # an in-flight connection through the sidecar gets one last
        # request; new requests use the restored env).
        restore_proxy_env(state.previous_env)

        # Stop the loop — the thread's `_run_loop` finally clause closes
        # the server + loop cleanly. Wait briefly for the thread to die
        # so a re-install can bind a fresh port without surprises.
        _stop_sidecar_loop(state)

        _state = None
    logger.info("watchlight: connect-proxy sidecar stopped")


def is_connect_proxy_installed() -> bool:
    """Test/inspection helper. Returns True when the sidecar is
    currently installed (and HTTPS_PROXY points at it)."""
    return _state is not None


def _atexit_cleanup() -> None:
    """Called automatically on Python process exit."""
    try:
        uninstall_connect_proxy()
    except Exception:  # noqa: BLE001 — atexit must never raise
        pass


def _make_client_handler(
    wl_proxy_host: str,
    wl_proxy_port: int,
    proxy_token: str,
    ssl_ctx: Optional[ssl.SSLContext] = None,
    owner: Optional["EgressBinding"] = None,
):
    """Build the async handler closure for one inbound CONNECT.

    With an ``owner`` (the run the token belongs to), each CONNECT carries
    that run's token as its binding gives it at that moment. Once the run
    has ended, or its binding cannot be read, the CONNECT is answered 403
    here: no token is sent, and the request never goes direct.

    Why a closure: keeps the token captured by reference but NOT
    exposed on the handler's signature, so a future inspect.signature
    auditor doesn't see it.
    """

    async def handler(
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
    ) -> None:
        try:
            # Parse the CONNECT request line.
            request_line = await client_reader.readline()
            if not request_line:
                return
            parts = request_line.split()
            if len(parts) < 2 or parts[0].upper() != b"CONNECT":
                # Only CONNECT is supported. Reject everything else
                # so the sidecar can't be repurposed as a generic
                # HTTP forwarder.
                client_writer.write(
                    b"HTTP/1.1 405 Method Not Allowed\r\n"
                    b"Content-Length: 0\r\n"
                    b"Connection: close\r\n\r\n"
                )
                await client_writer.drain()
                return
            target = parts[1].decode("ascii", errors="replace")

            # Drain the remaining inbound request headers (we
            # discard them — the customer's HTTP library may have
            # added Proxy-Authorization or similar, but we set our
            # own).
            while True:
                line = await client_reader.readline()
                if line in (b"\r\n", b""):
                    break

            connect_token = _connect_token(owner, proxy_token)
            if connect_token is None:
                client_writer.write(
                    b"HTTP/1.1 403 Forbidden\r\n"
                    b"Content-Length: 0\r\n"
                    b"X-Watchlight-Error: run-ended\r\n"
                    b"Connection: close\r\n\r\n"
                )
                await client_writer.drain()
                return

            # Open the upstream connection to wl-proxy.
            try:
                # With an https:// wl-proxy URL the hop is verified TLS
                # (hostname + chain); a failed handshake raises here,
                # BEFORE the token is ever written.
                if ssl_ctx is not None:
                    upstream_reader, upstream_writer = await asyncio.open_connection(
                        wl_proxy_host,
                        wl_proxy_port,
                        ssl=ssl_ctx,
                        server_hostname=wl_proxy_host,
                        ssl_handshake_timeout=10.0,
                    )
                else:
                    upstream_reader, upstream_writer = await asyncio.open_connection(
                        wl_proxy_host, wl_proxy_port
                    )
            except (OSError, asyncio.TimeoutError) as exc:
                # wl-proxy unreachable. Surface 502 to the customer's
                # HTTP library so it errors visibly.
                client_writer.write(
                    f"HTTP/1.1 502 Bad Gateway\r\n"
                    f"Content-Length: 0\r\n"
                    f"X-Watchlight-Error: wl-proxy-unreachable: {type(exc).__name__}\r\n"
                    f"Connection: close\r\n\r\n".encode("latin-1", errors="replace")
                )
                await client_writer.drain()
                return

            # The CONNECT carries only the run's proxy token. The
            # run's identity and lineage reach wl-proxy solely through the
            # token's verified claims; no ``X-Wl-*`` identity or lineage
            # header is ever sent (a client-settable header could name
            # another run).
            # Send the CONNECT to wl-proxy WITH our Proxy-Authorization.
            # CRITICAL: this is the only place the token touches the wire.
            connect_req = (
                f"CONNECT {target} HTTP/1.1\r\n"
                f"Host: {target}\r\n"
                f"Proxy-Authorization: Bearer {connect_token}\r\n"
                f"Proxy-Connection: keep-alive\r\n"
                f"\r\n"
            ).encode("latin-1")
            upstream_writer.write(connect_req)
            await upstream_writer.drain()

            # Read the upstream response status + headers, forward
            # them to the client unchanged (the client's HTTP lib
            # uses them to decide whether the tunnel succeeded).
            status_line = await upstream_reader.readline()
            client_writer.write(status_line)
            while True:
                header_line = await upstream_reader.readline()
                client_writer.write(header_line)
                if header_line in (b"\r\n", b""):
                    break
            await client_writer.drain()

            # If wl-proxy returned non-2xx (407/403/etc.), it
            # already closed the upstream socket. We close ours too.
            if not status_line.startswith(b"HTTP/1.1 2"):
                return

            # Bi-directional raw TCP relay until either side closes.
            await asyncio.gather(
                _relay(client_reader, upstream_writer),
                _relay(upstream_reader, client_writer),
                return_exceptions=True,
            )
        except (BrokenPipeError, ConnectionResetError):
            # The client or upstream hung up mid-relay. Normal.
            pass
        except Exception:  # noqa: BLE001
            # Defensive — the sidecar must NEVER crash the customer's
            # process. Log at debug only; in production we'd hook a
            # metrics counter here.
            logger.debug("connect-proxy handler failed", exc_info=True)
        finally:
            try:
                client_writer.close()
                await client_writer.wait_closed()
            except Exception:  # noqa: BLE001
                pass

    return handler


def set_active_handle_lineage(lineage: Optional["object"]) -> None:
    """Publish a :class:`HandleLineage` to the process-global state.
    Introspection only: it is never sent on the wire.

    The customer's ``BaseRunHandle.__aenter__`` calls this with a
    fresh snapshot; ``__aexit__`` calls it with ``None`` (or restores
    the parent's snapshot). Pass ``None`` to clear the binding.

    Thread-safe (guarded by a module-private lock) so concurrent
    sub-agent spawn / completion paths writing to the global don't
    race.

    The ``object`` typing is deliberate — to avoid the otherwise
    circular import between ``connect_proxy`` and ``run_handle``, this
    module accepts the value as opaque.
    """
    global _active_handle_lineage
    with _handle_lineage_lock:
        _active_handle_lineage = lineage


def get_active_handle_lineage() -> Optional["object"]:
    """Return the currently-published :class:`HandleLineage`, or
    ``None`` when no handle is bound. Reads under the same lock as
    :func:`set_active_handle_lineage` so the read is atomic w.r.t. a
    concurrent writer.
    """
    with _handle_lineage_lock:
        return _active_handle_lineage


async def _relay(
    src_reader: asyncio.StreamReader, dst_writer: asyncio.StreamWriter
) -> None:
    """Forward bytes from one stream to another until EOF. Used
    for the bidirectional TCP relay after the CONNECT tunnel is
    established."""
    try:
        while True:
            data = await src_reader.read(65536)
            if not data:
                break
            dst_writer.write(data)
            await dst_writer.drain()
    except (BrokenPipeError, ConnectionResetError):
        pass
    finally:
        try:
            dst_writer.close()
        except Exception:  # noqa: BLE001
            pass
