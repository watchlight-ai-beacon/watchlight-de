"""Launcher for the common ``wl-sidecar`` governance sidecar.

This replaces the per-language in-process CONNECT sidecar
(``connect_proxy.py``): instead of running an asyncio proxy inside the
customer's Python process, we spawn the shared, hardened Rust
``wl-sidecar`` binary as a subprocess and route the customer's outbound
traffic through it via the standard ``HTTP(S)_PROXY`` env vars.

**Why a subprocess of a Rust binary:** the credential + TLS path is
written ONCE, memory-safe, and the session token lives ONLY in the
sidecar process — it is handed over on the child's **stdin** and never
touches argv (``ps``-readable) or env (child-inherited), nor the
customer's Python heap.

Customer touches ZERO code — the plugin's ``start_run`` calls
:func:`install_sidecar`; from then on every HTTP library that honours
``HTTP(S)_PROXY`` routes through wl-proxy with the session credential
attached.
"""

from __future__ import annotations

import atexit
import os
import shutil
import subprocess
import threading
from typing import Dict, List, Optional

from .connect_proxy import (
    OWNED_BY_ANOTHER_RUN,
    _resolve_bypass_hosts as _resolve_bypass_hosts,  # noqa: F401 — shared rule
    apply_sidecar_proxy_env,
    owner_holds,
    restore_proxy_env,
    snapshot_proxy_env,
    validate_proxy_channel,
)
from .backend import EgressBinding
from .errors import GovernanceUnavailable, SidecarRunActive
from .log import get_logger

logger = get_logger("watchlight_core.sidecar")

#: Env var pointing at the ``wl-sidecar`` binary. When unset the binary
#: is looked up on ``PATH``.
ENV_SIDECAR_BINARY = "WL_SIDECAR_BINARY"
#: Env var naming wl-proxy's governance gateway listener (https://wl-proxy:8443)
#: for plain-HTTP lanes; ``WATCHLIGHT_PROXY_URL`` stays the CONNECT listener.
ENV_GATEWAY_URL = "WATCHLIGHT_GATEWAY_URL"
_DEFAULT_BINARY_NAME = "wl-sidecar"
#: How often the owner watcher checks that the owning run is still live.
_OWNER_POLL_SECONDS = 1.0

# The internal-host bypass list and its wildcard rule are shared with the
# in-process CONNECT proxy (``connect_proxy._resolve_bypass_hosts``).


class _SidecarProcess:
    __slots__ = (
        "proc",
        "bound",
        "prev_https",
        "prev_http",
        "prev_no_proxy_upper",
        "prev_no_proxy_lower",
        "prev_env",
        "owner",
        "watch_stop",
    )

    def __init__(
        self,
        proc: "subprocess.Popen",
        bound: str,
        prev_https: Optional[str],
        prev_http: Optional[str],
        prev_no_proxy_upper: Optional[str],
        prev_no_proxy_lower: Optional[str],
        prev_env: Optional[Dict[str, Optional[str]]] = None,
        owner: Optional[EgressBinding] = None,
    ):
        self.owner = owner
        self.watch_stop = threading.Event()
        self.proc = proc
        self.bound = bound
        self.prev_https = prev_https
        self.prev_http = prev_http
        self.prev_no_proxy_upper = prev_no_proxy_upper
        self.prev_no_proxy_lower = prev_no_proxy_lower
        self.prev_env = prev_env if prev_env is not None else {
            "HTTPS_PROXY": prev_https,
            "HTTP_PROXY": prev_http,
            "NO_PROXY": prev_no_proxy_upper,
            "no_proxy": prev_no_proxy_lower,
        }


_state: Optional[_SidecarProcess] = None
_lock = threading.Lock()


def _watch_owner(st: _SidecarProcess) -> None:
    """Stop ``st``'s sidecar once its owning run has ended (or its binding
    cannot be read). ``HTTP(S)_PROXY`` stays on the stopped sidecar's port,
    so later traffic fails to connect: it never goes direct and never
    carries the ended run's token. Only :func:`uninstall_sidecar` restores
    the env; the next run's install replaces the stopped sidecar."""
    assert st.owner is not None
    while not st.watch_stop.wait(_OWNER_POLL_SECONDS):
        try:
            live = st.owner.run_live()
        except Exception:  # noqa: BLE001 — unreadable owner: stop
            live = False
        if live:
            continue
        with _lock:
            if _state is st and not st.watch_stop.is_set():
                _stop_process(st)
                logger.info("wl-sidecar stopped: the run that owned it has ended")
        return


def _locate_binary(binary_path: Optional[str]) -> str:
    candidate = binary_path or os.environ.get(ENV_SIDECAR_BINARY)
    if candidate:
        if not os.path.isfile(candidate):
            raise FileNotFoundError(f"wl-sidecar binary not found at {candidate!r}")
        return candidate
    found = shutil.which(_DEFAULT_BINARY_NAME)
    if not found:
        raise FileNotFoundError(
            "wl-sidecar binary not found — set WL_SIDECAR_BINARY or put "
            "'wl-sidecar' on PATH"
        )
    return found


def build_sidecar_argv(
    binary: str,
    wl_proxy_url: str,
    *,
    governed_proxy_hosts: Optional[List[str]] = None,
    ca_cert: Optional[str] = None,
    client_cert: Optional[str] = None,
    client_key: Optional[str] = None,
    listen: str = "127.0.0.1:0",
    gateway_url: Optional[str] = None,
) -> List[str]:
    """Build the sidecar's NON-secret argv. The token is NEVER here — it
    goes on stdin (see :func:`install_sidecar`). Pure + unit-testable."""
    argv = [binary, "--wl-proxy-url", wl_proxy_url, "--listen", listen]
    # Governance gateway for plain-HTTP lanes (absolute-URI requests such
    # as ``POST http://proxy-mcp-web:8080/mcp``). ``wl_proxy_url`` is the
    # CONNECT tunnel listener, which accepts ONLY CONNECT now that it
    # terminates TLS natively; without a gateway every http:// MCP / LLM
    # lane is refused with "not a CONNECT request". Env fallback keeps
    # every framework plugin zero-touch: set ``WATCHLIGHT_GATEWAY_URL``.
    gateway = gateway_url if gateway_url is not None else os.environ.get(ENV_GATEWAY_URL)
    if gateway:
        argv += ["--gateway-url", gateway]
    if ca_cert:
        argv += ["--ca-cert", ca_cert]
    if client_cert:
        argv += ["--client-cert", client_cert]
    if client_key:
        argv += ["--client-key", client_key]
    if governed_proxy_hosts:
        argv += ["--governed-hosts", ",".join(governed_proxy_hosts)]
    return argv


def _read_port_line(stdout, timeout: float) -> Optional[str]:
    """Read the sidecar's announced ``host:port`` line from stdout with a
    timeout (a broken binary must not hang the customer's process)."""
    holder: dict = {}

    def _reader() -> None:
        try:
            holder["line"] = stdout.readline()
        except Exception:  # noqa: BLE001
            holder["line"] = ""

    t = threading.Thread(target=_reader, daemon=True)
    t.start()
    t.join(timeout)
    line = holder.get("line")
    if not line:
        return None
    return line.strip()


def _spawn_sidecar_process(
    argv: List[str], proxy_token: str, startup_timeout: float
) -> "tuple[subprocess.Popen, str]":
    """Start ``wl-sidecar``, hand it the token on stdin, and wait for its
    announced listen address. Raises (with the child killed) on failure."""
    proc = subprocess.Popen(  # noqa: S603 — argv is ours, no shell
        argv,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=None,  # inherit — structured JSON logs to our stderr
        text=True,
        bufsize=1,
    )

    # Hand off the SECRET on stdin. Keep stdin OPEN (do not close) so a
    # future lineage control-channel can stream updates to the sidecar.
    try:
        assert proc.stdin is not None
        proc.stdin.write(proxy_token + "\n")
        proc.stdin.flush()
    except Exception as exc:  # noqa: BLE001
        proc.kill()
        raise RuntimeError(
            f"failed to hand the session token to wl-sidecar: {type(exc).__name__}"
        ) from exc

    bound = _read_port_line(proc.stdout, startup_timeout) if proc.stdout else None
    if not bound:
        proc.kill()
        raise RuntimeError(
            "wl-sidecar did not announce its listen port within "
            f"{startup_timeout}s — check the binary + wl-proxy URL"
        )
    return proc, bound


def install_sidecar(
    wl_proxy_url: str,
    proxy_token: Optional[str],
    *,
    governed_proxy_hosts: Optional[List[str]] = None,
    ca_cert: Optional[str] = None,
    client_cert: Optional[str] = None,
    client_key: Optional[str] = None,
    binary_path: Optional[str] = None,
    startup_timeout: float = 5.0,
    gateway_url: Optional[str] = None,
    egress: Optional[EgressBinding] = None,
) -> None:
    """Spawn ``wl-sidecar`` and set ``HTTP(S)_PROXY`` so the customer's
    HTTP libraries auto-route through wl-proxy with the session token.

    The SECRET (``proxy_token``) is written to the child's stdin ONLY —
    never argv/env. NEVER logs the token.

    Fail closed: a missing ``proxy_token``, a missing binary or a failed
    bring-up raises :class:`GovernanceUnavailable`. The new sidecar is
    brought up BEFORE the previous one is stopped, so a failed re-install
    leaves the earlier sidecar (and its env) in place. ``http://`` to a
    non-loopback wl-proxy is refused (:class:`InsecureChannelError`)
    unless ``WATCHLIGHT_PROXY_ALLOW_PLAINTEXT=true``.

    **One run per process.** ``egress`` is the binding of the run the
    token belongs to, and that run owns the sidecar until it ends. While
    the owner is live, installing for any other run raises
    :class:`SidecarRunActive` before a process is started or the env is
    changed, so the running run's traffic never leaves on another run's
    token. A sidecar installed without ``egress`` is held until
    :func:`uninstall_sidecar`. Once the owner has ended, the next run's
    sidecar replaces it. Once the owner has ended, a watcher stops its
    sidecar within about a second and leaves ``HTTP(S)_PROXY`` on the
    stopped port: later traffic fails to connect, never goes direct and
    never carries the ended run's token.
    """
    global _state
    if not isinstance(proxy_token, str) or not proxy_token:
        raise GovernanceUnavailable(
            "A wl-proxy URL is configured but no proxy token was issued for "
            "this run; refusing to run with ungoverned egress."
        )
    validate_proxy_channel(wl_proxy_url)
    bypass_hosts = _resolve_bypass_hosts()

    with _lock:
        held = _state
        if held is not None and (egress is None or held.owner is not egress) and owner_holds(held.owner):
            raise SidecarRunActive(OWNED_BY_ANOTHER_RUN)
        try:
            binary = _locate_binary(binary_path)
            argv = build_sidecar_argv(
                binary,
                wl_proxy_url,
                governed_proxy_hosts=governed_proxy_hosts,
                ca_cert=ca_cert,
                gateway_url=gateway_url,
                client_cert=client_cert,
                client_key=client_key,
            )
            proc, bound = _spawn_sidecar_process(argv, proxy_token, startup_timeout)
        except Exception as exc:  # noqa: BLE001 — surfaced as fail-closed
            raise GovernanceUnavailable(
                f"wl-sidecar could not start ({exc}); refusing to run with "
                "ungoverned egress."
            ) from exc

        old = _state
        if old is not None:
            # Keep the customer's ORIGINAL env for the eventual uninstall.
            prev_https, prev_http = old.prev_https, old.prev_http
            prev_no_upper, prev_no_lower = old.prev_no_proxy_upper, old.prev_no_proxy_lower
            prev_env = old.prev_env
        else:
            prev_env = snapshot_proxy_env()
            prev_https = prev_env["HTTPS_PROXY"]
            prev_http = prev_env["HTTP_PROXY"]
            prev_no_upper = prev_env["NO_PROXY"]
            prev_no_lower = prev_env["no_proxy"]

        # Both spellings of the proxy vars point at the sidecar (a
        # pre-existing lower-case corporate proxy would otherwise win),
        # ALL_PROXY is cleared, NO_PROXY carries the merged bypass list.
        apply_sidecar_proxy_env(f"http://{bound}", prev_env, bypass_hosts)

        _state = _SidecarProcess(
            proc, bound, prev_https, prev_http, prev_no_upper, prev_no_lower, prev_env,
            owner=egress,
        )
        # The new sidecar is live; only now stop the old process.
        if old is not None:
            _stop_process(old)
        if egress is not None:
            threading.Thread(
                target=_watch_owner, args=(_state,), name="wl-sidecar-owner", daemon=True
            ).start()
        atexit.register(_atexit_cleanup)
        logger.info("wl-sidecar started on %s -> %s", bound, wl_proxy_url)


def is_sidecar_installed() -> bool:
    return _state is not None


def uninstall_sidecar() -> None:
    """Stop the sidecar subprocess + restore the customer's env. Safe to
    call when nothing is installed."""
    with _lock:
        _uninstall_locked()


def _stop_process(st: _SidecarProcess) -> None:
    """Stop one sidecar subprocess (no env changes)."""
    st.watch_stop.set()
    try:
        if st.proc.stdin:
            st.proc.stdin.close()
    except Exception:  # noqa: BLE001
        pass
    try:
        st.proc.terminate()
        try:
            st.proc.wait(timeout=2.0)
        except subprocess.TimeoutExpired:
            st.proc.kill()
    except Exception:  # noqa: BLE001
        pass


def _uninstall_locked() -> None:
    global _state
    if _state is None:
        return
    st = _state
    _state = None
    _stop_process(st)

    restore_proxy_env(st.prev_env)


def _atexit_cleanup() -> None:
    try:
        uninstall_sidecar()
    except Exception:  # noqa: BLE001 — atexit must never raise
        pass
