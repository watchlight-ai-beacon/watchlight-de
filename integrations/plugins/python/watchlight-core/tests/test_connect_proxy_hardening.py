"""Fail-closed install of the egress sidecars (in-process CONNECT proxy
and the wl-sidecar launcher).

* the new sidecar is brought up before any state is swapped; a
  failed bring-up raises :class:`GovernanceUnavailable` and leaves the
  earlier sidecar (and its env) in place; a missing proxy token raises.
* an ``https://`` proxy URL does verified TLS, so the proxy token
  is never written in cleartext; plain ``http://`` is refused for a
  non-loopback host.
* concurrent installs never leak a sidecar.
* a wildcard bypass (``*``) never exempts all egress.
"""

from __future__ import annotations

import asyncio
import datetime
import os
import socket
import ssl
import threading
import time

import httpx
import pytest

from watchlight_core import (
    GovernanceUnavailable,
    InsecureChannelError,
    install_connect_proxy,
    is_connect_proxy_installed,
    uninstall_connect_proxy,
)
from watchlight_core import connect_proxy as cp
from watchlight_core.backend import EgressBinding
from watchlight_core.errors import SidecarRunActive
from watchlight_core.sidecar import (
    install_sidecar,
    is_sidecar_installed,
    uninstall_sidecar,
)

_ENV_KEYS = (
    "HTTPS_PROXY",
    "https_proxy",
    "HTTP_PROXY",
    "http_proxy",
    "ALL_PROXY",
    "all_proxy",
    "NO_PROXY",
    "no_proxy",
    "WATCHLIGHT_PROXY_NO_PROXY",
    "WATCHLIGHT_PROXY_CA_CERT",
    "WATCHLIGHT_PROXY_ALLOW_PLAINTEXT",
    "STUB_TOKEN_SINK",
)


@pytest.fixture(autouse=True)
def _isolate_env():
    saved = {k: os.environ.get(k) for k in _ENV_KEYS}
    for k in _ENV_KEYS:
        os.environ.pop(k, None)
    yield
    uninstall_connect_proxy()
    uninstall_sidecar()
    for k, v in saved.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v


def _sidecar_threads() -> list:
    return [
        t
        for t in threading.enumerate()
        if t.name == "watchlight-connect-proxy" and t.is_alive()
    ]


# ─── capture server: records raw bytes it receives ──────────────────


class _RawCapture:
    """Plain-TCP listener that records every byte a client sends."""

    def __init__(self) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self.data = b""
        self._stop = False
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self) -> None:
        self.sock.settimeout(0.2)
        while not self._stop:
            try:
                conn, _ = self.sock.accept()
            except (socket.timeout, OSError):
                continue
            conn.settimeout(1.0)
            try:
                while True:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    self.data += chunk
            except (socket.timeout, OSError):
                pass
            finally:
                conn.close()

    def close(self) -> None:
        self._stop = True
        self.sock.close()


def _fire_through_sidecar() -> None:
    with httpx.Client(timeout=3.0) as client:
        try:
            client.get("https://api.example.com/v1/health")
        except httpx.HTTPError:
            pass


# ─── token required, bring-up before swap ─────────────────────


@pytest.mark.parametrize("token", [None, ""])
def test_connect_proxy_install_without_proxy_token_raises(token) -> None:
    with pytest.raises(GovernanceUnavailable):
        install_connect_proxy("http://127.0.0.1:1", token)  # type: ignore[arg-type]
    assert not is_connect_proxy_installed()


def test_connect_proxy_failed_bring_up_raises_and_keeps_previous_sidecar(
    monkeypatch,
) -> None:
    install_connect_proxy("http://127.0.0.1:1", "first-token")
    first_url = os.environ["HTTPS_PROXY"]

    async def _refuse_bind(*args, **kwargs):
        raise OSError("address unavailable")

    monkeypatch.setattr(cp.asyncio, "start_server", _refuse_bind)
    with pytest.raises(GovernanceUnavailable):
        install_connect_proxy("http://127.0.0.1:1", "second-token")
    monkeypatch.undo()

    # The earlier run's egress is still governed by its sidecar.
    assert is_connect_proxy_installed()
    assert os.environ["HTTPS_PROXY"] == first_url
    assert len(_sidecar_threads()) == 1


def test_connect_proxy_reinstall_keeps_customer_env_for_uninstall() -> None:
    os.environ["HTTPS_PROXY"] = "http://corp-proxy:3128"
    first_run = _EndedRun("a")
    install_connect_proxy("http://127.0.0.1:1", "a", egress=first_run.egress)
    first_run.ended = True
    install_connect_proxy("http://127.0.0.1:1", "b", egress=_EndedRun("b").egress)
    uninstall_connect_proxy()
    assert os.environ.get("HTTPS_PROXY") == "http://corp-proxy:3128"
    assert _sidecar_threads() == []


# ─── TLS to wl-proxy, never a cleartext token ─────────────────


def test_https_proxy_url_never_sends_token_in_cleartext() -> None:
    cap = _RawCapture()
    try:
        install_connect_proxy(
            f"https://127.0.0.1:{cap.port}", "CLEARTEXT-CANARY-TOKEN"
        )
        _fire_through_sidecar()
        time.sleep(0.3)
    finally:
        cap.close()
    assert b"CLEARTEXT-CANARY-TOKEN" not in cap.data
    assert b"Proxy-Authorization" not in cap.data


def test_plain_http_proxy_url_to_remote_host_is_refused() -> None:
    with pytest.raises(InsecureChannelError):
        install_connect_proxy("http://wl-proxy.example.com:8080", "tok")
    assert not is_connect_proxy_installed()


def test_plain_http_proxy_url_to_remote_host_allowed_only_by_explicit_opt_in(
    monkeypatch,
) -> None:
    monkeypatch.setenv("WATCHLIGHT_PROXY_ALLOW_PLAINTEXT", "true")
    install_connect_proxy("http://wl-proxy.example.com:8080", "tok")
    assert is_connect_proxy_installed()


def _self_signed(tmp_path):
    pytest.importorskip("cryptography")
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    import ipaddress

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(hours=1))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
            ),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    cert_path = tmp_path / "proxy.pem"
    key_path = tmp_path / "proxy.key"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return str(cert_path), str(key_path)


def test_https_proxy_url_delivers_token_inside_verified_tls(tmp_path) -> None:
    cert_path, key_path = _self_signed(tmp_path)
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.load_cert_chain(cert_path, key_path)
    received: dict = {}
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]

    def _serve() -> None:
        listener.settimeout(5.0)
        try:
            conn, _ = listener.accept()
            with ctx.wrap_socket(conn, server_side=True) as tls:
                tls.settimeout(3.0)
                data = b""
                while b"\r\n\r\n" not in data:
                    chunk = tls.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                received["head"] = data
                tls.sendall(
                    b"HTTP/1.1 407 Proxy Authentication Required\r\n"
                    b"Content-Length: 0\r\nConnection: close\r\n\r\n"
                )
        except Exception as exc:  # noqa: BLE001
            received["error"] = repr(exc)
        finally:
            listener.close()

    t = threading.Thread(target=_serve, daemon=True)
    t.start()
    os.environ["WATCHLIGHT_PROXY_CA_CERT"] = cert_path
    install_connect_proxy(f"https://localhost:{port}", "TLS-TOKEN")
    _fire_through_sidecar()
    t.join(timeout=5.0)
    assert b"Proxy-Authorization: Bearer TLS-TOKEN" in received.get("head", b""), received


# ─── concurrent installs never leak a sidecar ─────────────────


def test_concurrent_connect_proxy_installs_leave_exactly_one_sidecar(
    monkeypatch,
) -> None:
    real_start_server = asyncio.start_server

    async def _slow_start_server(*args, **kwargs):
        await asyncio.sleep(0.2)
        return await real_start_server(*args, **kwargs)

    monkeypatch.setattr(cp.asyncio, "start_server", _slow_start_server)
    errors: list = []

    def _install(i: int) -> None:
        try:
            install_connect_proxy(
                "http://127.0.0.1:1", f"token-{i}", egress=_EndedRun(f"token-{i}").egress
            )
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=_install, args=(i,)) for i in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10.0)
    monkeypatch.undo()

    # Four live runs race: exactly one owns the proxy, the other three are
    # refused (one live run per process).
    assert len(errors) == 3 and all(isinstance(e, SidecarRunActive) for e in errors)
    assert len(_sidecar_threads()) == 1
    assert os.environ["HTTPS_PROXY"] == f"http://127.0.0.1:{cp._state.port}"
    uninstall_connect_proxy()
    time.sleep(0.1)
    assert _sidecar_threads() == []


# ─── wildcard bypass never exempts all egress ────────────────


@pytest.mark.parametrize("value", ["*", "wl-apdp,*", "0.0.0.0/0"])
def test_wildcard_watchlight_proxy_no_proxy_is_refused(value) -> None:
    os.environ["WATCHLIGHT_PROXY_NO_PROXY"] = value
    with pytest.raises(GovernanceUnavailable):
        install_connect_proxy("http://127.0.0.1:1", "tok")
    assert not is_connect_proxy_installed()


@pytest.mark.parametrize("var", ["NO_PROXY", "no_proxy"])
def test_customer_wildcard_no_proxy_is_not_merged_while_installed(var) -> None:
    os.environ[var] = "corp.internal,*"
    install_connect_proxy("http://127.0.0.1:1", "tok")
    for name in ("NO_PROXY", "no_proxy"):
        entries = [e.strip() for e in os.environ[name].split(",")]
        assert "*" not in entries
        assert "corp.internal" in entries
    uninstall_connect_proxy()
    assert os.environ.get(var) == "corp.internal,*"


# ─── wl-sidecar launcher: same invariants ───────────────────────────

_GOOD_STUB = """#!/usr/bin/env python3
import sys, time
sys.stdin.readline()
print("127.0.0.1:54321", flush=True)
time.sleep(30)
"""

_BROKEN_STUB = """#!/usr/bin/env python3
import sys
sys.stdin.readline()
sys.exit(3)
"""


class _EndedRun:
    """A run's egress binding; set ``ended`` to end the run."""

    def __init__(self, token: str) -> None:
        self.token = token
        self.ended = False
        self.egress = EgressBinding(
            proxy_url=None,
            expires_at=None,
            token_source=lambda: None if self.ended else self.token,
        )


def _stub(tmp_path, name: str, body: str) -> str:
    p = tmp_path / name
    p.write_text(body)
    p.chmod(0o755)
    return str(p)


def test_sidecar_install_without_proxy_token_raises(tmp_path) -> None:
    good = _stub(tmp_path, "good", _GOOD_STUB)
    with pytest.raises(GovernanceUnavailable):
        install_sidecar("https://wl-proxy:8443", "", binary_path=good)
    assert not is_sidecar_installed()


def test_sidecar_failed_bring_up_raises_and_keeps_previous_sidecar(tmp_path) -> None:
    good = _stub(tmp_path, "good", _GOOD_STUB)
    broken = _stub(tmp_path, "broken", _BROKEN_STUB)
    first_run, second_run = _EndedRun("tok-a"), _EndedRun("tok-b")
    install_sidecar("https://wl-proxy:8443", "tok-a", binary_path=good, egress=first_run.egress)
    from watchlight_core import sidecar as sc

    first_proc = sc._state.proc
    first_run.ended = True
    with pytest.raises(GovernanceUnavailable):
        install_sidecar(
            "https://wl-proxy:8443",
            "tok-b",
            binary_path=broken,
            startup_timeout=2.0,
            egress=second_run.egress,
        )
    assert is_sidecar_installed()
    assert sc._state.proc is first_proc
    assert first_proc.poll() is None
    assert os.environ["HTTPS_PROXY"] == "http://127.0.0.1:54321"


def test_sidecar_missing_binary_raises_governance_unavailable(tmp_path) -> None:
    with pytest.raises(GovernanceUnavailable):
        install_sidecar(
            "https://wl-proxy:8443", "tok", binary_path=str(tmp_path / "absent")
        )


def test_sidecar_reinstall_keeps_customer_env_for_uninstall(tmp_path) -> None:
    good = _stub(tmp_path, "good", _GOOD_STUB)
    os.environ["HTTPS_PROXY"] = "http://corp-proxy:3128"
    first_run = _EndedRun("a")
    install_sidecar("https://wl-proxy:8443", "a", binary_path=good, egress=first_run.egress)
    first_run.ended = True
    install_sidecar("https://wl-proxy:8443", "b", binary_path=good, egress=_EndedRun("b").egress)
    uninstall_sidecar()
    assert os.environ.get("HTTPS_PROXY") == "http://corp-proxy:3128"


def test_sidecar_plain_http_to_remote_host_is_refused(tmp_path) -> None:
    good = _stub(tmp_path, "good", _GOOD_STUB)
    with pytest.raises(InsecureChannelError):
        install_sidecar("http://wl-proxy.example.com:8080", "tok", binary_path=good)
    assert not is_sidecar_installed()


def test_sidecar_wildcard_bypass_is_refused(tmp_path) -> None:
    good = _stub(tmp_path, "good", _GOOD_STUB)
    os.environ["WATCHLIGHT_PROXY_NO_PROXY"] = "*"
    with pytest.raises(GovernanceUnavailable):
        install_sidecar("https://wl-proxy:8443", "tok", binary_path=good)
    assert not is_sidecar_installed()


@pytest.mark.parametrize("var", ["NO_PROXY", "no_proxy"])
def test_sidecar_customer_wildcard_no_proxy_is_not_merged(tmp_path, var) -> None:
    good = _stub(tmp_path, "good", _GOOD_STUB)
    os.environ[var] = "corp.internal,*"
    install_sidecar("https://wl-proxy:8443", "tok", binary_path=good)
    for name in ("NO_PROXY", "no_proxy"):
        entries = [e.strip() for e in os.environ[name].split(",")]
        assert "*" not in entries
        assert "corp.internal" in entries
    uninstall_sidecar()
    assert os.environ.get(var) == "corp.internal,*"


# ─── pre-existing lower-case / catch-all proxies never win ──────────

_CORP = "http://corp-proxy.example:3128"


def _set_corporate_proxy_env() -> None:
    os.environ["https_proxy"] = _CORP
    os.environ["http_proxy"] = _CORP
    os.environ["ALL_PROXY"] = _CORP
    os.environ["all_proxy"] = _CORP


def _assert_clients_resolve_to(sidecar_url: str) -> None:
    import urllib.request

    import requests

    target = "https://api.example.test/v1"
    assert urllib.request.getproxies().get("https") == sidecar_url
    assert urllib.request.getproxies().get("http") == sidecar_url
    assert requests.utils.get_environ_proxies(target).get("https") == sidecar_url
    env = httpx._utils.get_environment_proxies()
    assert env.get("https://") == sidecar_url
    assert env.get("all://") is None
    with httpx.Client() as client:
        transport = client._transport_for_url(httpx.URL(target))
        assert transport is not client._transport  # routed via a proxy mount


def _assert_corporate_env_restored() -> None:
    for name in ("https_proxy", "http_proxy", "ALL_PROXY", "all_proxy"):
        assert os.environ.get(name) == _CORP
    assert os.environ.get("HTTPS_PROXY") is None


def test_connect_proxy_overrides_lower_case_and_all_proxy() -> None:
    _set_corporate_proxy_env()
    install_connect_proxy("http://127.0.0.1:1", "tok")
    sidecar_url = os.environ["HTTPS_PROXY"]
    assert sidecar_url.startswith("http://127.0.0.1:")
    assert os.environ["https_proxy"] == sidecar_url
    assert "ALL_PROXY" not in os.environ and "all_proxy" not in os.environ
    _assert_clients_resolve_to(sidecar_url)
    uninstall_connect_proxy()
    _assert_corporate_env_restored()


def test_sidecar_overrides_lower_case_and_all_proxy(tmp_path) -> None:
    good = _stub(tmp_path, "good", _GOOD_STUB)
    _set_corporate_proxy_env()
    install_sidecar("https://wl-proxy:8443", "tok", binary_path=good)
    sidecar_url = "http://127.0.0.1:54321"
    assert os.environ["HTTPS_PROXY"] == sidecar_url
    assert os.environ["https_proxy"] == sidecar_url
    assert "ALL_PROXY" not in os.environ and "all_proxy" not in os.environ
    _assert_clients_resolve_to(sidecar_url)
    uninstall_sidecar()
    _assert_corporate_env_restored()
