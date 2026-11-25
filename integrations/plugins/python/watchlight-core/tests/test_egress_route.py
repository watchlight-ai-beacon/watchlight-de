"""Core routes the process to the connector and proves it.

Real ``httpx``, ``aiohttp`` and provider SDK clients talk through a listener
that speaks ``CONNECT`` and terminates TLS under a throwaway CA, as the
connector's egress listener does. Hosts below are never resolved or reached:
a request that reached this listener went through the proxy, and a request
refused here never left the process.
"""

from __future__ import annotations

import asyncio
import datetime
import logging
import os
import shutil
import socket
import ssl
import tempfile
import threading
from pathlib import Path
from typing import Any, Iterator, List, Optional, Tuple
from unittest.mock import patch

import pytest

from watchlight_core import attribution as at
from watchlight_core import egress_route, provider_sdk_gate
from watchlight_core.attribution import EgressRefused, NO_PROXY_ENV_NAMES, PROXY_ENV_NAMES
from watchlight_core.backend import fetch_egress_binding
from watchlight_core.sidecar_backend import SidecarBackend

httpx = pytest.importorskip("httpx")
x509 = pytest.importorskip("cryptography.x509")
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402

from .wl_local_standin import StandInConnector  # noqa: E402

HEADER = "Watchlight-Run-Marker"
HOSTS = [
    "api.anthropic.com",
    "api.openai.com",
    "generativelanguage.googleapis.com",
    "provider.example.test",
]


def _issue(name: str, issuer: Any = None, issuer_key: Any = None, ca: bool = False) -> Tuple[Any, Any]:
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer if issuer is not None else subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=2))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
        # Python 3.13's default context verifies with VERIFY_X509_STRICT,
        # which needs the key identifiers and a key usage on every cert.
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                (issuer_key or key).public_key()
            ),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=not ca,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=ca,
                crl_sign=ca,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    )
    if not ca:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(h) for h in HOSTS]), critical=False
        ).add_extension(x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
    return key, builder.sign(issuer_key or key, hashes.SHA256())


class _Listener:
    """The connector's egress listener, for these tests."""

    def __init__(self, base: Path) -> None:
        ca_key, ca = _issue("test-ca", ca=True)
        key, leaf = _issue("leaf", ca.subject, ca_key)
        pem = serialization.Encoding.PEM
        self.ca_file = base / "ca.pem"
        self.ca_file.write_bytes(ca.public_bytes(pem))
        chain, key_file = base / "chain.pem", base / "key.pem"
        chain.write_bytes(leaf.public_bytes(pem) + ca.public_bytes(pem))
        key_file.write_bytes(
            key.private_bytes(
                pem, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()
            )
        )
        self._tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._tls.load_cert_chain(chain, key_file)
        self.requests: List[Tuple[str, Optional[str]]] = []
        self._socket = socket.create_server(("127.0.0.1", 0))
        self.url = f"http://127.0.0.1:{self._socket.getsockname()[1]}"
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self) -> None:
        while True:
            try:
                conn, _ = self._socket.accept()
            except OSError:
                return
            threading.Thread(target=self._one, args=(conn,), daemon=True).start()

    def _one(self, conn: socket.socket) -> None:
        try:
            head = b""
            while b"\r\n\r\n" not in head:
                head += conn.recv(4096)
            host = head.split()[1].decode()
            conn.sendall(b"HTTP/1.1 200 OK\r\n\r\n")
            tls = self._tls.wrap_socket(conn, server_side=True)
            request = b""
            while b"\r\n\r\n" not in request:
                data = tls.recv(65536)
                if not data:
                    return
                request += data
            head, _, body = request.partition(b"\r\n\r\n")
            marker = None
            length = 0
            for line in head.split(b"\r\n"):
                name, _, value = line.partition(b":")
                if name.lower() == HEADER.lower().encode():
                    marker = value.strip().decode()
                elif name.lower() == b"content-length":
                    length = int(value)
            # Closing with unread bytes would reset the answer away.
            while len(body) < length:
                body += tls.recv(65536)
            self.requests.append((host, marker))
            tls.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                b"Content-Length: 2\r\nConnection: close\r\n\r\n{}"
            )
            tls.close()
        except (OSError, ssl.SSLError):
            pass

    def close(self) -> None:
        self._socket.close()


class _Egress:
    marker_header = HEADER

    def __init__(self, proxy_url: str) -> None:
        self.proxy_url = proxy_url
        self.owner_pid = os.getpid()

    def marker(self) -> str:
        return "marker-a"

    def child_proxy_url(self) -> str:
        raise AssertionError("not used here")

    def report_connection_blocking(self, src_port: int, timeout_s: float = 2.0) -> bool:
        return True


@pytest.fixture(autouse=True)
def _environment(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    names = (*PROXY_ENV_NAMES, *NO_PROXY_ENV_NAMES, "SSL_CERT_FILE", "SSL_CERT_DIR")
    saved = {n: os.environ.pop(n, None) for n in names}
    monkeypatch.setattr(egress_route, "_route", None)
    monkeypatch.setattr(egress_route, "_proven", None)
    monkeypatch.setattr(egress_route, "partial_failures", {})
    yield
    for name, value in saved.items():
        os.environ.pop(name, None)
        if value is not None:
            os.environ[name] = value


@pytest.fixture
def listener(tmp_path: Path) -> Iterator[_Listener]:
    made = _Listener(tmp_path)
    # A deployment's CA distribution: certifi plus the customer's CA.
    certifi = pytest.importorskip("certifi")
    bundle = tmp_path / "bundle.pem"
    bundle.write_bytes(Path(certifi.where()).read_bytes() + made.ca_file.read_bytes())
    os.environ["SSL_CERT_FILE"] = str(bundle)
    yield made
    made.close()


class _Run:
    """The run's context."""

    def __init__(self, proxy_url: str) -> None:
        self.egress = _Egress(proxy_url)
        self._state = "active"
        self._is_subagent = False
        self._parent_handle_ref = None


@pytest.fixture
def run(listener: _Listener) -> Iterator[Any]:
    provider_sdk_gate.install()
    at.register_egress_endpoint(listener.url)
    yield _Run(listener.url)  # bound in each test: an async test has its own context
    at._endpoints.clear()


# ─── Admission ──────────────────────────────────────────────────────


@pytest.mark.asyncio
@pytest.mark.parametrize("bypass", ["*", "api.anthropic.com", ".googleapis.com"])
async def test_admission_replaces_every_variable_and_logs_only_names(
    listener: _Listener, caplog: Any, bypass: str
) -> None:
    os.environ["HTTPS_PROXY"] = "http://user:secret@corporate.example:3128"
    os.environ["NO_PROXY"] = bypass
    os.environ["no_proxy"] = bypass
    with caplog.at_level(logging.WARNING):
        await egress_route.admit(listener.url)
    assert all(os.environ[name] == listener.url for name in PROXY_ENV_NAMES)
    assert all(os.environ[name] == egress_route.LOOPBACK_NO_PROXY for name in NO_PROXY_ENV_NAMES)
    assert "HTTPS_PROXY was replaced" in caplog.text
    assert "secret" not in caplog.text and bypass not in caplog.text


@pytest.mark.asyncio
async def test_a_second_endpoint_is_refused_and_the_route_stays(listener: _Listener) -> None:
    await egress_route.admit(listener.url)
    with pytest.raises(EgressRefused, match="second_connector_endpoint"):
        await egress_route.admit("http://127.0.0.1:1")
    assert egress_route.current() == listener.url
    assert os.environ["HTTPS_PROXY"] == listener.url


@pytest.mark.asyncio
async def test_a_read_back_that_differs_is_refused(listener: _Listener) -> None:
    with patch("urllib.request.getproxies", return_value={"https": "http://other", "http": "x"}):
        with pytest.raises(EgressRefused, match="proxy_variables_not_effective"):
            await egress_route.admit(listener.url)


@pytest.mark.asyncio
async def test_a_ca_the_client_does_not_trust_is_refused(
    listener: _Listener,
) -> None:
    del os.environ["SSL_CERT_FILE"]
    with pytest.raises(EgressRefused, match="connector_tls_handshake_failed"):
        await egress_route.admit(listener.url)


@pytest.mark.asyncio
async def test_nothing_listening_is_refused() -> None:
    with socket.socket() as free:
        free.bind(("127.0.0.1", 0))
        port = free.getsockname()[1]
    with pytest.raises(EgressRefused, match="connector_tls_handshake_failed"):
        await egress_route.admit(f"http://127.0.0.1:{port}")


def _untrusting() -> ssl.SSLContext:
    return ssl.create_default_context(cafile=pytest.importorskip("certifi").where())


def _trusting(listener: _Listener) -> Any:
    return lambda: ssl.create_default_context(cafile=str(listener.ca_file))


@pytest.mark.asyncio
async def test_one_sdk_passing_admits_and_the_failure_is_counted(
    listener: _Listener, caplog: Any
) -> None:
    probes = [
        ("anthropic", "api.anthropic.com", _untrusting),
        ("openai", "api.openai.com", _trusting(listener)),
    ]
    with patch.object(egress_route, "_probes", return_value=probes), caplog.at_level(logging.WARNING):
        await egress_route.admit(listener.url)
    assert egress_route.partial_failures == {"anthropic": 1}
    assert "failed for anthropic (api.anthropic.com)" in caplog.text


@pytest.mark.asyncio
async def test_no_sdk_passing_is_refused_and_counts_no_partial_failure(listener: _Listener) -> None:
    probes = [("anthropic", "api.anthropic.com", _untrusting), ("openai", "api.openai.com", _untrusting)]
    with patch.object(egress_route, "_probes", return_value=probes):
        with pytest.raises(EgressRefused, match="connector_tls_handshake_failed"):
            await egress_route.admit(listener.url)
    assert egress_route.partial_failures == {}


@pytest.mark.asyncio
async def test_the_handshake_runs_once_per_process_and_endpoint_after_it_passes(
    listener: _Listener,
) -> None:
    with patch.object(egress_route, "_check_trust", side_effect=[EgressRefused("x"), None]) as check:
        with pytest.raises(EgressRefused):
            await egress_route.admit(listener.url)
        await egress_route.admit(listener.url)  # a failure is not remembered
        await egress_route.admit(listener.url)
    assert check.call_count == 2
    del os.environ["HTTPS_PROXY"], os.environ["https_proxy"]
    await egress_route.admit(listener.url)  # the variables are still forced
    assert os.environ["HTTPS_PROXY"] == listener.url


def test_a_module_whose_parent_is_missing_is_not_installed() -> None:
    assert egress_route._installed("watchlight_no_such_package.client") is False


@pytest.mark.asyncio
async def test_a_broken_install_is_a_typed_refusal(listener: _Listener) -> None:
    with patch("importlib.util.find_spec", side_effect=ImportError("broken")):
        with pytest.raises(EgressRefused, match="connector_tls_handshake_failed"):
            await egress_route.admit(listener.url)


@pytest.mark.asyncio
async def test_every_probe_skipped_is_still_refused(listener: _Listener) -> None:
    with patch.object(egress_route, "_installed", return_value=False):
        with patch.object(egress_route, "_httpx_context", _untrusting):
            with pytest.raises(EgressRefused, match="connector_tls_handshake_failed"):
                await egress_route.admit(listener.url)


def test_the_genai_handshake_uses_genais_own_context(listener: _Listener) -> None:
    pytest.importorskip("google.genai")
    egress_route._handshake(
        listener.url, "generativelanguage.googleapis.com", egress_route._genai_context()
    )
    # Its context comes from certifi when SSL_CERT_FILE is absent, as it does
    # for a real client: the throwaway CA then fails.
    saved = os.environ.pop("SSL_CERT_FILE")
    try:
        with pytest.raises(ssl.SSLError):
            egress_route._handshake(
                listener.url, "generativelanguage.googleapis.com", egress_route._genai_context()
            )
    finally:
        os.environ["SSL_CERT_FILE"] = saved


@pytest.mark.asyncio
async def test_a_connector_run_is_routed_and_refused_when_the_route_fails(
    listener: _Listener,
) -> None:
    base = Path(tempfile.mkdtemp(prefix="wlr", dir="/tmp"))  # a short socket path
    stand_in = await StandInConnector(base).start()
    backend = SidecarBackend(socket_path=stand_in.socket_path)
    try:
        info = await backend.create_session("agent-1")
        stand_in.proxy_url = listener.url
        bundle = os.environ.pop("SSL_CERT_FILE")
        with pytest.raises(EgressRefused, match="connector_tls_handshake_failed"):
            await fetch_egress_binding(backend, info.run)
        os.environ["SSL_CERT_FILE"] = bundle
        assert await fetch_egress_binding(backend, info.run) is not None
        assert os.environ["HTTPS_PROXY"] == listener.url
    finally:
        await backend.close()
        await stand_in.stop()
        shutil.rmtree(base, ignore_errors=True)


# ─── Real clients on the route ──────────────────────────────────────


@pytest.mark.asyncio
async def test_a_stainless_client_built_after_admission_reaches_the_connector(
    listener: _Listener, run: Any
) -> None:
    anthropic = pytest.importorskip("anthropic")
    await egress_route.admit(listener.url)
    client = anthropic.AsyncAnthropic(api_key="k", max_retries=0)
    with at.bound_run(run):
        await client.messages.create(
            model="m", max_tokens=1, messages=[{"role": "user", "content": "h"}]
        )
    assert listener.requests == [("api.anthropic.com:443", "marker-a")]


@pytest.mark.asyncio
async def test_an_openai_client_built_after_admission_reaches_the_connector(
    listener: _Listener, run: Any
) -> None:
    openai = pytest.importorskip("openai")
    await egress_route.admit(listener.url)
    client = openai.AsyncOpenAI(api_key="k", max_retries=0)
    with at.bound_run(run):
        await client.chat.completions.create(model="m", messages=[{"role": "user", "content": "h"}])
    assert listener.requests == [("api.openai.com:443", "marker-a")]


def _genai() -> Any:
    return pytest.importorskip("google.genai")


def _aiohttp() -> Any:
    """aiohttp, which CI installs with the dev extra. google-genai sends its
    async requests over it, so without it these tests fail rather than skip
    the path they prove."""
    try:
        import aiohttp
    except ImportError:
        pytest.fail("aiohttp is not installed: install watchlight-core[dev]")
    return aiohttp


@pytest.mark.asyncio
async def test_genai_over_aiohttp_reaches_the_connector(listener: _Listener, run: Any) -> None:
    _aiohttp()
    genai = _genai()
    await egress_route.admit(listener.url)
    client = genai.Client(api_key="k")
    assert client._api_client._use_aiohttp()
    with at.bound_run(run):
        await client.aio.models.generate_content(model="gemini-x", contents="h")
    assert listener.requests == [("generativelanguage.googleapis.com:443", "marker-a")]


@pytest.mark.asyncio
async def test_genai_over_httpx_reaches_the_connector(listener: _Listener, run: Any) -> None:
    genai = _genai()
    await egress_route.admit(listener.url)
    client = genai.Client(api_key="k")
    with at.bound_run(run):
        await asyncio.to_thread(client.models.generate_content, model="gemini-x", contents="h")
    assert listener.requests == [("generativelanguage.googleapis.com:443", "marker-a")]


# ─── Clients off the route ──────────────────────────────────────────


def _refused(listener: _Listener) -> Any:
    assert listener.requests == []
    return pytest.raises(EgressRefused, match="client_route")


@pytest.mark.asyncio
async def test_a_client_built_before_admission_is_refused_with_no_marker(
    listener: _Listener, run: Any
) -> None:
    anthropic = pytest.importorskip("anthropic")
    early = anthropic.AsyncAnthropic(api_key="k", max_retries=0)
    await egress_route.admit(listener.url)
    with at.bound_run(run):
        with _refused(listener):
            await early.messages.create(model="m", max_tokens=1, messages=[{"role": "user", "content": "h"}])
    assert listener.requests == []


@pytest.mark.asyncio
async def test_a_base_url_on_loopback_is_not_the_route(listener: _Listener, run: Any) -> None:
    anthropic = pytest.importorskip("anthropic")
    await egress_route.admit(listener.url)
    local = anthropic.AsyncAnthropic(api_key="k", base_url="http://127.0.0.1:9", max_retries=0)
    with at.bound_run(run):
        with _refused(listener):
            await local.messages.create(model="m", max_tokens=1, messages=[{"role": "user", "content": "h"}])


@pytest.mark.asyncio
async def test_custom_transports_and_no_trust_env_are_refused(listener: _Listener) -> None:
    await egress_route.admit(listener.url)
    url = "https://provider.example.test/"

    class _Subclass(httpx.HTTPTransport):
        pass

    for client in (
        httpx.Client(trust_env=False),
        httpx.Client(transport=httpx.HTTPTransport()),
        httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200))),
        httpx.Client(mounts={"https://": _Subclass(proxy=listener.url)}),
    ):
        with pytest.raises(EgressRefused):
            egress_route.require_httpx_route(client, url)


@pytest.mark.asyncio
async def test_the_mount_for_the_request_url_is_the_one_checked(listener: _Listener) -> None:
    await egress_route.admit(listener.url)
    client = httpx.Client(
        trust_env=False,
        mounts={
            "https://provider.example.test": httpx.HTTPTransport(),
            "all://": httpx.HTTPTransport(proxy=listener.url),
        },
    )
    egress_route.require_httpx_route(client, "https://other.example.test/")
    with pytest.raises(EgressRefused):
        egress_route.require_httpx_route(client, "https://provider.example.test/")


@pytest.mark.asyncio
async def test_a_proxy_on_another_port_is_refused(listener: _Listener) -> None:
    await egress_route.admit(listener.url)
    client = httpx.Client(proxy="http://127.0.0.1:1")
    with pytest.raises(EgressRefused):
        egress_route.require_httpx_route(client, "https://provider.example.test/")


@pytest.mark.asyncio
async def test_a_client_built_before_admission_with_no_bound_run_is_refused(
    listener: _Listener,
) -> None:
    anthropic = pytest.importorskip("anthropic")
    provider_sdk_gate.install()
    early = anthropic.AsyncAnthropic(api_key="k", max_retries=0)
    await egress_route.admit(listener.url)
    assert not at.connector_in_use()
    with pytest.raises(EgressRefused, match="client_route"):
        await early.messages.create(model="m", max_tokens=1, messages=[{"role": "user", "content": "h"}])
    assert listener.requests == []


@pytest.mark.asyncio
async def test_an_aiohttp_session_proxy_or_other_connector_is_refused(listener: _Listener) -> None:
    aiohttp = _aiohttp()
    await egress_route.admit(listener.url)
    url = "https://provider.example.test/"

    class _Connector(aiohttp.TCPConnector):
        pass

    async with aiohttp.ClientSession(trust_env=True, proxy="http://other.example") as session:
        with pytest.raises(EgressRefused, match="client_route"):
            egress_route.require_aiohttp_route(session, url, {})
    async with aiohttp.ClientSession(trust_env=True, connector=_Connector()) as session:
        with pytest.raises(EgressRefused, match="client_route"):
            egress_route.require_aiohttp_route(session, url, {})


@pytest.mark.asyncio
async def test_a_probe_that_cannot_be_built_counts_as_failed(listener: _Listener, caplog: Any) -> None:
    def broken() -> Any:
        raise AttributeError("moved")

    probes = [("google-genai", "generativelanguage.googleapis.com", broken)]
    with patch.object(egress_route, "_probes", return_value=probes), caplog.at_level(logging.WARNING):
        with pytest.raises(EgressRefused, match="connector_tls_handshake_failed"):
            await egress_route.admit(listener.url)
    assert "generativelanguage.googleapis.com" in caplog.text


def test_an_unreadable_route_refuses(listener: _Listener, run: Any) -> None:
    egress_route._route = listener.url
    with pytest.raises(EgressRefused, match="client_route_unreadable"):
        provider_sdk_gate._require_stainless_route((object(), None, object()), {})


@pytest.mark.asyncio
async def test_genai_plain_aiohttp_session_and_request_proxy_are_refused(
    listener: _Listener, run: Any
) -> None:
    aiohttp = _aiohttp()
    genai = _genai()
    await egress_route.admit(listener.url)
    async with aiohttp.ClientSession() as session:  # trust_env defaults to False
        with pytest.raises(EgressRefused, match="client_route"):
            egress_route.require_aiohttp_route(session, "https://provider.example.test/", {})
    async with aiohttp.ClientSession(trust_env=True) as session:
        egress_route.require_aiohttp_route(session, "https://provider.example.test/", {"proxy": None})
        with pytest.raises(EgressRefused, match="client_route"):
            egress_route.require_aiohttp_route(
                session, "https://provider.example.test/", {"proxy": "http://direct.example"}
            )
    client = genai.Client(api_key="k", http_options={"async_client_args": {"proxy": "http://other.example"}})
    with at.bound_run(run):
        with _refused(listener):
            await client.aio.models.generate_content(model="gemini-x", contents="h")
    assert listener.requests == []


@pytest.mark.asyncio
async def test_a_failed_genai_session_getter_refuses_before_any_marker(
    listener: _Listener, run: Any
) -> None:
    _aiohttp()
    genai = _genai()
    await egress_route.admit(listener.url)
    client = genai.Client(api_key="k")

    async def broken() -> Any:
        raise RuntimeError("no session")

    client._api_client._get_aiohttp_session = broken
    with at.bound_run(run):
        with _refused(listener):
            await client.aio.models.generate_content(model="gemini-x", contents="h")


def test_the_google_auth_transport_refuses(listener: _Listener, run: Any) -> None:
    genai = _genai()
    egress_route._route = listener.url
    client = genai.Client(api_key="k")
    with patch.object(type(client._api_client), "_use_google_auth_sync", return_value=True, create=True):
        with _refused(listener):
            client.models.generate_content(model="gemini-x", contents="h")
