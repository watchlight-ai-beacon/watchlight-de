"""Puts this process's traffic on the Watchlight connector.

At run admission :func:`admit` forces the proxy variables to the connector's
egress listener, reads them back, then does a real TLS handshake through
it under each installed provider SDK's own trust, once per process and
endpoint. One SDK passing shows that SDK's trust reaches a certificate through
that endpoint. Nothing here proves the endpoint is the connector: a blind
forwarder on the port the control channel named would pass. A host
the CA doesn't cover fails at TLS on the real request, which never goes
direct, so an unused SDK doesn't refuse the run. The route stays for the life of the process: all runs share it, because a request names
its run with the marker, and one process has one connector.

Core installs no trust. The CA is the customer's and they distribute it, so a
handshake that doesn't verify refuses the run.

Setting the variables doesn't reach a client built earlier, because a client
reads them when it is built. So :mod:`~watchlight_core.provider_sdk_gate`
calls the ``require_*`` checks here on every provider SDK request, before the
marker is added. They read private SDK and ``httpx`` attributes on purpose: a
new version that changes them refuses instead of leaking.

This doesn't enforce anything outside the three SDKs. A tool's own client or
a custom transport relies on the variables or on the deployment's network
policy.
"""

from __future__ import annotations

import asyncio
import importlib
import importlib.util
import logging
import os
import socket
import ssl
import sys
import threading
import urllib.request
from typing import Any, Dict, List, Mapping, Optional, Tuple
from urllib.parse import urlsplit

from .attribution import NO_PROXY_ENV_NAMES, PROXY_ENV_NAMES, EgressRefused

logger = logging.getLogger(__name__)

#: ``NO_PROXY`` replaces whatever was set: a kept list could name a provider.
LOOPBACK_NO_PROXY = "localhost,127.0.0.1,::1"

HANDSHAKE_TIMEOUT_S = 5.0

_lock = threading.Lock()
_route: Optional[str] = None
_proven: Optional[str] = None
#: Handshake failures per SDK, while another SDK's handshake passed.
partial_failures: Dict[str, int] = {}


def current() -> Optional[str]:
    """The connector this process is routed to, or ``None``."""
    return _route


def _set(name: str, value: str) -> None:
    previous = os.environ.get(name)
    if previous and previous != value:
        # The name only: a proxy URL can carry credentials.
        logger.warning("%s was replaced to route this process to the Watchlight connector", name)
    os.environ[name] = value


def _force(proxy_url: str) -> None:
    global _route
    with _lock:
        if _route is not None and _route != proxy_url:
            raise EgressRefused("second_connector_endpoint")
        for name in PROXY_ENV_NAMES:
            _set(name, proxy_url)
        for name in NO_PROXY_ENV_NAMES:
            _set(name, LOOPBACK_NO_PROXY)
        _route = proxy_url


def _read_back(proxy_url: str) -> None:
    # This proves the write, not the route; the handshake is the real check.
    proxies = urllib.request.getproxies()
    if proxies.get("https") != proxy_url or proxies.get("http") != proxy_url:
        raise EgressRefused("proxy_variables_not_effective")


def _genai_context() -> ssl.SSLContext:
    from google.genai import _api_client, types

    args = _api_client.BaseApiClient._ensure_httpx_ssl_ctx(types.HttpOptions())[0]
    context = args["verify"]
    if not isinstance(context, ssl.SSLContext):
        raise TypeError("no SSL context")
    return context


def _httpx_context() -> ssl.SSLContext:
    # The library the Anthropic and OpenAI SDKs send through when both exist.
    name = "httpx2" if _installed("httpx2") else "httpx"
    return importlib.import_module(name).create_ssl_context()


def _installed(module: str) -> bool:
    # find_spec imports the parent package, which may not be there. Any other
    # import failure is a broken install, and it stays an error.
    try:
        return importlib.util.find_spec(module) is not None
    except ModuleNotFoundError:
        return False


def _probes() -> List[Tuple[str, str, Any]]:
    """``(SDK, host, context builder)`` for each installed provider SDK, with
    the trust its clients use. ``httpx`` is always here, so there is one."""
    probes: List[Tuple[str, str, Any]] = []
    if _installed("anthropic"):
        probes.append(("anthropic", "api.anthropic.com", _httpx_context))
    if _installed("openai"):
        probes.append(("openai", "api.openai.com", _httpx_context))
    if _installed("google.genai"):
        probes.append(("google-genai", "generativelanguage.googleapis.com", _genai_context))
    return probes or [("httpx", "api.anthropic.com", _httpx_context)]


def _handshake(proxy_url: str, host: str, context: ssl.SSLContext) -> None:
    parts = urlsplit(proxy_url)
    with socket.create_connection(
        (parts.hostname, parts.port), timeout=HANDSHAKE_TIMEOUT_S
    ) as sock:
        sock.sendall(f"CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n".encode())
        head = b""
        while b"\r\n\r\n" not in head:
            chunk = sock.recv(4096)
            if not chunk or len(head) > 8192:
                raise OSError("no CONNECT answer")
            head += chunk
        if head.split(None, 2)[1:2] != [b"200"]:
            raise OSError("CONNECT refused")
        with context.wrap_socket(sock, server_hostname=host):
            pass


def _record_partial_failure(sdk: str, host: str) -> None:
    logger.warning(
        "TLS handshake through the connector failed for %s (%s): its requests will fail at TLS",
        sdk,
        host,
    )
    partial_failures[sdk] = partial_failures.get(sdk, 0) + 1
    # The warning is the signal. Core's OTLP provider isn't global, so this
    # exports only if the host sets one.
    try:
        from opentelemetry import metrics
    except ImportError:
        return
    metrics.get_meter("watchlight").create_counter(
        "wl.egress.handshake_partial_failures"
    ).add(1, {"sdk": sdk})


def _check_trust(proxy_url: str) -> None:
    failed: List[Tuple[str, str]] = []
    try:
        probes = _probes()
    except ImportError as exc:
        logger.warning("a provider SDK can't be read: %s", type(exc).__name__)
        raise EgressRefused("connector_tls_handshake_failed") from exc
    for sdk, host, build in probes:
        try:
            # Inside the try: a probe that can't be built counts as failed.
            _handshake(proxy_url, host, build())
        except Exception as exc:  # noqa: BLE001 - counted; none passing refuses
            logger.debug("handshake for %s failed: %s", sdk, type(exc).__name__)
            failed.append((sdk, host))
    if len(failed) == len(probes):
        hosts = ", ".join(host for _, host in failed)
        logger.warning("TLS handshake through the connector failed for every provider SDK: %s", hosts)
        raise EgressRefused("connector_tls_handshake_failed")
    for sdk, host in failed:
        _record_partial_failure(sdk, host)


async def admit(proxy_url: str) -> None:
    """Route this process to the connector at ``proxy_url`` and prove it.
    Raises :class:`~watchlight_core.attribution.EgressRefused`."""
    global _proven
    _force(proxy_url)
    _read_back(proxy_url)
    if _proven == proxy_url:
        return
    await asyncio.to_thread(_check_trust, proxy_url)
    _proven = proxy_url


def _is_route(proxy: Any) -> bool:
    route = urlsplit(_route or "")
    return (
        proxy is not None
        and proxy.scheme == route.scheme.encode()
        and proxy.host == (route.hostname or "").encode()
        and proxy.port == route.port
    )


def _httpx_library_of(client: Any) -> Any:
    # Newer Anthropic and OpenAI SDKs send through ``httpx2``, a separate
    # package with the same API.
    for name in ("httpx", "httpx2"):
        library = sys.modules.get(name)
        if library is not None and isinstance(client, (library.Client, library.AsyncClient)):
            return library
    raise EgressRefused("client_route_not_connector")


def require_httpx_route(client: Any, url: Any) -> None:
    """Refuse unless the mount ``client`` uses for ``url`` is the connector.
    A custom transport refuses, and so does anything unreadable."""
    library = _httpx_library_of(client)
    transport = client._transport_for_url(library.URL(str(url)))
    if type(transport) not in (library.HTTPTransport, library.AsyncHTTPTransport):
        raise EgressRefused("client_route_not_connector")
    if not _is_route(getattr(transport._pool, "_proxy_url", None)):
        raise EgressRefused("client_route_not_connector")


def _plain_connector(connector: Any, aiohttp: Any) -> bool:
    # google-genai builds its session on its own subclass, which changes only
    # how the connector is cleaned up. Any other subclass refuses.
    kind = type(connector)
    return kind is aiohttp.TCPConnector or (
        kind.__module__ == "google.genai._api_client"
        and kind.__name__ == "AiohttpTCPConnector"
        and kind.__bases__ == (aiohttp.TCPConnector,)
    )


def require_aiohttp_route(session: Any, url: str, request_args: Mapping[str, Any]) -> None:
    """Refuse unless an aiohttp ``session`` sends ``url`` to the connector.
    It reads the variables on each request, and only with ``trust_env``. A
    session-level proxy wins over them, and a connector of another type is
    the aiohttp form of a custom transport."""
    import aiohttp
    from aiohttp.helpers import get_env_proxy_for_url
    from yarl import URL

    if (
        session.trust_env is not True
        or request_args.get("proxy") is not None
        or session._default_proxy is not None
        or not _plain_connector(session.connector, aiohttp)
    ):
        raise EgressRefused("client_route_not_connector")
    proxy = get_env_proxy_for_url(URL(url))[0]
    if str(proxy) != _route:
        raise EgressRefused("client_route_not_connector")
