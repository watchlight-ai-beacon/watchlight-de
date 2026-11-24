"""The in-process CONNECT proxy carries one live run's egress.

The proxy is process-wide: every HTTP library in the process reaches it
through ``HTTP(S)_PROXY``. So while the run that installed it is live, a
second run's install is refused before anything changes, and each CONNECT
carries the owning run's token as its binding gives it at that moment.
Once the owning run has ended, a CONNECT is answered 403 locally: no token
goes out and nothing goes direct.
"""

from __future__ import annotations

import os
import socket
import socketserver
import threading
from queue import Empty, Queue
from typing import List

import pytest

from watchlight_core import (
    GovernanceUnavailable,
    SidecarRunActive,
    install_connect_proxy,
    is_connect_proxy_installed,
    uninstall_connect_proxy,
)
from watchlight_core.backend import EgressBinding


class _Run:
    """A run's egress binding whose backend entry can be ended."""

    def __init__(self, token: str) -> None:
        self.token = token
        self.ended = False
        self.egress = EgressBinding(
            proxy_url=None,
            expires_at=None,
            token_source=lambda: None if self.ended else self.token,
        )


# In-process stand-in for unit tests only: records the Proxy-Authorization
# of every CONNECT it receives, then answers 407.
class _RecordingWlProxy(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        self.request.settimeout(5.0)
        data = b""
        while b"\r\n\r\n" not in data and len(data) < 8192:
            chunk = self.request.recv(4096)
            if not chunk:
                return
            data += chunk
        auth = ""
        for line in data.split(b"\r\n\r\n", 1)[0].split(b"\r\n")[1:]:
            name, _, value = line.decode().partition(": ")
            if name.lower() == "proxy-authorization":
                auth = value
        self.server.seen.put(auth)  # type: ignore[attr-defined]
        self.request.sendall(b"HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n")


class _RecordingServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    seen: Queue


@pytest.fixture
def wl_proxy():
    server = _RecordingServer(("127.0.0.1", 0), _RecordingWlProxy)
    server.seen = Queue()
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield server
    server.shutdown()
    server.server_close()


@pytest.fixture(autouse=True)
def _isolate():
    saved = {k: os.environ.get(k) for k in ("HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY", "no_proxy")}
    yield
    uninstall_connect_proxy()
    for k, v in saved.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v


def _connect_through_the_proxy() -> bytes:
    """Send one CONNECT to the installed local proxy; return its status line."""
    port = int(os.environ["HTTPS_PROXY"].rsplit(":", 1)[1])
    with socket.create_connection(("127.0.0.1", port), timeout=5.0) as conn:
        conn.sendall(b"CONNECT api.example.test:443 HTTP/1.1\r\nHost: api.example.test:443\r\n\r\n")
        return conn.makefile("rb").readline()


def _drain(seen: Queue) -> List[str]:
    out = []
    while True:
        try:
            out.append(seen.get(timeout=0.5))
        except Empty:
            return out


def _url(server: _RecordingServer) -> str:
    return f"http://127.0.0.1:{server.server_address[1]}"


def test_a_second_run_is_refused_while_the_first_owns_the_proxy(wl_proxy):
    run_a, run_b = _Run("TOKEN-A"), _Run("TOKEN-B")
    install_connect_proxy(_url(wl_proxy), "TOKEN-A", egress=run_a.egress)
    env_before = os.environ["HTTPS_PROXY"]

    with pytest.raises(SidecarRunActive) as refused:
        install_connect_proxy(_url(wl_proxy), "TOKEN-B", egress=run_b.egress)

    assert isinstance(refused.value, GovernanceUnavailable)
    assert "TOKEN" not in str(refused.value)
    assert "3600" in str(refused.value)  # the session TTL that releases a dropped run
    assert os.environ["HTTPS_PROXY"] == env_before
    # The first run's egress still carries only the first run's token.
    assert b" 407 " in _connect_through_the_proxy()
    assert _drain(wl_proxy.seen) == ["Bearer TOKEN-A"]


def test_each_connect_reads_the_owner_token_and_an_ended_run_is_refused_locally(wl_proxy):
    run_a = _Run("TOKEN-A")
    install_connect_proxy(_url(wl_proxy), "TOKEN-A", egress=run_a.egress)
    run_a.token = "TOKEN-A-ROTATED"
    assert b" 407 " in _connect_through_the_proxy()
    assert _drain(wl_proxy.seen) == ["Bearer TOKEN-A-ROTATED"]

    run_a.ended = True
    status = _connect_through_the_proxy()

    assert status.startswith(b"HTTP/1.1 403")
    # Nothing reached wl-proxy: the ended run's token is never sent again.
    assert _drain(wl_proxy.seen) == []
    # And the process still routes to the refusing proxy, never direct.
    assert is_connect_proxy_installed()


def test_an_unreadable_owner_refuses_every_connect_and_holds_the_proxy(wl_proxy):
    def unreadable() -> str:
        raise RuntimeError("backend gone")

    owner = EgressBinding(proxy_url=None, expires_at=None, token_source=unreadable)
    install_connect_proxy(_url(wl_proxy), "TOKEN-A", egress=owner)

    assert _connect_through_the_proxy().startswith(b"HTTP/1.1 403")
    assert _drain(wl_proxy.seen) == []
    with pytest.raises(SidecarRunActive):
        install_connect_proxy(_url(wl_proxy), "TOKEN-B", egress=_Run("TOKEN-B").egress)


def test_after_the_owner_ends_the_next_run_replaces_the_proxy(wl_proxy):
    run_a, run_b = _Run("TOKEN-A"), _Run("TOKEN-B")
    install_connect_proxy(_url(wl_proxy), "TOKEN-A", egress=run_a.egress)
    run_a.ended = True

    install_connect_proxy(_url(wl_proxy), "TOKEN-B", egress=run_b.egress)

    assert b" 407 " in _connect_through_the_proxy()
    assert _drain(wl_proxy.seen) == ["Bearer TOKEN-B"]


def test_a_proxy_without_an_owner_is_held_until_uninstall(wl_proxy):
    install_connect_proxy(_url(wl_proxy), "tok-a")
    with pytest.raises(SidecarRunActive):
        install_connect_proxy(_url(wl_proxy), "tok-b")
    with pytest.raises(SidecarRunActive):
        install_connect_proxy(_url(wl_proxy), "tok-b", egress=_Run("tok-b").egress)

    uninstall_connect_proxy()
    install_connect_proxy(_url(wl_proxy), "tok-b")
    assert _connect_through_the_proxy()
    assert _drain(wl_proxy.seen) == ["Bearer tok-b"]


def test_the_owning_run_may_install_again(wl_proxy):
    run_a = _Run("TOKEN-A")
    install_connect_proxy(_url(wl_proxy), "TOKEN-A", egress=run_a.egress)
    install_connect_proxy(_url(wl_proxy), "TOKEN-A", egress=run_a.egress)
    assert _connect_through_the_proxy()
    assert _drain(wl_proxy.seen) == ["Bearer TOKEN-A"]
