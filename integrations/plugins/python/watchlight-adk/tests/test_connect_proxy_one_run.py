"""ADK: one governed run's CONNECT egress per process, through the
plugin's real run start.

The in-process CONNECT proxy is process-wide. While a run owns it, a second
run is refused with ``SidecarRunActive`` and the first run's CONNECTs carry
only its own token. Once that run ends, its CONNECTs are refused locally
(no token, never direct), and the next run starts on its own token.
"""

from __future__ import annotations

import os
import socket
import socketserver
import threading
import uuid
from queue import Empty, Queue
from typing import List

import pytest

from watchlight_core import SidecarRunActive, uninstall_connect_proxy
from watchlight_core.backend import egress_binding_for
from watchlight_core_testing import MockApdpClient
from unittest.mock import MagicMock

from watchlight_adk import WatchlightPlugin


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
def wl_proxy(monkeypatch):
    for name in ("HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY", "no_proxy", "WATCHLIGHT_PROXY_URL"):
        monkeypatch.delenv(name, raising=False)
    server = _RecordingServer(("127.0.0.1", 0), _RecordingWlProxy)
    server.seen = Queue()
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_address[1]}", server.seen
    uninstall_connect_proxy()
    server.shutdown()
    server.server_close()


def _connect() -> bytes:
    port = int(os.environ["HTTPS_PROXY"].rsplit(":", 1)[1])
    with socket.create_connection(("127.0.0.1", port), timeout=5.0) as conn:
        conn.sendall(b"CONNECT api.example.test:443 HTTP/1.1\r\nHost: api.example.test:443\r\n\r\n")
        return conn.makefile("rb").readline()


def _seen(queue: Queue) -> List[str]:
    out = []
    while True:
        try:
            out.append(queue.get(timeout=0.5))
        except Empty:
            return out


def _backend() -> MockApdpClient:
    backend = MockApdpClient()
    backend.proxy_token_prefix = "wlp_standin"
    backend.known_agents["agent-a"] = str(uuid.uuid4())
    backend.known_agents["agent-b"] = str(uuid.uuid4())
    return backend


def _adk_plugin(url: str, slug: str) -> WatchlightPlugin:
    plugin = WatchlightPlugin(
        apdp_url="https://localhost:8081",
        connect_proxy_url=url,
        agent_slug=slug,
        root_agent_name=slug.replace("-", "_"),
    )
    plugin.apdp = _backend()
    plugin._current_agent_id = plugin.apdp.known_agents[slug]
    plugin._current_execution_id = f"exec_{slug}"
    return plugin


def _ctx() -> MagicMock:
    ctx = MagicMock()
    ctx.state = {}
    return ctx


@pytest.mark.asyncio
async def test_a_second_run_is_refused_and_the_first_keeps_its_own_egress(wl_proxy):
    url, seen = wl_proxy
    first, second = _adk_plugin(url, "agent-a"), _adk_plugin(url, "agent-b")

    await first._open_session_and_manifest(_ctx())
    first_token = egress_binding_for(first.apdp, first._current_run).proxy_authorization()

    with pytest.raises(SidecarRunActive):
        await second._open_session_and_manifest(_ctx())

    assert b" 407 " in _connect()
    assert _seen(seen) == [f"Bearer {first_token}"]
    # The refused run's session was closed.
    assert len(second.apdp._closed_sessions) == 1

    await first.apdp.complete_session(first._current_run)
    # The ended run's CONNECT is refused here: no token, never direct.
    assert _connect().startswith(b"HTTP/1.1 403")
    assert _seen(seen) == []

    await second._open_session_and_manifest(_ctx())
    assert b" 407 " in _connect()
    assert len(_seen(seen)) == 1
