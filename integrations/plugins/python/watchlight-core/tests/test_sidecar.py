"""Tests for the wl-sidecar launcher.

We verify the launcher spawns the binary, hands the SECRET over on stdin
(NEVER argv), reads the announced port, sets HTTP(S)_PROXY + NO_PROXY,
and restores the customer's env on uninstall. A tiny stub `wl-sidecar`
(a Python script) stands in for the real Rust binary.
"""

from __future__ import annotations

import os

import pytest

from watchlight_core.backend import EgressBinding
from watchlight_core.errors import GovernanceUnavailable, SidecarRunActive
from watchlight_core.sidecar import (
    _locate_binary,
    build_sidecar_argv,
    install_sidecar,
    is_sidecar_installed,
    uninstall_sidecar,
)

# A stand-in for the Rust binary: read the token from stdin (first line),
# record token + argv to STUB_TOKEN_SINK, announce a port, then idle.
# In-process stand-in for unit tests only.
STUB_SIDECAR_SCRIPT = """#!/usr/bin/env python3
import sys, os, time
token = sys.stdin.readline().strip()
with open(os.environ["STUB_TOKEN_SINK"], "w") as f:
    f.write(token + "\\n")
    f.write("ARGV:" + " ".join(sys.argv[1:]) + "\\n")
print("127.0.0.1:54321", flush=True)
time.sleep(30)
"""


@pytest.fixture(autouse=True)
def _isolate_env():
    saved = {
        k: os.environ.get(k)
        for k in ("HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY", "no_proxy", "STUB_TOKEN_SINK")
    }
    yield
    uninstall_sidecar()
    for k, v in saved.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v


# ── argv construction (pure) ──────────────────────────────────────────


def test_build_argv_minimal():
    argv = build_sidecar_argv("wl-sidecar", "https://p:8443")
    assert argv == [
        "wl-sidecar",
        "--wl-proxy-url",
        "https://p:8443",
        "--listen",
        "127.0.0.1:0",
    ]


def test_build_argv_all_flags():
    argv = build_sidecar_argv(
        "wl-sidecar",
        "https://p:8443",
        governed_proxy_hosts=["a", "b"],
        ca_cert="/ca",
        client_cert="/c",
        client_key="/k",
    )
    joined = " ".join(argv)
    assert "--governed-hosts a,b" in joined
    assert "--ca-cert /ca" in joined
    assert "--client-cert /c" in joined
    assert "--client-key /k" in joined


def test_build_argv_gateway_from_kwarg_and_env(monkeypatch):
    monkeypatch.delenv("WATCHLIGHT_GATEWAY_URL", raising=False)
    argv = build_sidecar_argv("wl-sidecar", "https://p:3128")
    assert "--gateway-url" not in argv, "no gateway unless configured"

    argv = build_sidecar_argv("wl-sidecar", "https://p:3128", gateway_url="https://p:8443")
    assert "--gateway-url https://p:8443" in " ".join(argv)

    # Env fallback keeps every framework plugin zero-touch.
    monkeypatch.setenv("WATCHLIGHT_GATEWAY_URL", "https://p:8443")
    argv = build_sidecar_argv("wl-sidecar", "https://p:3128")
    assert "--gateway-url https://p:8443" in " ".join(argv)


# ── binary location ───────────────────────────────────────────────────


def test_locate_binary_from_env(tmp_path, monkeypatch):
    b = tmp_path / "wl-sidecar"
    b.write_text("x")
    b.chmod(0o755)
    monkeypatch.setenv("WL_SIDECAR_BINARY", str(b))
    assert _locate_binary(None) == str(b)


def test_locate_binary_missing_raises():
    with pytest.raises(FileNotFoundError):
        _locate_binary("/nonexistent/path/wl-sidecar")


# ── end-to-end launcher (stub binary) ─────────────────────────────────


# In-process stand-in for unit tests only.
def _write_stub(tmp_path) -> str:
    stub = tmp_path / "stub-sidecar"
    stub.write_text(STUB_SIDECAR_SCRIPT)
    stub.chmod(0o755)
    return str(stub)


def test_install_hands_token_on_stdin_not_argv_and_sets_env(tmp_path):
    sink = tmp_path / "token_sink"
    os.environ["STUB_TOKEN_SINK"] = str(sink)
    stub = _write_stub(tmp_path)

    install_sidecar(
        "https://wl-proxy:8443",
        "SECRET-TOKEN-123",
        governed_proxy_hosts=["proxy-mcp-web"],
        ca_cert="/ca.pem",
        binary_path=stub,
    )

    assert is_sidecar_installed()
    assert os.environ["HTTP_PROXY"] == "http://127.0.0.1:54321"
    assert os.environ["HTTPS_PROXY"] == "http://127.0.0.1:54321"
    # Internal-host bypass wired.
    assert "wl-apdp" in os.environ["NO_PROXY"]

    recorded = sink.read_text()
    # The SECRET arrived on stdin …
    assert "SECRET-TOKEN-123" in recorded.splitlines()[0]
    # … and is ABSENT from argv (never ps-readable).
    argv_line = next(line for line in recorded.splitlines() if line.startswith("ARGV:"))
    assert "SECRET-TOKEN-123" not in argv_line
    # Non-secret config IS on argv.
    assert "--wl-proxy-url https://wl-proxy:8443" in argv_line
    assert "--governed-hosts proxy-mcp-web" in argv_line
    assert "--ca-cert /ca.pem" in argv_line


def test_uninstall_restores_env_and_stops_process(tmp_path):
    os.environ["STUB_TOKEN_SINK"] = str(tmp_path / "sink")
    stub = _write_stub(tmp_path)
    # No pre-existing HTTP_PROXY → should be absent after uninstall.
    os.environ.pop("HTTP_PROXY", None)

    install_sidecar("https://wl-proxy:8443", "tok", binary_path=stub)
    proc = __import__("watchlight_core.sidecar", fromlist=["_state"])._state.proc  # type: ignore
    assert proc.poll() is None  # running

    uninstall_sidecar()
    assert not is_sidecar_installed()
    assert os.environ.get("HTTP_PROXY") is None
    # process torn down
    assert proc.wait(timeout=5) is not None


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


def _proc():
    return __import__("watchlight_core.sidecar", fromlist=["_state"])._state.proc  # type: ignore


def test_a_second_run_is_refused_while_the_first_owns_the_sidecar(tmp_path):
    stub = _write_stub(tmp_path)
    first_sink = tmp_path / "sink-a"
    os.environ["STUB_TOKEN_SINK"] = str(first_sink)
    run_a, run_b = _Run("TOKEN-A"), _Run("TOKEN-B")
    install_sidecar("https://wl-proxy:8443", "TOKEN-A", binary_path=stub, egress=run_a.egress)
    first = _proc()
    env_before = {k: os.environ.get(k) for k in ("HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY", "no_proxy")}

    second_sink = tmp_path / "sink-b"
    os.environ["STUB_TOKEN_SINK"] = str(second_sink)
    with pytest.raises(SidecarRunActive) as refused:
        install_sidecar("https://wl-proxy:8443", "TOKEN-B", binary_path=stub, egress=run_b.egress)

    assert isinstance(refused.value, GovernanceUnavailable)
    assert "TOKEN" not in str(refused.value)
    # No sidecar was started for the second run, so its token went nowhere.
    assert not second_sink.exists()
    # The first run's egress is untouched: same process, same env, and the
    # only token its sidecar ever held is the first run's.
    assert _proc() is first and first.poll() is None
    assert {k: os.environ.get(k) for k in env_before} == env_before
    assert first_sink.read_text().splitlines()[0] == "TOKEN-A"


def test_after_the_owner_ends_the_next_run_replaces_the_sidecar(tmp_path):
    stub = _write_stub(tmp_path)
    os.environ["STUB_TOKEN_SINK"] = str(tmp_path / "sink-a")
    run_a, run_b = _Run("TOKEN-A"), _Run("TOKEN-B")
    install_sidecar("https://wl-proxy:8443", "TOKEN-A", binary_path=stub, egress=run_a.egress)
    first = _proc()
    run_a.ended = True

    second_sink = tmp_path / "sink-b"
    os.environ["STUB_TOKEN_SINK"] = str(second_sink)
    install_sidecar("https://wl-proxy:8443", "TOKEN-B", binary_path=stub, egress=run_b.egress)

    assert first.wait(timeout=5) is not None
    assert _proc() is not first
    assert second_sink.read_text().splitlines()[0] == "TOKEN-B"


def test_the_owning_run_may_install_again(tmp_path):
    stub = _write_stub(tmp_path)
    os.environ["STUB_TOKEN_SINK"] = str(tmp_path / "sink")
    run_a = _Run("TOKEN-A")
    install_sidecar("https://wl-proxy:8443", "TOKEN-A", binary_path=stub, egress=run_a.egress)
    first = _proc()
    install_sidecar("https://wl-proxy:8443", "TOKEN-A", binary_path=stub, egress=run_a.egress)
    assert first.wait(timeout=5) is not None
    assert is_sidecar_installed()


def test_a_sidecar_without_an_owner_is_held_until_uninstall(tmp_path):
    os.environ["STUB_TOKEN_SINK"] = str(tmp_path / "sink")
    stub = _write_stub(tmp_path)
    install_sidecar("https://wl-proxy:8443", "tok-a", binary_path=stub)
    first = _proc()
    with pytest.raises(SidecarRunActive):
        install_sidecar("https://wl-proxy:8443", "tok-b", binary_path=stub, egress=_Run("tok-b").egress)
    with pytest.raises(SidecarRunActive):
        install_sidecar("https://wl-proxy:8443", "tok-b", binary_path=stub)
    assert _proc() is first and first.poll() is None

    uninstall_sidecar()
    install_sidecar("https://wl-proxy:8443", "tok-b", binary_path=stub)
    assert is_sidecar_installed()


def test_an_owner_that_cannot_be_read_still_holds_the_sidecar(tmp_path):
    os.environ["STUB_TOKEN_SINK"] = str(tmp_path / "sink")
    stub = _write_stub(tmp_path)

    def unreadable() -> str:
        raise RuntimeError("backend gone")

    owner = EgressBinding(proxy_url=None, expires_at=None, token_source=unreadable)
    install_sidecar("https://wl-proxy:8443", "tok-a", binary_path=stub, egress=owner)
    first = _proc()
    with pytest.raises(SidecarRunActive):
        install_sidecar("https://wl-proxy:8443", "tok-b", binary_path=stub, egress=_Run("tok-b").egress)
    assert _proc() is first and first.poll() is None


# A stand-in that really listens on the port it announces (tests only), so
# a test can show traffic failing once the sidecar is stopped.
LISTENING_STUB_SCRIPT = """#!/usr/bin/env python3
import os, socket, sys
token = sys.stdin.readline().strip()
with open(os.environ["STUB_TOKEN_SINK"], "a") as f:
    f.write(token + "\\n")
srv = socket.socket()
srv.bind(("127.0.0.1", 0))
srv.listen(8)
print("127.0.0.1:%d" % srv.getsockname()[1], flush=True)
while True:
    conn, _ = srv.accept()
    conn.close()
"""


def test_once_the_owner_ends_the_sidecar_stops_and_traffic_fails_never_direct(tmp_path, monkeypatch):
    import socket

    from watchlight_core import sidecar as sc

    monkeypatch.setattr(sc, "_OWNER_POLL_SECONDS", 0.05)
    stub = tmp_path / "listening-sidecar"
    stub.write_text(LISTENING_STUB_SCRIPT)
    stub.chmod(0o755)
    sink = tmp_path / "tokens"
    os.environ["STUB_TOKEN_SINK"] = str(sink)
    os.environ.pop("HTTPS_PROXY", None)
    run_a = _Run("TOKEN-A")
    install_sidecar("https://wl-proxy:8443", "TOKEN-A", binary_path=str(stub), egress=run_a.egress)
    proc = _proc()
    proxy = os.environ["HTTPS_PROXY"]
    port = int(proxy.rsplit(":", 1)[1])
    socket.create_connection(("127.0.0.1", port), timeout=5.0).close()

    run_a.ended = True

    assert proc.wait(timeout=5) is not None
    # The env still points at the stopped sidecar: traffic fails to
    # connect rather than going direct, and no sidecar holds the token.
    assert os.environ["HTTPS_PROXY"] == proxy
    with pytest.raises(OSError):
        socket.create_connection(("127.0.0.1", port), timeout=2.0).close()
    assert sink.read_text().splitlines() == ["TOKEN-A"]
    assert is_sidecar_installed()

    # Only uninstall restores the customer's env.
    uninstall_sidecar()
    assert os.environ.get("HTTPS_PROXY") is None


def test_the_next_run_replaces_a_sidecar_the_watcher_stopped(tmp_path, monkeypatch):
    from watchlight_core import sidecar as sc

    monkeypatch.setattr(sc, "_OWNER_POLL_SECONDS", 0.05)
    stub = tmp_path / "listening-sidecar"
    stub.write_text(LISTENING_STUB_SCRIPT)
    stub.chmod(0o755)
    sink = tmp_path / "tokens"
    os.environ["STUB_TOKEN_SINK"] = str(sink)
    run_a, run_b = _Run("TOKEN-A"), _Run("TOKEN-B")
    install_sidecar("https://wl-proxy:8443", "TOKEN-A", binary_path=str(stub), egress=run_a.egress)
    first = _proc()
    run_a.ended = True
    assert first.wait(timeout=5) is not None

    install_sidecar("https://wl-proxy:8443", "TOKEN-B", binary_path=str(stub), egress=run_b.egress)

    assert _proc() is not first and _proc().poll() is None
    assert sink.read_text().splitlines() == ["TOKEN-A", "TOKEN-B"]
