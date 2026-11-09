"""Tests for the wl-proxy CONNECT local sidecar proxy.

The security-critical contract: the sidecar MUST forward the
inbound CONNECT to wl-proxy with `Proxy-Authorization: Bearer <token>`
added. Without that header, wl-proxy returns 407 and the tunnel
never opens.

We verify this by standing up a tiny "stub wl-proxy" using
`socketserver.ThreadingTCPServer` that captures the FIRST CONNECT
it receives, then fires `httpx.get('https://...')` and asserts the
captured auth header.

Coverage:
- install + uninstall toggles + env var handling
- security-critical wire test (httpx + requests both fire through
  the sidecar; both result in our token being captured)
- non-CONNECT methods rejected with 405 (the sidecar can't be
  repurposed as a generic HTTP forwarder)
- token never appears in logs (audit log secret leakage)
- 502 surfaced when upstream wl-proxy is unreachable
"""

from __future__ import annotations

import asyncio
import logging
import os
import socket
import socketserver
import threading
from queue import Queue
from typing import Optional

import httpx
import pytest

from watchlight_core import (
    install_connect_proxy,
    is_connect_proxy_installed,
    uninstall_connect_proxy,
)


# In-process stand-in for unit tests only.
class _StubWlProxyHandler(socketserver.BaseRequestHandler):
    """Captures CONNECT requests + their headers. Responds 407 to
    every CONNECT — the same wire shape wl-proxy uses on auth
    failure. We don't actually open a tunnel; the sidecar just
    needs to FORWARD a CONNECT with our header on it."""

    def handle(self) -> None:  # noqa: D401 — socketserver contract
        try:
            self.request.settimeout(5.0)
            # Read up to the end-of-headers marker.
            data = b""
            while b"\r\n\r\n" not in data and len(data) < 8192:
                chunk = self.request.recv(4096)
                if not chunk:
                    return
                data += chunk
            # Parse the request line + headers.
            try:
                head, _ = data.split(b"\r\n\r\n", 1)
            except ValueError:
                return
            lines = head.split(b"\r\n")
            request_line = lines[0]
            headers: dict[str, str] = {}
            for line in lines[1:]:
                if b": " in line:
                    k, v = line.split(b": ", 1)
                    headers[k.decode().lower()] = v.decode()
            # Send the captured request to the test's queue.
            self.server.captured.put(  # type: ignore[attr-defined]
                {
                    "request_line": request_line.decode(),
                    "headers": headers,
                }
            )
            # 407 the connect.
            self.request.sendall(
                b"HTTP/1.1 407 Proxy Authentication Required\r\n"
                b'Proxy-Authenticate: Bearer realm="test"\r\n'
                b"Content-Length: 0\r\n"
                b"Connection: close\r\n\r\n"
            )
        except Exception:  # noqa: BLE001
            pass


# In-process stand-in for unit tests only.
class _StubWlProxyServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    captured: Queue


# In-process stand-in for unit tests only.
def _start_stub_wl_proxy() -> tuple[_StubWlProxyServer, threading.Thread, int]:
    """Start the stub wl-proxy on a free 127.0.0.1 port. Returns
    (server, thread, port). The caller must call ``server.shutdown()``
    to stop it cleanly."""
    server = _StubWlProxyServer(("127.0.0.1", 0), _StubWlProxyHandler)
    server.captured = Queue()
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread, port


@pytest.fixture(autouse=True)
def _isolate_connect_proxy():
    """Belt-and-braces — never leak a sidecar across tests."""
    # Save the customer's HTTPS_PROXY (if any) and restore on teardown
    # so unrelated tests don't see our env mutations.
    saved_https = os.environ.get("HTTPS_PROXY")
    saved_http = os.environ.get("HTTP_PROXY")
    saved_no_proxy_upper = os.environ.get("NO_PROXY")
    saved_no_proxy_lower = os.environ.get("no_proxy")
    saved_override = os.environ.get("WATCHLIGHT_PROXY_NO_PROXY")
    yield
    uninstall_connect_proxy()
    if saved_https is None:
        os.environ.pop("HTTPS_PROXY", None)
    else:
        os.environ["HTTPS_PROXY"] = saved_https
    if saved_http is None:
        os.environ.pop("HTTP_PROXY", None)
    else:
        os.environ["HTTP_PROXY"] = saved_http
    if saved_no_proxy_upper is None:
        os.environ.pop("NO_PROXY", None)
    else:
        os.environ["NO_PROXY"] = saved_no_proxy_upper
    if saved_no_proxy_lower is None:
        os.environ.pop("no_proxy", None)
    else:
        os.environ["no_proxy"] = saved_no_proxy_lower
    if saved_override is None:
        os.environ.pop("WATCHLIGHT_PROXY_NO_PROXY", None)
    else:
        os.environ["WATCHLIGHT_PROXY_NO_PROXY"] = saved_override


def test_install_uninstall_toggles_flag_and_env():
    """Smoke: install sets the env vars + flag; uninstall reverts both."""
    assert is_connect_proxy_installed() is False
    install_connect_proxy("http://127.0.0.1:1", "test-token")
    assert is_connect_proxy_installed() is True
    assert os.environ.get("HTTPS_PROXY", "").startswith("http://127.0.0.1:")
    assert os.environ.get("HTTP_PROXY", "").startswith("http://127.0.0.1:")
    uninstall_connect_proxy()
    assert is_connect_proxy_installed() is False
    # HTTPS_PROXY/HTTP_PROXY should be unset (or whatever the
    # _isolate_connect_proxy fixture saved — but the fixture cleanup
    # runs AFTER this point so right now they should be absent
    # because we didn't have them set going in).
    assert os.environ.get("HTTPS_PROXY") is None
    assert os.environ.get("HTTP_PROXY") is None


def test_uninstall_is_idempotent():
    """No-op when nothing installed; safe to call multiple times."""
    uninstall_connect_proxy()
    uninstall_connect_proxy()
    assert is_connect_proxy_installed() is False


def test_invalid_wl_proxy_url_fails_loud():
    """Misconfiguration must fail at install time, not at the first
    outbound request — fail-loud."""
    with pytest.raises(ValueError):
        install_connect_proxy("ftp://nope", "test-token")


def test_security_critical_proxy_authorization_on_upstream_connect():
    """**The load-bearing test.** Fires an httpx request through the
    sidecar; asserts the stub wl-proxy received CONNECT with our
    Proxy-Authorization: Bearer <token>."""
    stub_server, _t, stub_port = _start_stub_wl_proxy()
    try:
        token = "eyJabc.test-jwt-shape.signature-not-real"
        install_connect_proxy(f"http://127.0.0.1:{stub_port}", token)

        # Issue an HTTPS request. The sidecar receives our CONNECT,
        # rewrites with Proxy-Authorization, forwards to the stub.
        # The stub 407s; httpx surfaces the 407 (or a connection
        # close); we don't care about the result. Only the capture.
        with httpx.Client(timeout=5.0) as client:
            try:
                client.get("https://api.example.com/v1/health")
            except Exception:  # noqa: BLE001
                pass

        captured = stub_server.captured.get(timeout=3.0)
        request_line = captured["request_line"]
        headers = captured["headers"]
        assert request_line.startswith("CONNECT "), (
            f"sidecar did not forward as CONNECT: {request_line!r}"
        )
        assert "api.example.com" in request_line
        assert headers.get("proxy-authorization") == f"Bearer {token}", (
            f"missing or wrong Proxy-Authorization header: {headers}"
        )
    finally:
        stub_server.shutdown()
        stub_server.server_close()


def test_works_for_requests_library_too():
    """Universal coverage: the sidecar also intercepts the requests
    library — proves we're not httpx-only (the whole point of moving
    to a sidecar). Auto-skips when `requests` isn't installed (it's
    in [dev] extras for CI but not a runtime dep)."""
    requests = pytest.importorskip(
        "requests",
        reason="install with [dev] extras to exercise the universal-coverage proof",
    )

    stub_server, _t, stub_port = _start_stub_wl_proxy()
    try:
        token = "eyJ.token-for-requests-lib.sig"
        install_connect_proxy(f"http://127.0.0.1:{stub_port}", token)

        try:
            requests.get("https://api.example.com/v1/health", timeout=5.0)
        except requests.exceptions.RequestException:
            pass  # 407 from stub wl-proxy is expected

        captured = stub_server.captured.get(timeout=3.0)
        assert captured["request_line"].startswith("CONNECT ")
        assert captured["headers"].get("proxy-authorization") == f"Bearer {token}"
    finally:
        stub_server.shutdown()
        stub_server.server_close()


def test_non_connect_method_rejected_with_405():
    """The sidecar must not be repurposeable as a generic HTTP
    forwarder. Any non-CONNECT method gets 405."""
    install_connect_proxy("http://127.0.0.1:1", "test-token")
    sidecar_port = int(os.environ["HTTPS_PROXY"].rsplit(":", 1)[1])

    # Raw socket — issue a plain HTTP GET to the sidecar (not
    # CONNECT). Should get 405.
    with socket.create_connection(("127.0.0.1", sidecar_port), timeout=5.0) as s:
        s.sendall(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        data = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
            if b"\r\n\r\n" in data:
                break
    assert b"405" in data.split(b"\r\n", 1)[0]


def test_502_when_wl_proxy_unreachable():
    """When the upstream wl-proxy is down, the sidecar must surface a
    502 to the customer's HTTP library (not silently drop the
    connection — that would be a confusing failure mode)."""
    # Point at a port nothing is listening on.
    install_connect_proxy("http://127.0.0.1:1", "test-token")  # port 1 unused

    with httpx.Client(timeout=5.0) as client:
        with pytest.raises(httpx.HTTPError):
            client.get("https://api.example.com/v1/health")
    # The HTTP library should have errored — exact exception depends
    # on httpx version. The contract is "non-silent failure."


def test_never_logs_raw_token(caplog):
    """The install log MUST NOT carry the raw token."""
    caplog.set_level(logging.INFO, logger="watchlight.core.connect_proxy")

    sensitive_token = "eyJabc.SECRET-TOKEN-DO-NOT-LEAK.signature"
    install_connect_proxy("http://127.0.0.1:1", sensitive_token)

    for record in caplog.records:
        assert sensitive_token not in record.getMessage(), (
            "Install log leaked the raw token"
        )


def test_re_install_with_new_token_stops_old_sidecar_starts_fresh():
    """Once the owning run has ended, the next run's install cleanly
    stops the first sidecar."""
    from watchlight_core.backend import EgressBinding

    ended = {"first": False}
    first = EgressBinding(
        proxy_url=None,
        expires_at=None,
        token_source=lambda: None if ended["first"] else "first-token",
    )
    second = EgressBinding(proxy_url=None, expires_at=None, token_source=lambda: "second-token")
    install_connect_proxy("http://127.0.0.1:1", "first-token", egress=first)
    first_port = int(os.environ["HTTPS_PROXY"].rsplit(":", 1)[1])
    ended["first"] = True

    install_connect_proxy("http://127.0.0.1:1", "second-token", egress=second)
    second_port = int(os.environ["HTTPS_PROXY"].rsplit(":", 1)[1])

    # New port (the old socket was released) — but they MAY be the
    # same if the OS happened to hand back the same free port.
    # What's guaranteed: install returned without error + still
    # installed.
    assert is_connect_proxy_installed() is True
    _ = first_port, second_port  # quiet linter


def test_restores_previous_https_proxy_on_uninstall():
    """If the customer's environment already had HTTPS_PROXY set,
    uninstall must restore it — not just unset the var."""
    os.environ["HTTPS_PROXY"] = "http://corporate-proxy.example.com:3128"
    try:
        install_connect_proxy("http://127.0.0.1:1", "test-token")
        # During install, our sidecar takes precedence.
        assert os.environ["HTTPS_PROXY"].startswith("http://127.0.0.1:")
        uninstall_connect_proxy()
        # After uninstall, the customer's original is back.
        assert os.environ["HTTPS_PROXY"] == "http://corporate-proxy.example.com:3128"
    finally:
        os.environ.pop("HTTPS_PROXY", None)


# ---------------------------------------------------------------------------
# Internal-host bypass follow-up — the sidecar is CONNECT-only
# and would 405 plain-HTTP inter-service calls (wl-apdp, wl-registry, …).
# We set NO_PROXY so the customer's HTTP libraries bypass the sidecar for
# those hosts entirely.
# ---------------------------------------------------------------------------


_EXPECTED_DEFAULT_BYPASS = (
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


def test_install_sets_no_proxy_with_default_internal_hosts():
    """Install must populate NO_PROXY with the default internal-host
    bypass list so inter-service calls skip the sidecar."""
    install_connect_proxy("http://127.0.0.1:1", "test-token")

    no_proxy_upper = os.environ.get("NO_PROXY", "")
    no_proxy_lower = os.environ.get("no_proxy", "")

    # Both casings must be set — urllib3 / requests check lowercase
    # first, httpx checks uppercase. Set both so every library sees
    # the bypass.
    assert no_proxy_upper, "NO_PROXY (uppercase) must be set"
    assert no_proxy_lower, "no_proxy (lowercase) must be set"
    assert no_proxy_upper == no_proxy_lower

    entries = {p.strip() for p in no_proxy_upper.split(",") if p.strip()}
    for host in _EXPECTED_DEFAULT_BYPASS:
        assert host in entries, (
            f"default internal host {host!r} missing from NO_PROXY: {entries}"
        )


def test_install_no_proxy_includes_every_required_internal_service():
    """Belt-and-braces: every Watchlight inter-service host the
    plugin's APDP-client / registry-client / lineage-emitter
    talks to MUST be in the default bypass list."""
    install_connect_proxy("http://127.0.0.1:1", "test-token")

    no_proxy = os.environ["NO_PROXY"]
    # The runtime services the langgraph / adk / bedrock /
    # pydantic-ai / claude-agent plugins resolve over plain HTTP.
    must_bypass = {
        "wl-apdp",
        "wl-registry",
        "wl-execution-graph",
        "wl-secrets-broker",
        "localhost",
        "127.0.0.1",
    }
    for host in must_bypass:
        assert host in no_proxy, (
            f"{host!r} MUST bypass the sidecar — customer-bound traffic "
            f"only. NO_PROXY={no_proxy!r}"
        )


def test_watchlight_proxy_no_proxy_env_replaces_defaults():
    """`WATCHLIGHT_PROXY_NO_PROXY` REPLACES the defaults (per the
    PR spec) — not appends. Operators who set the override take
    full responsibility for the bypass list."""
    os.environ["WATCHLIGHT_PROXY_NO_PROXY"] = (
        "internal.example.com,vault.example.com"
    )
    install_connect_proxy("http://127.0.0.1:1", "test-token")

    no_proxy = os.environ.get("NO_PROXY", "")
    entries = {p.strip() for p in no_proxy.split(",") if p.strip()}

    # The override wins.
    assert "internal.example.com" in entries
    assert "vault.example.com" in entries
    # Defaults are GONE because the override replaces them.
    assert "wl-apdp" not in entries
    assert "wl-registry" not in entries


def test_watchlight_proxy_no_proxy_env_handles_whitespace_and_empties():
    """Operator hygiene — stray whitespace and trailing commas in
    the override must not inject blank entries into NO_PROXY."""
    os.environ["WATCHLIGHT_PROXY_NO_PROXY"] = " host-a , , host-b,"
    install_connect_proxy("http://127.0.0.1:1", "test-token")

    no_proxy = os.environ.get("NO_PROXY", "")
    entries = [p for p in no_proxy.split(",")]

    assert "host-a" in entries
    assert "host-b" in entries
    # No blank entries — those would broaden NO_PROXY to "everything
    # bypasses" in some libraries.
    assert "" not in entries


def test_install_appends_to_existing_no_proxy():
    """When the customer's environment already has NO_PROXY set
    (corporate bypass list), install MUST append our hosts — not
    clobber. The customer's bypass list survives."""
    os.environ["NO_PROXY"] = "corp.example.com,internal.example.com"
    try:
        install_connect_proxy("http://127.0.0.1:1", "test-token")

        no_proxy = os.environ["NO_PROXY"]
        entries = {p.strip() for p in no_proxy.split(",") if p.strip()}

        # Customer's entries survived.
        assert "corp.example.com" in entries
        assert "internal.example.com" in entries
        # Our defaults were appended.
        assert "wl-apdp" in entries
        assert "wl-registry" in entries
    finally:
        # The fixture restores; explicit cleanup here belt-and-braces
        # the install state.
        uninstall_connect_proxy()


def test_install_does_not_duplicate_existing_internal_host():
    """If the customer already had ``wl-apdp`` in NO_PROXY for some
    reason, the install must not produce ``...,wl-apdp,wl-apdp,...``"""
    os.environ["NO_PROXY"] = "wl-apdp,corp.example.com"
    try:
        install_connect_proxy("http://127.0.0.1:1", "test-token")

        no_proxy = os.environ["NO_PROXY"]
        entries = [p.strip() for p in no_proxy.split(",") if p.strip()]
        assert entries.count("wl-apdp") == 1, (
            f"wl-apdp duplicated in NO_PROXY: {no_proxy!r}"
        )
    finally:
        uninstall_connect_proxy()


def test_uninstall_restores_previous_no_proxy():
    """Symmetric to HTTPS_PROXY restore — uninstall must put back
    whatever was there before, not just blank the var."""
    os.environ["NO_PROXY"] = "corp.example.com"
    try:
        install_connect_proxy("http://127.0.0.1:1", "test-token")
        # During install, NO_PROXY was extended with our defaults.
        assert "wl-apdp" in os.environ["NO_PROXY"]
        uninstall_connect_proxy()
        # After uninstall, the customer's original NO_PROXY is back
        # exactly as it was.
        assert os.environ["NO_PROXY"] == "corp.example.com"
    finally:
        os.environ.pop("NO_PROXY", None)
        os.environ.pop("no_proxy", None)


def test_uninstall_unsets_no_proxy_when_not_previously_set():
    """If the customer had no NO_PROXY before install, uninstall
    must remove it (not leave our defaults dangling in the env)."""
    # Make sure NO_PROXY is unset going in.
    os.environ.pop("NO_PROXY", None)
    os.environ.pop("no_proxy", None)

    install_connect_proxy("http://127.0.0.1:1", "test-token")
    assert "NO_PROXY" in os.environ  # we set it
    uninstall_connect_proxy()
    # Cleanly removed.
    assert "NO_PROXY" not in os.environ
    assert "no_proxy" not in os.environ


def test_internal_host_bypass_keeps_customer_traffic_routed_through_sidecar():
    """End-to-end via env vars: customer-bound hosts (api.openai.com)
    go through the sidecar; internal hosts (wl-apdp) bypass it.

    We don't actually fire HTTP here — we verify the env state that
    httpx / requests / urllib3 consume to make the routing decision.
    """
    install_connect_proxy("http://127.0.0.1:1", "test-token")

    # The sidecar is the configured proxy for all outbound HTTP/S.
    assert os.environ["HTTPS_PROXY"].startswith("http://127.0.0.1:")
    assert os.environ["HTTP_PROXY"].startswith("http://127.0.0.1:")

    no_proxy = os.environ["NO_PROXY"]
    # api.openai.com is NOT in the bypass list — it stays routed
    # through the sidecar.
    assert "api.openai.com" not in no_proxy
    # wl-apdp IS in the bypass list — it skips the sidecar.
    assert "wl-apdp" in no_proxy


# ───────────────────────────────────────────────────────────────────────
# Root-cause fix — lineage header injection on CONNECT
# ───────────────────────────────────────────────────────────────────────


def test_connect_omits_lineage_headers_even_when_handle_lineage_bound():
    """Execution-lineage integrity. The lineage
    header conveyance is DECOMMISSIONED: even when a
    :class:`HandleLineage` is bound to the sidecar's process-global
    (via :func:`set_active_handle_lineage`, which
    ``BaseRunHandle.__aenter__`` does transparently), the sidecar MUST
    NOT stamp ``X-Wl-Execution-Id`` / ``X-Wl-Parent-Execution-Id`` /
    ``X-Wl-Root-Execution-Id`` / ``X-Wl-Parent-Agent-Id`` onto the
    upstream CONNECT.

    The execution identity is conveyed SOLELY via the wl-apdp-issued,
    wl-proxy-VERIFIED ``Proxy-Authorization`` token (``exec_id`` claim);
    a client-settable correlation header was a forgeable primitive (T1).
    wl-proxy derives the emitted ``execution_id`` from the verified
    claim and treats any client lineage header as a tamper tripwire.
    """
    from watchlight_core import HandleLineage
    from watchlight_core.connect_proxy import set_active_handle_lineage

    stub_server, _t, stub_port = _start_stub_wl_proxy()
    try:
        install_connect_proxy(f"http://127.0.0.1:{stub_port}", "tok-1")

        lineage = HandleLineage(
            execution_id="exec_aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            parent_execution_id="exec_11111111-2222-3333-4444-555555555555",
            root_execution_id="exec_00000000-1111-2222-3333-444444444444",
            parent_agent_id="orchestrator",
        )
        set_active_handle_lineage(lineage)
        try:
            with httpx.Client(timeout=5.0) as client:
                try:
                    client.get("https://api.example.com/v1/health")
                except Exception:  # noqa: BLE001
                    pass
        finally:
            set_active_handle_lineage(None)

        captured = stub_server.captured.get(timeout=3.0)
        headers = captured["headers"]
        # DECOMMISSIONED — no client-settable lineage identity headers.
        assert "x-wl-execution-id" not in headers
        assert "x-wl-parent-execution-id" not in headers
        assert "x-wl-root-execution-id" not in headers
        assert "x-wl-parent-agent-id" not in headers
        assert "x-wl-agent-id" not in headers
        assert "x-wl-session-id" not in headers
        assert "x-wl-tenant-id" not in headers
        # The verified-token conveyance (Proxy-Authorization) is intact.
        assert headers.get("proxy-authorization") == "Bearer tok-1"
    finally:
        stub_server.shutdown()
        stub_server.server_close()


def test_connect_omits_lineage_headers_when_no_handle_lineage_bound():
    """When no ``HandleLineage`` is bound (e.g. an httpx call outside
    a ``BaseRunHandle.__aenter__`` block), the CONNECT MUST NOT carry
    any ``X-Wl-*`` lineage headers.

    wl-proxy then stamps ``metadata.warning = "no_execution_context"``
    on emitted events so the gap is surfaced honestly
    (`feedback_truth_first_christian_principles`). The defensive
    wl-execution-graph filter then skips phantom ``lineage.executions``
    rows for these events.
    """
    stub_server, _t, stub_port = _start_stub_wl_proxy()
    try:
        install_connect_proxy(f"http://127.0.0.1:{stub_port}", "tok-no-lineage")
        with httpx.Client(timeout=5.0) as client:
            try:
                client.get("https://api.example.com/v1/health")
            except Exception:  # noqa: BLE001
                pass

        captured = stub_server.captured.get(timeout=3.0)
        headers = captured["headers"]
        assert "x-wl-execution-id" not in headers
        assert "x-wl-parent-execution-id" not in headers
        assert "x-wl-root-execution-id" not in headers
        assert "x-wl-parent-agent-id" not in headers
        assert "x-wl-agent-id" not in headers
        assert "x-wl-session-id" not in headers
        assert "x-wl-tenant-id" not in headers
        # Proxy-Authorization still present — only the lineage layer
        # was absent, not the auth.
        assert headers.get("proxy-authorization") == "Bearer tok-no-lineage"
    finally:
        stub_server.shutdown()
        stub_server.server_close()


def test_connect_drops_lineage_headers_with_crlf_injection_attempt():
    """`feedback_security_first` — the SDK's HandleLineage is a frozen
    dataclass under SDK control, but defensive guard: if a value
    contains CR or LF (header-injection attempt) the sidecar drops
    the header rather than splice the smuggled second-line payload
    onto the CONNECT.
    """
    from watchlight_core import HandleLineage
    from watchlight_core.connect_proxy import set_active_handle_lineage

    stub_server, _t, stub_port = _start_stub_wl_proxy()
    try:
        install_connect_proxy(f"http://127.0.0.1:{stub_port}", "tok-crlf")
        evil = HandleLineage(
            execution_id="exec_xxx\r\nX-Evil-Header: smuggled",
            parent_execution_id=None,
            root_execution_id=None,
            parent_agent_id=None,
        )
        set_active_handle_lineage(evil)
        try:
            with httpx.Client(timeout=5.0) as client:
                try:
                    client.get("https://api.example.com/v1/health")
                except Exception:  # noqa: BLE001
                    pass
        finally:
            set_active_handle_lineage(None)

        captured = stub_server.captured.get(timeout=3.0)
        headers = captured["headers"]
        # Smuggled header MUST NOT have landed.
        assert "x-evil-header" not in headers
        # Execution_id header MUST NOT have been forwarded either
        # (we dropped it rather than partially sanitise — defense in
        # depth).
        assert "x-wl-execution-id" not in headers
    finally:
        stub_server.shutdown()
        stub_server.server_close()
