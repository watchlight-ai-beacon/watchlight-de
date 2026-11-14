#!/usr/bin/env python3
"""Govern an MCP server in-process — deny a tool call BEFORE it reaches the server.

The Watchlight MCP Runtime PEP (``watchlight-mcp``) sits in front of any MCP
server (spec 2026-07-28, Streamable HTTP) and authorizes every ``tools/call``
with the real Watchlight engine, in-process, before forwarding it. A denied call
never reaches the server.

    pip install watchlight-mcp
    python examples/governed_mcp_server.py

Runs offline — no API key required. This is a self-contained demo: it starts a
tiny stand-in MCP server (which records which tools actually executed), starts
the PEP in front of it, then fires one allowed and one denied ``tools/call`` and
prints the result — proving the denied tool was blocked before it ran. It then
keeps serving so you can send your own requests; press Ctrl-C to stop.

The PEP also emits structured JSON logs to stdout (observability init, policy
decisions); the demo lines below are interleaved with them.

Expected output (demo lines, JSON logs omitted):

    ── Governed MCP server on http://127.0.0.1:9700/mcp ──
       watch decisions live:  watchlight dev --audit .watchlight/audit.jsonl

    ALLOW  get_file_contents  → {'resultType': 'complete', 'content': [{'type': 'text', 'text': 'EXECUTED get_file_contents'}]}
    DENY   delete_repository  → {'code': -32001, 'message': 'not authorized'}

    Tools that actually executed on the server: ['get_file_contents']
    ✓ delete_repository was blocked before it ran.

    PEP still serving. Point your MCP client at http://127.0.0.1:9700/mcp — Ctrl-C to stop.

Point a real MCP client at http://127.0.0.1:9700/mcp instead of the server.
"""

from __future__ import annotations

import http.client
import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import watchlight_mcp

HERE = os.path.dirname(os.path.abspath(__file__))
UPSTREAM_PORT = 3111
PEP_PORT = 9700
EXECUTED: list[str] = []  # ground truth: tools that actually ran on the server


# --- a ~30-line stand-in MCP server (records what actually executed) --------
class _Upstream(BaseHTTPRequestHandler):
    def log_message(self, *_):  # silence
        pass

    def do_POST(self):
        req = json.loads(self.rfile.read(int(self.headers.get("content-length", 0))) or b"{}")
        if req.get("method") == "tools/call":
            tool = (req.get("params") or {}).get("name")
            EXECUTED.append(tool)  # it ran
            result = {"resultType": "complete", "content": [{"type": "text", "text": f"EXECUTED {tool}"}]}
        else:
            result = {"resultType": "complete"}
        body = json.dumps({"jsonrpc": "2.0", "id": req.get("id"), "result": result}).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.end_headers()
        self.wfile.write(body)


def _call(tool: str) -> dict:
    body = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": tool, "arguments": {}}}
    ).encode()
    # A connection to the PEP on the loopback interface, by fixed host and port:
    # it cannot be pointed at another scheme or host, and it does not go through
    # a proxy from the environment. Plain HTTP is fine for a loopback demo; a
    # real deployment should use HTTPS with certificate verification.
    conn = http.client.HTTPConnection("127.0.0.1", PEP_PORT, timeout=10)
    try:
        conn.request(
            "POST",
            "/mcp",
            body=body,
            headers={
                "content-type": "application/json",
                "MCP-Protocol-Version": "2026-07-28",
                "Mcp-Method": "tools/call",
                "Mcp-Name": tool,
                "Watchlight-Agent-Id": "demo-agent",
                "Watchlight-Execution-Id": f"exec_{tool}",
            },
        )
        resp = conn.getresponse()
        payload = resp.read()
        # A governed call answers 200 with a JSON-RPC result or error (a denial
        # is a JSON-RPC error). Anything else means the PEP did not answer the
        # call as expected: stop rather than read it as a result.
        if resp.status != 200 or not resp.getheader("content-type", "").startswith("application/json"):
            raise RuntimeError(f"unexpected response from the PEP: HTTP {resp.status}")
        return json.loads(payload)
    finally:
        conn.close()


def main() -> None:
    # Audit to the SAME file `watchlight dev` tails by default, so every decision
    # this PEP makes shows up live in the console.
    audit_path = os.path.join(HERE, ".watchlight", "audit.jsonl")

    # 1. the MCP server we are putting under governance
    up = ThreadingHTTPServer(("127.0.0.1", UPSTREAM_PORT), _Upstream)
    threading.Thread(target=up.serve_forever, daemon=True).start()

    # 2. the Watchlight PEP in front of it (blocks → run in a thread)
    threading.Thread(
        target=lambda: watchlight_mcp.serve(
            listen_addr=f"127.0.0.1:{PEP_PORT}",
            # Loopback demo server only; a real upstream should be an
            # https:// URL with certificate verification.
            upstream_url=f"http://127.0.0.1:{UPSTREAM_PORT}/mcp",
            upstream_server="github",
            policy_files=[os.path.join(HERE, "mcp.policy.json")],
            audit_path=audit_path,
        ),
        daemon=True,
    ).start()
    time.sleep(1.5)  # let both bind

    print("\n── Governed MCP server on http://127.0.0.1:%d/mcp ──" % PEP_PORT)
    print("   watch decisions live:  watchlight dev --audit %s\n" % audit_path)

    # 3. an ALLOWED tool — policy permits it, so it reaches the server and runs
    allowed = _call("get_file_contents")
    print("ALLOW  get_file_contents  →", allowed.get("result", allowed))

    # 4. a DENIED tool — no policy permits it; blocked BEFORE it reaches the server
    denied = _call("delete_repository")
    print("DENY   delete_repository  →", denied.get("error", denied))

    print("\nTools that actually executed on the server:", EXECUTED)
    assert "delete_repository" not in EXECUTED, "denied tool must never execute"
    print("✓ delete_repository was blocked before it ran.\n")

    print("PEP still serving. Point your MCP client at http://127.0.0.1:%d/mcp — Ctrl-C to stop." % PEP_PORT)
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        print("\nstopped.")


if __name__ == "__main__":
    main()
