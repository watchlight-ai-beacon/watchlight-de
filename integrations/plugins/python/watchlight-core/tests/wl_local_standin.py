"""A stand-in ``wl-local/1`` connector for the SidecarBackend tests.

It follows ``contracts/wl-local-1/README.md``: framing and limits, the Unix
and loopback-TCP handshakes (the mutual HMAC proofs), run ownership per
connection, the ended-run window, ``kill`` pushes, and "a lost connection
kills its runs". It decides nothing real.

Conventions (mirroring the Rust core's stand-in backend):

* ``authorize`` with principal ``deny`` answers a Deny decision, ``busy``
  ``unavailable``, ``boom`` ``internal``, ``sleep:<ms>`` waits and allows,
  ``echo`` echoes the request's params in the decision;
* ``spawn_subagent`` with ``{"overreach": true}`` is ``denied``
  (``scope_attenuation_violation``), ``{"invalidated": true}`` is
  ``run_ended`` (``run_handle_invalidated``);
* ``resolve_agent`` for ``missing`` answers ``{"agent": null}``;
* ``create_session`` for an agent id starting with ``slow`` waits 400 ms.

Run as a script (``python wl_local_standin.py <dir>``) it serves loopback
TCP and prints its address and secret on stdout, as a launched connector
does.

Every client frame is checked against the protocol; a violation is recorded
in ``violations`` (and answered and closed as the connector would), so the
tests also prove the SDK only ever sends valid frames.

Adversarial knobs: ``override[method]`` returns what to do instead of the
normal answer (``{"ok": ...}``, ``{"error": ...}``, ``"close"``,
``"oversize"``, ``"garbage"`` or ``"silent"``); ``wrong_proof``;
``replay_challenge``.
"""

from __future__ import annotations

import asyncio
import base64
import hmac  # ip-boundary-allow: test stand-in for the wl-local/1 transport handshake, not lineage signing
import os
import secrets
import struct
import time
import uuid
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from watchlight_core import _wl_local as wire


def _token() -> str:
    return base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode()


class _Conn:
    def __init__(self, cid: int, writer: asyncio.StreamWriter) -> None:
        self.id = cid
        self.writer = writer
        self.lock = asyncio.Lock()
        self.in_flight = 0
        self.closed = False

    async def send(self, obj: Any) -> None:
        if self.closed:
            return
        body = obj if isinstance(obj, bytes) else wire.encode_frame(obj)
        async with self.lock:
            try:
                self.writer.write(body)
                await self.writer.drain()
            except (ConnectionError, OSError):
                self.closed = True


class StandInConnector:
    def __init__(self, base: Path, transport: str = "unix") -> None:
        self.base = base
        self.transport = transport
        self.dir = base / "wl"
        self.socket_path = str(self.dir / "control.sock")
        self.secret_path = str(self.dir / "secret")
        self.secret = os.urandom(32)
        self.address = ""
        self.server: Optional[asyncio.AbstractServer] = None
        self.runs: Dict[str, Dict[str, Any]] = {}
        self.conns: List[_Conn] = []
        self.received: List[Dict[str, Any]] = []
        self.violations: List[str] = []
        self.override: Dict[str, Callable[[Dict[str, Any]], Any]] = {}
        self.wrong_proof = False
        self.replay_challenge: Optional[Dict[str, str]] = None
        self.recorded_challenges: List[Dict[str, str]] = []
        self.hello_nonces: List[str] = []
        self.bytes_after_challenge: List[int] = []
        self.max_in_flight_seen = 0
        self._next_conn = 0

    # -- lifecycle --------------------------------------------------------

    async def start(self) -> "StandInConnector":
        self.dir.mkdir(mode=0o700)
        os.chmod(self.dir, 0o700)
        if self.transport == "unix":
            self.server = await asyncio.start_unix_server(self._handle, path=self.socket_path)
            os.chmod(self.socket_path, 0o600)
        else:
            self.server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
            port = self.server.sockets[0].getsockname()[1]
            self.address = f"127.0.0.1:{port}"
            fd = os.open(self.secret_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.write(fd, self.secret.hex().encode() + b"\n")
            os.close(fd)
        return self

    async def stop(self) -> None:
        if self.server is not None:
            self.server.close()
        for c in self.conns:
            c.closed = True
            c.writer.transport.abort()
        if self.server is not None:
            await self.server.wait_closed()

    def drop_all(self) -> None:
        """Close every client connection (as a connector that dies)."""
        for c in self.conns:
            c.closed = True
            c.writer.transport.abort()

    def live_runs(self) -> List[str]:
        return [r for r, s in self.runs.items() if not s["ended"]]

    async def kill(self, run: str, source: str = "refresh") -> None:
        state = self.runs[run]
        state["ended"] = True
        state["ended_at"] = time.monotonic()
        sub = state.get("subscriber")
        if sub is not None:
            await sub.send({"push": True, "event": "kill", "data": {"run": run, "reason": "ended", "source": source}})

    # -- framing ----------------------------------------------------------

    async def _read(self, reader: asyncio.StreamReader, limit: int) -> Any:
        header = await reader.readexactly(4)
        (n,) = struct.unpack(">I", header)
        if n == 0 or n > limit:
            raise wire.WireError("frame length")
        return wire.decode_json(await reader.readexactly(n))

    # -- connection -------------------------------------------------------

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self._next_conn += 1
        conn = _Conn(self._next_conn, writer)
        self.conns.append(conn)
        tasks: List[asyncio.Task] = []
        try:
            if not await self._handshake(conn, reader):
                return
            while not conn.closed:
                try:
                    frame = await self._read(reader, wire.MAX_FRAME)
                    wire.validate_client_frame(frame, transport=self.transport)
                except (wire.WireError, asyncio.IncompleteReadError, ConnectionError):
                    if not conn.closed:
                        self.violations.append("bad frame after hello")
                        await conn.send({"id": None, "error": {"code": "invalid"}})
                    return
                self.received.append(frame)
                conn.in_flight += 1
                self.max_in_flight_seen = max(self.max_in_flight_seen, conn.in_flight)
                if conn.in_flight > 16:  # the spec limit
                    self.violations.append("more than 16 requests in flight")
                tasks.append(asyncio.ensure_future(self._serve(conn, frame)))
        except (asyncio.IncompleteReadError, ConnectionError, wire.WireError):
            pass
        finally:
            conn.closed = True
            for t in tasks:
                t.cancel()
            # A lost connection kills every run created on it.
            for state in self.runs.values():
                if state["conn"] == conn.id and not state["ended"]:
                    state["ended"] = True
                    state["ended_at"] = time.monotonic()
            writer.transport.abort()

    async def _handshake(self, conn: _Conn, reader: asyncio.StreamReader) -> bool:
        frame = await asyncio.wait_for(self._read(reader, wire.MAX_HANDSHAKE_FRAME), 5)
        try:
            wire.validate_client_frame(frame, transport=self.transport)
            if frame["method"] != "hello":
                raise wire.WireError("first frame not hello")
        except wire.WireError as exc:
            self.violations.append(f"hello: {exc}")
            await conn.send({"id": None, "error": {"code": "unauthenticated"}})
            return False
        self.received.append(frame)
        params = frame["params"]
        answer = {"proto": "wl-local/1", "connector_version": "0.0.0-standin", "features": ["kill_push", "report_connection"]}
        if self.transport == "unix":
            await conn.send({"id": frame["id"], "ok": answer})
            return True
        nonce_c = params["nonce_c"]
        self.hello_nonces.append(nonce_c)
        sock = conn.writer.get_extra_info("socket")
        binding = wire.ChannelBinding.of(sock.getpeername(), sock.getsockname())
        nonce_s = secrets.token_hex(32)
        proof = wire.server_proof(self.secret, params["proto"], nonce_c, nonce_s, binding)
        challenge = {"nonce_s": nonce_s, "server_proof": proof}
        self.recorded_challenges.append(dict(challenge))
        if self.wrong_proof:
            challenge["server_proof"] = "0" * 64
        if self.replay_challenge is not None:
            challenge = dict(self.replay_challenge)
            nonce_s = challenge["nonce_s"]
        await conn.send({"id": frame["id"], "ok": challenge})
        if self.wrong_proof or self.replay_challenge is not None:
            # Record whatever the client sends after a bad challenge.
            try:
                data = await asyncio.wait_for(reader.read(65536), 1.0)
            except asyncio.TimeoutError:
                data = b"<timeout>"
            self.bytes_after_challenge.append(0 if data in (b"", b"<timeout>") else len(data))
            return False
        auth = await asyncio.wait_for(self._read(reader, wire.MAX_HANDSHAKE_FRAME), 5)
        expected = wire.client_proof(self.secret, params["proto"], nonce_c, nonce_s, binding)
        try:
            wire.validate_client_frame(auth, transport="tcp")
            ok = auth["method"] == "auth" and hmac.compare_digest(auth["params"]["client_proof"], expected)
        except wire.WireError:
            ok = False
        if not ok:
            self.violations.append("bad client proof")
            await conn.send({"id": auth.get("id") if isinstance(auth, dict) else None, "error": {"code": "unauthenticated"}})
            return False
        self.received.append(auth)
        await conn.send({"id": auth["id"], "ok": answer})
        return True

    # -- requests ---------------------------------------------------------

    async def _serve(self, conn: _Conn, frame: Dict[str, Any]) -> None:
        rid, method, params = frame["id"], frame["method"], frame["params"]
        try:
            if method in self.override:
                action = self.override[method](params)
                if isinstance(action, tuple) and action[0] == "kill_first":
                    # Answer normally, but push a kill for params[field]
                    # before the answer goes out.
                    ok = await self._answer(conn, method, params)
                    state = self.runs[params[action[1]]]
                    state["subscriber"] = state["subscriber"] or conn
                    await self.kill(params[action[1]], "operator")
                    await conn.send({"id": rid, "ok": ok})
                    return
                if action is not None:
                    await self._act(conn, rid, action)
                    return
            if method == "close":
                await conn.send({"id": rid, "ok": {}})
                conn.closed = True
                conn.writer.close()
                return
            try:
                ok = await self._answer(conn, method, params)
                await conn.send({"id": rid, "ok": ok})
            except _Refuse as r:
                await conn.send({"id": rid, "error": r.body})
        finally:
            conn.in_flight -= 1

    async def _act(self, conn: _Conn, rid: int, action: Any) -> None:
        if action == "close":
            conn.closed = True
            conn.writer.transport.abort()
        elif action == "oversize":
            await conn.send(struct.pack(">I", wire.MAX_FRAME + 1) + b"{}")
        elif action == "garbage":
            await conn.send(struct.pack(">I", 5) + b"nope!")
        elif action == "silent":
            return
        else:
            body = dict(action)
            body["id"] = rid
            await conn.send(body)

    def _owned(self, conn: _Conn, run: str, late_ok: bool = False) -> Dict[str, Any]:
        state = self.runs.get(run)
        if state is None or state["conn"] != conn.id:
            raise _Refuse({"code": "unknown_run"})
        if state["ended"]:
            if time.monotonic() - state["ended_at"] > wire.ENDED_RUN_WINDOW_S:
                raise _Refuse({"code": "unknown_run"})
            if not late_ok:
                raise _Refuse({"code": "run_ended"})
        return state

    def _new_run(self, conn: _Conn, parent: Optional[str] = None) -> Dict[str, Any]:
        run = _token()
        state = {"run": run, "conn": conn.id, "ended": False, "ended_at": 0.0, "marker": _token(),
                 "child_key": _token(), "parent": parent, "subscriber": None, "events": [], "modes": []}
        self.runs[run] = state
        return state

    async def _end(self, run: str) -> None:
        stack = [run]
        while stack:
            r = stack.pop()
            state = self.runs[r]
            if not state["ended"]:
                await self.kill(r, "local")
            stack.extend(x for x, s in self.runs.items() if s["parent"] == r)

    async def _answer(self, conn: _Conn, method: str, p: Dict[str, Any]) -> Dict[str, Any]:
        if method == "health":
            return {"status": "ok"}
        if method == "resolve_agent":
            return {"agent": None if p["slug"] == "missing" else {"id": str(uuid.uuid4()), "slug": p["slug"]}}
        if method == "create_session":
            if p["agent_id"].startswith("slow"):
                await asyncio.sleep(0.4)
            state = self._new_run(conn)
            sid = f"ses_{uuid.uuid4().hex}"
            eid = f"exec_{uuid.uuid4()}"
            return {"run": state["run"], "session_id": sid, "execution_id": eid, "root_execution_id": eid,
                    "scope": {"session": {"id": sid, "agent_id": p["agent_id"], "status": "active"},
                              "root_run_handle_id": str(uuid.uuid4())},
                    "marker": state["marker"], "child_key": state["child_key"]}
        if method == "authorize":
            if "run" in p:
                self._owned(conn, p["run"])
            principal = p["principal"]
            if principal == "deny":
                return {"decision": {"decision": "Deny", "reason": "policy"}}
            if principal == "busy":
                raise _Refuse({"code": "unavailable", "retry_after_ms": 250})
            if principal == "boom":
                raise _Refuse({"code": "internal"})
            if principal.startswith("sleep:"):
                await asyncio.sleep(int(principal[6:]) / 1000)
                return {"decision": {"decision": "Allow", "context": p.get("context")}}
            if principal == "echo":
                return {"decision": {"decision": "Allow", "echo": p}}
            return {"decision": {"decision": "Allow"}}
        if method == "get_manifest":
            self._owned(conn, p["run"])
            return {"manifest": {"tool_allowlist": ["search"]}}
        if method in ("preflight_step", "submit_plan"):
            self._owned(conn, p["run"])
            return {"result": {"allowed": True}}
        if method == "spawn_subagent":
            self._owned(conn, p["parent_run"])
            req = p["request"]
            if req.get("overreach"):
                raise _Refuse({"code": "denied", "reason": "scope_attenuation_violation"})
            if req.get("invalidated"):
                raise _Refuse({"code": "run_ended", "reason": "run_handle_invalidated"})
            child = self._new_run(conn, parent=p["parent_run"])
            sid = f"ses_{uuid.uuid4().hex}"
            eid = f"exec_{uuid.uuid4()}"
            return {"child_run": child["run"], "session_id": sid, "execution_id": eid,
                    "scope": {"child_run_handle_id": str(uuid.uuid4()),
                              "granted_scope": {"allowed_tools": ["search"], "max_depth": 1, "time_budget_seconds": 60},
                              "child_execution_id": eid, "child_session_id": sid},
                    "child_marker": child["marker"], "child_key": child["child_key"]}
        if method == "publish_events":
            state = self._owned(conn, p["run"], late_ok=True)
            state["events"].extend(p["events"])
            state["modes"].append(p.get("mode", "background"))
            return {"accepted": len(p["events"])}
        if method == "drain":
            self._owned(conn, p["run"], late_ok=True)
            return {"drained": True}
        if method in ("complete_session", "terminate_session", "session.revoke"):
            self._owned(conn, p["run"])
            await self._end(p["run"])
            return {}
        if method == "session.refresh_marker":
            state = self._owned(conn, p["run"])
            state["marker"] = _token()
            return {"marker": state["marker"]}
        if method == "egress_for":
            state = self._owned(conn, p["run"])
            state["marker"], state["child_key"] = _token(), _token()
            return {"proxy_url": "http://127.0.0.1:41001", "marker_header": "Watchlight-Run-Marker",
                    "marker": state["marker"], "child_proxy_url": f"http://wl:{state['child_key']}@127.0.0.1:41001"}
        if method == "report_connection":
            self._owned(conn, p["run"])
            return {}
        if method == "subscribe_kill":
            state = self._owned(conn, p["run"])
            state["subscriber"] = conn
            return {}
        raise _Refuse({"code": "invalid"})


class _Refuse(Exception):
    def __init__(self, body: Dict[str, Any]) -> None:
        super().__init__(body.get("code"))
        self.body = body


async def _main(base: str) -> None:  # pragma: no cover - run as a subprocess
    import sys

    connector = await StandInConnector(Path(base), transport="tcp").start()
    sys.stdout.write(connector.address + "\n" + connector.secret.hex() + "\n")
    sys.stdout.flush()
    sys.stdout.close()
    await asyncio.Event().wait()


if __name__ == "__main__":  # pragma: no cover
    import sys

    asyncio.run(_main(sys.argv[1]))
