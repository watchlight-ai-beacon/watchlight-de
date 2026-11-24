"""The wire layer of ``wl-local/1``, the local control protocol between this
SDK and the Watchlight connector (``wl-sidecar``).

This module holds what the protocol specification in
``contracts/wl-local-1/README.md`` fixes, and nothing that decides anything:

* framing (a 4-byte big-endian length and one UTF-8 JSON object of at most
  1 MiB) and strict JSON decoding (no duplicate keys, no ``NaN``);
* the shape of every request this SDK sends and every answer it accepts,
  mirrored from ``wl-local-1.schema.json``. Unknown fields are refused
  everywhere, so an answer that carries anything extra (a token, a CA
  bundle) is refused and never reaches the caller;
* the loopback-TCP handshake proofs (HMAC-SHA256 over length-prefixed
  fields, bound to both nonces and both ends of the connection);
* the checks the SDK makes before it connects: the control socket's
  directory, the socket file itself, the dial address and the secret file.

Nothing here logs a value. The secret, nonces and proofs never leave this
module except on the wire.
"""

from __future__ import annotations

import hmac  # ip-boundary-allow: transport authentication of the local control channel (wl-local/1 handshake), not lineage or audit signing
import hashlib
import ipaddress
import json
import os
import re
import socket
import stat
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional, Tuple

PROTO = "wl-local/1"
MAX_FRAME = 1 << 20
MAX_HANDSHAKE_FRAME = 16 * 1024
MAX_IN_FLIGHT = 16
MAX_REQUEST_ID = (1 << 53) - 1
HANDSHAKE_TIMEOUT_S = 5.0
FRAME_TIMEOUT_S = 10.0
WRITE_TIMEOUT_S = 10.0
HEARTBEAT_S = 30.0
ENDED_RUN_WINDOW_S = 10.0
MAX_JSON_DEPTH = 32
MAX_JSON_ELEMENTS = 10_000
MAX_EVENTS_PER_FRAME = 1000
MAX_PLAN_STEPS = 256
MAX_DRAIN_MS = 60_000
MAX_TTL_SECONDS = 86_400

SERVER_PROOF_LABEL = b"wl-local/1 server"
CLIENT_PROOF_LABEL = b"wl-local/1 client"

#: The features this SDK requires from the connector.
REQUIRED_FEATURES = ("kill_push",)

ERROR_CODES = frozenset(
    {
        "unauthenticated",
        "unsupported_version",
        "unknown_run",
        "run_ended",
        "denied",
        "unavailable",
        "invalid",
        "internal",
    }
)

#: The closed list of non-sensitive refusal categories. Anything else is
#: not a valid answer.
ERROR_REASONS = frozenset(
    {
        "scope_attenuation_violation",
        "run_handle_invalidated",
        "agent_not_registered",
        "goal_not_found",
        "quarantined",
        "terminated",
        "severed",
        "revoked",
        # wl-apdp's typed trust refusal.
        "agent_trust_revoked",
        "agent_quarantined",
        "agent_unverified",
        "delegation_chain_not_trusted",
    }
)

KILL_SOURCES = frozenset({"refresh", "authorize", "forward_lane", "local", "operator"})


class WireError(Exception):
    """A frame or value that does not follow ``wl-local/1``. The message
    names the rule, never the value."""


class InvalidRequest(WireError):
    """A request this SDK refuses to send: a parameter the protocol does
    not allow. The call fails closed without reaching the connector."""


# ---------------------------------------------------------------------------
# Strict JSON
# ---------------------------------------------------------------------------


def _no_duplicates(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise WireError("duplicate key in a JSON object")
        out[key] = value
    return out


def _no_constant(_name: str) -> Any:
    raise WireError("NaN or Infinity in a frame")


def decode_json(body: bytes) -> Any:
    """Decode one frame body: UTF-8, a single JSON value, no duplicate keys,
    no ``NaN``/``Infinity``."""
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise WireError("frame is not UTF-8") from exc
    try:
        return json.loads(
            text, object_pairs_hook=_no_duplicates, parse_constant=_no_constant
        )
    except WireError:
        raise
    except ValueError as exc:
        raise WireError("frame is not JSON") from exc


def encode_frame(obj: Mapping[str, Any]) -> bytes:
    """Encode one frame. Raises :class:`InvalidRequest` when the body would
    exceed :data:`MAX_FRAME`."""
    try:
        body = json.dumps(
            obj, separators=(",", ":"), ensure_ascii=False, allow_nan=False
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise InvalidRequest("a request is not JSON-serialisable") from exc
    if not body or len(body) > MAX_FRAME:
        raise InvalidRequest("a request frame exceeds 1 MiB")
    return struct.pack(">I", len(body)) + body


def frame_length(header: bytes, limit: int = MAX_FRAME) -> int:
    """The body length a 4-byte header announces. Zero or more than
    ``limit`` is a protocol violation: the connection must close without
    reading or allocating the claimed size."""
    (length,) = struct.unpack(">I", header)
    if length == 0 or length > limit:
        raise WireError("frame length out of bounds")
    return length


# ---------------------------------------------------------------------------
# Value checks (mirroring wl-local-1.schema.json; lengths count code points)
# ---------------------------------------------------------------------------

_IDENT = re.compile(r"[A-Za-z0-9._:@/+\-]+")
_B64URL = re.compile(r"[A-Za-z0-9_\-]+")
_FEATURE = re.compile(r"[a-z0-9_.]+")
_HEX64 = re.compile(r"[0-9a-f]{64}")
_MARKER = re.compile(r"[A-Za-z0-9_\-]{43}")
_VISIBLE_ASCII = re.compile(r"[\x21-\x7e]+")
_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_EXEC_ID = re.compile(
    r"exec_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
)

Check = Callable[[Any], bool]


def _str(min_len: int, max_len: int, pattern: Optional["re.Pattern[str]"] = None,
         no_controls: bool = False) -> Check:
    def check(v: Any) -> bool:
        if not isinstance(v, str) or not (min_len <= len(v) <= max_len):
            return False
        if pattern is not None and pattern.fullmatch(v) is None:
            return False
        if no_controls and _CONTROL.search(v) is not None:
            return False
        return True

    return check


def _int(lo: int, hi: int) -> Check:
    def check(v: Any) -> bool:
        return type(v) is int and lo <= v <= hi

    return check


is_ident = _str(1, 256, _IDENT)
is_run_ref = _str(16, 128, _B64URL)
is_short_text = _str(1, 256, no_controls=True)
is_cedar_ref = _str(1, 1024, no_controls=True)
is_feature = _str(1, 64, _FEATURE)
is_hex64 = _str(64, 64, _HEX64)
is_marker = _str(43, 43, _MARKER)
is_subject_token = _str(1, 16384, _VISIBLE_ASCII)
is_location = _str(1, 4096, no_controls=True)
is_execution_id = _str(41, 41, _EXEC_ID)
is_u32 = _int(0, 0xFFFFFFFF)
is_request_id = _int(0, MAX_REQUEST_ID)


def _shape_ok(v: Any, depth: int, count: List[int]) -> bool:
    count[0] += 1
    if depth > MAX_JSON_DEPTH or count[0] > MAX_JSON_ELEMENTS:
        return False
    if isinstance(v, (list, tuple)):
        return all(_shape_ok(x, depth + 1, count) for x in v)
    if isinstance(v, dict):
        return all(isinstance(k, str) for k in v) and all(
            _shape_ok(x, depth + 1, count) for x in v.values()
        )
    return v is None or isinstance(v, (str, bool, int, float))


def is_json_object(v: Any) -> bool:
    """A JSON object passed through to wl-apdp: at most 32 levels deep and
    10,000 values in all (the connector's own bound)."""
    if not isinstance(v, dict) or not all(isinstance(k, str) for k in v):
        return False
    count = [0]
    return all(_shape_ok(x, 2, count) for x in v.values())


def _list_of(check: Check, max_items: int) -> Check:
    def inner(v: Any) -> bool:
        return isinstance(v, list) and len(v) <= max_items and all(check(x) for x in v)

    return inner


def _enum(*values: str) -> Check:
    allowed = frozenset(values)
    return lambda v: isinstance(v, str) and v in allowed


def _is_empty(v: Any) -> bool:
    return isinstance(v, dict) and not v


# A shape: field -> (check, required).
Shape = Dict[str, Tuple[Check, bool]]


def _matches(obj: Any, shape: Shape) -> bool:
    if not isinstance(obj, dict):
        return False
    for key in obj:
        if key not in shape:
            return False
    for key, (check, required) in shape.items():
        if key in obj:
            if not check(obj[key]):
                return False
        elif required:
            return False
    return True


def _obj(shape: Shape) -> Check:
    return lambda v: _matches(v, shape)


_RUN: Shape = {"run": (is_run_ref, True)}

PARAMS: Dict[str, Shape] = {
    "hello": {
        "proto": (is_short_text, True),
        "nonce_c": (is_hex64, False),
        "lang": (is_short_text, True),
        "sdk_version": (is_short_text, True),
        "pid": (is_u32, True),
        "required_features": (_list_of(is_feature, 32), False),
    },
    "auth": {"client_proof": (is_hex64, True)},
    "resolve_agent": {"slug": (is_ident, True)},
    "create_session": {
        "agent_id": (is_ident, True),
        "goal_id": (is_ident, False),
        "max_actions": (is_u32, False),
        "ttl_seconds": (_int(1, MAX_TTL_SECONDS), True),
        "metadata": (is_json_object, False),
        "subject_token": (is_subject_token, False),
        "application_id": (is_ident, False),
        "workload_ref": (is_json_object, False),
    },
    "get_manifest": _RUN,
    "authorize": {
        "run": (is_run_ref, False),
        "principal": (is_cedar_ref, True),
        "action": (is_cedar_ref, True),
        "resource": (is_cedar_ref, True),
        "context": (is_json_object, False),
        "intent": (is_json_object, False),
        "execution_id": (is_execution_id, False),
    },
    "preflight_step": {
        "run": (is_run_ref, True),
        "action": (is_cedar_ref, True),
        "resource": (is_cedar_ref, True),
        "resource_type": (is_cedar_ref, False),
        "intent": (is_json_object, False),
        "context": (is_json_object, False),
    },
    "submit_plan": {
        "run": (is_run_ref, True),
        "plan": (_list_of(is_json_object, MAX_PLAN_STEPS), True),
    },
    "spawn_subagent": {
        "parent_run": (is_run_ref, True),
        "request": (is_json_object, True),
    },
    "publish_events": {
        "run": (is_run_ref, True),
        "events": (_list_of(is_json_object, MAX_EVENTS_PER_FRAME), True),
        "mode": (_enum("decision_path", "background"), False),
    },
    "complete_session": _RUN,
    "terminate_session": {"run": (is_run_ref, True), "reason": (is_short_text, True)},
    "drain": {"run": (is_run_ref, True), "timeout_ms": (_int(0, MAX_DRAIN_MS), True)},
    "session.refresh_marker": _RUN,
    "session.revoke": _RUN,
    "report_connection": {"src_port": (_int(1, 65535), True), "run": (is_run_ref, True)},
    "egress_for": _RUN,
    "subscribe_kill": _RUN,
    "health": {},
    "close": {},
}

METHODS = frozenset(PARAMS)

_HELLO_ANSWER: Shape = {
    "proto": (is_short_text, True),
    "connector_version": (is_short_text, True),
    "features": (_list_of(is_feature, 64), True),
}
_CHALLENGE: Shape = {"nonce_s": (is_hex64, True), "server_proof": (is_hex64, True)}


def _result_object(key: str) -> Shape:
    return {key: (is_json_object, True)}


RESULTS: Dict[str, Optional[Shape]] = {
    # hello depends on the transport; see validate_result.
    "hello": None,
    "auth": _HELLO_ANSWER,
    "resolve_agent": {"agent": (lambda v: v is None or is_json_object(v), True)},
    "create_session": {
        "run": (is_run_ref, True),
        "session_id": (is_ident, True),
        "execution_id": (is_ident, True),
        "root_execution_id": (is_ident, True),
        "scope": (is_json_object, True),
        "manifest": (is_json_object, False),
        "marker": (is_marker, True),
        "child_key": (is_marker, True),
    },
    "get_manifest": _result_object("manifest"),
    "authorize": _result_object("decision"),
    "preflight_step": _result_object("result"),
    "submit_plan": _result_object("result"),
    "spawn_subagent": {
        "child_run": (is_run_ref, True),
        "session_id": (is_ident, True),
        "execution_id": (is_ident, True),
        "scope": (is_json_object, True),
        "child_marker": (is_marker, True),
        "child_key": (is_marker, True),
    },
    "publish_events": {"accepted": (is_u32, True)},
    "complete_session": {},
    "terminate_session": {},
    "drain": {"drained": (lambda v: isinstance(v, bool), True)},
    "session.refresh_marker": {"marker": (is_marker, True)},
    "session.revoke": {},
    "report_connection": {},
    "egress_for": {
        "proxy_url": (is_location, True),
        "marker_header": (is_short_text, True),
        "marker": (is_marker, True),
        "child_proxy_url": (is_location, True),
    },
    "subscribe_kill": {},
    "health": {"status": (_enum("ok", "degraded"), True)},
    "close": {},
}

KILL_EVENT: Shape = {
    "run": (is_run_ref, True),
    "reason": (is_short_text, True),
    "source": (lambda v: isinstance(v, str) and v in KILL_SOURCES, True),
}


def validate_request(method: str, params: Mapping[str, Any], *, transport: Optional[str] = None) -> None:
    """Refuse a request the protocol does not allow (unknown method, unknown
    or invalid parameter). On TCP a ``hello`` must carry ``nonce_c``."""
    shape = PARAMS.get(method)
    if shape is None:
        raise InvalidRequest("unknown method")
    if not _matches(dict(params), shape):
        raise InvalidRequest(f"invalid parameters for {method}")
    if method == "hello" and transport == "tcp" and "nonce_c" not in params:
        raise InvalidRequest("a TCP hello needs nonce_c")


def validate_client_frame(frame: Any, *, transport: Optional[str] = None) -> None:
    """Check a whole request frame: ``{id, method, params}`` and nothing
    else. Used for the golden fixtures and by the test stand-in server."""
    if not isinstance(frame, dict) or set(frame) != {"id", "method", "params"}:
        raise WireError("a request is {id, method, params}")
    if not is_request_id(frame["id"]):
        raise WireError("request id out of range")
    if not isinstance(frame["method"], str) or not isinstance(frame["params"], dict):
        raise WireError("bad method or params")
    validate_request(frame["method"], frame["params"], transport=transport)


def validate_result(method: str, ok: Any, *, transport: Optional[str] = None) -> bool:
    """Whether ``ok`` is exactly the answer ``method`` may have. ``transport``
    (``unix`` or ``tcp``) picks the hello answer: the hello answer on the
    Unix socket, the challenge on TCP."""
    if method == "hello":
        if transport == "tcp":
            return _matches(ok, _CHALLENGE)
        if transport == "unix":
            return _matches(ok, _HELLO_ANSWER)
        return _matches(ok, _HELLO_ANSWER) or _matches(ok, _CHALLENGE)
    shape = RESULTS.get(method)
    if shape is None:
        return False
    return _matches(ok, shape)


@dataclass(frozen=True)
class ErrorBody:
    """A validated error answer. ``valid`` is false when the body broke a
    rule (an unknown code or reason, a stray field): the caller then treats
    the request as refused, never as anything more specific."""

    code: str
    retry_after_ms: Optional[int] = None
    reason: Optional[str] = None
    valid: bool = True


INVALID_ERROR = ErrorBody(code="internal", valid=False)


def parse_error_body(err: Any) -> ErrorBody:
    """Validate an error body: a known code; ``retry_after_ms`` exactly when
    the code is ``unavailable``; a ``reason`` from the closed list only with
    ``denied`` or ``run_ended``; no other field. Anything else is
    :data:`INVALID_ERROR` (a refusal with no detail)."""
    if not isinstance(err, dict):
        return INVALID_ERROR
    if set(err) - {"code", "retry_after_ms", "reason"}:
        return INVALID_ERROR
    code = err.get("code")
    if not isinstance(code, str) or code not in ERROR_CODES:
        return INVALID_ERROR
    retry = err.get("retry_after_ms")
    if code == "unavailable":
        if not is_u32(retry):
            return INVALID_ERROR
    elif "retry_after_ms" in err:
        return INVALID_ERROR
    reason = err.get("reason")
    if "reason" in err:
        if code not in ("denied", "run_ended"):
            return INVALID_ERROR
        if not isinstance(reason, str) or reason not in ERROR_REASONS:
            return INVALID_ERROR
    return ErrorBody(code=code, retry_after_ms=retry, reason=reason)


@dataclass(frozen=True)
class Response:
    """One answer: ``ok`` or ``error``. ``id`` is ``None`` only for an error
    about a frame the connector could not read (the connection closes)."""

    id: Optional[int]
    ok: Any = None
    error: Optional[ErrorBody] = None


@dataclass(frozen=True)
class KillPush:
    run: str
    reason: str
    source: str


def parse_server_frame(frame: Any) -> "Response | KillPush":
    """Classify a decoded server frame. Raises :class:`WireError` for
    anything that is neither a response nor a ``kill`` push. The ``ok`` body
    is NOT checked here (that needs the request's method): see
    :func:`validate_result`."""
    if not isinstance(frame, dict):
        raise WireError("a server frame is an object")
    keys = set(frame)
    if keys == {"id", "ok"}:
        if not is_request_id(frame["id"]):
            raise WireError("response id out of range")
        return Response(id=frame["id"], ok=frame["ok"])
    if keys == {"id", "error"}:
        rid = frame["id"]
        if rid is not None and not is_request_id(rid):
            raise WireError("response id out of range")
        return Response(id=rid, error=parse_error_body(frame["error"]))
    if keys == {"push", "event", "data"}:
        if frame["push"] is not True or frame["event"] != "kill":
            raise WireError("unknown push")
        data = frame["data"]
        if not _matches(data, KILL_EVENT):
            raise WireError("invalid kill push")
        return KillPush(run=data["run"], reason=data["reason"], source=data["source"])
    raise WireError("unknown server frame")


# ---------------------------------------------------------------------------
# Loopback-TCP handshake
# ---------------------------------------------------------------------------


def _ip_bytes(host: str) -> bytes:
    addr = ipaddress.ip_address(host.split("%", 1)[0])
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        return addr.ipv4_mapped.packed
    return addr.packed


@dataclass(frozen=True)
class ChannelBinding:
    """Both ends of a TCP connection, as this side sees it: the SDK's local
    address is the client, its peer the connector."""

    client_ip: bytes
    client_port: int
    server_ip: bytes
    server_port: int

    @classmethod
    def of(cls, client: Tuple[Any, ...], server: Tuple[Any, ...]) -> "ChannelBinding":
        return cls(_ip_bytes(client[0]), int(client[1]), _ip_bytes(server[0]), int(server[1]))

    @classmethod
    def from_socket(cls, sock: socket.socket) -> "ChannelBinding":
        return cls.of(sock.getsockname(), sock.getpeername())


def _mac_input(label: bytes, proto: str, first: bytes, second: bytes, b: ChannelBinding) -> bytes:
    out = bytearray()
    for field in (
        label,
        proto.encode("utf-8"),
        first,
        second,
        b.client_ip,
        struct.pack(">H", b.client_port),
        b.server_ip,
        struct.pack(">H", b.server_port),
    ):
        out += struct.pack(">I", len(field))
        out += field
    return bytes(out)


def _proof(secret: bytes, msg: bytes) -> str:
    return hmac.new(secret, msg, hashlib.sha256).hexdigest()


def server_proof(secret: bytes, proto: str, nonce_c_hex: str, nonce_s_hex: str, b: ChannelBinding) -> str:
    """``HMAC-SHA256(secret, "wl-local/1 server" ‖ proto ‖ nonce_c ‖ nonce_s ‖
    client ip/port ‖ server ip/port)`` as lowercase hex."""
    msg = _mac_input(SERVER_PROOF_LABEL, proto, bytes.fromhex(nonce_c_hex), bytes.fromhex(nonce_s_hex), b)
    return _proof(secret, msg)


def client_proof(secret: bytes, proto: str, nonce_c_hex: str, nonce_s_hex: str, b: ChannelBinding) -> str:
    """The SDK's proof: the client label, then ``nonce_s`` before ``nonce_c``."""
    msg = _mac_input(CLIENT_PROOF_LABEL, proto, bytes.fromhex(nonce_s_hex), bytes.fromhex(nonce_c_hex), b)
    return _proof(secret, msg)


def verify_server_proof(
    secret: bytes, proto: str, nonce_c_hex: str, nonce_s_hex: str, b: ChannelBinding, proof_hex: Any
) -> bool:
    """Constant-time check of the connector's proof."""
    if not is_hex64(proof_hex) or not is_hex64(nonce_s_hex):
        return False
    expected = server_proof(secret, proto, nonce_c_hex, nonce_s_hex, b)
    return hmac.compare_digest(expected.encode("ascii"), proof_hex.encode("ascii"))


def random_nonce_hex() -> str:
    """32 fresh bytes from the OS CSPRNG, as 64 lowercase hex characters."""
    return os.urandom(32).hex()


def parse_secret_hex(text: str) -> bytearray:
    """The 32-byte control secret from its 64-hex-character form (one
    trailing newline allowed)."""
    if text.endswith("\n"):
        text = text[:-1]
    if not is_hex64(text):
        raise WireError("the control secret is not 64 lowercase hex characters")
    return bytearray(bytes.fromhex(text))


# ---------------------------------------------------------------------------
# Pre-connect checks
# ---------------------------------------------------------------------------


def parse_dial_addr(text: str) -> Tuple[str, int]:
    """An IP literal and a port on loopback (``127.0.0.1:41000`` or
    ``[::1]:41000``). Hostnames such as ``localhost`` are refused: they can
    resolve to another loopback address than the one the connector listens
    on."""
    text = text.strip()
    m = re.fullmatch(r"\[([0-9A-Fa-f:.]+)\]:(\d{1,5})", text) or re.fullmatch(
        r"([0-9.]+):(\d{1,5})", text
    )
    if m is None:
        raise WireError("the control address must be an IP literal and a port (no hostnames)")
    try:
        ip = ipaddress.ip_address(m.group(1))
    except ValueError as exc:
        raise WireError("the control address must be an IP literal and a port (no hostnames)") from exc
    port = int(m.group(2))
    if not 1 <= port <= 65535:
        raise WireError("the control port is out of range")
    loopback = (
        ip.is_loopback
        if isinstance(ip, ipaddress.IPv4Address)
        else ip == ipaddress.IPv6Address("::1")
    )
    if not loopback:
        raise WireError("the control address must be a loopback address")
    return str(ip), port


def default_socket_path(uid: Optional[int] = None) -> Path:
    """``$XDG_RUNTIME_DIR/watchlight/control.sock`` when that is an absolute
    path, otherwise ``/tmp/wl-<uid>/control.sock`` (the connector's default)."""
    if uid is None:
        uid = os.geteuid()
    xdg = os.environ.get("XDG_RUNTIME_DIR")
    if xdg and os.path.isabs(xdg):
        return Path(xdg) / "watchlight" / "control.sock"
    return Path(f"/tmp/wl-{uid}/control.sock")


def check_private_dir(st: os.stat_result, uid: int, what: str) -> None:
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        raise WireError(f"the {what} is not a directory")
    if st.st_uid != uid:
        raise WireError(f"the {what} is not owned by this user")
    if st.st_mode & 0o077:
        raise WireError(f"the {what} is group or world accessible (it must be 0700)")


def check_ancestors(directory: str, uid: int) -> None:
    """Every ancestor must be owned by root or by us, and not writable by
    group or others unless it has the sticky bit."""
    canon = Path(os.path.realpath(directory))
    for anc in canon.parents:
        st = os.stat(anc)
        if st.st_uid not in (0, uid):
            raise WireError("an ancestor of the control directory is owned by another user")
        if st.st_mode & 0o022 and not st.st_mode & stat.S_ISVTX:
            raise WireError(
                "an ancestor of the control directory is writable by others without the sticky bit"
            )


def check_socket_path(path: str, uid: Optional[int] = None) -> None:
    """What the SDK checks before it connects to the control socket: its
    directory is a real directory, mode 0700, owned by us, with safe
    ancestors; the socket itself is a socket owned by us with no group or
    world permissions. Raises :class:`WireError` when any check fails."""
    if uid is None:
        uid = os.geteuid()
    if not os.path.isabs(path):
        raise WireError("the control socket path must be absolute")
    directory = os.path.dirname(path)
    if not directory:
        raise WireError("the control socket path has no directory")
    try:
        check_private_dir(os.lstat(directory), uid, "control socket directory")
        check_ancestors(directory, uid)
        st = os.lstat(path)
    except FileNotFoundError as exc:
        raise WireError("the control socket does not exist") from exc
    except OSError as exc:
        raise WireError(f"the control socket cannot be checked ({type(exc).__name__})") from exc
    if not stat.S_ISSOCK(st.st_mode):
        raise WireError("the control socket path is not a socket")
    if st.st_uid != uid:
        raise WireError("the control socket is not owned by this user")
    if st.st_mode & 0o077:
        raise WireError("the control socket is group or world accessible (it must be 0600)")


def read_secret_file(path: str, uid: Optional[int] = None) -> bytearray:
    """Read the control secret from the connector's secret file. The file's
    directory must be private to us (0700, ours) and the file a regular file
    of ours with mode 0600 or stricter; it is opened without following a
    symlink."""
    if uid is None:
        uid = os.geteuid()
    if not os.path.isabs(path):
        raise WireError("the secret file path must be absolute")
    try:
        check_private_dir(os.lstat(os.path.dirname(path)), uid, "secret file directory")
        check_ancestors(os.path.dirname(path), uid)
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    except WireError:
        raise
    except OSError as exc:
        raise WireError(f"the secret file cannot be opened ({type(exc).__name__})") from exc
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise WireError("the secret file is not a regular file")
        if st.st_uid != uid:
            raise WireError("the secret file is not owned by this user")
        if st.st_mode & 0o077:
            raise WireError("the secret file is group or world readable (it must be 0600)")
        raw = os.read(fd, 130)
    finally:
        os.close(fd)
    try:
        return parse_secret_hex(raw.decode("ascii"))
    except UnicodeDecodeError as exc:
        raise WireError("the control secret is not 64 lowercase hex characters") from exc
    finally:
        raw = b""


def peer_uid(sock: socket.socket) -> Optional[int]:
    """The uid of the process at the other end of a Unix socket, as the
    kernel reports it (``SO_PEERCRED`` on Linux, ``LOCAL_PEERCRED`` on macOS
    and the BSDs), or ``None`` when the platform does not report it."""
    so_peercred = getattr(socket, "SO_PEERCRED", None)
    if so_peercred is not None:
        raw = sock.getsockopt(socket.SOL_SOCKET, so_peercred, struct.calcsize("3i"))
        _pid, uid, _gid = struct.unpack("3i", raw)
        return uid
    local_peercred = getattr(socket, "LOCAL_PEERCRED", 0x001)
    sol_local = getattr(socket, "SOL_LOCAL", 0)
    try:
        # struct xucred { u_int cr_version; uid_t cr_uid; short cr_ngroups; gid_t cr_groups[16]; }
        raw = sock.getsockopt(sol_local, local_peercred, 76)
    except OSError:
        return None
    if len(raw) < 8:
        return None
    _version, uid = struct.unpack_from("=II", raw, 0)
    return uid
