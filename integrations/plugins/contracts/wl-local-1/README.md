# wl-local/1: the local control protocol

`wl-local/1` is the protocol a Watchlight language SDK uses to talk to the
connector (the `wl-sidecar` binary) on the same host or pod. The SDK asks
the connector to open sessions, authorize steps, spawn sub-agents and
publish lineage, and the connector holds every credential involved. The SDK
only ever receives an opaque run reference (`run`), never a run credential,
proxy token or egress token.

The protocol is implemented in `crates/wl-sidecar-core/src/local_proto/`.
The core parses, bounds and authenticates every message, and hands it to a
`ControlBackend` trait that the Enterprise crate implements. This folder
holds the contract that the SDKs build against:

- `wl-local-1.schema.json` is a JSON Schema (draft 2020-12) for every frame.
- `fixtures/valid/` and `fixtures/invalid/` hold golden frames. The Rust
  tests check that the connector accepts every valid fixture and refuses
  every invalid one, and the SDK test suites run the same files.

## Connecting

There are two ways to reach the connector. The SDK is told which one to use;
it never guesses.

**The Unix socket** is preferred. The default path is
`$XDG_RUNTIME_DIR/watchlight/control.sock`, or `/tmp/wl-<uid>/control.sock`
when `XDG_RUNTIME_DIR` is not set. The path may be at most 103 bytes on macOS
and the BSDs and 107 on Linux (the `sun_path` limit); a longer one is
refused at start with a clear error.

The connector creates the socket with mode 0600 inside a directory with mode
0700, and refuses to start unless:

- the directory is a real directory (not a symlink), owned by the
  connector's user, with no group or world permissions;
- every ancestor of the directory is owned by root or by that user, and is
  not writable by group or others unless it has the sticky bit (as `/tmp`
  does), so nobody else can rename the directory away.

If a socket is already at the path, the connector first tries to connect to
it. If something answers, another connector is running and this one refuses
to start; if nothing answers, the stale socket is replaced. On exit the
connector removes the socket only if it is still the file it created (same
device and inode).

For every connection, the connector reads the peer's user id from the kernel
(`SO_PEERCRED` on Linux, `getpeereid` on macOS) and drops the connection
without reading anything if it is not the connector's own user id. Where the
platform reports it, the kernel's view of the peer's process id is kept next
to the `pid` the client claims in `hello`.

**Before connecting, the SDK must check the socket's directory** the same
way: a real directory, mode 0700 (no group or world bits), owned by the
SDK's own user, with safe ancestors. If the check fails, the SDK must not
connect. The Rust form of this check is `check_socket_dir` in
`wl-sidecar-core`.

**Loopback TCP** is the fallback, for platforms where a shared socket is not
possible. The connector binds only a loopback address (`127.0.0.0/8` or
`::1`) and refuses any other. At each start it draws a 32-byte secret from
the system CSPRNG (aws-lc-rs) and wipes it from memory when it exits. The
SDK gets the secret in one of two ways:

- when the SDK launched the connector itself, from the connector's stdout:
  the first line is the bound address and the second line is the secret.
  The connector prints the secret only when its stdout is a pipe (FIFO) or a
  socket, checked with `fstat`; it refuses a terminal or a regular file,
  where the secret would be seen or kept;
- otherwise (for example in Kubernetes), from a file with mode 0600 at a
  configured path. The file's directory must be private to the connector's
  user (mode 0700, owned by it), so the SDK must run as the same user. The
  connector writes the file under a temporary name and renames it into
  place, so a symlink planted at that path is replaced and never followed.
  Only the address is printed on stdout. The connector removes the file
  when it exits, if it is still the file it wrote (same device and inode;
  the check and the removal are two steps, which is safe because the
  directory is private to the connector's user).

**The secret never crosses the connection.** On TCP the SDK and the
connector prove to each other that they know the secret with a mutual
challenge-response (see "Handshake"). Each proof is an HMAC-SHA256 keyed by
the secret and bound to both nonces, the protocol name and both ends of the
TCP connection (IP address and port), so it is useless to anyone who
records it: an impostor on the port cannot produce the connector's proof, a
recorded proof does not verify against a fresh nonce, and a relay in the
middle sees different addresses on its two legs (another loopback address,
another address family, or another port), so the proofs it forwards do not
verify on either side.

**TCP requires a direct loopback connection.** The SDK and the connector
must share a network namespace and talk over loopback directly: no port
mapping, userland proxy, NAT or service-mesh redirect in between, because
each of those changes the addresses one side sees and the handshake then
fails (as it should). The SDK dials the exact IP literal the connector
printed or was configured with, such as `127.0.0.1:41000` or `[::1]:41000`,
never a hostname: `localhost` can resolve to `::1` while the connector
listens on `127.0.0.1`, and whatever listens on the other address would get
the connection. The Rust helper `parse_dial_addr` refuses hostnames and
non-loopback addresses. On the Unix socket
there is no secret, nonce or proof: the kernel's peer-uid check and the
directory check above do that job.

**SDKs never reconnect over TCP after the connector they launched has
exited.** The port is free for anyone to take once the connector is gone. A
new connector means a new launch, a new secret and a new address.

TCP availability is best effort against a local process that floods the
port (see "Limits and timeouts"); the Unix socket, which only admits the
connector's own user, is the preferred transport. The secret is never
logged.

## Framing

Each frame is a 4-byte big-endian length followed by that many bytes of
UTF-8 JSON, which must be a single object. A frame body is at most 1 MiB. A
length of zero or above 1 MiB closes the connection at once; the connector
never reads or allocates the claimed size.

Requests look like this:

```json
{"id": 7, "method": "authorize", "params": {"run": "…", "principal": "…", "action": "…", "resource": "…"}}
```

- `id` is an integer from 0 to 2^53 - 1, chosen by the SDK. Each request
  gets exactly one response with the same `id`, so many requests can be in
  flight on one connection and answers can arrive in any order. An `id` may
  be reused once its response has arrived; reusing one that is still in
  flight closes the connection.
- `params` is always an object, `{}` for methods without parameters.
- Unknown fields are refused everywhere, as are duplicate keys in the
  envelope and in typed parameters.
- **String limits count Unicode code points**, as JSON Schema's
  `maxLength` does, so the schema and the connector agree on every string.
  (In TypeScript count with `[...s].length`, not `s.length`, which counts
  UTF-16 units.)
- **Integers are written as integers.** The connector refuses `1.0` or
  `1e3` where an integer is expected. JSON Schema cannot express this (it
  treats `1.0` as an integer), so the fixtures that cover it are marked
  `schema_cannot_express`; SDKs must always emit integers without a fraction
  or exponent.

A response is either `{"id": 7, "ok": {…}}` or `{"id": 7, "error": {…}}`.
The connector pushes messages that are not answers as
`{"push": true, "event": "kill", "data": {…}}`.

## Handshake

The first frame on every connection must be `hello`. On the Unix socket:

```json
{"id": 0, "method": "hello", "params": {"proto": "wl-local/1", "lang": "python", "sdk_version": "0.9.3", "pid": 4242, "required_features": ["kill_push"]}}
```

and the connector answers with the hello answer,
`{"proto": "wl-local/1", "connector_version": "…", "features": [ … ]}`.

On loopback TCP the handshake has two round trips, and the secret itself is
never sent:

1. SDK → `hello` with `nonce_c`: 32 fresh random bytes from a CSPRNG, as 64
   lowercase hex characters.
2. Connector → the challenge `{"nonce_s": "…", "server_proof": "…"}`, with
   a fresh `nonce_s` of its own.
3. The SDK recomputes `server_proof` and compares it in constant time. If it
   does not match, the SDK closes the connection at once and sends nothing
   more: it is not talking to the connector it launched. Only if it matches,
   SDK → `{"method": "auth", "params": {"client_proof": "…"}}`.
4. The connector checks `client_proof` in constant time and answers with the
   hello answer. Any failure is answered `unauthenticated` and the
   connection closes.

The proofs are

```
server_proof = HMAC-SHA256(secret, "wl-local/1 server" ‖ proto ‖ nonce_c ‖ nonce_s ‖ client_ip ‖ client_port ‖ server_ip ‖ server_port)
client_proof = HMAC-SHA256(secret, "wl-local/1 client" ‖ proto ‖ nonce_s ‖ nonce_c ‖ client_ip ‖ client_port ‖ server_ip ‖ server_port)
```

where every field is prefixed by its length as a 4-byte big-endian integer,
so different inputs never encode to the same bytes. `secret`, `nonce_c` and
`nonce_s` are the 32 decoded bytes; `proto` is the string the SDK sent in
`hello`; `client_ip` and `server_ip` are the raw address bytes (4 for
IPv4, 16 for IPv6; an IPv4-mapped IPv6 address counts as its IPv4 form) and
`client_port` and `server_port` are 2-byte big-endian TCP ports, each side
using its own view of the connection (the SDK: its socket's local and peer
address; the connector: the peer's address and its own local address). Both proofs are 64 lowercase hex characters. The Rust helpers for the
SDK side are `verify_server_proof`, `client_proof` and `ChannelBinding::new` (which
takes socket addresses, never names) in `wl-sidecar-core`;
the golden fixtures `server-hello-tcp-challenge.json` (with the secret and
both addresses in its `binding` field) and `client-auth.json` let every SDK check its
implementation.

The whole exchange must finish within 5 seconds of connecting, the first
byte must arrive within 1 second, and no frame before the hello answer may
be larger than 16 KiB.

The answer never carries a CA certificate: the CA that wl-sidecar uses for
interception belongs to the customer, who also distributes trust for it.

The fixtures for the handshake carry a `transport` field (`unix` or `tcp`).
On TCP a `hello` without `nonce_c` is invalid, and the answer to `hello`
must be the challenge; on the Unix socket it must be the hello answer. A
`hello` carrying `secret` (the old single-message form) is refused as an
unknown field.

The connector closes the connection after answering in these cases:

- `unauthenticated`: the first frame is not a valid `hello`; on TCP the
  nonce is missing, the frame after the challenge is not `auth`, or the
  client proof does not verify. Every message sent before the handshake
  completes gets this answer.
- `unsupported_version`: `proto` names another major version, or
  `required_features` lists a feature the connector does not offer. A newer
  minor version (`wl-local/1.4`) is accepted. On TCP this is checked only
  after the client proof has verified, so a peer that does not know the
  secret only ever sees the challenge and `unauthenticated`.

`auth` sent at any other time is answered `invalid`.

## Messages

| Method | Parameters | Answer |
|---|---|---|
| `resolve_agent` | `slug` | `{agent}` (an object, or `null`) |
| `create_session` | `agent_id`, `ttl_seconds` (1 to 86400), optional `goal_id`, `max_actions`, `metadata`, `subject_token`, `application_id`, `workload_ref` | `{run, session_id, execution_id, root_execution_id, scope, manifest?, marker, child_key}` |
| `get_manifest` | `run` | `{manifest}` |
| `authorize` | optional `run`, `principal`, `action`, `resource`, optional `context`, `intent`, `execution_id` (`exec_` and a lowercase UUID; overrides the execution the decision is recorded under) | `{decision}` (wl-apdp's decision) |
| `preflight_step` | `run`, `action`, `resource`, optional `resource_type`, `intent`, `context` | `{result}` |
| `submit_plan` | `run`, `plan` (up to 256 steps) | `{result}` |
| `spawn_subagent` | `parent_run`, `request` | `{child_run, session_id, execution_id, scope, child_marker, child_key}`, or the `denied` error |
| `publish_events` | `run`, `events` (up to 1000), optional `mode`: `decision_path` (delivered at once with a short, bounded retry budget) or `background` (queued on the connector's retry lanes; the default) | `{accepted}` |
| `complete_session` | `run` | `{}` |
| `terminate_session` | `run`, `reason` | `{}` |
| `drain` | `run`, `timeout_ms` (up to 60000) | `{drained}` |
| `session.refresh_marker` | `run` | `{marker}` |
| `session.revoke` | `run` | `{}` |
| `report_connection` | `src_port`, `run` | `{}` |
| `egress_for` | `run` | `{proxy_url, marker_header, marker, child_proxy_url}` (no CA or trust bundle: trust is the customer's) |
| `subscribe_kill` | `run` | `{}`; later the push `kill{run, reason, source}` |
| `health` | none | `{status}` (`ok` or `degraded`) |
| `close` | none | `{}`, then the connector closes the connection |

The objects that wl-apdp validates (`metadata`, `context`, `intent`, plan
steps, events, the spawn request) pass through unchanged. The connector only
limits each of them to 32 levels of nesting and 10,000 values in all; the
frame limit bounds their size.

**Runs belong to the connection that created them.** The connector records
the connection of every run returned by `create_session` or
`spawn_subagent`. A run named on any other connection, in any method
including `report_connection` and `egress_for`, is answered `unknown_run`
by the core of the connector before any decision is made.

After `complete_session`, `terminate_session` or `session.revoke` succeeds,
the run accepts only `drain` and `publish_events` (late lineage) for
10 seconds; every other method gets `run_ended`. After that the run is
forgotten and gets `unknown_run`. A connection holds at most 1024 runs at
once, including ended ones still in those 10 seconds; `create_session` or
`spawn_subagent` past that gets `unavailable` (`retry_after_ms` 1000).

## Errors

An error is `{"code": "…"}`, plus `retry_after_ms` for `unavailable`, and
optionally a `reason` for `denied` and `run_ended`. It never carries a
message or any detail about what went wrong inside the connector.

`reason` comes from a closed list of non-sensitive categories, which the
SDKs map to their typed errors: `scope_attenuation_violation`,
`run_handle_invalidated`, `agent_not_registered`, `goal_not_found`,
`quarantined`, `terminated`, `severed`, `revoked`, `agent_trust_revoked`,
`agent_quarantined`, `agent_unverified` and `delegation_chain_not_trusted`.
It is never server text: any other value, or a `reason` with another code,
is invalid.

The last four carry wl-apdp's typed trust refusal. When wl-apdp refuses a
`create_session`, `get_manifest` or `spawn_subagent` with `401` or `403` and
one of those codes, the connector answers `denied` with that reason. A
refused agent never runs: an SDK refuses the run on any `denied` answer to
`get_manifest`, in every governance mode.

| Code | Meaning |
|---|---|
| `unauthenticated` | No valid `hello` yet, or a wrong secret. The connection closes. |
| `unsupported_version` | Another major version, or a missing required feature. The connection closes. |
| `unknown_run` | The `run` is not known on this connection. |
| `run_ended` | The run has ended. |
| `denied` | Refused (for example a sub-agent spawn that asks for more than its parent has). |
| `unavailable` | Try again after `retry_after_ms`. |
| `invalid` | Unknown method or invalid parameters. The connection stays open. With `"id": null`, the frame itself was malformed and the connection closes. |
| `internal` | The connector failed, including a failure inside one request; the request id is freed and the connection stays open. |

The SDK treats every error, timeout or unparsable answer as a Deny, or
raises `GovernanceUnavailable`.

## Limits and timeouts

- At most 16 requests in flight per connection. The connector stops reading
  while it is at the limit.
- At most 64 MiB of request frames held at once across all connections,
  and at most 8 MiB per connection. A frame's bytes stay reserved until its
  answer has been written to the socket. A connection waits for room before
  reading a frame body, for up to the frame timeout; a frame larger than
  either limit closes its connection. A client that stops reading can
  therefore hold only its own share, and never starves the others.
- At most 8 MiB of answers queued for one connection's socket. A client
  that lets more pile up is disconnected.
- At most 256 control connections; more are closed at accept.
- At most 16 connections per listener may be waiting to complete `hello`
  (configurable). When a new connection arrives and all 16 slots are taken,
  the oldest waiting connection that has not sent anything yet is closed to
  make room (or the oldest of all, if every one has started sending). A
  client that sends its `hello` as soon as it connects is therefore not the
  one closed while silent peers remain, even when a local process keeps
  reconnecting. Waiting connections must send their first byte within
  1 second, and authenticated connections hold no slot.
- Once the first byte of a frame arrives, the whole frame must arrive within
  10 seconds.
- A connection with nothing in flight that sends nothing for 120 seconds is
  closed. SDKs send `health` as a heartbeat, every 30 seconds, while idle.
- A write that does not complete within 10 seconds closes the connection. If
  the SDK stops reading and pushes back up, the connection is closed too.

## When a connection ends

When a control connection ends for any reason (`close`, a lost socket, a
timeout or a protocol violation), every run created on it is killed, on both
sides. The connector stops serving egress for those runs at once. Requests
that were still running get a short grace period to finish, so that a
session they were creating is recorded, and is then ended with the others.
Requests still running when the grace ends are cancelled, and a run that a
request creates after its connection is gone is ended at once, never
registered.
This cleanup runs even if a part of the connector fails while handling the
end of the connection.
