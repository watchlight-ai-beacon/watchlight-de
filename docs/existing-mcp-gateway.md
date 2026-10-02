# Using Watchlight with an MCP gateway you already run

This page is for teams whose agents already reach their MCP servers through a
gateway: an Envoy-based proxy, an API gateway, or an MCP-aware router that
authenticates callers, routes them, rate-limits them and logs the traffic. You
keep that gateway. Watchlight goes one hop further in, directly in front of the
MCP server, and decides every tool call against your policy before the server
sees it.

Nothing on the gateway is replaced. Its route for the server points at the
Watchlight MCP policy enforcement point (PEP) instead of at the server, and it
sets one header.

## Where Watchlight sits

```text
  agent ──► your MCP gateway ──► Watchlight MCP PEP ──► MCP server ──► tools
            authenticates the    authorizes each        unchanged
            caller, routes,      tools/call against
            rate-limits, logs    your policy, writes
                                 a value-free audit
                                 record
```

To the gateway, the PEP looks like any other HTTP upstream. MCP clients and
servers talk JSON-RPC, so every request names a method. The PEP reads each
request and checks that method. Four methods are *governed*, because they make
the server do something: `tools/call`, `resources/read`, `resources/subscribe`
and `prompts/get`. For each of these, the PEP asks the Watchlight engine, which
runs inside the PEP's own process, for a decision. The call is forwarded to the
server only when a policy explicitly permits it. When the call is denied, the
PEP answers the caller itself, and the server never sees the request. Every
other method, including `tools/list`, is forwarded unchanged, and the PEP still
writes an audit record for it.

## Why enforcing at the server works with any gateway

- **No traffic is re-routed.** Requests still enter through your gateway and
  follow its routes. The PEP is the last hop before the server, so the decision
  holds whichever gateway, route or client the call came through, as long as the
  server is reachable only through the PEP.
- **Nothing is installed in the gateway.** There is no Watchlight plugin, filter
  or admin-API access to grant. The gateway needs only a route target and a
  header rule, which every gateway supports.
- **No credential changes hands.** Watchlight holds no credential and asks the
  gateway for none, and the gateway needs none from Watchlight. The PEP forwards
  the request's own headers to the server, except for three kinds that it
  strips: hop-by-hop headers, `Mcp-Param-*` mirror headers, and headers that
  only look like Watchlight's (such as `X-Watchlight-Agent-Id` or
  `watchlight_agent_id`). Its audit record never contains tool argument values,
  response bodies, tokens or credentials. It does record the Watchlight
  identity and context headers, such as the agent id and the execution id,
  because those say who made the call.
- **The decision is made on what the server will run.** The PEP reads the
  JSON-RPC body after the gateway has finished with it, so the policy matches
  the tool name the server will actually execute.

## Step by step

### 1. Install

```bash
pip install 'watchlight[mcp]'
```

That command installs two things: the PEP itself (the `watchlight-mcp`
package, version 0.4.4 or later) and the `watchlight` command-line tool you will
use to watch decisions. This page needs version 0.4.4. Earlier releases
accepted a governed call that carried no identity, and they could take the
caller's identity from more than one header, which is unsafe behind a
gateway.

### 2. Write a fail-closed policy

Watchlight denies anything that no policy permits, so you start from "nothing
is allowed" and add what you need. Permit only the tools this caller needs.
Then add a `forbid` policy for any action that must never happen. A `forbid`
always wins over a `permit`, so a broad `permit` that someone adds later still
cannot let that action through.

The PEP reads **one policy object per file**. Each object has an `id`, a `name`
and the Cedar `code`, in the same shape as
[`examples/mcp.policy.json`](../examples/mcp.policy.json). The two files below
let a research agent read from GitHub and stop every caller from deleting a
repository.

`policies/github-read.json`:

```json
{
  "id": "github-read-for-research-agent",
  "name": "github-read-for-research-agent",
  "description": "The research agent may call three read-only GitHub tools. Every other tool, and every other caller, is denied by default.",
  "code": "permit(principal == Agent::\"research-agent\", action, resource) when { context.mcp.server == \"github\" && (context.mcp.tool == \"search_repositories\" || context.mcp.tool == \"get_file_contents\" || context.mcp.tool == \"list_issues\") };"
}
```

`policies/never-delete-repositories.json`:

```json
{
  "id": "never-delete-repositories",
  "name": "never-delete-repositories",
  "description": "No caller deletes a repository, whatever else is permitted later.",
  "code": "forbid(principal, action, resource) when { context.mcp.tool == \"delete_repository\" };"
}
```

When the PEP asks for a decision on an MCP request, it fills in the following
values. Your policies can match on any of them.

| In Cedar | Holds |
|---|---|
| `principal` | `Agent::"<id>"`, built from the `Watchlight-Agent-Id` header (step 4) |
| `action` | the tool name |
| `resource` | `mcp://<upstream_server>/<tool>` |
| `context.mcp.server` | the `upstream_server` name you give the PEP |
| `context.mcp.tool` | the tool name, from the request body |
| `context.mcp.arguments` | the tool's arguments, for `when` conditions on values |

Always write the principal with its type, as in `Agent::"research-agent"`.
A policy that names one specific principal and specific tools fails closed:
any caller or tool it does not name is denied. A bare
`permit(principal, action, resource);` is the opposite. It lets every caller
run every tool, and it should never be loaded in front of a real server.

### 3. Put the PEP in front of the server

`pep.py`, based on
[`examples/governed_mcp_server.py`](../examples/governed_mcp_server.py):

```python
import watchlight_mcp

watchlight_mcp.serve(
    listen_addr="127.0.0.1:9700",                  # the gateway's new upstream
    upstream_url="http://127.0.0.1:3000/mcp",     # your MCP server
    upstream_server="github",                      # the name policies and audit use
    policy_files=[
        "policies/github-read.json",
        "policies/never-delete-repositories.json",
    ],
    audit_path=".watchlight/audit.jsonl",          # the file `watchlight dev` tails
)
```

```bash
python pep.py
```

`serve()` keeps running until you press Ctrl-C. While it runs, it writes
structured JSON logs to standard output, and it writes one audit record per
request to the audit file. Neither the logs nor the audit records contain
tool argument values, response bodies, tokens or credentials.

The security of this setup depends on where the PEP and the server can be
reached from. Two rules matter:

- **The MCP server must be reachable only through the PEP.** Bind it to
  loopback on the PEP's host, or restrict it at the network layer so that
  nothing else can connect to it. A caller that can reach the server directly is
  not governed.
- **The PEP must be reachable only from the gateway.** The PEP trusts the
  identity header it receives (step 4), so anyone who can connect to it can
  claim to be any agent. Keep it on loopback when the gateway
  runs on the same host or in the same pod. When the gateway is elsewhere, give
  the listener TLS and restrict it at the network layer to the gateway's
  addresses:

  ```python
  watchlight_mcp.serve(
      listen_addr="10.0.4.12:9700",
      upstream_url="http://127.0.0.1:3000/mcp",
      upstream_server="github",
      policy_files=["policies/github-read.json", "policies/never-delete-repositories.json"],
      audit_path=".watchlight/audit.jsonl",
      tls_cert="/etc/watchlight/pep-cert.pem",     # PEM chain, leaf first
      tls_key="/etc/watchlight/pep-key.pem",       # issued by your certificate tooling,
  )                                                # readable only by the PEP's user
  ```

  Configure the gateway to verify that certificate against your certificate
  authority (CA). Do not turn verification off. If the MCP server itself uses
  `https://` with a certificate from a private CA, pass that CA's certificate
  to the PEP as `upstream_ca=`. The PEP refuses to talk to an upstream server
  whose certificate does not verify.

### 4. Point the gateway at the PEP

The gateway already has a route that sends this server's traffic to the
server. Change three things in that route:

1. **Upstream.** Send the route to the PEP (`http://127.0.0.1:9700/mcp`, or the
   `https://` address from step 3) instead of the server.
2. **Remove every `Watchlight-*` header the caller sent.** The PEP reads the
   identity and the execution ids from these headers and trusts them as sent.
   If a caller's own `Watchlight-*` headers reach the PEP, the caller chooses
   who the policy thinks it is. When you then set a header in the next step,
   overwrite it rather than append to it. Appending leaves two copies of the
   header, and the PEP refuses a request that carries any `Watchlight-*`
   header more than once.
3. **Set `Watchlight-Agent-Id`** from the identity the gateway has just
   authenticated. Use a stable identifier, such as a client ID or a token's
   subject claim, not a display name. Optionally set `Watchlight-Execution-Id`
   to the gateway's request ID, so each audit record can be joined to the
   gateway's log line for the same call.

The gateway's own authentication, rate limits and logging stay as they are.

A governed call must say who is calling. If one arrives without a
`Watchlight-Agent-Id` header, the PEP refuses it: it answers with HTTP status
400 (bad request) and JSON-RPC error code `-32002`, which is the code the PEP
uses for a missing or refused identity. Methods that are not governed, such
as `initialize` and `tools/list`, do not need an identity.

The PEP also checks the format of every `Watchlight-*` header it reads, on
every request, including `initialize` and `tools/list`. It refuses the request
in the same way when any of these headers appears more than once, is empty, is
longer than 512 bytes, or contains anything other than visible ASCII
characters (so control characters and non-ASCII characters are both refused).
The identity header has three more rules: it must not contain a comma, it must
not name the reserved principal `unattributed`, and a value written as an
entity reference must be a well-formed `Type::"id"`. The PEP also refuses any
request that carries `Watchlight-Principal-Id`, because by default it takes
the identity from `Watchlight-Agent-Id` only.

These checks apply to `Watchlight-Execution-Id` too. If you set it from the
gateway's request ID, as suggested above, make sure that ID is plain visible
ASCII of at most 512 bytes, or every request will be refused.

There is an option, `serve(..., allow_unattributed=True)`, for the rare case
where you deliberately want anonymous callers. With it, a call without an
identity is decided as the principal `Agent::"unattributed"` instead of being
refused. Do not use it behind a gateway. Behind a gateway, a missing header
means the gateway is misconfigured, and the refusal is how you find out.

You can check the PEP before you change the gateway. Send it, by hand, the
same request the gateway will send:

```bash
curl -s http://127.0.0.1:9700/mcp \
  -H 'content-type: application/json' \
  -H 'Watchlight-Agent-Id: research-agent' \
  -H 'Watchlight-Execution-Id: req-0001' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_file_contents","arguments":{"path":"README.md"}}}'
```

The policies above permit that call, so the PEP forwards it and returns the
server's result. Now change the tool name to `delete_repository`. This time the
PEP answers by itself, without contacting the server:

```json
{"jsonrpc":"2.0","id":1,"error":{"code":-32001,"message":"not authorized"}}
```

The caller always gets the same `not authorized` message, whether no policy
permitted the call, a `forbid` matched, or the PEP itself failed. This is
deliberate: the reason would tell a caller how to get around your policy. You
can find the real reason in the audit record.

The table below lists every answer the PEP can give. Each answer has two
parts. The JSON-RPC error code, inside the response body, says what happened
in MCP terms. The HTTP status code is what your gateway sees and counts. Note
that a policy denial comes back with HTTP status 200, because the request
itself was valid and the refusal is a normal JSON-RPC answer.

| Outcome | JSON-RPC error | HTTP status |
|---|---|---|
| Permitted | none: the server's response is relayed | the server's |
| Denied by policy, or the engine failed | `-32001` `not authorized` | 200 |
| No identity on a governed call, or a `Watchlight-*` header refused on any request | `-32002` | 400 |
| `Mcp-Method` or `Mcp-Name` disagrees with the body | `-32020` | 400 |
| Unsupported `MCP-Protocol-Version` | `-32022` | 400 |
| Malformed body, or a missing tool name | `-32602` | 400 |
| The server is unreachable | `-32603` | 502 |

### 5. Watch ALLOW and DENY in the audit trail

The audit file records every decision the PEP makes. To watch the decisions in
a browser, run the local console from the directory the PEP runs in:

```bash
watchlight dev            # → http://127.0.0.1:7000
```

You can also read the file directly. Each governed call is one line of JSON.
The record below is wrapped to fit the page:

```json
{"timestamp":"…","json_rpc_request_id":"1","watchlight_execution_id":"req-0002",
 "principal":"Agent::\"research-agent\"","agent_id":"research-agent",
 "mcp_method":"tools/call","tool":"delete_repository","upstream":"github",
 "decision":"deny","reason":"Policy evaluation completed",
 "policy_id":"never-delete-repositories","policy_name":"never-delete-repositories",
 "policy_effect":"forbid","authorization_latency_us":282}
```

The `decision` field is `permit` or `deny` for a governed call. It is `pass`
for a method that is forwarded without a decision, such as `tools/list`. A
request of any method that the PEP refuses because of its `Watchlight-*`
headers is recorded as `deny`, even a `tools/list`.

The `policy_effect` field tells you *why* a call was denied. A value of
`forbid` means a `forbid` policy explicitly refused the call, and `policy_id`
names that policy. A value of `default-deny` means no policy permitted the
call, so there is no `policy_id`.

The record contains no tool argument values, response bodies, tokens or
credentials. For example, the `path` argument from the request above appears
nowhere in the record, and nowhere in the PEP's process log either. What the
record does contain from the request headers is the Watchlight identity and
context: `agent_id`, `watchlight_execution_id` and, when they are sent, the
task id, the parent execution id, the `traceparent` and the MCP protocol
version. For `resources/read` and `resources/subscribe`, the resource URI is
recorded in the `tool` field with its path replaced by a hash.

## Optional: also govern inside the agent

The PEP sees only the MCP calls that pass through it. If you also own the
agent's code, you can add a second check inside the agent itself. A framework
plugin authorizes each action in the agent's own process, before the request
leaves for the gateway. See
[Governing an agent you already have](integrations.md#a-framework-agent).

With both layers in place, a call has to be permitted twice: once by the
agent's policy before the request is sent, and once by the PEP's policy before
the server runs it. The agent layer is also where you narrow what a sub-agent
may do, using scopes and attenuation (`govern.scope()` and `delegate()`; see
[the identity model](identity-model.md)). The PEP itself does not narrow
scopes.

## Who does what

Your gateway keeps every job it does today. It authenticates callers and
terminates TLS at the edge. It routes each request to the right upstream. It
enforces rate limits and quotas, and it keeps access and traffic logs. The one
new job is to set `Watchlight-Agent-Id` from the identity it authenticated, and
to remove any `Watchlight-*` headers the caller sent.

Watchlight adds the authorization decision. For each governed call, it checks
your Cedar policy against the caller, the tool and, when a policy asks for it,
the values of the tool's arguments. A denied call is blocked before it reaches
the server. If anything goes wrong while deciding, the call is blocked rather
than forwarded. The PEP also refuses a request whose routing headers disagree
with its body. It writes one audit record per request that names the policy
which decided it and contains no argument values. If you also add a framework
plugin to the agent, you get scopes and sub-agent attenuation as well.

## Limitations

This setup has limits you should know about before you rely on it.

- **The identity is asserted, not proven.** The PEP believes whatever
  `Watchlight-Agent-Id` says, and it does not check that the request really
  came from your gateway. This setup is therefore only as strong as the two
  placement rules in step 3 and the header rules in step 4. The PEP's TLS
  listener does not ask for client certificates, and the PEP will run a
  plain-HTTP listener on a non-loopback address without complaint. Restrict
  who can connect to it at the network layer.
- **One server per PEP.** Each `serve()` call sits in front of exactly one
  `upstream_url`. Run one PEP for each server you govern, and give each one its
  own `upstream_server` name.
- **Tool lists are not filtered.** `tools/list` and the other methods that are
  not governed are forwarded unchanged. An agent therefore still sees tools it
  is not permitted to call. If it tries to call one, the call is denied.
- **The audit file is local and unsigned.** It is a JSON Lines file on the
  PEP's host. If you need to keep the records, ship them to your own store.
- **With `serve()`, changing policies needs a restart.** If you want to swap
  policies while the PEP is running, start it with `serve_background(...)`
  instead, and call `reload_policies([...])` on the handle it returns.
- **`serve()` speaks only Streamable HTTP.** Some gateways start MCP servers as
  local processes and talk to them over standard input and output (stdio)
  rather than over HTTP. If yours does, have it launch
  `watchlight_mcp.serve_stdio(...)` instead. That entry point starts the server
  itself. Because stdio has no per-request headers, it takes the identity once,
  as `agent_id=`, for the whole session, and it refuses to start without
  one.

## Troubleshooting

Every problem in the table below fails closed, which means the call does not
reach the server. Find the symptom you see in the first column. The second
column explains what causes it, and the third tells you how to fix it.

| You see | Cause | Fix |
|---|---|---|
| HTTP 400, error `-32002` `a governed call requires Watchlight-Agent-Id` | No identity reached the PEP | Set `Watchlight-Agent-Id` in the gateway route (step 4) |
| HTTP 400, error `-32002` `… is not accepted by this PEP` | The request carries `Watchlight-Principal-Id`, which the PEP does not read by default | Strip every inbound `Watchlight-*` header in the gateway, then set `Watchlight-Agent-Id` |
| HTTP 400, error `-32002` naming `Watchlight-Agent-Id` | The value is empty, longer than 512 bytes, contains a comma, a control character or a non-ASCII character, is a malformed `Type::"id"`, or is `unattributed` | Set one stable, plain identifier per request |
| HTTP 400, error `-32002` saying a header `appears more than once` | The gateway appended a `Watchlight-*` header instead of overwriting it, so the caller's copy is still there | Strip every inbound `Watchlight-*` header, then set yours |
| HTTP 400, error `-32002` naming another `Watchlight-*` header, on any method | `Watchlight-Execution-Id`, `Watchlight-Session-Id` or another context header is empty, repeated, longer than 512 bytes, or not visible ASCII | Fix or drop that header. If you set the execution id from the gateway's request ID, check that ID's format |
| `not authorized`; audit `policy_effect` is `default-deny` | No policy permits this principal and tool | Compare the audited `principal` and `tool` with your policy. If the gateway namespaces tools (`github__get_file_contents`), the PEP sees whatever name the gateway forwards |
| `not authorized`; audit `policy_effect` is `forbid` | A `forbid` matched | `policy_id` names it |
| Every call `not authorized`, `policy_effect` `default-deny` | The PEP started with no `policy_files` | Pass your policy files |
| HTTP 400, error `-32020` | An `Mcp-Method` or `Mcp-Name` header disagrees with the JSON-RPC body | If the gateway rewrites the body, rewrite those headers to match, or drop them; they are optional |
| HTTP 400, error `-32022` | `MCP-Protocol-Version` is one the PEP does not support | The error's `data.supported` lists the versions it accepts |
| HTTP 502, error `-32603` `upstream MCP server unavailable` | The call was permitted but the server did not answer | The audit record still says `permit`; check `upstream_url` and the server |
| Gateway metrics show denials as successful requests | A policy denial is HTTP 200 with a JSON-RPC error | Count JSON-RPC error code `-32001` as a refusal |
| `OSError: cannot read policy file …` at start-up | A path in `policy_files` does not exist | Fix the path; the PEP does not start without it |
| `RuntimeError: engine init failed: … Policy syntax error` | A policy's Cedar does not parse | Fix the policy; the PEP does not start with it |
| `RuntimeError: … policy does not match schema: missing field` followed by `name` | A policy object has no `name` | Add `name` |
| `RuntimeError: … policy does not match schema: invalid type: map` | A policy file holds a list | One policy object per file |
| `RuntimeError: upstream_url must be an http(s) URL` | The upstream is not Streamable HTTP | Use `serve_stdio` for a stdio-launched server |
| `OSError: cannot bind …: Address already in use` | Another process holds `listen_addr` | Stop it or choose another port |
| The gateway reports a TLS certificate error for the PEP | It does not trust the PEP's certificate | Give the gateway the issuing CA. Do not disable verification |

## See also

- [Governing an agent you already have](integrations.md#an-mcp-server) — the PEP's
  entry points and options.
- [`examples/governed_mcp_server.py`](../examples/governed_mcp_server.py) — an
  allowed and a denied call, and proof the denied one never ran.
- [How policy works](policies.md) — default deny, and how `permit` and `forbid`
  combine.
- [The MCP server guide](https://docs.watchlight.ai/de/mcp-server) — the full
  reference, error codes included.
