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

The PEP is an ordinary HTTP upstream to the gateway. It parses each JSON-RPC
request, and for a governed method (`tools/call`, `resources/read`,
`resources/subscribe`, `prompts/get`) it asks the in-process Watchlight engine
for a decision. Only an explicit permit is forwarded. A denied call is answered
by the PEP and never reaches the server. Every other method, `tools/list`
included, is forwarded unchanged and still gets an audit record.

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
  the request's own headers to the server, apart from hop-by-hop headers and
  `Mcp-Param-*` mirror headers, which it strips. It does not write any header
  value to its audit record.
- **The decision is made on what the server will run.** The PEP reads the
  JSON-RPC body after the gateway has finished with it, so the policy matches
  the tool name the server will actually execute.

## Step by step

### 1. Install

```bash
pip install 'watchlight[mcp]'
```

That installs the PEP (`watchlight-mcp`) and the `watchlight` CLI you will use
to watch decisions.

### 2. Write a fail-closed policy

Watchlight denies anything no policy permits. Permit only what this caller
needs, and add a `forbid` for the action you never want, so that a broad
`permit` added later cannot let it through.

The PEP takes **one policy per file**, in the shape of
[`examples/mcp.policy.json`](../examples/mcp.policy.json).

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

What a policy can read on an MCP request:

| In Cedar | Holds |
|---|---|
| `principal` | `Agent::"<id>"`, built from the `Watchlight-Agent-Id` header (step 4) |
| `action` | the tool name |
| `resource` | `mcp://<upstream_server>/<tool>` |
| `context.mcp.server` | the `upstream_server` name you give the PEP |
| `context.mcp.tool` | the tool name, from the request body |
| `context.mcp.arguments` | the tool's arguments, for `when` conditions on values |

Write the principal with its type, `Agent::"research-agent"`. Policies that
name a specific principal and a specific tool fail closed. A bare
`permit(principal, action, resource);` lets every caller run every tool and
should never be loaded in front of a real server.

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
RUST_LOG=warn python pep.py
```

`serve()` blocks until Ctrl-C. `RUST_LOG=warn` keeps the PEP's process log to
warnings and errors (see [Limitations](#limitations) for why). The decisions go
to the audit file either way.

Two placement rules carry the security of this setup:

- **The MCP server must be reachable only through the PEP.** Bind it to
  loopback on the PEP's host, or restrict it at the network layer so that
  nothing else can connect to it. A caller that can reach the server directly is
  not governed.
- **The PEP must be reachable only from the gateway.** The PEP trusts the
  identity header it receives (step 4). Keep it on loopback when the gateway
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

  Have the gateway verify that certificate against your CA. Do not turn
  verification off. If the MCP server itself speaks `https://` with a private
  CA, pass `upstream_ca=` with that CA's certificate. The PEP refuses an
  upstream whose certificate does not verify.

### 4. Point the gateway at the PEP

Change three things in the gateway's route for this server:

1. **Upstream.** Send the route to the PEP (`http://127.0.0.1:9700/mcp`, or the
   `https://` address from step 3) instead of the server.
2. **Remove every `Watchlight-*` header the caller sent.** More than one of them
   feeds the principal. If a caller's own `Watchlight-*` headers reach the PEP,
   the caller chooses who the policy thinks it is.
3. **Set `Watchlight-Agent-Id`** from the identity the gateway has just
   authenticated. Use a stable identifier, such as a client ID or a token's
   subject claim, not a display name. Optionally set `Watchlight-Execution-Id`
   to the gateway's request ID, so each audit record can be joined to the
   gateway's log line for the same call.

The gateway's own authentication, rate limits and logging stay as they are.

To check the PEP before changing the gateway, send it the request the gateway
will send:

```bash
curl -s http://127.0.0.1:9700/mcp \
  -H 'content-type: application/json' \
  -H 'Watchlight-Agent-Id: research-agent' \
  -H 'Watchlight-Execution-Id: req-0001' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_file_contents","arguments":{"path":"README.md"}}}'
```

That call is permitted and returns the server's result. Change the tool name to
`delete_repository`, and the PEP answers without contacting the server:

```json
{"jsonrpc":"2.0","id":1,"error":{"code":-32001,"message":"not authorized"}}
```

The caller always gets the same `not authorized` message, whether no policy
permitted the call, a `forbid` matched, or the PEP failed. The reason is only
in the audit record.

### 5. Watch ALLOW and DENY in the audit trail

From the directory the PEP runs in:

```bash
watchlight dev            # → http://127.0.0.1:7000
```

Or read the file. Each governed call is one JSON line (wrapped here):

```json
{"timestamp":"…","json_rpc_request_id":"1","watchlight_execution_id":"req-0002",
 "principal":"Agent::\"research-agent\"","agent_id":"research-agent",
 "mcp_method":"tools/call","tool":"delete_repository","upstream":"github",
 "decision":"deny","reason":"Policy evaluation completed",
 "policy_id":"never-delete-repositories","policy_name":"never-delete-repositories",
 "policy_effect":"forbid","authorization_latency_us":282}
```

- `decision` is `permit`, `deny`, or `pass` for a method that is forwarded
  without a decision, such as `tools/list`.
- `policy_effect` tells an explicit refusal (`forbid`, with the `policy_id`
  that matched) from an absent grant (`default-deny`, with no `policy_id`).
- There is no field for tool arguments, tokens or other header values. The
  `path` in the request above appears nowhere in the record.

## Optional: also govern inside the agent

The PEP sees only the MCP calls that pass through it. If you also own the agent
code, a framework plugin authorizes each action in the agent process too, before
the request leaves for the gateway. See
[Governing an agent you already have](integrations.md#a-framework-agent).

With both layers, a call has to be permitted twice: once by the agent's policy
before the request is sent, and once by the PEP's policy before the server runs
it. The agent layer is also where sub-agent scopes and attenuation live
(`govern.scope()`, `delegate()`; see [the identity model](identity-model.md)).
The PEP itself does not narrow scopes.

## Who does what

**Your gateway keeps doing:**

- authenticating callers to the gateway, and terminating TLS at the edge;
- routing each request to the right upstream;
- rate limits and quotas;
- access and traffic logs;
- setting `Watchlight-Agent-Id` from the identity it authenticated.

**Watchlight adds:**

- a decision on each governed call against Cedar policy, by principal, by tool,
  and by argument value where a policy asks for it;
- a denied call blocked before it reaches the server, and a call blocked on any
  error rather than forwarded;
- refusal of a request whose routing headers disagree with its body;
- one value-free audit record per request, naming the policy that decided it;
- with a framework plugin in the agent, scopes and sub-agent attenuation.

## Limitations

- **The identity is asserted, not proven.** The PEP builds the principal from
  `Watchlight-*` headers and does not authenticate the gateway. This setup is
  only as strong as the two rules in step 3 and the header rules in step 4. The
  PEP's TLS listener does not request client certificates, so restrict who can
  connect to it at the network layer.
- **One server per PEP.** Each `serve()` fronts one `upstream_url`. Run one PEP
  for each server you govern, each with its own `upstream_server` name.
- **Listing is not filtered.** `tools/list` and other non-governed methods are
  forwarded unchanged, so an agent still sees tools it is not permitted to call.
  Calling one is denied.
- **Process logs at the default level contain argument values.** The audit file
  is value-free, but at the default `info` level the engine logs each request it
  evaluates, arguments included. Run the PEP with `RUST_LOG=warn`, or keep its
  stdout away from shared log pipelines.
- **The audit file is local and unsigned.** It is a JSONL file on the PEP's host.
  Ship it to your own store if you need it kept.
- **Policy changes need a restart with `serve()`.** To swap policies while
  running, start the PEP with `serve_background(...)` and call
  `reload_policies([...])` on the handle it returns.
- **Streamable HTTP for `serve()`.** If your gateway launches MCP servers over
  stdio rather than calling them over HTTP, have it launch
  `watchlight_mcp.serve_stdio(...)` instead. That entry point spawns the server
  itself and takes the identity as `agent_id=` for the whole session, since there
  are no per-request headers.

## Troubleshooting

Every one of these fails closed: the call does not reach the server.

| You see | Cause | Fix |
|---|---|---|
| Every call `not authorized`; audit `principal` is `Agent::"unattributed"` | No `Watchlight-Agent-Id` reached the PEP | Set it in the gateway route (step 4) |
| `not authorized`; audit `policy_effect` is `default-deny` | No policy permits this principal and tool | Compare the audited `principal` and `tool` with your policy. If the gateway namespaces tools (`github__get_file_contents`), the PEP sees whatever name the gateway forwards |
| `not authorized`; audit `policy_effect` is `forbid` | A `forbid` matched | `policy_id` names it |
| Every call `not authorized`, `policy_effect` `default-deny` | The PEP started with no `policy_files` | Pass your policy files |
| HTTP 400, error `-32020` | An `Mcp-Method` or `Mcp-Name` header disagrees with the JSON-RPC body | If the gateway rewrites the body, rewrite those headers to match, or drop them; they are optional |
| HTTP 400, error `-32022` | `MCP-Protocol-Version` is one the PEP does not support | The error's `data.supported` lists the versions it accepts |
| HTTP 502, error `-32603` `upstream MCP server unavailable` | The call was permitted but the server did not answer | The audit record still says `permit`; check `upstream_url` and the server |
| Gateway metrics show denials as successful requests | A policy denial is HTTP 200 with a JSON-RPC error | Count JSON-RPC error code `-32001` as a refusal |
| `OSError: cannot read policy file …` at start-up | A path in `policy_files` does not exist | Fix the path; the PEP does not start without it |
| `RuntimeError: engine init failed: … Policy syntax error` | A policy's Cedar does not parse | Fix the policy; the PEP does not start with it |
| `RuntimeError: … policy does not match schema` | A policy file holds a list | One policy object per file |
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
