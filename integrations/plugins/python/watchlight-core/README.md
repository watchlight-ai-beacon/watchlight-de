# watchlight-agent-sdk

**Build governed AI agents.** The Watchlight Agent SDK lets you put a real,
fail-closed authorization decision in front of every action your agent takes —
and record what happened — with the same code whether you run it on your laptop
or across a production fleet.

```bash
pip install watchlight-agent-sdk
```

Import it as `watchlight_core`.

## What it does

Your agent asks "may I do this?" before it acts; Watchlight answers `Allow` or
`Deny` by evaluating your policies, and the action only runs if it's permitted.
The SDK gives you:

- **Authorization** — `authorize_action(action, resource)` gates every step, fail-closed.
- **Preflight** — a cheap read-only "would this be allowed?" check.
- **Lifecycle** — a `RunHandle` per agent run: submit a plan, authorize steps, complete or terminate.
- **Lineage** — canonical, value-free execution events for audit and debugging.
- **Framework plugins** — ready-made integrations for LangGraph, Google ADK, AWS
  Bedrock, Microsoft Agent Framework, Pydantic AI, and more.

The SDK is **glue**: it shapes a request, hands it to a Watchlight backend, and
projects the answer. Every decision is made by the backend — never in this
package — which is why it's open source (Apache-2.0).

## Two backends, same code

The SDK talks to a **backend** through one small interface, so the exact same
agent and plugin code runs against either:

| | Backend | Runs |
|---|---|---|
| **Developer Edition** | `InProcessClient` | The compiled engine, **in-process** — no server, no network |
| **Enterprise** | `ApdpClient` | The governed control plane — signed lineage, drift detection, fleet-wide governance |
| **Enterprise, through the connector** | `SidecarBackend` | The same control plane, reached through the Watchlight connector (`wl-sidecar`) on the same host or pod |

Moving from one to the other is a one-line change, never a rewrite.

## Choosing a backend

`select_backend()` picks the backend for a plugin. The rules are short, and
the SDK never falls back quietly from one backend to another:

1. If you pass a backend explicitly (`select_backend(my_backend)`), that
   backend is used.
2. Otherwise, if `WATCHLIGHT_BACKEND=sidecar` or any Enterprise variable is
   set, the SDK uses `SidecarBackend` and requires the connector. The
   Enterprise variables are every endpoint, credential, run-grant, TLS and
   connector setting the plugins read, such as `WATCHLIGHT_APDP_URL`,
   `WATCHLIGHT_PROXY_URL`, `WATCHLIGHT_PLUGIN_TOKEN`,
   `WATCHLIGHT_CREDENTIAL_FILE`, `WATCHLIGHT_RUN_CREDENTIAL`,
   `WATCHLIGHT_APDP_MTLS_CERT_PATH` and `WATCHLIGHT_SIDECAR_SOCKET`; the
   full list is `watchlight_core.sidecar_backend.ENTERPRISE_ENV_VARS`. If
   the connector is not running or cannot be reached, the run is refused
   with `GovernanceUnavailable`.
3. Otherwise the SDK uses the Developer Edition backend, `InProcessClient`.

`WATCHLIGHT_BACKEND` accepts `sidecar` or `in_process`. Any other value is
refused, and so is `in_process` together with an Enterprise variable.

### How `SidecarBackend` reaches the connector

`SidecarBackend` is a thin client. The connector holds the plugin credential,
every run credential and every egress token, and talks to the control plane
itself. Your process only ever holds an opaque run reference, so no token can
end up in your heap, your logs or an exception.

You tell the SDK where the connector is; it never guesses.

- **A Unix socket** is the preferred way. Set `WATCHLIGHT_SIDECAR_SOCKET` to
  the socket's absolute path. Without it, the SDK uses the connector's default
  path, `$XDG_RUNTIME_DIR/watchlight/control.sock` or
  `/tmp/wl-<uid>/control.sock`. Before connecting, the SDK checks that the
  socket's directory has mode 0700 and belongs to your user, that no parent
  directory lets another user replace it, and that the socket itself is yours.
  After connecting, it asks the kernel which user is on the other end and
  refuses any user but yours.
- **Loopback TCP** is for platforms where a shared socket is not possible. Set
  `WATCHLIGHT_SIDECAR_ADDR` to the connector's address as an IP literal and a
  port, such as `127.0.0.1:41000` or `[::1]:41000` (host names such as
  `localhost` are refused). Set `WATCHLIGHT_SIDECAR_SECRET_FILE` to the path
  of the secret file the connector writes. The secret never goes in an
  environment variable or on a command line, and it never crosses the
  connection: the SDK and the connector prove to each other that they know
  it, and the SDK checks the connector's proof before it sends anything else.
- **A connector you launch yourself**: `SidecarBackend.launch(argv)` starts
  the connector, reads its address and secret from its standard output pipe,
  and keeps the secret in memory only. Once that connector exits, the backend
  never connects to its port again.

Every error, timeout or malformed answer from the connector is treated as a
refusal: `authorize` returns a Deny, and a refused sub-agent spawn raises, so
the child never runs. If the connection to the connector is lost, every run
that was open on it is treated as killed.

A request the connector does not answer within `request_timeout_s` (60
seconds by default) gets its fail-closed answer at that point, but a late
answer alone does not end the connection, because some connector paths are
slow on purpose: a session create that waits on the control plane, or a
lineage publish or session close that the connector retries for up to its
retry budget, which operators can raise to 300 seconds. Instead the SDK then
asks the connector for its health. If that also gets no answer within 5
seconds, the connection is dropped and its runs are treated as killed,
because a connection that has stopped answering can no longer deliver kill
signals either. A run that a timed-out create or spawn makes later is ended
as soon as its answer arrives.

### Egress

`await backend.fetch_egress(run)` returns where the run's outbound traffic
goes: the connector's local proxy URL and the name of the header that carries
the run's marker. It does not return a CA bundle, and the SDK does not change
any trust settings. The connector inspects traffic with a CA that your
organisation issues, and you configure your clients to trust that CA in the
same way you configure any other internal CA.

## Quickstart — a governed decision, zero infrastructure

Install the in-process engine alongside the SDK:

```bash
pip install watchlight-agent-sdk "watchlight-engine>=0.2.5,<0.3"
```

```python
import asyncio
from watchlight_core import InProcessClient

# A Cedar policy: the research agent may read, nothing else.
POLICIES = [
    {"name": "reader",
     "code": 'permit(principal is Agent, action == Action::"read", resource) when { principal.name == "research-agent" };'},
]

async def main():
    gov = InProcessClient(POLICIES)          # real engine decisions, in-process — no network
    agent = await gov.resolve_agent("research-agent")
    me = f'Agent::"{agent["id"]}"'           # the principal: the agent's id, never its slug
    print((await gov.authorize(me, "read", "dataset"))["decision"])    # Allow
    print((await gov.authorize(me, "delete", "dataset"))["decision"])  # Deny

asyncio.run(main())
```

```text
Allow
Deny
```

That `Deny` is the point: the action is refused **before** it runs — by the same
engine that powers the Watchlight platform, with no database and no network.

### Agent-scoped policies

The principal of a governed call is the agent's **id**, `Agent::"<agent uuid>"`,
never its slug. `start_run("research-agent")` resolves the slug to that id before
the first decision. Against wl-apdp the id is the agent's registry id. Under
`InProcessClient` it is the id `resolve_agent` returns, a UUID derived from the
slug. A policy that names the slug as the id, `principal == Agent::"research-agent"`,
therefore matches neither.

Scope a rule to one agent with its attributes instead. Both backends set them from
a trusted source, never from the request:

- `principal.name` is the agent's registered name: the `name` that `resolve_agent`
  returns. On wl-apdp it is the name on the registry record. Under `InProcessClient`
  it is the slug, because the Developer Edition has no other name for an agent.
- `principal.slug` is the slug you start the run with, on both backends. The
  registry derives a slug from the name (an agent registered as `research-agent`
  gets the slug `agent-research-agent`), so when one policy must decide the same on
  both backends, use the slug.

```cedar
permit(principal is Agent, action == Action::"read", resource)
when { principal.name == "research-agent" };
```

- To allow every governed agent, write `principal is Agent`.
- A `forbid` scoped by name or slug applies to that agent. Still prefer a `forbid`
  for every principal, for example
  `forbid(principal, action == Action::"delete", resource);`, and narrow the
  `permit` rules instead: a `forbid` whose condition never matches forbids nothing,
  so a mistyped name there allows what it was meant to stop. A mistyped name in a
  `permit` only denies.
- `principal in Group::"..."` does not match: the engine builds no group membership
  yet.

## Govern a framework agent

Install the plugin for your framework and point it at a backend — your agent code
doesn't change:

```python
from watchlight_langgraph import WatchlightLangGraphPlugin   # or -adk, -bedrock, -pydantic-ai, …
from watchlight_core import InProcessClient

plugin = WatchlightLangGraphPlugin()
plugin.apdp = InProcessClient(POLICIES)      # the one line that differs from production

async with await plugin.start_run("research-agent") as handle:
    if not await handle.authorize_action("read", "dataset"):
        raise PermissionError("denied by policy")
    # ... your agent runs, every action governed ...
```

## Install once at the root

A plugin is installed once, at the root of your agent system, and governs
everything beneath it. Identity is not declared in code: the root run is the
agent your verified credential is bound to, and sub-agents need no
registration.

Open the root run without naming an agent. With `ApdpClient`, Watchlight opens
it as the agent the credential is bound to (an agent API key, or an identity
provider client mapped to an agent) and tells the SDK which agent that is. A
credential that is not bound to one agent, such as a tenant's shared plugin
credential, is refused with `CredentialBindsNoAgent`; nothing guesses an agent.
In the Developer Edition there is no credential, so the process's configured
identity plays that role: `InProcessClient(agent="orchestrator")` or the
`WATCHLIGHT_AGENT` environment variable.

```python
from watchlight_core import InProcessClient, open_root_session

gov = InProcessClient(POLICIES, agent="orchestrator")
session = await open_root_session(gov)        # the run is the credential's agent
print(session.agent_id)
```

Spawn a sub-agent by its label, the name your framework already gives it (a
deepagents or Claude `subagent_type`, an ADK `agent.name`, a Strands node id):

```python
child = await handle.spawn_subagent(child_label="research-agent", allowed_tools=["search"])
```

The child is always attenuated to a strict subset of its parent's scope, under
the usual rules: a time budget above what the parent has left is refused, and
delegation depth is limited. Its label is recorded in lineage and reaches
policy as `context.subagent_label`, as evidence only; it never grants anything.
Without further configuration the child runs as its parent's agent. An
operator can map a label to a registered agent for a tenant, and the child then
runs as that agent, still spawned and attenuated under its parent. In the
Developer Edition the equivalent is `InProcessClient(subagent_agents={"critic":
"critic-agent"})`.

Naming the agent is still supported as an optional override:
`open_root_session(backend, agent_slug="research-agent")`,
`create_session(agent_id=...)`, and `spawn_subagent(child_agent_id=...)` work as
before. When the credential is bound to an agent, Watchlight refuses a name
that does not match it. The connector backend (`SidecarBackend`) still needs the
agent to be named.

## Provider-hosted tools

Some tools run on the model provider's servers during the model call: web
search, code execution, file search, image generation and remote MCP servers.
No framework tool hook runs for them, so a plugin authorizes each one before it
sends the model call. Call `require_hosted_request_allowed` as the last step
before every model call, with the full request you are about to send:

```python
from watchlight_core import HostedToolTurn, require_hosted_request_allowed

turn = HostedToolTurn()  # one per model call
await require_hosted_request_allowed(
    handle,
    request,  # the whole request, not only its tools
    turn,
    registered_mcp_servers={"https://mcp.example.com/mcp": "docs-mcp"},
)
response = await client.call(request)  # reached only when every tool is allowed
turn.seal()
```

Pass the full request, not just its `tools`. Some fields outside `tools` turn
on a hosted capability too, and the gate reads them, at the top level and in
the passthrough scopes `config` (read as Gemini, so a function in
`config.tools` is gated), `extra_body`, `additionalModelRequestFields` (Bedrock
Converse) and `http_options.extra_body` (Gemini):

- `web_search_options` (OpenAI Chat Completions) is decided as `web_search`.
- `prompt` given as anything but a string (an OpenAI Responses stored prompt, which can
  carry its own tools) is decided as `Tool::"stored_prompt"`. It is refused
  unless a policy allows that resource.
- `mcp_servers` (Anthropic) is decided per server, like any remote MCP server.
- `cached_content` (Gemini, which can carry tools) is decided as
  `Tool::"cached_content"`. It is refused unless a policy allows that
  resource.
- `search_parameters` (xAI Live Search) is decided as `live_search`.
- `container` (Anthropic) is decided per skill: each `container.skills` entry
  is one decision on `Tool::"skill"`, with `context.hosted_tool.skill_type`
  and `context.hosted_tool.skill_id` naming it. A container given as an id
  loads no skills. A container that is neither a plain id nor `{id, skills}`
  with well-formed skills is refused, and so is a container or skill entry
  with a key the gate does not know.

The gate makes one decision per hosted tool, as `Action::"execute"` on
`Tool::"<kind>"` (for example `Tool::"web_search"`) with
`context.builtin_tool` set to `true` and `context.hosted_tool` naming the
provider and kind. A remote MCP server is decided as
`Resource::"mcp://<name>/"`, where the name is the one you registered for its
URL. A server you did not register is refused, and so is a server URL with
credentials, a backslash, whitespace, control characters or non-ASCII
characters. An `allowed_tools` list with more than 64 names, or with a name
that is not a plain token, is refused rather than shortened. A deny, a
required approval, an error or a timeout refuses the whole model call, and the
gate never removes a tool to make a call pass.

A `file_search` tool is decided with the stores it searches:
`context.hosted_tool.vector_store_ids` lists them, sorted and without
repeats (OpenAI `vector_store_ids`, Gemini `fileSearchStoreNames`, and in the
Python SDK Pydantic AI `file_store_ids`), so a policy can limit which stores
an agent may search. The same tool with other stores is another decision.
Store ids that are not a list of at most 64 plain ids are refused before any
decision. Store ids and skill ids appear only in the decision's context, never
in a hosted tool's summary.

`require_hosted_request_allowed` raises `HostedToolRefused` on a refusal; its
`gate.result` carries the decision (a required approval keeps its approval
request id, which you must not log). `authorize_hosted_request` returns the
result instead; test its `allowed` attribute, because the result itself has
no truth value and raises `TypeError` if you test it. A turn caches allows
only for its own model call; seal it once the call is made.

For a synchronous model call, use `require_hosted_request_allowed_blocking`.
It takes the same arguments plus `run_loop`, the event loop the run was opened
on. It makes the same decisions on an event loop on another thread while the
calling thread waits. It uses the backend's own I/O-loop thread when the
backend has one (the Enterprise sidecar backend), and otherwise `run_loop` if
that loop is running on another thread. Otherwise it refuses the call. That
covers: no such loop, a caller on that loop's own thread (waiting there would
deadlock), a closed or stopped loop, and no answer within the timeout. A
request that enables no hosted tool passes without any loop.
Any other error, such as a misused turn, an unreadable request or a failure
inside the gate, also refuses the call with `HostedToolRefused`. A run-ending
decision (quarantine, terminate, sever, revoke) raises its own error. Every
refusal seals the turn, so a decision that arrives after the wait gave up is
never reused.

`authorize_hosted_tools` and `normalize_hosted_tools` read a tools list only.
They miss request-level hosted tools; use `require_hosted_request_allowed` for
a full request. A request that is not a mapping or pydantic model, or that
looks like a single tool, raises `TypeError`. So does a passthrough scope or
`toolConfig` that is present but is not a mapping or pydantic model (a list, a
string or another class instance), and scopes nested more than three levels
deep, and a scope that carries two spellings of one key (`extra_body` and
`extraBody`, `http_options` and `httpOptions`, `toolConfig` and `tool_config`,
`additionalModelRequestFields` and `additional_model_request_fields`,
`cached_content` and `cachedContent`): the gate refuses what it cannot read
unambiguously. Mappings and lists are read only as an exact `dict` with
string keys, `list` or `tuple`: a dict subclass, another `Mapping`, a list
subclass or any other iterable (a generator, a view, a custom iterable)
raises `TypeError`, because its iteration can leave out a key or an entry
that the provider SDK's JSON body still carries, or yield different entries
when the SDK iterates it again. A dict value that is callable raises
`TypeError` too, as a function value does in the TypeScript SDK (where
`JSON.stringify` would call a `toJSON` function). A pydantic model is read
from what pydantic serializes (its `__dict__` and its extra fields), never through
attribute access, and a model class that replaces `__getattribute__`,
`__getattr__`, `model_dump`, `model_dump_json` or its serializer, or that has a
custom model or field serializer, a computed field, an excluded field
(`Field(exclude=True)` or `exclude_if`), or an alias naming another field,
raises `TypeError`. A Pydantic AI native tool is read from its dataclass
fields in `__dict__`; a class that hooks attribute access or shadows a field
with a property raises `TypeError`. The TypeScript SDK reads plain
objects only; this SDK also reads pydantic models, because the Python SDKs'
request types (such as google-genai's `GenerateContentConfig`) are pydantic
models. A malformed registry raises
`WatchlightContractError`, and a remote MCP entry that names both a
`server_url` and a `connector_id` is refused as ambiguous. Register an OpenAI
connector under the key `connector:<id>`; a `connector:` string given as a
server URL is refused. A `HostedTool` shows only the server's origin
(`scheme://host[:port]`) and label; the full URL stays private to the registry
lookup. It is not a dataclass field, so `dataclasses.asdict`, `vars`, `copy`
and `pickle` never carry it, and a copied MCP tool is refused as unregistered.

`normalize_hosted_request` and `normalize_hosted_tools` read the OpenAI,
Anthropic, Gemini (including `mcp_servers`), xAI, Bedrock Converse and
Pydantic AI shapes. Function tools are left to the framework's tool hook.
A tool entry of one shape (a function, a Bedrock `toolSpec` or `systemTool`, a
typed entry) that also carries a key another provider reads as a hosted tool
(a Gemini field such as `googleSearch` or `mcpServers`, an MCP `server_url` or
`server_label`, or `systemTool`) raises `TypeError`, as does an entry with
both `systemTool` and `toolSpec`: a provider SDK that copies the keys it knows
would otherwise send a hosted tool that was never decided. A
tool of a shape they do not know is reported by its type name, so a policy
decides it, and without a policy that allows it, it is denied. Summaries
carry no arguments, headers, tokens or URL paths: an MCP server appears by
its host. `publish_hosted_tool_observed` records a hosted tool invocation as
a `tool_call_observed` event with `metadata.hosted_tool` set to `true`.

A plugin whose framework can put hosted tools on a model call sets
`supports_hosted_tools = True` and defines
`async def conformance_hosted_tool_call(self, probe)`, which makes one model
call of `probe.request` through the plugin's own wiring, using
`probe.wrap(handle)` as the run handle, `probe.registered_mcp_servers` as the
registry and `probe.model_client` as the provider client. A plugin that passes
a provider hint to the gate also sets `hosted_tool_provider`. The probe request
carries request-level hosted tools, so a plugin that gates only
`request["tools"]` fails. Conformance invariant 19 drives that hook and fails a
plugin that calls the model without the gate, or after a refusal, and a
plugin whose hook raises while every hosted tool is allowed. The plugins
whose frameworks can carry hosted tools are listed in
`HOSTED_TOOL_PLUGINS_REQUIRED`; one of them that does not declare support
fails, unless it is still in `HOSTED_TOOL_PLUGINS_PENDING`, which must be
empty before the next core release. `check_required_hosted_tool_plugin(module)`
runs invariant 19 for one listed plugin on its own (some never call
`run_conformance`); the core tests run it for every listed plugin in the
environment that installs them all, where a plugin that cannot be imported
fails. A plugin whose constructor needs more than `apdp_url` defines a
`conformance_hosted_tool_instance()` classmethod that returns an instance to
drive.

### Deciding on the request the provider SDK sends

A framework sees only part of what its model integration sends. An
integration can add request fields of its own, such as
`ChatAnthropic(mcp_servers=...)`, so a gate placed in the framework can miss
a hosted tool. `watchlight_core.provider_sdk_gate` makes the decision where
the request leaves the process: it wraps, once and at class level, the method
that every request of a supported provider SDK passes through, and reads the
request body the SDK is about to send.

| SDK | Wrapped | Body read |
|---|---|---|
| `anthropic` (from 0.69) | `SyncAPIClient.request`, `AsyncAPIClient.request` | `json_data` merged with `extra_body`, as the SDK merges them |
| `openai` (from 1.109; also xAI through its base URL) | `SyncAPIClient.request`, `AsyncAPIClient.request`; Realtime `connect` | the same |
| `google-genai` (from 1.53) | `BaseApiClient.request`, `async_request`, `request_streamed`, `async_request_streamed`; Live `connect` | the REST body |

That covers every resource method of those SDKs, including streams, `parse`,
the beta resources and batches. Each request is then treated by its
endpoint. Reads and deletes always pass. A write that matches no row below is
refused, because an API the gate does not know is never assumed to be safe.

| Endpoint | Treatment |
|---|---|
| Anthropic Messages, count tokens | decided |
| Anthropic Message Batches | each request decided; one refusal refuses the batch |
| OpenAI Chat Completions, Responses, input tokens, Completions | decided |
| OpenAI Responses with `previous_response_id` or `conversation` | refused (the tools of the stored response are not in the request) |
| OpenAI Batches | refused (the requests are in a file, not in the request) |
| OpenAI Assistants, Threads and runs | refused (the tools are stored on the server) |
| OpenAI Realtime, Gemini Live | refused (the tools are set over the socket) |
| Gemini `generateContent`, `streamGenerateContent`, `countTokens`, cached contents | decided |
| Gemini batches | refused |
| Files, uploads, embeddings, moderations, audio, images, vector stores, containers, conversations, cancels | pass (they send no tools) |
| Anthropic Skills API (creating a skill or a version) | pass (a skill runs only when a model call loads it, and each loaded skill is decided) |
| Anything else that writes | refused |

The gate acts only inside a governed context. A plugin marks each run with
`attach_run(handle, run_loop=..., registered_mcp_servers=...)` when the run
opens, and ends it with `detach_run(attachment)`. `attach_run` installs the
wraps, and refuses the run with `GovernanceUnavailable` when a wrap was
replaced. Then:

- In the run's own context, while the run is open, a decided request needs an
  allow for every hosted tool it enables, as `require_hosted_request_allowed`
  makes them. A synchronous request waits on
  `require_hosted_request_allowed_blocking`, deciding on the run's loop, so a
  synchronous call made on that loop's own thread is refused rather than
  deadlocking. A refused API raises `ProviderApiRefused`. Nothing is sent
  after a refusal.
- A task that outlived its run still carries the run's context. It is
  refused every request that binds a tool (a function tool or a hosted tool)
  and every refused API.
- Code with no run in its context, while a governed run is live anywhere in
  the process (a bare thread, a fresh `contextvars.Context`), is refused every
  request that binds a tool, with `UnmarkedToolBindingRefused`, and every
  refused API. The refusal is logged at WARNING with the reason
  `unmarked_tool_binding` and counted (`unmarked_refusals()`); it does not end
  the live run. A request that binds no tool passes. As with the other
  process-wide backstops, an unrelated agent in the same process is refused
  while a governed run is live, so run such agents in a separate process.
- With no governed run live, nothing changes.

A function tool alone needs no decision here: the framework's tool hook
decides each call. The plugins' own framework layer sets the run marker and
checks their entry points; the hosted-tool decision is made here.

A request whose path the HTTP client could rewrite before sending is
refused in a governed context, never normalised. That covers a `.` or `..`
segment, an empty segment, a percent-encoded dot, slash or backslash, or a
backslash: `files/../responses` would be sent to `responses`.

What this gate does not cover. It stops mistakes, not deliberate bypass by
code in the same process:

- a subclass of an SDK client that overrides `request` itself, since the wrap
  is on the SDK's base class;
- code that puts a wrapped method's `__wrapped__` original back after a run
  has opened, since the wraps are checked when a run opens, not on every
  request;
- a model call made without one of these SDKs, such as with raw `httpx` or
  another HTTP client.

For those, route the workload's outbound HTTPS through wl-proxy's CONNECT
listener (`HTTPS_PROXY=https://wl-proxy:3128`; see the wl-proxy README).
wl-proxy then decides which hosts the process can reach. In CONNECT mode it
does not read the request body, so it limits where a request can go rather
than deciding the hosted tools in it.

## Custom agents (any framework)

For an agent not built on a supported framework, the `@watchlight` decorator
governs any function:

```python
from watchlight_core import InProcessClient, watchlight

gov = InProcessClient(POLICIES)

@watchlight(agent_id="custom-research", client=gov)
async def run_research(query: str) -> str:
    ...
```

## Optional: OpenTelemetry export

Install the `[otlp]` extra to export a subset of the lineage stream to your OTel
collector (off by default):

```bash
pip install 'watchlight-agent-sdk[otlp]'
```

## Lineage delivery and retries

Lineage events and the run's session close are retried when the server answers
`429`, `502`, `503` (it cannot yet know the run's state) or `504`, or the
connection fails. The SDK waits with exponential backoff and jitter and honours
`Retry-After`. A retried event is deduplicated by its `event_id`. A `500` and
every other `4xx` are final and never retried.

| Variable | Default | Range |
|---|---|---|
| `WATCHLIGHT_LINEAGE_RETRY_MAX_ATTEMPTS` | `6` | 1 to 20 |
| `WATCHLIGHT_LINEAGE_RETRY_MAX_WAIT_SECONDS` | `30` (hard wall-clock bound) | 0 to 300 |

A run's events are sent in call order. Authorization is never retried or delayed by lineage. The
`execution_started` sent before `authorize` is one direct attempt that never
waits behind a retry; if it fails, `authorize` fails closed (an action whose
execution was never started would be dropped from lineage), and a transient
failure is also queued for background delivery. Other events emitted while a
decision is applied (`execution_quarantined`) get one attempt if nothing else
is being sent for the run, and are otherwise queued; such an event can land
after a batch that was being retried when it was emitted, and the lineage view
orders events by timestamp. The quarantine kill signal fires before any
lineage is sent.

When a batch runs out of budget, the SDK logs one WARNING with
`reason=lineage_retry_exhausted` (event types and counts, no payloads), and
the run's later events get one attempt each and are then queued, until one is
delivered. When the run ends, the SDK waits up to one budget for its queued
events. `ApdpClient.lineage_delivery_counters` counts retries, give-ups,
queued batches and cancelled publishes.

## Learn more

- **Documentation:** https://docs.watchlight.ai/de
- **Developer Edition** (zero-infra quickstart) and **Enterprise** (the governed
  control plane): https://watchlight.ai

## License

Apache-2.0.
