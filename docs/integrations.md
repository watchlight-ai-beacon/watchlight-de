# Governing an agent you already have

You do not have to rebuild your agent around Watchlight. There are two ways to
add governance to an agent you already have. If the agent is built on a
supported framework, a **plugin** governs it from inside the agent process. If
the agent calls an MCP server, a **policy enforcement point** (PEP) sits in
front of that server and governs the calls that reach it. Both check each call
against your policy before it runs, and neither changes how the agent is
built.

## A framework agent

```bash
pip install 'watchlight[langgraph]'   # or [pydantic-ai], [claude-agent]
```

```python
from watchlight.langgraph import governed_plugin   # .pydantic_ai / .claude_agent

plugin = governed_plugin("watchlight.policy.json")   # in-process, zero infra

async with await plugin.start_run("research-agent") as handle:
    if not await handle.authorize_action("read", "tool/web_search"):
        raise PermissionError("denied before it executed")
    ...  # your tool runs, every action recorded to .watchlight/audit.jsonl
```

This is the same plugin you ship to production. Moving to production takes one
environment variable: set `WATCHLIGHT_APDP_URL`, and the same code authorizes
against a running policy service instead of in-process.

Runnable agents for all three frameworks are in [`examples/`](../examples/).

### What the plugin records

Every decision the plugin makes writes one decision record to the audit trail.
It is the same record that `Watchlight.authorize` writes: the agent, the
principal, the action (in the `intent` field), the resource, the verdict, and
`"event": "decision"`. It never contains the values the call carried. The Cedar
`context` and the declared intent are not recorded.

A record written by a plugin has two differences from one written by the
governor:

- It carries `execution_id`, the execution id the decision was made under. That
  is normally the run's id, which the run's `execution_started` and
  `execution_completed` lines also carry. If you pass your own `execution_id` to
  `authorize_action`, the record carries yours, and no lifecycle line has it.
- It has no `decision_id`, because the plugin does not return one to join on.

A decision made by a sub-agent names the sub-agent as `agent`, and carries the
delegation chain, root first, in `actor_chain`, the same field a governor made
with `delegate()` writes. Once a run is quarantined or severed, the plugin
refuses every later call itself, without asking the policy engine. Each of
those refusals is recorded as a `Deny` too. That covers the handle
`start_run` returns, every sub-agent handle `spawn_subagent` returns, the
Claude Agent SDK's native Task sub-agents, and the handles Pydantic AI's
automatic instrumentation opens. One route is not covered: a handle you read
from `watchlight_core.current_subagent_handle()` is the SDK's own handle, so a
refusal it makes on its own is not recorded. Use the handle that
`spawn_subagent` returned instead.

The principal, action, resource, `execution_id` and agent names are recorded
exactly as the call gave them, never shortened or rewritten, so `counters()`
can match them exactly. The JSON encoding keeps every record on one line,
whatever characters they contain. Agent names are not checked, because a
refusal raised inside a framework's own hook can leave that framework running
the call without governance. A plugin agent named `<unconfigured>` is
therefore recorded under that name.

The run handle a governed plugin returns is a wrapper around the SDK's handle.
It behaves the same, but `isinstance(handle, BaseRunHandle)` is `False` for it.

The gate is `handle.authorize_action`. A `handle.preflight_step` call is
advisory: it tells you what `authorize_action` would decide, but it does not
stop anything, does not count toward the run's budget, and writes no record.

The run itself still writes two lifecycle lines to the same file:
`execution_started` when the run begins and `execution_completed` when it ends.
These lines name their kind in an `event_type` field and have neither an
`event` nor a `decision` field.

Before this release, the plugin wrote only the two lifecycle lines, so
`counters()` and the forensics queries saw none of its decisions. They count
them now. See [breaking changes](breaking-changes.md) if a quota of yours counts
decisions.

To send the decision records to your own store as well, pass the same sink
options that `Watchlight` takes. They have the same meaning there:

```python
plugin = governed_plugin(
    "watchlight.policy.json",
    audit_sink=insert_many,      # receives a list, because batching is on
    audit_sink_batch=100,        # hand the sink lists from a background worker
    audit_sink_interval=2.0,     # and hand over a partial list after 2 seconds
)
```

The sink receives the decision records only. The lifecycle and attenuation
lines go to the file. A sink failure never changes a decision, and it is
reported once on stderr. A plain (synchronous) sink without batching runs
inside the decision and adds its own time to it. On the plugin path the
decision is made on your event loop, so a slow synchronous sink also holds up
every other task on that loop. Use batching, as above, or an `async` sink,
which is scheduled on the loop instead of awaited.

When `WATCHLIGHT_APDP_URL` is set, the policy service records the decisions,
and the sink options are not used. The plugin prints a warning once to say so.
If you build a plugin yourself around `in_process_backend()` instead of using
`governed_plugin()`, every decision the engine makes is recorded, but the
refusals the plugin makes on its own after a quarantine or a sever are not.

### Framework-created subagents inherit framework tools

Some frameworks automatically create a general-purpose subagent and give it
the parent's full tool list. Watchlight can only narrow a scope when the
framework asks it to authorize something, so it cannot narrow a subagent that
the framework sets up on its own. You have to configure the framework instead.
In deepagents, for example, pass your own subagent spec with the same name,
`general-purpose`, in the `subagents` argument to `create_deep_agent(...)`.
That replaces the automatic one, so it does not inherit the parent's custom
tools:

```python
subagents=[{
    "name": "general-purpose",
    "description": "General-purpose agent without parent custom tools.",
    "system_prompt": "Complete the delegated task.",
    "tools": [],
}]
```

An empty `tools` list does not remove tools that the framework's middleware
adds, such as deepagents' filesystem tools. If the subagent needs to be
confined more tightly, configure those separately.

### Per-call governance goes on the run handle

`governed_plugin()` sets the plugin up once, so it only takes settings that
apply to every call. Anything that belongs to a single call, such as who the
call is for, goes on the run handle when you authorize that call:

```python
await handle.authorize_action(
    "read_ticket", "tool/read_ticket",
    principal=f'User::"{user_id}"',                     # who the call is for
    context={"caller": caller, "owner": owner},         # what a policy reads
)
```

If you leave out `principal`, it defaults to the agent that is running, so
calls you have already written keep working unchanged. These arguments need
`watchlight-agent-sdk` 0.7.0 or later, which the extras already require.

If you pass `principal=`, `context=` or `resource=` to `governed_plugin()`
instead, it raises an error that names the argument. It does not silently
ignore it.

**Always name the entity type.** A policy that names `Agent::"u-1"` does not
match `User::"u-1"`. Leaving the type off is not harmless either: a bare `u-1`
matches that id as a `User`, an `Agent`, a `Group` or a `Role`. When it matches
more than one of those, an allow beats a forbid, which is the opposite of
Cedar's usual rule. So always write the type. The action is always of type
`Action`, and a policy that gives it another type is rejected.

## An MCP server

```bash
pip install 'watchlight[mcp]'   # watchlight-mcp 0.4.4 or later
```

```python
import watchlight_mcp

watchlight_mcp.serve(
    listen_addr="127.0.0.1:9700",
    upstream_url="http://localhost:3000/mcp",   # the MCP server you're governing
    upstream_server="github",
    policy_files=["examples/mcp.policy.json"],
    audit_path=".watchlight/audit.jsonl",       # ← the file `watchlight dev` tails
)
```

`watchlight-mcp` reads one policy object per file. `govern.load()` reads the
same shape, so one policy file can govern both an in-process agent and the
PEP.

Point your MCP client at `http://127.0.0.1:9700/mcp` instead of at the server.
Four MCP methods are governed, because they make the server do something:
`tools/call`, `resources/read`, `resources/subscribe` and `prompts/get`. The
PEP authorizes each of these calls in its own process before passing it on, so
a denied call never reaches the server. The PEP implements version
`2026-07-28` of the MCP specification.

The client must send a `Watchlight-Agent-Id: <agent>` header on every request.
The PEP turns it into the principal, `Agent::"<agent>"`, that your policies
match on. Since `watchlight-mcp` 0.4.4, the PEP refuses a governed call that
has no such header. It answers with HTTP status 400 (bad request) and JSON-RPC
error code `-32002`, the code it uses for a missing or refused identity. The
PEP does not verify the header, so anyone who can reach the listener can claim
any identity. Keep the PEP on loopback, or put it behind a gateway. That
gateway must strip every `Watchlight-*` header the caller sent and then set
`Watchlight-Agent-Id` from the identity it authenticated. Adding the header
only when it is missing is not enough, because a caller could then choose its
own identity. See
[Using Watchlight with an MCP gateway you already run](existing-mcp-gateway.md).

[`examples/governed_mcp_server.py`](../examples/governed_mcp_server.py) makes
one allowed call and one denied call, and shows that the denied one never
ran.

If your MCP traffic already goes through a gateway, you can keep it. Put the
PEP between the gateway and the server, as described in
[Using Watchlight with an MCP gateway you already run](existing-mcp-gateway.md).

`serve()` is not the only way to start the PEP. Use `serve_stdio(...)` for an
MCP server that is launched as a local process and talks over standard input
and output. Use `serve_background(...)` when you do not want the call to block;
it also lets you reload policies while the PEP is running. To serve HTTPS on
the PEP's own listener, pass `tls_cert=` and `tls_key=`. If the MCP server uses
`https://` with a certificate from a private certificate authority, pass that
authority's certificate as `upstream_ca=` so the PEP can verify it.

### Watch the decisions

`watchlight dev` is a local console that follows `.watchlight/audit.jsonl` as
decisions are written to it. Give the PEP that same `audit_path`, and run the
console from the same directory:

```bash
python examples/governed_mcp_server.py   # terminal 1
watchlight dev                           # terminal 2 → http://127.0.0.1:7000
```

## See also

- [`examples/`](../examples/README.md) — governed agents for LangGraph, Pydantic
  AI, the Claude Agent SDK and deepagents, plus the governed MCP server.
- [The TypeScript / Node lane](typescript.md) — `governedHooks()` and
  `governTool()` for the Node frameworks.
- [The identity model](identity-model.md) — what `principal`, the actor and the
  actor chain mean on a run handle.
- [Using Watchlight with an MCP gateway you already run](existing-mcp-gateway.md)
  — the PEP behind a gateway, the headers the gateway sets, and the failures
  you will see.
- [The MCP server guide](https://docs.watchlight.ai/de/mcp-server).
