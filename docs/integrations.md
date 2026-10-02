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
any identity. Keep the PEP on loopback, or put it behind a gateway that sets
the header itself.

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
