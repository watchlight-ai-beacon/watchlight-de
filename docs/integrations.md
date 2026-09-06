# Governing an agent you already have

You do not have to write your agent around Watchlight. Two integration points
put the same in-process engine in front of code you did not write: a **plugin**
for the agent frameworks, and a **policy enforcement point** for MCP servers.
Both authorize before the call executes, both write the same value-free trail,
and neither asks you to change how the agent is built.

## Already using a framework? Govern it in-process

Bring your existing **LangGraph**, **Pydantic AI**, or **Claude Agent SDK**
agent under governance with zero infrastructure — the *same* plugin you ship to
production, wired to the in-process engine:

```bash
pip install 'watchlight[langgraph]'   # or [pydantic-ai], [claude-agent]
```

```python
from watchlight.langgraph import governed_plugin   # .pydantic_ai / .claude_agent

plugin = governed_plugin("watchlight.policy.json")   # in-process, zero infra

async with await plugin.start_run("research-agent") as handle:
    if not await handle.authorize_action("read", "tool/web_search"):
        raise PermissionError("denied before it executed")
    ...  # your tool runs, every action governed + recorded to .watchlight/audit.jsonl
```

Going to production is one environment variable, not a rewrite — set
`WATCHLIGHT_APDP_URL` and the identical code authorizes against a running policy
service. Runnable examples for all three frameworks are in
[`examples/`](../examples/).

### What a plugin can express, and where

`governed_plugin()` is constructor wiring: it builds the published plugin and
hands it the in-process engine. The governance terms of a single call belong to
the plugin's own run handle, not to the factory.

- **Cedar `context` and the resource: yes, per call.**
  `await handle.authorize_action("read_ticket", "tool/read_ticket", context={"caller": caller, "owner": owner})`
  — a policy that reads `context.*` is satisfiable this way. (`tenant_id` is the
  plugin's own and wins over a value passed here.)
- **An acting subject: yes, per call.**
  `await handle.authorize_action("read_ticket", "tool/read_ticket", principal=f'User::"{user_id}"')`
  — a policy that must name the person or tenant a call is made **for** is
  satisfiable this way. Omitted, the subject defaults to the agent that runs,
  so an existing call is unchanged. Needs `watchlight-agent-sdk` 0.7.0 or
  later, which `watchlight[langgraph|pydantic-ai|claude-agent]` requires.

`governed_plugin()` refuses `principal=`, `context=` and `resource=` by name
rather than forwarding them into a constructor that would drop them — a term you
believe is reaching the decision, and is not, is a policy that never matches.
All three belong on the run handle, and the error says so.

**Name the entity type.** On this path `principal`, `resource` and the action
reach the engine exactly as you write them. A typed reference discriminates:
`User::"u-1"` is not matched by a policy naming `Agent::"u-1"`. A **bare** name is
not typed and not inert: it matches a policy naming that id under `User`,
`Agent`, `Group` or `Role`, and when it matches more than one, an allow beats a
forbid — the opposite of Cedar's usual rule. Name the type. The action is always Cedar
type `Action`; the engine rejects a policy that gives it any other type.

## Govern an MCP server

Put a **policy enforcement point (PEP)** in front of any
[MCP](https://modelcontextprotocol.io) server (spec `2026-07-28`). The MCP PEP
authorizes every governed call — `tools/call`, `resources/read`,
`resources/subscribe`, `prompts/get` — in-process **before** it reaches the
server, so a denied call never executes.

```bash
pip install watchlight-mcp
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

Point your MCP client at `http://127.0.0.1:9700/mcp` instead of the server. A
self-contained, self-demonstrating example (it fires an allowed and a denied
call and proves the denied one never ran) is in
[`examples/governed_mcp_server.py`](../examples/governed_mcp_server.py).

For a stdio-launched server use `serve_stdio(...)`; to run non-blocking and
hot-reload policies use `serve_background(...)`. Pass `tls_cert=`/`tls_key=` to
terminate HTTPS on the listener, and `upstream_ca=` to trust a private
`https://` upstream. See the [MCP server guide](https://docs.watchlight.ai/de/mcp-server).

### Watch the MCP decisions live

`watchlight dev` tails `.watchlight/audit.jsonl` — so give the PEP the **same**
`audit_path` (above) and run the console beside it, from the same directory:

```bash
# terminal 1 — the governed MCP server, auditing to the file the console tails
python examples/governed_mcp_server.py

# terminal 2 — the live console
watchlight dev                # → http://127.0.0.1:7000
```

Every `tools/call` decision streams in — the tool, the upstream it fronts, and
the reason a call was denied. (The example prints the exact
`watchlight dev --audit …` command for its own audit file.)

## See also

- [`examples/`](../examples/README.md) — a runnable governed agent for
  LangGraph, Pydantic AI, the Claude Agent SDK and deepagents, and a
  self-demonstrating governed MCP server.
- [The TypeScript / Node lane](typescript.md) — `governedHooks()` for the Claude
  Agent SDK and `governTool()` / `governTools()` for LangChain / LangGraph.js.
- [The identity model](identity-model.md) — what `principal`, the actor and the
  actor chain mean on a plugin's run handle, and why the entity type matters.
