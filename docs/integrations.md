# Governing an agent you already have

You do not have to write your agent around Watchlight. A **plugin** governs a
framework agent; a **policy enforcement point** governs an MCP server. Both
authorize before the call executes, and neither changes how the agent is built.

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

This is the same plugin you ship to production. Going there is one environment
variable — set `WATCHLIGHT_APDP_URL` and the identical code authorizes against a
running policy service.

Runnable agents for all three frameworks are in [`examples/`](../examples/).

### Per-call governance goes on the run handle

`governed_plugin()` is constructor wiring. The terms of a single call belong to
the handle:

```python
await handle.authorize_action(
    "read_ticket", "tool/read_ticket",
    principal=f'User::"{user_id}"',                     # who the call is for
    context={"caller": caller, "owner": owner},         # what a policy reads
)
```

`principal` defaults to the agent that runs, so existing calls are unchanged.
Needs `watchlight-agent-sdk` 0.7.0 or later, which the extras already require.

Pass `principal=`, `context=` or `resource=` to `governed_plugin()` and it
refuses them by name rather than dropping them silently.

**Name the entity type.** `User::"u-1"` is not matched by a policy naming
`Agent::"u-1"`. A bare `u-1` is not inert: it matches that id under `User`,
`Agent`, `Group` or `Role`, and when it matches more than one, an allow beats a
forbid — the opposite of Cedar's usual rule. Always write the type. The action
is always type `Action`; a policy that gives it another type is rejected.

## An MCP server

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

Point your MCP client at `http://127.0.0.1:9700/mcp` instead of the server. Every
governed call — `tools/call`, `resources/read`, `resources/subscribe`,
`prompts/get` — is authorized in-process before it reaches the server, so a
denied call never executes. The PEP implements MCP spec `2026-07-28`.

[`examples/governed_mcp_server.py`](../examples/governed_mcp_server.py) fires an
allowed and a denied call and proves the denied one never ran.

Other entry points:

- `serve_stdio(...)` for a stdio-launched server.
- `serve_background(...)` to run non-blocking, with policy hot-reload.
- `tls_cert=` / `tls_key=` to terminate HTTPS on the listener, `upstream_ca=` to
  trust a private `https://` upstream.

### Watch the decisions

`watchlight dev` tails `.watchlight/audit.jsonl`, so give the PEP that same
`audit_path` and run the console from the same directory:

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
- [The MCP server guide](https://docs.watchlight.ai/de/mcp-server).
