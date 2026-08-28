<p align="center">
  <a href="https://www.watchlight.ai">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset=".github/assets/watchlight-logo-white.svg" />
      <img alt="Watchlight" src=".github/assets/watchlight-logo-dark.svg" width="340" />
    </picture>
  </a>
</p>

<h1 align="center">Watchlight — Developer Edition</h1>

<p align="center"><b>Govern an AI agent in five minutes. One install, zero infrastructure, same API as production.</b></p>

<p align="center">
  <a href="https://pypi.org/project/watchlight/"><img alt="PyPI" src="https://img.shields.io/pypi/v/watchlight?color=fbbf24&amp;label=watchlight" /></a>
  <a href="https://pypi.org/project/watchlight/"><img alt="Python 3.9+" src="https://img.shields.io/badge/python-3.9%2B-fbbf24" /></a>
  <a href="LICENSE"><img alt="License: Apache-2.0" src="https://img.shields.io/badge/license-Apache--2.0-blue" /></a>
  <a href="https://docs.watchlight.ai/de"><img alt="Docs" src="https://img.shields.io/badge/docs-docs.watchlight.ai%2Fde-fbbf24" /></a>
</p>

**Watchlight is an Agent Runtime Governance Control Plane** — it puts a policy
decision point in front of every action your AI agents take, authorizing tool
calls and recording a tamper-evident, value-free audit trail.

The **Developer Edition** is the free, open front door to it. It runs the *real*
authorization engine **in-process**, so you can add a governed `ALLOW` / `DENY`
to your agent on your own laptop — no server, no database, no signup. It's for
evaluating the model and shipping governed agents; the code you write here is the
code you run in production — going to production is pointing the same code at the
running control plane, not a rewrite.

> **For enterprises**, Watchlight provides the wider **Agent Runtime Governance
> Control Plane**: signed, tamper-evident lineage; multi-tenant isolation;
> drift & anomaly detection → automatic quarantine; and fleet-wide revocation
> across every agent and environment. → **[watchlight.ai](https://www.watchlight.ai)**

## How the pieces fit together

```text
             your code · agents · tools
  ┌─────────────┬──────────────────┬──────────────┬─────────────┐
  │ @govern.tool│  LangGraph /     │  MCP client  │  custom app │
  │ (decorator) │  Pydantic AI /   │  (any tool)  │             │
  │             │  Claude Agent    │              │             │
  └──────┬──────┴────────┬─────────┴──────┬───────┴──────┬──────┘
         │               │                │              │
     watchlight   watchlight.<fw>   watchlight-mcp    watchlight
      (govern)   .governed_plugin   (PEP · MCP spec)     SDK
         └───────────────┴───────┬────────┴──────────────┘
                                 ▼
                 ┌───────────────────────────────┐
                 │  Watchlight engine · Cedar     │   the REAL engine,
                 │  in-process · zero infra       │   a compiled wheel
                 └───────────────┬───────────────┘
                PERMIT ─ forward │ ─ DENY  (blocked before execution)
                                 ▼
              value-free audit → .watchlight/audit.jsonl
                                 ▼
                 watchlight dev  ·  http://localhost:7000

  Production = the SAME code, pointed at the governed control plane
  (signed audit · multi-tenant · drift→quarantine · fleet revocation).
```

| Package | You use it for |
|---|---|
| `watchlight` | the `govern` decorator + the `watchlight dev` dashboard |
| `watchlight[langgraph\|pydantic-ai\|claude-agent]` | govern an existing framework agent |
| `watchlight-agent-sdk` | the lifecycle SDK — `InProcessClient`, sessions, preflight, local lineage (**imports as `watchlight_core`**) |
| `watchlight-mcp` | govern an MCP server (a policy enforcement point) |
| `watchlight-engine` | the compiled in-process engine (pulled in automatically) |
| **`watchlight[all]`** | **one install for the whole DE** — SDK + every plugin + the MCP PEP; runs every example in the docs |

> **Just want everything?** `pip install "watchlight[all]"` pulls the SDK, all
> framework plugins, and the MCP PEP in one go — so every example on
> [docs.watchlight.ai/de](https://docs.watchlight.ai/de) runs with a single install.
> Note the SDK's module name is **`watchlight_core`** (there is no `watchlight-core`
> package on PyPI).

Runnable, self-contained examples for every one of these are in
[`examples/`](examples/) — start with
[`examples/governed_research_agent.py`](examples/governed_research_agent.py).

---

## Quickstart

> The `govern` decorator, `watchlight dev`, and the framework + MCP integrations
> below all work today. Full guide: [Developer Edition docs](https://docs.watchlight.ai/de).

```bash
pip install watchlight
```

```python
from watchlight import govern

@govern.tool(intent="research")
def web_search(query: str) -> str:
    ...

@govern.tool(intent="transfer")           # governed, but no policy permits it
def transfer_funds(to: str, amount: int) -> str:
    ...
```

```text
$ python agent.py
watchlight: governing 'my-agent' (dev mode, in-process engine)
watchlight: ALLOW  read     tool/web_search
watchlight: DENY   execute  tool/transfer_funds     no matching policy
```

**That `DENY` line — in your own terminal, in under five minutes, with no
account — is the product.**

---

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
[`examples/`](examples/).

---

## Watch every decision live — `watchlight dev`

A zero-dependency local dashboard that tails your value-free audit trail and
shows every governance decision as it happens — the ALLOWs, and the DENYs that
stopped a tool **before** it ran.

```bash
watchlight dev            # → http://127.0.0.1:7000
```

Run your governed agent in another terminal and watch the decisions stream in.
It shows only *this* process — fleet-wide lineage, signed audit, and
drift→quarantine are the governed control plane (Enterprise).

---

## Govern an MCP server

Put a policy decision point in front of any [MCP](https://modelcontextprotocol.io)
server (spec `2026-07-28`). Every governed call — `tools/call`, `resources/read`,
`resources/subscribe`, `prompts/get` — is authorized in-process **before** it
reaches the server, so a denied call never executes.

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
[`examples/governed_mcp_server.py`](examples/governed_mcp_server.py).

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

---

## What runs locally

| Capability | Developer Edition (free / open) | Enterprise |
|---|---|---|
| Policy engine | in-process Cedar, policies from a local `.cedar` file | a running, scaled policy service |
| Sub-agent scope attenuation | engine-side strict-subset validation | same, server-side |
| Content / PII screening | policy-based, in-process | a running guardrails service |
| Audit | local JSONL, greppable, value-free | a signed, tamper-evident audit service |
| Dashboard | `watchlight dev` → `localhost:7000` (policies + execution lineage) | the full operator console |

Everything the Developer Edition removes is **infrastructure**, never a
**guarantee**. Fail-closed semantics, engine-side attenuation, explicit scopes,
and value-free audit are identical in every mode.

---

## Open source, and the compiled engine

Everything you write against is **open** and Apache-2.0 — read it, audit it, fork it:

- `watchlight` — the `govern` decorator, `govern.scope` attenuation, the CLI, and the `watchlight dev` dashboard
- the framework plugins — `watchlight-langgraph`, `watchlight-pydantic-ai`, `watchlight-claude-agent`
- the MCP PEP's transport layer, and every example in this repo

The **decision engine** ships as a **compiled wheel** — `watchlight-engine` (the Cedar authorization pipeline) and the `watchlight-mcp` runtime — both **free to use, including in production and commercially — for up to 25 governed agents per organization** (a commercial license is needed only above that, or to re-offer the engine itself as a hosted authorization service). The engine source is the part Watchlight sells; the code you integrate with is not.

You don't have to trust a black box to trust the decisions:

- **The policy language is open.** Decisions are standard [Cedar](https://www.cedarpolicy.com/) — an open, formally-specified language; the same policy yields the same decision, deterministically.
- **The integration layer is open.** The SDK, plugins, CLI, and PEP transport are all readable here, so you can see exactly what the engine is asked and what it returns.
- **Every decision is on disk.** Each `ALLOW`/`DENY` is appended, value-free, to `.watchlight/audit.jsonl` — inspect the engine's behaviour on your own machine, tool by tool.

Want the **engine source** or an **air-gapped build**? That's Enterprise — [email sales@watchlight.ai](mailto:sales@watchlight.ai?subject=Watchlight%20Enterprise).

---

## A note on identity

The Developer Edition authorizes the **principal you assert** — the `agent` you construct the governor with, or the `Watchlight-Agent-Id` a governed MCP request carries. It does **not** cryptographically *prove* the caller: on your own machine, running both sides, that's the right trade — zero setup, no IdP, no signup. **Bind any non-loopback listener behind something that authenticates the caller** (a reverse proxy doing mTLS/OIDC, or the Enterprise plane).

Identity hardens as you grow, **without changing your policies**:

- **Developer Edition** — the principal is **asserted** (cooperative, local-dev).
- **Next** — an optional **signed session token** binds the principal to a key your process holds, so a prompt-injected sub-agent can't rewrite a header to escalate — still no external infrastructure.
- **Enterprise** — identity is **attested**: federated (OIDC) and workload (mTLS) identity, cryptographically verified across the fleet.

Only *how strongly the principal is proven* changes between these — the policies you write do not.

---

## Developer Edition vs Enterprise

The Developer Edition is the real engine, free and in-process; **Enterprise**
points the *same code* — no rewrite — at the governed control plane, adding
signed tamper-evident lineage, multi-tenant isolation, drift→quarantine, and
fleet-wide revocation across every agent and environment.

→ **[watchlight.ai](https://www.watchlight.ai)**

---

## License

The Developer-Edition SDK, the framework plugins, this repository, and the
`watchlight dev` dashboard are **Apache-2.0** — use, fork, and ship them freely.
The authorization **engine** (`watchlight-engine`) and the MCP runtime
(`watchlight-mcp`) ship as **compiled wheels** under the Watchlight Developer
Edition license; they are **free to use, including in production and
commercially, for up to 25 governed agents per organization** — a commercial
license is needed only above that, or to re-offer the engine itself as a hosted
authorization service.

Want the **engine source**, an **air-gapped build**, or to govern a **fleet** in
production? That's the Enterprise plane — [email
sales@watchlight.ai](mailto:sales@watchlight.ai?subject=Watchlight%20Enterprise).
