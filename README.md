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
  <a href="https://www.npmjs.com/package/@watchlight/sdk"><img alt="npm" src="https://img.shields.io/npm/v/@watchlight/sdk?color=fbbf24&amp;label=%40watchlight%2Fsdk" /></a>
  <a href="https://www.npmjs.com/package/@watchlight/sdk"><img alt="Node 18+" src="https://img.shields.io/badge/node-18%2B-fbbf24" /></a>
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

## How the pieces fit together

There are two lanes — **Python** and **TypeScript / Node** — and they are one
product: the same compiled engine, the same Cedar policies, the same fail-closed
verdicts, the same value-free audit file. The diagram is the shape of both; the
table under it is how each lane spells it.

```text
                   your code · agents · tools
  ┌────────────┬─────────────────┬──────────────┬──────────────┐
  │ your own   │ LangGraph ·     │ an MCP       │ your own     │
  │ tools      │ Claude Agent ·  │ server       │ app          │
  │            │ Pydantic AI     │              │              │
  └─────┬──────┴────────┬────────┴──────┬───────┴──────┬───────┘
        │               │               │              │
   govern.tool  framework adapter    MCP PEP   govern.authorize
        └───────────────┴───────┬───────┴──────────────┘
                                ▼
                ┌──────────────────────────────┐
                │ Watchlight engine · Cedar    │  the REAL engine —
                │ in-process · zero infra      │  a compiled wheel
                └───────────────┬──────────────┘  or Wasm module
               PERMIT ─ forward │ ─ DENY  (blocked before execution)
                                ▼
   value-free audit → your sink and/or .watchlight/audit.jsonl
                                ▼
    watchlight dev · http://localhost:7000  (reads that file)

  Production = the SAME code, pointed at the governed control plane
  (signed audit · multi-tenant · drift→quarantine · fleet revocation).
```

| What you're governing | Python — `pip install …` | TypeScript / Node — `npm install …` |
|---|---|---|
| **A tool you wrote** | `watchlight` → `@govern.tool(intent=…)` | `@watchlight/sdk` → `govern.tool(fn, { intent })` |
| **A framework agent** | `watchlight[langgraph]` · `[pydantic-ai]` · `[claude-agent]` → `watchlight.<fw>.governed_plugin`; `[deepagents]` for a governed deep-agent tree | `@watchlight/sdk` → `governedHooks()` for the Claude Agent SDK, `governTool()` / `governTools()` for LangChain / LangGraph.js |
| **An MCP server** | `watchlight-mcp` → a policy enforcement point in front of any MCP server | governed on the Python side — an MCP client in **any** language points at the PEP |
| **Your own app, directly** | `watchlight` → `govern.authorize(…)`; `watchlight-agent-sdk` adds the lifecycle SDK — `InProcessClient`, sessions, preflight, local lineage (**imports as `watchlight_core`**) | `@watchlight/sdk` → `await govern.authorize({…})` |
| **The engine itself** | `watchlight-engine` — a compiled wheel, pulled in automatically | `@watchlight/engine` — the same core as WebAssembly, pulled in automatically |

```bash
pip install "watchlight[all]"   # Python — the SDK, every framework plugin, the MCP PEP
npm install @watchlight/sdk     # Node   — the SDK, and the engine with it
```

> `watchlight[all]` is one install for the whole Python lane, so every example in
> the documentation runs after it; note the lifecycle SDK's module name is
> **`watchlight_core`** (there is no `watchlight-core` package on PyPI). On the
> Node lane `@watchlight/sdk` is the only install you need. The `watchlight dev`
> dashboard ships in the Python `watchlight` package and tails
> `.watchlight/audit.jsonl` — the file **both** lanes write by default — so it
> shows a Node agent's decisions too.

---

## Quickstart

Five minutes to a governed `DENY`, in either lane. Prebuilt wheels and a
prebuilt Wasm engine: no Rust toolchain, no build step, no server, no database,
no account.

```bash
pip install watchlight        # Python — 3.9+, prebuilt wheels for Linux, macOS, Windows
npm install @watchlight/sdk   # Node   — 18+, the compiled engine comes with it
```

Prefer an isolated environment on the Python side? `python -m venv .venv &&
source .venv/bin/activate` first (Windows: `.venv\Scripts\activate`).

**Python** — save this as `agent.py` and run `python agent.py`:

```python
# agent.py — a complete, runnable program (copy, paste, run).
from watchlight import govern, configure_default, Denied

# Name the agent: it is what the audit trail records and what a policy reads as
# `context.actor`. Unnamed, the governor still runs but asserts no actor at all.
configure_default(agent="research-agent")

# Permit ONLY the "research" intent. Fail-closed: everything else is denied.
govern.allow('permit(principal, action == Action::"research", resource);')

@govern.tool(intent="research")
def web_search(query: str) -> str:
    return f"results for: {query}"

@govern.tool(intent="transfer")           # governed, but no policy permits it
def transfer_funds(to: str, amount: int) -> str:
    return f"sent ${amount} to {to}"      # never runs — denied first

print(web_search("watchlight docs"))      # ALLOW → the body runs
try:
    transfer_funds("mallory", 1000)       # DENY → refused before the body runs
except Denied as e:
    print(e)
```

```text
$ python agent.py
watchlight: governing 'research-agent' (dev mode, in-process engine)
watchlight: ALLOW  research  tool/web_search
results for: watchlight docs
watchlight: DENY   transfer  tool/transfer_funds     not authorized
watchlight denied intent 'transfer' on tool/transfer_funds: not authorized
```

**TypeScript / Node** — the same program, and the same four output lines,
naming `tool/webSearch` and `tool/transferFunds`. Save it in an ES-module or
TypeScript file (`await` at top level needs `"type": "module"` or a `.mjs`
file):

```ts
// agent.ts — the same DENY line, in Node.
import { govern, configureDefault, Denied } from "@watchlight/sdk";

// Name the agent: it is what the audit trail records and what a policy reads as
// `context.actor`. Unnamed, the governor still runs but asserts no actor at all.
configureDefault({ agent: "research-agent" });

// Permit ONLY the "research" intent. Fail-closed: everything else is denied.
govern.allow('permit(principal, action == Action::"research", resource);');

async function webSearch(query: string) { return `results for: ${query}`; }
async function transferFunds(to: string, amount: number) { return `sent $${amount} to ${to}`; } // never runs

const search   = govern.tool(webSearch,     { intent: "research" });
const transfer = govern.tool(transferFunds, { intent: "transfer" });   // no policy permits it

console.log(await search("watchlight docs"));   // ALLOW → the body runs
try {
  await transfer("mallory", 1000);              // DENY → refused before the body runs
} catch (e) {
  if (e instanceof Denied) console.log(e.message);
}
```

**That `DENY` line — in your own terminal, in under five minutes, with no
account — is the product.** The `transfer_funds` body never ran.

The Node lane's feature-for-feature parity list — approvals, egress hooks,
obligations, the framework adapters — is [the TypeScript / Node
lane](https://github.com/watchlight-ai-beacon/watchlight-de/blob/main/docs/typescript.md).

---

## Who is acting, and on whose behalf

A governed call answers these questions, and they are separate inputs:

| Question | Where it goes | Example |
|---|---|---|
| On whose behalf does this run? | `principal` — the subject | `User::"db:4412"` |
| Which runtime is acting? | the reserved `actor` context key, set by the SDK | `context.actor == "flight-booker"` |
| Through whose delegation? | the reserved `actor_chain` context key | `context.actor_chain.contains("flight-booker")` |
| Under what narrowed authority? | the attenuation scope | `govern.scope(tools=[...])` |

```cedar
// this runtime may book for any user — whoever it acts for
permit(principal is User, action == Action::"book", resource)
when { context.actor == "flight-booker" };
```

That is the difference from an `if`: the policy does not name a caller, it names
*whichever runtime is acting* and *whoever it acts for* — and the SDK sets
`context.actor` itself, from the governor's agent name, refusing a
caller-supplied value that disagrees, so a policy can trust it.

**→ [The identity model](https://github.com/watchlight-ai-beacon/watchlight-de/blob/main/docs/identity-model.md)** — the three cases with exact
values, one engine and many named agents, delegating to a sub-agent, and where
the values come from.

---

## Where to go next

`watchlight dev` opens a local dashboard that streams every decision as it
happens. `govern.test(...)` unit-tests a policy before it gates anything real.
Framework plugins bring an existing LangGraph, Pydantic AI or Claude Agent SDK
agent under governance without touching its code, and an MCP policy enforcement
point governs any MCP server from in front of it. All of that, and the reference
for every option, is behind one door:

→ **[The documentation index](https://github.com/watchlight-ai-beacon/watchlight-de/blob/main/docs/README.md)** — every page, and
when to read it.

Runnable, self-contained programs live in [`examples/`](examples/) — start with
[`governed_research_agent.py`](examples/governed_research_agent.py) in Python or
[`ts/examples/agent.mjs`](ts/examples/agent.mjs) in Node. The copy-paste policy
recipes for the high-stakes decisions — spending money, deleting things,
messaging the outside world, moving data, stopping a runaway agent — are in
[`examples/patterns/`](examples/patterns/), each one run through the real engine
so what a pattern claims and what the engine does cannot drift. The full
reference is on [docs.watchlight.ai/de](https://docs.watchlight.ai/de).

---

## A note on identity

The Developer Edition authorizes the **principal you assert** — the `agent` you construct the governor with, or the `Watchlight-Agent-Id` a governed MCP request carries. (There is no default name: a governor you never named still runs, but it asserts no actor and is recorded as the reserved `<unconfigured>` placeholder.) It does **not** cryptographically *prove* the caller: on your own machine, running both sides, that's the right trade — zero setup, no IdP, no signup. **Bind any non-loopback listener behind something that authenticates the caller** (a reverse proxy doing mTLS/OIDC, or the Enterprise plane).

Identity hardens as you grow, **without changing your policies**:

- **Developer Edition** — the principal is **asserted** (cooperative, local-dev).
- **Next** — an optional **signed session token** binds the principal to a key your process holds, so a prompt-injected sub-agent can't rewrite a header to escalate — still no external infrastructure.
- **Enterprise** — identity is **attested**: federated (OIDC) and workload (mTLS) identity, cryptographically verified across the fleet.

Only *how strongly the principal is proven* changes between these — the policies you write do not.

What the principal *contains* — the subject, the acting runtime, and how a
policy names each — is [The identity model](https://github.com/watchlight-ai-beacon/watchlight-de/blob/main/docs/identity-model.md).

---

## Developer Edition vs Enterprise

The Developer Edition is the real engine, free and in-process; **Enterprise**
points the *same code* — no rewrite — at the governed control plane, adding
signed tamper-evident lineage, multi-tenant isolation, drift→quarantine, and
fleet-wide revocation across every agent and environment.

| Capability | Developer Edition (free / open) | Enterprise |
|---|---|---|
| Policy engine | in-process Cedar, policies from a local `.cedar` file | a running, scaled policy service |
| Sub-agent scope attenuation | engine-side strict-subset validation | same, server-side |
| Scope across processes | HMAC scope token — integrity within one trust domain, not attestation (a secret holder can mint any scope, root included); the receiving engine re-proves the subset | independently attestable scopes |
| Content screening | rule-based, in-process, value-free: `govern.sanitize` (structured PII) + `govern.screen` (prompt-injection / output-leak shapes); not ML classification | a running guardrails service (ML classifiers, NER) |
| Audit | local JSONL, greppable, value-free | a signed, tamper-evident audit service |
| Dashboard | `watchlight dev` → `localhost:7000` (policies + execution lineage) | the full operator console |

Everything the Developer Edition removes is **infrastructure**, never a
**guarantee**. Fail-closed semantics, engine-side attenuation, explicit scopes,
and value-free audit are identical in every mode.

→ **[watchlight.ai](https://www.watchlight.ai)**

---

## Open source, and the license

Everything you write against is **open** and Apache-2.0 — read it, audit it, fork it:

- `watchlight` — the `govern` decorator, `govern.scope` attenuation, the CLI, and the `watchlight dev` dashboard
- the framework plugins — `watchlight-langgraph`, `watchlight-pydantic-ai`, `watchlight-claude-agent`
- the MCP PEP's transport layer, and every example in this repo

You don't have to trust a black box to trust the decisions:

- **The policy language is open.** Decisions are standard [Cedar](https://www.cedarpolicy.com/) — an open, formally-specified language; the same policy yields the same decision, deterministically.
- **The integration layer is open.** The SDK, plugins, CLI, and PEP transport are all readable here, so you can see exactly what the engine is asked and what it returns.
- **Every decision is yours to read.** Each `ALLOW`/`DENY` is emitted value-free to whatever destination you configure — by default `.watchlight/audit.jsonl`, so you can inspect the engine's behaviour on your own machine, tool by tool, with nothing set up.

The **decision engine** ships as a **compiled wheel** — `watchlight-engine`
(the Cedar authorization pipeline) and the `watchlight-mcp` runtime — under the
Watchlight Developer Edition license. Both are **free to use, including in
production and commercially, for up to 25 governed agents per organization**; a
commercial license is needed only above that, or to re-offer the engine itself
as a hosted authorization service. The engine source is the part Watchlight
sells; the code you integrate with is not.

Want the **engine source**, an **air-gapped build**, or to govern a **fleet** in
production? That's the Enterprise plane — [email
sales@watchlight.ai](mailto:sales@watchlight.ai?subject=Watchlight%20Enterprise).
