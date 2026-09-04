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

**Prerequisites:** Python **3.9+**. Prebuilt wheels ship for Linux, macOS, and
Windows — no Rust toolchain, no build step, no account.

```bash
pip install watchlight
```

Prefer an isolated environment? Install into a virtual environment instead:

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install watchlight
```

Save this as `agent.py` and run `python agent.py`:

```python
# agent.py — a complete, runnable program (copy, paste, run).
from watchlight import govern, Denied

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
watchlight: governing 'my-agent' (dev mode, in-process engine)
watchlight: ALLOW  research  tool/web_search
results for: watchlight docs
watchlight: DENY   transfer  tool/transfer_funds     not authorized
watchlight denied intent 'transfer' on tool/transfer_funds: not authorized
```

**That `DENY` line — in your own terminal, in under five minutes, with no
account — is the product.** The `transfer_funds` body never ran.

---

## TypeScript / Node

Same governance, in your Node app — no Python sidecar.
[`@watchlight/sdk`](https://www.npmjs.com/package/@watchlight/sdk) runs the same
compiled engine in-process (WebAssembly).

**Prerequisites:** Node **≥ 18**. `@watchlight/sdk` pulls in the compiled engine
(`@watchlight/engine`) automatically — no native toolchain.

```bash
npm install @watchlight/sdk
```

Then, in an ES-module / TypeScript file (`await` at top level needs `"type":
"module"` or a `.mjs` file):

```ts
// agent.ts — the same DENY line, in Node.
import { govern, Denied } from "@watchlight/sdk";

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

```text
watchlight: governing 'my-agent' (dev mode, in-process engine)
watchlight: ALLOW  research  tool/webSearch
results for: watchlight docs
watchlight: DENY   transfer  tool/transferFunds     not authorized
watchlight denied intent 'transfer' on tool/transferFunds: not authorized
```

It mirrors the Python package feature-for-feature:

- **Runtime context, per-user, human-in-the-loop:**
  `govern.tool(fn, { intent, principal?, resource?, context?, onNeedsApproval?, onResult? })`
  — runtime facts into Cedar `context.*`, per-call `principal`, and a three-state
  `Allow` / `Deny` / **`NeedsApproval`** verdict with a single-use approval token.
- **Govern what a tool returns:** `onResult(result, { intent, resource, principal,
  decisionId })` (Python `on_result`) runs after the body and before the caller
  sees the result — sanitize, screen, or re-authorize on its classification; a
  returned value replaces the payload, a throw withholds it (fail-closed). Writes
  a value-free `egress` audit record joined to the decision by `decision_id`.
- **Frameworks:** `governedHooks()` for the Claude Agent SDK; `governTool()` for
  LangChain / LangGraph.js.
- **Data minimization:** `govern.sanitize(text, { resource, decisionId })` —
  strip PII before an agent reads a document; pass the `decisionId` from
  `authorize` and the `sanitization` audit line joins the decision on
  `decision_id`.
- **Attenuation & graduation:** `govern.scope().attenuate()`; every decision
  returns a `decisionId` to join to your records; `WATCHLIGHT_APDP_URL` graduates
  the *same code* to the control plane.

Full API + runnable examples: [`ts/`](ts/) · npm: `@watchlight/sdk` (glue,
Apache-2.0) + `@watchlight/engine` (the compiled engine). Docs:
[docs.watchlight.ai/de/typescript](https://docs.watchlight.ai/de/typescript).

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

## Test your policies before they gate real actions

A policy is the only thing standing between an agent and a real action, so unit-test
it like any other code. Golden fixtures assert the expected verdict
(`Allow` / `Deny` / `NeedsApproval`) for a `(principal, action, resource, context)`;
a wrong expectation fails the suite. Run it in CI.

```python
from watchlight import govern

govern.load("watchlight.policy.json")
report = govern.test([
    {"name": "under limit allows", "action": "book",
     "context": {"amount": 200, "limit": 500, "refundable": True}, "expect": "Allow"},
    {"name": "over limit denies", "action": "book",
     "context": {"amount": 800, "limit": 500, "refundable": True}, "expect": "Deny"},
    {"name": "big wire needs a human", "action": "wire",
     "context": {"amount": 5000}, "expect": "NeedsApproval"},
])
assert report["failed"] == 0, report
```

`govern.test(...)` (Node: `await govern.test([...])`) drives the engine's decision
core directly, so it **never writes the audit trail** and holds zero decision logic —
every verdict is the engine's. Set `"approved": true` on a fixture to mint a
single-use token and assert the human-confirmed `NeedsApproval → Allow` downgrade.

Or from CI, with the CLI — a `suite.json` of `{ policyFile?, policies?, tests: [...] }`,
exit 1 on any failure:

```bash
watchlight policy test suite.json          # Python
npx watchlight policy test suite.json      # Node
```

---

## Patterns — advanced policies for high-stakes decisions

Past the quickstart, the interesting question is *what to write in the policy*.
The [**governance patterns**](./examples/patterns/) library is a set of
copy-paste recipes for the decisions people reach for the Developer Edition to
govern — spending money, deleting things, messaging the outside world, moving
data, killing a runaway agent. Each is a *problem shape*: a policy, the code that
governs the tool, and tests that prove the verdicts. Every policy is run through
the real engine by [`check.sh`](./examples/patterns/check.sh), so what a pattern
claims and what the engine does can't drift.

The advanced policy JSON — each a runnable `{ policies, tests }` suite with Cedar
`context` conditions and `@enforcement_effect` gates — lives under
[`examples/patterns/suites/`](./examples/patterns/suites/):

| Pattern | The high-stakes question | Policy JSON |
|---|---|---|
| [Money-bounded agent](./examples/patterns/money-bounded-agent.md) | Spend *this much*, on *this*, now — or does a human decide? | [`money-bounded.suite.json`](./examples/patterns/suites/money-bounded.suite.json) |
| [Destructive actions](./examples/patterns/destructive-actions.md) | Delete / drop / deploy: require a human; make some things undeletable. | [`destructive-actions.suite.json`](./examples/patterns/suites/destructive-actions.suite.json) |
| [External messaging](./examples/patterns/external-messaging.md) | May the agent message *outside* — allowlisted destinations only, with review? | [`external-messaging.suite.json`](./examples/patterns/suites/external-messaging.suite.json) |
| [Data egress](./examples/patterns/data-egress.md) | May *this classification* of data cross *this boundary*? | [`data-egress.suite.json`](./examples/patterns/suites/data-egress.suite.json) |
| [Egress after read](./examples/patterns/egress-after-read.md) | Govern what a tool *returns* — decide on the result's classification after the fetch. | [`egress-after-read.suite.json`](./examples/patterns/suites/egress-after-read.suite.json) |
| [Kill-switch / quarantine](./examples/patterns/kill-switch.md) | Stop a suspect agent cold — a hard boundary that beats every grant. | [`kill-switch.suite.json`](./examples/patterns/suites/kill-switch.suite.json) |
| [Per-user attribution](./examples/patterns/per-user-attribution.md) | Attribute the decision to the acting end-user, and scope policy to them. | [`per-user.suite.json`](./examples/patterns/suites/per-user.suite.json) |

Two more recipes — [PII before read](./examples/patterns/pii-before-read.md) and
[sub-agent confinement](./examples/patterns/subagent-confinement.md) — round out
the library. Run every suite at once:

```bash
examples/patterns/check.sh          # runs each suite through the real engine
```

---

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
