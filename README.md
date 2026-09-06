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

Watchlight puts a policy decision point in front of every action your agents
take. It authorizes each tool call and records a value-free audit trail.

The **Developer Edition** runs the real authorization engine **in-process**. No
server, no database, no signup — a governed `ALLOW` / `DENY` on your laptop, in
the same code you ship to production.

```bash
pip install watchlight        # Python 3.9+, prebuilt wheels
npm install @watchlight/sdk   # Node 18+, the compiled engine comes with it
```

## Quickstart

**Python** — save as `agent.py`, run `python agent.py`:

```python
from watchlight import govern, configure_default, Denied

configure_default(agent="research-agent")                # the name on every record

# Permit ONLY "research". Fail-closed: everything else is denied.
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

**TypeScript / Node** — the same program (`"type": "module"` or a `.mjs` file):

```ts
import { govern, configureDefault, Denied } from "@watchlight/sdk";

configureDefault({ agent: "research-agent" });

govern.allow('permit(principal, action == Action::"research", resource);');

async function webSearch(query: string) { return `results for: ${query}`; }
async function transferFunds(to: string, amount: number) { return `sent $${amount} to ${to}`; }

const search   = govern.tool(webSearch,     { intent: "research" });
const transfer = govern.tool(transferFunds, { intent: "transfer" });   // nothing permits it

console.log(await search("watchlight docs"));   // ALLOW → the body runs
try {
  await transfer("mallory", 1000);              // DENY → refused before the body runs
} catch (e) {
  if (e instanceof Denied) console.log(e.message);
}
```

Both lanes print the same decisions:

```text
watchlight: governing 'research-agent' (dev mode, in-process engine)
watchlight: ALLOW  research  tool/web_search
results for: watchlight docs
watchlight: DENY   transfer  tool/transfer_funds     not authorized
watchlight denied intent 'transfer' on tool/transfer_funds: not authorized
```

Node names the same tools `tool/webSearch` and `tool/transferFunds`. Both also
print a one-time note that no audit sink is configured.

**That `DENY` is the product.** The `transfer_funds` body never ran, and the
decision is already on disk in `.watchlight/audit.jsonl`.

## What you can govern

| | Python — `pip install …` | Node — `npm install …` |
|---|---|---|
| **A tool you wrote** | `watchlight` → `@govern.tool(intent=…)` | `@watchlight/sdk` → `govern.tool(fn, { intent })` |
| **A framework agent** | `watchlight[langgraph]` · `[pydantic-ai]` · `[claude-agent]` · `[deepagents]` | `governedHooks()` for the Claude Agent SDK, `governTool()` for LangChain / LangGraph.js |
| **An MCP server** | `watchlight-mcp` — a policy enforcement point in front of any MCP server | point any MCP client at that same PEP |
| **Your own app** | `govern.authorize(…)`; `watchlight-agent-sdk` adds sessions, preflight and local lineage (it imports as **`watchlight_core`**) | `await govern.authorize({…})` |

`pip install "watchlight[all]"` is one install for the whole Python lane, and
every Python example in the documentation runs after it. On the Node lane
`@watchlight/sdk` is the only install you need.

Both lanes write `.watchlight/audit.jsonl`, and `watchlight dev` tails it:

```bash
watchlight dev            # → http://localhost:7000
```

## Who is acting, and on whose behalf

A governed call answers two separate questions.

```cedar
// this runtime may book for any user — whoever it acts for
permit(principal is User, action == Action::"book", resource)
when { context.actor == "flight-booker" };
```

| Question | Where it goes |
|---|---|
| On whose behalf does this run? | `principal` — the subject, e.g. `User::"db:4412"` |
| Which runtime is acting? | `context.actor`, set by the SDK from the agent name |
| Through whose delegation? | `context.actor_chain` |
| Under what narrowed authority? | `govern.scope(tools=[...])` |

That is what separates a policy from an `if`: it names *whichever runtime is
acting* and *whoever it acts for*. The SDK sets `context.actor` itself and
refuses a caller-supplied value that disagrees, so a policy can trust it.

## Where to go next

→ **[The documentation index](https://github.com/watchlight-ai-beacon/watchlight-de/blob/main/docs/README.md)**
— every page, and when to read it.

Runnable programs live in [`examples/`](examples/) — start with
[`governed_research_agent.py`](examples/governed_research_agent.py) or
[`ts/examples/agent.mjs`](ts/examples/agent.mjs). Copy-paste policy recipes for
the high-stakes decisions — spending money, deleting things, messaging the
outside world, stopping a runaway agent — are in
[`examples/patterns/`](examples/patterns/), each one run through the real engine.

## A note on identity

The Developer Edition authorizes the principal you **assert** — the `agent` you
construct the governor with, or the `Watchlight-Agent-Id` on a governed MCP
request. It does not cryptographically *prove* the caller. On your own machine,
running both sides, that is the right trade.

**Bind any non-loopback listener behind something that authenticates the
caller** — a reverse proxy doing mTLS or OIDC, or the Enterprise plane.

Identity hardens as you grow, **without changing your policies**:

- **Developer Edition** — the principal is asserted (cooperative, local dev).
- **Next** — an optional signed session token binds the principal to a key your
  process holds, so a prompt-injected sub-agent cannot rewrite a header to
  escalate. It still needs no external infrastructure.
- **Enterprise** — identity is attested: federated (OIDC) and workload (mTLS),
  verified across the fleet.

Only *how strongly the principal is proven* changes. The policies do not.

## Developer Edition vs Enterprise

Enterprise points the *same code* at a running control plane — no rewrite. What
changes is what happens around the decision.

**What the Developer Edition does, and Enterprise keeps**

| Capability | Developer Edition | Enterprise |
|---|---|---|
| Allow / require approval / deny, on real Cedar | ✅ in-process engine, policies from a local file | ✅ a running, scaled decision service |
| Strict-subset sub-agent attenuation | ✅ engine-side, to a depth of 5 | ✅ server-side, unbounded |
| Human-in-the-loop approvals | ✅ single-use tokens | ✅ across the fleet, with an operator queue |
| Content screening | ✅ rule-based: `govern.sanitize`, `govern.screen` | ✅ a guardrails service with ML classifiers |
| Framework plugins | ✅ LangGraph, Pydantic AI, Claude Agent SDK, DeepAgents, LangChain.js, MCP | ✅ those plus Claude Code, Google ADK, AWS Bedrock, Microsoft Agent Framework, OpenClaw |
| Scopes across a process boundary | ✅ HMAC scope token — integrity within one trust domain | ✅ independently attestable scopes |
| Dashboard | ✅ `watchlight dev` → `localhost:7000` | ✅ the operator console |

**What only Enterprise does**

| Capability | Developer Edition | Enterprise |
|---|---|---|
| Real-time enforcement effects — quarantine an agent, terminate a run, sever a delegation subtree, revoke authority | ❌ the policy loads and the call is denied; the containment action never fires | ✅ fires fleet-wide, mid-execution |
| Drift detection | ❌ | ✅ an agent leaving its declared plan is quarantined at machine speed |
| Runtime enforcement proxy | ❌ governs in-process, plus a PEP in front of one MCP server | ✅ every wire request clears the proxy as well as the plugin |
| Discovery and registry | ❌ | ✅ finds every agent and MCP server across your environments and tracks trust state |
| Signed execution lineage | ❌ local JSONL, unsigned | ✅ tamper-evident, reconstructs the chain from the human who authorized it to the resource |
| Fleet-wide revocation | ❌ one process | ✅ zero standing privileges, multi-tenant |
| Attested identity | ❌ the principal is asserted | ✅ OIDC federation and mTLS workload identity |
| Air-gapped deployment | ❌ | ✅ on-premises, with local policy evaluation |

Everything the Developer Edition leaves out needs **state outside your process**
— a fleet to revoke across, a plane to quarantine into, a key to sign lineage
with. What it keeps is every guarantee that fits in one process: fail-closed
semantics, engine-side attenuation, explicit scopes, and value-free audit are
identical in both.

→ **[The platform](https://www.watchlight.ai/platform)** ·
[email sales@watchlight.ai](mailto:sales@watchlight.ai?subject=Watchlight%20Enterprise)

## Open source, and the license

Everything you write against is **open** and Apache-2.0 — the `govern` decorator
and scope attenuation, the CLI and the `watchlight dev` dashboard, the framework
plugins, the MCP PEP's transport layer, and every example here.

You do not have to trust a black box to trust the decisions. Policies are
standard [Cedar](https://www.cedarpolicy.com/) — open, formally specified, and
deterministic. The integration layer is readable, so you can see exactly what
the engine is asked and what it returns. And every `ALLOW` / `DENY` lands
value-free in a file you can grep.

The **decision engine** ships as a compiled wheel — `watchlight-engine` and the
`watchlight-mcp` runtime — under the Watchlight Developer Edition license. Both
are **free to use, including in production and commercially, for up to 25
governed agents per organization**. A commercial license is needed only above
that, or to re-offer the engine itself as a hosted authorization service.

Want the engine source, an air-gapped build, or to govern a fleet in production?
[email sales@watchlight.ai](mailto:sales@watchlight.ai?subject=Watchlight%20Enterprise).
