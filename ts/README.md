# @watchlight/sdk

Govern your Node/TypeScript agent's tools with a **fail-closed, in-process
policy decision** — zero infrastructure. Declare an intent, wrap a tool, and the
call is authorized against your Cedar policies before it runs; denied calls throw
and their body never executes. Every decision lands in a **value-free**
`.watchlight/audit.jsonl`.

This is the TypeScript counterpart of the Python `watchlight` package. It is thin
glue over [`@watchlight/engine`](https://www.npmjs.com/package/@watchlight/engine)
(the real `wl-apdp` Cedar core compiled to WebAssembly) and contains **no
decision logic** — every ALLOW/DENY comes from the engine.

## Install

```bash
npm install @watchlight/sdk
```

## Govern a tool

```ts
import { govern, Denied } from "@watchlight/sdk";

govern.load("watchlight.policy.json"); // or govern.allow('permit(principal, action == Action::"research", resource);')

const webSearch = govern.tool(async (q: string) => search(q), { intent: "research" });
const transferFunds = govern.tool(async (amt: number) => bank.send(amt), { intent: "transfer" });

await webSearch("cedar policy");   // ALLOW → runs
try {
  await transferFunds(1000);       // no policy permits "transfer" → DENY
} catch (e) {
  if (e instanceof Denied) console.error(e.message); // never executed
}
```

TypeScript uses a higher-order function (`govern.tool(fn, { intent })`) rather
than a decorator — it works across every TS build setup with full type
inference. Governed functions are always async (the engine's authorize path is
async in WebAssembly).

Fail-closed by default: with no matching policy, every governed call is denied.

## Sub-agent scope attenuation

Derive strictly-narrower child scopes for sub-agents; the real engine enforces
strict-subset, so a child can never hold a capability its parent lacks.

```ts
const root = await govern.scope({ tools: ["read", "search"], timeBudgetSeconds: 600 });
const child = root.attenuate({ tools: ["read"] });        // ⊆ parent → OK
root.attenuate({ tools: ["read", "write"] });             // escalation → throws AttenuationDenied
```

The Developer Edition governs the tree up to depth `DE_MAX_DEPTH` (5); beyond it,
`attenuate` throws `DevEditionCeiling`. Enterprise removes the cap and enforces
it server-side.

## Claude Agent SDK

Govern an SDK-managed agent's tool calls with a `PreToolUse` gate — no glue in
your tool bodies. Denied tools are blocked by the SDK before they run.

```ts
import { query } from "@anthropic-ai/claude-agent-sdk";
import { govern, governedHooks } from "@watchlight/sdk";

govern.load("watchlight.policy.json");

// Map Claude tool names → governance intents.
const TOOL_INTENTS: Record<string, string> = { WebSearch: "research", Bash: "execute" };
const { hooks } = governedHooks({ intentFor: (t) => TOOL_INTENTS[t] ?? t });

for await (const msg of query({ prompt, options: { hooks } })) {
  // WebSearch runs if a policy permits "research"; anything unpermitted is
  // denied before execution.
}
```

The hook is fail-closed and never throws back to the SDK — a governance error
denies the call. Every decision is audited.

## LangChain / LangGraph.js

Govern any LangChain `StructuredTool` (which is what LangGraph.js tools are) — the
tool is authorized before it runs; denied tools throw and never execute.

```ts
import { tool } from "@langchain/core/tools";
import { z } from "zod";
import { govern, governTool } from "@watchlight/sdk";

govern.load("watchlight.policy.json");

const search = governTool(
  tool(async ({ query }) => webSearch(query), {
    name: "web_search",
    schema: z.object({ query: z.string() }),
  }),
  { intent: "research" }
);

// Pass `search` to your LangGraph ToolNode / createReactAgent as usual.
```

`governTool(tool, { intent })` returns a governed view (the original tool isn't
mutated); `governTools(tools, { intentFor })` maps an array. Intent defaults to
the tool's name. Fail-closed. `@langchain/core` is a peer dependency.

## Value-free audit

`.watchlight/audit.jsonl` records **who / what intent / which tool / the
decision** — never argument values. Same contract as the production audit trail.

```json
{"ts":"2026-08-29T…Z","agent":"my-agent","intent":"research","resource":"tool/webSearch","decision":"Allow"}
```

## Graduation to Enterprise

Set `WATCHLIGHT_APDP_URL` and the **same code** authorizes against the networked
Watchlight control plane (signed lineage, cross-tenant isolation, IdP/mTLS
attestation) instead of the in-process engine — no policy or code change. The
authorize request/response shape is identical; only the transport swaps.

```bash
export WATCHLIGHT_APDP_URL=https://apdp.example.com   # → networked (Enterprise)
export WATCHLIGHT_PLUGIN_TOKEN=...                     # bearer for the control plane
export WATCHLIGHT_TENANT_ID=...                        # X-Wl-Tenant-Id
# unset WATCHLIGHT_APDP_URL → in-process (Developer Edition)
```

Or per-instance: `new Watchlight({ apdpUrl, token, tenantId })`. Check which is
live with `governor.mode` (`"in-process"` | `"networked"`). Networked mode is
fail-closed — an unreachable control plane denies. Sub-agent `attenuate()` runs
in-process in the DE; under `WATCHLIGHT_APDP_URL` it is enforced server-side, so
`scope()` defers to the control plane.

## License

Apache-2.0. The compiled engine it depends on (`@watchlight/engine`) is under the
Watchlight Developer Edition License (free for development, testing, and
production — including commercially — up to 25 governed agents per organization).
