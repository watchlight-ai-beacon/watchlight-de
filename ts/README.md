# @watchlight/sdk

Authorize every tool call your Node agent makes — against a Cedar policy, before
the call runs. A denied call throws and its body never executes, and every
decision lands in a value-free `.watchlight/audit.jsonl`.

There is no server to run. The real Watchlight decision engine
([`@watchlight/engine`](https://www.npmjs.com/package/@watchlight/engine) — the
Cedar core compiled to WebAssembly) installs with this package, and every
`ALLOW` / `DENY` comes from it. This is the TypeScript lane of
[Watchlight Developer Edition](https://github.com/watchlight-ai-beacon/watchlight-de);
everything here has a Python equivalent under a `snake_case` name.

## Install

```bash
npm install @watchlight/sdk    # Node >= 18, no native toolchain
```

## Deny a tool call before it runs

Save as `agent.mjs`, then `node agent.mjs`:

```ts
import { govern, configureDefault, Denied } from "@watchlight/sdk";

configureDefault({ agent: "research-agent" });          // the name on every record

// Permit ONLY "research". Fail-closed: everything else is denied.
govern.allow('permit(principal, action == Action::"research", resource);');

async function webSearch(query) { return `results for: ${query}`; }
async function transferFunds(to, amount) { return `sent $${amount} to ${to}`; }

const search   = govern.tool(webSearch,     { intent: "research" });
const transfer = govern.tool(transferFunds, { intent: "transfer" });  // nothing permits it

console.log(await search("watchlight docs"));   // ALLOW → the body runs
try {
  await transfer("mallory", 1000);              // DENY → refused before the body runs
} catch (e) {
  if (e instanceof Denied) console.log(e.message);
}
```

```text
watchlight: governing 'research-agent' (dev mode, in-process engine)
watchlight: ALLOW  research  tool/webSearch
results for: watchlight docs
watchlight: DENY   transfer  tool/transferFunds     not authorized
watchlight denied intent 'transfer' on tool/transferFunds: not authorized
```

**That `DENY` is the product.** The `transferFunds` body never ran, and the
decision is already on disk. The run also prints a one-time note that no audit
sink is configured.

A governed function is always async, because the engine's authorize path is
async in WebAssembly.

## Write the policies

Policies are standard [Cedar](https://www.cedarpolicy.com/) — open, formally
specified, deterministic. Keep them in a file your app loads at start-up:

```json
[
  { "name": "allow-research",
    "code": "permit(principal, action == Action::\"research\", resource);" }
]
```

```ts
govern.load("watchlight.policy.json");
if (!govern.hasPolicies) throw new Error("no policies — every call would be denied");
```

`load` is idempotent per file, so priming an engine twice cannot double the set.
`govern.allow(code)` loads a policy inline and is always additive.

Test a policy before it gates anything real:

```bash
npx --package @watchlight/sdk watchlight policy test suite.json   # exit 1 on any failure
```

→ [Testing your policies](https://github.com/watchlight-ai-beacon/watchlight-de/blob/main/docs/testing-policies.md)

## What else is in the box

### Say who the call was for

```ts
const book = govern.tool(bookTrip, {
  intent: "book",
  principal: (o) => `User::"${o.userId}"`,    // on whose behalf
  resource:  (o) => `trip/${o.tripId}`,
  context:   (o) => ({ amount: o.amount, limit: o.limit }),
});
```

Each term is a fixed value or a function of the call. The SDK sets
`context.actor` from the agent name and refuses a caller-supplied value that
disagrees, so a policy can trust it.

→ [The identity model](https://github.com/watchlight-ai-beacon/watchlight-de/blob/main/docs/identity-model.md)

### Govern an agent you did not write

```ts
const { hooks } = governedHooks({ intentFor: (t) => TOOL_INTENTS[t] ?? t });  // Claude Agent SDK
const tools = governTools(myTools, { intentFor: (t) => TOOL_INTENTS[t] ?? t }); // LangChain / LangGraph.js
```

Both adapters take the same governance terms as `govern.tool()`, so a policy
reaches the same verdict through an adapter as through a hand-written tool.
`@langchain/core` is a peer dependency.

→ [Governing an agent you already have](https://github.com/watchlight-ai-beacon/watchlight-de/blob/main/docs/integrations.md)

### Ask a human first

```ts
const wire = govern.tool(transfer, { intent: "wire", onNeedsApproval: askOps });
```

A permit annotated `@enforcement_effect("require_approval")` yields a third
verdict, `NeedsApproval`, and a single-use approval token. The defaults are
per-process: set `approvalSecret` to carry a token between processes, and an
`approvalStore` to make single use hold across replicas.

→ [The TypeScript lane](https://github.com/watchlight-ai-beacon/watchlight-de/blob/main/docs/typescript.md#ask-a-human-first)

### Check what a tool returns

```ts
const read = govern.tool(readDoc, {
  intent: "read",
  onResult: (doc, { obligations, decisionId }) => redact(doc, obligations),
});
```

`onResult` runs after the body and before the caller sees the result. A returned
value replaces the payload, a throw withholds it, and either way an `egress`
record joins the decision on `decision_id`. The hook is bounded by
`onResultTimeoutMs` (8 s by default) and cannot be switched off.

→ [The TypeScript lane](https://github.com/watchlight-ai-beacon/watchlight-de/blob/main/docs/typescript.md#govern-what-a-tool-returns)

### Strip PII, and screen what comes back

```ts
const clean  = govern.sanitize(text, { resource: "doc/1", decisionId, principal });
const vetted = govern.screen(text,   { resource: "doc/1", decisionId, principal });
```

`sanitize` strips structured PII — email, phone, SSN, card, IBAN, IPv4, API key,
labelled passport and date of birth — plus a `known` dictionary you supply.
`screen` flags prompt-injection shapes before retrieved text reaches the model.
Both are deterministic rules, not classifiers, and both record counts only,
never values.

→ [The TypeScript lane](https://github.com/watchlight-ai-beacon/watchlight-de/blob/main/docs/typescript.md#strip-pii-and-screen-what-comes-back)

### Narrow a sub-agent's authority

```ts
const root  = await govern.scope({ tools: ["read", "write"] });
const child = root.attenuate({ tools: ["read"] });   // strictly a subset, engine-enforced
const token = child.toToken();                       // carry it to a queue worker
```

Widening throws `AttenuationDenied`. `govern.scopeFromToken()` rebuilds a scope
on the far side and replays every level through the engine's validator. A token
needs a shared `signingSecret`; there is no default, and minting and verifying
both fail closed without one.

→ [The signing secret](https://github.com/watchlight-ai-beacon/watchlight-de/blob/main/docs/signing-secret.md)

### Ship the audit somewhere durable

```ts
configureDefault({ agent: "billing-agent", auditSink: (r) => db.insert("agent_audit", r) });
```

On an ephemeral host the local file is gone on the next deploy. A sink also
receives every record — decisions, sanitizations, screenings, egress
dispositions, attenuations — as a typed discriminated union. `counterSource` is
its read side, for quota policies that count what a durable store holds.

→ [The audit trail](https://github.com/watchlight-ai-beacon/watchlight-de/blob/main/docs/audit-trail.md)

### Point the same code at a control plane

```bash
export WATCHLIGHT_APDP_URL=https://apdp.example.com   # → networked (Enterprise)
```

The same code authorizes against the networked Watchlight control plane instead
of the in-process engine — no policy or code change. `governor.mode` reports
which is live, and networked mode is fail-closed.

## Documentation

- [docs.watchlight.ai/de](https://docs.watchlight.ai/de) — the full reference:
  every option, every record field, every error.
- [The TypeScript / Node lane](https://github.com/watchlight-ai-beacon/watchlight-de/blob/main/docs/typescript.md)
  — this package in depth, and the Python name for each thing.
- [Documentation index](https://github.com/watchlight-ai-beacon/watchlight-de/blob/main/docs/README.md)
  — every page, and when to read it.
- [`ts/examples/`](https://github.com/watchlight-ai-beacon/watchlight-de/tree/main/ts/examples)
  — runnable programs.
- [`examples/patterns/`](https://github.com/watchlight-ai-beacon/watchlight-de/tree/main/examples/patterns)
  — copy-paste policy recipes for spending money, deleting things, messaging the
  outside world, stopping a runaway agent.
- [Breaking changes](https://github.com/watchlight-ai-beacon/watchlight-de/blob/main/docs/breaking-changes.md)
  — read before bumping a version. Some entries surface as a denial rather than
  an error.

## License

Apache-2.0. The compiled engine it depends on
([`@watchlight/engine`](https://www.npmjs.com/package/@watchlight/engine)) is
under the Watchlight Developer Edition License — free for development, testing
and production, including commercially, up to 25 governed agents per
organization.
