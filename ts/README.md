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

To hand a scope to another process (a queue worker, a scheduler) without trusting
the job payload, serialise it as a **scope token**. Configure a shared secret
(≥ 16 bytes; `tokenSecret` or `WATCHLIGHT_TOKEN_SECRET` — there is no default,
minting and verifying fail closed without one):

```ts
const govern = new Watchlight({ tokenSecret: process.env.WATCHLIGHT_TOKEN_SECRET });
const token = child.toToken();                 // wls1.<canonical claims>.<HMAC-SHA256>
// ...in the worker (same agent identity, same secret):
const scope = await govern.scopeFromToken(token);
```

`scopeFromToken` verifies the signature (constant-time), the agent binding and
the `iat`/`exp` window, then rebuilds the root and **replays every level through
the engine's strict-subset validator** — a widened chain throws
`AttenuationDenied` even with a valid signature; a malformed, tampered, expired,
oversized or wrong-agent token throws `ScopeTokenError` (`.code`). The token
carries only the root grant, the per-level granted dimensions, `agent`, `depth`,
`iat`, `exp`. A shared secret is integrity within one trust domain, not
attestation: the root is rebuilt from the token, so a holder of the secret can
mint any scope at all, root included — the token adds no authority beyond what
the holder could grant itself with `scope()`. A rebuilt scope past the token's
`exp` refuses `attenuate()` / `toToken()` (`ScopeTokenError`, `expired`); call
`scope.assertActive()` before acting under a long-held scope.

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

## Gate a consequential action — runtime context, per-user, human-in-the-loop

For money-moving (or any high-stakes) tool calls, pass **runtime facts** into the
policy, attribute the decision to the **acting user**, get a **correlation id**
back, and route the risky ones to a **human**.

```ts
import { govern, NeedsApproval } from "@watchlight/sdk";

// principal / resource / context can each be a value or (args) => value
const book = govern.tool(bookTrip, {
  intent: "book",
  principal: (o) => `User::"${o.userId}"`,
  resource:  (o) => `trip/${o.tripId}`,
  context:   (o) => ({ amount: o.amount, limit: o.perActionLimit, refundable: o.refundable }),
  onNeedsApproval: async ({ decisionId }) => askUser(decisionId), // one-tap human confirm
});
```
```
permit(principal, action == Action::"book", resource)
when { context.amount <= context.limit && context.refundable };
```

Or use the low-level primitive directly (any framework):

```ts
const d = await govern.authorize({
  principal: `User::"${userId}"`, action: "wire", resource: `acct/${to}`, context: { amount },
});
// d.decision → "Allow" | "Deny" | "NeedsApproval"
// d.decisionId → store next to your booking row for reconstruction

if (d.decision === "NeedsApproval") {
  await getHumanConfirmation();
  const token = govern.mintApproval({ action: "wire", resource: `acct/${to}` }); // single-use, TTL, bound
  await govern.authorize({ principal: `User::"${userId}"`, action: "wire", resource: `acct/${to}`, context: { amount }, approval: token });
}
```

- **Three-state verdict** — `NeedsApproval` is surfaced when a matched permit is
  annotated `@enforcement_effect("require_approval")`.
- **Correlation id** — every decision returns `decisionId` (also in the audit
  line), so you can join it to your own records.
- **Obligations** — a permit annotated `@obligate_redact("ssn")`,
  `@obligate_max_items("25")`, `@obligate_log_values("false")`, or any
  `@obligate_<name>("raw")` yields `d.obligations` on an `Allow`:
  `{ redact?: string[], maxItems?: number, logValues?: boolean, extra?: Record<string,string> }`
  — constraints your code (or `onResult`) must honour. Several carrying permits
  merge to the strictest reading (`redact` union, `maxItems` min, `logValues`
  AND); `Deny` and `NeedsApproval` never carry any. Assert them in `govern.test`
  with `obligations: { redact: ["ssn"] }`.
- The audit line now carries `decision_id` + the resolved `principal`, and stays
  value-free (no context values).

## Govern what a tool returns — `onResult`

For retrieval tools the classification of what comes back is only known after the
fetch. `onResult` runs **after the body returns and before the caller sees the
result**, with the same `decisionId` that is on the call's decision line:

```ts
const readDoc = govern.tool(fetchDocument, {
  intent: "read",
  resource: (id) => `doc/${id}`,
  onResult: async (doc, { resource, principal, decisionId }) => {
    const release = await govern.authorize({
      principal, action: "release", resource, context: { classification: classify(doc) },
    });
    if (!release.allowed) throw new Denied(resource, "release", release.reason); // withheld
    return govern.sanitize(doc.text, { resource }).text;                          // replaces
  },
});
```

- **Return a value** → it replaces the payload. **Return `undefined` or `null`**
  → passthrough (Python: `None`). **Throw** → the error propagates and the raw
  result is never returned (fail-closed).
- Writes a **value-free** `egress` audit record — `{ ts, agent, principal,
  intent, event: "egress", resource, replaced, decision_id }` (plus
  `withheld: true` when the hook threw or timed out) — never the result. It
  joins the decision record on `decision_id`.
- The same option is on `governTool(tool, { onResult })` / `governTools` and on
  `governedHooks({ onResult, onResultTimeoutMs? })`, which installs a Claude
  Agent SDK `PostToolUse` hook: a returned value becomes the `updatedToolOutput`
  the model receives; a throw — or outrunning the internal deadline (default
  8 s; the SDK matcher timeout is set above it) — replaces the output with the
  opaque `"not authorized"`. The join uses the SDK's `tool_use_id`; without one
  the egress record carries no `decision_id`.

Pattern: [egress after read](../examples/patterns/egress-after-read.md).

## Strip PII before the agent reads a document

Redact PII from text before it reaches the agent — deterministic, in-process,
fail-closed. Extract your document to text first (never hand the agent the
original PDF — its hidden layers leak), then sanitize:

```ts
import { govern } from "@watchlight/sdk";

const { decisionId } = await govern.authorize({ action: "read", resource: "statement.pdf" });
const text = await extractPdfText("statement.pdf"); // your extractor
const { text: safe, report } = govern.sanitize(text, { resource: "statement.pdf", decisionId });

// safe → "Card on file: <CREDIT_CARD_1>  SSN: <SSN_1>  ..."
// report → { mode:"tag", counts:{ CREDIT_CARD:1, SSN:1, ... }, total, decisionId }  (value-free)
await agent.read(safe);
```

The deterministic detector (`DETECTOR_VERSION = "de-rules-2"`) covers structured
PII — `EMAIL`, `PHONE`, `SSN`, `CREDIT_CARD` (Luhn-validated), `IBAN`, `IPV4`,
`API_KEY`, `PASSPORT` (a number labelled `passport …`, plus ICAO machine-readable
zone lines; bare unlabelled numbers are deliberately not matched) and `DOB` (a
plausible date in a `DOB:` / `date of birth` / `born on` context; bare dates are
not matched). Modes: `tag` (consistent `<EMAIL_1>` placeholders, default), `mask`
(`[EMAIL]`), `hash`. `govern.sanitize` records a **value-free** audit entry
(counts by type + mode + detector version — never the values).

**Values you already hold** — names, streets, ids from your own records — go in
`known`. Every occurrence is redacted (exact string, case-insensitive; overlapping
or nested occurrences merge into one span) and counted under `KNOWN`; the values
never appear in the output, the report, or the audit line. `known` is honoured
even under a `types` filter. Matching is simple (ASCII-style) case-insensitive;
Unicode case folding differs between the TypeScript and Python lanes (Python's
`re.IGNORECASE` folds more characters), so supply the exact spellings you hold.

```ts
govern.sanitize(text, { known: [customer.fullName, customer.street] });
// report.counts → { KNOWN: 3, DOB: 1, … }   (counts only)
```

**Opt-in heuristics.** `PERSON` (honorific- or label-anchored names and bare
Title Case runs) and `ADDRESS` (numbered street + suffix, `P.O. Box`) are lower
precision — Title Case phrases and lower-case or unnumbered addresses are the
known trade-offs — so they are **off by default**: list them in `types` to run
them (`types: [...DEFAULT_PII_TYPES, "PERSON", "ADDRESS"]`). For precision, prefer
`known`.

`SanitizeOptions` is `{ mode?, types?, intent?, resource?, decisionId? }`. Pass
the `decisionId` returned by `authorize` and the `sanitization` audit line
carries the same `decision_id` as the decision that governed the read, so the
two records join on one key. The id is opaque and validated before it is
written — 1–128 characters (UTF-16 code units in TypeScript, code points in Python), no control or line-separator characters — otherwise `SanitizeError`
(fail-closed, nothing is written).

A pure `sanitize(text, opts)` is also exported. Fail-closed: it throws
`SanitizeError` rather than return partially-redacted text (a malformed `known`
entry is rejected without echoing it). Recall is bounded by the enabled
detectors; the report says exactly which ran.

## Screen retrieved content before it reaches the model

Anything an agent reads but did not write — a web page, a search result, a tool
result — goes back into the model as context; text in it that *looks like an
instruction* is the classic prompt-injection vector. `govern.screen` catches the
well-known shapes, deterministically and in-process; refuse before returning and
the raw result never reaches the model:

```ts
import { govern, Denied, DENY_REASON } from "@watchlight/sdk";

const readPage = govern.tool(async function fetchPage(url: string) {
  const html = await httpGet(url);                                   // your fetch
  const { text, report } = govern.screen(html, { resource: url, mode: "redact" });
  if (report.flagged) throw new Denied("fetchPage", "read", DENY_REASON); // refuse …
  return text;                                                        // … or hand back the redacted text
}, { intent: "read", resource: (url) => url });
// report → { counts: { INSTRUCTION_OVERRIDE: 1, HTML_INJECTION: 1 }, total: 2, flagged: true, … }  (value-free)
```

The same screen can run as the tool's egress hook instead — `onResult: (html,
{ resource }) => …` on `govern.tool` — when the body is not yours to edit.

Seven rule families, each a named counter: `INSTRUCTION_OVERRIDE`, `ROLE_SWITCH`,
`PROMPT_EXFILTRATION`, `JAILBREAK_MARKER`, `AUTHORITY_IMPERSONATION`,
`HTML_INJECTION`, and `PROMPT_LEAK` (for the output lane — run it on what the
model produced). Modes: `report` (default — text untouched, counts only) and
`redact` (matched spans replaced by `[FAMILY]` markers). Matching ignores case,
whitespace runs and zero-width characters. `govern.screen` records a
**value-free** `screening` audit entry (counts per family, mode, `flagged` —
never the text).

A pure `screen(text, opts)` is also exported. Fail-closed: it throws `ScreenError`
(fixed messages) on a non-string, unknown mode or family, or an empty family list
rather than returning a "clean" result. It is rules, not a classifier — it does
not decode leetspeak, homoglyphs or encodings, and a document that quotes an
attack string verbatim is flagged (the model would read it too); treat `flagged`
as a signal, not a verdict. `redact` marks the trigger (a whole `<script>…</script>`
element when its body has no `<`) — it does not neutralise HTML; strip markup to
text first if the model must not see it. Markers can be spoofed by input text, so
consumers decide from the report, never from markers in the text.

## Value-free audit

`.watchlight/audit.jsonl` records **who / what intent / which tool / the
decision** — never argument values. Same contract as the production audit trail.

```json
{"ts":"2026-08-29T…Z","agent":"my-agent","intent":"research","resource":"tool/webSearch","decision":"Allow","decision_id":"…"}
{"ts":"2026-08-29T…Z","agent":"my-agent","intent":"read","event":"sanitization","resource":"statement.pdf","mode":"tag","detector":"de-rules-1","counts":{"EMAIL":2},"total":2,"decision_id":"…"}
```

A `sanitization` line carries `decision_id` only when `govern.sanitize` was given
the `decisionId` of the `authorize` decision — the two lines then join on it.

### Ship it somewhere durable — `auditSink`

On an ephemeral host the file is gone on the next deploy. Add a sink and every
record — decisions, sanitizations, and the attenuations of every derived scope —
is also handed to your code, with **exactly** the fields the file line carries
(a frozen copy). The file stays on.

```ts
const govern = new Watchlight({
  auditSink: (record) => db.insert("agent_audit", record), // sync or async
});
```

The sink is **fire-and-forget**: a returned promise is not awaited, and a throw or
rejection is reported once (error type only) and never blocks or changes a
decision. Reference sinks — a Postgres row, an OTLP log record, a webhook — are in
[`examples/patterns/audit-sink.md`](../examples/patterns/audit-sink.md).

### Count it — `govern.counters` for quota policies

The trail is also an input. `govern.counters(...)` folds it into the number a
quota policy compares against — decisions for exactly this `principal` (and
`intent` / `resource` when given) whose `ts` falls in the last `window`:

```ts
const c = govern.counters({ principal: 'User::"u1"', intent: "read", window: "1h" });
// { count: 7, outcome: "allowed", window: { seconds: 3600, start, end }, records, skipped, truncated }
await govern.authorize({ action: "read", principal: 'User::"u1"', context: { reads_this_hour: c.count } });
```

Synchronous, so it runs inside a `context` binding. `window` is `"15m"` / `"1h"`
/ `"24h"` / `"7d"` or seconds; `outcome` is `allowed` (default) / `denied` / `all`.
Only decision records count (never `sanitization` / `egress` / `attenuation`);
the local file is streamed and scanned to at most `maxBytes` (64 MiB) from its
end — `truncated` marks a lower bound (omit the counter from `context` so the
policy denies, audited). Malformed or oversized lines are skipped and counted in
`skipped`, never echoed; a missing file is zero, an unreadable one throws
`AuditTrailUnreadable`. Each call rescans the tail — rotate the file on a
long-lived agent. Pattern: [quotas](../examples/patterns/quotas.md).

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
