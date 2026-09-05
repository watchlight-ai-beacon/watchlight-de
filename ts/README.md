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

`govern.load(file)` is **idempotent per source**: the real path (symlinks
resolved) or an explicit `{ sourceId }` is remembered, so priming an engine in a
factory and loading the same file again from an initialiser cannot double the
set. A missing file is not remembered, so it loads once it appears. The memo is
keyed on identity, not content — editing a loaded file and calling `load` again
is a no-op; pass `{ force: true }` to load it again (additively). `govern.allow(code)` is
always additive — the same code twice is two policies. `govern.policyCount` and
`govern.hasPolicies` report what an engine holds, worth asserting at start-up:
no policies means every call is denied.

## Who is acting, and on whose behalf

A governed call answers these questions, and they are separate inputs:

| Question | Where it goes | Example |
|---|---|---|
| On whose behalf does this run? | `principal` — the subject | `User::"alice"` |
| Which runtime is acting? | the reserved `actor` context key, set by the SDK | `context.actor == "flight-booker"` |
| Through whose delegation? | the reserved `actor_chain` context key | `context.actor_chain.contains("flight-booker")` |
| Under what narrowed authority? | the attenuation scope | `govern.scope({ tools: [...] })` |

```ts
import { govern, principals } from "@watchlight/sdk";

// the agent acting for a person
await govern.authorize({ action: "book", principal: principals.user("alice") });
// the agent acting on its own behalf — an omitted principal is Agent::"<name>"
await govern.authorize({ action: "cache" });
```

```cedar
// this runtime may book for any user — whoever it acts for
permit(principal is User, action == Action::"book", resource)
when { context.actor == "flight-booker" };
```

`principal` is always a typed entity reference; build it with `principals.user`
/ `principals.agent`, which escape an identifier that came from outside
(`policyEntityRef` builds the escaped form a generated policy needs). The SDK
sets `context.actor` on every call from the governor's agent name, and refuses a
caller-supplied value that disagrees (`ReservedContextError`), so a policy can
trust it.

**One engine per policy set, many named agents.** Construct once (with the sink
and the secrets), load the policies once, then name each agent with a view: it
shares the engine, the compiled policies and their load memo, the audit trail,
the sink and the secrets, and only changes the stamped name. Construct a second
governor for a genuinely different policy set — not to give an agent a name.

```ts
const billing = govern.as("billing-agent");    // no second engine, no second policy load
const research = govern.as("research-agent");
```

Views share the trail, so every named agent's records land in one destination,
told apart by the `agent` field — which is what makes a single audit stream
readable. Separate governors are how you get a separate trail per agent.

`authorize`, `sanitize`, `screen` and `tool` also take a per-call `agent`.

A sub-agent is a *delegation*, not a rename: `delegate` narrows a scope for it
(engine-enforced strict subset) and extends the actor chain, so the decision and
every record name both the sub-agent and whose delegation it acts under.

```ts
const root = await govern.scope({ tools: ["search", "book"] });
const picker = govern.delegate(root, "seat-picker", { tools: ["search"] });
await picker.authorize({ action: "pick_seat", principal: principals.user("alice") });
// records agent "seat-picker", actor_chain ["flight-booker", "seat-picker"]
```

The subject is a stable identifier for whoever your application already
authenticated — a users-table primary key is as valid as a token's subject
claim, and no identity provider is required. Derive it from something you
authenticated, never from a request header or body a caller can set, and prefer
an id that never moves over an email or a username.

**→ Full reference: [The identity model](https://github.com/watchlight-ai-beacon/watchlight-de/blob/main/docs/identity-model.md)** — the
one-engine shape, the three cases with exact values, worked policies, where the
values come from, and the 0.8.0 migration note.

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
- **Approval tokens are single-use, TTL-bounded and bound to the exact
  `(principal, action, resource)`.** Both defaults are **per-process**:
  - the token is signed with a **random per-process key**, so it cannot cross a
    process boundary and a restart invalidates every outstanding approval. Set
    `approvalSecret` (or `WATCHLIGHT_APPROVAL_SECRET`, or `tokenSecret` — one
    secret configures both, the approval key being
    `HMAC-SHA256(secret, "watchlight-de:approval-token:v1")`, never the secret
    itself) to mint in one process and consume in another.
  - "used once" is recorded in an **in-process map**, so behind two replicas the
    same token can be consumed once on *each*. Pass an `approvalStore`
    (`has(id)` / `add(id, expiresAt)`, sync or async — the read/write shape of an
    `auditSink`) backed by a store every replica shares, and single-use holds
    across all of them. A store that throws **refuses** the approval; it never
    admits one.

  ```ts
  const govern = new Watchlight({
    approvalSecret: process.env.APPROVAL_SECRET,          // >= 16 bytes
    approvalStore: {                                       // e.g. Redis
      has: (id) => redis.exists(`wl:appr:${id}`).then(Boolean),
      // a conditional write makes single-use atomic; `false` refuses the replay
      add: (id, expiresAt) =>
        redis.set(`wl:appr:${id}`, "1", { NX: true, PXAT: expiresAt }).then((r) => r !== null),
    },
  });
  ```

  Every refusal — expired, tampered, signed with another key, already consumed,
  or a store that could not answer — surfaces as the *same* `NeedsApproval` hold
  with the uniform `approval required` reason, so a probing caller learns nothing
  about which check refused.

  The signed payload is length-prefixed and carries a version marker, so no two
  different `(principal, action, resource)` triples can sign the same bytes, and
  both language packages sign identical bytes (a token minted by either verifies
  in the other under the same secret). **Breaking in 0.8.0:** approval tokens
  minted by an earlier version do not verify against 0.8.0 — they were signed
  under the previous payload format. Nothing else changes, and the tokens are
  short-lived, so drain in-flight approvals across the upgrade.
- **Correlation id** — every decision returns `decisionId` (also in the audit
  line), so you can join it to your own records.
- **Obligations** — a permit annotated `@obligate_redact("ssn")`,
  `@obligate_max_items("25")`, `@obligate_log_values("false")`, or any
  `@obligate_<name>("raw")` yields `d.obligations` on an `Allow`:
  `{ redact?: string[], maxItems?: number, logValues?: boolean, extra?: Record<string, string[]> }`
  — constraints your code (or `onResult`) must honour. Every carrier — the
  engine's merge and each determining permit — merges to the strictest reading
  (`redact` union, `maxItems` min, `logValues` AND; `extra[name]` lists every
  distinct value); `Deny` and `NeedsApproval` never carry any; a known
  obligation the SDK cannot read rejects with `AuthorizeError` instead of being
  dropped. Assert them in `govern.test` with `obligations: { redact: ["ssn"] }`.
  Needs `@watchlight/engine` >= 0.2.0.
- The audit line now carries `decision_id` + the resolved `principal`, and stays
  value-free (no context values).

## Govern what a tool returns — `onResult`

For retrieval tools the classification of what comes back is only known after the
fetch. `onResult` runs **after the body returns and before the caller sees the
result**, with the same `decisionId` that is on the call's decision line (and, on
`obligations`, the constraints that decision carries — see the obligations
section; `governTool` and the `governedHooks` `PostToolUse` hook pass the same
info shape):

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

**Name the subject with `principal`.** `sanitize` and `screen` both take
`principal` alongside `decisionId`, echoed onto the report and written to the
audit line under the same key the decision line uses:

```ts
govern.sanitize(text, { resource: "statement.pdf", principal: `User::"${userId}"`, decisionId });
```

Without it the record says what was redacted but not *for whom* — answerable only
by joining through `decisionId`, and only when a decision exists. A pipeline that
sanitizes and screens *before* it authorizes (the right order when the text must
never be embedded unsanitized) has nothing to join to, so a data-minimisation
audit gets "something was redacted for someone". `principal` is an identifier
**you** supply — never anything derived from the content — validated exactly like
`decisionId` (1–128 characters, no control or line-separator characters,
`SanitizeError` / `ScreenError` otherwise). Records without one are unchanged.

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
{ resource, decisionId }) => govern.screen(html, { resource, decisionId })…` on
`govern.tool` — when the body is not yours to edit; passing the hook's
`decisionId` writes it on the `screening` audit line, so it joins the decision.

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

`auditFile: false` makes the sink the **sole** destination: no `.watchlight`
directory, no file, and `govern.counters(...)` — which reads the local file —
throws rather than counting zero. With neither a file nor a sink the SDK says so
once instead of discarding records silently. The file is shared: every governor
pointed at the same directory, including concurrent instances in one process and
a test run in the same working directory, appends to the same `audit.jsonl`, so
those records interleave and are told apart only by their fields.

The exported `govern` is pre-constructed, so configure it before its first
governed call — otherwise it has no sink, and it says so the first time it
writes:

```ts
import { govern, configureDefault } from "@watchlight/sdk";

configureDefault({ agent: "billing-agent", auditSink: (r) => db.insert("agent_audit", r) });
```

`configureDefault(...)` throws once the default governor has written a record:
records already written cannot reach a sink added later, and a trail split
across two destinations reads like a data bug.

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

**Count the durable store instead — `counterSource`.** The local file is
per-container and does not survive a deploy, so a quota folded from it counts one
replica since its last restart. `counterSource` is the read side of `auditSink`:
the same query, answered by the store the sink writes to.

```ts
const govern = new Watchlight({
  auditSink: (record) => db.insert("agent_audit", record),
  counterSource: (q) => db.countDecisions(q),   // { principal, intent?, resource?, outcome, window }
});
const c = govern.counters({ principal: 'User::"u1"', intent: "read", window: "1h" });
// c.source === "external"; `records` / `skipped` describe the local scan that did not happen
```

The source is handed the **validated, resolved** query — `window.start`
exclusive, `window.end` inclusive, both ISO-8601 UTC, so it maps straight onto a
range query — and must return a non-negative integer. Fail-closed: a throw or a
non-count raises `CounterSourceError`; it never falls back to the local file,
because a silently local count is a quota that under-counts without saying so. An
**async** source is read with `await govern.countersAsync(...)`; calling the
synchronous `counters()` on one raises rather than answering from the file (the
`context` binding it feeds is synchronous, so resolve the number before the
call). With no source configured, everything above is unchanged and
`c.source === "local"`.

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
