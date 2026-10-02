# The TypeScript / Node lane

You get the same governance in your Node app, with no Python sidecar.
[`@watchlight/sdk`](https://www.npmjs.com/package/@watchlight/sdk) runs the same
compiled engine in-process, as WebAssembly.

```bash
npm install @watchlight/sdk     # Node >= 18, no native toolchain
```

The five-minute `DENY` is in the [repository README](../README.md#quickstart),
side by side with Python. This page is what the lane gives you after that.

Everything below has a Python equivalent under a `snake_case` name.

## Govern a tool

```ts
const search = govern.tool(webSearch, {
  intent: "research",
  principal: (q) => `User::"${q.userId}"`,   // who the call is for
  resource: "index/web",
  context: (q) => ({ tier: q.tier }),        // what a policy reads as context.*
});
```

Each option can be either a fixed value or a function that receives the call's
arguments. If you omit them all, the agent itself is the subject, the resource
is `tool/<name>`, and the context is empty.

## Ask a human first

Some actions should wait for a person to approve them. A policy annotated
`@enforcement_effect("require_approval")` produces a third verdict besides allow
and deny, `NeedsApproval`, together with a single-use approval token. The
`onNeedsApproval` handler is where your code asks a human.

```ts
const wire = govern.tool(transfer, { intent: "wire", onNeedsApproval: askOps });
```

By default that token is signed with a **random key made for each process**,
and its use is recorded in a map held in memory. That has three consequences:
the token cannot be used in a different process, a restart invalidates every
approval still outstanding, and if you run two replicas the same token can be
used once on *each* of them. Two options fix this:

- `approvalSecret` makes a token portable between processes. Setting
  `signingSecret` does the same, since it covers both kinds of token. See
  [the signing secret](signing-secret.md).
- `approvalStore` makes "use once" hold across all your replicas. The store has
  one required method, `add(id, expiresAt)`, and it must be an **atomic
  check-and-set**: in a single step, reserve the id only if it is not already
  present, and report whether this call made a new reservation.

If the store fails, times out, or does not give an answer, the approval is
**refused**.

**Cleaning up reservations is your job.** The SDK never deletes one.
`expiresAt` is the deadline, in milliseconds since the Unix epoch, after which
an id is safe to drop, so give each stored row a matching time-to-live.
Alternatively, implement the optional `prune(before)` method, which the SDK
calls from time to time when it makes a reservation. A failing `prune` never
changes a decision.

## Govern what a tool returns

```ts
const read = govern.tool(readDoc, {
  intent: "read",
  onResult: (doc, { obligations, decisionId }) => redact(doc, obligations),
  onResultTimeoutMs: 8_000,
});
```

`onResult` runs after the tool body has finished and before the caller sees
the result. Use it to sanitize or screen the payload, to apply the obligations
attached to the decision, or to authorize again based on what came back. If the
hook returns a value, that value replaces the result. If the hook throws, the
result is withheld. Either way, an `egress` record is written to the audit
trail and linked to the original decision by `decision_id`.

**The hook has a time limit.** `onResultTimeoutMs` defaults to 8 seconds, and
the same default applies on `govern.tool()`, `governTool` / `governTools` and
`governedHooks`. If the hook runs past it, the payload is withheld exactly as if
the hook had thrown: you get `EgressTimeout`, and the record says
`withheld: true`. A hook that finishes after the deadline is ignored. The
deadline cannot be switched off; if a hook genuinely needs longer, give it a
larger number.

Python behaves differently for **synchronous** tool bodies. If you pass
`on_result_timeout_ms` for one, the hook runs on a worker thread so that the
calling thread can enforce the deadline, which means the hook must be
thread-safe. If you do not pass it, a synchronous body's hook has no deadline at
all, as before; the 8-second default is not applied there.

## Read the obligations on an Allow

```ts
const d = await govern.authorize({ action: "read", resource: "doc/1" });
d.obligations;   // { redact: ["ssn"], maxItems: 25 } — only the keys a policy set
```

A policy can allow an action on conditions. A permit annotated with
`@obligate_redact("ssn")`, `@obligate_max_items("25")` or
`@obligate_log_values("false")`, or with any other `@obligate_<name>("raw")`,
attaches constraints that your code or your `onResult` hook must honour. When
several matching policies carry obligations, they are merged into the strictest
combination. Only an `Allow` verdict carries obligations. If an obligation
cannot be read, the call fails closed with `AuthorizeError`. Obligations need
engine version 0.2.0 or later. See the
[allow-but-redact pattern](../examples/patterns/allow-but-redact.md).

The obligations object has the fields `redact`, `maxItems` and `logValues`,
plus `extra`, which holds any `@obligate_<name>` the SDK does not interpret
itself. Python uses the names `redact`, `max_items`, `log_values` and `extra`,
under `result["obligations"]`.

## Frameworks

```ts
const { hooks } = governedHooks({ intentFor: (name) => TOOL_INTENTS[name] ?? name });   // Claude Agent SDK
const tools = governTools(myTools, { intentFor: (name) => TOOL_INTENTS[name] ?? name });
```

Each adapter accepts the same governance options as `govern.tool()`:
`principal`, `agent`, `resource` (called `resourceFor` on the forms that map
over several tools), `context`, `onNeedsApproval`, `onResult` and
`onResultTimeoutMs`. As a result, a policy reaches the same verdict whether a
call goes through an adapter or through a governed tool you wrote by hand. See
the
[context-through-an-adapter pattern](../examples/patterns/context-through-an-adapter.md).

## Strip PII, and screen what comes back

```ts
const clean  = govern.sanitize(text, { resource: "doc/1", decisionId, principal });
const vetted = govern.screen(text,   { resource: "doc/1", decisionId, principal });
```

`sanitize` removes personal data (PII) from text before an agent reads it. It
detects structured values: email addresses, phone numbers, SSNs, card numbers,
IBANs, IPv4 addresses, API keys, and labelled passport numbers and dates of
birth. It also removes any values in a `known` dictionary you supply, and it can
optionally use the `PERSON` and `ADDRESS` heuristics, which are off unless you
turn them on.

`screen` looks for text patterns typical of prompt injection, and flags or
redacts them before the text reaches the model. `registerScreenFamily` adds a
pattern specific to your domain, such as text claiming an approval was given or
a check was skipped, under a label of your own. Such patterns are guarded and
versioned in the same way as the custom detectors that `registerDetector` adds,
described next.

`registerDetector` adds an identifier the built-ins do not know — an alien
registration number, an internal case reference — under a label of your own:

```ts
registerDetector("ALIEN_NUMBER", /\bA[- ]?\d{8,9}\b/);   // at start-up
```

A registered detector is on by default and replaces matches with a tag, like
the built-ins do (`<ALIEN_NUMBER_1>`). A pattern prone to catastrophic
backtracking is refused at registration, because a single pattern such as
`(a+)+` would hang every call that scans a document. A built-in label cannot be
replaced. Once anything is registered, `detectorVersion` includes a digest of
the whole set, so each audit record shows which detectors were in use.

`known` holds values your application already has, so it covers **your**
subjects and structurally cannot cover anyone else — the friend named in a
request, the school, the doctor. `PERSON` and `ADDRESS` are what cover those,
and they are off by default because they are heuristics. Use both.

Because `PERSON` is a Title Case heuristic, pass exact values already known not
to be people in `personExclusions`. Matching is case-insensitive and suppresses
only a complete `PERSON` candidate; email, SSN, and other enabled detectors
still run. Exclusion values do not appear in the report or audit trail.

A `known` value matches as a whole word, case-insensitively — `"Smith"` covers
`Smith's` but not `Smithfield`. It cannot tell a name from the same word used
ordinarily, so a single-token name that is also a common word (`Will`, `May`,
`Grace`) redacts every use of that word. Pass the full name, and treat a bare
first name as a deliberate choice.

`decisionId` links the audit line to an authorization decision. `principal`
records *whose* data it was. If you omit `principal`, the line names this agent
instead, as `Agent::"<name>"`, so pass it whenever an audit of data minimisation
needs to name the person. Both are identifiers you supply; neither is ever
derived from the text itself. Both are validated: each must be 1 to 128
characters long and contain no control characters.

## Attenuate, and graduate

```ts
const root  = await govern.scope({ tools: ["read", "write"] });
const child = root.attenuate({ tools: ["read"] });   // strictly a subset
const token = child.toToken();                       // carry it to a worker
```

A scope is a set of permissions, and `attenuate` creates a child scope that
holds a strict subset of its parent's. How deep that tree of scopes can grow is
limited by the governor's `maxDelegationDepth` option, which defaults to 8. A
step beyond that limit throws `DelegationDepthExceeded`, which is a denial with
the code `DELEGATION_DEPTH_EXCEEDED`.

`govern.scopeFromToken()` rebuilds the scope in the receiving process, and the
engine there checks again that it really is a subset. Setting
`WATCHLIGHT_APDP_URL` moves the same code, unchanged, onto the Watchlight
control plane.

## Upgrading

These releases changed behaviour you may notice when upgrading:

- **0.9.1**: before this release, only the Claude Agent path had a deadline on
  the `onResult` hook. Now an `onResult` hook slower than 8 seconds also
  withholds the result on `govern.tool()` and the LangChain adapters, where it
  used to release the result late.
- **0.8.0**: the signed approval payload is now length-prefixed and versioned,
  so no two different `(principal, action, resource)` triples can produce the
  same signed bytes. Tokens minted by an earlier version do not verify. Approval
  tokens are short-lived, so let approvals already in flight finish (or expire)
  before you upgrade.

## See also

- [`ts/README.md`](../ts/README.md) — the npm package page: install, the denial,
  and what else is in the box.
- [`ts/examples/agent.mjs`](../ts/examples/agent.mjs) — runnable programs.
- [The audit trail](audit-trail.md) — `auditSink` and `counterSource`; both
  lanes write the same records.
- [docs.watchlight.ai/de/typescript](https://docs.watchlight.ai/de/typescript).
