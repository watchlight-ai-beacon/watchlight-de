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

Each option is a fixed value or a function of the call. Omit them all and the
agent is the subject, the resource is `tool/<name>`, the context is empty.

## Ask a human first

A policy annotated `@enforcement_effect("require_approval")` yields a third
verdict, `NeedsApproval`, and a single-use approval token.

```ts
const wire = govern.tool(transfer, { intent: "wire", onNeedsApproval: askOps });
```

By default that token is signed with a **random per-process key** and marked
used in an in-process map. It cannot cross a process boundary, a restart
invalidates outstanding approvals, and behind two replicas the same token is
consumable once on *each*. Two options fix that:

- `approvalSecret` makes a token portable. So does the `signingSecret`, which
  covers both kinds of token — see [the signing secret](signing-secret.md).
- `approvalStore` makes single use hold across replicas. One method,
  `add(id, expiresAt)`, which must be an **atomic check-and-set**: reserve the id
  only if absent, and report whether the reservation was new.

A store that fails, times out, or will not report **refuses** the approval.

**The reservations are yours.** The SDK never deletes one. `expiresAt` is the
epoch-millisecond deadline after which an id is safe to drop, so give the row a
TTL. Or implement the optional `prune(before)`, which the SDK calls
opportunistically alongside a reservation. A failing `prune` never moves a
decision.

## Govern what a tool returns

```ts
const read = govern.tool(readDoc, {
  intent: "read",
  onResult: (doc, { obligations, decisionId }) => redact(doc, obligations),
  onResultTimeoutMs: 8_000,
});
```

`onResult` runs after the body and before the caller sees the result. Sanitize,
screen, honour the decision's obligations, or re-authorize on the payload. A
returned value replaces it; a throw withholds it. Either way an `egress` record
is written, joined to the decision by `decision_id`.

**The hook is bounded.** `onResultTimeoutMs` defaults to 8 seconds, on
`govern.tool()`, `governTool` / `governTools` and `governedHooks` alike. Outrun
it and the payload is withheld exactly as a throw withholds it —
`EgressTimeout`, `withheld: true` — and a hook that settles later is discarded.
The deadline cannot be switched off; a hook that needs longer takes a larger
number.

Python enforces it on an **async** tool body only. It cannot interrupt a
synchronous hook, so `on_result_timeout_ms` on a synchronous body raises
`TypeError` rather than being ignored.

## Read the obligations on an Allow

```ts
const d = await govern.authorize({ action: "read", resource: "doc/1" });
d.obligations;   // { redact: ["ssn"], maxItems: 25 } — only the keys a policy set
```

A permit annotated `@obligate_redact("ssn")`, `@obligate_max_items("25")`,
`@obligate_log_values("false")` — or any `@obligate_<name>("raw")` — attaches
constraints your code or `onResult` must honour. Several carriers merge to the
strictest reading. Only an `Allow` carries them, and an unreadable obligation
fails closed with `AuthorizeError`. Needs engine >= 0.2.0. See the
[allow-but-redact pattern](../examples/patterns/allow-but-redact.md).

Fields: `redact`, `maxItems`, `logValues`, and `extra` for any
`@obligate_<name>` the SDK does not interpret. Python spells them `redact`,
`max_items`, `log_values`, `extra` under `result["obligations"]`.

## Frameworks

```ts
const { hooks } = governedHooks({ intentFor: (name) => TOOL_INTENTS[name] ?? name });   // Claude Agent SDK
const tools = governTools(myTools, { intentFor: (name) => TOOL_INTENTS[name] ?? name });
```

Each takes the same governance terms as `govern.tool()` — `principal`, `agent`,
`resource` (`resourceFor` on the mapping forms), `context`, `onNeedsApproval`,
`onResult`, `onResultTimeoutMs` — so a policy reaches the same verdict through
an adapter as through a hand-written governed tool. See the
[context-through-an-adapter pattern](../examples/patterns/context-through-an-adapter.md).

## Strip PII, and screen what comes back

```ts
const clean  = govern.sanitize(text, { resource: "doc/1", decisionId, principal });
const vetted = govern.screen(text,   { resource: "doc/1", decisionId, principal });
```

`sanitize` strips structured PII before an agent reads a document — email,
phone, SSN, card, IBAN, IPv4, API key, labelled passport and date of birth —
plus a `known` dictionary you supply and opt-in `PERSON` / `ADDRESS` heuristics.
`screen` flags or redacts prompt-injection shapes before text reaches the model.

`decisionId` joins the audit line to a decision. `principal` names *whose* data
it was. Omit `principal` and the line names this agent instead, as
`Agent::"<name>"` — so pass it when a data-minimisation audit has to name the
person. Both are identifiers you supply, never derived from the content, and
both are validated: 1–128 characters, no control characters.

## Attenuate, and graduate

```ts
const root  = await govern.scope({ tools: ["read", "write"] });
const child = root.attenuate({ tools: ["read"] });   // strictly a subset
const token = child.toToken();                       // carry it to a worker
```

`govern.scopeFromToken()` rebuilds it on the far side, and the receiving engine
re-proves the subset. Setting `WATCHLIGHT_APDP_URL` graduates the same code to
the control plane.

## Upgrading

- **0.9.1** — only the Claude Agent path had an egress deadline before. A hook
  slower than 8 s now withholds on `govern.tool()` and the LangChain adapters
  where it used to release late.
- **0.8.0** — the approval payload is length-prefixed and versioned, so no two
  `(principal, action, resource)` triples can sign the same bytes. Tokens minted
  by an earlier version do not verify. They are short-lived, so drain in-flight
  approvals across the upgrade.

## See also

- [`ts/README.md`](../ts/README.md) — the npm package page: install, the denial,
  and what else is in the box.
- [`ts/examples/agent.mjs`](../ts/examples/agent.mjs) — runnable programs.
- [The audit trail](audit-trail.md) — `auditSink` and `counterSource`; both
  lanes write the same records.
- [docs.watchlight.ai/de/typescript](https://docs.watchlight.ai/de/typescript).
