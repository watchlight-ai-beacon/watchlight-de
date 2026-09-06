# The TypeScript / Node lane

Same governance, in your Node app — no Python sidecar.
[`@watchlight/sdk`](https://www.npmjs.com/package/@watchlight/sdk) runs the same
compiled engine in-process (WebAssembly).

**Prerequisites:** Node **≥ 18**. `@watchlight/sdk` pulls in the compiled engine
(`@watchlight/engine`) automatically — no native toolchain.

```bash
npm install @watchlight/sdk
```

The five-minute `DENY` — install, one policy, two tools, one of them refused —
is in the [repository README](../README.md#quickstart), which shows it in both
lanes side by side. This page is what the Node lane gives you once that runs.

## It mirrors the Python package feature-for-feature

- **Runtime context, per-user, human-in-the-loop:**
  `govern.tool(fn, { intent, principal?, resource?, context?, onNeedsApproval?, onResult?, onResultTimeoutMs? })`
  — runtime facts into Cedar `context.*`, per-call `principal`, and a three-state
  `Allow` / `Deny` / **`NeedsApproval`** verdict with a single-use approval token.
  Approval tokens are signed with a **random per-process key** and recorded as
  used in an **in-process map** unless you configure otherwise — so by default a
  token cannot cross a process boundary, a restart invalidates outstanding
  approvals, and behind two replicas the same token can be consumed once on
  *each*. `approvalSecret` / `approval_secret` (or `WATCHLIGHT_APPROVAL_SECRET`,
  or the existing `signingSecret`, which covers both kinds of token — see
  [the signing secret](signing-secret.md)) makes a token portable; an `approvalStore` /
  `approval_store` (one method: `add(id, expiresAt)`) backed by a shared store
  makes single-use hold across replicas. `add` must be an **atomic
  check-and-set** — reserve the id only if absent, and say whether the
  reservation was new; a read followed by an unconditional write cannot enforce
  single use, because concurrent consumes of one token would all pass through
  the gap. The built-in default is atomic, so within one process N parallel
  consumes of one token yield exactly one `Allow`. A store that fails, times
  out, or will not report **refuses** the approval — it never admits one. The
  reservations are yours: the SDK never deletes one, and `expiresAt` /
  `expires_at` is the epoch-millisecond deadline after which an id is safe to
  drop — give the row a TTL, or implement the optional `prune(before)` and the
  SDK asks for the deletion on the same code path as the reservation. A store
  without `prune` is unchanged, and a failing `prune` never moves a decision.
  **Breaking in 0.8.0:** the signed payload is now length-prefixed and versioned,
  so no two different `(principal, action, resource)` triples can sign the same
  bytes — approval tokens minted by an earlier version do not verify against
  0.8.0. The tokens are short-lived, so drain in-flight approvals across the
  upgrade.
- **Govern what a tool returns:** `onResult(result, { intent, resource, principal,
  decisionId, obligations? })` (Python `on_result`) runs after the body and before
  the caller sees the result — sanitize, screen, honour the decision's
  obligations, or re-authorize on its classification; a
  returned value replaces the payload, a throw withholds it (fail-closed). Writes
  a value-free `egress` audit record joined to the decision by `decision_id`.
  The hook is **bounded**: `onResultTimeoutMs` / `on_result_timeout_ms`, 8 s by
  default, on `govern.tool()`, on `governTool` / `governTools` and on
  `governedHooks` alike. A hook that outruns it withholds the payload the same
  way a throwing one does — `EgressTimeout`, `withheld: true`, and a hook that
  settles later is discarded, so it can never release a payload late. There is no
  value that switches the deadline off; a hook that genuinely needs longer takes
  a larger number. **Breaking in 0.9.1:** only the Claude Agent path had a
  deadline before, so an egress hook slower than 8 s now withholds on
  `govern.tool()` and the LangChain adapters where it used to release late.
  Python enforces the deadline on an **async** tool body — it cannot interrupt a
  synchronous hook, so `on_result_timeout_ms` on a synchronous body is refused
  (`TypeError`) rather than silently ignored.
- **Obligations on an `Allow`:** a permit annotated `@obligate_redact("ssn")`,
  `@obligate_max_items("25")`, `@obligate_log_values("false")` (or any
  `@obligate_<name>("raw")`) yields `d.obligations` — `{ redact, maxItems,
  logValues, extra }` (Python `result["obligations"]`: `redact` / `max_items` /
  `log_values` / `extra`, the last as `{name: [values]}`) — constraints your code
  or `onResult` must honour. Several carriers merge to the strictest reading;
  only an `Allow` carries them; `Deny` and `NeedsApproval` never do; an
  unreadable obligation fails closed (`AuthorizeError`). Needs engine >= 0.2.0.
  See the [allow-but-redact pattern](../examples/patterns/allow-but-redact.md).
- **Frameworks:** `governedHooks()` for the Claude Agent SDK; `governTool()` /
  `governTools()` for LangChain / LangGraph.js. Each takes the same governance
  terms as `govern.tool()` — `principal`, `agent`, `resource` (`resourceFor` on
  the mapping forms), `context`, `onNeedsApproval`, `onResult`,
  `onResultTimeoutMs` — so a policy that
  reads Cedar `context.*` reaches the same verdict through an adapter as it does
  through a hand-written governed tool, and the record names the person the call
  was made for. Each is a fixed value or a function of the call. Pass none and
  the defaults are unchanged: the agent is the subject, the resource is
  `tool/<name>`, the context is empty. See the
  [context-through-an-adapter pattern](../examples/patterns/context-through-an-adapter.md).
- **Data minimization:** `govern.sanitize(text, { resource, decisionId, principal?, known? })`
  — strip PII before an agent reads a document: structured detectors (email,
  phone, SSN, card, IBAN, IPv4, API key, labelled passport / date of birth), an
  app-supplied `known` dictionary (`KNOWN`; simple case-insensitive match —
  Unicode case folding differs between lanes), and opt-in `PERSON` / `ADDRESS`
  heuristics. Pass the `decisionId` from `authorize` and the `sanitization`
  audit line joins the decision on `decision_id`; pass `principal` (Python
  `principal=`) and the line names *whose* data was redacted, under the same key
  the decision line uses. Omit it and the line still names a subject — this
  agent, typed as `Agent::"<name>"`, exactly as a decision that names no
  principal is recorded — so naming the person is what turns "redacted for the
  agent" into an answer a data-minimisation audit can use, and it is the only
  way to get one when the sanitization runs *before* any decision exists to
  join to.
- **Content screening:** `govern.screen(text, { resource, decisionId?, principal? })`
  — flag or redact prompt-injection shapes in what a read returns, before it
  reaches the model; with the `decisionId` the `screening` audit line joins the
  decision, and `principal` names whom it was screened for. Both fields are
  identifiers you supply — never anything derived from the content — and carry
  the same validation (1–128 characters, no control or line-separator
  characters).
- **Attenuation & graduation:** `govern.scope().attenuate()`; `scope.toToken()` /
  `govern.scopeFromToken()` carry an attenuated scope to a worker process (HMAC
  integrity; the receiving engine re-proves the subset); every decision returns a
  `decisionId` to join to your records; `WATCHLIGHT_APDP_URL` graduates the
  *same code* to the control plane.

Full API + runnable examples: [`ts/`](../ts/) · npm: `@watchlight/sdk` (glue,
Apache-2.0) + `@watchlight/engine` (the compiled engine). Docs:
[docs.watchlight.ai/de/typescript](https://docs.watchlight.ai/de/typescript).

## See also

- [`ts/README.md`](../ts/README.md) — the full package reference: every option,
  every adapter, and the longer worked examples.
- [`ts/examples/`](../ts/examples/) — runnable programs, starting with
  [`agent.mjs`](../ts/examples/agent.mjs).
- [The audit trail](audit-trail.md) — `auditSink`, `counterSource` and the
  record kinds, which are the same records both lanes write.
