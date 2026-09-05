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

## Who is acting, and on whose behalf

A governed call answers these questions, and they are separate inputs:

| Question | Where it goes | Example |
|---|---|---|
| On whose behalf does this run? | `principal` — the subject | `User::"alice"` |
| Which runtime is acting? | the reserved `actor` context key, set by the SDK | `context.actor == "flight-booker"` |
| Through whose delegation? | the reserved `actor_chain` context key | `context.actor_chain.contains("flight-booker")` |
| Under what narrowed authority? | the attenuation scope | `govern.scope(tools=[...])` |

```python
from watchlight import govern, principals

# the agent acting for a person
govern.authorize(action="book", principal=principals.user("alice"))
# the agent acting on its own behalf — an omitted principal is Agent::"<name>"
govern.authorize(action="cache")
```

```cedar
// this runtime may book for any user — whoever it acts for
permit(principal is User, action == Action::"book", resource)
when { context.actor == "flight-booker" };
```

`principal` is always a typed entity reference; build it with `principals.user`
/ `principals.agent`, which escape an identifier that came from outside. The
SDK sets `context.actor` on every call from the governor's agent name, and
refuses a caller-supplied value that disagrees, so a policy can trust it.

**One engine per policy set, many named agents.** Construct once (with the sink
and the secrets), load the policies once, then name each agent with a view: it
shares the engine, the compiled policies and their load memo, the audit trail,
the sink and the secrets, and only changes the stamped name. Construct a second
governor for a genuinely different policy set — not to give an agent a name.

```python
billing = govern.as_("billing-agent")     # no second engine, no second policy load
research = govern.as_("research-agent")
```

Views share the trail, so every named agent's records land in one destination,
told apart by the `agent` field — which is what makes a single audit stream
readable. Separate governors are how you get a separate trail per agent.

A sub-agent is a *delegation*, not a rename: `delegate` narrows a scope for it
(engine-enforced strict subset) and extends the actor chain, so the decision and
every record name both the sub-agent and whose delegation it acts under.

```python
root = govern.scope(tools=["search", "book"])
picker = govern.delegate(root, "seat-picker", tools=["search"])
picker.authorize(action="pick_seat", principal=principals.user("alice"))
# records agent "seat-picker", actor_chain ["flight-booker", "seat-picker"]
```

The subject is a stable identifier for whoever your application already
authenticated — a users-table primary key is as valid as a token's subject
claim, and no identity provider is required. Derive it from something you
authenticated, never from a request header or body a caller can set, and prefer
an id that never moves over an email or a username.

**→ Full reference: [The identity model](https://github.com/watchlight-ai-beacon/watchlight-de/blob/main/docs/identity-model.md)** — the
one-engine shape, the three cases with exact values, worked policies, where the
values come from, and the 0.8.0 migration note.

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
  Approval tokens are signed with a **random per-process key** and recorded as
  used in an **in-process map** unless you configure otherwise — so by default a
  token cannot cross a process boundary, a restart invalidates outstanding
  approvals, and behind two replicas the same token can be consumed once on
  *each*. `approvalSecret` / `approval_secret` (or `WATCHLIGHT_APPROVAL_SECRET`,
  or the existing `tokenSecret`, from which the approval key is derived with a
  distinct domain separator) makes a token portable; an `approvalStore` /
  `approval_store` (`has(id)` / `add(id, expiresAt)`) backed by a shared store
  makes single-use hold across replicas. A store that fails **refuses** the
  approval — it never admits one.
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
- **Obligations on an `Allow`:** a permit annotated `@obligate_redact("ssn")`,
  `@obligate_max_items("25")`, `@obligate_log_values("false")` (or any
  `@obligate_<name>("raw")`) yields `d.obligations` — `{ redact, maxItems,
  logValues, extra }` (Python `result["obligations"]`: `redact` / `max_items` /
  `log_values` / `extra`, the last as `{name: [values]}`) — constraints your code
  or `onResult` must honour. Several carriers merge to the strictest reading;
  only an `Allow` carries them; `Deny` and `NeedsApproval` never do; an
  unreadable obligation fails closed (`AuthorizeError`). Needs engine >= 0.2.0.
  See the [allow-but-redact pattern](examples/patterns/allow-but-redact.md).
- **Frameworks:** `governedHooks()` for the Claude Agent SDK; `governTool()` for
  LangChain / LangGraph.js.
- **Data minimization:** `govern.sanitize(text, { resource, decisionId, principal?, known? })`
  — strip PII before an agent reads a document: structured detectors (email,
  phone, SSN, card, IBAN, IPv4, API key, labelled passport / date of birth), an
  app-supplied `known` dictionary (`KNOWN`; simple case-insensitive match —
  Unicode case folding differs between lanes), and opt-in `PERSON` / `ADDRESS`
  heuristics. Pass the `decisionId` from `authorize` and the `sanitization`
  audit line joins the decision on `decision_id`; pass `principal` (Python
  `principal=`) and the line names *whose* data was redacted, under the same key
  the decision line uses — which is the only way to answer that when the
  sanitization runs *before* any decision exists to join to.
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

On an ephemeral host, keep the trail: pass an `audit_sink` and every record —
decisions, sanitizations, attenuations — is also handed to your code with exactly
the fields the file line carries (the file stays on). The sink is fire-and-forget
and can never block or change a decision; a failure is reported once.

```python
govern = Watchlight(agent="my-agent", audit_sink=lambda record: my_store.insert(record))
```

Reference sinks — a Postgres row, an OTLP log record, a webhook — are in
[`examples/patterns/audit-sink.md`](examples/patterns/audit-sink.md).

`audit_file=False` makes the sink the **sole** destination: no `.watchlight`
directory, no file, and `govern.counters(...)` — which reads the local file —
raises rather than counting zero. With neither a file nor a sink the SDK says so
once instead of discarding records silently. Note that the file is shared: every
governor pointed at the same directory, including concurrent instances in one
process and a test run in the same working directory, appends to the same
`audit.jsonl`, so those records interleave and are told apart only by their
fields.

The module-level `govern` is pre-constructed, so configure it before its first
governed call — otherwise it has no sink, and it says so the first time it
writes:

```python
from watchlight import govern, configure_default

configure_default(agent="billing-agent", audit_sink=my_store.insert)
```

`configure_default(...)` raises once the default governor has written a record:
records already written cannot reach a sink added later, and a trail split
across two destinations reads like a data bug.

The trail is also an input: `govern.counters(...)` folds it into a number for a
quota policy — decisions for exactly this principal (and intent / resource) in
the last `window`, from the record timestamps — so `context.reads_this_hour < 100`
has something to compare against. Streams the local file (bounded, 64 MiB by
default); malformed lines are skipped and counted, never echoed.

```python
c = govern.counters(principal='User::"u1"', intent="read", window="1h")   # {"count": 7, "window": {...}, ...}
govern.authorize(action="read", principal='User::"u1"', context={"reads_this_hour": c["count"]})
```

By default that count comes from the local file, which is per-container and does
not survive a deploy. `counter_source` / `counterSource` is the **read side** of
the sink: the same query, answered by the durable store the sink writes to, so
the quota spans every replica.

```python
govern = Watchlight(
    agent="my-agent",
    audit_sink=lambda record: my_store.insert(record),
    counter_source=lambda query: my_store.count_decisions(query),
)
c = govern.counters(principal='User::"u1"', intent="read", window="1h")   # c["source"] == "external"
```

The source is handed the validated, resolved query — `principal`, `intent`,
`resource`, `outcome` and a `window` whose `start` is exclusive and `end`
inclusive — and must return a non-negative integer. Fail-closed: it never falls
back to the local file, so a quota can never quietly under-count. An async source
is read with `counters_async(...)` / `countersAsync(...)`.

The [quotas pattern](examples/patterns/quotas.md) has the policy, the tool
binding, and the exact counting rules.

---

## Test your policies before they gate real actions

A policy is the only thing standing between an agent and a real action, so unit-test
it like any other code. Golden fixtures assert the expected verdict
(`Allow` / `Deny` / `NeedsApproval`) for a `(principal, action, resource, context)`;
a wrong expectation fails the suite. Run it in CI.

`govern.load(path)` is **idempotent per source**: the real path (symlinks
resolved) or an explicit `source_id=` is remembered, so priming an engine in a
factory and loading the same file again from an initialiser cannot double the
set. A missing file is not remembered, so it loads once it appears. The memo is
keyed on identity, not content — editing a loaded file and calling `load` again
is a no-op; pass `force=True` to load it again (additively). `govern.allow(code)` is
always additive — the same code twice is two policies. `govern.policy_count` and
`govern.has_policies` report what an engine holds, which is worth asserting at
start-up: no policies means every call is denied.

```python
from watchlight import govern

govern.load("watchlight.policy.json")
assert govern.has_policies, "no policies loaded — every call would be denied"
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
single-use token and assert the human-confirmed `NeedsApproval → Allow` downgrade;
set `"obligations": {"redact": ["ssn"]}` to also assert the obligations an `Allow`
carries (exact match; `{}` asserts none).

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

| Pattern | The high-stakes question | Verified by |
|---|---|---|
| [Money-bounded agent](./examples/patterns/money-bounded-agent.md) | Spend *this much*, on *this*, now — or does a human decide? | [`money-bounded-agent.suite.json`](./examples/patterns/suites/money-bounded-agent.suite.json) |
| [Destructive actions](./examples/patterns/destructive-actions.md) | Delete / drop / deploy: require a human; make some things undeletable. | [`destructive-actions.suite.json`](./examples/patterns/suites/destructive-actions.suite.json) |
| [External messaging](./examples/patterns/external-messaging.md) | May the agent message *outside* — allowlisted destinations only, with review? | [`external-messaging.suite.json`](./examples/patterns/suites/external-messaging.suite.json) |
| [Data egress](./examples/patterns/data-egress.md) | May *this classification* of data cross *this boundary*? | [`data-egress.suite.json`](./examples/patterns/suites/data-egress.suite.json) |
| [Egress after read](./examples/patterns/egress-after-read.md) | Govern what a tool *returns* — decide on the result's classification after the fetch. | [`egress-after-read.suite.json`](./examples/patterns/suites/egress-after-read.suite.json) |
| [Kill-switch / quarantine](./examples/patterns/kill-switch.md) | Stop a suspect agent cold — a hard boundary that beats every grant. | [`kill-switch.suite.json`](./examples/patterns/suites/kill-switch.suite.json) |
| [Per-user attribution](./examples/patterns/per-user-attribution.md) | Attribute the decision to the acting end-user, and scope policy to them. | [`per-user-attribution.suite.json`](./examples/patterns/suites/per-user-attribution.suite.json) |
| [PII before read](./examples/patterns/pii-before-read.md) | Strip PII from a document *before* the agent ever sees it; read only through the sanitizing path. | [`pii-before-read.suite.json`](./examples/patterns/suites/pii-before-read.suite.json) + [`pii-before-read.mjs`](./examples/patterns/scripts/pii-before-read.mjs) |
| [Screen before model](./examples/patterns/screen-before-model.md) | Catch prompt-injection shapes in what a read returns *before* the model reads it. | [`screen-before-model.mjs`](./examples/patterns/scripts/screen-before-model.mjs) |
| [Sub-agent confinement](./examples/patterns/subagent-confinement.md) | A spawned agent can only ever do *less* than its parent — never more. | [`subagent-confinement.mjs`](./examples/patterns/scripts/subagent-confinement.mjs) |
| [Audit sink](./examples/patterns/audit-sink.md) | Ship the value-free trail to a store you already run, without touching a decision. | [`audit-sink.mjs`](./examples/patterns/scripts/audit-sink.mjs) |
| [Quotas](./examples/patterns/quotas.md) | *This many* reads per hour, writes per day — a counter from the audit trail in `context`. | [`quotas.suite.json`](./examples/patterns/suites/quotas.suite.json) |

Patterns whose guarantee is not a policy verdict — sanitization, content
screening, scope attenuation, the audit sink — are verified by a Node script under
[`examples/patterns/scripts/`](./examples/patterns/scripts/) instead. Run every
suite and script at once:

```bash
examples/patterns/check.sh          # every pattern must have a suite or script; runs them all
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
| Scope across processes | HMAC scope token — integrity within one trust domain, not attestation (a secret holder can mint any scope, root included); the receiving engine re-proves the subset | independently attestable scopes |
| Content screening | rule-based, in-process, value-free: `govern.sanitize` (structured PII) + `govern.screen` (prompt-injection / output-leak shapes); not ML classification | a running guardrails service (ML classifiers, NER) |
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

What the principal *contains* — the subject, the acting runtime, and how a
policy names each — is [The identity model](https://github.com/watchlight-ai-beacon/watchlight-de/blob/main/docs/identity-model.md).

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
