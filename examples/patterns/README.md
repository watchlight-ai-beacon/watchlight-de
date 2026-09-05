# Governance patterns

Copy-paste recipes for the high-stakes decisions people reach for the Developer
Edition to make: an agent that can **spend money**, **delete things**, **message
the outside world**, **move data**, or **spawn sub-agents**. Each pattern is a
*problem shape* — a policy, the code that governs the tool, and tests that prove
the verdicts — that you can drop into your own app and adapt.

Every policy here is run through the real engine by [`check.sh`](./check.sh), so
what a pattern claims and what the engine does can't drift.

## The patterns

| Pattern | The high-stakes question it answers | Verified by |
|---|---|---|
| [Money-bounded agent](./money-bounded-agent.md) | May this agent spend *this much*, on *this*, right now — or does a human decide? | [`money-bounded-agent.suite.json`](./suites/money-bounded-agent.suite.json) |
| [Destructive actions](./destructive-actions.md) | Delete / drop / deploy: require a human, and make some things undeletable. | [`destructive-actions.suite.json`](./suites/destructive-actions.suite.json) |
| [External messaging](./external-messaging.md) | May the agent message *outside* — and only allowlisted destinations, with review? | [`external-messaging.suite.json`](./suites/external-messaging.suite.json) |
| [Data egress](./data-egress.md) | May *this classification* of data cross *this boundary*? Keep restricted data in. | [`data-egress.suite.json`](./suites/data-egress.suite.json) |
| [Egress after read](./egress-after-read.md) | Govern what a tool *returns* — decide on the result's classification after the fetch, in the audit trail. | [`egress-after-read.suite.json`](./suites/egress-after-read.suite.json) |
| [Allow, but redact](./allow-but-redact.md) | Say "yes, but…" *in the policy* — `@obligate_redact` / `@obligate_max_items` / `@obligate_log_values` ride on the `Allow`, and the suite asserts them. | [`allow-but-redact.suite.json`](./suites/allow-but-redact.suite.json) |
| [Kill-switch / quarantine](./kill-switch.md) | Stop a suspect agent cold — a hard boundary that beats every grant. | [`kill-switch.suite.json`](./suites/kill-switch.suite.json) |
| [Per-user attribution](./per-user-attribution.md) | Attribute the decision to the acting end-user, and scope policy to them. | [`per-user-attribution.suite.json`](./suites/per-user-attribution.suite.json) |
| [Context through an adapter](./context-through-an-adapter.md) | Does a policy that reads Cedar `context` hold when the tool is wrapped by a framework adapter? | [`context-through-an-adapter.mjs`](./scripts/context-through-an-adapter.mjs) |
| [PII before read](./pii-before-read.md) | Strip PII from a document *before* the agent ever sees it. | [`pii-before-read.suite.json`](./suites/pii-before-read.suite.json) + [`pii-before-read.mjs`](./scripts/pii-before-read.mjs) |
| [Screen before model](./screen-before-model.md) | Catch prompt-injection shapes in what a read returns *before* the model reads it. | [`screen-before-model.mjs`](./scripts/screen-before-model.mjs) |
| [Sub-agent confinement](./subagent-confinement.md) | A spawned agent can only ever do *less* than its parent — never more. | [`subagent-confinement.mjs`](./scripts/subagent-confinement.mjs) |
| [Audit sink](./audit-sink.md) | Ship the value-free trail to a store you already run — Postgres, OTLP, a webhook — without touching a decision. | [`audit-sink.mjs`](./scripts/audit-sink.mjs) |
| [Quotas](./quotas.md) | *This many* reads per hour, writes per day — a counter folded from the audit trail into Cedar `context`. | [`quotas.suite.json`](./suites/quotas.suite.json) |

## Run them

```bash
pip install watchlight            # or: npm i -g @watchlight/sdk
examples/patterns/check.sh        # runs every suite + a private-data scan
```

`check.sh` first checks that **every** pattern doc has a matching check — a
`suites/<name>.suite.json` (policy verdicts, run through `watchlight policy test`)
and/or a `scripts/<name>.mjs` (a Node script for the parts that aren't a policy
verdict: `sanitize`, scope attenuation, the audit sink) — and fails if one has
neither. It then runs every suite and script, and scans the folder for anything
resembling private data. The scripts need Node >= 18 and resolve the SDK from a
global `npm i -g @watchlight/sdk` or an in-repo build (`cd ts && npm run build`).
The [allow-but-redact](./allow-but-redact.md) suite asserts obligations and needs
an engine that emits them — `@watchlight/engine` / `watchlight-engine`
**>= 0.2.0** (what the current SDK depends on); on an older engine it fails
rather than passing vacuously.

## Contributing a pattern — the one rule

> **Patterns are generic, not case studies.** Describe a *problem shape* — "an
> agent that moves money," "an agent that reads documents" — with a policy, code,
> and tests anyone can run. **No customer or company names, no real thresholds,
> credentials, endpoints, data, or screenshots, and no "requested by" framing.**
> If a detail would only make sense for one specific business, generalize it or
> drop it. Use illustrative round numbers and reserved example domains
> (`partner.example`). Named stories belong on the marketing site, with
> permission — never in this repo.

`check.sh` enforces the mechanical parts — every pattern ships a suite or script
named after its doc, and no emails, keys, or tokens anywhere; the rest is on the
author and the reviewer. When in doubt, leave it out.
