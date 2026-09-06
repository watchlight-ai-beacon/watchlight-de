# Governance patterns

Copy-paste recipes for the high-stakes decisions people reach for the Developer
Edition to make: an agent that can **spend money**, **delete things**, **message
the outside world**, **move data**, or **spawn sub-agents**. Each one is a
problem shape — a policy, the code that governs the tool, and tests that prove
the verdicts — to drop into your own app and adapt.

Every policy here runs through the real engine in [`check.sh`](./check.sh), so
what a pattern claims and what the engine does cannot drift.

## The patterns

| Pattern | The question it answers | Verified by |
|---|---|---|
| [Money-bounded agent](./money-bounded-agent.md) | May this agent spend this much, on this, now — or does a human decide? | [suite](./suites/money-bounded-agent.suite.json) |
| [Destructive actions](./destructive-actions.md) | Delete, drop, deploy: require a human, and make some things undeletable. | [suite](./suites/destructive-actions.suite.json) |
| [External messaging](./external-messaging.md) | May the agent message outside, and only allowlisted destinations? | [suite](./suites/external-messaging.suite.json) |
| [Data egress](./data-egress.md) | May this classification of data cross this boundary? | [suite](./suites/data-egress.suite.json) |
| [Egress after read](./egress-after-read.md) | Govern what a tool *returns*, once its classification is known. | [suite](./suites/egress-after-read.suite.json) + [script](./scripts/egress-after-read.mjs) |
| [Allow, but redact](./allow-but-redact.md) | Say "yes, but…" in the policy — `@obligate_*` rides on the `Allow`. | [suite](./suites/allow-but-redact.suite.json) |
| [Kill-switch / quarantine](./kill-switch.md) | Stop a suspect agent cold, with one flag that beats every grant. | [suite](./suites/kill-switch.suite.json) |
| [Per-user attribution](./per-user-attribution.md) | Attribute the decision to the acting end-user, and scope policy to them. | [suite](./suites/per-user-attribution.suite.json) |
| [Context through an adapter](./context-through-an-adapter.md) | Does a policy reading Cedar `context` hold through a framework adapter? | [script](./scripts/context-through-an-adapter.mjs) |
| [PII before read](./pii-before-read.md) | Strip PII from a document before the agent ever sees it. | [suite](./suites/pii-before-read.suite.json) + [script](./scripts/pii-before-read.mjs) |
| [Screen before model](./screen-before-model.md) | Catch prompt-injection shapes in what a read returns. | [script](./scripts/screen-before-model.mjs) |
| [Sub-agent confinement](./subagent-confinement.md) | A spawned agent can only ever do less than its parent. | [script](./scripts/subagent-confinement.mjs) |
| [Audit sink](./audit-sink.md) | Ship the value-free trail to a store you already run. | [script](./scripts/audit-sink.mjs) |
| [Quotas](./quotas.md) | Allow this many reads per hour, folded from the trail into Cedar `context`. | [suite](./suites/quotas.suite.json) + [script](./scripts/quotas.mjs) |

The reference material these build on is in [`docs/`](../../docs/README.md).

## Run them

```bash
pip install watchlight            # or: npm i -g @watchlight/sdk
examples/patterns/check.sh        # every suite and script, plus a private-data scan
```

`check.sh` first checks that every pattern doc has a matching check. That is a
`suites/<name>.suite.json` for policy verdicts, a `scripts/<name>.mjs` for what
is not a verdict, or both. A doc with neither fails the run. It then runs them
all and scans the folder for anything resembling private data.

The scripts need Node >= 18 and resolve the SDK from a global
`npm i -g @watchlight/sdk` or an in-repo build (`cd ts && npm run build`). The
[allow-but-redact](./allow-but-redact.md) suite asserts obligations, so it needs
`@watchlight/engine` / `watchlight-engine` **>= 0.2.0**; on an older engine it
fails rather than passing vacuously.

## Contributing a pattern — the one rule

> **Patterns are generic, not case studies.** Describe a problem shape — "an
> agent that moves money," "an agent that reads documents" — with a policy, code,
> and tests anyone can run. **No customer or company names, no real thresholds,
> credentials, endpoints, data, or screenshots, and no "requested by" framing.**
> If a detail would only make sense for one specific business, generalize it or
> drop it. Use illustrative round numbers and reserved example domains
> (`partner.example`). Named stories belong on the marketing site, with
> permission — never in this repo.

`check.sh` enforces the mechanical parts: every pattern ships a suite or script
named after its doc, and no emails, keys, or tokens anywhere. The rest is on the
author and the reviewer. When in doubt, leave it out.
