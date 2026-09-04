# Governance patterns

Copy-paste recipes for the high-stakes decisions people reach for the Developer
Edition to make: an agent that can **spend money**, **delete things**, **message
the outside world**, **move data**, or **spawn sub-agents**. Each pattern is a
*problem shape* — a policy, the code that governs the tool, and tests that prove
the verdicts — that you can drop into your own app and adapt.

Every policy here is run through the real engine by [`check.sh`](./check.sh), so
what a pattern claims and what the engine does can't drift.

## The patterns

| Pattern | The high-stakes question it answers |
|---|---|
| [Money-bounded agent](./money-bounded-agent.md) | May this agent spend *this much*, on *this*, right now — or does a human decide? |
| [Destructive actions](./destructive-actions.md) | Delete / drop / deploy: require a human, and make some things undeletable. |
| [External messaging](./external-messaging.md) | May the agent message *outside* — and only allowlisted destinations, with review? |
| [Data egress](./data-egress.md) | May *this classification* of data cross *this boundary*? Keep restricted data in. |
| [Egress after read](./egress-after-read.md) | Govern what a tool *returns* — decide on the result's classification after the fetch, in the audit trail. |
| [Kill-switch / quarantine](./kill-switch.md) | Stop a suspect agent cold — a hard boundary that beats every grant. |
| [Per-user attribution](./per-user-attribution.md) | Attribute the decision to the acting end-user, and scope policy to them. |
| [PII before read](./pii-before-read.md) | Strip PII from a document *before* the agent ever sees it. |
| [Sub-agent confinement](./subagent-confinement.md) | A spawned agent can only ever do *less* than its parent — never more. |

## Run them

```bash
pip install watchlight            # or: npm i -g @watchlight/sdk
examples/patterns/check.sh        # runs every suite + a private-data scan
```

`check.sh` runs each `suites/*.suite.json` through `watchlight policy test` and
scans the folder for anything resembling private data.

## Contributing a pattern — the one rule

> **Patterns are generic, not case studies.** Describe a *problem shape* — "an
> agent that moves money," "an agent that reads documents" — with a policy, code,
> and tests anyone can run. **No customer or company names, no real thresholds,
> credentials, endpoints, data, or screenshots, and no "requested by" framing.**
> If a detail would only make sense for one specific business, generalize it or
> drop it. Use illustrative round numbers and reserved example domains
> (`partner.example`). Named stories belong on the marketing site, with
> permission — never in this repo.

`check.sh` enforces the mechanical part (no emails, keys, or tokens); the rest is
on the author and the reviewer. When in doubt, leave it out.
