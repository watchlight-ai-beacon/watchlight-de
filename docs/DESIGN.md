<!-- INTERNAL — design synthesis + build plan. Review before public release. -->

# Watchlight Developer Edition — design synthesis & build plan

Source-of-truth vision: [`original-notes.md`](original-notes.md). Open forks:
[`DECISIONS.md`](DECISIONS.md). This file is the *how we build it* plan.

## North star (one number)

**Time from `pip install watchlight` to a `DENY` line the developer sees in their
own terminal.** Target: < 5 minutes, no account, no infrastructure. Everything is
in service of that line.

## The architecture in one sentence

The Developer Edition is an **in-process authorization backend** that is
API-compatible with the production policy service, so the *same* agent code runs
against either — dev (in-process) or prod (remote service) — with only a config
change.

```
  agent code  ──▶  Watchlight authorization API  ──▶  { in-process engine  (dev, default)
  (unchanged)                                          { remote policy service (prod, one env var)
```

The authorization *pipeline* is identical in both: delegation chain → intent →
goal → policy selection → **Cedar evaluation** → **strict-subset scope
attenuation** → fail-closed decision → value-free audit. Only the Cedar
evaluation *substrate* differs (see Decision D1).

## MVP — "Milestone 0: the DENY line"

The smallest thing that delivers the north star. Everything else is layered on.

**Deliverable:** a `watchlight` package where a developer writes tools + scopes +
a local policy, runs their script, and sees `ALLOW` / `DENY` lines — fail-closed,
engine-side attenuation, value-free audit — with zero infrastructure.

**In scope for M0:**
- In-process authorization engine (Cedar eval per D1) loaded from a local policy file.
- The core guarantees, non-negotiable: fail-closed, engine-side strict-subset
  attenuation, explicit scopes, value-free audit.
- A minimal governed surface (`@govern.tool` / a `govern()` call) + a runnable
  example that prints the ALLOW/DENY output.
- Audit to stdout + `.watchlight/audit.jsonl`.

**Explicitly deferred past M0:** the deepagents factory wiring (M1), the local
dashboard (M2), `@governed_tool` codegen (M3), docker-compose Level-2 (M4).

## Build milestones (front-load the demoable win)

| M | Deliverable | Gate |
|---|---|---|
| **0** | The DENY line — in-process engine + core guarantees + one example | a developer sees ALLOW/DENY in < 5 min, zero infra |
| **1** | Same API as prod — the real `create_governed_deep_agent` runs on the in-process backend (D2) | one env var flips dev↔prod, no code change |
| **2** | `watchlight dev` local dashboard — decisions, denials, scope tree, execution lineage | governance is *visible* |
| **3** | `@governed_tool` → derive policy + scope + registration; `watchlight policy export` | one declaration, not four files |
| **4** | Level-2 `docker compose up` — real policy service, policies still local | the dev→prod bridge is real |

Milestones map to the vision's "progressive disclosure" levels; M0–M1 are the
product, M2+ are adoption accelerants.

## Guarantees that are identical to production (must not weaken)

From the vision §5 — these are *constraints*, not ceremony, and they stay on in
dev:
1. **Fail-closed everywhere** — unscoped sub-agent → zero privileges; unreachable
   engine → refuse.
2. **Engine-side scope attenuation** — the engine, never the client, validates
   strict subset.
3. **Explicit scopes** — never inferred from tools or free text.
4. **Value-free audit** — argument *values* never enter the trail.

A dev edition that relaxes any of these teaches the wrong mental model and breaks
on the road to prod — worse than no dev edition.

## Friction fixes to fold in (from vision §4)

These are the "developer quit around step 6" fixes. Several are pure DE wins;
some belong upstream in the platform and are tracked back there:
- **DE-native:** derive-from-one-declaration codegen (M3), startup tool↔policy
  reconciliation warning, factory-only path (raise when `subagents=` non-empty),
  minimal `default.yaml` + workload headers.
- **Upstream (platform) items** the DE surfaces but doesn't own: PyPI publish of
  the SDK, public images / credential-free compose, `/ready` gated on migrations,
  shared-DB assertion at bootstrap, guardrails hot-reload. Track against the
  platform; the DE benefits when they land.

## Open, before deep build

Settle **D1** (Cedar substrate) and **D2** (relationship to the prod plugin) —
both in `DECISIONS.md`. They change what M0/M1 look like; a short spike on D1
(does a Cedar Python binding give us real evaluation with a clean `pip install`?)
de-risks the whole plan.
