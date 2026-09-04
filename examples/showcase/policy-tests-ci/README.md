# Showcase: policy tests as a CI gate

A policy is the only thing between an agent and a real action, so it gets the
same treatment as code: golden fixtures, run on every pull request, red when a
verdict changes. This folder is a copy-and-paste setup for that gate.

```
policy-tests-ci/
├── policies/ticket-agent.policy.json     the policy set under test
├── tickets.suite.json                    11 fixtures: Allow / Deny / NeedsApproval / approved
├── widened/
│   ├── ticket-agent.policy.json          a deliberately widened copy (two `when` clauses dropped)
│   └── tickets.suite.json                the same 11 fixtures, pointed at the widened policy
├── github-workflow.policy-tests.yml      GitHub Actions TEMPLATE — copy into .github/workflows/
└── run-local.sh                          reproduces the gate locally, in every installed lane
```

The suite runs through `watchlight policy test`, which exists in both lanes —
the TypeScript CLI (`npm i -g @watchlight/sdk`) and the Python CLI
(`pip install watchlight`) — and drives the same engine. Every verdict below
comes from the engine; the harness has no decision logic of its own and never
writes to the audit trail.

## The policy set

A support-ticket agent: reads gated on classification, refunds banded by amount,
closing reserved to one principal, and no policy at all for `delete`.

```cedar
permit(principal, action == Action::"read", resource)
  when { context.classification == "public" || context.classification == "internal" };

forbid(principal, action == Action::"read", resource)
  when { context.classification == "restricted" };

permit(principal, action == Action::"refund", resource) when { context.amount <= 100 };

@enforcement_effect("require_approval")
permit(principal, action == Action::"refund", resource)
  when { context.amount > 100 && context.amount <= 1000 };

permit(principal == User::"ops", action == Action::"close", resource);
```

## Run it locally

```bash
pip install watchlight            # and/or: npm i -g @watchlight/sdk
cd examples/showcase/policy-tests-ci

watchlight policy test tickets.suite.json            # exit 0
watchlight policy test widened/tickets.suite.json    # exit 1
./run-local.sh                                       # both, in every installed lane
```

Both CLIs print the same report. Green, on the correct policy:

```
watchlight policy test — tickets.suite.json

  ✓ public ticket may be read → Allow
  ✓ internal ticket may be read → Allow
  ✓ restricted ticket is never read → Deny
  ✓ unclassified ticket fails closed → Deny
  ✓ small refund is allowed → Allow
  ✓ mid-size refund holds for a human → NeedsApproval
  ✓ mid-size refund proceeds once approved → Allow
  ✓ refund above the approval band is denied → Deny
  ✓ ops may close a ticket → Allow
  ✓ anyone else may not close → Deny
  ✓ delete has no policy and is denied → Deny

11 passed, 0 failed (11 total)
```

## The widened policy

`widened/ticket-agent.policy.json` is what a careless edit looks like: the
`when` clause fell off the read permit (and the `forbid` went with it), and the
close permit lost its principal.

```diff
-permit(principal, action == Action::"read", resource)
-  when { context.classification == "public" || context.classification == "internal" };
-forbid(principal, action == Action::"read", resource)
-  when { context.classification == "restricted" };
+permit(principal, action == Action::"read", resource);

-permit(principal == User::"ops", action == Action::"close", resource);
+permit(principal, action == Action::"close", resource);
```

The same fixtures now fail — and the process exits 1, which is what fails the CI
check:

```
watchlight policy test — widened/tickets.suite.json

  ✓ public ticket may be read → Allow
  ✓ internal ticket may be read → Allow
  ✗ restricted ticket is never read — expected Deny, got Allow
  ✗ unclassified ticket fails closed — expected Deny, got Allow
  ✓ small refund is allowed → Allow
  ✓ mid-size refund holds for a human → NeedsApproval
  ✓ mid-size refund proceeds once approved → Allow
  ✓ refund above the approval band is denied → Deny
  ✓ ops may close a ticket → Allow
  ✗ anyone else may not close — expected Deny, got Allow
  ✓ delete has no policy and is denied → Deny

8 passed, 3 failed (11 total)
```

Note the two deny fixtures that catch the read widening: one asserts the
explicit `forbid`, the other asserts that a request with **no** classification
fails closed. A permit with a `when` clause denies both; a bare permit allows
both. Keep a "missing context" fixture for every attribute a policy reads.

## Wire it into CI

`github-workflow.policy-tests.yml` is a template. It is not under this repo's
`.github/workflows/` on purpose — copy it into yours:

```bash
cp examples/showcase/policy-tests-ci/github-workflow.policy-tests.yml .github/workflows/policy-tests.yml
```

It defines three jobs:

| job | what it does |
|---|---|
| `typescript` | `npm install -g @watchlight/sdk` → `watchlight policy test "$SUITE"` |
| `python` | `pip install watchlight` → `watchlight policy test "$SUITE"` |
| `gate-has-teeth` | runs the suite against `WIDENED_SUITE` and fails if it **passes** — proof the fixtures still catch the widening |

Set `SUITE` to your own suite path; keep one or both lanes; drop
`gate-has-teeth` or keep a widened variant of your own next to your policy.

Exit codes, identical in both CLIs:

| exit | when |
|---|---|
| `0` | every fixture produced its expected verdict |
| `1` | at least one verdict differed from `expect` |
| `2` | the suite file is missing or not valid JSON, has no `tests`, or a fixture lacks `action` or `expect` |

One thing the loader does **not** treat as an error: a `policyFile` path that
does not exist. The engine is fail-closed, so a missing policy file loads
nothing and every fixture is evaluated against zero policies — every `Allow` and
`NeedsApproval` fixture then fails (exit `1`), but a suite whose fixtures all
expect `Deny` would pass (exit `0`). Keep at least one `Allow` fixture in every
suite so a mistyped `policyFile` shows up as a red run, not a green one. The
`gate-has-teeth` job also requires exit code exactly `1` from the widened suite
and a passing run of the correct one in the same job, so a missing CLI (exit
`127`) or a malformed suite (exit `2`) can never read as "the gate works".

## Add a case

A fixture is one object in `tests`:

```json
{ "name": "refund on a restricted ticket is denied",
  "action": "refund",
  "principal": "User::\"alice\"",
  "resource": "ticket/T-9",
  "context": { "amount": 40, "classification": "restricted" },
  "expect": "Deny" }
```

| field | required | meaning |
|---|---|---|
| `action` | yes | the intent, matched by `action == Action::"<action>"` |
| `expect` | yes | `Allow`, `Deny`, or `NeedsApproval` (case-insensitive; `permit` / `needs_approval` accepted) |
| `name` | no | label in the report; defaults to `<action> on <resource>` |
| `principal` | no | Cedar entity, e.g. `User::"alice"`; defaults to the agent identity |
| `resource` | no | Cedar resource, e.g. `ticket/T-1`; defaults to `resource` |
| `context` | no | attributes visible as `context.*`; omit an attribute to test the fail-closed path |
| `approved` | no | `true` mints a valid single-use approval token for this case, asserting the human-confirmed downgrade from `NeedsApproval` to `Allow` |

`policyFile` is resolved relative to the suite file. Inline `policies`
(`[{ "name", "code" }]`) can be used instead of, or in addition to, a file. The
suite is plain JSON, so the same file is read by both CLIs.

Two habits that keep the gate honest:

1. **One fixture per boundary, on both sides.** For `amount <= 100`, test 100
   and 101; for a classification list, test each member, one non-member, and
   the missing attribute.
2. **Keep the widened variant.** When a real widening is needed, change the
   fixtures first and watch them go red before touching the policy — the
   `gate-has-teeth` job does the same thing on every run.

See [`examples/patterns/`](../../patterns/README.md) for more policy shapes,
each with a suite that runs through the same harness.
