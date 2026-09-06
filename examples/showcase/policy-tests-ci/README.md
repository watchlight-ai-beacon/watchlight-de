# Policy tests as a CI gate

A policy is the only thing between an agent and a real action, so give it golden
fixtures and run them on every pull request. Copy this folder's shape into your
own repository.

```bash
cd examples/showcase/policy-tests-ci

watchlight policy test tickets.suite.json            # exit 0
watchlight policy test widened/tickets.suite.json    # exit 1
./run-local.sh                                       # both, in every installed lane
```

`watchlight policy test` ships in both lanes — `pip install watchlight` and
`npm i -g @watchlight/sdk` — and drives the same engine. It writes nothing to
the audit trail.

## What is here

```text
policies/ticket-agent.policy.json     the policy set under test
tickets.suite.json                    11 fixtures: Allow / Deny / NeedsApproval / approved
widened/                              a deliberately widened copy, and the same 11 fixtures
github-workflow.policy-tests.yml      GitHub Actions template — copy into .github/workflows/
run-local.sh                          the same gate, locally
```

The policy set is a support-ticket agent: reads gated on classification, refunds
banded by amount, closing reserved to one principal, and no policy at all for
`delete`.

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

## The widened policy

`widened/ticket-agent.policy.json` is what a careless edit looks like. The
`when` clause fell off the read permit, the `forbid` went with it, and the close
permit lost its principal:

```diff
-permit(principal, action == Action::"read", resource)
-  when { context.classification == "public" || context.classification == "internal" };
-forbid(principal, action == Action::"read", resource)
-  when { context.classification == "restricted" };
+permit(principal, action == Action::"read", resource);

-permit(principal == User::"ops", action == Action::"close", resource);
+permit(principal, action == Action::"close", resource);
```

The same fixtures go red, and the process exits 1:

```text
watchlight policy test — widened/tickets.suite.json

  ✓ public ticket may be read → Allow
  ✗ restricted ticket is never read — expected Deny, got Allow
  ✗ unclassified ticket fails closed — expected Deny, got Allow
  ✓ mid-size refund holds for a human → NeedsApproval
  ✗ anyone else may not close — expected Deny, got Allow
  …
8 passed, 3 failed (11 total)
```

Two `Deny` fixtures catch the read widening: one asserts the explicit `forbid`,
the other asserts that a request with **no** classification fails closed. A
permit with a `when` clause denies both; a bare permit allows both. Keep a
missing-context fixture for every attribute a policy reads.

## Wire it into CI

```bash
cp examples/showcase/policy-tests-ci/github-workflow.policy-tests.yml .github/workflows/policy-tests.yml
```

The template runs three jobs: `typescript` and `python` run `$SUITE` through
each CLI, and `gate-has-teeth` runs `$WIDENED_SUITE` and fails if it *passes*.
Point `SUITE` at your own suite, keep one lane or both, and keep a widened
variant of your policy next to it.

Exit codes, identical in both CLIs:

| Exit | When |
|---|---|
| `0` | every fixture produced its expected verdict |
| `1` | at least one verdict differed from `expect` |
| `2` | the suite file is missing or not valid JSON, has no `tests`, or a fixture lacks `action` or `expect` |

**A `policyFile` path that does not exist is not an error.** The engine is
fail-closed, so a missing file loads nothing and every fixture runs against zero
policies. Every `Allow` fixture then fails — but a suite of nothing but `Deny`
fixtures would pass green. Keep at least one `Allow` fixture in every suite.
`gate-has-teeth` also demands exit code exactly `1` from the widened suite, so a
missing CLI (`127`) or a malformed suite (`2`) can never read as a working gate.

## Add a case

```json
{ "name": "refund on a restricted ticket is denied",
  "action": "refund",
  "principal": "User::\"alice\"",
  "resource": "ticket/T-9",
  "context": { "amount": 40, "classification": "restricted" },
  "expect": "Deny" }
```

| Field | Required | Meaning |
|---|---|---|
| `action` | yes | the intent, matched by `action == Action::"<action>"` |
| `expect` | yes | `Allow`, `Deny` or `NeedsApproval` (case-insensitive; `permit` / `needs_approval` accepted) |
| `name` | no | label in the report; defaults to `<action> on <resource>` |
| `principal` | no | Cedar entity, e.g. `User::"alice"`; defaults to the agent identity |
| `resource` | no | Cedar resource, e.g. `ticket/T-1`; defaults to `resource` |
| `context` | no | attributes visible as `context.*`; omit one to test the fail-closed path |
| `approved` | no | `true` mints a single-use approval token and asserts the `NeedsApproval → Allow` downgrade |

`policyFile` resolves relative to the suite file. Inline `policies`
(`[{ "name", "code" }]`) work instead of, or alongside, a file.

Two habits keep the gate honest. Write one fixture per boundary, on both sides —
for `amount <= 100`, test 100 and 101. And when a real widening is needed,
change the fixtures first and watch them go red before touching the policy.

## Worth knowing

- A **bare identifier** in a fixture's `principal` matches `User`, `Agent`,
  `Group` and `Role` policies for that id, and when it matches more than one an
  allow beats a forbid. Write the type — `User::"alice"` — to test what you
  mean.
- `watchlight policy test` and `govern.test()` run the engine's decision core
  and write no records. A test that calls `authorize()` or a governed tool is a
  governed call like any other: set `WATCHLIGHT_AUDIT_FILE=0` for the test run
  to keep its records out of the application's trail.

Verified by [`check.sh`](./check.sh), which runs
[`run-local.sh`](./run-local.sh) and asserts that the workflow template's suite
paths still resolve. Nothing here runs the template itself — it is for your
repository. More policy shapes, each with its own suite, are in
[`examples/patterns/`](../../patterns/README.md); the reference is
[testing your policies](../../../docs/testing-policies.md).
