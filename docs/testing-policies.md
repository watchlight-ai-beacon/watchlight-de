# Testing your policies

A policy is the only thing between an agent and a real action. Unit-test it.

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

Each fixture asserts the verdict for a `(principal, action, resource, context)`.
A wrong expectation fails the suite.

`govern.test(...)` (Node: `await govern.test([...])`) drives the engine's
decision core directly, so it writes nothing to the audit trail and holds no
decision logic of its own.

Three more fixture keys:

- `"approved": true` mints a single-use token and asserts the
  `NeedsApproval → Allow` downgrade.
- `"obligations": {"redact": ["ssn"]}` asserts the obligations an `Allow`
  carries. Exact match; `{}` asserts none.
- `"actor": "document-reader"` evaluates the case as that agent, which is what a
  policy matching on `context.actor` needs.

## Testing a policy that names the actor

A policy written against the acting agent needs a fixture that can act as one:

```cedar
permit(principal, action == Action::"review", resource)
when { context.actor == "document-reader" };
```

```python
report = govern.test([
    {"action": "review", "actor": "document-reader", "expect": "Allow"},
    {"action": "review", "actor": "auditor", "expect": "Deny"},
])
```

The case runs against the same loaded policies under a different `context.actor`
— it is the governor renamed, not a second engine, so secrets and the approval
store are shared. Without the key the case runs as the governor's own agent, and
an actor-conditioned permit reads as a denial.

A key the runner does not implement raises rather than being dropped, so a
misspelled `"actr"` fails the suite instead of passing a case that proves
something else.

## Run it in CI

Put policies and fixtures in one `suite.json` —
`{ policyFile?, policies?, tests: [...] }` — and run it. Exit 1 on any failure:

```bash
watchlight policy test suite.json                                 # Python
npx --package @watchlight/sdk watchlight policy test suite.json   # Node
```

## Worth knowing

- **An unrecognised `@enforcement_effect` fails at load.** Anything outside
  `attenuate`, `escalate`, `observe`, `quarantine`, `require_approval`, `revoke`,
  `sever_subtree`, `terminate` raises `PolicyError`, and `load` adds nothing from
  that file. A typo in the annotation *name* only warns.
- `govern.load(path)` is idempotent per source, so priming an engine twice
  cannot double the policy set. The memo is keyed on the resolved path, not on
  content: edit a loaded file and pass `force=True` to load it again.
- `govern.allow(code)` is always additive. The same code twice is two policies.
- `govern.policy_count` and `govern.has_policies` are worth asserting at
  start-up. No policies means every call is denied.

## See also

- [`examples/showcase/policy-tests-ci/`](../examples/showcase/policy-tests-ci/README.md)
  — a suite, a GitHub Actions workflow that runs it in both lanes, and a widened
  policy that turns the run red.
- [Governance patterns](../examples/patterns/README.md) — every pattern ships
  the suite that proves its verdicts.
- [Using the governor](using-the-governor.md) — where policies are loaded.
