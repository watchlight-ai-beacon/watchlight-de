# Testing your policies

A policy is the only thing standing between an agent and a real action, so it
deserves unit tests like any other code. You describe a set of cases, each with
the verdict you expect, and the governor checks every one against your loaded
policies.

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

Each test case (a fixture) states the verdict you expect for one combination
of principal, action, resource and context. If the engine reaches a different
verdict for any case, the suite fails.

`govern.test(...)` (in Node, `await govern.test([...])`) calls the engine's
decision core directly. That means it writes nothing to the audit trail, and it
has no decision logic of its own that could drift from what production does.

Beyond the keys shown above, a fixture accepts three more:

- `"approved": true` mints a single-use approval token for the case and asserts
  that a `NeedsApproval` verdict becomes `Allow` once it is approved.
- `"obligations": {"redact": ["ssn"]}` asserts the obligations that an `Allow`
  carries. The match must be exact, and `{}` asserts that there are none.
- `"actor": "document-reader"` evaluates the case as that agent. You need this
  for any policy that matches on `context.actor`.

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

The case runs against the same loaded policies, with `context.actor` set to the
name you gave. It is the same governor under a different name, not a second
engine, so the secrets and the approval store are shared. If you leave the
`actor` key out, the case runs as the governor's own agent, and a permit that
depends on the actor will come back as a denial.

A fixture key the runner does not recognise raises an error rather than being
silently ignored. A misspelling such as `"actr"` therefore fails the suite,
instead of quietly passing a case that tests something other than you meant.

## Run it in CI

To run the same checks in CI, put the policies and the fixtures together in one
`suite.json` file with the shape `{ policyFile?, policies?, tests: [...] }`.
`policyFile` and `policies` are optional, and `tests` holds the fixtures. Then
run it with the command below.

The command exits with status 1 if any case fails. It exits with status 2 if the
suite cannot be run as written, for example when the `policyFile` is missing,
malformed or empty, or when the suite declares no policies at all.

```bash
watchlight policy test suite.json                                 # Python
npx --package @watchlight/sdk watchlight policy test suite.json   # Node
```

## Worth knowing

- **An unrecognised `@enforcement_effect` value fails at load time.** Any value
  other than `attenuate`, `escalate`, `observe`, `quarantine`,
  `require_approval`, `revoke`, `sever_subtree` or `terminate` raises
  `PolicyError`, and `load` adds nothing from that file. A typo in the
  annotation *name* itself only produces a warning.
- `govern.load(path)` loads each source only once, so loading the same file
  twice cannot double the policy set. It remembers files by their resolved path,
  not by their content. If you edit a file that is already loaded, pass
  `force=True` to load it again. Because loading only ever adds, the previous
  copy stays loaded alongside the new one.

  To replace policies instead, use `reload`. Be careful: `reload(path)`
  replaces the governor's **entire** policy set, not just that file. Every
  other loaded file and every inline `allow` is dropped, so a `forbid` that
  lived in another file can disappear without any warning. Give `reload` the
  complete set you want to keep, either as one file that holds every policy or
  as an in-memory list: `govern.reload(policies=[...])` in Python, or
  `govern.reload({ policies: [...] })` in TypeScript (see [using the governor](using-the-governor.md#replacing-the-set-not-adding-to-it)).
- `govern.allow(code)` always adds. Passing the same code twice gives you two
  policies.
- `govern.load(path)` raises an error that names the file when the file is
  missing, contains invalid JSON, has an unrecognised shape, or holds no
  policies. It accepts a list of `{"name", "code"}` objects, an object of the
  form `{"policies": [...]}`, or a single policy object. To load an empty set on
  purpose, pass `allow_empty=True` (in TypeScript, `{ allowEmpty: true }`).
- `govern.policy_count` and `govern.has_policies` are worth asserting at
  start-up, because a governor with no policies denies every call.

## See also

- [`examples/showcase/policy-tests-ci/`](../examples/showcase/policy-tests-ci/README.md)
  — a suite, a GitHub Actions workflow that runs it in both lanes, and a widened
  policy that turns the run red.
- [Governance patterns](../examples/patterns/README.md) — every pattern ships
  the suite that proves its verdicts.
- [Using the governor](using-the-governor.md) — where policies are loaded.
