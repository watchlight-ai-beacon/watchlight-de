# Testing your policies

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

Both entry points **check the enforcement effect before the policy loads**. A
policy annotated with an `@enforcement_effect` the engine does not implement —
anything outside `attenuate`, `escalate`, `observe`, `quarantine`,
`require_approval`, `revoke`, `sever_subtree`, `terminate` — raises `PolicyError`
naming the value and the accepted set, and `load` adds nothing from that file. An
unrecognised effect is otherwise *dropped*, which on a `forbid` is harmless (a
deny stays a deny) but on a `permit` turns a `require_approval` hold into an
unconditional allow, so a one-character typo would quietly remove a
human-in-the-loop gate. A near miss for the annotation *name* (`@enforcment_effect`)
warns instead of raising — an annotation the SDK does not read may well be yours.
See [the enforcement effect](using-the-governor.md#the-enforcement-effect-is-checked-when-the-policy-loads).

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
watchlight policy test suite.json                                 # Python
npx --package @watchlight/sdk watchlight policy test suite.json   # Node
```


## See also

- [`examples/showcase/policy-tests-ci/`](../examples/showcase/policy-tests-ci/README.md)
  — a policy set, an 11-fixture suite, a GitHub Actions workflow that runs it in
  both lanes, and a deliberately widened policy that turns the run red.
- [Governance patterns](../examples/patterns/README.md) — every pattern ships
  the suite that proves its verdicts, so each one is also a worked example of a
  fixture set.
- [Using the governor](using-the-governor.md#loading-policies) — where policies
  are loaded, and what a test governor should share with the real one.
