# Using the governor

Where the governor goes in an application, and what that looks like in a web
handler, a worker and a test. What to *pass* a governed call is the [identity
model](identity-model.md). Words used here are in the [glossary](glossary.md).

Every example below loads the same `watchlight.policy.json`:

```json
{
  "policies": [
    { "name": "the account owner may read her statement",
      "code": "permit(principal == User::\"db:4412\", action == Action::\"read_statement\", resource == Resource::\"account/acct-100\");" },
    { "name": "the reports worker may summarize for that owner",
      "code": "permit(principal == User::\"db:4412\", action == Action::\"summarize\", resource) when { context.actor == \"reports-worker\" };" }
  ]
}
```

## Construct it once, at start-up

Give the governor a module of its own. Construct it there, load the policy set
there, and import it everywhere else.

```python
# governance.py — the one module that holds the governor.
from pathlib import Path

from watchlight import Watchlight

POLICIES = Path(__file__).parent / "watchlight.policy.json"  # not relative to the working directory

govern = Watchlight(agent="statements-api")
govern.load(POLICIES)

# No policies means every call is denied. Fail at start-up, not in a request.
assert govern.has_policies, "no policies loaded — every call would be denied"
```

```ts
// governance.mjs — the one module that holds the governor.
import { fileURLToPath } from "node:url";

import { Watchlight } from "@watchlight/sdk";

const POLICIES = fileURLToPath(new URL("watchlight.policy.json", import.meta.url)); // not relative to the working directory

export const govern = new Watchlight({ agent: "statements-api" });
govern.load(POLICIES);

// No policies means every call is denied. Fail at start-up, not in a request.
if (!govern.hasPolicies) throw new Error("no policies loaded — every call would be denied");
```

Two details in that block matter:

- **The policy path does not depend on the working directory.** A `load` that
  misses its file raises nothing. It loads no policies, and every call is then
  denied.
- **It asserts that policies arrived.** The failure lands at start-up rather
  than in a request nobody can explain.

With a dependency container, register the governor as a long-lived singleton
built at start-up. A governor constructed inside a handler holds no policies
until that handler loads them.

## How many governors

**One per policy set.** Naming an agent is free, so several agents are not
several governors:

```python
from governance import govern

billing = govern.as_("billing-agent")
research = govern.as_("research-agent")
```

```ts
import { govern } from "./governance.mjs";

const billing = govern.as("billing-agent");
const research = govern.as("research-agent");
```

| Shared by every name off one governor | Not shared |
|---|---|
| the policy set — a policy added through any name applies to all of them | the agent name, stamped on every record as `agent` |
| the audit trail: the local file and the sink you configured | the delegation chain, which only `delegate` builds |
| the signing secret, the approval store and the counter source | |

Records from every name land in one trail, told apart by `agent`:

```text
{"agent":"statements-api","principal":"User::\"db:4412\"","intent":"invoice","decision":"Allow", …}
{"agent":"billing-agent","principal":"User::\"db:4412\"","intent":"invoice","decision":"Allow", …}
```

Construct a **second** governor when the policy set is genuinely different — a
strict set for real traffic, a permissive one for a sandbox. Wanting a separate
trail is the other reason; give it its own `audit_dir` / `auditDir`, because two
governors pointed at one directory append to the same `audit.jsonl`. Wanting a
different name is not a reason.

## In a request handler

The handler imports the governor. It takes the subject from the session the
request authenticated.

```python
# handler.py — the governor is imported, never constructed here.
from watchlight import DENY_REASON, Denied, principals
from governance import govern

STATEMENTS = {"acct-100": "closing balance 42.00"}


@govern.tool(
    "read_statement",
    # The subject comes from the session your application authenticated — never
    # from a header, a query parameter or the request body.
    principal=lambda session, account: principals.user(f"db:{session['user_id']}"),
    resource=lambda session, account: f"account/{account}",
)
def read_statement(session, account):
    return STATEMENTS[account]  # only reachable once the principal was authorized


def handle(session, account):
    try:
        return 200, read_statement(session, account)
    except Denied:
        return 403, DENY_REASON  # uniform "not authorized" — a denial never says why


print(handle({"user_id": 4412}, "acct-100"))  # the owner
print(handle({"user_id": 9001}, "acct-100"))  # another signed-in user
```

```ts
// handler.mjs — the governor is imported, never constructed here.
import { DENY_REASON, Denied, principals } from "@watchlight/sdk";
import { govern } from "./governance.mjs";

const STATEMENTS = { "acct-100": "closing balance 42.00" };

const readStatement = govern.tool((session, account) => STATEMENTS[account], {
  intent: "read_statement",
  // The subject comes from the session your application authenticated — never
  // from a header, a query parameter or the request body.
  principal: (session) => principals.user(`db:${session.userId}`),
  resource: (session, account) => `account/${account}`,
});

async function handle(session, account) {
  try {
    return [200, await readStatement(session, account)];
  } catch (e) {
    if (e instanceof Denied) return [403, DENY_REASON]; // uniform "not authorized" — a denial never says why
    throw e;
  }
}

console.log(await handle({ userId: 4412 }, "acct-100")); // the owner
console.log(await handle({ userId: 9001 }, "acct-100")); // another signed-in user
```

```text
watchlight: ALLOW  read_statement account/acct-100
watchlight: DENY   read_statement account/acct-100     not authorized
```

200 for the owner, 403 and the uniform `DENY_REASON` for the other signed-in
user. A caller probing the boundary learns nothing about which rule stopped it.
[Where subjects come from →](identity-model.md#where-the-values-come-from)

## In a background worker

A worker is a different process, so it constructs its own governor over the same
policy file. Two things cross the boundary: the narrowed authority for one job,
as a scope token, and the subject the enqueuing request authenticated.

Both processes must hold the **same** signing secret.
→ [The signing secret](signing-secret.md)

```python
# enqueue.py — runs in the web process.
from governance import govern


def enqueue_summary(session, account, queue):
    scope = govern.as_("reports-worker").scope(tools=["summarize"])  # minted under the worker's name
    queue.append(
        {
            "scope_token": scope.to_token(ttl_seconds=900),
            "subject": f"db:{session['user_id']}",  # the subject THIS request authenticated
            "account": account,
        }
    )
```

```ts
// enqueue.mjs — runs in the web process.
import { govern } from "./governance.mjs";

export async function enqueueSummary(session, account, queue) {
  const scope = await govern.as("reports-worker").scope({ tools: ["summarize"] }); // minted under the worker's name
  queue.push({
    scope_token: scope.toToken({ ttlSeconds: 900 }),
    subject: `db:${session.userId}`, // the subject THIS request authenticated
    account,
  });
}
```

```python
# worker.py — a separate process: its own governor, the same policy set.
import os
from pathlib import Path

from watchlight import Watchlight, principals

govern = Watchlight(
    agent="reports-worker",  # the name the scope token was minted under
    signing_secret=os.environ["WATCHLIGHT_SIGNING_SECRET"],  # the same value the web process holds
)
govern.load(Path(__file__).parent / "watchlight.policy.json")


def run_job(job):
    scope = govern.scope_from_token(job["scope_token"])  # rebuilt here, and re-proved by the engine
    if "summarize" not in scope.allowed_tools:
        raise PermissionError("not authorized")
    return govern.authorize(
        action="summarize",
        resource=f"account/{job['account']}",
        principal=principals.user(job["subject"]),  # the subject the enqueuing request authenticated
    )
```

```ts
// worker.mjs — a separate process: its own governor, the same policy set.
import { fileURLToPath } from "node:url";

import { Watchlight, principals } from "@watchlight/sdk";

const govern = new Watchlight({
  agent: "reports-worker",                              // the name the scope token was minted under
  signingSecret: process.env.WATCHLIGHT_SIGNING_SECRET, // the same value the web process holds
});
govern.load(fileURLToPath(new URL("watchlight.policy.json", import.meta.url)));

export async function runJob(job) {
  const scope = await govern.scopeFromToken(job.scope_token); // rebuilt here, and re-proved by the engine
  if (!scope.allowedTools.includes("summarize")) throw new Error("not authorized");
  return govern.authorize({
    action: "summarize",
    resource: `account/${job.account}`,
    principal: principals.user(job.subject),                  // the subject the enqueuing request authenticated
  });
}
```

Three things to get right, all of them in that block:

- **The worker's agent name matches the name the token was minted under.** A
  token presented under another name is refused.
- **Check the rebuilt scope before running the job.** A scope is not consulted
  when a call is authorized. The `allowed_tools` / `allowedTools` check is what
  refuses a job asking for something outside it.
- **The subject travels in the job record**, put there by your web process —
  never in anything the agent produced.

## In a test

A throwaway governor with a temporary audit directory keeps the test's records
out of the `.watchlight/audit.jsonl` the suite happens to run next to.

```python
# test_statements.py
import tempfile
from pathlib import Path

from watchlight import Watchlight

POLICIES = Path(__file__).parent / "watchlight.policy.json"


def test_statement_policies():
    with tempfile.TemporaryDirectory() as audit_dir:
        govern = Watchlight(agent="test", audit_dir=audit_dir)
        govern.load(POLICIES)
        assert govern.has_policies

        report = govern.test(
            [
                {"name": "the owner may read her statement", "action": "read_statement",
                 "principal": 'User::"db:4412"', "resource": "account/acct-100", "expect": "Allow"},
                {"name": "another signed-in user may not", "action": "read_statement",
                 "principal": 'User::"db:9001"', "resource": "account/acct-100", "expect": "Deny"},
            ]
        )
        assert report["failed"] == 0, report
```

```ts
// statements.test.mjs — run with `node --test`
import * as assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

import { Watchlight } from "@watchlight/sdk";

const POLICIES = fileURLToPath(new URL("watchlight.policy.json", import.meta.url));

test("statement policies", async () => {
  const auditDir = fs.mkdtempSync(join(os.tmpdir(), "statements-test-"));
  try {
    const govern = new Watchlight({ agent: "test", auditDir });
    govern.load(POLICIES);
    assert.ok(govern.hasPolicies);

    const report = await govern.test([
      { name: "the owner may read her statement", action: "read_statement",
        principal: 'User::"db:4412"', resource: "account/acct-100", expect: "Allow" },
      { name: "another signed-in user may not", action: "read_statement",
        principal: 'User::"db:9001"', resource: "account/acct-100", expect: "Deny" },
    ]);
    assert.equal(report.failed, 0, JSON.stringify(report.results));
  } finally {
    fs.rmSync(auditDir, { recursive: true, force: true });
  }
});
```

Test the *deployed* policy file, not a copy pasted into the test. The `Deny`
fixtures matter as much as the `Allow`: a policy that has been accidentally
widened still passes every `Allow` case. Every fixture key, the `suite.json`
form and the CI runner are on [testing your policies](testing-policies.md).

## Using the exported default governor

`from watchlight import govern` gives you a governor that is already
constructed — the right one for a single-process script, CLI, notebook or
example. Configure it before its first governed call:

```python
from watchlight import configure_default, govern

records = []
configure_default(agent="report-cli", audit_sink=records.append)  # before the first governed call
govern.load("watchlight.policy.json")

govern.authorize(action="read_statement", resource="account/acct-100", principal='User::"db:4412"')
```

```ts
import { configureDefault, govern } from "@watchlight/sdk";

const records = [];
configureDefault({ agent: "report-cli", auditSink: (r) => records.push(r) }); // before the first governed call
govern.load("watchlight.policy.json");

await govern.authorize({ action: "read_statement", resource: "account/acct-100", principal: 'User::"db:4412"' });
```

Anything with more than one policy set constructs its own, as at the top of this
page.

### Configuring it twice

```python
configure_default(agent="report-cli", audit_sink=records.append)   # again, same options → no-op
configure_default(agent="other")                                   # RuntimeError: agent would change …
```

Once the default governor has written its first record, its destination is
fixed. Re-applying the configuration already in force is a no-op. Changing an
option raises, and the error names the option, the old value and the new one.
Secret values are compared in constant time and never appear in it.

Two sinks match only if they are the same function on the same object.
`audit_sink=my_store.insert` passed twice is one sink. A rebuilt lambda, a new
closure or a fresh `fn.bind(obj)` is a different sink and conflicts. Bind once,
and pass the result around.

To ask before calling:

```python
from watchlight import can_configure_default, configure_default

if can_configure_default():
    configure_default(audit_sink=records.append)
```

```ts
import { canConfigureDefault, configureDefault } from "@watchlight/sdk";

if (canConfigureDefault()) {
  configureDefault({ auditSink: (r) => records.push(r) });
}
```

It is `true` until the first record is written and `false` afterwards, and
asking mutates nothing. `false` does not mean every call fails: options identical
to the ones in force are still accepted.

### Configuring it from the environment

```bash
WATCHLIGHT_AUDIT_FILE=0 pytest                # this run writes no trail into the working directory
WATCHLIGHT_AUDIT_DIR=.watchlight-test pytest  # …or keeps its own, next to the application's
```

Three variables configure the default governor without touching code, for a test
run, a container or a CI job:

| Variable | Effect |
|---|---|
| `WATCHLIGHT_AUDIT_DIR` | the directory `audit.jsonl` is written into (default `.watchlight`) |
| `WATCHLIGHT_AUDIT_FILE` | `0` / `false` / `no` / `off` writes no local file at all; `1` / `true` / `yes` / `on` keeps it |
| `WATCHLIGHT_AGENT` | the agent name, when the `agent` option does not give one; blank counts as unset |

That is the fix for a test suite sharing a working directory with a running
application. Policy tests (`govern.test()`, `watchlight policy test`) write
nothing already. A test that calls `authorize()` or a governed tool appends a
record like any other call.

Worth knowing:

- **Precedence is option, then environment, then default.** A governor you
  construct names its own options, so neither variable touches it.
- **`WATCHLIGHT_AUDIT_FILE=0` is `audit_file=False` by another route.** No
  `.watchlight` directory is created, `govern.counters(...)` raises rather than
  counting zero, and `watchlight dev` has nothing to tail. Use
  `WATCHLIGHT_AUDIT_DIR` when you want the trail kept, just not here.
- An unrecognised `WATCHLIGHT_AUDIT_FILE` value is reported once and ignored, so
  a typo cannot quietly turn a trail off.

## Loading policies

```python
from watchlight import Watchlight

govern = Watchlight(agent="statements-api")

govern.load("watchlight.policy.json")
print(govern.policy_count)          # 2
govern.load("watchlight.policy.json")
print(govern.policy_count)          # 2 — the same source loads once

govern.allow('permit(principal, action == Action::"ping", resource);')
govern.allow('permit(principal, action == Action::"ping", resource);')
print(govern.policy_count)          # 4 — allow() always adds

govern.load("watchlight.policy.json", force=True)
print(govern.policy_count)          # 6 — force adds another copy; nothing is ever removed
```

```ts
import { Watchlight } from "@watchlight/sdk";

const govern = new Watchlight({ agent: "statements-api" });

govern.load("watchlight.policy.json");
console.log(govern.policyCount);    // 2
govern.load("watchlight.policy.json");
console.log(govern.policyCount);    // 2 — the same source loads once

govern.allow('permit(principal, action == Action::"ping", resource);');
govern.allow('permit(principal, action == Action::"ping", resource);');
console.log(govern.policyCount);    // 4 — allow() always adds

govern.load("watchlight.policy.json", { force: true });
console.log(govern.policyCount);    // 6 — force adds another copy; nothing is ever removed
```

- **Policies are only ever added.** There is no unload.
- **`load` is idempotent per source.** Two paths to one file are one source.
  Give two files a shared `source_id` / `sourceId` to make them one too.
- **A file that does not exist is not remembered**, so it loads the first time
  it appears.
- **Editing a loaded file and calling `load` again changes nothing.** No error,
  no warning. A policy change takes effect on a **restart**, not on a re-`load`.
  `force` loads the file again, but nothing is ever removed, so you then hold
  both copies. Construct a fresh governor when the old set has to be gone.

## Enforcement effects are checked at load

A policy can carry an **enforcement effect** — what the engine does beyond
allowing or denying:

```cedar
@enforcement_effect("require_approval")
permit(principal, action == Action::"wire", resource)
when { context.amount > 1000 };
```

That one is the human-in-the-loop gate. The verdict is `NeedsApproval` rather
than `Allow`, and a person has to release it. The engine implements

`attenuate`, `escalate`, `observe`, `quarantine`, `require_approval`, `revoke`,
`sever_subtree`, `terminate`

and `allow` and `load` refuse anything else, in both lanes, before the policy
reaches the engine:

```python
govern.allow('@enforcement_effect("needs_approval")\npermit(principal, action, resource);')
# PolicyError: policy "policy-0": @enforcement_effect("needs_approval") is not an
# effect this engine implements. Accepted: attenuate, escalate, observe,
# quarantine, require_approval, revoke, sever_subtree, terminate. …
```

The Developer Edition acts on `require_approval`; the containment verbs load
and validate, and the verdict stays a plain `Deny`. Acting on `quarantine`,
`revoke`, `sever_subtree` or `terminate` is the Enterprise plane, so
[email sales@watchlight.ai](mailto:sales@watchlight.ai?subject=Watchlight%20Enterprise) if you need it.

Worth knowing:

- **A refusal is whole-file or nothing.** One bad policy loads none of the file,
  and the source is not remembered — fix it and load again.
- **A misspelled annotation NAME warns and still loads.** `@enforcment_effect`
  is legitimate Cedar and may well be yours. A near miss prints a warning;
  anything further away is silent.

## See also

- [The identity model](identity-model.md) — the subject you pass, the actor a
  policy reads, and delegation
- [Breaking changes](breaking-changes.md) — read before you bump the version
- [The signing secret](signing-secret.md) — the value both processes need before
  a token crosses between them
- [Glossary](glossary.md) — governor, policy set, scope, trail, and every other
  term
- [`examples/showcase/web-backend/`](../examples/showcase/web-backend/README.md)
  — the request-handler shape as a running FastAPI and Express app
- [`examples/showcase/identity/`](../examples/showcase/identity/README.md) — one
  governor, several named agents, in one audit stream
