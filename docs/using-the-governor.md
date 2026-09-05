# Using the governor

You have governed a tool and seen a `DENY`. The next questions are structural:
where does the governor go in an application, how many do you need, and what
does that look like in a web handler, a worker and a test.

What to *pass* a governed call — the subject, the acting agent — is the
[identity model](identity-model.md). Words used here are in the
[glossary](glossary.md).

Every example on this page loads the same policy file, `watchlight.policy.json`:

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

Give the governor a module of its own, construct it there, and load the policy
set in the same place. Everything else imports it.

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

Two things that block does deliberately:

- **The policy path does not depend on the working directory.** A web process, a
  worker and a test runner rarely share one, and a `load` that misses its file
  raises nothing — it loads no policies, and every call is then denied.
- **It asserts that policies arrived.** That is the difference between a start-up
  failure you see and a production request that is refused for a reason nobody
  can find.

If your application uses a dependency container, register the governor as a
single long-lived instance — a singleton provider built at start-up — rather
than a factory the container calls per request. Either way the rule is the same:
one instance for the process, built before the first request reaches it. A
governor constructed inside a handler holds no policies until that handler loads
them, so any path that skips the load denies everything, and the load is paid on
every request.

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

Six named agents cost one policy load and one audit trail. Nothing is re-read,
and `policy_count` / `policyCount` is the same number through every name.

Construct a **second** governor when the policy set is genuinely different — a
strict set for real traffic and a permissive one for a sandbox:

```python
from watchlight import Watchlight

sandbox = Watchlight(agent="sandbox-agent", audit_dir=".watchlight/sandbox")
sandbox.load("sandbox.policy.json")
```

```ts
import { Watchlight } from "@watchlight/sdk";

const sandbox = new Watchlight({ agent: "sandbox-agent", auditDir: ".watchlight/sandbox" });
sandbox.load("sandbox.policy.json");
```

Wanting a separate audit trail is the other reason: two governors pointed at the
same directory append to the same `audit.jsonl`, so a separate directory is what
separates the files. Wanting a different name is not a reason.

## What every name shares

| Shared by everything named from one governor | Not shared |
|---|---|
| the policy set — a policy added through any name applies to all of them | the agent name, stamped on every record as `agent` |
| the audit trail: the local file and the sink you configured | the delegation chain, which only `delegate` builds |
| the signing secret, the approval store and the counter source | |

```python
from watchlight import principals
from governance import govern

billing = govern.as_("billing-agent")
billing.allow('permit(principal is User, action == Action::"invoice", resource);')

print(govern.policy_count == billing.policy_count)                        # one policy set
govern.authorize(action="invoice", principal=principals.user("db:4412"))  # allowed under either name
billing.authorize(action="invoice", principal=principals.user("db:4412"))
```

```ts
import { principals } from "@watchlight/sdk";
import { govern } from "./governance.mjs";

const billing = govern.as("billing-agent");
billing.allow('permit(principal is User, action == Action::"invoice", resource);');

console.log(govern.policyCount === billing.policyCount);                              // one policy set
await govern.authorize({ action: "invoice", principal: principals.user("db:4412") }); // allowed under either name
await billing.authorize({ action: "invoice", principal: principals.user("db:4412") });
```

Both calls land in one trail, told apart by `agent`:

```text
{"agent":"statements-api","principal":"User::\"db:4412\"","intent":"invoice","decision":"Allow", …}
{"agent":"billing-agent","principal":"User::\"db:4412\"","intent":"invoice","decision":"Allow", …}
```

That single readable stream is the point of naming rather than constructing. Two
separate governors share none of it.

## Three places it goes

### A request handler

The handler imports the governor and takes the subject from the session the
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

200 for the owner; 403 and the uniform reason for the other signed-in user, in
both lanes.

Both refusals in that block are the security contract of a handler: the subject
is derived from what the application authenticated, and the 403 body is the
uniform `DENY_REASON`, so a caller probing the boundary learns nothing about
which rule stopped it. [Where subjects come
from →](identity-model.md#where-the-values-come-from)

### A background worker

A worker is a different process, so it constructs its own governor over the same
policy file. What crosses the boundary is the narrowed authority for one job, as
a scope token, plus the subject the enqueuing request authenticated.

Both processes must hold the **same** signing secret — add
`signing_secret=os.environ["WATCHLIGHT_SIGNING_SECRET"]` /
`signingSecret: process.env.WATCHLIGHT_SIGNING_SECRET` to the web process's
governor as well, spelled exactly as the worker below does it. → [The signing
secret](signing-secret.md)

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

Three things a worker must get right, and all three are in that block:

- **The worker's agent name matches the name the token was minted under**
  (`as_("reports-worker")` on the enqueuing side). A token presented to a
  governor under another name is refused.
- **The rebuilt scope still has to be checked before the job runs.** A scope
  bounds what a sub-agent may be handed; it is not consulted when a call is
  authorized, so a job asking for something outside it must be refused by the
  code, as the `allowed_tools` / `allowedTools` check does here.
- **The subject travels in the job record, not in anything the agent produced.**
  It is the value the enqueuing request authenticated, put there by your own web
  process, and the queue is inside your trust boundary.

### A test

A throwaway governor with a temporary audit directory: the test's own records
never mix into the `.watchlight/audit.jsonl` of whatever directory the suite
happens to run in.

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
                {"name": "the service acting alone may not", "action": "read_statement",
                 "resource": "account/acct-100", "expect": "Deny"},
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
      { name: "the service acting alone may not", action: "read_statement",
        resource: "account/acct-100", expect: "Deny" },
    ]);
    assert.equal(report.failed, 0, JSON.stringify(report.results));
  } finally {
    fs.rmSync(auditDir, { recursive: true, force: true });
  }
});
```

Test the *deployed* policy file, not a copy pasted into the test — a suite that
passes against a different policy set than the one production loads proves
nothing. The `Deny` fixtures matter as much as the `Allow`: a policy that has
been accidentally widened still passes every `Allow` case.

## Lifecycle

### The exported default governor

`from watchlight import govern` gives you a governor that is already
constructed. It is the right one for a single-process program with a single
policy set — a script, a CLI, a notebook, an example. Configure it before its
first governed call, which is the only way to give it a name, an audit
directory, a sink or a secret:

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

Anything with more than one policy set — or anything where you would rather be
explicit about what a module is governing — constructs its own, as at the top of
this page.

#### Configuring it twice

Once the default governor has written its first record, its destination is
fixed: records already written cannot be sent to a sink added afterwards, and a
trail split across two destinations reads like a data bug. But re-applying the
configuration that is *already in force* changes nothing, so it is accepted —
the defensive second call, from a second entry point into one process, is not an
exception path:

```python
configure_default(agent="report-cli", audit_sink=records.append)   # again, same options → no-op
configure_default(agent="other")                                   # RuntimeError: agent would change …
```

A conflict names the option that would change and what it would change from and
to. Secret values are compared in constant time and never appear in the message.
A callable or an object — `audit_sink`, `approval_store`, `counter_source` —
matches when it is the **same function on the same object**. `audit_sink=records.append`
or `audit_sink=my_store.insert` passed a second time is one sink, even though
Python builds a new bound-method object on every attribute access; the same
`store.insert` read twice in TypeScript is one function reference.

A callable **built** a second time is a different sink and is reported as a
conflict: a fresh `lambda` or arrow function, a new closure, and in TypeScript a
new `fn.bind(obj)` — `.bind` returns a new function on every call, so bind once
and pass the result around. Assuming a rebuilt callable equal to the first would
silently keep the first one and quietly discard the records you believed you had
just redirected, which is the failure the check exists to prevent. A class whose
`__eq__` raises, or answers with anything but `True`, is read as a conflict and
never allowed to break the configuration call.

To ask before calling, rather than wrapping the call:

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

`can_configure_default()` / `canConfigureDefault()` is `true` until the first
record is written and `false` afterwards; asking mutates nothing. `false` does
not mean every call fails — options identical to the ones in force are still
accepted.

#### Configuring it from the environment

Two variables configure the default governor's audit destination without
touching code, for the cases where the code is not yours to change — a test run,
a container, a CI job:

| Variable | Effect |
|---|---|
| `WATCHLIGHT_AUDIT_DIR` | the directory `audit.jsonl` is written into (default `.watchlight`) |
| `WATCHLIGHT_AUDIT_FILE` | `0` / `false` / `no` / `off` writes no local file at all; `1` / `true` / `yes` / `on` keeps it |

`WATCHLIGHT_AUDIT_FILE=0` is `audit_file=False` by another route, with the same
consequences: no `.watchlight` directory is created, `govern.counters(...)`
raises rather than counting zero, `watchlight dev` has nothing to tail, and with
no sink configured the SDK says once that records are being discarded. Redirect
with `WATCHLIGHT_AUDIT_DIR` instead when you want the trail kept, just not here.

```bash
WATCHLIGHT_AUDIT_FILE=0 pytest              # this run writes no trail into the working directory
WATCHLIGHT_AUDIT_DIR=.watchlight-test pytest  # …or keeps its own, next to the application's
```

That is the fix for a test suite sharing a working directory with a running
application. Policy tests (`govern.test()`, `watchlight policy test`) already
write nothing — they run the engine's decision core directly — but a test that
calls `authorize()`, or a governed tool, writes a record like any other governed
call, under the default agent name, into the same `audit.jsonl` the application
is appending to. Two views of "the same" trail then disagree, and the
discrepancy reads as a data bug rather than a configuration one. One variable
in the test process's environment ends it: no code change, no `try`/`except`, and
no dependence on whether the SDK was imported before or after the variable was
set — both are read lazily, at the default governor's first use.

**Precedence — option, then environment, then default.** An explicit
`configure_default(audit_dir=…)` beats `WATCHLIGHT_AUDIT_DIR`, which beats
`.watchlight`; the same order every other option in this SDK resolves in. A
governor you construct yourself (`Watchlight(audit_dir=…)`) already names its
own options at the call site, so neither variable touches it — the environment
layer exists for the one governor an application never constructs. A value the
SDK does not recognize in `WATCHLIGHT_AUDIT_FILE` is reported once and then
ignored: the conservative reading of an audit switch is "keep writing the
trail", so a typo can neither quietly turn a trail off nor take an application
down. `watchlight dev` reads `WATCHLIGHT_AUDIT_DIR` too, so the dashboard
follows the trail rather than having to be pointed at it twice.

**Why the default still writes a file.** It would be simpler to make the default
governor write nothing until it is configured, and that would make this class of
contamination impossible rather than solvable. It would also break the first
five minutes: `.watchlight/audit.jsonl` appearing with zero configuration *is*
the quickstart, and `watchlight dev` reads that file and nothing else. So the
default stays, and the opt-out is one variable away.

### Loading policies

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

- **Policies are only ever added.** There is no unload; `allow` with the same
  code twice gives you two policies.
- **`load` is idempotent per source.** Loading the same file twice loads it once,
  so priming a governor in a factory and loading the same file again in an
  initialiser cannot double the set. Two paths to one file are one source; give
  two files a shared `source_id` / `sourceId` to make them one too.
- **A file that does not exist is not remembered**, so it loads the first time it
  appears.
- **Editing a loaded file and calling `load` again changes nothing.** No error,
  no warning: the process carries on deciding with the policies it already
  holds. Restart it to pick up an edit. `force=True` / `{ force: true }` loads
  the file again, but since nothing is removed you then hold both the old copy
  and the new — construct a fresh governor when the old set has to be gone.

That last point is the one that costs people an afternoon. A policy change takes
effect on a restart, not on a re-`load`.

## See also

- [The identity model](identity-model.md) — the subject you pass, the actor a
  policy reads, and delegation
- [The signing secret](signing-secret.md) — the value both processes need before
  a token crosses between them
- [Glossary](glossary.md) — governor, policy set, scope, trail, and every other
  term
- [`examples/showcase/web-backend/`](../examples/showcase/web-backend/README.md)
  — the request-handler shape as a running FastAPI and Express app
- [`examples/showcase/identity/`](../examples/showcase/identity/README.md) — one
  governor, several named agents, in one audit stream
