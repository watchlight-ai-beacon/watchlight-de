# Pattern: quotas — reads per hour, writes per day

Cedar is stateless, so a quota policy needs a **number** in `context`.
`govern.counters(...)` folds the audit trail into that number, right before the
decision it feeds.

```cedar
// reads are fine while the caller is under the hourly quota
permit(principal, action == Action::"read", resource)
when { context.reads_this_hour < 100 };

// a hard ceiling no other permit can outvote
forbid(principal, action == Action::"read", resource)
when { context.reads_this_hour >= 100 };

// writes: a daily quota
permit(principal, action == Action::"write", resource)
when { context.writes_today < 20 };
```

## Govern the tool

Compute the counter in the `context` binding, so every call sees the trail as it
stands at that moment.

```ts
import { govern } from "@watchlight/sdk";
govern.load("quotas.policy.json");

const user = (o) => `User::"${o.userId}"`;

const readDoc = govern.tool(fetchDocument, {
  intent: "read",
  principal: user,
  resource: (o) => `doc/${o.docId}`,
  context: (o) => {
    const c = govern.counters({ principal: user(o), intent: "read", window: "1h" });
    return c.truncated ? {} : { reads_this_hour: c.count };   // truncated = a lower bound
  },
});
```

```python
from watchlight import govern
govern.load("quotas.policy.json")

def user(o): return f'User::"{o["userId"]}"'

def quota(o):
    c = govern.counters(principal=user(o), intent="read", window="1h")
    return {} if c["truncated"] else {"reads_this_hour": c["count"]}

@govern.tool("read", principal=user, resource=lambda o: f'doc/{o["docId"]}', context=quota)
def fetch_document(o): ...
```

**Omit the counter rather than throwing.** The binding runs before `authorize`,
so an exception there stops the call without writing a decision record and the
refusal is invisible. A context without the counter makes the condition
unevaluable, which the engine treats as `Deny` — and that `Deny` is audited.

## Verdicts

Proved by [`suites/quotas.suite.json`](./suites/quotas.suite.json).

| `reads_this_hour` | verdict |
|---|---|
| 0 | **Allow** |
| 99 | **Allow** — the 100th read |
| 100 | **Deny** — the 101st |
| *absent* | **Deny** — a condition that cannot evaluate is fail-closed |

| `writes_today` | verdict |
|---|---|
| 19 | **Allow** |
| 20 | **Deny** |

## What the counter counts

`govern.counters({ principal, intent?, resource?, window, outcome? })` returns
`{ count, window: { seconds, start, end }, records, skipped, truncated }` plus the
filter it applied. Both lanes behave identically.

- **Only decision records** — a line with a `decision` and no `event`.
  `sanitization`, `screening`, `egress` and `attenuation` are read past.
- **`outcome`** — `allowed` (default) is `Allow`, including approved ones;
  `denied` is `Deny` plus `NeedsApproval` holds; `all` is both.
- **Exact string matching** on `principal` (required — write it as it appears on
  the record, `User::"u1"`), and on `intent` and `resource` when given. No
  prefixes, no globs.
- **The window is `(now − window, now]`** on each record's own `ts`, never file
  order. `window` takes `"15m"`, `"1h"`, `"24h"`, `"7d"` or seconds, up to 366
  days. `now` defaults to the current time and can be pinned.
- **The count excludes this decision.** The first call sees `0`, so `< 100`
  admits exactly 100 reads and denies the 101st.

## Count a durable store instead

The local file is per-container. `counterSource` / `counter_source` answers the
same query from the store your [audit sink](./audit-sink.md) writes to, so the
quota spans every replica and survives a deploy.

A store is a network call, so the source returns a promise and the `context`
binding awaits `countersAsync` / `counters_async`. A synchronous source and a
synchronous binding work the same way.

```ts
import { Watchlight } from "@watchlight/sdk";

const govern = new Watchlight({
  agent: "doc-agent",
  auditSink: (record) => db.insert("agent_audit", record),
  counterSource: (q) => db.countDecisions({
    eventIsNull: true,       // decision rows ONLY — see the warning below
    principal: q.principal,
    intent: q.intent,        // absent when the caller didn't filter
    resource: q.resource,    // absent when the caller didn't filter
    outcome: q.outcome,      // "allowed" | "denied" | "all"
    after: q.window.start,   // exclusive
    until: q.window.end,     // inclusive
  }),
});

const readDoc = govern.tool(fetchDocument, {
  intent: "read",
  principal: user,
  resource: (o) => `doc/${o.docId}`,
  context: async (o) => {                        // awaited before the decision
    try {
      const c = await govern.countersAsync({ principal: user(o), intent: "read", window: "1h" });
      return c.truncated ? {} : { reads_this_hour: c.count };
    } catch {
      return {};   // no counter → the condition can't evaluate → Deny, audited
    }
  },
});
```

```python
from watchlight import CounterSourceError, Watchlight

govern = Watchlight(
    agent="doc-agent",
    audit_sink=lambda record: db.insert("agent_audit", record),
    counter_source=lambda q: db.count_decisions(
        event_is_null=True,                   # decision rows ONLY
        principal=q["principal"], intent=q.get("intent"), resource=q.get("resource"),
        outcome=q["outcome"], after=q["window"]["start"], until=q["window"]["end"],
    ),
)

async def quota(o):
    try:
        c = await govern.counters_async(principal=user(o), intent="read", window="1h")
        return {} if c["truncated"] else {"reads_this_hour": c["count"]}
    except CounterSourceError:
        return {}   # no counter → the condition can't evaluate → Deny, audited

# An async binding needs an async body: a sync tool has no moment in which to
# await it, and raises TypeError with nothing authorized.
@govern.tool("read", principal=user, resource=lambda o: f'doc/{o["docId"]}', context=quota)
async def fetch_document(o): ...
```

Over the `jsonb` column of the [audit-sink pattern](./audit-sink.md):

```sql
select count(*) from agent_audit
where record->>'event' is null            -- decisions only
  and record->>'principal' = $1
  and record->>'decision'  = 'Allow'      -- outcome = "allowed"
  and ts > $2 and ts <= $3;               -- start exclusive, end inclusive
```

**Count decision rows only.** The trail also carries `sanitization`, `screening`,
`egress` and `attenuation` records, and some of those carry a `principal` of
their own. A query filtered on principal and window alone counts them too, and
the quota denies early.

Your source is handed the validated, resolved query — the same filters the local
scan would apply. `intent` and `resource` are omitted when the caller did not
filter on them. It must return a non-negative integer. On an external result
`records` and `skipped` are `0` and `truncated` is `false`, because bounding your
own store is your job.

**Fail-closed.** A source that raises, or returns anything that is not a count,
raises `CounterSourceError`. It never falls back to the local file, because a
silently local count is a quota that under-counts without saying so.

### Which forms compose

| counter source | `context` binding | what happens |
|---|---|---|
| none — the local file | synchronous | the local count feeds the policy |
| none — the local file | async | the same count, awaited before the decision |
| synchronous source | either | the store's count feeds the policy |
| **async source** | **synchronous** | `CounterSourceError` naming `countersAsync` / `counters_async` |
| **async source** | **async** | the store's count feeds the policy, through `tool()` |

The binding is resolved once per call, before the decision — and before the
re-decision an approval triggers, so both see the same attributes.

## Reading the local file

- **Bounded and streamed.** 64 KiB chunks, at most `maxBytes` / `max_bytes`
  (default 64 MiB) taken from the **end** of the file. Past that, `truncated` is
  `true` and `count` is a lower bound. A line over 1 MiB, or nested deeper than
  32 levels, is skipped without being parsed.
- **Every call rescans the tail.** There is no index or cache. Rotate
  `.watchlight/audit.jsonl` on a schedule longer than your widest window, or
  lower `maxBytes` to a size that holds one window and treat `truncated` as over
  quota.
- **Value-free and fail-closed.** A malformed line is skipped and counted in
  `skipped`, never echoed. A missing file yields zeros; a file that exists but
  cannot be read raises `AuditTrailUnreadable`.

## Trust boundary

- **Whoever can write the audit file can reset their own quota** by truncating it
  or appending fabricated lines. Do not let the governed agent write to
  `.watchlight/`. When it runs in the same process as the governor, the file is a
  convenience, not a control — put the durable count in a store the agent cannot
  reach.
- **Concurrent writers make the count approximate.** Several governors appending
  to one file interleave, and a call may miss a record written a moment earlier.
  Rely on the policy's margin rather than exactness.
- **Clocks.** The window is on each record's own `ts`, written by the process
  that decided. Skew moves records into and out of the window.

With a `counterSource` the boundary moves to your store, and the same three
points apply there in whatever form they take.

## Verified by

The suite above, plus [`scripts/quotas.mjs`](./scripts/quotas.mjs), which runs an
async `counterSource` through `tool()` with the local file switched off. The
governed tool is allowed under the durable quota and denied at it, with the body
never entered. A synchronous binding over an async source fails closed.

See also [audit sink](./audit-sink.md) ·
[per-user attribution](./per-user-attribution.md).
