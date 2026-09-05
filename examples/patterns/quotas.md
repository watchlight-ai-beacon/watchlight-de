# Pattern: quotas — reads per hour, writes per day

**Problem.** An agent may read documents on a user's behalf, but not *unboundedly*:
100 reads per user per hour, 20 writes per day. Cedar is stateless and `context`
is whatever the application supplies, so the policy needs a **number** — and the
number has to come from somewhere the agent can't argue with.

The Developer Edition already writes every decision, value-free, to
`.watchlight/audit.jsonl`. `govern.counters(...)` folds that trail into exactly the
number the policy needs, right before the decision it feeds.

**Policy** — [`suites/quotas.suite.json`](./suites/quotas.suite.json):

```cedar
// reads are fine while the caller is under the hourly quota
permit(principal, action == Action::"read", resource)
when { context.reads_this_hour < 100 };

// a hard ceiling that no other permit can outvote
forbid(principal, action == Action::"read", resource)
when { context.reads_this_hour >= 100 };

// writes: a daily quota
permit(principal, action == Action::"write", resource)
when { context.writes_today < 20 };
```

**Govern the tool** — compute the counter in the `context` binding, so every call
sees the trail as it stands at that moment:

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
    // A truncated scan is a lower bound. Omit the counter rather than throwing:
    // the policy then denies ("missing counter denies") and the denial is AUDITED.
    return c.truncated ? {} : { reads_this_hour: c.count };
  },
});
```

```python
from watchlight import govern
govern.load("quotas.policy.json")

def user(o): return f'User::"{o["userId"]}"'

def quota(o):
    c = govern.counters(principal=user(o), intent="read", window="1h")
    # A truncated scan is a lower bound. Omit the counter rather than raising:
    # the policy then denies ("missing counter denies") and the denial is AUDITED.
    return {} if c["truncated"] else {"reads_this_hour": c["count"]}

@govern.tool("read", principal=user, resource=lambda o: f'doc/{o["docId"]}', context=quota)
def fetch_document(o): ...
```

Why not throw? The `context` binding runs *before* `authorize`, so an exception
there stops the call without writing a decision record — the refusal would be
invisible in the trail. Handing the engine a context without the counter makes
the policy's own condition fail to evaluate, which the engine treats as **Deny**,
and that Deny is written to `audit.jsonl` like any other.

**Verdicts** (from the suite, verified against the engine):

| `reads_this_hour` | verdict |
|---|---|
| 0 | **Allow** |
| 99 | **Allow** (the 100th read) |
| 100 | **Deny** (the 101st) |
| 250 | **Deny** |
| *absent* | **Deny** — a condition that cannot evaluate is fail-closed |

| `writes_today` | verdict |
|---|---|
| 19 | **Allow** |
| 20 | **Deny** |

## What the counter counts

`govern.counters({ principal, intent?, resource?, window, outcome? })` (Python:
`govern.counters(principal=..., intent=None, resource=None, window="1h",
outcome="allowed")`) returns `{ count, window: { seconds, start, end }, records,
skipped, truncated }` plus the filter it applied. The semantics are identical in
both languages:

- **Only decision records count** — the lines with a `decision` and no `event`.
  `sanitization`, `egress` and `attenuation` records are read past, never counted.
- **`outcome`** — `allowed` (default): `decision == "Allow"`, including approved
  ones; `denied`: every decision that did *not* let the body run (`Deny` and
  `NeedsApproval` holds); `all`: both. `allowed + denied == all`.
- **Matching is exact string equality** on `principal` (required — write it as it
  appears on the record, e.g. `User::"u1"`), and on `intent` and `resource` when
  given. No prefixes, no globs. A record without a `principal` matches no one.
- **The window is `(now − window, now]`** — start exclusive, end inclusive — on the
  record's own `ts`, never on file order. `window` is `"15m"`, `"1h"`, `"24h"`,
  `"7d"`, a bare number of seconds, or an integer of seconds — positive and at
  most 366 days; anything else is rejected. `now` defaults to the current time
  and can be pinned to an ISO-8601 string with a zone, an aware `datetime`
  (Python) or a `Date` / epoch milliseconds (TypeScript). Records timestamped
  after `now` do not count. Clocks across the processes that wrote the trail are
  the caller's concern.
- **The count is of decisions *before* this one.** The first call sees `0`, so
  `< 100` admits exactly 100 reads and denies the 101st.

## Which source is in play

`counters()` reads **one** of two sources, and the result says which:

| `source` | where the number comes from | what it bounds |
|---|---|---|
| `"local"` (default) | this container's `.watchlight/audit.jsonl` | decisions **this process** has written since the file was last rotated or lost |
| `"external"` | a `counterSource` / `counter_source` you configure | whatever your store holds — every replica, across deploys |

With no source configured nothing changes: the local file is folded exactly as
described above, and `records` / `skipped` / `truncated` describe that scan.

**Counting the durable store — `counterSource` / `counter_source`.** It is the
read side of the [`auditSink`](./audit-sink.md): the sink writes the records, the
source answers the same question over them.

```ts
import { Watchlight } from "@watchlight/sdk";

const govern = new Watchlight({
  auditSink: (record) => db.insert("agent_audit", record),
  counterSource: (q) =>
    db.countDecisions({                       // your query, your index
      // ONLY decision rows: the trail also carries `sanitization`, `screening`,
      // `egress` and `attenuation` records, and several of those now carry a
      // `principal` too — a filter on principal + window alone would count them
      // and deny early.
      eventIsNull: true,                      // i.e. WHERE record->>'event' IS NULL
      principal: q.principal,
      intent: q.intent,                       // absent when the caller didn't filter
      resource: q.resource,                   // absent when the caller didn't filter
      outcome: q.outcome,                     // "allowed" | "denied" | "all"
      after: q.window.start,                  // exclusive
      until: q.window.end,                    // inclusive
    }),
});
```

```python
from watchlight import Watchlight

govern = Watchlight(
    audit_sink=lambda record: db.insert("agent_audit", record),
    counter_source=lambda q: db.count_decisions(
        event_is_null=True,                   # decision rows only — see the note above
        principal=q["principal"], intent=q.get("intent"), resource=q.get("resource"),
        outcome=q["outcome"], after=q["window"]["start"], until=q["window"]["end"],
    ),
)
```

In SQL over the `jsonb` column of the [audit-sink pattern](./audit-sink.md):

```sql
select count(*) from agent_audit
where record->>'event' is null            -- decisions only, never sanitization/screening/egress
  and record->>'principal' = $1
  and record->>'decision'  = 'Allow'      -- outcome = "allowed"
  and ts > $2 and ts <= $3;               -- start exclusive, end inclusive
```

The source is handed the **validated, resolved** query — the same filters the
local scan would apply, with `window.start` exclusive and `window.end` inclusive,
both ISO-8601 UTC — and must return a **non-negative integer** (at most 2^53 − 1,
the same bound in both languages). `intent` and `resource` are **omitted** when
the caller did not filter on them, in both lanes, so one shared counting service
sees one shape; read them with `q.intent` / `q.get("intent")`.

It must apply the same *what counts* rules as the local scan, above — above all,
**decision records only**. The trail also carries `sanitization`, `screening`,
`egress` and `attenuation` records, and a `sanitization` / `screening` record can
carry a `principal` of its own, so a query filtered on principal and window alone
counts them too and denies early. On an external
result, `records` and `skipped` describe the local scan that did not happen and
are `0`; `truncated` is `false` (your store's bound is yours to enforce).

**Fail-closed.** A source that raises, or returns anything that is not a count,
raises `CounterSourceError` — it never falls back to the local file, because a
silently local count is a quota that under-counts without saying so. Handle it in
the `context` binding the same way as `truncated`: omit the counter so the policy
denies, and the denial is audited.

```ts
context: (o) => {
  try {
    const c = govern.counters({ principal: user(o), intent: "read", window: "1h" });
    return c.truncated ? {} : { reads_this_hour: c.count };
  } catch {
    return {};   // no counter → the condition can't evaluate → Deny, audited
  }
},
```

**An async source** is read with `await govern.countersAsync(...)` /
`await govern.counters_async(...)`, *before* the call whose `context` it feeds — a
`context` binding is synchronous. Calling the synchronous `counters()` while an
async source is configured raises and names the async method rather than quietly
answering from the local file.

## Durability and the bound

**Without a source, the local file is the source of truth.** An
[`auditSink`](./audit-sink.md) can mirror every record to a store you run, but
counters then read *only* the local file — the sink is never read back. On an
ephemeral host the count restarts with the file; if a quota must survive a
redeploy, configure a `counterSource` over your store (above), keep the file on a
persistent volume, or compute the counter yourself and place it in `context`.

**The read is bounded and streamed.** The file is read in 64 KiB chunks, never
loaded whole, and at most `maxBytes` / `max_bytes` (default 64 MiB) are scanned —
taken from the **end** of the file, where the recent records are. When the file
is larger, `truncated` is `true` and `count` is a *lower bound*. The examples
above fail closed on that flag; alternatively raise the bound, or rotate the file.
A single line longer than 1 MiB, or nested deeper than 32 levels, is skipped
without being buffered or parsed, so one oversized line costs at most the cap.

**Fail-closed and value-free.** A line that is not a well-formed decision record
is skipped and counted in `skipped` — nothing about it is echoed or logged. A
missing file yields zero counts (a fresh agent has done nothing yet); a file that
exists but cannot be read raises `AuditTrailUnreadable` (the path is on the
error object, not in its message).

## Operational cost

Every `counters()` call **rescans the tail of the file** — up to `maxBytes` — and
there is no index or cache. On a small trail that is sub-millisecond; on a trail
that has grown to the bound it is a per-decision cost you will notice (on the
order of a few hundred milliseconds for tens of MiB, depending on the language
and disk). Keep it cheap:

- **Rotate the audit file.** Move `.watchlight/audit.jsonl` aside on a schedule
  longer than your widest window (daily for `"24h"` quotas); the governor
  recreates it on the next write. Counters only ever need the current window.
- **Or lower `maxBytes` / `max_bytes`** to a size that comfortably holds one
  window of records, and treat `truncated` as "over quota" (above).
- **Widest window first.** One call with `window: "24h"` and `outcome: "all"` is
  not cheaper than one with `"15m"` — the scan is bounded by bytes, not time.
- **Durable counting belongs in your store.** The [audit sink](./audit-sink.md)
  mirrors every record into a database you run; a quota that must survive a
  redeploy or span several hosts is a `count(*)` there — reached through a
  `counterSource` (above) or placed in `context` by you. The local scan is the
  zero-infrastructure version of that query, and its cost is the tail rescan.

## Trust boundary

With a `counterSource` the trust boundary moves to your store, and these points
apply to it in whatever form they take there. Reading the local file,
`counters()` is only as trustworthy as that file:

- **Whoever can write the audit file can reset their own quota** — truncate it,
  or append fabricated `Allow`/`Deny` lines. Do not let the governed agent (or the
  end-user's code) write to `.watchlight/`; when the agent runs in the same
  process as the governor, the file is a *convenience*, not a control, and the
  durable count belongs in a store the agent cannot reach (via the sink).
- **Concurrent writers make the count approximate.** Several governors appending
  to one file interleave records and read partially-written tails; a call may
  miss a record written a moment earlier by another process. Treat the count as
  best-effort under concurrency, and rely on the policy's `<` / `>=` margin rather
  than exactness.
- **Clocks.** The window is on each record's own `ts`, written by the process that
  made the decision. Skewed clocks move records into or out of the window.

See also: [Audit sink](./audit-sink.md) ·
[Per-user attribution](./per-user-attribution.md) ·
[Field reference](https://docs.watchlight.ai/de/reference#counters).
