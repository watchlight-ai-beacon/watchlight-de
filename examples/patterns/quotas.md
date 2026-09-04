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

## Durability and the bound

**The local file is the source of truth.** An
[`auditSink`](./audit-sink.md) can mirror every record to a store you run, but
counters read *only* the local file — the sink is never read back. On an
ephemeral host the count restarts with the file; if a quota must survive a
redeploy, keep the file on a persistent volume, or compute the counter from your
own store and place it in `context` yourself.

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
  redeploy or span several hosts is a `count(*)` there, placed in `context` by
  you. `counters()` is the zero-infrastructure version of that query.

## Trust boundary

`counters()` is only as trustworthy as the file it reads:

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
