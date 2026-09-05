# Pattern: ship the audit trail somewhere durable

**Problem.** Every decision, sanitization and attenuation is appended to a local
`.watchlight/audit.jsonl`. On an ephemeral host — a container, a serverless
function, a CI runner — that file is gone on the next deploy, and the
`decision_id` you stored next to your own record has nothing left to join to.
You want the same value-free records in a store you already run.

This one isn't a policy decision — it's **where the trail goes** — so it uses
the `auditSink` / `audit_sink` option, not a policy.

**Use it:**

```ts
import { Watchlight } from "@watchlight/sdk";

const govern = new Watchlight({
  agent: "billing-agent",
  auditSink: (record) => store(record),   // sync or async; the file stays on
});
```

```python
from watchlight import Watchlight

govern = Watchlight(agent="billing-agent", audit_sink=store)  # sync callable, or async in a running loop
```

**What the sink receives.** Its own copy of **exactly** the fields the
`audit.jsonl` line carries — a decision (`ts, agent, principal, intent, resource,
decision, decision_id?, approved?`), a `sanitization` (counts by PII type + mode)
or an `attenuation` (`node_id, parent_id, tools, depth, reason?`), including the
attenuations of every scope derived from the governor. Never argument values,
never text, never secrets. In TypeScript the copy is frozen; in both languages
the file is written **first**, so nothing the sink does can alter it.

**What the sink can't do: hurt a decision.** The sink is **fire-and-forget**. It
is called synchronously after the file append, a returned promise/awaitable is
never awaited inline (in Python it is scheduled on the running event loop), and a
throw or a rejection is caught, reported **once** on stderr (error *type* only —
never the record), and swallowed. `authorize` returns the same verdict, in the
same time, with the same file line, whether the sink works, hangs, or fails. It
also means delivery is *best-effort*: if you need every record acknowledged,
enqueue in the sink and drain with retries out of band.

## Three reference sinks

Reference shapes, not first-party integrations — adapt the client to your own
stack. Each keeps the sink body tiny (hand the record off) so a slow store never
sits in the sink call.

**A Postgres row** — one `jsonb` column keeps every record kind in one table and
lets you join on `decision_id`:

```sql
create table agent_audit (
  id          bigserial primary key,
  ts          timestamptz not null,
  agent       text        not null,
  event       text        not null,          -- 'decision' | 'sanitization' | 'attenuation'
  decision_id text,                           -- join key to your own records
  record      jsonb       not null
);
```

```ts
import { Pool } from "pg";
const pool = new Pool();  // reads PG* from the environment

const auditSink = (r: Record<string, unknown>) =>
  pool.query(
    "insert into agent_audit (ts, agent, event, decision_id, record) values ($1,$2,$3,$4,$5)",
    [r.ts, r.agent, r.event ?? "decision", r.decision_id ?? null, JSON.stringify(r)]
  );  // returns a promise — not awaited by the SDK; a failure is reported once
```

```python
import json, queue, threading, psycopg

q: "queue.Queue[dict]" = queue.Queue(maxsize=10_000)

def audit_sink(record: dict) -> None:          # sync: hand off, never block
    try:
        q.put_nowait(record)
    except queue.Full:
        pass                                    # best-effort by contract; the file has it

def _drain() -> None:
    with psycopg.connect() as conn:            # reads PG* from the environment
        while True:
            r = q.get()
            conn.execute(
                "insert into agent_audit (ts, agent, event, decision_id, record) values (%s,%s,%s,%s,%s)",
                (r["ts"], r["agent"], r.get("event", "decision"), r.get("decision_id"), json.dumps(r)),
            )
            conn.commit()

threading.Thread(target=_drain, daemon=True).start()
```

**An OTLP log record** — the trail becomes log records in whatever backend your
collector feeds, correlated by `decision_id` as an attribute:

```ts
import { logs, SeverityNumber } from "@opentelemetry/api-logs";
const logger = logs.getLogger("watchlight-audit");   // your SDK/exporter setup elsewhere

const auditSink = (r: Record<string, unknown>) =>
  logger.emit({
    severityNumber: SeverityNumber.INFO,
    body: `watchlight ${r.event ?? "decision"}`,
    attributes: Object.fromEntries(
      Object.entries(r).map(([k, v]) => [`watchlight.${k}`, typeof v === "object" ? JSON.stringify(v) : v])
    ) as Record<string, string | number | boolean>,
  });
```

```python
import json
from opentelemetry._logs import get_logger

logger = get_logger("watchlight-audit")             # your SDK/exporter setup elsewhere

def audit_sink(record: dict) -> None:
    logger.emit(
        body=f"watchlight {record.get('event', 'decision')}",
        attributes={f"watchlight.{k}": (json.dumps(v) if isinstance(v, (dict, list)) else v)
                    for k, v in record.items()},
    )
```

**A webhook** — POST each record to an endpoint you own. Batch in the sink
(records arrive one per decision) and let the endpoint be idempotent on
`(ts, agent, decision_id)`:

```ts
const url = process.env.AUDIT_WEBHOOK_URL!;
const auth = "Bearer " + process.env.AUDIT_WEBHOOK_TOKEN;  // from your secret store, never in code
let batch: Record<string, unknown>[] = [];
let timer: NodeJS.Timeout | undefined;

const flush = async () => {
  const body = JSON.stringify(batch); batch = []; timer = undefined;
  await fetch(url, { method: "POST", headers: { "content-type": "application/json", authorization: auth }, body });
};
const auditSink = (r: Record<string, unknown>) => {
  batch.push(r);
  timer ??= setTimeout(() => flush().catch(() => {}), 1000);   // the SDK never awaits this
};
```

```python
import asyncio, json, os, urllib.request

URL = os.environ["AUDIT_WEBHOOK_URL"]
AUTH = "Bearer " + os.environ["AUDIT_WEBHOOK_TOKEN"]        # from your secret store

async def audit_sink(record: dict) -> None:                  # async: scheduled on the running loop
    req = urllib.request.Request(URL, data=json.dumps(record).encode(), method="POST",
                                 headers={"content-type": "application/json", "authorization": AUTH})
    await asyncio.to_thread(urllib.request.urlopen, req, None, 5)
```

**Two rules that matter.**

- **Keep the sink body cheap.** It runs on the decision path (synchronously, once
  per record) even though its result is never awaited. Hand the record to a
  queue, a logger or a promise and return; do the slow work elsewhere.
- **Don't add fields, and don't decode them into values.** The record is
  value-free by contract — the same contract the production audit service
  enforces. A sink that enriches it with tool arguments, message text or user
  data re-creates exactly the exposure the trail is designed not to have.

## Reading the store back

The sink is write-only: nothing in the SDK reads it back by itself. Two options
turn the same store into an input, for the two places where the local file is
otherwise the only source:

- **`counterSource` / `counter_source`** — the read side of this sink.
  `govern.counters(...)` then folds your store instead of the local file, so a
  quota spans every replica and survives a deploy. See the
  [quotas pattern](./quotas.md).
- **`approvalStore` / `approval_store`** — where consumed approval-token ids are
  recorded, so an approval is single-use across replicas rather than once per
  replica. See [destructive actions](./destructive-actions.md).

Both are separate from the sink deliberately: the sink is fire-and-forget and
must never affect a decision, while these two are read *on* the decision path and
so must fail closed — a source that cannot answer refuses the read, and a store
that cannot answer refuses the approval.

**Verify.** This pattern is a delivery contract, not a policy verdict, so it has
no `.suite.json`; `check.sh` runs [`scripts/audit-sink.mjs`](./scripts/audit-sink.mjs)
instead. It asserts that a decision, a sanitization and an attenuation each
reach the sink with exactly the fields of their `audit.jsonl` line (frozen,
value-free, joined on `decision_id`), and that a throwing sink changes neither
the verdicts nor the file and is reported once, by error type only.

In the Developer Edition the sink is your own store. Enterprise replaces it with a
signed, tamper-evident audit service — every record KMS-signed and joined into a
fleet-wide execution graph — with no sink code at all.
