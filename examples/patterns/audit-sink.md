# Pattern: ship the audit trail somewhere durable

`.watchlight/audit.jsonl` is gone on the next deploy of a container or a
serverless function, and the `decision_id` you stored has nothing left to join
to. A sink puts the same value-free records in a store you already run.

```ts
import { Watchlight } from "@watchlight/sdk";

const govern = new Watchlight({
  agent: "billing-agent",
  auditSink: (record) => store(record),   // sync or async; the file stays on
});
```

```python
from watchlight import Watchlight

govern = Watchlight(agent="billing-agent", audit_sink=store)  # sync, or async in a running loop
```

## What the sink receives

Its own copy of exactly the fields the `audit.jsonl` line carries — never
argument values, never text, never secrets. In TypeScript the copy is frozen, and
in both lanes the file is written first, so nothing the sink does can alter it.

Five record kinds, discriminated by `event`: a **decision** (no `event` at all), a
**`sanitization`**, a **`screening`**, an **`egress`** and an **`attenuation`**.
A record from a `delegate()`d governor also carries `actor_chain`. The kinds are
types — a TypeScript discriminated union, Python `TypedDict`s of the same names —
so renaming a field breaks a sink at build time instead of producing a column of
nulls.

```ts
import { Watchlight, type AuditRecord } from "@watchlight/sdk";

const auditSink = (r: AuditRecord) => {
  switch (r.event) {
    case undefined:      return store.decision(r.principal, r.decision, r.decision_id);
    case "sanitization": return store.redaction(r.counts, r.total);
    case "screening":    return store.screening(r.counts, r.flagged);
    case "egress":       return store.egress(r.replaced, r.withheld === true);
    case "attenuation":  return store.scopeNode(r.node_id, r.parent_id, r.tools);
  }
};
```

```python
from watchlight import AuditRecord

def audit_sink(record: AuditRecord) -> None:
    kind = record.get("event")                 # absent -> a decision
    if kind is None:
        store.decision(record["principal"], record["decision"], record.get("decision_id"))
    elif kind == "sanitization":
        store.redaction(record["counts"], record["total"])
    elif kind == "screening":
        store.screening(record["counts"], record["flagged"])
    elif kind == "egress":
        store.egress(record["replaced"], record.get("withheld", False))
    elif kind == "attenuation":
        store.scope_node(record["node_id"], record.get("parent_id"), record["tools"])
```

A sink that forwards records whole can stay untyped — `UnknownAuditRecord` in
TypeScript, `dict` in Python. The field table for each kind is in
[`examples/showcase/audit-forensics`](../showcase/audit-forensics/README.md).

## The sink cannot hurt a decision

It is fire-and-forget. A returned promise or awaitable is never awaited inline,
and a throw is caught, reported once on stderr by error type only, and swallowed.
`authorize` returns the same verdict in the same time whether the sink works,
hangs or fails.

Delivery is therefore best-effort. If you need every record acknowledged, enqueue
in the sink and drain with retries out of band.

## Three reference sinks

Shapes to adapt, not first-party integrations. Each keeps the sink body tiny so a
slow store never sits on the decision path.

**A Postgres row.** One `jsonb` column holds every kind and lets you join on
`decision_id`:

```sql
create table agent_audit (
  id          bigserial primary key,
  ts          timestamptz not null,
  agent       text        not null,
  event       text        not null,   -- 'decision' | 'sanitization' | 'screening' | 'egress' | 'attenuation'
  decision_id text,                    -- join key to your own records
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
  );  // a promise the SDK never awaits; a failure is reported once
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

**An OTLP log record**, correlated by `decision_id` as an attribute:

```ts
import { logs, SeverityNumber } from "@opentelemetry/api-logs";
const logger = logs.getLogger("watchlight-audit");   // your exporter setup elsewhere

const auditSink = (r: Record<string, unknown>) =>
  logger.emit({
    severityNumber: SeverityNumber.INFO,
    body: `watchlight ${r.event ?? "decision"}`,
    attributes: Object.fromEntries(
      Object.entries(r).map(([k, v]) => [`watchlight.${k}`, typeof v === "object" ? JSON.stringify(v) : v])
    ) as Record<string, string | number | boolean>,
  });
```

In Python, `opentelemetry._logs.get_logger(...).emit(body=..., attributes=...)`
takes the same two arguments.

**A webhook.** Batch in the sink, and make the endpoint idempotent on
`(ts, agent, decision_id)`:

```ts
const url = process.env.AUDIT_WEBHOOK_URL!;
const auth = "Bearer " + process.env.AUDIT_WEBHOOK_TOKEN;  // from your secret store
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

async def audit_sink(record: dict) -> None:                  # scheduled on the running loop
    req = urllib.request.Request(URL, data=json.dumps(record).encode(), method="POST",
                                 headers={"content-type": "application/json", "authorization": AUTH})
    await asyncio.to_thread(urllib.request.urlopen, req, None, 5)
```

## Reading the store back

The sink is write-only. Two options turn the same store into an input, and both
are read *on* the decision path, so both fail closed.

**`counterSource` / `counter_source`** answers `govern.counters(...)` from your
store, so a quota spans replicas and survives a deploy. **Count decision rows
only** — the table also holds `sanitization`, `screening`, `egress` and
`attenuation` records, some carrying a `principal` of their own, so a filter on
principal and window alone over-counts and denies early.

```sql
select count(*) from agent_audit
where record->>'event' is null          -- decisions only
  and record->>'principal' = $1
  and record->>'decision'  = 'Allow'
  and ts > $2 and ts <= $3;             -- start exclusive, end inclusive
```

See [quotas](./quotas.md).

**`approvalStore` / `approval_store`** reserves consumed approval-token ids, so
an approval is single-use across replicas rather than once per replica. Its
`add(id, expiresAt)` must be an atomic check-and-set. See
[destructive actions](./destructive-actions.md#approvals-across-processes).

## Worth knowing

- **Keep the sink body cheap.** It runs on the decision path, once per record,
  even though its result is never awaited. Hand the record off and return.
- **Do not add fields, and do not decode them into values.** The record is
  value-free by contract; enriching it with arguments, message text or user data
  re-creates the exposure the trail exists to avoid.

## Verified by

[`scripts/audit-sink.mjs`](./scripts/audit-sink.mjs) — this is a delivery
contract, not a policy verdict, so there is no suite. It asserts that all five
kinds reach the sink with exactly the fields of their `audit.jsonl` line, frozen
and value-free. A throwing sink changes neither the verdicts nor the file, and is
reported once by error type.
