# The audit trail

Every decision is appended to `.watchlight/audit.jsonl` as one JSON line — the
verdict, who it was for, what was asked. It never records the argument values.

## Watch decisions land

```bash
watchlight dev            # → http://127.0.0.1:7000
```

That command tails the audit file and streams every ALLOW and DENY as it
happens. Run your agent in another terminal. It shows this machine only.

## Send records to your own store

```python
govern = Watchlight(agent="my-agent", audit_sink=lambda record: my_store.insert(record))
```

Every record is also handed to your function — decisions, sanitizations,
screenings, egress dispositions, attenuations — with the same fields the file
line carries. The file stays on. The sink is fire-and-forget: it can never block
or change a decision, and a failure is reported once.

Records are typed and discriminated by `event`, which is absent on a decision
and a literal on every other kind. TypeScript exports the union
`AuditRecord`; Python exports `TypedDict`s of the same names. A sink that only
forwards records can stay untyped.

Set `audit_file=False` and the sink becomes the sole destination: no
`.watchlight` directory, no file. Then `watchlight dev` has nothing to tail, and
`govern.counters(...)` raises rather than counting zero.

### Keep the sink off the request path

The sink is called inside the decision, before your tool body returns. Anything
durable — a database, an object store, a log service — is too slow to sit there.
Configure batching and a background worker hands your sink a **list** instead:

```python
Watchlight(
    agent="my-agent",
    audit_sink=insert_many,          # receives a list, not a record
    audit_sink_batch=100,            # …of up to this many
    audit_sink_interval=2.0,         # …or sooner, every 2s
)
```

```ts
new Watchlight({ auditSink: insertMany, auditSinkBatch: 100, auditSinkInterval: 2000 });
```

Setting either option turns batching on and changes what your sink receives, so
a sink written for one record has to be adapted. In exchange the decision no
longer waits for it: 50 decisions against a 50ms sink cost 3ms rather than 2.5
seconds.

The queue is **bounded**. A destination that stops responding must not become
unbounded memory growth in the application it is auditing, so the oldest records
are dropped, the drop is reported once, and `trail.dropped` counts them. Non-zero
means the trail has holes and where they are is not recoverable — watch it.

Queued records are flushed when the process exits normally. Call `flush()`
before a deliberate shutdown if you want to wait for them.

Reference sinks — Postgres, OTLP, a webhook — are in
[`examples/patterns/audit-sink.md`](../examples/patterns/audit-sink.md). The
field table for each record kind is in
[`examples/showcase/audit-forensics`](../examples/showcase/audit-forensics/README.md).

## Configure the default governor

```python
from watchlight import govern, configure_default

configure_default(agent="billing-agent", audit_sink=my_store.insert)
```

Do this before the first governed call. After that, re-applying the same options
is a no-op; changing one raises and names it. `can_configure_default()` asks the
question and mutates nothing.

Three environment variables do the same job where the code is not yours to
change — a test run, a container, a CI job:

| Variable | Effect |
|---|---|
| `WATCHLIGHT_AUDIT_DIR` | directory `audit.jsonl` is written into (default `.watchlight`) |
| `WATCHLIGHT_AUDIT_FILE` | `0` / `false` / `no` / `off` writes no local file at all — which also turns quota counting off, unless a `counter_source` is configured |
| `WATCHLIGHT_AGENT` | the agent name, when the `agent` option does not give one |

All three apply to the default governor and to one you construct, for any option
you did not pass yourself.

```bash
WATCHLIGHT_AUDIT_FILE=0 pytest    # this run adds nothing to the app's audit.jsonl
```

Precedence is option, then environment, then default. `watchlight dev` reads
`WATCHLIGHT_AUDIT_DIR` too.

## Count past decisions for a quota

```python
c = govern.counters(principal='User::"u1"', intent="read", window="1h")
govern.authorize(action="read", principal='User::"u1"', context={"reads_this_hour": c["count"]})
```

`counters` folds the trail into a number a policy can compare against, from the
record timestamps. It streams the local file, bounded at 64 MiB.

That file is per-container and does not survive a deploy. `counter_source` /
`counterSource` answers the same query from the durable store your sink writes
to, so the quota spans every replica:

```python
govern = Watchlight(
    agent="my-agent",
    audit_sink=lambda record: my_store.insert(record),
    counter_source=lambda query: my_store.count_decisions(query),
)
```

Your source is handed the resolved query and must return a non-negative integer:

```python
{
    "principal": 'User::"u1"',
    "outcome":   "allowed",                       # or "denied" / "all"
    "window":    {"start": "2026-09-06T23:37:11.525Z",
                  "end":   "2026-09-07T00:37:11.525Z",
                  "seconds": 3600},
    "intent":    "read",                          # omitted entirely when not filtered on
}
```

`intent` and `resource` are **absent** rather than `None` when you did not filter
on them, so read them with `query.get("intent")`. Both lanes pass the same keys
and the same JSON, so one counting service can serve a Python and a Node caller
without recognising two shapes.

**It must count decision rows only.** The trail also carries `sanitization`,
`screening`, `egress` and `attenuation` records, so a query filtered on principal
and window alone over-counts and the quota denies early. It never falls back to
the local file.

A durable store is a network call, so read it with `counters_async(...)` /
`countersAsync(...)` from an async context binding:

```python
async def quota(o):
    c = await govern.counters_async(principal=user(o), intent="read", window="1h")
    return {} if c["truncated"] else {"reads_this_hour": c["count"]}

@govern.tool("read", principal=user, context=quota)
async def fetch_document(o): ...
```

The full counting rules are in
[`examples/patterns/quotas.md`](../examples/patterns/quotas.md).

## Worth knowing

- The audit file is shared. Every governor pointed at the same directory appends
  to the same `audit.jsonl`, so records interleave and are told apart by their
  fields.
- With neither a file nor a sink, the SDK says so once rather than discarding
  records silently.
- An async context binding needs an `async def` body. A synchronous tool cannot
  await one and raises `TypeError`.
- `authorize` takes a context you have already resolved. Handing it an
  unresolved awaitable raises `UnresolvedContextError` and records no decision.
- Malformed lines in the file are skipped and counted, never echoed.

## See also

- [Using the governor](using-the-governor.md) — where the governor is
  constructed, and the lifecycle of the default one.
- [`examples/showcase/audit-forensics/`](../examples/showcase/audit-forensics/README.md)
  — every record kind's fields, and the queries that join them.
- [`examples/patterns/audit-sink.md`](../examples/patterns/audit-sink.md) ·
  [`examples/patterns/quotas.md`](../examples/patterns/quotas.md)
