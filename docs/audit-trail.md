# The audit trail

Every decision is appended to `.watchlight/audit.jsonl` as one JSON line — the
verdict, who it was for, what was asked. It never records the argument values.
That holds for a decision made through a framework plugin
(`watchlight.<framework>.governed_plugin`) as well as for one made through the
governor: both write the same record, through the same code.

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

Every record is also handed to your function, with the same fields the file
line carries. That covers every kind of record: decisions, sanitizations,
screenings, egress dispositions and attenuations. The file stays on as well.
A sink can never block or change a decision: an error it raises never reaches
your code, and the failure is reported once. (A sink still runs inside the
decision, so it adds its own time to each call; the next section shows how to
move it off that path.)

Each record says what kind it is in its `event` field. A decision record has
`"event": "decision"`, and every other record carries the name of its kind. A
decision written by an earlier release has no `event` field at all, so treat a
missing `event` as a decision. For typed code, TypeScript exports the union type
`AuditRecord`, and Python exports `TypedDict`s with the same names. A sink that
only forwards records can stay untyped.

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
are dropped, the drop is reported once, and `trail.dropped` counts them. Watch
that counter: any value above zero means records are missing from the trail, and
there is no way to recover which ones.

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

Do this before the first governed call. After that call, passing the same
options again does nothing, and passing a different value for any option raises
an error that names the option. `can_configure_default()` tells you whether
configuring is still possible, without changing anything.

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

`counters` counts the matching decisions in the trail, using each record's
timestamp to decide whether it falls inside the window, and returns a number a
policy can compare against. It reads the local file as a stream and scans at
most 64 MiB of it.

That file belongs to one container and does not survive a deploy. The
`counter_source` option (`counterSource` in TypeScript) answers the same query
from the durable store your sink writes to, so the quota covers every replica:

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
on them, so read them with `query.get("intent")`. The Python and TypeScript SDKs
pass the same keys and the same JSON, so one counting service can serve a Python
caller and a Node caller without handling two different shapes.

**It must count decision rows only.** The trail also carries `sanitization`,
`screening`, `egress` and `attenuation` records, so a query filtered on principal
and window alone over-counts and the quota denies early. When a counter source
is configured, counting never falls back to the local file.

Reading a durable store is a network call, so use `counters_async(...)` in
Python or `countersAsync(...)` in TypeScript, and call it from an async context
binding (an `async` function passed as `context`):

```python
async def quota(o):
    c = await govern.counters_async(principal=user(o), intent="read", window="1h")
    return {} if c["truncated"] else {"reads_this_hour": c["count"]}

@govern.tool("read", principal=user, context=quota)
async def fetch_document(o): ...
```

The full counting rules are in
[`examples/patterns/quotas.md`](../examples/patterns/quotas.md).

## Decisions made by a framework plugin

A framework plugin built with `governed_plugin()` writes one decision record for
every `handle.authorize_action` call. The record has the same fields as one
written by `authorize()`, plus `execution_id`, the id of the run it was made in.
The plugin also writes `execution_started` and `execution_completed` lines when
a run begins and ends. Those lines name their kind in `event_type`, not
`event`, and they have no `decision` field.

`governed_plugin()` takes `audit_sink`, `audit_sink_batch` and
`audit_sink_interval`, and they mean exactly what they mean on `Watchlight`.
The sink receives the decision records. The lifecycle lines and the sub-agent
`attenuation` lines are written to the file only.

Writing a record works the same way on both paths. The file is written first,
then the sink is called. Neither can raise into your code, and neither can
change or delay a decision: if the file cannot be written, the decision still
stands, and a sink failure is reported once. The decision itself fails closed
on both paths. A request the engine cannot evaluate is recorded as a `Deny`
and then raised.

The TypeScript adapters, `governTool()` and `governedHooks()`, decide through
the governor's own `authorize`, so they have always written one decision
record per decision. They write no run lifecycle lines.

## Show a scope without recording it

`scope()` and `attenuate()` grant authority, and every grant is recorded. To show
what an agent or a sub-agent would hold — on an admin page, say — preview it
instead. A preview runs the same engine check and records nothing:

```python
preview = govern.preview_scope(tools=["read_document", "get_results"])
reader = preview.preview_attenuate(tools=["read_document"], agent="document-reader")
reader.allowed, reader.allowed_tools      # (True, ['read_document'])
```

```ts
const preview = await govern.previewScope({ tools: ["read_document", "get_results"] });
const reader = preview.previewAttenuate({ tools: ["read_document"], agent: "document-reader" });
```

A preview is data, not a scope: it cannot authorize, delegate or mint a token.
When a scope would be refused, `allowed` is false and `violations` and `reason`
say why. `scope.preview_attenuate(...)` in Python, or `scope.previewAttenuate(...)`
in TypeScript, previews a child of a live scope the same way.

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
- A file shared with a framework plugin also holds its run lifecycle lines,
  which have no `event` field. A query that reads a missing `event` as a
  decision should also require a `decision` field, for example in jq:
  `select((.event // "decision") == "decision" and .decision != null)`.
  `counters()` already does this.

## See also

- [Using the governor](using-the-governor.md) — where the governor is
  constructed, and the lifecycle of the default one.
- [`examples/showcase/audit-forensics/`](../examples/showcase/audit-forensics/README.md)
  — every record kind's fields, and the queries that join them.
- [`examples/patterns/audit-sink.md`](../examples/patterns/audit-sink.md) ·
  [`examples/patterns/quotas.md`](../examples/patterns/quotas.md)
