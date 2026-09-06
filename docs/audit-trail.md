# The audit trail

Every decision the engine makes is appended to a **value-free** record — the
verdict, who it was for, what was asked, never the argument values. That trail
is three things at once: something to watch while you build, something to ship
to a store you already run, and an input a policy can count. This page is all
three.

## Watch every decision live — `watchlight dev`

A zero-dependency local dashboard that tails your value-free audit trail and
shows every governance decision as it happens — the ALLOWs, and the DENYs that
stopped a tool **before** it ran.

```bash
watchlight dev            # → http://127.0.0.1:7000
```

Run your governed agent in another terminal and watch the decisions stream in.
It shows only *this* process — fleet-wide lineage, signed audit, and
drift→quarantine are the governed control plane (Enterprise).

## Ship it somewhere durable — the audit sink

On an ephemeral host, keep the trail: pass an `audit_sink` and every record —
decisions, sanitizations, screenings, egress dispositions, attenuations — is also
handed to your code with exactly the fields the file line carries (the file stays
on). The sink is fire-and-forget and can never block or change a decision; a
failure is reported once.

```python
govern = Watchlight(agent="my-agent", audit_sink=lambda record: my_store.insert(record))
```

The five kinds are **typed**, discriminated by `event` — absent on a decision, a
literal on every other kind. TypeScript exports them as a union
(`AuditRecord = DecisionRecord | SanitizationRecord | ScreeningRecord |
EgressRecord | AttenuationRecord`, common fields on `AuditRecordBase`) and Python
as `TypedDict`s of the same names, so a sink that maps fields breaks at build
time when a kind changes shape rather than quietly writing `null`s. A sink that
just forwards records can stay untyped: annotate `UnknownAuditRecord` (or a plain
`dict`) and nothing changes. The field table, kind by kind, is in
[`examples/showcase/audit-forensics`](../examples/showcase/audit-forensics/README.md).

Reference sinks — a Postgres row, an OTLP log record, a webhook — are in
[`examples/patterns/audit-sink.md`](../examples/patterns/audit-sink.md).

`audit_file=False` makes the sink the **sole** destination: no `.watchlight`
directory, no file, and `govern.counters(...)` — which reads the local file —
raises rather than counting zero. `watchlight dev` tails that same file, so it
has nothing to show once the file is off; read your sink's store instead. With neither a file nor a sink the SDK says so
once instead of discarding records silently. Note that the file is shared: every
governor pointed at the same directory, including concurrent instances in one
process and a test run in the same working directory, appends to the same
`audit.jsonl`, so those records interleave and are told apart only by their
fields.

## Configuring the default governor

The module-level `govern` is pre-constructed, so configure it before its first
governed call — otherwise it has no sink, and it says so the first time it
writes:

```python
from watchlight import govern, configure_default

configure_default(agent="billing-agent", audit_sink=my_store.insert)
```

Once it has written a record its destination is fixed: records already written
cannot reach a sink added later, and a trail split across two destinations reads
like a data bug. Re-applying the configuration *already in force* is a no-op, so
the defensive second call is not an exception path; a call that would CHANGE an
option raises and names which one. A sink matches when it is the same function
on the same object, so passing `audit_sink=my_store.insert` twice is one sink —
but a `lambda` written out a second time is a different one, and conflicts.
`can_configure_default()` asks the question outright, and mutates nothing:

```python
from watchlight import can_configure_default, configure_default

if can_configure_default():
    configure_default(audit_sink=my_store.insert)
```

Three environment variables configure the default governor where the code
is not yours to change — a test run, a container, a CI job:

| Variable | Effect |
|---|---|
| `WATCHLIGHT_AUDIT_DIR` | the directory `audit.jsonl` is written into (default `.watchlight`) |
| `WATCHLIGHT_AUDIT_FILE` | `0` / `false` / `no` / `off` writes no local file at all |
| `WATCHLIGHT_AGENT` | the agent name, when the `agent` option does not give one; blank counts as unset |

```bash
WATCHLIGHT_AUDIT_FILE=0 pytest    # this run adds nothing to the application's audit.jsonl
```

Both are read lazily, at first use, so setting them before or after importing
`watchlight` works the same. Precedence is option, then environment, then
default: an explicit `configure_default(audit_dir=…)` wins, and a governor you
construct yourself already names its own options and is untouched. `watchlight
dev` reads `WATCHLIGHT_AUDIT_DIR` too, so the dashboard follows the trail. The
default governor deliberately still writes `.watchlight/audit.jsonl` with no
opt-in — that file appearing with zero configuration is the quickstart, and
`watchlight dev` reads it and nothing else. Full guide:
[`using-the-governor.md`](using-the-governor.md#the-exported-default-governor).

## Turn the trail into a number — `govern.counters`

The trail is also an input: `govern.counters(...)` folds it into a number for a
quota policy — decisions for exactly this principal (and intent / resource) in
the last `window`, from the record timestamps — so `context.reads_this_hour < 100`
has something to compare against. Streams the local file (bounded, 64 MiB by
default); malformed lines are skipped and counted, never echoed.

```python
c = govern.counters(principal='User::"u1"', intent="read", window="1h")   # {"count": 7, "window": {...}, ...}
govern.authorize(action="read", principal='User::"u1"', context={"reads_this_hour": c["count"]})
```

By default that count comes from the local file, which is per-container and does
not survive a deploy. `counter_source` / `counterSource` is the **read side** of
the sink: the same query, answered by the durable store the sink writes to, so
the quota spans every replica.

```python
govern = Watchlight(
    agent="my-agent",
    audit_sink=lambda record: my_store.insert(record),
    counter_source=lambda query: my_store.count_decisions(query),
)
c = govern.counters(principal='User::"u1"', intent="read", window="1h")   # c["source"] == "external"
```

The source is handed the validated, resolved query — `principal`, `outcome`, a
`window` whose `start` is exclusive and `end` inclusive, plus `intent` /
`resource` when the caller filtered on them — and must return a non-negative
integer. It has to count **decision rows only**, exactly as the local scan does:
the trail also carries `sanitization`, `screening`, `egress` and `attenuation`
records, so a query filtered on principal and window alone over-counts and the
quota denies early. Fail-closed: it never falls back to the local file, so a
quota can never quietly under-count.

An async source — a durable store is a network call — is read with
`counters_async(...)` / `countersAsync(...)`, and a `context` binding may itself
be async: it is awaited before the decision, so the durable count is what the
policy evaluates and the quota works through a governed tool.

```python
async def quota(o):
    c = await govern.counters_async(principal=user(o), intent="read", window="1h")
    return {} if c["truncated"] else {"reads_this_hour": c["count"]}

# An async binding needs an `async def` body: the decision is made before the
# body runs, so a synchronous tool cannot await one and raises `TypeError`.
@govern.tool("read", principal=user, context=quota)
async def fetch_document(o): ...
```

A synchronous binding reads the local file or a synchronous source; an async
source needs the async binding — calling the synchronous `counters()` on one
raises, naming `counters_async`, rather than answering from the file.

The async form is a property of the tool binding, not of `authorize`, which
takes a context you have already resolved. Handing `authorize` an unresolved
awaitable raises `UnresolvedContextError` before anything reaches the engine,
and records no decision — the attributes it was going to carry are not there
yet, and a policy evaluated without them denies for a reason that has nothing
to do with the caller.

The [quotas pattern](../examples/patterns/quotas.md) has the policy, the tool
binding, and the exact counting rules.


## See also

- [Using the governor](using-the-governor.md#the-exported-default-governor) —
  where the governor is constructed, and the full lifecycle of the default one.
- [`examples/showcase/audit-forensics/`](../examples/showcase/audit-forensics/README.md)
  — every record kind's exact field names, and the queries that join them.
- [`examples/patterns/audit-sink.md`](../examples/patterns/audit-sink.md) —
  reference sinks: a Postgres row, an OTLP log record, a webhook.
- [`examples/patterns/quotas.md`](../examples/patterns/quotas.md) — the quota
  policy, the tool binding, and the exact counting rules.
