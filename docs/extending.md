# Extending Watchlight

The engine decides. Everything around the decision — where the trail goes, what
counts as an identifier, what counts as an attack, what a quota is folded from —
is yours, and each of those is a named place to plug your code in.

| You want to… | Use |
|---|---|
| Redact an identifier we do not know — a case number, an account number | [`register_detector`](#teach-it-an-identifier) |
| Flag an injection shape specific to your domain | [`register_screen_family`](#teach-it-an-attack) |
| Send the audit trail to your own store | [`audit_sink`](#send-the-trail-somewhere-durable) |
| Fold a quota from that store rather than the local file | [`counter_source`](#count-from-your-own-store) |
| Make an approval single-use across replicas | [`approval_store`](#share-approvals-across-processes) |
| Inspect or replace a result before it reaches the model | [`on_result`](#inspect-what-leaves) |
| Replace the policy set on a running process | [`reload`](#swap-the-policy-set) |

Two properties hold across all of them. **A hook never changes a verdict** — one
that raises or misbehaves fails closed, and the decision stands. And **the
value-free contract is not yours to widen**: the report and the trail carry
counts and labels, never the values behind them.

## Teach it an identifier

The built-in detectors cover identifiers everyone has — email, phone, SSN, card,
IBAN. Yours are yours: a case reference, an alien registration number, an
internal customer id. Register one and it redacts under its own label.

```python
from watchlight import register_detector

register_detector("CASE_NO", r"\bCASE-\d{4}-\d{5}\b")          # at start-up
```

```ts
registerDetector("CASE_NO", /\bCASE-\d{4}-\d{5}\b/);
```

```
"ref CASE-2026-00123"  ->  "ref <CASE_NO_1>"   counts {"CASE_NO": 1}
```

Pass `validate` for a check the pattern cannot express — the built-in card rule
uses it for a Luhn check. Registered detectors are on by default and selectable
through `types`.

## Teach it an attack

`screen` covers seven generic families of prompt injection and deliberately
leaves domain vocabulary alone — that is what lets it read a document about
substance history without rejecting it. The cost is that a shape specific to
your domain is covered by nothing. Register it, and the hit lands in the same
report and the same audit record as a built-in.

```python
register_screen_family("INJ_FORCE_APPROVAL", r"\bapprove this [a-z ]{0,30}immediately\b")
```

Write the pattern against **normalized** text: zero-width characters are removed
and whitespace runs collapsed before any rule runs, which is what defeats an
evasive spelling. Use single spaces and no `\s+`.

### Both registries refuse a pattern that can hang you

A detector and a screening rule each run over every document and every
submission, so one `(a+)+` is an outage. Both refuse it where you write it:

```python
register_detector("EVIL", r"(a+)+$")
# SanitizeError: detector 'EVIL': (a+)+ nests one unbounded quantifier inside
# another, which backtracks catastrophically on input that nearly matches.
```

The check is structural first, then empirical — growth measured over a few extra
characters, because a catastrophic pattern never returns and so cannot be timed
by waiting for it. A built-in label cannot be replaced, and once you register
anything, `detector_version` carries a digest of the set, so an audit record
says what was actually in force.

## Send the trail somewhere durable

The local `audit.jsonl` is gone on the next deploy. A sink receives the same
records:

```python
Watchlight(agent="svc", audit_sink=lambda record: store.insert(record))
```

The sink is called inside the decision, so anything durable is too slow to sit
there. Batching moves it off the request path and hands you a **list**:

```python
Watchlight(agent="svc", audit_sink=insert_many,
           audit_sink_batch=100, audit_sink_interval=2.0)
```

The queue is bounded — a destination that stops responding must not become
unbounded memory in the application it is auditing — so the oldest are dropped,
reported once, and counted on `trail.dropped`.

## Count from your own store

`counters()` folds the local file into a number a quota policy compares against.
Once the trail lives in your store, the file is the copy that cannot be trusted.
`counter_source` answers the same query from the store your sink writes to:

```python
Watchlight(agent="svc", audit_sink=insert_many,
           counter_source=lambda query: store.count_decisions(query))
```

Your source is handed the resolved query — `principal`, `outcome`, `window`, and
`intent` / `resource` only when the caller filtered on them — and must return a
non-negative integer counting **decision rows only**.

## Share approvals across processes

The default approval store is a dict in this process, so single-use is
per-replica rather than per token. Supply one every replica shares and it holds
across all of them. `add(id, expires_at)` must be an atomic check-and-set.

## Inspect what leaves

`on_result` sees a governed tool's result before the caller does. Return `None`
to pass it through, or a value to replace it. Raise, and the payload is withheld.

```python
@govern.tool(intent="read", on_result=screen_result, on_result_timeout_ms=200)
def fetch_document(): ...
```

The deadline bounds the decision to release: outrun it and the payload is
withheld, whatever the hook does afterwards.

## Swap the policy set

`load` and `allow` only ever add, so a reload built on them could add a permit
but never remove one. `reload` replaces:

```python
govern.reload("watchlight.policy.json")
govern.reload(policies=edited_bundle)
```

It is atomic — a set that does not compile leaves the governor exactly as it was
— and a missing file or an empty set raises rather than replacing your policies
with nothing.

## Next

- **[How policy works](policies.md)** — the Cedar model these plug into.
- **[The audit trail](audit-trail.md)** — record kinds, sinks and counters in full.
- **[Governance patterns](../examples/patterns/README.md)** — each one run against
  the real engine on every commit.
