# Pattern: allow, but redact — obligations on an `Allow`

Many decisions are "yes, but". An **obligation** puts the "but" in the policy,
where the suite tests it and the review can see it.

```cedar
// customer records are readable — with the SSN redacted first
@obligate_redact("ssn")
permit(principal, action == Action::"read", resource)
when { context.record_type == "customer" };

// internal notes are readable in full: no annotation, no obligations
permit(principal, action == Action::"read", resource)
when { context.record_type == "note" };

// exports are capped, redacted twice over, and never value-logged
@obligate_redact("ssn, dob")
@obligate_max_items("25")
@obligate_log_values("false")
permit(principal, action == Action::"export", resource)
when { context.record_type == "customer" };
```

## The vocabulary

The engine parses a closed set at load time and surfaces it on the result. A
malformed value rejects the policy.

| Annotation | Result field (TS / Python) | Meaning |
|---|---|---|
| `@obligate_redact("a, b")` | `redact` | field names to strip before the result is handed on |
| `@obligate_max_items("25")` | `maxItems` / `max_items` | how many items the caller may act on |
| `@obligate_log_values("false")` | `logValues` / `log_values` | whether these values may be logged |
| `@obligate_<name>("raw")` | `extra` | any other key, raw, for your own code to interpret |

## Honour them in `onResult`

The decision that let the body run is the one whose obligations apply, and the
hook receives them next to the `decisionId`.

```ts
import { govern } from "@watchlight/sdk";

const readRecord = govern.tool(fetchRecord, {
  intent: "read",
  resource: (id) => `customer/${id}`,
  context: () => ({ record_type: "customer" }),
  onResult: (record, { resource, decisionId, obligations }) => {
    for (const f of obligations?.redact ?? []) delete record[f];   // structural
    record.notes = govern.sanitize(record.notes ?? "", { resource, decisionId, types: ["SSN"] }).text;
    return record;                                                 // replaces the payload
  },
});
```

```python
from watchlight import govern

def honour_obligations(record, info):
    for field in (info.get("obligations") or {}).get("redact", []):
        record.pop(field, None)                      # structural redaction
    record["notes"] = govern.sanitize(record.get("notes", ""), resource=info["resource"],
                                      decision_id=info["decision_id"], types=["SSN"])["text"]
    return record

@govern.tool("read", resource=lambda rid: f"customer/{rid}",
             context=lambda rid: {"record_type": "customer"}, on_result=honour_obligations)
def fetch_record(rid): ...
```

Or read them off `authorize` directly, for a bounded export:

```ts
const d = await govern.authorize({ action: "export", resource: "customer/*", context: { record_type: "customer" } });
if (!d.allowed) throw new Error(d.reason);
const rows = await exportRows({ limit: d.obligations?.maxItems ?? 0 });   // 0 = nothing
if (d.obligations?.logValues === false) logger.redactValues();
```

## Verdicts

Proved by [`suites/allow-but-redact.suite.json`](./suites/allow-but-redact.suite.json),
which needs `@watchlight/engine` / `watchlight-engine` **0.2.0 or later**. On an
older engine the obligation assertions fail rather than pass vacuously.

| action | `record_type` | verdict | obligations |
|---|---|---|---|
| `read` | customer | **Allow** | `redact: ["ssn"]` |
| `read` | note | **Allow** | *(none)* |
| `export` | customer | **Allow** | `redact: ["ssn","dob"]`, `maxItems: 25`, `logValues: false` |
| `read` | other | **Deny** | — |
| `read` | *(none)* | **Deny** | fail-closed |

A fixture states the obligations an `Allow` must carry. The comparison is exact,
and `{}` asserts there are none:

```json
{ "name": "a customer record may be read - with the SSN redacted", "action": "read",
  "resource": "customer/42", "context": { "record_type": "customer" },
  "expect": "Allow", "obligations": { "redact": ["ssn"] } }
```

## Worth knowing

- **Only an `Allow` carries obligations.** `Deny` and `NeedsApproval` never do.
  An approved human-in-the-loop `Allow` carries them like any other.
- **Several permits merge to the strictest reading.** `redact` unions, `maxItems`
  takes the minimum, `logValues` is a logical AND. `extra[name]` keeps every
  carrier's value, sorted, for your code to reconcile.
- **An unreadable obligation fails closed.** A non-numeric `max_items`, a
  non-boolean `log_values` or an empty `redact` raises `AuthorizeError` and the
  tool body does not run.
- **Treat a missing obligation as no permission.** `maxItems ?? 0`, never
  `?? Infinity`.
- Obligations are policy-authored strings echoed as-is. Nothing is derived from
  request or result values, and nothing about the result enters the trail.

Pair with [egress after read](./egress-after-read.md) for the classification
decision and [PII before read](./pii-before-read.md) for the detectors.
