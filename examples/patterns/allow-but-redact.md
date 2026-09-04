# Pattern: allow, but redact — obligations on an `Allow`

**Problem.** Many decisions are not a clean yes or no. An agent *may* read a
customer record — but not the social-security number in it. It *may* export
records — but at most 25 at a time, and without logging the values. Today those
"yes, but…" rules live in application code next to the tool, where they drift
from the policy that `govern.test` checks and that the audit trail records.

An **obligation** moves the "but" into the policy. A `permit` annotated with
`@obligate_*` yields an `Allow` that carries structured constraints the caller
**must honour**, and the policy test harness asserts them like any other verdict.

**Policy** — [`suites/allow-but-redact.suite.json`](./suites/allow-but-redact.suite.json):

```cedar
// Customer records are readable — with the SSN redacted before anyone sees them.
@obligate_redact("ssn")
permit(principal, action == Action::"read", resource)
when { context.record_type == "customer" };

// Internal notes are readable in full: no annotation, no obligations.
permit(principal, action == Action::"read", resource)
when { context.record_type == "note" };

// Exports are capped, redacted twice over, and never value-logged.
@obligate_redact("ssn, dob")
@obligate_max_items("25")
@obligate_log_values("false")
permit(principal, action == Action::"export", resource)
when { context.record_type == "customer" };
```

**The vocabulary.** The engine parses a closed set of annotations at policy-load
time (a malformed value rejects the policy) and surfaces them on the result:

| Annotation | Result field (TS / Python) | Meaning |
|---|---|---|
| `@obligate_redact("a, b")` | `redact: ["a","b"]` / `"redact"` | Field names to strip before the result reaches the caller or the model. |
| `@obligate_max_items("25")` | `maxItems: 25` / `"max_items"` | Upper bound on how many items the caller may act on or return. |
| `@obligate_log_values("false")` | `logValues: false` / `"log_values"` | Whether the values handled under this decision may be logged. |
| `@obligate_<name>("raw")` | `extra: { name: ["raw"] }` / `"extra"` | Any other key, passed through raw for your own code to interpret — per name, the distinct values the carrying permits declared. |

**Honour it in `onResult`.** The decision that let the body run is the one whose
obligations apply, so read them where you already govern the result:

```ts
import { govern } from "@watchlight/sdk";

const readRecord = govern.tool(fetchRecord, {
  intent: "read",
  resource: (id) => `customer/${id}`,
  context: () => ({ record_type: "customer" }),
  onResult: async (record, { resource, principal, decisionId }) => {
    const d = await govern.authorize({ principal, action: "read", resource, context: { record_type: "customer" } });
    const fields = d.obligations?.redact ?? [];
    // 1. Structural redaction: drop the obligated fields from the record itself.
    for (const f of fields) delete record[f];
    // 2. Belt and braces: sanitize the free text too, joined to the same decision.
    record.notes = govern.sanitize(record.notes ?? "", { resource, decisionId, types: ["SSN"] }).text;
    return record;                                   // replaces what the caller sees
  },
});
```

```python
from watchlight import govern

def honour_obligations(record, info):
    d = govern.authorize(action="read", principal=info["principal"], resource=info["resource"],
                         context={"record_type": "customer"})
    for field in (d.get("obligations") or {}).get("redact", []):
        record.pop(field, None)                      # structural redaction
    record["notes"] = govern.sanitize(record.get("notes", ""), resource=info["resource"],
                                      decision_id=info["decision_id"], types=["SSN"])["text"]
    return record                                    # replaces what the caller sees

@govern.tool("read", resource=lambda rid: f"customer/{rid}",
             context=lambda rid: {"record_type": "customer"}, on_result=honour_obligations)
def fetch_record(rid): ...
```

Or use the primitive directly for a bounded export:

```ts
const d = await govern.authorize({ action: "export", resource: "customer/*", context: { record_type: "customer" } });
if (!d.allowed) throw new Error(d.reason);
const rows = await exportRows({ limit: d.obligations?.maxItems ?? 0 });   // 0 = nothing, fail-closed
if (d.obligations?.logValues === false) logger.redactValues();
```

**Verdicts** (verified by `check.sh`; the suite needs an engine that emits
obligations — `@watchlight/engine` / `watchlight-engine` **0.2.0 or later**; on
an older engine the two obligation assertions fail rather than pass vacuously):

| action | `record_type` | verdict | obligations |
|---|---|---|---|
| `read` | customer | **Allow** | `redact: ["ssn"]` |
| `read` | note | **Allow** | *(none — asserted with `obligations: {}`)* |
| `export` | customer | **Allow** | `redact: ["ssn","dob"]`, `maxItems: 25`, `logValues: false` |
| `read` | other | **Deny** | *(a Deny never carries any)* |
| `read` | *(none)* | **Deny** | fail-closed |

**Rules that matter.**

- **Only an `Allow` carries obligations.** `Deny` and `NeedsApproval` never do —
  there is nothing to honour until the action may run. An approved
  human-in-the-loop `Allow` carries them like any other.
- **Several permits, one merge — always the strictest.** Every carrier of the
  Allow — the engine's own merged obligations and each determining permit's —
  is merged to the strictest reading: `redact` is the union, `maxItems` the
  minimum, `logValues` the logical AND. `extra` values are raw strings the SDK
  never interprets, so every carrier's value is kept: `extra[name]` is the sorted
  list of distinct values, and *your* code decides what a disagreement means.
- **Unreadable means fail-closed.** A known obligation the SDK cannot read (a
  non-numeric `max_items`, a non-boolean `log_values`, an empty `redact`) is never
  dropped: `authorize` throws / raises `AuthorizeError` (`"invalid obligations on
  an Allow decision"`) and a governed tool body does not run.
- **Value-free, both ways.** Obligations are policy-authored strings echoed as-is;
  nothing is derived from request or result values, and nothing about the
  result enters the audit trail — the `sanitization` and `egress` lines carry
  counts and dispositions, joined to the decision by `decision_id`.
- **The default is fail-closed.** Treat a missing obligation as *no permission*,
  not *no limit*: `maxItems ?? 0`, not `maxItems ?? Infinity`.

**Test it like a verdict.** A fixture may state the obligations an `Allow` must
carry; the comparison is exact (`redact` as a set, `extra` by key and value), `{}`
asserts there are none, and an ill-typed expectation is a malformed suite:

```json
{ "name": "a customer record may be read - with the SSN redacted", "action": "read",
  "resource": "customer/42", "context": { "record_type": "customer" },
  "expect": "Allow", "obligations": { "redact": ["ssn"] } }
```

**Why it's high-stakes.** A redaction rule that lives only in code is invisible to
the policy review, untested by the policy suite, and one refactor away from
disappearing. Putting it on the `permit` makes "allow, but redact" a single
reviewable, testable statement — and the tool that ignores it is now provably
out of policy. Pair with [egress after read](./egress-after-read.md) for the
classification decision and [PII before read](./pii-before-read.md) for the
detectors.
