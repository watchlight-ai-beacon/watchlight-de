# Pattern: egress after read — govern what a tool *returns*

**Problem.** A retrieval tool — fetch a document, look up a record, search a
corpus — can be authorized *before* it runs, but what comes back is only known
*after* the fetch. Whether the agent may **see** the result (its classification,
the personal data in it) is a decision about the **result**, not the call. Without
a hook that decision ends up in application code, outside the audit trail.

The [data-egress](./data-egress.md) pattern decides before the bytes move, on facts
known before the call. This pattern is its complement: the `onResult` /
`on_result` hook runs **after the body returns and before the caller (or the
model) sees the result**, and its disposition is recorded next to the call's
decision.

**Policy** — [`suites/egress-after-read.suite.json`](./suites/egress-after-read.suite.json):

```cedar
// Fetching is permitted — the content is unknown until it comes back.
permit(principal, action == Action::"read", resource);

// Releasing the fetched content to the agent is a second decision, on its classification.
permit(principal, action == Action::"release", resource)
when { context.classification == "public" || context.classification == "internal" };

// Restricted content never reaches the agent — a hard stop.
forbid(principal, action == Action::"release", resource)
when { context.classification == "restricted" };
```

**Govern the tool:**

```ts
import { govern, Denied } from "@watchlight/sdk";

const readDoc = govern.tool(fetchDocument, {
  intent: "read",
  resource: (id) => `doc/${id}`,
  // Runs over the RESULT, with the same decisionId written on the call's decision line.
  onResult: async (doc, { resource, principal }) => {
    // 1. The classification is only known now — decide on it with a second authorize.
    const release = await govern.authorize({
      principal, action: "release", resource,
      context: { classification: classify(doc) },   // your classifier, not the agent's narration
    });
    if (!release.allowed) throw new Denied(resource, "release", release.reason); // withheld
    // 2. Minimize what the agent sees.
    return govern.sanitize(doc.text, { resource }).text;   // replaces the payload
  },
});
```

```python
from watchlight import govern, Denied

def release_gate(doc, info):
    release = govern.authorize(
        action="release", principal=info["principal"], resource=info["resource"],
        context={"classification": classify(doc)},
    )
    if not release["allowed"]:
        raise Denied(info["resource"], "release", release["reason"])   # withheld, fail-closed
    return govern.sanitize(doc["text"], resource=info["resource"])["text"]

@govern.tool("read", resource=lambda doc_id: f"doc/{doc_id}", on_result=release_gate)
def fetch_document(doc_id): ...
```

The same option exists on the framework adapters: `governTool(tool, { intent,
onResult })` for LangChain / LangGraph.js, and `governedHooks({ onResult })` for
the Claude Agent SDK, which installs a `PostToolUse` hook that replaces the tool
output the model receives.

**Verdicts** (verified):

| step | classification | verdict |
|---|---|---|
| `read` | — (unknown yet) | **Allow** — the fetch may run |
| `release` | public | **Allow** — result passes to the agent |
| `release` | internal | **Allow** |
| `release` | restricted | **Deny** — the `forbid` boundary; result withheld |
| `release` | *(none)* | **Deny** — unclassified is fail-closed |

**Hook semantics** (identical in TS and Python, and across `tool` / `governTool` /
the Claude `PostToolUse` hook):

- **Return a value** → it **replaces** the payload the caller or model receives.
- **Return nothing** (`undefined` / `null` / `None`) → the payload passes through
  unchanged.
- **Throw / raise** → the payload is **withheld**. In `tool()` and `governTool` the
  hook is awaited in-process and the error propagates — the raw result is never
  returned. In the Claude hook, which cannot throw back to the SDK, the model
  receives the opaque `"not authorized"` string instead of the raw output.
- **Outrun the deadline** → the payload is **withheld the same way**. This is the
  hook you are most tempted to make slow — a classifier call, a remote policy
  lookup — so it is bounded: `onResultTimeoutMs` / `on_result_timeout_ms`,
  **8 s by default**, on `tool()`, on `governTool` / `governTools` and on
  `governedHooks` alike. At the deadline the call rejects with `EgressTimeout`
  (the Claude hook, which cannot throw back to the SDK, substitutes the opaque
  `"not authorized"`), the `egress` record says `withheld: true`, and a hook that
  settles afterwards is discarded — a slow hook can never release a payload late.
  There is no value that switches the deadline off; a hook that genuinely needs
  longer takes a larger number (`onResultTimeoutMs: 300_000`).
- **What each lane can bound.** The deadline needs a moment in which to fire.
  TypeScript races the hook, so it applies everywhere. Python enforces it on an
  **async** tool body, where the hook is awaited; Python cannot interrupt running
  code, so a hook that blocks the event loop is not preempted, and
  `on_result_timeout_ms` on a *synchronous* tool body is refused fail-closed
  (`TypeError`) rather than accepted and ignored. Bound a synchronous hook
  yourself. (An async hook on a synchronous body is likewise refused fail-closed:
  `TypeError`, payload withheld.)
- **On `governedHooks` specifically**, the deadline does one thing more: SDK hooks
  run in parallel on the *original* output, so a hook that merely outran the SDK's
  own hook timeout would let the raw output through. The adapter therefore sets
  the SDK matcher timeout above its own (`ceil(ms / 0.8)` seconds), so our
  deadline always fires first and withholds.

**The audit trail.** The call's decision and the hook's disposition join on one
`decision_id`, and the `egress` line is **value-free** — it never carries the
result, the replacement, or anything derived from them:

```json
{"ts":"…","agent":"doc-agent","principal":"Agent::\"doc-agent\"","intent":"read","resource":"doc/42","decision":"Allow","decision_id":"…7f1"}
{"ts":"…","agent":"doc-agent","principal":"Agent::\"doc-agent\"","intent":"release","resource":"doc/42","decision":"Deny","decision_id":"…9c2"}
{"ts":"…","agent":"doc-agent","principal":"Agent::\"doc-agent\"","intent":"read","event":"egress","resource":"doc/42","replaced":false,"decision_id":"…7f1","withheld":true}
```

**Why it's high-stakes.** A prompt-injected or confused agent can ask for a
document it is allowed to *fetch* and then act on content it must never *see*.
Deciding at the call is not enough when the classification lives in the result;
this hook puts the second decision where the facts are, and puts its outcome in
the same trail as the first. Pair with [PII before read](./pii-before-read.md) for
the minimization step and [data egress](./data-egress.md) for the pre-call
boundary.

## Breaking in 0.9.1 — the deadline now applies to every path

**What changed.** `EgressRecord.withheld` has always been documented as "the hook
threw, **or outran its deadline** — the payload was never released", but only
`governedHooks` enforced a deadline. `govern.tool()` and the LangChain adapters
had none: a hook that took 12 s released the payload after 12 s, and the record
said nothing was withheld. All three paths now bound the hook at the same 8 s
default.

**Who is affected.** Anyone whose egress hook can take longer than 8 seconds —
in practice a hook that calls a model, a classifier or a remote policy service.
That hook now **withholds** where it used to release late: the call raises
`EgressTimeout` (Python) / rejects with `EgressTimeout` (TypeScript) and the
`egress` record says `withheld: true`. Nothing changes for a hook that finishes
inside 8 seconds. This is the closed direction — a payload is refused, never
released — so it fails safe, but a slow hook that used to succeed will now be
seen as a refusal at the call site.

**The one-line opt-out**, for a hook that genuinely needs longer:

```ts
govern.tool(fn, { intent: "read", onResult: slowClassifier, onResultTimeoutMs: 300_000 });
```

```python
@govern.tool("read", on_result=slow_classifier, on_result_timeout_ms=300_000)
async def read_doc(doc_id): ...
```

There is deliberately **no value that disables the deadline** — `0`, a negative
and `Infinity` / `inf` are refused (`RangeError` / `ValueError`) where the tool is
wrapped. An unbounded hook is the defect this closes, so it is not something a
config value can reintroduce by accident; a large explicit number says so in
review. Python additionally refuses `on_result_timeout_ms` on a **synchronous**
tool body (`TypeError`): a synchronous hook cannot be interrupted, and a deadline
that enforces nothing would be a deadline in name only.
