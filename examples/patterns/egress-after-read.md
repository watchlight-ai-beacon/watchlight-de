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
- **Return nothing** (`undefined` / `None`) → the payload passes through unchanged.
- **Throw / raise** → the payload is **withheld**. In `tool()` and `governTool` the
  error propagates and the raw result is never returned; in the Claude hook,
  which cannot throw back to the SDK, the model receives the opaque
  `"not authorized"` string instead of the raw output. Fail-closed: a broken
  classifier can never leak the result by accident.

**The audit trail.** The call's decision and the hook's disposition join on one
`decision_id`, and the `egress` line is **value-free** — it never carries the
result, the replacement, or anything derived from them:

```json
{"ts":"…","agent":"doc-agent","principal":"doc-agent","intent":"read","resource":"doc/42","decision":"Allow","decision_id":"…7f1"}
{"ts":"…","agent":"doc-agent","principal":"doc-agent","intent":"release","resource":"doc/42","decision":"Deny","decision_id":"…9c2"}
{"ts":"…","agent":"doc-agent","principal":"doc-agent","intent":"read","event":"egress","resource":"doc/42","replaced":false,"withheld":true,"decision_id":"…7f1"}
```

**Why it's high-stakes.** A prompt-injected or confused agent can ask for a
document it is allowed to *fetch* and then act on content it must never *see*.
Deciding at the call is not enough when the classification lives in the result;
this hook puts the second decision where the facts are, and puts its outcome in
the same trail as the first. Pair with [PII before read](./pii-before-read.md) for
the minimization step and [data egress](./data-egress.md) for the pre-call
boundary.
