# Pattern: egress after read — govern what a tool returns

A retrieval tool is authorized before it runs, but what comes back is only known
after the fetch. The `onResult` / `on_result` hook decides on the **result**, in
the same audit trail.

```cedar
// fetching is permitted — the content is unknown until it arrives
permit(principal, action == Action::"read", resource);

// releasing it to the agent is a second decision, on its classification
permit(principal, action == Action::"release", resource)
when { context.classification == "public" || context.classification == "internal" };

// restricted content never reaches the agent
forbid(principal, action == Action::"release", resource)
when { context.classification == "restricted" };
```

## Govern the tool

The hook runs after the body returns and before the caller or the model sees the
result.

```ts
import { govern, Denied } from "@watchlight/sdk";

const readDoc = govern.tool(fetchDocument, {
  intent: "read",
  resource: (id) => `doc/${id}`,
  onResult: async (doc, { resource, principal }) => {
    const release = await govern.authorize({
      principal, action: "release", resource,
      context: { classification: classify(doc) },   // your classifier
    });
    if (!release.allowed) throw new Denied(resource, "release", release.reason);
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
        raise Denied(info["resource"], "release", release["reason"])   # withheld
    return govern.sanitize(doc["text"], resource=info["resource"])["text"]

@govern.tool("read", resource=lambda doc_id: f"doc/{doc_id}", on_result=release_gate)
def fetch_document(doc_id): ...
```

The same option is on the framework adapters: `governTool(tool, { intent,
onResult })` for LangChain and LangGraph.js, and `governedHooks({ onResult })`
for the Claude Agent SDK, which replaces the tool output the model receives.

## Verdicts

Proved by [`suites/egress-after-read.suite.json`](./suites/egress-after-read.suite.json).

| step | classification | verdict |
|---|---|---|
| `read` | — (unknown yet) | **Allow** — the fetch may run |
| `release` | public | **Allow** |
| `release` | internal | **Allow** |
| `release` | restricted | **Deny** — result withheld |
| `release` | *(none)* | **Deny** — unclassified is fail-closed |

[`scripts/egress-after-read.mjs`](./scripts/egress-after-read.mjs) proves the
hook's own behaviour: every disposition below, the shared deadline, and
value-free `egress` records joined to their decision.

## What the hook can do

- **Return a value** — it replaces the payload the caller or model receives.
- **Return nothing** — the payload passes through unchanged.
- **Throw or raise** — the payload is withheld. The Claude hook cannot throw back
  to the SDK, so the model gets the opaque `"not authorized"` instead.
- **Outrun the deadline** — withheld the same way.

## The deadline

Every path bounds the hook at **8 seconds**, settable with `onResultTimeoutMs` /
`on_result_timeout_ms`. At the deadline the call rejects with `EgressTimeout`,
the `egress` record says `withheld: true`, and a hook that settles afterwards is
discarded. No value switches it off; a hook that genuinely needs longer takes a
larger number.

TypeScript races the hook, so the deadline applies everywhere. Python enforces it
on an **async** tool body, where the hook is awaited; a synchronous body with
`on_result_timeout_ms` raises `TypeError` rather than accepting a deadline it
cannot honour, so put your own time bound on a synchronous hook.

On `governedHooks` the adapter also raises the SDK's own matcher timeout above
its deadline, so ours fires first and withholds instead of letting the raw output
through.

## The audit trail

The call's decision and the hook's disposition join on one `decision_id`, and the
`egress` line never carries the result or anything derived from it.

```json
{"ts":"…","agent":"doc-agent","intent":"read","resource":"doc/42","decision":"Allow","decision_id":"…7f1"}
{"ts":"…","agent":"doc-agent","intent":"release","resource":"doc/42","decision":"Deny","decision_id":"…9c2"}
{"ts":"…","agent":"doc-agent","intent":"read","event":"egress","resource":"doc/42","replaced":false,"decision_id":"…7f1","withheld":true}
```

The deadline reached `govern.tool()` and the LangChain adapters in 0.9.1 — see
[breaking changes](../../docs/breaking-changes.md).

Pair with [PII before read](./pii-before-read.md) for minimization and
[data egress](./data-egress.md) for the pre-call boundary.
