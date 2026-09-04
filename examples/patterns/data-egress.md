# Pattern: data egress

**Problem.** An agent can move data (export, upload, forward). Data has a
**classification**, destinations have a **boundary**, and restricted data must not
cross to the outside — regardless of what the agent was asked to do.

**Policy** — [`suites/data-egress.suite.json`](./suites/data-egress.suite.json):

```cedar
permit(principal, action == Action::"export", resource)
when { context.destination == "internal" };

permit(principal, action == Action::"export", resource)
when { context.destination == "external" && context.classification == "public" };

// restricted data never leaves the boundary — a hard stop
forbid(principal, action == Action::"export", resource)
when { context.classification == "restricted" && context.destination == "external" };
```

**Govern the tool:**

```ts
const exportData = govern.tool(doExport, {
  intent: "export",
  context: (job) => ({ destination: job.destination, classification: classify(job.payload) }),
});
```

**Verdicts** (verified):

| destination | classification | verdict |
|---|---|---|
| external | public | **Allow** |
| internal | public | **Allow** |
| external | restricted | **Deny** — the `forbid` boundary |
| internal | restricted | **Allow** — stays usable inside |

**Why it's high-stakes.** This is an exfiltration guard: a prompt-injected or
confused agent can *ask* to export restricted data to the outside, and the
`forbid` stops it before the bytes move — the permits above it don't matter. The
decision keys on facts *you* supply (`classification`, `destination`), so your
classifier, not the agent's narration, drives the call. Pair with the
[kill-switch](./kill-switch.md) for a second, agent-wide stop.

**When the classification is only known after the call.** This pattern decides
*before* the bytes move, on facts known up front. For a retrieval tool — where
what comes back is unknown until it comes back — govern the **result** instead:
[egress after read](./egress-after-read.md) runs an `onResult` / `on_result` hook
over the returned payload and records its disposition in the same audit trail,
joined to the call's decision by `decision_id`.
