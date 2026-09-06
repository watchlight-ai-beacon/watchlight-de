# Pattern: data egress

Data has a classification, destinations have a boundary, and restricted data
never crosses to the outside.

```cedar
permit(principal, action == Action::"export", resource)
when { context.destination == "internal" };

permit(principal, action == Action::"export", resource)
when { context.destination == "external" && context.classification == "public" };

// restricted data never leaves — a hard stop
forbid(principal, action == Action::"export", resource)
when { context.classification == "restricted" && context.destination == "external" };
```

## Govern the tool

```ts
const exportData = govern.tool(doExport, {
  intent: "export",
  context: (job) => ({ destination: job.destination, classification: classify(job.payload) }),
});
```

## Verdicts

Proved by [`suites/data-egress.suite.json`](./suites/data-egress.suite.json).

| destination | classification | verdict |
|---|---|---|
| external | public | **Allow** |
| internal | public | **Allow** |
| external | restricted | **Deny** — the `forbid` boundary |
| internal | restricted | **Allow** — still usable inside |

## Worth knowing

- The `forbid` stops the export before any bytes move, whatever the permits
  above it say.
- The decision keys on facts you supply, so your classifier drives it, not the
  agent's description of the payload.
- Pair it with the [kill-switch](./kill-switch.md) for a second, agent-wide stop.
- **When the classification is only known after the call** — a retrieval tool —
  govern the result instead: [egress after read](./egress-after-read.md).
