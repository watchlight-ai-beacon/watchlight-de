# Pattern: destructive actions

**Problem.** An agent can delete, drop, or deploy. Reads should be free, deletes
should require a human, and some resources must be **undeletable** — a boundary no
approval can cross.

**Policy** — [`suites/destructive-actions.suite.json`](./suites/destructive-actions.suite.json):

```cedar
permit(principal, action == Action::"read", resource);

@enforcement_effect("require_approval")
permit(principal, action == Action::"delete", resource);

// a hard boundary: forbid always wins, even over the approval permit above
forbid(principal, action == Action::"delete", resource)
when { context.protected == true };
```

**Govern the tool:**

```ts
const del = govern.tool(deleteRecord, {
  intent: "delete",
  resource: (o) => `record/${o.id}`,
  context:  (o) => ({ protected: o.isProtected }),
  onNeedsApproval: async ({ decisionId }) => askAHuman(decisionId),
});
```

**Verdicts** (verified):

| action | `protected` | verdict |
|---|---|---|
| `read` | — | **Allow** |
| `delete` | false | **NeedsApproval** |
| `delete` | true | **Deny** — the `forbid` overrides the approval permit |
| `drop_table` (unlisted) | — | **Deny** — fail-closed |

**Why it's high-stakes.** The key move is that a `forbid` **beats** a
`require_approval` permit: a protected resource returns a flat `Deny`, not a
"click to approve." That's the difference between "a human *can* delete this" and
"this *cannot* be deleted." Unlisted actions (`drop_table`) are denied because
nothing permits them — you never have to enumerate every dangerous verb.

Graduate with `WATCHLIGHT_APDP_URL`; in Enterprise the same `forbid` boundaries
are centrally managed and the approval step becomes a full workflow.
