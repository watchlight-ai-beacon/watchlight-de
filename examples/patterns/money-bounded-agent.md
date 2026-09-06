# Pattern: money-bounded agent

An agent can charge a card. Small refundable charges go through; large ones wait
for a human.

```cedar
// small, refundable, inside the caller's own limit
permit(principal, action == Action::"charge", resource)
when { context.amount <= context.limit && context.refundable };

// anything large returns NeedsApproval instead of Allow
@enforcement_effect("require_approval")
permit(principal, action == Action::"charge", resource)
when { context.amount > 1000 };
```

## Govern the tool

```ts
import { govern } from "@watchlight/sdk";
govern.load("charge.policy.json");

const charge = govern.tool(chargeCard, {
  intent: "charge",
  principal: (o) => `User::"${o.userId}"`,            // the acting end-user
  context:   (o) => ({ amount: o.amount, limit: o.perActionLimit, refundable: o.refundable }),
  onNeedsApproval: async ({ decisionId }) => askAHuman(decisionId),
});
```

```python
from watchlight import govern
govern.load("charge.policy.json")

@govern.tool("charge",
             principal=lambda o: f'User::"{o["userId"]}"',
             context=lambda o: {"amount": o["amount"], "limit": o["perActionLimit"],
                                "refundable": o["refundable"]},
             on_needs_approval=lambda d: ask_a_human(d["decision_id"]))
def charge_card(o): ...
```

## Verdicts

Proved by [`suites/money-bounded-agent.suite.json`](./suites/money-bounded-agent.suite.json).

| amount | limit | refundable | verdict |
|---|---|---|---|
| 50 | 200 | yes | **Allow** |
| 500 | 200 | yes | **Deny** — over the limit |
| 50 | 200 | no | **Deny** — not refundable |
| 5000 | 200 | yes | **NeedsApproval**, then **Allow** once a human confirms |

## Worth knowing

- The body never runs on a `Deny` or a `NeedsApproval`. Nothing matching denies.
- `@enforcement_effect` only works on a `permit`. On a `forbid` it is ignored and
  you get a plain `Deny`.
- A misspelled effect raises `PolicyError` at load, so a typo cannot become a
  permit that charges without asking.
- Store the returned `decisionId` next to the charge record.
- An approval is valid in the process that minted it until you configure a
  secret and a store — see
  [destructive actions](./destructive-actions.md#approvals-across-processes).
