# Pattern: money-bounded agent

**Problem.** An agent can trigger charges. It should spend only within a
per-action limit, only on refundable items, and anything above a threshold should
go to a human — decided *before* the charge, not audited after.

**Policy** — [`suites/money-bounded.suite.json`](./suites/money-bounded.suite.json):

```cedar
// small, refundable charges within the limit are fine
permit(principal, action == Action::"charge", resource)
when { context.amount <= context.limit && context.refundable };

// anything large routes to a human (returns NeedsApproval)
@enforcement_effect("require_approval")
permit(principal, action == Action::"charge", resource)
when { context.amount > 1000 };
```

**Govern the tool** (TypeScript; Python is identical in shape):

```ts
import { govern } from "@watchlight/sdk";
govern.load("charge.policy.json");

const charge = govern.tool(chargeCard, {
  intent: "charge",
  principal: (o) => `User::"${o.userId}"`,            // the acting end-user
  context:   (o) => ({ amount: o.amount, limit: o.perActionLimit, refundable: o.refundable }),
  onNeedsApproval: async ({ decisionId }) => askAHuman(decisionId),  // one-tap confirm
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

**Verdicts** (from the suite, verified against the engine):

| amount | limit | refundable | verdict |
|---|---|---|---|
| 50 | 200 | ✅ | **Allow** |
| 500 | 200 | ✅ | **Deny** (over limit) |
| 50 | 200 | ❌ | **Deny** (non-refundable) |
| 5000 | 200 | ✅ | **NeedsApproval** → **Allow** once a human confirms |

**Guarantees.** Fail-closed — no matching policy denies. The tool body never runs
on `Deny`/`NeedsApproval`. Each decision returns a `decisionId` you can store next
to the charge record. Graduate to the control plane with `WATCHLIGHT_APDP_URL` —
same policy, same code.

See also: [Enforcement effects](https://docs.watchlight.ai/de/enforcement-effects)
· [Testing & rollout](https://docs.watchlight.ai/de/testing).
