# Pattern: external messaging

**Problem.** An agent can send messages (email, chat, webhook). Internal
recipients are fine; reaching *outside* should be limited to an **allowlist** of
destinations, and even those should get a human's eyes first.

**Policy** — [`suites/external-messaging.suite.json`](./suites/external-messaging.suite.json):

```cedar
permit(principal, action == Action::"send_message", resource)
when { context.recipient_internal == true };

@enforcement_effect("require_approval")
permit(principal, action == Action::"send_message", resource)
when { context.recipient_internal == false
    && ["partner.example", "vendor.example"].contains(context.recipient_domain) };
```

**Govern the tool:**

```ts
const send = govern.tool(sendMessage, {
  intent: "send_message",
  context: (m) => ({
    recipient_internal: m.domain === myOrgDomain,
    recipient_domain:   m.domain,
  }),
  onNeedsApproval: async ({ decisionId }) => askAHuman(decisionId),
});
```

**Verdicts** (verified):

| recipient | domain | verdict |
|---|---|---|
| internal | `internal.example` | **Allow** |
| external | `partner.example` (allowlisted) | **NeedsApproval** |
| external | `unknown.example` | **Deny** |

**Note on the allowlist.** `["partner.example", …].contains(context.recipient_domain)`
uses a **set literal** — the reliable way to allowlist in the Developer Edition
(entity-hierarchy `in` is not resolved in-process; see
[what the engine resolves](https://docs.watchlight.ai/de/policies)). Anything not
on the list falls through to **Deny**, so a new external destination can't be
reached until you add it — deliberately, in the policy.

Keeping the allowlist central across a fleet, and turning approval into a real
routing/hold/resume workflow, is what Enterprise adds on top of the same policy.
