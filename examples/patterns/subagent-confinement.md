# Pattern: sub-agent confinement

A child agent can only ever hold a subset of what its parent held, so a
prompt-injected sub-agent has no tool to reach for.

This is scope attenuation, not `authorize`: authority is a capability set that
only narrows.

```ts
import { govern } from "@watchlight/sdk";

const root = await govern.scope({
  tools: ["read_file", "web_search", "send_email", "transfer_funds"],
  timeBudgetSeconds: 600,
});

const summarizer = root.attenuate({ tools: ["read_file"] });   // a strict subset

summarizer.attenuate({ tools: ["send_email"] });   // throws — not in the parent set
```

```python
from watchlight import govern

root = govern.scope(tools=["read_file", "web_search", "send_email", "transfer_funds"],
                    time_budget_seconds=600)
summarizer = root.attenuate(tools=["read_file"])     # subset of the parent
# summarizer.attenuate(tools=["send_email"])         # raises AttenuationDenied
```

## Limits

- A child can drop tools, resources and intents and shrink budgets, never add.
  Widening raises `AttenuationDenied`.
- The tree goes **five levels deep** (`DE_MAX_DEPTH`). Deeper raises
  `DevEditionCeiling` — a product boundary, not a policy denial. Orchestrator →
  task → tool is depth 2 or 3.
- **A scope is checked when you delegate, never when a call is authorized.**
  Confining a sub-agent means narrowing the scope *and* writing the policy.
- The check is in-process and cooperative.

## The policy half

A scope is checked when you delegate, never when a call is authorized. So the
scope alone does not stop a confined child from asking for something else — a
policy does, and it reads the chain.

```cedar
permit(principal, action, resource);

forbid(principal, action == Action::"transfer", resource)
when { context.actor_chain.contains("research") };
```

The orchestrator may still transfer. Anything acting below `research` may not:

```
orchestrator          search    -> Allow
orchestrator          transfer  -> Allow
research (delegated)  search    -> Allow
research (delegated)  transfer  -> Deny
```

`delegate` appends to `context.actor_chain`, so the rule holds however deep the
tree goes. Renaming with `as` does not append, so it does not confine.

In the Developer Edition the check is in-process and cooperative: a child is
confined because your code asked the governor before it acted. Enterprise
confines it for you — the policy is distributed to the plugins and the
enforcement proxy, so a sub-agent is bounded whether or not its code
cooperates. See [the platform](https://www.watchlight.ai/platform).

## Crossing a process boundary

A queue worker cannot hold the parent's in-memory `Scope`, and it must not
re-assert the child's limits from the job payload. Hand it a **scope token** and
let the receiving engine re-prove the subset.

```ts
// orchestrator — a shared secret of >= 16 bytes; there is no default
const govern = new Watchlight({ agent: "orchestrator", signingSecret: process.env.WATCHLIGHT_SIGNING_SECRET });
const root = await govern.scope({ tools: ["read_file", "web_search", "send_email"], timeBudgetSeconds: 600 });
const summarizer = root.attenuate({ tools: ["read_file"] });
queue.push({ job, scope: summarizer.toToken() });     // wls1.<claims>.<hmac>

// worker — same agent identity, same secret, different process
const scope = await govern.scopeFromToken(msg.scope);  // the engine replays every level
scope.attenuate({ tools: ["send_email"] });            // still throws
```

```python
govern = Watchlight(agent="orchestrator", signing_secret=os.environ["WATCHLIGHT_SIGNING_SECRET"])
summarizer = govern.scope(tools=["read_file", "web_search", "send_email"]).attenuate(tools=["read_file"])
queue.push({"job": job, "scope": summarizer.to_token()})

scope = govern.scope_from_token(msg["scope"])          # worker: the engine replays the chain
```

What both processes need from the secret is in
[the signing secret](../../docs/signing-secret.md).

The token is an HMAC-SHA256 over the canonical scope claims, bound to the agent
identity, with `iat` and `exp`. `scopeFromToken` verifies the signature and the
time window, then replays each level through the strict-subset validator. A
chain that asks for more than its root allows is refused by the engine even with
a valid signature.

## Worth knowing

- **The secret buys integrity, not attestation.** It proves the token was minted
  by a holder of the secret and not altered. It does not prove *which* process
  minted it, and the root grant is rebuilt from the token, so any holder can mint
  any scope. Treat every process holding it as inside the boundary.
- **The token does not carry the actor chain.** A scope re-established elsewhere
  starts a fresh chain from the receiving governor's agent. Call `delegate` there
  if the delegation has to be recorded.
- Tampered, expired, oversized, wrong-agent and unknown-version tokens are
  refused with `ScopeTokenError`. With no signing secret, minting and verifying
  both fail closed.
- Every grant and refusal lands in the trail as an `attenuation` record carrying
  tool names and depth only.

## Verified by

[`scripts/subagent-confinement.mjs`](./scripts/subagent-confinement.mjs) — this
is a capability check, not a policy verdict, so there is no suite. It asserts
every rule above against the real engine, including the depth ceiling and the
token round-trip.
