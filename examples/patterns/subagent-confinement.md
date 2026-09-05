# Pattern: sub-agent confinement

**Problem.** Your agent spawns sub-agents — a researcher, a summarizer, a tool
runner. Each child should be able to do **less** than its parent, never more, so a
sub-agent whose prompt was shaped by untrusted content (a poisoned document, an
injected web page) can't reach for a tool it was never meant to hold.

This uses **scope attenuation**, not `authorize`: authority is a capability set
that can only ever narrow.

**Use it:**

```ts
import { govern } from "@watchlight/sdk";

const root = await govern.scope({
  tools: ["read_file", "web_search", "send_email", "transfer_funds"],
  timeBudgetSeconds: 600,
});

// the summarizer only needs to read — hand it a strict subset
const summarizer = root.attenuate({ tools: ["read_file"] });

summarizer.attenuate({ tools: ["send_email"] });   // ❌ throws — not in the parent set
```

```python
from watchlight import govern

root = govern.scope(tools=["read_file", "web_search", "send_email", "transfer_funds"],
                    time_budget_seconds=600)
summarizer = root.attenuate(tools=["read_file"])     # ⊆ parent → OK
# summarizer.attenuate(tools=["send_email"])         # raises — can't widen
```

**Why it's high-stakes.** The blast radius of a compromised sub-agent is exactly
the tools it holds. Attenuation makes that set as small as the job needs and makes
it **impossible** for a child to hold more than its parent granted — the engine
validates every `attenuate()` as a strict subset and refuses a widening. A
prompt-injected summarizer simply has no `send_email` capability to abuse.

**Guarantees & limits.**

- Strict-subset only: a child can drop tools/resources/intents and shrink limits,
  never add. Widening throws.
- The Developer Edition governs the tree up to **depth 5** (`DE_MAX_DEPTH`); going
  deeper raises `DevEditionCeiling` — a product boundary, not a policy denial.
  Typical orchestrator → task → tool chains are depth 2–3.
- In the DE the check is in-process and cooperative. Enterprise enforces
  attenuation **server-side** (an agent can't route around it), removes the depth
  ceiling, and records every spawn and clamp in signed lineage.

**Crossing a process boundary.** A queue worker or scheduler that runs the
sub-agent's job cannot hold the parent's in-memory `Scope`, and it must not
re-assert the child's limits from the job payload (the engine can't verify a
payload). Hand it a **scope token** instead, and let the *receiving* engine
re-prove the subset:

```ts
// orchestrator — needs a shared secret (≥ 16 bytes); there is no default
const govern = new Watchlight({ agent: "orchestrator", signingSecret: process.env.WATCHLIGHT_SIGNING_SECRET });
const root = await govern.scope({ tools: ["read_file", "web_search", "send_email"], timeBudgetSeconds: 600 });
const summarizer = root.attenuate({ tools: ["read_file"] });
queue.push({ job, scope: summarizer.toToken() });     // wls1.<claims>.<hmac>

// worker — same agent identity, same secret, different process
const scope = await govern.scopeFromToken(msg.scope);  // engine re-runs every attenuation
scope.attenuate({ tools: ["send_email"] });            // ❌ still throws — not in the chain
```

```python
govern = Watchlight(agent="orchestrator", signing_secret=os.environ["WATCHLIGHT_SIGNING_SECRET"])
summarizer = govern.scope(tools=["read_file", "web_search", "send_email"]).attenuate(tools=["read_file"])
queue.push({"job": job, "scope": summarizer.to_token()})

scope = govern.scope_from_token(msg["scope"])          # worker: engine replays the chain
```

The token is an HMAC-SHA256 over the canonical scope claims — the root grant and
the engine-granted scope at every level — bound to the agent identity, with
`iat`/`exp`, and never longer-lived than the scope it names. `scopeFromToken`
verifies the signature (constant-time) and time window, rebuilds the root, and
replays each level through the engine's strict-subset validator; a token whose
chain requests more than its root allows is refused **by the engine**, even with
a valid signature. Tampered, expired, oversized, wrong-agent, or unknown-version
tokens are rejected; with no `signingSecret` configured, minting and verifying both
fail closed.

*The honest bound:* a shared secret gives **integrity** across processes within
one trust domain — it proves the token was minted by a holder of the secret and
not altered since. It is **not attestation**: it does not prove *which* process
minted it, and the root grant is rebuilt **from the token**, not from the
receiver's configuration — so a holder of the secret can mint any scope at all,
root included. The token adds no authority beyond what the holder could grant
itself with `scope()`; it gives integrity across processes, not attestation. Keep
the secret out of job payloads and logs, rotate it like any credential, and treat
every process holding it as inside the boundary. Independently attestable scopes
are an Enterprise capability.

**Verify.** Attenuation is a capability check, not a policy verdict, so this
pattern has no `.suite.json`; `check.sh` runs
[`scripts/subagent-confinement.mjs`](./scripts/subagent-confinement.mjs) against
the real engine instead. It asserts the rules above: a child narrower than its
parent is granted and holds exactly the clamped subset (tools and time budget); a
child asking for a tool its parent lacks is refused with `AttenuationDenied`; what
the root never held cannot be granted below it, and a tool a parent dropped cannot
be re-acquired by a grandchild; depth `DE_MAX_DEPTH + 1` raises
`DevEditionCeiling`, not a denial; every grant and refusal lands in the audit
trail as an `attenuation` record carrying tool *names* and depth only; and the
token round-trip holds — a scope minted with `toToken()` in one `Watchlight`
instance is rebuilt by `scopeFromToken()` in another with the same secret and
the same grants, the rebuilt scope still cannot widen, and a tampered, wrong-secret
or expired token is refused with `ScopeTokenError`.

Full guide: [Sub-agent scope attenuation](https://docs.watchlight.ai/de/scope-attenuation).
