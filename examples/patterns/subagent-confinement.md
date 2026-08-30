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

Full guide: [Sub-agent scope attenuation](https://docs.watchlight.ai/de/scope-attenuation).
