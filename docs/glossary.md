# Glossary

Look a word up, or check one before you invent another.

## The four that carry the model

| Term | What it is | Where to read more |
|---|---|---|
| **Governor** | A `Watchlight` answers one question per call: may this subject, through this actor, take this action on this resource? It fails closed, and it governs only the calls you route through it. | [using the governor](using-the-governor.md) |
| **Subject** | The subject is whoever the call runs on behalf of. You pass it as `principal`. | [identity model](identity-model.md) |
| **Actor** | The actor is the runtime that made the call, and a policy reads it as `context.actor`. There is no request field for it. | [identity model](identity-model.md) |
| **Chain** | The chain is how the acting runtime got its authority: the ordered actors, root first, read as `context.actor_chain`. Outside a delegation it is `[agent]`. | [identity model](identity-model.md) |

A governor is not a sandbox — it cannot stop code that never asks. It is not a
verifier — it authorizes the identity your application asserts.

## Easy to confuse

| Pair | One | The other |
|---|---|---|
| **Subject vs actor** | The subject is *for whom* the call runs, and one person can be the subject of calls from many runtimes. | The actor is *who is running*, and one runtime can act for many people. |
| **Renaming vs delegating** | `as("name")` returns another governor under a different name, acting alone. | `delegate(scope, "name")` narrows authority *and* appends to the chain. |
| **Scope vs policy** | A scope is what `delegate` may hand a sub-agent, and it is checked when you delegate. | A policy decides each call. Confining a sub-agent means narrowing the scope *and* writing the policy. |
| **Scope vs goal** | A scope bounds what a delegated agent may *hold*. | A goal bounds what a *run* may do: its actions, its spend, its progress. Goals are Enterprise. |
| **Sanitizing vs screening** | Sanitizing strips personal data out of what leaves. | Screening decides whether what arrives is safe to act on. |
| **Approval token vs scope token** | An approval token records that a human confirmed one action, once. | A scope token carries a sub-agent's narrowed authority. |

## Terms

| Term | What it means | More |
|---|---|---|
| **Action** | The action is the verb of a request, matched as `Action::"book"`. It is what an `intent` names on a governed tool. | |
| **Agent name** | The agent name is what a governor acts under, stamped on every record and read as `context.actor`. An unnamed governor still runs, but it asserts no actor and records `<unconfigured>`. | |
| **Approval store** | An approval store is a shared store you supply, so a used approval token is recorded once across replicas. It needs one method, `add`, which must reserve atomically. | [destructive actions](../examples/patterns/destructive-actions.md) |
| **Approval token** | An approval token is a single-use grant, minted after a person confirms, that turns one `NeedsApproval` into an `Allow` for that subject, action and resource. | [human in the loop](../examples/showcase/human-in-the-loop/README.md) |
| **Attenuation** | Attenuation is narrowing a scope for a sub-agent, strictly to a subset. A child can never hold what its parent lacked. | [sub-agent confinement](../examples/patterns/subagent-confinement.md) |
| **Audit record** | An audit record is one line of the trail: who acted, on whose behalf, the intent, the resource, the verdict, never argument values. The five kinds — `decision`, `sanitization`, `screening`, `egress`, `attenuation` — are discriminated by `event`. | [audit forensics](../examples/showcase/audit-forensics/README.md) |
| **Audit sink** | An audit sink is a destination you supply that receives every record, alongside the local file. | [the audit trail](audit-trail.md) |
| **Audit trail** | The audit trail is the local `.watchlight/audit.jsonl` that every governor appends to. | [the audit trail](audit-trail.md) |
| **Context** | The context is the extra facts a policy may read on a request, such as an amount. `actor` and `actor_chain` are reserved within it. | |
| **Counter** | A counter is a count of past decisions for a subject and a window, and it is what a quota is built from. A **counter source** answers the same query from your durable store instead of the local file. | [quotas](../examples/patterns/quotas.md) |
| **Decision id** | The decision id is the correlation id on a verdict and on every record it produced. Join your own logs and traces to it. | |
| **Delegation** | Delegation is spawning a sub-agent under a narrowed scope, which appends it to the actor chain. The subject does not change. | |
| **Deny reason** | The deny reason is what a refused caller is told: a uniform *not authorized*. The specific reason stays in the trail. | |
| **Detector** | A detector is one rule that finds one kind of identifier in text — email, SSN, card. `sanitize` runs the built-in set, plus any you register for your own vocabulary. | [extending Watchlight](extending.md) |
| **Egress** | An egress record is written when a result leaves a governed call, and it says whether the result was withheld or rewritten. | [data egress](../examples/patterns/data-egress.md) |
| **Enforcement effect** | An enforcement effect is what a matched policy does beyond allow or deny, declared as `@enforcement_effect("<verb>")`. The Developer Edition acts on `require_approval`, and an unrecognised verb fails at load. | [enforcement effects](enforcement-effects.md) |
| **Fail closed** | Failing closed means that no matching policy denies, and that an evaluation which cannot be reached denies too. | |
| **Governed tool** | A governed tool is a function wrapped so the engine authorizes before the body runs. On a Deny the body is never entered. | [denied before execute](../examples/showcase/denied-before-execute/README.md) |
| **Intent** | The intent is the purpose you declare for a governed tool, and the action a policy matches. You declare it; it is never inferred. | |
| **Obligation** | An obligation is a constraint attached to an Allow that the caller must honour, such as redacting named fields. | [allow but redact](../examples/patterns/allow-but-redact.md) |
| **Policy** | A policy is one Cedar rule, `permit` or `forbid`, optionally guarded by a `when` clause over context. A **policy set** is what one governor holds; a **policy suite** is a JSON file of policies *and* their golden tests. | [testing your policies](testing-policies.md) |
| **Principal** | The principal is the field the subject is passed in, and it is always typed: `User::"db:4412"`, `Agent::"flight-booker"`. | |
| **Quarantine** | A quarantine is a policy you flip to stop an agent's next action. | [kill switch](../examples/patterns/kill-switch.md) |
| **Quota** | A quota is a limit on how often something may happen in a window, enforced by reading counters from the trail. | [quotas](../examples/patterns/quotas.md) |
| **Resource** | The resource is what the action is taken on. You choose the string, such as `trip/AX8821`. | |
| **Rotation** | Rotation replaces a signing secret without breaking tokens in flight: pass an ordered list, newest first, then drop the old value one deploy later. | [the signing secret](signing-secret.md) |
| **Sanitization** | Sanitization removes personal data from text before it goes further, and records that it happened. | [PII before read](../examples/patterns/pii-before-read.md) |
| **Scope** | A scope is the authority `delegate` may hand a sub-agent: which tools, resources and intents, and for how long. A **scope token** is its signed carrier between processes, and it does not carry the actor chain. | [sub-agent confinement](../examples/patterns/subagent-confinement.md) |
| **Screening** | Screening decides whether incoming text is safe to act on, and withholds it when it is not. | [screen before model](../examples/patterns/screen-before-model.md) |
| **Screening family** | A screening family is a named category of injection phrasing that `screen` counts — `INSTRUCTION_OVERRIDE`, `ROLE_SWITCH`, and five more. One label covers many phrasings of the same trick, and you can register families of your own. | [extending Watchlight](extending.md) |
| **Signing secret** | The signing secret is what makes a scope token or an approval token verifiable in another of your processes. It is never logged, written, or echoed in an error. | [the signing secret](signing-secret.md) |
| **Verdict** | A verdict is the answer to one call: `Allow`, `Deny`, or `NeedsApproval`. | |
