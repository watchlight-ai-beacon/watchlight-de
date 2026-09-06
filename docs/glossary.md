# Glossary

Look a word up, or check one before you invent another.

## The four that carry the model

- **Governor** — a `Watchlight`. One question per call: *may this subject,
  through this actor, take this action on this resource?* It fails closed, and
  it governs only the calls you route through it.
  → [using the governor](using-the-governor.md)
- **Subject** — on whose behalf the call runs. You pass it as `principal`.
  → [identity model](identity-model.md)
- **Actor** — which runtime made the call. A policy reads it as `context.actor`.
  There is no request field for it.
  → [identity model](identity-model.md)
- **Chain** — how the acting runtime got its authority: the ordered actors, root
  first, read as `context.actor_chain`. Outside a delegation it is `[agent]`.
  → [identity model](identity-model.md)

A governor is not a sandbox — it cannot stop code that never asks. It is not a
verifier — it authorizes the identity your application asserts.

## Easy to confuse

- **Subject vs actor** — *for whom* versus *who is running*. One person can be
  the subject of calls from many runtimes, and one runtime can act for many
  people.
- **Renaming vs delegating** — `as("name")` returns another governor under a
  different name, acting alone. `delegate(scope, "name")` narrows authority
  *and* appends to the chain.
- **Scope vs policy** — a scope is what `delegate` may hand a sub-agent, checked
  when you delegate. A policy decides each call. Confining a sub-agent means
  narrowing the scope *and* writing the policy.
- **Scope vs goal** — a scope bounds what a delegated agent may *hold*. A goal
  bounds what a *run* may do: its actions, its spend, its progress. Goals are
  Enterprise.
- **Sanitizing vs screening** — sanitize what leaves; screen what arrives.
- **Approval token vs scope token** — one records that a human confirmed one
  action, once. The other carries a sub-agent's narrowed authority.

## Terms

**Action** — the verb of a request, matched as `Action::"book"`. The same thing
an `intent` names on a governed tool.

**Agent name** — the name a governor acts under, stamped on every record and
read as `context.actor`. Unnamed, a governor still runs but asserts no actor and
is recorded as `<unconfigured>`.

**Approval store** — a shared store you supply, so a used approval token is
recorded once across replicas. One required method, `add`, which must reserve
atomically.
→ [destructive actions](../examples/patterns/destructive-actions.md)

**Approval token** — a single-use grant, minted after a person confirms, that
turns one `NeedsApproval` into an `Allow` for that subject, action and resource.
→ [human in the loop](../examples/showcase/human-in-the-loop/README.md)

**Attenuation** — narrowing a scope for a sub-agent. Strictly a subset: a child
can never hold what its parent lacked.
→ [sub-agent confinement](../examples/patterns/subagent-confinement.md)

**Audit record** — one line of the trail: who acted, on whose behalf, the intent,
the resource, the verdict. Never argument values. Five kinds — `decision`,
`sanitization`, `screening`, `egress`, `attenuation` — discriminated by `event`.
→ [audit forensics](../examples/showcase/audit-forensics/README.md)

**Audit sink** — a destination you supply that receives every record, alongside
the local file.
→ [the audit trail](audit-trail.md)

**Audit trail** — the local `.watchlight/audit.jsonl` every governor appends to.
→ [the audit trail](audit-trail.md)

**Context** — the extra facts a policy may read on a request, such as an amount.
`actor` and `actor_chain` are reserved within it.

**Counter** — a count of past decisions for a subject and a window. What a quota
is built from. A **counter source** answers the same query from your durable
store instead of the local file.
→ [quotas](../examples/patterns/quotas.md)

**Decision id** — the correlation id on a verdict and on every record it
produced. Join your own logs and traces to it.

**Delegation** — spawning a sub-agent under a narrowed scope, which appends it
to the actor chain. The subject does not change.

**Deny reason** — what a refused caller is told: a uniform *not authorized*. The
specific reason stays in the trail.

**Egress** — a record written when a result leaves a governed call, including
whether it was withheld or rewritten.
→ [data egress](../examples/patterns/data-egress.md)

**Enforcement effect** — what a matched policy does beyond allow or deny,
declared as `@enforcement_effect("<verb>")`. The Developer Edition acts on
`require_approval`. An unrecognised verb fails at load.
→ [testing your policies](testing-policies.md)

**Fail closed** — no matching policy means Deny, and an evaluation that cannot
be reached means Deny.

**Governed tool** — a function wrapped so the engine authorizes before the body
runs. On Deny the body is never entered.
→ [denied before execute](../examples/showcase/denied-before-execute/README.md)

**Intent** — the purpose you declare for a governed tool, and the action a policy
matches. Declared, never inferred.

**Obligation** — a constraint attached to an Allow that the caller must honour,
such as redacting named fields.
→ [allow but redact](../examples/patterns/allow-but-redact.md)

**Policy** — one Cedar rule, `permit` or `forbid`, optionally guarded by a `when`
clause over context. A **policy set** is what one governor holds; a **policy
suite** is a JSON file of policies *and* their golden tests.
→ [testing your policies](testing-policies.md)

**Principal** — the field the subject is passed in, always typed:
`User::"db:4412"`, `Agent::"flight-booker"`.

**Quarantine** — a policy you flip to stop an agent's next action.
→ [kill switch](../examples/patterns/kill-switch.md)

**Quota** — a limit on how often something may happen in a window, enforced by
reading counters from the trail.
→ [quotas](../examples/patterns/quotas.md)

**Resource** — what the action is taken on. A string you choose, such as
`trip/AX8821`.

**Rotation** — replacing a signing secret without breaking tokens in flight: an
ordered list, newest first, then drop the old value one deploy later.
→ [the signing secret](signing-secret.md)

**Sanitization** — removing personal data from text before it goes further, and
recording that it happened.
→ [PII before read](../examples/patterns/pii-before-read.md)

**Scope** — the authority `delegate` may hand a sub-agent: which tools,
resources and intents, and for how long. A **scope token** is its signed carrier
between processes; it does not carry the actor chain.
→ [sub-agent confinement](../examples/patterns/subagent-confinement.md)

**Screening** — deciding whether incoming text is safe to act on, and
withholding it when it is not.
→ [screen before model](../examples/patterns/screen-before-model.md)

**Signing secret** — the value that makes a scope token or an approval token
verifiable in another of your processes. Never logged, written, or echoed in an
error.
→ [the signing secret](signing-secret.md)

**Verdict** — the answer to one call: `Allow`, `Deny`, or `NeedsApproval`.
