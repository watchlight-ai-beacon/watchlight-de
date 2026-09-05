# Glossary

One place to look a word up, and one place to check a word before inventing
another. Every entry says what the thing is and what you do with it, and links
to the page that teaches it.

## The four that carry the model

**Governor** — a `Watchlight`. It is a **decision point**: it answers one
question per call, *may this subject, through this actor, take this action on
this resource, under your policies*. It evaluates the policies; it does not run
your agent, intercept its calls, or bound what it can do in general. It governs
exactly the calls you route through it, and it fails closed.

What a governor is *not*: a **sandbox** — it cannot stop code that never asks;
a **verifier** — it authorizes the identities your application asserts; an
**attestation mechanism** — a shared signing secret gives integrity across your
own processes, not proof of who they are.
→ [using the governor](using-the-governor.md), [README](../README.md), [identity model](identity-model.md)

**Subject** — on whose behalf the call runs. You pass it as the `principal`:
`User::"db:4412"` for a person, `Agent::"…"` when the agent acts for itself.
→ [identity model](identity-model.md#what-principal-contains)

**Actor** — which runtime made this particular call. It is the identity of the
governor you called through, read by a policy as `context.actor`; there is no
request field for it.
→ [identity model](identity-model.md#where-the-actor-comes-from)

**Chain** (actor chain) — how the acting runtime got its authority: the ordered
list of actors, root first, read by a policy as `context.actor_chain`. Outside
any delegation it is just `[agent]`.
→ [identity model](identity-model.md#delegating-to-a-sub-agent)

## Easy to confuse

- **Subject versus actor** — the subject is *for whom*, the actor is *who is
  running*. One person can be the subject of calls made by several runtimes, and
  one runtime can act for many people.
- **Renaming versus delegating** — `as("name")` returns another `Watchlight`
  under a different name, acting alone with a fresh single-element chain.
  `delegate(scope, "name")` narrows authority *and* appends to the chain. Rename
  to label; delegate to hand over narrowed authority.
- **Scope versus policy** — a scope is what `delegate` may hand a sub-agent,
  checked when you delegate and only ever narrowing. A policy decides each call
  that is authorized. The scope is not consulted at authorize time, so confining
  a sub-agent means narrowing the scope *and* writing the policy.
- **Sanitizing versus screening** — sanitizing removes personal data from text
  you are about to pass on; screening decides whether text is safe to use at
  all. Sanitize what leaves; screen what arrives.
- **Approval token versus scope token** — an approval token records that a human
  confirmed one specific action, once. A scope token carries a sub-agent's
  narrowed authority. Different lifetimes, different jobs; both are signed with
  the signing secret.

## Terms

**Action** — the verb of a request, matched by a policy as `Action::"book"`.
Same thing an `intent` names on a governed tool.
→ [README](../README.md)

**Actor** — see above.
→ [identity model](identity-model.md#where-the-actor-comes-from)

**Actor chain** — see *chain* above.
→ [identity model](identity-model.md#delegating-to-a-sub-agent)

**Agent name** — the name a governor acts under. It is stamped on every record
and is what a policy reads as `context.actor`.
→ [identity model](identity-model.md#one-engine-many-named-agents)

**Approval token** — a single-use grant, minted after a person confirms, that
turns one `NeedsApproval` verdict into an `Allow`, bound to that subject, action
and resource. With no secret configured it is keyed per process and cannot leave
it; configure a signing secret and it verifies elsewhere, and add an approval
store for single use across replicas.
→ [human in the loop](../examples/showcase/human-in-the-loop/README.md),
[the signing secret](signing-secret.md)

**Approval store** — a shared store you supply so a used approval token is
recorded once for every replica, not once per process. One method, `add`, which
must reserve the id atomically; a store that fails refuses the approval.
→ [destructive actions](../examples/patterns/destructive-actions.md)

**Attenuation** — narrowing a scope for a sub-agent. Strictly a subset: a child
can never hold what its parent lacked.
→ [sub-agent confinement](../examples/patterns/subagent-confinement.md)

**Audit record** — one line of the trail: who acted, through whose delegation,
on whose behalf, the intent, the resource and the verdict. Never argument
values.
→ [audit forensics](../examples/showcase/audit-forensics/README.md)

**Audit sink** — a destination you supply that receives every audit record, in
addition to the local trail file. Use it to ship records to your own logging.
→ [audit sink pattern](../examples/patterns/audit-sink.md)

**Audit trail** — the local `.watchlight/audit.jsonl` file every governor
appends to, and the stream every renamed agent and delegate writes into.
→ [audit forensics](../examples/showcase/audit-forensics/README.md)

**Context** — the extra facts a policy may read on a request, such as an amount
or a document class. `actor` and `actor_chain` are reserved within it.
→ [identity model](identity-model.md#writing-policies-against-them)

**Counter** — a count of past decisions for a subject and a window, read back
from the local trail or from a counter source you configure. What a quota is
built from.
→ [quotas](../examples/patterns/quotas.md)

**Counter source** — the read side of your audit sink: the same count query,
answered by the durable store the sink writes to, so a quota spans every replica
and survives a deploy. Without one, counts come from the local trail file.
→ [quotas](../examples/patterns/quotas.md)

**Decision id** — the correlation id on a verdict and on every record that
verdict produced. Join your own logs, tickets and traces to it.
→ [audit forensics](../examples/showcase/audit-forensics/README.md)

**Delegation** — spawning a sub-agent under a narrowed scope, which also appends
it to the actor chain. The subject does not change.
→ [identity model](identity-model.md#delegating-to-a-sub-agent)

**Deny reason** — what a refused caller is told: a uniform *not authorized*.
The specific reason stays in the trail, never in the refusal.
→ [README](../README.md)

**Egress** — a record written when a result leaves a governed call, including
whether it was withheld or rewritten.
→ [data egress](../examples/patterns/data-egress.md)

**Fail closed** — no matching policy means Deny, and an evaluation that cannot
be reached means Deny. Uncertainty never becomes permission.
→ [README](../README.md)

**Governed tool** — a function wrapped so the engine authorizes the call before
the body runs. On Deny the body is never entered.
→ [denied before execute](../examples/showcase/denied-before-execute/README.md)

**Governor** — see above.
→ [using the governor](using-the-governor.md)

**Intent** — the purpose you declare for a governed tool, and the action a
policy matches. Declared, never inferred from the function's name or body.
→ [README](../README.md)

**Obligation** — a constraint attached to an Allow that the caller must honour,
such as redacting named fields or capping how many items are returned.
→ [allow but redact](../examples/patterns/allow-but-redact.md)

**Policy** — one Cedar rule, `permit` or `forbid`, naming a principal, an action
and a resource, optionally guarded by a `when` clause over context.
→ [identity model](identity-model.md#writing-policies-against-them)

**Policy set** — the policies one governor holds. Load it once; every name that
governor answers to decides against the same set.
→ [using the governor](using-the-governor.md), [identity model](identity-model.md#one-engine-many-named-agents)

**Policy suite** — a JSON file holding policies *and* their golden tests, run by
`watchlight policy test` so a policy change is verified before it gates a real
action.
→ [policy tests in CI](../examples/showcase/policy-tests-ci/README.md)

**Principal** — the field you pass the subject in, always a typed reference:
`User::"db:4412"`, `Agent::"flight-booker"`.
→ [identity model](identity-model.md#what-principal-contains)

**Quarantine** (kill switch) — a policy you can flip to stop an agent's next
action, rather than detecting the problem afterwards.
→ [kill switch](../examples/patterns/kill-switch.md)

**Quota** — a limit on how often something may happen in a window, enforced by
reading counters from the trail.
→ [quotas](../examples/patterns/quotas.md)

**Renaming** — `as("name")` / `as_("name")`, or the per-call `agent` override.
Another `Watchlight` under a different name, backed by the same engine.
→ [identity model](identity-model.md#one-engine-many-named-agents)

**Rotation** — replacing a signing secret without breaking tokens already in
flight: pass an ordered list, newest first, wait out the longest token lifetime,
then drop the old value. Swapping a single value is an immediate cutover.
→ [the signing secret](signing-secret.md)

**Resource** — what the action is being taken on, matched by a policy. A string
you choose, such as `trip/AX8821`.
→ [README](../README.md)

**Sanitization** — removing personal data from text before it goes further, and
recording that it happened.
→ [PII before read](../examples/patterns/pii-before-read.md)

**Scope** — the authority `delegate` may hand a sub-agent: which tools,
resources and intents, and for how long. Checked when you delegate — a child can
only narrow what its parent held — not when a call is authorized.
→ [sub-agent confinement](../examples/patterns/subagent-confinement.md)

**Scope token** — a signed carrier for a narrowed scope, so it can be
re-established in another process. It does not carry the actor chain.
→ [sub-agent confinement](../examples/patterns/subagent-confinement.md)

**Screening** — deciding whether incoming text is safe to act on, and withholding
it when it is not.
→ [screen before model](../examples/patterns/screen-before-model.md)

**Signing secret** (`signing_secret` / `signingSecret`, or
`WATCHLIGHT_SIGNING_SECRET`) — the value that makes a scope token or an approval
token verifiable in another of your processes. Give the same one to every
process that exchanges tokens; it is never logged, written or echoed in an
error. It takes an ordered list for rotation, and `approval_secret` /
`approvalSecret` overrides it for approvals only. The former names
`token_secret` / `tokenSecret` still work and warn once.
→ [the signing secret](signing-secret.md)

**Subject** — see above.
→ [identity model](identity-model.md#what-principal-contains)

**Verdict** — the answer to one call: `Allow`, `Deny`, or `NeedsApproval`.
→ [README](../README.md)
