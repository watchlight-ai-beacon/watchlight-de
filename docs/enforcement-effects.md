# Enforcement effects

A Cedar decision is binary. Real governance sometimes needs a third answer:
*hold this one for a person*. An **enforcement effect** is an annotation on a
policy that says so, and Watchlight adds it without forking Cedar.

```cedar
@enforcement_effect("require_approval")
permit(principal, action == Action::"wire", resource)
when { context.amount > 1000 };
```

A matching `permit` annotated `require_approval` returns **`NeedsApproval`**
instead of `Allow`. The action does not run, and it is not denied either — your
app holds it for a human.

## Handle the hold

```python
from watchlight import govern, NeedsApproval

@govern.tool(intent="wire", context=lambda **kw: {"amount": kw["amount"]})
def wire_funds(to, amount):
    ...

try:
    wire_funds(to="acme", amount=5000)
except NeedsApproval as hold:
    queue_for_review(hold.decision_id)      # the body never ran
```

The `context` callable is what carries `amount` into the `when` clause. Leave it
out and the guard cannot be evaluated, so the call denies rather than holding.

A person approves it, you mint a single-use approval token for exactly that
subject, action and resource, and the retry allows once. The full flow — the
hold, a separate approver process, and replay being refused — is
[`examples/showcase/human-in-the-loop/`](../examples/showcase/human-in-the-loop/README.md).

A token has to be verifiable in whichever process acts on it, so set a
[signing secret](signing-secret.md) as soon as approving and acting are two
processes.

## The accepted verbs

The engine accepts `attenuate`, `escalate`, `observe`, `quarantine`,
`require_approval`, `revoke`, `sever_subtree` and `terminate`. The engine holds
this list; the SDK keeps no copy of it, so a new verb never needs an SDK
change.

Two combinations change the verdict your code receives here:

| Policy | Annotation | Instead of | You get |
|---|---|---|---|
| `permit` | `require_approval` | `Allow` | `NeedsApproval` |
| `forbid` | `observe` | `Deny` | whatever the rest of the set decides |

Every other pairing leaves the verdict alone: an annotated `forbid` still
denies, and an annotated `permit` still allows. Both of the combinations in the
table are explained in the sections below, and you can assert either one in a
test.

## What containment does and does not do here

The containment verbs are `quarantine`, `revoke`, `sever_subtree` and
`terminate`. A policy carrying one loads, evaluates, and **denies** — the call
is refused exactly as an unannotated `forbid` refuses it.

What does not happen is the containment action itself: freezing the agent,
ending the run, collapsing a sub-agent tree, or withdrawing trust across a
fleet. Each of those changes state outside this process, so each needs the
governed control plane. `escalate` has the same shape — the deny lands here, and
the out-of-band alert is the part the plane sends.

So in the Developer Edition these effects **demonstrate the capability**. You
write the policy, watch the verdict change, and test it against the same engine
Enterprise runs. Real-time enforcement is the Enterprise edition, where the
containment action fires as well as the deny.

Real-time containment across a fleet is the Enterprise plane —
[talk to us about Enterprise](mailto:sales@watchlight.ai). See [DE vs
Enterprise](https://docs.watchlight.ai/de/comparison) for what else the control plane adds.

## Monitor mode

A `forbid` annotated `observe` does not deny. The rest of the policy set decides
instead, so a rule you are still evaluating cannot break a caller.

```cedar
@enforcement_effect("observe")
forbid(principal, action == Action::"wire", resource)
when { context.amount > 1000 };
```

With a permit already covering the action, that returns `Allow` where the
unannotated rule would have returned `Deny`. Delete the annotation to turn the
rule on.

Cedar still default-denies underneath, so `observe` is not an allow of its own.
If no permit matches the action, the decision stays `Deny`.

The audit trail records the `Allow` that was returned. It does not mark which
observed rule would otherwise have denied, so keep the rule under test until you
are ready to enforce it.

## An unrecognised verb, or a misspelled name, fails at load

```text
PolicyError: policy "wire-approval": @enforcement_effect("needs_approval") is not
an effect this engine implements (accepted: attenuate, escalate, observe,
quarantine, require_approval, revoke, sever_subtree, terminate); on a permit an
unimplemented effect would leave a plain allow, so the policy is refused
```

A verb the engine does not implement used to have *no effect at all*. On a
`forbid` that is harmless, because the deny stands. On a **`permit` it is
fail-open**: dropping `require_approval` leaves a plain allow, so one mistyped
character turns an approval gate into an unconditional permit. A misspelled
annotation **name** (`@enforcment_effect`, `@Enforcement_Effect`) did the same,
because Cedar accepts any annotation name.

The engine (`watchlight-engine` 0.2.3 and later) now refuses both when the
policy is added, and the SDK raises `PolicyError`, the same type in the Python
and TypeScript SDKs. Its `code` says which:

| `code` | Meaning |
|---|---|
| `UNRECOGNISED_ENFORCEMENT_EFFECT` | The value is not one the engine implements. Case and spaces count, and an empty value is refused. |
| `ENFORCEMENT_EFFECT_NAME_NEAR_MISS` | The annotation name is within two edits of `enforcement_effect` (ignoring case) but is not that name. |

An annotation name further away, such as `@owner` or `@enforcement_action`, is
your own and loads. The same text inside a Cedar string or a `//` comment is not
an annotation.

In Python, `govern.allow()`, `govern.load()` and `govern.reload()` raise at once,
and nothing from the refused call is added: `load` adds none of the file and
does not remember the source, and `reload` keeps the set it had. In TypeScript
the engine compiles asynchronously, so the refusal surfaces at `govern.ready()`
or the next decision, as a compile error does, and every decision throws it
until a `reload` with a set that loads. `watchlight policy test` exits with
status 2 and prints the message.

## Fail-closed still wins

If an annotated policy **cannot be evaluated** — it reads a `context` key the
caller omitted — the engine denies rather than falling through to the approval
path. Write `when { context has amount && context.amount > 1000 }`, or keep the
guard unconditional.

## Next

- **[How policy works](policies.md)** — the Cedar model these annotations sit
  on.
- **[Testing your policies](testing-policies.md)** — asserting a `NeedsApproval` and its
  approved downgrade in a fixture.
