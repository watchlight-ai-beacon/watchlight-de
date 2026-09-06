# Human in the loop

A governed `delete` holds for a person. The engine answers `NeedsApproval`, a
separate approver signs a grant, and the agent resumes and deletes exactly once
— across two processes.

```bash
cd examples/showcase/human-in-the-loop
export APPROVER_SECRET="$(openssl rand -hex 32)"   # both commands read it from the environment

python agent.py request      # holds: writes a pending request, deletes nothing
python approve.py            # a person approves (or: --deny), signing a grant
python agent.py resume       # grant verified → the delete runs once
```

The Node lane is `node agent.mjs request`, `node approve.mjs`, `node agent.mjs
resume`. Both lanes share the file formats, so a request held by one can be
approved by the other. Every phase exits non-zero on a failed assertion.

## The policy

```cedar
@enforcement_effect("require_approval")
permit(principal, action == Action::"delete", resource);
```

The annotation goes on a **`permit`**. On a `forbid` it is silently a plain
deny and nothing ever asks a person. The verdict becomes `NeedsApproval` instead
of `Allow`, and a person has to release it.

The effect value is checked at load, so a misspelled one raises `PolicyError`
rather than leaving this permit as an unguarded allow. A misspelled annotation
*name* only warns — and that permit does become an unguarded allow.

## What you see

```text
$ python agent.py request
watchlight: APPRV? delete    record/rec-42     approval required
hold:    pending request written to .watchlight/hitl/pending.json; the delete did not run
  {"…", "decision": "NeedsApproval", "decision_id": "22ae936d-…"}
  ✓ the record store never received the delete (deletes=0)

$ python approve.py
pending request
  decision_id  22ae936d-f8a4-46d3-8bfb-55ad063049d9
  principal    records-agent
  action       delete
  resource     record/rec-42
approved — grant written to .watchlight/hitl/grant.json

$ python agent.py resume
resume:  grant verified and consumed — approves pending 22ae936d-…
watchlight: OK✓    delete    record/rec-42
result:  delete #1: record/rec-42 removed
  {"…", "decision": "Allow", "decision_id": "42bc2fb0-…", "approved": true}
join:    grant.pending_decision_id 22ae936d-… → approved decision 42bc2fb0-…
  ✓ the delete ran exactly once (deletes=1)
  ✓ the replayed grant was refused; deletes still 1
```

The approver sees who wants to do what to which resource — never a payload.

## How the two records join

The hold writes record **A** (`NeedsApproval`). The grant carries
`pending_decision_id: A`. On resume the engine evaluates the policy again — the
approval is never assumed — the hook verifies the grant, and the SDK mints a
single-use token that downgrades the verdict. That writes record **B**
(`Allow`, `approved: true`) with the same principal, intent and resource. The
script prints both ids and asserts the join.

## Why the approver signs a grant

The SDK's own approval token is minted and consumed inside one process. This
example configures no signing secret, so a token from `approve.py` would not
verify in `agent.py`. The grant is a separate, signed artifact — bound to one
`pending_decision_id`, five-minute TTL, single use — that crosses the process
boundary instead.

For a real deployment:

- Give both processes a [signing secret](../../../docs/signing-secret.md) and
  the SDK token verifies across them; add an `approval_store` /
  `approvalStore` and single use holds across replicas. Those reservations need
  a TTL of your own — the SDK never deletes one.
- **The HMAC here is symmetric.** Whoever holds `APPROVER_SECRET` can sign a
  grant, the agent included, so the role split is procedural rather than
  cryptographic. Production shape is an asymmetric signature: the approver holds
  the private key, the agent verifies with the public one.

→ [Destructive actions](../../patterns/destructive-actions.md)

## What is refused

| Presented | Result |
|---|---|
| The consumed grant, again | `grant already used (replay)` — the nonce is kept in `consumed.json` |
| A grant edited after signing | `signature does not verify`, exit 1 |
| A valid grant for a request that is not the outstanding one | `grant does not match the outstanding pending request` |
| The SDK's approval token, twice | `Allow` then `NeedsApproval` — single use per mint |
| `resume` with `APPROVER_SECRET` unset | exit 2, before the grant is read |

A refused grant never opens a new pending request, and nothing secret reaches
disk: `pending.json`, `grant.json` and `consumed.json` carry ids and names only.

## Worth knowing

- `consumed.json` grows with every approval and is never pruned. A forgotten
  nonce is a replayable one.
- Python's `on_needs_approval(decision)` hook receives the decision dict only,
  so `agent.py` binds the resource in a small per-call wrapper. The TypeScript
  hook receives `{ intent, resource, principal, decisionId }` directly.
- `watchlight policy test policy.suite.json` runs the fixtures beside the
  policy: the hold, the approved downgrade, and an unlisted action failing
  closed.

Verified by [`check.sh`](./check.sh), which drives request → approve → resume in
each lane and once across the two. Run the files individually and you check
nothing: `agent.py` needs a subcommand, `approve.py` needs a pending request,
and `hitl.py` is a helper module.
