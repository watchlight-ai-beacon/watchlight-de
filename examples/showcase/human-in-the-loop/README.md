# Human in the loop, end to end

A governed `delete` whose permit is annotated `@enforcement_effect("require_approval")`.
The engine answers **NeedsApproval** instead of Allow; the agent pauses and
writes a pending request; a separate command-line approver signs a grant for
exactly that request; the agent resumes, the approval is recorded, and the
delete runs **once**. The example then tries to replay the grant and to replay
the SDK's approval token, and asserts both are refused.

| File | Purpose |
|---|---|
| [`agent.py`](agent.py) / [`agent.mjs`](agent.mjs) | The governed agent: `request` holds, `resume` completes and runs the replay checks. |
| [`approve.py`](approve.py) / [`approve.mjs`](approve.mjs) | The out-of-band approver. Shows the pending request, signs a grant (`--deny` refuses it). |
| [`hitl.py`](hitl.py) / [`hitl.mjs`](hitl.mjs) | Shared helpers: pending/grant file formats, HMAC, audit-trail lookups. Same format in both lanes. |
| [`policy.suite.json`](policy.suite.json) | The Cedar policy **and** its golden tests (`NeedsApproval`, `approved → Allow`, unlisted → `Deny`). |

## Run

```bash
pip install watchlight                        # or: npm i -g @watchlight/sdk
cd examples/showcase/human-in-the-loop
export APPROVER_SECRET="$(openssl rand -hex 32)"   # shared by approver and agent, via env only

python agent.py request      # 1. NeedsApproval → .watchlight/hitl/pending.json; nothing deleted
python approve.py            # 2. a human approves → .watchlight/hitl/grant.json (or: --deny); pending.json stays
python agent.py resume       # 3. grant verified → approved decision → delete runs once; replays refused
```

The Node lane is `node agent.mjs request`, `node approve.mjs`, `node agent.mjs resume`.
The two lanes share file formats, so a request held by one can be approved by
the other. Every phase exits non-zero on a failed assertion. The policy on its own:

```bash
watchlight policy test examples/showcase/human-in-the-loop/policy.suite.json
```

## What you see

**request** — the hook writes the pending request and returns `false`; the
SDK raises `NeedsApproval`; the store's `deletes` is still `0`:

```
attempt: delete record/rec-42
watchlight: governing 'records-agent' (dev mode, in-process engine)
watchlight: APPRV? delete    record/rec-42     approval required
hold:    pending request written to .watchlight/hitl/pending.json; the delete did not run
held:    watchlight requires human approval for intent 'delete' on tool/delete
pending decision record:
  {"…","intent":"delete","resource":"record/rec-42","decision":"NeedsApproval","decision_id":"bbbd176c-…"}
  ✓ the record store never received the delete (deletes=0)
```

**approve** — the human sees only the identity of the request, never a payload:

```
pending request
  decision_id  bbbd176c-80e4-4966-8b88-d42ab06ffb4b
  principal    records-agent
  action       delete
  resource     record/rec-42

approved — grant written to .watchlight/hitl/grant.json
  bound to            records-agent / delete / record/rec-42
  valid for           300s, single use
```

**resume** — the hook verifies and consumes the grant and returns `true`; the
SDK mints a single-use approval token — here in-process, since this example
configures no secret — re-authorizes, and runs the body once. The two decision records and how they join:

```
attempt: delete record/rec-42 (grant on disk for pending bbbd176c-…)
watchlight: governing 'records-agent' (dev mode, in-process engine)
watchlight: APPRV? delete    record/rec-42     approval required
resume:  grant verified and consumed — approves pending bbbd176c-…
watchlight: OK✓    delete    record/rec-42
result:  delete #1: record/rec-42 removed

pending decision record (written by 'request'):
  {"…","decision":"NeedsApproval","decision_id":"bbbd176c-80e4-4966-8b88-d42ab06ffb4b"}
approved decision record (written now):
  {"…","decision":"Allow","decision_id":"969d5421-7f0e-458f-b437-a9dbc9e4b319","approved":true}
join:    grant.pending_decision_id bbbd176c-… → approved decision 969d5421-…
  ✓ the delete ran exactly once (deletes=1)
  ✓ both records name the same principal, intent and resource
  ✓ the resume re-evaluated the policy (a fresh hold) before applying the approval

replay: presenting the consumed grant again
refused: grant already used (replay); the delete did not run
  ✓ the replayed grant was refused; deletes still 1

replay: presenting a signed grant for a request that is not the outstanding one
refused: grant does not match the outstanding pending request; the delete did not run
  ✓ the grant for a non-outstanding request was refused; deletes still 1

replay: presenting the same SDK approval token twice (probe resource)
  ✓ a fresh token downgrades NeedsApproval to Allow once
  ✓ the same token presented again is refused (single use)
```

## How the records join

The pending record (`decision: NeedsApproval`, id **A**) is written when the
agent first asks. The grant carries `pending_decision_id: A`. When the agent
resumes, the SDK evaluates the policy again (a second `NeedsApproval` hold is
recorded — the approval is never assumed), calls the hook, mints the token, and
re-authorizes; the resulting record is `decision: Allow, approved: true` with a
new id **B**. So the chain is: record **A** ← grant(`pending_decision_id` = A) →
record **B**, with the same `principal`, `intent` and `resource` on both
records. The example prints A and B and asserts the join. The grant is accepted
only if A is the request currently outstanding in `pending.json`; on success
the agent removes `pending.json` and `grant.json` together.

## Why the approver signs a grant, not the SDK token — and what that does not give you

The DE's approval tokens (`mint_approval` / `mintApproval`) are HMAC-signed and
recorded as used, which makes them single-use and tamper-proof. **This example
configures no secret and no store**, so both defaults apply: the signing key is
random per process and the used-token record is that process's memory. A token
minted by `approve.py` therefore cannot be verified by `agent.py` (observed in
both lanes: the agent answers `NeedsApproval`, `approved: false`).

Configure a [signing secret](../../../docs/signing-secret.md) — or an
`approval_secret` / `approvalSecret` — and a token does verify in another
process; add an `approval_store` / `approvalStore` over a shared store and
single use holds across replicas too. Expiry of those reservations is the
store's own job — the SDK never deletes one — so give the row a TTL or implement
the optional `prune(before)`; see
[destructive actions](../../patterns/destructive-actions.md). The grant below is what this example uses
*instead*, and it stays useful either way: it is signed by the approver, so the
agent can tell an approval apart from anything it could have minted itself.

The example therefore separates the two roles:

- the **approver** signs a *grant* — `{pending_decision_id, principal, action,
  resource, exp, nonce, sig}`, HMAC-SHA256 under `$APPROVER_SECRET`, bound to
  one request, five-minute TTL;
- the **agent's hook** verifies the grant (signature, binding, expiry, nonce
  not yet consumed) and returns `true`; the **SDK** then mints and consumes its
  own token inline, which is what actually downgrades `NeedsApproval` to `Allow`.

Nothing secret is ever written to disk: the pending request and the grant carry
ids and names only; the secret lives in the environment of the two processes.
`APPROVER_SECRET` must be at least 16 characters — generate a fresh one per
session with `openssl rand -hex 32`; any placeholder such as
`replace-me-with-a-random-secret` works for a local walk-through.

**The HMAC is symmetric.** The agent process verifies the grant with the same
`APPROVER_SECRET` the approver signs with, so whoever holds the secret — the
agent included — can sign a grant for anything. The approver/agent role
separation in this example is procedural (two commands, one secret), not
cryptographic; the example itself demonstrates this by signing a grant from
inside the agent for a request that is not the outstanding one (refused on a
different check, not on the signature). The production shape is an asymmetric signature: the approver
holds a private key and the agent verifies with the public key, so the agent can
check approvals it could never mint. That is not implemented here.

## Replay behaviour (observed)

| Replay | Result |
|---|---|
| The same grant file presented again after it was consumed | Refused: `grant already used (replay)`. The nonce is recorded in `.watchlight/hitl/consumed.json` on first use; the file is deleted on sight, and a refused grant does **not** open a new pending request. |
| A grant edited after signing (e.g. a different `resource`) | Refused: `signature does not verify`. `resume` exits 1. |
| A correctly signed grant for a request that is not the outstanding one (e.g. approved for an earlier request, planted for a later one with the same principal/action/resource) | Refused: `grant does not match the outstanding pending request`. The agent compares `pending_decision_id`, principal, action and resource against the `pending.json` it wrote itself; `approve` leaves that file in place and the agent removes it only when a grant is consumed. |
| A grant for a different `(principal, action, resource)` | Refused: `grant is bound to a different request`. |
| The same SDK approval token passed to `authorize` twice | First call `Allow, approved: true`; second call `NeedsApproval`. Single use per mint. |
| An SDK token minted in another process | `NeedsApproval` — with no signing secret configured (as here) each process has its own random key. Configure one and it verifies. |
| `resume` with `APPROVER_SECRET` unset | Exits 2 before reading the grant, which stays on disk. |

## Notes

- **Python hook signature.** `on_needs_approval(decision)` receives the decision
  dict only, so `agent.py` binds the resource in a small per-call wrapper and
  hands it to the hook. The TS hook receives `{ intent, resource, principal,
  decisionId }` directly.
- **Files.** `.watchlight/hitl/` holds `pending.json`, `grant.json` and
  `consumed.json`; the audit trail is `.watchlight/audit.jsonl`, next to the
  scripts. Both are ignored by git. `consumed.json` (used grant nonces) grows
  with every approval and is never reset by design — a nonce forgotten is a
  nonce replayable; `request` clears only `pending.json` and `grant.json`.
