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
python approve.py            # 2. a human approves → .watchlight/hitl/grant.json (or: --deny)
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
SDK mints a single-use approval token in-process, re-authorizes, and runs the
body once. The two decision records and how they join:

```
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
records. The example prints A and B and asserts the join.

## Why the approver signs a grant, not the SDK token

The DE's approval tokens (`mint_approval` / `mintApproval`) are HMAC-signed
under a random secret generated when the *process* starts, and used tokens are
remembered in that process's memory. That makes them single-use and
tamper-proof, but also process-local: a token minted by `approve.py` cannot be
verified by `agent.py` (observed in both lanes: the agent answers
`NeedsApproval`, `approved: false`).

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

## Replay behaviour (observed)

| Replay | Result |
|---|---|
| The same grant file presented again after it was consumed | Refused: `grant already used (replay)`. The nonce is recorded in `.watchlight/hitl/consumed.json` on first use; the file is deleted on sight, and a refused grant does **not** open a new pending request. |
| A grant edited after signing (e.g. a different `resource`) | Refused: `signature does not verify`. `resume` exits 1. |
| A grant for a different `(principal, action, resource)` | Refused: `grant is bound to a different request`. |
| The same SDK approval token passed to `authorize` twice | First call `Allow, approved: true`; second call `NeedsApproval`. Single use per mint. |
| An SDK token minted in another process | `NeedsApproval` — the verifying process has a different secret. |
| `resume` with `APPROVER_SECRET` unset | Exits 2 before reading the grant, which stays on disk. |

## Notes

- **Python hook signature.** `on_needs_approval(decision)` receives the decision
  dict only, so `agent.py` binds the resource in a small per-call wrapper and
  hands it to the hook. The TS hook receives `{ intent, resource, principal,
  decisionId }` directly.
- **Files.** `.watchlight/hitl/` holds `pending.json`, `grant.json` and
  `consumed.json`; the audit trail is `.watchlight/audit.jsonl`, next to the
  scripts. Both are ignored by git.
