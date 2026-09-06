# Denied before it executed

An agent tries to move 25,000 through a stub bank. The engine refuses the call
before the tool body runs, and the bank's call counter proves it.

```bash
python agent.py          # or: node agent.mjs
```

No API key, no network, no server. Records land in `.watchlight/audit.jsonl`
next to the script.

## What you see

```text
attempt: transfer amount=25000 → account/acct-b
watchlight: DENY   transfer  account/acct-b     not authorized
refused: watchlight denied intent 'transfer' on tool/transfer: not authorized
verdict: Deny    decision_id: 484612a5-…
audit:   {"ts": "…", "agent": "payments-agent", "principal": "Agent::\"payments-agent\"", "intent": "transfer", "resource": "account/acct-b", "decision": "Deny", "decision_id": "484612a5-…"}
  ✓ the stub bank never received the call (calls=0)

attempt: transfer amount=250 → account/acct-b
watchlight: ALLOW  transfer  account/acct-b
result:  transfer #1 settled to account/acct-b
  ✓ the stub bank received the call exactly once (calls=1)

OK — the large transfer was denied before it executed; the small one ran once.
```

The script exits non-zero if a counter ever contradicts a verdict.

## Why the counter is the proof

```python
@govern.tool("transfer",
             resource=lambda to, amount: f"account/{to}",
             context=lambda to, amount: {"amount": amount})
def transfer(to, amount):
    return bank.transfer(to, amount)      # reached only after an Allow
```

`bank.transfer` is the only thing that moves the counter, and the governed tool
is the only path to it. The decorator authorizes first and raises `Denied` on a
deny, so the body is never entered. Nothing is mocked or intercepted: the real
engine decides, then the script reads the counter.

## The policy

```cedar
permit(principal, action == Action::"transfer", resource)
when { context.amount <= 1000 };

forbid(principal, action == Action::"transfer", resource)
when { context.amount > 1000 };
```

A Cedar `forbid` always beats a `permit`, so no later policy can re-open large
transfers. [`policy.suite.json`](policy.suite.json) holds these policies and
their golden fixtures in one file — the agent loads the policies, and
`watchlight policy test policy.suite.json` runs the fixtures. The fixtures pin
the fail-closed cases too: a transfer with no `amount` and an unlisted action
are both `Deny`, because nothing permits them.

## Worth knowing

- The audit line carries who, what, which resource and the verdict — never the
  amount. The script asserts that.
- `decision_id` joins the record to your own ledger, ticket or trace.
- The principal is `Agent::"payments-agent"`. No subject was passed, so the call
  is the agent's own. → [The identity model](../../../docs/identity-model.md)

Verified by [`check.sh`](./check.sh), which runs both lanes from a clean
`.watchlight`.
