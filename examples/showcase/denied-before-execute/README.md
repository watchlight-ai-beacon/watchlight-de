# Denied before it executed

An agent attempts a money transfer against a stub bank. Policy forbids
transfers above a threshold, so the engine refuses the call **before the tool
body runs** — and the example proves it: the stub's call counter is asserted to
be `0` after the denied attempt and `1` after a permitted one. The script exits
non-zero if either assertion fails.

| File | Purpose |
|---|---|
| [`agent.py`](agent.py) / [`agent.mjs`](agent.mjs) | The governed agent, one per lane. Same policy, same verdicts, same record shape. |
| [`policy.suite.json`](policy.suite.json) | The Cedar policies **and** their golden tests, in one file. The agent loads `policies`; `watchlight policy test` runs `tests`. |

## Run

```bash
# Python
pip install watchlight
python examples/showcase/denied-before-execute/agent.py

# TypeScript
npm i -g @watchlight/sdk            # or, in a clone: cd ts && npm install && npm run build
node examples/showcase/denied-before-execute/agent.mjs

# The policy on its own (either CLI)
watchlight policy test examples/showcase/denied-before-execute/policy.suite.json
```

Both lanes run offline: no API key, no network, no server. The audit trail is
written to `.watchlight/audit.jsonl` next to the scripts.

## What you see

```
stub bank calls at start: 0

attempt: transfer amount=25000 → account/acct-b
watchlight: governing 'payments-agent' (dev mode, in-process engine)
watchlight: DENY   transfer  account/acct-b     not authorized
refused: watchlight denied intent 'transfer' on tool/transfer: not authorized
verdict: Deny    decision_id: 5a8697c3-84a0-4fbd-bb0b-0e7718db7973
audit:   {"ts":"…","agent":"payments-agent","principal":"payments-agent","intent":"transfer","resource":"account/acct-b","decision":"Deny","decision_id":"5a8697c3-…"}
  ✓ verdict is Deny
  ✓ exactly one decision record was written for this call
  ✓ the audit line is value-free (no amount, no arguments)
  ✓ the stub bank never received the call (calls=0)
  ✓ stub bank calls == 0 after the denied transfer

attempt: transfer amount=250 → account/acct-b
watchlight: ALLOW  transfer  account/acct-b
result:  transfer #1 settled to account/acct-b
verdict: Allow    decision_id: f20fb8f3-13a2-417b-9d35-585faf76dc5d
audit:   {"ts":"…","decision":"Allow","decision_id":"f20fb8f3-…"}
  ✓ …
  ✓ stub bank calls == 1 after the allowed transfer

OK — the large transfer was denied before it executed; the small one ran once.
```

## How the never-called assertion works

The "bank" is an in-process object whose `transfer` method does one thing:
increment `calls`. The governed tool is the only path to it:

```python
@govern.tool("transfer",
             resource=lambda to, amount: f"account/{to}",
             context=lambda to, amount: {"amount": amount})
def transfer(to, amount):
    return bank.transfer(to, amount)      # reached only after an Allow
```

`govern.tool` authorizes `(principal, intent, resource, context)` with the
engine before calling the wrapped function. On `Deny` it raises `Denied`
(Python) / throws `Denied` (TS) and the body is never entered — so
`bank.calls` is still `0`. The example does not mock or intercept anything: it
lets the real engine decide and then reads the counter.

## The policy

```cedar
permit(principal, action == Action::"transfer", resource)
when { context.amount <= 1000 };

forbid(principal, action == Action::"transfer", resource)
when { context.amount > 1000 };
```

The `forbid` is the boundary: in Cedar a `forbid` always beats a `permit`, so
no other policy can re-open transfers above the threshold. The suite also checks
the fail-closed cases — a transfer with no `amount` in context and an unlisted
action (`withdraw`) are both `Deny`, because nothing permits them.

## Notes

- **Value-free trail.** The audit line carries who, what, which resource, the
  verdict and a `decision_id` — never the amount or any other argument. The
  example asserts this on the denied line.
- **Join key.** `decision_id` is the id printed on the verdict line and written
  on the record; join it to your own ledger, ticket or trace.
- **Same shape in both lanes.** Python writes `ts` with microseconds and
  spaces after `:`; Node writes millisecond ISO timestamps and compact JSON.
  Fields and values are otherwise identical.
