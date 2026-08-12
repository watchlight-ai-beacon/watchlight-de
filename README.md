# Watchlight — Developer Edition

**Govern an AI agent in five minutes. One install, zero infrastructure, same API as production.**

Watchlight puts a policy decision point in front of every action your AI agents
take — authorizing tool calls, attenuating sub-agent authority to a strict
subset, and recording a tamper-evident, value-free audit trail. The Developer
Edition runs that *entire* authorization model **in-process**, so you can see it
work in your own terminal with no server, no database, and no signup.

The code you write here is the code you ship to production. Going to production
is pointing at a running policy service — not a rewrite.

---

## Quickstart

> **Status: in active development.** The target experience is below; see
> [`docs/DECISIONS.md`](docs/DECISIONS.md) for what's being built now.

```bash
pip install watchlight
```

```python
from watchlight import govern

@govern.tool(intent="research")
def web_search(query: str) -> str:
    ...

@govern.tool(intent="transfer")           # governed, but no policy permits it
def transfer_funds(to: str, amount: int) -> str:
    ...
```

```text
$ python agent.py
watchlight: governing 'my-agent' (dev mode, in-process engine)
watchlight: ALLOW  read     tool/web_search
watchlight: DENY   execute  tool/transfer_funds     no matching policy
```

**That `DENY` line — in your own terminal, in under five minutes, with no
account — is the product.**

---

## What runs locally

| Capability | Developer Edition | In production |
|---|---|---|
| Policy engine | in-process Cedar, policies from a local `.cedar` file | a running policy service |
| Sub-agent scope attenuation | engine-side strict-subset validation | same, server-side |
| Content / PII screening | in-process evaluation of the same policy format | a running guardrails service |
| Audit | local JSONL, greppable, value-free | a signed audit service |
| Dashboard | `watchlight dev` → `localhost:7000` (policies + execution lineage) | the full operator console |

Everything the Developer Edition removes is **infrastructure**, never a
**guarantee**. Fail-closed semantics, engine-side attenuation, explicit scopes,
and value-free audit are identical in every mode.

---

## Progressive disclosure

Each level is one environment variable away from the next. **Nothing is
rewritten between levels.**

- **Level 0** — `pip install watchlight`. In-process engine, audit to stdout.
- **Level 1** — `watchlight dev`. Adds a local dashboard (decisions, denials, scope tree, execution lineage).
- **Level 2** — `docker compose up`. Real policy service + database; policies still from your local file.
- **Level 3** — Production. The full governed platform.

---

## License

TBD — see [`docs/DECISIONS.md`](docs/DECISIONS.md).
