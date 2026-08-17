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

| Capability | Developer Edition (free / open) | Enterprise |
|---|---|---|
| Policy engine | in-process Cedar, policies from a local `.cedar` file | a running, scaled policy service |
| Sub-agent scope attenuation | engine-side strict-subset validation | same, server-side |
| Content / PII screening | policy-based, in-process | a running guardrails service |
| Audit | local JSONL, greppable, value-free | a signed, tamper-evident audit service |
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

## Developer Edition vs Enterprise

The Developer Edition is the **real engine** — free, open, and running
in-process so you can evaluate the entire authorization model on your laptop
with zero infrastructure. Enterprise is the **same code** pointed at the
governed control plane; it doesn't replace anything, it adds what a fleet in
production needs:

- **Signed, tamper-evident lineage & audit** — every decision and lineage event
  cryptographically signed (KMS-backed), so the trail is court-defensible.
- **Multi-tenant isolation + roll-up administration** — tenant hierarchy, scoped
  admins, and a cross-tenant authorization matrix.
- **Drift & anomaly detection → automatic quarantine** — behavioural,
  goal-drift, and argument-shape detectors that quarantine a misbehaving agent
  *before* the next action.
- **Full enforcement-effect taxonomy** — beyond allow/deny: block, terminate,
  quarantine, sever-subtree, and revoke, enforced at runtime across the plane.
- **Fleet-wide revocation & cross-environment governance** — revoke authority
  across every agent at once, and govern dev, staging, and prod under one
  authority model (including **sovereign / air-gapped deployment**).
- **Content / PII guardrails service** and **global execution-graph lineage**
  with the full **operator console**.
- **SSO / RBAC / enterprise audit**, high availability, support, and SLAs.

### You've outgrown the Developer Edition when…

- Compliance asks *"prove who authorized this in production"* → you need
  **signed, tamper-evident lineage**.
- You're governing **more than one agent, or more than one environment** →
  central policy lifecycle + the **global execution graph**.
- Security wants a misbehaving agent **stopped before its next action** →
  **drift/anomaly detection → automatic quarantine**.
- You need to **revoke authority fleet-wide**, not process-by-process.
- Procurement needs **SSO, RBAC, HA, SLAs, or sovereign/air-gapped deployment**.

Each of these is a governance guarantee a single in-process engine structurally
cannot provide — it needs the control plane.

**Migrating is one environment variable — never a rewrite.** The tools you
decorate, the policies you write, and the guarantees you rely on
(fail-closed, engine-side attenuation, explicit scopes, value-free audit) are
identical in every mode. Enterprise simply points the same code at a running
plane.

> The engine ships as a compiled wheel and the Developer Edition is a deliberate
> *subset* of the platform — the governed control plane (signing, multi-tenant,
> guardrails, drift, execution-graph) is the enterprise product, never bundled
> here.

→ **[Talk to us about Enterprise](mailto:enterprise@watchlight.ai)** when you're
ready for production.

---

## License

TBD — see [`docs/DECISIONS.md`](docs/DECISIONS.md).
