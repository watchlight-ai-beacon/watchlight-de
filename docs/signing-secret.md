# The signing secret

A **scope token** carries an attenuated scope from one process to another. An
**approval token** carries a human's confirmation from the process that asked to
the process that acts. Both are signed, and the signing secret is what makes them
verifiable on the other side.

Set one whenever a token has to leave the process that made it.

## Set it

Generate thirty-two random bytes, once, and keep the value:

```bash
openssl rand -base64 32
```

Give it to the governor:

```python
import os
from watchlight import Watchlight

govern = Watchlight(agent="my-agent", signing_secret=os.environ["WATCHLIGHT_SIGNING_SECRET"])
```

```ts
import { Watchlight } from "@watchlight/sdk";

const govern = new Watchlight({
  agent: "my-agent",
  signingSecret: process.env.WATCHLIGHT_SIGNING_SECRET,
});
```

Or set `WATCHLIGHT_SIGNING_SECRET` in the environment and pass nothing — the
governor reads it:

```bash
export WATCHLIGHT_SIGNING_SECRET="$(openssl rand -base64 32)"
```

**Every process that exchanges tokens needs the same value.** A web process that
mints a scope token and a worker that rebuilds it are two processes; so are the
process that mints an approval and the one that consumes it. Different values, or
a value in one and none in the other, and the token does not verify.

Minimum thirty-two bytes is a good default; anything under sixteen is refused
when you construct the governor.

> **Renamed.** This option used to be called `tokenSecret` / `token_secret`
> (`WATCHLIGHT_TOKEN_SECRET`). The old name still works and warns once; setting
> both to different values is refused rather than resolved silently.

## What it signs

| | Signed with |
|---|---|
| Scope tokens — `scope.to_token()` / `govern.scope_from_token()` | the signing secret |
| Approval tokens — `govern.mint_approval()` | the signing secret, unless `approval_secret` / `approvalSecret` is set, which then takes over for approvals only |

One value covers both. The two kinds of token cannot be swapped for each other.

## When it is missing

Minting and verifying a scope token fail closed — there is no built-in default
and nothing weaker to fall back to:

```python
govern = Watchlight(agent="my-agent")            # no secret
govern.scope(tools=["read"]).to_token()          # ScopeTokenError: no_secret
```

Approvals still work *within* one process (they fall back to a random key that
process makes at startup), but a token cannot cross to another process and a
restart invalidates every approval still outstanding.

## When it changes

Every token signed with the old value stops verifying. Scope tokens fail with
`ScopeTokenError("signature")`; approvals stay held with the usual
`approval required`.

Rotate in **two deploys** instead, by passing a list — the first entry signs,
every entry verifies:

```python
# deploy 1: the new secret goes to the FRONT, the old one stays
govern = Watchlight(agent="my-agent", signing_secret=[NEW, OLD])
```

```ts
// deploy 1
const govern = new Watchlight({ agent: "my-agent", signingSecret: [NEW, OLD] });
```

Now wait. Tokens signed with the old secret are still being presented until the
last of them expires, so wait out **the longest lifetime any token in flight can
have** — the `ttl_seconds` you pass to `to_token()` (which cannot exceed the
scope's remaining time budget), and the `ttl_ms` of an approval (two minutes by
default). Then:

```python
# deploy 2: the old secret is gone
govern = Watchlight(agent="my-agent", signing_secret=[NEW])
```

The environment variable takes a list too, separated by commas, newest first:

```bash
export WATCHLIGHT_SIGNING_SECRET="$NEW,$OLD"
```

**A secret must not contain a comma.** In the environment variable a comma
separates entries, so a value containing one is split into pieces and only the
first piece signs. Base64 and hex values — what `openssl rand` above produces —
never contain one. A variable that is set but holds no usable secret (a lone
comma, a space) is refused when you construct the governor rather than treated
as unset.

Rotating a single value is an immediate cutover: the moment the new one is live,
every outstanding scope token and every unconsumed approval is refused. That is
the failure the list exists to avoid.

## It is yours, not ours

The library runs inside your process. It has no key management, cannot tell
where a value came from, and never stores one. Generating the secret, keeping it,
and getting it to every process that needs it are yours — the same way the
acting principal is yours to supply (see the
[identity model](./identity-model.md)).

What the library does with the value it is given:

- refuses one that is too short, when you construct the governor;
- never logs it, never writes it to the audit trail, and never puts it in an
  error message;
- keeps scope tokens and approval tokens on separate keys, so one value can drive
  both;
- fails closed when it is missing, rather than signing with something weaker.

## What it is not

- **Not encryption.** A token is signed, not sealed. Its claims — the granted
  tools, resources, intents and the time window — are readable by anyone holding
  the token. Do not put anything confidential in a scope.
- **Not the audit trail's signature.** The Developer Edition's trail is a plain
  local file; this secret does not sign it.
- **Not the engine's identity, and not attestation.** It says a token was made by
  someone holding the secret — not by which agent, on which host, or under whose
  authority.
- **Not authority.** Anyone holding the secret can mint any token, including a
  root scope. A scope token adds no authority beyond what its holder could grant
  itself. The secret buys integrity between processes inside **one trust domain**
  — it is not a way to extend trust to a party you do not already trust.

Enterprise replaces the shared secret with KMS-held keys and signed lineage, so
a token names who issued it and can be verified without holding the power to
mint one.
