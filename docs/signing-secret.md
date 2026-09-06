# The signing secret

Scope tokens and approval tokens are signed. The signing secret is what makes
them verifiable in another process. Set one whenever a token leaves the process
that made it.

## Set it

```bash
export WATCHLIGHT_SIGNING_SECRET="$(openssl rand -base64 32)"
```

The governor reads that variable, or takes the value directly:

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

**Every process that exchanges tokens needs the same value.** A web process that
mints a scope token and the worker that rebuilds it are two processes. So are
the process that asks for an approval and the one that acts on it.

## Rotate it in two deploys

Swapping a single value is an immediate cutover: every outstanding scope token
and unconsumed approval is refused the moment the new one goes live. Pass a list
instead. The first entry signs, every entry verifies:

```python
# deploy 1 — the new secret goes to the front, the old one stays
govern = Watchlight(agent="my-agent", signing_secret=[NEW, OLD])
```

```ts
const govern = new Watchlight({ agent: "my-agent", signingSecret: [NEW, OLD] });
```

Then wait out the longest lifetime a token in flight can have — the
`ttl_seconds` of a scope token, or the `ttl_ms` of an approval (two minutes by
default). Then deploy again with `[NEW]`.

The environment variable takes a comma-separated list, newest first:

```bash
export WATCHLIGHT_SIGNING_SECRET="$NEW,$OLD"
```

**A secret must not contain a comma**, or it is split and only the first piece
signs. Base64 and hex values never contain one.

## The secret is yours

The library runs inside your process. It has no key management, cannot tell
where a value came from, and never stores one. Generating it, keeping it, and
getting it to every process that needs it are yours.

What it does with the value you give it:

- refuses anything under sixteen bytes when you construct the governor (use
  thirty-two random bytes, as above);
- never logs it, writes it to the trail, or puts it in an error message;
- keeps scope tokens and approval tokens on separate keys, so one value drives
  both and the two kinds cannot be swapped;
- fails closed when it is missing, rather than signing with something weaker.

## Worth knowing

- With no secret, minting a scope token raises `ScopeTokenError("no_secret")`.
  Approvals still work inside one process, on a random key made at startup, but
  cannot cross to another and do not survive a restart.
- `approval_secret` / `approvalSecret` overrides the signing secret for
  approvals only.
- An empty or whitespace-only value counts as **unset**, not weak, so an
  unfilled `.env` placeholder still constructs. A value that is set but unusable
  (a lone comma, a space) is refused.
- The option used to be `token_secret` / `tokenSecret`. The old name still works
  and warns once; setting both to different values is refused.
- A token is **signed, not sealed**. Its claims — granted tools, resources,
  intents, time window — are readable by anyone holding it.
- Anyone holding the secret can mint any token, including a root scope. It buys
  integrity between your own processes, not attestation, and it does not sign
  the Developer Edition's audit trail.

Enterprise replaces the shared secret with KMS-held keys and signed lineage, so
a token names who issued it and can be verified without the power to mint one.
Getting there is a change of edition rather than a setting, so
[email sales@watchlight.ai](mailto:sales@watchlight.ai?subject=Watchlight%20Enterprise) when you need it.
