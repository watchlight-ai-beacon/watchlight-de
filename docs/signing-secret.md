# The signing secret

Scope tokens and approval tokens are signed. The signing secret is the key that
lets a different process check that signature and trust the token. Set one
whenever a token leaves the process that made it.

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

If you simply replace one value with another, the change takes effect all at
once: every scope token still in circulation, and every approval not yet used,
is refused the moment the new secret goes live. To avoid that, pass a list
instead. The first entry is used to sign new tokens, and every entry in the list
is accepted when checking a token:

```python
# deploy 1 — the new secret goes to the front, the old one stays
govern = Watchlight(agent="my-agent", signing_secret=[NEW, OLD])
```

```ts
const govern = new Watchlight({ agent: "my-agent", signingSecret: [NEW, OLD] });
```

Then wait for the longest lifetime that a token already in flight can have.
For a scope token that is its `ttl_seconds`; for an approval it is its `ttl_ms`,
which is two minutes by default. Once that time has passed, no token signed with
the old secret can still be valid, so deploy again with `[NEW]` alone.

The environment variable takes a comma-separated list, newest first:

```bash
export WATCHLIGHT_SIGNING_SECRET="$NEW,$OLD"
```

**A secret must not contain a comma.** The variable is split on commas, so a
secret containing one would be cut into pieces and only the first piece would
sign. Base64 and hex values never contain a comma.

## The secret is yours

The library runs inside your process. It does no key management of its own,
it cannot tell where a value came from, and it never stores one. Generating the
secret, keeping it safe, and getting it to every process that needs it are your
responsibility.

Here is what the library does with the value you give it:

- It refuses any secret shorter than sixteen bytes when you construct the
  governor. Use thirty-two random bytes, as in the example above.
- It never logs the secret, writes it to the audit trail, or puts it in an error
  message.
- It uses separate keys for scope tokens and for approval tokens. One value
  drives both, but a token of one kind can never be passed off as the other.
- If the secret is missing, it fails closed (refuses) rather than signing with
  something weaker.

## Worth knowing

- With no secret set, minting a scope token raises
  `ScopeTokenError("no_secret")`. Approvals still work inside one process,
  because they fall back to a random key made at startup. Those approvals cannot
  be used in another process, and they do not survive a restart.
- The `approval_secret` option (`approvalSecret` in TypeScript) overrides the
  signing secret for approvals only.
- An empty or whitespace-only value, even a single space, is treated as
  **unset**, not as a weak secret, so a governor still constructs when a `.env`
  placeholder has not been filled in. A value that is set but unusable, such as a lone
  comma, is refused.
- The option used to be called `token_secret` / `tokenSecret`. The old name
  still works and prints a warning once. Setting both names to different values
  is refused.
- A token is **signed, not sealed**: the signature proves it was not altered,
  but it is not encrypted. Its claims (the granted tools, resources, intents and
  time window) can be read by anyone who holds it.
- Anyone holding the secret can mint any token, including a root scope. The
  secret guarantees that tokens passed between your own processes were not
  tampered with. It does not prove which process or person issued a token
  (attestation), and it does not sign the Developer Edition's audit trail.

Enterprise replaces the shared secret with KMS-held keys and signed lineage, so
a token names who issued it and can be verified without the power to mint one.
Getting there is a change of edition rather than a setting, so
[email sales@watchlight.ai](mailto:sales@watchlight.ai?subject=Watchlight%20Enterprise) when you need it.
