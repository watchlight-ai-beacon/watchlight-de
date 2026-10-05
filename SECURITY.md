# Security policy

## Reporting a vulnerability

Please report security issues **privately**. Do not open a public issue or pull
request.

- **On GitHub:** use [Report a vulnerability](https://github.com/watchlight-ai-beacon/watchlight-de/security/advisories/new)
  on this repository's Security tab.
- **By email:** security@watchlight.ai

Include a minimal reproduction where you can. **Do not include secrets, tokens
or private data.** Watchlight's audit trail is value-free by design, so a
reproduction never needs them.

## What happens next

- We acknowledge your report within **2 business days**.
- We give you an initial assessment within **5 business days**.
- We fix accepted issues and publish a GitHub Security Advisory, with a CVE
  where appropriate, when the fixed release is out.
- We aim to release a fix within **7 days** for critical issues, **30 days** for
  high and **90 days** for the rest.
- We disclose no later than **90 days** after we accept a report, unless we
  agree a different date with you.
- We credit reporters who want to be credited.

## Scope

Every package published from this repository:

- `watchlight` (PyPI);
- `@watchlight/sdk` (npm);
- the examples.

The authorization engine (`watchlight-engine` and `@watchlight/engine`) and the
MCP runtime (`watchlight-mcp`) ship as compiled packages. Vulnerabilities in
them are equally in scope; report them the same way.

Reports about Watchlight Cloud or Watchlight AI Beacon are welcome at the same
address.

## Supported versions

We fix the latest minor release of each package. Upgrade to the newest release
to receive security fixes, and please check that the issue still occurs there
before reporting.

## Safe harbour

We will not take legal action against good-faith research that respects user
privacy, avoids harming systems or data, and gives us reasonable time to fix
the issue before disclosure.
