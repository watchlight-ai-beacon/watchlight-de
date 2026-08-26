# Security Policy

## Reporting a vulnerability

Please report security issues **privately** — do not open a public issue or PR.

- **Preferred:** [open a private security advisory](https://github.com/watchlight-ai-beacon/watchlight-de/security/advisories/new) on this repository.
- Or email **security@watchlight.ai**.

We aim to acknowledge reports within 3 business days.

Include a minimal reproduction where possible. **Do not include secrets, tokens,
or private data** — Watchlight's audit trail is value-free by design, so a repro
never needs them.

## Scope

This repository is the open **Developer Edition** package (`watchlight`) and its
examples. The authorization engine (`watchlight-engine`) and the MCP runtime
(`watchlight-mcp`) ship as compiled wheels; vulnerabilities in those are equally
in scope — report them the same way.

## Supported versions

The latest release published to PyPI is supported. Please upgrade to the latest
version before reporting.
