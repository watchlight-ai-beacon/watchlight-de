# Contributing

Thanks for helping improve the Watchlight Developer Edition!

## What lives here

This repo is the **open** Developer-Edition glue (Apache-2.0): the `govern`
decorator, the framework plugin shims, the `watchlight dev` dashboard, and
runnable examples. The authorization **engine** ships as a compiled wheel
(`watchlight-engine`) — its source is not in this repository.

## Ways to contribute

- **File an issue** — bugs, rough edges, and ideas:
  [open an issue](https://github.com/watchlight-ai-beacon/watchlight-de/issues/new/choose).
  We read every one.
- **Improve the docs or examples** — PRs welcome. Every example should be
  runnable and produce a *real* decision from the engine (no illustrative
  output).
- **Never include secrets** in issues, PRs, or examples — the audit trail is
  value-free by design, so you never need to.

## Running the examples

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e '.[langgraph]'          # or the extra you need
python examples/governed_research_agent.py
# watch decisions live in another terminal:
watchlight dev
```

## Reporting a security issue

Please do **not** open a public issue for security reports — see
[SECURITY.md](SECURITY.md).

## Enterprise / production

Governing a fleet, or need signed audit, drift→quarantine, SSO, air-gapped
deployment, or the engine source? → **sales@watchlight.ai** ·
[watchlight.ai](https://www.watchlight.ai)
