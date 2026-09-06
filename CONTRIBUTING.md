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

## Before you open a pull request

Run the preflight. It is one command, it runs everything, and it is exactly what
CI runs on your pull request — the same script, in the same order, so a green
run here and a green check there mean the same thing:

```bash
scripts/preflight.sh
```

It runs, in order:

| Step | What it covers |
|---|---|
| `tests/` | the Python suite |
| `ts/` | the TypeScript suite (it builds first) |
| [`examples/patterns/check.sh`](examples/patterns/check.sh) | every pattern doc's policy suite and script |
| [`examples/showcase/check.sh`](examples/showcase/check.sh) | every showcase, both lanes |
| [`scripts/adversarial-harness.mjs`](scripts/adversarial-harness.mjs) | hostile inputs — malformed identities, forged tokens, broken stores |

It does **not** stop at the first failure: you get the full picture in one run,
and a summary at the end naming every step that failed. It exits `1` if anything
did — and `3`, distinctly, if it could not run at all for want of a
prerequisite. `examples/showcase/check.sh` draws the same distinction, through
the same helpers, so a missing interpreter never arrives disguised as a wall of
failing examples.

CI runs it on Python 3.9 — the floor this package supports — and on a current
release, so a feature newer than we claim to support fails there even when it
passes on your machine. Nothing in that workflow uses a repository secret, and a
pull request from a fork gets a read-only token, so the gate is the same for a
first-time contributor as for a maintainer.

From a fresh clone it will install and build the Node side for you (both are
git-ignored build output inside the clone). It will never install Python
packages into an environment you did not ask it to — if nothing on hand can
import `watchlight`, it stops and prints the exact commands:

```bash
python3 -m venv .venv
.venv/bin/pip install -e . pytest
```

Two of the steps have optional extras. `examples/showcase/web-backend` needs
FastAPI or Express; without them those lanes are reported as **SKIP**, counted,
and listed loudly at the end — never silently passed. Install them to cover
that showcase too:

```bash
.venv/bin/pip install -r examples/showcase/web-backend/requirements.txt
(cd examples/showcase/web-backend && npm install)
```

### Adding an example

Every example is verified, and that is a rule the runners enforce rather than a
convention:

- A **pattern** doc under `examples/patterns/` needs a `suites/<name>.suite.json`,
  a `scripts/<name>.mjs`, or both.
- A **showcase** directory under `examples/showcase/` needs an executable
  `check.sh` declaring how it is run — which scripts, in which order, from what
  state. See [`examples/showcase/_check_lib.sh`](examples/showcase/_check_lib.sh)
  for the handful of helpers a `check.sh` is written with.

In both cases the runner fails on an example that declares no check, because an
example nothing runs will drift, and a check nothing runs is indistinguishable
from a check that passes.

## Reporting a security issue

Please do **not** open a public issue for security reports — see
[SECURITY.md](SECURITY.md).

## Enterprise / production

Governing a fleet, or need signed audit, drift→quarantine, SSO, air-gapped
deployment, or the engine source? → **sales@watchlight.ai** ·
[watchlight.ai](https://www.watchlight.ai)
