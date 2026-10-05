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

## Sign off your commits

Every commit must be signed off under the
[Developer Certificate of Origin](https://developercertificate.org/). The
sign-off certifies that you wrote the change, or otherwise have the right to
submit it under this repository's license. Add it with `-s`:

```bash
git commit -s -m "fix: ..."
```

That appends a line such as `Signed-off-by: Your Name <you@example.com>`, which
must match the commit's author. A required check, **DCO sign-off**, rejects a
pull request with an unsigned commit. To sign off commits you have already
made, run:

```bash
git rebase --signoff origin/main
git push --force-with-lease
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

### Adding a framework integration

A framework integration builds that framework's published Watchlight plugin
and wires it to the in-process engine. It is a declaration, not governance
code. Every integration — LangGraph, Pydantic AI and the Claude Agent SDK — is
on one contract, `src/watchlight/integrations/_contract.py`, and none has a
code path of its own.

The governance decisions an integration depends on (which backend the plugin
talks to, refusing per-call terms such as `principal` at construction, denying
everything when no policy is loaded) are made in one function,
`_select_backend_kwargs` in `src/watchlight/inprocess.py`. That is the decision
point. Integrations reach it only through `build_governed_plugin`, which also
refuses a keyword that would replace the chosen backend (`governance`,
`apdp_url`) and is the only place a framework plugin is imported. A change to
how plugins are governed is made there, once, and applies to every framework.

`watchlight.integrations` is an **internal surface for contributors, not a
public API**: it may change in any release. Users import
`watchlight.<framework>.governed_plugin`, which is stable.

To add one:

1. Create `src/watchlight/integrations/<name>.py` with an `INTEGRATION =
   FrameworkIntegration(...)` (the plugin's module, a top-level `watchlight_*`
   package; its class; its extra) and a documented
   `governed_plugin(policies=None, *, audit_path=..., **plugin_kwargs)` that
   returns `build_governed_plugin(INTEGRATION, ...)` and sets
   `governed_plugin.__module__ = "watchlight.<name>"`.
   [`integrations/langgraph.py`](src/watchlight/integrations/langgraph.py) is
   the reference.
2. Register it in `INTEGRATIONS` in `src/watchlight/integrations/__init__.py`,
   add the public module `src/watchlight/<name>.py` that re-exports it (see
   `langgraph.py`), and assign that module the `integration` layer in
   `tests/test_layering.py`.
3. Add the extra to `pyproject.toml`, and to `all`.
4. Pin the public module in `tests/test_public_api.py`: `PUBLIC_MODULES`,
   `FRAMEWORK_ALIASES` and `FRAMEWORK_DOC_DIGESTS`.

The new module must not import the plugin package or the governor
(`watchlight`), or reach `_select_backend_kwargs`, `in_process_backend` or the
contract's own steps; the contract does all of that for you. The layering test
catches the common forms of each; the behavioural tests prove the refusal;
review catches the rest.

`tests/integrations/test_integration_contract.py` and
`tests/test_adapter_parity.py` read their list from `INTEGRATIONS` and run
their checks against every registered integration, so you do not write those
tests yourself. They catch the mistakes we know to look for (a missing refusal,
a wrong signature, a misleading import error), but they are not a proof: a
factory written by hand around the contract can still be wrong, so a new
integration is reviewed against it.

### Layering

`tests/test_layering.py` holds the package to its layers: the foundation
(audit, scopes, approvals, principals) never imports the governor; only the
governor imports the compiled engine; an integration reaches governance only
through the contract, and only the contract imports a framework plugin or
references the seam's backend builders. It reads `importlib.import_module("x")` and
`__import__("x")` as imports, refuses any other dynamic import outside the
contract, and refuses other routes to loading code (`exec`, `eval`, `compile`,
`runpy`, `importlib.util`, `sys.modules`) in the foundation and in
integrations. It catches the common forms; review catches the rest. A new
module must be assigned a layer there. If the test fails, it names the import
and the rule; move the code rather than the rule.

## Reporting a security issue

Please do **not** open a public issue or pull request for a security report,
and do not push a fix for one to a public branch: a public fix discloses the
issue before users can upgrade. Report it privately as described in
[SECURITY.md](SECURITY.md), and we will fix it with you.

## Enterprise / production

Governing a fleet, or need signed audit, drift→quarantine, SSO, air-gapped
deployment, or the engine source? → **sales@watchlight.ai** ·
[watchlight.ai](https://www.watchlight.ai)
