# Watchlight plugins and SDKs

This directory is where the Watchlight framework plugins and the agent SDKs
they are built on are developed. A framework plugin governs an agent built on a
particular framework, such as LangGraph or the Claude Agent SDK, from inside the
agent process. The agent SDK is the lower-level lifecycle library that every
plugin uses to start a run, authorize each action, spawn sub-agents and record
what happened.

These are the same packages you ship to production. The Developer Edition's
`watchlight` package does not copy them: its extras install them, and the
wrappers in `src/watchlight/integrations/` point them at the in-process engine.

The package sources are being added to this directory in stages. Until a
package's directory exists, it is still installed from its published release,
and nothing in this repository builds it.

## What lives here

```
integrations/plugins/
  python/   one directory per Python package
  ts/       an npm workspace with one directory per TypeScript package
```

The Python packages:

| Directory | Package name | Imports as |
|---|---|---|
| `python/watchlight-core/` | `watchlight-agent-sdk` | `watchlight_core` |
| `python/watchlight-langgraph/` | `watchlight-langgraph` | `watchlight_langgraph` |
| `python/watchlight-pydantic-ai/` | `watchlight-pydantic-ai` | `watchlight_pydantic_ai` |
| `python/watchlight-claude-agent/` | `watchlight-claude-agent` | `watchlight_claude_agent` |
| `python/watchlight-adk/` | `watchlight-adk` | `watchlight_adk` |
| `python/watchlight-bedrock/` | `watchlight-bedrock` | `watchlight_bedrock` |
| `python/watchlight-msaf/` | `watchlight-msaf` | `watchlight_msaf` |
| `python/watchlight-deepagents/` | `watchlight-deepagents` | `watchlight_deepagents` |
| `python/watchlight-strands/` | `watchlight-strands` | `watchlight_strands` |
| `python/plugin-template/` | not released | `watchlight_template`, a starting point for a new plugin |

Note the first row. The SDK's directory is `watchlight-core` and it imports as
`watchlight_core`, but it is released under the name `watchlight-agent-sdk`.
There is no `watchlight-core` package to install.

The TypeScript packages:

| Directory | Package name |
|---|---|
| `ts/agent-sdk/` | `@watchlight/agent-sdk` |
| `ts/claude-agent/` | `@watchlight/claude-agent` |
| `ts/openclaw/` | `@watchlight/openclaw` |

Two things stay where they are. `src/watchlight/integrations/` holds the
Developer Edition's own wrappers, and `ts/` holds `@watchlight/sdk`. Neither
moves into this directory.

## Every package stands on its own

Each package has its own manifest (`pyproject.toml` or `package.json`), its own
version, its own tests and its own changelog. None of them lives inside
`src/watchlight/`, so none of them is part of the `watchlight` wheel or sdist
(the repository's `MANIFEST.in` prunes `integrations/` from the sdist as well),
and none is part of the `@watchlight/sdk` npm package. Installing `watchlight`
never installs plugin source from this directory; it installs the released
plugin packages that its extras name.

A package is built, tested and released on its own:

- **Build.** A Python package builds from its own directory with
  `python -m build integrations/plugins/python/<package>`. The TypeScript
  packages build together from the workspace root with `npm run build` in
  `integrations/plugins/ts/`.
- **Test.** The **Plugins** workflow runs each Python package's tests on every
  Python version from 3.10 to 3.13 that the package's `requires-python`
  accepts, one job per package and version, and runs the TypeScript
  workspace's build, type check and tests. It finds the packages by looking for
  `python/*/pyproject.toml` and `ts/*/package.json`, so a new package is tested
  as soon as its directory exists. While a directory holds no packages, the
  workflow says so and passes.
- **Release.** A package is released when its own version changes, separately
  from `watchlight` and `@watchlight/sdk`. A plugin release does not imply a
  Developer Edition release, and a Developer Edition release does not imply a
  plugin release. The release workflow for each package arrives with the
  package.

The repository's `scripts/preflight.sh` covers `src/`, `tests/`, `ts/` and
`examples/`. It does not run the plugin suites. Run the suite of each package you
change, as described below.

## How the `watchlight` extras relate to these packages

The `langgraph`, `pydantic-ai`, `claude-agent`, `sdk` and `all` extras in the
repository's `pyproject.toml` install released plugin packages, each capped
below its next minor release. For example, `pip install 'watchlight[langgraph]'`
installs `watchlight-langgraph` and `watchlight-agent-sdk` from the package
index, not from this directory.

That cap is deliberate. The in-process backend records every decision by
overriding the SDK client's public methods, so a release that adds a decision
method has to be classified before `watchlight` accepts it. Raising a cap is a
change to `pyproject.toml`, reviewed and tested like any other, and it happens
after the plugin release it points at is out.

## Developing across packages

Install the packages you are working on in editable mode, into the same virtual
environment as the Developer Edition. Install the SDK first, so the plugins use
your working copy of it rather than the released one:

```bash
python -m venv .venv
.venv/bin/pip install -e . pytest
.venv/bin/pip install -e integrations/plugins/python/watchlight-core
.venv/bin/pip install -e integrations/plugins/python/watchlight-langgraph
```

With that in place, a change to the SDK or the plugin is picked up immediately
by `watchlight.langgraph.governed_plugin`, the examples and the repository's own
tests. Run a package's tests from its directory:

```bash
cd integrations/plugins/python/watchlight-langgraph
../../../../.venv/bin/python -m pytest
```

A package declares the extra dependencies its tests need in a `dev` extra
(`pip install -e '<package>[dev]'`), which is what CI installs.

For the TypeScript packages, work from the workspace root. `npm ci` links every
package in the workspace to the others, so a change to `@watchlight/agent-sdk`
is seen by the plugins that depend on it:

```bash
cd integrations/plugins/ts
npm ci
npm run build
npm run typecheck
npm test
```

See [`python/README.md`](python/README.md) and [`ts/README.md`](ts/README.md)
for what each package directory must contain.

## Security issues

Please do not open a public issue or pull request for a security problem in any
of these packages, and do not push a fix for one to a public branch. Report it
privately as described in [SECURITY.md](../../SECURITY.md), and we will fix it
with you.
