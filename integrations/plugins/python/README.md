# Python plugins

Each directory here is one Python package with its own `pyproject.toml`. The
packages are listed in [`../README.md`](../README.md).

## What a package directory contains

- A `pyproject.toml` that names the package, its version and its supported
  Python versions in `requires-python`. CI tests the package on every version
  from 3.10 to 3.13 that `requires-python` accepts, and refuses a package
  that accepts none of them.
- The package source, either in `src/` or at the top of the directory.
- A `tests/` directory that `python -m pytest`, run from the package directory,
  collects. A package with no tests fails CI rather than passing silently.
- A `dev` extra listing whatever the tests need beyond the package's own
  dependencies. CI installs the package with `pip install -e '<package>[dev]'`
  together with `pytest`.
- A `README.md` and a `CHANGELOG.md` for the package.

Directory names use lowercase letters, digits, `.`, `_` and `-` only. CI refuses
any other name.

## How CI installs a package

For every package except `watchlight-core`, CI first installs
`watchlight-core` from this directory in editable mode, then the package itself.
A plugin is therefore always tested against the SDK source in the same commit,
not against the last SDK release. A change to the SDK that breaks a plugin fails
that plugin's job in the same pull request.

## Working on a package

```bash
.venv/bin/pip install -e integrations/plugins/python/watchlight-core
.venv/bin/pip install -e 'integrations/plugins/python/<package>[dev]'
cd integrations/plugins/python/<package> && ../../../../.venv/bin/python -m pytest
```
