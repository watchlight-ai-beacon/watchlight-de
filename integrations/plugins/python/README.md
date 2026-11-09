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

CI installs every third-party package from the hash-pinned lock in
[`ci/plugins.txt`](ci/plugins.txt): wheels only, every hash checked, nothing
resolved at install time. It then installs `watchlight-core`, the test doubles
in `watchlight-agent-sdk-testing` and the package itself from this directory,
editable and without dependencies, and runs `pip check`. A plugin is therefore
always tested against the SDK source in the same commit, not against the last
SDK release, and a change to the SDK that breaks a plugin fails that plugin's
job in the same pull request. The compiled engine comes from its own lock,
[`ci/engine.txt`](ci/engine.txt), and a test that needs it fails rather than
skipping.

CI tests each package on the Python versions its `requires-python` accepts
from the lock's floor up. `watchlight-adk` runs a second time at its declared
minimum `google-adk` ([`ci/adk-min.txt`](ci/adk-min.txt)), and every published
package is built and its wheel and sdist scanned by
[`ci/check_dist.py`](ci/check_dist.py).

A new package directory must be added to the list of open package roots in
`.github/workflows/plugins.yml`, with the name it is released under; CI refuses
any other directory.

## Working on a package

```bash
.venv/bin/pip install -e integrations/plugins/python/watchlight-core
.venv/bin/pip install -e integrations/plugins/python/watchlight-agent-sdk-testing
.venv/bin/pip install -e 'integrations/plugins/python/<package>[dev]'
cd integrations/plugins/python/<package> && ../../../../.venv/bin/python -m pytest
```

To test against exactly what CI installs:

```bash
.venv/bin/pip install --require-hashes --only-binary :all: --no-deps -r integrations/plugins/python/ci/plugins.txt
```
