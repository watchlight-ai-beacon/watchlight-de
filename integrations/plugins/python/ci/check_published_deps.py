#!/usr/bin/env python3
"""Refuse to publish a package before the Watchlight packages it needs.

WHY
===
watchlight-agent-sdk-testing and watchlight-claude-agent require
watchlight-agent-sdk at a version that may not be on PyPI yet. Uploaded out
of order, the package installs for nobody until its dependency follows, and
a resolver may pick an older release instead. The publish workflow runs this
before it builds, so the order is enforced rather than remembered.

WHAT IT CHECKS
==============
Every dependency of the package that is itself a published package (see
check_dist.PUBLISHED_PLUGINS) must state a `>=` floor, and that exact
version must be on PyPI. A dependency without a floor, a floor that is not
on PyPI, or an answer this check cannot read fails it.

USAGE
=====
    python3 integrations/plugins/python/ci/check_published_deps.py watchlight-claude-agent

Exit code 0 = every floor is on PyPI, 1 = findings (each printed), 2 = the
check could not run. Fail-closed: a check that cannot run has not passed.
"""

from __future__ import annotations

import http.client
import re
import ssl
import sys
import tomllib
from urllib.parse import quote
from collections.abc import Callable
from pathlib import Path

import check_dist as cd

INDEX_HOST = "pypi.org"
_REQ = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*([^;]*)")
_FLOOR = re.compile(r">=\s*([0-9][^,\s]*)")


class CheckError(Exception):
    pass


def on_pypi(name: str, version: str) -> bool:
    """True when PyPI has `name` at exactly `version`, False when it answers
    404. Any other answer, a redirect included, cannot be read as either."""
    path = f"/pypi/{quote(name, safe='')}/{quote(version, safe='')}/json"
    # nosemgrep: community.python.lang.security.audit.httpsconnection-detected the context verifies the certificate and the host name (Python 3.12, a fixed host)
    conn = http.client.HTTPSConnection(INDEX_HOST, timeout=30, context=ssl.create_default_context())
    try:
        conn.request("GET", path, headers={"Accept": "application/json"})
        status = conn.getresponse().status
    except (OSError, http.client.HTTPException) as exc:
        raise CheckError(f"https://{INDEX_HOST}{path}: {exc}") from exc
    finally:
        conn.close()
    if status == 200:
        return True
    if status == 404:
        return False
    raise CheckError(f"https://{INDEX_HOST}{path}: HTTP {status}")


def findings(plugin: str, *, root: Path | None = None,
             lookup: Callable[[str, str], bool] = on_pypi) -> list[str]:
    root = root or cd.ROOT
    path = root / cd.PACKAGES_REL / plugin / "pyproject.toml"
    try:
        with path.open("rb") as fh:
            deps = tomllib.load(fh)["project"].get("dependencies", [])
    except (OSError, KeyError, tomllib.TOMLDecodeError) as exc:
        raise CheckError(f"{path}: {exc}") from exc
    published = {cd._norm(d) for d, _ in cd.PUBLISHED_PLUGINS.values()}
    out = []
    for req in deps:
        m = _REQ.match(req)
        if not m or cd._norm(m.group(1)) not in published:
            continue
        name = m.group(1)
        floor = _FLOOR.search(m.group(2))
        if not floor:
            out.append(f"{plugin}: {req!r} states no >= floor, so its published version cannot be checked")
        elif not lookup(name, floor.group(1)):
            out.append(f"{plugin}: requires {name}>={floor.group(1)}, which is not on PyPI; publish it first")
    return out


def main(argv: list[str]) -> int:
    if len(argv) != 1 or argv[0] not in cd.PUBLISHED_PLUGINS:
        print("usage: check_published_deps.py <published package directory>", file=sys.stderr)
        return 2
    try:
        found = findings(argv[0])
    except CheckError as exc:
        print(f"::error::check_published_deps could not run: {exc}", file=sys.stderr)
        return 2
    for f in found:
        print(f"::error::{f}")
    if found:
        return 1
    print(f"check_published_deps: every Watchlight package {argv[0]} requires is on PyPI.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
