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
version must be on PyPI, with files, and not yanked. A dependency without a
floor, a floor that is missing, yanked or has no files, or an answer this
check cannot read fails it.

USAGE
=====
    python3 integrations/plugins/python/ci/check_published_deps.py watchlight-claude-agent

Exit code 0 = every floor is on PyPI, 1 = findings (each printed), 2 = the
check could not run. Fail-closed: a check that cannot run has not passed.
"""

from __future__ import annotations

import http.client
import json
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


PRESENT, MISSING, YANKED, NO_FILES = "present", "missing", "yanked", "no files"


def release_state(body: bytes) -> str:
    """The state of one release from its PyPI JSON: yanked when the release
    or any of its files is, no files when it has none, else present."""
    try:
        data = json.loads(body)
        info, urls = data["info"], data["urls"]
    except (ValueError, KeyError, TypeError) as exc:
        raise CheckError(f"unreadable PyPI answer: {exc}") from exc
    if not isinstance(info, dict) or not isinstance(urls, list):
        raise CheckError("unreadable PyPI answer: info or urls has the wrong type")
    if info.get("yanked") or any(isinstance(u, dict) and u.get("yanked") for u in urls):
        return YANKED
    return PRESENT if urls else NO_FILES


def on_pypi(name: str, version: str) -> str:
    """The state of `name` at exactly `version` on PyPI: MISSING on a 404,
    else read from the release's JSON. Any other answer, a redirect
    included, cannot be read as either."""
    path = f"/pypi/{quote(name, safe='')}/{quote(version, safe='')}/json"
    # nosemgrep: community.python.lang.security.audit.httpsconnection-detected the context verifies the certificate and the host name (Python 3.12, a fixed host)
    conn = http.client.HTTPSConnection(INDEX_HOST, timeout=30, context=ssl.create_default_context())
    try:
        conn.request("GET", path, headers={"Accept": "application/json"})
        resp = conn.getresponse()
        status, body = resp.status, resp.read(8 * 1024 * 1024)
    except (OSError, http.client.HTTPException) as exc:
        raise CheckError(f"https://{INDEX_HOST}{path}: {exc}") from exc
    finally:
        conn.close()
    if status == 200:
        return release_state(body)
    if status == 404:
        return MISSING
    raise CheckError(f"https://{INDEX_HOST}{path}: HTTP {status}")


def findings(plugin: str, *, root: Path | None = None,
             lookup: Callable[[str, str], str] = on_pypi) -> list[str]:
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
        else:
            state = lookup(name, floor.group(1))
            if state == MISSING:
                out.append(f"{plugin}: requires {name}>={floor.group(1)}, which is not on PyPI; publish it first")
            elif state != PRESENT:
                out.append(f"{plugin}: requires {name}>={floor.group(1)}, which is on PyPI but {state}; "
                           "raise the floor to a usable release")
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
