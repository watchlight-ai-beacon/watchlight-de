"""Self-tests for check_published_deps.py. No network: PyPI is a stub.

    python3 -m unittest discover -s integrations/plugins/python/ci -p 'test_check_published_deps.py'
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import check_dist as cd
import check_published_deps as cpd


def _root(tmp: str, deps: list[str]) -> Path:
    pkg = Path(tmp) / cd.PACKAGES_REL / "watchlight-claude-agent"
    pkg.mkdir(parents=True)
    listed = ", ".join(f'"{d}"' for d in deps)
    (pkg / "pyproject.toml").write_text(f'[project]\nname = "x"\ndependencies = [{listed}]\n')
    return Path(tmp)


def _index(*published: tuple[str, str]):
    asked: list[tuple[str, str]] = []

    def lookup(name: str, version: str) -> bool:
        asked.append((name, version))
        return (name, version) in published

    return lookup, asked


class TestPublishedDeps(unittest.TestCase):
    def test_a_floor_on_pypi_passes(self) -> None:
        lookup, asked = _index(("watchlight-agent-sdk", "0.10.2"))
        with tempfile.TemporaryDirectory() as tmp:
            root = _root(tmp, ["watchlight-agent-sdk>=0.10.2,<0.11", "httpx>=0.27"])
            self.assertEqual(cpd.findings("watchlight-claude-agent", root=root, lookup=lookup), [])
        # Only Watchlight packages are looked up, at their floor.
        self.assertEqual(asked, [("watchlight-agent-sdk", "0.10.2")])

    def test_a_floor_not_on_pypi_is_refused(self) -> None:
        lookup, _ = _index(("watchlight-agent-sdk", "0.10.1"))
        with tempfile.TemporaryDirectory() as tmp:
            root = _root(tmp, ["watchlight-agent-sdk>=0.10.2,<0.11"])
            found = cpd.findings("watchlight-claude-agent", root=root, lookup=lookup)
        self.assertEqual(len(found), 1)
        self.assertIn("watchlight-agent-sdk>=0.10.2, which is not on PyPI", found[0])

    def test_a_watchlight_dependency_without_a_floor_is_refused(self) -> None:
        lookup, _ = _index()
        for req in ("watchlight-agent-sdk", "watchlight-agent-sdk<0.11", "watchlight_agent_sdk[otel]==0.10.2"):
            with self.subTest(req=req), tempfile.TemporaryDirectory() as tmp:
                found = cpd.findings("watchlight-claude-agent", root=_root(tmp, [req]), lookup=lookup)
                self.assertEqual(len(found), 1, found)
                self.assertIn("no >= floor", found[0])

    def test_an_unreadable_answer_cannot_pass(self) -> None:
        def lookup(name: str, version: str) -> bool:
            raise cpd.CheckError("HTTP 503")

        with tempfile.TemporaryDirectory() as tmp:
            root = _root(tmp, ["watchlight-agent-sdk>=0.10.2"])
            with self.assertRaises(cpd.CheckError):
                cpd.findings("watchlight-claude-agent", root=root, lookup=lookup)

    def test_only_a_published_package_can_be_checked(self) -> None:
        self.assertEqual(cpd.main(["not-a-package"]), 2)
        self.assertEqual(cpd.main([]), 2)


if __name__ == "__main__":
    unittest.main()
