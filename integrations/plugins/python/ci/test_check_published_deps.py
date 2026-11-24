"""Self-tests for check_published_deps.py. No network: PyPI is a stub.

    python3 -m unittest discover -s integrations/plugins/python/ci -p 'test_check_published_deps.py'
"""

from __future__ import annotations

import json
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


def _index(*published: tuple[str, str], state: str = cpd.PRESENT):
    asked: list[tuple[str, str]] = []

    def lookup(name: str, version: str) -> str:
        asked.append((name, version))
        return state if (name, version) in published else cpd.MISSING

    return lookup, asked


def _release(yanked: bool = False, files: list[dict] | None = None) -> bytes:
    urls = [{"filename": "x.whl", "yanked": False}] if files is None else files
    return json.dumps({"info": {"version": "0.10.2", "yanked": yanked}, "urls": urls}).encode()


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

    def test_a_yanked_or_empty_floor_is_refused(self) -> None:
        for state in (cpd.YANKED, cpd.NO_FILES):
            lookup, _ = _index(("watchlight-agent-sdk", "0.10.2"), state=state)
            with self.subTest(state=state), tempfile.TemporaryDirectory() as tmp:
                root = _root(tmp, ["watchlight-agent-sdk>=0.10.2,<0.11"])
                found = cpd.findings("watchlight-claude-agent", root=root, lookup=lookup)
                self.assertEqual(len(found), 1, found)
                self.assertIn(f"which is on PyPI but {state}", found[0])

    def test_the_release_state_is_read_from_the_json(self) -> None:
        self.assertEqual(cpd.release_state(_release()), cpd.PRESENT)
        self.assertEqual(cpd.release_state(_release(yanked=True)), cpd.YANKED)
        self.assertEqual(cpd.release_state(_release(files=[{"filename": "x.whl", "yanked": True}])), cpd.YANKED)
        self.assertEqual(cpd.release_state(_release(files=[])), cpd.NO_FILES)
        for body in (b"not json", b"{}", b'{"info": {}, "urls": {}}', b'{"info": [], "urls": []}', b"[]"):
            with self.subTest(body=body), self.assertRaises(cpd.CheckError):
                cpd.release_state(body)

    def test_a_watchlight_dependency_without_a_floor_is_refused(self) -> None:
        lookup, _ = _index()
        for req in ("watchlight-agent-sdk", "watchlight-agent-sdk<0.11", "watchlight_agent_sdk[otel]==0.10.2"):
            with self.subTest(req=req), tempfile.TemporaryDirectory() as tmp:
                found = cpd.findings("watchlight-claude-agent", root=_root(tmp, [req]), lookup=lookup)
                self.assertEqual(len(found), 1, found)
                self.assertIn("no >= floor", found[0])

    def test_an_unreadable_answer_cannot_pass(self) -> None:
        def lookup(name: str, version: str) -> str:
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
