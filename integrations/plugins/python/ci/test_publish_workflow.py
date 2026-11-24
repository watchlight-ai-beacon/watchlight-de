"""Pins the safety properties of .github/workflows/publish-plugins.yml.

Standard library only, so the workflow is read as text: each job is the
block under its `  <name>:` line in `jobs:`.

    python3 -m unittest discover -s integrations/plugins/python/ci -p 'test_publish_workflow.py'
"""

from __future__ import annotations

import re
import unittest

import check_dist as cd

WORKFLOW = cd.ROOT / ".github" / "workflows" / "publish-plugins.yml"

#: The packages whose release has been reviewed. Adding one is a reviewed change.
REVIEWED = ["watchlight-agent-sdk", "watchlight-agent-sdk-testing", "watchlight-claude-agent"]


def _text() -> str:
    return WORKFLOW.read_text()


def _jobs(text: str) -> dict[str, str]:
    body = text.split("\njobs:\n", 1)[1]
    parts = re.split(r"(?m)^  ([a-z][\w-]*):[ \t]*\n", body)
    return dict(zip(parts[1::2], parts[2::2]))


def _before(block: str, first: str, then: str) -> bool:
    return first in block and then in block and block.index(first) < block.index(then)


class TestPublishWorkflow(unittest.TestCase):
    def setUp(self) -> None:
        self.text = _text()
        self.jobs = _jobs(self.text)

    def test_only_reviewed_packages_can_be_chosen(self) -> None:
        m = re.search(r"(?m)^      package:\n(?:        .*\n)*?        options:\n((?:          - .*\n)+)", self.text)
        self.assertIsNotNone(m)
        options = re.findall(r"- (\S+)", m.group(1))
        self.assertEqual(options, REVIEWED)
        dists = {d: plugin for plugin, (d, _) in cd.PUBLISHED_PLUGINS.items()}
        for name in options:
            # Each maps to the directory check_dist publishes it from.
            self.assertIn(f"{name}) dir={dists[name]} ;;", self.jobs["build"], name)
        self.assertIn('*) echo "::error::$PACKAGE is not a reviewed package"; exit 1 ;;', self.jobs["build"])

    def test_dry_run_is_the_default(self) -> None:
        self.assertRegex(self.text, r"(?m)^      dry_run:\n(?:        .*\n)*?        default: true\n")
        self.assertIn("if: ${{ !inputs.dry_run }}", self.jobs["publish"])

    def test_only_the_publish_job_holds_the_publishing_token(self) -> None:
        self.assertEqual(set(self.jobs), {"build", "publish"})
        self.assertNotIn("id-token", self.jobs["build"])
        self.assertIn("id-token: write", self.jobs["publish"])
        self.assertIn("environment: pypi", self.jobs["publish"])
        self.assertNotIn("id-token", self.text.split("\njobs:\n", 1)[0])

    def test_the_build_job_checks_dependencies_then_builds_and_scans(self) -> None:
        build = self.jobs["build"]
        self.assertTrue(_before(build, "test_check_dist test_check_published_deps test_publish_workflow",
                                "check_published_deps.py"))
        self.assertTrue(_before(build, "check_published_deps.py", '--build --out "$GITHUB_WORKSPACE/dist"'))
        self.assertTrue(_before(build, '--build --out "$GITHUB_WORKSPACE/dist"', "actions/upload-artifact@"))
        self.assertIn('--require-hashes --only-binary :all: --no-deps -r "$base/ci/dist.txt"', build)

    def test_the_publish_job_scans_what_it_uploads_first(self) -> None:
        self.assertTrue(_before(self.jobs["publish"], 'check_dist.py --dist dist --plugin "$DIR"',
                                "pypa/gh-action-pypi-publish@"))

    def test_every_action_is_pinned_to_a_commit(self) -> None:
        uses = re.findall(r"(?m)^\s*(?:- )?uses: (\S+)", self.text)
        self.assertTrue(uses)
        for ref in uses:
            self.assertRegex(ref, r"^[\w.-]+/[\w.-]+@[0-9a-f]{40}$", ref)

    def test_checkouts_keep_no_credentials(self) -> None:
        checkouts = self.text.count("uses: actions/checkout@")
        self.assertEqual(self.text.count("persist-credentials: false"), checkouts)


if __name__ == "__main__":
    unittest.main()
