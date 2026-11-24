"""Self-tests for check_dist.py.

    python3 -m unittest discover -s integrations/plugins/python/ci -p 'test_check_dist.py'
"""

from __future__ import annotations

import io
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

import check_dist as cd

DIST, MODULE, VERSION = "watchlight-msaf", "watchlight_msaf", "1.0.0"
INFO = f"watchlight_msaf-{VERSION}.dist-info"
TOP = f"watchlight_msaf-{VERSION}"

METADATA = (
    "Metadata-Version: 2.4\n"
    f"Name: {DIST}\n"
    f"Version: {VERSION}\n"
    "License-Expression: Apache-2.0\n"
    f"Project-URL: Repository, {cd.PUBLIC_REPO}\n"
    f"Project-URL: Issues, {cd.PUBLIC_REPO}/issues\n"
)


def _wheel(tmp: str, members: dict[str, str]) -> Path:
    path = Path(tmp) / f"watchlight_msaf-{VERSION}-py3-none-any.whl"
    base = {
        f"{MODULE}/__init__.py": "VALUE = 1\n",
        f"{INFO}/METADATA": METADATA,
        f"{INFO}/WHEEL": "Wheel-Version: 1.0\n",
        f"{INFO}/RECORD": "",
        f"{INFO}/licenses/LICENSE": "Apache License\n",
    }
    base.update(members)
    with zipfile.ZipFile(path, "w") as zf:
        for name, text in base.items():
            zf.writestr(name, text)
    return path


def _sdist(tmp: str, members: dict[str, str]) -> Path:
    path = Path(tmp) / f"watchlight_msaf-{VERSION}.tar.gz"
    base = {
        f"{TOP}/PKG-INFO": METADATA,
        f"{TOP}/pyproject.toml": "[project]\n",
        f"{TOP}/LICENSE": "Apache License\n",
        f"{TOP}/README.md": "readme\n",
        f"{TOP}/{MODULE}/__init__.py": "VALUE = 1\n",
    }
    base.update(members)
    with tarfile.open(path, "w:gz") as tf:
        for name, text in base.items():
            data = text.encode()
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return path


def _reasons(findings: list[cd.Finding]) -> list[str]:
    return [f"{f.member}: {f.reason}" for f in findings]


class TestWheel(unittest.TestCase):
    def test_a_clean_wheel_has_no_findings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(_reasons(cd.scan_wheel(_wheel(tmp, {}), DIST, MODULE, VERSION)), [])

    def test_a_test_module_or_a_double_never_ships(self) -> None:
        for name, text in (
            (f"{MODULE}/tests/test_x.py", "x = 1\n"),
            (f"{MODULE}/conftest.py", "x = 1\n"),
            (f"{MODULE}/_doubles.py", "x = 1\n"),
            (f"{MODULE}/helpers.py", "from watchlight_core_testing import MockApdpClient\n"),
        ):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                self.assertTrue(cd.scan_wheel(_wheel(tmp, {name: text}), DIST, MODULE, VERSION), name)

    def test_secret_like_text_is_a_finding(self) -> None:
        for text in (
            "KEY = 'AKIA" + "ABCDEFGHIJKLMNOP'\n",
            "TOKEN = 'sk-ant-" + "a" * 30 + "'\n",
            "HOST = 'http://build.internal/x'\n",
            # public-hygiene: allow[internal-host] a fixture for the home-directory rule under test
            "PATH = '/Users/someone/project/'\n",
            "-----BEGIN PRIVATE KEY-----\n" + "A" * 200 + "\n-----END PRIVATE KEY-----\n",
        ):
            with self.subTest(text=text[:20]), tempfile.TemporaryDirectory() as tmp:
                found = cd.scan_wheel(_wheel(tmp, {f"{MODULE}/leak.py": text}), DIST, MODULE, VERSION)
                self.assertTrue(found, text[:20])

    def test_metadata_must_name_this_repository(self) -> None:
        bad = METADATA.replace(cd.PUBLIC_REPO, "https://example.com/elsewhere")
        with tempfile.TemporaryDirectory() as tmp:
            found = _reasons(cd.scan_wheel(_wheel(tmp, {f"{INFO}/METADATA": bad}), DIST, MODULE, VERSION))
            self.assertTrue(any("Project-URL 'Repository'" in r for r in found), found)


class TestSdist(unittest.TestCase):
    def test_a_clean_sdist_has_no_findings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(_reasons(cd.scan_sdist(_sdist(tmp, {}), DIST, MODULE, VERSION)), [])

    def test_tests_and_secret_files_never_ship(self) -> None:
        for name in (f"{TOP}/tests/test_plugin.py", f"{TOP}/.env", f"{TOP}/deploy.pem", f"{TOP}/agent.creds"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                self.assertTrue(cd.scan_sdist(_sdist(tmp, {name: "x\n"}), DIST, MODULE, VERSION), name)

    def test_credential_and_key_file_names_are_secret_material(self) -> None:
        for name in (".env", ".env.local", "agent.creds", "user.nkey", "deploy.pem", "server.key", "api_token"):
            with self.subTest(name=name):
                self.assertIsNotNone(cd.committed_secret_reason(name, ""), name)

    def test_a_ca_bundle_is_not_a_private_key_file(self) -> None:
        self.assertIsNone(cd.committed_secret_reason("ca-bundle.pem", "-----BEGIN CERTIFICATE-----\n"))


class TestDistDir(unittest.TestCase):
    def test_an_unknown_file_in_the_upload_directory_is_a_finding(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "notes.txt").write_text("x")
            found = _reasons(cd.scan_dist_dir(Path(tmp)))
            self.assertTrue(any("not a wheel or sdist" in r for r in found), found)

    def test_an_empty_upload_directory_cannot_pass(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(cd.ScanError):
                cd.scan_dist_dir(Path(tmp))


def _named_wheel(tmp: str, dist: str, module: str, members: dict[str, str]) -> Path:
    info = f"{dist.replace('-', '_')}-{VERSION}.dist-info"
    path = Path(tmp) / f"{dist.replace('-', '_')}-{VERSION}-py3-none-any.whl"
    base = {
        f"{module}/__init__.py": "VALUE = 1\n",
        f"{info}/METADATA": METADATA.replace(f"Name: {DIST}", f"Name: {dist}"),
        f"{info}/WHEEL": "Wheel-Version: 1.0\n",
        f"{info}/RECORD": "",
        f"{info}/licenses/LICENSE": "Apache License\n",
    }
    base.update(members)
    with zipfile.ZipFile(path, "w") as zf:
        for name, text in base.items():
            zf.writestr(name, text)
    return path


DOUBLES = {
    "_doubles.py": "class MockApdpClient:\n    pass\n",
    "conformance.py": "from watchlight_core_testing import MockApdpClient\n",
}


class TestTestDoubleDistribution(unittest.TestCase):
    TESTING = ("watchlight-agent-sdk-testing", "watchlight_core_testing")

    def test_only_the_testing_distribution_may_ship_doubles(self) -> None:
        self.assertEqual(cd.TEST_DOUBLE_DISTS, frozenset({"watchlight-agent-sdk-testing"}))
        self.assertEqual(cd.PUBLISHED_PLUGINS["watchlight-agent-sdk-testing"], self.TESTING)

    def test_its_own_doubles_ship(self) -> None:
        dist, module = self.TESTING
        members = {f"{module}/{k}": v for k, v in DOUBLES.items()}
        with tempfile.TemporaryDirectory() as tmp:
            found = cd.scan_wheel(_named_wheel(tmp, dist, module, members), dist, module, VERSION)
            self.assertEqual(_reasons(found), [])

    def test_every_other_rule_still_applies_to_it(self) -> None:
        dist, module = self.TESTING
        for name, text in (
            (f"{module}/tests/test_x.py", "x = 1\n"),
            (f"{module}/leak.py", "KEY = 'AKIA" + "ABCDEFGHIJKLMNOP'\n"),
            ("watchlight_core/__init__.py", "x = 1\n"),
        ):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                found = cd.scan_wheel(_named_wheel(tmp, dist, module, {name: text}), dist, module, VERSION)
                self.assertTrue(found, name)

    def test_the_sdk_never_ships_them(self) -> None:
        dist, module = "watchlight-agent-sdk", "watchlight_core"
        for leaf, text in DOUBLES.items():
            with self.subTest(leaf=leaf), tempfile.TemporaryDirectory() as tmp:
                wheel = _named_wheel(tmp, dist, module, {f"{module}/{leaf}": text})
                self.assertTrue(cd.scan_wheel(wheel, dist, module, VERSION), leaf)


class TestOut(unittest.TestCase):
    def test_out_needs_build(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(cd.main(["--dist", tmp, "--out", str(Path(tmp) / "o")]), 2)

    def test_out_must_be_a_new_directory_and_is_left_alone(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            keep = Path(tmp) / "keep.txt"
            keep.write_text("x")
            self.assertEqual(cd.main(["--build", "--out", tmp, "--plugin", "watchlight-msaf"]), 2)
            self.assertTrue(keep.exists())


if __name__ == "__main__":
    unittest.main()
