#!/usr/bin/env python3
"""Built-artifact scan of the published Python packages.

WHY
===
What reaches PyPI is the wheel and the sdist a build produces, not the source
tree, and a build picks up more than a reviewer sees: setuptools puts `tests/`
into every sdist by default, a stale `build/lib` leaks deleted modules into a
wheel, and a stray `.env` or key next to pyproject.toml ships with the sdist.
Once a file is on PyPI it cannot be taken back. This check reads the built
files themselves and fails on anything that is not meant to ship.

WHAT IT CHECKS
==============
Contents, against an allowlist. A wheel may hold the package's own modules
(`<module>/**.py`, `<module>/py.typed`) and its `.dist-info` metadata
(METADATA, WHEEL, RECORD, top_level.txt, entry_points.txt, the licence
file). An sdist may hold the same modules plus README.md, LICENSE,
pyproject.toml, setup.cfg, MANIFEST.in, PKG-INFO and its `.egg-info`
metadata. Anything else fails: tests, conftest.py, `.env`, keys and
certificates, CI files. Test doubles and the conformance runner are test
modules too, except in watchlight-agent-sdk-testing, the one distribution
that exists to ship them (only its own modules; every other rule still
applies to it).

Text, in every member: no private address (192.168.*, 10.*, 172.16-31.*,
a URL or e-mail at a .local / .internal / .lan / .corp host), no absolute
home-directory path, and nothing secret-like: credential and private-key file
names, PEM private-key blocks and token shapes (AWS access keys, GitHub,
Slack, Anthropic and OpenAI tokens, NATS seeds). Test doubles and test-only
imports never ship in a published package.

Metadata (the wheel's METADATA and the sdist's PKG-INFO): the name and
version match the file name and the package's pyproject.toml; a licence is
declared (License or License-Expression) and a licence file ships; the
project URLs name this repository as `Repository` and its `/issues` as
`Issues`.

Every published package must produce exactly one wheel and one sdist.

USAGE
=====
    # CI: copy each package's tracked files to a scratch directory, build its
    # wheel and sdist offline (python -m build --no-isolation, with the tools
    # from the hash-pinned ci/dist.txt), and scan them.
    python3 integrations/plugins/python/ci/check_dist.py --build [--plugin watchlight-adk ...]

    # Publish workflow, build job: the same build and scan, keeping the files
    # in DIR (which must not exist yet) for the upload.
    python3 integrations/plugins/python/ci/check_dist.py --build --out DIR --plugin watchlight-core

    # Publish workflow: scan the files that are about to be uploaded. Every
    # file in DIR must belong to a published package. Standard library only.
    python3 integrations/plugins/python/ci/check_dist.py --dist dist

Exit code 0 = clean, 1 = findings (each printed), 2 = the scan could not run
(a build failed, a file could not be read, bad usage). Fail-closed: a scan
that cannot run has not passed.
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from dataclasses import dataclass
from email.parser import HeaderParser
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - python < 3.11
    tomllib = None  # type: ignore[assignment]

#: The repository root (git ls-files paths are relative to it).
ROOT = Path(__file__).resolve().parents[4]
PACKAGES_REL = "integrations/plugins/python"

#: The published Python packages: directory -> (PyPI name, import package).
PUBLISHED_PLUGINS: dict[str, tuple[str, str]] = {
    "watchlight-core": ("watchlight-agent-sdk", "watchlight_core"),
    "watchlight-agent-sdk-testing": ("watchlight-agent-sdk-testing", "watchlight_core_testing"),
    "watchlight-adk": ("watchlight-adk", "watchlight_adk"),
    "watchlight-langgraph": ("watchlight-langgraph", "watchlight_langgraph"),
    "watchlight-bedrock": ("watchlight-bedrock", "watchlight_bedrock"),
    "watchlight-deepagents": ("watchlight-deepagents", "watchlight_deepagents"),
    "watchlight-msaf": ("watchlight-msaf", "watchlight_msaf"),
    "watchlight-pydantic-ai": ("watchlight-pydantic-ai", "watchlight_pydantic_ai"),
    "watchlight-claude-agent": ("watchlight-claude-agent", "watchlight_claude_agent"),
    "watchlight-strands": ("watchlight-strands", "watchlight_strands"),
}

PUBLIC_REPO = "https://github.com/watchlight-ai-beacon/watchlight-de"
REQUIRED_URLS = {"Repository": PUBLIC_REPO, "Issues": PUBLIC_REPO + "/issues"}
LICENSE_NAMES = ("LICENSE",)

#: Files a wheel's .dist-info may hold (licence files are matched separately).
WHEEL_META = {"METADATA", "WHEEL", "RECORD", "top_level.txt", "entry_points.txt"}
#: Files at the top of an sdist (under <name>-<version>/).
SDIST_TOP = {"PKG-INFO", "README.md", "LICENSE", "pyproject.toml", "setup.cfg", "MANIFEST.in"}
#: Files an sdist's .egg-info may hold.
EGG_INFO = {"PKG-INFO", "SOURCES.txt", "dependency_links.txt", "requires.txt",
            "top_level.txt", "entry_points.txt", "not-zip-safe"}

# ── text rules ──────────────────────────────────────────────────────────
# The internal TLD must end the host name (`corp.example`, a reserved
# example domain, is not one).
_INTERNAL_HOST = r"[A-Za-z0-9.-]+\.(?:local|internal|lan|corp)(?![\w.-])"
TEXT_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("private IPv4 address", re.compile(
        r"(?<![\d.])(?:192\.168|10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}(?![\d.])")),
    ("internal host in a URL", re.compile(r"(?i)\b[a-z][a-z0-9+.-]*://(?:[^\s/@'\"]*@)?" + _INTERNAL_HOST)),
    ("internal e-mail or host", re.compile(r"(?i)[\w.+-]+@" + _INTERNAL_HOST)),
    ("absolute home-directory path", re.compile(r"(?<![\w.])/(?:Users|home)/[a-z][\w.-]*/")),
    ("AWS access key id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,})\b")),
    ("Slack token", re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}")),
    ("Anthropic API key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}")),
    ("OpenAI API key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9]{32,}\b")),
    ("NATS seed", re.compile(r"\bS[UANOCPX][A-Z2-7]{56}\b")),
)
#: The largest member that is scanned (no published module is near this). A
#: larger one is a finding, never a partial scan.
MAX_SCAN = 4 * 1024 * 1024


# ── secret files ────────────────────────────────────────────────────────
_SECRET_NAME = re.compile(r"(?i)(?:\.(?:creds|seed|nkey|jwt)|[-_](?:token|secret[-_]id|role[-_]id))$|^\.env(?:\..*)?$")
_PRIVKEY_NAME = re.compile(r"(?i)\.(?:pem|key)$")
#: Public trust material that shares those suffixes (CA bundles, certificates).
_PUBLIC_HINT = re.compile(r"(?i)(?:\bca\b|ca[-_.]|[-_.]ca\b|cacert|bundle|truststore|chain|public|pub[-_.]|-pub\b|pubkey|cert)")
_PEM_PRIVATE = re.compile(r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----(.*?)-----END (?:[A-Z]+ )?PRIVATE KEY-----", re.S)
#: A PEM body shorter than this is a placeholder in documentation, not a key.
PEM_MIN_BODY = 128


def committed_secret_reason(name: str, text: str) -> str | None:
    """Why this file is secret material, or None. Never names the value."""
    if _SECRET_NAME.search(name):
        return f"credential file ({name})"
    if _PRIVKEY_NAME.search(name) and not _PUBLIC_HINT.search(name):
        return f"private-key file ({name})"
    for m in _PEM_PRIVATE.finditer(text):
        if len(re.sub(r"\s+", "", m.group(1))) >= PEM_MIN_BODY:
            return "contains a PEM PRIVATE KEY block"
    return None


@dataclass(frozen=True)
class Finding:
    artifact: str
    member: str
    reason: str

    def __str__(self) -> str:
        where = f"{self.artifact}:{self.member}" if self.member else self.artifact
        return f"{where}: {self.reason}"


class ScanError(RuntimeError):
    """The scan could not run (fail closed: exit 2)."""


def _norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _underscored(name: str) -> str:
    return re.sub(r"[-_.]+", "_", name).lower()


#: Test doubles and the conformance runner ship only in the test-only
#: watchlight-agent-sdk-testing distribution, never in a published
#: plugin. A module by one of these names, or any *mock* module, is a test
#: module in the package.
TEST_ONLY_LEAVES = ("testing.py", "conformance.py", "_doubles.py")
#: ...and so is code that defines the double or imports the test-only
#: package (a docstring that names it is fine).
TEST_ONLY_CODE = re.compile(
    r"(?m)^[ \t]*(?:class[ \t]+MockApdpClient\b|(?:from|import)[ \t]+watchlight_core_testing\b)")
#: The distributions whose own modules are test doubles by design. Every
#: other check (contents, text, metadata) still applies to them.
TEST_DOUBLE_DISTS = frozenset({"watchlight-agent-sdk-testing"})


def text_findings(artifact: str, member: str, data: bytes, *, doubles: bool = False) -> list[Finding]:
    if len(data) > MAX_SCAN:
        return [Finding(artifact, member, f"{len(data)} bytes, over the {MAX_SCAN}-byte scan limit: "
                                          "not scanned, so it cannot ship")]
    out = []
    text = data.decode("utf-8", errors="replace")
    for label, rx in TEXT_RULES:
        m = rx.search(text)
        if m:
            line = text.count("\n", 0, m.start()) + 1
            out.append(Finding(artifact, member, f"{label} at line {line}"))
    reason = committed_secret_reason(os.path.basename(member), text)
    if reason:
        out.append(Finding(artifact, member, reason))
    if member.endswith(".py") and not doubles:
        m = TEST_ONLY_CODE.search(text)
        if m:
            line = text.count("\n", 0, m.start()) + 1
            out.append(Finding(artifact, member, f"test double or test-only import at line {line}"))
    return out


def _module_member(rel: str, module: str, *, doubles: bool = False) -> bool:
    """A file of the package itself: <module>/**.py or <module>/py.typed,
    never a test module (a test double only when `doubles`)."""
    parts = rel.split("/")
    if parts[0] != module or len(parts) < 2:
        return False
    if any(p in ("tests", "test", "testing", "__pycache__") for p in parts[1:-1]):
        return False
    leaf = parts[-1]
    if leaf == "conftest.py" or leaf.startswith("test_") or leaf.endswith("_test.py"):
        return False
    if not doubles and (leaf in TEST_ONLY_LEAVES or (leaf.endswith(".py") and "mock" in leaf.lower())):
        return False
    return leaf == "py.typed" or leaf.endswith(".py")


def _metadata_findings(artifact: str, member: str, raw: bytes, dist: str, version: str) -> list[Finding]:
    msg = HeaderParser().parsestr(raw.decode("utf-8", errors="replace"))
    out = []
    if _norm(msg.get("Name", "")) != _norm(dist):
        out.append(Finding(artifact, member, f"Name is {msg.get('Name')!r}, expected {dist!r}"))
    if msg.get("Version", "") != version:
        out.append(Finding(artifact, member, f"Version is {msg.get('Version')!r}, expected {version!r}"))
    if not (msg.get("License-Expression", "").strip() or msg.get("License", "").strip()):
        out.append(Finding(artifact, member, "no licence declared (License or License-Expression)"))
    urls: dict[str, str] = {}
    for value in msg.get_all("Project-URL") or []:
        label, _, url = value.partition(",")
        urls[label.strip()] = url.strip()
    for label, want in REQUIRED_URLS.items():
        got = urls.get(label)
        if got is None:
            out.append(Finding(artifact, member, f"no Project-URL {label!r} (want {want})"))
        elif got.rstrip("/") != want:
            out.append(Finding(artifact, member, f"Project-URL {label!r} is {got!r}, want {want}"))
    return out


def scan_wheel(path: Path, dist: str, module: str, version: str) -> list[Finding]:
    art = path.name
    out: list[Finding] = []
    distinfo = f"{_underscored(dist)}-{version}.dist-info"
    doubles = dist in TEST_DOUBLE_DISTS
    licence_seen = False
    metadata = None
    try:
        with zipfile.ZipFile(path) as zf:
            for info in zf.infolist():
                name = info.filename
                if info.is_dir():
                    continue
                if name.startswith(distinfo + "/"):
                    rel = name[len(distinfo) + 1:]
                    if rel in WHEEL_META:
                        pass
                    elif rel.startswith("licenses/") and os.path.basename(rel) in LICENSE_NAMES:
                        licence_seen = True
                    else:
                        out.append(Finding(art, name, "not on the wheel allowlist"))
                elif not _module_member(name, module, doubles=doubles):
                    out.append(Finding(art, name, "not on the wheel allowlist"))
                data = zf.read(info)
                if name == f"{distinfo}/METADATA":
                    metadata = data
                out.extend(text_findings(art, name, data, doubles=doubles))
    except (OSError, zipfile.BadZipFile) as exc:
        raise ScanError(f"{path}: cannot read the wheel: {exc}") from exc
    if metadata is None:
        out.append(Finding(art, f"{distinfo}/METADATA", "missing"))
    else:
        out.extend(_metadata_findings(art, f"{distinfo}/METADATA", metadata, dist, version))
    if not licence_seen:
        out.append(Finding(art, f"{distinfo}/licenses/LICENSE", "no licence file in the wheel"))
    return out


def scan_sdist(path: Path, dist: str, module: str, version: str) -> list[Finding]:
    art = path.name
    out: list[Finding] = []
    top = f"{_underscored(dist)}-{version}"
    egg = f"{_underscored(dist)}.egg-info"
    doubles = dist in TEST_DOUBLE_DISTS
    pkg_info = None
    licence_seen = False
    try:
        with tarfile.open(path, "r:gz") as tf:
            for m in tf.getmembers():
                name = m.name
                if m.isdir():
                    continue
                if not m.isfile():
                    out.append(Finding(art, name, "not a regular file (link or device)"))
                    continue
                if not name.startswith(top + "/"):
                    out.append(Finding(art, name, f"outside {top}/"))
                    continue
                rel = name[len(top) + 1:]
                if rel in SDIST_TOP:
                    licence_seen = licence_seen or rel in LICENSE_NAMES
                elif rel.startswith(egg + "/") and rel[len(egg) + 1:] in EGG_INFO:
                    pass
                elif not _module_member(rel, module, doubles=doubles):
                    out.append(Finding(art, name, "not on the sdist allowlist"))
                fh = tf.extractfile(m)
                if fh is None:  # pragma: no cover - isfile() above
                    raise ScanError(f"{path}: cannot read {name}")
                data = fh.read()
                if rel == "PKG-INFO":
                    pkg_info = data
                out.extend(text_findings(art, name, data, doubles=doubles))
    except (OSError, tarfile.TarError) as exc:
        raise ScanError(f"{path}: cannot read the sdist: {exc}") from exc
    if pkg_info is None:
        out.append(Finding(art, f"{top}/PKG-INFO", "missing"))
    else:
        out.extend(_metadata_findings(art, f"{top}/PKG-INFO", pkg_info, dist, version))
    if not licence_seen:
        out.append(Finding(art, f"{top}/LICENSE", "no licence file in the sdist"))
    return out


_WHEEL_RX = re.compile(r"^(?P<name>[A-Za-z0-9_.]+)-(?P<version>[^-]+)-[^-]+-[^-]+-[^-]+\.whl$")
_SDIST_RX = re.compile(r"^(?P<name>[A-Za-z0-9_.-]+?)-(?P<version>[0-9][^-]*)\.tar\.gz$")


def pyproject_version(plugin: str, root: Path | None = None) -> str:
    root = root or ROOT
    if tomllib is None:  # pragma: no cover
        raise ScanError("python 3.11+ is required (tomllib)")
    with (root / PACKAGES_REL / plugin / "pyproject.toml").open("rb") as fh:
        return str(tomllib.load(fh)["project"]["version"])


def scan_dist_dir(dist_dir: Path, *, expect: list[str] | None = None,
                  root: Path | None = None) -> list[Finding]:
    """Scan every file in `dist_dir`. Each must be a wheel or an sdist of a
    published plugin, and each plugin present (or each in `expect`) must have
    exactly one of each, at its pyproject.toml version."""
    root = root or ROOT
    by_dist = {_norm(d): (plugin, d, mod) for plugin, (d, mod) in PUBLISHED_PLUGINS.items()}
    found: dict[str, dict[str, list[Path]]] = {}
    out: list[Finding] = []
    files = sorted(p for p in dist_dir.iterdir())
    if not files:
        raise ScanError(f"{dist_dir}: no distributions to scan")
    for p in files:
        m = _WHEEL_RX.match(p.name) or _SDIST_RX.match(p.name)
        kind = "wheel" if p.name.endswith(".whl") else "sdist"
        if not p.is_file() or not m or _norm(m.group("name")) not in by_dist:
            out.append(Finding(p.name, "", "not a wheel or sdist of a published plugin"))
            continue
        found.setdefault(_norm(m.group("name")), {}).setdefault(kind, []).append(p)
    wanted = {_norm(PUBLISHED_PLUGINS[p][0]) for p in expect} if expect else set(found)
    for key in sorted(wanted | set(found)):
        plugin, dist, module = by_dist[key]
        kinds = found.get(key, {})
        if key not in wanted:
            out.append(Finding(dist, "", "built but not selected"))
        version = pyproject_version(plugin, root)
        for kind in ("wheel", "sdist"):
            paths = kinds.get(kind, [])
            if len(paths) != 1:
                out.append(Finding(dist, "", f"expected one {kind}, found {len(paths)}"))
            for path in paths:
                m = _WHEEL_RX.match(path.name) or _SDIST_RX.match(path.name)
                assert m is not None
                if m.group("version") != version:
                    out.append(Finding(path.name, "", f"version {m.group('version')} is not the "
                                                      f"pyproject.toml version {version}"))
                    continue
                scan = scan_wheel if kind == "wheel" else scan_sdist
                out.extend(scan(path, dist, module, version))
    return out


def _tracked_files(plugin: str, root: Path) -> list[str]:
    try:
        out = subprocess.run(["git", "-C", str(root), "ls-files", "-z", "--", f"{PACKAGES_REL}/{plugin}"],
                             check=True, capture_output=True).stdout
    except (OSError, subprocess.CalledProcessError) as exc:
        raise ScanError(f"git ls-files {PACKAGES_REL}/{plugin} failed: {exc}") from exc
    files = [f for f in out.decode().split("\0") if f]
    if not files:
        raise ScanError(f"{PACKAGES_REL}/{plugin}: no tracked files")
    return files


def build_plugins(plugins: list[str], out_dir: Path, *, python: str, root: Path | None = None) -> None:
    """Build each plugin's wheel and sdist into out_dir, offline, from a copy
    of its tracked files (what the publish workflow's fresh checkout holds;
    never a stale build/ or an untracked file of this worktree)."""
    root = root or ROOT
    with tempfile.TemporaryDirectory(prefix="plugin-dist-src-") as tmp:
        for plugin in plugins:
            src = Path(tmp) / plugin
            for rel in _tracked_files(plugin, root):
                dest = src / Path(rel).relative_to(f"{PACKAGES_REL}/{plugin}")
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(root / rel, dest)
            cmd = [python, "-m", "build", "--no-isolation", "--sdist", "--wheel",
                   "--outdir", str(out_dir), str(src)]
            env = {**os.environ, "PIP_NO_INDEX": "1", "SOURCE_DATE_EPOCH": "315532800"}
            proc = subprocess.run(cmd, capture_output=True, text=True, env=env)
            if proc.returncode != 0:
                tail = "\n".join((proc.stdout + proc.stderr).splitlines()[-30:])
                raise ScanError(f"building {PACKAGES_REL}/{plugin} failed:\n{tail}")


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--build", action="store_true", help="build each plugin offline, then scan")
    mode.add_argument("--dist", type=Path, help="scan the distributions in this directory")
    ap.add_argument("--plugin", action="append", default=[],
                    help="a package directory under integrations/plugins/python (repeatable; default: every published package)")
    ap.add_argument("--python", default=sys.executable, help="interpreter that runs `python -m build`")
    ap.add_argument("--out", type=Path,
                    help="with --build: keep the scanned distributions in this directory (must not exist)")
    args = ap.parse_args(argv)
    if args.out is not None and not args.build:
        print("check_dist: --out needs --build", file=sys.stderr)
        return 2
    unknown = [p for p in args.plugin if p not in PUBLISHED_PLUGINS]
    if unknown:
        print(f"check_dist: not a published plugin: {', '.join(unknown)}", file=sys.stderr)
        return 2
    plugins = args.plugin or list(PUBLISHED_PLUGINS)
    created = False
    try:
        if args.build and args.out is not None:
            if args.out.exists():
                raise ScanError(f"{args.out}: already exists; --out needs a new directory")
            args.out.mkdir(parents=True)
            created = True
            build_plugins(plugins, args.out, python=args.python)
            findings = scan_dist_dir(args.out, expect=plugins)
            if findings:
                shutil.rmtree(args.out)  # nothing that failed is left to upload
        elif args.build:
            with tempfile.TemporaryDirectory(prefix="plugin-dist-") as out:
                build_plugins(plugins, Path(out), python=args.python)
                findings = scan_dist_dir(Path(out), expect=plugins)
        else:
            if not args.dist.is_dir():
                raise ScanError(f"{args.dist}: not a directory")
            findings = scan_dist_dir(args.dist, expect=args.plugin or None)
    except ScanError as exc:
        if created:
            shutil.rmtree(args.out)  # a partial build is never left to upload
        print(f"::error::check_dist could not run: {exc}", file=sys.stderr)
        return 2
    for f in findings:
        print(f"::error::{f}")
    if findings:
        print(f"check_dist: {len(findings)} finding(s); nothing that fails here may be published.",
              file=sys.stderr)
        return 1
    print(f"check_dist: {len(plugins) if args.build else 'every'} plugin distribution(s) clean "
          "(allowlisted contents, no internal or secret-like text, public repository URLs, licence).")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
