#!/usr/bin/env bash
# Everything that has to be green before you open a pull request, in one command.
#
#   scripts/preflight.sh
#
# It runs five things, in this order:
#
#   1. the Python suite            tests/                       — the fastest
#   2. the TypeScript suite        ts/ (builds first)              signal, and
#   3. the patterns check          examples/patterns/check.sh      the rest need
#   4. the showcase check          examples/showcase/check.sh      the build
#   5. the adversarial harness     scripts/adversarial-harness.mjs
#
# Cheapest and most fundamental first: the two unit suites tell you what broke
# in the smallest terms, and steps 3 to 5 all run against the TypeScript build
# that step 2 produces. It does NOT stop at the first failure. A preflight is
# something you run to find out everything that is wrong before you push, not
# something you run five times to be told about one problem at a time. Every
# step runs, every step's output is printed, and the summary at the end names
# the ones that failed.
#
# The one thing it does stop for is a missing prerequisite — exit 3, distinct
# from the exit 1 that means something actually failed. A suite that cannot run
# tells you nothing, and a missing interpreter reported as a wall of failing
# lanes is worse than no run at all: it reads as drift in the code rather than
# as a PATH problem. The showcase runner draws the same distinction, through the
# same helpers.
#
# From a fresh clone:
#
#   * The Node side is set up for you — `npm install` and `npm run build` in ts/.
#     Both write only inside the clone, to git-ignored build output, so there is
#     nothing to surprise you.
#
#   * The Python side is never installed for you. Which interpreter this repo
#     should be installed into is your choice — a venv, uv, conda, the system
#     one — and quietly installing into whichever one happens to be active is
#     exactly the kind of surprise a preflight must not spring. It looks for
#     ./.venv first, then `python3`, and if neither can import `watchlight` it
#     stops and prints the exact commands.
#
# Environment:
#   WL_PYTHON   use this interpreter instead of ./.venv or python3
#   WL_VERBOSE  set to 1 for the showcase check's passing-lane output too
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/.." && pwd)"
cd "$repo" || exit 2

bold=""; plain=""
if [ -t 1 ]; then bold=$'\033[1m'; plain=$'\033[0m'; fi

die() { echo; echo "preflight: $*" >&2; exit 3; }

# ── prerequisites ────────────────────────────────────────────────────────────

# One copy of "which interpreter, and what to say when there is not one".
# examples/showcase/check.sh and every showcase's own check.sh resolve the
# toolchain through these same helpers, so all three agree on the answer and on
# the advice — and none of them reports a missing prerequisite as a test failure.
WL_CHECK_LIB_ONLY=1 . "$repo/examples/showcase/_check_lib.sh"

echo "${bold}== preflight: prerequisites ==${plain}"

wl_require_python || exit 3
PY="$WL_PYTHON"
echo "  python   $PY  ($("$PY" - <<'PYVER' 2>/dev/null
from importlib.metadata import version
print("watchlight", version("watchlight"), "/ engine", version("watchlight-engine"))
PYVER
))"

"$PY" -c 'import pytest' >/dev/null 2>&1 || die "pytest is missing. Install it:

    $PY -m pip install pytest"

wl_require_node || exit 3
command -v npm >/dev/null 2>&1 || die "no 'npm' on PATH. Install Node >= 18 (npm ships with it)."
echo "  node     $(node -v)"

# Node dependencies and build: set up in place, because both are git-ignored
# build output inside this clone.
if [ ! -d "$repo/ts/node_modules" ]; then
  echo "  ts/node_modules missing — running 'npm install' in ts/"
  (cd "$repo/ts" && npm install) >/dev/null 2>&1 \
    || die "'npm install' failed in ts/. Run it by hand to see why:

    cd ts && npm install"
fi
echo "  building the TypeScript SDK"
(cd "$repo/ts" && npm run build) >/dev/null 2>&1 \
  || die "the TypeScript build failed. Run it by hand to see why:

    cd ts && npm run build"
echo "  ts/dist  built"

# The Node lanes and the harness resolve the SDK from an installed package or
# from the build above. Assert it here rather than letting every .mjs lane fail
# identically further down.
wl_require_node_sdk || exit 3

# ── the steps ────────────────────────────────────────────────────────────────

names=()
codes=()

step() {
  local name="$1"; shift
  echo
  echo "${bold}══ $name ══${plain}"
  "$@"
  local code=$?
  names+=("$name")
  codes+=("$code")
  if [ "$code" -eq 0 ]; then echo "── $name: OK"; else echo "── $name: FAILED (exit $code)"; fi
  return 0
}

step "python suite"        "$PY" -m pytest "$repo/tests" -q
step "typescript suite"    bash -c "cd '$repo/ts' && npm test"
step "patterns check"      "$repo/examples/patterns/check.sh"
step "showcase check"      "$repo/examples/showcase/check.sh"
step "adversarial harness" node "$repo/scripts/adversarial-harness.mjs"

# ── summary ──────────────────────────────────────────────────────────────────

failed=0
echo
echo "${bold}════════════════════════════════════════════════════════════════════════${plain}"
echo "${bold}preflight summary${plain}"
for i in "${!names[@]}"; do
  if [ "${codes[$i]}" -eq 0 ]; then
    printf '  %-22s OK\n' "${names[$i]}"
  else
    printf '  %-22s FAILED (exit %s)\n' "${names[$i]}" "${codes[$i]}"
    failed=$((failed + 1))
  fi
done
echo

if [ "$failed" -ne 0 ]; then
  echo "${bold}PREFLIGHT FAILED${plain} — $failed of ${#names[@]} steps. Scroll up for the output of each."
  exit 1
fi
echo "${bold}PREFLIGHT OK${plain} — all ${#names[@]} steps green. Open the pull request."
