# Shared helpers for the per-showcase check.sh scripts. Sourced, never run.
#
# Every showcase under examples/showcase/ DECLARES how it is verified, in its
# own `check.sh`, because the showcases are order- and state-dependent in ways
# no file-globbing runner can guess:
#
#   * audit-forensics/forensics.py exits 1 until generate_trail.py has written
#     the trail it reads, and exits 0 afterwards — so a run that inherits a
#     previous run's trail passes for the wrong reason.
#   * human-in-the-loop is a three-phase sequence (request → approve → resume)
#     across two files; agent.py on its own is a usage error, and hitl.py is a
#     helper module with no entry point at all — running it exits 0 having
#     verified nothing.
#   * web-backend needs optional web extras and exits 2 saying so.
#
# A declaration is therefore the only honest mechanism, and the rule from
# examples/patterns/check.sh carries over: a showcase with no check.sh FAILS
# the run — one that cannot be verified cannot be kept from drifting.
#
# Writing one:
#
#   #!/usr/bin/env bash
#   . "$(dirname "${BASH_SOURCE[0]}")/../_check_lib.sh"
#   generated .watchlight                  # what a run leaves behind
#   suite policy.suite.json                # golden fixtures through the engine
#   lane "python" py rag.py                # a lane that must succeed
#   lane "node"   node rag.mjs
#   lane_red "python: bad input" py rag.py --broken   # a lane that must FAIL
#   finish
#
# Exit codes — the contract examples/showcase/check.sh reads:
#
#   0  every declared lane ran, and passed
#   1  a lane failed
#   2  nothing ran: every lane skipped a missing OPTIONAL prerequisite
#   3  a CORE prerequisite is missing — not a skip, and never reported as a
#      failed lane. An interpreter that cannot import `watchlight`, or a Node
#      with no SDK to resolve, turns EVERY lane red at once; that reads as drift
#      in the showcase, when the only thing wrong is the environment. It cost a
#      reader time once, so the toolchain is resolved and validated up front and
#      the run refuses to start rather than produce a wall of misleading red.
#
# A lane's own command uses the same convention: exit 2 means "an optional
# prerequisite is missing", which is how examples/showcase/web-backend already
# reports a missing FastAPI or Express. Any other non-zero exit is a failure.
#
# Environment:
#   WL_PYTHON   prefer this interpreter for the Python lanes
#   WL_VERBOSE  set to 1 to print the output of lanes that pass, too
#   WL_TALLY    file the runner collects per-lane results in (set by check.sh)
#   WL_CHECK_LIB_ONLY
#               set before sourcing to get the toolchain helpers below and
#               nothing else — no showcase context, no counters, no `cd`.
#               scripts/preflight.sh sources it this way, so there is one copy
#               of "which interpreter, and what to say when there isn't one".

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# ── toolchain: shared with scripts/preflight.sh ──────────────────────────────

# Echo the first interpreter that can import the package under test. Preference
# order: WL_PYTHON, this clone's .venv, then whatever `python3` is.
wl_pick_python() {
  local candidate
  for candidate in "${WL_PYTHON:-}" "$REPO_ROOT/.venv/bin/python" python3; do
    [ -n "$candidate" ] || continue
    command -v "$candidate" >/dev/null 2>&1 || continue
    if "$candidate" -c 'import watchlight, watchlight_engine' >/dev/null 2>&1; then
      command -v "$candidate"
      return 0
    fi
  done
  return 1
}

# Resolve the interpreter, export it, and put its scripts on PATH — so the
# `watchlight` CLI these checks call is the one from the environment we just
# chose, never an unrelated global. Returns 3 with the setup commands if none
# on hand can import the package.
wl_require_python() {
  local py
  if ! py="$(wl_pick_python)"; then
    {
      echo "error: no interpreter on hand can import 'watchlight'. Set one up:"
      echo
      echo "    python3 -m venv .venv"
      echo "    .venv/bin/pip install -e . pytest"
      echo
      echo "  (or install into your own environment and re-run, or point WL_PYTHON at it)"
    } >&2
    return 3
  fi
  WL_PYTHON="$py"
  export WL_PYTHON
  PATH="$(cd "$(dirname "$py")" && pwd):$PATH"
  export PATH
  return 0
}

wl_require_node() {
  command -v node >/dev/null 2>&1 || {
    echo "error: no 'node' on PATH. Install Node >= 18." >&2
    return 3
  }
  local major
  major="$(node -p 'process.versions.node.split(".")[0]' 2>/dev/null || echo 0)"
  [ "$major" -ge 18 ] 2>/dev/null || {
    echo "error: Node $(node -v) is too old — the SDK needs Node >= 18." >&2
    return 3
  }
  return 0
}

# The Node lanes resolve @watchlight/sdk from an installed package or from this
# clone's build. With neither, every .mjs lane fails identically — a missing
# prerequisite wearing the costume of a broken example.
wl_require_node_sdk() {
  [ -f "$REPO_ROOT/ts/dist/index.js" ] && return 0
  node -e 'require.resolve("@watchlight/sdk")' >/dev/null 2>&1 && return 0
  {
    echo "error: @watchlight/sdk is not available to Node. Install it —"
    echo "         npm i -g @watchlight/sdk"
    echo "       or build it in this clone —"
    echo "         cd ts && npm install && npm run build"
  } >&2
  return 3
}

# `watchlight policy test` — the installed CLI, this clone's build, or npx.
# Pin the package that owns the `watchlight` bin; never the unscoped name.
# Call AFTER wl_require_python, so the chosen environment's CLI wins.
wl_require_cli() {
  if command -v watchlight >/dev/null 2>&1; then
    WL_CLI=(watchlight)
  elif [ -f "$REPO_ROOT/ts/dist/cli.js" ]; then
    WL_CLI=(node "$REPO_ROOT/ts/dist/cli.js")
  elif command -v npx >/dev/null 2>&1; then
    WL_CLI=(npx --yes -p @watchlight/sdk watchlight)
  else
    {
      echo "error: no 'watchlight' CLI. Run one of:"
      echo "         pip install watchlight"
      echo "         npm i -g @watchlight/sdk"
      echo "         (cd $REPO_ROOT/ts && npm install && npm run build)"
    } >&2
    return 3
  fi
  return 0
}

# Everything a showcase needs before a single lane runs. Returns 3, having said
# exactly what to install, if anything is missing.
wl_require_toolchain() {
  wl_require_python || return 3
  wl_require_node || return 3
  wl_require_node_sdk || return 3
  wl_require_cli || return 3
  return 0
}

# scripts/preflight.sh wants the helpers above and nothing below.
if [ -n "${WL_CHECK_LIB_ONLY:-}" ]; then
  return 0
fi

# ── showcase context ─────────────────────────────────────────────────────────

SHOWCASE_DIR="$(cd "$(dirname "${BASH_SOURCE[1]}")" && pwd)"
SHOWCASE="$(basename "$SHOWCASE_DIR")"
cd "$SHOWCASE_DIR" || exit 3

_pass=0
_skip=0
_fail=0
WL_GENERATED=()

wl_require_toolchain || exit 3

# Short alias for a Python lane, so a check.sh reads `py rag.py`.
py() { "$WL_PYTHON" "$@"; }

# ── generated artifacts ──────────────────────────────────────────────────────

# `generated <path>...` — the paths a run of this showcase creates, relative to
# the showcase directory. They are removed BEFORE the first lane and again on
# exit, so no lane can pass on a previous run's leftovers.
generated() {
  local p
  for p in "$@"; do
    case "$p" in
      /*|*..*|"") echo "error: generated() takes paths inside $SHOWCASE, got '$p'" >&2; exit 3 ;;
    esac
  done
  WL_GENERATED=("$@")
  _purge
  trap _purge EXIT
}

_purge() {
  local p
  for p in ${WL_GENERATED+"${WL_GENERATED[@]}"}; do
    rm -rf "${SHOWCASE_DIR:?}/$p"
  done
}

# `regenerate` — drop the artifacts mid-run, so the next lane has to make its
# own. Used where one lane must not read the trail another lane wrote.
regenerate() { _purge; }

# ── lanes ────────────────────────────────────────────────────────────────────

_tally() {
  [ -n "${WL_TALLY:-}" ] && printf '%s\t%s\t%s\n' "$1" "$SHOWCASE" "$2" >>"$WL_TALLY"
  return 0
}

_indent() { sed 's/^/        /'; }

# `lane <name> <command...>` — the command must exit 0. Exit 2 is a skip.
lane() {
  local name="$1"; shift
  local out code
  out="$("$@" 2>&1)"; code=$?
  case "$code" in
    0)
      echo "    ✓ $name"
      [ -n "${WL_VERBOSE:-}" ] && printf '%s\n' "$out" | _indent
      _pass=$((_pass + 1)); _tally PASS "$name"
      ;;
    2)
      echo "    ○ SKIP  $name — optional prerequisite missing:"
      printf '%s\n' "$out" | grep -v '^[[:space:]]*$' | tail -3 | _indent
      _skip=$((_skip + 1)); _tally SKIP "$name"
      ;;
    *)
      echo "    ✗ FAIL  $name (exit $code)"
      printf '%s\n' "$out" | tail -25 | _indent
      _fail=$((_fail + 1)); _tally FAIL "$name"
      ;;
  esac
  return 0
}

# `lane_red <name> <command...>` — the command must FAIL. A showcase that ships
# a deliberately broken input (a widened policy, an unhandled corpus, a missing
# trail) is claiming the check goes red for it; this asserts that it does.
lane_red() {
  local name="$1"; shift
  local out code
  out="$("$@" 2>&1)"; code=$?
  if [ "$code" -ne 0 ] && [ "$code" -ne 2 ]; then
    echo "    ✓ $name (correctly red, exit $code)"
    _pass=$((_pass + 1)); _tally PASS "$name"
  else
    echo "    ✗ FAIL  $name — expected a non-zero exit, got $code"
    printf '%s\n' "$out" | tail -15 | _indent
    _fail=$((_fail + 1)); _tally FAIL "$name"
  fi
  return 0
}

# `suite <file>` — run a policy suite's golden fixtures through the real engine,
# so the verdicts a README quotes can never drift from the engine's.
suite() {
  lane "policy suite: $1" "${WL_CLI[@]}" policy test "$SHOWCASE_DIR/$1"
}

# `finish` — print this showcase's tally and exit on the contract above.
finish() {
  echo "    $SHOWCASE: $_pass passed, $_skip skipped, $_fail failed"
  [ "$_fail" -gt 0 ] && exit 1
  [ "$_pass" -eq 0 ] && exit 2
  exit 0
}
