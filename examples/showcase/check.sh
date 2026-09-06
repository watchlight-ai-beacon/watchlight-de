#!/usr/bin/env bash
# Verify every showcase in this folder.
#
#   1. Every showcase directory must DECLARE how it is checked, in an executable
#      `check.sh` of its own. A showcase with none FAILS the run — the same rule
#      examples/patterns/check.sh applies to pattern docs, for the same reason: a
#      showcase that cannot be verified cannot be kept from drifting.
#
#      Declaration, rather than globbing the scripts in each folder, because the
#      showcases are order- and state-dependent. audit-forensics/forensics.py
#      exits 1 before its trail is generated and 0 after; human-in-the-loop is a
#      three-phase sequence whose agent.py is a usage error on its own and whose
#      hitl.py is a helper module that exits 0 having checked nothing. A globbing
#      runner gives false failures on the first and a false pass on the second,
#      and its verdict depends on what the previous run left on disk. Each
#      check.sh states the order, and starts from a clean directory.
#
#   2. A missing OPTIONAL prerequisite is a SKIP, not a pass and not a failure —
#      examples/showcase/web-backend needs FastAPI or Express, which neither
#      `watchlight` nor @watchlight/sdk depends on. Skips are counted and listed
#      at the end, so a run that skipped half the showcases cannot be read as a
#      clean one. Core prerequisites — Python, Node, the policy CLI — are never
#      skipped; without them this script refuses to run at all.
#
#   3. Scans the folder for credential-shaped strings. (Unlike the patterns
#      check, this one does NOT flag e-mail addresses: several showcases carry
#      synthetic personal data on purpose, because redaction and screening are
#      what they demonstrate.)
#
# Requires: Python 3.9+ with `pip install watchlight`, and Node >= 18 with
# @watchlight/sdk — installed globally, or built in this clone with
# `cd ts && npm install && npm run build`.
#
#   examples/showcase/check.sh            # from anywhere
#   WL_VERBOSE=1 examples/showcase/check.sh   # print passing lanes' output too
#   examples/showcase/<name>/check.sh      # one showcase on its own
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../.." && pwd)"

# ── core prerequisites: refuse to run rather than turn every lane red ─────────
#
# The toolchain resolution lives in _check_lib.sh, so this runner, each showcase
# run on its own, and scripts/preflight.sh all choose the SAME interpreter the
# same way and give the same advice when there is not one. It matters here more
# than it looks: an interpreter that cannot import `watchlight` fails every
# Python lane in every showcase, and a wall of red lanes reads as drift in the
# examples rather than as a PATH problem. Exit 3 says "could not run", loudly,
# before a single lane does.
WL_CHECK_LIB_ONLY=1 . "$here/_check_lib.sh"
wl_require_toolchain || exit 3
echo "python: $WL_PYTHON"
echo "node:   $(node -v)"
echo

tally="$(mktemp -t wl-showcase-tally)"
trap 'rm -f "$tally"' EXIT
export WL_TALLY="$tally"

undeclared=()
sc_pass=0
sc_skip=0
sc_fail=0

echo "== every showcase declares how it is checked =="
for dir in "$here"/*/; do
  name="$(basename "$dir")"
  if [ -x "$dir/check.sh" ]; then
    echo "  ✓ $name — check.sh"
  elif [ -f "$dir/check.sh" ]; then
    echo "  ✗ $name — check.sh is not executable (chmod +x)" >&2
    undeclared+=("$name")
  else
    echo "  ✗ $name — no check.sh; a showcase nothing runs will drift" >&2
    undeclared+=("$name")
  fi
done

echo
echo "== running the showcases =="
for dir in "$here"/*/; do
  name="$(basename "$dir")"
  [ -x "$dir/check.sh" ] || continue
  echo "--- $name"
  "$dir/check.sh"
  case "$?" in
    0) sc_pass=$((sc_pass + 1)) ;;
    2) sc_skip=$((sc_skip + 1)); echo "    ○ SKIPPED ENTIRELY — every lane needed a prerequisite that is missing" ;;
    *) sc_fail=$((sc_fail + 1)) ;;
  esac
done

echo
echo "== hygiene: no credentials in the showcases =="
# Deliberately narrower than the patterns check: the showcase corpora contain
# synthetic e-mail addresses and names, because sanitizing them is the point.
# Real credentials never belong here in any form.
if grep -RInE \
     -e '\bAKIA[0-9A-Z]{16}\b' \
     -e '\b(sk|ghp|gho|xox[baprs])[-_][A-Za-z0-9]{16,}\b' \
     -e '[Bb]earer [A-Za-z0-9._-]{40,}' \
     -e '-----BEGIN [A-Z ]*PRIVATE KEY-----' \
     --include='*.md' --include='*.json' --include='*.mjs' --include='*.py' \
     --include='*.sh' --include='*.yml' --include='*.txt' \
     --exclude-dir=node_modules --exclude-dir=.watchlight --exclude-dir=trail \
     "$here"; then
  echo "error: the match above looks like a credential — the showcases must carry none" >&2
  cred=1
else
  echo "clean — no keys, tokens, or private keys found"
  cred=0
fi

# ── summary ──────────────────────────────────────────────────────────────────
# grep -c prints 0 and exits 1 when nothing matches; the count is what we want.
lane_pass=$(grep -c '^PASS' "$tally"); lane_skip=$(grep -c '^SKIP' "$tally"); lane_fail=$(grep -c '^FAIL' "$tally")

echo
echo "════════════════════════════════════════════════════════════════════════"
echo "showcases:  $sc_pass passed   $sc_skip skipped   $sc_fail failed   ${#undeclared[@]} undeclared"
echo "lanes:      $lane_pass passed   $lane_skip skipped   $lane_fail failed"

if [ "$lane_skip" -gt 0 ]; then
  echo
  echo "SKIPPED — these did NOT run, and this run says nothing about them:"
  awk -F'\t' '$1 == "SKIP" { print "  ○ " $2 " — " $3 }' "$tally"
  echo "  install the optional extras named above to cover them"
fi
if [ "$lane_fail" -gt 0 ]; then
  echo
  echo "FAILED:"
  awk -F'\t' '$1 == "FAIL" { print "  ✗ " $2 " — " $3 }' "$tally"
fi
if [ "${#undeclared[@]}" -gt 0 ]; then
  echo
  echo "UNDECLARED — add an executable check.sh to each (see _check_lib.sh):"
  for name in "${undeclared[@]}"; do echo "  ✗ $name"; done
fi

echo
if [ "$sc_fail" -gt 0 ] || [ "$lane_fail" -gt 0 ] || [ "${#undeclared[@]}" -gt 0 ] || [ "$cred" -ne 0 ]; then
  echo "FAILED"
  exit 1
fi
echo "ALL SHOWCASES OK"
