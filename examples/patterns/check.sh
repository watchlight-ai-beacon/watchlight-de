#!/usr/bin/env bash
# Verify every pattern in this folder — and keep it free of private information.
#
#   1. Runs each suites/*.suite.json through `watchlight policy test`, so the
#      verdicts shown in the pattern docs can never drift from the real engine.
#   2. Scans the folder for anything that looks like private data (emails, keys,
#      tokens) — patterns are generic problem shapes, never customer stories.
#
# Requires the DE installed:  pip install watchlight   (or: npm i -g @watchlight/sdk)
# Run from the repo root or anywhere:  examples/patterns/check.sh
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Pick whichever CLI is installed.
if command -v watchlight >/dev/null 2>&1; then
  run() { watchlight policy test "$1"; }
elif command -v npx >/dev/null 2>&1; then
  run() { npx --yes watchlight policy test "$1"; }
else
  echo "error: install the DE first — 'pip install watchlight' or 'npm i -g @watchlight/sdk'" >&2
  exit 2
fi

fail=0

echo "== running pattern suites =="
for suite in "$here"/suites/*.suite.json; do
  echo "--- $(basename "$suite")"
  run "$suite" || fail=1
done

echo
echo "== hygiene: no private information in patterns =="
# Generic markers only — we never hard-code a name here (that would itself leak one).
# Emails, obvious cloud keys, and bearer tokens have no place in a generic pattern.
if grep -RInE \
     -e '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}' \
     -e '\bAKIA[0-9A-Z]{16}\b' \
     -e '\b(sk|ghp|xox[baprs])[-_][A-Za-z0-9]{16,}\b' \
     -e '[Bb]earer [A-Za-z0-9._-]{20,}' \
     --include='*.md' --include='*.json' \
     --exclude-dir=node_modules \
     "$here"; then
  echo "error: the match above looks like private data — patterns must stay generic" >&2
  fail=1
else
  echo "clean — no emails, keys, or tokens found"
fi

echo
if [ "$fail" -ne 0 ]; then echo "FAILED"; exit 1; fi
echo "ALL PATTERNS OK"
