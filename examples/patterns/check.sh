#!/usr/bin/env bash
# Verify every pattern in this folder — and keep it free of private information.
#
#   1. Every pattern doc (`*.md`, except README) must have an executable check:
#      a policy suite `suites/<name>.suite.json` and/or a script
#      `scripts/<name>.mjs`, where <name> is the doc's basename. A pattern with
#      neither FAILS the run — a pattern that cannot be verified cannot be kept
#      from drifting.
#   2. Runs each suites/*.suite.json through `watchlight policy test`, so the
#      verdicts shown in the pattern docs can never drift from the real engine.
#   3. Runs each scripts/*.mjs with Node. Scripts cover the parts of a pattern
#      that are not a policy verdict — `sanitize`, scope attenuation, the audit
#      sink — against the real SDK, and exit non-zero on any failed assertion.
#      (`scripts/_*.mjs` are shared helpers, not patterns.)
#   4. Scans the folder for anything that looks like private data (emails, keys,
#      tokens) — patterns are generic problem shapes, never customer stories.
#
# Requires the DE installed:  npm i -g @watchlight/sdk   (or: pip install watchlight
# for the suites, plus Node >= 18 with the SDK for the scripts). Without a
# `watchlight` on PATH the suites run via `npx -p @watchlight/sdk watchlight`. Scripts resolve
# the SDK from the global npm root or from an in-repo build (`cd ts && npm run build`).
# Run from the repo root or anywhere:  examples/patterns/check.sh
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Pick whichever CLI is installed.
if command -v watchlight >/dev/null 2>&1; then
  run() { watchlight policy test "$1"; }
elif command -v npx >/dev/null 2>&1; then
  # Pin the package that owns the `watchlight` bin — never the unscoped name.
  run() { npx --yes -p @watchlight/sdk watchlight policy test "$1"; }
else
  echo "error: install the DE first — 'pip install watchlight' or 'npm i -g @watchlight/sdk'" >&2
  exit 2
fi

fail=0

echo "== every pattern has an executable check =="
for doc in "$here"/*.md; do
  name="$(basename "$doc" .md)"
  [ "$name" = "README" ] && continue
  have=()
  [ -f "$here/suites/$name.suite.json" ] && have+=("suites/$name.suite.json")
  [ -f "$here/scripts/$name.mjs" ] && have+=("scripts/$name.mjs")
  if [ "${#have[@]}" -eq 0 ]; then
    echo "  ✗ $name.md — no suites/$name.suite.json and no scripts/$name.mjs" >&2
    fail=1
  else
    echo "  ✓ $name.md — ${have[*]}"
  fi
done

echo
echo "== running pattern suites =="
for suite in "$here"/suites/*.suite.json; do
  echo "--- $(basename "$suite")"
  run "$suite" || fail=1
done

echo
echo "== running pattern scripts =="
if ! command -v node >/dev/null 2>&1; then
  echo "error: pattern scripts need Node >= 18 — install it (and 'npm i -g @watchlight/sdk')" >&2
  fail=1
else
  # Let a globally installed @watchlight/sdk resolve from the scripts.
  if command -v npm >/dev/null 2>&1; then
    export NODE_PATH="${NODE_PATH:+$NODE_PATH:}$(npm root -g 2>/dev/null || true)"
  fi
  for script in "$here"/scripts/*.mjs; do
    case "$(basename "$script")" in _*) continue ;; esac
    echo "--- $(basename "$script")"
    node "$script" || fail=1
  done
fi

echo
echo "== hygiene: no private information in patterns =="
# Generic markers only — we never hard-code a name here (that would itself leak one).
# Emails, obvious cloud keys, and bearer tokens have no place in a generic pattern.
if grep -RInE \
     -e '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}' \
     -e '\bAKIA[0-9A-Z]{16}\b' \
     -e '\b(sk|ghp|xox[baprs])[-_][A-Za-z0-9]{16,}\b' \
     -e '[Bb]earer [A-Za-z0-9._-]{20,}' \
     --include='*.md' --include='*.json' --include='*.mjs' \
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
