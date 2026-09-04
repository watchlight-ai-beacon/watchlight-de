#!/usr/bin/env bash
# Reproduce the CI gate locally: the correct policy must pass (exit 0) and the
# widened policy must fail (exit 1) — in whichever lanes are installed.
#
#   pip install watchlight          # Python lane
#   npm install -g @watchlight/sdk  # TypeScript lane
#   examples/showcase/policy-tests-ci/run-local.sh
#
# With neither on PATH, an in-repo TypeScript build (`cd ts && npm run build`)
# is used. Also checks that the two suites carry identical fixtures — only
# `policyFile` may differ between them.
set -uo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export NO_COLOR=1
fail=0

lanes=()
if command -v watchlight >/dev/null 2>&1; then
  # Whichever package owns the `watchlight` bin — both CLIs accept `policy test`.
  lanes+=("watchlight")
fi
if [ -f "$here/../../../ts/dist/cli.js" ]; then
  lanes+=("node $here/../../../ts/dist/cli.js")
fi
if [ "${#lanes[@]}" -eq 0 ]; then
  echo "error: no lane available — 'pip install watchlight', 'npm i -g @watchlight/sdk', or 'cd ts && npm run build'" >&2
  exit 2
fi

echo "== fixtures identical in both suites (only policyFile differs) =="
if command -v python3 >/dev/null 2>&1; then
  python3 - "$here/tickets.suite.json" "$here/widened/tickets.suite.json" <<'PY' || fail=1
import json, sys
a, b = (json.load(open(p)) for p in sys.argv[1:3])
if a["tests"] != b["tests"]:
    print("  ✗ the widened suite's fixtures differ from tickets.suite.json"); sys.exit(1)
print(f"  ✓ {len(a['tests'])} fixtures, identical in both suites")
PY
else
  node -e '
    const fs = require("fs"); const [a, b] = process.argv.slice(1).map((p) => JSON.parse(fs.readFileSync(p, "utf8")));
    if (JSON.stringify(a.tests) !== JSON.stringify(b.tests)) { console.log("  ✗ the widened suite fixtures differ"); process.exit(1); }
    console.log(`  ✓ ${a.tests.length} fixtures, identical in both suites`);
  ' "$here/tickets.suite.json" "$here/widened/tickets.suite.json" || fail=1
fi

for lane in "${lanes[@]}"; do
  echo
  echo "== lane: $lane =="
  echo "--- correct policy (must pass)"
  if $lane policy test "$here/tickets.suite.json"; then
    echo "  ✓ exit 0"
  else
    echo "  ✗ the correct policy failed the suite (exit $?)"; fail=1
  fi
  echo "--- widened policy (must fail)"
  if $lane policy test "$here/widened/tickets.suite.json"; then
    echo "  ✗ the widened policy PASSED — the suite is not gating"; fail=1
  else
    code=$?
    if [ "$code" -eq 1 ]; then echo "  ✓ exit 1"; else echo "  ✗ unexpected exit $code (malformed suite?)"; fail=1; fi
  fi
done

echo
if [ "$fail" -ne 0 ]; then echo "FAILED"; exit 1; fi
echo "GATE OK — correct policy passes, widened policy fails"
