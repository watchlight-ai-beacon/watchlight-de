#!/usr/bin/env bash
# test_regen.sh — positive controls for `regen.sh --check`: a lock edited by
# hand must fail it (exit 1, not 2), and the committed locks must pass.
#
#   ci/test_regen.sh
#
# Needs what regen.sh needs: the pinned uv (ci/tools.txt) and PyPI.
set -euo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
work=$(mktemp -d "${TMPDIR:-/tmp}/test-regen.XXXXXX")
trap 'rm -rf "$work"' EXIT
fails=0

# expect_fail NAME LOCK EDIT: EDIT (python that sets `t` from `s`, the lock's
# text) applied to a copy of the committed lock must fail the check.
expect_fail() {
  local name=$1 lock=$2 edit=$3 dir="$work/$1"
  mkdir -p "$dir"
  cp "$HERE"/*.txt "$dir/"
  python3 -I -c 'import sys; p=sys.argv[1]; s=open(p).read(); g={"s": s}; exec(sys.argv[2], g); t=g["t"]; assert t != s, "the edit changed nothing"; open(p,"w").write(t)' \
    "$dir/$lock.txt" "$edit"
  local rc=0
  "$HERE/regen.sh" --check --against "$dir" "$lock" >"$dir/out" 2>&1 || rc=$?
  if [ "$rc" -eq 1 ]; then
    echo "ok: $name fails the check"
  else
    echo "FAIL: $name: the check exited $rc, not 1"; cat "$dir/out"; fails=1
  fi
}

# A hash changed by hand.
expect_fail hash-edited engine 'import re; t = re.sub(r"sha256:([0-9a-f])", lambda m: "sha256:" + ("0" if m.group(1) != "0" else "1"), s, count=1)'
# An entry removed by hand.
expect_fail entry-removed dist 'import re; t = re.sub(r"(?ms)^wheel==.*?(?=^\S|\Z)", "", s)'
# An entry added by hand.
expect_fail entry-added dist 't = s + "six==1.17.0 \\\n    --hash=sha256:4721f391ed90541fddacab5acf947aa0d3dc7d27b2e1e8eda2be8970586c3274\n"'
# A pin the inputs do not allow (engine.in asks >=0.2.5).
expect_fail pin-outside-inputs engine 't = s.replace("watchlight-engine==0.2.5", "watchlight-engine==0.2.4")'
# The header edited by hand.
expect_fail header-edited plugins 't = s.replace("do not edit by hand", "edit freely", 1)'

# The compile resolves from wheels only, so it never builds an sdist (which
# would run code from PyPI).
if grep -q -- '--only-binary :all:' "$HERE/regen.sh"; then
  echo "ok: the compile is wheels only"
else
  echo "FAIL: regen.sh compiles without --only-binary :all:"; fails=1
fi

# Any uv but the pinned one is refused (exit 2), since its output can differ.
mkdir -p "$work/fake-uv"
printf '#!/bin/sh\necho "uv 0.0.1"\n' >"$work/fake-uv/uv"
chmod +x "$work/fake-uv/uv"
rc=0
PATH="$work/fake-uv:$PATH" "$HERE/regen.sh" --check engine >"$work/fake-uv/out" 2>&1 || rc=$?
if [ "$rc" -eq 2 ] && grep -q "is not the pinned uv" "$work/fake-uv/out"; then
  echo "ok: another uv is refused"
else
  echo "FAIL: another uv: the check exited $rc, not 2"; cat "$work/fake-uv/out"; fails=1
fi

# Every committed lock reproduces.
if "$HERE/regen.sh" --check; then
  echo "ok: every committed lock reproduces"
else
  fails=1
fi
exit $fails
