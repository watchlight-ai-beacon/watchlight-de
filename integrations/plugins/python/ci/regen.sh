#!/usr/bin/env bash
# regen.sh — regenerate, or check, the hash-pinned locks of this directory.
#
#   ci/regen.sh                    regenerate every <name>.txt from its <name>.in
#   ci/regen.sh plugins adk-min    only these
#   ci/regen.sh --check            fail unless regenerating reproduces every
#                                  committed lock byte for byte (CI runs this)
#   ci/regen.sh --check --against DIR [names]
#                                  check the locks in DIR instead (the CI
#                                  positive control uses it)
#
# Each <name>.in lists what one CI job installs: the packages next to this
# directory as `-e ../<package>[extras]` lines (paths relative to it), and
# everything else as plain requirements and `-c` files. <name>.txt is its
# lock: every distribution the job installs from PyPI, pinned to one version
# and to the SHA-256 of every file of that version, for Python 3.12 and later
# on every platform (a .in may name a lower floor with `# python-version:
# X.Y`). The -e packages are left out: CI installs them editable with
# --no-deps.
#
# The compile is seeded with the committed lock's versions (not its hashes,
# which always come from PyPI), so a pin moves only when the
# .in (or a package's pyproject.toml) no longer allows it. To move one on
# purpose, delete its entry from the lock, or pass uv's
# `--upgrade-package <name>` through UV_EXTRA (for example
# `UV_EXTRA="--upgrade-package dnspython" ci/regen.sh plugins`). --check never
# takes UV_EXTRA.
#
# What --check proves: each lock is exactly what this script writes for its
# .in from its own pins. A hand-edited hash, header or annotation, an entry
# that was added or removed by hand, and a pin the inputs no longer allow all
# fail it. A pin hand-moved to another version the inputs still allow is
# reproduced, so a version change is reviewed in the diff like any other.
# If PyPI later adds a file to a pinned version, the check fails until the
# lock is regenerated: fail-closed.
#
# Needs network access to PyPI and the uv that tools.txt pins (CI installs
# it from that lock; locally, `pip install --require-hashes --no-deps -r
# ci/tools.txt` into a venv). Any other uv version is refused, since its
# output can differ. Commit the .in and .txt files together.
set -euo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
cd "$HERE"

check=0
against=$HERE
names=()
while [ $# -gt 0 ]; do
  case "$1" in
    --check) check=1 ;;
    --against) shift; [ $# -gt 0 ] || { echo "regen.sh: --against needs a directory" >&2; exit 2; }
               against=$(cd "$1" && pwd -P) ;;
    -*) echo "regen.sh: unknown option $1" >&2; exit 2 ;;
    *) names+=("$1") ;;
  esac
  shift
done
if [ ${#names[@]} -eq 0 ]; then
  for f in "$HERE"/*.in; do names+=("$(basename "$f" .in)"); done
fi

command -v uv >/dev/null || { echo "regen.sh: uv is not installed (see ci/tools.txt)" >&2; exit 2; }
want=$(sed -n 's/^uv==\([0-9][0-9.]*\).*/\1/p' "$HERE/tools.in")
have=$(uv --version | awk '{print $2}')
[ -n "$want" ] && [ "$have" = "$want" ] || {
  echo "regen.sh: uv $have is not the pinned uv ${want:-?} (ci/tools.in); its output can differ" >&2
  exit 2
}

work=$(mktemp -d "${TMPDIR:-/tmp}/regen.XXXXXX")
trap 'rm -rf "$work"' EXIT

# Drop the -e lines (each carries its annotation on the same line): pip
# refuses editable requirements in hash-checking mode, and CI installs them
# itself.
strip_editables() {
  grep -v '^-e '
}

# compile NAME SEED OUT: write NAME's lock, seeded with the pins in SEED.
compile() {
  local n=$1 seed=$2 out=$3 extra=${4:-}
  local in="$n.in"
  [ -f "$in" ] || { echo "regen.sh: no ci/$in" >&2; exit 2; }
  local pyver
  pyver=$(sed -n 's/^# python-version: \([0-9][0-9.]*\)[[:space:]]*$/\1/p' "$in" | head -1)
  pyver=${pyver:-3.12}
  local raw="$work/$n.raw"
  rm -f "$raw"
  # The seed keeps each pin's version and marker, never its hashes: uv
  # carries the hashes of an existing output file into the new one, so a
  # seed with hashes would reproduce a hash edited by hand. Every hash comes
  # from PyPI.
  if [ -f "$seed" ]; then
    sed -n 's/^\([A-Za-z0-9][A-Za-z0-9._-]*==[^ \\]*\( ; [^\\]*[^ \\]\)\{0,1\}\).*$/\1/p' "$seed" >"$raw"
  fi
  # Only PyPI, and no uv configuration from the machine, the user or the
  # environment (every UV_* variable is dropped for the call). Wheels only,
  # so resolving never builds an sdist, which would run code from PyPI.
  # shellcheck disable=SC2046,SC2086
  env $(env | sed -n 's/^\(UV_[A-Za-z0-9_]*\)=.*/-u \1/p') \
  uv pip compile --quiet --no-config --index-url https://pypi.org/simple \
    --universal --python-version "$pyver" --generate-hashes --no-header \
    --only-binary :all: \
    --annotation-style line \
    $extra "$in" -o "$raw"
  {
    echo "# The hash-pinned lock of $in (Python $pyver and later, every platform)."
    echo "# Generated with ci/regen.sh $n; do not edit by hand. The packages of this"
    echo "# directory (the -e lines of the .in) are installed editable without their"
    echo "# dependencies, so they are not in this file."
    strip_editables <"$raw"
  } >"$out"
}

status=0
for n in "${names[@]}"; do
  if [ $check -eq 1 ]; then
    committed="$against/$n.txt"
    [ -f "$committed" ] || { echo "regen.sh: no lock $committed" >&2; exit 2; }
    compile "$n" "$committed" "$work/$n.txt"
    if cmp -s "$committed" "$work/$n.txt"; then
      echo "regen.sh: ci/$n.txt reproduces"
    else
      echo "::error::ci/$n.txt does not reproduce from ci/$n.in; run ci/regen.sh $n and commit the result"
      diff -u "$committed" "$work/$n.txt" | head -60 || true
      status=1
    fi
  else
    compile "$n" "$n.txt" "$work/$n.txt" "${UV_EXTRA:-}"
    mv "$work/$n.txt" "$n.txt"
    echo "regen.sh: ci/$n.txt ($(grep -c '==' "$n.txt") pins)"
  fi
done
exit $status
