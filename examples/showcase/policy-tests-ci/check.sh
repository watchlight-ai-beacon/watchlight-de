#!/usr/bin/env bash
# How this showcase is verified. Run it directly, or through
# examples/showcase/check.sh.
#
# This showcase already ships its own runner: run-local.sh reproduces the CI
# gate in every installed lane, asserting that the correct policy passes and the
# deliberately widened copy fails. Rather than restate that here, the check
# declares run-local.sh as the way this showcase is verified.
#
# github-workflow.policy-tests.yml is a TEMPLATE for a reader to copy into their
# own repository, not a workflow this one runs; run-local.sh is the executable
# form of the same gate, which is what a check can assert.
. "$(dirname "${BASH_SOURCE[0]}")/../_check_lib.sh"

lane "the CI gate, locally (both lanes)" ./run-local.sh

# Nothing executes the template, so the one thing in it that can rot silently is
# the pair of suite paths it points at. Assert they still resolve.
template_paths_exist() {
  local bad=0 key path
  for key in SUITE WIDENED_SUITE; do
    path="$(sed -n "s/^  $key: *//p" github-workflow.policy-tests.yml | head -1)"
    if [ -z "$path" ]; then
      echo "the template names no $key"; bad=1
    elif [ ! -f "$REPO_ROOT/$path" ]; then
      echo "$key points at $path, which does not exist"; bad=1
    else
      echo "$key -> $path"
    fi
  done
  return "$bad"
}
lane "the workflow template's suite paths resolve" template_paths_exist

finish
