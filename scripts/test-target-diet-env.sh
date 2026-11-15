#!/usr/bin/env bash
# TARGET-DIET: sovereign-ci.yml's workflow-level env must set the three target-size vars for every caller.
# Self-tests with a mutant per var: deleting any one must make the check fail.
set -u
WF=${1:-.github/workflows/sovereign-ci.yml}
VARS='CARGO_PROFILE_DEV_DEBUG CARGO_PROFILE_TEST_DEBUG CARGO_INCREMENTAL'
check() { # file -> rc 0 only if each var is "0" inside the top-level env: block
  local f=$1 v
  for v in $VARS; do
    awk -v v="$v" '/^env:/{e=1;next} e&&/^[^ #]/{e=0} e&&$1==v":"&&($2=="\"0\""||$2=="0"){ok=1} END{exit ok?0:1}' "$f" || { echo "missing at workflow level: $v"; return 1; }
  done
}
check "$WF" || { echo RED; exit 1; }
fail=0; T=$(mktemp -d); trap 'rm -rf "${T:?}"' EXIT
for v in $VARS; do
  grep -v "^  $v:" "$WF" > "$T/m.yml"
  if check "$T/m.yml" >/dev/null; then echo "FAIL: mutant without $v survived"; fail=1; else echo "ok: mutant without $v killed"; fi
done
[ $fail -eq 0 ] && echo "GREEN: target-diet env holds" || { echo RED; exit 1; }
