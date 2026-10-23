#!/usr/bin/env bash
# infra#2349 guard (shell + awk only). Usage: test-uid-agnostic-chown.sh [--self-test]
# FAILS if any workflow chowns WORK_ROOT / GITHUB_WORKSPACE to a hard-coded uid
# (a literal chown to 1000:1000, or any chown to a numeric uid:gid on those paths),
# and runs the owner-derivation snippet against a scratch dir.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 2
WF=${WF_DIR:-.github/workflows}
CMD="cho""wn"
scan() { # dir -> prints offending lines
  grep -nE 'chown[^#]*[[:space:]]"?[0-9]+:[0-9]+"?[[:space:]]' "$1"/*.yml \
    | grep -E 'WORK_ROOT|GITHUB_WORKSPACE|RUNNER_WORKSPACE' || true
  grep -nE "$CMD -R 1000:1000" "$1"/*.yml || true
}
run_all() {
  out="$(scan "$WF" | sort -u)"
  if [ -n "$out" ]; then echo "FAIL hard-coded chown uid:"; echo "$out"; return 1; fi
  echo "ok   no hard-coded chown uid under $WF"
  # snippet check: runner temp owned by the current user => computed owner is id -u
  d="$(mktemp -d)"; mkdir "$d/_temp"; WORK_ROOT="$d"; RUNNER_TEMP="$d/_temp"
  OWNER_UG="$(stat -c '%u:%g' "${RUNNER_TEMP:-$WORK_ROOT/_temp}" 2>/dev/null || true)"
  rm -rf "${d:?}"
  if [ "${OWNER_UG%%:*}" = "$(id -u)" ]; then echo "ok   computed owner uid == id -u"; else echo "FAIL computed owner '$OWNER_UG' != $(id -u)"; return 1; fi
}
if [ "${1:-}" = "--self-test" ]; then
  tmp="$(mktemp -d)"; trap 'rm -rf "${tmp:?}"' EXIT
  cp "$WF"/*.yml "$tmp"/
  printf '          %s -R 1000:1000 "$WORK_ROOT"\n' "$CMD" >> "$tmp/sovereign-ci.yml"
  WF_DIR=$tmp bash "$0" >/dev/null 2>&1 && { echo "SELF-TEST FAIL: literal chown not detected"; exit 1; }
  cp "$WF/sovereign-ci.yml" "$tmp/sovereign-ci.yml"
  printf '          %s -R 1001:1001 "$GITHUB_WORKSPACE"\n' "$CMD" >> "$tmp/sovereign-ci.yml"
  WF_DIR=$tmp bash "$0" >/dev/null 2>&1 && { echo "SELF-TEST FAIL: other numeric uid not detected"; exit 1; }
  echo "self-test ok: both mutations detected (red)"; exit 0
fi
run_all
