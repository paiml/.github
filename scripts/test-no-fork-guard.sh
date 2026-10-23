#!/usr/bin/env bash
# NO-FORK-1 guard test (shell + awk only). Usage: test-no-fork-guard.sh [--self-test]
# Asserts: every job of the PR-capable reusable workflows carries the head-repo guard
# (fork-guard and gate have their own fork logic, checked separately), and
# fork-pr-closer has no checkout and no author_association.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 2
WF=${WF_DIR:-.github/workflows}
rc=0
check_file() { # file
  awk -v F="$1" '
    function verdict(   ok) {
      if (job == "") return
      if (job == "fork-guard") ok = (ifl ~ /head\.repo\.full_name != github\.repository/ && runs ~ /ubuntu-latest/)
      else if (job == "gate") ok = (runs ~ /ubuntu-latest/ && runs ~ /head\.repo\.full_name != github\.repository/ && forkstep)
      else ok = (ifl ~ /startsWith\(github\.event_name, .pull_request.\)/ && ifl ~ /head\.repo\.full_name == github\.repository/)
      printf "%s %s:%s\n", (ok ? "ok  " : "FAIL"), F, job
      if (!ok) bad++
    }
    /^jobs:/ {inj=1; next}
    inj && /^  [A-Za-z0-9_-]+:[ ]*$/ { verdict(); job=$1; sub(/:$/,"",job); ifl=""; runs=""; forkstep=0; capture=0; next }
    inj && /^    if:/ { ifl=$0; capture=1; next }
    inj && capture && /^      / { ifl = ifl " " $0; next }
    inj && /^    [a-z-]+:/ { capture=0 }
    inj && /^    runs-on:/ { runs=$0 }
    inj && /NO-FORK-1 refuse fork head/ { forkstep=1 }
    END { verdict(); exit (bad ? 1 : 0) }' "$1" || rc=1
}
run_all() {
  for f in sovereign-ci.yml unified-gate.yml; do check_file "$WF/$f"; done
  if grep -nE 'actions/checkout' "$WF/fork-pr-closer.yml"; then echo "FAIL fork-pr-closer has actions/checkout"; rc=1; else echo "ok   fork-pr-closer: no actions/checkout"; fi
  if grep -v '^[[:space:]]*#' "$WF/fork-pr-closer.yml" | grep -n 'author_association'; then echo "FAIL author_association used"; rc=1; fi
  if grep -q 'pull-requests: write' "$WF/fork-pr-closer.yml"; then echo "ok   fork-pr-closer: pull-requests: write"; else echo "FAIL missing pull-requests: write"; rc=1; fi
}
if [ "${1:-}" = "--self-test" ]; then
  tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
  cp "$WF"/*.yml "$tmp"/
  # mutation 1: strip the guard from the lint job of sovereign-ci.yml
  awk '/^  lint:$/{inl=1} inl && /^    if: /{inl=0; next} {print}' "$WF/sovereign-ci.yml" > "$tmp/sovereign-ci.yml"
  WF_DIR=$tmp bash "$0" >/dev/null 2>&1 && { echo "SELF-TEST FAIL: guard removal not detected"; exit 1; }
  # mutation 2: add a checkout to the closer
  cp "$WF/sovereign-ci.yml" "$tmp/sovereign-ci.yml"
  { cat "$WF/fork-pr-closer.yml"; echo "      - uses: actions/checkout@v4"; } > "$tmp/fork-pr-closer.yml"
  WF_DIR=$tmp bash "$0" >/dev/null 2>&1 && { echo "SELF-TEST FAIL: closer checkout not detected"; exit 1; }
  echo "self-test ok: both mutations detected (red)"
  exit 0
fi
run_all
exit $rc
