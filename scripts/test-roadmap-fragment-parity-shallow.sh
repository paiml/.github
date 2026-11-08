#!/usr/bin/env bash
# Falsifier for the roadmap-fragment-parity shallow-checkout fix (paiml-implement#697).
# Usage: test-roadmap-fragment-parity-shallow.sh
# Extracts the step's run block from sovereign-ci.yml, runs it in a depth-1 clone of a
# merge commit (base and head shas absent), and requires: green with the fix, RED
# when the fix region (between "shallow-fix begin/end") is removed.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 2
WF=.github/workflows/sovereign-ci.yml
T=$(mktemp -d) || exit 2
trap 'rm -rf "${T:?}"' EXIT

# step body, 10-space indent stripped, from "run: |" to the next step
awk '/- name: roadmap-fragment-parity/{s=1;next} s&&/^      - name:/{exit} s&&/^        run: \|/{r=1;next} r{sub(/^          /,"");print}' "$WF" > "$T/step.sh"
[ -s "$T/step.sh" ] || { echo "FAIL: could not extract the step"; exit 2; }
grep -q 'shallow-fix begin' "$T/step.sh" || { echo "FAIL: fix markers missing"; exit 1; }
awk '/shallow-fix begin/{skip=1} !skip{print} /shallow-fix end/{skip=0}' "$T/step.sh" > "$T/step-nofix.sh"

g() { git -c user.name=t -c user.email=t@t -c commit.gpgsign=false "$@"; }
O="$T/origin"
git init -q --template= -b main "$O"
mkdir -p "$O/docs/roadmaps/entries"
echo a > "$O/docs/roadmaps/entries/PMAT-1.yaml"
g -C "$O" add -A; g -C "$O" commit -q -m base
BASE=$(git -C "$O" rev-parse HEAD)
g -C "$O" checkout -q -b pr
echo b > "$O/docs/roadmaps/entries/PMAT-2.yaml"
g -C "$O" add -A; g -C "$O" commit -q -m "feat

Pmat-Ticket: PMAT-2"
HEAD=$(git -C "$O" rev-parse HEAD)
g -C "$O" checkout -q main
echo c > "$O/other.txt"; g -C "$O" add -A; g -C "$O" commit -q -m advance
g -C "$O" merge -q --no-ff -m merge pr
git -C "$O" config uploadpack.allowAnySHA1InWant true

fresh_clone() {
  rm -rf "${T:?}/c"
  git clone -q --depth 1 "file://$O" "$T/c" 2>/dev/null
}
run_case() { # $1 = script
  fresh_clone
  ( cd "$T/c" && BASE_SHA=$BASE HEAD_SHA=$HEAD bash "$1" ) >"$T/out" 2>&1
}
fresh_clone
if git -C "$T/c" cat-file -e "$HEAD^{commit}" 2>/dev/null; then echo "FAIL: fixture not shallow"; exit 2; fi

rc=0
if run_case "$T/step.sh"; then echo "ok: with fix -> green"; else echo "FAIL: with fix is red"; tail -n 5 "$T/out"; rc=1; fi
if run_case "$T/step-nofix.sh"; then echo "FAIL: without fix is green (falsifier cannot discriminate)"; rc=1; else echo "ok: without fix -> red"; tail -n 2 "$T/out"; fi
exit $rc
