#!/usr/bin/env bash
# test-heavy-on-train.sh — heavy_on=train skips test/coverage only on an ordinary PR, and the gate never calls that a pass elsewhere.
# Runs the REAL `gate` "Check results" script extracted from sovereign-ci.yml, with the needs.*.result expressions fed from env.
set -uo pipefail
root=${1:-$(cd "$(dirname "$0")/.." && pwd)}; f=$root/.github/workflows/sovereign-ci.yml; fail=0
ok(){ echo "ok   $1"; }; bad(){ echo "FAIL $1"; fail=1; }
t=$(mktemp -d); trap 'rm -rf "${t:?}"' EXIT
awk '/^      - name: Check results$/{g=1} g&&/^        run: \|$/{r=1;next} r{sub(/^          /,"");print}' "$f" |
  sed -e 's/\${{ needs\.test\.result }}/${R_TEST}/; s/\${{ needs\.lint\.result }}/${R_LINT}/; s/\${{ needs\.coverage\.result }}/${R_COV}/; s/\${{ needs\.security\.result }}/${R_SEC}/' > "$t/gate.sh"
[ -s "$t/gate.sh" ] && ! grep -q '\${{' "$t/gate.sh" && ok "gate script extracted, no unresolved expressions" || { bad "extraction failed"; exit 1; }
g(){ # heavy_on event head full_ci test lint cov sec
  COVERAGE_ON=always HEAVY_ON=$1 EVENT_NAME=$2 HEAD_REF=$3 FULL_CI=$4 GIT_REF=refs/heads/x R_TEST=$5 R_LINT=$6 R_COV=$7 R_SEC=$8 bash "${GATE:-$t/gate.sh}" >"$t/out" 2>&1; }
row(){ local want=$1 name=$2; shift 2; g "$@"; local rc=$?
  if { [ "$want" = green ] && [ $rc -eq 0 ]; } || { [ "$want" = red ] && [ $rc -ne 0 ]; }; then ok "$name -> $want"; else bad "$name: want $want rc=$rc: $(tail -1 "$t/out")"; fi; }
row green "always: all success"                          always pull_request feat/x false success success success success
row red   "always: test skipped is RED (unchanged)"      always pull_request feat/x false skipped success success success
row green "train: ordinary PR, test+coverage skipped"    train  pull_request feat/x false skipped success skipped success
grep -q 'test: NOT MEASURED' "$t/out" && grep -q 'coverage: NOT MEASURED' "$t/out" && ok "skip is printed NOT MEASURED, not as a pass" || bad "NOT MEASURED lines missing"
row red   "train: ordinary PR, lint failed"              train  pull_request feat/x false skipped failure skipped success
row red   "train: ordinary PR, security skipped"         train  pull_request feat/x false skipped success skipped skipped
row red   "train: ordinary PR, test FAILED (ran, e.g. label added)" train pull_request feat/x false failure success skipped success
row red   "train: train/* head, test skipped is RED"     train  pull_request train/infra-1 false skipped success success success
row red   "train: batch/* head, test skipped is RED"     train  pull_request batch/rmedia-ci false skipped success success success
row red   "train: full-ci label, test skipped is RED"    train  pull_request feat/x true skipped success success success
row red   "train: push to main, test skipped is RED"     train  push "" false skipped success success success
row red   "train: merge_group, coverage skipped is RED"  train  merge_group "" false success success skipped success
row green "train: train/* head, all success"             train  pull_request train/infra-1 false success success success success
row red   "bogus heavy_on value"                         sometimes pull_request feat/x false success success success success
# static: the two heavy jobs carry the predicate; lint and security do not
P="inputs.heavy_on != 'train'"
jobif(){ awk -v j="  $1:" '$0==j{g=1;next} g&&/^  [A-Za-z0-9_-]+:$/{g=0} g&&/^    if:/{f=1} g&&f{print} g&&f&&/}}/{exit}' "$f"; }
jobif test | grep -qF "$P" && jobif coverage | grep -qF "$P" && ok "test and coverage carry the heavy_on predicate" || bad "heavy job missing the predicate"
jobif lint | grep -qF "$P" || jobif security | grep -qF "$P" && bad "lint/security must never be skipped by heavy_on" || ok "lint and security are not gated by heavy_on"
# mutants on the gate script
mut(){ local name=$1 expr=$2; shift 2; sed "$expr" "$t/gate.sh" > "$t/m.sh"; cmp -s "$t/m.sh" "$t/gate.sh" && { bad "mutant $name did not apply"; return; }
  GATE=$t/m.sh g "$@" && ok "mutant $name detected" || bad "mutant $name survived"; }
mut M_TRAIN_NOT_OWED 's#train/\*|batch/\*) heavy_owed=1#nope/*) heavy_owed=1#' train pull_request train/infra-1 false skipped success success success
mut M_LABEL_IGNORED  's/\[ "\$FULL_CI" = true \] && heavy_owed=1/:/'           train pull_request feat/x true skipped success success success
mut M_PUSH_NOT_OWED  's/^    \*) heavy_owed=1 ;;/    *) heavy_owed=0 ;;/'      train push "" false skipped success success success
exit $fail
