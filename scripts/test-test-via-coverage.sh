#!/usr/bin/env bash
# test-test-via-coverage.sh — test_via_coverage: coverage re-runs the suite, so `test` is skipped when coverage is owed and
# `gate` takes coverage=success as the test verdict. Runs the REAL gate "Check results" script from sovereign-ci.yml.
set -uo pipefail
root=${1:-$(cd "$(dirname "$0")/.." && pwd)}; f=$root/.github/workflows/sovereign-ci.yml; fail=0
ok(){ echo "ok   $1"; }; bad(){ echo "FAIL $1"; fail=1; }
t=$(mktemp -d); trap 'rm -rf "${t:?}"' EXIT
awk '/^      - name: Check results$/{g=1} g&&/^        run: \|$/{r=1;next} r{sub(/^          /,"");print}' "$f" |
  sed -e 's/\${{ needs\.test\.result }}/${R_TEST}/g; s/\${{ needs\.lint\.result }}/${R_LINT}/g; s/\${{ needs\.coverage\.result }}/${R_COV}/g; s/\${{ needs\.security\.result }}/${R_SEC}/g' > "$t/gate.sh"
[ -s "$t/gate.sh" ] && ! grep -q '\${{' "$t/gate.sh" && ok "gate script extracted, no unresolved expressions" || { bad "extraction failed"; exit 1; }
# g tvc skip_cov coverage_on event test cov   (lint and security always success; heavy_on=always)
g(){ TEST_VIA_COVERAGE=$1 SKIP_COVERAGE=$2 COVERAGE_ON=$3 HEAVY_ON=always EVENT_NAME=$4 HEAD_REF=feat/x FULL_CI=false GIT_REF=${GIT_REF:-refs/heads/x} \
  R_TEST=$5 R_LINT=success R_COV=$6 R_SEC=success bash "${GATE:-$t/gate.sh}" >"$t/out" 2>&1; }
row(){ local want=$1 name=$2; shift 2; g "$@"; local rc=$?
  if { [ "$want" = green ] && [ $rc -eq 0 ]; } || { [ "$want" = red ] && [ $rc -ne 0 ]; }; then ok "$name -> $want"; else bad "$name: want $want rc=$rc: $(tail -1 "$t/out")"; fi; }
row green "via=true: test skipped, coverage success"              true  false always pull_request skipped success
grep -q 'test verdict = coverage' "$t/out" && ok "prints 'test verdict = coverage'" || bad "verdict line missing"
row red   "via=true: test skipped, coverage FAILED"               true  false always pull_request skipped failure
row red   "via=true: test skipped, coverage cancelled"            true  false always pull_request skipped cancelled
row red   "via=true: test skipped, coverage skipped"              true  false always pull_request skipped skipped
row red   "via=true: test FAILED (ran) is still RED"              true  false always pull_request failure success
row green "via=true: test ran and succeeded (also fine)"          true  false always pull_request success success
row red   "via=false: test skipped is RED (old behaviour)"        false false always pull_request skipped success
row green "via=false: all success (old behaviour)"                false false always pull_request success success
row red   "via=false: coverage failed is RED (old behaviour)"     false false always pull_request success failure
# coverage not owed -> test runs, so test skipped has no verdict
row red   "via=true skip_coverage: test skipped is RED"           true  true  always pull_request skipped skipped
GIT_REF=refs/heads/main row green "via=true coverage_on=tag, push to branch: test ran, coverage NOT MEASURED" true false tag push success skipped
GIT_REF=refs/heads/main row red "via=true coverage_on=tag, push to branch: test skipped is RED (coverage not owed)" true false tag push skipped skipped
GIT_REF=refs/tags/v1.0.0 row green "via=true coverage_on=tag, v* tag: coverage owed, verdict = coverage"    true false tag push skipped success
GIT_REF=refs/tags/v1.0.0 row red   "via=true coverage_on=tag, v* tag: coverage failed"                       true false tag push skipped failure
row green "via=true coverage_on=tag, dispatch: verdict = coverage" true false tag workflow_dispatch skipped success
# static: input exists, default false; test job's if carries the predicate; coverage's does not
awk '/^      test_via_coverage:$/{g=1} g&&/default:/{print $2; exit}' "$f" | grep -qx false && ok "input test_via_coverage defaults to false" || bad "input missing or default not false"
jobif(){ awk -v j="  $1:" '$0==j{g=1;next} g&&/^  [A-Za-z0-9_-]+:$/{g=0} g&&/^    if:/{f=1} g&&f{print} g&&f&&/}}/{exit}' "$f"; }
jobif test | grep -qF 'inputs.test_via_coverage' && ok "test job if: carries test_via_coverage" || bad "test job if: lacks the predicate"
jobif coverage | grep -qF 'inputs.test_via_coverage' && bad "coverage must never be skipped by test_via_coverage" || ok "coverage job is not gated by test_via_coverage"
# mutants on the gate script
mut(){ local name=$1 expr=$2; shift 2; sed "$expr" "$t/gate.sh" > "$t/m.sh"; cmp -s "$t/m.sh" "$t/gate.sh" && { bad "mutant $name did not apply"; return; }
  GATE=$t/m.sh g "$@" && ok "mutant $name detected" || bad "mutant $name survived"; }
# mutants: each removes one clause of the verdict rule; the wrongly-accepted verdict line must then appear (it never does in the real gate)
mutv(){ local name=$1 expr=$2; shift 2; sed "$expr" "$t/gate.sh" > "$t/m.sh"; cmp -s "$t/m.sh" "$t/gate.sh" && { bad "mutant $name did not apply"; return; }
  GATE=$t/m.sh g "$@"; if grep -q 'test verdict = coverage (' "$t/out"; then ok "mutant $name detected"; else bad "mutant $name survived"; fi
  g "$@"; grep -q 'test verdict = coverage (' "$t/out" && bad "real gate wrongly accepts the $name case" || ok "real gate rejects the $name case"; }
mutv M_ACCEPT_ANY_COV 's/\[ "\${R_COV}" = success \]/[ -n "${R_COV}" ]/' true false always pull_request skipped failure
mutv M_IGNORE_SKIPCOV 's/ \&\& \[ "\${SKIP_COVERAGE:-false}" != true \]//' true true always pull_request skipped success
GIT_REF=refs/heads/main mutv M_IGNORE_OWED 's/ \&\& \[ "\$coverage_owed" = 1 \]\; then$/; then/' true false tag push skipped success
mutv M_IGNORE_INPUT 's/\[ "\${TEST_VIA_COVERAGE:-false}" = true \]/true/' false false always pull_request skipped success
exit $fail
