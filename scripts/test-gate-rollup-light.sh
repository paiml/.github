#!/usr/bin/env bash
# test-gate-rollup-light.sh — a `gate` roll-up job never asks for a heavy runner (GATE-ROLLUP-LIGHT, 2026-11-10).
# A roll-up only sums `needs` results. On 2026-11-10 one waited 36 min for an intel clean-room seat with every input green.
set -uo pipefail
root=${1:-$(cd "$(dirname "$0")/.." && pwd)}; fail=0
ok(){ echo "ok   $1"; }; bad(){ echo "FAIL $1"; fail=1; }
# runs-on line of the top-level job named `gate` in a workflow file
gate_runs_on(){ awk '/^  gate:$/{g=1;next} g&&/^  [A-Za-z0-9_-]+:$/{g=0} g&&/^    runs-on:/{print;exit}' "$1"; }
check(){ local f=$1 l; l=$(gate_runs_on "$f")
  [ -n "$l" ] || { bad "$f: no gate job runs-on found"; return; }
  case "$l" in *clean-room*|*tier2*|*inputs.runs_on*|*intel*) bad "$f: gate roll-up asks for a heavy runner: $l"; return;; esac
  case "$l" in *gate-light*) ok "$f: gate roll-up runs on gate-light";; *) bad "$f: gate roll-up not on gate-light: $l";; esac; }
check "$root/.github/workflows/ci.yml"; check "$root/.github/workflows/sovereign-ci.yml"
grep -q 'ubuntu-latest' <<<"$(gate_runs_on "$root/.github/workflows/sovereign-ci.yml")" && ok "fork-head branch still hosted (NO-FORK-1 kept)" || bad "NO-FORK-1 hosted branch lost"
# mutants: putting the heavy pool back must be caught
t=$(mktemp -d); trap 'rm -rf "${t:?}"' EXIT; mkdir -p "$t/.github/workflows"
if [ -z "${GRL_INNER:-}" ]; then
  cp "$root/.github/workflows/"{ci.yml,sovereign-ci.yml} "$t/.github/workflows/"; sed -i 's/runs-on: \[self-hosted, gate-light\]/runs-on: [self-hosted, Linux, X64, clean-room, intel]/' "$t/.github/workflows/ci.yml"
  GRL_INNER=1 bash "$0" "$t" >/dev/null 2>&1 && bad "mutant M_CI_HEAVY survived" || ok "mutant M_CI_HEAVY detected"
  cp "$root/.github/workflows/"{ci.yml,sovereign-ci.yml} "$t/.github/workflows/"; sed -i "s/|| fromJSON('\[\"self-hosted\",\"gate-light\"\]')/|| fromJSON(inputs.runs_on)/" "$t/.github/workflows/sovereign-ci.yml"
  GRL_INNER=1 bash "$0" "$t" >/dev/null 2>&1 && bad "mutant M_SOV_HEAVY survived" || ok "mutant M_SOV_HEAVY detected"
fi
exit $fail
