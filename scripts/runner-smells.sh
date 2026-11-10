#!/usr/bin/env bash
# RUNNER-SMELLS (paiml/infra#3828, pmat#1673): static check of a repo's GitHub Actions
# configuration for the runner and gate defects measured in the 2026-11-10 build outage.
# Interim shell implementation of the pmat comply rule set RS-01..RS-11; pmat takes the
# same rule ids when its binary reaches the runners.
#
# Usage:
#   runner-smells.sh [DIR]                     report findings for DIR/.github/workflows (default .)
#   runner-smells.sh --write-baseline [DIR]    print "RULE<TAB>COUNT" lines for the baseline file
#   runner-smells.sh --ratchet FILE [DIR]      fail when any rule's count exceeds FILE's count
#   runner-smells.sh --strict [DIR]            fail on any finding
#   runner-smells.sh --self-test               fixtures + one mutant per rule
# Finding line: RULE<TAB>file:line<TAB>message.
# Exit: 0 clean / within baseline, 1 findings over the bar, 2 nothing scanned or self-test broken.
set -uo pipefail
SELF="${BASH_SOURCE[0]}"

# One rule per line. The self-test deletes each line in turn and demands red.
RULES=(
  rs01 # RULE:RS-01 pull_request workflow without concurrency cancel-in-progress
  rs02 # RULE:RS-02 job without timeout-minutes
  rs03 # RULE:RS-03 GitHub-hosted runner on a pull_request workflow
  rs04 # RULE:RS-04 heavy suite (mutation, coverage, msrv, bench, fuzz, convergence, behavior) on every PR push
  rs05 # RULE:RS-05 pull_request_target trigger
  rs06 # RULE:RS-06 cargo build on a runner without the CI profile (debug info and incremental on)
  rs07 # RULE:RS-07 gate roll-up job not on a gate-light runner
  rs08 # RULE:RS-08 action or reusable workflow not pinned to a commit sha
  rs09 # RULE:RS-09 draft pull requests start CI
  rs11 # RULE:RS-11 examples or all targets built on the pull_request path
  rs12 # RULE:RS-12 mutation testing outside a scheduled nightly (HARD: no baseline can allow it)
)
MAX_PR_WORKFLOWS=3 # RS-10: pull_request-triggered workflow files per repo

is_pr() { # FILE -> 0 when on: names pull_request or pull_request_target
  awk '
    /^("on"|on|true)[ \t]*:/ { inon=1; v=$0; sub(/^[^:]*:[ \t]*/,"",v); if (v ~ /(^|[^a-z_])pull_request(_target)?([^a-z_]|$)/) pr=1; next }
    inon && /^[^ \t#]/ { inon=0 }
    inon && /^[ \t]+(- )?["\047]?pull_request(_target)?["\047]?[ \t]*(:|$|#)/ { pr=1 }
    END { exit pr ? 0 : 1 }' "$1"
}
nocomment() { sed -E 's/(^|[[:space:]])#.*$//' "$1"; }
# FILE -> "LINE<TAB>JOB<TAB>has_timeout<TAB>is_reusable<TAB>runs_on_text" per job
jobs_tsv() {
  awk '
    function flush() { if (job != "") printf "%d\t%s\t%d\t%d\t%s\n", jl, job, to, ru, ro }
    { s=$0; sub(/[ \t]#.*$/,"",s) }
    /^jobs:[ \t]*$/ { inj=1; next }
    inj && /^[^ \t#]/ { flush(); job=""; inj=0 }
    inj && s ~ /^  [A-Za-z0-9_-]+:[ \t]*$/ { flush(); job=s; gsub(/[ :\t]/,"",job); jl=NR; to=0; ru=0; ro=""; inro=0; next }
    inj && job != "" {
      if (s ~ /^    timeout-minutes:/) to=1
      if (s ~ /^    uses:/) ru=1
      if (s ~ /^    [A-Za-z0-9_-]+:/) inro=0
      if (s ~ /^    runs-on:/) { inro=1; v=s; sub(/^    runs-on:[ \t]*/,"",v); ro=v; next }
      if (inro) ro=ro " " s
    }
    END { flush() }' "$1"
}
# has ARGS...: grep that reads ALL of stdin. Never `grep -q` after a pipe here: under pipefail it exits at the
# first match, the writer dies of SIGPIPE (141), and the pipeline reads as 'no match' on files past the pipe buffer.
has() { grep "$@" >/dev/null; }
emit() { printf '%s\t%s:%s\t%s\n' "$1" "$2" "$3" "$4"; }

rs01() { is_pr "$1" || return 0; nocomment "$1" | has -E '^[[:space:]]*cancel-in-progress:[[:space:]]*[^f[:space:]]' || emit RS-01 "$1" 1 "pull_request workflow has no concurrency cancel-in-progress: a new push leaves the old run holding runners"; }
rs02() { jobs_tsv "$1" | while IFS=$'\t' read -r l j to ru ro; do [ "$to" = 1 ] || [ "$ru" = 1 ] || emit RS-02 "$1" "$l" "job '$j' has no timeout-minutes: a hung job holds its runner for 6 h"; done; }
rs03() { is_pr "$1" || return 0; jobs_tsv "$1" | while IFS=$'\t' read -r l j to ru ro; do printf '%s' "$ro" | has -E '(ubuntu|macos|windows)-(latest|[0-9])' && emit RS-03 "$1" "$l" "job '$j' runs on a GitHub-hosted runner on every PR push (paid minutes, no fleet cache)"; done; }
rs04() { is_pr "$1" || return 0; { basename "$1"; jobs_tsv "$1" | cut -f2; } | has -iE 'mutation|mutant|coverage|msrv|bench|fuzz|convergence|behavior' || return 0
         nocomment "$1" | has -E "train/|heavy_on|merge_group" || emit RS-04 "$1" 1 "heavy suite runs on every pull_request push; run it on train/* and the default branch only"; }
rs05() { nocomment "$1" | grep -nE '(^|[^a-z_])pull_request_target([^a-z_]|$)' | head -1 | while IFS=: read -r l _; do emit RS-05 "$1" "$l" "pull_request_target runs fork code with repository secrets"; done; }
rs06() { is_pr "$1" || return 0; nocomment "$1" | grep -nE '(^|[^[:alnum:]_-])cargo([[:space:]]+[+][^[:space:]]+)?[[:space:]]+(build|test|nextest|clippy|llvm-cov|check)([[:space:]]|$)' | head -1 | while IFS=: read -r l _; do
           grep -qE 'CARGO_PROFILE_(DEV|TEST)_DEBUG' "$1" && grep -qE 'CARGO_INCREMENTAL' "$1" || emit RS-06 "$1" "$l" "cargo runs without CARGO_PROFILE_DEV_DEBUG=0 / CARGO_PROFILE_TEST_DEBUG=0 / CARGO_INCREMENTAL=0 (measured: 66G build tree vs 5.5G)"; done; }
rs07() { jobs_tsv "$1" | while IFS=$'\t' read -r l j to ru ro; do [ "$j" = gate ] && [ "$ru" = 0 ] && ! printf '%s' "$ro" | has -E 'gate-light|inputs\.|matrix\.|vars\.' && emit RS-07 "$1" "$l" "roll-up job 'gate' asks for a heavy runner; it only reads other jobs' results"; done; }
rs08() { nocomment "$1" | grep -nE '^[[:space:]]*(- )?uses:[[:space:]]*[^.[:space:]][^[:space:]]*' | grep -vE '@[0-9a-f]{40}([[:space:]]|$)' | grep -vE 'uses:[[:space:]]*docker://' | while IFS=: read -r l t; do emit RS-08 "$1" "$l" "not pinned to a commit sha: $(printf '%s' "$t" | sed -E 's/^[[:space:]]*(- )?uses:[[:space:]]*//')"; done; }
rs09() { is_pr "$1" || return 0; nocomment "$1" | has -E 'draft|ready_for_review' || emit RS-09 "$1" 1 "draft pull requests start this workflow (no draft == false condition, no ready_for_review type)"; }
rs11() { is_pr "$1" || return 0; nocomment "$1" | grep -nE 'cargo[^#]*[[:space:]](--all-targets|--examples)([[:space:]]|$)' | grep -vE 'cargo[[:space:]]+(clippy|check)' | head -1 | while IFS=: read -r l _; do emit RS-11 "$1" "$l" "examples/all targets are built on the PR path (measured: 13-24G per runner)"; done; }

# FILE -> 0 when on: names any trigger other than schedule / workflow_dispatch
non_nightly() {
  awk '
    /^("on"|on|true)[ \t]*:/ { inon=1; v=$0; sub(/^[^:]*:[ \t]*/,"",v); gsub(/[\[\],"\047]/," ",v); n=split(v,a," "); for(i=1;i<=n;i++) if (a[i] !~ /^(schedule|workflow_dispatch)$/ && a[i] !~ /^#/) bad=1; next }
    inon && /^[^ \t#]/ { inon=0 }
    inon && /^  ["\047]?[a-z_]+["\047]?[ \t]*:/ { k=$0; gsub(/[ \t"\047:]/,"",k); sub(/#.*/,"",k); if (k !~ /^(schedule|workflow_dispatch)$/) bad=1 }
    inon && /^  - / { k=$0; gsub(/[ \t"\047-]/,"",k); if (k !~ /^(schedule|workflow_dispatch)$/) bad=1 }
    END { exit bad ? 0 : 1 }' "$1"
}
# Noah Gift, 2026-11-10 16:50Z, verbatim: "NO build can do mutation outside of nightly; the end. FOREVER".
rs12() { non_nightly "$1" || return 0; nocomment "$1" | grep -nE '(^|[^[:alnum:]_])cargo[ -]mutants([^[:alnum:]_]|$)' | head -1 | while IFS=: read -r l _; do emit RS-12 "$1" "$l" "mutation testing runs outside a scheduled nightly (operator ruling 2026-11-10: nightly only, forever)"; done; }
HARD_RULES="RS-12" # never ratcheted: any finding fails --ratchet and --strict, baseline or not

scan() { # DIR -> findings on stdout; returns 2 when nothing scanned
  local d="$1/.github/workflows" f n=0 pr=0 r
  [ -d "$d" ] || return 2
  for f in "$d"/*.yml "$d"/*.yaml; do [ -f "$f" ] || continue; n=$((n+1)); is_pr "$f" && pr=$((pr+1))
    for r in "${RULES[@]}"; do "$r" "$f"; done
  done
  [ "$n" -gt 0 ] || return 2
  [ "$pr" -le "$MAX_PR_WORKFLOWS" ] || emit RS-10 "$d" 0 "$pr workflow files start on pull_request (limit $MAX_PR_WORKFLOWS): one push fans out into $pr runs" # RULE:RS-10
  return 0
}
counts() { cut -f1 | sort | uniq -c | awk '{printf "%s\t%d\n",$2,$1}'; }

self_test() {
  local fx; fx="$(cd "$(dirname "$SELF")" && pwd)/fixtures/runner-smells"; local rc=0 id out t m
  out=$(scan "$fx/good") || { echo "SELF-TEST: good fixture not scanned"; return 2; }
  [ -z "$out" ] || { echo "SELF-TEST FAIL: good fixture has findings:"; echo "$out"; rc=1; }
  out=$(scan "$fx/good-nightly") || { echo "SELF-TEST: good-nightly not scanned"; return 2; }   # mutation on schedule only is allowed
  printf '%s\n' "$out" | cut -f1 | has -x "RS-12" && { echo "SELF-TEST FAIL: nightly-only mutation raised RS-12"; rc=1; } || echo "ok   good-nightly: scheduled mutation is not RS-12"
  out=$(scan "$fx/good-large") || { echo "SELF-TEST: good-large fixture not scanned"; return 2; }   # > 64 KiB: the pipefail/SIGPIPE regression
  [ -z "$out" ] && echo "ok   good-large (past the pipe buffer) is clean" || { echo "SELF-TEST FAIL: good-large has findings (grep -q under pipefail?):"; echo "$out"; rc=1; }
  for id in 01 02 03 04 05 06 07 08 09 10 11 12; do
    out=$(scan "$fx/bad-rs$id") || { echo "SELF-TEST: bad-rs$id not scanned"; return 2; }
    printf '%s\n' "$out" | cut -f1 | has -x "RS-$id" && echo "ok   bad-rs$id -> RS-$id" || { echo "SELF-TEST FAIL: bad-rs$id did not raise RS-$id"; rc=1; }
  done
  [ "${RUNNER_SMELLS_NO_MUTANTS:-0}" = 1 ] && return $rc
  t=$(mktemp -d); mkdir -p "$t/scripts"; cp -r "$fx/.." "$t/scripts/fixtures"
  for id in 01 02 03 04 05 06 07 08 09 10 11 12; do
    m="$t/scripts/runner-smells.sh"; grep -v "# RULE:RS-$id" "$SELF" > "$m"
    if RUNNER_SMELLS_NO_MUTANTS=1 bash "$m" --self-test >/dev/null 2>&1; then echo "SELF-TEST FAIL: mutant without RS-$id stayed green"; rc=1; else echo "ok   mutant M_RS$id detected"; fi
  done
  rm -rf "${t:?}"; return $rc
}

mode=report; base=""
case "${1:-}" in
  --self-test) self_test; exit $? ;;
  --write-baseline) mode=write; shift ;;
  --ratchet) mode=ratchet; base="${2:?baseline file}"; shift 2 ;;
  --strict) mode=strict; shift ;;
esac
dir="${1:-.}"
found=$(scan "$dir"); src=$?
[ "$src" = 2 ] && { echo "runner-smells: no workflow files under $dir/.github/workflows" >&2; exit 2; }
case $mode in
  write) printf '%s\n' "$found" | grep . | counts; exit 0 ;;
  report) [ -n "$found" ] && printf '%s\n' "$found"; echo "runner-smells: $(printf '%s\n' "$found" | grep -c .) finding(s) (report only)" >&2; exit 0 ;;
  strict) [ -z "$found" ] && { echo "runner-smells: clean" >&2; exit 0; }; printf '%s\n' "$found"; exit 1 ;;
  ratchet)
    hard=$(printf '%s\n' "$found" | awk -F'\t' -v h="$HARD_RULES" 'BEGIN{n=split(h,a," ");for(i=1;i<=n;i++)H[a[i]]=1} H[$1]')
    [ -z "$hard" ] || { echo "::error::hard rule violated (no baseline can allow it):"; printf '%s\n' "$hard"; exit 1; }
    [ -f "$base" ] || { [ -n "$found" ] && printf '%s\n' "$found"; echo "::warning::runner-smells: no baseline at $base; report only. Commit one with: runner-smells.sh --write-baseline > $base" >&2; exit 0; }
    over=0
    while IFS=$'\t' read -r rule n; do [ -n "$rule" ] || continue
      b=$(awk -F'\t' -v r="$rule" '$1==r{print $2}' "$base"); b=${b:-0}
      if [ "$n" -gt "$b" ]; then over=1; echo "::error::$rule: $n finding(s), baseline allows $b"; printf '%s\n' "$found" | awk -F'\t' -v r="$rule" '$1==r'; fi
    done < <(printf '%s\n' "$found" | grep . | counts)
    [ "$over" = 0 ] && echo "runner-smells: within baseline ($(printf '%s\n' "$found" | grep -c .) finding(s) allowed by $base)" >&2
    exit $over ;;
esac
