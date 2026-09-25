#!/usr/bin/env bash
# test_flow_guards.sh — case tables for the FLOW rule 17/18/19 guards and the
# §2.8 promotion schedule. Every guard ships must-match (RED) and
# must-not-match (GREEN) rows; a guard is trusted only after this table has
# been seen RED against a mutated guard (see the PR's mutation receipt).
#
# Usage: test_flow_guards.sh            # from anywhere; exits 0 only if every row holds
# Env:   FLOW_DIR  directory holding the guards (default: this script's dir) —
#        point it at a mutated copy to prove the table can fail.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FLOW_DIR="${FLOW_DIR:-$here}"
tmp="$(mktemp -d)"
trap 'rm -rf "${tmp:?}"' EXIT
pass=0
fail=0

# expect <id> <want-exit> <want-first-two-words> <actual-exit> <actual-output>
expect() {
  local id="$1" wx="$2" wv="$3" ax="$4" out="$5" got
  got="$(printf '%s\n' "$out" | head -1 | awk '{print $1" "$2}')"
  if [ "$ax" = "$wx" ] && [ "$got" = "$wv" ]; then
    pass=$((pass + 1))
  else
    fail=$((fail + 1))
    printf 'FAIL %-26s want exit=%s "%s"  got exit=%s "%s"\n' "$id" "$wx" "$wv" "$ax" "$(printf '%s' "$out" | head -1)"
  fi
}
run() { set +e; out="$("$@" 2>&1)"; rc=$?; set -e; }

# ---------------------------------------------------------------- rule 18
# id <TAB> want-exit <TAB> want-verdict <TAB> body (\n = newline)
states="$tmp/states.tsv"
printf '12\tOPEN\n13\tCLOSED\n14\tERROR\npaiml/infra#7\tOPEN\n' > "$states"
while IFS=$'\t' read -r id wx wv body; do
  printf '%b' "$body" > "$tmp/body"
  run bash "$FLOW_DIR/check_pr_closes.sh" --states "$states" "$tmp/body"
  expect "$id" "$wx" "$wv" "$rc" "$out"
done <<'EOF'
FALSIFY-FLOW-012	10	RED no-close	Fix the parser.\n\nRefs #12\n
PRC-empty	10	RED no-close
PRC-prose-only	10	RED no-close	This PR closes the gap in the parser.\n
PRC-template-comment	10	RED no-close	<!-- Closes #12 -->\nSummary here\n
PRC-multiline-comment	10	RED no-close	<!--\nFixes #12\n-->\nSummary\n
PRC-fenced-code	10	RED no-close	```\nCloses #12\n```\n
PRC-no-issue-empty	10	RED no-close	no-issue:\n
PRC-hash-no-number	10	RED no-close	Closes #\n
PRC-word-prefix	10	RED no-close	encloses #12\n
PRC-closed-only	10	RED closes-nothing-open	Closes #13\n
PRC-unknown-only	10	RED closes-nothing-open	Fixes #999\n
PRC-closes	0	GREEN closes	Closes #12\n
PRC-fixes-lower	0	GREEN closes	fixes #12\n
PRC-resolved-colon	0	GREEN closes	Resolved: #12\n
PRC-cross-repo	0	GREEN closes	Closes paiml/infra#7\n
PRC-one-open-of-two	0	GREEN closes	Closes #13, closes #12\n
PRC-no-issue	0	GREEN no-issue	Bump a pin.\n\nno-issue: dependabot action bump\n
PRC-no-issue-crlf	0	GREEN no-issue	Bump.\r\nNo-Issue: ci-only\r\n
PRC-refs-row	0	GREEN refs-row	Refs #12 row F-GUARD\n
PRC-api-error	2	tool error:	Closes #14\n
PRC-api-error-but-open	0	GREEN closes	Closes #14, closes #12\n
EOF

# Without --states/--repo the open-state check must SAY it did not measure.
printf 'Closes #13\n' > "$tmp/body"
run bash "$FLOW_DIR/check_pr_closes.sh" "$tmp/body"
if [ "$rc" = 0 ] && printf '%s' "$out" | grep -q 'NOT MEASURED'; then pass=$((pass + 1)); else
  fail=$((fail + 1)); echo "FAIL PRC-unmeasured-says-so  got exit=$rc \"$out\""; fi

# ---------------------------------------------------------------- rule 19
while IFS=$'\t' read -r id wx wv created closed; do
  run bash "$FLOW_DIR/check_issue_flow.sh" --created "$created" --closed "$closed"
  expect "$id" "$wx" "$wv" "$rc" "$out"
done <<'EOF'
FALSIFY-FLOW-013-red	10	RED inflow	30	20
FALSIFY-FLOW-013-green	0	GREEN inflow	20	30
FLOW-equal	0	GREEN inflow	25	25
FLOW-plus-one	10	RED inflow	26	25
FLOW-zero	0	GREEN inflow	0	0
FLOW-bad-count	2	usage error:	x	3
FLOW-negative	2	usage error:	-1	3
EOF

# ---------------------------------------------------------------- rule 17
repo="$tmp/ledger"
git init -q "$repo"
git -C "$repo" config user.email flow@test.invalid
git -C "$repo" config user.name flow-test
mkdir -p "$repo/docs/findings"
good='{"id":"F-1","title":"t","evidence":"e","repro":"r","suspected_epic":"E1","severity":"high","found_at_sha":"abc1234"}'
good2='{"id":"F-2","title":"t","evidence":"e","repro":"r","suspected_epic":"E1","severity":"low","found_at_sha":"0123456789abcdef0123456789abcdef01234567"}'
ledger() { run bash "$FLOW_DIR/check_findings_ledger.sh" --root "$repo" "$@"; }

ledger; expect FIND-no-ledger 0 "SKIP no-ledger" "$rc" "$out"
printf '%s\n' "$good" > "$repo/docs/findings/s1.jsonl"
ledger; expect FIND-good 0 "GREEN findings" "$rc" "$out"
git -C "$repo" add -A && git -C "$repo" commit -qm base >/dev/null 2>&1
printf '%s\n' "$good2" >> "$repo/docs/findings/s1.jsonl"
ledger --base HEAD; expect FIND-append 0 "GREEN findings" "$rc" "$out"
for bad in \
  'FIND-missing-key|{"id":"F-3","title":"t","evidence":"e","repro":"r","severity":"low","found_at_sha":"abc1234"}' \
  'FIND-empty-field|{"id":"F-3","title":"","evidence":"e","repro":"r","suspected_epic":"E","severity":"low","found_at_sha":"abc1234"}' \
  'FIND-number-field|{"id":3,"title":"t","evidence":"e","repro":"r","suspected_epic":"E","severity":"low","found_at_sha":"abc1234"}' \
  'FIND-bad-sha|{"id":"F-3","title":"t","evidence":"e","repro":"r","suspected_epic":"E","severity":"low","found_at_sha":"main"}' \
  'FIND-not-object|["F-3"]' \
  'FIND-invalid-json|{"id":"F-3",' ; do
  printf '%s\n' "${bad#*|}" > "$repo/docs/findings/s2.jsonl"
  ledger; expect "${bad%%|*}" 10 "RED findings-schema" "$rc" "$out"
done
printf '%s\n' "$good" > "$repo/docs/findings/s2.jsonl"
ledger; expect FIND-dup-id 10 "RED findings-dup-id" "$rc" "$out"
rm -f "${repo:?}/docs/findings/s2.jsonl"
printf '%s\n' "$good2" > "$repo/docs/findings/s1.jsonl"
ledger --base HEAD; expect FIND-rewrite-edit 10 "RED findings-rewrite" "$rc" "$out"
rm -f "${repo:?}/docs/findings/s1.jsonl"
ledger --base HEAD; expect FIND-rewrite-delete 10 "RED findings-rewrite" "$rc" "$out"
ledger --base no-such-ref; expect FIND-bad-base 2 "usage error:" "$rc" "$out"
printf '%s\n' "$good" > "$repo/docs/findings/a ñ.jsonl"
git -C "$repo" add -A && git -C "$repo" commit -qm spaced >/dev/null 2>&1
ledger --base HEAD; expect FIND-nonascii-path 0 "GREEN findings" "$rc" "$out"
rm -f "${repo:?}/docs/findings/a ñ.jsonl"
ledger --base HEAD; expect FIND-nonascii-path-delete 10 "RED findings-rewrite" "$rc" "$out"

# ---------------------------------------------------------------- workflow warn mode
# Run sovereign-ci's own `flow` step under the shell Actions uses for
# `shell: bash` (bash -eo pipefail) with stub guards that go RED: in warn mode
# the step must stay green and downgrade each RED to ::warning::.
wf="$FLOW_DIR/../../.github/workflows/sovereign-ci.yml"
ws="$tmp/wf"; mkdir -p "$ws/.flow-guards/scripts/flow"
awk '/name: FLOW guards \(rules 17, 18, 19\)/{f=1} f&&/run: \|/{r=1; next} r&&/^  [a-z]/{exit} r{sub(/^          /,""); print}' "$wf" > "$ws/step.sh"
for g in check_pr_closes check_findings_ledger check_issue_flow; do
  printf '#!/usr/bin/env bash\necho "RED stub %s"; exit 10\n' "$g" > "$ws/.flow-guards/scripts/flow/$g.sh"
done
printf '#!/usr/bin/env bash\necho warn\n' > "$ws/.flow-guards/scripts/flow/flow_mode.sh"
wfrun() { run env -C "$ws" EVENT_NAME=pull_request REPO=o/r PR_BODY=x BASE_SHA=HEAD bash -eo pipefail step.sh; }
# pick PATTERN: compare on the first output line carrying PATTERN (MISSING if none)
pick() { out="$(printf '%s\n' "$out" | grep -m1 -F -- "$1" || echo MISSING)"; }
wfrun; pick "::warning::inflow"; expect WF-warn-red-stays-green 0 "::warning::inflow (warn):" "$rc" "$out"
printf '#!/usr/bin/env bash\necho "usage error: bad json" >&2; exit 2\n' > "$ws/.flow-guards/scripts/flow/flow_mode.sh"
wfrun; pick "running in warn"; expect WF-bad-state-warns 0 "::warning::flow_mode could" "$rc" "$out"
printf '#!/usr/bin/env bash\necho block\n' > "$ws/.flow-guards/scripts/flow/flow_mode.sh"
wfrun; pick "::error::inflow"; expect WF-block-red-fails 1 "::error::inflow (block):" "$rc" "$out"

# ---------------------------------------------------------------- §2.8 schedule
st="$tmp/flow-guards.json"
cat > "$st" <<'EOF'
{"a5_done":"2026-09-27T12:00:00Z","cap_tag":"2026-10-02T00:00:00Z",
 "checks":{"no-close":{"first_green":"2026-09-26T00:00:00Z","last_violation":"2026-09-26T10:00:00Z"},
           "unmetered-intake":{"first_green":"2026-09-26T00:00:00Z"}}}
EOF
while IFS=$'\t' read -r id want check now file; do
  [ "$file" = none ] && file="$tmp/absent.json"
  [ "$file" = st ] && file="$st"
  run bash "$FLOW_DIR/flow_mode.sh" --check "$check" --state "$file" --now "$now"
  if [ "$rc" = 0 ] && [ "$out" = "$want" ]; then pass=$((pass + 1)); else
    fail=$((fail + 1)); printf 'FAIL %-26s want %s got exit=%s "%s"\n' "$id" "$want" "$rc" "$out"; fi
done <<'EOF'
MODE-no-state-warn	warn	no-close	2026-12-01T00:00:00Z	none
MODE-no-state-cap-alert	alert	cap	2026-12-01T00:00:00Z	none
MODE-noclose-clean-23h	warn	no-close	2026-09-27T09:59:59Z	st
MODE-noclose-clean-24h	block	no-close	2026-09-27T10:00:00Z	st
MODE-intake-24h-from-fg	block	unmetered-intake	2026-09-27T00:00:00Z	st
MODE-intake-before-24h	warn	unmetered-intake	2026-09-26T23:59:59Z	st
MODE-inflow-before-a5	warn	inflow	2026-09-27T11:59:59Z	st
MODE-inflow-at-a5	block	inflow	2026-09-27T12:00:00Z	st
MODE-ratchet-at-a5	block	ratchet	2026-09-28T00:00:00Z	st
MODE-orphan-at-a5	block	orphan	2026-09-28T00:00:00Z	st
MODE-priority-before-a5	warn	priority	2026-09-26T00:00:00Z	st
MODE-cap-before-tag	alert	cap	2026-10-01T23:59:59Z	st
MODE-cap-at-tag	block	cap	2026-10-02T00:00:00Z	st
MODE-unscheduled	warn	findings	2027-01-01T00:00:00Z	st
EOF
printf '{not json' > "$tmp/bad.json"
run bash "$FLOW_DIR/flow_mode.sh" --check inflow --state "$tmp/bad.json"
expect MODE-bad-json 2 "usage error:" "$rc" "$out"
printf '{"a5_done":"yesterday-ish"}' > "$tmp/baddate.json"
run bash "$FLOW_DIR/flow_mode.sh" --check inflow --state "$tmp/baddate.json"
expect MODE-bad-date 2 "usage error:" "$rc" "$out"

echo "flow guard case table: $pass passed, $fail failed"
[ "$fail" -eq 0 ] && [ "$pass" -gt 0 ]
