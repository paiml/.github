#!/usr/bin/env bash
# Falsifier for the ADV-001 advisory gate in sovereign-ci.yml (paiml/infra#3648).
# Usage: test-advisory-gate.sh            case table + end-to-end + mutants, stub scanner (CI)
#        ADV_REAL_DB=<advisory-db checkout> test-advisory-gate.sh
#                                         the same end-to-end legs with the REAL cargo-audit
#                                         and a real advisory-db (local evidence; no network)
#
# Extracts the "Advisory gate (diff-only, pinned advisory-db)" step body from the workflow
# and drives it two ways: sourced (SOV_ADV_LIB=1) for its functions, and executed whole
# against throwaway git repos for the PR / merge_group / push paths. Green requires:
#   - a PR whose lock ADDS a vulnerable crate is RED; an unchanged vulnerable lock is GREEN
#   - every cannot-check shape exits 75 (fail closed), never 0
#   - the positive control fails when the scanner is blind
#   - MUTANT: with the verdict's diff line replaced by `new=""` the case table goes RED
#     (proves this test, and the gate, can fail)
#   - the workflow defaults to diff-only, pins the DB, and checks out with fetch-depth: 0
# shellcheck disable=SC2034 # variables set in subshells are read by the sourced step
set -uo pipefail
cd "$(dirname "$0")/.." || exit 2
WF=${ADV_GATE_WF:-.github/workflows/sovereign-ci.yml}
T=$(mktemp -d) || exit 2
trap 'rm -rf "${T:?}"' EXIT
fails=0 oks=0
ok() { oks=$((oks + 1)); echo "ok   $1"; }
bad() { fails=$((fails + 1)); echo "FAIL $1"; }

awk '/- name: Advisory gate \(diff-only, pinned advisory-db\)/{s=1;next} s&&/^      - name:/{exit} s&&/^        run: \|/{r=1;next} r{sub(/^          /,"");print}' "$WF" >"$T/step.sh"
[ -s "$T/step.sh" ] || { echo "FAIL: could not extract the advisory gate step"; exit 2; }
grep -q '# adv-verdict-diff' "$T/step.sh" || { echo "FAIL: mutant marker '# adv-verdict-diff' missing"; exit 2; }

# ---- static: the workflow is wired the way ADV-001 says --------------------------------
inp() { awk -v k="      $1:" '$0==k{s=1;next} s&&/^      [a-z_]+:$/{exit} s&&/^        default:/{sub(/^        default: */,"");print;exit}' "$WF"; }
[ "$(inp advisories_diff_only)" = true ] && ok "advisories_diff_only defaults to true" || bad "advisories_diff_only default is '$(inp advisories_diff_only)', want true"
[[ "$(inp advisory_db_rev | tr -d "'")" =~ ^[0-9a-f]{40}$ ]] && ok "advisory_db_rev default is a 40-hex pin" || bad "advisory_db_rev default is not a 40-hex pin"
sec=$(awk '/^  security:$/{s=1} s&&/^  [a-z_-]+:$/&&!/^  security:$/{exit} s' "$WF")
grep -A8 'uses: actions/checkout@' <<<"$sec" | grep -q 'fetch-depth: 0' && ok "security checkout has fetch-depth: 0" || bad "security checkout lacks fetch-depth: 0"
grep -q -- '--no-fetch' "$T/step.sh" && ok "gate scans with --no-fetch" || bad "gate scan does not pass --no-fetch"
grep -A2 'name: Advisory gate (diff-only' <<<"$sec" | grep -q 'if: \${{ inputs.advisories_diff_only }}' && ok "gate step runs when diff-only" || bad "gate step if: is not inputs.advisories_diff_only"

# ---- stub cargo-audit: answers from a fixed table, like the real one -------------------
mkdir -p "$T/bin"
cat >"$T/bin/cargo" <<'STUB'
#!/usr/bin/env bash
# stub: cargo audit --db D --no-fetch --stale --json --file LOCK [--ignore ID]...
[ "${1:-}" = audit ] || { echo "stub cargo: only 'audit' ($*)" >&2; exit 2; }
shift
[ "${1:-}" = --version ] && { echo "cargo-audit-audit 0.0.0-stub"; exit 0; }
lock="" ign="" db=""
while [ $# -gt 0 ]; do
  case "$1" in --file) lock=$2; shift ;; --ignore) ign="$ign $2"; shift ;; --db) db=$2; shift ;; esac
  shift
done
[ -d "$db/crates" ] || { echo "error: error loading advisory database: $db" >&2; exit 1; }
[ -f "$lock" ] || { echo "error: not found: Couldn't load $lock" >&2; exit 2; }
[ -n "${STUB_BLIND:-}" ] && { printf '{"vulnerabilities":{"found":false,"count":0,"list":[]}}\n'; exit 0; }
list=$(awk '/^name = /{n=$3} /^version = /{gsub(/"/,"",n); v=$3; gsub(/"/,"",v); print n" "v}' "$lock" | while read -r n v; do
  case "$n@$v" in
    smallvec@0.6.9) id=RUSTSEC-2019-0009 ;;
    libsqlite3-sys@0.30.1) id=RUSTSEC-2026-0459 ;;
    *) continue ;;
  esac
  case " $ign " in *" $id "*) continue ;; esac
  jq -cn --arg i "$id" --arg n "$n" --arg v "$v" '{advisory:{id:$i},package:{name:$n,version:$v}}'
done | jq -s -c .)
jq -cn --argjson l "$list" '{vulnerabilities:{found:($l|length>0),count:($l|length),list:$l}}'
[ "$list" = "[]" ] && exit 0 || exit 1
STUB
cp "$T/bin/cargo" "$T/bin/cargo-audit"
chmod +x "$T/bin/cargo" "$T/bin/cargo-audit"
STUBPATH="$T/bin:$PATH"

# ---- case table over adv_verdict (sourced) ----------------------------------------------
F="$T/fx"; mkdir -p "$F"
row() { jq -cn --arg i "$1" --arg n "$2" --arg v "$3" '{advisory:{id:$i},package:{name:$n,version:$v}}'; }
rep() { local l; l=$(jq -s -c . <<<"$*"); jq -cn --argjson l "$l" '{vulnerabilities:{found:($l|length>0),count:($l|length),list:$l}}'; }
rep "$(row RUSTSEC-2026-0459 libsqlite3-sys 0.30.1)" >"$F/a.json"
rep "$(row RUSTSEC-2026-0459 libsqlite3-sys 0.30.1)" "$(row RUSTSEC-2019-0009 smallvec 0.6.9)" >"$F/a2.json"
rep "$(row RUSTSEC-2026-0459 libsqlite3-sys 0.30.1)" "$(row RUSTSEC-2026-0459 libsqlite3-sys 0.31.0)" >"$F/a3.json"
rep >"$F/empty.json"
printf 'garbage\n' >"$F/bad.json"
printf '{"vulnerabilities":{"found":true,"count":2,"list":[{"advisory":{"id":"X"},"package":{"name":"c","version":"1"}}]}}\n' >"$F/count.json"
printf '{"database":{}}\n' >"$F/nofound.json"

table() { # STEPFILE -> number of wrong rows
  local step=$1 wrong=0
  # shellcheck disable=SC1090
  ( SOV_ADV_LIB=1; . "$step"
    t() { local rc=0; adv_verdict "$F/$3" "$4" "$F/$5" "$6" >/dev/null 2>&1 || rc=$?
          [ "$rc" = "$2" ] || { echo "  row '$1' want $2 got $rc"; return 1; }; }
    n=0
    t 'same advisory on both sides: pass'               0  a.json 1 a.json 1 || n=$((n+1))
    t 'both clean: pass'                                0  empty.json 0 empty.json 0 || n=$((n+1))
    t 'PR adds a new id: block'                         1  a2.json 1 a.json 1 || n=$((n+1))
    t 'PR adds a crate version under a known id: block' 1  a3.json 1 a.json 1 || n=$((n+1))
    t 'PR adds a vulnerable crate to a clean base: block' 1 a.json 1 empty.json 0 || n=$((n+1))
    t 'base has it, PR fixed it: pass'                  0  empty.json 0 a.json 1 || n=$((n+1))
    t 'rc 0 but findings parsed: cannot check'          75 a.json 0 empty.json 0 || n=$((n+1))
    t 'rc 1 but nothing found: cannot check'            75 empty.json 1 empty.json 0 || n=$((n+1))
    t 'tool error rc 2: cannot check'                   75 empty.json 2 empty.json 0 || n=$((n+1))
    t 'garbage JSON: cannot check'                      75 bad.json 1 empty.json 0 || n=$((n+1))
    t 'not a cargo-audit report: cannot check'          75 nofound.json 0 empty.json 0 || n=$((n+1))
    t 'count != list length: cannot check'              75 count.json 1 empty.json 0 || n=$((n+1))
    t 'base side missing: cannot check'                 75 a.json 1 nope.json 1 || n=$((n+1))
    exit "$n" ) || wrong=$?
  return "$wrong"
}
if table "$T/step.sh"; then ok "verdict case table (13 rows)"; else bad "verdict case table"; fi

# MUTANT 1: the verdict never sees what the PR adds
sed 's/^\(.*\)new=\$(.*# adv-verdict-diff$/\1new=""/' "$T/step.sh" >"$T/mut1.sh"
cmp -s "$T/step.sh" "$T/mut1.sh" && { echo "FAIL: mutant 1 did not apply"; exit 2; }
w=0; table "$T/mut1.sh" >/dev/null || w=$?
[ "$w" -ge 3 ] && ok "MUTANT verdict-blind is caught ($w rows red)" || bad "MUTANT verdict-blind survived ($w rows red) -- the table cannot fail"

# ---- pinned advisory-db (adv_db) against a local origin -------------------------------
g() { git -c user.name=t -c user.email=t@t -c commit.gpgsign=false -c init.defaultBranch=main -c init.templateDir= -c core.hooksPath=/dev/null "$@"; }
if [ -n "${ADV_REAL_DB:-}" ]; then
  DBO="$ADV_REAL_DB"; REV=$(git -C "$DBO" rev-parse HEAD)
else
  DBO="$T/advisory-db"; g init -q "$DBO"; mkdir -p "$DBO/crates/smallvec"; echo x >"$DBO/crates/smallvec/RUSTSEC-2019-0009.md"
  g -C "$DBO" add -A; g -C "$DBO" commit -q -m db; REV=$(git -C "$DBO" rev-parse HEAD)
fi
git -C "$DBO" config uploadpack.allowAnySHA1InWant true 2>/dev/null || true
dbrun() { ( SOV_ADV_LIB=1 SOV_ADV_CACHE="$T/cache" SOV_ADV_MIRROR="$T/no-mirror" SOV_ADV_DB_URL="file://$DBO"; . "$T/step.sh"; adv_db "$1" ) 2>/dev/null; }
rc=0; p=$(dbrun "$REV") || rc=$?
[ "$rc" = 0 ] && [ "$(git -C "$p" rev-parse HEAD)" = "$REV" ] && ok "adv_db materialises exactly the pinned commit" || bad "adv_db at the pin rc=$rc"
rc=0; dbrun "${REV:0:12}" >/dev/null || rc=$?; [ "$rc" = 75 ] && ok "short pin -> 75" || bad "short pin rc=$rc"
rc=0; dbrun "$(printf 'f%.0s' {1..40})" >/dev/null || rc=$?; [ "$rc" = 75 ] && ok "unreachable pin -> 75" || bad "unreachable pin rc=$rc"
rc=0; ( SOV_ADV_LIB=1 SOV_ADV_CACHE="$T/cache" SOV_ADV_MIRROR="$T/no-mirror" SOV_ADV_DB_URL="file://$T/gone"; . "$T/step.sh"; adv_db "$REV" ) >/dev/null 2>&1 || rc=$?
[ "$rc" = 0 ] && ok "cached pin is reused with the origin gone (no fetch at gate time)" || bad "cached pin re-fetched (rc=$rc)"

# ---- positive control -------------------------------------------------------------------
if [ -n "${ADV_REAL_DB:-}" ]; then SCANPATH="$PATH"; else SCANPATH="$STUBPATH"; fi
pc() { ( PATH="$SCANPATH" SOV_ADV_LIB=1; . "$T/step.sh"; adv_positive_control "$p" ) >/dev/null 2>&1; }
pc && ok "positive control passes with a seeing scanner" || bad "positive control failed with a seeing scanner"
rc=0; ( PATH="$STUBPATH" SOV_ADV_LIB=1; export STUB_BLIND=1; . "$T/step.sh"; adv_positive_control "$p" ) >/dev/null 2>&1 || rc=$?
[ "$rc" != 0 ] && ok "MUTANT blind scanner: positive control goes RED" || bad "MUTANT blind scanner: positive control stayed green"

# ---- end to end: the whole step against a repo ----------------------------------------
LOCK_HDR='version = 3

[[package]]
name = "app"
version = "0.1.0"
'
VULN='
[[package]]
name = "libsqlite3-sys"
version = "0.30.1"
source = "registry+https://github.com/rust-lang/crates.io-index"
'
SMALL='
[[package]]
name = "smallvec"
version = "0.6.9"
source = "registry+https://github.com/rust-lang/crates.io-index"
'
mkrepo() { # NAME BASE_LOCK HEAD_LOCK -> prints "dir base"
  local d="$T/repos/$1"; mkdir -p "$d"; g init -q "$d"
  printf '[package]\nname = "app"\nversion = "0.1.0"\n' >"$d/Cargo.toml"; printf '%s' "$2" >"$d/Cargo.lock"
  g -C "$d" add -A; g -C "$d" commit -q -m base; local b; b=$(git -C "$d" rev-parse HEAD)
  printf '%s' "$3" >"$d/Cargo.lock"; echo "// change" >>"$d/Cargo.toml"; g -C "$d" add -A; g -C "$d" commit -q -m pr
  echo "$d $b"
}
e2e() { # EVENT DIR BASE [REF] -> rc of the step
  local rc=0
  ( cd "$2" && PATH="$SCANPATH" GITHUB_WORKSPACE="$2" GITHUB_TOKEN=x RUNNER_TOOL_CACHE="$T/rtc" SOV_ADV_CACHE="$T/cache" \
      SOV_ADV_MIRROR="$T/no-mirror" SOV_ADV_DB_URL="file://$DBO" SOV_ADV_EVENT="$1" SOV_ADV_REF="${4:-refs/heads/main}" SOV_ADV_PR_BASE="$3" SOV_ADV_MG_BASE="$3" \
      SOV_ADV_DB_REV_INPUT="$REV" bash "$T/step.sh" ) >"$T/e2e.out" 2>&1 || rc=$?
  echo "$rc"
}
if [ -n "${ADV_REAL_DB:-}" ]; then V="$VULN"; else V="$VULN"; fi
read -r d b < <(mkrepo unchanged "$LOCK_HDR$V" "$LOCK_HDR$V")
r=$(e2e pull_request "$d" "$b"); [ "$r" = 0 ] && ok "e2e PR, lock unchanged, vulnerable crate already on base -> GREEN" || { bad "e2e unchanged-vulnerable rc=$r"; tail -5 "$T/e2e.out"; }
grep -q 'ADVISORY ANDON (already on the base' "$T/e2e.out" && ok "e2e pre-existing advisory is reported as an andon warning" || bad "e2e pre-existing advisory not reported"
r=$(e2e merge_group "$d" "$b"); [ "$r" = 0 ] && ok "e2e merge_group, lock unchanged -> GREEN" || bad "e2e merge_group unchanged rc=$r"
read -r d b < <(mkrepo adds "$LOCK_HDR" "$LOCK_HDR$V")
r=$(e2e pull_request "$d" "$b"); [ "$r" = 1 ] && ok "e2e PR adds a vulnerable crate -> RED" || { bad "e2e adds-vulnerable rc=$r"; tail -5 "$T/e2e.out"; }
grep -q 'RUSTSEC-2026-0459|libsqlite3-sys@0.30.1' "$T/e2e.out" && ok "e2e RED names RUSTSEC-2026-0459|libsqlite3-sys@0.30.1" || bad "e2e RED does not name the finding"
r=$(e2e push "$d" "$b"); [ "$r" = 0 ] && grep -q '::warning::ADVISORY ANDON (on this commit' "$T/e2e.out" && ok "e2e push with an advisory -> warning, not red" || bad "e2e push rc=$r"
r=$(e2e schedule "$d" "$b"); [ "$r" = 0 ] && grep -q '::warning::ADVISORY ANDON (on this commit' "$T/e2e.out" && ok "e2e schedule with an advisory -> warning, not red" || bad "e2e schedule rc=$r"
# release paths are a GATE (GATE/LAB rule 6): a finding at the pin is RED, never a warning
r=$(e2e push "$d" "$b" refs/tags/v1.2.3); [ "$r" = 1 ] && grep -q '::error::advisory on a release path' "$T/e2e.out" && ok "e2e tag push (refs/tags/v1.2.3) with an advisory -> RED" || { bad "e2e tag push with an advisory rc=$r (release path must be RED)"; tail -3 "$T/e2e.out"; }
r=$(e2e workflow_dispatch "$d" "$b"); [ "$r" = 1 ] && grep -q '::error::advisory on a release path' "$T/e2e.out" && ok "e2e workflow_dispatch with an advisory -> RED" || { bad "e2e workflow_dispatch with an advisory rc=$r (release path must be RED)"; tail -3 "$T/e2e.out"; }
read -r d2 b2 < <(mkrepo clean "$LOCK_HDR" "$LOCK_HDR")
r=$(e2e push "$d2" "$b2" refs/tags/v1.2.3); [ "$r" = 0 ] && ok "e2e tag push with no advisory -> GREEN" || bad "e2e clean tag push rc=$r"
r=$(e2e pull_request "$d" "deadbeef"); [ "$r" = 75 ] && ok "e2e malformed base sha -> 75" || bad "e2e malformed base rc=$r"
r=$(e2e pull_request "$d" "$(printf 'a%.0s' {1..40})"); [ "$r" = 75 ] && ok "e2e base not in checkout -> 75" || bad "e2e absent base rc=$r"
# a PR may not waive what it introduces: ignore added only on the PR side
read -r d b < <(mkrepo waive "$LOCK_HDR" "$LOCK_HDR$SMALL")
mkdir -p "$d/.cargo"; printf 'ignore = ["RUSTSEC-2019-0009"]\n' >"$d/.cargo/audit.toml"; g -C "$d" add -A; g -C "$d" commit -q -m waive
r=$(e2e pull_request "$d" "$b"); [ "$r" = 1 ] && ok "e2e PR adding the vulnerable crate AND its ignore -> still RED (base ignores rule)" || bad "e2e self-waiver rc=$r"
# no scanner installed
rc=0; ( cd "$d" && PATH="/usr/bin:/bin" GITHUB_WORKSPACE="$d" GITHUB_TOKEN=x SOV_ADV_EVENT=pull_request SOV_ADV_PR_BASE="$b" SOV_ADV_DB_REV_INPUT="$REV" bash "$T/step.sh" ) >/dev/null 2>&1 || rc=$?
[ "$rc" = 75 ] && ok "e2e no cargo-audit on PATH -> 75" || bad "e2e no scanner rc=$rc"

# ---- advisory-andon.yml: one ticket per finding, never a duplicate ---------------------
AWF=.github/workflows/advisory-andon.yml
awk '/- name: Scan the default branch against the latest advisory-db/{s=1;next} s&&/^      - name:/{exit} s&&/^        run: \|/{r=1;next} r{sub(/^          /,"");print}' "$AWF" >"$T/andon.sh"
[ -s "$T/andon.sh" ] || { echo "FAIL: could not extract the andon step"; exit 2; }
grep -Eq '^  (pull_request|merge_group)' "$AWF" && bad "advisory-andon.yml has a PR/merge_group trigger" || ok "advisory-andon.yml is off the PR / merge_group path"
printf '#!/usr/bin/env bash\necho "$*" >>"%s/gh.calls"\n[ -n "${STUB_GH_FAIL:-}" ] && [ "$1 $2" = "issue list" ] && exit 1\n[ "$1 $2" = "issue list" ] && printf "%%s\\n" "${STUB_OPEN:-}"\nexit 0\n' "$T" >"$T/bin/gh"
chmod +x "$T/bin/gh"
printf 'RUSTSEC-2026-0459|libsqlite3-sys@0.30.1\nRUSTSEC-2019-0009|smallvec@0.6.9\n' >"$T/keys"
an() { : >"$T/gh.calls"; local rc=0; ( SOV_ADV_LIB=1 GH="$T/bin/gh"; export STUB_OPEN="$1" STUB_GH_FAIL="${2:-}"; . "$T/andon.sh"; andon_emit "$T/keys" ) >/dev/null 2>&1 || rc=$?; echo "$rc"; }
r=$(an ""); [ "$r" = 0 ] && [ "$(grep -c 'issue create' "$T/gh.calls")" = 2 ] && ok "andon: two new findings -> two issues" || bad "andon new findings rc=$r"
r=$(an "ADVISORY ANDON: RUSTSEC-2026-0459|libsqlite3-sys@0.30.1"); [ "$r" = 0 ] && [ "$(grep -c 'issue create' "$T/gh.calls")" = 1 ] && ok "andon: an open issue is not duplicated" || bad "andon dedupe rc=$r"
r=$(an "" 1); [ "$r" = 75 ] && ! grep -q 'issue create' "$T/gh.calls" && ok "andon: issue list failure -> 75, nothing created" || bad "andon list failure rc=$r"

echo "advisory gate falsifier: $oks ok, $fails failed$([ -n "${ADV_REAL_DB:-}" ] && echo " (REAL cargo-audit, advisory-db $REV)")"
[ "$fails" = 0 ]
