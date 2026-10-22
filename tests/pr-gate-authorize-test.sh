#!/usr/bin/env bash
# Test for the `authorize` step of .github/workflows/pr-gate.yml (aprender#5951).
# Extracts the REAL step script and runs it with event env vars. `gh` is a stub
# that exits 99 and records every call: the step must make zero calls.
# Mutants (must go RED): PRGATE_MUTATE=allownone (NONE on allow-list),
# PRGATE_MUTATE=failopen (fail-closed branches become passes).
set -uo pipefail
cd "$(dirname "$0")/.."
WF=.github/workflows/pr-gate.yml
T=$(mktemp -d); trap 'rm -rf "${T:?}"' EXIT

awk '/id: authz/{a=1} a&&/run: \|/{r=1;next} r&&/^      - name:/{exit} r{sub(/^          /,"");print}' "$WF" > "$T/step.sh"
[ -s "$T/step.sh" ] || { echo "FAIL: could not extract step"; exit 2; }
case "${PRGATE_MUTATE:-}" in
  allownone) sed -i 's/OWNER|MEMBER|COLLABORATOR)/OWNER|MEMBER|COLLABORATOR|NONE)/' "$T/step.sh" ;;
  failopen)  sed -i 's/^\( *\)exit 1 ;;$/\1exit 0 ;;/; s/^\( *\)exit 1$/\1exit 0/' "$T/step.sh" ;;
esac

mkdir -p "$T/bin"
cat > "$T/bin/gh" <<'STUB'
#!/usr/bin/env bash
echo "gh $*" >> "$GH_CALLS"; exit 99
STUB
chmod +x "$T/bin/gh"; export GH_CALLS="$T/gh.calls"

pass=0; fail=0
# run NAME WANT_RC WANT_ALLOW [VAR=VAL ...]  (env cleared of event vars first)
run() {
  local name=$1 want_rc=$2 want_allow=$3 out rc allow; shift 3
  : > "$T/out"
  out=$(env -u EVENT_NAME -u PR_AUTHOR -u PR_AUTHOR_TYPE -u PR_ASSOCIATION \
        PATH="$T/bin:$PATH" GITHUB_OUTPUT="$T/out" "$@" bash "$T/step.sh" 2>&1); rc=$?
  allow=$(sed -n 's/^allow=//p' "$T/out" | tail -n1)
  if [ "$rc" = "$want_rc" ] && [ "${allow:-}" = "$want_allow" ]; then
    echo "ok   $name"; pass=$((pass+1))
  else
    echo "FAIL $name: rc=$rc (want $want_rc) allow='${allow:-}' (want '$want_allow')"; printf '%s\n' "$out" | tail -n 3; fail=$((fail+1))
  fi
}
PR=(EVENT_NAME=pull_request_target PR_AUTHOR=alice PR_AUTHOR_TYPE=User)
for a in OWNER MEMBER COLLABORATOR; do run "$a -> pass" 0 true "${PR[@]}" PR_ASSOCIATION=$a; done
run "CONTRIBUTOR -> fail, allow=false" 1 false "${PR[@]}" PR_ASSOCIATION=CONTRIBUTOR
run "NONE -> fail, allow=false"        1 false "${PR[@]}" PR_ASSOCIATION=NONE
run "FIRST_TIME_CONTRIBUTOR -> fail"   1 false "${PR[@]}" PR_ASSOCIATION=FIRST_TIME_CONTRIBUTOR
run "FIRST_TIMER -> fail"              1 false "${PR[@]}" PR_ASSOCIATION=FIRST_TIMER
run "MANNEQUIN -> fail"                1 false "${PR[@]}" PR_ASSOCIATION=MANNEQUIN
run "empty -> fail-closed (open)"      1 ""    "${PR[@]}" PR_ASSOCIATION=
run "missing (unset) -> fail-closed"   1 ""    "${PR[@]}"
run "garbage -> fail-closed"           1 ""    "${PR[@]}" PR_ASSOCIATION=SUPERUSER
run "lowercase member -> fail-closed"  1 ""    "${PR[@]}" PR_ASSOCIATION=member
run "injection value -> fail, no cmd"  1 ""    "${PR[@]}" 'PR_ASSOCIATION=X
::set-output name=allow::true'
run "allowlisted external, NONE -> pass" 0 true EVENT_NAME=pull_request_target PR_AUTHOR=guyernest PR_AUTHOR_TYPE=User PR_ASSOCIATION=NONE
run "bot -> pass" 0 true EVENT_NAME=pull_request_target PR_AUTHOR=dependabot[bot] PR_AUTHOR_TYPE=Bot PR_ASSOCIATION=NONE
run "merge_group -> pass (no PR author)" 0 true EVENT_NAME=merge_group
run "push -> pass (no PR author)" 0 true EVENT_NAME=push
run "unknown event -> fail-closed" 1 "" EVENT_NAME=issues
run "no event at all -> fail-closed" 1 ""

if [ -s "$GH_CALLS" ]; then echo "FAIL gh invoked from step:"; cat "$GH_CALLS"; fail=$((fail+1)); else echo "ok   step never invoked gh (0 calls)"; pass=$((pass+1)); fi
# the extracted script must not mention gh as a command nor host credentials
if grep -Eq '(^|[^A-Za-z_-])gh (api|auth|pr)|unset GH_TOKEN|ambient' <(grep -v '^ *#' "$T/step.sh"); then echo "FAIL step text still references host gh"; fail=$((fail+1)); else echo "ok   no host-gh text in step code"; pass=$((pass+1)); fi

echo "passed=$pass failed=$fail"; [ "$fail" = 0 ]
