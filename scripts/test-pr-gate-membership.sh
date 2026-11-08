#!/usr/bin/env bash
# pr-gate authorize: membership() answers from the GraphQL budget first, so an
# exhausted REST core quota (an account-wide budget unrelated to the PR) cannot
# turn a member's PR red. Fail-closed is kept: both APIs failing = indeterminate.
#
# Runs the membership() block extracted VERBATIM from pr-gate.yml against a stub
# `gh` on PATH. Usage: test-pr-gate-membership.sh [--self-test]
#   --self-test  also proves the test can fail: a REST-only membership() (the
#                pre-fix shape) must be RED on this suite.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 2
WF=${WF_FILE:-.github/workflows/pr-gate.yml}
TMP=$(mktemp -d) || exit 2
trap 'rm -rf "${TMP:?}"' EXIT

# --- stub gh ---------------------------------------------------------------
# STUB_REST: member | pending | notfound | ratelimit
# STUB_GQL:  member | notmember | nouser | ratelimit | garbage
# Every call is logged to $STUB_LOG as "rest" or "graphql".
mkdir -p "$TMP/bin"
cat > "$TMP/bin/gh" <<'STUB'
#!/usr/bin/env bash
if [ "${1:-}" = api ] && [ "${2:-}" = graphql ]; then
  echo graphql >> "$STUB_LOG"
  case "$STUB_GQL" in
    member)    echo '{"data":{"user":{"login":"u","organization":{"login":"paiml"}}}}' ;;
    notmember) echo '{"data":{"user":{"login":"u","organization":null}}}' ;;
    nouser)    echo '{"data":{"user":null},"errors":[{"type":"NOT_FOUND","path":["user"],"message":"Could not resolve to a User"}]}'
               echo "gh: Could not resolve to a User" >&2 ;;
    ratelimit) echo '{"errors":[{"type":"RATE_LIMITED","message":"API rate limit exceeded"}]}'
               echo "gh: API rate limit exceeded" >&2; exit 1 ;;
    garbage)   echo 'not json'; exit 1 ;;
  esac
  exit 0
fi
if [ "${1:-}" = api ]; then
  echo rest >> "$STUB_LOG"
  case "$STUB_REST" in
    member)    echo '{"state":"active"}' ;;
    pending)   echo '{"state":"pending"}' ;;
    notfound)  echo 'gh: Not Found (HTTP 404)'; exit 1 ;;
    ratelimit) echo 'gh: API rate limit exceeded for user ID 1. (HTTP 403)'; exit 1 ;;
  esac
  exit 0
fi
exit 3
STUB
chmod +x "$TMP/bin/gh"

# --- extract membership() from the workflow, verbatim -----------------------
# From the "# Returns: member | notmember | indeterminate" comment to the next
# "# ----" banner (the instrument-probe section). Indentation is stripped.
extract() { # wf-file -> stdout
  awk '/# Returns: member \| notmember \| indeterminate/ {on=1}
       on && /# -{20,}/ {exit}
       on {sub(/^          /, ""); print}' "$1"
}

run_suite() { # fn-file -> 0 all pass, 1 any fail
  local fn="$1" bad=0 n=0
  # name | STUB_REST | STUB_GQL | want | want_rest_calls (0 = REST must not be called, - = any)
  while IFS='|' read -r name rest gql want rest_calls; do
    [ -n "$name" ] || continue
    n=$((n + 1))
    : > "$TMP/log"
    got=$(ORG=paiml STUB_LOG="$TMP/log" STUB_REST="$rest" STUB_GQL="$gql" PATH="$TMP/bin:$PATH" \
          bash -c 'set -uo pipefail; ORG=paiml; . "$1"; membership someuser' _ "$fn" 2>/dev/null)
    calls=$(grep -c '^rest$' "$TMP/log")
    ok=1
    [ "$got" = "$want" ] || ok=0
    [ "$rest_calls" = - ] || [ "$calls" = "$rest_calls" ] || ok=0
    if [ "$ok" = 1 ]; then echo "ok   $name -> $got (rest calls $calls)"
    else echo "FAIL $name -> got '$got' want '$want' (rest calls $calls, want $rest_calls)"; bad=$((bad + 1)); fi
  done <<'ROWS'
REST quota 0, GraphQL member -> member|ratelimit|member|member|0
REST quota 0, GraphQL notmember -> notmember|ratelimit|notmember|notmember|0
REST quota 0, GraphQL no such user -> notmember|ratelimit|nouser|notmember|0
GraphQL member answers without spending REST|member|member|member|0
GraphQL rate-limited falls back to REST member|member|ratelimit|member|1
GraphQL rate-limited falls back to REST pending -> notmember|pending|ratelimit|notmember|1
GraphQL rate-limited falls back to REST 404 -> notmember|notfound|ratelimit|notmember|1
GraphQL garbage falls back to REST member|member|garbage|member|1
BOTH rate-limited -> indeterminate (fail closed, never notmember)|ratelimit|ratelimit|indeterminate|1
GraphQL garbage + REST rate-limited -> indeterminate|ratelimit|garbage|indeterminate|1
ROWS
  echo "$((n - bad)) passed, $bad failed (of $n)"
  [ "$n" -gt 0 ] && [ "$bad" -eq 0 ]
}

extract "$WF" > "$TMP/fn.sh"
grep -q "^membership() {" "$TMP/fn.sh" || { echo "FAIL: membership() not found in $WF -- nothing to judge"; exit 1; }

if [ "${1:-}" = --self-test ]; then
  # The pre-fix shape: REST only. It MUST be red here, or this suite proves nothing.
  cat > "$TMP/restonly.sh" <<'OLD'
membership() {
  local user="$1" resp rc state
  resp=$(gh api "orgs/${ORG}/memberships/${user}" 2>&1) && rc=0 || rc=$?
  if [ "$rc" -eq 0 ]; then
    state=$(printf '%s' "$resp" | jq -r '.state // "unknown"')
    if [ "$state" = "active" ]; then echo member; else echo notmember; fi
    return 0
  fi
  case "$resp" in
    *"HTTP 404"*) echo notmember ;;
    *)            echo indeterminate ;;
  esac
}
OLD
  if run_suite "$TMP/restonly.sh" > "$TMP/st.out"; then
    echo "SELF-TEST FAIL: the REST-only membership() passed this suite"; exit 2
  fi
  echo "self-test ok: REST-only membership() is RED ($(tail -n 1 "$TMP/st.out"))"
fi

run_suite "$TMP/fn.sh"
