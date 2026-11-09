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

# Private repo: checkout is persist-credentials:false, so a fetch with no auth header dies "could not read
# Username" (exit 128 in rmedia#2459, jobs 129152425028/129156850838). A git shim refuses any fetch that
# carries no http.extraheader; the step must pass its token, and the original unauthenticated line must go red.
mkdir -p "$T/shim"
REAL=$(command -v git)
# The shim accepts a fetch only when the token arrives as git's env config (key scoped to github.com, value =
# the exact basic header for $GITHUB_TOKEN) and is NOT on argv (/proc/<pid>/cmdline is world-readable).
cat > "$T/shim/git" <<SHIM
#!/usr/bin/env bash
case " \$* " in *" fetch "*)
  case "\$*" in *extraheader*|*tok*) echo "fatal: token or header on argv" >&2; exit 97 ;; esac
  want="AUTHORIZATION: basic \$(printf 'x-access-token:%s' "\${GITHUB_TOKEN:-}" | base64 -w0)"
  if [ "\${GITHUB_TOKEN:-}" = "" ] || [ "\${GIT_CONFIG_KEY_0:-}" != "http.https://github.com/.extraheader" ] || [ "\${GIT_CONFIG_VALUE_0:-}" != "\$want" ]; then
    echo "fatal: could not read Username for 'https://github.com': No such device or address" >&2; exit 128
  fi ;;
esac
exec "$REAL" "\$@"
SHIM
chmod +x "$T/shim/git"
# GITHUB_TOKEN reaches the step only if the step's own env block declares it (as Actions would).
declares() { awk '/- name: roadmap-fragment-parity/{s=1;next} s&&/^      - name:/{exit} s' "$1" | grep -q '^ *GITHUB_TOKEN: \${{ github.token }}'; }
WF_NOENV="$T/wf-noenv.yml"; grep -v '^ *GITHUB_TOKEN: \${{ github.token }}' "$WF" > "$WF_NOENV"
sed '/export GIT_CONFIG_COUNT GIT_CONFIG_KEY_0 GIT_CONFIG_VALUE_0/d' "$T/step.sh" | awk '/shallow-fix/||1' > "$T/step-noauth.sh"
run_priv() { # $1 script, $2 workflow file whose env block decides if the token is passed
  fresh_clone
  if declares "$2"; then tok=tok; else tok=; fi
  ( cd "$T/c" && PATH="$T/shim:$PATH" GITHUB_TOKEN=$tok BASE_SHA=$BASE HEAD_SHA=$HEAD bash "$1" ) >"$T/out" 2>&1
}
if run_priv "$T/step.sh" "$WF"; then echo "ok: private origin, token via env -> green"; else echo "FAIL: private origin, with fix is red"; tail -n 5 "$T/out"; rc=1; fi
if run_priv "$T/step-noauth.sh" "$WF"; then echo "FAIL: private origin without auth is green (cannot discriminate)"; rc=1; else echo "ok: private origin without auth -> red"; fi
if run_priv "$T/step.sh" "$WF_NOENV"; then echo "FAIL: step green with the GITHUB_TOKEN env line deleted"; rc=1; else echo "ok: GITHUB_TOKEN env line deleted -> red"; fi
exit $rc
