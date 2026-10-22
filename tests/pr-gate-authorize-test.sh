#!/usr/bin/env bash
# Test for the `authorize` step of .github/workflows/pr-gate.yml (aprender#5951).
# Extracts the real step script from the workflow and runs it against a stubbed
# `gh`. Set PRGATE_MUTATE=failopen to prove the test discriminates (it rewires
# the fail-closed branches into passes and the test must go RED).
set -uo pipefail
cd "$(dirname "$0")/.."
WF=.github/workflows/pr-gate.yml
T=$(mktemp -d); trap 'rm -rf "${T:?}"' EXIT

awk '/id: authz/{a=1} a&&/run: \|/{r=1;next} r&&/^      - name:/{exit} r{sub(/^          /,"");print}' "$WF" > "$T/step.sh"
[ -s "$T/step.sh" ] || { echo "FAIL: could not extract step"; exit 2; }
if [ "${PRGATE_MUTATE:-}" = failopen ]; then
  sed -i 's/^\( *\)exit 1 ;;$/\1echo "allow=true" >> "$GITHUB_OUTPUT"; exit 0 ;;/' "$T/step.sh"
  sed -i 's/^\( *\)exit 1$/\1echo "allow=true" >> "$GITHUB_OUTPUT"; exit 0/' "$T/step.sh"
fi

mkdir -p "$T/bin"
cat > "$T/bin/gh" <<'STUB'
#!/usr/bin/env bash
# gh api orgs/paiml/memberships/<user>; replies from $STUB/<user> (rc|text per line, last repeats)
user=${2##*/}; f="$STUB/$user"; n=$(cat "$f.n" 2>/dev/null || echo 0); n=$((n+1)); echo $n > "$f.n"
line=$(sed -n "${n}p" "$f"); [ -n "$line" ] || line=$(tail -n1 "$f")
rc=${line%%|*}; txt=${line#*|}; printf '%s\n' "$txt"; exit "$rc"
STUB
chmod +x "$T/bin/gh"

pass=0; fail=0
run() {
  local name=$1 author=$2 want_rc=$3 want_allow=$4 out rc allow
  : > "$T/out"; export STUB="$T/s" GITHUB_OUTPUT="$T/out" PRGATE_BACKOFF="0 0 0"
  rm -f "${STUB:?}"/*.n
  out=$(PATH="$T/bin:$PATH" PR_AUTHOR=$author PR_AUTHOR_TYPE=User bash "$T/step.sh" 2>&1); rc=$?
  allow=$(sed -n 's/^allow=//p' "$T/out" | tail -n1)
  if [ "$rc" = "$want_rc" ] && [ "${allow:-}" = "$want_allow" ]; then
    echo "ok   $name"; pass=$((pass+1))
  else
    echo "FAIL $name: rc=$rc (want $want_rc) allow='${allow:-}' (want '$want_allow')"; printf '%s\n' "$out" | tail -n 4; fail=$((fail+1))
  fi
}
seed() { rm -rf "${T:?}/s"; mkdir -p "$T/s"; }
MEMBER='0|{"state":"active"}'; NOT='1|gh: Not Found (HTTP 404)'; S503='1|gh: Service Unavailable (HTTP 503)'
CTRL() { printf '%s\n' "$MEMBER" > "$T/s/noahgift"; printf '%s\n' "$NOT" > "$T/s/paiml-pr-gate-sentinel-no-such-user"; }

seed; CTRL; printf '%s\n' "$MEMBER" > "$T/s/alice"; run "member -> pass" alice 0 true
seed; CTRL; printf '%s\n' "$NOT" > "$T/s/mallory"; run "non-member -> rejected (allow=false)" mallory 0 false
seed; CTRL; printf '%s\n%s\n%s\n' "$S503" "$S503" "$MEMBER" > "$T/s/alice"; run "5xx twice then member -> pass" alice 0 true
seed; CTRL; printf '%s\n' "$S503" > "$T/s/alice"; run "persistent 5xx -> fail-closed" alice 1 ""
seed; CTRL; printf '%s\n' '1|gh: Resource not accessible (HTTP 302)' > "$T/s/alice"; run "302 -> fail-closed" alice 1 ""
seed; CTRL; printf '%s\n' '1|gh: Bad credentials (HTTP 401)' > "$T/s/alice"; run "401 -> fail-closed" alice 1 ""
seed; CTRL; printf '%s\n' '0|<html>proxy error</html>' > "$T/s/alice"; run "200 non-JSON -> fail-closed" alice 1 ""
seed; printf '%s\n' "$S503" > "$T/s/noahgift"; printf '%s\n' "$S503" > "$T/s/paiml-pr-gate-sentinel-no-such-user"; printf '%s\n' "$MEMBER" > "$T/s/alice"; run "probe indeterminate -> fail-closed" alice 1 ""
seed; printf '%s\n' "$MEMBER" > "$T/s/noahgift"; printf '%s\n' "$MEMBER" > "$T/s/paiml-pr-gate-sentinel-no-such-user"; run "blind instrument -> fail-closed" alice 1 ""
seed; CTRL; : > "$T/out"; export GITHUB_OUTPUT="$T/out" PRGATE_BACKOFF="0 0 0"
out=$(PATH="/nonexistent" PR_AUTHOR=alice PR_AUTHOR_TYPE=User /bin/bash "$T/step.sh" 2>&1); rc=$?
if [ "$rc" = 1 ] && grep -q 'gh not found' <<<"$out"; then echo "ok   gh missing -> fail-closed naming cause"; pass=$((pass+1)); else echo "FAIL gh missing: rc=$rc"; fail=$((fail+1)); fi

echo "passed=$pass failed=$fail"; [ "$fail" = 0 ]
