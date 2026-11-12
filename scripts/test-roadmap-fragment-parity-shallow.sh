#!/usr/bin/env bash
# Falsifier for roadmap-fragment-parity (GATE-JUNK-001, infra#3711): the step makes 0 network
# fetches, still goes RED when the base is truly missing, and is green on a full-history checkout.
# Usage: test-roadmap-fragment-parity-shallow.sh
set -uo pipefail
cd "$(dirname "$0")/.." || exit 2
WF=.github/workflows/sovereign-ci.yml
T=$(mktemp -d) || exit 2
trap 'rm -rf "${T:?}"' EXIT

awk '/- name: roadmap-fragment-parity/{s=1;next} s&&/^      - name:/{exit} s&&/^        run: \|/{r=1;next} r{sub(/^          /,"");print}' "$WF" > "$T/step.sh"
[ -s "$T/step.sh" ] || { echo "FAIL: could not extract the step"; exit 2; }
rc=0
if grep -v '^[[:space:]]*#' "$T/step.sh" | grep -q 'git fetch'; then echo "FAIL: step makes a network fetch"; rc=1; else echo "ok: step has no git fetch"; fi
# the security job's checkout must carry fetch-depth: 0
sec=$(awk '/^  security:/{s=1;next} s&&/^  [a-z-]+:$/{exit} s' "$WF")
# read the checkout step's whole `with:` block (up to the next step), not a fixed window: a comment
# block between `uses:` and `fetch-depth:` (ADV-001, #106) pushed it past a 4-line grep -A and
# turned this green check red on main.
if printf '%s\n' "$sec" | awk '/uses: actions\/checkout/{s=1;next} s&&/^      - /{exit} s&&/^          fetch-depth: 0[[:space:]]*$/{f=1} END{exit !f}'; then echo "ok: security checkout is fetch-depth: 0"; else echo "FAIL: security checkout lacks fetch-depth: 0"; rc=1; fi

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

# clone, then break the remote: any fetch would fail exactly like the credential-stripped runner
run_case() { # "$@" = extra clone args
  rm -rf "${T:?}/c"
  git clone -q "$@" "file://$O" "$T/c" 2>/dev/null
  git -C "$T/c" remote set-url origin "file://$T/does-not-exist"
  ( cd "$T/c" && BASE_SHA=$BASE HEAD_SHA=$HEAD bash "$T/step.sh" ) >"$T/out" 2>&1
}
if run_case; then echo "ok: full-history checkout -> green"; else echo "FAIL: full history is red"; tail -n 5 "$T/out"; rc=1; fi
if run_case --depth 1; then echo "FAIL: base missing is green (cannot go red)"; rc=1; else echo "ok: base missing -> red"; tail -n 2 "$T/out" | sed 's/^::error::/expected red: /'; fi
exit $rc
