#!/usr/bin/env bash
# lint-pr-gate-runs-on.sh -- the pr-gate `authorize` job must ask for the pr-gate runner label,
# and no workflow here may ask for a GitHub-hosted runner (paiml/infra#231, #1859; paiml/rmedia#1192).
set -uo pipefail
cd "$(dirname "$0")/.." || exit 2
W=.github/workflows/pr-gate.yml
rc=0
# runs-on line of the authorize job: first `runs-on:` after the `  authorize:` key
line=$(awk '/^  authorize:/{f=1} f && /^    runs-on:/{print; exit}' "$W")
if [ -z "$line" ]; then echo "lint-pr-gate-runs-on: FAIL: no runs-on found for the authorize job in $W"; rc=1
elif ! grep -qE '[[,] *pr-gate *[],]' <<<"$line"; then
  echo "lint-pr-gate-runs-on: FAIL: authorize runs-on lacks the pr-gate label: $line"; rc=1; fi
if grep -nE '^\s*runs-on:.*(ubuntu-|windows-|macos-)' .github/workflows/*.yml; then
  echo "lint-pr-gate-runs-on: FAIL: a workflow asks for a GitHub-hosted runner"; rc=1; fi
[ "$rc" -eq 0 ] && echo "lint-pr-gate-runs-on: OK (authorize carries pr-gate; no hosted runner)"
exit "$rc"
