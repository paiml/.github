#!/usr/bin/env bash
# roadmap-fragment-parity must fetch HEAD_SHA when the depth-1 merge checkout lacks it (rmedia#2374).
# Usage: test-fragment-parity-head.sh [--self-test]. Shell + awk only.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 2
WF=${WF:-.github/workflows/sovereign-ci.yml}
check() { # file -> 0 when the step fetches HEAD_SHA before the diff and refuses if still absent
  awk '
    /- name: roadmap-fragment-parity/ {s=1; next}
    s && /^      - name:/ {s=0}
    s && /git fetch .*"\$HEAD_SHA"/ {f=NR}
    s && /git cat-file -e "\$HEAD_SHA"/ {c=NR}
    s && /head \$HEAD_SHA is unreachable/ {u=NR}
    s && /git diff --name-only "\$BASE_SHA" "\$HEAD_SHA"/ {d=NR}
    END { exit !(f && c && u && d && f < d && u < d) }' "$1"
}
if [ "${1:-}" = "--self-test" ]; then
  t=$(mktemp); trap 'rm -f -- "$t"' EXIT
  grep -v 'HEAD_SHA"* *2>/dev/null || true' "$WF" | grep -v 'head \$HEAD_SHA is unreachable' > "$t"
  check "$t" && { echo "FAIL self-test: a step without the HEAD_SHA fetch passed"; exit 1; }
  echo "ok   self-test: a step without the HEAD_SHA fetch is refused"; exit 0
fi
check "$WF" && echo "ok   roadmap-fragment-parity fetches and verifies HEAD_SHA before the diff" || { echo "FAIL roadmap-fragment-parity never fetches HEAD_SHA (rmedia#2374: fatal: bad object)"; exit 1; }
