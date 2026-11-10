#!/usr/bin/env bash
# NET-INSTALL-LINT (paiml/infra#3828): a pull_request-triggered workflow must not fetch or
# install from the network in a step's run: text (curl, wget, apt/apt-get install, cargo
# install/binstall, pip install, npm i/install/ci/add). PR jobs run on shared self-hosted
# runners: a network install there is an unpinned, unreviewed input to the gate, and it
# fails the PR when the mirror does. Provision the tool instead (/opt/fleet-bin, forjar).
#
# Usage: net-install-lint.sh [--self-test] [FILE|DIR ...]   (default: .github/workflows)
# Reads each step's run: text (single line, quoted, or a | / > block), joins backslash
# continuations, drops comments, and skips echo/printf/: lines, so a mention is not a hit.
# Only workflows whose on: names pull_request or pull_request_target are judged.
# Exit: 0 clean, 1 finding(s), 2 nothing scanned or the self-test could not classify.
set -uo pipefail

# One pattern per line, "name|ERE". The self-test deletes each line in turn and demands red.
PATS=(
  'curl|(^|[^[:alnum:]_./-])curl([[:space:]]|$)' # PAT:curl
  'wget|(^|[^[:alnum:]_./-])wget([[:space:]]|$)' # PAT:wget
  'apt-get-install|(^|[^[:alnum:]_./-])apt-get([[:space:]]+-[^[:space:]]+)*[[:space:]]+install([[:space:]]|$)' # PAT:apt-get-install
  'apt-install|(^|[^[:alnum:]_./-])apt([[:space:]]+-[^[:space:]]+)*[[:space:]]+install([[:space:]]|$)' # PAT:apt-install
  'cargo-install|(^|[^[:alnum:]_./-])cargo([[:space:]]+[+][^[:space:]]+)?([[:space:]]+-[^[:space:]]+)*[[:space:]]+(install|binstall)([[:space:]]|$)' # PAT:cargo-install
  'pip-install|(^|[^[:alnum:]_./-])pip[0-9x.]*([[:space:]]+-[^[:space:]]+)*[[:space:]]+install([[:space:]]|$)' # PAT:pip-install
  'npm-install|(^|[^[:alnum:]_./-])npm([[:space:]]+-[^[:space:]]+)*[[:space:]]+(i|install|ci|add)([[:space:]]|$)' # PAT:npm-install
)

# FILE -> "LINE<TAB>text" for every line of every step's run: text, or nothing when the
# workflow is not pull_request-triggered. A block scalar ends at the first non-blank line
# indented at or under its run: key.
run_lines() {
  awk '
    function ind(s) { match(s, /^ */); return RLENGTH }
    BEGIN { pr = 0; inon = 0 }
    { L[NR] = $0 }
    /^("on"|on|true)[ \t]*:/ {
      inon = 1; v = $0; sub(/^[^:]*:[ \t]*/, "", v)
      if (v ~ /(^|[^a-z_])pull_request(_target)?([^a-z_]|$)/) pr = 1
      next
    }
    inon && /^[^ \t#]/ { inon = 0 }
    inon && /^[ \t]+(- )?["\047]?pull_request(_target)?["\047]?[ \t]*(:|$|#)/ { pr = 1 }
    END {
      if (!pr) exit 0
      for (i = 1; i <= NR; i++) {
        s = L[i]
        if (s !~ /^[ \t]*(- )?run:/) continue
        k = ind(s); if (s ~ /^[ \t]*- /) k += 2
        v = s; sub(/^[ \t]*(- )?run:[ \t]*/, "", v)
        if (v ~ /^[|>][-+0-9]*[ \t]*(#.*)?$/) {
          for (j = i + 1; j <= NR; j++) {
            t = L[j]
            if (t ~ /^[ \t]*$/) continue
            if (ind(t) <= k) break
            printf "%d\t%s\n", j, t
          }
          i = j - 1
        } else {
          if (v ~ /^".*"[ \t]*$/ || v ~ /^\047.*\047[ \t]*$/) { v = substr(v, 2); sub(/["\047][ \t]*$/, "", v) }
          printf "%d\t%s\n", i, v
        }
      }
    }' "$1"
}

# FILE -> "FAIL FILE:LINE: [pattern] command" per finding; returns 1 on any finding.
scan_file() {
  local f="$1" ln txt start="" acc="" hits=0 p name re cmd seg
  while IFS=$'\t' read -r ln txt; do
    [ -n "$start" ] || start="$ln"
    if [[ "$txt" =~ \\[[:space:]]*$ ]]; then acc+="${txt%\\*} "; continue; fi
    cmd="${acc}${txt}"; acc=""
    cmd="$(printf '%s' "$cmd" | sed -E 's/(^|[[:space:]])#.*$//')"
    # Judge each simple command on its own, so "echo x && curl y" is still a hit.
    while IFS= read -r seg; do
      seg="${seg#"${seg%%[![:space:]]*}"}"
      case "$seg" in echo|echo\ *|printf|printf\ *|:|:\ *) continue ;; esac
      for p in ${PATS[@]+"${PATS[@]}"}; do
        name="${p%%|*}"; re="${p#*|}"
        if [[ "$seg" =~ $re ]]; then
          printf 'FAIL %s:%s: [%s] %s\n' "$f" "$start" "$name" "$seg"
          hits=$((hits + 1)); break
        fi
      done
    done < <(printf '%s\n' "$cmd" | sed -E 's/(&&|\|\||;|\|)/\n/g')
    start=""
  done < <(run_lines "$f")
  [ "$hits" -eq 0 ]
}

# FILE|DIR ... -> scans every .yml/.yaml; prints a count line; 2 when nothing was scanned.
scan() {
  local -a files=()
  local a f rc=0 n=0 pr=0
  [ "$#" -gt 0 ] || set -- .github/workflows
  for a in "$@"; do
    if [ -d "$a" ]; then
      while IFS= read -r -d '' f; do files+=("$f"); done < <(find "$a" -maxdepth 1 -type f \( -name '*.yml' -o -name '*.yaml' \) -print0 | sort -z)
    elif [ -f "$a" ]; then files+=("$a"); fi
  done
  for f in ${files[@]+"${files[@]}"}; do
    n=$((n + 1))
    if [ -n "$(run_lines "$f")" ]; then pr=$((pr + 1)); fi
    scan_file "$f" || rc=1
  done
  echo "net-install-lint: scanned ${n} workflow(s), ${pr} pull_request-triggered with run: text, rc=${rc}"
  if [ "$n" -eq 0 ]; then echo "net-install-lint: 0 workflows scanned - refusing to report green" >&2; return 2; fi
  return "$rc"
}

# bad-*.yml carry "# expect: <pattern>" and must go red on exactly that pattern; good-*.yml
# must stay green. Then each PATS line is deleted in a copy of this script, and that
# mutant's fixture run must go red (a pattern no fixture needs is a pattern nobody tested).
self_test() {
  local dir out exp f rc bad=0 cnt=0 p name m
  dir="${NET_INSTALL_LINT_FIXTURES:-$(cd "$(dirname "$0")" && pwd)/fixtures/net-install-lint}"
  for f in "$dir"/*.yml; do
    [ -f "$f" ] || continue
    cnt=$((cnt + 1))
    out="$(scan_file "$f")"; rc=$?
    case "${f##*/}" in
      bad-*)
        exp="$(sed -n 's/^# expect: *//p' "$f" | head -n 1)"
        if [ "$rc" -ne 0 ] && grep -cF -- "[$exp]" <<<"$out" >/dev/null; then echo "ok   ${f##*/} red on [$exp]"
        else echo "FAIL ${f##*/} expected red on [$exp], got rc=$rc: $out"; bad=$((bad + 1)); fi ;;
      good-*)
        if [ "$rc" -eq 0 ]; then echo "ok   ${f##*/} green"; else echo "FAIL ${f##*/} expected green: $out"; bad=$((bad + 1)); fi ;;
    esac
  done
  if [ "$cnt" -lt 2 ]; then echo "self-test: ${cnt} fixture(s) in ${dir} - cannot classify" >&2; return 2; fi
  if [ -z "${NET_INSTALL_LINT_NO_MUTANTS:-}" ]; then
    for p in ${PATS[@]+"${PATS[@]}"}; do
      name="${p%%|*}"
      m="$(mktemp)"
      sed "/# PAT:${name}\$/d" "$0" > "$m"
      if cmp -s "$0" "$m"; then echo "FAIL mutant drop-${name} did not change the script"; bad=$((bad + 1))
      elif NET_INSTALL_LINT_NO_MUTANTS=1 NET_INSTALL_LINT_FIXTURES="$dir" bash "$m" --self-test >/dev/null 2>&1; then
        echo "FAIL mutant drop-${name} still passes the fixtures"; bad=$((bad + 1))
      else echo "ok   mutant drop-${name} killed"; fi
      rm -f -- "${m:?}"
    done
  fi
  echo "self-test: ${cnt} fixture(s), ${bad} failure(s)"
  [ "$bad" -eq 0 ]
}

if [ "${1:-}" = "--self-test" ]; then self_test; exit $?; fi
scan "$@"
