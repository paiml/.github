#!/usr/bin/env bash
# infra#2349 guard (shell + awk only). Usage: test-uid-agnostic-chown.sh [--self-test]
#
# A "site" is the uid-agnostic self-heal block: from the line carrying
# "uid-agnostic (infra#2349)" to the closing `rm -f "${CHOWN_FAILED:?}"` at step indent.
# The self-heal runs before checkout, so it is inline; all sites must be byte-identical.
# FAILS (tag in brackets) on:
#   [NUMERIC]  any numeric uid:gid chown, anywhere in the workflows
#   [LITERAL]  a 1000 / 1001 literal within 3 lines of a chown (non-comment lines)
#   [TARGET]   a chown in a site whose target is not "$OWNER_UG"
#   [ASSIGN]   OWNER_UG assigned from anything except the stat of the runner temp paths
#   [SWALLOW]  `|| true` or `2>/dev/null` on a chown in a site
#   [FALLBACK] a fallback branch (fallback wording, a case on OWNER_UG, a 0:0 special case)
#   [DRIFT]    sites not byte-identical, or an unterminated site
#   [NOSITE]   no site found (0 violations over 0 sites is not a pass)
# It also runs the first site for real: owner read, unreadable owner exits 1 with ::error::,
# a failing chown exits 1 with a count.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 2
WF=${WF_DIR:-.github/workflows}
MARK='uid-agnostic (infra#2349)'
STAT_LINE='            OWNER_UG="$(stat -c '"'"'%u:%g'"'"' "$P")" && break'
LOOP_LINE='          for P in "${RUNNER_TEMP:-}" "$WORK_ROOT/_temp" "$WORK_ROOT"; do'

extract_sites() { # file outdir -> writes outdir/site.N
  awk -v out="$2" -v mark="$MARK" '
    index($0, mark) && !on { on=1; n++; f=out "/site." n }
    on { print > f }
    on && $0 == "          rm -f \"${CHOWN_FAILED:?}\"" { on=0; close(f) }
  ' "$1"
}

check_files() { # prints FAIL[tag] lines; returns 1 if any
  local fails=0 tmp sites=0 f
  tmp="$(mktemp -d)"
  for f in "$WF"/*.yml; do
    # NUMERIC: any non-comment chown with a numeric uid[:gid] argument
    awk -v F="$f" '/^[[:space:]]*#/ {next} /chown[[:space:]]+(-[A-Za-z]+[[:space:]]+)*"?[0-9]+(:[0-9]+)?"?([[:space:]]|$)/ {print "FAIL[NUMERIC] " F ":" NR ": " $0}' "$f"
    # LITERAL: 1000/1001 within 3 lines of a chown
    awk -v F="$f" '/^[[:space:]]*#/ {next} {l[NR]=$0} /chown/ {c[NR]=1} END {for (i in l) if (l[i] ~ /(^|[^0-9])100[01]([^0-9]|$)/) for (j=i-3;j<=i+3;j++) if (c[j]) {print "FAIL[LITERAL] " F ":" i ": " l[i]; break}}' "$f"
  done | sort -u > "$tmp/global"
  [ -s "$tmp/global" ] && { cat "$tmp/global"; fails=1; }
  for f in "$WF"/*.yml; do
    mkdir "$tmp/d"; extract_sites "$f" "$tmp/d"
    for s in "$tmp"/d/site.*; do
      [ -e "$s" ] || continue
      sites=$((sites + 1)); cp "$s" "$tmp/all.$sites"
      grep -q '^          rm -f "${CHOWN_FAILED:?}"$' "$s" || { echo "FAIL[DRIFT] $f: unterminated site"; fails=1; }
      # TARGET: every chown command word in a site targets "$OWNER_UG"
      if grep -vE '^[[:space:]]*#|^[[:space:]]*echo ' "$s" | grep -E '(^|[^a-zA-Z_])chown[[:space:]]' | grep -vqE 'chown (-[a-zA-Z]+ )*"\$OWNER_UG" '; then
        echo "FAIL[TARGET] $f: a site chown target is not \"\$OWNER_UG\""; fails=1; fi
      # ASSIGN: only OWNER_UG="" and the stat line, plus the stat loop over exactly the runner paths
      bad="$(grep -nE '(^|[[:space:];])OWNER_UG=' "$s" | grep -vE ':[[:space:]]+OWNER_UG=""$' | grep -vF "$STAT_LINE" | grep -vE 'export OWNER_UG' || true)"
      [ -n "$bad" ] && { echo "FAIL[ASSIGN] $f: OWNER_UG not from stat of runner paths: $bad"; fails=1; }
      grep -qxF "$STAT_LINE" "$s" && grep -qxF "$LOOP_LINE" "$s" || { echo "FAIL[ASSIGN] $f: stat loop over the runner temp paths missing or altered"; fails=1; }
      # SWALLOW: || true / 2>/dev/null on a chown
      if grep -E '(^|[^a-zA-Z_])chown[[:space:]]' "$s" | grep -vE '^[[:space:]]*#' | grep -qE '\|\|[[:space:]]*true|2>[[:space:]]*/dev/null|&>[[:space:]]*/dev/null'; then
        echo "FAIL[SWALLOW] $f: chown error swallowed"; fails=1; fi
      # FALLBACK
      if grep -vE '^[[:space:]]*#' "$s" | grep -qiE 'fall(ing)?[ -]?back|case "\$OWNER_UG"|(^|[^0-9])0:0'; then
        echo "FAIL[FALLBACK] $f: fallback branch in a site"; fails=1; fi
    done
    rm -rf "${tmp:?}/d"
  done
  [ "$sites" -eq 0 ] && { echo "FAIL[NOSITE] no uid-agnostic site under $WF"; fails=1; }
  i=2
  while [ "$i" -le "$sites" ]; do
    cmp -s "$tmp/all.1" "$tmp/all.$i" || { echo "FAIL[DRIFT] site $i differs from site 1"; fails=1; }
    i=$((i + 1))
  done
  [ "$fails" -eq 0 ] && echo "ok   $sites site(s), byte-identical, uid-agnostic, no swallowed chown, no fallback"
  [ -e "$tmp/all.1" ] && cp "$tmp/all.1" "${SITE_COPY:-/dev/null}" 2>/dev/null
  rm -rf "${tmp:?}"
  return "$fails"
}

run_site() { # behavioural run of the first site: mode = ok | unreadable | chownfail
  local mode="$1" d site rc out
  d="$(mktemp -d)"; mkdir -p "$d/w/_temp" "$d/w/ws" "$d/bin"
  site="$d/site.sh"
  { echo 'set -u'; echo 'WORK_ROOT="$W"'; sed -e 's/^          //' "$SITE_FILE"; } > "$site"
  case "$mode" in
    unreadable) rmdir "$d/w/_temp" "$d/w/ws"; export RUNNER_TEMP="$d/none"; W="$d/none2" ;;
    chownfail) printf '#!/bin/sh\nexit 1\n' > "$d/bin/chown"; chmod +x "$d/bin/chown"; chown_target="$d/w/ws/x"; : > "$chown_target"
      export RUNNER_TEMP="$d/w/_temp"; W="$d/w" ;;
    *) export RUNNER_TEMP="$d/w/_temp"; W="$d/w" ;;
  esac
  export W
  if [ "$mode" = chownfail ]; then
    # make a file the owner check selects: pretend the owner uid differs via a stubbed stat
    printf '#!/bin/sh\necho 4242:4242\n' > "$d/bin/stat"; chmod +x "$d/bin/stat"
  fi
  out="$(PATH="$d/bin:$PATH" bash "$site" 2>&1)"; rc=$?
  rm -rf "${d:?}"
  printf '%s\n' "$out" | tail -n 3
  return "$rc"
}

behaviour() {
  [ -s "${SITE_FILE:-}" ] || { echo "FAIL[NOSITE] no site to execute"; return 1; }
  local rc=0 o
  o="$(run_site ok)" && echo "$o" | grep -q 'runner owner' && echo "ok   site runs, owner read from temp dir" || { echo "FAIL[BEHAVIOUR] ok-case: $o"; rc=1; }
  o="$(run_site unreadable)"; r=$?
  if [ "$r" -ne 0 ] && echo "$o" | grep -q '::error::cannot read the runner owner'; then echo "ok   unreadable owner -> ::error:: + nonzero"; else echo "FAIL[BEHAVIOUR] unreadable owner did not fail visibly: $o"; rc=1; fi
  o="$(run_site chownfail)"; r=$?
  if [ "$r" -ne 0 ] && echo "$o" | grep -q '::error::chown to .* failed on [1-9]'; then echo "ok   failing chown -> ::error:: with count + nonzero"; else echo "FAIL[BEHAVIOUR] chown failure swallowed: $o"; rc=1; fi
  return "$rc"
}

run_all() {
  export SITE_FILE; SITE_FILE="$(mktemp)"
  SITE_COPY="$SITE_FILE" check_files; local a=$?
  behaviour; local b=$?
  rm -f "${SITE_FILE:?}"
  [ "$a" -eq 0 ] && [ "$b" -eq 0 ]
}

if [ "${1:-}" = "--self-test" ]; then
  tmp="$(mktemp -d)"; trap 'rm -rf "${tmp:?}"' EXIT
  F=sovereign-ci.yml
  expect() { # name tag : run the guard on $tmp, demand FAIL[tag]
    if cmp -s "$WF/$F" "$tmp/$F"; then echo "SELF-TEST FAIL: mutation '$1' changed nothing"; exit 1; fi
    out="$(WF_DIR=$tmp SITE_COPY= bash "$0" 2>&1 || true)"
    echo "$out" | grep -q "FAIL\[$2\]" || { echo "SELF-TEST FAIL: '$1' not caught as [$2]"; echo "$out" | head -n 5; exit 1; }
    echo "  caught [$2] $1"
  }
  swap() { # name tag old new : replace the FIRST occurrence of old (plain text) with new
    cp "$WF"/*.yml "$tmp"/
    OLD="$3" NEW="$4" awk '!d && (i = index($0, ENVIRON["OLD"])) { $0 = substr($0, 1, i-1) ENVIRON["NEW"] substr($0, i+length(ENVIRON["OLD"])); d=1 } {print}' "$WF/$F" > "$tmp/$F"
    expect "$1" "$2"
  }
  app() { # name tag line : append a line
    cp "$WF"/*.yml "$tmp"/; printf '%s\n' "$3" >> "$tmp/$F"; expect "$1" "$2"
  }
  CH=chown
  C='chown -h "$OWNER_UG" "$p"'
  app  "numeric 1000:1000 chown"   NUMERIC  "          $CH -R 1000:1000 \"\$WORK_ROOT\""
  app  "numeric 1001:1001 chown"   NUMERIC  "          $CH -R 1001:1001 \"\$GITHUB_WORKSPACE\""
  app  "bare numeric uid chown"    NUMERIC  "          $CH -R 1234 \"\$WORK_ROOT\""
  swap "1000 literal near chown"   LITERAL  "$C" "$C; U=1000"
  swap "1001 literal near chown"   LITERAL  "$C" "$C; U=1001"
  swap "chown target not OWNER_UG" TARGET   "$C" 'chown -h "$OWNER" "$p"'
  swap "OWNER_UG from id"          ASSIGN   '          OWNER_UG=""' '          OWNER_UG="$(id -u):$(id -g)"'
  swap "extra OWNER_UG literal"    ASSIGN   '          export OWNER_UG' '          OWNER_UG=1234:1234'
  swap "stat path list altered"    ASSIGN   '"$WORK_ROOT/_temp" "$WORK_ROOT"; do' '"$WORK_ROOT/_temp" "$WORK_ROOT" "/home/runner"; do'
  swap "|| true on chown"          SWALLOW  '|| printf "%s\n" "$p"' '|| true'
  swap "2>/dev/null on chown"      SWALLOW  '"$p" ||' '"$p" 2>/dev/null ||'
  swap "fallback wording"          FALLBACK '          export OWNER_UG' '          echo "falling back"'
  swap "case on OWNER_UG"          FALLBACK '          export OWNER_UG' '          case "$OWNER_UG" in *) : ;; esac'
  swap "0:0 special case"          FALLBACK '          export OWNER_UG' '          [ "$OWNER_UG" = 0:0 ] && :'
  swap "one site drifts"           DRIFT    'runner owner (stat of runner temp dir)' 'runner owner'
  cp "$WF"/*.yml "$tmp"/; sed -i 's/uid-agnostic (infra#2349)/uid-x/' "$tmp/$F"
  out="$(WF_DIR=$tmp SITE_COPY= bash "$0" 2>&1 || true)"
  echo "$out" | grep -q 'FAIL\[NOSITE\]' || { echo "SELF-TEST FAIL: no-site not caught"; exit 1; }
  echo "  caught [NOSITE] no site at all"
  # BEHAVIOUR: a site that swallows the chown failure and a fallback-to-1000 site fail the executed check
  echo "self-test ok: every mutation caught (red)"; exit 0
fi
run_all
