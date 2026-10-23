#!/usr/bin/env bash
# infra#2349 guard (shell + awk only). Usage: test-uid-agnostic-chown.sh [--self-test]
#
# A "site" is the uid-agnostic self-heal block: from the line carrying
# "uid-agnostic (infra#2349)" to the closing `rm -f "${CHOWN_FAILED:?}"` at step indent.
# The self-heal runs before checkout, so it is inline; all sites must be byte-identical.
# The WHOLE of every workflow file is scanned (scripts/uid-agnostic-chown-scan.awk), not only the
# sites: every chown/chgrp command word must be the site find line or the bare-metal
# `chown -R "$OWNER" "$WORK_ROOT"` with OWNER="$(id -un):$(id -gn)" in a non-container job.
# FAILS (tag in brackets) on:
#   [NUMERIC]  any numeric uid:gid chown, anywhere in the workflows
#   [LITERAL]  a 1000 / 1001 literal within 3 lines of a chown (non-comment lines)
#   [TARGET]   any chown/chgrp that is not one of the two ruled shapes (incl. an unmarked site)
#   [GID]      a site find that selects by uid only (right uid, wrong gid is never repaired)
#   [ASSIGN]   OWNER_UG not from the stat of the runner temp paths; OWNER not id -un:id -gn
#   [SWALLOW]  `|| true` `|| :` `|| /bin/true` `|| echo` `; true` `2>/dev/null` `&>/dev/null`
#              on a chown or find line, `set +e`, or continue-on-error, in a step with a chown
#   [UNMARKED] a self-heal site without the marker comment
#   [OWNER_SRC] the owner is not read by the one stat of /__e (outside the chowned tree)
#   [INTREE]   a stat of any path inside the chowned tree (RUNNER_TEMP, WORK_ROOT, workspace, HOME, _temp)
#   [NOUID0]   no uid-0 check (error + exit 1, before the find) on the owner
#   [FALLBACK] a fallback branch (fallback wording, a case on OWNER_UG, a 0:0 special case)
#   [DRIFT]    sites not byte-identical, or an unterminated site
#   [NOSITE]   no site found; [NOSCAN] no workflow file or no chown command scanned
# It prints how many files and chown commands it scanned. It also runs the first site for real:
# owner read, unreadable owner exits 1 with ::error::, a failing chown exits 1 with a count, and a
# file with the right uid and the wrong gid gets chowned.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 2
WF=${WF_DIR:-.github/workflows}
MARK='uid-agnostic (infra#2349)'
# The owner source (r6): the step runs as uid 0 inside the job container, so the owner is the stat of
# /__e (the runner's externals dir, outside the chowned _work tree) and uid 0 is refused.
STAT_LINE='          OWNER_UG="$(stat -c '"'"'%u:%g'"'"' /__e)" || OWNER_UG=""'
UID0_LINE='          if [ "${OWNER_UG%%:*}" = "0" ]; then'
INTREE_RE='RUNNER_TEMP|WORK_ROOT|GITHUB_WORKSPACE|RUNNER_WORKSPACE|\$HOME|\${HOME|_temp|_work|/__w|/github/'
ACT=${ACT_DIR:-.github/actions}   # composite actions: scanned like workflows (their run steps are shell)
list_files() { local f; for f in "$WF"/*.yml "$WF"/*.yaml "$ACT"/*/action.yml "$ACT"/*/action.yaml "$ACT"/action.yml; do [ -e "$f" ] && echo "$f"; done; }
# Constants for the whole-file scan (logical lines are trimmed and continuation-joined).
CH=chown; BR='{}'
export MARK
export FIND_A='find "$WORK_ROOT" \( ! -user "${OWNER_UG%%:*}" -o ! -group "${OWNER_UG##*:}" \) -exec sh -c '"'"'for p; do chown -h "$OWNER_UG" "$p" || printf "%s\n" "$p"; done'"'"' sh '"$BR"' + > "$CHOWN_FAILED"'
export FIND_TAIL=' || { echo "::error::find under $WORK_ROOT failed"; rm -f "${CHOWN_FAILED:?}"; exit 1; }'
export OWNER_LINE='OWNER="$(id -un):$(id -gn)"'
export CHOWN_B="$CH -R \"\$OWNER\" \"\$WORK_ROOT\""
SCAN_AWK="${SCAN_AWK:-$(dirname "$0")/uid-agnostic-chown-scan.awk}"

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
  for f in $(list_files); do
    # NUMERIC: any non-comment chown with a numeric uid[:gid] argument
    awk -v F="$f" '/^[[:space:]]*#/ {next} /chown[[:space:]]+(-[A-Za-z]+[[:space:]]+)*"?[0-9]+(:[0-9]+)?"?([[:space:]]|$)/ {print "FAIL[NUMERIC] " F ":" NR ": " $0}' "$f"
    # LITERAL: 1000/1001 within 3 lines of a chown
    awk -v F="$f" '/^[[:space:]]*#/ {next} {l[NR]=$0} /chown/ {c[NR]=1} END {for (i in l) if (l[i] ~ /(^|[^0-9])100[01]([^0-9]|$)/) for (j=i-3;j<=i+3;j++) if (c[j]) {print "FAIL[LITERAL] " F ":" i ": " l[i]; break}}' "$f"
  done | sort -u > "$tmp/global"
  [ -s "$tmp/global" ] && { cat "$tmp/global"; fails=1; }
  # Whole-file scan: every chown/chgrp in every workflow, sites or not.
  local nfiles=0 nchown=0 out
  for f in $(list_files); do
    nfiles=$((nfiles + 1))
    out="$(awk -v F="$f" -f "$SCAN_AWK" "$f")" || { echo "FAIL[NOSCAN] scan of $f errored"; fails=1; continue; }
    printf '%s\n' "$out" | grep '^FAIL' && fails=1
    nchown=$((nchown + $(printf '%s\n' "$out" | sed -n 's/^SCAN //p' | head -n 1)))
  done
  { [ "$nfiles" -eq 0 ] || [ "$nchown" -eq 0 ]; } && { echo "FAIL[NOSCAN] scanned $nfiles file(s) and $nchown chown command(s) under $WF"; fails=1; }
  for f in $(list_files); do
    mkdir "$tmp/d"; extract_sites "$f" "$tmp/d"
    for s in "$tmp"/d/site.*; do
      [ -e "$s" ] || continue
      sites=$((sites + 1)); cp "$s" "$tmp/all.$sites"
      grep -q '^          rm -f "${CHOWN_FAILED:?}"$' "$s" || { echo "FAIL[DRIFT] $f: unterminated site"; fails=1; }
      # ASSIGN: OWNER_UG is assigned only by the one stat line (and exported); nothing else
      bad="$(grep -nE '(^|[[:space:];])OWNER_UG=' "$s" | grep -vF "$STAT_LINE" | grep -vE 'export OWNER_UG' || true)"
      [ -n "$bad" ] && { echo "FAIL[ASSIGN] $f: OWNER_UG assigned other than by the stat of /__e: $bad"; fails=1; }
      # OWNER_SRC: the new owner source is present, unaltered, and the ONLY stat in the site
      grep -qxF "$STAT_LINE" "$s" || { echo "FAIL[OWNER_SRC] $f: the owner is not read by the stat of /__e"; fails=1; }
      [ "$(grep -vE '^[[:space:]]*#' "$s" | grep -vE '^[[:space:]]*(echo|printf)[[:space:]]' | grep -cE '(^|[^A-Za-z_-])stat[[:space:]]')" -eq 1 ] || { echo "FAIL[OWNER_SRC] $f: the site must have exactly one stat (of /__e)"; fails=1; }
      # INTREE: no stat of a path inside the chowned tree, whatever else the site has
      grep -vE '^[[:space:]]*#' "$s" | grep -vE '^[[:space:]]*(echo|printf)[[:space:]]' | grep -E '(^|[^A-Za-z_-])stat[[:space:]]' | grep -qE "$INTREE_RE|for P in" && { echo "FAIL[INTREE] $f: owner stat of a path inside the chowned tree"; fails=1; }
      # NOUID0: the uid-0 check exists, reports ::error:: and exits 1, and runs before the find
      u0="$(grep -nxF "$UID0_LINE" "$s" | head -n 1 | cut -d: -f1)"; fd="$(grep -nE '^          find "\$WORK_ROOT"' "$s" | head -n 1 | cut -d: -f1)"
      if [ -z "$u0" ] || [ -z "$fd" ] || [ "$u0" -ge "$fd" ] \
         || ! sed -n "$((u0 + 1))p" "$s" | grep -qF '::error::runner user mismatch' || [ "$(sed -n "$((u0 + 2))p" "$s" | tr -d ' ')" != "exit1" ]; then
        echo "FAIL[NOUID0] $f: no uid-0 check (::error::runner user mismatch + exit 1) before the find"; fails=1; fi
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
  [ "$fails" -eq 0 ] && echo "ok   $sites site(s), byte-identical; scanned $nfiles workflow file(s), $nchown chown command(s): all ruled shapes, none swallowed, no fallback"
  [ -e "$tmp/all.1" ] && cp "$tmp/all.1" "${SITE_COPY:-/dev/null}" 2>/dev/null
  rm -rf "${tmp:?}"
  return "$fails"
}

run_site() { # behavioural run of the first site: mode = ok | unreadable | chownfail
  local mode="$1" d site rc out
  d="$(mktemp -d)"; mkdir -p "$d/w/_temp" "$d/w/ws" "$d/bin"
  site="$d/site.sh"
  mkdir -p "$d/e"
  { echo 'set -u'; echo 'WORK_ROOT="$W"'; sed -e 's/^          //' -e "s#/__e#$d/e#g" "$SITE_FILE"; } > "$site"
  case "$mode" in
    unreadable) rmdir "$d/w/_temp" "$d/w/ws" "$d/e"; export RUNNER_TEMP="$d/none"; W="$d/none2" ;;
    chownfail) printf '#!/bin/sh\nexit 1\n' > "$d/bin/chown"; chmod +x "$d/bin/chown"; chown_target="$d/w/ws/x"; : > "$chown_target"
      export RUNNER_TEMP="$d/w/_temp"; W="$d/w" ;;
    gidonly) printf '#!/bin/sh\nprintf "%%s\\n" "$*" >> "$LOG"\nexit 0\n' > "$d/bin/chown"; chmod +x "$d/bin/chown"; : > "$d/w/ws/x"
      printf '#!/bin/sh\necho "$(id -u):4242"\n' > "$d/bin/stat"; chmod +x "$d/bin/stat"
      export RUNNER_TEMP="$d/w/_temp" LOG="$d/log"; W="$d/w" ;;
    unsetrt) printf '#!/bin/sh\necho 4242:4343\n' > "$d/bin/stat"; chmod +x "$d/bin/stat"
      printf '#!/bin/sh\nprintf "%%s\n" "$*" >> "$LOG"\nexit 0\n' > "$d/bin/chown"; chmod +x "$d/bin/chown"; : > "$d/w/ws/x"
      unset RUNNER_TEMP; export LOG="$d/log"; W="$d/w" ;;   # RUNNER_TEMP unset: the owner never depended on it
    wrongtemp) printf '#!/bin/sh\nprintf "%%s\n" "$*" >> "$LOG"\nexit 0\n' > "$d/bin/chown"; chmod +x "$d/bin/chown"; : > "$d/w/ws/x"
      printf '#!/bin/sh\ncase "$*" in */e) echo 4242:4343 ;; *) echo 9999:9999 ;; esac\n' > "$d/bin/stat"; chmod +x "$d/bin/stat"
      export RUNNER_TEMP="$d/w/_temp" LOG="$d/log"; W="$d/w" ;;   # RUNNER_TEMP (inside the tree) and WORK_ROOT wrong-owned, /__e right
    uid0) printf '#!/bin/sh\nprintf "%%s\n" "$*" >> "$LOG"\nexit 0\n' > "$d/bin/chown"; chmod +x "$d/bin/chown"; : > "$d/w/ws/x"
      printf '#!/bin/sh\ncase "$*" in */e) echo 0:0 ;; *) echo 4242:4343 ;; esac\n' > "$d/bin/stat"; chmod +x "$d/bin/stat"
      export RUNNER_TEMP="$d/w/_temp" LOG="$d/log"; W="$d/w" ;;   # the owner source reads uid 0: must fail, never chown
    *) printf '#!/bin/sh\nexit 0\n' > "$d/bin/chown"; chmod +x "$d/bin/chown"
      printf '#!/bin/sh\necho 4242:4343\n' > "$d/bin/stat"; chmod +x "$d/bin/stat"; export RUNNER_TEMP="$d/w/_temp"; W="$d/w" ;;
  esac
  export W
  if [ "$mode" = chownfail ]; then
    # make a file the owner check selects: pretend the owner uid differs via a stubbed stat
    printf '#!/bin/sh\necho 4242:4242\n' > "$d/bin/stat"; chmod +x "$d/bin/stat"
  fi
  out="$(PATH="$d/bin:$PATH" bash "$site" 2>&1)"; rc=$?
  [ -s "$d/log" ] && out="$out"$'\n'"CHOWN-CALLED $(tr '\n' ' ' < "$d/log")"
  rm -rf "${d:?}"
  printf '%s\n' "$out" | tail -n 3
  return "$rc"
}

behaviour() {
  [ -s "${SITE_FILE:-}" ] || { echo "FAIL[NOSITE] no site to execute"; return 1; }
  local rc=0 o
  o="$(run_site ok)" && echo "$o" | grep -qE 'runner owner \(stat of .*\): 4242:4343' && echo "ok   site runs, owner read from /__e" || { echo "FAIL[BEHAVIOUR] ok-case: $o"; rc=1; }
  o="$(run_site unreadable)"; r=$?
  if [ "$r" -ne 0 ] && echo "$o" | grep -q '::error::cannot read the runner owner'; then echo "ok   unreadable owner -> ::error:: + nonzero"; else echo "FAIL[BEHAVIOUR] unreadable owner did not fail visibly: $o"; rc=1; fi
  o="$(run_site unsetrt)"; r=$?
  if [ "$r" -eq 0 ] && echo "$o" | grep -q "CHOWN-CALLED -h 4242:4343 "; then echo "ok   RUNNER_TEMP unset -> still repaired to the /__e owner"; else echo "FAIL[BEHAVIOUR] the owner depended on RUNNER_TEMP: $o"; rc=1; fi
  o="$(run_site wrongtemp)"; r=$?
  if [ "$r" -eq 0 ] && echo "$o" | grep -q "CHOWN-CALLED -h 4242:4343 " && ! echo "$o" | grep -q 9999; then echo "ok   RUNNER_TEMP + WORK_ROOT wrong-owned -> still repaired to the runner uid (the /__e owner)"; else echo "FAIL[BEHAVIOUR] a wrong-owned path inside the tree became the owner: $o"; rc=1; fi
  o="$(run_site uid0)"; r=$?
  if [ "$r" -ne 0 ] && echo "$o" | grep -q '::error::runner user mismatch' && ! echo "$o" | grep -q 'CHOWN-CALLED'; then echo "ok   owner uid 0 -> ::error:: runner user mismatch + nonzero, chown never called"; else echo "FAIL[BEHAVIOUR] uid 0 did not fail closed: $o"; rc=1; fi
  o="$(run_site chownfail)"; r=$?
  if [ "$r" -ne 0 ] && echo "$o" | grep -q '::error::chown to .* failed on [1-9]'; then echo "ok   failing chown -> ::error:: with count + nonzero"; else echo "FAIL[BEHAVIOUR] chown failure swallowed: $o"; rc=1; fi
  o="$(run_site gidonly)"; r=$?
  if [ "$r" -eq 0 ] && echo "$o" | grep -qE "CHOWN-CALLED -h [0-9]+:4242 "; then echo "ok   right uid + wrong gid -> chowned"; else echo "FAIL[BEHAVIOUR] a file with the right uid and the wrong gid was not repaired: $o"; rc=1; fi
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
  MISSES=0
  miss() { echo "SELF-TEST FAIL: $*"; [ -n "${KEEP_GOING:-}" ] || exit 1; MISSES=$((MISSES + 1)); }
  expect() { # name tags : run the guard on $tmp, demand FAIL[tag] for each comma-separated tag
    local t
    if cmp -s "$WF/$F" "$tmp/$F"; then echo "SELF-TEST FAIL: mutation '$1' changed nothing"; exit 1; fi
    out="$(WF_DIR=$tmp ACT_DIR=$tmp/actions SITE_COPY= bash "$0" 2>&1 || true)"
    local m0=$MISSES
    for t in ${2//,/ }; do
      echo "$out" | grep -q "FAIL\[$t\]" || miss "'$1' not caught as [$t]"
    done
    [ "$MISSES" -eq "$m0" ] && echo "  caught [$2] $1"
  }
  swap() { # name tags old new : replace the FIRST occurrence of old (plain text) in $F with new
    cp "$WF"/*.yml "$tmp"/
    OLD="$3" NEW="$4" awk '!d && (i = index($0, ENVIRON["OLD"])) { $0 = substr($0, 1, i-1) ENVIRON["NEW"] substr($0, i+length(ENVIRON["OLD"])); d=1 } {print}' "$WF/$F" > "$tmp/$F"
    expect "$1" "$2"
  }
  app() { # name tags text : append lines (printf %b) to $F
    cp "$WF"/*.yml "$tmp"/; printf '%b\n' "$3" >> "$tmp/$F"; expect "$1" "$2"
  }
  C='chown -h "$OWNER_UG" "$p"'
  # --- the site (find + chown -h) ---
  app  "numeric 1000:1000 chown"   NUMERIC  "          $CH -R 1000:1000 \"\$WORK_ROOT\""
  app  "numeric 1001:1001 chown"   NUMERIC  "          $CH -R 1001:1001 \"\$GITHUB_WORKSPACE\""
  app  "bare numeric uid chown"    NUMERIC  "          $CH -R 1234 \"\$WORK_ROOT\""
  swap "1000 literal near chown"   LITERAL  "$C" "$C; U=1000"
  swap "1001 literal near chown"   LITERAL  "$C" "$C; U=1001"
  swap "chown target not OWNER_UG" TARGET   "$C" 'chown -h "$OWNER" "$p"'
  # --- r6 owner source: /__e, outside the chowned tree; uid 0 refused ---
  S='OWNER_UG="$(stat -c '"'"'%u:%g'"'"' /__e)" || OWNER_UG=""'
  swap "OWNER_UG from id"          OWNER_SRC,ASSIGN "$S" 'OWNER_UG="$(id -u):$(id -g)"'
  swap "extra OWNER_UG literal"    ASSIGN   '          export OWNER_UG' '          OWNER_UG=1234:1234'
  swap "OLD FORM: stat of RUNNER_TEMP (ac1d2c3)" OWNER_SRC,INTREE "$S" 'OWNER_UG="$(stat -c '"'"'%u:%g'"'"' "$RUNNER_TEMP")" || OWNER_UG=""'
  swap "owner stat falls back to WORK_ROOT" OWNER_SRC,INTREE "$S" "$S"$'\n          [ -n "$OWNER_UG" ] || OWNER_UG="$(stat -c '"'"'%u:%g'"'"' "$WORK_ROOT")"'
  swap "stat of WORK_ROOT"         OWNER_SRC,INTREE "/__e)\"" '"$WORK_ROOT")"'
  swap "stat of GITHUB_WORKSPACE"  OWNER_SRC,INTREE "/__e)\"" '"$GITHUB_WORKSPACE")"'
  swap "stat of RUNNER_WORKSPACE"  OWNER_SRC,INTREE "/__e)\"" '"$RUNNER_WORKSPACE")"'
  swap "stat of HOME (/github/home)" OWNER_SRC,INTREE "/__e)\"" '"$HOME")"'
  swap "stat of WORK_ROOT/_temp"   OWNER_SRC,INTREE "/__e)\"" '"$WORK_ROOT/_temp")"'
  swap "stat of /__w"              OWNER_SRC,INTREE "/__e)\"" '/__w)"'
  swap "stat of a path outside the tree, not /__e" OWNER_SRC "/__e)\"" '/opt)"'
  swap "stat loop over _temp and WORK_ROOT" OWNER_SRC,INTREE,ASSIGN "$S" 'for P in "${RUNNER_TEMP:-}" "$WORK_ROOT/_temp"; do OWNER_UG="$(stat -c '"'"'%u:%g'"'"' "$P")"; done'
  swap "second stat added"         OWNER_SRC "$S" "$S"$'\n          stat -c %u /__e >/dev/null'
  swap "uid-0 check removed"       NOUID0   '          if [ "${OWNER_UG%%:*}" = "0" ]; then' '          if false; then'
  swap "uid-0 check compares gid"  NOUID0   '          if [ "${OWNER_UG%%:*}" = "0" ]; then' '          if [ "${OWNER_UG##*:}" = "0" ]; then'
  cp "$WF"/*.yml "$tmp"/   # uid-0 check reports but does not exit: the line after the mismatch error becomes `true`
  awk '{ if (p) { sub(/exit 1/, "true"); p = 0 } if (index($0, "::error::runner user mismatch")) p = 1; print }' "$WF/$F" > "$tmp/$F"
  expect "uid-0 check does not exit" NOUID0
  swap "uid-0 error is a warning"  NOUID0   '::error::runner user mismatch' '::warning::runner user mismatch'
  app  "stat of RUNNER_TEMP in another step" INTREE "      - name: x\n        run: |\n          stat -c '%u:%g' \"\$RUNNER_TEMP\""
  app  "stat -c %u of GITHUB_WORKSPACE in another step" INTREE "      - name: x\n        run: |\n          U=\$(stat -c %u \"\$GITHUB_WORKSPACE\")"
  swap "fallback wording"          FALLBACK '          export OWNER_UG' '          echo "falling back"'
  swap "case on OWNER_UG"          FALLBACK '          export OWNER_UG' '          case "$OWNER_UG" in *) : ;; esac'
  swap "0:0 special case"          FALLBACK '          export OWNER_UG' '          [ "$OWNER_UG" = 0:0 ] && :'
  swap "one site drifts"           DRIFT    'runner owner (stat of /__e)' 'runner owner'
  # --- infra-res ruling 1: uid OR gid ---
  PRED='\( ! -user "${OWNER_UG%%:*}" -o ! -group "${OWNER_UG##*:}" \)'
  swap "find selects by uid only"  GID,BEHAVIOUR "$PRED" '! -user "${OWNER_UG%%:*}"'
  swap "find selects by gid only"  TARGET   "$PRED" '! -group "${OWNER_UG##*:}"'
  swap "find needs uid AND gid wrong" TARGET "$PRED" '\( ! -user "${OWNER_UG%%:*}" ! -group "${OWNER_UG##*:}" \)'
  # --- ruling 3: every swallow form, at the site (A) ---
  AT='|| { echo "::error::find under $WORK_ROOT failed"; rm -f "${CHOWN_FAILED:?}"; exit 1; }'
  swap "site: || true on find"     SWALLOW  "$AT" '|| true'
  swap "site: || : on find"        SWALLOW  "$AT" '|| :'
  swap "site: || /bin/true"        SWALLOW  "$AT" '|| /bin/true'
  swap "site: || echo on find"     SWALLOW  "$AT" '|| echo skipped'
  swap "site: ; true at eol"       SWALLOW  "$AT" '; true'
  swap "site: || true in sh -c"    SWALLOW  '|| printf "%s\n" "$p"' '|| true'
  swap "site: || : in sh -c"       SWALLOW  '|| printf "%s\n" "$p"' '|| :'
  swap "site: 2>/dev/null on chown" SWALLOW '"$p" ||' '"$p" 2>/dev/null ||'
  swap "site: &>/dev/null on chown" SWALLOW '"$p" ||' '"$p" &>/dev/null ||'
  swap "site: 2>/dev/null on find" SWALLOW  '+ > "$CHOWN_FAILED"' '+ > "$CHOWN_FAILED" 2>/dev/null'
  swap "site: &>/dev/null on find" SWALLOW  '+ > "$CHOWN_FAILED"' '+ > "$CHOWN_FAILED" &>/dev/null'
  swap "site: set +e"              SWALLOW  '          OWNER_UG="$(stat' $'          set +e\n          OWNER_UG="$(stat'
  swap "site: continue-on-error"   SWALLOW  'name: Pre-checkout ownership restore (EACCES self-heal)' $'name: Pre-checkout ownership restore (EACCES self-heal)\n        continue-on-error: true'
  # --- ruling 2: whole file, not only the markers ---
  swap "marker removed, site intact"  UNMARKED 'uid-agnostic (infra#2349)' 'uid-x'
  cp "$WF"/*.yml "$tmp"/
  sed -e '0,/uid-agnostic (infra#2349)/s//uid-x/' -e "0,/$CH -h \"\$OWNER_UG\" \"\$p\"/s//$CH -R \"\$OWNER_UG\" \"\$WORK_ROOT\"/" "$WF/$F" > "$tmp/$F"
  expect "reverted site with its marker removed" TARGET
  app  "unmarked chown on GITHUB_WORKSPACE" TARGET "      - name: x\n        run: |\n          $CH -R \"\$OWNER_UG\" \"\$GITHUB_WORKSPACE\""
  app  "unmarked chgrp on RUNNER_TEMP"      TARGET "      - name: x\n        run: |\n          chgrp -R runner \"\$RUNNER_TEMP\""
  app  "chown of _temp by a derived-looking var" TARGET "      - name: x\n        run: |\n          $CH -R \"\$U:\$G\" \"\$WORK_ROOT/_temp\""
  app  "chown in a new step, owner via id" ASSIGN "      - name: x\n        run: |\n          OWNER=\"\$(id -u):\$(id -g)\"\n          $CH -R \"\$OWNER\" \"\$WORK_ROOT\""
  # --- bare-metal sites (B) in sovereign-ci.yml ---
  BT='|| { echo "::error::chown -R $OWNER failed under $WORK_ROOT (is /etc/sudoers.d/runner-chown deployed?)"; exit 1; }'
  swap "bare-metal: || true"       SWALLOW  "$BT" '|| true'
  swap "bare-metal: || :"          SWALLOW  "$BT" '|| :'
  swap "bare-metal: || /bin/true"  SWALLOW  "$BT" '|| /bin/true'
  swap "bare-metal: || echo"       SWALLOW  "$BT" '|| echo skipped'
  swap "bare-metal: ; true at eol" SWALLOW  "$BT" '; true'
  swap "bare-metal: 2>/dev/null"   SWALLOW  "$CHOWN_B ||" "$CHOWN_B 2>/dev/null ||"
  swap "bare-metal: &>/dev/null"   SWALLOW  "$CHOWN_B ||" "$CHOWN_B &>/dev/null ||"
  swap "bare-metal: 2>/dev/null on find" SWALLOW '-print -quit)"' '-print -quit 2>/dev/null)"'
  swap "bare-metal: set +e"        SWALLOW  '          OWNER="$(id -un):$(id -gn)"' $'          set +e\n          OWNER="$(id -un):$(id -gn)"'
  swap "bare-metal: owner not id"  ASSIGN   '          OWNER="$(id -un):$(id -gn)"' '          OWNER="$(id -u):$(id -g)"'
  swap "bare-metal: sudo and plain, both bare" TARGET "if ! sudo -n $CHOWN_B; then" "sudo -n $CHOWN_B \"\$X\"; if false; then"
  # --- the same, in unified-gate.yml (four sites) ---
  F=unified-gate.yml
  swap "unified-gate: || true"     SWALLOW  "$BT" '|| true'
  swap "unified-gate: || :"        SWALLOW  "$BT" '|| :'
  swap "unified-gate: 2>/dev/null" SWALLOW  "$CHOWN_B ||" "$CHOWN_B 2>/dev/null ||"
  swap "unified-gate: continue-on-error" SWALLOW 'name: Pre-checkout ownership restore (EACCES self-heal)' $'name: Pre-checkout ownership restore (EACCES self-heal)\n        continue-on-error: true'
  swap "unified-gate: original swallow form" SWALLOW "$BT" '|| true # was: sudo -n chown ... 2>/dev/null || chown ... || true'
  F=sovereign-ci.yml
  # --- infra-res ruling 1: every shell context (inline run:, run: |, run: >, composite actions) ---
  app  "inline run: chown (second key)" TARGET "      - name: x\n        run: $CH -R \"\$OWNER_UG\" \"\$GITHUB_WORKSPACE\""
  app  "inline - run: chown (first key)" TARGET "      - run: $CH -R \"\$OWNER_UG\" \"\$GITHUB_WORKSPACE\""
  app  "run: > folded block chown"  TARGET "      - name: x\n        run: >\n          $CH -R \"\$OWNER_UG\" \"\$GITHUB_WORKSPACE\""
  app  "inline run: swallowed chown" TARGET,SWALLOW "      - name: x\n        run: $CH -R \"\$OWNER_UG\" \"\$GITHUB_WORKSPACE\" || true"
  comp() { # name tags yaml : a composite action under $tmp/actions/x/action.yml
    rm -rf "${tmp:?}/actions"; mkdir -p "$tmp/actions/x"; cp "$WF"/*.yml "$tmp"/; printf '%b\n' "$3" > "$tmp/actions/x/action.yml"
    out="$(WF_DIR=$tmp ACT_DIR=$tmp/actions SITE_COPY= bash "$0" 2>&1 || true)"
    for t in ${2//,/ }; do echo "$out" | grep -q "FAIL\[$t\]" || { miss "composite '$1' not caught as [$t]"; }; done
    echo "  caught [$2] $1"; rm -rf "${tmp:?}/actions"
  }
  CA='name: c\nruns:\n  using: composite\n  steps:\n'
  comp "composite: inline run: chown"      TARGET "$CA    - run: $CH -R x y\n      shell: bash"
  comp "composite: run: | block chown"     TARGET "$CA    - name: s\n      shell: bash\n      run: |\n        $CH -R x y"
  comp "composite: run: > block chown"     TARGET "$CA    - name: s\n      shell: bash\n      run: >\n        $CH -R x y"
  comp "composite: swallowed chown"        SWALLOW "$CA    - name: s\n      shell: bash\n      run: |\n        $CH -R x y || true"
  comp "composite: numeric chown"          NUMERIC "$CA    - name: s\n      shell: bash\n      run: |\n        $CH -R 1000:1000 y"
  # --- ruling 2: every spelling of the command word ---
  for sp in '/usr/bin/chown' '/bin/chown' '/usr/bin/chgrp' 'chgrp' 'sudo chown' 'sudo -n chown' 'sudo -u root chown' 'sudo -n -E /usr/bin/chown' \
            'command chown' 'command -p chown' 'env FOO=1 chown' 'env -i chown' 'exec chown' 'nice chown' 'nice -n 5 chown' 'ionice -c 3 chown' \
            'doas chown' 'doas -u root chown' 'timeout 5 chown' 'timeout -k 1 5 chown' '"chown"' "'chown'" 'bash -c "chown'; do
    app "spelling: $sp" TARGET "      - name: x\n        run: |\n          $sp -R \"\$OWNER_UG\" \"\$GITHUB_WORKSPACE\""
  done
  app  "spelling: \${CHOWN} resolved to chown" VARCMD "      - name: x\n        run: |\n          CHOWN=chown\n          \${CHOWN} -R \"\$OWNER_UG\" \"\$GITHUB_WORKSPACE\""
  app  "spelling: \$CHOWN_BIN unresolved"      VARCMD "      - name: x\n        run: |\n          \$CHOWN_BIN -R \"\$OWNER_UG\" \"\$GITHUB_WORKSPACE\""
  app  "spelling: \"\$X\" from a command substitution" VARCMD "      - name: x\n        run: |\n          X=\$(command -v chown)\n          \"\$X\" -R a:b \"\$GITHUB_WORKSPACE\""
  app  "spelling: sudo \$X unresolved"         VARCMD "      - name: x\n        run: |\n          OWNER=\$(id -un)\n          sudo -n \$X -R a:b \"\$GITHUB_WORKSPACE\""
  app  "spelling: env FOO=1 \${CHOWN} unresolved" VARCMD "      - name: x\n        run: |\n          # chown below\n          env FOO=1 \${CHOWN} -R a:b \"\$GITHUB_WORKSPACE\""
  # a variable command that resolves to a non-chown must stay green (the rule fails only the unresolvable)
  cp "$WF"/*.yml "$tmp"/; printf '%b\n' "      - name: x\n        run: |\n          LS=/bin/ls\n          \$LS -R \"\$GITHUB_WORKSPACE\" # owner listing" >> "$tmp/$F"
  out="$(WF_DIR=$tmp ACT_DIR=$tmp/actions SITE_COPY= bash "$0" 2>&1 || true)"
  echo "$out" | grep -q 'FAIL\[VARCMD\]' && miss "a variable command resolving to /bin/ls was flagged"
  echo "  kept  [VARCMD] a variable command resolving to a non-chown stays green"
  # --- infra#2349 class rules (infra-res): NORMALISE the command word, then match CLASSES ---------
  # Every mutant below passed the literal-word detector at 366ffcc (infra-PR-cull: 0 of 3 caught).
  nm() { app "$1" "$2" "      - name: x\n        run: |\n          # chown audit\n          $3"; }
  # rule 1: the word is normalised the way the shell would (backslashes, quotes, ${V:-w}, basename)
  nm "norm: ch\\own (backslash inside)"      TARGET 'ch\\own -R "$OWNER_UG" "$GITHUB_WORKSPACE"'
  nm "norm: \\chown (leading backslash)"     TARGET '\\chown -R "$OWNER_UG" "$GITHUB_WORKSPACE"'
  nm "norm: /usr/bin/\\chown"                TARGET '/usr/bin/\\chown -R "$OWNER_UG" "$GITHUB_WORKSPACE"'
  nm "norm: sudo \\chown"                    TARGET 'sudo -n \\chown -R "$OWNER_UG" "$GITHUB_WORKSPACE"'
  nm "norm: \\sudo chown"                    TARGET '\\sudo chown -R "$OWNER_UG" "$GITHUB_WORKSPACE"'
  nm "norm: 'ch'own (split quotes)"          TARGET "'ch'own -R \"\$OWNER_UG\" \"\$GITHUB_WORKSPACE\""
  nm "norm: \"ch\"\"own\" (adjacent quotes)" TARGET '"ch""own" -R "$OWNER_UG" "$GITHUB_WORKSPACE"'
  nm "norm: \${CHOWN:-chown}"                TARGET '${CHOWN:-chown} -R "$OWNER_UG" "$GITHUB_WORKSPACE"'
  nm "norm: \${CHOWN-chown}"                 TARGET '${CHOWN-chown} -R "$OWNER_UG" "$GITHUB_WORKSPACE"'
  nm "norm: \${CHOWN:=chown}"                TARGET '${CHOWN:=chown} -R "$OWNER_UG" "$GITHUB_WORKSPACE"'
  nm "norm: \${CHOWN=chown}"                 TARGET '${CHOWN=chown} -R "$OWNER_UG" "$GITHUB_WORKSPACE"'
  nm "norm: \"\${CHOWN:-chown}\" quoted"     TARGET '"${CHOWN:-chown}" -R "$OWNER_UG" "$GITHUB_WORKSPACE"'
  nm "norm: \${CHOWN:-\\chown} nested"       TARGET '${CHOWN:-\\chown} -R "$OWNER_UG" "$GITHUB_WORKSPACE"'
  nm "norm: \${C:-\${D:-chgrp}} nested default" TARGET '${C:-${D:-chgrp}} runner "$GITHUB_WORKSPACE"'
  nm "norm: xargs chown"                     TARGET 'ls | xargs -n1 chown "$OWNER_UG"'
  nm "norm: unresolvable \${CHOWN:-\$X}"     VARCMD '${CHOWN:-$X} -R "$OWNER_UG" "$GITHUB_WORKSPACE"'
  nm "norm: \$(tool) command word"       VARCMD '$(find_tool) -R a:b "$GITHUB_WORKSPACE"'
  nm "norm: backtick command word"           VARCMD '`command -v chown` -R a:b "$GITHUB_WORKSPACE"'
  nm "norm: xargs \$X unresolved"            VARCMD 'ls | xargs -n1 $X "$OWNER_UG"'
  nm "norm: \"\$X\" after if !"              VARCMD 'if ! "$X" -R a:b "$GITHUB_WORKSPACE"; then exit 1; fi'
  # rule 2: the ownership primitives, each spelling normalised
  nm "prim: install -o 1000 -g 1000"         TARGET 'install -o 1000 -g 1000 -m 755 a b'
  nm "prim: install -o root"                 TARGET 'install -o root a b'
  nm "prim: install -g root"                 TARGET 'install -m 644 -g root a b'
  nm "prim: install -o1000 (attached)"       TARGET 'install -o1000 a b'
  nm "prim: install -Do (cluster)"           TARGET 'install -Do root a b'
  nm "prim: install --owner=root"            TARGET 'install --owner=root a b'
  nm "prim: install --group root"            TARGET 'install --group root a b'
  nm "prim: \\install -o"                    TARGET '\\install -o 1000 a b'
  nm "prim: /usr/bin/install -g"             TARGET '/usr/bin/install -g 1000 a b'
  nm "prim: \${INSTALL:-install} -o"         TARGET '${INSTALL:-install} -o 1000 a b'
  nm "prim: sudo install -o"                 TARGET 'sudo -n install -o 1000 a b'
  nm "prim: xargs install -g"                TARGET 'ls | xargs -I{} install -g 1000 {} /d'
  nm "prim: find -exec install -o"           TARGET 'find . -type f -exec install -o 1000 {} /d \\;'
  nm "prim: sh -c literal install -o"        TARGET "sh -c 'install -o 1000 a b'"
  nm "prim: env X=1 install -o"              TARGET 'env X=1 install -o 1000 a b'
  nm "prim: cp --chown"                      TARGET 'cp --chown=1000:1000 a b'
  nm "prim: cp -a --chown"                   TARGET 'cp -a --chown 1000 a b'
  nm "prim: rsync --chown"                   TARGET 'rsync -a --chown=1000:1000 a/ b/'
  nm "prim: rsync --owner --group"           TARGET 'rsync -a --owner --group a/ b/'
  nm "prim: tar --same-owner"                TARGET 'tar -xf a.tar --same-owner'
  nm "prim: tar --owner=0"                   TARGET 'tar -cf a.tar --owner=0 --group=0 d'
  nm "prim: \\tar --same-owner"              TARGET '\\tar xf a.tar --same-owner'
  nm "prim: setfacl"                         TARGET 'setfacl -R -m u:1000:rwx "$GITHUB_WORKSPACE"'
  nm "prim: sudo \\setfacl"                  TARGET 'sudo \\setfacl -b "$GITHUB_WORKSPACE"'
  nm "prim: \${SETFACL:-setfacl}"            TARGET '${SETFACL:-setfacl} -b "$GITHUB_WORKSPACE"'
  nm "prim: var resolved to install"         VARCMD 'I=install\n          $I -o 1000 a b'
  nm "prim: var resolved to setfacl"         VARCMD 'S=/usr/bin/setfacl\n          $S -b x'
  # rule 3: eval / sh -c / source with a non-literal argument, in a step that deals with ownership
  nm "opaque: eval \"\$CMD\""                OPAQUE 'eval "$CMD"'
  nm "opaque: eval \$CMD"                    OPAQUE 'eval $CMD'
  nm "opaque: eval-built command word"       OPAQUE 'X=ls; eval "$X -R a b"'
  nm "opaque: eval \$(build)"                OPAQUE 'eval $(build_cmd)'
  nm "opaque: eval \"\$(printf ...)\""       OPAQUE 'eval "$(printf "%s" x)"'
  nm "opaque: \\eval \"\$CMD\""              OPAQUE '\\eval "$CMD"'
  nm "opaque: sh -c \"\$CMD\""               OPAQUE 'sh -c "$CMD"'
  nm "opaque: bash -c \"\$CMD\""             OPAQUE 'bash -c "$CMD"'
  nm "opaque: bash -lc \"\$CMD\""            OPAQUE 'bash -lc "$CMD"'
  nm "opaque: sudo -n bash -c \"\$CMD\""     OPAQUE 'sudo -n bash -c "$CMD"'
  nm "opaque: sh -c \"\$(build)\""           OPAQUE 'sh -c "$(build_cmd)"'
  nm "opaque: source \"\$F\""                OPAQUE 'source "$F"'
  nm "opaque: dot-source \"\$F\""            OPAQUE '. "$F"'
  nm "opaque: \${SH:-sh} -c \"\$CMD\""       OPAQUE '${SH:-sh} -c "$CMD"'
  nm "opaque: find -exec sh -c \"\$CMD\""    OPAQUE 'find . -exec sh -c "$CMD" sh {} +'
  # the step deals with ownership by OWNER_UG alone (no chown word anywhere in it)
  app "opaque: mention by OWNER_UG alone"    OPAQUE "      - name: x\n        run: |\n          U=\"\$OWNER_UG\"\n          eval \"\$CMD\""
  # rule 5: controls. A resolved non-ownership command of the same shape stays GREEN (no FAIL at all).
  keep() { # name line : append a step that mentions chown, demand a clean run
    cp "$WF"/*.yml "$tmp"/; printf '%b\n' "      - name: x\n        run: |\n          # chown audit (comment only)\n          $2" >> "$tmp/$F"
    out="$(WF_DIR=$tmp ACT_DIR=$tmp/actions SITE_COPY= bash "$0" 2>&1 || true)"
    if echo "$out" | grep -q 'FAIL\['; then miss "control '$1' went red: $(echo "$out" | grep -m1 'FAIL\[')"; else echo "  kept  [green] $1"; fi
  }
  keep "ctl: \\ls -R"                        '\\ls -R "$GITHUB_WORKSPACE"'
  keep "ctl: \"ls\" quoted"                  '"ls" -R "$GITHUB_WORKSPACE"'
  keep "ctl: \${LS:-ls}"                     '${LS:-ls} -R "$GITHUB_WORKSPACE"'
  keep "ctl: \${LS:=/bin/ls}"                '${LS:=/bin/ls} -R "$GITHUB_WORKSPACE"'
  keep "ctl: ch\\mod"                        'ch\\mod -R a+r "$GITHUB_WORKSPACE"'
  keep "ctl: sudo \\chmod"                   'sudo -n \\chmod -R a+r "$GITHUB_WORKSPACE"'
  keep "ctl: xargs ls"                       'ls | xargs -n1 ls -d'
  keep "ctl: install -m 755 (no owner)"      'install -m 755 a b'
  keep "ctl: install -Dm755"                 'install -Dm755 a b'
  keep "ctl: cp -a"                          'cp -a a b'
  keep "ctl: rsync -a"                       'rsync -a a/ b/'
  keep "ctl: tar -czf"                       'tar -czf a.tgz d'
  keep "ctl: find -exec ls"                  'find . -type f -exec ls -l {} +'
  keep "ctl: sh -c 'ls' literal"             "sh -c 'ls -l'"
  keep "ctl: eval 'ls' literal"              "eval 'ls -l'"
  keep "ctl: source ./file literal"          'source ./env.sh'
  keep "ctl: var resolved to ls"             'LS=/bin/ls\n          $LS -R "$GITHUB_WORKSPACE"'
  keep "ctl: install -o from OWNER_UG"       'install -o "${OWNER_UG%%:*}" a b'
  # eval in a step that does not deal with ownership is not an ownership question
  cp "$WF"/*.yml "$tmp"/; printf '%b\n' '      - name: agent\n        run: |\n          eval "$(ssh-agent -s)"\n          sh -c "$BUILD"' >> "$tmp/$F"
  out="$(WF_DIR=$tmp ACT_DIR=$tmp/actions SITE_COPY= bash "$0" 2>&1 || true)"
  if echo "$out" | grep -q 'FAIL\['; then miss "control 'eval in a step with no ownership text' went red"; else echo "  kept  [green] eval in a step with no ownership text"; fi
  # --- no site / nothing scanned ---
  cp "$WF"/*.yml "$tmp"/; sed -i 's/uid-agnostic (infra#2349)/uid-x/' "$tmp/$F"
  out="$(WF_DIR=$tmp SITE_COPY= bash "$0" 2>&1 || true)"
  echo "$out" | grep -q 'FAIL\[NOSITE\]' || { echo "SELF-TEST FAIL: no-site not caught"; exit 1; }
  echo "  caught [NOSITE] no site at all"
  mkdir "$tmp/empty"
  out="$(WF_DIR=$tmp/empty SITE_COPY= bash "$0" 2>&1 || true)"
  echo "$out" | grep -q 'FAIL\[NOSCAN\] scanned 0 file' || { echo "SELF-TEST FAIL: empty WF_DIR not caught as NOSCAN with a count"; exit 1; }
  echo "  caught [NOSCAN] empty workflow dir, with its file count"
  [ "$MISSES" -eq 0 ] || { echo "self-test FAILED: $MISSES mutation(s) not caught"; exit 1; }
  echo "self-test ok: every mutation caught (red)"; exit 0
fi
run_all
