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
#   [OWNER_SRC] the owner is not read by the stat of GITHUB_ENV plus the confirming stat of GITHUB_OUTPUT (listener-created, this step)
#   [AGREE]    no ::error:: + exit 1 when the two disagree or are unreadable, before the uid-0 check
#   [INTREE]   a stat of any path inside the chowned tree (RUNNER_TEMP, WORK_ROOT, workspace, HOME, _temp)
#   [NOUID0]   no uid-0 check (error + exit 1, before the find) on the owner
#   [FALLBACK] a fallback branch (fallback wording, a case on OWNER_UG, a 0:0 special case)
#   [DRIFT]    sites not byte-identical, or an unterminated site
#   [NOSITE]   no site found; [NOSCAN] no workflow file or no chown command scanned
# It prints how many files and chown commands it scanned. It also runs the first site for real:
# owner read from the listener files, a disagreeing or unreadable owner exits 1 with ::error::, a failing chown exits 1 with a count, and a
# file with the right uid and the wrong gid gets chowned.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 2
WF=${WF_DIR:-.github/workflows}
MARK='uid-agnostic (infra#2349)'
# The owner source (r7): the step runs as uid 0 inside the job container, so the owner is the stat of the
# listener-created file-command file GITHUB_ENV, which must agree with GITHUB_OUTPUT; uid 0 is refused.
# (r6 read /__e, the HOST externals dir: 1000:1000 on gx10 where the listener is uid 1001.)
STAT_LINE='          OWNER_UG="$(stat -c '"'"'%u:%g'"'"' "${GITHUB_ENV:-}")" || OWNER_UG=""'
STAT_LINE2='          OWNER_CHK="$(stat -c '"'"'%u:%g'"'"' "${GITHUB_OUTPUT:-}")" || OWNER_CHK=""'
AGREE_LINE='          if [ -z "$OWNER_UG" ] || [ "$OWNER_UG" != "$OWNER_CHK" ]; then'
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
      [ -n "$bad" ] && { echo "FAIL[ASSIGN] $f: OWNER_UG assigned other than by the stat of GITHUB_ENV: $bad"; fails=1; }
      # OWNER_SRC: the owner source is the stat of GITHUB_ENV, cross-checked by the stat of GITHUB_OUTPUT; these are the ONLY two stats
      grep -qxF "$STAT_LINE" "$s" && grep -qxF "$STAT_LINE2" "$s" || { echo "FAIL[OWNER_SRC] $f: the owner is not read by the stat of GITHUB_ENV and GITHUB_OUTPUT"; fails=1; }
      [ "$(grep -vE '^[[:space:]]*#' "$s" | grep -vE '^[[:space:]]*(echo|printf)[[:space:]]' | grep -cE '(^|[^A-Za-z_-])stat[[:space:]]')" -eq 2 ] || { echo "FAIL[OWNER_SRC] $f: the site must have exactly two stats (GITHUB_ENV, GITHUB_OUTPUT)"; fails=1; }
      # AGREE: the two file-command owners must agree, with ::error:: + exit 1, before the uid-0 check and the find
      ag="$(grep -nxF "$AGREE_LINE" "$s" | head -n 1 | cut -d: -f1)"; u0a="$(grep -nxF "$UID0_LINE" "$s" | head -n 1 | cut -d: -f1)"
      if [ -z "$ag" ] || [ -z "$u0a" ] || [ "$ag" -ge "$u0a" ] \
         || ! sed -n "$((ag + 1))p" "$s" | grep -qF '::error::cannot establish the runner owner' || [ "$(sed -n "$((ag + 2))p" "$s" | tr -d ' ')" != "exit1" ]; then
        echo "FAIL[AGREE] $f: no two-file owner agreement (::error:: + exit 1) before the uid-0 check"; fails=1; fi
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

# Behavioural run of the first site against stubs. The stat stub answers by PATH, as the real files
# would: set_env / set_output are the listener-created file-command files (S_ENV / S_OUT = "uid:gid",
# empty = unreadable), the /__e stand-in is the HOST externals dir (S_E, 1000:1000 as on gx10), any
# other path (RUNNER_TEMP, WORK_ROOT, workspace) is wrong-owned 9999:9999.
# mode = ok | gx10 | disagree | uid0 | unsetenv | unreadable | chownfail | gidonly | wrongtemp
run_site() {
  local mode="$1" d site rc out
  d="$(mktemp -d)"; mkdir -p "$d/w/_temp" "$d/w/ws" "$d/bin" "$d/e" "$d/fc"
  : > "$d/fc/set_env"; : > "$d/fc/set_output"; : > "$d/w/ws/x"
  site="$d/site.sh"
  { echo 'set -u'; echo 'WORK_ROOT="$W"'; sed -e 's/^          //' -e "s#/__e#$d/e#g" "$SITE_FILE"; } > "$site"
  printf '#!/bin/sh\nprintf "%%s\\n" "$*" >> "$LOG"\nexit 0\n' > "$d/bin/chown"
  cat > "$d/bin/stat" <<'STUB'
#!/bin/sh
case "$3" in
  *set_env) [ -n "$S_ENV" ] && echo "$S_ENV" || exit 1 ;;
  *set_output) [ -n "$S_OUT" ] && echo "$S_OUT" || exit 1 ;;
  */e) echo "$S_E" ;;
  "") exit 1 ;;
  *) echo 9999:9999 ;;
esac
STUB
  chmod +x "$d/bin/chown" "$d/bin/stat"
  export LOG="$d/log" RUNNER_TEMP="$d/w/_temp" W="$d/w" GITHUB_ENV="$d/fc/set_env" GITHUB_OUTPUT="$d/fc/set_output"
  export S_ENV=4242:4343 S_OUT=4242:4343 S_E=1000:1000
  case "$mode" in
    gx10) S_ENV=1001:1001 S_OUT=1001:1001; export S_ENV S_OUT ;;                  # listener 1001, /__e 1000
    disagree) S_ENV=1001:1001 S_OUT=1000:1000; export S_ENV S_OUT ;;
    uid0) S_ENV=0:0 S_OUT=0:0; export S_ENV S_OUT ;;
    unsetenv) unset GITHUB_ENV ;;
    unreadable) S_ENV= S_OUT=; export S_ENV S_OUT ;;
    chownfail) printf '#!/bin/sh\nexit 1\n' > "$d/bin/chown"; S_ENV=4242:4242 S_OUT=4242:4242; export S_ENV S_OUT ;;
    gidonly) S_ENV="$(id -u):4242" S_OUT="$(id -u):4242"; export S_ENV S_OUT ;;
    wrongtemp) unset RUNNER_TEMP ;;   # RUNNER_TEMP unset and every tree path wrong-owned: the owner never depended on them
  esac
  out="$(PATH="$d/bin:$PATH" bash "$site" 2>&1)"; rc=$?
  [ -s "$d/log" ] && out="$out"$'\n'"CHOWN-CALLED $(tr '\n' ' ' < "$d/log")"
  rm -rf "${d:?}"
  printf '%s\n' "$out" | tail -n 3
  return "$rc"
}

behaviour() {
  [ -s "${SITE_FILE:-}" ] || { echo "FAIL[NOSITE] no site to execute"; return 1; }
  local rc=0 o r
  o="$(run_site ok)"; r=$?
  if [ "$r" -eq 0 ] && echo "$o" | grep -qE 'runner owner \(stat of GITHUB_ENV.*\): 4242:4343' && echo "$o" | grep -q "CHOWN-CALLED -h 4242:4343 "; then echo "ok   site runs, owner read from the listener files"; else echo "FAIL[BEHAVIOUR] ok-case: $o"; rc=1; fi
  o="$(run_site gx10)"; r=$?
  if [ "$r" -eq 0 ] && echo "$o" | grep -q "CHOWN-CALLED -h 1001:1001 " && ! echo "$o" | grep -q "1000:1000"; then echo "ok   gx10: listener files 1001, /__e 1000 -> chowned to 1001"; else echo "FAIL[BEHAVIOUR] gx10 case did not pick the listener uid 1001: $o"; rc=1; fi
  o="$(run_site disagree)"; r=$?
  if [ "$r" -ne 0 ] && echo "$o" | grep -q '::error::cannot establish the runner owner' && ! echo "$o" | grep -q 'CHOWN-CALLED'; then echo "ok   GITHUB_ENV and GITHUB_OUTPUT disagree -> ::error:: + nonzero, chown never called"; else echo "FAIL[BEHAVIOUR] disagreeing owners did not fail closed: $o"; rc=1; fi
  o="$(run_site uid0)"; r=$?
  if [ "$r" -ne 0 ] && echo "$o" | grep -q '::error::runner user mismatch' && ! echo "$o" | grep -q 'CHOWN-CALLED'; then echo "ok   owner uid 0 -> ::error:: runner user mismatch + nonzero, chown never called"; else echo "FAIL[BEHAVIOUR] uid 0 did not fail closed: $o"; rc=1; fi
  o="$(run_site unsetenv)"; r=$?
  if [ "$r" -ne 0 ] && echo "$o" | grep -q '::error::cannot establish the runner owner' && ! echo "$o" | grep -q 'CHOWN-CALLED'; then echo "ok   GITHUB_ENV unset -> ::error:: + nonzero, chown never called"; else echo "FAIL[BEHAVIOUR] unset GITHUB_ENV did not fail closed: $o"; rc=1; fi
  o="$(run_site unreadable)"; r=$?
  if [ "$r" -ne 0 ] && echo "$o" | grep -q '::error::cannot establish the runner owner' && ! echo "$o" | grep -q 'CHOWN-CALLED'; then echo "ok   unreadable listener files -> ::error:: + nonzero"; else echo "FAIL[BEHAVIOUR] unreadable owner did not fail visibly: $o"; rc=1; fi
  o="$(run_site wrongtemp)"; r=$?
  if [ "$r" -eq 0 ] && echo "$o" | grep -q "CHOWN-CALLED -h 4242:4343 " && ! echo "$o" | grep -q 9999; then echo "ok   RUNNER_TEMP unset, tree paths wrong-owned -> still the listener uid"; else echo "FAIL[BEHAVIOUR] a path inside the tree became the owner: $o"; rc=1; fi
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
  # --- r7 owner source: the listener's file-command files, two must agree; uid 0 refused ---
  S='OWNER_UG="$(stat -c '"'"'%u:%g'"'"' "${GITHUB_ENV:-}")" || OWNER_UG=""'
  AGREE='          if [ -z "$OWNER_UG" ] || [ "$OWNER_UG" != "$OWNER_CHK" ]; then'
  S2='OWNER_CHK="$(stat -c '"'"'%u:%g'"'"' "${GITHUB_OUTPUT:-}")" || OWNER_CHK=""'
  swap "OWNER_UG from id"          OWNER_SRC,ASSIGN "$S" 'OWNER_UG="$(id -u):$(id -g)"'
  swap "extra OWNER_UG literal"    ASSIGN   '          export OWNER_UG' '          OWNER_UG=1234:1234'
  swap "OLD FORM (r6): stat of /__e (gx10: 1000, listener 1001)" OWNER_SRC "$S" 'OWNER_UG="$(stat -c '"'"'%u:%g'"'"' /__e)" || OWNER_UG=""'
  swap "OLD FORM: stat of RUNNER_TEMP (ac1d2c3)" OWNER_SRC,INTREE "$S" 'OWNER_UG="$(stat -c '"'"'%u:%g'"'"' "$RUNNER_TEMP")" || OWNER_UG=""'
  swap "owner stat falls back to WORK_ROOT" OWNER_SRC,INTREE "$S" "$S"$'\n          [ -n "$OWNER_UG" ] || OWNER_UG="$(stat -c '"'"'%u:%g'"'"' "$WORK_ROOT")"'
  swap "stat of WORK_ROOT"         OWNER_SRC,INTREE '"${GITHUB_ENV:-}")"' '"$WORK_ROOT")"'
  swap "stat of GITHUB_WORKSPACE"  OWNER_SRC,INTREE '"${GITHUB_ENV:-}")"' '"$GITHUB_WORKSPACE")"'
  swap "stat of RUNNER_WORKSPACE"  OWNER_SRC,INTREE '"${GITHUB_ENV:-}")"' '"$RUNNER_WORKSPACE")"'
  swap "stat of HOME (/github/home)" OWNER_SRC,INTREE '"${GITHUB_ENV:-}")"' '"$HOME")"'
  swap "stat of WORK_ROOT/_temp"   OWNER_SRC,INTREE '"${GITHUB_ENV:-}")"' '"$WORK_ROOT/_temp")"'
  swap "stat of /__w"              OWNER_SRC,INTREE '"${GITHUB_ENV:-}")"' '/__w)"'
  swap "stat of a path outside the tree, not the listener files" OWNER_SRC '"${GITHUB_ENV:-}")"' '/opt)"'
  swap "stat loop over _temp and WORK_ROOT" OWNER_SRC,INTREE,ASSIGN "$S" 'for P in "${RUNNER_TEMP:-}" "$WORK_ROOT/_temp"; do OWNER_UG="$(stat -c '"'"'%u:%g'"'"' "$P")"; done'
  swap "third stat added"          OWNER_SRC "$S2" "$S2"$'\n          stat -c %u /__e >/dev/null'
  swap "confirming stat removed"   OWNER_SRC "$S2" 'OWNER_CHK="$OWNER_UG"'
  swap "agreement check removed"   AGREE    "$AGREE" '          if [ -z "$OWNER_UG" ]; then'
  swap "agreement is a warning"    AGREE    '::error::cannot establish the runner owner' '::warning::cannot establish the runner owner'
  cp "$WF"/*.yml "$tmp"/   # agreement check reports but does not exit
  awk '{ if (p) { sub(/exit 1/, "true"); p = 0 } if (index($0, "::error::cannot establish the runner owner")) p = 1; print }' "$WF/$F" > "$tmp/$F"
  expect "agreement check does not exit" AGREE
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
  swap "one site drifts"           DRIFT    'runner owner (stat of GITHUB_ENV' 'runner owner (stat of GITHUB_ENX'
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
  # finding 1: ANY command word that holds an expansion is a variable command word, not only a lone $VAR
  nm "concat: \"\$X\$Y\" (X=ch Y=own)"      OPAQUE 'X=ch; Y=own; "$X$Y" -R "$OWNER_UG" "$WORK_ROOT"'
  nm "concat: \$X\$Y unquoted"               OPAQUE 'X=ch; Y=own; $X$Y -R "$OWNER_UG" "$WORK_ROOT"'
  nm "concat: \${X}\${Y} braces"             OPAQUE 'X=ch; Y=own; "${X}${Y}" -R "$OWNER_UG" "$WORK_ROOT"'
  nm "concat: ch\$Y prefix literal"          OPAQUE 'Y=own; ch$Y -R "$OWNER_UG" "$WORK_ROOT"'
  nm "concat: \$Xown suffix literal"         OPAQUE 'X=ch; "$X"own -R "$OWNER_UG" "$WORK_ROOT"'
  nm "concat: sudo -n \"\$X\$Y\""            OPAQUE 'X=ch; Y=own; sudo -n "$X$Y" -R "$OWNER_UG" "$WORK_ROOT"'
  nm "concat: env A=1 \"\$X\$Y\""            OPAQUE 'X=ch; Y=own; env A=1 "$X$Y" -R "$OWNER_UG" "$WORK_ROOT"'
  nm "concat: leading assignment A=1 \"\$X\$Y\"" OPAQUE 'X=ch; Y=own; A=1 "$X$Y" -R "$OWNER_UG" "$WORK_ROOT"'
  nm "concat: \$DIR/\$TOOL path command"     OPAQUE 'D=/usr/bin; T=ch; U=own; "$D/$T$U" -R "$OWNER_UG" "$WORK_ROOT"'
  nm "concat: after && in an if"             OPAQUE 'X=ch; Y=own; if true && "$X$Y" -R "$OWNER_UG" "$WORK_ROOT"; then :; fi'
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
  # --- finding 2: every fail-closed exit in each self-heal site (and the unified-gate sites) ---------
  # For every `exit 1` that sits in a step with a chown / OWNER_UG, in sovereign-ci.yml and unified-gate.yml,
  # one mutant per replacement: true, :, nothing, exit 0. The guard (the scan, [EXIT]) must go red on each.
  # Mutants are checked per site against the scan alone, so the run stays fast.
  exitmut=0
  for F in sovereign-ci.yml unified-gate.yml; do
    lines="$(awk 'function flush(  i){ if(has) for(i=1;i<=ne;i++) print E[i]; ne=0; has=0 }
      /^[ \t]*- (name|uses|run|id|if):/{ flush() } /^  [A-Za-z0-9_.-]+:[ \t]*$/{ flush() }
      !/^[ \t]*#/ && (/chown/ || /OWNER_UG/) { has=1 } /exit 1/ { ne++; E[ne]=NR } END{ flush() }' "$WF/$F")"
    [ -n "$lines" ] || miss "no fail-closed exit found to mutate in $F"
    for N in $lines; do
      for R in 'true' ':' '' 'exit 0'; do
        sed "${N}s/exit 1/$R/" "$WF/$F" > "$tmp/m.yml"
        cmp -s "$WF/$F" "$tmp/m.yml" && { miss "exit mutant $F:$N '$R' changed nothing"; continue; }
        exitmut=$((exitmut + 1))
        awk -v F="$F" -f "$SCAN_AWK" "$tmp/m.yml" | grep -q 'FAIL\[EXIT\]' || miss "exit mutant $F:$N 'exit 1' -> '$R' not caught as [EXIT]: $(sed -n "${N}p" "$WF/$F" | cut -c1-100)"
      done
    done
    awk -v F="$F" -f "$SCAN_AWK" "$WF/$F" | grep -q 'FAIL\[EXIT\]' && miss "[EXIT] fired on the unmutated $F"
  done
  [ "$exitmut" -gt 0 ] && echo "  caught [EXIT] $exitmut fail-closed-exit mutants (true / : / nothing / exit 0) over sovereign-ci.yml and unified-gate.yml"
  F=sovereign-ci.yml
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
