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
STAT_LINE='            OWNER_UG="$(stat -c '"'"'%u:%g'"'"' "$RUNNER_TEMP")" || OWNER_UG=""'
LOOP_LINE='          if [ -n "${RUNNER_TEMP:-}" ]; then'
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
      # ASSIGN: only OWNER_UG="" and the stat line, plus the stat loop over exactly the runner paths
      bad="$(grep -nE '(^|[[:space:];])OWNER_UG=' "$s" | grep -vE ':[[:space:]]+OWNER_UG=""$' | grep -vF "$STAT_LINE" | grep -vE 'export OWNER_UG' || true)"
      [ -n "$bad" ] && { echo "FAIL[ASSIGN] $f: OWNER_UG not from stat of runner paths: $bad"; fails=1; }
      grep -qxF "$STAT_LINE" "$s" && grep -qxF "$LOOP_LINE" "$s" || { echo "FAIL[ASSIGN] $f: the \$RUNNER_TEMP-only stat is missing or altered"; fails=1; }
      # the owner source is the stat of $RUNNER_TEMP and nothing else: exactly one stat, no _temp/WORK_ROOT source
      [ "$(grep -vE '^[[:space:]]*#' "$s" | grep -cE '\$\(stat[[:space:]]+-')" -eq 1 ] || { echo "FAIL[ASSIGN] $f: the site must have exactly one stat (of \$RUNNER_TEMP)"; fails=1; }
      grep -vE '^[[:space:]]*#' "$s" | grep -qE 'WORK_ROOT/_temp|stat[^|]*WORK_ROOT|for P in' && { echo "FAIL[ASSIGN] $f: owner read from a path other than \$RUNNER_TEMP"; fails=1; }
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
  { echo 'set -u'; echo 'WORK_ROOT="$W"'; sed -e 's/^          //' "$SITE_FILE"; } > "$site"
  case "$mode" in
    unreadable) rmdir "$d/w/_temp" "$d/w/ws"; export RUNNER_TEMP="$d/none"; W="$d/none2" ;;
    chownfail) printf '#!/bin/sh\nexit 1\n' > "$d/bin/chown"; chmod +x "$d/bin/chown"; chown_target="$d/w/ws/x"; : > "$chown_target"
      export RUNNER_TEMP="$d/w/_temp"; W="$d/w" ;;
    gidonly) printf '#!/bin/sh\nprintf "%%s\\n" "$*" >> "$LOG"\nexit 0\n' > "$d/bin/chown"; chmod +x "$d/bin/chown"; : > "$d/w/ws/x"
      printf '#!/bin/sh\necho "$(id -u):4242"\n' > "$d/bin/stat"; chmod +x "$d/bin/stat"
      export RUNNER_TEMP="$d/w/_temp" LOG="$d/log"; W="$d/w" ;;
    unsetrt) unset RUNNER_TEMP; W="$d/w" ;;   # _temp and WORK_ROOT are readable: must still fail
    wrongroot) printf '#!/bin/sh\nprintf "%%s\n" "$*" >> "$LOG"\nexit 0\n' > "$d/bin/chown"; chmod +x "$d/bin/chown"; : > "$d/w/ws/x"
      printf '#!/bin/sh\ncase "$*" in *_temp) echo 4242:4343 ;; *) echo 9999:9999 ;; esac\n' > "$d/bin/stat"; chmod +x "$d/bin/stat"
      export RUNNER_TEMP="$d/w/_temp" LOG="$d/log"; W="$d/w" ;;   # WORK_ROOT wrong-owned, RUNNER_TEMP right
    *) export RUNNER_TEMP="$d/w/_temp"; W="$d/w" ;;
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
  o="$(run_site ok)" && echo "$o" | grep -q 'runner owner' && echo "ok   site runs, owner read from temp dir" || { echo "FAIL[BEHAVIOUR] ok-case: $o"; rc=1; }
  o="$(run_site unreadable)"; r=$?
  if [ "$r" -ne 0 ] && echo "$o" | grep -q '::error::cannot read the runner owner'; then echo "ok   unreadable owner -> ::error:: + nonzero"; else echo "FAIL[BEHAVIOUR] unreadable owner did not fail visibly: $o"; rc=1; fi
  o="$(run_site unsetrt)"; r=$?
  if [ "$r" -ne 0 ] && echo "$o" | grep -q '::error::cannot read the runner owner'; then echo "ok   RUNNER_TEMP unset (WORK_ROOT/_temp readable) -> ::error:: + nonzero"; else echo "FAIL[BEHAVIOUR] RUNNER_TEMP unset did not fail: $o"; rc=1; fi
  o="$(run_site wrongroot)"; r=$?
  if [ "$r" -eq 0 ] && echo "$o" | grep -q "CHOWN-CALLED -h 4242:4343 " && ! echo "$o" | grep -q 9999; then echo "ok   WORK_ROOT wrong-owned, RUNNER_TEMP right -> repaired to the RUNNER_TEMP owner"; else echo "FAIL[BEHAVIOUR] repair did not use the RUNNER_TEMP owner: $o"; rc=1; fi
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
  swap "OWNER_UG from id"          ASSIGN   '          OWNER_UG=""' '          OWNER_UG="$(id -u):$(id -g)"'
  swap "extra OWNER_UG literal"    ASSIGN   '          export OWNER_UG' '          OWNER_UG=1234:1234'
  swap "owner stat falls back to WORK_ROOT" ASSIGN ' || OWNER_UG=""' ' || OWNER_UG="$(stat -c '"'"'%u:%g'"'"' "$WORK_ROOT")"'
  swap "owner stat of WORK_ROOT, not RUNNER_TEMP" ASSIGN '"$RUNNER_TEMP")" ||' '"$WORK_ROOT")" ||'
  swap "RUNNER_TEMP guard dropped"  ASSIGN 'if [ -n "${RUNNER_TEMP:-}" ]; then' 'if true; then'
  swap "stat loop over _temp and WORK_ROOT" ASSIGN 'if [ -n "${RUNNER_TEMP:-}" ]; then' 'for P in "${RUNNER_TEMP:-}" "$WORK_ROOT/_temp" "$WORK_ROOT"; do'
  swap "fallback wording"          FALLBACK '          export OWNER_UG' '          echo "falling back"'
  swap "case on OWNER_UG"          FALLBACK '          export OWNER_UG' '          case "$OWNER_UG" in *) : ;; esac'
  swap "0:0 special case"          FALLBACK '          export OWNER_UG' '          [ "$OWNER_UG" = 0:0 ] && :'
  swap "one site drifts"           DRIFT    'runner owner (stat of $RUNNER_TEMP)' 'runner owner'
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
  swap "site: set +e"              SWALLOW  '          OWNER_UG=""' $'          set +e\n          OWNER_UG=""'
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
