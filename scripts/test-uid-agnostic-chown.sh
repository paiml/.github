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
#   [EXIT]     an ::error:: branch that is not EXACTLY the error echo, `exit 1` alone, then the branch close (or `|| { echo "::error::..."; [rm -f ...;] exit 1; }`), or a trap in a step with a chown
#   [DRIFT]    sites not byte-identical, or an unterminated site
#   [WORKROOT] a step that runs find/chown/chgrp/stat/... on $WORK_ROOT with no earlier symlink / not-a-directory guard
#              (`if [ -L "$WORK_ROOT" ] || [ ! -d "$WORK_ROOT" ]; then`, ::error:: + exit 1) in the same step. find does not
#              descend into a symlinked root, so it counts 0 wrong-owned paths and reports "restored".
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
STAT_LINE='          OWNER_UG="$(stat -L -c '"'"'%u:%g'"'"' "${GITHUB_ENV:-}")" || OWNER_UG=""'
STAT_LINE2='          OWNER_CHK="$(stat -L -c '"'"'%u:%g'"'"' "${GITHUB_OUTPUT:-}")" || OWNER_CHK=""'
REG_LINE='          if [ ! -f "${GITHUB_ENV:-}" ] || [ ! -f "${GITHUB_OUTPUT:-}" ]; then'
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
  # WORKROOT: per step, every command that touches $WORK_ROOT needs the guard (+ ::error:: + exit 1) earlier in that step.
  local nwr=0
  for f in $(list_files); do
    out="$(WR_GUARD='          if [ -L "$WORK_ROOT" ] || [ ! -d "$WORK_ROOT" ]; then' awk -v F="$f" '
      function step() { g = 0; pend = 0 }
      BEGIN { G = ENVIRON["WR_GUARD"]; step() }
      match($0, /^ *- /) && RLENGTH <= 8 { step() }
      pend == 1 { if (index($0, "::error::") && $0 ~ /^ *echo /) pend = 2; else { print "FAIL[WORKROOT] " F ":" NR ": WORK_ROOT guard without an ::error:: echo"; g = 0; pend = 0 } next }
      pend == 2 { if ($0 ~ /^ *exit 1$/) { g = 1 } else { print "FAIL[WORKROOT] " F ":" NR ": WORK_ROOT guard without exit 1"; g = 0 } pend = 0; next }
      $0 == G { pend = 1; next }
      /^[[:space:]]*#/ || /^[[:space:]]*(echo|printf)[[:space:]]/ { next }
      /(^|[^A-Za-z_-])(find|chown|chgrp|chmod|stat|rm|du|ls|cp|mv|tar|rsync|cd)[[:space:]][^#]*[$][{]?WORK_ROOT/ { n++; if (!g) print "FAIL[WORKROOT] " F ":" NR ": WORK_ROOT used without the symlink/not-a-directory guard: " $0 }
      END { print "WRN " n + 0 }' "$f")" || { echo "FAIL[NOSCAN] WORKROOT scan of $f errored"; fails=1; continue; }
    printf '%s\n' "$out" | grep '^FAIL' && fails=1
    nwr=$((nwr + $(printf '%s\n' "$out" | sed -n 's/^WRN //p' | head -n 1)))
  done
  [ "$nwr" -eq 0 ] && { echo "FAIL[NOSCAN] WORKROOT scan examined 0 command(s) on WORK_ROOT"; fails=1; }
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
      # REGFILE: both listener files must be regular files (-f follows links, so a dangling link or a directory fails), with ::error:: + exit 1, after the stats and the agreement check, before the uid-0 check
      rg="$(grep -nxF "$REG_LINE" "$s" | head -n 1 | cut -d: -f1)"; sg="$ag"
      if [ -z "$rg" ] || [ -z "$sg" ] || [ "$rg" -le "$sg" ] || [ "$rg" -ge "$u0a" ] \
         || ! sed -n "$((rg + 1))p" "$s" | grep -qF '::error::cannot establish the runner owner' || [ "$(sed -n "$((rg + 2))p" "$s" | tr -d ' ')" != "exit1" ]; then
        echo "FAIL[REGFILE] $f: no regular-file check on GITHUB_ENV and GITHUB_OUTPUT (::error:: + exit 1) after the agreement check and before the uid-0 check"; fails=1; fi
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
# mode = ok | gx10 | disagree | uid0 | unsetenv | unreadable | chownfail | gidonly | wrongtemp  | danglingout | foreignout | danglingenv | envdir | outdir
run_site() {
  local mode="$1" d site rc out
  d="$(mktemp -d)"; mkdir -p "$d/w/_temp" "$d/w/ws" "$d/bin" "$d/e" "$d/fc"
  : > "$d/fc/set_env"; : > "$d/fc/set_output"; : > "$d/w/ws/x"
  site="$d/site.sh"
  { echo 'set -u'; echo 'WORK_ROOT="$W"'; sed -e 's/^          //' -e "s#/__e#$d/e#g" "$SITE_FILE"; } > "$site"
  printf '#!/bin/sh\nprintf "%%s\\n" "$*" >> "$LOG"\nexit 0\n' > "$d/bin/chown"
  cat > "$d/bin/stat" <<'STUB'
#!/bin/sh
L=0; if [ "$1" = -L ]; then L=1; shift; fi   # then $1=-c $2=fmt $3=path, as the real stat
# -L follows the link: a dangling one fails; a link to the foreign file answers with the TARGET owner
if [ "$L" = 1 ]; then
  [ -e "$3" ] || exit 1
  if [ -L "$3" ]; then case "$(readlink "$3")" in *other) echo 7777:7777; exit 0 ;; esac; fi
fi
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
    danglingout) rm -f "${d:?}/fc/set_output"; ln -s "${d:?}/fc/nowhere" "${d:?}/fc/set_output" ;;   # symlink to nothing
    foreignout) : > "${d:?}/fc/other"; rm -f "${d:?}/fc/set_output"; ln -s "${d:?}/fc/other" "${d:?}/fc/set_output" ;;   # symlink to a file owned by 7777:7777
    danglingenv) rm -f "${d:?}/fc/set_env"; ln -s "${d:?}/fc/nowhere" "${d:?}/fc/set_env" ;;
    envdir) rm -f "${d:?}/fc/set_env"; mkdir "${d:?}/fc/set_env" ;;   # a directory where the file-command file should be
    outdir) rm -f "${d:?}/fc/set_output"; mkdir "${d:?}/fc/set_output" ;;
    # r12: wc (the failed-path counter) is untrusted output. A count that is empty or not a run of digits must fail closed.
    wcfail) printf '#!/bin/sh\nexit 1\n' > "${d:?}/bin/wc" ;;                       # wc fails and prints nothing
    wcempty) printf '#!/bin/sh\nexit 0\n' > "${d:?}/bin/wc" ;;                      # wc succeeds and prints nothing
    wcgarbage) printf '#!/bin/sh\necho oops\n' > "${d:?}/bin/wc" ;;                 # wc prints non-numeric output
    wcnegative) printf '#!/bin/sh\necho -1\n' > "${d:?}/bin/wc" ;;                  # wc prints a signed number
    wcspaces) printf '#!/bin/sh\necho "0 x"\n' > "${d:?}/bin/wc" ;;                 # a zero followed by text must not read as zero
    # r12: the owner read from the listener files must be a numeric uid:gid with a non-root uid
    ownergarbage) S_ENV=abc:def S_OUT=abc:def; export S_ENV S_OUT ;;
    ownernocolon) S_ENV=4242 S_OUT=4242; export S_ENV S_OUT ;;
    ownerzeropad) S_ENV=00:0 S_OUT=00:0; export S_ENV S_OUT ;;                      # uid 0 spelled so that `= "0"` misses it
    ownertwocolon) S_ENV=4242:4343:1 S_OUT=4242:4343:1; export S_ENV S_OUT ;;
    # GITHUB_ENV / GITHUB_OUTPUT INSIDE the tree being chowned (the listener keeps them under _work/_temp). The stat is taken
    # before the find/chown, so a wrong-owned tree cannot change what it reads; a wrong-owned file-command file cannot be used.
    intree) mkdir -p "${d:?}/w/_temp/_runner_file_commands"; : > "${d:?}/w/_temp/_runner_file_commands/set_env"; : > "${d:?}/w/_temp/_runner_file_commands/set_output"
            GITHUB_ENV="$d/w/_temp/_runner_file_commands/set_env"; GITHUB_OUTPUT="$d/w/_temp/_runner_file_commands/set_output"; export GITHUB_ENV GITHUB_OUTPUT ;;   # listener-owned 4242:4343, rest of the tree 9999:9999
    intreemixed) mkdir -p "${d:?}/w/_temp/_runner_file_commands"; : > "${d:?}/w/_temp/_runner_file_commands/set_env"; : > "${d:?}/w/_temp/_runner_file_commands/set_output"
            GITHUB_ENV="$d/w/_temp/_runner_file_commands/set_env"; GITHUB_OUTPUT="$d/w/_temp/_runner_file_commands/set_output"; S_ENV=9999:9999; export GITHUB_ENV GITHUB_OUTPUT S_ENV ;;   # in-tree GITHUB_ENV wrong-owned, GITHUB_OUTPUT the listener's
    intreeroot) mkdir -p "${d:?}/w/_temp/_runner_file_commands"; : > "${d:?}/w/_temp/_runner_file_commands/set_env"; : > "${d:?}/w/_temp/_runner_file_commands/set_output"
            GITHUB_ENV="$d/w/_temp/_runner_file_commands/set_env"; GITHUB_OUTPUT="$d/w/_temp/_runner_file_commands/set_output"; S_ENV=0:0 S_OUT=0:0; export GITHUB_ENV GITHUB_OUTPUT S_ENV S_OUT ;;   # both in-tree files root-owned (a container step ran as root)
    # WORK_ROOT itself is not a plain directory: find would not descend into a link (0 wrong-owned paths, "restored"); never follow it
    symlinkroot) mkdir "${d:?}/real"; : > "${d:?}/real/wrong-owned"; ln -s "${d:?}/real" "${d:?}/link"; W="$d/link"; export W ;;   # link to a dir holding wrong-owned files
    danglingroot) ln -s "${d:?}/nowhere" "${d:?}/link"; W="$d/link"; export W ;;
    fileroot) : > "${d:?}/rf"; W="$d/rf"; export W ;;
  esac
  [ -e "$d/bin/wc" ] && chmod +x "$d/bin/wc"
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
  for m in danglingout:"dangling GITHUB_OUTPUT symlink" foreignout:"GITHUB_OUTPUT symlink to a file of another owner" danglingenv:"dangling GITHUB_ENV symlink" envdir:"GITHUB_ENV is a directory" outdir:"GITHUB_OUTPUT is a directory"; do
    o="$(run_site "${m%%:*}")"; r=$?
    if [ "$r" -ne 0 ] && echo "$o" | grep -q '::error::cannot establish the runner owner' && ! echo "$o" | grep -q 'CHOWN-CALLED'; then echo "ok   ${m#*:} -> ::error:: + nonzero, chown never called"; else echo "FAIL[BEHAVIOUR] ${m#*:} did not fail closed: $o"; rc=1; fi
  done
  o="$(run_site intree)"; r=$?
  if [ "$r" -eq 0 ] && echo "$o" | grep -q "CHOWN-CALLED -h 4242:4343 " && ! echo "$o" | grep -q 9999; then echo "ok   GITHUB_ENV and GITHUB_OUTPUT inside the chowned tree, tree wrong-owned -> the listener uid (stat is taken before the chown)"; else echo "FAIL[BEHAVIOUR] in-tree GITHUB_ENV changed the owner: $o"; rc=1; fi
  for m in intreemixed:"in-tree GITHUB_ENV wrong-owned, GITHUB_OUTPUT the listener's" intreeroot:"in-tree GITHUB_ENV and GITHUB_OUTPUT root-owned"; do
    o="$(run_site "${m%%:*}")"; r=$?
    if [ "$r" -ne 0 ] && echo "$o" | grep -qE '::error::(cannot establish the runner owner|runner user mismatch)' && ! echo "$o" | grep -q 'CHOWN-CALLED'; then echo "ok   ${m#*:} -> ::error:: + nonzero, chown never called"; else echo "FAIL[BEHAVIOUR] ${m#*:} did not fail closed: $o"; rc=1; fi
  done
  # r12: the failed-path count is validated before it is compared. Each wc stub must make the site exit nonzero with the count ::error::.
  for m in wcfail:"wc stub that fails" wcempty:"wc stub that prints nothing" wcgarbage:"wc stub that prints non-numeric output" wcnegative:"wc stub that prints a negative number" wcspaces:"wc stub that prints a zero followed by text"; do
    o="$(run_site "${m%%:*}")"; r=$?
    if [ "$r" -ne 0 ] && echo "$o" | grep -q '::error::cannot count the failed paths'; then echo "ok   ${m#*:} -> ::error:: + nonzero"; else echo "FAIL[BEHAVIOUR] ${m#*:} did not fail closed: $o"; rc=1; fi
  done
  # r12: a listener owner that is not a numeric uid:gid with a non-root uid is refused before any find/chown.
  for m in ownergarbage:"owner stat prints non-numeric text" ownernocolon:"owner stat prints a uid with no gid" ownerzeropad:"owner stat prints uid 00 (root spelled with a pad)" ownertwocolon:"owner stat prints three fields"; do
    o="$(run_site "${m%%:*}")"; r=$?
    if [ "$r" -ne 0 ] && echo "$o" | grep -q '::error::runner owner' && ! echo "$o" | grep -q 'CHOWN-CALLED'; then echo "ok   ${m#*:} -> ::error:: + nonzero, chown never called"; else echo "FAIL[BEHAVIOUR] ${m#*:} did not fail closed: $o"; rc=1; fi
  done
  # WORK_ROOT must be a real directory: a symlink (even to a good tree), a dangling link or a regular file is ::error:: + exit 1, nothing chowned.
  for m in symlinkroot:"WORK_ROOT is a symlink to a dir holding wrong-owned files" danglingroot:"WORK_ROOT is a dangling symlink" fileroot:"WORK_ROOT is a regular file"; do
    o="$(run_site "${m%%:*}")"; r=$?
    if [ "$r" -ne 0 ] && echo "$o" | grep -q '::error::WORK_ROOT' && ! echo "$o" | grep -q 'CHOWN-CALLED' && ! echo "$o" | grep -q 'ownership restored'; then echo "ok   ${m#*:} -> ::error:: + nonzero, chown never called"; else echo "FAIL[BEHAVIOUR] ${m#*:} did not fail closed: $o"; rc=1; fi
  done
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
  S='OWNER_UG="$(stat -L -c '"'"'%u:%g'"'"' "${GITHUB_ENV:-}")" || OWNER_UG=""'
  AGREE='          if [ -z "$OWNER_UG" ] || [ "$OWNER_UG" != "$OWNER_CHK" ]; then'
  REG='          if [ ! -f "${GITHUB_ENV:-}" ] || [ ! -f "${GITHUB_OUTPUT:-}" ]; then'
  S2='OWNER_CHK="$(stat -L -c '"'"'%u:%g'"'"' "${GITHUB_OUTPUT:-}")" || OWNER_CHK=""'
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
  # --- r10 (PR #97): stat -L plus a regular-file check on BOTH listener files; a dangling link, a foreign link or a directory fails closed ---
  swap "FINDING: plain stat (no -L) of GITHUB_OUTPUT, one site" OWNER_SRC,DRIFT "$S2" 'OWNER_CHK="$(stat -c '"'"'%u:%g'"'"' "${GITHUB_OUTPUT:-}")" || OWNER_CHK=""'
  swap "plain stat (no -L) of GITHUB_ENV, one site" OWNER_SRC,DRIFT "$S" 'OWNER_UG="$(stat -c '"'"'%u:%g'"'"' "${GITHUB_ENV:-}")" || OWNER_UG=""'
  swap "regular-file check removed" REGFILE "$REG" '          if false; then'
  swap "regular-file check covers GITHUB_ENV only" REGFILE "$REG" '          if [ ! -f "${GITHUB_ENV:-}" ]; then'
  swap "regular-file check covers GITHUB_OUTPUT only" REGFILE "$REG" '          if [ ! -f "${GITHUB_OUTPUT:-}" ]; then'
  swap "-f weakened to -e (a directory passes)" REGFILE "$REG" '          if [ ! -e "${GITHUB_ENV:-}" ] || [ ! -e "${GITHUB_OUTPUT:-}" ]; then'
  # Executed mutants: each variant is applied at ALL 8 sites (so DRIFT stays quiet) and then the
  # behaviour fixtures are RUN against the mutated site; the named fixtures must go red.
  F_OUT='dangling GITHUB_OUTPUT symlink'; F_FOR='GITHUB_OUTPUT symlink to a file of another owner'
  F_ENV='dangling GITHUB_ENV symlink'; F_DIR='GITHUB_ENV is a directory'; F_ODIR='GITHUB_OUTPUT is a directory'
  FCHK='if \[ ! -f "\${GITHUB_ENV:-}" \] || \[ ! -f "\${GITHUB_OUTPUT:-}" \]; then'
  exmut() { # name sed-expr fixture... : sed over $F, guard must stay quiet on no tag we assert, each fixture must be FAIL[BEHAVIOUR]
    local n="$1" e="$2" fx out; shift 2
    cp "$WF"/*.yml "$tmp"/; sed -i "$e" "$tmp/$F"
    cmp -s "$WF/$F" "$tmp/$F" && { echo "SELF-TEST FAIL: mutation '$n' changed nothing"; exit 1; }
    out="$(WF_DIR=$tmp ACT_DIR=$tmp/actions SITE_COPY= bash "$0" 2>&1 || true)"
    for fx in "$@"; do echo "$out" | grep -qF "FAIL[BEHAVIOUR] $fx did not fail closed" || miss "'$n': fixture '$fx' stayed green"; done
    echo "  caught [BEHAVIOUR] $n: $# fixture(s) red"
  }
  exmut "FINDING at all 8 sites: plain stat of both files, no -f check" "s/stat -L -c/stat -c/; s/$FCHK/if false; then/" "$F_OUT" "$F_FOR" "$F_ENV" "$F_DIR" "$F_ODIR"
  exmut "plain stat at all 8 sites, -f check kept (dangling covered, foreign link not)" "s/stat -L -c/stat -c/" "$F_FOR"
  exmut "-f check removed at all 8 sites, stat -L kept" "s/$FCHK/if false; then/" "$F_DIR" "$F_ODIR"
  exmut "-f weakened to -e at all 8 sites" "s/! -f /! -e /g" "$F_DIR" "$F_ODIR"
  exmut "-f on GITHUB_ENV only at all 8 sites" 's/ || \[ ! -f "${GITHUB_OUTPUT:-}" \]; then/; then/' "$F_ODIR"
  # --- r12: the failed-path count and the owner shape are validated before use; executed mutants at ALL 8 sites ---
  F_WCF='wc stub that fails'; F_WCE='wc stub that prints nothing'; F_WCG='wc stub that prints non-numeric output'; F_WCS='wc stub that prints a zero followed by text'
  F_OG='owner stat prints non-numeric text'; F_ONC='owner stat prints a uid with no gid'; F_OZ='owner stat prints uid 00 (root spelled with a pad)'; F_O3='owner stat prints three fields'
  exmut "FINDING: count validation removed at all 8 sites (empty and garbage pass)" "s/^\( *\)''|\*\[!0-9\]\*)\$/\1__never__)/" "$F_WCF" "$F_WCE" "$F_WCG" "$F_WCS"
  exmut "count validation keeps only the empty case" "s/^\( *\)''|\*\[!0-9\]\*)\$/\1'')/" "$F_WCG" "$F_WCS"
  exmut "count validation keeps only the non-digit case (empty passes)" "s/^\( *\)''|\*\[!0-9\]\*)\$/\1*[!0-9]*)/" "$F_WCF" "$F_WCE"
  exmut "owner shape check removed at all 8 sites" "s/^\( *\)\*\[!0-9:\]\*|.*) ;;\$/\1*) OWNER_SHAPE_OK=1 ;;/" "$F_OG" "$F_ONC" "$F_OZ" "$F_O3"
  exmut "owner shape: leading-zero uid (00) allowed" "s/|:\*|0\*) ;;/|:*) ;;/" "$F_OZ"
  exmut "owner shape: non-digit characters allowed" "s/\*\[!0-9:\]\*|//" "$F_OG"
  exmut "owner shape: a second colon allowed" "s/|\*:\*:\*|/|/" "$F_O3"
  # --- r13: WORK_ROOT must not be a symlink or a non-directory; guard at every site, executed mutants ---
  WG='if \[ -L "\$WORK_ROOT" \] || \[ ! -d "\$WORK_ROOT" \]; then'
  F_SL='WORK_ROOT is a symlink to a dir holding wrong-owned files'; F_DL='WORK_ROOT is a dangling symlink'; F_RF='WORK_ROOT is a regular file'
  exmut "FINDING r13: WORK_ROOT guard removed at every marked site (symlinked root reports restored)" 's/'"$WG"'/if false; then/' "$F_SL" "$F_DL" "$F_RF"
  exmut "WORK_ROOT guard weakened to -d only (a link to a dir passes)" 's/if \[ -L "\$WORK_ROOT" \] || \[ ! -d/if [ ! -d/' "$F_SL"
  exmut "WORK_ROOT guard weakened to -L only (a regular file passes)" 's/ || \[ ! -d "\$WORK_ROOT" \]; then$/; then/' "$F_RF"
  exmut "WORK_ROOT guard exit removed" '/WORK_ROOT .* is a symlink or not a directory/{n;s/exit 1/true/}' "$F_SL" "$F_DL" "$F_RF"
  swap "WORK_ROOT guard removed at one marked site" WORKROOT,DRIFT 'if [ -L "$WORK_ROOT" ] || [ ! -d "$WORK_ROOT" ]; then' 'if false; then'
  swap "WORK_ROOT guard is a warning" WORKROOT 'echo "::error::WORK_ROOT' 'echo "::warning::WORK_ROOT'
  app  "new step: find on WORK_ROOT without the guard" WORKROOT "      - name: x\n        run: |\n          find \"\$WORK_ROOT\" -print"
  app  "new step: stat of WORK_ROOT without the guard" WORKROOT "      - name: x\n        run: |\n          U=\$(stat -c %u \"\$WORK_ROOT\")"
  swap "agreement check removed"   AGREE   "$AGREE" '          if [ -z "$OWNER_UG" ]; then'
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
    out="$(awk -v F="$F" -f "$SCAN_AWK" "$tmp/$F" 2>&1 || true)"   # the chown scanner alone: the OPAQUE class below is stricter by design
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
  # r4a: an OWNER_UG mention (argument or comment) exempts nothing: only the two ruled chown shapes are approved
  nm "r4a: install -o \"\${OWNER_UG%%:*}\" is not approved" TARGET 'install -o "${OWNER_UG%%:*}" a b'
  nm "r4a: tar --owner=root # OWNER_UG"                    TARGET 'tar --owner=root -xf a.tar # OWNER_UG'
  nm "r4a: cp --chown=root # OWNER_UG"                     TARGET 'cp --chown=root a b # OWNER_UG'
  nm "r4a: setfacl # OWNER_UG"                             TARGET 'setfacl -m u:root:rwx /w # OWNER_UG'
  # r4b: a message line whose output is piped is a command, not a message
  nm "r4b: printf 'chown ..' | sh (SCAN was 0)"            TARGET "printf 'chown -R root:root /w' | sh"
  nm "r4b: echo \"chown ..\" | bash"                       TARGET 'echo "chown -R root:root /w" | bash'
  nm "r4b: echo \"\$(chown ..)\" (expansion kept)"         TARGET 'echo "$(chown -R root:root /w)"'
  # eval in a step that does not deal with ownership is not an ownership question for the chown scanner,
  # the chown scanner stays quiet on it (the opaque-capability scan moved out under C324 s7).
  cp "$WF"/*.yml "$tmp"/; printf '%b\n' '      - name: agent\n        run: |\n          eval "$(ssh-agent -s)"\n          sh -c "$BUILD"' >> "$tmp/$F"
  out="$(awk -v F="$F" -f "$SCAN_AWK" "$tmp/$F" 2>&1 || true)"
  if echo "$out" | grep -q 'FAIL\['; then miss "control 'eval in a step with no ownership text' went red in the chown scanner"; else echo "  kept  [green] eval in a step with no ownership text (chown scanner)"; fi
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
  # --- r11 (finding on de1f305): the fail-closed branch is EXACT TEXT --------------------------------------
  # `echo "::error::x"; exit 0; exit 1; }` ended in `; exit 1; }` and so passed the old tail pattern, while the
  # step carried on. Class: anything between the ::error:: and the exit 1 that can end, skip or neutralise the exit
  # (exit 0, return, true, :, a trap, ||/&& chaining, a newline plus another command, `exit 1` in a comment or in
  # a string). Each mutant is applied to the real workflow, the scan must say [EXIT], and where the mutant is
  # really fail-open the mutated branch is EXECUTED and must be seen to carry on (CONTINUED, or rc 0).
  r11n=0
  r11run() { # name expect(open|any) mutated-file : run the branch the mutation touched
    local a="$WF/$F" b="$3" L s e frag res
    L="$(cmp "$a" "$b" | sed -n 's/.*line \([0-9]*\).*/\1/p')"
    if sed -n "${L}p" "$b" | grep -q '|| { echo'; then
      frag="$(sed -n "${L}p" "$b" | sed 's/^.*|| { echo/{ echo/')"; res="$(bash -c "false || $frag; echo CONTINUED" 2>/dev/null)"; rc=$?
    else
      s="$(awk -v L="$L" '/^ *if / && NR <= L { s = NR } END { print s }' "$b")"; e="$(awk -v L="$L" 'NR >= L && /^ *fi$/ { print NR; exit }' "$b")"
      frag="$(sed -n "${s},${e}p" "$b")"; res="$(bash -c "OWNER_UG=; OWNER_CHK=; $frag; echo CONTINUED" 2>/dev/null)"; rc=$?
    fi
    if [ "$rc" -eq 0 ] || echo "$res" | grep -q CONTINUED; then echo "  executed '$1': the mutated branch is FAIL-OPEN (rc=$rc, carried on)"; else miss "r11 '$1' was meant to be fail-open but the executed branch exited rc=$rc"; fi
  }
  r11chk() { # name expect mutated-file
    r11n=$((r11n + 1))
    awk -v F="$F" -f "$SCAN_AWK" "$3" | grep -q 'FAIL\[EXIT\]' || miss "r11 mutant '$1' not caught as [EXIT]"
    [ "$2" = open ] && r11run "$1" "$2" "$3"
  }
  r11inline() { # name expect old new : first OLD -> NEW
    OLD="$3" NEW="$4" awk '!d && (i = index($0, ENVIRON["OLD"])) { $0 = substr($0, 1, i-1) ENVIRON["NEW"] substr($0, i+length(ENVIRON["OLD"])); d=1 } {print}' "$WF/$F" > "$tmp/m11.yml"
    cmp -s "$WF/$F" "$tmp/m11.yml" && { miss "r11 mutant '$1' changed nothing"; return; }
    r11chk "$1" "$2" "$tmp/m11.yml"
  }
  r11next() { # name expect new-text : the line after the runner-owner agreement ::error:: becomes NEW (may hold newlines)
    REP="$3" awk '!d && p { $0 = ENVIRON["REP"]; d = 1 } { p = index($0, "unreadable or disagree\"") > 0 && !d; print }' "$WF/$F" > "$tmp/m11.yml"
    cmp -s "$WF/$F" "$tmp/m11.yml" && { miss "r11 mutant '$1' changed nothing"; return; }
    r11chk "$1" "$2" "$tmp/m11.yml"
  }
  MK='"::error::mktemp failed"; exit 1; }'
  r11inline "THE FINDING: echo ::error::; exit 0; exit 1; }" open "$MK" '"::error::mktemp failed"; exit 0; exit 1; }'
  r11inline "one-line: true; exit 1"                 any  "$MK" '"::error::mktemp failed"; true; exit 1; }'
  r11inline "one-line: : ; exit 1"                   any  "$MK" '"::error::mktemp failed"; : ; exit 1; }'
  r11inline "one-line: return 0; exit 1"             any  "$MK" '"::error::mktemp failed"; return 0; exit 1; }'
  r11inline "one-line: trap EXIT exit 0"             open "$MK" '"::error::mktemp failed"; trap '"'exit 0'"' EXIT; exit 1; }'
  r11inline "one-line: (exit 1) subshell"            open "$MK" '"::error::mktemp failed"; (exit 1); }'
  r11inline "one-line: exit 0 || exit 1"             open "$MK" '"::error::mktemp failed"; exit 0 || exit 1; }'
  r11inline "one-line: extra command, then exit 1"   any  "$MK" '"::error::mktemp failed"; touch /dev/null; exit 1; }'
  r11inline "one-line: exit 1 held in a string"      open "$MK" '"::error::mktemp failed"; echo "; exit 1; }"; }'
  r11inline "one-line: exit 1 inside the message"    open "$MK" '"::error::mktemp failed; exit 1"; }'
  r11inline "one-line: exit 1; } || true"            any  "$MK" '"::error::mktemp failed"; exit 1; } || true'
  r11inline "one-line: rm -f variant exit 0; exit 1" any  'rm -f "${CHOWN_FAILED:?}"; exit 1; }' 'rm -f "${CHOWN_FAILED:?}"; exit 0; exit 1; }'
  r11inline "one-line: rm -f swapped for other rm"   any  'rm -f "${CHOWN_FAILED:?}"; exit 1; }' 'rm -f /; exit 1; }'
  r11inline "chain: && { echo ::error:: }"           any  '"$(mktemp)" || { echo "::error::mktemp' '"$(mktemp)" && { echo "::error::mktemp'
  r11inline "chain: true || { echo ::error:: }"      any  '"$(mktemp)" || { echo "::error::mktemp' '"$(mktemp)" || true || { echo "::error::mktemp'
  r11inline "chain: : || { echo ::error:: }"         any  '"$(mktemp)" || { echo "::error::mktemp' '"$(mktemp)" ; : || { echo "::error::mktemp'
  r11inline "echo not first in the group"            any  '|| { echo "::error::mktemp failed"' '|| { true; echo "::error::mktemp failed"'
  r11inline "unclosed message quote"                 any  '"::error::mktemp failed"; exit 1; }' '"::error::mktemp failed; exit 1; }'
  r11inline "backtick in the message"                any  '"::error::mktemp failed"; exit 1; }' '"::error::mktemp `true` failed"; exit 1; }'
  r11next "multi-line: exit 0"                       open 'exit 0'
  r11next "multi-line: return 0"                     open 'return 0'
  r11next "multi-line: (exit 1) subshell"            open '(exit 1)'
  r11next "multi-line: exit 1 deleted"               open ''
  r11next "multi-line: exit 1 only in a comment"     open '# exit 1'
  r11next "multi-line: exit 1 only in a string"      open 'echo "exit 1"'
  r11next "multi-line: trap then exit 1"             open $'trap '"'exit 0'"' EXIT\n            exit 1'
  r11next "multi-line: true then exit 1"             any  $'true\n            exit 1'
  r11next "multi-line: : then exit 1"                any  $':\n            exit 1'
  r11next "multi-line: other command then exit 1"    any  $'touch /dev/null\n            exit 1'
  r11next "multi-line: exit 1 || true"               any  'exit 1 || true'
  r11next "multi-line: exit 1 # trailing"            any  'exit 1 # ok'
  r11next "multi-line: exit 1; true"                 any  'exit 1; true'
  r11next "multi-line: exit 1 then a command"        any  $'exit 1\n            true'
  r11inline "multi-line: echo ...; exit 0 on the echo line" open 'unreadable or disagree"' 'unreadable or disagree"; exit 0'
  r11inline "multi-line: echo ... && exit 0 on the echo line" open 'unreadable or disagree"' 'unreadable or disagree" && exit 0'
  # trap set earlier in the step (not between the error and the exit) rewrites every exit after it
  r11inline "trap EXIT exit 0 earlier in the step"   any  'OWNER_UG="$(stat -L -c' $'trap '"'exit 0'"' EXIT\n          OWNER_UG="$(stat -L -c'
  # controls: the unmutated file is green, and so is a harmless blank line and comment after the exit
  awk -v F="$F" -f "$SCAN_AWK" "$WF/$F" | grep -q 'FAIL\[EXIT\]' && miss "r11 control: [EXIT] fired on the unmutated $F"
  # the executed fail-open check must itself be able to fail: the unmutated one-line branch has to be seen CLOSED
  res="$(bash -c 'false || { echo "::error::mktemp failed"; exit 1; }; echo CONTINUED' 2>/dev/null)"; rc=$?
  { [ "$rc" -ne 0 ] && ! echo "$res" | grep -q CONTINUED; } || miss "r11 control: the unmutated branch is not fail-closed when executed"
  rm -f "${tmp:?}/m11.yml"
  echo "  caught [EXIT] $r11n exact-text mutants of the fail-closed branch (the finding, exit 0 / return / true / : / trap / chaining / newline / comment / string)"
  # --- r12 (finding at `if ! sudo -n chown ...; then BODY fi`): the body is exact text, checked by errshape() ---
  # Before r12 the scan accepted ANY body after `then`. Each mutant below rewrites the body of EVERY `if ! sudo -n chown`
  # in sovereign-ci.yml and unified-gate.yml; the scan must say [tag] at every one of them (6 sites), and where the mutant
  # really lets a failed sudo fall through, the mutated branch is EXECUTED (sudo and chown stubbed to fail) and must be
  # seen to carry on (CONTINUED or rc 0).
  r12n=0
  r12() { # name tag expect(open|any) mode rep
    local G cnt want got frag res rc nm="$1" tag="$2" ex="$3" mode="$4" rep="$5"
    want=0; got=0
    for G in sovereign-ci.yml unified-gate.yml; do
      MODE="$mode" REP="$rep" awk '/^ *if ! sudo -n chown/ { getline b; m = ENVIRON["MODE"]; r = ENVIRON["REP"]
          if (m == "ifrep") { print "          " r; print b } else if (m == "rep") { print; print "            " r } else if (m == "del") print
          else if (m == "after") { print; print b; print "            " r } else if (m == "before") { print; print "            " r; print b } ; next } { print }' "$WF/$G" > "$tmp/m12.yml"
      cmp -s "$WF/$G" "$tmp/m12.yml" && { miss "r12 mutant '$nm' changed nothing in $G"; continue; }
      cnt="$(grep -c '^ *if ! sudo -n chown' "$WF/$G")"; want=$((want + cnt))
      got=$((got + $(awk -v F="$G" -f "$SCAN_AWK" "$tmp/m12.yml" | grep -c "FAIL\[$tag\]")))
      if [ "$ex" = open ]; then
        frag="$(awk '/^ *if ! sudo -n chown/ { on = 1 } on { print } on && /^ *fi$/ { exit }' "$tmp/m12.yml")"
        res="$(bash -c "sudo() { return 1; }; chown() { return 1; }; OWNER=o; WORK_ROOT=/w; $frag; echo CONTINUED" 2>/dev/null)"; rc=$?
        if [ "$rc" -eq 0 ] || echo "$res" | grep -q CONTINUED; then :; else miss "r12 '$nm' was meant to be fail-open but the executed branch exited rc=$rc"; fi
      fi
    done
    r12n=$((r12n + 1))
    [ "$got" -ge "$want" ] && [ "$want" -gt 0 ] || miss "r12 mutant '$nm': [$tag] seen at $got of $want sites"
  }
  r12 "THE FINDING: body is only true"                 EXIT open rep 'true'
  r12 "body is only :"                                 EXIT open rep ':'
  r12 "body is exit 0"                                 EXIT open rep 'exit 0'
  r12 "body is return 0"                               EXIT open rep 'return 0'
  r12 "body is an empty line (no command)"             EXIT any  rep ''
  r12 "body deleted: then fi"                          EXIT any  del ''
  r12 "body is a comment only"                         EXIT any  rep '# chown -R "$OWNER" "$WORK_ROOT"'
  r12 "body is an echo only"                           EXIT open rep 'echo "sudo chown failed"'
  r12 "body is an ::error:: echo with no exit"         EXIT open rep 'echo "::error::sudo chown failed"'
  r12 "body is the plain chown || true"                EXIT open rep 'chown -R "$OWNER" "$WORK_ROOT" || true'
  r12 "body is the plain chown with exit 0 branch"     EXIT open rep 'chown -R "$OWNER" "$WORK_ROOT" || { echo "::error::chown failed"; exit 0; }'
  r12 "body is the plain chown, error with no exit"    EXIT open rep 'chown -R "$OWNER" "$WORK_ROOT" || { echo "::error::chown failed"; }'
  r12 "body is the plain chown alone (failure unchecked)" EXIT open rep 'chown -R "$OWNER" "$WORK_ROOT"'
  r12 "body is a different chown target"               EXIT any  rep 'chown -R "$OWNER" "$GITHUB_WORKSPACE" || { echo "::error::chown failed"; exit 1; }'
  r12 "second command after the plain chown"           EXIT any  after 'true'
  r12 "command before the plain chown"                 EXIT any  before 'true'
  r12 "exit 0 after the plain chown"                   EXIT any  after 'exit 0'
  r12 "if line carries || true"                        TARGET any  ifrep 'if ! sudo -n chown -R "$OWNER" "$WORK_ROOT" || true; then'
  r12 "if line is not negated (sudo success runs the plain chown)" TARGET any ifrep 'if sudo -n chown -R "$OWNER" "$WORK_ROOT"; then'
  r12 "if line then on the same line as the body"      TARGET any ifrep 'if ! sudo -n chown -R "$OWNER" "$WORK_ROOT"; then true; fi; if false; then'
  # control: the unmutated branch is seen closed when executed, and the unmutated scan has no [EXIT] / [TARGET] on it
  frag="$(awk '/^ *if ! sudo -n chown/ { on = 1 } on { print } on && /^ *fi$/ { exit }' "$WF/sovereign-ci.yml")"
  res="$(bash -c "sudo() { return 1; }; chown() { return 1; }; OWNER=o; WORK_ROOT=/w; $frag; echo CONTINUED" 2>/dev/null)"; rc=$?
  { [ "$rc" -ne 0 ] && ! echo "$res" | grep -q CONTINUED; } || miss "r12 control: the unmutated sudo branch is not fail-closed when executed"
  echo "  caught [EXIT/TARGET] $r12n mutants of the \`if ! sudo -n chown\` body, each at every site (the finding: true / : / exit 0 / empty / second command / unchecked chown)"
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
