#!/usr/bin/env bash
# infra-fetch-v1 guard. Usage: test-infra-fetch.sh [--self-test]   (WF_DIR overrides the workflow dir)
#
# unified-gate.yml syncs the private paiml/infra repo on the runner. Ephemeral seats have no ssh key,
# so when a caller passes the optional secret `infra_token` the sync goes over https with a per-command
# extraheader; with no token the original ssh commands run unchanged. The block sits between the
# comment markers "infra-fetch-v1 BEGIN" / "infra-fetch-v1 END" and is inline (a called workflow does
# not check out its own repo, so it cannot reach a script), therefore all sites must be IDENTICAL.
# FAILS (tag in brackets) on:
#   [NOSITE]   no paiml/infra clone site found      [NOSCAN]  no workflow file scanned
#   [OUTSIDE]  a git clone/fetch of paiml/infra, or a git@github.com:paiml/infra, outside a block
#              (inside a block the single legacy ssh clone is the token-empty branch)
#   [SSHURL]   an ssh://git@ form                   [REWRITE] a url.insteadOf rewrite
#   [URLTOKEN] credentials in an https URL (userinfo@)
#   [ECHO]     echo/printf of INFRA_TOKEN/INFRA_B64/INFRA_HDR other than ::add-mask:: or the base64 pipe
#   [DRIFT]    blocks not byte-identical            [NOBLOCK] a site without a block around it
#   [NOMASK]   a block that builds INFRA_B64 without ::add-mask::
# Also runs the first block for real against a stub `git` (behaviour test) and prints files scanned.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 2
WF=${WF_DIR:-.github/workflows}
FAIL=0
fail() { echo "FAIL [$1] $2"; FAIL=1; }

# scan_file FILE -> prints "TAG detail" lines; prints nothing when clean.
scan_file() {
  awk '
    function trim(s) { sub(/^[ \t]+/, "", s); return s }
    { raw=$0; t=trim(raw) }
    index(raw, "infra-fetch-v1 BEGIN") { inb=1; nb++; next }
    index(raw, "infra-fetch-v1 END")   { inb=0; next }
    substr(t,1,1) == "#" { next }                       # comment decoys never count
    { line=t }
    line ~ /ssh:\/\/git@/                       { print "SSHURL " FILENAME ":" NR }
    line ~ /insteadOf/                          { print "REWRITE " FILENAME ":" NR }
    line ~ /https:\/\/[^\/ "\047]+@/            { print "URLTOKEN " FILENAME ":" NR }
    (line ~ /(echo|printf)/) && (line ~ /INFRA_(TOKEN|B64|HDR)/) && (line !~ /::add-mask::/) && (line !~ /\| *base64/) {
      print "ECHO " FILENAME ":" NR }
    line ~ /INFRA_B64=/ { b64=1 }
    line ~ /::add-mask::/ { mask=1 }
    (line ~ /git@github\.com:paiml\/infra/ || line ~ /git +(clone|fetch)[^|]*paiml\/infra/) {
      sites++
      if (!inb) print "OUTSIDE " FILENAME ":" NR
    }
    END { if (b64 && !mask) print "NOMASK " FILENAME
          if (sites > 0 && nb == 0) print "NOBLOCK " FILENAME
          print "SITES " sites+0 }
  ' "$1"
}

# block_of FILE N -> the Nth block (markers excluded)
block_of() {
  awk -v n="$2" '
    index($0, "infra-fetch-v1 BEGIN") { c++; on=(c==n); next }
    index($0, "infra-fetch-v1 END")   { on=0; next }
    on { print }' "$1"
}

scan_dir() { # dir -> prints findings, sets SCANNED/SITES_TOTAL globals via files
  local f out sites=0 nfiles=0
  for f in "$1"/*.yml "$1"/*.yaml; do
    [ -e "$f" ] || continue
    nfiles=$((nfiles+1))
    out="$(scan_file "$f")"
    while IFS= read -r l; do
      [ -z "$l" ] && continue
      case "$l" in
        SITES\ *) sites=$((sites+${l#SITES }));;
        *) fail "${l%% *}" "${l#* }";;
      esac
    done <<EOF
$out
EOF
    # DRIFT: all blocks inside one file identical
    local nb i first="" cur
    nb=$(grep -c 'infra-fetch-v1 BEGIN' "$f" || true)
    for i in $(seq 1 "$nb"); do
      cur="$(block_of "$f" "$i")"
      if [ -z "$first" ]; then first="$cur"; elif [ "$cur" != "$first" ]; then fail DRIFT "$f block $i differs from block 1"; fi
    done
  done
  SCANNED=$nfiles; SITES_TOTAL=$sites
  echo "scanned $nfiles workflow file(s), $sites paiml/infra fetch site(s)"
  [ "$nfiles" -gt 0 ] || { echo "FAIL [NOSCAN] no workflow file scanned"; exit 2; }
  [ "$sites" -gt 0 ] || fail NOSITE "no paiml/infra clone site found"
}

# ---------- behaviour test with a stub git ----------
behaviour() {
  local wf="$1" tmp stub log dir out tok="ghs_FAKEtokenVALUE123" b64 blk
  tmp="$(mktemp -d)"; stub="$tmp/bin"; mkdir -p "$stub"
  printf '%s\n' '#!/usr/bin/env bash' 'printf "%s\n" "$*" >> "$GIT_LOG"' 'exit 0' > "$stub/git"
  chmod +x "$stub/git"
  blk="$(block_of "$wf" 1)"
  [ -n "$blk" ] || { fail NOBLOCK "no block to run in $wf"; rm -rf "${tmp:?}"; return; }
  printf '%s\n' "$blk" > "$tmp/block.sh"
  b64="$(printf 'x-access-token:%s' "$tok" | base64 -w0)"
  run_case() { # name token hasgit
    log="$tmp/$1.log"; : > "$log"; dir="$tmp/$1.dir"; mkdir -p "$dir"; rm -rf "${dir:?}"
    [ "$3" = yes ] && mkdir -p "$dir/.git"
    out="$(INFRA_TOKEN="$2" INFRA_DIR="$dir" GIT_LOG="$log" PATH="$stub:$PATH" bash "$tmp/block.sh" 2>&1)"
  }
  # token set, fresh clone
  run_case tfresh "$tok" no
  grep -q 'clone --depth 1 https://github.com/paiml/infra.git' "$tmp/tfresh.log" || fail BEHAV "token+fresh: no https clone"
  grep -q "http.https://github.com/.extraheader=AUTHORIZATION: basic $b64" "$tmp/tfresh.log" || fail BEHAV "token+fresh: no extraheader"
  ! grep -q 'git@' "$tmp/tfresh.log" || fail BEHAV "token+fresh: git@ used"
  ! printf '%s' "$out" | grep -qF "$tok" || fail BEHAV "token printed to output"
  [ "$(printf '%s' "$out" | grep -cF "$b64")" -le 1 ] || fail BEHAV "b64 printed more than the mask line"
  # token set, existing checkout (ssh origin): https URL explicit, remote untouched
  run_case texist "$tok" yes
  grep -q "fetch https://github.com/paiml/infra.git main" "$tmp/texist.log" || fail BEHAV "token+existing: fetch lacks https URL"
  grep -q "reset --hard FETCH_HEAD" "$tmp/texist.log" || fail BEHAV "token+existing: reset not FETCH_HEAD"
  ! grep -Eq 'git@|remote|config|origin' "$tmp/texist.log" || fail BEHAV "token+existing: touched remote/ssh"
  # token empty: argv equals the old commands exactly
  run_case efresh "" no
  [ "$(cat "$tmp/efresh.log")" = "clone --depth 1 git@github.com:paiml/infra.git $tmp/efresh.dir" ] || fail BEHAV "empty+fresh: argv differs from old"
  run_case eexist "" yes
  [ "$(cat "$tmp/eexist.log")" = "-C $tmp/eexist.dir fetch origin main
-C $tmp/eexist.dir reset --hard origin/main" ] || fail BEHAV "empty+existing: argv differs from old"
  rm -rf "${tmp:?}"
}

# ---------- fixtures: one per FORM VARIANT ----------
selftest() {
  local d f exp tmp
  tmp="$(mktemp -d)"
  mk() { printf '%s\n' "$2" > "$tmp/$1.yml"; }
  local GOOD='# infra-fetch-v1 BEGIN
if [ -n "${INFRA_TOKEN:-}" ]; then
  INFRA_B64="$(printf x:%s "$INFRA_TOKEN" | base64 -w0)"
  echo "::add-mask::$INFRA_B64"
  git -c "$H" clone https://github.com/paiml/infra.git "$D"
else
  git clone --depth 1 git@github.com:paiml/infra.git "$D"
fi
# infra-fetch-v1 END'
  mk green "$GOOD"
  mk decoy "$GOOD
# git clone git@github.com:paiml/infra.git (comment decoy)
# url.insteadOf ssh://git@github.com/ (comment decoy)"
  mk bare "$GOOD
git clone git@github.com:paiml/infra.git \"\$D\""
  mk sshurl "$GOOD
echo ssh://git@github.com/paiml/infra"
  mk rewrite "$GOOD
git config --global url.\"git@github.com:\".insteadOf https://github.com/"
  mk urltok "$GOOD
git clone https://x-access-token:\$T@github.com/paiml/infra.git \"\$D\""
  mk echo "$GOOD
echo \"token is \$INFRA_TOKEN\""
  mk nomask '# infra-fetch-v1 BEGIN
INFRA_B64="$(printf x:%s "$INFRA_TOKEN" | base64 -w0)"
git clone git@github.com:paiml/infra.git "$D"
# infra-fetch-v1 END'
  mk drift "$GOOD
$(printf '%s' "$GOOD" | sed 's/depth 1/depth 2/')"
  local bad=0 name tag
  for exp in green:NONE decoy:NONE bare:OUTSIDE sshurl:SSHURL rewrite:REWRITE urltok:URLTOKEN echo:ECHO nomask:NOMASK drift:DRIFT; do
    name=${exp%%:*}; tag=${exp##*:}
    mkdir -p "$tmp/$name.d"; cp "$tmp/$name.yml" "$tmp/$name.d/x.yml"
    out="$( ( FAIL=0; scan_dir "$tmp/$name.d" ) 2>&1 )"
    if [ "$tag" = NONE ]; then
      printf '%s' "$out" | grep -q '^FAIL' && { echo "SELFTEST BAD: fixture $name should be clean: $out"; bad=1; }
    else
      printf '%s' "$out" | grep -q "^FAIL \[$tag\]" || { echo "SELFTEST BAD: fixture $name not flagged $tag: $out"; bad=1; }
    fi
  done
  rm -rf "${tmp:?}"
  [ "$bad" = 0 ] && echo "self-test OK (9 fixtures: green, decoy, 7 variants)"
  return $bad
}

if [ "${1:-}" = "--self-test" ]; then selftest; exit $?; fi
selftest || exit 2
scan_dir "$WF"
behaviour "$WF/unified-gate.yml"
if [ "$FAIL" = 0 ]; then echo "GREEN infra-fetch-v1"; else echo "RED infra-fetch-v1"; exit 1; fi
