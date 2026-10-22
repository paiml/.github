#!/usr/bin/env bash
# Verify a keyless-signed file before using it (Noah 17:13Z items 5+6). No third state: any failure exits non-zero.
# Usage: sigstore-verify.sh <file> <bundle> <identity> <caller-repo> <caller-workflow-name> [<caller-ref>] | --self-test
#   identity             = the exact certificate identity, i.e. the sigstore-sign.yml ref the release pinned.
#   caller-repo          = owner/repo that CALLED the signer (e.g. paiml/rmedia). The SAN is the same for every caller
#                          of this public workflow, so the SAN alone proves nothing about who asked for the signature.
#   caller-workflow-name = the caller's workflow `name:` (e.g. Release).
#   caller-ref           = optional, e.g. refs/tags/v-rmedia-cli-0.6.0.
# The verifier is always `cosign` on PATH. There is no environment override: a variable that swaps the verifier
# would let COSIGN=true verify anything. The self-test replaces it by shadowing the function below, not by env.
set -euo pipefail
ISSUER="https://token.actions.githubusercontent.com"
run_cosign() { command cosign "$@"; }
verify() { # file bundle identity repo workflow [ref]
  [ "$#" -ge 5 ] || { echo "REFUSE: need file bundle identity caller-repo caller-workflow-name" >&2; return 1; }
  # an unknown flag is not a positional pin: it must never be read as an identity, repo or workflow
  local x; for x in "$@"; do case "$x" in -*) echo "REFUSE: unknown flag $x" >&2; return 1;; esac; done
  # cosign skips an EMPTY pin, so an empty one must never reach it
  local a; for a in "$@"; do [ -n "$a" ] || { echo "REFUSE: an empty argument (cosign would skip that pin)" >&2; return 1; }; done
  [ -f "$1" ] && [ -f "$2" ] || { echo "REFUSE: file or bundle missing" >&2; return 1; }
  local pin=(--certificate-identity "$3" --certificate-oidc-issuer "$ISSUER"
             --certificate-github-workflow-repository "$4" --certificate-github-workflow-name "$5")
  [ -z "${6:-}" ] || pin+=(--certificate-github-workflow-ref "$6")
  run_cosign verify-blob --new-bundle-format --bundle "$2" "${pin[@]}" -- "$1" > /dev/null 2>&1 \
    || { echo "REFUSE: signature does not verify for $3 as called by $4 ($5)" >&2; return 1; }
  echo "ok: $1 verified as $3 called by $4 ($5)"
}
if [ "${1:-}" = --self-test ]; then
  t=$(mktemp -d); trap 'rm -rf -- "${t:?}"' EXIT
  # model of cosign verify-blob: the bundle records "<sha256> <identity> <issuer> <repo> <workflow> <ref>";
  # verify = every pinned flag matches the record, and a flag that is not given is not checked.
  run_cosign() {
    local b="" i="" o="" r="" w="" g="" f="" nb=0
    shift # verify-blob
    while [ $# -gt 0 ]; do case "$1" in
      --new-bundle-format) nb=1;; --bundle) b="$2"; shift;; --certificate-identity) i="$2"; shift;;
      --certificate-oidc-issuer) o="$2"; shift;; --certificate-github-workflow-repository) r="$2"; shift;;
      --certificate-github-workflow-name) w="$2"; shift;; --certificate-github-workflow-ref) g="$2"; shift;;
      --) f="$2"; shift;; *) return 1;; esac; shift; done   # an unknown flag is a refusal, never ignored
    local s bi bo br bw bg; read -r s bi bo br bw bg < "$b"
    [ "$nb" = 1 ] && [ "$s" = "$(sha256sum "$f" | cut -d' ' -f1)" ] && { [ -z "$i" ] || [ "$bi" = "$i" ]; } && { [ -z "$o" ] || [ "$bo" = "$o" ]; } \
      && { [ -z "$r" ] || [ "$br" = "$r" ]; } && { [ -z "$w" ] || [ "$bw" = "$w" ]; } && { [ -z "$g" ] || [ "$bg" = "$g" ]; }
  }
  GOOD=https://github.com/paiml/.github/.github/workflows/sigstore-sign.yml@refs/heads/main
  REPO=paiml/rmedia; WF=Release; REF=refs/tags/v-rmedia-cli-0.6.0
  LIT_ISSUER=https://token.actions.githubusercontent.com   # literal, not $ISSUER: a wrong constant must not survive
  printf 'payload' > "$t/bin"; printf '%s %s %s %s %s %s\n' "$(sha256sum "$t/bin" | cut -d' ' -f1)" "$GOOD" "$LIT_ISSUER" "$REPO" "$WF" "$REF" > "$t/bin.sigstore.json"
  fail=0
  rows=0
  want() { # want ok|refuse "name" args...
    local w="$1" n="$2"; shift 2; rows=$((rows + 1))
    if ( verify "$@" ) > /dev/null 2>&1; then [ "$w" = ok ] || { echo "FAIL $n must refuse"; fail=1; }
    else [ "$w" = refuse ] || { echo "FAIL $n must install"; fail=1; }; fi
  }
  printf 'tampered' > "$t/bin2"; cp "$t/bin.sigstore.json" "$t/bin2.sigstore.json"
  want ok     "valid"                 "$t/bin" "$t/bin.sigstore.json" "$GOOD" "$REPO" "$WF" "$REF"
  want ok     "valid without ref pin" "$t/bin" "$t/bin.sigstore.json" "$GOOD" "$REPO" "$WF"
  want refuse "tampered binary"       "$t/bin2" "$t/bin2.sigstore.json" "$GOOD" "$REPO" "$WF" "$REF"
  want refuse "other workflow SAN"    "$t/bin" "$t/bin.sigstore.json" "https://github.com/evil/repo/.github/workflows/x.yml@refs/heads/main" "$REPO" "$WF" "$REF"
  want refuse "same SAN, other repo"  "$t/bin" "$t/bin.sigstore.json" "$GOOD" "evil/rmedia" "$WF" "$REF"
  want refuse "same SAN, other caller workflow" "$t/bin" "$t/bin.sigstore.json" "$GOOD" "$REPO" "Nightly" "$REF"
  want refuse "other caller ref"      "$t/bin" "$t/bin.sigstore.json" "$GOOD" "$REPO" "$WF" "refs/tags/v-other"
  want refuse "no repo pin given"     "$t/bin" "$t/bin.sigstore.json" "$GOOD"
  want refuse "empty repo pin"        "$t/bin" "$t/bin.sigstore.json" "$GOOD" "" "$WF" "$REF"
  want refuse "empty workflow pin"    "$t/bin" "$t/bin.sigstore.json" "$GOOD" "$REPO" "" "$REF"
  want refuse "empty ref pin"         "$t/bin" "$t/bin.sigstore.json" "$GOOD" "$REPO" "$WF" ""
  want refuse "empty identity"        "$t/bin" "$t/bin.sigstore.json" "" "$REPO" "$WF" "$REF"
  printf '%s %s %s %s %s %s\n' "$(sha256sum "$t/bin" | cut -d' ' -f1)" "$GOOD" "https://evil.example/issuer" "$REPO" "$WF" "$REF" > "$t/wi.sigstore.json"
  want refuse "wrong issuer in the cert" "$t/bin" "$t/wi.sigstore.json" "$GOOD" "$REPO" "$WF" "$REF"
  want refuse "missing bundle"        "$t/bin" "$t/none.sigstore.json" "$GOOD" "$REPO" "$WF" "$REF"
  # unknown flags: real files named like flags with valid pins (only the flag refusal can stop these), and a 7th flag
  cp "$t/bin" "$t/--insecure-ignore-tlog"; cp "$t/bin.sigstore.json" "$t/--trusted-root"
  ( cd "$t" && verify -- --insecure-ignore-tlog "$t/bin.sigstore.json" "$GOOD" "$REPO" "$WF" ) > /dev/null 2>&1 && { echo 'FAIL a flag-named file must refuse'; fail=1; }
  want refuse "flag as the file"         "--insecure-ignore-tlog" "$t/bin.sigstore.json" "$GOOD" "$REPO" "$WF"
  want refuse "flag as the bundle"       "$t/bin" "--trusted-root" "$GOOD" "$REPO" "$WF"
  want refuse "7th arg is a flag"        "$t/bin" "$t/bin.sigstore.json" "$GOOD" "$REPO" "$WF" "$REF" --insecure-ignore-tlog
  want refuse "flag as the ref pin"      "$t/bin" "$t/bin.sigstore.json" "$GOOD" "$REPO" "$WF" --certificate-identity-regexp=.*
  # the verifier cannot be swapped from the environment: COSIGN=true must not make a bad file verify
  cat > "$t/true" <<'S'
#!/usr/bin/env bash
exit 0
S
  chmod +x "$t/true"
  rows=$((rows + 1))
  if COSIGN="$t/true" COSIGN_BIN="$t/true" COSIGN_PATH="$t/true" SIGSTORE_ISSUER=x SIGSTORE_ID_TOKEN=x bash "$0" "$t/bin2" "$t/bin2.sigstore.json" "$GOOD" "$REPO" "$WF" > /dev/null 2>&1; then echo "FAIL COSIGN in the environment replaced the verifier"; fail=1; fi
  [ "$fail" = 0 ] && echo "PASS sigstore-verify self-test: $rows rows"
  exit "$fail"
fi
verify "$@"
