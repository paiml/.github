#!/usr/bin/env bash
# Verify a keyless-signed file before using it (Noah 17:13Z item 5). No third state: any failure exits non-zero.
# Usage: sigstore-verify.sh <file> <bundle> <identity> | --self-test
#   identity = the exact certificate identity, i.e. the sigstore-sign.yml ref the release pinned.
# COSIGN overrides the binary (the self-test injects a model of cosign's verdicts; real cosign is proven on the first tag).
set -euo pipefail
ISSUER="https://token.actions.githubusercontent.com"
COSIGN="${COSIGN:-cosign}"
verify() { # file bundle identity
  [ -f "$1" ] && [ -f "$2" ] || { echo "REFUSE: file or bundle missing" >&2; return 1; }
  "$COSIGN" verify-blob --bundle "$2" --certificate-identity "$3" --certificate-oidc-issuer "$ISSUER" -- "$1" > /dev/null 2>&1 \
    || { echo "REFUSE: signature does not verify for identity $3" >&2; return 1; }
  echo "ok: $1 verified as $3"
}
if [ "${1:-}" = --self-test ]; then
  t=$(mktemp -d); trap 'rm -rf -- "${t:?}"' EXIT
  # model of cosign verify-blob: the bundle records "<sha256> <identity> <issuer>"; verify = all three match
  cat > "$t/cosign" <<'M'
#!/usr/bin/env bash
while [ $# -gt 0 ]; do case "$1" in --bundle) b="$2"; shift;; --certificate-identity) i="$2"; shift;; --certificate-oidc-issuer) o="$2"; shift;; --) f="$2"; shift;; esac; shift; done
read -r s bi bo < "$b"
[ "$s" = "$(sha256sum "$f" | cut -d' ' -f1)" ] && [ "$bi" = "$i" ] && [ "$bo" = "$o" ]
M
  chmod +x "$t/cosign"; export COSIGN="$t/cosign"
  GOOD=https://github.com/paiml/.github/.github/workflows/sigstore-sign.yml@refs/heads/main
  printf 'payload' > "$t/bin"; printf '%s %s %s\n' "$(sha256sum "$t/bin" | cut -d' ' -f1)" "$GOOD" "$ISSUER" > "$t/bin.sigstore.json"
  fail=0
  ( verify "$t/bin" "$t/bin.sigstore.json" "$GOOD" ) > /dev/null 2>&1 || { echo "FAIL valid must install"; fail=1; }
  printf 'tampered' > "$t/bin2"; cp "$t/bin.sigstore.json" "$t/bin2.sigstore.json"
  ( verify "$t/bin2" "$t/bin2.sigstore.json" "$GOOD" ) > /dev/null 2>&1 && { echo "FAIL tampered binary must refuse"; fail=1; }
  ( verify "$t/bin" "$t/bin.sigstore.json" "https://github.com/evil/repo/.github/workflows/x.yml@refs/heads/main" ) > /dev/null 2>&1 && { echo "FAIL another workflow/repo must refuse"; fail=1; }
  ( verify "$t/bin" "$t/none.sigstore.json" "$GOOD" ) > /dev/null 2>&1 && { echo "FAIL missing bundle must refuse"; fail=1; }
  [ "$fail" = 0 ] && echo "PASS sigstore-verify self-test: 4 rows (valid / tampered / other identity / no bundle)"
  exit "$fail"
fi
verify "$@"
