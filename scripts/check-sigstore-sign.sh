#!/usr/bin/env bash
# The reusable signer must stay: workflow_call, id-token+contents write, tag-only guard, no stored key, 4 outputs.
# Usage: check-sigstore-sign.sh [file] | --self-test
set -euo pipefail
chk() { local f="$1" bad=0 k
  grep -q '^  workflow_call:' "$f" || { echo "RED not a workflow_call"; bad=1; }
  grep -q 'id-token: write' "$f" || { echo "RED no id-token: write"; bad=1; }
  grep -q 'contents: write' "$f" || { echo "RED no contents: write"; bad=1; }
  grep -q "ref_type" "$f" && grep -q '!= tag' "$f" || { echo "RED no tag-only guard"; bad=1; }
  grep -qiE 'RELEASE_SIGNING_KEY|--key[ =]|COSIGN_PRIVATE_KEY|secrets\.' "$f" && { echo "RED a stored key or secret"; bad=1; }
  for k in sha256 bundle identity rekor-index; do grep -q "^      $k:" "$f" || { echo "RED missing output $k"; bad=1; }; done
  [ "$bad" = 0 ] && echo "ok sigstore-sign.yml"; return "$bad"; }
if [ "${1:-}" = --self-test ]; then
  f=.github/workflows/sigstore-sign.yml; t=$(mktemp -d); trap 'rm -rf -- "${t:?}"' EXIT; fail=0
  chk "$f" > /dev/null || { echo "FAIL clean file must be GREEN"; fail=1; }
  for m in 's/^  workflow_call:/  push:/' 's/id-token: write/id-token: read/' 's/!= tag/!= branch/' 's/^      rekor-index:/      rekor:/' 's/--yes --bundle/--yes --key k.pem --bundle/'; do
    sed "$m" "$f" > "$t/m.yml"; cmp -s "$f" "$t/m.yml" && { echo "FAIL mutant did not apply: $m"; fail=1; }
    chk "$t/m.yml" > /dev/null 2>&1 && { echo "FAIL mutant must be RED: $m"; fail=1; }
  done
  [ "$fail" = 0 ] && echo "PASS check-sigstore-sign self-test: 6 rows"; exit "$fail"
fi
chk "${1:-.github/workflows/sigstore-sign.yml}"
