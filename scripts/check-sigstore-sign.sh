#!/usr/bin/env bash
# The reusable signer must stay what the 17:13Z ruling made it: workflow_call only; runs-on required with no default;
# job permissions exactly id-token+contents write; a tag-only guard AND a main-ancestry guard that really exit 1, run
# before anything is signed; the new bundle format; no stored key; every output wired; every action pinned to a sha.
# PARSED, not grepped: the YAML is read with yq (comments never count), and each rule reads the field it is about.
# Usage: check-sigstore-sign.sh [file] | --self-test
set -euo pipefail
export PATH="/opt/fleet-bin/bin:/usr/local/bin:$PATH"
command -v yq >/dev/null || { echo "::error::yq is not on PATH — an absent parser is a NO-GO, not a pass" >&2; exit 1; }
q() { yq -r "$1" "$F"; }
chk() { local F="$1" bad=0 r i
  red() { echo "RED $1"; bad=1; }
  yq -e '.' "$F" > /dev/null 2>&1 || { echo "RED not parseable YAML"; return 1; }
  [ "$(q '.on | keys | join(",")')" = workflow_call ] || red "trigger is not workflow_call only"
  [ "$(q '.on.workflow_call.inputs."runs-on".required')" = true ] || red "runs-on input is not required"
  [ "$(q '.on.workflow_call.inputs."runs-on" | has("default")')" = false ] || red "runs-on input has a default"
  [ "$(q '.on.workflow_call.inputs."artifact-name".required')" = true ] || red "artifact-name input is not required"
  [ "$(q '.jobs.sign."runs-on"')" = '${{ fromJSON(inputs.runs-on) }}' ] || red "job runs-on is not the caller-supplied input"
  [ "$(q '.permissions | length')" = 0 ] || red "top-level permissions are not empty"
  [ "$(q '.jobs.sign.permissions | to_entries | map(.key + "=" + .value) | sort | join(",")')" = 'contents=write,id-token=write' ] \
    || red "job permissions are not exactly contents+id-token write"
  [ "$(q '.jobs | keys | join(",")')" = sign ] || red "jobs are not exactly sign"
  for i in sha256 bundle identity rekor-index; do
    [ "$(q ".on.workflow_call.outputs.\"$i\".value")" = "\${{ jobs.sign.outputs.$i }}" ] || red "workflow output $i not wired to the job"
    [ "$(q ".jobs.sign.outputs.\"$i\"")" = "\${{ steps.out.outputs.$i }}" ] || red "job output $i not wired to step out"
  done
  # the step named out must actually write each output it advertises
  r=$(q '.jobs.sign.steps[] | select(.id == "out") | .run')
  for i in sha256 rekor-index bundle identity; do
    printf '%s\n' "$r" | grep -v '^ *#' | grep -qE "(echo \"$i(<<|=))" || red "step out never writes output $i"
  done
  # step order: tag guard, checkout, main-ancestry, download, installer, sign
  [ "$(q '.jobs.sign.steps | length')" -ge 7 ] || red "fewer steps than guard,checkout,ancestry,download,installer,sign,upload"
  [ "$(q '.jobs.sign.steps[0].run')" != null ] && printf '%s\n' "$(q '.jobs.sign.steps[0].run')" | grep -v '^ *#' | grep -qF '[ "$REF_TYPE" != tag ]' || red "step 0 is not the tag-only guard"
  printf '%s\n' "$(q '.jobs.sign.steps[0].run')" | grep -vE '^ *#' | grep -qE '^ *if \[ "\$REF_TYPE" != tag \]; then .*exit 1; fi$' || red "tag guard does not exit 1 on a non-tag"
  [ "$(q '.jobs.sign.steps[0].env.REF_TYPE')" = '${{ github.ref_type }}' ] || red "tag guard does not read github.ref_type"
  [ "$(q '.jobs.sign.steps[1].uses | test("^actions/checkout@[0-9a-f]{40}$")')" = true ] || red "step 1 is not a sha-pinned checkout"
  [ "$(q '.jobs.sign.steps[1].with."fetch-depth"')" = 0 ] || red "checkout is not full depth, main ancestry cannot be proven"
  [ "$(q '.jobs.sign.steps[1].with."persist-credentials"')" = false ] || red "checkout keeps credentials"
  r=$(q '.jobs.sign.steps[2].run')
  printf '%s\n' "$r" | grep -v '^ *#' | grep -qF 'git merge-base --is-ancestor "$TAG_SHA" refs/remotes/origin/main' || red "step 2 is not the main-ancestry check"
  printf '%s\n' "$r" | grep -v '^ *#' | grep -qE '\|\| \{ echo "::error::.*exit 1; \}' || red "main-ancestry check does not exit 1"
  printf '%s\n' "$r" | grep -v '^ *#' | grep -qF 'set -euo pipefail' || red "main-ancestry step is not strict"
  [ "$(q '.jobs.sign.steps[2].env.TAG_SHA')" = '${{ github.sha }}' ] || red "ancestry check does not test github.sha"
  [ "$(q '.jobs.sign.steps[3].uses | test("^actions/download-artifact@[0-9a-f]{40}$")')" = true ] || red "step 3 is not the pinned download"
  [ "$(q '.jobs.sign.steps[3].with.name')" = '${{ inputs.artifact-name }}' ] || red "download does not read the artifact-name input"
  [ "$(q '.jobs.sign.steps[4].uses | test("^sigstore/cosign-installer@[0-9a-f]{40}$")')" = true ] || red "step 4 is not the pinned cosign installer"
  [ "$(q '.jobs.sign.steps[4].with."cosign-release"')" = v2.5.3 ] || red "cosign is not pinned"
  for i in 0 2 5; do
    q ".jobs.sign.steps[$i].run" | grep -v '^ *#' | grep -qE '\|\| *(true|:)( |$|\\)|set \+e' && red "step $i masks a failure"
  done
  # no guard or signing step may be skipped or soft-failed
  for i in 0 1 2 3 4 5; do
    [ "$(q ".jobs.sign.steps[$i] | has(\"if\")")" = false ] || red "step $i is conditional"
    [ "$(q ".jobs.sign.steps[$i].\"continue-on-error\" // false")" = false ] || red "step $i is continue-on-error"
  done
  [ "$(q '.jobs.sign."continue-on-error" // false')" = false ] || red "job is continue-on-error"
  [ "$(q '.jobs.sign | has("if")')" = false ] || red "job is conditional"
  # the sign step
  [ "$(q '.jobs.sign.steps[5].id')" = out ] || red "step 5 is not the signing step"
  [ "$(q '.jobs.sign.steps[5]."working-directory"')" = sign ] || red "signing step is not in the downloaded dir"
  r=$(q '.jobs.sign.steps[5].run' | grep -v '^ *#')
  printf '%s\n' "$r" | head -1 | grep -qF 'set -euo pipefail' || red "signing step is not strict (set -euo pipefail first)"
  printf '%s\n' "$r" | grep -qE 'cosign sign-blob --yes --new-bundle-format --bundle "\.\./bundles/\$f\.sigstore\.json" -- "\$f" > /dev/null$' || red "sign-blob is not the new-bundle-format keyless call, un-masked"
  printf '%s\n' "$r" | grep -qE '\|\| *(true|:)|; *true *$|set \+e' && red "a failure is masked in the signing step"
  printf '%s\n' "$r" | grep -qF 'no Rekor log index' || red "signing step does not require a Rekor index"
  # nothing in the parsed document (comments are gone) may name a stored key or a secret
  yq -o=json '.' "$F" | grep -qiE 'secrets|--key|cosign_(private_)?key|signing_key|private.?key|\.pem|\.key\b' && red "a stored key or secret is named"
  # every action is a sha pin
  r=$(yq -r '.. | select(tag == "!!map") | select(has("uses")) | .uses' "$F" | grep -vE '@[0-9a-f]{40}$' || true)
  [ -z "$r" ] || red "unpinned action: $r"
  # the bundles reach the caller, and the release only when asked
  [ "$(q '.jobs.sign.steps[6].uses | test("^actions/upload-artifact@[0-9a-f]{40}$")')" = true ] || red "step 6 is not the pinned bundle upload"
  [ "$(q '.jobs.sign.steps[6].with.name')" = 'sigstore-bundles-${{ github.ref_name }}' ] || red "bundle artifact name drifted from the bundle output"
  [ "$(q '.jobs.sign.steps[6].with.path')" = 'bundles/' ] || red "bundle upload path is not bundles/"
  [ "$(q '.jobs.sign.steps[7].if')" = '${{ inputs.upload-to-release }}' ] || red "release attach is not gated on upload-to-release"
  [ "$bad" = 0 ] && echo "ok sigstore-sign.yml"; return "$bad"; }
if [ "${1:-}" = --self-test ]; then
  F0=.github/workflows/sigstore-sign.yml; t=$(mktemp -d); trap 'rm -rf -- "${t:?}"' EXIT; fail=0; n=0
  chk "$F0" > /dev/null || { echo "FAIL clean file must be GREEN"; fail=1; }
  mut() { n=$((n + 1)); sed "$2" "$F0" > "$t/m.yml"
    cmp -s "$F0" "$t/m.yml" && { echo "FAIL mutant did not apply: $1"; fail=1; return; }
    chk "$t/m.yml" > /dev/null 2>&1 && { echo "FAIL mutant must be RED: $1"; fail=1; }; return 0; }
  mut "trigger push"                  's/^  workflow_call:/  push:/'
  mut "runs-on gets a default"        "s|^        required: true\n||;/^      runs-on:/,/^      upload-to-release:/s|^        type: string|        type: string\n        default: '[\"ubuntu-latest\"]'|"
  mut "runs-on not required"          '/^      runs-on:/,/^      upload-to-release:/s/required: true/required: false/'
  mut "runner hard-coded hosted"      's/runs-on: ${{ fromJSON(inputs.runs-on) }}/runs-on: ubuntu-latest/'
  mut "id-token dropped (comment keeps it)" 's/id-token: write   # the keyless OIDC identity/id-token: read   # id-token: write/'
  mut "contents write dropped"        's/contents: write   # attach/contents: read   # attach/'
  mut "extra permission"              's/^      contents: write   # attach.*/&\n      packages: write/'
  mut "guard exit 0"                  's/(ref_type=$REF_TYPE, $REF_NAME)"; exit 1; fi/(ref_type=$REF_TYPE, $REF_NAME)"; exit 0; fi/'
  mut "guard flipped"                 's/"$REF_TYPE" != tag/"$REF_TYPE" = tag/'
  mut "guard if false &&"             's/if \[ "$REF_TYPE" != tag \]/if false \&\& [ "$REF_TYPE" != tag ]/'
  mut "guard step conditional"        '/name: Refuse anything but a tag build/a\        if: false'
  mut "guard commented out"           's/^          if \[ "$REF_TYPE" != tag \]/          # if [ "$REF_TYPE" != tag ]/'
  mut "guard reads wrong context"     's/REF_TYPE: ${{ github.ref_type }}/REF_TYPE: tag/'
  mut "ancestry check masked"         's/refs\/remotes\/origin\/main \\$/refs\/remotes\/origin\/main || true \\/'
  mut "ancestry exit dropped"         's/ exit 1; }$/ exit 0; }/'
  mut "ancestry tests wrong sha"      's/TAG_SHA: ${{ github.sha }}/TAG_SHA: ${{ github.ref_name }}/'
  mut "shallow checkout"              's/fetch-depth: 0/fetch-depth: 1/'
  mut "checkout keeps credentials"    's/persist-credentials: false/persist-credentials: true/'
  mut "legacy bundle format"          's/--yes --new-bundle-format --bundle/--yes --bundle/'
  mut "sign-blob masked"              's/-- "$f" > \/dev\/null$/-- "$f" > \/dev\/null || true/'
  mut "sign step not strict"          's/^          set -euo pipefail\n//;/Sign every file, keyless/,/mkdir -p/s/set -euo pipefail/set +e/'
  mut "key flag --key TAB"            's/--yes --new-bundle-format/--yes --key\tk.pem --new-bundle-format/'
  mut "secrets index syntax"          "s/TAG: \${{ github.ref_name }}/TAG: \${{ secrets['K'] }}/"
  mut "toJSON(secrets)"               's/TAG: ${{ github.ref_name }}/TAG: ${{ toJSON(secrets) }}/'
  mut "COSIGN_KEY env"                's/^          TAG: ${{ github.ref_name }}/&\n          COSIGN_KEY: x/'
  mut "output unwired (workflow)"     's/value: ${{ jobs.sign.outputs.identity }}/value: x/'
  mut "output unwired (job)"          's/rekor-index: ${{ steps.out.outputs.rekor-index }}/rekor-index: x/'
  mut "step stops writing an output"  's/echo "bundle=sigstore-bundles-$TAG"/echo "bundle-x=1"/'
  mut "Rekor index not required"      's/no Rekor log index in the bundle/skip/'
  mut "action unpinned"               's/actions\/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093/actions\/download-artifact@v4/'
  mut "cosign unpinned"               's/cosign-release: v2.5.3/cosign-release: latest/'
  mut "release attach unconditional"  's/if: ${{ inputs.upload-to-release }}/if: true/'
  mut "bundle name drift"             's/name: sigstore-bundles-${{ github.ref_name }}/name: bundles/'
  [ "$fail" = 0 ] && echo "PASS check-sigstore-sign self-test: clean GREEN + $n mutants RED"; exit "$fail"
fi
chk "${1:-.github/workflows/sigstore-sign.yml}"
