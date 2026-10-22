#!/usr/bin/env bash
# The reusable signer must stay what the 17:13Z ruling made it: workflow_call only; runs-on required with no default;
# job permissions exactly id-token+contents write; a tag-only guard AND a main-ancestry guard that really exit 1, run
# before anything is signed; the new bundle format; no stored key; every output wired; every action pinned to a sha.
# PARSED, not grepped: the YAML is read with yq (comments never count), and each rule reads the field it is about.
# Usage: check-sigstore-sign.sh [file] | --self-test
set -euo pipefail
export PATH="/opt/fleet-bin/bin:/usr/local/bin:$PATH"
command -v yq >/dev/null || { echo "::error::yq is not on PATH — an absent parser is a NO-GO, not a pass" >&2; exit 1; }
yq --version 2>/dev/null | grep -q "mikefarah/yq.* version v4\." || { echo "::error::yq is not mikefarah yq v4 (the parser the rules and pins are written for)" >&2; exit 1; }
command -v jq >/dev/null || { echo "::error::jq is not on PATH" >&2; exit 1; }
q() { yq -r "$1" "$F"; }
declare -A BEH_MEMO   # behaviour verdict per (guard body, ancestry body): a mutant that leaves both bodies alone costs nothing
behav() {
  local g="$1" a="$2" w
  w=$(mktemp -d)
  printf '%s\n' "$g" > "$w/g.sh"; printf '%s\n' "$a" > "$w/a.sh"
  ( cd "$w" && git init -q --bare o.git && git init -q seed && cd seed && git config user.email t@t && git config user.name t \
    && git checkout -q -b main && git commit -q --allow-empty -m a && git commit -q --allow-empty -m b && git checkout -q -b side \
    && git commit -q --allow-empty -m c && git push -q "$w/o.git" main side && cd .. && git clone -q o.git r ) > /dev/null 2>&1
  local A B C; A=$(git -C "$w/r" rev-parse origin/main~1); B=$(git -C "$w/r" rev-parse origin/main); C=$(git -C "$w/r" rev-parse origin/side)
  : > "$w/ghenv"; : > "$w/ghpath"
  runb() { # script cwd env... : production flags, empty environment
    local s="$1" d="$2"; shift 2
    ( cd "$d" && env -i PATH="$PATH" HOME="$w" CI=true GITHUB_ACTIONS=true GITHUB_WORKFLOW=Release GITHUB_RUN_ID=1 GITHUB_RUN_ATTEMPT=1 \
        GITHUB_ENV="$w/ghenv" GITHUB_PATH="$w/ghpath" GITHUB_OUTPUT="$w/ghout" RUNNER_TEMP="$w" "$@" \
        bash --noprofile --norc -eo pipefail "$s" ) > /dev/null 2>&1; }
  local job nm
  for job in sign build x; do for nm in v1.0 main release/1 x; do
    runb "$w/g.sh" "$w/r" GITHUB_JOB=$job REF_TYPE=tag REF_NAME=$nm || echo "RED tag guard body: a tag must pass ($job/$nm)"
    ! runb "$w/g.sh" "$w/r" GITHUB_JOB=$job REF_TYPE=branch REF_NAME=$nm || echo "RED tag guard body: a branch must fail ($job/$nm)"
    ! runb "$w/g.sh" "$w/r" GITHUB_JOB=$job REF_TYPE= REF_NAME=$nm || echo "RED tag guard body: an empty ref type must fail ($job/$nm)"
    ! runb "$w/g.sh" "$w/r" GITHUB_JOB=$job REF_NAME=$nm || echo "RED tag guard body: an unset ref type must fail ($job/$nm)"
    runb "$w/a.sh" "$w/r" GITHUB_JOB=$job TAG_SHA="$B" || echo "RED ancestry body: the tip of main must pass ($job)"
    runb "$w/a.sh" "$w/r" GITHUB_JOB=$job TAG_SHA="$A" || echo "RED ancestry body: a commit on main must pass ($job)"
    ! runb "$w/a.sh" "$w/r" GITHUB_JOB=$job TAG_SHA="$C" || echo "RED ancestry body: an off-main commit must fail ($job)"
    ! runb "$w/a.sh" "$w/r" GITHUB_JOB=$job TAG_SHA=deadbeef || echo "RED ancestry body: a garbage sha must fail ($job)"
    ! runb "$w/a.sh" "$w/r" GITHUB_JOB=$job TAG_SHA= || echo "RED ancestry body: an empty sha must fail ($job)"
    ! runb "$w/a.sh" "$w/r" GITHUB_JOB=$job || echo "RED ancestry body: an unset sha must fail ($job)"
  done; done
  # off Actions entirely: the verdicts must not depend on GITHUB_ACTIONS either
  ! ( cd "$w/r" && env -i PATH="$PATH" HOME="$w" REF_TYPE=branch REF_NAME=x bash --noprofile --norc -eo pipefail "$w/g.sh" ) > /dev/null 2>&1 || echo "RED tag guard body: a branch must fail off Actions"
  ! ( cd "$w/r" && env -i PATH="$PATH" HOME="$w" TAG_SHA="$C" bash --noprofile --norc -eo pipefail "$w/a.sh" ) > /dev/null 2>&1 || echo "RED ancestry body: off-main must fail off Actions"
  ( cd "$w/r" && git update-ref -d refs/remotes/origin/main && ! runb "$w/a.sh" "$w/r" GITHUB_JOB=sign TAG_SHA="$B" ) || echo "RED ancestry body: missing origin/main must fail"
  [ ! -s "$w/ghenv" ] && [ ! -s "$w/ghpath" ] && [ ! -e "$w/ghout" ] || echo "RED a guard wrote GITHUB_ENV / GITHUB_PATH / GITHUB_OUTPUT"
  rm -rf -- "${w:?}"
}
chk() { local F="$1" nog="${2:-}" bad=0 r i g a k
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
  for i in sha256 tag bundle identity rekor-index; do
    [ "$(q ".on.workflow_call.outputs.\"$i\".value")" = "\${{ jobs.sign.outputs.$i }}" ] || red "workflow output $i not wired to the job"
    [ "$(q ".jobs.sign.outputs.\"$i\"")" = "\${{ steps.out.outputs.$i }}" ] || red "job output $i not wired to step out"
  done
  # the step named out must actually write each output it advertises
  r=$(q '.jobs.sign.steps[] | select(.id == "out") | .run')
  for i in sha256 rekor-index bundle identity tag; do
    printf '%s\n' "$r" | grep -v '^ *#' | grep -qE "(echo \"$i(<<|=))" || red "step out never writes output $i"
  done
  # step order: tag guard, checkout, main-ancestry, download, installer, sign
  [ "$(q '.jobs.sign.steps | length')" = 8 ] || red "steps are not exactly the eight: guard,checkout,ancestry,download,installer,sign,upload,attach"
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
  # GOLDEN: the parsed workflow (comments gone) must equal the reviewed golden byte for byte, so every key of every
  # step is pinned — run bodies, env, shell, defaults, container, extra steps. An edit to the signer is an edit to
  # scripts/sigstore-sign.golden.json in the same PR, which is the review.
  here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
  [ "$nog" = nogolden ] || [ "$(yq -o=json -I2 '.' "$F" | jq -S . | sha256sum)" = "$(sha256sum < "$here/sigstore-sign.golden.json")" ] || red "workflow differs from scripts/sigstore-sign.golden.json"
  # LITERAL PINS (Q-GH91c): every executable body and every step's non-run keys are compared with text written in THIS
  # file, comment lines aside. There is no hash and nothing to regenerate: changing a body means editing the literal
  # below, and CODEOWNERS makes that a second reviewer's act. (The golden below stays as a belt over the braces.)
  want_run() { # step ; expected body on stdin
    local got; got=$(q ".jobs.sign.steps[$1].run" | grep -v '^ *#'); [ "$got" = "$(cat)" ] || red "step $1 run body differs from the pinned literal"; }
  want_step() { # step ; expected JSON of the step without its run key, on stdin
    local got; got=$(yq -o=json -I0 ".jobs.sign.steps[$1] | del(.run)" "$F" | jq -cS .); [ "$got" = "$(jq -cS . <<< "$(cat)")" ] || red "step $1 keys differ from the pinned literal"; }
  want_run 0 <<'PIN'
if [ "$REF_TYPE" != tag ]; then echo "::error::sigstore-sign signs tag builds only (ref_type=$REF_TYPE, $REF_NAME)"; exit 1; fi
PIN
  want_run 2 <<'PIN'
set -euo pipefail
git rev-parse --verify --quiet refs/remotes/origin/main >/dev/null || { echo "::error::origin/main is not in the checkout"; exit 1; }
git merge-base --is-ancestor "$TAG_SHA" refs/remotes/origin/main \
  || { echo "::error::$TAG_SHA is not an ancestor of origin/main; release signing is for tag builds from main only"; exit 1; }
PIN
  want_run 5 <<'PIN'
set -euo pipefail
mkdir "$WORK/bundles"; : > "$WORK/manifest.txt"; : > "$WORK/rekor.txt"
n=0
while IFS= read -r f; do
  f="${f#./}"
  sha256sum -- "$f" >> "$WORK/manifest.txt"
  cosign sign-blob --yes --new-bundle-format --bundle "$WORK/bundles/$f.sigstore.json" -- "$f" > /dev/null
  idx=$(jq -r '.verificationMaterial.tlogEntries[0].logIndex // empty' "$WORK/bundles/$f.sigstore.json")
  [ -n "$idx" ] || { echo "::error::no Rekor log index in the bundle for $f"; exit 1; }
  echo "$f=$idx" >> "$WORK/rekor.txt"
  n=$((n + 1))
done < <(find . -type f ! -name '*.sigstore.json' | LC_ALL=C sort)
[ "$n" -ge 1 ] || { echo "::error::artifact $ARTIFACT_NAME held no files to sign"; exit 1; }
b=$(find "$WORK/bundles" -name "*.sigstore.json" | LC_ALL=C sort | head -1)
id=$(jq -r ".verificationMaterial.certificate.rawBytes // .verificationMaterial.x509CertificateChain.certificates[0].rawBytes" "$b" | base64 -d | openssl x509 -inform DER -noout -ext subjectAltName | grep -o "https://[^, ]*" | head -1)
[ -n "$id" ] || { echo "::error::no signer identity in the certificate of $b"; exit 1; }
{
  echo "sha256<<EOF_SHA"; cat "$WORK/manifest.txt"; echo "EOF_SHA"
  echo "rekor-index<<EOF_REK"; cat "$WORK/rekor.txt"; echo "EOF_REK"
  echo "bundle=sigstore-bundles-$TAG"
  echo "tag=$TAG"
  echo "identity=$id"
} >> "$GITHUB_OUTPUT"
PIN
  want_run 7 <<'PIN'
gh release upload "$TAG" "$WORK"/bundles/*.sigstore.json --clobber --repo "$GITHUB_REPOSITORY"
PIN
  want_step 0 <<'PIN'
{"name":"Refuse anything but a tag build","env":{"REF_TYPE":"${{ github.ref_type }}","REF_NAME":"${{ github.ref_name }}"}}
PIN
  want_step 1 <<'PIN'
{"uses":"actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683","with":{"fetch-depth":0,"persist-credentials":false,"path":"caller-src"}}
PIN
  want_step 2 <<'PIN'
{"name":"Refuse a tag that is not on main","working-directory":"caller-src","env":{"TAG_SHA":"${{ github.sha }}"}}
PIN
  want_step 3 <<'PIN'
{"uses":"actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093","with":{"name":"${{ inputs.artifact-name }}","path":"${{ runner.temp }}/sigstore-sign-${{ github.run_id }}-${{ github.run_attempt }}/sign"}}
PIN
  want_step 4 <<'PIN'
{"uses":"sigstore/cosign-installer@d58896d6a1865668819e1d91763c7751a165e159","with":{"cosign-release":"v2.5.3"}}
PIN
  want_step 5 <<'PIN'
{"name":"Sign every file, keyless","id":"out","working-directory":"${{ runner.temp }}/sigstore-sign-${{ github.run_id }}-${{ github.run_attempt }}/sign","env":{"TAG":"${{ github.ref_name }}","ARTIFACT_NAME":"${{ inputs.artifact-name }}","WORK":"${{ runner.temp }}/sigstore-sign-${{ github.run_id }}-${{ github.run_attempt }}"}}
PIN
  want_step 6 <<'PIN'
{"uses":"actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02","with":{"name":"sigstore-bundles-${{ github.ref_name }}","path":"${{ runner.temp }}/sigstore-sign-${{ github.run_id }}-${{ github.run_attempt }}/bundles/"}}
PIN
  want_step 7 <<'PIN'
{"name":"Attach the bundles to the release","if":"${{ inputs.upload-to-release }}","env":{"GH_TOKEN":"${{ github.token }}","TAG":"${{ github.ref_name }}","WORK":"${{ runner.temp }}/sigstore-sign-${{ github.run_id }}-${{ github.run_attempt }}"}}
PIN
  [ "$(q '.jobs.sign | has("env")')" = false ] || red "job carries env (the per-run WORK dir is set per step: the runner context is not allowed at job level)"
  [ "$(q '.on.workflow_call.inputs."upload-to-release".default')" = true ] || red "upload-to-release default drifted"
  # BEHAVIOUR (Q-GH91c): the two guard bodies are RUN the way Actions runs them — empty environment plus realistic
  # Actions variables, the production shell flags, a clone of a bare origin — and must pass/fail the same under every
  # job name, REF_NAME and GITHUB_ACTIONS value, so a body that detects a fixture or a job name cannot survive.
  g=$(q '.jobs.sign.steps[0].run'); a=$(q '.jobs.sign.steps[2].run'); k=$(printf '%s\0%s' "$g" "$a" | sha256sum)
  [ -n "${BEH_MEMO[$k]+x}" ] || BEH_MEMO[$k]=$(behav "$g" "$a")
  [ -z "${BEH_MEMO[$k]}" ] || { printf '%s\n' "${BEH_MEMO[$k]}"; bad=1; }
  # nothing may change HOW a step runs: no shell/defaults/container/job env, and env key sets are exact
  [ "$(q 'keys | sort | join(",")')" = jobs,name,on,permissions ] || red "top-level keys are not exactly name,on,permissions,jobs"
  [ "$(q '.jobs.sign | keys | sort | join(",")')" = name,outputs,permissions,runs-on,steps,timeout-minutes ] || red "job keys are not exactly name,outputs,permissions,runs-on,steps,timeout-minutes"
  [ "$(q '[.jobs.sign.steps[] | has("shell")] | any')" = false ] || red "a step sets shell"
  [ "$(q '[.jobs.sign.steps[] | has("container") or has("services")] | any')" = false ] || red "a step sets container/services"
  for i in 0 2 5 7; do
    case $i in 0) want=REF_NAME,REF_TYPE;; 2) want=TAG_SHA;; 5) want=ARTIFACT_NAME,TAG,WORK;; 7) want=GH_TOKEN,TAG,WORK;; esac
    [ "$(q ".jobs.sign.steps[$i].env | keys | sort | join(\",\")")" = "$want" ] || red "step $i env keys are not exactly $want"
  done
  for i in 1 3 4 6; do [ "$(q ".jobs.sign.steps[$i] | has(\"env\")")" = false ] || red "step $i carries env"; done
  r=$(q '.jobs.sign.steps[5].run' | grep -v '^ *#')
  printf '%s\n' "$r" | grep -qE '(^|[;&| ])exit 0' && red "signing step can exit 0 early"
  [ "$(printf '%s\n' "$r" | grep -cE '^ *id=')" = 1 ] && printf '%s\n' "$r" | grep -qE '^ *id=\$\(jq -r "\.verificationMaterial' || red "identity is not read from the certificate"
  printf '%s\n' "$r" | grep -qF "logIndex // empty" || red "Rekor index has a default"
  printf '%s\n' "$r" | grep -qF 'sha256sum -- "$f" >> "$WORK/manifest.txt"' || red "manifest is not computed from the files"
  [ "$(printf '%s\n' "$r" | grep -c 'cosign ')" = 1 ] || red "more than one cosign call in the signing step"
  # no guard or signing step may be skipped or soft-failed
  for i in 0 1 2 3 4 5; do
    [ "$(q ".jobs.sign.steps[$i] | has(\"if\")")" = false ] || red "step $i is conditional"
    [ "$(q ".jobs.sign.steps[$i].\"continue-on-error\" // false")" = false ] || red "step $i is continue-on-error"
  done
  [ "$(q '.jobs.sign."continue-on-error" // false')" = false ] || red "job is continue-on-error"
  [ "$(q '.jobs.sign | has("if")')" = false ] || red "job is conditional"
  # the sign step
  [ "$(q '.jobs.sign.steps[5].id')" = out ] || red "step 5 is not the signing step"
  [ "$(q '.jobs.sign.steps[5]."working-directory"')" = '${{ runner.temp }}/sigstore-sign-${{ github.run_id }}-${{ github.run_attempt }}/sign' ] || red "signing step is not in the downloaded dir"
  r=$(q '.jobs.sign.steps[5].run' | grep -v '^ *#')
  printf '%s\n' "$r" | head -1 | grep -qF 'set -euo pipefail' || red "signing step is not strict (set -euo pipefail first)"
  printf '%s\n' "$r" | grep -qE 'cosign sign-blob --yes --new-bundle-format --bundle "\$WORK/bundles/\$f\.sigstore\.json" -- "\$f" > /dev/null$' || red "sign-blob is not the new-bundle-format keyless call, un-masked"
  printf '%s\n' "$r" | grep -qE '\|\| *(true|:)|; *true *$|set \+e' && red "a failure is masked in the signing step"
  printf '%s\n' "$r" | grep -qF 'no Rekor log index' || red "signing step does not require a Rekor index"
  # nothing in the parsed document (comments are gone) may name a stored key or a secret
  yq -o=json '.' "$F" | grep -qiE 'secrets|--key|cosign_(private_)?key|signing_key|private.?key|\.pem|\.key\b' && red "a stored key or secret is named"
  # every action is a sha pin
  r=$(yq -r '.. | select(tag == "!!map") | select(has("uses")) | .uses' "$F" | awk '!/@[0-9a-f]{40}$/')
  [ -z "$r" ] || red "unpinned action: $r"
  # the bundles reach the caller, and the release only when asked
  [ "$(q '.jobs.sign.steps[6].uses | test("^actions/upload-artifact@[0-9a-f]{40}$")')" = true ] || red "step 6 is not the pinned bundle upload"
  [ "$(q '.jobs.sign.steps[6].with.name')" = 'sigstore-bundles-${{ github.ref_name }}' ] || red "bundle artifact name drifted from the bundle output"
  [ "$(q '.jobs.sign.steps[6].with.path')" = '${{ runner.temp }}/sigstore-sign-${{ github.run_id }}-${{ github.run_attempt }}/bundles/' ] || red "bundle upload path is not the per-run bundles dir"
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
  # Q-GH91b: mutants that a structural grep let through. "B" rows run WITHOUT the golden, so the rule and
  # behaviour checks must kill them on their own; every row is also RED with the golden.
  mutb() { n=$((n + 1)); sed "$2" "$F0" > "$t/m.yml"
    cmp -s "$F0" "$t/m.yml" && { echo "FAIL mutant did not apply: $1"; fail=1; return; }
    chk "$t/m.yml" nogolden > /dev/null 2>&1 && { echo "FAIL (behaviour/rules alone) mutant must be RED: $1"; fail=1; }
    chk "$t/m.yml" > /dev/null 2>&1 && { echo "FAIL (with golden) mutant must be RED: $1"; fail=1; }; return 0; }
  mutb "exit 0 before the tag guard"   's/^          if \[ "$REF_TYPE" != tag \]/          exit 0\n&/'
  mutb "REF_TYPE reassigned"           's/^          if \[ "$REF_TYPE" != tag \]/          REF_TYPE=tag\n&/'
  mutb "guard then exit 0; exit 1"     's/ exit 1; fi$/ exit 0; exit 1; fi/'
  mutb "guard disabled by true ||"     's/if \[ "$REF_TYPE" != tag \]/if true || [ "$REF_TYPE" != tag ]/'
  mutb "step shell true"               '/name: Refuse anything but a tag build/a\        shell: "true {0}"'
  mutb "defaults.run.shell"            's/^permissions: {}$/&\ndefaults:\n  run:\n    shell: "true {0}"/'
  mutb "BASH_ENV on the guard"         's/^          REF_NAME: ${{ github.ref_name }}/&\n          BASH_ENV: \/dev\/null/'
  mutb "ancestry exit 0 first"         's/^          set -euo pipefail\n          # checkout//;/Refuse a tag that is not on main/,/rev-parse --verify/s/^          set -euo pipefail/          exit 0\n          set -euo pipefail/'
  mutb "TAG_SHA reassigned"            '/Refuse a tag that is not on main/,/merge-base/s/^          set -euo pipefail/&\n          TAG_SHA=$(git rev-parse HEAD)/'
  mutb "git shadowed"                  '/Refuse a tag that is not on main/,/merge-base/s/^          set -euo pipefail/&\n          git() { return 0; }/'
  mutb "update-ref origin/main"        '/Refuse a tag that is not on main/,/merge-base/s/^          set -euo pipefail/&\n          git update-ref refs\/remotes\/origin\/main "$TAG_SHA"/'
  mutb "ancestry or-chain HEAD"        's/refs\/remotes\/origin\/main \\$/refs\/remotes\/origin\/main || git merge-base --is-ancestor "$TAG_SHA" HEAD \\/'
  mutb "sign step early exit 0"        '/Sign every file, keyless/,/mkdir -p/s/^          set -euo pipefail/&\n          exit 0/'
  mutb "typed identity"                's/^          \[ -n "$id" \] || .*/          id=https:\/\/github.com\/paiml\/.github\/.github\/workflows\/sigstore-sign.yml@refs\/heads\/main/'
  mutb "logIndex defaults to 0"        "s|logIndex // empty|logIndex // 0|"
  mutb "second keyed sign-blob"        's/^            sha256sum -- "$f" >> "$WORK\/manifest.txt"/&\n            cosign sign-blob -k k.pem --tlog-upload=false -- "$f" > \/dev\/null/'
  mutb "ninth step"                    '$a\      - run: "true"'
  mutb "attach step if false"          's/if: ${{ inputs.upload-to-release }}/if: false/'
  mutb "upload step continue-on-error" '/uses: actions\/upload-artifact@/i\        continue-on-error: true'
  mutb "SIGSTORE_ID_TOKEN env"         's/^          TAG: ${{ github.ref_name }}$/&\n          SIGSTORE_ID_TOKEN: x/'
  mutb "PATH env on sign"              's/^          ARTIFACT_NAME: .*/&\n          PATH: \/tmp/'
  # Q-GH91c: bypasses that detect the job name / Actions / a ref shape, bare exits, PATH games, free `with:` keys,
  # a stale-workspace reuse, and a step-7 retarget. All run without the golden: the literal pins and the realistic
  # behaviour run must kill them on their own.
  mutb "guard gated on GITHUB_JOB"     's/^          if \[ "$REF_TYPE" != tag \]/          [ "${GITHUB_JOB:-}" = sign ] \&\& exit 0\n&/'
  mutb "guard gated on GITHUB_ACTIONS" 's/^          if \[ "$REF_TYPE" != tag \]/          [ -z "${GITHUB_ACTIONS:-}" ] || REF_TYPE=tag\n&/'
  mutb "guard release/* case bypass"   's/^          if \[ "$REF_TYPE" != tag \]/          case "$REF_NAME" in release\/*) exit 0;; esac\n&/'
  mutb "guard bare exit"               's/^          if \[ "$REF_TYPE" != tag \]/          exit\n&/'
  mutb "guard exit quoted 0"           's/^          if \[ "$REF_TYPE" != tag \]/          exit "0"\n&/'
  mutb "guard exit arith 0"            's/^          if \[ "$REF_TYPE" != tag \]/          exit $((0))\n&/'
  mutb "ancestry export PATH"          '/Refuse a tag that is not on main/,/merge-base/s/^          set -euo pipefail/&\n          export PATH=\/tmp\/shadow:$PATH/'
  mutb "ancestry GITHUB_PATH write"    '/Refuse a tag that is not on main/,/merge-base/s/^          set -euo pipefail/&\n          echo \/tmp\/shadow >> "$GITHUB_PATH"/'
  mutb "ancestry exit on GITHUB_JOB"   '/Refuse a tag that is not on main/,/merge-base/s/^          set -euo pipefail/&\n          [ "${GITHUB_JOB:-}" = sign ] \&\& exit 0/'
  mutb "sign export SIGSTORE var"      '/Sign every file, keyless/,/mkdir/s/^          set -euo pipefail/&\n          export SIGSTORE_REKOR_URL=http:\/\/evil/'
  mutb "sign export COSIGN var"        '/Sign every file, keyless/,/mkdir/s/^          set -euo pipefail/&\n          export COSIGN_EXPERIMENTAL=0/'
  mutb "sign printf -v id"             's/^          \[ -n "$id" \] || .*/          printf -v id "%s" https:\/\/x/'
  mutb "sign typed echo identity"      's/^            echo "identity=$id"/            echo "identity=https:\/\/x"/'
  mutb "logIndex default 7"            "s|logIndex // empty|logIndex // empty // 7|"
  mutb "forced idx"                    's/^            \[ -n "$idx" \] || .*/            idx=1/'
  mutb "extra manifest line"           's/echo "EOF_SHA"$/echo "EOF_SHA"; echo "deadbeef  forged"/'
  mutb "zero files not refused"        's/^          \[ "$n" -ge 1 \] || .*/          true/'
  mutb "forged bundle path"            's/^          b=$(find .*/          b=\/tmp\/forged.json/'
  mutb "narrowed find"                 "s/find . -type f ! -name '\*.sigstore.json'/find . -maxdepth 1 -type f ! -name '*.sigstore.json'/"
  mutb "second cosign via shadow"      's/^          n=0$/          cosign() { command cosign "$@"; command cosign "$@"; }\n&/'
  mutb "stale workspace reused"        's/mkdir "$WORK\/bundles"/mkdir -p "$WORK\/bundles"/'
  mutb "GITHUB_ENV write earlier"      '/Refuse a tag that is not on main/,/merge-base/s/^          set -euo pipefail/&\n          echo "BASH_ENV=\/tmp\/x" >> "$GITHUB_ENV"/'
  mutb "download extra run-id"         '/uses: actions\/download-artifact@/,/path:/s/^          path: .*/&\n          run-id: 1/'
  mutb "download extra repository"     '/uses: actions\/download-artifact@/,/path:/s/^          path: .*/&\n          repository: evil\/fork\n          github-token: x/'
  mutb "checkout other repository"     '/uses: actions\/checkout@/,/path: caller-src/s/^          path: caller-src/&\n          repository: evil\/fork/'
  mutb "installer install-dir"         's/^          cosign-release: v2.5.3.*/&\n          install-dir: \/tmp\/cosign-bin/'
  mutb "upload extra with"             '/uses: actions\/upload-artifact@/,/path:/s/^          path: .*/&\n          retention-days: 90\n          overwrite: true/'
  mutb "attach retargeted repo"        's/--repo "$GITHUB_REPOSITORY"/--repo evil\/fork/'
  mutb "attach extra flag"             's/--clobber --repo/--clobber --draft --repo/'
  mutb "upload-to-release default off" "/^      upload-to-release:/,/^    outputs:/s/default: true/default: false/"
  mutb "job env added"                 's/^    timeout-minutes: 15/&\n    env:\n      BASH_ENV: \/tmp\/x/'
  mutb "WORK not per-run"              's|^          WORK: .*|          WORK: ${{ runner.temp }}/sigstore-sign|'
  mutb "tag output unwired"            's/^      tag: ${{ steps.out.outputs.tag }}/      tag: x/'
  [ "$fail" = 0 ] && echo "PASS check-sigstore-sign self-test: clean GREEN + $n mutants RED"; exit "$fail"
fi
chk "${1:-.github/workflows/sigstore-sign.yml}"
