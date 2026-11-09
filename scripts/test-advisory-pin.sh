#!/usr/bin/env bash
# Falsifier for the advisory-db pin (rmedia#2459 / fix-advisory-pin-1515Z).
# Same Cargo.lock, same step: the verdict must depend on the committed .advisory-db-rev,
# not on the live database. Real advisory: RUSTSEC-2026-0459 (libsqlite3-sys 0.30.1),
# added to RustSec/advisory-db by one commit; the pin one commit before it is green,
# the pin at it is red, no pin (live) is red, a malformed or unreachable pin is red.
# Env: ADVISORY_DB_ORIGIN = local clone of RustSec/advisory-db (default: clone from GitHub).
set -uo pipefail
cd "$(dirname "$0")/.." || exit 2
WF=.github/workflows/sovereign-ci.yml
T=$(mktemp -d) || exit 2
trap 'rm -rf "${T:?}"' EXIT
command -v cargo-audit >/dev/null || { echo "NOT RUN: cargo-audit missing"; exit 2; }

ORIGIN=${ADVISORY_DB_ORIGIN:-}
if [ -z "$ORIGIN" ]; then
  git clone -q https://github.com/RustSec/advisory-db "$T/origin" || { echo "NOT RUN: clone failed"; exit 2; }
  ORIGIN="$T/origin"
fi
ADD=$(git -C "$ORIGIN" log --diff-filter=A --format=%H -1 -- crates/libsqlite3-sys/RUSTSEC-2026-0459.md)
[ -n "$ADD" ] || { echo "NOT RUN: advisory commit not found"; exit 2; }
BEFORE=$(git -C "$ORIGIN" rev-parse "$ADD^")

# the Audit step's run block, 10-space indent stripped
awk '/^      - name: Audit$/{s=1;next} s&&/^      - name:|^      # Symmetry/{exit} s&&/^        run: \|/{r=1;next} r{sub(/^          /,"");print}' "$WF" > "$T/step.sh"
[ -s "$T/step.sh" ] || { echo "FAIL: could not extract the Audit step"; exit 2; }
grep -q 'advisory-pin begin' "$T/step.sh" || { echo "FAIL: pin block missing from the Audit step"; exit 1; }

mkdir -p "$T/ws" "$T/shim" "$T/home/.cargo"
cat > "$T/ws/Cargo.toml" <<'TOML'
[package]
name = "fixture"
version = "0.1.0"
edition = "2021"
TOML
cat > "$T/ws/Cargo.lock" <<'LOCK'
version = 3

[[package]]
name = "fixture"
version = "0.1.0"
dependencies = [
 "libsqlite3-sys",
]

[[package]]
name = "libsqlite3-sys"
version = "0.30.1"
source = "registry+https://github.com/rust-lang/crates.io-index"
LOCK
REAL=$(command -v git)
cat > "$T/shim/git" <<SHIM
#!/usr/bin/env bash
args=()
for a in "\$@"; do args+=("\${a/https:\/\/github.com\/RustSec\/advisory-db/file://$ORIGIN}"); done
exec "$REAL" "\${args[@]}"
SHIM
chmod +x "$T/shim/git"
git -C "$ORIGIN" config uploadpack.allowAnySHA1InWant true

run() { # $1 = pin file content, or @none for no pin file
  rm -f "${T:?}/ws/.advisory-db-rev"
  [ "$1" = "@none" ] || printf '%s\n' "$1" > "$T/ws/.advisory-db-rev"
  ( cd "$T/ws" && PATH="$T/shim:$PATH" GITHUB_WORKSPACE="$T/ws" GITHUB_TOKEN= SOV_ADVISORIES_DIFF_ONLY= bash "$T/step.sh" ) >"$T/out" 2>&1
}
rc=0
expect() { # $1 label, $2 green|red, $3 pin content, $4 regex the output must match (red: the reason, green: the pin line)
  local label=$1 want=$2 got
  if run "$3"; then got=green; else got=red; fi
  if [ "$got" = "$want" ] && grep -Eq -- "$4" "$T/out"; then echo "ok: $label -> $got"; else echo "FAIL: $label -> $got, want $want matching /$4/"; tail -n 8 "$T/out"; rc=1; fi
}
expect "pin one commit before RUSTSEC-2026-0459" green "$BEFORE" "advisory-db pinned at $BEFORE"
expect "pin at the commit that adds RUSTSEC-2026-0459" red "$ADD" "ID:[[:space:]]+RUSTSEC-2026-0459"
expect "no pin file (live database)" red "@none" "ID:[[:space:]]+RUSTSEC-2026-0459"
expect "malformed pin" red "not-a-sha" "is not a 40-hex commit"
expect "short pin" red "${BEFORE:0:12}" "is not a 40-hex commit"
expect "unreachable pin" red "0000000000000000000000000000000000000000" "(fatal|error).*(not our ref|couldn.t find remote ref|0000000)"

# the deny step carries the identical pin block, and only the deny and Audit steps carry it
awk -v d="$T" '/advisory-pin begin/{p=1;b++} p{print > (d "/b" b)} /advisory-pin end/{p=0} END{print b+0 > (d "/nblocks")}' "$WF"
if [ "$(cat "$T/nblocks")" = 2 ] && cmp -s "$T/b1" "$T/b2"; then echo "ok: deny and Audit pin blocks identical (2 blocks)"; else echo "FAIL: pin block must appear identically in exactly the deny and Audit steps"; rc=1; fi
exit $rc
