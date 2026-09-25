#!/usr/bin/env bash
# check_findings_ledger.sh — FLOW rule 17: findings are not issues.
#
# A session that surfaces a defect appends ONE JSON line to
# docs/findings/<session>.jsonl instead of opening an issue. This guard holds
# the ledger to its contract (contracts/flow-findings-ledger-v1.yaml):
#   - every non-empty line is a JSON object with the seven required string
#     fields, none empty: id, title, evidence, repro, suspected_epic,
#     severity, found_at_sha (a 7..40 hex git sha);           RED findings-schema
#   - ids are unique across the whole ledger;                  RED findings-dup-id
#   - with --base REF: every ledger file present at REF is a byte prefix of
#     its current content (append-only; no edit, no delete).   RED findings-rewrite
#
# Usage: check_findings_ledger.sh [--root DIR] [--base GIT_REF]
# Output: one line, "GREEN …", "SKIP no-ledger …" or "RED <code> <detail>".
# Exit:   0 GREEN/SKIP, 10 RED, 2 usage/tool error.
set -euo pipefail

root="."
base=""
while [ $# -gt 0 ]; do
  case "$1" in
    --root) root="${2:?}"; shift 2 ;;
    --base) base="${2:?}"; shift 2 ;;
    -h|--help) sed -n '2,17p' "$0"; exit 0 ;;
    *) echo "usage error: unknown argument $1" >&2; exit 2 ;;
  esac
done
command -v jq >/dev/null || { echo "tool error: jq not found" >&2; exit 2; }

dir="$root/docs/findings"

# Append-only check first: a deleted ledger file is a rewrite even when the
# directory is now empty or gone.
if [ -n "$base" ]; then
  git -C "$root" rev-parse --verify --quiet "$base^{commit}" >/dev/null \
    || { echo "usage error: --base $base is not a commit in $root" >&2; exit 2; }
  while IFS= read -r -d '' path; do
    [ -n "$path" ] || continue
    if [ ! -f "$root/$path" ]; then
      echo "RED findings-rewrite $path existed at $base and was deleted"
      exit 10
    fi
    blen="$(git -C "$root" cat-file -s "$base:$path")"
    if ! cmp -s <(git -C "$root" show "$base:$path") <(head -c "$blen" "$root/$path"); then
      echo "RED findings-rewrite $path: content at $base is not a prefix of the current file"
      exit 10
    fi
  # Same scope as the schema scan below (docs/findings/*.jsonl, top level
  # only); -z so a path with spaces or non-ASCII is not quoted.
  done < <(git -C "$root" ls-tree -z --name-only "$base" -- docs/findings/ | grep -zE '^docs/findings/[^/]*\.jsonl$' || true)
fi

shopt -s nullglob
files=("$dir"/*.jsonl)
if [ "${#files[@]}" -eq 0 ]; then
  echo "SKIP no-ledger $dir has no *.jsonl (0 findings; nothing measured)"
  exit 0
fi

schema='
  def req: ["id","title","evidence","repro","suspected_epic","severity","found_at_sha"];
  if type != "object" then "not a JSON object"
  else
    ([req[] as $k | select((.[$k] | type) != "string" or (.[$k] | length) == 0) | $k]) as $bad
    | if ($bad | length) > 0 then "missing/empty/non-string: " + ($bad | join(","))
      elif (.found_at_sha | test("^[0-9a-f]{7,40}$") | not) then "found_at_sha is not a hex sha"
      else "ok" end
  end'

n=0
ids="$(mktemp)"
trap 'rm -f "$ids"' EXIT
for f in "${files[@]}"; do
  lineno=0
  while IFS= read -r line || [ -n "$line" ]; do
    lineno=$((lineno + 1))
    [ -n "${line//[[:space:]]/}" ] || continue
    verdict="$(printf '%s' "$line" | jq -r "$schema" 2>/dev/null)" || verdict="invalid JSON"
    if [ "$verdict" != "ok" ]; then
      echo "RED findings-schema ${f#"$root"/}:$lineno $verdict"
      exit 10
    fi
    printf '%s\t%s:%s\n' "$(printf '%s' "$line" | jq -r .id)" "${f#"$root"/}" "$lineno" >> "$ids"
    n=$((n + 1))
  done < "$f"
done

dup="$(cut -f1 "$ids" | sort | uniq -d | sed -n 1p)"
if [ -n "$dup" ]; then
  echo "RED findings-dup-id id '$dup' at $(awk -F'\t' -v d="$dup" '$1==d{printf "%s ",$2}' "$ids")"
  exit 10
fi
echo "GREEN findings $n line(s) in ${#files[@]} file(s)${base:+, append-only vs $base}"
