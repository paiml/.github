#!/usr/bin/env bash
# check_pr_closes.sh — FLOW rule 18: every merged PR discharges its issue.
#
# A PR body must carry ONE of:
#   - a GitHub closing keyword on an issue:  Closes #N / Fixes owner/repo#N / Resolves #N …
#   - a collapse-progress line (rule 20):    Refs #N row <row-id>
#   - an explicit trailer, with a reason:    no-issue: <reason>
# A bare "Refs #N" is NOT enough (FALSIFY-FLOW-012). This removes the
# "done on main, still open" class — a PR that lands without closing anything.
#
# HTML comments and fenced code blocks are stripped first: a PR template's
# "<!-- Closes #123 -->" placeholder must not satisfy the rule.
#
# Usage:
#   check_pr_closes.sh [--states FILE | --repo OWNER/REPO] [BODY_FILE]
#     BODY_FILE   PR body; read from stdin when omitted.
#     --states    TSV "ref<TAB>OPEN|CLOSED" (ref = N or owner/repo#N); test fixture.
#     --repo      resolve each referenced issue's state live with `gh`.
#   With neither, the open-state check is NOT MEASURED (printed, never a pass).
#
# Output: one line, "GREEN <why>" or "RED <code> <detail>".
# Exit:   0 GREEN, 10 RED, 2 usage/tool error. RED is >= 10 so an alarm can
#         never be mistaken for a crash (a crash is 1 or 2).
set -euo pipefail

states=""
repo=""
body_file=""
while [ $# -gt 0 ]; do
  case "$1" in
    --states) states="${2:?--states needs a file}"; shift 2 ;;
    --repo) repo="${2:?--repo needs OWNER/REPO}"; shift 2 ;;
    -h|--help) sed -n '2,24p' "$0"; exit 0 ;;
    -*) echo "usage error: unknown flag $1" >&2; exit 2 ;;
    *) body_file="$1"; shift ;;
  esac
done

if [ -n "$body_file" ]; then
  [ -r "$body_file" ] || { echo "usage error: cannot read $body_file" >&2; exit 2; }
  # The caller chooses the path (CI writes the PR body to a temp file); reading
  # it is the whole job, so there is no traversal boundary to defend here.
  raw="$(cat -- "$body_file")"  # bashrs disable-line=SEC010
else
  raw="$(cat)"
fi

command -v perl >/dev/null || { echo "tool error: perl not found" >&2; exit 2; }
# Strip HTML comments (possibly multi-line), then fenced code blocks, then CRs.
body="$(printf '%s\n' "$raw" \
  | perl -0pe 's/<!--.*?-->//gs' \
  | awk '/^[[:space:]]*(```|~~~)/{f=!f; next} !f' \
  | tr -d '\r')"

# 1. no-issue trailer with a non-empty reason.
if printf '%s\n' "$body" | grep -qiE '^[[:space:]]*no-issue:[[:space:]]*[^[:space:]]'; then
  echo "GREEN no-issue trailer"
  exit 0
fi

# 2. Collapse-progress line (rule 20): "Refs #N row <id>".
if printf '%s\n' "$body" | grep -qiE '(^|[^[:alnum:]_])refs?:?[[:space:]]+([[:alnum:]_.-]+/[[:alnum:]_.-]+)?#[0-9]+[[:space:]]+row[[:space:]]+[[:alnum:]_.-]+'; then
  echo "GREEN refs-row (rule 20 collapse progress)"
  exit 0
fi

# 3. Closing keywords, exactly GitHub's set.
refs="$(printf '%s\n' "$body" \
  | grep -oiE '(^|[^[:alnum:]_])(close[sd]?|fix(e[sd])?|resolve[sd]?):?[[:space:]]+([[:alnum:]_.-]+/[[:alnum:]_.-]+)?#[0-9]+' \
  | grep -oE '([[:alnum:]_.-]+/[[:alnum:]_.-]+)?#[0-9]+$' \
  | sed -E 's/^#//' | sort -u || true)"

if [ -z "$refs" ]; then
  if printf '%s\n' "$body" | grep -qiE '(^|[^[:alnum:]_])refs?:?[[:space:]]+#[0-9]+'; then
    echo "RED no-close only Refs #N — add Closes #N, 'Refs #N row <id>', or 'no-issue: <reason>'"
  else
    echo "RED no-close no Closes/Fixes #N and no 'no-issue: <reason>' trailer"
  fi
  exit 10
fi

# 4. At least one referenced issue must still be OPEN (closing a closed issue
#    discharges nothing).
state_of() {
  local ref="$1" n target
  if [ -n "$states" ]; then
    awk -F'\t' -v r="$ref" '$1==r{print $2; found=1} END{if(!found) print "UNKNOWN"}' "$states"
    return
  fi
  n="${ref##*#}"; target="$repo"
  case "$ref" in */*#*) target="${ref%%#*}" ;; esac
  gh issue view "$n" --repo "$target" --json state --jq .state 2>/dev/null || echo "UNKNOWN"
}

if [ -z "$states" ] && [ -z "$repo" ]; then
  echo "GREEN closes $(echo "$refs" | tr '\n' ' ')(open-state NOT MEASURED)"
  exit 0
fi

for ref in $refs; do
  if [ "$(state_of "$ref")" = "OPEN" ]; then
    echo "GREEN closes open issue $ref"
    exit 0
  fi
done
echo "RED closes-nothing-open every referenced issue is closed or unknown: $(echo "$refs" | tr '\n' ' ')"
exit 10
