#!/usr/bin/env bash
# check_issue_flow.sh — FLOW rule 19: the flow ratchet.
#
# Per repo, over a 3-day trailing window: issues created <= issues closed.
# Inflow above outflow is the queue growing; Little's law says a stock cap
# alone cannot hold, so arrivals are metered against departures.
#
# Usage:
#   check_issue_flow.sh --created N --closed M          # pure verdict (case tables)
#   check_issue_flow.sh --repo OWNER/REPO [--days 3] [--today YYYY-MM-DD]
#                                                       # live counts via `gh api search/issues`
#
# Output: one line, "GREEN inflow created=N closed=M ..." or "RED inflow ...".
# Exit:   0 GREEN, 10 RED, 2 usage/tool error.
set -euo pipefail

created=""
closed=""
repo=""
days=3
today=""
while [ $# -gt 0 ]; do
  case "$1" in
    --created) created="${2:?}"; shift 2 ;;
    --closed) closed="${2:?}"; shift 2 ;;
    --repo) repo="${2:?}"; shift 2 ;;
    --days) days="${2:?}"; shift 2 ;;
    --today) today="${2:?}"; shift 2 ;;
    -h|--help) sed -n '2,14p' "$0"; exit 0 ;;
    *) echo "usage error: unknown argument $1" >&2; exit 2 ;;
  esac
done

is_count() { case "$1" in ''|*[!0-9]*) return 1 ;; *) return 0 ;; esac; }
if ! is_count "$days" || [ "$days" -lt 1 ]; then
  echo "usage error: --days must be a positive integer" >&2; exit 2
fi

window=""
if [ -n "$repo" ]; then
  [ -z "$created$closed" ] || { echo "usage error: --repo excludes --created/--closed" >&2; exit 2; }
  command -v gh >/dev/null || { echo "tool error: gh not found" >&2; exit 2; }
  # The window is anchored to the wall clock on purpose: this is a live flow
  # measurement, not a build artifact. --today pins it for replays.
  today="${today:-$(date -u +%F)}"  # bashrs disable-line=DET002
  # bashrs disable-next-line=DET002
  if ! since="$(date -u -d "$today - $((days - 1)) days" +%F)"; then
    echo "usage error: bad --today $today" >&2; exit 2
  fi
  count() {
    gh api -X GET search/issues -f q="repo:$repo is:issue $1:>=$since" --jq .total_count
  }
  # An API failure must not read as "0 created" — that would be a vacuous GREEN.
  created="$(count created)" || { echo "tool error: gh search (created) failed" >&2; exit 2; }
  closed="$(count closed)" || { echo "tool error: gh search (closed) failed" >&2; exit 2; }
  window=" window=${since}..${today} repo=$repo"
fi

is_count "$created" || { echo "usage error: created must be a count, got '${created}'" >&2; exit 2; }
is_count "$closed" || { echo "usage error: closed must be a count, got '${closed}'" >&2; exit 2; }

if [ "$created" -le "$closed" ]; then
  echo "GREEN inflow created=$created closed=$closed$window"
  exit 0
fi
echo "RED inflow created=$created > closed=$closed (+$((created - closed)))$window"
exit 10
