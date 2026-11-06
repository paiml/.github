#!/usr/bin/env bash
# flow_mode.sh — FLOW-001-A1 §2.8: guard promotion warn -> block, per check and
# per repo. Prints the mode ONE check runs in on ONE repo right now:
#   warn   a RED prints ::warning:: and the job stays green
#   alert  (cap only, before its tag) a RED raises an alert, never blocks
#   block  a RED fails the job
#
# The schedule is encoded HERE, once, for the fleet. What varies per repo is
# only WHEN each milestone happened; the consuming repo records those dates in
# docs/roadmaps/flow-guards.json (next to epics.yaml):
#   {
#     "a5_done":  "2026-09-27T12:00:00Z",           # that repo's A5 finished
#     "cap_tag":  "2026-10-02T00:00:00Z",           # its 0.71-tag equivalent (rule 6a)
#     "checks": {
#       "no-close":         {"first_green": "…", "last_violation": "…"},
#       "unmetered-intake": {"first_green": "…", "last_violation": "…"}
#     }
#   }
# A missing file, key or date means the milestone has NOT happened: the check
# stays in warn (alert for cap). Promotion is never inferred, only recorded.
#
# Schedule (§2.8):
#   unmetered-intake, no-close   block once 24 h have passed at 0 violations
#                                since first-green: now >= max(first_green,
#                                last_violation) + 24 h
#   orphan, milestone, priority  block once a5_done   ("P?" in the spec)
#   ratchet, inflow              block once a5_done
#   cap                          block once cap_tag; alert before
#   anything else                warn (not scheduled — the operator decides)
#
# Usage: flow_mode.sh --check NAME [--state FILE] [--now ISO8601]
# Exit:  0 with the mode on stdout; 2 usage/tool error (bad JSON, bad date).
set -euo pipefail

check=""
state=""
now=""
while [ $# -gt 0 ]; do
  case "$1" in
    --check) check="${2:?}"; shift 2 ;;
    --state) state="${2:?}"; shift 2 ;;
    --now) now="${2:?}"; shift 2 ;;
    -h|--help) sed -n '2,36p' "$0"; exit 0 ;;
    *) echo "usage error: unknown argument $1" >&2; exit 2 ;;
  esac
done
[ -n "$check" ] || { echo "usage error: --check is required" >&2; exit 2; }
command -v jq >/dev/null || { echo "tool error: jq not found" >&2; exit 2; }

epoch() { date -u -d "$1" +%s 2>/dev/null || { echo "usage error: bad date '$1'" >&2; exit 2; }; }
now_s="$(epoch "${now:-now}")"

get() {  # jq path -> value or empty; a malformed state file is an error, not "warn"
  [ -n "$state" ] && [ -f "$state" ] || return 0
  jq -er "$1 // empty" "$state" 2>/dev/null || {
    jq -e . "$state" >/dev/null 2>&1 || { echo "usage error: $state is not valid JSON" >&2; exit 2; }
  }
}
reached() {  # reached <iso-date-or-empty>; a bad date exits 2, never reads as "not yet"
  local t
  [ -n "$1" ] || return 1
  t="$(epoch "$1")" || exit 2
  [ "$now_s" -ge "$t" ]
}

default=warn
case "$check" in
  unmetered-intake|no-close)
    fg="$(get ".checks[\"$check\"].first_green")"
    lv="$(get ".checks[\"$check\"].last_violation")"
    if [ -n "$fg" ]; then
      clean_since="$(epoch "$fg")"
      if [ -n "$lv" ]; then
        lv_s="$(epoch "$lv")"
        if [ "$lv_s" -gt "$clean_since" ]; then clean_since="$lv_s"; fi
      fi
      if [ "$now_s" -ge $((clean_since + 86400)) ]; then echo block; exit 0; fi
    fi ;;
  orphan|milestone|priority|ratchet|inflow)
    a5="$(get .a5_done)"
    if reached "$a5"; then echo block; exit 0; fi ;;
  cap)
    default=alert
    tag="$(get .cap_tag)"
    if reached "$tag"; then echo block; exit 0; fi ;;
esac
echo "$default"
