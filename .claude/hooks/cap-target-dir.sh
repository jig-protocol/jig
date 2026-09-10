#!/usr/bin/env bash
# Keep repos/target under a size cap so parallel subagent builds cannot fill
# the disk. Wired to the SubagentStop and Stop hooks in .claude/settings.json.
#
# Why --maxsize and not a full clean: every subagent shares this one target
# dir (that sharing is what makes their builds cache hits instead of a
# ten-minute rebuild each), so the right move is to trim the OLDEST artifacts
# back under a cap, never to wipe what the main session is about to link
# against. A build in flight is left alone unless the disk is nearly full —
# a failed link at 100% is worse than a rebuild.
#
# Measured 2026-09-10: 50 review subagents building in the shared dir ate
# 11 GB in one workflow and stopped the session dead with ENOSPC.
set -u

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CAP="${JIG_TARGET_CAP:-40GB}"
MIN_FREE_GB="${JIG_MIN_FREE_GB:-15}"

[ -d "$ROOT/repos/target" ] || exit 0
command -v cargo-sweep >/dev/null 2>&1 || exit 0

free_gb=$(df -Pk "$ROOT" | awk 'NR==2 { print int($4 / 1048576) }')
if { pgrep -x cargo >/dev/null 2>&1 || pgrep -x rustc >/dev/null 2>&1; } \
   && [ "${free_gb:-0}" -ge "$MIN_FREE_GB" ]; then
  exit 0
fi

dry=""
[ -n "${JIG_TARGET_CAP_DRY_RUN:-}" ] && dry="--dry-run"
out=$(cargo sweep --maxsize "$CAP" $dry "$ROOT/repos" 2>&1) || exit 0
cleaned=$(printf '%s\n' "$out" | sed -n 's/.*\(Cleaned\|Would clean:\) \([0-9.]* [KMG]iB\).*/\2/p' | tail -1)
case "$cleaned" in
  ""|"0 B"|"0.00 B") ;;
  *) printf '{"systemMessage": "cap-target-dir: swept %s from repos/target (cap %s, %s GB free)"}\n' "$cleaned" "$CAP" "$free_gb" ;;
esac
exit 0
