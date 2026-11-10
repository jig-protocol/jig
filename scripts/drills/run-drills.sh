#!/usr/bin/env bash
# run-drills.sh BIN_DIR
#
# The operator drills, in order, on this machine (systemd as PID 1, run as
# root): install from deploy/ and seal both keys, verify the deploy, check
# MemoryDenyWriteExecute on both units, give a user a channel and messages,
# back up with jig-backup.service, make this a fresh machine (everything
# machine-local gone, the host credential key included), install again,
# restore the snapshot, and check that the server and nameserver DIDs are the
# ones the user pinned, and that the user reads everything back without
# re-pinning. operator-drill.sh has each step.
#
# DESTRUCTIVE: it installs into and then wipes /etc/jig, /opt/jig,
# /var/lib/jig and the systemd credential store. For a CI runner or a
# throwaway container only.
#
# BIN_DIR holds release builds of jig, jig-server and jig-nameserver.
# DRILL_SLOTS is passed on (see operator-drill.sh).
set -euo pipefail

bin="$(cd "${1:?usage: $0 BIN_DIR}" && pwd)"
drill="$(cd "$(dirname "$0")" && pwd)/operator-drill.sh"
work="$(mktemp -d /root/drill.XXXXXX)"

DRILL_PASSPHRASE="$(od -An -tx1 -N24 /dev/urandom | tr -d ' \n')"
DRILL_CLIENT_KEY="$(od -An -tx1 -N32 /dev/urandom | tr -d ' \n')"
export DRILL_PASSPHRASE DRILL_CLIENT_KEY

summary() {
  echo "- $*"
  if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then echo "- $*" >> "$GITHUB_STEP_SUMMARY"; fi
}

"$drill" install "$bin"
"$drill" start
summary "installed from deploy/ as the README says; every row of \"Verify the deploy\" checks"
"$drill" mdwe
summary "jig-nameserver runs under MemoryDenyWriteExecute=yes; jig-server fails under it, as its unit says"
"$drill" client-setup
"$drill" dids > "$work/dids.before"
"$drill" backup "$work/snapshot"
summary "jig-backup.service: a snapshot that matches its MANIFEST"

"$drill" wipe
"$drill" install "$bin"
"$drill" restore "$work/snapshot"
"$drill" dids > "$work/dids.after"
if ! diff -u "$work/dids.before" "$work/dids.after"; then
  echo "FAIL: the restored server or nameserver has another DID" >&2
  exit 1
fi
"$drill" client-check
summary "restored onto a fresh machine: same server and nameserver DIDs, and the user reads everything back with the pins it had"
echo "PASS"
