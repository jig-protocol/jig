#!/usr/bin/env bash
# operator-drill.sh STEP [ARG]
#
# The operator procedures in deploy/README.md, run as written on a machine
# with systemd as PID 1, as root. scripts/drills/run-drills.sh runs it in
# throwaway systemd containers; it changes /etc, /opt/jig, /var/lib/jig and
# the systemd credential store, so never run it on a machine you care about.
#
# Steps:
#   install BIN_DIR   "Install": the jig user, binaries, configs and units from
#                     deploy/, with only the placeholders filled in (loopback
#                     for the tailnet address, a test suffix). Both keys sealed
#                     with deploy/setup-server-key.sh: a systemd credential and
#                     an offline passphrase ($DRILL_PASSPHRASE).
#   start             `systemctl enable --now` the units, then "Verify the
#                     deploy": every row of its table.
#   mdwe              jig-nameserver runs under MemoryDenyWriteExecute=yes, as
#                     shipped. jig-server under it fails to start, which is why
#                     its unit leaves it off; the drill checks both, so neither
#                     the setting nor the comment can drift.
#   client-setup      A user: identity, `jig server set`, a channel, messages.
#   client-check      The same user reads them back, with the pins it has.
#   backup OUT        jig-backup.service, then the newest snapshot copied to OUT.
#   wipe              Make this a fresh machine: units, configs, binaries, state,
#                     the credential store and systemd's host credential key,
#                     and the jig user, all gone. Keeps /root.
#   restore SNAP      "Restore" onto a fresh machine (after wipe and install):
#                     the snapshot's databases and keys, and this machine's new
#                     credential added as a slot with the offline passphrase.
#   dids              Print the server's and the nameserver's DIDs.
#
# The source tree is read from $DRILL_SRC (default: this script's repo).
#
# DRILL_SLOTS=passphrase seals the keys with the passphrase alone
# (setup-server-key.sh --passphrase-only), handed to the units in their
# EnvironmentFile: for a machine whose systemd cannot load credentials, such
# as a container nested in another sandbox. The default, credential, is the
# path the README recommends.
set -euo pipefail

SRC="${DRILL_SRC:-$(cd "$(dirname "$0")/../.." && pwd)}"
SUFFIX=drill.example.org
SERVER=https://127.0.0.1:7117
NS=https://127.0.0.1:7070
CLIENT_HOME=/root/drill-client
SLOTS="${DRILL_SLOTS:-credential}"
: "${DRILL_PASSPHRASE:?set DRILL_PASSPHRASE: the offline passphrase both keys are sealed with}"

log() { printf '\n== %s\n' "$*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }

wait_for() { # URL
  for _ in $(seq 1 100); do
    curl -fsk --connect-timeout 1 --max-time 2 -o /dev/null "$1" && return 0
    sleep 0.2
  done
  return 1
}

did_at() { # URL of a well-known document
  curl -fsSk "$1" | python3 -c 'import json,sys; print(json.load(sys.stdin)["server_did"])'
}

client() {
  env HOME="$CLIENT_HOME" JIG_HOME="$CLIENT_HOME/.jig" JIG_KEYCHAIN=none \
    JIG_KEY_UNLOCK=env:DRILL_CLIENT_KEY RUST_BACKTRACE=0 /opt/jig/bin/jig "$@"
}

step_install() {
  local bin="${1:?install BIN_DIR}"
  log "install (deploy/README.md, Install)"
  id jig >/dev/null 2>&1 || useradd --system --home-dir /var/lib/jig --shell /usr/sbin/nologin jig
  install -d -o jig -g jig -m 0750 /var/lib/jig /var/backups/jig
  install -d -m 0755 /etc/jig /opt/jig/bin
  install -m 0755 "$bin/jig-server" "$bin/jig-nameserver" "$bin/jig" /opt/jig/bin/
  install -m 0755 "$SRC/deploy/jig-backup.sh" /opt/jig/bin/
  # The placeholders, and nothing else.
  sed 's/100\.x\.y\.z/127.0.0.1/g' "$SRC/deploy/config.example.toml" > /etc/jig/config.toml
  sed "s/names\.example\.org/$SUFFIX/" "$SRC/deploy/jig-nameserver.example.toml" > /etc/jig/jig-nameserver.toml
  chmod 0644 /etc/jig/config.toml /etc/jig/jig-nameserver.toml
  install -m 0644 "$SRC/deploy/jig-server.service" "$SRC/deploy/jig-backup.service" \
    "$SRC/deploy/jig-backup.timer" /etc/systemd/system/
  sed 's/REPLACE_WITH_TAILNET_IPV4/127.0.0.1/' "$SRC/deploy/jig-nameserver.service" \
    > /etc/systemd/system/jig-nameserver.service
  systemctl daemon-reload

  seal_keys
}

# deploy/setup-server-key.sh for both keys: it makes a key where there is
# none, and adds this machine's slot to one restored from a backup.
seal_keys() {
  log "seal both keys (deploy/setup-server-key.sh, $SLOTS)"
  local args=()
  if [ "$SLOTS" = passphrase ]; then
    # EnvironmentFile= unquotes and trims a value: refuse what it would change.
    case "$DRILL_PASSPHRASE" in
      *\\* | *\"* | *\'* | [[:space:]]* | *[[:space:]]) fail "DRILL_PASSPHRASE: no quotes, backslashes or edge whitespace in passphrase mode" ;;
    esac
    args=(--passphrase-only)
    for env in /etc/jig/jig-server.env /etc/jig/jig-nameserver.env; do
      install -m 0600 /dev/null "$env"
      printf 'JIG_KEY_PASSPHRASE=%s\n' "$DRILL_PASSPHRASE" > "$env"
    done
  fi
  JIG_KEY_PASSPHRASE="$DRILL_PASSPHRASE" "$SRC/deploy/setup-server-key.sh" "${args[@]}"
  JIG_KEY_PASSPHRASE="$DRILL_PASSPHRASE" "$SRC/deploy/setup-server-key.sh" --nameserver "${args[@]}"
}

step_start() {
  log "start"
  systemctl enable --now jig-server jig-nameserver jig-backup.timer
  wait_for "$SERVER/healthz" || { journalctl -u jig-server --no-pager | tail -30; fail "jig-server /healthz"; }
  wait_for "$NS/v1/health" || { journalctl -u jig-nameserver --no-pager | tail -30; fail "jig-nameserver /v1/health"; }

  log "verify the deploy (deploy/README.md, Verify the deploy)"
  [ "$(curl -fsSk "$SERVER/healthz")" = ok ] || fail "/healthz is not ok"
  curl -fsSk "$SERVER/.well-known/jig" | python3 -c '
import json, sys
d = json.load(sys.stdin)
for k in ("server_did", "tls_binding"):
    assert k in d, k
# jig-server leaves the key out when nothing unsafe is on.
assert "unsafe_options_active" not in d, d["unsafe_options_active"]' || fail "/.well-known/jig"
  local metrics
  metrics="$(curl -fsSk --max-time 10 "$SERVER/metrics")" || fail "/metrics"
  grep -q '^# TYPE' <<<"$metrics" || fail "/metrics is not Prometheus text"
  [ "$(curl -sk -o /dev/null -w '%{http_code}' "$SERVER/api/v1/channels")" = 401 ] \
    || fail "an unsigned channel list is not refused with 401"
  curl -fsSk "$NS/v1/health" | grep -q '"ok"' || fail "nameserver /v1/health"
  curl -fsSk "$NS/.well-known/jig-ns" | python3 -c '
import json, sys
d = json.load(sys.stdin)
for k in ("server_did", "tls_binding"):
    assert k in d, k
# jig-nameserver always sends it: [] when nothing unsafe is on.
assert d["unsafe_options_active"] == [], d["unsafe_options_active"]' || fail "/.well-known/jig-ns"
  curl -fsSk "$NS/v1/challenge" | grep -Eq '"challenge":"[0-9a-f]{64}"' || fail "nameserver /v1/challenge"
  systemctl is-active --quiet jig-server jig-nameserver || fail "a unit is not active"
  echo "every row of the table checks"
}

step_mdwe() {
  log "MemoryDenyWriteExecute"
  [ "$(systemctl show -p MemoryDenyWriteExecute --value jig-nameserver)" = yes ] \
    || fail "jig-nameserver.service does not set MemoryDenyWriteExecute=yes"
  systemctl is-active --quiet jig-nameserver || fail "jig-nameserver is not running under it"
  echo "jig-nameserver: runs under MemoryDenyWriteExecute=yes"

  [ "$(systemctl show -p MemoryDenyWriteExecute --value jig-server)" = no ] \
    || fail "jig-server.service now sets MemoryDenyWriteExecute: check that blocks still run under it"
  # The unit says jig-server cannot start under it (wasmtime's JIT maps W then
  # X). Check the claim with a drop-in, then take the drop-in away.
  install -d /etc/systemd/system/jig-server.service.d
  printf '[Service]\nMemoryDenyWriteExecute=yes\n' > /etc/systemd/system/jig-server.service.d/zz-drill-mdwe.conf
  systemctl daemon-reload
  local since
  since="$(date '+%Y-%m-%d %H:%M:%S')"
  systemctl restart jig-server || true
  # Until it serves, or the journal says why it cannot: journald may write
  # the line a moment after the process exits.
  local up=0 denied=0
  for _ in $(seq 1 50); do
    if curl -fsk --connect-timeout 1 --max-time 2 -o /dev/null "$SERVER/healthz"; then up=1; break; fi
    if journalctl -u jig-server --since "$since" --no-pager | grep -q "unable to make memory executable"; then
      denied=1
      break
    fi
    sleep 0.2
  done
  rm /etc/systemd/system/jig-server.service.d/zz-drill-mdwe.conf
  systemctl daemon-reload
  systemctl reset-failed jig-server 2>/dev/null || true
  systemctl restart jig-server
  wait_for "$SERVER/healthz" || fail "jig-server did not come back without the drop-in"
  if [ "$up" = 1 ]; then
    fail "jig-server served under MemoryDenyWriteExecute=yes: its unit's reason for leaving it off is stale"
  fi
  # For the reason the unit gives, not some other failure.
  [ "$denied" = 1 ] || fail "jig-server failed under MemoryDenyWriteExecute=yes, but not because the JIT was denied"
  echo "jig-server: fails under MemoryDenyWriteExecute=yes, as its unit says; back up without it"
}

step_client_setup() {
  log "a user: identity, server, channel, messages"
  mkdir -p "$CLIENT_HOME"
  client init drill-user >/dev/null
  client server set "$SERVER" >/dev/null
  client channel create '#drill' >/dev/null
  client channel create '#drill-sealed' --encrypted >/dev/null
  client send --channel '#drill' "before the backup" >/dev/null
  client send --channel '#drill-sealed' "sealed before the backup" >/dev/null
  client read '#drill' | grep -q "before the backup" || fail "the user cannot read #drill"
}

step_client_check() {
  log "the user reads it back, with the pins it has"
  local out=/tmp/drill-read.out
  for pair in '#drill|before the backup' '#drill-sealed|sealed before the backup'; do
    client read "${pair%%|*}" > "$out" 2>&1 || { cat "$out" >&2; fail "the user cannot read ${pair%%|*}"; }
    grep -qF "${pair#*|}" "$out" || { cat "$out" >&2; fail "${pair%%|*} lost \"${pair#*|}\""; }
  done
  client send --channel '#drill-sealed' "sealed after" >/dev/null || fail "the user cannot post"
  client read '#drill-sealed' | grep -q "sealed after" || fail "the user cannot read what it posted"
  echo "messages and an encrypted channel read back; posting works"
}

step_backup() {
  local out="${1:?backup OUT}"
  log "backup (jig-backup.service)"
  systemctl start jig-backup.service || { journalctl -u jig-backup --no-pager | tail -20; fail "jig-backup.service"; }
  local snap
  snap="$(find /var/backups/jig -mindepth 1 -maxdepth 1 -type d | sort | tail -1)"
  [ -n "$snap" ] || fail "no snapshot in /var/backups/jig"
  for f in jig_v002.db nameserver_v002.db server.jigkey nameserver_v002.jigkey MANIFEST.txt; do
    [ -f "$snap/$f" ] || fail "the snapshot has no $f"
  done
  (cd "$snap" && sha256sum -c --quiet MANIFEST.txt) || fail "the snapshot does not match its MANIFEST"
  mkdir -p "$out"
  cp -a "$snap/." "$out/"
  echo "snapshot $(basename "$snap")"
}

step_restore() {
  local snap="${1:?restore SNAPSHOT}"
  log "restore onto this machine (deploy/README.md, Restore)"
  systemctl stop jig-server jig-nameserver
  cp "$snap/jig_v002.db" "$snap/nameserver_v002.db" /var/lib/jig/
  cp "$snap/server.jigkey" /var/lib/jig/server.jigkey
  cp "$snap/nameserver_v002.jigkey" /var/lib/jig/nameserver_v002.jigkey
  chown -R jig:jig /var/lib/jig
  chmod 600 /var/lib/jig/*.jigkey
  # Another machine: its own credential, added as a slot with the passphrase.
  seal_keys
  systemctl start jig-server jig-nameserver
  wait_for "$SERVER/healthz" || { journalctl -u jig-server --no-pager | tail -30; fail "restored jig-server"; }
  wait_for "$NS/v1/health" || { journalctl -u jig-nameserver --no-pager | tail -30; fail "restored jig-nameserver"; }
}

step_wipe() {
  log "wipe: this is a fresh machine now"
  systemctl disable --now jig-server jig-nameserver jig-backup.timer 2>/dev/null || true
  rm -rf /etc/systemd/system/jig-server.service* /etc/systemd/system/jig-nameserver.service* \
    /etc/systemd/system/jig-backup.* /etc/jig /opt/jig /var/lib/jig /var/backups/jig \
    /etc/credstore.encrypted /var/lib/systemd/credential.secret
  systemctl daemon-reload
  systemctl reset-failed 2>/dev/null || true
  id jig >/dev/null 2>&1 && userdel jig
  echo "removed: units, /etc/jig, /opt/jig, /var/lib/jig, backups, credentials, the host credential key, the jig user"
}

step_dids() {
  echo "server $(did_at "$SERVER/.well-known/jig")"
  echo "nameserver $(did_at "$NS/.well-known/jig-ns")"
}

[ "$(id -u)" = 0 ] || fail "run as root"
step="${1:?usage: $0 install BIN_DIR|start|mdwe|client-setup|client-check|backup OUT|wipe|restore SNAP|dids}"
shift
case "$step" in
  install) step_install "$@" ;;
  start) step_start ;;
  mdwe) step_mdwe ;;
  client-setup) step_client_setup ;;
  client-check) step_client_check ;;
  backup) step_backup "$@" ;;
  restore) step_restore "$@" ;;
  wipe) step_wipe ;;
  dids) step_dids ;;
  *) fail "unknown step $step" ;;
esac
