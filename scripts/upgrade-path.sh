#!/usr/bin/env bash
# upgrade-path.sh STEP...
#
# Installs each STEP in turn over one set of state, the way a user upgrades:
# re-running install.sh over an existing ~/.jig. Before the first upgrade it
# creates the state a beta user has:
#
#   - three identities: alice (the installer's), bob and carol;
#   - an open channel, a restricted one and an encrypted open one (MLS), a DM;
#   - messages in each, from alice and from bob;
#   - jig-server's key (written by install.sh) and a nameserver with its own
#     key, where carol holds an alias.
#
# After every step it checks that all of it is still there and still works:
# the same DIDs, every message so far readable (and decryptable) by every
# reader, every channel listed, carol's alias still resolving to her DID and
# vouched for by the same nameserver DID. Each step adds its own messages and
# an encrypted channel of its own, so later steps read what earlier releases
# wrote. After the last step jig-server rotates its key, and every client,
# pinned on the old DID, must follow the key link and keep working.
#
# STEP is one of:
#   vX.Y.Z...       a published release: install.sh and the tarball from its
#                   GitHub Release, verified against the release key
#                   (.github/release/allowed_signers).
#   mirror=URL      a local mirror laid out like a release (install.sh,
#                   SHA256SUMS, SHA256SUMS.sig, jig-<os>-<arch>.tar.gz), signed
#                   by $JIG_UPGRADE_MIRROR_SIGNER (an allowed_signers line).
#
# Upgrades the way the docs describe: jig-server is stopped before install.sh
# runs again, and a nameserver whose key an older release wrote unencrypted is
# sealed with `jig-nameserver keys seal` (deploy/README.md, "Sealing the server
# key"). install.sh itself is checked against the step's signed SHA256SUMS
# before it runs. Upgrade paths known not to work are checked on every run and
# reported as known gaps (see KNOWN GAPS below). A known gap of this build
# that stops reproducing fails the run, so the list cannot go stale.
#
# Env: JIG_REPO (default jig-protocol/jig), JIG_VERIFY_SIGNATURE (passed on),
# JIG_UPGRADE_KNOWN_GAPS (overrides the list below), JIG_UPGRADE_KEEP=1 keeps
# the sandbox. Writes a summary to $GITHUB_STEP_SUMMARY when set.
set -euo pipefail

[ "$#" -ge 2 ] || { echo "usage: $0 STEP STEP... (at least one upgrade)" >&2; exit 2; }

JIG_REPO="${JIG_REPO:-jig-protocol/jig}"

# KNOWN GAPS of this build: the mirror step and the key rotation after the
# last step. Each must reproduce on every run, or the run fails: a gap that
# was fixed is dropped from the list here, and from then on fails if it comes
# back. See `gap` below.
#   install-reuses-old-server: re-running install.sh while jig-server runs
#     replaces the binaries but leaves the old server process answering, so the
#     new client talks to the old server (alpha.1 → alpha.2: "malformed
#     handshake frame", and a hint to `jig server forget`). Fixed by #334.
KNOWN_GAPS="${JIG_UPGRADE_KNOWN_GAPS-install-reuses-old-server}"
# Gaps a published release has, and always will: expected on a release step
# and reported there, but never counted for KNOWN_GAPS, since a step that
# cannot change cannot show that a gap is still there.
#   install-reuses-old-server: above.
#   rotate-locks-out-clients: after `jig-server keys rotate`, clients follow the
#     key link but then refuse #jig/manifest, which the server re-created under
#     its new DID ("is not the channel this device pinned"). Fixed by #335, so
#     it fails the run when the last step is this build.
RELEASED_GAPS="install-reuses-old-server rotate-locks-out-clients"
ALLOWED_SIGNERS="$(cd "$(dirname "$0")/.." && pwd)/.github/release/allowed_signers"

SUFFIX=upgrade.jig
sandbox="$(mktemp -d "${TMPDIR:-/tmp}/jig-upgrade.XXXXXX")"
server_port=$(( 20000 + RANDOM % 20000 ))
ns_port=$(( server_port + 1 ))
ns_dir="$sandbox/ns"
ledger="$sandbox/ledger.tsv"
summary="$sandbox/summary.md"
seen_gaps=" "
mkdir -p "$ns_dir"
: > "$ledger"
: > "$summary"

# Secrets that open each identity's key and the nameserver's. Releases before
# sealed keys ignore them; later ones seal the old unencrypted keys with them.
rand_hex() { od -An -tx1 -N32 /dev/urandom | tr -d ' \n'; }
UPGRADE_KEY_ALICE="$(rand_hex)"
UPGRADE_KEY_BOB="$(rand_hex)"
UPGRADE_KEY_CAROL="$(rand_hex)"
UPGRADE_NS_KEY="$(rand_hex)"
export UPGRADE_KEY_ALICE UPGRADE_KEY_BOB UPGRADE_KEY_CAROL UPGRADE_NS_KEY

export JIG_NONINTERACTIVE=1 JIG_KEYCHAIN=none RUST_BACKTRACE=0
export USER="${USER:-upgrade}"
unset JIG_KEY_PASSPHRASE JIG_KEYS_STORAGE JIG_KEY_UNLOCK

home_of() { echo "$sandbox/$1"; }
ALICE_JIG_HOME="$(home_of alice)/.jig"
BIN="$ALICE_JIG_HOME/bin"
mkdir -p "$(home_of alice)" "$(home_of bob)" "$(home_of carol)"

log() { printf '\n== %s\n' "$*"; }
note() { echo "- $*" >> "$summary"; echo "   $*"; }
fail() {
  echo "FAIL: $*" >&2
  echo "- **FAIL**: $*" >> "$summary"
  exit 1
}

cleanup() {
  local rc=$?
  for pidfile in "$ALICE_JIG_HOME/jig-server.pid" "$ns_dir/ns.pid"; do
    [ -f "$pidfile" ] && kill "$(cat "$pidfile")" 2>/dev/null || true
  done
  if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    { echo "### Upgrade path: $*"; cat "$summary"; } >> "$GITHUB_STEP_SUMMARY" || true
  fi
  if [ "$rc" -ne 0 ]; then
    echo "--- jig-server log (tail)" >&2
    tail -40 "$ALICE_JIG_HOME/logs/jig-server.log" >&2 2>/dev/null || true
    echo "--- jig-nameserver log (tail)" >&2
    tail -20 "$ns_dir/ns.log" >&2 2>/dev/null || true
  fi
  if [ "${JIG_UPGRADE_KEEP:-0}" = 1 ]; then echo "kept $sandbox"; else rm -rf "$sandbox"; fi
}
trap 'cleanup "$@"' EXIT

# A known gap reproduced on a step of KIND (release or mirror). On a release
# step, one of RELEASED_GAPS is reported and nothing else is allowed. On this
# build, one of KNOWN_GAPS is reported and counted; anything else fails.
gap() {
  local name="$1" what="$2" kind="$3"
  if [ "$kind" = release ]; then
    case " $RELEASED_GAPS " in
      *" $name "*)
        note "released gap \`$name\` (a published release; fixed only in later ones): $what"
        return
        ;;
      *) fail "upgrade gap $name in a published release: $what" ;;
    esac
  fi
  case " $KNOWN_GAPS " in
    *" $name "*)
      seen_gaps="$seen_gaps$name "
      echo "::warning title=upgrade gap $name::$what"
      note "KNOWN GAP \`$name\`: $what"
      ;;
    *) fail "upgrade gap $name: $what" ;;
  esac
}

# --- the user's side ---------------------------------------------------------

# jig as USER (alice, bob or carol), from the one installed bin directory.
as() {
  local who="$1"; shift
  local upper; upper="$(echo "$who" | tr '[:lower:]' '[:upper:]')"
  env HOME="$(home_of "$who")" JIG_HOME="$(home_of "$who")/.jig" \
    JIG_KEY_UNLOCK="env:UPGRADE_KEY_$upper" "$BIN/jig" "$@"
}

did_of() { sed -n 's/^did = "\(.*\)"$/\1/p' "$(home_of "$1")/.jig/cli.toml"; }

# Post TEXT to CHANNEL as WHO, and record who must be able to read it.
post() {
  local who="$1" channel="$2" text="$3" readers="$4"
  as "$who" send --channel "$channel" "$text" >/dev/null || fail "$who could not post to $channel"
  printf '%s\t%s\t%s\n' "$channel" "$text" "$readers" >> "$ledger"
}

# Every message so far, read back by every reader it was meant for.
check_ledger() {
  local channel text readers reader out
  while IFS=$'\t' read -r channel text readers; do
    for reader in $readers; do
      out="$sandbox/read.out"
      as "$reader" read "$channel" --limit 500 > "$out" 2>&1 || {
        cat "$out" >&2; fail "$reader cannot read $channel"; }
      grep -qF -- "$text" "$out" || { cat "$out" >&2; fail "$reader does not see \"$text\" in $channel"; }
    done
  done < "$ledger"
  note "$(wc -l < "$ledger" | tr -d ' ') messages read back by every reader"
}

check_channels() {
  local who channel out="$sandbox/channels.out"
  for who in alice bob; do
    as "$who" channel list > "$out" 2>&1 || { cat "$out" >&2; fail "$who: channel list failed"; }
    while read -r channel; do
      grep -qF -- "$channel " "$out" || { cat "$out" >&2; fail "$who does not list $channel"; }
    done < <(cut -f1 "$ledger" | sort -u)
  done
}

check_dids() {
  local who
  for who in alice bob carol; do
    [ "$(did_of "$who")" = "$(cat "$sandbox/did.$who")" ] || fail "$who's DID changed"
  done
}

# Once a release seals keys, no identity key may stay on disk unencrypted.
check_keys_sealed() {
  local who dir
  for who in alice bob carol; do
    dir="$(home_of "$who")/.jig/keys"
    [ -f "$dir/$(did_of "$who").jigkey" ] || fail "$who's key was not sealed into a .jigkey"
    if compgen -G "$dir/*.key" >/dev/null; then fail "$who still has an unencrypted key in $dir"; fi
  done
  note "every identity key sealed, DIDs unchanged"
}

# --- jig-server -----------------------------------------------------------------

server_did() {
  curl -fsSk "https://127.0.0.1:$server_port/.well-known/jig" \
    | sed -n 's/.*"server_did":"\([^"]*\)".*/\1/p'
}

stop_server() {
  local pidfile="$ALICE_JIG_HOME/jig-server.pid" pid
  [ -f "$pidfile" ] || return 0
  pid="$(cat "$pidfile")"
  kill "$pid" 2>/dev/null || true
  for _ in $(seq 1 100); do kill -0 "$pid" 2>/dev/null || return 0; sleep 0.1; done
  fail "jig-server (pid $pid) did not stop"
}

# Started the way install.sh starts it.
start_server() {
  nohup "$BIN/jig-server" --config "$ALICE_JIG_HOME/config.toml" \
    >>"$ALICE_JIG_HOME/logs/jig-server.log" 2>&1 &
  echo $! > "$ALICE_JIG_HOME/jig-server.pid"
  for _ in $(seq 1 100); do
    [ -n "$(server_did 2>/dev/null)" ] && return 0
    sleep 0.1
  done
  fail "jig-server did not come back up"
}

# --- jig-nameserver -------------------------------------------------------------

# Releases up to v0.2.0-alpha.1 configure the nameserver from the environment
# (JIG_NS_DB_PATH, JIG_NS_SECRET); later ones need a config file.
ns_is_legacy() { "$BIN/jig-nameserver" serve --help | grep -q -- '--db-path'; }

NS_ENV=(HOME="$ns_dir" JIG_NS_DB_PATH="$ns_dir/nameserver.db"
  JIG_NS_BIND=127.0.0.1 JIG_NS_PORT="$ns_port")

ns_url() { if ns_is_legacy; then echo "http://127.0.0.1:$ns_port"; else echo "https://127.0.0.1:$ns_port"; fi; }

stop_ns() {
  [ -f "$ns_dir/ns.pid" ] || return 0
  local pid; pid="$(cat "$ns_dir/ns.pid")"
  kill "$pid" 2>/dev/null || true
  for _ in $(seq 1 100); do kill -0 "$pid" 2>/dev/null || return 0; sleep 0.1; done
  fail "jig-nameserver did not stop"
}

start_ns() {
  if ns_is_legacy; then
    printf '[v0_0_2.nameserver]\nalias_suffix = "%s"\n' "$SUFFIX" > "$ns_dir/ns.toml"
    nohup env "${NS_ENV[@]}" JIG_NS_CONFIG="$ns_dir/ns.toml" JIG_NS_SECRET="$(rand_hex)" \
      "$BIN/jig-nameserver" serve >>"$ns_dir/ns.log" 2>&1 &
  else
    printf '[[v0_0_2.nameserver.alias_suffixes]]\nsuffix = "%s"\n\n[v0_0_2.keys]\nunlock = "env:UPGRADE_NS_KEY"\n' \
      "$SUFFIX" > "$ns_dir/ns.toml"
    local ns=(env "${NS_ENV[@]}" JIG_NS_CONFIG="$ns_dir/ns.toml" "$BIN/jig-nameserver")
    if [ -f "$ns_dir/nameserver_v002.key" ]; then
      # An older release wrote the key unencrypted: the documented step.
      "${ns[@]}" keys seal --slot env:UPGRADE_NS_KEY || fail "jig-nameserver keys seal failed"
      note "sealed the nameserver key an older release wrote unencrypted"
    fi
    nohup "${ns[@]}" serve >>"$ns_dir/ns.log" 2>&1 &
  fi
  echo $! > "$ns_dir/ns.pid"
  for _ in $(seq 1 100); do
    curl -fsSk -o /dev/null "$(ns_url)/v1/health" && return 0
    kill -0 "$(cat "$ns_dir/ns.pid")" 2>/dev/null || { tail -5 "$ns_dir/ns.log" >&2; fail "jig-nameserver exited at startup"; }
    sleep 0.1
  done
  fail "jig-nameserver did not answer /v1/health"
}

# Clients of a release with verified naming find the suffix through their own
# delegation, which names the nameserver's DID.
delegate_suffix() {
  local who file
  for who in alice bob carol; do
    file="$(home_of "$who")/.jig/cli.toml"
    grep -qF "[naming.delegations.\"$SUFFIX\"]" "$file" && continue
    printf '\n[naming.delegations."%s"]\nauthorities = ["%s"]\nnameservers = ["%s"]\n' \
      "$SUFFIX" "$(cat "$sandbox/did.ns")" "https://127.0.0.1:$ns_port" >> "$file"
  done
}

check_alias() {
  local out="$sandbox/resolve.out" args=()
  ns_is_legacy && args=(--nameserver "$(ns_url)")
  as alice ns resolve "carol@$SUFFIX" "${args[@]}" > "$out" 2>&1 || { cat "$out" >&2; fail "carol@$SUFFIX does not resolve"; }
  grep -qF -- "-> $(cat "$sandbox/did.carol")" "$out" || { cat "$out" >&2; fail "carol@$SUFFIX resolves to someone else"; }
  if ! ns_is_legacy; then
    grep -qF -- "vouched for by $(cat "$sandbox/did.ns")" "$out" || { cat "$out" >&2; fail "carol@$SUFFIX is not vouched for by the same nameserver DID"; }
    [ "$(env "${NS_ENV[@]}" JIG_NS_CONFIG="$ns_dir/ns.toml" "$BIN/jig-nameserver" keys show | head -1)" = "$(cat "$sandbox/did.ns")" ] \
      || fail "the nameserver's DID changed"
  fi
  note "carol@$SUFFIX still resolves to carol, from the same nameserver DID"
}

# --- installing a step ------------------------------------------------------------

# Runs install.sh for STEP over the existing ~/.jig.
install_step() {
  local step="$1" url
  local envs=(HOME="$(home_of alice)" JIG_HOME="$ALICE_JIG_HOME" JIG_REPO="$JIG_REPO"
    JIG_SERVER_LISTEN="127.0.0.1:$server_port" JIG_KEY_UNLOCK=env:UPGRADE_KEY_ALICE)
  case "$step" in
    mirror=*)
      url="${step#mirror=}"
      envs+=(JIG_RELEASES_BASE="$url" JIG_RELEASE_SIGNER="${JIG_UPGRADE_MIRROR_SIGNER:?set JIG_UPGRADE_MIRROR_SIGNER for a mirror step}")
      ;;
    v*)
      url="https://github.com/$JIG_REPO/releases/download/$step"
      envs+=(JIG_VERSION="$step")
      ;;
    *) fail "unknown step $step" ;;
  esac
  curl -fsSL "$url/install.sh" -o "$sandbox/install.sh" || fail "could not fetch install.sh for $step"
  verify_installer "$step" "$url"
  env "${envs[@]}" bash "$sandbox/install.sh"
}

# install.sh runs as the user, so it is checked before it runs: against the
# step's SHA256SUMS, whose signature is checked against the release key (or,
# for a mirror, $JIG_UPGRADE_MIRROR_SIGNER).
verify_installer() {
  local step="$1" url="$2" signers="$sandbox/allowed_signers" want got
  case "$step" in
    mirror=*) echo "$JIG_UPGRADE_MIRROR_SIGNER" > "$signers" ;;
    *) cp "$ALLOWED_SIGNERS" "$signers" ;;
  esac
  curl -fsSL "$url/SHA256SUMS" -o "$sandbox/SHA256SUMS" || fail "could not fetch SHA256SUMS for $step"
  curl -fsSL "$url/SHA256SUMS.sig" -o "$sandbox/SHA256SUMS.sig" || fail "could not fetch SHA256SUMS.sig for $step"
  ssh-keygen -Y verify -f "$signers" -I jig-release -n jig-release \
    -s "$sandbox/SHA256SUMS.sig" < "$sandbox/SHA256SUMS" >/dev/null \
    || fail "SHA256SUMS for $step is not signed by the release key"
  want="$(awk '$2 == "install.sh" || $2 == "*install.sh" { print $1 }' "$sandbox/SHA256SUMS")"
  [ -n "$want" ] || fail "SHA256SUMS for $step does not list install.sh"
  if command -v sha256sum >/dev/null; then
    got="$(sha256sum "$sandbox/install.sh" | cut -d' ' -f1)"
  else
    got="$(shasum -a 256 "$sandbox/install.sh" | cut -d' ' -f1)"
  fi
  [ "$got" = "$want" ] || fail "install.sh for $step does not match its signed SHA256SUMS"
}

# --- state ---------------------------------------------------------------------------

seed() {
  log "creating state"
  as bob init bob >/dev/null
  as bob server set "https://127.0.0.1:$server_port" >/dev/null
  local out="$sandbox/carol-init.out"
  as carol init carol --request-alias carol --nameserver "$(ns_url)" > "$out" 2>&1 || { cat "$out" >&2; fail "carol could not take an alias"; }
  as carol server set "https://127.0.0.1:$server_port" >/dev/null
  sed -n 's/.*ns=\(did:jig:[a-z0-9]*\).*/\1/p' "$out" > "$sandbox/did.ns"
  [ -s "$sandbox/did.ns" ] || { cat "$out" >&2; fail "no nameserver DID in carol's attestation"; }
  local who
  for who in alice bob carol; do did_of "$who" > "$sandbox/did.$who"; done
  server_did > "$sandbox/did.server"

  as alice channel create '#open' >/dev/null
  as alice channel create '#sec' --visibility restricted >/dev/null
  as alice channel add '#sec' "$(cat "$sandbox/did.bob")" >/dev/null
  as alice channel create '#enc' --encrypted >/dev/null
  as bob channel join '#enc' >/dev/null
  as alice dm "$(cat "$sandbox/did.bob")" "dm from the first release" > "$out" 2>&1 || { cat "$out" >&2; fail "alice could not DM bob"; }
  sed -n 's/^channel created: \(#dm\/[0-9a-f]*\) .*/\1/p' "$out" > "$sandbox/dm.slug"
  [ -s "$sandbox/dm.slug" ] || { cat "$out" >&2; fail "no DM channel in jig dm's output"; }
  printf '%s\t%s\t%s\n' "$(cat "$sandbox/dm.slug")" "dm from the first release" "alice bob" >> "$ledger"
  note "alice $(cat "$sandbox/did.alice"), bob, carol; server $(cat "$sandbox/did.server"); nameserver $(cat "$sandbox/did.ns")"
}

# Messages written by STEP's release, and an encrypted channel of its own.
write_step() {
  local n="$1" dm; dm="$(cat "$sandbox/dm.slug")"
  post alice '#hello' "hello from step $n" "alice bob"
  post alice '#open' "open from step $n" "alice bob carol"
  post alice '#sec' "sec from alice, step $n" "alice bob"
  post bob '#sec' "sec from bob, step $n" "alice bob"
  post alice '#enc' "enc from alice, step $n" "alice bob"
  post bob '#enc' "enc from bob, step $n" "alice bob"
  post bob "$dm" "dm from bob, step $n" "alice bob"
  as alice channel create "#made-in-$n" --visibility restricted >/dev/null
  as alice channel add "#made-in-$n" "$(cat "$sandbox/did.bob")" >/dev/null
  post alice "#made-in-$n" "made in step $n" "alice bob"
}

check_all() {
  check_dids
  check_channels
  check_ledger
  check_alias
}

# --- the run ----------------------------------------------------------------------------

n=0
for step in "$@"; do
  log "step $n: $step"
  echo "- step $n: \`$step\`" >> "$summary"
  if [ "$n" -eq 0 ]; then
    install_step "$step"
    start_ns
    seed
    ns_is_legacy || delegate_suffix
  else
    # The path a user takes first: install.sh again, server still running.
    kind=release
    case "$step" in mirror=*) kind=mirror ;; esac
    old_pid="$(cat "$ALICE_JIG_HOME/jig-server.pid")"
    stop_ns
    installed=1
    install_step "$step" > "$sandbox/install-running.out" 2>&1 || installed=0
    reused=0
    kill -0 "$old_pid" 2>/dev/null && reused=1
    if [ "$installed" = 0 ]; then
      tail -5 "$sandbox/install-running.out"
      # A published installer that leaves the old server answering then fails
      # to talk to it (alpha.2: "malformed handshake frame"): that failure is
      # the released gap itself. Any other failure fails the run.
      if [ "$kind" = mirror ] || [ "$reused" = 0 ]; then
        fail "install.sh ($step) failed over a running jig-server"
      fi
    fi
    if [ "$reused" = 1 ]; then
      gap install-reuses-old-server "re-running install.sh ($step) left the previous release's jig-server (pid $old_pid) running" "$kind"
    fi
    # The documented path: stop the server, then install.
    stop_server
    install_step "$step" || fail "install.sh ($step) failed over the previous install"
    start_ns
    delegate_suffix
    [ "$(server_did)" = "$(cat "$sandbox/did.server")" ] || fail "jig-server's DID changed across the upgrade"
    check_all
    ns_is_legacy || check_keys_sealed
  fi
  write_step "$n"
  check_all
  n=$((n + 1))
done

# Key rotation on the last release: every client pinned on the old DID must
# follow the key link.
last_kind=release
case "${*: -1}" in mirror=*) last_kind=mirror ;; esac
log "rotating jig-server's key"
unlock="$(sed -n 's/^unlock = "\(.*\)"$/\1/p' "$ALICE_JIG_HOME/config.toml" | head -1)"
[ -n "$unlock" ] || fail "no [keys] unlock in jig-server's config to seal the new key with"
stop_server
"$BIN/jig-server" --config "$ALICE_JIG_HOME/config.toml" keys rotate --slot "$unlock" \
  || fail "jig-server keys rotate failed"
start_server
new_did="$(server_did)"
[ "$new_did" != "$(cat "$sandbox/did.server")" ] || fail "keys rotate did not change the server's DID"
note "rotated jig-server's key to $new_did"
rotate_out="$sandbox/after-rotate.out"
if ! as alice read '#enc' > "$rotate_out" 2>&1; then
  if grep -q "is not the channel this device pinned" "$rotate_out"; then
    gap rotate-locks-out-clients "after keys rotate, a client pinned on the old DID refuses the re-created #jig/manifest: $(grep -m1 'not the channel' "$rotate_out" | cut -c1-200)" "$last_kind"
  else
    cat "$rotate_out" >&2
    fail "alice cannot reach the server after its key rotated"
  fi
else
  check_all
  post alice '#enc' "enc after the key rotated" "alice bob"
  check_ledger
  note "every client followed the key link"
fi

for name in $KNOWN_GAPS; do
  case "$seen_gaps" in
    *" $name "*) ;;
    *) fail "known gap $name did not reproduce: if it is fixed, drop it from KNOWN_GAPS in $0" ;;
  esac
done
log "PASS: $*"
echo "- **PASS**" >> "$summary"
