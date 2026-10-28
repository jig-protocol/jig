#!/usr/bin/env bash
# jig install.sh — curl to hello-world.
#
#   curl -fsSL https://raw.githubusercontent.com/jig-protocol/jig/main/install.sh | bash
#
# KPI: a fresh machine goes from that line to "hello, world" posted in #hello on
# a local jig-server in under 60s. CI enforces it (.github/workflows/install-smoke.yml).
#
# What it does, in order:
#   1. Download jig-<os>-<arch>.tar.gz + SHA256SUMS + SHA256SUMS.sig from the
#      GitHub Release, verify the signature (ssh-keygen -Y, key pinned below)
#      and the tarball checksum, unpack into $JIG_HOME/bin.
#   2. Write a TOFU-mode server config bound to 127.0.0.1 and start jig-server.
#   3. jig init → server set → channel create #hello → send "hello, world".
#   4. If a terminal is attached, exec `jig chat #hello`.
#
# Knobs (environment):
#   JIG_VERSION           release tag, or "latest" (newest non-draft, prereleases
#                         included). Default: latest.
#   JIG_REPO              GitHub owner/repo. Default: jig-protocol/jig.
#   JIG_GITHUB_TOKEN      token for a private repo (falls back to GITHUB_TOKEN).
#   JIG_RELEASES_BASE     mirror base URL; files are fetched as $BASE/<file> and
#                         no GitHub API call is made.
#   JIG_VERIFY_SIGNATURE  1 (default): verify the signature, and refuse to install
#                         without ssh-keygen. 0: skip it, checksum only.
#   JIG_INSTALL_FROM      release (default) | source (cargo build; only from a checkout).
#   JIG_NONINTERACTIVE=1  never exec into the chat TUI.
#   JIG_NO_START=1        install binaries + config only.
#   JIG_KEY_PASSPHRASE / JIG_KEY_UNLOCK
#                         seal the new identity key with a passphrase or a
#                         secret (see `jig init`). Without them, and with no OS
#                         keychain and no terminal to ask, the key is stored
#                         unencrypted (JIG_KEYS_STORAGE=plaintext) and a warning
#                         says so.
#   JIG_HOME, JIG_SERVER_LISTEN, JIG_DEFAULT_CHANNEL.

set -euo pipefail

JIG_HOME="${JIG_HOME:-$HOME/.jig}"
JIG_REPO="${JIG_REPO:-jig-protocol/jig}"
JIG_VERSION="${JIG_VERSION:-latest}"
JIG_RELEASES_BASE="${JIG_RELEASES_BASE:-}"
JIG_GITHUB_TOKEN="${JIG_GITHUB_TOKEN:-${GITHUB_TOKEN:-}}"
JIG_VERIFY_SIGNATURE="${JIG_VERIFY_SIGNATURE:-1}"
JIG_INSTALL_FROM="${JIG_INSTALL_FROM:-release}"
JIG_NONINTERACTIVE="${JIG_NONINTERACTIVE:-0}"
JIG_NO_START="${JIG_NO_START:-0}"
JIG_SERVER_LISTEN="${JIG_SERVER_LISTEN:-127.0.0.1:7117}"
JIG_DEFAULT_CHANNEL="${JIG_DEFAULT_CHANNEL:-#hello}"

# Release signing key (trust root), in ssh allowed_signers format. Must match
# .github/release/allowed_signers; the release workflow refuses to publish if
# the two drift. Overridable only so CI can test against a throwaway key.
JIG_RELEASE_SIGNER="${JIG_RELEASE_SIGNER:-jig-release namespaces=\"jig-release\" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGFgYuNUl5Z8A3AwRUo2PxIg+MziW2zxjboNOq4ZhXq4}"

log()  { printf '[jig] %s\n' "$*"; }
warn() { printf '[jig] WARN: %s\n' "$*" >&2; }
die()  { printf '[jig] ERROR: %s\n' "$*" >&2; exit 1; }

detect_os() {
  case "$(uname -s)" in
    Linux)  echo "linux" ;;
    Darwin) echo "darwin" ;;
    *) die "unsupported OS: $(uname -s) (prebuilt: linux, darwin)" ;;
  esac
}

detect_arch() {
  case "$(uname -m)" in
    x86_64|amd64) echo "x86_64" ;;
    aarch64|arm64) echo "aarch64" ;;
    *) die "unsupported arch: $(uname -m) (prebuilt: x86_64, aarch64)" ;;
  esac
}

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d' ' -f1
  else
    shasum -a 256 "$1" | cut -d' ' -f1
  fi
}

# fetch <url> <dest> [accept] — the token is only sent to GitHub hosts; curl
# drops it on the cross-host redirect to the asset CDN.
fetch() {
  local args=(-fsSL --retry 3 --connect-timeout 10 -o "$2")
  if [ -n "${3:-}" ]; then args+=(-H "Accept: $3"); fi
  case "$1" in
    https://api.github.com/*|https://github.com/*)
      if [ -n "$JIG_GITHUB_TOKEN" ]; then args+=(-H "Authorization: Bearer $JIG_GITHUB_TOKEN"); fi ;;
  esac
  curl "${args[@]}" "$1"
}

# -----------------------------------------------------------------------------
# Release resolution. Sets RELEASE_TAG and, with a token, ASSET_IDS (name=id
# lines) so private-repo assets can be fetched through the API.
# -----------------------------------------------------------------------------
RELEASE_TAG=""
ASSET_IDS=""
INSTALL_TMP=""
SERVER_PID=""
API="https://api.github.com/repos/$JIG_REPO"

resolve_release() {
  local tmp="$1" json="$1/release.json"
  if [ "$JIG_VERSION" = "latest" ]; then
    # /releases/latest skips prereleases, and every v0.x tag is one. Each
    # release object has exactly one top-level tag_name and draft, so the
    # two lists pair up by index.
    fetch "$API/releases?per_page=20" "$tmp/releases.json" application/vnd.github+json \
      || die "could not list releases of $JIG_REPO (private repo? set JIG_GITHUB_TOKEN)"
    local tags drafts
    tags=$(grep -oE '"tag_name": *"[^"]*"' "$tmp/releases.json" | sed -E 's/.*"([^"]*)"$/\1/')
    drafts=$(grep -oE '"draft": *(true|false)' "$tmp/releases.json" | sed -E 's/.*: *//')
    RELEASE_TAG=$(paste -d' ' <(printf '%s\n' "$tags") <(printf '%s\n' "$drafts") \
      | awk '$2 == "false" { print $1; exit }')
    [ -n "$RELEASE_TAG" ] || die "no published release found in $JIG_REPO"
  else
    RELEASE_TAG="$JIG_VERSION"
  fi

  if [ -n "$JIG_GITHUB_TOKEN" ]; then
    fetch "$API/releases/tags/$RELEASE_TAG" "$json" application/vnd.github+json \
      || die "release $RELEASE_TAG not found in $JIG_REPO"
    local ids names
    ids=$(grep -oE '"url": *"[^"]*/releases/assets/[0-9]+"' "$json" | grep -oE '[0-9]+"$' | tr -d '"')
    names=$(grep -oE '"browser_download_url": *"[^"]*"' "$json" | sed -E 's#.*/##; s/"$//')
    ASSET_IDS=$(paste -d'=' <(printf '%s\n' "$names") <(printf '%s\n' "$ids"))
  fi
}

# download_asset <name> <dest>
download_asset() {
  if [ -n "$JIG_RELEASES_BASE" ]; then
    fetch "${JIG_RELEASES_BASE%/}/$1" "$2"
  elif [ -n "$ASSET_IDS" ]; then
    local id
    id=$(printf '%s\n' "$ASSET_IDS" | awk -F= -v n="$1" '$1 == n { print $2; exit }')
    [ -n "$id" ] || return 1
    fetch "$API/releases/assets/$id" "$2" application/octet-stream
  else
    fetch "https://github.com/$JIG_REPO/releases/download/$RELEASE_TAG/$1" "$2"
  fi
}

# Fails closed: threat-register SC-02 says installers MUST verify both the
# signature and the checksum, so a machine without ssh-keygen gets an error,
# not a checksum-only install. Only an explicit JIG_VERIFY_SIGNATURE=0 skips it.
verify_signature() {
  local sums="$1" sig="$2" signers err
  case "$JIG_VERIFY_SIGNATURE" in
    0)
      warn "JIG_VERIFY_SIGNATURE=0: skipping signature check (checksum only)"
      return 0 ;;
    1|auto) ;;
    *) die "JIG_VERIFY_SIGNATURE must be 1 or 0, not '$JIG_VERIFY_SIGNATURE'" ;;
  esac
  if ! command -v ssh-keygen >/dev/null 2>&1; then
    die "ssh-keygen (OpenSSH >= 8.1) is not installed, so the release signature cannot be verified.
  Install it and re-run: openssh-client (Debian/Ubuntu), openssh-keygen (Alpine), openssh (Fedora, Arch).
  To install anyway with the checksum check only, re-run with JIG_VERIFY_SIGNATURE=0."
  fi
  [ -f "$sig" ] || die "SHA256SUMS.sig missing from the release; refusing unsigned binaries (JIG_VERIFY_SIGNATURE=0 to override)"
  signers="$(dirname "$sums")/allowed_signers"
  printf '%s\n' "$JIG_RELEASE_SIGNER" > "$signers"
  # OpenSSH older than 8.1 has no -Y; its usage error goes in the message so
  # that case doesn't read as a bad signature.
  if ! err=$(ssh-keygen -Y verify -f "$signers" -I jig-release -n jig-release -s "$sig" < "$sums" 2>&1); then
    die "SHA256SUMS signature does not verify against the pinned jig release key (ssh-keygen: $(printf '%s' "$err" | head -n 1))"
  fi
  log "signature OK (jig-release ed25519)"
}

install_from_release() {
  local os arch name tarball tmp expected actual src b
  os="$(detect_os)"
  arch="$(detect_arch)"
  name="jig-${os}-${arch}"
  tarball="${name}.tar.gz"
  tmp="$(mktemp -d "${TMPDIR:-/tmp}/jig-install.XXXXXX")"
  INSTALL_TMP="$tmp"

  if [ -z "$JIG_RELEASES_BASE" ]; then
    resolve_release "$tmp"
    log "release $RELEASE_TAG from github.com/$JIG_REPO"
  else
    log "release mirror $JIG_RELEASES_BASE"
  fi

  log "downloading $tarball ..."
  download_asset "$tarball" "$tmp/$tarball" || die "download of $tarball failed (no build for $os/$arch in this release?)"
  download_asset SHA256SUMS "$tmp/SHA256SUMS" || die "download of SHA256SUMS failed"
  download_asset SHA256SUMS.sig "$tmp/SHA256SUMS.sig" || true

  verify_signature "$tmp/SHA256SUMS" "$tmp/SHA256SUMS.sig"
  expected=$(awk -v f="$tarball" '$2 == f || $2 == "*"f { print $1; exit }' "$tmp/SHA256SUMS")
  [ -n "$expected" ] || die "$tarball is not listed in SHA256SUMS"
  actual=$(sha256_of "$tmp/$tarball")
  [ "$expected" = "$actual" ] || die "checksum mismatch for $tarball (expected $expected, got $actual)"
  log "checksum OK"

  tar -xzf "$tmp/$tarball" -C "$tmp"
  # Tarball layout: <name>/bin/{jig,jig-server,jig-nameserver}. Packages from
  # earlier builds also carried <name>/blocks/text_block.wasm, which nothing loads.
  src="$tmp/$name"
  [ -d "$src/bin" ] || die "unexpected tarball layout: $name/bin missing"
  mkdir -p "$JIG_HOME/bin"
  for b in jig jig-server jig-nameserver; do
    if [ -f "$src/bin/$b" ]; then install -m 0755 "$src/bin/$b" "$JIG_HOME/bin/$b"; fi
  done
  if [ ! -x "$JIG_HOME/bin/jig" ] || [ ! -x "$JIG_HOME/bin/jig-server" ]; then
    die "tarball did not contain jig + jig-server"
  fi
  log "installed jig, jig-server, jig-nameserver to $JIG_HOME/bin/"
}

install_from_source() {
  local root
  root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  [ -f "$root/repos/Cargo.toml" ] || die "JIG_INSTALL_FROM=source needs install.sh run from a jig checkout"
  log "building from source in $root/repos (minutes, not seconds)..."
  (
    cd "$root/repos"
    cargo build --release -p jig-server -p jig-cli -p jig-nameserver
  )
  mkdir -p "$JIG_HOME/bin"
  for b in jig jig-server jig-nameserver; do
    install -m 0755 "$root/repos/target/release/$b" "$JIG_HOME/bin/$b"
  done
  log "installed binaries to $JIG_HOME/bin/"
}

# -----------------------------------------------------------------------------
# Write a TOFU-default server config to $JIG_HOME/config.toml.
#
# ONE FILE, TWO STRUCTS. jig-server loads this same path twice:
#   * root-level keys      -> jig_server::ServerConfig  (this is what BINDS)
#   * [server]/[identity]/[federation]/[debug] -> jig-config's JigServerConfig
# Neither type rejects the other's keys, which is what makes one file legal.
# Omitting the root-level half leaves jig-server with no database_path and it
# refuses to start, so both halves must stay here.
# Covered by `install_sh_writes_a_config_that_boots_both_halves` in
# repos/jig-server/src/config.rs — that test parses THIS heredoc.
# -----------------------------------------------------------------------------
# The secret the local server's sealed key opens with: a random file beside it.
# That keeps the key out of clear text on disk and lets the server restart
# unattended, but whoever can read both files has the key. A server others
# rely on uses a systemd credential instead (deploy/README.md, "Sealing the
# server key").
server_key_credential() {
  local cred="$JIG_HOME/server/server-key.credential"
  if [ ! -f "$cred" ]; then
    (umask 077 && head -c 48 /dev/urandom | base64 > "$cred")
  fi
  printf '%s' "$cred"
}

# A config this script wrote before server keys were sealed has no [keys]
# section and a raw server.key, which jig-server now refuses. Only for a file
# this script wrote (its header says so): give it [keys] and seal the key in
# place, keeping the server's DID. Any other config is the operator's.
migrate_server_key() {
  local cfg="$1" cred raw="$JIG_HOME/server/server.key"
  grep -q '^# jig-server config written by install.sh' "$cfg" || return 0
  grep -q '^\[keys\]' "$cfg" && return 0
  cred="$(server_key_credential)"
  # Seal first: a failure leaves the config as it was, so a rerun tries again.
  if [ -f "$raw" ] && [ ! -f "$JIG_HOME/server/server.jigkey" ]; then
    "$JIG_HOME/bin/jig-server" --config "$cfg" keys seal --keyfile "$raw" --slot "credential:$cred" \
      | while IFS= read -r line; do log "$line"; done
  fi
  printf '\n[keys]\n# Added by install.sh: see server_key_credential() there.\nunlock = "credential:%s"\n' \
    "$cred" >> "$cfg"
  log "added [keys] to $cfg"
}

write_server_config() {
  local cfg="$JIG_HOME/config.toml" cred
  mkdir -p "$JIG_HOME/server" "$JIG_HOME/logs"
  if [ -f "$cfg" ]; then
    log "found existing $cfg — leaving it alone"
    migrate_server_key "$cfg"
    return 0
  fi
  cred="$(server_key_credential)"
  cat > "$cfg" <<EOF
# jig-server config written by install.sh. One file, two structs — see the
# install.sh comment above write_server_config() for why.

# ---------------------------------------------------------------------------
# ServerConfig — the half that actually opens the socket.
# ---------------------------------------------------------------------------
database_path = "$JIG_HOME/jig.db"
bind_address = "${JIG_SERVER_LISTEN%%:*}"
port = ${JIG_SERVER_LISTEN##*:}
# TLS is on by default: with no [tls] section the server makes its own
# certificate in $JIG_HOME/tls/ on first start, and its DID vouches for it.

# ---------------------------------------------------------------------------
# JigServerConfig — the v0.0.2 half.
# ---------------------------------------------------------------------------

[server]
# DECORATIVE. This only builds the ws:// origin-tag string stamped onto blocks;
# the socket binds bind_address/port above. Keep the two in sync or clients get
# handed an origin URL that points somewhere the server isn't (jig-server logs
# a WARN at startup when they disagree).
listen = "$JIG_SERVER_LISTEN"
server_did_keyfile = "$JIG_HOME/server/server.key"
# allowed_block_kinds is left unset on purpose, so this server tracks the
# built-in default as new kinds ship. Today that is:
#   allowed_block_kinds = ["text-render", "channel-create", "member-add", "member-remove", "channel-promote", "channel-archive", "role-assign", "role-unassign", "channel-share", "channel-unshare", "contract-accept", "contract-refuse", "contract-end"]
# To restrict it, uncomment that line and remove kinds. A list here is fixed:
# kinds added in later releases stay refused until you add them.

[identity]
# TOFU mode: this server trusts whatever DID first claims an alias and pins it.
# To gate via a nameserver, switch to "nameserver" and list each alias suffix
# under [identity.delegations."<suffix>"] with authorities (DIDs) and
# nameservers (URLs). trusted_nameservers is not used to resolve aliases.
# Names under the default suffix, alice@jig, need no entry: the server ships
# the jig delegation built in (once the project authority DID is published).
# To override it, add your own:
#   [identity.delegations.jig]
#   authorities = ["did:jig:..."]
#   nameservers = ["https://ns.example"]
mode = "tofu"
trusted_nameservers = []
cache_ttl_seconds = 300
naively_allow_unknown_handles_fallback = false

[federation]
# No peers by default. Add [[federation.peers]] blocks to federate.
peers = []
dangerously_disable_federation_tls = false

[debug]
# Channel ops are on /api/v1/channels and always mounted; nothing here is
# needed for the default path.
list_handles = false

[keys]
# The server's key is sealed in $JIG_HOME/server/server.jigkey and opens with a
# random secret in the file below, so it restarts unattended. Whoever can read
# both files has the key: fine for a server on this machine for you, not for one
# others rely on (deploy/README.md, "Sealing the server key").
unlock = "credential:$cred"
EOF
  log "wrote $cfg"
}

# The scheme a jig-server on $JIG_SERVER_LISTEN answers on, if one does: https
# by default (its own certificate, which jig trusts through the server's DID,
# hence -k here), http for a server that predates that default or turned it off.
server_scheme() {
  local scheme
  for scheme in https http; do
    if curl -kfsS -o /dev/null --max-time 1 "$scheme://${JIG_SERVER_LISTEN}/healthz" 2>/dev/null; then
      echo "$scheme"
      return 0
    fi
  done
  return 1
}

server_healthy() {
  server_scheme >/dev/null
}

# The address $JIG_HOME/config.toml has jig-server listen on. A re-run keeps
# an existing config, so this can differ from $JIG_SERVER_LISTEN.
config_listen() {
  local cfg="$JIG_HOME/config.toml" host port
  host="$(sed -n 's/^bind_address = "\(.*\)"$/\1/p' "$cfg" 2>/dev/null | head -1)"
  port="$(sed -n 's/^port = \([0-9][0-9]*\)$/\1/p' "$cfg" 2>/dev/null | head -1)"
  [ -n "$host" ] && [ -n "$port" ] || return 1
  echo "$host:$port"
}

# The pid of the jig-server this installer started earlier, from
# $JIG_HOME/jig-server.pid, if that process is still that binary and its
# config has it listen on $JIG_SERVER_LISTEN, so it is the server answering
# there and not one elsewhere.
our_server_pid() {
  local pid
  pid="$(cat "$JIG_HOME/jig-server.pid" 2>/dev/null)" || return 1
  case "$pid" in ''|*[!0-9]*) return 1 ;; esac
  kill -0 "$pid" 2>/dev/null || return 1
  ps -o command= -p "$pid" 2>/dev/null | grep -qF "$JIG_HOME/bin/jig-server" || return 1
  [ "$(config_listen)" = "$JIG_SERVER_LISTEN" ] || return 1
  echo "$pid"
}

# A server still running the jig-server this run replaced keeps serving the
# old build, and a new client may not speak to it. Stop it when this installer
# started it; otherwise say so. Returns 0 when one is still answering.
replaced_server_answering() {
  server_healthy || return 1
  [ -n "${OLD_SERVER_SUM:-}" ] && [ "$OLD_SERVER_SUM" != "$(sha256_of "$JIG_HOME/bin/jig-server")" ] || {
    log "jig-server already answering on $JIG_SERVER_LISTEN — reusing it"
    return 0
  }
  local pid
  if ! pid="$(our_server_pid)"; then
    warn "the jig-server answering on $JIG_SERVER_LISTEN is not one this installer started there, so"
    warn "it still runs whatever build it started with. Restart it to run the one just installed."
    return 0
  fi
  log "stopping jig-server (pid $pid): it runs the build this install replaced"
  kill "$pid" 2>/dev/null || true
  for _ in $(seq 1 100); do
    kill -0 "$pid" 2>/dev/null || break
    sleep 0.1
  done
  kill -0 "$pid" 2>/dev/null && die "jig-server (pid $pid) did not stop; stop it and run this again"
  for _ in $(seq 1 50); do
    server_healthy || return 1
    sleep 0.1
  done
  die "something still answers on $JIG_SERVER_LISTEN after jig-server (pid $pid) stopped"
}

start_server_background() {
  local log_file="$JIG_HOME/logs/jig-server.log"
  replaced_server_answering && return 0
  log "starting jig-server on $JIG_SERVER_LISTEN (logs: $log_file)"
  nohup "$JIG_HOME/bin/jig-server" --config "$JIG_HOME/config.toml" >"$log_file" 2>&1 &
  SERVER_PID=$!
  echo "$SERVER_PID" > "$JIG_HOME/jig-server.pid"
  for _ in $(seq 1 100); do
    server_healthy && { log "jig-server up (pid $SERVER_PID)"; return 0; }
    kill -0 "$SERVER_PID" 2>/dev/null || { tail -20 "$log_file" >&2; die "jig-server exited during startup"; }
    sleep 0.1
  done
  tail -20 "$log_file" >&2
  die "jig-server did not answer /healthz within 10s"
}

# On exit: remove the download directory, and drop the passphrase this script
# may have read, so nothing it started later inherits it.
on_exit() {
  if [ -n "${INSTALL_TMP:-}" ]; then rm -rf "$INSTALL_TMP"; fi
  # `read -s` turns echo back on when it returns, and bash restores it on
  # Ctrl-C too; this covers any other way out of the prompt.
  if [ "${INSTALL_PROMPTING:-0}" = "1" ]; then stty echo </dev/tty 2>/dev/null || true; fi
  forget_passphrase
}

# Set when this script read the passphrase itself, so it only ever unsets its
# own, never one the person exported.
INSTALL_READ_PASSPHRASE=0
forget_passphrase() {
  if [ "$INSTALL_READ_PASSPHRASE" = "1" ]; then
    unset JIG_KEY_PASSPHRASE
    INSTALL_READ_PASSPHRASE=0
  fi
}

# Where jig will find no OS keychain but a person is at the terminal, ask for
# the new key's passphrase once, here, and hand it to every jig command this
# script runs. Otherwise each command would ask again (unlocked keys are cached
# per process). It lives only in this script's environment: never on disk, and
# unset before the script ends.
#
# `read_passphrase force` asks even where a keychain should exist: jig could not
# seal with it (it timed out, or refused), and a person is still here, so the
# answer is a passphrase, never plaintext.
read_passphrase() {
  [ -n "${JIG_KEY_PASSPHRASE:-}${JIG_KEY_UNLOCK:-}" ] && return 0
  [ "${JIG_KEYS_STORAGE:-}" = "plaintext" ] && return 0
  if [ "${1:-}" != "force" ]; then
    # The checks jig makes for a keychain (jig-client/src/keychain.rs).
    [ "$(uname -s)" = "Darwin" ] && [ "${JIG_KEYCHAIN:-}" != "none" ] && return 0
    if [ "${JIG_KEYCHAIN:-}" != "none" ] && command -v secret-tool >/dev/null 2>&1 \
      && { [ -n "${DBUS_SESSION_BUS_ADDRESS:-}" ] || [ -S "${XDG_RUNTIME_DIR:-/nonexistent}/bus" ]; }; then
      return 0
    fi
  fi
  { : </dev/tty; } 2>/dev/null || return 0
  local first second
  INSTALL_PROMPTING=1
  # INT and TERM leave through `exit`, so the EXIT trap restores the terminal.
  trap 'exit 130' INT
  trap 'exit 143' TERM
  if [ "${1:-}" = "force" ]; then
    printf '[jig] The OS keychain could not seal your identity key: choose a passphrase instead.\n' >/dev/tty
  else
    printf '[jig] No OS keychain here: choose a passphrase to seal your identity key.\n' >/dev/tty
  fi
  for _ in 1 2 3; do
    printf '[jig] passphrase: ' >/dev/tty
    IFS= read -rs first </dev/tty || die "could not read a passphrase"
    printf '\n' >/dev/tty
    # The same minimum jig enforces on a new passphrase.
    if [ "${#first}" -lt 8 ]; then
      printf '[jig] the passphrase needs at least 8 characters\n' >/dev/tty
      continue
    fi
    printf '[jig] repeat it: ' >/dev/tty
    IFS= read -rs second </dev/tty || die "could not read a passphrase"
    printf '\n' >/dev/tty
    if [ "$first" = "$second" ]; then
      export JIG_KEY_PASSPHRASE="$first"
      INSTALL_READ_PASSPHRASE=1
      INSTALL_PROMPTING=0
      trap - INT TERM
      return 0
    fi
    printf '[jig] the two did not match\n' >/dev/tty
  done
  die "no passphrase chosen"
}

# The identity key could not be sealed: no OS keychain, no terminal to ask for
# a passphrase, and none in the environment. Say so loudly, and keep using the
# unencrypted key for the rest of this script (DJ, 2026-10-18: the CLI never
# weakens storage on its own; the installer opts in, visibly).
plaintext_keys() {
  warn "========================================================================"
  warn "Your identity key is stored UNENCRYPTED in ~/.jig/keys/."
  warn "No OS keychain was available and there was no terminal to ask for a"
  warn "passphrase. Anyone who can read your home directory, or a backup of it,"
  warn "has your identity."
  warn "Until you seal it, run jig with JIG_KEYS_STORAGE=plaintext. To seal it,"
  warn "run any jig command from a terminal without that variable (you will be"
  warn "asked for a passphrase), or set JIG_KEY_PASSPHRASE for that run."
  warn "========================================================================"
  export JIG_KEYS_STORAGE=plaintext
}

hello_world() {
  local jig="$JIG_HOME/bin/jig" nickname="${USER:-jig-user}" init_err
  if [ ! -f "$HOME/.jig/cli.toml" ]; then
    read_passphrase
    log "generating your DID (nickname: $nickname)"
    # Exit status 78: no key slot could seal the key (jig-cli's
    # EXIT_NO_KEY_SLOT). The passphrase prompt, if any, is on /dev/tty, so
    # capturing stderr does not hide it.
    local rc=0
    init_err="$("$jig" init "$nickname" 2>&1 >/dev/null)" || rc=$?
    case "$rc" in
      0) ;;
      78)
        # Nothing could seal the key. With a person at the terminal, that is a
        # passphrase (jig may have been told not to prompt, or the keychain
        # gave up on them); plaintext is only for when nobody can be asked.
        if { : </dev/tty; } 2>/dev/null; then
          read_passphrase force
        fi
        if [ -z "${JIG_KEY_PASSPHRASE:-}" ]; then
          plaintext_keys
        fi
        "$jig" init "$nickname" >/dev/null || die "jig init failed"
        ;;
      *) printf '%s\n' "$init_err" >&2; die "jig init failed" ;;
    esac
  else
    log "reusing identity in ~/.jig/cli.toml"
  fi
  # A key stored raw (by an earlier version, or above) is sealed the next time
  # jig loads it, which needs a way to seal. Where there is none, keep it raw for
  # this script rather than fail, and say so.
  if [ "${JIG_KEYS_STORAGE:-}" != "plaintext" ] \
    && compgen -G "$HOME/.jig/keys/*.key" >/dev/null \
    && ! { : </dev/tty; } 2>/dev/null \
    && [ -z "${JIG_KEY_PASSPHRASE:-}${JIG_KEY_UNLOCK:-}" ]; then
    plaintext_keys
  fi
  local scheme
  scheme="$(server_scheme)" || die "jig-server stopped answering on $JIG_SERVER_LISTEN"
  "$jig" server set "$scheme://${JIG_SERVER_LISTEN}" >/dev/null
  # --exist-ok: a re-run (or a server someone already set up) keeps its #hello.
  "$jig" channel create "$JIG_DEFAULT_CHANNEL" --exist-ok >/dev/null \
    || die "could not create $JIG_DEFAULT_CHANNEL"
  "$jig" send --channel "$JIG_DEFAULT_CHANNEL" "hello, world" >/dev/null
  log "posted \"hello, world\" to $JIG_DEFAULT_CHANNEL (${SECONDS}s since start)"
}

main() {
  trap on_exit EXIT
  log "installing jig into $JIG_HOME"
  # What jig-server was before this run, to restart a server running it.
  OLD_SERVER_SUM=""
  if [ -f "$JIG_HOME/bin/jig-server" ]; then OLD_SERVER_SUM="$(sha256_of "$JIG_HOME/bin/jig-server")"; fi
  case "$JIG_INSTALL_FROM" in
    release) install_from_release ;;
    source)  install_from_source ;;
    *) die "JIG_INSTALL_FROM must be release or source" ;;
  esac
  write_server_config

  if [ "$JIG_NO_START" = "1" ]; then
    log "JIG_NO_START=1: run \`$JIG_HOME/bin/jig-server --config $JIG_HOME/config.toml\` when ready"
    return 0
  fi
  start_server_background
  hello_world

  forget_passphrase
  log "add jig to your PATH:  export PATH=\"$JIG_HOME/bin:\$PATH\""
  log "stop the server:       kill \$(cat $JIG_HOME/jig-server.pid)"
  if [ "$JIG_NONINTERACTIVE" != "1" ] && [ -t 1 ] && { : </dev/tty; } 2>/dev/null; then
    log "opening jig chat $JIG_DEFAULT_CHANNEL (Esc or Ctrl+Q to quit; the server keeps running)"
    exec "$JIG_HOME/bin/jig" chat "$JIG_DEFAULT_CHANNEL" </dev/tty
  fi
  log "done. chat with: $JIG_HOME/bin/jig chat '$JIG_DEFAULT_CHANNEL'"
}

main "$@"
