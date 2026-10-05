#!/usr/bin/env bash
# jig-protocol v0.0.2 install.sh — first-run flow.
#
# KPI: `curl -fsSL https://jig.onl/install.sh | bash` lands a fresh user in
# `jig chat #hello` in under 60s on a $5 VPS.
#
# Two run modes, auto-detected:
#   1. Source checkout (./repos/Cargo.toml or ./Cargo.toml present + cargo available)
#      → `cargo build --release` for jig-server, jig-cli, text-block (wasm32-wasip1).
#   2. Standalone (e.g. piped from curl)
#      → download `jig-<os>-<arch>.tar.gz` from $JIG_RELEASES_BASE/v0.0.2/.
#
# Non-interactive mode: set JIG_NONINTERACTIVE=1 (auto-yes to all prompts).
#
# Phase G1 of v0.0.2 hello-world. The post-merge operational tasks (publish
# releases.jig.onl, sign tarballs, point DNS) are tracked separately.

set -euo pipefail

# -----------------------------------------------------------------------------
# Configuration knobs (all env-overridable).
# -----------------------------------------------------------------------------
JIG_HOME="${JIG_HOME:-$HOME/.jig}"
JIG_RELEASES_BASE="${JIG_RELEASES_BASE:-https://releases.jig.onl}"
JIG_VERSION="${JIG_VERSION:-v0.0.2}"
JIG_NONINTERACTIVE="${JIG_NONINTERACTIVE:-0}"
JIG_SERVER_LISTEN="${JIG_SERVER_LISTEN:-127.0.0.1:7117}"
JIG_DEFAULT_CHANNEL="${JIG_DEFAULT_CHANNEL:-#hello}"

mkdir -p "$JIG_HOME/bin" "$JIG_HOME/blocks" "$JIG_HOME/server" "$JIG_HOME/logs"

# -----------------------------------------------------------------------------
# Tiny helpers.
# -----------------------------------------------------------------------------
log()  { printf '[jig] %s\n' "$*"; }
warn() { printf '[jig] WARN: %s\n' "$*" >&2; }
die()  { printf '[jig] ERROR: %s\n' "$*" >&2; exit 1; }

# prompt_yes_no <question> — defaults to Y, returns 0 for yes, 1 for no.
# Honors JIG_NONINTERACTIVE=1 (auto-yes).
prompt_yes_no() {
  local q="$1"
  if [ "$JIG_NONINTERACTIVE" = "1" ]; then
    log "$q [Y/n] (non-interactive: yes)"
    return 0
  fi
  # If stdin is not a tty (e.g. piped from curl), bail with a hint.
  if [ ! -t 0 ]; then
    warn "$q (stdin is not a tty; assuming yes — set JIG_NONINTERACTIVE=0 with a tty to prompt interactively)"
    return 0
  fi
  local reply
  printf '[jig] %s [Y/n] ' "$q"
  read -r reply
  case "${reply:-y}" in
    y|Y|yes|YES|"") return 0 ;;
    *) return 1 ;;
  esac
}

# detect_os → linux | darwin
detect_os() {
  case "$(uname -s)" in
    Linux)  echo "linux" ;;
    Darwin) echo "darwin" ;;
    *) die "unsupported OS: $(uname -s) (v0.0.2 supports linux + darwin)" ;;
  esac
}

# detect_arch → x86_64 | aarch64
detect_arch() {
  case "$(uname -m)" in
    x86_64|amd64) echo "x86_64" ;;
    aarch64|arm64) echo "aarch64" ;;
    *) die "unsupported arch: $(uname -m) (v0.0.2 supports x86_64 + aarch64)" ;;
  esac
}

# is_source_checkout → 0 if `cargo` is on PATH AND a Cargo.toml is in CWD or ./repos/.
is_source_checkout() {
  command -v cargo >/dev/null 2>&1 || return 1
  [ -f "./Cargo.toml" ] || [ -f "./repos/Cargo.toml" ]
}

# -----------------------------------------------------------------------------
# Install path 1: build from source.
# -----------------------------------------------------------------------------
install_from_source() {
  local workspace_dir="."
  if [ -f "./repos/Cargo.toml" ]; then
    workspace_dir="./repos"
  fi
  log "building from source in $workspace_dir (this can take 2-5 min)..."

  (
    cd "$workspace_dir"
    cargo build --release -p jig-server -p jig-cli
    # text-block is a Wasm artifact; uses wasm32-wasip1 (wasm32-wasi is deprecated).
    if ! rustup target list --installed 2>/dev/null | grep -q wasm32-wasip1; then
      log "adding wasm32-wasip1 toolchain target..."
      rustup target add wasm32-wasip1
    fi
    cargo build --release --target wasm32-wasip1 -p text-block
  )

  cp "$workspace_dir/target/release/jig-server" "$JIG_HOME/bin/jig-server"
  cp "$workspace_dir/target/release/jig"        "$JIG_HOME/bin/jig"
  cp "$workspace_dir/target/wasm32-wasip1/release/text_block.wasm" \
     "$JIG_HOME/blocks/text_block.wasm"
  log "installed binaries to $JIG_HOME/bin/"
}

# -----------------------------------------------------------------------------
# Install path 2: download prebuilt tarball.
# -----------------------------------------------------------------------------
install_from_release() {
  local os arch tarball url tmp
  os="$(detect_os)"
  arch="$(detect_arch)"
  tarball="jig-${os}-${arch}.tar.gz"
  url="${JIG_RELEASES_BASE}/${JIG_VERSION}/${tarball}"
  tmp="$(mktemp -d -t jig-install-XXXX)"
  log "downloading $url ..."

  if command -v curl >/dev/null 2>&1; then
    curl -fsSL -o "$tmp/$tarball" "$url" || die "download failed from $url (releases server may not be up yet — try building from source: git clone https://github.com/gigue-ai/jig-protocol && cd jig-protocol && ./install.sh)"
  elif command -v wget >/dev/null 2>&1; then
    wget -qO "$tmp/$tarball" "$url" || die "download failed from $url"
  else
    die "need either curl or wget to download the release tarball"
  fi

  tar -xzf "$tmp/$tarball" -C "$tmp"
  # Tarball layout: bin/jig-server bin/jig bin/jig-nameserver blocks/text_block.wasm
  cp "$tmp/bin/jig-server"          "$JIG_HOME/bin/jig-server"
  cp "$tmp/bin/jig"                 "$JIG_HOME/bin/jig"
  cp "$tmp/blocks/text_block.wasm"  "$JIG_HOME/blocks/text_block.wasm"
  if [ -f "$tmp/bin/jig-nameserver" ]; then
    cp "$tmp/bin/jig-nameserver" "$JIG_HOME/bin/jig-nameserver"
  fi
  rm -rf "$tmp"
  log "installed binaries to $JIG_HOME/bin/"
}

# -----------------------------------------------------------------------------
# Write a TOFU-default server config to ~/.jig/config.toml.
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
write_server_config() {
  local cfg="$JIG_HOME/config.toml"
  if [ -f "$cfg" ]; then
    log "found existing $cfg — leaving it alone"
    return 0
  fi
  cat > "$cfg" <<EOF
# jig-server config written by install.sh. One file, two structs — see the
# install.sh comment above write_server_config() for why.

# ---------------------------------------------------------------------------
# ServerConfig — the half that actually opens the socket.
# ---------------------------------------------------------------------------
database_path = "$JIG_HOME/jig.db"
bind_address = "${JIG_SERVER_LISTEN%%:*}"
port = ${JIG_SERVER_LISTEN##*:}

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
allowed_block_kinds = ["text-render", "channel-create", "member-add"]

[identity]
# TOFU mode: this server trusts whatever DID first claims an alias and pins it.
# Switch to "nameserver" + populate trusted_nameservers to gate via a nameserver.
mode = "tofu"
trusted_nameservers = []
cache_ttl_seconds = 300
naively_allow_unknown_handles_fallback = false

[federation]
# v0.0.2: no peers by default. Add [[federation.peers]] blocks to federate.
peers = []
dangerously_disable_federation_tls = false

[debug]
# Channel ops are on /api/v1/channels and always mounted.
admin_endpoints = false
list_handles = false
EOF
  log "wrote $cfg"
}

# -----------------------------------------------------------------------------
# Background-start jig-server, return its PID via $SERVER_PID.
# -----------------------------------------------------------------------------
SERVER_PID=""
start_server_background() {
  local cfg="$JIG_HOME/config.toml"
  local log_file="$JIG_HOME/logs/jig-server.log"
  log "starting jig-server in background on $JIG_SERVER_LISTEN (logs: $log_file)..."
  # nohup so the server survives this shell exiting (e.g. exec into chat).
  nohup "$JIG_HOME/bin/jig-server" --config "$cfg" \
    >"$log_file" 2>&1 &
  SERVER_PID=$!
  # Wait up to ~5s for the listener to come up.
  local i
  for i in 1 2 3 4 5 6 7 8 9 10; do
    if (echo >"/dev/tcp/${JIG_SERVER_LISTEN%%:*}/${JIG_SERVER_LISTEN##*:}") 2>/dev/null; then
      log "jig-server up (pid $SERVER_PID)"
      return 0
    fi
    sleep 0.5
  done
  warn "jig-server did not bind $JIG_SERVER_LISTEN within 5s — check $log_file"
  warn "continuing anyway; the next jig commands will surface any error"
}

# -----------------------------------------------------------------------------
# Run the user-facing setup chain: init → server set → channel create → chat.
# -----------------------------------------------------------------------------
run_first_chat() {
  local jig="$JIG_HOME/bin/jig"
  local nickname="${USER:-jig-user}"
  local server_url="ws://${JIG_SERVER_LISTEN}"

  # jig init — generates ~/.jig/keys/<did>.key and ~/.jig/cli.toml.
  # Idempotent-ish: refuses to clobber existing cli.toml without --force.
  if [ ! -f "$HOME/.jig/cli.toml" ]; then
    log "generating personal DID + nickname=$nickname ..."
    "$jig" init "$nickname"
  else
    log "found existing ~/.jig/cli.toml — reusing identity"
  fi

  # Point CLI at the local server.
  "$jig" server set "$server_url"

  # Create the default channel (idempotent-ish: server returns 409 if exists,
  # which the CLI surfaces as an error — non-fatal for the install flow).
  if ! "$jig" channel create "$JIG_DEFAULT_CHANNEL" 2>/dev/null; then
    log "channel $JIG_DEFAULT_CHANNEL already exists (or create failed) — continuing"
  fi

  log "handing off to: jig chat $JIG_DEFAULT_CHANNEL"
  log "press Ctrl+Q or Esc to exit; jig-server will keep running in the background."
  log "to stop the server later: kill $SERVER_PID"
  if [ "$JIG_NONINTERACTIVE" = "1" ]; then
    log "non-interactive mode: skipping exec into chat TUI"
    return 0
  fi
  exec "$jig" chat "$JIG_DEFAULT_CHANNEL"
}

# -----------------------------------------------------------------------------
# Main.
# -----------------------------------------------------------------------------
main() {
  log "jig-protocol v0.0.2 install"
  log "JIG_HOME=$JIG_HOME"

  if is_source_checkout; then
    log "detected source checkout — building locally"
    install_from_source
  else
    log "no source checkout detected — downloading prebuilt binaries"
    install_from_release
  fi

  write_server_config

  if prompt_yes_no "Start jig-server on $JIG_SERVER_LISTEN in TOFU mode?"; then
    start_server_background
  else
    log "skipped starting jig-server. Run \`$JIG_HOME/bin/jig-server --config $JIG_HOME/config.toml\` when ready."
    log "see also: \`$JIG_HOME/bin/jig --help\`"
    return 0
  fi

  if prompt_yes_no "Generate a personal DID and start chatting in $JIG_DEFAULT_CHANNEL?"; then
    run_first_chat
  else
    log "skipped first-chat setup. You can run \`$JIG_HOME/bin/jig init\` manually later."
    log "see also: \`$JIG_HOME/bin/jig --help\`"
  fi
}

main "$@"
