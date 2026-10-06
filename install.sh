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
#   JIG_VERIFY_SIGNATURE  auto (default: verify when ssh-keygen exists), 1 (require), 0 (skip).
#   JIG_INSTALL_FROM      release (default) | source (cargo build; only from a checkout).
#   JIG_NONINTERACTIVE=1  never exec into the chat TUI.
#   JIG_NO_START=1        install binaries + config only.
#   JIG_HOME, JIG_SERVER_LISTEN, JIG_DEFAULT_CHANNEL.

set -euo pipefail

JIG_HOME="${JIG_HOME:-$HOME/.jig}"
JIG_REPO="${JIG_REPO:-jig-protocol/jig}"
JIG_VERSION="${JIG_VERSION:-latest}"
JIG_RELEASES_BASE="${JIG_RELEASES_BASE:-}"
JIG_GITHUB_TOKEN="${JIG_GITHUB_TOKEN:-${GITHUB_TOKEN:-}}"
JIG_VERIFY_SIGNATURE="${JIG_VERIFY_SIGNATURE:-auto}"
JIG_INSTALL_FROM="${JIG_INSTALL_FROM:-release}"
JIG_NONINTERACTIVE="${JIG_NONINTERACTIVE:-0}"
JIG_NO_START="${JIG_NO_START:-0}"
JIG_SERVER_LISTEN="${JIG_SERVER_LISTEN:-127.0.0.1:7117}"
JIG_DEFAULT_CHANNEL="${JIG_DEFAULT_CHANNEL:-#hello}"

# Release signing key (trust root), in ssh allowed_signers format. Must match
# .github/release/allowed_signers; the release workflow refuses to publish if
# the two drift. Overridable only so CI can test against a throwaway key.
JIG_RELEASE_SIGNER="${JIG_RELEASE_SIGNER:-jig-release namespaces=\"jig-release\" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPWl5eoqC5CMrUrwIT0xexR698+V85uiNWsHea2iHZYW}"

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

verify_signature() {
  local sums="$1" sig="$2" signers
  if [ "$JIG_VERIFY_SIGNATURE" = "0" ]; then
    warn "JIG_VERIFY_SIGNATURE=0: skipping signature check"
    return 0
  fi
  if ! command -v ssh-keygen >/dev/null 2>&1; then
    if [ "$JIG_VERIFY_SIGNATURE" = "1" ]; then
      die "JIG_VERIFY_SIGNATURE=1 but ssh-keygen (OpenSSH >= 8.1) is not installed"
    fi
    warn "ssh-keygen not found: checksum verified, signature NOT verified"
    return 0
  fi
  [ -f "$sig" ] || die "SHA256SUMS.sig missing from the release; refusing unsigned binaries (JIG_VERIFY_SIGNATURE=0 to override)"
  signers="$(dirname "$sums")/allowed_signers"
  printf '%s\n' "$JIG_RELEASE_SIGNER" > "$signers"
  ssh-keygen -Y verify -f "$signers" -I jig-release -n jig-release -s "$sig" < "$sums" >/dev/null 2>&1 \
    || die "SHA256SUMS signature does not verify against the pinned jig release key"
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
  trap 'rm -rf "$INSTALL_TMP"' EXIT

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
  # Tarball layout: <name>/bin/{jig,jig-server,jig-nameserver} + <name>/blocks/text_block.wasm
  src="$tmp/$name"
  [ -d "$src/bin" ] || die "unexpected tarball layout: $name/bin missing"
  mkdir -p "$JIG_HOME/bin" "$JIG_HOME/blocks"
  for b in jig jig-server jig-nameserver; do
    if [ -f "$src/bin/$b" ]; then install -m 0755 "$src/bin/$b" "$JIG_HOME/bin/$b"; fi
  done
  if [ -f "$src/blocks/text_block.wasm" ]; then
    install -m 0644 "$src/blocks/text_block.wasm" "$JIG_HOME/blocks/text_block.wasm"
  fi
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
    rustup target add wasm32-wasip1 >/dev/null 2>&1 || true
    cargo build --release --target wasm32-wasip1 -p text-block
  )
  mkdir -p "$JIG_HOME/bin" "$JIG_HOME/blocks"
  for b in jig jig-server jig-nameserver; do
    install -m 0755 "$root/repos/target/release/$b" "$JIG_HOME/bin/$b"
  done
  install -m 0644 "$root/repos/target/wasm32-wasip1/release/text_block.wasm" "$JIG_HOME/blocks/text_block.wasm"
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
write_server_config() {
  local cfg="$JIG_HOME/config.toml"
  mkdir -p "$JIG_HOME/server" "$JIG_HOME/logs"
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
allowed_block_kinds = ["text-render", "channel-create", "member-add", "channel-archive"]

[identity]
# TOFU mode: this server trusts whatever DID first claims an alias and pins it.
# Switch to "nameserver" + populate trusted_nameservers to gate via a nameserver.
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
admin_endpoints = false
list_handles = false
EOF
  log "wrote $cfg"
}

server_healthy() {
  curl -fsS -o /dev/null --max-time 1 "http://${JIG_SERVER_LISTEN}/healthz" 2>/dev/null
}

start_server_background() {
  local log_file="$JIG_HOME/logs/jig-server.log"
  if server_healthy; then
    log "jig-server already answering on $JIG_SERVER_LISTEN — reusing it"
    return 0
  fi
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

hello_world() {
  local jig="$JIG_HOME/bin/jig" nickname="${USER:-jig-user}"
  if [ ! -f "$HOME/.jig/cli.toml" ]; then
    log "generating your DID (nickname: $nickname)"
    "$jig" init "$nickname" >/dev/null
  else
    log "reusing identity in ~/.jig/cli.toml"
  fi
  "$jig" server set "ws://${JIG_SERVER_LISTEN}" >/dev/null
  # --exist-ok: a re-run (or a server someone already set up) keeps its #hello.
  "$jig" channel create "$JIG_DEFAULT_CHANNEL" --exist-ok >/dev/null \
    || die "could not create $JIG_DEFAULT_CHANNEL"
  "$jig" send --channel "$JIG_DEFAULT_CHANNEL" "hello, world" >/dev/null
  log "posted \"hello, world\" to $JIG_DEFAULT_CHANNEL (${SECONDS}s since start)"
}

main() {
  log "installing jig into $JIG_HOME"
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

  log "add jig to your PATH:  export PATH=\"$JIG_HOME/bin:\$PATH\""
  log "stop the server:       kill \$(cat $JIG_HOME/jig-server.pid)"
  if [ "$JIG_NONINTERACTIVE" != "1" ] && [ -t 1 ] && { : </dev/tty; } 2>/dev/null; then
    log "opening jig chat $JIG_DEFAULT_CHANNEL (Esc or Ctrl+Q to quit; the server keeps running)"
    exec "$JIG_HOME/bin/jig" chat "$JIG_DEFAULT_CHANNEL" </dev/tty
  fi
  log "done. chat with: $JIG_HOME/bin/jig chat '$JIG_DEFAULT_CHANNEL'"
}

main "$@"
