#!/usr/bin/env bash
#
# jig-backup.sh — consistent, timestamped snapshot of a jig deployment.
#
# Backs up three things, because losing any one of them loses something
# different:
#   1. jig.db       — the v0.0.1 store (ServerConfig database_path).
#   2. jig_v002.db  — the v0.0.2 block store. jig-server DERIVES this name from
#                     database_path by appending "_v002" to the file stem, so a
#                     configured /var/lib/jig/jig.db means the blocks people
#                     actually sent live in /var/lib/jig/jig_v002.db. BOTH exist
#                     and both matter; backing up only jig.db backs up almost
#                     nothing of value.
#   3. server.key   — the ed25519 seed the server DID is derived from. Losing it
#                     changes the server's identity and breaks TOFU pinning for
#                     every client that ever connected. See deploy/README.md.
#
# SQLite is copied with `VACUUM INTO`, not `cp`: it takes a read lock and emits
# a single consistent file, so a snapshot taken while the server is serving is
# still restorable. `cp` of a live WAL database is not.
#
set -euo pipefail

JIG_STATE_DIR="${JIG_STATE_DIR:-/var/lib/jig}"
BACKUP_DIR="${JIG_BACKUP_DIR:-/var/backups/jig}"
# Prune snapshots older than this. 0 disables pruning entirely.
RETENTION_DAYS="${JIG_BACKUP_RETENTION_DAYS:-14}"
# Set DRY_RUN=1 to see what would be pruned without deleting anything.
DRY_RUN="${DRY_RUN:-0}"

# Snapshots contain a private key. Anything this script creates is owner-only.
umask 077

log()  { printf '[jig-backup] %s\n' "$*"; }
die()  { printf '[jig-backup] ERROR: %s\n' "$*" >&2; exit 1; }

command -v sqlite3 >/dev/null 2>&1 || die \
    "sqlite3 not found on PATH. Install it (apt-get install -y sqlite3) — a
    backup that silently skips the databases is worse than no backup at all."

[ -d "$JIG_STATE_DIR" ] || die "state dir $JIG_STATE_DIR does not exist"

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
DEST="$BACKUP_DIR/$STAMP"
# A manual run in the same second as the timer would otherwise land in an
# existing directory and trip VACUUM INTO's refuse-to-overwrite. Take the next
# free suffix instead of failing on a name clash.
if [ -e "$DEST" ]; then
    n=1
    while [ -e "${DEST}.$n" ]; do n=$((n + 1)); done
    DEST="${DEST}.$n"
fi
mkdir -p "$BACKUP_DIR"
mkdir "$DEST"

# A half-written snapshot is worse than no snapshot: it looks like a backup.
# Remove the (freshly created, known-empty-at-start) destination on any failure
# so only complete snapshots ever survive.
completed=0
cleanup_partial() {
    if [ "$completed" -eq 0 ] && [ -d "$DEST" ]; then
        rm -rf -- "$DEST"
        printf '[jig-backup] removed partial snapshot %s\n' "$DEST" >&2
    fi
}
trap cleanup_partial EXIT

backed_up=0

# VACUUM INTO refuses to overwrite, which is what we want inside a fresh
# timestamped directory: a collision means something is very wrong.
snapshot_db() {
    local src="$1" name
    name="$(basename "$src")"
    if [ ! -f "$src" ]; then
        log "skip: $src not present"
        return 0
    fi
    sqlite3 "$src" "VACUUM INTO '$DEST/$name'" \
        || die "VACUUM INTO failed for $src (corrupt db, or destination not writable)"
    log "db:   $src -> $DEST/$name"
    backed_up=$((backed_up + 1))
}

snapshot_db "$JIG_STATE_DIR/jig.db"
snapshot_db "$JIG_STATE_DIR/jig_v002.db"
# Not strictly part of the server's state, but it lives on the same box and a
# lost registry means every handle has to be re-registered.
snapshot_db "$JIG_STATE_DIR/nameserver.db"

# --- the irreplaceable one --------------------------------------------------
# The databases can be rebuilt from what people re-send. The key cannot be
# rebuilt from anything. If it is missing we do NOT quietly continue.
KEYFILE="${JIG_SERVER_KEYFILE:-$JIG_STATE_DIR/server.key}"
if [ -f "$KEYFILE" ]; then
    cp -p "$KEYFILE" "$DEST/server.key"
    chmod 600 "$DEST/server.key"
    log "key:  $KEYFILE -> $DEST/server.key"
    backed_up=$((backed_up + 1))
else
    die "server keyfile $KEYFILE not found — refusing to record a backup that
    omits the server identity. Set JIG_SERVER_KEYFILE if it lives elsewhere."
fi

[ "$backed_up" -gt 0 ] || die "nothing was backed up"

# A manifest makes a restore six months from now a five-minute job instead of
# an archaeology project. Both lists are computed BEFORE the redirect creates
# MANIFEST.txt, so the manifest does not list or hash itself.
hash_files() {
    if command -v sha256sum >/dev/null 2>&1; then
        find . -maxdepth 1 -type f -print0 | xargs -0 sha256sum
    elif command -v shasum >/dev/null 2>&1; then
        find . -maxdepth 1 -type f -print0 | xargs -0 shasum -a 256
    else
        printf '(no sha256 tool on PATH)\n'
    fi
}
manifest_files="$(cd "$DEST" && find . -maxdepth 1 -type f -exec basename {} \; | sort | tr '\n' ' ')"
manifest_hashes="$(cd "$DEST" && hash_files)"

{
    printf 'timestamp_utc=%s\n' "$STAMP"
    printf 'host=%s\n' "$(hostname)"
    printf 'state_dir=%s\n' "$JIG_STATE_DIR"
    printf 'files=%s\n' "$manifest_files"
    printf 'sha256:\n'
    printf '%s\n' "$manifest_hashes"
} > "$DEST/MANIFEST.txt"

# Past this point the snapshot is whole, so the EXIT trap must not delete it —
# a later failure in retention pruning should not discard a good backup.
completed=1
log "snapshot complete: $DEST ($backed_up item(s))"

# --- retention --------------------------------------------------------------
# Only ever touches directories directly under BACKUP_DIR whose names match the
# timestamp shape this script generates, so a mis-set JIG_BACKUP_DIR cannot turn
# this into an rm -rf of something else.
if [ "$RETENTION_DAYS" -gt 0 ]; then
    while IFS= read -r old; do
        [ -n "$old" ] || continue
        if [ "$DRY_RUN" = "1" ]; then
            log "prune (dry-run): $old"
        else
            rm -rf -- "$old"
            log "pruned: $old"
        fi
    # The second pattern catches same-second collisions (…Z.1, …Z.2), which
    # would otherwise accumulate forever because they don't match the first.
    done < <(find "$BACKUP_DIR" -mindepth 1 -maxdepth 1 -type d \
                  \( -name '20*T*Z' -o -name '20*T*Z.[0-9]*' \) \
                  -mtime "+$RETENTION_DAYS" 2>/dev/null || true)
else
    log "retention disabled (JIG_BACKUP_RETENTION_DAYS=0)"
fi

log "done"
