#!/usr/bin/env bash
#
# jig-backup.sh — consistent, timestamped snapshot of a jig deployment.
#
# Backs up these, because losing any one of them loses something different:
#   1. jig_v002.db  — the block store. jig-server DERIVES this name from
#                     database_path by appending "_v002" to the file stem, so a
#                     configured /var/lib/jig/jig.db means the blocks people
#                     actually sent live in /var/lib/jig/jig_v002.db. jig.db
#                     itself is no longer used (#196) and is not backed up.
#   2. server.jigkey — the server's signing key, sealed (a configured
#                     server.key names server.jigkey beside it). Losing it
#                     changes the server's identity and breaks TOFU pinning for
#                     every client that ever connected. See deploy/README.md.
#      server.key.link* — the server's key link (JEP-0012, #241), when it
#                     has one: the configured key path with ".link" appended,
#                     plus earlier links kept beside it as .link.1, .link.2,
#                     ... and .link.pruned-N. It is what lets clients that pinned an older DID
#                     follow the server to this one; restored without it, they
#                     refuse it. The earlier links stop one DID being linked
#                     twice, and later form the chain clients follow.
#      server.retired-*.jigkey — keys a rotation retired, still sealed.
#   3. nameserver_v002.db and nameserver_v002.jigkey, when this box runs
#                     jig-nameserver. nameserver_v002.db holds the alias
#                     bindings; the key is the nameserver's signing key.
#                     Without it a restore gets a new nameserver DID, and every
#                     attestation the old one signed stops verifying for anyone
#                     whose delegation names the old DID. nameserver.db, the
#                     legacy registry, is no longer used and is not backed up:
#                     it holds a raw key (`ns_identity`).
#
# A sealed key restores only with a secret for one of its slots, and this
# backup does not hold one: that is the point of sealing it. Keep a slot that
# can open it on another machine (a passphrase kept offline) beside the one the
# server boots with: a TPM-bound systemd credential does not move with the disk.
# `jig-server keys show` lists the slots. A raw key (`[keys] storage =
# "plaintext"`) is still copied, with a warning: the snapshot then holds the
# key in clear.
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

snapshot_db "$JIG_STATE_DIR/jig_v002.db"
# Not strictly part of the server's state, but it lives on the same box and a
# lost alias store means every handle has to be re-registered.
snapshot_db "$JIG_STATE_DIR/nameserver_v002.db"

# --- the irreplaceable ones -------------------------------------------------
# The databases can be rebuilt from what people re-send. A key cannot be
# rebuilt from anything. If it is missing we do NOT quietly continue.
#
# copy_key PATH LABEL: copy the key PATH names. PATH may name the raw file
# (server.key) or the sealed one (server.jigkey); the sealed one is what a
# server reads, so it is preferred. The extension is taken from the file name
# alone, as the server does: /srv/jig.d/server names /srv/jig.d/server.jigkey.
#
# Returns 1 if neither file exists and 2 if one does but could not be copied.
# It runs with `set -e` off (it is called in a test), so every step that can
# fail says so itself: a key that was not copied is never counted.
key_notes=""
copy_key() {
    local path="$1" label="$2" dir base sealed raw src dest
    dir="$(dirname -- "$path")"
    base="$(basename -- "$path")"
    case "$base" in
        *.jigkey) sealed="$path"; raw="" ;;
        *.*)      sealed="$dir/${base%.*}.jigkey"; raw="$path" ;;
        *)        sealed="$dir/$base.jigkey"; raw="$path" ;;
    esac
    if [ -f "$sealed" ]; then
        src="$sealed"
    elif [ -n "$raw" ] && [ -f "$raw" ]; then
        src="$raw"
    else
        return 1
    fi
    dest="$DEST/$(basename -- "$src")"
    cp -p -- "$src" "$dest" || { log "ERROR: could not copy $src (is it readable by $(id -un)?)"; return 2; }
    chmod 600 -- "$dest" || { log "ERROR: could not chmod $dest"; return 2; }
    [ -s "$dest" ] || { log "ERROR: $dest is empty after copying $src"; return 2; }
    if [ "$src" = "$sealed" ]; then
        log "key:  $sealed -> $dest (sealed)"
        if [ -n "$raw" ] && [ -f "$raw" ]; then
            log "WARN: $raw is a raw copy of the $label key in clear beside its sealed copy;"
            log "      it is not backed up, and $label refuses to start until it is removed"
        fi
        key_notes="$key_notes $label=sealed"
    else
        log "key:  $raw -> $dest"
        log "WARN: the $label key is stored in clear, so this snapshot holds it in clear."
        log "      Seal it: $label keys seal --keyfile $raw --slot ..."
        key_notes="$key_notes $label=raw-in-clear"
    fi
    backed_up=$((backed_up + 1))
}

KEYFILE="${JIG_SERVER_KEYFILE:-$JIG_STATE_DIR/server.key}"
rc=0
copy_key "$KEYFILE" jig-server || rc=$?
case "$rc" in
    0) ;;
    1) die "server key $KEYFILE (or its .jigkey) not found — refusing to record a
    backup that omits the server identity. Set JIG_SERVER_KEYFILE to [server]
    server_did_keyfile if it lives elsewhere." ;;
    *) die "the server key could not be copied — refusing to record a backup
    without it" ;;
esac

# The server's key links, if it serves one: jig-server reads the current link
# from the configured key path with ".link" appended, and a rotation keeps the
# earlier ones beside it as .link.1, .link.2, ... (and .link.pruned-N, which are
# not served but still count against linking one DID twice). They are public (they hold no
# secret), but without them clients that pinned an earlier DID refuse the
# server. Keys a rotation retired are kept sealed beside the key; copy them too.
key_dir="$(dirname -- "$KEYFILE")"
key_stem="$(basename -- "$KEYFILE")"
key_stem="${key_stem%.*}"
links=0
retired=0
for extra in "$KEYFILE".link "$KEYFILE".link.[0-9]* "$KEYFILE".link.pruned-[0-9]* \
             "$key_dir/$key_stem".retired-*.jigkey; do
    [ -f "$extra" ] || continue
    cp -p -- "$extra" "$DEST/$(basename -- "$extra")" || die "could not copy $extra"
    case "$extra" in
        *.jigkey) chmod 600 -- "$DEST/$(basename -- "$extra")" || die "could not chmod a copy of $extra"
                  log "key:  $extra -> $DEST/ (retired, sealed)"; retired=$((retired + 1)) ;;
        *)        log "link: $extra -> $DEST/"; links=$((links + 1)) ;;
    esac
done
[ "$links" -eq 0 ] || key_notes="$key_notes jig-server-links=$links"
[ "$retired" -eq 0 ] || key_notes="$key_notes jig-server-retired=$retired"

# The nameserver's signing key. The nameserver is optional on a box, so a
# missing key is fatal only when its alias store exists: bindings without the
# key that signed them restore into a nameserver with a different DID. The
# nameserver reads the path from [v0_0_2.server] server_did_keyfile when that
# is set; set JIG_NAMESERVER_KEYFILE to the same path in that case.
NS_KEYFILE="${JIG_NAMESERVER_KEYFILE:-$JIG_STATE_DIR/nameserver_v002.key}"
rc=0
copy_key "$NS_KEYFILE" jig-nameserver || rc=$?
if [ "$rc" -eq 2 ]; then
    die "the nameserver key could not be copied — refusing to record a backup
    without it"
elif [ "$rc" -eq 1 ]; then
    if [ -f "$JIG_STATE_DIR/nameserver_v002.db" ]; then
        die "nameserver key $NS_KEYFILE (or its .jigkey) not found, but
    $JIG_STATE_DIR/nameserver_v002.db exists — refusing to record a backup of
    alias bindings without the key that signed them. Set JIG_NAMESERVER_KEYFILE
    if it lives elsewhere."
    fi
    log "skip: $NS_KEYFILE not present"
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
    printf 'keys=%s\n' "${key_notes# }"
    printf 'restore: a sealed key opens only with a secret for one of its slots (not in this snapshot);\n'
    printf '         `jig-server keys show --keyfile <file>` lists them\n'
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
