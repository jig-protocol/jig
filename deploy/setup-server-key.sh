#!/usr/bin/env bash
#
# setup-server-key.sh: seal a jig-server's or jig-nameserver's signing key so
# that it boots unattended from a systemd credential, with a passphrase slot
# kept offline for restoring on other hardware. deploy/README.md, "Sealing the
# server key", is the same procedure by hand.
#
#   sudo deploy/setup-server-key.sh [--nameserver] [options]
#
# What it does, in this order. Each step only adds (a slot, a file, a line),
# so a failure part way leaves what was there working as it did:
#
#   1. Makes the boot secret: 48 random bytes, encrypted with
#      `systemd-creds encrypt --with-key=auto` (the TPM2 when there is one,
#      otherwise the host key) into /etc/credstore.encrypted/<name>. An
#      existing credential is reused.
#   2. Makes the key or takes the one there is, so that both the credential and
#      the passphrase open it:
#        - no key:          `keys generate`. The key is never written in clear.
#        - a raw key:       `keys seal`, in place. The DID is kept.
#        - --import SEED:   a 32-byte seed from elsewhere, such as a key
#                           ceremony, sealed the same way. The DID is the seed's.
#        - a sealed key:    `keys verify` each secret, and `keys add-slot`
#                           whichever does not open it yet.
#   3. Hands the credential to the unit, in a drop-in, and runs daemon-reload.
#   4. Sets `unlock` in the config's [keys] ([v0_0_2.keys] for the nameserver).
#
# It never restarts the unit: that is the last step, and it says so.
#
# --rotate (jig-server only) replaces a key this script set up with a new one,
# in place: a new credential secret and a new offline passphrase seal the new
# key, and `jig-server keys rotate` writes a key link from the old DID to the
# new one beside it, so clients and peers that pinned the old DID follow it.
# The old key and the old credential are kept, never deleted. An earlier key
# link is kept beside the new one and served too, so a client pinned on any
# earlier DID follows every hop. Once the chain is as long as a client
# follows, rotating again needs --prune-oldest: a client still pinned on the
# oldest DID is then refused and must re-pin.
#
# Running it again changes nothing. It refuses to replace a credential, a key,
# or a different `unlock` it finds; --force moves the old credential and key
# aside (never deletes them) and starts again with a NEW DID.
#
# Secrets: the credential's plaintext only passes through pipes. The passphrase
# is read from the terminal, or from JIG_KEY_PASSPHRASE, and goes to the jig
# binary in its environment, never on a command line. Neither is printed or
# logged. Do not run this script with `bash -x`.
#
# Without systemd-creds (systemd older than 250) there is no credential to boot
# with. --passphrase-only then seals the key with the passphrase alone, and the
# server needs JIG_KEY_PASSPHRASE at every boot, which protects the key only as
# far as wherever that is kept is apart from the key.
#
set -euo pipefail
umask 077

ROLE=server
CONFIG=""
KEYFILE=""
IMPORT=""
FORCE=0
NO_PASSPHRASE=0
PASSPHRASE_ONLY=0
ROTATE=0
PRUNE_OLDEST=0

BIN_DIR="${JIG_BIN_DIR:-/opt/jig/bin}"
CREDSTORE="${JIG_CREDSTORE_DIR:-/etc/credstore.encrypted}"
UNIT_DIR="${JIG_UNIT_DIR:-/etc/systemd/system}"

usage() {
  cat <<'EOF'
usage: setup-server-key.sh [--nameserver] [--config PATH] [--keyfile PATH]
                           [--import SEED_FILE] [--no-passphrase]
                           [--passphrase-only] [--force]
                           [--rotate [--prune-oldest]]

  --nameserver       set up jig-nameserver's key instead of jig-server's
  --config PATH      the config to set `unlock` in
                     (default /etc/jig/config.toml, or
                     /etc/jig/jig-nameserver.toml for --nameserver)
  --keyfile PATH     the key (default: the config's server_did_keyfile)
  --import FILE      seal this raw 32-byte seed as the key, keeping its DID
  --no-passphrase    no offline passphrase slot (the key then has one slot,
                     and is lost with this machine's TPM or host key)
  --passphrase-only  no systemd credential: the passphrase is the only slot,
                     and the server needs JIG_KEY_PASSPHRASE to boot
  --force            move an existing credential and key aside and make new
                     ones: the server gets a NEW DID
  --rotate           jig-server only: replace the key with a new one and link
                     the old DID to it; the new passphrase is read from the
                     terminal or JIG_KEY_NEW_PASSPHRASE
  --prune-oldest     with --rotate, once the chain of key links is as long as
                     a client follows: stop serving the oldest. Clients still
                     pinned on the DID it leaves must re-pin
EOF
}

die() {
  echo "setup-server-key: error: $*" >&2
  exit 1
}
say() { echo "setup-server-key: $*"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --nameserver) ROLE=nameserver ;;
    --config) CONFIG="${2:?--config needs a path}"; shift ;;
    --keyfile) KEYFILE="${2:?--keyfile needs a path}"; shift ;;
    --import) IMPORT="${2:?--import needs a file}"; shift ;;
    --no-passphrase) NO_PASSPHRASE=1 ;;
    --passphrase-only) PASSPHRASE_ONLY=1 ;;
    --force) FORCE=1 ;;
    --rotate) ROTATE=1 ;;
    --replace-link) echo "setup-server-key: warning: --replace-link does nothing now: earlier key links are kept and served" >&2 ;;
    --prune-oldest) PRUNE_OLDEST=1 ;;
    -h | --help) usage; exit 0 ;;
    *) usage >&2; die "unknown argument: $1" ;;
  esac
  shift
done

[ "$NO_PASSPHRASE" = 1 ] && [ "$PASSPHRASE_ONLY" = 1 ] &&
  die "--no-passphrase and --passphrase-only leave the key with no slot"
[ "$PRUNE_OLDEST" = 1 ] && [ "$ROTATE" = 0 ] && die "--prune-oldest goes with --rotate"
if [ "$ROTATE" = 1 ]; then
  [ "$ROLE" = server ] ||
    die "--rotate is for jig-server: a nameserver serves no key link, so a new nameserver key is a new identity"
  { [ -z "$IMPORT" ] && [ "$FORCE" = 0 ] && [ "$PASSPHRASE_ONLY" = 0 ]; } ||
    die "--rotate does not combine with --import, --force or --passphrase-only (rotate by hand with \`jig-server keys rotate\`)"
fi

if [ "$ROLE" = server ]; then
  UNIT=jig-server.service
  BIN="$BIN_DIR/jig-server"
  CRED_NAME=jig-server-key
  CONFIG="${CONFIG:-/etc/jig/config.toml}"
  KEYS_SECTION=keys
  KEYFILE_SECTION=server
else
  UNIT=jig-nameserver.service
  BIN="$BIN_DIR/jig-nameserver"
  CRED_NAME=jig-nameserver-key
  CONFIG="${CONFIG:-/etc/jig/jig-nameserver.toml}"
  KEYS_SECTION=v0_0_2.keys
  KEYFILE_SECTION=v0_0_2.server
fi
CRED="$CREDSTORE/$CRED_NAME"
DROPIN_DIR="$UNIT_DIR/$UNIT.d"
DROPIN="$DROPIN_DIR/50-jig-key-credential.conf"
UNLOCK="credential:/run/credentials/$UNIT/$CRED_NAME"
[ "$PASSPHRASE_ONLY" = 1 ] && UNLOCK=passphrase

[ "$(id -u)" = 0 ] || die "run as root: it writes $CREDSTORE and $UNIT_DIR"
command -v systemctl >/dev/null || die "systemctl not found: this script is for systemd hosts"
[ -x "$BIN" ] || die "$BIN not found (set JIG_BIN_DIR to where the jig binaries are)"
[ -f "$CONFIG" ] || die "$CONFIG not found (--config names it)"
if [ "$PASSPHRASE_ONLY" = 0 ] && ! command -v systemd-creds >/dev/null; then
  die "systemd-creds not found (it comes with systemd 250 and later). Without it, \
--passphrase-only seals the key with a passphrase alone, which the server then needs \
in JIG_KEY_PASSPHRASE at every boot"
fi

TMP=""
cleanup() {
  [ -n "$TMP" ] && rm -rf "$TMP"
  unset JIG_KEY_PASSPHRASE JIG_KEY_NEW_PASSPHRASE PASS
}
trap cleanup EXIT
TMP="$(mktemp -d)"

# The value of `key = "..."` in `[section]` of a TOML file, or nothing.
toml_get() { # file section key
  awk -v want="$2" -v key="$3" '
    /^[[:space:]]*\[/ {
      s = $0; sub(/^[[:space:]]*\[[[:space:]]*/, "", s); sub(/[[:space:]]*\].*$/, "", s)
      in_sec = (s == want); next
    }
    in_sec && $0 ~ "^[[:space:]]*" key "[[:space:]]*=" {
      v = $0; sub(/^[^=]*=[[:space:]]*/, "", v); sub(/[[:space:]]*(#.*)?$/, "", v)
      gsub(/^"|"$/, "", v); print v; exit
    }' "$1"
}

# --- Where the key is -------------------------------------------------------
if [ -z "$KEYFILE" ]; then
  KEYFILE="$(toml_get "$CONFIG" "$KEYFILE_SECTION" server_did_keyfile)"
  # jig-nameserver reads jig-server's default keyfile as "not set".
  # shellcheck disable=SC2088 # the literal default, not a path to expand
  if [ "$ROLE" = nameserver ] && [ "$KEYFILE" = "~/.jig/server/server.key" ]; then
    KEYFILE=""
  fi
  if [ -z "$KEYFILE" ] && [ "$ROLE" = nameserver ]; then
    # As jig-nameserver resolves it: beside the database (the unit's
    # JIG_NS_DB_PATH, else [storage] database_path), named after its stem.
    db="$(systemctl show -p Environment --value "$UNIT" 2>/dev/null |
      tr ' ' '\n' | sed -n 's/^JIG_NS_DB_PATH=//p')" || true
    db="${db%%$'\n'*}"
    [ -n "$db" ] || db="$(toml_get "$CONFIG" storage database_path)"
    if [ -n "$db" ]; then
      db_base="${db##*/}"
      case "$db_base" in
        ?*.*) db_stem="${db_base%.*}" ;;
        *) db_stem="$db_base" ;;
      esac
      KEYFILE="${db%/*}/${db_stem}_v002.key"
    fi
  fi
  [ -n "$KEYFILE" ] || die "no server_did_keyfile in [$KEYFILE_SECTION] of $CONFIG: pass --keyfile"
fi
case "$KEYFILE" in
  /*) ;;
  *) die "the keyfile must be an absolute path, not $KEYFILE (pass --keyfile)" ;;
esac
# As the jig binaries name it: the configured path with its extension
# replaced by .jigkey.
dir="${KEYFILE%/*}"
base="${KEYFILE##*/}"
case "$base" in
  ?*.*) stem="${base%.*}" ;;
  *) stem="$base" ;;
esac
case "$base" in
  *.jigkey) SEALED="$KEYFILE"; RAW="$dir/$stem.key" ;;
  *) SEALED="$dir/$stem.jigkey"; RAW="$KEYFILE" ;;
esac
SERVICE_USER="$(systemctl show -p User --value "$UNIT" 2>/dev/null || true)"
SERVICE_USER="${SERVICE_USER:-jig}"
id "$SERVICE_USER" >/dev/null 2>&1 || die "$UNIT runs as $SERVICE_USER, who does not exist"

# --- Refuse what would be replaced, unless --force --------------------------
active_unlock="$(toml_get "$CONFIG" "$KEYS_SECTION" unlock)"
if [ -n "$active_unlock" ] && [ "$active_unlock" != "$UNLOCK" ] && [ "$FORCE" = 0 ]; then
  die "[$KEYS_SECTION] unlock in $CONFIG is already set to something else; \
this script sets it to \"$UNLOCK\". Remove it, or pass --force"
fi
if [ "$(toml_get "$CONFIG" "$KEYS_SECTION" storage)" = plaintext ]; then
  die "[$KEYS_SECTION] storage = \"plaintext\" in $CONFIG: remove it first"
fi
if [ -n "$IMPORT" ]; then
  [ -f "$IMPORT" ] || die "$IMPORT not found"
  [ "$(wc -c <"$IMPORT")" -eq 32 ] || die "$IMPORT is not a raw 32-byte seed"
  if { [ -e "$SEALED" ] || [ -e "$RAW" ]; } && [ "$FORCE" = 0 ]; then
    die "there is already a key at $SEALED or $RAW; --import would replace it \
and change the DID. Move it away, or pass --force"
  fi
fi

stamp="$(date -u +%Y%m%dT%H%M%SZ)"
aside() { # path
  if [ -e "$1" ]; then
    mv -- "$1" "$1.replaced-$stamp"
    say "moved $1 aside to $1.replaced-$stamp (not deleted)"
  fi
}
if [ "$FORCE" = 1 ]; then
  if [ -e "$SEALED" ] || [ -e "$RAW" ] || [ -e "$CRED" ]; then
    say "--force: the server will get a NEW DID, and every client that pinned the old one will refuse it"
  fi
  if [ "$PASSPHRASE_ONLY" = 0 ]; then aside "$CRED"; fi
  aside "$SEALED"
  aside "$RAW"
fi

# --- The passphrase ---------------------------------------------------------
PASS=""
# A rotation seals a new key: its passphrase is a new one, not the old key's.
PASS_VAR=JIG_KEY_PASSPHRASE
[ "$ROTATE" = 1 ] && PASS_VAR=JIG_KEY_NEW_PASSPHRASE
if [ "$NO_PASSPHRASE" = 0 ]; then
  if [ -n "${!PASS_VAR:-}" ]; then
    PASS="${!PASS_VAR}"
  elif [ -r /dev/tty ]; then
    say "the passphrase is the key's offline slot: it opens the key on other hardware."
    [ "$ROTATE" = 1 ] && say "this is the NEW key's passphrase; choose a new one."
    read -rs -p "passphrase: " PASS </dev/tty; echo >/dev/tty
    read -rs -p "again: " again </dev/tty; echo >/dev/tty
    [ "$PASS" = "$again" ] || { unset again; die "the two passphrases differ"; }
    unset again
  else
    die "no terminal to read a passphrase from: set $PASS_VAR, or pass --no-passphrase"
  fi
  [ ${#PASS} -ge 12 ] || die "the passphrase is shorter than 12 characters"
fi
unset JIG_KEY_PASSPHRASE JIG_KEY_NEW_PASSPHRASE JIG_KEY_UNLOCK

# Run the jig binary on the key. Only what is offered here opens it: not the
# configured unlock (its /run/credentials path is the unit's, and absent here),
# nor anything else in this shell's environment.
jig_keys() {
  env -u JIG_KEY_UNLOCK -u JIG_KEY_PASSPHRASE \
    "$BIN" --config "$CONFIG" keys "$@" --keyfile "$KEYFILE"
}
# The same with the passphrase in the environment, where `--slot passphrase`
# and the opening of the key read it. Never on the command line.
jig_keys_pass() {
  if [ -n "$PASS" ]; then
    JIG_KEY_PASSPHRASE="$PASS" "$BIN" --config "$CONFIG" keys "$@" --keyfile "$KEYFILE"
  else
    "$BIN" --config "$CONFIG" keys "$@" --keyfile "$KEYFILE"
  fi
}
# A `--slot` that reads the credential's plaintext from a pipe, decrypted now.
# Each use is read once, so each call to the binary gets its own.
decrypt() { systemd-creds decrypt --name="$CRED_NAME" "$CRED" -; }

# --- --rotate ------------------------------------------------------------------
if [ "$ROTATE" = 1 ]; then
  [ -e "$SEALED" ] || die "no sealed key at $SEALED to rotate: run this script without --rotate first"
  [ -e "$RAW" ] && die "both $RAW and $SEALED exist; \`$BIN keys show\` or a boot says which to keep"
  [ -e "$CRED" ] || die "no credential at $CRED to open the key with: run this script without --rotate first"
  decrypt >/dev/null || die "$CRED does not decrypt on this machine (made on another?)"
  [ -e "$CRED.new" ] &&
    die "$CRED.new exists, left by an interrupted --rotate: if $SEALED opens with it (\`keys verify\`), it is the credential to keep; otherwise remove it"
  # The new secret is in the credstore before the key needs it, so no step
  # can leave the new key with its credential only in a temporary file.
  head -c 48 /dev/urandom | base64 -w0 |
    systemd-creds encrypt --with-key=auto --name="$CRED_NAME" - "$TMP/cred"
  mv -- "$TMP/cred" "$CRED.new"
  # The old credential is kept under its retired name before anything moves:
  # after the rotation one rename, which replaces atomically, puts the new
  # one in place.
  ln -- "$CRED" "$CRED.retired-$stamp" || {
    rm -f -- "$CRED.new"
    die "could not keep $CRED as $CRED.retired-$stamp; nothing was changed"
  }
  rotate_args=(--slot "credential:/dev/fd/3")
  if [ "$NO_PASSPHRASE" = 0 ]; then rotate_args+=(--slot passphrase); fi
  if [ "$PRUNE_OLDEST" = 1 ]; then rotate_args+=(--prune-oldest); fi
  # The old key opens with the old credential, on fd 4; the new one is sealed
  # with the new credential, on fd 3, and the new passphrase.
  if ! env -u JIG_KEY_PASSPHRASE JIG_KEY_UNLOCK="credential:/dev/fd/4" \
    JIG_KEY_NEW_PASSPHRASE="$PASS" \
    "$BIN" --config "$CONFIG" keys rotate --keyfile "$KEYFILE" "${rotate_args[@]}" \
    3< <(systemd-creds decrypt --name="$CRED_NAME" "$CRED.new" -) 4< <(decrypt); then
    rm -f -- "$CRED.new" "$CRED.retired-$stamp"
    die "the key was not rotated; nothing was changed"
  fi
  mv -f -- "$CRED.new" "$CRED" ||
    die "the key was rotated, but $CRED.new could not be moved to $CRED. The new key opens \
with $CRED.new (and the new passphrase): run \`mv -f $CRED.new $CRED\` before restarting"
  say "the old credential is kept as $CRED.retired-$stamp: with it, or the old passphrase, the retired key still opens. Move both offline; delete neither"
  echo
  jig_keys show
  echo
  say "next: systemctl restart $UNIT. Clients and peers that pinned the old DID follow the key link to the new one"
  if [ "$NO_PASSPHRASE" = 0 ]; then
    say "MUST DO NOW: store the NEW passphrase offline. The old one opens only the retired key"
  fi
  exit 0
fi

# --- 1. The credential ------------------------------------------------------
if [ "$PASSPHRASE_ONLY" = 0 ]; then
  if [ -e "$CRED" ]; then
    say "reusing the credential $CRED"
    decrypt >/dev/null || die "$CRED does not decrypt on this machine (made on another?)"
  else
    install -d -m 0700 "$CREDSTORE"
    head -c 48 /dev/urandom | base64 -w0 |
      systemd-creds encrypt --with-key=auto --name="$CRED_NAME" - "$TMP/cred"
    mv -- "$TMP/cred" "$CRED"
    if systemd-creds has-tpm2 >/dev/null 2>&1; then
      say "made $CRED, bound to this machine's TPM2"
    else
      say "made $CRED, encrypted with the host key in /var/lib/systemd/credential.secret (no TPM2): it protects the key from a copy of /var/lib/jig, not from a copy of the whole disk"
    fi
  fi
fi

# --- 2. The key ---------------------------------------------------------------
slots=()
if [ "$PASSPHRASE_ONLY" = 0 ]; then slots+=(--slot "credential:/dev/fd/3"); fi
if [ "$NO_PASSPHRASE" = 0 ]; then slots+=(--slot passphrase); fi

# Runs `keys <action> <slots>` with the credential on fd 3 when there is one.
with_slots() { # action
  if [ "$PASSPHRASE_ONLY" = 0 ]; then
    jig_keys_pass "$1" "${slots[@]}" 3< <(decrypt)
  else
    jig_keys_pass "$1" "${slots[@]}"
  fi
}

if [ -n "$IMPORT" ]; then
  install -m 0600 -o "$SERVICE_USER" -- "$IMPORT" "$RAW"
  if ! with_slots seal; then
    # Not left behind as a second copy of the seed in clear.
    rm -f -- "$RAW" || die "sealing the imported seed failed; remove the copy at $RAW by hand"
    die "sealing the imported seed failed; the copy at $RAW was removed"
  fi
  say "imported the seed from $IMPORT. That file still holds the key in clear: destroy it, or keep it offline as carefully as the passphrase"
elif [ -e "$SEALED" ]; then
  [ -e "$RAW" ] && die "both $RAW and $SEALED exist; \`$BIN keys show\` or a boot says which to keep"
  have_pass=0
  case "$(jig_keys show)" in *"a passphrase slot"*) have_pass=1 ;; esac
  if [ "$PASSPHRASE_ONLY" = 0 ]; then
    if jig_keys verify --slot "credential:/dev/fd/3" 3< <(decrypt) >/dev/null 2>&1; then
      say "the credential already opens $SEALED"
    else
      [ "$NO_PASSPHRASE" = 0 ] ||
        die "the credential does not open $SEALED, and with --no-passphrase there is nothing to open it with to add it"
      jig_keys_pass verify --slot passphrase >/dev/null ||
        die "the passphrase does not open $SEALED, so the credential cannot be added"
      # Opened by the passphrase, in the environment.
      jig_keys_pass add-slot --slot "credential:/dev/fd/3" 3< <(decrypt)
    fi
  fi
  if [ "$NO_PASSPHRASE" = 0 ]; then
    if [ "$have_pass" = 1 ]; then
      jig_keys_pass verify --slot passphrase >/dev/null ||
        die "$SEALED has a passphrase slot, and this passphrase does not open it"
      say "the passphrase already opens $SEALED"
    elif [ "$PASSPHRASE_ONLY" = 1 ]; then
      die "$SEALED has no passphrase slot, and with --passphrase-only there is nothing to open it with to add one"
    else
      # Opened by the credential, which is the only secret offered.
      JIG_KEY_UNLOCK="credential:/dev/fd/3" jig_keys_pass add-slot --slot passphrase 3< <(decrypt)
    fi
  fi
elif [ -e "$RAW" ]; then
  with_slots seal
else
  [ -d "$dir" ] || install -d -m 0750 -o "$SERVICE_USER" "$dir"
  with_slots generate >/dev/null
  say "made a new key"
fi
chown "$SERVICE_USER": "$SEALED"
chmod 0600 "$SEALED"

# --- 3. The unit --------------------------------------------------------------
if [ "$PASSPHRASE_ONLY" = 0 ]; then
  line="LoadCredentialEncrypted=$CRED_NAME:$CRED"
  current="$(systemctl cat "$UNIT" 2>/dev/null | grep -E "^LoadCredentialEncrypted=$CRED_NAME:" || true)"
  if [ "$current" = "$line" ]; then
    say "$UNIT already loads the credential"
  elif [ -n "$current" ] && ! grep -qxF "$current" "$DROPIN" 2>/dev/null; then
    die "$UNIT already has '$current', which is not this script's; make it '$line' by hand"
  else
    install -d -m 0755 "$DROPIN_DIR"
    printf '# Written by deploy/setup-server-key.sh. [%s] unlock in %s names it.\n[Service]\n%s\n' \
      "$KEYS_SECTION" "$CONFIG" "$line" >"$TMP/dropin"
    install -m 0644 "$TMP/dropin" "$DROPIN"
    systemctl daemon-reload
    say "wrote $DROPIN"
  fi
fi

# --- 4. The config ------------------------------------------------------------
if [ "$(toml_get "$CONFIG" "$KEYS_SECTION" unlock)" = "$UNLOCK" ]; then
  say "$CONFIG already says unlock = \"$UNLOCK\""
else
  # An active `unlock` (only there with --force) is replaced; otherwise the
  # first commented one, or the line goes at the end of the section.
  active=0
  if [ -n "$(toml_get "$CONFIG" "$KEYS_SECTION" unlock)" ]; then active=1; fi
  awk -v want="$KEYS_SECTION" -v line="unlock = \"$UNLOCK\"" -v active="$active" '
    /^[[:space:]]*\[/ {
      if (in_sec && !done) { print line; done = 1 }
      s = $0; sub(/^[[:space:]]*\[[[:space:]]*/, "", s); sub(/[[:space:]]*\].*$/, "", s)
      in_sec = (s == want)
      print
      next
    }
    in_sec && active && /^[[:space:]]*unlock[[:space:]]*=/ {
      if (!done) { print line; done = 1 }
      next
    }
    in_sec && !active && !done && /^[[:space:]]*#[[:space:]]*unlock[[:space:]]*=/ {
      print line; done = 1; next
    }
    { print }
    END {
      if (in_sec && !done) { print line; done = 1 }
      if (!done) { print ""; print "[" want "]"; print line }
    }' "$CONFIG" >"$TMP/config"
  cp -p -- "$CONFIG" "$CONFIG.before-setup-server-key-$stamp"
  # Beside the config, with its owner and mode, then renamed over it.
  new="$(mktemp "$CONFIG.XXXXXX")"
  cat "$TMP/config" >"$new"
  chown --reference="$CONFIG" "$new"
  chmod --reference="$CONFIG" "$new"
  mv -- "$new" "$CONFIG"
  say "set [$KEYS_SECTION] unlock = \"$UNLOCK\" in $CONFIG (the old one is $CONFIG.before-setup-server-key-$stamp)"
fi

# --- Done ---------------------------------------------------------------------
echo
jig_keys show
echo
say "next: systemctl restart $UNIT, and check that /.well-known/jig names the DID above"
if [ "$PASSPHRASE_ONLY" = 1 ]; then
  say "the server needs JIG_KEY_PASSPHRASE at every boot (EnvironmentFile= at 0600, or a secret manager). It protects the key only as far as that is kept apart from the key"
fi
if [ "$NO_PASSPHRASE" = 1 ]; then
  say "WARNING: the key has one slot, the credential. Losing this machine's TPM or host key loses the key and its DID. Add an offline passphrase: rerun without --no-passphrase"
else
  say "MUST DO NOW: store the passphrase offline (a password manager, or paper in a safe). It is the only thing that opens this key on other hardware: the credential does not leave this machine"
fi
