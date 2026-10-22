#!/usr/bin/env bash
# test-setup-server-key.sh BIN_DIR: deploy/setup-server-key.sh against the real
# jig-server and jig-nameserver in BIN_DIR, with stub systemctl and
# systemd-creds. Run as root (it chowns the key to the unit's user, here the
# caller). Checks:
#
#   - a fresh server: credential, sealed key with both slots, drop-in, unlock;
#   - running it again changes nothing; a wrong passphrase changes nothing;
#   - a raw key is sealed in place and keeps its DID, the same as --import;
#   - a ceremony key sealed with a passphrase alone gains the credential;
#   - a different unlock, or --import over a key, is refused;
#   - --force moves the old key aside and makes a new DID;
#   - the nameserver's [v0_0_2.keys];
#   - no output ever holds the passphrase or the credential's plaintext.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
bin="$(cd "${1:?usage: $0 BIN_DIR}" && pwd)"
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }
t="$(mktemp -d)"
trap 'rm -rf "$t"' EXIT
script="$root/deploy/setup-server-key.sh"
PASS='correct horse battery staple'
me="$(id -un)"

mkdir -p "$t/fakebin"
# systemd-creds: "encrypts" by prefixing; the secret itself is logged so the
# test can look for it in the script's output.
cat >"$t/fakebin/systemd-creds" <<'STUB'
#!/usr/bin/env bash
set -e
case "$1" in
  encrypt) secret="$(cat)"; printf '%s' "$secret" >>"$STUB_DIR/secrets"; printf 'FAKE:%s' "$secret" >"${@: -1}" ;;
  decrypt) sed 's/^FAKE://' "${@: -2:1}" ;;
  has-tpm2) exit 1 ;;
  *) exit 2 ;;
esac
STUB
cat >"$t/fakebin/systemctl" <<'STUB'
#!/usr/bin/env bash
case "$1" in
  show) [ "$3" = User ] && echo "$STUB_USER"
        [ "$3" = Environment ] && echo "JIG_NS_DB_PATH=${STUB_NS_DB:-$STUB_DIR/ns/nameserver.db}" ;;
  cat) cat "$JIG_UNIT_DIR/$2.d/"*.conf 2>/dev/null ;;
  daemon-reload) echo reload >>"$STUB_DIR/reloads" ;;
esac
STUB
chmod +x "$t/fakebin/"*
export PATH="$t/fakebin:$PATH" STUB_DIR="$t" STUB_USER="$me" JIG_BIN_DIR="$bin"

fail() { echo "FAIL: $*" >&2; exit 1; }
# A fresh host: config, credstore and unit dir under $1.
host() {
  mkdir -p "$1/etc" "$1/units" "$1/var"
  sed "s#/var/lib/jig/server.key#$1/var/server.key#" "$root/deploy/config.example.toml" >"$1/etc/config.toml"
}
run() { # host-dir args...
  local h="$1"; shift
  JIG_CREDSTORE_DIR="$h/credstore" JIG_UNIT_DIR="$h/units" \
    JIG_KEY_PASSPHRASE="${P-$PASS}" "$script" --config "$h/etc/config.toml" "$@" \
    </dev/null >"$h/out" 2>&1
}
show() { "$bin/jig-server" --config "$1/etc/config.toml" keys show --keyfile "$1/var/server.key"; }
did_of() { show "$1" | head -n1; }
sums() { (cd "$1" && find credstore units var etc -type f ! -name '*.before-*' -exec sha256sum {} + | sort); }

# Fresh server.
h="$t/a"; host "$h"
run "$h" || { cat "$h/out"; fail "fresh setup"; }
[ -s "$h/credstore/jig-server-key" ] || fail "no credential"
[ -s "$h/var/server.jigkey" ] && [ ! -e "$h/var/server.key" ] || fail "no sealed key, or a raw one"
[ "$(stat -c %a "$h/var/server.jigkey")" = 600 ] || fail "key mode"
show "$h" | grep -q "a credential slot, a passphrase slot" || { show "$h"; fail "slots"; }
grep -qx "LoadCredentialEncrypted=jig-server-key:$h/credstore/jig-server-key" "$h/units/jig-server.service.d/"*.conf || fail "drop-in"
grep -qx 'unlock = "credential:/run/credentials/jig-server.service/jig-server-key"' "$h/etc/config.toml" || fail "unlock"
[ "$(grep -c '^\[keys\]' "$h/etc/config.toml")" = 1 ] || fail "one [keys]"
JIG_KEY_PASSPHRASE="$PASS" "$bin/jig-server" --config "$h/etc/config.toml" keys verify --slot passphrase --keyfile "$h/var/server.key" >/dev/null || fail "passphrase opens it"
grep -q "MUST DO NOW" "$h/out" || fail "the must-do line"
cp "$h/out" "$t/all-out"

# Again: nothing changes.
before="$(sums "$h")"; did="$(did_of "$h")"
run "$h" || { cat "$h/out"; fail "rerun"; }
[ "$(sums "$h")" = "$before" ] || fail "a rerun changed something"
cat "$h/out" >>"$t/all-out"
# A wrong passphrase: refused, nothing changes.
if P='not the passphrase at all' run "$h"; then fail "a wrong passphrase was accepted"; fi
grep -q "does not open" "$h/out" || { cat "$h/out"; fail "wrong passphrase message"; }
[ "$(sums "$h")" = "$before" ] || fail "a refused run changed something"
cat "$h/out" >>"$t/all-out"

# A different unlock is refused.
h2="$t/b"; host "$h2"
sed -i 's|^# *unlock = .*|unlock = "env:SOMETHING"|' "$h2/etc/config.toml"
grep -q '^unlock = "env:SOMETHING"' "$h2/etc/config.toml" || fail "test setup: no unlock line to replace"
if run "$h2"; then fail "a different unlock was replaced"; fi
[ ! -e "$h2/var/server.jigkey" ] && [ ! -e "$h2/credstore" ] || fail "a refused run wrote something"
cat "$h2/out" >>"$t/all-out"

# --force over a different unlock replaces it: one unlock, ours.
run "$h2" --force || { cat "$h2/out"; fail "--force over a different unlock"; }
[ "$(grep -c '^unlock = ' "$h2/etc/config.toml")" = 1 ] || fail "two unlock lines"
grep -qx 'unlock = "credential:/run/credentials/jig-server.service/jig-server-key"' "$h2/etc/config.toml" || fail "--force unlock"
show "$h2" >/dev/null || fail "--force config does not load"

# A raw key keeps its DID, the same one --import gives.
head -c 32 /dev/urandom >"$t/seed"
h3="$t/c"; host "$h3"
install -m 0600 "$t/seed" "$h3/var/server.key"
run "$h3" || { cat "$h3/out"; fail "sealing a raw key"; }
[ ! -e "$h3/var/server.key" ] || fail "the raw key is left"
h4="$t/d"; host "$h4"
run "$h4" --import "$t/seed" || { cat "$h4/out"; fail "--import"; }
[ "$(did_of "$h3")" = "$(did_of "$h4")" ] || fail "seal and --import give different DIDs"
if run "$h4" --import "$t/seed"; then fail "--import over a key"; fi
cat "$h3/out" "$h4/out" >>"$t/all-out"

# A ceremony key, sealed with a passphrase alone, gains the credential.
h5="$t/e"; host "$h5"
JIG_KEY_PASSPHRASE="$PASS" "$bin/jig-server" --config "$h5/etc/config.toml" keys generate --slot passphrase --keyfile "$h5/var/server.key" >/dev/null
cdid="$(did_of "$h5")"
run "$h5" || { cat "$h5/out"; fail "adding the credential to a ceremony key"; }
show "$h5" | grep -q "a passphrase slot, a credential slot" || { show "$h5"; fail "ceremony slots"; }
[ "$(did_of "$h5")" = "$cdid" ] || fail "the ceremony DID changed"
cat "$h5/out" >>"$t/all-out"

# --force: a new DID, the old key moved aside.
run "$h" --force || { cat "$h/out"; fail "--force"; }
[ "$(did_of "$h")" != "$did" ] || fail "--force kept the DID"
compgen -G "$h/var/server.jigkey.replaced-*" >/dev/null || fail "the old key was not kept"
compgen -G "$h/credstore/jig-server-key.replaced-*" >/dev/null || fail "the old credential was not kept"
cat "$h/out" >>"$t/all-out"

# The nameserver, keyfile beside its database as the unit sets it.
h6="$t/f"; mkdir -p "$h6/etc" "$h6/units" "$t/ns"
cp "$root/deploy/jig-nameserver.example.toml" "$h6/etc/config.toml"
JIG_CREDSTORE_DIR="$h6/credstore" JIG_UNIT_DIR="$h6/units" JIG_KEY_PASSPHRASE="$PASS" \
  "$script" --nameserver --config "$h6/etc/config.toml" </dev/null >"$h6/out" 2>&1 ||
  { cat "$h6/out"; fail "nameserver"; }
[ -s "$t/ns/nameserver_v002.jigkey" ] || fail "no nameserver key"
[ -s "$h6/credstore/jig-nameserver-key" ] || fail "no nameserver credential"
grep -qx "LoadCredentialEncrypted=jig-nameserver-key:$h6/credstore/jig-nameserver-key" \
  "$h6/units/jig-nameserver.service.d/"*.conf || fail "nameserver drop-in"
awk '/^\[v0_0_2.keys\]/{s=1;next} /^\[/{s=0} s' "$h6/etc/config.toml" |
  grep -qx 'unlock = "credential:/run/credentials/jig-nameserver.service/jig-nameserver-key"' || fail "nameserver unlock"
cat "$h6/out" >>"$t/all-out"

# The nameserver's own resolution: jig-server's default keyfile reads as
# unset, and the key is named after the database's stem, whatever its
# extension.
h7="$t/g"; mkdir -p "$h7/etc" "$h7/units" "$t/ns2"
cp "$root/deploy/jig-nameserver.example.toml" "$h7/etc/config.toml"
printf '\n[v0_0_2.server]\nserver_did_keyfile = "~/.jig/server/server.key"\n' >>"$h7/etc/config.toml"
STUB_NS_DB="$t/ns2/nameserver.sqlite" JIG_CREDSTORE_DIR="$h7/credstore" JIG_UNIT_DIR="$h7/units" \
  JIG_KEY_PASSPHRASE="$PASS" "$script" --nameserver --config "$h7/etc/config.toml" \
  </dev/null >"$h7/out" 2>&1 || { cat "$h7/out"; fail "nameserver with the default keyfile"; }
[ -s "$t/ns2/nameserver_v002.jigkey" ] || { ls "$t/ns2"; fail "nameserver key beside a .sqlite database"; }
cat "$h7/out" >>"$t/all-out"

# No secret in any output.
grep -qF "$PASS" "$t/all-out" && fail "the passphrase was printed"
while IFS= read -r -n 64 secret; do
  [ -n "$secret" ] && grep -qF "$secret" "$t/all-out" && fail "a credential was printed"
done <"$t/secrets"
echo "setup-server-key.sh: all checks passed"
