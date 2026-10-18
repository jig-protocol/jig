#!/usr/bin/env bash
# test-install-key-fallback.sh: how install.sh seals the identity key when jig
# cannot (exit status 78), checked against a stub `jig`, with and without a
# terminal. Needs util-linux `script` for the pseudo-terminal.
#
#   - a person at the terminal, keychain expected but failing: install.sh asks
#     for a passphrase and every jig call gets it; never plaintext;
#   - nobody at a terminal: plaintext, with the UNENCRYPTED banner.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
t="$(mktemp -d)"
trap 'rm -rf "$t"' EXIT
mkdir -p "$t/home/.jig/bin" "$t/fakebin"

cat > "$t/home/.jig/bin/jig" <<'STUB'
#!/usr/bin/env bash
case "$1" in
  init)
    [ -n "${JIG_KEY_PASSPHRASE:-}" ] && { echo "init sealed" >> "$STUB_LOG"; exit 0; }
    [ "${JIG_KEYS_STORAGE:-}" = plaintext ] && { echo "init plaintext" >> "$STUB_LOG"; exit 0; }
    exit 78 ;;
  *) echo "$1 pass=${JIG_KEY_PASSPHRASE:+set} storage=${JIG_KEYS_STORAGE:-}" >> "$STUB_LOG" ;;
esac
STUB
chmod +x "$t/home/.jig/bin/jig"
# A keychain that seems present, so install.sh does not ask up front.
printf '#!/bin/sh\nexit 0\n' > "$t/fakebin/secret-tool"
chmod +x "$t/fakebin/secret-tool"

{ sed '$d' "$root/install.sh"; cat <<RUN
server_scheme() { echo http; }
export HOME="$t/home" JIG_HOME="$t/home/.jig" STUB_LOG="$t/log" JIG_NONINTERACTIVE=1
hello_world
RUN
} > "$t/run.sh"

fail() { echo "FAIL: $*" >&2; cat "$t/log" >&2 || true; exit 1; }

echo "== terminal present, keychain fails: passphrase, never plaintext"
printf 'pw\rpw\r' | PATH="$t/fakebin:$PATH" DBUS_SESSION_BUS_ADDRESS=unix:path=/x \
  script -qec "bash $t/run.sh" /dev/null > "$t/tty.out"
grep -q "init sealed" "$t/log" || fail "init was not sealed with the passphrase"
grep -q "plaintext" "$t/log" && fail "fell back to plaintext with a person present"
grep -q "send pass=set" "$t/log" || fail "later jig calls did not get the passphrase"

echo "== no terminal: plaintext, loudly"
rm -f "$t/log" "$t/home/.jig/cli.toml"
setsid -w bash "$t/run.sh" < /dev/null > "$t/notty.out" 2>&1
grep -q "init plaintext" "$t/log" || fail "headless init did not fall back to plaintext"
grep -q "UNENCRYPTED" "$t/notty.out" || fail "no UNENCRYPTED banner"
echo "PASS"
