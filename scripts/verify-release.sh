#!/usr/bin/env bash
# Verify a published jig release the way a careful user would, before
# announcing it.
#
# Usage: scripts/verify-release.sh TAG
#
# For TAG it checks, and fails loudly on the first mismatch:
#   1. The GitHub Release exists, is published (not a draft), is marked
#      prerelease, and is titled TAG.
#   2. Its assets are exactly install.sh, SHA256SUMS, SHA256SUMS.sig and one
#      tarball per built target.
#   3. SHA256SUMS.sig is a valid `ssh-keygen -Y` signature of SHA256SUMS by
#      the release key (.github/release/allowed_signers, principal and
#      namespace "jig-release").
#   4. Every asset but SHA256SUMS and its signature matches its line in
#      SHA256SUMS, and SHA256SUMS lists nothing that was not published.
#   5. The key pinned in the release's own install.sh is that same key.
#   6. The verified install.sh installs the verified tarballs (served from
#      the download directory, so nothing is fetched twice) into a scratch
#      JIG_HOME, and `jig --version` and `jig-server --version` name TAG.
#
# Env: JIG_REPO (default jig-protocol/jig); JIG_GITHUB_TOKEN or GITHUB_TOKEN,
# optional, for the API's rate limit; JIG_VERIFY_EXPECT_VERSION, the version
# the binaries must report (default: TAG without its leading v);
# JIG_VERIFY_SUMS, a local SHA256SUMS to use in place of the published one
# (to check that a tampered copy fails); JIG_VERIFY_KEEP=1 keeps the scratch
# directory.
#
# It prints only public material: the release key's fingerprint and the
# assets' hashes. Nothing it runs needs a secret.
set -euo pipefail

TAG="${1:?usage: $0 TAG}"
JIG_REPO="${JIG_REPO:-jig-protocol/jig}"
EXPECT_VERSION="${JIG_VERIFY_EXPECT_VERSION:-${TAG#v}}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ALLOWED_SIGNERS="$ROOT/.github/release/allowed_signers"
# One tarball per target built by .github/workflows/release.yml.
TARBALLS=(jig-linux-x86_64.tar.gz jig-linux-aarch64.tar.gz jig-darwin-aarch64.tar.gz)

fail() { echo "FAIL: $*" >&2; exit 1; }
ok() { echo "ok: $*"; }

for tool in curl python3 ssh-keygen tar; do
  command -v "$tool" >/dev/null || fail "$tool is needed"
done
if command -v sha256sum >/dev/null; then sha256() { sha256sum "$1" | cut -d' ' -f1; }
else sha256() { shasum -a 256 "$1" | cut -d' ' -f1; }; fi

work="$(mktemp -d "${TMPDIR:-/tmp}/jig-verify-release.XXXXXX")"
# shellcheck disable=SC2329 # run by the EXIT trap
cleanup() { if [ "${JIG_VERIFY_KEEP:-0}" = 1 ]; then echo "kept $work"; else rm -rf "$work"; fi; }
trap cleanup EXIT
dl="$work/dist"
mkdir -p "$dl"

token="${JIG_GITHUB_TOKEN:-${GITHUB_TOKEN:-}}"
api() {
  # The token only ever goes to the API host, in a header, never on a
  # command line other processes can read.
  if [ -n "$token" ]; then
    curl -fsSL -H @- "https://api.github.com/$1" <<<"Authorization: Bearer $token"
  else
    curl -fsSL "https://api.github.com/$1"
  fi
}

# --- 1. the release ------------------------------------------------------------

api "repos/$JIG_REPO/releases/tags/$TAG" > "$work/release.json" \
  || fail "no published release $TAG in $JIG_REPO (a draft is not visible here either)"
python3 - "$work/release.json" "$TAG" "$work/assets.tsv" <<'PY' || exit 1
import json, sys
path, tag, out = sys.argv[1:]
r = json.load(open(path))
def fail(msg):
    print(f"FAIL: {msg}", file=sys.stderr)
    sys.exit(1)
if r.get("draft"):
    fail(f"{tag} is still a draft")
if not r.get("prerelease"):
    fail(f"{tag} is not marked prerelease")
if r.get("name") != tag:
    fail(f"{tag} is titled {r.get('name')!r}, not {tag!r}")
with open(out, "w") as f:
    for a in r.get("assets", []):
        f.write(f"{a['name']}\t{a['size']}\t{a['browser_download_url']}\n")
print(f"ok: {tag} is a published prerelease titled {tag}")
PY

# --- 2. the assets ---------------------------------------------------------------

want="$(printf '%s\n' install.sh SHA256SUMS SHA256SUMS.sig "${TARBALLS[@]}" | sort)"
have="$(cut -f1 "$work/assets.tsv" | sort)"
[ "$have" = "$want" ] || fail "$TAG's assets are not the expected set:
$(diff <(echo "$want") <(echo "$have") | sed -n 's/^[<>]/ &/p') (< expected, > published)"
while IFS=$'\t' read -r name size url; do
  # Download URLs redirect to GitHub's asset host; curl follows them.
  curl -fsSL -o "$dl/$name" "$url" || fail "could not download $name"
  [ "$(wc -c < "$dl/$name" | tr -d ' ')" = "$size" ] || fail "$name is not the size the release lists ($size bytes)"
done < "$work/assets.tsv"
ok "downloaded the $(wc -l < "$work/assets.tsv" | tr -d ' ') assets"

if [ -n "${JIG_VERIFY_SUMS:-}" ]; then
  cp "$JIG_VERIFY_SUMS" "$dl/SHA256SUMS"
  echo "note: using $JIG_VERIFY_SUMS in place of the published SHA256SUMS"
fi

# --- 3. the signature ------------------------------------------------------------

key_fpr="$(ssh-keygen -lf <(cut -d' ' -f3- "$ALLOWED_SIGNERS") | awk '{print $2}')"
echo "release key: $key_fpr (.github/release/allowed_signers)"
ssh-keygen -Y verify -f "$ALLOWED_SIGNERS" -I jig-release -n jig-release \
  -s "$dl/SHA256SUMS.sig" < "$dl/SHA256SUMS" >/dev/null 2>&1 \
  || fail "SHA256SUMS.sig is not the release key's signature of SHA256SUMS"
ok "SHA256SUMS is signed by the release key"

# --- 4. the checksums ------------------------------------------------------------

listed=0
while read -r hash name; do
  name="${name#\*}"
  [ -f "$dl/$name" ] || fail "SHA256SUMS lists $name, which the release does not publish"
  case "$name" in SHA256SUMS | SHA256SUMS.sig) fail "SHA256SUMS lists $name" ;; esac
  got="$(sha256 "$dl/$name")"
  [ "$got" = "$hash" ] || fail "$name has sha256 $got; SHA256SUMS says $hash"
  echo "  $hash  $name"
  listed=$((listed + 1))
done < "$dl/SHA256SUMS"
for name in install.sh "${TARBALLS[@]}"; do
  grep -qE "^[0-9a-f]{64} [ *]?$name\$" "$dl/SHA256SUMS" || fail "SHA256SUMS does not list $name"
done
ok "all $listed assets match the signed SHA256SUMS"

# --- 5. the key install.sh pins ----------------------------------------------------

pinned="$(bash -c "$(grep '^JIG_RELEASE_SIGNER=' "$dl/install.sh"); printf '%s' \"\$JIG_RELEASE_SIGNER\"")"
[ "$pinned" = "$(cat "$ALLOWED_SIGNERS")" ] \
  || fail "the release's install.sh pins a different key from .github/release/allowed_signers"
ok "install.sh pins the release key"

# --- 6. install and run --------------------------------------------------------------

home="$work/home"
mkdir -p "$home"
# The verified files, served as a mirror: install.sh downloads them again
# from here and runs its own signature and checksum checks over them.
env -i PATH="$PATH" HOME="$home" JIG_HOME="$home/.jig" TMPDIR="$work" \
  JIG_VERSION="$TAG" JIG_RELEASES_BASE="file://$dl" JIG_VERIFY_SIGNATURE=1 \
  JIG_NO_START=1 JIG_NONINTERACTIVE=1 \
  bash "$dl/install.sh" > "$work/install.out" 2>&1 \
  || { tail -20 "$work/install.out" >&2; fail "install.sh $TAG failed"; }
grep -q "signature OK" "$work/install.out" || { cat "$work/install.out" >&2; fail "install.sh did not report a verified signature"; }
ok "install.sh installed $TAG into a scratch JIG_HOME"
for bin in jig jig-server; do
  out="$("$home/.jig/bin/$bin" --version 2>&1)" || fail "$bin --version failed: $out"
  case " $out " in
    *" $EXPECT_VERSION "*) ok "$bin --version: $out" ;;
    *) fail "$bin --version says '$out', not $EXPECT_VERSION" ;;
  esac
done

echo "PASS: $TAG"
