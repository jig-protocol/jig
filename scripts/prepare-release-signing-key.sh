#!/usr/bin/env bash
# prepare-release-signing-key.sh <private-key-path>
#
# Writes SIGNING_KEY to <path> and the matching public key to <path>.pub.
# ssh-keygen -Y sign looks up the public half beside the private key and
# fails with "Couldn't load public key … No such file or directory" when
# that file is missing or the secret was stored as one line with literal
# \n. Never prints private key material.
set -euo pipefail

dest="${1:?private key destination required}"
if [ -z "${SIGNING_KEY:-}" ]; then
  echo "SIGNING_KEY is empty" >&2
  exit 1
fi

python3 - "$dest" <<'PY'
import os, pathlib, sys
dest = pathlib.Path(sys.argv[1])
raw = os.environ["SIGNING_KEY"]
if raw.startswith("\ufeff"):
    raw = raw.lstrip("\ufeff")
raw = raw.replace("\r\n", "\n").replace("\r", "\n").strip()
if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in "\"'":
    raw = raw[1:-1].strip()
# A PEM pasted into a one-line secret often keeps the two-character
# sequence \n instead of real newlines. Base64 has no backslashes.
if "\\n" in raw and raw.count("\n") < 2 and "-----BEGIN" in raw:
    raw = raw.replace("\\n", "\n").strip()
dest.write_text(raw + "\n")
os.chmod(dest, 0o600)
PY

err="$(mktemp)"
if ! ssh-keygen -y -f "$dest" > "${dest}.pub" 2>"$err"; then
  # Describe the shape only. A one-line secret can put key bytes on line 1,
  # so never echo that line unless it is a short PEM header.
  header="$(head -n 1 "$dest" || true)"
  lines="$(wc -l < "$dest" | tr -d ' ')"
  case "$header" in
    "-----BEGIN OPENSSH PRIVATE KEY-----")
      echo "ssh-keygen could not read the OpenSSH private key (${lines} lines)" >&2
      ;;
    "-----BEGIN PRIVATE KEY-----"|"-----BEGIN EC PRIVATE KEY-----"|"-----BEGIN RSA PRIVATE KEY-----")
      echo "ssh-keygen could not read the PEM private key (${lines} lines)" >&2
      ;;
    ssh-ed25519\ *|ssh-rsa\ *|ssh-dss\ *|ecdsa-sha2-*)
      echo "signing key looks like a public key, not a private key" >&2
      ;;
    *)
      echo "signing key is not an OpenSSH private key (${lines} lines)" >&2
      ;;
  esac
  rm -f "$err" "${dest}.pub"
  exit 1
fi
rm -f "$err"
chmod 644 "${dest}.pub"
