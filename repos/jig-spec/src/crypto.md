# Crypto Primitives

> **Encryption is per channel since v0.2.** This chapter's signature, hashing and key
> management sections describe the protocol. Confidentiality is specified in
> [Encryption](encryption.md): channels created under `mls` are end-to-end encrypted;
> others are signed, not encrypted. Keys are sealed at rest (see Storage below), and
> rotation and revocation are not yet implemented; those sections are marked.

**Audience:** This chapter is primarily for **protocol implementers** and **developers building on Jig**. If you're an **end user** or **server operator**, you don't need to understand the cryptographic details—just know that Jig uses modern, audited crypto that's the same stuff Signal, SSH, and WireGuard use.

If you're implementing the Jig protocol or building blocks that do crypto operations, keep reading.

---

Cryptography is how Jig ensures messages are authentic (really from who they claim), tamper-proof (not modified in transit), and, from v0.2, private (only readable by intended recipients). We don't roll our own crypto—we use **modern, widely-reviewed primitives** that are battle-tested.

## Our Crypto Stack

Here's what Jig uses and why:

### Signatures: Ed25519

**What it does:** Proves a message was signed by someone with the private key corresponding to a public key.

**Why Ed25519:**
- **Fast**: Signing and verification are cheap (thousands per second on modest hardware)
- **Small**: Signatures are 64 bytes, public keys are 32 bytes
- **Secure**: Based on Curve25519, which has good resistance to side-channel attacks
- **Widely deployed**: Used by Signal, SSH, Tor, age, and many others

**For developers:** Every message and block manifest MUST be signed with Ed25519. Use libsodium, ring, or ed25519-dalek—don't implement the math yourself.

**For implementers:** Signature operations MUST be constant-time with respect to secret keys (no timing leaks).

### Hashing: BLAKE3

**What it does:** Takes arbitrary data and produces a fixed-size fingerprint (hash). Collision-resistant (can't find two inputs with same hash) and one-way (can't reverse).

**Why BLAKE3:**
- **Fast**: Faster than SHA-256, especially on modern CPUs (uses SIMD)
- **Secure**: Based on BLAKE2, which is cryptanalysis-friendly (no known weaknesses)
- **Flexible**: Can be used for hashing, key derivation, and MAC (keyed hashing)
- **Modern**: Designed in 2020, learns from decades of hash function research

**For developers:** Use BLAKE3 for content addressing (block CIDs), key derivation (KDF), and integrity checks.

**For implementers:** When using BLAKE3 for KDF (e.g., deriving per-purpose keys), use domain separation (different context strings for different purposes).

## Key Management

This section is for **implementers** building Jig clients, servers, or libraries.

### Identity Keys (Long-Term)

Your DID is derived from a long-term Ed25519 keypair:
```
did:jig:z<base32(public_key)>
```
The body is the 32-byte public key in RFC 4648 base32, lowercase and without padding: 52
characters after the `z`. The `z` marks a key-derived DID; a DID without it is a legacy
label that names no key.

**Storage:**
- Private keys MUST be stored encrypted at rest. A key file (`.jigkey`) holds the 32-byte
  seed sealed with XChaCha20-Poly1305 under a random per-key data key, and one or more
  **slots**, each wrapping that data key under its own key-encryption key. Any one slot
  opens the file. The header (version, DID, slots) is the associated data, so a slot cannot
  be swapped or removed without the file failing to open. The slots:
  - `keychain`: a random secret in the OS keychain (service `jig`, account the DID);
  - `passphrase`: Argon2id (64 MiB, t=3, p=4 by default) over a passphrase of at least 8
    characters, salted per slot;
  - `credential`: at least 32 bytes read from a file that only its owner can read, such
    as a systemd credential (`LoadCredentialEncrypted=`, TPM2-bound where the machine has
    one);
  - `env`: at least 32 bytes from an environment variable, for a secret manager.
- **The CLI** seals each identity key in `~/.jig/keys/<did>.jigkey`, with the OS keychain
  where there is one and a passphrase otherwise, and converts an older raw key file on
  first load (#177). An identity's MLS state and read history are sealed under keys derived
  from the same data key, one per file. `jig keys protect` lists the slots and adds or
  removes one; removing the last is refused. Removing a slot changes only this file: the
  data key stays, so a backup or synced copy made before still opens with the removed
  slot. For a secret that may have leaked, move to a new key (`jig keys rotate`).
- **jig-server and jig-nameserver** seal their own signing keys the same way (#254). A
  server never prompts: `[keys] unlock` names a `credential:`, `env:` or `passphrase`
  slot, and a server with nothing to open its key refuses to start rather than write one
  in clear. `jig-server keys` (and `jig-nameserver keys`) seals a raw key, adds a slot,
  verifies one, or makes a new key; `deploy/setup-server-key.sh` sets up a systemd
  credential and an offline passphrase.
- Keys in clear remain possible only by asking for them (`JIG_KEYS_STORAGE=plaintext`,
  `[keys] storage = "plaintext"`), with a warning on every load. Key files are created
  0600, and one that group or others can read is warned about (sealed) or refused (raw).
- **What this does not protect against:** code running as the user, or as the server,
  while a key is in use. Such code can ask the keychain, read a passphrase as it is typed,
  read a credential, or read the key from memory, where it is while a process signs.
  At-rest encryption protects a key that is not in use: on a stolen or discarded disk, in a
  backup, in a synced home directory, or from another local user.
- Backups SHOULD use more than one mechanism. A sealed key file is safe to back up as it
  is; keep a passphrase slot, written down offline, so the key opens on another machine.
  A keychain or TPM-bound slot does not move with the file.
- **A recovery kit** (`jig keys export --out FILE`) is the key file with one slot of its
  own: a passphrase of at least 12 characters, at the full Argon2id parameters whatever
  the local slots use, because a kit is meant to leave the machine and can be attacked
  offline. It is a `.jigkey` like any other, so `jig keys verify FILE` checks it and
  `jig keys import FILE` restores it: the restored file keeps the kit's passphrase slot
  and gains the slot the machine seals new keys with. The kit holds the same data key as the file it came from. Kits encrypted to an
  age recipient (a hardware token, a team key) may be added later as another export
  format, beside this one.

**Rotation:**
- Clients and servers MUST support key rotation (publishing new key signed by old key)
- Rotation certificates MUST be published to nameserver and propagated via transparency log

*(not yet implemented: a DID is its key, and nothing rotates it. The nameserver's `/v1/rotate` moves an alias to a new DID, with proofs from both keys; it is not a rotation certificate and no transparency log receives it.)*

**For end users:** Your keys = your identity. If you lose them, you lose your account. Back them up. If they're stolen, rotate immediately.

**For server operators:** Store server signing keys in HSMs or encrypted volumes. Rotate annually or after suspected compromise.

### Encryption Keys

Encryption keys, their lifetimes and their derivation belong to the encryption suite. For
the default suite they are MLS's ([RFC 9420](https://www.rfc-editor.org/rfc/rfc9420)).
See [Encryption](encryption.md).

**Normative requirement (implementers):** Secret key material that a suite marks as
ephemeral MUST be memory-only and zeroized after use.

## Constant-Time Operations

**Audience: Protocol implementers only**

All cryptographic operations MUST be constant-time with respect to secret data:

**What this means:**
- Signature verification takes same time whether signature is valid or invalid
- Key comparison takes same time whether keys match or differ
- No secret-dependent branches (if/else on secret values)

**Why:** Timing variations leak information. An attacker measuring response times can brute-force signatures, keys, or plaintext.

**How:**
- Use vetted libraries (libsodium, ring, ed25519-dalek)
- Don't implement crypto primitives yourself
- Use constant-time comparison functions (`crypto_verify_*` in libsodium)
- Avoid short-circuit evaluation on secrets (always check full signature)

**Example (wrong):**
```rust
// DON'T DO THIS - leaks timing
if signature[0] != expected[0] {
    return Err("invalid");  // exits early if first byte wrong
}
```

**Example (correct):**
```rust
// Use constant-time comparison
let valid = crypto_verify_64(signature, expected);
if valid != 0 {
    return Err("invalid");  // always checks all bytes
}
```

## Algorithm Agility

**Audience: Protocol implementers**

Crypto algorithms have expiration dates. SHA-1 is broken. MD5 is broken. DES is broken. Eventually, something will break Ed25519 (quantum computers, cryptanalysis, implementation bugs).

So Jig supports **algorithm agility**: the ability to negotiate and upgrade crypto algorithms without breaking the protocol.

**How it works:**
- Signature and hash algorithms are versioned and explicit (`ed25519:v1:`), so a new one
  can be added without a format change
- Encryption is negotiated separately, as a suite ([Encryption](encryption.md#suites))
- Unknown algorithm versions and unknown suites are rejected (fail closed)

**Wire format for keys:**
```
<type:version>:<base64url-no-padding>

Examples:
ed25519:v1:PkQx7TfHJ_3eLZ8YxH4YGJLXVJsJcZjYh7x_VJLXVJs
```

**Future-proofing:**
- Post-quantum signatures would be added as a new algorithm, for example `ml-dsa:v1`
- Old clients continue working with old algorithms
- New clients prefer new algorithms
- Mixed deployments negotiate down to common version

**For implementers:** Don't hardcode algorithm names. Parse the version prefix and reject unknown versions.

## Key Rotation and Revocation

**Audience: Server operators and protocol implementers**

Keys need to be rotated periodically (annual schedule) or immediately (after compromise).

> **Not implemented.** No rotation certificate, `/v1/identity/rotate` endpoint, grace period
> or revocation certificate exists. A server whose key changes has a new DID. What exists is
> the key link (JEP-0012): `jig-server keys rotate` signs one from the old DID to the new,
> the server serves it, and clients and peers that pinned the old DID follow it one hop. A
> client pinned two keys back is refused.

### Rotation Certificate Format

```json
{
  "subject_did": "did:jig:oldkey123",
  "old_public_key": "ed25519:v1:...",
  "new_public_key": "ed25519:v1:...",
  "valid_from": "2025-11-09T00:00:00Z",
  "valid_until": "2026-11-09T00:00:00Z",
  "signatures": [
    {
      "key": "ed25519:v1:oldkey...",
      "signature": "..."  // Signs entire certificate with old key
    },
    {
      "key": "ed25519:v1:newkey...",
      "signature": "..."  // Signs entire certificate with new key
    }
  ]
}
```

**Dual signature requirement:** Both old and new keys MUST sign the rotation certificate. This prevents an attacker with only one key from rotating.

**Publication:** Rotation certificates MUST be:
- Published to nameserver (`POST /v1/identity/rotate`)
- Logged to transparency log (prevents secret rotations)
- Propagated to federation peers (via gossip or pull)

**Grace period:** Peers SHOULD accept both old and new keys during the overlap window (`valid_from` to `valid_until`). After `valid_until`, old key is rejected.

**For server operators:** Rotate annually or immediately after compromise. Use HSMs to protect keys during rotation.

### Revocation

If a key is compromised and you don't have the private key anymore (e.g., hardware destroyed), you can't rotate normally (can't sign with old key).

**Emergency revocation:**
- Publish revocation certificate signed by **threshold** of trusted peers (multi-sig)
- Requires pre-established trust anchors (e.g., 3-of-5 tribunal members)
- Published to transparency log and nameserver

**Trade-off:** More complex to set up (requires trust anchors), but works when primary key is lost.

## Encryption Modes

A channel is either unencrypted (suite `none`, the default) or encrypted under the suite
chosen when it was created (`mls`). DMs are channels with locked membership, not a separate mode. See
[Encryption](encryption.md).

## Wire Format Examples

**Audience: Protocol implementers**

### Signed Message

```json
{
  "id": "01932f9a-b123-7abc-9def-0123456789ab",
  "version": 1,
  "routing": {
    "from": "did:jig:alice",
    "to": "#general",
    "timestamp": "2025-11-09T12:34:56Z"
  },
  "content": {
    "type": "text",
    "text": "Hello, world!"
  },
  "signatures": [
    {
      "key": "ed25519:v1:PkQx7TfHJ...",
      "signature": "ed25519:v1:9f86d081..."
    }
  ]
}
```

**Signature covers:** Canonical JSON of `{id, version, routing, content}` (everything except `signatures` field itself).

## Practical Guidance

### For End Users

**What you need to know:**
- Your keys = your identity. Back them up (paper backup + cloud backup).
- DMs and channels created encrypted are end-to-end encrypted with MLS. Every other
  channel is readable by the server operator.
- If a server bans you, take your keys elsewhere. You're still you.

**What you DON'T need to know:**
- What Ed25519 is
- How BLAKE3 works
- Anything in this chapter, honestly

### For Server Operators

**What you need to do:**
- Store server signing keys in HSM or encrypted volume
- Rotate keys annually (or immediately after compromise)
- Log only hashed DIDs (not full DIDs) for rate limiting
- Use vetted crypto libraries (libsodium, ring, RustCrypto)

**Don't:**
- Log encryption keys (ever)
- Implement crypto primitives yourself
- Skip constant-time operations

### For Developers

**What you need to do:**
- Sign every message with user's Ed25519 key
- Use a vetted MLS implementation for encryption once it ships (v0.2)
- Use BLAKE3 for content addressing (block CIDs)

**Use these libraries:**
- Rust: ed25519-dalek, blake3, openmls (v0.2)
- JavaScript: libsodium-wrappers, @noble/ed25519, @noble/curves
- Python: PyNaCl, cryptography

**Don't:**
- Roll your own crypto
- Reuse keys across different contexts
- Skip signature verification (even in tests!)

### For Protocol Implementers

**What you need to do:**
- Constant-time operations (use vetted libraries)
- Explicit algorithm negotiation (no silent downgrade)
- Zeroize ephemeral secrets (explicit_bzero)
- Support key rotation (dual-signature certificates) *(not yet implemented)*

**Test vectors:** See [Appendix § Test Vectors](appendix.md#test-vectors) for canonical examples.

---

**Next:** Read [Handshake](handshake.md) to see how these primitives are used during connection setup, or [Message Format](message-format.md) to see how signatures are applied to messages.
