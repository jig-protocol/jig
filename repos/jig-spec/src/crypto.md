# Crypto Primitives

**Audience:** This chapter is primarily for **protocol implementers** and **developers building on Jig**. If you're an **end user** or **server operator**, you don't need to understand the cryptographic details—just know that Jig uses modern, audited crypto that's the same stuff Signal, age, and WireGuard use.

If you're implementing the Jig protocol or building blocks that do crypto operations, keep reading.

---

Cryptography is how Jig ensures messages are authentic (really from who they claim), tamper-proof (not modified in transit), and private (only readable by intended recipients). We don't roll our own crypto—we use **modern, widely-reviewed primitives** that are battle-tested.

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

### Key Exchange: X25519

**What it does:** Two parties generate a shared secret without ever transmitting it over the network (Diffie-Hellman).

**Why X25519:**
- **Matching security level**: Same curve family as Ed25519 (Curve25519)
- **Simple**: One function call, no parameter negotiation
- **Forward secrecy**: Each session uses ephemeral keys; compromise of long-term keys doesn't decrypt past sessions

**For developers:** Use X25519 for session key establishment in E2EE. Don't reuse keys across sessions—generate fresh ephemeral keys each time.

**For implementers:** Ephemeral key material MUST be memory-only and zeroized immediately after deriving session keys.

### Hashing: BLAKE3

**What it does:** Takes arbitrary data and produces a fixed-size fingerprint (hash). Collision-resistant (can't find two inputs with same hash) and one-way (can't reverse).

**Why BLAKE3:**
- **Fast**: Faster than SHA-256, especially on modern CPUs (uses SIMD)
- **Secure**: Based on BLAKE2, which is cryptanalysis-friendly (no known weaknesses)
- **Flexible**: Can be used for hashing, key derivation, and MAC (keyed hashing)
- **Modern**: Designed in 2020, learns from decades of hash function research

**For developers:** Use BLAKE3 for content addressing (block CIDs), key derivation (KDF), and integrity checks.

**For implementers:** When using BLAKE3 for KDF (e.g., deriving session keys), use domain separation (different context strings for different purposes).

## Key Management

This section is for **implementers** building Jig clients, servers, or libraries.

### Identity Keys (Long-Term)

Your DID is derived from a long-term Ed25519 keypair:
```
did:jig:<base58(public_key)>
```

**Storage:**
- Private keys MUST be stored encrypted at rest (OS keychain, hardware token, or encrypted file)
- Backups SHOULD use multiple mechanisms (paper backup + cloud + hardware key)

**Rotation:**
- Clients and servers MUST support key rotation (publishing new key signed by old key)
- Rotation certificates MUST be published to nameserver and propagated via transparency log

**For end users:** Your keys = your identity. If you lose them, you lose your account. Back them up. If they're stolen, rotate immediately.

**For server operators:** Store server signing keys in HSMs or encrypted volumes. Rotate annually or after suspected compromise.

### Session Keys (Ephemeral)

For E2EE, each session uses ephemeral X25519 keys:

1. **Generate fresh keypair** on session start
2. **Exchange public keys** via handshake
3. **Derive shared secret** via X25519(my_private, their_public)
4. **Derive session keys** via HKDF-BLAKE3 with domain separation
5. **Zeroize ephemeral private keys** immediately

**Normative requirements (implementers):**
- Ephemeral keys MUST be memory-only (never written to disk)
- Zeroization MUST use explicit_bzero() or equivalent (prevent compiler optimization)
- Persistence of ephemeral keys to logs/swap MUST be treated as security incident

**Why this matters:** If an attacker steals your long-term keys tomorrow, they can't decrypt past sessions (forward secrecy). Each session has unique keys that are destroyed immediately.

### Key Derivation

When deriving session keys from X25519 shared secret:

```
session_key = HKDF-BLAKE3(
  shared_secret,
  salt = handshake_transcript_hash,
  info = "jig-v1.session.encrypt" || protocol_version || peer_dids,
  length = 32
)
```

**MUST include in derivation:**
- Protocol version (prevents cross-version attacks)
- Both peer DIDs (prevents key reuse across different peers)
- Handshake transcript hash (binds to negotiation, prevents MITM)

**Domain separation:** Use different `info` strings for different purposes:
- `jig-v1.session.encrypt` for message encryption
- `jig-v1.session.mac` for message authentication
- `jig-v1.block.seal` for block encryption

**For implementers:** Never reuse a KDF output for multiple purposes. Derive separate keys even if it seems wasteful.

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

Crypto algorithms have expiration dates. SHA-1 is broken. MD5 is broken. DES is broken. Eventually, something will break Ed25519 or X25519 (quantum computers, cryptanalysis, implementation bugs).

So Jig supports **algorithm agility**: the ability to negotiate and upgrade crypto algorithms without breaking the protocol.

**How it works:**
- Handshake declares supported crypto suites (e.g., `ed25519+x25519+blake3`)
- Peers negotiate intersection (highest common version)
- Suite identifiers are versioned and explicit (no silent downgrade)
- Unknown suites are rejected (fail closed)

**Wire format for keys:**
```
<type:version>:<base64url-no-padding>

Examples:
ed25519:v1:PkQx7TfHJ_3eLZ8YxH4YGJLXVJsJcZjYh7x_VJLXVJs
x25519:v1:aBcDeF1234567890aBcDeF1234567890aBcDeF12
```

**Future-proofing:**
- When post-quantum algorithms are standardized, we'll add them as `ed25519:v2` or `ml-dsa:v1`
- Old clients continue working with old algorithms
- New clients prefer new algorithms
- Mixed deployments negotiate down to common version

**For implementers:** Don't hardcode algorithm names. Parse the version prefix and reject unknown versions.

## Key Rotation and Revocation

**Audience: Server operators and protocol implementers**

Keys need to be rotated periodically (annual schedule) or immediately (after compromise).

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

**Audience: Developers and end users**

Jig supports multiple encryption modes depending on your threat model:

### E2EE (End-to-End Encrypted)

**Who can read:** Only sender and recipient(s). Server can't read content.

**How it works:**
- Sender derives session key via X25519 with recipient's public key
- Content encrypted with age+x25519
- Routing metadata stays plaintext (so server can deliver)

**When to use:** Private conversations, sensitive data, anything you don't trust server with.

**Trade-off:** Server can't index content for search. Message forwarding requires re-encryption.

### Plaintext

**Who can read:** Everyone (server, relays, network observers if TLS is broken).

**How it works:** Content is not encrypted. Only signatures for authenticity.

**When to use:**
- Public channels where privacy isn't needed
- IRC mode (IRC clients can't do E2EE)
- Email bridge (Outlook doesn't understand E2EE)

**Trade-off:** No privacy, but maximum compatibility.

### Future: Homomorphic/MLS

**Planned features:**
- **Homomorphic encryption**: Server can compute on encrypted data (e.g., search, moderation) without decrypting
- **MLS (Message Layer Security)**: Efficient group encryption (better than N^2 pairwise encryption)

**Not yet specified:** See [Security Considerations § Future Work](security.md#future-work) for roadmap.

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

### Encrypted Message

```json
{
  "id": "01932f9a-b123-7abc-9def-0123456789ab",
  "version": 1,
  "routing": {
    "from": "did:jig:alice",
    "to": "did:jig:bob",
    "timestamp": "2025-11-09T12:34:56Z"
  },
  "content": {
    "type": "encrypted",
    "recipients": [
      {
        "did": "did:jig:bob",
        "ephemeral_key": "x25519:v1:aBcDeF...",
        "encrypted_session_key": "base64..."
      }
    ],
    "ciphertext": "base64...",
    "nonce": "base64..."
  },
  "signatures": [
    {
      "key": "ed25519:v1:PkQx7TfHJ...",
      "signature": "ed25519:v1:9f86d081..."
    }
  ]
}
```

**Encryption order:**
1. Generate ephemeral X25519 keypair
2. Derive session key via X25519(ephemeral_private, bob_public)
3. Encrypt content with session key + nonce
4. Encrypt session key for each recipient (multi-recipient support)
5. Sign entire message (routing + encrypted content)

**Why sign after encrypt:** So server can verify sender without decrypting content.

## Practical Guidance

### For End Users

**What you need to know:**
- Your keys = your identity. Back them up (paper backup + cloud backup).
- E2EE is on by default for DMs. Public channels are plaintext (unless you explicitly enable E2EE).
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
- Log ephemeral keys or session keys (ever)
- Implement crypto primitives yourself
- Skip constant-time operations

### For Developers

**What you need to do:**
- Sign every message with user's Ed25519 key
- Use X25519 for E2EE session establishment
- Use BLAKE3 for content addressing (block CIDs)
- Follow domain separation for KDF (different purposes = different keys)

**Use these libraries:**
- Rust: libsodium-sys, ring, ed25519-dalek, x25519-dalek, blake3
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
- Domain separation in KDF (bind protocol version + peer IDs)
- Support key rotation (dual-signature certificates)

**Test vectors:** See [Appendix § Test Vectors](appendix.md#test-vectors) for canonical examples.

---

**Next:** Read [Handshake](handshake.md) to see how these primitives are used during connection setup, or [Message Format](message-format.md) to see how signatures and encryption are applied to messages.
