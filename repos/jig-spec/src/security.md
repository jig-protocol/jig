# Security Considerations

**Audience:** This chapter is for **server operators**, **protocol implementers**, and **security engineers**. **Developers** building on Jig will want to understand threat models and mitigations. **End users** might care about operational security practices (key management, incident response).

---

Security isn't a feature you add at the end—it's a design constraint that informs every decision. This chapter summarizes the threats Jig is designed to resist and the mitigations to employ when running a production system.

**Foundation:** This entire chapter builds on the [Zero-Trust Model](zero-trust.md). If you haven't read that yet, start there—it defines the security assumptions for the entire protocol.

## Threat Model Overview

Jig assumes a hostile network with active attackers:

- **Network attackers**: Can intercept, modify, or drop traffic (MitM).
- **Malicious peers**: Federated servers or clients trying to exploit vulnerabilities.
- **Compromised servers**: Attacker gains access to a server and tries to exfiltrate data or forge messages.
- **Side-channel attackers**: Measure timing, power consumption, or cache hits to infer secrets.

**Defense strategy:** Layer multiple independent controls (defense-in-depth). If one fails, others still hold.

## Cryptographic Operations

### Constant-Time Implementation

**MUST use constant-time implementations** for all cryptographic operations involving secret data.

**What this means:**

- Signature verification takes the same time whether the signature is valid or invalid.
- Key comparison takes the same time whether keys match or differ.
- No secret-dependent branches (`if (secret[0] == expected[0]) return early;`).

**Why:** Timing variations leak information. An attacker measuring response times can brute-force signatures, keys, or plaintext.

**Example attack:** Server verifies message signatures. If verification exits early on mismatch (fast invalid, slow valid), an attacker can brute-force signatures by measuring timing.

**Mitigation:**

Use vetted crypto libraries:

- **Rust**: `libsodium-sys`, `ring`, `ed25519-dalek`
- **JavaScript**: `libsodium-wrappers`, `@noble/ed25519`
- **Python**: `PyNaCl`, `cryptography`

Don't implement crypto primitives yourself. Use `crypto_verify_*` functions for comparisons (constant-time).

**For implementers:** Profile your crypto operations in debug mode. If timing varies based on secret values, you have a bug.

### Randomness

**MUST use a cryptographically secure PRNG (CSPRNG)** for all nonces, ephemeral keys, and salts.

**Good sources:**

- **Linux**: `/dev/urandom` (not `/dev/random`—it blocks unnecessarily)
- **Rust**: `rand::rngs::OsRng`
- **JavaScript (Node.js)**: `crypto.randomBytes()`
- **Python**: `os.urandom()`

**Bad sources:**

- `Math.random()` (JavaScript): **Not cryptographically secure**. Predictable.
- `rand()` (C): **Not cryptographically secure**. Seeded poorly.
- Timestamps: **Not random**. Predictable.

**Nonce reuse:** MUST prevent nonce reuse. If the same nonce is used twice with the same key, encryption is broken (key leakage).

**For developers:** Use UUIDv7 for message IDs—it's time-ordered (sortable) and globally unique (no coordination needed).

## Replay Protection

**MUST enforce replay protection** using unique nonces and strict timestamp windows.

### How Replay Attacks Work

1. Attacker records Alice's signed message: `{"id": "msg-1", "content": "Transfer $100 to Bob"}`.
2. Attacker replays the message 100 times.
3. Without replay protection, server processes it 100 times (Alice loses $10,000).

### Mitigation: Nonces + Timestamps

**Nonces:** Use UUIDv7 (globally unique, time-ordered). Track seen nonces in a time-windowed cache (e.g., Redis with TTL).

```python
def is_duplicate(nonce):
    if redis.exists(f"nonce:{nonce}"):
        return True
    redis.setex(f"nonce:{nonce}", ttl=600, value="1")  # 10-minute TTL
    return False
```

**Timestamp windows:** Reject messages with timestamps outside ±10 minutes.

```python
def is_timestamp_valid(timestamp):
    now = datetime.utcnow()
    delta = abs((timestamp - now).total_seconds())
    return delta < 600  # 10 minutes
```

**Trade-off:** Strict windows require clock sync (NTP). Loose windows increase replay risk.

**For server operators:** Run NTP on all servers. Monitor clock drift (alert if >1 second).

## Downgrade Prevention

**MUST detect and reject downgrade attempts** in protocol versions and crypto suites.

### How Downgrade Attacks Work

1. Alice's client says "I support TLS 1.3 + Ed25519".
2. Attacker intercepts and modifies to "I support TLS 1.0 + RSA".
3. Server accepts TLS 1.0 (weak crypto).
4. Attacker can now break encryption.

### Mitigation: Explicit Negotiation

**Protocol versions:**

- Client declares supported versions during [Handshake](handshake.md).
- Server picks the highest version both sides support.
- If no overlap, reject connection (fail closed).

**Crypto suites:**

- Client declares supported suites (`ed25519+x25519+blake3`).
- Server picks one suite.
- Unknown suites are ignored (don't error—just skip).
- If no suites overlap, reject connection.

**Downgrade detection:**

- Client signs handshake with claimed capabilities.
- If server sees different capabilities on the wire (intercepted and modified), signature won't verify.

**For implementers:** Never silently downgrade. If negotiation fails, close the connection and log the attempt.

## Input Validation

**MUST fail closed on malformed or ambiguous inputs.**

### Fail Closed vs. Fail Open

**Fail closed** (reject by default, allow on explicit match): Safer but less flexible.

**Fail open** (allow by default, deny on error): Flexible but enables weird bugs and security bypasses.

Jig chooses **fail closed** everywhere:

- Unknown protocol version? Reject.
- Malformed JSON? Reject.
- Unknown field (not in `extensions`)? Reject.
- Invalid signature? Drop silently (no error response—prevents oracle attacks).

**Trade-off:** Debugging is harder (things get silently dropped). But it prevents entire classes of attacks.

**For implementers:** Parse strictly. Use schema validation (e.g., JSON Schema). Log rejected messages for debugging (but don't send error responses—attackers can use those as oracles).

**Example (wrong):**

```python
# BAD: Silently ignores unknown fields
def parse_message(data):
    msg = json.loads(data)
    return {
        'id': msg['id'],
        'content': msg['content']
    }
    # Unknown fields silently dropped!
```

**Example (correct):**

```python
# GOOD: Fail closed on unknown fields
KNOWN_FIELDS = {'id', 'version', 'routing', 'content', 'signatures', 'extensions'}

def parse_message(data):
    msg = json.loads(data)
    unknown = set(msg.keys()) - KNOWN_FIELDS
    if unknown:
        raise ValueError(f"Unknown fields: {unknown}")
    return msg
```

## Metadata Minimization

**MUST minimize metadata** in transports and logs.

### Why Metadata Matters

Even if message content is encrypted, metadata reveals:

- Who talks to whom (social graph)
- When messages are sent (timing patterns)
- Message sizes (length correlation)

**Example attack:** Attacker analyzes message timestamps and infers Alice is talking to her lawyer every Monday at 10am. Even without reading content, this leaks information.

### Mitigation: Minimize and Scrub

**Transports:**

- Don't send unnecessary headers (e.g., custom `X-User-Agent` with version details).
- Strip metadata at ingress (federation endpoints don't need full user profiles).

**Logs:**

- Log only what's needed for debugging/abuse prevention.
- Hash DIDs instead of logging them plaintext.
- Expire logs quickly (7-30 days max).
- Don't log message content (violates privacy).

**For server operators:** Configure log retention policies:

```
# Example log entry (good)
2025-11-09T12:34:56Z INFO msg_received hash=sha256:abc123 size=512

# Example log entry (bad - leaks too much)
2025-11-09T12:34:56Z INFO msg_received from=did:jig:alice to=did:jig:bob content="Hello"
```

## Key Compromise and Recovery

**Assume keys get compromised.** Design so the damage is limited and recovery is fast.

### Key Rotation

**MUST support key rotation** (see [Crypto Primitives § Key Rotation](crypto.md#key-rotation-and-revocation)).

**Process:**

1. Generate new keypair.
2. Publish rotation certificate signed by both old and new keys.
3. Distribute to nameserver and federation peers.
4. After grace period, old key is invalidated.

**Why dual signatures:** Prevents attacker with only one key from rotating (they'd need both old and new to sign the certificate).

**For server operators:** Rotate keys annually or immediately after suspected compromise.

### Ephemeral Secret Handling

**MUST keep ephemeral secrets in memory only.** Zeroize immediately after use.

**What's ephemeral:**

- Session keys (X25519 Diffie-Hellman transcripts)
- Nonces
- Temporary decryption keys

**Why:** If ephemeral secrets get logged or swapped to disk, an attacker with filesystem access can decrypt past sessions (breaks forward secrecy).

**Mitigation:**

Use `explicit_bzero()` or equivalent to zeroize memory:

```c
// C example
void process_session_key(uint8_t *key, size_t len) {
    // Use key...

    // Zeroize before freeing
    explicit_bzero(key, len);
    free(key);
}
```

**For implementers:** Don't rely on compiler optimizations—use explicit zeroization functions. Check that secrets aren't logged (grep logs for base64-encoded keys during testing).

### Out-of-Band Verification

**SHOULD support out-of-band verification** for key recovery.

**Scenario:** Alice's laptop dies. She loses her private key. How does she recover her identity?

**Solution:** Multi-signature recovery. Alice pre-designated 3 trusted friends. To recover:

1. Alice generates new keypair.
2. Alice gets 2 of 3 friends to sign a recovery certificate.
3. Certificate is published to nameserver.
4. Alice's identity is transferred to the new key.

**For developers:** Implement recovery certificates in client software (optional feature).

## Secure Defaults

**MUST disable legacy/insecure algorithms and protocol versions by default.**

### TLS Configuration

**Only TLS 1.3** for all TLS-based transports. No TLS 1.2 or older.

**Cipher suites:**

- `TLS_AES_256_GCM_SHA384`
- `TLS_CHACHA20_POLY1305_SHA256`
- `TLS_AES_128_GCM_SHA256`

**For server operators:** Configure your TLS library:

```
# nginx example
ssl_protocols TLSv1.3;
ssl_ciphers TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256;
ssl_prefer_server_ciphers on;
```

### SSH Configuration

Disable weak SSH algorithms:

```
# /etc/ssh/sshd_config
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
HostKeyAlgorithms ssh-ed25519
```

No `ssh-rsa` (weak), `3des-cbc` (broken), or `arcfour` (broken).

## Abuse Mitigation

**MUST enforce rate limiting and admission control** at all ingress points.

### Rate Limiting

**Per-IP:**

```
100 requests/minute per IP
```

**Per-DID:**

```
60 messages/minute per user
100 blocks/hour per user
```

**Per-server (federation):**

```
1000 messages/minute per federated server
```

**For implementers:** Use sliding window rate limiters (e.g., Redis `INCR` + `EXPIRE`). Track limits separately for each ingress point (WebSocket, IRC, federation).

### Circuit Breakers

**SHOULD use circuit breakers** to prevent thundering herds.

**Scenario:** `server-b.com` goes down. 1000 clients all retry at the same time (thundering herd).

**Solution:** Circuit breaker. After 10 failures, stop retrying for 10 minutes. After 10 minutes, try once. If it succeeds, open the circuit (allow traffic). If it fails, stay closed.

**For implementers:** Use libraries like `resilience4j` (Java), `tenacity` (Python), or `circuit-breaker-js` (Node.js).

### Backoff and Jitter

**MUST use exponential backoff + jitter** for retries (see [Federation § Retry Logic](federation.md#retry-logic)).

**Why jitter:** Prevents all clients from retrying at the exact same time (avoids thundering herd).

## Privacy Considerations

### Length Correlation

**SHOULD consider length correlation risks.**

**Problem:** If message lengths are visible (even with E2EE), an attacker can correlate:

- Short messages (10 bytes): "Yes" or "No"
- Long messages (500 bytes): Detailed responses

**Mitigation: Padding**

Pad messages to fixed sizes (e.g., 128, 256, 512, 1024 bytes):

```
Plaintext: "Yes" (3 bytes)
Padded:    "Yes\x00\x00\x00...\x00" (128 bytes)
```

**Trade-off:** Increased bandwidth. 3-byte message becomes 128 bytes.

**For developers:** Implement optional padding for high-security users. Make it opt-in (most users prefer smaller messages).

### Timing Correlation

**SHOULD consider timing correlation risks.**

**Problem:** If messages are sent immediately when typed, an attacker can correlate timing:

- Fast typing → short message
- Slow typing → long message or thoughtful response

**Mitigation: Batching**

Queue messages and send in batches at fixed intervals (e.g., every 5 seconds):

```
Alice types "Hello" → queued
Alice types "How are you?" → queued
After 5 seconds → both sent together
```

**Trade-off:** Increased latency. Messages aren't instant.

**For developers:** Implement optional batching for high-security users. Default to instant delivery (most users prefer real-time).

## Operational Security

### Key Storage

**For server operators:**

- Store server signing keys in HSMs (Hardware Security Modules) or encrypted volumes.
- Use OS keychains (macOS Keychain, GNOME Keyring, Windows Credential Manager) for client keys.
- Backup keys offline (paper wallets, encrypted USB drives, split key shards).

**Don't:**

- Store keys in plaintext files.
- Commit keys to git.
- Send keys via email or Slack.

### Access Control

**For server operators:**

- Limit who can access server keys (use `sudo` + audit logs).
- Rotate keys annually or after personnel changes (employee leaves → rotate all keys they had access to).
- Use multi-signature for high-value operations (e.g., 2-of-3 admins must approve key rotation).

### Monitoring and Alerts

**For server operators:**

- Monitor for downgrade attempts (version negotiation failures).
- Alert on invalid signatures (potential forgery or bug).
- Track reputation scores for federated peers (downgrade suspicious servers).
- Monitor clock drift (>1 second → alert, NTP might be broken).

**For implementers:** Emit structured logs (JSON) for easy parsing:

```json
{"timestamp": "2025-11-09T12:34:56Z", "event": "signature_invalid", "from": "hash:abc123", "severity": "error"}
```

### Incident Response

**For server operators:** Have a plan for compromise:

1. **Detect:** Invalid signatures, unexpected key rotations, anomalous traffic.
2. **Contain:** Isolate compromised servers, revoke keys.
3. **Investigate:** Analyze logs, identify attack vector.
4. **Recover:** Rotate keys, patch vulnerabilities, restore from backups.
5. **Learn:** Post-mortem, update security policies.

**For end users:** If you suspect your key is compromised:

1. **Rotate immediately** (publish rotation certificate).
2. **Notify contacts** ("I rotated my key—verify new key fingerprint is XYZ").
3. **Audit recent messages** (check if attacker sent messages on your behalf).

## Normative Requirements Summary

**MUST:**

- Use constant-time crypto implementations (no timing leaks).
- Enforce replay protection (nonces + timestamp windows).
- Detect and reject downgrade attempts (versions, crypto suites).
- Fail closed on malformed or unknown-critical inputs.
- Minimize metadata in transports and logs.
- Use CSPRNGs for all random values (nonces, keys, salts).
- Support key rotation and revocation.
- Zeroize ephemeral secrets immediately after use.
- Disable legacy crypto (only TLS 1.3, modern ciphers).
- Enforce rate limiting at all ingress points.

**SHOULD:**

- Use backoff and jitter for retries.
- Implement circuit breakers to prevent thundering herds.
- Consider length and timing correlation (padding, batching).
- Store keys in HSMs or encrypted volumes.
- Monitor for downgrade attempts, invalid signatures, clock drift.
- Have an incident response plan.

**MAY:**

- Implement optional padding for high-security users.
- Implement optional batching for timing obfuscation.
- Support out-of-band key recovery (multi-sig recovery certificates).

---

**Related chapters:**

- **[Zero-Trust Model](zero-trust.md)**: Foundational security assumptions.
- **[Crypto Primitives](crypto.md)**: Key management, constant-time operations.
- **[Handshake](handshake.md)**: Version negotiation, downgrade prevention.
- **[Federation](federation.md)**: Server-to-server security (mTLS, reputation).

**This is the final technical chapter.** For complete reference material, see the [Appendix](appendix.md) (test vectors, affordances registry, analytics schemas).
