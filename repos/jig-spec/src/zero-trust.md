# Zero-Trust Model

**Audience:** This chapter is foundational for **everyone**—protocol implementers, server operators, and developers. **End users** might find the "What Zero-Trust Means in Practice" section useful for understanding why Jig works the way it does.

---

This chapter establishes the security assumptions that inform every decision in the Jig protocol. If you're wondering why something seems paranoid or inconvenient, the answer is usually "because zero-trust."

## The Premise: Everyone Is Hostile Until Proven Otherwise

Here's the uncomfortable truth: **you can't trust anyone on the network**.

Not because people are evil (mostly they're not), but because:

- Networks get compromised
- Servers get hacked
- Clients run malware
- ISPs log everything
- Nation-states do nation-state things

So Jig assumes the worst and designs around it. This is called **zero-trust**: verify everything, trust nothing.

### What Zero-Trust Means in Practice

**For users:**

- Your messages are signed and (optionally) encrypted, even if you trust the server. We don't assume the server stays trustworthy forever.
- You can verify any receipt by replaying the execution locally. You don't have to take the host's word for billing.
- If a server goes rogue, you take your keys to a different server. Your identity is yours, not theirs.

**For server operators:**

- You rate-limit and authenticate every request, even from "trusted" peers. Federation doesn't mean blind trust.
- You log only what's necessary for abuse mitigation, and you expire those logs quickly. Metadata is an attack surface.
- You assume clients will send garbage. Malformed inputs get rejected, not silently ignored.

**For implementers:**

- Silent protocol downgrades are forbidden. If a client asks for TLS 1.3 and the server only supports TLS 1.2, fail loudly.
- Replay attacks are blocked via nonces or strict timestamp windows. Old messages don't get accepted twice.
- Ephemeral secrets (session keys) live in memory only and get zeroed immediately after use. No secret material on disk unless absolutely required.

## Core Tenets

These principles guide every normative requirement in this spec:

### 1. Adversarial-by-Default

**Assume every peer is malicious until proven otherwise.**

This doesn't mean you can't have trusted peers—it means trust is **earned and continuously verified**, not assumed.

**Example:** When federating with another server, you don't just accept their receipts at face value. You replay blocks locally and verify the receipts match. If they diverge repeatedly, you downgrade that peer's reputation or stop federating entirely.

**Trade-off:** More verification means higher CPU costs. But it prevents billing fraud and makes trustless federation possible.

### 2. Minimize Metadata

**Only transmit what's strictly necessary. When in doubt, fail closed.**

Metadata leaks are attacks. Who you talk to, when, and how often reveals a lot—even if the content is encrypted.

**Example:** Jig separates routing metadata (plaintext, needed for delivery) from content (encrypted). But we still minimize routing metadata: timestamps are coarse-grained, DIDs are pseudonymous, and servers don't log connection graphs unless abuse mitigation requires it (and then with time-bounded retention).

**Why IRC mode exists:** IRC clients can't do E2EE, so content stays plaintext. This is a conscious trade-off for compatibility—users who need privacy should use WebSocket transport with E2EE enabled.

### 3. Defense-in-Depth

**Layer multiple independent controls. Don't rely on a single mechanism.**

If one defense fails, others should still hold.

**Example:** Block execution uses:

- **Cryptographic verification** (manifest signatures)
- **Capability isolation** (no ambient authority)
- **Resource limits** (fuel metering, memory caps, timeouts)
- **Sandboxing** (Wasm runtime isolation)

Even if an attacker bypasses one layer (e.g., finds a Wasm escape), fuel limits prevent runaway execution and signatures prevent attribution spoofing.

### 4. Compromise Containment

**Assume keys get stolen. Design so the damage is limited and recovery is fast.**

**Example:** If a server's signing key is compromised:

- Old signatures on receipts/messages stay valid (can't rewrite history)
- But the server can generate a new keypair and publish a key rotation certificate
- Clients verify the rotation was signed by both old and new keys
- Federation peers are notified and update their trust anchors

The blast radius is "receipts signed during the compromise window" (which can be audited via replays), not "every receipt ever signed."

**Why key rotation matters:** Hardware fails, admins get coerced, bugs leak secrets. Rotation is inevitable, so the protocol makes it non-catastrophic.

## Normative Requirements

These are the rules. Violate them and you're not Jig-compliant.

### Protocol Versioning

**MUST version all protocol elements and negotiate explicitly.**

- Handshake phase declares client and server protocol versions
- Mismatched versions get rejected cleanly (fail closed)
- Silent downgrades (e.g., "client asks TLS 1.3, server silently uses TLS 1.0") are **forbidden**

**Why:** Downgrade attacks are how attackers force you onto weak crypto. We make them impossible by requiring explicit negotiation and rejecting incompatible peers.

See [Handshake](handshake.md#version-negotiation) for details.

### Replay Protection

**MUST prevent message replay via nonces or strict timestamp windows.**

- Every message includes a unique nonce (e.g., UUIDv7) and/or a timestamp
- Servers reject messages with duplicate nonces or stale timestamps
- Acceptance windows should be narrow (e.g., ±5 minutes) to limit replay window

**Why:** Without replay protection, an attacker can record a signed "transfer 10 credits" message and replay it 100 times.

**Trade-off:** Strict timestamp windows require clock synchronization (NTP). If client clocks drift badly, legitimate messages get rejected. We recommend clients use NTP and servers use generous-but-bounded windows (e.g., ±10 minutes max).

See [Message Format § Replay Protection](message-format.md#replay-protection) for implementation.

### End-to-End Verification

**MUST ensure authenticity and integrity end-to-end. Transport security alone is insufficient.**

- Messages are signed by the sender's keypair (Ed25519)
- Content can be encrypted (age+x25519) before signing
- Relays and servers see routing metadata but can't forge or tamper with content

**Why:** TLS protects you from network attackers but not malicious servers. E2E signatures and encryption mean even the server operator can't forge messages or read encrypted content.

**Trade-off:** More crypto overhead (signatures on every message). But modern Ed25519 is fast enough that this isn't a bottleneck.

See [Crypto Primitives § Signatures](crypto.md#signatures) and [Message Format § Signatures](message-format.md#signatures).

### Ephemeral Secret Handling

**MUST keep ephemeral secrets in memory only. Zeroize immediately after use.**

- Session keys (Diffie-Hellman transcripts, nonces) live in RAM
- After use, overwrite with zeros before deallocating
- Persistence of ephemeral secrets to disk/log MUST be treated as a security incident

**Why:** If ephemeral secrets get logged or swapped to disk, an attacker with filesystem access can decrypt past sessions (breaks forward secrecy).

**Implementation note:** Use `explicit_bzero()` or equivalent to prevent compiler optimizations from skipping the zeroing.

See [Crypto Primitives § Key Management](crypto.md#key-management).

### Logging and Metadata Retention

**MUST exclude sensitive identifiers from logs unless strictly necessary. Retention MUST be minimal and time-bounded.**

- Don't log DIDs, message content, or linkable metadata in plaintext
- If abuse mitigation requires logging (e.g., rate limit tracking), use hashed IDs and expire logs quickly (e.g., 7-30 days)
- Make log retention configurable; operators decide based on their threat model

**Why:** Logs are honeypots. If they contain full DIDs and message graphs, an attacker (or subpoena) gets a complete social graph.

**Trade-off:** Debugging is harder without detailed logs. We recommend structured logging with privacy-preserving identifiers (hashed DIDs, pseudonymous session IDs) that can be correlated when needed but don't leak by default.

See [Security Considerations § Operational Security](security.md#operational-security).

### Rate Limiting and DoS Protection

**MUST enforce rate limits and admission control at all ingress points.**

- Limit messages per second per DID/IP
- Use proof-of-work challenges for new or low-reputation identities
- Federation peers get quotas based on reputation scores

**Why:** Without rate limits, a single attacker can flood the server with garbage and take it offline.

**Trade-off:** Legitimate high-volume users, verified bots, etc. need higher quotas. Reputation tiers solve this: `verified` users get higher limits than `null_sec` users.

**Implementation note:** Bridges are key attack surfaces because they link unidentified entry points to identified internal users and servers. An attacker can use a bridge to flood the network with traffic from unknown sources (e.g. a botnet sending millions of emails from programmatically-generated addresses to a known Jig user). The primary role of any bridge implementation is to validate the appropriate rate limits for the incoming bridged traffic and reject violations to protect the integrity of the network.

See [Protocol Overview § Capability Grants](protocol-overview.md#step-1-connection-setup) and future reputation documentation.

### Fail Closed on Unknown Input

**MUST reject unknown or malformed inputs. Undefined behavior is prohibited.**

- Unknown protocol version? Reject connection.
- Malformed JSON? Reject message.
- Invalid signature? Drop silently (no error response to avoid oracle attacks).

**Why:** "Fail open" (allow by default, deny on error) leads to weird bugs and security bypasses. "Fail closed" (deny by default, allow on explicit match) is safer but less flexible.

**Trade-off:** Debugging is painful when things get silently dropped. We recommend verbose logging (in debug builds) but strict rejection in production. Practically speaking, Jig codebases enforce small named allowlists of valid inputs to minimize ambiguity when debugging.

## Threat Classes

Here are the specific attacks Jig is designed to resist:

### 1. Active Network Attacker (MiTM, Replay, Downgrade)

**Threat:** Attacker sits between client and server, intercepts traffic, modifies messages, or forces weak crypto.

**Mitigations:**

- TLS 1.3 for transport security (prevents MiTM on the wire)
- E2E signatures (prevents message tampering even if TLS is bypassed)
- Explicit version negotiation (prevents downgrade attacks)
- Replay protection (nonces + timestamps)

**Example attack:** Attacker intercepts handshake and modifies "client supports TLS 1.3" to "client supports TLS 1.0". Jig rejects because server sees a version mismatch between client's signed claim and the intercepted value.

### 2. Malicious Federation Peer

**Threat:** Federated server tries to harvest metadata, forge receipts, or spam your users.

**Mitigations:**

- Receipt verification (replay blocks locally, check signatures)
- Reputation scoring (downgrade peers that send bad receipts)
- Rate limiting (federated peers get quotas)
- Cryptographic attestations (useful-work proofs can't be forged)

**Example attack:** Malicious server sends you receipts claiming blocks used 1M fuel when they actually used 100k (billing fraud). You replay locally, detect mismatch, and downgrade that peer's reputation. After repeated violations, you stop federating with them.

### 3. Compromised Client or Server

**Threat:** Attacker gains access to a client/server and exfiltrates keys or coerces operations.

**Mitigations:**

- Key rotation (compromised keys can be rotated; damage is time-bounded)
- Forward secrecy (past sessions stay secret even if current keys leak)
- Audit logs (detect anomalous behavior post-compromise)
- Multi-signature requirements (for high-value operations like tribunal decisions)

**Example attack:** Attacker steals server's signing key. They can sign new receipts, but can't rewrite old receipts (signatures are immutable). Server operator detects compromise, rotates key, and publishes rotation certificate. Clients verify and update trust anchors.

### 4. Side-Channel and Timing Attacks

**Threat:** Attacker infers secrets by measuring timing variations, power consumption, or cache hits.

**Mitigations:**

- Constant-time crypto (use libsodium, ring, or similar)
- No secret-dependent branches in hot paths
- Timing jitter for network responses (optional)

**Example attack:** Attacker measures how long signature verification takes. If it exits early on mismatch (fast) vs checking full signature (slow), they can brute-force signatures. Jig uses constant-time crypto libraries that always take the same time regardless of input.

## Cross-Chapter Implications

These zero-trust requirements inform specific chapters:

**[Handshake](handshake.md)**
: Version negotiation, capability grants, fail-closed semantics

**[Message Format](message-format.md)**
: Signatures, nonces, replay protection, envelope/content separation

**[Crypto Primitives](crypto.md)**
: Key management, constant-time operations, forward secrecy

**[Block Execution Model](block-execution.md)**
: Capability isolation, fuel limits, deterministic verification

**[Receipts](receipts.md)**
: Signatures, replay audits, fraud detection

**[Federation](federation.md)**
: Peer reputation, receipt verification, rate limiting

**[Transports](transports.md)**
: TLS requirements, transport-specific security properties

**[Security Considerations](security.md)**
: Operational mitigations, incident response, threat modeling

## Why This Matters

Zero-trust isn't paranoia—it's reality. Networks get compromised. Servers get subpoenaed. Clients run malware.

By designing for the worst case, Jig stays secure even when parts of the system fail. It's not perfect (nothing is), but it makes entire classes of attacks impossible and contains the damage from the ones that do succeed.

**The cost:** More complexity, more crypto overhead, less flexibility. Debugging is harder. Backwards compatibility is harder. But the alternative—trusting by default and hoping nothing goes wrong—has failed spectacularly for every protocol that tried it.

**The benefit:** You own your identity. You can verify receipts. You can't be de-platformed. Federation works without trusting peers. Compromise is containable, not catastrophic.

That's the zero-trust trade-off, and Jig makes that choice explicitly.

---

**Next:** We recommend reading [Crypto Primitives](crypto.md) to see how these security properties are implemented with keys, signatures, and encryption.
