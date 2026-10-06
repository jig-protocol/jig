# Handshake

> **Not implemented in v0.1.** No handshake exists today. This chapter predates
> [JEP-0002](https://github.com/jig-protocol/jig/blob/main/repos/jig-spec/jep/jep-0002-handshake.md),
> which makes the handshake mandatory, signed by the server and fail-closed. Where they
> differ, JEP-0002 is the direction. Encryption suites are specified in
> [Encryption](encryption.md), not by the `crypto_suites` strings below.

**Audience:** This chapter is for **protocol implementers** and **developers** building clients or servers. **End users** don't need to understand handshakes—your client handles this automatically. **Server operators** might care about the features and crypto suites their servers advertise.

---

The handshake is how clients and servers (or two servers in a federation) figure out if they can talk to each other. Before any messages flow, they need to agree on:

- **Protocol version**: Which version of Jig are we speaking?
- **Features**: E2EE? Block execution? Federation?
- **Crypto suites**: Ed25519 + X25519 + BLAKE3? Something newer?

If they can't agree, the connection fails immediately. This is **fail closed** in action—better to reject incompatible connections up front than discover weird bugs 10 minutes later.

## Why Handshakes Matter

Here's the problem: you can't just start blasting messages at a server and hope it understands. Maybe the client speaks Jig v1.3 but the server only speaks v1.0. Maybe the client needs E2EE but the server doesn't support it. Maybe the server requires a crypto suite the client has never heard of.

The handshake solves this by making everything **explicit and negotiated**:

- Versions are declared and matched (no silent downgrades)
- Features are requested and granted (or denied)
- Crypto is negotiated once (applies to all subsequent messages)

**Why this matters:** Without handshakes, you get version mismatches mid-conversation, silent security downgrades, and weird edge cases where half the protocol works and half doesn't. Handshakes front-load all that complexity into a single, deterministic negotiation.

**Trade-off:** More round-trips before you can send your first message. But we're talking milliseconds—and it prevents hours of debugging later.

## Client ↔ Server Handshake

Here's the flow when a client connects to a server:

### Step 1: Client Sends HELLO

As soon as the transport is up (WebSocket connected, IRC line open, SSH session started), the client sends a `HELLO` message declaring what it supports:

```json
{
  "type": "HELLO",
  "versions": ["1.3", "1.2", "1.1"],
  "features": {
    "e2ee": "required",
    "blocks": "optional",
    "federation": "optional"
  },
  "crypto_suites": ["v1:ed25519+x25519+blake3", "v2:ml-dsa+x25519+blake3"]
}
```

**What this means:**

- **`versions`**: Client speaks Jig v1.1, v1.2, and v1.3, preferring v1.3 (highest first).
- **`features`**: Client requires E2EE (if server doesn't support it, fail). Blocks and federation are nice-to-have.
- **`crypto_suites`**: Client supports two crypto suites. The `v1` suite uses Ed25519 for signatures, X25519 for key exchange, and BLAKE3 for hashing. The `v2` suite uses a post-quantum signature algorithm (ML-DSA) but is otherwise similar.

**For implementers:** The `versions` array MUST be sorted by descending preference. The server picks the highest version it also supports.

### Step 2: Server Sends WELCOME

The server looks at what the client offered and decides:

- **Protocol version**: Pick the highest version both sides support.
- **Features**: Grant what the server supports. If the client marked something `required` and the server doesn't have it, reject the connection.
- **Crypto suite**: Pick exactly one suite from the client's list. If none overlap, reject.

```json
{
  "type": "WELCOME",
  "version": "1.2",
  "features": {
    "e2ee": "granted",
    "blocks": "granted",
    "federation": "denied"
  },
  "crypto_suite": "v1:ed25519+x25519+blake3",
  "capabilities": {
    "max_message_size": 1048576,
    "rate_limit": {
      "messages_per_minute": 60,
      "blocks_per_hour": 100
    },
    "reputation_tier": "low_sec"
  }
}
```

**What this means:**

- **`version`**: Server chose v1.2 (client offered v1.3, but server only goes up to v1.2, so they meet in the middle).
- **`features`**: E2EE and block execution are enabled. Federation is disabled (maybe this is an IRC-only server that doesn't federate).
- **`crypto_suite`**: Using the v1 suite (Ed25519, X25519, BLAKE3).
- **`capabilities`**: Server tells client what limits apply. Messages can't exceed 1MB. Client gets 60 messages/minute and 100 blocks/hour. Reputation tier is `low_sec` (new user, no history).

**For developers:** The `capabilities` section is how servers enforce rate limits and quotas. Save these values—your client needs to respect them.

**For server operators:** You configure these limits based on your threat model and resources. A public server might have strict limits for `null_sec` users but higher limits for `verified` users.

### Step 3: Client Sends READY

Client got the `WELCOME`, checked that required features were granted, and is happy. It sends `READY` to confirm:

```json
{
  "type": "READY"
}
```

Now the connection is established and normal messaging can begin.

### Error Handling: Fail Closed

If anything goes wrong during the handshake, the connection **MUST be terminated immediately**. No partial negotiations, no retries, no fallback to plaintext.

**Common error scenarios:**

**No common protocol version:**

```json
{
  "type": "ERROR",
  "code": "unsupported_version",
  "message": "Server supports v1.0-v1.2, client requires v1.3+",
  "supported_versions": ["1.2", "1.1", "1.0"]
}
```

Server closes the connection. Client should either upgrade the server or downgrade the client (or fail and notify the user).

**Required feature unavailable:**

```json
{
  "type": "ERROR",
  "code": "unsupported_feature",
  "message": "Client requires 'e2ee', server does not support it",
  "supported_features": ["blocks", "irc_mode"]
}
```

Server closes the connection. This server doesn't do E2EE (maybe it's an IRC bridge). Client should either use a different server or disable the E2EE requirement (if the user explicitly opts into plaintext mode).

**No compatible crypto suite:**

```json
{
  "type": "ERROR",
  "code": "unsupported_crypto",
  "message": "No overlap between client and server crypto suites",
  "supported_suites": ["v1:ed25519+x25519+blake3"]
}
```

Server closes the connection. Client wanted a post-quantum suite that the server doesn't support yet.

**Why fail closed:** Allowing partial handshakes or silent downgrades opens the door to **downgrade attacks**—where an attacker intercepts the handshake and forces both sides onto weak crypto or disabled features. By failing loudly, we make downgrades impossible.

**Trade-off:** Less flexibility. If a client requires a feature the server doesn't have, the connection just fails. But the alternative (silent feature degradation) is worse—users think they have E2EE when they don't.

## Server ↔ Server Federation Handshake

When two servers federate, they use a **symmetric handshake**—either side can initiate, and both sides authenticate each other.

**Prerequisites:**

- Both servers MUST use **mutual TLS** (mTLS) for the transport. This means both sides present X.509 certificates and verify each other's identity before the handshake even starts.
- Certificates SHOULD be pinned or validated against a known trust anchor (e.g., Let's Encrypt, or a private CA for closed federations).

### Step 1: Initiator Sends FED_HELLO

One server (let's say `server-a.example.com`) initiates:

```json
{
  "type": "FED_HELLO",
  "from_did": "did:jig:server-a.example.com",
  "versions": ["1.2", "1.1"],
  "features": {
    "receipt_exchange": "required",
    "reputation_sync": "optional"
  },
  "crypto_suite": "v1:ed25519+x25519+blake3",
  "signature": {
    "key": "ed25519:v1:PkQx7TfHJ...",
    "signature": "ed25519:v1:9f86d081..."
  }
}
```

**What's different from client-server:**

- **`from_did`**: Server's DID (derived from its long-term Ed25519 keypair).
- **`signature`**: The entire `FED_HELLO` (minus the `signature` field itself) is signed by the server's keypair. This proves the message came from whoever controls that DID.

**Why signatures:** In federation, you can't trust the transport alone (even with mTLS, a compromised CA or stolen cert could impersonate a server). Signing every handshake message binds it to the server's cryptographic identity.

### Step 2: Responder Sends FED_ACCEPT

The other server (`server-b.example.com`) validates the signature, checks the offered versions and features, and responds:

```json
{
  "type": "FED_ACCEPT",
  "from_did": "did:jig:server-b.example.com",
  "version": "1.2",
  "features": {
    "receipt_exchange": "granted",
    "reputation_sync": "denied"
  },
  "crypto_suite": "v1:ed25519+x25519+blake3",
  "signature": {
    "key": "ed25519:v1:aBcDeF...",
    "signature": "ed25519:v1:1234abcd..."
  }
}
```

Mutual authentication complete: both servers know who they're talking to and what features are enabled.

### Step 3: Initiator Sends FED_READY

Initiator confirms:

```json
{
  "type": "FED_READY",
  "signature": {
    "key": "ed25519:v1:PkQx7TfHJ...",
    "signature": "ed25519:v1:5678efgh..."
  }
}
```

Federation connection is now established. Servers can exchange messages, receipts, and other protocol data.

### Federation Error Handling

If anything fails, the responder sends a **signed** `FED_ERROR` and both sides close:

```json
{
  "type": "FED_ERROR",
  "code": "unsupported_version",
  "message": "No overlapping protocol versions",
  "supported_versions": ["1.1", "1.0"],
  "signature": {
    "key": "ed25519:v1:aBcDeF...",
    "signature": "ed25519:v1:error123..."
  }
}
```

**Why sign errors:** Even error messages could be forged by an attacker trying to disrupt federation. Signing ensures the error came from the legitimate server.

**Downgrade detection:** If server A says it supports v1.2, but then later (after a network hiccup) reconnects and claims to only support v1.0, this is suspicious. Implementations SHOULD log this as a potential downgrade attack and raise an alert for the operator to investigate.

**For server operators:** Monitor your federation logs for downgrade attempts. If you see repeated mismatches with a specific peer, it could indicate a compromised server or an active attack.

## Cryptographic Suites

A **crypto suite** is a bundle of algorithms used together:

```
v1:ed25519+x25519+blake3
│  │       │      └─ Hashing: BLAKE3
│  │       └─ Key exchange: X25519
│  └─ Signatures: Ed25519
└─ Suite version
```

**Why bundle:** Because mixing and matching crypto primitives can be dangerous. If you use Ed25519 for signatures but SHA-1 for hashing, you've undermined the whole system. Suites ensure algorithms are validated together as a coherent unit.

**Normative requirement:** Implementations MUST support the v1 suite (`ed25519+x25519+blake3`). Implementations MAY support newer suites (e.g., post-quantum algorithms).

**Unknown suites:** If a client offers a suite the server doesn't recognize, the server MUST ignore it (don't error on unknown—just skip). If no suites overlap, then error with `unsupported_crypto`.

**For implementers:** Don't hardcode algorithm names. Parse the suite string, extract the version prefix, and reject unknown versions. This enables forward compatibility—new clients with `v2` suites can still talk to old servers with `v1` suites.

**Future-proofing example:**

When NIST standardizes post-quantum algorithms (e.g., ML-DSA for signatures, ML-KEM for key exchange), Jig will add them as a new suite:

```
v2:ml-dsa+ml-kem+blake3
```

Old clients (v1 only) and new clients (v1 + v2) can still interoperate by negotiating down to v1. Over time, as deployments upgrade, v2 becomes the default.

## Capability Grants

The `capabilities` section in the `WELCOME` message is how servers enforce **resource quotas** and **reputation-based limits**.

**Common capabilities:**

```json
{
  "max_message_size": 1048576,       // 1MB max per message
  "rate_limit": {
    "messages_per_minute": 60,       // 1 msg/second sustained
    "blocks_per_hour": 100,          // Max 100 block executions/hour
    "fuel_quota": 10000000           // 10M fuel units/day
  },
  "reputation_tier": "low_sec",      // User's reputation level
  "allowed_transports": ["websocket", "irc"],
  "max_channels": 50                 // Can join up to 50 channels
}
```

**Reputation tiers:**

- **`null_sec`**: No reputation (new key, never seen before). Strictest limits.
- **`low_sec`**: Some history, no violations. Moderate limits.
- **`high_sec`**: Verified identity, good track record. Higher limits.
- **`verified`**: Formal verification (e.g., domain ownership, email verification). Highest limits.

**For developers:** Your client should display these limits to users. If a user tries to join 100 channels but the server only allows 50, show a helpful error ("Your account is limited to 50 channels. Upgrade your reputation or part some existing channels.").

**For server operators:** Configure limits based on your threat model:

- **Public servers** with open registration: Start users at `null_sec` with strict limits to prevent spam/abuse.
- **Private servers** with invite-only: Start at `low_sec` or `high_sec` since you trust invited users more.
- **Enterprise servers**: All users might be `verified` (authenticated via SSO), so limits can be very high.

**Dynamic adjustment:** Servers MAY adjust capabilities mid-session (e.g., user gets rate-limited after hitting quota). When this happens, the server SHOULD send a `CAPABILITY_UPDATE` message:

```json
{
  "type": "CAPABILITY_UPDATE",
  "capabilities": {
    "rate_limit": {
      "messages_per_minute": 10  // Reduced from 60 due to rate limit violation
    }
  }
}
```

Clients MUST respect updated capabilities immediately.

## Transport-Specific Handshakes

Different transports have slightly different handshake flows:

### WebSocket

Handshake happens over the WebSocket connection as JSON messages. No special ceremony—just send `HELLO` as the first frame after the WebSocket is open.

### IRC

IRC doesn't have a native handshake protocol, so Jig layers it on top:

1. Client sends `CAP REQ :jig` to request Jig capabilities (standard IRC CAP negotiation).
2. Server responds `CAP ACK :jig` if it supports Jig.
3. Client sends Jig `HELLO` as a `PRIVMSG` to a special pseudo-user (e.g., `PRIVMSG JigHandshake :{"type":"HELLO",...}`).
4. Server responds with `WELCOME` as a `NOTICE` from `JigHandshake`.

If the server doesn't support Jig (no `CAP ACK`), the client falls back to plain IRC mode (no E2EE, no blocks, just text messages).

**Trade-off:** IRC mode is less secure (no E2EE support in most IRC clients) but maximizes compatibility.

### SSH

Handshake happens over the SSH session as line-delimited JSON:

1. Client authenticates via SSH keys (standard SSH public-key auth).
2. Client sends `HELLO` as the first line.
3. Server responds with `WELCOME`.
4. Client sends `READY`.

SSH's transport security (encryption + authentication) is already strong, so the Jig handshake just negotiates protocol-level features.

**For developers:** See [Transports](transports.md) for full transport-specific details.

## Security Properties

The handshake establishes several security properties:

**Version binding:** Once negotiated, the protocol version can't change mid-session. Attempts to switch versions are treated as attacks (connection drops).

**Feature binding:** If E2EE was granted, all subsequent messages MUST be encrypted. If blocks were denied, clients MUST NOT send block messages.

**Crypto suite binding:** All signatures, encryptions, and hashes use the negotiated suite. No mixing—if you negotiated `v1:ed25519+x25519+blake3`, you can't suddenly start using `v2:ml-dsa+...` without renegotiating.

**Downgrade resistance:** Because versions and crypto suites are explicit (not negotiated via flags or silent fallback), attackers can't force downgrades. If a client says it requires v1.3 and E2EE, an attacker can't intercept and modify the handshake to say "actually v1.0 and plaintext please"—the signatures and fail-closed semantics prevent it.

**For implementers:** The handshake MUST be **constant-time** with respect to secret data (e.g., signature verification takes the same time whether valid or invalid). This prevents timing attacks that could leak information about keys or crypto state.

## Normative Requirements Summary

**MUST:**

- Negotiate protocol version explicitly before any application messages.
- Fail closed if no common version, required feature unavailable, or no compatible crypto suite.
- Use signed handshake messages for server-to-server federation.
- Respect capability grants (rate limits, quotas) throughout the session.
- Close connection immediately upon any `ERROR` message.
- Support the v1 crypto suite (`ed25519+x25519+blake3`).

**SHOULD:**

- Sort `versions` in descending preference (highest first).
- Use mutual TLS (mTLS) for federation handshakes.
- Log downgrade attempts and alert operators.
- Send `CAPABILITY_UPDATE` when limits change mid-session.

**MAY:**

- Support additional crypto suites beyond v1.
- Dynamically adjust capabilities based on user behavior (reputation changes, rate limit violations).
- Implement transport-specific handshake optimizations (e.g., pipelining on WebSocket).

---

**Next:** Now that the handshake is complete and both sides know what they're speaking, let's look at [Message Format](message-format.md) to see how actual messages are structured and exchanged.
