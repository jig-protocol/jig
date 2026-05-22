# Federation

**Audience:** This chapter is for **server operators** running federated Jig servers and **protocol implementers** building federation support. **End users** might care about how federation affects message delivery and privacy. **Developers** building federated applications will want to understand cross-server communication.

---

Federation is how Jig servers talk to each other. Without it, every server is an island—users on `server-a.example.com` can't talk to users on `server-b.example.com`. With federation, the network becomes interconnected like email: you choose your server, but you can still communicate with everyone.

## Why Federation?

Here's the problem with centralized platforms (Slack, Discord): the company controls everything. If they ban you, you're done. If they shut down, your data is gone. If they change pricing, you pay or leave.

Federation solves this:

- **Server choice**: You pick a server you trust (or run your own). Don't like the rules? Switch servers, keep your identity (DIDs are portable).
- **Resilience**: If one server goes down, the rest keep working. The network doesn't have a single point of failure.
- **Privacy control**: Choose a server with policies you trust. Some servers log everything, others log nothing. You decide.

**Real-world example:** Alice uses `server-a.com`, Bob uses `server-b.com`. When Alice sends Bob a message:

1. Alice's server signs the message with its keypair.
2. Alice's server connects to Bob's server via TLS 1.3 + mutual authentication.
3. Message is delivered to Bob's server.
4. Bob's server verifies the signature and delivers to Bob.

Bob sees the message as if it came from `alice@server-a.com`.

**Trade-off:** More complexity. Federation requires DNS discovery, mutual TLS, signature verification, receipt exchange, and reputation scoring. But the payoff is a decentralized network that no single entity controls.

## Server Discovery

How does `server-a.com` know how to reach `server-b.com`? **DNS SRV records.**

### DNS SRV Records

Servers publish their federation endpoints via `_jig._tcp` SRV records:

```
_jig._tcp.server-b.com. 3600 IN SRV 0 5 8443 jig-fed.server-b.com.
```

This says: "To federate with `server-b.com`, connect to `jig-fed.server-b.com` on port 8443."

**Why SRV records:**

- **Standard**: DNS SRV is how email (MX records), XMPP, and SIP handle service discovery.
- **Flexible**: You can run federation on a different host/port than your main server.
- **Redundant**: Multiple SRV records enable failover (priority + weight-based load balancing).

**For server operators:** Configure your DNS:

```
_jig._tcp.example.com. 3600 IN SRV 0 5 8443 fed1.example.com.
_jig._tcp.example.com. 3600 IN SRV 10 5 8443 fed2.example.com.
```

Priority 0 (fed1) is primary; priority 10 (fed2) is fallback.

**For implementers:** Query SRV records before connecting:

```python
import dns.resolver

answers = dns.resolver.resolve('_jig._tcp.server-b.com', 'SRV')
for rdata in sorted(answers, key=lambda r: (r.priority, -r.weight)):
    print(f"Connect to {rdata.target}:{rdata.port}")
```

### .well-known Discovery

Servers MUST publish their public keys via `/.well-known/jig`:

```
GET https://server-b.com/.well-known/jig
```

Response:

```json
{
  "server_did": "did:jig:server-b.com",
  "public_key": "ed25519:v1:PkQx7TfHJ_3eLZ8YxH4YGJLXVJsJcZjYh7x_VJLXVJs",
  "federation_endpoints": [
    "wss://fed1.server-b.com:8443/jig",
    "wss://fed2.server-b.com:8443/jig"
  ],
  "protocol_versions": ["1.2", "1.1", "1.0"]
}
```

**Why `.well-known`:** So clients can discover a server's public key and federation endpoints without DNS (useful for IP-based servers or Tor hidden services).

**For server operators:** Host this JSON at `/.well-known/jig` (HTTP, not HTTPS—it's public data anyway).

## Authentication

Federation uses **mutual TLS** (mTLS): both servers present X.509 certificates and verify each other's identity.

### Mutual TLS (mTLS)

**Normative requirement:** Federation connections MUST use TLS 1.3 with mutual authentication.

**What this means:**

- Both servers present certificates.
- Both servers verify the peer's certificate against a trust store.
- No self-signed certs (unless explicitly pinned via SPKI).

**For server operators:** Get a certificate from Let's Encrypt or your internal CA. Configure your server to require client certs:

```
# nginx example
ssl_client_certificate /etc/nginx/ca.crt;
ssl_verify_client on;
```

**Why mTLS:** Because you can't trust DNS alone. An attacker could MitM DNS and redirect federation traffic to a rogue server. mTLS ensures the server you're talking to is the one the certificate says it is.

**Trade-off:** More operational complexity. You need to manage certificates, CAs, and expiration. But the security benefit (authenticated, encrypted server-to-server communication) is worth it.

### End-to-End Signatures

**MUST sign all federation payloads** with the originating server's keypair.

Even though TLS 1.3 encrypts the connection, federation messages are **also signed** by the server's DID keypair (Ed25519).

**Why:** Because mTLS protects you from network attackers, but not from compromised servers. If `server-c.com` gets hacked and starts forwarding messages on behalf of `server-a.com`, E2E signatures detect the forgery.

**What gets signed:** Canonical JSON of the federation message:

```json
{
  "from_server": "did:jig:server-a.com",
  "to_server": "did:jig:server-b.com",
  "timestamp": "2025-11-09T12:34:56Z",
  "nonce": "01932f9a-b123-7abc-9def-0123456789ab",
  "payload": { /* actual message */ },
  "signature": {
    "key": "ed25519:v1:serverAkey...",
    "signature": "ed25519:v1:sigBytes..."
  }
}
```

**For implementers:** Sign the entire message (minus the `signature` field) and verify every incoming federation message.

### Replay Protection

**MUST use nonces and strict timestamp windows** to prevent replay attacks.

- **Nonce**: UUIDv7 (time-ordered, globally unique).
- **Timestamp window**: ±10 minutes (configurable, but no more than ±30 minutes).

If a message's timestamp is outside the window or the nonce is a duplicate, reject it.

**For implementers:** Track seen nonces in a time-windowed cache (e.g., Redis with TTL).

### Version Negotiation

**MUST negotiate protocol version explicitly** (see [Handshake](handshake.md)).

Servers declare supported versions during the handshake. If there's no overlap, the connection fails.

**No silent downgrades:** If `server-a` only supports v1.3 and `server-b` only supports v1.0, they can't federate—fail loudly.

**For server operators:** Monitor federation logs for version mismatches. If a peer repeatedly fails negotiation, they might be running an outdated version (or attacking you).

## Routing

Messages between servers follow the `user@server` addressing model (like email):

```
alice@server-a.com → bob@server-b.com
```

### Message Flow

1. **Alice** (on `server-a.com`) sends a message to `bob@server-b.com`.
2. **server-a** looks up `server-b.com` via SRV records (`_jig._tcp.server-b.com`).
3. **server-a** connects to `server-b` via mTLS + handshake.
4. **server-a** signs the message and sends it to `server-b`.
5. **server-b** verifies the signature, checks replay protection, and delivers to **Bob**.

### Retry Logic

**MUST implement retry with exponential backoff and jitter.**

If `server-b` is unreachable (network down, server reboot, etc.), `server-a` retries:

```
Retry 1: Wait 1s
Retry 2: Wait 2s
Retry 3: Wait 4s
Retry 4: Wait 8s
...
Max retries: 10 (or 1 hour, whichever comes first)
```

**Jitter:** Add randomness to avoid thundering herd (all servers retrying at the same time).

```python
import random

def retry_delay(attempt):
    base = 2 ** attempt  # Exponential backoff
    jitter = random.uniform(0, 1)  # Random 0-1 seconds
    return min(base + jitter, 300)  # Cap at 5 minutes
```

**Circuit breakers:** If `server-b` fails 10 times in a row, stop retrying for 10 minutes. This prevents `server-a` from wasting resources on a dead server.

**For implementers:** Use a library like `tenacity` (Python) or `resilience4j` (Java) for retry logic.

### Rate Limiting

**MUST enforce rate limits at ingress.**

Federated peers are untrusted—they could send 1M messages/second and DoS you.

**For server operators:** Configure per-server rate limits:

```
server-a.com: 1000 messages/minute
server-b.com: 500 messages/minute (lower reputation)
server-c.com: 10,000 messages/minute (verified, high reputation)
```

**Reputation scoring:** Track how often a peer sends valid vs. invalid messages. If `server-b` sends 50% invalid signatures, downgrade their reputation and tighten rate limits.

**For implementers:** Use a sliding window rate limiter (e.g., Redis with `INCR` + `EXPIRE`).

## Receipt Exchange

When one server executes a block on behalf of a user from another server, it sends the receipt back:

1. **Alice** (on `server-a`) sends a block to **Bob** (on `server-b`).
2. **server-b** executes the block, emits a receipt.
3. **server-b** sends the receipt to **server-a** (so Alice can verify billing).

**Why exchange receipts:** So Alice can audit `server-b`'s work. If the receipt claims 5M fuel but Alice's replay only uses 500k, she knows `server-b` is overcharging (or buggy).

**Receipt format:** Same as [Receipts](receipts.md), but wrapped in a federation envelope:

```json
{
  "from_server": "did:jig:server-b.com",
  "to_server": "did:jig:server-a.com",
  "timestamp": "2025-11-09T12:35:00Z",
  "nonce": "01932f9b-c456-7def-9abc-0123456789cd",
  "payload": {
    "type": "receipt",
    "receipt": { /* full receipt from receipts.md */ }
  },
  "signature": {
    "key": "ed25519:v1:serverBkey...",
    "signature": "ed25519:v1:sigBytes..."
  }
}
```

**For implementers:** Always verify incoming receipts by replaying the block locally (if you have it cached). If receipts repeatedly mismatch, downgrade that server's reputation.

## Reputation Scoring

Not all federated servers are equally trustworthy. Some are well-run and honest, others are buggy or malicious.

**Jig uses reputation scoring** to decide how much to trust a federated peer:

### Reputation Tiers

**`verified`**: Server has proven identity (e.g., domain ownership, PGP web of trust). High trust.

**`high_sec`**: Server has a good track record (valid signatures, accurate receipts). Moderate trust.

**`low_sec`**: Server is new or has occasional issues. Low trust.

**`null_sec`**: Server is unknown or has frequent violations. Minimal trust.

### How Reputation Changes

**Positive signals:**

- Valid signatures (every message verifies correctly).
- Accurate receipts (replays match claimed fuel usage).
- Uptime (server is reachable 99%+ of the time).

**Negative signals:**

- Invalid signatures (fails verification).
- Receipt fraud (replays show vastly different fuel usage).
- Downtime (server unreachable for extended periods).
- Spam (sends messages to non-existent users).

**For server operators:** Monitor your reputation with federated peers. If you drop to `low_sec`, investigate (certificate expired? Bug in signing code?).

**For implementers:** Track reputation locally (not gossiped globally—that's a privacy leak). Each server decides its own trust model.

## Security Considerations

### Metadata Minimization

**MUST minimize metadata in federation messages.**

Don't leak information beyond what's necessary for delivery:

- Don't include full user profiles in headers.
- Don't log full message content (just hashes for debugging).
- Don't expose internal IPs or server topology.

**For server operators:** Configure federation endpoints to strip unnecessary metadata.

### Fail Closed

**MUST reject unknown-critical fields.**

If a federation message includes a field you don't recognize and it's not in an `extensions` namespace, reject it.

**Why:** To prevent silent protocol extensions that could break security assumptions.

### Logging

**MUST minimize logging of federation data.**

- Log only metadata (sender server, timestamp, message ID).
- Don't log message content (violates user privacy).
- Expire logs quickly (7-30 days max).

**For server operators:** Federation logs are honeypots—attackers who breach your server get a complete map of who's talking to whom. Minimize what you log.

## Normative Requirements Summary

**MUST:**

- Use DNS SRV records (`_jig._tcp`) for service discovery.
- Publish public keys via `/.well-known/jig`.
- Use mutual TLS 1.3 for all federation connections.
- Sign all federation payloads with server keypair (E2E signatures).
- Perform replay detection (nonces + strict timestamp windows).
- Negotiate protocol versions explicitly (no silent downgrades).
- Enforce rate limiting at ingress.
- Implement retry with exponential backoff and jitter.
- Use circuit breakers to avoid thundering herds.
- Minimize metadata in federation messages.
- Fail closed on unknown-critical fields.
- Verify receipts by replaying blocks when fraud is suspected.

**SHOULD:**

- Use SPKI pinning for additional certificate validation.
- Track reputation scores for federated peers.
- Downgrade reputation for invalid signatures or receipt fraud.
- Expire federation logs within 7-30 days.
- Monitor version negotiation failures (indicates outdated peer or attack).

**MAY:**

- Implement custom reputation models (not standardized).
- Use alternative discovery methods (Tor hidden services, I2P, etc.).
- Add federation-specific extensions (in `extensions` namespace).

---

**Next:** You've reached the core technical chapters! For operational security and best practices, check out [Security Considerations](security.md). Or jump back to earlier chapters to dive deeper into [Block Execution](block-execution.md) or [Receipts](receipts.md).
