# Transports

**Audience:** This chapter is for **protocol implementers** building clients or servers that need to support multiple transports, and **server operators** deciding which transports to enable. **End users** might care about which transports their favorite clients support. **Developers** building integrations (IRC bots, email gateways) will want to understand transport-specific constraints.

---

Jig isn't forcing you to adopt a new client. Instead, it meets you where you are—IRC, WebSocket, SSH, Email. The protocol stays the same, but the transport adapts.

## Why Multiple Transports?

Here's the problem: everyone has their own workflow. Some people live in terminals (IRC, SSH). Others use browsers (WebSocket). Your boss uses Outlook (Email). Forcing everyone onto a single client kills adoption.

Jig solves this by **transport neutrality**:

- **Same protocol, different wrappers**: Messages, blocks, receipts work identically across all transports. A message sent via IRC arrives via WebSocket with the same content.
- **Meet users where they are**: Want to use weechat? Connect via IRC. Building a web app? Use WebSocket. Need to integrate with email? Bridge it.
- **Graceful degradation**: If a transport can't support E2EE (like IRC), it falls back to plaintext mode (with user consent).

**Trade-off:** More implementation complexity. You need to support multiple transport layers instead of just one. But the payoff is universal accessibility—anyone can use Jig without installing new software.

## General Requirements (All Transports)

Before diving into transport-specific details, here are rules that apply to **all** transports:

### TLS 1.3 Only

**MUST use TLS 1.3** for all TLS-based transports (WebSocket, SSH with TLS, Email with STARTTLS).

**No TLS 1.2 or older.** Cipher suites MUST provide:

- **AEAD** (Authenticated Encryption with Associated Data): `AES-GCM`, `ChaCha20-Poly1305`
- **PFS** (Perfect Forward Secrecy): Ephemeral Diffie-Hellman key exchange

**Why TLS 1.3:** Because TLS 1.2 has optional features that downgrade security (weak ciphers, no PFS by default). TLS 1.3 removes that optionality—everything is secure by default.

**For implementers:** Configure your TLS library to reject TLS 1.2 and older. Use OpenSSL 1.1.1+ or BoringSSL.

### Minimize Metadata

**MUST omit unnecessary headers and identifiers.**

Don't leak information beyond what's required for delivery:

- WebSocket: Don't send custom headers (except `Origin` for CORS checks).
- IRC: Don't relay Jig-specific metadata in CTCP messages.
- Email: Don't include Jig DIDs in email headers (they're in the message body, encrypted if E2EE).

**Why:** Metadata is an attack surface. The more you transmit, the more can be logged, intercepted, or leaked.

**For server operators:** Configure your transports to strip unnecessary metadata at ingress.

### Fail Closed

**MUST reject malformed or unknown-critical inputs.**

If you see a field you don't understand and it's marked critical (not in an `extensions` namespace), reject the connection/message.

**For implementers:** Parse strictly. Don't silently ignore unknown fields—log and reject.

### Rate Limiting

**MUST enforce rate limits at ingress to prevent DoS.**

Every transport is an attack vector. Without rate limits, an attacker can flood the server with garbage.

**For server operators:** Configure per-IP and per-DID rate limits. Example:

- **WebSocket**: 100 messages/minute per connection
- **IRC**: 10 JOIN/PART per minute per user
- **Email**: 50 emails/hour per sender domain

**Trade-off:** Legitimate high-volume users (bots, automation) need higher quotas. Use reputation tiers (see [Handshake § Capability Grants](handshake.md#capability-grants)).

### End-to-End Verification

**Transport security does not replace E2E verification.**

Even if TLS 1.3 encrypts the connection, **messages MUST still be signed** by the sender. This prevents malicious servers from forging messages.

**Why:** TLS protects you from network attackers, but not from compromised servers. E2E signatures mean even the server can't forge messages.

## IRC Bridge

IRC is the oldest and simplest transport. It's plaintext by default (most IRC clients don't do E2EE), but it works with 30+ years of existing clients and muscle memory.

### Core Commands

Jig IRC bridges MUST support these RFC 1459 commands:

**`NICK <nickname>`**: Set nickname. Maps to Jig DID (hashed or truncated for IRC's 9-char nick limit).

**`USER <username> <hostname> <servername> <realname>`**: Identify user. Jig uses `username` as a hint but relies on DID for actual identity.

**`JOIN <channel>`**: Join a channel. Maps directly to Jig channels (e.g., `JOIN #general` → join `#general` on Jig).

**`PART <channel> [reason]`**: Leave a channel.

**`PRIVMSG <target> :<message>`**: Send a message. Maps to Jig text messages.

**Optional:**

- `WHOIS <nick>`: Query user info (returns DID, reputation tier).
- `MODE <channel> +o <nick>`: Grant operator status (maps to Jig capability grants).

### Message Mapping

**Text content MUST be preserved exactly.**

If Alice sends "Hello, world!" via IRC, Bob sees "Hello, world!" via WebSocket (same bytes).

**Formatting SHOULD be preserved when possible:**

- **Bold**: `\x02text\x02` (IRC) → `**text**` (Markdown)
- **Italic**: `\x1Dtext\x1D` (IRC) → `*text*` (Markdown)
- **Colors**: Strip (IRC color codes don't map to Markdown)

**For implementers:** Use a library like `irc-formatting` to parse IRC control codes and convert to Markdown.

### Identity Mapping

**DIDs must fit IRC's 9-character nick limit.**

Jig DIDs look like `did:jig:base58pubkey` (long). IRC nicks are max 9 chars.

**Solution:** Hash and truncate:

```
nick = base58(BLAKE3(did))[:9]
```

Example: `did:jig:5HpG9w8EBLe9vNqvdcXtUNJRaWHhTjdxYWdBqNpmQBZG` → `H3x9AkLm2`

**Collision resistance:** With 9 chars of base58 (approx. 52 bits of entropy), collisions are rare (~1 in 4 trillion).

**For developers:** Store the DID ↔ nick mapping in a database. When a user joins, check if their nick is taken; if yes, append a suffix (`H3x9AkLm2_`).

### Security Constraints

**No E2EE support** (IRC clients don't understand it).

**Solution:** Messages are sent plaintext, but still signed. Users opting into IRC mode are explicitly choosing plaintext communication (with signatures for authenticity).

**For server operators:** Warn users when they connect via IRC:

```
:server NOTICE alice :You are using IRC mode. Messages are NOT encrypted. Use WebSocket for E2EE.
```

**Information leakage:** IRC bridge MUST NOT tunnel Jig-specific metadata via CTCP or other side channels.

**For implementers:** Only map core IRC commands. Don't expose Jig blocks, receipts, or capabilities via IRC (clients won't understand them anyway).

### Trade-Offs

**Pros:**

- **Universal compatibility**: Works with any IRC client (weechat, irssi, HexChat, mIRC).
- **Muscle memory**: If you know IRC, you know Jig IRC mode.
- **Low bandwidth**: Text-only, no images or blocks (unless you use pastebins).

**Cons:**

- **No E2EE**: Plaintext by design.
- **Limited features**: No threading, no reactions, no rich formatting.
- **Nick collisions**: Hash-based nicks can be confusing.

**When to use:** For terminal users, automation scripts, or environments where WebSocket/SSH aren't available.

## WebSocket

WebSocket is the primary transport for modern web and desktop clients. It's real-time, bidirectional, and fully supports E2EE, blocks, receipts, and all Jig features.

### Connection Setup

**MUST use WSS** (WebSocket over TLS 1.3). Plain `ws://` is forbidden.

**Origin checking MUST be enforced:**

```javascript
// Server-side (Node.js example)
wss.on('connection', (ws, req) => {
  const origin = req.headers.origin;
  if (!ALLOWED_ORIGINS.includes(origin)) {
    ws.close(1008, 'Forbidden origin');
    return;
  }
  // Continue handshake
});
```

**Why origin checking:** Prevents cross-site WebSocket hijacking (CSWSH). Without origin checks, a malicious site could open a WebSocket to your Jig server and send messages on behalf of the user.

**For developers:** Always send the `Origin` header from your client. Servers reject connections without it.

### Subprotocol Negotiation

Clients MUST declare supported subprotocols:

```javascript
const ws = new WebSocket('wss://server.example.com/jig', ['jig-v1', 'jig-v2']);
```

Server responds with the chosen subprotocol:

```
HTTP/1.1 101 Switching Protocols
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Protocol: jig-v1
```

**No subprotocol match → reject connection.**

**Why explicit negotiation:** Prevents silent protocol downgrades. If the client only supports `jig-v2` but the server only supports `jig-v1`, they can't communicate—fail loudly.

### Message Framing

Messages are sent as **JSON** (default) or **CBOR** (optional, negotiated during handshake):

```json
{
  "id": "01932f9a-b123-7abc-9def-0123456789ab",
  "version": 1,
  "routing": { "from": "did:jig:alice", "to": "#general", "timestamp": "2025-11-09T12:34:56Z" },
  "content": { "type": "text", "text": "Hello via WebSocket!" },
  "signatures": [{ "key": "ed25519:v1:...", "signature": "ed25519:v1:..." }]
}
```

Each message is a single WebSocket frame (no fragmentation unless the message exceeds frame size limits).

**For implementers:** Use `wss.send(JSON.stringify(message))` to send, `JSON.parse(data)` to receive.

### Compression

**Compression SHOULD be disabled** unless authenticated and non-leaky.

Why disable compression? **CRIME/BREACH attacks**. If an attacker can inject data into your WebSocket stream and observe compressed size changes, they can extract secrets (like session tokens).

**If you must enable compression:**

- Use `permessage-deflate` extension
- Disable context takeover (`client_no_context_takeover`, `server_no_context_takeover`)
- Only compress non-sensitive messages

**For server operators:** Disable compression by default. If users complain about bandwidth, enable it only for authenticated, high-reputation users.

### JSON-RPC Style

WebSocket communication SHOULD use a JSON-RPC-like request/response pattern for control commands:

**Request:**

```json
{
  "jsonrpc": "2.0",
  "method": "channel.join",
  "params": { "channel": "#general" },
  "id": 1
}
```

**Response:**

```json
{
  "jsonrpc": "2.0",
  "result": { "status": "joined", "channel": "#general" },
  "id": 1
}
```

**For developers:** Use the `id` field to match responses to requests (async operations).

### Security Properties

**Full E2EE support:** Messages can be encrypted (see [Message Format § Encryption](message-format.md#encryption)).

**Replay protection:** UUIDv7 message IDs and timestamp windows prevent replay attacks.

**Origin-based access control:** Only whitelisted origins can connect (mitigates CSWSH).

**For implementers:** Always validate origin, enforce TLS 1.3, and verify message signatures.

### Trade-Offs

**Pros:**

- **Real-time**: Instant message delivery (no polling).
- **Full features**: E2EE, blocks, receipts, threading—everything works.
- **Browser-native**: No plugins, just JavaScript.

**Cons:**

- **More complex**: Requires a WebSocket server (not just HTTP).
- **Stateful**: Server must maintain open connections (harder to scale than HTTP).
- **Firewall issues**: Some corporate firewalls block WebSocket.

**When to use:** For web and desktop clients where real-time communication and full feature support matter.

## SSH Transport

SSH is for terminal users and automation scripts. It's secure by default (authenticated encryption) and works great for CLI tools.

### Subsystem

Clients connect via SSH subsystem:

```bash
ssh -s jig user@server.example.com
```

The `-s jig` flag tells SSH to invoke the `jig` subsystem instead of a shell.

**Server configuration (`/etc/ssh/sshd_config`):**

```
Subsystem jig /usr/local/bin/jig-server --subsystem
```

When a client requests the `jig` subsystem, the SSH daemon spawns `/usr/local/bin/jig-server --subsystem` and pipes stdin/stdout.

### Message Format

Messages are sent as **line-delimited JSON** over the SSH channel:

```
{"id":"msg-1","version":1,"routing":{...},"content":{...},"signatures":[...]}\n
{"id":"msg-2","version":1,"routing":{...},"content":{...},"signatures":[...]}\n
```

Each line is a complete JSON message (no fragmentation).

**For implementers:** Use `readline()` to read messages, `write(json + '\n')` to send.

### Authentication

SSH handles authentication (public key, password, etc.). Once authenticated, the user's SSH key maps to their Jig DID:

```
ssh_pubkey = "ssh-ed25519 AAAAC3NzaC1..."
did = "did:jig:" + base58(ssh_pubkey)
```

**For server operators:** Configure SSH authorized keys (`~/.ssh/authorized_keys`) to allow specific DIDs.

### Security Properties

**Authenticated encryption by default:** SSH provides TLS-equivalent security (Diffie-Hellman key exchange, ChaCha20-Poly1305 or AES-GCM encryption).

**No origin checks needed:** SSH doesn't have the same cross-origin issues as WebSocket (it's a dedicated connection, not browser-based).

**For implementers:** Only enable modern SSH ciphers:

```
# /etc/ssh/sshd_config
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
```

Disable legacy algorithms (`ssh-rsa`, `3des-cbc`, etc.).

### Rate Limiting

**Session channels MUST be rate limited.**

An attacker with a valid SSH key could open thousands of subsystems and DoS the server.

**For server operators:** Limit concurrent SSH sessions per user:

```
MaxSessions 10
MaxStartups 30:10:60
```

**Idle timeouts SHOULD be enforced:**

```
ClientAliveInterval 300  # Ping client every 5 minutes
ClientAliveCountMax 2    # Disconnect after 2 missed pings
```

### Trade-Offs

**Pros:**

- **Secure by default**: SSH handles encryption and authentication.
- **Terminal-friendly**: Works with any SSH client.
- **Scriptable**: Perfect for automation (e.g., `echo '{"id":"msg-1",...}' | ssh -s jig user@server`).

**Cons:**

- **Text-only**: Not suitable for rich clients (use WebSocket for that).
- **No browser support**: SSH doesn't work in browsers (use WebSocket).
- **Firewall issues**: Some networks block SSH (port 22).

**When to use:** For CLI tools, automation scripts, or server-to-server communication.

## Email Bridge

Email is the ultimate compatibility layer—your boss uses Outlook, and you're not going to convince them to install a Jig client. The email bridge lets you send and receive Jig messages as emails.

### Inbound (SMTP → Jig)

When someone emails `alice@jig.example.com`, the server:

1. **Receives email via SMTP**.
2. **Parses headers and body**:
   - `From: bob@example.com` → maps to Jig DID (if known) or creates a guest identity
   - `To: alice@jig.example.com` → routes to `did:jig:alice`
   - `Subject:` → ignored (Jig has no subject field; use first line of body)
   - Body → becomes `content.type = "text"`
3. **Signs the message** with the bridge's keypair (not Bob's—Bob doesn't have a Jig DID).
4. **Delivers to Jig** as a normal message.

**For implementers:** Use an SMTP server (e.g., Postfix, OpenSMTPD) and pipe incoming mail to a Jig bridge script.

### Outbound (Jig → SMTP)

When Alice sends a Jig message to `bob@example.com`, the server:

1. **Receives Jig message** (signed by Alice).
2. **Converts to email**:
   - `routing.from = "did:jig:alice"` → `From: alice@jig.example.com`
   - `routing.to = "bob@example.com"` → `To: bob@example.com`
   - `content.type = "text"` → email body
   - Signatures → `X-Jig-Signature` header (so Jig clients can verify)
3. **Sends via SMTP**.

**For implementers:** Use an SMTP library (e.g., `nodemailer`, `smtplib`) to send emails.

### Security Constraints

**No E2EE support** (email clients don't understand Jig encryption).

**Solution:** Messages are plaintext, but still signed. Users opting into email mode are explicitly choosing plaintext communication.

**For server operators:** Warn users when bridging to email:

```
Your message to bob@example.com will be sent as plaintext email (not encrypted).
```

**Spam and abuse:** Email is a major spam vector. Bridges MUST enforce strict rate limits (see [Zero-Trust § Rate Limiting](zero-trust.md#rate-limiting-and-dos-protection)).

**For server operators:** Validate sender domains (SPF, DKIM, DMARC) and reject emails from untrusted sources.

### Threading

Email threading (via `In-Reply-To` and `References` headers) maps to Jig threading:

- `In-Reply-To: <msg-1@jig.example.com>` → `routing.reply_to = "msg-1"`
- `References: <msg-1@jig.example.com> <msg-2@jig.example.com>` → `routing.thread = "msg-1"`

**For developers:** Parse email headers and map to Jig `routing` fields.

### Trade-Offs

**Pros:**

- **Universal compatibility**: Works with any email client (Outlook, Gmail, Thunderbird).
- **Asynchronous**: No need for real-time connections.
- **Archival**: Email clients handle storage and search.

**Cons:**

- **No E2EE**: Plaintext by design.
- **High latency**: Email can take seconds to minutes to deliver.
- **Spam**: Email is a major abuse vector (requires strict rate limiting).

**When to use:** For integrating with non-Jig users (bosses, clients, legacy systems).

## Normative Requirements Summary

**MUST (All Transports):**

- Use TLS 1.3 for all TLS-based transports (WebSocket, SSH with TLS, Email with STARTTLS).
- Minimize metadata (omit unnecessary headers/identifiers).
- Fail closed on malformed or unknown-critical inputs.
- Enforce rate limiting at ingress.
- Verify end-to-end signatures (transport security doesn't replace E2E verification).

**MUST (IRC):**

- Support core commands: `NICK`, `USER`, `JOIN`, `PART`, `PRIVMSG`.
- Preserve text content exactly.
- Use deterministic, collision-resistant nick mapping (hash-based).
- Prevent information leakage beyond mapped fields.

**MUST (WebSocket):**

- Use WSS (WebSocket over TLS 1.3) only.
- Enforce origin checking (reject unexpected `Origin` headers).
- Negotiate subprotocols explicitly (no silent downgrade).

**MUST (SSH):**

- Provide `-s jig` subsystem.
- Disable legacy SSH algorithms (only modern ciphers, KEX, MACs).
- Rate limit session channels and enforce idle timeouts.

**MUST (Email):**

- Validate sender domains (SPF, DKIM, DMARC).
- Enforce strict rate limits (email is a spam vector).
- Warn users about plaintext mode.

**SHOULD:**

- Use JSON-RPC style for WebSocket control commands.
- Disable WebSocket compression unless authenticated and non-leaky.
- Preserve basic formatting when bridging (e.g., IRC bold → Markdown).

**MAY:**

- Support optional IRC commands (`WHOIS`, `MODE`).
- Implement custom threading for email (map `In-Reply-To` to Jig threading).
- Use CBOR encoding for WebSocket (negotiate during handshake).

---

**Next:** Now that you understand how transports work, check out [Federation](federation.md) to see how servers communicate with each other, or jump to [Security Considerations](security.md) for operational security best practices.
