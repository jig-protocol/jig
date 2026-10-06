# Message Format

**Audience:** This chapter is for **protocol implementers** and **developers** building clients or servers. **End users** don't need to understand message formats—your client handles this. **Server operators** might care about message size limits and signature validation.

---

A Jig message is the atomic unit of communication. Every text message, every block, every control command—they all use the same envelope structure. This consistency makes the protocol simple to implement and easy to extend.

## The Envelope Model

Think of a Jig message like a physical envelope:

- **Outside (routing metadata)**: Sender, recipient, timestamp. This stays visible so relays can deliver it.
- **Inside (content)**: The actual message—text, blocks, binary data. This can be encrypted if you want privacy.
- **Seal (signatures)**: Cryptographic proof the message wasn't tampered with and really came from who it claims.

**Why separate routing from content?**

1. **Encryption flexibility**: You can encrypt content while leaving routing metadata visible. Relays need to know where to send the message, but they don't need to read it.

2. **Transport neutrality**: An IRC bridge can map routing metadata to IRC headers (FROM, TO, etc.) without understanding the content.

3. **Threading support**: Threading metadata lives in the envelope (thread IDs, reply-to pointers), so you can thread conversations without nesting messages infinitely deep.

**Trade-off:** More structure means slightly larger messages. But we're talking bytes, not kilobytes—and the flexibility is worth it.

## Envelope Structure

Every message MUST include these top-level fields:

```json
{
  "id": "01932f9a-b123-7abc-9def-0123456789ab",
  "version": 1,
  "routing": { /* addressing info */ },
  "content": { /* actual message */ },
  "signatures": [ /* cryptographic seals */ ],
  "extensions": { /* optional extras */ }
}
```

Let's break down each field:

### Message ID

```json
"id": "01932f9a-b123-7abc-9def-0123456789ab"
```

**What it is:** A UUIDv7 (time-ordered UUID). The timestamp embedded in the UUID makes IDs sortable—useful for displaying messages in chronological order.

**Why UUIDv7:** Because it's globally unique (no coordination needed) and time-ordered (messages naturally sort by creation time).

**Normative requirement:** Servers MUST reject messages with duplicate IDs. This prevents replay attacks—an attacker can't record a message and send it again.

**For implementers:** Use a library that generates UUIDv7 correctly. Don't just slap `uuid.v4()` in there—v4 is random and not time-ordered.

### Protocol Version

```json
"version": 1
```

**What it is:** The protocol version negotiated during the [Handshake](handshake.md). This stays constant for the entire session.

**Normative requirement:** Servers MUST reject messages with a version that wasn't negotiated during handshake. If handshake agreed on v1.2, every message MUST say `"version": 1` (major version).

**Why enforce this:** Prevents version confusion attacks where an attacker injects messages claiming to be a different protocol version mid-session.

### Routing Header

The `routing` object contains addressing and delivery metadata:

```json
"routing": {
  "from": "did:jig:alice",
  "to": "#general",
  "timestamp": "2025-11-09T12:34:56Z",
  "thread": "01932f8a-1111-7abc-9def-0123456789ab",
  "reply_to": "01932f9a-2222-7abc-9def-0123456789ab"
}
```

**Fields:**

**`from` (REQUIRED)**: Sender's DID or server identifier. For user messages, this is `did:jig:pubkey`. For server control messages, it might be a server domain.

**`to` (REQUIRED)**: Recipient. Can be:
- A channel: `#general`
- A user DID (direct message): `did:jig:bob`
- A broadcast target: `*` (all connected users)

**`timestamp` (REQUIRED)**: Message creation time in RFC 3339 format (UTC). Used for replay protection and chronological ordering.

**`thread` (OPTIONAL)**: UUID of the thread this message belongs to. For Slack-style threading, all replies in a thread reference the same `thread` ID.

**`reply_to` (OPTIONAL)**: UUID of the message being directly replied to. For nested Reddit-style threading, this creates parent-child relationships.

**For implementers:** Unknown fields in `routing` MUST be rejected (fail closed). If you see a `routing.foo` field you don't recognize, drop the message. This prevents silent protocol extensions that could break security assumptions.

**Exception:** `routing.extensions` (see below) is the namespace for optional metadata that implementations can safely ignore.

### Routing Extensions

```json
"routing": {
  "from": "did:jig:alice",
  "to": "#general",
  "timestamp": "2025-11-09T12:34:56Z",
  "extensions": {
    "com.example.priority": "high",
    "org.acme.tag": "urgent"
  }
}
```

**What it is:** A map of namespaced keys to arbitrary JSON values. This is where transport-specific or vendor-specific metadata goes.

**Namespacing:** Use reverse-DNS or similar (e.g., `com.example.foo`) to avoid collisions.

**Normative requirement:** Implementations MUST preserve unknown `extensions` entries verbatim when forwarding messages (so signatures stay valid), but MAY ignore them when processing.

**Why this matters:** Alice's client might add `com.alice-client.emoji-reaction: "👍"` to a message. Bob's client doesn't understand that extension, but it keeps the field intact when verifying Alice's signature—because the signature covers the entire envelope, including extensions.

## Content Variants

The `content` object has a `type` field that discriminates between different message types:

### Text Messages

The simplest content type: just text.

```json
"content": {
  "type": "text",
  "text": "Hello, world!"
}
```

**Markdown support:** Clients MAY render Markdown formatting:

```json
"content": {
  "type": "text",
  "text": "Here's some **bold** and _italic_ text."
}
```

**For developers:** If your client doesn't support Markdown, just display the raw text. Users can still read it.

**Trade-off:** Markdown is human-readable even without rendering (unlike HTML), but it's less expressive (no custom CSS, no JavaScript, no XSS vulnerabilities).

### Block Messages

Blocks are structured, composable message components. Think Notion or Slack's message composer—text blocks, code blocks, images, links.

```json
"content": {
  "type": "blocks",
  "blocks": [
    {
      "type": "text",
      "content": "Check out this code:"
    },
    {
      "type": "code",
      "language": "rust",
      "content": "fn main() {\n    println!(\"Hello, Jig!\");\n}"
    },
    {
      "type": "link",
      "url": "https://example.com",
      "text": "Learn more"
    }
  ]
}
```

**Why blocks:** Because composability. Instead of cramming everything into a single text field with ad-hoc formatting, blocks let you mix text, code, images, quotes, tables, etc., in a structured way.

**Standard block types:**

- **`text`**: Plain text or Markdown.
  ```json
  { "type": "text", "content": "Hello!" }
  ```

- **`code`**: Syntax-highlighted code.
  ```json
  {
    "type": "code",
    "language": "python",
    "content": "print('Hello')"
  }
  ```

- **`quote`**: Block quote.
  ```json
  { "type": "quote", "content": "To be or not to be" }
  ```

- **`list`**: Ordered or unordered list.
  ```json
  {
    "type": "list",
    "ordered": true,
    "items": ["First", "Second", "Third"]
  }
  ```

- **`table`**: Tabular data.
  ```json
  {
    "type": "table",
    "headers": ["Name", "Age"],
    "rows": [["Alice", "30"], ["Bob", "25"]]
  }
  ```

- **`link`**: Hyperlink with optional text.
  ```json
  {
    "type": "link",
    "url": "https://jig.onl",
    "text": "Jig Protocol"
  }
  ```

**Unknown block types:** Clients MUST ignore block types they don't recognize, but MUST preserve the raw JSON for signature verification.

**Example:** Alice's cutting-edge client sends a `type: "3d-model"` block. Bob's old client doesn't know what that is, so it shows `[Unsupported block type: 3d-model]`. But Bob's client keeps the raw JSON when validating Alice's signature—because the signature covers the entire message, including unknown blocks.

**For developers:** When rendering unknown blocks, show a fallback like `[Unsupported: <type>]` or check for a `metadata.fallback_text` field.

### Executable Blocks (Wasm)

Executable blocks are WebAssembly modules embedded in messages. See [Block Execution Model](block-execution.md) for full details.

```json
"content": {
  "type": "executable_block",
  "manifest": {
    "block_id": "cid:bafyreigz7...",
    "version": "0.2.0",
    "authors": ["did:jig:alice"],
    "constraints": {
      "max_fuel": 1000000,
      "max_memory_pages": 16
    },
    "capabilities": {
      "net.fetch": ["https://api.weather.gov/*"],
      "crypto.sign": []
    }
  },
  "code_cid": "cid:bafyreigz7...",
  "resources": []
}
```

**What this enables:** Alice sends a block that fetches weather data from an API and formats it as a message. The server executes it, charges Alice based on CPU used (fuel), and emits a signed receipt proving the API call succeeded.

**Security:** Blocks start with zero permissions. The `capabilities` field explicitly grants network access (to specific URLs) and crypto operations. The server decides whether to honor these requests based on Alice's reputation and quotas.

**For end users:** Executable blocks are like secure, metered Lambda functions in your messages. Your client handles them automatically—you just see the result (e.g., "Weather in SF: 65°F, sunny").

### Binary Messages

For images, videos, files, etc.

```json
"content": {
  "type": "binary",
  "mime_type": "image/png",
  "data": "iVBORw0KGgoAAAANSUhEUgAA...",
  "metadata": {
    "filename": "screenshot.png",
    "size_bytes": 42378
  }
}
```

**`data`**: Base64-encoded binary content.

**`mime_type`**: Standard MIME type (e.g., `image/png`, `application/pdf`, `video/mp4`).

**`metadata`**: Optional map with filename, size, checksum, etc.

**Trade-off:** Base64 encoding increases size by ~33%. For large files, consider uploading to a content-addressable storage system (IPFS, S3) and sending a link instead.

**For developers:** When receiving binary messages, decode base64, validate MIME type, and check `metadata.size_bytes` against your client's size limits before processing.

### Control Messages

Control messages coordinate protocol operations (channel joins, presence updates, typing indicators).

```json
"content": {
  "type": "control",
  "command": "channel.join",
  "params": {
    "channel": "#general"
  }
}
```

**Common control commands:**

- **`channel.join`**: User joins a channel.
- **`channel.part`**: User leaves a channel.
- **`user.presence`**: User status change (online, away, offline).
- **`typing.indicator`**: User is typing (ephemeral, not persisted).

**Normative requirement:** Control messages MUST still be signed (they're not exempt from authentication just because they're protocol coordination).

**For implementers:** Control messages should NOT be logged or persisted (except for audit purposes). They're ephemeral state updates.

## Threading

Jig supports multiple threading models:

### Linear (IRC-style)

No threading—messages are just a flat chronological stream.

```json
{ "id": "msg-1", "routing": { "to": "#general" }, "content": { "type": "text", "text": "A" } }
{ "id": "msg-2", "routing": { "to": "#general" }, "content": { "type": "text", "text": "B" } }
{ "id": "msg-3", "routing": { "to": "#general" }, "content": { "type": "text", "text": "C" } }
```

All messages appear in order: A, B, C.

**When to use:** IRC mode, real-time chat where context is implicit from recent history.

### Slack-Style Threads

Messages in a thread share a common `thread` ID (usually the ID of the first message in the thread).

```json
// Original message
{
  "id": "msg-1",
  "routing": { "to": "#general" },
  "content": { "type": "text", "text": "Anyone know how to deploy Jig?" }
}

// Reply in thread
{
  "id": "msg-2",
  "routing": {
    "to": "#general",
    "thread": "msg-1",
    "reply_to": "msg-1"
  },
  "content": { "type": "text", "text": "Check the docs at jig.onl" }
}

// Another reply in same thread
{
  "id": "msg-3",
  "routing": {
    "to": "#general",
    "thread": "msg-1",
    "reply_to": "msg-1"
  },
  "content": { "type": "text", "text": "Or use the one-liner: curl -L https://jig.onl | sh" }
}
```

All three messages have `thread: "msg-1"`, so the client can display them together as a thread.

**When to use:** Slack-like UX where threads are collapsed and expanded on demand.

### Nested (Reddit/Forum-Style)

Messages form a tree via `reply_to` pointers.

```json
// Top-level post
{
  "id": "msg-1",
  "routing": { "to": "#general" },
  "content": { "type": "text", "text": "What's your favorite Jig feature?" }
}

// Reply to top-level
{
  "id": "msg-2",
  "routing": { "to": "#general", "reply_to": "msg-1" },
  "content": { "type": "text", "text": "Signed blocks!" }
}

// Reply to msg-2 (nested)
{
  "id": "msg-3",
  "routing": { "to": "#general", "reply_to": "msg-2" },
  "content": { "type": "text", "text": "Yeah, privacy is key" }
}

// Another reply to top-level
{
  "id": "msg-4",
  "routing": { "to": "#general", "reply_to": "msg-1" },
  "content": { "type": "text", "text": "Executable blocks are wild" }
}
```

This forms a tree:
```
msg-1
├─ msg-2
│  └─ msg-3
└─ msg-4
```

**When to use:** Forums, Reddit-style discussions, anywhere deep nesting is valuable.

**Trade-off:** More complex to render and navigate. Deep nesting can be confusing.

**For developers:** Support whichever threading model fits your UX. The protocol is flexible—you can render Slack-style threads in a forum client or vice versa.

## Signatures

Every message MUST be signed by the sender.

```json
"signatures": [
  {
    "key": "ed25519:v1:PkQx7TfHJ_3eLZ8YxH4YGJLXVJsJcZjYh7x_VJLXVJs",
    "signature": "ed25519:v1:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
  }
]
```

**What gets signed:** Canonical JSON of `{id, version, routing, content}`. Everything except the `signatures` field itself.

**Canonicalization:** Use deterministic JSON encoding:
- Keys sorted lexicographically
- No extra whitespace
- Numbers in standard form (no leading zeros, scientific notation only when necessary)

See [Appendix § Canonicalization](appendix.md#canonicalization) for test vectors.

**Why array:** To support multi-signature scenarios (e.g., a message co-signed by a bot and a human, or a server attestation plus user signature).

**Normative requirement:** Servers MUST verify at least one signature before accepting a message. Invalid signatures MUST cause message rejection (fail closed).

**For implementers:** Use constant-time signature verification (see [Crypto Primitives § Constant-Time Operations](crypto.md#constant-time-operations)) to prevent timing attacks.

## Replay Protection

Messages include a timestamp and a unique ID. Servers use these to prevent replay attacks:

**Nonce (ID):** UUIDv7 is globally unique and time-ordered. Servers track seen IDs (e.g., in a bloom filter or time-windowed cache) and reject duplicates.

**Timestamp window:** Servers reject messages with timestamps too far in the past or future (e.g., ±10 minutes). This limits the replay window.

**Example attack prevented:**

1. Attacker records Alice's message: `{"id": "msg-1", "timestamp": "2025-11-09T12:00:00Z", "content": "Transfer 10 credits to Bob"}`
2. Attacker tries to replay it 100 times.
3. Server sees duplicate `id: "msg-1"` and rejects all but the first instance.

**For server operators:** Configure timestamp windows based on your clock sync tolerance. If clients have NTP enabled, ±5 minutes is reasonable. If not, ±10 minutes to allow for clock drift.

**Trade-off:** Stricter windows (±1 minute) improve security but require better clock sync. Looser windows (±30 minutes) tolerate clock drift but increase replay risk.

## Encryption

> **Not implemented in v0.1.** Content is signed, never encrypted.

Encryption is specified in [Encryption](encryption.md): the suite (MLS by default) is
named on every frame and in the manifest, and is fixed per channel. Routing metadata stays
visible to the server.

## Extensions (Top-Level)

Similar to `routing.extensions`, but for message-level metadata:

```json
{
  "id": "...",
  "version": 1,
  "routing": { /* ... */ },
  "content": { /* ... */ },
  "signatures": [ /* ... */ ],
  "extensions": {
    "com.slack.reactions": ["👍", "❤️"],
    "org.example.priority": "urgent"
  }
}
```

**Use cases:**

- **Reactions**: Slack-style emoji reactions (not part of core protocol but widely useful).
- **Priority flags**: Mark messages as urgent, low-priority, etc.
- **Client metadata**: Track which client sent the message (useful for debugging).

**Normative requirement:** Unknown `extensions` MUST be preserved when forwarding (so signatures stay valid) but MAY be ignored when processing.

## Serialization

Messages are serialized as JSON or CBOR:

### JSON (Default)

Most transports (WebSocket, IRC, SSH) use JSON because it's human-readable and debugging-friendly.

**Canonical form for signatures:**

```json
{"content":{"text":"Hello","type":"text"},"id":"01932f9a-b123-7abc-9def-0123456789ab","routing":{"from":"did:jig:alice","timestamp":"2025-11-09T12:34:56Z","to":"#general"},"version":1}
```

- Keys sorted lexicographically
- No whitespace
- Deterministic number formatting

**For implementers:** Use a canonicalization library (e.g., `jcs` for JSON Canonicalization Scheme) to ensure deterministic encoding.

### CBOR (Optional)

For binary transports or size-constrained environments (e.g., IoT devices), CBOR is more compact.

**Canonical form:** Use deterministic CBOR encoding (RFC 8949 § 4.2).

**For developers:** If your client supports CBOR, advertise it during handshake as a feature (`cbor_encoding: "optional"`). If the server supports it, you can switch to CBOR for all subsequent messages.

**Trade-off:** CBOR is ~30% smaller than JSON but not human-readable. Use JSON for debugging, CBOR for production.

## Unknown Fields and Forward Compatibility

**Normative requirements:**

- Unknown fields at the **top level** (outside `extensions`) MUST be rejected (fail closed).
- Unknown fields in **`routing`** (outside `routing.extensions`) MUST be rejected.
- Unknown fields in **`extensions`** or **`routing.extensions`** MUST be preserved but MAY be ignored.
- Unknown **content types** MUST be rejected.
- Unknown **block types** MUST be preserved but ignored (show fallback).

**Why fail closed:** To prevent silent protocol extensions that could break security assumptions. If a future version adds a `routing.priority` field that affects delivery order, old implementations must reject messages with that field—not silently ignore it and deliver out of order.

**Exception:** The `extensions` namespace is explicitly for optional metadata that old implementations can safely ignore.

**For implementers:** When you see an unknown field, check if it's inside an `extensions` map. If yes, ignore it. If no, reject the message.

## Normative Requirements Summary

**MUST:**

- Include `id`, `version`, `routing`, `content`, `signatures` in every message.
- Use UUIDv7 for message IDs.
- Sign messages with Ed25519 (or negotiated crypto suite).
- Verify at least one signature before accepting a message.
- Reject messages with duplicate IDs (replay protection).
- Reject messages with timestamps outside the acceptable window (e.g., ±10 minutes).
- Preserve unknown `extensions` fields for signature verification.
- Reject unknown top-level or routing fields (outside `extensions`).
- Use canonical JSON or CBOR encoding for signature verification.

**SHOULD:**

- Use Markdown for text formatting (for human readability).
- Provide fallback rendering for unknown block types.
- Set timestamp windows based on clock sync tolerance (±5 to ±10 minutes).

**MAY:**

- Support CBOR encoding for binary transports.
- Implement multiple threading models (linear, Slack-style, nested).
- Add custom `extensions` for client-specific metadata.
- Multi-sign messages (e.g., user + bot co-signature).

---

**Next:** With messages defined, let's dive into [Block Execution Model](block-execution.md) to see how executable blocks work, or jump to [Transports](transports.md) to see how messages are adapted for IRC, WebSocket, SSH, and Email.
