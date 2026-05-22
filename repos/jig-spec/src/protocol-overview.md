# Protocol Overview

**Audience:** This chapter is for **developers** and **protocol implementers** who need to understand Jig's architecture. **Server operators** might find the scaling and transport sections useful. **End users** can skip this—it's pretty technical.

---

Before diving into the technical details, let's get oriented. This chapter walks through Jig's core concepts and how they fit together.

If you're the "show me the code" type, you might want to skip straight to [Message Format](message-format.md) or [Block Execution Model](block-execution.md). But if you're here to understand _why_ Jig works the way it does, stick around.

> **First-time reader?** We recommend reading [Zero-Trust Model](zero-trust.md) right after this chapter. It explains the security assumptions that inform every other decision in this spec.

## Core Concepts

### Identities: You Are Your Keys

In Jig, your identity **is** your Ed25519 keypair. No email signup, no OAuth dance, no password reset flow. Just you and your keys.

**Why this matters:** You can't be de-platformed. If a server bans you, take your keys elsewhere and you're still you. Your DIDs (`did:jig:alice123`) are portable across servers because they're cryptographically derived from your public keys, not assigned by a central authority. This also means you can have diverse identities, compartmentalized to different servers and communities, since you can have arbitrary numbers of keys.

**Trade-off:** Lose your keys, lose your identity. This is why we recommend key backup strategies in [Crypto Primitives](crypto.md#key-management), but the protocol itself stays agnostic — your keys, your responsibility. There's also a potential downside to having too many unique identities: if you're signing into a server with a heretofore unknown keypair, you're starting 'from scratch' in terms of reputation (more on reputation in a bit).

For the full cryptographic details, see [Crypto Primitives](crypto.md#identities-and-dids).

### Messages: More Than Just Text

A Jig message is an **envelope** containing:

- **Content** (text, blocks, binary data, or control commands)
- **Routing metadata** (sender, recipient, threading)
- **Signatures** (cryptographic proof of authorship)

**Why envelopes matter:** By separating routing from content, we can:

- Encrypt content while leaving routing metadata visible (for relay efficiency)
- Thread conversations without nesting messages (Slack-style or Reddit-style threading)
- Add new content types without breaking old clients (forward compatibility)

**Real-world example:** An email bridge can route Jig messages over SMTP by mapping the envelope to email headers, even if it can't decrypt the content. The message still gets delivered.

For the full schema, see [Message Format](message-format.md).

### Blocks: Lambdas in Your Messages

Here's where Jig gets interesting. A **block** is a WebAssembly module embedded in a message. Think of it like a secure, metered Lambda function—but instead of calling AWS, you're packaging the code _with_ the message.

**What's in a block:**

- **WebAssembly module**: Deterministic code that runs the same everywhere
- **Manifest**: Declares what capabilities it needs (network access, crypto, storage)
- **Resources**: Optional data files (images, configs, etc.)
- **Receipts**: After execution, hosts emit a signed receipt proving what happened

**Why executable messages?**

1. **Outcome-based pricing**: Hosts charge based on CPU used (`fuel`) and whether the block succeeded. Failed executions cost less. This aligns incentives—you don't pay full price for the host's bugs.

2. **Portable verification**: Anyone can re-execute a block with the same inputs and verify the receipt matches. This prevents billing fraud and enables trustless federation.

3. **Capability-based security**: Blocks start with zero permissions. Want network access? Declare it in the manifest. The host decides whether to grant it based on policy (reputation, quotas, etc.).

**Real-world example:** You send a block that fetches weather data from an API and formats it as a message. The host executes it, charges you 0.0001 credits (fuel-based pricing), and emits a receipt proving the API returned 200 OK. If the API times out, you get a `soft_fail` receipt and only pay 50% since the host couldn't deliver the outcome.

For full technical details:

- [Block Execution Model](block-execution.md) explains the validation → execution → receipt lifecycle
- [Receipts](receipts.md) covers the v0.2 receipt schema with fuel metering

### Channels: IRC, But Better

Channels work like IRC: `#general`, `#random`, `#potato-enthusiasts`. Join, chat, leave. But with Jig, channels support:

- **Threading**: Slack-style threads or Reddit-style nested replies (see [Message Format](message-format.md#threading))
- **Access control**: Capability-based permissions instead of flat `+o` operator flags
- **Federation**: Channels can span multiple servers transparently

**What didn't change:** The fundamentals. If you know `/join`, `/part`, `/msg`, you know Jig. We respect IRC muscle memory because it's proven UX that's stood the test of time.

### Transports: Meet People Where They Are

Jig isn't trying to force everyone onto a new client. Instead, we support multiple transports so you can use the tools you already have:

**IRC (RFC 1459)**
: Connect via any IRC client (weechat, irssi, HexChat). Perfect for terminal lovers. Trade-off: No E2EE support (IRC clients don't understand it), so messages are plaintext.

**WebSocket**
: Real-time bidirectional communication for web/desktop apps. Full E2EE support, block execution, everything.

**Email (SMTP/IMAP)**
: Bridge Jig channels to email. Your boss can reply from Outlook without knowing Jig exists. Trade-off: Asynchronous, no real-time features.

**SSH**
: Secure terminal access for servers and automation scripts. Think `git push` over SSH, but for messages.

For transport-specific protocols, see [Transports](transports.md).

## How It All Fits Together

Here's a typical flow from connection to message delivery:

### Step 1: Connection Setup

When a client connects, the [Handshake](handshake.md) negotiates:

**Protocol version**
: Client says "I speak Jig v1.2", server says "Cool, I speak v1.0-v1.3, let's use v1.2". Mismatched versions get rejected cleanly.

**Optional features**
: Things like E2EE, block execution, federation support. Client asks, server grants or denies. Example: An IRC-only server might disable block execution entirely (no Wasm runtime needed).

**Cryptographic suites**
: Agree on signature algorithms (Ed25519), encryption (age+x25519), and hashing (BLAKE3). If the client only supports weak crypto, fail closed—no connection.

**Capability grants**
: Server tells client what it's allowed to do (send messages, execute blocks, join channels). This is where reputation tiers kick in—`low_sec` users might have stricter rate limits than `verified` users.

Why negotiate up front? Because **failing closed** means rejecting incompatible connections immediately, not discovering mismatches 10 messages in. It's annoying for debugging but saves you from weird runtime failures.

### Step 2: Message Exchange

Once connected, clients send [Messages](message-format.md):

**Text messages**
: Human conversation. Plain text or Markdown.

**Block messages**
: Executable content. The host validates the block (signatures, capabilities) before running it.

**Control messages**
: Protocol coordination (channel joins, user presence, typing indicators).

All messages are signed by the sender's keypair. If E2EE is enabled, content is encrypted before signing (routing metadata stays plaintext so relays can... relay).

### Step 3: Block Execution (Optional)

If a message contains a block, here's what happens:

1. **Validation** ([Block Execution Model § Validation](block-execution.md#41-validation-phase)): Host checks signatures, verifies capabilities are allowed, validates WebAssembly module structure.

2. **Execution** ([Block Execution Model § Execution](block-execution.md#42-execution-phase)): Wasm module runs in an isolated sandbox with fuel metering. Think Docker, but way lighter—just syscall filtering and CPU limits.

3. **Receipt** ([Receipts](receipts.md)): Host emits a signed receipt with:
   - How much fuel was consumed (e.g., 421,337 units)
   - Which capabilities were used (e.g., `net.fetch` used 310k fuel, `crypto.sign` used 60k)
   - Execution outcome (`ok`, `soft_fail`, or `hard_fail`)
   - Success signals called "affordances" (e.g., `email.delivered`)

**Why receipts matter:** They enable dispute resolution. If a host says "your block used 5M fuel", you can replay it locally and prove it only used 500k. Deterministic execution means everyone gets the same answer.

### Step 4: Delivery

Messages (and receipts) propagate through the network:

**Within a server**
: Direct delivery to connected clients. Fast.

**Across federation** ([Federation](federation.md))
: Server-to-server protocol relays messages and receipts between domains. Each server maintains a trust score for federated peers based on receipt accuracy.

**Cross-transport**
: An IRC user sees a Slack-style thread as nested messages. An email user sees it as a reply chain. The protocol stays the same; the presentation adapts.

## Security Model: Zero Trust, Always

Jig's security model is simple: **trust no one, verify everything**.

Every operation requires cryptographic proof:

- Messages are signed by the sender
- Blocks are signed by the author
- Receipts are signed by the executing host
- Capabilities are explicitly granted, never assumed

**What "fail closed" means in practice:**

- Unknown protocol version? Reject the connection.
- Capability not granted? Deny the operation.
- Signature doesn't verify? Drop the message.
- Nondeterministic execution detected? Halt and investigate.

This is less flexible than "fail open" (allow by default), but it prevents entire classes of attacks. You can't forge messages, you can't execute code without permission, and you can't bill users for work you didn't do.

For the full threat model and security requirements that apply to _every_ chapter in this spec, see [Zero-Trust Model](zero-trust.md). Seriously, read it—it's foundational.

For specific mitigations and operational security, see [Security Considerations](security.md).

## What Makes This Different?

**From IRC:**

- ✅ Keep: Simplicity, channels, slash commands, scriptability
- ➕ Add: E2EE, signatures, federation, executable blocks, outcome-based pricing

**From Slack/Discord:**

- ✅ Keep: Rich threading, modern UX expectations
- ➕ Add: Portable identity, open protocol, self-hosting, no lock-in

**From Matrix:**

- ✅ Keep: Federation, E2EE
- ➕ Add: Simpler protocol (no DAG sync), capability-based security, executable blocks, potato-friendly (10k msg/sec on a Raspberry Pi)

**From Email:**

- ✅ Keep: Universal interoperability, asynchronous delivery
- ➕ Add: Threading, signatures by default, better spam prevention (reputation + useful work)

## Reading Order Suggestions

If you're implementing Jig, here's a recommended path:

1. **[Zero-Trust Model](zero-trust.md)** — Read this next. It defines security assumptions for everything else.
2. **[Crypto Primitives](crypto.md)** — Keys, signatures, encryption. The building blocks.
3. **[Message Format](message-format.md)** — Core message envelope and content types.
4. **[Handshake](handshake.md)** — How clients and servers establish connections.
5. **[Transports](transports.md)** — Pick your transport (WebSocket, IRC, SSH, Email).

If you want to support block execution: 6. **[Block Execution Model](block-execution.md)** — Manifests, Wasm validation, capability grants. 7. **[Receipts](receipts.md)** — Fuel metering, outcome-based pricing, replay audits.

If you're running a federated server: 8. **[Federation](federation.md)** — Server-to-server protocol, receipt exchange, reputation.

For everything else: 9. **[Security Considerations](security.md)** — Threat mitigations, operational security. 10. **[Appendix](appendix.md)** — Test vectors, affordances registry, analytics schemas.

## Normative Language

When you see **MUST**, **SHOULD**, or **MAY** in this spec, they follow [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119):

**MUST**
: Absolute requirement. Violate this and you're not Jig-compliant.

**SHOULD**
: Strong recommendation. If you skip it, document why (and expect questions).

**MAY**
: Optional. Implementers choose based on their use case.

All requirements operate under the [Zero-Trust Model](zero-trust.md). That chapter applies to every other chapter—its rules are always in effect.

---

**Next:** We recommend reading [Zero-Trust Model](zero-trust.md) to understand the security assumptions, then diving into [Message Format](message-format.md) to see the core protocol in action.
