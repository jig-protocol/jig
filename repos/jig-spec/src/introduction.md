# Introduction

**Audience:** This chapter is for **everyone**—whether you're an end user curious about Jig, a developer building on the protocol, a server operator setting up infrastructure, or a protocol implementer. It provides a high-level overview before diving into technical details.

---

Welcome to the Jig Protocol spec!

> **Status (v0.1).** Messages are signed, **not encrypted**: end-to-end encryption (MLS) is
> specified in [Encryption](encryption.md) and ships in v0.2. Chapters describing unbuilt
> features say so in a banner. v0.x makes **no compatibility guarantee**; see
> [Versioning](versioning.md). Server operators are treated as untrusted; see the
> [Threat Register](threat-register.md).

Jig is a modern messaging protocol that brings IRC's simplicity into the 2025 era—with end-to-end encryption, executable blocks, and federation built in from day one.

**Why another messaging protocol?** Good question. We love IRC's minimalism and scriptability, but it lacks modern privacy guarantees. We love Slack's UX, but it's a walled garden. Jig bridges that gap: it's IRC-compatible where it matters, but extends the model with cryptographic security, capability-based sandboxing, and cross-server federation.

## What Makes Jig Different?

### It's IRC-Friendly

If you've used IRC, you'll feel at home. Channels, nicknames, and slash commands work the way you expect. But under the hood, everything is cryptographically signed and can be end-to-end encrypted by default.

### It's Executable

Messages aren't just text—they can contain **blocks** (WebAssembly modules) that run in isolated sandboxes. Think of it like embedding a secure, metered lambda function in a message. Hosts can execute these blocks deterministically and emit **receipts** that prove what happened and how much fuel (CPU) was consumed. This enables outcome-based pricing, federated verification, and portable computation across organizational boundaries.

### It's Zero-Trust

You sure _seem_ friendly, but... we're not going to take your word for it. We assume networks are hostile and metadata leaks. Every operation requires cryptographic proof. Capabilities are explicitly granted, never assumed. Encryption is on by default. Fail closed, not open.

### It's Designed to Scale

Jig starts simple (SQLite on a Raspberry Pi) but scales to hyperscale infrastructure (distributed ClickHouse, multi-region federation). Same protocol, different deployment profiles.

## Design Principles

Here's what guides every decision in this spec:

**Zero-trust by default**
: Networks are hostile. Metadata leaks are attacks. Minimize what you expose, and when in doubt, fail closed.

**Zero-dependency core**
: The base protocol has no external dependencies beyond standard crypto primitives. Extensions are explicit and optional.

**10k messages/second on a garden-variety potato**
: If you have a functioning Raspberry Pi and an internet connection, you can have a Jig server. Fancier servers need fancier gear, but you don't have to pay to play.

**curl-to-hello-world in less than 60 seconds**
: For that zero-dependency 'potato' build, you should be able to download, build, cold-start, and send your first message in under a minute. Adding extensions adds time, but the core should be tiny.

**IRC muscle memory respected**
: If you know IRC, you know Jig's basics. Progressive enhancement means new features don't break old workflows.

**End-to-end encryption by default**
: Privacy isn't opt-in. E2EE should be the default experience, with plaintext as the exception (when needed for compatibility).

**Federation-ready from day one**
: Server-to-server communication is a first-class concern, not an afterthought. Receipts travel across federation boundaries to enable verification and useful-work attribution.

## About This Spec

This document is the **authoritative, implementation-agnostic** specification for the Jig protocol. When code and spec disagree, the spec wins (and we update the code).

### What's Inside

- **[Protocol Overview](protocol-overview.md)** – High-level tour of identities, messages, blocks, and transports
- **[Handshake](handshake.md)** – How connections negotiate versions, features, and crypto suites
- **[Message Format](message-format.md)** – The envelope structure and content types
- **[Block Execution Model](block-execution.md)** – How WebAssembly blocks run in sandboxes with fuel metering
- **[Receipts](receipts.md)** – Deterministic proof of execution with outcome-based pricing
- **[Versioning](versioning.md)** – Version gates and the v0.x compatibility policy
- **[Crypto Primitives](crypto.md)** – Signatures, hashing, and key management
- **[Encryption](encryption.md)** – Pluggable suites, MLS by default, DMs as locked channels
- **[Federation](federation.md)** – Server-to-server protocol and receipt exchange
- **[Transports](transports.md)** – IRC, WebSocket, Email, SSH adapters
- **[Zero-Trust Model](zero-trust.md)** – Threat model and security requirements
- **[Security Considerations](security.md)** – Mitigations, best practices, and known risks
- **[Threat Register](threat-register.md)** – Decisions against malicious server operators
- **[Appendix](appendix.md)** – Test vectors, affordances registry, analytics schemas

### Normative Language

When you see **MUST**, **SHOULD**, or **MAY** in this spec, they follow [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) semantics:

- **MUST** = absolute requirement (violate this and you're not compliant)
- **SHOULD** = strong recommendation (exceptions need good reasons and documentation)
- **MAY** = optional feature (implementers can choose)

All requirements operate under the **zero-trust model** defined in [zero-trust.md](zero-trust.md). That chapter applies to every other chapter—read it early.

### Implementation Notes

This spec occasionally references implementations like `jig-core` (Rust library), `jig-server` (relay server), and `jig-cli` (command-line client) for clarity. These are **non-normative examples**—the spec is the source of truth, not the code.

If you're implementing Jig, start with the [Protocol Overview](protocol-overview.md) to get oriented, then dive into the chapters that matter for your use case.

## Contributing

Found an issue? Have a proposal for a new feature? Check out the [JEP (Jig Enhancement Proposal) process](appendix.md#jep-process) for how to contribute changes to this spec.

For security issues, see our [SECURITY.md](../SECURITY.md) for responsible disclosure guidelines.

---

**Let's dive in.** → Start with the [Protocol Overview](protocol-overview.md)
