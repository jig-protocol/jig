+++
jep = 0003
title = "Nameserver Server Discovery"
status = "Draft"
type = "Standards Track"
category = "Federation"
authors = ["DJ <dev@jig.onl>"]
created = "2026-10-05"
requires = ["0002"]
replaces = []
superseded_by = []
discussions_to = "https://github.com/jig-protocol/jig/issues"
+++

# Abstract

Placeholder for the discovery design project (D15): how clients and servers find servers
and channels through nameservers, inside the protocol, without central control. This stub
names the project and its subtopics and fixes one v0.1 commitment. It specifies nothing
else.

# Motivation

A federated network nobody can find does not grow. Discovery must run inside the protocol,
through nameservers, so decentralised federation stays in control. PoW and reputation are
part of the design, not additions to it.

# Specification

v0.1 commitment: the fields `/.well-known/jig` serves today keep their meaning, so the
document can grow into the discovery record. New fields may be added; existing ones are
not repurposed.

Subtopics the project must cover:

| Subtopic | Question |
| --- | --- |
| Discovery | How does a client find servers and channels it was never told about? |
| Exposure | What does a server or channel make visible, and to whom? |
| Activation | How does a discovered server or channel become joinable or trusted? |
| Search | How are queries answered across nameservers? |
| Reputation and PoW | How are Sybils and spam resisted, and how does reputation feed the handshake's `reputation` field (JEP-0002)? |
| Governance | Who runs nameservers, and how are bad actors delisted without central control? |

# Security Considerations (Zero-Trust)

Threat register OP-10 (Sybil servers, fake activity) and OP-08 (name-to-DID
substitution). Until this JEP defines reputation, reputation is not a security input.

# Backwards Compatibility

v0.x makes no compatibility guarantee, beyond the `/.well-known/jig` commitment above.

# Copyright

This document is licensed under CC-BY-4.0.
