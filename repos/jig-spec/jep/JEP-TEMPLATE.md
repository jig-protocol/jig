+++
jep = 0000
title = "Short Descriptive Title"
status = "Draft" # Draft | Review | Accepted | Final | Deprecated | Superseded
type = "Standards Track" # Standards Track | Informational | Process
category = "Protocol/Core" # Core | Transport | Federation | Security | Meta
authors = ["Your Name <you@example.com>"]
created = "2025-09-05"
requires = []
replaces = []
superseded_by = []
discussions_to = "https://github.com/jig-protocol/jig-spec/issues/XXXX"
+++

# Abstract

A short (~200 words) description of the proposal and its intent.

# Motivation

- Problem statement and context
- Goals and non-goals

# Specification

- Normative definitions using RFC 2119 MUST/SHOULD/MAY
- Wire formats, data structures (prefer TOML for examples)
- State machines, error handling, edge cases

# Security Considerations (Zero-Trust)

- Assume adversarial network, untrusted servers, malicious clients
- Define integrity, confidentiality, replay, and metadata-minimization requirements
- Key compromise recovery, rotation, and downgrade-prevention

# Backwards Compatibility

- Versioning, negotiation, and migration plan

# Reference Implementation (if applicable)

- Pointers to prototype code, test harnesses

# Test Vectors

- Canonical inputs/outputs for interoperable verification

# LLM Influence (if applicable)

- Pointers to LLM-generated code, validation, and analysis

# Rejected Alternatives

- Options considered and rationale for rejection

# Copyright

This document is licensed under CC-BY-4.0.
