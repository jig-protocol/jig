# Schemas and Canonical Test Vectors

This directory documents the TOML‑first configuration approach and how canonical JSON/CBOR test vectors are produced for the Jig specification.

## TOML‑First

- Use TOML for examples and configuration that appear in the spec.
- When an on‑the‑wire representation is needed, the canonical JSON/CBOR encodings are derived from the TOML examples.
- This keeps examples readable while enabling precise, testable encodings.

## Canonicalization

- JSON MUST use a deterministic canonical form (stable key ordering, normalized whitespace, deterministic number formatting) for signature verification.
- CBOR MUST use a canonical encoding profile appropriate for signature verification (deterministic key ordering, shortest encodings).
- Unless otherwise specified by a JEP, the same field set and ordering are used across formats.

## Test Vectors

- Each normative structure SHOULD include test vectors:
  - TOML source example
  - Canonical JSON
  - Canonical CBOR (hex)
  - Signature preimage and signature (if applicable)
- Vectors MUST include version fields and nonces/timestamps where required by the zero‑trust model.

## Tooling

- Vector generation MAY be automated in implementation repositories; this spec repository tracks the canonical text for vectors.
- Any generator MUST be reproducible and documented (inputs, versions), and produce byte‑for‑byte stable outputs from the same TOML input.

See `src/message-format.md` and `src/zero-trust.md` for normative requirements that affect canonicalization and vector construction.

Current schemas:

- `wire-envelope.json` – header fields (`v`, `suite`, `op`) of every v0.1 wire frame
- `message-envelope.json` – the `JigMessage` format described in `src/message-format.md` (not implemented in v0.1)
- `block-manifest.json` – block manifest schema (v0.1) for execution blocks
- `receipt-v0.2.json` – execution receipt schema (v0.2) with counters, timings, and outcome
