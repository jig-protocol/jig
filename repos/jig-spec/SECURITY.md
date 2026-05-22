# Security Policy and Vulnerability Disclosure

We take the security of the Jig protocol and its implementations seriously. This repository contains the formal specification. Please report security issues privately so we can coordinate a responsible disclosure.

## Reporting a Vulnerability

- Email: security@jig.onl
- Please include a clear description, impact assessment, and any proof-of-concept you can share safely.
- Do not open a public issue for security vulnerabilities.

We will aim to acknowledge receipt within 72 hours and provide a triage assessment within 7 days. Coordinated disclosure timelines may vary depending on severity and mitigations.

## Scope

- This repository: protocol specification defects that could lead to security issues (e.g., ambiguous requirements, unsafe defaults, downgrade risks).
- Implementations (e.g., `jig-core`, `jig-server`): please report to their respective repositories following their policies. If unsure, contact us at the email above and we will route appropriately.

## Zero‑Trust Assumptions

The Jig specification is written under a strict zero-trust model: networks are hostile, peers are untrusted without continuous verification, and metadata is a sensitive target. All normative requirements MUST be interpreted under these assumptions. See `src/zero-trust.md` for details.

## Safe Harbor for Security Research

We support good-faith security research and coordinated disclosure. If you follow this policy and avoid privacy violations, service disruption, and data exfiltration, we will consider your research to be in scope for safe harbor.

## Encryption and Sensitive Material

If you prefer to encrypt your report, mention this in your initial email and we will provide a public key and instructions.

Thank you for helping keep Jig users safe.
