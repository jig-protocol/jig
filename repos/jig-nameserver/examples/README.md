# Jig Nameserver Examples

This directory contains illustrative configuration and payload snippets to help new contributors understand how reputation rulesets, tribunal flows, and observations fit together. Files here are for learning only and are *excluded* from automated formatting and tests.

Contents:
- `config/profile_potato.toml` – minimal single-node deployment with a high-sec ruleset.
- `config/profile_federated.toml` – multi-ruleset config showing cross-translation contracts.
- `requests/reputation_observation.json` – sample `POST /v1/reputation/observe` payloads.
- `requests/tribunal_case.json` – sample tribunal case creation + decision bodies.
