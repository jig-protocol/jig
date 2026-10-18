# Security policy

jig is pre-alpha. **Restricted channels, DMs and open channels created with `--encrypted`
are end-to-end encrypted.** Each is one MLS group (RFC 9420), and the server holds no group
secret. Open channels are plaintext to their server's operator unless created encrypted.
A restricted channel created plaintext before restricted channels became always-MLS
([D25](docs/ROADMAP.md)) is frozen: its history stays readable to the operator, and it takes
no new content. Encrypted channels do not federate yet, and the email bridge refuses inbound
mail until it can join a thread's MLS group. Do not use jig for anything confidential yet: it has not been
audited.

## Reporting a vulnerability

Report it in private. Either channel reaches the same place:

- [GitHub private vulnerability reporting](https://github.com/jig-protocol/jig/security/advisories/new)
- Email **security@jig.onl**

Please do not open a public issue, pull request or discussion for a vulnerability.

Include what you found, how to reproduce it, the version or commit, and the impact as you
understand it. If you want to encrypt the report, say so in a first short email and we will
send a key.

For anything that is not a vulnerability, write to **dev@jig.onl** or open an issue.

## What to expect

| Step | Target |
| --- | --- |
| Acknowledge your report | 1 day |
| Triage: confirm, assess severity, agree a plan with you | 7 days |
| Release a fix | 28 days from your report |

"Release a fix" means a tagged release containing the fix, not a merged patch.

We follow **90-day coordinated disclosure**. We publish an advisory when the fix is
released, or 90 days after your report, whichever comes first. We may agree a different
date with you, for example if a fix needs a protocol change or the issue is already being
exploited. We credit reporters unless you ask us not to.

The project owner, DJ ([@the-jig-is-up](https://github.com/the-jig-is-up)), handles
reports.

## Supported versions

Only the latest v0.x release and `main` receive fixes. v0.x makes **no compatibility
guarantee**: a fix may change the wire format, the receipt format or the configuration
without a migration path.

## Scope

In scope:

- Every crate in this repository: `jig-core`, `jig-pipeline`, `jig-server`, `jig-client`,
  `jig-cli`, `jig-config`, `jig-nameserver`, `jig-runtime`, the bridges and the sample
  blocks.
- The specification in [`repos/jig-spec/`](repos/jig-spec/): ambiguous requirements,
  unsafe defaults and downgrade paths.
- **Malicious server operators.** jig treats operators as untrusted. A way for an operator
  (or a federated peer server) to attack users or other servers *beyond what the
  [threat register](repos/jig-spec/src/threat-register.md) already lists as open* is a
  vulnerability. So is a way to defeat a mitigation the register marks as implemented.
- Wasm sandbox escapes and bypasses of fuel, memory or time limits.
- Bypasses of signature verification, read proofs, channel membership or admission policy.

Known and documented, so not reportable on their own:

- Operators can read the content of channels that are not encrypted, and see who talks to
  whom and when in every channel, encrypted or not.
- The default admission policy admits any key. Admission proof-of-work exists but is off by
  default ([D26](docs/ROADMAP.md)). Rate limits are on by default.
- The nameserver serves plaintext HTTP. A server's default TLS certificate is self-signed and
  trusted through the DID the client pins, not through a certificate authority.
- The open entries in the [threat register](repos/jig-spec/src/threat-register.md).

If you find a cheaper or wider way to exploit one of these, please do report it.

Out of scope:

- The configuration of a particular deployment. Report that to its operator. A protocol or
  implementation weakness that lets *any* operator attack their users stays in scope.
- Volume denial of service against servers you do not run, and social engineering.

## Safe harbour

We will not pursue or support legal action against good-faith research that follows this
policy: test against your own deployments, avoid other people's data, and do not degrade
services you do not run. If in doubt, ask security@jig.onl first.
