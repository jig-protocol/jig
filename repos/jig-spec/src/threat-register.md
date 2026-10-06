# Threat Register: Server Operators

Server operators are **untrusted**. The protocol cannot require good operators, so every
protocol decision assumes an operator may run modified software, read and alter its own
storage, and lie on the wire. An operator cannot forge a user's signature.

Each entry records the decision that binds implementations and its status in v0.1.
Modelling and justifications:
[`docs/security/operator-threat-model.md`](https://github.com/jig-protocol/jig/blob/main/docs/security/operator-threat-model.md).
Every JEP MUST name the entries it affects, and every release MUST state which entries it
mitigates.

**Status:** *Open*: no mitigation shipped. *Partial*: some of the decision is
implemented. *Accepted*: a known limit this version does not try to close.

| ID | Threat | Decision | v0.1 |
| --- | --- | --- | --- |
| OP-01 | Operator disables or strips the handshake | Every connection completes the handshake before any other frame. A client MUST close a connection with no handshake, or a malformed one ([JEP-0002]). | Open |
| OP-02 | False handshake answers (version, capabilities, suites, reputation) | Handshake answers are signed by the server key. A client MUST treat later behaviour that contradicts a signed answer as a handshake failure, and SHOULD keep the signed answer as evidence ([JEP-0002]). | Open |
| OP-03 | Suite downgrade: advertising only weak suites, or `none` | Unknown or unimplemented suites are refused, never treated as `none`. A channel's suite is fixed at creation; a client MUST NOT post under any other ([Encryption], [JEP-0001]). | Partial: the field and refusals ship; `none` is the only suite |
| OP-04 | Metadata harvesting: who talks to whom, when, how much | The server sees routing metadata. v0.x makes no metadata-privacy claim. | Accepted |
| OP-05 | Content disclosure: operator reads messages | Content confidentiality comes from end-to-end encryption, MLS by default ([Encryption]). | Accepted: v0.1 is unencrypted |
| OP-06 | Dropping, reordering, delaying, replaying or selectively censoring blocks | A block is accepted once per CID, and read proofs carry a replay guard. Detecting omission and reordering is open. | Partial: replay only |
| OP-07 | Forged or withheld receipts; lying about fuel or execution | A receipt is a signed claim by the server that produced it, not proof. Clients compare `render_hash` across servers. | Partial: divergence is a warning, not a refusal |
| OP-08 | Key substitution at first contact or nameserver resolution | A DID is its own key, so substitution happens where a name maps to a DID. That mapping is a claim by whoever resolved it, server or nameserver. Clients SHOULD pin a name's DID and the server's DID on first sight and surface any change. | Open: the only pin is server-side, which the operator controls |
| OP-09 | Federation abuse: relaying junk, impersonating a peer | A receiving server re-verifies every relayed block's author signature, and runs the same version and suite gates, before persisting it. | Partial: relayed blocks skip the write gate |
| OP-10 | Discovery and reputation gaming: Sybil servers, fake activity | Reputation is not a security input until [JEP-0003] defines it; handshake reputation fields are informational. | Open |

[Encryption]: encryption.md
[JEP-0001]: https://github.com/jig-protocol/jig/blob/main/repos/jig-spec/jep/jep-0001-encryption-suites.md
[JEP-0002]: https://github.com/jig-protocol/jig/blob/main/repos/jig-spec/jep/jep-0002-handshake.md
[JEP-0003]: https://github.com/jig-protocol/jig/blob/main/repos/jig-spec/jep/jep-0003-server-discovery.md
