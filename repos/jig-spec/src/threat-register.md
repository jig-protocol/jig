# Threat Register

Server operators are **untrusted**. The protocol cannot require good operators, so every
protocol decision assumes an operator may run modified software, read and alter its own
storage, and lie on the wire. An operator cannot forge a user's signature.

Operators are not the only adversary. The families after OP cover abuse and Sybil attacks
(AB), the supply chain (SC), privacy (PV), malicious nameservers (NS), governance (GV) and
time (TM). The same rule holds for each: a party the protocol cannot vet is assumed hostile.

Each entry records the decision that binds implementations and its status in v0.2. The
decision is the obligation, whether or not anything implements it yet; the status says what
v0.2 does, and a prototype does not meet a decision because it exists. A *ruleset group* is
one concrete group of servers, clients and nameservers rated by the same ruleset; a
*security level* (high-sec, low-sec, null-sec) is a category of ruleset, and nothing is
pooled across one. Servers enforce; nameservers hold tribunals, compute net reputation and
police servers. D-numbers refer to the roadmap's
[decisions log](https://github.com/jig-protocol/jig/blob/main/docs/ROADMAP.md#decisions-log).
Modelling and justifications: for OP,
[`docs/security/operator-threat-model.md`](https://github.com/jig-protocol/jig/blob/main/docs/security/operator-threat-model.md);
for the other families, the
[trust, federation and identity whitepaper](https://github.com/jig-protocol/jig/blob/main/docs/whitepaper/trust-federation-identity.md).
Every JEP MUST name the entries it affects, and every release MUST state which entries it
mitigates.

**Status:** *Open*: no mitigation shipped. *Partial*: some of the decision is
implemented. *Accepted*: a known limit this version does not try to close. *By design*: a
property the decisions choose deliberately, with its cost stated.

## Server operators (OP)

| ID | Threat | Decision | v0.2 |
| --- | --- | --- | --- |
| OP-01 | Operator disables or strips the handshake | Every connection completes the handshake before any other frame. A client MUST close a connection with no handshake, or a malformed one ([JEP-0002]). | Partial: WSS refuses a frame before `hello`; the client closes when the welcome is missing or malformed. Version and suite refusals leave the socket open |
| OP-02 | False handshake answers (version, capabilities, suites, reputation) | Handshake answers are signed by the server key. A client MUST treat later behaviour that contradicts a signed answer as a handshake failure, and SHOULD keep the signed answer as evidence ([JEP-0002]). | Partial: the welcome is signed; a bad signature or a self-contradiction closes the client. The CLI pins the welcome's DID and suites per server: a welcome signed by another key fails closed, and one that no longer advertises a pinned suite is refused. Later frames are not yet checked against it |
| OP-03 | Suite downgrade: advertising only weak suites, or `none` | Unknown or unimplemented suites are refused, never treated as `none`. A channel's suite is fixed at creation; a client MUST NOT post under any other ([Encryption], [JEP-0001]). | Partial: the suite is fixed per channel and enforced on every post; frames claiming `mls` are refused. The CLI takes a channel's suite from the owner-signed creation block the listing names, not from the listing, and pins that block on first sight; a client holding the group treats the channel as `mls` regardless. A server can still answer a device's very first look at a channel with a channel it made up itself |
| OP-04 | Metadata harvesting: who talks to whom, when, how much | The server sees routing metadata. v0.x makes no metadata-privacy claim. | Accepted |
| OP-05 | Content disclosure: operator reads messages | Content confidentiality comes from end-to-end encryption, selected per channel at creation; MLS is the registered suite ([Encryption]). | Partial: channels created `mls` are end-to-end encrypted and the server stores ciphertext; channels created without a suite are plaintext, and encrypted channels do not federate |
| OP-06 | Dropping, reordering, delaying, replaying or selectively censoring blocks | A block is accepted once per CID, and read proofs carry a replay guard. Detecting omission and reordering is open. | Partial: replay only |
| OP-07 | Forged or withheld receipts; lying about fuel or execution | A receipt is a signed claim by the server that produced it, not proof. Clients compare `render_hash` across servers. | Partial: divergence is a warning, not a refusal |
| OP-08 | Key substitution at first contact or nameserver resolution | A DID is its own key, so substitution happens where a name maps to a DID. That mapping is a claim by whoever resolved it, server or nameserver. Clients SHOULD pin a name's DID and the server's DID on first sight and surface any change. | Partial: the CLI pins each server's DID on its first signed welcome, or on the first TLS probe, and refuses another. Over TLS (the default) every REST and WebSocket connection accepts only the certificate the pinned DID vouches for, or a CA-issued one. A name's DID is not yet pinned on the client |
| OP-09 | Federation abuse: relaying junk, impersonating a peer | A receiving server ingests every relayed block as it would a local submission: author signature, version and suite gates, admission, the write gate, effects, and its own execution and receipt. A server accepts blocks only over a connection it dialed to a listed peer whose welcome is signed by that peer's pinned DID, and only listed peers may subscribe to its federation stream. | Partial: relayed blocks run the full write gate, and peers are pinned and listed. Encrypted and restricted channels still do not federate until the federation contract (D12) says how one group spans two servers; relayed blocks for local channels that do not federate are refused |
| OP-10 | Discovery and reputation gaming: Sybil servers, fake activity | Reputation is not a security input until [JEP-0003] defines it; handshake reputation fields are informational. | Open |

## Abuse and Sybil (AB)

| ID | Threat | Decision | v0.2 |
| --- | --- | --- | --- |
| AB-01 | Challenge replay: reusing an issued or solved challenge | A challenge is single-use and short-lived; the issuer MUST consume it on first use and refuse it after expiry. A proof answering a challenge MUST cover the action, the alias and every DID involved, not the bare challenge. | Partial: nameserver challenges are consumed once and expire after 60 s, but proofs are not bound to an action or DID; read proofs carry a nonce and an acceptance window. Admission proof-of-work uses no challenge: the work is bound to the server's DID and the new DID, so it cannot be replayed against another server or for another identity |
| AB-02 | Botnet proof-of-work: distributed solving makes PoW cheap for an attacker with many machines | A server MUST enforce PoW on the clients it serves, as a rate cost its ruleset sets, and a nameserver MUST require it on its own binding endpoints (D23). PoW is not, alone, a Sybil defence (AB-05) and MUST NOT be the only admission gate. Difficulty is a ruleset parameter and MAY scale with reputation. | Partial: servers rate-limit by default (`[auth.rate_limit]`): a token bucket per verified DID covers REST, WebSocket, federation and bridge writes, and one per remote address covers every v0.0.2 HTTP request and WebSocket frame (not `/.well-known/jig`, `/healthz` or `/metrics`). Admission proof-of-work for unknown DIDs exists but is off by default (`unknown_dids = "proof-of-work"`, D26), and blocks relayed by a peer or submitted by a bridge are not asked for it. The nameserver's v0.0.2 binding endpoints (`/v1/register`, `/v1/rotate`, `/v1/renew`) have no proof-of-work and no rate limit; only its legacy routes are rate-limited, and its experimental PoW prototype is unused by the alias flow |
| AB-03 | Relay and bridge quota abuse: amplifying traffic from unidentified sources | A bridge or relay is an ingress point and MUST apply its own limits to what it admits. A relayed block MUST stay attributable to its author and SHOULD be attributable to the relaying server's DID. | Partial: authors are attributable by signature; relayed blocks are recorded against the peer's URL; the per-DID rate limit applies to every block's author whichever ingress carried it, and the per-address limit to v0.0.2 HTTP requests and WebSocket frames, not to blocks a peer relays over a connection this server dialed. No limit is kept per peer or per bridge |
| AB-04 | Over-broad capability requests by blocks | A block receives only the capabilities its manifest names, attenuated at each nesting level. A host MUST refuse a capability the manifest does not declare. There is no ambient authority. | Partial: the server executes only its own canonical `text-render` module, so no third-party block holds a capability; the capability DSL is validated in `jig-core` |
| AB-05 | Identity farming: a per-identity cost grows only linearly with the number of identities | Sybil resistance MUST hold against identity farming and the other known attack classes, not only raise their price linearly. A fresh DID starts unknown; standing is earned under the ruleset, over time the ruleset group measures; many cheap identities MUST NOT add up to the standing of one costly one (D23). | Open: no mechanism; the nameserver's experimental PoW and reputation prototype prices identities linearly and is unused |
| AB-06 | Unprovable abuse in encrypted channels, or abuse policed through a backdoor | A participant in an incident MUST be able to prove abuse in an encrypted channel to a tribunal, by delegating its key or view or by another effective proof, with no backdoor, escrow or client-side scanning. Only a participant can produce such a report (D22). | Open: the DID-key content signature that makes proof possible exists; no report format, delegation or tribunal intake exists |

## Supply chain (SC)

| ID | Threat | Decision | v0.2 |
| --- | --- | --- | --- |
| SC-01 | Malicious connector or bridge blocks | A connector that runs as a block is addressed by CID, MUST be signed by its author, and runs only with its manifest's capabilities. A host SHOULD pin connectors by CID. | Accepted: bridges are compiled into the server binary and share its trust; none run as blocks |
| SC-02 | SDK or dependency substitution | The reference implementation depends only on this workspace and public crates. Release artifacts MUST be signed and checksummed, and installers MUST verify both. | Partial: `cargo deny` refuses unknown registries and git sources; `install.sh` verifies the signed `SHA256SUMS` when `ssh-keygen` is present and otherwise, by default, the checksum only; no release is published and builds are not reproducible |
| SC-03 | Wasm runtime zero-day | The sandbox is one layer of several. Execution MUST be fuel-metered, memory-bounded and capability-gated, and a host executes only modules it chose. A server MUST NOT execute encrypted content. | Partial: the server executes only its canonical module; encrypted blocks get a `sealed` receipt; advisories are checked daily |

## Privacy (PV)

| ID | Threat | Decision | v0.2 |
| --- | --- | --- | --- |
| PV-01 | Federation timing correlation: linking identities across servers by when blocks appear on each | v0.x makes no unlinkability claim against an observer of several servers (see OP-04). Identities a holder keeps apart are unlinkable only as distinct DIDs. | Accepted |
| PV-02 | Receipt linkage: receipts revealing who executed what, where and when | A receipt carries only the block's CID, the server's identity, time and execution facts. A receipt for encrypted content MUST NOT carry a render hash or any content-derived value. | Partial: `sealed` receipts carry no `render_hash`; receipts still link a CID to every server that handled it |
| PV-03 | Identity cross-linking by the protocol or the client | No protocol message links two DIDs, and none links an `--anon` session key to any DID (D20). A session SHOULD be bound to one DID. Clients SHOULD keep identities used in different ruleset groups in separate key stores and never use two of them from one session. | Partial: no message links DIDs; there is no `--anon` mode; a socket rebinds its read identity per subscription; the CLI keeps every identity under `~/.jig/` |
| PV-04 | Non-deniability: signed content is attributable to its author by anyone it is disclosed to | Every block is signed by its author's DID, and on an encrypted channel the MLS content signature uses the same key. This is deliberate: it makes abuse provable (AB-06, D22). jig makes no deniability claim for content signed by a DID. | By design |

## Malicious nameservers (NS)

| ID | Threat | Decision | v0.2 |
| --- | --- | --- | --- |
| NS-01 | False or poisoned resolution: a nameserver, cache or network attacker maps an alias to the wrong DID | An alias resolution is an attestation signed by the nameserver. A resolver MUST accept it only from a nameserver authoritative for the alias's suffix, MUST verify its signature against that nameserver's DID, and MUST NOT cache it past its validity. Clients SHOULD pin (OP-08). | Partial: attestations are signed and expire; the server's resolver does not verify them, does not bind suffixes to nameservers, and takes the first nameserver that answers |
| NS-02 | Equivocation: a nameserver gives different answers to different askers | Two validly signed attestations binding one alias to different DIDs in overlapping validity windows are proof of misbehaviour. A ruleset group's nameservers MUST append registrations, rotations, net reputation changes, penalties and verdicts to a transparency log every member can audit, and each server MUST keep its own log of what it enforced and reported (D23). Resolvers SHOULD retain the attestations they act on. | Open: nothing retains attestations; servers keep no log; the nameserver's experimental log store receives no entries |
| NS-03 | Cross-nameserver collusion on clock or state (account age, registrations, reputation) | No single nameserver, anchor included, decides a claim for its ruleset group. A ruleset group SHOULD require agreement among nameservers run by independent operators. | Open: nameservers do not coordinate |

## Governance (GV)

| ID | Threat | Decision | v0.2 |
| --- | --- | --- | --- |
| GV-01 | Tribunal capture: one party controls a ruleset group's verdicts | Every ruleset group that shares penalties MUST have a tribunal process, held by its nameservers (D23). Tribunals are per ruleset group. No group is bound by another group's verdict; any group MAY ignore it. A verdict SHOULD be a signed block that cites its evidence. | Open: no tribunal protocol; the nameserver's experimental case records are a prototype nothing consumes |
| GV-02 | Sybil panels or voters | Eligibility to judge or vote MUST NOT rest on the number of identities a party holds. | Open |
| GV-03 | Penalty propagation without consent or evidence | An entity MUST NOT lose reputation under a ruleset it has not acknowledged. Reputation is one number per ruleset, and a ruleset group's members are rated by the same rules (D21). Servers report reputation changes to their nameservers, which compute and enforce the net change (D23). A penalty MUST NOT propagate beyond the ruleset group that adopted the ruleset, never across a security level, except by a translation both groups agreed to, and SHOULD cite a verdict or evidence. | Open: admission bans and floors are local operator configuration; servers report nothing to nameservers |

## Time (TM)

| ID | Threat | Decision | v0.2 |
| --- | --- | --- | --- |
| TM-01 | Clock-skewed farms against time-based limits (account age, windows, decay) | Time-based limits MUST use the verifier's clock, never the claimant's. Age SHOULD be measured from the first signed observation by a party other than the subject. | Partial: replay windows use the server's clock; no time-based limits exist; the server's clock adopts block timestamps without a skew bound (`naively_unbounded_clock_skew`) |
| TM-02 | Self-asserted timestamps used to fake history or ordering | A signer's own timestamp is a claim. Ordering and age SHOULD come from receipts or countersignatures by other parties. | Open: a block's `hlc_ts` is set by its author and orders history; the receipt's `produced_at` is the only server-signed time |

[Encryption]: encryption.md
[JEP-0001]: https://github.com/jig-protocol/jig/blob/main/repos/jig-spec/jep/jep-0001-encryption-suites.md
[JEP-0002]: https://github.com/jig-protocol/jig/blob/main/repos/jig-spec/jep/jep-0002-handshake.md
[JEP-0003]: https://github.com/jig-protocol/jig/blob/main/repos/jig-spec/jep/jep-0003-server-discovery.md
