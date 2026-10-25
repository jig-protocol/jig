# Identity and Reputation

> **Status.** This chapter states what the system must do. Where the reference code is
> behind, a **Status** line says so; the code's current behaviour is not the intent.
>
> - **Implemented:** `did:jig` identities, nameserver-attested aliases, TOFU resolution in
>   servers, verified name resolution through per-suffix delegations in servers (#200) and
>   clients (#201), the default `@jig` delegation (#214, #218), client name pins in `jig dm`,
>   `jig channel add` and `jig trust verify-name` (#213, #215), operator-seeded
>   per-ruleset scores for server admission, and JEP-0008 proof-of-work with a per-suffix
>   registration pool on the nameserver's binding endpoints (see
>   [Nameserver mechanics](#nameserver-mechanics)).
> - **Removed prototype:** the reference nameserver's earlier surface (proof-of-work
>   challenges with penalties, `/v1/claim`, `/v1/alias`, reputation observations, tribunal
>   case records, the transparency log, useful work and nameserver federation) is no longer
>   served. Its routes were deleted in #154. Status lines below that described it now say
>   so.
> - **Being redesigned** (draft JEPs): lane R's [framing doc](https://github.com/jig-protocol/jig/blob/main/docs/superpowers/specs/2026-10-18-reputation-pow-tribunals-framing.md),
>   [JEP-0008](https://github.com/jig-protocol/jig/blob/main/repos/jig-spec/jep/jep-0008-proof-of-work.md) proof-of-work and capacity pools,
>   [JEP-0009](https://github.com/jig-protocol/jig/blob/main/repos/jig-spec/jep/jep-0009-rulesets-reputation-logs.md) rulesets, reputation and transparency logs, and
>   [JEP-0010](https://github.com/jig-protocol/jig/blob/main/repos/jig-spec/jep/jep-0010-reports-tribunals-lists.md) abuse reports, tribunals and server lists.
> - **Required, not yet implemented or partial:** proof-of-work enforced by servers as a
>   ruleset-set cost (only one-time admission proof-of-work exists, off by default), server
>   capacity pools, reputation reports from servers to nameservers and
>   net reputation computed by nameservers, reputation shared within a ruleset group,
>   cross-registration within a high-sec ruleset group, tribunals held by nameservers,
>   transparency logs at servers and nameservers, abuse reporting from encrypted channels,
>   and Sybil resistance beyond linear cost.
> - **Proposed:** anchor nameservers, soul validation and useful-work rewards.
>
> Decisions D19 to D24 in the roadmap's
> [decisions log](https://github.com/jig-protocol/jig/blob/main/docs/ROADMAP.md#decisions-log)
> settle the model this chapter specifies.
>
> Reputation is not a protocol gate until
> [JEP-0003](https://github.com/jig-protocol/jig/blob/main/repos/jig-spec/jep/jep-0003-server-discovery.md)
> defines it ([OP-10](threat-register.md)). Rationale and cost model:
> [`docs/security/nameserver-abuse-economics.md`](https://github.com/jig-protocol/jig/blob/main/docs/security/nameserver-abuse-economics.md).

**Audience:** protocol implementers, nameserver and server operators. End users need only
[Identity](#identity) and
[Security levels and ruleset groups](#security-levels-and-ruleset-groups-server-policy).

## Overview

- An **identity** is a `did:jig`: a self-certifying Ed25519 key the user mints locally.
- An **alias** (`alice@example.com`) is a nameserver's signed claim that a name maps to a
  DID. It is never the sender.
- **Reputation** is one number per subject **per ruleset**. A user, a server and a
  nameserver can each have one. Behaviour raises or lowers it. It has no tiers.
- A **ruleset** is a named, versioned scoring policy.
- A **ruleset group** is a concrete set of servers, clients and nameservers that have all
  agreed to be rated by the same ruleset, whose rules produce the same reputation maths for
  every member, and to share reputation, penalties and tribunal outcomes under it (D21).
- A **security level** (high-sec, low-sec or null-sec) is a category that describes a
  server's or a ruleset group's policy. It is not a group, and nothing is shared across
  it: two high-sec ruleset groups share nothing unless they agree to.

A security level is never a property of a user.

## Servers and nameservers

Servers are the execution and enforcement boundary. A server looks clients up by DID and
deals with them under policies it presets and the client agrees to. Nameservers sit behind
servers: they judge and net out, and they hold servers to account (D23).

| Party | Obligations |
| --- | --- |
| **Server** | Enforces [proof-of-work](#proof-of-work) on the clients it serves. Decides about a client by reputation, using a ruleset recorded in its nameserver network, a ruleset it holds privately, or none. Reports reputation changes for the clients it works with to the nameservers it belongs to, as part of its data contract with them. Keeps its own [transparency log](#transparency-log). |
| **Nameserver** | Holds the ruleset group's [tribunals](#tribunals). Computes and enforces *net* reputation changes from every member server's reports, not one server's marginal observation. Enforces servers' good behaviour through servers' own scores and penalties. Keeps a transparency log of bindings, net reputation changes, penalties and decisions. |

A server with no nameserver sets its own policy for all of this.

**Status:** partial. A server can require proof-of-work of a DID it has not seen
(`[auth.admission] unknown_dids = "proof-of-work"`), but it is off by default (D26) and is
not set by a ruleset. Servers report nothing to nameservers and keep no transparency log;
the reference nameserver computes a per-nameserver aggregate from its own observations (see
[Reputation is a number](#reputation-is-a-number)).

## Identity

### DIDs

A `did:jig` is derived from an Ed25519 public key and proves itself: whoever signs with the
key is the DID. No authority issues or revokes one.

- A block's sender MUST be a DID. Aliases are display and lookup aids only.
- A sender has one canonical DID per identity. A user MAY hold different identities, for
  example in different ruleset groups.
- A new keypair is a new identity with no reputation. The protocol has no mechanism that
  links two DIDs, except [alias rotation](#aliases), which both keys must sign.
  **Status:** the [JEP-0012](https://github.com/jig-protocol/jig/blob/main/repos/jig-spec/jep/jep-0012-key-links.md)
  draft specifies a key link, signed by both keys, that moves one DID's standing to another
  for one audience (a channel, an alias at one nameserver, a contact, or the public), and
  `jig_core::key_link` implements it as a library (#235). No record carries a link yet, and
  `/v1/rotate` still takes signatures over the challenge.
- Losing the private key loses the identity. Clients SHOULD make key backup explicit.

### Aliases

A name is `alias@suffix`. The alias is 1 to 24 characters from `[A-Za-z0-9_-]`, compared
case-insensitively; the suffix is a domain name. A name says nothing about which server its
holder uses. [JEP-0004](https://github.com/jig-protocol/jig/blob/main/repos/jig-spec/jep/jep-0004-verified-naming.md) specifies every object and check
in this section exactly; this section says what each one is for.

**Signed bytes.** Every naming object is a COSE_Sign1 over deterministic CBOR whose payload
names the object in a `domain` entry (JEP-0004 rule 0), so one value has one encoding and a
signature made for one object never verifies as another. An attestation is the nameserver's
signature over `did`, `alias`, `ns_did`, `valid_from` and `valid_until` (rule 8). Its bytes
are what travels, what a resolver verifies and what it keeps as evidence. The default
validity is 90 days.

**Delegation: who may attest a suffix.** A suffix delegation names the DIDs whose
attestations count for one suffix (rule 3). Its root says what makes it authoritative:

| Root | Authoritative because |
| --- | --- |
| `config` | the resolver's own configuration names the authorities; never published |
| `dns` | the suffix's own host serves it at `https://<suffix>/.well-known/jig-ns-delegation`, under a CA-valid certificate, signed by every authority it lists |
| `contract` | a threshold of the parties to a shared data contract signs it (v0.3) |

A resolver settles a suffix's delegation before it accepts any attestation under it, with
precedence `config` > `contract` > `dns`, and refuses an attestation from a DID outside it
(rules 4 and 5). A single-label suffix such as `jig` is never `dns`-rooted: `https://jig/`
reaches whatever host the local network calls `jig`. `@jig` is the default suffix. Clients
and servers ship a `config` delegation for it naming the project nameserver, and an
operator's own entry for `jig` replaces it.

**Action-bound proofs.** `GET /v1/challenge` returns a fresh nonce. Register and renew carry
a proof of control: the DID's COSE_Sign1 over the action, the nameserver's DID, the alias
and that challenge (rule 10). A proof made for one action, name or nameserver does not
verify for another, and a signature over the bare challenge is refused. The nameserver
consumes the challenge on the first proof that verifies. Register, renew and rotate also
carry proof-of-work bound to the same challenge
([Nameserver mechanics](#nameserver-mechanics)).

**Rotation by link.** An alias moves to another DID only by a key link
([JEP-0012](https://github.com/jig-protocol/jig/blob/main/repos/jig-spec/jep/jep-0012-key-links.md)) from the old DID to the new one, signed by both
keys and scoped to one nameserver and one alias (rule 9). The nameserver keeps every link it
accepted and serves the chain with the attestation it produced, so a client follows its pin
from the old DID to the new one on signatures alone, without trusting the nameserver.

**Reachability.** A DID has no home server. It MAY sign a reachability record listing the
servers where it wants to be found (rule 21). Nobody but the DID can produce one, and a
nameserver MAY serve the DID's latest record beside its attestation.

An alias is a claim by the nameserver, not proof ([OP-08](threat-register.md)). Whoever acts
on a binding verifies it, and a client pins it (see
[Resolution by clients](#resolution-by-clients)).

Registering an alias creates a binding, so it MUST carry
[proof-of-work](#proof-of-work) and be rate-limited like any other binding endpoint.

**Status:** *(partial)*.

- **Implemented:** COSE attestations and action-bound register and renew proofs (#210);
  `config` delegations in servers (#200), which do no `dns` discovery; `config` and `dns`
  delegations in clients (#201); the built-in `@jig`
  delegation in the CLI (#214) and the server (#218); reachability records, taken at
  register and served beside the attestation. The built-in `@jig` delegation fails closed:
  while its authority is a placeholder (every build without jig-core's
  `test-default-authority` feature), nothing is added, and `@jig` names are refused like any
  undelegated suffix.
- **Wire details:** register, renew, rotate and resolve return the attestation
  base64url-encoded as `attestation`, beside `links` and `reachability`, plus unsigned `did`,
  `alias` and `valid_until` hints for older clients. `GET /.well-known/jig-ns-delegation`
  serves the nameserver's signed delegation for a `dns`-rooted suffix (`?suffix=`, else the
  request's `Host`) as `{"envelopes": [...]}`; a single-label suffix has none.
- **Not yet rotation by link:** until lane I's I3, `/v1/rotate` takes two signatures over the
  bare challenge, one by each key, and `links` is always empty. A client therefore sees a
  rotation as any other change of DID behind a pinned name, and moves the pin only when its
  user accepts the new DID (rule 18).
- **Proof-of-work:** `/v1/register`, `/v1/renew` and `/v1/rotate` carry JEP-0008
  proof-of-work, on by default per suffix, and registrations by strangers pass a per-suffix
  pool. They are also rate-limited per client IP and per DID (`[alias_rate_limits]`). See
  [Nameserver mechanics](#nameserver-mechanics).
- **TLS:** the reference nameserver serves TLS by default (rule 12). `[tls] enabled = false`
  serves plaintext and is listed in `unsafe_options_active`.

One nameserver serves several suffixes (#224). `[[v0_0_2.nameserver.alias_suffixes]]` is
required, with no default, and each suffix sets its own policy: `registration` (`open` or
`closed`; a closed suffix still resolves, renews and rotates), `min_alias_len`, reserved names,
and `registration_allow`, which lets one DID register exact names past that policy. A
single-label suffix needs `single_label_authority = true`. Register takes an optional `suffix`
(required when more than one is served: `SUFFIX_REQUIRED`; unserved: `UNKNOWN_SUFFIX`), and a
DID holds at most one name per suffix: a second registration, or a rotation onto a DID that
already holds one, is refused with 409 `DID_HOLDS_NAME`. Policy refusals are
`REGISTRATION_CLOSED`, `ALIAS_TOO_SHORT` and `ALIAS_RESERVED`. `GET /v1/suffixes` lists the
suffixes served, their registration mode and the nameserver's DID, unsigned.

### Resolution by servers

A server resolves the alias on an incoming block in one of two modes (`[identity] mode`). In
`tofu` mode, the default, the first DID seen for a nickname is locked, and a later block with
a different DID is refused. In `nameserver` mode the server verifies the name:

- **Suffix binding.** The server resolves `alias@suffix` only through that suffix's entry in
  `[identity.delegations]` (`authorities` and `nameservers`), plus the built-in `@jig`
  entry, and refuses a suffix with none. Nothing falls back to another nameserver.
- **Verification.** It asks every listed nameserver, and accepts an attestation only when one
  of the suffix's `authorities` signed it, inside its validity window on the server's clock,
  for exactly that alias (JEP-0004 rule 13).
- **Equivocation.** Two valid answers naming different DIDs refuse the alias, and both are
  kept (rule 15).
- **Caching within validity.** A verified binding is cached until the earlier of
  `cache_ttl_seconds` (default 300) and the attestation's `valid_until`, and its validity is
  checked again on every use (rule 14).
- **Evidence.** Every attestation the resolver acts on is kept (rule 20).

A server's check serves only the server's own decisions. A client never relies on it
(rule 13).

**Status:** implemented (#200, #218). Ingest verifies a name only when a block carries one
(`metadata.nickname`); blocks without one are not checked. Evidence goes to the server's
`name_evidence` table. `trusted_nameservers` is ignored, with a startup warning.

### Resolution by clients

A client resolves a name through its own delegations (`[naming.delegations]` in `cli.toml`,
plus the built-in `@jig` entry), else `dns` discovery, and verifies every attestation as a
server does. It never takes a server's word for a name, and fetching through a server
changes nothing about verification (rules 13 and 16). Then it holds the answer to its pin:

- A name seen for the first time is pinned, keyed by alias, suffix, root and root
  identifier (rules 6 and 17), and the client shows the DID and the nameserver that vouched
  for it.
- A pinned name that resolves to its pinned DID is used.
- Any other answer is refused, with both DIDs, unless a chain of rotation links leads from
  the pinned DID to the new one, or the user accepts the change (rule 18). That covers a
  nameserver that re-binds the name, a change of nameserver, and re-registration after
  expiry.
- Everything a resolution acted on, every attestation and link exactly as served, is kept
  as evidence (rule 20).

**Status:** implemented in the CLI. `jig dm`, `jig channel add` and `jig channel kick` take
`alias@suffix`, pin on first use and refuse a changed DID before anything about the peer is
sent (#215). `jig trust verify-name` resolves and pins, `jig trust accept-name` moves a pin
to a DID its holder confirmed (#213, #225), and `jig ns resolve` verifies without pinning.
Evidence goes to `~/.jig/evidence/names/`, one file per resolution. Integration test
`h13_verified_names` runs each case against real nameservers: an honest name, a re-bound
name, a rotation, a signer outside the delegation, two authorities that disagree, an expired
attestation and a forged one. Until rotation links exist, a rotation needs the user's
acceptance (see [Aliases](#aliases)).

### Anonymous identities

An **anonymous** (`--anon`) identity is a fresh, unregistered session key (D20). The client mints
it for one session, registers it with no nameserver, and discards it afterwards. It still
signs and still proves possession of its key: it is unregistered, not unauthenticated. Any
reputation it earns lasts at most for the session.

Whether a server looks an `--anon` key up against a nameserver, and what it does with the
result, is that server's policy. A lookup finds nothing, so the key is unknown under every
ruleset (see [Reputation is a number](#reputation-is-a-number)). Usually only
[null-sec](#security-levels-and-ruleset-groups-server-policy) servers admit `--anon`
identities.

- The protocol MUST NOT define any mechanism that links an anonymous identity to a DID.
  There is no warrant, escrow or tribunal path that unmasks one.
- A nameserver or server MUST NOT require a DID, or a proof derived from a DID key, to
  admit an anonymous identity.
- Clients SHOULD keep anonymous keypairs apart from DID keypairs: separate storage, no
  derivation from a DID seed, no reuse across identities, and no shared device
  identifiers in requests made under different identities.
- Clients SHOULD show which kind of identity is active (for example `~` for anonymous,
  `@` for an alias).

`--anon` needs no alias. Separately, the nameserver can mint short-lived anonymous aliases
(`anon-` plus 12 hex characters) through `POST /v1/alias` *(not served: removed with the
legacy routes)*. An alias minted **with** a
`subject` is a pseudonym, not an anonymous identity: the nameserver stores the link to the
subject. It MUST NOT be presented to users as anonymous.

**Status:** servers and the CLI have no `--anon` login yet. Server admission admits DIDs it
has no score for unless the operator sets `unknown_dids` to refuse, which is how an `--anon`
key would be treated today.

### Capability tokens

Capability tokens are signed grants that bind an identity to a specific permission (for
example "alice can fetch from `api.weather.gov`"). They carry no ambient authority: each
action needs an explicit token.

```json
{
  "issued_to": "did:jig:alice",
  "capability": "net.fetch",
  "scope": ["https://api.weather.gov/*"],
  "fuel": 1000000,
  "expires_at": "2025-12-31T23:59:59Z",
  "issuer_signature": "ed25519:..."
}
```

The server verifies the signature and expiry before granting access. Blocks request
capabilities in their manifest ([Block Execution Model](block-execution.md)).

## Reputation

### Reputation is a number

Reputation is a score for a **user**, a **server** or a **nameserver**, under one
**ruleset**. Behaviours raise or lower it. It is not a tier, and nothing about it is a
stage gate a subject "transitions" through.

- A score MUST be scoped to one ruleset. There is no global score.
- The priority is a **shared ruleset**: every member of a
  [ruleset group](#security-levels-and-ruleset-groups-server-policy) is rated by the same
  rules, which produce the same reputation maths, so a score means the same thing wherever
  the group uses it (D21).
- A server MUST report reputation changes for the clients it works with to the nameservers
  of its ruleset group. The nameservers MUST compute the net change from every member
  server's reports and enforce it across the group (D23). A nameserver MUST treat a server's
  report as a claim by that server, not as a fact, and MUST NOT let one server's marginal
  observation stand for the net change.
- Scores MUST NOT be pooled across a security level. A score moves to a different ruleset
  only through a [translation contract](#rulesets-and-translation-contracts) both parties
  agreed to.
- A subject with no score under a ruleset is **unknown** for that ruleset, not low. What a
  server does with unknown subjects is its own policy.

The reference nameserver computes a score as the weighted mean of the unexpired
observations recorded for that subject and ruleset (at most 1024 are read). An observation
carries `score`, `weight` (default 1.0), `observer`, optional `evidence` and optional
`expires_at`.

| Endpoint | Purpose |
| --- | --- |
| `POST /v1/reputation/observe` | Record an observation and return the new aggregate |
| `GET /v1/reputation/{subject}/{id}` | Aggregates for every ruleset the subject has |
| `GET /v1/reputation/{subject}/{id}/observations` | Raw observations (`ruleset`, `limit` ≤ 1000) |

`{subject}` is `user`, `server` or `nameserver`.

**Status:** not served by the nameserver. Its observation endpoints were removed with the
legacy routes, so it records and returns no scores. Servers keep operator-seeded scores
per ruleset for admission floors (`[auth.admission] records`) and report nothing to
nameservers. Net computation across a ruleset group is not implemented; its redesign is the
[JEP-0009](https://github.com/jig-protocol/jig/blob/main/repos/jig-spec/jep/jep-0009-rulesets-reputation-logs.md) draft.

### Rulesets and translation contracts

A **ruleset** is a named, versioned scoring policy: `key`, `version`, `authority`,
`weight`, a PoW policy (`min_bits`, `max_bits`, `multiplier`) and a tribunal policy
(`quorum`, `auto_escalate_score`, `evidence_window_secs`). Servers and nameservers that
adopt the same ruleset key agree on what its scores mean.

Parties with different rulesets MAY map scores between them with a **translation
contract**: `from`, `to`, `weight`, and a `linear` (`slope`, `intercept`, optional clamps)
or `table` transform. A contract is a data contract between the two parties. Neither side
is bound by the other's ruleset without one. Interop between ruleset groups this way is
possible but not a first priority; the priority is a shared ruleset within a group (D21).

**Status:** rulesets and contracts are parsed and published in `/.well-known/jig-ns`, and
nothing applies them. The nameserver's proof-of-work is set per suffix in its own config,
not by a ruleset, and it serves no scores.

### Reputation is not a protocol gate

Until JEP-0003 defines reputation:

- Reputation is not a protocol security input: no protocol step requires or refuses
  anything because of a score, and handshake reputation fields are informational
  ([OP-10](threat-register.md)).
- A nameserver uses its own scores to scale proof-of-work, and a server MAY use its own
  scores in its admission policy. Both are local policy, not protocol.

### Sybil resistance

Proof-of-work prices each new identity at one solution, so N identities cost N times one.
That linear cost is a **known weakness the nameserver design must close**, not an
accepted property. Fresh keys stay cheap on purpose, because `--anon` depends on them; what
must not stay linearly cheap is standing: aliases, and reputation under a ruleset.

- A ruleset group MUST NOT rest its Sybil resistance on proof-of-work alone.
- Before the nameserver design is complete, a ruleset group MUST have an admission input
  for standing that costs an attacker more per identity than hashing does. Candidates are
  cross-registration within the group and [soul validation](#proposed-soul-validation).
- That input MUST NOT link identities to each other or to a person.

**Status:** not yet designed. Today Sybil cost is linear. The nameserver's registration pool
caps how many names strangers get per hour on a suffix, whatever they spend, but it prices
names, not identities.

### Proposed: soul validation

*Not implemented.* Real humans vouch that another identity is a real human by staking
their own reputation on it. While the vouch stands, the vouchee's reputation gains are
boosted. The vouchee's reputation losses also propagate to every voucher, the vouchee's
**soulnet**. Open questions for a JEP: the boost and propagation factors, how far losses
propagate, how a voucher withdraws, and how to resist rings that vouch for each other.

## Security levels and ruleset groups (server policy)

A security level describes what user behaviour and how much anonymity a server or a
ruleset group permits, and how enforcement spreads. Any user MAY try to join any server.
A user MAY hold different identities in different ruleset groups, and the protocol MUST
NOT link them.

| Security level | Nameservers | Identities | Proof-of-work | Enforcement |
| --- | --- | --- | --- | --- |
| **High-sec** | Several, in one ruleset group: they cross-register identities | DIDs registered across the group | Scales with reputation under the group's ruleset | Penalties and tribunal outcomes propagate across the group |
| **Low-sec** | A local nameserver | DIDs, optionally aliased | Local defaults | Local penalties; few or no tribunals |
| **Null-sec** | Optional | `--anon` allowed; identities may be unregistered and unprotected | Highest floor | Minimal; reputation is transient |

Everything shared is shared within one ruleset group. Two ruleset groups at the same
security level are independent: reputation, penalties and tribunal outcomes do not cross
between them, except under a translation contract they both agreed to.

High-sec servers are more likely to require a higher local reputation to join. Null-sec
servers are usually the only ones that admit `--anon` identities.

**Status:** security levels and ruleset groups are not yet configuration settings. The
nameserver's anonymous proof-of-work floor (`JIG_NS_ANON_MIN_POW`) went with the legacy
alias challenges; it is still parsed, no longer published (#192), and nothing applies it.

### Admission proof-of-work (servers)

A server MAY ask a DID it has no record of to do proof-of-work once, before the server
serves that DID anything. The work is JEP-0008's `admit` action: admission mode, with an
empty binding and salt, bound to the server's DID (the verifier) and the new DID (the
subject). It cannot be reused for another server or another identity, and anyone can check
it. The server holds no state for a DID until the work is done.
[JEP-0008](https://github.com/jig-protocol/jig/blob/main/repos/jig-spec/jep/jep-0008-proof-of-work.md)
rules 6–15 are normative; this section describes the reference server.

- **Proof.** The client posts `{did, pow, sig_b64}` to `POST /api/v1/admission`. `pow` is
  the rule-10 proof `{alg, effort, nonce, salt_id}`, with `salt_id = 0`. `sig_b64` is the
  DID's Ed25519 signature over the labelled BLAKE3 hash of (`domain`, `jig-admission-v2`),
  (`server`), (`did`), (`alg`), (`effort`), (`nonce`) and (`salt_id`), so nobody can admit
  a key they do not hold.
- **Order.** The server checks the work first (one digest, rule 10), then the signature,
  then refuses a banned DID. It then records the DID as proven. A DID stays proven if the
  server later asks for more.
- **Legacy form, for one release.** The server still accepts `{did, nonce, sig_b64}` under
  `jig-admission-pow-v1` (JEP-0008, Backwards Compatibility). Its digest is over
  (`domain`, `jig-admission-pow-v1`), (`server`), (`did`) and (`nonce`, a JSON string of at
  most 64 bytes), and needs `pow_bits` leading zero bits. Its `sig_b64` signs (`domain`,
  `jig-admission-v1`), (`server`), (`did`) and (`nonce`). It is accepted for one release,
  then refused.
- **The ask.** When admission asks for work, the signed welcome states it as
  `admit: {alg, effort, salt_id, expires_at}` (rule 15). `/.well-known/jig` repeats it as
  unsigned hints: `admission_pow` (`alg`, `effort`, `salt_id`) and the legacy
  `admission_pow_bits`.
- **Standing.** A signed `GET /api/v1/admission` returns the caller's own `did`, `proven`,
  `pow_bits` and `effort`. `proven` is true when admission lets the DID in without (more)
  work: it did the work, or the server has a record of it, or asks for none. Owing work is
  not a refusal here, so a DID that owes it can ask; any other admission refusal is
  returned as itself. It does not charge the caller's rate, and it never answers for any
  DID but the signer's.
- **Refusal.** Until the DID is proven, admission refuses it on every read, subscription
  and write with `403 PROOF_OF_WORK_REQUIRED`. Work that does not verify is
  `400 PROOF_OF_WORK_INSUFFICIENT`.
- **Relayed authors.** The author of a block relayed by a federated peer or submitted by a
  bridge never spoke to this server, so is not asked for the work (rule 30). Bans, floors
  and rate limits still apply to it.

**Status:** partial. The reference server does this under `[auth.admission] unknown_dids =
"proof-of-work"`. The effort is still set by `pow_bits` (default 20, accepted 1 to 28), as
`2^pow_bits`. The default policy is still `admit`, and the effort is fixed: no controller
adapts it to load and no ruleset sets it, so rule 33's adaptive default-on is not built
yet. The CLI does the work the first time it talks to such a server, in the JEP-0008 form
when the server advertises `admission_pow`, else in the legacy form. 2^20 digests take
about 0.2 s on one server core and far less on a GPU. The work makes minting identities to
spread a flood across rate-limit buckets cost something; it does not stop a determined
Sybil (see [Sybil resistance](#sybil-resistance)).

### Capacity pools (servers)

<!-- R1 task 5a: confirm against the merged [auth.pools] PR -->

JEP-0008 rules 21–23 divide a server's capacity between members, invited subjects and
strangers, so a flood of fresh identities reaches only the stranger pool.

- **Shares.** Each pool gets a share of the server's local writes. Strangers get at most
  20 % and invited subjects at most 10 % by default. Members never wait on the other pools.
- **Members**, until JEP-0009, are DIDs in the server's admission `records`, or DIDs whose
  admission proof is at least `local_member_age_secs` old.
- **Invited** stays empty until JEP-0009 defines invites.
- **Strangers** are everyone else, and every `--anon` key.

**Status:** not on `main`. It lands in a separate PR as `[auth.pools]`. Until then a server
has only its per-DID and per-address rate limits (`[auth.rate_limit]`).

### Cross-registration within a ruleset group

Nameservers in a high-sec ruleset group MUST cross-register identities: they share their
alias-to-DID mappings, penalties and tribunal outcomes, so an alias resolves to the same DID
on every member and a user is cross-validated across handles and servers. The nameservers
compute the net reputation change from the group's servers' reports and apply it on every
member under the group's ruleset. This shared registry is what makes a group high-sec.

A nameserver MUST NOT resolve another nameserver's aliases as its own unless that
nameserver agrees to federate.

**Status:** not yet implemented. The nameserver resolves only its own aliases
(`/v1/resolve/{alias}`). Its earlier SRV-based remote resolution (`/v1/resolve?name=`) and
its gossip endpoints were removed with the legacy routes.

### Anchor nameservers

*Proposed.* A nameserver MAY **anchor** a ruleset group, usually a high-sec one, so members
do not bootstrap from scratch. An anchor publishes initial coordination:

- default proof-of-work parameters,
- address and handle conventions,
- tribunal coordination.

Rules:

- Joining an anchored ruleset group is opt-in.
- An anchor's defaults are advisory. A member MAY override any of them and MAY leave.
- No nameserver, anchor included, holds a veto over another nameserver, server or ruleset
  group, or can control the network.
- Anyone MAY run ruleset groups at any security level with their own anchors, or none, or
  connect to servers without joining one. A group MAY have more than one anchor.

## Nameserver mechanics

> **Normative source:** [JEP-0008](https://github.com/jig-protocol/jig/blob/main/repos/jig-spec/jep/jep-0008-proof-of-work.md)
> (proof-of-work, pools, penalties) and
> [JEP-0004](https://github.com/jig-protocol/jig/blob/main/repos/jig-spec/jep/jep-0004-verified-naming.md)
> (challenges, proofs of control). This section describes what the reference nameserver
> serves. Where it and the JEPs differ, the JEPs govern and the difference is a gap in the
> code.
>
> The prototype's proof-of-work challenges (`POST /v1/challenge`, `/v1/claim`, `/v1/alias`),
> its penalties and rate keys, `/v1/policy`, `/v1/resolve?name=`, the transparency and admin
> routes and nameserver federation were removed (#154) and are not served.
> `/.well-known/jig-ns` publishes `policy.alias_rate_limits` (`enabled`, `per_ip_per_min`,
> `per_did_per_min`), and still publishes the legacy `automation` and `reputation`
> parameters, which nothing enforces. It publishes no proof-of-work or pool parameters: a
> client learns the effort from the signed offer.

### Endpoints

| Path | Method | Purpose |
| --- | --- | --- |
| `/.well-known/jig-ns` | GET | Discovery document (JSON) |
| `/.well-known/jig-ns/capabilities` | GET | Capability document (plain text) |
| `/v1/health` | GET | Liveness |
| `/v1/challenge` | GET | A challenge for one action, DID and name, with the signed effort offer |
| `/v1/register` | POST | Bind an alias to a DID; carries `pow` |
| `/v1/renew`, `/v1/rotate` | POST | Renew an alias, or move it to a new DID; carry `pow` |
| `/v1/resolve/{alias}` | GET | Alias attestation lookup |
| `/.well-known/jig-ns-delegation` | GET | Signed delegation for a DNS-rooted suffix |
| `/v1/suffixes` | GET | Suffixes served, their registration mode, and the nameserver's DID |
| `/v1/handles` | GET | Every registered alias; served only with `[v0_0_2.debug] list_handles` |

### Challenge flow

1. **Ask.** `GET /v1/challenge?action=register|renew|rotate&did=<did>&name=<alias@suffix>`.
   For rotate, `did` is the old DID. A request with `action` but no `did` or `name` is
   `400 BINDING_REQUIRED`.
2. **Offer.** The reply is `{challenge, pow: {alg, effort, salt_id, expires_at}, pow_offer}`.
   - `challenge` is 32 random bytes in hex, valid for 60 s.
   - `pow_offer` is a COSE_Sign1 by the nameserver's DID over the deterministic-CBOR offer
     (`jig-ns-pow-offer-v1`: `challenge`, `action`, `name`, `did`, `ns_did`, `alg`,
     `effort`, `salt_id`, `expires_at`). This is rule 16's signed effort. A client verifies
     it against the DID the suffix's delegation names.
   - The nameserver records the action, DID, name and promised effort with the challenge.
     It checks the proof against that promise, so an effort rise mid-solve never refuses a
     client.
3. **Cheap refusals first.** For `action=register`, the policy runs before any offer:
   `REGISTRATION_CLOSED`, `ALIAS_TOO_SHORT`, `ALIAS_RESERVED`, and `ALIAS_TAKEN` by another
   DID. Nobody solves work for a name they cannot have. Not `DID_HOLDS_NAME`: the request is
   unauthenticated, and refusing there would tell anyone which name a DID holds.
4. **Solve and send.** The client solves the offer and sends the proof as `pow`
   (rule 10: `{alg, effort, nonce, salt_id}`, `salt_id = 0`, `effort` at least the offer's)
   with `challenge` on register, renew or rotate.

A bare `GET /v1/challenge` (no `action`) still works for clients from before R1. On a suffix
that asks for work it can only lead to `428 POW_REQUIRED`.

### Proof-of-work

Proof-of-work is required, not optional (D23):

- A server MUST enforce proof-of-work on the clients it serves, at the cost its ruleset
  sets.
- A nameserver MUST require it on every request that creates or keeps a binding (rule 31).
- A client MUST be able to solve it from public information alone (rule 9).
- A nameserver that adopts a ruleset MUST scale effort by the subject's standing under it,
  within the ruleset's bounds (rule 28), so standing moves the price but never becomes a
  gate.

**Bindings (rule 11).** The work's subject and binding:

| Request | Subject | Binding |
| --- | --- | --- |
| register | `did` | `proof_hash("register", ns_did, alias, challenge)` |
| renew | `did` | `proof_hash("renew", ns_did, alias, challenge)` |
| rotate | `old_did` | interim: BLAKE3 of the deterministic-CBOR map `{domain: "jig-alias-rotate-pow-v1", ns_did, alias, old_did, new_did, challenge}`, until JEP-0004 gains a rotate proof |

So work done for one action, alias, nameserver or challenge fails for any other.

**Order of checks in `register`.** Cheap refusals before work, work before any signature:

1. Parse the alias, the suffix and the name.
2. Suffix policy: closed, too short, reserved.
3. The challenge: known, unexpired, and issued for this action, DID and alias. Otherwise
   `401 CHALLENGE_UNKNOWN`, and the challenge stays usable by its rightful request.
4. The work: one digest against the promised effort.
5. The proof of control (the DID's signature), then the reachability record.
6. `ALIAS_TAKEN` by another DID.
7. The [registration pool](#the-registration-pool), for a stranger.
8. Consume the challenge; `ALIAS_TAKEN` and `DID_HOLDS_NAME` again, since the store can
   change meanwhile.

Renew checks the work, then the proof of control, then consumes the challenge, then that
the DID holds the alias. Rotate checks the work before both signatures, and consumes the
challenge last. No refusal before the consume uses the challenge up.

**Refusals.**

| Refusal | When |
| --- | --- |
| `428 POW_REQUIRED` | No `pow` for a challenge that promised work; the body restates `pow_offer`. Also any request on a challenge issued without `action`, on a suffix that asks for work |
| `400 POW_INVALID` | Another algorithm or salt, a nonce over 64 bytes, or a digest that misses the bid |
| `400 POW_INSUFFICIENT` | A bid below the promised effort |
| `503 REGISTRATION_BUSY` | The suffix's registration pool has no token for this stranger; `Retry-After` (and `retry_after` in the body) is the seconds until the next token |
| `503 BUSY` | The challenge map is full (`max_pending_challenges`); live challenges are never evicted |

A `pow` field that is not a proof object fails to parse, and the request is refused before
any check.

**Effort for one registration (rule 18).** Per suffix, in
`[v0_0_2.nameserver.alias_suffixes.pow]`:

```
E = clamp( max(min_effort, suggested)
           × short_name_factor ^ max(0, short_name_len − len(alias))
           × 2 ^ penalty_points,
           min_effort, max_effort )
```

- `suggested` is the pool's controller (below). `m_standing` is 1 until JEP-0009.
- Defaults: `min_effort` 2^20, `max_effort` 2^24, `short_name_len` 5, `short_name_factor`
  4. So 4 letters cost 4× and 3 letters 16× a name of 5 or more.
- 1 and 2 letters are reserved: `min_alias_len = 3` refuses them, and only a
  `registration_allow` entry can register them.
- An allowlisted registration (`registration_allow`) pays `min_effort`, with no length
  multiplier or penalty.
- Renew and rotate pay `renew_effort` (default 1).
- `min_effort = 0` turns proof-of-work off on the suffix, for all three actions.
- Boot refuses a `max_effort` above 2^28, or one that does not fit `max_solve_secs` at
  5.5 million digests a second, or a `max_solve_secs` above half the challenge lifetime.

### The registration pool

Per suffix, in `[v0_0_2.nameserver.alias_suffixes.pool]` (rules 17, 21–24). It bounds how
many strangers register per hour, however much compute they bring.

- **Strangers** are registrants the suffix's `registration_allow` does not name. Renew and
  rotate by the holder, and allowlisted registrations, skip the pool.
- **Tokens.** A token bucket of `strangers_per_hour` (default 60) with `burst` (default 10).
  A stranger whose work and signature verified takes a token.
- **Queue.** With no token, the request waits in a queue of `queue_len` (default 20),
  highest bid first, arrival order between equal bids. A full queue takes a newcomer only
  if it bids more than the lowest waiting request, which is then refused. After
  `queue_wait_secs` (default 10) without a token, the answer is `503 REGISTRATION_BUSY`.
- **Replays.** The request claims its challenge before it queues, so a replay of the same
  proof takes no second token.
- **Controller** (`doubling`, per `controller_window_secs`, default 300). After a window in
  which the queue was full, `suggested` doubles, up to `max_effort`. After a window in which
  nothing queued, it halves, never below `min_effort`. New offers state the result.
- `enabled = false` admits every stranger whose work verifies.

### Rate limiting

In `[alias_rate_limits]`, in fixed one-minute windows held in memory, per process:

| Limit | Default | Counted |
| --- | --- | --- |
| `per_ip_per_min` | 30 | Each `POST` to register, renew or rotate, per client address |
| `per_did_per_min` | 10 | Each one that succeeds, per DID it names; success needs that DID's signature |
| `challenge_per_ip_per_min` | 60 | Each `GET /v1/challenge`, per client address, in a bucket of its own |
| `max_pending_challenges` | 100 000 | Challenges issued and not yet used or expired. A tenth is kept for renew and rotate |

- IPv6 addresses count per /64. Behind a proxy (`[network] trust_proxy`), the address is
  the last entry of `proxy_ip_header`.
- A refusal is `429 RATE_LIMITED` with `Retry-After`. It charges no bucket and adds no
  penalty.
- Rate limits run before the pool (rule 23).
- `enabled = false` turns the three per-minute limits off. `max_pending_challenges` always
  applies.

### Penalties

Penalties raise the effort a registration is asked for (rules 26–27). They key on:

- **`ip:<address>`** (IPv6 per /64), for work that does not verify on register
  (`POW_INVALID`, `POW_INSUFFICIENT`). The work is checked before the signature, so the DID
  it names is unproven; charging that DID would let anyone raise its price.
- **`pair:<alias>|<did>`**, for a signed register attempt on an alias another DID holds.
  Other DIDs asking for the same alias pay nothing more.

Each point doubles the effort: the pair's and the address's points add, up to 32 counted,
and the result is clamped at `max_effort`. A penalty lives `penalty_decay_secs` (default
600). A repeat offence before it lapses adds a point and doubles its life, up to a day; when
the life ends, all its points lapse at once. At most 100 000 keys are held. Renew and rotate
neither read nor add penalties. Penalties, the pool and the controller are in memory and
per process, like the rate limits.

### Policy and discovery documents

A nameserver publishes its policy at three paths:

- **`GET /.well-known/jig-ns`** (JSON): `version`, `endpoints`, and `policy` with `pow` (`base`, `min`, `max`,
  `anonymous_min`) *(not served: removed in #192)*, `rate_limit` (`per_key_per_min`,
  `per_ip_per_min`, `global_per_min`) *(not served: replaced by `alias_rate_limits` in #197)*,
  `alias_rate_limits` (`enabled`, `per_ip_per_min`, `per_did_per_min`; the limits the alias
  routes enforce), `automation` (legacy; nothing enforces it) and `reputation`.
  `allow_domains`, `deny_domains` and `cache_ttl_secs` are no longer served (removed with
  nameserver federation, #237). `ns_id` and `policy.public_key`, which named a second,
  legacy nameserver key, are no longer served (#259): a nameserver has one identity, its
  `ns_did`. Where the document carries `server_did`, that is the same DID, the one its TLS
  certificate is bound to. The document is unsigned, so `server_did` is a hint only: clients
  authenticate a nameserver by its TLS binding and the suffix's delegation.
- **`GET /.well-known/jig-ns/capabilities`** (plain text): `version`, optional `domain`,
  one `work:` line per useful-work type, `tribunal:` and `transparency:` (`enabled` or
  `disabled`), and optional `affordance:` lines. The `federation:` line is no longer served
  (#259).
- **`GET /v1/policy`** (JSON) *(not served: removed with the legacy routes)*: `pow` (`base_difficulty`, `min_difficulty`,
  `max_difficulty`, `anonymous_min_difficulty`), `rate_limits`, `automation` and
  `reputation`.

DNS SRV records advertise nameserver endpoints:

```
_jig-ns._tcp.example.com. 3600 IN SRV 10 5 7070 ns1.example.com.
```

Without an SRV record, a resolver falls back to the domain's addresses on port 7070.

### Federation between nameservers

A nameserver chooses its peers. Deny takes precedence over allow, and an empty allow list
admits every domain not denied. With `[federation] enabled`, peers exchange policy hashes
(`GET /v1/federation/policy`) and gossip (`POST /v1/federation/gossip`). A nameserver MUST
treat gossip as claims by the sending peer, not as facts. *(not served: both routes were
removed with the legacy routes.)*

## Transparency log

Servers and nameservers each keep a transparency log (D23). A server MUST keep an
append-only log of what it enforced and the reputation reports it sent, under the same
evidence and redaction rules as below. A nameserver MUST keep an append-only transparency
log and publish it, so members of its ruleset group and anyone else can check what it
enforced. The nameserver's log:

- MUST record tribunal decisions, penalty and reputation changes made by a decision or
  received from the ruleset group, and identity bindings it creates;
- MUST chain entries by hash, publish the chain head periodically, and let anyone verify
  the chain;
- MUST cite evidence by reference (block CIDs), never by content, and MUST redact personal
  data;
- MUST NOT record anything that links an anonymous identity to a DID.

**Status:** not implemented. Servers keep no log. The nameserver's read endpoints
(`GET /v1/transparency/entries`, `/hashes`, `/verify`) were removed with the legacy routes;
it never wrote entries. Redesign: the [JEP-0009](https://github.com/jig-protocol/jig/blob/main/repos/jig-spec/jep/jep-0009-rulesets-reputation-logs.md) draft.

## Useful work

*Not served.* The prototype's routes were removed. Under them an operator queued work (`POST /v1/work/enqueue`, admin), workers claimed it
(`POST /v1/work/assign`) and submitted results (`POST /v1/work/{id}/result`). Kinds:
`validate_block`, `verify_observation`, `audit_ruleset`, `custom`,
`process_executable_block`, `validate_fuel_counts`, `cross_validate_receipt`,
`resolve_receipt_dispute`.

*Proposed:* results checked by independent validators, with concurrence earning reputation
and wrong or late results losing it. Until then, results do not change reputation or
proof-of-work. The proof-of-work in [Proof-of-work](#proof-of-work) is plain hashing, not
useful work.

## Tribunals

Tribunals are required, and a ruleset group's nameservers hold them (D23). Automatic
penalties handle volume; tribunals handle judgement: harassment, coordinated campaigns,
appeals against a penalty, and a federated instance that lies. Servers bring cases and
evidence. Each ruleset group judges disputes under its own ruleset, and recognition across
groups is voluntary. There is no tribunal above the groups.

- A high-sec ruleset group MUST provide a tribunal. A low-sec group MAY keep tribunals
  local and rare. A null-sec group need not provide one.
- A case MUST be openable both by automated triggers (for example high penalty
  accumulation or a high-severity anomaly) and by a report from a participant.
- A case MUST cite its evidence by reference. A decision that cites no evidence is not a
  decision.
- A decision MUST be signed by the panelists who made it and appended to the
  [transparency log](#transparency-log).
- The nameservers MUST enforce a decision's outcome as a net reputation change, and the
  group's servers apply it under the ruleset; no one else is bound unless they choose to
  recognise it.
- A subject SHOULD be able to appeal once, to a panel with no members of the first.
- A ruleset group MAY set panel size, appeal limits and penalty ranges in its ruleset.
- A tribunal never has a path to unmask an anonymous identity
  ([Anonymous identities](#anonymous-identities)).

Panel selection and appeal mechanics need a JEP.

**Status:** not implemented. The prototype's case records (`POST /v1/tribunal/cases`,
`/v1/tribunal/cases/{id}/decision`) were removed with the legacy routes. Panels,
signatures, appeals, penalties, logging and propagation were never implemented. Redesign:
the [JEP-0010](https://github.com/jig-protocol/jig/blob/main/repos/jig-spec/jep/jep-0010-reports-tribunals-lists.md) draft.

### Reporting abuse in encrypted channels

A tribunal MUST be able to act on abuse that happened in an encrypted channel (D22). Abuse
happens in channels, and a channel has exactly one owning server (D24), but neither that server
nor any nameserver can read an encrypted channel's content. The evidence must therefore
come from a participant who received it.

The mechanism is **victim-key delegation**, or another form of effective proof: the
recipient gives the tribunal, for the reported messages only, what it needs to verify that
the accused's key sent that content in that channel. Requirements:

- Only a recipient of the content can start a report.
- The proof MUST be scoped to the reported messages and MUST NOT give the tribunal or any
  server standing access to the channel.
- It MUST NOT require key escrow, server-held decryption keys or content scanning.
- It attributes content to the sending key. For an `--anon` sender that is a session key,
  and the report MUST NOT reveal anything more.
- It MUST work for every encryption suite a ruleset group admits. Suites are pluggable;
  MLS is the default ([Encryption](encryption.md)).

**Status:** not yet designed. Nothing implements it.

## Normative requirements summary

Items marked *(not yet implemented)* or *(partial)* are obligations the reference code does
not yet meet.

**MUST:**

- Use a DID as the sender of every block; treat aliases as nameserver claims.
- Verify an alias attestation's signature before using it (servers).
- Scope every reputation score to one ruleset; share it only within the ruleset group, and
  treat what peers send as claims *(partial)*.
- Report reputation changes for clients to the ruleset group's nameservers (servers) *(not
  yet implemented)*.
- Compute and enforce net reputation changes from every member server's reports, and
  enforce servers' good behaviour (nameservers) *(not yet implemented)*.
- Enforce proof-of-work on the clients a server serves (servers) *(partial: admission
  proof-of-work, which the reference server offers but does not turn on by default)*.
- Require proof-of-work, solvable from public information, on register, renew and rotate,
  checked before any signature (nameservers).
- Cap stranger registrations per suffix with a pool that compute cannot raise
  (nameservers).
- Divide a server's capacity into member, invited and stranger pools (servers) *(not yet
  implemented)*.
- Scale proof-of-work by standing under an adopted ruleset, within its bounds *(not yet
  implemented: standing is 1 until JEP-0009)*.
- Refuse used, expired or mismatched challenges.
- Raise effort monotonically with penalty points, clamped to the configured maximum, and
  let points decay to zero without new penalties.
- Close linear Sybil cost with an admission input for standing that costs more than
  hashing, without linking identities *(not yet implemented)*.
- Cross-register identities within a high-sec ruleset group, and resolve another
  nameserver's aliases only with its agreement *(not yet implemented)*.
- Keep and publish a hash-chained transparency log of decisions, enforcement changes and
  bindings (nameservers) *(partial)*, and a log of what a server enforced and reported
  (servers) *(not yet implemented)*.
- Provide a tribunal, held by the nameservers, in a high-sec ruleset group; sign decisions,
  log them, and apply them within the group *(partial)*.
- Let a recipient report abuse in an encrypted channel to a tribunal with effective proof
  *(not yet implemented)*.
- Publish policy at `/.well-known/jig-ns`, `/.well-known/jig-ns/capabilities` and
  `/v1/policy`.
- Treat federated gossip as claims by the sending peer.

**MUST NOT:**

- Define or implement any link between an anonymous identity and a DID.
- Present a pseudonymous alias (one minted with a subject) as anonymous.
- Pool reputation across a security level.
- Treat reputation as a protocol gate before JEP-0003.

**SHOULD:**

- Pin the DID first seen for a name and surface changes (clients).
- Keep anonymous keypairs separate from DID keypairs (clients).
- Allow one appeal against a tribunal decision.
- Advertise nameservers with `_jig-ns._tcp` SRV records.

**MAY:**

- Trust more than one nameserver (servers).
- Use local reputation in admission policy (servers).
- Ask a DID with no record for admission proof-of-work, bound to the server and the DID
  (servers).
- Anchor a ruleset group, join one, override its defaults, or run without one.
- Map reputation between rulesets with translation contracts.
- Set tribunal panel size, appeal limits and penalty ranges in a ruleset.

---

**Related chapters:**

- **[Zero-Trust Model](zero-trust.md)**: fail-closed semantics and adversarial assumptions.
- **[Crypto Primitives](crypto.md)**: Ed25519 for DIDs, BLAKE3 for proof-of-work.
- **[Encryption](encryption.md)**: suites and the MLS default.
- **[Federation](federation.md)**: server-to-server trust.
- **[Threat Register](threat-register.md)**: OP-08 (key substitution) and OP-10
  (reputation gaming).
