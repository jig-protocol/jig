# Identity and Reputation

> **Status.** This chapter states what the system must do. Where the reference code is
> behind, a **Status** line says so; the code's current behaviour is not the intent.
>
> - **Implemented:** `did:jig` identities, nameserver-attested aliases, TOFU and nameserver
>   resolution in servers, per-ruleset reputation scores, proof-of-work with penalties on
>   the nameserver's claim and alias challenges, and tribunal case records.
> - **Required, not yet implemented or partial:** proof-of-work enforced by servers and on
>   every nameserver binding endpoint, reputation reports from servers to nameservers and
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

**Status:** not yet implemented. Servers enforce no proof-of-work, report nothing to
nameservers and keep no transparency log; the reference nameserver computes a
per-nameserver aggregate from its own observations (see
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
- Losing the private key loses the identity. Clients SHOULD make key backup explicit.

### Aliases

A nameserver attests aliases under the suffix it is authoritative for (`alias_suffix`).

1. `GET /v1/challenge` returns a 32-byte hex nonce.
2. The client signs the nonce with its DID key and sends `POST /v1/register` with `did`,
   `requested_alias`, `challenge` and `proof_of_control`.
3. The nameserver returns an attestation (`did`, `alias`, `ns_did`, `valid_from`,
   `valid_until`, `profile_ttl_seconds`, `sig`) signed with its own key. The default
   validity is 90 days.

`POST /v1/renew` extends an attestation. `POST /v1/rotate` moves an alias from one DID to
another and requires signatures from both keys, so the nameserver can link the two DIDs.
`GET /v1/resolve/{alias}` returns the current binding.

The local part is 1 to 24 characters from `[A-Za-z0-9_-]`. An alias is a claim by the
nameserver, not proof ([OP-08](threat-register.md)): a client SHOULD pin the DID it first
saw for a name and surface any change.

Registering an alias creates a binding, so it MUST carry
[proof-of-work](#proof-of-work) and be rate-limited like any other binding endpoint.
**Status:** not yet implemented. This path has neither; proof-of-work and penalties apply
only to the older claim and alias endpoints described under
[Nameserver mechanics](#nameserver-mechanics).

### Resolution by servers

A server resolves the alias on an incoming block in one of two modes
(`[identity] mode`):

| Mode | Behaviour |
| --- | --- |
| `tofu` (default) | The first DID seen for a nickname is locked; a later block with a different DID is refused. |
| `nameserver` | The server queries each URL in `trusted_nameservers` in order and refuses the block if the alias resolves to a different DID. Results are cached for `cache_ttl_seconds` (default 300). |

A server MAY trust more than one nameserver. A server in `nameserver` mode MUST verify the
attestation signature before it uses the binding. **Status:** not yet implemented.

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
(`anon-` plus 12 hex characters) through `POST /v1/alias`. An alias minted **with** a
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

**Status:** partial. The nameserver keeps scores per subject and ruleset, each computed
from its own observations only. Servers keep operator-seeded scores per ruleset for
admission floors (`[auth.admission] records`) and report nothing to nameservers. Net
computation across a ruleset group is not implemented: reputation gossip is received and
stored, not applied.

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

**Status:** rulesets and contracts are parsed and published in `/.well-known/jig-ns`.
Only `pow_policy.multiplier` is applied (see [Proof-of-work](#proof-of-work)). Contracts
are not yet applied to incoming scores.

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

**Status:** not yet designed. Today Sybil cost is linear.

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
nameserver applies the anonymous floor (`JIG_NS_ANON_MIN_POW`) to alias challenges without
a subject, unless `JIG_NS_ANON_ENABLED` is false, and treats every other challenge as
low-sec. Turning the setting off removes the floor; it does not stop anonymous aliases
being minted.

### Cross-registration within a ruleset group

Nameservers in a high-sec ruleset group MUST cross-register identities: they share their
alias-to-DID mappings, penalties and tribunal outcomes, so an alias resolves to the same DID
on every member and a user is cross-validated across handles and servers. The nameservers
compute the net reputation change from the group's servers' reports and apply it on every
member under the group's ruleset. This shared registry is what makes a group high-sec.

A nameserver MUST NOT resolve another nameserver's aliases as its own unless that
nameserver agrees to federate.

**Status:** not yet implemented. The nameserver resolves remote handles through
`_jig-ns._tcp` SRV discovery, gated by `JIG_NS_ALLOW_DOMAINS` and `JIG_NS_DENY_DOMAINS` and
cached for `JIG_NS_CACHE_TTL` seconds, without asking for agreement and without verifying
remote records. Reputation and tribunal gossip is received and stored, not applied.

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

### Endpoints

| Path | Method | Purpose |
| --- | --- | --- |
| `/.well-known/jig-ns` | GET | Discovery document (JSON) |
| `/.well-known/jig-ns/capabilities` | GET | Capability document (plain text) |
| `/v1/policy` | GET | Policy snapshot (JSON) |
| `/v1/health` | GET | Liveness |
| `/v1/challenge` | GET | Alias registration nonce ([Aliases](#aliases)) |
| `/v1/register`, `/v1/renew`, `/v1/rotate` | POST | Alias attestations |
| `/v1/resolve/{alias}` | GET | Alias attestation lookup |
| `/v1/challenge` | POST | Proof-of-work challenge for `claim` or `alias` |
| `/v1/claim` | POST | Bind a handle to a key, with proof-of-work |
| `/v1/alias` | POST | Mint a scoped or anonymous alias, with proof-of-work |
| `/v1/resolve?name=` | GET | Handle lookup: local, then cache, then federated |
| `/v1/transparency/entries`, `/hashes`, `/verify` | GET | [Transparency log](#transparency-log) |
| `/v1/admin/penalties`, `/v1/admin/rate` | GET, POST | Inspect or reset a penalty or rate key |

### Challenge flow

1. `POST /v1/challenge` with `action` (`claim` or `alias`), `subject` and, for `alias`,
   `scope`. The response is `challenge_id`, `difficulty` and `expires_at` (Unix seconds;
   default lifetime 600 s).
2. The client finds a `nonce` that meets `difficulty`.
3. `POST /v1/claim` with the signed claim and `pow: {challenge_id, nonce}`, or
   `POST /v1/alias` with `scope`, optional `subject`, optional `ttl_seconds` (default 3600)
   and `pow`.

A challenge is bound to its action, subject and scope, and is single-use. The nameserver
MUST refuse a used, expired or mismatched challenge.

### Proof-of-work

Proof-of-work is required, not optional (D23). A server MUST enforce proof-of-work on the
clients it serves, at the cost its ruleset sets. A nameserver MUST require a solved
challenge on every request that creates a binding. A client MUST be able to solve a
challenge from public information alone.

**Status:** servers enforce no proof-of-work.

A solution is valid when `BLAKE3(challenge_id|action|subject|scope|nonce)` has at least
`difficulty` leading zero bits. Expected work is about 2^`difficulty` hashes.

**Status:** partial. Only `/v1/claim` and `/v1/alias` require it (not `/v1/register`). The
reference nameserver keys this hash with `BLAKE3(server_secret)`, which clients do not
hold, so only a holder of the secret can solve a challenge today. The key must become
public, or be removed, before third-party clients can use these endpoints.

The difficulty for a challenge is computed per rate key:

```
p      = min(penalty_points(key), max_points)
bits   = base_difficulty + step_bits × p
m_rep  = reputation multiplier       (1.0 without a default ruleset or a score)
m_auto = 1 + p^power_law_alpha × pile_on_factor, clamped to [1, max_multiplier]
                                     (1.0 when automation is disabled)
d      = round(bits × m_rep × m_auto)
d      = max(d, floor)               (anonymous_min for an alias with no subject,
                                      otherwise min_difficulty)
d      = clamp(d, min_difficulty, max_difficulty)
```

A nameserver that adopts a ruleset MUST scale difficulty by the subject's reputation under
that ruleset, within the ruleset's `pow_policy` bounds, so that reputation lowers or raises
the price of acting but never becomes a gate.

`m_rep` is the ruleset `multiplier` times `1 − 0.25 × score` (score clamped to [−1, 1]),
pulled towards 1.0 when the score's weight is below 1, and clamped to [0.1, 8]. With a
ruleset multiplier of 1.0, a good score lowers difficulty by at most a quarter and a bad
one raises it by at most a quarter.

**Status:** partial. Only `pow_policy.multiplier` is applied; `min_bits` and `max_bits` are
not.

With the default parameters and no reputation score, a single penalty point raises `d` to
`max_difficulty` (see [Penalties](#penalties)).

### Rate limiting

Challenge issuance is limited per client IP and per rate key, in fixed one-minute windows.

| Limit | Default | Key |
| --- | --- | --- |
| Per IP | 120 per minute (`JIG_NS_RATE_PER_IP_PER_MIN`) | `ip:<address>` |
| Per key | 60 per minute (`JIG_NS_RATE_PER_MIN`) | `claim:subject:<handle>` or `alias:scope:<scope>:subject:<subject>` |

The client IP is the socket address, or the first entry of `JIG_NS_PROXY_IP_HEADER`
(default `x-forwarded-for`) when `JIG_NS_TRUST_PROXY` is set. A refused request gets
HTTP 429 and adds one penalty point to the key that refused it, so retrying raises the next
difficulty.

**Status:** `global_per_min` is published in policy documents but not enforced.

### Penalties

A nameserver keeps penalty points per rate key. One point is added for each of:

- an invalid proof-of-work on `/v1/claim` or `/v1/alias`;
- a refused challenge request (per-key or per-IP rate limit).

Points raise difficulty by `step_bits` each, at most `max_points` of them count, and the
result is clamped to `[min_difficulty, max_difficulty]` (formula above).

**Decay is linear.** On each read, one point is removed for every full `decay_secs` since
the key last changed, floored at 0. A new penalty resets that clock, so a key that keeps
misbehaving does not decay.

| Parameter | Default | Setting |
| --- | --- | --- |
| `base_difficulty` | 18 | `JIG_NS_POW_DIFFICULTY` |
| `min_difficulty` / `max_difficulty` | 8 / 28 | `JIG_NS_POW_MIN` / `JIG_NS_POW_MAX` |
| `anonymous_min` | 12 | `JIG_NS_ANON_MIN_POW` |
| `step_bits` | 2 per point | `JIG_NS_PENALTY_STEP_BITS` |
| `max_points` | 64 | `[penalties] max_points` |
| `decay_secs` | 300 | `JIG_NS_PENALTY_DECAY` |
| `power_law_alpha` / `pile_on_factor` / `max_multiplier` | 1.4 / 0.5 / 8.0 | `JIG_NS_AUTOMATION_ALPHA` / `_PILE_ON` / `_MAX` |

A nameserver MUST raise difficulty monotonically with penalty points up to its maximum, and
MUST let points decay to zero when no new penalties arrive.

**Status:** points on `ip:` keys are recorded but do not affect difficulty, which is read
from the action key only. Penalties for misbehaving hosts (receipt anomalies: 2, 4 or 8
bits by severity) are a separate ledger at `GET /v1/hosts/{did}/penalties` and do not
decay. Known weaknesses the design must close are listed in the
[abuse economics](https://github.com/jig-protocol/jig/blob/main/docs/security/nameserver-abuse-economics.md#known-weaknesses-the-design-must-close).

### Policy and discovery documents

A nameserver publishes its policy at three paths:

- **`GET /.well-known/jig-ns`** (JSON): `version`, `ns_id` (BLAKE3 of the nameserver's
  public key, hex), `endpoints`, and `policy` with `pow` (`base`, `min`, `max`,
  `anonymous_min`), `rate_limit` (`per_key_per_min`, `per_ip_per_min`, `global_per_min`),
  `automation`, `allow_domains`, `deny_domains`, `cache_ttl_secs`, `reputation` and
  `public_key`.
- **`GET /.well-known/jig-ns/capabilities`** (plain text): `version`, optional `domain`,
  one `work:` line per useful-work type, `tribunal:`, `transparency:` and `federation:`
  (`enabled` or `disabled`), and optional `affordance:` lines.
- **`GET /v1/policy`** (JSON): `pow` (`base_difficulty`, `min_difficulty`,
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
treat gossip as claims by the sending peer, not as facts.

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

**Status:** partial. Servers keep no log. On the nameserver, the log's storage, a
hash-chain verifier and the read endpoints (`GET /v1/transparency/entries`, `/hashes`,
`/verify`) exist; the running service writes no entries and does not compute periodic chain
hashes.

## Useful work

*Partial.* An operator queues work (`POST /v1/work/enqueue`, admin), workers claim it
(`POST /v1/work/assign`) and submit results (`POST /v1/work/{id}/result`). Kinds:
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

**Status:** partial. Case records exist. `POST /v1/tribunal/cases` opens a case (`subject`,
`subject_id`, `ruleset`, `reason`, optional `reporter`, `severity`, `metadata`).
`POST /v1/tribunal/cases/{id}/decision` records an outcome (`sustain`, `modify`,
`overturn`, `dismiss` or `escalate`) with optional `penalty_delta` and `notes`. The anomaly
detector opens cases automatically for high and critical receipt anomalies. Panels,
signatures, appeals, application of `penalty_delta`, logging and propagation are not
implemented.

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
- Verify an alias attestation's signature before using it (servers) *(not yet
  implemented)*.
- Scope every reputation score to one ruleset; share it only within the ruleset group, and
  treat what peers send as claims *(partial)*.
- Report reputation changes for clients to the ruleset group's nameservers (servers) *(not
  yet implemented)*.
- Compute and enforce net reputation changes from every member server's reports, and
  enforce servers' good behaviour (nameservers) *(not yet implemented)*.
- Enforce proof-of-work on the clients a server serves (servers) *(not yet implemented)*.
- Require proof-of-work, solvable from public information, on every request that creates a
  binding (nameservers) *(partial)*.
- Scale proof-of-work by reputation under an adopted ruleset, within its bounds
  *(partial)*.
- Refuse used, expired or mismatched proof-of-work challenges.
- Raise difficulty monotonically with penalty points, clamped to the configured maximum,
  and let points decay to zero without new penalties.
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
