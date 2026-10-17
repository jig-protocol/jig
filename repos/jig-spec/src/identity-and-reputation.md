# Identity and Reputation

> **Status.** Implemented: `did:jig` identities, nameserver-attested aliases, TOFU and
> nameserver resolution in servers, proof-of-work with penalties on the nameserver's claim
> and alias challenges, per-ruleset reputation scores, and tribunal case records.
> Proposed: security zones as configuration, cross-registration between nameservers,
> anchor nameservers, soul validation, useful-work rewards, and tribunal panels. Each
> section says which applies. Reputation is not a protocol gate until
> [JEP-0003](https://github.com/jig-protocol/jig/blob/main/repos/jig-spec/jep/jep-0003-server-discovery.md)
> defines it ([OP-10](threat-register.md)). Rationale and cost model:
> [`docs/security/nameserver-abuse-economics.md`](https://github.com/jig-protocol/jig/blob/main/docs/security/nameserver-abuse-economics.md).

**Audience:** protocol implementers, nameserver and server operators. End users need only
[Identity](#identity) and [Security zones](#security-zones-server-policy).

## Overview

- An **identity** is a `did:jig`: a self-certifying Ed25519 key the user mints locally.
- An **alias** (`alice@example.com`) is a nameserver's signed claim that a name maps to a
  DID. It is never the sender.
- **Reputation** is a number a nameserver or server keeps about a user, a server or a
  nameserver. Behaviour raises or lowers it. It is local, and it has no tiers.
- A **security zone** is a policy of a server or a nameserver federation. It is not a
  property of a user.

## Identity

### DIDs

A `did:jig` is derived from an Ed25519 public key and proves itself: whoever signs with the
key is the DID. No authority issues or revokes one.

- A block's sender MUST be a DID. Aliases are display and lookup aids only.
- A sender has one canonical DID per identity. A user MAY hold different identities, for
  example in different zones.
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

**Status:** this path has no proof-of-work and no rate limit. Proof-of-work and penalties
apply to the older claim and alias endpoints described under
[Nameserver mechanics](#nameserver-mechanics).

### Resolution by servers

A server resolves the alias on an incoming block in one of two modes
(`[identity] mode`):

| Mode | Behaviour |
| --- | --- |
| `tofu` (default) | The first DID seen for a nickname is locked; a later block with a different DID is refused. |
| `nameserver` | The server queries each URL in `trusted_nameservers` in order and refuses the block if the alias resolves to a different DID. Results are cached for `cache_ttl_seconds` (default 300). |

A server MAY trust more than one nameserver. **Status:** the server reads the `did` field
from the resolve response and does not yet verify the attestation signature.

### Anonymous identities

A server that permits it MAY admit an **anonymous** (`--anon`) identity: no DID is presented
at login, and any reputation lasts only for the session. Usually only
[null-sec](#security-zones-server-policy) servers admit them.

- The protocol MUST NOT define any mechanism that links an anonymous identity to a DID.
  There is no warrant, escrow or tribunal path that unmasks one.
- A nameserver or server MUST NOT require a DID, or a proof derived from a DID key, to
  admit an anonymous identity.
- Clients SHOULD keep anonymous keypairs apart from DID keypairs: separate storage, no
  derivation from a DID seed, no reuse across identities, and no shared device
  identifiers in requests made under different identities.
- Clients SHOULD show which kind of identity is active (for example `~` for anonymous,
  `@` for an alias).

The nameserver mints anonymous aliases (`anon-` plus 12 hex characters) through
`POST /v1/alias`. An alias minted **with** a `subject` is a pseudonym, not an anonymous
identity: the nameserver stores the link to the subject. It MUST NOT be presented to users
as anonymous.

**Status:** servers and the CLI have no `--anon` login yet. Anonymous aliases exist only on
the nameserver.

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

Reputation is a score for a **user**, a **server** or a **nameserver**, per ruleset.
Behaviours raise or lower it. It is not a tier, and nothing about it is a stage gate a
subject "transitions" through.

Each nameserver computes its own scores. A score is the weighted mean of the unexpired
observations recorded for that subject and ruleset (at most 1024 are read). An observation
carries `score`, `weight` (default 1.0), `observer`, optional `evidence` and optional
`expires_at`.

| Endpoint | Purpose |
| --- | --- |
| `POST /v1/reputation/observe` | Record an observation and return the new aggregate |
| `GET /v1/reputation/{subject}/{id}` | Aggregates for every ruleset the subject has |
| `GET /v1/reputation/{subject}/{id}/observations` | Raw observations (`ruleset`, `limit` ≤ 1000) |

`{subject}` is `user`, `server` or `nameserver`.

### Rulesets and translation contracts

A **ruleset** is a named, versioned scoring policy: `key`, `version`, `authority`,
`weight`, a PoW policy (`min_bits`, `max_bits`, `multiplier`) and a tribunal policy
(`quorum`, `auto_escalate_score`, `evidence_window_secs`). Nameservers that use the same
ruleset key agree on what its scores mean.

Nameservers with different rulesets MAY map scores between them with a **translation
contract**: `from`, `to`, `weight`, and a `linear` (`slope`, `intercept`, optional clamps)
or `table` transform. A contract is a data contract between the two parties. Neither side
is bound by the other's ruleset without one.

**Status:** rulesets and contracts are parsed and published in `/.well-known/jig-ns`.
Only `pow_policy.multiplier` is applied (see [Proof-of-work](#proof-of-work)). Contracts
are not yet applied to incoming scores.

### Reputation is not a protocol gate

Until JEP-0003 defines reputation:

- Reputation is not a protocol security input: no protocol step requires or refuses
  anything because of a score, and handshake reputation fields are informational
  ([OP-10](threat-register.md)).
- A nameserver MAY use its own scores to scale proof-of-work, and a server MAY use its own
  scores in its admission policy. Both are local policy, not protocol.

### Proposed: soul validation

*Not implemented.* Real humans vouch that another identity is a real human by staking
their own reputation on it. While the vouch stands, the vouchee's reputation gains are
boosted. The vouchee's reputation losses also propagate to every voucher, the vouchee's
**soulnet**. Open questions for a JEP: the boost and propagation factors, how far losses
propagate, how a voucher withdraws, and how to resist rings that vouch for each other.

## Security zones (server policy)

A zone is a property of a **server** or a **nameserver federation**. It states what user
behaviour and how much anonymity the server permits, and how enforcement spreads. Any user
MAY try to join any server. A user MAY hold different identities in different zones, and
the protocol MUST NOT link them.

| Zone | Nameservers | Identities | Proof-of-work | Enforcement |
| --- | --- | --- | --- | --- |
| **High-sec** | Several, coordinated: they cross-register identities | DIDs registered across the federation | Scales with reputation | Penalties and tribunal outcomes propagate across linked servers |
| **Low-sec** | A local nameserver | DIDs, optionally aliased | Local defaults | Local penalties; few or no tribunals |
| **Null-sec** | Optional | `--anon` allowed; identities may be unregistered and unprotected | Highest floor | Minimal; reputation is transient |

High-sec servers are more likely to require a higher local reputation to join. Null-sec
servers are usually the only ones that admit `--anon` identities.

**Status:** zones are not yet a configuration setting. The nameserver applies the anonymous
floor (`JIG_NS_ANON_MIN_POW`) to alias challenges without a subject, unless
`JIG_NS_ANON_ENABLED` is false, and treats every other challenge as low-sec. Turning the
setting off removes the floor; it does not stop anonymous aliases being minted.

### Cross-registration (high-sec)

*Proposed.* Nameservers in a high-sec federation share identity registries: their
alias-to-DID mappings, plus penalties and tribunal outcomes. Sharing registries is what
makes a federation high-sec: a user is cross-validated across handles and servers, and a
reputation change on one linked nameserver is applied by the others under their
translation contracts.

A nameserver MAY resolve another nameserver's aliases when that nameserver agrees to
federate. **Status:** the nameserver resolves remote handles through `_jig-ns._tcp` SRV
discovery, gated by `JIG_NS_ALLOW_DOMAINS` and `JIG_NS_DENY_DOMAINS` and cached for
`JIG_NS_CACHE_TTL` seconds. It does not ask for agreement, and it does not verify remote
records. Reputation and tribunal gossip is received and stored, not applied.

### Anchor nameservers

*Proposed.* A nameserver MAY **anchor** a high-sec zone, so members do not bootstrap from
scratch. An anchor publishes initial coordination:

- default proof-of-work parameters,
- address and handle conventions,
- tribunal coordination.

Rules:

- Joining an anchored zone is opt-in.
- An anchor's defaults are advisory. A member MAY override any of them and MAY leave.
- No nameserver, anchor included, holds a veto over another nameserver, server or zone, or
  can control the network.
- Anyone MAY run zones at any level with their own anchors, or none, or connect to servers
  without joining a zone. A zone MAY have more than one anchor.

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

A solution is valid when `BLAKE3(challenge_id|action|subject|scope|nonce)` has at least
`difficulty` leading zero bits. Expected work is about 2^`difficulty` hashes.

**Status:** the reference nameserver keys this hash with `BLAKE3(server_secret)`, which
clients do not hold, so only a holder of the secret can solve a challenge today. The
key must become public, or be removed, before third-party clients can use these
endpoints.

The difficulty for a challenge is computed per rate key:

```
p      = min(penalty_points(key), max_points)
bits   = base_difficulty + step_bits × p
m_rep  = reputation multiplier       (1.0 without a default ruleset or a score)
m_auto = 1 + p^power_law_alpha × pile_on_factor, clamped to [1, max_multiplier]
                                     (1.0 when automation is disabled)
d      = round(bits × m_rep × m_auto)
d      = max(d, zone_floor)          (anonymous_min for an alias with no subject,
                                      otherwise min_difficulty)
d      = clamp(d, min_difficulty, max_difficulty)
```

`m_rep` is the ruleset `multiplier` times `1 − 0.25 × score` (score clamped to [−1, 1]),
pulled towards 1.0 when the score's weight is below 1, and clamped to [0.1, 8]. With a
ruleset multiplier of 1.0, a good score lowers difficulty by at most a quarter and a bad
one raises it by at most a quarter.

With the default parameters and no reputation score, a single penalty point raises `d` to
`max_difficulty` (see
[Penalties](#penalties)).

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
from the action key only. A tribunal decision's `penalty_delta` is stored, not applied.
Penalties for misbehaving hosts (receipt anomalies: 2, 4 or 8 bits by severity) are a
separate ledger at `GET /v1/hosts/{did}/penalties` and do not decay.

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
admits every domain not denied. With `[federation] enabled`, peers exchange policy hashes (`GET /v1/federation/policy`) and gossip (`POST /v1/federation/gossip`). A
nameserver MUST treat gossip as claims by the sending peer, not as facts.

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

*Implemented:* case records. `POST /v1/tribunal/cases` opens a case (`subject`,
`subject_id`, `ruleset`, `reason`, optional `reporter`, `severity`, `metadata`).
`POST /v1/tribunal/cases/{id}/decision` records an outcome (`sustain`, `modify`,
`overturn`, `dismiss` or `escalate`) with optional `penalty_delta` and `notes`. The anomaly
detector opens cases automatically for high and critical receipt anomalies.

*Proposed:* tribunals are per zone. In high-sec, panels of members from several linked
servers decide cases, decisions are signed and logged, and outcomes propagate across the
federation. In low-sec, tribunals are rare and local. Null-sec has none. A tribunal never
has a path to unmask an anonymous identity ([Anonymous identities](#anonymous-identities)).
Panel selection, evidence handling and appeals need a JEP before any of this is normative.

## Normative requirements summary

**MUST:**

- Use a DID as the sender of every block; treat aliases as nameserver claims.
- Refuse used, expired or mismatched proof-of-work challenges.
- Raise difficulty monotonically with penalty points, clamped to the configured maximum,
  and let points decay to zero without new penalties.
- Publish policy at `/.well-known/jig-ns`, `/.well-known/jig-ns/capabilities` and
  `/v1/policy`.
- Treat federated gossip as claims by the sending peer.

**MUST NOT:**

- Define or implement any link between an anonymous identity and a DID.
- Present a pseudonymous alias (one minted with a subject) as anonymous.
- Treat reputation as a protocol gate before JEP-0003.

**SHOULD:**

- Pin the DID first seen for a name and surface changes (clients).
- Keep anonymous keypairs separate from DID keypairs (clients).
- Advertise nameservers with `_jig-ns._tcp` SRV records.

**MAY:**

- Trust more than one nameserver (servers).
- Scale proof-of-work by local reputation (nameservers); use local reputation in admission
  policy (servers).
- Anchor a high-sec zone, join one, override its defaults, or run without one.
- Map reputation between rulesets with translation contracts.

---

**Related chapters:**

- **[Zero-Trust Model](zero-trust.md)**: fail-closed semantics and adversarial assumptions.
- **[Crypto Primitives](crypto.md)**: Ed25519 for DIDs, BLAKE3 for proof-of-work.
- **[Federation](federation.md)**: server-to-server trust.
- **[Threat Register](threat-register.md)**: OP-08 (key substitution) and OP-10
  (reputation gaming).
