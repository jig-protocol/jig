# Nameserver abuse economics

Why the nameserver prices registration the way it does, what an attacker pays, and where
the model is still thin. This is reasoning, not specification.

- The rules: [JEP-0008](../../repos/jig-spec/jep/jep-0008-proof-of-work.md), and the spec's
  [Nameserver mechanics](../../repos/jig-spec/src/identity-and-reputation.md#nameserver-mechanics).
- The threats: [AB-01, AB-02 and AB-05](../../repos/jig-spec/src/threat-register.md).
- What an operator does: the [nameserver abuse runbook](../operations/nameserver-abuse-runbook.md).
- The design record: lane R's
  [framing doc](../superpowers/specs/2026-10-18-reputation-pow-tribunals-framing.md),
  sections 4–5.

Numbers are the reference nameserver's defaults unless stated. Solve times use the
5.5 million digests a second that `jig-core`'s `benches/pow.rs` measured on one server
core. GPU figures are estimates, not measurements.

This replaces the analysis of the removed prototype (#154), which priced requests with
penalty bits on a keyed puzzle that only the nameserver could solve.

## What the model is for

- Make taking names in bulk slow, whatever the attacker spends.
- Keep an ordinary registration cheap: well under a second on a laptop.
- Never price an identity. Fresh keys stay free, because `--anon` depends on them.
- Let every nameserver set its own prices, per suffix, with no central ledger.

## What proof-of-work buys

- **A price that is cheap to check.** Solving costs the client `E` digests on average.
  Checking costs the nameserver one, before any signature or store read.
- **Order under load.** Strangers waiting for the pool are served highest bid first.
- **No reuse.** Work is bound to the action, the alias, the nameserver, the subject and a
  single-use challenge (JEP-0008 rule 11). Work for one registration pays for no other.
- **No work for nothing.** A closed suffix, a short, reserved or taken name is refused at
  the challenge, before any work.

| Name | Effort | One server core |
| --- | --- | --- |
| 5 letters or more | 2^20 | about 0.2 s |
| 4 letters | 2^22 | about 0.8 s |
| 3 letters | 2^24 | about 3 s |
| 1 or 2 letters | refused (allowlist only) | — |
| renew, rotate | 1 | one digest |

## What proof-of-work does not buy

- **Protection from a GPU.** 2^20 digests take a GPU about a millisecond (estimate). A
  thousand 3-letter names are seconds of GPU time.
- **Protection from a botnet.** Its compute is free to the attacker.
- **An identity price.** DIDs cost nothing to mint, and one name per DID per suffix only
  means the attacker mints one DID per name.

Any effort a phone tolerates is cheap for these attackers. So effort is a price on
capacity and an ordering, never the bound.

## The pool is the real bound

Each suffix caps stranger registrations with a token bucket: `strangers_per_hour = 60`,
`burst = 10`. Compute cannot raise the cap. Allowlisted registrations, renew and rotate do
not use it.

| Period | Most stranger names, whatever the spend |
| --- | --- |
| first minute | 11 (the burst, plus the refill) |
| one day | about 1,450 |
| one week | about 10,000 |

- There are 38^3 = 54,872 three-letter aliases (`[a-z0-9_-]`), less the reserved ones.
  Taking all of them at the cap takes about 38 days, if the attacker wins every token.
- The **controller** doubles the effort after a five-minute window in which the queue was
  full, and halves it after one in which nothing queued, between `min_effort` and
  `max_effort`. It makes a flood dearer, but it is a price, not a bound.
- The **per-address limits** (30 requests and 60 challenges a minute) bound one host. A
  botnet or a large address pool walks around them.

What the pool does not do: decide who gets the tokens. Under contention the queue sells
them to the highest bidder, so an attacker with more compute can take most of the cap and
leave honest newcomers with `503 REGISTRATION_BUSY`. The pool bounds how fast names go,
not who gets them.

## Length scaling

Short names are scarce, so they cost more (R1 decision 1):

- `effort × short_name_factor ^ (short_name_len − length)`: ×4 per letter under 5.
- 1 and 2 letters are reserved: `min_alias_len = 3` refuses them, and only a
  `registration_allow` entry can take one.
- The multiplier applies even when the controller is idle, because the floor `min_effort`
  is taken before it (JEP-0008 rule 18, amended).

At the defaults a 3-letter name already costs `max_effort` (2^24). The controller and
penalties cannot raise it further, so a 3-letter name and a 5-letter one cost the same
under heavy load.

## Penalties and decay

Penalties raise what one client is asked for its next registration. They key on:

- **the address** (`ip:`, IPv6 per /64), for work that does not verify. The work is checked
  before the signature, so the DID it names is not proven yet;
- **the pair** (alias, DID), for a signed attempt on a name another DID holds.

Each point doubles the effort, up to `max_effort`. So penalties have 16× of range for a
long name, 4× for a 4-letter one and none for a 3-letter one at the defaults.

**Decay remembers repeat offenders.** A penalty lives `penalty_decay_secs` (600 s). A
repeat before it lapses adds a point and doubles its life, up to a day. When the life ends,
all its points lapse at once.

| Offences, each before the last lapsed | Life of the penalty |
| --- | --- |
| 1 | 10 minutes |
| 2 | 20 minutes |
| 4 | 80 minutes |
| 8 | about 21 hours |
| 9 or more | 1 day (the cap) |

Penalties price mistakes and misbehaving addresses. They do not touch a careful attacker,
who never sends bad work, nor a fresh DID, which carries no pair points.

## Griefing protections

A third party should not be able to raise a victim's price or cost a holder their name.

- **Unproven work charges the sender's address only**, never the DID it names (JEP-0008
  rule 26, amended).
- **Pair penalties** land on the DID that signed, for that alias only. Other DIDs asking
  for the same alias pay nothing more.
- **The per-DID rate limit** counts only requests that succeed, which need that DID's
  signature.
- **Challenges are bound** at issue to one action, DID and name. A request for anything
  else is refused and leaves the challenge for its rightful use.
- **Refusals do not burn challenges.** Bad work, a bad signature, a busy pool: none
  consumes the challenge.
- **No DID-to-name oracle.** The unauthenticated challenge never says which name a DID
  holds; `DID_HOLDS_NAME` comes only after the DID has signed.
- **Holders keep their names under a flood.** Renew and rotate skip the pool, pay one
  digest and carry no penalties, and a tenth of the challenge map is kept for them.
- **Signed effort.** The offer is signed, and the proof is checked against the effort
  promised, so a forged or mid-solve rise cannot refuse an honest client.

What still works for a griefer:

- **Shared addresses.** Behind one NAT, carrier-grade NAT or proxy (without
  `trust_proxy`), one sender's bad work raises the price for everyone on that address.
- **Pool starvation**, as above.
- **Challenge exhaustion.** 90,000 register challenges fill the map. At 60 a minute per
  address and a 60 s lifetime, that takes about 1,500 addresses, and then new register
  challenges get `503 BUSY` until they expire. Renew and rotate keep their tenth.

## Servers

A server's one-time admission work is the same puzzle (`admit`), at a fixed `2^pow_bits`
(default 2^20), and off by default. It makes spreading a flood across rate-limit buckets
cost something; it does not stop a Sybil. Capacity pools at servers (member, invited and
stranger shares, JEP-0008 rules 21–23) are what bounds strangers there, and are not on
`main` yet. <!-- R1 task 5a: confirm against the merged [auth.pools] PR -->

## Known weaknesses the design must close

Each is a gap, not an accepted property:

- **Linear Sybil cost.** Identities are free and the pool prices names, not identities.
  Standing (reputation under a ruleset) must cost more per identity than hashing, without
  linking identities (AB-05, JEP-0009).
- **Compute buys the pool.** The queue serves the highest bid, and bids are not capped at
  `max_effort`, so a GPU or a botnet outbids every phone. Algorithm agility (Equi-X, rule 8)
  narrows the GPU gap only.
- **No headroom for short names.** At the defaults a 3-letter name is already at
  `max_effort`.
- **No metrics.** The nameserver counts admitted and refused registrations, the suggested
  effort and the queue, but exports none of it. An operator reads the effort by asking for
  a challenge.
- **State is per process and in memory.** A restart refills every pool, drops penalties and
  resets the controller; several processes share nothing.
- **Penalties differ from JEP-0008 in shape.** Points lapse all at once, not one per
  `decay_secs` (rule 27); a signed refusal charges the pair but not the address (rule 26).
- **No squatting remedy.** Signed, logged operator removal (R1 decision 5) is not built, and
  no tribunal can rule on a name.
- **Server admission is fixed and off by default**, not adaptive (JEP-0008 rule 33).
- **No tribunals, transparency log or reporting from encrypted channels.**

## Open questions

- Which admission input closes linear Sybil cost: cross-registration within a ruleset
  group, soul validation, invites (JEP-0009), or something else.
- Whether the queue should cap a bid at `max_effort`, or fall back to arrival order under
  load, so compute buys less of the pool.
- Whether short names need their own ceiling, so length scaling keeps working under load.
- What `strangers_per_hour` and `burst` should be after `@jig`'s first week (R1 decision 2).
- Whether R1's measurements justify a second algorithm (rule 8).
- How victim-key delegation works for each encryption suite, and what a tribunal may accept
  as effective proof.
