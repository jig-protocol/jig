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
- **Order under load.** Strangers waiting for the pool are served highest bid first, with
  bids counted only up to `max_effort`; between capped bids, arrival order decides.
- **No reuse.** Work is bound to the action, the alias, the nameserver, the subject and a
  single-use challenge (JEP-0008 rule 11). Work for one registration pays for no other.
- **No work for nothing.** A closed suffix, a short, reserved or taken name is refused at
  the challenge, before any work.

| Name | Effort | One server core | Headroom to `max_effort` (2^26) |
| --- | --- | --- | --- |
| 5 letters or more | 2^20 | about 0.2 s | 64× |
| 4 letters | 2^22 | about 0.8 s | 16× |
| 3 letters | 2^24 | about 3 s | 4× |
| 1 or 2 letters | refused (allowlist only) | — | — |
| renew, rotate | 1 | one digest | — |

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
them to the highest bidder, but a bid counts only up to `max_effort` (2^26, about 12 s on
one server core). Past that, arrival order decides, so compute buys priority only until an
honest client also bids the cap. An attacker who reaches the cap faster can still take
most of the tokens and leave honest newcomers with `503 REGISTRATION_BUSY`. The pool bounds
how fast names go, not who gets them.

## Length scaling

Short names are scarce, so they cost more (R1 decision 1):

- `effort × short_name_factor ^ (short_name_len − length)`: ×4 per letter under 5.
- 1 and 2 letters are reserved: `min_alias_len = 3` refuses them, and only a
  `registration_allow` entry can take one.
- The multiplier applies even when the controller is idle, because the floor `min_effort`
  is taken before it (JEP-0008 rule 18, amended).

At the defaults a 3-letter name costs 2^24, a quarter of `max_effort` (2^26, DJ's decision
for short-name headroom). The controller and penalties can raise it 4× before the cap, so
under heavy load a 3-letter name still costs more than a 5-letter one until both reach it.

## Penalties and decay

Penalties raise what one client is asked for its next registration. They key on:

- **the address** (`ip:`, IPv6 per /64), for work that does not verify. The work is checked
  before the signature, so the DID it names is not proven yet;
- **the pair** (alias, DID), for a signed attempt on a name another DID holds.

Each point doubles the effort, up to `max_effort`. So penalties have 64× of range for a
long name, 16× for a 4-letter one and 4× for a 3-letter one at the defaults. Points past
those that take `min_effort` to `max_effort` change no price and are not kept.

**Decay remembers repeat offenders.** One point decays per `penalty_decay_secs` (600 s). A
repeat while points remain adds a point and doubles the time each point takes to decay, up
to a day. A key whose points have all decayed starts over (JEP-0008 rule 27).

| Offences, each while points remained | Time for one point to decay |
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

A server's one-time admission work is the same puzzle (`admit`), off by default (D26,
JEP-0008 rule 33). A server that turns it on asks at least `min_effort` (default 2^20), and
its controller raises the effort when more unknown DIDs arrive per window than its target
(rule 17). It makes spreading a flood across rate-limit buckets cost something; it does not
stop a Sybil. Capacity pools (`[auth.pools]`, JEP-0008 rules 21–23) are what bounds
strangers there: strangers share at most 20 % of local writes and invited subjects 10 %, so
however many identities a flood brings, members keep the rest.

## Known weaknesses the design must close

Each is a gap, not an accepted property:

- **Linear Sybil cost.** Identities are free and the pool prices names, not identities.
  Standing (reputation under a ruleset) must cost more per identity than hashing, without
  linking identities (AB-05, JEP-0009).
- **Compute still buys speed in the pool.** Bids count only up to `max_effort`, but a GPU or
  a botnet reaches the cap in milliseconds where a phone takes minutes, and arrives first.
  Algorithm agility (Equi-X, rule 8) narrows the GPU gap only.
- **State is per process and in memory.** A restart refills every pool, drops penalties and
  resets the controller; several processes share nothing.
- **A taken name charges the pair only.** `ALIAS_TAKEN` comes after valid work and a valid
  signature, so it charges the (alias, DID) pair and not the address (DJ's decision): a
  NAT's other users pay nothing for it, and a careful attacker who never sends bad work
  pays no address penalty at all.
- **No squatting remedy.** Signed, logged operator removal (R1 decision 5) is not built, and
  no tribunal can rule on a name.
- **Server admission is off by default** (D26). It adapts to load once turned on, and turns
  on by default only with R2's earned standing (JEP-0008 rule 33).
- **No tribunals, transparency log or reporting from encrypted channels.**

## Open questions

- Which admission input closes linear Sybil cost: cross-registration within a ruleset
  group, soul validation, invites (JEP-0009), or something else.
- Whether arrival order between capped bids should give way to something compute cannot
  buy, such as standing, so a GPU's speed stops deciding who gets the pool.
- Whether short names need their own ceiling, so length scaling keeps working under load.
- What `strangers_per_hour` and `burst` should be after `@jig`'s first week (R1 decision 2).
- Whether R1's measurements justify a second algorithm (rule 8).
- How victim-key delegation works for each encryption suite, and what a tribunal may accept
  as effective proof.
