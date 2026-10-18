# Nameserver abuse economics

Why the nameserver prices abuse the way it does, what an attacker pays, and where the model
is still thin. This is reasoning, not specification. It separates what the design must do
from what the reference nameserver does today. Where today's behaviour falls short, that is
a gap the design must close, not a property to accept. The rules are in the spec's
[Identity and Reputation](../../repos/jig-spec/src/identity-and-reputation.md) chapter, and
reputation gaming is threat [OP-10](../../repos/jig-spec/src/threat-register.md). Operator
responses are in the
[nameserver abuse runbook](../operations/nameserver-abuse-runbook.md).

Numbers below are the reference nameserver's defaults (`repos/jig-nameserver/src/config.rs`)
unless stated.

> **The mechanisms priced here are no longer served.** Proof-of-work challenges, penalties,
> the per-IP and per-key challenge limits, the anonymous floor, reputation observations,
> the admin reset endpoints and federation gossip were the nameserver's legacy prototype,
> whose routes were removed in #154. Today the nameserver serves only the alias routes,
> which have no proof-of-work and no rate limit. The analysis stays as input to the
> redesign; read "today" below as "in the removed prototype".

## What the model is for

- Make abuse cost more than ordinary use, without identifying anyone.
- Keep the cost of ordinary use close to the floor.
- Let every nameserver set its own prices. Nothing here depends on a central registry or
  a global ledger: each nameserver keeps its own penalties and scores, and shares them only
  within the ruleset group it chose to join.

The model prices abuse in computation and time. Nothing in it lets an identity buy a lower
difficulty.

## Why proof-of-work

A nameserver cannot tell a person from a script, and the protocol does not ask it to. What
it can do is make each request cost the requester something it does not cost the
nameserver. Proof-of-work does that: issuing and checking a challenge is one hash for the
nameserver, while solving it takes about 2^d hashes for the client.

| Difficulty `d` (bits) | Expected hashes | Relative to the base (18) |
| --- | --- | --- |
| 8 (minimum) | 256 | 1/1024 |
| 12 (anonymous floor) | 4,096 | 1/64 |
| 18 (base) | 262,144 | 1 |
| 24 | 16,777,216 | 64 |
| 28 (maximum) | 268,435,456 | 1024 |

Each added bit doubles the work. A spread of 20 bits between minimum and maximum gives the
nameserver a price range of about a million to one, which is what makes penalties bite.

## Why difficulty scales with reputation, but only a little

Reputation is one number per subject and ruleset, built from observations. It is shared
within the ruleset group that adopted the ruleset, never across a whole security level:
two high-sec groups keep separate numbers for the same DID. A nameserver with
a default ruleset multiplies difficulty by `1 − 0.25 × score`, so a subject with the best
possible score pays three quarters of the bits and one with the worst pays five quarters.

The effect is deliberately small:

- **Reputation is not yet a security input** (OP-10). Anything an attacker can mint, such as
  observations from accounts it controls, must not unlock large discounts. A quarter of the
  bits is a real reward for good standing, and a bounded loss if the score is gamed.
- **New identities have no score**, so the multiplier is 1.0. Reputation cannot make
  Sybils cheaper. It can only make established identities cheaper.
- **Penalties do the heavy lifting.** They act on observed misbehaviour by a specific key,
  which an attacker cannot fake on someone else's behalf as easily as a score (but see
  [Griefing](#griefing-a-target-key)).

A larger reputation effect needs inputs an attacker cannot cheaply mint. Cross-registration
within a ruleset group (required for high-sec, not yet built) and soul validation
(proposed) are candidates. JEP-0003 decides how far reputation may move the price.

## Cost of a Sybil attack

A Sybil attacker wants many handles or aliases. Every new subject is a new rate key with no
penalties, so each costs one base-difficulty solution:

```
cost(N handles) ≈ N × 2^base_difficulty hashes
```

The cost is **linear in N**. That is a known weakness, and the spec requires the nameserver
design to close it in full: a ruleset group must not rest Sybil resistance on proof-of-work
alone. Earlier drafts claimed exponential cost for Sybils through "triangulation". Nothing
produced that, and the claim is gone; the obligation to do better than linear stays.

What limits a Sybil attacker today:

- **Base difficulty.** Doubling the work per handle costs one bit.
- **The per-IP limit** (120 challenges per minute per address). It slows a single host. A
  botnet or a large address pool walks around it, and `global_per_min` is published but not
  enforced.
- **The anonymous floor** for aliases minted without a subject. Its default (12 bits) is
  below the base, so it changes nothing until an operator raises it above 18, as
  anonymous-heavy nameservers should.

What does not limit one:

- Penalties, which only accrue to keys that misbehave. A careful Sybil attacker never
  misbehaves on any one key.
- Reputation, as above.
- The alias registration path the CLI uses (`POST /v1/register`). The spec requires
  proof-of-work and rate limits there; the code has neither yet. Until it does, Sybil
  resistance for aliases rests on the reverse proxy in front of the nameserver.

Summary: proof-of-work turns Sybils from free into linearly priced, and linear is not
enough. Fresh keys must stay cheap, because `--anon` depends on them. What must stop being
linearly cheap is standing: aliases, and reputation under a ruleset. That needs an
admission input that costs an attacker more per identity than hashing and does not link
identities. Designing it is part of the nameserver work, not an optional follow-up
(OP-10, JEP-0003).

## Cost of spam against one key

Spam aims many requests at one subject or scope, for example repeated claims on a handle
or a flood of aliases in one scope. Here the per-key machinery works as intended.

1. **The per-key limit** (60 challenges per minute) caps how fast challenges can be
   fetched for that key, so the attacker cannot pre-fetch cheaply.
2. **Every refusal is a penalty.** A rate-limit refusal adds a point, and so does an invalid
   solution. Hammering the limit raises the price of the next challenge.
3. **Penalties raise difficulty.** Each point adds `step_bits` (2), and the automation
   multiplier `1 + p^1.4 × 0.5` (capped at 8) amplifies the total. With the defaults, one
   point takes the key from 18 bits to the 28-bit maximum: about a thousand times the work.
4. **Points stop counting at 64**, but they are stored without limit, so a long flood keeps
   the key at the maximum for longer.

In effect, the defaults are binary: a key pays the base until its first offence, then the
maximum until its points have decayed. An operator who wants a graded response lowers
`pile_on_factor` or disables automation. With automation off, each point is a flat 2 bits,
so the maximum arrives at 5 points.

## Decay

Penalties decay linearly: one point per `decay_secs` (300 s) of quiet. Any new penalty
resets the clock.

| Points | Time to return to the base, if quiet |
| --- | --- |
| 1 | 5 minutes |
| 12 | 1 hour |
| 64 (the counted maximum) | about 5 hours 20 minutes |
| 1,000 (a long flood) | about 3 days 11 hours |

Two properties follow:

- **Forgiveness.** A key that stops misbehaving returns to the base price with no operator
  action, so a false positive heals itself.
- **No decay under fire.** An attacker who keeps misbehaving keeps resetting the clock, so
  points only fall once the abuse stops.

Linear decay is simple and predictable. Its weakness is that a chronic abuser who stops
for a few hours is fully forgiven. The design must close that with decay that remembers
repeat offenders. Until then, an operator approximates it by raising `decay_secs` for the
whole nameserver, which also slows forgiveness for false positives.

## Griefing a target key

Penalties key on the target (`claim:subject:<handle>`, `alias:scope:<scope>:subject:<…>`),
not on the requester. That is deliberate: spreading a flood across many addresses does not
dilute the price, because every request lands on the same key.

The cost is that a third party can raise a victim's price. Anyone can request challenges
for `claim:subject:victim@example.com` past the per-key limit and push the key to the
maximum. The victim then pays 28 bits for a legitimate claim until the points decay.

This is a known weakness the design must close. Today's mitigations are operational:
reset the key (`POST /v1/admin/penalties`), and raise the per-key limit if a key is under
sustained griefing. A structural fix keys penalties on the pair (target, requester), which
needs signed challenge requests.

Points on `ip:` keys are recorded when the per-IP limit refuses a request, but difficulty is
read from the action key only, so an abusive address is throttled, not priced.

## Federation

Each nameserver keeps its own ledgers. Nothing is shared by default, and nothing is shared
globally.

- **Resolution.** A nameserver resolves remote handles through `_jig-ns._tcp` SRV records,
  gated by its allow and deny lists, and caches positive answers for `JIG_NS_CACHE_TTL`
  (300 s). The cache bounds the load a hostile peer can cause. It also means a poisoned
  answer lives for one TTL.
- **Gossip.** Peers exchange policy hashes, reputation summaries and tribunal decisions.
  Within a ruleset group, members must apply what they receive under the group's ruleset,
  as claims by the sender, never as facts. Across groups, a summary counts only through a
  translation contract both sides agreed to. Today the receiver stores summaries and
  decisions without applying them.
- **High-sec ruleset groups** must cross-register identities and propagate penalties and
  tribunal outcomes among their members. That raises the price of abuse across the group,
  because a key penalised on one member is penalised on all. Propagation stops at the edge
  of the group: it never spreads across a security level, there is no global blocklist,
  and no nameserver's decisions bind anyone outside its group. Not yet built.

## Tribunals, per ruleset group (required, not yet built)

Automatic penalties handle volume. They do not handle judgement: harassment, coordinated
campaigns, appeals against a penalty, or a federated instance that lies. Tribunals do that,
and the spec makes them an obligation of the nameserver design, not an experiment.

What exists is the record-keeping. A nameserver stores cases and decisions, and the anomaly
detector opens cases for high and critical receipt anomalies. A decision's `penalty_delta`
is stored, not applied, and decisions are not signed or logged.

What the design must provide:

- **Tribunals belong to ruleset groups.** A high-sec group must have one: panels draw on
  members of several linked servers, decisions are signed and written to the transparency
  log, and outcomes propagate across the group under its ruleset. In low-sec they are rare
  and local. Null-sec need not have one. Other groups may recognise a decision or ignore it.
- **Inputs** are what the nameserver already records: penalty history per key, rate data,
  reputation observations, anomaly records, and evidence block CIDs supplied by the
  reporter. Content stays with the parties. A tribunal sees what they choose to show it.
- **Reports from encrypted channels.** Much abuse will happen in encrypted channels that no
  server can read. The spec requires a reporting path anyway: a recipient gives the
  tribunal effective proof, scoped to the reported messages, that the accused's key sent
  them (victim-key delegation). It must not need escrow, server-held keys or content
  scanning, and it must work for every suite a group admits, MLS by default. The mechanism
  is not designed yet. Without it, tribunals cannot judge much of the abuse they exist for.
- **Outputs** are adjustments a nameserver already understands: penalty changes, reputation
  observations, and allow or deny entries for federated peers.
- **Transparency.** Every decision, and every enforcement change it causes, goes into the
  nameserver's hash-chained transparency log, with evidence cited by CID and personal data
  redacted. The log's storage and read endpoints exist; nothing writes to it yet.
- **Limits.** A tribunal cannot unmask an anonymous identity, because the protocol has no
  link to unmask. It cannot bind a nameserver outside its ruleset group. An anchor
  nameserver may coordinate a group's tribunals, but holds no veto over their outcomes or
  over anyone else's.

Panel selection and appeal mechanics need a JEP.

## Known weaknesses the design must close

Each of these is a gap in today's design or code, not an accepted property:

- **Linear Sybil cost.** Standing (aliases, reputation under a ruleset) must cost an
  attacker more per identity than hashing, without linking identities (OP-10, JEP-0003).
- **No proof-of-work or rate limit on alias registration** (`POST /v1/register`).
- **Griefing.** Penalties keyed on the target alone let a third party raise a victim's
  price. Key them on (target, requester).
- **Forgetful decay.** A chronic abuser is fully forgiven after a few quiet hours. Decay
  must remember repeat offenders.
- **Unpriced addresses.** Points on `ip:` keys throttle but do not raise difficulty.
- **No tribunal outcomes, propagation or transparency entries.** Decisions are stored and
  go nowhere.
- **No path for reporting abuse from encrypted channels.**

## Open questions

- Which admission input closes linear Sybil cost: cross-registration within a ruleset
  group, soul validation, or something else.
- How victim-key delegation works for each encryption suite, and what a tribunal may accept
  as effective proof.
- Whether reputation summaries from members of a ruleset group should ever move difficulty
  by more than the local quarter-of-the-bits bound.
