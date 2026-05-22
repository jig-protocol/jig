# Identity and Reputation

**Audience:** This chapter is for **server operators** (configuring nameservers, tribunal policies), **protocol implementers** (building identity systems), and **developers** (understanding reputation tiers and useful work). **End users** might care about how reputation affects their message costs and what happens if they're reported to a tribunal.

---

Identity in Jig isn't just usernames and passwords. It's a reputation system that adapts based on behavior: spammers pay more to send messages, trusted contributors get discounts, and bad actors get ejected by community tribunals. It's like credit scores for messaging, but transparent, federated, and built into the protocol.

## Why Reputation Matters

Here's the problem with most messaging systems: either everyone can spam freely (chaos), or you need a central authority to ban people (censorship risk). Jig takes a third path: **adaptive costs** based on reputation.

**How it works:**

- **New users** pay a high cost (proof-of-work) to send messages. This prevents spam bots from flooding the network.
- **Good users** build reputation by contributing useful work (validating signatures, relaying messages, participating in governance). Their costs drop.
- **Bad users** accumulate penalties (sent spam, violated community rules). Their costs rise exponentially until they're priced out or get tribunal-banned.

**Real-world example:**

Alice joins Jig (new account, null-sec zone). She wants to send a message. Her client solves a 24-bit proof-of-work puzzle (takes ~10 seconds on her laptop). Message sent.

Over the next month, Alice contributes useful work (validates 50 messages, relays blocks for her community). She graduates to low-sec zone. Now her PoW drops to 16-bit (~1 second).

Bob joins Jig and immediately sends 1000 spam messages. Servers detect the pattern, add penalties to his account. His PoW jumps to 32-bit (~2 minutes per message). He gives up and leaves.

// woof fix, not how this works

**Trade-offs:**

- **More complex:** Plain usernames are simpler. Reputation requires scoring, useful work allocation, and tribunal governance.
- **More resilient:** No single point of failure. Spammers are priced out economically, not by central ban lists.
- **More fair:** Good behavior is rewarded (lower costs), bad behavior is punished (higher costs), and appeals are handled by community tribunals (not corporate overlords).

**For end users:** Your reputation tier determines how much it costs (in time or money) to send messages. Build reputation by being a good community member.

**For server operators:** You configure reputation policies (PoW difficulty, penalty decay rates, tribunal escalation thresholds) in `jig-config.toml`.

**For developers:** Reputation tiers affect rate limits, capability grants, and fuel costs. Design your apps to handle users across all tiers gracefully.

## Identity Stack

Jig's identity system has four layers:

### 1. DIDs (Decentralized Identifiers)

**What they are:** Cryptographically-verifiable IDs like `did:jig:5HpG9w8EBLe9vNqvdcXtUNJRaWHhTjdxYWdBqNpmQBZG`.

**How they work:** Your DID is derived from your public key (Ed25519). You prove ownership by signing messages with your private key.

**Why they matter:** No central authority can revoke your DID. If you lose trust with one server, move to another server with the same DID (your reputation travels with you) or create a new DID with a new keypair. Note that your reputation restarts at zero on all nameservers with a new identity. There's no way to associate the two, and that's a good thing!

**For end users:** Your DID is your identity. Back up your private key: if you lose it, you lose your identity and reputation.

### 2. Nameserver

**What it is:** A federated service mapping human-readable handles (like `alice@example.com`) to DIDs.

**How it works:**

1. You register `alice` on nameserver `example.com`.
2. The nameserver links `alice@example.com` → `did:jig:5HpG9w...`.
3. Other users can message `alice@example.com` (easy to remember) instead of `did:jig:5HpG9w...` (hard to remember).

**Why it's federated:** No single nameserver controls all names. If `example.com` goes down, use a different nameserver. Your DID stays the same.

**For server operators:** Run a nameserver if you want to offer human-readable handles for your community. See the nameserver chapter for setup details.

// also - you can associate with another nameserver to pick up _their_ handles, if they agree to it (federate).
// nameservers can share identity registries / mapping (this is what constitutes "high-sec:" cross-validation of users across handles and servers + permutation of reputation rewards & penalties across all linked servers/nameservers as a result)

### 3. Capability Tokens

**What they are:** Signed grants that bind identities to specific permissions (like "alice can fetch from api.weather.gov" or ~~"bob can vote in tribunals"~~). // don't think we've implemented non-automated tribunals

**How they work:**

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

The server signs this token and gives it to Alice. Alice includes it when executing blocks that need `net.fetch`. The server verifies the signature and checks expiry before granting access.

**Why tokens:** Zero ambient authority. Just because you're logged in doesn't mean you can do anything. You need explicit capability tokens for each action.

**For developers:** Request capabilities in your block manifest. The runtime provides capability tokens at execution time.

### 4. Reputation Graph

**What it is:** A weighted graph where nodes are DIDs and edges are reputation flows (useful work validations, tribunal verdicts, federated attestations).

**How it works:**

Jig uses a PageRank-like algorithm with damping factor 0.85:

```
reputation(Alice) = base_score
                  + 0.85 × Σ(reputation(Validator) / out_degree(Validator))
                  + penalty_adjustments
```

If high-reputation users vouch for you (by validating your useful work), your reputation rises. If you accumulate penalties (spam, rule violations), your reputation falls.

**Why graph-based:** Sybil-resistant. An attacker can't just create 1000 fake accounts to vouch for themselves—they'd need to earn reputation on each account first (expensive).

**For server operators:** Reputation graphs are local (each server computes its own). Federated servers gossip reputation summaries (signed attestations), but you decide how much to trust them. // rulesets - shared or data contract

## Account Zones

Jig has three reputation zones. ~~Your zone determines your costs, capabilities, and trust level.~~ // nope - zones are for servers, reflect what kind of user behaviors + anonymity are permitted. Any user can try to join any server; high-sec servers are more likely to require higher reputation scores to join, and null-sec servers are usually the only ones that permit --anon accounts to join (where no did is proffered at login and reputation is transient with session).

| Zone         | Requirements                                                                    | Capabilities                                                      | Notes                                                                 |
| ------------ | ------------------------------------------------------------------------------- | ----------------------------------------------------------------- | --------------------------------------------------------------------- |
| **Null-sec** | None (anonymous, no registration)                                               | Post-only, no federation, no reputation accrual                   | High PoW (24-bit), short-lived tokens. For cold starts and anonymity. |
| **Low-sec**  | Nameserver registration, adaptive PoW                                           | Normal messaging, limited useful work, local federation           | Default community tier. Lower PoW (16-bit adaptive).                  |
| **High-sec** | Soul validation (≥2 validators), 90-day age, useful work streak, optional stake | Tribunal voting, governance actions, block marketplace publishing | Lowest PoW (8-bit or none). Trusted operators and orgs.               |

// fix this

### Zone Transitions

// ok, this is thematically right but off because reputation is a number for users (and servers and nameservs, for that matter)
// so users don't "transition" like this. these items influence user reputation gains/losses, but aren't stage-gates

**Null-sec → Low-sec:**

1. Register a handle with a nameserver (proves you control an email or domain).
2. Wait for adaptive PoW to adjust based on your behavior (usually a few messages).
3. Automatically promoted once thresholds are met.

**Low-sec → High-sec:**

1. Get soul validation: At least 2 existing high-sec users vouch for you (signed attestations).
   // soul validation is a cool concept! we haven't implemented it yet, but if real humans validate that you're a real human - and stake their reputation on yours - you can boost your reputation gain. but if you lose reputation, your entire soulnet loses reputation. skin-in-the-game and all that.
2. Maintain 90-day account age (prevents fresh accounts from gaining power).
3. Complete useful work streak (e.g., validate 100 signatures without errors).
4. Optionally stake reputation or tokens (proves skin-in-the-game).

**Downgrade (High-sec → Low-sec):**

- Accumulate too many penalties (tribunal censures, spam reports, failed useful work).
- Can appeal via tribunal (see below).

**Cost scaling (triangulation):**

Zone transitions use exponential cost scaling to prevent gaming:

```
cost_to_promote = base_cost × 3^(current_tier)
```

Moving from null-sec to low-sec is cheap. Moving from low-sec to high-sec is expensive. This prevents attackers from cheaply flooding the high-sec tier.

## Identity Modes

Users can choose how they're identified:

### Anonymous (`~hash`)

**What it is:** Default null-sec persona backed by ephemeral keys + PoW. No linkage across sessions.

**Use case:** Whistleblowers, privacy-conscious users, quick experiments.

**Example:** `~4f3a8b2c` (hash of ephemeral key).

**Trade-offs:** High PoW cost, no reputation accrual, no federation. Pure privacy.

### Verified (`@user.domain`)

**What it is:** High-sec persona anchored to enterprise attestations (SAML/OIDC, hardware tokens). Meets compliance requirements. Cross-linked to networked servers shared across (that server's) high-sec space.

**Use case:** Corporate accounts, verified journalists, government officials. Banking, purchases, signing contracts, doing business.

**Example:** `@alice.acme.com` (verified by Acme Corp's identity provider).

**Trade-offs:** No anonymity, but trusted and low-cost. Required for regulated industries (finance, healthcare).

### Dual (`±selector`)

// I think this is probably really dangerous. It probably makes sense to have _no way in protocol_ to link an --anon account to a live did, and maybe see if we can help block on-machine cross-links of keypairs too.

**What it is:** Linked identities allowing operators to maintain anonymous + verified personas simultaneously. Active mode selected per conversation while provenance is auditable under tribunal warrant.

**Use case:** Investigative journalists (anonymous when interviewing sources, verified when publishing), corporate whistleblowers (anonymous when reporting, verified when providing evidence).

**Example:** `±alice` (could be `~4f3a8b2c` in one conversation, `@alice.news.com` in another).

**Trade-offs:** Complex UX, but flexible. Tribunals can unmask dual identities under warrant (prevents abuse).

**For developers:** Render identity prefixes accordingly so users know which persona is active (`~` = anonymous, `@` = verified, `±` = dual).

## Adaptive Proof-of-Work

Instead of flat rate limiting (everyone gets 10 messages/minute), Jig uses **adaptive PoW**: your cost adjusts based on reputation.

### Cost Function

```rust
fn message_cost(tier: ReputationTier) -> ProofOfWork {
    match tier {
        ReputationTier::New => ProofOfWork::difficulty(24),       // ~10 sec
        ReputationTier::Basic => ProofOfWork::difficulty(16),     // ~1 sec
        ReputationTier::Trusted => ProofOfWork::difficulty(8),    // ~0.1 sec
        ReputationTier::Verified => ProofOfWork::none(),          // instant
        ReputationTier::Suspicious => ProofOfWork::difficulty(32), // ~2 min
        ReputationTier::Blocked => ProofOfWork::infinite(),       // impossible
    }
}
```

**How it works:**

- **New senders** (null-sec, no reputation): 24-bit PoW (~10 seconds to compute).
- **Basic senders** (low-sec, some reputation): 16-bit PoW (~1 second).
- **Trusted senders** (high-sec, good reputation): 8-bit PoW (~0.1 seconds).
- **Verified senders** (enterprise SSO, hardware tokens): No PoW (instant).
- **Suspicious senders** (penalties accumulated): 32-bit PoW (~2 minutes).
- **Blocked senders** (tribunal-banned): Infinite PoW (can't send messages).

**Proof-of-work algorithm:**

```python
def solve_pow(challenge, difficulty):
    nonce = 0
    while True:
        hash = BLAKE3(challenge + str(nonce))
        if hash.startswith('0' * difficulty):  # e.g., 24 leading zeros
            return nonce
        nonce += 1
```

The server issues a challenge (random bytes). Your client finds a nonce such that `BLAKE3(challenge + nonce)` has `difficulty` leading zero bits. More bits = exponentially harder.

**For end users:** PoW happens in the background (your client does it automatically). You'll notice messages send instantly (verified) or take a few seconds (new account), but you don't have to do anything manually.

**For server operators:** Configure PoW difficulty curves in `jig-config.toml`. Lower difficulty = easier spam (but better UX). Higher difficulty = harder spam (but worse UX for new users).

## Proof-of-Useful-Work

Instead of wasting CPU on arbitrary puzzles (like Bitcoin mining), Jig's PoW is **useful work**: tasks that benefit the network.

### Work Types

- **Validation**: Verify message signatures, check block manifests, validate receipts.
- **Spam filtering**: Apply heuristics to detect spam (stylometry, rate patterns).
- **Gossip relay**: Forward blocks across federation boundaries.
- **Storage proofs**: Prove you're storing historical blocks (help with archival).
- **Governance tasks**: Participate in tribunals, review appeals, vote on policy changes.

### Allocation

**How assignments work:**

1. Server picks users randomly, weighted by reputation (high-sec users validate more than null-sec users).
2. Server issues an assignment block:

```json
{
  "assignment_id": "work_abc123",
  "user": "did:jig:alice",
  "tier": "low_sec",
  "task": {
    "type": "validate_signatures",
    "messages": ["cid:msg1", "cid:msg2", "cid:msg3"]
  },
  "validators": ["did:jig:bob", "did:jig:carol"],
  "expires_at": "2025-11-09T13:00:00Z"
}
```

3. Alice validates the signatures for `msg1`, `msg2`, `msg3` and submits a proof block:

```json
{
  "assignment_id": "work_abc123",
  "results": [
    { "message": "cid:msg1", "valid": true },
    { "message": "cid:msg2", "valid": true },
    { "message": "cid:msg3", "valid": false, "reason": "signature_mismatch" }
  ],
  "signature": "ed25519:aliceSig..."
}
```

4. Validators (Bob and Carol) check Alice's work. If ≥2/3 agree, Alice gets reputation credits and lower PoW cost.

### Rewards

- **Reputation credits**: Your reputation score increases (lowers future PoW cost).
- **Capability discounts**: Get reduced fuel costs for blocks you execute.
- **Relay quota top-ups**: If you're a federation relay, get more bandwidth quota.

### Penalties

- **Incorrect work**: If Alice claims a signature is valid but it's not (and validators catch it), she gets penalty points.
- **Timeouts**: If Alice doesn't complete the assignment before expiry, minor penalty.
- **Disagreements**: If validators disagree on Alice's work, tribunal review is triggered (see below).

**Penalty effect:** Penalty points raise PoW difficulty and reduce capability quotas. They decay over time (e.g., halve every 30 days) so reformed spammers can recover.

**For developers:** Useful work assignments are blocks like any other. You can build clients that auto-complete assignments in the background (helps the network, builds your reputation).

## Nameserver Mechanics

The nameserver maps human-readable handles to DIDs and enforces reputation-based rate limiting.

### Challenge Flow

**Step 1: Request challenge**

```http
GET https://ns.example.com/challenge?handle=alice
```

**Response:**

```json
{
  "challenge": "01932f9a-b123-7abc-9def-0123456789ab",
  "difficulty": 16,
  "expires_at": "2025-11-09T12:40:00Z"
}
```

**Step 2: Solve PoW**

Client computes:

```python
nonce = solve_pow(challenge="01932f9a-b123-...", difficulty=16)
```

**Step 3: Submit solution**

```http
POST https://ns.example.com/register
{
  "handle": "alice",
  "did": "did:jig:5HpG9w...",
  "challenge": "01932f9a-b123-...",
  "nonce": 42387,
  "signature": "ed25519:aliceSig..."
}
```

**Response (success):**

```json
{
  "status": "registered",
  "handle": "alice@example.com",
  "did": "did:jig:5HpG9w...",
  "tier": "low_sec"
}
```

**Response (failure):**

```json
{
  "status": "error",
  "reason": "POW_INVALID",
  "retry_after_seconds": 300
}
```

### Rate Limiting

Nameservers use **token buckets** per handle/scope:

- **Global limit**: 1000 registrations/minute across all users (prevents DoS).
- **Per-handle limit**: 1 registration per handle per hour (prevents name squatting).
- **Per-IP limit**: 10 registrations/minute per IP (prevents bot swarms).

**Circuit breakers:** If a user exceeds limits repeatedly, exponential backoff is enforced:

```
retry_after = base_delay × 2^(consecutive_failures)
```

After 3 failures, you wait 8× the base delay. After 10 failures, you're effectively rate-limited out.

### Penalties

Nameservers track penalty scores:

- **Invalid PoW submission**: +5 penalty points.
- **Spam reports** (from other users): +10 penalty points.
- **Tribunal censure**: +50 penalty points.

Penalty points adjust PoW difficulty:

```
effective_difficulty = base_difficulty + (penalty_points / 10)
```

If your penalty score is 100, your PoW difficulty increases by 10 bits (1024× harder).

**Decay:** Penalty points halve every 30 days (floor of 0). So even heavily penalized users can recover if they clean up their behavior.

### Federation

Nameservers publish their policies via `/.well-known/jig-ns.json`:

```json
{
  "nameserver_did": "did:jig:ns:example.com",
  "base_difficulty": 16,
  "rate_limits": {
    "global_per_minute": 1000,
    "per_handle_per_hour": 1,
    "per_ip_per_minute": 10
  },
  "federation_peers": ["did:jig:ns:friendly.org", "did:jig:ns:trusted.net"],
  "deny_list": ["did:jig:ns:spammy.biz"]
}
```

Nameservers choose which peers to trust (share reputation signals with). They can also denylist known-bad nameservers.

**DNS SRV records** advertise nameserver endpoints:

```
_jig-ns._tcp.example.com. 3600 IN SRV 0 5 8443 ns1.example.com.
```

**For server operators:** Run a nameserver if you want to offer handles for your community. See the nameserver setup guide (implementation docs) for installation steps.

## Tribunal System

When automated penalties aren't enough (or when users want to appeal), cases escalate to **tribunals**: community-run dispute resolution.

### When Tribunals Trigger

**Automated triggers:**

- High penalty accumulation (e.g., >200 penalty points in 7 days).
- Useful work disagreement (validators don't concur on someone's work).
- Multiple spam reports from high-sec users.

**Human triggers:**

- User submits appeal ("I was falsely flagged as spam").
- Community member files a report ("This user is doxxing people").

### Tribunal Workflow

**Step 1: Intake**

Reporter submits a tribunal block:

```json
{
  "type": "tribunal_case",
  "case_id": "case_abc123",
  "subject": "did:jig:bob",
  "reason": "spam",
  "evidence": ["cid:msg1", "cid:msg2", "cid:chatLog"],
  "reporter": "did:jig:alice",
  "reporter_signature": "ed25519:..."
}
```

**Step 2: Panel Selection**

Random selection of high-sec members:

- **Size**: 3–7 panelists (configurable per community).
- **Diversity**: Cross-instance when possible (prevents collusion).
- **Recusal**: Panelists can't judge cases involving themselves or close contacts.

**Step 3: Deliberation**

Panelists fetch evidence blocks, review chat logs, and may request sealed content via zero-knowledge proofs (for E2EE messages).

They discuss privately (tribunal channel) and vote:

- **Sustain**: Penalties upheld or increased.
- **Modify**: Reduce penalties, issue warning.
- **Overturn**: Remove penalties, compensate reporter if false claim.

**Step 4: Decision Block**

Tribunal publishes outcome:

```json
{
  "type": "tribunal_decision",
  "case_id": "case_abc123",
  "outcome": "sustain",
  "reasoning": "Evidence shows pattern of unsolicited DMs (50+ in 1 hour). Penalties upheld.",
  "penalty_adjustment": +100,
  "reputation_adjustment": -500,
  "panelists": [
    {"did": "did:jig:judge1", "vote": "sustain"},
    {"did": "did:jig:judge2", "vote": "sustain"},
    {"did": "did:jig:judge3", "vote": "modify"}
  ],
  "transparency_hash": "blake3:decisionHash...",
  "signatures": [...]
}
```

Panelists sign the decision. It's appended to the transparency log (minus private payloads).

**Step 5: Appeal**

Subjects can appeal once:

- **Cost**: Stake additional reputation or useful work credits (prevents frivolous appeals).
- **New panel**: Different panelists (randomly selected, no overlap with original panel).
- **Finality**: After second tribunal, decision is final (no more appeals).

### Privacy Considerations

**Public data:**

- Case ID, subject DID (anonymized as hash in public logs), outcome, penalty adjustments.

**Private data:**

- Evidence content (only panelists see it), deliberation transcripts, reporter identity (if they request anonymity).

**Zero-knowledge proofs:** For E2EE evidence, blocks can include ZK proofs asserting properties (e.g., "this message contains a doxxing address") without revealing plaintext. Panelists verify the proof.

**For server operators:** Configure tribunal policies in `jig-config.toml` (panel size, appeal limits, penalty ranges). Tribunals can be community-specific or federated.

## Reputation Propagation

Reputation is **local** (each server computes its own scores) but **gossip-enabled** (servers can share summaries).

### Local Computation

Each server tracks:

- **Useful work ledger**: Who validated what, outcomes.
- **Penalty log**: Spam reports, tribunal censures, failed PoW.
- **Interaction graph**: Who messages whom (edge weights).

PageRank algorithm:

```python
def compute_reputation(users, edges, penalties):
    scores = {user: 1.0 for user in users}
    for iteration in range(100):  # Converge after ~100 iterations
        new_scores = {}
        for user in users:
            incoming = [edge for edge in edges if edge.to == user]
            new_scores[user] = (1 - 0.85) + 0.85 * sum(
                scores[edge.from_user] / out_degree(edge.from_user)
                for edge in incoming
            )
            new_scores[user] -= penalties[user] * 0.1  # Penalty adjustment
        scores = new_scores
    return scores
```

### Federated Gossip

Servers exchange **signed reputation summaries**:

```json
{
  "from_server": "did:jig:server:example.com",
  "subject": "did:jig:bob",
  "reputation_score": 0.75,
  "tier": "low_sec",
  "useful_work_count": 42,
  "penalty_points": 5,
  "last_updated": "2025-11-09T12:00:00Z",
  "signature": "ed25519:serverSig..."
}
```

Receiving servers decide how much to trust the gossip:

- **Trusted peer** (high-sec federation partner): Weight 0.8.
- **Untrusted peer** (new or low-reputation): Weight 0.2.

Combined reputation:

```python
def combine_reputation(local_score, remote_summaries):
    weighted_sum = local_score
    weight_total = 1.0
    for summary in remote_summaries:
        trust = trust_weight(summary.from_server)
        weighted_sum += summary.reputation_score * trust
        weight_total += trust
    return weighted_sum / weight_total
```

**Sybil resistance:**

- **Triangulation cost**: Creating N fake accounts costs 3^N (exponential).
- **Aging requirement**: High-sec tier requires 90-day account age (can't instant-spawn high-reputation accounts).
- **Stylometry detection**: Servers analyze writing patterns (if 100 accounts all write identically, flag them as Sybil cluster).

**For server operators:** Decide which peers to trust for reputation gossip. Configure in `jig-config.toml` with per-peer trust weights.

## Normative Requirements Summary

**MUST:**

- Support DIDs as primary identifiers (Ed25519-derived).
- Enforce adaptive PoW based on reputation tier (difficulty scales with penalties).
- Track penalty points and decay them over time (halving every 30 days by default).
- Verify PoW solutions before accepting registrations or messages.
- Randomly assign useful work tasks weighted by reputation.
- Require ≥2/3 validator concurrence for useful work acceptance.
- Trigger tribunal review on high penalty accumulation or validator disagreement.
- Support at least anonymous (`~hash`) and verified (`@user.domain`) identity modes.
- Publish nameserver policies via `/.well-known/jig-ns.json`.
- Use DNS SRV records for nameserver discovery (`_jig-ns._tcp`).
- Sign tribunal decisions with panelist signatures and log to transparency log.

**SHOULD:**

- Support dual identity mode (`±selector`) for privacy-flexibility balance.
- Use PageRank-style reputation scoring with damping factor 0.85.
- Enable federated reputation gossip with trust-weighted scoring.
- Implement circuit breakers for rate limiting (exponential backoff on repeated failures).
- Allow tribunal appeals with staking requirement (prevents frivolous appeals).
- Use zero-knowledge proofs for E2EE evidence in tribunal cases.
- Apply stylometry and aging heuristics for Sybil detection.

**MAY:**

- Customize tribunal policies (panel size, penalty ranges, appeal limits) per community.
- Integrate enterprise SSO (SAML/OIDC) for verified identity mode.
- Offer hardware token support (YubiKey, etc.) for high-sec accounts.
- Implement custom useful work types beyond the canonical set.

---

**Related chapters:**

- **[Zero-Trust Model](zero-trust.md)**: Fail-closed semantics, adversarial assumptions (foundation for reputation system).
- **[Crypto Primitives](crypto.md)**: Ed25519 for DIDs, BLAKE3 for PoW hashing, key transparency.
- **[Federation](federation.md)**: Cross-server reputation gossip, federation peer trust.
- **[Security Considerations](security.md)**: Sybil resistance, abuse mitigation, operational security for nameservers.

**Next:** Now that you understand identity and reputation, check out [Federation](federation.md) to see how reputation scores influence cross-server trust and rate limiting. Or dive into [Security Considerations](security.md) for operational best practices (nameserver hardening, tribunal privacy, incident response).
