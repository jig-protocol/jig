# Authn/Authz Phase 2: Tier-0 Authentication Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make every read request carry a verifiable proof that the caller holds the private key for the DID it claims, with replay defence, on any transport.

**Architecture:** A caller signs a domain-separated BLAKE3 hash over the request's method, path, body, HLC and a nonce. The canonical hashing lives in `jig-core` so client and server cannot disagree about it. The server verifies the signature, rejects timestamps outside an acceptance window, and rejects nonces already seen inside that window using a bounded structure that cannot grow under flood. Reads are gated behind config so the change can land before every client is updated.

**Tech Stack:** Rust 2024, ed25519-dalek 3.0, blake3, axum 0.7, `cargo nextest`.

**Spec:** [`docs/superpowers/specs/2026-08-24-jig-server-authn-authz-design.md`](../specs/2026-08-24-jig-server-authn-authz-design.md)

**Depends on:** Phase 1 (`GateOutcome`, `DisclosurePolicy`) must be merged first.

**Working directory:** All `cargo` commands run from `repos/`. Use `cargo +stable` for clippy.

---

### Task 1: Canonical request hashing in `jig-core`

The hash must be **domain-separated from block signing**. A signature a caller produced over a request must never be replayable as a signature over a block, and vice versa. `hash_labeled_parts` already provides unambiguous length-prefixed encoding; the domain label is what stops cross-protocol reuse.

**Files:**
- Create: `repos/jig-core/src/request_auth.rs`
- Modify: `repos/jig-core/src/lib.rs`
- Test: inline `#[cfg(test)]` in `request_auth.rs`

- [ ] **Step 1: Write the failing test**

Create `repos/jig-core/src/request_auth.rs` containing ONLY the test module:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    /// Every field must change the hash. A field that does not is a field an
    /// attacker can alter freely while reusing a captured signature.
    #[test]
    fn every_field_is_covered_by_the_hash() {
        let base = canonical_request_hash("GET", "/api/v1/channels", b"", 1000, 0, "n1");

        assert_ne!(
            base,
            canonical_request_hash("POST", "/api/v1/channels", b"", 1000, 0, "n1"),
            "method must be covered"
        );
        assert_ne!(
            base,
            canonical_request_hash("GET", "/api/v1/blocks", b"", 1000, 0, "n1"),
            "path must be covered"
        );
        assert_ne!(
            base,
            canonical_request_hash("GET", "/api/v1/channels", b"x", 1000, 0, "n1"),
            "body must be covered"
        );
        assert_ne!(
            base,
            canonical_request_hash("GET", "/api/v1/channels", b"", 1001, 0, "n1"),
            "hlc wall_ms must be covered"
        );
        assert_ne!(
            base,
            canonical_request_hash("GET", "/api/v1/channels", b"", 1000, 1, "n1"),
            "hlc logical must be covered"
        );
        assert_ne!(
            base,
            canonical_request_hash("GET", "/api/v1/channels", b"", 1000, 0, "n2"),
            "nonce must be covered"
        );
    }

    /// The same inputs must always produce the same hash, or a client and a
    /// server on different machines could never agree.
    #[test]
    fn hashing_is_deterministic() {
        let a = canonical_request_hash("GET", "/x", b"body", 42, 7, "nonce");
        let b = canonical_request_hash("GET", "/x", b"body", 42, 7, "nonce");
        assert_eq!(a, b);
    }

    /// Field boundaries must be unambiguous. Without length prefixing,
    /// ("ab", "c") and ("a", "bc") would hash identically, letting an attacker
    /// shift bytes between path and nonce while keeping a captured signature
    /// valid.
    #[test]
    fn adjacent_fields_cannot_be_confused() {
        let a = canonical_request_hash("GET", "ab", b"", 1, 0, "c");
        let b = canonical_request_hash("GET", "a", b"", 1, 0, "bc");
        assert_ne!(a, b, "field boundaries must be unambiguous");
    }

    /// A request signature must not be usable as a block signature. Different
    /// domain labels are what guarantee it, and this test fails loudly if the
    /// label is ever dropped.
    #[test]
    fn request_hash_is_domain_separated_from_raw_hashing() {
        let payload = b"GET/api/v1/channels";
        let request = canonical_request_hash("GET", "/api/v1/channels", b"", 0, 0, "");
        let raw = crate::crypto::blake3_hash(payload);
        assert_ne!(
            request.as_bytes(),
            raw.as_bytes(),
            "request hashing must be domain-separated, not a bare hash of concatenated fields"
        );
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run:
```bash
cd repos && cargo +stable nextest run -p jig-core --lib request_auth
```

Expected: compile error — `canonical_request_hash` is not defined and the module is not declared.

- [ ] **Step 3: Write the implementation**

Prepend to `repos/jig-core/src/request_auth.rs`:

```rust
//! Canonical bytes a caller signs to prove possession of a DID's key.
//!
//! Lives in `jig-core` rather than in the server so that client and server
//! cannot drift into hashing different things — a drift that would present as
//! "every signature is invalid" with no indication of which side is wrong.
//!
//! # Domain separation
//!
//! The label below is load-bearing. Without it, a signature produced over a
//! request could potentially be replayed as a signature over some other
//! protocol artefact that happened to hash the same bytes. Every distinct thing
//! jig asks a key to sign gets its own label.

use blake3::Hash;

use crate::crypto::hash_labeled_parts;

/// Domain label for request authentication. Never reuse this for anything else,
/// and never sign a request without it.
const DOMAIN: &str = "jig-request-auth-v1";

/// Hash the canonical form of a request.
///
/// Every parameter is covered, and `hash_labeled_parts` length-prefixes each
/// field, so no two different requests can produce the same hash by shifting
/// bytes across a field boundary.
///
/// `body` is the exact bytes of the request body; pass `b""` for a body-less
/// request such as a GET.
pub fn canonical_request_hash(
    method: &str,
    path: &str,
    body: &[u8],
    hlc_wall_ms: u64,
    hlc_logical: u32,
    nonce: &str,
) -> Hash {
    hash_labeled_parts(&[
        ("domain", DOMAIN.as_bytes()),
        ("method", method.as_bytes()),
        ("path", path.as_bytes()),
        ("body", body),
        ("hlc_wall_ms", &hlc_wall_ms.to_le_bytes()),
        ("hlc_logical", &hlc_logical.to_le_bytes()),
        ("nonce", nonce.as_bytes()),
    ])
}
```

Add to `repos/jig-core/src/lib.rs`, in the existing `pub mod` list:

```rust
pub mod request_auth;
```

- [ ] **Step 4: Run the tests to verify they pass**

Run:
```bash
cd repos && cargo +stable nextest run -p jig-core --lib request_auth
```

Expected: 4 tests pass.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat(jig-core): canonical request hashing for proof of possession

Domain-separated BLAKE3 over method, path, body, HLC and nonce, built on
hash_labeled_parts so every field is length-prefixed and adjacent fields
cannot be confused by shifting bytes across a boundary.

In jig-core rather than the server so client and server cannot drift into
hashing different things — a drift that would present as 'every signature is
invalid' with no indication of which side is wrong. The domain label stops a
request signature from being replayable as a signature over any other jig
artefact."
```

---

### Task 2: The replay guard

Signature verification alone does not stop a captured request being sent again. Two defences together: an HLC acceptance window, and a record of nonces seen inside it.

**The structure must be bounded independently of the window.** Bounding only by time means a flood at 100k req/s grows memory without limit until the window rolls. Bounding by capacity means memory is capped, and an eviction inside the window degrades to rejecting a replay-window miss — refusing a legitimate retry rather than accepting a replay. Refusing is the safe direction.

**Files:**
- Create: `repos/jig-server/src/auth/replay.rs`
- Modify: `repos/jig-server/src/auth/mod.rs`
- Test: inline `#[cfg(test)]` in `replay.rs`

- [ ] **Step 1: Write the failing test**

Create `repos/jig-server/src/auth/replay.rs` containing ONLY the test module:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fresh_nonce_is_accepted_once() {
        let mut guard = ReplayGuard::new(1000, 100);
        assert!(guard.check_and_record("nonce-a", 5_000, 5_000).is_ok());
    }

    #[test]
    fn the_same_nonce_twice_is_a_replay() {
        let mut guard = ReplayGuard::new(1000, 100);
        guard.check_and_record("nonce-a", 5_000, 5_000).unwrap();
        assert_eq!(
            guard.check_and_record("nonce-a", 5_000, 5_000),
            Err(ReplayRejection::AlreadySeen)
        );
    }

    /// A timestamp far in the past is stale. Without this, a captured request
    /// could be replayed forever once its nonce fell out of the structure.
    #[test]
    fn a_timestamp_before_the_window_is_stale() {
        let mut guard = ReplayGuard::new(1000, 100);
        assert_eq!(
            guard.check_and_record("nonce-a", 1_000, 5_000),
            Err(ReplayRejection::OutsideWindow)
        );
    }

    /// A timestamp in the future is equally refused. Allowing it would let a
    /// caller mint requests valid long after capture; the window is symmetric
    /// so that clock skew is tolerated in both directions and no further.
    #[test]
    fn a_timestamp_after_the_window_is_stale() {
        let mut guard = ReplayGuard::new(1000, 100);
        assert_eq!(
            guard.check_and_record("nonce-a", 9_000, 5_000),
            Err(ReplayRejection::OutsideWindow)
        );
    }

    #[test]
    fn a_timestamp_at_the_window_edge_is_accepted() {
        let mut guard = ReplayGuard::new(1000, 100);
        assert!(guard.check_and_record("edge-early", 4_000, 5_000).is_ok());
        assert!(guard.check_and_record("edge-late", 6_000, 5_000).is_ok());
    }

    /// Memory is capped by capacity, not by traffic. This is the property that
    /// keeps a flood from exhausting a $5 VPS.
    #[test]
    fn memory_is_bounded_by_capacity_under_flood() {
        let capacity = 50;
        let mut guard = ReplayGuard::new(1000, capacity);
        for i in 0..10_000 {
            let _ = guard.check_and_record(&format!("nonce-{i}"), 5_000, 5_000);
        }
        assert!(
            guard.len() <= capacity,
            "guard grew to {} entries against a capacity of {capacity}",
            guard.len()
        );
    }

    /// Eviction must drop the OLDEST nonce, so a replay of something recent is
    /// still caught. Dropping the newest would make the guard useless exactly
    /// when it is under pressure.
    #[test]
    fn eviction_drops_the_oldest_nonce_first() {
        let mut guard = ReplayGuard::new(1000, 2);
        guard.check_and_record("first", 5_000, 5_000).unwrap();
        guard.check_and_record("second", 5_000, 5_000).unwrap();
        guard.check_and_record("third", 5_000, 5_000).unwrap();

        assert!(
            guard.check_and_record("first", 5_000, 5_000).is_ok(),
            "the oldest nonce should have been evicted"
        );
        assert_eq!(
            guard.check_and_record("third", 5_000, 5_000),
            Err(ReplayRejection::AlreadySeen),
            "the newest nonce must still be remembered"
        );
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run:
```bash
cd repos && cargo +stable nextest run -p jig-server --lib auth::replay
```

Expected: compile error — `ReplayGuard` and `ReplayRejection` are not defined.

- [ ] **Step 3: Write the implementation**

Prepend to `repos/jig-server/src/auth/replay.rs`:

```rust
//! Replay defence for tier-0 requests.
//!
//! A valid signature proves who sent a request, not that they meant to send it
//! *now*. Two defences combine:
//!
//! 1. An **acceptance window** on the request's HLC, so a captured request
//!    stops being usable once it ages out.
//! 2. A **record of nonces** seen inside that window, so a request cannot be
//!    used twice while it is still fresh.
//!
//! # Why capacity-bounded rather than time-bounded
//!
//! Bounding only by the window means memory grows with traffic: at the
//! protocol's 10,000 msg/s target a ±30s window implies retaining on the order
//! of 300,000 nonces, and a flood is unbounded until the window rolls. That is
//! hostile to the $5-VPS and Raspberry Pi deployment targets.
//!
//! Capping capacity means memory is fixed. The cost is that under flood an
//! entry can be evicted while its window is still open, so a legitimate retry
//! of a very old in-window request may be refused. Refusing a legitimate
//! request is the safe direction to fail; accepting a replay is not.
//!
//! Note that capability-authenticated (tier-1) requests need no nonce at all,
//! which is an independent reason busy servers will want trusted connections.

use std::collections::{HashSet, VecDeque};

/// Why a request was refused by the replay guard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayRejection {
    /// This nonce was already seen inside the acceptance window.
    AlreadySeen,
    /// The request's timestamp is outside the acceptance window, in either
    /// direction.
    OutsideWindow,
}

/// Bounded record of recently-seen request nonces.
///
/// Not internally synchronised: hold it behind the server's existing state
/// lock rather than adding a second locking discipline.
pub struct ReplayGuard {
    window_ms: u64,
    capacity: usize,
    seen: HashSet<String>,
    order: VecDeque<String>,
}

impl ReplayGuard {
    /// `window_ms` is the half-width of the acceptance window: a request is
    /// accepted if its timestamp is within `window_ms` of now, in either
    /// direction. `capacity` is the hard cap on retained nonces.
    pub fn new(window_ms: u64, capacity: usize) -> Self {
        Self {
            window_ms,
            capacity,
            seen: HashSet::new(),
            order: VecDeque::new(),
        }
    }

    /// Number of nonces currently retained.
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    /// True when no nonces are retained.
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }

    /// Check a request's freshness and uniqueness, recording it if it passes.
    ///
    /// `now_ms` is supplied by the caller rather than read from the clock here,
    /// so this type stays a pure function of its inputs and is testable without
    /// sleeping.
    pub fn check_and_record(
        &mut self,
        nonce: &str,
        request_ms: u64,
        now_ms: u64,
    ) -> Result<(), ReplayRejection> {
        let skew = request_ms.abs_diff(now_ms);
        if skew > self.window_ms {
            return Err(ReplayRejection::OutsideWindow);
        }

        if self.seen.contains(nonce) {
            return Err(ReplayRejection::AlreadySeen);
        }

        // Evict oldest-first so a replay of something recent is still caught.
        // Dropping the newest would make the guard useless exactly when it is
        // under the most pressure.
        while self.seen.len() >= self.capacity {
            match self.order.pop_front() {
                Some(oldest) => {
                    self.seen.remove(&oldest);
                }
                None => break,
            }
        }

        self.seen.insert(nonce.to_string());
        self.order.push_back(nonce.to_string());
        Ok(())
    }
}
```

Add to `repos/jig-server/src/auth/mod.rs`:

```rust
pub mod replay;

pub use replay::{ReplayGuard, ReplayRejection};
```

- [ ] **Step 4: Run the tests to verify they pass**

Run:
```bash
cd repos && cargo +stable nextest run -p jig-server --lib auth::replay
```

Expected: 7 tests pass.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat(jig-server): bounded replay guard for tier-0 requests

A valid signature proves who sent a request, not that they meant to send it
now. An HLC acceptance window ages captured requests out; a nonce record
stops reuse while they are still fresh.

Bounded by capacity rather than by the window, because time-bounding alone
grows with traffic — at 10k msg/s a 30s window implies ~300k retained
nonces, and a flood is unbounded until the window rolls. Capping memory
means an entry can be evicted while its window is still open, so a very old
in-window retry may be refused; refusing a legitimate request is the safe
direction to fail, accepting a replay is not. Eviction is oldest-first so a
replay of something recent is still caught under pressure."
```

---

### Task 3: The authenticate gate

**Files:**
- Create: `repos/jig-server/src/auth/authenticate.rs`
- Modify: `repos/jig-server/src/auth/mod.rs`
- Test: inline `#[cfg(test)]` in `authenticate.rs`

- [ ] **Step 1: Write the failing test**

Create `repos/jig-server/src/auth/authenticate.rs` containing ONLY the test module:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use jig_core::crypto::ed25519::KeyPair;
    use jig_core::did::Did;

    fn proof_for(kp: &KeyPair, method: &str, path: &str, body: &[u8], ms: u64, nonce: &str)
        -> AuthProof
    {
        let did = Did::from_ed25519_pubkey(&kp.public_key_bytes());
        let hash = jig_core::request_auth::canonical_request_hash(
            method, path, body, ms, 0, nonce,
        );
        AuthProof {
            did,
            hlc_wall_ms: ms,
            hlc_logical: 0,
            nonce: nonce.to_string(),
            signature: kp.sign(hash.as_bytes()),
        }
    }

    #[test]
    fn a_correctly_signed_request_authenticates() {
        let kp = KeyPair::generate();
        let proof = proof_for(&kp, "GET", "/api/v1/channels", b"", 5_000, "n1");
        let mut guard = ReplayGuard::new(30_000, 128);

        let did = authenticate(&proof, "GET", "/api/v1/channels", b"", 5_000, &mut guard)
            .expect("a correctly signed request must authenticate");
        assert_eq!(did, proof.did);
    }

    #[test]
    fn a_corrupted_signature_is_refused() {
        let kp = KeyPair::generate();
        let mut proof = proof_for(&kp, "GET", "/api/v1/channels", b"", 5_000, "n1");
        proof.signature[0] ^= 0xff;
        let mut guard = ReplayGuard::new(30_000, 128);

        assert_eq!(
            authenticate(&proof, "GET", "/api/v1/channels", b"", 5_000, &mut guard),
            Err(GateOutcome::AuthSignatureInvalid)
        );
    }

    /// The signature covers the request. Presenting a valid signature against a
    /// DIFFERENT path is the attack this prevents — capture a signed read of a
    /// public channel, replay it against a private one.
    #[test]
    fn a_signature_for_another_path_is_refused() {
        let kp = KeyPair::generate();
        let proof = proof_for(&kp, "GET", "/api/v1/channels/%23public/blocks", b"", 5_000, "n1");
        let mut guard = ReplayGuard::new(30_000, 128);

        assert_eq!(
            authenticate(
                &proof,
                "GET",
                "/api/v1/channels/%23private/blocks",
                b"",
                5_000,
                &mut guard
            ),
            Err(GateOutcome::AuthSignatureInvalid),
            "a signature bound to one path must not authenticate another"
        );
    }

    /// A validly signed request presented twice is a replay. The signature is
    /// genuine both times — that is the whole point of testing it here rather
    /// than trusting the signature check alone.
    #[test]
    fn a_replayed_request_is_refused_despite_a_valid_signature() {
        let kp = KeyPair::generate();
        let proof = proof_for(&kp, "GET", "/api/v1/channels", b"", 5_000, "n1");
        let mut guard = ReplayGuard::new(30_000, 128);

        authenticate(&proof, "GET", "/api/v1/channels", b"", 5_000, &mut guard).unwrap();
        assert_eq!(
            authenticate(&proof, "GET", "/api/v1/channels", b"", 5_000, &mut guard),
            Err(GateOutcome::AuthReplayed)
        );
    }

    #[test]
    fn a_stale_request_is_refused() {
        let kp = KeyPair::generate();
        let proof = proof_for(&kp, "GET", "/api/v1/channels", b"", 5_000, "n1");
        let mut guard = ReplayGuard::new(1_000, 128);

        assert_eq!(
            authenticate(&proof, "GET", "/api/v1/channels", b"", 500_000, &mut guard),
            Err(GateOutcome::AuthStale)
        );
    }

    /// A DID whose bytes are not a valid ed25519 key cannot verify anything.
    /// Refusing at the signature gate rather than panicking matters: the DID
    /// string is attacker-controlled input.
    #[test]
    fn a_malformed_did_is_refused_not_panicked_on() {
        let kp = KeyPair::generate();
        let mut proof = proof_for(&kp, "GET", "/api/v1/channels", b"", 5_000, "n1");
        proof.did = Did::from_str_unchecked("did:jig:not-a-real-key");
        let mut guard = ReplayGuard::new(30_000, 128);

        assert_eq!(
            authenticate(&proof, "GET", "/api/v1/channels", b"", 5_000, &mut guard),
            Err(GateOutcome::AuthSignatureInvalid)
        );
    }

    /// A stale request must not consume a nonce slot. Otherwise an attacker
    /// could flood expired requests to evict live nonces from the guard and
    /// open a replay window on real traffic.
    #[test]
    fn a_stale_request_does_not_consume_guard_capacity() {
        let kp = KeyPair::generate();
        let mut guard = ReplayGuard::new(1_000, 128);
        let before = guard.len();

        let proof = proof_for(&kp, "GET", "/api/v1/channels", b"", 5_000, "n1");
        let _ = authenticate(&proof, "GET", "/api/v1/channels", b"", 500_000, &mut guard);

        assert_eq!(guard.len(), before, "a stale request must not occupy a slot");
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run:
```bash
cd repos && cargo +stable nextest run -p jig-server --lib auth::authenticate
```

Expected: compile error — `AuthProof` and `authenticate` are not defined.

- [ ] **Step 3: Write the implementation**

Prepend to `repos/jig-server/src/auth/authenticate.rs`:

```rust
//! Gate 1: does the caller hold the key for the DID it claims?
//!
//! Tier 0 — per-request proof. The caller signs the canonical request hash from
//! [`jig_core::request_auth`]; the server recomputes that hash from the request
//! it actually received and verifies the signature against the claimed DID's
//! public key.
//!
//! Recomputing rather than trusting any hash the caller supplies is the point:
//! it binds the signature to *this* request, so a signature captured against
//! one path cannot authenticate another.

use jig_core::crypto::ed25519::KeyPair;
use jig_core::did::Did;
use jig_core::request_auth::canonical_request_hash;

use crate::auth::{GateOutcome, ReplayGuard, ReplayRejection};

/// A caller's proof of possession, however the transport carried it.
///
/// REST parses this from headers, WSS from frame fields. Keeping it a plain
/// struct is what lets one verification path serve every transport — the
/// design's transport-agnostic requirement lives here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthProof {
    /// The identity the caller claims.
    pub did: Did,
    /// Wall-clock component of the request's HLC, milliseconds since epoch.
    pub hlc_wall_ms: u64,
    /// Logical component of the request's HLC.
    pub hlc_logical: u32,
    /// Single-use value making an otherwise identical request unique.
    pub nonce: String,
    /// ed25519 signature over the canonical request hash.
    pub signature: Vec<u8>,
}

/// Verify a caller's proof of possession for a specific request.
///
/// Returns the authenticated DID, which gates 2 and 3 then reason about.
///
/// Freshness is checked **before** the nonce is recorded, so a flood of expired
/// requests cannot evict live nonces from the guard and open a replay window on
/// real traffic.
pub fn authenticate(
    proof: &AuthProof,
    method: &str,
    path: &str,
    body: &[u8],
    now_ms: u64,
    guard: &mut ReplayGuard,
) -> Result<Did, GateOutcome> {
    let hash = canonical_request_hash(
        method,
        path,
        body,
        proof.hlc_wall_ms,
        proof.hlc_logical,
        &proof.nonce,
    );

    // The DID string is attacker-controlled: a malformed one must be a refusal,
    // never a panic.
    let pubkey = proof
        .did
        .as_bytes()
        .map_err(|_| GateOutcome::AuthSignatureInvalid)?;

    KeyPair::verify_detached(&pubkey, hash.as_bytes(), &proof.signature)
        .map_err(|_| GateOutcome::AuthSignatureInvalid)?;

    match guard.check_and_record(&proof.nonce, proof.hlc_wall_ms, now_ms) {
        Ok(()) => Ok(proof.did.clone()),
        Err(ReplayRejection::AlreadySeen) => Err(GateOutcome::AuthReplayed),
        Err(ReplayRejection::OutsideWindow) => Err(GateOutcome::AuthStale),
    }
}
```

- [ ] **Step 4: Add the detached verify helper to `jig-core`**

`KeyPair::verify` verifies against a keypair the server does not have — it only has the caller's public key. Add a free-standing verifier to `repos/jig-core/src/crypto.rs`, inside the `pub mod ed25519` block, next to the existing `KeyPair` impl:

```rust
    /// Verify a signature against a raw public key.
    ///
    /// The server holds a caller's *public* key only, recovered from their DID,
    /// so it cannot use [`KeyPair::verify`]. Separated out rather than
    /// constructing a half-empty `KeyPair`, which would invite someone to sign
    /// with it.
    impl KeyPair {
        pub fn verify_detached(
            public_key: &[u8; 32],
            data: &[u8],
            signature: &[u8],
        ) -> Result<()> {
            use ed25519_dalek::{Signature, Verifier, VerifyingKey};

            let vk = VerifyingKey::from_bytes(public_key)
                .map_err(|e| JigError::Signing(format!("invalid ed25519 public key: {e}")))?;
            let sig = Signature::from_slice(signature)
                .map_err(|e| JigError::Signing(format!("invalid signature: {e}")))?;
            vk.verify(data, &sig)
                .map_err(|e| JigError::Signing(format!("ed25519 verification failed: {e}")))
        }
    }
```

If the existing `impl KeyPair` block is in scope, add the method to that block instead of opening a second one — check the file first and follow whichever form is already there.

- [ ] **Step 5: Add `pub mod authenticate;` to `repos/jig-server/src/auth/mod.rs`**

```rust
pub mod authenticate;

pub use authenticate::{AuthProof, authenticate};
```

- [ ] **Step 6: Run the tests to verify they pass**

Run:
```bash
cd repos && cargo +stable nextest run -p jig-server --lib auth && cargo +stable nextest run -p jig-core
```

Expected: all pass.

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "feat(jig-server): tier-0 authenticate gate

Recomputes the canonical request hash from the request actually received and
verifies the caller's signature against the public key recovered from their
DID. Recomputing rather than trusting a supplied hash is what binds a
signature to THIS request — otherwise a signature captured against a public
channel would authenticate a read of a private one.

Freshness is checked before the nonce is recorded, so a flood of expired
requests cannot evict live nonces and open a replay window on real traffic.
A malformed DID is a refusal rather than a panic, since the DID string is
attacker-controlled input."
```

---

### Task 4: `[auth]` configuration

**Files:**
- Modify: `repos/jig-config/src/v0_0_2_server.rs`
- Test: inline `#[cfg(test)]` in the same file

- [ ] **Step 1: Write the failing test**

Add to the existing `mod tests` in `repos/jig-config/src/v0_0_2_server.rs`:

```rust
    /// The default must be the safe one. A server that boots without an
    /// [auth] block should require authentication, not skip it — the whole
    /// point of the work is that a fresh install is safe on a public address.
    #[test]
    fn auth_defaults_to_requiring_authentication() {
        let auth = AuthSection::default();
        assert!(
            auth.require_authenticated_reads,
            "a default server must require authenticated reads"
        );
        assert_eq!(auth.replay_window_ms, 30_000);
        assert_eq!(auth.replay_capacity, 100_000);
    }

    /// The escape hatch is named loudly, per repo convention for any carve-out
    /// that weakens a guarantee.
    #[test]
    fn the_unauthenticated_escape_hatch_is_loudly_named() {
        let toml = r#"
            [auth]
            require_authenticated_reads = false
        "#;
        let cfg: JigServerConfig = toml::from_str(toml).expect("parses");
        assert!(!cfg.auth.require_authenticated_reads);
    }

    #[test]
    fn auth_section_round_trips_through_toml() {
        let toml = r#"
            [auth]
            require_authenticated_reads = true
            replay_window_ms = 5000
            replay_capacity = 256
        "#;
        let cfg: JigServerConfig = toml::from_str(toml).expect("parses");
        assert!(cfg.auth.require_authenticated_reads);
        assert_eq!(cfg.auth.replay_window_ms, 5_000);
        assert_eq!(cfg.auth.replay_capacity, 256);
    }
```

- [ ] **Step 2: Run the test to verify it fails**

Run:
```bash
cd repos && cargo +stable nextest run -p jig-config --lib v0_0_2_server
```

Expected: compile error — `AuthSection` is not defined and `JigServerConfig` has no `auth` field.

- [ ] **Step 3: Write the implementation**

Add to `repos/jig-config/src/v0_0_2_server.rs`, following the shape of the existing `IdentitySection`:

```rust
/// Authentication policy for this server.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct AuthSection {
    /// Require a valid proof of possession on read requests.
    ///
    /// Defaults to **true**: a server that boots without an `[auth]` block must
    /// be safe on a public address, because the install flow puts it on one.
    /// Setting this false restores the pre-authentication behaviour where any
    /// caller reads any channel, and is intended only for migrating an existing
    /// deployment.
    pub require_authenticated_reads: bool,

    /// Half-width of the request acceptance window, in milliseconds. A request
    /// is fresh if its timestamp is within this of the server's clock in either
    /// direction. Wider tolerates more clock skew and costs more memory.
    pub replay_window_ms: u64,

    /// Hard cap on retained nonces. Memory is bounded by this rather than by
    /// traffic; see `jig_server::auth::replay`.
    pub replay_capacity: usize,
}

impl Default for AuthSection {
    fn default() -> Self {
        Self {
            require_authenticated_reads: true,
            replay_window_ms: 30_000,
            replay_capacity: 100_000,
        }
    }
}
```

Add the field to `JigServerConfig` (around line 30), matching how the other sections are declared there:

```rust
    #[serde(default)]
    pub auth: AuthSection,
```

- [ ] **Step 4: Run the tests to verify they pass**

Run:
```bash
cd repos && cargo +stable nextest run -p jig-config
```

Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat(jig-config): [auth] section, defaulting to authenticated reads

Defaults to requiring authentication because the install flow puts servers on
public addresses — a config block a fresh install does not write must still
produce a safe server. require_authenticated_reads = false restores the
pre-auth behaviour for migrating existing deployments.

Replay window defaults to +/-30s with a 100k nonce cap: bounded by capacity
rather than traffic, so a flood cannot exhaust a small VPS."
```

---

### Task 5: Wire authentication into the REST read path

**Files:**
- Modify: `repos/jig-server/src/v0_0_2_blocks.rs`
- Modify: `repos/jig-server/src/v0_0_2.rs` (AppState — add the guard and policy)
- Test: `repos/jig-server/tests/authenticated_reads.rs` (create)

- [ ] **Step 1: Write the failing integration test**

Create `repos/jig-server/tests/authenticated_reads.rs`:

```rust
//! Reads require proof of possession when the server is configured to demand it.

use axum::http::StatusCode;

mod support;
use support::{TestServer, signed_get, unsigned_get};

#[tokio::test]
async fn an_unsigned_read_is_refused_when_authentication_is_required() {
    let server = TestServer::builder().require_authenticated_reads(true).build();
    let (status, body) = unsigned_get(&server, "/api/v1/channels").await;

    assert_eq!(status, StatusCode::UNAUTHORIZED, "body={body}");
    assert_eq!(body["code"], "AUTH_REQUIRED");
}

#[tokio::test]
async fn a_correctly_signed_read_succeeds() {
    let server = TestServer::builder().require_authenticated_reads(true).build();
    let caller = server.new_identity();
    let (status, _body) = signed_get(&server, &caller, "/api/v1/channels").await;

    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn a_replayed_read_is_refused_the_second_time() {
    let server = TestServer::builder().require_authenticated_reads(true).build();
    let caller = server.new_identity();
    let proof = server.build_proof(&caller, "GET", "/api/v1/channels", b"");

    let (first, _) = server.get_with_proof("/api/v1/channels", &proof).await;
    assert_eq!(first, StatusCode::OK, "precondition: the first read succeeds");

    let (second, body) = server.get_with_proof("/api/v1/channels", &proof).await;
    assert_eq!(second, StatusCode::UNAUTHORIZED, "body={body}");
    assert_eq!(body["code"], "REPLAYED");
}

#[tokio::test]
async fn unsigned_reads_still_work_when_the_escape_hatch_is_set() {
    let server = TestServer::builder().require_authenticated_reads(false).build();
    let (status, _body) = unsigned_get(&server, "/api/v1/channels").await;

    assert_eq!(
        status,
        StatusCode::OK,
        "the migration escape hatch must restore pre-auth behaviour"
    );
}
```

- [ ] **Step 2: Write the test support module**

Create `repos/jig-server/tests/support/mod.rs`. Build it by following the existing helpers in `repos/jig-server/src/v0_0_2_admin.rs`'s test module — specifically `test_identity`, `post_json`, and the router construction — which already solve identity creation and request plumbing for this codebase. Mirror those rather than inventing a second style.

The module must expose: `TestServer` (with a `builder()` taking `require_authenticated_reads`), `TestServer::new_identity`, `TestServer::build_proof`, `TestServer::get_with_proof`, plus free functions `signed_get` and `unsigned_get` returning `(StatusCode, serde_json::Value)`.

`build_proof` constructs an `AuthProof` exactly as `authenticate.rs`'s test helper does: hash with `canonical_request_hash`, sign the hash bytes, and carry the DID, HLC and nonce.

- [ ] **Step 3: Run the tests to verify they fail**

Run:
```bash
cd repos && cargo +stable nextest run -p jig-server --test authenticated_reads
```

Expected: all four fail — the read handlers do not authenticate yet.

- [ ] **Step 4: Carry the proof over HTTP headers**

Add to `repos/jig-server/src/auth/authenticate.rs`:

```rust
/// Header names carrying a tier-0 proof over HTTP.
///
/// HTTP-specific by necessity; the *verification* is not, which is what keeps
/// the design transport-agnostic. A future SSH or gRPC transport carries the
/// same four values however it can and calls the same [`authenticate`].
pub mod headers {
    pub const DID: &str = "x-jig-did";
    pub const HLC_WALL_MS: &str = "x-jig-hlc-wall-ms";
    pub const HLC_LOGICAL: &str = "x-jig-hlc-logical";
    pub const NONCE: &str = "x-jig-nonce";
    pub const SIGNATURE: &str = "x-jig-signature";
}

/// Extract a proof from HTTP headers, if one is present and well-formed.
///
/// Returns `None` when no proof was offered at all, which the caller maps to
/// [`GateOutcome::AuthMissing`]. A malformed proof is also `None`: telling an
/// unauthenticated caller precisely which header they got wrong is detail they
/// have not earned.
pub fn proof_from_headers(headers: &axum::http::HeaderMap) -> Option<AuthProof> {
    use base64::Engine as _;

    let get = |name: &str| headers.get(name)?.to_str().ok();

    let did = Did::from_did_jig_string(get(headers::DID)?).ok()?;
    let hlc_wall_ms = get(headers::HLC_WALL_MS)?.parse().ok()?;
    let hlc_logical = get(headers::HLC_LOGICAL)?.parse().ok()?;
    let nonce = get(headers::NONCE)?.to_string();
    let signature = base64::engine::general_purpose::STANDARD
        .decode(get(headers::SIGNATURE)?)
        .ok()?;

    Some(AuthProof {
        did,
        hlc_wall_ms,
        hlc_logical,
        nonce,
        signature,
    })
}
```

- [ ] **Step 5: Add the guard and policy to `AppState`**

In `repos/jig-server/src/v0_0_2.rs`, add to the `AppState` struct:

```rust
    /// Replay defence for tier-0 reads. `Mutex` rather than `RwLock`: every
    /// check mutates, so a read lock would never be taken.
    pub replay_guard: std::sync::Mutex<crate::auth::ReplayGuard>,
    /// How much of a refusal's truth this server discloses.
    pub disclosure: crate::auth::DisclosurePolicy,
    /// Whether reads must carry a proof of possession.
    pub require_authenticated_reads: bool,
```

Initialise them wherever `AppState` is constructed, from `JigServerConfig::auth`. Find every construction site with:

```bash
grep -rn 'AppState {' repos/jig-server/src/ | grep -v test
```

- [ ] **Step 6: Gate the read handlers**

In `repos/jig-server/src/v0_0_2_blocks.rs`, add a helper and call it at the top of both `list_channels` and `get_channel_history`:

```rust
/// Run gate 1 for a read, returning the authenticated DID.
///
/// Returns the disclosure-mapped error body on refusal, so no handler decides
/// for itself how much of the truth to tell.
fn authenticate_read(
    state: &AppState,
    headers: &axum::http::HeaderMap,
    method: &str,
    path: &str,
    started: std::time::Instant,
) -> Result<Option<jig_core::did::Did>, (StatusCode, Json<ErrorBody>)> {
    if !state.require_authenticated_reads {
        return Ok(None);
    }

    let proof = match crate::auth::authenticate::proof_from_headers(headers) {
        Some(p) => p,
        None => return Err(refuse(state, &crate::auth::GateOutcome::AuthMissing, started)),
    };

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    let mut guard = state
        .replay_guard
        .lock()
        .expect("replay guard mutex poisoned");

    match crate::auth::authenticate(&proof, method, path, b"", now_ms, &mut guard) {
        Ok(did) => Ok(Some(did)),
        Err(outcome) => Err(refuse(state, &outcome, started)),
    }
}

/// Map a gate outcome to a response through this server's disclosure policy,
/// logging the true outcome regardless of what the policy emits.
///
/// **This is the single disclosure point.** Every refusal in the read path
/// routes through here, which is what lets a concealing policy be added later
/// without editing call sites — and what gives the timing mitigation somewhere
/// to live.
///
/// `started` is the instant the request began handling. It is unused today and
/// deliberately so: gates refuse at different depths, so a future
/// constant-time mitigation must know how long the request has already taken in
/// order to pad to a fixed floor. Threading it now costs one parameter; adding
/// it later would mean touching every call site again, which is the exact
/// retrofit this design exists to avoid.
fn refuse(
    state: &AppState,
    outcome: &crate::auth::GateOutcome,
    started: std::time::Instant,
) -> (StatusCode, Json<ErrorBody>) {
    let _ = started; // see doc comment: reserved for timing normalization
    tracing::info!(audit = %crate::auth::audit_line(outcome), "request refused");

    let (status, code, message) = state.disclosure.disclose(outcome);
    let status = StatusCode::from_u16(status).unwrap_or(StatusCode::FORBIDDEN);
    err(status, code, message)
}
```

Then change both handlers to take `headers: axum::http::HeaderMap` as an extractor and call `authenticate_read` first.

**Bind the result as `caller_did`, exactly that name:**

```rust
    // Captured at the top of the handler, before any gate runs, so `refuse`
    // can pad to a constant-time floor when that mitigation lands.
    let started = std::time::Instant::now();

    // Phase 3 consumes this to enforce membership. `None` means the server is
    // running with require_authenticated_reads = false.
    let caller_did = authenticate_read(&state, &headers, "GET", "/api/v1/channels", started)?;
```

For `get_channel_history`, pass that handler's own method and path — the path must be the one the caller actually requested, including the encoded slug, or the recomputed hash will not match the signature.

Phase 3's tasks are written against `caller_did` in both handlers. Naming it anything else here — `_caller`, `did`, `authenticated` — means phase 3's code blocks will not compile when pasted in. Rust will warn that it is unused in this phase; that warning is expected and is resolved by phase 3, so do **not** silence it with an underscore prefix or `#[allow(unused)]` in a way that changes the binding's name.

If `-D warnings` fails the build on the unused binding, prefix the *use* rather than the name — add a temporary `let _ = &caller_did;` line with a comment naming phase 3, and delete that line in phase 3 task 3.

- [ ] **Step 7: Run the tests to verify they pass**

Run:
```bash
cd repos && cargo +stable nextest run -p jig-server
```

Expected: all pass, including the four new integration tests.

- [ ] **Step 8: Verify the whole workspace**

Run:
```bash
cd repos && cargo +stable fmt --all && cargo +stable clippy -p jig-core -p jig-config -p jig-server --all-targets -- -D warnings && cargo +stable nextest run
```

Expected: fmt clean, clippy silent, full suite green.

- [ ] **Step 9: Commit**

```bash
git add -A
git commit -m "feat(jig-server): require proof of possession on REST reads

list_channels and get_channel_history now run gate 1. An unsigned read is
401 AUTH_REQUIRED; a replayed one is 401 REPLAYED even though its signature
is genuine.

Refusals route through the disclosure policy rather than each handler
choosing its own status, and the true outcome is logged whatever the policy
emits. require_authenticated_reads = false restores the old behaviour for
migrating an existing deployment.

The authenticated DID is not consumed yet — phase 3 uses it to enforce
membership. Bound explicitly rather than discarded so the seam is visible."
```

---

## Phase 2 exit criteria

- [ ] `canonical_request_hash` covers every field, is length-prefixed, and is domain-separated from block signing.
- [ ] A signature bound to one path does not authenticate another.
- [ ] A replayed request is refused despite a genuine signature.
- [ ] A stale request is refused and does **not** consume replay-guard capacity.
- [ ] A malformed DID is refused, never panicked on.
- [ ] Replay guard memory is capped by capacity under flood, evicting oldest-first.
- [ ] `require_authenticated_reads` defaults to **true**.
- [ ] Full suite green; clippy clean across all 11 crates on stable.
