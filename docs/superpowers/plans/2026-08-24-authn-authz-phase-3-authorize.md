# Authn/Authz Phase 3: Authorization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `visibility = "restricted"` mean what the CLI already claims it means — membership-gated reads — across history, channel listing, and live WSS delivery.

**Architecture:** A single `authorize_read` decision consumes the DID phase 2 authenticated and the channel's stored visibility and membership. It is called from three places that currently have no access control: timeline reads, channel listing, and fanout delivery. The fanout case requires subscriptions to remember who subscribed, so authorization can be re-evaluated on every delivery rather than trusted from subscribe time.

**Tech Stack:** Rust 2024, axum 0.7, rusqlite, tokio, `cargo nextest`.

**Spec:** [`docs/superpowers/specs/2026-08-24-jig-server-authn-authz-design.md`](../specs/2026-08-24-jig-server-authn-authz-design.md)

**Depends on:** Phases 1 and 2 must be merged first. This phase consumes the `Did` that phase 2's `authenticate_read` returns.

**Working directory:** All `cargo` commands run from `repos/`. Use `cargo +stable` for clippy.

**Completing this phase closes `RELEASE_READINESS.md` blocker #1.**

---

### Task 1: Membership lookup

**The trap in this task:** memberships are keyed by the channel's **CID**, not its slug. There is a regression test at `repos/jig-pipeline/src/ingest.rs:1076` recording exactly that, because it has been got wrong before. A lookup that passes a slug to `list_members` compiles, returns an empty list, and silently denies every member.

**Files:**
- Modify: `repos/jig-pipeline/src/persist.rs`
- Test: inline `#[cfg(test)]` in `persist.rs`

- [ ] **Step 1: Write the failing test**

Add to the existing `mod tests` in `repos/jig-pipeline/src/persist.rs`:

```rust
    #[test]
    fn is_member_finds_a_member_by_slug() {
        let store = Store::open_in_memory().unwrap();
        store
            .upsert_channel(&StoredChannel {
                id: "bafychannelcid".to_string(),
                slug: "#private".to_string(),
                visibility: "restricted".to_string(),
                created_at: 0,
                owner_did: "did:jig:owner".to_string(),
            })
            .unwrap();
        store
            .upsert_membership(&StoredMembership {
                channel_id: "bafychannelcid".to_string(),
                member_did: "did:jig:member".to_string(),
                added_at: 0,
            })
            .unwrap();

        assert!(store.is_member("#private", "did:jig:member").unwrap());
        assert!(!store.is_member("#private", "did:jig:stranger").unwrap());
    }

    /// The regression this method exists to prevent: memberships are keyed by
    /// the channel's CID, not its slug. A lookup that forwards the slug
    /// straight to the memberships table compiles, returns nothing, and denies
    /// every legitimate member.
    #[test]
    fn is_member_resolves_slug_to_channel_id_first() {
        let store = Store::open_in_memory().unwrap();
        store
            .upsert_channel(&StoredChannel {
                id: "bafyrealcid".to_string(),
                slug: "#private".to_string(),
                visibility: "restricted".to_string(),
                created_at: 0,
                owner_did: "did:jig:owner".to_string(),
            })
            .unwrap();
        // Membership stored against the CID, which is how effect.rs writes it.
        store
            .upsert_membership(&StoredMembership {
                channel_id: "bafyrealcid".to_string(),
                member_did: "did:jig:member".to_string(),
                added_at: 0,
            })
            .unwrap();

        assert!(
            store.is_member("#private", "did:jig:member").unwrap(),
            "is_member must resolve the slug to the channel id before querying \
             memberships — see the CID-keying regression at ingest.rs:1076"
        );
    }

    #[test]
    fn is_member_is_false_for_an_unknown_channel() {
        let store = Store::open_in_memory().unwrap();
        assert!(!store.is_member("#nope", "did:jig:anyone").unwrap());
    }

    #[test]
    fn channel_by_slug_returns_visibility_and_owner() {
        let store = Store::open_in_memory().unwrap();
        store
            .upsert_channel(&StoredChannel {
                id: "bafycid".to_string(),
                slug: "#open".to_string(),
                visibility: "open".to_string(),
                created_at: 0,
                owner_did: "did:jig:owner".to_string(),
            })
            .unwrap();

        let ch = store.channel_by_slug("#open").unwrap().expect("channel exists");
        assert_eq!(ch.visibility, "open");
        assert_eq!(ch.owner_did, "did:jig:owner");
        assert!(store.channel_by_slug("#missing").unwrap().is_none());
    }
```

If `Store::open_in_memory`, `upsert_channel`, or the `StoredMembership` field names differ from the above, match whatever the existing tests in that file already use — do not invent a second convention.

- [ ] **Step 2: Run the tests to verify they fail**

Run:
```bash
cd repos && cargo +stable nextest run -p jig-pipeline --lib persist
```

Expected: compile error — `is_member` and `channel_by_slug` are not defined.

- [ ] **Step 3: Write the implementation**

Add to the `impl Store` block in `repos/jig-pipeline/src/persist.rs`, next to `list_members`:

```rust
    /// Look up a channel by its slug.
    pub fn channel_by_slug(&self, slug: &str) -> Result<Option<StoredChannel>> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let mut stmt = conn.prepare(
            "SELECT id, slug, visibility, created_at, owner_did \
             FROM channels WHERE slug = ?1",
        )?;
        let mut rows = stmt.query([slug])?;
        match rows.next()? {
            Some(row) => Ok(Some(StoredChannel {
                id: row.get(0)?,
                slug: row.get(1)?,
                visibility: row.get(2)?,
                created_at: row.get(3)?,
                owner_did: row.get(4)?,
            })),
            None => Ok(None),
        }
    }

    /// Whether `member_did` is a member of the channel with this slug.
    ///
    /// Resolves the slug to the channel's **id (its CID)** first, because
    /// memberships are keyed by CID and not by slug — passing a slug straight
    /// to the memberships table compiles, matches nothing, and silently denies
    /// every real member. See the regression test at `ingest.rs:1076`.
    pub fn is_member(&self, slug: &str, member_did: &str) -> Result<bool> {
        // `channel_by_slug` takes and releases the lock before returning, so
        // acquiring it below is safe. Do NOT inline that call's body here while
        // holding the guard: std::sync::Mutex is not reentrant and it would
        // deadlock on the second acquire.
        let Some(channel) = self.channel_by_slug(slug)? else {
            return Ok(false);
        };
        let conn = self.conn.lock().expect("store mutex poisoned");
        let mut stmt = conn.prepare(
            "SELECT 1 FROM memberships WHERE channel_id = ?1 AND member_did = ?2 LIMIT 1",
        )?;
        let mut rows = stmt.query([channel.id.as_str(), member_did])?;
        Ok(rows.next()?.is_some())
    }
```

Match the surrounding code's connection-access idiom exactly — read `list_members` immediately above and follow whatever it does for locking and error handling.

- [ ] **Step 4: Run the tests to verify they pass**

Run:
```bash
cd repos && cargo +stable nextest run -p jig-pipeline --lib persist
```

Expected: 4 new tests pass.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat(jig-pipeline): channel_by_slug and is_member lookups

Membership reads for authorization. is_member resolves the slug to the
channel's CID before querying, because memberships are keyed by CID — a
lookup that forwards the slug straight through compiles, matches nothing,
and silently denies every real member. The regression test says so
explicitly so the next person does not rediscover it."
```

---

### Task 2: The authorize gate

**Files:**
- Create: `repos/jig-server/src/auth/authorize.rs`
- Modify: `repos/jig-server/src/auth/mod.rs`
- Test: inline `#[cfg(test)]` in `authorize.rs`

- [ ] **Step 1: Write the failing test**

Create `repos/jig-server/src/auth/authorize.rs` containing ONLY the test module:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_open_channel_is_readable_by_any_admitted_caller() {
        assert_eq!(
            authorize_read(Visibility::Open, false, false),
            Ok(())
        );
    }

    #[test]
    fn a_restricted_channel_is_readable_by_a_member() {
        assert_eq!(
            authorize_read(Visibility::Restricted, true, false),
            Ok(())
        );
    }

    #[test]
    fn a_restricted_channel_refuses_a_non_member() {
        assert_eq!(
            authorize_read(Visibility::Restricted, false, false),
            Err(GateOutcome::AuthzNotMember)
        );
    }

    /// An owner who never added themselves as a member must still be able to
    /// read their own channel. Otherwise creating a restricted channel locks
    /// out its creator, which would look like data loss.
    #[test]
    fn a_restricted_channel_is_readable_by_its_owner() {
        assert_eq!(
            authorize_read(Visibility::Restricted, false, true),
            Ok(())
        );
    }

    /// An unrecognised visibility string must fail closed. The column is a
    /// free-form TEXT field, so a typo or a value written by a future version
    /// must deny rather than silently grant.
    #[test]
    fn an_unknown_visibility_string_fails_closed() {
        assert_eq!(
            Visibility::parse("banana"),
            Visibility::Restricted,
            "an unrecognised visibility must be treated as the closed case"
        );
        assert_eq!(
            authorize_read(Visibility::parse("banana"), false, false),
            Err(GateOutcome::AuthzNotMember)
        );
    }

    #[test]
    fn visibility_parses_the_two_known_values() {
        assert_eq!(Visibility::parse("open"), Visibility::Open);
        assert_eq!(Visibility::parse("restricted"), Visibility::Restricted);
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run:
```bash
cd repos && cargo +stable nextest run -p jig-server --lib auth::authorize
```

Expected: compile error — `Visibility` and `authorize_read` are not defined.

- [ ] **Step 3: Write the implementation**

Prepend to `repos/jig-server/src/auth/authorize.rs`:

```rust
//! Gate 3: may this caller do this, here?
//!
//! Deliberately a pure function of already-fetched facts rather than something
//! that queries the store itself. Two reasons: it is trivially testable without
//! a database, and the fanout path must call it per delivery, where doing I/O
//! inside the decision would be a performance problem.

use crate::auth::GateOutcome;

/// A channel's read policy.
///
/// The stored column is free-form `TEXT`, so parsing must be total.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Visibility {
    /// Readable by any admitted caller.
    Open,
    /// Readable only by members and the owner.
    Restricted,
}

impl Visibility {
    /// Parse a stored visibility string, **failing closed**.
    ///
    /// Anything not recognised is treated as `Restricted`. A typo, or a value
    /// written by a newer version of the server, must deny rather than grant —
    /// the failure mode of guessing wrong in the other direction is silently
    /// publishing a private channel.
    pub fn parse(raw: &str) -> Self {
        match raw {
            "open" => Visibility::Open,
            _ => Visibility::Restricted,
        }
    }
}

/// Decide whether a caller may read a channel.
///
/// `is_member` and `is_owner` are supplied by the caller so this stays pure.
/// The owner check is not a convenience: an owner who never added themselves to
/// the memberships table would otherwise be locked out of the channel they
/// created, which presents as data loss rather than as a permissions error.
pub fn authorize_read(
    visibility: Visibility,
    is_member: bool,
    is_owner: bool,
) -> Result<(), GateOutcome> {
    match visibility {
        Visibility::Open => Ok(()),
        Visibility::Restricted if is_member || is_owner => Ok(()),
        Visibility::Restricted => Err(GateOutcome::AuthzNotMember),
    }
}
```

Add to `repos/jig-server/src/auth/mod.rs`:

```rust
pub mod authorize;

pub use authorize::{Visibility, authorize_read};
```

- [ ] **Step 4: Run the tests to verify they pass**

Run:
```bash
cd repos && cargo +stable nextest run -p jig-server --lib auth::authorize
```

Expected: 6 tests pass.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat(jig-server): authorize_read gate

A pure function of already-fetched facts, so it is testable without a
database and cheap enough for the fanout path to call per delivery.

Visibility parsing fails closed: the stored column is free-form TEXT, and an
unrecognised value must deny rather than grant, because guessing wrong in
the other direction silently publishes a private channel. The owner is
allowed even without a membership row — otherwise creating a restricted
channel locks out its creator, which presents as data loss."
```

---

### Task 3: Enforce on timeline reads

**Files:**
- Modify: `repos/jig-server/src/v0_0_2_blocks.rs` (`get_channel_history`)
- Test: `repos/jig-server/tests/restricted_reads.rs` (create)

- [ ] **Step 1: Write the failing integration test**

Create `repos/jig-server/tests/restricted_reads.rs`:

```rust
//! `visibility = "restricted"` gates reads, as the CLI has always claimed.

use axum::http::StatusCode;

mod support;
use support::{TestServer, signed_get};

#[tokio::test]
async fn a_non_member_cannot_read_a_restricted_channel() {
    let server = TestServer::builder().require_authenticated_reads(true).build();
    let owner = server.new_identity();
    let stranger = server.new_identity();
    server.create_channel(&owner, "#private", "restricted").await;

    let (status, body) =
        signed_get(&server, &stranger, "/api/v1/channels/%23private/blocks").await;

    assert_eq!(status, StatusCode::FORBIDDEN, "body={body}");
    assert_eq!(body["code"], "NOT_A_MEMBER");
}

#[tokio::test]
async fn a_member_can_read_a_restricted_channel() {
    let server = TestServer::builder().require_authenticated_reads(true).build();
    let owner = server.new_identity();
    let member = server.new_identity();
    server.create_channel(&owner, "#private", "restricted").await;
    server.add_member(&owner, "#private", &member).await;

    let (status, _body) =
        signed_get(&server, &member, "/api/v1/channels/%23private/blocks").await;

    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn an_owner_can_read_their_own_restricted_channel() {
    let server = TestServer::builder().require_authenticated_reads(true).build();
    let owner = server.new_identity();
    server.create_channel(&owner, "#private", "restricted").await;

    let (status, _body) =
        signed_get(&server, &owner, "/api/v1/channels/%23private/blocks").await;

    assert_eq!(
        status,
        StatusCode::OK,
        "an owner must not be locked out of the channel they created"
    );
}

#[tokio::test]
async fn an_open_channel_is_readable_by_any_authenticated_caller() {
    let server = TestServer::builder().require_authenticated_reads(true).build();
    let owner = server.new_identity();
    let stranger = server.new_identity();
    server.create_channel(&owner, "#open", "open").await;

    let (status, _body) =
        signed_get(&server, &stranger, "/api/v1/channels/%23open/blocks").await;

    assert_eq!(status, StatusCode::OK);
}
```

Extend `repos/jig-server/tests/support/mod.rs` (created in phase 2) with `create_channel` and `add_member`, built on the admin endpoints the way `v0_0_2_admin.rs`'s tests already do.

- [ ] **Step 2: Run the tests to verify they fail**

Run:
```bash
cd repos && cargo +stable nextest run -p jig-server --test restricted_reads
```

Expected: `a_non_member_cannot_read_a_restricted_channel` fails — it currently returns 200 with the full timeline.

- [ ] **Step 3: Write the implementation**

In `get_channel_history` in `repos/jig-server/src/v0_0_2_blocks.rs`, after the phase-2 authentication call, add:

```rust
    // Gate 3. Runs before any block is fetched, so a refusal cannot be
    // distinguished from an empty channel by response size.
    if let Some(caller) = caller_did.as_ref() {
        let channel = state
            .ingest_ctx
            .store
            .channel_by_slug(&slug)
            .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, "PERSIST_ERROR", e.to_string()))?;

        let Some(channel) = channel else {
            return Err(refuse(&state, &crate::auth::GateOutcome::AuthzChannelUnknown, started));
        };

        let is_member = state
            .ingest_ctx
            .store
            .is_member(&slug, caller.as_str())
            .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, "PERSIST_ERROR", e.to_string()))?;
        let is_owner = channel.owner_did == caller.as_str();

        if let Err(outcome) = crate::auth::authorize_read(
            crate::auth::Visibility::parse(&channel.visibility),
            is_member,
            is_owner,
        ) {
            return Err(refuse(&state, &outcome, started));
        }
    }
```

- [ ] **Step 4: Run the tests to verify they pass**

Run:
```bash
cd repos && cargo +stable nextest run -p jig-server --test restricted_reads
```

Expected: all 4 pass.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat(jig-server): enforce visibility on channel history reads

--visibility restricted has advertised 'membership-gated reads' in the CLI's
help text since it shipped, while the flag was stored and never read. It is
now true: a non-member gets 403 NOT_A_MEMBER, a member and the owner get the
timeline.

The check runs before any block is fetched, so a refusal cannot be
distinguished from an empty channel by response size."
```

---

### Task 4: Filter the channel listing

`list_channels` takes only `State` — no caller identity reaches it — and returns `slug`, `visibility` **and `owner_did`** for every channel on the server. It discloses who owns each restricted channel, not merely that one exists. Any 404-style concealment elsewhere is theatre while this stands.

**Files:**
- Modify: `repos/jig-server/src/v0_0_2_blocks.rs` (`list_channels`)
- Test: `repos/jig-server/tests/restricted_reads.rs`

- [ ] **Step 1: Write the failing test**

Append to `repos/jig-server/tests/restricted_reads.rs`:

```rust
#[tokio::test]
async fn the_channel_list_hides_restricted_channels_from_non_members() {
    let server = TestServer::builder().require_authenticated_reads(true).build();
    let owner = server.new_identity();
    let stranger = server.new_identity();
    server.create_channel(&owner, "#open", "open").await;
    server.create_channel(&owner, "#private", "restricted").await;

    let (status, body) = signed_get(&server, &stranger, "/api/v1/channels").await;
    assert_eq!(status, StatusCode::OK);

    let listed = body["channels"].as_array().expect("channels array");
    let slugs: Vec<&str> = listed.iter().filter_map(|c| c["slug"].as_str()).collect();

    assert!(slugs.contains(&"#open"), "open channels stay visible: {slugs:?}");
    assert!(
        !slugs.contains(&"#private"),
        "a restricted channel must not be listed to a non-member — listing it \
         leaks both its existence and its owner_did: {slugs:?}"
    );
}

#[tokio::test]
async fn the_channel_list_shows_restricted_channels_to_their_members() {
    let server = TestServer::builder().require_authenticated_reads(true).build();
    let owner = server.new_identity();
    let member = server.new_identity();
    server.create_channel(&owner, "#private", "restricted").await;
    server.add_member(&owner, "#private", &member).await;

    let (status, body) = signed_get(&server, &member, "/api/v1/channels").await;
    assert_eq!(status, StatusCode::OK);

    let listed = body["channels"].as_array().expect("channels array");
    let slugs: Vec<&str> = listed.iter().filter_map(|c| c["slug"].as_str()).collect();
    assert!(slugs.contains(&"#private"), "members see their channels: {slugs:?}");
}
```

Adjust `body["channels"]` to match whatever `ChannelsResponse` actually serializes — read the struct before writing the assertion.

- [ ] **Step 2: Run the tests to verify they fail**

Run:
```bash
cd repos && cargo +stable nextest run -p jig-server --test restricted_reads
```

Expected: `the_channel_list_hides_restricted_channels_from_non_members` fails — `#private` is listed.

- [ ] **Step 3: Write the implementation**

Replace the mapping in `list_channels` so each channel runs the same decision:

```rust
    let channels = stored
        .into_iter()
        .filter(|c| match caller_did.as_ref() {
            // Unauthenticated mode (the migration escape hatch) lists
            // everything, exactly as before this phase.
            None => true,
            Some(caller) => {
                let is_owner = c.owner_did == caller.as_str();
                let is_member = state
                    .ingest_ctx
                    .store
                    .is_member(&c.slug, caller.as_str())
                    .unwrap_or(false);
                crate::auth::authorize_read(
                    crate::auth::Visibility::parse(&c.visibility),
                    is_member,
                    is_owner,
                )
                .is_ok()
            }
        })
        .map(|c| ChannelView {
            slug: c.slug,
            visibility: c.visibility,
            owner_did: c.owner_did,
            created_at: c.created_at,
        })
        .collect();
```

Note `unwrap_or(false)`: a store error while listing must hide the channel, not reveal it. This is the same fail-closed reasoning as `Visibility::parse`.

- [ ] **Step 4: Run the tests to verify they pass**

Run:
```bash
cd repos && cargo +stable nextest run -p jig-server --test restricted_reads
```

Expected: all 6 pass.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat(jig-server): filter the channel listing by read authorization

list_channels took only State — no caller identity reached it — and returned
slug, visibility AND owner_did for every channel, disclosing who owns each
restricted channel rather than merely that one exists. Any concealment
elsewhere was theatre while this stood.

Each channel now runs the same authorize_read decision as a timeline read. A
store error during listing hides the channel rather than revealing it, the
same fail-closed direction as unknown visibility strings."
```

---

### Task 5: Re-check authorization at delivery

A subscription authorized once at `Frame::Subscribe` keeps delivering for the whole connection lifetime. If membership is revoked, or a channel flips to restricted, a long-lived connection keeps receiving — revocation silently fails for exactly the users an operator most wants to cut off.

Fanout subscriptions currently carry no identity at all: `subscribe_local(scope, tx)`. They must remember who subscribed so the decision can be re-run per delivery.

**Files:**
- Modify: `repos/jig-pipeline/src/fanout.rs`
- Modify: `repos/jig-server/src/v0_0_2_ws.rs`
- Test: `repos/jig-server/tests/revocation.rs` (create)

- [ ] **Step 1: Write the failing test**

Create `repos/jig-server/tests/revocation.rs`:

```rust
//! Revoking membership must stop delivery on an already-open subscription.

mod support;
use support::TestServer;

#[tokio::test]
async fn revoking_membership_stops_delivery_on_a_live_subscription() {
    let server = TestServer::builder().require_authenticated_reads(true).build();
    let owner = server.new_identity();
    let member = server.new_identity();
    server.create_channel(&owner, "#private", "restricted").await;
    server.add_member(&owner, "#private", &member).await;

    let mut sub = server.subscribe_ws(&member, "#private").await;

    server.post_text_block(&owner, "#private", "before revocation").await;
    let first = sub.next_block().await;
    assert!(
        first.is_some(),
        "precondition: a member must receive blocks before revocation"
    );

    server.remove_member(&owner, "#private", &member).await;
    server.post_text_block(&owner, "#private", "after revocation").await;

    assert!(
        sub.next_block_timeout().await.is_none(),
        "delivery must stop after revocation — a subscription authorized once \
         at subscribe time keeps delivering to revoked members forever"
    );
}
```

Extend `tests/support/mod.rs` with `subscribe_ws` (returning a handle exposing `next_block` and a timeout variant), `post_text_block`, and `remove_member`. Build the WSS client on the existing pattern in `v0_0_2_ws.rs`'s own test module rather than a new one.

- [ ] **Step 2: Run the test to verify it fails**

Run:
```bash
cd repos && cargo +stable nextest run -p jig-server --test revocation
```

Expected: fails — the block after revocation is still delivered.

- [ ] **Step 3: Give subscriptions an identity**

In `repos/jig-pipeline/src/fanout.rs`, change `subscribe_local` to record the subscriber:

```rust
    /// Register a local subscriber.
    ///
    /// `subscriber_did` is retained so authorization can be re-evaluated on
    /// every delivery. Authorizing once at subscribe time would mean a
    /// revoked member keeps receiving for as long as their connection lives —
    /// which is precisely the person an operator revoking access wants to cut
    /// off. `None` means an unauthenticated subscriber, only possible when the
    /// server runs with the migration escape hatch set.
    pub async fn subscribe_local(
        &self,
        scope: SubscriptionScope,
        subscriber_did: Option<String>,
        tx: DeliverySender,
    ) -> u64 {
```

Store `subscriber_did` alongside the scope and sender in whatever structure `subscribe_local` currently pushes into, and expose it to the broadcast path.

- [ ] **Step 4: Filter at delivery**

In the broadcast path, before sending to each local subscriber, skip any subscriber whose authorization no longer holds. The delivery site needs a predicate rather than store access — pass one in from the server so `jig-pipeline` does not acquire a dependency on the server's auth module:

```rust
    /// Deliver to local subscribers that still pass `may_receive`.
    ///
    /// The predicate is supplied rather than computed here so this crate stays
    /// free of authorization policy: fanout knows who subscribed, the server
    /// knows what they may see.
    pub async fn broadcast_local_filtered(
        &self,
        block: &StoredBlock,
        receipt: &StoredReceipt,
        may_receive: &dyn Fn(Option<&str>, &str) -> bool,
    ) {
```

where the arguments to `may_receive` are the subscriber's DID and the channel slug.

- [ ] **Step 5: Supply the predicate from the server**

In `repos/jig-server/src/v0_0_2_ws.rs`, pass a closure that runs the same `authorize_read` decision used by the REST path, resolving visibility and membership from the store per delivery.

Update the `Frame::Subscribe` arm to pass the authenticated DID into `subscribe_local`.

- [ ] **Step 6: Run the tests to verify they pass**

Run:
```bash
cd repos && cargo +stable nextest run -p jig-server --test revocation
```

Expected: passes.

- [ ] **Step 7: Run the full suite and lints**

Run:
```bash
cd repos && cargo +stable fmt --all && cargo +stable clippy -p jig-core -p jig-config -p jig-pipeline -p jig-server --all-targets -- -D warnings && cargo +stable nextest run
```

Expected: fmt clean, clippy silent, full suite green.

- [ ] **Step 8: Commit**

```bash
git add -A
git commit -m "feat: re-check read authorization at fanout delivery

A subscription authorized once at Frame::Subscribe kept delivering for the
whole connection lifetime, so revoking a membership did nothing to an open
connection — failing for exactly the user an operator revoking access most
wants to cut off. Subscriptions now carry the subscriber's DID and the
decision is re-run per delivery.

The predicate is supplied by the server rather than computed in
jig-pipeline: fanout knows who subscribed, the server knows what they may
see, and the dependency direction stays intact."
```

---

### Task 6: Correct the documentation this phase makes false

**Files:**
- Modify: `deploy/README.md`
- Modify: `docs/RELEASE_READINESS.md`

- [ ] **Step 1: Update the deployment security posture**

`deploy/README.md` states "the tailnet IS the authentication". Replace it with a description of the actual model: reads require proof of possession, restricted channels are membership-gated, and network placement is defence in depth rather than the only defence.

- [ ] **Step 2: Update the readiness verdict**

In `docs/RELEASE_READINESS.md`, update sections 1.1 and 1.2 from BLOCKER, noting what now holds and what does not — admission policy (phase 4) and trusted connections (phase 5) are still outstanding, and E2EE remains a separate blocker. Do not mark the overall verdict ready; other blockers remain.

- [ ] **Step 3: Commit**

```bash
git add -A
git commit -m "docs: jig-server no longer relies on network placement for access control

Reads require proof of possession and restricted channels are
membership-gated, so 'the tailnet IS the authentication' is no longer true.
RELEASE_READINESS sections 1.1 and 1.2 updated; admission policy and trusted
connections are still outstanding, and E2EE remains a separate blocker."
```

---

## Phase 3 exit criteria

- [ ] A non-member reading a restricted channel gets 403 `NOT_A_MEMBER`.
- [ ] A member and the owner can both read it; the owner needs no membership row.
- [ ] `list_channels` hides restricted channels — and their `owner_did` — from non-members.
- [ ] Unknown visibility strings and store errors both fail **closed**.
- [ ] Revoking membership stops delivery on an already-open WSS subscription.
- [ ] `deploy/README.md` no longer claims the tailnet is the authentication.
- [ ] Full suite green; clippy clean across all 11 crates on stable.
- [ ] **`RELEASE_READINESS.md` blocker #1 is closed.**
