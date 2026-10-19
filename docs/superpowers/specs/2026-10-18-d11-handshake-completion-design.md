# D11: handshake completion

**Date:** 2026-10-18
**Author:** DJ + Claude (lane L7)
**Status:** Decisions settled with DJ in the 2026-10-18 design Q&A; this write-up is under
review. No code yet. The build plan follows in `docs/superpowers/plans/`.
**Builds on:** [JEP-0002](../../../repos/jig-spec/jep/jep-0002-handshake.md), the
[threat register](../../../repos/jig-spec/src/threat-register.md) (OP-01, OP-02, OP-03,
OP-06, OP-08, TM-01, TM-02), the
[operator threat model](../../security/operator-threat-model.md), and the federation
contract design in draft jig-protocol/jig#106 (lane F, JEP-0005).

## Goal

Meet the v0.2 phase-1 exit criterion 3: **a hostile operator's downgrade or false
handshake is detected.** "Detected" means the client refuses to go on, and it keeps
evidence that anyone can check without trusting the client.

The work closes three gaps:

- **After the welcome, nothing is checked against it.** The client's reader drops
  frames it cannot parse (`jig-client/src/connection.rs`, the reader task). So a frame at
  a version or suite the welcome did not advertise is silently thrown away, when it
  should end the connection. Receipts are never checked against the welcome's
  `server_did`.
- **A server can drop, reorder or fork a channel's history** and leave no trace (OP-06).
  It can also move its clock to any time a block claims (TM-01). History is ordered by
  the author's own timestamp (TM-02).
- **A server can tell different clients different things** about what it supports.
  Pins catch a server that changes its story to one client. They do not catch two
  different stories told to two clients from the first contact.

## Scope

This is option **B′** of the design Q&A. The narrow set the criterion's wording needs,
plus the cheap ordering and replay fixes, plus one signed record per block:

| # | Item | Threats |
| --- | --- | --- |
| 1 | Which failures close a connection, and who closes it | OP-01 |
| 2 | One `hello` per connection | OP-01 |
| 3 | Later frames checked against the signed welcome | OP-02 |
| 4 | The client refuses a restricted channel that is not MLS | OP-03 |
| 5 | A per-channel `ingest` record, signed by the channel's owning server | OP-06, TM-02 |
| 6 | `seen` on authored blocks, and anonymous head gossip, to detect forks | OP-06 |
| 7 | Leave and remove blocks name the membership they end | OP-06 |
| 8 | A bound on how far ahead an author's clock may run | TM-01 |
| 9 | Evidence: a self-checking bundle, kept by the client; sticky refusals | OP-02 |
| 10 | No plaintext REST from the CLI, except to loopback | OP-08 |
| 11 | Name pinning, with rotations signed by the old key (lane F's rule) | OP-08 |
| 12 | A mutual server-to-server handshake, bound to the TLS session | OP-09 |
| 13 | A per-server manifest log that every welcome cites | OP-02, OP-03 |

### Out of scope, and where it goes

- **Binding the handshake transcript into MLS group joins** (JEP-0002 Q4). Item 12
  produces a transcript hash, which a later design can put into MLS joins.
- **A non-null `reputation`.** It stays `null` until JEP-0003 (OP-10).
- **A `render_hash` divergence becoming a refusal** (OP-07). This needs deterministic,
  portable fuel; it stays a warning.
- **Merkle logs with inclusion proofs and gossip.** This is the long-term direction for
  fork detection. It needs machinery v0.2 does not have.
- **Heads co-signed by several carriers** in high-sec federation, using federation as
  consensus. Item 6's limit is the hook.
- **An optional handshake-transcript channel** (see item 13). It is designed here and
  not built in v0.2.
- **Re-running the block that armed a timer**, before accepting its fire. This waits
  for lane A's block ABI.
- **Plaintext REST bound to the handshake.** For now plaintext REST is refused (item
  10). Extending the handshake to REST, through TLS and the DID, is later work.

---

## Decisions

### 1. Which failures close a connection

A failure falls into one of four classes, or is an ordinary error. The class decides
who closes the connection, whether anything is signed, and the WebSocket close code.

| Class | Examples | Who closes | Signed | Close code |
| --- | --- | --- | --- | --- |
| 1. Handshake failure | The welcome is missing, malformed, has a bad signature, a stale nonce or a DID other than the pinned one; it contradicts itself or the offer; it drops a pinned suite; it advertises a skew bound outside the protocol's range; the wait times out; a server dialer sends no `peer_proof` | The side that detects it, sending nothing more | — (the frame is kept as evidence) | 4001 |
| 2. Incompatible | No version or suite in common | The server, after a signed `refusal` naming what it supports | yes | 4002 |
| 3. Contradiction | A later frame at a version or suite the welcome did not advertise; an advertised capability refused; a receipt or `ingest` record signed by a key other than the expected one; a gap in `seq` or a broken `prev` chain; a fork shown by `seen` or by gossip; a block accepted outside the advertised skew bound; a welcome that does not match the manifest it cites | The client | evidence kept (item 9) | 4003 |
| 4. Protocol violation | A frame before `hello`; a second `hello`; a client frame outside the version or suite it offered | The server | — | 4004 |
| Ordinary error | Not a member, auth refused, duplicate block, bad block, rate limit, `CLOCK_SKEW`, a malformed frame after the handshake | Nobody: an error frame, and the connection stays open | | |

**Why classes, not "close on any failure".** JEP-0002's open question 6 was right that
closing on every refusal makes ordinary errors look like attacks. The socket staying
open is not what tells them apart, though. The class does, and so does who signed what.
After a version or suite refusal the open socket has no use: with one `hello` per
connection the client cannot try again on it.

**A signed refusal.** Today a version or suite refusal is an unsigned error frame and
leaves no evidence. A server that once advertised `mls` and now refuses it is
downgrading, and should have to sign that. The `refusal` frame is sealed like a
welcome, under its own domain tag `jig-handshake-refusal-v1`. It carries:

- the client's nonce;
- the refusal code;
- the versions and suites the server supports.

The client checks it against what it pinned: a pinned suite missing from a signed
refusal is a downgrade (class 3 evidence, not class 2).

**Changes from today:**

- **The server.** A frame before `hello` was answered with `HANDSHAKE_REQUIRED`, and
  the socket stayed open. Now the server sends that error and closes (4004).
  `UNSUPPORTED_VERSION` and `UNSUPPORTED_SUITE`, in answer to a `hello`, become a
  signed `refusal` and a close (4002).
- **The client.** `HandshakeResult::LeaveOpen` goes. It is replaced by an
  `Incompatible` result that carries the verified refusal.

### 2. One `hello` per connection

Today the server answers a repeat `hello` by signing a fresh welcome
(`v0_0_2_ws.rs`, `handle_text`). Under the new rule, a second `hello` is a class 4
protocol violation. A client that wants a new offer opens a new connection.

**Every connection runs the full handshake** (JEP-0002 Q2). No cached welcome is
reused. A capability change takes effect on new connections only: open connections
keep the welcome they were given (JEP-0002 Q3). The change is published in the
manifest log (item 13).

### 3. Later frames are checked against the welcome

After the welcome, the client's reader no longer drops frames it cannot parse. It
classifies them:

- **An envelope at a version or suite the welcome did not advertise** is a class 3
  contradiction. Today `Envelope::parse` refuses it, and the reader drops it.
- **A frame the client cannot parse at all** is an ordinary error, logged. A bad byte
  is not evidence of anything.
- **A refused advertised capability** is a class 3 contradiction: for example, a
  `KIND_NOT_ALLOWED` for a block kind the welcome listed in `capabilities.block_kinds`.
- **A `ReceiptRef` whose `server_did` is not the welcome's `server_did`** is a class 3
  contradiction. This covers receipts the connected server produced itself. A receipt
  a peer produced, relayed in federation, names the peer and is checked against that
  peer's pin instead.
- **An `ingest` record** is checked as in item 5.
- **A mid-session `welcome` frame** is a class 4 protocol violation from the server.
  The client treats it as a class 3 contradiction.

A client checks only against what the server signed. A newer client's own
expectations never count as a contradiction (item 9, rule 3).

### 4. A restricted channel must be MLS

D25 makes restricted channels always MLS. So a client that proves a channel from its
creation block (`pins::prove_channel`) refuses a restricted channel whose creation
block names `none`. This shrinks the first-look gap of OP-03 to a smaller one. A server
can still present a channel it made up itself, but it must then be:

- **open**, and readable by the server by definition; or
- **an MLS group the server owns.** This is impersonation of the channel under its
  name, not a downgrade.

Name pinning (item 11) and the `channel-create` CID as the channel's identity (item 5)
are what narrow impersonation further.

### 5. The `ingest` record

Every block in a channel gets one record, signed by the server that owns the channel.
Lane F's design (#106, section 5.2) fixes that a channel has exactly one owning server.
It alone accepts writes into the channel's history. Other servers the channel is
shared with ("carriers") relay writes to it and pass its records through unchanged.

**Fields:**

| Field | Content |
| --- | --- |
| `channel_id` | The CID of the channel's `channel-create` block. That CID alone identifies the channel; the owning server is a hint (F's decision, after Matrix room v12) |
| `seq` | 0 for the `channel-create` block, then +1 for each block the owner accepts |
| `ingest_hlc` | The owner's HLC when it accepted the block |
| `block_cid` | The block |
| `prev` | BLAKE3 hash of the previous record's canonical bytes; 32 zero bytes at `seq` 0 |
| `sequencer` | The DID that signs this record |
| `sig` | ed25519 by `sequencer` over the canonical bytes |

The canonical bytes are length-prefixed and domain-separated (`jig-ingest-v1`), in the
same style as `WelcomeStatement::canonical_bytes`.

**What it orders.** History is ordered by `seq`, not by the author's `hlc_ts`.
`ingest_hlc` is the time lanes A and C use when a block is run. It is also the clock
that time-based limits use (TM-01: the verifier's clock, not the claimant's).
`hlc_ts` stays as the author's claim. A client shows it as "written at", next to
"received at" (`ingest_hlc`), when the two differ by more than the skew bound.

**How it travels.** A `block` frame carries its record. A block the reader may not
read (for example, a pre-join block on an MLS channel) is delivered as a `record`
frame: the record without the block. Gap checks therefore still work. REST history
responses carry records too, so the chain is checkable whatever the transport.

**What the client checks**, per channel, keeping the last record it verified:

- the signature, by the expected sequencer;
- `seq` = last + 1;
- `prev` = the hash of the last record;
- `channel_id` = the pinned `channel-create` CID;
- `block_cid` = the CID of the block delivered with it;
- `ingest_hlc` does not go backwards;
- on live delivery, `ingest_hlc` is within the skew bound of the client's own clock.

**What failure means.** Each check that fails is a class 3 contradiction. A backfill
can start from the last verified record, or from `seq` 0, where the record is the
`channel-create` block's.

**The movable sequencer.** The owner can move the job of signing records to another
server, with a `sequencer-set` block. Only the owner may sign one in v0.2; it is an
owner-only right in F's role set (#106, sections 5.3 and 6).

- **The handover.** The block names the new sequencer's DID and the last record the
  old sequencer signed (the "cited head"). The record for the `sequencer-set` block is
  always signed by the **new** sequencer, at `seq` = cited head + 1, with `prev` = the
  cited head's hash. This holds whether the old sequencer is alive or dead, so a
  handover never looks like a fork (only one key signs any `seq`), and a dead sequencer
  cannot block it. This matches #106 and JEP-0005 item 11a.
- **Preconditions.** The new sequencer must have accepted the channel's federation
  contract first, and be on the operators' peer lists (F's rule).
- **The expected sequencer.** The `channel-create`'s server from `seq` 0, and the new
  sequencer from the `seq` of each `sequencer-set` record onward.

**A partitioned sequencer.** An old sequencer that is partitioned, not dead, can keep
signing records after the move. Carriers that hold the `sequencer-set` refuse its later
records:

- **Lost writes.** Blocks it accepted after the cited head are lost.
- **MLS state.** Members whose clients merged an MLS commit past the cited head rejoin
  by external commit.

This is bounded, because only the owner can trigger a move.

**Timer fires.** Lane C (#117) defines a `timer-fire` block kind:

- **Author.** The owning server's DID, through `ingest` like any block, so the fire
  gets a record.
- **What it cites.** `install`, the owner-signed block-install whose grant bounds
  `min_interval_ms` and `max_horizon_ms`; and `set_by`, the receipt of the run that
  armed the timer. It also carries `scheduled_at` and `tag`.

The record therefore stays blocks-only.

**Bots on a sequencer move.** Bot DIDs belong to the sequencer that runs them. The new
sequencer names fresh bot DIDs in its `contract-accept`, and the owner's
`sequencer-set` carries the reinstalls (agreed by F and C).

**What the client checks:**

- the fire's author is the expected sequencer;
- `scheduled_at` respects the install's grant;
- `ingest_hlc` is within the skew bound of `scheduled_at`.

**Accepted limits.** `set_by` is a receipt, so it is the server's word (OP-07), and the
grant only bounds how often and how far ahead a server can claim a timer. A server can
also delay a fire within the bound, or never fire at all. Checking that the arming run
really returned the `set-timer` effect, by running it again, waits for lane A.

### 6. Detecting a forked history

A server can keep two chains and show one to each group of members; each chain is
valid on its own. A fork is proven by two records signed by the same sequencer, for one
`channel_id` and one `seq`, with different contents. Whoever reports them does not
matter. Two paths carry records between members so that such a pair can meet.

**`seen` on authored blocks.** Every block a member writes into a channel carries
`seen`: the latest record the author verified for that channel. It is the full signed
record, about 200 bytes, not just its hash. A reader on the other side of a fork then
holds both conflicting records without having to ask anyone for the second. `seen` is
in the manifest, so it is plaintext even on an encrypted channel. It reveals only what
the server already knows: what it delivered to the author. A `channel-create` block has
no `seen`.

When a client receives a block whose `seen` is a record it can check:

- If `seen` conflicts with its own chain at that `seq`, that is a fork: class 3, and
  both records are the evidence.
- If `seen` is ahead of its own chain, the client is behind, and it fetches the missing
  records.
- If the server's own record for the block is earlier than the block's `seen`, the
  server is reordering: class 3.

**Anonymous head gossip.** A client sends its carrier a `head` frame holding the latest
record it verified for a channel, with no DID attached.

- **What the carrier does.** It verifies that the record is a valid record signed by
  the sequencer, which cannot be forged. It keeps the latest head per channel, and
  forwards it to the owning server and to the other carriers it links to.
- **What it costs in privacy.** The carrier learns nothing new: it delivered those
  records. Other servers learn that some reader on that carrier reached `seq` N, not
  who.
- **Spam** is limited to replaying real heads.
- **Withholding by a carrier** shows as "readers through carrier X are stuck at
  `seq` N", which needs no reader identity.

Members under a `read` grant author nothing, so they send no `seen`. They SHOULD send
anonymous `head` frames like any client: those are what catch a carrier withholding
from its own readers. Withholding by the sequencer from them is detected through `seen`
on blocks other members write (F's design, JEP-0005 items 11a and 14a).

**The limit, stated in JEP-0002.** Gossip that passes only through the sequencer cannot
catch the sequencer. Records must cross by paths the sequencer does not control:

- `seen` on another member's block (the reliable path);
- a client on two carriers;
- direct links between carriers.

So withholding from a whole carrier is detected only once a member on another carrier
posts, and a channel with a single poster has no detection against its sequencer. In
high-sec federation this limit is the place for a consensus mechanism, such as carriers
co-signing heads. Merkle logs with gossip are the long-term answer.

### 7. Leave and remove name the membership they end

Today the self-leave replay crosses servers. A member leaves on server A and rejoins.
Anyone can then hand server B the old leave block, which B has never seen, so its CID
dedupe does not stop it, and B removes the member.

The fix: a `member-remove` block, including a self-leave, carries `ends`: the CID of
the `member-add` block whose membership it ends. The write gate refuses a remove whose
`ends` is not the member's current membership. A replayed leave then names a membership
that has already ended, and is refused everywhere.

### 8. The author's clock, and the server's

**The bound.** The owning server refuses, at ingest, a block whose `hlc_ts` is more
than `max_future_skew_ms` ahead of its own clock.

- **The past is unbounded**, so a message composed offline can be sent hours later.
  History no longer depends on `hlc_ts` (item 5), so a past bound would buy nothing.
- **The refusal** is `CLOCK_SKEW`, an ordinary error that carries the server's time.
  The client can then tell its user that the device clock is wrong.

**Who sets it:**

- **The protocol** fixes a floor and a ceiling: 30 seconds and 15 minutes. Without a
  ceiling, an operator could set an enormous bound and bring back
  `naively_unbounded_clock_skew` under another name.
- **The operator** chooses a value in that range in server config. The default is
  5 minutes, the usual tolerance (as in Kerberos).
- **A ruleset group** may narrow it later, never widen it. That is a hook for lane R,
  not v0.2 work.

**How it is checked.** The welcome advertises the bound as
`capabilities.max_future_skew_ms`, so it is signed. Three checks follow:

- A client refuses a welcome whose bound is outside the protocol's range (class 1).
- A block whose `hlc_ts` is ahead of its `ingest_hlc` by more than the bound shows that
  the server broke its own signed bound (class 3).
- The client's own tolerance, for checking `ingest_hlc` against its clock (item 5), is
  local config in the same range, defaulting to 5 minutes.

**The server's clock.** The server adopts a block's time (`update_on_receive`) only
within the bound. `naively_unbounded_clock_skew` goes from `unsafe_options_active`, and
the h7 integration test changes with it.

### 9. Evidence

**The bundle, `jig-evidence-v1`, is self-checking.** It holds:

- the verbatim signed welcome (or refusal);
- every signed item that contradicts it (frames, `ingest` records, blocks, `seen`
  records);
- the class and code;
- the server URL and the pinned DID;
- the local time it was seen.

Everything that proves the lie is signed by the server, so anyone can check the bundle
without trusting whoever presents it.

- **No user signature.** The bundle is not signed by the user's DID by default, since
  that would link the user to a report (PV-03).
- **No plaintext.** It never holds decrypted content, only signed ciphertext and
  records.

**Where it is kept.** It is written to `~/.jig/evidence/<server-key>/<time>-<code>.json`.
It stays with the user who saw it. It is not sent to a third party, because the
offender may be any of a client, a server or a nameserver. So reporting must ultimately
happen outside the reach of whoever is compromised. The format is ready for a tribunal
intake later (lane R; AB-06, GV-01).

**The CLI.**
- `jig trust evidence list|show <id>|export <id>`.
- `jig trust evidence import <file>` checks a bundle someone else made, and shows it.

**A contradiction is sticky.** After a class 3 contradiction, every later connection to
that server, REST or WebSocket, is refused until the user runs
`jig trust accept <server>`. The refusal names the evidence file. Otherwise a reconnect
loop would carry on quietly with a server just caught lying.

**Rules against abuse of the evidence system:**

1. **Only something the server signed can make a refusal sticky:** a signed welcome or
   refusal, a signed `ingest` record, or a chain that breaks the server's own rules.
   Timeouts, dropped connections and malformed frames never do. A network attacker can
   cause those, but cannot forge the server's signature.
2. **The fault must be the server's own.** A delivered block whose author signature
   fails is the server's fault, since the server must check it at ingest. A block that
   verifies but is abusive is not evidence against the server. A hostile client cannot
   get a server refused for anything the server legitimately passed on.
3. **A client checks the server against what the server signed, and nothing else.** A
   newer client's own expectations never count as a contradiction, so version skew
   does not look like an attack.
4. **Other people's evidence is never imported automatically.** `jig trust evidence
   import` checks a bundle and shows it, but it never makes a refusal sticky.
   Otherwise one widely shared report could turn many clients against a server.
5. **A bundle must be complete, so that a selective one cannot mislead.** A gap is
   evidence only with the records on both sides of it. A gap the reader was entitled
   to (a record delivered without its block) is not a gap.
6. **The cost is accepted.** An honest server with a bug locks its users out until they
   act. The refusal says so plainly and points at the bundle, so they can file a bug.
   DJ accepted this: it is one of many ways a server can fail to reach its users.

### 10. No plaintext REST from the CLI

The CLI refuses every `http://` REST request, except to a loopback address. The check
lives in `jig-cli/src/cmd/trust.rs` (`server_tls` and `http`), not in `jig_client`.

- **Why not just suite decisions.** Refusing plaintext only where it decides a suite
  would be easy to get wrong, and a plaintext response can lie about anything.
- **The loopback exemption** keeps local development and the CLI tests that dial
  `http://127.0.0.1:1` working.
- **Why not in `jig_client`.** The integration-test harness uses raw `reqwest` and
  `jig_client::Client` over plaintext, and is unaffected.
- **Nameserver clients are not covered.** A nameserver's answers are signed
  attestations, and checking them is NS-01's work (lanes L6 and F), not a transport
  question.

The CLI's default `base_url` becomes `https://` in a lane L3 PR first.

### 11. Name pinning

This is lane F's rule (#106, design 4.4, decided by DJ as F's Q3 B), applied in
`jig_client::pins` and `jig trust`.

**The rule.** A pinned name moves to a new DID automatically only with a rotation signed
by the old key. Any other change is refused until the holder accepts it. The UX may
soften the friction, never the check.

**The refusal:**
- It says why in plain words: re-registered after expiry, a different nameserver, or no
  rotation signed by the old key.
- It shows both fingerprints.

**What the user can do:**
- `jig trust accept-name <name>` accepts the change, after the user has compared
  fingerprints out of band. The acceptance is recorded in the pin store.
- The CLI warns before a pinned name's attestation expires.

Lane I will later let a second device sign rotations.

The pin store gains a `names` map beside `servers`. Today `jig dm` takes only DIDs or
local `[contacts]`, so this lands before name resolution reaches end-to-end encryption.

### 12. The server-to-server handshake

There are three messages. The first two are today's, extended:

1. **`hello`** carries the dialer's `nonce`, and `peer_did` when the dialer is a
   server.
2. **`welcome`** is signed as today. It also carries `server_nonce`, and covers the
   TLS exporter value.
3. **`peer_proof`** comes from the dialer. It holds an ed25519 signature by `peer_did`
   over the transcript hash, under the domain tag `jig-handshake-peer-v1`.

The **transcript hash** is the BLAKE3 hash of the domain tag, the `hello` frame's
bytes, the `welcome` frame's bytes and the TLS exporter value, each length-prefixed.

**When `peer_proof` is required:**

- **Server to server, it is mandatory.** A `hello` with `peer_did` and no valid
  `peer_proof` within `WELCOME_WAIT` is a class 1 failure, and the dialed server closes
  the connection.
- **For clients it is absent.** An anonymous client connection stays possible (PV-03);
  a client proves its DID per subscription, as today.

**After the handshake the connection is symmetric.** Either side may subscribe and
push. Whether a given peer DID may do so is F's rule (peer lists, share grants,
JEP-0005). The handshake only supplies a DID both sides have authenticated. This
answers F's asks 1 and 2.

**TLS channel binding** (RFC 9266, `tls-exporter`). Both the welcome signature and
`peer_proof` cover a 32-byte exporter value from the TLS session, with the label
`EXPORTER-jig-handshake`. This applies to client connections too. A signed handshake
then cannot be relayed through a middlebox that terminates TLS.

- **Over plaintext** (loopback, or `dangerously_allow_plaintext_federation`) the value
  is empty, and the welcome says so.
- **A client that connected over TLS** and gets a welcome with an empty value treats it
  as class 1.

Building this needs the exporter on both ends:

- **The client** reads it from the rustls connection inside
  `tokio_tungstenite::MaybeTlsStream`.
- **The server** reads it in `serve_tls` (`jig-server/src/server.rs`, a lane L3 file),
  and hands it to the upgrade as a request extension. That needs a small separate PR,
  agreed with L3.

### 13. The manifest log

Each server keeps one reserved channel: its **manifest log**.

**What goes in.** Only these block kinds:

- `server-manifest`: the server's suites, capabilities, skew bound and protocol
  versions, plus its signed peer policy (lane F, #106): the block kinds it relays,
  per-peer quotas, the peer DIDs it publishes, and the suffixes it attests with their
  roots;
- `sequencer-set` notices for channels the server sequences;
- handover notices.

Every other kind is refused. Only the server's DID writes it. Anyone may read it, so
clients, owners and admins can review a server's claims over time. It is a channel like
any other, so it has `ingest` records, gap checks and gossip. Federation contract
messages cite the manifest by CID and `seq` too, so a server's handshake claims and its
peer policy are one signed, gap-checked document, not two.

**Metadata cost.** A public manifest log exposes the server's peer graph. A server may
publish only the peers it wants known.

**How a welcome uses it.** Each welcome carries `manifest`, the CID and `seq` of the
current `server-manifest` block. In v0.2:

- **The server** publishes a new manifest whenever what it advertises changes.
- **The client** fetches the cited manifest, and checks that the welcome's suites,
  capabilities and skew bound equal the manifest's (class 3 if not).
- **Pins.** The client pins the server's manifest-log chain like any channel.
- **Review.** `jig trust show <server>` prints the manifest history.

**What it buys.** Without the log, a server can tell a new client "no `mls` here" while
telling everyone else the truth. Pins do not catch that from first contact. With the
log, every claim lands in one signed chain. Two clients whose heads for it differ hold
evidence of equivocation, through the same gossip as any channel.

**Why not log every handshake.** Logging every welcome with its nonce would record who
connected and when.

**The handshake-transcript channel (designed, not built in v0.2).** A server may also
keep an optional channel of handshake transcripts. If it does:

- its manifest MUST advertise it;
- a client MUST agree to it before posting, as part of the ruleset it consents to.

This is the protocol's mutual consent to rulesets. It is not part of v0.2.

### 14. Nameserver refusal lists

A nameserver may name servers as abandoned or compromised, so that others refuse them.
Such a list is itself a claim, and nameservers are as untrusted as operators (NS-01,
NS-02). So:

- **It is advisory.** A carrier may refuse to peer with a listed server. A listing never
  unseats the sequencer the owner names in `sequencer-set`. Only the owner moves it,
  with a new `sequencer-set`.
- **Its scope is limited.** It applies only within the ruleset group whose nameservers
  published it, and it SHOULD cite evidence (GV-03).

This is lane F's and lane R's to build. JEP-0002 states only the rule that a listing
cannot override the owner's `sequencer-set`.

---

## Wire changes

| Where | Change |
| --- | --- |
| `hello` | + `peer_did` (optional) |
| `welcome` | + `server_nonce`, `tls_exporter` (signed), `manifest`, `capabilities.max_future_skew_ms` |
| New frame `refusal` | Signed: nonce, code, supported versions and suites |
| New frame `peer_proof` | The dialer's signature over the transcript hash |
| `block` | + `ingest` record |
| New frame `record` | A record delivered without its block |
| New frame `head` | Anonymous head gossip |
| Block manifest | + `seen` (a full `ingest` record); `member-remove` + `ends` |
| New block kinds | `sequencer-set`, `server-manifest` (and C's `timer-fire`) |
| Errors | + `CLOCK_SKEW`; `HANDSHAKE_REQUIRED` now closes |
| WebSocket close codes | 4001–4004 |

v0.x has no compatibility guarantee. Clients and servers on either side of this change
cannot talk to each other.

## Threat-register rows (proposed)

`threat-register.md` is an existing spec page. Its status cells belong to lane L1, so
these rows are applied in the build PRs, after L1 has merged.

| ID | Decision (new text) | v0.2 status once built |
| --- | --- | --- |
| OP-01 | Every connection completes the handshake before any other frame. Failures fall into four classes; the class decides who closes and with which code. A version or suite refusal is signed, then closes ([JEP-0002]). | Mitigated over WSS. Plaintext REST is refused by the CLI, except to loopback |
| OP-02 | Handshake answers are signed and cite the server's manifest log. A client MUST treat later behaviour that contradicts a signed answer as a contradiction, close, and keep a self-checking evidence bundle. A contradiction makes the server refused until the user accepts it ([JEP-0002]). | Mitigated for WSS frames, receipts, `ingest` records and the manifest; evidence stays local |
| OP-03 | … plus: a client refuses a restricted channel whose creation block is not `mls`; a channel's identity is its `channel-create` CID. | Partial: a made-up channel must be open or an MLS group the server owns |
| OP-06 | Every block in a channel has a record signed by the channel's sequencer, with a per-channel `seq` and a hash chain. Authors carry the latest record they verified (`seen`), and readers gossip heads without identity. A `member-remove` names the membership it ends. | Partial: drops, reordering and forks are detected once records cross by a path the sequencer does not control; a single-poster channel has no detection against its sequencer; delay within the skew bound is not detected |
| OP-08 | … plus: a pinned name moves only with a rotation signed by the old key; otherwise the holder must accept the change. | Mitigated in the CLI |
| OP-09 | … plus: server-to-server connections authenticate both DIDs in the handshake, bound to the TLS session. | Partial (encrypted federation follows JEP-0005) |
| TM-01 | … plus: a server refuses a block more than `max_future_skew_ms` ahead (30 s–15 min, default 5 min, signed in the welcome), and adopts block time only within that bound. | Mitigated for author clocks; the server's clock is checked by clients within the bound |
| TM-02 | History is ordered by the sequencer's `seq`; `hlc_ts` is shown as the author's claim. | Mitigated, with the sequencer as the trusted orderer, checked by the chain |

The operator threat model gets matching status evidence in the same PRs. Its OP-06
line, "the manifest's `hlc_ts` is set by the ingesting server", is wrong today: the
author sets it. The orchestrator has reported that to L1.

## Accepted limits

- **First contact is still trust on first use.** A pin turns a later lie into one that
  is caught. It does not make the first answer true.
- **The sequencer orders history.** It can delay a block within the skew bound, and
  choose the order of concurrent writes. It cannot hide that it did either outside the
  bound.
- **Fork detection** needs records to cross by paths the sequencer does not control
  (item 6).
- **Timer fires** are the server's word, bounded by the install's grant (item 5).
- **A server bug** that trips a contradiction locks its users out until they act
  (item 9, rule 6).

## Coordination

| Lane | What it relies on here |
| --- | --- |
| A (block ABI, #112) | `ingest.ingest_hlc` is the time a block runs at |
| C (capabilities, #117) | `timer-fire` cites `install` and `set_by`; the record stays blocks-only |
| F (federation, #106) | One owning server per channel; `sequencer-set` is owner-only; `channel_id` = the `channel-create` CID; the mutual handshake; anonymous head gossip; the name-pinning rule |
| L1 (docs) | Applies threat-register status cells; fixes the OP-06 `hlc_ts` line |
| L3 (legacy sweep) | The default `base_url` becomes `https://` first; the `serve_tls` exporter hook |
| I (identity) | A second device signing rotations, later |

## Build slices (outline)

The full plan follows in `docs/superpowers/plans/` after this design merges. Slices
start after L3's first slice (#107) merges.

1. Close classes, signed `refusal`, one `hello`, and the frame and receipt checks
   (items 1–3).
2. Restricted ⇒ MLS on the client (item 4), and plaintext REST refused (item 10).
3. Skew bound at ingest, advertised and checked; the flag removed (item 8).
4. `ingest` records: signing, storage, delivery, `record` frames and client checks
   (item 5).
5. `seen`, head gossip and the fork check (item 6), and `ends` on removes (item 7).
6. Evidence bundles, sticky refusals and `jig trust evidence` (item 9).
7. The manifest log, and welcomes that cite it (item 13).
8. The mutual handshake with TLS channel binding (item 12), with the L3 hook first.
9. Name pinning in `jig trust` (item 11).
10. `sequencer-set` and handover (item 5). Last, because F's contract has to land
    around it.

[JEP-0002]: ../../../repos/jig-spec/jep/jep-0002-handshake.md
