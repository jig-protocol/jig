# M2: MLS encryption and channel dynamics

**Date:** 2026-10-11
**Author:** DJ + Claude
**Status:** Implemented on `claude/vibrant-ramanujan-r7kznf`. Decisions below are defaults
chosen to ship the MVP; each one names what would change it.
**Builds on:** [JEP-0001](../../../repos/jig-spec/jep/jep-0001-encryption-suites.md) (its
"Proposed for v0.2" list and open questions), the
[encryption rationale](../../security/encryption.md), and the M1 groundwork tagged
`v0.1.0-alpha.1`.

## Goal

A jig server that stores and relays message content it **cannot read**, with channels
whose membership can grow, shrink and lock, while keeping one code path for a DM, a
group DM and a channel.

Concretely, at the end of M2:

```bash
jig channel create '#ops' --restricted --encrypted   # one MLS group, owner at epoch 0
jig channel add '#ops' <did>                         # MLS commit + welcome ride a member-add
jig dm <did>                                         # locked, encrypted, two members
jig send --channel '#ops' "rotate the keys"          # server stores ciphertext
jig channel kick '#ops' <did>                        # removed member cannot decrypt what follows
jig channel leave '#ops'
```

and the server's database holds no plaintext for `#ops`.

### Out of scope

- **Multi-device.** One DID is one MLS client (JEP-0001 Q4). A second device with the same
  key would fork the group state.
- **Federated MLS channels.** Channel and membership state does not replicate (M1), so an
  encrypted channel is single-server in v0.2. Federation refuses to carry it rather than
  carrying it without the gates.
- **Metadata privacy** (OP-04): unchanged. The server sees sender, channel, timing, sizes
  and membership changes.
- **Post-quantum** (D13). The registry stays one `mls` entry; the MLS cipher suite is
  `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`.
- **Client-side Wasm execution** of decrypted content (JEP-0001 Q7, second half).

---

## Locked decisions

**1. The DID key is the MLS signature key.** The cipher suite signs with Ed25519, and a
`did:jig` *is* an Ed25519 public key. Every MLS leaf therefore carries a `BasicCredential`
whose identity is the canonical `did:jig:z…` string and whose signature key is that DID's
key. The server and every member check both. There is no second credential system and no
MLS-level identity a server could substitute (OP-08). The cost is that rotating a DID key
means re-joining groups, which is already true of everything else signed by that key.

**2. The server is a validating delivery service.** Commits are sent as MLS
`PublicMessage`s (wire-format policy *mixed plaintext*: handshake messages in the clear,
application messages always encrypted). The server keeps an openmls `PublicGroup` per
encrypted channel and runs every commit through it before accepting the block that
carries it. This buys three things a relay cannot:

- **Ordering.** A commit built on a stale epoch is refused (`409 STALE_EPOCH`), so the
  channel has one linear history and no fork for clients to resolve.
- **Binding.** The commit inside a `member-add` must add exactly the leaf whose credential
  is `member_did`; inside a `member-remove`, remove exactly that DID's leaf. The jig
  membership table and the MLS tree cannot drift apart, and an owner cannot quietly add a
  different key than the one the block names.
- **Liveness.** A malformed commit is refused at ingest instead of being fanned out and
  wedging every member at an epoch the server thinks has passed.

Alternative rejected: an opaque relay with a server-side epoch counter. It orders commits
but cannot tell a valid one from garbage, so any member of an open encrypted channel could
brick it with one bad external commit.

Revealing commits to the server reveals adds, removes and key updates — exactly the
membership metadata the spec already says the server sees.

**3. Membership blocks carry the MLS handshake.** (JEP-0001 "membership blocks drive MLS
commits".)

| Block | On an `mls` channel it carries |
| --- | --- |
| `channel-create` | `suite: "mls"`, `mls_group_info` and `mls_ratchet_tree` at epoch 0 (one member: the creator) |
| `member-add` (owner adds someone) | `mls_commit` (adds `member_did`), `mls_welcome`, `mls_group_info` for the new epoch |
| `member-add` (self-join, open channel) | `mls_commit` is an **external commit** whose new leaf is the sender; `mls_group_info` |
| `member-remove` (owner kicks) | `mls_commit` removing `member_did`'s leaf; `mls_group_info` |
| `member-remove` (self-leave) | nothing. A member cannot commit its own removal in MLS (RFC 9420 §12.4) |
| `member-remove` (tidy-up) | `mls_commit` removing a DID that has already left; any remaining member may send it |

Every commit-bearing block also names `mls_epoch`, the epoch the commit was built on, so a
client can skip a commit it has already merged (its own) without parsing it.

**4. Self-leave is two steps, and the gap is stated.** `member-remove` for yourself drops
your membership row immediately: the server stops delivering to you and stops serving you
history. Your leaf stays in the MLS tree until the next member to come online commits its
removal (decision 3, tidy-up row). Until then a departed member who *also* obtained new
ciphertext out of band could decrypt it. A compliant server never gives it to them.

**5. Key packages live on the home server** (JEP-0001 Q3). `POST /api/v1/mls/key-packages`
accepts a batch; each key package is validated (its leaf signature key must equal the
DID's key, decision 1) so no caller can publish for someone else. `GET
/api/v1/mls/key-packages/:did` hands one out and consumes it. A key package marked
*last resort* is handed out without being consumed, so a DID is never unreachable. Consumed
packages are remembered by reference and cannot be re-uploaded. Nameserver distribution is
deferred: the nameserver is optional and a server already knows its users.

**6. A DM is a restricted, encrypted channel; restricted *is* locked.** (JEP-0001 Q5,
spec "Channels".) `restricted` already means "nobody joins on their own; only the owner
adds", which is the spec's *locked membership*. `jig dm <did>` creates
`#dm/<hash of the sorted DID pair>` as `restricted` + `mls` with `dm: true` in the
creation block, owned by whoever opened it, and adds the other party. Growing it is a
membership change (`jig channel add`), and opening it up is `channel-promote` — never a
migration. The question "who signs membership changes in an ownerless DM" is answered by
there being no ownerless DMs: the opener owns it.

**7. A channel's suite is fixed at creation and enforced on every post** (JEP-0001
"Proposed"). The `channels` row records `suite`. Content into an `mls` channel must declare
`privacy.encryption = "mls"` and carry its payload as `metadata.mls_message` (an MLS
`PrivateMessage` for the channel's group, at a current or recent epoch); a plaintext
`metadata.body` is refused outright, so a buggy client cannot leak plaintext into an
encrypted channel. Content declaring `mls` into a `none` channel is refused the same way
(`400 SUITE_MISMATCH`). Changing a channel's suite is a new channel (JEP-0001 Q6).

**8. No server execution over ciphertext** (JEP-0001 Q7). The server cannot run
`text-render` over an MLS ciphertext, so it does not pretend to: an encrypted content block
takes a server-signed receipt marked `"content": "sealed"` attesting only that the server
verified the signature, the suite, the group and the epoch, and persisted the block. No
`render_hash` is issued for it.

**9. Frames stay `none`.** The envelope `suite` describes the *frame*. No v0.2 frame is
encrypted as a unit — a frame carries blocks, and an encrypted block is encrypted inside its
manifest. The handshake advertises `["none", "mls"]` as the content suites the server can
host; the envelope gate still refuses `suite: "mls"` on a frame. This keeps the per-channel
negotiation JEP-0001 asks for and rules out a per-connection one.

**10. Clients keep plaintext; the MLS ratchet does not.** MLS deletes a message key once
used (forward secrecy), so a message decrypts exactly once, and a sender can never decrypt
its own ciphertext. The client therefore keeps a local plaintext cache keyed by block CID,
written when it sends or first decrypts. History replays read from it. MLS state and the
cache live under `~/.jig/mls/<did>/`, `0700`, guarded by an exclusive file lock so `jig chat`
and `jig send` cannot fork the group state.

---

## Channel dynamics

| Command | Block | Rule |
| --- | --- | --- |
| `jig channel create --encrypted` | `channel-create` + `suite: mls` | as M1, plus epoch-0 group state |
| `jig channel add <slug> <did>` | `member-add` | owner only (M1); MLS: fetch a key package, commit, welcome |
| `jig channel join <slug>` | `member-add` (self) | open channels (M1); MLS: external commit from the server's group info |
| `jig channel kick <slug> <did>` | `member-remove` | owner only; owner cannot be kicked |
| `jig channel leave <slug>` | `member-remove` (self) | any member but the owner, who archives instead |
| `jig channel promote <slug>` | `channel-promote` | owner only (M1 rule; now reachable from the CLI) |
| `jig channel members <slug>` | `GET /api/v1/channels/:slug/members` | readable by whoever can read the channel |
| `jig dm <did>` | create + add | decision 6 |

`member-remove` joins `member-add`, `channel-promote` and `channel-create` in the default
`allowed_block_kinds`. A server whose config lists kinds explicitly must add it.

## Federation (v0.2 rule)

Only **open, unencrypted** channels federate. Outbound fanout no longer relays blocks from
restricted or encrypted channels to peers (in M1 it relayed restricted content to every
peer, which no peer could gate). Inbound, a peer block naming a local encrypted channel is
refused. The relay also derives block CIDs the way `ingest` does; in M1 it used a different
scheme, so one block had two identities.

## M1 cleanup carried in this batch

- Federation CID scheme (above).
- Clients verify every delivered block's author signature before displaying it. The README's
  "a relaying server cannot forge what it passes on" was a server-side property only.
- `jig read` uses the signed history endpoint instead of the gated-off v0.0.1 route.
- `jig --version`.
- Stale status claims in `README.md` and `docs/RELEASE_READINESS.md`.

## Known limitations

- History backfill is the last 200 blocks. A client offline across more than 200 blocks
  that include commits cannot catch up and must be re-added.
- Key-package exhaustion: anyone admitted can fetch (and so consume) a DID's key packages.
  The last-resort package keeps the DID reachable; rate limiting is the admission work's.
- Decision 4's window.
- The server sees every commit (decision 2), so it sees who was added and removed and when.
