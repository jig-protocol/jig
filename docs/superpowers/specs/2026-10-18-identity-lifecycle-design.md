# Identity lifecycle: keys at rest, devices, rotation, revocation

**Date:** 2026-10-18
**Author:** DJ + Claude (lane I)
**Status:** Decided by DJ in the lane's Q&A, 2026-10-18 (see the decisions log at the
end). The plan for milestone I1, which gates G2, is in
[`plans/2026-10-18-identity-i1-keys-at-rest.md`](../plans/2026-10-18-identity-i1-keys-at-rest.md).
No code yet.
**Builds on:** the D11 handshake design (#136, JEP-0002, lane L7), the federation and
naming design (#106, JEP-0004 and JEP-0005, lane F), the block ABI (#112, lane A) and
capabilities (#117, lane C) designs, the
[M2 design](2026-10-11-m2-mls-and-channel-dynamics-design.md), ROADMAP D20 and D24.

## Goal

Make an identity survive the things that happen to keys: a stolen laptop, a second
device, a lost phone, a leaked server key, a key that is simply old. Today each of these
is either silent exposure or a new identity that every contact must re-accept by hand.

Gate G2 (tag `v0.2.0`) needs only the first milestone: **keys and the MLS plaintext cache
are encrypted at rest** (`crypto.md:60` is a MUST).

## What is true today

Checked against `main` at `062fe91`.

| Fact | Where |
| --- | --- |
| A DID *is* its key: `did:jig:z` + lowercase base32 of the Ed25519 public key. `crypto.md:57` still says base58; the spec is wrong | `jig-core/src/did.rs:56` |
| Identity keys are raw 32-byte seeds in `~/.jig/keys/<did>.key`, protected only by mode 0600 | `jig-client/src/identity.rs` |
| The server key is a raw seed at `server_did_keyfile`, 0600 | `jig-server/src/v0_0_2.rs:307` |
| The DID key is also the MLS signature key. A leaf is valid only if its credential's DID decodes to its signature key | `jig-mls/src/credential.rs` |
| `~/.jig/mls/<did>/` holds `state.bin` (every group's secrets and unused key packages), `groups.json` (which channels the DID is in) and `plaintext.jsonl` (every message ever read, in clear). Files are 0600 in a 0700 directory; nothing is encrypted | `jig-client/src/secure.rs` |
| `jig keys rotate` mints a new DID, moves an alias to it at the nameserver (`/v1/rotate`, both keys sign the challenge), and renames the old seed to `<did>.key.rotated`, still in clear | `jig-cli/src/cmd/keys.rs:143` |
| Nothing else rotates. No rotation certificate, no `POST /v1/identity/rotate`, no revocation, no transparency log | `crypto.md:64`, `zero-trust.md:98` |
| About 20 source files decode a DID straight to a verifying key | `rg 'Did.*as_bytes'` |
| Everything is keyed by DID: the owner in a channel pin (`owner_did`), memberships, roles (F 5.9), DM slugs (`#dm/` + hash of the two DIDs), server pins (`server_did`), peers' `expected_did`, `ingest` record signers, reputation | `pins.rs`, `jig-core/src/dm.rs` |
| The email bridge derives shadow identities from `bridge_secret` (read from the environment) and never stores them | `bridges/email/src/inbound.rs:89` |

So rotating a key today means a new DID. That stays true (Q2). What changes is that a new
DID no longer has to lose the channels it owns, its DMs, its roles, or its pins at every
contact and every peer: the holder can carry them across with a link, disclosed to the
parties they choose.

## Prior art

| System | Device model | Rotation and revocation | Keys at rest | Lesson for jig |
| --- | --- | --- | --- | --- |
| **MLS** (RFC 9420, RFC 9750) | A user is a set of clients; each client is a leaf | Leaves update their own keys; removal is a commit | Out of scope | One leaf per device. RFC 9420 section 7.3 requires `signature_key` to be unique across leaves, so two devices cannot share an MLS signature key |
| **Signal** (Sesame, linked devices) | The account identity key is **copied** to every linked device during provisioning; Sesame keeps a session per device | Unlinking a device does not change the identity key. A new identity key is a "safety number changed" warning | Platform keystore wraps a local database key | Copying the root key is simple and every device then holds the crown jewels. A stolen device cannot be cut off without a new identity |
| **Matrix** cross-signing | Per-device keys, signed by a self-signing key, which a master key signs | Devices are revoked by un-signing them; resetting the master key warns every contact | Secret Storage (4S): secrets encrypted under a recovery key or passphrase, stored on the homeserver | A root above device keys lets devices come and go while contacts verify once |
| **Keybase** sigchain | Each device holds a "sibkey" with full power; paper keys are offline sibkeys | Any sibkey can add or revoke any other. The chain is append-only, signed link by link, its root anchored in a public Merkle tree | Device keys in the OS keychain where available | An append-only, self-signed chain makes rotation and revocation self-authenticating without a trusted server |
| **did:plc** (ATProto) | One DID, a list of rotation keys in priority order, plus a signing key | A higher-priority rotation key can override an operation made by a lower one within **72 hours** | Out of scope | The identifier outlives its keys. A contest window stops a stolen low-tier key from taking the identity outright |
| **KERI** | The identifier is derived from an inception event | **Pre-rotation:** each event commits to the hash of the next key, so a stolen current key cannot rotate | Out of scope | Worth having later; heavy for v0.2 |
| **age** | n/a | n/a | File encryption to recipients (X25519, plugins for YubiKey, TPM, Secure Enclave) or to a passphrase (scrypt). An scrypt stanza must be the only one in a file | Good for exported backups. Cannot hold "keychain *or* passphrase" in one file |
| **OS keychains** (macOS Keychain, Windows Credential Manager/DPAPI, Secret Service on Linux) | n/a | n/a | A per-user secret, unlocked with the login session | No prompt for routine use. Absent on headless Linux and over plain SSH. Secure Enclave and most TPMs cannot hold Ed25519 keys, so hardware can wrap a key-encryption key but not hold the signing key |

**Why jig does not adopt the log designs** (Keybase, did:plc, KERI, Matrix cross-signing).
Each keeps an online record of every key behind an identifier. That record undoes **key
ablation**: a holder discards a key under deanonymization pressure, and nobody can tell
the old and new identities apart unless the holder says so (DJ, 2026-10-18). jig takes
from them only the ideas that survive without a public record: dual-signed rotation and
self-signed revocation.

## Q5. Keys and MLS state at rest (gates G2)

**Decided (DJ, 2026-10-18): option A, key slots.**

### What encryption at rest buys, said plainly

- **It protects against:** a stolen or discarded disk, backups and cloud sync of the home
  directory (Time Machine, Dropbox on `~`), a dotfiles repo that swept up `~/.jig`, and
  other local users when permissions slip.
- **It does not protect against** malware running as the user. Such malware can ask the
  keychain, read the passphrase as it is typed, or read the key from memory. `crypto.md`
  should say so.
- **The plaintext cache matters more than the key.** It holds every message ever read, in
  clear. It undoes MLS forward secrecy for anyone who copies the file. Encrypting it is the
  point of the G2 line.

### Options

| Option | How it unlocks | Against |
| --- | --- | --- |
| **A. Key slots: one data key, several ways to unwrap it** | OS keychain by default; passphrase where there is none; a credential file or environment reference for headless processes | We define a small envelope format (built from standard parts, see below) |
| **B. Passphrase only** (age with scrypt, or Argon2id) | A prompt every time a process starts | `jig send` in a script prompts or needs a passphrase in the environment. Concurrent `jig chat` and `jig send` each prompt. Needs an agent to be usable, which is more code than A |
| **C. Ship G2 with an honest `crypto.md`** | Nothing changes | The G2 line is met on paper. The plaintext cache stays the weakest point in the system for another milestone |

Option A was chosen (decided above).

### The envelope (option A)

**A key file** replaces `~/.jig/keys/<did>.key` with `~/.jig/keys/<did>.jigkey`:

- A random 256-bit **data key** per identity.
- One or more **slots**. Each slot wraps the data key under its own key-encryption key:
  - `keychain`: a random key held in the OS keychain (service `jig`, account the DID);
  - `passphrase`: Argon2id (RFC 9106's second recommended setting, 64 MiB, t=3, p=4) over
    a passphrase, with its salt in the slot;
  - `credential`: bytes read from a path, for systemd `LoadCredentialEncrypted=` (TPM2
    bound where the machine has one) or a mounted secret;
  - `env`: a reference such as `env:JIG_KEY_UNLOCK`, resolved the way the email bridge
    resolves `bridge_secret`, for secret managers.
- The payload: the 32-byte identity seed, sealed with the data key.
- The AEAD is XChaCha20-Poly1305 (random 192-bit nonces need no counter). The associated
  data is the header (version, DID, slot list), so a slot cannot be swapped or downgraded
  without the payload failing to open.

Any one slot opens the file. `jig keys protect --add passphrase` adds a slot, which is how
a keychain user also gets a recovery passphrase.

**MLS state** in `~/.jig/mls/<did>/` is encrypted under keys derived from the data key
(BLAKE3 `derive_key`, one context string per file):

- `state.bin` and `groups.json`: whole-file AEAD, written through today's `write_atomic`.
  `groups.json` holds no secrets but lists every channel the DID is in, which is
  metadata worth hiding.
- `plaintext.jsonl`: one AEAD record per line, so appends stay appends and the
  concurrency model (`secure.rs`, "Concurrency") is unchanged.
- The associated data binds the DID and the file's role, so a ciphertext cannot be moved
  between files or identities.

**Not encrypted:** `pins.json`. It holds public facts. Its integrity matters, but a local
attacker who can write it can also replace the binary. The metadata it leaks (which servers
this user talks to) goes on the open list for v0.3.

**Hardware-backed keys** are a later slot type (`tpm`, `secure-enclave`, an age plugin for
YubiKey). The hardware wraps the data key. It cannot hold the identity key, because the
Secure Enclave and most TPMs do not do Ed25519, and MLS signs too often for a token. The
identity key is in memory while a process uses it, and the spec says so.

**Exported backups** use age: `jig keys export` writes the seed to an age file, encrypted to a passphrase or an age recipient. That is a standard,
audited format that other tools can open.

### Who unlocks how

| Process | Default slot | Notes |
| --- | --- | --- |
| CLI on macOS, Windows, Linux desktop | `keychain` | No prompt. Concurrent `jig chat` and `jig send` both work |
| CLI over SSH, or Linux without Secret Service | `passphrase` | Prompted once per process. `jig chat` is long-lived, so this is one prompt per session. An unlock agent is v0.3 |
| CI and tests | `env` | Documented as weaker: the secret sits in the environment |
| `jig-server`, `jig-nameserver` | `credential` (systemd) or `env` | `server_did_keyfile` points at a `.jigkey`. A server with no slot it can open refuses to start |
| Email bridge | unchanged | Its shadow keys are derived from `bridge_secret` and never stored. `bridge_secret` already comes from the environment. The bridge's own DID key, if it has one, follows the server row |
| C3 custodial bot keys | the server's slot | Random per-install seeds, sealed with a key derived from the server's data key; the associated data binds the install's CID. Restoring the server restores its bots. Bot keys are separate DIDs, as C3 decided, so one bot can be revoked alone |

**A plaintext store is an antipattern flag:** `keys.storage = "plaintext"` in config, or
`--insecure-plaintext-keys`. It warns on every run and is never the default.

**Migration.** On first load of a raw `<did>.key` (or `.key.rotated`), the CLI seals it
into a `.jigkey` with the default slot, re-encrypts the MLS directory, and removes the raw
files. It says plainly that removing a file does not erase it on an SSD or a
copy-on-write filesystem, and that a key which was ever in a backup should be rotated
once rotation exists (milestone I3). `jig-server` refuses a raw keyfile unless the flag is
set, and prints the one command that seals it.

**Crates:** `chacha20poly1305`, `argon2`, `keyring` (OS keychains), `zeroize`. All are
RustCrypto or widely used. `age` for export only.

**Push-back on a likely assumption:** "a server key encrypted at rest protects users from
the operator." It does not. The key belongs to the operator. At rest it protects the
operator from disk theft and leaked backups. Restricted content is protected from the
operator by MLS (D25), not by this.


## Q1. Devices

**Decided (DJ, 2026-10-18): copy the DID key to each device. MLS leaves are scoped.**

Rejected:
- **Device subkeys certified by the DID.** These need a public device list, which is the
  log Q2 rejects.
- **One DID per device.** DMs, ownership and roles would split per device.

**Pairing.**
- The new device shows a one-time X25519 recipient, as text or a QR code.
- The existing device seals the DID seed to that recipient with age. The user moves the
  sealed seed over any channel, or through a server mailbox.
- The new device seals the seed under its own key slots (Q5). The user compares
  fingerprints on both screens.
- No server learns that a pairing happened.

**MLS: a fresh leaf key per key package.**
- RFC 9420 7.3 makes each leaf's `signature_key` unique, so a device cannot use the DID
  key as its leaf key.
- Each key package gets a fresh Ed25519 leaf key. The DID key signs a **leaf
  certificate**: (`domain`, `jig-mls-leaf-v1`), the DID, the leaf key.
- Key packages are single-use, so each group sees a different leaf key per device. A
  device cannot be correlated across groups by its leaf key.
- An external commit makes its own fresh leaf key.
- `jig_mls::credential::bound_did` checks the leaf certificate instead of requiring the
  leaf key to be the DID key.
- **What members learn.** A group's members see how many devices a DID has in that
  group, and nothing else. No list exists outside groups.

**Adding and removing:**
- **Adding a DID** adds one leaf per device that has stocked key packages. Custodians (F
  5.4) release one package per device under the DID's single release policy.
- **A newly paired device joins groups through its sibling.** The existing device commits
  the new leaf.
- **MLS gate rule (new):** any member may commit leaves certified by its own DID, and
  remove its own DID's leaves. Roles still govern adding and removing *other* DIDs.
- **Removing a DID** removes all its leaves.

**Unchanged:** blocks (signed by the DID key), DM slugs, roles, ownership, pins,
admission and reputation. `--anon` keys (D20) never pair.

**History** before a device joined is unreadable to it. Transfer between sibling devices
is v0.3.

**The cost.**
- Every device holds the identity.
- A stolen device burns the DID. Its holder revokes it (Q3) and, if they choose, links a
  new DID (Q2).
- This is key ablation as designed: keys are expendable.

## Q2. Rotation and links

**Decided (DJ, 2026-10-18): a DID is bound to its key and does not outlive it.** A
rotation is a new DID. Rejected: an identity log that ties keys to a DID. Its online record
of every key behind a DID would undo key ablation, one of jig's main anonymity guarantees
([authn/authz design](2026-08-24-jig-server-authn-authz-design.md): "unless I tell
them").

**Decided (DJ, 2026-10-18): the holder chooses who learns that two DIDs share a
holder.**

### The link statement

A **link** is one signed object:

| Field | Meaning |
| --- | --- |
| `old` | The DID being left |
| `new` | The DID taking over |
| `audience` | Exactly one of: a channel (its `channel_id`), a nameserver DID with an alias, a contact's DID, or `public` (servers only, in practice) |
| `issued_at` | When it was signed |

- **Signed by both keys**, so neither key alone can claim the other.
- **Not published by default.** The holder hands it to the audience it names.
- **Bound to its audience.** A link scoped to one channel cannot move roles in another,
  or an alias.

**Push-back: a disclosed link is permanent and can be forwarded.** A signature proves the
link to anyone the recipient shows it to. "The holder chooses who learns" therefore holds
only as far as each recipient keeps it to itself. The CLI must say so before it sends one.
**Deniable links** would fix this for contacts: a MAC under a key the two parties share, so
the recipient is convinced but cannot prove it to anyone else. They are v0.3. Channels and
nameservers need a transferable signature, because more than one party verifies the link.

**Push-back: keeping a public name means a public link.** A nameserver that moves
`alice@example.org` to a new DID must show the link to every resolver that pinned the old
DID (F 4.4). That is the point of keeping the name. A holder who wants ablation drops the
name.

### What a link moves, per audience

| Audience | What moves | How |
| --- | --- | --- |
| A channel | The old DID's roles (owner, co-owner, admin), and its membership | A `key-link` block, authored by the new DID, carrying the link. Through `ingest`, so the chain fixes the cut-over. From that `seq`, the owner's server reads the old DID's roles as the new DID's. The new DID commits its own leaves in, and the old DID's leaves out, under the Q1 gate rule. The creator rule (F 5.9: the creator cannot be demoted) carries across the link |
| A nameserver and alias | The alias attestation | `/v1/rotate` takes the link (audience = that nameserver and alias) in place of today's two challenge signatures. The nameserver keeps it and serves it with the new attestation. Name pins follow it (F 4.4, L7 item 11) |
| A contact | The contact's pin of the old DID, and the DM | Sent in the old DM. The contact's client moves its pin and opens the new DM (a new slug), showing the old one locally as earlier history |
| `public` | Server pins, peers' `expected_did`, sequencing | Q4 |

**Not moved by any link:** reputation. A score is a scorer's opinion of a DID. Whether a
scorer accepts a link it is shown is the scorer's policy, and a holder with a bad score
need not show one. This is what ablation means
([authn/authz phase 4](../plans/2026-09-11-authn-authz-phase-4-admit.md): "unknown is a
choice").

**A fork.** Two links from one old DID to different new DIDs mean the old key was stolen.
Any verifier that holds both keeps them as evidence and accepts neither automatically.

### Encoding

**Decided (DJ, 2026-10-18): COSE over deterministic CBOR (A5).**
- Single-signer objects (revocations, leaf certificates) are COSE_Sign1 (RFC 9052),
  EdDSA with Ed25519, over RFC 8949 section 4.2 deterministic CBOR.
- Links are COSE_Sign, with two signatures.
- Every payload carries a domain tag: `jig-key-link-v1`, `jig-key-revoke-v1`,
  `jig-mls-leaf-v1`.
- Encoding sits behind one trait, so another encoding would be one new implementation.
- The link type implements F's `AliasLink` trait (`jig_core::naming`, #147), so
  `verify_rotation_chain` checks alias moves without knowing the encoding.
- This is the same stack as the v0.3 receipts.

#### The link, byte for byte

Implemented in `jig_core::key_link`. Test vectors, one per audience, are in
`repos/jig-spec/jep/vectors/key-link/vectors.json`. Field names and the `domain` entry
follow JEP-0004's signed objects.

The payload is a text-keyed map in RFC 8949 section 4.2 deterministic CBOR:

| Key | Type | Value |
| --- | --- | --- |
| `domain` | text | `jig-key-link-v1` |
| `old` | text | The DID being left (`did:jig:z…`) |
| `new` | text | The DID taking over. Must differ from `old` |
| `audience` | map | One of the four below |
| `issued_at` | integer | When it was signed, in Unix seconds |

| `audience.kind` | Other keys | Meaning |
| --- | --- | --- |
| `channel` | `channel_id`: bytes, the channel's binary canonical CIDv1 (raw codec, BLAKE3-256), as ingest records carry it | The old DID's roles and membership in that channel |
| `alias` | `ns_did`: text; `alias`: text, the full lowercased `local@suffix` | That alias at that nameserver (JEP-0004 rule 9) |
| `contact` | `did`: text | That contact's pin of the old DID |
| `public` | none | A server's own key change |

The envelope is a COSE_Sign (RFC 9052) with an empty body header and exactly two
signatures, each with protected header `{1: -8}` (EdDSA) and no `kid`: first by `old`,
then by `new`. A verifier:

1. parses the envelope and refuses any other shape;
2. decodes the payload, checks `domain`, and checks every field: DIDs are `did:jig`
   keys, `old` ≠ `new`, a `channel_id` is a canonical CIDv1 in its canonical encoding,
   an `alias` is a full name in its canonical spelling;
3. re-encodes the fields and requires the exact payload bytes, which refuses unknown keys
   and non-canonical encodings;
4. checks the first signature against `old` and the second against `new`.

A verifier acts on a link only for the audience it names. Two verified links with the same
`old` and different `new` are a fork (`key_link::fork`): evidence of a stolen key, followed
by neither.

## Q3. Revocation

**Decided (DJ, 2026-10-18): self-revocation.**

**The statement.** A **revocation** is signed by the key it revokes:
`{did, compromised_since?, issued_at}`.
- It names no other DID, so it links nothing.
- It is final: nothing un-revokes a DID.
- A thief can sign one too. That only burns a key that was already burned.

**Who learns, and how fast:**

| Party | How it learns | Then |
| --- | --- | --- |
| Each channel the DID is in | A `key-revoke` block, posted by the holder's client from its local `groups.json` list, through `ingest` | The owner's server refuses blocks from the DID after that `seq`. Members remove its leaves (any member may remove a revoked DID's leaves). Blocks before the cut-over stay valid. If `compromised_since` is set, clients mark the DID's blocks after that time as suspect, and still show them |
| Custodians (F 5.4) | Sent directly | They stop releasing its key packages |
| Nameservers | Sent directly | They expire attestations bound to it. A later link to a new DID re-binds the alias |
| Servers it authenticates to | Sent directly, and seen in channels | They refuse its handshakes |
| Everyone else | Head gossip and carriers, eventually | Bounded by gossip, not by any guarantee. The spec says so |

**What cannot be done:**
- **Past content stays read.** Whatever the stolen device decrypted cannot be recalled.
  MLS post-compromise security protects only epochs after the removal commit.
- **A withheld revocation.** A hostile sequencer can withhold a `key-revoke` block. The
  holder detects that the same way as any withheld block (`seen`, L7) and posts through
  another carrier. This is ID-03.
- **Recovery after total loss.** A holder whose only copy of the key is gone cannot sign
  a revocation. But the key is gone for a thief too, unless the thief holds the device.
  So the CLI makes a **recovery kit** (`jig keys export`, an age file) at `jig init` and
  asks the holder to store it elsewhere. Recovery contacts are v0.3, with lane R.

## Q4. The server-key ceremony

**Decided (DJ, 2026-10-18).** A server publishes a `public` link. On a verified link,
clients move the server pin, peers move `expected_did`, and the old key hands over
sequencing for every channel it sequences.

**Steps:**

1. **Generate** the new key into a `.jigkey`. Sign the link `old → new`, audience
   `public`.
2. **Publish the link:**
   - in the old DID's **manifest log** (L7 item 13), as its last block, a
     `server-rekey` block carrying the link;
   - the first block of the new DID's manifest log cites it;
   - the welcome carries the link during an overlap window (a config value; 30 days is
     the proposed default).
3. **Hand over sequencing.** In each channel it sequences, the server ingests a
   `sequencer-rekey` record:
   - signed by the **old** key, at `seq` = head + 1;
   - naming the new DID and citing the link;
   - from the next `seq` on, the new key signs records.

   No owner signature is needed: this is the same server under a new key, not a new
   sequencer.
4. **Re-issue the TLS binding** (#95). `/.well-known/jig` serves a certificate vouched
   for by the new DID. During the overlap the old key also vouches, so clients that still
   pin the old DID connect, read the link, and move.
5. **Retire the old key.** At the end of the overlap the server signs a revocation of
   the old DID, and the old key's `.jigkey` is destroyed.

**What a client or peer does when the server is not the pinned DID:**

| What it finds | Result |
| --- | --- |
| A link `pinned → presented`, audience `public`, both signatures valid | Move the pin (or `expected_did`) and say once: the server's key changed, the date, signed by the old key. No refusal |
| No link, or one that does not verify | A class 3 contradiction (L7): refuse and keep evidence. Not sticky: the server has signed nothing that proves a lie |
| Two links from the pinned DID to different DIDs | Server-signed evidence of a stolen key: a **sticky** refusal (L7 item 9) until `jig trust accept` |
| A `sequencer-rekey` not signed by the expected sequencer, or naming a DID without a matching link | A class 3 contradiction in that channel's chain |

**How it fits L7:**
- Signed refusals verify under whichever DID the client accepted at the time.
- `sequencer-set` is unchanged: it is still the owner's tool to move a channel to another
  *server*.
- `sequencer-rekey` is a new record kind (an L7 amendment): the *same* server under a
  new key, signed by the old key, with the link cited.
- **Precedence: the owner's `sequencer-set` beats a server's `sequencer-rekey`** (L7's
  rule, 2026-10-18). A `sequencer-rekey` is the server's own act, so a leaked server key
  could otherwise rekey channels to a thief's DID without the owner.
  - The owner may answer a rekey with a `sequencer-set` whose cited head is the record
    before the rekey. That set overrides the rekey.
  - Carriers that hold the set refuse the rekey and every record after it, the same way
    they refuse a partitioned old sequencer (L7 item 5).
  - A rekey never overrides a `sequencer-set`. A rekey whose cited head precedes a set
    the carrier already holds is a class 3 contradiction.
- A compromised server key is the race case. The thief can sign a competing link, and
  the fork row above catches it. Rotate fast and revoke the old key. Owners undo any
  rekey to the thief's DID with `sequencer-set`, under the precedence rule above.

**Bots (C3)** have their own DIDs, so a server rekey does not touch them. A bot is rekeyed
by its host with its own `public` link, and the owner's next `block-install` names it.

## Q6. Coordination with other lanes

| Lane | What this design asks of it | When |
| --- | --- | --- |
| L7 (handshake, pins, trust) | A `sequencer-rekey` record, which an owner's `sequencer-set` overrides; the welcome carries a server link during the overlap; the evidence bundle takes link forks; `server-rekey` joins the manifest log's allow-list; `jig trust` shows key changes and revocations | I2 |
| F (federation, naming) | `/v1/rotate` takes a COSE link in place of two challenge signatures, and serves it with the attestation. The name-pin rule (4.4) reads "a link from the pinned DID, audience this nameserver and alias". Roles follow a channel-scoped `key-link` at its `seq` (5.9), and the creator rule carries across. Custodians release one key package per device, and stop on revocation. Peers move `expected_did` on a `public` link | I2 (servers), I3 (users), I4 (devices) |
| A (block ABI), A5 | New block kinds `key-link` and `key-revoke`; the COSE stack is shared with receipts | I2 |
| C (capabilities) | Bot keys sealed in the server's keystore (I1). Bot rekey by `public` link | I1, I2 |
| S (suite registry) | MLS credentials carry a leaf certificate; the conformance vectors grow a multi-device case | I4 |
| L3 (CLI) | `jig keys protect`, `jig keys export`, `jig keys rotate` (rebuilt on links), `jig keys revoke`, `jig device pair` | I1 to I4 |
| R (reputation) | Whether and how a scorer accepts a link it is shown; recovery contacts | Later |

## Proposed spec and JEP changes

These are applied in implementation PRs, not in this one.

- **`crypto.md`:**
  - Fix the DID encoding (base32, `z` prefix).
  - "Storage": the slot model, and a plain statement of what at-rest encryption does not
    cover.
  - "Rotation": a rotation is a new DID. Replace the old certificate with the link: both
    keys sign it, and the holder chooses its audience. **Drop the MUST that publishes
    rotations to a transparency log**, which contradicts key ablation. Servers publish
    theirs.
  - "Revocation": self-revocation. Threshold revocation by peers becomes recovery
    contacts (v0.3, lane R).
- **`zero-trust.md` and `security.md`:**
  - Server rotation becomes the Q4 ceremony.
  - The incident runbook (`security.md:466`) becomes "revoke, then link, to whom you
    choose".
- **`threat-register.md`.** New rows:
  - ID-01: stolen device;
  - ID-02: link fork (stolen key);
  - ID-03: revocation withheld by a sequencer;
  - ID-04: key or cache theft at rest;
  - ID-05: a disclosed link forwarded.

  PV-03 gains a sentence: a link is the one message that ties two DIDs, and only the
  holder makes one.
- **A new JEP, "Key links and revocation"** (its number is still to be assigned: 0006 went to the block ABI): the objects, their encoding, the
  `key-link`, `key-revoke`, `server-rekey` and `sequencer-rekey` records, and who acts
  on each.
- **JEP-0001 Q4:** a leaf per device, under leaf certificates. A rotation is a new DID
  and a channel-scoped link.
- **JEP-0002:** `sequencer-rekey`; the welcome carries the link during an overlap.
- **JEP-0004 and JEP-0005:** `/v1/rotate` on links; roles across links; custodians per
  device.

## Milestones

**Decided (DJ, 2026-10-18): G2 waits on I1 only.**

| Milestone | Scope | Gate | Rough size |
| --- | --- | --- | --- |
| **I1. Keys at rest** | The `.jigkey` envelope and slots; encrypted MLS state and plaintext cache; server, nameserver and bot keys; migration; `jig keys protect` and `jig keys export` (the recovery kit); `crypto.md` storage text | **G2** | 3 PRs ([plan](../plans/2026-10-18-identity-i1-keys-at-rest.md)) |
| **I2. Signed objects and the server ceremony** | The COSE and deterministic-CBOR stack; links and revocations; `server-rekey`, `sequencer-rekey`, link-following in clients and peers; TLS re-binding | M3 | Medium, and it depends on L7's manifest log and `ingest` records |
| **I3. User rotation and revocation** | `key-link` and `key-revoke` blocks; roles across links; `/v1/rotate` on links; the contact and DM flow; `jig keys rotate` and `jig keys revoke` | M3 | Medium, and it depends on F's roles |
| **I4. Devices** | Pairing; leaf certificates and fresh leaf keys; the MLS gate rule; one key package per device at custodians | M3 | Medium, and it depends on F's custodians |
| **Later (v0.3)** | Deniable links, history transfer between devices, an unlock agent, hardware slots, recovery contacts | | |

## Decisions log

| # | Question | Decision (DJ, 2026-10-18) |
| --- | --- | --- |
| I-Q5 | Keys and MLS state at rest | Key slots: keychain, passphrase, credential, env |
| I-Q2 | Does a DID outlive its key? | No. A DID is bound to its key; an identity log would undo key ablation. A rotation is a new DID |
| I-Q2b | Who learns that two DIDs are linked? | Whoever the holder chooses: a link signed by both keys, scoped to one audience. Servers publish theirs |
| I-Q1 | Devices | The DID key copied by pairing; a fresh MLS leaf key per key package, certified by the DID |
| I-Q3 | Revocation | Self-revocation, posted to channels, custodians, nameservers and servers |
| I-Q4 | Server ceremony | A `public` link moves pins and `expected_did`; the old key signs a `sequencer-rekey` in each channel it sequences |
| I-A5 | Encoding | COSE over deterministic CBOR, behind a trait |
| I-Scope | What G2 waits on | I1 only |
