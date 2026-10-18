# Identity lifecycle: keys at rest, devices, rotation, revocation

**Date:** 2026-10-18
**Author:** DJ + Claude (lane I)
**Status:** Research pass. Every answer below is a **recommendation**, not a decision. DJ
decides them one at a time in this lane's Q&A, starting with Q5 (keys at rest), because
gate G2 waits on it. No code until DJ approves.
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

So rotating a key today means a new DID, and a new DID loses the channels it owns, its
DMs, its roles, its pins at every contact and every peer, and its reputation.

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

## The idea that makes the rest cheap

**Make the DID outlive its key.** Keep today's DID string, `did:jig:z<base32(key)>`, but
read it as "the identity whose first key is this one", as did:plc and KERI do. Each DID
gets an **identity log**: an append-only chain of entries, each signed by a key the log
already authorises. A DID with an empty log is exactly today's DID, so every existing
identity stays valid with no migration.

Then:

- **Rotation changes no DID.** Channel ownership, roles, memberships, DM slugs, server
  pins, `expected_did`, `ingest` signers, name attestations and reputation all stay put.
  Nothing has to "follow" a rotation, because nothing that is keyed by DID moves.
- **Devices are entries in the same log.** Adding and revoking a device is the same
  mechanism as rotating.
- **The cost is one new seam:** every verifier asks "which keys does this DID authorise
  at this point?" instead of decoding the DID. That is about 20 call sites today, behind
  one `KeyResolver` in `jig-core`.

The alternative is a new DID per rotation, plus a rotation certificate linking old to new
(what `crypto.md` describes now). Every DID-keyed thing then needs its own migration rule,
and one of them breaks outright: a server that rotates its key would need every channel
owner to sign a `sequencer-set` naming its new DID (L7 item 5), because only owners move a
sequencer. Q2 compares the two.

## Q5 first: keys and MLS state at rest (gates G2)

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

**Recommendation: A.**

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

**Exported backups** use age: `jig keys export` writes the seed (and, later, the identity
log) to an age file, encrypted to a passphrase or an age recipient. That is a standard,
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
once rotation exists (milestone I2). `jig-server` refuses a raw keyfile unless the flag is
set, and prints the one command that seals it.

**Crates:** `chacha20poly1305`, `argon2`, `keyring` (OS keychains), `zeroize`. All are
RustCrypto or widely used. `age` for export only.

**Push-back on a likely assumption:** "a server key encrypted at rest protects users from
the operator." It does not. The key belongs to the operator. At rest it protects the
operator from disk theft and leaked backups. Restricted content is protected from the
operator by MLS (D25), not by this.

## Q1. Device model

| Option | MLS | Signatures | DM slugs, ownership, roles | Admission and reputation | Revoking one device |
| --- | --- | --- | --- | --- | --- |
| **A. One DID per device, plus an account-binding certificate** | A leaf per device | Each device signs as itself | Keyed by device, so DMs and ownership fork per device, or everything moves up to a new "account" identifier | Split per device, or moved to the account | Easy |
| **B. One DID key copied to every device** (Signal) | Impossible as is: RFC 9420 7.3 forbids two leaves with one signature key. MLS would need per-device keys anyway, so B becomes C for MLS | Unchanged | Unchanged | Unchanged | Impossible without a new key for the whole identity: every device holds the root |
| **C. Device keys certified by the DID** (Matrix, Keybase) | A leaf per device; the credential is the DID plus the device's certificate | A device key signs; the signature carries its certificate | Unchanged: still keyed by DID | Unchanged: still per DID | One log entry. The DID does not change |

**Recommendation: C**, built on the identity log.

- **Option A is C with the names swapped.** Its "account" identifier is C's DID, and
  everything that is keyed by DID today would move to it.
- **Option B is not available for MLS,** and a stolen device is unrecoverable without a
  new identity.

### How C works

**Keys and their powers:**

- The **root key** is the DID's first key, or whichever key the log last rotated to.
- **Device keys** are Ed25519 keys, one per device, each added by a `device-add` entry.
- **Who may sign what:**

  | Entry | Root | Any device |
  | --- | --- | --- |
  | `device-add` | yes | yes (Keybase's rule; every other device shows the addition) |
  | `device-revoke` | yes | yes. A stolen device that revokes the others is a denial of service; the root re-adds them |
  | `root-rotate` | yes, at once | yes, but it takes effect only after a **contest window** (did:plc's idea; default 72 hours). The root can veto it inside the window. This is how "a second device signs a rotation" (F's Q3) stays safe against a stolen device |

- **Where the root lives.** On the first device by default, plus a recovery kit (an age
  export) that the CLI asks the user to make. A user may move it offline and run every
  device on a device key.

**Blocks:**

- The author is still the DID.
- The signature is by a device key. The block carries that device's certificate (the
  `device-add` entry, about 200 bytes) and the identity-log head it was signed under.
- A verifier checks the chain back to the DID with no network round trip.
- **Legacy path:** a block signed by the DID's own key, under an empty log, verifies
  exactly as today.

**MLS:**

- **A leaf per device.** The credential is the DID; the signature key is the device key;
  a leaf extension carries the device certificate. `jig_mls::credential::bound_did`
  checks the certificate instead of decoding the DID.
- **Adding a DID adds all its devices.** A `member-add` names the DID, and the commit adds
  one leaf per current device, from key packages each device stocks at its custodians
  (F 5.4). Alice's release policy (F 5.4) is per DID, so it covers all her devices.
- **A new MLS gate rule:** any member may commit leaves for its own DID's devices, and any
  member may remove a leaf whose device the DID's log revoked. Both are checked against
  the log, not the role. Roles still govern adding and removing *DIDs*.
- **A new device reads from the epoch it joins.** Moving history between one's own
  devices (a private self-channel, as in Matrix key backup or Signal's transfer) is v0.3.

**DM slugs** hash the two DIDs and are unchanged. **Admission and reputation** stay per
DID. A server may still limit devices per DID.

**Privacy (PV-03):**

- A DID's log shows how many devices it has.
- MLS leaves show the same to channel members, as in every multi-device MLS system.
- Device certificates name no device and no platform.
- No entry links two DIDs.
- `--anon` keys (D20) are unaffected: they have no log.

## Q2. Rotation: format, propagation, and what follows it

### Options

| Option | What rotation is | What must follow it |
| --- | --- | --- |
| **A. The DID outlives its key (identity log)** | A `root-rotate` entry in the DID's log, signed by the old root and the new one | Nothing that is keyed by DID. Verifiers learn the new key from the log |
| **B. A new DID, with a rotation certificate** (`crypto.md` today) | A dual-signed certificate from old DID to new DID | Pins, `expected_did`, ownership (F has no ownership transfer before v0.3), roles, memberships (an MLS rejoin), DM slugs (a new DM; history splits), reputation, name attestations. Server rotation needs a `sequencer-set` from every owner whose channel the server sequences |

**Recommendation: A.** B is the status quo's design, and it turns one key change into
eight migrations, one of which another party has to sign.

### The identity log

| Field | Meaning |
| --- | --- |
| `did` | The DID |
| `seq` | 0, 1, 2, … |
| `prev` | Hash of the previous entry; absent at 0 |
| `kind` | `device-add`, `device-revoke`, `root-rotate`, `root-veto` |
| `body` | Per kind: the device key; the revoked key and an optional `compromised_since`; the new root key; the vetoed entry's hash |
| `signer` | The key that signs: root, or a device the log authorises at `seq - 1` |
| `sig` | The signature. A `root-rotate` by the root carries two: old root and new root |

- **Self-certifying.** Entry 0 is checked against the key the DID string encodes. Each
  later entry is checked against the key set the log has authorised so far.
- **A fork is evidence.** Two valid entries at one `seq` are proof of a stolen key (or of
  equivocation), the same shape as two conflicting `ingest` records. The client keeps
  both and asks the user to choose (L7's evidence bundle, item 9).
- **Pre-rotation** (KERI: each root commits to the hash of the next root) is an optional
  field reserved for v0.3. It closes the race in which a thief with the current root
  rotates first.

### Encoding (A5)

**Recommendation:** each entry is a COSE_Sign1 (RFC 9052) over deterministic CBOR (RFC
8949 section 4.2), algorithm EdDSA with Ed25519. A dual-signed `root-rotate` is a
COSE_Sign with two signatures. This matches the v0.3 receipts (A5), so jig would have one
stack for long-lived signed objects. The other formats are short-lived or wire-level.

**Swappable:**

- The verifier consumes a decoded `LogEntry` and the exact bytes that were signed.
- Encoding sits behind one trait. A labelled-BLAKE3 encoding (`hash_labeled_parts` with
  the domain `jig-identity-log-v1`, the form F 4.6 uses for attestations) implements the
  same trait.
- If DJ decides A5 does not extend past receipts, I1 to I3 ship with the labelled hash
  and lose nothing.
- The domain tag goes into the signed bytes either way.

### Propagation: how everyone learns

There are no rotation endpoints to add. The log is served wherever the DID is already
found.

1. **Custodians and the reachability record (F 4.7).** The record gains `id_head`:
   `{seq, hash}`. Every custodian that stocks the DID's key packages also serves its log.
   Key packages are signed by device keys, so a custodian must serve the log for them to
   verify at all.
2. **Nameservers** serve the log next to the attestation. Under A, an alias stays bound to
   the same DID across rotations, so `/v1/rotate` is only for moving an alias to a
   *different* DID, and F's name-pin rule fires only then. Key rotation stops touching
   names at all.
3. **In each channel: an `identity-update` block.** It cites a log entry. The DID's own
   device posts one into every channel it is in after a rotation or revocation. Servers
   may post one too. It goes through `ingest`, so the channel's own chain fixes the order:
   blocks before it are judged by the old key set, blocks after it by the new one. A
   hostile sequencer that delays it is outrun by the DID's device posting it, and by
   carriers that already hold the newer log.
4. **The handshake.** A client's `hello` authentication carries its device certificate
   and `id_head`. A server answers with its own, so clients learn of server rotations at
   connect (Q4).
5. **Head gossip.** Identity-log heads ride L7's anonymous head gossip next to `ingest`
   heads, so a fork that only some carriers saw becomes visible to all.

### What each DID-keyed thing does

| Thing | Under A |
| --- | --- |
| Server pins (`pins.json`), `expected_did` | Unchanged. The pin store adds the last verified `id_head` per DID |
| Name pins (L7 item 11) | Unchanged on rotation. A name that moves to another DID still follows F's rule. F's "signed by the old key" reads as "signed by a key the old DID's log authorises" |
| Channel ownership, co-owners, roles (F 5.9) | Unchanged |
| Memberships, MLS leaves | Unchanged by root rotation: device certificates the old root signed stay valid. A revoked device's leaves are removed (Q3) |
| DM slugs | Unchanged |
| `ingest` signers, the manifest log | Unchanged. Records are checked against the sequencer DID's keys at that `seq` (Q4) |
| Reputation | Unchanged |

## Q3. Revocation

- **One device lost or stolen:**
  1. Another device, or the root, signs `device-revoke`.
  2. It posts `identity-update` into each of the DID's channels.
  3. It commits the removal of that device's leaves.
  4. Other members may also remove a revoked leaf (Q1's gate rule).
- **Latency:**
  - Immediate at any server that sees the update.
  - In every channel, as fast as a remaining device can post. The CLI does it on the
    revoke command and again at its next connect.
  - A channel nobody posts the update to keeps accepting the revoked key until a carrier
    learns the log from gossip, a handshake or a custodian. That is bounded by gossip, not
    by any guarantee. The spec says so.
- **Past content:**
  - Blocks ordered before the `identity-update` stay valid: they were signed while the key
    was good, and the chain proves the order.
  - What the stolen device had already decrypted is gone; nothing can recall it.
  - After the removal commit, MLS post-compromise security keeps it out of new epochs.
  - If the revocation carries `compromised_since`, clients mark that device's blocks
    after that time as suspect. They still show them; they never delete them.
- **Root lost, a device left:** the device signs `root-rotate`, which takes effect after
  the contest window.
- **Root stolen:** rotate from the root, or the recovery kit, at once, and revoke the
  devices. A thief who rotated first creates a fork (two entries at one `seq`). That is
  evidence, not a resolution: contacts see a fork and must choose. Pre-rotation (v0.3)
  removes this race.
- **Everything lost:** the identity is gone. The user makes a new DID and contacts accept
  it by hand (F's rule). `crypto.md`'s threshold revocation by trusted peers becomes
  **recovery contacts**: a k-of-n log entry naming DIDs who may jointly sign a
  `root-rotate` after a longer contest window. That is v0.3, with lane R (tribunals).

## Q4. The server-key ceremony

**A server is a DID like any other,** so it gets the same log. The practice the spec
already asks for ("HSMs or encrypted volumes", "rotate annually") becomes concrete:

- **Root offline, operational key online.** The server runs on a device key. Its root
  lives offline: in a `.jigkey` with only a passphrase slot, on another machine, or
  later in an HSM.
- **A routine rotation** is `device-add` of a new operational key followed by
  `device-revoke` of the old. It is cheap enough to automate. Every DID-keyed thing
  stays put.
- **The ceremony is for the root.** It is rare: compromise, or a policy period.

**Steps:**

1. **Generate** the new key and **sign** the log entry: the old key signs; for a root,
   both keys sign.
2. **Publish:**
   - an `identity-update` block in the server's **manifest log** (L7 item 13; add the kind
     to the manifest log's allow-list);
   - an `identity-update` in each channel it sequences, so each `ingest` chain fixes the
     cut-over `seq`;
   - the new `id_head` in its welcome.
3. **Re-issue the TLS binding** (#95). `/.well-known/jig` serves a certificate vouched for
   by the new key, plus the log chain that authorises it. During an overlap window it
   serves both, so connections that are already open and cached certificates keep
   working.
4. **Peers** keep `expected_did`. The mutual handshake (L7 item 12) carries `id_head`
   both ways, so each peer verifies the extension and moves on.
5. **Revoke** the old operational key once the overlap ends.

**What a client does on a mismatch** (the server signs with a key the client did not
expect):

| What the client finds | Result |
| --- | --- |
| A log chain from its pinned `id_head` that authorises the new key | It updates `id_head` and says once that the server rotated its key, on what date, signed by the old key. No refusal |
| No chain, or a chain that does not verify | A class 3 contradiction (L7): refuse, keep evidence. Not sticky: the server has signed nothing that proves a lie |
| A fork: two valid entries at one `seq`, both signed by the server's keys | Server-signed evidence, so the refusal is **sticky** (L7 item 9) until `jig trust accept` |

**How it fits L7:**

- **Signed refusals** (`jig-handshake-refusal-v1`) verify under the key set at the time
  of signing.
- **`ingest` records** verify under the sequencer DID's keys at that `seq`. The
  `identity-update` record marks the cut-over inside each chain.
- **`sequencer-set`** is untouched: it names a DID, and the DID did not change. That is
  the main reason to prefer A.
- **A server that moves the sequencer** (`sequencer-set`) to escape a key compromise is
  the wrong tool. Rotation is the right one. The runbook should say so.

## Q6. Coordination with other lanes

| Lane | What this design asks of it | When |
| --- | --- | --- |
| L7 (handshake, pins, trust) | Pins keep `id_head` per DID. The evidence bundle takes identity-log forks. `hello` and the welcome carry the device certificate and `id_head`. The name-pin rule reads "signed by a key the old DID's log authorises". `identity-update` joins the manifest log's allow-list. `jig trust` shows device lists and pending rotations | I2 (servers) and I3 (devices). Nothing in I1 |
| F (federation, naming) | The reachability record gains `id_head`. Custodians and nameservers serve logs. Key packages are per device; a `member-add` adds every device. `/v1/rotate` narrows to "alias moves to another DID". Role checks are unchanged | I3 |
| A (block ABI) | Blocks carry a signer certificate and `id_head` beside the author DID | I3 |
| C (capabilities) | Bot keys are sealed in the server's keystore (I1). A bot is a DID, so it can have a log, and its host rotates it | I1, then I2 |
| S (suite registry) | The MLS credential carries a device certificate, so the `mls` suite's conformance vectors grow a multi-device case | I3 |
| L3 (CLI) | New commands: `jig keys protect`, `jig keys export`, `jig device link / list / revoke`, `jig keys rotate` rebuilt on the log | I1 to I4 |
| DJ (A5) | Whether COSE extends to identity-log entries | Before I2 |

## Proposed spec and JEP changes

These are applied in implementation PRs, not in this one.

- **`crypto.md`**
  - Fix the DID encoding (base32, `z` prefix).
  - Replace "Storage" with the slot model and the plain statement of what at-rest
    encryption does not cover.
  - Replace the rotation-certificate section with the identity log.
  - Replace threshold revocation with recovery contacts (marked v0.3).
- **`zero-trust.md`, `security.md`:** server rotation is a log entry, and the DID stays.
  The incident runbook (`security.md:466`) becomes "revoke the device, or rotate the root".
- **`threat-register.md`**
  - New rows:
    - ID-01: stolen device.
    - ID-02: identity-log fork or equivocation.
    - ID-03: revocation withheld by a sequencer.
    - ID-04: key or cache theft at rest.
  - OP-08 and PV-03 updated.
- **New JEP-0006, "Identity logs":** entry format, verification, propagation and the
  `identity-update` block.
- **JEP-0001 Q4:** answered by JEP-0006: a leaf per device; rotation without a rejoin.
- **JEP-0002:** `id_head` and the device certificate in `hello` and the welcome.
- **JEP-0004 and JEP-0005:**
  - `id_head` in the reachability record.
  - Logs served by custodians and nameservers.
  - `/v1/rotate` narrowed.

## Milestones

| Milestone | Scope | Gate | Rough size |
| --- | --- | --- | --- |
| **I1. Keys at rest** | The `.jigkey` envelope and its slots; encrypted MLS state and plaintext cache; server, nameserver and bot keys; migration; `jig keys protect` and `jig keys export`; `crypto.md` storage text | **G2** | 3 PRs: envelope and slots in `jig-core`/`jig-client`; MLS directory; servers and migration |
| **I2. Identity logs, servers first** | The log format and verifier (`KeyResolver`, replacing direct DID decoding); `identity-update`; servers on operational keys; the root ceremony; client handling of mismatches; manifest-log and TLS-binding changes | M3 | Large: the resolver seam touches about 20 files |
| **I3. User devices** | Device keys and certificates; device linking (the new device shows a code, an existing device confirms and signs); a leaf per device; key packages per device; the MLS gate rule | M3 | Large; leans on F's custodians |
| **I4. Revocation and contested rotation** | `device-revoke` end to end, leaf removal, `compromised_since`, rotation from a device with the contest window and veto | M3 | Medium |
| **Later (v0.3)** | Pre-rotation, recovery contacts, history transfer between one's own devices, hardware slots, an unlock agent, a transparency log (lane R) | | |

**Push-back on scope:** the phase-1 list has "multi-device and key rotation; a server-key
rotation ceremony", but phase 1's exit criterion does not mention them. I recommend that
G2 wait only on I1, and that I2 to I4 land in M3. DJ should say if v0.2 must hold them.

## Open questions for DJ, in order

1. **Q5:** key slots (A), passphrase only (B), or an honest `crypto.md` for G2 (C).
   Recommended: A.
2. **Q2:** does the DID outlive its key (identity log, A) or does each rotation make a new
   DID (B)? Recommended: A. This decides most of the rest.
3. **Q1:** device subkeys certified by the DID (C), a copied root key (B), or a DID per
   device (A). Recommended: C.
4. **Q1 detail:** may any device add devices, and may a device rotate the root after a
   72-hour contest window? Recommended: yes to both.
5. **A5:** COSE_Sign1 over deterministic CBOR for log entries, or the labelled BLAKE3
   hash. Recommended: COSE, with the encoding behind a trait.
6. **Q4:** servers run on an operational key, with the root offline, by default?
   Recommended: yes, from I2.
7. **Scope:** does G2 wait only on I1? Recommended: yes.
