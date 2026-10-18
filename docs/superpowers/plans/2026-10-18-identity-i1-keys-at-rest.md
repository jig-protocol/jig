# Identity I1: keys and MLS state at rest, implementation plan

**Date:** 2026-10-18
**Design:** [identity lifecycle](../specs/2026-10-18-identity-lifecycle-design.md), Q5 (decided
by DJ, 2026-10-18: key slots).
**Gate:** G2. The phase-1 line is "Keys and the MLS plaintext cache are encrypted at rest".

## Locked semantics (from the design and DJ)

1. **The envelope:**
   - Each identity has one `.jigkey` file: a random 256-bit data key, one or more slots,
     and the 32-byte seed sealed under the data key.
   - Any one slot opens the file.
   - The AEAD is XChaCha20-Poly1305. Its associated data is the header: version, DID and
     slot list.
2. **Slots:**
   - `keychain`: the OS keychain, service `jig`, account the DID.
   - `passphrase`: Argon2id with m=64 MiB, t=3, p=4 and a per-slot salt.
   - `credential`: a path, for systemd `LoadCredentialEncrypted=`.
   - `env`: `env:NAME`.
   - The default is `keychain` where it works, else `passphrase`.
3. **MLS state is encrypted under keys derived from the data key.**
   - Keys come from BLAKE3 `derive_key`, one context per file.
   - `state.bin` and `groups.json` are sealed whole-file.
   - `plaintext.jsonl` is sealed one record per line.
   - The associated data binds the DID and the file's role.
4. **Plaintext storage is an antipattern flag.** It is `keys.storage = "plaintext"`, or
   `--insecure-plaintext-keys`. It warns on every run and is never the default.
5. **Migration is automatic for the CLI and explicit for servers.**
   - The CLI seals a raw `<did>.key` or `.key.rotated` on first load, re-encrypts the MLS
     directory, removes the raw files, and says that removal is not erasure.
   - `jig-server` and `jig-nameserver` refuse a raw keyfile without the flag. The error
     names the sealing command.
6. **What this does not cover:** malware running as the user, and keys in memory.
   `crypto.md` says so.
7. **The keyfile format freeze still holds.** A golden raw seed migrates to a `.jigkey`
   that loads to the same DID (`identity.rs`,
   `a_preexisting_keyfile_still_loads_to_its_original_did`).

## Ownership

| File | Owner | How |
| --- | --- | --- |
| New `jig-core/src/keystore/` | lane I (new files) | this plan |
| `jig-client/src/identity.rs`, `jig-client/src/secure.rs` | no lane listed in the v0.2 plan; L7 owns `pins.rs`, which this plan does not touch | lane I, after the orchestrator confirms |
| `jig-server/src/v0_0_2.rs` key loading | L3 sweeps v0.0.1 paths only; this is a v0.0.2 path | lane I; tell L3 |
| `jig-nameserver/src/v0_0_2.rs` key loading; the legacy `ns_identity` table in SQLite (a raw seed) | L6 | ask L6. Delete the legacy table if L6 removes the legacy routes, otherwise seal it |
| `jig-cli/src/cmd/{keys,init}.rs` | L3 | small PRs against `main`, coordinated with L3 |
| `repos/jig-spec/src/crypto.md` storage text | applied in the last implementation PR, after L1 merges | lane I |

## Task 1: the keystore in `jig-core` (PR 1)

- `Keystore::seal(seed, slots) -> JigKey` and `JigKey::open(&[Unlocker]) -> Seed`. The
  seed is held in `Zeroizing`.
- One `Slot` trait. `passphrase`, `credential` and `env` live here. `keychain` sits
  behind a `keychain` cargo feature, using the `keyring` crate, so servers build without
  D-Bus.
- `derive_file_key(data_key, context)` and the sealed-file and sealed-record helpers.
- The wire format: a magic number, a version, and a JSON header carrying the slots.
- New dependencies: `chacha20poly1305`, `argon2`, `zeroize`, and `keyring` behind its
  feature. `age` comes in Task 4.
- **Merge the two copies of `load_or_generate_server_key`,** one each in `jig-server` and
  `jig-nameserver`, into one function here.
- **Tests:**
  - a round trip through each slot;
  - a wrong passphrase fails;
  - a tampered header fails (swap a slot, change the DID, bump the version);
  - a tampered payload fails;
  - two slots, either one opens;
  - golden vectors for the format, with a fixed seed, salt and nonce.

## Task 2: CLI identities and MLS state (PR 2)

- `Identity::load_from_dir` opens `<did>.jigkey` and keeps the data key's derived file
  keys for `Session`.
- If only a raw `<did>.key` exists, it migrates (semantics 5), unless storage is
  `plaintext`.
- `Identity::generate_and_save` writes a `.jigkey` with the default slot.
- `secure.rs`:
  - `write_atomic` seals `state.bin` and `groups.json`;
  - `remember` and `reload_read` seal and open records in `plaintext.jsonl`;
  - a file left in clear by an older version is re-encrypted on first open, under the
    directory lock;
  - a record that fails to open is an error, never skipped. Today a line that does not
    parse is skipped, and the sealed path must not inherit that.
- `jig keys rotate` writes the new identity as a `.jigkey`, and seals the old one rather
  than renaming it to `.key.rotated`.
- **Tests:**
  - the existing `secure.rs` tests pass unchanged against sealed files;
  - no plaintext appears in any file under `~/.jig/mls/` (grep the bytes for a known
    message);
  - migration from a raw keyfile and a clear MLS directory;
  - concurrent `remember` from two `Session`s;
  - the format-freeze test (semantics 7).

## Task 3: servers, nameserver, bots (PR 3)

- `server_did_keyfile` accepts a `.jigkey`. A new `[keys] unlock = "credential:<path>" |
  "env:<NAME>" | "passphrase"` option says which slot to try.
- A server with no slot it can open refuses to start.
- `jig-server keys seal <raw> --slot credential:...` converts a raw keyfile.
- Bot keys (C3) are sealed by the same keystore when lane C builds them. The design
  only fixes the interface.
- The integration harness (`integration-tests/src/harness.rs`) uses the `env` slot.
- **Tests:**
  - startup with each slot;
  - refusal of a raw keyfile without the flag;
  - the flag's warning.

## Task 4: recovery kit and docs (in PR 3, or PR 4 if large)

- `jig keys export` writes an age file, to a passphrase or an age recipient.
  `jig keys import` reads one.
- `jig init` offers to make the kit.
- `jig keys protect --add <slot>` and `--remove <slot>`. Removing the last slot is
  refused.
- `crypto.md`:
  - the storage text;
  - the plain statement of what at-rest encryption does not cover (semantics 6);
  - the DID encoding fix (base32, `z`).
- Threat register: an ID-04 row.
- `docs/operations`: a systemd credential example.

## Exit criteria

- No identity key or MLS file is written in clear by default, by the CLI, the server or
  the nameserver.
- Existing users migrate on first run with no lost groups or history.
- `crypto.md:60` is true, and the "not yet implemented" note is gone.
- CI runs the keystore golden vectors.
- Every PR follows AGENTS.md: `CARGO_INCREMENTAL=0`, and build output cleaned before
  hand-back.
