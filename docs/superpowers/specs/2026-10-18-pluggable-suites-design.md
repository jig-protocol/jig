# Pluggable suites: a test suite and conformance vectors (lane S)

Status: questions settled by DJ 2026-10-18 (§6). Decision D13 is deferred (ROADMAP, settled 2026-10-18): v0.2 proves
suites are pluggable with a test-only second suite and per-suite conformance vectors. A
production second suite stays a stretch goal.

Exit criterion served: "suites are pluggable, shown by a test suite that runs through the
registry with conformance vectors" (ROADMAP, phase 1).

## 1. Audit: what assumes MLS

Read on `main` at `062fe91`. "Blocks" means a second suite cannot run until it changes.

| Where | Assumption | Effect on a second suite | Blocks? |
| --- | --- | --- | --- |
| `jig_core::EncryptionSuite` (`suite.rs`) | Closed enum `{Unencrypted, Mls}`; `REGISTERED`, `is_implemented` list both | A new suite is a new variant. That is the design: no catch-all, unknown ids never parse | Yes (add the variant) |
| `jig_pipeline::mls_gate::plan`, content branch | Every channel suite other than `mls` is treated as plaintext: no `body` check, no payload check, returns `Nothing` | A second encrypted suite's channel would accept a plaintext `body` and its blocks would get a normal (executed) receipt, not `"content": "sealed"` | **Yes, and fail-open** |
| `mls_gate::plan`, `channel-create` | `suite != Mls` → must be open; `Mls` → MLS genesis | Correct for D25 as long as the second suite is open-only (§3.4) | No |
| `mls_gate::check_dm_create` | A DM is `mls` | Correct: DMs stay MLS | No |
| `jig_client::secure::Session::observe` | Content whose suite is not `mls` is `Seen::Plain` | A client shows another suite's block as plaintext instead of "sealed, suite not supported" | Yes, fail-open on display |
| `jig_client::pins::ChannelPin::encrypted`, `jig-cli` `ChannelInfo::encrypted` | `encrypted == (suite == "mls")` | The CLI would post plaintext into a test-suite channel; the server refuses it (`SUITE_MISMATCH`), so this fails closed, but the CLI should refuse first | No (fix in the same PR, small) |
| `jig_pipeline::handshake::implemented_suite_names` | Advertises every implemented registered suite | Advertises the test suite whenever it is compiled in | No, as long as it is compiled only into tests (§3.3) |
| `fanout::DeliveryPolicy::federates`, `v0_0_2_federation` relay check | Only `none` federates | Fails closed for any new suite | No |
| `authorize_write` "tidy-up" removal | MLS-only leaf cleanup | MLS semantics; irrelevant to a stateless suite | No |
| `ingest::suite_refusal` | A plaintext `body` refusal reports the channel suite as the literal `"mls"` | Wrong diagnostic on another suite's channel | No (fix with the gate change) |
| `ingest` (`get_mls_group` lookup), `MlsPlan` | Named for MLS, keyed on `suite == "mls"` | Fine: a stateless suite needs no group row | No |
| `jig-mls` | One ciphersuite (`CIPHERSUITE`), one crate | Correct by JEP-0001: the MLS cipher suite is negotiated inside the group, not in jig's registry | No |
| Plaintext cache (`~/.jig/mls/<did>/plaintext.jsonl`) | Under the MLS directory, keyed by block CID | Suite-agnostic in shape; nothing to change for a test suite the CLI does not speak | No |
| CLI `channel create --encrypted`, 🔒 marker | Encrypted means `mls` | Correct: the CLI only creates MLS channels | No |

So two changes are needed before a second suite can exist, both small:

1. **Suite properties in the registry.** `EncryptionSuite` gains `is_encrypted()` (content is
   ciphertext; `false` only for `none`) and `payload_field()` (the metadata key that carries
   the ciphertext: `mls_message`, or the test suite's). The gate's content branch then checks
   any encrypted suite the same way: no `body`, the payload field present and base64, receipt
   sealed. MLS keeps its extra group validation. This also fixes the fail-open above for
   any future suite.
2. **Client display.** `observe` returns `Sealed { reason: "suite … not supported" }` for an
   encrypted suite it cannot decrypt, never `Plain`. `encrypted()` in pins and the CLI becomes
   `is_encrypted()`; the CLI refuses to post to a channel whose suite it does not speak.

No trait-object suite registry. Properties on the enum are enough for two suites, keep
exhaustive matching, and keep the "no catch-all variant" guarantee. A trait is worth it when a
production second suite with its own group state arrives (D13).

## 2. The test suite

**Id: `test-aead`.** The registry reserves the prefix `test-` for conformance testing. A
production build does not know any `test-` id, so it refuses one as unregistered
(`UNSUPPORTED_SUITE`), the rule every unknown suite already follows.

**Construction.** ChaCha20-Poly1305 under one static 32-byte key published in the spec
(the test vectors carry it). Per message:

- `test_ciphertext`: base64 of a 12-byte nonce followed by the AEAD output (one payload
  field, so the gate checks every encrypted suite the same way);
- AAD: the UTF-8 of `jig-test-aead-v1|<channel slug>|<sender DID>`, so a ciphertext cannot be
  replayed into another channel or under another author.

It is real authenticated encryption with a public key: confidentiality against nobody, which
is the point. It exercises the registry, the manifest's `privacy.encryption`, the handshake
advertisement, the gate, sealed receipts and the vectors without anything MLS. There is no
group state: membership blocks on a `test-aead` channel are plain control blocks.

`chacha20poly1305 0.10` is already in `Cargo.lock` (through openmls). Using it from jig-core
adds a dependency edge, so the build PR touches `Cargo.lock`; I tell the orchestrator before
it goes into the queue.

### 2.1 Keeping it out of release builds

- `jig-core` gets a feature `test-suite`. The `TestAead` variant, its registry entry and the
  AEAD code exist only under it.
- Only `dev-dependencies` enable it (`jig-pipeline`, `jig-server`, `integration-tests`).
  With resolver 2, dev-dependency features do not reach `cargo build`/`--release` of any
  binary.
- CI check: `cargo tree -e features -p jig-server -p jig-cli -p jig-nameserver` (normal
  edges only) must not contain `jig-core feature "test-suite"`. A failing grep fails the job.
- The handshake never advertises a `test-` suite, even in a test build. One `cargo nextest`
  run unifies features across every crate it tests, so advertising it there would change
  every handshake assertion in the workspace. The gate still accepts a `test-aead` channel
  in a test build, because creating a channel does not depend on what is advertised.

`cfg(test)` alone does not work: it applies only to the crate under test, and the gate, the
server and the integration tests are three other crates.

## 3. Conformance vectors

### 3.1 What a vector proves

A vector pins **jig's mapping**, not the cryptography beneath it. RFC 9420 has its own
interop vectors; ChaCha20-Poly1305 has RFC 8439's. jig's vectors check what only jig
defines: which blocks a server accepts or refuses on a channel of that suite, with which
code, and (where the suite allows it) what a member reads.

### 3.2 Format

One JSON file per registered suite, `repos/jig-spec/vectors/suites/<id>.json`, CC-BY-4.0
with the spec:

```json
{
  "format": 1,
  "suite": "test-aead",
  "identities": { "alice": "<ed25519 seed, hex>", "bob": "…" },
  "suite_params": { "key": "<hex>" },
  "cases": [
    {
      "name": "content without the payload field is refused",
      "steps": [
        { "sender": "alice", "kind": "channel-create",
          "manifest": { …block manifest JSON… },
          "expect": "accept" },
        { "sender": "alice", "kind": "text-render",
          "manifest": { … },
          "expect": { "refuse": "MISSING_METADATA" } },
        { "reader": "bob", "block": 1,
          "expect": { "plaintext": "hello" } }
      ]
    }
  ]
}
```

- Steps run in order against an empty server state: one channel's history.
- A step either submits a manifest (`expect`: `accept`, or `refuse` with the spec's
  error code) or, for suites whose reading is deterministic from the vector, checks what a
  member reads (`reader`, `expect.plaintext`). Signature and freshness checks are out of
  scope: they are suite-independent and their own tests cover them, so manifests are
  unsigned and timestamps do not expire.
- The harness drives `mls_gate::plan`, applies its result as ingest does, and maps refusals
  to codes through the same `IngestError` mapping the server answers with, so the vectors
  exercise the same gate code and codes as live traffic.

### 3.3 Which vectors each suite ships

Every suite: create accepted; content without the payload refused (`MISSING_METADATA`);
plaintext `body` refused and content under another suite refused (both `SUITE_MISMATCH`); restricted create refused unless the
suite may serve restricted channels (`RESTRICTED_REQUIRES_MLS`); control blocks declaring the
suite refused.

- `test-aead`: the above plus read steps (decrypt with the published key), and a ciphertext
  moved to another channel failing to read (AAD).
- `mls`: the above plus genesis, add with welcome, external join, remove, stale-epoch commit
  (`STALE_EPOCH`), a commit doing more than its block says, an application message for
  another group. MLS reading is not deterministic from public data, so `mls` vectors have no
  read steps; the RFC 9420 vectors and the existing `h12` tests cover decryption.
- `none` gets a file too: it is a registered suite.

The vectors are generated by an `#[ignore]`d test and checked in. **Confirmed while
building:** openmls 0.9 checks leaf lifetimes against the clock, both in the genesis tree
(`PublicGroup::from_external`) and on every add. By default a leaf lasts about three
months, so checked-in `mls` vectors would expire. openmls never enforces its maximum
lifetime range, so the generator mints leaves that last until 2126. It uses a jig-mls
`conformance` feature (`Member::with_lifetime_until`) that only dev-dependencies enable,
and the CI check in §2.1 covers that feature too. The file's description records the
expiry.

### 3.4 CI check

A test in `jig-server` (where the refusal-to-code mapping lives; in the CI crate list, so `workspace` runs it) loads every file in
`vectors/suites/`, and fails if a registered suite has no file or a file names a suite that
is not registered. No new CI job.

## 4. Spec and JEP changes

- `encryption.md` registry: a row `test-aead` with status "Reserved for conformance
  testing", and the rule: identifiers starting `test-` MUST NOT be implemented by a
  production build and are refused as unregistered.
- JEP-0001: the vector format (§3.2), the test suite and its id, "a new suite ships a
  vector file" as a registration requirement (closes open question 8), and D13 recorded as
  deferred in open question 2.

## 4a. Report profile (added for lane R)

DJ decided in lane R (Q7) that every suite defines a report profile: what a member
discloses about one message so a tribunal can verify its authorship and content, opening no
other message. JEP-0001 (in the build PR) records it:

- `none`: nothing to disclose. The block's author signature covers the plaintext.
- `mls`: per-message key disclosure (R's framing, 8.3). The reporter discloses the message
  key and nonce and the sender-data key and nonce for that one message, plus the epoch's
  `GroupContext`. The verifier checks the block signature, decrypts, and checks the MLS
  content signature, which is made with the DID key.
- `test-aead`: nothing to disclose. The key is published, and the AAD plus the block
  signature bind the payload to its channel and author.

Report-profile vectors belong to R5. Whether openmls exposes per-message secrets is R5's to
confirm.

## 5. PRs

1. This design (docs only).
2. Build, one PR: registry properties + gate generalisation + client fail-closed display
   (the audit fixes), the `test-aead` suite behind the feature, the vector files and
   harness, the `cargo tree` CI check, the spec and JEP-0001 text. Touches `Cargo.lock`.
   If it grows past about 1,500 lines I split the audit fixes out first.

## 6. Decisions

DJ settled all four on 2026-10-18, each as recommended below.

1. **May the test suite serve restricted channels?** **No**: its key is public,
   so the operator can read it, which is exactly what D25 forbids. The gate keeps
   "restricted requires `mls`". A future production suite's JEP decides whether it may.
2. **Test suite id.** `test-aead`, with the whole `test-` prefix reserved.
3. **Where the vectors live.** `repos/jig-spec/vectors/suites/` (normative,
   CC-BY-4.0, next to the JEPs), not a crate's `tests/` directory.
4. **Does the CLI speak `test-aead`?** **No**: the gate, the server and the
   vectors prove pluggability; teaching the CLI a suite nobody may deploy adds code no
   user path runs. The CLI only learns to refuse suites it does not speak.
