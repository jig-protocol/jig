• Ran cargo check -p jig-runtime after the wasmparser refactor; jig-core now builds cleanly, but the check still fails inside
jig-runtime because its multihash = "0.17" dependency is compiled without the Blake3 variant. The call in jig-runtime/src/
receipt.rs:179 to Code::Blake3_256.digest(...) needs the blake3 codetable enabled (or the crate bumped to ≥0.18 where we
already use that feature set in jig-core). Recommend the runtime team switch the dependency to something like:

multihash = { version = "0.18", default-features = false, features = ["std", "blake3"] }

(or add "blake3" to the existing feature list) so the variant is available. Once that’s in place the cargo check should
pass; no further wasmparser changes are needed on the jig-core side.
