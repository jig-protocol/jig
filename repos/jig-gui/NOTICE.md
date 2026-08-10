# jig-gui (Riverdance) — licence deliberately not yet granted

**The `MIT OR Apache-2.0` dual licence that covers the rest of this repository
does NOT extend to anything under `repos/jig-gui/`.**

This is a decision, not an oversight. The protocol crates are permissively
licensed because a protocol nobody can embed is not a protocol — anyone should
be able to build on `jig-core`, `jig-client`, `jig-server` and the rest for any
purpose. The reasoning does not transfer to a client application, where a
copyleft or source-available licence (AGPL, BSL) may be the right call. That
call has not been made yet.

Until it is, no licence is granted for this subtree. Default copyright applies:
all rights reserved by the Jig Protocol Contributors.

## What this means in practice

| | |
| --- | --- |
| Reading the source | Fine — it is in a public repository. |
| Building and running it locally | Fine. |
| Redistributing, forking, or shipping it in a product | **Not permitted** until a licence is chosen. |
| Depending on it from another crate | Do not. All five crates are `publish = false`, so they cannot reach crates.io. |

Nothing in the protocol crates depends on this subtree, so its licence status
cannot contaminate them. The dependency arrow points one way: Riverdance may use
the protocol crates; the protocol crates never use Riverdance.

Contributions here are welcome but will be relicensed under whatever this
subtree eventually adopts — say so in your PR if that is a problem for you.

See [`docs/RELEASE_READINESS.md`](../../docs/RELEASE_READINESS.md) for the wider
licensing position.
