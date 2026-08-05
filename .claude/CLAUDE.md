## Rules of Engagement (ROE)

### Core Principles

1. **Small, Tactical Files**: Each file should have a single, clear purpose
2. **Live Builds After Each Task**: Every change must maintain a buildable app
3. **TDD Approach**: Write tests first before code implementation - write implementation test flows before each module, and cargo nextest unit tests before each file / update
4. **Clean Linting**: All code must pass lint checks before moving on
5. **Incremental Progress**: Complete one task fully before starting the next
6. **Clean Up After Every Run**: Leave no processes, databases, or build artifacts behind

## Cleanup ROE (applies to direct, parallel-agent, and worktree runs)

Anything you start, you stop. Anything you write outside the repo, you delete. This
applies per-agent: if you spawned it, you own its teardown, and you do it before you
report, not after.

**Measured 2026-08-04, why this rule exists:** `repos/target/debug` in the main checkout
had reached **121 GB**, with another **32 GB** in a single worktree and 27 `target/`
directories across `gigue-ai` — against 38 GB free. Build-artifact accumulation, not
stray databases, is what degrades this machine.

### Before you report a task complete

1. **Kill every server you started.** Track the PID when you spawn it and kill it in
   teardown — do not rely on the shell exiting.
   ```
   pkill -f 'jig-server|jig-nameserver' || true
   ```
   Never assume a `timeout`-wrapped run died; confirm with `ps`.

2. **Delete every database and temp file you created.** Test servers write SQLite plus
   `-wal` and `-shm` sidecars — remove all three. Prefer writing them under the session
   scratchpad or a `TempDir` in the first place so cleanup is automatic.

3. **Never write to `~/.jig`.** That is real user state (`jig.db`, `server/`, keys).
   Isolate every test identity with `HOME=<scratch>` instead.

4. **Remove any git worktree you created**, including detached-HEAD scratch checkouts:
   ```
   git worktree remove <path> && git worktree prune
   ```
   Each one carries its own `target/` and costs tens of GB.

### Build artifacts — the actual problem

`target/debug` grows without bound across branches and rebuilds; nothing reclaims it.

- **Share one target directory** across checkouts and worktrees so N worktrees cost one
  build cache instead of N: set `CARGO_TARGET_DIR` (or `build.target-dir` in
  `.cargo/config.toml`). This is the single highest-leverage fix.
- **Sweep periodically.** `cargo clean` is a blunt full rebuild; prefer pruning by age:
  ```
  cargo install cargo-sweep && cargo sweep --time 14
  ```
- **Check before you build big.** If `df -h /` shows under ~50 GB free, sweep first —
  a failed link step at 100% disk wastes more time than the sweep.

Destructive commands (`rm -rf`, `cargo clean`, `git worktree remove` on a path you did
not create) still require DJ's approval per the root working agreement. Tee them up
rather than running them.
