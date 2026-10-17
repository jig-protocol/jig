# Notes for coding agents

[CONTRIBUTING.md](CONTRIBUTING.md) is the source for how to build, test and open a pull request. This file adds only the rules for agents working in parallel.

## Worktrees and build output

Each git worktree builds into its own `repos/target/`, and a full test build of this workspace takes tens of GB. A few leftover worktrees will fill a laptop disk.

- **Delete your build output before you finish.** When the task you ran in a worktree is done (pushed, or handed back), run `scripts/clean-build-artifacts.sh --here --yes`. Do this even if the worktree itself stays around for review. Skip it only if whoever started you asked you to keep the build.
- **Pass the rule on.** If you start subagents that build in worktrees, tell them to follow this rule. When you have collected their results, run `scripts/clean-build-artifacts.sh` to see what is left, then run it again with `--yes`.
- **Remove worktrees you created** once their branch is merged or abandoned: `git worktree remove <path>`.
- **Build with `CARGO_INCREMENTAL=0`** for one-off build and test runs. Incremental caches make `target/` bigger and only pay off over repeated edit–build cycles.
- **Never point two worktrees at one `CARGO_TARGET_DIR`, even one after the other.** Cargo names a workspace crate's build output without the checkout's path, and decides whether it is fresh by the source files it was built from. So a build in worktree B can find worktree A's output, check A's unchanged files, and reuse it: tests then run A's code and pass, and nothing in the output says so (a test run that finishes in under a second without compiling is the tell). Run concurrently, the two also queue on Cargo's lock. Build each worktree into its own `repos/target/`, or switch branches in one checkout.
