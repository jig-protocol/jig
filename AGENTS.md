# Notes for coding agents

[CONTRIBUTING.md](CONTRIBUTING.md) is the source for how to build, test and open a pull request. This file adds only the rules for agents working in parallel.

## Worktrees and build output

Each git worktree builds into its own `repos/target/`, and a full test build of this workspace takes tens of GB. A few leftover worktrees will fill a laptop disk.

- **Delete your build output before you finish.** When the task you ran in a worktree is done (pushed, or handed back), run `scripts/clean-build-artifacts.sh --here --yes`. Do this even if the worktree itself stays around for review. Skip it only if whoever started you asked you to keep the build.
- **Pass the rule on.** If you start subagents that build in worktrees, tell them to follow this rule. When you have collected their results, run `scripts/clean-build-artifacts.sh` to see what is left, then run it again with `--yes`.
- **Remove worktrees you created** once their branch is merged or abandoned: `git worktree remove <path>`.
- **Build with `CARGO_INCREMENTAL=0`** for one-off build and test runs. Incremental caches make `target/` bigger and only pay off over repeated edit–build cycles.
- **Do not share one `CARGO_TARGET_DIR` across concurrent worktrees.** Cargo locks its build directory, so parallel agents would queue behind each other.
