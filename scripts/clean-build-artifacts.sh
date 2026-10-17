#!/usr/bin/env bash
# clean-build-artifacts.sh — delete Cargo build output in this repository's
# git worktrees.
#
# Usage: scripts/clean-build-artifacts.sh [--here | --all] [--yes] [--force]
#
#   (default)  every worktree of this repository except the one you are in
#   --here     only the worktree you are in (what an agent runs before it
#              finishes a task)
#   --all      every worktree, including the one you are in
#   --yes      delete; without it the script only lists what it would delete
#   --force    delete even when it cannot tell whether a build is running
#
# Every worktree builds into its own repos/target, and a full test build of
# this workspace runs to tens of GB, so finished worktrees fill a disk fast.
# The script finds Cargo target directories (a `target` holding
# CACHEDIR.TAG) up to repos/<crate>/<sub>/target in each worktree, skips any
# whose build lock is held by a running cargo, and with --yes deletes the
# rest and prunes worktree entries whose directories are already gone.
# Sources, branches and the worktrees themselves are left alone.
#
# Portable to macOS's bash 3.2: no arrays of arrays, mapfile or ${x,,}.
set -euo pipefail

scope=others
yes=0
force=0
for arg in "$@"; do
	case "$arg" in
	--here) scope=here ;;
	--all) scope=all ;;
	--yes) yes=1 ;;
	--force) force=1 ;;
	-h | --help)
		awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0"
		exit 0
		;;
	*)
		echo "unknown argument: $arg (see --help)" >&2
		exit 2
		;;
	esac
done

# Physical path, so /var and /private/var (macOS) compare equal.
real() { (cd "$1" 2>/dev/null && pwd -P); }

here="$(real "$(git rev-parse --show-toplevel)")"

# Worktree roots, one per line. `git worktree list` covers every worktree of
# the repository wherever it lives (.claude/worktrees, ~/.cursor/worktrees, …).
worktrees() {
	git worktree list --porcelain | sed -n 's/^worktree //p'
}

# Exit 0 when no process holds a cargo build lock under target dir $1, 1 when
# one does, 2 when there is no tool to tell. Cargo flock(2)s
# <profile>/.cargo-lock (and, since 1.9x, .cargo-build-lock and
# .cargo-artifact-lock) while it builds; taking the same locks without
# blocking proves nobody has them.
idle() {
	local locks
	locks="$(find "$1" -maxdepth 3 -type f \( -name .cargo-lock -o -name '.cargo-*-lock' \) 2>/dev/null)"
	[ -z "$locks" ] && return 0
	if command -v perl >/dev/null 2>&1; then
		printf '%s\n' "$locks" | perl -MFcntl=:flock -e '
			while (my $path = <STDIN>) {
				chomp $path;
				open(my $f, "<", $path) or next;
				flock($f, LOCK_EX | LOCK_NB) or exit 1;
			}'
	elif command -v lsof >/dev/null 2>&1; then
		while IFS= read -r lock; do
			lsof -t -- "$lock" >/dev/null 2>&1 && return 1
		done <<EOF
$locks
EOF
		return 0
	else
		return 2
	fi
}

human() { awk -v k="$1" 'BEGIN { if (k >= 1048576) printf "%.1f GiB", k / 1048576; else printf "%d MiB", k / 1024 }'; }

kib_total=0
deleted=0
skipped=0
while IFS= read -r wt; do
	[ -d "$wt" ] || continue
	wt="$(real "$wt")"
	case "$scope" in
	here) [ "$wt" = "$here" ] || continue ;;
	others) [ "$wt" = "$here" ] && continue ;;
	esac
	# Linked worktrees can sit inside the main one (.claude/worktrees/...);
	# the depth limit and the prunes keep each target attributed to its own.
	targets="$(find "$wt" -maxdepth 4 \
		\( -name .git -o -name .claude -o -name .cursor -o -name node_modules \) -prune \
		-o -type d -name target -prune -print 2>/dev/null)"
	[ -n "$targets" ] || continue
	while IFS= read -r t; do
		[ -f "$t/CACHEDIR.TAG" ] || continue
		kib="$(du -sk "$t" 2>/dev/null | cut -f1)"
		size="$(human "$kib")"
		state=0
		idle "$t" || state=$?
		if [ "$state" -eq 1 ]; then
			echo "busy     $size  $t  (a cargo build holds its lock)"
			skipped=$((skipped + 1))
			continue
		fi
		if [ "$state" -eq 2 ] && [ "$force" -eq 0 ]; then
			echo "unknown  $size  $t  (no perl or lsof to check for a running build; --force to delete)"
			skipped=$((skipped + 1))
			continue
		fi
		kib_total=$((kib_total + kib))
		if [ "$yes" -eq 1 ]; then
			rm -rf "$t"
			echo "deleted  $size  $t"
			deleted=$((deleted + 1))
		else
			echo "would    $size  $t"
		fi
	done <<EOF
$targets
EOF
done <<EOF
$(worktrees)
EOF

total="$(human "$kib_total")"
if [ "$yes" -eq 1 ]; then
	git worktree prune
	echo "freed $total from $deleted target dir(s); $skipped skipped"
else
	echo "$total reclaimable; $skipped skipped. Rerun with --yes to delete."
fi
