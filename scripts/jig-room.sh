#!/usr/bin/env bash
# jig-room.sh — keep a `jig chat` session up across server restarts.
#
# Usage: scripts/jig-room.sh '#hello'
#
# TRADEOFF, read before relying on this: this is a deliberate stand-in for
# real reconnect-with-backoff inside the client. It is a fixed 2s retry with
# no jitter, no cap, and no distinction between "the server bounced" and
# "your config is wrong" — a permanently unreachable server produces an
# infinite 2s loop. Ctrl-C to stop. Proper backoff (and resubscribe without
# tearing down the TUI) belongs in jig-client and is tracked separately.
#
# It works only because `jig chat` now exits NON-ZERO when the connection
# drops. A clean quit (Ctrl+Q / Esc) exits zero and ends the loop, which is
# what makes the `until` the right construct here: quitting means quitting,
# disconnecting means reconnecting.
set -euo pipefail

if [ "$#" -lt 1 ]; then
	echo "usage: $(basename "$0") <channel> [extra jig args...]" >&2
	exit 2
fi

until jig chat "$@"; do
	echo "reconnecting…" >&2
	sleep 2
done
