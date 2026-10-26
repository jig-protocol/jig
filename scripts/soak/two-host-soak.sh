#!/usr/bin/env bash
# Two-host soak: two federated jig-servers, a client on each, posting to one
# open channel both ways for hours, while the harness checks that every
# message crosses, how long it takes, and how the servers hold up.
#
# Usage: scripts/soak/two-host-soak.sh [ENV_FILE]
#
# Every setting is an environment variable, or a line in ENV_FILE (sourced).
# Hosts are parameters only: keep ENV_FILE outside the repository. The summary
# names the servers A and B, never their URLs, so it can be shared as is.
#
#   SOAK_MODE          local (default): boot two servers on this machine,
#                      peered over loopback. remote: use two servers that are
#                      already running and list each other as peers.
#   SOAK_PATH          legacy (default): the channel crosses by the peers'
#                      open-channel relay, and both sides post. contract: A
#                      shares the channel with B (JEP-0005, `jig channel
#                      share`), B follows A's records, and only A posts:
#                      B does not relay writes back yet.
#   SOAK_CONTRACT_SETUP isolated (default): create and share the channel
#                      while B is down, so only the contract can bring it to
#                      B. steady: with both up, where the legacy relay gets
#                      there first (see README). Remote isolated mode needs
#                      SOAK_B_STOP_CMD and SOAK_B_START_CMD.
#   SOAK_A_URL         remote: server A's base URL, https://HOST:PORT
#   SOAK_B_URL         remote: server B's base URL
#   SOAK_BIN           directory holding jig (and jig-server for local mode);
#                      default repos/target/release
#   SOAK_DURATION      seconds of sending (default 3600)
#   SOAK_INTERVAL      seconds between one side's messages (default 10)
#   SOAK_POLL          seconds between reads on each side (default 5)
#   SOAK_DEADLINE      a message not seen across within this many seconds is
#                      lost (default 300)
#   SOAK_SETTLE        seconds to keep reading after the last send (default
#                      SOAK_DEADLINE)
#   SOAK_HEALTH_EVERY  seconds between health samples (default 60)
#   SOAK_RESTART_EVERY seconds between server restarts (default 0: none)
#   SOAK_RESTART_SIDE  b (default), a, or alternate: which server restarts
#   SOAK_A_RESTART_CMD remote: command that restarts server A (e.g. over ssh)
#   SOAK_B_RESTART_CMD remote: command that restarts server B
#   SOAK_B_STOP_CMD    remote, contract isolated setup: stops server B
#   SOAK_B_START_CMD   remote, contract isolated setup: starts it again
#   SOAK_A_PROBE_CMD   remote, optional: command printing "RSS_KB FDS" for
#                      server A's process; local mode reads /proc itself
#   SOAK_B_PROBE_CMD   remote, optional: the same for B
#   SOAK_OUT           output directory (default soak-out/RUN_ID)
#   SOAK_PORT_A        local: A's port (default 47501)
#   SOAK_PORT_B        local: B's port (default 47502)
#
# Output in SOAK_OUT: sends.tsv, seen.tsv, gaps.tsv, health.tsv and
# summary.md. Exits 1 if a message was lost, or a server stopped answering
# at the end.

set -euo pipefail

if [ $# -gt 0 ]; then
  # shellcheck disable=SC1090
  . "$1"
fi

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
MODE="${SOAK_MODE:-local}"
BIN="${SOAK_BIN:-$ROOT/repos/target/release}"
DURATION="${SOAK_DURATION:-3600}"
INTERVAL="${SOAK_INTERVAL:-10}"
POLL="${SOAK_POLL:-5}"
DEADLINE="${SOAK_DEADLINE:-300}"
SETTLE="${SOAK_SETTLE:-$DEADLINE}"
HEALTH_EVERY="${SOAK_HEALTH_EVERY:-60}"
RESTART_EVERY="${SOAK_RESTART_EVERY:-0}"
RESTART_SIDE="${SOAK_RESTART_SIDE:-b}"
FED_PATH="${SOAK_PATH:-legacy}"
SETUP="${SOAK_CONTRACT_SETUP:-isolated}"
case "$FED_PATH" in legacy | contract) ;; *) echo "SOAK_PATH is legacy or contract" >&2; exit 1 ;; esac
case "$SETUP" in isolated | steady) ;; *) echo "SOAK_CONTRACT_SETUP is isolated or steady" >&2; exit 1 ;; esac
case "$RESTART_SIDE" in a | b | alternate) ;; *) echo "SOAK_RESTART_SIDE is a, b or alternate" >&2; exit 1 ;; esac
# Whether B comes up only after the channel is shared.
LATE_B=0
if [ "$FED_PATH" = contract ] && [ "$SETUP" = isolated ]; then LATE_B=1; fi
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-$(od -An -N3 -tx1 /dev/urandom | tr -d ' \n')"
OUT="${SOAK_OUT:-$PWD/soak-out/$RUN_ID}"
CHANNEL="#soak-${RUN_ID,,}"

log() { printf '[soak %s] %s\n' "$(date -u +%H:%M:%S)" "$*" >&2; }
fail() { log "FAIL: $*"; exit 1; }
now_ms() { date +%s%3N; }
rand_secret() { od -An -N32 -tx1 /dev/urandom | tr -d ' \n'; }

[ -x "$BIN/jig" ] || fail "no jig in $BIN (set SOAK_BIN)"
command -v python3 >/dev/null || fail "python3 is needed for the summary"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
WORK="$OUT/work"
mkdir -p "$WORK"

PIDS=()
# shellcheck disable=SC2329 # run by the EXIT trap
cleanup() {
  local pid
  for pid in "${PIDS[@]}"; do kill "$pid" 2>/dev/null || true; done
  if [ "$MODE" = local ]; then local_stop a; local_stop b; fi
}
trap cleanup EXIT

# --- servers ---------------------------------------------------------------

# Local mode: each server's state, key and log live under $WORK/server-X. The
# key secrets live only in this shell, unexported: each server gets its own
# as SOAK_KEY and nothing else sees either.
# shellcheck disable=SC2034 # read through ${!key}
SOAK_KEY_A="$(rand_secret)"
# shellcheck disable=SC2034 # read through ${!key}
SOAK_KEY_B="$(rand_secret)"

local_dir() { echo "$WORK/server-$1"; }
local_port() { if [ "$1" = a ]; then echo "${SOAK_PORT_A:-47501}"; else echo "${SOAK_PORT_B:-47502}"; fi; }
key_var() { if [ "$1" = a ]; then echo SOAK_KEY_A; else echo SOAK_KEY_B; fi; }

local_server() {
  local dir key
  dir="$(local_dir "$1")"; key="$(key_var "$1")"
  env "SOAK_KEY=${!key}" "$BIN/jig-server" --config "$dir/config.toml" "${@:2}"
}

local_init() {
  local side="$1" dir port
  dir="$(local_dir "$side")"; port="$(local_port "$side")"
  mkdir -p "$dir"
  "$BIN/jig-server" --init-config "$dir/config.toml" >/dev/null
  sed -i \
    -e "s#^database_path = .*#database_path = \"$dir/jig.db\"#" \
    -e "s#^port = .*#port = $port#" \
    -e "s#^listen = .*#listen = \"127.0.0.1:$port\"#" \
    -e "s#^server_did_keyfile = .*#server_did_keyfile = \"$dir/server.key\"#" \
    -e 's#^storage = "sealed"#storage = "sealed"\nunlock = "env:SOAK_KEY"#' \
    "$dir/config.toml"
  grep -q '^unlock = "env:SOAK_KEY"' "$dir/config.toml" || fail "the config template changed: no [keys] storage line"
  local_server "$side" keys generate --slot env:SOAK_KEY 2>/dev/null | head -1 > "$dir/did"
}

local_start() {
  local dir; dir="$(local_dir "$1")"
  # Something else on the port would answer the health check below.
  if curl -sk -o /dev/null --max-time 2 "$(url_of "$1")/healthz"; then
    fail "port $(local_port "$1") is already taken (set SOAK_PORT_${1^^})"
  fi
  local key; key="$(key_var "$1")"
  # exec, so the recorded pid is jig-server's own.
  (cd "$dir" && exec env "SOAK_KEY=${!key}" "$BIN/jig-server" --config "$dir/config.toml" \
    >>"$dir/server.log" 2>&1) &
  echo $! > "$dir/pid"
  local url; url="$(url_of "$1")"
  for _ in $(seq 1 100); do
    curl -fsk -o /dev/null --max-time 2 "$url/healthz" && return 0
    sleep 0.1
  done
  tail -n 20 "$dir/server.log" >&2
  fail "local server $1 did not start"
}

local_stop() {
  local pidfile pid
  pidfile="$(local_dir "$1")/pid"
  [ -f "$pidfile" ] || return 0
  pid="$(cat "$pidfile")"
  kill "$pid" 2>/dev/null || true
  for _ in $(seq 1 100); do kill -0 "$pid" 2>/dev/null || break; sleep 0.1; done
  rm -f "$pidfile"
}

url_of() {
  if [ "$MODE" = local ]; then
    echo "https://127.0.0.1:$(local_port "$1")"
  elif [ "$1" = a ]; then
    echo "${SOAK_A_URL:?set SOAK_A_URL}"
  else
    echo "${SOAK_B_URL:?set SOAK_B_URL}"
  fi
}

restart_server() {
  local side="$1" cmd
  if [ "$MODE" = local ]; then
    local_stop "$side"; local_start "$side"
  else
    if [ "$side" = a ]; then cmd="${SOAK_A_RESTART_CMD:-}"; else cmd="${SOAK_B_RESTART_CMD:-}"; fi
    [ -n "$cmd" ] || fail "SOAK_RESTART_EVERY is set but SOAK_${side^^}_RESTART_CMD is not"
    bash -c "$cmd" >/dev/null 2>&1 || log "restart command for $side failed"
  fi
}

# Contract isolated setup, remote: take B down until the channel is shared.
remote_b() {
  local what="$1" cmd
  if [ "$what" = stop ]; then cmd="${SOAK_B_STOP_CMD:-}"; else cmd="${SOAK_B_START_CMD:-}"; fi
  [ -n "$cmd" ] || fail "the isolated contract setup needs SOAK_B_STOP_CMD and SOAK_B_START_CMD in remote mode (or SOAK_CONTRACT_SETUP=steady)"
  bash -c "$cmd" >/dev/null 2>&1 || fail "SOAK_B_${what^^}_CMD failed"
  local _
  for _ in $(seq 1 120); do
    if [ "$what" = stop ]; then
      curl -fsk -o /dev/null --max-time 2 "$(url_of b)/healthz" || return 0
    else
      curl -fsk -o /dev/null --max-time 2 "$(url_of b)/healthz" && return 0
    fi
    sleep 1
  done
  fail "server B did not $what"
}

# "RSS_KB FDS" for a server's process, or "- -".
probe() {
  local side="$1" pid cmd
  if [ "$MODE" = local ]; then
    pid="$(cat "$(local_dir "$side")/pid" 2>/dev/null)" || { echo "- -"; return; }
    if [ -r "/proc/$pid/status" ]; then
      echo "$(awk '/^VmRSS:/ {print $2}' "/proc/$pid/status") $(find "/proc/$pid/fd" -mindepth 1 -maxdepth 1 2>/dev/null | wc -l)"
    else
      echo "- -"
    fi
    return
  fi
  if [ "$side" = a ]; then cmd="${SOAK_A_PROBE_CMD:-}"; else cmd="${SOAK_B_PROBE_CMD:-}"; fi
  if [ -n "$cmd" ]; then bash -c "$cmd" 2>/dev/null | head -1 || echo "- -"; else echo "- -"; fi
}

server_did() { curl -fsSk --max-time 5 "$1/.well-known/jig" | python3 -c 'import json,sys; print(json.load(sys.stdin)["server_did"])'; }

if [ "$MODE" = local ]; then
  [ -x "$BIN/jig-server" ] || fail "no jig-server in $BIN"
  log "booting two local servers"
  local_init a; local_init b
  printf '\n[[federation.peers]]\nurl = "wss://127.0.0.1:%s"\nexpected_did = "%s"\n' \
    "$(local_port b)" "$(cat "$(local_dir b)/did")" >> "$(local_dir a)/config.toml"
  printf '\n[[federation.peers]]\nurl = "wss://127.0.0.1:%s"\nexpected_did = "%s"\n' \
    "$(local_port a)" "$(cat "$(local_dir a)/did")" >> "$(local_dir b)/config.toml"
  # B takes A's offers without an operator.
  [ "$FED_PATH" = contract ] && echo 'offers = "accept"' >> "$(local_dir b)/config.toml"
  local_start a
  [ "$LATE_B" = 1 ] || local_start b
elif [ "$MODE" != remote ]; then
  fail "SOAK_MODE is local or remote, not $MODE"
fi
URL_A="$(url_of a)"; URL_B="$(url_of b)"
DID_A="$(server_did "$URL_A")" || fail "server A does not answer /.well-known/jig"
if [ "$MODE" = local ] && [ "$LATE_B" = 1 ]; then
  DID_B="$(cat "$(local_dir b)/did")"
else
  DID_B="$(server_did "$URL_B")" || fail "server B does not answer /.well-known/jig"
fi

# --- clients -------------------------------------------------------------------

# One identity per side, alice on A and bob on B, made fresh for this run.
# Their key secrets are never written down: jig reads them from the
# environment (JIG_KEY_UNLOCK=env:...), so they are exported.
SOAK_U_A="$(rand_secret)"; SOAK_U_B="$(rand_secret)"
export SOAK_U_A SOAK_U_B
as() {
  local side="$1"; shift
  local home="$WORK/client-$side" var="SOAK_U_${side^^}"
  env HOME="$home" JIG_HOME="$home/.jig" JIG_KEY_UNLOCK="env:$var" RUST_BACKTRACE=0 \
    "$BIN/jig" "$@"
}

client_init() {
  local side="$1" name
  mkdir -p "$WORK/client-$side"
  name="$([ "$side" = a ] && echo alice || echo bob)"
  as "$side" init "$name" >"$WORK/client-$side.init" 2>&1 || { cat "$WORK/client-$side.init" >&2; fail "jig init on $side"; }
  as "$side" server set "$(url_of "$side")" >/dev/null 2>&1 || fail "jig server set on $side"
}

# Wait until FROM's posts are read on TO's server, through REF (the slug, or
# on a follower the channel's id): this checks the peering, and keeps the
# time before the links are up out of the numbers. Posts made while a link
# is down never cross later on the legacy relay, so the warm-up posts again
# until one is seen.
warm_up() {
  local from="$1" to="$2" ref="$3" wait="$4" n=0 deadline
  deadline=$(( $(date +%s) + wait ))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    n=$((n + 1))
    as "$from" send --channel "$CHANNEL" "soak $RUN_ID warmup $from $n" >/dev/null 2>&1 || true
    sleep 5
    if as "$to" --json read "$ref" --limit 200 2>/dev/null | grep -qF "soak $RUN_ID warmup $from "; then
      return 0
    fi
  done
  fail "nothing posted on ${from^^} reached ${to^^} within ${wait} s: do the servers list each other as federation peers?"
}

client_init a
as a channel create "$CHANNEL" >/dev/null 2>&1 || fail "could not create $CHANNEL on A"
READ_A="$CHANNEL"; READ_B="$CHANNEL"
if [ "$FED_PATH" = contract ]; then
  as a channel share --help >/dev/null 2>&1 || fail "$BIN/jig has no \`channel share\`: build one that does"
  if [ "$LATE_B" = 1 ] && [ "$MODE" = remote ]; then remote_b stop; fi
  as a channel share "$CHANNEL" "$DID_B" --grant write > "$WORK/share.out" 2>&1 || { cat "$WORK/share.out" >&2; fail "jig channel share"; }
  READ_B="$(sed -n 's/.*read it by its id: jig read \(.*\)$/\1/p' "$WORK/share.out")"
  [ -n "$READ_B" ] || { cat "$WORK/share.out" >&2; fail "no channel id in jig channel share's output"; }
  if [ "$LATE_B" = 1 ]; then
    if [ "$MODE" = local ]; then local_start b; else remote_b start; fi
  fi
  client_init b
  # B accepts within a resend of the offer (30 s), then pulls every 10 s.
  warm_up a b "$READ_B" 240
  # A followed channel has no slug on B. If B serves A's posts by slug, B
  # took the channel as its own from the legacy relay, and what B shows is
  # that copy, not the contract's.
  if as b --json read "$CHANNEL" --limit 200 2>/dev/null | grep -qF "soak $RUN_ID warmup a "; then
    printf '# Two-host soak %s\n\n**FAIL**: server B holds %s as a channel it sequences itself (it came by the legacy relay before the share), so the contract carries nothing to it. See scripts/soak/README.md.\n' \
      "$RUN_ID" "$CHANNEL" | tee "$OUT/summary.md"
    exit 1
  fi
  log "run $RUN_ID: $CHANNEL shared with B (id $READ_B), ${DURATION}s of posts on A every ${INTERVAL}s"
else
  client_init b
  warm_up a b "$READ_B" 120
  warm_up b a "$READ_A" 120
  log "run $RUN_ID: channel $CHANNEL, ${DURATION}s of sends every ${INTERVAL}s each way"
fi

# --- the run ---------------------------------------------------------------------

printf 'side\tseq\tsent_ms\tok\n' > "$OUT/sends.tsv"
printf 'reader\tsender\tseq\tseen_ms\n' > "$OUT/seen.tsv"
printf 'reader\tat_ms\tafter_seq\tnext_seen\n' > "$OUT/gaps.tsv"
printf 'at_ms\tside\thealthz\tlatency_s\trss_kb\tfds\tfederation_ingested\n' > "$OUT/health.tsv"
printf 'at_ms\tside\n' > "$OUT/restarts.tsv"

END_SEND=$(( $(date +%s) + DURATION ))

sender() {
  local side="$1" seq=0 ok
  while [ "$(date +%s)" -lt "$END_SEND" ]; do
    seq=$((seq + 1))
    local at; at="$(now_ms)"
    if as "$side" send --channel "$CHANNEL" "soak $RUN_ID $side $seq" >/dev/null 2>&1; then ok=1; else ok=0; fi
    printf '%s\t%s\t%s\t%s\n' "$side" "$seq" "$at" "$ok" >> "$OUT/sends.tsv"
    sleep "$INTERVAL"
  done
}

# Reads the channel on READER's server and records the first sighting of
# each of the other side's messages. A read returns at most 200 messages:
# when the oldest of them is past the last one seen, what fell between could
# not be checked, and that is recorded as a gap rather than a loss.
reader() {
  local side="$1" ref="$2" other state
  other="$([ "$side" = a ] && echo b || echo a)"
  state="$WORK/reader-$side.state"
  : > "$state"
  while :; do
    local at
    if as "$side" --json read "$ref" --limit 200 > "$WORK/read-$side.json" 2>/dev/null; then
      # Seen by the time the read returned: never earlier than the send.
      at="$(now_ms)"
      python3 - "$WORK/read-$side.json" "$state" "$OUT/seen.tsv" "$OUT/gaps.tsv" \
        "$RUN_ID" "$side" "$other" "$at" <<'PY'
import json, sys
path, state_path, seen_path, gaps_path, run, reader, other, at = sys.argv[1:]
prefix = f"soak {run} {other} "
LIMIT = 200
seqs, total = [], 0
for line in open(path):
    line = line.strip()
    if not line:
        continue
    total += 1
    try:
        body = json.loads(line).get("body", "")
    except ValueError:
        continue
    # The sequence number, then whatever the client appends (a follower,
    # which keeps no receipt of its own, marks the line `[unverified]`).
    if isinstance(body, str) and body.startswith(prefix):
        try:
            seqs.append(int(body[len(prefix):].split()[0]))
        except (ValueError, IndexError):
            pass
seen = set()
try:
    with open(state_path) as f:
        seen = {int(x) for x in f.read().split()}
except FileNotFoundError:
    pass
last = max(seen, default=0)
new = sorted(set(seqs) - seen)
# A full read whose oldest message is past the last one seen: what fell
# between was never in view.
if total >= LIMIT and seqs and min(seqs) > last + 1:
    with open(gaps_path, "a") as g:
        g.write(f"{reader}\t{at}\t{last}\t{min(seqs)}\n")
with open(seen_path, "a") as f:
    for s in new:
        f.write(f"{reader}\t{other}\t{s}\t{at}\n")
seen.update(new)
with open(state_path, "w") as f:
    f.write(" ".join(map(str, sorted(seen))))
PY
    fi
    sleep "$POLL"
  done
}

health() {
  while :; do
    local side url at code metrics
    for side in a b; do
      url="$(url_of "$side")"; at="$(now_ms)"
      code="$(curl -sk -o /dev/null --max-time 10 -w '%{http_code} %{time_total}' "$url/healthz" || echo "000 -")"
      metrics="$(curl -fsSk --max-time 10 "$url/metrics" 2>/dev/null \
        | awk '/^jig_blocks_ingested_total\{source="federation"\}/ {print $2}' || true)"
      printf '%s\t%s\t%s\t%s\t%s\n' "$at" "$side" "${code// /$'\t'}" "$(probe "$side" | tr ' ' '\t')" "${metrics:--}" >> "$OUT/health.tsv"
    done
    sleep "$HEALTH_EVERY"
  done
}

restarter() {
  local n=0 side
  while :; do
    sleep "$RESTART_EVERY"
    [ "$(date +%s)" -lt "$END_SEND" ] || return 0
    n=$((n + 1))
    side="$RESTART_SIDE"
    if [ "$side" = alternate ]; then side="$([ $((n % 2)) = 1 ] && echo b || echo a)"; fi
    log "restarting server ${side^^}"
    printf '%s\t%s\n' "$(now_ms)" "$side" >> "$OUT/restarts.tsv"
    restart_server "$side"
  done
}

health & PIDS+=($!)
reader b "$READ_B" & PIDS+=($!)
if [ "$RESTART_EVERY" -gt 0 ]; then restarter & PIDS+=($!); fi
sender a & SENDERS=($!)
if [ "$FED_PATH" = legacy ]; then
  reader a "$READ_A" & PIDS+=($!)
  sender b & SENDERS+=($!)
fi
PIDS+=("${SENDERS[@]}")
wait "${SENDERS[@]}"
log "sending done; reading for ${SETTLE}s more"
sleep "$SETTLE"

# A last health sample, then stop everything.
FINAL_OK=1
for side in a b; do
  curl -fsSk -o /dev/null --max-time 10 "$(url_of "$side")/healthz" || { FINAL_OK=0; log "server ${side^^} does not answer at the end"; }
done
[ "$(server_did "$URL_A")" = "$DID_A" ] || { FINAL_OK=0; log "server A's DID changed"; }
[ "$(server_did "$URL_B")" = "$DID_B" ] || { FINAL_OK=0; log "server B's DID changed"; }
for pid in "${PIDS[@]}"; do kill "$pid" 2>/dev/null || true; done
# Only the loops: in local mode the servers are this shell's children too.
wait "${PIDS[@]}" 2>/dev/null || true
PIDS=()

STATUS=0
python3 "$ROOT/scripts/soak/summarize.py" "$OUT" "$RUN_ID" "$MODE" "$DURATION" "$INTERVAL" \
  "$POLL" "$DEADLINE" "$RESTART_EVERY" "$FINAL_OK" "$FED_PATH" "$RESTART_SIDE" > "$OUT/summary.md" || STATUS=$?
cat "$OUT/summary.md"
exit "$STATUS"
