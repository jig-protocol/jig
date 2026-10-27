# Two-host soak

`two-host-soak.sh` runs two federated jig-servers under steady traffic and
checks every message.

- **Traffic:** one client on each server (alice on A, bob on B). Each posts
  to one open channel every `SOAK_INTERVAL` seconds.
- **What it checks:**
  - every message reaches the other server within `SOAK_DEADLINE`;
  - how long that takes;
  - whether `/healthz`, memory and file descriptors hold steady.
- **Faults:** it can restart server B on a schedule.

```sh
# Two servers on this machine, peered over loopback, for 10 minutes:
SOAK_DURATION=600 scripts/soak/two-host-soak.sh

# The same with server B restarted every 5 minutes:
SOAK_DURATION=600 SOAK_RESTART_EVERY=300 scripts/soak/two-host-soak.sh

# Two servers you run elsewhere, settings in a file outside this repository:
scripts/soak/two-host-soak.sh ~/soak.env
```

Every setting is listed at the top of the script.

## Two paths

`SOAK_PATH` picks how the channel reaches B:

- **`legacy`** (the default): the relay every pair of peers runs for open
  channels. Both sides post.
- **`contract`**: A shares the channel with B (JEP-0005, `jig channel
  share`), and B follows A's ordered records, pulling what it missed after
  any outage. Only A posts, because B does not relay writes back yet, and B
  reads the channel by its id. B's peer entry for A must accept offers:
  local mode sets `offers = "accept"`, and in remote mode you set it.

```sh
# The contract path, with A and B restarted in turn every 5 minutes:
SOAK_PATH=contract SOAK_RESTART_EVERY=300 SOAK_RESTART_SIDE=alternate \
  SOAK_DURATION=3600 scripts/soak/two-host-soak.sh
```

Between peers that are both up, the legacy relay delivers a new open channel
to B within seconds, and B takes it as a channel it orders itself. A share
made after that is accepted but carries nothing. So the contract path's
default setup, `SOAK_CONTRACT_SETUP=isolated`, creates and shares the channel
while B is down: the legacy relay is live-only, so it never brings that
channel to B, and everything B gets comes by the contract. In remote mode
this needs `SOAK_B_STOP_CMD` and `SOAK_B_START_CMD`.
`SOAK_CONTRACT_SETUP=steady` shares with both up instead, and the run fails
at setup, naming that collision, until it is fixed.

## Concurrent ingest

`SOAK_INGEST=concurrent` (legacy path only) runs `SOAK_WRITERS` writers on
each side (16 by default), and every writer on both sides posts on the same
tick. Each server then orders its own client's posts and the other server's
relayed ones into the channel at the same moment. Every read holds the page
to the chain of signed ingest records the reader pinned for the channel; a
server that signs two records with one sequence number, rewinds its clock or
rewrites a record breaks that chain, and the client keeps the evidence.

```sh
SOAK_INGEST=concurrent SOAK_INTERVAL=2 SOAK_DURATION=600 scripts/soak/two-host-soak.sh
```

## Remote mode

Remote mode runs against two servers you have deployed. **Each must already
list the other** under `[[federation.peers]]`. The harness never logs in to a
host. It talks to the servers' public endpoints as a client would, and runs
only the commands you give it:

- `SOAK_A_RESTART_CMD`, `SOAK_B_RESTART_CMD`: how to restart each server,
  for `SOAK_RESTART_EVERY`.
- `SOAK_A_PROBE_CMD`, `SOAK_B_PROBE_CMD`: optional. Each prints `RSS_KB FDS`
  for the server's process.

An env file looks like this. Keep yours outside the repository:

```sh
SOAK_MODE=remote
SOAK_A_URL=https://a.example.invalid:7117
SOAK_B_URL=https://b.example.invalid:7117
SOAK_DURATION=86400
SOAK_RESTART_EVERY=21600
SOAK_B_RESTART_CMD='ssh soak-b sudo systemctl restart jig-server'
SOAK_A_PROBE_CMD='ssh soak-a "pid=\$(pgrep -xo jig-server); echo \$(ps -o rss= -p \$pid) \$(sudo ls /proc/\$pid/fd | wc -l)"'
```

The clients are fresh identities made for each run. Their key secrets, like
the local servers' secrets, live only in the harness's environment and are
never written to disk.

## Output

Everything lands in `SOAK_OUT`, by default `soak-out/RUN_ID`:

| File | What it holds |
|---|---|
| `sends.tsv` | Every post: side, sequence number, time, whether it was accepted. |
| `seen.tsv` | The first time each post was seen on the other server. |
| `gaps.tsv` | Stretches no read could cover: a read returns at most 200 messages. Messages in a gap count as unverifiable, not lost. |
| `health.tsv` | `/healthz` status and time, RSS, fds, and `jig_blocks_ingested_total{source="federation"}` per server. The counter is per process: it starts again from 0 after a restart. |
| `evidence.tsv` | Every evidence bundle a client kept against its server, with its code (`chain-forked`, `chain-clock-backwards`, ...). |
| `chain.tsv` | How far each client verified the channel's signed chain. |
| `read-errors.tsv` | Reads refused because the server contradicted itself. |
| `summary.md` | The verdict, per direction and per hour. |

The summary names the servers A and B, never their URLs, so it can be shared
as is. The run exits 1 when:

- any message is lost, including one first seen after `SOAK_DEADLINE`;
- any send fails in a run with no restarts injected (with restarts, a send
  can fail while a server is down);
- nothing was delivered at all;
- a client kept evidence that its server contradicted itself, such as any
  `chain-*` break in the channel's signed history;
- a server stops answering or changes its DID by the end.

Latency is the first sighting minus the send time, so its resolution is
`SOAK_POLL`.

## What it has found

- **A peer restart loses messages for good, both ways.** Federation is a
  live subscription with no catch-up on resubscribe; `Frame::CatchUp` is
  still a stub. When B restarts:
  - posts on B while A's subscription is down are never relayed to A (A
    reconnects after a constant 5 s);
  - posts on A while B is down never reach B either.

  With `SOAK_RESTART_EVERY` set, a run on main loses one or two messages per
  restart and FAILs.
- **The contract path catches up.** With A and B restarted in turn every
  40 s, the contract path (isolated setup) delivered every post: 35 of 35,
  p95 3 s, at most 8 s just after a restart. B pulls A's records from its own
  head after each reconnect.
- **Between peers that are both up, the legacy relay takes the channel
  first.** B orders the channel itself, and acts on owner-only blocks
  relayed to it: a `channel-share` relayed from A makes B log its own
  `contract-refuse`. A share then delivers nothing. `SOAK_CONTRACT_SETUP=steady`
  shows it.
- **Concurrent ingest signed a clock that ran backwards (fixed by #347).**
  With 16 writers a side posting on the same tick, a build without #347
  signed record 605 with an older clock than record 604 within two minutes.
  Alice's client kept the proof (`chain-clock-backwards`) and refused her
  own server from then on, so every later send from A failed. With 4 writers
  a side the race did not show in two minutes: use 16 or more. On main
  with #347, the same run for three minutes delivered 1424 of 1424 each way,
  and both clients verified the chain to record 2850.
- **The warm-up exists for the same reason.** Before sending, the harness
  waits until a post crosses each way, re-posting until one does. Posts made
  before both links are up would otherwise be lost the same way.
