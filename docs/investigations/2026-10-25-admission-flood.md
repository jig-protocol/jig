# Bot-flood admission benchmark: nameserver registration

What an honest `jig ns register` meets when agents outnumber humans on one
suffix, under the recommended registration policy on main (`a740fa8`).

Reproduce: `cargo run --release -p jig-nameserver --example admission_flood --
--rate 2e7` (and `--rate 2e6`; `--ratios 3,5,6,8` for the threshold table).
Every table below is that command's output, seed 1. A seed and a rate give the
same numbers on any machine.

## Summary

- **The pool holds.** However large the flood, about 61 names an hour are
  admitted (60/h plus the burst of 10, spread over the run). The namespace's
  growth is bounded.
- **The pool doesn't keep honest users in.** Past the pool's capacity,
  honest users get roughly capacity ÷ demand: 57 % at 10:1, 6 % at 100:1,
  0–2 % at 1000:1. Proof-of-work does not separate them from agents. At the
  highest price, `max_effort = 2^24`, one 4-core machine pays about 0.8 s
  per identity.
- **Outbidding is cheap.** Agents that bid 4× the asked effort always win
  the queue over an honest client, which bids what is asked and at most 2×
  on its retry. Sixty such agents an hour (6:1 over 10 humans/h) cut honest
  success from 94 % to 58 %, for about 1 % of one machine's time.
- **With the pool off, the price never rises.** The controller reads only
  the queue, so with no queue it stays at the `2^20` floor: about 0.05 s
  per identity, some 70,000 identities an hour per machine. Every honest user
  gets in; so does every agent.
- **Slow devices lose on expiry.** At 2 M digests/s (a phone, or one old
  core) and a price of `2^24`, 3.8 % of honest attempts fail because the
  retry's doubled bid (`2^25`, about 17 s on average) outlives the 55 s the
  challenge leaves.

Conclusion for the public argument: on its own, proof-of-work at these
prices bounds how fast names are minted. It does not keep honest users
admitted against an agent flood of 10:1 or more. Separating the two needs
something an agent can't buy at this price: standing (JEP-0009), invites,
or a price set by that. This benchmark measures what is on main. It does not
say which lever to pull.

## Setup

- **What runs:** the nameserver's own `Market` (pool, queue, controller), from
  `jig_nameserver::v0_0_2_pow_policy`:
  - `PowPolicy::recommended()`: effort `2^20`..`2^24`, short names from 5.
  - `PoolPolicy::recommended()`: 60/h, burst 10, queue 20 for 10 s, doubling
    window 300 s.
  - The asked effort is `register_effort`; admission is `admit(bid)`.
- **Clock:** tokio's paused clock, stepped 1 ms at a time (see the finding
  below).
- **Work:** a solve at effort E takes Exp(E) digests: the lottery
  `jig_core::pow::meets` runs. The bid the queue orders by is verified work
  (`check_pow` checks the proof meets its own claimed effort), so an agent
  cannot bid without paying.
- **Honest client:** jig-cli's `with_pow`.
  - It bids what is asked.
  - It abandons a solve that would pass the challenge's 60 s life minus the
    5 s send margin, and retries once on a fresh challenge.
  - On `REGISTRATION_BUSY` it waits out `Retry-After` (up to 60 s), then
    retries once at `max(asked, 2 × last bid)`, capped at 60 s of its own
    work.
  - A second refusal ends the attempt. Real users might try again later;
    that isn't modelled.
- **Agents** solve 10× faster than the honest machine.
  - `client` agents run the honest client's logic.
  - `outbid` agents bid 4× the asked effort. They resend the same proof
    after each busy refusal while its challenge lives; a busy refusal leaves
    the challenge usable. Then they start over on a fresh challenge, for up
    to an hour.
- **Load:** honest users arrive Poisson at 10/h; agents at the stated ratio ×
  10/h. Each run is 6 h of arrivals, plus the tail until the last identity
  finishes.
- **Identities:** each is a fresh DID with an 8-letter alias and its own
  address, so no short-name multiplier and no penalty applies. Per-address
  rate limits are assumed evaded. One address is enough anyway: its 30
  registrations a minute exceed the pool's 60 an hour.
- **Rates:**
  - 2×10^7 digests/s is this benchmark's 4-core container (`measure_rate`
    gave 21–23 M).
  - 2×10^6 stands for a slow device.
  - Seconds in the tables are at the honest rate.
  - "Agent fleet" is the agents' total work over the run, in machines at the
    honest rate running without pause.
- **Latencies** (p50, p95) are of honest users who got in, from arrival to
  admission.

## Results: honest rate 2×10^7 digests/s

| pool | agents | agents:human | honest admitted | busy | expired | p50 s | p95 s | honest s/admit | agents admitted | agent s/identity | agent fleet | asked (max) | admitted/h |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| recommended | client | 0:1 | 100.0% of 53 | 0.0% | 0.0% | 0 | 0 | 0.0 | – | – | – | 2^20.0 | 8.9 |
| recommended | client | 1:1 | 100.0% of 53 | 0.0% | 0.0% | 0 | 0 | 0.0 | 67 of 67 | 0.1 | 0.00 | 2^20.0 | 20.1 |
| recommended | client | 10:1 | 56.6% of 53 | 43.4% | 0.0% | 4 | 57 | 0.2 | 339 of 573 | 0.2 | 0.00 | 2^20.0 | 61.5 |
| recommended | client | 100:1 | 5.7% of 53 | 94.3% | 0.0% | 10 | 11 | 37.7 | 367 of 5855 | 36.9 | 0.63 | 2^24.0 | 61.6 |
| recommended | client | 1000:1 | 0.0% of 53 | 100.0% | 0.0% | – | – | – | 371 of 59970 | 390.1 | 6.68 | 2^24.0 | 61.6 |
| recommended | outbid | 1:1 | 100.0% of 53 | 0.0% | 0.0% | 0 | 0 | 0.0 | 67 of 67 | 0.3 | 0.00 | 2^20.0 | 20.1 |
| recommended | outbid | 10:1 | 13.2% of 53 | 86.8% | 0.0% | 6 | 20 | 15.0 | 396 of 573 | 1690.2 | 28.34 | 2^24.0 | 61.4 |
| recommended | outbid | 100:1 | 0.0% of 53 | 100.0% | 0.0% | – | – | – | 430 of 5855 | 45643.3 | 778.38 | 2^24.0 | 61.4 |
| recommended | outbid | 1000:1 | 0.0% of 53 | 100.0% | 0.0% | – | – | – | 430 of 59970 | 505847.0 | 8627.93 | 2^24.0 | 61.4 |
| off | client | 0:1 | 100.0% of 53 | 0.0% | 0.0% | 0 | 0 | 0.0 | – | – | – | 2^20.0 | 8.9 |
| off | client | 1:1 | 100.0% of 53 | 0.0% | 0.0% | 0 | 0 | 0.0 | 67 of 67 | 0.1 | 0.00 | 2^20.0 | 20.1 |
| off | client | 10:1 | 100.0% of 53 | 0.0% | 0.0% | 0 | 0 | 0.0 | 573 of 573 | 0.1 | 0.00 | 2^20.0 | 104.5 |
| off | client | 100:1 | 100.0% of 53 | 0.0% | 0.0% | 0 | 0 | 0.0 | 5855 of 5855 | 0.1 | 0.01 | 2^20.0 | 984.7 |
| off | client | 1000:1 | 100.0% of 53 | 0.0% | 0.0% | 0 | 0 | 0.0 | 59970 of 59970 | 0.1 | 0.15 | 2^20.0 | 10003.9 |

## Results: honest rate 2×10^6 digests/s

| pool | agents | agents:human | honest admitted | busy | expired | p50 s | p95 s | honest s/admit | agents admitted | agent s/identity | agent fleet | asked (max) | admitted/h |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| recommended | client | 0:1 | 100.0% of 53 | 0.0% | 0.0% | 0 | 1 | 0.5 | – | – | – | 2^20.0 | 8.9 |
| recommended | client | 1:1 | 100.0% of 53 | 0.0% | 0.0% | 0 | 1 | 0.5 | 67 of 67 | 0.6 | 0.00 | 2^20.0 | 20.1 |
| recommended | client | 10:1 | 50.9% of 53 | 49.1% | 0.0% | 2 | 58 | 2.3 | 342 of 573 | 2.1 | 0.03 | 2^20.0 | 61.5 |
| recommended | client | 100:1 | 5.7% of 53 | 90.6% | 3.8% | 23 | 81 | 357.9 | 367 of 5855 | 368.7 | 6.26 | 2^24.0 | 61.6 |
| recommended | client | 1000:1 | 1.9% of 53 | 94.3% | 3.8% | 77 | 77 | 1103.5 | 370 of 59970 | 3911.7 | 66.77 | 2^24.0 | 61.6 |
| recommended | outbid | 1:1 | 100.0% of 53 | 0.0% | 0.0% | 0 | 1 | 0.5 | 67 of 67 | 2.5 | 0.01 | 2^20.0 | 20.1 |
| recommended | outbid | 10:1 | 17.0% of 53 | 79.2% | 3.8% | 9 | 116 | 111.7 | 396 of 573 | 3913.1 | 65.27 | 2^24.0 | 61.4 |
| recommended | outbid | 100:1 | 0.0% of 53 | 96.2% | 3.8% | – | – | – | 430 of 5855 | 88801.5 | 1514.35 | 2^24.0 | 61.4 |
| recommended | outbid | 1000:1 | 0.0% of 53 | 96.2% | 3.8% | – | – | – | 430 of 59970 | 979056.0 | 16698.93 | 2^24.0 | 61.4 |
| off | client | 0:1 | 100.0% of 53 | 0.0% | 0.0% | 0 | 1 | 0.5 | – | – | – | 2^20.0 | 8.9 |
| off | client | 1:1 | 100.0% of 53 | 0.0% | 0.0% | 0 | 1 | 0.5 | 67 of 67 | 0.6 | 0.00 | 2^20.0 | 20.1 |
| off | client | 10:1 | 100.0% of 53 | 0.0% | 0.0% | 0 | 1 | 0.5 | 573 of 573 | 0.6 | 0.01 | 2^20.0 | 104.5 |
| off | client | 100:1 | 100.0% of 53 | 0.0% | 0.0% | 0 | 1 | 0.5 | 5855 of 5855 | 0.5 | 0.15 | 2^20.0 | 984.7 |
| off | client | 1000:1 | 100.0% of 53 | 0.0% | 0.0% | 0 | 1 | 0.5 | 59970 of 59970 | 0.5 | 1.47 | 2^20.0 | 10003.9 |

## Threshold: just above the pool's capacity (rate 2×10^7)

| pool | agents | agents:human | honest admitted | busy | expired | p50 s | p95 s | honest s/admit | agents admitted | agent s/identity | agent fleet | asked (max) | admitted/h |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| recommended | client | 3:1 | 100.0% of 53 | 0.0% | 0.0% | 0 | 0 | 0.0 | 176 of 176 | 0.1 | 0.00 | 2^20.0 | 38.2 |
| recommended | client | 5:1 | 100.0% of 53 | 0.0% | 0.0% | 0 | 0 | 0.1 | 283 of 284 | 0.1 | 0.00 | 2^20.0 | 56.1 |
| recommended | client | 6:1 | 94.3% of 53 | 5.7% | 0.0% | 0 | 38 | 0.1 | 316 of 344 | 0.1 | 0.00 | 2^20.0 | 61.1 |
| recommended | client | 8:1 | 66.0% of 53 | 34.0% | 0.0% | 3 | 58 | 0.2 | 334 of 467 | 0.2 | 0.00 | 2^20.0 | 61.6 |
| recommended | outbid | 3:1 | 100.0% of 53 | 0.0% | 0.0% | 0 | 0 | 0.0 | 176 of 176 | 0.2 | 0.00 | 2^20.0 | 38.2 |
| recommended | outbid | 5:1 | 100.0% of 53 | 0.0% | 0.0% | 0 | 0 | 0.1 | 284 of 284 | 0.2 | 0.00 | 2^20.0 | 56.3 |
| recommended | outbid | 6:1 | 58.5% of 53 | 41.5% | 0.0% | 0 | 49 | 0.2 | 344 of 344 | 0.8 | 0.01 | 2^20.0 | 61.5 |
| recommended | outbid | 8:1 | 15.1% of 53 | 84.9% | 0.0% | 5 | 21 | 13.0 | 393 of 467 | 694.6 | 11.62 | 2^24.0 | 61.4 |
| off | client | 3:1 | 100.0% of 53 | 0.0% | 0.0% | 0 | 0 | 0.0 | 176 of 176 | 0.1 | 0.00 | 2^20.0 | 38.2 |
| off | client | 5:1 | 100.0% of 53 | 0.0% | 0.0% | 0 | 0 | 0.0 | 284 of 284 | 0.1 | 0.00 | 2^20.0 | 56.3 |
| off | client | 6:1 | 100.0% of 53 | 0.0% | 0.0% | 0 | 0 | 0.0 | 344 of 344 | 0.1 | 0.00 | 2^20.0 | 66.3 |
| off | client | 8:1 | 100.0% of 53 | 0.0% | 0.0% | 0 | 0 | 0.0 | 467 of 467 | 0.1 | 0.00 | 2^20.0 | 86.8 |

## Reading the tables

- **"admitted/h"** is the pool's ceiling at work. The rows with the pool off
  show what it holds back.
- **"asked (max)"** shows the controller reaching `max_effort` within the
  run once the queue fills: 4 windows of 300 s from `2^20`. In the threshold
  runs the queue never fills, so the price never moves, though honest users
  are already being refused.
- **"agent fleet"** for `outbid` at 100:1 and 1000:1 is large only because
  these agents are wasteful: each keeps re-solving for an hour. Denial needs
  far less. The threshold table shows 6:1 `outbid` costing 0.01 machines.
  The cheapest denial is to keep slightly more demand than the pool's
  capacity, bidding above an honest retry.
- **"honest s/admit"** is all honest work divided by honest admissions, so
  failed attempts' work is charged to those who got in.

## Not measured

- jig-server's admission. Today it asks a one-time proof per new DID at
  `2^pow_bits` (default 20, off by default) and has no pool. Its capacity
  pools (#318) and its load-following effort (#325) are open. This harness is
  meant to be pointed at them once they merge.
- Network latency, server CPU for verification, `max_pending_challenges`,
  penalties, short names, the allowlist, and standing (not built yet).
- Users who come back later. Each honest arrival is one `jig ns register`.

## Finding in the code under test

`Market::admit` can spin without sleeping. Say a waiter finds the pool short
of a token by less than a float's breadth: `tokens` is something like
`0.99999999999`. Then `until_token()` is under a nanosecond, and
`Duration::from_secs_f64` makes it 0. The waiter's `sleep_until(now)`
completes without parking.

- **On a real clock:** a few nanoseconds of spinning until time moves.
  Harmless.
- **On tokio's paused clock:** the runtime never goes idle, so auto-advance
  never moves time, and the run hangs. Any test that drives the pool with
  contention under `start_paused` hits it.

This harness steps the clock itself (`tokio::time::advance`, 1 ms) rather
than change the market. Rounding `until_token` up to the timer's 1 ms
resolution would fix it.
