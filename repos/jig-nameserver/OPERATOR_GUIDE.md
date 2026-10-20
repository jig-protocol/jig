# jig-nameserver Operator Guide

This guide covers what an operator configures on a v0.0.2 nameserver: the routes it serves, the alias rate limits, and running it behind a reverse proxy.

- Normative behaviour: the spec's [Identity and Reputation](../jig-spec/src/identity-and-reputation.md) chapter.
- Why the parameters work the way they do: [nameserver abuse economics](../../docs/security/nameserver-abuse-economics.md).
- The [nameserver abuse runbook](../../docs/operations/nameserver-abuse-runbook.md) is historical. It was written for the v0.0.1 surface (proof-of-work challenges, penalties, admin, reputation, tribunal and federation routes), which has been removed.

## Routes

`jig-nameserver serve` mounts these routes and nothing else:

| Route | Method | Purpose |
|---|---|---|
| `/.well-known/jig-ns` | GET | discovery document |
| `/.well-known/jig-ns/capabilities` | GET | capabilities (plain text) |
| `/v1/health` | GET | liveness |
| `/v1/challenge` | GET | one-time challenge for register and renew |
| `/v1/register` | POST | bind an alias to a DID |
| `/v1/resolve/{alias}` | GET | look up an alias |
| `/v1/rotate` | POST | move an alias to a new key |
| `/v1/renew` | POST | renew an alias |
| `/v1/handles` | GET | list every alias; **debug-gated** behind `[v0_0_2.debug] list_handles` |

`register` and `renew` need a signature by the DID's key over the challenge; `rotate` needs signatures by both the old and the new key. `/v1/handles` enumerates every registered alias, so leave it off unless you need it. `register`, `renew` and `rotate` also carry proof-of-work on a suffix that asks for it: see [Proof-of-work](#proof-of-work). None of the routes needs a server secret.

A future feature that needs a symmetric server secret will add a purpose-named, optional key; none is needed today.

## Configuration

Settings come from the config file (`JIG_NS_CONFIG`, or the default path), then environment variables override them. Settings are read at start-up; restart the service after changing them.

- `[[v0_0_2.nameserver.alias_suffixes]]` (required, no default): each suffix this nameserver serves, with its registration policy. The nameserver refuses to start without one. See `deploy/README.md` for the per-suffix options.
- `[v0_0_2.server] server_did_keyfile`: the nameserver's signing key. Created on first start if missing. Back it up; a new key is a new nameserver identity.
- `[v0_0_2.debug] list_handles` (default `false`): mounts `/v1/handles`.
- `[storage] database_path` / `JIG_NS_DB_PATH`: the alias database.
- `[network] bind` / `JIG_NS_BIND` and `[network] port` / `JIG_NS_PORT`: listen address.
- `[network] trust_proxy` / `JIG_NS_TRUST_PROXY` and `[network] proxy_ip_header` / `JIG_NS_PROXY_IP_HEADER`: see [Behind a reverse proxy](#behind-a-reverse-proxy).

Every config section denies unknown keys: a typo, or a key in the wrong section, stops the nameserver at start-up with an error naming the key. A section or key that was removed (`[pow]`, `[rate_limits]`, `[transparency]`, `[runtime]`, `[anomaly_detection]`, `[hot]`, `[federation]`, `storage.backend*`, `analytics.backend*`) fails with a message saying so; delete it. Removed environment variables, such as `JIG_NS_SECRET`, `JIG_NS_POW_*` and the federation `JIG_NS_*` variables, don't stop start-up: the nameserver logs a warning naming each one and ignores it.

## Proof-of-work

Each suffix sets the JEP-0008 work its register, renew and rotate requests carry. It is **on by default**, at these recommended values, and `jig` solves it:

```toml
[v0_0_2.nameserver.alias_suffixes.pow]
min_effort = 1048576     # 2^20: an ordinary registration of 5 letters or more
max_effort = 16777216    # 2^24: the most any registration is asked for
max_solve_secs = 10      # max_effort must fit this at 5.5M digests/s, or boot fails
short_name_len = 5       # shorter names pay short_name_factor per missing letter
short_name_factor = 4
renew_effort = 1         # renew and rotate by the holder
```

- **The offer.** `GET /v1/challenge?action=register|renew|rotate&did=<did>&name=<alias@suffix>` returns the challenge, the effort asked (`pow`), and `pow_offer`: the same, signed by the nameserver's DID. The proof is checked against that promise, so raising `min_effort` never refuses a client mid-solve. For rotate, `did` is the old DID.
- **Refused before any work.** For `register`, the challenge request already refuses a closed suffix, a short or reserved alias and a taken alias. `register` checks them again, and refuses a second name for the DID once the DID has signed (not before, since the refusal names the alias it holds).
- **Order of checks.** The work is checked (one hash) before any signature. Bad work is `400 POW_INVALID`, too little is `400 POW_INSUFFICIENT`, missing work is `428 POW_REQUIRED` with the offer restated. None of them consumes the challenge.
- **Allowlisted names** (`registration_allow`) pay `min_effort`, with no length multiplier.
- **Penalties.** Work that does not verify adds a point to the client's address (never to the DID it names, which is unproven at that stage). A signed attempt on a name another DID holds adds a point to that (alias, DID) pair only. Each point doubles the effort asked; it lasts `penalty_decay_secs` (600), and a repeat before it lapses adds a point and doubles its life.
- **Off:** `min_effort = 0`. A challenge requested without `action` still works on such a suffix; on one that asks for work it can only lead to `428`.

## Registration pool

The pool caps registrations by DIDs that `registration_allow` does not name, however much work they bring:

```toml
[v0_0_2.nameserver.alias_suffixes.pool]
enabled = true                 # the default; jig waits out 503 REGISTRATION_BUSY
strangers_per_hour = 60
burst = 10
controller = "doubling"
controller_window_secs = 300
queue_len = 20
queue_wait_secs = 10
```

- A stranger registration whose work and signature verified takes a token. With none left it waits, up to `queue_len` of them, the highest effort bid first; a full queue takes a newcomer only if it bids more than the lowest waiting, which is refused. After `queue_wait_secs` without a token the answer is `503 REGISTRATION_BUSY` with `Retry-After`. The challenge is not consumed, but the client should fetch a fresh one.
- **The controller.** After a window in which the queue filled, the effort asked doubles (up to `max_effort`); after a window in which nothing queued, it halves (never below `min_effort`). New challenges state the current effort.
- Allowlisted registrations skip the pool and pay `min_effort`.
- The pool, controller and penalties are in memory and per process.

## Rate limits

The nameserver limits `POST /v1/register`, `/v1/rotate` and `/v1/renew`, and `GET /v1/challenge`:

```toml
[alias_rate_limits]
enabled = true
per_ip_per_min = 30              # requests per client IP, across the three routes
per_did_per_min = 10             # successful requests naming a DID
challenge_per_ip_per_min = 60    # GET /v1/challenge per client IP, a bucket of its own
max_pending_challenges = 100000  # past it, new challenges get 503 BUSY; live ones are kept, and a tenth is kept for renew and rotate
```

- **Per client IP.** Every admitted request is counted against its client IP before the handler runs. IPv6 clients are counted per /64, so one host cannot rotate through its own addresses to escape the limit.
- **Per DID.** A request naming a DID (`did`, `old_did` or `new_did`) is refused if that DID's bucket is full, but it is counted only when it succeeds. Each successful request needs that DID's signature, so only the key holder can use up a DID's limit. A forged request naming someone else's DID costs the sender's IP bucket and leaves the victim's untouched.
- A refused request is not counted. It gets HTTP 429 with code `RATE_LIMITED` and a `Retry-After` header.
- Windows are fixed, one minute long and held in memory. They reset when the nameserver restarts and are not shared between processes.
- A limit of `0` refuses every request on that bucket. `enabled = false` turns the per-IP and per-DID limits off; `max_pending_challenges` always applies.
- `GET /.well-known/jig-ns` publishes these three values under `policy.alias_rate_limits`.

## Behind a reverse proxy

Without `trust_proxy`, the nameserver takes the client IP from the socket, so every client behind a proxy shares the proxy's address and its rate limit.

If the nameserver runs behind a reverse proxy, set:

```toml
[network]
trust_proxy = true
proxy_ip_header = "x-forwarded-for"   # the default
```

The nameserver uses the **last** address in that header, the one your proxy appended. Earlier entries are whatever the client sent and are ignored. With one proxy in front this is the client's address; behind several, the limit applies to the nearest proxy. Only set `trust_proxy` when the nameserver is reachable through the proxy alone, since anyone who can connect directly can otherwise choose the address they are counted under.

## Security notes

- Back up `server_did_keyfile` and keep it readable by the service user only.
- Keep `[v0_0_2.debug] list_handles` off on any nameserver reachable by people you do not trust.
- `[federation] enabled` (off by default) still starts an outbound gossip loop, but no peer can reach this nameserver's federation routes because they were removed. Leave it off.
- Keep instance logs minimal; avoid storing sensitive metadata.
