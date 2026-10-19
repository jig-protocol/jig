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

`register` and `renew` need a signature by the DID's key over the challenge; `rotate` needs signatures by both the old and the new key. `/v1/handles` enumerates every registered alias, so leave it off unless you need it. None of the routes asks for proof-of-work, and none needs a server secret.

A future feature that needs a symmetric server secret will add a purpose-named, optional key; none is needed today.

## Configuration

Settings come from the config file (`JIG_NS_CONFIG`, or the default path), then environment variables override them. Settings are read at start-up; restart the service after changing them.

- `[v0_0_2.nameserver] alias_suffix` (default `gigue.jig`): the suffix aliases are registered under.
- `[v0_0_2.server] server_did_keyfile`: the nameserver's signing key. Created on first start if missing. Back it up; a new key is a new nameserver identity.
- `[v0_0_2.debug] list_handles` (default `false`): mounts `/v1/handles`.
- `[storage] database_path` / `JIG_NS_DB_PATH`: the alias database.
- `[network] bind` / `JIG_NS_BIND` and `[network] port` / `JIG_NS_PORT`: listen address.
- `[network] trust_proxy` / `JIG_NS_TRUST_PROXY` and `[network] proxy_ip_header` / `JIG_NS_PROXY_IP_HEADER`: see [Behind a reverse proxy](#behind-a-reverse-proxy).

Older configs that still set `[pow]`, or environments that still export `JIG_NS_SECRET` or `JIG_NS_POW_*`, keep starting: those settings are ignored. Remove them at your next change.

## Rate limits

The nameserver limits `POST /v1/register`, `/v1/rotate` and `/v1/renew`:

```toml
[alias_rate_limits]
enabled = true
per_ip_per_min = 30   # requests per client IP, across the three routes
per_did_per_min = 10  # successful requests naming a DID
```

- **Per client IP.** Every admitted request is counted against its client IP before the handler runs. IPv6 clients are counted per /64, so one host cannot rotate through its own addresses to escape the limit.
- **Per DID.** A request naming a DID (`did`, `old_did` or `new_did`) is refused if that DID's bucket is full, but it is counted only when it succeeds. Each successful request needs that DID's signature, so only the key holder can use up a DID's limit. A forged request naming someone else's DID costs the sender's IP bucket and leaves the victim's untouched.
- A refused request is not counted. It gets HTTP 429 with code `RATE_LIMITED` and a `Retry-After` header.
- Windows are fixed, one minute long and held in memory. They reset when the nameserver restarts and are not shared between processes.
- A limit of `0` refuses every request on that bucket. `enabled = false` turns both limits off.
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
