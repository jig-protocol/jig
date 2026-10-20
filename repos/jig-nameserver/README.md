# Jig Nameserver

The Jig nameserver binds human-readable aliases (`alice@names.example.org`) to DIDs. It serves each binding as a signed attestation that a resolver checks itself, so a client never has to trust the transport. Normative behaviour is in the spec's [Identity and Reputation](../jig-spec/src/identity-and-reputation.md) chapter (JEP-0004).

## Configuration

The nameserver reads one config file, named by `--config <path>` or else `JIG_NS_CONFIG`. There is no default path: with neither set it refuses to start. It no longer reads `JIG_CONFIG`, `~/.jig/config.toml` or `./config/jig-nameserver/jig-config.toml`. Environment variables (`JIG_NS_BIND`, `JIG_NS_PORT`, `JIG_NS_DB_PATH`, …) override the file. The file must name the suffixes it serves; see `deploy/jig-nameserver.example.toml` and `OPERATOR_GUIDE.md`.

A minimal file:

```toml
[network]
bind = "127.0.0.1"
port = 7070

[[v0_0_2.nameserver.alias_suffixes]]
suffix = "names.example.org"
```

For more examples, see [`examples/config`](examples/config/).

## Routes

| Route | Method | Purpose |
| --- | --- | --- |
| `/v1/challenge` | GET | one-time nonce that register and renew sign |
| `/v1/register` | POST | bind an alias to a DID |
| `/v1/resolve/{alias}` | GET | the signed attestation, links and reachability for an alias |
| `/v1/rotate` | POST | move an alias to a new key (signed by both keys) |
| `/v1/renew` | POST | refresh an alias's validity window |
| `/v1/suffixes` | GET | the suffixes served and this nameserver's DID |
| `/.well-known/jig-ns-delegation` | GET | signed delegation for a DNS-rooted suffix |
| `/.well-known/jig-ns` | GET | discovery document, including the published rate limits |
| `/.well-known/jig-ns/capabilities` | GET | capabilities as plain text |
| `/v1/health` | GET | liveness |
| `/v1/handles` | GET | every registered alias; mounted only with `[v0_0_2.debug] list_handles = true` |

[`OPERATOR_GUIDE.md`](OPERATOR_GUIDE.md) covers the rate limits on the write routes and running behind a reverse proxy. [`deploy/README.md`](../../deploy/README.md) covers suffix and registration policy.

## Commands

- `jig-nameserver serve` (the default): run the HTTP server. `--bind` and `--port` override the config.
- `jig-nameserver keygen --out <path>`: write a new signing key and print its DID, for a key ceremony before a server exists. It never overwrites a file.
- `dns-txt [CONFIG]`: print DNS TXT records advertising the `[capabilities]` section.

## Running Locally

```bash
cargo run -p jig-nameserver -- --config ./my-nameserver.toml serve
```

## Tests

```bash
cargo nextest run -p jig-nameserver
```
