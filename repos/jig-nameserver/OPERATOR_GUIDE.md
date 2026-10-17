# jig-nameserver Operator Guide (PoW, Rate Limits, Federation)

This guide helps operators tune PoW difficulty, rate limits, penalties, and federation behavior for resilient deployments.

- Incident response (harassment reports, registration and relay abuse, a compromised nameserver, a rogue federated instance): [nameserver abuse runbook](../../docs/operations/nameserver-abuse-runbook.md).
- Why the parameters work the way they do: [nameserver abuse economics](../../docs/security/nameserver-abuse-economics.md).
- Normative behaviour: the spec's [Identity and Reputation](../jig-spec/src/identity-and-reputation.md) chapter.

## Key Concepts

- PoW Difficulty: Hashcash-style blake3 keyed work with leading-zero bits. Expected trials ≈ 2^bits.
- Rate Limiting: Per-key and per-IP counters in fixed one-minute windows on challenge issuance (`POST /v1/challenge`). A refused request returns HTTP 429 and adds one penalty point to the refusing key.
- Penalties: Points per key increase effective PoW by `step_bits` per point (at most `max_points` = 64 count), then the automation multiplier applies, then the result is clamped to `[min, max]`. With the defaults one point reaches the maximum. Decay is linear: one point per `decay_secs` of quiet; a new penalty restarts the clock. Points on `ip:` keys are recorded but do not change difficulty.
- Scope: PoW, rate limits and penalties apply to the legacy `POST /v1/challenge`, `/v1/claim` and `/v1/alias` endpoints. The alias registration path the CLI uses (`GET /v1/challenge`, `POST /v1/register`) has neither; rate-limit it at the reverse proxy.
- Federation: `_jig-ns._tcp` SRV discovery with allow/deny domain gates and TTL caching.

## Configuration (Env Vars)

- `JIG_NS_POW_DIFFICULTY` (u16, default 18): Base PoW difficulty.
- `JIG_NS_POW_MIN` / `JIG_NS_POW_MAX` (u16): Clamp effective PoW.
- `JIG_NS_PENALTY_STEP_BITS` (u16, default 2): Bits added per penalty point.
- `[penalties] max_points` (TOML only, default 64): Most penalty points that count towards difficulty.
- `JIG_NS_PENALTY_DECAY` (secs, default 300): One penalty point decays per interval.
- `JIG_NS_AUTOMATION_ENABLED` (bool, default true), `JIG_NS_AUTOMATION_ALPHA` (default 1.4), `JIG_NS_AUTOMATION_PILE_ON` (default 0.5), `JIG_NS_AUTOMATION_MAX` (default 8.0): Penalty amplifier `1 + points^alpha × pile_on`, capped at max. Disable it, or lower `PILE_ON`, for a graded response instead of jumping to the maximum.
- `JIG_NS_RATE_PER_MIN` (u32, default 60): Per-key challenges per minute.
- `JIG_NS_RATE_PER_IP_PER_MIN` (u32, default 120): Per-IP challenges per minute.
- `JIG_NS_ANON_ENABLED` (bool, default true): Apply the anonymous floor to alias challenges without a subject. Setting it to false removes the floor; it does not stop anonymous aliases being minted (block `POST /v1/alias` at the proxy for that).
- `JIG_NS_ANON_MIN_POW` (u16, default 12): Floor for anonymous alias challenges. It has no effect unless it is above the base difficulty.
- `JIG_NS_ALLOW_DOMAINS` / `JIG_NS_DENY_DOMAINS` (CSV lowercased): Federation gates.
- `JIG_NS_CACHE_TTL` (secs, default 300): Federated identity cache TTL. Cached entries are served before the allow/deny check.
- `JIG_NS_ADMIN_TOKEN`: When set, admin endpoints require the `x-admin-token` header. When unset, they are open.
- `JIG_NS_TRUST_PROXY` (bool) and `JIG_NS_PROXY_IP_HEADER` (default `x-forwarded-for`): Take the client IP from the proxy header instead of the socket.

Settings are read at start-up; restart the service after changing them. Penalties and rate windows are stored in the database and survive restarts.

## Recommended Defaults

- Open instances: `JIG_NS_POW_DIFFICULTY=18`, `JIG_NS_ANON_MIN_POW=24`, `JIG_NS_RATE_PER_MIN=60`, `JIG_NS_RATE_PER_IP_PER_MIN=120`, `JIG_NS_PENALTY_STEP_BITS=2`, `JIG_NS_PENALTY_DECAY=600`.
- Closed/enterprise: Block `POST /v1/alias` at the proxy if you do not want anonymous aliases, or raise `JIG_NS_ANON_MIN_POW` to 26–28 (keep `JIG_NS_POW_MAX` at or above it).

## Introspection and Admin Endpoints

Admin endpoints require `x-admin-token` only when `JIG_NS_ADMIN_TOKEN` is set. Other write endpoints (`/v1/reputation/observe`, `/v1/tribunal/cases*`, `/v1/receipts/submit`, `/v1/attestations/submit`, `/v1/federation/gossip`, `/v1/register`) have no auth: restrict them with network policy or reverse-proxy ACLs.

- Policy snapshot: `GET /v1/policy`
- Well-known (discovery): `GET /.well-known/jig-ns`
- Capabilities (plain text): `GET /.well-known/jig-ns/capabilities`
- Penalty points: `GET /v1/admin/penalties?key=<k>`
- Reset penalty: `POST /v1/admin/penalties` with `{ "key": "<k>" }`
- Rate info: `GET /v1/admin/rate?key=<k>`
- Reset rate: `POST /v1/admin/rate` with `{ "key": "<k>" }`

Keys:
- Claim subject: `claim:subject:<handle>`
- Alias scope+subject: `alias:scope:<scope>:subject:<subject-or-empty>`
- IP bucket: `ip:<ip-address>`

## Operations Playbook

Quick reference. Step-by-step incident runbooks are in [nameserver abuse runbook](../../docs/operations/nameserver-abuse-runbook.md).

- Spike in abuse (global):
  - Temporarily raise `JIG_NS_POW_DIFFICULTY` and lower `JIG_NS_RATE_PER_IP_PER_MIN`.
  - Add denylist for offending domains, then gradually remove.
- Targeted scope abuse:
  - Inspect `alias:scope:<scope>:subject:<subject>` penalty/rate; reset, or raise `JIG_NS_ANON_MIN_POW` above the base.
  - To stop anonymous aliasing temporarily, block `POST /v1/alias` at the proxy.
- Chronic subject abuse:
  - Clear penalties upon remediation; keep rate low until behavior stabilizes.
- Federation latency/cache:
  - Increase `JIG_NS_CACHE_TTL` during high latency periods; maintain allowlist for trusted peers.

## Test Snippets

Issue challenge (claim):

```bash
curl -s http://127.0.0.1:7070/v1/challenge \
  -H 'content-type: application/json' \
  -d '{"action":"claim","subject":"alice@example.com"}' | jq .
```

Check penalty:

```bash
curl -s 'http://127.0.0.1:7070/v1/admin/penalties?key=claim:subject:alice@example.com' | jq .
```

Reset penalty:

```bash
curl -sX POST http://127.0.0.1:7070/v1/admin/penalties \
  -H 'content-type: application/json' \
  -d '{"key":"claim:subject:alice@example.com"}'
```

## Security Notes

- Protect admin endpoints behind an authenticated reverse proxy.
- Rotate `JIG_NS_SECRET` periodically. There is no overlap window: rotation invalidates every outstanding challenge, so rotate at a quiet time.
- Keep instance logs minimal; avoid storing sensitive metadata.

## Federation SRV

Configure DNS SRV for nameserver discovery:

```
_jig-ns._tcp.example.com.  3600 IN SRV 10 5 7070 ns1.example.com.
ns1.example.com.          3600 IN A   203.0.113.10
```

