# jig-nameserver Operator Guide (PoW, Rate Limits, Federation)

This guide helps operators tune PoW difficulty, rate limits, penalties, and federation behavior for resilient deployments.

## Key Concepts

- PoW Difficulty: Hashcash-style blake3 keyed work with leading-zero bits. Expected trials ≈ 2^bits.
- Rate Limiting: Per-key and per-IP token buckets (minute window) on challenge issuance.
- Penalties: Points per key increase effective PoW by `penalty_step_bits` per point; decays over time.
- Federation: `_jig-ns._tcp` SRV discovery with allow/deny domain gates and TTL caching.

## Configuration (Env Vars)

- `JIG_NS_POW_DIFFICULTY` (u16, default 18): Base PoW difficulty.
- `JIG_NS_POW_MIN` / `JIG_NS_POW_MAX` (u16): Clamp effective PoW.
- `JIG_NS_PENALTY_STEP_BITS` (u16, default 2): Bits added per penalty point.
- `JIG_NS_PENALTY_DECAY` (secs, default 300): Penalty decay interval.
- `JIG_NS_RATE_PER_MIN` (u32, default 60): Per-key challenges per minute.
- `JIG_NS_RATE_PER_IP_PER_MIN` (u32, default 120): Per-IP challenges per minute.
- `JIG_NS_ANON_ENABLED` (bool, default true): Allow anonymous alias minting.
- `JIG_NS_ANON_MIN_POW` (u16, default 8): Minimum PoW for anonymous alias challenges.
- `JIG_NS_ALLOW_DOMAINS` / `JIG_NS_DENY_DOMAINS` (CSV lowercased): Federation gates.
- `JIG_NS_CACHE_TTL` (secs, default 300): Federated identity cache TTL.

## Recommended Defaults

- Open instances: `JIG_NS_POW_DIFFICULTY=18`, `JIG_NS_ANON_MIN_POW=24`, `JIG_NS_RATE_PER_MIN=60`, `JIG_NS_RATE_PER_IP_PER_MIN=120`, `JIG_NS_PENALTY_STEP_BITS=2`, `JIG_NS_PENALTY_DECAY=600`.
- Closed/enterprise: Lower base for verified users; set `JIG_NS_ANON_ENABLED=false` or raise anon min Pow to 26–28.

## Introspection and Admin Endpoints

Note: No auth layer yet — protect with network policy or reverse proxy ACLs.

- Policy snapshot: `GET /v1/policy`
- Well-known (discovery): `GET /.well-known/jig-ns`
- Penalty points: `GET /v1/admin/penalties?key=<k>`
- Reset penalty: `POST /v1/admin/penalties` with `{ "key": "<k>" }`
- Rate info: `GET /v1/admin/rate?key=<k>`
- Reset rate: `POST /v1/admin/rate` with `{ "key": "<k>" }`

Keys:
- Claim subject: `claim:subject:<handle>`
- Alias scope+subject: `alias:scope:<scope>:subject:<subject-or-empty>`
- IP bucket: `ip:<ip-address>`

## Operations Playbook

- Spike in abuse (global):
  - Temporarily raise `JIG_NS_POW_DIFFICULTY` and lower `JIG_NS_RATE_PER_IP_PER_MIN`.
  - Add denylist for offending domains, then gradually remove.
- Targeted scope abuse:
  - Inspect `alias:scope:<scope>` penalty/rate; reset or raise min PoW for anonymous.
  - Consider temporarily disabling anonymous aliasing (`JIG_NS_ANON_ENABLED=false`).
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
- Rotate `JIG_NS_SECRET` periodically with overlap windows; avoid long-lived secrets.
- Keep instance logs minimal; avoid storing sensitive metadata.

## Federation SRV

Configure DNS SRV for nameserver discovery:

```
_jig-ns._tcp.example.com.  3600 IN SRV 10 5 7070 ns1.example.com.
ns1.example.com.          3600 IN A   203.0.113.10
```

