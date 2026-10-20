# Nameserver abuse runbook

> **Superseded.** This runbook described the nameserver's legacy prototype. #154 removed the
> routes most steps below call: `/v1/admin/*`,
> `/v1/policy`, `/v1/tribunal/*`, `/v1/reputation/*`, `/v1/work/*`, `/v1/hosts/*`,
> `/v1/resolve?name=`, `/v1/federation/*`, and the proof-of-work challenges for `/v1/claim`
> and `/v1/alias`. The `JIG_NS_POW_*`, `JIG_NS_PENALTY_*`, `JIG_NS_ANON_*` and
> `JIG_NS_RATE_*` settings no longer affect any served route. What still applies:
> - Section 1: steps 1, 2, 5 and 6.
> - Section 2: step 5 (rate-limit `/v1/register`, `/v1/rotate` and `/v1/renew` at the reverse
>   proxy).
> - Section 3, "Compromised nameserver": steps 1 to 3 and 5 to 7. Step 4's attestation-key
>   rotation also still applies.
> - Section 4 no longer applies: nameserver federation was removed (#237).
>
> A new runbook follows lane R's redesign: the [framing doc](../superpowers/specs/2026-10-18-reputation-pow-tribunals-framing.md) and the draft
> [JEP-0008](../../repos/jig-spec/jep/jep-0008-proof-of-work.md), [JEP-0009](../../repos/jig-spec/jep/jep-0009-rulesets-reputation-logs.md) and [JEP-0010](../../repos/jig-spec/jep/jep-0010-reports-tribunals-lists.md).

What a `jig-nameserver` operator does about harassment reports, registration and relay
abuse, a compromised nameserver, and a rogue federated instance. Parameters and endpoints
are the reference implementation's. Settings and defaults are listed in the
[operator guide](../../repos/jig-nameserver/OPERATOR_GUIDE.md); the reasoning behind them is
in [nameserver abuse economics](../security/nameserver-abuse-economics.md).

Every step marked **(not yet implemented)** depends on tribunals, cross-registration within
a ruleset group, the transparency log or encrypted-abuse reporting. The spec requires all
four; the code does not have them yet. Skip those steps today, and do not treat their
absence as the intended design.

There is no global ledger and no central blocklist. Every decision below is yours, for your
nameserver. Tell your peers what you did; they decide for themselves. If you belong to a
ruleset group, its members apply shared outcomes under the group's ruleset; nothing
spreads further than the group.

## Before an incident

- **Set `JIG_NS_ADMIN_TOKEN`.** Without it, `/v1/admin/*` and `/v1/work/enqueue` accept
  anyone. With it, they require the `x-admin-token` header.
- **Restrict every write endpoint at the reverse proxy.** The admin token does not cover
  `/v1/reputation/observe`, `/v1/tribunal/cases*`, `/v1/receipts/submit`,
  `/v1/attestations/submit` or `/v1/federation/gossip`, and `/v1/register` has no
  proof-of-work (it is rate-limited per client IP and per DID, `[alias_rate_limits]`). The
  shipped unit binds to the tailnet only ([`deploy/README.md`](../../deploy/README.md)). Keep it that way until these are
  authenticated.
- **Know your files.** With the shipped unit: legacy store `/var/lib/jig/nameserver.db`
  (penalties, rate windows, federation cache, reputation, tribunal records, the
  `ns_identity` key), alias store `/var/lib/jig/nameserver_v002.db`, attestation signing key
  `/var/lib/jig/nameserver_v002.key` (or `[v0_0_2.server] server_did_keyfile`), and any
  `JIG_NS_*` settings in the optional `/etc/jig/jig-nameserver.env`. The nameserver has no
  `JIG_NS_SECRET` any more (#192).
- **Know that settings are read at start-up.** Every `JIG_NS_*` change below needs
  `sudo systemctl restart jig-nameserver`. A restart does not reset the legacy penalties or
  rate windows, which live in the database. It does reset the `[alias_rate_limits]`
  buckets on `/v1/register`, `/v1/rotate` and `/v1/renew`, which are held in memory.
- **Turn on a default ruleset** (`[reputation] default_ruleset`) if you want reputation
  observations to affect proof-of-work. Without one, they are recorded and ignored.

Admin calls used below (add `-H 'x-admin-token: <token>'` when the token is set):

```bash
# Penalty points on a key (decay is applied on read)
curl -s 'http://127.0.0.1:7070/v1/admin/penalties?key=claim:subject:alice@example.com'

# Clear a key's penalty points
curl -sX POST http://127.0.0.1:7070/v1/admin/penalties \
  -H 'content-type: application/json' -d '{"key":"claim:subject:alice@example.com"}'

# Current one-minute rate window for a key, and reset it
curl -s 'http://127.0.0.1:7070/v1/admin/rate?key=ip:203.0.113.7'
curl -sX POST http://127.0.0.1:7070/v1/admin/rate \
  -H 'content-type: application/json' -d '{"key":"ip:203.0.113.7"}'

# Effective policy, to confirm a change took
curl -s http://127.0.0.1:7070/v1/policy
```

Rate keys: `claim:subject:<handle>`, `alias:scope:<scope>:subject:<subject-or-empty>`,
`ip:<address>`.

## 1. Harassment report

Harassment happens in channels, which the nameserver never sees. Its part is the identities:
the DIDs that sent the blocks and the aliases that name them. Each channel has exactly one
owning server.

1. **Collect evidence as references.** Ask the reporter for block CIDs and the channel. Every
   block's sender is a DID, so the DID is the subject, whatever alias was displayed. Do not
   copy message content into the nameserver.
2. **Act where the content is.** The operator of the channel's owning server removes the
   sender or the blocks. The nameserver cannot. If the channel is encrypted, neither that
   server nor you can read it: the evidence is whatever the reporter, as a recipient,
   chooses to disclose. Record it by reference. Never ask a reporter for their keys.
3. **Record the case:**

   ```bash
   curl -sX POST http://127.0.0.1:7070/v1/tribunal/cases \
     -H 'content-type: application/json' \
     -d '{"subject":"user","subject_id":"did:jig:...","reason":"harassment report",
          "severity":"high","metadata":{"evidence_cids":["..."],"channel":"..."}}'
   ```

   Pass `"ruleset"` if no default ruleset is configured. The case is a record. It changes
   nothing by itself.
4. **Record a negative observation** if you run a default ruleset. It raises the subject's
   proof-of-work by at most a quarter of the bits on your nameserver:

   ```bash
   curl -sX POST http://127.0.0.1:7070/v1/reputation/observe \
     -H 'content-type: application/json' \
     -d '{"subject":"user","subject_id":"did:jig:...","score":-1.0,"weight":1.0,
          "evidence":"case <id>","expires_at":"2026-12-31T00:00:00Z"}'
   ```

   Set `expires_at`, so the mark falls away.
5. **If an alias impersonates the victim**, check `GET /v1/resolve/<alias>`. There is no
   revocation endpoint yet. Record the case, and ask servers that trust you to block the
   DID locally.
6. **Do not try to connect identities.** If the harasser is anonymous, the protocol has no
   link from that identity to a DID, by design. Do not correlate addresses, timing or
   devices to build one.
7. **Close the case** with `POST /v1/tribunal/cases/<id>/decision`
   (`{"outcome":"sustain","notes":"..."}`, or `dismiss`). A `penalty_delta` is stored, not
   applied yet; the spec requires decisions to be applied and logged.
8. **(not yet implemented)** In a high-sec ruleset group, refer the case to the group's
   tribunal and apply its outcome under the group's ruleset. For an encrypted channel, the
   reporter submits effective proof of the reported messages through the victim-key
   delegation path the spec requires.

## 2. Registration and relay abuse

**Signs:** a run of HTTP 429s at the proxy, many fresh handles or aliases in a short time, or
one scope collecting aliases.

1. **Find the key.** Check the hottest addresses and keys with `GET /v1/admin/rate` and
   `GET /v1/admin/penalties`. A single address points to the per-IP limit. A single
   subject or scope points to the per-key limit.
2. **Flood on one key (spam).** The defaults already price it: any penalty point takes the
   key to `JIG_NS_POW_MAX` (28 bits) until the points decay at one per `JIG_NS_PENALTY_DECAY`
   (300 s). Usually nothing more is needed. To hold the price longer, raise
   `JIG_NS_PENALTY_DECAY` (for example to 600 or 1800).
3. **Many fresh keys (Sybil).** Penalties do not help, because each key is new. Raise
   `JIG_NS_POW_DIFFICULTY` by 2 to 4 bits (each bit doubles the work) and lower
   `JIG_NS_RATE_PER_IP_PER_MIN` (for example from 120 to 30). Keep `JIG_NS_POW_MAX` at least
   a few bits above the base, or penalties lose their range.
4. **Anonymous aliases.** Raise `JIG_NS_ANON_MIN_POW` above the base (24 is a reasonable
   open-instance value; its default of 12 does nothing while the base is 18). If that is not
   enough, block `POST /v1/alias` at the reverse proxy until the flood stops. Do **not**
   set `JIG_NS_ANON_ENABLED=false` for this: it removes the anonymous floor but does not
   stop anonymous aliases being minted.
5. **Abuse of `/v1/register`.** It has no proof-of-work. It is rate-limited per client IP
   and per DID (`[alias_rate_limits]`, defaults 30 and 10 per minute); lower
   `per_ip_per_min` for the duration, or close it to all but known clients at the reverse
   proxy.
6. **Behind a proxy**, set `JIG_NS_TRUST_PROXY=true` and `JIG_NS_PROXY_IP_HEADER` to the
   header your proxy sets, or every request shares the proxy's address and one bucket.
7. **Griefing.** If a legitimate user's key was pushed to the maximum by someone else's
   requests, clear it with `POST /v1/admin/penalties`. If it recurs, raise
   `JIG_NS_RATE_PER_MIN` for the duration.
8. **Relay abuse by a federated server** (junk relayed into channels) is handled in that
   server's federation settings, not here (threat
   [OP-09](../../repos/jig-spec/src/threat-register.md)). On the nameserver, record a case
   and an observation with `"subject":"server"`. Receipt anomalies are ledgered separately
   at `GET /v1/hosts/<did>/penalties`.
9. **Step back down.** Once traffic is normal, return the settings to their defaults.
   Leaving the base raised taxes every honest user.

## 3. Compromised nameserver

**Signs:** aliases resolving to DIDs their owners did not register, unexpected changes to
`/v1/policy`, the database or key files modified outside the service, or an admin token
seen where it should not be.

A compromised nameserver cannot forge a block: blocks are signed by their senders' DIDs. It
can point an alias at the wrong DID ([OP-08](../../repos/jig-spec/src/threat-register.md)),
issue attestations, and read or change everything in its databases.

1. **Contain.** Stop the service (`sudo systemctl stop jig-nameserver`) or firewall it. Keep
   copies of both databases, the key file and the logs before changing anything.
2. **Cut dependent servers loose.** Operators of servers with `[identity] mode =
   "nameserver"` remove your nameserver's `ns_did` from the `authorities` of each suffix
   under `[identity.delegations]` (and your URL from its `nameservers`), or switch to
   `tofu`, and restart. Servers accept only attestations an authority signed (#200), so an
   attestation under the removed key is refused from then on. `trusted_nameservers` is no
   longer used. Clients that list your suffix under `[naming.delegations]` need the same
   change.
3. **Find what changed.** Compare alias bindings in `nameserver_v002.db` and identities in
   `nameserver.db` against your latest backup. List every alias whose DID changed.
4. **Rotate everything:**
   - `JIG_NS_ADMIN_TOKEN`: new value.
   - Attestation key: move `nameserver_v002.key` aside and let the service mint a new one,
     which gives the nameserver a new `ns_did`. Every attestation signed by the old key
     must be treated as untrusted. Dependent servers and clients accept the new key only
     once its `ns_did` is in their delegation's `authorities`, so tell them the new DID.
   - `ns_identity` key: delete its row from `nameserver.db` so a new one is generated. This
     changes the `ns_id` in `/.well-known/jig-ns`.
5. **Restore bindings.** Revert changed aliases from backup. Ask users to renew
   (`POST /v1/renew`) so attestations are reissued under the new key. Users who rotated
   their DID since the backup must re-register.
6. **Tell people.** Announce the new `ns_did` and `ns_id`, the window of compromise and the
   affected aliases through channels your users already trust, and tell your federation
   peers directly. Clients that pinned DIDs will have flagged changed aliases; tell users
   to trust those warnings.
7. **Write it up**: timeline, cause, what was exposed, what changed.
8. **(not yet implemented)** In a high-sec ruleset group, open an incident case with the
   group's tribunal so the other members can quarantine cross-registered records from the
   window of compromise, and check your transparency log against their copies.

## 4. Rogue federated instance

**Signs:** a peer domain's handles resolving to conflicting DIDs, policy hashes from a peer
changing often, junk gossip, or reports that names from one domain are unreliable.

1. **Gather evidence.** Record the remote answers you saw (`GET /v1/resolve?name=<handle>`),
   gossip and policy hashes (`GET /v1/federation/policy`), and timestamps.
2. **Cut it off.** Add the domain to `JIG_NS_DENY_DOMAINS` (comma-separated, lowercase), or
   remove it from `JIG_NS_ALLOW_DOMAINS` if you run an allow list, and restart. Deny wins
   over allow.
3. **Purge the cache.** Cached answers are served before the deny check, so bad records
   from that domain live until `JIG_NS_CACHE_TTL` (default 300 s) expires. To drop them at
   once, delete that domain's rows from the `cache_identities` table in `nameserver.db`.
4. **Record it.** Open a case and record an observation with `"subject":"nameserver"` (or
   `"server"`) and the domain or DID as `subject_id`.
5. **Tell your peers** what you saw and what you did. They decide for themselves. No
   nameserver, an anchor included, can defederate an instance on anyone else's behalf.
6. **Reinstate deliberately.** Remove the domain from the deny list once the other operator
   explains and fixes the problem, and watch its answers for a while.
7. **(not yet implemented)** If the instance is in your ruleset group, take the evidence to
   the group's tribunal. Members apply its outcome under the group's ruleset; an anchor
   coordinates, it does not decide. A rogue instance outside your group is yours alone to
   cut off.
