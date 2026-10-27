# Nameserver abuse runbook

What a `jig-nameserver` operator does about a registration flood, squatting, a harassment
report, a compromised nameserver, and a rogue or contradicting nameserver.

- Settings and defaults: the [operator guide](../../repos/jig-nameserver/OPERATOR_GUIDE.md).
- What the nameserver does: the spec's
  [Nameserver mechanics](../../repos/jig-spec/src/identity-and-reputation.md#nameserver-mechanics);
  normative source [JEP-0008](../../repos/jig-spec/jep/jep-0008-proof-of-work.md).
- Why the parameters are what they are:
  [nameserver abuse economics](../security/nameserver-abuse-economics.md).

There is no global ledger and no central blocklist. Every decision below is yours, for your
nameserver. Tell your peers what you did; they decide for themselves.

Steps marked **(not yet implemented)** depend on tribunals, cross-registration, the
transparency log or signed operator removal. The spec requires them; the code does not
have them yet. Skip those steps today.

## Before an incident

- **Know that settings are read at start-up.** Every change below is a config edit and a
  restart of the service. There is no reload and no admin endpoint.
- **Know what a restart resets.** The rate-limit buckets, the penalties, each suffix's
  pool and controller, and the pending challenges are all in memory. A restart:
  - refills every pool to its `burst`;
  - drops every penalty;
  - sets the suggested effort back to `min_effort`;
  - drops every pending challenge, so requests in flight get `CHALLENGE_UNKNOWN` and must
    start again.

  During a flood, a restart hands the attacker a fresh burst at the lowest price. Make the
  change you need in one restart.
- **Know your files.** The alias store is `<stem>_v002.db` beside `[storage]
  database_path`. The signing key is the sealed `.jigkey` that `[v0_0_2.server]
  server_did_keyfile` names (by default beside the store). Back both up
  ([`deploy/README.md`](../../deploy/README.md)).
- **Set `[network] trust_proxy`** if a TLS-terminating proxy sits in front, or every client
  shares the proxy's address, its rate limits and its penalties. A nameserver for a
  `config` or `contract` suffix must not sit behind one (operator guide, "Behind a reverse
  proxy").

## 1. Registration flood

**Signs:** many `503 REGISTRATION_BUSY`, `429 RATE_LIMITED` or `503 BUSY` answers in your
proxy or client reports; users saying registration is slow or always busy.

### Read the pool and the effort

The nameserver exports **no metrics**. It counts admitted and refused registrations, the
suggested effort, the queue and the tokens per suffix in memory, but no route, log line or
metrics endpoint publishes them. It logs nothing per request, except an info line for each
allowlisted registration. What you can see today:

- **The effort asked now.** Ask for a challenge as a client would, for a name of 5 or more
  letters, with any valid `did:jig`:

  ```bash
  curl -s "https://<nameserver>/v1/challenge?action=register&did=<did>&name=<longname>@<suffix>"
  ```

  `pow.effort` is `max(min_effort, suggested)`, times your own address's penalties. Above
  `min_effort` means the controller has raised it: the queue was full in a recent window.
  It costs one challenge, which expires in 60 s, and one of your 60 challenges a minute.
  Against a self-signed certificate, curl needs `-k`; the number is only a reading, and the
  offer that carries it is signed.
- **Refusals.** Count `503` responses with code `REGISTRATION_BUSY` at your proxy, if you
  have one, or ask users for the `Retry-After` they were given.
- **The suffix's mode.** `GET /v1/suffixes` lists each suffix and whether its registration
  is `open` or `closed`.

### Respond

1. **Usually nothing.** The pool already caps strangers at `strangers_per_hour`, and the
   controller doubles the effort after each window in which the queue filled. A flood buys
   at most the pool's rate, whatever it spends.
2. **Lower the pool** to admit fewer strangers per hour. In the suffix's entry:

   ```toml
   [v0_0_2.nameserver.alias_suffixes.pool]
   strangers_per_hour = 20     # default 60
   burst = 3                   # default 10
   ```

   Each must be at least 1 while the pool is on. Raise them the same way when demand is
   honest and the queue is busy. `enabled = false` turns the pool off and admits every
   stranger whose work verifies: do not do that during a flood.
3. **Raise the price.** `min_effort` (default 2^20) is the floor every stranger pays;
   `max_effort` (default 2^24) caps the controller and the penalties. Boot refuses a
   `max_effort` that does not fit `max_solve_secs` at 5.5 million digests a second, or one
   above 2^28. A higher price slows phones as well as bots, and `jig` refuses an offer it
   cannot solve within its own time cap.
4. **Lower the rate limits** in `[alias_rate_limits]`: `per_ip_per_min` (default 30),
   `challenge_per_ip_per_min` (default 60). They bound one address, not a botnet.
5. **Close the suffix** if none of this is enough ([section 2](#2-close-a-suffix-fast)).
6. **Step back down** once traffic is normal. A raised floor taxes every honest user.

## 2. Close a suffix fast

1. In the suffix's entry, set:

   ```toml
   registration = "closed"
   ```

2. Restart the service.
3. Check `GET /v1/suffixes` shows `"registration": "closed"`.

What a closed suffix does:

- New registrations are refused with `403 REGISTRATION_CLOSED`, at `GET /v1/challenge`
  before any work, and again at `POST /v1/register`.
- Existing names still resolve, renew and rotate.
- The nameserver still takes `registration_allow` entries, at `min_effort`, past the pool,
  and logs each one.
- But `jig` reads `/v1/suffixes` and stops on a closed suffix before it asks for a
  challenge, allowlisted or not. With today's CLI, an allowlisted DID cannot register while
  the suffix is closed.

To reopen, set `registration = "open"` and restart. Consider lowering `strangers_per_hour`
for the first days.

## 3. Squatting complaint

**Signs:** someone says a name that is theirs (a project, a person, a trademark) was
registered by another DID.

What exists today:

- **No removal.** There is no endpoint, command or config that removes or reassigns a
  binding. Decision 5 of the R1 plan (operator removal, signed, logged and with a published
  reason) is a follow-up that is not built yet. Do not edit the alias store by hand: nothing
  would sign or log the change, and clients that pinned the name will refuse the new DID
  anyway.
- **Expiry.** A binding is valid for 90 days, and only its holder can renew it. If the
  holder stops renewing, the name lapses.
- **Stop it happening again.** Add the word to the suffix's `reserved` (or
  `reserved_contains`, `reserved_affixes`), and restart. New registrations of it, and its
  normalized near-misses, are refused. This does not touch the current binding: renew and
  rotate do not check the reserved lists.
- **Hand it over later.** Add a `registration_allow` entry for the complainant's DID and
  the exact alias. If the name lapses, the nameserver lets that DID register it, even while
  it is reserved. Until then, it gets `409 ALIAS_TAKEN` like anyone else. (On a closed
  suffix, today's `jig` will not try: see [section 2](#2-close-a-suffix-fast).)

Record what you were told and what you did. Then:

1. **(not yet implemented)** Signed, logged operator removal (decision 5).
2. **(not yet implemented)** A tribunal ruling on the dispute
   ([JEP-0010](../../repos/jig-spec/jep/jep-0010-reports-tribunals-lists.md)).

## 4. Harassment report

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
3. **If an alias impersonates the victim**, check `GET /v1/resolve/<alias>`, and treat it as
   [squatting](#3-squatting-complaint): there is no revocation yet. Ask servers that trust
   you to block the DID locally.
4. **Do not try to connect identities.** If the harasser is anonymous, the protocol has no
   link from that identity to a DID, by design. Do not correlate addresses, timing or
   devices to build one.
5. **(not yet implemented)** Record a case, and in a high-sec ruleset group refer it to the
   group's tribunal. For an encrypted channel, the reporter submits effective proof of the
   reported messages through the victim-key delegation path the spec requires.

## 5. Compromised nameserver

**Signs:** aliases resolving to DIDs their owners did not register, the database or key files
modified outside the service, or a config change you did not make.

A compromised nameserver cannot forge a block: blocks are signed by their senders' DIDs. It
can point an alias at the wrong DID ([OP-08](../../repos/jig-spec/src/threat-register.md)),
issue attestations, and read or change everything in its store.

1. **Contain.** Stop the service or firewall it. Keep copies of the store, the key file, the
   config and the logs before changing anything.
2. **Cut dependent servers loose.** Operators of servers with `[identity] mode =
   "nameserver"` remove your nameserver's `ns_did` from the `authorities` of each suffix
   under `[identity.delegations]` (and your URL from its `nameservers`), or switch to
   `tofu`, and restart. Servers accept only attestations an authority signed (#200), so an
   attestation under the removed key is refused from then on. Clients that list your suffix
   under `[naming.delegations]` need the same change.
3. **Find what changed.** Compare alias bindings in the store against your latest backup.
   List every alias whose DID changed.
4. **Rotate the signing key.** Move the `.jigkey` aside and let the service seal a new one,
   which gives the nameserver a new `ns_did`. Treat every attestation signed by the old key
   as untrusted. Dependent servers and clients accept the new key only once its `ns_did` is
   in their delegation's `authorities`, so tell them the new DID. A box upgraded from an
   older release may still hold a `nameserver.db` whose `ns_identity` table is a raw key
   that signs nothing: delete it, and its copies in old backups.
5. **Restore bindings.** Revert changed aliases from backup. Ask users to renew
   (`jig keys renew`) so attestations are reissued under the new key. Users who rotated
   their DID since the backup must re-register.
6. **Tell people.** Announce the new `ns_did`, the window of compromise and the affected
   aliases through channels your users already trust. Clients that pinned DIDs will have
   flagged changed aliases; tell users to trust those warnings.
7. **Write it up**: timeline, cause, what was exposed, what changed.
8. **(not yet implemented)** In a high-sec ruleset group, open an incident case with the
   group's tribunal, and check your transparency log against the members' copies.

## 6. Rogue or contradicting nameserver

**Signs:** two valid attestations for one alias that name different DIDs over overlapping
windows (equivocation, JEP-0004 rule 15), resolution evidence a client kept under
`~/.jig/evidence/names/` (#227), or attestations that fail against the authority the
suffix's delegation names.

1. **Keep the evidence.** Save the attestations and evidence files exactly as served, with
   timestamps. The nameserver signed each attestation, so anyone can check them without
   trusting you.
2. **Cut it off where lookups happen.** Remove or replace that suffix's delegation in
   `[identity.delegations]` (jig-server) or `[naming.delegations]` (`cli.toml`).
   - jig-server refuses a suffix with no entry. The exception is `jig`: without an entry the
     server falls back to its built-in `@jig` delegation, once a build ships the project's
     authority. A build without it ships none, so `@jig` names fail closed.
   - The CLI falls back when `cli.toml` has no entry: to the suffix's DNS-rooted delegation
     for a multi-label suffix, and to the built-in `@jig` delegation for `jig`. So deleting
     an entry can land on the same nameserver again.
   - To refuse every name under a suffix, with no fallback on either side, **refuse it
     rather than delete it**: drop its delegation and list it in `[identity]
     refused_suffixes` (jig-server) or `[naming] refused_suffixes` (`cli.toml`), e.g.
     `refused_suffixes = ["example.org"]`. Matching is exact and ignores case. A refused
     suffix is checked before every delegation source, and a suffix that is both delegated
     and refused is a config error.

   No nameserver can defederate another: each server and client decides whose attestations
   it accepts.
3. **Tell your peers** what you saw and what you changed. They decide for themselves.
4. **(not yet implemented)** Shared lists and tribunal outcomes: the draft
   [JEP-0010](../../repos/jig-spec/jep/jep-0010-reports-tribunals-lists.md).
