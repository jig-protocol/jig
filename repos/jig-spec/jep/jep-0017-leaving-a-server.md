+++
jep = 0017
title = "Leaving a Server: Ending Custody, Ending Local Adds, Erasure"
status = "Draft"
type = "Standards Track"
category = "Federation"
authors = ["DJ <dev@jig.onl>"]
created = "2026-11-21"
requires = ["0002", "0004", "0005", "0009", "0012"]
replaces = []
superseded_by = []
discussions_to = "https://github.com/jig-protocol/jig/issues/449"
+++

# Abstract

A member can make three requests of a server it has used. Each one is separate, explicit and
signed by the member:

- **R1, end custody:** stop releasing the member's key packages to other servers' members.
- **R2, end local adds:** stop adding the member to channels this server sequences.
- **R3, erase and leave:** remove the member's data from this server and stop serving the member.

No request is inferred from another. This JEP says, for each request and for each combination:

- what the member's devices, this server, the other members of affected channels and other
  servers do;
- who signs, under which domain, and how replay is stopped;
- what an adder sees;
- whether, and how, the request is undone.

It settles what cannot be recalled: key packages already released, logs that are append-only,
and copies held by other servers.

# Motivation

JEP-0005 rule 21a (added with the custody slice, #440) lets a member withdraw a custodian by
publishing a reachability record without it. That ends one thing only: releases to other
servers' requesters. A member that stops using a server may want more:

- that the server stop adding it to the server's own channels;
- that the server keep as little about it as it can.

Inferring the larger requests from the smaller one would surprise members who wanted only the
smaller one. So would inferring them from a client simply going quiet. Each request is
therefore separate, signed and explicit.

Goals:

- every effect has a defined owner and a defined error;
- the effects survive replay, rollback and a member's other devices;
- the effects are honest about their limits.

Non-goals:

- binding other servers;
- recalling data other parties already hold;
- multi-device key packages (lane I);
- revocation (a later JEP, per JEP-0012).

This JEP describes protocol behaviour. It makes no claim about any legal regime.

# Specification

## Terms

1. **Member:** the DID `D` making the request.
2. **This server:** the server `S` the request is addressed to, named by its server DID.
3. **Affected channel:** a channel `D` is a member of, or owns, that `S` sequences or carries.
4. **Adder:** a member of a channel who tries to add `D` to it.
5. **Stock:** `D`'s unconsumed ordinary key packages and its last-resort package held by `S`
   (`/api/v1/mls/key-packages`).
6. **Custody:** `S` releasing `D`'s stock to other servers' requesters (JEP-0005 rules 21–21b).
7. **Local adds:** `S` handing out `D`'s stock for channels `S` sequences, and `S` accepting a
   `member-add` of `D` to a channel `S` sequences.

## Signed objects

8. Every object below is a `COSE_Sign1` by `D` over deterministic CBOR, as JEP-0004 rule 0
   states. Each names `S` by its server DID, so it cannot be replayed to another server.

   | Request | Object | Domain | Replay protection |
   | --- | --- | --- | --- |
   | R1 | reachability record without `S` (JEP-0004 rule 21) | `jig-reach-v1` | `seq`: `S` keeps only a higher `seq` (JEP-0005 rule 21a) |
   | R2 | `{domain, did, server, allow: bool, seq}` | `jig-local-adds-v1` | `seq`: `S` keeps only a higher `seq`; `allow = true` undoes R2 |
   | R3 | `{domain, did, server, nonce, issued_at}` | `jig-erase-v1` | `nonce` (16 fresh bytes), and `issued_at` within `S`'s request window (`[custody] request_window_secs`); `S` keeps the request's digest, pending and then in the tombstone (rule 28), and acts on it at most once |
   | Cancel R3 | `{domain, did, server, request_digest, issued_at}` | `jig-erase-cancel-v1` | names one pending R3 by its digest; `issued_at` within the request window; a cancelled digest stays cancelled, so the R3 cannot be resent to restart it |

9. `S` MUST verify the signature, that `did` is `D`, and that `server` is its own DID. Otherwise
   it answers `400 BAD_REQUEST` or `400 WRONG_SERVER`.
10. Each request passes `S`'s admission for `D` as any other request does. A DID `S` has banned
    MAY still send R3; the ban outlives it (rule 28).

## Routes

11. Every route takes the signed object as `{request_b64}`:

    | Request | Route | Answer |
    | --- | --- | --- |
    | R1 | `PUT /api/v1/reach/{did}` (existing) | `200 {stored, seq}` |
    | R2 | `PUT /api/v1/local-adds/{did}` | `200 {allow, seq}` |
    | R3 | `POST /api/v1/erase/{did}` | `202 ERASE_PENDING {request_digest, acts_at}` (rule 21a); `409 STILL_A_MEMBER`, `409 STILL_AN_OWNER` (rule 26); `409 ERASE_PENDING` while another R3 is pending; `410 ERASED` once `S` has acted |
    | Cancel R3 | `DELETE /api/v1/erase/{did}` with a `jig-erase-cancel-v1` | `200 {cancelled: request_digest}`; `404` if nothing is pending; `410 ERASED` once `S` has acted |
    | R3 receipt | `GET /api/v1/erase/{did}/receipt`, a signed read by `D` | `200` with the receipt once `S` has acted, re-signed from the tombstone; `202` with the pending state before; `404` to anyone else |
    | Stock state | `GET /api/v1/mls/key-packages/{did}/stock` (existing), no signed object | `200 {available, last_resort, stocked}`; `stocked` is new and is `false` once R1 and R2 are both in force here (rule 19) |

## R1: end custody

12. R1 is JEP-0005 rule 21a's withdrawal. A client MUST offer it as an explicit command. A client
    that stops using `S` MUST NOT publish it on its own.
13. Effects:

    | Party | Effect |
    | --- | --- |
    | Member's devices | The record kept on every other server and nameserver should drop `S` too. The client publishes the same higher-`seq` record to each, best effort. Packages already released stay usable (rule 31). Local stock at `S` is kept: local adds continue. Each other device of `D` learns of the withdrawal from the record `S` serves `D` (below), MUST NOT list `S` again on its own, and runs rule 32's rotation for the keys it holds. |
    | This server | Keeps the record as a withdrawal. Answers `404 NO_CUSTODY` to custody requests from then on. The check runs inside the release's transaction, so a request racing the withdrawal releases nothing. `GET /api/v1/reach/{did}` answers `404 NO_RECORD` to anyone but `D`, and serves `D`'s own signed read the withdrawal record, so `D`'s devices can tell a withdrawal from no record. Stock, memberships and data are untouched. |
    | Other members of affected channels | Nothing changes. They can still add `D` through `S` (local adds). |
    | Other servers | Custodians, nameservers and sequencers are not told by `S`. A server that still keeps an older record that names `S` sends adders to `S`, which answers `NO_CUSTODY`, so the adder's client tries the record's next entry. |

14. Adders on other servers see `NO_CUSTODY` from `S`. If no other custodian releases a package,
    the add fails with nothing committed (JEP-0005 rule 21a).
15. **Undo:** publish a record that lists `S` again, at a higher `seq`.

## R2: end local adds

16. While `D`'s latest `jig-local-adds-v1` at `S` says `allow = false`, `S` MUST:
    - answer `GET /api/v1/mls/key-packages/{did}` with `403 LOCAL_ADDS_ENDED`;
    - refuse a custody request naming a channel `S` sequences, with `403 LOCAL_ADDS_ENDED`;
    - refuse a `member-add` of `D` to a channel `S` sequences, wherever the package came from,
      with `403 MEMBER_DECLINED`. The `member-add` block is not stored.

    `D` may still join a channel `S` sequences by its own act: an external commit, or a join
    `D` signs. R2 governs being added by others.
17. Effects:

    | Party | Effect |
    | --- | --- |
    | Member's devices | The client records, per server, that local adds are ended. It keeps the stock topped up only if custody is still in force (rule 19). Existing memberships are untouched; the member leaves channels separately. |
    | This server | Keeps the newest marker per `D` (by `seq`), with the request. Applies rule 16. Custody for channels other servers sequence is unchanged. |
    | Other members of affected channels | Members of channels `S` sequences cannot add `D`. They see `LOCAL_ADDS_ENDED`, or `MEMBER_DECLINED` if they fetched a package elsewhere. Existing memberships continue. |
    | Other servers | Not told. A channel another server sequences is outside R2 at `S`: the member sends R2 to that server if it wants the same there. |

18. A client MUST treat `LOCAL_ADDS_ENDED` and `MEMBER_DECLINED` as definite refusals. It MUST NOT
    fall back to other custodians for the same channel, because the sequencer would refuse the
    `member-add` anyway.
19. **Re-stocking:**
    - R2 alone does not purge the stock, because custody may still use it. Re-stocking does not
      undo R2: the marker, not the stock, decides.
    - When R1 and R2 are both in force, the stock has no use. `S` MUST delete it and MUST refuse
      uploads (`POST /api/v1/mls/key-packages`) with `403 NOT_STOCKED_HERE`.
    - This server-side refusal is what holds when one of `D`'s devices sends R2 while another
      keeps publishing. A client SHOULD also keep the state per server, to stop trying.
    - `S` reports this state as `stocked: false` on the stock route (rule 11). The field is
      additive: a client that does not know it ignores it, and a server without it is read as
      `stocked: true`. A client MUST delete the private keys of its stock at `S` only on
      `stocked: false`, never on an empty stock (`available = 0`): `S` answers a repeat of a
      request it already served with the same released package, so that package's key is
      still needed.
20. **Undo:** a `jig-local-adds-v1` with `allow = true` at a higher `seq`. Uploads are accepted
    again.

## R3: erase and leave

21. R3 asks `S` to delete what it holds about `D`, keep only the tombstone of rule 28, and stop
    serving `D`. It binds `S` only (rule 34).
21a. **Delay and cancel.** R3 is irreversible, and every one of `D`'s devices holds a key that
     can sign it (Encryption chapter: a leaf's signature key is the DID's Ed25519 key). So `S`
     does not act at once:
     - `S` records the request as pending and answers `202 ERASE_PENDING` with `acts_at`, which
       is the request's arrival plus `erase_delay_secs`. The reference default is 72 hours, to
       be measured. An operator MAY set it longer, never shorter than 24 hours.
     - While it is pending, every answer `S` gives to a request authenticated as `D`, signed
       read or signed write, HTTP or the WebSocket welcome, carries
       `erase_pending: {request_digest, acts_at, joined}`, where `joined` lists the channels
       `D` has joined since the request. So each of `D`'s devices learns of it the next time it
       talks to `S`.
     - `D` cancels with a signed `jig-erase-cancel-v1` naming the request's digest, at any time
       before `acts_at`. Nothing has changed at `S`, so nothing needs undoing.
     - Until `S` acts, `D`'s data, stock, custody and local adds are as they were. A member that
       wants packages to stop leaving at once sends R1 and R2 as well; they take effect
       immediately and are separate requests.
     - While R3 is pending, `S` MUST refuse a `member-add` of `D` by anyone else with
       `403 MEMBER_DECLINED`: in channels it sequences, and in membership blocks it relays for
       channels it carries. Otherwise another member could re-add `D` before every `acts_at`
       and block the erasure for good. A cancel lifts the refusal. `D`'s own blocks, its
       self-leaves above all, pass as before.
     - A sequencer elsewhere can still take an add of `D` directly, for a channel `S` carries.
       `S` lists every channel `D` has joined since the request in the `erase_pending` field.
       `D`'s client self-leaves each before `acts_at`, through `S`. The re-check counts
       memberships at `acts_at` only, so a membership that was added and left during the delay
       does not abort the erasure. `D` may also send R2 to that sequencer.
     - At `acts_at`, `S` checks rule 26's preconditions again. If `D` joined or came to own a
       channel during the delay, `S` does not act: the request ends as
       `aborted: STILL_A_MEMBER` or `aborted: STILL_AN_OWNER`, listing the channels, and `D`'s
       next authenticated answer says so. `D` leaves and sends a new R3, which starts a new
       delay. Otherwise `S` acts on it as this section describes, and issues the receipt
       (rule 30).
22. **What R3 does at this server.** "Deleted" means removed from `S`'s live store. Deletion
    from backups follows the operator's retention.

    | Data at `S` | Under R3 |
    | --- | --- |
    | Stock (ordinary and last-resort packages) | Deleted. Uploads refused afterwards (`410 ERASED`). |
    | Reachability record | Envelope deleted; its `seq` kept in the tombstone. |
    | `jig-local-adds-v1` marker | Deleted; its `seq` kept in the tombstone. |
    | Memberships | None remain: rule 26 requires `D` to have left first. |
    | Subscription and catch-up cursors, delivery state | Deleted. |
    | Admission proofs, rate-limit and reputation inputs about `D` held only locally | Deleted, except `S`'s own moderation decisions, which the tombstone keeps (rule 28). |
    | TOFU keys, name evidence and attestations `S` holds for `D` | Deleted. |
    | Bridge state keyed by `D` | Deleted. |
    | Release log, rows where `D` is the DID released | Deleted. They exist for `D`'s audit only. |
    | Release log, rows where `D` is the requester | Kept. They are another DID's record of who took its packages, and R3 cannot erase another DID's record. The row holds `D`'s signed request, and stays as long as that DID's log does. |
    | Blocks `D` authored in channels that still have other members | Kept: rule 27. |
    | Blocks in a channel `D` was the only member of | Deleted. |
    | Ingest records, manifest log, contract records | Kept: rule 29. |
    | JEP-0009 log leaves about `D` | Kept. `S` deletes the salts it holds for `D`'s leaves: rule 29. |

23. Effects on each party:

    | Party | Effect |
    | --- | --- |
    | Member's devices | Before sending R3, the client leaves every affected channel (rule 26). While R3 is pending, every device that talks to `S` shows the pending state and offers to cancel (rule 21a). After `S`'s receipt, it deletes, per device: its MLS state for channels on `S`; the private init keys of every key package it stocked at `S` (rule 31); its pins for `S`. It stops publishing to `S`. It keeps `S`'s signed receipt as evidence. A device that was offline during R3 and later gets `410 ERASED` from `S` fetches the receipt (rule 11), checks it, and then runs the same deletion. |
    | This server | Applies rule 22 and keeps the tombstone (rule 28). Refuses `D`'s own signed uploads, records and writes with `410 ERASED`. Answers anyone else as for a DID it never knew (rule 25). Serves nothing about `D` except what rules 27–29 keep. |
    | Other members of affected channels | They saw `D` leave: a `member-remove` naming `D`, then a commit removing `D`'s leaf (rule 26). They keep their history, including `D`'s messages. |
    | Other servers | `S` sends nothing. The client SHOULD publish a higher-`seq` reachability record without `S` to every other server and nameserver it uses (R1 everywhere), and MAY send R3 to them separately. Sequencers of federated channels saw `D`'s self-leave (rule 26). Copies other servers hold are theirs: rule 34. |

24. R3 has the effects of R1 and R2 at `S`. They are recorded as R3's effects, not as separate
    requests.
25. To anyone but `D`, `S` answers as it would for a DID it never knew, so the answer does not
    reveal that `D` used `S` and left:
    - `404 NO_CUSTODY` to a custody request;
    - `404 NO_KEY_PACKAGE` for a local package;
    - `404 NO_RECORD` for the reachability record.

    A `member-add` of `D` to a channel `S` sequences is refused with `403 MEMBER_DECLINED`, as
    under R2. `S` sends `410 ERASED` only in answer to a request `D` signed.
26. **Leaving first.** These preconditions are checked when R3 arrives, and again when `S` is
    about to act (rule 21a). `S` MUST refuse R3 with:
    - `409 STILL_A_MEMBER`, listing the channels, while `D` holds a membership in a channel `S`
      sequences or carries;
    - `409 STILL_AN_OWNER`, listing them, while `D` owns a channel `S` sequences that is not
      archived.

    Whoever can sign R3 holds `D`'s key and so can sign the leaves. The client therefore:
    1. archives each channel `D` owns. No transfer of ownership is defined; JEP-0005 rule 11a
       moves a channel's sequencer, not its owner;
    2. sends a self-leave (`member-remove` naming `D`, no commit) to each channel, through `S`.
       For a channel another server sequences, `S` relays it to that sequencer; a follower
       relays a self-leave under any grant (JEP-0005 rule 7a);
    3. then sends R3.

    A membership ends when its self-leave lands, before any commit (Encryption chapter,
    Leaving). So `STILL_A_MEMBER` clears at the self-leave block. R3 never waits for a remaining
    member's commit. A channel `S` no longer carries, because its contract ended, is not an
    affected channel of `S`: `D` leaves it at its sequencer directly.

    The MLS removal is committed by a remaining member, as for any self-leave (Encryption
    chapter, Leaving): the next remaining member online commits `D`'s leaf out. On a federated
    channel that member commits through its own server to the channel's sequencer. Remaining
    members see the self-leave, then that commit. Until the commit lands, `D` holds keys for the
    current epoch only, and the sequencer delivers nothing to `D`.
27. **Stored messages.** A block `D` wrote in a channel that still has other members is part of
    their history:
    - its CID is in the sequencer's signed chain;
    - a commit `D` made is part of the channel's epoch history, which later joiners and catch-up
      replay.

    R3 MUST NOT delete or alter those blocks. On an encrypted channel `S` holds only ciphertext.
    Blocks of a channel `D` was the only member of are nobody else's history; R3 deletes them
    (rule 22).
28. **Tombstone.** For each erased DID, `S` MUST keep exactly:
    - `did`;
    - the highest reachability `seq` and the highest `jig-local-adds-v1` `seq` it has seen;
    - the digests of R3 requests it has acted on, and of those cancelled;
    - the time of erasure;
    - any revocation it holds for `D`;
    - `S`'s own moderation decisions about `D`: a ban, if `D` was banned, and a standing floor,
      which is `D`'s standing at `S` at the time of erasure under each ruleset `S` applies.

    It keeps nothing else. In particular, it keeps no evidence behind those decisions and no
    data from other servers. A reachability record or marker at or below the tombstone's `seq`
    is refused, so an older record cannot restore custody. A repeat of R3 answers `410 ERASED`.
29. **Append-only logs.** A log whose entries are signed and chained cannot drop an entry
    without breaking its proofs:
    - **Ingest records and the manifest log** (JEP-0002 rule 12): kept. They hold block CIDs and
      DIDs, not message content.
    - **Contract records** (JEP-0005): kept. They name servers.
    - **JEP-0009 transparency logs:** leaves about a user carry `subject_commit`, a salted
      commitment to the DID (JEP-0009 rule 32). `S` deletes every salt it holds for `D`. The
      leaves stay, and without the salt they cannot be linked to `D`. Salts already handed to `D`
      or to the group's members under the data contract cannot be recalled. `S` MAY ask the
      group's members to delete theirs.
    - **Release log:** rule 22.
30. **Receipt.** When `S` acts on R3, not when the request arrives, it issues a `COSE_Sign1` by
    its server DID, domain `jig-erase-receipt-v1`, over
    `{domain, server, did, request_digest, erased_at}`. `D` fetches it with the receipt route
    (rule 11).
    - The receipt states only that `S` acted on the request.
    - It is evidence for `D`. It does not prove what other parties hold.

## Released packages, lifetimes and rotation

31. No request recalls a key package `S` already released. A released package stays usable, by
    whoever holds it, until the first of:
    - its leaf lifetime ends: jig's packages carry openmls's default of 84 days plus a one-hour
      margin, unless the client sets a shorter one. An adder's client MUST refuse an expired
      package, and a sequencer MUST refuse a commit that adds one. Both follow from MLS's leaf
      validation (RFC 9420 section 7.3, openmls `valn0106`), which jig's adder and sequencer
      run on every Add;
    - `D` deletes the package's private init key: a Welcome to that package can then not be
      opened, so an add made with it gives the adder a group `D` is not in.

    A last-resort package is reused by everyone who receives it until one of those happens.
32. **Rotation:**
    - On R1, the client carries out R1's own intent and keeps local adds working:
      - it publishes a fresh last-resort package at `S` and deletes the old one's private init
        key, so the last-resort package other servers' requesters received is dead. `S` MUST
        let `D`'s new last-resort package replace the one it holds, and MUST NOT release or
        accept again the one it replaced;
      - it deletes the private init keys of the ordinary packages the release log
        (`GET /api/v1/custody/{did}/releases`) shows went to other servers' requesters. Each
        entry names the released package's reference (`reference_hex`), and the log pages with
        `?offset=`, so the client reads every release still within a package's lifetime. If a
        package was used and the device has processed the Welcome, its key is already gone. If
        the device has not yet processed it, the add is lost on that device: an add committed
        before R1 to a device that was offline gives the adder a group `D` is not in.
      - Each release-log entry carries `kind`: `custody` for a release to a signed custody
        request, `local` for a take by `S`'s own key-package route. The client deletes keys for
        `custody` entries only. An entry without `kind`, from a server before this rule, is
        `local` when its `channel_id` is empty and it carries no signed request (as #440 logs a
        local take), and `custody` otherwise.

      The rest of the stock stays for local adds.
    - On R2 together with R1, and on R3, the client MUST delete the private init keys of every
      package it stocked at `S`, the last-resort package included. It publishes a fresh
      last-resort package only to servers where it still keeps a stock.
    - To delete exactly those keys, a client MUST record, per server, the reference of each
      package it stocks there.
33. A client SHOULD use a leaf lifetime shorter than the default, so the bound in rule 31 is
    tighter. The value is a reference default, to be measured; this JEP does not fix it.

## Combinations

34. **Other servers.** A request binds only the server it names. `S` MUST NOT claim, in a receipt
    or anywhere else, that another server has acted. A member that wants the same elsewhere
    sends the request to each server.
35. **Combinations** at one server:

    | In force | Custody | Local adds | Stock | Uploads | Data | Undo |
    | --- | --- | --- | --- | --- | --- | --- |
    | none | yes | yes | kept | accepted | kept | n/a |
    | R1 | no (`NO_CUSTODY`) | yes | kept | accepted | kept | newer record listing `S` |
    | R2 | yes, for channels other servers sequence | no (`LOCAL_ADDS_ENDED`, `MEMBER_DECLINED`) | kept | accepted | kept | marker `allow = true` |
    | R1 + R2 | no | no | deleted | refused (`NOT_STOCKED_HERE`) | kept | undo either; uploads resume when either is undone |
    | R3 pending | as before R3 | packages as before R3; `member-add` by others refused (`MEMBER_DECLINED`) | as before R3 | as before R3 | kept | cancel (`jig-erase-cancel-v1`) before `acts_at` |
    | R3 (alone or with others) | no (`NO_CUSTODY` to others) | no (`NO_KEY_PACKAGE` to others; `MEMBER_DECLINED` on `member-add`) | deleted | refused (`ERASED`, to `D`) | deleted per rule 22 | none for the data; rule 36 to come back |

36. **Coming back after R3.** The data is gone and is not restored. `D` may use `S` again by
    sending a `jig-local-adds-v1` with `allow = true` and a reachability record that lists `S`,
    each at a `seq` above the tombstone's.
    - Stock, memberships and admission start empty.
    - `S`'s moderation does not: a ban in the tombstone still applies, and `D`'s standing under
      each ruleset starts from the lower of a stranger's standing and the tombstone's floor.
    - The tombstone stays.
37. Requests at different servers are independent. R1 at every server ends all custody, but
    the member's own server keeps adding it locally unless R2 is sent there too.

# Security Considerations (Zero-Trust)

- **Forgery.** Every request is signed by `D` and names `S`. Nobody but `D` can end, or restore,
  `D`'s custody or local adds.
- **Replay and rollback.**
  - R1 and R2 are monotonic by `seq`, and the tombstone keeps the `seq` past R3.
  - R3 is one-shot by `nonce`, `issued_at` and the kept digest. A cancel names one digest,
    and a cancelled digest cannot be resent.
- **Races.** A custody release re-checks the record inside its transaction (JEP-0005 rule 21a).
  R2's checks run in the same transaction as the release or the ingest of the `member-add`.
- **A single signature.** Any one of `D`'s devices, or anyone holding its key, can sign R3.
  The delay of rule 21a, the pending state on every answer to `D`, and the cancel bound the
  damage of a lost device or a mistake to the delay. They do not help when every device is
  lost, or the key is held by someone else for the whole delay. The delay protects `S`'s data
  only. The steps rule 26 requires first, the self-leaves and the archives, take effect as
  soon as they land. Any holder of `D`'s key can take those steps without this JEP, so this
  adds no exposure.
- **Moderation is not reset by erasure.** R3 followed by a return does not clear a ban or a
  low standing at `S` (rules 28 and 36). Deleting the JEP-0009 salts (rule 29) still makes
  `D`'s earlier leaves unlinkable, so the tombstone's ban and floor are `S`'s own record; no
  one else can rebuild a proof from the log.
- **Residual: released packages** stay usable until rule 31's bound. A hostile holder can add
  `D` to a group `D` cannot open once `D` has deleted the key. That is harmless to `D` but
  misleads the group about who is in it.
- **Residual: other servers** keep what they hold (rule 34). A server can ignore R3. The receipt
  makes its answer provable, not its compliance.
- **Residual: other members** keep their history, including `D`'s messages (rule 27).
- **Metadata.** The tombstone, the logs of rule 29 and the release rows of rule 22 that are kept
  still record that `D` existed at `S`. The tombstone also records whether `S` had banned `D`,
  and `D`'s standing at erasure. To anyone but `D`, `S` answers as for an unknown DID (rule 25).

# Backwards Compatibility

- v0.x makes no compatibility guarantee.
- R1 exists with #440.
- R2 and R3 are new routes; a server without them answers `404`, and a client treats that as
  "not supported" and says so.

# Reference Implementation

None yet. The work, by request:

- **R1:** the server side is #440. Still to do: an explicit client command that publishes the
  withdrawal to every server and nameserver the member uses, and the R1 rotation of rule 32.
- **R2:**
  - `jig-local-adds-v1` with vectors, a marker table and `PUT /api/v1/local-adds/{did}`;
  - the refusals on the key-package route, on the custody route for channels sequenced here,
    and on `member-add` ingest;
  - the purge and upload refusal under R1 + R2;
  - client per-server state, the explicit command and the client's handling of the new codes.
- **R3:**
  - `jig-erase-v1`, `jig-erase-cancel-v1` and `jig-erase-receipt-v1` with vectors, and the
    receipt and cancel routes;
  - the pending state: storage, `erase_delay_secs`, the `erase_pending` field on every answer
    to `D`, and a task that acts at `acts_at`;
  - the preconditions (`STILL_A_MEMBER`, `STILL_AN_OWNER`), checked on arrival and again before
    acting;
  - the tombstone's moderation entries, and rule 36's return applying them;
  - deletion across the store, the tombstone and its checks on every upload route, and rule
    25's answers to third parties;
  - the client's leave-archive-erase sequence, its local deletion, offline devices, and
    per-server package references.

  JEP-0009 salt deletion waits for those logs to exist.
- **Tests:** an expired key package is refused by the adder and by the sequencer (rule 31);
  each request across two servers, including a federated channel.

# Test Vectors

To be added with the implementation: one each of `jig-local-adds-v1`, `jig-erase-v1`,
`jig-erase-cancel-v1` and `jig-erase-receipt-v1` under
fixed test keys, as deterministic payload and `COSE_Sign1`, in hex, in `vectors/0017/`.

# Rejected Alternatives

- **One withdrawal that means everything.** It would turn a narrow request into a broad one the
  member did not make.
- **Inferring R2 or R3 from a client going quiet.** It is not a request; devices go offline.
- **Acting on R3 at once.** One signature, from any device, would erase with no way back.
- **Resetting moderation on erasure.** R3 would become a way to clear a ban.
- **Purging stock on R1.** The server's own channels still use it (#449).
- **Server-authored `member-remove` under R3.** A block must be signed by its author. Requiring
  the self-leave first keeps every membership change signed by the member.
- **Deleting `D`'s blocks from shared channels.** It breaks other members' history, the
  sequencer's chain and the channel's epoch history.

# Copyright

This document is licensed under CC-BY-4.0.
