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
   | R3 | `{domain, did, server, nonce, issued_at}` | `jig-erase-v1` | `nonce` (16 fresh bytes), and `issued_at` within `S`'s request window (`[custody] request_window_secs`); `S` acts once and keeps the request's digest in the tombstone (rule 28) |

9. `S` MUST verify the signature, that `did` is `D`, and that `server` is its own DID. Otherwise
   it answers `400 BAD_REQUEST` or `400 WRONG_SERVER`.
10. Each request passes `S`'s admission for `D` as any other request does. A DID `S` has banned
    MAY still send R3.

## Routes

11. Every route takes the signed object as `{request_b64}`:

    | Request | Route | Answer |
    | --- | --- | --- |
    | R1 | `PUT /api/v1/reach/{did}` (existing) | `200 {stored, seq}` |
    | R2 | `PUT /api/v1/local-adds/{did}` | `200 {allow, seq}` |
    | R3 | `POST /api/v1/erase/{did}` | `200` with a receipt signed by `S` (rule 30); `409 STILL_A_MEMBER`, `409 STILL_AN_OWNER` (rule 26); `410 ERASED` for a repeat |

## R1: end custody

12. R1 is JEP-0005 rule 21a's withdrawal. A client MUST offer it as an explicit command. A client
    that stops using `S` MUST NOT publish it on its own.
13. Effects:

    | Party | Effect |
    | --- | --- |
    | Member's devices | The record kept on every other server and nameserver should drop `S` too. The client publishes the same higher-`seq` record to each, best effort. Packages already released stay usable (rule 31). Local stock at `S` is kept: local adds continue. |
    | This server | Keeps the record as a withdrawal. Answers `404 NO_CUSTODY` to custody requests from then on. The check runs inside the release's transaction, so a request racing the withdrawal releases nothing. `GET /api/v1/reach/{did}` answers `404 NO_RECORD`. Stock, memberships and data are untouched. |
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
20. **Undo:** a `jig-local-adds-v1` with `allow = true` at a higher `seq`. Uploads are accepted
    again.

## R3: erase and leave

21. R3 asks `S` to delete what it holds about `D`, keep only the tombstone of rule 28, and stop
    serving `D`. It binds `S` only (rule 34).
22. **What R3 does at this server.** "Deleted" means removed from `S`'s live store. Deletion
    from backups follows the operator's retention.

    | Data at `S` | Under R3 |
    | --- | --- |
    | Stock (ordinary and last-resort packages) | Deleted. Uploads refused afterwards (`410 ERASED`). |
    | Reachability record | Envelope deleted; its `seq` kept in the tombstone. |
    | `jig-local-adds-v1` marker | Deleted; its `seq` kept in the tombstone. |
    | Memberships | None remain: rule 26 requires `D` to have left first. |
    | Subscription and catch-up cursors, delivery state | Deleted. |
    | Admission proofs, rate-limit and reputation inputs about `D` held only locally | Deleted. A later request from `D` starts as a stranger's. |
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
    | Member's devices | Before sending R3, the client leaves every affected channel (rule 26). After `S`'s receipt, it deletes, per device: its MLS state for channels on `S`; the private init keys of every key package it stocked at `S` (rule 31); its pins for `S`. It stops publishing to `S`. It keeps `S`'s signed receipt as evidence. |
    | This server | Applies rule 22 and keeps the tombstone (rule 28). Refuses uploads, records and writes from `D` with `410 ERASED`. Serves nothing about `D` except what rules 27–29 keep. |
    | Other members of affected channels | They saw `D` leave: a `member-remove` naming `D`, then a commit removing `D`'s leaf (rule 26). They keep their history, including `D`'s messages. |
    | Other servers | `S` sends nothing. The client SHOULD publish a higher-`seq` reachability record without `S` to every other server and nameserver it uses (R1 everywhere), and MAY send R3 to them separately. Sequencers of federated channels saw `D`'s self-leave (rule 26). Copies other servers hold are theirs: rule 34. |

24. R3 has the effects of R1 and R2 at `S`. They are recorded as R3's effects, not as separate
    requests.
25. Adders see:
    - `410 ERASED` from `S` for a custody request or a local package;
    - `403 MEMBER_DECLINED` for a `member-add` of `D` to a channel `S` sequences.

    A client treats both as definite.
26. **Leaving first.** `S` MUST refuse R3 with:
    - `409 STILL_A_MEMBER`, listing the channels, while `D` holds a membership in a channel `S`
      sequences or carries;
    - `409 STILL_AN_OWNER`, listing them, while `D` owns a channel `S` sequences that is not
      archived.

    Whoever can sign R3 holds `D`'s key and so can sign the leaves. The client therefore:
    1. archives each channel `D` owns. No transfer of ownership is defined; JEP-0005 rule 11a
       moves a channel's sequencer, not its owner;
    2. sends a self-leave (`member-remove` naming `D`, no commit) to each channel, through `S`;
       for a channel another server sequences, `S` relays it to that sequencer;
    3. then sends R3.

    The MLS removal is committed by a remaining member, as for any self-leave (Encryption
    chapter, Leaving): the next remaining member online commits `D`'s leaf out. On a federated channel that member commits through its own server to the channel's
    sequencer. Remaining members see the self-leave, then that commit. Until the commit lands,
    `D` holds keys for the current epoch only, and the sequencer delivers nothing to `D`.
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
    - the digests of R3 requests it has acted on;
    - the time of erasure;
    - any revocation it holds for `D`.

    It keeps nothing else. A reachability record or marker at or below the tombstone's `seq` is
    refused, so an older record cannot restore custody. A repeat of R3 answers `410 ERASED`.
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
30. **Receipt.** `S` answers R3 with a `COSE_Sign1` by its server DID, domain
    `jig-erase-receipt-v1`, over `{domain, server, did, request_digest, erased_at}`.
    - The receipt states only that `S` acted on the request.
    - It is evidence for `D`. It does not prove what other parties hold.

## Released packages, lifetimes and rotation

31. No request recalls a key package `S` already released. A released package stays usable, by
    whoever holds it, until the first of:
    - its leaf lifetime ends: jig's packages carry openmls's default of 84 days plus a one-hour
      margin, unless the client sets a shorter one, and an adder's client refuses an expired
      package;
    - `D` deletes the package's private init key: a Welcome to that package can then not be
      opened, so an add made with it gives the adder a group `D` is not in.

    A last-resort package is reused by everyone who receives it until one of those happens.
32. **Rotation:**
    - On R1, the client does not rotate. Local adds still use the stock. The release log
      (`GET /api/v1/custody/{did}/releases`) shows the member which packages left and to whom.
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
    | R3 (alone or with others) | no (`ERASED`) | no (`MEMBER_DECLINED`) | deleted | refused (`ERASED`) | deleted per rule 22 | none for the data; rule 36 to come back |

36. **Coming back after R3.** The data is gone and is not restored. `D` may use `S` again by
    sending a `jig-local-adds-v1` with `allow = true` and a reachability record that lists `S`,
    each at a `seq` above the tombstone's. `S` then treats `D` as a new DID: admission, stock
    and memberships start empty. The tombstone stays.
37. Requests at different servers are independent. R1 at every server ends all custody, but
    the member's own server keeps adding it locally unless R2 is sent there too.

# Security Considerations (Zero-Trust)

- **Forgery.** Every request is signed by `D` and names `S`. Nobody but `D` can end, or restore,
  `D`'s custody or local adds.
- **Replay and rollback.**
  - R1 and R2 are monotonic by `seq`, and the tombstone keeps the `seq` past R3.
  - R3 is one-shot by `nonce`, `issued_at` and the kept digest.
- **Races.** A custody release re-checks the record inside its transaction (JEP-0005 rule 21a).
  R2's checks run in the same transaction as the release or the ingest of the `member-add`.
- **Residual: released packages** stay usable until rule 31's bound. A hostile holder can add
  `D` to a group `D` cannot open once `D` has deleted the key. That is harmless to `D` but
  misleads the group about who is in it.
- **Residual: other servers** keep what they hold (rule 34). A server can ignore R3. The receipt
  makes its answer provable, not its compliance.
- **Residual: other members** keep their history, including `D`'s messages (rule 27).
- **Metadata.** The tombstone, the logs of rule 29 and the release rows of rule 22 that are kept
  still record that `D` existed at `S`.

# Backwards Compatibility

- v0.x makes no compatibility guarantee.
- R1 exists with #440.
- R2 and R3 are new routes; a server without them answers `404`, and a client treats that as
  "not supported" and says so.

# Reference Implementation

None yet. The sizing below is for DJ to decide what ships in alpha.7.

| Request | Work | Size |
| --- | --- | --- |
| R1 | Done in #440 (server). Remaining: an explicit client command that publishes the withdrawal to every server and nameserver the member uses, and its test. | S: about 100 lines with tests |
| R2 | `jig-local-adds-v1` with vectors; a marker table; `PUT /api/v1/local-adds/{did}`; refusals on the key-package route, on the custody route for channels sequenced here, and on `member-add` ingest; the purge and upload refusal under R1 + R2; client per-server state, the explicit command and the CLI's handling of the new codes; integration tests. | M: about 500–700 lines with tests |
| R3 | `jig-erase-v1` and `jig-erase-receipt-v1` with vectors; preconditions (`STILL_A_MEMBER`, `STILL_AN_OWNER`); deletion across about ten tables; the tombstone and its checks on every upload route; the client's leave-archive-erase sequence and its local key and state deletion; per-server package references; integration tests across two servers, including a federated channel. JEP-0009 salt deletion waits for those logs to exist. | L: about 1,200–1,600 lines with tests |

# Test Vectors

To be added with the implementation: one `jig-local-adds-v1` and one `jig-erase-v1` under
fixed test keys, as deterministic payload and `COSE_Sign1`, in hex, in `vectors/0017/`.

# Rejected Alternatives

- **One withdrawal that means everything.** It would turn a narrow request into a broad one the
  member did not make.
- **Inferring R2 or R3 from a client going quiet.** It is not a request; devices go offline.
- **Purging stock on R1.** The server's own channels still use it (#449).
- **Server-authored `member-remove` under R3.** A block must be signed by its author. Requiring
  the self-leave first keeps every membership change signed by the member.
- **Deleting `D`'s blocks from shared channels.** It breaks other members' history, the
  sequencer's chain and the channel's epoch history.

# Copyright

This document is licensed under CC-BY-4.0.
