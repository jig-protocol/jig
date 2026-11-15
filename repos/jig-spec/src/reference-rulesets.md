# Reference Rulesets

> **Draft (R2.1).** These are four reference rulesets, given as data before any code. They use
> JEP-0009's verifiable-standing rules 35–52, which are still under review in #418. Every
> number here is a starting point, to be tuned against R1's pool metrics. None is final until
> DJ approves it.

A ruleset document (JEP-0009 rule 3) fixes how standing is computed, and recommends what a server
does with it. The four reference rulesets cover the security levels the framing names:

| Ruleset | For | In a group | Tribunal | Useful work | Invites | Vouching |
| --- | --- | --- | --- | --- | --- | --- |
| `jig-reference` | a single server, the default | no (`witness_threshold` 0) | no | no | no | no |
| `high-sec` | a ruleset group with seats | yes (3 witnesses) | yes | yes | 1 per 30 epochs | no |
| `community` | a small group of friendly servers | yes (1 witness) | no | no | 3 per 30 epochs | yes |
| `null-sec` | anonymous-first servers | no | no | no | no | no |

Data:

- [`vectors/0009/rulesets/`](https://github.com/jig-protocol/jig/tree/main/repos/jig-spec/jep/vectors/0009/rulesets):
  each ruleset document's payload as JSON. The CBOR encoding, the signature and the CID come
  with the `jig-core` implementation.
- [`vectors/0009/standing-traces.json`](https://github.com/jig-protocol/jig/tree/main/repos/jig-spec/jep/vectors/0009/standing-traces.json):
  70 epochs of `f` under each ruleset, for a fixed set of leaves. It gives every subject's `r`,
  `s`, score, age and established flag after each epoch.
- [`vectors/0009/reference_model.py`](https://github.com/jig-protocol/jig/tree/main/repos/jig-spec/jep/vectors/0009/reference_model.py):
  the exact-integer model of rule 40 that wrote both. The `jig-core` implementation must
  reproduce every value. It then becomes the generator, and the model is removed.

## Shared choices

- **Maths:** `jig-beta-v1` v1 (JEP-0009 rule 40). The score is `(r − s) / (r + s + 2)`, in
  parts per million.
- **Epochs:** one day of epoch time (`epoch_secs` 86 400), closed at a witnessed checkpoint
  (rule 36).
- **Accrual:** at most one unit of positive evidence per epoch (`accrual_per_period`), and
  `good-standing-interval` is worth exactly one unit. Activity beyond one interval per epoch
  buys nothing (rule 17).
- **Authors:** empty. The project's DID signs the reference documents at release. An operator
  who changes anything publishes their own `id` (R2 plan, decision 9).

## Parameters `f` reads

Evidence is in units (one unit is 10⁶ micro-units), scores in parts per million, and decay as a
half-life in epochs, written as its per-epoch fraction in ppm.

| Parameter | `jig-reference` | `high-sec` | `community` | `null-sec` |
| --- | --- | --- | --- | --- |
| `established_ppm` | 300 000 | 500 000 | 200 000 | unreachable (999 999) |
| `min_age_epochs` | 30 | 60 | 14 | 0 |
| `max_idle_epochs` | 14 | 7 | 7 | none |
| `accrual_per_period` | 1 unit | 1 unit | 1 unit | 0 |
| `per_reporter_cap` (positive) | 4 units | 2 units | 4 units | 4 units |
| `per_reporter_neg_cap` | 25 units | 50 units | 15 units | 25 units |
| `unknown_reporter_weight_ppm` | 0 | 0 | 250 000 | 0 |
| `r` half-life (`lambda_pos_ppm`) | 90 epochs (7 672) | 180 epochs (3 843) | 60 epochs (11 486) | none (0) |
| `s` half-life (`lambda_neg_ppm`) | 30 epochs (22 840) | 90 epochs (7 672) | 14 epochs (48 305) | 30 epochs (22 840) |
| `minor` | 1 unit | 1 unit | 2 units | 1 unit |
| `admit_age_epochs` (rule 49) | 7 | none | 3 | 7 |
| `receipt_positions` | 4 096 | 1 024 | 4 096 | 4 096 |

## Event weights

In units. `null-sec` weighs only offences that prove themselves.

| Code | `jig-reference` | `high-sec` | `community` | `null-sec` |
| --- | --- | --- | --- | --- |
| `good-standing-interval` | +1 | +1 | +1 | 0 |
| `quota-breach` | −1 | −2 | −0.5 | 0 |
| `invalid-proof` | −1 | −2 | −1 | −1 |
| `spam-confirmed` | −10 | −20 | −5 | 0 |
| `signed-contradiction` | −25 | −50 | −15 | −25 |
| `standing-fraud` (rule 44) | −25 | −50 | −15 | −25 |
| `verdict-applied` | the verdict's penalty | the verdict's penalty | the verdict's penalty | the verdict's penalty |
| `invite-redeemed` | 0 | 0 | 0 | 0 |
| `useful-work` | — | `credit[kind]` | — | — |
| `useful-work-fraud` | — | −5 | — | — |
| `beacon-withheld` | — | −10 | — | — |

`high-sec`'s useful-work block uses JEP-0016's starting points: `n` 5, `k` 3, `n_escalate` 11,
`k_escalate` 7. It credits 0.1 unit for `witness` and `retrieve`, and 0.2 for `validate` and
`reexecute`. `credit_cap_per_period` is half of accrual. `fraud_weight` is −5 units, more than a
period's capped credit (JEP-0016 rule 35).

## Consequences (recommended, local)

`f` outputs only the score and the established flag. What a server does with them is local
policy (rule 50). Each ruleset declares this table so a subject sees it before its `ack`:

| Band | Pool (JEP-0008 rule 21) | Effort (JEP-0008 rule 28) | Join role (JEP-0014) |
| --- | --- | --- | --- |
| `high-sec` only: score ≤ −0.5 | stranger | `max_penalty_multiplier` | none: refuse new joins |
| negative | stranger | above 1, up to `max_penalty_multiplier` | guest |
| unknown, or below `established` | member by aged proof, else stranger | 1 | guest |
| established | member | falls to `1 / max_standing_discount` | member |

`high-sec` has no membership by aged proof: only established subjects are members there.

## What the traces show

Each trace runs 70 epochs with these subjects. Only the owner reports on the single-server
rulesets. Two established peers report in the group rulesets.

- **`steady`** writes every epoch. It is established exactly at `min_age_epochs` (epoch 29 under
  `jig-reference`, 59 under `high-sec`, 13 under `community`), however much it writes.
- **`offender`** writes every epoch, with 3 quota breaches at epoch 10, one confirmed spam at
  epoch 20 and 2 invalid proofs at epoch 25.
  - Under `jig-reference` it falls to 0.21 at epoch 20, recovers, and is established at
    epoch 29.
  - Under `high-sec` the spam drives its score negative. It is never established within the
    trace.
  - Under `community` it stays established.
- **`lapsed`** writes for 10 epochs, then stops. The idle limit keeps it from becoming
  established, or drops it soon after. Under `community` it is established at epoch 13 and drops
  at 16.
- **`burst`** claims 50 intervals in epoch 0 and then stops. The caps turn that into one unit,
  and it is never established.
- **`selfish`** reports about itself only. It has no state (rule 12).
- **`fresh-only`**, under `community`, is reported only by an unknown reporter weighted 0.25. It
  gets a quarter unit and stays far below `established`. Under the other rulesets, the same
  report weighs 0 and creates no state.
- **`worker`**, **`keeper`** and **`worker-only`**, under `high-sec`:
  - `worker` does useful work on top of writing. The accrual cap makes the credit add nothing.
  - `keeper` stops writing at epoch 61 and stays established on useful work alone.
  - `worker-only` does useful work from the start, and never gets state. Credit counts only for
    a subject established at `N − 1` (rule 40; JEP-0016 rules 8 and 31).
- Under **`null-sec`**, nobody accrues and nobody is established. The `offender`'s invalid proofs
  give it a negative score that decays. Every other subject stays unknown, and is a member only
  by aged proof.

## Not in these vectors yet

- A verdict with a pinned penalty, an invite redemption, and a vouching graph.
- State leaves, `standing_root` and fraud proofs. They need the CBOR encoding, so they come with
  the `jig-core` implementation.
- Epoch boundaries from cosigned checkpoints. The traces take epoch numbers as given.

## For DJ

1. **The numbers.** Every row above is a proposal. The three that matter most:
   - `min_age_epochs`: 30, 60 and 14 epochs;
   - `max_idle_epochs`: 14, 7 and 7 epochs;
   - the spam weights against the negative caps.
2. **`community`'s unknown-reporter weight.** It is 0.25, so a fresh server's reports count a
   little. That lets a new group bootstrap, at the cost of a farm of fresh reporters adding a
   quarter unit each, still under the accrual cap. The other rulesets weigh unknown reporters
   at 0.
3. **`null-sec`'s design.** Standing there can only cost, never earn. Membership comes only from
   aged admission proofs, and offences raise effort.
