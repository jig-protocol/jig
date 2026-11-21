#!/usr/bin/env python3
"""Reference model of JEP-0009 rule 40 (jig-beta-v1) and the four reference rulesets.

Writes repos/jig-spec/jep/vectors/0009/{rulesets/*.json, standing-traces.json}.
Run from the repository root: python3 repos/jig-spec/jep/vectors/0009/reference_model.py .
Temporary: the jig-core implementation must reproduce every value, then replaces this model.
Exact integer arithmetic only; Python's // is floor division, as rule 40 requires.
"""
import json, os, sys

U = 1_000_000  # one evidence unit, in micro-units
PPM = 1_000_000

def ruleset(id_, *, epoch, standing, events, pow_, pools, consequences, tribunal, useful_work,
            invites, binding):
    return {
        "v": 1, "id": id_, "version": 1, "authors": [],
        "maths": {"id": "jig-beta-v1", "version": 1},
        "epoch": epoch,
        "parameters": {"pow": pow_, "pools": pools, "standing": standing, "invites": invites},
        "events": events,
        "consequences": consequences,
        "tribunal": tribunal,
        "useful_work": useful_work,
        "invites": invites["invites_per_window"] > 0,
        "binding": binding,
    }

def consequences(penalty, member_by_age):
    rows = [
        {"band": "negative", "score_ppm": [-PPM + 1, -1], "pool": "stranger",
         "effort": "m_standing above 1, up to max_penalty_multiplier", "join": "guest"},
        {"band": "unknown", "score_ppm": None, "pool": "member" if member_by_age else "stranger",
         "effort": "m_standing = 1", "join": "guest",
         "note": "member only by aged proof (rule 49)" if member_by_age else "stranger"},
        {"band": "below-established", "score_ppm": [0, "established - 1"],
         "pool": "member" if member_by_age else "stranger",
         "effort": "m_standing = 1", "join": "guest",
         "note": "member only by aged proof (rule 49)" if member_by_age else "stranger"},
        {"band": "established", "score_ppm": ["established", PPM - 1], "pool": "member",
         "effort": "m_standing falls linearly to 1 / max_standing_discount", "join": "member"},
    ]
    if penalty:
        rows.insert(0, {"band": "severe", "score_ppm": [-PPM + 1, penalty], "pool": "stranger",
                        "effort": "m_standing = max_penalty_multiplier", "join": "none",
                        "note": "recommend refusing new channel joins"})
        rows[1]["score_ppm"] = [penalty + 1, -1]
    return rows

POW_REF = {"admit": {"min_effort": 1 << 20, "max_effort": 1 << 24, "max_solve_secs": 13},
           "max_penalty_multiplier": 16, "max_standing_discount": 4}

REF_EVENTS = {
    "good-standing-interval": 1 * U,
    "quota-breach": -1 * U,
    "invalid-proof": -1 * U,
    "spam-confirmed": -10 * U,
    "signed-contradiction": -25 * U,
    "verdict-applied": 0,
    "invite-redeemed": 0,
    "standing-fraud": -25 * U,
}

RULESETS = {
    "jig-reference": ruleset(
        "jig-reference",
        epoch={"epoch_secs": 86_400, "witness_threshold": 0},
        standing={"established": 300_000, "min_age_epochs": 30,
                  "accrual_per_period": 1 * U, "per_reporter_cap": 4 * U, "per_reporter_neg_cap": 25 * U, "max_idle_epochs": 14,
                  "unknown_reporter_weight": 0, "lambda_pos": 7_672,
                  "lambda_neg": 22_840, "minor": 1 * U, "admit_age_epochs": 7,
                  "receipt_positions": 4_096},
        events=REF_EVENTS,
        pow_=POW_REF,
        pools={"stranger_share": 20, "invited_share": 10, "aged_share": 25},
        consequences=consequences(None, True),
        tribunal=None, useful_work=None,
        invites={"invites_per_window": 0, "invite_window_epochs": 30, "invite_start": 0},
        binding=[]),
    "high-sec": ruleset(
        "high-sec",
        epoch={"epoch_secs": 86_400, "witness_threshold": 3},
        standing={"established": 500_000, "min_age_epochs": 60,
                  "accrual_per_period": 1 * U, "per_reporter_cap": 2 * U, "per_reporter_neg_cap": 50 * U, "max_idle_epochs": 7,
                  "unknown_reporter_weight": 0, "lambda_pos": 3_843,
                  "lambda_neg": 7_672, "minor": 1 * U, "admit_age_epochs": None,
                  "receipt_positions": 1_024, "vouch_min_epochs": None, "vouch_cap": None},
        events={**{k: v * 2 if v < 0 else v for k, v in REF_EVENTS.items()},
                "useful-work-fraud": -5 * U, "beacon-withheld": -10 * U},
        pow_={**POW_REF, "admit": {"min_effort": 1 << 22, "max_effort": 1 << 24,
                                    "max_solve_secs": 13}},
        pools={"stranger_share": 10, "invited_share": 10, "aged_share": 0},
        consequences=consequences(-500_000, False),
        tribunal={"seats": 5, "evidence_threshold": 3, "provisional_threshold": 2,
                  "provisional_ttl": 259_200, "panel_size": 5, "panel_sustain": 4,
                  "response_window": 604_800, "appeal_window": 1_209_600,
                  "seat_admission_threshold": 4},
        useful_work={"kinds": ["witness", "validate", "reexecute", "retrieve"],
                     "n": {"witness": 5, "validate": 5, "reexecute": 5, "retrieve": 5},
                     "k": {"witness": 3, "validate": 3, "reexecute": 3, "retrieve": 3},
                     "n_escalate": 11, "k_escalate": 7,
                     "sample_rate": 1_000, "reexecute_rate": 1_000,
                     "retrieve_samples": 16,
                     "beacon_reveal_positions": 1_024, "beacon_min_reveals": 3,
                     "beacon_exclusion_epochs": 7, "beacon_withheld_weight": -10 * U,
                     "commit_positions": 2_048, "reveal_positions": 2_048, "max_carry": 3,
                     "same_subject_cooldown_epochs": 30,
                     "max_missed": 3, "miss_window_epochs": 7, "miss_pause_epochs": 7,
                     "retrievability_epochs": 7, "dispute_retention_epochs": 90,
                     "credit": {"witness": 100_000, "validate": 200_000, "reexecute": 200_000,
                                "retrieve": 100_000},
                     "credit_cap_per_period": 500_000,
                     "fraud_weight": -5 * U},
        invites={"invites_per_window": 1, "invite_window_epochs": 30,
                 "invite_start": 1 * U},
        binding=[]),
    "community": ruleset(
        "community",
        epoch={"epoch_secs": 86_400, "witness_threshold": 1},
        standing={"established": 200_000, "min_age_epochs": 14,
                  "accrual_per_period": 1 * U, "per_reporter_cap": 4 * U, "per_reporter_neg_cap": 15 * U, "max_idle_epochs": 7,
                  "unknown_reporter_weight": 250_000, "lambda_pos": 11_486,
                  "lambda_neg": 48_305, "minor": 2 * U, "admit_age_epochs": 3,
                  "receipt_positions": 4_096, "vouch_min_epochs": 30, "vouch_cap": 2 * U},
        events={"good-standing-interval": 1 * U, "quota-breach": -500_000,
                "invalid-proof": -1 * U, "spam-confirmed": -5 * U,
                "signed-contradiction": -15 * U, "verdict-applied": 0, "invite-redeemed": 0,
                "standing-fraud": -15 * U},
        pow_=POW_REF,
        pools={"stranger_share": 30, "invited_share": 15, "aged_share": 25},
        consequences=consequences(None, True),
        tribunal=None, useful_work=None,
        invites={"invites_per_window": 3, "invite_window_epochs": 30,
                 "invite_start": 1 * U},
        binding=["linked-vouching"]),
    "null-sec": ruleset(
        "null-sec",
        epoch={"epoch_secs": 86_400, "witness_threshold": 0},
        standing={"established": PPM - 1, "min_age_epochs": 0,
                  "accrual_per_period": 0, "per_reporter_cap": 4 * U,
                  "per_reporter_neg_cap": 25 * U, "max_idle_epochs": None,
                  "unknown_reporter_weight": 0, "lambda_pos": 0,
                  "lambda_neg": 22_840, "minor": 1 * U, "admit_age_epochs": 7,
                  "receipt_positions": 4_096},
        events={"good-standing-interval": 0, "quota-breach": 0, "invalid-proof": -1 * U,
                "spam-confirmed": 0, "signed-contradiction": -25 * U, "verdict-applied": 0,
                "invite-redeemed": 0, "standing-fraud": -25 * U},
        pow_=POW_REF,
        pools={"stranger_share": 50, "invited_share": 0, "aged_share": 100},
        consequences=consequences(None, True),
        tribunal=None, useful_work=None,
        invites={"invites_per_window": 0, "invite_window_epochs": 30, "invite_start": 0},
        binding=[]),
}

# ---- jig-beta-v1 (JEP-0009 rule 40) ----

def score(r, s):
    return (r - s) * PPM // (r + s + 2 * PPM)

def step(rs, state, epoch, events, reporters_established, lone_owner):
    """One epoch of f. events: list of (reporter, subject, code, count)."""
    p = rs["parameters"]["standing"]
    uw = rs["useful_work"]
    lp, ln = p["lambda_pos"], p["lambda_neg"]
    out = {}
    subjects = set(state) | {e[1] for e in events}
    for subj in sorted(subjects):
        st = dict(state.get(subj, {"r": 0, "s": 0, "first_epoch": epoch}))
        # 1. decay
        st["r"] -= st["r"] * lp // PPM
        st["s"] -= st["s"] * ln // PPM
        # 2. per reporter
        pos_uw = pos = neg = 0
        by_rep = {}
        for rep, sub, code, count in events:
            if sub != subj or rep == subj:
                continue
            if code == "useful-work":
                w = uw["credit"][count[0]] * count[1]  # (kind, n)
                key = "uw"
            else:
                w = rs["events"][code] * count
                key = "ev"
            d = by_rep.setdefault(rep, {"pos": 0, "neg": 0, "uw": 0})
            if key == "uw":
                d["uw"] += w
            elif w >= 0:
                d["pos"] += w
            else:
                d["neg"] += -w
        cap = p["per_reporter_cap"]
        for rep, d in sorted(by_rep.items()):
            if lone_owner:
                wt = PPM
            else:
                wt = PPM if reporters_established.get(rep) else p["unknown_reporter_weight"]
            pos += min(d["pos"], cap) * wt // PPM
            pos_uw += min(d["uw"], cap) * wt // PPM
            neg += min(d["neg"], p["per_reporter_neg_cap"]) * wt // PPM
        # 3. accrual cap. Useful-work credit counts only for a subject established at N-1
        # (JEP-0016 rules 8 and 31: it keeps standing, it never buys it).
        acc = p["accrual_per_period"]
        if subj not in state or not view(rs, state[subj], epoch - 1)["established"]:
            pos_uw = 0
        if uw:
            pos_uw = min(pos_uw, uw["credit_cap_per_period"] * acc // PPM)
        positive = min(pos + pos_uw, acc)
        # 4. add
        st["r"] += positive
        st["s"] += neg
        if subj not in state:
            # Age starts only when f adds evidence (rule 39): zero-weight reports from
            # unknown reporters create no state and start no clock.
            if positive == 0 and neg == 0:
                continue
            st["first_epoch"] = epoch
        if positive or neg:
            st["last_epoch"] = epoch
        out[subj] = st
    return out

def events_about(events, subj):
    return any(e[1] == subj and e[0] != subj for e in events)

def view(rs, st, epoch):
    p = rs["parameters"]["standing"]
    sc = score(st["r"], st["s"])
    age = epoch - st["first_epoch"] + 1
    idle = p["max_idle_epochs"]
    active = idle is None or epoch - st["last_epoch"] < idle
    return {"r": st["r"], "s": st["s"], "score_ppm": sc, "age_epochs": age,
            "last_epoch": st["last_epoch"],
            "established": sc >= p["established"] and age >= p["min_age_epochs"]
            and active}

EPOCHS = 70

def scenario(name):
    """Leaves per epoch, as (reporter, subject, code, count)."""
    lone = name in ("jig-reference", "null-sec")
    reps = ["did:jig:zserver"] if lone else ["did:jig:zserver-a", "did:jig:zserver-b",
                                              "did:jig:zserver-c"]
    plan = []
    for e in range(EPOCHS):
        ev = []
        for rep in reps[:1] if lone else reps[:2]:
            ev.append((rep, "steady", "good-standing-interval", 1))
            ev.append((rep, "offender", "good-standing-interval", 1))
            if e < 10:
                ev.append((rep, "lapsed", "good-standing-interval", 1))
        if e == 10:
            ev.append((reps[0], "offender", "quota-breach", 3))
        if e == 20:
            ev.append((reps[0], "offender", "spam-confirmed", 1))
        if e == 25:
            ev.append((reps[0], "offender", "invalid-proof", 2))
        if e == 0:
            # one reporter claims far more than the caps allow
            ev.append((reps[0], "burst", "good-standing-interval", 50))
            # a reporter reporting about itself is ignored (rule 12)
            ev.append(("selfish", "selfish", "good-standing-interval", 5))
        if not lone and e == 0:
            # an unknown reporter (not established) weighs unknown_reporter_weight
            ev.append(("did:jig:zfresh", "fresh-only", "good-standing-interval", 1))
        if name == "high-sec":
            ev.append((reps[0], "worker", "good-standing-interval", 1))
            ev.append((reps[0], "worker", "useful-work", ("validate", 10)))
            # "keeper": ordinary evidence until epoch 61, then useful work only; credit is
            # ignored until it is established, then keeps it established
            if e <= 61:
                ev.append((reps[0], "keeper", "good-standing-interval", 1))
            ev.append((reps[0], "keeper", "useful-work", ("validate", 10)))
            # useful work alone never establishes a subject
            ev.append((reps[0], "worker-only", "useful-work", ("validate", 10)))
        plan.append(ev)
    established = {r: True for r in reps}
    return plan, established, lone

def trace(name):
    rs = RULESETS[name]
    plan, established, lone = scenario(name)
    state, rows = {}, []
    for e, ev in enumerate(plan):
        state = step(rs, state, e, ev, established, lone)
        rows.append({"epoch": e,
                     "subjects": {k: view(rs, v, e) for k, v in sorted(state.items())}})
    leaves = [{"epoch": e, "reporter": r, "subject": s, "code": c,
               "count": list(n) if isinstance(n, tuple) else n}
              for e, ev in enumerate(plan) for (r, s, c, n) in ev]
    return {"ruleset": name, "lone_owner": lone,
            "established_reporters": sorted(established),
            "leaves": leaves, "epochs": rows}

def main(root):
    d = os.path.join(root, "repos/jig-spec/jep/vectors/0009")
    os.makedirs(os.path.join(d, "rulesets"), exist_ok=True)
    for name, rs in RULESETS.items():
        rs = json.loads(json.dumps(rs))
        est = rs["parameters"]["standing"]["established"]
        for row in rs["consequences"]:
            if row["score_ppm"]:
                row["score_ppm"] = [est if x == "established" else
                                    est - 1 if x == "established - 1" else x
                                    for x in row["score_ppm"]]
        for blk in (rs["parameters"]["standing"], rs["events"], rs["useful_work"] or {}):
            for k in [k for k, v in blk.items() if v is None]:
                del blk[k]
        with open(os.path.join(d, "rulesets", name + ".json"), "w") as f:
            json.dump(rs, f, indent=2, sort_keys=True)
            f.write("\n")
    traces = {"maths": "jig-beta-v1", "note": "generated by a reference model of JEP-0009 "
              "rule 40; the jig-core implementation must reproduce every value",
              "traces": [trace(n) for n in RULESETS]}
    with open(os.path.join(d, "standing-traces.json"), "w") as f:
        # one leaf and one epoch per line: diffable, and small enough to read
        f.write("{\n")
        f.write(f' "maths": {json.dumps(traces["maths"])},\n')
        f.write(f' "note": {json.dumps(traces["note"])},\n "traces": [\n')
        for ti, t in enumerate(traces["traces"]):
            f.write("  {\n")
            for k in ("ruleset", "lone_owner", "established_reporters"):
                f.write(f'   {json.dumps(k)}: {json.dumps(t[k])},\n')
            f.write('   "leaves": [\n')
            f.write(",\n".join("    " + json.dumps(l, sort_keys=True) for l in t["leaves"]))
            f.write('\n   ],\n   "epochs": [\n')
            f.write(",\n".join("    " + json.dumps(e, sort_keys=True, separators=(",", ":"))
                               for e in t["epochs"]))
            f.write("\n   ]\n  }" + ("," if ti < len(traces["traces"]) - 1 else "") + "\n")
        f.write(" ]\n}\n")
    # summary for the docs
    for t in traces["traces"]:
        print("==", t["ruleset"])
        for e in (0, 9, 10, 19, 20, 25, 29, 30, 59, 62, 69):
            row = t["epochs"][e]["subjects"]
            print(e, {k: (v["score_ppm"], v["established"]) for k, v in row.items()})

if __name__ == "__main__":
    main(sys.argv[1])
