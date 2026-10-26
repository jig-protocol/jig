#!/usr/bin/env python3
"""Summarise a two-host-soak.sh run as Markdown. Exits 1 if a message was
lost or a server failed the end-of-run check.

Usage: summarize.py OUT RUN_ID MODE DURATION INTERVAL POLL DEADLINE
                    RESTART_EVERY FINAL_OK

The summary names the servers A and B only, never their URLs.
"""

import csv
import os
import sys


def rows(out, name):
    path = os.path.join(out, name)
    if not os.path.exists(path):
        return []
    with open(path, newline="") as f:
        return list(csv.DictReader(f, delimiter="\t"))


def pct(values, p):
    if not values:
        return None
    values = sorted(values)
    return values[min(len(values) - 1, round((len(values) - 1) * p))]


def secs(v):
    return "–" if v is None else f"{v:.1f}"


def num(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def main():
    (out, run_id, mode, duration, interval, poll, deadline, restart_every,
     final_ok) = sys.argv[1:10]
    deadline_s = float(deadline)
    sends = rows(out, "sends.tsv")
    seen = rows(out, "seen.tsv")
    gaps = rows(out, "gaps.tsv")
    health = rows(out, "health.tsv")
    restarts = rows(out, "restarts.tsv")

    first_seen = {}
    for r in seen:
        key = (r["sender"], int(r["seq"]))
        first_seen.setdefault(key, int(r["seen_ms"]))
    # Sequence numbers a reader could not see: (reader, after, next) means
    # after+1 .. next-1 fell outside every read.
    unverifiable = set()
    for g in gaps:
        sender = "b" if g["reader"] == "a" else "a"
        for s in range(int(g["after_seq"]) + 1, int(g["next_seen"])):
            unverifiable.add((sender, s))

    lines = [
        f"# Two-host soak {run_id}",
        "",
        f"- Mode {mode}; {duration} s of sends, one message each way every "
        f"{interval} s; reads every {poll} s; a message unseen after "
        f"{deadline} s is lost.",
        f"- Server B restarted every {restart_every} s"
        if restart_every != "0" else "- No restarts injected.",
        f"- Latency is first sighting minus send time, so it is rounded up "
        f"to the next read ({poll} s).",
        "",
        "| direction | sent | send errors | delivered | late | lost | "
        "unverifiable | p50 s | p95 s | p99 s | max s |",
        "|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    lost_total = 0
    hourly = {}
    for sender, reader in (("a", "b"), ("b", "a")):
        mine = [s for s in sends if s["side"] == sender]
        ok = [s for s in mine if s["ok"] == "1"]
        errors = len(mine) - len(ok)
        latencies, late, lost, unver = [], 0, 0, 0
        for s in ok:
            key = (sender, int(s["seq"]))
            sent_ms = int(s["sent_ms"])
            hour = (sent_ms - int(sends[0]["sent_ms"])) // 3_600_000
            bucket = hourly.setdefault((sender, hour), [0, 0, []])
            bucket[0] += 1
            if key in first_seen:
                lat = (first_seen[key] - sent_ms) / 1000
                latencies.append(lat)
                bucket[2].append(lat)
                if lat > deadline_s:
                    late += 1
            elif key in unverifiable:
                unver += 1
            else:
                lost += 1
                bucket[1] += 1
        lost_total += lost
        lines.append(
            f"| {sender.upper()} → {reader.upper()} | {len(ok)} | {errors} | "
            f"{len(latencies)} | {late} | {lost} | {unver} | "
            f"{secs(pct(latencies, 0.5))} | {secs(pct(latencies, 0.95))} | "
            f"{secs(pct(latencies, 0.99))} | {secs(max(latencies, default=None))} |"
        )

    if len({h for _, h in hourly}) > 1:
        lines += ["", "## By hour", "",
                  "| hour | direction | sent | lost | p95 s |", "|---|---|---|---|---|"]
        for (sender, hour), (sent, lost, lats) in sorted(hourly.items(), key=lambda kv: (kv[0][1], kv[0][0])):
            reader = "b" if sender == "a" else "a"
            lines.append(f"| {hour} | {sender.upper()} → {reader.upper()} | {sent} | "
                         f"{lost} | {secs(pct(lats, 0.95))} |")

    lines += ["", "## Servers", "",
              "| server | samples | /healthz not 200 | RSS KiB first → last (max) | "
              "fds first → last (max) | federation blocks ingested |",
              "|---|---|---|---|---|---|"]
    for side in ("a", "b"):
        hs = [h for h in health if h["side"] == side]
        bad = sum(1 for h in hs if h["healthz"] != "200")
        rss = [num(h["rss_kb"]) for h in hs if num(h["rss_kb"]) is not None]
        fds = [num(h["fds"]) for h in hs if num(h["fds"]) is not None]
        fed = [num(h["federation_ingested"]) for h in hs if num(h["federation_ingested"]) is not None]

        def span(v):
            return "–" if not v else f"{v[0]:.0f} → {v[-1]:.0f} ({max(v):.0f})"

        fed_s = "–" if not fed else f"{fed[0]:.0f} → {fed[-1]:.0f}"
        lines.append(f"| {side.upper()} | {len(hs)} | {bad} | {span(rss)} | {span(fds)} | {fed_s} |")
    lines.append("")
    lines.append(f"Restarts injected: {len(restarts)}. Visibility gaps: {len(gaps)}. "
                 "Ingest counters are per process and start again after a restart.")
    lines.append("")
    ok = lost_total == 0 and final_ok == "1"
    verdict = "PASS" if ok else "FAIL"
    reasons = []
    if lost_total:
        reasons.append(f"{lost_total} lost")
    if final_ok != "1":
        reasons.append("a server failed the end-of-run check")
    lines.append(f"**{verdict}**" + (f": {', '.join(reasons)}" if reasons else ""))
    print("\n".join(lines))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
