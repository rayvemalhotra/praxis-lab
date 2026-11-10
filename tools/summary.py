"""One table over every result card: python3 tools/summary.py  ->  results/_summary.md (and prints it).
Every row is a local run of the tool. The praxis runs of record (Hex) are stated above the table and are not in it."""
import glob
import json
import os

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
cards = []
for f in sorted(glob.glob(os.path.join(HERE, "results", "*.json"))):
    if os.path.basename(f).startswith("_"):
        continue
    cards.append(json.load(open(f)))
order = {"the study": 0, "ranking check": 1}
cards.sort(key=lambda c: (order.get(c.get("study_role"), 2), c["name"]))


def pts(h):
    return f"{h['gain'] * 100:+.1f} [{h['lo'] * 100:+.1f}, {h['hi'] * 100:+.1f}]" + (" yes" if h["clears"] else " no")


RECORD = """# Summary of the result cards

Every row below is a local run of the tool (protocol budget, the tool's own split), not the run of record. {MACHINES}
Only DataSense carries the praxis claims.

The praxis runs of record, computed in Hex, are:

- DataSense CIC IIoT 2025 (Hex, 11 October 2026, three seeds): H1 +41.1 [+32.5, +49.6], H2 +45.8 [+37.0, +53.9].
- Edge-IIoTset, the ranking check (Hex, 19 October 2026): H1 +70.8 [+69.6, +72.0], H2 +61.5 [+60.4, +62.6].

The local runs of these two datasets in the table differ from the runs of record in the decimals; the H1 and H2 decisions are the same.
Columns H1, H2, Centralized and Fingerprint sharing give the mean gain in attack-class recall against isolated training, in points, with its 95% range, and yes or no for the 5-point rule.
All four training conditions are in the table: isolated training is the baseline of every gain. Fingerprint sharing is experimental and not a praxis training condition. What a fingerprint reveals about its sender has not been measured.
The hypotheses of the praxis are tested on DataSense alone; every other row is a tool test.
"""
lines = ["| Dataset | Role | Run | Records (train+val+test) | Organizations | Numbers kept | Isolated training | H1 sharing | H2 federated | Centralized (reference) | Fingerprint sharing (experimental) | H3 traced above the majority-host baseline (observed) | Verdicts sharing A/B/C | Verdicts federated A/B/C |", "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|"]
for c in cards:
    s1 = c["step1"]
    n = sum(s1[o]["train"] + s1[o]["val"] + s1[o]["test"] for o in "ABC")
    orgs = "hosts" if "groups of hosts" in c["rules"]["companies"] or "device groups" in c["rules"]["companies"] else "random thirds"
    h3 = c["hypotheses"].get("H3")
    h3s = ("all 3" if h3 and h3["yes"] else ("not all" if h3 else "not tested"))
    v = c.get("verdicts", {})
    short = lambda t: {"gain met": "gain", "gain met, privacy trade-off": "trade-off", "gain met, false-positive limit breached": "FP breach", "not worth it (gain not met)": "no gain"}.get(t, t)
    vs = "/".join(short(v.get(o, {}).get("2_sharing", "?")) for o in "ABC")
    vf = "/".join(short(v.get(o, {}).get("3_federated", "?")) for o in "ABC")
    e = (c.get("experimental") or {}).get("fingerprint_sharing")
    run = "tool rerun, not the run of record" if c.get("id") in ("datasense", "edge_iiotset") else "local run of the tool"
    lines.append(f"| {c['name']} | {c.get('study_role', '')} | {run} | {n:,} | {orgs} | {c['step2']['kept_numbers']} | baseline | {pts(c['hypotheses']['H1'])} | {pts(c['hypotheses']['H2'])} | {pts(c['checks']['pooled'])} | {pts(e['mean_gain']) if e else 'not measured'} | {h3s} | {vs} | {vf} |")
failed = os.path.join(HERE, "results", "_failed.json")
if os.path.exists(failed):
    for k, v in json.load(open(failed)).items():
        lines.append(f"| {k} | failed | local run of the tool | | | | not measured | {v['error'][:120]} | | | | | | |")
cached = sum(1 for c in cards if "cached" in (c.get("computed") or ""))
machines = (f"{len(cards) - cached} cards were computed on the author's Mac; {cached} were recomputed in a Linux sandbox from the cached training results of the October runs "
            "(their decimals differ from the runs of record for that reason).")
out = RECORD.replace("{MACHINES}", machines) + "\n" + "\n".join(lines)
open(os.path.join(HERE, "results", "_summary.md"), "w").write(out + "\n")
print(out)
print(len(cards), "cards")
