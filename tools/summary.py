"""One table over every result card: python3 tools/summary.py  ->  results/_summary.md (and prints it)."""
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


lines = ["| Dataset | Role | Records (train+val+test) | Organizations | Numbers kept | H1 sharing | H2 federated | Centralized (reference) | Fingerprint sharing (experimental) | H3 traced above guessing | Verdicts sharing A/B/C | Verdicts federated A/B/C |", "|---|---|---|---|---|---|---|---|---|---|---|---|"]
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
    lines.append(f"| {c['name']} | {c.get('study_role', '')} | {n:,} | {orgs} | {c['step2']['kept_numbers']} | {pts(c['hypotheses']['H1'])} | {pts(c['hypotheses']['H2'])} | {pts(c['checks']['pooled'])} | {pts(e['mean_gain']) if e else 'not measured'} | {h3s} | {vs} | {vf} |")
failed = os.path.join(HERE, "results", "_failed.json")
if os.path.exists(failed):
    for k, v in json.load(open(failed)).items():
        lines.append(f"| {k} | failed | | | | {v['error'][:120]} | | | | | | |")
out = "\n".join(lines)
open(os.path.join(HERE, "results", "_summary.md"), "w").write(out + "\n")
print(out)
print(len(cards), "cards")
