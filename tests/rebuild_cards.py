"""Rebuild the seven result cards from the cached training runs of system.py (5 and 6 October 2026).
Nothing is retrained; the scorecard (ranges, verdicts, per-condition false-positive rates and bytes) is recomputed
with engine.py so that the published tool shows the same fields for every dataset. Reads the praxis folders only."""
import sys, os, json, shutil, glob, time
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import engine

PS = os.environ.get("PRAXIS_SYSTEM", "/sessions/stoic-magical-cannon/mnt/Dissertation/Praxis_System")
MAP = [("/Users/malhotra/Desktop/GW/1_A_DISSERTATION", "/sessions/stoic-magical-cannon/mnt/1_A_DISSERTATION")]
OUT = os.path.join(os.path.dirname(HERE), "results")


def fix(p):
    for a, b in MAP:
        if p.startswith(a):
            p = b + p[len(a):]
    return p if os.path.isabs(p) else os.path.join(PS, p)


for f in sorted(glob.glob(f"{PS}/datasets/*.json")):
    cfg = json.load(open(f))
    did = cfg["id"]
    if "path" in cfg:
        cfg["path"] = fix(cfg["path"])
    if "paths" in cfg:
        cfg["paths"] = [fix(p) for p in cfg["paths"]]
    cache = f"/tmp/cache_copy/{did}"
    if not os.path.exists(cache):
        shutil.copytree(f"{PS}/cache/{did}", cache)
        for fl in glob.glob(f"{cache}/*_flower.pkl"):
            os.remove(fl)
    t = time.time()
    card = engine.run(cfg, budget=engine.PROTOCOL, log=lambda m: None, cache=cache)
    card["id"] = did
    card["study_role"] = cfg.get("study_role", "tool test")
    card["info"] = cfg.get("info", {})
    card["computed"] = "training results cached from the 5 and 6 October 2026 runs of system.py; scorecard recomputed by this tool"
    json.dump(card, open(f"{OUT}/{did}.json", "w"), indent=1, default=float)
    h1, h2 = card["hypotheses"]["H1"], card["hypotheses"]["H2"]
    print(f"{did:12s} H1 {h1['gain']*100:+.1f} [{h1['lo']*100:+.1f},{h1['hi']*100:+.1f}]  H2 {h2['gain']*100:+.1f} [{h2['lo']*100:+.1f},{h2['hi']*100:+.1f}]  H3 {card['hypotheses']['H3']}  {time.time()-t:.0f}s")
    for o, c in card["companies"].items():
        print("   ", o, c["never_seen"], "named", {r[2:5]: round(v * 100, 1) for r, v in c["named"].items()},
              "fp", {r[2:5]: round(v * 100, 2) for r, v in c["false_alarm"].items()},
              "|", card["verdicts"][o]["2_sharing"], "|", card["verdicts"][o]["3_federated"])
