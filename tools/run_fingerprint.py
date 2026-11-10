"""Run the EXPERIMENTAL fingerprint-sharing arm (fp_experiment.py) on every dataset that has a result card and write it
into the card under "experimental". It is not one of the four training conditions of the praxis.

    .venv/bin/python tools/run_fingerprint.py                 every card
    .venv/bin/python tools/run_fingerprint.py --only dnp3     one dataset
    --map FROM=TO   rewrite absolute paths in the settings (for a machine other than the one they were written on)
"""
import argparse
import glob
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
import pandas as pd  # noqa: E402
import engine  # noqa: E402
import fp_experiment  # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("--only", default=None)
ap.add_argument("--map", default="")
ap.add_argument("--force", action="store_true")
a = ap.parse_args()
DS = os.path.abspath(os.path.join(HERE, "..", "Praxis_Lab_Datasets"))
PS = os.path.abspath(os.path.join(HERE, "..", "Praxis_System"))
LOG = os.path.join(HERE, "runs.log")


def fix(p, base):
    for m in filter(None, a.map.split(";")):
        f, t = m.split("=", 1)
        if p.startswith(f):
            p = t + p[len(f):]
    return p if os.path.isabs(p) else os.path.join(base, p)


def log(msg):
    line = f"{time.strftime('%Y-%m-%d %H:%M:%S')}  {msg}"
    print(line, flush=True)
    with open(LOG, "a") as fh:
        fh.write(line + "\n")


for card_path in sorted(glob.glob(os.path.join(HERE, "results", "*.json"))):
    did = os.path.splitext(os.path.basename(card_path))[0]
    if did.startswith("_") or (a.only and did not in a.only.split(",")):
        continue
    card = json.load(open(card_path))
    if card.get("experimental", {}).get("fingerprint_sharing") and not a.force:
        log(f"{did}: fingerprint arm exists, skipped")
        continue
    s_new, s_old = os.path.join(DS, "settings", f"{did}.json"), os.path.join(PS, "datasets", f"{did}.json")
    if os.path.exists(s_new):
        cfg, base = json.load(open(s_new)), DS
    elif os.path.exists(s_old):
        cfg, base = json.load(open(s_old)), PS
    else:
        log(f"{did}: no settings file, skipped")
        continue
    t0 = time.time()
    try:
        if "path" in cfg:
            cfg["path"] = fix(cfg["path"], base)
        frame = None
        if "paths" in cfg:
            cfg["paths"] = [fix(p, base) for p in cfg["paths"]]
            frame = pd.concat([pd.read_csv(p, low_memory=False, nrows=cfg.get("nrows")) for p in cfg["paths"]], ignore_index=True)
        data = engine.Data(cfg, frame=frame, budget=engine.PROTOCOL_MANY)
        bench = engine.Bench(data, budget=engine.PROTOCOL_MANY)
        res = fp_experiment.run(data, bench, seeds=tuple(card.get("seeds", [0, 1, 2])), resamples=2000)
        res["computed"] = time.strftime("%d %B %Y")
        card.setdefault("experimental", {})["fingerprint_sharing"] = res
        json.dump(card, open(card_path, "w"), indent=1, default=float)
        g = res["mean_gain"]
        log(f"{did}: fingerprint sharing {g['gain'] * 100:+.1f} [{g['lo'] * 100:+.1f}, {g['hi'] * 100:+.1f}] "
            f"(sharing {card['hypotheses']['H1']['gain'] * 100:+.1f}, federated {card['hypotheses']['H2']['gain'] * 100:+.1f}); "
            + ", ".join(f"{o} {res['orgs'][o]['named'] * 100:.1f}%" for o in "ABC") + f"; {time.time() - t0:.0f} s")
    except Exception as e:
        log(f"{did}: fingerprint arm FAILED: {e}")
log("run_fingerprint: finished")
