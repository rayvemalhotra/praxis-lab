"""Run the praxis procedure on every dataset that has a settings file, with the protocol budget, and write one
scorecard per dataset into Praxis_Lab/results/ so that the results page shows it.

    .venv/bin/python tools/run_all.py                 every settings file in ../Praxis_Lab_Datasets/settings/
    .venv/bin/python tools/run_all.py --only dnp3     one dataset
    .venv/bin/python tools/run_all.py --quick         the quick budget (a check, not a result)
    .venv/bin/python tools/run_all.py --force         recompute even when a result exists

Training results are cached per dataset in Praxis_Lab/cache/<id>/, so an interrupted run continues where it stopped.
Progress is appended to Praxis_Lab/runs.log. A dataset that stops with an error is recorded in results/_failed.json
and the run moves on.
"""
import argparse
import glob
import json
import os
import sys
import time
import traceback

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
import pandas as pd  # noqa: E402
import engine  # noqa: E402

DS = os.path.abspath(os.path.join(HERE, "..", "Praxis_Lab_Datasets"))
RESULTS = os.path.join(HERE, "results")
LOG = os.path.join(HERE, "runs.log")

ap = argparse.ArgumentParser()
ap.add_argument("--only", default=None)
ap.add_argument("--quick", action="store_true")
ap.add_argument("--force", action="store_true")
ap.add_argument("--datasets", default=DS)
a = ap.parse_args()
budget = engine.QUICK if a.quick else engine.PROTOCOL_MANY
os.makedirs(RESULTS, exist_ok=True)


def log(msg):
    line = f"{time.strftime('%Y-%m-%d %H:%M:%S')}  {msg}"
    print(line, flush=True)
    with open(LOG, "a") as fh:
        fh.write(line + "\n")


failed_path = os.path.join(RESULTS, "_failed.json")
failed = json.load(open(failed_path)) if os.path.exists(failed_path) else {}
files = sorted(glob.glob(os.path.join(a.datasets, "settings", "*.json")))
if a.only:
    files = [f for f in files if os.path.splitext(os.path.basename(f))[0] in a.only.split(",")]
log(f"run_all: {len(files)} settings files, budget {budget.name}")
for f in files:
    cfg = json.load(open(f))
    did = cfg["id"]
    out = os.path.join(RESULTS, f"{did}.json")
    if os.path.exists(out) and not a.force:
        log(f"{did}: result exists, skipped")
        continue
    paths = [p if os.path.isabs(p) else os.path.join(a.datasets, p) for p in cfg["paths"]]
    if not all(os.path.exists(p) for p in paths):
        log(f"{did}: data file missing ({paths[0]}), skipped")
        continue
    t0 = time.time()
    try:
        frame = pd.concat([pd.read_csv(p, low_memory=False) for p in paths], ignore_index=True)
        log(f"{did}: {len(frame):,} records, {frame.shape[1]} columns; starting")
        card = engine.run(cfg, frame=frame, budget=budget, log=lambda m: log(f"{did}:   {m}"), cache=os.path.join(HERE, "cache", did))
        card["id"] = did
        card["study_role"] = cfg.get("study_role", "tool test")
        card["info"] = cfg.get("info", {})
        card["computed"] = f"computed by this tool on {time.strftime('%d %B %Y')} with the {budget.name} budget on the working sample described above; the split is the tool's own"
        json.dump(card, open(out, "w"), indent=1, default=float)
        failed.pop(did, None)
        h1, h2 = card["hypotheses"]["H1"], card["hypotheses"]["H2"]
        log(f"{did}: done in {(time.time() - t0) / 60:.1f} min. H1 {h1['gain'] * 100:+.1f} [{h1['lo'] * 100:+.1f}, {h1['hi'] * 100:+.1f}]  H2 {h2['gain'] * 100:+.1f} [{h2['lo'] * 100:+.1f}, {h2['hi'] * 100:+.1f}]  H3 {card['hypotheses']['H3']}")
    except Exception as e:
        failed[did] = dict(error=str(e), when=time.strftime("%Y-%m-%d %H:%M"), trace=traceback.format_exc()[-1500:])
        log(f"{did}: FAILED after {(time.time() - t0) / 60:.1f} min: {e}")
    json.dump(failed, open(failed_path, "w"), indent=1)
log("run_all: finished")
