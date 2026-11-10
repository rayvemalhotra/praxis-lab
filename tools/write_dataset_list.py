"""Write results/_datasets.json, the list of public datasets shown on the Students page, from the settings files kept beside the install
(../Praxis_Lab_Datasets/settings/*.json). The list is a tracked file so that a clone or a hosted copy shows the same table as the author's machine.

    python tools/write_dataset_list.py
"""
import glob
import json
import os

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SETTINGS = os.path.abspath(os.path.join(HERE, "..", "Praxis_Lab_Datasets", "settings"))
RESULTS = os.path.join(HERE, "results")

failed = {}
try:
    failed = json.load(open(os.path.join(RESULTS, "_failed.json")))
except Exception:
    pass
rows = []
for f in sorted(glob.glob(os.path.join(SETTINGS, "*.json"))):
    try:
        s = json.load(open(f))
    except Exception:
        continue
    did = s.get("id") or os.path.splitext(os.path.basename(f))[0]
    info = s.get("info", {})
    if did in failed:
        runs = "no: " + str(failed[did].get("error", "the run stopped"))
    elif os.path.exists(os.path.join(RESULTS, did + ".json")):
        runs = "yes, see its card on the Results page"
    else:
        runs = "not run"
    rows.append({"Dataset": s.get("name", did), "Made by": info.get("maker", ""), "Attack types": info.get("attacks", ""), "Host column": info.get("host", ""),
                 "Source": info.get("source", ""), "Licence": info.get("licence", ""), "Runs in the tool": runs})
if not rows:
    raise SystemExit(f"no settings files found in {SETTINGS}; the list was not rewritten")
with open(os.path.join(RESULTS, "_datasets.json"), "w", encoding="utf-8") as fh:
    json.dump(rows, fh, indent=1, ensure_ascii=False)
print(len(rows), "datasets written to results/_datasets.json")
