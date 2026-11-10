"""Section A: the ingestion matrix. Every sample file and every working dataset goes through the AUTOMATIC path of the
upload page: read the file, engine.inspect with no settings, accept every suggestion, engine.run with the quick budget.
Each file runs in its own process so that a crash, a hang or the memory of one file cannot hide in another.

    python tests/pressure/matrix.py                 every file, writes qa/matrix_results.json
    python tests/pressure/matrix.py --only samples  the files in samples/ only
    python tests/pressure/matrix.py --one PATH      one file, prints one JSON line (used by the parent process)
"""
import glob
import json
import os
import resource
import subprocess
import sys
import time

from common import DATASETS, ROOT, auto_cfg, save

TIMEOUT_S = 1500
UPLOAD_LIMIT = 200 * 1000 * 1000


def one(path):
    import pandas as pd
    import engine
    out = dict(file=os.path.basename(path), bytes=os.path.getsize(path))
    t = time.time()
    try:
        df = pd.read_parquet(path) if path.lower().endswith(".parquet") else pd.read_csv(path, low_memory=False)
    except Exception as e:
        return dict(out, stage="read", ok=False, error=f"{type(e).__name__}: {e}"[:300])
    out.update(read_s=round(time.time() - t, 1), rows=len(df), columns=df.shape[1])
    t = time.time()
    try:
        ins = engine.inspect(df)
    except Exception as e:
        return dict(out, stage="inspect", ok=False, error=f"{type(e).__name__}: {e}"[:300])
    out.update(inspect_s=round(time.time() - t, 1), detected=dict(label_col=ins["label_col"], benign_label=ins["benign_label"],
                                                                   source_col=ins["source_col"], time_col=ins["time_col"]),
               label_values=len(ins["label_values"]), numbers=len(ins["numbers"]), identifiers=len(ins["identifiers"]))
    if not ins["label_col"]:
        return dict(out, stage="inspect", ok=False, error="no label column was recognized")
    cfg, numbers = auto_cfg(df, ins)
    t = time.time()
    try:
        card = engine.run(cfg, frame=df, budget=engine.QUICK)
    except Exception as e:
        return dict(out, stage="run", ok=False, error=f"{type(e).__name__}: {e}"[:300])
    H = card["hypotheses"]
    v = card.get("verdicts", {})
    out.update(stage="done", ok=True, run_s=round(time.time() - t, 1), organizations=card["rules"]["companies"][:60],
               kept_numbers=card["step2"]["kept_numbers"],
               withheld={o: card["companies"][o]["never_seen"] for o in engine.ORG},
               H1=dict(gain=round(H["H1"]["gain"] * 100, 1), clears=H["H1"]["clears"]), H2=dict(gain=round(H["H2"]["gain"] * 100, 1), clears=H["H2"]["clears"]),
               H3=(None if not H.get("H3") else bool(H["H3"]["yes"])),
               verdict_sharing=[v.get(o, {}).get("2_sharing") for o in engine.ORG])
    return out


def expected_for(name):
    f = os.path.join(DATASETS, "settings", os.path.splitext(name)[0] + ".json")
    if not os.path.exists(f):
        return None
    s = json.load(open(f))
    return dict(label_col=s.get("label_col"), benign_label=s.get("benign_label"), source_col=s.get("source_col"), time_col=s.get("time_col"),
                label_map=s.get("label_map") or {},
                hand_tuned=sorted(k for k in ("label_map", "drop_labels", "drop", "keep", "min_class_rows", "sample_rows", "never_seen", "companies") if s.get(k)))


SAMPLE_EXPECTED = {  # the roles a person would pick for the sample files
    "sample_organization_water_utility_SYNTHETIC.csv": dict(label_col="attack_type", benign_label="normal", source_col="device_name", time_col="timestamp"),
    "sample_organization_hospital_SYNTHETIC.csv": dict(label_col="attack_category", benign_label="benign", source_col="asset_name", time_col="event_time"),
    "sample_organization_manufacturing_plant_SYNTHETIC.csv": dict(label_col="Label", benign_label="Normal", source_col="station", time_col="ts"),
    "sample_power_grid_dnp3_REAL_CC-BY-4.0.csv": dict(label_col="Label", benign_label="NORMAL", source_col="Dst IP", time_col="Timestamp"),
}


NOTES = {  # where the automatic choice differs from the hand-made settings and why (checked by hand on 9 and 10 November 2026)
    "cidds002.csv": "The file holds one attack type (scan) in attackType; the hand-made settings built attack types from the nmap arguments and name a time column "
                    "the file does not have. Without that hand work the table cannot support an evaluation, and the tool says so in one sentence.",
    "rt_iot2022.csv": "No label value means normal (the normal traffic is labeled by device: Thing_Speak, MQTT_Publish, Wipro_bulb, Amazon-Alexa). The tool takes the most "
                      "frequent value and flags it as a guess (benign_guess) for the person to correct; the hand-made settings merge the four values.",
    "iot23.csv": "The tool picks the originating host (987 hosts); the hand-made settings used the responding host (50,267 values, one for every second record). "
                 "Either way the hosts cannot form three organizations and the tool uses random thirds.",
}


def main():
    if "--one" in sys.argv:
        r = one(sys.argv[sys.argv.index("--one") + 1])
        r["peak_mb"] = round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / (1024 * 1024 if sys.platform == "darwin" else 1024))
        print("RESULT " + json.dumps(r, default=str))
        return
    files = sorted(glob.glob(os.path.join(ROOT, "samples", "*.csv")))
    if "--only" not in sys.argv or sys.argv[sys.argv.index("--only") + 1] != "samples":
        files += sorted(glob.glob(os.path.join(DATASETS, "*.csv")))
    results = []
    for f in files:
        name = os.path.basename(f)
        t = time.time()
        try:
            p = subprocess.run([sys.executable, os.path.abspath(__file__), "--one", f], capture_output=True, text=True, timeout=TIMEOUT_S, cwd=os.path.dirname(os.path.abspath(__file__)))
            line = [x for x in p.stdout.splitlines() if x.startswith("RESULT ")]
            r = json.loads(line[-1][7:]) if line else dict(file=name, stage="process", ok=False, error=("process ended without a result: " + (p.stderr or "")[-300:]))
        except subprocess.TimeoutExpired:
            r = dict(file=name, stage="timeout", ok=False, error=f"no result after {TIMEOUT_S} s")
        r["total_s"] = round(time.time() - t, 1)
        r["kind"] = "sample" if os.sep + "samples" + os.sep in f else "dataset"
        r["over_upload_limit"] = r.get("bytes", os.path.getsize(f)) > UPLOAD_LIMIT
        exp = SAMPLE_EXPECTED.get(name) or expected_for(name)
        r["expected"] = exp
        if exp and r.get("detected"):
            det = r["detected"]
            r["match"] = {k: (det.get(k) == exp.get(k)) for k in ("label_col", "benign_label", "source_col", "time_col")}
            if not r["match"]["benign_label"] and (exp.get("label_map") or {}).get(str(det.get("benign_label"))) == exp.get("benign_label"):
                r["match"]["benign_label"] = True          # the hand-made settings rename the raw value (for example '---' to 'normal')
            r["notes"] = NOTES.get(name, "")
            exp.pop("label_map", None)
        results.append(r)
        print(name, "ok" if r.get("ok") else "FAIL", r.get("stage"), r.get("total_s"), r.get("match"), (r.get("error") or "")[:160], flush=True)
        save("matrix_results.json", results)
    print("files", len(results), "ran", sum(1 for r in results if r.get("ok")))


if __name__ == "__main__":
    main()
