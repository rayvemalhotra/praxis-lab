"""N-BaIoT (UCI 442): nine IoT devices, each with a benign CSV and attack CSVs packed in .rar files (gafgyt and mirai).
Extracts the zip and every .rar with bsdtar (libarchive reads RAR), then builds one table with a device column (the host)
and an attack_type column, sampled per file.

    python3 build_nbaiot.py nbaiot.zip OUT.csv [--per-file 2500]
"""
import argparse
import glob
import os
import re
import shutil
import subprocess
import tempfile

import numpy as np
import pandas as pd

ap = argparse.ArgumentParser()
ap.add_argument("zip")
ap.add_argument("out")
ap.add_argument("--per-file", type=int, default=2500)
a = ap.parse_args()
rng = np.random.RandomState(0)
work = tempfile.mkdtemp(prefix="nbaiot_")
subprocess.run(["bsdtar", "-xf", a.zip, "-C", work], check=True)
for r in glob.glob(os.path.join(work, "**", "*.rar"), recursive=True):
    dest = r[:-4]
    os.makedirs(dest, exist_ok=True)
    subprocess.run(["bsdtar", "-xf", r, "-C", dest], check=True)
    os.remove(r)
csvs = sorted(glob.glob(os.path.join(work, "**", "*.csv"), recursive=True))
print(len(csvs), "csv files after extraction")
frames = []
for n in csvs:
    rel = os.path.relpath(n, work)
    parts = rel.split(os.sep)
    device = next((p for p in parts if re.search(r"(Doorbell|Thermostat|Monitor|Camera|Webcam)", p)), parts[0])
    low = rel.lower()
    base = os.path.basename(n).replace(".csv", "")
    if "benign" in low:
        attack = "benign"
    elif "gafgyt" in low:
        attack = f"gafgyt_{base}"
    elif "mirai" in low:
        attack = f"mirai_{base}"
    else:
        attack = base
    d = pd.read_csv(n, low_memory=False)
    if len(d) > a.per_file:
        d = d.sample(a.per_file, random_state=rng)
    d["device"] = device
    d["attack_type"] = attack
    frames.append(d)
    print(rel, len(d), flush=True)
df = pd.concat(frames, ignore_index=True).sample(frac=1.0, random_state=0).reset_index(drop=True)
df.to_csv(a.out, index=False)
print(df.shape, df.attack_type.value_counts().to_dict(), df.device.value_counts().to_dict())
shutil.rmtree(work, ignore_errors=True)
