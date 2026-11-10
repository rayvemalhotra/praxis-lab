"""Section D: the fingerprint and the local agent.

  1. The agent's command line on every sample file: it must write a fingerprint that verifies, and the fingerprint must
     hold no identifier value of the source file (device names, addresses, MAC strings, places, operators, time stamps).
  2. How often the lowest and highest stored quantile equal the true smallest and largest value of a behavior number.
  3. Hostile fingerprint uploads: every one must end in one sentence (DataProblem) or be refused by the digest check.
  4. The "contribute" write path: a digest made of path characters, and a flood of contributions.
  5. The agent's command line on hostile files: one line for the person, no traceback.

    python tests/pressure/fingerprint.py       writes qa/fingerprint_results.json
"""
import copy
import glob
import json
import os
import shutil
import subprocess
import sys
import tempfile

import numpy as np
import pandas as pd

from common import ROOT, save

import engine
import threatprint_agent as agent

AGENT = os.path.join(ROOT, "threatprint_agent.py")
results = []


def add(test, ok, evidence):
    results.append(dict(test=test, ok=ok, evidence=evidence))
    print({True: "PASS", False: "FAIL", None: "NOTE"}[ok], test[:100].ljust(100), "|", str(evidence)[:170], flush=True)


def old_page_logic(data):
    """What the fingerprint page did with an upload before load_fingerprint existed (app.py of 9 November, page_agent)."""
    fp = json.loads(data.decode("utf-8"))
    if fp.get("format") not in agent.FORMATS:
        return "refused: not a fingerprint"
    agent.verify(fp)
    f"{len(fp.get('classes', {}))}{len(fp.get('features', []))}"
    b = fp.get("payload_bytes", 0)
    (f"{b / 1000:.0f} KB" if b >= 1000 else f"{b} bytes")
    agent.readiness(fp)
    for lab, c in fp.get("classes", {}).items():
        f"{c['records']:,}{c.get('family', '')}{[t['id'] + t['name'] + t['matrix'] for t in c.get('techniques', [])]}"
    return "shown"


def main():
    tmp = tempfile.mkdtemp(prefix="tp_fp_")
    samples = sorted(glob.glob(os.path.join(ROOT, "samples", "*.csv")))
    good_fp = None
    # ---- 1 and 2
    for path in samples:
        name = os.path.basename(path)
        out = os.path.join(tmp, name + ".fingerprint.json")
        p = subprocess.run([sys.executable, AGENT, path, "--out", out], capture_output=True, text=True, timeout=300)
        if p.returncode != 0 or not os.path.exists(out):
            add(f"agent on {name}", False, f"exit {p.returncode}: {(p.stderr or p.stdout)[-200:]}")
            continue
        text = open(out).read()
        fp = json.loads(text)
        v = subprocess.run([sys.executable, AGENT, "--verify", out], capture_output=True, text=True)
        add(f"agent on {name}: fingerprint written and its digest verifies", agent.verify(fp) and v.returncode == 0 and "Nothing was sent anywhere" in p.stdout,
            f"{len(fp['classes'])} attack types, {len(fp['features'])} behavior numbers, {os.path.getsize(out) / 1000:.0f} KB on disk")
        good_fp = good_fp or fp
        df = agent.read_table(path)
        ins = agent.inspect(df)
        ident_cols = [c for c in [ins["source_col"], ins["time_col"]] + ins["identifiers"] + ins["text_columns"] if c is not None and df[c].dtype == object]
        values = set()
        for c in ident_cols:
            values |= {str(v) for v in df[c].dropna().unique() if len(str(v)) >= 5}
        leaked = [v for v in values if v in text]
        add(f"fingerprint of {name}: no identifier value of the source file", not leaked,
            f"{len(values):,} distinct identifier values from {len(ident_cols)} columns searched in the file; found: {leaked[:3] if leaked else 'none'}")
        y = df[ins["label_col"]].astype(str).str.strip()
        lo = hi = cells = 0
        for lab, c in fp["classes"].items():
            X = df.loc[y == lab, fp["features"]].apply(pd.to_numeric, errors="coerce")
            q = np.asarray(c["quantiles"], float)
            for j, f in enumerate(fp["features"]):
                cells += 1
                lo += bool(np.isclose(q[0, j], X[f].min(), rtol=1e-5))
                hi += bool(np.isclose(q[-1, j], X[f].max(), rtol=1e-5))
        add(f"fingerprint of {name}: how often the lowest or highest stored quantile equals the true smallest or largest value", None,
            f"of {cells} attack-type and number pairs, the 1% quantile equals the smallest value in {lo} ({lo / cells:.0%}) and the 99% quantile equals the largest in {hi} ({hi / cells:.0%})")

    # ---- 3 hostile fingerprints
    base = json.dumps(good_fp, separators=(",", ":"))

    def mut(fn):
        fp = copy.deepcopy(good_fp)
        fn(fp)
        return json.dumps(fp).encode()

    lab0 = next(iter(good_fp["classes"]))
    hostile = {
        "not JSON (random bytes)": bytes(np.random.default_rng(0).integers(0, 256, 4000, dtype=np.uint8)),
        "not JSON (a CSV file)": b"a,b,c\n1,2,3\n",
        "JSON list instead of an object": b"[1, 2, 3]",
        "JSON string": b"\"threatprint-fingerprint\"",
        "empty file": b"",
        "wrong format name": mut(lambda f: f.update(format="something-else")),
        "format only, every other key missing": json.dumps(dict(format=agent.FORMAT)).encode(),
        "classes is a list": mut(lambda f: f.update(classes=[1, 2])),
        "classes missing": mut(lambda f: f.pop("classes")),
        "features is a number": mut(lambda f: f.update(features=7)),
        "records is a string": mut(lambda f: f["classes"][lab0].update(records="many")),
        "records is 10**400": base.replace('"records":', '"records":1' + "0" * 400 + ', "x":', 1).encode(),
        "NaN among the quantiles": base.replace('"quantiles":[[', '"quantiles":[[NaN,', 1).encode(),
        "Infinity as payload size": base.replace('"payload_bytes":', '"payload_bytes":Infinity,"x":', 1).encode(),
        "image tag as removed_columns_count (ui.stats puts its values into the page unescaped)": mut(lambda f: f.update(removed_columns_count="<img src=x onerror=alert(1)>")),
        "script tag as payload_bytes": mut(lambda f: f.update(payload_bytes="<script>alert(1)</script>")),
        "script tag as a technique name": mut(lambda f: f["classes"][lab0]["techniques"].append(dict(id="<script>", name="<script>alert(1)</script>", matrix="x"))),
        "normal.records is a list": mut(lambda f: f.update(normal=dict(records=[1]))),
        "hosts is a dict": mut(lambda f: f.update(hosts=dict(a=1))),
        "integrity missing": mut(lambda f: f.pop("integrity")),
        "integrity.digest is a path (../../../etc/passwd)": mut(lambda f: f["integrity"].update(digest="../../../etc/passwd")),
        "integrity.digest is a number": mut(lambda f: f["integrity"].update(digest=12345)),
        "quantiles of the wrong shape": mut(lambda f: f["classes"][lab0].update(quantiles=[[1, 2], [3]])),
        "100,000 features": mut(lambda f: f.update(features=["f"] * 100000)),
        "deeply nested JSON (100,000 levels)": b"[" * 100000 + b"]" * 100000,
        "50 MB of JSON": b'{"format":"threatprint-fingerprint","pad":"' + b"x" * 50_000_000 + b'"}',
    }
    old_bad = new_bad = 0
    for name, data in hostile.items():
        try:
            old = old_page_logic(data)
        except RecursionError:
            old = "TRACEBACK RecursionError"
        except Exception as e:  # noqa
            old = f"TRACEBACK {type(e).__name__}"
        raw_shown = old == "shown" and name.startswith("image tag as removed_columns_count")   # ui.stats puts its values into the page unescaped
        old_bad += old.startswith("TRACEBACK") or raw_shown
        try:
            agent.load_fingerprint(data)
            new = "accepted"
        except agent.DataProblem as e:
            new = f"refused: {e}"
        except BaseException as e:  # noqa
            new = f"TRACEBACK {type(e).__name__}: {e}"
        ok = new.startswith("refused")
        new_bad += not ok
        add(f"hostile fingerprint: {name}", ok, f"before: {old + (' (markup from the file put into the page unescaped)' if raw_shown else '')} | now: {new[:110]}")
    add("hostile fingerprints, total", new_bad == 0, f"{len(hostile)} files; before the check {old_bad} ended in a traceback or put markup from the file into the page; now {new_bad} do")

    tampered = copy.deepcopy(good_fp)
    tampered["classes"][lab0]["records"] += 10
    ok = True
    try:
        agent.load_fingerprint(json.dumps(tampered).encode())
    except agent.DataProblem:
        ok = False
    add("tampered fingerprint (one count changed): well-formed, and the digest check refuses it", ok and not agent.verify(tampered), f"verify = {agent.verify(tampered)}")
    add("the genuine fingerprint still loads and verifies; a file of the old format name is still read", agent.verify(agent.load_fingerprint(base.encode()))
        and agent.check_fingerprint(dict(copy.deepcopy(good_fp), format="praxis-lab-fingerprint")) is not None, "load_fingerprint + verify on the agent's own output")

    # ---- 4 the contribute write path
    folder = os.path.join(tmp, "contributions")
    evil = copy.deepcopy(good_fp)
    evil["integrity"]["digest"] = "../../../../tmp/tp_pwned"
    old_name = f"{evil['integrity']['digest'][:16]}.json"
    old_target = os.path.normpath(os.path.join(folder, old_name))
    add("contribute, as the page did it: the file name came from the uploaded digest field", None,
        f"a digest of '../../../../tmp/tp_pwned' gives the file name '{old_name}', which resolves to {old_target} (outside the folder: {not old_target.startswith(folder)}); "
        "only the disabled state of a button stood in the way")
    try:
        engine.save_contribution(evil, folder)
        ok, ev = False, "kept a fingerprint whose digest is a path"
    except agent.DataProblem as e:
        ok, ev = True, f"refused: {e}"
    add("engine.save_contribution refuses a fingerprint whose digest is a path", ok, ev)
    name = engine.save_contribution(copy.deepcopy(good_fp), folder)
    add("engine.save_contribution names the file from the digest it computes itself", bool(__import__("re").fullmatch(r"[0-9a-f]{16}\.json", name)) and os.listdir(folder) == [name], f"file {name}")
    kept = refused = 0
    for i in range(8):
        fp = copy.deepcopy(good_fp)
        fp["removed_columns_count"] = 1000 + i
        fp["integrity"]["digest"] = agent.digest(fp)
        try:
            engine.save_contribution(fp, folder, max_files=5)
            kept += 1
        except agent.DataProblem:
            refused += 1
    add("contributions have an upper limit (here 5 files): a flood cannot fill the disk", len(os.listdir(folder)) == 5 and refused == 4, f"8 more contributions sent: {kept} kept, {refused} refused, {len(os.listdir(folder))} files in the folder")

    # ---- 5 the agent's command line on hostile files
    cases = {"empty.csv": b"", "binary.csv": bytes(range(256)) * 20, "nolabel.csv": b"a,b,c\n1,2,3\n4,5,6\n7,8,9\n", "pdf.csv": b"%PDF-1.4 not a table",
             "crash_cell.csv": b"a,b,attack_type\n1e2147483648,1,dos\n2,2,normal\n3,3,scan\n"}
    bad = []
    for fname, data in cases.items():
        f = os.path.join(tmp, fname)
        open(f, "wb").write(data)
        p = subprocess.run([sys.executable, AGENT, f], capture_output=True, text=True, timeout=120)
        if "Traceback" in p.stderr or p.returncode < 0:
            bad.append(f"{fname}: exit {p.returncode} {p.stderr.strip()[-80:]}")
    p = subprocess.run([sys.executable, AGENT, os.path.join(tmp, "no_such_file.csv")], capture_output=True, text=True)
    p2 = subprocess.run([sys.executable, AGENT, samples[0], "--label", "no_such_column", "--out", os.path.join(tmp, "x.json")], capture_output=True, text=True)
    p3 = subprocess.run([sys.executable, AGENT, "--verify", os.path.join(tmp, "binary.csv")], capture_output=True, text=True)
    for tag, q in (("missing file", p), ("--label with a column that does not exist", p2), ("--verify on a binary file", p3)):
        if "Traceback" in q.stderr or q.returncode <= 0:
            bad.append(f"{tag}: exit {q.returncode} {q.stderr.strip()[-80:]}")
    add("agent command line on 8 hostile inputs: one line for the person, no traceback, no dead process", not bad, bad or "empty file, binary file, no label, a PDF, the cell that ends pandas, a missing file, a wrong --label, --verify on a binary file")
    src = open(AGENT, encoding="utf-8").read()
    net = [w for w in ("import socket", "import urllib", "import requests", "import http", "urlopen", "import ftplib", "import smtplib", "subprocess") if w in src]
    add("the agent file has no network code and starts no other program", not net, net or "none of: socket, urllib, requests, http, ftplib, smtplib, subprocess")
    shutil.rmtree(tmp, ignore_errors=True)
    save("fingerprint_results.json", results)
    return results


if __name__ == "__main__":
    main()
