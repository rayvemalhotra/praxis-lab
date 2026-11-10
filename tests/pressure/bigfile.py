"""A table at the upload limit (200 MB): how long the reader, the column detection and a quick look take, and how much
memory the process needs. Builds the file in the system's temporary folder from a library dataset and deletes it.

    python tests/pressure/bigfile.py           writes qa/bigfile_results.json   (--one PATH is the measured child)
"""
import json
import os
import resource
import subprocess
import sys
import tempfile
import time

from common import DATASETS, auto_cfg, save

TARGET = 200 * 1000 * 1000


def child(path):
    import engine
    out = dict(bytes=os.path.getsize(path))
    t = time.time()
    df = engine.read_table(path)
    out.update(read_s=round(time.time() - t, 1), rows=len(df), columns=df.shape[1])
    t = time.time()
    ins = engine.inspect(df)
    out.update(inspect_s=round(time.time() - t, 1), label_col=ins["label_col"])
    cfg, _ = auto_cfg(df, ins)
    t = time.time()
    card = engine.run(cfg, frame=df, budget=engine.QUICK)
    out.update(quick_s=round(time.time() - t, 1), h1=round(card["hypotheses"]["H1"]["gain"] * 100, 1),
               peak_mb=round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / (1024 * 1024 if sys.platform == "darwin" else 1024)))
    print("RESULT " + json.dumps(out))


def main():
    if "--one" in sys.argv:
        return child(sys.argv[sys.argv.index("--one") + 1])
    src = os.path.join(DATASETS, "cic_ids2017.csv")
    path = os.path.join(tempfile.gettempdir(), "threatprint_pressure_200mb.csv")
    data = open(src, "rb").read()
    head, body = data.split(b"\n", 1)
    with open(path, "wb") as fh:
        fh.write(head + b"\n")
        n = len(head) + 1
        while n + len(body) <= TARGET:
            fh.write(body)
            n += len(body)
        fh.write(body[:body.rfind(b"\n", 0, max(0, TARGET - n)) + 1])
    try:
        p = subprocess.run([sys.executable, os.path.abspath(__file__), "--one", path], capture_output=True, text=True, timeout=1800, cwd=os.path.dirname(os.path.abspath(__file__)))
        line = [x for x in p.stdout.splitlines() if x.startswith("RESULT ")]
        r = json.loads(line[-1][7:]) if line else dict(error=(p.stderr or "")[-400:], exit=p.returncode)
    except subprocess.TimeoutExpired:
        r = dict(error="no result after 30 minutes")
    finally:
        os.remove(path)
    r["machine"] = dict(platform=sys.platform, cpus=os.cpu_count())
    save("bigfile_results.json", r)
    print(r)


if __name__ == "__main__":
    main()
