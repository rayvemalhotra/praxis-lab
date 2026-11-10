"""One protocol-budget run on the largest sample upload, through the same path as the upload page: read the file, engine.inspect with
no settings, accept every suggestion, engine.run with the protocol budget (three seeds, 2,000 resamples, the tracing test).
Measured: seconds and peak memory. A local run of the tool, not the run of record.

    python tests/pressure/protocol_sample.py       writes qa/protocol_sample_results.json
"""
import json
import os
import resource
import sys
import time

from common import ROOT, auto_cfg, save

sys.path.insert(0, ROOT)
import engine  # noqa: E402


def main():
    listed = json.load(open(os.path.join(ROOT, "samples", "manifest.json")))
    files = sorted((os.path.getsize(os.path.join(ROOT, "samples", e["file"])), e["file"]) for e in listed)
    size, name = files[-1]
    path = os.path.join(ROOT, "samples", name)
    t = time.time()
    df = engine.read_table(path, name)
    ins = engine.inspect(df)
    cfg, numbers = auto_cfg(df, ins, name)
    read_s = time.time() - t
    t = time.time()
    row = dict(file=name, bytes=size, rows=int(len(df)), columns=int(df.shape[1]), budget="protocol")
    try:
        card = engine.run(cfg, frame=df, budget=engine.PROTOCOL)
        h1, h2 = card["hypotheses"]["H1"], card["hypotheses"]["H2"]
        row.update(ok=True, run_s=round(time.time() - t), read_s=round(read_s, 1), seeds=len(card["seeds"]),
                   H1=dict(gain=round(h1["gain"] * 100, 1), clears=bool(h1["clears"])), H2=dict(gain=round(h2["gain"] * 100, 1), clears=bool(h2["clears"])),
                   traced=bool(card["hypotheses"].get("H3")))
    except Exception as e:
        row.update(ok=False, error=f"{type(e).__name__}: {e}"[:300], run_s=round(time.time() - t))
    row["peak_mb"] = round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / (1024 * 1024 if sys.platform == "darwin" else 1024))
    save("protocol_sample_results.json", row)
    print(row)


if __name__ == "__main__":
    main()
