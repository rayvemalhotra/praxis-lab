"""Section B: malformed and hostile tables. Each case goes through the path of the upload page: read the file (when the
case is a file), engine.inspect, accept every suggestion, engine.run with a tiny budget, engine.sanitize.

A case passes when it either runs or is refused with a sentence written for a person (engine.DataProblem, or a ValueError
from the reader). Anything else (KeyError, IndexError, a NumPy or scikit-learn message, a crash of the process, a hang)
fails. Every case runs in its own process with a time limit, because one of them is a 13-byte file that kills the
process of pandas 2.3 on Linux.

    python tests/pressure/hostile.py            all cases, writes qa/hostile_results.json
    python tests/pressure/hostile.py --one NAME one case, prints one JSON line
"""
import io
import json
import os
import subprocess
import sys
import time

import numpy as np
import pandas as pd

from common import auto_cfg, save

LIMIT_S = 120


def base(n_hosts=12, per=120, seed=0):
    """A small well-formed table: 12 hosts, 4 attack types and normal, 6 behavior numbers, a clock."""
    rng = np.random.default_rng(seed)
    rows = []
    kinds = ["normal", "normal", "dos", "scan", "mitm", "brute"]
    for h in range(n_hosts):
        for i in range(per):
            k = kinds[(i // 10 + h) % len(kinds)]
            m = dict(normal=0, dos=5, scan=2, mitm=-3, brute=8)[k]
            rows.append(dict(timestamp=1_700_000_000 + h * 5000 + i * 2, device_ip=f"10.0.0.{h + 1}", src_port=int(rng.integers(1024, 65000)),
                             pkts=rng.normal(10 + m, 2), bytes_out=rng.normal(500 + 40 * m, 50), duration=abs(rng.normal(1 + 0.1 * m, 0.2)),
                             syn_count=rng.poisson(2 + abs(m)), rate=rng.normal(3 + m, 1), size_mean=rng.normal(200 - 10 * m, 20), attack_type=k))
    return pd.DataFrame(rows)


def csv_bytes(df, **kw):
    return df.to_csv(index=False, **kw).encode()


CASES = {}


def case(name, expect):
    def deco(fn):
        CASES[name] = (fn, expect)
        return fn
    return deco


# ---- tables that should RUN
@case("well-formed base table", "run")
def _():
    return base()


@case("labels with stray spaces and mixed case (' Normal ', 'DoS ')", "run")
def _():
    d = base()
    d["attack_type"] = d.attack_type.map(lambda v: {"normal": " Normal ", "dos": "DoS ", "scan": " scan"}.get(v, v))
    return d


@case("constant column and all-empty column among the numbers", "run")
def _():
    d = base()
    d["const"] = 7
    d["empty"] = np.nan
    return d


@case("infinite values in a number column", "run")
def _():
    d = base()
    d.loc[d.index[::7], "rate"] = np.inf
    d.loc[d.index[::11], "rate"] = -np.inf
    return d


@case("unicode, emoji and very long headers", "run")
def _():
    d = base()
    return d.rename(columns={"pkts": "paquets_émis_\U0001F680", "rate": "速度", "size_mean": "x" * 300, "duration": "مدة"})


@case("2,000 number columns", "run")
def _():
    d = base(per=120)
    rng = np.random.default_rng(1)
    extra = pd.DataFrame(rng.normal(size=(len(d), 2000)).astype("float32"), columns=[f"f{i}" for i in range(2000)])
    return pd.concat([d, extra], axis=1)


@case("numeric labels (0 = normal, 1..4 = attack types)", "run")
def _():
    d = base()
    d["attack_type"] = d.attack_type.map(dict(normal=0, dos=1, scan=2, mitm=3, brute=4))
    return d


@case("mixed types in one number column (numbers and words)", "run")
def _():
    d = base()
    d["rate"] = d.rate.astype(object)
    d.loc[d.index[::50], "rate"] = "n/a"
    return d


@case("no host column and no clock", "run")
def _():
    return base().drop(columns=["device_ip", "timestamp"])


@case("file: UTF-8 byte order mark at the start", "run")
def _():
    return b"\xef\xbb\xbf" + csv_bytes(base())


@case("file: semicolon delimiter", "run")
def _():
    return csv_bytes(base(), sep=";")


@case("file: tab delimiter", "run")
def _():
    return csv_bytes(base(), sep="\t")


@case("file: Latin-1 bytes in a header (not UTF-8)", "run")
def _():
    return csv_bytes(base()).replace(b"size_mean", "taille_moyenné".encode("latin-1"))


@case("file: duplicate column names", "run")
def _():
    return csv_bytes(base()).replace(b"size_mean", b"rate", 1)


@case("file: a cell '1e2147483648' (a number with an impossible exponent; pandas 2.3 on Linux dies on it)", "run")
def _():
    d = base()
    d["payload"] = "abc"
    d.loc[d.index[5], "payload"] = "1e2147483648"
    d.loc[d.index[9], "payload"] = "32342e33302037352e37350d0a"
    d["scale"] = d.rate.round(2).astype(object)          # a number column whose very first cell is the dangerous one:
    d.loc[d.index[0], "scale"] = "1e2147483648"          # the CSV reader itself meets it before any other code runs
    return csv_bytes(d)


@case("table: the same impossible-exponent cell inside a DataFrame (Parquet path)", "run")
def _():
    d = base()
    d["payload"] = "abc"
    d.loc[d.index[5], "payload"] = "1e2147483648"
    return d


@case("file: Parquet with a nested (list) column", "run")
def _():
    d = base()
    d["nested"] = [[1, 2, 3]] * len(d)
    b = io.BytesIO()
    d.to_parquet(b, index=False)
    return ("x.parquet", b.getvalue())


@case("file: script and image tags in column names, label values and host names", "run")
def _():
    d = base()
    d = d.rename(columns={"pkts": "<script>alert(1)</script>", "rate": "<img src=x onerror=alert(2)>", "duration": "a\"b'c`d"})
    d["attack_type"] = d.attack_type.replace({"dos": "<script>alert('dos')</script>", "scan": "<b>scan</b>**md**"})
    d["device_ip"] = d.device_ip.replace({"10.0.0.1": "<svg onload=alert(3)>"})
    return csv_bytes(d)


# ---- tables that must be REFUSED with a sentence for a person
@case("file: empty (0 bytes)", "refuse")
def _():
    return b""


@case("file: header only, no records", "refuse")
def _():
    return b"a,b,attack_type\n"


@case("file: one record", "refuse")
def _():
    return csv_bytes(base().head(1))


@case("file: not a table at all (random bytes)", "refuse")
def _():
    return bytes(np.random.default_rng(0).integers(0, 256, 5000, dtype=np.uint8))


@case("file: a PDF named .csv (wrong extension)", "refuse")
def _():
    return b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n1 0 obj\n<< /Type /Catalog >>\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF\n" * 3


@case("file: a CSV named .parquet (wrong extension)", "refuse")
def _():
    return ("x.parquet", csv_bytes(base()))


@case("no label column", "refuse")
def _():
    return base().drop(columns=["attack_type"]).rename(columns={"device_ip": "h", "src_port": "p"})


@case("one class only (all normal)", "refuse")
def _():
    d = base()
    d["attack_type"] = "normal"
    return d


@case("all attack, no normal records", "refuse")
def _():
    d = base()
    return d[d.attack_type != "normal"]


@case("two classes (normal and one attack type)", "refuse")
def _():
    d = base()
    return d[d.attack_type.isin(["normal", "dos"])]


@case("columns named like the tool's own working columns (y, org, part, event, source)", "run")
def _():
    d = base()
    d["y"] = d.pkts * 2
    d["org"] = "ACME"
    d["part"] = np.arange(len(d))
    return d.rename(columns={"timestamp": "event", "device_ip": "source"})


@case("missing labels in some records", "run")
def _():
    d = base()
    d.loc[d.index[::40], "attack_type"] = np.nan
    return d


@case("three attack types with 5 records each (runs, with a warning in the scorecard)", "run")
def _():
    d = base()
    return pd.concat([d[d.attack_type == "normal"]] + [d[d.attack_type == k].head(5) for k in ("dos", "scan", "mitm")])


@case("no number columns (text only)", "refuse")
def _():
    d = base()
    return pd.DataFrame(dict(a=d.device_ip, b=d.attack_type.str.upper(), c="x", attack_type=d.attack_type))


@case("every number column empty", "refuse")
def _():
    d = base()
    for c in ("pkts", "bytes_out", "duration", "syn_count", "rate", "size_mean", "src_port"):
        d[c] = np.nan
    return d


@case("20 records in all", "refuse")
def _():
    return base(n_hosts=2, per=10)


TINY = dict(name="tiny (pressure test)", passes=2, local_epochs=1, resamples=50, trace_seeds=1, trace_trees=20, trace_permutations=5,
            trace_perm_trees=10, trace_perm_rows=500, seeds=(0,), max_rows=5000, nothing_withheld_check=False)


def read(name, data):
    """The reader of the upload page: threatprint_agent.read_table when it exists, else what the page did before (pandas alone)."""
    import threatprint_agent as agent
    if hasattr(agent, "read_table"):
        return agent.read_table(io.BytesIO(data), name)
    return pd.read_parquet(io.BytesIO(data)) if name.endswith(".parquet") else pd.read_csv(io.BytesIO(data), low_memory=False)


def human(e):
    """Was this exception written for a person?"""
    import engine
    dp = getattr(engine, "DataProblem", None)
    if dp is not None:
        return isinstance(e, dp) and not getattr(e, "unexpected", False)
    return type(e) is ValueError and any(k in str(e) for k in ("at least three attack types", "normal validation records", "usable number columns"))


def one(name):
    import engine
    fn, expect = CASES[name]
    obj = fn()
    out = dict(case=name, expect=expect)
    t = time.time()
    try:
        if isinstance(obj, tuple):
            df = read(*obj)
        elif isinstance(obj, (bytes, bytearray)):
            df = read("x.csv", bytes(obj))
        else:
            df = obj
        out["shape"] = list(df.shape)
        ins = engine.inspect(df)
        if not ins["label_col"]:
            out.update(outcome="refused", message="No label column was recognized (the page asks the person to pick it).", human=True)
            return out
        cfg, numbers = auto_cfg(df, ins)
        card = engine.run(cfg, frame=df, budget=engine.Budget(**TINY))
        engine.sanitize(df, cfg["label_col"], [c for c in card["step2"]["kept"] if c in df.columns])
        json.dumps(card, default=float)
        out.update(outcome="ran", kept=card["step2"]["kept_numbers"], organizations=card["rules"]["companies"][:50])
    except Exception as e:  # noqa
        out.update(outcome="refused", message=f"{type(e).__name__}: {e}"[:300], human=bool(human(e)))
    out["seconds"] = round(time.time() - t, 1)
    return out


def main():
    if "--one" in sys.argv:
        print("RESULT " + json.dumps(one(sys.argv[sys.argv.index("--one") + 1]), default=str))
        return
    results = []
    for name, (fn, expect) in CASES.items():
        t = time.time()
        try:
            p = subprocess.run([sys.executable, os.path.abspath(__file__), "--one", name], capture_output=True, text=True, timeout=LIMIT_S, cwd=os.path.dirname(os.path.abspath(__file__)))
            line = [x for x in p.stdout.splitlines() if x.startswith("RESULT ")]
            r = json.loads(line[-1][7:]) if line else dict(case=name, expect=expect, outcome="crash", message=f"the process died (exit code {p.returncode}) " + (p.stderr or "")[-160:].replace("\n", " "))
        except subprocess.TimeoutExpired:
            r = dict(case=name, expect=expect, outcome="hang", message=f"no result after {LIMIT_S} s")
        r["seconds"] = r.get("seconds", round(time.time() - t, 1))
        if r["outcome"] == "ran":
            r["ok"] = expect == "run"
            r["note"] = "" if r["ok"] else "ran, but the table cannot support an evaluation and should have been refused"
        elif r["outcome"] == "refused":
            r["ok"] = bool(r.get("human")) and expect == "refuse"
            r["note"] = "" if r["ok"] else ("refused although it should run" if r.get("human") else "ended with an error that is not written for a person")
        else:
            r["ok"] = False
            r["note"] = r["outcome"]
        results.append(r)
        print(("PASS " if r["ok"] else "FAIL ") + name[:70].ljust(70), r["outcome"], (r.get("message") or "")[:150], flush=True)
        save("hostile_results.json" if "--tag" not in sys.argv else f"hostile_results_{sys.argv[sys.argv.index('--tag') + 1]}.json", results)
    print("cases", len(results), "passed", sum(1 for r in results if r["ok"]))
    return results


if __name__ == "__main__":
    main()
