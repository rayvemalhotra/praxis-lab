"""Does today's engine still give the library's result card? Runs one library dataset again with its hand-made settings
and the budget written in the stored card, without the cache, and compares every result value with the stored card in
results/<id>.json. The lists of kept and removed column names are compared as sets (one stored card had a column name
changed by hand, which moved it in the sorted list).

    python tests/pressure/reproduce_card.py iec104 [dnp3 ...]      appends to qa/reproduce_results.json
"""
import json
import os
import sys
import time

import pandas as pd

from common import DATASETS, ROOT, load, save

import baseline
import engine


def flat(o, path=""):
    if isinstance(o, dict):
        for k, v in o.items():
            yield from flat(v, f"{path}/{k}")
    elif isinstance(o, list):
        for i, v in enumerate(o):
            yield from flat(v, f"{path}/{i}")
    else:
        yield path, o


def main():
    NAME = "reproduce_results.json" if not os.environ.get("TP_ENGINE_DIR") else "reproduce_results_last_commit.json"
    out = load(NAME, []) or []
    for did in sys.argv[1:]:
        cfg = json.load(open(os.path.join(DATASETS, "settings", did + ".json")))
        stored = json.load(open(os.path.join(ROOT, "results", did + ".json")))
        frame = pd.concat([pd.read_csv(os.path.join(DATASETS, p), low_memory=False) for p in cfg["paths"]], ignore_index=True)
        t = time.time()
        bud = dict(stored["budget"])
        bud["seeds"] = tuple(bud.get("seeds", (0, 1, 2)))
        budget = engine.Budget(**{k: v for k, v in bud.items() if k in engine.Budget.__dataclass_fields__})
        card = engine.run(cfg, frame=frame, budget=budget)
        na, nb = baseline.numbers(stored), baseline.numbers(card)
        for n_ in (na, nb):
            for k in ("kept", "removed_columns"):
                n_["step2"][k] = sorted(n_["step2"].get(k) or [])
        a, b = dict(flat(na)), dict(flat(nb))
        a = {k: v for k, v in a.items() if not k.startswith("/warnings")}
        diffs, worst = [], 0.0
        for k in sorted(set(a) | set(b)):
            x, y = a.get(k), b.get(k)
            if isinstance(x, (int, float)) and isinstance(y, (int, float)) and not isinstance(x, bool):
                if x != x and y != y:
                    continue
                d = abs(float(x) - float(y))
                worst = max(worst, d)
                if d > 1e-9:
                    diffs.append((k, x, y))
            elif x != y:
                diffs.append((k, x, y))
        r = dict(dataset=did, budget=budget.name, stored_made=stored.get("made"), values_compared=len(a), differences=len(diffs), largest_difference=worst, minutes=round((time.time() - t) / 60, 1),
                 examples=[f"{k}: {x} -> {y}" for k, x, y in diffs[:6]], h1_stored=stored["hypotheses"]["H1"]["gain"], h1_now=card["hypotheses"]["H1"]["gain"])
        out = [x for x in out if x["dataset"] != did] + [r]
        save(NAME, out)
        print(r, flush=True)


if __name__ == "__main__":
    main()
