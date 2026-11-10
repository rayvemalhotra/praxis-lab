"""The scorecard of the built-in example under the quick budget, reduced to its numbers. Used to show that an engine
change did not move any result:   python tests/pressure/baseline.py save | check

The baseline is kept per kind of machine (qa/baseline_example_quick_<system>_<processor>.json): the training numbers of
the example are bit-identical on Linux and macOS, but the tracing forests differ in late decimals between the two, so a
scorecard is only compared with one made on the same kind of machine. The Linux baseline was saved before any engine
change of the pressure test (10 November 2026); on a machine without a baseline, check saves one and says so."""
import hashlib
import json
import os
import platform
import sys

from common import QA

import engine


def numbers(card):
    """Every result number of a scorecard, without the clock, the versions and the date."""
    keep = {k: card[k] for k in ("step1", "step2", "classes", "benign", "companies", "hypotheses", "checks", "verdicts", "sharing_minus_federated") if k in card}
    return json.loads(json.dumps(keep, sort_keys=True, default=float))


def example_card():
    df = engine.example_data()
    ins = engine.inspect(df)
    cfg = dict(name="example", label_col=ins["label_col"], benign_label=ins["benign_label"], source_col=ins["source_col"], time_col=ins["time_col"], drop=ins["identifiers"])
    return engine.run(cfg, frame=df, budget=engine.QUICK)


def baseline_file():
    return os.path.join(QA, f"baseline_example_quick_{platform.system()}_{platform.machine()}.json".lower())


def fingerprint(obj):
    return hashlib.sha256(json.dumps(obj, sort_keys=True).encode()).hexdigest()


if __name__ == "__main__":
    f = baseline_file()
    n = numbers(example_card())
    if sys.argv[1:] == ["save"] or not os.path.exists(f):
        json.dump(dict(sha256=fingerprint(n), numbers=n), open(f, "w"), indent=1)
        print("saved a baseline for this kind of machine" + ("" if sys.argv[1:] == ["save"] else " (there was none to compare with)"), fingerprint(n))
    else:
        old = json.load(open(f))
        same = old["sha256"] == fingerprint(n)
        print("IDENTICAL to the baseline" if same else "DIFFERENT from the baseline", fingerprint(n))
        if not same:
            def walk(a, b, path=""):
                if isinstance(a, dict) and isinstance(b, dict):
                    for k in sorted(set(a) | set(b)):
                        walk(a.get(k), b.get(k), path + "/" + str(k))
                elif a != b:
                    print("  ", path, a, "->", b)
            walk(old["numbers"], n)
        sys.exit(0 if same else 1)
