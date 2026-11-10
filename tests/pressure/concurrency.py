"""Section F: determinism, concurrency and load. Streamlit runs every visitor's script in a thread of one process, so the
test does the same: several engine runs at once in threads of one process, each compared with the serial result.

    python tests/pressure/concurrency.py [N ...]      default: 2 6     writes qa/concurrency_results.json
"""
import json
import os
import resource
import sys
import threading
import time

from common import save

import baseline
import engine


def rss_mb():
    return round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / (1024 * 1024 if sys.platform == "darwin" else 1024))


def main():
    sizes = [int(x) for x in sys.argv[1:] if x.isdigit()] or [2, 6]
    out = dict(machine=dict(platform=sys.platform, cpus=os.cpu_count()), runs=[])
    rss0 = rss_mb()
    t = time.time()
    ref = baseline.numbers(baseline.example_card())
    serial_s = time.time() - t
    again = baseline.numbers(baseline.example_card())
    out["serial"] = dict(seconds=round(serial_s, 1), identical_when_repeated=(baseline.fingerprint(ref) == baseline.fingerprint(again)),
                         h1_gain=ref["hypotheses"]["H1"]["gain"], peak_mb_after_two_serial_runs=rss_mb(), mb_before=rss0)
    print("serial", out["serial"], flush=True)
    for n in sizes:
        cards, errors, waits = [None] * n, [None] * n, [None] * n

        def work(i):
            try:
                cards[i] = baseline.numbers(baseline.example_card())
            except Exception as e:  # noqa
                errors[i] = f"{type(e).__name__}: {e}"

        t = time.time()
        th = [threading.Thread(target=work, args=(i,)) for i in range(n)]
        [x.start() for x in th]
        [x.join() for x in th]
        took = time.time() - t
        diff = [i for i in range(n) if cards[i] is not None and baseline.fingerprint(cards[i]) != baseline.fingerprint(ref)]
        gains = [round(c["hypotheses"]["H1"]["gain"] * 100, 2) for c in cards if c]
        r = dict(at_once=n, seconds=round(took, 1), errors=[e for e in errors if e], different_from_serial=len(diff),
                 h1_gain_points=gains, h1_serial_points=round(ref["hypotheses"]["H1"]["gain"] * 100, 2), peak_mb=rss_mb())
        out["runs"].append(r)
        print(r, flush=True)
    save("concurrency_results.json" if "--tag" not in sys.argv else f"concurrency_results_{sys.argv[sys.argv.index('--tag') + 1]}.json", out)


if __name__ == "__main__":
    main()
