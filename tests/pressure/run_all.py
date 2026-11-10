"""The pressure suite in one command.

    python tests/pressure/run_all.py            everything this machine can run (about 12 minutes on the Mac with the datasets)
    python tests/pressure/run_all.py --quick    without the 19 library datasets, the 200 MB file and the card reruns (about 5 minutes)
    python tests/pressure/run_all.py --report   only rebuild qa/PRESSURE_TEST_REPORT.md from the result files in qa/

Each part runs in its own process and writes a result file in qa/; the report is built from those files, so parts run
on two machines (the Mac for the heavy ones, a Linux box for the browser and the dependency audit) end up in one report.
Parts that need something this machine does not have (Playwright, pip-audit, git, the dataset folder) are skipped and say so.
Exit code 0 = no failed test outside the ones that wait for a patch in app.py (qa/APP_PATCHES.md).
"""
import json
import os
import shutil
import subprocess
import sys
import time

from common import DATASETS, QA, ROOT, load

HERE = os.path.dirname(os.path.abspath(__file__))
QUICK = "--quick" in sys.argv
WAITING = ("csv_safe", "server-side limit on password guesses", "no error box", "impossible_exponent", "hostile fingerprint through the real page")      # tests that pass once qa/APP_PATCHES.md is applied


def part(name, args, timeout, python=None):
    t = time.time()
    print(f"== {name}", flush=True)
    try:
        p = subprocess.run([python or sys.executable] + args, cwd=HERE, timeout=timeout, capture_output=True, text=True)
        tail = (p.stdout or "").strip().splitlines()[-1:] or [(p.stderr or "").strip()[-200:]]
        print(f"   {tail[0][:160]}  ({time.time() - t:.0f} s)", flush=True)
    except subprocess.TimeoutExpired:
        print(f"   no result after {timeout} s", flush=True)


def run():
    have_data = os.path.isdir(DATASETS) and len([f for f in os.listdir(DATASETS) if f.endswith(".csv")]) >= 10
    part("determinism: the built-in example against the saved baseline", ["baseline.py", "check"], 300)
    part("B. malformed and hostile tables", ["hostile.py"], 1500)
    part("C. injection", ["injection.py"], 600)
    part("D. fingerprint and agent", ["fingerprint.py"], 900)
    part("E. access gate and server", ["gate_probe.py"], 600)
    part("F. concurrency", ["concurrency.py", "2"] if QUICK else ["concurrency.py", "2", "6"], 900)
    part("A and H. ingestion matrix" + (" (sample files only)" if QUICK or not have_data else ""), ["matrix.py"] + (["--only", "samples"] if QUICK or not have_data else []), 7200)
    if not QUICK and have_data:
        part("B. a 200 MB table", ["bigfile.py"], 2400)
        part("library cards rerun (iec104, dnp3, cidds001)", ["reproduce_card.py", "iec104", "dnp3", "cidds001"], 3600)
    if shutil.which("git") and os.path.isdir(os.path.join(ROOT, ".git")):
        part("G. repository", ["repo_scan.py"], 600)
    part("G. dependency audit", ["audit.py"], 900)
    py3 = shutil.which("python3") or sys.executable
    part("C. the hostile files through the real page (browser)", ["ui_upload.py"], 900, python=os.environ.get("TP_BROWSER_PY") or py3)
    part("C. the same with patch P1 applied to a copy of the page", ["ui_upload.py", "--patched"], 900, python=os.environ.get("TP_BROWSER_PY") or py3)
    part("D. hostile fingerprints through the real page (browser)", ["fp_page_probe.py"], 600, python=os.environ.get("TP_BROWSER_PY") or py3)
    part("E. the sign-in path in a real browser", ["signin_flow.py"], 600, python=os.environ.get("TP_BROWSER_PY") or py3)
    part("F. five browser sessions at once through the real page", ["browser_load.py", "5"], 600, python=os.environ.get("TP_BROWSER_PY") or py3)
    if not QUICK:
        part("F. one protocol-budget run on the largest sample upload", ["protocol_sample.py"], 3600)


def main():
    if "--report" not in sys.argv:
        run()
    import report
    failed = report.write()
    real = [f for f in failed if not any(w in f for w in WAITING)]
    print(f"\nreport: {os.path.join(QA, 'PRESSURE_TEST_REPORT.md')}")
    print(f"failed: {len(failed)} ({len(failed) - len(real)} wait for a patch in app.py)")
    for f in real:
        print("  FAIL", f[:150])
    sys.exit(1 if real else 0)


if __name__ == "__main__":
    main()
