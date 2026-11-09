"""Open every page (and, on the results page, every dataset) in a headless browser and write the rendered text to one
Markdown file, so that the praxis checker can read what a person sees.

    python3 tests/render_text.py OUT.md                       every page, every dataset
    python3 tests/render_text.py OUT.md ",definitions"        only the pages named (empty = start page)
    python3 tests/render_text.py OUT.md results 0-11          results page, datasets 0 to 11 (0-based, inclusive)

Reuses an app already serving on port 8766; otherwise starts one (PRAXIS_PY = the Python of the install).
"""
import glob
import json
import os
import subprocess
import sys
import time
import urllib.request

from playwright.sync_api import sync_playwright

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = sys.argv[1] if len(sys.argv) > 1 else "/tmp/rendered.md"
PAGES = sys.argv[2].split(",") if len(sys.argv) > 2 else ["", "results", "definitions", "evaluate", "sanitize", "students"]
RANGE = [int(x) for x in sys.argv[3].split("-")] if len(sys.argv) > 3 else None
PY = os.environ.get("PRAXIS_PY", sys.executable)
PORT = 8766


def healthy():
    try:
        urllib.request.urlopen(f"http://127.0.0.1:{PORT}/_stcore/health", timeout=1)
        return True
    except Exception:
        return False


def open_expanders(pg):
    for ex in pg.locator("[data-testid='stExpander'] summary").all():
        try:
            ex.click()
            time.sleep(0.2)
        except Exception:
            pass


GATE_PW = os.environ.get("PRAXIS_LAB_PASSWORD") or "render-check"
srv = None
if not healthy():
    env = dict(os.environ, PRAXIS_LAB_PASSWORD=GATE_PW)
    srv = subprocess.Popen([os.path.join(os.path.dirname(PY), "streamlit"), "run", "app.py", "--server.port", str(PORT), "--server.address", "127.0.0.1"],
                           cwd=ROOT, stdout=open("/tmp/st2.log", "w"), stderr=subprocess.STDOUT, env=env)
    for _ in range(40):
        time.sleep(1)
        if healthy():
            break
out = []
try:
    with sync_playwright() as p:
        b = p.chromium.launch(executable_path=os.environ.get("PW_CHROME") or None)
        pg = b.new_page(viewport={"width": 1400, "height": 6000})
        for path in PAGES:
            pg.goto(f"http://127.0.0.1:{PORT}/{path}", wait_until="load", timeout=60000)
            print("opened", path or "start", flush=True)
            time.sleep(4)
            if pg.locator("input[type='password']").count():          # the access gate
                pg.locator("input[type='password']").fill(GATE_PW)
                pg.get_by_role("button", name="Enter").click()
                time.sleep(5)
                pg.goto(f"http://127.0.0.1:{PORT}/{path}", wait_until="load", timeout=60000)
                time.sleep(4)
            if path == "results":
                names = [json.load(open(jf))["name"] for jf in sorted(glob.glob(os.path.join(ROOT, "results", "*.json"))) if not os.path.basename(jf).startswith("_")]
                for i, name in enumerate(names):
                    if RANGE and not (RANGE[0] <= i <= RANGE[1]):
                        continue
                    box = pg.locator("[data-testid='stSelectbox'] input").first
                    box.click()
                    time.sleep(0.4)
                    box.fill(name[:40])
                    time.sleep(0.8)
                    opts = pg.locator("[role='option']")
                    if opts.count():
                        opts.first.click()
                        time.sleep(2.5)
                    open_expanders(pg)
                    txt = pg.locator("[data-testid='stMain']").inner_text()
                    assert name[:30] in txt, f"dataset {name} did not open"
                    print("  dataset", i, name[:40], flush=True)
                    out.append(f"\n\n## results page, dataset {i}: {name}\n\n" + txt)
            else:
                open_expanders(pg)
                out.append(f"\n\n## page {path or 'start'}\n\n" + pg.locator("[data-testid='stMain']").inner_text())
        b.close()
    open(OUT, "w").write("# Praxis Lab rendered pages\n" + "".join(out))
    print("wrote", OUT)
finally:
    if srv is not None:
        srv.terminate()
