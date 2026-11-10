"""Start the app, open every page in a headless browser and save one tall screenshot per page. A visual check, not a test.

    python3 tests/screenshots.py OUTDIR        (THREATPRINT_PY = the Python of the install, when it is not the one running this script)
"""
import os
import subprocess
import sys
import time
import urllib.request

from playwright.sync_api import sync_playwright

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = sys.argv[1] if len(sys.argv) > 1 else "/tmp"
PY = os.environ.get("THREATPRINT_PY") or os.environ.get("PRAXIS_PY") or sys.executable
PORT = 8765
PAGES = ["", "results", "evaluate", "sanitize", "agent", "research", "organizations", "definitions", "students"]

env = dict(os.environ, TP_OPEN="1")
env.pop("TP_PAGE", None)
srv = subprocess.Popen([os.path.join(os.path.dirname(PY), "streamlit"), "run", "app.py", "--server.port", str(PORT), "--server.address", "127.0.0.1", "--server.headless", "true"],
                       cwd=ROOT, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
try:
    for _ in range(40):
        time.sleep(1)
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{PORT}/_stcore/health", timeout=1)
            break
        except Exception:
            pass
    with sync_playwright() as p:
        b = p.chromium.launch(executable_path=os.environ.get("PW_CHROME") or None)
        for path in PAGES:
            pg = b.new_page(viewport={"width": 1440, "height": 900})
            pg.goto(f"http://127.0.0.1:{PORT}/{path}", wait_until="networkidle")
            time.sleep(5)
            h = pg.evaluate("document.querySelector('.stMainBlockContainer').scrollHeight")      # the page scrolls inside the app, so the window is made as tall as the page
            pg.set_viewport_size({"width": 1440, "height": int(h) + 40})
            time.sleep(2.5)
            pg.screenshot(path=os.path.join(OUT, f"{path or 'overview'}.png"))
            print(path or "overview", "ok", h, flush=True)
            pg.close()
        b.close()
finally:
    srv.terminate()
