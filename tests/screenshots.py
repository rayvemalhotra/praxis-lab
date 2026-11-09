"""Start the app, open every page in a headless browser, save full-page screenshots. Sandbox check only.
    python3 tests/screenshots.py OUTDIR [--evaluate]   (--evaluate also runs the built-in example end to end)"""
import os, subprocess, sys, time
from playwright.sync_api import sync_playwright

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = sys.argv[1] if len(sys.argv) > 1 else "/tmp"
PY = os.environ.get("PRAXIS_PY", sys.executable)
PORT = 8765
srv = subprocess.Popen([os.path.join(os.path.dirname(PY), "streamlit"), "run", "app.py", "--server.port", str(PORT), "--server.address", "127.0.0.1"],
                       cwd=ROOT, stdout=open("/tmp/st.log", "w"), stderr=subprocess.STDOUT)
try:
    for _ in range(40):
        time.sleep(1)
        try:
            import urllib.request
            urllib.request.urlopen(f"http://127.0.0.1:{PORT}/_stcore/health", timeout=1)
            break
        except Exception:
            pass
    with sync_playwright() as p:
        b = p.chromium.launch(executable_path=os.environ.get("PW_CHROME") or None)
        pg = b.new_page(viewport={"width": 1400, "height": int(os.environ.get("PW_H", "1000"))})
        for path in ["", "results", "evaluate", "definitions", "sanitize"]:
            pg.goto(f"http://127.0.0.1:{PORT}/{path}", wait_until="networkidle")
            time.sleep(5)
            pg.screenshot(path=f"{OUT}/shot_{path or 'start'}.png", full_page=True)
            print(path, "ok")
        if "--evaluate" in sys.argv:
            pg.goto(f"http://127.0.0.1:{PORT}/evaluate", wait_until="networkidle")
            time.sleep(4)
            pg.get_by_text("Use the built-in example", exact=False).click()
            time.sleep(5)
            pg.get_by_role("button", name="Run the evaluation").click()
            for _ in range(60):
                time.sleep(3)
                if pg.get_by_text("Step 5. Scorecard", exact=False).count():
                    break
            time.sleep(4)
            pg.screenshot(path=f"{OUT}/shot_evaluate_done.png", full_page=True)
            print("evaluate run ok")
        b.close()
finally:
    srv.terminate()
