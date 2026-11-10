"""The same hostile files through the real page in a real browser (needs Playwright; skipped when it is not installed).
Uploads on the Evaluate page: a table full of script tags (a dialog opening = script ran), the 13-byte file that ends
pandas on Linux, a binary file named .csv. After each: is there a traceback on the page, did a script run, is the
server still alive?

    python3 tests/pressure/ui_upload.py             writes qa/ui_upload_results.json   (THREATPRINT_PY = the Python of the install)
    python3 tests/pressure/ui_upload.py --patched   the same against a copy of the page with patch P1 of qa/APP_PATCHES.md applied in
                                                    memory (app.py itself is not touched); writes qa/ui_upload_results_patched.json
"""
import io
import os
import subprocess
import sys
import tempfile
import time
import urllib.request

from common import ROOT, save

PORT = int(os.environ.get("TP_UI_PORT", "8782"))
PY = os.environ.get("THREATPRINT_PY") or sys.executable


def alive():
    try:
        return urllib.request.urlopen(f"http://127.0.0.1:{PORT}/_stcore/health", timeout=2).status == 200
    except Exception:
        return False


PATCHED = "--patched" in sys.argv
ENTRY = '''import os, re, sys
ROOT = os.environ["TP_ROOT"]
sys.path.insert(0, ROOT)
src = open(os.path.join(ROOT, "app.py"), encoding="utf-8").read()
P1 = """def _read_upload(up):
    df = engine.read_table(up, up.name)
    for note in df.attrs.get("notes", []):
        st.caption(f"Note: {note}.")
    return df


"""
new = re.sub(r"def _read_upload\\(up\\):\\n(?:(?:    .*)?\\n)+?(?=\\S)", lambda m: P1, src, count=1)
assert new != src, "patch P1 did not apply: _read_upload was not found"
exec(compile(new, os.path.join(ROOT, "app.py"), "exec"), {"__name__": "__main__", "__file__": os.path.join(ROOT, "app.py")})
'''


def start():
    env = dict(os.environ, TP_OPEN="1", TP_ROOT=ROOT)
    script = "app.py"
    if PATCHED:
        script = os.path.join(tempfile.mkdtemp(prefix="tp_patched_"), "app_with_p1.py")
        open(script, "w").write(ENTRY)
    for k in ("TP_PAGE", "TP_PASSWORD", "PRAXIS_LAB_PAGE", "PRAXIS_LAB_PASSWORD"):
        env.pop(k, None)
    srv = subprocess.Popen([PY, "-m", "streamlit", "run", script, "--server.port", str(PORT), "--server.address", "127.0.0.1", "--server.headless", "true"],
                           cwd=ROOT, env=env, stdout=open(os.path.join(ROOT, "qa", "_ui_server.log"), "w"), stderr=subprocess.STDOUT)
    for _ in range(60):
        time.sleep(1)
        if alive():
            break
    return srv


def main():
    results = []
    try:
        from playwright.sync_api import sync_playwright
    except Exception:
        results.append(dict(test="browser upload test", ok=None, evidence="Playwright is not installed here; not run"))
        save("ui_upload_results.json", results)
        print(results)
        return results
    import hostile
    tmp = tempfile.mkdtemp(prefix="tp_ui_")
    files = {}
    for name, key in (("script_tags.csv", "file: script and image tags in column names, label values and host names"),
                      ("impossible_exponent.csv", "file: a cell '1e2147483648' (a number with an impossible exponent; pandas 2.3 on Linux dies on it)"),
                      ("binary.csv", "file: not a table at all (random bytes)"), ("semicolons.csv", "file: semicolon delimiter")):
        p = os.path.join(tmp, name)
        open(p, "wb").write(hostile.CASES[key][0]())
        files[name] = p
    srv = start()
    try:
        with sync_playwright() as pw:
            b = pw.chromium.launch()
            for name, path in files.items():
                if not alive():
                    srv = start()
                pg = b.new_page(viewport={"width": 1440, "height": 1000})
                dialogs = []
                pg.on("dialog", lambda d: (dialogs.append(d.message), d.dismiss()))
                pg.goto(f"http://127.0.0.1:{PORT}/evaluate", wait_until="networkidle")
                time.sleep(4)
                up = pg.locator("input[type=file]")
                if not up.count():
                    results.append(dict(test=f"browser upload: {name}", ok=None, evidence="no file input found on the Evaluate page (the page changed)"))
                    pg.close()
                    continue
                up.first.set_input_files(path)
                time.sleep(7)
                ran = False
                btn = pg.get_by_role("button", name="Run the evaluation")
                if alive() and btn.count():
                    btn.first.click()
                    for _ in range(30):
                        time.sleep(2)
                        if pg.get_by_text("Scorecard", exact=False).count() or pg.locator("[data-testid='stAlertContainer']").count() > 1 or not alive():
                            break
                    ran = True
                    time.sleep(3)
                    for ex in pg.locator("[data-testid='stExpander'] summary").all()[:12]:
                        try:
                            ex.click()
                            time.sleep(0.2)
                        except Exception:
                            pass
                up_alive = alive()
                trace = pg.locator("[data-testid='stException']").count() if up_alive else 0
                injected = pg.evaluate("document.querySelectorAll('img[onerror], svg[onload], [data-testid=stMain] script').length") if up_alive else 0
                text = pg.locator("[data-testid='stMain']").inner_text()[:20000] if up_alive else ""
                msg = next((ln for ln in text.split("\n") if "could not be read" in ln or "The run stopped" in ln or "kept as text" in ln or "separated by" in ln), "")
                ok = up_alive and not trace and not dialogs and not injected
                results.append(dict(test=f"browser upload: {name}", ok=ok,
                                    evidence=f"server alive: {up_alive}; tracebacks on the page: {trace}; scripts that ran: {len(dialogs)}; injected elements: {injected}; evaluation started: {ran}; page said: {msg[:150] or 'nothing special'}"))
                print(results[-1], flush=True)
                pg.close()
            b.close()
    finally:
        srv.terminate()
    save("ui_upload_results_patched.json" if PATCHED else "ui_upload_results.json", results)
    return results


if __name__ == "__main__":
    main()
