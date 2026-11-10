"""Section D through the real page: a fingerprint whose removed_columns_count is an image tag with a script handler is
uploaded on the Agent page in a headless browser. Did markup from the file reach the page, and did its script run?

    python3 tests/pressure/fp_page_probe.py      writes qa/fp_page_results.json   (needs Playwright; THREATPRINT_PY = the Python of the install)
"""
import json
import os
import sys
import tempfile
import time

from common import ROOT, save

import ui_upload


def main():
    results = []
    try:
        from playwright.sync_api import sync_playwright
    except Exception:
        save("fp_page_results.json", [dict(test="hostile fingerprint through the real page", ok=None, evidence="Playwright is not installed here; not run")])
        return
    good = json.load(open(os.path.join(ROOT, "samples", "sample_organization_water_utility_SYNTHETIC.fingerprint.example.json")))
    tmp = tempfile.mkdtemp(prefix="tp_fpui_")
    cases = {"image tag with a script handler as removed_columns_count": dict(good, removed_columns_count="<img src=x onerror=alert(1) id=tp_injected>"),
             "a JSON list": [1, 2, 3]}
    srv = ui_upload.start()
    try:
        with sync_playwright() as pw:
            b = pw.chromium.launch()
            for name, obj in cases.items():
                path = os.path.join(tmp, "hostile.fingerprint.json")
                json.dump(obj, open(path, "w"))
                pg = b.new_page(viewport={"width": 1440, "height": 1000})
                dialogs = []
                pg.on("dialog", lambda d: (dialogs.append(d.message), d.dismiss()))
                pg.goto(f"http://127.0.0.1:{ui_upload.PORT}/agent", wait_until="networkidle")
                time.sleep(4)
                up = pg.locator("input[type=file]")
                if not up.count():
                    results.append(dict(test=f"hostile fingerprint through the real page: {name}", ok=None, evidence="no file input on the Agent page (the page changed)"))
                    pg.close()
                    continue
                up.first.set_input_files(path)
                time.sleep(7)
                injected = pg.evaluate("document.querySelectorAll('#tp_injected, [data-testid=stMain] img[src=x]').length")
                handler = pg.evaluate("Array.from(document.querySelectorAll('[data-testid=stMain] img[src=x]')).filter(e => e.hasAttribute('onerror')).length")
                trace = pg.locator("[data-testid='stException']").count()
                text = pg.locator("[data-testid='stMain']").inner_text()
                said = next((ln for ln in text.split("\n") if "could not be used" in ln or "could not be read" in ln or "not a ThreatPrint" in ln), "")
                ok = not dialogs and not injected and not trace
                results.append(dict(test=f"hostile fingerprint through the real page: {name}", ok=ok,
                                    evidence=f"scripts that ran: {len(dialogs)}; elements from the file in the page: {injected} (with its script handler still attached: {handler}); tracebacks: {trace}; page said: {said[:120] or 'nothing'}"))
                print(results[-1], flush=True)
                pg.close()
            b.close()
    finally:
        srv.terminate()
    save("fp_page_results.json", results)


if __name__ == "__main__":
    main()
