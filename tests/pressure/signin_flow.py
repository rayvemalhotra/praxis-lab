"""The sign-in path in a real browser (needs Playwright; skipped when it is not installed): a wrong password is refused, the right one
admits, the cookie that remembers the browser is set, a reload and a direct page address stay signed in, a browser without the cookie
still meets the sign-in screen, and "Leave the site" clears the cookie.

    python3 tests/pressure/signin_flow.py      writes qa/signin_flow_results.json   (THREATPRINT_PY = the Python of the install)
"""
import os
import subprocess
import sys
import time
import urllib.request

from common import ROOT, save

PORT = int(os.environ.get("TP_SIGNIN_PORT", "8786"))
PY = os.environ.get("THREATPRINT_PY") or sys.executable
PW = "signin-flow-password"
BASE = f"http://127.0.0.1:{PORT}"


def alive():
    try:
        return urllib.request.urlopen(BASE + "/_stcore/health", timeout=2).status == 200
    except Exception:
        return False


def main():
    try:
        from playwright.sync_api import sync_playwright
    except Exception:
        print("Playwright is not installed; sign-in flow skipped")
        return
    env = dict(os.environ, TP_PASSWORD=PW)
    for k in ("TP_OPEN", "TP_PAGE", "PRAXIS_LAB_OPEN", "PRAXIS_LAB_PAGE", "PRAXIS_LAB_PASSWORD"):
        env.pop(k, None)
    srv = subprocess.Popen([PY, "-m", "streamlit", "run", "app.py", "--server.port", str(PORT), "--server.address", "127.0.0.1", "--server.headless", "true"],
                           cwd=ROOT, env=env, stdout=open(os.path.join(ROOT, "qa", "_signin_server.log"), "w"), stderr=subprocess.STDOUT)
    rows = []
    add = lambda test, ok, evidence: rows.append(dict(test=test, ok=ok, evidence=evidence))
    try:
        for _ in range(60):
            time.sleep(1)
            if alive():
                break
        ver = subprocess.run([PY, "-c", "import streamlit as s; print(s.__version__, 'st.iframe' if hasattr(s, 'iframe') else 'components.html')"], capture_output=True, text=True).stdout.split()
        ver = ver if len(ver) == 2 else ["?", "?"]
        with sync_playwright() as p:
            b = p.chromium.launch()
            ctx = b.new_context(viewport={"width": 1280, "height": 800})
            pg = ctx.new_page()
            pg.goto(BASE + "/", wait_until="domcontentloaded")
            pg.wait_for_selector("input[type='password']", timeout=30000)
            add("the sign-in screen is what a new browser gets", pg.locator(".st-key-tp_nav").count() == 0, "password field shown, no navigation bar")
            pg.locator("input[type='password']").fill("not-the-password")
            pg.get_by_role("button", name="Enter").click()
            pg.wait_for_selector("text=did not match", timeout=30000)
            add("a wrong password is refused", pg.locator(".st-key-tp_nav").count() == 0, "the page says the password did not match")
            pg.locator("input[type='password']").fill(PW)
            pg.get_by_role("button", name="Enter").click()
            pg.wait_for_selector(".st-key-tp_nav", timeout=30000)
            time.sleep(1.5)
            cookie = [c for c in ctx.cookies() if c["name"] == "tp_access"]
            add("the right password admits and the remembering cookie is set", bool(cookie and cookie[0]["value"]),
                f"cookie tp_access present: {bool(cookie)}; the server runs Streamlit {ver[0]} and sets the cookie through {ver[1]}")
            pg.reload(wait_until="domcontentloaded")
            pg.wait_for_selector(".st-key-tp_nav", timeout=30000)
            add("a reload stays signed in", pg.locator("input[type='password']").count() == 0, "navigation bar shown, no password field")
            p2 = ctx.new_page()
            p2.goto(BASE + "/results", wait_until="domcontentloaded")
            p2.wait_for_selector("text=Open a scorecard", timeout=60000)
            add("a direct page address opens for the signed-in browser", p2.locator("input[type='password']").count() == 0, "/results shows the results page")
            other = b.new_context().new_page()
            other.goto(BASE + "/results", wait_until="domcontentloaded")
            other.wait_for_selector("input[type='password']", timeout=30000)
            add("a browser without the cookie meets the sign-in screen at a direct page address", other.get_by_text("Open a scorecard").count() == 0, "/results shows the password field only")
            pg.get_by_role("button", name="Leave the site").click()
            pg.wait_for_selector("input[type='password']", timeout=30000)
            time.sleep(1.5)
            left = [c for c in ctx.cookies() if c["name"] == "tp_access" and c["value"]]
            pg.reload(wait_until="domcontentloaded")
            pg.wait_for_selector("input[type='password']", timeout=30000)
            add("Leave the site signs out and clears the cookie", not left and pg.locator(".st-key-tp_nav").count() == 0, f"cookie with a value after leaving: {len(left)}; a reload shows the sign-in screen")
            b.close()
    finally:
        srv.terminate()
    save("signin_flow_results.json", rows)
    for r in rows:
        print("pass" if r["ok"] else "FAIL", r["test"], "|", r["evidence"])


if __name__ == "__main__":
    main()
