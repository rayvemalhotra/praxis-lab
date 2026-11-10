"""Several real browser sessions on the real page at once (needs Playwright; skipped when it is not installed).
Each session signs in with the password, opens the Live demo and starts a quick look of the built-in example; all start together.
While they run, one more session signs in and opens the Overview and the Results page. Measured: seconds until each run has
finished, whether every session shows the same H1 number, errors on any page, the latency of the extra session, and the memory
of the server process. This also repeats sign-in on the pages as they are now.

    python3 tests/pressure/browser_load.py [sessions]     writes qa/browser_load_results.json   (THREATPRINT_PY = the Python of the install)
"""
import os
import subprocess
import sys
import time
import urllib.request

from common import ROOT, save

PORT = int(os.environ.get("TP_LOAD_PORT", "8785"))
PY = os.environ.get("THREATPRINT_PY") or sys.executable
N = int(sys.argv[1]) if len(sys.argv) > 1 else 5
PW = "load-test-password"
BASE = f"http://127.0.0.1:{PORT}"


def alive():
    try:
        return urllib.request.urlopen(BASE + "/_stcore/health", timeout=2).status == 200
    except Exception:
        return False


def rss_mb(pid):
    """Resident memory of the server process and its children, in MB (Linux /proc; 0 where that is not available)."""
    total = 0
    try:
        kids = subprocess.run(["pgrep", "-P", str(pid)], capture_output=True, text=True).stdout.split()
        for p in [str(pid)] + kids:
            with open(f"/proc/{p}/status") as fh:
                for line in fh:
                    if line.startswith("VmRSS:"):
                        total += int(line.split()[1])
    except Exception:
        return 0
    return round(total / 1024)


def sign_in(pg, path=""):
    t = time.time()
    pg.goto(BASE + "/" + path, wait_until="domcontentloaded")
    pg.wait_for_selector("input[type='password']", timeout=30000)
    pg.locator("input[type='password']").fill(PW)
    pg.get_by_role("button", name="Enter").click()
    pg.wait_for_selector(".st-key-tp_nav", timeout=30000)
    return round(time.time() - t, 1)


def main():
    try:
        from playwright.sync_api import sync_playwright
    except Exception:
        print("Playwright is not installed; browser load measurement skipped")
        return
    env = dict(os.environ, TP_PASSWORD=PW)
    for k in ("TP_OPEN", "TP_PAGE", "PRAXIS_LAB_OPEN", "PRAXIS_LAB_PAGE", "PRAXIS_LAB_PASSWORD"):
        env.pop(k, None)
    srv = subprocess.Popen([PY, "-m", "streamlit", "run", "app.py", "--server.port", str(PORT), "--server.address", "127.0.0.1", "--server.headless", "true"],
                           cwd=ROOT, env=env, stdout=open(os.path.join(ROOT, "qa", "_load_server.log"), "w"), stderr=subprocess.STDOUT)
    rows = []
    try:
        for _ in range(60):
            time.sleep(1)
            if alive():
                break
        rss0 = rss_mb(srv.pid)
        with sync_playwright() as p:
            b = p.chromium.launch()
            pages, signin = [], []
            for i in range(N):
                pg = b.new_context(viewport={"width": 1280, "height": 800}).new_page()
                signin.append(sign_in(pg, "demo"))
                pages.append(pg)
            rows.append(dict(test=f"{N} browser sessions sign in with the password and reach the Live demo", ok=True,
                             evidence=f"sign-in and page ready in {min(signin)} to {max(signin)} s per session, one after another"))
            for pg in pages:                                         # the sign-in cookie carries the session to the page asked for
                if not pg.get_by_role("button", name="Run the demo: Built-in example").count():
                    pg.goto(BASE + "/demo", wait_until="domcontentloaded")
                pg.get_by_role("button", name="Run the demo: Built-in example").wait_for(timeout=30000)
            t0 = time.time()
            for pg in pages:
                pg.get_by_role("button", name="Run the demo: Built-in example").click()
            extra = b.new_context(viewport={"width": 1280, "height": 800}).new_page()       # a visitor who arrives while the runs are going
            lat_sign = sign_in(extra)
            t = time.time()
            extra.goto(BASE + "/results", wait_until="domcontentloaded")
            extra.wait_for_selector("text=Open a scorecard", timeout=60000)
            lat_results = round(time.time() - t, 1)
            done, peak = {}, rss0
            while len(done) < N and time.time() - t0 < 150:
                for i, pg in enumerate(pages):
                    if i not in done and pg.get_by_text("Reading the verdicts").count():
                        done[i] = round(time.time() - t0, 1)
                peak = max(peak, rss_mb(srv.pid))
                time.sleep(1)
            bad = sum(1 for pg in pages + [extra] if pg.get_by_text("Traceback").count() or pg.locator("[data-testid='stException']").count())
            h1 = []
            for pg in pages:
                try:
                    h1.append(pg.locator(".tp-hyp .big").first.inner_text(timeout=3000).strip())
                except Exception:
                    h1.append("?")
            times = [done[i] for i in sorted(done)]
            rows.append(dict(test=f"{N} quick looks started together through the page all finish", ok=(len(done) == N),
                             evidence=f"{len(done)} of {N} finished; seconds from the click to the finished scorecard, in order of finishing: {sorted(times)} (one evaluation runs at a time; the others wait in line)"))
            rows.append(dict(test="every session shows the same result for the same file", ok=(len(set(h1)) == 1 and "?" not in h1), evidence=f"H1 tile of each session: {h1}"))
            rows.append(dict(test="no page showed an error or a traceback during the load", ok=(bad == 0), evidence=f"{bad} pages with an error box, of {N + 1}"))
            rows.append(dict(test="a visitor who arrives during the runs can sign in and open the Results page", ok=(lat_results < 60),
                             evidence=f"sign-in {lat_sign} s, Results page ready in {lat_results} s while {N} runs were in line"))
            rows.append(dict(test="memory of the server during the load", ok=None,
                             evidence=f"server process {rss0} MB before, peak {peak} MB during {N} sessions (resident memory of the server and its children; 0 means not measurable on this system)"))
            rows.append(dict(test="the server is alive after the load", ok=alive(), evidence="health answer after the last session"))
            b.close()
    finally:
        srv.terminate()
    save("browser_load_results.json", rows)
    for r in rows:
        print(("pass" if r["ok"] else "note" if r["ok"] is None else "FAIL"), r["test"], "|", r["evidence"])


if __name__ == "__main__":
    main()
