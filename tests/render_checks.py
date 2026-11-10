"""Render what a person reads (pages, scorecards, the Live demo after a run, the Agent page with a fingerprint, the hover text of the charts,
the sign-in screen, the downloadable reports) to text files in qa/checker_runs/, and run the praxis checker on each when it is available,
keeping its output beside the text. So that "0 errors" has a file behind it.

    python3 tests/render_checks.py pages | results 0-12 | results 13-24 | flows | reports
    THREATPRINT_PY = the Python of the install; TP_CHECKER = path of praxis_check/check.py (the checker lives outside this repository)
"""
import glob
import json
import os
import subprocess
import sys
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "qa", "checker_runs")
PY = os.environ.get("THREATPRINT_PY") or sys.executable
CHECKER = os.environ.get("TP_CHECKER", "")
PORT = int(os.environ.get("TP_RENDER_PORT", "8787"))
BASE = f"http://127.0.0.1:{PORT}"
MODE = sys.argv[1] if len(sys.argv) > 1 else "pages"
PAGES = ["", "demo", "evaluate", "agent", "research", "organizations", "definitions", "students"]


def keep(name, text):
    os.makedirs(OUT, exist_ok=True)
    path = os.path.join(OUT, name + ".md")
    open(path, "w", encoding="utf-8").write(f"# {name}\n\n{text}\n")
    verdict = "checker not available"
    if CHECKER and os.path.exists(CHECKER):
        p = subprocess.run([sys.executable, "-B", CHECKER, "--advisor", path], capture_output=True, text=True)
        out = (p.stdout or "") + (p.stderr or "")
        open(os.path.join(OUT, name + ".check.txt"), "w", encoding="utf-8").write(time.strftime("%Y-%m-%d %H:%M ") + "check.py --advisor " + os.path.basename(path) + "\n" + out)
        verdict = next((line.strip() for line in out.splitlines() if "error(s)" in line), out.strip()[-120:])
    print(f"{name}: {len(text):,} characters; {verdict}", flush=True)


def page_text(pg):
    """Visible text plus the hover text of every chart mark (SVG titles are not part of the visible text)."""
    for ex in pg.locator("[data-testid='stExpander'] summary").all():
        try:
            ex.click()
            time.sleep(0.15)
        except Exception:
            pass
    body = pg.locator("[data-testid='stMain']").inner_text()
    tips = pg.evaluate("[...document.querySelectorAll('svg title')].map(t => t.textContent)")
    return body, "\n".join(tips)


def reports():
    code = ("import app, json\n"
            "for c in app.load_cards():\n"
            "    if c.get('id') in ('datasense', 'edge_iiotset'):\n"
            "        open(r'%s' + '/report_' + c['id'] + '.html', 'w', encoding='utf-8').write(app.report_html(c))\n" % OUT)
    subprocess.run([PY, "-c", code], cwd=ROOT, env=dict(os.environ, TP_OPEN="1"), capture_output=True, text=True)
    import html
    import re
    for cid in ("datasense", "edge_iiotset"):
        raw = open(os.path.join(OUT, f"report_{cid}.html"), encoding="utf-8").read()
        text = html.unescape(re.sub(r"<[^>]+>", " ", re.sub(r"<style.*?</style>", " ", raw, flags=re.S)))
        keep(f"report_{cid}", re.sub(r"[ \t]+", " ", text))
    cards = []
    for f in sorted(glob.glob(os.path.join(ROOT, "results", "*.json"))):
        if not os.path.basename(f).startswith("_"):
            strings = []

            def walk(o):
                if isinstance(o, dict):
                    for v in o.values():
                        walk(v)
                elif isinstance(o, list):
                    for v in o:
                        walk(v)
                elif isinstance(o, str) and " " in o:
                    strings.append(o)
            walk(json.load(open(f)))
            cards.append(f"## {os.path.basename(f)}\n\n" + "\n\n".join(strings))
    keep("text_of_the_result_card_files", "\n\n".join(cards))


def main():
    if MODE == "reports":
        return reports()
    from playwright.sync_api import sync_playwright
    env = dict(os.environ, TP_OPEN="1")
    if MODE == "signin":
        env.pop("TP_OPEN")
        env["TP_PASSWORD"] = "render-check-password"
    for k in ("TP_PAGE", "PRAXIS_LAB_PAGE", "PRAXIS_LAB_OPEN", "PRAXIS_LAB_PASSWORD"):
        env.pop(k, None)
    srv = subprocess.Popen([PY, "-m", "streamlit", "run", "app.py", "--server.port", str(PORT), "--server.address", "127.0.0.1", "--server.headless", "true"],
                           cwd=ROOT, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    try:
        for _ in range(60):
            time.sleep(1)
            try:
                if urllib.request.urlopen(BASE + "/_stcore/health", timeout=2).status == 200:
                    break
            except Exception:
                pass
        with sync_playwright() as p:
            b = p.chromium.launch()
            pg = b.new_page(viewport={"width": 1400, "height": 5000})
            if MODE == "signin":
                pg.goto(BASE + "/", wait_until="domcontentloaded")
                pg.wait_for_selector("input[type='password']", timeout=30000)
                time.sleep(2)
                keep("signin_screen", pg.locator("[data-testid='stMain']").inner_text())
            elif MODE == "pages":
                for path in PAGES:
                    pg.goto(BASE + "/" + path, wait_until="domcontentloaded")
                    pg.wait_for_selector(".tp-footer", timeout=60000)
                    time.sleep(2.5)
                    body, tips = page_text(pg)
                    keep("page_" + (path or "overview"), body + ("\n\n## Hover text of the chart marks\n\n" + tips if tips else ""))
            elif MODE == "results":
                lo, hi = [int(x) for x in sys.argv[2].split("-")]
                names = sorted(json.load(open(f))["name"] for f in glob.glob(os.path.join(ROOT, "results", "*.json")) if not os.path.basename(f).startswith("_"))
                pg.goto(BASE + "/results", wait_until="domcontentloaded")
                pg.wait_for_selector(".tp-footer", timeout=60000)
                time.sleep(3)
                if lo == 0:
                    body, tips = page_text(pg)
                    keep("page_results_as_opened", body)
                    keep("page_results_hover_text_of_the_charts", tips)
                for i, name in enumerate(names):
                    if not (lo <= i <= hi):
                        continue
                    box = pg.locator("[data-testid='stSelectbox'] input").first
                    box.scroll_into_view_if_needed()
                    box.click()
                    pg.keyboard.press("ControlOrMeta+a")
                    pg.keyboard.type(name[:32], delay=8)                 # typing filters the list, which is drawn only in part
                    pg.get_by_role("option", name=name, exact=True).first.wait_for(timeout=15000)
                    pg.get_by_role("option", name=name, exact=True).first.click()
                    time.sleep(2.2)
                    body, _ = page_text(pg)
                    assert name[:28] in body, name
                    keep(f"results_card_{i:02d}", body[body.index("Open a scorecard"):] if "Open a scorecard" in body else body)
            elif MODE == "flows":
                pg.goto(BASE + "/demo", wait_until="domcontentloaded")
                pg.get_by_role("button", name="Run the demo: Water utility").wait_for(timeout=60000)
                pg.get_by_role("button", name="Run the demo: Water utility").click()
                pg.get_by_text("Reading the verdicts").wait_for(timeout=120000)
                time.sleep(2)
                body, tips = page_text(pg)
                keep("live_demo_after_a_run_water_utility", body)
                pg.goto(BASE + "/agent", wait_until="domcontentloaded")
                pg.wait_for_selector("input[type=file]", state="attached", timeout=60000)
                pg.locator("input[type=file]").set_input_files(os.path.join(ROOT, "samples", "sample_organization_water_utility_SYNTHETIC.fingerprint.example.json"))
                pg.get_by_text("Integrity digest matches").wait_for(timeout=60000)
                time.sleep(2)
                body, tips = page_text(pg)
                keep("agent_page_with_the_example_fingerprint", body)
            b.close()
    finally:
        srv.terminate()


if __name__ == "__main__":
    main()
