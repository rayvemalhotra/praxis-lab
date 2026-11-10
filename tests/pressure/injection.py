"""Section C: injection. A table whose column names, label values and host names carry HTML, script and Markdown is
evaluated; then every piece of HTML the tool builds from it is searched for the raw payloads. A payload that appears
unescaped in HTML the page marks as safe would run in the visitor's browser.

Also: formula injection in the CSV files the tool lets a person download (a cell that starts with = + - @ runs as a
formula when a peer opens the file in a spreadsheet program).

    python tests/pressure/injection.py        writes qa/injection_results.json
"""
import io
import json
import os
import sys

import numpy as np
import pandas as pd

from common import ROOT, auto_cfg, save

import hostile

PAYLOADS = ["<script>alert(1)</script>", "<img src=x onerror=alert(2)>", "<script>alert('dos')</script>", "<b>scan</b>", "<svg onload=alert(3)>"]
RAW = ["<script>alert", "<img src=x onerror", "<svg onload", "<b>scan</b>"]
FORMULAS = ["=HYPERLINK(\"http://example.invalid\",\"click\")", "+SUM(1,2)", "-2+3", "@cmd"]


def hostile_card():
    import engine
    import threatprint_agent as agent
    fn, _ = hostile.CASES["file: script and image tags in column names, label values and host names"]
    df = agent.read_table(io.BytesIO(fn()), "x.csv") if hasattr(agent, "read_table") else pd.read_csv(io.BytesIO(fn()), low_memory=False)
    ins = engine.inspect(df)
    cfg, numbers = auto_cfg(df, ins, name="<script>alert('name')</script>")
    card = engine.run(cfg, frame=df, budget=engine.Budget(**hostile.TINY))
    card["id"] = "your_data"
    card["study_role"] = "your data"
    return df, ins, cfg, numbers, card


def find_raw(html):
    return [p for p in RAW if p in html]


def main():
    os.environ["TP_OPEN"] = "1"
    os.environ.pop("TP_PAGE", None)
    results = []
    df, ins, cfg, numbers, card = hostile_card()
    labels_with_payload = [v for v in card["classes"] if "<" in v]
    results.append(dict(test="the payloads survive into the scorecard data (so the rendering is really tested)", ok=bool(labels_with_payload) and any("<" in c for c in card["step2"]["kept"]),
                        evidence=f"attack types in the card: {labels_with_payload[:2]}; kept columns with a tag: {[c for c in card['step2']['kept'] if '<' in c][:2]}"))

    # everything the page marks as safe HTML is recorded
    import streamlit as st
    from streamlit.delta_generator import DeltaGenerator
    seen = []
    real = DeltaGenerator.markdown

    def spy(self, body, *a, **k):
        seen.append((bool(k.get("unsafe_allow_html")), str(body)))
        return real(self, body, *a, **k)

    DeltaGenerator.markdown = spy
    real_st = st.markdown

    def spy_st(body, *a, **k):                    # st.markdown is bound when streamlit is imported, so it is replaced as well
        seen.append((bool(k.get("unsafe_allow_html")), str(body)))
        return real_st(body, *a, **k)

    st.markdown = spy_st
    import app
    import ui

    def check(name, fn):
        seen.clear()
        try:
            out = fn()
        except Exception as e:  # noqa
            results.append(dict(test=name, ok=False, evidence=f"could not run: {type(e).__name__}: {str(e)[:160]}"))
            return
        html = "\n".join(b for unsafe, b in seen if unsafe) + ("\n" + out if isinstance(out, str) else "")
        raw = find_raw(html)
        results.append(dict(test=name, ok=not raw, evidence=(f"raw payload in page HTML: {raw}" if raw else f"{len(html):,} characters of HTML, every payload escaped")))

    for fname, call in [("app.report_html (the downloadable report)", lambda: app.report_html(card)),
                        ("app.org_panel (organization panels of the scorecard)", lambda: "".join(app.org_panel(card, o) for o in "ABC")),
                        ("app.show_card (the whole scorecard, expanders included)", lambda: app.show_card(card, heading=False)),
                        ("app.org_table through ui.table", lambda: [ui.table(app.org_table(card, o)) for o in "ABC"] and None),
                        ("app._before_after (one record before and after sanitizing)", lambda: app._before_after(df, cfg, numbers)),
                        ("ui.table on the raw table (column names and cells)", lambda: ui.table(df.head(5))),
                        ("ui.chip on every column name", lambda: "".join(ui.chip(c) for c in df.columns)),
                        ("app.role_reasons (why each column got its role, live demo)", lambda: json.dumps(app.role_reasons(df, ins, cfg), default=str) if hasattr(app, "role_reasons") else "")]:
        target = fname.split(" ")[0].split(".")
        if target[0] == "app" and not hasattr(app, target[1]):
            results.append(dict(test=fname, ok=None, evidence="function not in app.py any more (renamed by the layout work); covered by the browser test"))
            continue
        check(fname, call)
    DeltaGenerator.markdown = real
    st.markdown = real_st

    # ---- formula injection in downloaded CSV files
    import engine
    import threatprint_agent as agent
    d = hostile.base()
    d["attack_type"] = d.attack_type.replace({"dos": FORMULAS[0], "scan": FORMULAS[1], "mitm": FORMULAS[2], "brute": FORMULAS[3]})
    d = d.rename(columns={"pkts": "=1+1"})
    ins2 = engine.inspect(d)
    cfg2, numbers2 = auto_cfg(d, ins2)
    san = engine.sanitize(d, cfg2["label_col"], [c for c in numbers2 if c in d.columns])

    def formula_cells(text):
        rows = list(pd.read_csv(io.StringIO(text), header=None, dtype=str, keep_default_na=False).itertuples(index=False))
        def is_number(c):
            try:
                float(c)
                return True
            except ValueError:
                return False
        return sum(1 for r in rows for cell in r if cell[:1] in ("=", "@") or (cell[:1] in ("+", "-") and not is_number(cell)))

    plain = san.to_csv(index=False)
    results.append(dict(test="the download written by pandas with no helper (what the page did): cells a spreadsheet would run as formulas", ok=None,
                        evidence=f"{formula_cells(plain):,} cells start with = + - @ (label values and one column name came from the sender)"))
    if hasattr(agent, "csv_safe"):
        safe = agent.csv_safe(san).to_csv(index=False)
        n = formula_cells(safe)
        back = pd.read_csv(io.StringIO(safe))
        same_numbers = bool(np.allclose(back.select_dtypes("number").to_numpy(), san.select_dtypes("number").to_numpy(), equal_nan=True))
        results.append(dict(test="threatprint_agent.csv_safe: no cell of the downloaded table starts a formula, and no number changes", ok=(n == 0 and same_numbers),
                            evidence=f"{n} formula cells after csv_safe; numbers identical: {same_numbers}"))
    else:
        results.append(dict(test="threatprint_agent.csv_safe exists", ok=False, evidence="no csv_safe in the agent"))
    src = open(os.path.join(ROOT, "app.py"), encoding="utf-8").read()
    uses = src.count("csv_safe(")
    writes = src.count(".to_csv(")
    results.append(dict(test="app.py: every CSV download goes through csv_safe", ok=(uses >= writes and writes > 0),
                        evidence=f"{writes} to_csv calls in app.py, {uses} csv_safe calls (see qa/APP_PATCHES.md when they differ)"))
    save("injection_results.json", results)
    for r in results:
        print({True: "PASS", False: "FAIL", None: "NOTE"}[r["ok"]], r["test"][:95].ljust(95), "|", r["evidence"][:150])
    return results


if __name__ == "__main__":
    main()
