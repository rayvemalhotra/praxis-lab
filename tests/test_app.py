"""Headless tests of ThreatPrint (the web product, the engine, the local agent).   python -m pytest tests -q"""
import json
import os
import re
import sys

import pandas as pd
import pytest
from streamlit.testing.v1 import AppTest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
import engine  # noqa: E402

APP = os.path.join(ROOT, "app.py")
BANNED = ["first", "proven", "anonymized", "anonymous", "guarantee", "no leakage", "removes the risk"]
PAGES = ["start", "demo", "results", "evaluate", "agent", "research", "organizations", "definitions", "students"]
SIX_STAGES = ["Ingest", "Detect column roles", "Sanitize", "Organize", "Train and test", "Scorecard"]
FOUR = ["Isolated training", "Sanitized attack-record sharing", "Federated learning", "Centralized training"]
for _k in ("PRAXIS_LAB_PAGE", "PRAXIS_LAB_PASSWORD", "PRAXIS_LAB_OPEN", "TP_OPEN"):
    os.environ.pop(_k, None)


TEST_PW = "test-password-for-the-suite"


def run_page(page, timeout=600):
    """Open one page; pass the access gate with a known password (the environment variable wins over secrets.toml)."""
    os.environ["TP_PAGE"] = page
    os.environ["TP_PASSWORD"] = TEST_PW
    at = AppTest.from_file(APP, default_timeout=timeout)
    at.run()
    if at.text_input(key="_access_input") if any(x.key == "_access_input" for x in at.text_input) else None:
        at.text_input(key="_access_input").set_value(TEST_PW)
        at.button[0].click().run()
    return at


def all_text(at):
    parts = []
    for kind in ("markdown", "caption", "title", "subheader", "header", "info", "warning", "error", "success"):
        for el in getattr(at, kind):
            parts.append(str(el.value))
    return "\n".join(parts)


def test_engine_quick_on_example():
    df = engine.example_data()
    ins = engine.inspect(df)
    assert ins["label_col"] == "attack_type" and ins["benign_label"] == "normal" and ins["source_col"] == "device_ip"
    cfg = dict(name="example", label_col=ins["label_col"], benign_label=ins["benign_label"], source_col=ins["source_col"],
               time_col=ins["time_col"], drop=ins["identifiers"])
    card = engine.run(cfg, frame=df, budget=engine.QUICK)
    for o in engine.ORG:
        for road in engine.ROADS:
            assert road in card["companies"][o]["named"]
            assert road in card["companies"][o]["false_alarm"]
            assert road in card["companies"][o]["bytes"]
        assert card["verdicts"][o]["1_isolated"] == "baseline" and card["verdicts"][o]["4_centralized"] == "reference"
    assert card["hypotheses"]["H1"]["gain"] > 0.3          # the example is built so that sharing helps a lot
    json.dumps(card, default=float)


def test_results_folder_cards_have_all_four_conditions():
    files = sorted(os.listdir(os.path.join(ROOT, "results")))
    assert len([f for f in files if f.endswith(".json") and not f.startswith("_")]) >= 7
    for f in files:
        if not f.endswith(".json") or f.startswith("_"):
            continue
        c = json.load(open(os.path.join(ROOT, "results", f)))
        for o in engine.ORG:
            assert set(c["companies"][o]["named"]) == set(engine.ROADS)
            assert set(c["verdicts"][o]) == set(engine.ROADS)


def test_start_page():
    at = run_page("start")
    assert not at.exception
    t = all_text(at)
    assert "withheld attack type" in t and "isolated training" in t and "centralized training" in t
    assert "Know what sharing buys" in t and "ThreatPrint" in t


def test_results_page_shows_every_dataset():
    at = run_page("results")
    assert not at.exception
    t = all_text(at)
    assert "DataSense" in t
    assert t.count("Isolated training") >= 3           # three organization tables
    assert "run of record" in t


def test_definitions_page():
    at = run_page("definitions")
    assert not at.exception
    t = all_text(at)
    assert "Attack-class recall" in t and "Withheld attack type" in t and "Decision rule" in t
    at.text_input(key="gl_q").set_value("tracing").run()            # the search narrows the glossary
    t = all_text(at)
    assert "Tracing (H3)" in t and "Attack-class recall" not in t


def test_every_page_is_branded_and_clean():
    """Every page opens, carries the product name, never the working name, no em dash and none of the banned words."""
    for page in PAGES:
        at = run_page(page)
        assert not at.exception, (page, [str(e.value)[:300] for e in at.exception])
        t = all_text(at)
        assert "ThreatPrint" in t, page
        assert "Praxis Lab" not in t, page
        assert "\u2014" not in t, page
        low = re.sub(r"<[^>]+>", " ", t).lower()
        for w in BANNED:
            assert not re.search(r"\b" + re.escape(w) + r"\b", low), (page, w)


def test_evaluate_page_runs_example_end_to_end():
    at = run_page("evaluate", timeout=900)
    assert not at.exception
    at.radio(key="ev_data").set_value("Use the built-in example (made-up data, for trying the tool)").run()
    assert not at.exception
    assert at.selectbox(key="ev_label").value == "attack_type"
    assert at.selectbox(key="ev_host").value == "device_ip"
    at.button(key="ev_run").click().run()
    assert not at.exception, at.exception
    t = all_text(at)
    assert "H1" in t and "H2" in t and "Quick look" in t
    assert t.count("Isolated training") >= 3
    assert "not measured" not in t.split("Step 5")[0].split("Steps 3 and 4")[-1]
    keys = [str(b.key) for b in at.get("download_button")]
    assert any("dl_json" in k for k in keys) and any("dl_html" in k for k in keys), keys


def test_students_page():
    at = run_page("students")
    assert not at.exception
    assert "one-hour exercise" in all_text(at)


def test_sanitizer_is_a_tab_of_evaluate_and_waits_for_a_file():
    at = run_page("evaluate")
    assert not at.exception
    t = all_text(at)
    assert "Waiting for a file." in t and "Waiting for a file to sanitize" in t
    assert [tab.label for tab in at.tabs] == ["Run the evaluation", "Sanitize a file only"]


def _manifest_samples():
    """(id, title) of every sample in samples/manifest.json whose file exists, with the id the app gives it."""
    out = []
    for e in json.load(open(os.path.join(ROOT, "samples", "manifest.json"), encoding="utf-8")):
        name = os.path.basename(str(e.get("file", "")))
        if name and os.path.isfile(os.path.join(ROOT, "samples", name)):
            out.append((re.sub(r"[^a-z0-9]+", "_", os.path.splitext(name)[0].lower()).strip("_"), e.get("title") or name))
    return out


def test_evaluate_offers_the_sample_files():
    at = run_page("evaluate")
    assert "Try a sample file" in at.radio(key="ev_data").options
    at.radio(key="ev_data").set_value("Try a sample file").run()
    assert not at.exception
    titles = [t for _, t in _manifest_samples()]
    assert list(at.selectbox(key="ev_sample").options) == titles and titles
    if "Water utility" in titles:
        at.selectbox(key="ev_sample").set_value("Water utility").run()
        assert not at.exception
        assert at.selectbox(key="ev_label").value == "attack_type" and at.selectbox(key="ev_host").value == "device_name"


def _demo_checks(at):
    assert not at.exception, [str(e.value)[:400] for e in at.exception]
    assert not at.error, [e.value[:300] for e in at.error]
    t = all_text(at)
    for i, name in enumerate(SIX_STAGES, 1):
        assert f"Stage {i} of 6" in t and name in t, (i, name)
    for name in FOUR:                                               # all four training conditions, in the stage that trains and in the scorecard
        assert t.count(name) >= 3, name
    assert "quick look, local run of the tool, not the run of record" in t
    assert "Sanitized means direct identifiers removed, nothing more." in t
    assert "What just happened." in t and "Reading the verdicts." in t
    assert "MITRE ATT&CK" in t and "Withheld attack type" in t
    assert "Traceback" not in t
    return t


def test_live_demo_before_a_run_explains_the_six_stages():
    at = run_page("demo")
    assert not at.exception
    t = all_text(at)
    for name in SIX_STAGES:
        assert name in t
    assert "No run yet" in all_text(at) and "Built-in example" in t
    keys = [b.key for b in at.button]
    assert "demo_run_builtin" in keys and all(f"demo_run_{sid}" in keys for sid, _ in _manifest_samples())


def test_live_demo_runs_the_builtin_example_through_all_six_stages():
    at = run_page("demo", timeout=900)
    at.button(key="demo_run_builtin").click().run()
    t = _demo_checks(at)
    assert "6,600 records" in t and "attack_type" in t
    at.run()                                                         # another pass of the page: the run is still there, drawn from the session
    _demo_checks(at)
    at.button(key="demo_clear").click().run()
    assert "No run yet" in all_text(at)


def test_live_demo_runs_a_manifest_sample_through_all_six_stages():
    samples = _manifest_samples()
    assert samples, "samples/manifest.json lists no readable sample"
    sid, title = samples[0]
    at = run_page("demo", timeout=900)
    at.button(key=f"demo_run_{sid}").click().run()
    t = _demo_checks(at)
    assert f"Sample: {title}" in t


def test_ui_text_has_no_em_dash_or_banned_words():
    """Only the text shown to people is checked: every string literal in app.py and ui.py."""
    import ast
    texts = []
    for f in (APP, os.path.join(ROOT, "ui.py")):
        tree = ast.parse(open(f, encoding="utf-8").read())
        texts += [n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str)]
    low = "\n".join(texts).lower()
    assert "\u2014" not in low
    for w in ("anonymized", "anonymous", "guarantee", "no leakage", "removes the risk", "proven"):
        assert w not in low, w
    for w in ("roads", "road 1", "road 2", "working alone", "(alone)", "unseen", "never seen", "never-seen", "praxis lab"):
        assert w not in low, w
    # two sentences that were not true as written (10 November 2026): a contributed fingerprint IS kept, and the 1% and 99%
    # quantiles of a fingerprint can equal the extremes
    readme = open(os.path.join(ROOT, "README.md"), encoding="utf-8").read().lower()
    for w in ("nothing you upload is stored", "never stored", "no minimum or maximum values"):
        assert w not in low and w not in readme, w
    assert "only if you choose to contribute it" in low


def test_password_gate_blocks_and_admits():
    os.environ["TP_PASSWORD"] = "test-password-123"
    try:
        os.environ["TP_PAGE"] = "definitions"
        at = AppTest.from_file(APP, default_timeout=120)
        at.run()
        assert not at.exception
        assert "access password" in all_text(at).lower()
        assert "Attack-class recall" not in all_text(at)   # the glossary is not shown before the password
        at.text_input(key="_access_input").set_value("wrong")
        at.button[0].click().run()
        assert "did not match" in all_text(at)
        assert "Attack-class recall" not in all_text(at)
        at.text_input(key="_access_input").set_value("test-password-123")
        at.button[0].click().run()
        assert "Attack-class recall" in all_text(at)       # admitted: the glossary is there
    finally:
        os.environ["TP_PASSWORD"] = TEST_PW


def test_research_and_organizations_pages():
    at = run_page("research")
    assert not at.exception
    txt = all_text(at)
    assert "Problem statement" in txt and "+41.1" in txt and "awaiting advisor approval" in txt
    at = run_page("organizations")
    assert not at.exception
    t = all_text(at)
    for part in ("Who it is for", "What you get", "Three ways to deploy", "Deployment across sites", "What is built, and what is designed", "Why post-quantum matters here", "Honest limits"):
        assert part in t, part
    assert "Free during the review period" in t and "$" not in t and "per month" not in t.lower()      # no prices, no paid tier
    assert "NVIDIA FLARE job export" in t and ("designed, not built" in t or "tested" in t)


def test_agent_classify_and_fingerprint_roundtrip(tmp_path):
    import numpy as np
    import threatprint_agent as agent
    assert agent.classify("DDoS_UDP")["family"] == "Distributed denial of service"
    assert agent.classify("ARP_poisioning")["techniques"][0]["id"] == "T1557.002"
    assert agent.classify("COLD_RESTART")["techniques"][0]["id"] == "T0816"
    assert agent.classify("something else")["family"] == agent.UNMAPPED
    df = engine.example_data()
    roles = agent.inspect(df)
    fp = agent.build_fingerprint(df, roles["label_col"], roles["benign_label"], roles["numbers"], source_col=roles["source_col"], time_col=roles["time_col"])
    assert agent.verify(fp) and len(fp["classes"]) == 6 and fp["format"] == "threatprint-fingerprint"
    old = dict(fp, format="praxis-lab-fingerprint")                  # files written before the rename are still read
    assert old["format"] in agent.FORMATS
    text = json.dumps(fp)
    assert "10.0." not in text and "192.168." not in text            # no addresses from the example table
    c = next(iter(fp["classes"].values()))
    x = agent.synthesize(c, 200, np.random.default_rng(0))
    assert x.shape == (200, len(fp["features"])) and np.isfinite(x).all()
    fp["classes"][next(iter(fp["classes"]))]["records"] += 10          # tampering is detected
    assert not agent.verify(fp)
    assert all(isinstance(ok, bool) for ok, _ in agent.readiness(fp))


def test_agent_page_and_samples():
    at = run_page("agent")
    assert not at.exception, [str(e.value)[:400] for e in at.exception]
    txt = all_text(at)
    assert "Waiting for a fingerprint file" in txt and "not a formal privacy protection" in txt
    for f in ("sample_organization_water_utility_SYNTHETIC.csv", "sample_power_grid_dnp3_REAL_CC-BY-4.0.csv"):
        assert os.path.exists(os.path.join(ROOT, "samples", f))


def test_gate_counts_wrong_passwords_across_fresh_sessions():
    """A guesser who opens a fresh session for every try is stopped by the count the whole site shares (qa/APP_PATCHES.md, P4)."""
    os.environ["TP_PASSWORD"] = "test-password-123"
    os.environ["TP_PAGE"] = "definitions"
    engine.GATE_LIMITER = engine.AttemptLimiter()
    try:
        seen = []
        for i in range(7):
            at = AppTest.from_file(APP, default_timeout=120)
            at.run()
            at.text_input(key="_access_input").set_value(f"wrong-{i}")
            at.button[0].click().run()
            assert not at.exception
            seen.append(all_text(at))
        assert "did not match" in seen[0] and "Too many wrong passwords" in seen[-1]
        assert not any("Attack-class recall" in t for t in seen)
        at = AppTest.from_file(APP, default_timeout=120)                 # while the client waits, even the right password is not looked at
        at.run()
        at.text_input(key="_access_input").set_value("test-password-123")
        at.button[0].click().run()
        assert "Too many wrong passwords" in all_text(at) and "Attack-class recall" not in all_text(at)
    finally:
        engine.GATE_LIMITER = engine.AttemptLimiter()
        os.environ["TP_PASSWORD"] = TEST_PW


def test_page_uses_the_safe_reader_the_safe_contribution_and_safe_downloads():
    """Source guards for the patches of qa/APP_PATCHES.md: the page must call the checked functions, never pandas or a path from an upload."""
    src = open(APP, encoding="utf-8").read()
    assert "engine.read_table(up, up.name)" in src and "pd.read_csv(" not in src and "pd.read_parquet(" not in src
    assert "agent.load_fingerprint(up.getvalue())" in src and "json.loads(up.getvalue()" not in src
    assert "engine.save_contribution(fp, CONTRIBUTIONS)" in src and "['integrity']['digest'][:16]}.json" not in src
    assert src.count(".to_csv(") == src.count("engine.csv_safe(") == 3
    assert "engine.GATE_LIMITER.wait(" in src and "? '; Secure' : ''" in src


def _titles(svg_html):
    return re.findall(r"<title>(.*?)</title>", svg_html)


def test_results_gains_chart_shows_all_four_conditions_and_the_experiment_apart():
    """Hard rule 11 on the Results page: isolated (zero line), sharing, federated and centralized in the gains chart; the experimental arm on its own chart."""
    at = run_page("results")
    assert not at.exception
    t = all_text(at)
    assert "Isolated training: the zero line" in t and "Centralized training (reference)" in t
    a, b = t.index("How much each approach added"), t.index("Fingerprint sharing, on its own chart")
    main, rest = t[a:b], t[b:]
    tips = _titles(main)
    for name in ("Sanitized attack-record sharing", "Federated learning", "Centralized training (reference)"):
        assert sum(1 for x in tips if name in x) >= 25, name
    assert not any("Fingerprint" in x for x in tips)                         # the experimental arm is not among the training conditions
    assert all(("not the run of record" in x) or ("run of record (Hex" in x) for x in tips)      # every hover text says which run it is
    assert any("DataSense" in x and "+41.1 [+32.5, +49.6], run of record (Hex, 11 October 2026)" in x for x in tips)
    fp_tips = _titles(rest.split("Which attack families transfer")[0])
    assert fp_tips and all("experimental, not a praxis condition" in x for x in fp_tips)
    assert "has not been measured" in rest.split("Which attack families transfer")[0]
    assert "CIDDS-002" in t and "21 source datasets" in t                     # the dataset that did not run, and the double versions, are said
    assert "tool tests, not study results" in t
    assert "Centralized training, the reference (points, 95% range)" in t     # the summary table has the fourth condition


def test_h3_is_shown_as_observed_and_the_praxis_cards_lead_with_the_run_of_record():
    at = run_page("results")                                                  # the DataSense card is the one open by default
    t = all_text(at)
    tile = t[t.index("H3 · TRACING"):][:1200]
    assert "observed" in tile and "supported" not in tile.split("</div></div>")[0]
    assert "not called settled" in tile
    h1 = t[t.index("H1 · SANITIZED SHARING"):][:900]
    assert "+41.1 <small>points</small>" in h1 and "Run of record (Hex, 11 October 2026)" in h1 and "not the run of record" in h1
    at = run_page("research")
    t = all_text(at)
    assert "H3 was supported" not in t and "not called settled" in t and "majority-device baseline" in t
    assert "Prof. Fossaceca" not in t and "not reviewed or endorsed by the university or the advisor" in t
    at = run_page("definitions")
    t = all_text(at)
    assert "For uploads and public datasets" in t and "across devices" in t and "in the sense the praxis uses it" not in t


def test_agent_page_downloads_follow_the_manifest_and_offer_an_example_fingerprint():
    at = run_page("agent")
    assert not at.exception
    keys = [str(b.key) for b in at.get("download_button")]
    listed = json.load(open(os.path.join(ROOT, "samples", "manifest.json")))
    assert len(listed) >= 4 and sum(1 for k in keys if k.startswith("dl_sample_")) == len(listed), keys
    assert "dl_example_fp" in keys and "dl_agent" in keys
    import threatprint_agent as agent
    fp = agent.load_fingerprint(open(os.path.join(ROOT, "samples", "sample_organization_water_utility_SYNTHETIC.fingerprint.example.json"), "rb").read())
    assert agent.verify(fp)                                                    # the example a visitor downloads loads and verifies with today's agent


def test_students_dataset_list_is_a_tracked_file_inside_the_repository():
    rows = json.load(open(os.path.join(ROOT, "results", "_datasets.json")))
    assert len(rows) >= 19 and all(r.get("Dataset") and "Runs in the tool" in r for r in rows)
    assert any(r["Dataset"].startswith("CIDDS-002") and r["Runs in the tool"].startswith("no") for r in rows)
    at = run_page("students")
    t = all_text(at)
    assert "CIDDS-002" in t and "Runs in the tool" in t


def test_parquet_upload_is_sized_from_its_metadata_before_it_is_read():
    import io
    import numpy as np
    import threatprint_agent as agent
    small = pd.DataFrame({"x": np.arange(50), "label": ["normal"] * 50})
    buf = io.BytesIO()
    small.to_parquet(buf)
    assert agent.read_table(buf.getvalue(), "small.parquet") is not None
    big = pd.DataFrame({f"c{i}": np.zeros(600_000, dtype="int8") for i in range(100)})      # 60 million cells in a quarter of a megabyte on disk
    buf = io.BytesIO()
    big.to_parquet(buf, compression="zstd")
    assert len(buf.getvalue()) < 5_000_000
    with pytest.raises(agent.DataProblem) as e:
        agent.read_table(buf.getvalue(), "big.parquet")
    assert "more than this tool reads at once" in str(e.value)


def test_share_script_cannot_start_the_public_site_open():
    import subprocess
    src = open(os.path.join(ROOT, "share.sh")).read()
    line = next(x for x in src.splitlines() if "streamlit run app.py" in x and "TP_PASSWORD" in x)
    for var in ("TP_OPEN", "PRAXIS_LAB_OPEN", "TP_PAGE", "PRAXIS_LAB_PAGE"):
        assert f"-u {var}" in line, var
    flags = re.search(r"env ((?:-u \w+ )+)", line).group(1).split()
    out = subprocess.run(["env", *flags, sys.executable, "-c", "import os; print(os.environ.get('TP_OPEN'), os.environ.get('PRAXIS_LAB_OPEN'))"],
                         env=dict(os.environ, TP_OPEN="1", PRAXIS_LAB_OPEN="1"), capture_output=True, text=True)
    assert out.stdout.strip() == "None None"


def test_scorecard_shows_all_four_conditions_and_labels_the_experiment():
    # keep the two tests that import the app last: importing it as a module runs it outside a Streamlit session
    os.environ["TP_OPEN"] = "1"
    import app as _app  # noqa
    cards = _app.load_cards()
    assert len(cards) >= 25
    for c in cards:
        for o in engine.ORG:
            panel = _app.org_panel(c, o)
            for name in _app.SHORT.values():
                assert name in panel, (c["name"], o, name)
            if _app.exp_of(c):
                assert "Fingerprint sharing (experimental)" in panel
            tbl = _app.org_table(c, o)
            assert list(tbl["Training condition"][:4]) == list(_app.SHORT.values())


def test_manifest_loader_is_tolerant_and_stays_inside_samples(tmp_path, monkeypatch):
    os.environ["TP_OPEN"] = "1"
    import app as _app  # noqa
    (tmp_path / "ok.csv").write_text("a,label\n1,normal\n")
    (tmp_path / "manifest.json").write_text(json.dumps([{"file": "ok.csv"}, {"file": "../app.py"}, {"file": "missing.csv", "title": "x"}, {"title": "no file"}, "junk",
                                                        {"file": "sub/../ok.csv", "title": "same file again"}]))
    monkeypatch.setattr(_app, "SAMPLES", str(tmp_path))
    got = _app.load_manifest()
    assert [g["file"] for g in got] == ["ok.csv"] and got[0]["title"] == "ok.csv" and got[0]["kind"] == "sample" and got[0]["roles"] == {}
    (tmp_path / "manifest.json").write_text("not json")
    assert [g["file"] for g in _app.load_manifest()] == ["ok.csv"]                 # an unreadable manifest falls back to the files in the folder
    nv = _app.nvflare_status()
    assert nv is None or (nv["status"] in ("tested", "not built") and isinstance(nv["details"], list))


def test_role_reasons_and_plain_reading_escape_what_the_file_says():
    os.environ["TP_OPEN"] = "1"
    import app as _app  # noqa
    df = engine.example_data().rename(columns={"device_ip": "device_ip<script>"})
    ins = engine.inspect(df)
    cfg, numbers = _app.auto_cfg(df, ins, "x")
    why = _app.role_reasons(df, ins, cfg)
    assert cfg["label_col"] == "attack_type" and "attack" in why["label"] and why["benign"] == "a usual word for normal traffic"
    assert all(len(row) == 3 for row in why["identifiers"])
    assert _app._cn(" Label") == "' Label'" and _app._cn("Label") == "Label"
    card = _app.load_cards()[0]
    card["companies"]["A"]["name"] = "<b>x</b>"
    html = _app.plain_reading(card)
    assert "<b>x</b>" not in html.replace("<b>&lt;b&gt;x&lt;/b&gt;</b>", "") and "&lt;b&gt;x&lt;/b&gt;" in html


def test_report_html_is_self_contained():
    import glob as _g
    os.environ["TP_OPEN"] = "1"
    import app as _app  # noqa
    cards = [json.load(open(f)) for f in sorted(_g.glob(os.path.join(ROOT, "results", "*.json"))) if not os.path.basename(f).startswith("_")]
    html = _app.report_html(cards[0])
    assert "<html" in html and "Step 5. Scorecard" in html and "decision rule" in html.lower()
    assert "ThreatPrint report" in html and "Praxis Lab" not in html and "http" not in html.split("</style>")[0]   # no outside fonts or scripts


def test_confirm_form_warns_about_a_guessed_normal_value_and_leaves_out_empty_labels(monkeypatch):
    os.environ["TP_OPEN"] = "1"
    import app as _app  # noqa
    said = []
    monkeypatch.setattr(_app.st, "warning", lambda m, *a, **k: said.append(str(m)))
    monkeypatch.setattr(_app.st, "caption", lambda m, *a, **k: said.append(str(m)))
    df = engine.example_data()
    df["attack_type"] = df["attack_type"].replace({"normal": "web_browsing"})       # no value that means normal traffic
    df.loc[df.index[:7], "attack_type"] = None                                       # seven records without a label
    ins = engine.inspect(df)
    assert ins["label_col"] == "attack_type" and ins.get("benign_guess")
    cfg, numbers = _app._confirm_columns(df, ins, "t_guess")
    assert any("No label value looks like normal traffic" in m for m in said), said
    assert cfg.get("drop_labels") == ["nan"] and any("7 records have no label" in m for m in said), said
    cfg2, _ = _app.auto_cfg(df, ins, "t_auto")                                       # the live demo takes the roles as proposed: the same rule
    assert cfg2.get("drop_labels") == ["nan"]


def test_upload_reader_answers_in_one_sentence_and_cards_carry_their_warnings():
    import io
    os.environ["TP_OPEN"] = "1"
    import app as _app  # noqa
    pdf = io.BytesIO(b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n")
    pdf.name = "records.csv"
    with pytest.raises(engine.DataProblem) as e:
        _app._read_upload(pdf)
    assert "PDF" in str(e.value) and "Traceback" not in str(e.value)
    cards = _app.load_cards()
    assert all(isinstance(c.get("warnings"), list) for c in cards)
    edge = next(c for c in cards if c.get("id") == "edge_iiotset")
    assert any("random thirds" in w for w in edge["warnings"])


def test_verdicts_are_shown_in_the_words_of_the_decision_rule_and_no_card_number_moved():
    os.environ["TP_OPEN"] = "1"
    import app as _app  # noqa
    say = _app.say_verdict
    assert say("gain met, false-positive limit breached", "3_federated").startswith("not worth it")
    assert say("gain met, privacy trade-off", "2_sharing").startswith("trade-off")
    assert say("gain met", "2_sharing", {"trace": {"traced": 0.2}}).startswith("worth it")
    assert say("gain met", "2_sharing", {"trace": {"skipped": "x"}}) == "gain met (tracing not tested)"
    assert say("gain met", "3_federated") == "gain met" and say("not worth it (gain not met)").startswith("not worth it")
    assert "exposure of the fingerprint not measured" in _app.say_fp_verdict("not worth it (gain not met)")
    cards = {c["id"]: c for c in _app.load_cards()}
    ds = cards["datasense"]                                                   # the stored verdicts of the praxis dataset read as the run of record does
    shown = {o: (say(ds["verdicts"][o]["2_sharing"], "2_sharing", ds["companies"][o]), say(ds["verdicts"][o]["3_federated"], "3_federated", ds["companies"][o])) for o in "ABC"}
    assert shown["A"][0].startswith("trade-off") and shown["B"][0].startswith("trade-off") and shown["A"][1] == "gain met" and shown["B"][1] == "gain met"
    assert shown["C"][0].startswith("not worth it") and shown["C"][1].startswith("not worth it")
    assert _app.RECORD_NUM["datasense"] == {"H1": (41.1, 32.5, 49.6), "H2": (45.8, 37.0, 53.9)}
    assert _app.RECORD_NUM["edge_iiotset"] == {"H1": (70.8, 69.6, 72.0), "H2": (61.5, 60.4, 62.6)}
    for cid in ("datasense", "edge_iiotset"):                                 # the downloadable reports carry the run of record and the H3 wording
        html = _app.report_html(cards[cid])
        assert "Run of record." in html and "run of record (Hex" in html
        assert "<b>H3</b> tracing: " in html or "Result: <b>observed</b>" in html
        assert "Result: <b>supported</b>. An observed" not in html
    assert "label2" not in ds["step2"]["removed_columns"] and len(ds["step2"]["removed_columns"]) == ds["step2"]["removed"]
    ed = cards["edge_iiotset"]
    assert "Attack_type" not in ed["step2"]["removed_columns"] and "no device column" not in json.dumps(ed).lower()

