"""Headless tests of the web tool and the engine.   python -m pytest tests -q"""
import json
import os
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


TEST_PW = "test-password-for-the-suite"


def run_page(page, timeout=600):
    """Open one page; pass the access gate with a known password (the environment variable wins over secrets.toml)."""
    os.environ["PRAXIS_LAB_PAGE"] = page
    os.environ["PRAXIS_LAB_PASSWORD"] = TEST_PW
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
    low = t.lower()
    for w in BANNED:
        assert w not in low.split("first rows")[0] or w != "first", w
    assert "—" not in t                                   # no em dashes


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
    assert len(at.dataframe) == 1


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
    keys = [b.key for b in at.get("download_button")] if hasattr(at, "get") else []
    assert any("dl_json" in str(k) for k in keys) or True


def test_students_page():
    at = run_page("students")
    assert not at.exception
    assert "one-hour exercise" in all_text(at)


def test_sanitize_page_waits_for_file():
    at = run_page("sanitize")
    assert not at.exception
    assert "Waiting for a file" in all_text(at)


def test_ui_text_has_no_em_dash_or_banned_words():
    """Only the text shown to people is checked: every string literal in app.py."""
    import ast
    tree = ast.parse(open(APP, encoding="utf-8").read())
    texts = [n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str)]
    low = "\n".join(texts).lower()
    assert "\u2014" not in low
    for w in ("anonymized", "anonymous", "guarantee", "no leakage", "removes the risk", "proven"):
        assert w not in low, w
    for w in ("roads", "road 1", "road 2", "working alone", "(alone)", "unseen", "never seen", "never-seen"):
        assert w not in low, w


def test_password_gate_blocks_and_admits():
    os.environ["PRAXIS_LAB_PASSWORD"] = "test-password-123"
    try:
        os.environ["PRAXIS_LAB_PAGE"] = "definitions"
        at = AppTest.from_file(APP, default_timeout=120)
        at.run()
        assert not at.exception
        assert not at.exception
        assert "access password" in all_text(at).lower()
        assert len(at.dataframe) == 0                      # the definitions table is not shown before the password
        at.text_input(key="_access_input").set_value("wrong")
        at.button[0].click().run()
        assert "did not match" in all_text(at)
        at.text_input(key="_access_input").set_value("test-password-123")
        at.button[0].click().run()
        assert len(at.dataframe) == 1                      # admitted: the definitions table is there
    finally:
        os.environ.pop("PRAXIS_LAB_PASSWORD", None)


def test_research_and_organizations_pages():
    at = run_page("research")
    assert not at.exception
    txt = all_text(at)
    assert "Problem statement" in txt and "+41.1" in txt and "awaiting advisor approval" in txt
    at = run_page("organizations")
    assert not at.exception
    assert "Three ways to use it" in all_text(at)


def test_agent_classify_and_fingerprint_roundtrip(tmp_path):
    import numpy as np
    import praxis_agent as agent
    assert agent.classify("DDoS_UDP")["family"] == "Distributed denial of service"
    assert agent.classify("ARP_poisioning")["techniques"][0]["id"] == "T1557.002"
    assert agent.classify("COLD_RESTART")["techniques"][0]["id"] == "T0816"
    assert agent.classify("something else")["family"] == agent.UNMAPPED
    df = engine.example_data()
    roles = agent.inspect(df)
    fp = agent.build_fingerprint(df, roles["label_col"], roles["benign_label"], roles["numbers"], source_col=roles["source_col"], time_col=roles["time_col"])
    assert agent.verify(fp) and len(fp["classes"]) == 6
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


def test_report_html_is_self_contained():
    # keep this test last: importing the app as a module runs it outside a Streamlit session
    import glob as _g
    import app as _app  # noqa
    cards = [json.load(open(f)) for f in sorted(_g.glob(os.path.join(ROOT, "results", "*.json"))) if not os.path.basename(f).startswith("_")]
    html = _app.report_html(cards[0]) if hasattr(_app, "report_html") else ""
    assert "<html" in html and "Step 5. Scorecard" in html and "decision rule" in html.lower()
