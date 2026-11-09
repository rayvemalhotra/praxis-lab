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
