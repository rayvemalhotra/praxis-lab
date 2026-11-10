"""ThreatPrint: know what sharing buys, and what it exposes.

A web product that runs a privacy-aware evaluation of collaborative intrusion detection on any labeled intrusion
dataset, built on the procedure of a George Washington University doctoral praxis.

    streamlit run app.py

Pages: Overview, Live demo, Results, Evaluate (with the sanitizer), Agent, Research, Organizations, Glossary, Students.
The look lives in ui.py; the evaluation in engine.py; the local agent in threatprint_agent.py.
"""
import glob
import json
import math
import os
import re
import time

import pandas as pd
import streamlit as st

import engine
import threatprint_agent as agent
import ui
from engine import ORG, ROADS
from ui import H, esc

HERE = os.path.dirname(os.path.abspath(__file__))
_test_page = os.environ.get("TP_PAGE") or os.environ.get("PRAXIS_LAB_PAGE")      # the headless tests open one page at a time
RESULTS = os.path.join(HERE, "results")
CONTRIBUTIONS = os.environ.get("TP_CONTRIB_DIR") or os.path.join(HERE, "contributions")     # the live copy points this at the main folder
TOOL = ui.BRAND
VERSION = "0.4 (10 November 2026)"

st.set_page_config(page_title=f"{TOOL}: {ui.TAGLINE}", page_icon=os.path.join(HERE, "assets", "icon.png"),
                   layout="wide", initial_sidebar_state="collapsed")
ui.inject()

# ---------------------------------------------------------------- facts shown beside the tool's own reruns
RUN_OF_RECORD = {
    "recall": {"A": {"1_isolated": 0.0, "2_sharing": 59.9, "3_federated": 57.6, "4_centralized": 65.3},
               "B": {"1_isolated": 0.0, "2_sharing": 63.5, "3_federated": 79.9, "4_centralized": 67.8},
               "C": {"1_isolated": 0.0, "2_sharing": 0.0, "3_federated": 0.0, "4_centralized": 0.0}},
    "fp": {"A": {"1_isolated": 6.99, "2_sharing": 6.15, "3_federated": 4.37, "4_centralized": 7.14},
           "B": {"1_isolated": 6.32, "2_sharing": 6.53, "3_federated": 5.45, "4_centralized": 6.67},
           "C": {"1_isolated": 4.68, "2_sharing": 4.98, "3_federated": 6.53, "4_centralized": 5.47}},
    "traced": {"A": (55.3, 34.5), "B": (41.2, 16.9), "C": (41.1, 7.3)},
    "note": "The praxis run of record for DataSense (Hex, 11 October 2026, three seeds) reports H1 +41.1 points "
            "[32.5, 49.6] and H2 +45.8 points [37.0, 53.9]. The rerun shown here was computed on another machine; "
            "the decimals differ and every decision is the same.",
}
DATASENSE_NAMES = {"A": "A, network gear", "B": "B, cameras", "C": "C, sensors and plugs"}
DATASENSE_ORGS = {"A": ("A, network gear", "7 devices", "DoS"), "B": ("B, cameras", "10 devices", "DDoS"), "C": ("C, sensors and plugs", "21 devices", "MITM")}

APPROVED = {  # verbatim, from the praxis record; the thesis is a proposal until the advisor approves it
    "title": "Privacy-Aware Evaluation of Sanitized Attack-Record Sharing and Federated Learning for Intrusion Detection on Industrial Network Data",
    "problem_statement": "Deploying collaborative intrusion detection across industrial networks creates conflicts between privacy and reliability, leaving organizations unable to determine whether the benefits of collaboration outweigh its costs (Hernandez-Ramos et al., 2025; Zibak & Simpson, 2018).",
    "thesis": "Sanitized attack-record sharing and federated learning improve mean attack-class recall compared with isolated training across the withheld attack types evaluated in the study.",
    "RQ1": "To what extent does receiving sanitized attack records from peers improve attack-class recall for withheld attack types compared with isolated training?",
    "RQ2": "To what extent does federated learning improve attack-class recall for withheld attack types compared with isolated training?",
    "RQ3": "To what extent can the source device of a sanitized attack record be inferred after direct identifiers are removed?",
    "H1": "Sharing sanitized attack records improves mean attack-class recall for withheld attack types by at least 5 percentage points compared with isolated training.",
    "H2": "Federated learning improves mean attack-class recall for withheld attack types by at least 5 percentage points compared with isolated training.",
    "H3": "After direct identifiers are removed, a receiving peer with device-labelled reference traffic identifies the source device of shared attack records more accurately than the majority-device baseline.",
}
SHORT = {"1_isolated": "Isolated training", "2_sharing": "Sanitized attack-record sharing",
         "3_federated": "Federated learning", "4_centralized": "Centralized training"}
RECORD = {  # praxis runs of record, shown next to the tool's own rerun so that nobody mistakes one for the other
    "datasense": {"H1": "+41.1 [+32.5, +49.6]", "H2": "+45.8 [+37.0, +53.9]", "where": "Hex, 11 October 2026"},
    "edge_iiotset": {"H1": "+70.8 [+69.6, +72.0]", "H2": "+61.5 [+60.4, +62.6]", "where": "Hex, 19 October 2026"},
}


# ---------------------------------------------------------------- small helpers
RECORD_NUM = {"datasense": {"H1": (41.1, 32.5, 49.6), "H2": (45.8, 37.0, 53.9)},        # the same runs of record as numbers, for the tiles and the chart
              "edge_iiotset": {"H1": (70.8, 69.6, 72.0), "H2": (61.5, 60.4, 62.6)}}
ROR_CHECKS = ("Run of record for the same checks: centralized +44.4 [+36.6, +51.7]; flagging only sharing -3.5 [-8.9, +0.5], "
              "federated -4.1 [-10.2, +0.8]; nothing withheld sharing +2.3 [-3.9, +8.2], federated +0.8 [-6.0, +7.7]; "
              "membership test (separate 10-round run) no clear signal, all six 95% ranges include 0.5.")
RESEARCH_NOTE = "The local agent, the fingerprint and the MITRE ATT&CK mapping are product research, not part of the praxis."
FP_UNMEASURED = "What a fingerprint reveals about its sender has not been measured."
IN_PROGRESS = "Praxis in progress; not reviewed or endorsed by the university or the advisor."
H3_OBSERVED = ("Observed finding: tracing exceeded the majority-device baseline for every sender under the labelled-reference assumption. "
               "The statistical support is not called settled yet: the reported accuracy, its 95% range and the shuffle test are not computed on the same model settings. "
               "This is an open item of the praxis.")
H3_OBSERVED_TOOL = ("An observed finding, not a settled statistical result: the reported accuracy, its 95% range and the shuffle test are not computed on the same model settings.")
RULE_WORDS = ("Verdict words of the rule: not worth it (the gain is not met, or the false-positive rate rises by more than 1 point); trade-off (sanitized attack-record sharing: "
              "the gain is met and the organization's own sent records are traced above the baseline); worth it (sanitized attack-record sharing: the gain is met and they are not); "
              "gain met (federated learning).")


def baseline_name(card=None):
    """The comparison of H3 in the praxis's own words: devices on DataSense, hosts in every other table."""
    return "majority-device baseline" if (card or {}).get("id") == "datasense" else "majority-host baseline"


def say_verdict(v, road=None, c=None):
    """A stored verdict in the words of the decision rule of 8 October (display only; the cards and their numbers are not changed)."""
    v = v or "not measured"
    if v == "gain met, false-positive limit breached":
        return "not worth it (false-positive rate up more than 1 point)"
    if v == "gain met, privacy trade-off":
        return "trade-off (gain met, its sent records traced)"
    if v == "gain met" and road == "2_sharing":
        tested = "traced" in ((c or {}).get("trace") or {})
        return "worth it (gain met, its sent records not traced)" if tested else "gain met (tracing not tested)"
    return v


def say_fp_verdict(v):
    """The verdict of the experimental fingerprint row: the rule's words, and always what was not measured."""
    t = say_verdict(v)
    if "exposure" in t:
        return t
    return (t[:-1] + "; exposure of the fingerprint not measured)") if t.endswith(")") else t + " (exposure of the fingerprint not measured)"


def ror_text(card):
    """The run-of-record note of the two praxis datasets (page and report use the same words)."""
    if card.get("id") == "datasense":
        return RUN_OF_RECORD["note"]
    if card.get("id") == "edge_iiotset":
        return (f"The praxis run of record for Edge-IIoTset ({RECORD['edge_iiotset']['where']}) reports H1 {RECORD['edge_iiotset']['H1']} and "
                f"H2 {RECORD['edge_iiotset']['H2']}. The local run shown here was computed on another machine; the decimals differ and the H1 and H2 decisions are the same.")
    return ""


def pct(x, d=1):
    if x is None or (isinstance(x, float) and math.isnan(x)):
        return "not measured"
    return f"{x * 100:.{d}f}%"


def pts(g):
    if not g or g.get("gain") is None or (isinstance(g["gain"], float) and math.isnan(g["gain"])):
        return "not measured"
    return f"{g['gain'] * 100:+.1f} [{g['lo'] * 100:+.1f}, {g['hi'] * 100:+.1f}]"


def kb(b):
    if b is None:
        return "not measured"
    if b == 0:
        return "0"
    if b >= 1_000_000:
        return f"{b / 1_000_000:.2f} MB"
    if b >= 1000:
        return f"{b / 1000:.0f} KB"
    return f"{b} bytes"


def _orgs(t):
    return t.replace("companies", "organizations").replace("Companies", "Organizations").replace("company", "organization").replace("Company", "Organization")


def load_cards():
    cards = []
    for f in sorted(glob.glob(os.path.join(RESULTS, "*.json"))):
        if os.path.basename(f).startswith("_"):
            continue
        c = json.load(open(f))
        for k in ("about", "rules"):
            if isinstance(c.get(k), str):
                c[k] = _orgs(c[k])
        c["rules"] = {k: (_orgs(v) if isinstance(v, str) else v) for k, v in c["rules"].items()}
        c["info"] = {k: (_orgs(v) if isinstance(v, str) else v) for k, v in (c.get("info") or {}).items()}
        if c.get("id") == "datasense":
            for o in ORG:
                c["companies"][o]["name"] = DATASENSE_NAMES[o]
        if "warnings" not in c:                                  # cards made before the engine wrote this key: the same sentences, no rerun
            try:
                c["warnings"] = engine.warnings_for(c)
            except Exception:
                c["warnings"] = []
        cards.append(c)
    order = {"the study": 0, "ranking check": 1}
    cards.sort(key=lambda c: (order.get(c.get("study_role"), 2), c["name"]))
    return cards


def exp_of(card):
    return (card.get("experimental") or {}).get("fingerprint_sharing")


def org_table(card, o):
    """One organization, all four training conditions (and the experimental arm under them when it was run)."""
    c = card["companies"][o]
    v = card.get("verdicts", {}).get(o, {})
    rows = []
    for road in ROADS:
        g = c["gain"].get(road) if road != "1_isolated" else None
        row = {"Training condition": SHORT[road], "Recall, withheld type": pct(c["named"].get(road)), "Flagged": pct(c["flagged"].get(road)),
               "False-positive rate": pct(c["false_alarm"].get(road), 2),
               "Gain vs isolated, this local run [95% range]": "baseline" if road == "1_isolated" else pts(g),
               "Data sent": kb(c.get("bytes", {}).get(road)), "Steps": f"{c.get('steps', {}).get(road, 0):,}" if c.get("steps") else "not measured",
               "Verdict": say_verdict(v.get(road, "not measured"), road, c)}
        if card.get("id") == "datasense":
            row["Run of record, recall"] = f"{RUN_OF_RECORD['recall'][o][road]:.1f}%"
            row["Run of record, false-positive rate"] = f"{RUN_OF_RECORD['fp'][o][road]:.2f}%"
        rows.append(row)
    e = exp_of(card)
    if e:
        r = e["orgs"][o]
        row = {"Training condition": "Fingerprint sharing (experimental, not a praxis condition)", "Recall, withheld type": pct(r["named"]), "Flagged": pct(r["flagged"]),
               "False-positive rate": pct(r["false_alarm"], 2), "Gain vs isolated, this local run [95% range]": pts(r["gain"]), "Data sent": kb(r["bytes"]),
               "Steps": f"{r.get('steps', 0):,}", "Verdict": say_fp_verdict(r["verdict"])}
        if card.get("id") == "datasense":
            row["Run of record, recall"] = "not part of the praxis"
            row["Run of record, false-positive rate"] = "not part of the praxis"
        rows.append(row)
    return pd.DataFrame(rows)


def attack_line(label):
    c = agent.classify(label)
    return f"Attack family: {c['family']}. MITRE ATT&CK: {agent.technique_text(c['techniques'])}."


def family_stats(cards):
    """Across the library: for each attack family of the withheld attack types, the mean attack-class recall under each condition."""
    rows = []
    for c in cards:
        e = exp_of(c)
        for o in ORG:
            k = c["companies"][o]
            rows.append(dict(family=agent.classify(k["never_seen"])["family"],
                             iso=k["named"]["1_isolated"], sha=k["named"]["2_sharing"], fed=k["named"]["3_federated"], cen=k["named"]["4_centralized"],
                             fp=(e["orgs"][o]["named"] if e else float("nan"))))
    d = pd.DataFrame(rows)
    default = {}
    for fam, _, ids in agent.FAMILIES:                       # the family's general techniques, not one label's specific one
        default.setdefault(fam, ", ".join(ids))
    g = d.groupby("family").agg(cases=("iso", "size"), iso=("iso", "mean"), sha=("sha", "mean"), fed=("fed", "mean"),
                                 cen=("cen", "mean"), fp=("fp", "mean")).reset_index().sort_values("cases", ascending=False)
    g["techniques"] = g["family"].map(lambda f: default.get(f, "no mapping"))
    return g


def run_label(card):
    return "tool rerun" if card.get("id") == "datasense" else "local run"


# ---------------------------------------------------------------- the scorecard, drawn
def org_panel(card, o):
    """One organization as a panel: who it is, what is withheld, the four training conditions as bars, the verdicts, tracing."""
    c, s, v = card["companies"][o], card["step1"][o], card.get("verdicts", {}).get(o, {})
    cl = agent.classify(c["never_seen"])
    rows = [(SHORT[r], c["named"].get(r), ui.COND[r], False) for r in ROADS]
    e = exp_of(card)
    if e:
        rows.append(("Fingerprint sharing (experimental)", e["orgs"][o]["named"], ui.COPPER, True))
    fam = ui.chip(cl["family"], "indigo") + "".join(ui.chip(t["id"]) for t in cl["techniques"][:3])
    hosts = f"{s['sources']} hosts · " if s.get("sources") else ""
    fpr = ", ".join(f"{n} {pct(c['false_alarm'].get(r), 2)}" for r, n in zip(ROADS, ("isolated", "sharing", "federated", "centralized")))
    t = c.get("trace") or {}
    if "traced" in t:
        trace = (f"<div class='sub' style='margin-bottom:6px'><b>Tracing.</b> A peer traced this organization's sanitized attack records to their source host:</div>"
                 + ui.duo(t["traced"], t["guessing"], "traced to the source host", baseline_name(card))
                 + f"<div class='sub'>Gain {t['advantage'] * 100:+.1f} points, 95% range between {t['lo'] * 100:+.1f} and {t['hi'] * 100:+.1f}; {t['sources']} hosts; shuffle test p = {t['p_value']:.3f}."
                 + (f" Note: {esc(t['note'])}." if t.get("note") else "") + "</div>")
    else:
        trace = f"<div class='sub'><b>Tracing.</b> {esc(t.get('skipped', 'not measured for this organization'))}.</div>"
    ror = ""
    if card.get("id") == "datasense":
        r = RUN_OF_RECORD["recall"][o]
        ror = (f"<div class='sub'>Run of record, recall: isolated {r['1_isolated']:.1f}%, sharing {r['2_sharing']:.1f}%, federated {r['3_federated']:.1f}%, centralized {r['4_centralized']:.1f}%. "
               "The bars above are a tool rerun, not the run of record.</div>")
    return (f"<div class='tp-org'><div class='top'><div class='name'>{esc(c['name'])}</div>{ui.badge(run_label(card), 'na')}</div>"
            f"<div class='meta'>{hosts}trains on {s.get('train_after', s['train']):,} records · {s['test_never_seen']:,} test records of the withheld type</div>"
            f"<div style='margin-bottom:10px'>{ui.chip('withheld: ' + str(c['never_seen']), 'dark')}{fam}</div>"
            f"<div class='lab'>Attack-class recall on the withheld type</div>"
            f"{ui.bars(rows)}"
            f"<div class='row' style='margin-top:8px'><span>Sanitized attack-record sharing</span>{ui.verdict_badge(say_verdict(v.get('2_sharing'), '2_sharing', c))}</div>"
            f"<div class='row'><span>Federated learning</span>{ui.verdict_badge(say_verdict(v.get('3_federated'), '3_federated', c))}</div>"
            f"<div class='sub'><b>False-positive rate.</b> {fpr}.</div>{ror}"
            f"<div class='sep'>{trace}</div></div>")


def hyp_tile(tag, title, h, color, card=None, name=None):
    if not h:
        return f"<div class='tp-hyp'><div class='h'><b>{tag}</b>{ui.badge('not measured')}</div><div class='big'>n/a</div><div class='d'>{esc(title)}</div></div>"
    cid = (card or {}).get("id")
    rec, num = RECORD.get(cid, {}), RECORD_NUM.get(cid, {})
    badge = ui.badge('supported', 'ok') if h['clears'] else ui.badge('not supported', 'no')
    if name in num:                                  # the two praxis datasets lead with the run of record; the tool's own run is the small line
        g, lo, hi = num[name]
        return (f"<div class='tp-hyp'><div class='h'><b>{tag}</b>{badge}</div>"
                f"<div class='big'>{g:+.1f} <small>points</small></div>"
                f"<div class='d'>{esc(title)}. Run of record ({rec['where']}), 95% range [{lo:+.1f}, {hi:+.1f}]. "
                f"The {run_label(card)} on another machine gave {h['gain'] * 100:+.1f} [{h['lo'] * 100:+.1f}, {h['hi'] * 100:+.1f}], not the run of record; the decision is the same.</div>"
                f"{ui.bullet(g, lo, hi, color)}</div>")
    return (f"<div class='tp-hyp'><div class='h'><b>{tag}</b>{badge}</div>"
            f"<div class='big'>{h['gain'] * 100:+.1f} <small>points</small></div>"
            f"<div class='d'>{esc(title)}. 95% range [{h['lo'] * 100:+.1f}, {h['hi'] * 100:+.1f}], {run_label(card or {})}, not the run of record.</div>"
            f"{ui.bullet(h['gain'] * 100, h['lo'] * 100, h['hi'] * 100, color)}</div>")


def show_card(card, heading=True, steps=True):
    """The whole scorecard of one dataset: header, three organization panels, hypothesis tiles, then every number in tables.
    steps=False leaves out the step numbers of the procedure (the live demo counts its own stages)."""
    s1, s2, rules = card["step1"], card["step2"], card["rules"]
    n_rec = sum(s1[o]["train"] + s1[o]["val"] + s1[o]["test"] for o in ORG)
    by = "hosts" if ("groups of hosts" in rules["companies"] or "device groups" in rules["companies"]) else "random thirds"
    quick = card.get("budget", {}).get("name") == "quick"
    chips = (ui.chip(card.get("study_role", "your data"), "dark") + ui.chip(f"{n_rec:,} records") + ui.chip(f"{s2['kept_numbers']} behavior numbers kept", "teal")
             + ui.chip(f"{s2['removed']} columns removed", "teal") + ui.chip(f"organizations by {by}") + ui.chip(f"{len(card['seeds'])} seed{'s' if len(card['seeds']) != 1 else ''}")
             + ui.chip("quick look" if quick else "protocol budget", "amber" if quick else "indigo"))
    H(f"<div class='tp-dshead'><div><h3>{esc(card['name'] if heading else 'Your scorecard')}</h3><p>{esc(card.get('about', ''))}</p><div>{chips}</div></div>{ui.mini_print(card.get('id') or card['name'], 104, ridges=11)}</div>")
    if ror_text(card):
        H(f"<div class='tp-callout'><b>Run of record.</b> {ror_text(card)}</div>")
    notes = card.get("warnings")
    if notes is None and quick:
        notes = ["Quick look: a smaller training budget, one seed and fewer resamples than the protocol. It shows whether the data works in the tool; it is not a result to report."]
    if notes:
        H("<div class='tp-note' style='margin-top:10px'>" + "".join(f"<p>{esc(w)}</p>" for w in notes) + "</div>")

    H(f"<div class='tp-sec tight'><div class='k'>{'Steps 3 and 4' if steps else 'Results'}</div><h2>Four training conditions, tested on the withheld attack type</h2></div>")
    H(ui.legend([(SHORT[r], ui.COND[r]) for r in ROADS] + ([("Fingerprint sharing (experimental, not a praxis condition)", ui.COPPER)] if exp_of(card) else [])))
    ui.grid([org_panel(card, o) for o in ORG])
    st.caption("The attack family and the technique numbers on each panel are the tool's mapping of the dataset's own labels to MITRE ATT&CK: product research, not part of the praxis."
               + (" " + FP_UNMEASURED if exp_of(card) else ""))

    H(f"<div class='tp-sec tight'><div class='k'>{'Step 5' if steps else 'Hypotheses'}</div><h2>{'Scorecard' if steps else 'What the run says about the hypotheses'}</h2></div>")
    Hy = card["hypotheses"]
    h3 = Hy.get("H3")
    if h3:
        t3 = (f"<div class='tp-hyp'><div class='h'><b>H3 · TRACING</b>{ui.badge('observed', 'amber') if h3['yes'] else ui.badge('not observed', 'na')}</div>"
              f"<div class='big'>{'All' if h3['yes'] else 'Not all'} {h3['companies']} <small>organizations</small></div>"
              f"<div class='d'>Sanitized attack records traced above the {baseline_name(card)}. Gain over the baseline from {h3['low'] * 100:+.1f} to {h3['high'] * 100:+.1f} points, {run_label(card)}. "
              f"{H3_OBSERVED if card.get('id') == 'datasense' else H3_OBSERVED_TOOL}</div></div>")
    else:
        t3 = (f"<div class='tp-hyp'><div class='h'><b>H3 · TRACING</b>{ui.badge('not tested')}</div><div class='big'>n/a</div>"
              f"<div class='d'>{esc(Hy.get('H3_note') or 'not measured')}.</div></div>")
    tiles = [hyp_tile("H1 · SANITIZED SHARING", "Sanitized attack-record sharing: mean gain in attack-class recall over the three organizations", Hy.get("H1"), ui.GOLD, card, "H1"),
             hyp_tile("H2 · FEDERATED", "Federated learning: mean gain in attack-class recall over the three organizations", Hy.get("H2"), ui.STEEL, card, "H2"), t3]
    e = exp_of(card)
    if e:
        g = e["mean_gain"]
        tiles.append(f"<div class='tp-hyp exp'><div class='h'><b>FINGERPRINTS</b>{ui.badge('experimental', 'amber')}</div>"
                     f"<div class='big'>{g['gain'] * 100:+.1f} <small>points</small></div>"
                     f"<div class='d'>Fingerprint sharing: not a praxis training condition. 95% range [{g['lo'] * 100:+.1f}, {g['hi'] * 100:+.1f}], local run. What a fingerprint reveals about its sender has not been measured.</div>"
                     f"{ui.bullet(g['gain'] * 100, g['lo'] * 100, g['hi'] * 100, ui.COPPER)}</div>")
    ui.grid(tiles)

    st.markdown("")
    with st.expander("All numbers: every training condition for each organization"):
        for o in ORG:
            c = card["companies"][o]
            note = " (tool rerun; the run of record is in the last two columns)" if card.get("id") == "datasense" else " (local run of the tool)"
            st.markdown(f"**{c['name']}**, withheld attack type **{c['never_seen']}**, {c['test_rows']:,} test records of that type{note}")
            st.caption(attack_line(c["never_seen"])
                       + (" The fingerprint row is judged against the experiment's own isolated baseline, which can differ in the decimals from the isolated row above it." if exp_of(card) else "")
                       + (" The table below is a tool rerun, not the run of record." if card.get("id") == "datasense" else " The table below is a local run of the tool."))
            ui.table(org_table(card, o), wrap=("Training condition", "Verdict"), row_class=lambda n, r: "exp" if str(r["Training condition"]).startswith("Fingerprint") else "")
    with st.expander(("Step 1: the" if steps else "The") + " three organizations and their withheld attack types"):
        rows = []
        for o in ORG:
            s = s1[o]
            rows.append({"Organization": card["companies"][o]["name"], "Hosts": str(s.get("sources")) if s.get("sources") else "none in the table given to the tool",
                         "Training records": f"{s['train']:,}", "Withheld attack type": s["never_seen"], "Taken out": f"{s.get('withheld', 0):,}",
                         "Trains on": f"{s.get('train_after', s['train']):,}", "of which normal": f"{s.get('train_normal', 0):,}", "of which attack": f"{s.get('train_attack', 0):,}",
                         "Test records of the withheld type": f"{s['test_never_seen']:,}", "Attack events in those": str(s.get("events_never_seen", ""))})
        ui.table(pd.DataFrame(rows), wrap=("Organization",))
        st.caption(f"Organizations: {rules['companies']}. Split: {rules['split']}.")
    with st.expander(("Step 2: sanitizing" if steps else "Sanitizing") + ", which columns were kept and which were removed"):
        st.markdown(f"{s2['raw_columns']} columns in the table given to the tool. Kept: {s2['kept_numbers']} behavior numbers and the attack type. Removed: {s2['removed']} columns (identifiers, text, other labels)."
                    + (" The publisher's raw file has 63 columns; the praxis uses a cleaned copy." if card.get("id") == "edge_iiotset" else ""))
        H("<div style='margin:6px 0 4px 0;font-weight:700'>Kept</div><div>" + "".join(ui.chip(c, "teal") for c in s2.get("kept", [])) + "</div>"
          "<div style='margin:10px 0 4px 0;font-weight:700'>Removed</div><div>" + "".join(ui.chip(c) for c in s2.get("removed_columns", s2.get("removed_examples", []))) + "</div>")
    with st.expander("How it was run, and the separate checks"):
        b = card.get("budget") or {}
        st.markdown(f"Same network ({rules['network']}), the same step budget per tested detector ({rules['passes']} passes of the largest organization at batch {rules['batch']}; the steps of each training condition are in the tables above), "
                    f"same alarm rule (95th percentile of the organization's own normal validation scores). Federated learning: {card['checks']['rounds']} rounds, "
                    f"{rules['local_epochs']} local passes per round. Seeds: {len(card['seeds'])}.")
        if b:
            st.caption(f"Tracing test: {b.get('trace_seeds')} random forests of {b.get('trace_trees')} trees on at most {engine.TRACE_MAX:,} records per side; "
                       f"shuffle test {b.get('trace_permutations')} shuffles with {b.get('trace_perm_trees', 100)}-tree forests"
                       + (f" on at most {b['trace_perm_rows']:,} records per side" if b.get('trace_perm_rows') else "") + f". Budget: {b.get('name')}.")
        ch = card["checks"]
        st.markdown("**Separate checks (local run of the tool).** " +
                    f"Centralized training against isolated training: {pts(ch.get('pooled'))} points. " +
                    f"Flagging only (attack or not, type ignored): sharing {pts(ch['flagged']['H1'])}, federated {pts(ch['flagged']['H2'])}. " +
                    (f"Nothing withheld: sharing {pts(ch['nothing_withheld']['H1'])}, federated {pts(ch['nothing_withheld']['H2'])}. " if ch.get("nothing_withheld") else "Nothing-withheld check: not measured. ") +
                    "Membership test on model weights: not measured in this tool.")
        if card.get("id") == "datasense":
            st.caption("Tool rerun above. " + ROR_CHECKS)
        m = card.get("sharing_minus_federated", {}).get("mean")
        if m:
            st.markdown(f"**Sharing minus federated**, same test events, local run: {m['diff'] * 100:+.1f} points, 95% range [{m['lo'] * 100:+.1f}, {m['hi'] * 100:+.1f}].")
        if card.get("computed"):
            st.caption(card["computed"])
    info = card.get("info") or {}
    if info:
        with st.expander("About this dataset"):
            for k, label in (("maker", "Made by"), ("year", "Year"), ("what", "What it is"), ("records", "Records used"),
                             ("attacks", "Attack types"), ("host", "Host or device column"), ("role_text", "Role in the praxis"), ("source", "Source")):
                if info.get(k):
                    st.markdown(f"**{label}.** {info[k]}")
    with st.expander("The decision rule behind the verdicts"):
        st.markdown(engine.verdicts.__doc__)
        st.caption(RULE_WORDS)


def report_html(card):
    """A self-contained HTML report of one scorecard (print it to PDF from the browser)."""
    e = esc
    Hy = card["hypotheses"]
    rows1 = "".join(f"<tr><td>{e(card['companies'][o]['name'])}</td><td>{e(str(card['step1'][o].get('sources') or 'none in the table given to the tool'))}</td>"
                    f"<td>{card['step1'][o]['train']:,}</td><td>{e(card['step1'][o]['never_seen'])}</td><td>{card['step1'][o].get('withheld', 0):,}</td>"
                    f"<td>{card['step1'][o].get('train_after', card['step1'][o]['train']):,}</td><td>{card['step1'][o]['test_never_seen']:,}</td></tr>" for o in ORG)
    org_tables = ""
    label = ("The table below is a tool rerun, not the run of record." if card.get("id") == "datasense" else "The table below is a local run of the tool.")
    ror = (f"<div class='box'><b>Run of record.</b> {e(ror_text(card))}</div>" if ror_text(card) else "")
    for o in ORG:
        df = org_table(card, o)
        head = "".join(f"<th>{e(str(c))}</th>" for c in df.columns)
        body = "".join("<tr>" + "".join(f"<td>{e(str(v))}</td>" for v in r) + "</tr>" for r in df.itertuples(index=False))
        tr = card["companies"][o].get("trace") or {}
        trace = (f"<p class='small'>Tracing ({run_label(card)}): traced {tr['traced'] * 100:.1f}% against the {baseline_name(card)} of {tr['guessing'] * 100:.1f}%; gain {tr['advantage'] * 100:+.1f} points, "
                 f"95% range between {tr['lo'] * 100:+.1f} and {tr['hi'] * 100:+.1f}; {tr['sources']} hosts; shuffle test p = {tr['p_value']:.3f}.</p>" if "traced" in tr else
                 f"<p class='small'>Tracing: {e(tr.get('skipped', 'not measured'))}.</p>")
        org_tables += (f"<h3>{e(card['companies'][o]['name'])}, withheld attack type {e(card['companies'][o]['never_seen'])}, {card['companies'][o]['test_rows']:,} test records</h3>"
                       f"<p class='small'>{e(attack_line(card['companies'][o]['never_seen']))} {label}</p>"
                       f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>{trace}")

    def hyp(name, h, what):
        if not h:
            return f"<p><b>{name}</b> {what}: not measured.</p>"
        num, rec = RECORD_NUM.get(card.get("id"), {}), RECORD.get(card.get("id"), {})
        result = f"Rule: the whole range above 5 points. Result: <b>{'supported' if h['clears'] else 'not supported'}</b>."
        rerun = f"{h['gain'] * 100:+.1f} points, 95% range [{h['lo'] * 100:+.1f}, {h['hi'] * 100:+.1f}]"
        if name in num:
            g, lo, hi = num[name]
            return (f"<p><b>{name}</b> {what}: run of record ({e(rec['where'])}) {g:+.1f} points, 95% range [{lo:+.1f}, {hi:+.1f}]. "
                    f"The {run_label(card)} on another machine gave {rerun}, not the run of record; the decision is the same. {result}</p>")
        return f"<p><b>{name}</b> {what}: {rerun}, {run_label(card)}, not the run of record. {result}</p>"
    h3 = Hy.get("H3")
    h3txt = (f"<p><b>H3</b> tracing ({run_label(card)}): sanitized attack records were traced above the {baseline_name(card)} in {'all' if h3['yes'] else 'not all'} {h3['companies']} organizations tested "
             f"(gain over the baseline from {h3['low'] * 100:+.1f} to {h3['high'] * 100:+.1f} points). Result: <b>{'observed' if h3['yes'] else 'not observed'}</b>. "
             f"{e(H3_OBSERVED if card.get('id') == 'datasense' else H3_OBSERVED_TOOL)}</p>" if h3
             else f"<p><b>H3</b> tracing: {e(Hy.get('H3_note') or 'not measured')}.</p>")
    computed = (card.get("computed") or "").strip().rstrip(".")
    opening = (computed[:1].upper() + computed[1:] + ". " if computed else "") + ("Tool rerun, not the run of record." if card.get("id") == "datasense" else "Local run of the tool, not the run of record.")
    ch = card["checks"]
    b = card.get("budget") or {}
    return f"""<!doctype html><html><head><meta charset='utf-8'><title>{e(TOOL)} report: {e(card['name'])}</title>
<style>{ui.REPORT_CSS}</style></head><body>
<div class='brand'>{ui.mark_svg(30, uid='r')}<span>{ui.wordmark()}</span></div>
<h1>{e(TOOL)} report</h1><div class='muted'>{e(card['name'])}. Generated {e(time.strftime('%d %B %Y, %H:%M'))}. {e(opening)}</div>
<p>{e(card.get('about', ''))}</p>{ror}
<h2>Step 1. Three organizations and their withheld attack types</h2>
<table><thead><tr><th>Organization</th><th>Hosts</th><th>Training records</th><th>Withheld attack type</th><th>Taken out</th><th>Trains on</th><th>Test records of the withheld type</th></tr></thead><tbody>{rows1}</tbody></table>
<p class='small'>Organizations: {e(card['rules']['companies'])}. Split: {e(card['rules']['split'])}.</p>
<h2>Step 2. Sanitizing</h2><p>{card['step2']['raw_columns']} columns in the table given to the tool{" (the publisher's raw file has 63 columns; the praxis uses a cleaned copy)" if card.get('id') == 'edge_iiotset' else ''}. Kept: {card['step2']['kept_numbers']} behavior numbers and the attack type. Removed: {card['step2']['removed']} columns.</p>
<p class='small'>Kept: {e(', '.join(card['step2'].get('kept', [])))}</p><p class='small'>Removed: {e(', '.join(card['step2'].get('removed_columns', [])))}</p>
<h2>Steps 3 and 4. Four training conditions, tested on the withheld attack type</h2>
<p class='small'>Network {e(card['rules']['network'])}; {card['rules']['passes']} passes of the largest organization at batch {card['rules']['batch']}; alarm rule: 95th percentile of the organization's own normal validation scores;
federated learning {card['checks']['rounds']} rounds of {card['rules']['local_epochs']} local passes; seeds {len(card['seeds'])}; tracing {b.get('trace_seeds')} forests of {b.get('trace_trees')} trees, shuffle test {b.get('trace_permutations')} shuffles. Budget: {e(str(b.get('name')))}.</p>
{org_tables}
<h2>Step 5. Scorecard</h2>
{hyp('H1', Hy.get('H1'), 'sanitized attack-record sharing, mean gain in attack-class recall over the three organizations')}
{hyp('H2', Hy.get('H2'), 'federated learning, mean gain in attack-class recall over the three organizations')}
{h3txt}
<p class='small'>Separate checks ({run_label(card)}, not the run of record): centralized training against isolated training {e(pts(ch.get('pooled')))} points; flagging only (attack or not, type ignored) sharing {e(pts(ch['flagged']['H1']))}, federated {e(pts(ch['flagged']['H2']))};
{('nothing withheld: sharing ' + e(pts(ch['nothing_withheld']['H1'])) + ', federated ' + e(pts(ch['nothing_withheld']['H2'])) + '.') if ch.get('nothing_withheld') else 'nothing-withheld check: not measured.'} Membership test on model weights: not measured in this tool.{(' ' + e(ROR_CHECKS)) if card.get('id') == 'datasense' else ''}</p>
<div class='box'><b>The decision rule.</b> Gain: the low end of the 95% range of the gain in attack-class recall must be above 5 points. False positives: the false-positive rate may rise by at most 1 point over isolated training.
Privacy (sharing): if the gain is met but the organization's own sent records are traced above the {baseline_name(card)}, the result is a trade-off. Data sent is reported, not judged. {e(RULE_WORDS)}</div>
<p class='muted'>{e(TOOL)}, built on the praxis procedure of Rayve Malhotra (George Washington University, SEAS 8499). {IN_PROGRESS} Sanitized means direct identifiers removed, nothing more. The study claims rest on the DataSense dataset alone; every other dataset shows that the procedure runs on new data with the tool's own split. Fingerprint sharing, where shown, is experimental and not a praxis training condition. {FP_UNMEASURED} The attack families and MITRE ATT&CK lines are the tool's mapping: product research, not part of the praxis. This report was generated by the tool, which was built with AI assistance; none of it is text from the praxis document.</p>
</body></html>"""


def download_buttons(card, key):
    c0, c1, c2 = st.columns(3)
    c0.download_button("Download the report (HTML, print to PDF)", report_html(card), file_name=f"{ui.SLUG}_report_{key}.html", mime="text/html", key=f"dl_html_{key}", type="primary", use_container_width=True)
    c1.download_button("Download the scorecard (JSON)", json.dumps(card, indent=1, default=float), file_name=f"{ui.SLUG}_{key}.json", mime="application/json", key=f"dl_json_{key}", use_container_width=True)
    tbl = pd.concat([org_table(card, o).assign(Organization=card["companies"][o]["name"]) for o in ORG])
    c2.download_button("Download the tables (CSV)", engine.csv_safe(tbl).to_csv(index=False), file_name=f"{ui.SLUG}_{key}_tables.csv", mime="text/csv", key=f"dl_csv_{key}", use_container_width=True)


# ---------------------------------------------------------------- navigation pieces
PG = {}
NAV = [("start", "Overview"), ("demo", "Live demo"), ("results", "Results"), ("evaluate", "Evaluate"), ("agent", "Agent"),
       ("research", "Research"), ("organizations", "Organizations"), ("definitions", "Glossary"), ("students", "Students")]


def link(key, label, style="cta_dark", uid=""):
    """A button that goes to another page (a plain chip in the headless tests, where there is no navigation)."""
    if _test_page or key not in PG:
        H(f"<span class='tp-chip dark'>{esc(label)}</span>")
        return
    with st.container(key=f"{style}_{key}_{uid}"):
        st.page_link(PG[key], label=label)


def top_nav(current):
    with st.container(key="tp_nav"):
        if _test_page or not PG:
            H(f"<div style='display:flex;justify-content:space-between;align-items:center'>{ui.logo()}<div class='tp-navstatic'>" + "".join(f"<span>{esc(t)}</span>" for _, t in NAV) + "</div></div>")
            return
        cols = st.columns([2.5, 1.15, 1.2, 1.0, 1.1, 0.9, 1.15, 1.55, 1.1, 1.1, 1.3])
        with cols[0]:
            H(ui.logo())
        for col, (key, label) in zip(cols[1:], NAV):
            with col:
                if key == current:
                    with st.container(key=f"tp_on_{key}"):
                        st.page_link(PG[key], label=label)
                else:
                    st.page_link(PG[key], label=label)
        with cols[-1]:                                   # the same nine links as one menu; CSS shows it instead of the row on a narrow screen
            with st.container(key="tp_navmenu"):
                with st.popover("Menu"):
                    for key, label in NAV:
                        with st.container(key=f"tp_mon_{key}" if key == current else f"tp_mit_{key}"):
                            st.page_link(PG[key], label=label)


def footer():
    H(f"<div class='tp-footer'><div>{ui.logo()}<div style='margin-top:12px;max-width:520px'>{esc(ui.TAGLINE)} Built on the procedure of a George Washington University doctoral praxis "
      f"by Rayve Malhotra (SEAS 8499). {IN_PROGRESS} The tool and the text of this site were built with AI assistance; none of it is text from the praxis document. "
      f"The study design, protocol, hypotheses and decisions are the author's. {RESEARCH_NOTE}</div></div>"
      f"<div class='r'><b>{esc(TOOL)}</b> {VERSION}<br>Uploads are not stored. A fingerprint is kept only if you choose to contribute it.<br>Sanitized means direct identifiers removed, nothing more.</div></div>")


def sub_hero(eyebrow, title, lead, right=""):
    H(ui.sub_hero_html(eyebrow, title, lead, right))


# ---------------------------------------------------------------- pages
def page_start():
    cards = load_cards()
    r = RUN_OF_RECORD["recall"]["B"]
    shot = (f"<div class='tp-heroart'>{ui.print_art('h')}"
            f"<div class='tp-shot'><div class='t'>DataSense · run of record</div><div class='n'>Organization B, cameras · DDoS withheld</div>"
            + ui.bars([(SHORT[k], r[k] / 100.0, ui.COND[k], False) for k in ROADS], width=360, timed=True, dark=True)
            + "<div class='f'>sharing: trade-off (gain met, its sent records traced) · federated: gain met<br>Tracing, run of record: <b>41.2%</b> of B's sanitized records traced to their device, against the majority-device baseline of <b>16.9%</b></div></div></div>")
    with st.container(key="tp_hero"):
        c1, c2 = st.columns([1.12, 0.88], gap="large")
        with c1:
            H("<span class='tp-eyebrow'>Collaborative defense, measured</span>"
              "<h1><span class='s'>Know what sharing buys.</span><br><em>Know what it exposes.</em></h1>"
              f"<p class='lead'>{esc(TOOL)} measures, on your own intrusion records, what working with other organizations would add to your detection of attack types you have not trained on, "
              "and what it would give away. Four training conditions, one scorecard, one decision rule.</p>")
            b1, b2, _ = st.columns([1.0, 1.45, 0.25])
            with b1:
                link("demo", "Watch the live demo", "cta_onhero")
            with b2:
                link("results", f"See the {len(cards)} result cards", "cta_dark", "hero")
            H("<div class='tp-trust'><span><i></i>Built on a GWU doctoral praxis, in progress</span><span><i></i>MITRE ATT&CK v20.1 mapping (product research)</span><span><i></i>Runs inside your network</span></div>")
        with c2:
            H(shot)
    ui.stats([(f"{len(cards)}", "result cards run with the protocol budget, the praxis dataset and its ranking check among them", ""),
              ("4", "training conditions: same network, same step budget per tested detector, same alarm rule", "indigo"),
              ("11", "attack families mapped to MITRE ATT&CK v20.1, Enterprise and ICS (the tool's mapping, product research)", "amber"),
              ("0", "records leave your network when you use the local agent (product research, not part of the praxis)", "ink")])

    ui.section("How it works", "Five steps on any labeled table of network or device records",
               "Three organizations each run an intrusion detector. Each one has an attack type it has not trained on: its <b>withheld attack type</b>. The other two have seen it. "
               "Does working together let each organization catch and name that attack, and what does it give away in return?")
    steps = [("Make three organizations", "Hosts or devices are split into organizations A, B and C. One attack type is withheld from each organization's own training records."),
             ("Sanitize", "Keep the behavior numbers and the attack type. Remove device names, addresses, ports, time stamps and other labels. Sanitized means direct identifiers removed, nothing more."),
             ("Train under four training conditions", "Isolated training, sanitized attack-record sharing, federated learning and centralized training, with the same network, budget and alarm rule."),
             ("Test on the withheld attack type", "Was it flagged as an attack, and was it named with the right attack type? That share is the attack-class recall."),
             ("Read the scorecard", "Gain against isolated training with a 95% range, false-positive rate, data sent, and whether sanitized records can be traced to their source host.")]
    H(ui.steps_scene(steps))

    with st.container(key="tp_band_demo"):
        t1, t2 = st.columns([3.6, 1], vertical_alignment="center")
        with t1:
            H("<div class='t'>See these steps happen on a sample file</div><div class='d'>The live demo reads a file, shows which columns it removes and why, "
              "forms the three organizations, trains the four training conditions and draws the scorecard, in under a minute.</div>")
        with t2:
            link("demo", "Open the live demo", "cta_dark", "band")

    conds = [("isolated", "Isolated training", "The baseline. The detector learns from the organization's own records only. Nothing travels."),
             ("sharing", "Sanitized attack-record sharing", "Own records plus the peers' sanitized attack records. Records travel; identifiers do not."),
             ("federated", "Federated learning", "Own records only. After each round the model weights are averaged into one shared detector. No records travel."),
             ("centralized", "Centralized training", "The reference. One detector trained on the training records every organization keeps after withholding, in one place.")]
    H(ui.conditions_scene("The comparison", "Four training conditions, one detector design",
                          "Every organization trains the same detector four times. Only what it learns from changes.", conds))

    ui.section("The verdict", "A decision rule, not an opinion", "The rule judges each of the two approaches for each organization. Sanitized attack-record sharing is worth it when the gain and the false-positive checks pass and its sent records are not traced; if they are traced it is a trade-off. "
               "Federated learning is judged on the gain and the false-positive checks. Data sent is reported, not judged.")
    H(ui.rule_scene([("Gain", "5", "points", "The low end of the 95% range of the recall gain must be above 5 points."),
                     ("False positives", "1", "point", "The false-positive rate may rise by at most 1 point over isolated training."),
                     ("Privacy", ui.mini_print("privacy, traced or not", 124, ridges=11), "trade-off", "If sanitized records can be traced to their source host above the majority-host guess, the gain comes with a privacy trade-off.")]))

    ui.section("Start anywhere", "Three ways in")
    ways = [("demo", "Watch it work", "Pick a sample file and watch the product take it in, stage by stage: read, detect column roles, sanitize, organize, train under the four training conditions, score.", "Open the live demo"),
            ("evaluate", "Evaluate your own data", "Upload a CSV with a label column. The tool suggests which columns are identifiers, you confirm, and it runs the four training conditions and draws the scorecard.", "Evaluate your data"),
            ("agent", "Share only a fingerprint", "Run the local agent on your own machine. It sanitizes, maps your attack types to MITRE ATT&CK and writes a fingerprint: summary statistics, no records. Product research, not part of the praxis.", "Get the agent")]
    with st.container(key="tp_ways_start"):
        for i, (key, t, x, cta) in enumerate(ways):
            with st.container(key=f"tp_way_start{i}"):                  # the text and its own link stay together on every screen
                H(ui.way_html(i + 1, t, x))
                link(key, cta, "cta_light", "ways")

    st.caption(RESEARCH_NOTE + " The praxis itself is the comparison of the four training conditions on DataSense, with Edge-IIoTset as the ranking check.")
    ui.section("Limits", "Stated plainly")
    H("<div class='tp-prose'>"
      "<p>The study claims rest on the DataSense dataset alone. Every other dataset, and every upload, shows that the procedure runs on new data; the splits are the tool's own and are not audited.</p>"
      "<p>Removing identifiers does not stop tracing. On DataSense, sanitized attack records were traced to their source device 41% to 55% of the time against a majority-device baseline of 7% to 35%. The tool measures this for your data when a host column exists.</p>"
      "<p>A quick look uses a smaller training budget than the protocol. It shows whether your data works in the tool; the protocol run is the one to report.</p>"
      "<p>The tool does not store uploads: everything runs in the session and is gone when the page closes. A fingerprint is kept only if you choose to contribute it on the Agent page. Do not upload data you are not allowed to process.</p></div>")


# ---------------------------------------------------------------- sample files and the automatic path
SAMPLES = os.path.join(HERE, "samples")
BUILTIN = dict(id="builtin", file=None, path=None, title="Built-in example", kind="built in", sector="Mixed devices",
               summary="A made-up network generated inside the tool: 30 hosts, six attack types, 6,600 records. It shows how the tool works and says nothing about real attacks.",
               licence="Generated by the tool itself. Free to use.", roles={})
RUN_NOTE = "quick look, local run of the tool, not the run of record"
DEMO_STAGES = ["Ingest", "Detect column roles", "Sanitize", "Organize", "Train and test", "Scorecard"]


def load_manifest():
    """The sample files listed in samples/manifest.json, read at run time (the list can grow while the site runs).
    Entries without a readable file inside samples/ are left out; every field except the file name is optional."""
    try:
        with open(os.path.join(SAMPLES, "manifest.json"), encoding="utf-8") as fh:
            entries = json.load(fh)
    except Exception:
        entries = [{"file": os.path.basename(f)} for f in sorted(glob.glob(os.path.join(SAMPLES, "*.csv")))]
    out, seen = [], set()
    for e in entries if isinstance(entries, list) else []:
        if not isinstance(e, dict) or not e.get("file"):
            continue
        name = os.path.basename(str(e["file"]))                                     # a file inside samples/, never a path
        path = os.path.join(SAMPLES, name)
        sid = re.sub(r"[^a-z0-9]+", "_", os.path.splitext(name)[0].lower()).strip("_")
        if sid in seen or not name.lower().endswith((".csv", ".parquet")) or not os.path.isfile(path):
            continue
        seen.add(sid)
        out.append(dict(id=sid, file=name, path=path, title=str(e.get("title") or name), kind=str(e.get("kind") or "sample").lower(),
                        sector=str(e.get("sector") or "Sample file"), summary=str(e.get("summary") or ""),
                        licence=str(e.get("licence") or e.get("license") or ""), roles=e.get("roles") if isinstance(e.get("roles"), dict) else {}))
    return out


@st.cache_data(show_spinner=False, max_entries=8)
def _sample_frame(path, mtime):
    return engine.read_table(path)


def sample_frame(s):
    """The table of one sample (the built-in example is generated, the others are read from samples/)."""
    if not s.get("path"):
        return engine.example_data()
    return _sample_frame(s["path"], os.path.getmtime(s["path"]))


def auto_cfg(df, ins, name, roles=None):
    """Settings for a run that takes the roles the tool proposed (a sample may state a role for itself in the manifest).
    The same rule as the confirmation form of the Evaluate page with nothing changed. Returns the settings and the numbers kept."""
    roles, cols = roles or {}, list(df.columns)
    pick = lambda k: roles[k] if (k in roles and (roles[k] is None or roles[k] in cols)) else ins[k]
    label_col, source_col, time_col = pick("label_col"), pick("source_col"), pick("time_col")
    benign = roles.get("benign_label", ins["benign_label"]) if label_col == ins["label_col"] or "benign_label" in roles else None
    if label_col and benign is None:
        vc = df[label_col].dropna().astype(str).str.strip().value_counts()
        hits = [v for v in vc.index if agent.NORMAL_RX.match(v)]
        benign = hits[0] if hits else (vc.index[0] if len(vc) else None)
    fixed = {label_col, source_col, time_col} - {None}
    rest = [c for c in cols if c not in fixed]
    demoted = [ins[k] for k in ("label_col", "source_col", "time_col") if ins[k] and ins[k] not in fixed]      # a role the manifest took away
    removed = [c for c in ins["identifiers"] + ins["label_cols"] + ins["text_columns"] + ins["unusable"] + demoted if c in rest]
    numbers = [c for c in rest if c not in removed]
    cfg = dict(name=name, label_col=label_col, benign_label=benign, source_col=source_col, time_col=time_col,
               drop=removed, label_cols=[], keep=[c for c in numbers if engine.IDENT_RX.search(c)])
    if label_col and df[label_col].isna().any():
        cfg["drop_labels"] = ["nan"]                             # records with an empty label are left out
    return cfg, numbers


def _cn(c):
    """A column name as shown to a person: a name with a space at either end is put in quotes, so that it is not taken for another column."""
    c = str(c)
    return c if c == c.strip() else f"'{c}'"


def _hit(rx, name):
    m = rx.search(str(name))
    return m.group(0).strip("_. ").lower() if m and m.group(0).strip("_. ") else None


def role_reasons(df, ins, cfg, stated=()):
    """Why each role was proposed, in plain words. Derived here from the public rules of the local agent (threatprint_agent),
    which are the rules the tool applies; a role stated in the manifest of a sample says so."""
    n, out = len(df), {}
    lab, host, clock = cfg["label_col"], cfg["source_col"], cfg["time_col"]
    if lab:
        vals = df[lab].dropna().astype(str).str.strip()
        why = []
        if "label_col" in stated:
            why.append("stated in the description of the sample")
        h = _hit(agent.LABEL_NAME_RX, lab)
        if h:
            why.append(f"its name contains \"{h}\"")
        why.append(f"it holds {vals.nunique()} different values, a short list of names and not a measurement")
        normal = [v for v in vals.unique() if agent.NORMAL_RX.match(v)]
        if normal:
            why.append(f"one of its values is a usual word for normal traffic (\"{normal[0]}\")")
        if df[lab].dtype == object:
            why.append("its values are text")
        out["label"] = "; ".join(why)
        out["benign"] = ("stated in the description of the sample" if "benign_label" in stated else
                         "a usual word for normal traffic" if agent.NORMAL_RX.match(str(cfg["benign_label"])) else
                         "the most frequent value of the label column; no usual word for normal was found, so this one deserves a check")
    if host:
        why = ["stated in the description of the sample"] if "source_col" in stated else []
        h = _hit(agent.HOST_RX, host)
        if h:
            why.append(f"its name contains \"{h}\"")
        why.append(f"it holds {df[host].nunique()} different values in {n:,} records, few enough to be hosts and not one per record")
        if re.search(r"dst|des_|dest|^d(addr|ip)", str(host), re.I):
            why.append("it is the destination side, the host that receives the traffic")
        out["host"] = "; ".join(why)
    else:
        out["host"] = "no column looks like a host or a device, so the organizations are three random thirds of the records and tracing cannot be tested"
    if clock:
        why = ["stated in the description of the sample"] if "time_col" in stated else []
        h = _hit(agent.TIME_RX, clock)
        if h:
            why.append(f"its name contains \"{h}\"")
        why.append(f"it holds {df[clock].nunique():,} different values")
        out["time"] = "; ".join(why)
    else:
        out["time"] = "no clock was found, so every record is its own attack event, the split is random and the 95% ranges are optimistic"
    ident = []
    for c in cfg["drop"]:
        if c in ins["label_cols"]:
            kind, why = "second label", "another column that names the attack; left in, it would give the answer away"
        elif c in ins["text_columns"]:
            kind, why = "text", "its values are text, not a behavior number"
        elif c in ins["unusable"]:
            kind, why = "not usable", "one single value, or mostly empty, so it carries nothing a detector can learn from"
        else:
            h1, h2 = _hit(agent.IDENT_RX, c), _hit(agent.IDENT_NAME_RX, c)
            kind = "identifier"
            why = (f"its name contains \"{h1}\": an address, a host name, an id or a time stamp" if h1 else
                   f"its name contains \"{h2}\": a port, a protocol, a service, a state, a name or an id" if h2 else
                   "it was proposed as a role by its name and is not used as one in this run, so it is treated as an identifier")
        ident.append((c, kind, why))
    if host:
        ident.insert(0, (host, "host column", "used to form the organizations and to test tracing, then removed: it names a device"))
    if clock:
        ident.insert(0, (clock, "time column", "used to keep one attack together as an event and to split by time, then removed: a time stamp can point to a device"))
    out["identifiers"] = ident
    return out


def plain_reading(card):
    """The verdicts of one scorecard as sentences a person can read aloud. HTML, every data value escaped."""
    parts = []
    for o in ORG:
        c, v = card["companies"][o], card.get("verdicts", {}).get(o, {})
        s = (f"<b>{esc(c['name'])}</b> had the attack type <b>{esc(c['never_seen'])}</b> withheld. Its detector named {pct(c['named'].get('1_isolated'))} of those test records under isolated training, "
             f"{pct(c['named'].get('2_sharing'))} with sanitized attack-record sharing, {pct(c['named'].get('3_federated'))} with federated learning and "
             f"{pct(c['named'].get('4_centralized'))} with centralized training. Verdict for sanitized attack-record sharing: {esc(say_verdict(v.get('2_sharing'), '2_sharing', c))}; "
             f"for federated learning: {esc(say_verdict(v.get('3_federated'), '3_federated', c))}.")
        t = c.get("trace") or {}
        if "traced" in t:
            s += (f" A receiving peer traced {pct(t['traced'])} of its sanitized attack records to their source host, against {pct(t['guessing'])} for the majority-host baseline (always naming its busiest host).")
        parts.append(f"<p>{s}</p>")
    return "".join(parts)


# ---------------------------------------------------------------- the live demo: one sample through the product, stage by stage
def _demo_stage1(R):
    g = R["ingest"]
    with st.container(key="tp_stage_1"):
        ui.stage_head(1, "Ingest", f"The file was read into a table of <b>{g['rows']:,} records</b> (one row each) and <b>{g['cols']} columns</b>. "
                      "Nothing was changed and nothing was stored: the table lives in this browser session and is gone when the page closes.", R["times"].get(0))
        H(ui.kv([("File", esc(g["file"])), ("Size", esc(g["size"])), ("Records", f"{g['rows']:,}"),
                 ("Columns", f"{g['cols']}: {g['text_cols']} with text values, {g['num_cols']} with numbers")]))
        with st.expander("The opening rows of the file"):
            st.caption("The opening rows, exactly as recorded. Device names, addresses and time stamps are still in the table at this stage.")
            st.dataframe(g["head"], hide_index=True, width="stretch")


def _demo_stage2(R):
    g = R["roles"]
    with st.container(key="tp_stage_2"):
        ui.stage_head(2, "Detect column roles", "The tool read the column names and the values and proposed a role for every column: which one is the label, which value means normal, "
                      "which column names the host or device, which one is the clock, and which columns are identifiers. In this demo the proposals are taken as they are; "
                      "on the Evaluate page a person confirms or changes each one before a run.", R["times"].get(1))
        none = ui.badge("none found", "warn")
        rows = [{"Role": "Label column (the attack type, or normal)", "Proposed": ui.chip(g["label_col"], "dark"), "Why": g["why"]["label"]},
                {"Role": "Value that means normal traffic", "Proposed": ui.chip(g["benign_label"], "teal"), "Why": g["why"]["benign"]},
                {"Role": "Host or device column (forms the organizations, used to test tracing)", "Proposed": ui.chip(g["source_col"], "dark") if g["source_col"] else none, "Why": g["why"]["host"]},
                {"Role": "Time column (keeps one attack together as an event)", "Proposed": ui.chip(g["time_col"], "dark") if g["time_col"] else none, "Why": g["why"]["time"]}]
        ui.table(pd.DataFrame(rows), wrap=("Role", "Why"), raw=("Proposed",))
        idf = pd.DataFrame([{"Column": ui.chip(_cn(c)), "Treated as": k, "Why": w} for c, k, w in g["why"]["identifiers"]])
        H(f"<div class='tp-facts'><span><b>{len(g['why']['identifiers'])}</b> columns to remove before anything leaves, and why</span>"
          f"<span><b>{len(g['numbers'])}</b> columns proposed as behavior numbers</span></div>")
        if len(idf):
            with st.expander(f"The {len(idf)} columns and the reason for each"):
                ui.table(idf, wrap=("Why",), raw=("Column",))
        else:
            st.caption("No identifier, text or unusable column was found beside the role columns above.")
        with st.expander("The attack types found and the columns proposed as behavior numbers"):
            H(f"<div style='margin:4px 0 6px 0;font-weight:700'>Attack types found in the label column</div><div>"
              + "".join(ui.chip(f"{k} ({v:,})", "teal" if str(k) == str(g["benign_label"]) else "") for k, v in g["labels"]) + "</div>")
            H(f"<div style='margin:14px 0 6px 0;font-weight:700'>{len(g['numbers'])} columns proposed as behavior numbers</div><div>"
              + "".join(ui.chip(_cn(c), "teal") for c in g["numbers"][:24]) + (ui.chip(f"and {len(g['numbers']) - 24} more") if len(g["numbers"]) > 24 else "") + "</div>")


def _demo_stage3(R):
    g = R["sanitize"]
    with st.container(key="tp_stage_3"):
        ui.stage_head(3, "Sanitize", f"<b>{len(g['removed'])} columns were removed</b> and <b>{len(g['kept'])} behavior numbers plus the attack type were kept</b>. "
                      f"With sanitized attack-record sharing only attack records travel: {g['attack_rows']:,} of the {g['rows']:,} records; normal records are not sent. "
                      "Sanitized means direct identifiers removed, nothing more.", R["times"].get(2))
        H("<div style='margin:4px 0 6px 0;font-weight:700'>Removed before anything leaves</div><div>" + ("".join(ui.chip(_cn(c)) for c in g["removed"][:18]) or "nothing")
          + (ui.chip(f"and {len(g['removed']) - 18} more") if len(g["removed"]) > 18 else "") + "</div>")
        st.caption("What is still exposed: the behavior numbers themselves. Stage 6 measures whether a peer can trace them back to a host.")
        with st.expander("One attack record, before and after, and the columns that were kept"):
            H("<div style='margin:4px 0 6px 0;font-weight:700'>Kept</div><div>" + "".join(ui.chip(_cn(c), "teal") for c in g["kept"][:24])
              + (ui.chip(f"and {len(g['kept']) - 24} more") if len(g["kept"]) > 24 else "") + ui.chip(g["label_col"], "dark") + "</div>")
            if len(g["removed"]) > 18:
                H("<div style='margin:12px 0 6px 0;font-weight:700'>Every removed column</div><div>" + "".join(ui.chip(_cn(c)) for c in g["removed"]) + "</div>")
            H("<div style='margin:16px 0 2px 0;font-weight:700'>One attack record, before and after</div>")
            rows = [{"Column": _cn(c), "Before (as recorded)": b, "After sanitizing (what a peer receives)": (f"<td>{esc(b)}</td>" if kept else f"<td>{ui.badge('removed', 'no')}</td>")}
                    for c, b, kept in g["example"]]
            ui.table(pd.DataFrame(rows), raw=("After sanitizing (what a peer receives)",))
            if g["more"]:
                st.caption(f"{g['more']} more kept behavior numbers are not listed here; they pass through unchanged.")
            if g["dropped_late"]:
                st.caption("Dropped by the engine after a closer look at the values (not at least 95% numeric, or one single value in the records used): " + ", ".join(g["dropped_late"]) + ".")


def _demo_stage4(R):
    g = R["organize"]
    with st.container(key="tp_stage_4"):
        how = re.sub(r"^organizations\s*=\s*", "", str(g["company_note"]))
        ui.stage_head(4, "Organize", f"The records were divided among three organizations: {esc(how)}. One attack type was withheld from each organization's own training records: "
                      "its <b>withheld attack type</b>, which the other two still hold. Then each organization's records were split into training, validation and test.", R["times"].get(3))
        panels = []
        for o in ORG:
            s, hosts = g["step1"][o], g["hosts"].get(o)
            cl = agent.classify(s["never_seen"])
            who = ("".join(ui.chip(h) for h in hosts[:6]) + (ui.chip(f"and {len(hosts) - 6} more") if len(hosts) > 6 else "")) if hosts else ui.chip("a random third of the records")
            panels.append(f"<div class='tp-org'><div class='name'>{esc(s['name'])}</div>"
                          f"<div class='meta'>{(str(s['sources']) + ' hosts · ') if s.get('sources') else ''}{s['train']:,} training, {s['val']:,} validation and {s['test']:,} test records</div>"
                          f"<div style='margin-bottom:8px'>{who}</div>"
                          f"<div class='row'><span>Withheld attack type</span><span>{ui.chip(s['never_seen'], 'dark')}</span></div>"
                          f"<div class='row'><span>Attack family</span><span>{ui.chip(cl['family'], 'indigo')}</span></div>"
                          f"<div class='row'><span>Taken out of its training records</span><b>{s['withheld']:,}</b></div>"
                          f"<div class='row'><span>Trains on</span><b>{s['train_after']:,}</b></div>"
                          f"<div class='row'><span>Test records of the withheld type</span><b>{s['test_never_seen']:,}</b></div></div>")
        ui.grid(panels)
        if g["hosts"]:
            st.caption("Host names are shown here because this is the sample's own table in your own session. They are used to form the organizations and to test tracing; they are never part of a sanitized record.")
        st.caption(f"Split: {g['split_note']}.")
        H("<div class='tp-facts'><span>Every attack type in the file, mapped to a common family and to MITRE ATT&CK</span></div>")
        with st.expander("The mapping, label by label"):
            rows = [{"Label in the file": lab, "Records": f"{n:,}", "Attack family": ui.chip(fam, "indigo"),
                     "MITRE ATT&CK technique (closest)": "<td class='wrap'>" + ("".join(ui.chip(t) for t in techs) or ui.badge("no mapping")) + "</td>"}
                    for lab, n, fam, techs in g["attack"]]
            ui.table(pd.DataFrame(rows), raw=("Attack family", "MITRE ATT&CK technique (closest)"))
            st.caption("The mapping is the tool's suggestion from the label names (MITRE ATT&CK v20.1, Enterprise and ICS), not a ruling.")


COND_USES = [("isolated", "1_isolated", "Isolated training", "Its own training records only.", "Nothing."),
             ("sharing", "2_sharing", "Sanitized attack-record sharing", "Its own records plus the sanitized attack records of its two peers.", "Sanitized attack records."),
             ("federated", "3_federated", "Federated learning", "Its own records only; the three models are averaged after every round.", "Model weights, every round."),
             ("centralized", "4_centralized", "Centralized training", "Every organization's training records, in one place.", "All training records, once.")]


def _demo_stage5_headhtml(R, running=False):
    return ui.stage_head_html(5, "Train and test", "Every organization trains the same detector four times, once under each training condition, with the same network, the same step budget per tested detector and the same alarm rule. "
                              "Only what the detector learns from changes. Each trained detector is then tested on the organization's own test records of its withheld attack type.",
                              None if running else R["times"].get(4), extra=(ui.badge("running", "amber") if running else ""),
                              lead="What is happening." if running else "What just happened.")


def _demo_stage5_cards():
    H(ui.conditions_scene("", "", "", [(kind, name, f"<b>Trains on.</b> {esc(uses)}<br><b>What travels.</b> {esc(travels)}") for kind, _, name, uses, travels in COND_USES], light=True))


def _demo_stage5_result(R, live=False):
    card = R["card"]
    rows = []
    for _, road, name, _, _ in COND_USES:
        row = {"Training condition": name}
        for o in ORG:
            c = card["companies"][o]
            row[f"Data sent, {c['name']}"] = kb(c.get("bytes", {}).get(road))
        row["Training steps"] = f"{card['companies']['A'].get('steps', {}).get(road, 0):,}" if card["companies"]["A"].get("steps") else "not measured"
        rows.append(row)
    H("<div style='margin:14px 0 2px 0;font-weight:700'>What travelled in this run</div>")
    ui.table(pd.DataFrame(rows), wrap=("Training condition",))
    rec = ", ".join(f"{card['companies'][o]['name']} {card['companies'][o].get('records_received', 0):,}" for o in ORG)
    st.caption(f"Sanitized attack records received under sharing: {rec}. Federated learning ran {card['checks']['rounds']} rounds of {card['rules']['local_epochs']} local passes. "
               f"Network {card['rules']['network']}, {card['rules']['passes']} passes of the largest organization at batch {card['rules']['batch']}. Data sent is calculated as the glossary defines it, not captured on a wire.")
    if not live and R.get("log"):
        with st.expander("The log of this run"):
            st.code("\n".join(R["log"]), language=None)


def _demo_stage6(R):
    card = R["card"]
    with st.container(key="tp_stage_6"):
        ui.stage_head(6, "Scorecard", "The gains against isolated training were computed with their 95% ranges, the decision rule was applied, and, where the file has a host column, "
                      "a receiving peer tried to trace the sanitized attack records back to their source host.", R["times"].get(5), extra=ui.badge(RUN_NOTE, "na"))
        H(f"<div class='tp-note'><p><b>Reading the verdicts.</b> This is a {RUN_NOTE}.</p>{plain_reading(card)}"
          "<p>A quick look shows that the file works in the tool. The protocol budget on the Evaluate page is the run to decide on.</p></div>")
        show_card(card, heading=True, steps=False)
        download_buttons(card, "demo")


def _demo_band(R, running=False):
    s = R["sample"]
    state = ui.badge("running", "amber") if running else (ui.badge("stopped", "no") if R.get("error") else ui.badge("finished", "ok"))
    return (f"<div class='tp-band'><div><div class='t'>Sample: {esc(s['title'])}</div><div class='d'>{esc(s['sector'])} · {esc(s['kind'])} data · "
            f"{esc(s['file'] or 'generated in the tool')}</div></div><div>{state} {ui.badge(RUN_NOTE, 'na')}</div></div>")


def _demo_error(R):
    e = R["error"]
    st.error(f"Stage {e['stage']} ({DEMO_STAGES[e['stage'] - 1]}) stopped: {e['text']}")
    st.markdown("Usual causes: no column that names the attack type; fewer than three attack types with enough records in every organization; "
                "fewer than 25 normal validation records in an organization. On the Evaluate page the columns can be set by hand.")


def _demo_draw(R, band, rail):
    """Draw a finished (or stopped) run again from what was kept in the session."""
    done = R.get("done", 0)
    band.markdown(_demo_band(R), unsafe_allow_html=True)
    rail.markdown(ui.rail(DEMO_STAGES, done, None, R["times"]), unsafe_allow_html=True)
    for i, draw in enumerate((_demo_stage1, _demo_stage2, _demo_stage3, _demo_stage4), 1):
        if done >= i:
            draw(R)
    if done >= 5:
        with st.container(key="tp_stage_5"):
            H(_demo_stage5_headhtml(R))
            _demo_stage5_cards()
            _demo_stage5_result(R)
    if done >= 6:
        _demo_stage6(R)
    if R.get("error"):
        _demo_error(R)


def _demo_run(s, band, rail):
    """Run one sample through the product and draw every stage as it finishes. Returns what the page needs to draw the run again."""
    R = dict(sample={k: s.get(k) for k in ("id", "title", "kind", "sector", "file")}, times={}, log=[], done=0, error=None)
    budget = engine.QUICK

    def tick(now=None):
        band.markdown(_demo_band(R, running=now is not None), unsafe_allow_html=True)
        rail.markdown(ui.rail(DEMO_STAGES, R["done"], now, R["times"]), unsafe_allow_html=True)

    def stop(stage, e, lead):
        text = str(e).strip().splitlines()[0][:300] if str(e).strip() else type(e).__name__
        R["error"] = dict(stage=stage, text=f"{lead} ({text})" if text else lead)
        tick()
        _demo_error(R)
        return R

    tick(0)
    # ---- stage 1: ingest
    t = time.time()
    try:
        df = sample_frame(s)
    except Exception as e:
        return stop(1, e, "the sample file could not be read")
    num_cols = int(sum(pd.api.types.is_numeric_dtype(df[c]) for c in df.columns))
    R["ingest"] = dict(file=s["file"] or "generated in the tool (no file)", rows=len(df), cols=int(df.shape[1]), num_cols=num_cols, text_cols=int(df.shape[1]) - num_cols,
                       size=(kb(os.path.getsize(s["path"])) + " on disk") if s.get("path") else (kb(int(df.memory_usage(deep=True).sum())) + " in memory"),
                       head=df.head(4).copy())
    R["times"][0] = time.time() - t
    R["done"] = 1
    _demo_stage1(R)
    tick(1)
    # ---- stage 2: detect column roles
    t = time.time()
    try:
        ins = engine.inspect(df)
        cfg, numbers = auto_cfg(df, ins, s["title"], s.get("roles"))
    except Exception as e:
        return stop(2, e, "the columns could not be read")
    if not cfg["label_col"]:
        return stop(2, "", "no label column was recognized: the tool needs one column that names the attack type or says normal")
    cfg["about"] = s.get("summary", "")
    labels = df[cfg["label_col"]].astype(str).str.strip().value_counts()
    R["roles"] = dict(label_col=cfg["label_col"], benign_label=str(cfg["benign_label"]), source_col=cfg["source_col"], time_col=cfg["time_col"], numbers=list(numbers),
                      labels=[(str(k), int(v)) for k, v in labels.head(30).items()], why=role_reasons(df, ins, cfg, stated=tuple((s.get("roles") or {}).keys())))
    R["times"][1] = time.time() - t
    R["done"] = 2
    _demo_stage2(R)
    tick(2)
    # ---- stages 3 and 4: the engine reads the table with these roles, sanitizes it and forms the organizations
    t = time.time()
    try:
        data = engine.Data(cfg, frame=df, budget=budget, log=R["log"].append)
        step1 = data.describe()
    except Exception as e:
        return stop(4, e, "the records could not be organized into three organizations")
    t_org = time.time() - t
    t = time.time()
    try:
        kept = [c for c in data.feats if c in df.columns]
        removed = [c for c in df.columns if c not in kept and c != cfg["label_col"]]
        san = engine.sanitize(df, cfg["label_col"], kept, attack_only=True, benign_label=cfg["benign_label"])
        attack = df[df[cfg["label_col"]].astype(str).str.strip() != str(cfg["benign_label"])]
        row = (attack if len(attack) else df).iloc[0]
        shown = removed[:10] + kept[:6] + [cfg["label_col"]]
        R["sanitize"] = dict(removed=removed, kept=kept, label_col=cfg["label_col"], rows=len(df), attack_rows=len(san),
                             example=[(c, str(row[c])[:40], c in kept or c == cfg["label_col"]) for c in shown],
                             more=max(0, len(kept) - 6), dropped_late=[c for c in numbers if c not in kept])
    except Exception as e:
        return stop(3, e, "the table could not be sanitized")
    R["times"][2] = time.time() - t
    R["done"] = 3
    _demo_stage3(R)
    tick(3)
    hosts = {}
    if data.source_col:
        for o in ORG:
            hosts[o] = [str(h) for h in sorted(data.df[data.df.org == o].source.astype(str).unique())]
    counts = data.df.y.astype(str).value_counts()
    attack_rows = []
    for lab, n in counts.items():
        if lab == str(data.benign):
            continue
        cl = agent.classify(lab)
        attack_rows.append((lab, int(n), cl["family"], [f"{x['id']} {x['name']} ({x['matrix']})" for x in cl["techniques"]]))
    R["organize"] = dict(step1=step1, hosts=hosts, company_note=data.company_note, split_note=data.split_note, attack=attack_rows)
    R["times"][3] = t_org
    R["done"] = 4
    _demo_stage4(R)
    tick(4)
    # ---- stage 5: train under the four training conditions and test; stage 6: scorecard
    marks = {}
    with st.container(key="tp_stage_5"):
        head5 = st.empty()
        head5.markdown(_demo_stage5_headhtml(R, running=True), unsafe_allow_html=True)
        _demo_stage5_cards()
        box = st.status("Training under the four training conditions", expanded=True)

        def log(m):
            R["log"].append(m)
            if m.startswith("Step 5") and "score" not in marks:
                marks["score"] = time.time()
            box.write(m)

        t = time.time()
        try:
            card = engine.run(cfg, frame=df, budget=budget, log=log)
        except Exception as e:
            box.update(label="The run stopped", state="error", expanded=False)
            head5.markdown(ui.stage_head_html(5, "Train and test", extra=ui.badge("stopped", "no")), unsafe_allow_html=True)
            return stop(5, e, "training or testing did not finish")
        end = time.time()
        R["times"][4] = marks.get("score", end) - t
        R["times"][5] = end - marks.get("score", end)
        box.update(label=f"Trained and tested in {R['times'][4]:.0f} s", state="complete", expanded=False)
        card["id"] = "demo_" + str(s["id"])
        card["study_role"] = "sample file"
        card["name"] = f"{s['title']} (sample file)"
        R["card"] = card
        R["done"] = 5
        head5.markdown(_demo_stage5_headhtml(R), unsafe_allow_html=True)
        _demo_stage5_result(R, live=True)
    tick(5)
    R["done"] = 6
    _demo_stage6(R)
    tick()
    return R


def page_demo():
    sub_hero("Live demo", "Watch a file go through <em>the whole product</em>",
             "Pick a sample file and press one button. The page shows each stage as it happens, with the real numbers of that run: the file is read, the columns get their roles, "
             "the identifiers are removed, three organizations are formed, the four training conditions are trained and tested, and the scorecard is drawn.")
    samples = load_manifest() + [BUILTIN]
    ui.section("Samples", "Pick a sample file", "Real samples are open data under the licence shown. Synthetic samples are made up by a script and say nothing about real attacks.")
    chosen = None
    with st.container(key="tp_cells_samples"):
        for i, s in enumerate(samples):
            with st.container(key=f"tp_cell_sample{i}"):               # the card and its own button stay together on every screen
                H(ui.sample_card(s["title"], s["sector"], s["kind"], s["summary"], s["licence"]))
                if st.button(f"Run the demo: {s['title']}", key=f"demo_run_{s['id']}", type="primary", use_container_width=True):
                    chosen = s
    ui.section("The run", "Six stages, from the file to the scorecard",
               "Every stage shows what the product did to the data and why. A quick look takes well under a minute on most samples.")
    R = st.session_state.get("demo")
    if chosen is None and not R:
        H(ui.rail(DEMO_STAGES, 0))
        what = [("upload", "Ingest", "The file is read into a table. Records and columns are counted; nothing is changed or stored."),
                ("columns", "Detect column roles", "The label, the value that means normal, the host column, the clock and the identifiers are proposed, each with its reason."),
                ("filter", "Sanitize", "Identifiers are removed. The behavior numbers and the attack type stay. One record is shown before and after."),
                ("orgs", "Organize", "Hosts are split into organizations A, B and C, one attack type is withheld from each, and every label is mapped to MITRE ATT&CK."),
                ("chip", "Train and test", "The same detector is trained under the four training conditions and tested on the withheld attack type."),
                ("chart", "Scorecard", "Gains with 95% ranges, false-positive rates, data sent, the tracing test and the verdicts of the decision rule.")]
        H(ui.rows([(t, esc(x)) for _, t, x in what], cols=2))
        st.markdown("")
        st.info("No run yet. Press one of the buttons above to start.")
        return
    band, rail = st.empty(), st.empty()
    if chosen is not None:
        R = _demo_run(chosen, band, rail)
        st.session_state["demo"] = R
    else:
        _demo_draw(R, band, rail)
    st.markdown("")
    c1, c2, _ = st.columns([1, 1.2, 2])
    with c1:
        if st.button("Clear this run", key="demo_clear", use_container_width=True):
            st.session_state.pop("demo", None)
            st.rerun()
    with c2:
        link("evaluate", "Evaluate your own data", "cta_light", "demo")


def page_results():
    cards = load_cards()
    sub_hero("Results", f"{len(cards)} result cards, one procedure",
             "The praxis dataset, the ranking check and public intrusion datasets, each run with the protocol budget: three organizations, one withheld attack type each, four training conditions. "
             "Only DataSense carries the praxis claims; every other row is a local run of the tool on its own split.")
    if not cards:
        st.warning("No result files found.")
        return
    h1_ok = sum(1 for c in cards if c["hypotheses"]["H1"]["clears"])
    h2_ok = sum(1 for c in cards if c["hypotheses"]["H2"]["clears"])
    h3_ok = sum(1 for c in cards if c["hypotheses"].get("H3") and c["hypotheses"]["H3"]["yes"])
    h3_n = sum(1 for c in cards if c["hypotheses"].get("H3"))
    ui.stats([(f"{len(cards)}", "result cards, each a local run of the tool with the protocol budget", "ink"),
              (f"{h1_ok}<small> of {len(cards)}</small>", "local tool runs where the whole 95% range of the sanitized attack-record sharing gain is above 5 points (tool tests, not study results)", ""),
              (f"{h2_ok}<small> of {len(cards)}</small>", "local tool runs where the whole 95% range of the federated learning gain is above 5 points (tool tests, not study results)", "indigo"),
              (f"{h3_ok}<small> of {h3_n}</small>", "local tool runs where records were traced above the majority-host baseline in all three organizations, of those where tracing could be tested", "amber")])
    full = sum(1 for c in cards if (c.get("budget") or {}).get("name") == "protocol")
    failed = {}
    try:
        failed = json.load(open(os.path.join(RESULTS, "_failed.json")))
    except Exception:
        pass
    H("<div class='tp-note' style='margin-top:14px'>"
      f"<p><b>What the {len(cards)} cards are.</b> {len(cards)} result cards from 21 source datasets: BoT-IoT, CIC-IDS2017, Edge-IIoTset and ToN_IoT each appear in two versions. "
      f"{full} cards use the protocol budget as written; the other {len(cards) - full} use it with a smaller shuffle test for tracing (5,000 records per side, 50-tree forests), stated on each card. "
      "The hypotheses of the praxis are tested on DataSense alone; every other card is a tool test on the tool's own split.</p>"
      + "".join(f"<p><b>One dataset did not run.</b> {esc(k.upper().replace('CIDDS002', 'CIDDS-002'))}: {esc(str(v.get('error', 'the run stopped')))}. It has no card.</p>" for k, v in failed.items())
      + "</div>")

    ui.section("Gain against isolated training", "How much each approach added, dataset by dataset",
               "Mean gain in attack-class recall on the withheld attack types over the three organizations, with its 95% range. All four training conditions are here: isolated training is the zero line "
               "(every gain is measured against it), and sanitized attack-record sharing, federated learning and centralized training (the reference) are the three marks. "
               "An approach clears the rule when its whole range lies to the right of the dashed line. Local runs of the tool, not the run of record, except where the hover text of a mark says run of record.")
    series = [("sha", "Sanitized attack-record sharing", ui.GOLD), ("fed", "Federated learning", ui.STEEL), ("cen", "Centralized training (reference)", ui.COND["4_centralized"], "square")]
    fig1 = ui.legend([("Isolated training: the zero line", ui.COND["1_isolated"])]) + ui.legend([(x[1], x[2]) for x in series], shapes=True)
    rows, fp_rows = [], []
    order = sorted(cards, key=lambda c: ({"the study": 0, "ranking check": 1}.get(c.get("study_role"), 2), -c["hypotheses"]["H1"]["gain"]))
    for c in order:
        Hy, e, cid = c["hypotheses"], exp_of(c), c.get("id")
        note = f"{run_label(c)}, not the run of record"
        tri = lambda h: tuple(h[k] * 100 for k in ("gain", "lo", "hi")) + (note,)
        vals = {"sha": tri(Hy["H1"]), "fed": tri(Hy["H2"])}
        if c["checks"].get("pooled"):
            vals["cen"] = tri(c["checks"]["pooled"])
        if cid in RECORD_NUM:                            # the two praxis rows plot the run of record
            ror = f"run of record ({RECORD[cid]['where']})"
            vals["sha"], vals["fed"] = RECORD_NUM[cid]["H1"] + (ror,), RECORD_NUM[cid]["H2"] + (ror,)
            if cid == "datasense":
                vals["cen"] = (44.4, 36.6, 51.7, ror)
        role = c.get("study_role", "")
        tag = role if role in ("the study", "ranking check") else ""
        rows.append(dict(name=c["name"], tag=tag, strong=(role == "the study"), vals=vals))
        if e:
            fp_rows.append(dict(name=c["name"], tag=tag, strong=False, vals={"fp": tuple(e["mean_gain"][k] * 100 for k in ("gain", "lo", "hi")) + ("local run, experimental, not a praxis condition",)}))
    cap1 = ("Hover a mark for its numbers and for which run it is. On the DataSense row the three marks are the run of record "
            f"(H1 {RECORD['datasense']['H1']}, H2 {RECORD['datasense']['H2']}, centralized +44.4 [+36.6, +51.7]). On the Edge-IIoTset row sharing and federated are the run of record "
            f"(H1 {RECORD['edge_iiotset']['H1']}, H2 {RECORD['edge_iiotset']['H2']}); its centralized mark is the local run of the tool, because the run of record did not record it. "
            "Every other row is a local run of the tool. Where a dataset has no clock the split is random and the ranges are optimistic.")
    H(ui.figure(fig1 + ui.forest(rows, series), "Figure 1", esc(cap1)))

    if fp_rows:
        ui.section("Experimental, not part of the praxis", "Fingerprint sharing, on its own chart",
                   "Fingerprint sharing is product research and not one of the four training conditions of the praxis, so it is drawn apart from them. Mean gain in attack-class recall on the withheld attack types "
                   f"against the experiment's own isolated baseline, local runs of the tool. {FP_UNMEASURED} A gain here is half of an answer.")
        H(ui.figure(ui.legend([("Fingerprint sharing (experimental, not a praxis condition)", ui.COPPER)]) + ui.forest(fp_rows, [("fp", "Fingerprint sharing (experimental)", ui.COPPER, "hatch")]),
                    "Figure 2", esc("Fingerprint sharing, experimental and not a praxis training condition: mean gain against the experiment's own isolated baseline, local runs of the tool. " + FP_UNMEASURED)))

    ui.section("By attack family", "Which attack families transfer", art="attack families",
               text=
               "Mean attack-class recall on the withheld attack type, grouped by the tool's attack family for that type (each family is mapped to MITRE ATT&CK techniques), under each training condition. A case is one organization in one dataset. "
               "Local runs of the tool, not the run of record.")
    fs = family_stats(cards)
    rows = [{"Attack family of the withheld type": r.family, "MITRE ATT&CK": r.techniques, "Cases": int(r.cases),
             "Isolated training": ui.heat(r.iso), "Sanitized attack-record sharing": ui.heat(r.sha), "Federated learning": ui.heat(r.fed), "Centralized training": ui.heat(r.cen),
             "Fingerprint sharing (experimental)": ui.heat(r.fp, exp=True)} for r in fs.itertuples()]
    ui.table(pd.DataFrame(rows), wrap=("Attack family of the withheld type", "MITRE ATT&CK"),
             raw=("Isolated training", "Sanitized attack-record sharing", "Federated learning", "Centralized training", "Fingerprint sharing (experimental)"))
    st.caption("Local runs of the tool, not the run of record. Families and techniques are the tool's mapping of each dataset's own labels (MITRE ATT&CK v20.1, Enterprise and ICS); a suggestion, not a ruling. "
               "The families and the mapping are product research, not part of the praxis. Fingerprint sharing is experimental and not a praxis training condition. " + FP_UNMEASURED)

    ui.section("Dataset by dataset", "Open a scorecard")
    names = [c["name"] for c in cards]
    pick = st.selectbox("Dataset", names, index=0, label_visibility="collapsed")
    card = cards[names.index(pick)]
    show_card(card)
    download_buttons(card, card.get("id", "card"))

    with st.expander("Summary table of all datasets"):
        rows = []
        for c in cards:
            Hy = c["hypotheses"]
            h3 = Hy.get("H3")
            cid, rn = c.get("id"), RECORD_NUM.get(c.get("id"), {})
            cell = lambda h, k: ((f"run of record {RECORD[cid][k]}; {run_label(c)} " if k in rn else "") + pts(h) + " "
                                 + ui.badge("supported" if h["clears"] else "not supported", "ok" if h["clears"] else "no"))
            rows.append({"Dataset": c["name"], "Role": c.get("study_role", "tool test") + ", " + run_label(c),
                         "Isolated training": "baseline",
                         "H1 sanitized attack-record sharing (points, 95% range)": cell(Hy["H1"], "H1"),
                         "H2 federated learning (points, 95% range)": cell(Hy["H2"], "H2"),
                         "Centralized training, the reference (points, 95% range)": pts(c["checks"].get("pooled")),
                         "H3 records traced above the majority-host baseline": (ui.badge("observed, all organizations", "amber") if h3 and h3["yes"] else (ui.badge("not all", "na") if h3 else ui.badge("not tested"))),
                         "Seeds": len(c["seeds"])})
        ui.table(pd.DataFrame(rows), wrap=("Dataset", "H1 sanitized attack-record sharing (points, 95% range)", "H2 federated learning (points, 95% range)"),
                 raw=("H1 sanitized attack-record sharing (points, 95% range)", "H2 federated learning (points, 95% range)", "H3 records traced above the majority-host baseline"))
        st.caption("All four training conditions: isolated training is the baseline of every gain; H1 and H2 are the mean gains of sanitized attack-record sharing and federated learning in attack-class recall on the withheld attack types "
                   "over the three organizations, supported when the whole 95% range is above 5 points; centralized training is the reference. "
                   f"Local run = this tool's run on another machine; the praxis runs of record are DataSense H1 {RECORD['datasense']['H1']}, H2 {RECORD['datasense']['H2']} "
                   f"and Edge-IIoTset H1 {RECORD['edge_iiotset']['H1']}, H2 {RECORD['edge_iiotset']['H2']}, with the same H1 and H2 decisions. "
                   "H3 is shown as observed, not as a settled statistical result. The hypotheses of the praxis are tested on DataSense alone; every other row is a tool test.")


def _confirm_columns(df, ins, key):
    """Let the user confirm the roles the tool guessed. Returns the settings dict and the kept numbers."""
    cols = list(df.columns)
    none = "(none)"
    c1, c2 = st.columns(2)
    label_col = c1.selectbox("Label column (the attack type or normal)", cols, index=cols.index(ins["label_col"]) if ins["label_col"] in cols else 0, key=f"{key}_label")
    n_missing = int(df[label_col].isna().sum())                  # a record with an empty label is left out, not read as an attack type called "nan"
    values = df[label_col].dropna().astype(str).str.strip().value_counts()
    if not len(values):
        values = pd.Series({"(no label values)": 0})
    benign = c2.selectbox("Which label value means normal traffic", list(values.index),
                          index=list(values.index).index(ins["benign_label"]) if (label_col == ins["label_col"] and ins["benign_label"] in values.index) else 0, key=f"{key}_benign")
    if ins.get("benign_guess") and label_col == ins["label_col"]:
        st.warning(f"No label value looks like normal traffic. '{benign}' is only the most frequent value. Pick the value that means normal traffic before you run.")
    if n_missing:
        st.caption(f"{n_missing:,} records have no label and are left out of the run.")
    c3, c4 = st.columns(2)
    src_opts = [none] + [c for c in cols if c != label_col]
    source_col = c3.selectbox("Host or device column (forms the organizations and is used to test tracing)", src_opts,
                              index=src_opts.index(ins["source_col"]) if ins["source_col"] in src_opts else 0, key=f"{key}_host")
    time_col = c4.selectbox("Time column (keeps one attack together as an event)", src_opts,
                            index=src_opts.index(ins["time_col"]) if ins["time_col"] in src_opts else 0, key=f"{key}_time")
    source_col = None if source_col == none else source_col
    time_col = None if time_col == none else time_col
    fixed = {label_col, source_col, time_col} - {None}
    rest = [c for c in cols if c not in fixed]
    suggested_removed = [c for c in ins["identifiers"] + ins["label_cols"] + ins["text_columns"] + ins["unusable"] if c in rest]
    removed = st.multiselect("Columns removed before anything leaves an organization (identifiers, other labels, text, mostly empty). Add or remove as you see fit.",
                             rest, default=suggested_removed, key=f"{key}_removed")
    numbers = [c for c in rest if c not in removed]
    st.caption(f"{len(numbers)} columns will be kept as behavior numbers; columns that are not at least 95% numeric are dropped at run time. "
               f"Labels found: {', '.join(f'{k} ({v:,})' for k, v in values.head(12).items())}{' ...' if len(values) > 12 else ''}.")
    cfg = dict(name="your data", label_col=label_col, benign_label=benign, source_col=source_col, time_col=time_col,
               drop=removed, label_cols=[], keep=[c for c in numbers if engine.IDENT_RX.search(c)])
    if n_missing:
        cfg["drop_labels"] = ["nan"]
    return cfg, numbers


def _before_after(df, cfg, numbers):
    """One record before and after sanitizing."""
    attack = df[df[cfg["label_col"]].astype(str).str.strip() != str(cfg["benign_label"])]
    row = (attack if len(attack) else df).iloc[0]
    rows = []
    for c in df.columns:
        kept = c in numbers or c == cfg["label_col"]
        rows.append({"Column": _cn(c), "Before (as recorded)": str(row[c])[:40],
                     "After sanitizing (what a peer receives)": (f"<td>{esc(str(row[c])[:40])}</td>" if kept else f"<td>{ui.badge('removed', 'no')}</td>")})
    ui.table(pd.DataFrame(rows), raw=("After sanitizing (what a peer receives)",))


def _read_upload(up):
    """The uploaded table, read by the safe reader (engine.read_table): never a traceback, never a dead process."""
    df = engine.read_table(up, up.name)
    for note in df.attrs.get("notes", []):
        st.caption(f"Note: {note}.")
    return df


def _step_head(no, title, text=""):
    H(ui.step_head_html(no, title, text))


def _pick_data(prefix):
    """Three ways to bring a table: upload one, take a sample file, or use the built-in example. Returns the table, or None while there is none."""
    samples = load_manifest()
    opts = ["Upload a CSV or Parquet file"] + (["Try a sample file"] if samples else []) + ["Use the built-in example (made-up data, for trying the tool)"]
    src = st.radio("Data", opts, horizontal=True, key=f"{prefix}_data", label_visibility="collapsed")
    if src.startswith("Upload"):
        up = st.file_uploader("CSV or Parquet, one header row", type=["csv", "parquet"], key=f"{prefix}_upload", label_visibility="collapsed")
        if up is None:
            return None
        try:
            return _read_upload(up)
        except Exception as e:
            st.error(f"The file could not be read: {e}")
            return None
    if src.startswith("Try"):
        names = [s["title"] for s in samples]
        pick = st.selectbox("Sample file", names, key=f"{prefix}_sample")
        s = samples[names.index(pick)]
        st.caption(f"{s['kind'].capitalize()} data, {s['sector']}. {s['summary']} {s['licence']}")
        try:
            return sample_frame(s)
        except Exception as e:
            st.error(f"The sample file could not be read: {e}")
            return None
    st.caption("The example is synthetic: 30 hosts, six attack types, 6,600 records. It says nothing about real attacks; it shows how the tool works.")
    return engine.example_data()


def page_evaluate():
    sub_hero("Evaluate", "Run the evaluation on your own records",
             "Upload a table where each row is one record (a flow, a packet summary or a time window) with a label column that names the attack type or says normal. "
             "The tool suggests the roles of the columns; you confirm them. The table is not stored. No file at hand? Take a sample file here, or watch the Live demo.")
    tab_run, tab_san = st.tabs(["Run the evaluation", "Sanitize a file only"])
    with tab_run:
        _evaluate_body()
    with tab_san:
        _sanitize_body()


def _evaluate_body():
    _step_head(1, "Bring a table", "A CSV or Parquet file with one header row, a sample file, or the built-in example.")
    df = _pick_data("ev")
    if df is None:
        st.info("Waiting for a file. No file at hand? Choose \"Try a sample file\" above, or open the Live demo to watch one go through.")
        last = st.session_state.get("ev_card")
        if last:
            ui.section("This session", "Your last scorecard", "The run you made earlier in this session. It is gone when the page closes.")
            show_card(last, heading=False)
            download_buttons(last, "your_data")
        return
    H(f"<div style='margin:8px 0'>{ui.chip(f'{len(df):,} records', 'dark')}{ui.chip(f'{df.shape[1]} columns')}</div>")
    with st.expander("Opening rows of the table"):
        st.dataframe(df.head(5), hide_index=True, width="stretch")
    ins = engine.inspect(df)
    if not ins["label_col"]:
        st.warning("No label column was recognized. Pick it below.")
    _step_head(2, "Confirm the columns", "The tool's guesses are filled in. Change anything it got wrong.")
    cfg, numbers = _confirm_columns(df, ins, "ev")
    with st.expander("One record before and after sanitizing"):
        _before_after(df, cfg, numbers)

    _step_head(3, "Choose the budget and run")
    budget_name = st.radio("Budget", ["Quick look (about a minute; one seed, 24 passes, 400 resamples)",
                                      "Protocol run (the praxis budget: three seeds, 61 passes, 2,000 resamples; minutes to an hour)"], key="ev_budget", label_visibility="collapsed")
    st.caption("Limits: an upload can be up to 200 MB. A quick look samples at most 40,000 records; a protocol run samples at most 150,000. One evaluation runs at a time on this site, "
               "so a run may wait a short while behind another visitor's run.")
    budget = engine.QUICK if budget_name.startswith("Quick") else engine.PROTOCOL
    if budget is engine.PROTOCOL and len(df) > 150_000:
        st.warning(f"{len(df):,} records. The protocol run will sample 150,000 records by class so that the run finishes in a public host's memory.")
        budget = engine.Budget(**{**engine.PROTOCOL.__dict__, "max_rows": 150_000})
    trace_on = st.checkbox("Run the tracing test (H3) when a host column exists", value=True, key="ev_trace")
    if not trace_on:
        budget = engine.Budget(**{**budget.__dict__, "do_trace": False})

    if st.button("Run the evaluation", type="primary", key="ev_run"):
        with st.container(key="tp_status_ev"):                       # a keyed holder, so that the log of the run can be styled as a log
            log_box = st.status("Running the five steps", expanded=True)

        def log(m):
            log_box.write(m)

        t = time.time()
        try:
            card = engine.run(cfg, frame=df, budget=budget, log=log)
        except Exception as e:
            log_box.update(label="The run stopped", state="error")
            st.error(f"The run stopped: {e}")
            st.markdown("Usual causes: fewer than three attack types with enough records in every organization; fewer than 25 normal validation records in an organization; "
                        "a label column that is not the attack type. Change the columns above and run again.")
            return
        log_box.update(label=f"Done in {time.time() - t:.0f} s", state="complete", expanded=False)
        card["id"] = "your_data"
        card["study_role"] = "your data"
        st.session_state["ev_card"] = card
    card = st.session_state.get("ev_card")
    if card:
        _step_head(4, "Read the scorecard")
        show_card(card, heading=False)
        download_buttons(card, "your_data")
        san = engine.sanitize(df, cfg["label_col"], [c for c in card["step2"]["kept"] if c in df.columns])
        st.download_button("Download the sanitized table (what a peer would receive, all records)", engine.csv_safe(san).to_csv(index=False), file_name="sanitized.csv", mime="text/csv", key="ev_dl_san")


def _sanitize_body():
    st.markdown("See exactly what would leave. Bring a table and download the version an organization could send to a peer: the behavior numbers and the attack type, "
                "with the identifiers removed. The tool suggests the roles of the columns; you confirm them.")
    df = _pick_data("sa")
    if df is None:
        st.info("Waiting for a file to sanitize.")
        return
    ins = engine.inspect(df)
    cfg, numbers = _confirm_columns(df, ins, "sa")
    attack_only = st.checkbox("Attack records only (what the praxis sharing condition sends; normal records are not sent)", value=True, key="sa_attack_only")
    san = engine.sanitize(df, cfg["label_col"], numbers, attack_only=attack_only, benign_label=cfg["benign_label"])
    removed = [c for c in df.columns if c not in numbers and c != cfg["label_col"]]
    ui.stats([(f"{len(df):,}", "records in your table", "ink"), (f"{len(san):,}", "records in the sanitized table", ""),
              (f"{len(numbers)}", "behavior numbers kept, plus the attack type", "indigo"), (f"{len(removed)}", "columns removed", "amber")])
    H("<div style='margin:16px 0 4px 0;font-weight:700'>Removed</div><div>" + ("".join(ui.chip(_cn(c)) for c in removed) or "nothing") + "</div>"
      "<div style='margin:10px 0 4px 0;font-weight:700'>Kept</div><div>" + "".join(ui.chip(_cn(c), "teal") for c in numbers + [cfg["label_col"]]) + "</div>")
    with st.expander("One record before and after"):
        _before_after(df, cfg, numbers)
    st.warning("What is still exposed: the behavior numbers themselves. A peer that holds reference traffic labeled by host can try to trace a sanitized record "
               "back to its source host from those numbers. On DataSense this worked 41% to 55% of the time against a majority-device baseline of 7% to 35%. "
               "Run the evaluation in the other tab to measure it for your data.")
    st.download_button("Download the sanitized table (CSV)", engine.csv_safe(san).to_csv(index=False), file_name="sanitized.csv", mime="text/csv", key="sa_dl", type="primary")


TERMS = [
    ("Record", "One row of the table: one flow, one packet summary or one time window at one host, described by numbers, with a label."),
    ("Attack type", "The label of a record: normal, or the kind of attack it belongs to (for example DoS, DDoS, MITM, scanning)."),
    ("Organization", "One of three groups of hosts or devices, each running its own intrusion detector on its own records."),
    ("Withheld attack type", "The attack type taken out of an organization's own training records. It is still in the other two organizations' training records and in the organization's own test records."),
    ("Sanitized", "Direct identifiers removed (device names, addresses, ports, time stamps, other labels), nothing more. The behavior numbers and the attack type stay."),
    ("Training condition", "One way of training the same detector, defined by what it learns from. Four are run: isolated training, sanitized attack-record sharing, federated learning, centralized training."),
    ("Isolated training", "The baseline. The detector learns from the organization's own records only."),
    ("Sanitized attack-record sharing", "The organization adds the sanitized attack records of its two peers to its own training records and trains again."),
    ("Federated learning", "Each organization trains on its own records; after each round the model weights are averaged into one shared detector (FedAvg, McMahan et al., 2017). No records travel."),
    ("Centralized training", "The reference. One detector trained on the training records every organization keeps after withholding, in one place."),
    ("Attack-class recall", "Of the test records of the withheld attack type, the share that the detector flagged as an attack and named with the right attack type."),
    ("Flagged", "Of the test records of the withheld attack type, the share the detector called an attack, whatever name it gave."),
    ("False-positive rate", "Of the normal test records, the share the detector called an attack. The alarm threshold is set so that about 5% of the organization's own normal validation records are flagged."),
    ("Gain", "Attack-class recall under a condition minus attack-class recall under isolated training, in percentage points."),
    ("95% range", "The range of the gain over 2,000 resamples of the attack events (bootstrap), so that records of one attack stay together. See Attack event for how events are formed."),
    ("Attack event", "For uploads and public datasets: a run of records of one attack type on one host with gaps under 15 seconds, cut at 300 seconds or 200 records. "
                     "On DataSense the praxis groups records of the same attack type and subtype, no more than 15 seconds apart, across devices (936 reconstructed events; these are reconstructed groups, not confirmed independent attacks)."),
    ("Tracing (H3)", "A receiving peer that holds the sender's normal traffic labeled by host trains a random forest to name the source host of each sanitized attack record. Scored against the majority-host baseline: always naming the sender's busiest host (on DataSense, the majority-device baseline). "
                     "The peer's labelled reference traffic is a test assumption."),
    ("Data sent", "Sharing: received records times (4 bytes per number plus 1 byte for the label). Federated learning: model weights, 4 bytes each, two directions, every round. Centralized: each organization's training records sent once."),
    ("Decision rule", "Gain: the low end of the 95% range above 5 points. False positives: a rise of at most 1 point over isolated training. Privacy (sharing): if the gain is met but the organization's own sent records are traced above the majority-host baseline, the result is a trade-off. Data sent is reported, not judged. " + RULE_WORDS),
    ("Fingerprint", "A file of summary statistics per attack type written by the local agent: quantiles and rank correlations of the behavior numbers for groups of at least 50 records. No records, no identifier columns. A summary, not a formal privacy protection."),
    ("Run of record", "The praxis run whose numbers the study reports. DataSense: Hex, 11 October 2026, three seeds, the protocol budget. Edge-IIoTset, the ranking check: Hex, 19 October 2026. "
                      "Every other run shown by this tool is a local run or a tool rerun and is labelled so."),
    ("Quick look and protocol budget", "A quick look trains with one seed, fewer passes and fewer resamples: it shows that a file works in the tool. The protocol budget (three seeds, 61 passes, 2,000 resamples) is the praxis budget and the one to report."),
    ("Column role", "What a column is used for: the label, the host or device, the clock, an identifier to remove, or a behavior number to keep. The tool proposes the roles; a person confirms them."),
    ("MITRE ATT&CK", "A public catalogue of adversary techniques kept by MITRE. The tool maps each dataset's own attack labels to a common attack family and to the closest techniques (v20.1, Enterprise and ICS); a suggestion, not a ruling."),
]


def page_definitions():
    sub_hero("Glossary", "The words, defined once", "Every term, as this tool uses it. Where the praxis applies a different rule on DataSense, the entry says so.")
    q = st.text_input("Search the glossary", "", placeholder="Search, for example: recall, sanitized, tracing", key="gl_q", label_visibility="collapsed")
    shown = [(t, d) for t, d in TERMS if q.lower() in (t + " " + d).lower()]
    if shown:
        H(ui.deflist(shown))
    if not shown:
        st.info("No term matches that search.")
    ui.section("Sources", "Where the procedure comes from")
    st.markdown("""
The procedure is the frozen protocol of a George Washington University Doctor of Engineering praxis: *Privacy-Aware Evaluation of Sanitized Attack-Record Sharing and
Federated Learning for Intrusion Detection on Industrial Network Data* (Rayve Malhotra, in progress). The study dataset is DataSense CIC IIoT 2025
(Firouzi, Dadkhah, Maret and Ghorbani, 2025; Canadian Institute for Cybersecurity). The ranking check uses Edge-IIoTset (Ferrag, Friha, Hamouda, Maglaras and Janicke, 2022).
Federated averaging follows McMahan et al. (2017). The other datasets are public intrusion datasets used to show that the procedure runs on new data; their makers are named on each result page.
""")


def page_students():
    sub_hero("Students", "A one-hour exercise",
             "You need one labeled intrusion dataset: a CSV with one row per record and a column that names the attack type or says normal. "
             "The list at the bottom gives public datasets with direct downloads; the results page shows what the tool found on each of them. "
             "No dataset yet? The Live demo runs sample files, and Evaluate offers the same samples.")
    steps = [("Look at the data", "10 minutes", "Open Evaluate and upload your file. Read the opening rows. Check the columns the tool proposes: which one is the label, which value means normal, which column names the host or device, which column is the clock. Fix anything it got wrong. Open the record shown before and after sanitizing and write down what a peer would receive and what stays home."),
             ("Make the organizations", "5 minutes", "Note how the tool formed organizations A, B and C (groups of hosts, or random thirds when there is no host column), and which attack type each organization has withheld. Write one sentence per organization: what it trains on, and which attack type it has withheld."),
             ("Run a quick look", "5 minutes", "Choose Quick look and run. Read the bars of each organization. Which training condition named the withheld attack type best? Which one raised the false-positive rate? What did each condition send, in bytes?"),
             ("Read the verdicts", "10 minutes", "For each organization and each of the two approaches, write whether the gain was met, whether the false-positive limit held, and whether the sanitized records could be traced back to their host above the majority-host baseline. Is the verdict the same for all three organizations? If not, why not?"),
             ("Run the protocol budget", "20 minutes or more", "Repeat with Protocol run. Compare the 95% ranges with the quick look. Did any verdict change? A quick look is a check; only the protocol run is a result."),
             ("Write five sentences", "10 minutes", "Dataset, organizations, the best condition for each organization, what it cost (false positives, bytes, tracing), and what you would tell an organization that asked whether to share.")]
    H(ui.rows([(t, esc(x), ui.chip(dur, "teal")) for t, dur, x in steps]))
    H("<div class='tp-note'><p><b>What to be careful about.</b> The split is the tool's own when a dataset has no clock (random split, optimistic ranges). A dataset with few normal records "
      "gives an unreliable alarm threshold. A dataset with few behavior numbers gives the detector little to work with. The tool reports all of this on the result page; read it before you trust a number.</p></div>")
    ui.section("Data", "Public datasets with a direct download")
    rows = dataset_list()
    if rows:
        ui.table(pd.DataFrame(rows), wrap=("Dataset", "Made by", "Attack types", "Host column", "Source", "Licence", "Runs in the tool"))
    else:
        st.caption("The dataset list file (results/_datasets.json) was not found in this copy. The sources are named on each result page.")
    st.caption("Kaggle and IEEE DataPort releases need a sign-in and are not listed. Every dataset keeps its makers' licence; cite them in anything you write.")


def dataset_list():
    """The public datasets of the Students page, from the tracked file results/_datasets.json (written by tools/write_dataset_list.py),
    so that a clone or a hosted copy shows the same list as the author's machine."""
    try:
        with open(os.path.join(RESULTS, "_datasets.json"), encoding="utf-8") as fh:
            rows = json.load(fh)
    except Exception:
        return []
    cols = ("Dataset", "Made by", "Attack types", "Host column", "Source", "Licence", "Runs in the tool")
    return [{c: str(r.get(c, "")) for c in cols} for r in rows if isinstance(r, dict) and r.get("Dataset")]


EXAMPLE_FP = os.path.join(SAMPLES, "sample_organization_water_utility_SYNTHETIC.fingerprint.example.json")


@st.cache_data(show_spinner=False)
def _file_bytes(path):
    with open(path, "rb") as fh:
        return fh.read()


TERMINAL = ("<div class='tp-term'><div class='dots'><i></i><i></i><i></i></div>"
            "<span class='m'>$</span> python threatprint_agent.py my_records.csv<br>"
            "Read <span class='y'>22,073</span> records, 31 columns from my_records.csv<br>"
            "<span class='c'>Removed before anything leaves (11):</span> timestamp, site,<br>  device_name, device_ip, device_mac, peer_ip, ...<br>"
            "<span class='c'>Kept as behavior numbers (19):</span> duration_s, packets_out, ...<br>"
            "  arp_mitm        Adversary in the middle        <span class='y'>T1557.002</span><br>"
            "  port_scan       Reconnaissance and scanning    <span class='y'>T1595</span><br>"
            "  ddos_udp_flood  Distributed denial of service  <span class='y'>T1498</span><br>"
            "  <span class='m'>... and four more attack types</span><br>"
            "<span class='g'>[ok]</span> 7 attack types with at least 50 records<br>"
            "Wrote my_records.fingerprint.json (27 KB calculated payload)<br>"
            "<span class='g'>Nothing was sent anywhere.</span><br>"
            "<span class='m'>(output of the agent on the synthetic sample file, shortened)</span></div>")


def page_agent():
    cards = load_cards()
    sub_hero("Local agent and fingerprint", "Run the agent at home. <em>Share only a fingerprint.</em>",
             "The agent is one readable Python file. On your own machine it finds the identifier columns, removes them, maps your attack labels to common attack families and to MITRE ATT&CK, "
             "and writes a small fingerprint file: summary statistics per attack type, no records. You look at the file, and only then decide whether to upload it. The agent and the fingerprint are product research; they are not part of the praxis.", right=TERMINAL)
    H(ui.rows([(t, x) for _, t, x, _, _ in [
        ("term", "Download the agent", "One file, pandas and numpy only, no network code. A security team can read all of it before running it.", "ink", 1),
        ("filter", "Run it on your records", "It prints what it removed, what it kept, the ATT&CK mapping and a readiness check, and writes the fingerprint next to your file.", "", 2),
        ("print", "Upload the fingerprint", "This page checks its integrity digest, shows your attack coverage against the library and tells you whether the full evaluation can run on your data.", "amber", 3)]], cols=3))
    st.markdown("")
    samples = load_manifest()
    d1, d2 = st.columns(2)
    d1.download_button("Download the agent (one Python file)", _file_bytes(os.path.join(HERE, "threatprint_agent.py")), file_name="threatprint_agent.py", mime="text/x-python", key="dl_agent", type="primary", use_container_width=True)
    if os.path.isfile(EXAMPLE_FP):
        d2.download_button("Example fingerprint (try the upload without a terminal)", _file_bytes(EXAMPLE_FP), file_name=os.path.basename(EXAMPLE_FP), mime="application/json", key="dl_example_fp", use_container_width=True)
    if samples:
        for col, smp in zip(st.columns(len(samples)), samples):
            col.download_button(f"Sample file: {smp['title']} ({smp['kind']})", _file_bytes(smp["path"]), file_name=smp["file"],
                                mime="text/csv" if smp["file"].lower().endswith(".csv") else "application/octet-stream", key=f"dl_sample_{smp['id']}", use_container_width=True)
        H("<div class='tp-note' style='margin-top:10px'><p><b>" + f"{len(samples)} sample files to try the tool with." + "</b> Upload any of them on the Evaluate page, watch one on the Live demo, or run the agent on it.</p>"
          + "".join(f"<p><b>{esc(smp['title'])}</b> ({esc(smp['kind'])}). {esc(smp['summary'])} {esc(smp['licence'])}</p>" for smp in samples)
          + "<p><b>Example fingerprint.</b> The file the agent wrote for the synthetic water utility. Download it and upload it below to see the coverage, the gaps and the readiness check without running anything.</p></div>")

    ui.section("Your fingerprint", "Upload a fingerprint", art="your fingerprint", text="A fingerprint file written by the agent (.json). It is checked, read and compared; it is kept only if you choose to contribute it.")
    up = st.file_uploader("A fingerprint file written by the agent (.json)", type=["json"], key="fp_upload", label_visibility="collapsed")
    if up is not None:
        try:
            fp = agent.load_fingerprint(up.getvalue())        # every field checked; one sentence when it is not a fingerprint
        except agent.DataProblem as e:
            st.error(f"This file could not be used: {e}.")
            fp = None
        except Exception:
            st.error(f"This file could not be used: it is not a {TOOL} fingerprint.")
            fp = None
        if fp is not None:
            good = agent.verify(fp)
            if good:
                st.success(f"Integrity digest matches (SHA3-256 {agent.digest(fp)[:16]}...). Agent version {fp.get('agent')}, made {fp.get('created')}.")
            else:
                st.error("The integrity digest does not match: the file was changed after the agent wrote it. Nothing below should be relied on.")
            ui.stats([(f"{len(fp.get('classes', {}))}", "attack types in the fingerprint", "ink"), (f"{len(fp.get('features', []))}", "behavior numbers kept", ""),
                      (esc(str(fp.get('removed_columns_count', 0))), "columns removed before anything left", "indigo"), (esc(kb(fp.get("payload_bytes", 0))), "calculated payload of the fingerprint", "amber")])
            ui.section("Readiness", "Can the full evaluation run on your data?")
            H("<div class='tp-card'><ul class='tp-list'>" + "".join(
                f"<li><span class='i {'ok' if ok else 'wait'}'>{ui.icon('check' if ok else 'minus', 13, 3)}</span><span>{esc(text)}</span></li>" for ok, text in agent.readiness(fp)) + "</ul></div>")
            ui.section("Coverage", "Your attack coverage, by MITRE ATT&CK")
            rows = [{"Your label": lab, "About how many records": f"{c['records']:,}", "Attack family": f"<td>{ui.chip(c.get('family', ''), 'indigo')}</td>",
                     "MITRE ATT&CK technique (closest)": "<td class='wrap'>" + "".join(ui.chip(f"{t['id']} {t['name']} ({t['matrix']})") for t in c.get("techniques", [])) + "</td>"}
                    for lab, c in fp.get("classes", {}).items()]
            ui.table(pd.DataFrame(rows), raw=("Attack family", "MITRE ATT&CK technique (closest)"))
            if fp.get("suppressed"):
                st.caption(f"{len(fp['suppressed'])} attack types were left out of the fingerprint because they had fewer than {fp.get('min_group_size')} records.")
            ui.section("Gaps", "What the library holds that you do not",
                       "A family marked no is one your detectors have no examples of. The colored cells show how much peers' examples of it helped others in the library; it is not a forecast for your network.")
            mine = {c.get("family") for c in fp.get("classes", {}).values()}
            lib = {}
            for c in cards:
                for fam in {agent.classify(x)["family"] for x in c.get("classes", [])}:
                    lib.setdefault(fam, []).append(c["name"])
            fs = family_stats(cards).set_index("family") if cards else None
            rows = []
            for fam, names in sorted(lib.items(), key=lambda kv: -len(kv[1])):
                if fam == agent.UNMAPPED:
                    continue
                r = fs.loc[fam] if fs is not None and fam in fs.index else None
                rows.append({"Attack family": fam, "In your fingerprint": f"<td>{ui.badge('yes', 'ok') if fam in mine else ui.badge('no', 'no')}</td>", "Datasets in the library that hold it": len(names),
                             "Isolated training": ui.heat(r.iso if r is not None else None), "Sanitized attack-record sharing": ui.heat(r.sha if r is not None else None),
                             "Federated learning": ui.heat(r.fed if r is not None else None), "Centralized training": ui.heat(r.cen if r is not None else None)})
            ui.table(pd.DataFrame(rows), wrap=("Attack family",), raw=("In your fingerprint", "Isolated training", "Sanitized attack-record sharing", "Federated learning", "Centralized training"))
            st.caption("The four recall columns are library means from local runs of the tool, not the run of record: when an organization had that family withheld, the share of its test records named correctly under each training condition.")
            ui.section("Contribute", "Add this fingerprint to the library (optional)")
            agree = st.checkbox("I am allowed to share this fingerprint, and I agree that the operator of this site keeps it to compare attack coverage across organizations. "
                                "It holds summary statistics only: no records and no identifier columns.", key="fp_agree")
            st.caption("A contributed fingerprint is kept on the machine that runs this site until its operator deletes it. To have it removed, give the operator the start of its digest, shown above. "
                       "The agent itself never uploads anything; contributing is this manual step.")
            if st.button("Contribute this fingerprint", disabled=not (agree and good), key="fp_contribute"):
                try:
                    engine.save_contribution(fp, CONTRIBUTIONS)
                    st.success("Kept on the machine that runs this site. Thank you.")
                except engine.DataProblem as e:
                    st.error(f"Not kept: {e}.")
    else:
        st.info("Waiting for a fingerprint file. To try it now, download the example fingerprint above and upload it here. To make your own: download the agent and a sample file, then run the agent on the sample.")

    ui.section("Inside the file", "What a fingerprint is, and what it is not")
    H("<div class='tp-duo2'>" + "".join([
          (f"<div><h4>What it holds</h4><p>For every attack type with at least {agent.K_MIN} records: the record count rounded down to the nearest ten, "
          f"{len(agent.GRID)} quantiles (1% to 99%) of every behavior number, and the rank correlations between them. A SHA3-256 integrity digest, and a signature field reserved for a post-quantum signature "
          "(ML-DSA, FIPS 204); signing is designed, not built.</p></div>"),
          (f"<div><h4>What it does not hold, and what it does not promise</h4><p>No rows, no device names, no addresses, no ports, no time stamps. The lowest and highest points it stores are the 1% and 99% quantiles, not the extremes; "
          "for a number with few distinct values (a count that is mostly 0) they can equal the smallest or largest value. Normal traffic is not fingerprinted. It is a summary, not a formal privacy protection: no differential privacy is applied, and what a fingerprint reveals about the organization that made it has not been measured.</p></div>")]) + "</div>")

    ui.section("Experiment, not part of the praxis", "Does a fingerprint carry enough to help?")
    done = [c for c in cards if exp_of(c)]
    if done:
        ok_fp = sum(1 for c in done if exp_of(c)["mean_gain"]["clears"])
        above_fed = sum(1 for c in done if exp_of(c)["mean_gain"]["gain"] > c["hypotheses"]["H2"]["gain"])
        above_sha = sum(1 for c in done if exp_of(c)["mean_gain"]["gain"] > c["hypotheses"]["H1"]["gain"])
        ratios = sorted(sum(c["companies"][o]["bytes"]["2_sharing"] for o in ORG) / max(1, sum(exp_of(c)["orgs"][o]["bytes"] for o in ORG)) for c in done)
        st.markdown(f"Fingerprint sharing was run on {len(done)} datasets of the library as a fifth, experimental arm: the receiver trains on its own records plus made-up records drawn from its peers' fingerprints, "
                    f"with the same training budget and alarm rule as the four training conditions.")
        ui.stats([(f"{ok_fp}<small> of {len(done)}</small>", "datasets where the whole 95% range of its mean gain is above 5 points", "amber"),
                  (f"{above_fed}<small> of {len(done)}</small>", "datasets where its mean gain is above federated learning's (point estimates)", "indigo"),
                  (f"{above_sha}<small> of {len(done)}</small>", "datasets where its mean gain is above sanitized attack-record sharing's", ""),
                  (f"{ratios[len(ratios) // 2]:.0f}<small> times</small>", "fewer bytes than record sharing (median over the datasets)", "ink")])
        with st.expander("The numbers, dataset by dataset"):
            rows = []
            for c in done:
                e = exp_of(c)
                rows.append({"Dataset": c["name"], "Run": "local run", "Isolated training": "baseline", "Sanitized attack-record sharing": pts(c["hypotheses"]["H1"]), "Federated learning": pts(c["hypotheses"]["H2"]),
                             "Centralized training": pts(c["checks"].get("pooled")), "Fingerprint sharing (experimental)": pts(e["mean_gain"]),
                             "Data sent, sharing": kb(sum(c["companies"][o]["bytes"]["2_sharing"] for o in ORG)), "Data sent, fingerprints": kb(sum(e["orgs"][o]["bytes"] for o in ORG))})
            ui.table(pd.DataFrame(rows), wrap=("Dataset",))
        st.caption("Mean gain in attack-class recall on the withheld attack types against isolated training; local runs of the tool on the tool's own splits, which are optimistic where a dataset has no clock. "
                   "Only DataSense carries the praxis claims, and the praxis has four training conditions; fingerprint sharing is product research, run with its own isolated baseline. "
                   "What a fingerprint reveals about its sender has not been measured, so a gain here is half of an answer.")
    else:
        st.caption("Not yet run on this install.")


def page_research():
    H(ui.sub_hero_html(f"The research behind {TOOL}", esc(APPROVED['title']),
                       "Doctor of Engineering praxis, George Washington University, SEAS 8499. Author: Rayve Malhotra. " + IN_PROGRESS, long=True))
    ui.section("Problem statement", "The problem")
    H(f"<div class='tp-quote'>{esc(APPROVED['problem_statement'])}</div>")
    ui.section("Thesis", "Thesis (proposed, awaiting advisor approval)")
    H(f"<div class='tp-quote amber'>{esc(APPROVED['thesis'])}</div>")
    ui.section("Questions and answers", "Research questions, hypotheses and what the study found",
               "Findings are the DataSense run of record (Hex, 11 October 2026, three seeds).")
    res = [("+41.1", "points, 95% range [32.5, 49.6]", "supported"), ("+45.8", "points, 95% range [37.0, 53.9]", "supported"), ("41% to 55%", "traced, against a majority-device baseline of 7% to 35%", "observed")]
    for i, (big, small, verdict) in enumerate(res, 1):
        H(f"<div class='tp-pair'><div><span class='tag'>RQ{i}</span>{esc(APPROVED[f'RQ{i}'])}</div><div><span class='tag'>H{i}</span>{esc(APPROVED[f'H{i}'])}</div>"
          f"<div class='res'><span class='v'>{big}</span><span class='s'>{small}</span>{ui.badge(verdict, 'ok' if verdict == 'supported' else 'amber')}</div></div>")
    H(f"<div class='tp-note'><p><b>H3.</b> {H3_OBSERVED}</p></div>")
    ui.section("Run of record", "What the study found on DataSense, organization by organization", art="run of record", text=
               "Attack-class recall on the withheld attack type under the four training conditions, and how often a receiving peer traced sanitized attack records to their source device.")
    H(ui.legend([(SHORT[r], ui.COND[r]) for r in ROADS]))
    panels = []
    for o in ORG:
        name, dev, withheld = DATASENSE_ORGS[o]
        r, (tr, gu) = RUN_OF_RECORD["recall"][o], RUN_OF_RECORD["traced"][o]
        panels.append(f"<div class='tp-org'><div style='display:flex;justify-content:space-between;align-items:flex-start'><div class='name'>{name}</div>{ui.badge('run of record', 'ok')}</div>"
                      f"<div class='meta'>{dev}</div><div style='margin-bottom:10px'>{ui.chip('withheld: ' + withheld, 'dark')}</div>"
                      + ui.bars([(SHORT[k], r[k] / 100.0, ui.COND[k], False) for k in ROADS])
                      + "<div class='sep'>" + ui.duo(tr / 100.0, gu / 100.0, "traced to the source device", "majority-device baseline") + "</div></div>")
    ui.grid(panels)
    st.markdown("")
    ui.stats([("+41.1", "H1: mean gain, sanitized attack-record sharing [32.5, 49.6]", ""), ("+45.8", "H2: mean gain, federated learning [37.0, 53.9]", "indigo"),
              ("41% to 55%", "H3, observed: sanitized records traced to their device (majority-device baseline 7% to 35%)", "amber"), ("0.499 to 0.513", "membership test on model weights (separate 10-round run): AUC, all six 95% ranges include 0.5, no clear signal", "ink")])
    st.markdown("""
Three organizations were made from the DataSense CIC IIoT 2025 testbed by device role: A, network gear (7 devices, DoS withheld); B, cameras (10 devices, DDoS withheld);
C, sensors and plugs (21 devices, MITM withheld). Each organization trained one detector under the four training conditions with the same network, the same step budget per tested detector
and the same alarm rule, and was tested on its withheld attack type. H1 and H2 were supported: the whole 95% range of the mean gain lies above 5 points.
For H3 the observed finding is that a receiving peer holding device-labelled reference traffic traced the sanitized attack records to their source device above the majority-device baseline
for every sender, so removing identifiers is not enough on its own; the statistical support for H3 is not called settled yet (see the note above). Organization C named none of its withheld MITM records under any condition, which the study reports as it is.
""")
    ui.section("From study to product", f"What {TOOL} adds")
    st.markdown("""
The same procedure, as a service: any organization can run it on its own records without sending them anywhere, and read the answer in the terms of the study, with the
decision rule applied. The results page shows the procedure on the praxis dataset, on the ranking check (Edge-IIoTset) and on public intrusion datasets, so that the procedure
is seen on more than one source of data. The study claims rest on DataSense alone; every other run is a tool test with the tool's own split.
""")
    st.caption("The problem statement, research questions and hypotheses above are quoted as recorded in the praxis; the thesis is a proposal until the advisor approves it. "
               "The local agent, the MITRE ATT&CK mapping and fingerprint sharing are product research built on the praxis procedure; they are not part of the praxis. "
               "The paragraphs on this page that are not quoted were written with AI assistance for this site; they are not text from the praxis document.")


def nvflare_status():
    """What the NVIDIA FLARE integration says about itself in integrations/nvflare/STATUS.json; None when there is no such file or it cannot be read.
    The page states nothing about NVIDIA beyond what this file confirms."""
    try:
        with open(os.path.join(HERE, "integrations", "nvflare", "STATUS.json"), encoding="utf-8") as fh:
            d = json.load(fh)
    except Exception:
        return None
    if not isinstance(d, dict) or d.get("status") not in ("tested", "not built"):
        return None
    details = d.get("details") if isinstance(d.get("details"), list) else []
    return dict(status=d["status"], summary=str(d.get("summary") or "").strip(), details=[str(x).strip() for x in details if isinstance(x, (str, int, float)) and str(x).strip()][:12])


def page_organizations():
    sub_hero("For organizations", "An evaluation, <em>not a promise</em>",
             "Information-sharing groups ask members to contribute attack data. Federated learning vendors ask them to contribute model updates. "
             f"{TOOL} measures, on your own records, what each would gain in detecting the attack types you have not trained on, what it would cost in false alarms, how many bytes would leave, "
             "and whether a sanitized record could still be traced back to one of your devices.")

    ui.section("Who it is for", "Three kinds of organization ask this question")
    H(ui.rows([(t, x) for _, t, x, _ in [
        ("building", "Operators of industrial and IoT networks", "Utilities, manufacturing, building systems, healthcare devices. You are asked to share attack data or to join a federated program, "
         "and you need to know what it would add to your own detection and what it would expose.", ""),
        ("orgs", "Groups that ask members to share", "ISACs, sector CERTs and consortia. Each member gets its own evidence of the gain and of the exposure, in the same terms as every other member: "
         "for this member, with this data, is sharing worth it?", "indigo"),
        ("flask", "Builders and researchers of federated detection", "One test bench for every approach: the same detector, the same step budget per tested detector and the same alarm rule, on the customer's own records, "
         "with the decision rule applied.", "amber")]], cols=3, numbered=False))

    ui.section("What you get", "Before you share, know what it buys and what it exposes")
    H(ui.rows([(t, x) for _, t, x, _ in [
        ("chart", "A scorecard in your own terms", "Four training conditions on your data, one withheld attack type per organization, gains with 95% ranges, false-positive rates, data sent, tracing. "
         "A report you can hand to a security committee.", ""),
        ("scale", "A rule, not an opinion", "The decision rule says when an approach is worth it: gain low end above 5 points, false positives up by at most 1 point, and a tracing check on what sharing exposes.", "amber"),
        ("print", "Coverage by MITRE ATT&CK", "The local agent maps your attack labels to common families and techniques and shows which families the library holds that you do not.", "indigo"),
        ("lock", "Run it where your records are", "Run the tool on your own machine or inside your network (one container) and nothing leaves it. Uploads to a hosted copy live in the browser session only and are not stored; a fingerprint is kept only if you choose to contribute it.", "ink")]], cols=2))

    ui.section("How to use it", "Three ways to deploy", "Free during the review period.")
    use = [("demo", "On this site", "Watch a sample file go through the product, then upload a labeled sample of your own, run a quick look, read the scorecard and download the report. "
            "The table you upload is not stored.", "Open the live demo", 1),
           ("agent", "With the local agent", "Run the agent on your records and upload only the fingerprint: no records leave your network. You get your MITRE ATT&CK coverage, "
            "the gaps against the library and a readiness check.", "Get the agent", 2),
           ("research", "Inside your network", "The same tool as a container or a local install (the repository and the Dockerfile are public). Protocol-budget runs on your full records, "
            "reports for your records only.", "Read the research", 3)]
    with st.container(key="tp_ways_org"):
        for key, t, x, cta, no in use:
            with st.container(key=f"tp_way_org{no}"):                    # the option and its own link stay together on every screen
                H(ui.way_html(no, t, esc(x)))
                link(key, cta, "cta_light", "org")

    ui.section("Deployment across sites", "From one machine to separate sites",
               "In this tool the federated learning condition runs in one process: the three organizations are simulated on one machine and their model weights are averaged with FedAvg. "
               "Running the same condition across separate sites needs a federated runtime. This section reports only what has been run and tested.")
    nv = nvflare_status()
    if nv and nv["status"] == "tested":
        H(f"<div class='tp-card'><div style='display:flex;justify-content:space-between;align-items:center;gap:10px'><h5 style='margin:0'>NVIDIA FLARE job export</h5>{ui.badge('tested', 'ok')}</div>"
          f"<p style='margin-top:8px'>{esc(nv['summary'])}</p>"
          + ("<ul class='tp-list' style='margin-top:8px'>" + "".join(f"<li><span class='i ok'>{ui.icon('check', 13, 3)}</span><span>{esc(x)}</span></li>" for x in nv["details"]) + "</ul>" if nv["details"] else "")
          + "</div>")
        st.caption("Product research built on the praxis procedure. It is not part of the praxis, which compares the four training conditions inside one process.")
    else:
        text = nv["summary"] if nv and nv["summary"] else "No tested integration is on file, so none is claimed here."
        H(f"<div class='tp-card'><div style='display:flex;justify-content:space-between;align-items:center;gap:10px'><h5 style='margin:0'>NVIDIA FLARE job export</h5>{ui.badge('designed, not built', 'amber')}</div>"
          f"<p style='margin-top:8px'>NVIDIA FLARE job export: designed, not built. {esc(text)}</p></div>")

    ui.section("Status", "What is built, and what is designed")
    built = [("Evaluation of four training conditions on your data, with the decision rule", "ok"), ("Live demo: a sample file through every stage, with the numbers of that run", "ok"),
             ("Sanitizer with one record shown before and after", "ok"),
             ("Local agent: sanitize at home, fingerprint file, SHA3-256 integrity digest", "ok"),
             ("Attack labels mapped to common families and MITRE ATT&CK v20.1 (Enterprise and ICS), identifiers checked against MITRE's published data", "ok"),
             ("Library of public datasets run with the protocol budget, with a table of which attack families transfer", "ok"),
             ("Fingerprint sharing as an experimental fifth arm", "ok")]
    later = [("Measuring what a fingerprint reveals about its sender (tracing and membership tests on fingerprints)", "wait", "designed, not built"),
             ("Post-quantum signature on fingerprints (ML-DSA, FIPS 204) and post-quantum key exchange for uploads (ML-KEM, FIPS 203)", "wait", "designed, not built"),
             ("Differential privacy or other formal protection on what is shared", "no", "not built"), ("Accounts, saved runs, payments", "no", "not built")]
    H("<div class='tp-duo2'><div><h4>Built</h4><ul class='tp-list'>" + "".join(f"<li><span class='i ok'>{ui.icon('check', 13, 3)}</span><span>{esc(t)}</span></li>" for t, _ in built) + "</ul></div>"
      "<div><h4>Designed or not built</h4><ul class='tp-list'>" + "".join(
          f"<li><span class='i {k}'>{ui.icon('clock' if k == 'wait' else 'minus', 13, 2.6)}</span><span>{esc(t)} {ui.badge(s, 'amber' if k == 'wait' else 'na')}</span></li>" for t, k, s in later) + "</ul></div></div>")

    ui.section("Looking ahead", "Why post-quantum matters here", art="post-quantum")
    H("<div class='tp-card'>" + ui.timeline([("August 2024", "Standards published", "FIPS 203, 204 and 205|(ML-KEM, ML-DSA, SLH-DSA)"),
                                             ("Today", "Harvest now, decrypt later", "Traffic captured today can be stored|and decrypted once the machines exist"),
                                             ("2030", "Deprecated", "Today's public-key algorithms, as reported|from NIST's transition report IR 8547"),
                                             ("2035", "Disallowed", "The same algorithms,|as reported from the same report")]) + "</div>")
    st.caption("The 2030 and 2035 dates are as reported from NIST IR 8547; whether that report is final was not confirmed on nist.gov when this page was written.")
    st.markdown("""
Attack records, model updates and fingerprints describe the weak points of industrial equipment that stays in service for fifteen or twenty years, so what organizations exchange about their defenses
needs protection with a long life. In this tool the fingerprint already carries a hash-based integrity digest (SHA3-256) and a signature field built to take ML-DSA; the signing itself and a
post-quantum upload channel are designed, not built. Quantum machine learning for detection is not part of the plan: the value is in protecting what is shared, not in a quantum detector.
""")
    ui.section("Limits", "Honest limits")
    H("<div class='tp-note'>"
      "<p>The procedure needs labeled records with at least three attack types, a normal label, and ideally a host or device column and a clock. It evaluates detectors of the study's design; it is not an intrusion detection product itself.</p>"
      "<p>Sanitized means direct identifiers removed, nothing more. The tracing test shows what that leaves exposed; it does not apply differential privacy or any other control.</p>"
      "<p>Results on a quick look are a check; the protocol budget is the one to decide on. The study claims rest on DataSense; your data gets its own evidence.</p></div>")
    ui.section("Contact", "Talk to the author")
    st.markdown("Open an issue or a discussion on [the project repository](https://github.com/rayvemalhotra/praxis-lab).")


# ---------------------------------------------------------------- access
def access_password():
    """The shared access password, from the TP_PASSWORD (or PRAXIS_LAB_PASSWORD) environment variable or .streamlit/secrets.toml
    ([access] password = "..."). No password set = open access (the local install)."""
    if os.environ.get("TP_OPEN") == "1" or os.environ.get("PRAXIS_LAB_OPEN") == "1":          # a local-only copy for the owner's own machine
        return ""
    pw = (os.environ.get("TP_PASSWORD") or os.environ.get("PRAXIS_LAB_PASSWORD") or "").strip()
    if pw:
        return pw
    try:
        return str(st.secrets["access"]["password"]).strip()
    except Exception:
        return ""


def _token(pw, day=None):
    """A day-scoped token derived from the password, kept in a browser cookie so that a page reload does not ask again."""
    import hashlib
    import hmac as _hmac
    day = day if day is not None else int(time.time() // 86400)
    return _hmac.new(pw.encode(), f"threatprint-{day}".encode(), hashlib.sha256).hexdigest()[:40]


def _cookie_ok(pw):
    try:
        got = st.context.cookies.get("tp_access", "")
    except Exception:
        return False
    if not isinstance(got, str) or not got or len(got) > 200:    # only a short text can be the token
        return False
    import hmac as _hmac
    today = int(time.time() // 86400)
    return any(_hmac.compare_digest(got, _token(pw, d)) for d in (today, today - 1)) if got else False


def _set_cookie(value, max_age=86400):
    """Set (or clear) the sign-in cookie from a small script. The value is this app's own token or empty, never anything a visitor typed.
    st.iframe is the supported call since Streamlit 1.67; older installs fall back to the components call it replaces."""
    doc = (f"<script>document.cookie = 'tp_access={value}; path=/; max-age={int(max_age)}; SameSite=Lax' + (location.protocol === 'https:' ? '; Secure' : '');</script>")
    if hasattr(st, "iframe"):
        st.iframe(doc, height=1)
    else:
        import streamlit.components.v1 as components
        components.html(doc, height=0)


def _ss(key, default=None):
    """A session value that only this script sets; a forged widget message of the same name must not break the page."""
    try:
        return st.session_state.get(key, default)
    except Exception:
        return default


def _client():
    """Who is knocking: the address the tunnel or proxy reports, else the socket address."""
    try:
        h = st.context.headers
        for v in (h.get("Cf-Connecting-Ip"), (h.get("X-Forwarded-For") or "").split(",")[0].strip(), st.context.ip_address):
            if isinstance(v, str) and v:
                return v[:64]
    except Exception:
        pass
    return "unknown"


def gate():
    """Ask for the access password once per browser (a cookie keeps the session for a day). Returns True when the person may use the tool."""
    import hmac
    pw = access_password()
    if not pw:
        return True
    if _ss("_access_ok") is True:
        return True
    if not _ss("_left") and _cookie_ok(pw):     # cookies are read at session start, so a session that left ignores them
        st.session_state["_access_ok"] = True
        return True
    H("<div style='height:7vh'></div>")
    left, right = st.columns([1.2, 1], gap="large", vertical_alignment="center")
    with left:
        H(f"<div class='tp-gate'><div class='art' aria-hidden='true'>{ui.print_art('g', ridges=26, w=520, h=620, pts=30)}</div><div>{ui.logo(light=True)}<h1>Know what sharing buys.<br><em>Know what it exposes.</em></h1>"
          "<p>A privacy-aware evaluation of collaborative intrusion detection, on your own records.</p>"
          "<ul><li><i>1</i>Four training conditions, one scorecard, one decision rule</li><li><i>2</i>Attack types mapped to MITRE ATT&CK v20.1</li>"
          "<li><i>3</i>A local agent that shares a fingerprint, not your records</li></ul></div>"
          f"<div class='foot'>Built on the procedure of a George Washington University doctoral praxis. {IN_PROGRESS} {RESEARCH_NOTE}</div></div>")
    with right:
        with st.container(key="tp_gate_card"):
            H(f"<div class='tp-gatehead'><div class='k'>Reviewer access</div><div class='t'>Enter {esc(TOOL)}</div>"
              "<div class='d'>This site is for people who were given the access password.</div></div>")
            try:                                         # a forged widget message can make Streamlit itself fail while it draws the form;
                                                         # that session then gets one calm sentence instead of an error box
                try:
                    attempts = int(_ss("_access_attempts", 0) or 0)
                except Exception:
                    attempts = 0
                with st.form("access_form", border=False):
                    given = st.text_input("Access password", type="password", key="_access_input")
                    ok = st.form_submit_button("Enter", use_container_width=True)
                if ok:
                    who = _client()
                    wait = engine.GATE_LIMITER.wait(who)             # one count for the whole site: a fresh session does not reset it
                    if wait:
                        st.error(f"Too many wrong passwords were tried. Wait {wait} seconds and try again.")
                    elif hmac.compare_digest(str(given or "").strip().encode(), pw.encode()):
                        engine.GATE_LIMITER.passed(who)
                        st.session_state["_access_ok"] = True
                        st.session_state["_left"] = False
                        st.session_state["_access_attempts"] = 0
                        _set_cookie(_token(pw))
                        time.sleep(0.4)
                        st.rerun()
                    else:
                        engine.GATE_LIMITER.failed(who)
                        attempts += 1
                        st.session_state["_access_attempts"] = attempts
                        time.sleep(min(2 ** min(attempts, 4), 10))
                        st.error("That password did not match. Ask the person who runs this site for the access password.")
            except Exception:
                st.warning("The sign-in form could not be drawn in this session. Reload the page to start a clean session.")
            st.caption("Uploads are not stored: every run lives in your browser session and is gone when the page closes. A fingerprint is kept only if you choose to contribute it.")
    return False


# ---------------------------------------------------------------- run
PAGES = {"start": (page_start, "Overview"), "demo": (page_demo, "Live demo"), "results": (page_results, "Results"), "evaluate": (page_evaluate, "Evaluate"),
         "agent": (page_agent, "Agent"), "research": (page_research, "Research"),
         "organizations": (page_organizations, "Organizations"), "definitions": (page_definitions, "Glossary"), "students": (page_students, "Students")}

if not gate():
    st.stop()
if _test_page in PAGES:
    top_nav(_test_page)
    PAGES[_test_page][0]()
    footer()
else:
    for key, (fn, title) in PAGES.items():
        PG[key] = st.Page(fn, title=title, url_path=("" if key == "start" else key), default=(key == "start"))
    nav = st.navigation(list(PG.values()), position="hidden")
    current = next((k for k, p in PG.items() if p is nav), "start")
    top_nav(current)
    nav.run()
    footer()
    if access_password():
        if st.button("Leave the site", key="_leave"):
            st.session_state["_access_ok"] = False
            st.session_state["_left"] = True
            _set_cookie("", 0)
            time.sleep(0.4)
            st.rerun()
