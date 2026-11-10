"""ThreatPrint: know what sharing buys, and what it exposes.

A web product that runs a privacy-aware evaluation of collaborative intrusion detection on any labeled intrusion
dataset, built on the procedure of a George Washington University doctoral praxis.

    streamlit run app.py

Pages: Overview, Results, Evaluate, Sanitize, Agent, Research, Organizations, Glossary, Students.
The look lives in ui.py; the evaluation in engine.py; the local agent in threatprint_agent.py.
"""
import glob
import json
import math
import os
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
TOOL = ui.BRAND
VERSION = "0.3 (9 November 2026)"

st.set_page_config(page_title=f"{TOOL}: {ui.TAGLINE}", page_icon=os.path.join(HERE, "assets", "threatprint_icon.png"),
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
            c["about"] = ("Industrial IoT testbed, 38 devices in the files analyzed, one record per 10 seconds per device: 59 behavior numbers "
                          "(52 network, 7 log) and the attack type. The organizations are device groups by role.")
        if c.get("id") == "edge_iiotset":
            c["about"] = ("IoT and IIoT testbed, packet records, 38 cleaned features. The praxis run used three random thirds of the records. "
                          "Tracing was not repeated: normal traffic never goes to one of the two attacked hosts, so the attacker of the protocol cannot be built.")
            c["hypotheses"]["H3_note"] = "not repeated on this dataset (see the dataset note)"
            c["info"]["role_text"] = ("Used to check that the ranking of the two approaches seen on DataSense holds on different data. The cleaned file has no host column, "
                                      "so organizations are random thirds; tracing was not repeated (normal traffic never goes to one of the two attacked hosts).")
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
               "Verdict": v.get(road, "not measured")}
        if card.get("id") == "datasense":
            row["Run of record, recall"] = f"{RUN_OF_RECORD['recall'][o][road]:.1f}%"
            row["Run of record, false-positive rate"] = f"{RUN_OF_RECORD['fp'][o][road]:.2f}%"
        rows.append(row)
    e = exp_of(card)
    if e:
        r = e["orgs"][o]
        row = {"Training condition": "Fingerprint sharing (experimental, not a praxis condition)", "Recall, withheld type": pct(r["named"]), "Flagged": pct(r["flagged"]),
               "False-positive rate": pct(r["false_alarm"], 2), "Gain vs isolated, this local run [95% range]": pts(r["gain"]), "Data sent": kb(r["bytes"]),
               "Steps": f"{r.get('steps', 0):,}", "Verdict": r["verdict"]}
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
        rows.append(("Fingerprint sharing (experimental)", e["orgs"][o]["named"], ui.AMBER, True))
    fam = ui.chip(cl["family"], "indigo") + "".join(ui.chip(t["id"]) for t in cl["techniques"][:3])
    hosts = f"{s['sources']} hosts · " if s.get("sources") else ""
    fpr = ", ".join(f"{n} {pct(c['false_alarm'].get(r), 2)}" for r, n in zip(ROADS, ("isolated", "sharing", "federated", "centralized")))
    t = c.get("trace") or {}
    if "traced" in t:
        trace = (f"<div class='sub' style='margin-bottom:4px'><b style='color:{ui.INK}'>Tracing.</b> A peer traced this organization's sanitized attack records to their source host:</div>"
                 + ui.duo(t["traced"], t["guessing"], "traced to the source host", "always guessing the busiest host")
                 + f"<div class='sub'>Gain {t['advantage'] * 100:+.1f} points, 95% range between {t['lo'] * 100:+.1f} and {t['hi'] * 100:+.1f}; {t['sources']} hosts; shuffle test p = {t['p_value']:.3f}."
                 + (f" Note: {esc(t['note'])}." if t.get("note") else "") + "</div>")
    else:
        trace = f"<div class='sub'><b style='color:{ui.INK}'>Tracing.</b> {esc(t.get('skipped', 'not measured for this organization'))}.</div>"
    ror = ""
    if card.get("id") == "datasense":
        r = RUN_OF_RECORD["recall"][o]
        ror = (f"<div class='sub'>Run of record, recall: isolated {r['1_isolated']:.1f}%, sharing {r['2_sharing']:.1f}%, federated {r['3_federated']:.1f}%, centralized {r['4_centralized']:.1f}%. "
               "The bars above are a tool rerun, not the run of record.</div>")
    return (f"<div class='tp-org'><div style='display:flex;justify-content:space-between;align-items:flex-start;gap:8px'><div class='name'>{esc(c['name'])}</div>{ui.badge(run_label(card), 'na')}</div>"
            f"<div class='meta'>{hosts}trains on {s.get('train_after', s['train']):,} records · {s['test_never_seen']:,} test records of the withheld type</div>"
            f"<div style='margin-bottom:10px'>{ui.chip('withheld: ' + str(c['never_seen']), 'dark')}{fam}</div>"
            f"<div style='font-size:.74rem;font-weight:700;letter-spacing:.08em;color:{ui.MUTED};text-transform:uppercase;margin-bottom:6px'>Attack-class recall on the withheld type</div>"
            f"{ui.bars(rows)}"
            f"<div class='row' style='margin-top:8px'><span>Sanitized attack-record sharing</span>{ui.verdict_badge(v.get('2_sharing'))}</div>"
            f"<div class='row'><span>Federated learning</span>{ui.verdict_badge(v.get('3_federated'))}</div>"
            f"<div class='sub'><b style='color:{ui.INK}'>False-positive rate.</b> {fpr}.</div>{ror}"
            f"<div style='border-top:1px solid #f0f3f8;margin-top:10px;padding-top:10px'>{trace}</div></div>")


def hyp_tile(tag, title, h, color, card=None, name=None):
    if not h:
        return f"<div class='tp-hyp'><div class='h'><b>{tag}</b>{ui.badge('not measured')}</div><div class='big'>n/a</div><div class='d'>{esc(title)}</div></div>"
    rec = RECORD.get((card or {}).get("id"), {})
    extra = (f" Run of record ({rec['where']}): {rec[name]}, same decision." if name in rec else "")
    return (f"<div class='tp-hyp'><div class='h'><b>{tag}</b>{ui.badge('supported', 'ok') if h['clears'] else ui.badge('not supported', 'no')}</div>"
            f"<div class='big'>{h['gain'] * 100:+.1f} <small>points</small></div>"
            f"<div class='d'>{esc(title)}. 95% range [{h['lo'] * 100:+.1f}, {h['hi'] * 100:+.1f}], {run_label(card or {})}, not the run of record.{extra}</div>"
            f"{ui.bullet(h['gain'] * 100, h['lo'] * 100, h['hi'] * 100, color)}</div>")


def show_card(card, heading=True):
    """The whole scorecard of one dataset: header, three organization panels, hypothesis tiles, then every number in tables."""
    s1, s2, rules = card["step1"], card["step2"], card["rules"]
    n_rec = sum(s1[o]["train"] + s1[o]["val"] + s1[o]["test"] for o in ORG)
    by = "hosts" if ("groups of hosts" in rules["companies"] or "device groups" in rules["companies"]) else "random thirds"
    quick = card.get("budget", {}).get("name") == "quick"
    chips = (ui.chip(card.get("study_role", "your data"), "dark") + ui.chip(f"{n_rec:,} records") + ui.chip(f"{s2['kept_numbers']} behavior numbers kept", "teal")
             + ui.chip(f"{s2['removed']} columns removed", "teal") + ui.chip(f"organizations by {by}") + ui.chip(f"{len(card['seeds'])} seed{'s' if len(card['seeds']) != 1 else ''}")
             + ui.chip("quick look" if quick else "protocol budget", "amber" if quick else "indigo"))
    H(f"<div class='tp-dshead'><h3>{esc(card['name'] if heading else 'Your scorecard')}</h3><p>{esc(card.get('about', ''))}</p><div>{chips}</div></div>")
    if card.get("id") == "datasense":
        H(f"<div class='tp-callout'><b>Run of record.</b> {RUN_OF_RECORD['note']}</div>")
    if card.get("id") == "edge_iiotset":
        H(f"<div class='tp-callout'><b>Run of record.</b> The praxis run of record for Edge-IIoTset ({RECORD['edge_iiotset']['where']}) reports H1 {RECORD['edge_iiotset']['H1']} and "
          f"H2 {RECORD['edge_iiotset']['H2']}. The local run shown here was computed on another machine; the decimals differ and every decision is the same.</div>")
    if quick:
        st.warning("Quick look: fewer training passes, one seed and fewer resamples than the protocol. Use it to see whether the data works in the tool, not to report a result.")

    H("<div class='tp-sec' style='margin-top:26px'><div class='k'>Steps 3 and 4</div><h2 style='font-size:1.35rem !important'>Four training conditions, tested on the withheld attack type</h2></div>")
    H(ui.legend([(SHORT[r], ui.COND[r]) for r in ROADS] + ([("Fingerprint sharing (experimental, not a praxis condition)", ui.AMBER)] if exp_of(card) else [])))
    ui.grid([org_panel(card, o) for o in ORG])

    H("<div class='tp-sec' style='margin-top:30px'><div class='k'>Step 5</div><h2 style='font-size:1.35rem !important'>Scorecard</h2></div>")
    Hy = card["hypotheses"]
    h3 = Hy.get("H3")
    if h3:
        t3 = (f"<div class='tp-hyp'><div class='h'><b>H3 · TRACING</b>{ui.badge('supported', 'ok') if h3['yes'] else ui.badge('not supported', 'no')}</div>"
              f"<div class='big'>{'All' if h3['yes'] else 'Not all'} {h3['companies']} <small>organizations</small></div>"
              f"<div class='d'>Sanitized attack records traced above the majority-host guess. Gain over guessing from {h3['low'] * 100:+.1f} to {h3['high'] * 100:+.1f} points, {run_label(card)}.</div></div>")
    else:
        t3 = (f"<div class='tp-hyp'><div class='h'><b>H3 · TRACING</b>{ui.badge('not tested')}</div><div class='big'>n/a</div>"
              f"<div class='d'>{esc(Hy.get('H3_note') or 'not measured')}.</div></div>")
    tiles = [hyp_tile("H1 · RECORD SHARING", "Sanitized attack-record sharing: mean gain in attack-class recall over the three organizations", Hy.get("H1"), ui.TEAL, card, "H1"),
             hyp_tile("H2 · FEDERATED", "Federated learning: mean gain in attack-class recall over the three organizations", Hy.get("H2"), ui.INDIGO, card, "H2"), t3]
    e = exp_of(card)
    if e:
        g = e["mean_gain"]
        tiles.append(f"<div class='tp-hyp' style='border-color:#fde3b0;background:#fffdf7'><div class='h'><b>FINGERPRINTS</b>{ui.badge('experimental', 'amber')}</div>"
                     f"<div class='big'>{g['gain'] * 100:+.1f} <small>points</small></div>"
                     f"<div class='d'>Fingerprint sharing: not a praxis training condition. 95% range [{g['lo'] * 100:+.1f}, {g['hi'] * 100:+.1f}], local run. What a fingerprint reveals about its sender has not been measured.</div>"
                     f"{ui.bullet(g['gain'] * 100, g['lo'] * 100, g['hi'] * 100, ui.AMBER)}</div>")
    ui.grid(tiles)

    st.markdown("")
    with st.expander("All numbers: every training condition for each organization"):
        for o in ORG:
            c = card["companies"][o]
            note = " (tool rerun; the run of record is in the last two columns)" if card.get("id") == "datasense" else " (local run of the tool)"
            st.markdown(f"**{c['name']}**, withheld attack type **{c['never_seen']}**, {c['test_rows']:,} test records of that type{note}")
            st.caption(attack_line(c["never_seen"]) + (" The table below is a tool rerun, not the run of record." if card.get("id") == "datasense" else " The table below is a local run of the tool."))
            ui.table(org_table(card, o), wrap=("Training condition", "Verdict"), row_class=lambda n, r: "exp" if str(r["Training condition"]).startswith("Fingerprint") else "")
    with st.expander("Step 1: the three organizations and their withheld attack types"):
        rows = []
        for o in ORG:
            s = s1[o]
            rows.append({"Organization": card["companies"][o]["name"], "Hosts": str(s.get("sources")) if s.get("sources") else "no host column",
                         "Training records": f"{s['train']:,}", "Withheld attack type": s["never_seen"], "Taken out": f"{s.get('withheld', 0):,}",
                         "Trains on": f"{s.get('train_after', s['train']):,}", "of which normal": f"{s.get('train_normal', 0):,}", "of which attack": f"{s.get('train_attack', 0):,}",
                         "Test records of the withheld type": f"{s['test_never_seen']:,}", "Attack events in those": str(s.get("events_never_seen", ""))})
        ui.table(pd.DataFrame(rows), wrap=("Organization",))
        st.caption(f"Organizations: {rules['companies']}. Split: {rules['split']}.")
    with st.expander("Step 2: sanitizing, which columns were kept and which were removed"):
        st.markdown(f"{s2['raw_columns']} columns in the raw data. Kept: {s2['kept_numbers']} behavior numbers and the attack type. Removed: {s2['removed']} columns (identifiers, text, other labels).")
        H("<div style='margin:6px 0 4px 0;font-weight:700'>Kept</div><div>" + "".join(ui.chip(c, "teal") for c in s2.get("kept", [])) + "</div>"
          "<div style='margin:10px 0 4px 0;font-weight:700'>Removed</div><div>" + "".join(ui.chip(c) for c in s2.get("removed_columns", s2.get("removed_examples", []))) + "</div>")
    with st.expander("How it was run, and the separate checks"):
        b = card.get("budget") or {}
        st.markdown(f"Same network ({rules['network']}), same training budget ({rules['passes']} passes of the largest organization at batch {rules['batch']}), "
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
            st.caption("Tool rerun above. Run of record for the same checks: centralized +44.4 [+36.6, +51.7]; flagging only sharing -3.5 [-8.9, +0.5], "
                       "federated -4.1 [-10.2, +0.8]; nothing withheld sharing +2.3 [-3.9, +8.2], federated +0.8 [-6.0, +7.7]; "
                       "membership test (separate 10-round run) no clear signal, all six 95% ranges include 0.5.")
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


def report_html(card):
    """A self-contained HTML report of one scorecard (print it to PDF from the browser)."""
    e = esc
    Hy = card["hypotheses"]
    rows1 = "".join(f"<tr><td>{e(card['companies'][o]['name'])}</td><td>{e(str(card['step1'][o].get('sources') or 'no host column'))}</td>"
                    f"<td>{card['step1'][o]['train']:,}</td><td>{e(card['step1'][o]['never_seen'])}</td><td>{card['step1'][o].get('withheld', 0):,}</td>"
                    f"<td>{card['step1'][o].get('train_after', card['step1'][o]['train']):,}</td><td>{card['step1'][o]['test_never_seen']:,}</td></tr>" for o in ORG)
    org_tables = ""
    for o in ORG:
        df = org_table(card, o)
        head = "".join(f"<th>{e(str(c))}</th>" for c in df.columns)
        body = "".join("<tr>" + "".join(f"<td>{e(str(v))}</td>" for v in r) + "</tr>" for r in df.itertuples(index=False))
        tr = card["companies"][o].get("trace") or {}
        trace = (f"<p class='small'>Tracing: traced {tr['traced'] * 100:.1f}% against guessing {tr['guessing'] * 100:.1f}%; gain {tr['advantage'] * 100:+.1f} points, "
                 f"95% range between {tr['lo'] * 100:+.1f} and {tr['hi'] * 100:+.1f}; {tr['sources']} hosts; shuffle test p = {tr['p_value']:.3f}.</p>" if "traced" in tr else
                 f"<p class='small'>Tracing: {e(tr.get('skipped', 'not measured'))}.</p>")
        org_tables += (f"<h3>{e(card['companies'][o]['name'])}, withheld attack type {e(card['companies'][o]['never_seen'])}, {card['companies'][o]['test_rows']:,} test records</h3>"
                       f"<p class='small'>{e(attack_line(card['companies'][o]['never_seen']))}</p>"
                       f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>{trace}")

    def hyp(name, h, what):
        if not h:
            return f"<p><b>{name}</b> {what}: not measured.</p>"
        return (f"<p><b>{name}</b> {what}: {h['gain'] * 100:+.1f} points, 95% range [{h['lo'] * 100:+.1f}, {h['hi'] * 100:+.1f}]. "
                f"Rule: the whole range above 5 points. Result: <b>{'supported' if h['clears'] else 'not supported'}</b>.</p>")
    h3 = Hy.get("H3")
    h3txt = (f"<p><b>H3</b> tracing: sanitized attack records were traced above the majority-host guess in {'all' if h3['yes'] else 'not all'} {h3['companies']} organizations tested "
             f"(gain over guessing from {h3['low'] * 100:+.1f} to {h3['high'] * 100:+.1f} points). Result: <b>{'supported' if h3['yes'] else 'not supported'}</b>.</p>" if h3
             else f"<p><b>H3</b> tracing: {e(Hy.get('H3_note') or 'not measured')}.</p>")
    ch = card["checks"]
    b = card.get("budget") or {}
    return f"""<!doctype html><html><head><meta charset='utf-8'><title>{TOOL} report: {e(card['name'])}</title>
<style>body{{font-family:Inter,-apple-system,'Segoe UI',Helvetica,Arial,sans-serif;color:#0b1530;max-width:1040px;margin:30px auto;padding:0 20px;line-height:1.5}}
h1{{font-size:1.9rem;margin-bottom:4px;letter-spacing:-.02em}} h2{{font-size:1.15rem;color:#0d9488;margin-top:28px;border-bottom:2px solid #e5e9f2;padding-bottom:4px}} h3{{font-size:1rem;margin-top:18px}}
table{{border-collapse:collapse;width:100%;font-size:0.82rem;margin:8px 0}} th{{text-align:left;background:#f8fafd;padding:6px 8px;border-bottom:1px solid #e5e9f2}} td{{padding:5px 8px;border-bottom:1px solid #f0f3f8}}
.small{{font-size:0.85rem;color:#334155}} .box{{background:#ecfdf8;border:1px solid #b6efe3;padding:10px 14px;border-radius:10px}} .muted{{color:#64748b;font-size:0.8rem}}
@media print{{body{{margin:10px}} h2{{break-after:avoid}}}}</style></head><body>
<h1>{TOOL} report</h1><div class='muted'>{e(card['name'])}. Generated {e(time.strftime('%d %B %Y, %H:%M'))}. {e(card.get('computed', ''))} Local run of the tool.</div>
<p>{e(card.get('about', ''))}</p>
<h2>Step 1. Three organizations and their withheld attack types</h2>
<table><thead><tr><th>Organization</th><th>Hosts</th><th>Training records</th><th>Withheld attack type</th><th>Taken out</th><th>Trains on</th><th>Test records of the withheld type</th></tr></thead><tbody>{rows1}</tbody></table>
<p class='small'>Organizations: {e(card['rules']['companies'])}. Split: {e(card['rules']['split'])}.</p>
<h2>Step 2. Sanitizing</h2><p>{card['step2']['raw_columns']} columns in the raw data. Kept: {card['step2']['kept_numbers']} behavior numbers and the attack type. Removed: {card['step2']['removed']} columns.</p>
<p class='small'>Kept: {e(', '.join(card['step2'].get('kept', [])))}</p><p class='small'>Removed: {e(', '.join(card['step2'].get('removed_columns', [])))}</p>
<h2>Steps 3 and 4. Four training conditions, tested on the withheld attack type</h2>
<p class='small'>Network {e(card['rules']['network'])}; {card['rules']['passes']} passes of the largest organization at batch {card['rules']['batch']}; alarm rule: 95th percentile of the organization's own normal validation scores;
federated learning {card['checks']['rounds']} rounds of {card['rules']['local_epochs']} local passes; seeds {len(card['seeds'])}; tracing {b.get('trace_seeds')} forests of {b.get('trace_trees')} trees, shuffle test {b.get('trace_permutations')} shuffles. Budget: {e(str(b.get('name')))}.</p>
{org_tables}
<h2>Step 5. Scorecard</h2>
{hyp('H1', Hy.get('H1'), 'sanitized attack-record sharing, mean gain in attack-class recall over the three organizations')}
{hyp('H2', Hy.get('H2'), 'federated learning, mean gain in attack-class recall over the three organizations')}
{h3txt}
<p class='small'>Separate checks: centralized training against isolated training {e(pts(ch.get('pooled')))} points; flagging only (attack or not, type ignored) sharing {e(pts(ch['flagged']['H1']))}, federated {e(pts(ch['flagged']['H2']))};
{('nothing withheld: sharing ' + e(pts(ch['nothing_withheld']['H1'])) + ', federated ' + e(pts(ch['nothing_withheld']['H2'])) + '.') if ch.get('nothing_withheld') else 'nothing-withheld check: not measured.'}</p>
<div class='box'><b>The decision rule.</b> Gain: the low end of the 95% range of the gain in attack-class recall must be above 5 points. False positives: the false-positive rate may rise by at most 1 point over isolated training.
Privacy (sharing): if the gain is met but sanitized records are traced above the majority-host guess, the result is a trade-off. Data sent is reported, not judged.</div>
<p class='muted'>{TOOL}, built on the praxis procedure of Rayve Malhotra (George Washington University, SEAS 8499). Sanitized means direct identifiers removed, nothing more. The study claims rest on the DataSense dataset alone; every other dataset shows that the procedure runs on new data with the tool's own split. Fingerprint sharing, where shown, is experimental and not a praxis training condition.</p>
</body></html>"""


def download_buttons(card, key):
    c0, c1, c2 = st.columns(3)
    c0.download_button("Download the report (HTML, print to PDF)", report_html(card), file_name=f"threatprint_report_{key}.html", mime="text/html", key=f"dl_html_{key}", type="primary", use_container_width=True)
    c1.download_button("Download the scorecard (JSON)", json.dumps(card, indent=1, default=float), file_name=f"threatprint_{key}.json", mime="application/json", key=f"dl_json_{key}", use_container_width=True)
    tbl = pd.concat([org_table(card, o).assign(Organization=card["companies"][o]["name"]) for o in ORG])
    c2.download_button("Download the tables (CSV)", tbl.to_csv(index=False), file_name=f"threatprint_{key}_tables.csv", mime="text/csv", key=f"dl_csv_{key}", use_container_width=True)


# ---------------------------------------------------------------- navigation pieces
PG = {}
NAV = [("start", "Overview"), ("results", "Results"), ("evaluate", "Evaluate"), ("sanitize", "Sanitize"), ("agent", "Agent"),
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
        cols = st.columns([2.5, 1.15, 1.0, 1.1, 1.05, 0.9, 1.15, 1.55, 1.1, 1.1])
        with cols[0]:
            H(ui.logo())
        for col, (key, label) in zip(cols[1:], NAV):
            with col:
                if key == current:
                    with st.container(key=f"tp_on_{key}"):
                        st.page_link(PG[key], label=label)
                else:
                    st.page_link(PG[key], label=label)


def footer():
    H(f"<div class='tp-footer'><div>{ui.logo()}<div style='margin-top:8px;max-width:520px'>{ui.TAGLINE} Built on the procedure of a George Washington University doctoral praxis "
      f"by Rayve Malhotra (SEAS 8499). AI-assisted engineering; the study design, protocol and decisions are the author's.</div></div>"
      f"<div style='text-align:right'><b>{TOOL}</b> {VERSION}<br>Nothing you upload is stored.<br>Sanitized means direct identifiers removed, nothing more.</div></div>")


def sub_hero(eyebrow, title, lead, right=""):
    cls = "tp-hero sub" + ("" if right else " single")
    H(f"<div class='{cls}'><div class='grid'><div><span class='tp-eyebrow'>{esc(eyebrow)}</span><h1>{title}</h1><p class='lead'>{lead}</p></div>{f'<div>{right}</div>' if right else ''}</div></div>")


# ---------------------------------------------------------------- pages
def page_start():
    cards = load_cards()
    r = RUN_OF_RECORD["recall"]["B"]
    shot = (f"<div class='tp-shot'><div class='t'>DataSense · run of record</div><div class='n'>Organization B, cameras · DDoS withheld</div>"
            + ui.bars([(SHORT[k], r[k] / 100.0, ui.COND[k], False) for k in ROADS], width=360)
            + f"<div style='display:flex;gap:6px;flex-wrap:wrap;margin-top:6px'>{ui.badge('sharing: gain met, privacy trade-off', 'warn')}{ui.badge('federated: gain met', 'ok')}</div></div>"
            f"<div class='tp-float'>Tracing, run of record: <b>41.2%</b> of B's sanitized records traced to their device, against <b>16.9%</b> by guessing</div>")
    with st.container(key="tp_hero"):
        c1, c2 = st.columns([1.1, 0.9], gap="large")
        with c1:
            H("<span class='tp-eyebrow'>Collaborative defense, measured</span>"
              "<h1>Know what sharing buys.<br><em>Know what it exposes.</em></h1>"
              f"<p class='lead'>{TOOL} measures, on your own intrusion records, what working with other organizations would add to your detection of attack types you have not trained on, "
              "and what it would give away. Four training conditions, one scorecard, one decision rule.</p>")
            b1, b2, _ = st.columns([1, 1.45, 0.25])
            with b1:
                link("evaluate", "Evaluate your data", "cta_onhero")
            with b2:
                link("results", f"See the results on {len(cards)} datasets", "cta_dark", "hero")
            H("<div class='tp-trust'><span><i></i>Built on a GWU doctoral praxis</span><span><i></i>MITRE ATT&CK v20.1</span><span><i></i>Runs inside your network</span></div>")
        with c2:
            H(shot)
    ui.stats([(f"{len(cards)}", "datasets run with the protocol budget, the praxis dataset among them", ""),
              ("4", "training conditions: same network, same training budget, same alarm rule", "indigo"),
              ("11", "attack families mapped to MITRE ATT&CK v20.1, Enterprise and ICS", "amber"),
              ("0", "records leave your network when you use the local agent", "ink")])

    ui.section("How it works", "Five steps on any labeled table of network or device records",
               "Three organizations each run an intrusion detector. Each one has an attack type it has not trained on: its <b>withheld attack type</b>. The other two have seen it. "
               "Does working together let each organization catch and name that attack, and what does it give away in return?")
    steps = [("orgs", "Make three organizations", "Hosts or devices are split into organizations A, B and C. One attack type is withheld from each organization's own training records."),
             ("filter", "Sanitize", "Keep the behavior numbers and the attack type. Remove device names, addresses, ports, time stamps and other labels. Sanitized means direct identifiers removed, nothing more."),
             ("chip", "Train under four training conditions", "Isolated training, sanitized attack-record sharing, federated learning and centralized training, with the same network, budget and alarm rule."),
             ("target", "Test on the withheld attack type", "Was it flagged as an attack, and was it named with the right attack type? That share is the attack-class recall."),
             ("chart", "Read the scorecard", "Gain against isolated training with a 95% range, false-positive rate, data sent, and whether sanitized records can be traced to their source host.")]
    ui.grid([ui.card_html(t, x, ico, ["", "", "indigo", "amber", "ink"][i], no=i + 1) for i, (ico, t, x) in enumerate(steps)])

    ui.section("The comparison", "Four training conditions, one detector design",
               "Every organization trains the same detector four times. Only what it learns from changes.")
    conds = [("isolated", "Isolated training", "The baseline. The detector learns from the organization's own records only. Nothing travels."),
             ("sharing", "Sanitized attack-record sharing", "Own records plus the peers' sanitized attack records. Records travel; identifiers do not."),
             ("federated", "Federated learning", "Own records only. After each round the model weights are averaged into one shared detector. No records travel."),
             ("centralized", "Centralized training", "The reference. One detector trained on every organization's training records in one place.")]
    ui.grid([f"<div class='tp-card'>{ui.cond_diagram(kind)}<h5>{esc(t)}</h5><p>{x}</p></div>" for kind, t, x in conds])

    ui.section("The verdict", "A decision rule, not an opinion", "A collaboration method is worth it for an organization when it clears three checks. Data sent is reported, not judged.")
    rule = [("scale", "Gain", "The low end of the 95% range of the recall gain must be above 5 points.", ""),
            ("target", "False positives", "The false-positive rate may rise by at most 1 point over isolated training.", "indigo"),
            ("lock", "Privacy", "If sanitized records can be traced to their source host above the majority-host guess, the gain comes with a privacy trade-off.", "amber")]
    ui.grid([ui.card_html(t, x, ico, tone) for ico, t, x, tone in rule])

    ui.section("Start anywhere", "Three ways in")
    ways = [("results", "chart", "See the evidence", f"The praxis dataset, the ranking check and public intrusion datasets, {len(cards)} in all, run through the same procedure with the protocol budget.", "Open the results"),
            ("evaluate", "upload", "Evaluate your own data", "Upload a CSV with a label column. The tool suggests which columns are identifiers, you confirm, and it runs the four training conditions and draws the scorecard.", "Evaluate your data"),
            ("agent", "print", "Share only a fingerprint", "Run the local agent on your own machine. It sanitizes, maps your attack types to MITRE ATT&CK and writes a fingerprint: summary statistics, no records.", "Get the agent")]
    ui.grid([ui.card_html(t, x, ico, "ink") for _, ico, t, x, _ in ways])
    for col, (key, _, _, _, cta) in zip(st.columns(3, gap="small"), ways):
        with col:
            link(key, cta, "cta_light", "ways")

    ui.section("Limits", "Stated plainly")
    H("<div class='tp-note'>"
      "<p>The study claims rest on the DataSense dataset alone. Every other dataset, and every upload, shows that the procedure runs on new data; the splits are the tool's own and are not audited.</p>"
      "<p>Removing identifiers does not stop tracing. On DataSense, sanitized attack records were traced to their source device 41% to 55% of the time against 7% to 35% by guessing. The tool measures this for your data when a host column exists.</p>"
      "<p>A quick look uses a smaller training budget than the protocol. It shows whether your data works in the tool; the protocol run is the one to report.</p>"
      "<p>The tool does not store uploads. Everything runs in the session and is gone when the page closes. Do not upload data you are not allowed to process.</p></div>")


def page_results():
    cards = load_cards()
    sub_hero("Results", f"{len(cards)} datasets, one procedure",
             "The praxis dataset, the ranking check and public intrusion datasets, each run with the protocol budget: three organizations, one withheld attack type each, four training conditions. "
             "Only DataSense carries the praxis claims; every other row is a local run of the tool on its own split.")
    if not cards:
        st.warning("No result files found.")
        return
    h1_ok = sum(1 for c in cards if c["hypotheses"]["H1"]["clears"])
    h2_ok = sum(1 for c in cards if c["hypotheses"]["H2"]["clears"])
    h3_ok = sum(1 for c in cards if c["hypotheses"].get("H3") and c["hypotheses"]["H3"]["yes"])
    h3_n = sum(1 for c in cards if c["hypotheses"].get("H3"))
    ui.stats([(f"{len(cards)}", "datasets run with the protocol budget", "ink"),
              (f"{h1_ok}<small> of {len(cards)}</small>", "H1 supported: sanitized attack-record sharing clears the 5-point rule", ""),
              (f"{h2_ok}<small> of {len(cards)}</small>", "H2 supported: federated learning clears the 5-point rule", "indigo"),
              (f"{h3_ok}<small> of {h3_n}</small>", "tracing above guessing in all three organizations, where it could be tested", "amber")])

    ui.section("Gain against isolated training", "How much each method added, dataset by dataset",
               "Mean gain in attack-class recall on the withheld attack types over the three organizations, with its 95% range. A method clears the rule when its whole range lies to the right of the dashed line. "
               "Local runs of the tool, not the run of record.")
    series = [("sha", "Sanitized attack-record sharing", ui.TEAL), ("fed", "Federated learning", ui.INDIGO), ("fp", "Fingerprint sharing (experimental, not a praxis condition)", ui.AMBER)]
    H(ui.legend([(l, c) for _, l, c in series]))
    rows = []
    order = sorted(cards, key=lambda c: ({"the study": 0, "ranking check": 1}.get(c.get("study_role"), 2), -c["hypotheses"]["H1"]["gain"]))
    for c in order:
        Hy, e = c["hypotheses"], exp_of(c)
        vals = {"sha": tuple(Hy["H1"][k] * 100 for k in ("gain", "lo", "hi")), "fed": tuple(Hy["H2"][k] * 100 for k in ("gain", "lo", "hi"))}
        if e:
            vals["fp"] = tuple(e["mean_gain"][k] * 100 for k in ("gain", "lo", "hi"))
        role = c.get("study_role", "")
        rows.append(dict(name=c["name"], tag=(role if role in ("the study", "ranking check") else ""), strong=(role == "the study"), vals=vals))
    H(ui.forest(rows, series))
    st.caption("Hover a dot for its numbers. Only DataSense carries the praxis claims; the praxis runs of record are "
               f"DataSense H1 {RECORD['datasense']['H1']}, H2 {RECORD['datasense']['H2']} and Edge-IIoTset H1 {RECORD['edge_iiotset']['H1']}, H2 {RECORD['edge_iiotset']['H2']}, with the same decisions. "
               "Where a dataset has no clock the split is random and the ranges are optimistic.")

    ui.section("By attack family", "Which attack families transfer",
               "Mean attack-class recall on the withheld attack type, grouped by the MITRE ATT&CK family of that type, under each training condition. A case is one organization in one dataset. "
               "Local runs of the tool, not the run of record.")
    fs = family_stats(cards)
    rows = [{"Attack family of the withheld type": r.family, "MITRE ATT&CK": r.techniques, "Cases": int(r.cases),
             "Isolated training": ui.heat(r.iso), "Sanitized attack-record sharing": ui.heat(r.sha), "Federated learning": ui.heat(r.fed), "Centralized training": ui.heat(r.cen),
             "Fingerprint sharing (experimental)": ui.heat(r.fp, exp=True)} for r in fs.itertuples()]
    ui.table(pd.DataFrame(rows), wrap=("Attack family of the withheld type", "MITRE ATT&CK"),
             raw=("Isolated training", "Sanitized attack-record sharing", "Federated learning", "Centralized training", "Fingerprint sharing (experimental)"))
    st.caption("Local runs of the tool, not the run of record. Families and techniques are the tool's mapping of each dataset's own labels (MITRE ATT&CK v20.1, Enterprise and ICS); a suggestion, not a ruling. "
               "Fingerprint sharing is experimental and not a praxis training condition.")

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
            rows.append({"Dataset": c["name"], "Role": c.get("study_role", "tool test") + ", local run",
                         "H1 sanitized attack-record sharing (points, 95% range)": pts(Hy["H1"]) + " " + ui.badge("supported" if Hy["H1"]["clears"] else "not supported", "ok" if Hy["H1"]["clears"] else "no"),
                         "H2 federated learning (points, 95% range)": pts(Hy["H2"]) + " " + ui.badge("supported" if Hy["H2"]["clears"] else "not supported", "ok" if Hy["H2"]["clears"] else "no"),
                         "H3 records traced above guessing": (ui.badge("yes, all organizations", "ok") if h3 and h3["yes"] else (ui.badge("not all", "no") if h3 else ui.badge("not tested"))),
                         "Seeds": len(c["seeds"])})
        ui.table(pd.DataFrame(rows), wrap=("Dataset",),
                 raw=("H1 sanitized attack-record sharing (points, 95% range)", "H2 federated learning (points, 95% range)", "H3 records traced above guessing"))
        st.caption("H1 and H2: mean gain in attack-class recall on the withheld attack types over the three organizations, against isolated training; supported when the whole 95% range is above 5 points. "
                   f"Local run = this tool's rerun on another machine; the praxis runs of record are DataSense H1 {RECORD['datasense']['H1']}, H2 {RECORD['datasense']['H2']} "
                   f"and Edge-IIoTset H1 {RECORD['edge_iiotset']['H1']}, H2 {RECORD['edge_iiotset']['H2']}, with the same decisions.")


def _confirm_columns(df, ins, key):
    """Let the user confirm the roles the tool guessed. Returns the settings dict and the kept numbers."""
    cols = list(df.columns)
    none = "(none)"
    c1, c2 = st.columns(2)
    label_col = c1.selectbox("Label column (the attack type or normal)", cols, index=cols.index(ins["label_col"]) if ins["label_col"] in cols else 0, key=f"{key}_label")
    values = df[label_col].astype(str).str.strip().value_counts()
    benign = c2.selectbox("Which label value means normal traffic", list(values.index),
                          index=list(values.index).index(ins["benign_label"]) if (label_col == ins["label_col"] and ins["benign_label"] in values.index) else 0, key=f"{key}_benign")
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
    return cfg, numbers


def _before_after(df, cfg, numbers):
    """One record before and after sanitizing."""
    attack = df[df[cfg["label_col"]].astype(str).str.strip() != str(cfg["benign_label"])]
    row = (attack if len(attack) else df).iloc[0]
    rows = []
    for c in df.columns:
        kept = c in numbers or c == cfg["label_col"]
        rows.append({"Column": c, "Before (as recorded)": str(row[c])[:40],
                     "After sanitizing (what a peer receives)": (f"<td>{esc(str(row[c])[:40])}</td>" if kept else f"<td>{ui.badge('removed', 'no')}</td>")})
    ui.table(pd.DataFrame(rows), raw=("After sanitizing (what a peer receives)",))


def _read_upload(up):
    name = up.name.lower()
    if name.endswith(".parquet"):
        return pd.read_parquet(up)
    return pd.read_csv(up, low_memory=False)


def _step_head(no, title, text=""):
    sub = f"<div style='color:{ui.MUTED};font-size:.9rem'>{text}</div>" if text else ""
    H(f"<div style='display:flex;gap:12px;align-items:center;margin:26px 0 8px 0'><span style='width:30px;height:30px;border-radius:50%;background:{ui.INK};color:#fff;display:inline-flex;"
      f"align-items:center;justify-content:center;font-weight:800;font-size:.9rem'>{no}</span><div><div style='font-weight:800;font-size:1.12rem;color:{ui.INK}'>{esc(title)}</div>"
      f"{sub}</div></div>")


def page_evaluate():
    sub_hero("Evaluate", "Run the evaluation on your own records",
             "Upload a table where each row is one record (a flow, a packet summary or a time window) with a label column that names the attack type or says normal. "
             "The tool suggests the roles of the columns; you confirm them. Nothing is stored.")
    _step_head(1, "Bring a table", "A CSV or Parquet file with one header row, or the built-in example.")
    src = st.radio("Data", ["Upload a CSV or Parquet file", "Use the built-in example (made-up data, for trying the tool)"], horizontal=True, key="ev_data", label_visibility="collapsed")
    df = None
    if src.startswith("Upload"):
        up = st.file_uploader("CSV or Parquet, one header row", type=["csv", "parquet"], key="ev_upload", label_visibility="collapsed")
        if up is not None:
            try:
                df = _read_upload(up)
            except Exception as e:
                st.error(f"The file could not be read: {e}")
                return
    else:
        df = engine.example_data()
        st.caption("The example is synthetic: 30 hosts, six attack types, 6,600 records. It says nothing about real attacks; it shows how the tool works.")
    if df is None:
        st.info("Waiting for a file. No file at hand? The Agent page has two sample organization files to download.")
        last = st.session_state.get("ev_card")
        if last:
            ui.section("This session", "Your last scorecard", "The run you made earlier in this session. It is gone when the page closes.")
            show_card(last, heading=False)
            download_buttons(last, "your_data")
        return
    H(f"<div style='margin:8px 0'>{ui.chip(f'{len(df):,} records', 'dark')}{ui.chip(f'{df.shape[1]} columns')}</div>")
    with st.expander("Opening rows of the table"):
        st.dataframe(df.head(5), hide_index=True, use_container_width=True)
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
    budget = engine.QUICK if budget_name.startswith("Quick") else engine.PROTOCOL
    if budget is engine.PROTOCOL and len(df) > 150_000:
        st.warning(f"{len(df):,} records. The protocol run will sample 150,000 records by class so that the run finishes in a public host's memory.")
        budget = engine.Budget(**{**engine.PROTOCOL.__dict__, "max_rows": 150_000})
    trace_on = st.checkbox("Run the tracing test (H3) when a host column exists", value=True, key="ev_trace")
    if not trace_on:
        budget = engine.Budget(**{**budget.__dict__, "do_trace": False})

    if st.button("Run the evaluation", type="primary", key="ev_run"):
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
        st.download_button("Download the sanitized table (what a peer would receive, all records)", san.to_csv(index=False), file_name="sanitized.csv", mime="text/csv", key="ev_dl_san")


def page_sanitize():
    sub_hero("Sanitize", "See exactly what would leave",
             "Upload a table and download the version an organization could send to a peer: the behavior numbers and the attack type, with the identifiers removed. "
             "The tool suggests the roles of the columns; you confirm them.")
    up = st.file_uploader("CSV or Parquet, one header row", type=["csv", "parquet"], key="sa_upload", label_visibility="collapsed")
    if up is None:
        st.info("Waiting for a file.")
        return
    try:
        df = _read_upload(up)
    except Exception as e:
        st.error(f"The file could not be read: {e}")
        return
    ins = engine.inspect(df)
    cfg, numbers = _confirm_columns(df, ins, "sa")
    attack_only = st.checkbox("Attack records only (what the praxis sharing condition sends; normal records stay home)", value=True, key="sa_attack_only")
    san = engine.sanitize(df, cfg["label_col"], numbers, attack_only=attack_only, benign_label=cfg["benign_label"])
    removed = [c for c in df.columns if c not in numbers and c != cfg["label_col"]]
    ui.stats([(f"{len(df):,}", "records in your table", "ink"), (f"{len(san):,}", "records in the sanitized table", ""),
              (f"{len(numbers)}", "behavior numbers kept, plus the attack type", "indigo"), (f"{len(removed)}", "columns removed", "amber")])
    H("<div style='margin:16px 0 4px 0;font-weight:700'>Removed</div><div>" + ("".join(ui.chip(c) for c in removed) or "nothing") + "</div>"
      "<div style='margin:10px 0 4px 0;font-weight:700'>Kept</div><div>" + "".join(ui.chip(c, "teal") for c in numbers + [cfg["label_col"]]) + "</div>")
    with st.expander("One record before and after"):
        _before_after(df, cfg, numbers)
    st.warning("What is still exposed: the behavior numbers themselves. A peer that holds reference traffic labeled by host can try to trace a sanitized record "
               "back to its source host from those numbers. On DataSense this worked 41% to 55% of the time against 7% to 35% by guessing. "
               "Use the evaluation page to measure it for your data.")
    st.download_button("Download the sanitized table (CSV)", san.to_csv(index=False), file_name="sanitized.csv", mime="text/csv", key="sa_dl", type="primary")


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
    ("Centralized training", "The reference. One detector trained on every organization's training records in one place."),
    ("Attack-class recall", "Of the test records of the withheld attack type, the share that the detector flagged as an attack and named with the right attack type."),
    ("Flagged", "Of the test records of the withheld attack type, the share the detector called an attack, whatever name it gave."),
    ("False-positive rate", "Of the normal test records, the share the detector called an attack. The alarm threshold is set so that about 5% of the organization's own normal validation records are flagged."),
    ("Gain", "Attack-class recall under a condition minus attack-class recall under isolated training, in percentage points."),
    ("95% range", "The range of the gain over 2,000 resamples of the attack events (bootstrap). An attack event is one attack on one host; records under 15 s apart stay together."),
    ("Attack event", "A run of records of one attack type on one host with gaps under 15 seconds, cut at 300 seconds or 200 records."),
    ("Tracing (H3)", "A receiving peer that holds the sender's normal traffic labeled by host trains a random forest to guess the source host of each sanitized attack record. Scored against always guessing the busiest host."),
    ("Data sent", "Sharing: received records times (4 bytes per number plus 1 byte for the label). Federated learning: model weights, 4 bytes each, two directions, every round. Centralized: each organization's training records sent once."),
    ("Decision rule", "Gain: the low end of the 95% range above 5 points. False positives: a rise of at most 1 point over isolated training. Privacy (sharing): if the gain is met but the records are traced above guessing, the result is a trade-off. Data sent is reported, not judged."),
    ("Fingerprint", "A file of summary statistics per attack type written by the local agent: quantiles and rank correlations of the behavior numbers for groups of at least 50 records. No records, no identifier columns. A summary, not a formal privacy protection."),
    ("MITRE ATT&CK", "A public catalogue of adversary techniques kept by MITRE. The tool maps each dataset's own attack labels to a common attack family and to the closest techniques (v20.1, Enterprise and ICS); a suggestion, not a ruling."),
]


def page_definitions():
    sub_hero("Glossary", "The words, defined once", "Every term the tool uses, in the sense the praxis uses it.")
    q = st.text_input("Search the glossary", "", placeholder="Search, for example: recall, sanitized, tracing", key="gl_q", label_visibility="collapsed")
    shown = [(t, d) for t, d in TERMS if q.lower() in (t + " " + d).lower()]
    if shown:
        ui.grid([f"<div class='tp-card'><h5 style='margin-top:0'>{esc(t)}</h5><p>{esc(d)}</p></div>" for t, d in shown], cols=3)
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
             "The list at the bottom gives public datasets with direct downloads; the results page shows what the tool found on each of them.")
    steps = [("Look at the data", "10 minutes", "Open Evaluate and upload your file. Read the opening rows. Check the columns the tool proposes: which one is the label, which value means normal, which column names the host or device, which column is the clock. Fix anything it got wrong. Open the record shown before and after sanitizing and write down what a peer would receive and what stays home."),
             ("Make the organizations", "5 minutes", "Note how the tool formed organizations A, B and C (groups of hosts, or random thirds when there is no host column), and which attack type each organization has withheld. Write one sentence per organization: what it trains on, and which attack type it has withheld."),
             ("Run a quick look", "5 minutes", "Choose Quick look and run. Read the bars of each organization. Which training condition named the withheld attack type best? Which one raised the false-positive rate? What did each condition send, in bytes?"),
             ("Read the verdicts", "10 minutes", "For each organization and each of the two methods, write whether the gain was met, whether the false-positive limit held, and whether the sanitized records could be traced back to their host above guessing. Is the verdict the same for all three organizations? If not, why not?"),
             ("Run the protocol budget", "20 minutes or more", "Repeat with Protocol run. Compare the 95% ranges with the quick look. Did any verdict change? A quick look is a check; only the protocol run is a result."),
             ("Write five sentences", "10 minutes", "Dataset, organizations, the best condition for each organization, what it cost (false positives, bytes, tracing), and what you would tell an organization that asked whether to share.")]
    ui.grid([f"<div class='tp-card'><div style='display:flex;justify-content:space-between;align-items:center'><span class='no' style='font-size:.72rem;font-weight:800;color:{ui.MUTED};letter-spacing:.1em'>STEP {j}</span>{ui.chip(dur, 'teal')}</div><h5>{esc(t)}</h5><p>{esc(x)}</p></div>"
             for j, (t, dur, x) in enumerate(steps, 1)], cols=3)
    H("<div class='tp-note'><p><b>What to be careful about.</b> The split is the tool's own when a dataset has no clock (random split, optimistic ranges). A dataset with few normal records "
      "gives an unreliable alarm threshold. A dataset with few behavior numbers gives the detector little to work with. The tool reports all of this on the result page; read it before you trust a number.</p></div>")
    ui.section("Data", "Public datasets with a direct download")
    rows = []
    for f in sorted(glob.glob(os.path.join(HERE, "..", "Praxis_Lab_Datasets", "settings", "*.json"))):
        try:
            sdef = json.load(open(f))
        except Exception:
            continue
        info = sdef.get("info", {})
        rows.append({"Dataset": sdef["name"], "Made by": info.get("maker", ""), "Attack types": info.get("attacks", ""),
                     "Host column": info.get("host", ""), "Source": info.get("source", ""), "Licence": info.get("licence", "")})
    if rows:
        ui.table(pd.DataFrame(rows), wrap=("Dataset", "Made by", "Attack types", "Host column", "Source", "Licence"))
    else:
        st.caption("The dataset list is read from the settings files kept next to the install; none were found here. The sources are named on each result page.")
    st.caption("Kaggle and IEEE DataPort releases need a sign-in and are not listed. Every dataset keeps its makers' licence; cite them in anything you write.")


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
             "and writes a small fingerprint file: summary statistics per attack type, no records. You look at the file, and only then decide whether to upload it.", right=TERMINAL)
    ui.grid([ui.card_html(t, x, ico, tone, no=no) for ico, t, x, tone, no in [
        ("term", "Download the agent", "One file, pandas and numpy only, no network code. A security team can read all of it before running it.", "ink", 1),
        ("filter", "Run it on your records", "It prints what it removed, what it kept, the ATT&CK mapping and a readiness check, and writes the fingerprint next to your file.", "", 2),
        ("print", "Upload the fingerprint", "This page checks its integrity digest, shows your attack coverage against the library and tells you whether the full evaluation can run on your data.", "amber", 3)]])
    st.markdown("")
    d1, d2, d3 = st.columns(3)
    d1.download_button("Download the agent (one Python file)", _file_bytes(os.path.join(HERE, "threatprint_agent.py")), file_name="threatprint_agent.py", mime="text/x-python", key="dl_agent", type="primary", use_container_width=True)
    syn = os.path.join(HERE, "samples", "sample_organization_water_utility_SYNTHETIC.csv")
    real = os.path.join(HERE, "samples", "sample_power_grid_dnp3_REAL_CC-BY-4.0.csv")
    if os.path.exists(syn):
        d2.download_button("Sample file: synthetic water utility", _file_bytes(syn), file_name=os.path.basename(syn), mime="text/csv", key="dl_syn", use_container_width=True)
    if os.path.exists(real):
        d3.download_button("Sample file: real DNP3 power-grid flows", _file_bytes(real), file_name=os.path.basename(real), mime="text/csv", key="dl_real", use_container_width=True)
    st.caption("Two files to try the tool with. The water utility is made up by a script (24 devices, 7 attack types, 22,073 records; device names, addresses and operators are invented) and says nothing about real attacks. "
               "The power-grid file is a sample of 10,952 real flows from the DNP3 Intrusion Detection Dataset (Kelli et al., 2022, Zenodo record 7348493, licence CC BY 4.0). "
               "Upload either one on the Evaluate page, or run the agent on it.")

    ui.section("Your fingerprint", "Upload a fingerprint", "A fingerprint file written by the agent (.json). It is checked, read and compared; it is kept only if you choose to contribute it.")
    up = st.file_uploader("A fingerprint file written by the agent (.json)", type=["json"], key="fp_upload", label_visibility="collapsed")
    if up is not None:
        try:
            fp = json.loads(up.getvalue().decode("utf-8"))
        except Exception as e:
            st.error(f"The file could not be read as a fingerprint: {e}")
            fp = None
        if fp is not None and fp.get("format") not in agent.FORMATS:
            st.error(f"This file is not a {TOOL} fingerprint.")
            fp = None
        if fp is not None:
            good = agent.verify(fp)
            if good:
                st.success(f"Integrity digest matches (SHA3-256 {fp['integrity']['digest'][:16]}...). Agent version {fp.get('agent')}, made {fp.get('created')}.")
            else:
                st.error("The integrity digest does not match: the file was changed after the agent wrote it. Nothing below should be relied on.")
            ui.stats([(f"{len(fp.get('classes', {}))}", "attack types in the fingerprint", "ink"), (f"{len(fp.get('features', []))}", "behavior numbers kept", ""),
                      (f"{fp.get('removed_columns_count', 0)}", "columns removed before anything left", "indigo"), (kb(fp.get("payload_bytes", 0)), "calculated payload of the fingerprint", "amber")])
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
            if st.button("Contribute this fingerprint", disabled=not (agree and good), key="fp_contribute"):
                folder = os.path.join(HERE, "contributions")
                os.makedirs(folder, exist_ok=True)
                with open(os.path.join(folder, f"{fp['integrity']['digest'][:16]}.json"), "w") as fh:
                    json.dump(fp, fh, separators=(",", ":"))
                st.success("Kept on the machine that runs this site. Thank you.")
    else:
        st.info("Waiting for a fingerprint file. To make one: download the agent and a sample file above, then run the agent on the sample.")

    ui.section("Inside the file", "What a fingerprint is, and what it is not")
    ui.grid([
          (f"<div class='tp-card'><div class='tp-ico'>{ui.icon('check')}</div><h5>What it holds</h5><p>For every attack type with at least {agent.K_MIN} records: the record count rounded down to the nearest ten, "
          f"{len(agent.GRID)} quantiles (1% to 99%) of every behavior number, and the rank correlations between them. A SHA3-256 integrity digest, and a signature field reserved for a post-quantum signature "
          "(ML-DSA, FIPS 204); signing is designed, not built.</p></div>"),
          (f"<div class='tp-card'><div class='tp-ico amber'>{ui.icon('lock')}</div><h5>What it does not hold, and what it does not promise</h5><p>No rows, no device names, no addresses, no ports, no time stamps, no minimum or maximum values; "
          "normal traffic is not fingerprinted. It is a summary, not a formal privacy protection: no differential privacy is applied, and what a fingerprint reveals about the organization that made it has not been measured.</p></div>")])

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
    H(f"<div class='tp-hero sub single'><div class='grid'><div><span class='tp-eyebrow'>The research behind {TOOL}</span><h1 style='font-size:2.05rem !important;line-height:1.15 !important'>{APPROVED['title']}</h1>"
      "<p class='lead'>Doctor of Engineering praxis, George Washington University, SEAS 8499. Author: Rayve Malhotra. Research advisor: Prof. Fossaceca.</p></div></div></div>")
    ui.section("Problem statement", "The problem")
    H(f"<div class='tp-quote'>{esc(APPROVED['problem_statement'])}</div>")
    ui.section("Thesis", "Thesis (proposed, awaiting advisor approval)")
    H(f"<div class='tp-quote' style='border-left-color:{ui.AMBER}'>{esc(APPROVED['thesis'])}</div>")
    ui.section("Questions and answers", "Research questions, hypotheses and what the study found",
               "Findings are the DataSense run of record (Hex, 11 October 2026, three seeds).")
    res = [("+41.1", "points, 95% range [32.5, 49.6]", "supported"), ("+45.8", "points, 95% range [37.0, 53.9]", "supported"), ("41% to 55%", "traced, against 7% to 35% by guessing", "supported")]
    for i, (big, small, verdict) in enumerate(res, 1):
        H(f"<div class='tp-pair'><div><span class='tag'>RQ{i}</span>{esc(APPROVED[f'RQ{i}'])}</div><div><span class='tag'>H{i}</span>{esc(APPROVED[f'H{i}'])}</div>"
          f"<div class='res'><span class='v'>{big}</span><span style='font-size:.78rem;color:{ui.MUTED}'>{small}</span>{ui.badge(verdict, 'ok')}</div></div>")
    ui.section("Run of record", "What the study found on DataSense, organization by organization",
               "Attack-class recall on the withheld attack type under the four training conditions, and how often a receiving peer traced sanitized attack records to their source device.")
    H(ui.legend([(SHORT[r], ui.COND[r]) for r in ROADS]))
    panels = []
    for o in ORG:
        name, dev, withheld = DATASENSE_ORGS[o]
        r, (tr, gu) = RUN_OF_RECORD["recall"][o], RUN_OF_RECORD["traced"][o]
        panels.append(f"<div class='tp-org'><div style='display:flex;justify-content:space-between;align-items:flex-start'><div class='name'>{name}</div>{ui.badge('run of record', 'ok')}</div>"
                      f"<div class='meta'>{dev}</div><div style='margin-bottom:10px'>{ui.chip('withheld: ' + withheld, 'dark')}</div>"
                      + ui.bars([(SHORT[k], r[k] / 100.0, ui.COND[k], False) for k in ROADS])
                      + "<div style='border-top:1px solid #f0f3f8;margin-top:10px;padding-top:10px'>" + ui.duo(tr / 100.0, gu / 100.0, "traced to the source device", "always guessing the busiest device") + "</div></div>")
    ui.grid(panels)
    st.markdown("")
    ui.stats([("+41.1", "H1: mean gain, sanitized attack-record sharing [32.5, 49.6]", ""), ("+45.8", "H2: mean gain, federated learning [37.0, 53.9]", "indigo"),
              ("41% to 55%", "H3: sanitized records traced to their device (7% to 35% by guessing)", "amber"), ("0.499 to 0.513", "membership test on model weights: no clear signal", "ink")])
    st.markdown("""
Three organizations were made from the DataSense CIC IIoT 2025 testbed by device role: A, network gear (7 devices, DoS withheld); B, cameras (10 devices, DDoS withheld);
C, sensors and plugs (21 devices, MITM withheld). Each organization trained one detector under the four training conditions with the same network, the same training budget
and the same alarm rule, and was tested on its withheld attack type. H1 and H2 were supported: the whole 95% range of the mean gain lies above 5 points.
H3 was supported: a receiving peer holding device-labelled reference traffic traced the sanitized attack records to their source device well above the majority-device guess,
so removing identifiers is not enough on its own. Organization C named none of its withheld MITM records under any condition, which the study reports as it is.
""")
    ui.section("From study to product", f"What {TOOL} adds")
    st.markdown("""
The same procedure, as a service: any organization can run it on its own records without sending them anywhere, and read the answer in the terms of the study, with the
decision rule applied. The results page shows the procedure on the praxis dataset, on the ranking check (Edge-IIoTset) and on public intrusion datasets, so that the method
is judged on more than one source of data. The study claims rest on DataSense alone; every other run is a tool test with the tool's own split.
""")
    st.caption("The problem statement, research questions and hypotheses above are quoted as recorded in the praxis; the thesis is a proposal until the advisor approves it. "
               "The local agent, the MITRE ATT&CK mapping and fingerprint sharing are product research built on the praxis procedure; they are not part of the praxis.")


def page_organizations():
    sub_hero("For organizations", "An evaluation, <em>not a promise</em>",
             "Information-sharing groups ask members to contribute attack data. Federated learning vendors ask them to contribute model updates. "
             f"{TOOL} measures, on your own records, what each would gain in detecting the attack types you have not trained on, what it would cost in false alarms, how many bytes would leave, "
             "and whether a sanitized record could still be traced back to one of your devices.")
    ui.section("What you get", "Before you share, know what it buys and what it exposes")
    ui.grid([ui.card_html(t, x, ico, tone) for ico, t, x, tone in [
        ("chart", "A scorecard in your own terms", "Four training conditions on your data, one withheld attack type per organization, gains with 95% ranges, false-positive rates, data sent, tracing. A report you can hand to a security committee.", ""),
        ("lock", "Nothing leaves your network", "Run the tool on your own machine or inside your network (one container). Uploads to a hosted copy are kept in the browser session only and never stored.", "indigo"),
        ("scale", "A rule, not an opinion", "The decision rule says when a method is worth it: gain low end above 5 points, false positives up by at most 1 point, and a tracing check on what sharing exposes.", "amber")]])
    ui.section("Getting started", "Three ways to use it", "Free during the review period.")
    use = [("evaluate", "Try it here", "Upload a labeled sample, run a quick look, read the scorecard and download the report.", "Evaluate a sample", 1),
           ("agent", "Start with a fingerprint", "Run the local agent on your records and upload only the fingerprint: no records leave your network. You get your MITRE ATT&CK coverage, the gaps against the library and a readiness check.", "Get the agent", 2),
           ("research", "Run it inside your network", "The same tool as a container or a local install (the repository and the Dockerfile are public). Protocol-budget runs on your full records, reports for your records only.", "Read the research", 3)]
    ui.grid([ui.card_html(t, x, None, "", no=no) for _, t, x, _, no in use])
    for col, (key, _, _, cta, _) in zip(st.columns(3, gap="small"), use):
        with col:
            link(key, cta, "cta_light", "org")
    H("<div class='tp-callout' style='margin-top:22px'><b>Who this is for.</b> Operators of industrial and IoT networks (utilities, manufacturing, building systems, healthcare devices) and the groups that ask them to share: "
      "ISACs, sector CERTs, consortia and vendors of federated detection. It answers the question those groups rarely measure: for this member, with this data, is sharing worth it?</div>")

    ui.section("Status", "What is built, and what is designed")
    built = [("Evaluation of four training conditions on your data, with the decision rule", "ok"), ("Sanitizer with one record shown before and after", "ok"),
             ("Local agent: sanitize at home, fingerprint file, SHA3-256 integrity digest", "ok"),
             ("Attack labels mapped to common families and MITRE ATT&CK v20.1 (Enterprise and ICS), identifiers checked against MITRE's published data", "ok"),
             ("Library of public datasets run with the protocol budget, with a table of which attack families transfer", "ok"),
             ("Fingerprint sharing as an experimental fifth arm", "ok")]
    later = [("Measuring what a fingerprint reveals about its sender (tracing and membership tests on fingerprints)", "wait", "designed, not built"),
             ("Post-quantum signature on fingerprints (ML-DSA, FIPS 204) and post-quantum key exchange for uploads (ML-KEM, FIPS 203)", "wait", "designed, not built"),
             ("Differential privacy or other formal protection on what is shared", "no", "not built"), ("Accounts, saved runs, payments", "no", "not built")]
    ui.grid(["<div class='tp-card'><h5 style='margin-top:0'>Built</h5><ul class='tp-list'>" + "".join(f"<li><span class='i ok'>{ui.icon('check', 13, 3)}</span><span>{esc(t)}</span></li>" for t, _ in built) + "</ul></div>",
             "<div class='tp-card'><h5 style='margin-top:0'>Designed or not built</h5><ul class='tp-list'>" + "".join(
                 f"<li><span class='i {k}'>{ui.icon('clock' if k == 'wait' else 'minus', 13, 2.6)}</span><span>{esc(t)} {ui.badge(s, 'amber' if k == 'wait' else 'na')}</span></li>" for t, k, s in later) + "</ul></div>"])

    ui.section("Looking ahead", "Why post-quantum matters here")
    H("<div class='tp-card'>" + ui.timeline([("August 2024", "Standards published", "FIPS 203, 204 and 205|(ML-KEM, ML-DSA, SLH-DSA)"),
                                             ("Today", "Harvest now, decrypt later", "Traffic captured today can be stored|and decrypted once the machines exist"),
                                             ("2030", "Deprecated", "Today's public-key algorithms,|per NIST's transition report IR 8547"),
                                             ("2035", "Disallowed", "The same algorithms,|per the same report")]) + "</div>")
    st.markdown("")
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
    st.markdown("Open an issue or a discussion on the repository: https://github.com/rayvemalhotra/praxis-lab")


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
    import hmac as _hmac
    today = int(time.time() // 86400)
    return any(_hmac.compare_digest(got, _token(pw, d)) for d in (today, today - 1)) if got else False


def _set_cookie(value, max_age=86400):
    import streamlit.components.v1 as components
    components.html(f"<script>document.cookie = 'tp_access={value}; path=/; max-age={max_age}; SameSite=Lax';</script>", height=0)


def gate():
    """Ask for the access password once per browser (a cookie keeps the session for a day). Returns True when the person may use the tool."""
    import hmac
    pw = access_password()
    if not pw:
        return True
    if st.session_state.get("_access_ok"):
        return True
    if not st.session_state.get("_left") and _cookie_ok(pw):     # cookies are read at session start, so a session that left ignores them
        st.session_state["_access_ok"] = True
        return True
    H("<div style='height:7vh'></div>")
    left, right = st.columns([1.2, 1], gap="large", vertical_alignment="center")
    with left:
        H(f"<div class='tp-gate'><div>{ui.logo()}<h1>Know what sharing buys.<br>Know what it exposes.</h1>"
          "<p>A privacy-aware evaluation of collaborative intrusion detection, on your own records.</p>"
          "<ul><li><i>1</i>Four training conditions, one scorecard, one decision rule</li><li><i>2</i>Attack types mapped to MITRE ATT&CK v20.1</li>"
          "<li><i>3</i>A local agent that shares a fingerprint, not your records</li></ul></div>"
          "<div class='foot'>Built on the procedure of a George Washington University doctoral praxis.</div></div>")
    with right:
        with st.container(key="tp_gate_card"):
            H(f"<div style='font-size:.74rem;font-weight:700;letter-spacing:.14em;color:{ui.TEAL};text-transform:uppercase'>Reviewer access</div>"
              f"<div style='font-size:1.6rem;font-weight:800;color:{ui.INK};letter-spacing:-.02em;margin:6px 0 4px 0'>Enter {TOOL}</div>"
              f"<div style='color:{ui.MUTED};font-size:.93rem;margin-bottom:10px'>This site is for people who were given the access password.</div>")
            attempts = int(st.session_state.get("_access_attempts", 0))
            with st.form("access_form", border=False):
                given = st.text_input("Access password", type="password", key="_access_input")
                ok = st.form_submit_button("Enter", use_container_width=True)
            if ok:
                if hmac.compare_digest(given.strip().encode(), pw.encode()):
                    st.session_state["_access_ok"] = True
                    st.session_state["_left"] = False
                    st.session_state["_access_attempts"] = 0
                    _set_cookie(_token(pw))
                    time.sleep(0.4)
                    st.rerun()
                else:
                    attempts += 1
                    st.session_state["_access_attempts"] = attempts
                    time.sleep(min(2 ** attempts, 10))
                    st.error("That password did not match. Ask the person who runs this site for the access password.")
            st.caption("Nothing you upload is stored; every run lives in your browser session and is gone when the page closes.")
    return False


# ---------------------------------------------------------------- run
PAGES = {"start": (page_start, "Overview"), "results": (page_results, "Results"), "evaluate": (page_evaluate, "Evaluate"),
         "sanitize": (page_sanitize, "Sanitize"), "agent": (page_agent, "Agent"), "research": (page_research, "Research"),
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
