"""Praxis Lab: a web tool that runs the praxis evaluation on any labeled intrusion dataset.

    streamlit run app.py

Pages: Start here; Results on the datasets; Evaluate your own data; Sanitize a file; Definitions.
"""
import glob
import io
import json
import math
import os
import time

import numpy as np
import pandas as pd
import streamlit as st

import engine
import praxis_agent as agent
from engine import ORG, ROADS, CONDITION

HERE = os.path.dirname(os.path.abspath(__file__))
_test_page = os.environ.get("PRAXIS_LAB_PAGE")        # the headless tests open one page at a time
RESULTS = os.path.join(HERE, "results")
TOOL = "Praxis Lab"
VERSION = "0.1 (8 November 2026)"

st.set_page_config(page_title=TOOL, layout="wide", initial_sidebar_state="expanded")

CSS = """
<style>
:root { --ink:#13233a; --ink2:#3b4a5e; --muted:#6b7a90; --line:#dfe5ee; --bg:#f5f7fb; --card:#ffffff;
        --navy:#1f4e79; --navy2:#163a5c; --teal:#0f8a8a; --amber:#b7791f; --rose:#b3433f; --mint:#e8f4f2; }
html, body, [data-testid="stAppViewContainer"] { background: var(--bg); }
[data-testid="stAppViewContainer"] .main .block-container { max-width: 1180px; padding-top: 1.2rem; padding-bottom: 3rem; }
h1, h2, h3, h4 { color: var(--ink); letter-spacing: -0.01em; }
h1 { font-size: 2.1rem !important; font-weight: 800 !important; }
h3 { font-size: 1.25rem !important; font-weight: 700 !important; margin-top: 1.4rem !important; }
h4 { font-size: 1.02rem !important; font-weight: 700 !important; color: var(--navy) !important; text-transform: uppercase; letter-spacing: 0.06em; }
p, li { color: var(--ink2); line-height: 1.55; }
[data-testid="stSidebar"] { background: var(--navy2); }
[data-testid="stSidebar"] * { color: #e8eef7 !important; }
[data-testid="stSidebar"] a[data-testid="stSidebarNavLink"] { border-radius: 8px; margin: 2px 0; }
[data-testid="stSidebar"] a[data-testid="stSidebarNavLink"]:hover { background: rgba(255,255,255,0.08); }
[data-testid="stSidebar"] a[data-testid="stSidebarNavLink"][aria-current="page"] { background: rgba(255,255,255,0.16); }
[data-testid="stSidebar"] [data-testid="stSidebarNavSeparator"] { border-color: rgba(255,255,255,0.15); }
[data-testid="stSidebarHeader"] img, [data-testid="stLogo"] { height: 56px !important; max-width: 240px; }
.plab-mark { display:flex; align-items:center; gap:10px; padding: 6px 0 14px 0; }
.plab-mark .word { font-weight: 800; font-size: 1.15rem; letter-spacing: 0.08em; }
.plab-mark .sub { font-size: 0.78rem; opacity: 0.8; margin-top: -2px; }
.plab-hero { background: linear-gradient(135deg, var(--navy2) 0%, var(--navy) 55%, #2b6a9b 100%); color: #fff; border-radius: 18px;
             padding: 38px 40px 34px 40px; margin: 4px 0 22px 0; box-shadow: 0 10px 30px rgba(19,35,58,0.18); }
.plab-hero h1 { color: #fff !important; font-size: 2.5rem !important; margin: 0 0 8px 0 !important; }
.plab-hero .lead { color: #e6eef8; font-size: 1.12rem; max-width: 820px; margin: 0; }
.plab-hero .tag { display:inline-block; background: rgba(255,255,255,0.14); border: 1px solid rgba(255,255,255,0.25); color:#fff;
                  padding: 4px 10px; border-radius: 999px; font-size: 0.78rem; letter-spacing: 0.06em; text-transform: uppercase; margin-bottom: 14px; }
.plab-card { background: var(--card); border: 1px solid var(--line); border-radius: 14px; padding: 18px 20px; height: 100%;
             box-shadow: 0 1px 2px rgba(19,35,58,0.04); }
.plab-card .num { display:inline-flex; width: 30px; height: 30px; border-radius: 50%; background: var(--navy); color:#fff; font-weight: 700;
                  align-items:center; justify-content:center; margin-bottom: 10px; font-size: 0.95rem; }
.plab-card h5 { margin: 0 0 6px 0; font-size: 1.02rem; color: var(--ink); font-weight: 700; }
.plab-card p { margin: 0; font-size: 0.93rem; color: var(--ink2); }
.plab-kpi { background: var(--card); border: 1px solid var(--line); border-left: 5px solid var(--navy); border-radius: 12px; padding: 14px 18px; }
.plab-kpi .v { font-size: 1.9rem; font-weight: 800; color: var(--ink); line-height: 1.1; }
.plab-kpi .l { font-size: 0.82rem; color: var(--muted); text-transform: uppercase; letter-spacing: 0.06em; margin-top: 4px; }
.plab-kpi.teal { border-left-color: var(--teal); } .plab-kpi.amber { border-left-color: var(--amber); } .plab-kpi.rose { border-left-color: var(--rose); }
.plab-callout { background: var(--mint); border-left: 5px solid var(--teal); border-radius: 10px; padding: 14px 18px; margin: 8px 0 14px 0; color: var(--ink2); }
.plab-callout b { color: var(--ink); }
.plab-muted { background: #eef1f6; border-radius: 12px; padding: 16px 20px; color: var(--ink2); font-size: 0.94rem; }
.plab-pill { display:inline-block; padding: 2px 10px; border-radius: 999px; font-size: 0.78rem; font-weight: 600; letter-spacing: 0.03em; }
.plab-pill.ok { background:#e3f3ea; color:#1f6b3a; } .plab-pill.no { background:#fbe9e7; color:#a23b36; } .plab-pill.na { background:#eceff4; color:#5b6878; }
table.plab { border-collapse: separate; border-spacing: 0; width: 100%; font-size: 0.86rem; margin: 0.2rem 0 0.8rem 0; background: var(--card);
             border: 1px solid var(--line); border-radius: 12px; overflow: hidden; }
table.plab th { text-align: left; vertical-align: bottom; font-weight: 700; color: var(--ink2); background: #f0f3f8; border-bottom: 1px solid var(--line);
                padding: 8px 10px; font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.04em; }
table.plab td { border-bottom: 1px solid #edf0f5; padding: 7px 10px; white-space: nowrap; vertical-align: top; color: var(--ink2); }
table.plab tr:last-child td { border-bottom: none; }
table.plab tr:hover td { background: #f8fafd; }
table.plab td.wrap, table.plab th.wrap { white-space: normal; }
div[data-testid="stExpander"] { background: var(--card); border: 1px solid var(--line); border-radius: 12px; }
div[data-testid="stForm"] { background: var(--card); border: 1px solid var(--line); border-radius: 14px; padding: 18px 22px; }
.stButton > button[kind="primary"] { background: var(--navy); border: none; border-radius: 10px; padding: 0.55rem 1.2rem; font-weight: 700; }
.stButton > button[kind="primary"]:hover { background: var(--navy2); }
.stDownloadButton > button[kind="primary"] { background: var(--navy); border: none; font-weight: 700; }
.stButton > button[kind="primary"] p, .stDownloadButton > button[kind="primary"] p { color: #ffffff !important; }
.stDownloadButton > button, .stButton > button { border-radius: 10px; }
div[data-testid="stStatusWidget"] { display: none; }
[data-testid="stSidebar"] .stButton > button { border: 1px solid rgba(255,255,255,0.55); background: rgba(255,255,255,0.08); }
[data-testid="stSidebar"] .stButton > button:hover { background: rgba(255,255,255,0.18); border-color: #fff; }
a[data-testid="stPageLink-NavLink"] { background: var(--card); border: 1px solid var(--line); border-radius: 10px; padding: 8px 14px; }
a[data-testid="stPageLink-NavLink"]:hover { border-color: var(--navy); }
footer { visibility: hidden; }
</style>
"""
st.markdown(CSS, unsafe_allow_html=True)

MARK_SVG = ("<svg width='34' height='34' viewBox='0 0 34 34' xmlns='http://www.w3.org/2000/svg'>"
            "<path d='M17 2 L30 7 V17 C30 25 24 30 17 32 C10 30 4 25 4 17 V7 Z' fill='#ffffff' fill-opacity='0.14' stroke='#ffffff' stroke-width='1.6'/>"
            "<circle cx='17' cy='12' r='2.6' fill='#7fd1c8'/><circle cx='11' cy='21' r='2.6' fill='#7fd1c8'/><circle cx='23' cy='21' r='2.6' fill='#7fd1c8'/>"
            "<path d='M17 14.6 L11 18.4 M17 14.6 L23 18.4 M13.6 21 L20.4 21' stroke='#ffffff' stroke-width='1.4' stroke-linecap='round'/></svg>")


def wordmark():
    st.markdown(f"<div class='plab-mark'>{MARK_SVG}<div><div class='word'>PRAXIS LAB</div>"
                f"<div class='sub'>privacy-aware evaluation of collaborative intrusion detection</div></div></div>", unsafe_allow_html=True)


def kpi(value, label, tone=""):
    st.markdown(f"<div class='plab-kpi {tone}'><div class='v'>{value}</div><div class='l'>{label}</div></div>", unsafe_allow_html=True)


def card(title, text, num=None):
    n = f"<div class='num'>{num}</div>" if num is not None else ""
    st.markdown(f"<div class='plab-card'>{n}<h5>{title}</h5><p>{text}</p></div>", unsafe_allow_html=True)


def pill(text, tone):
    return f"<span class='plab-pill {tone}'>{text}</span>"


def html_table(df, wrap=("Verdict", "Training condition", "Organization", "Withheld attack type"), raw=()):
    """A compact HTML table: numbers never wrap, long text columns do. Columns in `raw` carry HTML (pills)."""
    import html as _h
    cols = list(df.columns)
    out = ["<table class='plab'><thead><tr>"]
    for c in cols:
        out.append(f"<th class='wrap'>{_h.escape(str(c))}</th>")
    out.append("</tr></thead><tbody>")
    for _, r in df.iterrows():
        out.append("<tr>")
        for c in cols:
            cls = "wrap" if c in wrap else ""
            cell = str(r[c]) if c in raw else _h.escape(str(r[c]))
            out.append(f"<td class='{cls}'>{cell}</td>")
        out.append("</tr>")
    out.append("</tbody></table>")
    st.markdown("".join(out), unsafe_allow_html=True)

# ---------------------------------------------------------------- shared text and helpers
RUN_OF_RECORD = {
    "H1": (41.1, 32.5, 49.6), "H2": (45.8, 37.0, 53.9),
    "recall": {"A": {"1_isolated": 0.0, "2_sharing": 59.9, "3_federated": 57.6, "4_centralized": 65.3},
               "B": {"1_isolated": 0.0, "2_sharing": 63.5, "3_federated": 79.9, "4_centralized": 67.8},
               "C": {"1_isolated": 0.0, "2_sharing": 0.0, "3_federated": 0.0, "4_centralized": 0.0}},
    "fp": {"A": {"1_isolated": 6.99, "2_sharing": 6.15, "3_federated": 4.37, "4_centralized": 7.14},
           "B": {"1_isolated": 6.32, "2_sharing": 6.53, "3_federated": 5.45, "4_centralized": 6.67},
           "C": {"1_isolated": 4.68, "2_sharing": 4.98, "3_federated": 6.53, "4_centralized": 5.47}},
    "note": "The praxis run of record for DataSense (Hex, 11 October 2026, three seeds) reports H1 +41.1 points "
            "[32.5, 49.6] and H2 +45.8 points [37.0, 53.9]. The rerun shown here was computed on another machine; "
            "the decimals differ and every decision is the same.",
}
DATASENSE_NAMES = {"A": "A, network gear", "B": "B, cameras", "C": "C, sensors and plugs"}

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
            c["hypotheses"]["H3_note"] = "not repeated on this dataset (see the note above)"
            c["info"]["role_text"] = ("Used to check that the ranking of the two approaches seen on DataSense holds on different data. The cleaned file has no host column, "
                                      "so organizations are random thirds; tracing was not repeated (normal traffic never goes to one of the two attacked hosts).")
        cards.append(c)
    order = {"the study": 0, "ranking check": 1}
    cards.sort(key=lambda c: (order.get(c.get("study_role"), 2), c["name"]))
    return cards


def org_table(card, o):
    """One organization, all four training conditions. A condition that was not measured says so."""
    c = card["companies"][o]
    v = card.get("verdicts", {}).get(o, {})
    rows = []
    for road in ROADS:
        g = c["gain"].get(road) if road != "1_isolated" else None
        row = {
            "Training condition": SHORT[road],
            "Recall, withheld type": pct(c["named"].get(road)),
            "Flagged": pct(c["flagged"].get(road)),
            "False-positive rate": pct(c["false_alarm"].get(road), 2),
            "Gain vs isolated, this local run [95% range]": "baseline" if road == "1_isolated" else pts(g),
            "Data sent": kb(c.get("bytes", {}).get(road)),
            "Steps": f"{c.get('steps', {}).get(road, 0):,}" if c.get("steps") else "not measured",
            "Verdict": v.get(road, "not measured"),
        }
        if card.get("id") == "datasense":
            rr = RUN_OF_RECORD["recall"][o][road]
            rf = RUN_OF_RECORD["fp"][o][road]
            row["Run of record, recall"] = f"{rr:.1f}%"
            row["Run of record, false-positive rate"] = f"{rf:.2f}%"
        rows.append(row)
    return pd.DataFrame(rows)


RECORD = {  # praxis runs of record, shown next to the tool's own rerun so that nobody mistakes one for the other
    "datasense": {"H1": "+41.1 [+32.5, +49.6]", "H2": "+45.8 [+37.0, +53.9]", "where": "Hex, 11 October 2026"},
    "edge_iiotset": {"H1": "+70.8 [+69.6, +72.0]", "H2": "+61.5 [+60.4, +62.6]", "where": "Hex, 19 October 2026"},
}


def attack_line(label):
    c = agent.classify(label)
    return f"Attack family: {c['family']}. MITRE ATT&CK: {agent.technique_text(c['techniques'])}."


def experimental_table(card, o):
    """All four training conditions and, under them, the experimental fingerprint-sharing arm."""
    exp = (card.get("experimental") or {}).get("fingerprint_sharing")
    if not exp:
        return None
    c, v, r = card["companies"][o], card.get("verdicts", {}).get(o, {}), exp["orgs"][o]
    rows = []
    for road in ROADS:
        rows.append({"Training condition": SHORT[road], "Recall, withheld type": pct(c["named"].get(road)), "False-positive rate": pct(c["false_alarm"].get(road), 2),
                     "Gain vs isolated, this local run [95% range]": "baseline" if road == "1_isolated" else pts(c["gain"].get(road)),
                     "Data sent": kb(c.get("bytes", {}).get(road)), "Verdict": v.get(road, "not measured")})
    rows.append({"Training condition": "Fingerprint sharing (experimental, not a praxis condition)", "Recall, withheld type": pct(r["named"]),
                 "False-positive rate": pct(r["false_alarm"], 2), "Gain vs isolated, this local run [95% range]": pts(r["gain"]),
                 "Data sent": kb(r["bytes"]), "Verdict": r["verdict"]})
    return pd.DataFrame(rows)


def family_stats(cards):
    """Across the library: for each attack family of the withheld attack types, the mean attack-class recall under each condition."""
    rows = []
    for c in cards:
        exp = (c.get("experimental") or {}).get("fingerprint_sharing")
        for o in ORG:
            k = c["companies"][o]
            cl = agent.classify(k["never_seen"])
            rows.append(dict(family=cl["family"], techniques=", ".join(t["id"] for t in cl["techniques"]) or "no mapping",
                             iso=k["named"]["1_isolated"], sha=k["named"]["2_sharing"], fed=k["named"]["3_federated"], cen=k["named"]["4_centralized"],
                             fp=(exp["orgs"][o]["named"] if exp else float("nan"))))
    d = pd.DataFrame(rows)
    default = {}
    for fam, _, ids in agent.FAMILIES:                       # the family's general techniques, not one label's specific one
        default.setdefault(fam, ", ".join(ids))
    d["techniques"] = d["family"].map(lambda f: default.get(f, "no mapping"))
    g = d.groupby("family").agg(cases=("iso", "size"), techniques=("techniques", "first"), iso=("iso", "mean"), sha=("sha", "mean"), fed=("fed", "mean"),
                                 cen=("cen", "mean"), fp=("fp", "mean")).reset_index().sort_values("cases", ascending=False)
    return g


def hypothesis_line(name, h, what, card=None):
    if not h:
        return f"**{name}** {what}: not measured."
    yn = "supported" if h.get("clears") else "not supported"
    rec = RECORD.get((card or {}).get("id"), {})
    tag = (f" This is a local run of the tool, not the run of record; the run of record ({rec['where']}) is {rec[name]} with the same decision."
           if name in rec else " (local run of the tool on the working sample)")
    return f"**{name}** {what}: {h['gain'] * 100:+.1f} points, 95% range [{h['lo'] * 100:+.1f}, {h['hi'] * 100:+.1f}]. Rule: the whole range above 5 points. Result: **{yn}**.{tag}"


def show_card(card, heading=True):
    if heading:
        st.subheader(card["name"])
    if card.get("about"):
        st.caption(card["about"])
    info = card.get("info") or {}
    if info:
        with st.expander("About this dataset"):
            for k, label in (("maker", "Made by"), ("year", "Year"), ("what", "What it is"), ("records", "Records used"),
                             ("attacks", "Attack types"), ("host", "Host or device column"), ("role_text", "Role in the praxis"), ("source", "Source")):
                if info.get(k):
                    st.markdown(f"**{label}.** {info[k]}")
    if card.get("id") == "datasense":
        st.info(RUN_OF_RECORD["note"])
    if card.get("computed"):
        st.caption(card["computed"])
    if card.get("budget", {}).get("name") == "quick":
        st.warning("Quick look: fewer training passes, one seed and fewer resamples than the protocol. "
                   "Use it to see whether the data works in the tool, not to report a result.")

    st.markdown("#### Step 1. Three organizations and their withheld attack types")
    s1 = card["step1"]
    rows = []
    for o in ORG:
        s = s1[o]
        rows.append({"Organization": card["companies"][o]["name"], "Hosts": str(s.get("sources")) if s.get("sources") else "no host column",
                     "Training records": f"{s['train']:,}", "Withheld attack type": s["never_seen"],
                     "Taken out": f"{s.get('withheld', 0):,}", "Trains on": f"{s.get('train_after', s['train']):,}",
                     "of which normal": f"{s.get('train_normal', 0):,}", "of which attack": f"{s.get('train_attack', 0):,}",
                     "Test records of the withheld type": f"{s['test_never_seen']:,}", "Attack events in those": str(s.get("events_never_seen", ""))})
    html_table(pd.DataFrame(rows))
    st.caption(f"Organizations: {card['rules']['companies']}. Split: {card['rules']['split']}.")

    st.markdown("#### Step 2. Sanitizing")
    s2 = card["step2"]
    st.markdown(f"{s2['raw_columns']} columns in the raw data. Kept: {s2['kept_numbers']} behavior numbers and the attack type. "
                f"Removed: {s2['removed']} columns (identifiers, text, other labels).")
    with st.expander("Which columns were kept and which were removed"):
        c1, c2 = st.columns(2)
        c1.markdown("**Kept (behavior numbers)**")
        c1.write(", ".join(s2.get("kept", [])) or "see the dataset settings")
        c2.markdown("**Removed**")
        c2.write(", ".join(s2.get("removed_columns", s2.get("removed_examples", []))) or "see the dataset settings")

    st.markdown("#### Steps 3 and 4. Four training conditions, tested on the withheld attack type")
    st.markdown(f"Same network ({card['rules']['network']}), same training budget ({card['rules']['passes']} passes of the largest organization at batch {card['rules']['batch']}), "
                f"same alarm rule (95th percentile of the organization's own normal validation scores). Federated learning: {card['checks']['rounds']} rounds, "
                f"{card['rules']['local_epochs']} local passes per round. Seeds: {len(card['seeds'])}.")
    b = card.get("budget") or {}
    if b:
        st.caption(f"Tracing test: {b.get('trace_seeds')} random forests of {b.get('trace_trees')} trees on at most {engine.TRACE_MAX:,} records per side; "
                   f"shuffle test {b.get('trace_permutations')} shuffles with {b.get('trace_perm_trees', 100)}-tree forests"
                   + (f" on at most {b['trace_perm_rows']:,} records per side" if b.get('trace_perm_rows') else "") + f". Budget: {b.get('name')}.")
    for o in ORG:
        c = card["companies"][o]
        rerun = " (tool rerun; the run of record is in the last two columns)" if card.get("id") == "datasense" else " (local run of the tool)"
        st.markdown(f"**{c['name']}**, withheld attack type **{c['never_seen']}**, {c['test_rows']:,} test records of that type{rerun}")
        st.caption(attack_line(c["never_seen"]) + (" The table below is a tool rerun, not the run of record." if card.get("id") == "datasense" else " The table below is a local run of the tool."))
        html_table(org_table(card, o))
        local = "Local run of the tool. " if card.get("id") != "datasense" else "Tool rerun. "
        if not c.get("trace"):
            st.caption(local + "Tracing (H3): not measured for this organization.")
        if c.get("trace"):
            t = c["trace"]
            if "traced" in t:
                st.caption(local + f"Tracing (H3): a receiving peer holding this organization's normal traffic labeled by host traced the sanitized attack records "
                           f"to their source host {t['traced'] * 100:.1f}% of the time; always guessing the busiest host gives {t['guessing'] * 100:.1f}%. "
                           f"Gain {t['advantage'] * 100:+.1f} points, 95% range between {t['lo'] * 100:+.1f} and {t['hi'] * 100:+.1f}, {t['sources']} hosts, {t['records']:,} records, shuffle test p = {t['p_value']:.3f}."
                           + (f" Note: {t['note']}." if t.get('note') else ""))
            else:
                st.caption(local + f"Tracing (H3): {t.get('skipped', 'not measured')}.")

    st.markdown("#### Step 5. Scorecard")
    H = card["hypotheses"]
    st.markdown(hypothesis_line("H1", H.get("H1"), "sanitized attack-record sharing, mean gain in attack-class recall over the three organizations", card))
    st.markdown(hypothesis_line("H2", H.get("H2"), "federated learning, mean gain in attack-class recall over the three organizations", card))
    if H.get("H3"):
        h3 = H["H3"]
        st.markdown(f"**H3** tracing: sanitized attack records were traced above the majority-host guess in "
                    f"{'all' if h3['yes'] else 'not all'} {h3['companies']} organizations tested (gain over guessing from {h3['low'] * 100:+.1f} to {h3['high'] * 100:+.1f} points). "
                    f"Result: **{'supported' if h3['yes'] else 'not supported'}**.")
    else:
        st.markdown(f"**H3** tracing: {H.get('H3_note') or 'not measured'}.")
    ch = card["checks"]
    st.markdown("**Separate checks (local run of the tool).** " +
                f"Centralized training against isolated training: {pts(ch.get('pooled'))} points. " +
                f"Flagging only (attack or not, type ignored): sharing {pts(ch['flagged']['H1'])}, federated {pts(ch['flagged']['H2'])}. " +
                (f"Nothing withheld: sharing {pts(ch['nothing_withheld']['H1'])}, federated {pts(ch['nothing_withheld']['H2'])}. " if ch.get("nothing_withheld") else "Nothing-withheld check: not measured. ") +
                f"Membership test on model weights: not measured in this tool.")
    if card.get("id") == "datasense":
        st.caption("Tool rerun above. Run of record for the same checks: centralized +44.4 [+36.6, +51.7]; flagging only sharing -3.5 [-8.9, +0.5], "
                   "federated -4.1 [-10.2, +0.8]; nothing withheld sharing +2.3 [-3.9, +8.2], federated +0.8 [-6.0, +7.7]; "
                   "membership test (separate 10-round run) no clear signal, all six 95% ranges include 0.5.")
    m = card.get("sharing_minus_federated", {}).get("mean")
    if m:
        st.markdown(f"**Sharing minus federated**, same test events: {m['diff'] * 100:+.1f} points, 95% range [{m['lo'] * 100:+.1f}, {m['hi'] * 100:+.1f}].")
    with st.expander("Decision rule used for the verdicts"):
        st.markdown(engine.verdicts.__doc__)
    exp = (card.get("experimental") or {}).get("fingerprint_sharing")
    if exp:
        st.markdown("#### Experimental: fingerprint sharing (not part of the praxis)")
        g = exp["mean_gain"]
        st.markdown(f"Each organization sends a statistical fingerprint of its attack types (quantiles and rank correlations, groups of at least {exp['min_group_size']} records; no records, no model weights). "
                    f"The receiver draws made-up records from its peers' fingerprints and trains with the same budget and alarm rule. "
                    f"Mean gain against isolated training in this local run: {g['gain'] * 100:+.1f} points, 95% range [{g['lo'] * 100:+.1f}, {g['hi'] * 100:+.1f}]. "
                    f"What a fingerprint reveals about its sender has not been measured.")
        for o in ORG:
            st.markdown(f"**{card['companies'][o]['name']}**, withheld attack type **{card['companies'][o]['never_seen']}** (local run of the tool)")
            html_table(experimental_table(card, o))


def report_html(card):
    """A self-contained HTML report of one scorecard (print it to PDF from the browser)."""
    import html as _h
    e = _h.escape
    H = card["hypotheses"]
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
                       f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>{trace}")
    def hyp(name, h, what):
        if not h:
            return f"<p><b>{name}</b> {what}: not measured.</p>"
        return (f"<p><b>{name}</b> {what}: {h['gain'] * 100:+.1f} points, 95% range [{h['lo'] * 100:+.1f}, {h['hi'] * 100:+.1f}]. "
                f"Rule: the whole range above 5 points. Result: <b>{'supported' if h['clears'] else 'not supported'}</b>.</p>")
    h3 = H.get("H3")
    h3txt = (f"<p><b>H3</b> tracing: sanitized attack records were traced above the majority-host guess in {'all' if h3['yes'] else 'not all'} {h3['companies']} organizations tested "
             f"(gain over guessing from {h3['low'] * 100:+.1f} to {h3['high'] * 100:+.1f} points). Result: <b>{'supported' if h3['yes'] else 'not supported'}</b>.</p>" if h3
             else f"<p><b>H3</b> tracing: {e(H.get('H3_note') or 'not measured')}.</p>")
    ch = card["checks"]
    b = card.get("budget") or {}
    return f"""<!doctype html><html><head><meta charset='utf-8'><title>Praxis Lab report: {e(card['name'])}</title>
<style>body{{font-family:-apple-system,'Segoe UI',Helvetica,Arial,sans-serif;color:#13233a;max-width:1000px;margin:30px auto;padding:0 20px;line-height:1.45}}
h1{{font-size:1.8rem;margin-bottom:4px}} h2{{font-size:1.2rem;color:#1f4e79;margin-top:28px;border-bottom:2px solid #dfe5ee;padding-bottom:4px}} h3{{font-size:1rem;margin-top:18px}}
table{{border-collapse:collapse;width:100%;font-size:0.85rem;margin:8px 0}} th{{text-align:left;background:#f0f3f8;padding:6px 8px;border-bottom:1px solid #dfe5ee}} td{{padding:5px 8px;border-bottom:1px solid #edf0f5;white-space:nowrap}}
.small{{font-size:0.85rem;color:#3b4a5e}} .box{{background:#e8f4f2;border-left:5px solid #0f8a8a;padding:10px 14px;border-radius:8px}} .muted{{color:#6b7a90;font-size:0.8rem}}
@media print{{body{{margin:10px}} h2{{break-after:avoid}}}}</style></head><body>
<h1>Praxis Lab report</h1><div class='muted'>{e(card['name'])}. Generated {e(time.strftime('%d %B %Y, %H:%M'))}. {e(card.get('computed', ''))}</div>
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
{hyp('H1', H.get('H1'), 'sanitized attack-record sharing, mean gain in attack-class recall over the three organizations')}
{hyp('H2', H.get('H2'), 'federated learning, mean gain in attack-class recall over the three organizations')}
{h3txt}
<p class='small'>Separate checks: centralized training against isolated training {e(pts(ch.get('pooled')))} points; flagging only (attack or not, type ignored) sharing {e(pts(ch['flagged']['H1']))}, federated {e(pts(ch['flagged']['H2']))};
{('nothing withheld: sharing ' + e(pts(ch['nothing_withheld']['H1'])) + ', federated ' + e(pts(ch['nothing_withheld']['H2'])) + '.') if ch.get('nothing_withheld') else 'nothing-withheld check: not measured.'}</p>
<div class='box'><b>The decision rule.</b> Gain: the low end of the 95% range of the gain in attack-class recall must be above 5 points. False positives: the false-positive rate may rise by at most 1 point over isolated training.
Privacy (sharing): if the gain is met but sanitized records are traced above the majority-host guess, the result is a trade-off. Data sent is reported, not judged.</div>
<p class='muted'>Praxis Lab, built on the praxis procedure of Rayve Malhotra (George Washington University, SEAS 8499). Sanitized means direct identifiers removed, nothing more. The study claims rest on the DataSense dataset alone; every other dataset shows that the procedure runs on new data with the tool's own split.</p>
</body></html>"""


def download_buttons(card, key):
    c0, c1, c2 = st.columns(3)
    c0.download_button("Download the report (HTML, print to PDF)", report_html(card), file_name=f"praxis_lab_report_{key}.html", mime="text/html", key=f"dl_html_{key}", type="primary")
    c1.download_button("Download the scorecard (JSON)", json.dumps(card, indent=1, default=float), file_name=f"praxis_lab_{key}.json", mime="application/json", key=f"dl_json_{key}")
    table = pd.concat([org_table(card, o).assign(Organization=card["companies"][o]["name"]) for o in ORG])
    c2.download_button("Download the four-condition tables (CSV)", table.to_csv(index=False), file_name=f"praxis_lab_{key}_tables.csv", mime="text/csv", key=f"dl_csv_{key}")


# ---------------------------------------------------------------- pages
def page_start():
    st.markdown(f"""<div class='plab-hero'><div class='tag'>George Washington University praxis, SEAS 8499</div>
<h1>Does sharing help, and what does it expose?</h1>
<p class='lead'>Run a privacy-aware evaluation of collaborative intrusion detection on your own data: three organizations, one withheld attack type each,
four training conditions, one scorecard with 95% ranges, false-positive rates, data sent, and whether sanitized records can be traced back to their source.</p></div>""",
                unsafe_allow_html=True)
    if not _test_page:
        c0 = st.columns([1.6, 3])[0]
        c0.page_link(st.Page(page_agent, title="Local agent and fingerprint", url_path="agent"), label="New: run the agent at home, share only a fingerprint", icon=":material/fingerprint:")
        c1, c2, c3, c4 = st.columns([1.3, 1.3, 1.1, 1.2])
        c1.page_link(st.Page(page_results, title="Results on the datasets", url_path="results"), label="See the results on the datasets", icon=":material/table_chart:")
        c2.page_link(st.Page(page_evaluate, title="Evaluate your own data", url_path="evaluate"), label="Evaluate your own data", icon=":material/upload_file:")
        c3.page_link(st.Page(page_research, title="The research", url_path="research"), label="The research", icon=":material/school:")
        c4.page_link(st.Page(page_organizations, title="For organizations", url_path="organizations"), label="For organizations", icon=":material/domain:")
    st.markdown("""
Three organizations each run an intrusion detector. Each one has an attack type it has never trained on: its **withheld attack type**.
The other two organizations have seen that attack. The question is whether working together lets each organization catch and name
the attack it has not seen, and what it gives away in return.
""")
    st.markdown("#### The five steps")
    cols = st.columns(5)
    steps = [("Make three organizations", "Hosts or devices are split into organizations A, B and C. One attack type is withheld from each organization's own training records."),
             ("Sanitize", "Keep the behavior numbers and the attack type. Remove device names, addresses, ports, time stamps and the other label columns. Sanitized means direct identifiers removed, nothing more."),
             ("Train under four training conditions", "Same network, same training budget, same alarm rule: isolated training, sanitized attack-record sharing, federated learning, centralized training."),
             ("Test on the withheld attack type", "Was it flagged as an attack, and was it named with the right attack type (attack-class recall)?"),
             ("Scorecard", "Gain against isolated training with a 95% range, false-positive rate, data sent, and whether the sanitized records can be traced back to their source host.")]
    for i, (col, (t, x)) in enumerate(zip(cols, steps), 1):
        with col:
            card(t, x, num=i)
    st.markdown("#### The four training conditions")
    cols = st.columns(4)
    conds = [("Isolated training", "The baseline. The detector learns from the organization's own records only."),
             ("Sanitized attack-record sharing", "Own records plus the peers' sanitized attack records. Records travel; identifiers do not."),
             ("Federated learning", "Own records only; after each round the model weights are averaged into one shared detector. No records travel."),
             ("Centralized training", "The reference. One detector trained on every organization's training records in one place.")]
    for col, (t, x) in zip(cols, conds):
        with col:
            card(t, x)
    st.markdown("<div class='plab-callout'><b>The decision rule.</b> A collaboration method is worth it for an organization when the low end of the 95% range of its recall gain is above 5 points "
                "and its false-positive rate rises by at most 1 point. If sanitized records can be traced to their source host above the majority-host guess, the gain comes with a privacy trade-off. "
                "Data sent is reported, not judged.</div>", unsafe_allow_html=True)
    st.markdown("#### What you can do here")
    c1, c2, c3 = st.columns(3)
    with c1:
        card("Results on the datasets", "The praxis dataset (DataSense CIC IIoT 2025), the ranking check (Edge-IIoTset) and other public intrusion datasets, all run through the same procedure with the protocol budget.")
    with c2:
        card("Evaluate your own data", "Upload a CSV with a label column. The tool suggests which columns are identifiers, lets you confirm, makes the organizations, runs the four training conditions and shows the scorecard.")
    with c3:
        card("Sanitize a file", "Upload a table and download the sanitized version an organization could send to a peer, with a list of what was removed and what is still exposed.")
    st.markdown("#### Limits, stated plainly")
    st.markdown("""<div class='plab-muted'>
<p>The study claims rest on the DataSense dataset alone. Every other dataset, and every upload, shows that the procedure runs on new data; the splits are the tool's own and are not audited.</p>
<p>Removing identifiers does not stop tracing. On DataSense, sanitized attack records were traced to their source device 41% to 55% of the time against 7% to 35% by guessing. The tool measures this for your data when a host column exists.</p>
<p>A quick look uses a smaller training budget than the protocol. It shows whether your data works in the tool; the protocol run is the one to report.</p>
<p style='margin-bottom:0'>The tool does not store uploads. Everything runs in the session and is gone when the page closes. Do not upload data you are not allowed to process.</p>
</div>""", unsafe_allow_html=True)
    st.caption(f"{TOOL} {VERSION}. Built on the praxis code of Rayve Malhotra, Doctor of Engineering candidate, George Washington University (SEAS 8499). "
               "AI-assisted engineering; the study design, protocol and decisions are the author's.")


def page_results():
    cards = load_cards()
    st.title(f"Results on {len(cards)} datasets")
    if not cards:
        st.warning("No result files found.")
        return
    h1_ok = sum(1 for c in cards if c["hypotheses"]["H1"]["clears"])
    h2_ok = sum(1 for c in cards if c["hypotheses"]["H2"]["clears"])
    h3_ok = sum(1 for c in cards if c["hypotheses"].get("H3") and c["hypotheses"]["H3"]["yes"])
    h3_tested = sum(1 for c in cards if c["hypotheses"].get("H3"))
    k1, k2, k3, k4 = st.columns(4)
    with k1:
        kpi(len(cards), "datasets run with the protocol budget")
    with k2:
        kpi(f"{h1_ok} of {len(cards)}", "H1 sanitized attack-record sharing supported", "teal")
    with k3:
        kpi(f"{h2_ok} of {len(cards)}", "H2 federated learning supported", "teal")
    with k4:
        kpi(f"{h3_ok} of {h3_tested}", "tracing above guessing in all three organizations (where tested)", "amber")
    st.markdown("")
    rows = []
    for c in cards:
        H = c["hypotheses"]
        h3 = H.get("H3")
        rows.append({"Dataset": c["name"], "Role": c.get("study_role", "tool test") + ", local run",
                     "H1 sanitized attack-record sharing (points, 95% range)": pts(H["H1"]) + " " + pill("supported" if H["H1"]["clears"] else "not supported", "ok" if H["H1"]["clears"] else "no"),
                     "H2 federated learning (points, 95% range)": pts(H["H2"]) + " " + pill("supported" if H["H2"]["clears"] else "not supported", "ok" if H["H2"]["clears"] else "no"),
                     "H3 records traced above guessing": (pill("yes, all organizations", "ok") if h3 and h3["yes"] else (pill("not all", "no") if h3 else pill("not tested", "na"))),
                     "Seeds": len(c["seeds"])})
    html_table(pd.DataFrame(rows), wrap=("Dataset",),
               raw=("H1 sanitized attack-record sharing (points, 95% range)", "H2 federated learning (points, 95% range)", "H3 records traced above guessing"))
    st.caption("H1 and H2: mean gain in attack-class recall on the withheld attack types over the three organizations, against isolated training; "
               "supported when the whole 95% range is above 5 points. Only DataSense carries the praxis claims. "
               f"Local run = this tool's rerun on another machine; the praxis runs of record are DataSense H1 {RECORD['datasense']['H1']}, H2 {RECORD['datasense']['H2']} "
               f"and Edge-IIoTset H1 {RECORD['edge_iiotset']['H1']}, H2 {RECORD['edge_iiotset']['H2']}, with the same decisions.")
    st.markdown("#### Which attack families transfer (by MITRE ATT&CK)")
    fs = family_stats(cards)
    rows = [{"Attack family of the withheld type": r.family, "MITRE ATT&CK": r.techniques, "Cases": int(r.cases),
             "Isolated training": pct(r.iso), "Sanitized attack-record sharing": pct(r.sha), "Federated learning": pct(r.fed), "Centralized training": pct(r.cen),
             "Fingerprint sharing (experimental)": pct(r.fp)} for r in fs.itertuples()]
    html_table(pd.DataFrame(rows), wrap=("Attack family of the withheld type", "MITRE ATT&CK"))
    st.caption("Local runs of the tool, not the run of record. A case is one organization in one dataset; the number is the mean attack-class recall on the withheld attack type over the cases of that family. "
               "Families and techniques are the tool's mapping of each dataset's own labels (MITRE ATT&CK v20.1, Enterprise and ICS); a suggestion, not a ruling. "
               "Fingerprint sharing is experimental and not a praxis training condition.")
    names = [c["name"] for c in cards]
    pick = st.selectbox("Open a dataset", names, index=0)
    card = cards[names.index(pick)]
    show_card(card)
    download_buttons(card, card.get("id", "card"))


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
    source_col = c3.selectbox("Host or device column (which machine the record is about; used to form organizations and to test tracing)", src_opts,
                              index=src_opts.index(ins["source_col"]) if ins["source_col"] in src_opts else 0, key=f"{key}_host")
    time_col = c4.selectbox("Time column (used to keep one attack together as an event)", src_opts,
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
        rows.append({"Column": c, "Before (as recorded)": str(row[c])[:40], "After sanitizing (what a peer receives)": (str(row[c])[:40] if kept else "removed")})
    st.dataframe(pd.DataFrame(rows), hide_index=True, use_container_width=True, height=min(600, 38 * (len(rows) + 1)))


def _read_upload(up):
    name = up.name.lower()
    if name.endswith(".parquet"):
        return pd.read_parquet(up)
    return pd.read_csv(up, low_memory=False)


def page_evaluate():
    st.title("Evaluate your own data")
    st.markdown("Upload a table where each row is one record (a flow, a packet summary or a time window) with a label column that names the attack type or says normal. "
                "The tool suggests the roles of the columns; you confirm them. Nothing is stored.")
    src = st.radio("Data", ["Upload a CSV or Parquet file", "Use the built-in example (made-up data, for trying the tool)"], horizontal=True, key="ev_data")
    df = None
    if src.startswith("Upload"):
        up = st.file_uploader("CSV or Parquet, one header row", type=["csv", "parquet"], key="ev_upload")
        if up is not None:
            try:
                df = _read_upload(up)
            except Exception as e:
                st.error(f"The file could not be read: {e}")
                return
    else:
        df = engine.example_data()
        st.caption("The example is synthetic: 30 hosts, six attack types, 6,600 records. It proves nothing about real attacks; it shows how the tool works.")
    if df is None:
        st.info("Waiting for a file.")
        return
    st.markdown(f"**{len(df):,} records, {df.shape[1]} columns.** Opening rows:")
    st.dataframe(df.head(5), hide_index=True, use_container_width=True)
    ins = engine.inspect(df)
    if not ins["label_col"]:
        st.warning("No label column was recognized. Pick it below.")
    st.markdown("#### 1. Confirm the columns")
    cfg, numbers = _confirm_columns(df, ins, "ev")
    with st.expander("One record before and after sanitizing"):
        _before_after(df, cfg, numbers)

    st.markdown("#### 2. Choose the budget")
    budget_name = st.radio("Budget", ["Quick look (about a minute; one seed, 24 passes, 400 resamples)",
                                      "Protocol run (the praxis budget: three seeds, 61 passes, 2,000 resamples; minutes to an hour)"], key="ev_budget")
    budget = engine.QUICK if budget_name.startswith("Quick") else engine.PROTOCOL
    if budget is engine.PROTOCOL and len(df) > 150_000:
        st.warning(f"{len(df):,} records. The protocol run will sample 150,000 records by class so that the run finishes in a public host's memory.")
        budget = engine.Budget(**{**engine.PROTOCOL.__dict__, "max_rows": 150_000})
    trace_on = st.checkbox("Run the tracing test (H3) when a host column exists", value=True, key="ev_trace")
    if not trace_on:
        budget = engine.Budget(**{**budget.__dict__, "do_trace": False})

    if st.button("Run the evaluation", type="primary", key="ev_run"):
        log_box = st.status("Running the five steps", expanded=True)
        lines = []

        def log(m):
            lines.append(m)
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
        st.session_state["ev_card"] = card
    card = st.session_state.get("ev_card")
    if card:
        st.markdown("---")
        show_card(card, heading=False)
        download_buttons(card, "your_data")
        san = engine.sanitize(df, cfg["label_col"], [c for c in card["step2"]["kept"] if c in df.columns])
        st.download_button("Download the sanitized table (what a peer would receive, all records)", san.to_csv(index=False), file_name="sanitized.csv", mime="text/csv", key="ev_dl_san")


def page_sanitize():
    st.title("Sanitize a file")
    st.markdown("Upload a table and download the version an organization could send to a peer: the behavior numbers and the attack type, with the identifiers removed. "
                "The tool suggests the roles of the columns; you confirm them.")
    up = st.file_uploader("CSV or Parquet, one header row", type=["csv", "parquet"], key="sa_upload")
    if up is None:
        st.info("Waiting for a file.")
        return
    try:
        df = _read_upload(up)
    except Exception as e:
        st.error(f"The file could not be read: {e}")
        return
    st.markdown(f"**{len(df):,} records, {df.shape[1]} columns.**")
    ins = engine.inspect(df)
    cfg, numbers = _confirm_columns(df, ins, "sa")
    attack_only = st.checkbox("Attack records only (what the praxis sharing condition sends; normal records stay home)", value=True, key="sa_attack_only")
    san = engine.sanitize(df, cfg["label_col"], numbers, attack_only=attack_only, benign_label=cfg["benign_label"])
    st.markdown(f"**Sanitized table: {len(san):,} records, {san.shape[1]} columns** ({len(numbers)} behavior numbers and the attack type).")
    removed = [c for c in df.columns if c not in numbers and c != cfg["label_col"]]
    c1, c2 = st.columns(2)
    c1.markdown("**Removed**")
    c1.write(", ".join(removed) or "nothing")
    c2.markdown("**Kept**")
    c2.write(", ".join(numbers + [cfg["label_col"]]))
    with st.expander("One record before and after"):
        _before_after(df, cfg, numbers)
    st.warning("What is still exposed: the behavior numbers themselves. A peer that holds reference traffic labeled by host can try to trace a sanitized record "
               "back to its source host from those numbers. On DataSense this worked 41% to 55% of the time against 7% to 35% by guessing. "
               "Use the evaluation page to measure it for your data.")
    st.download_button("Download the sanitized table (CSV)", san.to_csv(index=False), file_name="sanitized.csv", mime="text/csv", key="sa_dl")


def page_definitions():
    st.title("Definitions")
    terms = [
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
    ]
    st.dataframe(pd.DataFrame(terms, columns=["Term", "Meaning in this tool"]), hide_index=True, use_container_width=True, height=38 * (len(terms) + 1))
    st.markdown("#### Where the procedure comes from")
    st.markdown("""
The procedure is the frozen protocol of a George Washington University Doctor of Engineering praxis: *Privacy-Aware Evaluation of Sanitized Attack-Record Sharing and
Federated Learning for Intrusion Detection on Industrial Network Data* (Rayve Malhotra, in progress). The study dataset is DataSense CIC IIoT 2025
(Firouzi, Dadkhah, Maret and Ghorbani, 2025; Canadian Institute for Cybersecurity). The ranking check uses Edge-IIoTset (Ferrag, Friha, Hamouda, Maglaras and Janicke, 2022).
Federated averaging follows McMahan et al. (2017). The other five datasets are public intrusion datasets used to show that the procedure runs on new data; their makers are named on each result page.
""")


def page_students():
    st.title("For students")
    st.markdown("""
A one-hour exercise. You need one labeled intrusion dataset (a CSV with one row per record and a column that names the attack type or says normal).
The list at the bottom gives public datasets with direct downloads; the results page shows what the tool found on each of them.

**1. Look at the data (10 minutes).** Open "Evaluate your own data" and upload your file. Read the opening rows. Check the columns the tool proposes:
which one is the label, which value means normal, which column names the host or device, which column is the clock. Fix anything it got wrong.
Open "One record before and after sanitizing" and write down what a peer would receive and what stays home.

**2. Make the organizations (5 minutes).** Note how the tool formed organizations A, B and C (groups of hosts, or random thirds when there is no host column),
and which attack type each organization has withheld. Write one sentence per organization: what it trains on, and which attack type it has withheld.

**3. Run a quick look (5 minutes).** Choose Quick look and run. Read the four-condition table of each organization. Which condition caught the withheld
attack type best? Which one raised the false-positive rate? What did each condition send, in bytes?

**4. Read the verdicts (10 minutes).** For each organization and each of the two methods, write whether the gain was met, whether the false-positive limit
held, and whether the sanitized records could be traced back to their host above guessing. Is the verdict the same for all three organizations? If not, why not?

**5. Run the protocol budget (20 minutes or more).** Repeat with Protocol run. Compare the 95% ranges with the quick look. Did any verdict change?
A quick look is a check; only the protocol run is a result.

**6. Write five sentences.** Dataset, organizations, the best condition for each organization, what it cost (false positives, bytes, tracing), and what you
would tell an organization that asked whether to share.

**What to be careful about.** The split is the tool's own when a dataset has no clock (random split, optimistic ranges). A dataset with few normal records
gives an unreliable alarm threshold. A dataset with few behavior numbers gives the detector little to work with. The tool reports all of this on the result page;
read it before you trust a number.
""")
    st.markdown("#### Public datasets with a direct download")
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
        html_table(pd.DataFrame(rows), wrap=("Dataset", "Made by", "Attack types", "Host column", "Source", "Licence"))
    else:
        st.caption("The dataset list is read from the settings files in Praxis_Lab_Datasets/settings; none were found next to this install.")
    st.caption("Kaggle and IEEE DataPort releases need a sign-in and are not listed. Every dataset keeps its makers' licence; cite them in anything you write.")


def access_password():
    """The shared access password, from the PRAXIS_LAB_PASSWORD environment variable or .streamlit/secrets.toml
    ([access] password = "..."). No password set = open access (the local install)."""
    if os.environ.get("PRAXIS_LAB_OPEN") == "1":          # a local-only copy for the owner's own machine (bind it to 127.0.0.1)
        return ""
    pw = os.environ.get("PRAXIS_LAB_PASSWORD", "").strip()
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
    return _hmac.new(pw.encode(), f"praxis-lab-{day}".encode(), hashlib.sha256).hexdigest()[:40]


def _cookie_ok(pw):
    try:
        got = st.context.cookies.get("plab_access", "")
    except Exception:
        return False
    import hmac as _hmac
    today = int(time.time() // 86400)
    return any(_hmac.compare_digest(got, _token(pw, d)) for d in (today, today - 1)) if got else False


def _set_cookie(value, max_age=86400):
    import streamlit.components.v1 as components
    components.html(f"<script>document.cookie = 'plab_access={value}; path=/; max-age={max_age}; SameSite=Lax';</script>", height=0)


def gate():
    """Ask for the access password once per browser (a cookie keeps the session for a day). Returns True when the person may use the tool."""
    import hmac
    pw = access_password()
    if not pw:
        return True
    if st.session_state.get("_access_ok"):
        return True
    if not st.session_state.get("_left") and _cookie_ok(pw):     # st.context.cookies is read at session start, so a session that left ignores it
        st.session_state["_access_ok"] = True
        return True
    st.title(TOOL)
    st.markdown("Does sharing help, and what does it expose? Run the praxis evaluation on your own intrusion data. "
                "This site is for people who were given the access password.")
    attempts = int(st.session_state.get("_access_attempts", 0))
    with st.form("access_form"):
        given = st.text_input("Access password", type="password", key="_access_input")
        ok = st.form_submit_button("Enter")
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



def page_research():
    st.title("The research behind the tool")
    st.markdown(f"<div class='plab-callout'><b>{APPROVED['title']}</b><br>Doctor of Engineering praxis, George Washington University, SEAS 8499. Author: Rayve Malhotra. Research advisor: Prof. Fossaceca.</div>", unsafe_allow_html=True)
    st.markdown("#### Problem statement")
    st.markdown(APPROVED["problem_statement"])
    st.markdown("#### Thesis (proposed, awaiting advisor approval)")
    st.markdown(APPROVED["thesis"])
    st.markdown("#### Research questions and hypotheses")
    c1, c2 = st.columns(2)
    with c1:
        card("RQ1", APPROVED["RQ1"])
        st.markdown("")
        card("RQ2", APPROVED["RQ2"])
        st.markdown("")
        card("RQ3", APPROVED["RQ3"])
    with c2:
        card("H1", APPROVED["H1"])
        st.markdown("")
        card("H2", APPROVED["H2"])
        st.markdown("")
        card("H3", APPROVED["H3"])
    st.markdown("#### What the study found on DataSense (run of record)")
    k1, k2, k3, k4 = st.columns(4)
    with k1:
        kpi("+41.1", "H1: mean gain, sanitized attack-record sharing [32.5, 49.6]", "teal")
    with k2:
        kpi("+45.8", "H2: mean gain, federated learning [37.0, 53.9]", "teal")
    with k3:
        kpi("41% to 55%", "H3: sanitized records traced to their device (7% to 35% by guessing)", "amber")
    with k4:
        kpi("0.499 to 0.513", "membership test on model weights: no clear signal", "")
    st.markdown("""
Three organizations were made from the DataSense CIC IIoT 2025 testbed by device role: A, network gear (7 devices, DoS withheld); B, cameras (10 devices, DDoS withheld);
C, sensors and plugs (21 devices, MITM withheld). Each organization trained one detector under the four training conditions with the same network, the same training budget
and the same alarm rule, and was tested on its withheld attack type. H1 and H2 were supported: the whole 95% range of the mean gain lies above 5 points.
H3 was supported: a receiving peer holding device-labelled reference traffic traced the sanitized attack records to their source device well above the majority-device guess,
so removing identifiers is not enough on its own. Organization C named none of its withheld MITM records under any condition, which the study reports as it is.
""")
    st.markdown("#### What this tool adds")
    st.markdown("""
The same procedure, as a service: any organization can run it on its own records without sending them anywhere, and read the answer in the terms of the study, with the
decision rule applied. The results page shows the procedure on the praxis dataset, on the ranking check (Edge-IIoTset) and on public intrusion datasets, so that the method
is judged on more than one source of data. The study claims rest on DataSense alone; every other run is a tool test with the tool's own split.
""")
    st.caption("The problem statement, research questions and hypotheses above are quoted as recorded in the praxis; the thesis is a proposal until the advisor approves it. "
               "The local agent, the MITRE ATT&CK mapping and fingerprint sharing are product research built on the praxis procedure; they are not part of the praxis.")


def page_organizations():
    st.title("For organizations")
    st.markdown("""<div class='plab-hero'><div class='tag'>Before you share, know what it buys and what it exposes</div>
<h1>An evaluation, not a promise</h1>
<p class='lead'>Information-sharing groups ask members to contribute attack data. Federated learning vendors ask them to contribute model updates. Praxis Lab measures, on your own
records, what each would gain in detecting the attack types you have not seen, what it would cost in false alarms, how many bytes would leave, and whether a sanitized record
could still be traced back to one of your devices.</p></div>""", unsafe_allow_html=True)
    st.markdown("#### What you get")
    c1, c2, c3 = st.columns(3)
    with c1:
        card("A scorecard in your own terms", "Four training conditions on your data, one withheld attack type per organization, gains with 95% ranges, false-positive rates, data sent, tracing. A report you can hand to a security committee.")
    with c2:
        card("Nothing leaves your network", "Run the tool on your own machine or inside your network (one container). Uploads to a hosted copy are kept in the browser session only and never stored.")
    with c3:
        card("A rule, not an opinion", "The decision rule says when a method is worth it: gain low end above 5 points, false positives up by at most 1 point, and a tracing check on what sharing exposes.")
    st.markdown("#### Three ways to use it")
    c1, c2, c3 = st.columns(3)
    with c1:
        card("Try it here", "Upload a labeled sample, run a quick look, read the scorecard. Free.", num=1)
    with c2:
        card("Run it inside your network", "The same tool as a container or a local install (the repository and the Dockerfile are public). Protocol-budget runs on your full records, reports for your records only.", num=2)
    with c3:
        card("Start with a fingerprint", "Run the local agent on your records and upload only the fingerprint: no records leave your network. You get your MITRE ATT&CK coverage, the gaps against the library and a readiness check. Free during the review period.", num=3)
    st.markdown("<div class='plab-callout'><b>Who this is for.</b> Operators of industrial and IoT networks (utilities, manufacturing, building systems, healthcare devices) and the groups that ask them to share: ISACs, sector CERTs, consortia and vendors of federated detection. "
                "It answers the question those groups rarely measure: for this member, with this data, is sharing worth it?</div>", unsafe_allow_html=True)
    st.markdown("#### Honest limits")
    st.markdown("""<div class='plab-muted'>
<p>The procedure needs labeled records with at least three attack types, a normal label, and ideally a host or device column and a clock. It evaluates detectors of the study's design; it is not an intrusion detection product itself.</p>
<p>Sanitized means direct identifiers removed, nothing more. The tracing test shows what that leaves exposed; it does not apply differential privacy or any other control.</p>
<p style='margin-bottom:0'>Results on a quick look are a check; the protocol budget is the one to decide on. The study claims rest on DataSense; your data gets its own evidence.</p>
</div>""", unsafe_allow_html=True)
    st.markdown("#### What is built, and what is designed")
    built = [("Evaluation of four training conditions on your data, with the decision rule", "built"),
             ("Sanitizer with one record shown before and after", "built"),
             ("Local agent: sanitize at home, fingerprint file, SHA3-256 integrity digest", "built"),
             ("Attack labels mapped to common families and MITRE ATT&CK v20.1 (Enterprise and ICS), identifiers checked against MITRE's published data", "built"),
             ("Library of public datasets run with the protocol budget, with a table of which attack families transfer", "built"),
             ("Fingerprint sharing as an experimental fifth arm", "built, experimental"),
             ("Measuring what a fingerprint reveals about its sender (tracing and membership tests on fingerprints)", "designed, not built"),
             ("Post-quantum signature on fingerprints (ML-DSA, FIPS 204) and post-quantum key exchange for uploads (ML-KEM, FIPS 203)", "designed, not built"),
             ("Differential privacy or other formal protection on what is shared", "not built"),
             ("Accounts, saved runs, payments", "not built")]
    html_table(pd.DataFrame([{"Capability": b, "Status": s} for b, s in built]), wrap=("Capability",))
    st.markdown("#### Why post-quantum matters here")
    st.markdown("""
Attack records, model updates and fingerprints describe the weak points of industrial equipment that stays in service for fifteen or twenty years. Traffic captured today can be stored and decrypted
later, once a large quantum computer exists, so what organizations exchange about their defenses is exactly the kind of data that needs protection with a long life. NIST published the standards in August 2024:
FIPS 203 (ML-KEM, key exchange), FIPS 204 (ML-DSA, signatures) and FIPS 205 (SLH-DSA, signatures), and its transition report IR 8547 gives 2030 as the date after which today's public-key algorithms are deprecated
and 2035 as the date after which they are disallowed. In this tool the fingerprint already carries a hash-based integrity digest (SHA3-256) and a signature field built to take ML-DSA; the signing itself and a
post-quantum upload channel are designed, not built. Quantum machine learning for detection is not part of the plan: the value is in protecting what is shared, not in a quantum detector.
""")
    st.markdown("#### Contact")
    st.markdown("Open an issue or a discussion on the repository: https://github.com/rayvemalhotra/praxis-lab. The author replies there.")



@st.cache_data(show_spinner=False)
def _file_bytes(path):
    with open(path, "rb") as fh:
        return fh.read()


def page_agent():
    st.title("Local agent and fingerprint")
    st.markdown("""<div class='plab-hero'><div class='tag'>Your records never leave your network</div>
<h1>Run the agent at home. Share only a fingerprint.</h1>
<p class='lead'>The agent is one readable Python file. On your own machine it finds the identifier columns, removes them, maps your attack labels to common attack families
and to MITRE ATT&CK, and writes a small fingerprint file: summary statistics per attack type, no records. You look at the file, and only then decide whether to upload it.</p></div>""",
                unsafe_allow_html=True)
    c1, c2, c3 = st.columns(3)
    with c1:
        card("Download the agent", "One file, pandas and numpy only, no network code. A security team can read all of it before running it.", num=1)
    with c2:
        card("Run it on your records", "python praxis_agent.py my_records.csv. It prints what it removed, what it kept, the ATT&CK mapping and a readiness check, and writes my_records.fingerprint.json.", num=2)
    with c3:
        card("Upload the fingerprint", "This page checks its integrity digest, shows your attack coverage against the library and tells you whether the full evaluation can run on your data.", num=3)
    st.markdown("")
    d1, d2, d3 = st.columns(3)
    d1.download_button("Download the agent (praxis_agent.py)", _file_bytes(os.path.join(HERE, "praxis_agent.py")), file_name="praxis_agent.py", mime="text/x-python", key="dl_agent", type="primary")
    syn = os.path.join(HERE, "samples", "sample_organization_water_utility_SYNTHETIC.csv")
    real = os.path.join(HERE, "samples", "sample_power_grid_dnp3_REAL_CC-BY-4.0.csv")
    if os.path.exists(syn):
        d2.download_button("Sample organization file (synthetic water utility)", _file_bytes(syn), file_name=os.path.basename(syn), mime="text/csv", key="dl_syn")
    if os.path.exists(real):
        d3.download_button("Sample organization file (real power-grid DNP3 flows)", _file_bytes(real), file_name=os.path.basename(real), mime="text/csv", key="dl_real")
    st.caption("Two files to try the tool with. The water utility is made up by a script (24 devices, 7 attack types, 22,073 records; device names, addresses and operators are invented) and says nothing about real attacks. "
               "The power-grid file is a sample of 10,952 real flows from the DNP3 Intrusion Detection Dataset (Kelli et al., 2022, Zenodo record 7348493, licence CC BY 4.0). "
               "Upload either one on the page Evaluate your own data, or run the agent on it.")

    st.markdown("#### Upload a fingerprint")
    up = st.file_uploader("A fingerprint file written by the agent (.json)", type=["json"], key="fp_upload")
    cards = load_cards()
    if up is not None:
        try:
            fp = json.loads(up.getvalue().decode("utf-8"))
        except Exception as e:
            st.error(f"The file could not be read as a fingerprint: {e}")
            fp = None
        if fp is not None and fp.get("format") != agent.FORMAT:
            st.error("This file is not a Praxis Lab fingerprint.")
            fp = None
        if fp is not None:
            good = agent.verify(fp)
            if good:
                st.success(f"Integrity digest matches (SHA3-256 {fp['integrity']['digest'][:16]}...). Agent version {fp.get('agent')}, made {fp.get('created')}.")
            else:
                st.error("The integrity digest does not match: the file was changed after the agent wrote it. Nothing below should be relied on.")
            k1, k2, k3, k4 = st.columns(4)
            with k1:
                kpi(len(fp.get("classes", {})), "attack types in the fingerprint")
            with k2:
                kpi(len(fp.get("features", [])), "behavior numbers kept", "teal")
            with k3:
                kpi(fp.get("removed_columns_count", 0), "columns removed before anything left", "teal")
            with k4:
                kpi(kb(fp.get("payload_bytes", 0)), "calculated payload of the fingerprint", "amber")
            st.markdown("#### Readiness for the full evaluation")
            for ok, text in agent.readiness(fp):
                st.markdown(("- " + pill("ok", "ok") if ok else "- " + pill("missing", "no")) + " " + text, unsafe_allow_html=True)
            st.markdown("#### Your attack coverage, by MITRE ATT&CK")
            rows = [{"Your label": lab, "About how many records": f"{c['records']:,}", "Attack family": c.get("family", ""),
                     "MITRE ATT&CK technique (closest)": agent.technique_text(c.get("techniques", []))} for lab, c in fp.get("classes", {}).items()]
            html_table(pd.DataFrame(rows), wrap=("Attack family", "MITRE ATT&CK technique (closest)"))
            if fp.get("suppressed"):
                st.caption(f"{len(fp['suppressed'])} attack types were left out of the fingerprint because they had fewer than {fp.get('min_group_size')} records.")
            st.markdown("#### What the library holds that you do not")
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
                rows.append({"Attack family": fam, "In your fingerprint": "yes" if fam in mine else "no", "Datasets in the library that hold it": len(names),
                             "Isolated training": pct(r.iso) if r is not None else "not measured", "Sanitized attack-record sharing": pct(r.sha) if r is not None else "not measured",
                             "Federated learning": pct(r.fed) if r is not None else "not measured", "Centralized training": pct(r.cen) if r is not None else "not measured"})
            html_table(pd.DataFrame(rows), wrap=("Attack family",))
            st.caption("The four recall columns are library means from local runs of the tool, not the run of record: when an organization had that family withheld, the share of its test records named correctly under each training condition. "
                       "A family marked no is one your detectors have no examples of; the library shows how much peers' examples of it helped others. It is not a forecast for your network.")
            st.markdown("#### Contribute this fingerprint (optional)")
            agree = st.checkbox("I am allowed to share this fingerprint, and I agree that the operator of this site keeps it to compare attack coverage across organizations. "
                                "It holds summary statistics only: no records and no identifier columns.", key="fp_agree")
            if st.button("Contribute this fingerprint", disabled=not (agree and good), key="fp_contribute"):
                folder = os.path.join(HERE, "contributions")
                os.makedirs(folder, exist_ok=True)
                with open(os.path.join(folder, f"{fp['integrity']['digest'][:16]}.json"), "w") as fh:
                    json.dump(fp, fh, separators=(",", ":"))
                st.success("Kept on the machine that runs this site. Thank you.")
    else:
        st.info("Waiting for a fingerprint file. To make one: download the agent and a sample file above, then run python praxis_agent.py on the sample.")

    st.markdown("#### What a fingerprint is, and what it is not")
    st.markdown(f"""<div class='plab-muted'>
<p>For every attack type with at least {agent.K_MIN} records the fingerprint stores the record count rounded down to the nearest ten, {len(agent.GRID)} quantiles (1% to 99%) of every behavior number, and the rank correlations between them.
It stores no rows, no device names, no addresses, no ports, no time stamps and no minimum or maximum values. Normal traffic is not fingerprinted.</p>
<p>It is a summary, not a formal privacy protection: no differential privacy is applied, and what a fingerprint reveals about the organization that made it has not been measured.</p>
<p style='margin-bottom:0'>Each fingerprint carries a SHA3-256 integrity digest, and a signature field reserved for a post-quantum signature (ML-DSA, FIPS 204). Signing is designed, not built.</p>
</div>""", unsafe_allow_html=True)

    st.markdown("#### Does a fingerprint carry enough to help? (experiment, not part of the praxis)")
    done = [c for c in cards if (c.get("experimental") or {}).get("fingerprint_sharing")]
    if done:
        ok_fp = sum(1 for c in done if c["experimental"]["fingerprint_sharing"]["mean_gain"]["clears"])
        st.markdown(f"Fingerprint sharing was run on {len(done)} datasets of the library as a fifth, experimental arm: the receiver trains on its own records plus made-up records drawn from its peers' fingerprints, "
                    f"with the same training budget and alarm rule as the four training conditions. On {ok_fp} of {len(done)} datasets the whole 95% range of the mean gain is above 5 points.")
        above_fed = sum(1 for c in done if c["experimental"]["fingerprint_sharing"]["mean_gain"]["gain"] > c["hypotheses"]["H2"]["gain"])
        above_sha = sum(1 for c in done if c["experimental"]["fingerprint_sharing"]["mean_gain"]["gain"] > c["hypotheses"]["H1"]["gain"])
        ratios = sorted(sum(c["companies"][o]["bytes"]["2_sharing"] for o in ORG) / max(1, sum(c["experimental"]["fingerprint_sharing"]["orgs"][o]["bytes"] for o in ORG)) for c in done)
        k1, k2, k3 = st.columns(3)
        with k1:
            kpi(f"{above_fed} of {len(done)}", "datasets where its mean gain is above federated learning's (point estimates)", "teal")
        with k2:
            kpi(f"{above_sha} of {len(done)}", "datasets where its mean gain is above sanitized attack-record sharing's", "amber")
        with k3:
            kpi(f"{ratios[len(ratios) // 2]:.0f} times", "fewer bytes than record sharing (median over the datasets)", "teal")
        st.markdown("")
        rows = []
        for c in done:
            e = c["experimental"]["fingerprint_sharing"]
            sent_sharing = sum(c["companies"][o]["bytes"]["2_sharing"] for o in ORG)
            sent_fp = sum(e["orgs"][o]["bytes"] for o in ORG)
            rows.append({"Dataset": c["name"], "Run": "local run", "Isolated training": "baseline", "Sanitized attack-record sharing": pts(c["hypotheses"]["H1"]), "Federated learning": pts(c["hypotheses"]["H2"]),
                         "Centralized training": pts(c["checks"].get("pooled")), "Fingerprint sharing (experimental)": pts(e["mean_gain"]),
                         "Data sent, sharing": kb(sent_sharing), "Data sent, fingerprints": kb(sent_fp)})
        html_table(pd.DataFrame(rows), wrap=("Dataset",))
        st.caption("Mean gain in attack-class recall on the withheld attack types against isolated training, points, with the 95% range; local runs of the tool on the tool's own splits, which are optimistic where a dataset has no clock. "
                   "Only DataSense carries the praxis claims, and the praxis has four training conditions; fingerprint sharing is product research, run with its own isolated baseline. "
                   "Data sent is the calculated payload received by the three organizations together. What a fingerprint reveals about its sender has not been measured, so a gain here is half of an answer.")
    else:
        st.caption("Not yet run on this install.")


PAGES = {"start": (page_start, "Start here"), "results": (page_results, "Results on the datasets"),
         "evaluate": (page_evaluate, "Evaluate your own data"), "sanitize": (page_sanitize, "Sanitize a file"),
         "definitions": (page_definitions, "Definitions"), "students": (page_students, "For students"),
         "agent": (page_agent, "Local agent and fingerprint"),
         "research": (page_research, "The research"), "organizations": (page_organizations, "For organizations")}

if not gate():
    st.stop()
if _test_page in PAGES:
    PAGES[_test_page][0]()
else:
    nav = st.navigation([st.Page(fn, title=title, url_path=("" if key == "start" else key), default=(key == "start")) for key, (fn, title) in PAGES.items()])
    try:
        st.logo(os.path.join(HERE, "assets", "praxis_lab_logo.svg"), size="large")
    except Exception:
        pass
    with st.sidebar:
        st.caption(f"Privacy-aware evaluation of sanitized attack-record sharing and federated learning for intrusion detection. {VERSION}")
        if access_password() and st.button("Leave the site", key="_leave"):
            st.session_state["_access_ok"] = False
            st.session_state["_left"] = True
            _set_cookie("", 0)
            time.sleep(0.4)
            st.rerun()
    nav.run()
