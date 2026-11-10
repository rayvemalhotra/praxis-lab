"""ThreatPrint design system: tokens, CSS, components and inline SVG charts for the Streamlit app.

Everything visual lives here so that app.py holds only pages and logic. All charts are plain SVG built in Python:
no chart library, the same look everywhere, and the numbers stay in the page text.
"""
import html as _html
import math
import re

import streamlit as st

BRAND = "ThreatPrint"
TAGLINE = "Know what sharing buys. Know what it exposes."

INK, INK2, MUTED, LINE, BG, CARD = "#0b1530", "#334155", "#64748b", "#e5e9f2", "#f6f8fc", "#ffffff"
TEAL, INDIGO, AMBER, SLATE, GRAPHITE = "#0d9488", "#6366f1", "#f59e0b", "#94a3b8", "#334155"
GREEN, RED, ORANGE = "#15803d", "#b91c1c", "#c2410c"
COND = {"1_isolated": SLATE, "2_sharing": TEAL, "3_federated": INDIGO, "4_centralized": GRAPHITE, "fp": AMBER}

CSS = """
<style>
@font-face { font-family: 'Inter'; font-style: normal; font-weight: 100 900; font-display: swap; src: url('/app/static/inter-latin-wght-normal.woff2') format('woff2-variations'), url('/app/static/inter-latin-wght-normal.woff2') format('woff2'); }
@font-face { font-family: 'JetBrains Mono'; font-style: normal; font-weight: 100 800; font-display: swap; src: url('/app/static/jetbrains-mono-latin-wght-normal.woff2') format('woff2-variations'), url('/app/static/jetbrains-mono-latin-wght-normal.woff2') format('woff2'); }
:root { --ink:#0b1530; --ink2:#334155; --muted:#64748b; --line:#e5e9f2; --bg:#f6f8fc; --card:#ffffff; --teal:#0d9488; --teal2:#14b8a6;
        --indigo:#6366f1; --amber:#f59e0b; --slate:#94a3b8; --graphite:#334155; --shadow:0 1px 2px rgba(11,21,48,.04), 0 8px 24px rgba(11,21,48,.06); }
html, body, .stApp, .stMarkdown, button, input, textarea, select, [data-testid="stWidgetLabel"] * { font-family: 'Inter', -apple-system, 'Segoe UI', Helvetica, Arial, sans-serif !important; }
.stApp { background: var(--bg); }
[data-testid="stHeader"], [data-testid="stToolbar"], [data-testid="stSidebar"], [data-testid="stSidebarCollapsedControl"], [data-testid="stStatusWidget"], footer { display: none !important; }
.stMainBlockContainer { max-width: 1240px; padding: 0.4rem 2rem 2rem 2rem; }
h1, h2, h3, h4 { color: var(--ink); letter-spacing: -0.02em; }
p, li { color: var(--ink2); line-height: 1.6; }
a { color: var(--teal); }

/* ---------- top navigation ---------- */
[data-testid='stLayoutWrapper']:has(> .st-key-tp_nav) { position: sticky; top: 10px; z-index: 99; }
.st-key-tp_nav { position: relative; background: rgba(255,255,255,.86); backdrop-filter: saturate(160%) blur(14px); -webkit-backdrop-filter: saturate(160%) blur(14px);
                 border: 1px solid var(--line); border-radius: 16px; padding: 8px 12px 8px 16px; margin-top: 6px; box-shadow: 0 1px 2px rgba(11,21,48,.04), 0 10px 30px rgba(11,21,48,.07); }
.st-key-tp_nav [data-testid="stHorizontalBlock"] { align-items: center; gap: 2px; }
.st-key-tp_nav [data-testid="stPageLink-NavLink"] { justify-content: center; border-radius: 9px; padding: 7px 4px; background: transparent; }
.st-key-tp_nav [data-testid="stPageLink-NavLink"] p { font-size: 0.875rem; font-weight: 600; color: var(--ink2); white-space: nowrap; }
.st-key-tp_nav [data-testid="stPageLink-NavLink"]:hover { background: #e9eef6; }
.st-key-tp_nav [class*="st-key-tp_on"] [data-testid="stPageLink-NavLink"] { background: var(--ink); }
.st-key-tp_nav [class*="st-key-tp_on"] [data-testid="stPageLink-NavLink"] p { color: #fff; }
.tp-logo { display: flex; align-items: center; gap: 10px; text-decoration: none; }
.st-key-tp_nav .tp-logo { margin-bottom: -1rem; transform: translateY(-1px); }
.st-key-tp_nav [data-testid='stMarkdownContainer'] p { margin: 0; }
.tp-logo .w { font-weight: 800; font-size: 1.22rem; letter-spacing: -0.03em; color: var(--ink); }
.tp-logo .w b { color: var(--teal); font-weight: 800; }
.tp-navstatic { display:flex; gap:18px; align-items:center; font-size:.875rem; font-weight:600; color: var(--ink2); }

/* ---------- buttons ---------- */
.stButton > button, .stDownloadButton > button, [data-testid="stFormSubmitButton"] > button { border-radius: 10px; font-weight: 600; border: 1px solid #cfd6e4; background: #fff; color: var(--ink); padding: 0.5rem 1rem; }
.stButton > button:hover, .stDownloadButton > button:hover { border-color: var(--ink); color: var(--ink); }
.stButton > button[kind="primary"], .stDownloadButton > button[kind="primary"], [data-testid="stFormSubmitButton"] > button { background: var(--ink); border: 1px solid var(--ink); }
.stButton > button[kind="primary"] p, .stDownloadButton > button[kind="primary"] p, [data-testid="stFormSubmitButton"] > button p { color: #fff !important; }
.stButton > button[kind="primary"]:hover, .stDownloadButton > button[kind="primary"]:hover, [data-testid="stFormSubmitButton"] > button:hover { background: var(--teal); border-color: var(--teal); }
[class*="st-key-cta_dark"] [data-testid="stPageLink-NavLink"] { background: var(--ink); border-radius: 12px; padding: 12px 18px; justify-content: center; box-shadow: var(--shadow); }
[class*="st-key-cta_dark"] [data-testid="stPageLink-NavLink"] p { color: #fff; font-weight: 700; }
[class*="st-key-cta_dark"] [data-testid="stPageLink-NavLink"]:hover { background: var(--teal); }
[class*="st-key-cta_light"] [data-testid="stPageLink-NavLink"] { background: #fff; border: 1px solid #cfd6e4; border-radius: 12px; padding: 11px 18px; justify-content: center; }
[class*="st-key-cta_light"] [data-testid="stPageLink-NavLink"] p { color: var(--ink); font-weight: 700; }
[class*="st-key-cta_light"] [data-testid="stPageLink-NavLink"]:hover { border-color: var(--ink); }
[class*="st-key-cta_onhero"] [data-testid="stPageLink-NavLink"] { background: #fff; border-radius: 12px; padding: 12px 18px; justify-content: center; }
[class*="st-key-cta_onhero"] [data-testid="stPageLink-NavLink"] p { color: var(--ink); font-weight: 700; }

/* ---------- hero ---------- */
.tp-hero { position: relative; overflow: hidden; border-radius: 24px; padding: 48px 56px 46px 56px; margin: 22px 0 22px 0; color: #fff;
           background: radial-gradient(900px 420px at 88% -10%, rgba(20,184,166,.38), transparent 60%), radial-gradient(700px 380px at 0% 110%, rgba(99,102,241,.35), transparent 60%), linear-gradient(135deg, #070d1f 0%, #0b1530 55%, #10254a 100%);
           box-shadow: 0 20px 50px rgba(11,21,48,.25); }
.tp-hero .grid { display: grid; grid-template-columns: 1.08fr 0.92fr; gap: 44px; align-items: center; }
.tp-hero.single .grid { grid-template-columns: 1fr; }
.tp-eyebrow { display: inline-flex; align-items: center; gap: 8px; font-size: .74rem; font-weight: 700; letter-spacing: .12em; text-transform: uppercase; color: #99f6e4;
              background: rgba(20,184,166,.14); border: 1px solid rgba(45,212,191,.35); padding: 6px 12px; border-radius: 999px; }
.tp-hero h1 { color: #fff !important; font-size: 3.25rem !important; line-height: 1.04 !important; font-weight: 800 !important; letter-spacing: -0.035em; margin: 18px 0 16px 0 !important; padding: 0 !important; }
.tp-hero h1 em { font-style: normal; background: linear-gradient(90deg, #5eead4, #a5b4fc); -webkit-background-clip: text; background-clip: text; color: transparent; }
.tp-hero.sub h1 { font-size: 2.5rem !important; }
.tp-hero p.lead { color: #cbd5e1; font-size: 1.08rem; max-width: 720px; margin: 0; }
.tp-trust { display: flex; flex-wrap: wrap; gap: 8px 18px; margin-top: 20px; color: #94a3b8; font-size: .82rem; }
.tp-trust span { display: inline-flex; align-items: center; gap: 6px; }
.tp-trust i { width: 6px; height: 6px; border-radius: 50%; background: #2dd4bf; display: inline-block; }
.tp-shot { background: #fff; border-radius: 18px; padding: 20px 22px 34px 22px; box-shadow: 0 30px 60px rgba(0,0,0,.35); color: var(--ink); transform: rotate(-1deg); }
.tp-shot .t { font-size: .74rem; color: var(--muted); font-weight: 600; letter-spacing: .08em; text-transform: uppercase; }
.tp-shot .n { font-weight: 800; font-size: 1.02rem; margin: 2px 0 8px 0; }
.tp-float { position: relative; width: fit-content; max-width: 88%; margin: -22px -10px 0 auto; background: #0b1530; color: #e2e8f0; border: 1px solid rgba(148,163,184,.35); border-radius: 14px; padding: 11px 15px; font-size: .82rem; line-height: 1.45;
            box-shadow: 0 16px 40px rgba(0,0,0,.45); transform: rotate(1.2deg); }
.tp-float b { color: #5eead4; }

.st-key-tp_hero { position: relative; overflow: hidden; border-radius: 24px; padding: 54px 54px 46px 54px; margin: 22px 0 8px 0;
           background: radial-gradient(900px 420px at 88% -10%, rgba(20,184,166,.38), transparent 60%), radial-gradient(700px 380px at 0% 110%, rgba(99,102,241,.35), transparent 60%), linear-gradient(135deg, #070d1f 0%, #0b1530 55%, #10254a 100%);
           box-shadow: 0 20px 50px rgba(11,21,48,.25); }
.st-key-tp_hero h1 { color: #fff !important; font-size: 2.95rem !important; white-space: nowrap; line-height: 1.04 !important; font-weight: 800 !important; letter-spacing: -0.035em; margin: 18px 0 16px 0 !important; padding: 0 !important; }
.st-key-tp_hero h1 em { font-style: normal; background: linear-gradient(90deg, #5eead4, #a5b4fc); -webkit-background-clip: text; background-clip: text; color: transparent; }
.st-key-tp_hero p.lead { color: #cbd5e1; font-size: 1.1rem; max-width: 600px; margin: 0 0 22px 0; }
.st-key-tp_hero [data-testid="stHorizontalBlock"] { align-items: center; }
/* ---------- sections, cards, stats ---------- */
.tp-grid { display: grid; gap: 16px; align-items: stretch; margin: 6px 0 4px 0; }
.tp-grid > div { height: 100%; }
.tp-sec { margin: 46px 0 14px 0; }
.tp-sec .k { font-size: .74rem; font-weight: 700; letter-spacing: .14em; text-transform: uppercase; color: var(--teal); }
.tp-sec h2 { font-size: 1.9rem !important; font-weight: 800 !important; margin: 6px 0 6px 0 !important; padding: 0 !important; }
.tp-sec p { color: var(--muted); font-size: 1.02rem; max-width: 760px; margin: 0; }
.tp-card { background: var(--card); border: 1px solid var(--line); border-radius: 16px; padding: 20px 22px; height: 100%; box-shadow: var(--shadow); }
.tp-card h5 { margin: 10px 0 6px 0; font-size: 1.02rem; font-weight: 700; color: var(--ink); letter-spacing: -0.01em; }
.tp-card p { margin: 0; font-size: .92rem; color: var(--ink2); }
.tp-ico { width: 40px; height: 40px; border-radius: 11px; display: inline-flex; align-items: center; justify-content: center; background: #e6faf7; color: var(--teal); }
.tp-ico.indigo { background: #eef0ff; color: var(--indigo); } .tp-ico.amber { background: #fff5e0; color: #b45309; } .tp-ico.ink { background: #e8ecf5; color: var(--ink); }
.tp-step { position: relative; }
.tp-step .no { font-size: .72rem; font-weight: 800; color: var(--muted); letter-spacing: .1em; }
.tp-stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 14px; margin: 18px 0 0 0; }
.tp-stat { background: var(--card); border: 1px solid var(--line); border-radius: 16px; padding: 18px 20px; box-shadow: var(--shadow); }
.tp-stat .v { font-size: 2.1rem; font-weight: 800; color: var(--ink); letter-spacing: -0.03em; line-height: 1.05; }
.tp-stat .v small { font-size: 1rem; color: var(--muted); font-weight: 700; }
.tp-stat .l { font-size: .84rem; color: var(--muted); margin-top: 6px; line-height: 1.35; }
.tp-stat .bar { height: 4px; width: 36px; border-radius: 4px; background: var(--teal); margin-bottom: 12px; }
.tp-stat.indigo .bar { background: var(--indigo); } .tp-stat.amber .bar { background: var(--amber); } .tp-stat.ink .bar { background: var(--ink); }
.tp-chip { display: inline-flex; align-items: center; gap: 6px; padding: 4px 10px; border-radius: 999px; background: #eef2f7; color: var(--ink2); font-size: .78rem; font-weight: 600; margin: 0 6px 6px 0; }
.tp-chip.teal { background: #e6faf7; color: #0f766e; } .tp-chip.indigo { background: #eef0ff; color: #4338ca; } .tp-chip.amber { background: #fff5e0; color: #92400e; } .tp-chip.dark { background: var(--ink); color: #fff; }
.tp-badge { display: inline-flex; align-items: center; gap: 5px; padding: 3px 9px; border-radius: 999px; font-size: .74rem; font-weight: 700; white-space: nowrap; }
.tp-badge.ok { background: #dcfce7; color: #166534; } .tp-badge.no { background: #fee2e2; color: #991b1b; } .tp-badge.warn { background: #ffedd5; color: #9a3412; }
.tp-badge.na { background: #eef2f7; color: #475569; } .tp-badge.amber { background: #fef3c7; color: #92400e; }
.tp-callout { background: #ecfdf8; border: 1px solid #b6efe3; border-radius: 14px; padding: 16px 20px; color: var(--ink2); margin: 10px 0; }
.tp-callout b { color: var(--ink); }
.tp-note { background: #eef2f8; border-radius: 14px; padding: 16px 20px; color: var(--ink2); font-size: .93rem; }
.tp-note p { margin: 0 0 8px 0; font-size: .93rem; } .tp-note p:last-child { margin: 0; }
.tp-legend { display: flex; flex-wrap: wrap; gap: 6px 18px; font-size: .8rem; color: var(--ink2); margin: 4px 0 10px 0; }
.tp-legend span { display: inline-flex; align-items: center; gap: 7px; }
.tp-legend i { width: 10px; height: 10px; border-radius: 3px; display: inline-block; }
.tp-org { background: var(--card); border: 1px solid var(--line); border-radius: 16px; padding: 18px 20px 14px 20px; box-shadow: var(--shadow); height: 100%; }
.tp-org .name { font-weight: 800; font-size: 1.05rem; color: var(--ink); }
.tp-org .meta { font-size: .8rem; color: var(--muted); margin: 2px 0 10px 0; }
.tp-org .sub { font-size: .78rem; color: var(--muted); margin-top: 8px; line-height: 1.45; }
.tp-org .row { display: flex; justify-content: space-between; align-items: center; font-size: .8rem; color: var(--ink2); padding: 5px 0; border-top: 1px solid #f0f3f8; }
.tp-hyp { background: var(--card); border: 1px solid var(--line); border-radius: 16px; padding: 18px 20px; box-shadow: var(--shadow); height: 100%; }
.tp-hyp .h { display: flex; justify-content: space-between; align-items: center; }
.tp-hyp .h b { font-size: .8rem; letter-spacing: .08em; color: var(--muted); }
.tp-hyp .big { font-size: 2rem; font-weight: 800; letter-spacing: -0.03em; color: var(--ink); margin-top: 6px; line-height: 1.1; }
.tp-hyp .big small { font-size: .9rem; color: var(--muted); font-weight: 600; }
.tp-hyp .d { font-size: .84rem; color: var(--muted); margin-top: 4px; line-height: 1.45; }
.tp-dshead { background: var(--card); border: 1px solid var(--line); border-radius: 18px; padding: 22px 26px; box-shadow: var(--shadow); margin-top: 8px; }
.tp-dshead h3 { margin: 0 0 4px 0 !important; padding: 0 !important; font-size: 1.45rem !important; font-weight: 800 !important; }
.tp-dshead p { margin: 0 0 10px 0; color: var(--muted); font-size: .93rem; }
.tp-term { background: #0b1530; color: #cbd5e1; border-radius: 16px; padding: 16px 18px; font-family: 'JetBrains Mono', ui-monospace, Menlo, monospace !important; font-size: .76rem; line-height: 1.6;
           box-shadow: 0 30px 60px rgba(0,0,0,.35); border: 1px solid rgba(148,163,184,.25); white-space: pre-wrap; overflow: hidden; }
.tp-term * { font-family: 'JetBrains Mono', ui-monospace, Menlo, monospace !important; }
.tp-term .dots { display: flex; gap: 6px; margin-bottom: 10px; } .tp-term .dots i { width: 10px; height: 10px; border-radius: 50%; background: #334155; display: inline-block; }
.tp-term .c { color: #5eead4; } .tp-term .g { color: #86efac; } .tp-term .m { color: #64748b; } .tp-term .y { color: #fcd34d; }
.tp-quote { background: var(--card); border: 1px solid var(--line); border-left: 5px solid var(--teal); border-radius: 14px; padding: 18px 22px; font-size: 1.06rem; color: var(--ink); line-height: 1.6; box-shadow: var(--shadow); }
.tp-pair { display: grid; grid-template-columns: 1fr 1fr 190px; gap: 0; background: var(--card); border: 1px solid var(--line); border-radius: 16px; overflow: hidden; box-shadow: var(--shadow); margin-bottom: 12px; }
.tp-pair > div { padding: 16px 20px; font-size: .93rem; color: var(--ink2); line-height: 1.5; }
.tp-pair > div + div { border-left: 1px solid var(--line); }
.tp-pair .tag { font-size: .72rem; font-weight: 800; letter-spacing: .1em; color: var(--teal); display: block; margin-bottom: 4px; }
.tp-pair .res { display: flex; flex-direction: column; justify-content: center; align-items: flex-start; gap: 6px; background: #fafbfe; }
.tp-pair .res .v { font-weight: 800; font-size: 1.3rem; white-space: nowrap; color: var(--ink); letter-spacing: -0.02em; }
.tp-list { list-style: none; padding: 0; margin: 0; }
.tp-list li { display: flex; gap: 10px; align-items: flex-start; padding: 9px 0; border-bottom: 1px solid #f0f3f8; font-size: .92rem; }
.tp-list li:last-child { border-bottom: none; }
.tp-list .i { flex: 0 0 22px; height: 22px; border-radius: 50%; display: inline-flex; align-items: center; justify-content: center; margin-top: 1px; }
.tp-list .i.ok { background: #dcfce7; color: #166534; } .tp-list .i.wait { background: #fef3c7; color: #92400e; } .tp-list .i.no { background: #eef2f7; color: #64748b; }
.tp-footer { margin-top: 64px; padding: 26px 0 8px 0; border-top: 1px solid var(--line); color: var(--muted); font-size: .84rem; display: flex; justify-content: space-between; gap: 24px; flex-wrap: wrap; }
.tp-footer b { color: var(--ink); }

/* ---------- tables ---------- */
table.tp { border-collapse: separate; border-spacing: 0; width: 100%; font-size: .85rem; margin: 6px 0 12px 0; background: var(--card); border: 1px solid var(--line); border-radius: 14px; overflow: hidden; }
table.tp th { text-align: left; vertical-align: bottom; font-weight: 700; color: var(--muted); background: #f8fafd; border-bottom: 1px solid var(--line); padding: 10px 12px; font-size: .74rem; letter-spacing: .04em; text-transform: uppercase; }
table.tp td { border-bottom: 1px solid #f0f3f8; padding: 9px 12px; white-space: nowrap; vertical-align: middle; color: var(--ink2); }
table.tp tr:last-child td { border-bottom: none; }
table.tp th, table.tp td { border-left: none !important; border-right: none !important; border-top: none !important; }
table.tp td.wrap, table.tp th.wrap { white-space: normal; }
table.tp td.heat { text-align: center; font-weight: 700; font-variant-numeric: tabular-nums; }
table.tp tr.exp td { background: #fffaf0; }

/* ---------- streamlit widgets ---------- */
div[data-testid="stExpander"] { background: var(--card); border: 1px solid var(--line); border-radius: 14px; box-shadow: var(--shadow); }
div[data-testid="stExpander"] summary p { font-weight: 600; color: var(--ink); }
div[data-testid="stForm"] { background: transparent; border: none; padding: 0; }
[data-testid="stFileUploaderDropzone"] { background: #fff; border: 1.5px dashed #b8c2d6; border-radius: 16px; padding: 22px; }
[data-testid="stFileUploaderDropzone"]:hover { border-color: var(--teal); }
[data-testid="stAlertContainer"] { border-radius: 14px; }
[data-baseweb="select"] > div, [data-baseweb="input"], [data-baseweb="base-input"] { border-radius: 10px !important; }
.stTextInput [data-baseweb="input"], .stTextInput [data-baseweb="base-input"], .stTextInput input, [data-baseweb="select"] > div { background: #fff !important; }
.stTextInput [data-baseweb="input"], [data-baseweb="select"] > div { border: 1px solid #cfd6e4 !important; }
.st-key-tp_gate_card { background: #fff; border: 1px solid var(--line); border-radius: 20px; padding: 30px 30px 22px 30px; box-shadow: 0 20px 50px rgba(11,21,48,.10); }
.tp-gate { border-radius: 24px; padding: 44px 40px; color: #fff; min-height: 520px; display: flex; flex-direction: column; justify-content: space-between;
           background: radial-gradient(700px 360px at 90% 0%, rgba(20,184,166,.40), transparent 60%), radial-gradient(600px 340px at 0% 100%, rgba(99,102,241,.38), transparent 60%), linear-gradient(135deg, #070d1f, #0b1530 60%, #10254a); }
.tp-gate h1 { color: #fff !important; font-size: 2.3rem !important; font-weight: 800 !important; letter-spacing: -0.03em; line-height: 1.08 !important; margin: 26px 0 12px 0 !important; padding: 0 !important; }
.tp-gate p { color: #cbd5e1; font-size: 1rem; margin: 0; }
.tp-gate ul { list-style: none; padding: 0; margin: 24px 0 0 0; } .tp-gate li { color: #e2e8f0; font-size: .93rem; padding: 7px 0; display: flex; gap: 10px; align-items: center; }
.tp-gate li i { width: 22px; height: 22px; border-radius: 50%; background: rgba(45,212,191,.2); color: #5eead4; display: inline-flex; align-items: center; justify-content: center; font-style: normal; font-size: .75rem; }
.tp-gate .logo .w { color: #fff; } .tp-gate .logo .w b { color: #5eead4; } .tp-gate .foot { color: #94a3b8; font-size: .8rem; }
svg text { font-family: 'Inter', -apple-system, 'Segoe UI', Helvetica, Arial, sans-serif; }
@media (max-width: 900px) { .tp-grid { grid-template-columns: 1fr !important; } .st-key-tp_hero h1 { white-space: normal; font-size: 2.2rem !important; } .tp-hero .grid { grid-template-columns: 1fr; } .tp-hero h1 { font-size: 2.3rem !important; } .tp-stats { grid-template-columns: 1fr 1fr; } .tp-pair { grid-template-columns: 1fr; } .tp-float { display: none; } }
</style>
"""

ICON = {
    "upload": "<path d='M12 16V4M7 9l5-5 5 5M4 20h16'/>",
    "shield": "<path d='M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z'/>",
    "orgs": "<circle cx='6' cy='17' r='3'/><circle cx='18' cy='17' r='3'/><circle cx='12' cy='6' r='3'/>",
    "filter": "<path d='M4 5h16l-6 8v6l-4-2v-4z'/>",
    "chip": "<rect x='6' y='6' width='12' height='12' rx='2'/><path d='M9 2v4M15 2v4M9 18v4M15 18v4M2 9h4M2 15h4M18 9h4M18 15h4'/>",
    "target": "<circle cx='12' cy='12' r='8'/><circle cx='12' cy='12' r='3'/>",
    "chart": "<path d='M4 20V10M10 20V4M16 20v-7M22 20H2'/>",
    "print": "<path d='M6 11a6 6 0 0112 0v2M9 11a3 3 0 016 0v4M12 11v6M6 15v2M18 16v1'/>",
    "lock": "<rect x='5' y='11' width='14' height='9' rx='2'/><path d='M8 11V8a4 4 0 018 0v3'/>",
    "check": "<path d='M5 12l5 5 9-10'/>",
    "clock": "<circle cx='12' cy='12' r='8'/><path d='M12 8v4l3 2'/>",
    "minus": "<path d='M6 12h12'/>",
    "term": "<rect x='3' y='4' width='18' height='16' rx='2'/><path d='M7 9l3 3-3 3M12 15h5'/>",
    "book": "<path d='M5 4h11a3 3 0 013 3v13H8a3 3 0 01-3-3z'/><path d='M5 17a3 3 0 013-3h11'/>",
    "building": "<rect x='5' y='3' width='14' height='18' rx='1'/><path d='M9 7h2M13 7h2M9 11h2M13 11h2M9 15h2M13 15h2'/>",
    "file": "<path d='M7 3h7l4 4v14H7z'/><path d='M14 3v4h4M10 12h5M10 16h5'/>",
    "scale": "<path d='M12 4v16M6 20h12M5 8h14M5 8l-2 6a3 3 0 006 0zM19 8l-2 6a3 3 0 006 0z'/>",
}


def esc(x):
    return _html.escape(str(x))


def icon(name, size=20, stroke=2):
    return (f"<svg width='{size}' height='{size}' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='{stroke}' "
            f"stroke-linecap='round' stroke-linejoin='round'>{ICON[name]}</svg>")


def H(html):
    """Render an HTML fragment. Line breaks and indentation are collapsed so that Markdown never reads them as code."""
    st.markdown(re.sub(r"\s*\n\s*", " ", html).strip(), unsafe_allow_html=True)


def inject():
    st.markdown(re.sub(r"\s*\n\s*", " ", CSS), unsafe_allow_html=True)


MARK = ("<svg width='34' height='34' viewBox='0 0 34 34'><defs><linearGradient id='tpg' x1='0' y1='0' x2='1' y2='1'><stop offset='0' stop-color='#14b8a6'/><stop offset='1' stop-color='#6366f1'/></linearGradient></defs>"
        "<rect width='34' height='34' rx='9' fill='url(#tpg)'/><g fill='none' stroke='#fff' stroke-width='2' stroke-linecap='round'>"
        "<path d='M9 19a8 8 0 0116 0v3'/><path d='M13 19a4 4 0 018 0v6'/><path d='M17 19v8'/><path d='M9 23v2'/></g></svg>")


def logo(light=False):
    return f"<div class='tp-logo logo'>{MARK}<span class='w'>Threat<b>Print</b></span></div>"


def section(kicker, title, text=""):
    H(f"<div class='tp-sec'><div class='k'>{esc(kicker)}</div><h2>{esc(title)}</h2>{f'<p>{text}</p>' if text else ''}</div>")


def card_html(title, text, ico=None, tone="", no=None, extra=""):
    top = f"<div class='tp-ico {tone}'>{icon(ico)}</div>" if ico else ""
    n = f"<div class='no'>STEP {no}</div>" if no else ""
    return f"<div class='tp-card tp-step'>{top}{n}<h5>{esc(title)}</h5><p>{text}</p>{extra}</div>"


def card(title, text, ico=None, tone="", no=None, extra=""):
    H(card_html(title, text, ico, tone, no, extra))


def grid(items, cols=None, gap=16):
    """A row of equal-height cards: items are HTML strings."""
    H(f"<div class='tp-grid' style='grid-template-columns:repeat({cols or len(items)},minmax(0,1fr));gap:{gap}px'>" + "".join(items) + "</div>")


def stats(items):
    """items: (value, label, tone). A row of headline numbers."""
    H("<div class='tp-stats'>" + "".join(f"<div class='tp-stat {t}'><div class='bar'></div><div class='v'>{v}</div><div class='l'>{esc(l)}</div></div>" for v, l, t in items) + "</div>")


def chip(text, tone=""):
    return f"<span class='tp-chip {tone}'>{esc(text)}</span>"


def badge(text, tone="na"):
    return f"<span class='tp-badge {tone}'>{esc(text)}</span>"


def verdict_badge(v):
    v = v or "not measured"
    tone = ("ok" if v.startswith("gain met") and "breach" not in v and "trade-off" not in v else
            "warn" if ("trade-off" in v or "breach" in v) else
            "no" if v.startswith("not worth") else "na")
    return badge(v, tone)


def legend(items):
    return "<div class='tp-legend'>" + "".join(f"<span><i style='background:{c}'></i>{esc(t)}</span>" for t, c in items) + "</div>"


# ---------------------------------------------------------------- charts (inline SVG)
def bars(rows, width=380):
    """Horizontal bars, one per training condition. rows: (label, value 0..1 or None, color, experimental?)."""
    rh, top = 36, 2
    h = top + rh * len(rows)
    out = [f"<svg viewBox='0 0 {width} {h}' width='100%' style='display:block'>"
           "<defs><pattern id='tphatch' width='6' height='6' patternUnits='userSpaceOnUse' patternTransform='rotate(45)'><rect width='6' height='6' fill='#f59e0b'/><rect width='3' height='6' fill='#fbbf24'/></pattern></defs>"]
    for i, (label, v, color, exp) in enumerate(rows):
        y = top + i * rh
        txt = "not measured" if v is None or (isinstance(v, float) and math.isnan(v)) else f"{v * 100:.1f}%"
        w = 0 if txt == "not measured" else max(0.0, min(1.0, v)) * width
        out.append(f"<text x='0' y='{y + 13}' font-size='12' fill='{INK2}' font-weight='{600 if not exp else 700}'>{esc(label)}</text>")
        out.append(f"<text x='{width}' y='{y + 13}' font-size='12.5' fill='{INK}' font-weight='800' text-anchor='end'>{txt}</text>")
        out.append(f"<rect x='0' y='{y + 19}' width='{width}' height='9' rx='4.5' fill='#eef2f7'/>")
        if w > 0:
            out.append(f"<rect x='0' y='{y + 19}' width='{max(w, 6):.1f}' height='9' rx='4.5' fill='{'url(#tphatch)' if exp else color}'/>")
    out.append("</svg>")
    return "".join(out)


def bullet(gain, lo, hi, color=TEAL, width=260):
    """One gain with its 95% range against the 5-point rule. Values in points (0..100)."""
    x = lambda v: 6 + max(-5.0, min(100.0, v)) / 100.0 * (width - 12)
    return (f"<svg viewBox='0 0 {width} 50' width='100%' style='display:block;margin-top:10px'>"
            f"<rect x='6' y='14' width='{width - 12}' height='8' rx='4' fill='#eef2f7'/>"
            f"<rect x='{x(lo):.1f}' y='11' width='{max(3.0, x(hi) - x(lo)):.1f}' height='14' rx='7' fill='{color}' opacity='.28'/>"
            f"<circle cx='{x(gain):.1f}' cy='18' r='6.5' fill='{color}' stroke='#fff' stroke-width='2'/>"
            f"<line x1='{x(5):.1f}' y1='4' x2='{x(5):.1f}' y2='32' stroke='{RED}' stroke-width='1.5' stroke-dasharray='3 2'/>"
            f"<text x='{x(5) - 4:.1f}' y='45' font-size='11' fill='{RED}' font-weight='700'>5-point rule</text>"
            f"<text x='{width - 6}' y='45' font-size='11' fill='{MUTED}' text-anchor='end'>100 points</text></svg>")


def duo(a, b, la, lb, ca=AMBER, cb=SLATE, width=340):
    """Two bars against each other (for tracing: traced against guessing). Values 0..1."""
    out = [f"<svg viewBox='0 0 {width} 50' width='100%' style='display:block'>"]
    for i, (v, l, c) in enumerate(((a, la, ca), (b, lb, cb))):
        y = i * 25
        out.append(f"<text x='0' y='{y + 12}' font-size='11.5' fill='{INK2}' font-weight='600'>{esc(l)}</text>"
                   f"<text x='{width}' y='{y + 12}' font-size='12' fill='{INK}' font-weight='800' text-anchor='end'>{v * 100:.1f}%</text>"
                   f"<rect x='0' y='{y + 16}' width='{width}' height='6' rx='3' fill='#eef2f7'/><rect x='0' y='{y + 16}' width='{max(4.0, v * width):.1f}' height='6' rx='3' fill='{c}'/>")
    out.append("</svg>")
    return "".join(out)


def forest(rows, series, width=1140):
    """Gains with 95% ranges for many datasets. rows: dict(name, tag, vals={key: (gain, lo, hi) in points}); series: (key, label, color)."""
    left, right, rh, top = 330, 30, 30, 34
    pw = width - left - right
    h = top + rh * len(rows) + 34
    x = lambda v: left + max(-4.0, min(100.0, v)) / 100.0 * pw
    out = [f"<svg viewBox='0 0 {width} {h}' width='100%' style='display:block;background:#fff;border:1px solid {LINE};border-radius:16px'>"]
    for g in (0, 25, 50, 75, 100):
        out.append(f"<line x1='{x(g):.1f}' y1='{top - 8}' x2='{x(g):.1f}' y2='{h - 30}' stroke='#eef2f7' stroke-width='1'/>"
                   f"<text x='{x(g):.1f}' y='{h - 12}' font-size='11' fill='{MUTED}' text-anchor='middle'>{'+' if g else ''}{g}</text>")
    out.append(f"<line x1='{x(5):.1f}' y1='{top - 8}' x2='{x(5):.1f}' y2='{h - 30}' stroke='{RED}' stroke-width='1.4' stroke-dasharray='4 3'/>"
               f"<text x='{x(5) + 5:.1f}' y='{top - 12}' font-size='10.5' fill='{RED}' font-weight='700'>5-point rule</text>"
               f"<text x='{width - right}' y='{top - 12}' font-size='10.5' fill='{MUTED}' text-anchor='end'>gain in attack-class recall against isolated training, points</text>")
    off = {0: -7, 1: 0, 2: 7}
    for i, r in enumerate(rows):
        y = top + i * rh + rh / 2
        if i % 2 == 0:
            out.append(f"<rect x='8' y='{y - rh / 2:.1f}' width='{width - 16}' height='{rh}' rx='8' fill='#fafbfe'/>")
        name = r["name"] if len(r["name"]) <= 40 else r["name"][:39] + "…"
        out.append(f"<text x='20' y='{y + 4:.1f}' font-size='12.5' fill='{INK}' font-weight='{800 if r.get('strong') else 600}'>{esc(name)}</text>")
        if r.get("tag"):
            out.append(f"<text x='{left - 14}' y='{y + 4:.1f}' font-size='10' fill='{MUTED}' text-anchor='end'>{esc(r['tag'])}</text>")
        for j, (key, label, color) in enumerate(series):
            v = r["vals"].get(key)
            if not v:
                continue
            g, lo, hi = v
            yy = y + off.get(j, 0)
            out.append(f"<line x1='{x(lo):.1f}' y1='{yy:.1f}' x2='{x(hi):.1f}' y2='{yy:.1f}' stroke='{color}' stroke-width='2.2' stroke-linecap='round' opacity='.55'/>"
                       f"<circle cx='{x(g):.1f}' cy='{yy:.1f}' r='4.3' fill='{color}' stroke='#fff' stroke-width='1.3'><title>{esc(r['name'])}, {esc(label)}: {g:+.1f} [{lo:+.1f}, {hi:+.1f}]</title></circle>")
    out.append("</svg>")
    return "".join(out)


def heat(v, exp=False):
    """A heat-map cell for a share between 0 and 1."""
    if v is None or (isinstance(v, float) and math.isnan(v)):
        return "<td class='heat' style='color:#94a3b8;font-weight:500'>not measured</td>"
    rgb = "245,158,11" if exp else "13,148,136"
    a = 0.06 + 0.82 * max(0.0, min(1.0, v))
    fg = "#fff" if a > 0.55 else INK
    return f"<td class='heat' style='background:rgba({rgb},{a:.2f});color:{fg}'>{v * 100:.1f}%</td>"


def table(df, wrap=(), raw=(), row_class=None):
    """A styled HTML table: numbers never wrap, the columns named in wrap do, the columns in raw carry HTML."""
    cols = list(df.columns)
    out = ["<table class='tp'><thead><tr>"] + [f"<th class='wrap'>{esc(c)}</th>" for c in cols] + ["</tr></thead><tbody>"]
    for n, (_, r) in enumerate(df.iterrows()):
        out.append(f"<tr class='{row_class(n, r) if row_class else ''}'>")
        for c in cols:
            cell = str(r[c]) if c in raw else esc(r[c])
            out.append(cell if (c in raw and cell.startswith("<td")) else f"<td class='{'wrap' if c in wrap else ''}'>{cell}</td>")
        out.append("</tr>")
    out.append("</tbody></table>")
    st.markdown("".join(out), unsafe_allow_html=True)


def cond_diagram(kind):
    """A small picture of one training condition: three organizations and what travels between them."""
    n = lambda cx, cy, t: (f"<circle cx='{cx}' cy='{cy}' r='13' fill='#fff' stroke='{INK}' stroke-width='1.6'/>"
                           f"<text x='{cx}' y='{cy + 4}' font-size='11' font-weight='800' text-anchor='middle' fill='{INK}'>{t}</text>")
    a, b, c = (34, 62), (146, 62), (90, 18)
    body = ""
    if kind == "sharing":
        for (p, q) in ((b, a), (c, a), (a, b), (c, b), (a, c), (b, c)):
            body += f"<line x1='{p[0]}' y1='{p[1]}' x2='{q[0]}' y2='{q[1]}' stroke='{TEAL}' stroke-width='1.6' stroke-dasharray='3 3'/>"
        body += f"<rect x='84' y='56' width='12' height='9' rx='2' fill='{TEAL}'/><rect x='55' y='34' width='12' height='9' rx='2' fill='{TEAL}'/><rect x='113' y='34' width='12' height='9' rx='2' fill='{TEAL}'/>"
    elif kind == "federated":
        m = (90, 48)
        for p in (a, b, c):
            body += f"<line x1='{p[0]}' y1='{p[1]}' x2='{m[0]}' y2='{m[1]}' stroke='{INDIGO}' stroke-width='1.6'/>"
        body += f"<circle cx='90' cy='48' r='8' fill='{INDIGO}'/><path d='M86 48h8M90 44v8' stroke='#fff' stroke-width='1.6'/>"
    elif kind == "centralized":
        for p in (a, b, c):
            body += f"<line x1='{p[0]}' y1='{p[1]}' x2='90' y2='49' stroke='{GRAPHITE}' stroke-width='1.4' opacity='.45'/>"
        body += f"<rect x='62' y='36' width='56' height='26' rx='8' fill='{GRAPHITE}'/><text x='90' y='52.5' font-size='9.5' fill='#fff' font-weight='700' text-anchor='middle'>one place</text>"
    elif kind == "fingerprint":
        for (p, q) in ((b, a), (c, a), (a, b), (c, b), (a, c), (b, c)):
            body += f"<line x1='{p[0]}' y1='{p[1]}' x2='{q[0]}' y2='{q[1]}' stroke='{AMBER}' stroke-width='1.6' stroke-dasharray='1 4' stroke-linecap='round'/>"
    return f"<svg viewBox='0 0 180 82' width='100%' style='display:block;margin-bottom:4px'>{body}{n(*a, 'A')}{n(*b, 'B')}{n(*c, 'C')}</svg>"


def timeline(points):
    """points: (label, title, text). A horizontal timeline."""
    w, n = 1100, len(points)
    out = [f"<svg viewBox='0 0 {w} 122' width='100%' style='display:block'><line x1='60' y1='34' x2='{w - 60}' y2='34' stroke='{LINE}' stroke-width='4' stroke-linecap='round'/>"]
    for i, (lab, title, text) in enumerate(points):
        x = 60 + i * (w - 120) / (n - 1)
        anchor = "start" if i == 0 else ("end" if i == n - 1 else "middle")
        out.append(f"<circle cx='{x:.0f}' cy='34' r='9' fill='{TEAL if i < n - 1 else INK}' stroke='#fff' stroke-width='3'/>"
                   f"<text x='{x:.0f}' y='14' font-size='12' font-weight='800' fill='{INK}' text-anchor='{anchor}'>{esc(lab)}</text>"
                   f"<text x='{x:.0f}' y='66' font-size='13' font-weight='700' fill='{INK}' text-anchor='{anchor}'>{esc(title)}</text>")
        for k, line in enumerate(text.split("|")):
            out.append(f"<text x='{x:.0f}' y='{86 + k * 16}' font-size='11.5' fill='{MUTED}' text-anchor='{anchor}'>{esc(line)}</text>")
    out.append("</svg>")
    return "".join(out)
