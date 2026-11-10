"""Design system: tokens, CSS, generative art, components and inline SVG charts for the Streamlit app.

Everything visual lives here so that app.py holds only pages and logic. The look belongs to the rayvelabs.com family
(paper, ink, one gold accent, serif display type, mono labels) with silver and graphite neutrals. All charts and all
art are plain SVG built in Python: no chart library, no image files, no third-party server, and the numbers stay in the
page text. The product name is one switch: set TP_BRAND (and TP_TAGLINE) in the environment.
"""
import hashlib
import html as _html
import math
import os
import re

import streamlit as st

BRAND = (os.environ.get("TP_BRAND") or "ThreatPrint").strip() or "ThreatPrint"
TAGLINE = (os.environ.get("TP_TAGLINE") or "Know what sharing buys. Know what it exposes.").strip()
SLUG = re.sub(r"[^a-z0-9]+", "_", BRAND.lower()).strip("_") or "product"

# ---- tokens (the same values are declared as CSS variables below)
PAPER, PAPER_DEEP, VEIL, CARD, SILVER_BG = "#fbfbf9", "#f4efe3", "#fdfcf7", "#ffffff", "#f5f5f7"
INK, INK2, MUTED, FAINT, LINE, LINE2 = "#1d1d1f", "#424245", "#6e6e73", "#86868b", "#e3e0d8", "#eeebe4"
GOLD, GOLD_BRIGHT, GOLD_PALE, GOLD_INK = "#9d8552", "#c4a565", "#e9d9a6", "#7a6537"
SILVER, STEEL, GRAPHITE, COPPER, BLACK = "#b4b7bf", "#44608a", "#1d1d1f", "#a8623f", "#0b0b0c"
SILVER_EDGE, TRACK = "#7f828a", "#f3f1ec"      # the light silver bar carries a darker edge, and the track is light enough, for 3:1 against every bar
GREEN, RED, ORANGE = "#2f6b4f", "#8c2f2a", "#8a5a1c"
BG = PAPER
# the four training conditions and the experimental arm: lightness and hue both differ, and the experimental arm is always hatched
COND = {"1_isolated": SILVER, "2_sharing": GOLD, "3_federated": STEEL, "4_centralized": GRAPHITE, "fp": COPPER}
TEAL, INDIGO, AMBER, SLATE = GOLD, STEEL, COPPER, SILVER      # names used before the redesign; kept so that older calls still work

CSS = """
<style>
@font-face { font-family: 'Inter'; font-style: normal; font-weight: 100 900; font-display: swap; src: url('/app/static/inter-latin-wght-normal.woff2') format('woff2'); }
@font-face { font-family: 'Source Serif 4'; font-style: normal; font-weight: 200 900; font-display: swap; src: url('/app/static/source-serif-4-latin-wght-normal.woff2') format('woff2'); }
@font-face { font-family: 'Source Serif 4'; font-style: italic; font-weight: 200 900; font-display: swap; src: url('/app/static/source-serif-4-latin-wght-italic.woff2') format('woff2'); }
@font-face { font-family: 'JetBrains Mono'; font-style: normal; font-weight: 100 800; font-display: swap; src: url('/app/static/jetbrains-mono-latin-wght-normal.woff2') format('woff2'); }
:root { --paper:#fbfbf9; --paper-deep:#f4efe3; --veil:#fdfcf7; --card:#ffffff; --silver:#f5f5f7; --silver2:#e8e8ed; --ink:#1d1d1f; --ink2:#424245; --muted:#6e6e73; --faint:#86868b;
        --line:#e3e0d8; --line2:#eeebe4; --gold:#9d8552; --gold2:#c4a565; --gold3:#e9d9a6; --gold-ink:#7a6537; --gold-soft:rgba(157,133,82,.11); --steel:#44608a; --copper:#a8623f; --black:#0b0b0c;
        --ok:#2f6b4f; --warn:#8a5a1c; --no:#8c2f2a; --bg:#fbfbf9; --teal:#9d8552;
        --serif:'Source Serif 4','Iowan Old Style','Palatino Linotype',Palatino,Georgia,serif; --sans:'Inter',-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;
        --mono:'JetBrains Mono',ui-monospace,SFMono-Regular,Menlo,monospace; --ease:cubic-bezier(.2,.7,.2,1);
        --shadow:0 1px 2px rgba(40,30,10,.04),0 4px 14px rgba(40,30,10,.05); --shadow2:0 10px 30px rgba(40,30,10,.10),0 30px 80px rgba(40,30,10,.10);
        --metal-gold:linear-gradient(100deg,#8a7443 0%,#c4a565 26%,#f3e6bd 44%,#c4a565 60%,#9d8552 100%); --metal-silver:linear-gradient(180deg,#ffffff 0%,#e8e8ed 46%,#a9abb3 100%); }
html, body, .stApp { font-family: var(--sans); -webkit-font-smoothing: antialiased; -moz-osx-font-smoothing: grayscale; text-rendering: optimizeLegibility; }
.stApp { background: var(--paper); }
[data-testid="stHeader"], [data-testid="stToolbar"], [data-testid="stSidebar"], [data-testid="stSidebarCollapsedControl"], [data-testid="stStatusWidget"], footer { display: none !important; }
.stMainBlockContainer { max-width: 1200px; padding: 0.4rem 2rem 2.5rem 2rem; }
h1, h2, h3 { font-family: var(--serif) !important; color: var(--ink); letter-spacing: -0.025em; font-weight: 500 !important; }
h4, h5, h6 { font-family: var(--sans) !important; color: var(--ink); letter-spacing: -0.012em; }
p, li { color: var(--ink2); line-height: 1.62; letter-spacing: -0.006em; }
.stMarkdown a, .stCaption a { color: var(--ink); text-decoration: underline; text-decoration-color: var(--gold2); text-underline-offset: 3px; text-decoration-thickness: 1.5px; }
.stMarkdown a:hover { color: var(--gold-ink); }
[data-testid="stCaptionContainer"], [data-testid="stCaptionContainer"] p { color: var(--muted) !important; font-size: .84rem; line-height: 1.55; }
::selection { background: rgba(196,165,101,.32); }
:focus-visible { outline: 2px solid var(--gold) !important; outline-offset: 2px !important; }

/* ---------- motion vocabulary ---------- */
@keyframes tp-rise { from { opacity: 0; transform: translateY(26px); } to { opacity: 1; transform: none; } }
@keyframes tp-settle { from { opacity: 0; transform: translateY(14px); filter: blur(7px); } to { opacity: 1; transform: none; filter: blur(0); } }
@keyframes tp-grow { from { transform: scaleX(0); } to { transform: scaleX(1); } }
@keyframes tp-fill { from { transform: scaleX(0); } to { transform: scaleX(1); } }
@keyframes tp-pop { 0% { transform: scale(.6); } 60% { transform: scale(1.12); } 100% { transform: scale(1); } }
@keyframes tp-sheen { 0% { background-position: 120% 0; } 45%, 100% { background-position: -40% 0; } }
@keyframes tp-move { 0% { offset-distance: 0%; opacity: 0; } 12% { opacity: 1; } 88% { opacity: 1; } 100% { offset-distance: 100%; opacity: 0; } }
@keyframes tp-pulse { 0%, 100% { opacity: .35; } 50% { opacity: 1; } }
@keyframes tp-ridge-in { from { opacity: 0; stroke-dashoffset: 140; } to { opacity: 1; stroke-dashoffset: 0; } }
@keyframes tp-sweep { 0% { transform: translateX(0); } 36%, 100% { transform: translateX(var(--tw)); } }
@keyframes tp-float { 0%, 100% { transform: translateY(0); } 50% { transform: translateY(-7px); } }

/* ---------- top navigation: a pane of glass ---------- */
[data-testid='stLayoutWrapper']:has(> .st-key-tp_nav) { position: sticky; top: 12px; z-index: 99; }
[data-testid='stLayoutWrapper']:has(> .st-key-tp_nav)::before { content: ''; position: absolute; left: -2rem; right: -2rem; top: -14px; height: 46px; background: linear-gradient(var(--paper) 45%, rgba(251,251,249,0)); z-index: -1; pointer-events: none; }
.st-key-tp_nav { position: relative; background: rgba(253,252,247,.84); backdrop-filter: saturate(180%) blur(22px); -webkit-backdrop-filter: saturate(180%) blur(22px);
                 border: 1px solid rgba(227,224,216,.9); border-radius: 18px; padding: 7px 10px 7px 18px; margin-top: 8px; box-shadow: 0 1px 0 rgba(255,255,255,.8) inset, 0 8px 30px rgba(40,30,10,.06); }
.st-key-tp_nav [data-testid="stHorizontalBlock"] { align-items: center; gap: 2px; }
.st-key-tp_nav [data-testid="stPageLink-NavLink"] { justify-content: center; border-radius: 10px; padding: 8px 4px; background: transparent !important; transition: background .3s var(--ease); }
.st-key-tp_nav [data-testid="stPageLink-NavLink"] p { font-size: 0.82rem; font-weight: 500; color: var(--ink2); white-space: nowrap; letter-spacing: -0.008em; transition: color .3s var(--ease); }
.st-key-tp_nav [data-testid="stPageLink-NavLink"]:hover p { color: var(--ink); }
.st-key-tp_nav [data-testid="stPageLink-NavLink"]:hover { background: rgba(29,29,31,.045) !important; }
.st-key-tp_nav [class*="st-key-tp_on"] [data-testid="stPageLink-NavLink"] p { color: var(--ink); font-weight: 650; }
.st-key-tp_nav [class*="st-key-tp_on"] [data-testid="stPageLink-NavLink"] { position: relative; }
.st-key-tp_nav [class*="st-key-tp_on"] [data-testid="stPageLink-NavLink"]::after { content: ''; position: absolute; left: 50%; bottom: 2px; width: 18px; height: 2px; margin-left: -9px; border-radius: 2px; background: var(--metal-gold); }
.tp-logo { display: flex; align-items: center; gap: 10px; text-decoration: none; }
.st-key-tp_nav .tp-logo { margin: 0; }
.st-key-tp_nav [data-testid='stMarkdownContainer'] { margin-bottom: 0 !important; }
.st-key-tp_nav [data-testid='stMarkdownContainer'] p { margin: 0; }
.tp-logo .w { font-family: var(--sans); font-weight: 650; font-size: 1.12rem; letter-spacing: -0.03em; color: var(--ink); }
.tp-logo .w b { font-weight: 400; color: var(--gold-ink); }
.tp-logo.on-dark .w { background: var(--metal-silver); -webkit-background-clip: text; background-clip: text; color: transparent; } .tp-logo.on-dark .w b { color: var(--gold2); -webkit-text-fill-color: var(--gold2); }
.tp-navstatic { display:flex; gap:18px; align-items:center; font-size:.82rem; font-weight:500; color: var(--ink2); }

/* ---------- buttons: pills ---------- */
.stButton > button, .stDownloadButton > button, [data-testid="stFormSubmitButton"] > button, [data-testid="stBaseButton-secondary"] { border-radius: 980px !important; font-weight: 600; border: 1px solid #cfcabd; background: rgba(255,255,255,.8); color: var(--ink);
    padding: 0.56rem 1.25rem; letter-spacing: -0.01em; transition: transform .35s var(--ease), box-shadow .35s var(--ease), background .25s, border-color .25s; }
.stButton > button:hover, .stDownloadButton > button:hover { border-color: var(--ink); color: var(--ink); background: #fff; transform: translateY(-1px); box-shadow: var(--shadow); }
.stButton > button:active, .stDownloadButton > button:active { transform: translateY(0) scale(.985); }
.stButton > button[kind="primary"], .stDownloadButton > button[kind="primary"], [data-testid="stFormSubmitButton"] > button { background: var(--ink); border: 1px solid var(--ink); }
.stButton > button[kind="primary"] p, .stDownloadButton > button[kind="primary"] p, [data-testid="stFormSubmitButton"] > button p { color: #fff !important; }
.stButton > button[kind="primary"]:hover, .stDownloadButton > button[kind="primary"]:hover, [data-testid="stFormSubmitButton"] > button:hover { background: #000; border-color: #000; box-shadow: 0 8px 24px rgba(0,0,0,.18); }
.stButton > button:disabled { opacity: .45; transform: none; box-shadow: none; }
[class*="st-key-cta_"] [data-testid="stPageLink-NavLink"] { border-radius: 980px; padding: 12px 24px; justify-content: center; width: fit-content; transition: transform .35s var(--ease), box-shadow .35s var(--ease), background .25s; }
[class*="st-key-cta_"] [data-testid="stPageLink-NavLink"] p { font-weight: 600; font-size: .95rem; letter-spacing: -0.01em; white-space: nowrap; }
[class*="st-key-cta_"] [data-testid="stPageLink-NavLink"]:hover { transform: translateY(-1px); }
[class*="st-key-cta_dark"] [data-testid="stPageLink-NavLink"] { background: var(--ink) !important; }
[class*="st-key-cta_dark"] [data-testid="stPageLink-NavLink"] p { color: #fff; }
[class*="st-key-cta_dark"] [data-testid="stPageLink-NavLink"]:hover { background: #000 !important; box-shadow: 0 8px 24px rgba(0,0,0,.18); }
[class*="st-key-cta_light"] [data-testid="stPageLink-NavLink"] { background: transparent !important; border: 1px solid #cfcabd; padding: 10px 22px; margin-top: 8px; }
[class*="st-key-cta_light"] [data-testid="stPageLink-NavLink"] p { color: var(--ink); }
[class*="st-key-cta_light"] [data-testid="stPageLink-NavLink"] p::after { content: ' \\2192'; color: var(--gold); }
[class*="st-key-cta_light"] [data-testid="stPageLink-NavLink"]:hover { border-color: var(--ink); background: #fff !important; }
[class*="st-key-cta_onhero"] [data-testid="stPageLink-NavLink"] { background: var(--silver) !important; }
[class*="st-key-cta_onhero"] [data-testid="stPageLink-NavLink"] p { color: var(--ink); }
[class*="st-key-cta_onhero"] [data-testid="stPageLink-NavLink"]:hover { background: #fff !important; box-shadow: 0 10px 34px rgba(196,165,101,.28); }

/* ---------- the stage: the graphite hero of the opening page ---------- */
.st-key-tp_hero { position: relative; overflow: hidden; isolation: isolate; border-radius: 34px; margin: 20px 0 0 0; padding: 84px 66px 74px 66px;
                  background: radial-gradient(860px 640px at 79% 44%, #2b2b30 0%, #141416 46%, #0b0b0c 80%); box-shadow: 0 30px 80px rgba(20,16,8,.26), 0 0 0 1px rgba(255,255,255,.04) inset; }
.st-key-tp_hero::before { content: ''; position: absolute; right: 9%; top: 18%; width: 460px; height: 460px; border-radius: 50%; background: radial-gradient(circle, rgba(196,165,101,.22), transparent 64%); filter: blur(26px); z-index: -1; }
.st-key-tp_hero [data-testid="stHorizontalBlock"] { align-items: center; }
.st-key-tp_hero h1 { font-family: var(--serif) !important; color: #f5f5f7 !important; font-size: clamp(2.2rem, 3.75vw, 3.4rem) !important; white-space: nowrap; line-height: 1.07 !important; font-weight: 470 !important; letter-spacing: -0.034em;
                     margin: 22px 0 24px 0 !important; padding: 0 !important; position: relative; z-index: 3; }
.st-key-tp_hero h1 .s { background: var(--metal-silver); -webkit-background-clip: text; background-clip: text; color: transparent; }
.st-key-tp_hero h1 em { font-style: italic; font-weight: 420; background: var(--metal-gold); background-size: 220% 100%; -webkit-background-clip: text; background-clip: text; color: transparent; padding-right: .08em; animation: tp-sheen 9s var(--ease) 1.6s infinite; }
.st-key-tp_hero [data-testid="stColumn"]:nth-child(1) { position: relative; z-index: 2; }
.st-key-tp_hero p.lead { color: #a1a1a6; font-size: 1.08rem; line-height: 1.58; max-width: 510px; margin: 0 0 30px 0; letter-spacing: -0.012em; }
.st-key-tp_hero .tp-eyebrow { color: var(--gold2); }
.st-key-tp_hero [class*="st-key-cta_dark"] [data-testid="stPageLink-NavLink"] { background: transparent !important; border: 1px solid rgba(255,255,255,.3); padding: 11px 23px; }
.st-key-tp_hero [class*="st-key-cta_dark"] [data-testid="stPageLink-NavLink"]:hover { background: rgba(255,255,255,.08) !important; border-color: rgba(255,255,255,.6); box-shadow: none; }
.st-key-tp_hero [data-testid="stColumn"]:nth-child(1) [data-testid="stMarkdownContainer"], .st-key-tp_hero [data-testid="stColumn"]:nth-child(1) [data-testid="stHorizontalBlock"] { animation: tp-rise 1s var(--ease) both; }
.st-key-tp_hero [data-testid="stColumn"]:nth-child(1) [data-testid="stHorizontalBlock"] { animation-delay: .25s; }
.st-key-tp_hero [data-testid="stColumn"]:nth-child(1) [data-testid="stHorizontalBlock"] { flex-wrap: wrap; gap: 12px; }
.st-key-tp_hero [data-testid="stColumn"]:nth-child(1) [data-testid="stHorizontalBlock"] > [data-testid="stColumn"] { flex: 0 0 auto !important; width: auto !important; min-width: 0 !important; position: static; }
.tp-eyebrow { display: inline-block; font-family: var(--mono); font-size: .7rem; font-weight: 500; letter-spacing: .2em; text-transform: uppercase; color: var(--gold-ink); }
.tp-trust { display: flex; flex-wrap: wrap; gap: 8px 18px; margin-top: 30px; color: #86868b; font-family: var(--mono); font-size: .61rem; letter-spacing: .1em; text-transform: uppercase; animation: tp-rise 1s var(--ease) .45s both; }
.tp-trust span { display: inline-flex; align-items: center; gap: 8px; }
.tp-trust i { width: 5px; height: 5px; border-radius: 50%; background: var(--gold2); display: inline-block; }
.tp-heroart { position: relative; margin: -104px -176px -120px -34px; }
.tp-heroart .tp-art { -webkit-mask-image: linear-gradient(90deg, transparent 2%, #000 40%); mask-image: linear-gradient(90deg, transparent 2%, #000 40%); }
.tp-shot { position: absolute; right: 176px; bottom: 118px; width: 340px; border-radius: 22px; padding: 20px 22px 18px 22px; background: rgba(22,22,24,.66); border: 1px solid rgba(255,255,255,.13);
           backdrop-filter: blur(26px) saturate(160%); -webkit-backdrop-filter: blur(26px) saturate(160%); color: #e8e8ed; box-shadow: 0 30px 80px rgba(0,0,0,.6), 0 1px 0 rgba(255,255,255,.08) inset; animation: tp-rise 1.1s var(--ease) .9s both; }
.tp-shot .t { font-family: var(--mono); font-size: .62rem; color: var(--gold2); letter-spacing: .18em; text-transform: uppercase; }
.tp-shot .n { font-weight: 600; font-size: .92rem; margin: 6px 0 8px 0; color: #f5f5f7; letter-spacing: -0.01em; }
.tp-shot .f { margin-top: 10px; padding-top: 10px; border-top: 1px solid rgba(255,255,255,.1); font-size: .74rem; line-height: 1.5; color: #a1a1a6; }
.tp-shot .f b { color: var(--gold2); font-weight: 600; }

/* ---------- inner-page headers: paper, serif, one gold rule ---------- */
.tp-hero { position: relative; margin: 54px 0 34px 0; padding: 0 0 44px 0; border-bottom: 1px solid var(--line); overflow: hidden; }
.tp-hero .grid { display: grid; grid-template-columns: 1.12fr 0.88fr; gap: 56px; align-items: center; }
.tp-hero.single .grid { grid-template-columns: 1.5fr .5fr; }
.tp-hero .grid > div:nth-child(1) { animation: tp-rise .9s var(--ease) both; }
.tp-hero h1 { color: var(--ink) !important; font-size: clamp(2.2rem, 3.9vw, 3.5rem) !important; line-height: 1.06 !important; font-weight: 480 !important; letter-spacing: -0.032em; margin: 18px 0 20px 0 !important; padding: 0 !important; text-wrap: balance; }
.tp-hero h1.long { font-size: clamp(1.7rem, 2.6vw, 2.35rem) !important; line-height: 1.16 !important; }
.tp-hero h1 em { font-style: italic; font-weight: 430; background: var(--metal-gold); -webkit-background-clip: text; background-clip: text; color: transparent; padding-right: .08em; }
.tp-hero .tp-eyebrow::after { content: ''; display: block; width: 46px; height: 2px; background: var(--metal-gold); margin-top: 16px; border-radius: 2px; }
.tp-hero p.lead { color: var(--muted); font-size: 1.16rem; line-height: 1.6; max-width: 680px; margin: 0; letter-spacing: -0.012em; text-wrap: pretty; }
.tp-hero .quiet { opacity: .92; }
.tp-hero .quiet .tp-art { width: 232px; margin: -6px 0 -30px auto; }

/* ---------- sections, cards, stats ---------- */
.tp-grid { display: grid; gap: 20px !important; align-items: stretch; margin: 8px 0 4px 0; }
.tp-grid > div { height: 100%; }
.tp-sec { margin: 92px 0 26px 0; }
.tp-sec .k { font-family: var(--mono); font-size: .7rem; font-weight: 500; letter-spacing: .2em; text-transform: uppercase; color: var(--gold-ink); }
.tp-sec h2 { font-size: clamp(1.8rem, 3vw, 2.6rem) !important; font-weight: 480 !important; line-height: 1.1 !important; letter-spacing: -0.03em; margin: 12px 0 12px 0 !important; padding: 0 !important; text-wrap: balance; }
.tp-sec p { color: var(--muted); font-size: 1.1rem; line-height: 1.6; max-width: 720px; margin: 0; letter-spacing: -0.01em; text-wrap: pretty; }
.tp-sec p b { color: var(--ink); font-weight: 600; }
.tp-sec.tight { margin-top: 44px; } .tp-sec.tight h2 { font-size: 1.55rem !important; }
.tp-card { position: relative; background: var(--card); border: 1px solid var(--line2); border-radius: 22px; padding: 26px 26px 24px 26px; height: 100%; box-shadow: var(--shadow); transition: transform .6s var(--ease), box-shadow .6s var(--ease), border-color .4s; }
.tp-card:hover { transform: translateY(-4px); box-shadow: var(--shadow2); border-color: var(--line); }
.tp-card h5 { margin: 14px 0 8px 0; font-size: 1.06rem; font-weight: 600; color: var(--ink); letter-spacing: -0.018em; line-height: 1.3; padding: 0; }
.tp-card p { margin: 0; font-size: .93rem; color: var(--muted); line-height: 1.58; }
.tp-card:not(.tp-step):not(.tp-sample) > h5 { font-family: var(--serif) !important; font-size: 1.24rem; font-weight: 500; letter-spacing: -0.02em; }
[data-testid="stTextInput"] button { background: transparent !important; border: none !important; }
.tp-ico { width: 42px; height: 42px; border-radius: 50%; display: inline-flex; align-items: center; justify-content: center; background: transparent; color: var(--ink); border: 1px solid var(--line); }
.tp-ico svg { stroke-width: 1.5; width: 19px; height: 19px; }
.tp-ico.amber { border-color: var(--gold2); color: var(--gold-ink); }
.tp-step .no { position: absolute; right: 24px; top: 30px; font-family: var(--mono); font-size: .62rem; font-weight: 500; letter-spacing: .18em; text-transform: uppercase; color: var(--gold-ink); }
.tp-step .no.num { top: 24px; font-family: var(--serif); font-size: 2.1rem; line-height: 1; font-weight: 400; color: transparent; background: var(--metal-gold); -webkit-background-clip: text; background-clip: text; letter-spacing: -0.04em; text-transform: none; }
.tp-step:not(:has(.tp-ico)) .no { position: static; margin-bottom: 4px; }
.tp-stats { display: grid; grid-template-columns: repeat(4, 1fr); gap: 0; margin: 64px 0 22px 0; border-top: 1px solid var(--line); border-bottom: 1px solid var(--line); }
.tp-stat { padding: 34px 28px 32px 28px; border-left: 1px solid var(--line2); }
.tp-stat:nth-child(1) { border-left: none; padding-left: 4px; }
.tp-stat .v { font-family: var(--serif); font-size: 3.3rem; font-weight: 400; color: var(--ink); letter-spacing: -0.04em; line-height: 1; font-variant-numeric: lining-nums; }
.tp-stat .v.long { font-size: 2.15rem; line-height: 1.12; letter-spacing: -0.03em; padding-top: 6px; }
.tp-stat .v small { font-family: var(--sans); font-size: .95rem; color: var(--muted); font-weight: 500; letter-spacing: -0.01em; margin-left: 4px; }
.tp-stat .l { font-size: .86rem; color: var(--muted); margin-top: 12px; line-height: 1.45; max-width: 230px; }
.tp-stat .bar { display: none; }
.tp-stat.amber .v { background: var(--metal-gold); -webkit-background-clip: text; background-clip: text; color: transparent; }
.tp-chip { display: inline-flex; align-items: center; gap: 6px; padding: 4px 11px; border-radius: 999px; background: transparent; border: 1px solid var(--line); color: var(--ink2); font-size: .74rem; font-weight: 500; margin: 0 6px 6px 0; letter-spacing: -0.004em; }
.tp-chip.teal { background: var(--gold-soft); border-color: transparent; color: var(--gold-ink); } .tp-chip.indigo { background: var(--silver); border-color: transparent; color: var(--ink2); }
.tp-chip.amber { background: var(--paper-deep); border-color: transparent; color: var(--warn); } .tp-chip.dark { background: var(--ink); border-color: var(--ink); color: #fff; }
.tp-badge { display: inline-flex; align-items: center; gap: 7px; padding: 3px 10px 3px 9px; border-radius: 999px; font-size: .72rem; font-weight: 600; white-space: nowrap; border: 1px solid var(--line); color: var(--ink2); background: #fff; letter-spacing: -0.004em; }
.tp-badge::before { content: ''; width: 6px; height: 6px; border-radius: 50%; background: var(--faint); flex: 0 0 6px; }
.tp-badge.ok { color: var(--ok); border-color: rgba(47,107,79,.28); } .tp-badge.ok::before { background: var(--ok); }
.tp-badge.no { color: var(--no); border-color: rgba(140,47,42,.28); } .tp-badge.no::before { background: var(--no); }
.tp-badge.warn { color: var(--warn); border-color: rgba(138,90,28,.3); } .tp-badge.warn::before { background: var(--warn); }
.tp-badge.amber { color: var(--gold-ink); border-color: rgba(157,133,82,.4); background: var(--veil); } .tp-badge.amber::before { background: var(--gold2); }
.tp-callout { background: var(--paper-deep); border: none; border-left: 2px solid var(--gold); border-radius: 0 16px 16px 0; padding: 18px 24px; color: var(--ink2); margin: 14px 0; font-size: .95rem; line-height: 1.6; }
.tp-callout b { color: var(--ink); }
.tp-note { background: var(--veil); border: 1px solid var(--line2); border-radius: 18px; padding: 20px 26px; color: var(--ink2); font-size: .93rem; }
.tp-note p { margin: 0 0 10px 0; font-size: .93rem; } .tp-note p:last-child { margin: 0; }
.tp-legend { display: flex; flex-wrap: wrap; gap: 8px 22px; font-size: .78rem; color: var(--ink2); margin: 4px 0 14px 0; }
.tp-legend span { display: inline-flex; align-items: center; gap: 8px; }
.tp-legend i { width: 18px; height: 6px; border-radius: 3px; display: inline-block; }
.tp-legend i.c { width: 9px; height: 9px; border-radius: 50%; } .tp-legend i.d { width: 8px; height: 8px; border-radius: 1px; transform: rotate(45deg); } .tp-legend i.q { width: 9px; height: 9px; border-radius: 1px; }
.tp-legend i.x { background-image: repeating-linear-gradient(45deg, rgba(255,255,255,.75) 0 2px, transparent 2px 4px); }
.tp-org { background: var(--card); border: 1px solid var(--line2); border-radius: 22px; padding: 24px 24px 18px 24px; box-shadow: var(--shadow); height: 100%; transition: box-shadow .6s var(--ease), transform .6s var(--ease); }
.tp-org:hover { box-shadow: var(--shadow2); transform: translateY(-3px); }
.tp-org .top { display: flex; justify-content: space-between; align-items: flex-start; gap: 8px; }
.tp-org .name { font-family: var(--serif); font-weight: 500; font-size: 1.32rem; color: var(--ink); letter-spacing: -0.02em; line-height: 1.2; }
.tp-org .meta { font-size: .78rem; color: var(--muted); margin: 6px 0 12px 0; line-height: 1.45; }
.tp-org .lab { font-family: var(--mono); font-size: .62rem; font-weight: 500; letter-spacing: .16em; color: var(--muted); text-transform: uppercase; margin: 14px 0 8px 0; }
.tp-org .sub { font-size: .78rem; color: var(--muted); margin-top: 10px; line-height: 1.5; }
.tp-org .sub b { color: var(--ink); font-weight: 600; }
.tp-org .row { display: flex; justify-content: space-between; align-items: center; gap: 10px; font-size: .8rem; color: var(--ink2); padding: 7px 0; border-top: 1px solid var(--line2); }
.tp-org .sep { border-top: 1px solid var(--line2); margin-top: 12px; padding-top: 12px; }
.tp-hyp { background: var(--card); border: 1px solid var(--line2); border-radius: 22px; padding: 22px 24px; box-shadow: var(--shadow); height: 100%; }
.tp-hyp.exp { background: var(--veil); border-color: rgba(168,98,63,.28); border-style: dashed; }
.tp-hyp .h { display: flex; justify-content: space-between; align-items: center; gap: 8px; }
.tp-hyp .h b { font-family: var(--mono); font-size: .64rem; font-weight: 500; letter-spacing: .16em; color: var(--muted); }
.tp-hyp .big { font-family: var(--serif); font-size: 2.7rem; font-weight: 400; letter-spacing: -0.04em; color: var(--ink); margin-top: 14px; line-height: 1; }
.tp-hyp .big small { font-family: var(--sans); font-size: .86rem; color: var(--muted); font-weight: 500; letter-spacing: -0.01em; }
.tp-hyp .d { font-size: .82rem; color: var(--muted); margin-top: 10px; line-height: 1.5; }
.tp-dshead { background: transparent; border: none; border-top: 1px solid var(--line); padding: 30px 0 4px 0; margin-top: 18px; }
.tp-dshead h3 { margin: 0 0 8px 0 !important; padding: 0 !important; font-size: 2rem !important; font-weight: 480 !important; letter-spacing: -0.028em; line-height: 1.15 !important; }
.tp-dshead p { margin: 0 0 16px 0; color: var(--muted); font-size: .98rem; max-width: 860px; }
.tp-term { background: linear-gradient(180deg, #1f1f22, #121214); color: #c7c7cc; border-radius: 20px; padding: 18px 22px 20px 22px; font-family: var(--mono) !important; font-size: .74rem; line-height: 1.68;
           box-shadow: var(--shadow2), 0 1px 0 rgba(255,255,255,.08) inset; border: 1px solid #2c2c2e; white-space: pre-wrap; overflow: hidden; animation: tp-rise 1s var(--ease) .2s both; }
.tp-term * { font-family: var(--mono) !important; }
.tp-term .dots { display: flex; gap: 7px; margin-bottom: 14px; } .tp-term .dots i { width: 10px; height: 10px; border-radius: 50%; background: #3a3a3c; display: inline-block; }
.tp-term .c { color: var(--gold2); } .tp-term .g { color: #a8c7a0; } .tp-term .m { color: #86868b; } .tp-term .y { color: var(--gold3); }
.tp-quote { position: relative; background: transparent; border: none; border-left: 2px solid var(--gold); border-radius: 0; padding: 6px 0 6px 30px; font-family: var(--serif); font-size: 1.42rem; font-weight: 400; color: var(--ink); line-height: 1.5; letter-spacing: -0.014em; max-width: 980px; text-wrap: pretty; }
.tp-quote.amber { border-left-color: var(--line); color: var(--ink2); }
.tp-pair { display: grid; grid-template-columns: 1fr 1fr 200px; gap: 0; background: var(--card); border: 1px solid var(--line2); border-radius: 22px; overflow: hidden; box-shadow: var(--shadow); margin-bottom: 16px; }
.tp-pair > div { padding: 22px 26px; font-size: .95rem; color: var(--ink2); line-height: 1.55; }
.tp-pair > div + div { border-left: 1px solid var(--line2); }
.tp-pair .tag { font-family: var(--mono); font-size: .66rem; font-weight: 500; letter-spacing: .18em; color: var(--gold-ink); display: block; margin-bottom: 8px; }
.tp-pair .res { display: flex; flex-direction: column; justify-content: center; align-items: flex-start; gap: 8px; background: var(--veil); }
.tp-pair .res .v { font-family: var(--serif); font-weight: 400; font-size: 1.75rem; white-space: nowrap; color: var(--ink); letter-spacing: -0.035em; line-height: 1; }
.tp-pair .res .s { font-size: .76rem; color: var(--muted); line-height: 1.4; }
.tp-list { list-style: none; padding: 0; margin: 0; }
.tp-list li { display: flex; gap: 12px; align-items: flex-start; padding: 11px 0; border-bottom: 1px solid var(--line2); font-size: .93rem; color: var(--ink2); }
.tp-list li:last-child { border-bottom: none; }
.tp-list .i { flex: 0 0 22px; height: 22px; border-radius: 50%; display: inline-flex; align-items: center; justify-content: center; margin-top: 1px; border: 1px solid var(--line); }
.tp-list .i.ok { background: var(--ink); border-color: var(--ink); color: #fff; } .tp-list .i.wait { background: var(--veil); border-color: var(--gold2); color: var(--gold-ink); } .tp-list .i.no { background: transparent; color: var(--faint); }
.tp-stephead { display: flex; gap: 16px; align-items: center; margin: 44px 0 12px 0; }
.tp-stephead .n { flex: 0 0 38px; height: 38px; border-radius: 50%; border: 1px solid var(--gold2); color: var(--gold-ink); display: inline-flex; align-items: center; justify-content: center; font-family: var(--serif); font-size: 1.15rem; font-weight: 500; }
.tp-stephead .t { font-family: var(--serif); font-weight: 500; font-size: 1.45rem; color: var(--ink); letter-spacing: -0.022em; line-height: 1.2; }
.tp-stephead .s { color: var(--muted); font-size: .92rem; margin-top: 2px; }
.tp-mini { font-family: var(--mono); font-size: .64rem; font-weight: 500; letter-spacing: .16em; color: var(--muted); text-transform: uppercase; }
.tp-footer { margin-top: 110px; padding: 34px 0 10px 0; border-top: 1px solid var(--line); color: var(--muted); font-size: .8rem; line-height: 1.6; display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: 40px; align-items: end; }
.tp-footer b { color: var(--ink); font-weight: 600; }
.tp-footer .r { text-align: right; font-family: var(--mono); font-size: .68rem; letter-spacing: .04em; line-height: 1.9; }

/* ---------- tables ---------- */
table.tp { border-collapse: separate; border-spacing: 0; width: 100%; font-size: .84rem; margin: 8px 0 14px 0; background: var(--card); border: 1px solid var(--line2); border-radius: 18px; overflow: hidden; box-shadow: var(--shadow); }
table.tp th { text-align: left; vertical-align: bottom; font-family: var(--mono); font-weight: 500; color: var(--muted); background: var(--veil); border-bottom: 1px solid var(--line) !important; padding: 13px 14px; font-size: .62rem; letter-spacing: .12em; text-transform: uppercase; line-height: 1.5; }
table.tp td { border-bottom: 1px solid var(--line2); padding: 11px 14px; white-space: nowrap; vertical-align: middle; color: var(--ink2); font-variant-numeric: tabular-nums; }
table.tp tr:last-child td { border-bottom: none; }
table.tp th, table.tp td { border-left: none !important; border-right: none !important; border-top: none !important; }
table.tp td.wrap, table.tp th.wrap { white-space: normal; }
table.tp td.heat { text-align: center; font-weight: 600; font-variant-numeric: tabular-nums; color: var(--ink); }
table.tp tr.exp td { background: var(--veil); }
table.tp tbody tr { transition: background .25s; } table.tp tbody tr:hover td:not(.heat) { background: var(--veil); }

/* ---------- the live demo ---------- */
.tp-rail { display: grid; grid-template-columns: repeat(6, minmax(0, 1fr)); background: rgba(255,255,255,.7); border: 1px solid var(--line2); border-radius: 22px; box-shadow: var(--shadow); padding: 22px 10px 16px 10px; margin: 8px 0 12px 0; }
.tp-rail .s { position: relative; text-align: center; padding: 0 6px; }
.tp-rail .s:not(:last-child)::before { content: ''; position: absolute; top: 17px; left: calc(50% + 26px); width: calc(100% - 52px); height: 1px; background: var(--line); }
.tp-rail .s.done:not(:last-child)::after { content: ''; position: absolute; top: 16px; left: calc(50% + 26px); width: calc(100% - 52px); height: 3px; border-radius: 2px; background: var(--metal-gold); transform-origin: left center; }
.tp-rail .s.new:not(:last-child)::after { animation: tp-fill .8s var(--ease) both; }
.tp-rail .n { width: 36px; height: 36px; border-radius: 50%; display: inline-flex; align-items: center; justify-content: center; font-family: var(--serif); font-weight: 500; font-size: 1rem; background: var(--paper); color: var(--muted); border: 1px solid var(--line); position: relative; z-index: 1; }
.tp-rail .s.done .n { background: var(--ink); color: var(--gold3); border-color: var(--ink); }
.tp-rail .s.new .n { animation: tp-pop .55s var(--ease) both; }
.tp-rail .s.now .n { background: #fff; color: var(--ink); border-color: var(--gold); box-shadow: 0 0 0 5px var(--gold-soft); animation: tp-pulse-ring 1.6s ease-in-out infinite; }
@keyframes tp-pulse-ring { 0%, 100% { box-shadow: 0 0 0 4px rgba(157,133,82,.10); } 50% { box-shadow: 0 0 0 9px rgba(157,133,82,.18); } }
.tp-rail .t { font-size: .84rem; font-weight: 600; color: var(--ink); margin-top: 10px; letter-spacing: -0.01em; }
.tp-rail .s.todo .t { color: var(--muted); font-weight: 500; }
.tp-rail .e { font-family: var(--mono); font-size: .64rem; letter-spacing: .06em; color: var(--muted); min-height: 1.3em; margin-top: 2px; }
[class*="st-key-tp_stage"] { background: var(--card); border: 1px solid var(--line2); border-radius: 26px; padding: 30px 34px 26px 34px; box-shadow: var(--shadow); margin-top: 20px; animation: tp-rise .8s var(--ease) both; }
.tp-stagehead { display: flex; align-items: center; gap: 18px; }
.tp-stagehead .n { flex: 0 0 46px; height: 46px; border-radius: 50%; background: var(--ink); color: var(--gold3); display: inline-flex; align-items: center; justify-content: center; font-family: var(--serif); font-weight: 500; font-size: 1.3rem; }
.tp-stagehead .k { font-family: var(--mono); font-size: .64rem; font-weight: 500; letter-spacing: .18em; text-transform: uppercase; color: var(--gold-ink); }
.tp-stagehead .t { font-family: var(--serif); font-size: 1.7rem; font-weight: 500; color: var(--ink); letter-spacing: -0.026em; line-height: 1.2; }
.tp-stagehead .r { margin-left: auto; display: flex; gap: 6px; align-items: center; }
.tp-what { border-left: 2px solid var(--gold); background: var(--veil); border-radius: 0 14px 14px 0; padding: 14px 20px; margin: 18px 0 14px 0; color: var(--ink2); font-size: .97rem; line-height: 1.6; }
.tp-what b { color: var(--ink); }
.tp-sample { display: flex; flex-direction: column; gap: 6px; }
.tp-sample .top { display: flex; justify-content: space-between; align-items: center; gap: 8px; }
.tp-sample .sector { font-family: var(--mono); font-size: .62rem; font-weight: 500; letter-spacing: .16em; text-transform: uppercase; color: var(--muted); }
.tp-sample h5 { margin: 10px 0 4px 0 !important; font-family: var(--serif) !important; font-size: 1.35rem !important; font-weight: 500 !important; letter-spacing: -0.022em !important; }
.tp-sample .lic { font-size: .76rem; color: var(--muted); margin-top: auto; padding-top: 12px; border-top: 1px solid var(--line2); line-height: 1.5; }
.tp-kv { display: grid; grid-template-columns: max-content 1fr; gap: 8px 22px; font-size: .93rem; color: var(--ink2); margin: 6px 0; }
.tp-kv dt { font-weight: 600; color: var(--ink); }
.tp-kv dd { margin: 0; }
.tp-band { display: flex; justify-content: space-between; align-items: center; gap: 18px; flex-wrap: wrap; background: var(--paper-deep); border: none; border-radius: 22px; padding: 22px 30px; margin: 12px 0; }
.tp-band .t { font-family: var(--serif); font-size: 1.4rem; font-weight: 500; color: var(--ink); letter-spacing: -0.022em; }
.tp-band .d { color: var(--ink2); font-size: .92rem; line-height: 1.5; }
[class*="st-key-tp_band"] { position: relative; overflow: hidden; background: radial-gradient(700px 300px at 88% 50%, #2b2b30 0%, #141416 55%, #0b0b0c 100%); border-radius: 30px; padding: 44px 48px 50px 48px; margin: 72px 0 8px 0; box-shadow: 0 30px 80px rgba(20,16,8,.2); }
[class*="st-key-tp_band"] .t { font-family: var(--serif); font-size: 2rem; font-weight: 470; color: #f5f5f7; letter-spacing: -0.03em; line-height: 1.15; }
[class*="st-key-tp_band"] .d { color: #a1a1a6; font-size: 1.02rem; line-height: 1.55; margin-top: 10px; max-width: 640px; }
[class*="st-key-tp_band"] [class*="st-key-cta_dark"] [data-testid="stPageLink-NavLink"] { background: var(--silver) !important; margin-left: auto; }
[class*="st-key-tp_band"] [class*="st-key-cta_dark"] [data-testid="stPageLink-NavLink"] p { color: var(--ink); }
[class*="st-key-tp_band"] [class*="st-key-cta_dark"] [data-testid="stPageLink-NavLink"]:hover { background: #fff !important; box-shadow: 0 10px 34px rgba(196,165,101,.28); }

/* ---------- streamlit widgets, made to belong ---------- */
div[data-testid="stExpander"] { background: var(--card); border: 1px solid var(--line2) !important; border-radius: 18px !important; box-shadow: none; overflow: hidden; transition: box-shadow .4s var(--ease), border-color .3s; }
div[data-testid="stExpander"]:hover { border-color: var(--line) !important; box-shadow: var(--shadow); }
div[data-testid="stExpander"] details { border: none !important; border-radius: 18px !important; }
div[data-testid="stExpander"] summary { padding: 15px 20px; } div[data-testid="stExpander"] summary:hover { color: var(--ink); }
div[data-testid="stExpander"] summary p { font-weight: 600; color: var(--ink); font-size: .95rem; letter-spacing: -0.012em; }
div[data-testid="stForm"] { background: transparent; border: none; padding: 0; }
[data-testid="stFileUploaderDropzone"] { background: var(--veil); border: 1px dashed #cfcabd; border-radius: 22px; padding: 30px 28px; transition: border-color .3s, background .3s; }
[data-testid="stFileUploaderDropzone"]:hover { border-color: var(--gold); background: #fff; }
[data-testid="stFileUploaderDropzone"] button { border-radius: 980px !important; }
[data-testid="stAlertContainer"] { border-radius: 16px; border: 1px solid var(--line2); }
[data-testid="stAlertContainer"] p { font-size: .93rem; }
[data-baseweb="select"] > div, [data-baseweb="input"], [data-baseweb="base-input"], [data-baseweb="textarea"] { border-radius: 14px !important; }
[data-baseweb="select"] > div, .stTextInput [data-baseweb="input"], .stTextInput [data-baseweb="base-input"], .stTextInput input, .stMultiSelect [data-baseweb="select"] > div, [data-testid="stSelectbox"] div:has(> input), [data-testid="stMultiSelect"] div:has(> input) { background: #fff !important; }
[data-testid="stSelectbox"] div:has(> input) { border-color: #d6d2c7 !important; border-radius: 14px !important; min-height: 46px; transition: border-color .25s, box-shadow .25s; }
[data-testid="stSelectbox"] div:has(> input):focus-within { border-color: var(--gold) !important; box-shadow: 0 0 0 4px var(--gold-soft) !important; }
[data-baseweb="select"] > div, .stTextInput [data-baseweb="input"] { border: 1px solid #d6d2c7 !important; transition: border-color .25s, box-shadow .25s; min-height: 44px; }
[data-baseweb="select"] > div:hover, .stTextInput [data-baseweb="input"]:hover { border-color: var(--faint) !important; }
[data-baseweb="select"] > div:focus-within, .stTextInput [data-baseweb="input"]:focus-within { border-color: var(--gold) !important; box-shadow: 0 0 0 4px var(--gold-soft) !important; }
[data-baseweb="tag"] { border-radius: 999px !important; background: var(--silver) !important; border: 1px solid var(--line) !important; }
[data-baseweb="tag"] span, [data-baseweb="tag"] svg { color: var(--ink) !important; fill: var(--ink) !important; }
[data-baseweb="popover"] [role="listbox"], [data-baseweb="menu"] { border-radius: 14px !important; }
[data-testid="stWidgetLabel"] p { font-size: .84rem; font-weight: 500; color: var(--ink2); }
[data-baseweb="tab-list"], [role="tablist"] { gap: 30px; border-bottom: 1px solid var(--line); }
[role="tab"] { padding: 12px 0 14px 0 !important; background: transparent !important; }
[role="tab"] p { font-size: 1rem; font-weight: 500; color: var(--muted); letter-spacing: -0.012em; transition: color .25s; } [role="tab"]:hover p { color: var(--ink); } [role="tab"][aria-selected="true"] p { color: var(--ink); font-weight: 600; }
[data-baseweb="tab"] { padding: 12px 0 14px 0 !important; background: transparent !important; }
[data-baseweb="tab"] p { font-size: 1rem; font-weight: 500; color: var(--muted); letter-spacing: -0.012em; transition: color .25s; }
[data-baseweb="tab"]:hover p { color: var(--ink); }
[data-baseweb="tab"][aria-selected="true"] p { color: var(--ink); font-weight: 600; }
[data-baseweb="tab-highlight"] { background: var(--metal-gold) !important; height: 2px !important; border-radius: 2px; }
[data-baseweb="tab-border"] { display: none !important; }
[data-testid="stRadio"] label p, [data-testid="stCheckbox"] label p { font-size: .95rem; color: var(--ink2); }
[data-testid="stDataFrame"] { border-radius: 14px; overflow: hidden; border: 1px solid var(--line2); }
[data-testid="stCode"] pre, .stCode pre { border-radius: 16px !important; background: var(--veil) !important; border: 1px solid var(--line2); font-size: .76rem !important; }
[data-testid="stStatusWidget"] { display: none; }
hr { border-color: var(--line) !important; }

/* ---------- sign-in ---------- */
.st-key-tp_gate_card { background: #fff; border: 1px solid var(--line2); border-radius: 28px; padding: 40px 38px 30px 38px; box-shadow: var(--shadow2); animation: tp-rise 1s var(--ease) .2s both; }
.tp-gate { position: relative; overflow: hidden; isolation: isolate; border-radius: 34px; padding: 50px 46px; color: #fff; min-height: 580px; display: flex; flex-direction: column; justify-content: space-between;
           background: radial-gradient(700px 560px at 76% 62%, #2b2b30 0%, #141416 48%, #0b0b0c 82%); box-shadow: 0 30px 80px rgba(20,16,8,.26); }
.tp-gate .art { position: absolute; right: -230px; bottom: -250px; width: 600px; z-index: -1; opacity: .9; -webkit-mask-image: linear-gradient(115deg, transparent 22%, #000 62%); mask-image: linear-gradient(115deg, transparent 22%, #000 62%); }
.tp-gate h1 { font-family: var(--serif) !important; color: #f5f5f7 !important; font-size: 2.7rem !important; font-weight: 470 !important; letter-spacing: -0.032em; line-height: 1.08 !important; margin: 34px 0 16px 0 !important; padding: 0 !important; }
.tp-gate h1 em { font-style: italic; font-weight: 420; background: var(--metal-gold); -webkit-background-clip: text; background-clip: text; color: transparent; padding-right: .08em; }
.tp-gate p { color: #a1a1a6; font-size: 1.02rem; margin: 0; max-width: 400px; }
.tp-gate ul { list-style: none; padding: 0; margin: 30px 0 0 0; } .tp-gate li { color: #d2d2d7; font-size: .92rem; padding: 8px 0; display: flex; gap: 14px; align-items: center; }
.tp-gate li i { width: 24px; height: 24px; border-radius: 50%; border: 1px solid rgba(196,165,101,.6); color: var(--gold2); display: inline-flex; align-items: center; justify-content: center; font-style: normal; font-family: var(--serif); font-size: .82rem; flex: 0 0 24px; }
.tp-gate .foot { color: #86868b; font-family: var(--mono); font-size: .62rem; letter-spacing: .12em; text-transform: uppercase; }
.tp-gatehead .k { font-family: var(--mono); font-size: .68rem; font-weight: 500; letter-spacing: .2em; color: var(--gold-ink); text-transform: uppercase; }
.tp-gatehead .t { font-family: var(--serif); font-size: 2rem; font-weight: 500; color: var(--ink); letter-spacing: -0.028em; margin: 10px 0 6px 0; line-height: 1.15; }
.tp-gatehead .d { color: var(--muted); font-size: .95rem; margin-bottom: 14px; }

/* ---------- art and charts ---------- */
svg text { font-family: 'Inter', -apple-system, 'Segoe UI', Helvetica, Arial, sans-serif; }
svg text.sf { font-family: 'Source Serif 4', Georgia, serif; }
.tp-art { display: block; overflow: visible; }
.tp-ridge { opacity: 0; animation: tp-ridge-in 1.15s var(--ease) both; animation-delay: calc(var(--k) * 40ms + 180ms); }
.tp-ridge.g { stroke: #c4a565; }
.tp-sweep { animation: tp-sweep 10s cubic-bezier(.4,0,.2,1) 2.4s infinite; }
.tp-chart { display: block; view-timeline-name: --tpc; view-timeline-axis: block; }
.tp-scroll { overflow-x: auto; -webkit-overflow-scrolling: touch; padding-bottom: 6px; }
.tp-bar, .tp-range { transform-box: fill-box; transform-origin: left center; }
.tp-bar.t { animation: tp-grow 1.3s var(--ease) both; animation-delay: calc(var(--i, 0) * 110ms + 1.3s); }
.tp-mv { offset-rotate: 0deg; animation: tp-move 3.6s linear infinite; }
.tp-hub { animation: tp-pulse 3.6s ease-in-out infinite; }
.tp-st { display: none; }

/* scroll-driven: sections rise into place, bars grow, numbers settle (only where the browser supports it; otherwise everything is simply there) */
@media (prefers-reduced-motion: no-preference) { @supports (animation-timeline: view()) {
  .tp-sec, .tp-grid > *, .tp-stats, .tp-quote, .tp-pair, .tp-note, .tp-callout, table.tp, .tp-dshead, .tp-hero .quiet { animation: tp-rise linear both; animation-timeline: view(); animation-range: entry 0% entry 62%; }
  .tp-grid > *:nth-child(2) { animation-range: entry 6% entry 70%; } .tp-grid > *:nth-child(3) { animation-range: entry 12% entry 78%; } .tp-grid > *:nth-child(4) { animation-range: entry 18% entry 86%; } .tp-grid > *:nth-child(5) { animation-range: entry 24% entry 94%; }
  .tp-stat .v, .tp-hyp .big, .tp-pair .res .v { animation: tp-settle linear both; animation-timeline: view(); animation-range: entry 10% entry 100%; }
  .tp-bar:not(.t), .tp-range { animation: tp-grow linear both; animation-timeline: --tpc; animation-range: entry 15% cover 32%; }
} }
@media (prefers-reduced-motion: reduce) { *, *::before, *::after { animation: none !important; transition: none !important; } .tp-ridge { opacity: 1; } .tp-mv { display: none; } .tp-st { display: inline; } }

/* ---------- smaller screens ---------- */
@media (max-width: 1100px) { .st-key-tp_nav [data-testid="stPageLink-NavLink"] p { font-size: .76rem; } .st-key-tp_nav { padding-left: 12px; } .st-key-tp_hero { padding: 64px 44px 58px 44px; } .tp-heroart { margin: -80px -150px -100px -20px; } .tp-shot { right: 150px; bottom: 96px; width: 300px; } .tp-stat { padding: 26px 18px; } .tp-stat .v { font-size: 2.6rem; } }
@media (max-width: 900px) { .tp-grid { grid-template-columns: 1fr 1fr !important; } .tp-hero .grid, .tp-hero.single .grid { grid-template-columns: 1fr; } .tp-hero .quiet { display: none; } .tp-stats { grid-template-columns: 1fr 1fr; } .tp-stat:nth-child(3) { border-left: none; padding-left: 4px; }
  .tp-stat:nth-child(n+3) { border-top: 1px solid var(--line2); } .tp-pair { grid-template-columns: 1fr; } .tp-pair > div + div { border-left: none; border-top: 1px solid var(--line2); }
  .tp-rail { grid-template-columns: repeat(3, minmax(0, 1fr)); row-gap: 18px; } .tp-rail .s::before, .tp-rail .s::after { display: none; } .tp-kv { grid-template-columns: 1fr; } }
@media (max-width: 640px) {
  .stMainBlockContainer { padding: 0.3rem 1.05rem 2rem 1.05rem; }
  .st-key-tp_nav { padding: 6px 8px 6px 12px; border-radius: 16px; }
  .st-key-tp_nav [data-testid="stHorizontalBlock"] { flex-wrap: nowrap !important; overflow-x: auto; gap: 4px; scrollbar-width: none; -webkit-overflow-scrolling: touch; }
  .st-key-tp_nav [data-testid="stHorizontalBlock"]::-webkit-scrollbar { display: none; }
  .st-key-tp_nav [data-testid="stColumn"] { flex: 0 0 auto !important; width: auto !important; min-width: max-content !important; }
  .st-key-tp_nav [data-testid="stPageLink-NavLink"] { padding: 8px 9px; } .tp-logo .w { font-size: 1rem; }
  .tp-grid { grid-template-columns: 1fr !important; }
  .st-key-tp_hero { padding: 44px 26px 0 26px; border-radius: 26px; } .st-key-tp_hero h1 { white-space: normal; font-size: 2.35rem !important; } .st-key-tp_hero p.lead { font-size: 1.02rem; }
  .tp-heroart { margin: -10px -26px 0 -26px; } .tp-shot { position: relative; right: auto; bottom: auto; width: auto; margin: -150px 14px 26px 14px; }
  .tp-hero { margin: 30px 0 22px 0; padding-bottom: 28px; } .tp-hero h1 { font-size: 2.1rem !important; } .tp-hero p.lead { font-size: 1.02rem; }
  .tp-sec { margin: 60px 0 18px 0; } .tp-sec h2 { font-size: 1.75rem !important; } .tp-sec p { font-size: 1rem; }
  .tp-stats { margin-top: 40px; } .tp-stat { padding: 22px 12px; } .tp-stat .v { font-size: 2.3rem; }
  .tp-card { padding: 22px 20px; border-radius: 20px; } [class*="st-key-tp_stage"] { padding: 22px 18px; border-radius: 22px; } .tp-stagehead { gap: 12px; flex-wrap: wrap; } .tp-stagehead .t { font-size: 1.35rem; } .tp-stagehead .r { margin-left: 0; }
  [class*="st-key-tp_band"] { padding: 30px 24px 34px 24px; border-radius: 24px; margin-top: 48px; } [class*="st-key-tp_band"] .t { font-size: 1.55rem; } [class*="st-key-tp_band"] [class*="st-key-cta_dark"] [data-testid="stPageLink-NavLink"] { margin: 14px 0 0 0; }
  .tp-rail { grid-template-columns: repeat(2, minmax(0, 1fr)); padding: 18px 6px 12px 6px; }
  .tp-gate { min-height: 0; padding: 34px 26px 150px 26px; border-radius: 26px; } .tp-gate h1 { font-size: 2.1rem !important; } .tp-gate .art { width: 340px; right: -70px; bottom: -150px; } .st-key-tp_gate_card { padding: 28px 22px 22px 22px; border-radius: 24px; }
  .tp-quote { font-size: 1.14rem; padding-left: 20px; } .tp-dshead h3 { font-size: 1.55rem !important; } .tp-footer { margin-top: 70px; } .tp-footer { grid-template-columns: 1fr; gap: 18px; } .tp-footer .r { text-align: left; }
  .tp-scroll > svg { width: 820px; min-width: 820px; }
  table.tp td.wrap, table.tp th.wrap { min-width: 132px; } .tp-band .d, .tp-kv dd, .tp-what { overflow-wrap: anywhere; }
  table.tp { display: block; overflow-x: auto; -webkit-overflow-scrolling: touch; } .tp-org { padding: 20px 18px 14px 18px; } .tp-pair > div { padding: 18px 20px; }
}

/* ================= second pass: set pieces, a family of art, editorial pages, phone ================= */
@keyframes tp-growy { from { transform: scaleY(0); } to { transform: scaleY(1); } }
.tp-trust { flex-direction: column; gap: 9px; }
.st-key-tp_hero h1 em { animation-iteration-count: 2; }
.tp-mini-print { display: inline-block; line-height: 0; flex: 0 0 auto; }
.tp-mini-print .tp-ridge { animation: none; opacity: 1; }
.tp-sec.has-art { display: grid; grid-template-columns: minmax(0, 1fr) 210px; gap: 48px; align-items: end; }
.tp-secart { height: 150px; overflow: hidden; opacity: .5; -webkit-mask-image: linear-gradient(180deg, #000 30%, transparent 96%); mask-image: linear-gradient(180deg, #000 30%, transparent 96%); }
.tp-secart .tp-art { width: 210px; margin-top: -10px; } .tp-secart .tp-ridge { animation: none; opacity: 1; }
.tp-sample { position: relative; overflow: hidden; } .tp-sample .tp-mini-print { position: absolute; right: 14px; top: 12px; opacity: .8; }
.tp-sample .top { padding-right: 84px; min-height: 30px; } .tp-sample h5 { padding-right: 70px !important; margin-top: 6px !important; } .tp-sample p { margin-top: 8px; }
.tp-dshead { display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: 30px; align-items: start; } .tp-dshead .tp-mini-print { margin-top: -4px; }

/* figures */
.tp-fig { margin: 26px 0 10px 0; padding: 30px 0 0 0; border-top: 1px solid var(--line); }
.tp-fig .tp-legend { margin: 0 0 18px 0; }
.tp-fig figcaption { font-size: .88rem; color: var(--muted); line-height: 1.62; max-width: 940px; margin-top: 18px; padding-top: 16px; border-top: 1px solid var(--line2); text-wrap: pretty; }
.tp-fig figcaption b { font-family: var(--mono); font-size: .66rem; letter-spacing: .16em; text-transform: uppercase; color: var(--gold-ink); font-weight: 500; margin-right: 12px; }

/* the five steps: one line with five stations */
.tp-steps { position: relative; margin: 46px 0 0 0; padding-top: 0; }
.tp-steps::before { content: ''; position: absolute; left: 0; right: 0; top: 5px; height: 1px; background: linear-gradient(90deg, var(--gold) 0%, var(--gold2) 55%, var(--line) 100%); transform-origin: left center; }
.tp-steps ol { list-style: none; margin: 0; padding: 0; display: grid; grid-template-columns: repeat(5, minmax(0, 1fr)); gap: 0 34px; }
.tp-steps li { padding: 0; margin: 0; position: relative; }
.tp-steps li::before { content: ''; display: block; width: 11px; height: 11px; border-radius: 50%; background: var(--paper); border: 1.5px solid var(--gold); position: relative; z-index: 1; }
.tp-steps .n { display: block; font-family: var(--serif); font-size: 4.6rem; line-height: 1; font-weight: 300; letter-spacing: -.05em; margin: 22px 0 18px -3px; background: var(--metal-gold); -webkit-background-clip: text; background-clip: text; color: transparent; font-variant-numeric: lining-nums; }
.tp-steps h4 { font-family: var(--serif) !important; font-size: 1.34rem; font-weight: 500; letter-spacing: -.022em; line-height: 1.2; margin: 0 0 10px 0; padding: 0; color: var(--ink); text-wrap: balance; }
.tp-steps p { font-size: .93rem; color: var(--muted); line-height: 1.6; margin: 0; }

/* the four training conditions: one scene on a graphite plate */
.tp-plate { position: relative; overflow: hidden; isolation: isolate; border-radius: 34px; margin: 104px 0 0 0; padding: 74px 62px 58px 62px; color: #f5f5f7;
            background: radial-gradient(900px 560px at 84% -6%, #2b2b30 0%, #141416 50%, #0b0b0c 84%); box-shadow: 0 30px 80px rgba(20,16,8,.22), 0 0 0 1px rgba(255,255,255,.04) inset; }
.tp-plateart { position: absolute; right: -150px; top: -210px; width: 520px; z-index: -1; opacity: .42; -webkit-mask-image: linear-gradient(200deg, #000 30%, transparent 70%); mask-image: linear-gradient(200deg, #000 30%, transparent 70%); }
.tp-plateart .tp-ridge { animation: none; opacity: 1; }
.tp-plate > .k { font-family: var(--mono); font-size: .7rem; font-weight: 500; letter-spacing: .2em; text-transform: uppercase; color: var(--gold2); }
.tp-plate > h2 { font-family: var(--serif) !important; color: #f5f5f7 !important; font-size: clamp(1.9rem, 3.3vw, 2.9rem) !important; font-weight: 470 !important; letter-spacing: -.03em; line-height: 1.08 !important; margin: 14px 0 14px 0 !important; padding: 0 !important; }
.tp-plate > p { color: #a1a1a6; font-size: 1.12rem; line-height: 1.6; max-width: 640px; margin: 0; }
.tp-conds { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); margin-top: 50px; border-top: 1px solid rgba(255,255,255,.14); }
.tp-conds .c { padding: 26px 26px 6px 26px; border-left: 1px solid rgba(255,255,255,.1); }
.tp-conds .c:nth-child(1) { border-left: none; padding-left: 0; } .tp-conds .c:last-child { padding-right: 0; }
.tp-conds .i { font-family: var(--mono); font-size: .62rem; letter-spacing: .18em; text-transform: uppercase; color: #86868b; }
.tp-conds svg { margin: 18px 0 14px 0 !important; }
.tp-conds h4 { font-family: var(--serif) !important; color: #f5f5f7; font-size: 1.32rem; font-weight: 500; letter-spacing: -.02em; line-height: 1.2; margin: 0 0 8px 0; padding: 0; text-wrap: balance; }
.tp-conds p { color: #a1a1a6; font-size: .92rem; line-height: 1.58; margin: 0; }
.tp-conds p b { color: #d2d2d7; font-weight: 600; }
.tp-conds.light { margin-top: 18px; border-top: 1px solid var(--line); border-bottom: 1px solid var(--line); padding-bottom: 18px; }
.tp-conds.light .c { border-left-color: var(--line2); padding-top: 18px; } .tp-conds.light .i { color: var(--muted); } .tp-conds.light h4 { color: var(--ink); font-size: 1.14rem; }
.tp-conds.light p { color: var(--muted); font-size: .88rem; } .tp-conds.light p b { color: var(--ink); } .tp-conds.light svg { margin: 8px 0 6px 0 !important; max-width: 230px; }

/* the decision rule: three large marks under hairlines */
.tp-rule { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 0 56px; margin-top: 46px; }
.tp-rule .r { border-top: 1px solid var(--ink); padding-top: 18px; }
.tp-rule .l { font-family: var(--mono); font-size: .66rem; font-weight: 500; letter-spacing: .2em; text-transform: uppercase; color: var(--gold-ink); }
.tp-rule .g { display: flex; align-items: baseline; gap: 14px; height: 168px; }
.tp-rule .g b { font-family: var(--serif); font-size: 9.4rem; font-weight: 300; line-height: 1.02; letter-spacing: -.06em; color: var(--ink); font-variant-numeric: lining-nums; }
.tp-rule .g span { font-family: var(--serif); font-style: italic; font-size: 1.5rem; color: var(--gold-ink); letter-spacing: -.01em; }
.tp-rule .g .tp-mini-print { align-self: center; }
.tp-rule p { font-size: 1.04rem; color: var(--ink2); line-height: 1.6; margin: 4px 0 0 0; max-width: 340px; text-wrap: pretty; }

/* ways forward and paired cells: every piece of text keeps its own button, on every screen */
[class*="st-key-tp_ways"] { display: grid !important; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 0 44px !important; margin-top: 30px; align-items: stretch; }
[class*="st-key-tp_ways"] > div { height: 100%; }
[class*="st-key-tp_way_"] { border-top: 1px solid var(--ink); padding-top: 20px; height: 100%; gap: .5rem !important; }
[class*="st-key-tp_way_"] > div:nth-child(1) { flex: 1 1 auto; }
.tp-wayt .n { font-family: var(--mono); font-size: .66rem; font-weight: 500; letter-spacing: .2em; color: var(--gold-ink); }
.tp-wayt h4 { font-family: var(--serif) !important; font-size: 1.62rem; font-weight: 480; letter-spacing: -.026em; line-height: 1.14; margin: 14px 0 10px 0; padding: 0; color: var(--ink); text-wrap: balance; }
.tp-wayt p { font-size: .98rem; color: var(--muted); line-height: 1.6; margin: 0; }
[class*="st-key-tp_cells"] { display: grid !important; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 26px 20px !important; align-items: stretch; }
[class*="st-key-tp_cells"] > div { height: 100%; }
[class*="st-key-tp_cell_"] { height: 100%; gap: .7rem !important; }
[class*="st-key-tp_cell_"] > div:nth-child(1) { flex: 1 1 auto; }
[class*="st-key-tp_cell_"] > div:nth-child(1) :is([data-testid="stMarkdown"], [data-testid="stMarkdownContainer"]) { height: 100%; }

/* editorial rows, definition lists, quiet prose */
.tp-rows { margin-top: 26px; border-bottom: 1px solid var(--line); }
.tp-rows .r { display: grid; grid-template-columns: 74px minmax(0, 1fr) auto; gap: 6px 26px; align-items: start; padding: 28px 0 30px 0; border-top: 1px solid var(--line); }
.tp-rows .n { font-family: var(--serif); font-size: 2.7rem; line-height: 1; font-weight: 300; letter-spacing: -.04em; background: var(--metal-gold); -webkit-background-clip: text; background-clip: text; color: transparent; font-variant-numeric: lining-nums; }
.tp-rows h4 { font-family: var(--serif) !important; font-size: 1.46rem; font-weight: 500; letter-spacing: -.024em; line-height: 1.18; margin: 2px 0 8px 0; padding: 0; color: var(--ink); }
.tp-rows p { font-size: 1rem; color: var(--muted); line-height: 1.62; margin: 0; max-width: 760px; text-wrap: pretty; }
.tp-rows .m { padding-top: 6px; white-space: nowrap; }
.tp-rows.c2 { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); column-gap: 64px; }
.tp-rows.c3 { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); column-gap: 44px; border-bottom: none; }
.tp-rows.c3 .r { grid-template-columns: minmax(0, 1fr); border-top-color: var(--ink); padding-top: 18px; } .tp-rows.c3 .n { font-size: 3.4rem; margin-bottom: 8px; display: block; } .tp-rows.c3 .m { order: -1; }
.tp-dl { columns: 2; column-gap: 64px; margin: 26px 0 0 0; }
.tp-dl > div { break-inside: avoid; border-top: 1px solid var(--line); padding: 20px 0 22px 0; }
.tp-dl dt { font-family: var(--serif); font-size: 1.3rem; font-weight: 500; letter-spacing: -.02em; color: var(--ink); line-height: 1.2; }
.tp-dl dd { margin: 8px 0 0 0; font-size: .97rem; color: var(--muted); line-height: 1.62; }
.tp-prose { columns: 2; column-gap: 64px; column-rule: 1px solid var(--line2); margin-top: 30px; border-top: 1px solid var(--line); padding-top: 26px; }
.tp-prose p { break-inside: avoid; font-size: 1.03rem; line-height: 1.68; color: var(--ink2); margin: 0 0 20px 0; text-wrap: pretty; }
.tp-prose p b { color: var(--ink); }
.tp-duo2 { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 0 64px; margin-top: 26px; }
.tp-duo2 > div { border-top: 1px solid var(--ink); padding-top: 18px; }
.tp-duo2 h4 { font-family: var(--serif) !important; font-size: 1.46rem; font-weight: 500; letter-spacing: -.024em; margin: 0 0 10px 0; padding: 0; color: var(--ink); }
.tp-duo2 p { font-size: 1rem; color: var(--muted); line-height: 1.64; margin: 0; }

/* bars as text and rules */
.tp-bars { display: grid; gap: 10px; }
.tp-bars .r { display: grid; grid-template-columns: minmax(0, 1fr) auto; column-gap: 12px; row-gap: 6px; align-items: baseline; }
.tp-bars .l { font-size: .82rem; font-weight: 500; color: var(--ink2); letter-spacing: -.006em; line-height: 1.3; }
.tp-bars .v { font-size: .86rem; font-weight: 650; color: var(--ink); font-variant-numeric: tabular-nums; }
.tp-bars .v.nm { font-weight: 400; color: var(--muted); }
.tp-bars .tr { grid-column: 1 / -1; height: 6px; border-radius: 3px; background: #f3f1ec; display: block; }
.tp-bars .tp-bar { display: block; height: 100%; border-radius: 3px; transform-origin: left center; }
.tp-bars .tp-bar.s { box-shadow: inset 0 0 0 1px #7f828a; }
.tp-bars .tp-bar.x { background-image: repeating-linear-gradient(45deg, rgba(255,255,255,.62) 0 2px, transparent 2px 5px); }
.tp-bars.dark .l { color: #c7c7cc; } .tp-bars.dark .v { color: #f5f5f7; } .tp-bars.dark .tr { background: rgba(255,255,255,.13); }
.tp-bars.timed .tp-bar { animation: tp-grow 1.3s var(--ease) both; animation-delay: calc(var(--i, 0) * 110ms + 1.3s); }
.tp-bars.duo { gap: 8px; } .tp-bars.duo .tr { height: 5px; }
.tp-shot .tp-bars { gap: 8px; } .tp-shot .tp-bars .l { font-size: .76rem; } .tp-shot .tp-bars .v { font-size: .8rem; }

/* tables scroll sideways inside their own holder */
.tp-tscroll { overflow-x: auto; -webkit-overflow-scrolling: touch; }
.tp-band { background: transparent; border-top: 1px solid var(--ink); border-radius: 0; padding: 20px 0 6px 0; }

/* drawers become ruled rows */
div[data-testid="stExpander"] { background: transparent !important; border: none !important; border-top: 1px solid var(--line) !important; border-bottom: 1px solid var(--line) !important; border-radius: 0 !important; box-shadow: none !important; }
div[data-testid="stExpander"]:hover { box-shadow: none !important; border-color: #cfcabd !important; }
div[data-testid="stExpander"] details { border-radius: 0 !important; background: transparent !important; }
div[data-testid="stExpander"] summary { padding: 17px 4px; min-height: 44px; }
div[data-testid="stExpander"] summary p { font-size: 1rem; }
div[data-testid="stExpander"] summary svg { color: var(--gold-ink); }
[data-testid="stElementContainer"]:has(> div[data-testid="stExpander"]) + [data-testid="stElementContainer"]:has(> div[data-testid="stExpander"]) { margin-top: calc(-1rem - 1px); }

/* notices in the paper language */
[data-testid="stAlertContainer"] { background: var(--veil) !important; border: 1px solid var(--line2) !important; border-left: 2px solid var(--gold) !important; border-radius: 0 16px 16px 0 !important; padding: 16px 22px !important; }
[data-testid="stAlertContainer"] p, [data-testid="stAlertContainer"] li { color: var(--ink2) !important; font-size: .95rem; line-height: 1.6; }
[data-testid="stAlertContainer"]:has([data-testid="stAlertContentWarning"]) { border-left-color: var(--warn) !important; background: #fbf6ea !important; }
[data-testid="stAlertContainer"]:has([data-testid="stAlertContentError"]) { border-left-color: var(--no) !important; background: #fbf1ef !important; }
[data-testid="stAlertContainer"]:has([data-testid="stAlertContentSuccess"]) { border-left-color: var(--ok) !important; background: #f2f6f2 !important; }

/* the live demo: a rail that stays in view, stages that keep their detail one click away */
[data-testid="stElementContainer"]:has(.tp-rail) { position: sticky; top: 78px; z-index: 40; }
.tp-rail { background: rgba(253,252,247,.84); backdrop-filter: saturate(180%) blur(20px); -webkit-backdrop-filter: saturate(180%) blur(20px); padding: 14px 10px 10px 10px; border-radius: 20px; margin: 4px 0 6px 0; }
.tp-rail .n { width: 30px; height: 30px; font-size: .9rem; } .tp-rail .t { margin-top: 6px; font-size: .8rem; } .tp-rail .s:not(:last-child)::before { top: 14px; left: calc(50% + 22px); width: calc(100% - 44px); } .tp-rail .s.done:not(:last-child)::after { top: 13px; left: calc(50% + 22px); width: calc(100% - 44px); }
[class*="st-key-tp_stage"] { animation: none; padding: 28px 34px 18px 34px; }
[class*="st-key-tp_stage"] div[data-testid="stExpander"] { border-bottom: none !important; margin-top: 4px; }

/* the menu that replaces the row of links on a narrow screen */
.st-key-tp_nav [data-testid="stColumn"]:has(.st-key-tp_navmenu) { display: none; }
.st-key-tp_navmenu button { border-radius: 980px !important; min-height: 44px; padding: 6px 12px 6px 18px !important; border: 1px solid #cfcabd !important; background: #fff !important; }
.st-key-tp_navmenu button p { font-weight: 600; font-size: .92rem; color: var(--ink); white-space: nowrap; }
[data-testid="stPopoverBody"] { border-radius: 22px !important; border: 1px solid var(--line2) !important; box-shadow: var(--shadow2) !important; background: #fdfcf7 !important; padding: 10px !important; }
[data-testid="stPopoverBody"] [data-testid="stPageLink-NavLink"] { min-height: 46px; padding: 10px 14px; border-radius: 12px; background: transparent !important; }
[data-testid="stPopoverBody"] [data-testid="stPageLink-NavLink"]:hover { background: rgba(29,29,31,.05) !important; }
[data-testid="stPopoverBody"] [data-testid="stPageLink-NavLink"] p { font-size: 1.02rem; font-weight: 500; color: var(--ink); }
[data-testid="stPopoverBody"] [class*="st-key-tp_mon"] [data-testid="stPageLink-NavLink"] p { font-weight: 650; }
[data-testid="stPopoverBody"] [class*="st-key-tp_mon"] [data-testid="stPageLink-NavLink"] p::after { content: ''; display: inline-block; width: 6px; height: 6px; border-radius: 50%; background: var(--gold); margin-left: 10px; vertical-align: middle; }
[data-testid="stPopoverBody"] [data-testid="stVerticalBlock"] { gap: 2px !important; }

/* sign-in: the words stay clear of the art */
.tp-gate .art { right: -262px; bottom: -286px; opacity: .82; -webkit-mask-image: linear-gradient(118deg, transparent 34%, #000 70%); mask-image: linear-gradient(118deg, transparent 34%, #000 70%); }
.tp-gate .foot { position: relative; max-width: 300px; line-height: 1.7; }

/* scroll-linked motion for the set pieces (static where the browser has no view timelines) */
@media (prefers-reduced-motion: no-preference) { @supports (animation-timeline: view()) {
  .tp-steps::before { animation: tp-grow linear both; animation-timeline: view(); animation-range: entry 30% cover 46%; }
  .tp-steps li, .tp-conds .c, .tp-rule .r { animation: tp-rise linear both; animation-timeline: view(); animation-range: entry calc(var(--i, 0) * 7%) entry calc(60% + var(--i, 0) * 9%); }
  .tp-rule .g b { animation: tp-settle linear both; animation-timeline: view(); animation-range: entry 10% entry 100%; }
  .tp-plate, .tp-fig, .tp-rows .r, .tp-dl > div, .tp-prose, .tp-duo2 > div { animation: tp-rise linear both; animation-timeline: view(); animation-range: entry 0% entry 55%; }
  .tp-bars:not(.timed) .tp-bar { animation: tp-grow linear both; animation-timeline: view(); animation-range: entry 0% entry 100%; }
} }

/* ---------- second pass, smaller screens ---------- */
@media (max-width: 1100px) {
  .tp-steps::before { left: 5px; right: auto; top: 6px; bottom: 30px; width: 1px; height: auto; transform-origin: center top; background: linear-gradient(180deg, var(--gold), var(--gold2) 55%, var(--line)); }
  .tp-steps ol { grid-template-columns: minmax(0, 1fr); gap: 0; }
  .tp-steps li { display: grid; grid-template-columns: 96px minmax(0, 1fr); column-gap: 10px; padding: 0 0 38px 40px; }
  .tp-steps li::before { position: absolute; left: 0; top: 4px; }
  .tp-steps .n { grid-row: 1 / span 2; font-size: 4rem; margin: -8px 0 0 0; } .tp-steps h4 { font-size: 1.42rem; } .tp-steps p { font-size: 1rem; max-width: 620px; }
  .tp-conds { grid-template-columns: repeat(2, minmax(0, 1fr)); } .tp-conds .c { padding: 26px 26px 26px 26px; } .tp-conds .c:nth-child(odd) { border-left: none; padding-left: 0; } .tp-conds .c:nth-child(n+3) { border-top: 1px solid rgba(255,255,255,.1); }
  .tp-conds.light .c:nth-child(n+3) { border-top-color: var(--line2); } .tp-conds svg { max-width: 300px; }
  .tp-plate { padding: 58px 44px 44px 44px; }
  .tp-rule { gap: 0 34px; } .tp-rule .g b { font-size: 7rem; } .tp-rule .g { height: 132px; }
}
@supports (animation-timeline: view()) { @media (max-width: 1100px) and (prefers-reduced-motion: no-preference) { .tp-steps::before { animation-name: tp-growy; } } }
@media (max-width: 900px) {
  [class*="st-key-tp_ways"] { grid-template-columns: minmax(0, 1fr); gap: 34px 0 !important; }
  [class*="st-key-tp_cells"] { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .tp-rule { grid-template-columns: minmax(0, 1fr); gap: 34px 0; } .tp-rule .g { height: auto; padding: 6px 0 2px 0; } .tp-rule p { max-width: 560px; }
  .tp-rows.c2, .tp-rows.c3 { grid-template-columns: minmax(0, 1fr); } .tp-dl, .tp-prose { columns: 1; } .tp-duo2 { grid-template-columns: minmax(0, 1fr); gap: 30px 0; }
  .tp-sec.has-art { grid-template-columns: minmax(0, 1fr); } .tp-secart { display: none; }
}
@media (max-width: 820px) {
  .st-key-tp_nav [data-testid="stColumn"]:has([data-testid="stPageLink"]) { display: none !important; }
  .st-key-tp_nav [data-testid="stColumn"]:has(.st-key-tp_navmenu) { display: block !important; flex: 0 0 auto !important; width: auto !important; min-width: 0 !important; }
  .st-key-tp_nav [data-testid="stHorizontalBlock"] { flex-wrap: nowrap !important; justify-content: space-between; overflow: visible; }
  .st-key-tp_nav [data-testid="stColumn"]:nth-child(1) { flex: 1 1 auto !important; width: auto !important; min-width: 0 !important; }
  .st-key-tp_nav { padding: 6px 8px 6px 14px; }
  [data-testid="stHorizontalBlock"]:has(.st-key-tp_gate_card) { flex-direction: column-reverse !important; gap: 22px !important; }
  [data-testid="stElementContainer"]:has(.tp-rail) { top: 70px; }
}
@media (max-width: 640px) {
  [class*="st-key-tp_cells"] { grid-template-columns: minmax(0, 1fr); }
  .tp-plate { padding: 44px 24px 30px 24px; border-radius: 26px; margin-top: 64px; } .tp-plateart { display: none; }
  .tp-conds { grid-template-columns: minmax(0, 1fr); margin-top: 34px; } .tp-conds .c { padding: 24px 0 24px 0 !important; border-left: none; border-top: 1px solid rgba(255,255,255,.1); } .tp-conds .c:nth-child(1) { border-top: none; }
  .tp-conds svg { max-width: 260px; } .tp-conds.light .c { border-top-color: var(--line2); }
  .tp-steps li { grid-template-columns: 62px minmax(0, 1fr); padding: 0 0 32px 30px; } .tp-steps .n { font-size: 3.1rem; margin-top: -4px; } .tp-steps h4 { font-size: 1.24rem; } .tp-steps p { font-size: .97rem; }
  .tp-rule .g b { font-size: 6rem; } .tp-rows .r { grid-template-columns: 46px minmax(0, 1fr); gap: 6px 14px; padding: 22px 0 24px 0; } .tp-rows .n { font-size: 2rem; } .tp-rows h4 { font-size: 1.24rem; } .tp-rows .m { grid-column: 2; padding-top: 2px; white-space: normal; }
  .tp-wayt h4 { font-size: 1.4rem; } .tp-dl dt { font-size: 1.18rem; } .tp-prose p { font-size: 1rem; }
  .tp-gate { padding: 30px 26px 120px 26px; } .tp-gate ul { margin-top: 18px; } .tp-gate .art { width: 320px; right: -80px; bottom: -170px; }
  .tp-dshead { grid-template-columns: minmax(0, 1fr); } .tp-dshead .tp-mini-print { display: none; }
  table.tp { display: table; min-width: max-content; } .tp-tscroll { margin-right: -1.05rem; padding-right: 1.05rem; -webkit-mask-image: linear-gradient(90deg, #000 calc(100% - 34px), transparent); mask-image: linear-gradient(90deg, #000 calc(100% - 34px), transparent); }
  .tp-scroll { margin-right: -1.05rem; -webkit-mask-image: linear-gradient(90deg, #000 calc(100% - 34px), transparent); mask-image: linear-gradient(90deg, #000 calc(100% - 34px), transparent); }
  .stButton > button, .stDownloadButton > button, [data-testid="stFormSubmitButton"] > button, [data-testid="stPageLink-NavLink"], [role="tab"], [data-baseweb="tab"] { min-height: 44px; }
  [data-testid="stRadio"] label, [data-testid="stCheckbox"] label { min-height: 44px; align-items: center; }
  .tp-rail { grid-template-columns: repeat(6, minmax(0, 1fr)); padding: 10px 2px 6px 2px; row-gap: 0; } .tp-rail .t { font-size: .56rem; letter-spacing: -.02em; line-height: 1.15; margin-top: 4px; } .tp-rail .e { display: none; } .tp-rail .n { width: 26px; height: 26px; font-size: .8rem; }
  [class*="st-key-tp_stage"] { padding: 22px 18px 12px 18px; }
  .tp-fig { padding-top: 22px; } .tp-trust { gap: 7px; }
}

/* the band that follows the steps is a quiet plate, so the graphite is kept for the hero and the conditions */
.st-key-tp_band_demo { background: var(--paper-deep) !important; box-shadow: none !important; border-radius: 26px; padding: 34px 40px 40px 40px; margin: 70px 0 0 0; }
.st-key-tp_band_demo .t { color: var(--ink); font-size: 1.7rem; } .st-key-tp_band_demo .d { color: var(--ink2); }
.st-key-tp_band_demo [class*="st-key-cta_dark"] [data-testid="stPageLink-NavLink"] { background: var(--ink) !important; }
.st-key-tp_band_demo [class*="st-key-cta_dark"] [data-testid="stPageLink-NavLink"] p { color: #fff; }
.st-key-tp_band_demo [class*="st-key-cta_dark"] [data-testid="stPageLink-NavLink"]:hover { background: #000 !important; box-shadow: 0 8px 24px rgba(0,0,0,.18); }

.tp-rows.nn .r { grid-template-columns: minmax(0, 1fr) auto; }
.tp-rows.c2 .r { grid-template-columns: 58px minmax(0, 1fr) auto; } .tp-rows.c2.nn .r { grid-template-columns: minmax(0, 1fr) auto; }
.tp-rows.c3.nn h4 { margin-top: 6px; }
.tp-facts { display: flex; flex-wrap: wrap; gap: 6px 28px; margin: 14px 0 4px 0; font-size: .92rem; color: var(--ink2); font-weight: 600; }
.tp-facts b { font-family: var(--serif); font-size: 1.25rem; font-weight: 500; color: var(--ink); margin-right: 4px; }
.tp-conds { margin-left: -26px; margin-right: -26px; border-top: none; position: relative; }
.tp-conds::before { content: ''; position: absolute; left: 26px; right: 26px; top: 0; height: 1px; background: rgba(255,255,255,.14); }
.tp-conds .c:nth-child(1) { padding-left: 26px; } .tp-conds .c:last-child { padding-right: 26px; }
.tp-conds.light { border-top: none; border-bottom: none; } .tp-conds.light::before { background: var(--line); }
.tp-rule .g { align-items: flex-end; padding-bottom: 10px; } .tp-rule .g b { line-height: .84; } .tp-rule .g span { margin-bottom: 6px; } .tp-rule .g .tp-mini-print { align-self: flex-end; margin-bottom: 2px; }
[class*="st-key-tp_ways"] { margin-bottom: 30px; }
@media (max-width: 1100px) { .tp-conds .c:nth-child(odd) { padding-left: 26px; } }
@media (max-width: 640px) { .tp-conds { margin-left: 0; margin-right: 0; } .tp-conds::before { left: 0; right: 0; } }
[class*="st-key-tp_cell_"] > div:nth-child(1), [class*="st-key-tp_cell_"] > div:nth-child(1) > div, [class*="st-key-tp_cell_"] > div:nth-child(1) [data-testid="stMarkdownContainer"] { flex: 1 1 auto; display: flex; flex-direction: column; height: auto; }
[class*="st-key-tp_cell_"] .tp-card { flex: 1 1 auto; height: auto; }
.tp-org .row { flex-wrap: wrap; row-gap: 5px; } .tp-org .row > span:nth-child(1) { flex: 1 0 auto; }
.stDownloadButton > button, .stButton > button { height: auto; min-height: 42px; }
.stDownloadButton > button p, .stButton > button p { white-space: normal !important; overflow: visible !important; text-overflow: clip !important; line-height: 1.3; }
table.tp th { white-space: nowrap; } table.tp th.wrap { white-space: normal; }
[data-testid="stElementContainer"]:has(.tp-rail)::before { content: ''; position: absolute; left: -2rem; right: -2rem; top: -26px; height: 40px; background: linear-gradient(var(--paper) 70%, rgba(251,251,249,0)); z-index: -1; pointer-events: none; }
/* the pointer and the scroll get an answer: light on the print, focus on one condition, a little depth */
@keyframes tp-sweep2 { 0% { transform: translateX(0); } 100% { transform: translateX(var(--tw)); } }
@keyframes tp-drift { to { transform: translateY(64px) scale(1.035); } }
@keyframes tp-drift2 { from { transform: translateY(-34px); } to { transform: translateY(46px); } }
.tp-sweep { animation-iteration-count: 3; }
.tp-heroart:hover .tp-sweep, .tp-gate:hover .tp-sweep { animation: tp-sweep2 2.6s cubic-bezier(.4,0,.2,1) 1 both; }
.tp-conds .c { transition: opacity .5s var(--ease); } .tp-conds:hover .c { opacity: .5; } .tp-conds .c:hover { opacity: 1; }
.tp-plateart { transition: opacity 1.2s var(--ease); } .tp-plate:hover .tp-plateart { opacity: .62; }
.tp-steps li .n { transition: filter .5s var(--ease), transform .5s var(--ease); transform-origin: left bottom; } .tp-steps li:hover .n { filter: brightness(1.18); transform: translateY(-3px); }
[class*="st-key-tp_way_"] { transition: border-color .4s var(--ease); } [class*="st-key-tp_way_"]:hover { border-top-color: var(--gold); }
.tp-sample .tp-mini-print { transition: transform .7s var(--ease), opacity .5s; transform-origin: 70% 30%; } .tp-sample:hover .tp-mini-print { transform: scale(1.16) rotate(-3deg); opacity: 1; }
.tp-rows .r { transition: background .4s var(--ease); } .tp-rows .r:hover .n { filter: brightness(1.15); }
@media (prefers-reduced-motion: no-preference) { @supports (animation-timeline: view()) {
  .tp-heroart > .tp-art { animation: tp-drift linear both; animation-timeline: view(); animation-range: exit 0% exit 100%; }
  .tp-plateart { animation: tp-drift2 linear both; animation-timeline: view(); animation-range: entry 0% exit 100%; }
} }
[data-testid="stHeaderActionElements"] { display: none !important; }
@media (max-width: 640px) { .tp-badge { white-space: normal; text-align: left; } .tp-band > div { min-width: 0; } }
:is(.st-key-tp_status_ev, .st-key-tp_stage_5) [data-testid="stExpanderDetails"] [data-testid="stVerticalBlock"] { gap: .12rem !important; }
:is(.st-key-tp_status_ev, .st-key-tp_stage_5) [data-testid="stExpanderDetails"] p { font-family: var(--mono); font-size: .76rem; line-height: 1.6; color: var(--ink2); margin: 0; }
:is(.st-key-tp_status_ev, .st-key-tp_stage_5) [data-testid="stExpanderDetails"] { background: var(--veil); border-radius: 14px; padding: 14px 18px; margin: 0 0 16px 0; }
:is(.st-key-tp_status_ev, .st-key-tp_stage_5) [data-testid="stExpanderDetails"] [data-testid="stVerticalBlock"] { height: auto !important; } :is(.st-key-tp_status_ev, .st-key-tp_stage_5) [data-testid="stExpanderDetails"] [data-testid="stVerticalBlock"] > * { flex-shrink: 0; }
:is(.st-key-tp_status_ev, .st-key-tp_stage_5) div[data-testid="stExpander"] summary { background: transparent !important; }
:is(.st-key-tp_status_ev, .st-key-tp_stage_5) [data-testid="stExpanderDetails"] [data-testid="stMarkdownContainer"] { margin-bottom: 0 !important; }
/* a sample and its button are one card */
[class*="st-key-tp_cell_"] { background: var(--card); border: 1px solid var(--line2); border-radius: 22px; box-shadow: var(--shadow); padding: 0 0 22px 0; overflow: hidden; transition: transform .6s var(--ease), box-shadow .6s var(--ease); }
[class*="st-key-tp_cell_"]:hover { transform: translateY(-4px); box-shadow: var(--shadow2); }
[class*="st-key-tp_cell_"] .tp-card, [class*="st-key-tp_cell_"] .tp-card:hover { background: transparent; border: none; box-shadow: none; border-radius: 0; transform: none; padding-bottom: 8px; }
[class*="st-key-tp_cell_"] .stButton { padding: 0 22px; }
[class*="st-key-tp_cell_"] .tp-sample .lic { border-top: none; padding-top: 8px; }
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
    "play": "<path d='M8 5l11 7-11 7z'/>",
    "columns": "<rect x='3' y='4' width='18' height='16' rx='2'/><path d='M9 4v16M15 4v16'/>",
    "flask": "<path d='M9 3h6M10 3v6l-5 9a2 2 0 002 3h10a2 2 0 002-3l-5-9V3'/>",
    "bolt": "<path d='M13 3L5 14h6l-1 7 8-11h-6z'/>",
}


def esc(x):
    return _html.escape(str(x))


def icon(name, size=20, stroke=2):
    return (f"<svg width='{size}' height='{size}' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='{stroke}' "
            f"stroke-linecap='round' stroke-linejoin='round' aria-hidden='true'>{ICON[name]}</svg>")


def H(html):
    """Render an HTML fragment. Line breaks and indentation are collapsed so that Markdown never reads them as code."""
    st.markdown(re.sub(r"\s*\n\s*", " ", html).strip(), unsafe_allow_html=True)


def inject():
    st.markdown(re.sub(r"\s*\n\s*", " ", CSS), unsafe_allow_html=True)


# ---------------------------------------------------------------- the threat print: a family of generative drawings, deterministic
KINDS = ("whorl", "loop", "arch", "double")


def art_seed(name):
    """A stable number from any text, so that the same page, sample or dataset always gets the same print."""
    h = hashlib.sha256(str(name).encode("utf-8")).digest()
    return (int.from_bytes(h[:4], "big") % 997) / 100.0


def art_kind(name):
    """The pattern family of a name's print (a different part of the same hash, so that names spread evenly over the four families)."""
    return KINDS[hashlib.sha256(str(name).encode("utf-8")).digest()[6] % 4]


def _ridge_points(k, cx, cy, d, pts, seed):
    r = d * k
    out = []
    for i in range(pts):
        t = 2 * math.pi * i / pts
        m = (1 + 0.075 * math.sin(2 * t + 0.9 + 0.11 * k + seed) + 0.045 * math.sin(3 * t + 2.1 - 0.07 * k + 1.7 * seed) + 0.022 * math.sin(5 * t + 0.5 + 0.19 * k))
        out.append((cx + r * 0.84 * m * math.cos(t) + 0.10 * r * math.sin(t + 0.4 + seed),
                    cy + r * m * math.sin(t) + 0.16 * r * max(0.0, math.sin(t)) ** 2 - 0.05 * r))
    return out


def _ridge_path(p, prec=0):
    f = (lambda v: str(int(round(v)))) if prec == 0 else (lambda v: f"{v:.{prec}f}")
    mid = lambda a, b: ((a[0] + b[0]) / 2, (a[1] + b[1]) / 2)
    s = mid(p[-1], p[0])
    d = [f"M{f(s[0])} {f(s[1])}"]
    for i in range(len(p)):
        e = mid(p[i], p[(i + 1) % len(p)])
        d.append(f"Q{f(p[i][0])} {f(p[i][1])} {f(e[0])} {f(e[1])}")
    return "".join(d) + "Z"


def _open_path(p, prec=0):
    f = (lambda v: str(int(round(v)))) if prec == 0 else (lambda v: f"{v:.{prec}f}")
    d = [f"M{f(p[0][0])} {f(p[0][1])}"]
    for i in range(1, len(p) - 1):
        e = ((p[i][0] + p[i + 1][0]) / 2, (p[i][1] + p[i + 1][1]) / 2)
        d.append(f"Q{f(p[i][0])} {f(p[i][1])} {f(e[0])} {f(e[1])}")
    d.append(f"L{f(p[-1][0])} {f(p[-1][1])}")
    return "".join(d)


def _ridge_dash(k, seed):
    x = (k * 7919 + int(seed * 1000) * 104729 + 13) % 2147483647
    out = []
    for _ in range(4):
        x = (x * 48271) % 2147483647
        out.append(str(46 + x % 150))
        x = (x * 48271) % 2147483647
        out.append(str(3 + x % 5))
    return " ".join(out)


def _ridges(kind, n, w, h, pts, seed, prec=0):
    """The ridge paths of one print and its cores (x, y, radius). Four pattern families, as on a real hand: whorl, loop, arch and double loop."""
    cx, cy = w * 0.5, h * 0.455
    if kind == "loop":                                   # ridges enter from below, turn around one core and leave below: the crowns crowd at the top
        d = min(w * 0.5 / (n * 1.0 + 1.6), h * 0.36 / (n * 0.5 + 1.2))
        lean = 0.10 * math.sin(seed * 1.3 + 0.6)
        top = h * 0.37
        paths = [_ridge_path(_ridge_points(k, cx + lean * d * k, top + d * k * 0.50, d, pts, seed), prec) for k in range(1, n + 1)]
        return paths, [(cx + lean * d, top + d * 0.5, d * 0.28)], d
    if kind == "arch":                                   # ridges cross from side to side and rise over the middle
        d = h * 0.60 / (n + 2)
        skew = 0.05 * w * math.sin(seed * 2.1)
        paths = []
        for k in range(1, n + 1):
            y0 = h * 0.84 - d * k * 0.60
            amp = d * k * 0.50
            s = w * (0.15 + 0.011 * k)
            pp = []
            for i in range(pts + 1):
                x = -0.05 * w + 1.10 * w * i / pts
                y = y0 - amp * math.exp(-((x - cx - skew * (k / n)) / s) ** 2) + 0.9 * d * math.sin(x / w * 5.0 + 0.4 * k + seed) * 0.35
                pp.append((x, y))
            paths.append(_open_path(pp, prec))
        return paths, [], d
    if kind == "double":                                 # two cores turning into each other, wrapped by shared ridges
        n_in = max(3, int(round(n * 0.22)))
        d = min(w * 0.5 / ((n + 0.5 * n_in) * 0.94 + 2), h * 0.52 / ((n + 0.5 * n_in) * 1.08 + 2))
        rho = d * (n_in + 0.5)
        phi = 0.85 + 0.45 * math.sin(seed * 1.7)
        c1 = (cx - rho * math.cos(phi), cy - rho * math.sin(phi))
        c2 = (cx + rho * math.cos(phi), cy + rho * math.sin(phi))
        paths = [_ridge_path(_ridge_points(k, c[0], c[1], d * 0.96, max(12, pts * 2 // 3), seed + j), prec) for j, c in enumerate((c1, c2)) for k in range(1, n_in + 1)]
        r0 = 1.5 * rho + 0.9 * d
        for j in range(n - n_in):
            R = r0 + d * j
            a = 0.5 * rho / R
            pp = []
            for i in range(pts):
                t = 2 * math.pi * i / pts
                m = 1 + a * math.cos(2 * (t - phi)) + 0.03 * math.sin(3 * t + 0.3 * j + seed)
                pp.append((cx + R * 0.9 * m * math.cos(t), cy + R * m * math.sin(t)))
            paths.append(_ridge_path(pp, prec))
        return paths, [(c1[0], c1[1], d * 0.26), (c2[0], c2[1], d * 0.26)], d
    d = min(w * 0.5 / (n * 0.86 + 1.2), h * 0.52 / (n * 1.1 + 1.2))        # whorl: closed ridges around one core
    return [_ridge_path(_ridge_points(k, cx, cy, d, pts, seed), prec) for k in range(1, n + 1)], [(cx, cy - d * 0.05, d * 0.28)], d


def print_art(uid=None, ridges=30, w=600, h=720, seed=0.0, on="dark", pts=34, sweep=True, kind=None):
    """The signature art: contour ridges in the shape of a fingerprint, silver with gold catching the light.
    A family of drawings: the seed picks the pattern (whorl, loop, arch, double loop), the lean, which ridges are gold and where they break,
    so every page, sample and dataset has its own print and the same seed always gives the same drawing. on='dark' for graphite, 'light' for paper."""
    kind = kind or KINDS[int(round(seed * 100)) % 4]
    uid = uid or f"{kind[0]}{int(round(seed * 100))}x{ridges}{on[0]}"
    paths, cores, d = _ridges(kind, ridges, w, h, pts, seed, 0 if w >= 300 else 1)
    sw = max(0.9, d * 0.36)
    gm = 6 + int(seed * 10) % 3
    g0 = (3 + int(seed * 100)) % gm
    body = "".join(f"<path class='tp-ridge{' g' if (k - g0) % gm == 0 else ''}' style='--k:{min(k, 34)}' stroke-dasharray='{_ridge_dash(k, seed)}' d='{p}'/>" for k, p in enumerate(paths, 1))
    silver = ("<stop offset='0' stop-color='#f5f5f7'/><stop offset='.45' stop-color='#b9bcc4'/><stop offset='1' stop-color='#6e7078'/>" if on == "dark"
              else "<stop offset='0' stop-color='#a4a6ad'/><stop offset='.5' stop-color='#55565c'/><stop offset='1' stop-color='#2a2a2d'/>")
    sweep_svg = f"<use href='#tpr{uid}' stroke='url(#tpgo{uid})' stroke-width='{sw * 1.15:.2f}' mask='url(#tpsw{uid})'/>" if sweep else ""
    dots = "".join(f"<circle cx='{x:.0f}' cy='{y:.0f}' r='{r:.1f}' fill='url(#tpgo{uid})'/>" for x, y, r in cores)
    return (f"<svg class='tp-art' viewBox='0 0 {w} {h}' width='100%' role='img' aria-label='Abstract contour drawing in the shape of a fingerprint'>"
            f"<defs><linearGradient id='tpsi{uid}' x1='0' y1='0' x2='1' y2='1'>{silver}</linearGradient>"
            f"<linearGradient id='tpgo{uid}' x1='0' y1='0' x2='1' y2='1'><stop offset='0' stop-color='#f3e6bd'/><stop offset='.5' stop-color='#c4a565'/><stop offset='1' stop-color='#9d8552'/></linearGradient>"
            f"<radialGradient id='tpfa{uid}' cx='50%' cy='46%' r='52%'><stop offset='.55' stop-color='#fff'/><stop offset='.86' stop-color='#fff' stop-opacity='.55'/><stop offset='1' stop-color='#fff' stop-opacity='0'/></radialGradient>"
            f"<linearGradient id='tpbd{uid}' x1='0' y1='0' x2='1' y2='0'><stop offset='0' stop-color='#fff' stop-opacity='0'/><stop offset='.5' stop-color='#fff'/><stop offset='1' stop-color='#fff' stop-opacity='0'/></linearGradient>"
            f"<mask id='tpma{uid}'><rect width='{w}' height='{h}' fill='url(#tpfa{uid})'/></mask>"
            f"<mask id='tpsw{uid}'><rect class='tp-sweep' x='{-w * 0.45:.0f}' y='0' width='{w * 0.45:.0f}' height='{h}' fill='url(#tpbd{uid})' style='--tw:{w * 1.5:.0f}px'/></mask>"
            f"<g id='tpr{uid}' fill='none' stroke-linecap='round'>{body}</g></defs>"
            f"<g mask='url(#tpma{uid})'><use href='#tpr{uid}' stroke='url(#tpsi{uid})' stroke-width='{sw:.2f}'/>{sweep_svg}{dots}</g></svg>")


def mini_print(name, size=96, on="light", ridges=9):
    """A small print that belongs to one thing (a sample, a dataset, a page): its name is the seed."""
    return f"<span class='tp-mini-print' style='width:{size}px' aria-hidden='true'>{print_art(ridges=ridges, w=120, h=144, seed=art_seed(name), on=on, pts=16, sweep=False, kind=art_kind(name))}</span>"


def mark_svg(size=34, uid="m", standalone=False):
    """The logo mark: five ridges of the print on a graphite tile, one of them gold."""
    pts = [_ridge_points(k, 17.0, 17.6, 2.55, 14, 0.0) for k in range(1, 6)]
    ridges = "".join(f"<path d='{_ridge_path(p, 1)}' stroke='{'#c4a565' if k == 2 else f'url(#tpmk{uid})'}'/>" for k, p in enumerate(pts))
    ns = " xmlns='http://www.w3.org/2000/svg'" if standalone else ""
    return (f"<svg{ns} width='{size}' height='{size}' viewBox='0 0 34 34' aria-hidden='true'><defs><linearGradient id='tpmk{uid}' x1='0' y1='0' x2='1' y2='1'><stop offset='0' stop-color='#ffffff'/><stop offset='1' stop-color='#9a9ca4'/></linearGradient>"
            f"<radialGradient id='tpmb{uid}' cx='68%' cy='30%' r='90%'><stop offset='0' stop-color='#3a3a3f'/><stop offset='1' stop-color='#0b0b0c'/></radialGradient></defs>"
            f"<rect width='34' height='34' rx='9.5' fill='url(#tpmb{uid})'/><g fill='none' stroke-width='1.25' stroke-linecap='round'>{ridges}</g><circle cx='17' cy='17.4' r='1' fill='#c4a565'/></svg>")


def wordmark():
    """The wordmark is built from the product name: a name of two capitalized parts gets its second part in a lighter gold."""
    m = re.match(r"^(.*[a-z0-9])([A-Z][a-z0-9]+)$", BRAND)
    return f"{esc(m.group(1))}<b>{esc(m.group(2))}</b>" if m else esc(BRAND)


def logo(light=False):
    return f"<div class='tp-logo logo{' on-dark' if light else ''}'>{mark_svg(uid='l' if light else 'd')}<span class='w'>{wordmark()}</span></div>"


def sub_hero_html(eyebrow, title, lead, right="", long=False):
    """The header of an inner page: mono eyebrow, a gold rule, a serif title (may carry <em>), a lead, and either the given right side or the page's own print."""
    side = f"<div>{right}</div>" if right else f"<div class='quiet' aria-hidden='true'>{print_art('q', ridges=24, w=440, h=530, seed=art_seed(eyebrow), on='light', pts=28, sweep=False, kind=art_kind(eyebrow))}</div>"
    return (f"<div class='tp-hero sub{'' if right else ' single'}'><div class='grid'><div><span class='tp-eyebrow'>{esc(eyebrow)}</span>"
            f"<h1 class='{'long' if long else ''}'>{title}</h1><p class='lead'>{lead}</p></div>{side}</div></div>")


def section(kicker, title, text="", tight=False, art=None):
    """A section head. art (any text) adds a quiet partial print at the right, seeded by that text."""
    body = f"<div class='k'>{esc(kicker)}</div><h2>{esc(title)}</h2>{f'<p>{text}</p>' if text else ''}"
    if art:
        side = f"<div class='tp-secart' aria-hidden='true'>{print_art(ridges=16, w=360, h=430, seed=art_seed(art), on='light', pts=22, sweep=False, kind=art_kind(art))}</div>"
        H(f"<div class='tp-sec has-art{' tight' if tight else ''}'><div>{body}</div>{side}</div>")
    else:
        H(f"<div class='tp-sec{' tight' if tight else ''}'>{body}</div>")


def card_html(title, text, ico=None, tone="", no=None, extra=""):
    top = f"<div class='tp-ico {tone}'>{icon(ico)}</div>" if ico else ""
    n = f"<div class='no num' aria-label='Step {no}'>{no}</div>" if no else ""
    return f"<div class='tp-card tp-step'>{top}{n}<h5>{esc(title)}</h5><p>{text}</p>{extra}</div>"


def card(title, text, ico=None, tone="", no=None, extra=""):
    H(card_html(title, text, ico, tone, no, extra))


def grid(items, cols=None, gap=16):
    """A row of equal-height cards: items are HTML strings."""
    H(f"<div class='tp-grid' style='grid-template-columns:repeat({cols or len(items)},minmax(0,1fr));gap:{gap}px'>" + "".join(items) + "</div>")


def stats(items):
    """items: (value, label, tone). A row of headline numbers. The caller escapes values that come from a person."""
    long = lambda v: " long" if len(re.sub(r"<small>.*?</small>|<[^>]+>", "", str(v))) > 6 else ""
    H("<div class='tp-stats'>" + "".join(f"<div class='tp-stat {t}'><div class='bar'></div><div class='v{long(v)}'>{v}</div><div class='l'>{esc(l)}</div></div>" for v, l, t in items) + "</div>")


def chip(text, tone=""):
    return f"<span class='tp-chip {tone}'>{esc(text)}</span>"


def badge(text, tone="na"):
    return f"<span class='tp-badge {tone}'>{esc(text)}</span>"


def verdict_badge(v):
    v = v or "not measured"
    tone = ("no" if v.startswith("not worth") else
            "warn" if ("trade-off" in v or "breach" in v) else
            "ok" if v.startswith(("gain met", "worth it")) else "na")
    return badge(v, tone)


def legend(items, shapes=False):
    """items: (text, color). With shapes=True the swatches are the markers of the forest plot: circle, diamond, square, in that order.
    The experimental arm (copper) is always hatched."""
    out = []
    for n, (t, c) in enumerate(items):
        cls = (("c", "d", "q")[min(n, 2)] if shapes else "") + (" x" if c == COPPER else "")
        edge = f";box-shadow:inset 0 0 0 1px {SILVER_EDGE}" if c == SILVER else ""
        out.append(f"<span><i class='{cls.strip()}' style='background-color:{c}{edge}'></i>{esc(t)}</span>")
    return "<div class='tp-legend'>" + "".join(out) + "</div>"


# ---------------------------------------------------------------- charts (inline SVG)
HATCH = ("<defs><pattern id='tphx' width='5' height='5' patternUnits='userSpaceOnUse' patternTransform='rotate(45)'>"
         f"<rect width='5' height='5' fill='{COPPER}'/><rect width='2' height='5' fill='#e3bfa8'/></pattern></defs>")
_ON_DARK = {SILVER: "#8e8e93", GOLD: GOLD_BRIGHT, STEEL: "#8fa9d6", GRAPHITE: "#f5f5f7"}


def bars(rows, width=380, timed=False, dark=False):
    """Horizontal bars, one per training condition. rows: (label, value 0..1 or None, color, experimental?).
    Plain HTML, so the labels and numbers are real text at a readable size on every screen.
    timed=True grows the bars on load (for a chart that is on screen from the start); otherwise they grow as the chart scrolls into view."""
    out = [f"<div class='tp-bars{' dark' if dark else ''}{' timed' if timed else ''}'>"]
    for i, (label, v, color, exp) in enumerate(rows):
        missing = v is None or (isinstance(v, float) and math.isnan(v))
        txt = "not measured" if missing else f"{v * 100:.1f}%"
        w = 0.0 if missing else max(0.0, min(1.0, v)) * 100
        c = _ON_DARK.get(color, color) if dark else color
        cls = "tp-bar" + (" x" if exp else "") + (" s" if (color == SILVER and not dark) else "")
        fill = f"<i class='{cls}' style='width:{max(w, 1.6):.1f}%;background-color:{c};--i:{i}'></i>" if w > 0 else ""
        out.append(f"<div class='r'><span class='l'>{esc(label)}</span><span class='v{' nm' if missing else ''}'>{txt}</span><span class='tr'>{fill}</span></div>")
    out.append("</div>")
    return "".join(out)


def bullet(gain, lo, hi, color=GOLD, width=260):
    """One gain with its 95% range against the 5-point rule. Values in points (0..100)."""
    x = lambda v: 6 + max(-5.0, min(100.0, v)) / 100.0 * (width - 12)
    return (f"<svg class='tp-chart' viewBox='0 0 {width} 50' width='100%' style='margin-top:14px'>"
            f"<rect x='6' y='16' width='{width - 12}' height='4' rx='2' fill='{TRACK}'/>"
            f"<rect class='tp-range' x='{x(lo):.1f}' y='11' width='{max(3.0, x(hi) - x(lo)):.1f}' height='14' rx='7' fill='{color}' opacity='.26'/>"
            f"<circle cx='{x(gain):.1f}' cy='18' r='6' fill='{color}' stroke='#fff' stroke-width='2'/>"
            f"<line x1='{x(5):.1f}' y1='5' x2='{x(5):.1f}' y2='31' stroke='{RED}' stroke-width='1.2' stroke-dasharray='3 2.5'/>"
            f"<text x='{x(5) - 4:.1f}' y='45' font-size='10.5' fill='{RED}' font-weight='600'>5-point rule</text>"
            f"<text x='{width - 6}' y='45' font-size='10.5' fill='{MUTED}' text-anchor='end'>100 points</text></svg>")


def duo(a, b, la, lb, ca=INK, cb=SILVER, width=340):
    """Two bars against each other (for tracing: traced against the baseline). Values 0..1."""
    return bars([(la, a, ca, False), (lb, b, cb, False)]).replace("class='tp-bars", "class='tp-bars duo", 1)


def forest(rows, series, width=1140):
    """Gains with 95% ranges for many datasets. rows: dict(name, tag, vals={key: (gain, lo, hi) in points}); series: (key, label, color).
    Each series has its own marker (circle, diamond, square) so that the chart does not rest on color alone."""
    left, right, rh, top = 392, 30, 30, 40
    pw = width - left - right
    h = top + rh * len(rows) + 36
    x = lambda v: left + max(-4.0, min(100.0, v)) / 100.0 * pw
    out = [f"<div class='tp-scroll'><svg class='tp-chart' viewBox='0 0 {width} {h}' width='100%' style='background:transparent'>{HATCH}"]
    for g in (0, 25, 50, 75, 100):
        out.append(f"<line x1='{x(g):.1f}' y1='{top - 8}' x2='{x(g):.1f}' y2='{h - 32}' stroke='{LINE2}' stroke-width='1'/>"
                   f"<text x='{x(g):.1f}' y='{h - 13}' font-size='10.5' fill='{MUTED}' text-anchor='middle'>{'+' if g else ''}{g}</text>")
    out.append(f"<line x1='{x(5):.1f}' y1='{top - 8}' x2='{x(5):.1f}' y2='{h - 32}' stroke='{RED}' stroke-width='1.2' stroke-dasharray='4 3'/>"
               f"<text x='{x(5) + 6:.1f}' y='{top - 15}' font-size='10.5' fill='{RED}' font-weight='600'>5-point rule</text>"
               f"<text x='{width - right}' y='{top - 15}' font-size='10.5' fill='{MUTED}' text-anchor='end'>gain in attack-class recall against isolated training, points</text>")
    off = {0: -7, 1: 0, 2: 7}
    for i, r in enumerate(rows):
        y = top + i * rh + rh / 2
        if r.get("strong"):
            out.append(f"<rect x='8' y='{y - rh / 2:.1f}' width='{width - 16}' height='{rh}' rx='9' fill='{PAPER_DEEP}'/>")
        elif i % 2 == 0:
            out.append(f"<rect x='8' y='{y - rh / 2:.1f}' width='{width - 16}' height='{rh}' rx='9' fill='{VEIL}'/>")
        name = r["name"] if len(r["name"]) <= 50 else r["name"][:49] + "…"
        out.append(f"<text x='22' y='{y + 4:.1f}' font-size='12.5' fill='{INK}' font-weight='{650 if r.get('strong') else 500}'>{esc(name)}</text>")
        if r.get("tag"):
            out.append(f"<text x='{left - 14}' y='{y + 3.5:.1f}' font-size='9.5' fill='{GOLD_INK}' text-anchor='end' style='letter-spacing:.08em;text-transform:uppercase'>{esc(r['tag'])}</text>")
        for j, ser in enumerate(series):
            key, label, color = ser[:3]
            shape = ser[3] if len(ser) > 3 else ("circle", "diamond", "hatch")[min(j, 2)]      # a fourth element names the marker
            v = r["vals"].get(key)
            if not v:
                continue
            g, lo, hi = v[:3]
            yy = y + (off.get(j, 0) if len(series) > 1 else 0)
            tip = f"<title>{esc(r['name'])}, {esc(label)}: {g:+.1f} [{lo:+.1f}, {hi:+.1f}]{(', ' + esc(v[3])) if len(v) > 3 else ''}</title>"
            out.append(f"<line x1='{x(lo):.1f}' y1='{yy:.1f}' x2='{x(hi):.1f}' y2='{yy:.1f}' stroke='{color}' stroke-width='2' stroke-linecap='round' opacity='.5'/>")
            if shape == "diamond":
                out.append(f"<rect x='{x(g) - 3.6:.1f}' y='{yy - 3.6:.1f}' width='7.2' height='7.2' rx='1' transform='rotate(45 {x(g):.1f} {yy:.1f})' fill='{color}' stroke='#fff' stroke-width='1.2'>{tip}</rect>")
            elif shape in ("hatch", "square"):
                out.append(f"<rect x='{x(g) - 3.8:.1f}' y='{yy - 3.8:.1f}' width='7.6' height='7.6' rx='1' fill='{'url(#tphx)' if shape == 'hatch' else color}' stroke='#fff' stroke-width='1.2'>{tip}</rect>")
            else:
                out.append(f"<circle cx='{x(g):.1f}' cy='{yy:.1f}' r='4.4' fill='{color}' stroke='#fff' stroke-width='1.2'>{tip}</circle>")
    out.append("</svg></div>")
    return "".join(out)


def heat(v, exp=False):
    """A heat-map cell for a share between 0 and 1: gold for the training conditions, copper for the experimental arm. The text stays ink, which keeps its contrast on every shade."""
    if v is None or (isinstance(v, float) and math.isnan(v)):
        return f"<td class='heat' style='color:{MUTED};font-weight:400'>not measured</td>"
    rgb = "168,98,63" if exp else "157,133,82"
    a = 0.04 + 0.78 * max(0.0, min(1.0, v))
    return f"<td class='heat' style='background:rgba({rgb},{a:.2f})'>{v * 100:.1f}%</td>"


def table(df, wrap=(), raw=(), row_class=None):
    """A styled HTML table: numbers never wrap, the columns named in wrap do, the columns in raw carry HTML.
    The table sits in a holder that scrolls sideways on a narrow screen, with a fade at the edge to show there is more."""
    cols = list(df.columns)
    out = ["<div class='tp-tscroll'><table class='tp'><thead><tr>"] + [f"<th class='wrap'>{esc(c)}</th>" for c in cols] + ["</tr></thead><tbody>"]
    for n, (_, r) in enumerate(df.iterrows()):
        out.append(f"<tr class='{row_class(n, r) if row_class else ''}'>")
        for c in cols:
            cell = str(r[c]) if c in raw else esc(r[c])
            out.append(cell if (c in raw and cell.startswith("<td")) else f"<td class='{'wrap' if c in wrap else ''}'>{cell}</td>")
        out.append("</tr>")
    out.append("</tbody></table></div>")
    st.markdown("".join(out), unsafe_allow_html=True)


def cond_diagram(kind, dark=False):
    """A small moving picture of one training condition: three organizations and what travels between them
    (records as small squares, model weights as dots, nothing at all under isolated training). dark=True for a graphite ground."""
    A, B, C = (36, 70), (144, 70), (90, 20)
    ink, fill, edge = ("#f5f5f7", "#19191b", "#a1a1a6") if dark else (INK, "#fff", INK)
    gold, steel, graph, ring = (GOLD_BRIGHT, "#8fa9d6", "#e8e8ed", "#6e6e73") if dark else (GOLD, STEEL, GRAPHITE, SILVER)
    node = lambda p, t: (f"<circle cx='{p[0]}' cy='{p[1]}' r='13.5' fill='{fill}' stroke='{edge}' stroke-width='1.1'/>"
                         f"<text class='sf' x='{p[0]}' y='{p[1] + 4.3}' font-size='12.5' font-weight='500' text-anchor='middle' fill='{ink}'>{t}</text>")
    seg = lambda p, q: f"M{p[0]} {p[1]} L{q[0]} {q[1]}"
    mid = lambda p, q: ((p[0] + q[0]) / 2, (p[1] + q[1]) / 2)
    sq = lambda p, q, color, delay: f"<rect class='tp-mv' x='-3.5' y='-2.6' width='7' height='5.2' rx='1.1' fill='{color}' style=\"offset-path:path('{seg(p, q)}');animation-delay:{delay}s\"/>"
    dot = lambda p, q, color, delay: f"<circle class='tp-mv' r='2.7' fill='{color}' style=\"offset-path:path('{seg(p, q)}');animation-delay:{delay}s\"/>"
    body = ""
    if kind == "isolated":
        body = "".join(f"<circle cx='{p[0]}' cy='{p[1]}' r='19.5' fill='none' stroke='{ring}' stroke-width='1' stroke-dasharray='2 3'/>" for p in (A, B, C))
    elif kind in ("sharing", "fingerprint"):
        color = gold if kind == "sharing" else COPPER
        pairs = ((A, B), (B, C), (C, A), (B, A), (C, B), (A, C))
        dash = "stroke-dasharray='1 4' stroke-linecap='round'" if kind == "fingerprint" else ""
        body = "".join(f"<line x1='{p[0]}' y1='{p[1]}' x2='{q[0]}' y2='{q[1]}' stroke='{color}' stroke-width='1' opacity='.45' {dash}/>" for p, q in pairs[:3])
        make = sq if kind == "sharing" else (lambda p, q, c, dl: f"<circle class='tp-mv' r='2.4' fill='none' stroke='{c}' stroke-width='1.2' style=\"offset-path:path('{seg(p, q)}');animation-delay:{dl}s\"/>")
        body += "".join(make(p, q, color, -0.6 * i) for i, (p, q) in enumerate(pairs))
        body += "".join(f"<rect class='tp-st' x='{mid(p, q)[0] - 3.5:.1f}' y='{mid(p, q)[1] - 2.6:.1f}' width='7' height='5.2' rx='1.1' fill='{color}'/>" for p, q in pairs[:3])
    elif kind == "federated":
        M = (90, 54)
        body = "".join(f"<line x1='{p[0]}' y1='{p[1]}' x2='{M[0]}' y2='{M[1]}' stroke='{steel}' stroke-width='1' opacity='.5'/>" for p in (A, B, C))
        body += "".join(dot(p, M, steel, -1.2 * i) + dot(M, p, steel, -1.2 * i - 1.8) for i, p in enumerate((A, B, C)))
        body += f"<circle class='tp-hub' cx='{M[0]}' cy='{M[1]}' r='12' fill='{steel}' opacity='.14'/><circle cx='{M[0]}' cy='{M[1]}' r='7.5' fill='{steel}'/><path d='M{M[0] - 3.4} {M[1]}h6.8M{M[0]} {M[1] - 3.4}v6.8' stroke='{'#0b0b0c' if dark else '#fff'}' stroke-width='1.4' stroke-linecap='round'/>"
    elif kind == "centralized":
        M = (90, 54)
        body = "".join(f"<line x1='{p[0]}' y1='{p[1]}' x2='{M[0]}' y2='{M[1]}' stroke='{graph}' stroke-width='1' opacity='.3'/>" for p in (A, B, C))
        body += "".join(sq(p, M, graph, -1.2 * i) for i, p in enumerate((A, B, C)))
        body += f"<rect x='{M[0] - 28}' y='{M[1] - 11}' width='56' height='22' rx='11' fill='{graph}'/><text x='{M[0]}' y='{M[1] + 3.4}' font-size='8.6' fill='{'#0b0b0c' if dark else '#fff'}' font-weight='600' text-anchor='middle'>one place</text>"
    return f"<svg viewBox='0 0 180 96' width='100%' style='display:block;margin:-4px 0 6px 0' aria-hidden='true'>{body}{node(A, 'A')}{node(B, 'B')}{node(C, 'C')}</svg>"


def timeline(points):
    """points: (label, title, text). A horizontal timeline."""
    w, n = 1100, len(points)
    out = [f"<svg viewBox='0 0 {w} 126' width='100%' style='display:block'><line x1='60' y1='36' x2='{w - 60}' y2='36' stroke='{LINE}' stroke-width='1.2'/>"]
    for i, (lab, title, text) in enumerate(points):
        x = 60 + i * (w - 120) / (n - 1)
        anchor = "start" if i == 0 else ("end" if i == n - 1 else "middle")
        out.append(f"<circle cx='{x:.0f}' cy='36' r='6.5' fill='{'#fff' if i < n - 1 else INK}' stroke='{GOLD if i < n - 1 else INK}' stroke-width='2'/>"
                   f"<text x='{x:.0f}' y='16' font-size='10.5' font-weight='500' fill='{GOLD_INK}' text-anchor='{anchor}' style='letter-spacing:.14em;text-transform:uppercase;font-family:JetBrains Mono,monospace'>{esc(lab)}</text>"
                   f"<text class='sf' x='{x:.0f}' y='70' font-size='16' font-weight='500' fill='{INK}' text-anchor='{anchor}'>{esc(title)}</text>")
        for k, line in enumerate(text.split("|")):
            out.append(f"<text x='{x:.0f}' y='{90 + k * 16}' font-size='11.5' fill='{MUTED}' text-anchor='{anchor}'>{esc(line)}</text>")
    out.append("</svg>")
    return "".join(out)


# ---------------------------------------------------------------- live demo, sample cards, small heads
def rail(steps, done=0, now=None, times=None):
    """The stage rail: numbered steps, how many are finished, which one is running (0-based), seconds per finished stage. Returns HTML.
    Only the stage that has just finished animates, so a redraw does not replay the whole rail."""
    times = times or {}
    out = ["<div class='tp-rail'>"]
    for i, name in enumerate(steps):
        state = "done" if i < done else ("now" if now == i else "todo")
        mark = icon("check", 15, 3) if state == "done" else str(i + 1)
        t = times.get(i)
        took = ("under 0.1 s" if t < 0.1 else f"{t:.1f} s") if (state == "done" and t is not None) else ("running" if state == "now" else "")
        out.append(f"<div class='s {state}{' new' if (state == 'done' and i == done - 1) else ''}'><span class='n'>{mark}</span><div class='t'>{esc(name)}</div><div class='e'>{took}</div></div>")
    out.append("</div>")
    return "".join(out)


def stage_head_html(no, title, what="", elapsed=None, extra="", lead="What just happened."):
    """The head of one stage of the live demo as HTML: number, title, time taken and one plain line saying what happened (what may carry HTML)."""
    took = ""
    if elapsed is not None:
        took = chip("under 0.1 s" if elapsed < 0.1 else f"{elapsed:.1f} s", "teal")
    return (f"<div class='tp-stagehead'><span class='n'>{no}</span><div><div class='k'>Stage {no} of 6</div><div class='t'>{esc(title)}</div></div><div class='r'>{extra}{took}</div></div>"
            + (f"<div class='tp-what'><b>{esc(lead)}</b> {what}</div>" if what else ""))


def stage_head(no, title, what="", elapsed=None, extra="", lead="What just happened."):
    H(stage_head_html(no, title, what, elapsed, extra, lead))


def step_head_html(no, title, text=""):
    """A numbered step inside a page (the Evaluate flow). text may carry HTML."""
    return (f"<div class='tp-stephead'><span class='n'>{no}</span><div><div class='t'>{esc(title)}</div>" + (f"<div class='s'>{text}</div>" if text else "") + "</div></div>")


def sample_card(title, sector, kind, summary, licence=""):
    """A card for one sample file, with the sample's own print. kind: 'synthetic', 'real' or 'built in'."""
    tone = {"real": "ok", "synthetic": "amber"}.get(kind, "na")
    label = kind + " data" if kind in ("real", "synthetic") else kind
    return (f"<div class='tp-card tp-sample'>{mini_print(title, 74)}<div class='top'><span class='sector'>{esc(sector)}</span></div>"
            f"<h5>{esc(title)}</h5><div>{badge(label, tone)}</div><p>{esc(summary)}</p>" + (f"<div class='lic'>{esc(licence)}</div>" if licence else "") + "</div>")


# ---------------------------------------------------------------- set pieces and editorial components (no card grids where the content is prose)
def figure(html, label, caption):
    """A chart as a figure: the drawing, then a labelled caption. caption may carry HTML that the caller has escaped."""
    return f"<figure class='tp-fig'>{html}<figcaption><b>{esc(label)}</b>{caption}</figcaption></figure>"


def steps_scene(steps):
    """The five steps as one line that draws itself as the page scrolls, with a station and a large numeral per step. steps: (title, text)."""
    items = "".join(f"<li style='--i:{i}'><span class='n' aria-hidden='true'>{i + 1}</span><h4>{esc(t)}</h4><p>{x}</p></li>" for i, (t, x) in enumerate(steps))
    return f"<div class='tp-steps'><ol>{items}</ol></div>"


def conditions_scene(kicker, title, text, conds, light=False):
    """The four training conditions as one scene on a graphite plate (or, with light=True, as a quiet strip on paper):
    A, B and C with what travels under each condition. conds: (kind, name, text); text may carry HTML."""
    cells = "".join(f"<div class='c' style='--i:{i}'><div class='i'>{i + 1} of {len(conds)}</div>{cond_diagram(kind, dark=not light)}<h4>{esc(name)}</h4><p>{x}</p></div>" for i, (kind, name, x) in enumerate(conds))
    if light:
        return f"<div class='tp-conds light'>{cells}</div>"
    head = f"<div class='k'>{esc(kicker)}</div><h2>{esc(title)}</h2><p>{text}</p>"
    return f"<div class='tp-plate'><div class='tp-plateart' aria-hidden='true'>{print_art('pl', ridges=22, w=520, h=620, seed=2.01, on='dark', pts=28, sweep=False, kind='loop')}</div>{head}<div class='tp-conds'>{cells}</div></div>"


def rule_scene(items):
    """The decision rule as three large marks under hairlines. items: (label, big, unit, text); big may be a numeral or HTML (a small print)."""
    out = []
    for i, (label, big, unit, text) in enumerate(items):
        glyph = f"<b>{big}</b>" if len(str(big)) <= 3 else str(big)
        out.append(f"<div class='r' style='--i:{i}'><div class='l'>{esc(label)}</div><div class='g'>{glyph}<span>{esc(unit)}</span></div><p>{text}</p></div>")
    return "<div class='tp-rule'>" + "".join(out) + "</div>"


def rows(items, cols=1, start=1, numbered=True):
    """Editorial rows under hairlines instead of a grid of cards. items: (title, text, meta); text and meta may carry HTML the caller has escaped.
    Each row gets a large serif numeral; cols=2 sets the rows in two columns."""
    out = [f"<div class='tp-rows c{cols}{'' if numbered else ' nn'}'>"]
    for i, it in enumerate(items):
        title, text = it[0], it[1]
        meta = it[2] if len(it) > 2 else ""
        num = f"<span class='n' aria-hidden='true'>{i + start}</span>" if numbered else ""
        out.append(f"<div class='r'>{num}<div class='b'><h4>{esc(title)}</h4><p>{text}</p></div>" + (f"<div class='m'>{meta}</div>" if meta else "") + "</div>")
    out.append("</div>")
    return "".join(out)


def deflist(pairs):
    """Terms and their definitions in two ruled columns, the way a glossary is set in a book."""
    return "<dl class='tp-dl'>" + "".join(f"<div><dt>{esc(t)}</dt><dd>{esc(d)}</dd></div>" for t, d in pairs) + "</dl>"


def way_html(no, title, text):
    """One of several ways forward: a mono index, a serif title and a line of text. The page link that belongs to it is drawn right under it by the caller."""
    return f"<div class='tp-wayt'><span class='n'>{no:02d}</span><h4>{esc(title)}</h4><p>{text}</p></div>"


def kv(pairs):
    """A two-column list of facts. pairs: (name, value); the value may carry HTML."""
    return "<dl class='tp-kv'>" + "".join(f"<dt>{esc(k)}</dt><dd>{v}</dd>" for k, v in pairs) + "</dl>"


# ---------------------------------------------------------------- the downloadable report (one self-contained file: no outside fonts, images or scripts)
REPORT_CSS = (
    "body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;color:#1d1d1f;background:#fff;max-width:1000px;margin:44px auto;padding:0 28px;line-height:1.58;font-size:15px;-webkit-font-smoothing:antialiased}"
    ".brand{display:flex;align-items:center;gap:10px;font-weight:650;font-size:1.05rem;letter-spacing:-.03em;padding-bottom:18px;border-bottom:1px solid #e3e0d8}.brand b{font-weight:400;color:#7a6537}"
    "h1,h2,h3{font-family:'Iowan Old Style','Palatino Linotype',Palatino,'Source Serif 4',Georgia,serif;font-weight:500;letter-spacing:-.02em;color:#1d1d1f}"
    "h1{font-size:2.5rem;line-height:1.1;margin:34px 0 8px}h2{font-size:1.4rem;margin:44px 0 10px;padding-top:18px;border-top:1px solid #e3e0d8;position:relative}"
    "h2::before{content:'';position:absolute;left:0;top:-1.5px;width:46px;height:2px;background:#9d8552}h3{font-size:1.08rem;margin:26px 0 4px}"
    "p{margin:8px 0}table{border-collapse:collapse;width:100%;font-size:.8rem;margin:10px 0 6px;font-variant-numeric:tabular-nums}"
    "th{text-align:left;vertical-align:bottom;padding:8px 9px;border-bottom:1px solid #1d1d1f;font-size:.66rem;letter-spacing:.08em;text-transform:uppercase;color:#6e6e73;font-weight:600}"
    "td{padding:7px 9px;border-bottom:1px solid #eeebe4;color:#424245}"
    ".small{font-size:.86rem;color:#424245}.muted{color:#6e6e73;font-size:.8rem}.box{background:#f4efe3;border-left:2px solid #9d8552;padding:16px 20px;border-radius:0 12px 12px 0;margin:26px 0 14px;font-size:.92rem}"
    "@page{margin:16mm 14mm}@media print{body{margin:0;max-width:none;padding:0;font-size:11pt}h2{break-after:avoid}table,.box{break-inside:avoid}.brand{padding-bottom:10px}}")
