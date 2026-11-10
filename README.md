---
title: ThreatPrint
colorFrom: green
colorTo: indigo
sdk: streamlit
sdk_version: 1.50.0
app_file: app.py
pinned: false
---

# ThreatPrint

Know what sharing buys. Know what it exposes. A web product that runs a privacy-aware evaluation of collaborative intrusion detection on any labeled intrusion dataset: upload a table, confirm which columns are identifiers, and the tool makes three organizations, withholds one attack type from each, trains one detector per organization under four training conditions (isolated training, sanitized attack-record sharing, federated learning, centralized training), tests on the withheld attack type and reports the gains with 95% ranges, the false-positive rates, the data sent, and whether the sanitized records can be traced back to their source host.

The procedure is the frozen protocol of a George Washington University Doctor of Engineering praxis by Rayve Malhotra: *Privacy-Aware Evaluation of Sanitized Attack-Record Sharing and Federated Learning for Intrusion Detection on Industrial Network Data*. The engine (`engine.py`) is the praxis code (`system.py`) as a library; the study logic is unchanged.

## Run it on your computer (one command)

Python 3.10 or newer.

```
pip install -r requirements.txt          # Linux or Windows (CPU build of PyTorch)
pip install -r requirements-mac.txt      # macOS
streamlit run app.py
```

Then open http://localhost:8501.

## What is in the folder

| File | What |
|---|---|
| `app.py` | the web product: Overview, Results, Evaluate, Sanitize, Agent, Research, Organizations, Glossary, Students |
| `ui.py` | the design system: colors, type, cards, badges and the charts (bars, forest plot, heat map, diagrams) drawn as inline SVG, no chart library |
| `static/` | the two typefaces served with the app (Inter and JetBrains Mono, SIL Open Font License; the licence texts are in the folder), so that no page calls a third-party server |
| `engine.py` | the five-step procedure as a library: `engine.run(settings, frame=DataFrame, budget=engine.QUICK or engine.PROTOCOL)` returns the scorecard; `engine.inspect(df)` guesses column roles; `engine.sanitize(...)` returns what a peer would receive |
| `threatprint_agent.py` | the local agent, one readable file with no network code (pandas and numpy only): an organization runs it on its own machine; it guesses column roles, sanitizes, maps attack labels to common families and MITRE ATT&CK v20.1, and writes a fingerprint (summary statistics per attack type, no records) with a SHA3-256 integrity digest. Also the single definition of the column rules the web tool uses |
| `fp_experiment.py` | fingerprint sharing as an experimental fifth arm (not a praxis training condition): the receiver trains on its own records plus made-up records drawn from its peers' fingerprints; `tools/run_fingerprint.py` runs it on every dataset |
| `samples/` | two files to try the tool with: a synthetic water utility (made by `tools/make_sample_org.py`) and a sample of real power-grid DNP3 flows (CC BY 4.0, see `samples/README.md`) |
| `tools/verify_attack_ids.py` | checks every MITRE ATT&CK identifier and name used by the agent against MITRE's published STIX data |
| `results/*.json` | one scorecard per dataset shown on the results page: the praxis dataset (DataSense CIC IIoT 2025), the ranking check (Edge-IIoTset) and public intrusion datasets run with the protocol budget (`tools/run_all.py`) |
| `tools/sample_dataset.py` | makes a working sample of a large labeled file without loading it whole (chunked, sampled by label, zip members allowed) |
| `tools/run_all.py` | runs the procedure on every dataset that has a settings file in `../Praxis_Lab_Datasets/settings/`, protocol budget, cached and resumable |
| `tools/make_settings.py`, `tools/write_sources.py` | the settings files and `SOURCES.md` of the dataset folder (maker, year, link, licence note) |
| `tools/build_nbaiot.py`, `tools/fetch_big_on_mac.sh` | helpers used to fetch and sample the larger public datasets |
| `tests/test_app.py` | headless tests of the engine and every page, including an end-to-end run on the built-in example: `python -m pytest tests -q` |
| `tests/screenshots.py` | opens every page in a headless browser and saves screenshots (needs Playwright) |
| `tests/rebuild_cards.py` | rebuilds `results/*.json` from the cached training runs of `system.py` (praxis folders, read only) |
| `Dockerfile` | the same tool in a container, port 7860 |
| `.streamlit/config.toml` | upload limit 200 MB, usage statistics off, minimal toolbar, the theme and the self-hosted typefaces |
| `share.sh` | runs the app with a password on a temporary public https link from one computer (Cloudflare quick tunnel) |

## Using the engine without the web page

```python
import pandas as pd, engine
df = pd.read_csv("my_records.csv")
roles = engine.inspect(df)                      # label_col, benign_label, source_col, time_col, identifiers, numbers
cfg = dict(name="my data", label_col=roles["label_col"], benign_label=roles["benign_label"],
           source_col=roles["source_col"], time_col=roles["time_col"], drop=roles["identifiers"])
card = engine.run(cfg, frame=df, budget=engine.QUICK, log=print)   # engine.PROTOCOL for the full budget
print(card["hypotheses"], card["verdicts"])
```

Budgets: `QUICK` (one seed, 24 passes, 400 resamples, 40,000 records at most) shows whether the data works in the tool. `PROTOCOL` (three seeds, 61 passes of the largest organization at batch 128, 2,000 resamples over attack events, the nothing-withheld check, tracing with five random forests and a 200-shuffle test) is the praxis budget and the one to report.

## The local agent and the fingerprint

```
python threatprint_agent.py my_records.csv                      # writes my_records.fingerprint.json; nothing is sent anywhere
python threatprint_agent.py my_records.csv --sanitized out.csv  # also writes the sanitized attack records
python threatprint_agent.py --verify my_records.fingerprint.json
```

For every attack type with at least 50 records the fingerprint stores the record count rounded down to the nearest ten, 41 quantiles (1% to 99%) of every behavior number and the rank correlations between them. It stores no rows, no identifier columns and no minimum or maximum values. It is a summary, not a formal privacy protection; what a fingerprint reveals about its sender has not been measured. The Agent page of the web product checks the digest of an uploaded fingerprint, shows the MITRE ATT&CK coverage, compares it with the library and reports whether the full evaluation can run on the data behind it. The signature field is reserved for a post-quantum signature (ML-DSA, FIPS 204); signing is designed, not built.

Fingerprint sharing (train on made-up records drawn from peers' fingerprints) is an experiment of this tool. It is not one of the four training conditions of the praxis, and its results are shown apart from them.

## Access password

With no password set, the tool is open (a local install). To ask visitors for a shared password, set the environment variable `TP_PASSWORD`
(on Streamlit Community Cloud or a Hugging Face Space: a secret with that name), or put `[access]` / `password = "..."` in `.streamlit/secrets.toml`
(never committed). A wrong try is slowed down; a right one is remembered in the browser for a day.

## Publishing (free hosts)

The repository is ready for Streamlit Community Cloud (deploy `app.py` from the GitHub repository; 1 GB of memory, so prefer the quick look there)
or a Hugging Face Space (Streamlit SDK; the front matter at the top of this file is read by the Space; 16 GB of memory, protocol runs are fine).
A protocol run on a large upload can take tens of minutes on a free host; the quick look takes about a minute. Any machine with Docker:
`docker build -t threatprint . && docker run -p 7860:7860 threatprint`. Tests run on every push (`.github/workflows/tests.yml`).

## Adding a dataset

Put the CSV in `../Praxis_Lab_Datasets/`, add a settings file in `../Praxis_Lab_Datasets/settings/` (copy one; set `paths`, `label_col`, `benign_label`, and when present `source_col` and `time_col`; list identifier columns under `drop`, number columns whose names look like identifiers under `keep`, labels to leave out under `drop_labels`, renames under `label_map`), then run `python tools/run_all.py --only <id>`. The card appears on the results page.

## What the tool does not do

It does not store uploads; everything runs in the session. It does not apply differential privacy or any control beyond removing identifiers: sanitized means direct identifiers removed, nothing more. The study claims rest on the DataSense dataset alone; every other dataset and every upload shows that the procedure runs on new data, with the tool's own unaudited splits. The membership test on model weights of the praxis is not part of this tool.

## Credits

Study design, protocol, hypotheses and decisions: Rayve Malhotra. Research advisor: Prof. Fossaceca, George Washington University. Datasets belong to their makers, named on each result page. AI-assisted engineering of the tool (Claude, November 2026).
