---
title: Praxis Lab
colorFrom: blue
colorTo: gray
sdk: streamlit
sdk_version: 1.50.0
app_file: app.py
pinned: false
---

# Praxis Lab

Does sharing help, and what does it expose? A web tool that runs a privacy-aware evaluation of collaborative intrusion detection on any labeled intrusion dataset: upload a table, confirm which columns are identifiers, and the tool makes three organizations, withholds one attack type from each, trains one detector per organization under four training conditions (isolated training, sanitized attack-record sharing, federated learning, centralized training), tests on the withheld attack type and reports the gains with 95% ranges, the false-positive rates, the data sent, and whether the sanitized records can be traced back to their source host.

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
| `app.py` | the web tool: Start here, Results on the datasets, Evaluate your own data, Sanitize a file, Definitions, For students |
| `engine.py` | the five-step procedure as a library: `engine.run(settings, frame=DataFrame, budget=engine.QUICK or engine.PROTOCOL)` returns the scorecard; `engine.inspect(df)` guesses column roles; `engine.sanitize(...)` returns what a peer would receive |
| `results/*.json` | one scorecard per dataset shown on the results page: the praxis dataset (DataSense CIC IIoT 2025), the ranking check (Edge-IIoTset) and public intrusion datasets run with the protocol budget (`tools/run_all.py`) |
| `tools/sample_dataset.py` | makes a working sample of a large labeled file without loading it whole (chunked, sampled by label, zip members allowed) |
| `tools/run_all.py` | runs the procedure on every dataset that has a settings file in `../Praxis_Lab_Datasets/settings/`, protocol budget, cached and resumable |
| `tools/make_settings.py`, `tools/write_sources.py` | the settings files and `SOURCES.md` of the dataset folder (maker, year, link, licence note) |
| `tools/build_nbaiot.py`, `tools/fetch_big_on_mac.sh` | helpers used to fetch and sample the larger public datasets |
| `tests/test_app.py` | headless tests of the engine and every page, including an end-to-end run on the built-in example: `python -m pytest tests -q` |
| `tests/screenshots.py` | opens every page in a headless browser and saves screenshots (needs Playwright) |
| `tests/rebuild_cards.py` | rebuilds `results/*.json` from the cached training runs of `system.py` (praxis folders, read only) |
| `Dockerfile` | the same tool in a container, port 7860 |
| `.streamlit/config.toml` | upload limit 200 MB, usage statistics off, minimal toolbar |
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

## Access password

With no password set, the tool is open (a local install). To ask visitors for a shared password, set the environment variable `PRAXIS_LAB_PASSWORD`
(on Streamlit Community Cloud or a Hugging Face Space: a secret with that name), or put `[access]` / `password = "..."` in `.streamlit/secrets.toml`
(never committed). A wrong try is slowed down; a right one is remembered in the browser for a day.

## Publishing (free hosts)

The repository is ready for Streamlit Community Cloud (deploy `app.py` from the GitHub repository; 1 GB of memory, so prefer the quick look there)
or a Hugging Face Space (Streamlit SDK; the front matter at the top of this file is read by the Space; 16 GB of memory, protocol runs are fine).
A protocol run on a large upload can take tens of minutes on a free host; the quick look takes about a minute. Any machine with Docker:
`docker build -t praxis-lab . && docker run -p 7860:7860 praxis-lab`. Tests run on every push (`.github/workflows/tests.yml`).

## Adding a dataset

Put the CSV in `../Praxis_Lab_Datasets/`, add a settings file in `../Praxis_Lab_Datasets/settings/` (copy one; set `paths`, `label_col`, `benign_label`, and when present `source_col` and `time_col`; list identifier columns under `drop`, number columns whose names look like identifiers under `keep`, labels to leave out under `drop_labels`, renames under `label_map`), then run `python tools/run_all.py --only <id>`. The card appears on the results page.

## What the tool does not do

It does not store uploads; everything runs in the session. It does not apply differential privacy or any control beyond removing identifiers: sanitized means direct identifiers removed, nothing more. The study claims rest on the DataSense dataset alone; every other dataset and every upload shows that the procedure runs on new data, with the tool's own unaudited splits. The membership test on model weights of the praxis is not part of this tool.

## Credits

Study design, protocol, hypotheses and decisions: Rayve Malhotra. Research advisor: Prof. Fossaceca, George Washington University. Datasets belong to their makers, named on each result page. AI-assisted engineering of the tool (Claude, November 2026).
