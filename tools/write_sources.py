"""Write ../Praxis_Lab_Datasets/SOURCES.md from the settings files: one entry per dataset with maker, year, what it is,
what was sampled, the source link and the licence note.    python3 tools/write_sources.py"""
import glob
import json
import os

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DS = os.path.abspath(os.path.join(HERE, "..", "Praxis_Lab_Datasets"))
rows = []
for f in sorted(glob.glob(os.path.join(DS, "settings", "*.json"))):
    s = json.load(open(f))
    i = s.get("info", {})
    p = os.path.join(DS, s["paths"][0])
    size = f"{os.path.getsize(p) / 1e6:.0f} MB" if os.path.exists(p) else "not downloaded"
    rows.append(f"""### {s['name']} (`{s['id']}`)

{i.get('what', '')}

- Made by: {i.get('maker', '')} ({i.get('year', '')})
- Source: {i.get('source', '')}
- Working sample: `{s['paths'][0]}` ({size}); {i.get('records', '')}
- Attack types: {i.get('attacks', '')}
- Host column: {i.get('host', '')}; label column: `{s['label_col']}`; normal value: `{s['benign_label']}`
- Licence and use: {i.get('licence', 'cite the makers; analysis use')}
""")
head = """# Datasets used by ThreatPrint

Working samples (at most 120,000 records, sampled by label so that rare attack types survive) made with `Praxis_Lab/tools/sample_dataset.py`
from the makers' files. Each has a settings file in `settings/` (label column, normal value, host column, time column, columns removed before
sharing). The raw files were only read. These samples are for analysis and teaching; they are not re-hosted publicly, and every dataset keeps
its makers' licence and citation.

Seven datasets were already run in October 2026 from `Praxis_System/data/samples` (DataSense, Edge-IIoTset cleaned file, NF-ToN-IoT-v3, X-IIoTID,
WUSTL-IIoT-2021, BoT-IoT sample, UNSW-NB15); their cards are in `Praxis_Lab/results/`.

Not included, and why: Kaggle and IEEE DataPort releases (X-IIoTID, MQTT-IoT-IDS2020, IoTID20, ACI-IoT-2023, TII-SSRC-23) need a sign-in;
the Canadian Institute for Cybersecurity now routes CIC-DDoS2019, CICIoMT2024 and CICAPT-IIoT downloads through a request form; KDD Cup 1999 on
UCI is a set of broken links; WUSTL-EHMS-2020 is served with a self-signed certificate; Gotham 2025 (24 GB), Kitsune (several GB) and
CSE-CIC-IDS2018 improved (10 GB) were too large for this round; HAI, SWaT and Kyoto 2006+ carry a yes/no label only, and the procedure needs
at least three attack types.

"""
open(os.path.join(DS, "SOURCES.md"), "w").write(head + "\n".join(rows))
print("wrote SOURCES.md with", len(rows), "entries")
