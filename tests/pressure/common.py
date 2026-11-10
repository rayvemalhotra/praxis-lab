"""Shared helpers of the pressure suite."""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
QA = os.path.join(ROOT, "qa")
DATASETS = os.path.abspath(os.path.join(ROOT, "..", "Praxis_Lab_Datasets"))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
if os.environ.get("TP_ENGINE_DIR"):                      # compare with another copy of engine.py and threatprint_agent.py (for example the last commit)
    sys.path.insert(0, os.environ["TP_ENGINE_DIR"])
os.makedirs(QA, exist_ok=True)


def auto_cfg(df, ins, name="your data"):
    """The settings the upload page builds when a person accepts every suggestion of engine.inspect (app._confirm_columns)."""
    import engine
    cols = list(df.columns)
    fixed = {ins["label_col"], ins["source_col"], ins["time_col"]} - {None}
    rest = [c for c in cols if c not in fixed]
    removed = [c for c in ins["identifiers"] + ins["label_cols"] + ins["text_columns"] + ins["unusable"] if c in rest]
    numbers = [c for c in rest if c not in removed]
    return dict(name=name, label_col=ins["label_col"], benign_label=ins["benign_label"], source_col=ins["source_col"], time_col=ins["time_col"],
                drop=removed, label_cols=[], keep=[c for c in numbers if engine.IDENT_RX.search(c)]), numbers


def save(name, obj):
    import platform
    import time
    with open(os.path.join(QA, name), "w") as fh:
        json.dump(obj, fh, indent=1, default=str)
    meta_path = os.path.join(QA, "runs_meta.json")
    meta = json.load(open(meta_path)) if os.path.exists(meta_path) else {}
    meta[name] = dict(when=time.strftime("%Y-%m-%d %H:%M"), machine=f"{platform.system()} {platform.machine()}, {os.cpu_count()} cores", python=platform.python_version())
    with open(meta_path, "w") as fh:
        json.dump(meta, fh, indent=1)


def load(name, default=None):
    p = os.path.join(QA, name)
    return json.load(open(p)) if os.path.exists(p) else default
