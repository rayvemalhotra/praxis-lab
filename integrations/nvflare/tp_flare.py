"""ThreatPrint on NVIDIA FLARE: the federated learning condition of the engine as a FLARE FedAvg job.

Product research. NOT part of the praxis: the praxis federated condition is the engine's own FedAvg loop
(engine.Bench.run), and the praxis scope names no other framework. Nothing here changes a praxis number.

What is the same as the engine's federated condition (read from the engine, not copied):
  the detector (engine.Detector), the training loop (engine.Bench.train), batch size and learning rate (engine.BATCH,
  engine.LR), local passes per round and the training budget (engine.Budget), the number of rounds (the engine's rule,
  checked against the engine's own run), scaling fitted on each organization's own records, weighting by the number of
  an organization's own training records, the alarm rule and the scoring (engine.Bench.test).
What cannot be the same: the random draws (starting weights and shuffling order), because the engine draws them from
  one stream shared by its four training conditions. See README.md.
"""
import glob
import json
import math
import os
import platform
import shutil
import sys
import time

import numpy as np
import pandas as pd
import torch

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
for _p in (ROOT, HERE):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import engine  # noqa: E402
import site_train  # noqa: E402

ORG = engine.ORG
SITE = {o: f"site-{o}" for o in ORG}                       # FLARE site names
INITIAL = "initial_global_model.pt"
BUDGETS = {"quick": engine.QUICK, "protocol": engine.PROTOCOL}
SAMPLES = {"example": None,
           "water_utility": os.path.join(ROOT, "samples", "sample_organization_water_utility_SYNTHETIC.csv")}


# ---------------------------------------------------------------- the table and the three organizations, as the engine makes them
def load_table(which):
    """'example' (the built-in made-up table), a name in SAMPLES, or a path to a CSV or Parquet file."""
    if which == "example":
        return engine.example_data(), "built-in example"
    path = SAMPLES.get(which, which)
    return engine.read_table(path), os.path.basename(path)


def auto_cfg(df, name):
    """The settings the web tool uses when a person accepts every column role it proposes (app.auto_cfg with nothing changed)."""
    ins = engine.inspect(df)
    if not ins["label_col"]:
        raise engine.DataProblem("no label column was recognized in this table")
    label_col, source_col, time_col = ins["label_col"], ins["source_col"], ins["time_col"]
    fixed = {label_col, source_col, time_col} - {None}
    rest = [c for c in df.columns if c not in fixed]
    removed = [c for c in ins["identifiers"] + ins["label_cols"] + ins["text_columns"] + ins["unusable"] if c in rest]
    numbers = [c for c in rest if c not in removed]
    cfg = dict(name=name, label_col=label_col, benign_label=ins["benign_label"], source_col=source_col, time_col=time_col,
               drop=removed, label_cols=[], keep=[c for c in numbers if engine.IDENT_RX.search(c)])
    if df[label_col].isna().any():
        cfg["drop_labels"] = ["nan"]
    return cfg


def build(df, name, budget):
    """engine.Data and engine.Bench for a table, with the engine's own fallback to random thirds (engine._run)."""
    cfg = auto_cfg(df, name)
    try:
        data = engine.Data(cfg, frame=df, budget=budget)
    except engine.DataProblem as e:
        if not (cfg.get("source_col") and "normal validation records" in str(e)):
            raise
        data = engine.Data(dict(cfg, companies="random"), frame=df, budget=budget)
    return cfg, data, engine.Bench(data, budget=budget)


def own_records(data):
    """An organization's own training records in the test world: its withheld attack type taken out (engine.Bench.run, world 0)."""
    return {o: data.TR[o][data.TR[o].y != data.never[o]] for o in ORG}


def plan(data, bench):
    """Training budget, local steps and rounds by the engine's rule (engine.Bench.run). run_simulator checks the rounds
    against the number the engine itself reports."""
    own, b = own_records(data), bench.b
    total = b.passes * math.ceil(max(len(own[o]) for o in ORG) / engine.BATCH)
    local = {o: b.local_epochs * math.ceil(len(own[o]) / engine.BATCH) for o in ORG}
    return dict(total_steps=int(total), local_steps={o: int(v) for o, v in local.items()},
                rounds=int(max(1, round(total / sum(local.values())))), records={o: int(len(own[o])) for o in ORG})


# ---------------------------------------------------------------- what each site holds
def write_sites(data, bench, root, seed):
    """One folder per organization with ITS OWN training records only (behavior numbers and attack type: what
    engine.Data.clean lets out of an organization, here not even leaving the site), a contract every site shares,
    and the starting weights of the shared detector. Returns the contract."""
    os.makedirs(root, exist_ok=True)
    own = own_records(data)
    contract = dict(features=list(bench.F), classes=[str(c) for c in bench.le.classes_], benign=str(data.benign),
                    local_epochs=int(bench.b.local_epochs), batch=int(engine.BATCH), learning_rate=float(engine.LR), seed=int(seed),
                    sites={SITE[o]: dict(organization=o, index=i) for i, o in enumerate(ORG)})
    with open(os.path.join(root, site_train.CONTRACT), "w") as fh:
        json.dump(contract, fh, indent=1)
    for o in ORG:
        os.makedirs(os.path.join(root, SITE[o]), exist_ok=True)
        rows = data.clean(own[o])
        rows.assign(y=rows["y"].astype(str)).to_parquet(os.path.join(root, SITE[o], site_train.TRAIN_FILE), index=False)
        s = site_train.setup(root, SITE[o])                    # the site's view must equal the engine's view of the same records
        assert torch.equal(s.Y, bench.Y(own[o])), f"labels of {SITE[o]} are not encoded as the engine encodes them"
        assert s.records == len(own[o])
    torch.manual_seed(seed)
    torch.save(engine.Detector(bench.NF, bench.C).state_dict(), os.path.join(root, INITIAL))
    return contract


# ---------------------------------------------------------------- the FLARE job
def make_recipe(root, contract, pl, name="threatprint_fedavg", trace_dir=""):
    """The federated learning condition as an NVIDIA FLARE FedAvg job (FLARE Recipe API).
    trace_dir: for checking only, every site keeps a copy of the shared detector it receives at the start of each round."""
    from nvflare.app_opt.pt.recipes.fedavg import FedAvgRecipe
    if " " in root or " " in trace_dir:
        raise ValueError("the data folder must have no space in its path (it is passed to the site script as an argument)")
    # FLARE weights a site by aggregation_weight x the optimizer steps it reports. The engine weights an organization by its
    # number of own training records. records / steps as the aggregation weight gives each site exactly its record count.
    weights = {SITE[o]: pl["records"][o] / pl["local_steps"][o] for o in ORG}
    recipe = FedAvgRecipe(
        name=name, min_clients=len(ORG), num_rounds=pl["rounds"],
        model={"class_path": "engine.Detector", "args": {"n_in": len(contract["features"]), "n_classes": len(contract["classes"])}},
        initial_ckpt=os.path.join(root, INITIAL),
        train_script=os.path.join(HERE, "flare_client.py"), train_args=f"--data_root {root}" + (f" --trace_dir {trace_dir}" if trace_dir else ""),
        aggregation_weights=weights)
    for f in (os.path.join(HERE, "site_train.py"), os.path.join(ROOT, "engine.py"), os.path.join(ROOT, "threatprint_agent.py")):
        recipe.add_client_file(f)                              # the job carries the engine, so a site needs no ThreatPrint install
    for f in (os.path.join(ROOT, "engine.py"), os.path.join(ROOT, "threatprint_agent.py")):
        recipe.add_server_file(f)
    return recipe


def run_flare(root, contract, pl, workspace, threads=None, name="threatprint_fedavg", trace_dir=""):
    """Run the job in the FLARE simulator (CPU). Returns the folder of the finished run."""
    from nvflare.recipe import SimEnv
    recipe = make_recipe(root, contract, pl, name=name, trace_dir=trace_dir)
    env = SimEnv(clients=[SITE[o] for o in ORG], num_threads=threads or len(ORG), workspace_root=workspace)
    recipe.run(env)                                            # blocks until the simulation ends; raises if it failed
    return os.path.join(workspace, name)


def global_model(run_dir, contract):
    """The shared detector FLARE saved after the last round, as an engine.Detector."""
    from nvflare.app_common.app_constant import DefaultCheckpointFileName
    found = glob.glob(os.path.join(run_dir, "**", DefaultCheckpointFileName.GLOBAL_MODEL), recursive=True)
    if not found:
        raise FileNotFoundError(f"FLARE saved no {DefaultCheckpointFileName.GLOBAL_MODEL} under {run_dir}")
    saved = torch.load(found[0], map_location="cpu", weights_only=False)
    state = saved["model"] if isinstance(saved, dict) and "model" in saved else saved
    m = engine.Detector(len(contract["features"]), len(contract["classes"]))
    m.load_state_dict({k: torch.as_tensor(np.asarray(v)) for k, v in state.items()})
    return m, found[0]


# ---------------------------------------------------------------- the same job without FLARE, to check FLARE's arithmetic
def plain_loop(root, contract, pl):
    """The engine's federated loop (engine.Bench.run) fed with the SAME starting weights, the SAME per-round shuffling
    seeds and the SAME site folders as the FLARE job, and no FLARE code. If FLARE does the same arithmetic, the two
    shared detectors agree to rounding error. Returns the shared detector and its weights after every round."""
    sites = {o: site_train.setup(root, SITE[o]) for o in ORG}
    shared = engine.Detector(len(contract["features"]), len(contract["classes"]))
    shared.load_state_dict(torch.load(os.path.join(root, INITIAL), map_location="cpu"))
    w = np.array([pl["records"][o] for o in ORG], float)
    w /= w.sum()
    after = []
    for rnd in range(pl["rounds"]):
        for o in ORG:
            sites[o].model.load_state_dict(shared.state_dict())
            site_train.local_round(sites[o], rnd)
        shared.load_state_dict({k: sum(w[i] * sites[ORG[i]].model.state_dict()[k] for i in range(len(ORG))) for k in shared.state_dict()})
        after.append({k: v.clone() for k, v in shared.state_dict().items()})
    return shared, after


def _state(m):
    return m.state_dict() if hasattr(m, "state_dict") else m


def largest_difference(a, b):
    """The largest absolute difference between two sets of detector weights."""
    a, b = _state(a), _state(b)
    return float(max((a[k].double() - b[k].double()).abs().max() for k in a))


def gap_after_each_round(trace_dir, flare_model, loop_after):
    """Largest weight difference between FLARE's shared detector and the plain loop's after every round. FLARE's detector
    after round r is the one the sites receive at the start of round r + 1 (kept in trace_dir); after the last round it is
    the saved one. Also checks that the three sites received the same weights."""
    gaps = []
    for r, loop_state in enumerate(loop_after):
        if r < len(loop_after) - 1:
            got = {o: torch.load(os.path.join(trace_dir, SITE[o], f"received_round{r + 1}.pt"), map_location="cpu") for o in ORG}
            for o in ORG[1:]:
                if largest_difference(got[ORG[0]], got[o]) != 0.0:
                    raise RuntimeError(f"round {r + 1}: {SITE[o]} and {SITE[ORG[0]]} did not receive the same shared detector")
            gaps.append(largest_difference(got[ORG[0]], loop_state))
        else:
            gaps.append(largest_difference(flare_model, loop_state))
    return gaps


# ---------------------------------------------------------------- scoring with the engine's own test
def score(data, bench, model):
    """engine.Bench.test of one shared detector for every organization, with the scaling each organization fitted on its own records."""
    from sklearn.preprocessing import StandardScaler
    own = own_records(data)
    out = {}
    for o in ORG:
        r = bench.test(model, StandardScaler().fit(own[o][bench.F]), o)
        out[o] = dict(recall=r["named"], flagged=r["flagged"], false_positive_rate=r["false_alarm_test"], test_records=r["test_rows"])
    return out


def engine_federated(bench, seed):
    """The engine's own federated learning condition (one seed, the test world), exactly as the product runs it."""
    rows = [r for r in bench.run(0, seed) if r["road"] == "3_federated"]
    return ({r["org"]: dict(recall=r["named"], flagged=r["flagged"], false_positive_rate=r["false_alarm_test"], test_records=r["test_rows"]) for r in rows},
            int(rows[0]["rounds"]))


def versions():
    import nvflare
    return dict(nvflare_version=nvflare.__version__, torch=torch.__version__, python=platform.python_version(),
                platform=f"{platform.system()} {platform.machine()}", processors=os.cpu_count(),
                cuda_available=bool(torch.cuda.is_available()), date=time.strftime("%Y-%m-%d %H:%M:%S %Z"))


def engine_fingerprint():
    """Which engine and agent files the run used (SHA-256, opening 16 characters)."""
    import hashlib
    out = {}
    for f in ("engine.py", "threatprint_agent.py"):
        with open(os.path.join(ROOT, f), "rb") as fh:
            out[f] = hashlib.sha256(fh.read()).hexdigest()[:16]
    return out


def clean_folder(path):
    if os.path.isdir(path):
        shutil.rmtree(path)
