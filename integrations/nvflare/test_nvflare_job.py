"""The federated learning condition as an NVIDIA FLARE job, run in the FLARE simulator. Skipped when nvflare is not installed.

    pip install -r requirements.txt -r requirements-nvflare.txt
    python -m pytest integrations/nvflare -q

Product research, not part of the praxis. CPU only.
"""
import json
import os
import subprocess
import sys

import pytest

pytest.importorskip("nvflare", reason="NVIDIA FLARE is not installed (pip install -r requirements-nvflare.txt)")

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import tp_flare as T  # noqa: E402

import engine  # noqa: E402

SMALL = engine.Budget(name="test", passes=6, local_epochs=1, resamples=50, seeds=(0,), max_rows=40000, nothing_withheld_check=False, do_trace=False)


@pytest.fixture(scope="module")
def job(tmp_path_factory):
    work = str(tmp_path_factory.mktemp("tp_nvflare"))
    assert " " not in work
    df, name = T.load_table("example")
    cfg, data, bench = T.build(df, name, SMALL)
    pl = T.plan(data, bench)
    root = os.path.join(work, "sites")
    contract = T.write_sites(data, bench, root, seed=0)
    run_dir = T.run_flare(root, contract, pl, os.path.join(work, "flare"), threads=3, trace_dir=os.path.join(work, "trace"))
    return dict(work=work, data=data, bench=bench, plan=pl, root=root, contract=contract, run_dir=run_dir)


def test_plan_mirrors_the_engine(job):
    _, engine_rounds = T.engine_federated(job["bench"], 0)
    assert engine_rounds == job["plan"]["rounds"] >= 2


def test_each_site_folder_holds_only_its_own_sanitized_training_records(job):
    import pandas as pd
    own = T.own_records(job["data"])
    for o in T.ORG:
        d = pd.read_parquet(os.path.join(job["root"], T.SITE[o], "train.parquet"))
        assert list(d.columns) == job["bench"].F + ["y"]                 # behavior numbers and the attack type, nothing else
        assert len(d) == len(own[o]) and job["data"].never[o] not in set(d.y)   # the withheld attack type is not in the site's training records
    contract = json.load(open(os.path.join(job["root"], "contract.json")))
    assert "records" not in json.dumps(contract)                         # the contract carries no site's record count


def test_simulator_finishes_and_the_engine_can_score_the_model(job):
    model, path = T.global_model(job["run_dir"], job["contract"])
    assert os.path.basename(path) == "FL_global_model.pt"
    scores = T.score(job["data"], job["bench"], model)
    for o in T.ORG:
        assert 0.0 <= scores[o]["recall"] <= 1.0 and 0.0 <= scores[o]["false_positive_rate"] <= 1.0 and scores[o]["test_records"] > 0


def test_flare_does_the_arithmetic_of_the_engine_loop(job):
    model, _ = T.global_model(job["run_dir"], job["contract"])
    loop_model, after = T.plain_loop(job["root"], job["contract"], job["plan"])
    gaps = T.gap_after_each_round(os.path.join(job["work"], "trace"), model, after)
    assert len(gaps) == job["plan"]["rounds"]
    assert gaps[0] < 1e-6, gaps                                          # one round: float rounding in the weighted mean, nothing else
    assert gaps[-1] < 1e-2, gaps                                         # later rounds train on from there; the rounding stays small
    assert T.score(job["data"], job["bench"], model) == T.score(job["data"], job["bench"], loop_model)


def test_exported_job_runs_under_the_flare_command_line_without_threatprint_installed(job, tmp_path_factory):
    """The job folder carries the engine: run it with `nvflare simulator` from another folder with no PYTHONPATH."""
    out = str(tmp_path_factory.mktemp("tp_export"))
    T.make_recipe(job["root"], job["contract"], job["plan"]).export(os.path.join(out, "job"))
    job_dir = os.path.join(out, "job", "threatprint_fedavg")
    assert os.path.exists(os.path.join(job_dir, "app", "custom", "engine.py"))
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    exe = os.path.join(os.path.dirname(sys.executable), "nvflare")
    r = subprocess.run([exe, "simulator", job_dir, "-w", os.path.join(out, "ws"), "-c", ",".join(T.SITE[o] for o in T.ORG), "-t", "3"],
                       cwd=out, env=env, capture_output=True, text=True, timeout=600)
    assert r.returncode == 0, (r.stdout + r.stderr)[-2000:]
    model, _ = T.global_model(os.path.join(out, "ws"), job["contract"])
    in_process, _ = T.global_model(job["run_dir"], job["contract"])
    assert T.largest_difference(model, in_process) < 1e-2
