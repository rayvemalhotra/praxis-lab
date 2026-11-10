"""Run the federated learning condition as an NVIDIA FLARE job in the FLARE simulator and compare it with the engine.

    python integrations/nvflare/run_simulator.py                         built-in example and the water utility sample, quick budget, seeds 0 1 2
    python integrations/nvflare/run_simulator.py --table my_records.csv  any labeled table the web tool can read
    python integrations/nvflare/run_simulator.py --budget protocol       the praxis training budget (61 passes, 4 local passes per round)

Product research, not part of the praxis. Runs on CPU; no NVIDIA hardware is needed or claimed.
For each table and seed it: (1) makes the three organizations as the engine does, (2) runs the engine's own federated
condition, (3) writes each organization's own training records to its own site folder, (4) runs FedAvg in the FLARE
simulator, (5) scores FLARE's shared detector with the engine's own test, (6) repeats the job without FLARE from the
same starting weights and compares the shared detector after every round, to check FLARE's arithmetic. It then writes
STATUS.json next to this file.
"""
import argparse
import json
import os
import shlex
import sys
import tempfile
import time
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
# After round 1 the two shared detectors come from identical site models, so they may differ by float32 rounding
# in the weighted mean and by nothing else. Later rounds train on from those weights, so the rounding grows; it is reported.
ARITHMETIC_TOLERANCE = 1e-6


def pct(x):
    return "not measured" if x is None or x != x else f"{x * 100:.1f}%"


def one_table(T, which, budget, seeds, workspace, threads, log):
    import engine
    df, name = T.load_table(which)
    cfg, data, bench = T.build(df, name, budget)
    pl = T.plan(data, bench)
    out = dict(table=name, records=int(len(data.df)), behavior_numbers=int(bench.NF), attack_types_and_normal=int(bench.C), detector_weights=int(bench.PARAMS),
               organizations={o: dict(name=data.companies[o]["name"], withheld_attack_type=str(data.never[o]),
                                      own_training_records=pl["records"][o], local_steps_per_round=pl["local_steps"][o]) for o in T.ORG},
               rounds=pl["rounds"], local_passes_per_round=int(bench.b.local_epochs), batch=int(engine.BATCH), learning_rate=float(engine.LR),
               training_budget_steps=pl["total_steps"], seeds=[])
    log(f"\n{name}: {out['records']:,} records, {bench.NF} behavior numbers, {pl['rounds']} rounds of {bench.b.local_epochs} local passes")
    for seed in seeds:
        t = time.time()
        eng, eng_rounds = T.engine_federated(bench, seed)
        if eng_rounds != pl["rounds"]:
            raise RuntimeError(f"the engine ran {eng_rounds} rounds and this integration planned {pl['rounds']}; the rule in tp_flare.plan no longer mirrors engine.Bench.run")
        tag = f"{os.path.splitext(name)[0].replace(' ', '_')}_seed{seed}"
        root = os.path.join(workspace, tag, "sites")
        T.clean_folder(os.path.join(workspace, tag))
        contract = T.write_sites(data, bench, root, seed)
        t1 = time.time()
        trace = os.path.join(workspace, tag, "trace")
        run_dir = T.run_flare(root, contract, pl, os.path.join(workspace, tag, "flare"), threads=threads, trace_dir=trace)
        flare_seconds = time.time() - t1
        model, _ = T.global_model(run_dir, contract)
        fl = T.score(data, bench, model)
        loop_model, loop_after = T.plain_loop(root, contract, pl)
        loop = T.score(data, bench, loop_model)
        gaps = T.gap_after_each_round(trace, model, loop_after)
        row = dict(seed=int(seed), engine=eng, flare=fl, plain_loop=loop,
                   flare_minus_engine_points={o: round((fl[o]["recall"] - eng[o]["recall"]) * 100, 1) for o in T.ORG},
                   flare_scores_equal_plain_loop=bool(fl == loop), weight_gap_flare_vs_plain_loop_after_each_round=gaps,
                   flare_seconds=round(flare_seconds, 1), seconds=round(time.time() - t, 1))
        out["seeds"].append(row)
        log(f"  seed {seed}: recall on the withheld type   engine " + ", ".join(f"{o} {pct(eng[o]['recall'])}" for o in T.ORG)
            + "   FLARE " + ", ".join(f"{o} {pct(fl[o]['recall'])}" for o in T.ORG)
            + f"   FLARE against the plain loop: {gaps[0]:.0e} after round 1, {gaps[-1]:.0e} at the end, scores {'equal' if fl == loop else 'NOT equal'}   ({flare_seconds:.0f} s in the simulator)")
    mean = lambda side: {o: sum(r[side][o]["recall"] for r in out["seeds"]) / len(out["seeds"]) for o in T.ORG}
    out["mean_recall_engine"], out["mean_recall_flare"] = mean("engine"), mean("flare")
    spread = lambda side: {o: round((max(r[side][o]["recall"] for r in out["seeds"]) - min(r[side][o]["recall"] for r in out["seeds"])) * 100, 1) for o in T.ORG}
    out["engine_spread_between_seeds_points"], out["flare_spread_between_seeds_points"] = spread("engine"), spread("flare")
    return out


def main():
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--table", nargs="+", default=["example", "water_utility"], help="example, water_utility, or paths to CSV or Parquet files")
    p.add_argument("--budget", choices=["quick", "protocol"], default="quick")
    p.add_argument("--seeds", nargs="+", type=int, default=[0, 1, 2])
    p.add_argument("--workspace", default=None, help="where the site folders and the simulator files go (default: a temporary folder, removed at the end)")
    p.add_argument("--threads", type=int, default=3, help="sites trained at the same time in the simulator")
    p.add_argument("--status", default=os.path.join(HERE, "STATUS.json"), help="where to write the status file ('' = do not write)")
    a = p.parse_args()
    command = "python integrations/nvflare/run_simulator.py " + " ".join(shlex.quote(x) for x in sys.argv[1:])
    status = dict(status="not built", summary="", details=[], command=command.strip(), budget=a.budget)
    made_here = a.workspace is None
    workspace = a.workspace or tempfile.mkdtemp(prefix="tp_nvflare_")
    try:
        import tp_flare as T
        import engine
        status.update(T.versions())
        status["engine_files_sha256"] = T.engine_fingerprint()
        tables = [one_table(T, w, T.BUDGETS[a.budget], a.seeds, workspace, a.threads, print) for w in a.table]
        rows = [r for t in tables for r in t["seeds"]]
        gap = max(r["weight_gap_flare_vs_plain_loop_after_each_round"][0] for r in rows)
        end = max(r["weight_gap_flare_vs_plain_loop_after_each_round"][-1] for r in rows)
        same = sum(r["flare_scores_equal_plain_loop"] for r in rows)
        if gap > ARITHMETIC_TOLERANCE:
            raise RuntimeError(f"after one round FLARE's shared detector differs from the plain loop by {gap:.2e} (allowed {ARITHMETIC_TOLERANCE:.0e}); the job does not do the engine's arithmetic")
        runs = len(rows)
        status.update(status="tested", tables=tables, largest_weight_gap_after_one_round=gap, largest_weight_gap_at_the_end=end,
                      arithmetic_tolerance=ARITHMETIC_TOLERANCE, runs_with_scores_equal_to_plain_loop=f"{same} of {runs}",
                      summary=(f"The federated learning condition ran as an NVIDIA FLARE {status['nvflare_version']} FedAvg job in the FLARE simulator on CPU "
                               f"({runs} runs, three sites each, no NVIDIA hardware); product research, not part of the praxis."))
        d = [f"NVIDIA FLARE {status['nvflare_version']}, simulator, CPU only ({status['platform']}); no NVIDIA GPU was used and none is claimed.",
             "Three sites, one per organization. Each site read only its own training records; model weights travelled, records did not.",
             "Same detector, training loop, batch size, learning rate, local passes, rounds and record-count weighting as the engine's federated condition, read from the engine.",
             f"Check of FLARE's arithmetic: from the same starting weights and shuffling seeds, a plain loop without FLARE gave the same shared detector, "
             f"to within {gap:.0e} after one round (float rounding) and {end:.0e} at the end, with identical scores in {same} of {runs} runs."]
        for t in tables:
            r = t["seeds"][0]
            d.append(f"{t['table']}, {a.budget} budget, seed {r['seed']}, attack-class recall on the withheld type (local run of the tool): engine "
                     + ", ".join(f"{o} {pct(r['engine'][o]['recall'])}" for o in T.ORG) + "; FLARE " + ", ".join(f"{o} {pct(r['flare'][o]['recall'])}" for o in T.ORG)
                     + ". The two differ only in their random draws.")
        if len(a.seeds) > 1:
            worst = max(((abs(r["flare_minus_engine_points"][o]), t, r, o) for t in tables for r in t["seeds"] for o in T.ORG), key=lambda x: x[0])
            gap_pts, t, r, o = worst
            d.append(f"Largest difference between engine and FLARE at the same seed over the {runs} runs: {gap_pts:.1f} points (organization {o} of {t['table']}, "
                     f"{r['engine'][o]['test_records']} test records of the withheld type). Between seeds the engine itself moved by up to {t['engine_spread_between_seeds_points'][o]:.1f} points there.")
        d += ["Not shown: real separate sites, FLARE provisioning and secured channels, training on NVIDIA GPUs.",
              "Product research. The praxis federated condition is the engine's own loop and is unchanged."]
        status["details"] = d
        status["not_shown"] = ["no NVIDIA hardware: CPU simulator only", "no real separate sites: three simulated sites on one machine",
                               "no FLARE provisioning, certificates or secured channels", "no secure aggregation, homomorphic encryption or differential privacy",
                               "no claim about what model weights reveal about a site"]
    except Exception as e:
        status.update(status="not built", error=f"{type(e).__name__}: {e}", traceback=traceback.format_exc()[-3000:],
                      summary="NVIDIA FLARE job: not built; the run in the FLARE simulator did not complete. Product research, not part of the praxis.",
                      details=[f"The run stopped: {type(e).__name__}: {str(e)[:300]}"])
        print(f"\nNOT BUILT: {type(e).__name__}: {e}", file=sys.stderr)
    finally:
        if made_here:
            import shutil
            shutil.rmtree(workspace, ignore_errors=True)
    if a.status:
        with open(a.status, "w") as fh:
            json.dump(status, fh, indent=1, default=float)
        print(f"\nstatus: {status['status']}   written to {a.status}")
    print(status["summary"])
    return 0 if status["status"] == "tested" else 1


if __name__ == "__main__":
    sys.exit(main())
