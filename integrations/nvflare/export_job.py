"""Export the federated learning condition of a table as an NVIDIA FLARE job folder, with one data folder per site.

    python integrations/nvflare/export_job.py --table water_utility --out /tmp/threatprint_flare
    nvflare simulator /tmp/threatprint_flare/job/threatprint_fedavg -w /tmp/threatprint_flare/workspace -c site-A,site-B,site-C -t 3

Product research, not part of the praxis. What it writes under --out:
    sites/contract.json                 what every site agrees on: the behavior numbers, the attack types, the training settings
    sites/site-A|B|C/train.parquet      each organization's OWN training records (behavior numbers and attack type, no identifiers)
    sites/initial_global_model.pt       the starting weights of the shared detector
    job/threatprint_fedavg/             the FLARE job: FedAvg on the server, flare_client.py at each site, the engine inside the job
In a real federation each site keeps its own folder on its own machine and sets --data_root to it; here they sit side by side.
"""
import argparse
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)


def export(table, out, budget="quick", seed=0, log=print):
    import tp_flare as T
    out = os.path.abspath(out)
    df, name = T.load_table(table)
    cfg, data, bench = T.build(df, name, T.BUDGETS[budget])
    pl = T.plan(data, bench)
    root = os.path.join(out, "sites")
    T.clean_folder(root)
    T.clean_folder(os.path.join(out, "job"))
    contract = T.write_sites(data, bench, root, seed)
    T.make_recipe(root, contract, pl).export(os.path.join(out, "job"))
    job = os.path.join(out, "job", "threatprint_fedavg")
    log(f"{name}: {pl['rounds']} rounds, " + ", ".join(f"{T.SITE[o]} {pl['records'][o]:,} own records (withheld: {data.never[o]})" for o in T.ORG))
    log(f"site folders: {root}")
    log(f"FLARE job:    {job}")
    log(f"run it:       nvflare simulator {job} -w {os.path.join(out, 'workspace')} -c {','.join(T.SITE[o] for o in T.ORG)} -t {len(T.ORG)}")
    return dict(job=job, sites=root, contract=contract, plan=pl, data=data, bench=bench)


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--table", default="example", help="example, water_utility, or a path to a CSV or Parquet file")
    p.add_argument("--out", required=True, help="an empty folder with no space in its path")
    p.add_argument("--budget", choices=["quick", "protocol"], default="quick")
    p.add_argument("--seed", type=int, default=0)
    a = p.parse_args()
    export(a.table, a.out, a.budget, a.seed)
