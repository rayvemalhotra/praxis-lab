"""The script NVIDIA FLARE runs at each site (FLARE Client API). Product research, not part of the praxis.

    --data_root DIR    the folder that holds contract.json and this site's own folder (DIR/<site name>/train.parquet)
    --trace_dir DIR    optional, for checking only: keep a copy of the shared detector as received at the start of each round

Each round: receive the shared detector, train it on the site's own records with the engine's loop, send the weights back.
No records leave the site; the number of optimizer steps travels with the weights (FLARE's NUM_STEPS_CURRENT_ROUND).
"""
import argparse
import os

import torch

import nvflare.client as flare

import site_train


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--data_root", required=True)
    p.add_argument("--trace_dir", default="")
    args = p.parse_args()
    flare.init()
    site = flare.system_info()["site_name"]
    s = site_train.setup(args.data_root, site)
    print(f"{site}: {s.records} own training records, {s.steps} optimizer steps per round", flush=True)
    while flare.is_running():
        received = flare.receive()
        if received is None:
            break
        rnd = int(received.current_round or 0)
        s.model.load_state_dict({k: torch.as_tensor(v) for k, v in received.params.items()})
        if args.trace_dir:
            os.makedirs(os.path.join(args.trace_dir, site), exist_ok=True)
            torch.save({k: v.detach().clone() for k, v in s.model.state_dict().items()}, os.path.join(args.trace_dir, site, f"received_round{rnd}.pt"))
        done = site_train.local_round(s, rnd)
        params = {k: v.detach().cpu().clone() for k, v in s.model.state_dict().items()}
        flare.send(flare.FLModel(params=params, meta={"NUM_STEPS_CURRENT_ROUND": done}))
        print(f"{site}: round {rnd} done, {done} steps", flush=True)


if __name__ == "__main__":
    main()
