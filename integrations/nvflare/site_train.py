"""What one organization (one FLARE site) does in one round of federated learning. Product research, not part of the praxis.

This file travels with the job to every site. It reads ONLY the site's own folder and the contract every site agreed on
(the behavior numbers, the list of attack types, the training settings). The training loop, the scaling, the batch size
and the learning rate are the engine's own (engine.Bench.train, engine.BATCH, engine.LR); nothing is copied by hand.
"""
import json
import math
import os
from types import SimpleNamespace

import numpy as np
import pandas as pd
import torch
from sklearn.preprocessing import LabelEncoder, StandardScaler

import engine

CONTRACT = "contract.json"
TRAIN_FILE = "train.parquet"


def round_seed(seed, site_index, rnd):
    """One shuffling seed per run, site and round, so that a site needs no memory between rounds."""
    return int(seed) * 1_000_003 + int(site_index) * 1_009 + int(rnd)


def setup(data_root, site):
    """Load the site's own training records and get them ready the way the engine does for federated learning."""
    with open(os.path.join(data_root, CONTRACT)) as fh:
        c = json.load(fh)
    if site not in c["sites"]:
        raise ValueError(f"site '{site}' is not in the contract; the contract lists {sorted(c['sites'])}")
    d = pd.read_parquet(os.path.join(data_root, site, TRAIN_FILE))
    le = LabelEncoder()
    le.classes_ = np.array(c["classes"], dtype=object)
    d = d.assign(y=d["y"].astype(str))
    shim = SimpleNamespace(F=list(c["features"]), le=le, lossf=torch.nn.CrossEntropyLoss())   # what engine.Bench.X, Y and train read
    sc = StandardScaler().fit(d[shim.F])                       # scaling fitted on the site's own records, as in the engine
    return SimpleNamespace(site=site, index=int(c["sites"][site]["index"]), seed=int(c["seed"]), shim=shim, scaler=sc,
                           X=engine.Bench.X(shim, sc, d), Y=engine.Bench.Y(shim, d), records=int(len(d)),
                           steps=int(c["local_epochs"]) * math.ceil(len(d) / engine.BATCH),
                           model=engine.Detector(len(shim.F), len(c["classes"])))


def local_round(s, rnd):
    """Train the site's copy of the detector for one round with the engine's own loop. Returns the optimizer steps taken."""
    gen = torch.Generator().manual_seed(round_seed(s.seed, s.index, rnd))
    return engine.Bench.train(s.shim, s.model, s.X, s.Y, s.steps, gen)
