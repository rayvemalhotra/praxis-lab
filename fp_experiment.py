"""Fingerprint sharing: an EXPERIMENTAL arm of Praxis Lab. It is not one of the four training conditions of the praxis.

Idea: instead of sanitized attack records (records travel) or model weights (federated learning), each organization
sends a statistical fingerprint of each of its attack types (praxis_agent.class_fingerprints: quantiles and rank
correlations, groups of at least K records). The receiver draws made-up records from its peers' fingerprints, adds
them to its own records and trains the same detector with the same training budget and the same alarm rule.

Scored exactly like the praxis conditions: attack-class recall on the withheld attack type, gain against isolated
training with a 95% range (bootstrap over attack events), false-positive rate, calculated bytes received.
Not measured here: what a fingerprint reveals about the organization that made it.
"""
import math

import numpy as np
import pandas as pd
import torch
from sklearn.preprocessing import StandardScaler

import engine
import praxis_agent as agent
from engine import ORG, BATCH, MIN_GAIN, FP_LIMIT, Detector


def run(data, bench, seeds=(0, 1, 2), resamples=2000, k=agent.K_MIN, log=None):
    log = log or (lambda m: None)
    d, F = data, bench.F
    own = {o: d.TR[o][d.TR[o].y != d.never[o]] for o in ORG}
    steps = bench.b.passes * math.ceil(max(len(own[o]) for o in ORG) / BATCH)
    fps = {}
    for p in ORG:                                                             # what each organization would send
        att = own[p][own[p].y != d.benign]
        fps[p] = agent.class_fingerprints(att[F], att["y"], k=k)
    runs, rows = {}, []
    for seed in seeds:
        torch.manual_seed(seed)
        gen = torch.Generator().manual_seed(seed)
        rng = np.random.default_rng(seed)
        for o in ORG:                                                         # isolated training, same order and generator as engine.Bench.run
            sc = StandardScaler().fit(own[o][F])
            m = Detector(bench.NF, bench.C)
            bench.train(m, bench.X(sc, own[o]), bench.Y(own[o]), steps, gen)
            r = bench.test(m, sc, o)
            runs[(seed, "iso", o)] = engine.plain(r.pop("events"))
            rows.append(dict(seed=seed, arm="iso", org=o, **r))
        for o in ORG:                                                         # fingerprint sharing
            parts, nbytes = [], 0
            for p in ORG:
                if p == o:
                    continue
                for lab, c in fps[p]["classes"].items():
                    part = pd.DataFrame(agent.synthesize(c, c["records"], rng), columns=F)
                    part["y"] = lab
                    parts.append(part)
                nbytes += fps[p]["bytes"]
            synth = pd.concat(parts, ignore_index=True) if parts else pd.DataFrame(columns=F + ["y"])
            both = pd.concat([own[o][F + ["y"]], synth], ignore_index=True)
            sc = StandardScaler().fit(both[F])
            m = Detector(bench.NF, bench.C)
            bench.train(m, bench.X(sc, both), bench.Y(both), steps, gen)
            r = bench.test(m, sc, o)
            runs[(seed, "fp", o)] = engine.plain(r.pop("events"))
            rows.append(dict(seed=seed, arm="fp", org=o, bytes=nbytes, synthetic=len(synth), **r))
        log(f"fingerprint sharing: seed {seed} done")
    R = pd.DataFrame(rows)
    mean = R.groupby(["arm", "org"]).mean(numeric_only=True)

    def table(arm, o, stage="s2"):
        first = runs[(seeds[0], arm, o)]
        hits = np.mean([runs[(s, arm, o)][stage] for s in seeds], axis=0)
        return pd.DataFrame(dict(n=first["n"], hits=hits * first["n"]), index=pd.Index(first["event"]))

    rng = np.random.default_rng(0)
    orgs, boots, ests = {}, [], []
    for o in ORG:
        est, bs, kk = engine.compare(table("fp", o), table("iso", o), rng, resamples)
        lo, hi = (float(np.nanpercentile(bs, 2.5)), float(np.nanpercentile(bs, 97.5))) if kk else (float("nan"), float("nan"))
        fp_rate, iso_rate = float(mean.loc[("fp", o), "false_alarm_test"]), float(mean.loc[("iso", o), "false_alarm_test"])
        gain_met = bool(kk and lo > MIN_GAIN)
        verdict = ("not worth it (gain not met)" if not gain_met else
                   ("gain met, false-positive limit breached" if fp_rate - iso_rate > FP_LIMIT else "gain met (exposure of the fingerprint not measured)"))
        peers_have = [p for p in ORG if p != o and d.never[o] in fps[p]["classes"]]
        orgs[o] = dict(named=float(mean.loc[("fp", o), "named"]), flagged=float(mean.loc[("fp", o), "flagged"]), false_alarm=fp_rate,
                       isolated_named=float(mean.loc[("iso", o), "named"]), isolated_false_alarm=iso_rate,
                       gain=dict(gain=float(est), lo=lo, hi=hi, events=int(kk)), bytes=int(mean.loc[("fp", o), "bytes"]),
                       synthetic_records=int(mean.loc[("fp", o), "synthetic"]), steps=int(steps),
                       withheld_type_in_peer_fingerprints=len(peers_have), verdict=verdict)
        boots.append(bs)
        ests.append(est)
    bs = np.nanmean(boots, axis=0)
    lo, hi = np.nanpercentile(bs, [2.5, 97.5])
    return dict(name="Fingerprint sharing", status="experimental; not one of the four training conditions of the praxis",
                min_group_size=int(k), quantile_points=len(agent.GRID), seeds=list(seeds), resamples=int(resamples),
                sender_classes={p: len(fps[p]["classes"]) for p in ORG}, sender_suppressed={p: len(fps[p]["suppressed"]) for p in ORG},
                sender_bytes={p: int(fps[p]["bytes"]) for p in ORG}, orgs=orgs,
                mean_gain=dict(gain=float(np.nanmean(ests)), lo=float(lo), hi=float(hi), clears=bool(lo > MIN_GAIN)))
