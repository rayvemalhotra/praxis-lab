"""Praxis Lab engine: the praxis study procedure as a library, for any labeled intrusion dataset.

This is Rayve Malhotra's praxis code (praxis-rayve/system.py, frozen protocol rev 7 and rev 8) with three changes
so that a web tool can drive it: it takes a DataFrame or a settings dict instead of files in a fixed folder, every
budget number is a parameter (so a quick look and the full protocol run are both possible), and it reports
progress through a callback instead of printing. The study logic is unchanged.

Steps
  1  Make three organizations. Hosts (or devices) are split into organizations A, B, C. One attack type is withheld
     from each organization's own training records: its withheld attack type.
  2  Sanitize the records. Keep the behavior numbers and the attack type. Remove device names, addresses, ports,
     time stamps and the other label columns.
  3  Train one detector per organization under four training conditions, with the same network, the same number of
     training steps and the same alarm rule:
       isolated training                  own records only (baseline)
       sanitized attack-record sharing    own records plus the peers' sanitized attack records
       federated learning                 own records; only model weights travel (FedAvg)
       centralized training               every organization's training records in one place (reference)
  4  Test on the withheld attack type: flagged as an attack, and named with the right attack type.
  5  Scorecard: gains against isolated training with 95% ranges (bootstrap over attack events), false-positive
     rate, data sent, and whether sanitized records can be traced back to their source host.
"""
import json
import math
import os
import pickle
import re
import time
import warnings
from dataclasses import dataclass, asdict, field

import numpy as np
import pandas as pd
import torch
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, balanced_accuracy_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from torch import nn

warnings.filterwarnings("ignore")
torch.set_num_threads(max(1, min(4, os.cpu_count() or 1)))

ORG = ["A", "B", "C"]
ROADS = ["1_isolated", "2_sharing", "3_federated", "4_centralized"]
CONDITION = {"1_isolated": "isolated training", "2_sharing": "sanitized attack-record sharing",
             "3_federated": "federated learning", "4_centralized": "centralized training"}

# ---------------- frozen protocol settings ----------------
BATCH, LR = 128, 1e-3
FALSE_ALARM = 0.05                                      # alarm threshold: 95th percentile of own validation normal scores
MIN_GAIN = 0.05                                         # H1 and H2: the whole 95% range above 5 points
FP_LIMIT = 0.01                                         # decision rule: false-positive rate may rise by at most 1 point
TRACE_MAX = 15000
TRACE_MAX_HOSTS, TRACE_TOP_HOSTS = 200, 50                  # tracing with more hosts than this covers the busiest 50 only
EVENT_GAP_S, EVENT_MAX_S, EVENT_MAX_ROWS = 15, 300, 200
IDENT_RX = re.compile(r"(^|_|\.)(ip|ips|mac|macs|addr|address|host|hostname|timestamp|time_start|time_end|flow_id|uid|id)($|_|\.)", re.I)


@dataclass
class Budget:
    """How much computing a run may use. 'protocol' is the praxis protocol; 'quick' is a short look."""
    name: str = "protocol"
    passes: int = 61                 # training budget: passes over the largest organization's training records
    local_epochs: int = 4            # federated learning: local passes per round
    resamples: int = 2000            # bootstrap resamples over attack events
    trace_seeds: int = 5             # H3 attacker: random forests
    trace_trees: int = 300
    trace_permutations: int = 200    # H3 shuffle test: how many shuffles
    trace_perm_trees: int = 100      # trees per shuffled forest (system.py: 100)
    trace_perm_rows: int = 0         # records per side in the shuffle test; 0 = the same records as the tracing forests (system.py)
    seeds: tuple = (0, 1, 2)
    max_rows: int = 0                # 0 = no cap; otherwise the records are sampled by class to this many
    nothing_withheld_check: bool = True
    do_trace: bool = True


PROTOCOL = Budget()
QUICK = Budget(name="quick", passes=24, local_epochs=2, resamples=400, trace_seeds=2, trace_trees=100, trace_permutations=40,
               trace_perm_trees=50, trace_perm_rows=3000, seeds=(0,), max_rows=40000, nothing_withheld_check=False)
# the protocol budget with a cheaper shuffle test, for running many public datasets: the tracing forests, the ranges and
# the training budget are the protocol's; only the 200 shuffled forests use 50 trees on at most 5,000 records per side
PROTOCOL_MANY = Budget(name="protocol (shuffle test on 5,000 records per side, 50-tree forests)", trace_perm_trees=50, trace_perm_rows=5000)


# ================= STEP 1 and 2: load, make organizations, sanitize =================
class Data:
    """df with columns: y (attack type or normal), org (A/B/C), part (train/val/evaluation), event, source.
    feats = the behavior numbers an organization may send."""

    def __init__(self, cfg, frame=None, budget=PROTOCOL, log=None):
        self.cfg = cfg
        self.name = cfg.get("name", "dataset")
        self.benign = cfg["benign_label"]
        self.source_col = cfg.get("source_col") or None
        self.time_col = cfg.get("time_col") or None
        self.budget = budget
        self.log = log or (lambda m: None)
        if cfg.get("loader") == "datasense":
            self._load_datasense()
        else:
            self._load_generic(frame)
        self.companies = cfg["companies"] if isinstance(cfg.get("companies"), dict) else self._auto_companies()
        for o in ORG:
            self.companies[o].setdefault("name", f"Organization {o}")
        self.never = {o: self.companies[o]["never_seen"] for o in ORG}
        for o in ORG:
            nb = ((self.df.part == "val") & (self.df.org == o) & (self.df.y == self.benign)).sum()
            if nb < 25:
                raise ValueError(f"organization {o} has only {nb} normal validation records; the alarm threshold needs at least 25")
        self.TR = {o: self.df[(self.df.part == "train") & (self.df.org == o)] for o in ORG}
        self.VA = {o: self.df[(self.df.part == "val") & (self.df.org == o)] for o in ORG}
        self.EV = {o: self.df[(self.df.part == "evaluation") & (self.df.org == o)] for o in ORG}

    # ---- DataSense: the audited event split of the study ----
    def _load_datasense(self):
        d = self.cfg["path"]
        c = self.cfg
        A = pd.read_csv(f"{d}/data/attack_10s.csv", low_memory=False)
        Bn = pd.read_csv(f"{d}/data/benign_10s.csv", low_memory=False)
        self.raw_columns = A.shape[1]
        df = pd.concat([A, Bn], ignore_index=True)
        dev = {o: set(c["companies"][o].get("sources") or []) for o in ORG}
        df["org"] = df.device_name.map(lambda x: next((o for o in ORG if x in dev[o]), c.get("rest_company", "C")))
        df["y"] = df[c["label_col"]].astype(str)
        df["source"] = df[self.source_col]
        S = json.load(open(f"{d}/split/internal_split.json"))
        EM = pd.read_csv(f"{d}/split/event_map.csv")
        EM["_ts"] = pd.to_datetime(EM.timestamp_start, format="ISO8601", utc=True)
        df["part"] = np.where(EM.y == "benign", EM._ts.apply(lambda t: S["benign_timestamp_assignment"].get(t.isoformat(), "DROPPED")),
                              EM.event.map(S["attack_event_assignment"]))
        df["event"] = EM.event.values
        self.feats = pd.read_csv(f"{d}/results/section4_model_inputs.csv").iloc[:, 0].tolist()
        self.dropped = sorted(set(df.columns) - set(self.feats) - {"y", "org", "part", "event", "source"})
        self.df = df
        self.split_note = "audited event split of the study (train/validation/test by attack event and by time)"
        self.company_note = "organizations = device groups by role (network gear, cameras, sensors)"

    # ---- any other labeled table ----
    def _load_generic(self, frame):
        c = self.cfg
        if frame is None:
            frames = [pd.read_csv(p, low_memory=False, nrows=c.get("nrows")) for p in c["paths"]]
            df = pd.concat(frames, ignore_index=True)
        else:
            df = frame.copy()
        self.raw_columns = df.shape[1]
        df["y"] = df[c["label_col"]].astype(str).str.strip()
        if c.get("label_map"):
            df["y"] = df.y.replace(c["label_map"])
        if c.get("drop_labels"):
            df = df[~df.y.isin([str(v) for v in c["drop_labels"]])]
        if c.get("min_class_rows"):
            keep = df.y.value_counts()
            keep = keep[keep >= c["min_class_rows"]].index
            df = df[df.y.isin(keep)]
        cap = c.get("sample_rows") or self.budget.max_rows
        if cap and len(df) > cap:
            frac = cap / len(df)
            df = df.groupby("y", group_keys=False).apply(lambda g: g.sample(max(min(len(g), 200), int(len(g) * frac)), random_state=0))
            self.log(f"sampled {len(df):,} of the records by class (cap {cap:,})")
        df = df.reset_index(drop=True)
        df["source"] = df[self.source_col].astype(str) if self.source_col else "unknown"
        # STEP 2: which columns may leave an organization? numbers only, no identifiers, no label columns
        drop = set(c.get("drop", [])) | set(c.get("label_cols", [])) | {c["label_col"], "y", "source"}
        if self.source_col:
            drop.add(self.source_col)
        if self.time_col:
            drop.add(self.time_col)
        keep_anyway = set(c.get("keep", []))
        feats = []
        for col in df.columns:
            if col in drop or col in ("org", "part", "event"):
                continue
            if col not in keep_anyway and IDENT_RX.search(col):
                drop.add(col)
                continue
            v = df[col]
            if v.dtype == object and set(v.dropna().astype(str).str.upper().unique()) <= {"TRUE", "FALSE"}:
                v = v.astype(str).str.upper().map({"TRUE": 1.0, "FALSE": 0.0})
            v = pd.to_numeric(v, errors="coerce").replace([np.inf, -np.inf], np.nan)   # infinite rates count as missing
            if v.notna().mean() < 0.95 or v.nunique() < 2:
                drop.add(col)
                continue
            df[col] = v.astype(float)
            feats.append(col)
        if len(feats) < 3:
            raise ValueError(f"only {len(feats)} usable number columns were found; the detector needs more")
        self.feats = feats
        self.dropped = sorted(drop - {"y", "source"})
        # organizations: by source host when there is one, else class-stratified random thirds
        if self.source_col and isinstance(c.get("companies"), dict) and all("sources" in c["companies"][o] for o in ORG if o != c.get("rest_company")):
            src = {o: set(c["companies"][o].get("sources") or []) for o in ORG}
            df["org"] = df.source.map(lambda x: next((o for o in ORG if x in src[o]), c.get("rest_company", "C")))
            self.company_note = "organizations = groups of hosts named in the settings"
        else:
            df["org"] = None
            if self.source_col and c.get("companies", "auto") != "random":
                counts = df.source.value_counts()
                hosts = list(counts.index)
                assign = {h: ORG[i % 3] for i, h in enumerate(hosts)}      # round-robin by traffic volume, busiest first
                df["org"] = df.source.map(assign)
                ct = pd.crosstab(df.org, df.y).drop(columns=[self.benign], errors="ignore").reindex(index=ORG, fill_value=0)
                ok = all(sum(1 for k in ct.columns if ct.loc[o, k] >= 60 and (ct.drop(index=o)[k] >= 60).all()) >= 3 for o in ORG) \
                    and all((df[df.org == o].y == self.benign).sum() >= 300 for o in ORG)
                if ok:
                    self.company_note = "organizations = groups of hosts (each host belongs to one organization)"
                else:
                    df["org"] = None
            if df.org.isna().all():
                strat = df.y if df.y.value_counts().min() >= 3 else None
                a, bc = train_test_split(df, train_size=1 / 3, stratify=strat, random_state=0)
                strat2 = bc.y if bc.y.value_counts().min() >= 2 else None
                b, cc = train_test_split(bc, train_size=0.5, stratify=strat2, random_state=0)
                df["org"] = "C"
                df.loc[a.index, "org"] = "A"
                df.loc[b.index, "org"] = "B"
                self.company_note = ("organizations = three random thirds of the records (no host column in this data)" if not self.source_col else
                                     "organizations = three random thirds of the records (the hosts in this data are too few or too one-sided to form three organizations)")
        # split: by time inside each organization when there is a clock, else class-stratified random 50/20/30
        df["part"] = "train"
        df["event"] = np.arange(len(df))
        if self.time_col:
            t = pd.to_numeric(df[self.time_col], errors="coerce")
            if t.isna().mean() > 0.5:
                t = pd.to_datetime(df[self.time_col], errors="coerce", utc=True).astype("int64") / 1e9
            else:
                t = t / (1000 if t.median() > 1e11 else 1)       # milliseconds -> seconds
            df["_t"] = t.fillna(t.median())
            df = df.sort_values(["source", "y", "_t"])
            grp = df.groupby(["source", "y"])
            new_ev = (grp._t.diff() > EVENT_GAP_S) | grp.cumcount().eq(0)
            df["event"] = new_ev.cumsum().values
            start = df.groupby("event")._t.transform("min")
            df["event"] = df.event * 1000 + ((df._t - start) // EVENT_MAX_S).astype(int)
            df["event"] = pd.factorize(df.event)[0]
            df["event"] = df.event * 100000 + df.groupby("event").cumcount() // EVENT_MAX_ROWS
            df["event"] = pd.factorize(df.event)[0]
            df = df.sort_index()
            rng = np.random.RandomState(0)
            part = pd.Series("train", index=df.index)
            for (o, cls), d in df.groupby(["org", "y"]):
                sizes = d.groupby("event").size()
                if len(sizes) < 10:
                    idx = d.index.values.copy()
                    rng.shuffle(idx)
                    n = len(idx)
                    part[idx[int(0.5 * n):int(0.7 * n)]] = "val"
                    part[idx[int(0.7 * n):]] = "evaluation"
                    continue
                ev = sizes.index.values.copy()
                rng.shuffle(ev)
                cum = sizes.loc[ev].cumsum().values / sizes.sum()
                val_ev = ev[(cum > 0.5) & (cum <= 0.7)]
                test_ev = ev[cum > 0.7]
                part[d.index[d.event.isin(val_ev)]] = "val"
                part[d.index[d.event.isin(test_ev)]] = "evaluation"
            df["part"] = part.values
            df = df.drop(columns="_t")
            self.split_note = f"by event inside each organization (records of one attack on one host under {EVENT_GAP_S} s apart stay together; 50/20/30 train/validation/test by record count)"
        else:
            for o in ORG:
                d = df[df.org == o]
                strat = d.y if d.y.value_counts().min() >= 3 else None
                tr, rest = train_test_split(d, train_size=0.5, stratify=strat, random_state=0)
                strat2 = rest.y if rest.y.value_counts().min() >= 3 else None
                va, ev = train_test_split(rest, train_size=0.4, stratify=strat2, random_state=0)
                df.loc[va.index, "part"] = "val"
                df.loc[ev.index, "part"] = "evaluation"
            self.split_note = "class-stratified random 50/20/30 inside each organization; no clock, so each record is its own event (ranges are optimistic)"
        self.df = df

    def _auto_companies(self):
        """Pick each organization's withheld attack type: the largest attack type it has in its test records that
        every peer also has in training, each organization a different one."""
        TR = self.df[self.df.part == "train"]
        EV = self.df[self.df.part == "evaluation"]
        ct = pd.crosstab(TR.org, TR.y).drop(columns=[self.benign], errors="ignore").reindex(index=ORG, fill_value=0)
        ce = pd.crosstab(EV.org, EV.y).reindex(index=ORG, columns=ct.columns, fill_value=0)
        if ct.shape[1] < 3:
            raise ValueError("at least three attack types are needed so that each organization can withhold a different one")
        out = {o: {} for o in ORG}
        taken = set()
        fixed = self.cfg.get("never_seen", {}) or {}
        for o in ORG:
            if o in fixed and fixed[o] in ct.columns:
                out[o]["never_seen"] = fixed[o]
                taken.add(fixed[o])
        for o in ORG:
            if "never_seen" in out[o]:
                continue
            cand = [k for k in ct.columns if k not in taken and ce.loc[o, k] >= 30 and (ct.drop(index=o)[k] >= 30).all()]
            if not cand:
                cand = [k for k in ct.columns if k not in taken and ce.loc[o, k] > 0] or [k for k in ct.columns if k not in taken]
            pick = max(cand, key=lambda k: min(ce.loc[o, k], ct.drop(index=o)[k].min()))
            out[o]["never_seen"] = pick
            taken.add(pick)
        names = self.cfg.get("company_names") or {}
        for o in ORG:
            out[o]["name"] = names.get(o, f"Organization {o}")
        return out

    def clean(self, rows):
        """What an organization may send: the behavior numbers and the attack type. Nothing else."""
        out = rows[self.feats + ["y"]]
        assert "source" not in out.columns and (self.source_col not in out.columns), "an identifier would leave the organization"
        return out

    def describe(self):
        d = {}
        for o in ORG:
            tr = self.TR[o]
            d[o] = dict(name=self.companies[o]["name"], never_seen=self.never[o],
                        sources=int(self.df[self.df.org == o].source.nunique()) if self.source_col else None,
                        train=len(tr), withheld=int((tr.y == self.never[o]).sum()), train_after=int((tr.y != self.never[o]).sum()),
                        train_normal=int((tr.y == self.benign).sum()), train_attack=int(((tr.y != self.benign) & (tr.y != self.never[o])).sum()),
                        val=len(self.VA[o]), test=len(self.EV[o]),
                        test_never_seen=int((self.EV[o].y == self.never[o]).sum()),
                        events_never_seen=int(self.EV[o][self.EV[o].y == self.never[o]].event.nunique()))
        return d


# ================= STEP 3 and 4: the detector, training and testing (same for every condition) =================
class Detector(nn.Module):
    def __init__(self, n_in, n_classes):
        super().__init__()
        self.net = nn.Sequential(nn.Linear(n_in, 128), nn.ReLU(), nn.Linear(128, 64), nn.ReLU(), nn.Linear(64, n_classes))

    def forward(self, x):
        return self.net(x)


class Bench:
    def __init__(self, data, budget=PROTOCOL, log=None):
        self.d = data
        self.b = budget
        self.log = log or (lambda m: None)
        self.F = data.feats
        self.NF = len(self.F)
        self.le = LabelEncoder().fit(data.df.y)
        self.C = len(self.le.classes_)
        self.BEN = int(self.le.transform([data.benign])[0])
        self.PARAMS = self.NF * 128 + 128 + 128 * 64 + 64 + 64 * self.C + self.C
        self.lossf = nn.CrossEntropyLoss()

    def X(self, sc, d):
        return torch.tensor(np.nan_to_num(sc.transform(d[self.F])), dtype=torch.float32)

    def Y(self, d):
        return torch.tensor(self.le.transform(d.y), dtype=torch.long)

    def train(self, model, X, Y, steps, gen):
        opt = torch.optim.Adam(model.parameters(), lr=LR)
        n = len(Y)
        done = 0
        while done < steps:
            perm = torch.randperm(n, generator=gen)
            for i in range(0, n, BATCH):
                if done >= steps:
                    break
                b = perm[i:i + BATCH]
                opt.zero_grad()
                self.lossf(model(X[b]), Y[b]).backward()
                opt.step()
                done += 1
        return done

    @torch.no_grad()
    def attack_score(self, model, X):
        z = model(X).double()
        mask = torch.ones(z.shape[1], dtype=torch.bool)
        mask[self.BEN] = False
        return (torch.logsumexp(z[:, mask], 1) - z[:, self.BEN]).numpy()

    @torch.no_grad()
    def test(self, model, sc, o):
        d = self.d
        never = d.never[o]
        Xv = self.X(sc, d.VA[o])
        yv = self.le.transform(d.VA[o].y)
        sv = self.attack_score(model, Xv)
        thr = float(np.quantile(sv[yv == self.BEN], 1 - FALSE_ALARM, method="higher"))
        Xe = self.X(sc, d.EV[o])
        ye = self.le.transform(d.EV[o].y)
        se = self.attack_score(model, Xe)
        p = torch.softmax(model(Xe), 1).numpy()
        p[:, self.BEN] = -1
        named = p.argmax(1)
        flag = se > thr
        k = int(self.le.transform([never])[0])
        idx = ye == k
        ev = pd.DataFrame(dict(event=d.EV[o].event.values[idx], s1=flag[idx].astype(float), s2=(flag[idx] & (named[idx] == k)).astype(float)))
        return dict(flagged=float(flag[idx].mean()) if idx.any() else float("nan"),
                    named=float((flag[idx] & (named[idx] == k)).mean()) if idx.any() else float("nan"),
                    false_alarm_test=float(flag[ye == self.BEN].mean()), false_alarm_val=float((sv[yv == self.BEN] > thr).mean()),
                    test_rows=int(idx.sum()), events=ev.groupby("event")[["s1", "s2"]].agg(["mean", "size"]))

    def run(self, world, seed):
        """world 0: each organization's attack type is withheld (the test). world 1: nothing withheld (the check)."""
        d = self.d
        b = self.b
        own = {o: (d.TR[o][d.TR[o].y != d.never[o]] if world == 0 else d.TR[o]) for o in ORG}
        steps = b.passes * math.ceil(max(len(own[o]) for o in ORG) / BATCH)
        torch.manual_seed(seed)
        gen = torch.Generator().manual_seed(seed)
        out = []
        for o in ORG:                                                     # isolated training
            sc = StandardScaler().fit(own[o][self.F])
            m = Detector(self.NF, self.C)
            u = self.train(m, self.X(sc, own[o]), self.Y(own[o]), steps, gen)
            out.append(dict(road="1_isolated", org=o, steps=u, bytes=0, **self.test(m, sc, o)))
        self.log(f"seed {seed}: isolated training done")
        for o in ORG:                                                     # sanitized attack-record sharing
            received = pd.concat([d.clean(own[p][own[p].y != d.benign]) for p in ORG if p != o])
            data = pd.concat([own[o], received])
            sc = StandardScaler().fit(data[self.F])
            m = Detector(self.NF, self.C)
            u = self.train(m, self.X(sc, data), self.Y(data), steps, gen)
            out.append(dict(road="2_sharing", org=o, steps=u, bytes=int(len(received) * (self.NF * 4 + 1)), records_received=int(len(received)), **self.test(m, sc, o)))
        self.log(f"seed {seed}: sanitized attack-record sharing done")
        scs = {o: StandardScaler().fit(own[o][self.F]) for o in ORG}      # federated learning
        Xs = {o: self.X(scs[o], own[o]) for o in ORG}
        Ys = {o: self.Y(own[o]) for o in ORG}
        per_round = sum(b.local_epochs * math.ceil(len(own[o]) / BATCH) for o in ORG)
        rounds = max(1, round(steps / per_round))
        shared = Detector(self.NF, self.C)
        local = {o: Detector(self.NF, self.C) for o in ORG}
        used = 0
        w = np.array([len(own[o]) for o in ORG], float)
        w /= w.sum()
        for _ in range(rounds):
            for o in ORG:
                local[o].load_state_dict(shared.state_dict())
                used += self.train(local[o], Xs[o], Ys[o], b.local_epochs * math.ceil(len(own[o]) / BATCH), gen)
            shared.load_state_dict({k: sum(w[i] * local[ORG[i]].state_dict()[k] for i in range(3)) for k in shared.state_dict()})
        for o in ORG:
            out.append(dict(road="3_federated", org=o, steps=used, rounds=rounds, bytes=int(self.PARAMS * 4 * 2 * rounds), **self.test(shared, scs[o], o)))
        self.log(f"seed {seed}: federated learning done ({rounds} rounds)")
        pool = pd.concat(own.values())                                    # centralized training
        sc = StandardScaler().fit(pool[self.F])
        m = Detector(self.NF, self.C)
        u = self.train(m, self.X(sc, pool), self.Y(pool), steps, gen)
        for o in ORG:
            out.append(dict(road="4_centralized", org=o, steps=u, bytes=int(len(own[o]) * (self.NF * 4 + 1)), **self.test(m, sc, o)))
        self.log(f"seed {seed}: centralized training done")
        return out


# ================= STEP 5a: ranges (bootstrap over attack events) =================
def plain(ev):
    if isinstance(ev, dict):
        return ev
    return dict(event=np.asarray(ev.index), s1=ev[("s1", "mean")].to_numpy(float), s2=ev[("s2", "mean")].to_numpy(float), n=ev[("s1", "size")].to_numpy(float))


def event_table(runs, world, road, o, stage, seeds):
    first = plain(runs[(world, seeds[0], road, o)])
    hits = np.mean([plain(runs[(world, s, road, o)])[stage] for s in seeds], axis=0)
    n = first["n"]
    return pd.DataFrame(dict(n=n, hits=hits * n), index=pd.Index(first["event"]))


def compare(tA, tB, rng, resamples):
    j = tA.index.intersection(tB.index)
    tA, tB = tA.loc[j], tB.loc[j]
    k = len(j)
    if k == 0:
        return float("nan"), np.full(resamples, np.nan), 0
    rec = lambda t, i: t.hits.values[i].sum() / t.n.values[i].sum()
    est = rec(tA, np.arange(k)) - rec(tB, np.arange(k))
    bs = np.array([rec(tA, i) - rec(tB, i) for i in (rng.integers(0, k, k) for _ in range(resamples))])
    return est, bs, k


# ================= STEP 5b: H3, can a sanitized record be traced to its source host? =================
def trace(data, budget, log, cache=None):
    """Attacker = the receiving organization, holding the sender's sanitized attack records plus the sender's normal
    traffic labeled by source host (an upper bound). Scored against always guessing the most common host."""
    df = data.df
    feats = data.feats
    TR = df[df.part == "train"]
    rng = np.random.RandomState(0)
    out = {}
    for o in ORG:
        f = f"{cache}/trace_{o}.json" if cache else None
        if f and os.path.exists(f):
            out[o] = json.load(open(f))
            continue
        own = TR[(TR.org == o) & (TR.y != data.never[o])]
        note = None
        if own.source.nunique() > TRACE_MAX_HOSTS:
            # thousands of hosts (public flow datasets with external addresses) make the forests impractically slow and the
            # question ill-posed; the test then covers the sender's busiest hosts only, and says so
            top_hosts = own.source.value_counts().index[:TRACE_TOP_HOSTS]
            note = f"the sender has {own.source.nunique():,} hosts; the test covers its {TRACE_TOP_HOSTS} busiest hosts only"
            own = own[own.source.isin(top_hosts)]
        sent = own[own.y != data.benign].reset_index(drop=True)
        ref = own[own.y == data.benign]
        if len(sent) > TRACE_MAX:
            sent = sent.sample(TRACE_MAX, random_state=0).reset_index(drop=True)
        if len(ref) > TRACE_MAX:
            ref = ref.sample(TRACE_MAX, random_state=0)
        y = sent.source.values
        if len(sent) < 20 or len(ref) < 20 or len(np.unique(y)) < 2 or len(np.unique(ref.source)) < 2:
            out[o] = dict(skipped="not enough source hosts or records to test tracing")
            if f:
                json.dump(out[o], open(f, "w"))
            continue
        top = pd.Series(y).value_counts().index[0]
        Xr, Xs = np.nan_to_num(ref[feats].values), np.nan_to_num(sent[feats].values)
        P = [RandomForestClassifier(n_estimators=budget.trace_trees, n_jobs=-1, random_state=s).fit(Xr, ref.source.values).predict(Xs) for s in range(budget.trace_seeds)]
        acc = float(np.mean([accuracy_score(y, p) for p in P]))
        guess = float(np.mean(y == top))
        bal = float(np.mean([balanced_accuracy_score(y, p) for p in P]))
        d = pd.DataFrame(dict(ev=sent.event, c=(P[0] == y).astype(float), b=(y == top).astype(float))).groupby("ev").agg(c=("c", "sum"), b=("b", "sum"), n=("c", "size"))
        E = d.index.values
        bs = []
        for _ in range(budget.resamples):
            s = d.loc[rng.choice(E, len(E))]
            bs.append((s.c.sum() - s.b.sum()) / s.n.sum())
        lo, hi = np.percentile(bs, [2.5, 97.5])
        beat = 0
        Xr_p, yr_p, Xs_p, y_p = Xr, ref.source.values, Xs, y
        if budget.trace_perm_rows and (len(Xr) > budget.trace_perm_rows or len(Xs) > budget.trace_perm_rows):
            ir = rng.choice(len(Xr), min(len(Xr), budget.trace_perm_rows), replace=False)
            i_s = rng.choice(len(Xs), min(len(Xs), budget.trace_perm_rows), replace=False)
            Xr_p, yr_p, Xs_p, y_p = Xr[ir], ref.source.values[ir], Xs[i_s], y[i_s]
            acc_p = float(np.mean([accuracy_score(y_p, p[i_s]) for p in P]))
        else:
            acc_p = acc
        for i in range(budget.trace_permutations):
            p = RandomForestClassifier(n_estimators=budget.trace_perm_trees, n_jobs=-1, random_state=i).fit(Xr_p, rng.permutation(yr_p)).predict(Xs_p)
            beat += accuracy_score(y_p, p) >= acc_p
        out[o] = dict(records=int(len(sent)), sources=int(len(np.unique(y))), traced=acc, guessing=guess, balanced=bal,
                      advantage=acc - guess, lo=float(lo), hi=float(hi), p_value=(beat + 1) / (budget.trace_permutations + 1), note=note)
        log(f"tracing {data.companies[o]['name']}: traced {acc:.1%} against guessing {guess:.1%}")
        if f:
            json.dump(out[o], open(f, "w"), indent=1)
    return out


# ================= the whole procedure on one dataset =================
def run(cfg, frame=None, budget=PROTOCOL, log=None, cache=None):
    """Run the five steps. cfg: settings dict (label_col, benign_label, optional source_col, time_col, drop, keep,
    label_cols, never_seen, companies). frame: a DataFrame instead of cfg['paths']. Returns the scorecard dict."""
    log = log or (lambda m: None)
    t0 = time.time()
    seeds = list(budget.seeds)
    if cache:
        os.makedirs(cache, exist_ok=True)
    log("Step 1: load the records and make the three organizations")
    data = Data(cfg, frame=frame, budget=budget, log=log)
    bench = Bench(data, budget=budget, log=log)
    step1 = data.describe()
    for o in ORG:
        s = step1[o]
        log(f"  {s['name']}: withheld attack type {s['never_seen']}; training records {s['train']:,} ({s['withheld']:,} withheld, {s['train_after']:,} kept); test records of the withheld type {s['test_never_seen']:,}")
    log(f"Step 2: sanitize. {data.raw_columns} columns in the raw data; {len(data.feats)} numbers plus the attack type kept; {data.raw_columns - len(data.feats) - 1} removed")

    rows, runs = [], {}
    worlds = (0, 1) if budget.nothing_withheld_check else (0,)
    for world in worlds:
        for seed in seeds:
            f = f"{cache}/run_world{world}_seed{seed}.pkl" if cache else None
            if f and os.path.exists(f):
                res = pickle.load(open(f, "rb"))
            else:
                label = "withheld attack types" if world == 0 else "nothing withheld (check)"
                log(f"Step 3 and 4: train under the four training conditions and test, {label}, seed {seed}")
                t = time.time()
                res = bench.run(world, seed)
                for r in res:
                    r["events"] = plain(r["events"])
                if f:
                    pickle.dump(res, open(f, "wb"))
                log(f"  done in {time.time() - t:.0f} s")
            for r in res:
                r = dict(r)
                runs[(world, seed, r["road"], r["org"])] = plain(r.pop("events"))
                rows.append(dict(world=world, seed=seed, **r))
    R = pd.DataFrame(rows)

    log("Step 5: scorecard")
    rng = np.random.default_rng(0)
    per_org, agg = [], {}
    for world in worlds:
        for o in ORG:
            for road in ROADS[1:]:
                for stage in ("s1", "s2"):
                    est, bs, k = compare(event_table(runs, world, road, o, stage, seeds), event_table(runs, world, "1_isolated", o, stage, seeds), rng, budget.resamples)
                    agg[(world, o, road, stage)] = (est, bs)
                    per_org.append(dict(world=world, org=o, road=road, stage=stage, events=k, gain=est,
                                        lo=float(np.nanpercentile(bs, 2.5)), hi=float(np.nanpercentile(bs, 97.5))))
    H = {}
    for world in worlds:
        for road in ROADS[1:]:
            for stage in ("s1", "s2"):
                ests = [agg[(world, o, road, stage)][0] for o in ORG]
                bs = np.nanmean([agg[(world, o, road, stage)][1] for o in ORG], axis=0)
                lo, hi = np.nanpercentile(bs, [2.5, 97.5])
                H[(world, road, stage)] = dict(gain=float(np.nanmean(ests)), lo=float(lo), hi=float(hi), clears=bool(lo > MIN_GAIN))

    rng2 = np.random.default_rng(1)
    m1m2 = {}
    for o in ORG:
        est, bs, k = compare(event_table(runs, 0, "2_sharing", o, "s2", seeds), event_table(runs, 0, "3_federated", o, "s2", seeds), rng2, budget.resamples)
        m1m2[o] = dict(diff=est, lo=float(np.nanpercentile(bs, 2.5)), hi=float(np.nanpercentile(bs, 97.5)), events=k, _bs=bs)
    bs = np.nanmean([m1m2[o]["_bs"] for o in ORG], axis=0)
    m1m2["mean"] = dict(diff=float(np.nanmean([m1m2[o]["diff"] for o in ORG])), lo=float(np.nanpercentile(bs, 2.5)), hi=float(np.nanpercentile(bs, 97.5)))
    for o in ORG:
        m1m2[o].pop("_bs")

    tr = None
    if budget.do_trace and data.source_col:
        log("Step 5b: can sanitized records be traced back to their source host?")
        tr = trace(data, budget, log, cache)
    traced = {o: t for o, t in (tr or {}).items() if "traced" in t}

    mean = R.groupby(["world", "road", "org"]).mean(numeric_only=True)
    by = lambda w, road, o, col: float(mean.loc[(w, road, o), col])
    card = {
        "name": cfg.get("name", "dataset"), "about": cfg.get("about", ""), "made": time.strftime("%d %b %Y, %H:%M"),
        "minutes": round((time.time() - t0) / 60, 1), "budget": asdict(budget), "seeds": seeds,
        "software": dict(torch=torch.__version__, numpy=np.__version__, pandas=pd.__version__),
        "rules": dict(false_alarm_target=FALSE_ALARM, min_gain=MIN_GAIN, fp_limit=FP_LIMIT, batch=BATCH, passes=budget.passes,
                      local_epochs=budget.local_epochs, resamples=budget.resamples, network=f"{bench.NF}-128-64-{bench.C}",
                      split=data.split_note, companies=data.company_note),
        "step1": step1,
        "step2": dict(raw_columns=data.raw_columns, kept_numbers=len(data.feats), removed=data.raw_columns - len(data.feats) - 1,
                      kept=list(data.feats), removed_columns=list(getattr(data, "dropped", []) or [])),
        "classes": sorted(c for c in data.df.y.unique() if c != data.benign),
        "benign": data.benign,
        "companies": {o: dict(
            name=data.companies[o]["name"], never_seen=data.never[o], test_rows=int(by(0, "1_isolated", o, "test_rows")),
            named={road: by(0, road, o, "named") for road in ROADS},
            flagged={road: by(0, road, o, "flagged") for road in ROADS},
            false_alarm={road: by(0, road, o, "false_alarm_test") for road in ROADS},
            bytes={road: int(by(0, road, o, "bytes")) for road in ROADS},
            steps={road: int(by(0, road, o, "steps")) for road in ROADS},
            named_check=({road: by(1, road, o, "named") for road in ROADS} if 1 in worlds else None),
            gain={p["road"]: dict(gain=p["gain"], lo=p["lo"], hi=p["hi"], events=p["events"]) for p in per_org if p["world"] == 0 and p["org"] == o and p["stage"] == "s2"},
            gain_flagged={p["road"]: dict(gain=p["gain"], lo=p["lo"], hi=p["hi"]) for p in per_org if p["world"] == 0 and p["org"] == o and p["stage"] == "s1"},
            records_received=int(by(0, "2_sharing", o, "records_received")),
            trace=(tr or {}).get(o)) for o in ORG},
        "sharing_minus_federated": m1m2,
        "hypotheses": {
            "H1": H[(0, "2_sharing", "s2")], "H2": H[(0, "3_federated", "s2")],
            "H3": None if not traced else dict(yes=all(t["lo"] > 0 for t in traced.values()), companies=len(traced),
                                               low=min(t["advantage"] for t in traced.values()), high=max(t["advantage"] for t in traced.values())),
            "H3_note": None if data.source_col else "this data has no device or host column, so tracing cannot be tested"},
        "checks": {
            "pooled": H[(0, "4_centralized", "s2")],
            "flagged": {"H1": H[(0, "2_sharing", "s1")], "H2": H[(0, "3_federated", "s1")]},
            "nothing_withheld": ({"H1": H[(1, "2_sharing", "s2")], "H2": H[(1, "3_federated", "s2")]} if 1 in worlds else None),
            "benign_val_rows": {o: int((data.VA[o].y == data.benign).sum()) for o in ORG},
            "rounds": int(R[(R.world == 0) & (R.road == "3_federated")].rounds.iloc[0])},
    }
    card["verdicts"] = verdicts(card)
    log(f"H1 sanitized attack-record sharing: {card['hypotheses']['H1']['gain'] * 100:+.1f} points [{card['hypotheses']['H1']['lo'] * 100:+.1f}, {card['hypotheses']['H1']['hi'] * 100:+.1f}]")
    log(f"H2 federated learning: {card['hypotheses']['H2']['gain'] * 100:+.1f} points [{card['hypotheses']['H2']['lo'] * 100:+.1f}, {card['hypotheses']['H2']['hi'] * 100:+.1f}]")
    log(f"done in {card['minutes']} min")
    return card


def verdicts(card):
    """The decision rule of 8 October, per organization and condition.
    Gain: the low end of the 95% range of the gain in attack-class recall must be above 5 points.
    False positives: the false-positive rate may rise by at most 1 point over isolated training.
    Privacy (sharing only): if the gain is met but sanitized records are traced above the majority-host guess, the
    result is a trade-off. Data sent is reported, not judged."""
    out = {}
    for o, c in card["companies"].items():
        v = {"1_isolated": "baseline", "4_centralized": "reference"}
        fp0 = c["false_alarm"]["1_isolated"]
        for road in ("2_sharing", "3_federated"):
            g = c["gain"].get(road) or {}
            gain_met = bool(g and not math.isnan(g.get("lo", float("nan"))) and g["lo"] > MIN_GAIN)
            fp_ok = (c["false_alarm"][road] - fp0) <= FP_LIMIT
            if not gain_met:
                v[road] = "not worth it (gain not met)"
            elif not fp_ok:
                v[road] = "gain met, false-positive limit breached"
            elif road == "2_sharing" and c.get("trace") and "traced" in c["trace"] and c["trace"]["lo"] > 0:
                v[road] = "gain met, privacy trade-off"
            else:
                v[road] = "gain met"
        out[o] = v
    return out


# ================= helpers for the web tool =================
LABEL_NAME_RX = re.compile(r"attack|label|class|categor|type|cat$|^y$|target|malicious|anomal", re.I)
STRICT_LABEL_RX = re.compile(r"label|attack|class|categor|target|malicious|anomal", re.I)
NORMAL_RX = re.compile(r"^(normal|benign|legit(imate)?|clean|none|background|0|no|false)$", re.I)
HOST_RX = re.compile(r"ip$|^ip|ips?(_|\.|$)|(^|_|\.)ip|mac|addr|host|device|sensor|node|asset|machine|station", re.I)
TIME_RX = re.compile(r"time|stamp|^ts$|date|stime|ltime|start|frame\.time", re.I)
KEEP_HINT_RX = re.compile(r"len|size|byte|pkt|packet|count|cnt|rate|dur|num|avg|mean|min|max|std|sum|ttl|throughput|ratio|freq|conn|^n_|^ct_|per_", re.I)
IDENT_NAME_RX = re.compile(r"port$|_port|port_|^proto(col)?$|service|state$|^uid$|^id$|name|^flow_id|^label", re.I)


def inspect(df):
    """Guess the roles of the columns in an uploaded table. Everything here is a suggestion the user can change."""
    n = len(df)
    cols = list(df.columns)
    nun = {c: int(df[c].nunique(dropna=True)) for c in cols}
    # label column: text or small-integer column, 2 to 80 values, name or values look like labels
    cands = []
    for c in cols:
        if not (2 <= nun[c] <= 80):
            continue
        vals = df[c].dropna().astype(str).str.strip()
        score = 0
        if LABEL_NAME_RX.search(c):
            score += 3
        if vals.str.match(NORMAL_RX).any():
            score += 2
        if df[c].dtype == object:
            score += 2
        if nun[c] >= 3:
            score += 1
        if c in cols[-3:]:
            score += 1
        if IDENT_RX.search(c) or TIME_RX.search(c):
            score -= 4
        cands.append((score, -nun[c] if nun[c] <= 2 else 0, c))
    cands.sort(reverse=True)
    label_col = cands[0][2] if cands and cands[0][0] > 0 else None
    other_labels = [c for s, _, c in cands if c != label_col and s >= 3 and STRICT_LABEL_RX.search(c)]
    benign = None
    if label_col:
        vc = df[label_col].astype(str).str.strip().value_counts()
        hits = [v for v in vc.index if NORMAL_RX.match(v)]
        benign = hits[0] if hits else vc.index[0]
    # source host: a column that names a device or an address, with a sensible number of values
    srcs = []
    for c in cols:
        if c == label_col or c in other_labels:
            continue
        if HOST_RX.search(c) and 2 <= nun[c] <= max(5, n // 20) and not re.search(r"port", c, re.I):
            if df[c].dtype != object:
                v = pd.to_numeric(df[c], errors="coerce").dropna()
                if KEEP_HINT_RX.search(c) or nun[c] < 3 or (len(v) and not (v == v.round()).all()):
                    continue
            pri = 0
            if re.search(r"device|host|sensor|node|asset|machine|station", c, re.I):
                pri += 3
            if re.search(r"dst|des_|dest|^d(addr|ip)", c, re.I):
                pri += 2
            if df[c].dtype == object:
                pri += 3
            srcs.append((pri, c))
    srcs.sort(reverse=True)
    source_col = srcs[0][1] if srcs else None
    times = [c for c in cols if TIME_RX.search(c) and c != label_col and nun[c] > 10
             and not re.search(r"duration|elapsed|iat|interval|_per_|rate|end|ttl|live|active|idle", c, re.I)]
    time_col = times[0] if times else None
    identifiers, text_cols, numbers, unusable = [], [], [], []
    for c in cols:
        if c in (label_col, source_col, time_col) or c in other_labels:
            continue
        v = pd.to_numeric(df[c], errors="coerce")
        is_number = v.notna().mean() >= 0.95 and v.nunique() >= 2
        if IDENT_RX.search(c) and not (is_number and KEEP_HINT_RX.search(c)):
            identifiers.append(c)
        elif IDENT_NAME_RX.search(c):
            identifiers.append(c)
        elif is_number:
            numbers.append(c)
        elif df[c].dtype == object:
            text_cols.append(c)
        else:
            unusable.append(c)
    return dict(rows=n, columns=len(cols), label_col=label_col, benign_label=benign, label_cols=other_labels,
                source_col=source_col, time_col=time_col, identifiers=identifiers, text_columns=text_cols, numbers=numbers, unusable=unusable,
                label_values=(df[label_col].astype(str).str.strip().value_counts().to_dict() if label_col else {}))


def sanitize(df, label_col, keep_numbers, attack_only=False, benign_label=None):
    """Return the sanitized table an organization may send: the chosen behavior numbers and the attack type."""
    out = df[keep_numbers + [label_col]].copy()
    for c in keep_numbers:
        out[c] = pd.to_numeric(out[c], errors="coerce")
    if attack_only and benign_label is not None:
        out = out[out[label_col].astype(str).str.strip() != str(benign_label)]
    return out.reset_index(drop=True)


def example_data(seed=0, n_hosts=30, per_host=220):
    """A small made-up table with the shape of an intrusion dataset, so the tool can be tried without an upload.
    It is synthetic and proves nothing about real attacks."""
    rng = np.random.default_rng(seed)
    kinds = ["normal", "dos", "ddos", "scan", "mitm", "brute_force", "malware"]
    base = {k: rng.normal(0, 1, 12) * (0 if k == "normal" else 1) + (np.arange(12) % 3 == i % 3) * (0.8 + 0.3 * i) for i, k in enumerate(kinds)}
    rows = []
    t = 1.7e9
    for h in range(n_hosts):
        host = f"10.0.{h // 10}.{h % 10 + 1}"
        hshift = rng.normal(0, 0.4, 12)
        for _ in range(per_host):
            k = "normal" if rng.random() < 0.45 else kinds[1 + rng.integers(0, 6)]
            x = base[k] + hshift + rng.normal(0, 0.7, 12)
            x = np.abs(x) * np.array([900, 40, 12, 60, 3, 1500, 25, 8, 200, 5, 70, 15])
            t += float(rng.exponential(6))
            rows.append([t, host, f"192.168.1.{rng.integers(1, 250)}", int(rng.integers(1024, 65535)), int(rng.integers(0, 3)), *np.round(x, 2), k])
    cols = ["timestamp", "device_ip", "peer_ip", "src_port", "proto_id", "bytes_in", "pkts_in", "bytes_out", "pkts_out", "syn_count",
            "pkt_size_max", "pkt_size_mean", "ack_count", "flow_duration", "rst_count", "log_lines", "log_errors", "attack_type"]
    return pd.DataFrame(rows, columns=cols)
