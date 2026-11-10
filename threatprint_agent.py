#!/usr/bin/env python3
"""ThreatPrint local agent.

Run this on your own machine, on your own records. It reads a labeled table of network or device records, works out
which columns are identifiers, removes them, maps each attack label to a common attack family and to MITRE ATT&CK,
and writes a FINGERPRINT: a small file of summary statistics per attack type. The fingerprint holds no records and no
identifier columns. Nothing is sent anywhere: this file has no network code. You decide whether to upload the
fingerprint to a ThreatPrint site.

    python threatprint_agent.py my_records.csv                        writes my_records.fingerprint.json
    python threatprint_agent.py my_records.csv --sanitized out.csv    also writes the sanitized table (attack records only)
    python threatprint_agent.py my_records.csv --label attack_type --normal normal --host device_name --time timestamp
    python threatprint_agent.py --verify my_records.fingerprint.json  checks the integrity digest of a fingerprint

Needs Python 3.9 or newer with pandas and numpy. The file is one page of plain Python so that a security team can
read all of it before running it.

What a fingerprint is, and what it is not
  For every attack type with at least K records (default 50) it stores: the record count rounded down to the nearest
  ten, 41 quantiles (1% to 99%) of every behavior number, and the rank correlations between the behavior numbers.
  It stores no rows, no device names, no addresses, no ports, no time stamps, and no minimum or maximum values.
  It is a summary, not a formal privacy protection: no differential privacy is applied, and what a fingerprint
  reveals about the organization that made it has not been measured in the praxis.
"""
import argparse
import hashlib
import json
import math
import os
import re
import sys
import time

import numpy as np
import pandas as pd

AGENT_VERSION = "0.3"
FORMAT = "threatprint-fingerprint"
FORMATS = (FORMAT, "praxis-lab-fingerprint")           # the second is the name used until 9 November 2026
ATTACK_VERSION = "MITRE ATT&CK v20.1 (Enterprise and ICS), identifiers checked on 9 November 2026"
K_MIN = 50                                   # minimum records per attack type; smaller groups are left out
GRID = [round(x, 4) for x in np.linspace(0.01, 0.99, 41)]

# ---------------------------------------------------------------- column roles (shared with the web tool)
IDENT_RX = re.compile(r"(^|_|\.)(ip|ips|mac|macs|addr|address|host|hostname|timestamp|time_start|time_end|flow_id|uid|id)($|_|\.)", re.I)
LABEL_NAME_RX = re.compile(r"attack|label|class|categor|type|cat$|^y$|target|malicious|anomal", re.I)
STRICT_LABEL_RX = re.compile(r"label|attack|class|categor|target|malicious|anomal", re.I)
NORMAL_RX = re.compile(r"^(normal|benign|legit(imate)?|clean|none|background|0|no|false)$", re.I)
HOST_RX = re.compile(r"ip$|^ip|ips?(_|\.|$)|(^|_|\.)ip|mac|addr|host|device|sensor|node|asset|machine|station", re.I)
TIME_RX = re.compile(r"time|stamp|^ts$|date|stime|ltime|start|frame\.time", re.I)
KEEP_HINT_RX = re.compile(r"len|size|byte|pkt|packet|count|cnt|rate|dur|num|avg|mean|min|max|std|sum|ttl|throughput|ratio|freq|conn|^n_|^ct_|per_", re.I)
IDENT_NAME_RX = re.compile(r"port$|_port|port_|^proto(col)?$|service|state$|^uid$|^id$|name|^flow_id|^label", re.I)


def inspect(df):
    """Guess the roles of the columns in a table. Everything here is a suggestion the user can change."""
    n = len(df)
    cols = list(df.columns)
    nun = {c: int(df[c].nunique(dropna=True)) for c in cols}
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


# ---------------------------------------------------------------- common attack families and MITRE ATT&CK
E, I = "Enterprise", "ICS"
T = {  # identifier -> (matrix, name); every entry is checked against MITRE's published STIX data by tools/verify_attack_ids.py
    "T1595": (E, "Active Scanning"), "T1046": (E, "Network Service Discovery"), "T0846": (I, "Remote System Discovery"),
    "T0888": (I, "Remote System Information Discovery"),
    "T1498": (E, "Network Denial of Service"), "T1499": (E, "Endpoint Denial of Service"), "T0814": (I, "Denial of Service"),
    "T1557": (E, "Adversary-in-the-Middle"), "T1557.002": (E, "Adversary-in-the-Middle: ARP Cache Poisoning"), "T0830": (I, "Adversary-in-the-Middle"),
    "T1692.001": (I, "Unauthorized Message: Command Message"), "T1692.002": (I, "Unauthorized Message: Reporting Message"),
    "T1691.002": (I, "Block Operational Technology Message: Reporting Message"),
    "T0816": (I, "Device Restart/Shutdown"), "T0881": (I, "Service Stop"),
    "T1110": (E, "Brute Force"),
    "T1190": (E, "Exploit Public-Facing Application"), "T0819": (I, "Exploit Public-Facing Application"),
    "T1486": (E, "Data Encrypted for Impact"), "T1041": (E, "Exfiltration Over C2 Channel"),
    "T1071": (E, "Application Layer Protocol"), "T0869": (I, "Standard Application Layer Protocol"),
    "T1210": (E, "Exploitation of Remote Services"), "T1068": (E, "Exploitation for Privilege Escalation"), "T0866": (I, "Exploitation of Remote Services"),
}
FAMILIES = [  # (family, pattern on the lower-cased label with separators turned into spaces, technique identifiers); the order decides
    ("Reconnaissance and scanning", r"\b(mirai|gafgyt)\b.*scan", ["T1595", "T1046", "T0846"]),
    ("Distributed denial of service", r"ddos|\bloic\b|\bhoic\b|\b(mirai|gafgyt)\b", ["T1498", "T0814"]),
    ("Adversary in the middle", r"mitm|\barp\b|arp ?spoof|arp ?poison|spoof|poison|man in the middle", ["T1557", "T0830"]),
    ("Denial of service", r"\b(dos|rdos|slowloris|slowhttptest|hulk|goldeneye|neptune|smurf|teardrop|pod|land|back|apache2|processtable|mailbomb|udpstorm|hping)\b|flood|denial of service", ["T1499", "T0814"]),
    ("Industrial control messages", r"write attack|read attack|response attack|force error|replay|cold restart|warm restart|stop app|init data|disable unsolicited|command attack|\bc (ci|rd|rp|sc|se) na\b|\bm sp na\b|comminj|tamper|modbus|false data", ["T1692.001"]),
    ("Reconnaissance and scanning", r"scan|recon|probe|nmap|satan|sweep|\bsaint\b|fingerprint|os detect|enumerat|discovery|recognition|\binfo\b|vulnerab", ["T1595", "T1046", "T0846"]),
    ("Web and injection", r"xss|sql|injection", ["T1190", "T0819"]),
    ("Brute force and credentials", r"brute|password|passwd|patator|guess|dictionary|\bbfa\b|credential", ["T1110"]),
    ("Web and injection", r"sql|xss|injection|web|browser ?hijack|upload|\bphf\b|heartbleed|httptunnel", ["T1190", "T0819"]),
    ("Ransomware", r"ransom", ["T1486"]),
    ("Exfiltration", r"exfil", ["T1041"]),
    ("Malware, botnet and command and control", r"\bbot\b|botnet|c&c|\bc2\b|command and control|malware|backdoor|trojan|\bworms?\b|neris|rbot|donbot|fast flux|qvod|sogou|torii|okiru|heartbeat|file ?download|weaponization|keylog|rootkit|shellcode", ["T1071", "T0869"]),
    ("Exploitation and lateral movement", r"exploit|\bu2r\b|\br2l\b|buffer overflow|loadmodule|\bperl\b|xterm|\bps\b|lateral|privilege|infilt|multihop|warez|\bimap\b|\bnamed\b|sendmail|xlock|xsnoop|\bspy\b|ftp write|snmpgetattack|fuzz", ["T1210", "T1068", "T0866"]),
]
OVERRIDES = [  # more specific technique for some labels inside a family
    (r"\barp\b|arp ?spoof|arp ?poison", ["T1557.002", "T0830"]),
    (r"cold restart|warm restart", ["T0816"]),
    (r"stop app", ["T0881"]),
    (r"disable unsolicited", ["T1691.002"]),
    (r"response attack|replay", ["T1692.002"]),
    (r"\binfo\b|enumerat", ["T0888", "T0846"]),
]
UNMAPPED = "Other or unmapped"


def classify(label):
    """Map one attack label to a common attack family and to MITRE ATT&CK techniques (the closest ones; a suggestion)."""
    s = re.sub(r"[^a-z0-9&]+", " ", str(label).lower()).strip()
    for family, rx, ids in FAMILIES:
        if re.search(rx, s):
            for orx, oids in OVERRIDES:
                if re.search(orx, s):
                    ids = oids
                    break
            return dict(family=family, techniques=[dict(id=i, matrix=T[i][0], name=T[i][1]) for i in ids])
    return dict(family=UNMAPPED, techniques=[])


def technique_text(techs):
    return "; ".join(f"{t['id']} {t['name']} ({t['matrix']})" for t in techs) if techs else "no mapping"


# ---------------------------------------------------------------- fingerprint
def _sig(v):
    return float(f"{float(v):.6g}")


def class_fingerprint(X):
    """Summary of one attack type: quantiles of every behavior number and their rank correlations. X: numeric DataFrame."""
    X = X.apply(pd.to_numeric, errors="coerce").replace([np.inf, -np.inf], np.nan)
    X = X.fillna(X.median()).fillna(0.0)
    if len(X) > 20000:
        X = X.sample(20000, random_state=0)
    q = np.quantile(X.values.astype(float), GRID, axis=0)                    # grid x features
    r = X.rank().corr().values                                               # Spearman rank correlation
    r = np.nan_to_num(r, nan=0.0)
    np.fill_diagonal(r, 1.0)
    rho = 2.0 * np.sin(np.pi * r / 6.0)                                       # rank correlation -> Gaussian copula correlation
    iu = np.triu_indices(X.shape[1], 1)
    return dict(records=int(len(X) // 10 * 10),
                quantiles=[[_sig(v) for v in row] for row in q],
                corr=[round(float(v), 3) for v in rho[iu]],
                integer=[bool(np.all(np.equal(np.mod(X[c].values, 1), 0))) for c in X.columns])


def class_fingerprints(X, y, k=K_MIN):
    """Fingerprints of every attack type in y with at least k records. Returns (classes, suppressed labels, payload bytes)."""
    classes, suppressed = {}, []
    y = pd.Series(np.asarray(y).astype(str), index=X.index)
    for lab, n in y.value_counts().items():
        if n < k:
            suppressed.append(lab)
            continue
        classes[lab] = class_fingerprint(X[y == lab])
    f = X.shape[1]
    nbytes = int(len(classes) * (len(GRID) * f + f * (f - 1) // 2 + 1) * 4)
    return dict(classes=classes, suppressed=suppressed, bytes=nbytes)


def _phi(z):
    """Standard normal distribution function (Abramowitz and Stegun 7.1.26), so that scipy is not needed."""
    x = np.abs(z) / math.sqrt(2.0)
    t = 1.0 / (1.0 + 0.3275911 * x)
    y = 1.0 - (((((1.061405429 * t - 1.453152027) * t) + 1.421413741) * t - 0.284496736) * t + 0.254829592) * t * np.exp(-x * x)
    return 0.5 * (1.0 + np.sign(z) * y)


def synthesize(c, n, rng):
    """Draw n made-up records from one attack type's fingerprint (Gaussian copula over the stored quantiles)."""
    q = np.asarray(c["quantiles"], float)
    f = q.shape[1]
    rho = np.eye(f)
    iu = np.triu_indices(f, 1)
    rho[iu] = c["corr"]
    rho = rho + rho.T - np.eye(f)
    w, v = np.linalg.eigh(rho)                                               # nearest usable correlation matrix
    rho = (v * np.clip(w, 1e-6, None)) @ v.T
    d = np.sqrt(np.diag(rho))
    rho = rho / d[:, None] / d[None, :]
    z = rng.standard_normal((int(n), f)) @ np.linalg.cholesky(rho + 1e-9 * np.eye(f)).T
    u = np.clip(_phi(z), GRID[0], GRID[-1])
    x = np.column_stack([np.interp(u[:, j], GRID, q[:, j]) for j in range(f)])
    for j, is_int in enumerate(c.get("integer", [])):
        if is_int:
            x[:, j] = np.round(x[:, j])
    return x


def digest(fp):
    """SHA3-256 over the canonical JSON of the fingerprint without its integrity and signature fields."""
    body = {k: v for k, v in fp.items() if k not in ("integrity", "signature")}
    return hashlib.sha3_256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def verify(fp):
    return fp.get("format") in FORMATS and fp.get("integrity", {}).get("digest") == digest(fp)


def _bucket(n):
    return "none" if not n else ("fewer than 10" if n < 10 else ("10 to 49" if n < 50 else "50 or more"))


def build_fingerprint(df, label_col, benign_label, numbers, source_col=None, time_col=None, k=K_MIN, removed_count=0):
    y = df[label_col].astype(str).str.strip()
    X = df[numbers].apply(pd.to_numeric, errors="coerce")
    ok = [c for c in numbers if X[c].notna().mean() >= 0.95 and X[c].nunique() >= 2]
    att = y != str(benign_label)
    res = class_fingerprints(X.loc[att, ok], y[att], k=k)
    hosts = int(df[source_col].nunique()) if source_col else 0
    fp = dict(format=FORMAT, version=1, agent=AGENT_VERSION, created=time.strftime("%Y-%m-%d"), attack_reference=ATTACK_VERSION,
              min_group_size=int(k), quantile_grid=GRID, features=ok,
              normal=dict(records=int((~att).sum() // 10 * 10)),
              hosts=_bucket(hosts), has_host_column=bool(source_col), has_time_column=bool(time_col),
              removed_columns_count=int(removed_count),
              classes={lab: dict(c, **classify(lab)) for lab, c in res["classes"].items()},
              suppressed=[dict(family=classify(lab)["family"], reason=f"fewer than {k} records") for lab in res["suppressed"]],
              payload_bytes=res["bytes"])
    fp["integrity"] = dict(alg="SHA3-256", digest=digest(fp))
    fp["signature"] = dict(alg="none", note="reserved for a post-quantum signature (ML-DSA, FIPS 204); not implemented in this version")
    return fp


def readiness(fp):
    """Can the ThreatPrint evaluation run on the data behind this fingerprint? Returns a list of (ok, sentence)."""
    n_types = len(fp.get("classes", {}))
    out = [(n_types >= 3, f"{n_types} attack types with at least {fp.get('min_group_size', K_MIN)} records "
                          "(three are needed, so that each of the three organizations can withhold a different one)"),
           (fp.get("normal", {}).get("records", 0) >= 900, f"about {fp.get('normal', {}).get('records', 0):,} normal records "
                                                          "(about 300 per organization are needed for the alarm threshold)"),
           (len(fp.get("features", [])) >= 3, f"{len(fp.get('features', []))} behavior numbers kept after sanitizing"),
           (bool(fp.get("has_host_column")) and fp.get("hosts") not in ("none", None),
            f"host or device column: {'present, ' + fp.get('hosts', '') + ' hosts' if fp.get('has_host_column') else 'absent'} "
            "(needed to form organizations by host and to test tracing; without it organizations are random thirds)"),
           (bool(fp.get("has_time_column")), f"time column: {'present' if fp.get('has_time_column') else 'absent'} "
                                             "(needed to keep one attack together as an event; without it the ranges are optimistic)")]
    return out


# ---------------------------------------------------------------- command line
def main():
    ap = argparse.ArgumentParser(description="ThreatPrint local agent: sanitize a labeled table and write its fingerprint. Nothing is sent anywhere.")
    ap.add_argument("file", nargs="?", help="CSV or Parquet file with one header row")
    ap.add_argument("--label", help="label column (attack type or normal)")
    ap.add_argument("--normal", help="label value that means normal traffic")
    ap.add_argument("--host", help="host or device column")
    ap.add_argument("--time", help="time column")
    ap.add_argument("--k", type=int, default=K_MIN, help=f"minimum records per attack type (default {K_MIN})")
    ap.add_argument("--out", help="fingerprint file to write (default: <file>.fingerprint.json)")
    ap.add_argument("--sanitized", help="also write the sanitized table here (attack records only)")
    ap.add_argument("--all-records", action="store_true", help="with --sanitized: include the normal records too")
    ap.add_argument("--verify", help="check the integrity digest of a fingerprint file and exit")
    a = ap.parse_args()
    if a.verify:
        fp = json.load(open(a.verify))
        good = verify(fp)
        print(("Integrity digest matches: " if good else "INTEGRITY DIGEST DOES NOT MATCH: ") + fp.get("integrity", {}).get("digest", "none"))
        sys.exit(0 if good else 1)
    if not a.file:
        ap.error("give a file, or --verify FINGERPRINT")
    df = pd.read_parquet(a.file) if a.file.lower().endswith(".parquet") else pd.read_csv(a.file, low_memory=False)
    roles = inspect(df)
    label = a.label or roles["label_col"]
    if not label:
        sys.exit("No label column was recognized. Name it with --label.")
    if a.label and a.label != roles["label_col"]:                           # the user's label changes what the other columns are
        roles["numbers"] = [c for c in roles["numbers"] if c != a.label]
    normal = a.normal or (roles["benign_label"] if label == roles["label_col"] else df[label].astype(str).str.strip().value_counts().index[0])
    host = a.host or roles["source_col"]
    tcol = a.time or roles["time_col"]
    numbers = [c for c in roles["numbers"] if c not in (label, host, tcol)]
    removed = [c for c in df.columns if c not in numbers and c != label]
    print(f"Read {len(df):,} records, {df.shape[1]} columns from {os.path.basename(a.file)}")
    print(f"Label column: {label}   normal value: {normal}   host column: {host or 'none'}   time column: {tcol or 'none'}")
    print(f"Removed before anything leaves ({len(removed)}): {', '.join(removed)}")
    print(f"Kept as behavior numbers ({len(numbers)}): {', '.join(numbers)}")
    fp = build_fingerprint(df, label, normal, numbers, source_col=host, time_col=tcol, k=a.k, removed_count=len(removed))
    print("\nAttack types in the fingerprint, with common family and MITRE ATT&CK technique:")
    for lab, c in fp["classes"].items():
        print(f"  {lab:32s} about {c['records']:>6,} records   {c['family']:40s} {technique_text(c['techniques'])}")
    if fp["suppressed"]:
        print(f"Left out ({len(fp['suppressed'])} attack types with fewer than {a.k} records).")
    print("\nReadiness for the ThreatPrint evaluation:")
    for good, text in readiness(fp):
        print(f"  [{'ok' if good else '--'}] {text}")
    out = a.out or (os.path.splitext(a.file)[0] + ".fingerprint.json")
    json.dump(fp, open(out, "w"), separators=(",", ":"))
    print(f"\nWrote {out} ({os.path.getsize(out) / 1000:.0f} KB on disk, {fp['payload_bytes'] / 1000:.0f} KB calculated payload).")
    print(f"Integrity digest (SHA3-256): {fp['integrity']['digest']}")
    print("The fingerprint holds no records and no identifier columns. Nothing was sent anywhere.")
    if a.sanitized:
        s = sanitize(df, label, fp["features"], attack_only=not a.all_records, benign_label=normal)
        s.to_csv(a.sanitized, index=False)
        print(f"Wrote the sanitized table: {a.sanitized} ({len(s):,} records, {s.shape[1]} columns).")


if __name__ == "__main__":
    main()
