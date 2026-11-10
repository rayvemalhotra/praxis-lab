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
  It stores no rows, no device names, no addresses, no ports and no time stamps. The lowest and highest points it
  stores are the 1% and 99% quantiles, not the extremes; for a number with few distinct values (a count that is
  mostly 0) those quantiles can equal the smallest or largest value.
  It is a summary, not a formal privacy protection: no differential privacy is applied, and what a fingerprint
  reveals about the organization that made it has not been measured. The fingerprint is product research; it is not part of the praxis.
"""
import argparse
import hashlib
import io
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
GRID = [float(round(x, 4)) for x in np.linspace(0.01, 0.99, 41)]      # plain Python numbers (the same values, the same digest)

# ---------------------------------------------------------------- column roles (shared with the web tool)
IDENT_RX = re.compile(r"(^|_|\.)(ip|ips|mac|macs|addr|address|host|hostname|timestamp|time_start|time_end|flow_id|uid|id)($|_|\.)", re.I)
LABEL_NAME_RX = re.compile(r"attack|label|class|categor|type|cat$|^y$|target|malicious|anomal|intrusion|threat", re.I)
STRICT_LABEL_RX = re.compile(r"label|attack|class|categor|target|malicious|anomal", re.I)
NORMAL_RX = re.compile(r"^(normal|benign|legit(imate)?|clean|clear|none|background|0|no|false|-+)$", re.I)
ATTACK_TYPE_NAME_RX = re.compile(r"^attack[ _.-]?(type|cat(egory)?|name|class)s?$", re.I)      # the usual names of the attack-type column
PLAIN_LABEL_NAME_RX = re.compile(r"^(label|class|category|type)$", re.I)
NOT_A_LABEL_RX = re.compile(r"desc|comment|note|message|text|(?:[a-z]ID|_id|\bid)$")           # free text or an identifier that happens to contain "attack"
HOST_RX = re.compile(r"ip$|^ip|ips?(_|\.|$)|(^|_|\.)ip|mac|addr|host|device|sensor|node|asset|machine|station|(^|[._])(orig|resp)_h$", re.I)   # the last one: Zeek logs
TIME_RX = re.compile(r"time|stamp|^ts$|date|stime|ltime|start|frame\.time", re.I)
KEEP_HINT_RX = re.compile(r"len|size|byte|pkt|packet|count|cnt|rate|dur|num|avg|mean|min|max|std|sum|ttl|throughput|ratio|freq|conn|^n_|^ct_|per_", re.I)
IDENT_NAME_RX = re.compile(r"port$|_port|port_|^proto(col)?$|service|state$|^uid$|^id$|name|^flow_id|^label", re.I)


class DataProblem(ValueError):
    """A problem with the table that the person can fix. The message is one sentence written for that person.
    unexpected = True marks an error the tool did not foresee (a bug to report), wrapped so that no page shows a traceback."""

    def __init__(self, message, unexpected=False):
        super().__init__(message)
        self.unexpected = unexpected


# ---------------------------------------------------------------- reading a table safely
# A cell that starts like a number with an exponent of five or more digits, for example 1e2147483648 or the hex string
# 32342e33302037352e37350d0a. No measurement has such an exponent (the largest a 64-bit number can hold is 308), and the
# number parser of pandas 2.3 ends the whole Python process on some of them on Linux (measured on 9 November 2026:
# read_csv and to_numeric, exit by segmentation fault). Such cells are kept as text with a "~" in front.
DANGEROUS_NUMBER = r"[+-]?(?:\d+\.?\d*|\.\d+)[eE][+-]?\d{5,}"
_DANGEROUS_CELL_RX = re.compile(r"^\s*" + DANGEROUS_NUMBER)
_DANGEROUS_BYTES_RX = re.compile((r'(^|[,;\t\r\n])("?[ ]*)(' + DANGEROUS_NUMBER + ")").encode(), re.M)
DEFUSED = "threatprint_defused"
MAGIC = [(b"%PDF", "a PDF document"), (b"PK\x03\x04", "an Excel workbook or a zip archive"), (b"\x89PNG", "a PNG image"), (b"\xff\xd8\xff", "a JPEG image"),
         (b"GIF8", "a GIF image"), (b"\x1f\x8b", "a gzip archive"), (b"\xd0\xcf\x11\xe0", "an old Excel or Word file"), (b"PAR1", "a Parquet file"), (b"SQLite format", "a SQLite database")]


def _hashable(col):
    try:
        col.head(50).map(hash)
        return True
    except TypeError:
        return False


def defuse(df):
    """Change, in place, every text cell that starts like a number with an impossible exponent (see above) so that no
    later number conversion can end the process; turn cells that hold lists or dicts into text. Returns how many cells changed."""
    changed = 0
    for i in range(df.shape[1]):
        col = df.iloc[:, i]
        if col.dtype != object:
            continue
        name = df.columns[i]
        if not _hashable(col):
            df[name] = col.map(lambda v: v if (v is None or isinstance(v, (str, int, float, bool))) else str(v))
            col = df[name]
        text = col.astype(str)
        hit = text.str.match(_DANGEROUS_CELL_RX)
        if hit.any():
            df[name] = col.where(~hit, "~" + text)
            changed += int(hit.sum())
    df.attrs[DEFUSED] = True
    return changed


def _defused(df):
    """The same table, safe for number conversion; the caller's table is left as it is."""
    if df.attrs.get(DEFUSED):
        return df
    out = df.copy(deep=False)
    defuse(out)
    return out


PARQUET_MAX_CELLS = 50_000_000              # records times columns a Parquet upload may unpack to (a 200 MB CSV of numbers holds about half of this)
PARQUET_MAX_BYTES = 1_500_000_000           # and its unpacked size in bytes, from the file's own metadata


def read_table(source, name=None):
    """Read an uploaded CSV or Parquet table the way the web tool and this agent need it: never a traceback, never a dead
    process. source: a path, bytes, or a file-like object (an upload). Raises DataProblem with one sentence for the person.
    Notes for the person (for example a delimiter that was guessed) are in the attrs of the returned table under 'notes'."""
    name = str(name or (source if isinstance(source, str) else getattr(source, "name", "")) or "")
    if isinstance(source, str):
        with open(source, "rb") as fh:
            data = fh.read()
    elif isinstance(source, (bytes, bytearray, memoryview)):
        data = bytes(source)
    else:
        data = source.getvalue() if hasattr(source, "getvalue") else source.read()
        if isinstance(data, str):
            data = data.encode()
    if len(data) == 0:
        raise DataProblem("the file is empty")
    notes = []
    if name.lower().endswith((".parquet", ".pq")):
        if not data.startswith(b"PAR1"):
            raise DataProblem("the file is named as a Parquet file but is not one; if it is a CSV, give it a name that ends in .csv")
        try:                                                 # a Parquet file can unpack to far more than its size on disk: read its own metadata before the table
            import pyarrow.parquet as pq
            meta = pq.ParquetFile(io.BytesIO(data)).metadata
            rows, cols = int(meta.num_rows), int(meta.num_columns)
            unpacked = sum(int(meta.row_group(i).total_byte_size) for i in range(meta.num_row_groups))
        except Exception as e:
            raise DataProblem(f"the Parquet file could not be read ({type(e).__name__})") from e
        if rows * max(cols, 1) > PARQUET_MAX_CELLS or unpacked > PARQUET_MAX_BYTES:
            raise DataProblem(f"the Parquet file unpacks to {rows:,} records by {cols:,} columns, more than this tool reads at once; "
                              f"export a sample of at most {PARQUET_MAX_CELLS // max(cols, 1):,} records")
        try:
            df = pd.read_parquet(io.BytesIO(data))
        except Exception as e:
            raise DataProblem(f"the Parquet file could not be read ({type(e).__name__})") from e
    else:
        for magic, what in MAGIC:
            if data.startswith(magic):
                raise DataProblem(f"the file is {what}, not a CSV table; export the records as CSV (one header row, one record per row)")
        head = data[:4096]
        if b"\x00" in head or sum(1 for b in head if b < 9 or 13 < b < 32) > len(head) * 0.05:
            raise DataProblem("the file is not a text table; it looks like a binary file with a .csv name")
        if _DANGEROUS_BYTES_RX.search(data):
            data, k = _DANGEROUS_BYTES_RX.subn(rb"\1\2~\3", data)
            notes.append(f"{k:,} cells look like numbers with an impossible exponent (for example 1e2147483648); they are kept as text with a ~ in front")
        df = None
        for enc in ("utf-8", "cp1252", "latin-1"):
            try:
                df = pd.read_csv(io.BytesIO(data), low_memory=False, encoding=enc)
                if enc != "utf-8":
                    notes.append(f"the file is not UTF-8; it was read as {enc}")
                break
            except UnicodeDecodeError:
                continue
            except pd.errors.EmptyDataError:
                raise DataProblem("the file has no columns; a CSV table needs one header row and one record per row") from None
            except pd.errors.ParserError as e:
                raise DataProblem(f"the file is not a regular CSV table ({str(e)[:140]}); every row needs the same number of columns") from e
            except Exception as e:
                raise DataProblem(f"the file could not be read as a CSV table ({type(e).__name__})") from e
        if df is None:
            raise DataProblem("the file is not a text table that could be read as UTF-8 or Latin-1")
        if df.shape[1] == 1 and len(df.columns[0]) > 3:                      # one column: the delimiter may be a semicolon or a tab
            for sep, what in ((";", "semicolons"), ("\t", "tabs")):
                if str(df.columns[0]).count(sep) >= 2:
                    try:
                        alt = pd.read_csv(io.BytesIO(data), low_memory=False, encoding=enc, sep=sep)
                    except Exception:
                        continue
                    if alt.shape[1] > 2:
                        df = alt
                        notes.append(f"the columns are separated by {what}, not commas; the file was read that way")
                        break
    df.columns = [str(c) for c in df.columns]
    if df.columns.duplicated().any():
        seen, names = {}, []
        for c in df.columns:
            seen[c] = seen.get(c, 0) + 1
            names.append(c if seen[c] == 1 else f"{c}.{seen[c] - 1}")
        df.columns = names
        notes.append("some columns had the same name; a number was added to the later ones")
    if len(df) == 0:
        raise DataProblem("the table has column names but no records")
    defuse(df)
    df.attrs["notes"] = notes
    return df


def _nunique(col):
    """Distinct values of a column; a column of lists or dicts (not hashable) counts as text."""
    try:
        return int(col.nunique(dropna=True))
    except TypeError:
        return int(col.astype(str).nunique(dropna=True))


def inspect(df):
    """Guess the roles of the columns in a table. Everything here is a suggestion the user can change."""
    dup = [str(c) for c in df.columns[df.columns.duplicated()]]
    if dup:
        raise DataProblem(f"two columns are both named '{dup[0]}'; rename one of them and load the table again")
    if not df.attrs.get(DEFUSED):
        df = df.copy(deep=False)                 # the caller's table is not changed
        defuse(df)
    n = len(df)
    cols = list(df.columns)
    nun = {c: _nunique(df[c]) for c in cols}
    cands = []
    for c in cols:
        if not (2 <= nun[c] <= 80):
            continue
        vals = df[c].dropna().astype(str).str.strip()
        score = 0
        has_normal = bool(vals.str.match(NORMAL_RX).any())
        if LABEL_NAME_RX.search(str(c)):
            score += 3
        if has_normal:
            score += 2
        if df[c].dtype == object:
            score += 2
        if nun[c] >= 3:
            score += 1
        if c in cols[-3:]:
            score += 1
        if IDENT_RX.search(str(c)) or TIME_RX.search(str(c)):
            score -= 4
        if not (LABEL_NAME_RX.search(str(c)) or (has_normal and df[c].dtype == object)):
            continue                              # no sign that this column is a label (a count that contains 0 is not one): the person picks it
        if NOT_A_LABEL_RX.search(str(c).strip()):
            score -= 4
        # which label-like column is the attack type? one with three or more values comes before a yes/no column; then the
        # usual names (attack_type before label, class, category, type; a sub-category after its category); then the score
        name = str(c).strip()
        best = 3 if ATTACK_TYPE_NAME_RX.search(name) else (2 if PLAIN_LABEL_NAME_RX.search(name) else 0)
        best -= 1 if re.match(r"sub", name, re.I) else 0
        cands.append((score > 0, nun[c] >= 3, best, score, str(c), c))
    cands.sort(key=lambda t: t[:5], reverse=True)
    label_col = cands[0][5] if cands and cands[0][0] else None
    other_labels = [t[5] for t in cands if t[5] != label_col and t[3] >= 3 and STRICT_LABEL_RX.search(str(t[5]))]
    benign, benign_guess = None, False
    if label_col is not None:
        vc = df[label_col].dropna().astype(str).str.strip().value_counts()      # a missing label is not a value (as text, None would read as a word for normal)
        hits = [v for v in vc.index if NORMAL_RX.match(v)]
        benign = hits[0] if hits else (vc.index[0] if len(vc) else None)
        benign_guess = not hits                   # no value looks like "normal": the most frequent value is only a guess
    srcs = []
    for c in cols:
        if c == label_col or c in other_labels:
            continue
        if HOST_RX.search(str(c)) and 2 <= nun[c] <= max(5, n // 10) and not re.search(r"port", str(c), re.I):
            if df[c].dtype != object:
                v = pd.to_numeric(df[c], errors="coerce").dropna()
                if KEEP_HINT_RX.search(str(c)) or nun[c] < 3 or (len(v) and not (v == v.round()).all()):
                    continue
            if n and df[c].astype(str).value_counts().iloc[0] / n >= 0.95:
                continue                          # one value in nearly every record: not a column that tells hosts apart
            pri = 0
            if re.search(r"device|host|sensor|node|asset|machine|station", str(c), re.I):
                pri += 3
            if re.search(r"dst|des_|dest|^d(addr|ip)|resp_h$", str(c), re.I):
                pri += 2
            if df[c].dtype == object:
                pri += 3
            if not re.search(r"ip|mac|addr", str(c), re.I):
                pri += 1                          # a device name before the same device's address
            srcs.append((pri, str(c), c))
    srcs.sort(key=lambda t: t[:2], reverse=True)
    source_col = srcs[0][2] if srcs else None
    times = [c for c in cols if TIME_RX.search(str(c)) and c != label_col and c != source_col and nun[c] > 10
             and not re.search(r"duration|elapsed|iat|interval|_per_|rate|end|ttl|live|active|idle", str(c), re.I)]
    time_col = times[0] if times else None
    identifiers, text_cols, numbers, unusable = [], [], [], []
    for c in cols:
        if c in (label_col, source_col, time_col) or c in other_labels:
            continue
        v = pd.to_numeric(df[c], errors="coerce") if df[c].dtype != object or _hashable(df[c]) else pd.Series(np.nan, index=df.index)
        is_number = v.notna().mean() >= 0.95 and v.nunique() >= 2
        if IDENT_RX.search(str(c)) and not (is_number and KEEP_HINT_RX.search(str(c))):
            identifiers.append(c)
        elif IDENT_NAME_RX.search(str(c)):
            identifiers.append(c)
        elif is_number:
            numbers.append(c)
        elif df[c].dtype == object:
            text_cols.append(c)
        else:
            unusable.append(c)
    return dict(rows=n, columns=len(cols), label_col=label_col, benign_label=benign, benign_guess=benign_guess, label_cols=other_labels,
                source_col=source_col, time_col=time_col, identifiers=identifiers, text_columns=text_cols, numbers=numbers, unusable=unusable,
                label_values=(df[label_col].dropna().astype(str).str.strip().value_counts().to_dict() if label_col is not None else {}))


def sanitize(df, label_col, keep_numbers, attack_only=False, benign_label=None):
    """Return the sanitized table an organization may send: the chosen behavior numbers and the attack type."""
    out = _defused(df)[keep_numbers + [label_col]].copy()
    for c in keep_numbers:
        out[c] = pd.to_numeric(out[c], errors="coerce")
    if attack_only and benign_label is not None:
        out = out[out[label_col].astype(str).str.strip() != str(benign_label)]
    return out.reset_index(drop=True)


FORMULA_START = ("=", "+", "-", "@", "\t", "\r")


def csv_safe(df):
    """A copy of a table for writing to a CSV file that somebody else will open. A text cell or a column name that starts
    with = + - or @ is run as a formula by spreadsheet programs; label values and column names come from whoever made the
    table, so each such cell gets a single quote in front. Number columns are not touched."""
    def fix(v):
        return "'" + v if isinstance(v, str) and v[:1] in FORMULA_START else v
    out = df.copy()
    for i in range(out.shape[1]):
        if out.iloc[:, i].dtype == object:
            out[out.columns[i]] = out.iloc[:, i].map(fix)
    out.columns = [fix(c) for c in out.columns]
    return out


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
    """True when the file is a fingerprint of a known format whose integrity digest matches. Never raises on a hostile file."""
    try:
        integ = fp.get("integrity")
        return (isinstance(fp, dict) and fp.get("format") in FORMATS and isinstance(integ, dict)
                and isinstance(integ.get("digest"), str) and integ["digest"] == digest(fp))
    except Exception:
        return False


FP_MAX_BYTES = 5_000_000                        # a fingerprint is small (the synthetic sample: 45 KB); nothing larger is read
HOST_BUCKETS = ("none", "fewer than 10", "10 to 49", "50 or more")


def check_fingerprint(fp):
    """Is this object a fingerprint, field by field? Raises DataProblem with the reason. A site that receives a fingerprint
    from a stranger must not trust any field to have the right type: every value shown on a page passes here before."""
    def need(ok, what):
        if not ok:
            raise DataProblem(f"the file is not a valid fingerprint: {what}")

    def whole(v, lo=0, hi=10 ** 12):
        return type(v) is int and lo <= v <= hi

    def text(v, n):
        return isinstance(v, str) and len(v) <= n

    def number(v):
        return type(v) in (int, float) and math.isfinite(v)

    need(isinstance(fp, dict), "it is not a JSON object")
    need(fp.get("format") in FORMATS, "its format field is not a ThreatPrint fingerprint")
    need(whole(fp.get("version"), 1, 1000), "version")
    need(text(fp.get("agent"), 20) and text(fp.get("created"), 10) and re.fullmatch(r"\d{4}-\d{2}-\d{2}", fp["created"]) is not None, "agent or created")
    need(text(fp.get("attack_reference"), 300), "attack_reference")
    need(whole(fp.get("min_group_size"), 1, 10 ** 6), "min_group_size")
    grid = fp.get("quantile_grid")
    need(isinstance(grid, list) and 3 <= len(grid) <= 201 and all(number(g) and 0 < g < 1 for g in grid) and all(a < b for a, b in zip(grid, grid[1:])), "quantile_grid")
    feats = fp.get("features")
    need(isinstance(feats, list) and 1 <= len(feats) <= 5000 and all(text(f, 300) for f in feats), "features")
    need(isinstance(fp.get("normal"), dict) and whole(fp["normal"].get("records")), "normal.records")
    need(fp.get("hosts") in HOST_BUCKETS, "hosts")
    need(type(fp.get("has_host_column")) is bool and type(fp.get("has_time_column")) is bool, "has_host_column or has_time_column")
    need(whole(fp.get("removed_columns_count"), 0, 10 ** 6) and whole(fp.get("payload_bytes")), "removed_columns_count or payload_bytes")
    classes = fp.get("classes")
    need(isinstance(classes, dict) and len(classes) <= 1000, "classes")
    f = len(feats)
    for lab, c in classes.items():
        where = f"attack type '{str(lab)[:40]}'"
        need(text(lab, 300) and isinstance(c, dict), where)
        need(whole(c.get("records")), f"{where}: records")
        q = c.get("quantiles")
        need(isinstance(q, list) and len(q) == len(grid) and all(isinstance(r, list) and len(r) == f and all(number(v) for v in r) for r in q), f"{where}: quantiles")
        need(isinstance(c.get("corr"), list) and len(c["corr"]) == f * (f - 1) // 2 and all(number(v) and -2.1 <= v <= 2.1 for v in c["corr"]), f"{where}: corr")
        need(isinstance(c.get("integer"), list) and len(c["integer"]) == f and all(type(v) is bool for v in c["integer"]), f"{where}: integer")
        need(text(c.get("family"), 100), f"{where}: family")
        t = c.get("techniques")
        need(isinstance(t, list) and len(t) <= 10 and all(isinstance(x, dict) and text(x.get("id"), 12) and re.fullmatch(r"T\d{4}(\.\d{3})?", x["id"]) is not None
                                                           and text(x.get("name"), 120) and text(x.get("matrix"), 20) for x in t), f"{where}: techniques")
    sup = fp.get("suppressed")
    need(isinstance(sup, list) and len(sup) <= 5000 and all(isinstance(x, dict) and text(x.get("family"), 100) and text(x.get("reason"), 100) for x in sup), "suppressed")
    integ = fp.get("integrity")
    need(isinstance(integ, dict) and text(integ.get("alg"), 20) and isinstance(integ.get("digest"), str) and re.fullmatch(r"[0-9a-f]{64}", integ["digest"]) is not None, "integrity")
    need(fp.get("signature") is None or isinstance(fp["signature"], dict), "signature")
    return fp


def load_fingerprint(data):
    """Read an uploaded fingerprint (bytes or text) and check every field. Raises DataProblem with one sentence; never
    a traceback, whatever the file holds. Whether its integrity digest matches is a separate question: verify(fp)."""
    if isinstance(data, (bytes, bytearray, memoryview)):
        data = bytes(data)
        if len(data) > FP_MAX_BYTES:
            raise DataProblem(f"a fingerprint is a small file (tens of kilobytes); this file is {len(data) / 1e6:.1f} MB and was not read")
        try:
            data = data.decode("utf-8")
        except UnicodeDecodeError:
            raise DataProblem("the file is not a fingerprint (it is not UTF-8 text)") from None
    elif len(data) > FP_MAX_BYTES:
        raise DataProblem("a fingerprint is a small file (tens of kilobytes); this one was not read")

    def no_constant(name):
        raise ValueError(name)                    # NaN and Infinity are not JSON and not fingerprint values

    try:
        fp = json.loads(data, parse_constant=no_constant)
    except RecursionError:
        raise DataProblem("the file is not a fingerprint (it is nested too deeply)") from None
    except Exception:
        raise DataProblem("the file is not a fingerprint (it is not JSON, or it holds values that are not numbers)") from None
    return check_fingerprint(fp)


def _bucket(n):
    return "none" if not n else ("fewer than 10" if n < 10 else ("10 to 49" if n < 50 else "50 or more"))


def build_fingerprint(df, label_col, benign_label, numbers, source_col=None, time_col=None, k=K_MIN, removed_count=0):
    df = _defused(df)
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
        try:
            fp = json.load(open(a.verify))
        except Exception as e:
            sys.exit(f"Could not read {a.verify} as a fingerprint file ({type(e).__name__}).")
        if not isinstance(fp, dict):
            sys.exit(f"{a.verify} is not a fingerprint file.")
        good = verify(fp)
        print(("Integrity digest matches: " if good else "INTEGRITY DIGEST DOES NOT MATCH: ") + fp.get("integrity", {}).get("digest", "none"))
        sys.exit(0 if good else 1)
    if not a.file:
        ap.error("give a file, or --verify FINGERPRINT")
    if not os.path.exists(a.file):
        sys.exit(f"No such file: {a.file}")
    try:
        df = read_table(a.file)
        roles = inspect(df)
    except DataProblem as e:
        sys.exit(f"Could not use this file: {e}.")
    for note in df.attrs.get("notes", []):
        print(f"Note: {note}.")
    for flag, value in (("--label", a.label), ("--host", a.host), ("--time", a.time)):
        if value and value not in df.columns:
            sys.exit(f"{flag} {value}: no column of that name. The columns are: {', '.join(map(str, df.columns[:40]))}")
    label = a.label or roles["label_col"]
    if not label:
        sys.exit("No label column was recognized. Name it with --label.")
    if a.label and a.label != roles["label_col"]:                           # the user's label changes what the other columns are
        roles["numbers"] = [c for c in roles["numbers"] if c != a.label]
    normal = a.normal or (roles["benign_label"] if label == roles["label_col"] else df[label].astype(str).str.strip().value_counts().index[0])
    if not a.normal and (roles.get("benign_guess") or label != roles["label_col"]):
        print(f"Note: no label value looks like 'normal'; the most frequent value '{normal}' is taken as normal traffic. If that is wrong, name it with --normal.")
    if a.normal and str(a.normal) not in set(df[label].astype(str).str.strip()):
        sys.exit(f"--normal {a.normal}: no record has that value in column {label}.")
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
        csv_safe(s).to_csv(a.sanitized, index=False)
        print(f"Wrote the sanitized table: {a.sanitized} ({len(s):,} records, {s.shape[1]} columns).")


if __name__ == "__main__":
    main()
