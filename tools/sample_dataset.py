"""Make a working sample of a large labeled dataset without loading it whole.

    python3 sample_dataset.py --label Attack --out sample.csv --max-rows 120000 file1.csv file2.csv.gz big.zip::member.csv

Reads every input in chunks, keeps at most --per-class rows of each label value (so that rare attack types survive),
then cuts the result to --max-rows with a class-stratified draw. Inputs may be CSV, gzip CSV, or a member of a zip
file written as archive.zip::member. Use --names when the file has no header row (one name per column, comma-separated)
and --sep for a separator other than a comma. The raw files are only read.
"""
import argparse
import io
import os
import sys
import zipfile

import numpy as np
import pandas as pd


def open_input(spec):
    if "::" in spec:
        z, member = spec.split("::", 1)
        zf = zipfile.ZipFile(z)
        return io.TextIOWrapper(zf.open(member), encoding="utf-8", errors="replace")
    if spec.endswith(".gz"):
        import gzip
        return io.TextIOWrapper(gzip.open(spec), encoding="utf-8", errors="replace")
    return open(spec, encoding="utf-8", errors="replace")


def csv_chunks(fh, size, names, sep, skiprows):
    import csv
    csv.field_size_limit(10 ** 9)
    r = csv.reader(fh, delimiter=sep)
    for _ in range(skiprows):
        next(r, None)
    header = names or [str(c).strip() for c in next(r)]
    rows = []
    for row in r:
        if len(row) != len(header):
            continue
        rows.append(row)
        if len(rows) >= size:
            yield pd.DataFrame(rows, columns=header)
            rows = []
    if rows:
        yield pd.DataFrame(rows, columns=header)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("inputs", nargs="+")
    ap.add_argument("--label", required=True, help="label column (name, or 0-based index when --names is not given and the file has no header)")
    ap.add_argument("--out", required=True)
    ap.add_argument("--max-rows", type=int, default=120000)
    ap.add_argument("--per-class", type=int, default=40000)
    ap.add_argument("--chunk", type=int, default=200000)
    ap.add_argument("--names", default=None, help="comma-separated column names for a file without a header row")
    ap.add_argument("--sep", default=",")
    ap.add_argument("--skiprows", type=int, default=0)
    ap.add_argument("--strip-label", action="store_true", help="strip whitespace from the label values")
    ap.add_argument("--drop-labels", default="", help="comma-separated label values to leave out (e.g. nan)")
    ap.add_argument("--csv-module", action="store_true", help="read with Python's csv module (slower; for files that crash the pandas parser)")
    ap.add_argument("--seed", type=int, default=0)
    a = ap.parse_args()
    rng = np.random.RandomState(a.seed)
    names = a.names.split(",") if a.names else None
    kept = {}        # label -> list of DataFrames
    counts = {}      # label -> rows seen
    total_seen = 0
    for spec in a.inputs:
        fh = open_input(spec)
        if a.csv_module:
            reader = csv_chunks(fh, a.chunk, names, a.sep, a.skiprows)
        else:
            reader = pd.read_csv(fh, chunksize=a.chunk, sep=a.sep, names=names, header=None if names else "infer",
                                 skiprows=a.skiprows, low_memory=False, on_bad_lines="skip")
        for chunk in reader:
            chunk.columns = [str(c).strip() for c in chunk.columns]
            lab = a.label if a.label in chunk.columns else chunk.columns[int(a.label)] if a.label.isdigit() else None
            if lab is None:
                sys.exit(f"label column {a.label!r} not found in {spec}; columns: {list(chunk.columns)[:20]} ...")
            y = chunk[lab].astype(str)
            if a.strip_label:
                y = y.str.strip()
            total_seen += len(chunk)
            if a.drop_labels:
                keep = ~y.isin(a.drop_labels.split(","))
                chunk, y = chunk[keep], y[keep]
            for v, g in chunk.groupby(y):
                seen = counts.get(v, 0)
                have = sum(len(d) for d in kept.get(v, []))
                counts[v] = seen + len(g)
                room = a.per_class - have
                if room <= 0:
                    # reservoir-style replacement so that late rows also have a chance
                    take = g.sample(min(len(g), max(1, a.per_class // 20)), random_state=rng) if rng.rand() < 0.5 else None
                    if take is not None:
                        kept[v].append(take)
                        allv = pd.concat(kept[v])
                        kept[v] = [allv.sample(a.per_class, random_state=rng)]
                    continue
                kept.setdefault(v, []).append(g if len(g) <= room else g.sample(room, random_state=rng))
        fh.close()
        print(f"read {spec}: {total_seen:,} rows so far", flush=True)
    frames = [pd.concat(v) for v in kept.values()]
    df = pd.concat(frames, ignore_index=True)
    if len(df) > a.max_rows:
        lab = a.label if a.label in df.columns else df.columns[int(a.label)]
        y = df[lab].astype(str).str.strip() if a.strip_label else df[lab].astype(str)
        frac = a.max_rows / len(df)
        df = df.groupby(y, group_keys=False).apply(lambda g: g.sample(max(min(len(g), 300), int(len(g) * frac)), random_state=rng))
    df = df.sample(frac=1.0, random_state=rng).reset_index(drop=True)
    os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
    df.to_csv(a.out, index=False)
    lab = a.label if a.label in df.columns else df.columns[int(a.label)]
    print(f"wrote {a.out}: {len(df):,} rows, {df.shape[1]} columns, from {total_seen:,} rows read")
    print("rows seen per label:", {k: int(v) for k, v in sorted(counts.items(), key=lambda kv: -kv[1])})
    print("rows kept per label:", df[lab].astype(str).value_counts().to_dict())


if __name__ == "__main__":
    main()
