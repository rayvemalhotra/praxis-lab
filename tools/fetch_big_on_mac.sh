#!/bin/sh
# Downloads the large open datasets that do not fit the small sandbox, samples them, and removes the raw files.
# Run from the Praxis_Lab folder:  sh tools/fetch_big_on_mac.sh
# Raw files go to ~/Downloads/Praxis_Lab_raw (deleted after sampling); samples go to ../Praxis_Lab_Datasets.
set -u
HERE=$(cd "$(dirname "$0")/.." && pwd)
PY="$HERE/.venv/bin/python"
S="$HERE/tools/sample_dataset.py"
OUT="$HERE/../Praxis_Lab_Datasets"
RAW="$HOME/Downloads/Praxis_Lab_raw"
mkdir -p "$RAW" "$OUT"
cd "$RAW" || exit 1

echo "== N-BaIoT (UCI 442)"
if [ ! -f "$OUT/n_baiot.csv" ]; then
  curl -sS -L --retry 3 -o nbaiot.zip "https://archive.ics.uci.edu/static/public/442/detection+of+iot+botnet+attacks+n+baiot.zip" \
   && "$PY" "$HERE/tools/build_nbaiot.py" nbaiot.zip "$OUT/n_baiot.csv" --per-file 2500 && rm -f nbaiot.zip
fi

echo "== CSE-CIC-IDS2018 (AWS S3, public bucket), seven day files"
B="https://cse-cic-ids2018.s3.ca-central-1.amazonaws.com/Processed%20Traffic%20Data%20for%20ML%20Algorithms"
if [ ! -f "$OUT/cse_cic_ids2018.csv" ]; then
  FILES=""
  for d in Wednesday-14-02-2018 Thursday-15-02-2018 Friday-16-02-2018 Wednesday-21-02-2018 Thursday-22-02-2018 Friday-23-02-2018 Friday-02-03-2018; do
    curl -sS -L --retry 3 -o "$d.csv" "$B/${d}_TrafficForML_CICFlowMeter.csv" && FILES="$FILES $d.csv"
  done
  "$PY" "$S" --label Label --strip-label --chunk 300000 --out "$OUT/cse_cic_ids2018.csv" --max-rows 120000 --per-class 20000 $FILES && rm -f *-2018.csv
fi

echo "== Electra S7comm (University of Murcia)"
if [ ! -f "$OUT/electra_s7comm.csv" ]; then
  curl -sS -L --retry 3 -o electra_s7comm.zip "http://perception.inf.um.es/ICS-datasets/csv/electra_s7comm.zip" \
   && M=$(unzip -Z1 electra_s7comm.zip | grep -i csv | head -1) \
   && "$PY" "$S" --label label --chunk 500000 --out "$OUT/electra_s7comm.csv" --max-rows 120000 --per-class 30000 "electra_s7comm.zip::$M" && rm -f electra_s7comm.zip
fi

echo "== CIDDS-002 (Coburg)"
if [ ! -f "$OUT/cidds002.csv" ]; then
  curl -sS -L --retry 3 -o cidds002.zip "https://www.hs-coburg.de/wp-content/uploads/2024/11/CIDDS-002.zip" \
   && MS=$(unzip -Z1 cidds002.zip | grep -i "traffic/.*\.csv" | head -2 | sed "s|^|cidds002.zip::|") \
   && "$PY" "$S" --label attackType --strip-label --chunk 400000 --out "$OUT/cidds002.csv" --max-rows 120000 --per-class 30000 $MS && rm -f cidds002.zip
fi
echo "FETCH_DONE"
