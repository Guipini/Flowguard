# Dataset directory

**Not committed to git** (CSVs are too large — see `.gitignore`).

## What goes here

1. Go to https://www.unb.ca/cic/datasets/ids-2017.html → **CSVs folder**.
2. Download **`MachineLearningCSV.zip`** (≈500 MB).
3. Extract the archive. Inside you'll find pre-computed flow feature CSVs, one per capture day.
4. Copy these two files into this folder:
   - `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv`
   - `Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv`
5. Delete the rest of the extracted files — we don't need them.

These two days contain the attack labels we train on (DDoS + Port Scan). Benign traffic comes from the same files.

## Known dataset quirks (handled in `02_feature_engineering.ipynb`)

- Column names have **leading whitespace** (e.g., `" Destination Port"`). Stripped on load.
- Contains `Infinity` and `NaN` values in rate columns (e.g., `Flow Bytes/s`). Replaced with 0.0.
- Duplicate rows exist. Dropped.
- Column names are renamed to `snake_case` as the first step to keep runtime and training aligned.
